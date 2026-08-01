package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// managerClient speaks the authority-manager control plane
// (docs/authority-manager.md): it resolves volumeId+branch to a live VCS
// authority endpoint plus the mount credential.
type managerClient struct {
	*jsonClient

	// opMu guards the retained operation ids below. Access-lease operations
	// are idempotent per operationId (the manager keeps receipts), so an
	// AMBIGUOUS failure — transport error, timeout, 5xx — must retry the SAME
	// id; a definitive outcome (success or 4xx) ends the logical attempt and
	// the next one mints a fresh id.
	opMu            sync.Mutex
	pendingCreateOp map[string]string // volumeID+"\x00"+branch -> retained operationId
}

func newManagerClient(baseURL, token string) *managerClient {
	return &managerClient{jsonClient: newJSONClient(baseURL, token), pendingCreateOp: map[string]string{}}
}

// managerClient is the env-bound constructor command code uses (arms the
// version handshake); newManagerClient stays for handshake-free construction.
func (e *cmdEnv) managerClient(baseURL, token string) *managerClient {
	return &managerClient{jsonClient: e.jsonClient(baseURL, token), pendingCreateOp: map[string]string{}}
}

// accessSession is the resolved data-plane endpoint + credential for one
// mount, minted by POST /v1/access-leases/create — the only resolution route.
type accessSession struct {
	AuthorityURL        string             `json:"authorityUrl"`
	Host                string             `json:"host"`
	Port                int                `json:"port"`
	Token               string             `json:"token"`
	ExpiresAtMs         int64              `json:"expiresAtMs"`
	AuthorityInstanceID string             `json:"authorityInstanceId"`
	DataPlaneTransport  dataPlaneTransport `json:"dataPlaneTransport"`
	// Lease is the renewable slice: the mount renews it at half-TTL and
	// releases it on unmount.
	Lease *leaseState `json:"lease,omitempty"`
}

// newOperationID mints a v4 UUID for one logical access-lease operation.
func newOperationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint access-lease operation id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// cliConsumerID identifies this machine's CLI to the access-lease ledger. The
// CLI config keeps no separate machine identity, so a real hostname is
// required. Identity resolution fails closed: different machines must never
// collapse onto a shared placeholder consumer.
func cliConsumerID() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("resolve CLI consumer hostname: %w", err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("resolve CLI consumer hostname: operating system returned an empty hostname")
	}
	return "cli:" + host, nil
}

// ambiguousFailure reports whether an access-lease request may or may not
// have executed at the manager: transport errors and 5xx/timeout statuses
// retry the same operationId; anything else is a definitive outcome. Unwraps
// so callers may add context before classifying.
func ambiguousFailure(err error) bool {
	var he *httpError
	if !errors.As(err, &he) {
		return true // no HTTP status at all: transport-level, ambiguous
	}
	return he.Status >= 500 || he.Status == 408 || he.Status == 429
}

// leaseDefinitelyEnded reports whether the manager gave a DEFINITE answer
// about THIS LEASE saying it can never renew again. The codes are the
// manager's stable ACCESS_LEASE_* envelope (apps/authority-manager
// access-lease routes):
//
//	404 ACCESS_LEASE_NOT_FOUND    the lease does not exist
//	409 ACCESS_LEASE_REVOKED      ended (e.g. endReason "authority-retired")
//	409 ACCESS_LEASE_RELEASED     ended by a release
//	409/410 ACCESS_LEASE_EXPIRED  ended by expiry
//	401 ACCESS_LEASE_UNAUTHORIZED our token no longer authenticates it
//
// Every one of these is a statement about the LEASE, and every one is final:
// the keeper fails closed and never mints a replacement lease identity.
func leaseDefinitelyEnded(err error) bool {
	var he *httpError
	if !errors.As(err, &he) {
		return false
	}
	switch he.Code {
	case "ACCESS_LEASE_NOT_FOUND",
		"ACCESS_LEASE_EXPIRED",
		"ACCESS_LEASE_REVOKED",
		"ACCESS_LEASE_RELEASED",
		"ACCESS_LEASE_UNAUTHORIZED":
		return true
	}
	return false
}

// leaseEpochSuperseded reports the one typed answer that is about the
// MANAGER, not about the lease: 503 ACCESS_LEASE_EPOCH_SUPERSEDED means the
// manager instance we reached discovered its own claim was superseded and
// refused to answer — "reacquire against the new manager". It says NOTHING
// about whether this lease is still live; the successor manager still holds
// the same durable lease ledger and may renew it unchanged.
//
// So supersession leaves the renewal UNRESOLVED, not finished. Replaying it
// is not minting anything: identical accessLeaseId, identical accessToken,
// identical expectedControlSeq, identical operationId. It is the same
// renewal, completed against whoever now owns the epoch — and it converges,
// because the successor answers definitely (renewed, or ended). Treating it
// as terminal is what turned every manager epoch change into a dead mount.
func leaseEpochSuperseded(err error) bool {
	var he *httpError
	if !errors.As(err, &he) {
		return false
	}
	return he.Code == "ACCESS_LEASE_EPOCH_SUPERSEDED"
}

// leaseWire is the lease shape shared by the create/renew/release responses
// (packages/protocol accessLeaseSchema, trimmed to the fields the CLI uses).
type leaseWire struct {
	AccessLeaseID string `json:"accessLeaseId"`
	ControlSeq    string `json:"controlSeq"`
	ExpiresAt     int64  `json:"expiresAt"`
	State         string `json:"state"`
}

func (w leaseWire) toState(token string) *leaseState {
	return &leaseState{AccessLeaseID: w.AccessLeaseID, AccessToken: token, ExpiresAtMs: w.ExpiresAt, ControlSeq: w.ControlSeq}
}

// resolveAccess drives POST /v1/access-leases/create — the only endpoint
// resolution route (retired mount-session/authority-session routes answer
// 410). teamID is sent ONLY for a split self-host deployment (a distinct
// volume-api and authority-manager, where the client resolves tenancy); a
// unified control plane (the hosted broker) owns tenancy itself and rejects a
// client teamId, so the caller passes "" there. See resolveVolumeTeamID.
func (c *managerClient) resolveAccess(ctx context.Context, volumeID, branch, teamID string) (*accessSession, error) {
	consumerID, err := cliConsumerID()
	if err != nil {
		return nil, err
	}
	key := volumeID + "\x00" + branch
	c.opMu.Lock()
	opID := c.pendingCreateOp[key]
	if opID == "" {
		opID, err = newOperationID()
		if err != nil {
			c.opMu.Unlock()
			return nil, err
		}
		c.pendingCreateOp[key] = opID
	}
	c.opMu.Unlock()

	session, err := c.resolveAccessExact(ctx, opID, volumeID, branch, teamID, consumerID)
	if err != nil {
		if !ambiguousFailure(err) {
			c.opMu.Lock()
			delete(c.pendingCreateOp, key)
			c.opMu.Unlock()
		}
		return nil, err
	}
	c.opMu.Lock()
	delete(c.pendingCreateOp, key)
	c.opMu.Unlock()
	return session, nil
}

// resolveAccessExact executes one caller-owned durable create transaction.
// The operation and consumer identities are supplied explicitly so a mount
// intent can be persisted before the POST and replayed after a crash.
func (c *managerClient) resolveAccessExact(ctx context.Context, opID, volumeID, branch, teamID, consumerID string) (*accessSession, error) {
	if opID == "" || consumerID == "" {
		return nil, fmt.Errorf("create access lease for %s@%s: missing durable operation or consumer identity", volumeID, branch)
	}
	var out struct {
		Authority struct {
			AuthorityURL        string             `json:"authorityUrl"`
			Host                string             `json:"host"`
			Port                int                `json:"port"`
			AuthorityInstanceID string             `json:"authorityInstanceId"`
			DataPlaneTransport  dataPlaneTransport `json:"dataPlaneTransport"`
		} `json:"authority"`
		Lease       leaseWire `json:"lease"`
		AccessToken string    `json:"accessToken"`
	}
	createBody := map[string]any{
		"operationId": opID,
		"volumeId":    volumeID,
		"branch":      branch,
		"consumerId":  consumerID,
	}
	if teamID != "" {
		createBody["teamId"] = teamID
	}
	err := c.do(ctx, "POST", "/v1/access-leases/create", createBody, &out, 0)
	if err != nil {
		return nil, fmt.Errorf("create access lease for %s@%s: %w", volumeID, branch, err)
	}
	if out.Authority.AuthorityURL == "" {
		return nil, fmt.Errorf("manager returned an access lease without an authority endpoint")
	}
	if out.AccessToken == "" || out.Lease.AccessLeaseID == "" {
		return nil, fmt.Errorf("manager returned an incomplete access lease for %s@%s", volumeID, branch)
	}
	if err := out.Authority.DataPlaneTransport.validate(); err != nil {
		return nil, fmt.Errorf("manager returned an invalid data-plane transport for %s@%s: %w", volumeID, branch, err)
	}
	return &accessSession{
		AuthorityURL:        out.Authority.AuthorityURL,
		Host:                out.Authority.Host,
		Port:                out.Authority.Port,
		Token:               out.AccessToken,
		ExpiresAtMs:         out.Lease.ExpiresAt,
		AuthorityInstanceID: out.Authority.AuthorityInstanceID,
		DataPlaneTransport:  out.Authority.DataPlaneTransport,
		Lease:               out.Lease.toState(out.AccessToken),
	}, nil
}

// renewAccessLease drives POST /v1/access-leases/renew with the retry-stable
// CAS precondition (expectedControlSeq = the controlSeq from the last lease
// response). operationId is supplied by the caller so an ambiguous failure
// can retry the SAME renewal.
func (c *managerClient) renewAccessLease(ctx context.Context, opID string, lease leaseState) (*leaseState, error) {
	var out struct {
		Lease       leaseWire `json:"lease"`
		AccessToken string    `json:"accessToken"` // present only when the renew rotated the token
	}
	err := c.do(ctx, "POST", "/v1/access-leases/renew", map[string]any{
		"operationId":        opID,
		"accessLeaseId":      lease.AccessLeaseID,
		"accessToken":        lease.AccessToken,
		"expectedControlSeq": lease.ControlSeq,
	}, &out, 0)
	if err != nil {
		return nil, fmt.Errorf("renew access lease %s: %w", lease.AccessLeaseID, err)
	}
	token := lease.AccessToken
	if out.AccessToken != "" {
		token = out.AccessToken
	}
	return out.Lease.toState(token), nil
}

// releaseAccessLease drives exactly one logical
// POST /v1/access-leases/release operation. The caller owns operationId so an
// ambiguous response can replay the same transition without ever minting a
// replacement operation.
func (c *managerClient) releaseAccessLease(ctx context.Context, opID string, lease leaseState) error {
	err := c.do(ctx, "POST", "/v1/access-leases/release", map[string]any{
		"operationId":   opID,
		"accessLeaseId": lease.AccessLeaseID,
		"accessToken":   lease.AccessToken,
	}, nil, 0)
	if err != nil {
		return fmt.Errorf("release access lease %s: %w", lease.AccessLeaseID, err)
	}
	return nil
}

// leaseKeeper renews one mounted volume's access lease in the background and
// releases it on unmount. Renewals fire at half the remaining TTL. A terminal
// refusal stops the keeper and is surfaced; it never creates a replacement
// lease or changes resolution paths.
type leaseKeeper struct {
	manager  *managerClient
	tokens   *sessionTokenSource
	onUpdate func(leaseState) // persists the lease slice into mount state
	// credWatch makes a terminal renewal refusal loud (one mount log line +
	// a persisted status) instead of leaving a silent EIO zombie.
	credWatch *credentialWatch

	// now is the clock the expiry bound is measured against (injectable in
	// tests). The bound itself is the lease's OWN expiry — a deadline the
	// protocol already defines, never a retry budget invented here.
	now func() time.Time

	mu           sync.Mutex
	lease        leaseState
	pendingRenew string // retained operationId: an unresolved renew replays the SAME id
	// unresolved records that the last renewal neither succeeded nor received
	// a definite answer (ambiguous transport/5xx, or epoch supersession). The
	// keeper then retries at the minimum cadence instead of half the TTL, so
	// the renewal converges well inside the lease's own expiry.
	unresolved bool
	terminal   bool
}

func newLeaseKeeper(manager *managerClient, tokens *sessionTokenSource, initial leaseState, onUpdate func(leaseState)) *leaseKeeper {
	return &leaseKeeper{manager: manager, tokens: tokens, onUpdate: onUpdate, lease: initial, now: time.Now}
}

func (k *leaseKeeper) applyUpdate(lease leaseState) {
	if k.tokens != nil {
		k.tokens.setToken(lease.AccessToken, lease.ExpiresAtMs)
	}
	if k.onUpdate != nil {
		k.onUpdate(lease)
	}
}

func (k *leaseKeeper) snapshot() leaseState {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.lease
}

// renewOnce performs one renewal and classifies the answer into exactly three
// outcomes — the same three the manager actually distinguishes:
//
//	RENEWED    a fresh lease slice; the identity is unchanged.
//	ENDED      a definite answer about this lease (leaseDefinitelyEnded) or any
//	           other definitive refusal (CAS conflict, evicted receipt, 4xx).
//	           Fail closed. A replacement lease identity is NEVER minted here.
//	UNRESOLVED nobody has answered yet: transport failure, an untyped 5xx, or
//	           503 ACCESS_LEASE_EPOCH_SUPERSEDED. The SAME operationId is
//	           retained and the SAME renewal is replayed next tick, bounded by
//	           the lease's own expiry — the protocol's existing deadline, so
//	           the loop always terminates definitely.
//
// The middle and last rows used to be one row. Epoch supersession sat in the
// terminal set, so a manager epoch change (and, once the hosted broker
// flattened 409 REVOKED into 404, an authority retirement too) killed a mount
// whose lease the successor manager would have renewed unchanged.
func (k *leaseKeeper) renewOnce(ctx context.Context) {
	k.mu.Lock()
	if k.terminal {
		k.mu.Unlock()
		return
	}
	opID := k.pendingRenew
	if opID == "" {
		var err error
		opID, err = newOperationID()
		if err != nil {
			k.terminal = true
			k.mu.Unlock()
			k.credWatch.noteRejected(err)
			return
		}
		k.pendingRenew = opID
	}
	lease := k.lease
	k.mu.Unlock()

	renewed, err := k.manager.renewAccessLease(ctx, opID, lease)
	if err == nil {
		k.mu.Lock()
		k.lease = *renewed
		k.pendingRenew = ""
		k.unresolved = false
		k.mu.Unlock()
		k.applyUpdate(*renewed)
		return
	}
	if !leaseDefinitelyEnded(err) && (leaseEpochSuperseded(err) || ambiguousFailure(err)) {
		// UNRESOLVED. Bound the replay by the lease's own expiry: past it the
		// lease is over by definition, so continuing would be a retry loop
		// with no definite end. Inside it, the same operationId replays.
		if expiry := time.UnixMilli(lease.ExpiresAtMs); !k.now().Before(expiry) {
			k.mu.Lock()
			k.pendingRenew = ""
			k.unresolved = false
			k.terminal = true
			k.mu.Unlock()
			k.credWatch.noteRejected(fmt.Errorf(
				"access lease %s reached its own expiry with the renewal still unresolved: %w",
				lease.AccessLeaseID, err))
			return
		}
		k.mu.Lock()
		k.unresolved = true
		k.mu.Unlock()
		return // same operationId replays next tick
	}
	// ENDED. A definite answer about this lease (expired/revoked/released/
	// unknown/unauthorized) or any other definitive refusal (CAS conflict
	// after a lost receipt, evicted receipt). Fail closed; the mount never
	// mints a replacement lease identity.
	k.mu.Lock()
	k.pendingRenew = ""
	k.unresolved = false
	k.terminal = true
	k.mu.Unlock()
	k.credWatch.noteRejected(err)
}

// run renews until ctx is cancelled. The wait is recomputed from the live
// lease each cycle: half the remaining TTL, floored so a short-TTL (or
// clock-skewed) lease cannot spin. While a renewal is UNRESOLVED the wait
// stays at the floor — the renewal is in flight against a definite deadline
// (the lease's own expiry) and must be given every chance to converge before
// it, rather than sleeping half the TTL between attempts.
func (k *leaseKeeper) run(ctx context.Context) {
	const minWait = 5 * time.Second
	for {
		k.mu.Lock()
		lease := k.lease
		terminal := k.terminal
		unresolved := k.unresolved
		k.mu.Unlock()
		if terminal {
			return
		}
		wait := minWait
		if remaining := time.Until(time.UnixMilli(lease.ExpiresAtMs)); !unresolved && remaining/2 > minWait {
			wait = remaining / 2
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			k.renewOnce(ctx)
		}
	}
}

// release ends the lease on unmount. Ambiguous failures retry the SAME
// operationId within the caller's deadline. A definitive refusal or an
// exhausted deadline is returned visibly; cleanup never creates another
// lease or silently changes routes.
func (k *leaseKeeper) release(ctx context.Context) error {
	opID, err := newOperationID()
	if err != nil {
		return err
	}
	return k.releaseWithOperation(ctx, opID)
}

func (k *leaseKeeper) releaseWithOperation(ctx context.Context, opID string) error {
	if opID == "" {
		return fmt.Errorf("release access lease: missing durable operation id")
	}
	lease := k.snapshot()
	delay := 100 * time.Millisecond
	for {
		err := k.manager.releaseAccessLease(ctx, opID, lease)
		if err == nil {
			return nil
		}
		if leaseReleaseSatisfied(err) {
			return nil
		}
		if !ambiguousFailure(err) || leaseDefinitelyEnded(err) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("release access lease %s: exact retry deadline exhausted after ambiguous response: %w", lease.AccessLeaseID, ctx.Err())
		case <-timer.C:
		}
		if delay < time.Second {
			delay *= 2
			if delay > time.Second {
				delay = time.Second
			}
		}
	}
}

func leaseReleaseSatisfied(err error) bool {
	var he *httpError
	if !errors.As(err, &he) {
		return false
	}
	switch he.Code {
	case "ACCESS_LEASE_NOT_FOUND",
		"ACCESS_LEASE_EXPIRED",
		"ACCESS_LEASE_REVOKED",
		"ACCESS_LEASE_RELEASED",
		"ACCESS_LEASE_EPOCH_SUPERSEDED":
		return true
	default:
		return false
	}
}
