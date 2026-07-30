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

// leaseTerminal reports whether the manager answered with a TYPED code
// saying this lease can never renew again. The codes are the manager's
// stable ACCESS_LEASE_* envelope (apps/authority-manager access-lease routes):
// epoch-superseded and unknown-lease are what every mount sees after a
// manager restart (lease state is scoped to the manager epoch), the terminal
// trio after a release/expiry/revoke, unauthorized after a rotation this
// client missed. Checked BEFORE the ambiguity rule because epoch-superseded
// ships as a 503, which would otherwise read as "retry the same renew" and
// leave the mount renewing a dead lease forever.
func leaseTerminal(err error) bool {
	var he *httpError
	if !errors.As(err, &he) {
		return false
	}
	switch he.Code {
	case "ACCESS_LEASE_EPOCH_SUPERSEDED",
		"ACCESS_LEASE_NOT_FOUND",
		"ACCESS_LEASE_EXPIRED",
		"ACCESS_LEASE_REVOKED",
		"ACCESS_LEASE_RELEASED",
		"ACCESS_LEASE_UNAUTHORIZED":
		return true
	}
	return false
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

	mu           sync.Mutex
	lease        leaseState
	pendingRenew string // retained operationId: ambiguous renew failures retry the SAME id
	terminal     bool
}

func newLeaseKeeper(manager *managerClient, tokens *sessionTokenSource, initial leaseState, onUpdate func(leaseState)) *leaseKeeper {
	return &leaseKeeper{manager: manager, tokens: tokens, onUpdate: onUpdate, lease: initial}
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

// renewOnce performs one renewal. An ambiguous failure retains the
// operationId so the next tick replays the SAME renewal (the manager's
// receipts make that idempotent); a definitive failure stops this lease.
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
		k.mu.Unlock()
		k.applyUpdate(*renewed)
		return
	}
	if !leaseTerminal(err) && ambiguousFailure(err) {
		return // same operationId retries next tick
	}
	// Definitive refusal (epoch superseded, unknown to the new epoch,
	// expired/revoked/released, CAS conflict after a lost receipt): this
	// lease can never renew again. Fail closed; never mint a replacement.
	k.mu.Lock()
	k.pendingRenew = ""
	k.terminal = true
	k.mu.Unlock()
	k.credWatch.noteRejected(err)
}

// run renews until ctx is cancelled. The wait is recomputed from the live
// lease each cycle: half the remaining TTL, floored so a short-TTL (or
// clock-skewed) lease cannot spin.
func (k *leaseKeeper) run(ctx context.Context) {
	const minWait = 5 * time.Second
	for {
		k.mu.Lock()
		lease := k.lease
		terminal := k.terminal
		k.mu.Unlock()
		if terminal {
			return
		}
		wait := minWait
		if remaining := time.Until(time.UnixMilli(lease.ExpiresAtMs)); remaining/2 > minWait {
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
		if !ambiguousFailure(err) || leaseTerminal(err) {
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
