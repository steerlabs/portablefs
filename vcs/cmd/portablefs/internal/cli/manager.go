package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"os"
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

// mountSession is the resolved data-plane endpoint + credential for one mount.
type mountSession struct {
	AuthorityURL        string `json:"authorityUrl"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	NFSPort             int    `json:"nfsPort"`
	Token               string `json:"token"`
	ExpiresAtMs         int64  `json:"expiresAtMs"`
	AuthorityInstanceID string `json:"authorityInstanceId"`
	// Lease is set when the session came from the canonical access-lease
	// route; the mount renews it at half-TTL and releases it on unmount.
	Lease *leaseState `json:"lease,omitempty"`
}

// newOperationID mints a v4 UUID for one logical access-lease operation.
func newOperationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is effectively fatal elsewhere too; fall back to
		// a time-free constant-length id rather than panicking in a CLI.
		return "op-rand-unavailable"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// cliConsumerID identifies this machine's CLI to the access-lease ledger. The
// CLI config keeps no machine identity, so the hostname is the stable id.
func cliConsumerID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return "cli:" + host
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

// leaseUnrecoverable reports whether the manager answered with a TYPED code
// saying this lease can never renew again — the caller must re-acquire a
// fresh lease instead of retrying the renewal. The codes are the manager's
// stable ACCESS_LEASE_* envelope (apps/authority-manager access-lease routes):
// epoch-superseded and unknown-lease are what every mount sees after a
// manager restart (lease state is scoped to the manager epoch), the terminal
// trio after a release/expiry/revoke, unauthorized after a rotation this
// client missed. Checked BEFORE the ambiguity rule because epoch-superseded
// ships as a 503, which would otherwise read as "retry the same renew" and
// leave the mount renewing a dead lease forever.
func leaseUnrecoverable(err error) bool {
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

// createAccessLease drives POST /v1/access-leases/create. handled=false means
// the manager predates the route (404/405) and the caller must fall back to
// the mount-session chain. teamID is sent ONLY for a split self-host
// deployment (a distinct volume-api and authority-manager, where the client
// resolves tenancy); a unified control plane (the hosted broker) owns tenancy
// itself and rejects a client teamId, so the caller passes "" there. See
// resolveVolumeTeamID.
func (c *managerClient) createAccessLease(ctx context.Context, volumeID, branch, teamID string) (*mountSession, bool, error) {
	key := volumeID + "\x00" + branch
	c.opMu.Lock()
	opID := c.pendingCreateOp[key]
	if opID == "" {
		opID = newOperationID()
		c.pendingCreateOp[key] = opID
	}
	c.opMu.Unlock()

	var out struct {
		Authority struct {
			AuthorityURL        string `json:"authorityUrl"`
			Host                string `json:"host"`
			Port                int    `json:"port"`
			NFSPort             int    `json:"nfsPort"`
			AuthorityInstanceID string `json:"authorityInstanceId"`
		} `json:"authority"`
		Lease       leaseWire `json:"lease"`
		AccessToken string    `json:"accessToken"`
	}
	createBody := map[string]any{
		"operationId": opID,
		"volumeId":    volumeID,
		"branch":      branch,
		"consumerId":  cliConsumerID(),
	}
	if teamID != "" {
		createBody["teamId"] = teamID
	}
	err := c.do(ctx, "POST", "/v1/access-leases/create", createBody, &out, 0)
	if httpStatus(err) == 404 || httpStatus(err) == 405 {
		// Older manager without the route: the operation never executed;
		// drop the retained id and use the legacy chain.
		c.opMu.Lock()
		delete(c.pendingCreateOp, key)
		c.opMu.Unlock()
		return nil, false, err
	}
	if err != nil {
		if !ambiguousFailure(err) {
			c.opMu.Lock()
			delete(c.pendingCreateOp, key)
			c.opMu.Unlock()
		}
		return nil, true, fmt.Errorf("create access lease for %s@%s: %w", volumeID, branch, err)
	}
	c.opMu.Lock()
	delete(c.pendingCreateOp, key)
	c.opMu.Unlock()
	if out.Authority.AuthorityURL == "" {
		return nil, true, fmt.Errorf("manager returned an access lease without an authority endpoint")
	}
	if out.AccessToken == "" || out.Lease.AccessLeaseID == "" {
		return nil, true, fmt.Errorf("manager returned an incomplete access lease for %s@%s", volumeID, branch)
	}
	return &mountSession{
		AuthorityURL:        out.Authority.AuthorityURL,
		Host:                out.Authority.Host,
		Port:                out.Authority.Port,
		NFSPort:             out.Authority.NFSPort,
		Token:               out.AccessToken,
		ExpiresAtMs:         out.Lease.ExpiresAt,
		AuthorityInstanceID: out.Authority.AuthorityInstanceID,
		Lease:               out.Lease.toState(out.AccessToken),
	}, true, nil
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

// releaseAccessLease drives POST /v1/access-leases/release (best-effort; the
// lease expires on its own if this is lost).
func (c *managerClient) releaseAccessLease(ctx context.Context, lease leaseState) error {
	err := c.do(ctx, "POST", "/v1/access-leases/release", map[string]any{
		"operationId":   newOperationID(),
		"accessLeaseId": lease.AccessLeaseID,
		"accessToken":   lease.AccessToken,
	}, nil, 0)
	if err != nil {
		return fmt.Errorf("release access lease %s: %w", lease.AccessLeaseID, err)
	}
	return nil
}

// leaseKeeper renews a mounted volume's access lease in the background and
// releases it on unmount. Renewals fire at half the remaining TTL; a renewal
// that fails definitively (lease expired/revoked/epoch-superseded) falls back
// to minting a fresh lease through the full mountSession ladder, so a mount
// outlives any single lease.
type leaseKeeper struct {
	manager  *managerClient
	volumeID string
	branch   string
	teamID   string
	tokens   *sessionTokenSource
	onUpdate func(leaseState) // persists the lease slice into mount state
	// credWatch observes credential outcomes (nil-safe): a definitive
	// rejection on BOTH the renew and the re-acquire path is what a key
	// revocation looks like, and the watch is what makes it loud (one mount
	// log line + a persisted status) instead of a silent EIO zombie.
	credWatch *credentialWatch

	mu           sync.Mutex
	lease        leaseState
	pendingRenew string // retained operationId: ambiguous renew failures retry the SAME id
}

func newLeaseKeeper(manager *managerClient, volumeID, branch, teamID string, tokens *sessionTokenSource, initial leaseState, onUpdate func(leaseState)) *leaseKeeper {
	return &leaseKeeper{manager: manager, volumeID: volumeID, branch: branch, teamID: teamID, tokens: tokens, onUpdate: onUpdate, lease: initial}
}

// adopt swaps in a lease minted outside the renewal loop (a token-source
// refresh that re-resolved the session).
func (k *leaseKeeper) adopt(lease leaseState) {
	k.mu.Lock()
	k.lease = lease
	k.pendingRenew = ""
	k.mu.Unlock()
	k.applyUpdate(lease)
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
// receipts make that idempotent); a definitive failure re-creates a fresh
// lease via the mountSession ladder.
func (k *leaseKeeper) renewOnce(ctx context.Context) {
	k.mu.Lock()
	opID := k.pendingRenew
	if opID == "" {
		opID = newOperationID()
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
		k.credWatch.noteHealthy()
		return
	}
	if !leaseUnrecoverable(err) && ambiguousFailure(err) {
		return // same operationId retries next tick
	}
	// Definitive refusal (epoch superseded, unknown to the new epoch,
	// expired/revoked/released, CAS conflict after a lost receipt): this
	// lease can never renew again; mint a fresh one through the full ladder.
	k.mu.Lock()
	k.pendingRenew = ""
	k.mu.Unlock()
	ms, createErr := k.manager.mountSession(ctx, k.volumeID, k.branch, k.teamID)
	if createErr != nil {
		// Re-acquire failing with a credential rejection is TERMINAL: after
		// a key revocation both the renew and the create path answer
		// 401/ACCESS_LEASE_UNAUTHORIZED forever, so surface it instead of
		// letting the mount rot into a silent EIO zombie. Other failures
		// stay quiet: the half-TTL cadence retries and the token-source
		// refresh is the backstop.
		if credentialRejected(createErr) {
			k.credWatch.noteRejected(createErr)
		}
		return
	}
	if ms.Lease == nil {
		// A non-lease manager rung answered: the credential is accepted,
		// there is just no lease to adopt on this transport.
		k.credWatch.noteHealthy()
		return
	}
	k.mu.Lock()
	k.lease = *ms.Lease
	k.mu.Unlock()
	k.applyUpdate(*ms.Lease)
	k.credWatch.noteHealthy()
}

// run renews until ctx is cancelled. The wait is recomputed from the live
// lease each cycle: half the remaining TTL, floored so a short-TTL (or
// clock-skewed) lease cannot spin.
func (k *leaseKeeper) run(ctx context.Context) {
	const minWait = 5 * time.Second
	for {
		lease := k.snapshot()
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

// release ends the lease on unmount, best-effort with a short deadline.
func (k *leaseKeeper) release() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := k.manager.releaseAccessLease(ctx, k.snapshot()); err != nil {
		// Best-effort by contract: the lease expires on its own.
		fmt.Fprintf(os.Stderr, "portablefs: %v\n", err)
	}
}

type authorityPayload struct {
	AuthorityURL        string `json:"authorityUrl"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	NFSPort             int    `json:"nfsPort"`
	AuthorityInstanceID string `json:"authorityInstanceId"`
	AuthorityAuthToken  string `json:"authorityAuthToken"`
	AuthorityExpiresAt  int64  `json:"authorityExpiresAt"`
}

// mountSession resolves a live mount endpoint for volumeID+branch. It prefers
// the canonical POST /v1/access-leases/create route (idempotent per
// operationId, renewable, releasable); a manager that predates it (404/405)
// is served by POST /v1/volumes/:id/mount-sessions, then the flat
// /v1/mount-sessions alias, then the legacy /v1/authorities/ensure +
// /v1/authorities/session pair — exactly the pre-lease ladder. The canonical
// access-lease route resolves tenancy control-plane-side; only the legacy
// self-host env-mode ladder still accepts a client teamId, so it rides along
// there when known.
func (c *managerClient) mountSession(ctx context.Context, volumeID, branch, teamID string) (*mountSession, error) {
	if ms, handled, err := c.createAccessLease(ctx, volumeID, branch, teamID); handled {
		return ms, err
	}
	ref := map[string]string{"volumeId": volumeID, "branch": branch}
	if teamID != "" {
		ref["teamId"] = teamID
	}
	var newStyle struct {
		MountSession struct {
			Endpoint struct {
				AuthorityURL string `json:"authorityUrl"`
				Host         string `json:"host"`
				Port         int    `json:"port"`
				NFSPort      int    `json:"nfsPort"`
			} `json:"endpoint"`
			Token               string `json:"token"`
			ExpiresAtMs         int64  `json:"expiresAtMs"`
			AuthorityInstanceID string `json:"authorityInstanceId"`
		} `json:"mountSession"`
	}
	// Canonical volume-scoped route first (served by both the OSS manager and
	// hosted control planes), then the flat alias, then the legacy pair.
	err := c.do(ctx, "POST", "/v1/volumes/"+url.PathEscape(volumeID)+"/mount-sessions", ref, &newStyle, 0)
	if httpStatus(err) == 404 || httpStatus(err) == 405 {
		err = c.do(ctx, "POST", "/v1/mount-sessions", ref, &newStyle, 0)
	}
	if err == nil {
		ms := newStyle.MountSession
		if ms.Endpoint.AuthorityURL == "" {
			return nil, fmt.Errorf("manager returned a mount session without an authority endpoint")
		}
		return &mountSession{
			AuthorityURL:        ms.Endpoint.AuthorityURL,
			Host:                ms.Endpoint.Host,
			Port:                ms.Endpoint.Port,
			NFSPort:             ms.Endpoint.NFSPort,
			Token:               ms.Token,
			ExpiresAtMs:         ms.ExpiresAtMs,
			AuthorityInstanceID: ms.AuthorityInstanceID,
		}, nil
	}
	if httpStatus(err) != 404 {
		return nil, fmt.Errorf("resolve mount session for %s@%s: %w", volumeID, branch, err)
	}

	// Older manager: ensure the authority exists, then mint the session token.
	var ensure struct {
		Authority authorityPayload `json:"authority"`
	}
	if err := c.do(ctx, "POST", "/v1/authorities/ensure", ref, &ensure, 0); err != nil {
		return nil, fmt.Errorf("ensure authority for %s@%s: %w", volumeID, branch, err)
	}
	var session struct {
		Authority authorityPayload `json:"authority"`
	}
	if err := c.do(ctx, "POST", "/v1/authorities/session", ref, &session, 0); err != nil {
		return nil, fmt.Errorf("mint mount session for %s@%s: %w", volumeID, branch, err)
	}
	a := session.Authority
	if a.AuthorityURL == "" {
		a.AuthorityURL = ensure.Authority.AuthorityURL
	}
	if a.AuthorityInstanceID == "" {
		a.AuthorityInstanceID = ensure.Authority.AuthorityInstanceID
	}
	if a.AuthorityURL == "" {
		return nil, fmt.Errorf("manager returned no authority endpoint for %s@%s", volumeID, branch)
	}
	return &mountSession{
		AuthorityURL:        a.AuthorityURL,
		Host:                a.Host,
		Port:                a.Port,
		NFSPort:             a.NFSPort,
		Token:               a.AuthorityAuthToken,
		ExpiresAtMs:         a.AuthorityExpiresAt,
		AuthorityInstanceID: a.AuthorityInstanceID,
	}, nil
}
