package fsproto

// Authority reachability fail-fast.
//
// When the authority's TCP peer is dead (black-holed, fenced host, dead LB
// backend), every remote-bound op otherwise burns its own opTimeout socket
// deadline: vnode ops surface as 60s stalls followed by EIO storms, and
// unmount-class barriers stack those stalls into kernel-visible hangs. The
// connHealth tracker turns a CONFIRMED dead transport into an immediate,
// cheap failure instead.
//
// Entry: failFastThreshold consecutive transport failures (dial errors,
// handshake transport failures, request/response encode/decode errors —
// deadline timeouts included) whose streak has persisted for at least
// failFastGrace. A DEFINITE auth rejection (ErrSessionTokenRejected) never
// counts: the peer answered, so it is reachable — only its credential check
// failed, and that terminal result is not reachability state.
// The grace window means a transient blip (an authority restart, a brief
// LB flap) never engages fail-fast: ops keep retrying normally for the
// first ~10s of any outage.
//
// Exit is automatic: any successful dial+handshake or round-trip clears the
// state. While engaged, a dedicated prober re-dials the authority with a
// SHORT bounded timeout every failFastProbeInterval, and the subscribe
// stream's own 500ms reconnect loop (gate-exempt) doubles as an on-demand
// probe — so recovery needs no operator action and no op ever has to burn a
// full deadline to discover the authority came back. A credential install
// flows through tokenForHandshake, so a probe after renewal also recovers a
// previously-rejected handshake.
//
// Fail-fast is reachability state only. It never fences the exact session,
// never drops parked identities (their replayer keeps retrying at its own
// backoff and resolves definitively after recovery), and never weakens any
// coherence rule: cache-satisfiable reads are served before the client is
// consulted at all.

import (
	"errors"
	"sync"
	"time"
)

const (
	// failFastThreshold is the consecutive transport-failure count required
	// before fail-fast may engage.
	failFastThreshold = 3
	// failFastGrace is how long a failure streak must have persisted before
	// fail-fast engages: ~10s of confirmed disconnect, so a brief restart
	// or socket flap never trips it.
	failFastGrace = 10 * time.Second
	// failFastStreakWindow bounds the gap between CONSECUTIVE failures for
	// them to count as one streak. It must exceed opTimeout: serial ops
	// against a black-holed peer fail at most one opTimeout apart, and they
	// are exactly the streak this exists to catch. Sporadic blips further
	// apart than this (with no successes in between on an idle mount) reset
	// the streak instead of accumulating into a false engage.
	failFastStreakWindow = opTimeout + 30*time.Second
	// failFastProbeInterval is the prober's re-dial cadence while engaged.
	failFastProbeInterval = 2 * time.Second
	// failFastProbeDialTimeout bounds one probe dial+handshake attempt.
	failFastProbeDialTimeout = 3 * time.Second
)

// ErrAuthorityUnreachable is returned WITHOUT touching the network while
// fail-fast is engaged: the authority has been continuously unreachable past
// the confirmation grace, so sending would only burn the op's socket
// deadline. Frontends map it to EIO like any other transport failure; the
// prober (and the subscribe reconnect loop) clear the state automatically on
// the next successful dial.
var ErrAuthorityUnreachable = errors.New(
	"fsproto: authority unreachable (fail-fast engaged after repeated transport failures); operation not attempted")

// connHealth tracks authority transport reachability for one client (shared
// by every pooled, subscribe, and probe connection).
type connHealth struct {
	// now is injectable for tests; time.Now in production.
	now func() time.Time
	// onEngage starts the client's reachability prober. Called at most once
	// per engagement (probing guards re-entry) and never under mu.
	onEngage func()

	mu           sync.Mutex
	failures     int
	firstFailure time.Time
	lastFailure  time.Time
	engaged      bool
	probing      bool
	// credentialRejected latches the DEFINITE verdict that a reachable
	// authority refused this client's credential. It is not reachability
	// state — engaging it CLEARS the transport breaker, because the peer
	// answered — and it is the one verdict a probe cannot undo: only a fresh
	// credential can, through CredentialInstalled.
	credentialRejected bool
}

func newConnHealth() *connHealth {
	return &connHealth{now: time.Now}
}

// recordFailure counts one transport failure and engages fail-fast when the
// streak crosses the threshold past the grace window.
func (h *connHealth) recordFailure() {
	if h == nil {
		return
	}
	h.mu.Lock()
	now := h.now()
	if h.failures > 0 && now.Sub(h.lastFailure) > failFastStreakWindow {
		h.failures = 0
	}
	h.failures++
	if h.failures == 1 {
		h.firstFailure = now
	}
	h.lastFailure = now
	engage := h.maybeEngageLocked(now)
	h.mu.Unlock()
	if engage != nil {
		engage()
	}
}

// recordSuccess clears the failure streak and exits fail-fast: reachability
// has been re-proven, so ops flow normally again. A successful handshake also
// clears any latched credential verdict — the credential it just used works.
func (h *connHealth) recordSuccess() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.failures = 0
	h.engaged = false
	h.credentialRejected = false
	h.mu.Unlock()
}

// recordCredentialRejected latches the definite credential verdict and CLEARS
// the transport breaker, because a peer that refuses a credential has answered.
func (h *connHealth) recordCredentialRejected() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.credentialRejected = true
	h.failures = 0
	h.engaged = false
	h.mu.Unlock()
}

// clearCredentialRejected re-arms probing after a fresh credential is
// installed. It does not claim the new credential works — only that the
// previous verdict is no longer about the credential in use.
func (h *connHealth) clearCredentialRejected() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.credentialRejected = false
	h.mu.Unlock()
}

// credentialDead reports the latched verdict.
func (h *connHealth) credentialDead() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.credentialRejected
}

// maybeEngageLocked flips to engaged when the entry conditions hold and
// returns the prober starter to run outside the lock (nil otherwise).
func (h *connHealth) maybeEngageLocked(now time.Time) func() {
	if !h.engaged && h.failures > 0 && now.Sub(h.lastFailure) > failFastStreakWindow {
		// A stale streak is history, not evidence of an outage ending NOW:
		// the failures stopped more than a streak window ago, so an op
		// arriving after a long idle gap must probe the network, not inherit
		// fail-fast from them. recordFailure applies this window when
		// EXTENDING a streak; applying it here too keeps gate() — which
		// evaluates the engage condition without recording anything — from
		// engaging on staleness alone and failing a healthy mount's next op
		// with a spurious EIO. (While engaged this must NOT run: only a
		// proven success may disengage, and the prober keeps lastFailure
		// fresh for as long as the outage actually persists.)
		h.failures = 0
	}
	if h.engaged || h.failures < failFastThreshold || now.Sub(h.firstFailure) < failFastGrace {
		if !h.engaged || h.probing || h.onEngage == nil {
			return nil
		}
		// Already engaged but the prober is not running (it exited on a
		// success that a racing failure immediately re-engaged): restart it.
		h.probing = true
		return h.onEngage
	}
	h.engaged = true
	if h.probing || h.onEngage == nil {
		return nil
	}
	h.probing = true
	return h.onEngage
}

// gate returns ErrAuthorityUnreachable while fail-fast is engaged. Exempt
// connections (the subscribe stream and the prober — the recovery paths)
// always pass. The engage condition is also evaluated here so an op arriving
// after a quiet streak fails fast instead of burning one more deadline.
func (h *connHealth) gate(exempt bool) error {
	if h == nil || exempt {
		return nil
	}
	h.mu.Lock()
	engage := h.maybeEngageLocked(h.now())
	engaged := h.engaged
	h.mu.Unlock()
	if engage != nil {
		engage()
	}
	if engaged {
		return ErrAuthorityUnreachable
	}
	return nil
}

// active reports whether fail-fast is currently engaged.
func (h *connHealth) active() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.engaged
}

// proberShouldExit atomically checks the exit condition and clears the
// probing flag when exiting, so an engage racing the prober's exit can never
// strand an engaged client without a prober.
func (h *connHealth) proberShouldExit() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.engaged {
		h.probing = false
		return true
	}
	return false
}

// proberDone force-clears the probing flag (client closed).
func (h *connHealth) proberDone() {
	h.mu.Lock()
	h.probing = false
	h.mu.Unlock()
}

// FailFast reports whether this client is currently failing remote-bound ops
// fast because the authority is confirmed unreachable. Unmount-class paths
// consult it to choose the journal-first (local WAL durability) barrier
// instead of a doomed network flush.
//
// This is deliberately DISTINCT from SessionFenced: unreachability means
// there is no truth to be had (journal-first success is the honest answer),
// while a fence is a definite, knowable verdict — the authority rejected this
// generation — and conflating the two let a fenced-but-reachable session
// answer barriers with a durability claim m1 forbids (see
// clientcore.Volume.SyncVolumeBounded).
func (c *Client) FailFast() bool { return c.health.active() }

// CredentialRejected reports the DEFINITE verdict that a reachable authority
// refused this client's credential. It is deliberately distinct from FailFast
// (no answer at all) and from SessionFenced (a rejected session generation):
// a mount in this state has a healthy authority and a dead access credential,
// and only `portablefs login` + remount can change it. Status surfaces it as
// credential-expired rather than as unreachability, and the admitted backlog
// belongs to the durable parked-job path rather than to a retry loop.
func (c *Client) CredentialRejected() bool { return c.health.credentialDead() }

// CredentialInstalled re-arms reachability probing after a fresh credential is
// installed, so a mount that latched a credential verdict recovers without a
// restart if the new credential is accepted.
func (c *Client) CredentialInstalled() {
	c.health.clearCredentialRejected()
	c.health.mu.Lock()
	engaged := c.health.engaged
	start := !c.health.probing && c.health.onEngage != nil && engaged
	if start {
		c.health.probing = true
	}
	onEngage := c.health.onEngage
	c.health.mu.Unlock()
	if start && onEngage != nil {
		onEngage()
	}
}

// probeOutcome is what ONE reachability probe proved. The three cases are
// genuinely different facts about the far end and the mount must not conflate
// them — conflating the last two is exactly how a mount whose ACCESS LEASE had
// died reported `authority unreachable (fail-fast engaged after repeated
// transport failures)` while a concurrent fresh mount proved the authority
// perfectly healthy.
type probeOutcome uint8

const (
	// probeUnreachable: no answer. Reachability is still unknown-bad; keep
	// probing, since only the network can change this.
	probeUnreachable probeOutcome = iota
	// probeReachable: dial + handshake succeeded. Fail-fast clears.
	probeReachable
	// probeCredentialRejected: the authority ANSWERED and refused this
	// client's credential. That is a definite classification about the
	// CREDENTIAL, not about reachability, and it is terminal for this
	// client: re-handshaking with the same dead credential can never succeed
	// (per the lease decision table only login + remount can). Probing stops.
	probeCredentialRejected
)

// runReachabilityProbe re-dials the authority (bounded) until it answers, the
// authority definitively rejects this client's credential, or the client
// closes. It runs at most once per client at a time (connHealth.probing).
func (c *Client) runReachabilityProbe() {
	defer c.health.proberDone()
	for {
		if c.isClosed() {
			return
		}
		if c.health.proberShouldExit() {
			return
		}
		switch c.probeAuthority() {
		case probeReachable:
			c.health.recordSuccess()
			// Loop once more: proberShouldExit clears probing under the
			// same lock that a racing re-engage takes.
			continue
		case probeCredentialRejected:
			// THE AUTHORITY IS REACHABLE. Saying otherwise is a lie, and it
			// was the lie that made a dead-lease mount indistinguishable from
			// a network outage: every op answered "authority unreachable", the
			// admitted backlog stranded with no parked-job engagement, and this
			// loop re-handshook with the same dead credential every two seconds
			// for as long as the mount lived.
			//
			// Clearing the transport breaker publishes the truth (reachable),
			// and latching the credential verdict publishes the rest of it
			// (refused). Ops then surface a credential-expired classification
			// instead of a reachability one, and this loop stops: nothing it
			// can do changes a rejected credential. A credential INSTALL
			// re-arms it (see CredentialInstalled).
			c.health.recordCredentialRejected()
			return
		}
		select {
		case <-c.closed:
			return
		case <-time.After(failFastProbeInterval):
		}
	}
}

// probeAuthority performs one bounded dial + auth handshake and CLASSIFIES the
// result. Success proves the authority is reachable AND accepting this client's
// current credential (tokenForHandshake reads the live source, so a credential
// install is picked up automatically); an explicit token rejection proves it is
// reachable and this credential is dead.
func (c *Client) probeAuthority() probeOutcome {
	cn := &conn{
		addrs:       c.addrs,
		tls:         c.tls,
		auth:        c.tokenForHandshake,
		transport:   c.transport,
		client:      c,
		health:      c.health,
		gateExempt:  true,
		dialTimeout: failFastProbeDialTimeout,
	}
	if !c.registerDedicated(cn) {
		return probeUnreachable
	}
	defer func() {
		cn.reset()
		c.unregisterDedicated(cn)
	}()
	if err := cn.ensure(); err != nil {
		if errors.Is(err, ErrSessionTokenRejected) {
			return probeCredentialRejected
		}
		return probeUnreachable
	}
	return probeReachable
}
