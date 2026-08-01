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
	// ── THE CREDENTIAL VERDICT IS GENERATION-TAGGED ─────────────────────────
	//
	// The verdict used to be one bool, and a bool cannot say WHICH credential
	// it is about. Three untruths followed from that, and every one of them
	// reported a healthy mount:
	//
	//   - installing a credential CLEARED the verdict and only probed when the
	//     transport breaker happened to be engaged, so installing another
	//     INVALID credential left the mount reporting healthy and untested;
	//   - a successful round trip on an ALREADY-AUTHENTICATED connection
	//     cleared the verdict without any handshake having proved the CURRENT
	//     credential;
	//   - an ordinary (non-probe) handshake rejection was not recorded as a
	//     credential rejection at all — only the prober's was.
	//
	// So the credential has a GENERATION, bumped by every installation, and
	// every verdict names the generation it is about:
	//
	//   credGen        the generation now offered to handshakes
	//   credRejectedAt the generation a reachable authority refused (0 = none)
	//   credVerifiedAt the generation a handshake proved good (0 = none)
	//   credPending    an installed generation that has not been proved either
	//                  way yet
	//
	// The rules are then exact: only a handshake using credGen may clear or
	// confirm it, a rejection of credGen LATCHES wherever it happens, and an
	// installation is unproven until its own bounded gate-exempt handshake
	// says otherwise.
	credGen        uint64
	credRejectedAt uint64
	credVerifiedAt uint64
	credPending    bool
}

func newConnHealth() *connHealth {
	return &connHealth{now: time.Now, credGen: 1, credPending: true}
}

// generation reports the credential generation a handshake starting now will
// be offering. The caller carries it back into the verdict recorders so a
// handshake that raced an install cannot claim anything about the successor.
func (h *connHealth) generation() uint64 {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.credGen
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
// has been re-proven, so ops flow normally again.
//
// It says NOTHING about the credential. It is called for every successful round
// trip, and a round trip travels an ALREADY-AUTHENTICATED connection whose
// handshake may predate the current credential entirely — clearing a verdict
// here declared a credential healthy that nothing had ever offered.
func (h *connHealth) recordSuccess() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.failures = 0
	h.engaged = false
	h.mu.Unlock()
}

// recordHandshakeSuccess is recordSuccess PLUS the credential verdict a
// completed handshake is entitled to make. Only a handshake that offered the
// CURRENT generation may clear or confirm it: one that raced an install proves
// something about the predecessor and must not speak for its successor.
func (h *connHealth) recordHandshakeSuccess(gen uint64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.failures = 0
	h.engaged = false
	if gen != 0 && gen == h.credGen {
		h.credRejectedAt = 0
		h.credVerifiedAt = gen
		h.credPending = false
	}
	h.mu.Unlock()
}

// recordCredentialRejected latches the definite credential verdict for gen and
// CLEARS the transport breaker, because a peer that refuses a credential has
// answered. It is called from EVERY handshake that is refused — ordinary pooled
// dials included, not only the prober's — because a rejection is a rejection
// wherever the authority delivers it.
func (h *connHealth) recordCredentialRejected(gen uint64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.failures = 0
	h.engaged = false
	if gen != 0 && gen == h.credGen {
		h.credRejectedAt = gen
		h.credPending = false
	}
	h.mu.Unlock()
}

// installCredential opens a new credential generation. The new generation is
// UNPROVEN — not healthy — until a handshake offering it says otherwise, which
// is what Client.CredentialInstalled goes on to run.
func (h *connHealth) installCredential() uint64 {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.credGen++
	h.credRejectedAt = 0
	h.credVerifiedAt = 0
	h.credPending = true
	return h.credGen
}

// credentialDead reports the latched verdict for the CURRENT generation.
func (h *connHealth) credentialDead() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.credRejectedAt != 0 && h.credRejectedAt == h.credGen
}

// credentialUnproven reports that the current generation has neither been
// accepted nor refused by any handshake yet.
func (h *connHealth) credentialUnproven() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.credPending && h.credVerifiedAt != h.credGen && h.credRejectedAt != h.credGen
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

// CredentialUnproven reports that the installed credential has not yet been
// offered to the authority by any handshake. It is neither healthy nor dead —
// it is UNTESTED — and a mount must not be reported as recovered on it.
func (c *Client) CredentialUnproven() bool { return c.health.credentialUnproven() }

// CredentialInstalled opens a new credential generation and IMMEDIATELY proves
// it, with a bounded, gate-exempt handshake, on this call's own goroutine
// budget (asynchronously, so an installer is never blocked by a dead peer).
//
// It used to merely clear the verdict bool and start the prober only when the
// transport breaker happened to be engaged. Installing a second INVALID
// credential therefore moved the mount from "credential rejected" to "healthy",
// with nothing anywhere having offered the new credential to anyone: the mount
// reported recovered and untested, and the next real op discovered the truth.
//
// Installation now enters VERIFICATION-PENDING (see connHealth.credPending) and
// runs the handshake at once. Only that handshake — offering this generation —
// can move it to verified or to latched-rejected.
func (c *Client) CredentialInstalled() {
	gen := c.health.installCredential()
	c.health.mu.Lock()
	onEngage := c.health.onEngage
	engaged := c.health.engaged
	startProber := engaged && !c.health.probing && onEngage != nil
	if startProber {
		c.health.probing = true
	}
	c.health.mu.Unlock()
	if startProber {
		onEngage()
	}
	go c.verifyCredential(gen)
}

// verifyCredential performs ONE bounded gate-exempt handshake for gen and
// records the verdict it earns. A transport failure proves nothing about the
// credential and leaves it pending: the prober and the subscribe reconnect loop
// own reachability, and the next successful handshake will classify it.
func (c *Client) verifyCredential(gen uint64) {
	if c.isClosed() {
		return
	}
	// The verdict is recorded by the handshake itself (conn.ensureWithGate,
	// generation-tagged), so this only has to make the handshake happen.
	_ = gen
	c.probeAuthority()
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
			// The verdict was already latched, against the exact generation the
			// refused handshake offered, by conn.ensureWithGate.
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
		// Only an EXPLICIT refusal is terminal. A clean EOF before any ack is
		// a router or authority tearing the connection down mid-handshake; the
		// prober must keep going rather than declare a healthy credential dead.
		if errors.Is(err, ErrCredentialRefused) {
			return probeCredentialRejected
		}
		return probeUnreachable
	}
	return probeReachable
}
