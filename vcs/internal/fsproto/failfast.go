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
// publishes the credential every handshake reads, so a probe after renewal also
// recovers a previously-rejected handshake.
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
	// credentialVerifyInterval is the cadence at which an installed but still
	// UNPROVEN credential is re-offered to the authority. It only ever runs
	// inside the credential's OWN stated expiry (see connHealth.credExpiry),
	// so it is a bounded convergence loop, not an open-ended retry budget.
	credentialVerifyInterval = 2 * time.Second
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

	// ── THE UNPROVEN STATE HAS A BOUNDARY ───────────────────────────────────
	//
	// credPending had no timestamp, no deadline and no TTL. A credential that
	// was neither accepted nor refused therefore stayed pending FOREVER, and
	// the one interleaving that produces it in production — the router or
	// authority tearing the connection down cleanly after reading the token
	// frame but before answering ack (see ErrCredentialRefused) — never trips
	// the transport breaker either, because a clean EOF is not a transport
	// failure. So the mount latched nothing, engaged nothing, and reported
	// nothing: a permanent maybe.
	//
	// credExpiry closes that. It reports the CURRENT credential's own stated
	// expiry (unix ms; 0 = the issuer stated none), read live from the
	// credential source. Past that instant an unproven credential HARDENS into
	// the same definite verdict a refusal would have latched: the lease is
	// over by its own terms, so "we never found out" resolves to "dead", and
	// the operator gets the one instruction that works instead of an
	// indefinite pending state.
	//
	// It is installed once, at client construction, and is therefore read
	// WITHOUT h.mu — it reads the client's published credential, and nesting
	// the two locks would invent a lock order for no reason at all.
	//
	// It returns the expiry TOGETHER WITH the generation that expiry belongs
	// to. The pair is what makes the boundary safe to apply: an expiry read
	// for generation G says nothing about generation G+1, and hardening G+1
	// against G's deadline would declare a credential dead on a predecessor's
	// terms.
	credExpiry func() (int64, uint64)
}

func newConnHealth() *connHealth {
	return &connHealth{now: time.Now, credGen: 1, credPending: true}
}

// statedExpiry is the CURRENT credential's own stated expiry (unix ms) and the
// generation it belongs to; 0 expiry means the issuer stated none. Never called
// with h.mu held.
func (h *connHealth) statedExpiry() (int64, uint64) {
	if h == nil || h.credExpiry == nil {
		return 0, 0
	}
	return h.credExpiry()
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

// installCredential opens a new credential generation and PUBLISHES, under the
// same lock, the exact credential that generation names. The new generation is
// UNPROVEN — not healthy — until a handshake offering it says otherwise, which
// is what Client.InstallCredential goes on to run.
//
// publish runs while h.mu is held, so no observer can ever see a generation
// without its token or a token without its generation. That pairing is the
// whole point: the counter and the credential used to be written separately,
// and a handshake that read one before and the other after filed its verdict
// against a credential it had never presented.
func (h *connHealth) installCredential(publish func(gen uint64)) uint64 {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.credGen++
	h.credRejectedAt = 0
	h.credVerifiedAt = 0
	h.credPending = true
	if publish != nil {
		publish(h.credGen)
	}
	return h.credGen
}

// pendingLocked is the raw "no handshake has classified the current
// generation" predicate, before the expiry boundary is applied.
func (h *connHealth) pendingLocked() bool {
	return h.credPending && h.credVerifiedAt != h.credGen && h.credRejectedAt != h.credGen
}

// hardenedLocked reports that an unproven credential has outlived the deadline
// its OWN issuer stated for it, so the pending state resolves to dead.
//
// expiresAtMs of 0 is "the issuer stated no deadline" and can never harden:
// old CLIs, static --addr mounts and VCS_AUTH_TOKEN all land there, and none
// of them may start reporting a dead credential just because this boundary now
// exists. A deadline is only ever honoured when somebody actually stated one.
//
// expiryGen is the generation that deadline was published with. It is read
// outside h.mu, so an install can land in between; a deadline belonging to a
// SUPERSEDED credential says nothing about the current one, and applying it
// would harden a freshly installed credential on its predecessor's terms.
// A pair that no longer names the current generation simply does not apply.
func (h *connHealth) hardenedLocked(expiresAtMs int64, expiryGen uint64) bool {
	if expiresAtMs <= 0 || expiryGen != h.credGen || !h.pendingLocked() {
		return false
	}
	return !h.now().Before(time.UnixMilli(expiresAtMs))
}

// credentialDead reports the latched verdict for the CURRENT generation — or
// the HARDENED one: an unproven credential past its own stated expiry is dead
// by the issuer's own terms even though no handshake ever said so out loud.
func (h *connHealth) credentialDead() bool {
	if h == nil {
		return false
	}
	expiresAtMs, expiryGen := h.statedExpiry()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.credRejectedAt != 0 && h.credRejectedAt == h.credGen {
		return true
	}
	return h.hardenedLocked(expiresAtMs, expiryGen)
}

// credentialUnproven reports that the current generation has neither been
// accepted nor refused by any handshake yet AND is still inside whatever
// deadline its issuer stated. Past that deadline it is no longer unproven —
// it is expired (credentialDead), and the two states must never both be true:
// "we never found out" and "it is dead" call for different operator actions.
func (h *connHealth) credentialUnproven() bool {
	if h == nil {
		return false
	}
	expiresAtMs, expiryGen := h.statedExpiry()
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pendingLocked() && !h.hardenedLocked(expiresAtMs, expiryGen)
}

// generationPending reports whether gen is STILL the current generation and
// still unclassified. The credential verifier uses it to stop the moment its
// generation is superseded by a newer install or resolved by any handshake.
func (h *connHealth) generationPending(gen uint64) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return gen != 0 && gen == h.credGen && h.pendingLocked()
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
// accepted or refused by any handshake. It is neither healthy nor dead — it is
// UNTESTED — and a mount must not be reported as recovered on it.
//
// It is DISJOINT from CredentialRejected by construction: once the credential
// passes its own stated expiry the unproven state hardens into the rejected
// one, so exactly one of the two is ever true. The distinction is not
// cosmetic — the operator actions differ. Rejected means the authority
// answered "no": log in again. Unproven means the authority never answered at
// all, because something between the mount and it is tearing the handshake
// down before the ack: look at the router, not at the login.
func (c *Client) CredentialUnproven() bool { return c.health.credentialUnproven() }

// CredentialGeneration reports the generation of the credential this client is
// currently offering to handshakes. It exists so callers (and tests) can prove
// that ONE credential installation opens exactly ONE generation: the seam
// between clientcore and the daemon used to bump it twice — once through the
// token setter and once through a separate "installed" notification — opening a
// generation that nothing would ever go on to prove.
func (c *Client) CredentialGeneration() uint64 { return c.health.generation() }

// installVerify starts verification for a freshly opened generation and re-arms
// the reachability prober when the transport breaker had latched.
//
// It used to be the whole of installation: clear the verdict bool, and start
// the prober only when the breaker happened to be engaged. Installing a second
// INVALID credential therefore moved the mount from "credential rejected" to
// "healthy", with nothing anywhere having offered the new credential to anyone:
// the mount reported recovered and untested, and the next real op discovered
// the truth.
//
// Installation now enters VERIFICATION-PENDING (see connHealth.credPending) and
// runs the handshake at once. Only that handshake — offering this generation —
// can move it to verified or to latched-rejected.
func (c *Client) installVerify(gen uint64) {
	// A client with no health tracker (an embedder-built zero Client) opened no
	// generation, so there is nothing to verify and nobody to tell.
	if c.health == nil || gen == 0 {
		return
	}
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

// verifyCredential offers gen to the authority with bounded, gate-exempt
// handshakes until it is CLASSIFIED — or until the credential's own stated
// expiry says there is nothing left to classify.
//
// It used to be a single probe. One probe is enough when the answer arrives
// (accepted, or refused with ack 1), and it is enough when the peer is
// genuinely unreachable, because that trips the transport breaker and the
// reachability prober takes over. It is NOT enough for the interleaving this
// whole boundary exists for: a router or authority that closes cleanly after
// reading the token frame and before answering ack. That produces no ack to
// latch, no transport failure to count, and therefore no breaker, no prober
// and no second attempt — one probe, then silence, with the credential pending
// forever. A streak of those now gets re-offered.
//
// The loop is bounded by the credential's OWN stated expiry, exactly as the
// lease keeper bounds its unresolved renewals: past that instant the pending
// state hardens to dead (see connHealth.hardenedLocked) and there is nothing
// left to prove. A credential whose issuer stated NO deadline has no boundary
// to loop inside, so it keeps precisely the old single-probe behaviour rather
// than acquiring an open-ended retry loop this layer would have had to invent.
func (c *Client) verifyCredential(gen uint64) {
	for {
		if c.isClosed() {
			return
		}
		switch c.probeAuthority() {
		case probeReachable, probeCredentialRejected:
			// The handshake itself recorded the generation-tagged verdict
			// (conn.ensureWithGate); either way gen is now classified.
			return
		}
		// INCONCLUSIVE. Only keep offering while this exact generation is
		// still the live, still-unclassified one.
		if !c.health.generationPending(gen) {
			return
		}
		expiresAtMs, expiryGen := c.health.statedExpiry()
		if expiryGen != gen {
			// The deadline on offer belongs to some other credential; this
			// generation has been superseded and owns no boundary any more.
			return
		}
		if expiresAtMs <= 0 {
			// No stated deadline: no boundary, so no loop.
			return
		}
		if !c.health.now().Before(time.UnixMilli(expiresAtMs)) {
			// The credential is over by its own terms; it has hardened.
			return
		}
		select {
		case <-c.closed:
			return
		case <-time.After(credentialVerifyInterval):
		}
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
			// re-arms it (see InstallCredential).
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
// current credential (credentialForHandshake reads the published value, so a
// credential install is picked up automatically, and the verdict it records
// names that installation's own generation); an explicit token rejection proves
// it is reachable and this credential is dead.
func (c *Client) probeAuthority() probeOutcome {
	cn := &conn{
		addrs:       c.addrs,
		tls:         c.tls,
		auth:        c.credentialForHandshake,
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
