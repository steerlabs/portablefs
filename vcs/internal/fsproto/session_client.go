package fsproto

// Exact mount sessions, client side.
//
// The client mints a stable random session identity (id + token) once per
// mount instance, establishes it durably on the authority, and stamps every
// write-through mutation with an exact-once identity: (session, generation,
// slot, slot sequence). Slots bound concurrency; each slot carries at most one
// in-flight identity, and its sequence advances ONLY on a definite reply.
//
// A request whose outcome is UNKNOWN (connection died after the request may
// have durably prepared) is PARKED: a background replayer resends the
// IDENTICAL identity — never a fresh one — until the authority answers
// definitively (executed exactly once, or the stored duplicate outcome, or a
// fence). The slot stays unavailable meanwhile, so the identity can never be
// reused for different bytes.
//
// A fenced/expired session never re-establishes a fresh generation by itself:
// every subsequent mutation fails ESTALE until the operator remounts. That is
// deliberate — an automatic new generation would let a zombie mount overwrite
// state a successor already took over.
//
// Sessions are mandatory: the client requires the authority to negotiate
// exactly ProtocolVersion (v8) and refuses anything else. PFRQ2 peers return
// a typed version mismatch; older request-wire peers fail closed at framing.
// There is no legacy downgrade.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// DefaultExactSlots bounds a mount's concurrent in-flight exact mutations.
const DefaultExactSlots = 64

// exactForegroundAttempts is how many transport attempts a FUSE-blocking
// mutation makes before parking its identity with the background replayer and
// surfacing ErrMutationUnknown (the identity is never reused).
const exactForegroundAttempts = 3

// parkRetryMin/Max bound the background replayer's backoff.
const (
	parkRetryMin = 250 * time.Millisecond
	parkRetryMax = 5 * time.Second
)

// exactGateRetryDelay paces re-issuing an exact mutation after the
// authority's delegation gate returned a definite EAGAIN mid-recall. The
// recall it timed out on is already in flight, so the next attempt usually
// succeeds; the delay only prevents a tight identity-consuming loop.
const exactGateRetryDelay = 250 * time.Millisecond

// exactGateRetryBudget bounds how long DoContext keeps re-issuing after
// definite gate EAGAINs before surfacing the last one. Each server-side gate
// attempt already waits a full recall timeout, so a budget of a few recall
// timeouts covers every converging recall while a scope stuck behind a dead
// holder's recovery delegation still surfaces instead of blocking until
// lease expiry. Variable (not const) so tests can compress it.
var exactGateRetryBudget = 90 * time.Second

// ErrMutationUnknown is returned when a mutation's outcome could not be
// determined within the foreground budget. The identity is parked and will be
// replayed until definite; it is NEVER reused for a different request.
var ErrMutationUnknown = errors.New("fsproto: mutation outcome unknown; identity parked for replay")

// ErrSessionFenced is returned once the mount session has been fenced or
// superseded: no further mutations are possible from this mount instance.
var ErrSessionFenced = errors.New("fsproto: mount session fenced (stale generation); remount required")

// exactSession is the client's mount-session state.
type exactSession struct {
	id    string
	token string
	gen   uint64
	owner string
	slots uint32
	// features is the immutable bitmap returned by the protocol probe that
	// preceded this session's establishment.
	features uint64

	mu     sync.Mutex
	fenced bool
	seq    []uint64 // per-slot last COMMITTED sequence
	avail  chan uint32
	// leaseMs is the lease lifetime the authority last stated, and expiresAt is
	// the LOCAL monotonic deadline that statement anchors to. See noteLease.
	leaseMs   int64
	expiresAt time.Time
	stopOnce  sync.Once
	stop      chan struct{}
}

// noteLease records the authority's own statement about this session's lease.
//
// ── WHY THIS IS SKEW-FREE, AND WHY IT ANCHORS AT SEND TIME ──────────────────
//
// The authority never states an absolute expiry on the wire. OpSessionOpen
// answers with the full TTL and OpSessionResume/OpSessionAttach answer with
// time.Until(storedExpiry) — both computed on the authority, both RELATIVE
// durations (see Server.sessionOpen/sessionResume). Nothing in this protocol
// ever compares a client timestamp with an authority timestamp, so there is no
// clock skew to handle: a remaining-duration is converted against the client's
// own monotonic clock and is correct however far apart the two wall clocks are.
//
// sentAt is when the REQUEST left, not when the reply landed. The authority
// computed the remaining lease somewhere inside that round trip, so anchoring
// at send time understates the true expiry by at most one round trip and can
// never overstate it. Understating is the safe direction: it renews early.
func (es *exactSession) noteLease(sentAt time.Time, leaseMs int64) {
	if leaseMs <= 0 {
		return
	}
	es.mu.Lock()
	es.leaseMs = leaseMs
	es.expiresAt = sentAt.Add(time.Duration(leaseMs) * time.Millisecond)
	es.mu.Unlock()
}

// leaseWindow returns the last CONFIRMED expiry and the lifetime it was
// confirmed for. A zero expiry means no authority statement has been recorded.
func (es *exactSession) leaseWindow() (expiry time.Time, ttl time.Duration) {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.expiresAt, time.Duration(es.leaseMs) * time.Millisecond
}

func newExactSession(owner string, slots uint32) (*exactSession, error) {
	if slots == 0 {
		slots = DefaultExactSlots
	}
	if slots > MaxSessionSlots {
		slots = MaxSessionSlots
	}
	id, err := randToken(12)
	if err != nil {
		return nil, err
	}
	token, err := randToken(24)
	if err != nil {
		return nil, err
	}
	es := &exactSession{
		id:    "pfs-" + id,
		token: "pfstok_" + token,
		gen:   1,
		owner: owner,
		slots: slots,
		seq:   make([]uint64, slots),
		avail: make(chan uint32, slots),
		stop:  make(chan struct{}),
	}
	for i := uint32(0); i < slots; i++ {
		es.avail <- i
	}
	return es, nil
}

func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("fsproto: mint exact-session credential: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (es *exactSession) isFenced() bool {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.fenced
}

// fence permanently disables the session client-side (server fenced it, its
// lease expired, or its generation was superseded). Idempotent.
func (es *exactSession) fence() {
	es.mu.Lock()
	es.fenced = true
	es.mu.Unlock()
	es.stopOnce.Do(func() { close(es.stop) })
}

// acquire reserves a slot and returns its next (uncommitted) sequence. It
// blocks while every slot is in flight or parked; deadline bounds the wait.
func (es *exactSession) acquire(deadline time.Duration) (slot uint32, seq uint64, err error) {
	if es.isFenced() {
		return 0, 0, ErrSessionFenced
	}
	t := time.NewTimer(deadline)
	defer t.Stop()
	select {
	case slot = <-es.avail:
	case <-es.stop:
		return 0, 0, ErrSessionFenced
	case <-t.C:
		return 0, 0, errors.New("fsproto: no exact-mutation slot available (all identities in flight or parked)")
	}
	es.mu.Lock()
	seq = es.seq[slot] + 1
	es.mu.Unlock()
	return slot, seq, nil
}

// commit records a definite outcome for (slot, seq) and frees the slot.
func (es *exactSession) commit(slot uint32, seq uint64) {
	es.mu.Lock()
	es.seq[slot] = seq
	fenced := es.fenced
	es.mu.Unlock()
	if !fenced {
		es.avail <- slot
	}
}

// abort frees a slot WITHOUT advancing its sequence — legal only when the
// request was provably never sent (no bytes hit a connection).
func (es *exactSession) abort(slot uint32) {
	if !es.isFenced() {
		es.avail <- slot
	}
}

func (es *exactSession) envelope(slot uint32, seq uint64) *wal.Envelope {
	return &wal.Envelope{SessionID: es.id, Generation: es.gen, Slot: slot, SlotSeq: seq}
}

// ---- client wiring ----

// exactState returns the client's session (nil if not established).
func (c *Client) exactState() *exactSession {
	c.exactMu.RLock()
	defer c.exactMu.RUnlock()
	return c.exact
}

// SetExactSlots bounds this mount's concurrent in-flight exact mutations.
// Call before the first mutation (0 = DefaultExactSlots).
func (c *Client) SetExactSlots(n uint32) { c.exactSlots = n }

// ExactSessionActive reports whether an exact session is live (established and
// not fenced).
func (c *Client) ExactSessionActive() bool {
	es := c.exactState()
	return es != nil && !es.isFenced()
}

// SessionFenced reports whether the mount session was fenced (stale
// generation / lease lost). A fenced mount must not flush old dirty bytes and
// never mints a fresh generation; remount to recover.
func (c *Client) SessionFenced() bool {
	es := c.exactState()
	return es != nil && es.isFenced()
}

func (c *Client) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *Client) takeConn() (*conn, error) {
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case cn := <-c.conns:
		if c.isClosed() {
			c.conns <- cn
			return nil, net.ErrClosed
		}
		return cn, nil
	}
}

func (c *Client) takeConnContext(ctx context.Context) (*conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, net.ErrClosed
	case cn := <-c.conns:
		if err := ctx.Err(); err != nil {
			c.conns <- cn
			return nil, err
		}
		if c.isClosed() {
			c.conns <- cn
			return nil, net.ErrClosed
		}
		return cn, nil
	}
}

// EnsureExactSession establishes the mount session, negotiating the protocol
// version first: the authority must speak exactly ProtocolVersion (v8).
// Returns (true, nil) when the session is live and an error otherwise —
// including ErrProtocolVersionMismatch against an older authority. There is
// no legacy downgrade.
//
// It never holds exactMu across network I/O (pool users take exactMu.RLock
// while holding a pooled conn; holding the write lock while waiting for a
// conn would invert that order and deadlock). establishMu serializes the
// one-time establish instead.
func (c *Client) EnsureExactSession() (bool, error) {
	if es := c.exactState(); es != nil {
		return !es.isFenced(), nil
	}
	c.establishMu.Lock()
	defer c.establishMu.Unlock()
	if es := c.exactState(); es != nil {
		return !es.isFenced(), nil
	}
	probe, err := c.doRaw(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)}, true)
	if err != nil {
		return false, err
	}
	if probe.Status != OK || probe.ProtoVersion != ProtocolVersion {
		return false, &ErrProtocolVersionMismatch{ServerVersion: probe.ProtoVersion}
	}
	es, err := newExactSession(c.owner, c.exactSlots)
	if err != nil {
		return false, err
	}
	es.features = probe.Features
	// The exact (id, gen, owner, slots, token) tuple is idempotent, so a lost
	// establish reply is safely replayed with the identical tuple.
	var resp *Response
	var sentAt time.Time
	for attempt := 0; attempt < exactForegroundAttempts; attempt++ {
		sentAt = time.Now()
		resp, err = c.doRaw(&Request{
			Op: OpSessionOpen, SessionID: es.id, SessionGen: es.gen,
			SessionToken: es.token, SessionSlots: es.slots, Owner: es.owner,
		}, true)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false, err
	}
	switch resp.Status {
	case OK:
	case ESTALE:
		// A 96-bit random id colliding with a live tombstone is not a chance
		// event; treat as fenced (never bump the generation automatically).
		es.fence()
		c.exactMu.Lock()
		c.exact = es
		c.exactMu.Unlock()
		return false, ErrSessionFenced
	default:
		return false, statusError("session open", resp.Status)
	}
	if resp.SessionSlots != 0 && resp.SessionSlots < es.slots {
		// Authority narrowed the slot budget; honor it. No identity has been
		// handed out yet (establish precedes first acquire), so rebuild the
		// free list with only in-budget slot ids.
		for len(es.avail) > 0 {
			<-es.avail
		}
		es.slots = resp.SessionSlots
		es.seq = es.seq[:es.slots]
		for i := uint32(0); i < es.slots; i++ {
			es.avail <- i
		}
	}
	// The authority's own statement, anchored at SEND time. The whole renewal
	// schedule is measured from this, not from loop iterations.
	es.noteLease(sentAt, resp.LeaseMs)
	c.exactMu.Lock()
	c.exact = es
	c.exactMu.Unlock()
	go c.renewLoop(es)
	return true, nil
}

// Features returns the optional capability bitmap negotiated before the
// current exact session was established. Zero means either no live session
// or an authority that advertises no optional features.
func (c *Client) Features() uint64 {
	es := c.exactState()
	if es == nil {
		return 0
	}
	return es.features
}

// ── THE LEASE IS NOT DATA (ROUND 16, DEFECT B) ──────────────────────────────
//
// The renewal used to run through doRaw, which takes a POOLED connection, and
// takeConn is an unbounded blocking receive on a pool of four that every
// write-through mutation also draws from — each holding its connection for up
// to opTimeout (60s). Four concurrent bulk writes is therefore all it takes to
// stop the lease renewing, and a burst produces far more than four.
//
// Measured live: 768 MiB written unpaced at 110 MB/s (every byte on the
// uncharged authority lane, so nothing paced it) starved the renewal past the
// 90-second lease TTL. The authority's sweeper journaled the session terminal,
// the next reply was ESTALE, finishExact fenced the session PERMANENTLY, and
// 734 MiB of data the kernel had already acknowledged to the application was
// lost at the deferred flush. The same 768 MiB paced at 8 MB/s was byte-exact.
//
// This is the identical disease the authority-manager's claim heartbeat had one
// commit ago, and it takes the identical cure: the renewal gets a RESERVED
// transport of its own, so no amount of data-plane traffic can queue in front of
// the one call that keeps this mount alive. Two further properties come with it,
// both borrowed from the manager fix:
//
//   - EACH ATTEMPT IS BOUNDED TO ONE INTERVAL. Two slow attempts can no longer
//     overrun the TTL between them; a hung attempt is abandoned and the next
//     tick redials.
//   - EVERY FAILURE MODE IS SILENCE. A renewal that cannot be made simply does
//     not move the lease, and the authority fences on schedule — which is the
//     correct, conservative outcome and exactly what happened before.
//
// It is deliberately NOT a wider change to the pool. The pool is sized for the
// data plane and should be; what was wrong is that a control-plane obligation
// was drawing from it at all.
func (c *Client) renewLoop(es *exactSession) {
	c.renewLoopWith(es, realLeaseClock(), c.renewOnce)
}

// leaseClock is the renewal loop's whole view of time. The loop takes it as a
// parameter so its SCHEDULE can be tested deterministically against injected
// latencies instead of raced against the wall clock.
type leaseClock struct {
	now   func() time.Time
	after func(time.Duration) <-chan time.Time
}

func realLeaseClock() leaseClock { return leaseClock{now: time.Now, after: time.After} }

// leaseAttempt is one bounded renewal attempt: dial + authenticate + round
// trip, all inside budget. renewed is true only when the authority confirmed a
// fresh expiry; fenced is true only when it definitely refused the generation.
type leaseAttempt func(es *exactSession, budget time.Duration) (renewed, fenced bool)

// ── ROUND 17b: THE SCHEDULE AROUND THE RESERVED TRANSPORT ───────────────────
//
// The reservation above is sound. The schedule around it was not, and it left a
// hole the exact size of the lease.
//
// The loop used to tick on a fixed cadence of TTL/3 (30s for a 90s lease),
// sleeping a full cadence BEFORE every attempt and another full cadence after a
// failed one, with the advertised per-attempt bound covering only the round trip
// — leaseConn's dial and authentication happened before it and outside it.
// Worked example, 90s lease:
//
//	t=30   first renewal starts
//	t=45   ~15s dialing and authenticating, NOT inside the 30s bound
//	t=75   30s round trip hits the bound and fails
//	t=105  the next attempt — 15 seconds after the lease died at t=90
//
// One failure inside a 90-second lease was therefore enough to lose it, and even
// on an already-connected transport a single full-bound failure ended at t=60
// and put the next attempt exactly on the expiry boundary with zero margin.
//
// FOUR CHANGES, AND THE INVARIANT THEY BUY:
//
//   - SCHEDULE FROM THE LAST CONFIRMED AUTHORITY EXPIRY, never from loop
//     iterations. The authority states its own remaining lease on every
//     open/resume; noteLease anchors it to the local monotonic clock at SEND
//     time. The cost of a slow round trip is therefore charged to our own slack
//     instead of pushing the next renewal past the lease.
//   - ONE BUDGET COVERS DIAL + AUTH + REQUEST. renewOnce takes a deadline and
//     spends it across the whole attempt, so nothing happens outside the bound
//     the loop is reasoning about.
//   - A FAILED ATTEMPT RETRIES IMMEDIATELY, with bounded exponential backoff
//     (leaseRetryMin..leaseRetryMax), not a cadence later. The remaining window
//     is the scarce resource; sleeping a full interval in it is the defect.
//   - A STRICT PRE-EXPIRY MARGIN. The loop works against deadline =
//     expiry - leaseMargin(ttl), never against expiry itself.
//
// INVARIANT (>= 2 ATTEMPTS BEFORE EXPIRY). At every attempt start the budget is
// at most HALF the time remaining until that margin deadline. So an attempt that
// consumes its entire budget and fails still leaves at least half the window it
// started with — strictly more than one further complete attempt — and by
// induction attempts keep fitting until the window shrinks to the retry pacing.
// Concretely, for a 90s lease the first attempt of a term starts at t=30 with
// 51s of pre-margin window and a 20s budget: at least four bounded attempts
// finish strictly before t=90, and never fewer than two.
//
// The safety direction is UNCHANGED. Every failure mode is still silence: a
// lease that cannot be renewed is not renewed, the authority fences on schedule,
// and only a definite ESTALE fences the session client-side. The floor budget
// past the margin exists only so a lease that is going to lapse learns it from a
// definite ESTALE promptly, rather than after another whole cadence of quiet.
const (
	// leaseAttemptMax caps one renewal attempt however much window is left: a
	// single attempt should not be able to hold the whole term.
	leaseAttemptMax = 20 * time.Second
	// leaseAttemptMin is the floor budget used once the pre-expiry window is
	// spent. It is not part of the >= 2 invariant, which is proved at the start
	// of the window; it exists only so an attempt past the margin is still long
	// enough to collect a definite answer (typically the ESTALE that ends the
	// loop) instead of failing on its own budget.
	leaseAttemptMin = 2 * time.Second
	// leaseRetryMin/Max pace the IMMEDIATE retry of a failed attempt.
	//
	// The steady state of leaseRetryMax is deliberate. When the failure is a
	// definite credential refusal — this transport authenticates with the
	// mount's access credential like every other — nothing the loop sends can
	// repair it, and one dial every 5s against a refusing authority is the
	// price of noticing a REPLACEMENT credential within 5s of its install. The
	// reachability prober makes the opposite trade (it stops on refusal)
	// because it has no obligation with an expiry attached; this loop does.
	leaseRetryMin = 250 * time.Millisecond
	leaseRetryMax = 5 * time.Second
	// leaseFallbackTTL is used only when the authority stated no lease at all
	// (a peer that answers OK with LeaseMs == 0). Renewing conservatively
	// against an unstated lease is better than not renewing.
	leaseFallbackTTL = 30 * time.Second
)

// leaseRenewLead is how long before the confirmed expiry a renewal term opens:
// one third of the lease elapses first, leaving two thirds of it as the window
// the invariant above is proved in.
func leaseRenewLead(ttl time.Duration) time.Duration { return ttl * 2 / 3 }

// leaseMargin is the strict pre-expiry margin the loop keeps clear. Attempts are
// scheduled against expiry-margin, so the last scheduled attempt still has
// margin left to land in.
func leaseMargin(ttl time.Duration) time.Duration {
	m := ttl / 10
	if m < time.Second {
		m = time.Second
	}
	if m > 10*time.Second {
		m = 10 * time.Second
	}
	return m
}

func (c *Client) renewLoopWith(es *exactSession, clk leaseClock, attempt leaseAttempt) {
	defer c.releaseLeaseConn()
	backoff := leaseRetryMin
	for {
		expiry, ttl := es.leaseWindow()
		if ttl <= 0 {
			ttl = leaseFallbackTTL
		}
		if expiry.IsZero() {
			expiry = clk.now().Add(ttl)
		}
		deadline := expiry.Add(-leaseMargin(ttl))

		now := clk.now()
		wait := backoff
		if due := expiry.Add(-leaseRenewLead(ttl)); now.Before(due) {
			// A confirmed lease with time still to run: sleep to the point where
			// this term's renewal is due, and reset the retry pacing with it.
			wait = due.Sub(now)
			backoff = leaseRetryMin
		}
		if !c.leaseWait(es, clk, wait) {
			return
		}

		// HALF the remaining pre-margin window, so a fully consumed failure
		// always leaves room for at least one more complete attempt.
		budget := deadline.Sub(clk.now()) / 2
		if budget > leaseAttemptMax {
			budget = leaseAttemptMax
		}
		if budget < leaseAttemptMin {
			budget = leaseAttemptMin
		}
		renewed, fenced := attempt(es, budget)
		if fenced {
			return
		}
		if renewed {
			backoff = leaseRetryMin
			continue
		}
		if backoff *= 2; backoff > leaseRetryMax {
			backoff = leaseRetryMax
		}
	}
}

// leaseWait sleeps d, or returns false if the session or the client ended
// first. The terminal channels are checked BEFORE the timer so a loop driven by
// a compressed clock cannot win a select race against its own shutdown.
func (c *Client) leaseWait(es *exactSession, clk leaseClock, d time.Duration) bool {
	select {
	case <-es.stop:
		return false
	case <-c.closed:
		return false
	default:
	}
	if d <= 0 {
		return true
	}
	select {
	case <-es.stop:
		return false
	case <-c.closed:
		return false
	case <-clk.after(d):
		return true
	}
}

// renewOnce makes one lease renewal on the session's own reserved transport and
// reports whether the session was definitely fenced by it.
//
// bound is one renewal interval: an attempt that cannot finish inside its own
// tick has already lost that tick, and holding the reserved transport past it
// would only make the NEXT tick late too.
func (c *Client) renewOnce(es *exactSession, bound time.Duration) (renewed, fenced bool) {
	if bound <= 0 {
		return false, false
	}
	deadline := time.Now().Add(bound)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	cn, err := c.leaseConnContext(ctx)
	if err != nil {
		// Dialing or AUTHENTICATING the reserved transport failed. This is the
		// one failure the old code called "transport trouble" and dropped on the
		// floor — and it is exactly where an access-lease credential rejection
		// arrives, because this transport authenticates with the mount's access
		// credential like every other. Record it so the failure has a name
		// somewhere; the loop's answer is unchanged and deliberately so (retry,
		// stay silent, let the authority fence on schedule) because nothing this
		// loop can do repairs a dead credential — only a credential install can,
		// and that re-arms this path automatically.
		c.noteRenewFailure(err)
		return false, false
	}
	// sentAt is the anchor for whatever expiry the authority states back. It is
	// read BEFORE the request goes out so the confirmed expiry can only ever be
	// understated (see noteLease).
	sentAt := time.Now()
	left := deadline.Sub(sentAt)
	if left <= 0 {
		// The dial and auth consumed the whole attempt. That is a failed attempt,
		// not a licence to overrun: the loop retries immediately with what is
		// left of the pre-expiry window.
		c.noteRenewFailure(context.DeadlineExceeded)
		return false, false
	}
	resp, err := cn.boundedRoundtrip(&Request{
		Op: OpSessionResume, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
	}, left)
	if err != nil {
		// The reserved transport is this loop's alone, so a failed roundtrip may
		// have left it mid-frame with nobody else to notice. Retire it; the next
		// attempt dials a fresh one.
		c.releaseLeaseConn()
		c.noteRenewFailure(err)
		return false, false
	}
	if resp.Status == ESTALE {
		es.fence()
		return false, true
	}
	if resp.Status != OK {
		c.noteRenewFailure(statusError("session resume", resp.Status))
		return false, false
	}
	// THE AUTHORITY'S OWN STATEMENT, not an assumption. sessionResume answers
	// with time.Until(storedExpiry) — the remaining lease as the authority sees
	// it — so a lease the authority shortened, lengthened, or measured
	// differently than we did is tracked rather than guessed at. A peer that
	// answers OK while stating no lease at all gets the conservative fallback
	// rather than an unmoved expiry, which would spin this loop.
	stated := resp.LeaseMs
	if stated <= 0 {
		stated = leaseFallbackTTL.Milliseconds()
	}
	es.noteLease(sentAt, stated)
	c.noteRenewFailure(nil)
	return true, false
}

// noteRenewFailure records the last renewal outcome. nil clears it.
//
// It exists because "the renewal is quietly failing" and "the renewal is fine"
// used to be indistinguishable from outside this file, and the failure that
// matters most — the access credential this transport authenticates with having
// been rejected — arrived on the one path that returned a bare false.
func (c *Client) noteRenewFailure(err error) {
	c.renewMu.Lock()
	c.renewErr = err
	c.renewMu.Unlock()
}

// LeaseRenewalError reports the last session-lease renewal failure, or nil when
// the last attempt confirmed a fresh expiry. It is diagnostic only: the mount's
// behaviour is decided by the authority's fence, never by this value.
func (c *Client) LeaseRenewalError() error {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()
	return c.renewErr
}

// leaseConn returns the session lease's reserved transport, dialing it on first
// use. It is registered as a DEDICATED conn, so it is interrupted and joined by
// the client's own close exactly like the subscribe stream.
//
// gateExempt for the same reason the subscribe stream is: the lease is a
// recovery-critical path, and refusing to dial it while the fail-fast breaker is
// engaged would guarantee the fence the breaker is trying to survive.
func (c *Client) leaseConn() (*conn, error) {
	return c.leaseConnContext(context.Background())
}

// leaseConnContext is leaseConn bounded by ctx. The bound is the point: the dial
// and the authentication handshake are part of the renewal ATTEMPT and must be
// spent from the attempt's budget, not from dialTimeout + dialHandshakeTimeout
// (15s of constants nothing above this line knew about).
//
// ctx alone is not sufficient to interrupt an authenticating socket, so the
// cancellation also closes it — adoptTransport publishes the socket BEFORE the
// handshake for exactly this reason. The interrupt goroutine is JOINED before
// returning, so no interrupt can leak onto the transport a later attempt dials.
func (c *Client) leaseConnContext(ctx context.Context) (*conn, error) {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()
	if c.renewConn != nil {
		return c.renewConn, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cn := &conn{
		addrs:       c.addrs,
		tls:         c.tls,
		auth:        c.credentialForHandshake,
		transport:   c.transport,
		client:      c,
		health:      c.health,
		gateExempt:  true,
		dialTimeout: leaseDialTimeout(ctx),
	}
	if !c.registerDedicated(cn) {
		return nil, net.ErrClosed
	}
	stopInterrupt := make(chan struct{})
	interruptDone := make(chan struct{})
	go func() {
		defer close(interruptDone)
		select {
		case <-ctx.Done():
			cn.interrupt()
		case <-stopInterrupt:
		}
	}()
	err := cn.ensureWithGateContext(ctx, false)
	close(stopInterrupt)
	<-interruptDone
	if err != nil {
		cn.reset()
		c.unregisterDedicated(cn)
		return nil, err
	}
	if c.isClosed() {
		cn.reset()
		c.unregisterDedicated(cn)
		return nil, net.ErrClosed
	}
	c.renewConn = cn
	return cn, nil
}

// leaseDialTimeout bounds the TCP connect by whatever remains of the attempt's
// budget, so a blackholed authority costs this attempt and no more. Zero keeps
// the package default for an unbounded caller.
func leaseDialTimeout(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	d := time.Until(deadline)
	if d <= 0 {
		return time.Millisecond
	}
	if d > dialTimeout {
		return dialTimeout
	}
	return d
}

// releaseLeaseConn retires the reserved transport. It is idempotent, and safe to
// call from the renew loop's exit as well as from a failed attempt.
func (c *Client) releaseLeaseConn() {
	c.renewMu.Lock()
	cn := c.renewConn
	c.renewConn = nil
	c.renewMu.Unlock()
	if cn == nil {
		return
	}
	cn.reset()
	c.unregisterDedicated(cn)
}

// doRaw runs one session-management request (probe/open/resume) on a pooled
// connection WITHOUT session attach. These are all lost-response safe by
// construction, so retry re-sends the identical request once after a
// transport error.
func (c *Client) doRaw(req *Request, retry bool) (*Response, error) {
	cn, err := c.takeConn()
	if err != nil {
		return nil, err
	}
	defer func() { c.conns <- cn }()
	resp, err := cn.roundtrip(req)
	if err != nil && retry {
		resp, err = cn.roundtrip(req)
	}
	return resp, err
}

// doAttached runs one session-scoped request on a pooled connection that has
// this session authenticated onto it (attaching first if the conn re-dialed).
// ReclaimDone/SessionExpire prove identity by the ATTACHED connection, so a
// bare roundtrip on a fresh conn would be silently ignored server-side.
func (c *Client) doAttached(req *Request, retry bool) (*Response, error) {
	resp, sent, err := c.roundtripAttached(req)
	if err != nil && retry && sent {
		resp, _, err = c.roundtripAttached(req)
	}
	return resp, err
}

// roundtripAttached performs one session-attached request attempt. sent is
// false only when the request itself provably never reached a transport
// (taking/dialing/attaching failed first). Once cn.roundtrip is entered an
// error is conservatively ambiguous: request bytes may have reached the
// authority even if encoding or reading the reply failed.
func (c *Client) roundtripAttached(req *Request) (resp *Response, sent bool, err error) {
	return c.roundtripAttachedWithGate(req, false)
}

// roundtripAttachedContext is the cancellable form used by the write-back
// flusher. Cancellation interrupts the checked-out transport and then JOINS
// the roundtrip before returning. That join is the important ordering
// property: a timed-out digest batch can never remain live in a detached
// goroutine while the flusher submits a later batch for the same stream.
// The caller may safely replay the identical digest-addressed batch after an
// ambiguous error.
func (c *Client) roundtripAttachedContext(ctx context.Context, req *Request) (resp *Response, sent bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	cn, err := c.takeConnContext(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { c.conns <- cn }()

	stopInterrupt := make(chan struct{})
	interruptDone := make(chan struct{})
	go func() {
		defer close(interruptDone)
		select {
		case <-ctx.Done():
			cn.interrupt()
		case <-stopInterrupt:
		}
	}()
	defer func() {
		close(stopInterrupt)
		<-interruptDone
	}()

	if err := c.prepareConnContext(ctx, cn); err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, false, err
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	resp, sent, err = cn.roundtripSentWithGateContext(ctx, req, false)
	if err != nil && ctx.Err() != nil {
		return nil, sent, ctx.Err()
	}
	return resp, sent, err
}

func (c *Client) roundtripAttachedWithGate(req *Request, resolved bool) (resp *Response, sent bool, err error) {
	cn, err := c.takeConn()
	if err != nil {
		return nil, false, err
	}
	defer func() { c.conns <- cn }()
	if err := c.prepareConnWithGate(cn, resolved); err != nil {
		return nil, false, err
	}
	return cn.roundtripSentWithGate(req, resolved)
}

// doAttachedResolved runs an idempotent, session-scoped operation whose
// successful execution has durable side effects but no exact slot recording
// its response. A pre-send failure is definite and returns immediately. Once
// any attempt may have reached the authority, the identical request is replayed
// until its reply is known, the session is fenced, or the client closes.
//
// This is intentionally the envelope-less counterpart of
// doCoordinateResolved. Callers must retain any local serialization barrier
// that makes the operation idempotent for this method's whole lifetime.
func (c *Client) doAttachedResolved(req *Request) (*Response, error) {
	es := c.exactState()
	if es == nil || es.isFenced() {
		return &Response{Status: ESTALE}, nil
	}
	sent := false
	backoff := parkRetryMin
	var lastErr error
	for {
		resp, wasSent, err := c.roundtripAttachedWithGate(req, true)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		sent = sent || wasSent
		if !sent {
			// The operation never crossed the attached transport, so it has no
			// durable side effect to discover.
			if es.isFenced() {
				return &Response{Status: ESTALE}, nil
			}
			return nil, err
		}
		select {
		case <-es.stop:
			// Terminalization releases the generation's pins, making the
			// unresolved prepare harmless and its session outcome definite.
			return &Response{Status: ESTALE}, nil
		case <-c.closed:
			return nil, lastErr
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > parkRetryMax {
			backoff = parkRetryMax
		}
	}
}

// prepareConn dials (if needed) and attaches the client's exact session onto
// the transport, so subsequent mutations on it pass the server's envelope==
// connection-session check. A definite ESTALE on attach fences the session.
func (c *Client) prepareConn(cn *conn) error {
	return c.prepareConnWithGate(cn, false)
}

func (c *Client) prepareConnContext(ctx context.Context, cn *conn) error {
	return c.prepareConnContextWithGate(ctx, cn, false)
}

func (c *Client) prepareConnContextWithGate(ctx context.Context, cn *conn, resolved bool) error {
	if err := cn.ensureWithGateContext(ctx, resolved); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	es := c.exactState()
	if es == nil || es.isFenced() || cn.attached == es.id {
		return nil
	}
	resp, _, err := cn.roundtripSentWithGateContext(ctx, &Request{
		Op: OpSessionAttach, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
	}, resolved)
	if err != nil {
		return err
	}
	if resp.Status != OK {
		if resp.Status == ESTALE {
			es.fence()
		}
		return statusError("session attach", resp.Status)
	}
	cn.attached = es.id
	return nil
}

func (c *Client) prepareConnWithGate(cn *conn, resolved bool) error {
	if err := cn.ensureWithGate(resolved); err != nil {
		return err
	}
	es := c.exactState()
	if es == nil || es.isFenced() || cn.attached == es.id {
		return nil
	}
	resp, _, err := cn.roundtripSentWithGate(&Request{
		Op: OpSessionAttach, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
	}, resolved)
	if err != nil {
		return err
	}
	if resp.Status != OK {
		if resp.Status == ESTALE {
			es.fence()
		}
		return statusError("session attach", resp.Status)
	}
	cn.attached = es.id
	return nil
}

// ExpireSession voluntarily fences this session (clean unmount): the authority
// releases its lease-owned locks/delegations immediately and durably.
func (c *Client) ExpireSession() {
	es := c.exactState()
	if es == nil || es.isFenced() {
		return
	}
	_, _ = c.doAttached(&Request{Op: OpSessionExpire, SessionID: es.id, SessionGen: es.gen}, false)
	es.fence()
}

// doExact executes exactly one mutation identity. Every definite server reply
// (including EAGAIN) commits that identity and returns immediately; transport
// failures replay only the IDENTICAL identity. Managed exact admission has no
// client-visible reclaim-grace status distinct from delegation contention, so
// blanket fresh-identity EAGAIN retry would turn one bounded recall timeout
// into a full opTimeout stall and could repeat a real lock/contention result.
//
// ctx carries only the park-transfer hook (WithParkTransfer): an exact
// identity is never abandoned on cancellation, but if it parks, the exclusion
// the caller issued it under must travel with it.
func (c *Client) doExact(ctx context.Context, req *Request) (*Response, error) {
	return c.doExactOnce(ctx, req)
}

func (c *Client) doExactOnce(ctx context.Context, req *Request) (*Response, error) {
	es := c.exactState()
	if es == nil {
		live, err := c.EnsureExactSession()
		if err != nil {
			return nil, err
		}
		if !live {
			return &Response{Status: ESTALE}, nil
		}
		es = c.exactState()
	}
	if es.isFenced() {
		return &Response{Status: ESTALE}, nil
	}
	slot, seq, err := es.acquire(opTimeout)
	if err != nil {
		return nil, err
	}
	req.Env = es.envelope(slot, seq)
	if req.Owner == "" {
		req.Owner = c.owner
	}
	sent := false
	for attempt := 0; attempt < exactForegroundAttempts; attempt++ {
		resp, wasSent, rerr := c.roundtripExact(req)
		if rerr == nil {
			// Every definite reply is a durable outcome (grants, ENOENT,
			// EEXIST, EAGAIN alike): the identity is consumed and the
			// sequence advances. There is no unrecorded definite flow — an
			// outcome the authority could not durably record is replied as
			// NOTHING (transport drop) and replayed.
			c.finishExact(es, slot, seq, resp)
			return resp, nil
		}
		sent = sent || wasSent
		if !sent {
			// Nothing ever hit a connection: the identity is provably unused
			// (dialing or the pre-send session attach failed).
			es.abort(slot)
			if es.isFenced() {
				// The attach's definite ESTALE fenced the session before the
				// mutation could be sent: it never executed and never will
				// from this generation. That is a definite outcome.
				return &Response{Status: ESTALE}, nil
			}
			return nil, rerr
		}
	}
	// UNKNOWN: park the identity; the replayer resends it until definite. The
	// park takes ownership of the caller's exclusion release, so the caller
	// may return ErrMutationUnknown without handing that exclusion to anyone.
	c.parkExact(ctx, es, slot, seq, req)
	return nil, ErrMutationUnknown
}

// finishExact commits a definite outcome and maintains session health state.
func (c *Client) finishExact(es *exactSession, slot uint32, seq uint64, resp *Response) {
	es.commit(slot, seq)
	if resp.Status == ESTALE {
		// The authority no longer recognizes this generation (fenced,
		// expired, superseded, or slot-state violation): stop mutating
		// permanently. The mount surfaces a hard error; remount recovers.
		es.fence()
	}
}

// parkExact hands an UNKNOWN-outcome identity to the background replayer.
//
// INVARIANT: a possibly-sent exact identity reaches a definite outcome BEFORE
// the exclusion state it was issued under is released to anyone else. The
// identity may execute minutes from now, so parking it also parks the
// caller's delegation-transition claim / exact exclusion: parkExact captures
// that release from ctx (WithParkTransfer) synchronously, before the parking
// caller returns, and drops it on exactly one of three definite ends —
//
//  1. an authority reply for the identity (executed, or its stored outcome),
//  2. a session fence (es.stop: the generation can never execute again),
//  3. client teardown (Close/Abort, both of which fence first and then JOIN
//     this goroutine, so no transferred claim outlives the client).
//
// Every exit path runs the release exactly once via defer; with no hook
// installed the release is a no-op and behavior is unchanged.
func (c *Client) parkExact(ctx context.Context, es *exactSession, slot uint32, seq uint64, req *Request) {
	release := beginParkTransfer(ctx)
	if !c.registerPark() {
		// Torn down already: this identity can never be re-sent from this
		// generation, so its outcome is definite by teardown. Release inline —
		// a goroutine started here would not be joined by the close that is
		// already past its wait.
		release()
		return
	}
	go func() {
		defer c.parkWG.Done()
		// Ordered after Done's registration and therefore run BEFORE it: the
		// exclusion is handed back before teardown's join returns.
		defer release()
		backoff := parkRetryMin
		for {
			if es.isFenced() || c.isClosed() {
				return // slot retired with the session
			}
			resp, _, err := c.roundtripExact(req)
			if err == nil {
				c.finishExact(es, slot, seq, resp)
				if resp.Status == OK {
					// The caller already returned ErrMutationUnknown; keep the
					// client's own cache coherent for the write that DID land.
					// This runs INSIDE the still-transferred exclusion (the
					// deferred release follows), so the local overlay reflects
					// the landed write before the scope can be handed to a new
					// claim holder. The self-write recorder must therefore
					// never re-enter that exclusion.
					c.selfWrote(req.Path, resp, req.Op == OpWrite || req.Op == OpTruncate || req.Op == OpSetattr)
				}
				return
			}
			select {
			case <-es.stop:
				return
			case <-c.closed:
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > parkRetryMax {
				backoff = parkRetryMax
			}
		}
	}()
}

// roundtripExact performs one attempt of an exact mutation on a pooled
// connection. wasSent reports whether any request bytes may have reached the
// authority (false only when dialing or the pre-send attach itself failed).
func (c *Client) roundtripExact(req *Request) (resp *Response, wasSent bool, err error) {
	return c.roundtripExactWithGate(req, false)
}

func (c *Client) roundtripExactResolved(req *Request) (resp *Response, wasSent bool, err error) {
	return c.roundtripExactWithGate(req, true)
}

func (c *Client) roundtripExactWithGate(req *Request, resolved bool) (resp *Response, wasSent bool, err error) {
	cn, err := c.takeConn()
	if err != nil {
		return nil, false, err
	}
	defer func() { c.conns <- cn }()
	if err := c.prepareConnWithGate(cn, resolved); err != nil {
		return nil, false, err
	}
	return cn.roundtripSentWithGate(req, resolved)
}

// exactOp reports whether op is a write-through tree mutation that must carry
// an exact-once identity on a session-negotiated authority. Mirrors the
// server's admission surface (mutatingOp + OpReap).
func exactOp(op Op) bool {
	switch op {
	case OpWrite, OpCreate, OpMkdir, OpRemove, OpRename, OpSymlink, OpLink, OpTruncate, OpSetattr, OpOrphan, OpReap,
		OpSetxattr, OpRemovexattr:
		return true
	default:
		return false
	}
}

func statusError(op string, status int32) error {
	return fmt.Errorf("fsproto: %s failed with status %d", op, status)
}
