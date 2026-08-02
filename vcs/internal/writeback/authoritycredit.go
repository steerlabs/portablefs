package writeback

// The authority lane's gate.
//
// ── WHY A SECOND GATE, AND WHY IT IS NOT THE FIRST ONE ──────────────────────
//
// The stream gate (credit.go) paces bulk data against the authority-APPLIED
// watermark, because the quantity it bounds is resident unapplied WAL bytes and
// the watermark is exactly what frees them. Write-through bytes never enter the
// WAL, so charging them there would be dimensionally wrong twice over: it would
// consume stream budget a write-through can never use, and it would make
// ENOSPC — a statement about a bounded LOCAL store — depend on traffic that
// never touches that store.
//
// So the previous shape drew the obvious conclusion and charged them NOWHERE.
// That is the defect. "These bytes do not belong in the stream ledger" is true;
// "therefore they are unaccounted and unpaced" does not follow, and the
// difference between the two is a measured 734 MiB.
//
// ── WHAT ACTUALLY HAPPENED, AND WHAT IT RULES OUT ───────────────────────────
//
// From fsproto/session_client.go:414-419, measured live: 768 MiB written
// unpaced at 110 MB/s — "every byte on the uncharged authority lane, so nothing
// paced it" — starved the lease renewal past the 90-second TTL, the session was
// fenced, and 734 MiB the kernel had already acknowledged "was lost AT THE
// DEFERRED FLUSH". The same 768 MiB paced at 8 MB/s was byte-exact.
//
// Read that carefully, because it rules out the gate one would reach for first.
// The authority in that incident was FAST — 110 MB/s. A gate that paced against
// the observed ACK rate would have measured a healthy far end, opened to its
// ceiling, and admitted every one of those bytes. Rate pacing on acks would not
// have moved the incident by a single megabyte.
//
// What was unbounded was not the rate. It was the quantity of data that had
// been ACKNOWLEDGED TO THE APPLICATION and not yet PROVEN DURABLE. The
// authority's write reply is a receipt, not a durability proof: it says the
// bytes reached the session, and a fenced session discards exactly those bytes
// at the deferred flush. Every acknowledged-but-unproven byte is therefore a
// byte at risk, and the loss is bounded by, and only by, how many of them the
// mount is willing to hold at once.
//
// ── THE BOUND, AND THE CONTROL LOOP THAT SIZES IT ───────────────────────────
//
// So this gate bounds UNPROVEN bytes, and its rate estimator is fed by PROOF
// events rather than by acks — the exact structural mirror of the stream gate,
// whose "proof" is the applied watermark advance:
//
//	setpoint = clamp(provenRate * creditDrainTarget, floor, ceiling)
//
// A far end that proves promptly measures a high rate, opens to the ceiling,
// and is not throttled at all. A far end that acks at 110 MB/s and proves
// nothing measures a rate decaying to zero, collapses to the floor, and stops
// admitting — which is the backpressure the incident needed and did not have.
// The bound on unproven bytes IS the bound on the loss.
//
// The proof is not left to the application. An application that never calls
// fsync would otherwise wedge this lane at its floor forever, so the gate
// PROVES ITS OWN BACKLOG: crossing the trigger schedules one barrier, and the
// barrier's return is the proof event. That is the same bargain the write-back
// lane already makes with its flusher — bounded debt, drained by a mechanism
// the writer does not have to ask for.
//
// ── TERMINATION ─────────────────────────────────────────────────────────────
//
// This gate sits in front of the unwind's forced second pass, so it must not be
// able to livelock it. Three properties make that hold, and all three are
// structural rather than tuned:
//
//  1. A PACED PASS IS STILL A SECOND PASS. ErrLaneChanged is produced for
//     exactly one input — a ctx whose resolved lane is LaneDelegated
//     (engine.go, admitDataBytes). The forced pass resolves LaneAuthority, so
//     it cannot be answered ErrLaneChanged and cannot unwind again, however
//     long it waits here. The two-pass bound is a property of the LANE, not of
//     the speed of admission, and adding a wait cannot change it.
//  2. THE WAIT IS BOUNDED AND SELF-RELIEVING. Waiters block on proof, the gate
//     schedules the barrier that produces proof, and the whole wait runs under
//     the operation deadline clientcore already installs. Nothing here waits on
//     an event only the application could cause.
//  3. THE OUTCOME IS ALWAYS DEFINITE. Either some credit arrives — and a short
//     grant is PROGRESS, surfaced as a POSIX short write the kernel reissues
//     the remainder of — or the wait ends and the answer is a typed error. A
//     zero-length success, the one outcome no kernel write path can act on, is
//     never returned.

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ErrAuthorityUnproven reports that the authority lane is holding as many
// acknowledged-but-unproven bytes as it is allowed to and could not prove any
// of them within the caller's deadline.
//
// It is EIO-class, never ENOSPC: the local store is irrelevant to it. It means
// the far end is taking writes and not proving them durable, which is the exact
// condition that preceded the 734 MiB loss — reported now instead of absorbed.
var ErrAuthorityUnproven = errors.New("writeback: authority lane has unproven acknowledged bytes and cannot admit more")

// authorityProofTriggerNum/Den set the fraction of the setpoint at which the
// gate stops waiting for someone else to call fsync and proves its own backlog.
// Half is deliberate: it leaves a full half-setpoint of headroom for writes
// that arrive while the barrier is in flight, so the common case never blocks
// at all.
const (
	authorityProofTriggerNum = 1
	authorityProofTriggerDen = 2
)

// authorityPollInterval re-evaluates a waiter's setpoint, so a proof rate that
// recovers (or collapses) while it waits is reflected without depending on a
// proof event that may never arrive.
var authorityPollInterval = 50 * time.Millisecond

// authorityWaitCap bounds ONE AdmitAuthorityBytes call's wait, exactly as
// creditWaitCap bounds the stream gate's. A var so tests compress it.
var authorityWaitCap = 5 * time.Second

// authorityGate is the authority lane's admission gate and unproven ledger.
type authorityGate struct {
	// ceiling and floor bound the setpoint. They are the SAME pair the stream
	// gate uses, for one reason: both lanes' debt has to be drainable inside
	// one barrier bound, and the barrier bound is a property of the mount, not
	// of the lane. The floor guarantees the gate PACES rather than deadlocks —
	// a rate collapsed to zero still admits the largest single operation.
	ceiling int64
	floor   int64

	setpoint atomic.Int64

	// inflight is charged at admission and cleared when the RPC returns.
	// unproven is charged when the RPC returns SUCCESSFULLY — those bytes are
	// acknowledged to the application — and cleared only by proof.
	//
	// The bound is over their SUM. In-flight bytes are every bit as much at
	// risk as acknowledged ones (a fence loses both), and bounding only the
	// acknowledged half would let an unbounded burst sit in flight and be
	// acknowledged all at once the instant the barrier returned.
	inflight atomic.Int64
	unproven atomic.Int64

	// acked and proven are monotone lifetime totals, for the durability
	// identity rather than for admission. acked is every byte this lane ever
	// acknowledged; proven is every byte it ever proved.
	acked  atomic.Int64
	proven atomic.Int64

	mu       sync.Mutex
	rate     float64 // EWMA-with-peak-hold of PROVEN bytes/sec
	haveRate bool
	lastPoll time.Time
	// proofWake is closed and replaced on every proof, so a waiter is woken by
	// exactly the event that can free it.
	proofWake chan struct{}
	// prove is the barrier the gate runs against its own backlog. nil until a
	// frontend installs one; see SetAuthorityProver for what nil means.
	prove   func(context.Context) error
	proving bool
	// proveCancel ends the in-flight barrier, so a seal does not leave an RPC
	// running against a far end nobody is waiting for.
	proveCancel context.CancelFunc
	gateErr     error
	sealed      bool
	unprovabl   bool
}

func newAuthorityGate(ceiling int64) *authorityGate {
	if ceiling < 0 {
		ceiling = 0
	}
	if ceiling > creditDebtMax {
		ceiling = creditDebtMax
	}
	floor := int64(creditFloorBytes)
	if floor > ceiling {
		floor = ceiling
	}
	g := &authorityGate{
		ceiling:  ceiling,
		floor:    floor,
		lastPoll: time.Now(),
		// No prover until a frontend installs one, and "no prover" IS
		// unprovable. Defaulting the flag the other way would make an engine
		// with no barrier BLOCK its first flood on a proof that can never
		// arrive — a fresh wedge in place of the old leak. The gate refuses to
		// invent either: with nothing able to prove, it settles on
		// acknowledgement and says so in Status.
		unprovabl: true,
		proofWake: make(chan struct{}),
	}
	// Optimistic cold start, exactly as the stream gate's: there is no
	// measurement yet that could justify throttling a fresh mount's first
	// burst, and the first proof installs a real rate.
	g.setpoint.Store(ceiling)
	return g
}

// outstanding is the quantity the setpoint bounds.
func (g *authorityGate) outstanding() int64 {
	return g.inflight.Load() + g.unproven.Load()
}

// SetAuthorityProver installs the barrier the authority lane proves its backlog
// with. Production installs clientcore's bounded authority barrier
// (Volume.boundedBarrier over client.Sync), which is precisely the RPC that
// makes earlier authority writes durable and published.
//
// With NO prover installed the gate cannot distinguish acknowledged from
// proven, so it settles on acknowledgement and reports itself UNPROVABLE in
// Status. That degradation is deliberate and it is LOUD: silently treating an
// ack as a proof is the original defect, and a mount that has to do it says so
// rather than presenting a durability guarantee it is not making.
func (e *Engine) SetAuthorityProver(prove func(context.Context) error) {
	if e == nil || e.authority == nil {
		return
	}
	g := e.authority
	g.mu.Lock()
	g.prove = prove
	g.unprovabl = prove == nil
	g.mu.Unlock()
}

// currentSetpoint recomputes the operating limit from the measured proof rate.
func (g *authorityGate) currentSetpoint(now time.Time) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.setpointLocked(now)
}

func (g *authorityGate) setpointLocked(now time.Time) int64 {
	if !g.haveRate {
		return g.setpoint.Load()
	}
	// Decay the held peak toward zero, so a far end that stops proving loses
	// its setpoint on a schedule rather than keeping it forever.
	if elapsed := now.Sub(g.lastPoll); elapsed > 0 {
		g.rate *= math.Exp(-float64(elapsed) / float64(creditRateTau))
		g.lastPoll = now
	}
	sp := int64(g.rate * creditDrainTarget.Seconds())
	if sp < g.floor {
		sp = g.floor
	}
	if sp > g.ceiling {
		sp = g.ceiling
	}
	g.setpoint.Store(sp)
	return sp
}

// noteProven folds one barrier's worth of proof into the gate: it clears the
// proven bytes from the unproven ledger, samples the proof rate, and wakes
// every waiter.
func (g *authorityGate) noteProven(n int64, now time.Time) {
	if n < 0 {
		n = 0
	}
	g.mu.Lock()
	if n > 0 {
		gap := now.Sub(g.lastPoll)
		if gap < creditMinSampleGap {
			gap = creditMinSampleGap
		}
		sample := float64(n) / gap.Seconds()
		switch {
		case !g.haveRate || sample > g.rate:
			// Rise instantly to a newly observed peak: an underestimate
			// throttles a far end that is keeping up, which is the costlier
			// error. The ceiling bounds the overestimate.
			g.rate, g.haveRate = sample, true
		default:
			g.rate = g.rate*math.Exp(-float64(gap)/float64(creditRateTau)) +
				sample*(1-math.Exp(-float64(gap)/float64(creditRateTau)))
		}
		g.lastPoll = now
		g.setpointLocked(now)
	}
	wake := g.proofWake
	g.proofWake = make(chan struct{})
	g.mu.Unlock()
	if n > 0 {
		for {
			cur := g.unproven.Load()
			next := cur - n
			if next < 0 {
				next = 0
			}
			if g.unproven.CompareAndSwap(cur, next) {
				break
			}
		}
		g.proven.Add(n)
	}
	close(wake)
}

// seal refuses and wakes everything, permanently.
func (g *authorityGate) seal(err error) {
	g.mu.Lock()
	if !g.sealed {
		g.sealed, g.gateErr = true, err
	}
	cancel := g.proveCancel
	g.proveCancel = nil
	wake := g.proofWake
	g.proofWake = make(chan struct{})
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	close(wake)
}

// maybeProve schedules one barrier when the backlog has crossed the trigger and
// no barrier is already running. It never blocks the caller: the whole point is
// that a writer waits for PROOF, not for the act of asking for it.
func (g *authorityGate) maybeProve(e *Engine) {
	g.mu.Lock()
	sp := g.setpointLocked(time.Now())
	trigger := sp * authorityProofTriggerNum / authorityProofTriggerDen
	if g.proving || g.sealed || g.prove == nil || g.unproven.Load() < trigger {
		g.mu.Unlock()
		return
	}
	g.proving = true
	prove := g.prove
	// The barrier's budget is decided HERE, at schedule time, not read inside
	// the goroutine. A goroutine that outlives its scheduler must not reach back
	// into package state to find out how long it is allowed to run — the race
	// detector caught exactly that against the test knob, and the same shape
	// against a live reconfiguration would be a barrier whose deadline changed
	// underneath it.
	bound := volumeBarrierBound
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	// Tie the barrier to the gate's lifetime. Without this the goroutine
	// survives the engine that scheduled it, and a seal — a fence, a close, a
	// forced unmount — would leave an RPC running against a far end nobody is
	// waiting for any more.
	g.proveCancel = cancel
	g.mu.Unlock()

	go func() {
		defer cancel()
		// Snapshot BEFORE the barrier. A barrier proves everything acknowledged
		// before it started; bytes acknowledged while it ran are the next
		// barrier's business, and crediting them to this one would clear a
		// ledger entry no RPC ever covered.
		claim := g.unproven.Load()
		err := prove(ctx)
		g.mu.Lock()
		g.proving = false
		g.proveCancel = nil
		g.mu.Unlock()
		if err != nil {
			// An unproven barrier proves nothing. Wake the waiters anyway so
			// they re-evaluate against a setpoint that is now decaying, and
			// reach their own definite answer rather than sleeping on a far end
			// that has stopped answering.
			g.mu.Lock()
			wake := g.proofWake
			g.proofWake = make(chan struct{})
			g.mu.Unlock()
			close(wake)
			return
		}
		g.noteProven(claim, time.Now())
	}()
}

// volumeBarrierBound mirrors clientcore.volumeBarrierTimeout. It is stated here
// rather than imported because writeback must not depend on clientcore; the
// two are checked against each other in TestAuthorityBarrierBoundMatchesFrontend.
var volumeBarrierBound = 60 * time.Second

// ─── exported gate ───────────────────────────────────────────────────────────

// AdmitAuthorityBytes is the authority lane's admission. It is the exact twin
// of AcquireDataCredit and obeys the same contract: it takes no engine,
// namespace or handle lock, a waiter inside it holds nothing, a short grant is
// normal and becomes a POSIX short write, and it never returns zero with a nil
// error.
//
// Every byte it grants is charged to the lane's in-flight ledger. The caller
// MUST hand every granted byte back with SettleAuthorityBytes.
func (e *Engine) AdmitAuthorityBytes(ctx context.Context, n int64) (int64, error) {
	if e == nil || e.authority == nil || n <= 0 {
		return n, nil
	}
	g := e.authority

	// The wait cap bounds a wait that is making NO progress, not the total wait.
	// A far end that is proving — slowly — is healthy, and the engine's contract
	// for a slow link is a paced completion rather than an error (see
	// AcquireDataCredit's "keep pacing" arm). So the cap is re-armed whenever
	// proof lands, and only a full cap with nothing proven is a refusal. The
	// TOTAL is still bounded, by the operation deadline the frontend installs.
	deadline := time.Now().Add(authorityWaitCap)
	provenAtLastArm := g.proven.Load()
	for {
		g.mu.Lock()
		sealed, gateErr := g.sealed, g.gateErr
		unprovable := g.unprovabl
		sp := g.setpointLocked(time.Now())
		wake := g.proofWake
		g.mu.Unlock()
		if sealed {
			return 0, gateErr
		}

		// One operation larger than the whole lane can never fit, at any
		// occupancy. Grant it the ceiling as a short write rather than
		// refusing: the kernel reissues the remainder, and a bound that turns
		// a large write into an error would be a new failure mode, not a fix.
		want := n
		if want > sp {
			want = sp
		}

		out := g.outstanding()
		if room := sp - out; room > 0 {
			grant := want
			if grant > room {
				grant = room
			}
			if grant > 0 {
				g.inflight.Add(grant)
				// Ask for proof on the way past, not only when blocked: a
				// backlog that crosses the trigger while the gate is still
				// open is exactly the backlog whose barrier should already be
				// running by the time someone has to wait for it.
				g.maybeProve(e)
				return grant, nil
			}
		}
		if unprovable {
			// Nothing can ever clear this ledger, so waiting is a lie. Admit
			// and let Status carry the truth (see SetAuthorityProver).
			g.inflight.Add(n)
			return n, nil
		}

		// Blocked. Make sure a barrier is running before sleeping on one.
		g.maybeProve(e)

		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if !time.Now().Before(deadline) {
			if now := g.proven.Load(); now > provenAtLastArm {
				// Proof landed while this caller waited: the far end IS
				// draining its backlog, just not fast enough to have freed
				// room for THIS write yet. Re-arm and keep pacing.
				provenAtLastArm = now
				deadline = time.Now().Add(authorityWaitCap)
				continue
			}
			// The wait cap, reached with no proof. If the flusher's watchdog
			// says the far end is dead, relay that verdict — it is the same
			// EIO-class answer every other lane gives. Otherwise the far end is
			// merely slow to prove, and that is this gate's own typed
			// condition.
			if e.StallVerdict().Stalled {
				return 0, ErrUplinkStalled
			}
			return 0, ErrAuthorityUnproven
		}
		timer := time.NewTimer(authorityPollInterval)
		select {
		case <-wake:
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		}
		timer.Stop()
	}
}

// SettleAuthorityBytes closes out one authority-lane write. granted is what
// AdmitAuthorityBytes handed out; acked is how many of those bytes the
// authority's reply actually acknowledged to the application.
//
// The split is the whole point. granted-acked never existed as far as any
// application is concerned and is released outright. acked bytes are
// acknowledged AND UNPROVEN: they move to the ledger a durability check reads,
// and they stay there until a barrier proves them.
func (e *Engine) SettleAuthorityBytes(granted, acked int64) {
	if e == nil || e.authority == nil || granted <= 0 {
		return
	}
	g := e.authority
	if acked < 0 {
		acked = 0
	}
	if acked > granted {
		acked = granted
	}
	for {
		cur := g.inflight.Load()
		next := cur - granted
		if next < 0 {
			next = 0
		}
		if g.inflight.CompareAndSwap(cur, next) {
			break
		}
	}
	if acked > 0 {
		g.unproven.Add(acked)
		g.acked.Add(acked)
		g.maybeProve(e)
	} else {
		// A refused write frees the lane immediately; wake anyone the charge
		// was blocking.
		g.mu.Lock()
		wake := g.proofWake
		g.proofWake = make(chan struct{})
		g.mu.Unlock()
		close(wake)
	}
}

// NoteAuthorityProven is the frontend's own barrier reporting in: an fsync or
// unmount barrier the APPLICATION asked for proves the same bytes the gate's
// self-triggered one would have, and must clear the same ledger.
func (e *Engine) NoteAuthorityProven() {
	if e == nil || e.authority == nil {
		return
	}
	e.authority.noteProven(e.authority.unproven.Load(), time.Now())
}

// ─── the charge, carried on the operation's ctx ──────────────────────────────
//
// An authority-lane charge is opened by the pre-lock classifier and closed by
// the frontend's settle func, but only the code that ran the RPC knows how many
// bytes came back ACKNOWLEDGED — and that is a third place, inside the locks.
// A settlement object on the ctx is how the existing frontend data grant solves
// the identical three-way split (dataCreditGrant, credit.go), and this is the
// same shape for the same reason: acquire in one place, learn the outcome in a
// second, settle in a third, exactly once.

type authorityChargeKey struct{}

type authorityCharge struct {
	granted int64
	acked   atomic.Int64
	settled atomic.Bool
}

// WithAuthorityCharge marks ctx as carrying granted bytes of authority-lane
// admission, charged by AdmitAuthorityBytes before the frontend took a lock.
func WithAuthorityCharge(ctx context.Context, granted int64) context.Context {
	if granted <= 0 {
		return ctx
	}
	return context.WithValue(ctx, authorityChargeKey{}, &authorityCharge{granted: granted})
}

// NoteAuthorityAck records that the authority acknowledged n bytes of ctx's
// charge to the application. It is called by the code that ran the RPC, and it
// is what turns an in-flight byte into an acknowledged-but-unproven one.
//
// A write-through that fails, or returns a short count, calls it with what the
// authority actually acknowledged — never with what was asked for. That is the
// whole difference between a ledger and a guess.
func NoteAuthorityAck(ctx context.Context, n int) {
	c, _ := ctx.Value(authorityChargeKey{}).(*authorityCharge)
	if c == nil || n <= 0 {
		return
	}
	c.acked.Add(int64(n))
}

// SettleAuthorityCharge closes ctx's charge exactly once. It is safe (and
// expected) to call unconditionally on every exit path of a frontend write,
// including the paths that never reached the authority at all — those settle
// with zero acknowledged, which releases the whole charge.
func (e *Engine) SettleAuthorityCharge(ctx context.Context) {
	c, _ := ctx.Value(authorityChargeKey{}).(*authorityCharge)
	if c == nil || !c.settled.CompareAndSwap(false, true) {
		return
	}
	e.SettleAuthorityBytes(c.granted, c.acked.Load())
}

// AuthorityLedger is one reading of the authority lane's durability state.
type AuthorityLedger struct {
	// InFlight is charged and not yet answered by the authority.
	InFlight int64
	// Unproven is ACKNOWLEDGED TO THE APPLICATION and not yet proven durable.
	// This is the number the 18a incident had to reconstruct by subtraction:
	// at the instant a session is fenced it is the exact size of the loss.
	Unproven int64
	// Setpoint is the operating bound on InFlight+Unproven.
	Setpoint int64
	// Acked and Proven are monotone lifetime totals.
	Acked  int64
	Proven int64
	// Unprovable reports that no barrier is installed, so Unproven is settled
	// on acknowledgement and carries no durability claim at all.
	Unprovable bool
}

// AuthorityLedgerStatus reports the authority lane's durability accounting.
func (e *Engine) AuthorityLedgerStatus() AuthorityLedger {
	if e == nil || e.authority == nil {
		return AuthorityLedger{}
	}
	g := e.authority
	g.mu.Lock()
	sp := g.setpointLocked(time.Now())
	unprovable := g.unprovabl
	g.mu.Unlock()
	return AuthorityLedger{
		InFlight:   g.inflight.Load(),
		Unproven:   g.unproven.Load(),
		Setpoint:   sp,
		Acked:      g.acked.Load(),
		Proven:     g.proven.Load(),
		Unprovable: unprovable,
	}
}
