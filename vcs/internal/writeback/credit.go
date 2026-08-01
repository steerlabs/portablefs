package writeback

// Drain-time credit control.
//
// The bounded WAL budget is a HARD cap enforced by an exact byte reservation
// (see appendMutationsWithin). A hard cap alone gives the data plane exactly
// one behaviour at saturation: it accepts everything at full speed and then
// falls off a cliff into ENOSPC. That cliff is correct as an emergency floor
// and useless as a policy — an application that writes faster than the uplink
// applies gets no signal at all until the moment it gets a POSIX error.
//
// The credit controller adds the missing middle: an ADMISSION rate for bulk
// data derived from the one thing that actually frees stream bytes, the
// authority-applied watermark. It never moves the hard cap. It only decides
// how much UNAPPLIED bulk data may be resident at once:
//
//	setpoint = clamp(measuredRate * T_drain, B_min, dataCap)
//
// On a link fast enough to apply the whole cap within T_drain the setpoint IS
// the cap: every burst is absorbed exactly as before, at one atomic load of
// cost. On a slow link the setpoint collapses toward B_min, so the resident
// debt stays drainable inside ONE barrier bound BY CONSTRUCTION — which is
// what makes fsync, unmount and delegation recall bounded rather than hopeful.
// Writers pace against the uplink instead of racing it to a cliff.
//
// Two lanes, one cap. Bulk data is credit-gated and bounded by
// dataCap = hardCap - metadataReserve. Metadata (create/mkdir/rename/remove/
// setattr/xattr and every control record) is never credit-charged and is
// bounded by the full hard cap, so the reserve is always there for it: a
// namespace mutation stays instant while a data flood is paced. The reserve
// buys ADMISSION responsiveness only. It does not reorder anything on the
// wire — the dense ordered mutation stream is untouched.

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ErrUplinkStalled reports that a data mutation could not be admitted because
// the authority is not applying anything: the credit gate handed out no credit
// within its per-call bound AND the flusher's no-progress watchdog says the
// uplink has stopped making durable progress.
//
// It is deliberately NOT ErrNoSpace. ENOSPC means a bounded local store is
// full and the operation can never fit; this means the store is fine and the
// far end is not answering, which frontends map to an EIO-class outcome. The
// engine is not poisoned, no delegation is released, and the very next
// admission after the uplink resumes is accepted normally.
var ErrUplinkStalled = errors.New("writeback: uplink stalled; no authority progress")

// errDataHeadroom is internal: the data lane's HARD reservation could not fit
// this append right now, but the append is not oversized — it would fit an
// empty stream. The caller waits for applied progress and retries through the
// credit gate rather than surfacing a definite ENOSPC.
var errDataHeadroom = errors.New("writeback: data lane has no headroom yet")

const (
	// creditRateTau is the decay time constant of the applied-rate estimator.
	// The estimator rises instantly to a newly observed peak and decays toward
	// zero with this constant when acks stop arriving. Rising fast is the safe
	// direction (the hard cap still bounds every grant, so an overestimate
	// costs at most a larger burst window, while an underestimate throttles a
	// link that is keeping up); falling slowly stops one sparse ack from
	// collapsing a healthy link's setpoint.
	creditRateTau = 5 * time.Second

	// creditChunkBytes is the queue's grant quantum. Above the setpoint,
	// freed credit is handed out one chunk at a time in arrival order, so a
	// single multi-megabyte request cannot absorb every byte an advance frees
	// while a 4 KiB request behind it waits. It matches the engine's own
	// write record chunking, so a granted chunk is exactly one WAL record.
	creditChunkBytes = 1 << 20

	// creditMinSampleGap floors the denominator of one rate sample so two acks
	// landing in the same instant cannot divide by zero.
	creditMinSampleGap = time.Millisecond

	// creditPollInterval re-evaluates the setpoint for a queued waiter, so a
	// rate that collapses (or recovers) while it waits is reflected without
	// depending on an ack that may never come.
	creditPollInterval = 50 * time.Millisecond

	// metadataReserveBytes is one segment of the hard cap reserved for the
	// metadata lane. Bulk data can never consume it, so a create/rename/unlink
	// is never refused for want of space a data flood already took.
	metadataReserveBytes = 64 << 20
)

// creditFloorBytes (B_min) is the operating setpoint's floor: one
// maximum-size mutation frame plus one segment rollover (a fresh header and
// the re-emitted live-delegation set, allowed 64 KiB here). A rate that has
// collapsed to zero therefore still leaves a setpoint able to admit the
// largest single operation the WAL can carry. The gate PACES; it never
// deadlocks a writer that a hard cap would have accepted.
const creditFloorBytes = maxMutationPayload + frameHeaderSize + frameAlign + segmentHeaderSize + (64 << 10)

// creditDrainTarget (T_drain) is the operating setpoint's horizon: the engine
// admits at most as much unapplied bulk data as the measured uplink can apply
// in this long. It is chosen well under clientcore's volumeBarrierTimeout
// (60s), which bounds ONE fsync/unmount drain attempt, and well under the FSKit
// kernel's own operation ceiling — so a barrier taken at any instant has a
// construction-level reason to complete inside its own timeout instead of
// inheriting an unbounded backlog. A var so tests can compress the horizon;
// production never changes it.
var creditDrainTarget = 25 * time.Second

// creditWaitCap bounds ONE AcquireDataCredit call's wait. Past it the call
// returns whatever credit it collected (a partial grant the caller surfaces as
// a POSIX short write) rather than holding a frontend operation open
// indefinitely. A var so tests compress it; production never changes it.
var creditWaitCap = 5 * time.Second

// metadataReserveFor scales the reserve for caps too small to give a whole
// segment away (package fixtures, tiny caches): it degrades to a quarter of
// the cap, which keeps the two-lane split's shape at any size.
func metadataReserveFor(budget int64) int64 {
	if budget <= 0 {
		return 0
	}
	if quarter := budget / 4; quarter < metadataReserveBytes {
		return quarter
	}
	return metadataReserveBytes
}

// dataBudgetBytes is the HARD cap of the bulk-data lane: the stream budget
// minus the metadata reserve. Data appends are reserved against this; metadata
// appends are reserved against the full budget.
//
// A third slice — the WAL's control reserve — is subtracted from whichever of
// these two numbers reaches admission, once, inside the WAL (see
// streamWAL.controlReserveLocked for the full partition of BudgetBytes). This
// function therefore states only the data/metadata boundary; both lanes inherit
// the control reserve without double-counting it.
func (e *Engine) dataBudgetBytes() int64 {
	return e.cfg.BudgetBytes - metadataReserveFor(e.cfg.BudgetBytes)
}

// creditWaiter is one queued request. It holds NOTHING while it waits: not
// e.mu, not the WAL mutex, not a delegation, not a handle. A recall, a freeze,
// a close, a checkpoint and every metadata mutation run to completion with
// waiters parked here.
type creditWaiter struct {
	want    int64
	granted int64
	done    bool
	err     error
	ready   chan struct{}
}

func (w *creditWaiter) signal() {
	select {
	case w.ready <- struct{}{}:
	default:
	}
}

// creditController is the admission gate for bulk data bytes.
type creditController struct {
	e *Engine

	// ceiling is the data lane's hard cap and floor is B_min; both are fixed
	// at construction. The setpoint moves between them; neither moves.
	ceiling int64
	floor   int64

	// setpoint and debt are the fast path: one load and one CAS, no lock, no
	// allocation. debt is bulk data bytes granted but not yet applied by the
	// authority. waiting is non-zero exactly while the queue is non-empty and
	// makes the fast path yield to it (no barging past a queued waiter).
	setpoint atomic.Int64
	debt     atomic.Int64
	waiting  atomic.Int64

	mu         sync.Mutex
	queue      []*creditWaiter
	rate       float64 // EWMA-with-peak-hold of applied bytes/sec
	haveRate   bool
	lastSample time.Time
	// drainWake is closed and replaced on every applied advance, so a waiter
	// blocked on hard-cap headroom (rather than on credit) is woken by exactly
	// the event that can free it.
	drainWake chan struct{}
	// gateErr refuses and wakes everything while the engine is frozen or
	// closed; sealed makes that permanent. gated mirrors "gateErr != nil" for
	// the fast path, which must honour a freeze without taking c.mu.
	gateErr error
	sealed  bool
	gated   atomic.Bool
}

func newCreditController(e *Engine) *creditController {
	ceiling := e.dataBudgetBytes()
	if ceiling < 0 {
		ceiling = 0
	}
	floor := int64(creditFloorBytes)
	if floor > ceiling {
		// A cap too small to hold one maximum-size operation: the floor cannot
		// exceed the ceiling it lives under, and the hard cap still refuses any
		// single operation larger than the lane.
		floor = ceiling
	}
	c := &creditController{
		e: e, ceiling: ceiling, floor: floor,
		lastSample: time.Now(),
		drainWake:  make(chan struct{}),
	}
	// Before the first applied sample the setpoint is the full data cap:
	// optimistic, and still bounded by the hard cap. A fresh mount must absorb
	// its first burst at full speed — there is no measurement yet that could
	// justify throttling it, and the very first ack installs a real one.
	c.setpoint.Store(ceiling)
	return c
}

// ─── exported gate ───────────────────────────────────────────────────────────

// AcquireDataCredit reserves admission credit for n bytes of bulk data. It is
// pure and lock-safe: it takes no engine, namespace or handle lock, so callers
// MUST call it BEFORE they take any of those. A waiter parked inside it holds
// nothing at all.
//
// Contract:
//
//   - Below the setpoint the call is a single atomic check and returns
//     granted == n. This is the hot path for essentially every operation.
//   - Above it the call joins a FIFO queue that is served in chunks as applied
//     bytes free credit, and returns within creditWaitCap.
//   - A short grant (0 < granted < n) is normal: the caller writes exactly
//     granted bytes and surfaces a POSIX short write.
//   - granted == 0 with a nil error means "no credit yet, but the uplink IS
//     making progress" — the link is simply slower than one wait cap. The
//     caller decides: retry (the engine's own write path does, so a slow link
//     produces a paced completion rather than an error) or report a short
//     write of zero.
//   - granted == 0 with ErrUplinkStalled means no credit arrived AND the
//     flusher's no-progress watchdog says the authority has stopped applying.
//     Frontends map it to an EIO-class outcome, never to ENOSPC.
//   - ErrNoSpace means n exceeds the data lane's hard cap at ANY occupancy:
//     no amount of draining can ever admit this one operation. This is the
//     only ENOSPC the gate produces.
//   - A context error, a freeze or a close returns (0, err) with every
//     collected credit already refunded, so an error outcome never leaks
//     credit and never needs a settlement call.
//
// Credit granted and NOT turned into WAL bytes must be returned with
// ReleaseDataCredit; the engine's own write path settles this automatically.
func (e *Engine) AcquireDataCredit(ctx context.Context, n int) (int, error) {
	return e.credits.acquire(ctx, int64(n))
}

// ReleaseDataCredit returns credit that never became WAL bytes — a grant whose
// mutation was refused, fell through to the authority lane, or was only
// partly used. Refunding is what keeps the ledger honest against the exact
// reservation machinery: a grant that races a reservation failure gives its
// bytes straight back, and the hard cap is untouched either way.
func (e *Engine) ReleaseDataCredit(n int) { e.credits.refund(int64(n)) }

type dataCreditKey struct{}

// dataCreditGrant is one frontend-acquired grant riding on an operation's ctx.
//
// It is a settlement OBJECT rather than a number because a frontend grant can
// end in more places than the engine can see. The operation may reach
// pacedWrite (the engine consumes its part and refunds whatever did not become
// WAL bytes), or clientcore may divert it first — the orphan lane, the pathless
// exact-handle lane, a delegated-binding retry, a hardlink scope release — or
// the frontend may fail before any of that. A single counter that BOTH sides
// decrement exactly once is what makes "acquire before the lock, settle
// wherever the operation actually ends" leak-free without either side having to
// enumerate the other's lanes.
type dataCreditGrant struct{ remaining atomic.Int64 }

// take removes at most n bytes from the grant and returns what it removed.
func (g *dataCreditGrant) take(n int64) int64 {
	if n <= 0 {
		return 0
	}
	for {
		cur := g.remaining.Load()
		if cur <= 0 {
			return 0
		}
		got := min(cur, n)
		if g.remaining.CompareAndSwap(cur, cur-got) {
			return got
		}
	}
}

// drain empties the grant and returns everything that was left in it.
func (g *dataCreditGrant) drain() int64 {
	for {
		cur := g.remaining.Load()
		if cur <= 0 {
			return 0
		}
		if g.remaining.CompareAndSwap(cur, 0) {
			return cur
		}
	}
}

// WithDataCredit marks ctx as already carrying granted bytes of data credit,
// acquired by a frontend with AcquireDataCredit before it took its
// namespace/handle locks. Engine.WriteAt/WriteAppend then consume that grant
// instead of acquiring a second time.
//
// The engine takes exactly the part it can use — min(remaining, len(data)) —
// and refunds whatever of that does not become WAL bytes. Whatever is still on
// the ctx when the operation ends is the frontend's to reclaim: call
// ReclaimDataCredit and hand the result to ReleaseDataCredit. Both sides are
// exactly-once, so the frontend's unconditional deferred reclaim is a no-op
// when the engine already consumed the grant.
func WithDataCredit(ctx context.Context, granted int) context.Context {
	if granted <= 0 {
		return ctx
	}
	g := &dataCreditGrant{}
	g.remaining.Store(int64(granted))
	return context.WithValue(ctx, dataCreditKey{}, g)
}

// ReclaimDataCredit empties ctx's frontend grant and returns the bytes the
// engine never consumed, so the frontend can refund them with
// ReleaseDataCredit. It is safe (and expected) to call unconditionally on
// every exit path of a frontend write, including the success path.
func ReclaimDataCredit(ctx context.Context) int {
	g, _ := ctx.Value(dataCreditKey{}).(*dataCreditGrant)
	if g == nil {
		return 0
	}
	return int(g.drain())
}

// takeDataCredit consumes up to want bytes of a frontend grant on ctx.
func takeDataCredit(ctx context.Context, want int64) int64 {
	g, _ := ctx.Value(dataCreditKey{}).(*dataCreditGrant)
	if g == nil {
		return 0
	}
	return g.take(want)
}

type resolvedLaneKey struct{}

// ResolvedLane is a frontend classifier's DEFINITE answer for one data
// mutation, reached before the frontend took any namespace, inode or handle
// lock, and binding on everything the operation does afterwards.
//
// The lane exists because a data mutation has exactly two of them and choosing
// between them is not free. Reaching the delegated lane can require pushing an
// ancestor grant down — drain its whole unshipped tail through the uplink, then
// release it durably — or acquiring a grant over an authority round trip.
// Reaching the authority lane can require releasing whatever covers the path,
// which is the same drain. Both are DELEGATION TRANSITIONS, and a transition
// taken while a frontend lock is held is the incident this whole placement
// exists to prevent: Go's RWMutex is writer-preferring, so one paced writer on
// the read side parks the next rename, remove or delegation reclaim, and every
// lookup, getattr and read behind it — a namespace-wide stall caused by a
// backlog on one path.
//
// So the transition is paid where it costs one operation instead of a mount,
// and what crosses into the locked region is not a hint but a decided answer.
// Inside the locks the engine only ever CHECKS the answer; if it no longer
// holds it says so (ErrLaneChanged) and the frontend reclassifies outside its
// locks, rather than transitioning where it must not.
type ResolvedLane int

const (
	// LaneUnresolved: no frontend classifier ran. The engine owns the entire
	// decision and may transition freely — a caller that reached it without a
	// classifier holds no frontend lock, so waiting costs only that caller.
	// This is the engine's own API surface and every non-frontend embedder.
	LaneUnresolved ResolvedLane = iota

	// LaneAuthority: this mutation will not reach the write-back WAL. Either
	// the node's identity forbids it — an orphaned inode, a hard link, a
	// pathless detached handle — or nothing delegates the path. It consumes no
	// stream budget, so it is never credit-charged and never queued: pacing it
	// would throttle a workload that is not responsible for the backlog and
	// cannot help drain it.
	//
	// When the path WAS covered, the classifier has already released the
	// covering grant and holds the transition exclusion that keeps a new one
	// from being installed underneath the operation. That is what makes the
	// answer definite rather than a guess: the engine can assert it without
	// re-deriving it, and clientcore never has to release anything under a
	// frontend lock.
	LaneAuthority

	// LaneDelegated: a grant at the mutation's exact governing scope was
	// retained when the classifier looked, and data credit was charged against
	// it. A grant can still be recalled between then and the write — by the
	// authority, by the idle releaser, by an exact operation — and the engine
	// answers that with ErrLaneChanged rather than by transitioning.
	LaneDelegated
)

// WithResolvedLane records a classifier's decision on ctx.
func WithResolvedLane(ctx context.Context, lane ResolvedLane) context.Context {
	if lane == LaneUnresolved {
		return ctx
	}
	return context.WithValue(ctx, resolvedLaneKey{}, lane)
}

func resolvedLaneOf(ctx context.Context) ResolvedLane {
	lane, _ := ctx.Value(resolvedLaneKey{}).(ResolvedLane)
	return lane
}

// LaneOf reports the lane a frontend classifier decided for this operation, or
// LaneUnresolved if none ran. Frontends read it to tell "I am inside my locks
// with a decided answer" from "no classifier ran", which is what makes a
// delegation transition forbidden in the first case and free in the second.
func LaneOf(ctx context.Context) ResolvedLane { return resolvedLaneOf(ctx) }

// NoProgressWindow and CreditWaitCap publish the two bounds a frontend's own
// admission budget must be proved against: the watchdog's stall verdict window
// and one credit acquisition's wait. A frontend budget that does not strictly
// exceed their sum would expire before the engine could say whether the uplink
// is stalled, and the frontend would have to invent the verdict — which is
// exactly the lie the split exists to prevent. Exported so that proof is a test
// rather than a comment.
func NoProgressWindow() time.Duration { return noProgressWindow }
func CreditWaitCap() time.Duration    { return creditWaitCap }

// UplinkStalled is the engine's stall verdict — the ONLY thing that may make a
// frontend report ErrUplinkStalled. A frontend that derives it from elapsed
// time instead reports a dead far end for a link the engine considers healthy.
func (e *Engine) UplinkStalled() bool { return e.fl.uplinkStalled() }

// ─── acquisition ─────────────────────────────────────────────────────────────

func (c *creditController) acquire(ctx context.Context, n int64) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if c.gated.Load() {
		// Frozen or closed: refuse before charging anything, so a lifecycle
		// event is a definite outcome on the fast path too.
		c.mu.Lock()
		err := c.gateErr
		c.mu.Unlock()
		if err != nil {
			return 0, err
		}
	}
	if n > c.ceiling {
		// Definite at any occupancy: draining the entire stream would still not
		// make room for this single operation. That is what ENOSPC means.
		return 0, ErrNoSpace
	}
	if c.tryFast(n) {
		return int(n), nil
	}
	return c.wait(ctx, n)
}

// creditFastPathCAS is the seam that lets a test land a waiter in the exact
// window between the fast path's debt snapshot and the CAS that commits it. It
// is nil in production, where it costs one predicted-not-taken nil compare per
// admission and nothing else.
var creditFastPathCAS func()

// tryFast is the whole hot path: two atomic loads and one CAS. It yields to a
// non-empty queue so a flood of small arrivals cannot starve waiters that are
// already in line.
//
// The queue check lives INSIDE the loop, after the debt snapshot the CAS will
// commit. That ordering is the fairness property itself. Reading `waiting` once
// before the loop admits a barge: a caller that observes an empty queue, loses
// its CAS to a racing admission, and retries would commit its second attempt
// against a queue that became non-empty in between — precisely the "flood of
// small arrivals starves the waiter already in line" case the queue exists to
// prevent. Re-reading it every iteration gives the strongest property a
// lock-free fast path can carry: between the last observation of an empty queue
// and the successful CAS, this goroutine performs no other operation, so no
// admission ever COMPLETES after the queue was seen to be non-empty.
func (c *creditController) tryFast(n int64) bool {
	setpoint := c.setpoint.Load()
	for {
		cur := c.debt.Load()
		if cur+n > setpoint {
			return false
		}
		if c.waiting.Load() != 0 {
			return false
		}
		if creditFastPathCAS != nil {
			creditFastPathCAS()
		}
		if c.debt.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// hasHeadroom reports whether the gate could admit n right now, WITHOUT
// charging anything. It is the question a classifier asks before deciding
// whether taking a delegation is worth it at all: a grant that cannot be
// credit-admitted turns a free write-through into a paced delegated write.
//
// It reads the same two atomics tryFast does and yields to a non-empty queue
// for the same reason — a caller that would have to queue does not have
// headroom, it has a place in line.
func (c *creditController) hasHeadroom(n int64) bool {
	if n <= 0 {
		return true
	}
	if c.gated.Load() || c.waiting.Load() != 0 {
		return false
	}
	return c.debt.Load()+n <= c.setpoint.Load()
}

// refund returns unspent credit to the ledger and re-runs the queue: a refund
// is real headroom for whoever is waiting.
func (c *creditController) refund(n int64) {
	if n <= 0 {
		return
	}
	c.release(n)
	c.mu.Lock()
	c.pumpLocked()
	c.mu.Unlock()
}

func (c *creditController) release(n int64) {
	for {
		cur := c.debt.Load()
		next := cur - n
		if next < 0 {
			next = 0
		}
		if c.debt.CompareAndSwap(cur, next) {
			return
		}
	}
}

// wait queues the request and serves it in chunks until it is satisfied, the
// per-call cap expires, the context ends, or the gate closes.
func (c *creditController) wait(ctx context.Context, n int64) (int, error) {
	w := &creditWaiter{want: n, ready: make(chan struct{}, 1)}
	c.mu.Lock()
	if c.gateErr != nil {
		err := c.gateErr
		c.mu.Unlock()
		return 0, err
	}
	c.queue = append(c.queue, w)
	c.waiting.Store(int64(len(c.queue)))
	c.recomputeSetpointLocked(time.Now())
	c.pumpLocked()
	granted, done, gerr := w.granted, w.done, w.err
	c.mu.Unlock()
	if done {
		return c.finish(w, granted, gerr)
	}

	capTimer := time.NewTimer(creditWaitCap)
	defer capTimer.Stop()
	poll := time.NewTicker(creditPollInterval)
	defer poll.Stop()
	for {
		select {
		case <-w.ready:
			c.mu.Lock()
			granted, done, gerr = w.granted, w.done, w.err
			c.mu.Unlock()
			if done {
				return c.finish(w, granted, gerr)
			}
		case <-poll.C:
			c.mu.Lock()
			c.recomputeSetpointLocked(time.Now())
			c.pumpLocked()
			granted, done, gerr = w.granted, w.done, w.err
			c.mu.Unlock()
			if done {
				return c.finish(w, granted, gerr)
			}
		case <-capTimer.C:
			granted = c.dequeue(w)
			if granted > 0 {
				// Partial grant: the caller writes exactly this much and
				// surfaces a short write.
				return int(granted), nil
			}
			if c.e.fl.uplinkStalled() {
				return 0, ErrUplinkStalled
			}
			// The uplink IS applying, just more slowly than one wait cap. Not
			// an error: report zero and let the caller decide.
			return 0, nil
		case <-ctx.Done():
			// Refund (not just release): the bytes this waiter collected are
			// immediate headroom for whoever is still in line.
			c.refund(c.dequeue(w))
			return 0, ctx.Err()
		}
	}
}

func (c *creditController) finish(w *creditWaiter, granted int64, err error) (int, error) {
	if err != nil {
		// Freeze/close paths already refunded and zeroed the grant.
		return int(granted), err
	}
	return int(granted), nil
}

// dequeue removes w from the queue and returns whatever it collected.
func (c *creditController) dequeue(w *creditWaiter) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, q := range c.queue {
		if q == w {
			c.queue = append(c.queue[:i], c.queue[i+1:]...)
			c.waiting.Store(int64(len(c.queue)))
			break
		}
	}
	w.done = true
	return w.granted
}

// pumpLocked hands freed credit to waiters.
//
// Fairness: one pass walks the queue in ARRIVAL order and gives each waiter at
// most creditChunkBytes; passes repeat while headroom remains. Two properties
// follow. No waiter starves: every pass reaches every waiter before any waiter
// receives a second chunk, and arrivals append to the tail so they can never
// preempt a waiter already in line (the fast path also refuses to barge while
// the queue is non-empty). And no waiter monopolizes: a 64 MiB request cannot
// swallow an advance that freed 2 MiB while a 4 KiB request waits behind it —
// it takes one chunk per pass exactly like everyone else. A request is
// therefore served in time proportional to its own size plus the work queued
// ahead of it, never in time proportional to the largest request in the queue.
func (c *creditController) pumpLocked() {
	if len(c.queue) == 0 {
		return
	}
	headroom := c.setpoint.Load() - c.debt.Load()
	finished := false
	for headroom > 0 {
		progressed := false
		for _, w := range c.queue {
			if w.done || headroom <= 0 {
				continue
			}
			take := min(int64(creditChunkBytes), min(w.want-w.granted, headroom))
			if take <= 0 {
				continue
			}
			c.debt.Add(take)
			headroom -= take
			w.granted += take
			progressed = true
			if w.granted >= w.want {
				w.done = true
				finished = true
			}
			w.signal()
		}
		if !progressed {
			break
		}
	}
	if finished {
		kept := make([]*creditWaiter, 0, len(c.queue))
		for _, w := range c.queue {
			if !w.done {
				kept = append(kept, w)
			}
		}
		c.queue = kept
		c.waiting.Store(int64(len(c.queue)))
	}
}

// ─── measurement ─────────────────────────────────────────────────────────────

// noteApplied folds one authority advance into the controller: appliedTotal is
// every byte the authority made durable in it (the rate signal), appliedData is
// the bulk-data subset (the credit refill). ONLY durable applied progress
// reaches here — never a transport attempt, never a heartbeat, never a local
// append.
func (c *creditController) noteApplied(appliedData, appliedTotal int64, now time.Time) {
	if appliedData > 0 {
		c.release(appliedData)
	}
	c.mu.Lock()
	if appliedTotal > 0 {
		c.sampleLocked(appliedTotal, now)
	}
	c.recomputeSetpointLocked(now)
	c.pumpLocked()
	c.wakeDrainLocked()
	c.mu.Unlock()
}

// sampleLocked folds one applied batch into the rate estimator: instant rise
// to a new peak, exponential decay otherwise (see creditRateTau).
func (c *creditController) sampleLocked(bytes int64, now time.Time) {
	gap := now.Sub(c.lastSample)
	if gap < creditMinSampleGap {
		gap = creditMinSampleGap
	}
	instant := float64(bytes) / gap.Seconds()
	if decayed := c.decayedRateLocked(now); decayed > instant {
		instant = decayed
	}
	c.rate = instant
	c.haveRate = true
	c.lastSample = now
}

// decayedRateLocked is the measured rate as of now. Decaying on READ rather
// than on a timer is what makes a rate collapse mid-flood self-correcting: an
// uplink that stops acking has its setpoint shrink toward B_min with no
// bookkeeping goroutine at all.
func (c *creditController) decayedRateLocked(now time.Time) float64 {
	if !c.haveRate {
		return 0
	}
	gap := now.Sub(c.lastSample)
	if gap <= 0 {
		return c.rate
	}
	return c.rate * math.Exp(-gap.Seconds()/creditRateTau.Seconds())
}

// recomputeSetpointLocked republishes the ONE adapted quantity:
//
//	setpoint = clamp(rate * T_drain, B_min, dataCap)
//
// No PID, no curve, no second control loop. The hard cap is not a term in it.
func (c *creditController) recomputeSetpointLocked(now time.Time) {
	if !c.haveRate {
		c.setpoint.Store(c.ceiling)
		return
	}
	want := c.decayedRateLocked(now) * creditDrainTarget.Seconds()
	var setpoint int64
	switch {
	case math.IsNaN(want) || want <= float64(c.floor):
		setpoint = c.floor
	case want >= float64(c.ceiling):
		setpoint = c.ceiling
	default:
		setpoint = int64(want)
	}
	c.setpoint.Store(setpoint)
}

// tick refreshes the setpoint on the flusher's health cadence so the fast path
// never reads a stale one, even with nobody waiting.
func (c *creditController) tick() {
	c.mu.Lock()
	c.recomputeSetpointLocked(time.Now())
	c.pumpLocked()
	c.mu.Unlock()
}

// ─── hard-cap headroom ───────────────────────────────────────────────────────

// waitForApplied blocks until the authority watermark advances — the only
// event that frees HARD-cap headroom — or the per-call cap, the context, or a
// close ends the wait. It is the pacing step behind an errDataHeadroom retry.
// Like the credit queue it holds nothing.
func (c *creditController) waitForApplied(ctx context.Context) error {
	c.mu.Lock()
	if c.gateErr != nil {
		err := c.gateErr
		c.mu.Unlock()
		return err
	}
	wake := c.drainWake
	c.mu.Unlock()

	capTimer := time.NewTimer(creditWaitCap)
	defer capTimer.Stop()
	select {
	case <-wake:
		return nil
	case <-capTimer.C:
		if c.e.fl.uplinkStalled() {
			return ErrUplinkStalled
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *creditController) wakeDrainLocked() {
	close(c.drainWake)
	c.drainWake = make(chan struct{})
}

// ─── lifecycle ───────────────────────────────────────────────────────────────

// freeze refuses and wakes every waiter with a definite outcome. Reversible:
// a close that fails at its barrier thaws the engine and the gate with it.
func (c *creditController) freeze(err error) { c.close(err, false) }

// seal is freeze that never thaws (close, force-close, abandon, park).
func (c *creditController) seal(err error) { c.close(err, true) }

func (c *creditController) close(err error, permanent bool) {
	if err == nil {
		err = ErrFenced
	}
	c.mu.Lock()
	if c.gateErr == nil || (permanent && !c.sealed) {
		c.gateErr = err
	}
	if permanent {
		c.sealed = true
	}
	c.gated.Store(true)
	queued := c.queue
	c.queue = nil
	c.waiting.Store(0)
	for _, w := range queued {
		// Refund before waking: a woken waiter returns zero granted with a
		// definite error, so no credit is stranded by a lifecycle event.
		c.release(w.granted)
		w.granted = 0
		w.done = true
		w.err = c.gateErr
		w.signal()
	}
	c.wakeDrainLocked()
	c.mu.Unlock()
}

func (c *creditController) thaw() {
	c.mu.Lock()
	if !c.sealed {
		c.gateErr = nil
		c.gated.Store(false)
	}
	c.mu.Unlock()
}

// creditStatus snapshots the controller for Status/observability.
func (c *creditController) status() (setpoint, debt, ceiling int64, rate float64, waiting int) {
	c.mu.Lock()
	rate = c.decayedRateLocked(time.Now())
	waiting = len(c.queue)
	c.mu.Unlock()
	return c.setpoint.Load(), c.debt.Load(), c.ceiling, rate, waiting
}
