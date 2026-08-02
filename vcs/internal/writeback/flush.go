package writeback

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

const (
	// Batch dispatch thresholds.
	flushMaxRecords = 128
	flushMaxAge     = 10 * time.Millisecond

	// Retry backoff bounds (full jitter, no attempt limit).
	flushBackoffMin = 50 * time.Millisecond
	flushBackoffMax = 5 * time.Second

	// flushAttemptTimeout bounds ONE network flush attempt, so a blackholed
	// authority costs one bounded attempt on the backoff schedule and a
	// force-close can cancel the in-flight attempt promptly.
	flushAttemptTimeout = 30 * time.Second
)

// flushMaxBytes is the UPLINK amortization knob for the DATA lane: one batch is
// one request, one authority apply turn, and one reply, so everything a batch
// costs besides moving its bytes is paid once per batch. At 8 MiB the measured
// production shape was 1.52s per batch of which ~0.70s was transfer — 44%
// link utilization, i.e. the majority of a batch's wall time was the fixed
// cost, and each lane worker ships strictly one batch at a time.
//
// 32 MiB is the largest value that stays comfortably inside every bound
// that actually constrains it:
//
//   - THE REQUEST FRAME. A batch is one PFRQ2 request, bounded by
//     fsproto.maxRequestBytes (72 MiB). The build loop admits records while
//     bytes < flushMaxBytes, so the worst case is flushMaxBytes plus one
//     whole record (maxMutationPayload, 1 MiB + 64 KiB) plus per-record
//     paths and envelopes — ~34 MiB against a 72 MiB ceiling.
//   - THE JOURNAL ENTRY. wal.MaxPFR1RecordBytes and pfj3.MaxEntryBytes are
//     both 8 MiB and neither applies to the batch: the authority journals a
//     flush as ONE ROW PER RECORD (see fsproto flushBatchManaged), so the
//     entry bound is a bound on a single 1 MiB write, not on the batch. This
//     is the constraint that would otherwise cap the batch at 8 MiB, and it
//     is worth stating explicitly because the two numbers coinciding at
//     8 MiB invites exactly the wrong conclusion.
//   - THE RECORD COUNT. flushMaxRecords still caps the batch independently.
//     It is deliberately NOT raised with the byte bound: it bounds one
//     authority apply turn (each record is its own journal row), not the
//     transfer. The upload path the byte bound exists for chunks writes at
//     1 MiB, so 32 MiB is 32 records — a quarter of the record cap. A
//     workload of small records is bounded by the record count first and
//     amortizes the fixed cost less; that is a separate bound with a
//     separate argument, not a knob to turn here.
//   - THE RESEND CONTRACT. attemptEnd pins a batch by its END LANE SEQUENCE,
//     and a pinned resend replays exactly the records that sequence covers,
//     with no size bound applied — so an exact resend is byte-identical at any
//     batch size. Nothing here changes what a retry sends.
//   - THE CREDIT LEDGER and the metadata/control reserves are all sized in
//     WAL bytes and are independent of how the drained bytes are grouped for
//     transmission.
//
// The cost is transient client memory: one in-flight batch materializes its
// records on the heap plus its encoded frame, so ~64 MiB peak instead of
// ~16 MiB, against a 512 MiB default local budget.
//
// It is emphatically NOT the namespace lane's bound — see laneMaxBytes. The
// whole reason the batch may be this large is that nothing interactive is
// queued behind it any more.
//
// A var so the batch-size measurement can compare two values in one process;
// production never changes it.
var flushMaxBytes int64 = 32 << 20

// nsFlushMaxBytes bounds ONE namespace-lane request. Namespace records are
// hundreds of bytes, so this is never the binding constraint in practice
// (flushMaxRecords and flushMaxAge are); it exists so the lane's request size
// is a stated bound rather than an inherited one. A namespace batch must stay
// small enough that its TRANSFER TIME is not itself a latency source on a slow
// uplink: 1 MiB is a quarter second at the 4 MB/s the live battery measured.
var nsFlushMaxBytes int64 = 1 << 20

func laneMaxBytes(lane StreamLane) int64 {
	if lane == StreamLaneNamespace {
		return nsFlushMaxBytes
	}
	return flushMaxBytes
}

// noProgressWindow is the sticky-degraded watchdog: pending work whose
// authority watermark has not advanced for this long degrades the mount. It is
// also the credit gate's stall verdict — the one signal that turns "no credit
// yet" into ErrUplinkStalled. A var so tests compress it; production never
// changes it.
var noProgressWindow = 30 * time.Second

// SetNoProgressWindowForTest compresses the watchdog's verdict window and
// returns its restore.
//
// The verdict is a CROSS-PACKAGE contract now: clientcore's data gate classifies
// its own budget expiry from Engine.StallVerdict rather than from an arithmetic
// claim about this constant, and a test of that contract cannot spend 30 real
// seconds waiting for the window to become closable. Production never calls it.
func SetNoProgressWindowForTest(d time.Duration) (restore func()) {
	old := noProgressWindow
	noProgressWindow = d
	return func() { noProgressWindow = old }
}

// watchdogInterval is the health sweep cadence. The watchdog runs on its own
// goroutine so it fires even while a flush attempt is blocked inside the
// network call. A var for the same reason as noProgressWindow.
var watchdogInterval = time.Second

// pendingRec indexes one unshipped mutation: its payload stays in the WAL on
// disk and is re-read at send time, so a large backlog does not live on the
// heap.
type pendingRec struct {
	seq     uint64 // GLOBAL stream sequence (local identity)
	scope   string
	ordinal uint64
	off     int64
	length  int
	// data is the record's BULK payload size (zero for metadata records). The
	// credit ledger is charged in exactly these bytes at admission and refilled
	// in exactly these bytes when the authority applies them, so a grant and
	// its refund are the same quantity and the ledger cannot drift.
	data int
	// laneSeq is the record's dense sequence within its lane, and digest the
	// lane chain digest after it — the pair the authority verifies.
	laneSeq uint64
	digest  [32]byte
	// nsRequired is a data record's namespace dependency (zero on every other
	// lane): the namespace watermark it was admitted behind.
	nsRequired uint64
}

type drainWaiter struct {
	target uint64
	ch     chan error
}

// laneQueue is ONE lane's independently-applicable stream state: its unshipped
// records in sequence order, its durable watermark and chain digest, its retry
// pin, and its own progress clock.
//
// Everything in here used to be a single set of fields on the flusher, and that
// singleness WAS the defect this round exists to remove: one watermark over one
// chained stream means "apply through X" transitively means "apply everything
// admitted before X", so a metadata-only scope's release inherited the whole
// bulk backlog's drain time (measured: 18.99s cold p99 at 4 MB/s). Splitting the
// state is what lets the namespace watermark advance while megabytes of data sit
// unshipped.
type laneQueue struct {
	lane StreamLane

	pending []pendingRec
	// bytes is Σ payload length over pending. It is MAINTAINED rather than
	// summed on demand because the dispatch decision reads it on every run-loop
	// iteration, and the data lane's backlog is thousands of records under
	// exactly the flood this round exists to survive.
	bytes int64
	// applied is the authority's durable watermark IN LANE SEQUENCE.
	applied       uint64
	appliedDigest [32]byte
	// attemptEnd pins the exact batch prefix across ambiguous transport
	// failures, in LANE sequence. New admissions may extend pending while an
	// attempt is in flight, but retries MUST resend byte-for-byte the same
	// digest range until its authority outcome is definite. Otherwise a late
	// smaller request and a newer superset can reach the authority out of
	// order. The pin is per lane because the resend is per lane: two lanes
	// retrying at once are two independent exactness claims.
	attemptEnd uint64
	oldestAt   time.Time
	urgent     bool
	waiters    []*drainWaiter

	backoff     time.Duration
	nextAttempt time.Time
	// lastProgress is this lane's own advance clock. A shared clock would let a
	// healthy namespace lane mask a dead data lane, and a drain waiting on the
	// data lane would then never get a verdict — the exact permanent-draining
	// shape round 3 eliminated.
	//
	// It moves on this lane's authority watermark advance, and on exactly one
	// other event: an advance in the lane this one is DEPENDENCY-BLOCKED on (see
	// laneDependencyBlockedLocked and advance). That is not a shared clock
	// creeping back in. A blocked lane is forbidden by this client to dispatch
	// at all, so its own watermark cannot move by construction, and reading its
	// stillness as evidence about the far end is reading the client's own queue
	// discipline as a fault in the authority. The lane it waits on is watched on
	// its own terms, and when THAT lane goes quiet the inheritance stops with
	// it — so a genuinely dead uplink still closes the window here.
	lastProgress time.Time

	wake chan struct{}
}

// flusher owns network flush ordering. Each lane has its own worker goroutine,
// its own dense batches with explicit scope runs, and its own exact watermark
// reconciliation; health, parking and the credit ledger stay stream-wide.
type flusher struct {
	e *Engine

	mu     sync.Mutex
	lanes  [streamLaneCount]laneQueue
	stream streamMark // the GLOBAL applied prefix and every lane's mark at it

	pendingBytes int64
	// admitted is the highest GLOBAL sequence ever handed to this flusher. With
	// no lane holding anything, it IS the applied prefix.
	admitted uint64
	perScope map[string]int
	// perScopeData counts a scope's UNAPPLIED data-lane records. It is the lane
	// router's whole input: a namespace record admitted into a scope with
	// unapplied bulk data must apply after it, so it joins the data lane
	// instead (see Engine.streamLaneLocked). Zero means every data record of
	// that scope is durable at the authority, so a namespace record admitted
	// now cannot be ordered before any of them.
	perScopeData map[string]int

	degraded    bool
	lastFailure string
	lastFailAt  time.Time
	terminal    error

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func newFlusher(e *Engine) *flusher {
	f := &flusher{
		e: e, perScope: map[string]int{}, perScopeData: map[string]int{},
		stopCh: make(chan struct{}),
	}
	for lane := range f.lanes {
		f.lanes[lane] = laneQueue{
			lane:          StreamLane(lane),
			appliedDigest: digestZero(),
			wake:          make(chan struct{}, 1),
		}
		f.stream.lanes[lane].digest = digestZero()
	}
	return f
}

func (f *flusher) start() {
	f.wg.Add(1 + streamLaneCount)
	for lane := range f.lanes {
		lane := StreamLane(lane)
		go func() { defer f.wg.Done(); f.run(lane) }()
	}
	go func() { defer f.wg.Done(); f.watchdogLoop() }()
}

// stop signals every lane worker and waits for ACTUAL termination. The engine
// cancels its lifetime context first, which resolves any in-flight remote
// call promptly, so a late flush can never run against a closed WAL.
func (f *flusher) stop() {
	select {
	case <-f.stopCh:
	default:
		close(f.stopCh)
	}
	f.mu.Lock()
	var waiters []*drainWaiter
	for lane := range f.lanes {
		waiters = append(waiters, f.lanes[lane].waiters...)
		f.lanes[lane].waiters = nil
	}
	f.mu.Unlock()
	for _, waiter := range waiters {
		waiter.ch <- ErrFenced
	}
	f.wg.Wait()
}

// watchdogLoop sweeps health on its own goroutine: a flush attempt blocked
// inside the network call cannot starve the no-progress verdict.
func (f *flusher) watchdogLoop() {
	t := time.NewTicker(watchdogInterval)
	defer t.Stop()
	for {
		select {
		case <-f.stopCh:
			return
		case <-t.C:
			f.watchdog()
			// Republish the setpoint on the same cadence so a collapsing rate
			// shrinks the gate even with nobody waiting on it.
			f.e.credits.tick()
		}
	}
}

// admit registers appended records. Caller holds e.mu (append order == seq
// order). Every result carries its own lane, so one call never spans lanes.
// dataBytes, when non-nil, is parallel to results and carries each record's
// bulk payload size; nil means the record class carries no bulk bytes.
func (f *flusher) admit(scope string, results []appendResult, dataBytes []int) {
	if len(results) == 0 {
		return
	}
	lane := results[0].lane
	f.mu.Lock()
	q := &f.lanes[lane]
	for i, r := range results {
		bulk := 0
		if i < len(dataBytes) {
			bulk = dataBytes[i]
		}
		q.pending = append(q.pending, pendingRec{
			seq: r.seq, scope: scope, ordinal: r.ordinal,
			off: r.payloadOff, length: r.payloadLen, data: bulk,
			laneSeq: r.laneSeq, digest: r.digest, nsRequired: r.nsRequired,
		})
		q.bytes += int64(r.payloadLen)
		f.pendingBytes += int64(r.payloadLen)
		f.admitted = max(f.admitted, r.seq)
		f.perScope[scope]++
		if lane == StreamLaneData {
			f.perScopeData[scope]++
		}
	}
	if q.oldestAt.IsZero() {
		q.oldestAt = time.Now()
		q.lastProgress = time.Now()
	}
	f.mu.Unlock()
	f.kick(lane)
}

func (f *flusher) kick(lane StreamLane) {
	select {
	case f.lanes[lane].wake <- struct{}{}:
	default:
	}
}

func (f *flusher) outstanding(scope string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.perScope[scope]
}

// scopeHasUnappliedData reports whether scope still holds data-lane records the
// authority has not applied. It is the lane router's question, asked under the
// same e.mu that admits the record, so the answer cannot change underneath it:
// the count only rises through admit (which holds e.mu) and only falls through
// advance (which holds f.mu and retires records the authority has made
// durable).
func (f *flusher) scopeHasUnappliedData(scope string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.perScopeData[scope] > 0
}

// scopeTails reports, per lane, the highest admitted LANE SEQUENCE still
// unshipped for scope (0 = that lane holds nothing for this scope).
//
// It is the drain target a RELEASE of that scope actually needs. Releasing a
// scope means one thing: everything this mount acknowledged locally under that
// grant is durable at the authority, so a peer that acquires it next sees the
// complete state. Nothing about that claim mentions the rest of the stream, and
// — since round 7 — nothing about it mentions the OTHER LANE either.
//
// That second narrowing is the round's whole point. Round 3 already reduced the
// target from the STREAM's tail to the SCOPE's tail, but a single chained
// stream made "this scope's last record" transitively mean "every record
// admitted before it", including every megabyte of unrelated bulk data. A
// metadata-only scope therefore inherited the bulk backlog's drain time — 18.99s
// at 4 MB/s in the throttled contract test, 38s live. With lanes, a scope that
// has no data-lane record waits on the namespace watermark alone, and the
// namespace lane's backlog is its own records only.
//
// Within a lane the stream is still dense and ordered, so waiting for THIS
// scope's last record still implies waiting for everything of that lane
// appended before it. That is inherent and correct — those bytes precede the
// scope's own state at the authority. What is excluded is everything appended
// AFTER (admission for a draining delegation is already closed) and everything
// in the OTHER lane, which by the lane-routing rule cannot be ordered before
// this scope's namespace records.
func (f *flusher) scopeTails(scope string) [streamLaneCount]uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var tails [streamLaneCount]uint64
	if f.perScope[scope] == 0 {
		return tails
	}
	for lane := range f.lanes {
		q := &f.lanes[lane]
		for i := len(q.pending) - 1; i >= 0; i-- {
			if q.pending[i].scope == scope {
				tails[lane] = q.pending[i].laneSeq
				break
			}
		}
	}
	return tails
}

func (f *flusher) pendingStats() (int, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for lane := range f.lanes {
		n += len(f.lanes[lane].pending)
	}
	return n, f.pendingBytes
}

// appliedThrough is the GLOBAL applied prefix: the highest global sequence such
// that every record at or below it is durable at the authority. It is what
// segment reclamation, extent folding and the recovery job counters are
// statements about, and it is deliberately a PREFIX rather than a per-lane
// maximum — a segment holds records of both lanes, so retiring it needs both.
func (f *flusher) appliedThrough() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stream.global
}

// laneApplied reads one lane's durable watermark.
func (f *flusher) laneApplied(lane StreamLane) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lanes[lane].applied
}

// drainThrough blocks until LANE's authority watermark covers target, the
// stream parks terminally, the WATCHDOG declares that lane stalled, or ctx ends.
//
// The watchdog arm is not a convenience, it is the bound. A delegation release
// runs detached under the ENGINE's lifetime context — deliberately, so that a
// cancelled request cannot interrupt Checkin — and until this function had a
// verdict of its own that meant a release against an authority which had stopped
// applying waited FOREVER. The scope stayed `draining` with drainErr never set,
// which is the one state that has no exit: every later mutation on that scope
// joins the same attempt, the namespace lock holder in front of them never
// returns, and the mount wedges. Observed live at 13-14 minutes with ~100
// frontend goroutines queued behind one release.
//
// The verdict makes it definite instead. A stalled uplink yields
// ErrUplinkStalled, the caller records it as drainErr, and the scope LEAVES
// draining with a recorded reason — the same shape a fence or a park produces,
// and the same one force-detach relies on: the grant can be surrendered with the
// tail parked durably. A scope must never be permanently draining.
//
// It cannot fire on a healthy-but-slow link: the window is measured from that
// lane's last watermark ADVANCE, so any progress at all rearms it.
func (f *flusher) drainThrough(ctx context.Context, lane StreamLane, target uint64) error {
	if target == 0 {
		return nil
	}
	f.mu.Lock()
	q := &f.lanes[lane]
	if q.applied >= target {
		f.mu.Unlock()
		return nil
	}
	if f.terminal != nil {
		err := f.terminal
		f.mu.Unlock()
		return err
	}
	q.urgent = true
	// A barrier tries NOW: the backoff schedule protects steady state, not
	// an explicit durability request after a transient failure.
	q.nextAttempt = time.Time{}
	w := &drainWaiter{target: target, ch: make(chan error, 1)}
	q.waiters = append(q.waiters, w)
	verdict := f.laneStallVerdictLocked(lane, time.Now())
	f.mu.Unlock()
	f.kick(lane)
	drop := func() {
		f.mu.Lock()
		q := &f.lanes[lane]
		for i, waiter := range q.waiters {
			if waiter == w {
				q.waiters = append(q.waiters[:i], q.waiters[i+1:]...)
				break
			}
		}
		f.mu.Unlock()
	}
	// Arm for the exact instant the watchdog could first declare, then re-ask.
	// Sleeping on the verdict's own Remaining keeps this free of a second stall
	// policy: the timer is a wake-up, the verdict is the decision.
	timer := time.NewTimer(stallRecheckDelay(verdict))
	defer timer.Stop()
	for {
		select {
		case err := <-w.ch:
			return err
		case <-ctx.Done():
			drop()
			return ctx.Err()
		case <-timer.C:
			if v := f.laneStallVerdict(lane); v.Stalled {
				drop()
				return ErrUplinkStalled
			} else {
				timer.Reset(stallRecheckDelay(v))
			}
		}
	}
}

// drainLanesThrough drains every lane's target. Targets are per lane and a zero
// target is "this lane holds nothing for the caller", so a metadata-only scope
// waits on the namespace lane alone — which is exactly the contract this round
// delivers.
//
// The order is namespace FIRST, deliberately. It is the lane that is fast, and
// the lane a data batch's dependency names: draining it first can only help the
// data lane's own dispatch, never delay it.
func (f *flusher) drainLanesThrough(ctx context.Context, targets [streamLaneCount]uint64) error {
	order := [...]StreamLane{StreamLaneNamespace, StreamLaneLegacy, StreamLaneData}
	for _, lane := range order {
		if err := f.drainThrough(ctx, lane, targets[lane]); err != nil {
			return err
		}
	}
	return nil
}

// drainAll drains every lane to the WAL's own tail: the fsync-class barrier,
// which by definition is a claim about everything this mount has acknowledged
// and therefore about both lanes.
func (f *flusher) drainAll(ctx context.Context, w *streamWAL) error {
	lanes := w.Lanes()
	var targets [streamLaneCount]uint64
	for i := range lanes {
		targets[i] = lanes[i].through
	}
	return f.drainLanesThrough(ctx, targets)
}

// stallRecheckDelay is how long a drain may sleep before asking the watchdog
// again: exactly the time the verdict says it still needs, floored so a verdict
// that is momentarily unavailable (no pending work registered yet) does not spin.
func stallRecheckDelay(v StallVerdict) time.Duration {
	const floor = 100 * time.Millisecond
	if v.Remaining < floor {
		return floor
	}
	return v.Remaining
}

func (f *flusher) run(lane StreamLane) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-f.stopCh:
			return
		default:
		}
		f.mu.Lock()
		wait := f.nextWaitLocked(lane)
		f.mu.Unlock()
		if wait == 0 {
			f.sendBatch(lane)
			continue
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-f.stopCh:
			return
		case <-f.lanes[lane].wake:
		case <-timer.C:
		}
	}
}

// nextWaitLocked reports how long to wait before the next dispatch attempt for
// lane (0 = dispatch now).
func (f *flusher) nextWaitLocked(lane StreamLane) time.Duration {
	q := &f.lanes[lane]
	if len(q.pending) == 0 || f.terminal != nil {
		return time.Hour
	}
	if until := time.Until(q.nextAttempt); until > 0 {
		return until
	}
	// THE CROSS-LANE DEPENDENCY, CLIENT SIDE. A data batch may not be offered
	// ahead of the namespace state its records were admitted behind. The
	// authority enforces this too (and definitively); refusing to dispatch here
	// keeps the steady state free of a round trip that would only be held.
	if blocked, _ := f.laneDependencyBlockedLocked(lane); blocked {
		return flushMaxAge
	}
	if q.urgent || len(q.pending) >= flushMaxRecords || q.bytes >= laneMaxBytes(lane) {
		return 0
	}
	if age := time.Since(q.oldestAt); age >= flushMaxAge {
		return 0
	}
	return flushMaxAge - time.Since(q.oldestAt)
}

// nextBatchLenLocked selects the prefix of q.pending that the NEXT attempt on
// this lane would carry: the pinned range if a resend is armed, otherwise the
// dense run the size bounds admit.
//
// It is factored out because two callers have to agree about it EXACTLY. The
// dispatch decision (nextWaitLocked) and the dispatch itself (sendBatch) both
// ask whether the next batch may go, and if they select different batches they
// answer different questions: the loop used to test the HEAD record's namespace
// dependency while sendBatch tested the MAXIMUM over the whole batch, so the
// loop could wave through a batch sendBatch then refused. That disagreement was
// structural, not a bug in either predicate, and the only way to remove it is to
// make "the next batch" one definition.
//
// A pinned selection is returned as-is even when it does not cover the pin;
// validating the pin is sendBatch's job, because the answer there is to PARK the
// stream and this is a read.
func (f *flusher) nextBatchLenLocked(q *laneQueue) int {
	if q.attemptEnd != 0 {
		n := 0
		for n < len(q.pending) && q.pending[n].laneSeq <= q.attemptEnd {
			n++
		}
		return n
	}
	n := 0
	var bytes int64
	maxBytes := laneMaxBytes(q.lane)
	for n < len(q.pending) && n < flushMaxRecords && bytes < maxBytes {
		bytes += int64(q.pending[n].length)
		n++
	}
	return n
}

// laneDependencyBlockedLocked is THE dispatchability predicate: may the batch
// this lane would offer right now be sent, or is it still waiting on the
// namespace state its records were admitted behind? needed is the namespace
// watermark that batch declares (its MAXIMUM nsRequired — every record in the
// request has to be applicable, not just the first).
//
// Only the data lane can be blocked, and only ever on the namespace lane, so
// this cannot deadlock: the namespace lane's own dispatch consults nothing.
//
// The distinction this names is the one the health machinery kept getting
// wrong. A blocked lane is not a failing lane and not a slow lane — it is a lane
// with nothing it is ALLOWED to do yet, and the thing it is waiting for lives in
// another lane that is being watched on its own terms. Wherever the engine asks
// "has this lane made progress", it first has to ask this.
func (f *flusher) laneDependencyBlockedLocked(lane StreamLane) (blocked bool, needed uint64) {
	q := &f.lanes[lane]
	if lane != StreamLaneData || len(q.pending) == 0 {
		return false, 0
	}
	for _, p := range q.pending[:f.nextBatchLenLocked(q)] {
		needed = max(needed, p.nsRequired)
	}
	return needed > f.lanes[StreamLaneNamespace].applied, needed
}

// sendBatch builds and ships the next dense run of one lane.
func (f *flusher) sendBatch(lane StreamLane) {
	f.mu.Lock()
	q := &f.lanes[lane]
	if len(q.pending) == 0 || f.terminal != nil {
		q.urgent = len(q.pending) != 0 && q.urgent
		f.mu.Unlock()
		return
	}
	n := f.nextBatchLenLocked(q)
	if q.attemptEnd != 0 && (n == 0 || q.pending[n-1].laneSeq != q.attemptEnd) {
		err := fmt.Errorf("%w: pinned %s-lane flush batch ending at %d is absent from pending stream", ErrConflict, lane, q.attemptEnd)
		f.mu.Unlock()
		f.park(err)
		return
	}
	// Asked over the SAME selection the batch is built from, and under the same
	// hold of f.mu, so this is the authoritative answer rather than a second
	// opinion: an admission that arrived since the run loop last looked can
	// widen the batch and raise its declared watermark, and that has to be
	// caught here, where the request is actually formed.
	//
	// A hold is deliberately NOT noteFailure. It used to be, and that was wrong
	// in both directions. It wrote the hold into the stream-wide lastFailure, so
	// a perfectly healthy stream reported "data batch requires namespace
	// watermark N" as its failure string in Status and in the watchdog's health
	// message — a diagnosis pointing at nothing. And it grew this lane's
	// exponential backoff, up to five seconds, for a condition that resolves the
	// instant the namespace lane advances and already wakes this worker by kick:
	// the penalty for waiting was a delay in noticing the wait had ended. No
	// request was sent, nothing failed, and nothing here is retried — the run
	// loop re-polls on flushMaxAge and the namespace advance kicks it sooner.
	blocked, nsRequired := f.laneDependencyBlockedLocked(lane)
	if blocked {
		f.mu.Unlock()
		return
	}
	if q.attemptEnd == 0 {
		q.attemptEnd = q.pending[n-1].laneSeq
	}
	batch := append([]pendingRec(nil), q.pending[:n]...)
	prevDigest := q.appliedDigest
	f.mu.Unlock()

	e := f.e
	e.mu.RLock()
	w := e.wal
	epochs := make(map[string]string, len(batch))
	for _, p := range batch {
		d := e.delegations[p.scope]
		if d == nil {
			continue
		}
		epochs[p.scope] = d.epoch
	}
	e.mu.RUnlock()
	if w == nil {
		f.park(fmt.Errorf("%w: pending records have no live WAL", ErrConflict))
		return
	}
	scopeRuns := make([]FlushScope, 0, len(batch))
	for _, p := range batch {
		epoch := epochs[p.scope]
		if epoch == "" {
			// A record without its live grant cannot exist (drain precedes
			// every release); this is engine-state corruption.
			f.park(fmt.Errorf("%w: pending record for %q has no live delegation", ErrConflict, p.scope))
			return
		}
		if len(scopeRuns) != 0 &&
			scopeRuns[len(scopeRuns)-1].Scope == p.scope &&
			scopeRuns[len(scopeRuns)-1].Epoch == epoch {
			scopeRuns[len(scopeRuns)-1].Through = p.laneSeq
		} else {
			scopeRuns = append(scopeRuns, FlushScope{Scope: p.scope, Epoch: epoch, Through: p.laneSeq})
		}
	}
	if len(scopeRuns) == 0 {
		// A record without its live grant cannot exist (drain precedes every
		// release); this is engine-state corruption.
		f.park(fmt.Errorf("%w: pending batch has no scope runs", ErrConflict))
		return
	}
	records := make([]wal.Record, 0, len(batch))
	for _, p := range batch {
		payload, err := w.ReadPayload(p.ordinal, p.off, p.length)
		if err != nil {
			f.park(fmt.Errorf("%w: pending payload unreadable: %v", ErrCorrupt, err))
			return
		}
		rec, err := wal.DecodePFR1(payload)
		if err != nil {
			f.park(fmt.Errorf("%w: pending payload undecodable: %v", ErrCorrupt, err))
			return
		}
		// The authority sequences records IN LANE SPACE: that is what its
		// density check and its digest chain are written in.
		rec.Seq = p.laneSeq
		records = append(records, rec)
	}
	ctx, cancel := context.WithTimeout(e.ctx, flushAttemptTimeout)
	reply, err := e.remote.Flush(ctx, FlushRequest{
		WritebackID: e.writebackID,
		Lane:        lane, NSRequired: nsRequired,
		PrevDigest: prevDigest, EndDigest: batch[len(batch)-1].digest,
		Records: records, ScopeRuns: scopeRuns,
	})
	cancel()
	if err != nil {
		f.noteFailure(lane, err.Error())
		return
	}
	switch {
	case reply.Status == 0:
		// The durable watermark is EXACTLY reply.Through, never past it. A
		// success must name this batch's exact end. A short watermark would
		// drop unshipped records; a watermark past the sent end claims bytes
		// this request never supplied. Either is a protocol-integrity failure.
		if batchEnd := batch[len(batch)-1].laneSeq; reply.Through != batchEnd {
			f.park(fmt.Errorf("%w: %s-lane flush succeeded with authority watermark %d, want exact batch end %d", ErrConflict, lane, reply.Through, batchEnd))
			return
		}
		f.advance(lane, reply.Through)
	case reply.Status == 116: // ESTALE: fenced or scope no longer live
		f.park(fmt.Errorf("%w: authority fenced the stream (status %d)", ErrFenced, reply.Status))

	// ── PROVEN CONTRADICTION: terminal ───────────────────────────────────────
	//
	// A status may end a stream only when it is a statement ABOUT THIS BATCH
	// that re-sending the identical bytes cannot change. There are exactly two,
	// and both are decided by the authority from the batch's own content:
	//
	//	EINVAL (22)  workfs.ErrWritebackCorrupt — the stream's typed structure
	//	             does not decode or its digest chain does not link.
	//	EPERM  (1)   a record falls outside the granted checkout subtree.
	//
	// Neither can be relieved by anything, on either side, ever. Parking is the
	// honest outcome: the tail stays available for local sync and attach-time
	// recovery, and the mount stops pretending it can drain.
	case reply.Status == 22 || reply.Status == 1:
		f.park(fmt.Errorf(
			"%w: authority rejected the batch's own content (status %d)",
			ErrConflict, reply.Status,
		))

	// ── DEFINITE CAPACITY REFUSAL: terminal, and NAMED ───────────────────────
	//
	//	ENOSPC (28)   a bounded store on the authority is full — its resident
	//	              dirty-block pool (VCS_DIRTY_RSS_MAX_MB) or its WAL.
	//	EDQUOT (122)  the generation's durable journal backlog quota.
	//
	// These are the ONLY two statuses fsproto's quota classifier issues, from
	// the exact path and the flush path alike, and unlike EIO or an unknown
	// status they name the condition exactly: nothing was applied because a
	// bounded resource is full.
	//
	// They belong here rather than in the retry arm below for one reason that
	// production proved: RETRYING THEM FROM THIS SIDE NEVER TERMINATES. The
	// refusal is a statement about a bounded resource at the AUTHORITY, and no
	// number of re-offers from the client changes it. Held as a transient it
	// froze the watermark, tripped the no-progress watchdog, and took a live
	// mount to EIO; the operator's documented escape (truncate to release the
	// memory) was itself EIO by the time it could be issued.
	//
	// Round 19 gave the AUTHORITY a release path for its dirty pool
	// (history-cut adoption now folds it — workfs/dirtyfold.go), which is why
	// a healthy volume should never produce this status at all. It does not
	// change the classification one bit: relief still happens over there, on
	// the authority's own schedule, and a client that sat here re-offering
	// would still be a client inventing progress it cannot make. Parking with
	// a definite verdict and letting the application see ENOSPC remains the
	// only honest answer.
	//
	// So the verdict is taken at face value and the stream parks — with a cause
	// that wraps ErrNoSpace, so every surface that already maps writeback
	// errors (clientcore statusErr, the FUSE mount) answers the application a
	// real ENOSPC. That is the whole point: a write that cannot be made durable
	// must FAIL, in the application's own hands, with the errno POSIX defines
	// for exactly this. An unexplained stall is not an answer.
	//
	// This does not weaken the "UNKNOWN IS RETRYABLE" rule above it — it is the
	// enumerated exception that rule always allowed for. Terminal still
	// requires proof; a named capacity refusal is proof, and a catch-all is not.
	case reply.Status == 28 || reply.Status == 122: // ENOSPC / EDQUOT
		f.park(fmt.Errorf(
			"%w: authority refused the %s-lane batch for capacity (status %d); "+
				"nothing on this side can relieve it",
			ErrNoSpace, lane, reply.Status,
		))

	// ── EVERYTHING ELSE: retryable under the watchdog ────────────────────────
	//
	// This default used to park the stream as a terminal ErrConflict, which
	// latched ErrFailedClosed and took the whole live mount to EIO — for good,
	// with the authority demonstrably reachable and the backlog undrained.
	// Production reached it with ONE reply carrying status 5.
	//
	// Status 5 is not a conflict. EIO is the authority's CATCH-ALL for an error
	// it did not classify (fsproto.toErrno's default), so it means "something
	// went wrong at the far end" and nothing whatsoever about this batch. The
	// same is true of any status a future authority adds that this client does
	// not yet know. Reading either as a proven contradiction is the client
	// inventing a verdict from an absence of information, and the cost of being
	// wrong is a permanently destroyed mount.
	//
	// So the rule is inverted, and it is the only sound direction: UNKNOWN IS
	// RETRYABLE. Terminal requires proof, and proof is enumerated above.
	//
	// This is not "retry until it works". noteFailure enters the same bounded
	// machinery every transport failure already uses: exponential backoff, and
	// the flusher's no-progress watchdog as the ONE stall verdict. An authority
	// that keeps refusing stops making durable progress, uplinkStalled() goes
	// true within noProgressWindow, and every frontend surfaces the EIO-class
	// answer it surfaces for a dead uplink — while force-detach still parks the
	// stream durably and recovery still replays it. Bounded, definite, and
	// reversible the instant the far end recovers, which is exactly what a
	// two-minute database outage deserves instead of a forty-minute one.
	//
	// EAGAIN is also how the authority reports a HELD data batch whose
	// namespace dependency is not applied yet. That is a hold, not a verdict,
	// and it resolves by itself the moment the namespace lane advances.
	case reply.Status == 11: // EAGAIN: the authority's typed retryable answer
		f.noteFailure(lane, "authority cannot apply this batch yet (EAGAIN)")
	default:
		f.noteFailure(lane, fmt.Sprintf(
			"authority rejected the flush with unclassified status %d; retrying",
			reply.Status,
		))
	}
}

// advance applies one lane's authority watermark: trims that lane's pending
// prefix, recomputes the GLOBAL applied prefix, wakes the lane's drains, and
// records the durable APPLIED checkpoint.
func (f *flusher) advance(lane StreamLane, through uint64) {
	f.mu.Lock()
	q := &f.lanes[lane]
	if q.attemptEnd != 0 && through >= q.attemptEnd {
		q.attemptEnd = 0
	}
	// THE DEPENDENCY-BLOCKED LANE INHERITS THIS ADVANCE.
	//
	// Two conditions, and both are load-bearing. The watermark must actually
	// MOVE: a success reply naming a watermark this lane already holds is a
	// resend landing on durable state, and while that is a live round trip it is
	// not new progress — crediting it would let a namespace lane looping on
	// already-applied batches keep the data lane's clock fresh while its own ran
	// out, which is a hole exactly the size of the one being closed. And the
	// block must be read BEFORE q.applied moves, because the question is about
	// the interval this advance closes: the lane was held for all of it,
	// including by the advance that finally releases it, and that last one is
	// precisely the moment it inherits a clock it then has to run on alone.
	//
	// See laneDependencyBlockedLocked for why this is the honest reading and not
	// a favour. A blocked data lane has not failed to make progress; it has not
	// been ALLOWED to, by a rule this client enforces on itself, and the entity
	// that decides when it may go is the namespace lane's watermark. So the
	// namespace lane's advances ARE the blocked lane's progress, and this is the
	// one place they are observed.
	//
	// It is inheritance and not exemption, and the difference is the whole
	// safety argument: when the namespace lane stops advancing there are no
	// advances to inherit, the blocked lane's clock freezes where the last one
	// left it, and the window closes on it exactly as it would on any other
	// silent lane. A dead uplink still reaches a verdict, so a drain on the data
	// lane still terminates. Nothing here can hide one.
	//
	// It also stays narrow. Only a lane the predicate says is blocked takes
	// anything from this, so the round-7 property that a healthy namespace lane
	// must never mask a DEAD data lane is untouched: an unblocked data lane that
	// stops applying keeps its own frozen clock however busy the other lane is.
	now := time.Now()
	if lane == StreamLaneNamespace && through > q.applied {
		if blocked, _ := f.laneDependencyBlockedLocked(StreamLaneData); blocked {
			f.lanes[StreamLaneData].lastProgress = now
		}
	}
	if through > q.applied {
		q.applied = through
		q.lastProgress = now
	}
	i := 0
	var appliedData, appliedTotal int64
	for i < len(q.pending) && q.pending[i].laneSeq <= through {
		appliedData += int64(q.pending[i].data)
		appliedTotal += int64(q.pending[i].length)
		q.bytes -= int64(q.pending[i].length)
		f.pendingBytes -= int64(q.pending[i].length)
		scope := q.pending[i].scope
		f.perScope[scope]--
		if f.perScope[scope] == 0 {
			delete(f.perScope, scope)
		}
		if lane == StreamLaneData {
			f.perScopeData[scope]--
			if f.perScopeData[scope] == 0 {
				delete(f.perScopeData, scope)
			}
		}
		q.appliedDigest = q.pending[i].digest
		i++
	}
	q.pending = q.pending[i:]
	if len(q.pending) == 0 {
		q.oldestAt = time.Time{}
		q.urgent = false
	} else {
		q.oldestAt = time.Now()
	}
	q.backoff = 0
	q.nextAttempt = time.Time{}
	if f.degraded && f.allLanesDrainedLocked() {
		// Every admission from before the failure is applied: clear the
		// sticky verdict (lastFailure stays visible for diagnosis).
		f.degraded = false
		f.notifyHealthLocked(nil)
	}
	f.recomputeStreamLocked()
	var ready []*drainWaiter
	kept := q.waiters[:0]
	for _, wtr := range q.waiters {
		if wtr.target <= q.applied {
			ready = append(ready, wtr)
		} else {
			kept = append(kept, wtr)
		}
	}
	q.waiters = kept
	// Capture the whole applied position atomically: a racing later advance in
	// the other lane must not pair this global watermark with a newer lane
	// digest in the APPLIED checkpoint.
	mark := f.stream
	f.mu.Unlock()
	// A namespace advance can release a data batch that was waiting on its
	// dependency. Nudge the data worker rather than making it poll.
	if lane == StreamLaneNamespace {
		f.kick(StreamLaneData)
	}
	// The ONLY input to the credit controller: bytes the authority made
	// durable. Never an attempt, never a heartbeat, never a local append.
	//
	// It runs BEFORE the drain waiters are woken, and the order is load-bearing.
	// A drain waiter's whole claim is "everything admitted up to my target is
	// applied", and the credit ledger is part of what that means: a waiter woken
	// first can observe a drained stream whose ledger still carries the debt for
	// the very bytes that drain just retired. Returning the credit first makes
	// the two views agree at the instant the waiter is released.
	f.e.credits.noteApplied(appliedData, appliedTotal, time.Now())
	for _, wtr := range ready {
		wtr.ch <- nil
	}
	f.e.noteApplied(mark)
}

func (f *flusher) allLanesDrainedLocked() bool {
	for lane := range f.lanes {
		if len(f.lanes[lane].pending) != 0 {
			return false
		}
	}
	return true
}

// recomputeStreamLocked republishes the GLOBAL applied prefix and the per-lane
// marks at it.
//
// The prefix is the lowest still-unshipped global sequence minus one, over ALL
// lanes — not the maximum of the lanes' own progress. Segment reclamation and
// extent folding are statements about the global sequence, and a segment holds
// records of both lanes, so a segment is only retirable when both lanes have
// passed it. This is the one place lane independence is deliberately given up,
// and it costs nothing that matters: reclamation is a space optimisation with no
// latency contract, whereas a release is a latency contract with no space one.
func (f *flusher) recomputeStreamLocked() {
	first := uint64(0)
	for lane := range f.lanes {
		if p := f.lanes[lane].pending; len(p) > 0 {
			if first == 0 || p[0].seq < first {
				first = p[0].seq
			}
		}
	}
	// With nothing unshipped the prefix is everything ever admitted. f.admitted
	// is tracked here rather than read from the WAL on purpose: admission takes
	// e.mu then f.mu, so reaching back for e.mu under f.mu would invert the
	// order and deadlock.
	global := f.admitted
	if first > 0 {
		global = first - 1
	}
	if global < f.stream.global {
		global = f.stream.global
	}
	f.stream.global = global
	for lane := range f.lanes {
		f.stream.lanes[lane] = laneMark{
			through: f.lanes[lane].applied,
			digest:  f.lanes[lane].appliedDigest,
		}
	}
}

// appliedState reads the whole applied position atomically.
func (f *flusher) appliedState() streamMark {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stream
}

// noteFailure schedules the jittered retry for one lane and feeds the watchdog.
func (f *flusher) noteFailure(lane StreamLane, msg string) {
	f.mu.Lock()
	q := &f.lanes[lane]
	f.lastFailure = msg
	f.lastFailAt = time.Now()
	if q.backoff == 0 {
		q.backoff = flushBackoffMin
	} else {
		q.backoff = min(q.backoff*2, flushBackoffMax)
	}
	delay := time.Duration(rand.Int63n(int64(q.backoff) + 1))
	q.nextAttempt = time.Now().Add(delay)
	f.mu.Unlock()
}

// park permanently stops flushing EVERY lane (definite fence, conflict,
// corruption): the stream's written tail stays available for an explicit local
// sync and exact attach-time recovery. The engine seals all mutation admission —
// a local ack without a live stream would violate the active-delegation
// invariant, and another lane must not order around it.
//
// Parking is stream-wide on purpose. The lanes are independently APPLICABLE,
// not independently SURVIVABLE: they share a WAL, a session, a set of grants and
// a recovery job, so a proven contradiction in one is a proven contradiction
// about the stream that holds both.
func (f *flusher) park(err error) {
	f.mu.Lock()
	f.terminal = err
	f.lastFailure = err.Error()
	f.lastFailAt = time.Now()
	f.degraded = true
	var waiters []*drainWaiter
	for lane := range f.lanes {
		waiters = append(waiters, f.lanes[lane].waiters...)
		f.lanes[lane].waiters = nil
	}
	f.mu.Unlock()
	// LATCH BEFORE RELEASING THE WAITERS. A drain waiter wakes with the
	// terminal verdict in its hand and its very next act is typically to ask
	// the engine what the mount's standing answer now is (Engine.MutationError,
	// which clientcore's statusErr maps to the application's errno). Releasing
	// the waiters first left a window where DrainAll had already returned
	// ErrNoSpace while MutationError still said "healthy" — so a mutation
	// racing that window got the EIO-class default instead of the definite
	// ENOSPC this whole classification exists to deliver, and the parked
	// stream's own drain could report a verdict the engine did not yet hold.
	// Sealing the credit ledger and latching the engine first makes the
	// verdict indivisible: nobody can observe the refusal without also
	// observing that it is terminal.
	f.e.credits.seal(err)
	f.e.markStreamDead(err)
	for _, wtr := range waiters {
		wtr.ch <- err
	}
	if f.e.job != nil {
		f.e.job.update(func(j *RecoveryJob) {
			j.State = JobParked
			j.LastError = err.Error()
		})
		if persistErr := f.e.job.persist(); persistErr != nil {
			f.e.logf("writeback: persist parked recovery job: %v", persistErr)
		}
	}
}

func (e *Engine) markStreamDead(err error) {
	dead := e.failClosed(err)
	e.mu.Lock()
	if e.streamDead == nil {
		e.streamDead = dead
	}
	dead = e.streamDead
	for _, d := range e.delegations {
		if !d.draining {
			continue
		}
		d.drainErr = dead
		if d.attempt != nil {
			d.attempt.complete(dead)
		}
	}
	e.mu.Unlock()
}

// watchdog flips sticky degraded when ANY lane's pending work makes no
// watermark progress for the window.
//
// f.degraded is STREAM-WIDE, so what this sweep latches on one lane it latches
// on the mount. That is right for a lane that has genuinely gone silent and
// catastrophically wrong for a lane that is merely waiting on another lane's
// watermark, which is why a dependency-blocked lane's progress clock tracks the
// lane it waits on (see laneQueue.lastProgress). The sweep needs no case for it:
// it reads one clock per lane, and a blocked lane's clock is already telling the
// truth about whether anything is still moving.
func (f *flusher) watchdog() {
	f.mu.Lock()
	if !f.degraded {
		for lane := range f.lanes {
			q := &f.lanes[lane]
			if len(q.pending) > 0 && !q.lastProgress.IsZero() &&
				time.Since(q.lastProgress) >= noProgressWindow {
				f.degraded = true
				recs, bytes := len(q.pending), f.pendingBytes
				f.notifyHealthLocked(fmt.Errorf(
					"writeback: flush stalled: %d %s-lane records (%d bytes pending) with no watermark progress since %s (last failure: %s)",
					recs, StreamLane(lane), bytes, q.lastProgress.Format(time.RFC3339), f.lastFailure))
				break
			}
		}
	}
	f.mu.Unlock()
}

// StallVerdict is the flusher watchdog's LIVE state: the ONE place in the engine
// where a stall is decided. Admission gates RELAY it; they never synthesize one
// from elapsed time.
//
// It exists because elapsed time does not prove a verdict, and two admission
// gates used to assume it did. Each justified a fixed budget with the chain
//
//	noProgressWindow (30s) + creditWaitCap (5s) = 35s  <  budget (40s)
//
// and concluded that a genuinely stalled uplink must already have been DECLARED
// stalled by the time the budget expired — so expiry could only mean "healthy
// but slow". It cannot. The window below is measured from the last WATERMARK
// ADVANCE (advance resets lastProgress), not from the moment a caller began to
// wait: an operation that parks at t0 and sees the authority advance at t39
// reaches a 40s budget at t40 with the watchdog unable to declare anything
// before ~t69. Budget expiry proves NEITHER a stall NOR progress, so the gates
// ask for the verdict instead of deriving one.
//
//   - Stalled: the watchdog holds — or, recomputed now, would hold — a stall
//     verdict. This is the only thing that makes ErrUplinkStalled honest.
//   - Pending: there is pending work whose progress is being watched. With none,
//     there is nothing a stall could be a statement about.
//   - Remaining: how long until the watchdog COULD declare, measured from the
//     last advance. Zero when Stalled (it already has) and when !Pending (there
//     is nothing to declare). A non-zero Remaining is the exact refutation of
//     the old arithmetic: the verdict is NOT AVAILABLE yet, however long the
//     caller has already waited.
type StallVerdict struct {
	Stalled   bool
	Pending   bool
	Remaining time.Duration
}

// StallVerdict publishes the watchdog's live state to the admission gates — the
// namespace lane's own (AdmitMetadataMutation) and clientcore's data lane — so
// both classify their expiry from ONE verdict instead of restating an
// arithmetic proof of it in a comment.
//
// Across lanes it is the WORST of them: an uplink with one dead lane is a
// stalled uplink, whichever lane the asking caller happens to sit behind. Per-
// lane drains take the per-lane verdict instead, because a drain IS a statement
// about one lane.
func (e *Engine) StallVerdict() StallVerdict {
	if e == nil || e.fl == nil {
		return StallVerdict{}
	}
	return e.fl.stallVerdict()
}

// stallVerdict snapshots terminal, pending, degraded and lastProgress against
// noProgressWindow under ONE hold of f.mu. Reading them across separate holds
// would be two verdicts again: a caller could pair pending work observed before
// an advance with a lastProgress observed after it.
func (f *flusher) stallVerdict() StallVerdict {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	var worst StallVerdict
	for lane := range f.lanes {
		v := f.laneStallVerdictLocked(StreamLane(lane), now)
		if v.Stalled {
			return v
		}
		if !worst.Pending && v.Pending {
			worst = v
		} else if v.Pending && v.Remaining < worst.Remaining {
			worst = v
		}
	}
	return worst
}

func (f *flusher) laneStallVerdict(lane StreamLane) StallVerdict {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.laneStallVerdictLocked(lane, time.Now())
}

func (f *flusher) laneStallVerdictLocked(lane StreamLane, now time.Time) StallVerdict {
	if f.terminal != nil {
		// A parked stream is stalled with or without pending work: nothing it
		// holds can ever be applied, and nothing will ever advance again.
		return StallVerdict{Stalled: true}
	}
	q := &f.lanes[lane]
	if len(q.pending) == 0 {
		return StallVerdict{}
	}
	v := StallVerdict{Pending: true}
	switch {
	case f.degraded:
		// The health sweep already latched the sticky verdict.
		v.Stalled = true
	case q.lastProgress.IsZero():
		// Pending work whose progress clock never started. Nothing has been
		// observed to stall yet, and a whole window would have to elapse first.
		v.Remaining = noProgressWindow
	default:
		// The same recomputation the sweep does, deliberately live rather than
		// waiting for the sweep tick, so a paced caller's outcome does not
		// depend on watchdog phase.
		if since := now.Sub(q.lastProgress); since >= noProgressWindow {
			v.Stalled = true
		} else {
			v.Remaining = noProgressWindow - since
		}
	}
	return v
}

// uplinkStalled is the credit gate's stall verdict, and it is now exactly the
// Stalled field of the one verdict above rather than a second computation that
// has to be kept in agreement with it.
func (f *flusher) uplinkStalled() bool { return f.stallVerdict().Stalled }

// notifyHealthLocked reports the sticky verdict without holding the caller's
// callback under f.mu.
func (f *flusher) notifyHealthLocked(err error) {
	cb := f.e.cfg.Events.OnHealth
	if cb == nil {
		return
	}
	if err == nil {
		err = f.e.MutationError()
	}
	go cb(err)
}

func (f *flusher) status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	records := 0
	var oldest time.Time
	var progress time.Time
	for lane := range f.lanes {
		q := &f.lanes[lane]
		records += len(q.pending)
		if !q.oldestAt.IsZero() && (oldest.IsZero() || q.oldestAt.Before(oldest)) {
			oldest = q.oldestAt
		}
		if !q.lastProgress.IsZero() && (progress.IsZero() || q.lastProgress.Before(progress)) {
			progress = q.lastProgress
		}
	}
	st := Status{
		PendingRecords: records,
		PendingBytes:   f.pendingBytes,
		AppliedThrough: f.stream.global,
		Degraded:       f.degraded,
		LastFailure:    f.lastFailure,
	}
	if !oldest.IsZero() {
		st.OldestPendingMs = time.Since(oldest).Milliseconds()
	}
	if !progress.IsZero() {
		st.LastProgressMs = time.Since(progress).Milliseconds()
	}
	if f.terminal != nil {
		st.LastFailure = f.terminal.Error()
	}
	return st
}

// noteApplied lets the engine fold and reclaim behind the advancing
// watermark, and refreshes the recovery-job counters. Folding runs on every
// advance (not just under budget pressure): applied extents' bytes are
// authority-served now, so dropping them keeps the steady-state overlay heap
// proportional to the UNSHIPPED tail, not to everything ever written.
func (e *Engine) noteApplied(mark streamMark) {
	through := mark.global
	e.mu.Lock()
	w := e.wal
	for _, fv := range e.files {
		fv.foldApplied(through)
	}
	if w != nil {
		pins := map[uint64]bool{}
		for _, fv := range e.files {
			fv.segmentsPinned(pins)
		}
		if err := w.CheckpointAndReclaim(mark, func(ord uint64) bool { return pins[ord] }); err != nil {
			// The checkpoint could not be made durable, so nothing was
			// reclaimed. The WAL latches the sync failure — subsequent
			// appends fail loudly rather than acknowledging onto a log that
			// cannot checkpoint.
			e.failLocalWAL("checkpoint", err)
			e.logf("writeback: APPLIED checkpoint at %d failed (nothing reclaimed): %v", through, err)
		}
	}
	// Republish the exhaustion mirror the data plane reads: a watermark that
	// reclaimed segments is exactly what lifts a definite ENOSPC.
	e.noteBudgetLocked()
	job := e.job
	e.mu.Unlock()
	if job != nil {
		recs, bytes := e.fl.pendingStats()
		if err := job.updateDebounced(func(j *RecoveryJob) {
			j.AppliedThrough = through
			j.PendingRecords = uint64(recs)
			j.PendingBytes = uint64(bytes)
		}); err != nil {
			e.failLocalWAL("persist recovery progress", err)
		}
	}
}
