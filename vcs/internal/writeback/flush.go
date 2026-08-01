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

// flushMaxBytes is the UPLINK amortization knob: one batch is one request,
// one authority apply turn, and one reply, so everything a batch costs
// besides moving its bytes is paid once per batch. At 8 MiB the measured
// production shape was 1.52s per batch of which ~0.70s was transfer — 44%
// link utilization, i.e. the majority of a batch's wall time was the fixed
// cost, and the flusher ships strictly one batch at a time.
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
//   - THE RESEND CONTRACT. attemptEnd pins a batch by its END SEQUENCE, and a
//     pinned resend replays exactly the records that sequence covers, with no
//     size bound applied — so an exact resend is byte-identical at any batch
//     size. Nothing here changes what a retry sends.
//   - THE CREDIT LEDGER and the metadata/control reserves are all sized in
//     WAL bytes and are independent of how the drained bytes are grouped for
//     transmission.
//
// The cost is transient client memory: one in-flight batch materializes its
// records on the heap plus its encoded frame, so ~64 MiB peak instead of
// ~16 MiB, against a 512 MiB default local budget.
//
// A var so the batch-size measurement can compare two values in one process;
// production never changes it.
var flushMaxBytes int64 = 32 << 20

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
	seq     uint64
	scope   string
	ordinal uint64
	off     int64
	length  int
	// data is the record's BULK payload size (zero for metadata records). The
	// credit ledger is charged in exactly these bytes at admission and refilled
	// in exactly these bytes when the authority applies them, so a grant and
	// its refund are the same quantity and the ledger cannot drift.
	data   int
	digest [32]byte // chain digest after this record
}

type drainWaiter struct {
	target uint64
	ch     chan error
}

// flusher owns network flush ordering: one goroutine, dense global batches
// with explicit scope runs, exact watermark reconciliation, sticky health.
type flusher struct {
	e *Engine

	mu            sync.Mutex
	pending       []pendingRec
	pendingBytes  int64
	perScope      map[string]int
	applied       uint64
	appliedDigest [32]byte
	// attemptEnd pins the exact batch prefix across ambiguous transport
	// failures. New admissions may extend pending while an attempt is in
	// flight, but retries MUST resend byte-for-byte the same digest range
	// until its authority outcome is definite. Otherwise a late smaller
	// request and a newer superset can reach the authority out of order.
	attemptEnd uint64
	oldestAt   time.Time
	urgent     bool
	waiters    []*drainWaiter

	backoff     time.Duration
	nextAttempt time.Time

	degraded     bool
	lastFailure  string
	lastFailAt   time.Time
	lastProgress time.Time
	terminal     error

	wake   chan struct{}
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func newFlusher(e *Engine) *flusher {
	return &flusher{
		e: e, perScope: map[string]int{},
		appliedDigest: digestZero(),
		wake:          make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
	}
}

func (f *flusher) start() {
	f.wg.Add(2)
	go func() { defer f.wg.Done(); f.run() }()
	go func() { defer f.wg.Done(); f.watchdogLoop() }()
}

// stop signals the run loop and waits for ACTUAL termination. The engine
// cancels its lifetime context first, which resolves any in-flight remote
// call promptly, so a late flush can never run against a closed WAL.
func (f *flusher) stop() {
	select {
	case <-f.stopCh:
	default:
		close(f.stopCh)
	}
	f.mu.Lock()
	waiters := f.waiters
	f.waiters = nil
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
// order).
// dataBytes, when non-nil, is parallel to results and carries each record's
// bulk payload size (the data lane); nil means the metadata lane.
func (f *flusher) admit(scope string, results []appendResult, dataBytes []int) {
	f.mu.Lock()
	for i, r := range results {
		bulk := 0
		if i < len(dataBytes) {
			bulk = dataBytes[i]
		}
		f.pending = append(f.pending, pendingRec{
			seq: r.seq, scope: scope, ordinal: r.ordinal,
			off: r.payloadOff, length: r.payloadLen, data: bulk, digest: r.digest,
		})
		f.pendingBytes += int64(r.payloadLen)
		f.perScope[scope]++
	}
	if f.oldestAt.IsZero() && len(f.pending) > 0 {
		f.oldestAt = time.Now()
		f.lastProgress = time.Now()
	}
	f.mu.Unlock()
	f.kick()
}

func (f *flusher) kick() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *flusher) outstanding(scope string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.perScope[scope]
}

// scopeTail reports the highest admitted sequence still unshipped for scope, and
// whether the scope has any unshipped record at all.
//
// It is the drain target a RELEASE of that scope actually needs. Releasing a
// scope means one thing: everything this mount acknowledged locally under that
// grant is durable at the authority, so a peer that acquires it next sees the
// complete state. Nothing about that claim mentions the rest of the stream.
//
// Draining to the STREAM's tail instead made a release head-of-line blocked
// behind every byte any other scope had appended since. With the data lane
// deliberately holding a backlog at its credit setpoint, that turned releasing
// an already-applied metadata scope into a wait for hundreds of megabytes of
// unrelated bulk data — and Engine.admit takes exactly that transition whenever
// a mutation lands outside the current grant, which is what walking into a fresh
// directory does. Measured live: a cold-scope mkdir blocked 26.6s on a mount
// whose own metadata was long since applied.
//
// The stream is dense and ordered, so waiting for THIS scope's last record still
// implies waiting for everything appended before it. That is inherent and
// correct — those bytes precede the scope's own state at the authority. What is
// excluded is everything appended AFTER, which the scope's release cannot
// depend on: admission for a draining delegation is already closed, so no new
// record can join the scope behind this snapshot.
func (f *flusher) scopeTail(scope string) (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.perScope[scope] == 0 {
		return 0, false
	}
	for i := len(f.pending) - 1; i >= 0; i-- {
		if f.pending[i].scope == scope {
			return f.pending[i].seq, true
		}
	}
	return 0, false
}

func (f *flusher) pendingStats() (int, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending), f.pendingBytes
}

func (f *flusher) appliedThrough() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied
}

// drainThrough blocks until the authority watermark covers target, the stream
// parks terminally, the WATCHDOG declares the uplink stalled, or ctx ends.
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
// It cannot fire on a healthy-but-slow link: the window is measured from the
// last watermark ADVANCE, so any progress at all rearms it.
func (f *flusher) drainThrough(ctx context.Context, target uint64) error {
	f.mu.Lock()
	if f.applied >= target {
		f.mu.Unlock()
		return nil
	}
	if f.terminal != nil {
		err := f.terminal
		f.mu.Unlock()
		return err
	}
	f.urgent = true
	// A barrier tries NOW: the backoff schedule protects steady state, not
	// an explicit durability request after a transient failure.
	f.nextAttempt = time.Time{}
	w := &drainWaiter{target: target, ch: make(chan error, 1)}
	f.waiters = append(f.waiters, w)
	verdict := f.stallVerdictLocked(time.Now())
	f.mu.Unlock()
	f.kick()
	drop := func() {
		f.mu.Lock()
		for i, waiter := range f.waiters {
			if waiter == w {
				f.waiters = append(f.waiters[:i], f.waiters[i+1:]...)
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
			if v := f.stallVerdict(); v.Stalled {
				drop()
				return ErrUplinkStalled
			} else {
				timer.Reset(stallRecheckDelay(v))
			}
		}
	}
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

func (f *flusher) run() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-f.stopCh:
			return
		default:
		}
		f.mu.Lock()
		wait := f.nextWaitLocked()
		f.mu.Unlock()
		if wait == 0 {
			f.sendBatch()
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
		case <-f.wake:
		case <-timer.C:
		}
	}
}

// nextWaitLocked reports how long to wait before the next dispatch attempt
// (0 = dispatch now).
func (f *flusher) nextWaitLocked() time.Duration {
	if len(f.pending) == 0 || f.terminal != nil {
		return time.Hour
	}
	if until := time.Until(f.nextAttempt); until > 0 {
		return until
	}
	if f.urgent || len(f.pending) >= flushMaxRecords || f.pendingBytes >= flushMaxBytes {
		return 0
	}
	if age := time.Since(f.oldestAt); age >= flushMaxAge {
		return 0
	}
	return flushMaxAge - time.Since(f.oldestAt)
}

// sendBatch builds and ships the next dense same-scope run.
func (f *flusher) sendBatch() {
	f.mu.Lock()
	if len(f.pending) == 0 || f.terminal != nil {
		f.urgent = len(f.pending) != 0 && f.urgent
		f.mu.Unlock()
		return
	}
	n := 0
	if f.attemptEnd != 0 {
		for n < len(f.pending) && f.pending[n].seq <= f.attemptEnd {
			n++
		}
		if n == 0 || f.pending[n-1].seq != f.attemptEnd {
			err := fmt.Errorf("%w: pinned flush batch ending at %d is absent from pending stream", ErrConflict, f.attemptEnd)
			f.mu.Unlock()
			f.park(err)
			return
		}
	} else {
		var bytes int64
		for n < len(f.pending) && n < flushMaxRecords && bytes < flushMaxBytes {
			bytes += int64(f.pending[n].length)
			n++
		}
		f.attemptEnd = f.pending[n-1].seq
	}
	batch := append([]pendingRec(nil), f.pending[:n]...)
	prevDigest := f.appliedDigest
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
			scopeRuns[len(scopeRuns)-1].Through = p.seq
		} else {
			scopeRuns = append(scopeRuns, FlushScope{Scope: p.scope, Epoch: epoch, Through: p.seq})
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
		rec.Seq = p.seq
		records = append(records, rec)
	}
	ctx, cancel := context.WithTimeout(e.ctx, flushAttemptTimeout)
	reply, err := e.remote.Flush(ctx, FlushRequest{
		WritebackID: e.writebackID,
		PrevDigest:  prevDigest, EndDigest: batch[len(batch)-1].digest,
		Records: records, ScopeRuns: scopeRuns,
	})
	cancel()
	if err != nil {
		f.noteFailure(err.Error())
		return
	}
	switch {
	case reply.Status == 0:
		// The durable watermark is EXACTLY reply.Through, never past it. A
		// A success must name this batch's exact end. A short watermark would
		// drop unshipped records; a watermark past the sent end claims bytes
		// this request never supplied. Either is a protocol-integrity failure.
		if batchEnd := batch[len(batch)-1].seq; reply.Through != batchEnd {
			f.park(fmt.Errorf("%w: flush succeeded with authority watermark %d, want exact batch end %d", ErrConflict, reply.Through, batchEnd))
			return
		}
		f.advance(reply.Through)
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
	case reply.Status == 11: // EAGAIN: the authority's typed retryable answer
		f.noteFailure("authority cannot apply this batch yet (EAGAIN)")
	default:
		f.noteFailure(fmt.Sprintf(
			"authority rejected the flush with unclassified status %d; retrying",
			reply.Status,
		))
	}
}

// advance applies an authority watermark: trims pending, wakes drains, and
// records the durable APPLIED checkpoint.
func (f *flusher) advance(through uint64) {
	f.mu.Lock()
	if f.attemptEnd != 0 && through >= f.attemptEnd {
		f.attemptEnd = 0
	}
	if through > f.applied {
		f.applied = through
		f.lastProgress = time.Now()
	}
	i := 0
	var appliedData, appliedTotal int64
	for i < len(f.pending) && f.pending[i].seq <= through {
		appliedData += int64(f.pending[i].data)
		appliedTotal += int64(f.pending[i].length)
		f.pendingBytes -= int64(f.pending[i].length)
		f.perScope[f.pending[i].scope]--
		if f.perScope[f.pending[i].scope] == 0 {
			delete(f.perScope, f.pending[i].scope)
		}
		f.appliedDigest = f.pending[i].digest
		i++
	}
	f.pending = f.pending[i:]
	if len(f.pending) == 0 {
		f.oldestAt = time.Time{}
		f.urgent = false
		if f.degraded {
			// Every admission from before the failure is applied: clear the
			// sticky verdict (lastFailure stays visible for diagnosis).
			f.degraded = false
			f.notifyHealthLocked(nil)
		}
	} else {
		f.oldestAt = time.Now()
	}
	f.backoff = 0
	f.nextAttempt = time.Time{}
	var ready []*drainWaiter
	kept := f.waiters[:0]
	for _, wtr := range f.waiters {
		if wtr.target <= f.applied {
			ready = append(ready, wtr)
		} else {
			kept = append(kept, wtr)
		}
	}
	f.waiters = kept
	// Capture the (watermark, digest) pair atomically: a racing later
	// advance must not pair this watermark with a newer digest in the
	// APPLIED checkpoint.
	appliedNow, digestNow := f.applied, f.appliedDigest
	f.mu.Unlock()
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
	f.e.noteApplied(appliedNow, digestNow)
}

// appliedState reads the (watermark, digest-at-watermark) pair atomically.
func (f *flusher) appliedState() (uint64, [32]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied, f.appliedDigest
}

// noteFailure schedules the jittered retry and feeds the watchdog.
func (f *flusher) noteFailure(msg string) {
	f.mu.Lock()
	f.lastFailure = msg
	f.lastFailAt = time.Now()
	if f.backoff == 0 {
		f.backoff = flushBackoffMin
	} else {
		f.backoff = min(f.backoff*2, flushBackoffMax)
	}
	delay := time.Duration(rand.Int63n(int64(f.backoff) + 1))
	f.nextAttempt = time.Now().Add(delay)
	f.mu.Unlock()
}

// park permanently stops flushing (definite fence, conflict, corruption):
// the stream's written tail stays available for an explicit local sync and
// exact attach-time recovery. The engine seals all mutation admission — a
// local ack without a live stream would violate the active-delegation
// invariant, and another lane must not order around it.
func (f *flusher) park(err error) {
	f.mu.Lock()
	f.terminal = err
	f.lastFailure = err.Error()
	f.lastFailAt = time.Now()
	f.degraded = true
	waiters := f.waiters
	f.waiters = nil
	f.mu.Unlock()
	for _, wtr := range waiters {
		wtr.ch <- err
	}
	f.e.credits.seal(err)
	f.e.markStreamDead(err)
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

// watchdog flips sticky degraded when pending work makes no watermark
// progress for the window.
func (f *flusher) watchdog() {
	f.mu.Lock()
	if len(f.pending) > 0 && !f.degraded && !f.lastProgress.IsZero() &&
		time.Since(f.lastProgress) >= noProgressWindow {
		f.degraded = true
		recs, bytes := len(f.pending), f.pendingBytes
		f.notifyHealthLocked(fmt.Errorf(
			"writeback: flush stalled: %d records (%d bytes) pending with no watermark progress since %s (last failure: %s)",
			recs, bytes, f.lastProgress.Format(time.RFC3339), f.lastFailure))
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
	return f.stallVerdictLocked(time.Now())
}

func (f *flusher) stallVerdictLocked(now time.Time) StallVerdict {
	if f.terminal != nil {
		// A parked stream is stalled with or without pending work: nothing it
		// holds can ever be applied, and nothing will ever advance again.
		return StallVerdict{Stalled: true}
	}
	if len(f.pending) == 0 {
		return StallVerdict{}
	}
	v := StallVerdict{Pending: true}
	switch {
	case f.degraded:
		// The health sweep already latched the sticky verdict.
		v.Stalled = true
	case f.lastProgress.IsZero():
		// Pending work whose progress clock never started. Nothing has been
		// observed to stall yet, and a whole window would have to elapse first.
		v.Remaining = noProgressWindow
	default:
		// The same recomputation the sweep does, deliberately live rather than
		// waiting for the sweep tick, so a paced caller's outcome does not
		// depend on watchdog phase.
		if since := now.Sub(f.lastProgress); since >= noProgressWindow {
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
	st := Status{
		PendingRecords: len(f.pending),
		PendingBytes:   f.pendingBytes,
		AppliedThrough: f.applied,
		Degraded:       f.degraded,
		LastFailure:    f.lastFailure,
	}
	if !f.oldestAt.IsZero() {
		st.OldestPendingMs = time.Since(f.oldestAt).Milliseconds()
	}
	if !f.lastProgress.IsZero() {
		st.LastProgressMs = time.Since(f.lastProgress).Milliseconds()
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
func (e *Engine) noteApplied(through uint64, digest [32]byte) {
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
		if err := w.CheckpointAndReclaim(through, digest, func(ord uint64) bool { return pins[ord] }); err != nil {
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
