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
	flushMaxBytes   = 8 << 20
	flushMaxAge     = 10 * time.Millisecond

	// Retry backoff bounds (full jitter, no attempt limit).
	flushBackoffMin = 50 * time.Millisecond
	flushBackoffMax = 5 * time.Second

	// flushAttemptTimeout bounds ONE network flush attempt, so a blackholed
	// authority costs one bounded attempt on the backoff schedule and a
	// force-close can cancel the in-flight attempt promptly.
	flushAttemptTimeout = 30 * time.Second

	// noProgressWindow is the sticky-degraded watchdog: pending work whose
	// authority watermark has not advanced for this long degrades the mount.
	noProgressWindow = 30 * time.Second

	// watchdogInterval is the health sweep cadence. The watchdog runs on its
	// own goroutine so it fires even while a flush attempt is blocked inside
	// the network call.
	watchdogInterval = time.Second
)

// pendingRec indexes one unshipped mutation: its payload stays in the WAL on
// disk and is re-read at send time, so a large backlog does not live on the
// heap.
type pendingRec struct {
	seq     uint64
	scope   string
	ordinal uint64
	off     int64
	length  int
	digest  [32]byte // chain digest after this record
}

type drainWaiter struct {
	target uint64
	ch     chan error
}

// flusher owns network flush ordering: one goroutine, dense same-scope runs,
// exact watermark reconciliation, sticky health.
type flusher struct {
	e *Engine

	mu            sync.Mutex
	pending       []pendingRec
	pendingBytes  int64
	perScope      map[string]int
	applied       uint64
	appliedDigest [32]byte
	oldestAt      time.Time
	urgent        bool
	waiters       []drainWaiter

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
		}
	}
}

// admit registers appended records. Caller holds e.mu (append order == seq
// order).
func (f *flusher) admit(scope string, results []appendResult) {
	f.mu.Lock()
	for _, r := range results {
		f.pending = append(f.pending, pendingRec{
			seq: r.seq, scope: scope, ordinal: r.ordinal,
			off: r.payloadOff, length: r.payloadLen, digest: r.digest,
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

// drainThrough blocks until the authority watermark covers target, the
// stream parks terminally, or ctx ends.
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
	w := drainWaiter{target: target, ch: make(chan error, 1)}
	f.waiters = append(f.waiters, w)
	f.mu.Unlock()
	f.kick()
	select {
	case err := <-w.ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
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
	scope := f.pending[0].scope
	n := 0
	var bytes int64
	for n < len(f.pending) && n < flushMaxRecords && bytes < flushMaxBytes && f.pending[n].scope == scope {
		bytes += int64(f.pending[n].length)
		n++
	}
	batch := append([]pendingRec(nil), f.pending[:n]...)
	prevDigest := f.appliedDigest
	f.mu.Unlock()

	e := f.e
	e.mu.RLock()
	w := e.wal
	var epoch string
	if d := e.delegations[scope]; d != nil {
		epoch = d.epoch
	}
	e.mu.RUnlock()
	if w == nil || epoch == "" {
		// A record without its live grant cannot exist (drain precedes every
		// release); this is engine-state corruption.
		f.park(fmt.Errorf("%w: pending record for %q has no live delegation", ErrConflict, scope))
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
		WritebackID: e.writebackID, Scope: scope, Epoch: epoch,
		PrevDigest: prevDigest, EndDigest: batch[len(batch)-1].digest,
		Records: records,
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
	case reply.Status == 11: // EAGAIN: lease projection; retry
		f.noteFailure("authority lease re-anchor pending (EAGAIN)")
	default:
		f.park(fmt.Errorf("%w: flush rejected with status %d", ErrConflict, reply.Status))
	}
}

// advance applies an authority watermark: trims pending, wakes drains, and
// records the durable APPLIED checkpoint.
func (f *flusher) advance(through uint64) {
	f.mu.Lock()
	if through > f.applied {
		f.applied = through
		f.lastProgress = time.Now()
	}
	i := 0
	for i < len(f.pending) && f.pending[i].seq <= through {
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
	var ready []drainWaiter
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
// the stream's tail stays durable locally and recovers on the next attach.
// The engine stops admitting under the dead stream's scopes — a local ack
// without a live stream would violate the active-delegation invariant.
func (f *flusher) park(err error) {
	f.mu.Lock()
	f.terminal = err
	f.lastFailure = err.Error()
	f.lastFailAt = time.Now()
	f.degraded = true
	waiters := f.waiters
	f.waiters = nil
	f.notifyHealthLocked(err)
	f.mu.Unlock()
	for _, wtr := range waiters {
		wtr.ch <- err
	}
	f.e.markStreamDead(err)
	if f.e.job != nil {
		f.e.job.update(func(j *RecoveryJob) {
			j.State = JobParked
			j.LastError = err.Error()
		})
		_ = f.e.job.persist()
	}
}

func (e *Engine) markStreamDead(err error) {
	e.mu.Lock()
	if e.streamDead == nil {
		e.streamDead = err
	}
	dead := e.streamDead
	for _, d := range e.delegations {
		if !d.draining {
			continue
		}
		d.drainErr = dead
		closeReleaseSignal(d.done)
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

// notifyHealthLocked reports the sticky verdict without holding the caller's
// callback under f.mu.
func (f *flusher) notifyHealthLocked(err error) {
	cb := f.e.cfg.Events.OnHealth
	if cb == nil {
		return
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
			e.logf("writeback: APPLIED checkpoint at %d failed (nothing reclaimed): %v", through, err)
		}
	}
	job := e.job
	e.mu.Unlock()
	if job != nil {
		recs, bytes := e.fl.pendingStats()
		job.updateDebounced(func(j *RecoveryJob) {
			j.AppliedThrough = through
			j.PendingRecords = uint64(recs)
			j.PendingBytes = uint64(bytes)
		})
	}
}
