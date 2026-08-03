package workfs

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/metrics"
)

// RESIDENT-BYTE PACING: admission that costs what it actually consumes.
//
// ── THE CONSERVATION LAW ────────────────────────────────────────────────────
//
// Resident dirty bytes obey one equation and no amount of threshold tuning
// changes it:
//
//	d(resident)/dt = accept_rate - release_rate
//
// The live gate measured accept 7.00 MiB/s against release 1.06 MiB/s: net
// growth 5.94 MiB/s, forever. Every knob that has been reached for so far —
// the backlog trigger percentage, the coordinated dirty bound, the cut
// cadence — moves only WHEN the cliff arrives, never WHETHER. A bounded-RAM
// authority can survive an unbounded OFFERED write rate; it cannot promise an
// unbounded ACCEPTED one. So admission has to be paced against the rate at
// which resident bytes are actually RELEASED, and nothing else.
//
// ── WHY A LEVEL, NOT A RATE ESTIMATOR ───────────────────────────────────────
//
// The obvious shape is a token bucket refilled at the measured release rate.
// It is the wrong shape: a rate estimator has to pick a window, it lags every
// step change (a cut lands and releases a gigabyte in one instant), and its
// error accumulates into exactly the drift it exists to prevent.
//
// The level does the same job exactly and needs no estimate. Admission of a
// write runs FREE while resident bytes are below a setpoint S, and WAITS at
// or above it. Above S, therefore, every admitted byte is preceded by a
// released byte — the accepted rate IS the release rate, by construction,
// whatever that rate happens to be at that instant. Below S the writer is
// unthrottled and residency is free to rise. The steady state is residency
// hovering at S with the writer paced to whatever the fold delivers: a
// saw-tooth, not a climb.
//
// The setpoint is deliberately BELOW the hard bound (VCS_DIRTY_RSS_MAX_MB).
// The gap between them is not slack, it is RESERVED CAPACITY, and it has
// named occupants: rows already admitted and still waiting for their ordered
// apply turn (dirtyReserved), cold replay, delegation recalls, and every
// metadata/control/lease row that must stay admissible while a writer is
// being held. dirtyMax stays exactly what it was — an emergency invariant
// answered with a definite ENOSPC — and pacing exists so a healthy volume
// never reaches it.
//
// ── WHAT COUNTS AS A RELEASE ────────────────────────────────────────────────
//
// Only an actual fall in resident bytes: a fold that rebound blocks to the
// adopted base, a truncate, an orphan reap, a transaction rollback. NOT a cut
// becoming ready, NOT an adoption landing, NOT a fold pass reporting success
// — those are upstream events that may or may not have moved any memory, and
// crediting them is how a pacer quietly reintroduces the drift it was built
// to remove. The credit signal is taken at the one place the exact total
// moves (addDirtyBlockBytesLocked / restoreDirtyBlockBytesLocked), so it
// cannot disagree with the number the bound is checked against.
//
// ── LOCK ORDER ──────────────────────────────────────────────────────────────
//
// The wait happens BEFORE fs.mu, before any per-inode lock, before the exact
// op slot and before LSN reservation — in the same pre-lock region that
// already performs lazy-base hydration. This is not a preference. The dirty
// reservation itself is taken atomically under fs.mu together with the LSN
// reservation (reserveDirtyGrowthLocked); blocking THERE would convert memory
// pressure into lock and delegation deadlock — a writer asleep under fs.mu
// stops the fold that is the only thing that could wake it.
//
// The pacer therefore shares no mutex with fs.mu. The level it compares
// against is PUBLISHED into an atomic under fs.mu, and wakeups travel on a
// broadcast channel; a waiter never holds a pacer lock while needing fs.mu,
// and the publisher never blocks.
//
// ── PACING IS NOT HANGING ───────────────────────────────────────────────────
//
// A paced write is slow on purpose, and it is bounded: one operation waits at
// most dirtyPaceMaxWait before it gets the definite ENOSPC this package
// already contracts for. That single bound is a client-latency decision and
// nothing more — see its comment for why a second "nothing has been released
// lately" trigger is actively wrong here. Sealing the admission gate releases
// every waiter immediately, so a quiesce is never held behind memory
// pressure.
//
// ── WHAT PACING DOES NOT DO, AND THE TIER THAT WOULD ────────────────────────
//
// Pacing makes the promise HONEST; it does not make the promise BIGGER. A
// volume whose release rate is 1 MiB/s now sustains 1 MiB/s of accepted
// writes instead of accepting 7 MiB/s for five minutes and then failing every
// write. Raising the accepted rate is a separate problem, and the reason it
// is hard is one conflation in the current architecture:
//
//	A PUBLISHABLE, GC-ROOTED, IMMUTABLE RECOVERY SNAPSHOT IS THE ONLY BACKING
//	STORE FROM WHICH LIVE AUTHORITY RAM MAY BE EVICTED.
//
// Two separable facts sit behind that sentence:
//
//	(a) these bytes have a safe replacement, so the RAM can be freed;
//	(b) this complete filesystem revision is publishable and can replace the
//	    recovery base.
//
// Eviction needs PROVENANCE (cheap: blockSeq/truncSeq already carry it, and
// FoldToBase's proof is exactly this) plus a READABLE REPLACEMENT SOURCE.
// Today only (b) supplies the replacement, so eviction waits on a full cut
// materialising, publishing, and being adopted. The durable journal proves
// provenance but is NOT a backing store: PFJ3 records are mutation INTENTS
// including partial writes, so serving an arbitrary evicted block out of them
// is replay, not a read.
//
// THE NEXT TIER (design; to be built separately, not bolted on here) is an
// EPHEMERAL LOCAL FILE-BACKED SPILL that supplies (a) without (b):
//
//   - After a block's journal transaction is durable, a STABLE FULL resident
//     block may be written to a local spill file and its RAM buffer replaced
//     by a sparse file-backed content.Source under the SAME commit-phase
//     recheck FoldToBase already performs (blockSeq/truncSeq re-read under
//     fs.mu after the I/O, outside it).
//   - The spill index records (inode, block, version/LSN, size epoch, offset,
//     hash). A later write to that block SUPERSEDES its spill entry exactly
//     as it supersedes fold eligibility — one buffer, one provenance, never a
//     block whose bytes come from two generations.
//   - It need NOT survive process death and is NOT a new persisted format:
//     the journal remains durable truth, so on spill loss the correct action
//     is to terminate the child and cold-replay. That is what keeps this out
//     of the recovery-format surface entirely.
//   - COLD REPLAY MUST USE THE SAME TIER. A large replay reconstructs the
//     whole dirty suffix in RAM and recreates the exact problem the tier
//     exists to solve.
//
// INVARIANT THE TIER MUST SATISFY: for every block, the bytes a read returns
// are unchanged by whether that block is resident, spilled, or folded — and
// at most one of the three is authoritative at any instant, chosen under
// fs.mu by the same provenance stamps. Spilling is a memory decision only; it
// must be invisible to content, to identity, and to the journal.
//
// A partial cut must NEVER be advertised as a recovery base: namespace, size,
// control state and root identity need an atomic boundary. Incremental RELIEF
// is publishable; incremental READINESS is not.
//
// With the tier in place the pacer does not change shape at all — the spill
// simply becomes another thing that makes resident bytes fall, which is the
// only event this file has ever credited.

var (
	dirtyPaceSetpointGauge  = metrics.Default.Gauge("vcs_dirty_pace_setpoint_bytes")
	dirtyPaceWaitsTotal     = metrics.Default.Counter("vcs_dirty_pace_waits")
	dirtyPaceWaitNanosTotal = metrics.Default.Counter("vcs_dirty_pace_wait_nanos")
	dirtyPaceRefusalsTotal  = metrics.Default.Counter("vcs_dirty_pace_refusals")
	dirtyReleasedBytesTotal = metrics.Default.Counter("vcs_dirty_released_bytes")
	dirtyReleaseRateGauge   = metrics.Default.Gauge("vcs_dirty_release_bytes_per_sec")
)

const (
	// defaultDirtyPacePercent puts the setpoint at half the dirty bound. That
	// is not a fresh guess: coordinatedBacklogPercent already sizes the cut
	// trigger against half this bound on both sides, and the fold driver
	// already switches to its fast cadence at the same fraction. Pacing
	// therefore engages exactly when the fold is running as hard as it can,
	// and the remaining half is the reserved capacity described above.
	defaultDirtyPacePercent = 50

	// dirtyPaceMaxWait bounds ONE operation's total wait, and it is the ONLY
	// refusal trigger. It is a CLIENT-LATENCY decision — how long a write may
	// block before ENOSPC is kinder than continuing to wait — deliberately
	// not a judgement about the relief plane.
	//
	// An earlier revision also refused after a fixed window with no release
	// observed ("this is not pacing, it is stuck"). That window reasoned
	// about the wrong period. Relief is BURSTY: the fold releases only on cut
	// adoption, so between cuts there is legitimately no release at all for
	// as long as a cut takes — minutes at the rates the live gate measured.
	// Any fixed no-release window shorter than the cut period therefore fires
	// in the NORMAL inter-cut gap and refuses a perfectly healthy volume.
	//
	// Worse, the period is load-coupled in the wrong direction. A sustained
	// writer saturates Postgres WAL, which slows every writer sharing it —
	// including cut materialization, adoption and reclamation, i.e. the
	// machinery that RELIEVES this memory. So the gap between releases widens
	// exactly when writers are queued on it, and a stall detector tuned at
	// idle would fire hardest under load. One bound on one operation's wait
	// has no such coupling: it says nothing about why relief is late.
	dirtyPaceMaxWait = 30 * time.Second
)

// dirtyPacer holds write admission to the rate at which resident dirty bytes
// are actually released. It shares no lock with fs.mu: the level is published
// into an atomic from under fs.mu, and waiters are woken by closing a
// broadcast channel.
type dirtyPacer struct {
	// setpoint is the resident level at or above which a write waits
	// (0 = pacing disabled).
	setpoint atomic.Int64
	// level mirrors fs.dirtyBytes+fs.dirtyReserved, published under fs.mu.
	level atomic.Int64
	// releasedTotal is the monotone count of bytes actually released; a
	// waiter watches it to tell "paced" from "stuck".
	releasedTotal atomic.Int64

	// maxWait is the refusal bound (a field so tests can compress it;
	// production uses the constant above).
	maxWait atomic.Int64 // nanoseconds

	mu     sync.Mutex
	wake   chan struct{} // closed and replaced on every release
	closed bool          // admission sealed: every waiter is released at once

	// release-rate estimate, for operators and for sizing — never for the
	// admission decision itself.
	rateMu     sync.Mutex
	rateAt     time.Time
	rateAnchor int64
	rate       float64
}

func newDirtyPacer() *dirtyPacer {
	p := &dirtyPacer{wake: make(chan struct{})}
	p.maxWait.Store(int64(dirtyPaceMaxWait))
	return p
}

// configure sets the setpoint from the hard bound and a percentage. A
// non-positive bound, or a percentage outside 1..99, disables pacing: the
// hard bound alone then behaves exactly as it did before.
func (p *dirtyPacer) configure(maxBytes int64, percent int) {
	if p == nil {
		return
	}
	if maxBytes <= 0 || percent < 1 || percent > 99 {
		p.setpoint.Store(0)
		dirtyPaceSetpointGauge.Set(0)
		p.wakeAll()
		return
	}
	// Multiply first: dividing first rounds the setpoint DOWN by up to 99
	// bytes per hundred, which is invisible at gigabyte scale and, at the
	// block granularity tests work in, silently puts the setpoint just under
	// a whole number of blocks. The guard keeps the product in range for
	// absurdly large bounds rather than trusting it not to overflow.
	setpoint := maxBytes / 100 * int64(percent)
	if maxBytes <= (1<<62)/100 {
		setpoint = maxBytes * int64(percent) / 100
	}
	if setpoint < 1 {
		setpoint = 1
	}
	p.setpoint.Store(setpoint)
	dirtyPaceSetpointGauge.Set(setpoint)
	p.wakeAll()
}

// publish records the new resident level and separately credits the bytes
// that were genuinely RELEASED. The two are not the same number and must not
// be conflated: the level also falls when an over-reservation is returned
// after a row applies (the worst-case charge minus the actual growth), which
// frees admission room but frees no memory. Counting that as a release would
// inflate the release-rate estimate operators size this volume against with
// the writer's own bookkeeping.
//
// Called under fs.mu; it must never block.
func (p *dirtyPacer) publish(level, released int64) {
	if p == nil {
		return
	}
	prev := p.level.Swap(level)
	if released > 0 {
		p.releasedTotal.Add(released)
		dirtyReleasedBytesTotal.Add(released)
	}
	// Any FALL in the level may have opened room for a waiter, whether or not
	// it freed memory.
	if level < prev || released > 0 {
		p.wakeAll()
	}
}

// wakeAll releases every waiter by closing the current broadcast channel and
// installing a fresh one.
func (p *dirtyPacer) wakeAll() {
	p.mu.Lock()
	ch := p.wake
	p.wake = make(chan struct{})
	p.mu.Unlock()
	close(ch)
}

// notify returns the channel closed by the next release.
func (p *dirtyPacer) notify() (<-chan struct{}, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wake, p.closed
}

// stop releases every waiter permanently (admission sealed).
func (p *dirtyPacer) stop() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	ch := p.wake
	p.wake = make(chan struct{})
	p.mu.Unlock()
	close(ch)
}

// await holds one write admission until the resident level leaves room for
// its worst-case growth, or refuses. It BLOCKS, and it must be called with no
// fs lock held.
//
// The three outcomes are distinct on purpose:
//
//	nil                     admitted (immediately, or after being paced)
//	ErrDirtyRSSCapacity     nothing is being released, or the wait ceiling
//	                        was reached: the definite refusal this package
//	                        already contracts for
//	ErrSealed               admission closed underneath the waiter
func (p *dirtyPacer) await(need int64) (time.Duration, error) {
	if p == nil {
		return 0, nil // pacing not configured: the hard bound alone decides
	}
	setpoint := p.setpoint.Load()
	if setpoint <= 0 || need <= 0 {
		return 0, nil
	}
	if need >= setpoint {
		// One row whose worst-case growth alone reaches the setpoint could
		// never be admitted by pacing however much is released, so pacing it
		// would turn a legitimately large write into a guaranteed timeout.
		// It goes straight to the hard bound, which is the correct authority
		// for "this single operation does not fit".
		return 0, nil
	}
	if p.level.Load()+need <= setpoint {
		return 0, nil // the common case: room, no wait, no bookkeeping
	}

	start := time.Now()
	maxWait := time.Duration(p.maxWait.Load())
	waited := false

	for {
		// Take the wakeup channel BEFORE re-reading the level: a release
		// landing between the two closes this channel, so the wait below
		// returns immediately instead of sleeping through it.
		wake, closed := p.notify()
		if closed {
			return time.Since(start), ErrSealed
		}
		if p.level.Load()+need <= setpoint {
			elapsed := time.Since(start)
			if waited {
				dirtyPaceWaitsTotal.Inc()
				dirtyPaceWaitNanosTotal.Add(elapsed.Nanoseconds())
			}
			return elapsed, nil
		}
		now := time.Now()
		if now.Sub(start) >= maxWait {
			dirtyPaceRefusalsTotal.Inc()
			return now.Sub(start), ErrDirtyRSSCapacity
		}
		waited = true

		// Wake on the next release, or re-evaluate at the deadline. The floor
		// keeps a nearly-expired bound from spinning.
		until := maxWait - now.Sub(start)
		if until < time.Millisecond {
			until = time.Millisecond
		}
		timer := time.NewTimer(until)
		select {
		case <-wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// observeRate refreshes the released-bytes-per-second estimate. It informs
// operators and sizing; the admission decision never reads it.
func (p *dirtyPacer) observeRate(now time.Time) float64 {
	p.rateMu.Lock()
	defer p.rateMu.Unlock()
	released := p.releasedTotal.Load()
	if p.rateAt.IsZero() {
		p.rateAt, p.rateAnchor = now, released
		return 0
	}
	elapsed := now.Sub(p.rateAt).Seconds()
	if elapsed < 1 {
		return p.rate
	}
	sample := float64(released-p.rateAnchor) / elapsed
	// A gentle EWMA: the sample is already an average over the interval, and
	// this only smooths the step a single large fold produces.
	if p.rate == 0 {
		p.rate = sample
	} else {
		p.rate = 0.7*p.rate + 0.3*sample
	}
	p.rateAt, p.rateAnchor = now, released
	dirtyReleaseRateGauge.Set(int64(p.rate))
	return p.rate
}

// ─── FS surface ─────────────────────────────────────────────────────────────

// SetDirtyPacePercent sets the pacing setpoint as a percentage of the dirty
// bound (0, or anything outside 1..99, disables pacing and leaves the hard
// bound behaving exactly as it did before). Order-independent with
// SetDirtyRSSMax: each records its half and re-derives the setpoint.
func (fs *FS) SetDirtyPacePercent(percent int) {
	fs.mu.Lock()
	fs.dirtyPacePercent = percent
	max := fs.dirtyMax
	fs.mu.Unlock()
	fs.pace.configure(max, percent)
}

// DirtyPaceSetpoint reports the resident level at or above which writes are
// paced (0 = pacing disabled).
func (fs *FS) DirtyPaceSetpoint() int64 {
	if fs.pace == nil {
		return 0
	}
	return fs.pace.setpoint.Load()
}

// DirtyReleasedBytes reports the monotone total of resident dirty bytes this
// generation has actually released (fold, truncate, reap, rollback).
func (fs *FS) DirtyReleasedBytes() int64 {
	if fs.pace == nil {
		return 0
	}
	return fs.pace.releasedTotal.Load()
}

// DirtyReleaseRate samples the released-bytes-per-second estimate. It is the
// number the whole design turns on: sustained accepted write throughput
// cannot exceed it, and an operator sizing a volume is choosing between
// raising it and accepting the pace.
func (fs *FS) DirtyReleaseRate() float64 {
	if fs.pace == nil {
		return 0
	}
	return fs.pace.observeRate(time.Now())
}

// paceDirtyGrowth is the pre-lock admission wait. need is the same worst-case
// growth the reservation under fs.mu will charge; a row that allocates no
// dirty blocks (control-only, metadata, truncate, reap) passes straight
// through, which is what keeps relief and liveness admissible while a writer
// is being held.
func (fs *FS) paceDirtyGrowth(need int64) error {
	if need <= 0 {
		return nil
	}
	_, err := fs.pace.await(need)
	return err
}

// publishDirtyLevelLocked republishes the resident level to the pacer.
// released is the bytes this change actually freed — a fall in dirtyBytes and
// nothing else. Caller holds fs.mu.
func (fs *FS) publishDirtyLevelLocked(released int64) {
	if released < 0 {
		released = 0
	}
	fs.pace.publish(fs.dirtyBytes+fs.dirtyReserved, released)
}
