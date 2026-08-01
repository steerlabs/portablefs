package writeback

import (
	"context"
	"errors"
	"testing"
	"time"
)

// newTestCredits builds the controller in isolation from the surfaces that use
// it, so the admission algebra is pinned without a live stream, a WAL or an
// authority in the way.
func newTestCredits(t *testing.T, budget int64) *creditController {
	t.Helper()
	e := &Engine{cfg: Config{BudgetBytes: budget}}
	e.fl = newFlusher(e)
	e.credits = newCreditController(e)
	return e.credits
}

// pinCreditTimings compresses the gate's per-call wait cap, the setpoint
// horizon and the flusher's no-progress window so pacing and the stalled-uplink
// verdict are reachable inside a unit test's patience. Production never changes
// any of them.
func pinCreditTimings(t *testing.T, waitCap, drainTarget, noProgress time.Duration) {
	t.Helper()
	oldCap, oldTarget, oldWindow, oldTick := creditWaitCap, creditDrainTarget, noProgressWindow, watchdogInterval
	creditWaitCap, creditDrainTarget, noProgressWindow = waitCap, drainTarget, noProgress
	watchdogInterval = 20 * time.Millisecond
	t.Cleanup(func() {
		creditWaitCap, creditDrainTarget, noProgressWindow, watchdogInterval = oldCap, oldTarget, oldWindow, oldTick
	})
}

// TestCreditFastPathGrantsInFullBelowTheSetpoint pins the 99.9% case: below the
// operating setpoint an acquisition is a full grant with no queue, no wait and
// no bookkeeping beyond one counter. This is the property that makes the gate
// free to sit in front of every write.
func TestCreditFastPathGrantsInFullBelowTheSetpoint(t *testing.T) {
	c := newTestCredits(t, 512<<20)
	ctx := context.Background()
	granted, err := c.acquire(ctx, 1<<20)
	if err != nil || granted != 1<<20 {
		t.Fatalf("fast-path acquire: granted=%d err=%v", granted, err)
	}
	if c.debt.Load() != 1<<20 {
		t.Fatalf("debt %d after a %d-byte grant", c.debt.Load(), 1<<20)
	}
	if c.waiting.Load() != 0 {
		t.Fatalf("the fast path queued %d waiters", c.waiting.Load())
	}
	c.refund(1 << 20)
	if c.debt.Load() != 0 {
		t.Fatalf("debt %d after refunding the whole grant", c.debt.Load())
	}
}

// TestSetpointIsTheHardCapBeforeTheFirstAppliedSample documents the startup
// choice explicitly: with no measurement there is nothing that could justify
// throttling, so the setpoint is the data lane's whole hard cap. Optimistic,
// and still bounded — the exact reservation underneath never moves.
func TestSetpointIsTheHardCapBeforeTheFirstAppliedSample(t *testing.T) {
	const budget = 512 << 20
	c := newTestCredits(t, budget)
	want := int64(budget) - metadataReserveFor(budget)
	if got := c.setpoint.Load(); got != want {
		t.Fatalf("startup setpoint %d, want the data cap %d", got, want)
	}
	if c.ceiling != want {
		t.Fatalf("data ceiling %d, want %d", c.ceiling, want)
	}
}

// TestSetpointTracksTheMeasuredAppliedRate is the control law itself:
// setpoint = clamp(rate * T_drain, B_min, dataCap), adapted from
// authority-applied bytes and nothing else.
func TestSetpointTracksTheMeasuredAppliedRate(t *testing.T) {
	const budget = 512 << 20
	c := newTestCredits(t, budget)
	now := time.Now()

	// A link applying 1 MiB/s: 25s of drain is 25 MiB of resident debt.
	c.lastSample = now
	c.noteApplied(1<<20, 1<<20, now.Add(time.Second))
	got := c.setpoint.Load()
	if want := int64(25 << 20); got < want*9/10 || got > want*11/10 {
		t.Fatalf("setpoint %d for a 1 MiB/s link, want ~%d (rate x T_drain)", got, want)
	}
	if got >= c.ceiling {
		t.Fatalf("a 1 MiB/s link kept the full %d-byte cap open; the setpoint never engaged", c.ceiling)
	}

	// A link an order of magnitude faster saturates the clamp at the hard cap:
	// full burst absorption, zero behaviour change.
	c.noteApplied(512<<20, 512<<20, now.Add(2*time.Second))
	if got := c.setpoint.Load(); got != c.ceiling {
		t.Fatalf("setpoint %d for a fast link, want the full cap %d", got, c.ceiling)
	}

	// Rate collapse mid-flood: no further acks, so the estimator decays and the
	// setpoint walks down to B_min. Nothing is evicted; admission just narrows.
	c.tick()
	c.mu.Lock()
	c.lastSample = time.Now().Add(-60 * creditRateTau)
	c.mu.Unlock()
	c.tick()
	if got := c.setpoint.Load(); got != c.floor {
		t.Fatalf("setpoint %d after the rate collapsed, want the B_min floor %d", got, c.floor)
	}
	if c.floor < maxMutationPayload {
		t.Fatalf("B_min %d cannot admit one maximum-size operation (%d)", c.floor, maxMutationPayload)
	}
}

// TestOperationLargerThanTheDataLaneIsDefiniteENOSPC keeps the one ENOSPC the
// gate still produces exactly where it belongs: an operation that could not fit
// an EMPTY lane can never be paced into fitting, so it is refused immediately
// rather than short-granted or queued.
func TestOperationLargerThanTheDataLaneIsDefiniteENOSPC(t *testing.T) {
	c := newTestCredits(t, 4<<20)
	granted, err := c.acquire(context.Background(), 64<<20)
	if !errors.Is(err, ErrNoSpace) || granted != 0 {
		t.Fatalf("oversized acquire: granted=%d err=%v, want 0/%v", granted, err, ErrNoSpace)
	}
	if c.debt.Load() != 0 {
		t.Fatalf("a refused acquire charged %d bytes", c.debt.Load())
	}
}

// TestCreditQueueIsFIFOFairBetweenLargeAndSmallWaiters is the fairness
// argument under test. A waiter that wants far more than the whole setpoint
// must not absorb every byte a drain frees while a small waiter queued behind
// it starves: credit is handed out one chunk per waiter per pass, in arrival
// order. Both make progress, and the small one finishes long before the large
// one does.
func TestCreditQueueIsFIFOFairBetweenLargeAndSmallWaiters(t *testing.T) {
	pinCreditTimings(t, 10*time.Second, 25*time.Second, 30*time.Second)
	c := newTestCredits(t, 512<<20)
	ctx := context.Background()

	// Saturate: the setpoint is fully spent, so every arrival queues.
	if !c.tryFast(c.setpoint.Load()) {
		t.Fatal("could not spend the setpoint")
	}

	type result struct {
		granted int
		err     error
		at      time.Time
	}
	large := make(chan result, 1)
	small := make(chan result, 1)
	const largeWant = 64 << 20
	const smallWant = 64 << 10

	go func() {
		g, err := c.acquire(ctx, largeWant)
		large <- result{g, err, time.Now()}
	}()
	waitForWaiters(t, c, 1)
	go func() {
		g, err := c.acquire(ctx, smallWant)
		small <- result{g, err, time.Now()}
	}()
	waitForWaiters(t, c, 2)

	// Free credit the way an applied advance would, in modest increments.
	// The large request alone could swallow all of it.
	freed := int64(0)
	deadline := time.After(10 * time.Second)
	var smallRes result
	for smallRes.granted == 0 {
		select {
		case smallRes = <-small:
		case <-deadline:
			t.Fatal("the small waiter never received credit: the large one monopolized every freed byte")
		default:
			c.refund(2 << 20)
			freed += 2 << 20
			if freed > largeWant {
				t.Fatal("freed more than the large request wanted without satisfying the small one")
			}
			time.Sleep(time.Millisecond)
		}
	}
	if smallRes.err != nil || smallRes.granted != smallWant {
		t.Fatalf("small waiter: granted=%d err=%v, want %d", smallRes.granted, smallRes.err, smallWant)
	}
	// The small waiter finished while the large one was still in line — that is
	// the anti-monopoly property. The large one must also have been progressing.
	if c.waiting.Load() != 1 {
		t.Fatalf("%d waiters remain; the large request should still be queued", c.waiting.Load())
	}
	// Drain the rest so the large waiter completes rather than leaking.
	for i := 0; i < 64; i++ {
		c.refund(4 << 20)
		select {
		case res := <-large:
			if res.err != nil || res.granted != largeWant {
				t.Fatalf("large waiter: granted=%d err=%v", res.granted, res.err)
			}
			return
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the large waiter never completed")
}

// TestCreditWaiterWokenByFreezeGetsADefiniteOutcome: a lifecycle event resolves
// queued waiters immediately, refunds every byte they had collected, and never
// leaves one parked behind a close that will never drain.
func TestCreditWaiterWokenByFreezeGetsADefiniteOutcome(t *testing.T) {
	pinCreditTimings(t, 10*time.Second, 25*time.Second, 30*time.Second)
	c := newTestCredits(t, 512<<20)
	if !c.tryFast(c.setpoint.Load()) {
		t.Fatal("could not spend the setpoint")
	}
	spent := c.debt.Load()

	done := make(chan error, 1)
	go func() {
		_, err := c.acquire(context.Background(), 8<<20)
		done <- err
	}()
	waitForWaiters(t, c, 1)
	// Hand the waiter a partial grant so the refund path has something to undo.
	c.refund(2 << 20)
	spent -= 2 << 20

	c.freeze(ErrFenced)
	select {
	case err := <-done:
		if !errors.Is(err, ErrFenced) {
			t.Fatalf("frozen waiter returned %v, want %v", err, ErrFenced)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a freeze did not wake the queued waiter")
	}
	if c.waiting.Load() != 0 {
		t.Fatalf("%d waiters survived the freeze", c.waiting.Load())
	}
	if got := c.debt.Load(); got != spent {
		t.Fatalf("debt %d after the freeze, want %d: the woken waiter leaked its partial grant", got, spent)
	}
	// A freeze is reversible; a thaw reopens admission.
	c.thaw()
	c.refund(c.debt.Load())
	if g, err := c.acquire(context.Background(), 1<<20); err != nil || g != 1<<20 {
		t.Fatalf("acquire after thaw: granted=%d err=%v", g, err)
	}

	// A seal is not reversible.
	c.seal(ErrFenced)
	c.thaw()
	if _, err := c.acquire(context.Background(), 1<<20); !errors.Is(err, ErrFenced) {
		t.Fatalf("acquire after seal+thaw returned %v, want %v", err, ErrFenced)
	}
}

// TestCreditWaiterCancelledByContextRefundsEverything: a cancelled caller
// leaves the ledger exactly as it found it, so a frontend that gives up cannot
// slowly strangle the gate for everyone else.
func TestCreditWaiterCancelledByContextRefundsEverything(t *testing.T) {
	pinCreditTimings(t, 10*time.Second, 25*time.Second, 30*time.Second)
	c := newTestCredits(t, 512<<20)
	if !c.tryFast(c.setpoint.Load()) {
		t.Fatal("could not spend the setpoint")
	}
	before := c.debt.Load()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.acquire(ctx, 8<<20)
		done <- err
	}()
	waitForWaiters(t, c, 1)
	c.refund(2 << 20) // partial grant to the waiter
	before -= 2 << 20
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled waiter returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not wake the queued waiter")
	}
	if got := c.debt.Load(); got != before {
		t.Fatalf("debt %d after cancellation, want %d", got, before)
	}
}

// TestZeroCreditWithAProgressingUplinkIsNotAnError pins the third outcome
// precisely. A link whose acks are simply sparser than one wait cap is NOT
// stalled: the gate reports zero granted with a nil error and leaves the
// decision to the caller, instead of manufacturing an EIO out of slowness.
func TestZeroCreditWithAProgressingUplinkIsNotAnError(t *testing.T) {
	pinCreditTimings(t, 60*time.Millisecond, 25*time.Second, 30*time.Second)
	c := newTestCredits(t, 512<<20)
	if !c.tryFast(c.setpoint.Load()) {
		t.Fatal("could not spend the setpoint")
	}
	// The flusher has no pending work and no failure, so it is not stalled.
	granted, err := c.acquire(context.Background(), 8<<20)
	if granted != 0 || err != nil {
		t.Fatalf("acquire under a slow-but-healthy uplink: granted=%d err=%v, want 0/nil", granted, err)
	}
	if c.debt.Load() != c.setpoint.Load() {
		t.Fatalf("a zero-credit return moved the ledger to %d", c.debt.Load())
	}
}

// TestSetpointBelowResidencyAdmitsNothingAndNeverLivelocks covers the shrink
// case explicitly: when the measured rate collapses, the setpoint can fall
// BELOW what is already resident. Nothing is evicted — the debt is real,
// acknowledged data. Admission simply stops until drain brings residency back
// under the new setpoint, and then resumes.
func TestSetpointBelowResidencyAdmitsNothingAndNeverLivelocks(t *testing.T) {
	pinCreditTimings(t, 100*time.Millisecond, 25*time.Second, 30*time.Second)
	const budget = 512 << 20
	c := newTestCredits(t, budget)
	resident := int64(64 << 20)
	if !c.tryFast(resident) {
		t.Fatal("could not seed residency")
	}

	// Collapse the rate: one tiny sample a long time ago.
	c.mu.Lock()
	c.rate = 1
	c.haveRate = true
	c.lastSample = time.Now()
	c.recomputeSetpointLocked(time.Now())
	c.mu.Unlock()
	if c.setpoint.Load() >= resident {
		t.Fatalf("setpoint %d did not fall below residency %d", c.setpoint.Load(), resident)
	}
	if c.debt.Load() != resident {
		t.Fatalf("shrinking the setpoint evicted debt: %d, want %d", c.debt.Load(), resident)
	}
	if granted, err := c.acquire(context.Background(), 1<<20); granted != 0 || err != nil {
		t.Fatalf("admission above the shrunk setpoint: granted=%d err=%v", granted, err)
	}

	// Drain back under the setpoint: admission resumes with no external kick,
	// so the shrink cannot wedge the gate.
	c.release(resident)
	c.mu.Lock()
	c.pumpLocked()
	c.mu.Unlock()
	granted, err := c.acquire(context.Background(), 64<<10)
	if err != nil || granted != 64<<10 {
		t.Fatalf("admission after draining under the setpoint: granted=%d err=%v", granted, err)
	}
}

// TestMetadataReserveIsCarvedFromTheHardCap pins the lane split arithmetic: the
// data lane's cap is the hard cap minus one segment (scaled down for caps too
// small to give a whole segment away), and the hard cap itself never moves.
func TestMetadataReserveIsCarvedFromTheHardCap(t *testing.T) {
	for _, tc := range []struct {
		budget, reserve int64
	}{
		{512 << 20, 64 << 20},
		{1 << 30, 64 << 20},
		{64 << 20, 16 << 20}, // too small for a whole segment: a quarter
		{4 << 20, 1 << 20},
	} {
		if got := metadataReserveFor(tc.budget); got != tc.reserve {
			t.Fatalf("reserve for %d = %d, want %d", tc.budget, got, tc.reserve)
		}
		e := &Engine{cfg: Config{BudgetBytes: tc.budget}}
		if got := e.dataBudgetBytes(); got != tc.budget-tc.reserve {
			t.Fatalf("data budget for %d = %d, want %d", tc.budget, got, tc.budget-tc.reserve)
		}
		if e.laneBudget(laneMetadata) != tc.budget {
			t.Fatalf("metadata lane budget %d, want the whole cap %d", e.laneBudget(laneMetadata), tc.budget)
		}
	}
}

// TestConcurrentAcquisitionsNeverExceedTheSetpoint is the ledger's own
// invariant, mirroring the WAL reservation invariant one layer down: however
// grants, refunds and applied refills interleave, outstanding credit never
// exceeds the operating setpoint. Run under -race it also covers the CAS loops.
func TestConcurrentAcquisitionsNeverExceedTheSetpoint(t *testing.T) {
	pinCreditTimings(t, 200*time.Millisecond, 25*time.Second, 30*time.Second)
	c := newTestCredits(t, 32<<20)
	ctx := context.Background()
	over := make(chan int64, 1)
	done := make(chan struct{})
	stop := make(chan struct{})

	go func() { // watchdog on the invariant
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if d, s := c.debt.Load(), c.setpoint.Load(); d > s {
				select {
				case over <- d:
				default:
				}
				return
			}
		}
	}()

	work := make(chan struct{})
	for w := 0; w < 8; w++ {
		go func(w int) {
			defer func() { work <- struct{}{} }()
			for i := 0; i < 40; i++ {
				n := int64(64<<10) << (i % 5)
				granted, err := c.acquire(ctx, n)
				if err != nil {
					continue
				}
				c.refund(int64(granted))
			}
		}(w)
	}
	for w := 0; w < 8; w++ {
		<-work
	}
	close(stop)
	<-done
	select {
	case d := <-over:
		t.Fatalf("outstanding credit reached %d, past the setpoint %d", d, c.setpoint.Load())
	default:
	}
	if got := c.debt.Load(); got != 0 {
		t.Fatalf("%d bytes of credit survived every grant being refunded", got)
	}
}

func waitForWaiters(t *testing.T, c *creditController, n int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for c.waiting.Load() != n {
		if time.Now().After(deadline) {
			t.Fatalf("queue holds %d waiters, want %d", c.waiting.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}
