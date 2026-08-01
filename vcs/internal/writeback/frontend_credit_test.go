package writeback

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// exhaustCreditLedger drives the credit ledger to the data lane's ceiling
// without touching the setpoint, so every SUBSEQUENT ungranted acquisition
// queues and — with the uplink gated shut — receives nothing. It leaves the
// WAL untouched: the point of these tests is the admission geometry, not the
// stream.
func exhaustCreditLedger(t *testing.T, e *Engine) {
	t.Helper()
	e.credits.debt.Store(e.credits.ceiling)
}

// sampleCreditWaiters records the high-water mark of the credit queue for as
// long as the returned stop func is uncalled. A frontend-granted write must
// never appear in it: that is the whole promise of pre-acquired credit.
func sampleCreditWaiters(e *Engine) (peak *atomic.Int64, stop func()) {
	peak = &atomic.Int64{}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if w := int64(e.Status().CreditWaiters); w > peak.Load() {
				peak.Store(w)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	return peak, func() { close(done) }
}

// TestFrontendGrantedWriteNeverEntersTheCreditQueue is task 4's invariant: a
// write whose credit was acquired by the frontend BEFORE it took its locks
// must consume that grant and go straight to the WAL. If it queued again it
// would be waiting twice for the same bytes — and the second wait would be the
// one taken under the frontend's namespace lock, which is precisely the
// geometry the frontend placement exists to remove.
//
// The ledger is driven to the data ceiling with the uplink gated shut, so any
// ungranted acquisition would park for a full creditWaitCap. The write
// completing in a small fraction of that, with the queue never non-empty, is
// the proof.
func TestFrontendGrantedWriteNeverEntersTheCreditQueue(t *testing.T) {
	pinCreditTimings(t, 5*time.Second, 25*time.Second, 30*time.Second)
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	chunk := make([]byte, 256<<10)

	// The frontend's acquisition, taken while it holds nothing.
	granted, err := f.e.AcquireDataCredit(ctx, len(chunk))
	if err != nil || granted != len(chunk) {
		t.Fatalf("frontend acquire: granted=%d err=%v", granted, err)
	}
	exhaustCreditLedger(t, f.e)

	opCtx := WithFrontendPacing(WithDataCredit(ctx, granted))
	peak, stop := sampleCreditWaiters(f.e)
	promptly(t, 2*time.Second, "frontend-granted write under an exhausted ledger", func() {
		_, handled, werr := f.e.WriteAt(opCtx, "d/f", 0, chunk)
		if werr != nil || !handled {
			t.Errorf("frontend-granted write: handled=%v err=%v", handled, werr)
		}
	})
	stop()
	if got := peak.Load(); got != 0 {
		t.Fatalf("a frontend-granted write queued for credit (peak waiters %d); it paid for those bytes already", got)
	}
	if left := ReclaimDataCredit(opCtx); left != 0 {
		t.Fatalf("the engine left %d bytes of the frontend grant unconsumed", left)
	}
}

// TestFrontendPacedWriteTakesTheAuthorityLaneInsteadOfQueuing covers the race
// the frontend probe cannot close on its own: the path was uncovered when the
// frontend classified it write-through (and therefore did not charge), and a
// delegation appeared before the engine's own check. The engine must NOT take
// the wait back under the caller's locks. It takes the authority lane.
//
// The contrast half is the same write without the marker: a lock-free caller
// SHOULD pace there, and does, until its context ends.
func TestFrontendPacedWriteTakesTheAuthorityLaneInsteadOfQueuing(t *testing.T) {
	pinCreditTimings(t, 400*time.Millisecond, 25*time.Second, 30*time.Second)
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("fixture did not take a delegation over d/f")
	}
	exhaustCreditLedger(t, f.e)
	chunk := make([]byte, 256<<10)

	peak, stop := sampleCreditWaiters(f.e)
	promptly(t, time.Second, "frontend-paced write whose lane changed", func() {
		_, handled, werr := f.e.WriteAt(WithFrontendPacing(ctx), "d/f", 0, chunk)
		if werr != nil {
			t.Errorf("frontend-paced write errored instead of changing lanes: %v", werr)
		}
		if handled {
			t.Error("frontend-paced write was admitted locally; it must take the authority lane rather than queue under the caller's locks")
		}
	})
	stop()
	if got := peak.Load(); got != 0 {
		t.Fatalf("a frontend-paced write queued for credit (peak waiters %d)", got)
	}

	// Contrast: the identical write with no marker is a lock-free caller and
	// paces, exactly as the engine's own contract says it should.
	wctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	start := time.Now()
	if _, handled, werr := f.e.WriteAt(wctx, "d/f", 0, chunk); werr == nil || !handled {
		t.Fatalf("an unmarked write did not pace: handled=%v err=%v", handled, werr)
	}
	if waited := time.Since(start); waited < 400*time.Millisecond {
		t.Fatalf("an unmarked write returned after %v; it never entered the credit queue at all", waited)
	}
}

// TestFrontendGrantIsSettledExactlyOnce pins the ledger algebra the frontend
// placement depends on. A frontend grant can end in more places than the engine
// can see — the engine's write, clientcore's orphan or exact-handle lanes, or a
// frontend error before any of them — so both sides settle through one counter
// and neither can double-refund.
func TestFrontendGrantIsSettledExactlyOnce(t *testing.T) {
	ctx := WithDataCredit(context.Background(), 100)
	if got := takeDataCredit(ctx, 30); got != 30 {
		t.Fatalf("first take = %d, want 30", got)
	}
	if got := takeDataCredit(ctx, 1000); got != 70 {
		t.Fatalf("an oversized take = %d, want the remaining 70", got)
	}
	if got := takeDataCredit(ctx, 10); got != 0 {
		t.Fatalf("take from an empty grant = %d, want 0", got)
	}
	if got := ReclaimDataCredit(ctx); got != 0 {
		t.Fatalf("reclaim of a fully consumed grant = %d, want 0", got)
	}

	ctx = WithDataCredit(context.Background(), 100)
	if got := takeDataCredit(ctx, 40); got != 40 {
		t.Fatalf("take = %d, want 40", got)
	}
	if got := ReclaimDataCredit(ctx); got != 60 {
		t.Fatalf("frontend reclaim = %d, want the unconsumed 60", got)
	}
	if got := ReclaimDataCredit(ctx); got != 0 {
		t.Fatalf("second reclaim = %d; a deferred reclaim must be idempotent", got)
	}

	// A ctx with no grant is the write-through case: nothing to take, nothing
	// to give back, and no allocation on the hot path.
	bare := context.Background()
	if got := takeDataCredit(bare, 10); got != 0 {
		t.Fatalf("take from an ungranted ctx = %d", got)
	}
	if got := ReclaimDataCredit(bare); got != 0 {
		t.Fatalf("reclaim from an ungranted ctx = %d", got)
	}
}

// TestFrontendGrantIsRefundedWhenTheWriteNeverReachesTheWAL is the error-path
// audit in ledger form. The frontend charges before its locks; the write then
// fails to become WAL bytes (here: the target does not exist locally, so the
// engine changes lanes). Every granted byte must come back, or the ledger
// drifts away from the exact reservation underneath it and the gate starts
// throttling against debt nobody owes.
func TestFrontendGrantIsRefundedWhenTheWriteNeverReachesTheWAL(t *testing.T) {
	pinCreditTimings(t, 400*time.Millisecond, 25*time.Second, 30*time.Second)
	f := newSaturationFixture(t, 8<<20)
	// The lane change below releases the covering delegation, which drains; the
	// uplink has to be open for that. Saturation is not what this test measures.
	f.openUplink()
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	before := f.e.Status().CreditDebt
	chunk := make([]byte, 256<<10)

	granted, err := f.e.AcquireDataCredit(ctx, len(chunk))
	if err != nil || granted != len(chunk) {
		t.Fatalf("frontend acquire: granted=%d err=%v", granted, err)
	}
	if charged := f.e.Status().CreditDebt; charged != before+int64(granted) {
		t.Fatalf("acquire charged %d, want %d", charged-before, granted)
	}

	opCtx := WithFrontendPacing(WithDataCredit(ctx, granted))
	if _, handled, werr := f.e.WriteAt(opCtx, "d/absent", 0, chunk); handled {
		t.Fatalf("write to an unknown path was admitted locally: err=%v", werr)
	}
	if left := ReclaimDataCredit(opCtx); left != 0 {
		t.Fatalf("the engine consumed the grant but left %d bytes on the ctx", left)
	}
	if after := f.e.Status().CreditDebt; after != before {
		t.Fatalf("credit debt %d after a lane change, want the pre-grant %d: the grant leaked", after, before)
	}
}

// TestFrontendGrantSurvivesTheFrontendsOwnErrorPath is the other half: the
// frontend charges and then fails BEFORE it ever calls the engine (a bad
// handle, a detached volume, a request rejected after admission). Nothing on
// the engine side can settle that grant, so the frontend's unconditional
// deferred reclaim has to.
func TestFrontendGrantSurvivesTheFrontendsOwnErrorPath(t *testing.T) {
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()
	before := f.e.Status().CreditDebt

	granted, err := f.e.AcquireDataCredit(ctx, 256<<10)
	if err != nil {
		t.Fatalf("frontend acquire: %v", err)
	}
	opCtx := WithFrontendPacing(WithDataCredit(ctx, granted))
	// ... the frontend fails here and never reaches the engine.
	f.e.ReleaseDataCredit(ReclaimDataCredit(opCtx))
	if after := f.e.Status().CreditDebt; after != before {
		t.Fatalf("credit debt %d after a frontend-side failure, want %d", after, before)
	}
	// The deferred reclaim runs on the success path too and must be inert.
	f.e.ReleaseDataCredit(ReclaimDataCredit(opCtx))
	if after := f.e.Status().CreditDebt; after != before {
		t.Fatalf("a repeated reclaim moved the ledger to %d", after)
	}
}

// TestFrontendPacedWriteNeverWaitsOnHardCapHeadroom is the second no-wait
// promise. The credit ledger counts payload bytes; the WAL counts framed bytes
// and whole segments, so a granted write can still find the exact reservation
// full. A lock-free caller waits for applied progress there — correct for it,
// and wrong for a frontend that is already holding its namespace lock. The
// frontend-paced write changes lanes instead of blocking.
func TestFrontendPacedWriteNeverWaitsOnHardCapHeadroom(t *testing.T) {
	pinCreditTimings(t, 3*time.Second, 25*time.Second, 30*time.Second)
	// 4 MiB of stream budget leaves a 3 MiB data lane, for BOTH the credit
	// ceiling and the WAL's exact data reservation. Three 1 MiB writes therefore
	// fit the ledger to the byte and overrun the reservation by exactly the
	// framing — the shape where a fully granted write still finds no headroom.
	f := newSaturationFixture(t, 4<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	chunk := make([]byte, 1<<20)

	for i := 0; i < 3; i++ {
		granted, err := f.e.AcquireDataCredit(ctx, len(chunk))
		if err != nil {
			t.Fatalf("frontend acquire %d: %v", i, err)
		}
		if granted == 0 {
			t.Skipf("the credit gate bound before the hard cap at write %d", i)
		}
		opCtx := WithFrontendPacing(WithDataCredit(ctx, granted))
		start := time.Now()
		_, handled, werr := f.e.WriteAppend(opCtx, "d/f", chunk[:granted])
		waited := time.Since(start)
		f.e.ReleaseDataCredit(ReclaimDataCredit(opCtx))
		if waited > 2*time.Second {
			t.Fatalf("frontend-paced append %d blocked for %v: it waited on hard-cap headroom, which a caller holding a namespace lock must never do", i, waited)
		}
		if werr != nil && !errors.Is(werr, ErrNoSpace) {
			t.Fatalf("frontend-paced append %d: %v", i, werr)
		}
		if !handled {
			// The hard cap bound and the engine answered with the authority
			// lane instead of waiting. That is the whole contract.
			return
		}
	}
	t.Skip("the hard cap never became the binding constraint at this budget")
}
