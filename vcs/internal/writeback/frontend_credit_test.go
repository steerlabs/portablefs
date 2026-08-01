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

	opCtx := WithResolvedLane(WithDataCredit(ctx, granted), LaneDelegated)
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

// TestAuthorityResolvedWriteIsNeverChargedAndNeverQueues is the authority
// lane's half of the classifier contract.
//
// A write the classifier resolved as authority-only — an orphaned inode, a hard
// link, a pathless handle, or simply an uncovered path — produces no stream
// bytes at all. It must therefore be neither charged nor queued, WHATEVER the
// delegation state has become since, and whatever the credit ledger looks like.
// Both halves matter and they fail differently:
//
//   - queuing would take the wait back under the caller's locks, which is the
//     namespace-wide stall the pre-lock classifier exists to remove;
//   - charging would put a debt on the ledger for bytes that can never become
//     WAL bytes, throttling honest delegated writers against a phantom.
//
// The second is why the lane is consulted BEFORE the credit fast path: with a
// free ledger the fast path is one successful CAS and would charge silently.
// This test covers a delegation that appeared after classification (the ledger
// exhausted, so a charge would be visible as a queue) and then the same write
// against a free ledger (where a charge would be visible as debt).
//
// The contrast half is the same write with no classifier: a lock-free caller
// SHOULD pace there, and does, until its context ends.
func TestAuthorityResolvedWriteIsNeverChargedAndNeverQueues(t *testing.T) {
	pinCreditTimings(t, 400*time.Millisecond, 25*time.Second, 30*time.Second)
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("fixture did not take a delegation over d/f")
	}
	authority := WithResolvedLane(ctx, LaneAuthority)
	chunk := make([]byte, 256<<10)

	// A free ledger: a charge would show up as debt.
	before := f.e.Status().CreditDebt
	if _, handled, werr := f.e.WriteAt(authority, "d/f", 0, chunk); werr != nil || handled {
		t.Fatalf("authority-resolved write: handled=%v err=%v, want the authority lane", handled, werr)
	}
	if after := f.e.Status().CreditDebt; after != before {
		t.Fatalf("an authority-resolved write charged %d bytes it can never turn into WAL bytes", after-before)
	}

	// An exhausted ledger: a charge would show up as a queued waiter.
	exhaustCreditLedger(t, f.e)
	peak, stop := sampleCreditWaiters(f.e)
	promptly(t, time.Second, "authority-resolved write under an exhausted ledger", func() {
		_, handled, werr := f.e.WriteAt(authority, "d/f", 0, chunk)
		if werr != nil {
			t.Errorf("authority-resolved write errored: %v", werr)
		}
		if handled {
			t.Error("authority-resolved write was admitted locally")
		}
	})
	stop()
	if got := peak.Load(); got != 0 {
		t.Fatalf("an authority-resolved write queued for credit (peak waiters %d)", got)
	}

	// Contrast: the identical write with no classifier is a lock-free caller
	// and paces, exactly as the engine's own contract says it should.
	wctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	start := time.Now()
	if _, handled, werr := f.e.WriteAt(wctx, "d/f", 0, chunk); werr == nil || !handled {
		t.Fatalf("an unclassified write did not pace: handled=%v err=%v", handled, werr)
	}
	if waited := time.Since(start); waited < 400*time.Millisecond {
		t.Fatalf("an unclassified write returned after %v; it never entered the credit queue at all", waited)
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
// only way on is the authority lane, which the engine may not enter from inside
// the caller's locks). Every granted byte must come back, or the ledger drifts
// away from the exact reservation underneath it and the gate starts throttling
// against debt nobody owes.
//
// It also pins WHICH answer the engine gives. Reaching the authority lane from
// here means releasing the covering delegation — a drain, under the caller's
// namespace and handle locks — so the engine reports ErrLaneChanged and the
// frontend pays for that release outside them. Silently taking the lane, as the
// pre-classifier shape did, is what put a drain under nsMu.
func TestFrontendGrantIsRefundedWhenTheWriteNeverReachesTheWAL(t *testing.T) {
	pinCreditTimings(t, 400*time.Millisecond, 25*time.Second, 30*time.Second)
	f := newSaturationFixture(t, 8<<20)
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

	opCtx := WithResolvedLane(WithDataCredit(ctx, granted), LaneDelegated)
	_, handled, werr := f.e.WriteAt(opCtx, "d/absent", 0, chunk)
	if handled {
		t.Fatalf("write to an unknown path was admitted locally: err=%v", werr)
	}
	if !errors.Is(werr, ErrLaneChanged) {
		t.Fatalf("write to an unknown path = %v, want ErrLaneChanged: reaching the "+
			"authority lane from here means releasing a delegation under the caller's locks", werr)
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
	opCtx := WithResolvedLane(WithDataCredit(ctx, granted), LaneDelegated)
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

// TestClassifiedWriteNeverWaitsOnHardCapHeadroom is the second no-wait promise.
// The credit ledger counts payload bytes; the WAL counts framed bytes and whole
// segments, so a fully granted write can still find the exact reservation full.
// A lock-free caller waits for applied progress there — correct for it, and
// wrong for a frontend already holding its namespace lock. A classified write
// reports the lane changed instead of blocking, and instead of diverting: the
// divert would mean releasing the grant that is holding these very bytes, which
// is the same drain under the same locks.
func TestClassifiedWriteNeverWaitsOnHardCapHeadroom(t *testing.T) {
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
		opCtx := WithResolvedLane(WithDataCredit(ctx, granted), LaneDelegated)
		start := time.Now()
		_, handled, werr := f.e.WriteAppend(opCtx, "d/f", chunk[:granted])
		waited := time.Since(start)
		f.e.ReleaseDataCredit(ReclaimDataCredit(opCtx))
		if waited > 2*time.Second {
			t.Fatalf("classified append %d blocked for %v: it waited on hard-cap headroom, which a caller holding a namespace lock must never do", i, waited)
		}
		if errors.Is(werr, ErrLaneChanged) {
			// The hard cap bound and the engine reported the lane changed
			// instead of waiting or diverting. That is the whole contract.
			return
		}
		if werr != nil && !errors.Is(werr, ErrNoSpace) {
			t.Fatalf("classified append %d: %v", i, werr)
		}
		if !handled {
			t.Fatalf("classified append %d changed lanes without saying so", i)
		}
	}
	t.Skip("the hard cap never became the binding constraint at this budget")
}
