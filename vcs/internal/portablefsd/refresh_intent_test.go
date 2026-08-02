package portablefsd

// ── FINDING 2 (ROUND 13): CONTENTION IS NOT A COHERENCE FAILURE ─────────────
//
// The reservation is taken at pre-lock admission and released only when the
// handler has published, so it spans the frontend mirrors, the namespace and
// handle locks, and the whole authority round trip the handler makes. That is
// exactly what it must span — but it means an ORDINARY size mutation can hold
// it for a second or more merely by queueing behind an exclusive rename, a
// reclaim, or one healthy-but-slow authority operation.
//
// The refresh's answer to a reservation was to REFUSE and retry: 41 attempts,
// 25ms apart, ≈1.025s of budget. A reservation outliving that budget exhausted
// the exact transaction, and the authority event watcher turns a failed exact
// refresh into failCoherence — a TERMINAL, remount-only verdict, reached from
// nothing but contention. Overlapping writers reached it the same way with no
// single slow mutation at all, because the refresh had no priority: every
// arrival could barge in front of it, indefinitely.
//
// The fix is a per-item refresh INTENT. Once a refresh is pending, later
// reservations queue; the reservations already outstanding drain; and the
// intent becomes the pin without ever reopening the door. Contention then waits
// under the caller's real deadline instead of consuming stale-sample retries,
// and failCoherence is left for genuine no-progress.

import (
	"context"
	"sync"
	"testing"
	"time"
)

// stubRefreshSyscall makes the refresh's own ftruncate a no-op that still opens
// and closes a real window, so a transaction's outcome is decided by the token
// protocol and nothing else.
func stubRefreshSyscall(a *attach) {
	a.testRefreshKernelFile = func(
		_ string, _ string, _ uint64, _ int64, arm func() (func(), error),
	) (kernelRefreshOutcome, error) {
		disarm, err := arm()
		if err != nil {
			return kernelRefreshRetry, err
		}
		disarm()
		return kernelRefreshApplied, nil
	}
}

// TestOneSlowSizeMutationDoesNotExhaustTheRefreshBudget is the finding's first
// shape, at its smallest: ONE ordinary size mutation holds its reservation for
// slightly longer than the stale-sample budget.
//
// Nothing here is pathological. A mutation admitted and then queued behind an
// exclusive namespace request, or simply waiting on one healthy authority round
// trip, holds exactly this claim for exactly this long. The exact transaction
// must not treat it as a failure to converge: its caller fail-freezes the mount.
func TestOneSlowSizeMutationDoesNotExhaustTheRefreshBudget(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mountPath = "/unused-test-mount"
	stubRefreshSyscall(a)

	// Comfortably past staleSampleRetries+1 attempts of refreshCoalesce each.
	hold := time.Duration(staleSampleRetries+1)*refreshCoalesce + 400*time.Millisecond

	release, _, eno := a.reserveSizeMutation(context.Background(), itemID)
	if eno != 0 {
		t.Fatalf("reserving an idle item was refused: errno=%d", eno)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(hold)
		release()
		close(released)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	err := a.refreshKernelItemExactMode(ctx, itemID, true)
	elapsed := time.Since(start)
	<-released
	if err != nil {
		t.Fatalf("an exact kernel refresh failed after %s because one ordinary size "+
			"mutation held its reservation for %s: %v\n"+
			"the authority event watcher turns this into failCoherence, so ordinary "+
			"contention terminally freezes the mount", elapsed, hold, err)
	}
	if elapsed < hold {
		t.Fatalf("the refresh completed in %s, before the reservation it had to be "+
			"ordered behind was released (%s): it armed over a live size mutation",
			elapsed, hold)
	}
}

// TestContinuousWritersCannotBargePastAPendingRefresh is the second shape, and
// it is the one no budget can survive: no single mutation is slow, but arrivals
// overlap, so at no instant is the item free of a reservation. Without a pending
// refresh's claim on the item, every attempt the refresh makes finds one.
func TestContinuousWritersCannotBargePastAPendingRefresh(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mountPath = "/unused-test-mount"
	stubRefreshSyscall(a)

	// The one reservation that is already outstanding when the refresh becomes
	// pending. It drains on its own schedule — well inside the budget — so a
	// refresh that is allowed to WAIT converges quickly; a refresh that must
	// re-check against whatever is reserved at each 25ms tick never does,
	// because the arriving writers below keep the item covered.
	primer, _, eno := a.reserveSizeMutation(context.Background(), itemID)
	if eno != 0 {
		t.Fatalf("reserving an idle item was refused: errno=%d", eno)
	}
	primerReleased := make(chan struct{})
	go func() {
		time.Sleep(300 * time.Millisecond)
		primer()
		close(primerReleased)
	}()

	// Continuous overlapping writers. Each holds far longer than the interval at
	// which the next one arrives, so their coverage of the item is unbroken —
	// and each releases on its own timer, never waiting for a successor, exactly
	// as a real handler does.
	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			writers.Add(1)
			go func() {
				defer writers.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				rel, _, eno := a.reserveSizeMutation(ctx, itemID)
				if eno != 0 {
					return
				}
				time.Sleep(500 * time.Millisecond)
				rel()
			}()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := a.refreshKernelItemExactMode(ctx, itemID, true)
	close(stop)
	writers.Wait()
	<-primerReleased
	if err != nil {
		t.Fatalf("a pending exact refresh was barged out of its whole budget by "+
			"ordinary overlapping writers: %v\n"+
			"a refresh that can be starved by arrivals has no bound at all, and "+
			"its failure is terminal at the caller", err)
	}
}

// TestRefreshIntentQueuesLaterReservationsAndDrainsExistingOnes is the protocol
// itself, without a syscall or an authority in the picture.
//
//	– an intent does not become pending over an outstanding reservation: it
//	  waits for that reservation to drain;
//	– a reservation that arrives after the intent is pending QUEUES, however
//	  many times it is retried, so the drain can actually complete;
//	– releasing the intent wakes the queue.
func TestRefreshIntentQueuesLaterReservationsAndDrainsExistingOnes(t *testing.T) {
	a := &attach{}
	const item = uint64(41)

	outstanding, _, eno := a.reserveSizeMutation(context.Background(), item)
	if eno != 0 {
		t.Fatalf("reserving an idle item was refused: errno=%d", eno)
	}

	intentReady := make(chan func(), 1)
	go func() {
		release, err := a.acquireRefreshIntent(context.Background(), item)
		if err != nil {
			t.Errorf("acquiring a refresh intent failed: %v", err)
			close(intentReady)
			return
		}
		intentReady <- release
	}()

	select {
	case <-intentReady:
		t.Fatal("a refresh intent became ready while a size mutation reservation " +
			"was still outstanding: the refresh would arm over a mutation that can " +
			"still commit inside its syscall")
	case <-time.After(150 * time.Millisecond):
	}

	// A reservation arriving while the intent is pending must QUEUE. If it were
	// granted, the drain the intent is waiting for could never complete.
	queued := make(chan int32, 1)
	go func() {
		rel, _, eno := a.reserveSizeMutation(context.Background(), item)
		if rel != nil {
			defer rel()
		}
		queued <- eno
	}()
	select {
	case <-queued:
		t.Fatal("a size mutation reserved an item a refresh had already declared " +
			"an intent on: continuous arrivals can then starve the refresh forever")
	case <-time.After(150 * time.Millisecond):
	}

	outstanding()
	var releaseIntent func()
	select {
	case releaseIntent = <-intentReady:
		if releaseIntent == nil {
			t.Fatal("the refresh intent never became ready")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh intent never drained after its only outstanding " +
			"reservation was released")
	}
	select {
	case <-queued:
		t.Fatal("the queued size mutation was granted while the refresh still held " +
			"its intent")
	case <-time.After(100 * time.Millisecond):
	}

	releaseIntent()
	select {
	case eno := <-queued:
		if eno != 0 {
			t.Fatalf("the queued size mutation failed with errno=%d", eno)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("releasing the refresh intent never woke the mutation queued " +
			"behind it")
	}
}

// TestRefreshIntentWaitIsBoundedAndDoesNotHoldAnyLock is the liveness half.
//
// The wait is under the refresh transaction's own bounded context and holds
// nothing, so a drain that genuinely never happens ends as a bounded error the
// caller can report — never as an unbounded park, and never by giving up on the
// exclusion and arming anyway.
func TestRefreshIntentWaitIsBoundedAndDoesNotHoldAnyLock(t *testing.T) {
	a := &attach{}
	const item = uint64(42)

	stuck, _, eno := a.reserveSizeMutation(context.Background(), item)
	if eno != 0 {
		t.Fatalf("reserving an idle item was refused: errno=%d", eno)
	}
	defer stuck()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	release, err := a.acquireRefreshIntent(ctx, item)
	if err == nil {
		release()
		t.Fatal("a refresh intent became ready over a reservation that never drained")
	}
	if !a.mu.TryLock() {
		t.Fatal("the refresh intent's drain wait held a.mu")
	}
	a.mu.Unlock()
	a.mu.Lock()
	pending := len(a.refreshIntents)
	a.mu.Unlock()
	if pending != 0 {
		t.Fatalf("a refused intent left %d pending intent(s) behind: every size "+
			"mutation on the item would queue forever", pending)
	}
	// And the item is usable again: a new reservation is granted immediately.
	rel, _, eno := a.reserveSizeMutation(ctx, item)
	if eno != 0 {
		t.Fatalf("a reservation after a refused intent failed with errno=%d", eno)
	}
	rel()
}
