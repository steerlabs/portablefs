package portablefsd

// ── ROUND 16, DEFECT A: THE REPAIR STARVED THE APPLICATION ──────────────────
//
// The crossed-scope repair guarded itself with a POINT-IN-TIME read —
// `if a.sizeMutationReserved(itemID) { continue }` — taken outside the item's
// arrival order, one instruction before acquireRefreshIntent installed an
// EXCLUSIVE intent. An ordinary write loop has a gap between one operation's
// release and the next one's admission; the repair wins that gap by
// construction, and from the instant its intent is installed every ARRIVING
// size mutation on the item queues behind it for the whole of the pass.
//
// Live, on a fresh mount with ONE file and a plain
// open(O_APPEND)/write/fsync/close loop: fsync=400.9s (state UN), open=50.1s,
// fsync=300.3s, and NORMAL the instant the 10-minute repair budget expired.
//
// These are the two properties the fix must establish, and both fail against
// the pre-fix daemon:
//
//   1. AN APPLICATION SIZE MUTATION IS NEVER HELD BY A REPAIR PASS. The repair
//      is a coherence correction, not a mutation; it has no claim that outranks
//      the application's, so a mutation arriving behind it takes the item.
//   2. A CONTINUOUSLY WRITTEN ITEM CONVERGES. The give-up path stays as the
//      backstop, but a busy item is discharged by the writer's own publications
//      rather than by exhausting ten minutes of budget.

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// stallingRefreshSyscall makes every refresh apply report retry WITHOUT ever
// arming a pin, which is the pre-pin shape of the live non-convergence: the
// pass holds its intent for its whole transaction and never reaches the one
// legitimately non-preemptible region.
//
// Each call also costs `per`, so one pass occupies its context rather than
// spinning through 41 attempts in a millisecond. That is what makes the
// application's wait measurable in a unit test at all.
func stallingRefreshSyscall(a *attach, per time.Duration) {
	a.testRefreshKernelFile = func(
		_ string, _ string, _ uint64, _ int64, _ func() (func(), error),
	) (kernelRefreshOutcome, error) {
		time.Sleep(per)
		return kernelRefreshRetry, nil
	}
}

// compressRepairBudgets shrinks the repair's three production bounds so a test
// drives the same failure shape in seconds. Production never changes them.
func compressRepairBudgets(t *testing.T, attempt, retry, budget time.Duration) {
	t.Helper()
	origAttempt, origRetry, origBudget := crossedRefreshTimeout, crossedRepairRetryDelay, crossedRepairBudget
	origMax := crossedRepairMaxRetryDelay
	crossedRefreshTimeout = attempt
	crossedRepairRetryDelay = retry
	crossedRepairBudget = budget
	crossedRepairMaxRetryDelay = retry
	t.Cleanup(func() {
		crossedRefreshTimeout = origAttempt
		crossedRepairRetryDelay = origRetry
		crossedRepairBudget = origBudget
		crossedRepairMaxRetryDelay = origMax
	})
}

// TestCrossedRepairNeverHoldsAnArrivingSizeMutation is defect A at its
// smallest: a repair is running on an item, and an ordinary application write
// arrives while it holds its intent.
//
// The application must not wait for the repair. Not for the repair's
// per-attempt bound, not for a shortened one — a coherence correction the
// daemon owes ITSELF may not stop the work the mount exists to do.
func TestCrossedRepairNeverHoldsAnArrivingSizeMutation(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mountPath = "/unused-test-mount"
	// A pass that occupies its whole transaction and never pins.
	compressRepairBudgets(t, 3*time.Second, 50*time.Millisecond, 30*time.Second)
	stallingRefreshSyscall(a, 40*time.Millisecond)

	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	repairDone := make(chan struct{})
	go func() {
		defer close(repairDone)
		a.repairCrossedItem(lifetime, itemID)
	}()

	// Let the repair take the item. This is exactly the gap a write loop leaves
	// between close(2) and the next open(2), and the pre-fix repair's
	// point-in-time reservation check passes through it every time.
	time.Sleep(300 * time.Millisecond)

	// Now the application arrives, as it does on every iteration of the repro.
	const applicationMustNotWaitLongerThan = 400 * time.Millisecond
	worst := time.Duration(0)
	for i := 0; i < 8; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		start := time.Now()
		release, _, eno := a.reserveSizeMutation(ctx, itemID)
		waited := time.Since(start)
		cancel()
		if eno != 0 {
			t.Fatalf("an application size mutation was refused while a coherence "+
				"repair ran: errno=%d", eno)
		}
		// A real handler holds its reservation across its commit and publication,
		// then releases and the next open/write pair arrives a moment later.
		time.Sleep(20 * time.Millisecond)
		release()
		if waited > worst {
			worst = waited
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancelLifetime()
	<-repairDone

	if worst > applicationMustNotWaitLongerThan {
		t.Fatalf("an application size mutation waited %s behind a kernel coherence "+
			"repair (limit %s).\n"+
			"The repair installs an exclusive refresh intent and every arriving "+
			"mutation queues behind it for the whole pass; live this is a "+
			"multi-minute uninterruptible freeze of an ordinary write loop.",
			worst, applicationMustNotWaitLongerThan)
	}
}

// TestCrossedRepairConvergesWhileTheItemIsContinuouslyWritten is the second
// half, and it is the one a yield alone does not satisfy.
//
// Yielding to every writer makes the application fast and makes the repair
// never converge: it would retry for its whole ten-minute budget and end on the
// give-up path, leaving the mount permanently degraded on every busy file. The
// repair must instead DISCHARGE on the writer's own publications — the daemon
// restating this item's attributes to the kernel is precisely the correction
// the repair wanted, and the crossed path has already published the lazy
// content invalidation that covers the item's pages.
//
// ROUND 17: the writer below runs the WHOLE bracket a real write handler runs,
// and it must. It used to reserve, assign attributes, and release — which is
// only the daemon-side half — and that is the same assumption the witness
// itself made, so the test could not have failed on the defect it was meant to
// pin. A publication is a discharge only when it is the RESERVING mutation's
// own committed publication and that publication has been DELIVERED to the
// frontend (repairwitness.go), so the writer marks and delivers exactly as
// ops.go and the dispatcher do.
func TestCrossedRepairConvergesWhileTheItemIsContinuouslyWritten(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mountPath = "/unused-test-mount"
	compressRepairBudgets(t, 3*time.Second, 50*time.Millisecond, 8*time.Second)
	stallingRefreshSyscall(a, 40*time.Millisecond)

	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()

	// A continuous writer: reserve, publish post-op attributes, release — the
	// exact bracket a real write handler runs, at a rate that leaves the item
	// covered essentially all the time.
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			release, token, eno := a.reserveSizeMutation(ctx, itemID)
			if eno != 0 {
				cancel()
				continue
			}
			// The request context every handler for this mutation runs under.
			reqCtx := withSizeMutationToken(ctx, token)
			a.mu.Lock()
			if rec := a.items[itemID]; rec != nil {
				attr := rec.attr
				attr.Size += 4096
				a.publishRecordAttrLocked(rec, attr, false)
				// ops.go: committed, and the post-op size is in the registry.
				markSizeMutationPublished(reqCtx)
			}
			a.mu.Unlock()
			release()
			// The dispatcher: the reply frame carrying that size went out.
			a.noteSizeMutationDelivered(reqCtx)
			cancel()
		}
	}()

	start := time.Now()
	a.repairCrossedItem(lifetime, itemID)
	elapsed := time.Since(start)
	close(stop)
	<-writerDone

	a.mu.RLock()
	gaveUp := a.coherenceRepairGaveUp
	a.mu.RUnlock()
	if gaveUp {
		t.Fatalf("the coherence repair spent its whole %s budget and gave up on an "+
			"item its own writer was continuously republishing (%s elapsed).\n"+
			"Give-up is the backstop, not the normal outcome for a busy file: every "+
			"actively written file would leave the mount permanently degraded.",
			crossedRepairBudget, elapsed)
	}
	if elapsed >= crossedRepairBudget {
		t.Fatalf("the coherence repair ran for %s against a %s budget: it did not "+
			"converge on the writer's own publications", elapsed, crossedRepairBudget)
	}
}

// TestCrossedRepairYieldsTheItemBeforeItPins proves the yield is a property of
// the turnstile rather than of timing: a mutation that queues behind a yielding
// intent PREEMPTS it, and the preemption is visible the moment the mutation
// takes its ticket.
func TestCrossedRepairYieldsTheItemBeforeItPins(t *testing.T) {
	a := &attach{}
	const item = uint64(77)

	release, preempt, err := a.acquireRefreshIntentMode(context.Background(), item, true)
	if err != nil {
		t.Fatalf("acquiring a yielding refresh intent failed: %v", err)
	}
	defer release()

	select {
	case <-preempt:
		t.Fatal("a yielding intent was preempted before any mutation arrived")
	default:
	}

	granted := make(chan int32, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rel, _, eno := a.reserveSizeMutation(ctx, item)
		if rel != nil {
			rel()
		}
		granted <- eno
	}()

	select {
	case <-preempt:
	case <-time.After(5 * time.Second):
		t.Fatal("a size mutation queued behind a yielding refresh intent and the " +
			"intent was never preempted: the application waits for the repair")
	}

	release()
	select {
	case eno := <-granted:
		if eno != 0 {
			t.Fatalf("the preempting size mutation failed with errno=%d", eno)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("releasing a preempted intent never granted the mutation behind it")
	}
}

// TestNonYieldingRefreshIntentIsNotPreemptible keeps the barrier path exactly
// where round 13-15 left it. The authority invalidation watcher's exact refresh
// is a PROOF the authority's coherence barrier waits on; it must still exclude
// writers, and nothing here may weaken it.
func TestNonYieldingRefreshIntentIsNotPreemptible(t *testing.T) {
	a := &attach{}
	const item = uint64(78)

	release, preempt, err := a.acquireRefreshIntentMode(context.Background(), item, false)
	if err != nil {
		t.Fatalf("acquiring a refresh intent failed: %v", err)
	}
	defer release()

	queued := make(chan int32, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rel, _, eno := a.reserveSizeMutation(ctx, item)
		if rel != nil {
			rel()
		}
		queued <- eno
	}()

	select {
	case <-preempt:
		t.Fatal("a non-yielding refresh intent was preempted by an arriving size " +
			"mutation: the authority coherence barrier no longer excludes writers")
	case <-queued:
		t.Fatal("a size mutation was granted over a non-yielding refresh intent")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestRepairPublicationWatchCountsOnlyDeliveredSizeMutations keeps the
// convergence witness honest in every direction that matters.
//
// -- WHAT THE OLD VERSION OF THIS TEST ASSERTED, AND WHY IT WAS VACUOUS ------
//
// It published ARBITRARY attributes under an ARBITRARY reservation and demanded
// that they be counted. That is exactly the assumption the defect is made of:
// "some publication happened while some reservation existed" is a statement
// about the item, not about any mutation, so a test written that way agrees
// with the bug by construction and can never fail on it.
//
// The witness now counts a publication only when all three hold:
//
//   - it came from the request holding the item's reservation TOKEN;
//   - that request COMMITTED and installed its post-op size into the registry;
//   - the reply carrying it was DELIVERED to the frontend.
//
// and the map still never grows with the working set.
func TestRepairPublicationWatchCountsOnlyDeliveredSizeMutations(t *testing.T) {
	a := newMetadataTestAttach()
	rec := a.bindTestRecord(&itemRecord{
		item: pfslocal.Item{ItemID: 91, ItemGeneration: 1},
		path: "d/g", attr: fsproto.Attr{Kind: "file"},
	})
	unwatched := a.bindTestRecord(&itemRecord{
		item: pfslocal.Item{ItemID: 92, ItemGeneration: 1},
		path: "d/h", attr: fsproto.Attr{Kind: "file"},
	})

	a.mu.Lock()
	a.publishRecordAttrLocked(unwatched, unwatched.attr, false)
	a.mu.Unlock()
	a.mu.RLock()
	tracked := len(a.repairPublicationWatches)
	a.mu.RUnlock()
	if tracked != 0 {
		t.Fatalf("publishing attributes for an unwatched item recorded %d entries: "+
			"the witness would grow with the working set", tracked)
	}

	watch := a.watchRepairPublications(rec.item.ItemID)
	if got := watch.since(); got != 0 {
		t.Fatalf("a fresh watch already counted %d publications", got)
	}

	// (1) A publication by something holding NO token -- a getattr, a
	// reconciliation install -- counts for nothing whatever is reserved.
	release, _, eno := a.reserveSizeMutation(context.Background(), rec.item.ItemID)
	if eno != 0 {
		t.Fatalf("reserving an idle item was refused: errno=%d", eno)
	}
	a.mu.Lock()
	a.publishRecordAttrLocked(rec, rec.attr, false)
	a.mu.Unlock()
	a.noteSizeMutationDelivered(context.Background())
	if got := watch.since(); got != 0 {
		t.Fatalf("a publication by a request holding no size-mutation token "+
			"counted %d: the repair would discharge on state that says nothing "+
			"about what the kernel was told", got)
	}
	release()

	// (2) A mutation that holds its token and NEVER COMMITS counts for nothing.
	release, token, eno := a.reserveSizeMutation(context.Background(), rec.item.ItemID)
	if eno != 0 {
		t.Fatalf("reserving an idle item was refused: errno=%d", eno)
	}
	abandoned := withSizeMutationToken(context.Background(), token)
	release()
	a.noteSizeMutationDelivered(abandoned)
	if got := watch.since(); got != 0 {
		t.Fatalf("a size mutation that took its reservation and committed nothing "+
			"counted %d", got)
	}

	// (3) A mutation that COMMITS but whose reply is never delivered -- an errno
	// after the commit, or a retracted operation -- counts for nothing either:
	// the kernel was not told.
	release, token, eno = a.reserveSizeMutation(context.Background(), rec.item.ItemID)
	if eno != 0 {
		t.Fatalf("reserving an idle item was refused: errno=%d", eno)
	}
	undelivered := withSizeMutationToken(context.Background(), token)
	a.mu.Lock()
	a.publishRecordAttrLocked(rec, rec.attr, false)
	markSizeMutationPublished(undelivered)
	a.mu.Unlock()
	release()
	if got := watch.since(); got != 0 {
		t.Fatalf("a committed publication whose reply never reached the frontend "+
			"counted %d", got)
	}

	// (4) The real thing: token, commit, delivery. Twice, and it counts twice --
	// and a single token delivered twice counts once.
	for i := 0; i < 2; i++ {
		release, token, eno = a.reserveSizeMutation(context.Background(), rec.item.ItemID)
		if eno != 0 {
			t.Fatalf("reserving an idle item was refused: errno=%d", eno)
		}
		reqCtx := withSizeMutationToken(context.Background(), token)
		a.mu.Lock()
		a.publishRecordAttrLocked(rec, rec.attr, false)
		markSizeMutationPublished(reqCtx)
		a.mu.Unlock()
		release()
		a.noteSizeMutationDelivered(reqCtx)
		a.noteSizeMutationDelivered(reqCtx)
	}
	if got := watch.since(); got != 2 {
		t.Fatalf("delivered size-mutation publications = %d, want 2", got)
	}

	watch.stop()
	a.mu.RLock()
	tracked = len(a.repairPublicationWatches)
	a.mu.RUnlock()
	if tracked != 0 {
		t.Fatalf("stopping the watch left %d entries behind", tracked)
	}
}

// TestCrossedRepairOnAQuietItemConvergesByRefreshing answers the question the
// live run could not: when the item is NOT busy, does the repair still converge
// by actually refreshing, or does it fall through to the give-up backstop?
//
// It drives the real repairCrossedItem over a real volume and a real authority,
// with only the ftruncate syscall stubbed (stubRefreshSyscall opens and closes a
// genuine window). Nothing here yields, because nothing is writing — so this
// exercises the ordinary convergence path, and it must end by REFRESHING, not by
// publication-discharge and not by giving up.
func TestCrossedRepairOnAQuietItemConvergesByRefreshing(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mountPath = "/unused-test-mount"
	compressRepairBudgets(t, 10*time.Second, 50*time.Millisecond, 20*time.Second)
	stubRefreshSyscall(a)
	quietWatch := a.watchRepairPublications(itemID)
	defer quietWatch.stop()

	start := time.Now()
	a.repairCrossedItem(context.Background(), itemID)
	elapsed := time.Since(start)

	a.mu.RLock()
	gaveUp := a.coherenceRepairGaveUp
	lastErr := a.lastErr
	a.mu.RUnlock()
	if gaveUp {
		t.Fatalf("a QUIET item's coherence repair reached the give-up backstop after %s: "+
			"the repair no longer converges by refreshing, so every crossed item would "+
			"leave the mount degraded", elapsed)
	}
	if lastErr != "" {
		t.Fatalf("a converged repair left the attach degraded: %q", lastErr)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("a quiet item took %s to converge", elapsed)
	}
	// And it converged by REFRESHING: no writer ever ran, so the publication
	// witness must have counted nothing.
	if n := quietWatch.since(); n != 0 {
		t.Fatalf("a quiet item recorded %d delivered writer publications", n)
	}
}
