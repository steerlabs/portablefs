package portablefsd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// ── FINDING 1 (ROUND 12): THE REFRESH TRUNCATE MUST BE A LINEARIZATION POINT ──
//
// Round 10 gave the fence a witness for a mutation that had already committed,
// and round 11 taught the window classifier to refuse a mutation that STARTS
// while a window is open. Both are checks, and a check speaks only about the
// past: each detects a mutation that began before it ran.
//
// The interleaving that survived both is the one where nothing is checked at
// all. The refresh's setattr upcall reaches its phase-3 revalidation, observes
// no mutation in flight, answers locally and returns — releasing every lock. The
// Swift callback carrying that answer has not returned to the kernel yet, so the
// original unix.Ftruncate(2) has not completed. A second callback on the same
// item now opens its own sequence and commits an extension, the application is
// told the bytes are durable, and only THEN does ftruncate(S) complete, cutting
// the kernel's vnode back over them.
//
// No stronger predicate placed before the syscall completes can close that: the
// gap is a missing ORDER, not a missing observation. See refreshpin.go.

// TestNoSizeMutationCommitsInsideARefreshTruncate is the interleaving itself,
// driven through the real dispatcher admission and the real refresh apply path.
//
// The refresh is inside its ftruncate — arm() has returned and the disarm has
// not run — and a real application write is admitted against the same item at
// exactly that moment. It must not be able to commit until the syscall has
// completed, and it must complete promptly once it has.
func TestNoSizeMutationCommitsInsideARefreshTruncate(t *testing.T) {
	a, vol, itemID, handleID := newMutationSeqAttach(t)
	ctx := context.Background()

	a.mu.RLock()
	live := a.items[itemID]
	snapshot := &itemRecord{
		item: live.item, path: live.path, state: live.state,
		attr: live.attr, graft: live.graft,
	}
	a.mu.RUnlock()
	sampledSize, version, generation, outcome := refreshLocalSampleAuthorityContext(
		ctx, vol, "d/f", snapshot.state.AuthorityIno(),
	)
	if outcome != refreshSampleReady {
		t.Fatalf("pre-write authority sample outcome = %v", outcome)
	}
	fence := refreshApplyFence{
		observedSize: snapshot.attr.Size,
		version:      version,
		generation:   generation,
	}

	payload := []byte("an extension admitted inside the refresh's own syscall")
	writeDone := make(chan int32, 1)
	admitted := make(chan struct{})
	var committedInsideTheSyscall bool

	a.testRefreshKernelFile = func(
		_ string, _ string, _ uint64, size int64, arm func() (func(), error),
	) (kernelRefreshOutcome, error) {
		disarm, err := arm()
		if err != nil {
			return kernelRefreshRetry, err
		}
		// INSIDE unix.Ftruncate(2). The upcall this syscall produced has already
		// been answered and every lock it held is released; this is exactly the
		// state in which the finding's second callback runs.
		go func() {
			close(admitted)
			_, eno := admittedWrite(ctx, a, &pfslocal.WriteRequest{
				Handle: handleID, Offset: 0, Data: payload,
			})
			writeDone <- eno
		}()
		<-admitted
		select {
		case <-writeDone:
			committedInsideTheSyscall = true
		case <-time.After(300 * time.Millisecond):
		}
		disarm()
		return kernelRefreshApplied, nil
	}

	applyOutcome, applyErr := a.applyKernelRefresh(
		"/unused-test-mount", "d/f", snapshot, sampledSize, fence,
	)
	if committedInsideTheSyscall {
		t.Fatal("a size mutation ran to completion while the daemon was inside the " +
			"ftruncate(2) of a pinned refresh: the refresh's syscall is not a " +
			"linearization point, so its truncate can land after a commit the " +
			"application has already been told is durable")
	}
	if applyOutcome != kernelRefreshApplied || applyErr != nil {
		t.Fatalf("the refresh itself was refused (%v, %v): the token must order the "+
			"mutation behind the syscall, not wedge the refresh", applyOutcome, applyErr)
	}

	// And the ordering is a WAIT, not a refusal: the write completes the moment
	// the syscall does, and its bytes are published.
	select {
	case eno := <-writeDone:
		if eno != 0 {
			t.Fatalf("the write held behind the refresh failed with errno=%d", eno)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the write never completed after the refresh released its pin")
	}
	a.mu.RLock()
	published := a.items[itemID].attr.Size
	unstable := a.itemMutationInFlightLocked(itemID)
	a.mu.RUnlock()
	if published != int64(len(payload)) {
		t.Fatalf("registry holds %d after a write of %d committed bytes", published, len(payload))
	}
	if unstable {
		t.Fatal("the ordered write left its item permanently unstable")
	}
}

// TestRefreshRefusesToArmOverAnAdmittedSizeMutation is the other half of the
// token, and it is the arm's side of the handshake: a mutation that has been
// admitted but has not yet reached its engine commit is invisible to the
// mutation SEQUENCE (which opens immediately before the commit) and must still
// stop the window from opening.
func TestRefreshRefusesToArmOverAnAdmittedSizeMutation(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mu.RLock()
	live := a.items[itemID]
	snapshot := &itemRecord{item: live.item, path: live.path, attr: live.attr}
	a.mu.RUnlock()
	fence := refreshApplyFence{observedSize: snapshot.attr.Size}

	settle, eno := a.reserveSizeMutation(context.Background(), itemID)
	if eno != 0 {
		t.Fatalf("reserving an unpinned item was refused: errno=%d", eno)
	}
	if a.itemMutationInFlightLocked(itemID) {
		t.Fatal("an admitted mutation that has not committed must not look like an " +
			"open sequence; the reservation is the earlier, independent witness")
	}
	_, _, err := a.armRefreshWindowLocked("d/f", snapshot, snapshot.attr.Size, fence)
	if err == nil {
		t.Fatal("a refresh armed a truncate window over an admitted size mutation: " +
			"the mutation can still commit inside the syscall the window brackets")
	}
	var superseded *errRefreshSampleSuperseded
	if !errors.As(err, &superseded) {
		t.Fatalf("arm refused with %v, want a supersession retry", err)
	}

	settle()
	disarm, _, err := a.armRefreshWindowLocked("d/f", snapshot, snapshot.attr.Size, fence)
	if err != nil {
		t.Fatalf("the item stayed fenced after its mutation finished: %v", err)
	}
	if err := disarm(); err != nil {
		t.Fatalf("an undisturbed window failed its post-syscall settle: %v", err)
	}
}

// TestPinnedRefreshHoldsASizeMutationAndThenReleasesIt pins the wait itself,
// without a syscall in the picture: a reservation attempted while a pin is held
// blocks, and completes as soon as the pin is released.
func TestPinnedRefreshHoldsASizeMutationAndThenReleasesIt(t *testing.T) {
	a := &attach{}
	const item = uint64(31)

	a.mu.Lock()
	unpin := a.pinRefreshItemLocked(item)
	a.mu.Unlock()

	reserved := make(chan int32, 1)
	go func() {
		release, eno := a.reserveSizeMutation(context.Background(), item)
		if release != nil {
			defer release()
		}
		reserved <- eno
	}()
	select {
	case <-reserved:
		t.Fatal("a size mutation reserved an item a refresh had pinned for its ftruncate")
	case <-time.After(150 * time.Millisecond):
	}
	unpin()
	select {
	case eno := <-reserved:
		if eno != 0 {
			t.Fatalf("the released reservation failed with errno=%d", eno)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a released pin never woke its waiter")
	}
}

// TestReservationWaitIsBoundedByTheOperationDeadline is the liveness half. The
// wait is deliberately not bounded by a private timer that could expire while a
// pin was still live — giving up would mean committing inside somebody else's
// ftruncate — so the request's own deadline is what bounds it, and the answer is
// the interrupted-syscall errno, which is honest because nothing was attempted.
func TestReservationWaitIsBoundedByTheOperationDeadline(t *testing.T) {
	a := &attach{}
	const item = uint64(32)
	a.mu.Lock()
	unpin := a.pinRefreshItemLocked(item)
	a.mu.Unlock()
	defer unpin()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	release, eno := a.reserveSizeMutation(ctx, item)
	if release != nil {
		release()
		t.Fatal("a reservation was granted while the item was pinned")
	}
	if eno != darwinEINTR {
		t.Fatalf("a deadline-bounded reservation answered errno=%d, want EINTR", eno)
	}
	if a.sizeMutationReservedLocked(item) {
		t.Fatal("a refused reservation left a claim behind")
	}
}

// TestRefreshThatCannotProveItsWindowAfterTheSyscallReportsRetry is the
// enforcement of the invariant rather than the invariant itself.
//
// The token makes a local commit inside the ftruncate impossible. This pins what
// happens if it ever became possible again: the pass must NOT report that it
// applied anything, because the vnode it just wrote is a state the daemon can no
// longer vouch for. The retry outcome re-samples and runs the corrective pass
// under the same bounded budget.
//
// The assertion is deliberately narrow. A size this daemon merely LEARNED during
// the window — a peer mount's write, discovered and published like any other
// observation — is not a violation and is covered by the pass's own post-apply
// verification sample; see TestRefreshWindowCannotDiscardARealApplicationTruncate,
// which drives exactly that shape and must keep reporting an applied refresh.
func TestRefreshThatCannotProveItsWindowAfterTheSyscallReportsRetry(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mu.RLock()
	live := a.items[itemID]
	snapshot := &itemRecord{
		item: live.item, path: live.path, state: live.state, attr: live.attr,
	}
	a.mu.RUnlock()
	fence := refreshApplyFence{observedSize: snapshot.attr.Size}

	a.testRefreshKernelFile = func(
		_ string, _ string, _ uint64, _ int64, arm func() (func(), error),
	) (kernelRefreshOutcome, error) {
		disarm, err := arm()
		if err != nil {
			return kernelRefreshRetry, err
		}
		// A local size mutation commits inside the syscall — the state the token
		// exists to make unreachable, forced here directly.
		a.mu.Lock()
		a.beginItemMutationLocked(itemID)
		a.mu.Unlock()
		disarm()
		return kernelRefreshApplied, nil
	}

	outcome, err := a.applyKernelRefresh(
		"/unused-test-mount", "d/f", snapshot, snapshot.attr.Size, fence,
	)
	if outcome == kernelRefreshApplied {
		t.Fatal("a pass over which a local size mutation committed during its own " +
			"ftruncate reported that it applied the refresh: the transaction would " +
			"settle on a kernel vnode the daemon has already stated it cannot vouch for")
	}
	var superseded *errRefreshSampleSuperseded
	if !errors.As(err, &superseded) {
		t.Fatalf("the pass reported %v, want a supersession retry", err)
	}
	a.mu.RLock()
	pinned := len(a.refreshPins)
	a.mu.RUnlock()
	if pinned != 0 {
		t.Fatalf("a returned refresh left %d pin(s) behind: every size mutation on "+
			"the item would park until its operation deadline", pinned)
	}
}

// TestTheDaemonsOwnRefreshUpcallNeverReservesItsItem is the exclusion that keeps
// the token from deadlocking against itself. The refresh's upcall is a
// size-bearing setattr like any other; making it wait for the pin would make it
// wait for the syscall it is itself completing.
func TestTheDaemonsOwnRefreshUpcallNeverReservesItsItem(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mu.RLock()
	rec := a.items[itemID]
	item, size := rec.item, uint64(rec.attr.Size)
	a.mu.RUnlock()

	// Open a pinned window for exactly this (item, size), as a live refresh does.
	snapshot := &itemRecord{item: item, path: "d/f", attr: rec.attr}
	disarm, _, err := a.armRefreshWindowLocked("d/f", snapshot, int64(size), refreshApplyFence{
		observedSize: rec.attr.Size,
	})
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	defer func() { _ = disarm() }()

	req := &pfslocal.SetAttrRequest{Item: item, Size: &size}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	opCtx, settle, eno, _ := a.admitRequest(ctx, req, false)
	settle()
	if eno != 0 {
		t.Fatalf("the daemon's own refresh upcall was refused at admission: errno=%d "+
			"— it waited for the pin of the syscall it is the upcall of", eno)
	}
	if verdict, ok := a.frozenRefreshVerdict(opCtx, req); !ok ||
		verdict.class == refreshClassApplication {
		t.Fatalf("phase 1 did not recognise the upcall as daemon-originated: %+v", verdict)
	}
	if a.sizeMutationReservedLocked(item.ItemID) {
		t.Fatal("the daemon's own refresh upcall took a size reservation on the item " +
			"its refresh has pinned")
	}
}
