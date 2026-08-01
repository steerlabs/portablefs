package portablefsd

// ── FINDING 1 (ROUND 13): A WINDOW'S TEARDOWN IS ONE STEP, NOT TWO ──────────
//
// The provenance marker and the pin are two statements about the same fact.
// The marker says "the daemon is inside its own ftruncate(2) for this (item,
// size)"; the pin is what MAKES that true, because it is what holds every
// application size mutation on the item behind the syscall.
//
// Tearing them down in two separate critical sections opens an interval in
// which the marker is still installed and the pin is already gone. A size-set
// matching (item, S) that arrives in it is admitted — nothing is pinned, so it
// takes no wait — and phase 1 reads the still-pinned marker, calls it daemon
// bookkeeping, and freezes that verdict. It takes NO reservation, the handler
// answers it locally, and a real application mutation is silently swallowed as
// refresh bookkeeping: the authority never sees it, no version ordering is
// published, and every other observer's ctime ordering for it never happens.

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestRefreshWindowTeardownLeavesNoStaleProvenanceMarker stands at the exact
// instant the pin becomes invisible and asks the daemon's own phase-1
// classifier the question an application truncate would ask there.
//
// The answer must be "this is an application mutation": the window is over, the
// syscall it described has returned, and nothing about the request in front of
// the classifier is the daemon's.
func TestRefreshWindowTeardownLeavesNoStaleProvenanceMarker(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)

	a.mu.RLock()
	live := a.items[itemID]
	snapshot := &itemRecord{
		item: live.item, path: live.path, state: live.state, attr: live.attr,
	}
	item := live.item
	size := uint64(live.attr.Size)
	a.mu.RUnlock()
	fence := refreshApplyFence{observedSize: snapshot.attr.Size}

	var (
		classAtTeardown  refreshClass
		verdictKnown     bool
		reservedAtDown   bool
		markerAtTeardown bool
		probeRan         bool
	)
	a.testRefreshWindowTeardown = func(p string, teardownItem uint64) {
		probeRan = true
		a.mu.RLock()
		_, markerAtTeardown = a.expectedTruncates[p]
		a.mu.RUnlock()

		// The real admission path, for a real application truncate to the size
		// the window named. Nothing is pinned any more, so it must not wait —
		// and it must be recognised for what it is.
		req := &pfslocal.SetAttrRequest{Item: item, Size: &size}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		opCtx, settle, eno, _ := a.admitRequest(ctx, req, false)
		if eno != 0 {
			t.Errorf("an application truncate admitted after the pin was released "+
				"was refused: errno=%d", eno)
		}
		var verdict refreshVerdict
		verdict, verdictKnown = a.frozenRefreshVerdict(opCtx, req)
		classAtTeardown = verdict.class
		reservedAtDown = a.sizeMutationReservedLocked(teardownItem)
		settle()
	}

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

	outcome, err := a.applyKernelRefresh(
		"/unused-test-mount", "d/f", snapshot, snapshot.attr.Size, fence,
	)
	if outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("refresh pass outcome=%v err=%v", outcome, err)
	}
	if !probeRan {
		t.Fatal("the refresh window teardown never ran")
	}
	if markerAtTeardown {
		t.Error("the provenance marker was still installed after the pin had been " +
			"released: for that whole interval the daemon claims to be inside an " +
			"ftruncate(2) that has already returned, with nothing holding an " +
			"application mutation behind it")
	}
	if !verdictKnown {
		t.Fatal("phase 1 minted no verdict for a size-bearing setattr")
	}
	if classAtTeardown != refreshClassApplication {
		t.Errorf("phase 1 classified a real application truncate as %v after the "+
			"refresh's pin was gone: the mutation is answered locally as refresh "+
			"bookkeeping and never reaches the authority, so the mutation and "+
			"version ordering it owes every other observer is silently dropped",
			classAtTeardown)
	}
	if !reservedAtDown {
		t.Error("an application size mutation admitted after the pin was released " +
			"took no size reservation: a refresh can arm underneath it")
	}
}
