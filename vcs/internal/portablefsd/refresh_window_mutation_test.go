package portablefsd

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// ── FINDING 2 (ROUND 11): AN OPEN WINDOW MUST NOTICE A NEW MUTATION ──────────
//
// The mutation sequence was consulted in exactly one place: the ARM. That
// closes the case where a mutation is already in flight when a refresh pass
// tries to open its window, and it says nothing about the reverse ordering —
// a window that is already open when a mutation STARTS.
//
// That ordering is ordinary, not exotic. The refresh arms on (item, S) and
// enters its ftruncate; a control write (or any other frontend's write, which
// bypasses the kernel entirely) opens its own sequence and commits N; before it
// publishes, the refresh's own setattr upcall reaches the provenance predicate.
// The registry still says S — that is the whole defect, not an accident of
// timing — so the predicate answered Internal, the daemon suppressed its own
// upcall as bookkeeping, and the stale kernel truncate to S completed after the
// newer commit.
//
// So the window's classification consults the sequence too, in BOTH phases:
// phase 1 (classifyRefreshRequest, through refreshWindowClassLocked) and the
// handler's phase-3 revalidation. Both take a.mu, which is also what the
// mutation bracket takes, so the two events are mutually ordered.

// TestOpenRefreshWindowIsAmbiguousWhileAMutationIsUnpublished is the predicate
// itself, in the one place both phases share.
func TestOpenRefreshWindowIsAmbiguousWhileAMutationIsUnpublished(t *testing.T) {
	a := &attach{
		items:       map[uint64]*itemRecord{},
		paths:       map[string]*itemRecord{},
		itemAliases: map[uint64]map[string]struct{}{},
	}
	rec := a.bindTestRecord(&itemRecord{
		item: pfslocal.Item{ItemID: 9, ItemGeneration: 1},
		path: "d/f",
		attr: fsproto.Attr{Kind: "file", Size: 4},
	})
	fence := refreshApplyFence{observedSize: 4}
	snapshot := &itemRecord{item: rec.item, path: rec.path, attr: rec.attr}

	disarm, _, err := a.armRefreshWindowLocked("d/f", snapshot, 4, fence)
	if err != nil {
		t.Fatalf("a stable item refused to arm: %v", err)
	}
	defer disarm()

	a.mu.RLock()
	class := a.refreshWindowClassLocked(9, 4, false)
	a.mu.RUnlock()
	if class != refreshClassInternal {
		t.Fatalf("an open window over an unchanged item classified %v, want Internal", class)
	}

	// A mutation STARTS while the window is open — a control write that has
	// committed and not yet published is the production shape.
	a.mu.Lock()
	a.beginItemMutationLocked(9)
	a.mu.Unlock()

	a.mu.RLock()
	class = a.refreshWindowClassLocked(9, 4, false)
	a.mu.RUnlock()
	if class != refreshClassAmbiguous {
		t.Fatalf("a window classified %v while a mutation was committed and "+
			"unpublished, want Ambiguous: the registry has NOT moved — that is the "+
			"defect, not the proof — so answering Internal lets the daemon's stale "+
			"ftruncate complete after the newer commit", class)
	}

	// And it is transient, not a wedge.
	a.mu.Lock()
	a.settleItemMutationLocked(9, true)
	a.mu.Unlock()
	a.mu.RLock()
	class = a.refreshWindowClassLocked(9, 4, false)
	a.mu.RUnlock()
	if class != refreshClassInternal {
		t.Fatalf("the window stayed ambiguous after the mutation published (%v)", class)
	}
}

// TestSetattrRefusesAnInternalUpcallWhileAMutationIsUnpublished drives the whole
// handler, because the predicate above is only half the fix: the frozen-verdict
// revalidation re-derives its own staleness test under the locks, and that test
// asked only about the composed size — the exact quantity a committed-but-
// unpublished mutation cannot move.
func TestSetattrRefusesAnInternalUpcallWhileAMutationIsUnpublished(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	ctx := context.Background()

	a.mu.RLock()
	live := a.items[itemID]
	snapshot := &itemRecord{
		item: live.item, path: live.path, state: live.state, attr: live.attr,
	}
	item := live.item
	a.mu.RUnlock()

	disarm, _, err := a.armRefreshWindowLocked(
		"d/f", snapshot, 0, refreshApplyFence{observedSize: 0},
	)
	if err != nil {
		t.Fatalf("arm the refresh window: %v", err)
	}
	defer disarm()

	size := uint64(0)
	req := &pfslocal.SetAttrRequest{Item: item, Size: &size}

	// The daemon's own upcall, with nothing else going on, is answered locally.
	if _, eno := a.setattr(ctx, req); eno != 0 {
		t.Fatalf("the daemon's own refresh upcall was refused with errno %d while "+
			"nothing else was mutating the item: the refresh would never converge", eno)
	}

	// A foreign mutation commits inside the open window and has not published.
	a.mu.Lock()
	a.beginItemMutationLocked(itemID)
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.settleItemMutationLocked(itemID, true)
		a.mu.Unlock()
	}()

	reply, eno := a.setattr(ctx, req)
	if eno != darwinEINTR {
		t.Fatalf("setattr inside an open window returned (%v, errno=%d) while a "+
			"mutation was committed and unpublished, want EINTR: the handler answered "+
			"the daemon's own upcall as bookkeeping, so the kernel's vnode is "+
			"shortened to the sampled size over a newer commit", reply, eno)
	}
}

// TestSetattrDoesNotRefuseItselfThroughItsOwnBracket is the regression the fix
// has to avoid, and it is why the bracket moved rather than the check being
// made owner-aware by hand.
//
// The daemon's own refresh upcall IS a size-bearing setattr. Opening its
// mutation sequence before the provenance decision would make every refresh
// upcall find "a mutation in flight" — its own — and refuse itself forever.
func TestSetattrDoesNotRefuseItselfThroughItsOwnBracket(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	ctx := context.Background()

	a.mu.RLock()
	live := a.items[itemID]
	snapshot := &itemRecord{
		item: live.item, path: live.path, state: live.state, attr: live.attr,
	}
	item := live.item
	a.mu.RUnlock()

	disarm, _, err := a.armRefreshWindowLocked(
		"d/f", snapshot, 0, refreshApplyFence{observedSize: 0},
	)
	if err != nil {
		t.Fatalf("arm the refresh window: %v", err)
	}
	defer disarm()

	size := uint64(0)
	for i := range 3 {
		if _, eno := a.setattr(ctx, &pfslocal.SetAttrRequest{Item: item, Size: &size}); eno != 0 {
			t.Fatalf("refresh upcall %d was refused with errno %d: the handler's own "+
				"bracket made it ambiguous to itself", i, eno)
		}
	}
	a.mu.RLock()
	stuck := a.itemMutationInFlightLocked(itemID)
	a.mu.RUnlock()
	if stuck {
		t.Fatal("a locally-answered refresh upcall left a mutation sequence open")
	}
}
