package portablefsd

// ── ROUND 17, FINDING 2: THE CROSSED REPAIR CONVERGED ON SOMEBODY ELSE ──────
//
// A crossed-scope repair may end by observing that the mutation which preempted
// it has already restated the item to the kernel. That is a real proof, and it
// is what keeps a continuously written file from walking the whole repair
// budget down to the give-up path — but only if the thing observed really is
// that mutation.
//
// The witness proved nothing of the kind. It counted ANY attribute assignment
// on the item made while ANY size reservation existed, and both halves are
// ambient facts about the item:
//
//	1. a getattr for the item is ALREADY IN FLIGHT, holding a.nsMu.RLock and the
//	   handle gate;
//	2. the repair yields the item to write W;
//	3. W is granted its reservation at pre-lock admission, then queues behind
//	   the getattr's locks, having committed nothing;
//	4. the getattr completes and publishes its PRE-WRITE observation — the very
//	   value the repair exists to correct. W's reservation exists, so it counts;
//	5. the repair exits "discharged";
//	6. W is cancelled, or fails, before it commits.
//
// No post-crossing size mutation ever reached the kernel and the coherence debt
// was discarded.
//
// These tests drive that interleaving with a REAL getattr against a real volume
// and a real authority — not by publishing arbitrary attributes — and they pin
// the concurrent-repair bookkeeping the same defect note raises.

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestCrossedRepairIsNotDischargedByAnInFlightGetattr is the exact interleaving.
func TestCrossedRepairIsNotDischargedByAnInFlightGetattr(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.ref = "crossed-repair-attribution"
	a.mountPath = "/unused-test-mount"

	// STEP: the repair is running and has ARMED its witness.
	watch := a.watchRepairPublications(itemID)
	defer watch.stop()

	a.mu.RLock()
	rec := a.items[itemID]
	preWrite := rec.attr
	a.mu.RUnlock()
	if rec == nil {
		t.Fatal("the test attach lost its item record")
	}

	// STEP 2/3: the repair yields, and W — a real application write — is granted
	// the item's reservation at pre-lock admission. It has committed NOTHING: in
	// the live shape it is now queued behind the getattr's namespace and handle
	// locks.
	releaseW, tokenW, eno := a.reserveSizeMutation(context.Background(), itemID)
	if eno != 0 {
		t.Fatalf("the preempting size mutation was refused: errno=%d", eno)
	}
	if tokenW == nil {
		t.Fatal("a granted size-mutation reservation minted no generation token: " +
			"nothing can attribute a later publication to the mutation that " +
			"preempted the repair")
	}

	// STEP 4: the older getattr completes and publishes its PRE-WRITE
	// observation, through the real handler, holding no size-mutation token.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, eno := a.getattr(ctx, &pfslocal.GetAttrRequest{Item: rec.item}); eno != 0 {
		t.Fatalf("the in-flight getattr failed: errno=%d", eno)
	}
	a.mu.RLock()
	published := a.items[itemID].attr
	a.mu.RUnlock()
	if published.Size != preWrite.Size {
		t.Fatalf("the getattr published a POST-write size (%d, was %d): the test "+
			"is no longer driving the pre-write observation the finding describes",
			published.Size, preWrite.Size)
	}

	// STEP 6: W is cancelled before it commits. Nothing it would have published
	// ever existed.
	releaseW()

	// STEP 5, checked last because it is the verdict: the repair must NOT
	// consider itself discharged. It has yielded once and made one attempt.
	if a.repairDischargedByPublication(watch, 1, 1) {
		t.Fatal(
			"the crossed repair discharged its coherence debt on an unrelated " +
				"publication.\n" +
				"An older getattr published its PRE-WRITE observation while the " +
				"preempting write merely held a reservation; the write then went " +
				"away without committing. No post-crossing size mutation ever " +
				"reached the kernel, and the kernel is left holding exactly the " +
				"stale value this repair existed to correct.\n" +
				"A reservation existing on the item is not a mutation, and an " +
				"attribute assignment is not a statement about what the kernel " +
				"was told.",
		)
	}
	if got := watch.since(); got != 0 {
		t.Fatalf("the witness counted %d publication(s) for a mutation that never "+
			"committed", got)
	}
}

// TestCrossedRepairIsDischargedByThePreemptingMutation is the other half, and it
// is the round-16 property that must not regress: the writer that really did
// take the item and really did tell the kernel discharges the debt, so a busy
// file does not walk the budget down to the give-up path.
func TestCrossedRepairIsDischargedByThePreemptingMutation(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mountPath = "/unused-test-mount"
	watch := a.watchRepairPublications(itemID)
	defer watch.stop()

	release, token, eno := a.reserveSizeMutation(context.Background(), itemID)
	if eno != 0 {
		t.Fatalf("the preempting size mutation was refused: errno=%d", eno)
	}
	reqCtx := withSizeMutationToken(context.Background(), token)

	a.mu.Lock()
	rec := a.items[itemID]
	attr := rec.attr
	attr.Size += 4096
	a.publishRecordAttrLocked(rec, attr, false)
	markSizeMutationPublished(reqCtx)
	a.mu.Unlock()
	release()
	a.noteSizeMutationDelivered(reqCtx)

	if !a.repairDischargedByPublication(watch, 1, 1) {
		t.Fatal("a repair that yielded to a write which committed AND delivered " +
			"its own post-op size was not discharged: every busy file walks the " +
			"whole repair budget down to the give-up path and leaves the mount " +
			"permanently degraded")
	}
}

// TestConcurrentRepairsOnOneItemDoNotBlindEachOther pins the second half of the
// finding: two repairs can name the same item — a disconnect repair and a
// crossing repair, or two crossings — and refreshCrossedItems is reached from
// several places.
//
// The old state was one map[itemID]counter, written as `= 0` by every watcher
// and `delete`d by every stop. A later watcher therefore RESET an earlier one's
// count, and either watcher's stop DELETED the shared entry, so the survivor
// silently stopped counting and ran to its give-up path.
func TestConcurrentRepairsOnOneItemDoNotBlindEachOther(t *testing.T) {
	a := newMetadataTestAttach()
	rec := a.bindTestRecord(&itemRecord{
		item: pfslocal.Item{ItemID: 4242, ItemGeneration: 1},
		path: "d/shared", attr: fsproto.Attr{Kind: "file"},
	})

	deliver := func() {
		release, token, eno := a.reserveSizeMutation(context.Background(), rec.item.ItemID)
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
	}

	first := a.watchRepairPublications(rec.item.ItemID)
	deliver()

	// A SECOND repair arms on the same item. It must start from zero without
	// erasing what the first has already been told.
	second := a.watchRepairPublications(rec.item.ItemID)
	if got := second.since(); got != 0 {
		t.Fatalf("a freshly armed second watcher already counted %d", got)
	}
	if got := first.since(); got != 1 {
		t.Fatalf("arming a second repair on the same item reset the first "+
			"repair's count to %d (want 1): the first repair loses a discharge it "+
			"had already earned and runs to its give-up path", got)
	}

	deliver()
	if got, want := first.since(), uint64(2); got != want {
		t.Fatalf("first watcher counted %d, want %d", got, want)
	}
	if got, want := second.since(), uint64(1); got != want {
		t.Fatalf("second watcher counted %d, want %d", got, want)
	}

	// And one watcher's stop must not take the other's state with it.
	second.stop()
	deliver()
	if got, want := first.since(), uint64(3); got != want {
		t.Fatalf("after a concurrent repair stopped, the surviving repair counted "+
			"%d, want %d: its witness was deleted out from under it and it can "+
			"never converge by publication again", got, want)
	}

	first.stop()
	a.mu.RLock()
	tracked := len(a.repairPublicationWatches)
	a.mu.RUnlock()
	if tracked != 0 {
		t.Fatalf("the last watcher's stop left %d entries behind", tracked)
	}
}

// TestRepairWitnessIgnoresPublicationsBeforeTheWatchArmed keeps the baseline
// honest in the direction the refcount opens up: an item whose generation is
// already nonzero (another repair has been running) must not hand a newly armed
// repair an instant, unearned discharge.
func TestRepairWitnessIgnoresPublicationsBeforeTheWatchArmed(t *testing.T) {
	a := newMetadataTestAttach()
	rec := a.bindTestRecord(&itemRecord{
		item: pfslocal.Item{ItemID: 4243, ItemGeneration: 1},
		path: "d/warm", attr: fsproto.Attr{Kind: "file"},
	})
	holder := a.watchRepairPublications(rec.item.ItemID)
	defer holder.stop()

	release, token, eno := a.reserveSizeMutation(context.Background(), rec.item.ItemID)
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

	late := a.watchRepairPublications(rec.item.ItemID)
	defer late.stop()
	if a.repairDischargedByPublication(late, 1, 1) {
		t.Fatal("a repair armed AFTER a publication was discharged by it: the " +
			"debt it owes was created by a crossing that happened later, and a " +
			"publication that predates the crossing proves nothing about it")
	}
	_ = time.Now()
}
