package portablefsd

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// ── FINDINGS 3 AND 4: THE DEBT ONLY BOUND THE PUBLISHER THAT MINTED IT ───────
//
// A reincarnation debt says "this alias's retained attributes predate a
// replacement". Round 9 made the publisher that DISCOVERED the replacement pay
// it before its own reply left, which is necessary and was not sufficient:
//
//	FINDING 3  nothing stopped a DIFFERENT publisher from publishing the
//	           indebted alias in the meantime. Publisher A records the debt and
//	           releases a.mu to go and restat; publisher B answers getattr(b)
//	           from the pre-reincarnation cache, mints an INERT ticket because it
//	           displaced nothing, and exposes the stale snapshot. A's later
//	           registry install has no ordering relationship to B's reply at all.
//	FINDING 4  a REJECTED install was counted as a payment. The settle recorded
//	           success from `eno == 0` — the RPC having succeeded — and threw
//	           away InstallOK's verdict, so a refusal advanced doneGen, deleted
//	           the debt, and left the pre-reincarnation snapshot in the registry
//	           permanently.

// newDebtAttach is a daemon attach with no authority, which is all the
// admission half of these findings needs: it is about what happens under a.mu,
// before anybody goes anywhere.
func newDebtAttach(t *testing.T, name string) *attach {
	t.Helper()
	a := newAttach("att_"+name, "key", ensureAttachRequest{
		VolumeID: "vol-" + name, Branch: "main",
		MountPath: "/Volumes/" + name, AuthorityURL: "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
	}, privateTestDir(t))
	a.identityEpoch = 11
	return a
}

// TestPublishingAnIndebtedAliasIsAdmittedNotWavedThrough is finding 3 as an A/B
// publisher race, run in the order that made it invisible: A opens the debt and
// is still away restating when B publishes.
//
// B displaced nothing, so it used to receive an inert ticket, settle instantly,
// and expose the pre-reincarnation attributes it read on the way in. The reply
// carried the replacement's identity beside the displaced inode's stale link
// count — the impossible pair the whole mechanism exists to prevent, published
// by the one publisher nothing was watching.
func TestPublishingAnIndebtedAliasIsAdmittedNotWavedThrough(t *testing.T) {
	a := newDebtAttach(t, "PublicationAdmission")
	a.registerLocked("a", fsproto.Attr{Ino: 81, Kind: "file", Nlink: 2, Size: 10})
	a.registerLocked("b", fsproto.Attr{Ino: 81, Kind: "file", Nlink: 2, Size: 10})

	// PUBLISHER A: a peer replaced "a", which displaces inode 81 and leaves "b"
	// carrying a pre-replacement snapshot.
	_, ticketA := a.registerOwned("a", fsproto.Attr{Ino: 181, Kind: "file", Nlink: 1})
	if ticketA == nil || !ticketA.owes("b") {
		t.Fatalf("the reincarnating registration did not own its retained alias: %+v", ticketA)
	}
	if !a.debtOutstanding("b") {
		t.Fatal("no debt was recorded for the retained alias")
	}

	// PUBLISHER B, while A is still away restating: an ordinary getattr(b) that
	// displaces nothing at all.
	_, ticketB := a.registerOwned("b", fsproto.Attr{Ino: 81, Kind: "file", Nlink: 2, Size: 10})
	if ticketB == nil {
		t.Fatal("a publisher of an alias with outstanding reconciliation debt was " +
			"given an inert ticket: it settles instantly and exposes the exact " +
			"pre-reincarnation snapshot the debt exists to retire, with no ordering " +
			"against the reconciliation that is running right now")
	}
	if !ticketB.owes("b") {
		t.Fatalf("publisher B's ticket does not carry the alias it is publishing: %+v", ticketB)
	}

	// And it must be a STRICTLY NEWER generation than the one already in flight.
	// Joining the outstanding one is not enough: a runner that finished between
	// B's read and B's registration would satisfy the joined generation with a
	// refresh taken BEFORE B wrote its stale value, and B would then re-read its
	// own stale write and call it reconciled.
	a.mu.RLock()
	st := a.reincarnatedAliases["b"]
	need, done := st.needGen, st.doneGen
	a.mu.RUnlock()
	if need < 2 {
		t.Fatalf("publishing over an indebted alias did not mint a fresh generation "+
			"(needGen=%d doneGen=%d): the reconciliation B waits for may be one that "+
			"completed before B's own registration", need, done)
	}
}

// TestReconciliationInstallDoesNotMintDebtAgainstItself is the termination proof
// for the rule above. The reconciliation pays the debt by REGISTERING the alias
// it just restated, and that registration is a publication of an alias whose
// debt is — at that instant, before doneGen advances — still outstanding. Left
// unexempted it would bump the requirement it is in the middle of satisfying,
// and the alias would never converge.
func TestReconciliationInstallDoesNotMintDebtAgainstItself(t *testing.T) {
	a := newDebtAttach(t, "ReconcileTermination")
	a.registerLocked("a", fsproto.Attr{Ino: 91, Kind: "file", Nlink: 2})
	a.registerLocked("b", fsproto.Attr{Ino: 91, Kind: "file", Nlink: 2})
	_, ticket := a.registerOwned("a", fsproto.Attr{Ino: 191, Kind: "file", Nlink: 1})
	if ticket == nil || !ticket.owes("b") {
		t.Fatalf("the reincarnating registration did not own its retained alias: %+v", ticket)
	}
	a.mu.RLock()
	before := a.reincarnatedAliases["b"].needGen
	a.mu.RUnlock()

	// The reconciliation's own install, armed exactly as settleAliasDebt arms it.
	a.mu.Lock()
	saved := a.beginReincarnationSettleLocked(ticket)
	a.registerLocked("b", fsproto.Attr{Ino: 91, Kind: "file", Nlink: 1})
	a.endReincarnationOwnerLocked(saved)
	after := a.reincarnatedAliases["b"].needGen
	a.mu.Unlock()

	if after != before {
		t.Fatalf("the reconciliation's own install minted fresh debt for the alias "+
			"it was paying (needGen %d -> %d): every payment would create a new "+
			"obligation and the alias could never converge", before, after)
	}

	// And the exemption is scoped to that one install: an ordinary publisher
	// arriving immediately afterwards is admitted as before.
	_, other := a.registerOwned("b", fsproto.Attr{Ino: 91, Kind: "file", Nlink: 1})
	if other == nil || !other.owes("b") {
		t.Fatal("the settling exemption leaked past the reconciliation's own install")
	}
}

// TestRecordingDebtRetiresTheCachedObservationAtomically is the other half of
// finding 3, and it is the half that decides whether the admission above is
// reachable at all.
//
// The eviction used to live in settleAliasDebt, which runs with a.mu RELEASED.
// So between "the debt is open" and "the stale entry is gone" there was a real
// window, and a competing publisher's getattr in that window got a CACHE HIT:
// no authority round trip, no observation to gate, nothing for any admission
// check to look at. Opening the debt and retiring the observation it describes
// have to be one event.
func TestRecordingDebtRetiresTheCachedObservationAtomically(t *testing.T) {
	authority, _ := serveAuthorityServer(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr: authority, Pool: 2, Owner: "debt-cache-holder",
		WALDir: privateTestDir(t), VolumeID: "debt-cache-volume",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vol.Close() })

	a := newDebtAttach(t, "DebtCacheEviction")
	a.vol = vol
	a.registerLocked("c", fsproto.Attr{Ino: 82, Kind: "file", Nlink: 2})
	a.registerLocked("d", fsproto.Attr{Ino: 82, Kind: "file", Nlink: 2})

	gen := vol.VersionCache.CurrentGen()
	stale := fsproto.Attr{Ino: 82, Kind: "file", Nlink: 2, Size: 10}
	vol.AttrCache.PutAttr(gen, 1, "d", stale)
	if _, ok := vol.AttrCache.Get(gen, 1, "d"); !ok {
		t.Fatal("the fixture did not seed the cached observation it is about to retire")
	}

	a.mu.Lock()
	a.recordReincarnationDebtLocked("d")
	// STILL UNDER a.mu. This is the whole assertion: there is no instant at
	// which the debt is open and the observation it describes is still
	// reachable, because a competing publisher takes a.mu to register and would
	// otherwise have read the cache before ever reaching it.
	_, reachable := vol.AttrCache.Get(gen, 1, "d")
	a.mu.Unlock()
	if reachable {
		t.Fatal("opening a reincarnation debt left the pre-reincarnation attributes " +
			"reachable in the cache: a competing publisher's getattr answers from " +
			"them without any authority round trip, and publishes the snapshot the " +
			"debt was opened to retire")
	}
}

// TestRejectedInstallLeavesTheDebtOutstanding is finding 4.
//
// InstallOK's verdict was discarded and the debt was settled from `eno == 0`,
// which says only that the RPC succeeded. PublishOKToken refuses for four
// reasons and only one of them is even arguably "something newer already
// installed this" — and that one is about the VERSION CACHE, not about the
// daemon registry the debt is a statement about. A generation epoch moving
// WIPES every retained version, so strictly less is known than before; a
// delegation ownership fence publishes nothing at all.
//
// The refusal modelled here is the ownership fence, wedged between the
// reconciliation's authority reply and its install — the exact interleaving a
// delegation handoff produces, and one that proves nothing whatsoever about
// itemRecord.attr. The debt must survive it.
func TestRejectedInstallLeavesTheDebtOutstanding(t *testing.T) {
	authority, _ := serveAuthorityServer(t)
	ctx := context.Background()
	vol, err := clientcore.Dial(ctx, clientcore.Options{
		Addr: authority, Pool: 2, Owner: "rejected-install-holder",
		WALDir: privateTestDir(t), VolumeID: "rejected-install-volume",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vol.Close() })
	if _, st := vol.Create(ctx, "f", 0o644); st != fsproto.OK {
		t.Fatalf("create f: %d", st)
	}
	attr, st := vol.Getattr(ctx, "f", nil)
	if st != fsproto.OK {
		t.Fatalf("getattr f: %d", st)
	}

	a := newDebtAttach(t, "RejectedInstall")
	a.vol = vol
	a.registerLocked("e", fsproto.Attr{Ino: attr.Ino, Kind: "file", Nlink: 2})
	a.registerLocked("f", fsproto.Attr{Ino: attr.Ino, Kind: "file", Nlink: 2})
	_, ticket := a.registerOwned("e", fsproto.Attr{Ino: attr.Ino + 100, Kind: "file", Nlink: 1})
	if ticket == nil || !ticket.owes("f") {
		t.Fatalf("the reincarnating registration did not own its retained alias: %+v", ticket)
	}
	before := registryAttrOf(t, a, "f")

	// The wedge: an ownership boundary lands after the reconciliation's read
	// began, so its token can no longer publish and InstallOK refuses. This
	// seam is where settleAliasDebt calls back after its authority round trip.
	var fences int
	a.testLookupAfterVolume = func(alias string) {
		if alias == "f" {
			fences++
			vol.VersionCache.FencePrefix("f")
		}
	}

	eno, reconciled := ticket.settle(ctx, vol)
	if !reconciled {
		t.Fatal("a ticket that owned an obligation reported settling nothing")
	}
	if fences < 2 {
		t.Fatalf("the settle made %d attempt(s) against a refused install: a refusal "+
			"must be resampled with a fresh token, not accepted as a payment", fences)
	}
	if eno == 0 {
		t.Fatal("a settle whose install was refused every time reported success: " +
			"the alias keeps its pre-reincarnation attributes and the publisher " +
			"goes on to expose the replacement beside them")
	}
	if !a.debtOutstanding("f") {
		t.Fatal("a REFUSED install discharged the debt: nothing proved the newer " +
			"attributes reached the daemon registry, and the stale alias is now " +
			"permanent because the obligation that would have retried it is gone")
	}
	if after := registryAttrOf(t, a, "f"); after != before {
		t.Fatalf("the registry moved on a refused install: %+v -> %+v", before, after)
	}

	// And the refusal is bounded, not a spin: once installs are accepted again
	// the very next settle discharges the debt.
	a.testLookupAfterVolume = nil
	if eno, _ := ticket.settle(ctx, vol); eno != 0 {
		t.Fatalf("the debt could not be settled after the fence stopped moving: errno=%d", eno)
	}
	if a.debtOutstanding("f") {
		t.Fatal("an accepted install left the debt outstanding")
	}
}

func registryAttrOf(t *testing.T, a *attach, p string) fsproto.Attr {
	t.Helper()
	a.mu.RLock()
	defer a.mu.RUnlock()
	rec := a.paths[p]
	if rec == nil {
		t.Fatalf("no registry record for %q", p)
	}
	return rec.attr
}
