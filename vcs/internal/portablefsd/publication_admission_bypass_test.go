package portablefsd

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// ── FINDING 4 (ROUND 11): ADMISSION BELONGS TO THE ASSIGNMENT ────────────────
//
// Publication admission sat at the registration ENTRY POINTS — registrations
// that resolve a NAME. Two assignments reach an itemRecord by another route and
// therefore bypassed it entirely:
//
//	(a) a DETACHED handle's attribute registration, which writes straight onto
//	    the canonical record and onto every retained alias by item identity;
//	(b) the hard-link publication path, which DOES call admission but whose
//	    production caller installed under no reincarnation owner and settled no
//	    ticket, so the debt it minted was unowned by construction.
//
// Both are now expressed the same way: admission is bound to
// publishRecordAttrLocked — the one place an itemRecord's attributes are ever
// assigned — and every admitting caller owns and settles its ticket.

// TestDetachedHandlePublicationIsAdmitted is (a).
//
// A getattr issued before a peer's rename-over and answered after the
// reconciliation that repaired the displaced inode's aliases would otherwise
// write the pre-reincarnation snapshot back over the repair. Permanently: its
// ticket was inert, so no fresh generation was ever minted and nothing was ever
// obliged to refresh it again.
func TestDetachedHandlePublicationIsAdmitted(t *testing.T) {
	a := &attach{
		items:          map[uint64]*itemRecord{},
		paths:          map[string]*itemRecord{},
		itemAliases:    map[uint64]map[string]struct{}{},
		authorityItems: map[uint64]frontendItemIdentity{},
		handles:        map[uint64]*handleRecord{},
	}
	const itemID = uint64(41)
	state := clientcore.NewNodeState(itemID, true)
	rec := a.bindTestRecord(&itemRecord{
		item:  pfslocal.Item{ItemID: itemID, ItemGeneration: 1},
		path:  "a",
		state: state,
		attr:  fsproto.Attr{Kind: "file", Size: 8, Nlink: 2, Ino: itemID},
	})
	alias := &itemRecord{
		item: rec.item, path: "b", state: state,
		attr: fsproto.Attr{Kind: "file", Size: 8, Nlink: 2, Ino: itemID},
	}
	a.mu.Lock()
	a.paths["b"] = alias
	a.addItemAliasLocked(alias)
	a.mu.Unlock()

	// The handle is DETACHED: its remembered open path no longer names this
	// inode, so registerHandleAttrLocked takes the identity arm.
	h := &handleRecord{
		id: 1, itemID: itemID, path: "a-was-renamed-away",
		openPath: "a", state: state, write: true,
	}

	// A reincarnation has left both retained names owing a refresh.
	a.mu.Lock()
	a.recordReincarnationDebtLocked("a")
	a.recordReincarnationDebtLocked("b")
	a.mu.Unlock()
	if !a.debtOutstanding("a") || !a.debtOutstanding("b") {
		t.Fatal("fixture: the retained names do not owe a reconciliation")
	}

	// A delayed handle getattr publishes the PRE-reincarnation snapshot.
	stale := fsproto.Attr{Kind: "file", Size: 8, Nlink: 2, Ino: itemID}
	a.mu.Lock()
	saved := a.beginReincarnationOwnerLocked(nil)
	got := a.registerHandleAttrLocked(h, stale)
	ticket := a.endReincarnationOwnerLocked(saved)
	a.mu.Unlock()
	if got == nil {
		t.Fatal("the detached handle's registration was refused; the fixture is wrong")
	}

	if !ticket.owes("b") {
		t.Fatal("a detached handle's attribute registration overwrote a retained " +
			"alias without publication admission: the pre-reincarnation snapshot is " +
			"now the newest thing the registry holds for that name, its ticket is " +
			"inert, no fresh generation was minted, and nothing will ever refresh it")
	}
	if !ticket.owes("a") {
		t.Fatal("the canonical record's own assignment was not admitted either")
	}
}

// TestHardLinkOwnsAndSettlesTheDebtItMints is (b).
//
// registerHardLinkAliasLocked calls admitPublicationLocked, and the production
// caller installed under no owner at all — so the debt it minted was recorded
// with nobody obliged to pay it, and an indebted reused name kept its
// pre-reincarnation snapshot beside a fresh identity for the life of the mount.
func TestHardLinkOwnsAndSettlesTheDebtItMints(t *testing.T) {
	a, vol, _, _ := newMutationSeqAttach(t)
	ctx := context.Background()

	dir, _ := a.registerOwned("d", fsproto.Attr{Kind: "dir", Mode: 0o755, Ino: 7000})
	if dir == nil {
		t.Fatal("register d")
	}
	a.mu.RLock()
	src := a.paths["d/f"]
	a.mu.RUnlock()
	if src == nil {
		t.Fatal("fixture: d/f is not registered")
	}

	// The destination name carries debt from an earlier reincarnation, which is
	// exactly the state a reused name is in.
	a.mu.Lock()
	a.recordReincarnationDebtLocked("d/link")
	a.mu.Unlock()
	if !a.debtOutstanding("d/link") {
		t.Fatal("fixture: the destination name does not owe a reconciliation")
	}

	reply, eno := a.hardLink(ctx, &pfslocal.HardLinkRequest{
		Item: src.item, Dir: dir.item, Name: []byte("link"),
	})
	if eno != 0 || reply == nil {
		t.Fatalf("hardLink: errno=%d", eno)
	}
	if a.debtOutstanding("d/link") {
		t.Fatal("link(2) minted reconciliation debt for the name it published and " +
			"settled none of it: the publication went out over an alias the daemon " +
			"itself had recorded as predating a reincarnation, and no later operation " +
			"is obliged to repair it")
	}
	_ = vol
}
