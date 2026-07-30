package clientcore

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func TestHardlinkIdentityRetainsNlinkOneAndUnsafeIsMonotonic(t *testing.T) {
	h := newHardlinkAliases()
	h.observe("a/source", fsproto.Attr{Ino: 42, Nlink: 1})

	if got := h.inosForPaths("a/source"); len(got) != 1 || got[0] != 42 {
		t.Fatalf("nlink-one identity=%v, want [42]", got)
	}
	if h.contains(42) {
		t.Fatal("nlink-one observation was prematurely alias-unsafe")
	}

	staleObservation := h.beginObservation()
	h.markAliasUnsafe([]uint64{42})
	staleObservation.Observe("a/source", fsproto.Attr{Ino: 42, Nlink: 1})
	staleObservation.Close()
	h.observe("b/alias", fsproto.Attr{Ino: 42, Nlink: 1}) // stale nlink value
	if !h.contains(42) || !h.containsPath("a/source") || !h.containsPath("b/alias") {
		t.Fatal("delayed nlink-one observation cleared alias-unsafe state")
	}
	if got := h.pathsForInos([]uint64{42}); len(got) != 2 {
		t.Fatalf("observed aliases=%v, want two paths", got)
	}

	// Unsafe identity is compact, permanent correctness state even after all
	// local spellings disappear. Reusing inode safety is conservative; inode
	// IDs are not recycled within one authority generation.
	h.removePath("a/source")
	h.removePath("b/alias")
	if len(h.byIno) != 0 || len(h.byPath) != 0 {
		t.Fatalf("path identity was not pruned: byIno=%d byPath=%d", len(h.byIno), len(h.byPath))
	}
	if !h.contains(42) || len(h.unsafe) != 1 {
		t.Fatalf("unsafe identity was lost or expanded: unsafe=%v", h.unsafe)
	}

	unseen := newHardlinkAliases()
	unseenObservation := unseen.beginObservation()
	unseen.markAliasUnsafe([]uint64{99})
	if len(unseen.unsafe) != 0 {
		t.Fatalf("unseen invalidation retained inode state: %v", unseen.unsafe)
	}
	unseenObservation.Observe("late", fsproto.Attr{Ino: 99, Nlink: 1})
	unseenObservation.Close()
	if !unseen.contains(99) {
		t.Fatal("delayed pre-invalidation observation was not alias-unsafe")
	}

	unrelated := newHardlinkAliases()
	unrelatedObservation := unrelated.beginObservation()
	unrelated.markAliasUnsafe([]uint64{100})
	unrelatedObservation.Observe("unrelated", fsproto.Attr{Ino: 101, Nlink: 1})
	unrelatedObservation.Close()
	if unrelated.contains(101) {
		t.Fatal("unrelated namespace invalidation disabled delegation")
	}
	if len(unrelated.pending) != 0 {
		t.Fatalf("completed observation retained pending identities: %v", unrelated.pending)
	}
}

func TestHardlinkIdentityObservationHasNoDuplicateGrowth(t *testing.T) {
	h := newHardlinkAliases()
	for i := 0; i < 10_000; i++ {
		h.observe("d/file", fsproto.Attr{Ino: 7, Nlink: 1})
	}
	if len(h.byIno) != 1 || len(h.byPath) != 1 || len(h.byIno[7].paths) != 1 {
		t.Fatalf(
			"duplicate observation grew index: byIno=%d byPath=%d paths=%d",
			len(h.byIno),
			len(h.byPath),
			len(h.byIno[7].paths),
		)
	}
}

func TestHardlinkIdentityNamespacePrunesStalePrefix(t *testing.T) {
	h := newHardlinkAliases()
	h.observe("tree", fsproto.Attr{Ino: 1, Nlink: 1})
	h.observe("tree/a", fsproto.Attr{Ino: 2, Nlink: 2})
	h.observe("tree/sub/b", fsproto.Attr{Ino: 3, Nlink: 1})
	h.observe("other", fsproto.Attr{Ino: 4, Nlink: 1})

	h.removePrefix("tree")
	if len(h.byPath) != 1 || h.byPath["other"] != 4 {
		t.Fatalf("prefix prune left stale identities: %v", h.byPath)
	}
	if !h.contains(2) {
		t.Fatal("prefix prune discarded permanent alias-unsafe fact")
	}
}

func TestHardlinkIdentityRenameOverDropsDestinationBindings(t *testing.T) {
	h := newHardlinkAliases()
	h.observe("old", fsproto.Attr{Kind: "directory", Ino: 1, Nlink: 2})
	h.observe("old/source", fsproto.Attr{Kind: "file", Ino: 2, Nlink: 1})
	h.observe("new", fsproto.Attr{Kind: "directory", Ino: 3, Nlink: 2})
	h.observe("new/replaced", fsproto.Attr{Kind: "file", Ino: 4, Nlink: 2})

	h.rekey("old", "new")

	if got := h.inosForPaths("new"); len(got) != 1 || got[0] != 1 {
		t.Fatalf("renamed root identity=%v, want [1]", got)
	}
	if got := h.inosForPaths("new/source"); len(got) != 1 || got[0] != 2 {
		t.Fatalf("renamed child identity=%v, want [2]", got)
	}
	if aliases := h.pathsForInos([]uint64{3, 4}); len(aliases) != 0 {
		t.Fatalf("replaced destination retained stale aliases: %v", aliases)
	}
	if !h.contains(4) {
		t.Fatal("rename-over discarded permanent destination unsafe fact")
	}
}
