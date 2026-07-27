package pft2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// wideRootDirectory hand-builds a verification-consistent directory root
// index holding one leftmost subtree plus enough decoy leaves that a modest
// insert wave overflows the root splice and forces root stacking.
func wideRootDirectory(
	t *testing.T, store *MemoryStore, leftmost DirectoryIndexChild, decoys int,
) Ref {
	t.Helper()
	children := []DirectoryIndexChild{leftmost}
	for i := 0; i < decoys; i++ {
		name := fmt.Sprintf("zz-a-%03d", i)
		leaf := leafOfNames(t, store, name)
		children = append(children, DirectoryIndexChild{
			FirstName: name, LastName: name, Child: leaf, EntryCount: 1,
		})
	}
	return putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
		Children: children,
	}})
}

// waveName sorts above every base name in the wideRootDirectory fixtures.
func waveName(i int) string {
	return fmt.Sprintf("zz-b-%05d-%s", i, strings.Repeat("q", 200))
}

// stageRootSplitWave stages enough new entries in the root directory to
// overflow the root splice (the last decoy's leaf run splits into several
// leaves, pushing the spliced child list past MaxIndexChildren).
func stageRootSplitWave(t *testing.T, f *editorFixture, entries int) {
	t.Helper()
	ctx := context.Background()
	if err := f.editor.PutInode(ctx, Inode{Ino: 5, Kind: FileKindRegular, Mode: 0o644, Nlink: uint64(entries)}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < entries; i++ {
		if err := f.editor.PutDirEntry(ctx, RootIno, DirEntry{
			Name: waveName(i), Ino: 5, Kind: FileKindRegular,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestEditorRootSplitDepthRefusal pins gate E: a legal maximum-depth base
// whose root split would push unproven index subtrees past MaxTreeDepth
// must fail typed before anything is emitted, never commit an unreadable
// depth-13 tree.
func TestEditorRootSplitDepthRefusal(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	// Height-11 chain under the root index = legal height-12 tree.
	_, chainSummary := buildDeepDirectoryChain(t, store, MaxTreeDepth-1)
	dirRoot := wideRootDirectory(t, store, chainSummary, 254)
	rootRef, _ := singleDirFixture(t, store, &dirRoot)

	f := newEditorFixtureAt(t, store, rootRef, nil, EditorLimits{})
	stageRootSplitWave(t, f, 800)
	sink := &countingSink{store: store}
	_, err := f.editor.Commit(ctx, sink, sink)
	if !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("depth-13 root split must fail typed: %v", err)
	}
	if !strings.Contains(err.Error(), "max depth") {
		t.Fatalf("unexpected rejection: %v", err)
	}
	if sink.nodePuts+sink.packPuts != 0 {
		t.Fatalf("rejected root split leaked %d/%d staged objects", sink.nodePuts, sink.packPuts)
	}
}

// TestEditorRootSplitShallowBaseSucceeds is the positive control: the same
// overflow wave over a two-level base succeeds because every sinking child
// is proven a leaf by the single-fetch resolution pass, and stacking starts
// from real leaf heights.
func TestEditorRootSplitShallowBaseSucceeds(t *testing.T) {
	store := NewMemoryStore()
	leftLeaf := leafOfNames(t, store, "aa")
	leftmost := DirectoryIndexChild{FirstName: "aa", LastName: "aa", Child: leftLeaf, EntryCount: 1}
	dirRoot := wideRootDirectory(t, store, leftmost, 254)
	rootRef, _ := singleDirFixture(t, store, &dirRoot)

	f := newEditorFixtureAt(t, store, rootRef, nil, EditorLimits{})
	stageRootSplitWave(t, f, 800)
	result := f.commit(t)

	entries := listAll(t, store, result.Root, RootIno)
	if len(entries) != 1+254+800 {
		t.Fatalf("entry count %d", len(entries))
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name >= entries[i].Name {
			t.Fatal("entries out of order after root split")
		}
	}
	counts := map[Kind]int{}
	walkTreeShapes(t, store, dirRootRef(t, store, result.Root, RootIno), counts)
	if counts[KindDirectoryIndex] < 3 {
		t.Fatalf("expected stacked index levels, got %+v", counts)
	}
}

// TestEditorDeepChainCollapse deletes the deepest entry of a legal deep
// chain: collapses propagate to the root, the result stays readable, and
// every fetched edge on the routed path verified.
func TestEditorDeepChainCollapse(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	chainRoot, _ := buildDeepDirectoryChain(t, store, 6)
	rootRef, _ := singleDirFixture(t, store, &chainRoot)

	f := newEditorFixtureAt(t, store, rootRef, nil, EditorLimits{})
	if err := f.editor.DeleteDirEntry(ctx, RootIno, "aa"); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)

	entries := listAll(t, store, result.Root, RootIno)
	want := []string{"zz-02", "zz-03", "zz-04", "zz-05", "zz-06"}
	if len(entries) != len(want) {
		t.Fatalf("entries after collapse: %+v", entries)
	}
	for i, name := range want {
		if entries[i].Name != name {
			t.Fatalf("entry %d = %q, want %q", i, entries[i].Name, name)
		}
	}
}
