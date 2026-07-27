package pft2

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// wideName produces long names so leaves hold few entries and index levels
// appear at test-friendly sizes.
func wideName(i int) string {
	return fmt.Sprintf("entry-%06d-%s", i, strings.Repeat("q", 200))
}

// listAll drains a committed directory through the public reader.
func listAll(t *testing.T, store *MemoryStore, root Ref, dirIno uint64) []DirEntry {
	t.Helper()
	ctx := context.Background()
	reader, err := NewTreeReader(TreeReaderConfig{
		Fetcher: &countingFetcher{store: store},
		Bounds:  ReadBounds{MaxNodes: 1 << 20, MaxBytes: 1 << 62},
	}, root)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := reader.GetInode(ctx, dirIno)
	if err != nil {
		t.Fatal(err)
	}
	var out []DirEntry
	cursor := ""
	for {
		entries, next, err := reader.ReadDir(ctx, dir.Ref, cursor, 512)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, entries...)
		if next == "" {
			return out
		}
		cursor = next
	}
}

// walkTreeShapes recursively validates fanout by decoding every reachable
// node (DecodeNode re-validates all bounds) and reports counts by kind.
func walkTreeShapes(t *testing.T, store *MemoryStore, ref Ref, counts map[Kind]int) {
	t.Helper()
	data, err := store.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	node, err := DecodeNode(data)
	if err != nil {
		t.Fatal(err)
	}
	counts[node.Kind]++
	switch node.Kind {
	case KindDirectoryIndex:
		for _, child := range node.DirectoryIndex.Children {
			walkTreeShapes(t, store, child.Child, counts)
		}
	case KindInodeIndexIndex:
		for _, child := range node.InodeIndexIndex.Children {
			walkTreeShapes(t, store, child.Child, counts)
		}
	case KindExtentIndex:
		for _, child := range node.ExtentIndex.Children {
			walkTreeShapes(t, store, child.Child, counts)
		}
	}
}

func dirRootRef(t *testing.T, store *MemoryStore, root Ref, dirIno uint64) Ref {
	t.Helper()
	reader := readerAt(t, store, root)
	view, err := reader.GetInode(context.Background(), dirIno)
	if err != nil {
		t.Fatal(err)
	}
	// The public view strips roots; fetch the raw inode object instead.
	data, err := store.Fetch(context.Background(), view.Ref)
	if err != nil {
		t.Fatal(err)
	}
	node, err := DecodeNodeKind(data, KindInode)
	if err != nil {
		t.Fatal(err)
	}
	if node.Inode.DirectoryRoot == nil {
		t.Fatal("directory has no root")
	}
	return *node.Inode.DirectoryRoot
}

func TestEditorDirectorySplitAndCollapse(t *testing.T) {
	ctx := context.Background()
	// The fetch budget counts traversal VISITS (cached or not), so byte
	// budgets for many-edit transactions must scale with edits × node size.
	generous := EditorLimits{
		MaxEdits: 1 << 21, MaxFetchNodes: 1 << 21, MaxFetchBytes: 1 << 42,
		MaxNewObjects: 1 << 20, MaxNewObjectBytes: 1 << 31,
	}
	f := newEditorFixture(t, generous)

	// Split: 2000 long-named entries into /a (which has 2 short ones).
	const added = 2000
	for i := 0; i < added; i++ {
		ino := uint64(1000 + i)
		if err := f.editor.PutInode(ctx, Inode{Ino: ino, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
			t.Fatal(err)
		}
		if err := f.editor.PutDirEntry(ctx, 2, DirEntry{Name: wideName(i), Ino: ino, Kind: FileKindRegular}); err != nil {
			t.Fatal(err)
		}
	}
	result := f.commit(t)
	entries := listAll(t, f.store, result.Root, 2)
	if len(entries) != added+2 {
		t.Fatalf("directory holds %d entries", len(entries))
	}
	counts := map[Kind]int{}
	walkTreeShapes(t, f.store, dirRootRef(t, f.store, result.Root, 2), counts)
	if counts[KindDirectoryIndex] == 0 || counts[KindDirectoryLeaf] < 2 {
		t.Fatalf("expected a split tree, got %+v", counts)
	}
	if result.RootFacts.DirentCount != 5+added {
		t.Fatalf("dirent count %d", result.RootFacts.DirentCount)
	}

	// Determinism: an identical fresh transaction produces the same root.
	g := newEditorFixture(t, generous)
	for i := added - 1; i >= 0; i-- { // reverse staging order
		ino := uint64(1000 + i)
		if err := g.editor.PutInode(ctx, Inode{Ino: ino, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
			t.Fatal(err)
		}
		if err := g.editor.PutDirEntry(ctx, 2, DirEntry{Name: wideName(i), Ino: ino, Kind: FileKindRegular}); err != nil {
			t.Fatal(err)
		}
	}
	if g.commit(t).Root != result.Root {
		t.Fatal("identical edit sets committed different roots")
	}

	// Collapse: delete everything added; the tree returns to one leaf and
	// the shape equals the base tree exactly.
	f2 := newEditorFixtureAt(t, f.store, result.Root, nil, generous)
	for i := 0; i < added; i++ {
		if err := f2.editor.DeleteDirEntry(ctx, 2, wideName(i)); err != nil {
			t.Fatal(err)
		}
		if err := f2.editor.DeleteInode(ctx, uint64(1000+i)); err != nil {
			t.Fatal(err)
		}
	}
	result2 := f2.commit(t)
	back := listAll(t, f.store, result2.Root, 2)
	if len(back) != 2 || back[0].Name != "empty" || back[1].Name != "hello.bin" {
		t.Fatalf("collapsed directory: %+v", back)
	}
	counts2 := map[Kind]int{}
	walkTreeShapes(t, f.store, dirRootRef(t, f.store, result2.Root, 2), counts2)
	if counts2[KindDirectoryIndex] != 0 || counts2[KindDirectoryLeaf] != 1 {
		t.Fatalf("expected a single-leaf directory, got %+v", counts2)
	}
	if dirRootRef(t, f.store, result2.Root, 2) != dirRootRef(t, f.store, f.rootRef, 2) {
		t.Fatal("collapse did not reproduce the base leaf bytes")
	}
	if result2.RootFacts.DirentCount != 5 || result2.RootFacts.InodeCount != 6 {
		t.Fatalf("counters %+v", result2.RootFacts)
	}
}

func TestEditorIndexOverflowTailRebalance(t *testing.T) {
	if testing.Short() {
		t.Skip("large shape test")
	}
	ctx := context.Background()
	generous := EditorLimits{
		MaxEdits: 1 << 22, MaxFetchNodes: 1 << 22, MaxFetchBytes: 1 << 44,
		MaxNewObjects: 1 << 21, MaxNewObjectBytes: 1 << 32,
	}

	// Base: an empty-base filesystem whose root directory holds enough
	// long-named entries that its index level is near the 256-child bound;
	// a follow-up insert wave forces index re-chunking (tail rebalance).
	editor, err := NewEditor(ctx, nil, nil, generous)
	if err != nil {
		t.Fatal(err)
	}
	if err := editor.PutInode(ctx, Inode{Ino: 1, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	// ~300 entries per leaf at ~220-byte bodies; 70000 entries ≈ 235 leaves.
	const baseEntries = 70000
	if err := editor.PutInode(ctx, Inode{Ino: 2, Kind: FileKindRegular, Mode: 0o644, Nlink: uint64(baseEntries) + 8}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < baseEntries; i++ {
		if err := editor.PutDirEntry(ctx, 1, DirEntry{Name: wideName(i * 2), Ino: 2, Kind: FileKindRegular}); err != nil {
			t.Fatal(err)
		}
	}
	store := NewMemoryStore()
	sink := &countingSink{store: store}
	base, err := editor.Commit(ctx, sink, sink)
	if err != nil {
		t.Fatal(err)
	}
	baseCounts := map[Kind]int{}
	walkTreeShapes(t, store, dirRootRef(t, store, base.Root, 1), baseCounts)
	if baseCounts[KindDirectoryLeaf] < 200 {
		t.Fatalf("base shape too small for the overflow scenario: %+v", baseCounts)
	}

	// Insert interleaved names to split many leaves in one transaction,
	// pushing the child list past MaxIndexChildren.
	f := newEditorFixtureAt(t, store, base.Root, nil, generous)
	const wave = 30000
	for i := 0; i < wave; i++ {
		if err := f.editor.PutDirEntry(ctx, 1, DirEntry{Name: wideName(i*2 + 1), Ino: 2, Kind: FileKindRegular}); err != nil {
			t.Fatal(err)
		}
	}
	result := f.commit(t)
	entries := listAll(t, store, result.Root, 1)
	if len(entries) != baseEntries+wave {
		t.Fatalf("entry count %d", len(entries))
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name >= entries[i].Name {
			t.Fatal("entries out of order")
		}
	}
	// Every node revalidates on decode (fanout >= 2 enforced), and the tree
	// now has at least two index levels.
	counts := map[Kind]int{}
	walkTreeShapes(t, store, dirRootRef(t, store, result.Root, 1), counts)
	if counts[KindDirectoryIndex] < 3 {
		t.Fatalf("expected stacked index levels, got %+v", counts)
	}
	if result.RootFacts.DirentCount != baseEntries+wave {
		t.Fatalf("dirent count %d", result.RootFacts.DirentCount)
	}
}

func TestEditorInodeIndexGrowthAndCollapse(t *testing.T) {
	ctx := context.Background()
	generous := EditorLimits{
		MaxEdits: 1 << 21, MaxFetchNodes: 1 << 21, MaxFetchBytes: 1 << 42,
		MaxNewObjects: 1 << 20, MaxNewObjectBytes: 1 << 31,
	}
	f := newEditorFixture(t, generous)

	const added = 30000
	for i := 0; i < added; i++ {
		if err := f.editor.PutInode(ctx, Inode{
			Ino: uint64(10000 + i), Kind: FileKindRegular, Mode: 0o644, Nlink: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	result := f.commit(t)
	if result.RootFacts.InodeCount != 6+added || result.RootFacts.MaxInoSeen != uint64(10000+added-1) {
		t.Fatalf("facts %+v", result.RootFacts)
	}
	counts := map[Kind]int{}
	walkTreeShapes(t, f.store, result.RootFacts.InodeIndex, counts)
	if counts[KindInodeIndexIndex] == 0 || counts[KindInodeIndexLeaf] < 2 {
		t.Fatalf("expected a split inode index, got %+v", counts)
	}
	reader := readerAt(t, f.store, result.Root)
	if _, err := reader.GetInode(ctx, uint64(10000+added-1)); err != nil {
		t.Fatal(err)
	}

	// Collapse back to the base index bytes.
	f2 := newEditorFixtureAt(t, f.store, result.Root, nil, generous)
	for i := 0; i < added; i++ {
		if err := f2.editor.DeleteInode(ctx, uint64(10000+i)); err != nil {
			t.Fatal(err)
		}
	}
	result2 := f2.commit(t)
	if result2.RootFacts.InodeCount != 6 {
		t.Fatalf("inode count %d", result2.RootFacts.InodeCount)
	}
	baseData, err := f.store.Fetch(ctx, f.rootRef)
	if err != nil {
		t.Fatal(err)
	}
	baseRoot, err := DecodeNodeKind(baseData, KindRoot)
	if err != nil {
		t.Fatal(err)
	}
	if result2.RootFacts.InodeIndex != baseRoot.Root.InodeIndex {
		t.Fatal("inode index did not collapse back to the base bytes")
	}
}
