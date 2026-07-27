package pft2

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// putRawNode encodes and stores one hand-built node.
func putRawNode(t *testing.T, store *MemoryStore, node *Node) Ref {
	t.Helper()
	encoded, err := EncodeNode(node)
	if err != nil {
		t.Fatal(err)
	}
	ref := RefOf(encoded)
	if err := store.PutNode(ref, encoded); err != nil {
		t.Fatal(err)
	}
	return ref
}

// buildDeepDirectoryChain builds a verification-consistent directory chain of
// the requested height: every index level holds the chain child plus a decoy
// leaf, and every advertised summary equals the child's true first/last/
// count, so only depth bounds or genuine corruption can stop a walk. It
// returns the top reference and its true summary.
func buildDeepDirectoryChain(t *testing.T, store *MemoryStore, height int) (Ref, DirectoryIndexChild) {
	t.Helper()
	leaf := &DirectoryLeaf{Entries: []DirEntry{{Name: "aa", Ino: 2, Kind: FileKindRegular}}}
	ref := putRawNode(t, store, &Node{Kind: KindDirectoryLeaf, DirectoryLeaf: leaf})
	summary := DirectoryIndexChild{FirstName: "aa", LastName: "aa", Child: ref, EntryCount: 1}
	for level := 2; level <= height; level++ {
		decoyName := fmt.Sprintf("zz-%02d", level)
		decoyLeaf := &DirectoryLeaf{Entries: []DirEntry{{Name: decoyName, Ino: 3, Kind: FileKindRegular}}}
		decoyRef := putRawNode(t, store, &Node{Kind: KindDirectoryLeaf, DirectoryLeaf: decoyLeaf})
		index := &DirectoryIndex{Children: []DirectoryIndexChild{
			summary,
			{FirstName: decoyName, LastName: decoyName, Child: decoyRef, EntryCount: 1},
		}}
		ref = putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: index})
		summary = DirectoryIndexChild{
			FirstName:  summary.FirstName,
			LastName:   decoyName,
			Child:      ref,
			EntryCount: summary.EntryCount + 1,
		}
	}
	return ref, summary
}

// singleDirFixture wires a hand-built directory tree into a minimal
// filesystem: root inode 1 is a directory whose tree root is dirRoot, and
// the ROOT facts carry the tree's advertised dirent count.
func singleDirFixture(t *testing.T, store *MemoryStore, dirRoot *Ref) (Ref, Ref) {
	t.Helper()
	inodeRef := putRawNode(t, store, &Node{Kind: KindInode, Inode: &Inode{
		Ino: 1, Kind: FileKindDirectory, Nlink: 1, DirectoryRoot: dirRoot,
	}})
	indexRoot, _, err := BuildInodeIndexTree([]InodeIndexEntry{{Ino: 1, Inode: inodeRef}}, store)
	if err != nil {
		t.Fatal(err)
	}
	var direntCount uint64
	if dirRoot != nil {
		data, err := store.Fetch(context.Background(), *dirRoot)
		if err != nil {
			t.Fatal(err)
		}
		node, err := DecodeNode(data)
		if err != nil {
			t.Fatal(err)
		}
		summary, err := nodeSummary(node)
		if err != nil {
			t.Fatal(err)
		}
		direntCount = summary.count
	}
	rootRef := putRawNode(t, store, &Node{Kind: KindRoot, Root: &Root{
		RootInode: inodeRef, InodeIndex: *indexRoot, MaxInoSeen: 1, InodeCount: 1,
		DirentCount: direntCount,
	}})
	return rootRef, inodeRef
}

func readerOver(t *testing.T, store *MemoryStore, root Ref) *TreeReader {
	t.Helper()
	reader, err := NewTreeReader(TreeReaderConfig{
		Fetcher: &countingFetcher{store: store},
		Bounds:  ReadBounds{MaxNodes: 1 << 16, MaxBytes: 1 << 40},
	}, root)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

// leafOfNames builds one directory leaf holding the given sorted names.
func leafOfNames(t *testing.T, store *MemoryStore, names ...string) Ref {
	t.Helper()
	entries := make([]DirEntry, len(names))
	for i, name := range names {
		entries[i] = DirEntry{Name: name, Ino: uint64(10 + i), Kind: FileKindRegular}
	}
	return putRawNode(t, store, &Node{Kind: KindDirectoryLeaf, DirectoryLeaf: &DirectoryLeaf{Entries: entries}})
}

// TestCorruptDirectoryEdges drives Lookup and ReadDir over crafted
// digest-correct directory graphs whose parent advertisements lie about
// their children. Every lie must fail closed with ErrCorrupt on the first
// walk that fetches the lying edge.
func TestCorruptDirectoryEdges(t *testing.T) {
	ctx := context.Background()

	type liar struct {
		name  string
		build func(t *testing.T, store *MemoryStore) Ref // returns the directory tree root
		// lookup that must route through the lying edge
		lookup string
	}
	cases := []liar{
		{
			name: "false entry count",
			build: func(t *testing.T, store *MemoryStore) Ref {
				left := leafOfNames(t, store, "aa", "ab")
				right := leafOfNames(t, store, "mm")
				return putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
					Children: []DirectoryIndexChild{
						{FirstName: "aa", LastName: "ab", Child: left, EntryCount: 3}, // actual 2
						{FirstName: "mm", LastName: "mm", Child: right, EntryCount: 1},
					},
				}})
			},
			lookup: "aa",
		},
		{
			name: "false first key",
			build: func(t *testing.T, store *MemoryStore) Ref {
				left := leafOfNames(t, store, "ab") // actual first "ab"
				right := leafOfNames(t, store, "mm")
				return putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
					Children: []DirectoryIndexChild{
						{FirstName: "aa", LastName: "ab", Child: left, EntryCount: 1},
						{FirstName: "mm", LastName: "mm", Child: right, EntryCount: 1},
					},
				}})
			},
			lookup: "aa",
		},
		{
			name: "hidden entries beyond advertised last",
			build: func(t *testing.T, store *MemoryStore) Ref {
				left := leafOfNames(t, store, "aa", "ab", "zz") // "zz" hidden by the advertisement
				right := leafOfNames(t, store, "mm")
				return putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
					Children: []DirectoryIndexChild{
						{FirstName: "aa", LastName: "ab", Child: left, EntryCount: 2},
						{FirstName: "mm", LastName: "mm", Child: right, EntryCount: 1},
					},
				}})
			},
			lookup: "aa",
		},
		{
			name: "duplicate entries across disjoint ranges",
			build: func(t *testing.T, store *MemoryStore) Ref {
				left := leafOfNames(t, store, "aa", "ab")
				right := leafOfNames(t, store, "ab", "mm") // "ab" duplicated, outside advertised range
				return putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
					Children: []DirectoryIndexChild{
						{FirstName: "aa", LastName: "ab", Child: left, EntryCount: 2},
						{FirstName: "mm", LastName: "mm", Child: right, EntryCount: 2},
					},
				}})
			},
			lookup: "mm",
		},
		{
			name: "misordered subtree behind a lying range",
			build: func(t *testing.T, store *MemoryStore) Ref {
				// The child advertises [aa..cc] but actually holds [nn..zz]:
				// under an unverified reader this loops or skips cursors.
				left := leafOfNames(t, store, "nn", "zz")
				right := leafOfNames(t, store, "dd")
				return putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
					Children: []DirectoryIndexChild{
						{FirstName: "aa", LastName: "cc", Child: left, EntryCount: 2},
						{FirstName: "dd", LastName: "dd", Child: right, EntryCount: 1},
					},
				}})
			},
			lookup: "aa",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryStore()
			dirRoot := tc.build(t, store)
			rootRef, inodeRef := singleDirFixture(t, store, &dirRoot)
			reader := readerOver(t, store, rootRef)

			if _, err := reader.Lookup(ctx, inodeRef, tc.lookup); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("lookup through lying edge: %v", err)
			}
			// Full enumeration must fail closed too, never emit lied entries.
			if _, _, err := reader.ReadDir(ctx, inodeRef, "", 1024); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("readdir over lying edge: %v", err)
			}
		})
	}
}

// TestCorruptDirectoryMixedChildKind routes a directory edge into an
// inode-index leaf: the family kind check must fail closed.
func TestCorruptDirectoryMixedChildKind(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	inodeLeafRef := putRawNode(t, store, &Node{Kind: KindInodeIndexLeaf, InodeIndexLeaf: &InodeIndexLeaf{
		Entries: []InodeIndexEntry{{Ino: 5, Inode: labelRef("any", 100)}},
	}})
	right := leafOfNames(t, store, "mm")
	dirRoot := putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
		Children: []DirectoryIndexChild{
			{FirstName: "aa", LastName: "ab", Child: inodeLeafRef, EntryCount: 1},
			{FirstName: "mm", LastName: "mm", Child: right, EntryCount: 1},
		},
	}})
	rootRef, inodeRef := singleDirFixture(t, store, &dirRoot)
	reader := readerOver(t, store, rootRef)
	if _, err := reader.Lookup(ctx, inodeRef, "aa"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mixed child kind: %v", err)
	}
}

// TestCorruptReadDirCursorLie pins the paging behavior: a child whose
// advertised range extends above its true content would make cursor paging
// revisit the same entries forever; verification stops the first page.
func TestCorruptReadDirCursorLie(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	// Child advertises [aa..zz] but actually holds only [aa..ab]: after one
	// page with cursor "ab" the walk would re-enter this child forever
	// (advertised last "zz" > cursor), re-emitting aa/ab under an
	// unverified reader.
	left := leafOfNames(t, store, "aa", "ab")
	right := leafOfNames(t, store, "zz")
	dirRoot := putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
		Children: []DirectoryIndexChild{
			{FirstName: "aa", LastName: "yy", Child: left, EntryCount: 2},
			{FirstName: "zz", LastName: "zz", Child: right, EntryCount: 1},
		},
	}})
	rootRef, inodeRef := singleDirFixture(t, store, &dirRoot)
	reader := readerOver(t, store, rootRef)
	if _, _, err := reader.ReadDir(ctx, inodeRef, "", 2); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cursor lie: %v", err)
	}
}

// TestCorruptExtentEdges covers extent-tree lies: hidden pages read as holes
// and overlapping/duplicated pages, both failing closed when fetched.
func TestCorruptExtentEdges(t *testing.T) {
	ctx := context.Background()

	buildFile := func(t *testing.T, store *MemoryStore, extentRoot Ref, size uint64) (Ref, Ref) {
		t.Helper()
		inodeRef := putRawNode(t, store, &Node{Kind: KindInode, Inode: &Inode{
			Ino: 2, Kind: FileKindRegular, Nlink: 1, Size: size, ExtentRoot: &extentRoot,
		}})
		rootInodeRef := putRawNode(t, store, &Node{Kind: KindInode, Inode: &Inode{
			Ino: 1, Kind: FileKindDirectory, Nlink: 1,
		}})
		indexRoot, _, err := BuildInodeIndexTree([]InodeIndexEntry{
			{Ino: 1, Inode: rootInodeRef}, {Ino: 2, Inode: inodeRef},
		}, store)
		if err != nil {
			t.Fatal(err)
		}
		rootRef := putRawNode(t, store, &Node{Kind: KindRoot, Root: &Root{
			RootInode: rootInodeRef, InodeIndex: *indexRoot, MaxInoSeen: 2, InodeCount: 2, LogicalBytes: size,
		}})
		return rootRef, inodeRef
	}

	pageNode := func(t *testing.T, store *MemoryStore, fill byte) Ref {
		t.Helper()
		cell := make([]byte, CellBytes)
		cell[0] = fill
		packer := NewCellPacker()
		if _, err := packer.Add(cell); err != nil {
			t.Fatal(err)
		}
		cells, err := packer.Finish(store)
		if err != nil {
			t.Fatal(err)
		}
		page := &DataPage{}
		page.Cells[0] = &cells[0]
		return putRawNode(t, store, &Node{Kind: KindDataPage, DataPage: page})
	}

	t.Run("read hole from hidden pages", func(t *testing.T) {
		store := NewMemoryStore()
		page0 := pageNode(t, store, 1)
		page1 := pageNode(t, store, 2)
		page4 := pageNode(t, store, 3)
		// Left leaf actually holds pages 0 and 1 but the parent advertises
		// only page 0 (count 1, last 0): page 1 would silently read as a
		// hole under an unverified reader.
		left := putRawNode(t, store, &Node{Kind: KindExtentLeaf, ExtentLeaf: &ExtentLeaf{
			Entries: []ExtentEntry{{PageOffset: 0, Page: page0}, {PageOffset: PageBytes, Page: page1}},
		}})
		right := putRawNode(t, store, &Node{Kind: KindExtentLeaf, ExtentLeaf: &ExtentLeaf{
			Entries: []ExtentEntry{{PageOffset: 4 * PageBytes, Page: page4}},
		}})
		extentRoot := putRawNode(t, store, &Node{Kind: KindExtentIndex, ExtentIndex: &ExtentIndex{
			Children: []ExtentIndexChild{
				{FirstPage: 0, LastPage: 0, Child: left, EntryCount: 1},
				{FirstPage: 4 * PageBytes, LastPage: 4 * PageBytes, Child: right, EntryCount: 1},
			},
		}})
		rootRef, fileRef := buildFile(t, store, extentRoot, 5*PageBytes)
		reader := readerOver(t, store, rootRef)
		if _, err := reader.ReadExtents(ctx, fileRef, 0, 5*PageBytes); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("hidden extent pages: %v", err)
		}
	})

	t.Run("duplicated page outside advertised range", func(t *testing.T) {
		store := NewMemoryStore()
		page0 := pageNode(t, store, 1)
		page4 := pageNode(t, store, 3)
		left := putRawNode(t, store, &Node{Kind: KindExtentLeaf, ExtentLeaf: &ExtentLeaf{
			Entries: []ExtentEntry{{PageOffset: 0, Page: page0}},
		}})
		// Right leaf duplicates page 0 although its advertised (and
		// node-valid: two pages fit the two-page range) span starts at
		// page 4.
		right := putRawNode(t, store, &Node{Kind: KindExtentLeaf, ExtentLeaf: &ExtentLeaf{
			Entries: []ExtentEntry{{PageOffset: 0, Page: page0}, {PageOffset: 4 * PageBytes, Page: page4}},
		}})
		extentRoot := putRawNode(t, store, &Node{Kind: KindExtentIndex, ExtentIndex: &ExtentIndex{
			Children: []ExtentIndexChild{
				{FirstPage: 0, LastPage: 0, Child: left, EntryCount: 1},
				{FirstPage: 4 * PageBytes, LastPage: 5 * PageBytes, Child: right, EntryCount: 2},
			},
		}})
		rootRef, fileRef := buildFile(t, store, extentRoot, 6*PageBytes)
		reader := readerOver(t, store, rootRef)
		if _, err := reader.ReadExtents(ctx, fileRef, 0, 6*PageBytes); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("duplicated extent page: %v", err)
		}
	})
}

// TestCorruptInodeIndexEdges covers inode-index lies plus root-fact pinning.
func TestCorruptInodeIndexEdges(t *testing.T) {
	ctx := context.Background()

	inodeNode := func(t *testing.T, store *MemoryStore, ino uint64) Ref {
		t.Helper()
		kind := FileKindRegular
		if ino == RootIno {
			kind = FileKindDirectory
		}
		return putRawNode(t, store, &Node{Kind: KindInode, Inode: &Inode{Ino: ino, Kind: kind, Nlink: 1}})
	}

	t.Run("leaf outside advertised ino range", func(t *testing.T) {
		store := NewMemoryStore()
		leftLeaf := putRawNode(t, store, &Node{Kind: KindInodeIndexLeaf, InodeIndexLeaf: &InodeIndexLeaf{
			Entries: []InodeIndexEntry{
				{Ino: 1, Inode: inodeNode(t, store, 1)},
				{Ino: 9, Inode: inodeNode(t, store, 9)}, // beyond advertised last 5
			},
		}})
		rightLeaf := putRawNode(t, store, &Node{Kind: KindInodeIndexLeaf, InodeIndexLeaf: &InodeIndexLeaf{
			Entries: []InodeIndexEntry{{Ino: 20, Inode: inodeNode(t, store, 20)}},
		}})
		indexRoot := putRawNode(t, store, &Node{Kind: KindInodeIndexIndex, InodeIndexIndex: &InodeIndexIndex{
			Children: []InodeIndexChild{
				{FirstIno: 1, LastIno: 5, Child: leftLeaf, EntryCount: 2},
				{FirstIno: 20, LastIno: 20, Child: rightLeaf, EntryCount: 1},
			},
		}})
		rootRef := putRawNode(t, store, &Node{Kind: KindRoot, Root: &Root{
			RootInode: inodeNode(t, store, 1), InodeIndex: indexRoot, MaxInoSeen: 20, InodeCount: 3,
		}})
		reader := readerOver(t, store, rootRef)
		if _, err := reader.GetInode(ctx, 1); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("ino range lie: %v", err)
		}
	})

	t.Run("root inode count mismatch", func(t *testing.T) {
		store := NewMemoryStore()
		rootInode := inodeNode(t, store, 1)
		indexRoot, _, err := BuildInodeIndexTree([]InodeIndexEntry{
			{Ino: 1, Inode: rootInode},
			{Ino: 2, Inode: inodeNode(t, store, 2)},
		}, store)
		if err != nil {
			t.Fatal(err)
		}
		rootRef := putRawNode(t, store, &Node{Kind: KindRoot, Root: &Root{
			RootInode: rootInode, InodeIndex: *indexRoot, MaxInoSeen: 2, InodeCount: 1, // actual 2
		}})
		reader := readerOver(t, store, rootRef)
		if _, err := reader.GetInode(ctx, 1); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("inode count lie: %v", err)
		}
	})

	t.Run("index holds ino beyond max_ino_seen", func(t *testing.T) {
		store := NewMemoryStore()
		rootInode := inodeNode(t, store, 1)
		indexRoot, _, err := BuildInodeIndexTree([]InodeIndexEntry{
			{Ino: 1, Inode: rootInode},
			{Ino: 9, Inode: inodeNode(t, store, 9)},
		}, store)
		if err != nil {
			t.Fatal(err)
		}
		rootRef := putRawNode(t, store, &Node{Kind: KindRoot, Root: &Root{
			RootInode: rootInode, InodeIndex: *indexRoot, MaxInoSeen: 5, InodeCount: 2,
		}})
		reader := readerOver(t, store, rootRef)
		if _, err := reader.GetInode(ctx, 1); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("high-water lie: %v", err)
		}
	})

	t.Run("index missing the root inode", func(t *testing.T) {
		store := NewMemoryStore()
		indexRoot, _, err := BuildInodeIndexTree([]InodeIndexEntry{
			{Ino: 2, Inode: inodeNode(t, store, 2)},
			{Ino: 3, Inode: inodeNode(t, store, 3)},
		}, store)
		if err != nil {
			t.Fatal(err)
		}
		rootRef := putRawNode(t, store, &Node{Kind: KindRoot, Root: &Root{
			RootInode: inodeNode(t, store, 1), InodeIndex: *indexRoot, MaxInoSeen: 3, InodeCount: 2,
		}})
		reader := readerOver(t, store, rootRef)
		if _, err := reader.GetInode(ctx, 2); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("missing root ino: %v", err)
		}
	})
}

// TestCorruptEdgePropagationIntoEditor stages an edit routed through a lying
// base edge: the commit must fail closed and publish nothing.
func TestCorruptEdgePropagationIntoEditor(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	left := leafOfNames(t, store, "aa", "ab")
	right := leafOfNames(t, store, "mm")
	dirRoot := putRawNode(t, store, &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
		Children: []DirectoryIndexChild{
			{FirstName: "aa", LastName: "ab", Child: left, EntryCount: 3}, // actual 2
			{FirstName: "mm", LastName: "mm", Child: right, EntryCount: 1},
		},
	}})
	rootRef, _ := singleDirFixture(t, store, &dirRoot)
	f := newEditorFixtureAt(t, store, rootRef, nil, EditorLimits{})

	// Staging the entry probes the base through the lying edge.
	err := f.editor.PutDirEntry(ctx, 1, DirEntry{Name: "aa", Ino: 1, Kind: FileKindDirectory})
	if !errors.Is(err, ErrCorrupt) {
		// Some staging paths may not touch the lying edge until commit;
		// then the commit itself must fail closed.
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		sink := &countingSink{store: store}
		if _, err := f.editor.Commit(ctx, sink, sink); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("commit over lying edge: %v", err)
		}
		if sink.nodePuts+sink.packPuts != 0 {
			t.Fatal("corrupt-base commit emitted objects")
		}
	}
}

// TestControlSummaryVerification exercises the shared verifier on control
// nodes directly (PFT2 itself has no lazy control walk; recovery streaming
// lives outside this package).
func TestControlSummaryVerification(t *testing.T) {
	leaf := &Node{Kind: KindControlLeaf, ControlLeaf: &ControlLeaf{
		Entries: []ControlEntry{
			{Key: []byte("a"), Kind: 1},
			{Key: []byte("b"), Kind: 1, Value: []byte("v")},
		},
	}}
	ref := labelRef("control-leaf", 100)
	good := edgeSummary{first: []byte("a"), last: []byte("b"), count: 2}
	if err := verifyEdgeSummary("control child", ref, leaf, good); err != nil {
		t.Fatalf("exact summary rejected: %v", err)
	}
	for _, bad := range []edgeSummary{
		{first: []byte("a"), last: []byte("b"), count: 3},
		{first: []byte("a"), last: []byte("c"), count: 2},
		{first: []byte("0"), last: []byte("b"), count: 2},
	} {
		if err := verifyEdgeSummary("control child", ref, leaf, bad); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("lying summary accepted: %v", err)
		}
	}
	index := &Node{Kind: KindControlIndex, ControlIndex: &ControlIndex{
		Children: []ControlIndexChild{
			{FirstKey: []byte("a"), LastKey: []byte("c"), Child: labelRef("l0", 90), EntryCount: 4},
			{FirstKey: []byte("d"), LastKey: []byte("f"), Child: labelRef("l1", 90), EntryCount: 2},
		},
	}}
	if err := verifyEdgeSummary("control child", ref, index,
		edgeSummary{first: []byte("a"), last: []byte("f"), count: 6}); err != nil {
		t.Fatalf("index summary rejected: %v", err)
	}
	if err := verifyEdgeSummary("control child", ref, index,
		edgeSummary{first: []byte("a"), last: []byte("f"), count: 5}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("index count lie accepted: %v", err)
	}
}

// TestReaderBudgetDeterminism pins gate G: budget accounting is identical
// for every operation regardless of cache history. Before the fix, an
// operation that failed AFTER resolving the root left the root cached, and
// the next identical operation succeeded with a smaller charge.
func TestReaderBudgetDeterminism(t *testing.T) {
	ctx := context.Background()

	// GetInode(1) on the golden filesystem visits exactly root + index leaf
	// + inode object = 3 nodes.
	t.Run("exact budget repeats identically", func(t *testing.T) {
		reader, fetcher, _ := newGoldenReader(t, TreeReaderConfig{Bounds: ReadBounds{MaxNodes: 3}})
		for i := 0; i < 3; i++ {
			if _, err := reader.GetInode(ctx, RootIno); err != nil {
				t.Fatalf("op %d: %v", i, err)
			}
		}
		cold := fetcher.calls.Load()
		if _, err := reader.GetInode(ctx, RootIno); err != nil {
			t.Fatal(err)
		}
		if fetcher.calls.Load() != cold {
			t.Fatal("warm operation re-fetched (I/O must stay amortized)")
		}
	})

	t.Run("one-short budget fails every repeat identically", func(t *testing.T) {
		reader, _, _ := newGoldenReader(t, TreeReaderConfig{Bounds: ReadBounds{MaxNodes: 2}})
		for i := 0; i < 3; i++ {
			if _, err := reader.GetInode(ctx, RootIno); !errors.Is(err, ErrBoundExceeded) {
				t.Fatalf("op %d must fail on budget regardless of cache history: %v", i, err)
			}
		}
	})
}
