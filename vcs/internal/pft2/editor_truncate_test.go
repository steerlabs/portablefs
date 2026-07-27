package pft2

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// oracleTruncate applies exact truncate semantics to a plain byte slice.
func oracleTruncate(data []byte, size uint64) []byte {
	out := make([]byte, size)
	copy(out, data)
	return out
}

// verifyFileBytes reads a committed file back and compares it to want.
func verifyFileBytes(t *testing.T, store *MemoryStore, root Ref, ino uint64, want []byte) {
	t.Helper()
	reader := readerAt(t, store, root)
	got := readWholeFile(t, reader, store, ino)
	if len(got) != len(want) {
		t.Fatalf("size %d, want %d", len(got), len(want))
	}
	if !bytes.Equal(got, want) {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("byte %d: got %#x want %#x", i, got[i], want[i])
			}
		}
	}
}

func TestEditorShrinkThenGrowRevealsOnlyZeros(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})

	// hello.bin (ino 4) is 100000 bytes. Shrink to an unaligned size inside
	// cell 2, then grow to 50000: bytes 10000..50000 must read zero.
	if err := f.editor.SetFileSize(ctx, 4, 10000); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.SetFileSize(ctx, 4, 50000); err != nil {
		t.Fatal(err)
	}
	// The editor's own merged reads agree before commit.
	cell2, err := f.editor.ReadCell(ctx, 4, 2*CellBytes)
	if err != nil {
		t.Fatal(err)
	}
	want := oracleTruncate(oracleTruncate(goldenFileContentA(), 10000), 50000)
	if !bytes.Equal(cell2, want[2*CellBytes:3*CellBytes]) {
		t.Fatal("merged straddle cell mismatch before commit")
	}
	result := f.commit(t)
	// Exactly one repacked cell: the straddled COW cell.
	if result.NewPacks != 1 {
		t.Fatalf("straddle shrink produced %d packs", result.NewPacks)
	}
	verifyFileBytes(t, f.store, result.Root, 4, want)
	if result.RootFacts.LogicalBytes != 50000+3+uint64(len("a/hello.bin")) {
		t.Fatalf("logical bytes %d", result.RootFacts.LogicalBytes)
	}
}

func TestEditorShrinkToCellAlignedSizeNeedsNoPack(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})
	if err := f.editor.SetFileSize(ctx, 4, 2*CellBytes); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)
	if result.NewPacks != 0 {
		t.Fatalf("aligned shrink repacked %d packs", result.NewPacks)
	}
	verifyFileBytes(t, f.store, result.Root, 4, oracleTruncate(goldenFileContentA(), 2*CellBytes))
}

func TestEditorShrinkToZero(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})
	if err := f.editor.SetFileSize(ctx, 4, 0); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)
	if result.NewPacks != 0 {
		t.Fatalf("shrink to zero repacked %d packs", result.NewPacks)
	}
	reader := readerAt(t, f.store, result.Root)
	view, err := reader.GetInode(context.Background(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if view.Inode.Size != 0 {
		t.Fatalf("size %d", view.Inode.Size)
	}
	extents, err := reader.ReadExtents(context.Background(), view.Ref, 0, PageBytes)
	if err != nil || len(extents) != 0 {
		t.Fatalf("%v %v", extents, err)
	}
	if result.RootFacts.LogicalBytes != 3+uint64(len("a/hello.bin")) {
		t.Fatalf("logical bytes %d", result.RootFacts.LogicalBytes)
	}
}

func TestEditorGrowOnlyKeepsExtentRoot(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})

	baseReader := readerAt(t, f.store, f.rootRef)
	baseView, err := baseReader.GetInode(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	baseExtents, err := baseReader.ReadExtents(ctx, baseView.Ref, 0, 100000)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.editor.SetFileSize(ctx, 4, 3*PageBytes); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)
	if result.NewPacks != 0 {
		t.Fatalf("grow repacked %d packs", result.NewPacks)
	}
	// Only inode + inode-index path + root rewrite: three nodes.
	if result.NewNodes != 3 {
		t.Fatalf("grow produced %d nodes", result.NewNodes)
	}
	want := oracleTruncate(goldenFileContentA(), 3*PageBytes)
	verifyFileBytes(t, f.store, result.Root, 4, want)
	// The extent tree is shared byte for byte: same extents resolve.
	newReader := readerAt(t, f.store, result.Root)
	newView, err := newReader.GetInode(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	newExtents, err := newReader.ReadExtents(ctx, newView.Ref, 0, 100000)
	if err != nil {
		t.Fatal(err)
	}
	if len(newExtents) != len(baseExtents) {
		t.Fatalf("extent count changed %d -> %d", len(baseExtents), len(newExtents))
	}
	for i := range baseExtents {
		if *newExtents[i].Cell != *baseExtents[i].Cell {
			t.Fatalf("extent %d cell changed", i)
		}
	}
}

func TestEditorSparseWriteBeyondOldEOF(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})

	// Grow /small (3 bytes) sparsely: one cell at 1 MiB, size 1 MiB + 100.
	const mib = uint64(1) << 20
	cell := make([]byte, CellBytes)
	copy(cell[:100], bytes.Repeat([]byte{0xEE}, 100))
	if err := f.editor.WriteCell(ctx, 6, mib, cell); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.SetFileSize(ctx, 6, mib+100); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)
	want := make([]byte, mib+100)
	copy(want, "hi\n")
	copy(want[mib:], cell[:100])
	verifyFileBytes(t, f.store, result.Root, 6, want)
}

func TestEditorStagedSuffixZeroedByShrink(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})

	// Fill a whole valid cell on /small, then shrink into it: the staged
	// suffix must zero, so a later grow reveals zeros.
	junk := bytes.Repeat([]byte{0x77}, CellBytes)
	if err := f.editor.WriteCell(ctx, 6, 0, junk); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.SetFileSize(ctx, 6, CellBytes); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.SetFileSize(ctx, 6, 10); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.SetFileSize(ctx, 6, 200); err != nil {
		t.Fatal(err)
	}
	merged, err := f.editor.ReadCell(ctx, 6, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, CellBytes)
	copy(want[:10], junk[:10])
	if !bytes.Equal(merged, want) {
		t.Fatal("staged suffix not zeroed by shrink")
	}
	result := f.commit(t)
	fileWant := make([]byte, 200)
	copy(fileWant[:10], junk[:10])
	verifyFileBytes(t, f.store, result.Root, 6, fileWant)
}

func TestEditorNonzeroCellBeyondFinalSizeRejected(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})
	// Truncate first, then write a nonzero cell beyond the final size: the
	// engine broke its contract and the commit must fail typed.
	if err := f.editor.SetFileSize(ctx, 4, CellBytes); err != nil {
		t.Fatal(err)
	}
	cell := make([]byte, CellBytes)
	cell[0] = 1
	if err := f.editor.WriteCell(ctx, 4, 2*CellBytes, cell); err != nil {
		t.Fatal(err)
	}
	sink := &countingSink{store: f.store}
	if _, err := f.editor.Commit(ctx, sink, sink); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("commit: %v", err)
	}
	if sink.nodePuts+sink.packPuts != 0 {
		t.Fatal("rejected commit emitted objects")
	}
}

func TestEditorDirtyTerminalSuffixRejected(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})
	// Write a junk-tailed cell and size the file inside it WITHOUT the
	// shrink path (grow from 0 via a fresh file): the terminal suffix is
	// nonzero and commit must fail.
	if err := f.editor.PutInode(ctx, Inode{Ino: 9, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	junk := bytes.Repeat([]byte{0x55}, CellBytes)
	if err := f.editor.SetFileSize(ctx, 9, 100); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.WriteCell(ctx, 9, 0, junk); err != nil {
		t.Fatal(err)
	}
	sink := &countingSink{store: f.store}
	if _, err := f.editor.Commit(ctx, sink, sink); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("commit: %v", err)
	}
}

// TestEditorLargeSparseShrinkBoundedFetches is the defect-3 regression: a
// shrink over N base pages must cost one ordered range walk (near nodes)
// plus the touched pages, never N repeated root-to-leaf searches. The fetch
// budget below is sufficient for one range walk plus the commit paths but
// far below pages-times-depth, so the old per-page findExtentPage behavior
// would fail typed here.
func TestEditorLargeSparseShrinkBoundedFetches(t *testing.T) {
	ctx := context.Background()
	const pageCount = 2500

	buildBase := func(t *testing.T) (*MemoryStore, Ref) {
		t.Helper()
		store := NewMemoryStore()
		packer := NewCellPacker()
		for i := 0; i < pageCount; i++ {
			cell := make([]byte, CellBytes)
			cell[0] = byte(i%251) + 1
			cell[1] = byte(i / 251)
			if _, err := packer.Add(cell); err != nil {
				t.Fatal(err)
			}
		}
		cellRefs, err := packer.Finish(store)
		if err != nil {
			t.Fatal(err)
		}
		entries := make([]ExtentEntry, pageCount)
		for i := 0; i < pageCount; i++ {
			page := &DataPage{}
			cell := cellRefs[i]
			page.Cells[0] = &cell
			entries[i] = ExtentEntry{
				PageOffset: uint64(i) * PageBytes,
				Page:       putRawNode(t, store, &Node{Kind: KindDataPage, DataPage: page}),
			}
		}
		extentRoot, _, err := BuildExtentTree(entries, store)
		if err != nil {
			t.Fatal(err)
		}
		// The extent tree must have real index depth for the regression to
		// be meaningful.
		data, err := store.Fetch(ctx, *extentRoot)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeNodeKind(data, KindExtentIndex); err != nil {
			t.Fatalf("base extent root must be an index: %v", err)
		}
		fileRef := putRawNode(t, store, &Node{Kind: KindInode, Inode: &Inode{
			Ino: 2, Kind: FileKindRegular, Mode: 0o644, Nlink: 1,
			Size: pageCount * PageBytes, ExtentRoot: extentRoot,
		}})
		rootInodeRef := putRawNode(t, store, &Node{Kind: KindInode, Inode: &Inode{
			Ino: 1, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1,
		}})
		indexRoot, _, err := BuildInodeIndexTree([]InodeIndexEntry{
			{Ino: 1, Inode: rootInodeRef}, {Ino: 2, Inode: fileRef},
		}, store)
		if err != nil {
			t.Fatal(err)
		}
		rootRef := putRawNode(t, store, &Node{Kind: KindRoot, Root: &Root{
			RootInode: rootInodeRef, InodeIndex: *indexRoot, MaxInoSeen: 2, InodeCount: 2,
			LogicalBytes: pageCount * PageBytes,
		}})
		return store, rootRef
	}

	// A low traversal budget must not fail spuriously: ~20 visits are needed,
	// the old behavior needed >2*pageCount.
	limits := EditorLimits{MaxFetchNodes: 60, MaxFetchBytes: 8 << 20}
	shrinkTo := uint64(PageBytes / 2) // cell-aligned: no COW pack expected

	runShrink := func(t *testing.T) Ref {
		t.Helper()
		store, rootRef := buildBase(t)
		f := newEditorFixtureAt(t, store, rootRef, nil, limits)
		if err := f.editor.SetFileSize(ctx, 2, shrinkTo); err != nil {
			t.Fatal(err)
		}
		result := f.commit(t)
		if result.NewPacks != 0 {
			t.Fatalf("aligned shrink repacked %d packs", result.NewPacks)
		}
		reader, err := NewTreeReader(TreeReaderConfig{
			Fetcher: &countingFetcher{store: store},
			Bounds:  ReadBounds{MaxNodes: 1 << 16, MaxBytes: 1 << 40},
		}, result.Root)
		if err != nil {
			t.Fatal(err)
		}
		view, err := reader.GetInode(ctx, 2)
		if err != nil {
			t.Fatal(err)
		}
		if view.Inode.Size != shrinkTo {
			t.Fatalf("size %d", view.Inode.Size)
		}
		extents, err := reader.ReadExtents(ctx, view.Ref, 0, pageCount*PageBytes)
		if err != nil {
			t.Fatal(err)
		}
		if len(extents) != 1 || extents[0].FileOffset != 0 {
			t.Fatalf("extents after shrink: %d", len(extents))
		}
		return result.Root
	}

	rootA := runShrink(t)
	rootB := runShrink(t)
	if rootA != rootB {
		t.Fatal("identical shrinks committed different roots")
	}
}

// TestEditorBudgetRestoreOnTransientFailures pins the retry-safe budget
// semantics: every failed attempt restores the traversal budget, so
// transient fetch failures never wedge an editor whose budget is only
// sufficient for individual attempts, and the healed commit emits the same
// root as a clean run.
func TestEditorBudgetRestoreOnTransientFailures(t *testing.T) {
	ctx := context.Background()

	// Clean run for the expected root.
	clean := newEditorFixture(t, EditorLimits{})
	cell := make([]byte, CellBytes)
	cell[0] = 9
	if err := clean.editor.WriteCell(ctx, 4, 0, cell); err != nil {
		t.Fatal(err)
	}
	cleanResult := clean.commit(t)

	store := NewMemoryStore()
	rootRef := buildGoldenFilesystem(t, store)
	failing := &failOnceFetcher{store: store, failures: map[Ref]bool{}}
	reader, err := NewTreeReader(TreeReaderConfig{Fetcher: failing}, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	// Tight budget: enough for any single attempt, far below the cumulative
	// cost of all healing retries without restore.
	limits := EditorLimits{MaxFetchNodes: 40, MaxFetchBytes: 8 << 20}
	var editor *Editor
	for attempt := 0; attempt < 8; attempt++ {
		if editor, err = NewEditor(ctx, reader, nil, limits); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("NewEditor never healed: %v", err)
	}
	wrote := false
	for attempt := 0; attempt < 32; attempt++ {
		if err = editor.WriteCell(ctx, 4, 0, cell); err == nil {
			wrote = true
			break
		}
		if errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("budget wedged during retries: %v", err)
		}
	}
	if !wrote {
		t.Fatalf("WriteCell never healed: %v", err)
	}
	var result *CommitResult
	for attempt := 0; attempt < 64; attempt++ {
		sink := &countingSink{store: store}
		if result, err = editor.Commit(ctx, sink, sink); err == nil {
			break
		}
		if errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("budget wedged during commit retries: %v", err)
		}
		if sink.nodePuts+sink.packPuts != 0 {
			t.Fatal("failed commit emitted objects")
		}
	}
	if err != nil {
		t.Fatalf("commit never healed: %v", err)
	}
	if result.Root != cleanResult.Root {
		t.Fatal("healed retry committed different bytes than a clean run")
	}
}

func TestEditorTruncateAcrossManyPagesDropsThem(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})

	// Build a multi-page file: pages 0..4 with one cell each, then shrink to
	// one page and verify the extent tree drops pages 1..4.
	if err := f.editor.PutInode(ctx, Inode{Ino: 11, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	for pageIndex := uint64(0); pageIndex < 5; pageIndex++ {
		cell := make([]byte, CellBytes)
		cell[0] = byte(pageIndex + 1)
		if err := f.editor.WriteCell(ctx, 11, pageIndex*PageBytes, cell); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.editor.SetFileSize(ctx, 11, 5*PageBytes); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "multi", Ino: 11, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	first := f.commit(t)

	f2 := newEditorFixtureAt(t, f.store, first.Root, nil, EditorLimits{})
	if err := f2.editor.SetFileSize(ctx, 11, PageBytes); err != nil {
		t.Fatal(err)
	}
	second := f2.commit(t)
	if second.NewPacks != 0 {
		t.Fatalf("page-aligned truncate repacked %d packs", second.NewPacks)
	}
	reader := readerAt(t, f.store, second.Root)
	view, err := reader.GetInode(ctx, 11)
	if err != nil {
		t.Fatal(err)
	}
	extents, err := reader.ReadExtents(ctx, view.Ref, 0, 10*PageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].FileOffset != 0 {
		t.Fatalf("extents after truncate: %+v", extents)
	}
	want := make([]byte, PageBytes)
	want[0] = 1
	verifyFileBytes(t, f.store, second.Root, 11, want)
}
