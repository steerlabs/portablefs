package pft2

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// countingSink wraps a MemoryStore and counts/fails puts.
type countingSink struct {
	store    *MemoryStore
	nodePuts int
	packPuts int
	failAt   int // fail the Nth put overall (1-based); 0 = never
}

func (s *countingSink) put(ref Ref, data []byte, pack bool) error {
	if s.failAt > 0 && s.nodePuts+s.packPuts+1 >= s.failAt {
		return fmt.Errorf("injected sink failure at put %d", s.failAt)
	}
	if pack {
		s.packPuts++
		return s.store.PutPack(ref, data)
	}
	s.nodePuts++
	return s.store.PutNode(ref, data)
}

func (s *countingSink) PutNode(ref Ref, data []byte) error { return s.put(ref, data, false) }
func (s *countingSink) PutPack(ref Ref, data []byte) error { return s.put(ref, data, true) }

// editorFixture opens an editor over a fresh golden filesystem.
type editorFixture struct {
	store   *MemoryStore
	fetcher *countingFetcher
	reader  *TreeReader
	rootRef Ref
	editor  *Editor
}

func newEditorFixture(t *testing.T, limits EditorLimits) *editorFixture {
	t.Helper()
	store := NewMemoryStore()
	rootRef := buildGoldenFilesystem(t, store)
	return newEditorFixtureAt(t, store, rootRef, nil, limits)
}

func newEditorFixtureAt(
	t *testing.T, store *MemoryStore, rootRef Ref, orphan *Ref, limits EditorLimits,
) *editorFixture {
	t.Helper()
	fetcher := &countingFetcher{store: store}
	reader, err := NewTreeReader(TreeReaderConfig{Fetcher: fetcher}, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	editor, err := NewEditor(context.Background(), reader, orphan, limits)
	if err != nil {
		t.Fatal(err)
	}
	return &editorFixture{store: store, fetcher: fetcher, reader: reader, rootRef: rootRef, editor: editor}
}

func (f *editorFixture) commit(t *testing.T) *CommitResult {
	t.Helper()
	sink := &countingSink{store: f.store}
	result, err := f.editor.Commit(context.Background(), sink, sink)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// readerAt opens a fresh reader over a committed root.
func readerAt(t *testing.T, store *MemoryStore, root Ref) *TreeReader {
	t.Helper()
	reader, err := NewTreeReader(TreeReaderConfig{Fetcher: &countingFetcher{store: store}}, root)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

// readWholeFile assembles a file's logical bytes through the public reader,
// verifying every cell slice.
func readWholeFile(t *testing.T, reader *TreeReader, store *MemoryStore, ino uint64) []byte {
	t.Helper()
	ctx := context.Background()
	view, err := reader.GetInode(ctx, ino)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, view.Inode.Size)
	extents, err := reader.ReadExtents(ctx, view.Ref, 0, view.Inode.Size)
	if err != nil {
		t.Fatal(err)
	}
	for _, extent := range extents {
		pack, err := store.Fetch(ctx, extent.Cell.Object)
		if err != nil {
			t.Fatal(err)
		}
		cell, err := VerifyCellBytes(extent.Cell, pack, extent.Length)
		if err != nil {
			t.Fatal(err)
		}
		copy(out[extent.FileOffset:extent.FileOffset+extent.Length], cell[:extent.Length])
	}
	return out
}

func TestEditorNoOpCommit(t *testing.T) {
	f := newEditorFixture(t, EditorLimits{})
	sink := &countingSink{store: f.store}
	result, err := f.editor.Commit(context.Background(), sink, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Unchanged || result.Root != f.rootRef {
		t.Fatalf("no-op commit changed the root: %+v", result)
	}
	if sink.nodePuts != 0 || sink.packPuts != 0 {
		t.Fatalf("no-op commit emitted %d nodes %d packs", sink.nodePuts, sink.packPuts)
	}
	// Sealed afterwards.
	if err := f.editor.PutInode(context.Background(), Inode{Ino: 9, Kind: FileKindRegular, Nlink: 1}); !errors.Is(err, ErrEditorSealed) {
		t.Fatalf("op after commit: %v", err)
	}
	if _, err := f.editor.Commit(context.Background(), sink, sink); !errors.Is(err, ErrEditorSealed) {
		t.Fatalf("second commit: %v", err)
	}
}

func TestEditorIdenticalWriteCommitsUnchanged(t *testing.T) {
	f := newEditorFixture(t, EditorLimits{})
	ctx := context.Background()
	// Rewrite cell 0 of hello.bin (ino 4) with its existing bytes.
	current, err := f.editor.ReadCell(ctx, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.editor.WriteCell(ctx, 4, 0, current); err != nil {
		t.Fatal(err)
	}
	sink := &countingSink{store: f.store}
	result, err := f.editor.Commit(ctx, sink, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Unchanged || result.Root != f.rootRef {
		t.Fatal("identical rewrite must commit unchanged (digest reuse)")
	}
	if sink.nodePuts != 0 || sink.packPuts != 0 {
		t.Fatalf("identical rewrite emitted %d/%d objects", sink.nodePuts, sink.packPuts)
	}
}

func TestEditorSingleCellMinimality(t *testing.T) {
	f := newEditorFixture(t, EditorLimits{})
	ctx := context.Background()

	cell := make([]byte, CellBytes)
	for i := range cell {
		cell[i] = 0xA5
	}
	if err := f.editor.WriteCell(ctx, 4, 0, cell); err != nil {
		t.Fatal(err)
	}
	fetchesBeforeCommit := f.fetcher.calls.Load()
	result := f.commit(t)
	commitFetches := f.fetcher.calls.Load() - fetchesBeforeCommit

	// Exactly: 1 pack; new DATA_PAGE, extent leaf, inode 4, inode-index
	// leaf, ROOT = 5 nodes.
	if result.NewPacks != 1 || result.NewNodes != 5 {
		t.Fatalf("single-cell edit produced %d packs, %d nodes", result.NewPacks, result.NewNodes)
	}
	if result.Unchanged {
		t.Fatal("edit reported unchanged")
	}
	// Commit itself touches only the changed paths (page + extent leaf; the
	// index/dir paths were cached by the staging op).
	if commitFetches > 6 {
		t.Fatalf("commit fetched %d objects", commitFetches)
	}

	// Unchanged references are reused byte for byte.
	if result.RootFacts.RootInode != buildGoldenRootInodeRef(t, f.store) {
		t.Fatal("root directory inode changed")
	}
	reader := readerAt(t, f.store, result.Root)
	rootView, err := reader.GetInode(ctx, RootIno)
	if err != nil {
		t.Fatal(err)
	}
	baseReader := readerAt(t, f.store, f.rootRef)
	baseRootView, err := baseReader.GetInode(ctx, RootIno)
	if err != nil {
		t.Fatal(err)
	}
	if rootView.Ref != baseRootView.Ref {
		t.Fatal("unchanged root directory inode was rewritten")
	}

	// Content: cell 0 changed, everything else preserved.
	want := goldenFileContentA()
	copy(want[:CellBytes], cell)
	got := readWholeFile(t, reader, f.store, 4)
	if len(got) != len(want) {
		t.Fatalf("size %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d differs", i)
		}
	}
	// Counters: logical bytes unchanged.
	if result.RootFacts.LogicalBytes != 100000+3+uint64(len("a/hello.bin")) {
		t.Fatalf("logical bytes %d", result.RootFacts.LogicalBytes)
	}
}

// buildGoldenRootInodeRef recomputes the golden filesystem's ino-1 ref.
func buildGoldenRootInodeRef(t *testing.T, store *MemoryStore) Ref {
	t.Helper()
	reader := readerAt(t, store, buildGoldenFilesystem(t, NewMemoryStore()))
	_ = reader
	// The golden root inode ref is stable; read it through the base root.
	base := buildGoldenFilesystem(t, NewMemoryStore())
	data, err := store.Fetch(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	node, err := DecodeNodeKind(data, KindRoot)
	if err != nil {
		t.Fatal(err)
	}
	return node.Root.RootInode
}

func TestEditorInodeAndDirentLifecycle(t *testing.T) {
	f := newEditorFixture(t, EditorLimits{})
	ctx := context.Background()

	// Create a file with content and link it under /a.
	if err := f.editor.PutInode(ctx, Inode{Ino: 7, Kind: FileKindRegular, Mode: 0o600, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	cell := make([]byte, CellBytes)
	copy(cell, "new file content")
	if err := f.editor.WriteCell(ctx, 7, 0, cell); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.SetFileSize(ctx, 7, 16); err != nil {
		t.Fatal(err)
	}
	// Whoops: bytes beyond size 16 must be zero; rewrite canonically.
	canonical := make([]byte, CellBytes)
	copy(canonical, "new file content")
	if err := f.editor.WriteCell(ctx, 7, 0, canonical); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.PutDirEntry(ctx, 2, DirEntry{Name: "created", Ino: 7, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)
	if result.RootFacts.InodeCount != 7 || result.RootFacts.DirentCount != 6 {
		t.Fatalf("counters %+v", result.RootFacts)
	}
	if result.RootFacts.MaxInoSeen != 7 {
		t.Fatalf("max ino %d", result.RootFacts.MaxInoSeen)
	}
	if result.RootFacts.LogicalBytes != 100000+3+uint64(len("a/hello.bin"))+16 {
		t.Fatalf("logical bytes %d", result.RootFacts.LogicalBytes)
	}
	reader := readerAt(t, f.store, result.Root)
	dirA, err := reader.GetInode(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := reader.Lookup(ctx, dirA.Ref, "created")
	if err != nil || entry.Ino != 7 {
		t.Fatalf("%+v %v", entry, err)
	}
	got := readWholeFile(t, reader, f.store, 7)
	if string(got) != "new file content" {
		t.Fatalf("content %q", got)
	}

	// Second transaction: remove it again.
	f2 := newEditorFixtureAt(t, f.store, result.Root, nil, EditorLimits{})
	if err := f2.editor.DeleteDirEntry(ctx, 2, "created"); err != nil {
		t.Fatal(err)
	}
	if err := f2.editor.DeleteInode(ctx, 7); err != nil {
		t.Fatal(err)
	}
	// Deleting an absent dirent is typed not-found.
	if err := f2.editor.DeleteDirEntry(ctx, 2, "created"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
	result2 := f2.commit(t)
	if result2.RootFacts.InodeCount != 6 || result2.RootFacts.DirentCount != 5 {
		t.Fatalf("counters after delete %+v", result2.RootFacts)
	}
	// MaxInoSeen stays monotone (allocation/observation high-water).
	if result2.RootFacts.MaxInoSeen != 7 {
		t.Fatalf("max ino regressed to %d", result2.RootFacts.MaxInoSeen)
	}
	reader2 := readerAt(t, f.store, result2.Root)
	dirA2, err := reader2.GetInode(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader2.Lookup(ctx, dirA2.Ref, "created"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lookup after delete: %v", err)
	}
	if _, err := reader2.GetInode(ctx, 7); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inode after delete: %v", err)
	}
}

// TestEditorMaxInoSeenHighWater pins the gate-D semantic: MaxInoSeen is a
// monotonic allocation/observation high-water covering orphan-homed inodes,
// never the exact maximum present, and deleting the highest inode does not
// lower it.
func TestEditorMaxInoSeenHighWater(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})

	// Raise the high-water with a linked file.
	if err := f.editor.PutInode(ctx, Inode{Ino: 40, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "forty", Ino: 40, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	first := f.commit(t)
	if first.RootFacts.MaxInoSeen != 40 {
		t.Fatalf("high-water %d after create", first.RootFacts.MaxInoSeen)
	}

	// Delete the highest inode: the high-water must not regress, reads of
	// the deleted ino stay typed not-found, and the root facts still verify.
	f2 := newEditorFixtureAt(t, f.store, first.Root, nil, EditorLimits{})
	if err := f2.editor.DeleteDirEntry(ctx, RootIno, "forty"); err != nil {
		t.Fatal(err)
	}
	if err := f2.editor.DeleteInode(ctx, 40); err != nil {
		t.Fatal(err)
	}
	second := f2.commit(t)
	if second.RootFacts.MaxInoSeen != 40 {
		t.Fatalf("high-water regressed to %d after deleting the highest ino", second.RootFacts.MaxInoSeen)
	}
	reader := readerAt(t, f.store, second.Root)
	if _, err := reader.GetInode(ctx, 40); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted highest ino: %v", err)
	}
	if _, err := reader.GetInode(ctx, RootIno); err != nil {
		t.Fatalf("root facts must still verify after delete-highest: %v", err)
	}

	// An orphan-homed inode above the current high-water raises it even
	// though it never appears in the filesystem index.
	f3 := newEditorFixtureAt(t, f.store, second.Root, nil, EditorLimits{})
	if err := f3.editor.PutOrphanInode(ctx, Inode{Ino: 50, Kind: FileKindRegular, Mode: 0o600, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	third := f3.commit(t)
	if third.RootFacts.MaxInoSeen != 50 {
		t.Fatalf("orphan-homed ino did not raise the high-water: %d", third.RootFacts.MaxInoSeen)
	}
	if third.OrphanIndex == nil {
		t.Fatal("missing orphan index")
	}
	reader3 := readerAt(t, f.store, third.Root)
	if _, err := reader3.GetInode(ctx, RootIno); err != nil {
		t.Fatalf("fs index root facts with orphan-raised high-water: %v", err)
	}

	// Allocate-after-delete retry: re-creating below and above the
	// high-water both work; below leaves it unchanged.
	f4 := newEditorFixtureAt(t, f.store, third.Root, third.OrphanIndex, EditorLimits{})
	if err := f4.editor.PutInode(ctx, Inode{Ino: 41, Kind: FileKindSymlink, Mode: 0o777, Nlink: 1, SymlinkTarget: "t", Size: 1}); err != nil {
		t.Fatal(err)
	}
	if err := f4.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "fortyone", Ino: 41, Kind: FileKindSymlink}); err != nil {
		t.Fatal(err)
	}
	fourth := f4.commit(t)
	if fourth.RootFacts.MaxInoSeen != 50 {
		t.Fatalf("re-create below high-water changed it: %d", fourth.RootFacts.MaxInoSeen)
	}
	f5 := newEditorFixtureAt(t, f.store, fourth.Root, fourth.OrphanIndex, EditorLimits{})
	if err := f5.editor.PutInode(ctx, Inode{Ino: 60, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	if err := f5.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "sixty", Ino: 60, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	fifth := f5.commit(t)
	if fifth.RootFacts.MaxInoSeen != 60 {
		t.Fatalf("high-water %d after creating above it", fifth.RootFacts.MaxInoSeen)
	}
}

func TestEditorHardlinkCompatibleRefs(t *testing.T) {
	f := newEditorFixture(t, EditorLimits{})
	ctx := context.Background()
	// Link /small (ino 6) under a second name with nlink 2.
	small, found, err := f.editor.GetInode(ctx, 6)
	if err != nil || !found {
		t.Fatalf("%v %v", found, err)
	}
	small.Nlink = 2
	if err := f.editor.PutInode(ctx, small); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.PutDirEntry(ctx, 2, DirEntry{Name: "small-link", Ino: 6, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)

	reader := readerAt(t, f.store, result.Root)
	root, err := reader.GetInode(ctx, RootIno)
	if err != nil {
		t.Fatal(err)
	}
	dirA, err := reader.GetInode(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reader.Lookup(ctx, root.Ref, "small")
	if err != nil {
		t.Fatal(err)
	}
	second, err := reader.Lookup(ctx, dirA.Ref, "small-link")
	if err != nil {
		t.Fatal(err)
	}
	if first.Ino != 6 || second.Ino != 6 {
		t.Fatalf("hardlink inos %d %d", first.Ino, second.Ino)
	}
	view, err := reader.GetInode(ctx, 6)
	if err != nil {
		t.Fatal(err)
	}
	if view.Inode.Nlink != 2 {
		t.Fatalf("nlink %d", view.Inode.Nlink)
	}
	// One inode object, one content: both names resolve to the same ref.
	if string(readWholeFile(t, reader, f.store, 6)) != "hi\n" {
		t.Fatal("hardlinked content mismatch")
	}
	// Dirent count grew by one; inode count did not.
	if result.RootFacts.InodeCount != 6 || result.RootFacts.DirentCount != 6 {
		t.Fatalf("counters %+v", result.RootFacts)
	}
}

func TestEditorRollbackAtSinkBoundary(t *testing.T) {
	ctx := context.Background()
	// Clean run to learn the total put count and the expected root.
	clean := newEditorFixture(t, EditorLimits{})
	if err := clean.editor.PutInode(ctx, Inode{Ino: 9, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	cell := make([]byte, CellBytes)
	cell[0] = 1
	if err := clean.editor.WriteCell(ctx, 9, 0, cell); err != nil {
		t.Fatal(err)
	}
	if err := clean.editor.SetFileSize(ctx, 9, CellBytes); err != nil {
		t.Fatal(err)
	}
	if err := clean.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "nine", Ino: 9, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	cleanResult := clean.commit(t)
	totalPuts := cleanResult.NewNodes + cleanResult.NewPacks
	if totalPuts == 0 {
		t.Fatal("expected new objects")
	}

	for failAt := 1; failAt <= totalPuts; failAt++ {
		f := newEditorFixture(t, EditorLimits{})
		if err := f.editor.PutInode(ctx, Inode{Ino: 9, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
			t.Fatal(err)
		}
		if err := f.editor.WriteCell(ctx, 9, 0, cell); err != nil {
			t.Fatal(err)
		}
		if err := f.editor.SetFileSize(ctx, 9, CellBytes); err != nil {
			t.Fatal(err)
		}
		if err := f.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "nine", Ino: 9, Kind: FileKindRegular}); err != nil {
			t.Fatal(err)
		}
		failing := &countingSink{store: f.store, failAt: failAt}
		if _, err := f.editor.Commit(ctx, failing, failing); err == nil {
			t.Fatalf("failAt %d: commit succeeded", failAt)
		}
		// Nothing published, editor usable: retry emits identical bytes.
		retry := &countingSink{store: f.store}
		result, err := f.editor.Commit(ctx, retry, retry)
		if err != nil {
			t.Fatalf("failAt %d retry: %v", failAt, err)
		}
		if result.Root != cleanResult.Root {
			t.Fatalf("failAt %d: retry root differs", failAt)
		}
	}
}

func TestEditorRollbackAtFetchBoundary(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	rootRef := buildGoldenFilesystem(t, store)
	// A fetcher that fails each distinct object the first time it is asked.
	failing := &failOnceFetcher{store: store, failures: map[Ref]bool{}}
	reader, err := NewTreeReader(TreeReaderConfig{Fetcher: failing, CacheBytes: -1}, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	editor, err := NewEditor(ctx, reader, nil, EditorLimits{})
	if err == nil {
		// Root fetch may have failed once already inside NewEditor; if it
		// succeeded (fetch order), continue and fail later.
		cell := make([]byte, CellBytes)
		cell[0] = 7
		writeErr := editor.WriteCell(ctx, 4, 0, cell)
		if writeErr == nil {
			t.Fatal("expected at least one injected fetch failure")
		}
		// The op failed cleanly; retrying heals fetch by fetch.
		for i := 0; i < 16; i++ {
			if writeErr = editor.WriteCell(ctx, 4, 0, cell); writeErr == nil {
				break
			}
		}
		if writeErr != nil {
			t.Fatalf("retry after fetch failure: %v", writeErr)
		}
		commitWithHealingFetches(ctx, t, editor, store)
		return
	}
	// NewEditor itself failed on the injected root fetch: retry heals.
	editor, err = NewEditor(ctx, reader, nil, EditorLimits{})
	if err != nil {
		t.Fatalf("retry NewEditor: %v", err)
	}
	cell := make([]byte, CellBytes)
	cell[0] = 7
	for i := 0; i < 16; i++ { // heal every path fetch
		if err = editor.WriteCell(ctx, 4, 0, cell); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("op never healed: %v", err)
	}
	commitWithHealingFetches(ctx, t, editor, store)
}

// commitWithHealingFetches retries Commit until every fail-once fetch has
// healed, asserting each failure published nothing.
func commitWithHealingFetches(ctx context.Context, t *testing.T, editor *Editor, store *MemoryStore) {
	t.Helper()
	for attempt := 0; attempt < 32; attempt++ {
		sink := &countingSink{store: store}
		if _, err := editor.Commit(ctx, sink, sink); err == nil {
			return
		} else if sink.nodePuts+sink.packPuts != 0 {
			t.Fatalf("failed commit emitted objects: %v", err)
		}
	}
	t.Fatal("commit never healed")
}

type failOnceFetcher struct {
	store    *MemoryStore
	mu       sync.Mutex
	failures map[Ref]bool
}

func (f *failOnceFetcher) Fetch(ctx context.Context, ref Ref) ([]byte, error) {
	f.mu.Lock()
	failed := f.failures[ref]
	if !failed {
		f.failures[ref] = true
	}
	f.mu.Unlock()
	if !failed {
		return nil, fmt.Errorf("injected fetch failure for %s", ref.Hex())
	}
	return f.store.Fetch(ctx, ref)
}

func TestEditorValidationFailurePublishesNothing(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})
	// Dangling dirent target.
	if err := f.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "dangling", Ino: 42, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	sink := &countingSink{store: f.store}
	if _, err := f.editor.Commit(ctx, sink, sink); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("dangling dirent commit: %v", err)
	}
	if sink.nodePuts != 0 || sink.packPuts != 0 {
		t.Fatal("failed validation emitted objects")
	}
	// Heal by creating the target; the editor stays usable.
	if err := f.editor.PutInode(ctx, Inode{Ino: 42, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.editor.Commit(ctx, sink, sink); err != nil {
		t.Fatalf("healed commit: %v", err)
	}
}

func TestEditorKindChangeForbidden(t *testing.T) {
	f := newEditorFixture(t, EditorLimits{})
	ctx := context.Background()
	err := f.editor.PutInode(ctx, Inode{Ino: 6, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1})
	if !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("kind change: %v", err)
	}
}

func TestEditorCorruptBase(t *testing.T) {
	ctx := context.Background()
	t.Run("corrupt root", func(t *testing.T) {
		store := NewMemoryStore()
		rootRef := buildGoldenFilesystem(t, store)
		store.mu.Lock()
		store.objects[rootRef][10] ^= 0x20
		store.mu.Unlock()
		reader, err := NewTreeReader(TreeReaderConfig{Fetcher: &countingFetcher{store: store}}, rootRef)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewEditor(ctx, reader, nil, EditorLimits{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corrupt base root: %v", err)
		}
	})
	t.Run("corrupt inode object under edit path", func(t *testing.T) {
		store := NewMemoryStore()
		rootRef := buildGoldenFilesystem(t, store)
		// Corrupt ino 4's inode object.
		reader := readerAt(t, store, rootRef)
		view, err := reader.GetInode(ctx, 4)
		if err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		store.objects[view.Ref][8] ^= 0x10
		store.mu.Unlock()
		f := newEditorFixtureAt(t, store, rootRef, nil, EditorLimits{})
		cell := make([]byte, CellBytes)
		cell[0] = 1
		if err := f.editor.WriteCell(ctx, 4, 0, cell); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corrupt inode under edit: %v", err)
		}
	})
}

func TestEditorTransactionLimits(t *testing.T) {
	ctx := context.Background()

	t.Run("edit count", func(t *testing.T) {
		f := newEditorFixture(t, EditorLimits{MaxEdits: 2})
		if err := f.editor.PutInode(ctx, Inode{Ino: 30, Kind: FileKindRegular, Nlink: 1}); err != nil {
			t.Fatal(err)
		}
		if err := f.editor.PutInode(ctx, Inode{Ino: 31, Kind: FileKindRegular, Nlink: 1}); err != nil {
			t.Fatal(err)
		}
		err := f.editor.PutInode(ctx, Inode{Ino: 32, Kind: FileKindRegular, Nlink: 1})
		if !errors.Is(err, ErrTransactionLimit) {
			t.Fatalf("edit limit: %v", err)
		}
	})

	t.Run("staged cell bytes", func(t *testing.T) {
		f := newEditorFixture(t, EditorLimits{MaxStagedCellBytes: CellBytes})
		cell := make([]byte, CellBytes)
		cell[0] = 1
		if err := f.editor.WriteCell(ctx, 4, 0, cell); err != nil {
			t.Fatal(err)
		}
		// Overwriting the same cell stays within budget.
		if err := f.editor.WriteCell(ctx, 4, 0, cell); err != nil {
			t.Fatal(err)
		}
		if err := f.editor.WriteCell(ctx, 4, CellBytes, cell); !errors.Is(err, ErrTransactionLimit) {
			t.Fatalf("staged byte limit: %v", err)
		}
	})

	t.Run("fetch budget", func(t *testing.T) {
		f := newEditorFixture(t, EditorLimits{MaxFetchNodes: 2})
		// The base root consumed one visit; a content edit walks more.
		cell := make([]byte, CellBytes)
		cell[0] = 1
		if err := f.editor.WriteCell(ctx, 4, 0, cell); !errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("fetch budget: %v", err)
		}
	})

	t.Run("new object budget", func(t *testing.T) {
		f := newEditorFixture(t, EditorLimits{MaxNewObjects: 2})
		cell := make([]byte, CellBytes)
		cell[0] = 1
		if err := f.editor.WriteCell(ctx, 4, 0, cell); err != nil {
			t.Fatal(err)
		}
		sink := &countingSink{store: f.store}
		if _, err := f.editor.Commit(ctx, sink, sink); !errors.Is(err, ErrTransactionLimit) {
			t.Fatalf("new object budget: %v", err)
		}
		if sink.nodePuts != 0 || sink.packPuts != 0 {
			t.Fatal("budget failure emitted objects")
		}
	})
}

func TestEditorEmptyBase(t *testing.T) {
	ctx := context.Background()

	t.Run("must create the root inode", func(t *testing.T) {
		editor, err := NewEditor(ctx, nil, nil, EditorLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if err := editor.PutInode(ctx, Inode{Ino: 2, Kind: FileKindRegular, Nlink: 1}); err != nil {
			t.Fatal(err)
		}
		store := NewMemoryStore()
		sink := &countingSink{store: store}
		if _, err := editor.Commit(ctx, sink, sink); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("missing root inode: %v", err)
		}
	})

	t.Run("fresh filesystem", func(t *testing.T) {
		editor, err := NewEditor(ctx, nil, nil, EditorLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if err := editor.PutInode(ctx, Inode{Ino: 1, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1}); err != nil {
			t.Fatal(err)
		}
		if err := editor.PutInode(ctx, Inode{Ino: 2, Kind: FileKindSymlink, Mode: 0o777, Nlink: 1, SymlinkTarget: "t"}); err != nil {
			t.Fatal(err)
		}
		if err := editor.PutDirEntry(ctx, 1, DirEntry{Name: "l", Ino: 2, Kind: FileKindSymlink}); err != nil {
			t.Fatal(err)
		}
		store := NewMemoryStore()
		sink := &countingSink{store: store}
		result, err := editor.Commit(ctx, sink, sink)
		if err != nil {
			t.Fatal(err)
		}
		if result.RootFacts.InodeCount != 2 || result.RootFacts.DirentCount != 1 ||
			result.RootFacts.LogicalBytes != 1 || result.RootFacts.MaxInoSeen != 2 {
			t.Fatalf("fresh facts %+v", result.RootFacts)
		}
		reader := readerAt(t, store, result.Root)
		root, err := reader.GetInode(ctx, RootIno)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := reader.Lookup(ctx, root.Ref, "l")
		if err != nil || entry.Kind != FileKindSymlink {
			t.Fatalf("%+v %v", entry, err)
		}
	})
}

func TestEditorParkedOrphans(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})

	// Park /a/hello.bin (ino 4): unlink its name and move it to the orphan
	// index, preserving content. The transition engine drives these exact
	// low-level steps.
	if err := f.editor.DeleteDirEntry(ctx, 2, "hello.bin"); err != nil {
		t.Fatal(err)
	}
	hello, found, err := f.editor.GetInode(ctx, 4)
	if err != nil || !found {
		t.Fatalf("%v %v", found, err)
	}
	if err := f.editor.DeleteInode(ctx, 4); err != nil {
		t.Fatal(err)
	}
	hello.Nlink = 1
	if err := f.editor.PutOrphanInode(ctx, hello); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)
	if result.OrphanIndex == nil {
		t.Fatal("no orphan index emitted")
	}
	if result.RootFacts.InodeCount != 5 || result.RootFacts.DirentCount != 4 {
		t.Fatalf("counters %+v", result.RootFacts)
	}
	if result.RootFacts.LogicalBytes != 3+uint64(len("a/hello.bin")) {
		t.Fatalf("logical bytes %d", result.RootFacts.LogicalBytes)
	}
	// The filesystem no longer resolves ino 4; the orphan index does.
	reader := readerAt(t, f.store, result.Root)
	if _, err := reader.GetInode(ctx, 4); !errors.Is(err, ErrNotFound) {
		t.Fatalf("parked ino still in fs: %v", err)
	}

	// Second transaction over the new base: read parked content, unpark.
	f2 := newEditorFixtureAt(t, f.store, result.Root, result.OrphanIndex, EditorLimits{})
	parked, found, err := f2.editor.GetOrphanInode(ctx, 4)
	if err != nil || !found {
		t.Fatalf("%v %v", found, err)
	}
	if parked.Size != 100000 {
		t.Fatalf("parked size %d", parked.Size)
	}
	cell, err := f2.editor.ReadCell(ctx, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := goldenFileContentA()
	if cell[0] != want[0] || cell[100] != want[100] {
		t.Fatal("parked content unreadable")
	}
	// Dirent to a parked ino is rejected.
	if err := f2.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "bad", Ino: 4, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	sink := &countingSink{store: f2.store}
	if _, err := f2.editor.Commit(ctx, sink, sink); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("dirent to parked ino: %v", err)
	}
	if sink.nodePuts+sink.packPuts != 0 {
		t.Fatal("rejected commit emitted objects")
	}

	// Third: proper unpark (delete orphan, put back, relink).
	f3 := newEditorFixtureAt(t, f.store, result.Root, result.OrphanIndex, EditorLimits{})
	if err := f3.editor.DeleteOrphanInode(ctx, 4); err != nil {
		t.Fatal(err)
	}
	if err := f3.editor.PutInode(ctx, parked); err != nil {
		t.Fatal(err)
	}
	if err := f3.editor.PutDirEntry(ctx, 2, DirEntry{Name: "hello.bin", Ino: 4, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	result3 := f3.commit(t)
	if result3.OrphanIndex != nil {
		t.Fatalf("orphan index should be empty, got %v", result3.OrphanIndex)
	}
	reader3 := readerAt(t, f.store, result3.Root)
	got := readWholeFile(t, reader3, f.store, 4)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unparked byte %d differs", i)
		}
	}
	if result3.RootFacts.InodeCount != 6 || result3.RootFacts.DirentCount != 5 {
		t.Fatalf("counters %+v", result3.RootFacts)
	}
}

func TestEditorDeletedDirectoryMustCommitEmpty(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{})
	if err := f.editor.DeleteDirEntry(ctx, RootIno, "a"); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.DeleteInode(ctx, 2); err != nil {
		t.Fatal(err)
	}
	sink := &countingSink{store: f.store}
	if _, err := f.editor.Commit(ctx, sink, sink); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("non-empty deleted directory: %v", err)
	}
	// Empty it (and drop its children's inodes) and the commit passes.
	if err := f.editor.DeleteDirEntry(ctx, 2, "empty"); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.DeleteDirEntry(ctx, 2, "hello.bin"); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.DeleteInode(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.DeleteInode(ctx, 4); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)
	if result.RootFacts.InodeCount != 3 || result.RootFacts.DirentCount != 2 {
		t.Fatalf("counters %+v", result.RootFacts)
	}
}

func TestEditorDeterminismAcrossOrderAndGoroutines(t *testing.T) {
	ctx := context.Background()

	type edit struct {
		ino  uint64
		cell uint64
		fill byte
	}
	var edits []edit
	for i := 0; i < 40; i++ {
		edits = append(edits, edit{ino: 4, cell: uint64(i%12) * CellBytes, fill: byte(i + 1)})
	}

	apply := func(f *editorFixture, order []int, parallel bool) Ref {
		t.Helper()
		run := func(index int) error {
			cell := make([]byte, CellBytes)
			for j := range cell {
				cell[j] = edits[index].fill
			}
			return f.editor.WriteCell(ctx, edits[index].ino, edits[index].cell, cell)
		}
		if parallel {
			var wg sync.WaitGroup
			errs := make([]error, len(order))
			for slot, index := range order {
				wg.Add(1)
				go func(slot, index int) {
					defer wg.Done()
					errs[slot] = run(index)
				}(slot, index)
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
		} else {
			for _, index := range order {
				if err := run(index); err != nil {
					t.Fatal(err)
				}
			}
		}
		// Deterministic tiebreak: the LAST write to a cell wins; make the
		// final value order-independent by replaying the canonical order for
		// each cell's final value.
		final := map[uint64]byte{}
		for _, e := range edits {
			final[e.cell] = e.fill
		}
		for cellOffset, fill := range final {
			cell := make([]byte, CellBytes)
			for j := range cell {
				cell[j] = fill
			}
			if err := f.editor.WriteCell(ctx, 4, cellOffset, cell); err != nil {
				t.Fatal(err)
			}
		}
		return f.commit(t).Root
	}

	forward := make([]int, len(edits))
	backward := make([]int, len(edits))
	for i := range edits {
		forward[i] = i
		backward[i] = len(edits) - 1 - i
	}
	rootA := apply(newEditorFixture(t, EditorLimits{}), forward, false)
	rootB := apply(newEditorFixture(t, EditorLimits{}), backward, false)
	rootC := apply(newEditorFixture(t, EditorLimits{}), forward, true)
	if rootA != rootB || rootA != rootC {
		t.Fatal("commit output depends on edit order or goroutine count")
	}
}

func TestEditorConcurrentIndependentEditors(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	rootRef := buildGoldenFilesystem(t, store)
	reader := readerAt(t, store, rootRef)

	const workers = 8
	roots := make([]Ref, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			editor, err := NewEditor(ctx, reader, nil, EditorLimits{})
			if err != nil {
				errs[w] = err
				return
			}
			ino := uint64(100 + w)
			if err := editor.PutInode(ctx, Inode{Ino: ino, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
				errs[w] = err
				return
			}
			cell := make([]byte, CellBytes)
			cell[0] = byte(w + 1)
			if err := editor.WriteCell(ctx, ino, 0, cell); err != nil {
				errs[w] = err
				return
			}
			if err := editor.SetFileSize(ctx, ino, 1); err != nil {
				errs[w] = err
				return
			}
			if err := editor.PutDirEntry(ctx, RootIno, DirEntry{
				Name: fmt.Sprintf("worker-%d", w), Ino: ino, Kind: FileKindRegular,
			}); err != nil {
				errs[w] = err
				return
			}
			sink := &countingSink{store: store}
			result, err := editor.Commit(ctx, sink, sink)
			if err != nil {
				errs[w] = err
				return
			}
			roots[w] = result.Root
		}(w)
	}
	wg.Wait()
	for w, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", w, err)
		}
	}
	// Each editor produced an independent valid successor of the same base.
	for w := 0; w < workers; w++ {
		r := readerAt(t, store, roots[w])
		root, err := r.GetInode(ctx, RootIno)
		if err != nil {
			t.Fatalf("worker %d root: %v", w, err)
		}
		entry, err := r.Lookup(ctx, root.Ref, fmt.Sprintf("worker-%d", w))
		if err != nil || entry.Ino != uint64(100+w) {
			t.Fatalf("worker %d entry: %+v %v", w, entry, err)
		}
		for other := 0; other < workers; other++ {
			if other == w {
				continue
			}
			if _, err := r.Lookup(ctx, root.Ref, fmt.Sprintf("worker-%d", other)); !errors.Is(err, ErrNotFound) {
				t.Fatalf("worker %d sees worker %d", w, other)
			}
		}
	}
}

func TestEditorGlobalPackBoundaries(t *testing.T) {
	ctx := context.Background()
	f := newEditorFixture(t, EditorLimits{
		MaxStagedCellBytes: 1 << 30, MaxNewObjectBytes: 1 << 30,
		MaxFetchBytes: 1 << 40, MaxFetchNodes: 1 << 20, MaxEdits: 1 << 20,
	})

	// 1030 changed cells across two inodes: one exactly full 4 MiB pack
	// (1024 cells) plus one 6-cell underfilled terminal pack, regardless of
	// staging order.
	cellsPerPack := MaxPackBytes / CellBytes // 1024
	total := cellsPerPack + 6
	if err := f.editor.PutInode(ctx, Inode{Ino: 21, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.PutInode(ctx, Inode{Ino: 22, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	// Stage in a scrambled order; the frozen (ino, pageOffset, cellIndex)
	// sort owns pack boundaries.
	for i := total - 1; i >= 0; i-- {
		ino := uint64(21)
		index := i
		if i%3 == 0 {
			ino = 22
		}
		cell := make([]byte, CellBytes)
		cell[0] = byte(i%250) + 1
		cell[1] = byte(i / 250)
		if err := f.editor.WriteCell(ctx, ino, uint64(index)*CellBytes, cell); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.editor.SetFileSize(ctx, 21, uint64(total)*CellBytes); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.SetFileSize(ctx, 22, uint64(total)*CellBytes); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "pack-a", Ino: 21, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	if err := f.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: "pack-b", Ino: 22, Kind: FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)
	if result.NewPacks != 2 {
		t.Fatalf("pack count %d", result.NewPacks)
	}
	if result.NewPackBytes != int64(total)*CellBytes {
		t.Fatalf("pack bytes %d", result.NewPackBytes)
	}
	// The terminal pack is underfilled in exact cell increments. The file
	// spans ~65 pages, so the verifying reader needs a wider per-op budget
	// than the 64-node default.
	reader, err := NewTreeReader(TreeReaderConfig{
		Fetcher: &countingFetcher{store: f.store},
		Bounds:  ReadBounds{MaxNodes: 4096, MaxBytes: 1 << 30},
	}, result.Root)
	if err != nil {
		t.Fatal(err)
	}
	view, err := reader.GetInode(ctx, 22)
	if err != nil {
		t.Fatal(err)
	}
	extents, err := reader.ReadExtents(ctx, view.Ref, 0, uint64(total)*CellBytes)
	if err != nil {
		t.Fatal(err)
	}
	sizes := map[uint64]bool{}
	for _, extent := range extents {
		sizes[extent.Cell.Object.Size] = true
	}
	if !sizes[uint64(MaxPackBytes)] || !sizes[6*CellBytes] || len(sizes) != 2 {
		t.Fatalf("pack sizes %v", sizes)
	}
}

func TestEditorLargeSparseFileMinimalTouch(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	// Base: a 1 GiB sparse file with three present pages, built directly.
	packer := NewCellPacker()
	var cellRefs []CellRef
	for i := 0; i < 3; i++ {
		cell := make([]byte, CellBytes)
		cell[0] = byte(i + 1)
		if _, err := packer.Add(cell); err != nil {
			t.Fatal(err)
		}
	}
	refs, err := packer.Finish(store)
	if err != nil {
		t.Fatal(err)
	}
	cellRefs = refs
	const gib = uint64(1) << 30
	pageOffsets := []uint64{0, gib / 2, gib - PageBytes}
	var extents []ExtentEntry
	for i, pageOffset := range pageOffsets {
		page := &DataPage{}
		cell := cellRefs[i]
		page.Cells[0] = &cell
		encoded, err := EncodeNode(&Node{Kind: KindDataPage, DataPage: page})
		if err != nil {
			t.Fatal(err)
		}
		ref := RefOf(encoded)
		if err := store.PutNode(ref, encoded); err != nil {
			t.Fatal(err)
		}
		extents = append(extents, ExtentEntry{PageOffset: pageOffset, Page: ref})
	}
	extentRoot, _, err := BuildExtentTree(extents, store)
	if err != nil {
		t.Fatal(err)
	}
	putInode := func(inode Inode) Ref {
		encoded, err := EncodeNode(&Node{Kind: KindInode, Inode: &inode})
		if err != nil {
			t.Fatal(err)
		}
		ref := RefOf(encoded)
		if err := store.PutNode(ref, encoded); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	fileRef := putInode(Inode{Ino: 2, Kind: FileKindRegular, Mode: 0o644, Nlink: 1, Size: gib, ExtentRoot: extentRoot})
	dirRoot, dirCount, err := BuildDirectoryTree([]DirEntry{{Name: "big", Ino: 2, Kind: FileKindRegular}}, store)
	if err != nil {
		t.Fatal(err)
	}
	rootInodeRef := putInode(Inode{Ino: 1, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1, DirectoryRoot: dirRoot})
	indexRoot, inodeCount, err := BuildInodeIndexTree([]InodeIndexEntry{
		{Ino: 1, Inode: rootInodeRef}, {Ino: 2, Inode: fileRef},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	rootEncoded, err := EncodeNode(&Node{Kind: KindRoot, Root: &Root{
		RootInode: rootInodeRef, InodeIndex: *indexRoot, MaxInoSeen: 2,
		InodeCount: inodeCount, DirentCount: dirCount, LogicalBytes: gib,
	}})
	if err != nil {
		t.Fatal(err)
	}
	rootRef := RefOf(rootEncoded)
	if err := store.PutNode(rootRef, rootEncoded); err != nil {
		t.Fatal(err)
	}

	// Tight budgets prove the edit never materializes the file.
	f := newEditorFixtureAt(t, store, rootRef, nil, EditorLimits{
		MaxFetchNodes:      24,
		MaxFetchBytes:      1 << 20,
		MaxStagedCellBytes: 4 * CellBytes,
		MaxNewObjects:      16,
	})
	cell := make([]byte, CellBytes)
	copy(cell, "middle of a huge sparse file")
	if err := f.editor.WriteCell(ctx, 2, gib/2+5*CellBytes, cell); err != nil {
		t.Fatal(err)
	}
	result := f.commit(t)
	if result.NewPacks != 1 || result.NewNodes > 6 {
		t.Fatalf("sparse edit produced %d packs, %d nodes", result.NewPacks, result.NewNodes)
	}
	reader := readerAt(t, store, result.Root)
	view, err := reader.GetInode(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if view.Inode.Size != gib {
		t.Fatalf("size %d", view.Inode.Size)
	}
	extentsOut, err := reader.ReadExtents(ctx, view.Ref, gib/2, PageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(extentsOut) != 2 { // original cell 0 plus the new cell 5
		t.Fatalf("middle page extents %d", len(extentsOut))
	}
}
