package pft2

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingFetcher wraps a store and records fetch calls (optionally slowly,
// to widen singleflight coalescing windows).
type countingFetcher struct {
	store *MemoryStore
	calls atomic.Int64
	delay time.Duration
}

func (f *countingFetcher) Fetch(ctx context.Context, ref Ref) ([]byte, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.store.Fetch(ctx, ref)
}

func newGoldenReader(t *testing.T, cfg TreeReaderConfig) (*TreeReader, *countingFetcher, Ref) {
	t.Helper()
	store := NewMemoryStore()
	rootRef := buildGoldenFilesystem(t, store)
	fetcher := &countingFetcher{store: store}
	cfg.Fetcher = fetcher
	reader, err := NewTreeReader(cfg, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	return reader, fetcher, rootRef
}

func TestTreeReaderWalksGoldenFilesystem(t *testing.T) {
	reader, _, _ := newGoldenReader(t, TreeReaderConfig{})
	ctx := context.Background()

	root, err := reader.GetInode(ctx, RootIno)
	if err != nil {
		t.Fatal(err)
	}
	if root.Inode.Kind != FileKindDirectory {
		t.Fatalf("root kind %s", root.Inode.Kind)
	}

	entryA, err := reader.Lookup(ctx, root.Ref, "a")
	if err != nil {
		t.Fatal(err)
	}
	if entryA.Ino != 2 || entryA.Kind != FileKindDirectory {
		t.Fatalf("lookup a: %+v", entryA)
	}
	if _, err := reader.Lookup(ctx, root.Ref, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing lookup: %v", err)
	}

	dirA, err := reader.GetInode(ctx, entryA.Ino)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := reader.Lookup(ctx, dirA.Ref, "hello.bin")
	if err != nil {
		t.Fatal(err)
	}
	if hello.Ino != 4 {
		t.Fatalf("hello ino %d", hello.Ino)
	}

	link, err := reader.GetInode(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if link.Inode.SymlinkTarget != "a/hello.bin" {
		t.Fatalf("symlink target %q", link.Inode.SymlinkTarget)
	}

	// Lookup through a non-directory fails closed.
	if _, err := reader.Lookup(ctx, link.Ref, "x"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("lookup through symlink: %v", err)
	}
	if _, err := reader.GetInode(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown ino: %v", err)
	}
}

func TestTreeReaderRootFacts(t *testing.T) {
	reader, fetcher, _ := newGoldenReader(t, TreeReaderConfig{})
	ctx := context.Background()

	facts, err := reader.RootFacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if facts.MaxInoSeen < 5 || facts.InodeCount == 0 {
		t.Fatalf("root facts %+v carry no verified counters", facts)
	}
	// The facts are the SAME verified ROOT every walk consumes: the index
	// entry for inode 1 must resolve to exactly facts.RootInode.
	rootView, err := reader.GetInode(ctx, RootIno)
	if err != nil {
		t.Fatal(err)
	}
	if rootView.Ref != facts.RootInode {
		t.Fatalf("index maps root to %s, facts advertise %s", rootView.Ref, facts.RootInode)
	}
	// Bounded and cached: repeated reads add no fetches.
	before := fetcher.calls.Load()
	again, err := reader.RootFacts(ctx)
	if err != nil || again.MaxInoSeen != facts.MaxInoSeen {
		t.Fatalf("repeat root facts %+v, %v", again, err)
	}
	if fetcher.calls.Load() != before {
		t.Fatal("cached root facts refetched")
	}

	// A corrupt root fails closed.
	badStore := NewMemoryStore()
	goldenRoot := buildGoldenFilesystem(t, badStore)
	corrupt := &corruptOnceFetcher{store: badStore}
	badReader, err := NewTreeReader(TreeReaderConfig{Fetcher: corrupt}, goldenRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badReader.RootFacts(ctx); err == nil {
		t.Fatal("corrupt root facts accepted")
	}
}

// corruptOnceFetcher flips one bit of every response.
type corruptOnceFetcher struct{ store *MemoryStore }

func (f *corruptOnceFetcher) Fetch(ctx context.Context, ref Ref) ([]byte, error) {
	data, err := f.store.Fetch(ctx, ref)
	if err != nil {
		return nil, err
	}
	flipped := append([]byte(nil), data...)
	flipped[0] ^= 0x01
	return flipped, nil
}

func TestTreeReaderReadDirPaging(t *testing.T) {
	reader, _, _ := newGoldenReader(t, TreeReaderConfig{})
	ctx := context.Background()
	root, err := reader.GetInode(ctx, RootIno)
	if err != nil {
		t.Fatal(err)
	}

	var all []string
	cursor := ""
	for {
		entries, next, err := reader.ReadDir(ctx, root.Ref, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			all = append(all, entry.Name)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	want := []string{"a", "link", "small"}
	if len(all) != len(want) {
		t.Fatalf("entries %v", all)
	}
	for i := range want {
		if all[i] != want[i] {
			t.Fatalf("entries %v", all)
		}
	}

	// Empty directory: /a/empty is a file; make an empty-dir inode directly.
	if _, _, err := reader.ReadDir(ctx, root.Ref, "", 0); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("zero limit: %v", err)
	}
}

func TestTreeReaderReadExtents(t *testing.T) {
	reader, _, _ := newGoldenReader(t, TreeReaderConfig{})
	ctx := context.Background()

	hello, err := reader.GetInode(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("full file skips holes", func(t *testing.T) {
		extents, err := reader.ReadExtents(ctx, hello.Ref, 0, 200000)
		if err != nil {
			t.Fatal(err)
		}
		// Page 0 has cells 0..3 and 8..15 present (4..7 zeroed) and page 1 is
		// wholly zero, so exactly 12 extents.
		if len(extents) != 12 {
			t.Fatalf("extent count %d", len(extents))
		}
		for _, extent := range extents {
			if extent.Cell == nil || extent.Legacy != nil {
				t.Fatalf("extent source: %+v", extent)
			}
			if extent.Length != CellBytes {
				t.Fatalf("interior extent length %d", extent.Length)
			}
		}
		if extents[4].FileOffset != 8*CellBytes {
			t.Fatalf("post-hole extent offset %d", extents[4].FileOffset)
		}
	})

	t.Run("window inside a hole is empty", func(t *testing.T) {
		extents, err := reader.ReadExtents(ctx, hello.Ref, 4*CellBytes, 4*CellBytes)
		if err != nil {
			t.Fatal(err)
		}
		if len(extents) != 0 {
			t.Fatalf("hole window returned %d extents", len(extents))
		}
	})

	t.Run("zero length and past-EOF windows are empty", func(t *testing.T) {
		if extents, err := reader.ReadExtents(ctx, hello.Ref, 0, 0); err != nil || len(extents) != 0 {
			t.Fatalf("%v %v", extents, err)
		}
		if extents, err := reader.ReadExtents(ctx, hello.Ref, 1<<40, 10); err != nil || len(extents) != 0 {
			t.Fatalf("%v %v", extents, err)
		}
	})

	t.Run("terminal extent clamps to EOF", func(t *testing.T) {
		small, err := reader.GetInode(ctx, 6)
		if err != nil {
			t.Fatal(err)
		}
		extents, err := reader.ReadExtents(ctx, small.Ref, 0, PageBytes)
		if err != nil {
			t.Fatal(err)
		}
		if len(extents) != 1 || extents[0].Length != 3 || extents[0].FileOffset != 0 {
			t.Fatalf("small extents %+v", extents)
		}
	})

	t.Run("directory rejected", func(t *testing.T) {
		root, err := reader.GetInode(ctx, RootIno)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ReadExtents(ctx, root.Ref, 0, 10); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("empty file has no extents", func(t *testing.T) {
		empty, err := reader.GetInode(ctx, 3)
		if err != nil {
			t.Fatal(err)
		}
		extents, err := reader.ReadExtents(ctx, empty.Ref, 0, 100)
		if err != nil || len(extents) != 0 {
			t.Fatalf("%v %v", extents, err)
		}
	})
}

func TestTreeReaderExtentBeyondEOFIsCorrupt(t *testing.T) {
	// Hand-build a file inode of size 10 whose extent tree claims page 65536.
	store := NewMemoryStore()
	pageContent := make([]byte, CellBytes)
	pageContent[0] = 1
	packer := NewCellPacker()
	if _, err := packer.Add(pageContent); err != nil {
		t.Fatal(err)
	}
	cells, err := packer.Finish(store)
	if err != nil {
		t.Fatal(err)
	}
	page := &DataPage{}
	page.Cells[0] = &cells[0]
	pageEncoded, err := EncodeNode(&Node{Kind: KindDataPage, DataPage: page})
	if err != nil {
		t.Fatal(err)
	}
	pageRef := RefOf(pageEncoded)
	if err := store.PutNode(pageRef, pageEncoded); err != nil {
		t.Fatal(err)
	}
	extentRoot, _, err := BuildExtentTree([]ExtentEntry{{PageOffset: PageBytes, Page: pageRef}}, store)
	if err != nil {
		t.Fatal(err)
	}
	inodeEncoded, err := EncodeNode(&Node{Kind: KindInode, Inode: &Inode{
		Ino: 7, Kind: FileKindRegular, Nlink: 1, Size: 10, ExtentRoot: extentRoot,
	}})
	if err != nil {
		t.Fatal(err)
	}
	inodeRef := RefOf(inodeEncoded)
	if err := store.PutNode(inodeRef, inodeEncoded); err != nil {
		t.Fatal(err)
	}
	indexRoot, _, err := BuildInodeIndexTree([]InodeIndexEntry{{Ino: 7, Inode: inodeRef}}, store)
	if err != nil {
		t.Fatal(err)
	}
	rootEncoded, err := EncodeNode(&Node{Kind: KindRoot, Root: &Root{
		RootInode: inodeRef, InodeIndex: *indexRoot, MaxInoSeen: 7, InodeCount: 1, LogicalBytes: 10,
	}})
	if err != nil {
		t.Fatal(err)
	}
	rootRef := RefOf(rootEncoded)
	if err := store.PutNode(rootRef, rootEncoded); err != nil {
		t.Fatal(err)
	}

	reader, err := NewTreeReader(TreeReaderConfig{Fetcher: &countingFetcher{store: store}}, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	// The stray page is inside the requested window only if the window is
	// large; the whole point is EOF clamping keeps it out of range entirely,
	// so a full-range read simply never visits it.
	extents, err := reader.ReadExtents(context.Background(), inodeRef, 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 0 {
		t.Fatalf("beyond-EOF page leaked %d extents", len(extents))
	}
}

func TestTreeReaderVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("oversized advertised ref rejected before fetch", func(t *testing.T) {
		reader, fetcher, _ := newGoldenReader(t, TreeReaderConfig{})
		bad := Ref{Digest: labelDigest("big"), Size: MaxNodeBytes + 1}
		if _, err := reader.Lookup(ctx, bad, "x"); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
		if fetcher.calls.Load() != 0 {
			t.Fatalf("fetcher called %d times for an invalid ref", fetcher.calls.Load())
		}
	})

	t.Run("undersized advertised ref rejected before fetch", func(t *testing.T) {
		reader, fetcher, _ := newGoldenReader(t, TreeReaderConfig{})
		bad := Ref{Digest: labelDigest("small"), Size: MinNodeBytes - 1}
		if _, err := reader.GetInode(ctx, RootIno); err != nil {
			t.Fatal(err)
		}
		before := fetcher.calls.Load()
		if _, err := reader.Lookup(ctx, bad, "x"); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
		if fetcher.calls.Load() != before {
			t.Fatal("fetcher called for undersized ref")
		}
	})

	t.Run("corrupted bytes fail closed", func(t *testing.T) {
		store := NewMemoryStore()
		rootRef := buildGoldenFilesystem(t, store)
		// Corrupt the root object in place (same length, one bit).
		store.mu.Lock()
		data := store.objects[rootRef]
		data[10] ^= 0x40
		store.mu.Unlock()
		reader, err := NewTreeReader(TreeReaderConfig{Fetcher: &countingFetcher{store: store}}, rootRef)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.GetInode(ctx, RootIno); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("size mismatch fails closed", func(t *testing.T) {
		store := NewMemoryStore()
		rootRef := buildGoldenFilesystem(t, store)
		lied := Ref{Digest: rootRef.Digest, Size: rootRef.Size + 1}
		reader, err := NewTreeReader(TreeReaderConfig{Fetcher: &countingFetcher{store: store}}, lied)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.GetInode(ctx, RootIno); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong kind for edge fails closed", func(t *testing.T) {
		// A ROOT whose InodeIndex references an INODE object.
		store := NewMemoryStore()
		inodeEncoded, err := EncodeNode(&Node{Kind: KindInode, Inode: &Inode{
			Ino: 1, Kind: FileKindDirectory, Nlink: 1,
		}})
		if err != nil {
			t.Fatal(err)
		}
		inodeRef := RefOf(inodeEncoded)
		if err := store.PutNode(inodeRef, inodeEncoded); err != nil {
			t.Fatal(err)
		}
		rootEncoded, err := EncodeNode(&Node{Kind: KindRoot, Root: &Root{
			RootInode: inodeRef, InodeIndex: inodeRef, MaxInoSeen: 1, InodeCount: 1,
		}})
		if err != nil {
			t.Fatal(err)
		}
		rootRef := RefOf(rootEncoded)
		if err := store.PutNode(rootRef, rootEncoded); err != nil {
			t.Fatal(err)
		}
		reader, err := NewTreeReader(TreeReaderConfig{Fetcher: &countingFetcher{store: store}}, rootRef)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.GetInode(ctx, 1); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("inode object advertising the wrong ino fails closed", func(t *testing.T) {
		store := NewMemoryStore()
		inodeEncoded, err := EncodeNode(&Node{Kind: KindInode, Inode: &Inode{
			Ino: 9, Kind: FileKindDirectory, Nlink: 1,
		}})
		if err != nil {
			t.Fatal(err)
		}
		inodeRef := RefOf(inodeEncoded)
		if err := store.PutNode(inodeRef, inodeEncoded); err != nil {
			t.Fatal(err)
		}
		indexRoot, _, err := BuildInodeIndexTree([]InodeIndexEntry{{Ino: 1, Inode: inodeRef}}, store)
		if err != nil {
			t.Fatal(err)
		}
		rootEncoded, err := EncodeNode(&Node{Kind: KindRoot, Root: &Root{
			RootInode: inodeRef, InodeIndex: *indexRoot, MaxInoSeen: 1, InodeCount: 1,
		}})
		if err != nil {
			t.Fatal(err)
		}
		rootRef := RefOf(rootEncoded)
		if err := store.PutNode(rootRef, rootEncoded); err != nil {
			t.Fatal(err)
		}
		reader, err := NewTreeReader(TreeReaderConfig{Fetcher: &countingFetcher{store: store}}, rootRef)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.GetInode(ctx, 1); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestTreeReaderBounds(t *testing.T) {
	ctx := context.Background()

	t.Run("node budget", func(t *testing.T) {
		reader, _, _ := newGoldenReader(t, TreeReaderConfig{Bounds: ReadBounds{MaxNodes: 1}})
		if _, err := reader.GetInode(ctx, 4); !errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("byte budget", func(t *testing.T) {
		reader, _, _ := newGoldenReader(t, TreeReaderConfig{Bounds: ReadBounds{MaxBytes: 64}})
		if _, err := reader.GetInode(ctx, 4); !errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("depth budget on an adversarial deep chain", func(t *testing.T) {
		store := NewMemoryStore()
		// Build a verification-consistent chain: every parent advertises its
		// child's true first/last/count, so only the depth bound can stop a
		// walk. Each level pairs the chain with a decoy leaf whose name lies
		// strictly above the chain's last name.
		ref, _ := buildDeepDirectoryChain(t, store, MaxTreeDepth+2)
		inodeEncoded, err := EncodeNode(&Node{Kind: KindInode, Inode: &Inode{
			Ino: 1, Kind: FileKindDirectory, Nlink: 1, DirectoryRoot: &ref,
		}})
		if err != nil {
			t.Fatal(err)
		}
		inodeRef := RefOf(inodeEncoded)
		if err := store.PutNode(inodeRef, inodeEncoded); err != nil {
			t.Fatal(err)
		}
		indexRoot, _, err := BuildInodeIndexTree([]InodeIndexEntry{{Ino: 1, Inode: inodeRef}}, store)
		if err != nil {
			t.Fatal(err)
		}
		rootEncoded, err := EncodeNode(&Node{Kind: KindRoot, Root: &Root{
			RootInode: inodeRef, InodeIndex: *indexRoot, MaxInoSeen: 1, InodeCount: 1,
		}})
		if err != nil {
			t.Fatal(err)
		}
		rootRef := RefOf(rootEncoded)
		if err := store.PutNode(rootRef, rootEncoded); err != nil {
			t.Fatal(err)
		}
		reader, err := NewTreeReader(TreeReaderConfig{
			Fetcher: &countingFetcher{store: store},
			Bounds:  ReadBounds{MaxNodes: 1000, MaxBytes: 1 << 30},
		}, rootRef)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.Lookup(ctx, inodeRef, "aa"); !errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestTreeReaderCacheAndSingleflight(t *testing.T) {
	ctx := context.Background()

	t.Run("repeat reads hit the cache", func(t *testing.T) {
		reader, fetcher, _ := newGoldenReader(t, TreeReaderConfig{})
		if _, err := reader.GetInode(ctx, 4); err != nil {
			t.Fatal(err)
		}
		cold := fetcher.calls.Load()
		if cold == 0 {
			t.Fatal("no fetches on cold read")
		}
		for i := 0; i < 5; i++ {
			if _, err := reader.GetInode(ctx, 4); err != nil {
				t.Fatal(err)
			}
		}
		if fetcher.calls.Load() != cold {
			t.Fatalf("warm reads fetched (%d -> %d)", cold, fetcher.calls.Load())
		}
	})

	t.Run("disabled cache still verifies and serves", func(t *testing.T) {
		reader, fetcher, _ := newGoldenReader(t, TreeReaderConfig{CacheBytes: -1})
		if _, err := reader.GetInode(ctx, 4); err != nil {
			t.Fatal(err)
		}
		first := fetcher.calls.Load()
		if _, err := reader.GetInode(ctx, 4); err != nil {
			t.Fatal(err)
		}
		if fetcher.calls.Load() <= first {
			t.Fatal("cacheless reader did not refetch")
		}
	})

	t.Run("concurrent identical reads coalesce", func(t *testing.T) {
		reader, fetcher, _ := newGoldenReader(t, TreeReaderConfig{MaxConcurrentFetches: 4})
		fetcher.delay = 5 * time.Millisecond
		var wg sync.WaitGroup
		errs := make([]error, 32)
		for i := range errs {
			wg.Add(1)
			go func(slot int) {
				defer wg.Done()
				_, errs[slot] = reader.GetInode(ctx, 4)
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		// GetInode(4) touches exactly root, one index leaf, one inode: three
		// distinct objects, one fetch each regardless of 32 callers.
		if calls := fetcher.calls.Load(); calls != 3 {
			t.Fatalf("fetch calls %d, want 3", calls)
		}
	})

	t.Run("failed fetch is not cached", func(t *testing.T) {
		store := NewMemoryStore()
		rootRef := buildGoldenFilesystem(t, store)
		fetcher := &countingFetcher{store: store}
		reader, err := NewTreeReader(TreeReaderConfig{Fetcher: fetcher}, rootRef)
		if err != nil {
			t.Fatal(err)
		}
		// Corrupt, observe failure, restore, observe success.
		store.mu.Lock()
		original := append([]byte(nil), store.objects[rootRef]...)
		store.objects[rootRef][10] ^= 0x01
		store.mu.Unlock()
		if _, err := reader.GetInode(ctx, RootIno); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
		store.mu.Lock()
		store.objects[rootRef] = original
		store.mu.Unlock()
		if _, err := reader.GetInode(ctx, RootIno); err != nil {
			t.Fatalf("recovered read failed: %v", err)
		}
	})
}

func TestVerifyCellBytesSliceChecks(t *testing.T) {
	cellContent := make([]byte, CellBytes)
	copy(cellContent, []byte("payload"))
	store := NewMemoryStore()
	packer := NewCellPacker()
	if _, err := packer.Add(cellContent); err != nil {
		t.Fatal(err)
	}
	cells, err := packer.Finish(store)
	if err != nil {
		t.Fatal(err)
	}
	cell := cells[0]
	packBytes, err := store.Fetch(context.Background(), cell.Object)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCellBytes(&cell, packBytes, CellBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cellContent) {
		t.Fatal("cell bytes mismatch")
	}
	if _, err := VerifyCellBytes(&cell, packBytes[:len(packBytes)-1], CellBytes); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short pack accepted: %v", err)
	}
	flipped := append([]byte(nil), packBytes...)
	flipped[0] ^= 1
	if _, err := VerifyCellBytes(&cell, flipped, CellBytes); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("flipped pack accepted: %v", err)
	}
	if _, err := VerifyCellBytes(&cell, packBytes, CellBytes+1); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("oversized logical accepted: %v", err)
	}
}
