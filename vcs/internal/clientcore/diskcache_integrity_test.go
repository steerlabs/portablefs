package clientcore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestDiskCacheTruncatedBlockRefetches pins M2: a block file truncated/corrupted on disk must be
// treated as a miss and refetched from the authority, never served (GetRange's EOF-short rule would
// otherwise turn a truncated cache file into a silently shorter file — the Cache Rule violation).
func TestDiskCacheTruncatedBlockRefetches(t *testing.T) {
	ctx := context.Background()
	cacheDir := t.TempDir()

	blockA := make([]byte, DiskBlockSize)
	for i := range blockA {
		blockA[i] = 'a'
	}

	addr := serveCore(t)
	seed := dialCore(t, addr, Options{})
	a, st := seed.Create(ctx, "big", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := seed.Write(ctx, "big", n, 0, blockA); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	client := dialCore(t, addr, Options{DiskCacheDir: cacheDir, DiskCacheBytes: int64(DiskBlockSize * 4), VolumeID: "vol"})
	la, st := client.Lookup(ctx, "big")
	if st != fsproto.OK {
		t.Fatalf("lookup: %d", st)
	}
	cn := NewNodeState(la.Ino, la.Ino != 0)
	if data, st := client.Read(ctx, "big", cn, 0, DiskBlockSize); st != fsproto.OK || len(data) != DiskBlockSize {
		t.Fatalf("warm read: len=%d st=%d", len(data), st)
	}

	// Corrupt the cached block by truncating its file to a short prefix (well under one block).
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	truncated := 0
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		if err := os.Truncate(filepath.Join(cacheDir, e.Name()), 100); err != nil {
			t.Fatal(err)
		}
		truncated++
	}
	if truncated == 0 {
		t.Fatal("no cached block file to truncate")
	}

	data, st := client.Read(ctx, "big", cn, 0, DiskBlockSize)
	if st != fsproto.OK {
		t.Fatalf("read after truncation: st=%d", st)
	}
	if len(data) != DiskBlockSize {
		t.Fatalf("truncated block served as a short file: got len=%d want %d", len(data), DiskBlockSize)
	}
	for i, b := range data {
		if b != 'a' {
			t.Fatalf("byte %d = %q, want 'a' (refetch returned corrupt bytes)", i, b)
		}
	}
}

// TestDiskCacheRebuildDiscardsTruncatedBlock pins the M2 restart path: a block truncated on disk while
// the process was down must be dropped during index rebuild (its framed length disagrees with the file
// size), not rebuilt into the LRU where it could later be served as a short EOF block.
func TestDiskCacheRebuildDiscardsTruncatedBlock(t *testing.T) {
	dir := t.TempDir()
	c, err := NewDiskBlockCache(dir, int64(DiskBlockSize*4))
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 4096)
	for i := range block {
		block[i] = 'z'
	}
	c.Put("vol", 1, 7, 0, 3, block)
	if _, ok := c.Get("vol", 1, 7, 0, 3); !ok {
		t.Fatal("precondition: block should be cached")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		if err := os.Truncate(filepath.Join(dir, e.Name()), 100); err != nil {
			t.Fatal(err)
		}
	}

	reopened, err := NewDiskBlockCache(dir, int64(DiskBlockSize*4))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Get("vol", 1, 7, 0, 3); ok {
		t.Fatal("rebuild served a truncated block; it must be discarded and refetched")
	}
	if bytes, _ := reopened.Stats(); bytes != 0 {
		t.Fatalf("rebuild accounted a discarded block: bytes=%d", bytes)
	}
}

// TestDiskBlockCacheGetReinsertEvictsOverCap pins m4: when Get re-inserts a block that was found on
// disk but absent from the in-memory index, the re-insert must evict LRU tail if it pushes the cache
// over its byte budget.
func TestDiskBlockCacheGetReinsertEvictsOverCap(t *testing.T) {
	dir := t.TempDir()
	const S = 4096
	c, err := NewDiskBlockCache(dir, int64(2*S))
	if err != nil {
		t.Fatal(err)
	}
	block := func(b byte) []byte {
		x := make([]byte, S)
		for i := range x {
			x[i] = b
		}
		return x
	}
	// Fill the index to exactly the cap with two blocks.
	c.Put("vol", 1, 2, 0, 1, block('b'))
	c.Put("vol", 1, 3, 0, 1, block('c'))
	if bytes, capB := c.Stats(); bytes != int64(2*S) || capB != int64(2*S) {
		t.Fatalf("precondition: bytes=%d cap=%d, want both %d", bytes, capB, 2*S)
	}

	// Place a third block directly on disk but NOT in the index (the found-on-disk/untracked case).
	keyA := diskBlockKey("vol", 1, 4, 0, 1)
	if err := os.WriteFile(filepath.Join(dir, keyA), encodeDiskBlock(block('a')), 0o600); err != nil {
		t.Fatal(err)
	}

	// Get it: the re-insert would push the index to 3*S; it must evict back within budget.
	if got, ok := c.Get("vol", 1, 4, 0, 1); !ok || got[0] != 'a' {
		t.Fatalf("get untracked block: ok=%v first=%q", ok, got[:1])
	}
	if bytes, capB := c.Stats(); bytes > capB {
		t.Fatalf("Get re-insert left the cache over budget: bytes=%d cap=%d", bytes, capB)
	}
}
