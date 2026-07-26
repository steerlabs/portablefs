package workfs

// Resource contracts of the lazy PFT2 base:
//
//   - directory-emptiness probes stop at the FIRST proven entry instead of
//     loading unbounded children;
//   - no remote object fetch runs while fs.mu is held (read or write) on
//     the exercised lookup, listing, read, and managed mutation paths —
//     hydration and write-target warming run strictly outside the lock and
//     the locked apply hits warm caches.

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

func TestEmptinessProbeStopsAtFirstProvenEntry(t *testing.T) {
	// A directory with many base entries: deciding "non-empty" for rmdir
	// must prove ONE entry, never fetch a whole page of inode views.
	var records []wal.Record
	records = append(records, wal.Record{Op: wal.OpMkdir, Path: "big", Mode: 0o755})
	for i := 0; i < 600; i++ {
		records = append(records, wal.Record{
			Op: wal.OpCreate, Path: fmt.Sprintf("big/f%04d", i), Mode: 0o644,
		})
	}
	base := buildLazyTestBase(t, records)
	fs, fetcher := newLazyFS(t, base, newFakeEntryLog())

	before := fetcher.fetches()
	// rmdir of a non-empty directory: the apply needs the emptiness fact.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpRemove, Path: "big"}, nil, ""); err != nil {
		t.Fatalf("remove commit: %v", err)
	}
	delta := fetcher.fetches() - before
	// Budget: the "big" dirent + directory inode, one directory page of
	// names, ONE proven child inode view, and a handful of shared index
	// nodes. 600 views would blow far past this.
	if delta > 25 {
		t.Fatalf("emptiness probe fetched %d objects for a 600-entry directory; must stop at the first proven entry", delta)
	}

	// The tree is untouched: the rmdir outcome was deterministic ENOTEMPTY.
	if _, err := fs.Lstat("big/f0000"); err != nil {
		t.Fatalf("directory content lost after refused rmdir: %v", err)
	}
}

func TestEmptinessProbeCompletesTrulyEmptyDirectory(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpMkdir, Path: "empty", Mode: 0o755},
		{Op: wal.OpCreate, Path: "witness", Mode: 0o644},
	})
	fs, _ := newLazyFS(t, base, newFakeEntryLog())
	// rmdir of a base-empty directory succeeds: the probe exhausts the
	// (empty) enumeration, completes the directory, and the apply removes it.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpRemove, Path: "empty"}, nil, ""); err != nil {
		t.Fatalf("remove of empty directory: %v", err)
	}
	if _, err := fs.Lstat("empty"); err == nil {
		t.Fatal("empty directory still resolves after rmdir")
	}
}

func TestNoRemoteFetchEverRunsUnderFsMu(t *testing.T) {
	// The fetch hook proves the lock discipline: operations run serially, so
	// a failed TryLock during a fetch means the FETCHING call stack itself
	// holds fs.mu (read or write) — exactly the contract violation.
	const fileSize = 6 << 20 // dense multi-block file (block = 4 MiB)
	content := bytes.Repeat([]byte{'D'}, fileSize)
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpMkdir, Path: "dir/sub", Mode: 0o755},
		{Op: wal.OpCreate, Path: "dir/sub/data.bin", Mode: 0o644},
		{Op: wal.OpWrite, Path: "dir/sub/data.bin", Data: content},
		{Op: wal.OpCreate, Path: "dir/sub/other", Mode: 0o644},
		{Op: wal.OpMkdir, Path: "victim", Mode: 0o755},
	})
	fs, fetcher := newLazyFS(t, base, newFakeEntryLog())

	var violations atomic.Int64
	fetcher.setOnFetch(func() {
		if fs.mu.TryLock() {
			fs.mu.Unlock()
		} else {
			violations.Add(1)
		}
	})

	// Managed mutations over the COLD lazy base first: the partial write's
	// read-modify-write is the FIRST touch of its base blocks, so without
	// the outside-lock warm pass the locked apply itself would have to
	// fetch the packs remotely — exactly the violation the hook detects.
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "dir/sub/new", Mode: 0o644})
	commitTree(t, fs, wal.Record{Op: wal.OpWrite, Path: "dir/sub/data.bin", Offset: (4 << 20) + 100, Data: []byte("partial-overwrite")})
	commitTree(t, fs, wal.Record{Op: wal.OpRename, Path: "dir/sub/other", NewPath: "dir/sub/renamed"})
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpRemove, Path: "dir"}, nil, ""); err != nil {
		t.Fatalf("rmdir refusal: %v", err)
	}

	// Read paths: lookup + stat (dirent hydration), full listing (paged
	// load), and a ranger read of a still-cold region.
	if _, err := fs.Lstat("dir/sub/data.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadDir("dir/sub"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128<<10)
	h, err := fs.Open("dir/sub/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadAt(buf, 1<<20); err != nil {
		t.Fatal(err)
	}
	_ = h.Close()

	if n := violations.Load(); n != 0 {
		t.Fatalf("%d remote fetches ran while fs.mu was held", n)
	}
	if fetcher.fetches() == 0 {
		t.Fatal("test exercised no fetches; the contract was not actually probed")
	}
}
