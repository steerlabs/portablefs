package workfs

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func wantDirty(t *testing.T, fs *FS, want int64, step string) {
	t.Helper()
	if got := fs.DirtyBlockBytes(); got != want {
		t.Fatalf("%s: dirty-block bytes = %d, want %d", step, got, want)
	}
}

func dirtyReservedOf(fs *FS) int64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.dirtyReserved
}

func inoOf(t *testing.T, fs *FS, name string) uint64 {
	t.Helper()
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n := fs.resolve(name)
	if n == nil {
		t.Fatalf("no inode at %s", name)
	}
	return n.ino
}

// backedFixture builds a chunked backed file of nblk full blocks, returning
// the manifest entry and a blob store serving its chunks.
func backedFixture(nblk int, name string) ([]backend.Entry, *fakeBlobs) {
	data := map[string][]byte{}
	var chunks []backend.Chunk
	for i := 0; i < nblk; i++ {
		blk := bytes.Repeat([]byte{byte('A' + i)}, blockSize)
		d := digestOf(blk)
		data[d] = blk
		chunks = append(chunks, backend.Chunk{Digest: d, Size: blockSize, Offset: int64(i) * blockSize})
	}
	entries := []backend.Entry{{
		Path: name, Kind: "file", Mode: 0o644, Size: int64(nblk) * blockSize, Chunks: chunks,
	}}
	return entries, &fakeBlobs{data: data}
}

// TestDirtyAccountingExactAcrossLifecycles walks the counter through every
// release path a WAL-store volume has: overwrite, grow, sparse write,
// truncate shrink/zero, remove, rename-over, orphan park + reap, and the
// checkpoint fold (MarkClean). Any leak here would eventually wedge the
// bound closed on memory that was actually freed.
func TestDirtyAccountingExactAcrossLifecycles(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	wantDirty(t, fs, 0, "fresh volume")

	if _, _, err := fs.WriteAt("a.txt", 0, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 5, "born 5-byte write")
	if _, _, err := fs.WriteAt("a.txt", 0, []byte("HEL"), 0); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 5, "in-place overwrite grows nothing")
	if _, _, err := fs.WriteAt("a.txt", 5, []byte("xyz"), 0); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 8, "append grows by 3")
	if _, _, err := fs.WriteAt("a.txt", 2*blockSize+7, []byte("Z"), 0); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 16, "sparse write materialises only its short tail block")

	if err := fs.TruncateAs("a.txt", 3, ""); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 3, "shrink drops past-EOF blocks and trims the boundary")
	if err := fs.TruncateAs("a.txt", 0, ""); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 0, "truncate to zero releases everything")

	if _, _, err := fs.WriteAt("a.txt", 0, bytes.Repeat([]byte("x"), 10), 0); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 10, "rewrite after zero-truncate")
	if err := fs.Remove("a.txt"); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 0, "remove destroys the inode and releases its blocks")

	// Rename over an existing (not-open) destination destroys the replaced inode.
	if _, _, err := fs.WriteAt("src", 0, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fs.WriteAt("dst", 0, []byte("1234567"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 12, "two dirty files")
	if err := fs.Rename("src", "dst"); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 5, "rename-over releases the clobbered destination")
	if err := fs.Remove("dst"); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 0, "cleanup")

	// Open-after-unlink: parking keeps the blocks resident (the handle still
	// reads/writes them); only the reap releases.
	if _, _, err := fs.WriteAt("o.txt", 0, []byte("orphan"), 0o644); err != nil {
		t.Fatal(err)
	}
	ino := inoOf(t, fs, "o.txt")
	if err := fs.mutate(wal.Record{Op: wal.OpOrphan, Path: "o.txt"}); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 6, "parked orphan stays resident")
	if err := fs.mutate(wal.Record{Op: wal.OpReap, Ino: ino}); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 0, "reap destroys the orphan")

	// Checkpoint fold: MarkClean rebinds to the committed base and releases.
	payload := []byte("clean")
	if _, _, err := fs.WriteAt("m.txt", 0, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 5, "pre-checkpoint dirty file")
	snap := fs.Snapshot()
	fs.MarkClean(snap, "m.txt", content.Source{BlobDigest: digestOf(payload), BlobSize: 5, Size: 5})
	wantDirty(t, fs, 0, "checkpoint fold releases the committed blocks")
}

// TestDirtyAccountingWholeBlockFill pins the amplification pathology the
// bound exists for: ONE byte written into a fresh region of a backed file
// accounts a WHOLE 4 MiB block (the read-modify-write materialises the full
// block), i.e. ~40 journal bytes cost blockSize resident bytes.
func TestDirtyAccountingWholeBlockFill(t *testing.T) {
	entries, blobs := backedFixture(3, "big.bin")
	fs, _ := newFS(t, entries, blobs)
	wantDirty(t, fs, 0, "backed base is not dirty")

	if _, _, err := fs.WriteAt("big.bin", blockSize+100, []byte{'Z'}, 0); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, blockSize, "1 byte into a fresh backed region accounts one whole block")

	if _, _, err := fs.WriteAt("big.bin", blockSize+200, []byte{'Q'}, 0); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, blockSize, "a second byte into the SAME block adds nothing")
}

func assertDirtyCapacityRefusal(t *testing.T, err error, step string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: write past the dirty bound was admitted", step)
	}
	if !errors.Is(err, ErrDirtyRSSCapacity) {
		t.Fatalf("%s: error = %v, want ErrDirtyRSSCapacity", step, err)
	}
	if !errors.Is(err, ErrWALCapacity) {
		t.Fatalf("%s: refusal does not chain to ErrWALCapacity (loses the definite-ENOSPC wire classification)", step)
	}
	if got := errnos.Of(err); got != errnos.ENOSPC {
		t.Fatalf("%s: wire errno = %d, want ENOSPC (%d)", step, got, errnos.ENOSPC)
	}
}

// TestDirtyBoundRefusesAndRecovers (WAL store): writes refuse at the bound
// with the ENOSPC capacity shape; releases keep working and reopen admission
// — the volume is never wedged.
func TestDirtyBoundRefusesAndRecovers(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	fs.SetDirtyRSSMax(2 * blockSize)

	block := bytes.Repeat([]byte("b"), blockSize)
	if _, _, err := fs.WriteAt("f1", 0, block, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fs.WriteAt("f2", 0, block, 0o644); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 2*blockSize, "filled to the bound")

	_, _, err := fs.WriteAt("f3", 0, block, 0o644)
	assertDirtyCapacityRefusal(t, err, "third block write")
	// The implicit create (0 dirty bytes) landed; the refused WRITE did not.
	if fi, statErr := fs.Stat("f3"); statErr != nil || fi.Size() != 0 {
		t.Fatalf("refused write leaked bytes: stat = %v, %v", fi, statErr)
	}
	wantDirty(t, fs, 2*blockSize, "refusal applied nothing")

	// Reads and metadata ops keep serving at the bound.
	if got := readFile(t, fs, "f1"); got != string(block) {
		t.Fatal("read at the bound returned wrong bytes")
	}
	if err := fs.Rename("f2", "f2b"); err != nil {
		t.Fatalf("metadata op at the bound: %v", err)
	}

	// A flushed write-back batch refuses the same way.
	batchErr := fs.ApplyBatch([]wal.Record{{Op: wal.OpWrite, Path: "f1", Offset: 0, Data: block}}, "mount-1")
	assertDirtyCapacityRefusal(t, batchErr, "write-back flush at the bound")

	// Releasing memory reopens admission.
	if err := fs.Remove("f1"); err != nil {
		t.Fatalf("remove at the bound must succeed: %v", err)
	}
	wantDirty(t, fs, blockSize, "remove released one block")
	if _, _, err := fs.WriteAt("f3", 0, block, 0o644); err != nil {
		t.Fatalf("write after release: %v", err)
	}
	wantDirty(t, fs, 2*blockSize, "admission reopened")
	if reserved := dirtyReservedOf(fs); reserved != 0 {
		t.Fatalf("WAL store must not hold reservations, got %d", reserved)
	}
}

func managedWrite(fs *FS, path string, off int64, data []byte) error {
	_, err := fs.CommitEntry(&wal.Record{Op: wal.OpWrite, Path: path, Offset: off, Data: data}, nil, "")
	return err
}

// TestDirtyBoundManagedRefusesReleasesAndReplays exercises the managed
// (journal-native) store — the child that never checkpoints in-process, so
// the bound is its only dirty-memory backstop: whole-block amplification
// fills the bound, the refusal is a definite pre-reservation ENOSPC, control
// rows still commit at the bound, truncation reopens admission, and a cold
// replay of the identical journal rebuilds the exact counter.
func TestDirtyBoundManagedRefusesReleasesAndReplays(t *testing.T) {
	entries, blobs := backedFixture(4, "big.bin")
	log := newFakeEntryLog()
	fs, err := NewManaged(entries, blobs, log)
	if err != nil {
		t.Fatal(err)
	}
	fs.SetDirtyRSSMax(2 * blockSize)

	if err := managedWrite(fs, "big.bin", 100, []byte{'X'}); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, blockSize, "1 amplified byte in block 0")
	if err := managedWrite(fs, "big.bin", blockSize+100, []byte{'Y'}); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 2*blockSize, "1 amplified byte in block 1: at the bound")

	refusal := managedWrite(fs, "big.bin", 2*blockSize+100, []byte{'Z'})
	assertDirtyCapacityRefusal(t, refusal, "managed write past the bound")
	wantDirty(t, fs, 2*blockSize, "refusal applied nothing")
	if reserved := dirtyReservedOf(fs); reserved != 0 {
		t.Fatalf("refused reservation leaked: %d", reserved)
	}
	if got := log.Watermark(); got != 2 {
		t.Fatalf("refusal must be pre-reservation (nothing journaled): watermark = %d, want 2", got)
	}

	// Control-only rows (exactness, sessions, locks) ride free at the bound,
	// like the journal control reserve: the volume can still record
	// outcomes and terminalize sessions while writes are refused.
	openManagedSession(t, fs, "pfs-dirty", 1)

	// Releasing memory reopens admission.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpTruncate, Path: "big.bin", Size: blockSize}, nil, ""); err != nil {
		t.Fatalf("truncate at the bound must succeed: %v", err)
	}
	wantDirty(t, fs, blockSize, "truncate released block 1")
	if err := managedWrite(fs, "big.bin", 100, []byte{'W'}); err != nil {
		t.Fatalf("write after release: %v", err)
	}
	wantDirty(t, fs, blockSize, "overwrite of the resident block grows nothing")

	// Cold replay of the identical durable rows rebuilds the exact counter —
	// the bound is generation-portable because the accounting is replayed
	// state, not process history.
	replayed, err := NewManaged(entries, blobs, log)
	if err != nil {
		t.Fatal(err)
	}
	wantDirty(t, replayed, fs.DirtyBlockBytes(), "cold replay")

	// A bound LOWERED to the replayed residency loads fine (replay never
	// refuses), refuses new writes, and recovers through release. blockSize
	// is the smallest admissible bound: every write reserves at least one
	// whole block, so a smaller bound would refuse everything forever.
	replayed.SetDirtyRSSMax(blockSize)
	lowErr := managedWrite(replayed, "big.bin", blockSize+100, []byte{'L'})
	assertDirtyCapacityRefusal(t, lowErr, "write on an over-bound replayed volume")
	if _, err := replayed.CommitEntry(&wal.Record{Op: wal.OpTruncate, Path: "big.bin", Size: 0}, nil, ""); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, replayed, 0, "over-bound volume recovered by truncate")
	if err := managedWrite(replayed, "big.bin", 0, []byte("ok")); err != nil {
		t.Fatalf("write after recovering under the lowered bound: %v", err)
	}
}

// TestDirtyBoundConcurrentWritersNeverOvershoot races writers against the
// managed check-and-reserve admission: the reservation is taken under the
// same fs.mu hold that admits the row, so N racing writers can never all
// pass one stale check (TOCTOU) and collectively overshoot at their apply
// turns. Run with -race.
func TestDirtyBoundConcurrentWritersNeverOvershoot(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	const bound = 2 * blockSize
	fs.SetDirtyRSSMax(bound)

	const writers = 8
	const rounds = 6
	payload := bytes.Repeat([]byte("p"), 64<<10)
	var wg sync.WaitGroup
	errCh := make(chan error, writers*rounds*2)
	successes := make([]int64, writers)
	for w := 0; w < writers; w++ {
		path := fmt.Sprintf("w%d.bin", w)
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: path, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(w int, path string) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				err := managedWrite(fs, path, 0, payload)
				switch {
				case err == nil:
					successes[w]++
				case errors.Is(err, ErrDirtyRSSCapacity):
					// The only legitimate refusal near the bound.
				default:
					errCh <- fmt.Errorf("writer %d round %d: %v", w, r, err)
					return
				}
				if got := fs.DirtyBlockBytes(); got > bound {
					errCh <- fmt.Errorf("writer %d round %d: dirty %d overshot bound %d", w, r, got, bound)
					return
				}
				if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpTruncate, Path: path, Size: 0}, nil, ""); err != nil {
					errCh <- fmt.Errorf("writer %d round %d truncate: %v", w, r, err)
					return
				}
			}
		}(w, path)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	wantDirty(t, fs, 0, "every surviving block was truncated away")
	if reserved := dirtyReservedOf(fs); reserved != 0 {
		t.Fatalf("reservations did not drain: %d", reserved)
	}
	var total int64
	for _, s := range successes {
		total += s
	}
	if total == 0 {
		t.Fatal("no write ever succeeded under the bound")
	}
}

// TestDirtyWriteReserveDominates pins the estimator's shape: it must be a
// state-independent ceiling on apply-time growth (block-span times
// blockSize; append pays one extra straddle block), because on the managed
// store rows apply after admission against a tree other rows have moved.
func TestDirtyWriteReserveDominates(t *testing.T) {
	cases := []struct {
		name string
		r    wal.Record
		want int64
	}{
		{"empty write", wal.Record{Op: wal.OpWrite}, 0},
		{"one byte", wal.Record{Op: wal.OpWrite, Data: []byte{1}}, blockSize},
		{"straddles a boundary", wal.Record{Op: wal.OpWrite, Offset: blockSize - 1, Data: []byte{1, 2}}, 2 * blockSize},
		{"exactly one block", wal.Record{Op: wal.OpWrite, Data: make([]byte, blockSize)}, blockSize},
		{"one block plus a byte", wal.Record{Op: wal.OpWrite, Data: make([]byte, blockSize+1)}, 2 * blockSize},
		{"append pays the straddle", wal.Record{Op: wal.OpWrite, Append: true, Data: []byte{1}}, 2 * blockSize},
		{"truncate reserves nothing", wal.Record{Op: wal.OpTruncate, Size: 1}, 0},
	}
	for _, tc := range cases {
		if got := dirtyWriteReserve(&tc.r); got != tc.want {
			t.Errorf("%s: reserve = %d, want %d", tc.name, got, tc.want)
		}
	}
}
