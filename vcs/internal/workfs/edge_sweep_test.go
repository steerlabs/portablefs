package workfs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// timeMillis is a tiny wrapper so the chtimes assertions read clearly.
func timeMillis(ms int64) time.Time { return time.UnixMilli(ms) }

// edge_sweep_test.go is an exhaustive boundary + concurrency sweep of the authority
// FS block-addressed content store (blocks.go, blockSize = 4 MiB) reached only via
// the public API (billy.File / FS methods / ApplyBatch). It deliberately overlaps the
// existing block tests on intent but pushes every boundary to its extreme: zero/one/
// huge, exactly-at and ±1 of a block edge, partial vs full overwrite, holes, grow /
// shrink / truncate-to-0, base-fetch vs born-dirty, batch atomicity, and a -race
// reconstruction-vs-flat-array check.

// ---- shared fixtures ----------------------------------------------------------

// newWAL opens a fresh WAL under a temp dir (the helpers in this package's other test
// files take a *fakeBlobs; here we sometimes want a countingBlobs, so build directly).
func newWAL(t *testing.T) (*wal.WAL, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wal.log")
	w, err := wal.Open(p)
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	return w, p
}

// blockChunkedBackedFile builds a backed source for `content`, laid out as one chunk
// per blockSize-aligned block (mirrors the manifest a chunked-checkpoint emits and
// what TestPartialWriteFetchesOnlyTouchedBlock relies on). It returns the manifest
// entry plus a populated blob map keyed by the real per-chunk digest, so the content
// layer's read-time digest verification passes.
func blockChunkedBackedFile(path string, content []byte) (backend.Entry, map[string][]byte) {
	data := map[string][]byte{}
	var chunks []backend.Chunk
	for off := 0; off < len(content); off += blockSize {
		end := off + blockSize
		if end > len(content) {
			end = len(content)
		}
		blk := append([]byte(nil), content[off:end]...)
		d := digestOf(blk)
		data[d] = blk
		chunks = append(chunks, backend.Chunk{Digest: d, Size: int64(len(blk)), Offset: int64(off)})
	}
	e := backend.Entry{Path: path, Kind: "file", Mode: 0o644, Size: int64(len(content)), Chunks: chunks}
	return e, data
}

// wholeBlobBackedFile builds a single whole-file-blob backed source (no chunks).
func wholeBlobBackedFile(path string, content []byte) (backend.Entry, map[string][]byte) {
	d := digestOf(content)
	return backend.Entry{
		Path: path, Kind: "file", Mode: 0o644, Size: int64(len(content)),
		BlobDigest: d, BlobSize: int64(len(content)),
	}, map[string][]byte{d: append([]byte(nil), content...)}
}

// readAll reads a whole file via ReadAt windows so a short Read loop can't confuse the
// assertion; it returns the exact `size` bytes the file reports.
func readAllAt(t *testing.T, fs *FS, name string) []byte {
	t.Helper()
	fi, err := fs.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	f, err := fs.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	out := make([]byte, fi.Size())
	n, err := f.ReadAt(out, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("readAt %s: %v", name, err)
	}
	return out[:n]
}

// writeAt opens the file RDWR (creating it if missing), writes at off, closes.
func writeAtPath(t *testing.T, fs *FS, name string, off int64, data []byte) {
	t.Helper()
	f, err := fs.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		t.Fatalf("seek %s: %v", name, err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

// ---- single + multi-block write/read round-trips -------------------------------

// TestBornFileSingleAndMultiBlockRoundTrip: a freshly created (born, no base) file
// round-trips byte-for-byte across a sub-block payload, exactly one block, exactly one
// block + 1, and several blocks — the dirty-block path with no base reads.
func TestBornFileSingleAndMultiBlockRoundTrip(t *testing.T) {
	sizes := []int64{
		0,                  // empty
		1,                  // one byte
		blockSize - 1,      // last byte of block 0
		blockSize,          // exactly one block
		blockSize + 1,      // first byte of block 1
		2*blockSize - 1,    // last byte of block 1
		2 * blockSize,      // exactly two blocks
		3*blockSize + 1234, // several blocks + remainder
	}
	for _, size := range sizes {
		size := size
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			w, _ := newWAL(t)
			fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
			if err != nil {
				t.Fatal(err)
			}
			want := make([]byte, size)
			for i := range want {
				want[i] = byte(i*7 + 13) // deterministic, spans all byte values
			}
			f, err := fs.Create("f.bin")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write(want); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if fi, _ := fs.Stat("f.bin"); fi.Size() != size {
				t.Fatalf("size = %d, want %d", fi.Size(), size)
			}
			if got := readAllAt(t, fs, "f.bin"); !bytes.Equal(got, want) {
				t.Fatalf("round-trip mismatch at size %d (len got=%d)", size, len(got))
			}
		})
	}
}

// TestPartialOverwritePreservesUntouchedBytesFromBase: a partial (read-modify-write)
// overwrite at a range INSIDE a backed multi-block file preserves every untouched byte,
// across writes that (a) sit wholly inside one block, (b) straddle a 4 MiB boundary,
// (c) start exactly on a boundary, (d) end exactly on a boundary, and (e) span >2 blocks.
func TestPartialOverwritePreservesUntouchedBytesFromBase(t *testing.T) {
	const fileSize = 3*blockSize + 777
	base := make([]byte, fileSize)
	for i := range base {
		base[i] = byte('a' + i%26)
	}
	type wr struct {
		name string
		off  int64
		data []byte
	}
	mk := func(n int, c byte) []byte { return bytes.Repeat([]byte{c}, n) }
	cases := []wr{
		{"inside-block0", 100, mk(50, '#')},
		{"straddle-b0b1", blockSize - 3, mk(6, '@')},                 // 3 bytes each side of the edge
		{"start-on-b1", blockSize, mk(10, '$')},                      // exactly the first byte of block 1
		{"end-on-b1", blockSize - 8, mk(8, '%')},                     // ends exactly at the block-1 edge
		{"span-three-blocks", blockSize - 1, mk(2*blockSize+2, '^')}, // touches blocks 0,1,2,3
		{"last-partial-block", 3*blockSize + 100, mk(77, '&')},       // inside the short final block
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			entry, blobs := blockChunkedBackedFile("big.bin", base)
			w, _ := newWAL(t)
			fs, err := New([]backend.Entry{entry}, &fakeBlobs{data: blobs}, w)
			if err != nil {
				t.Fatal(err)
			}
			writeAtPath(t, fs, "big.bin", c.off, c.data)

			want := append([]byte(nil), base...)
			copy(want[c.off:], c.data)
			got := readAllAt(t, fs, "big.bin")
			if !bytes.Equal(got, want) {
				// Find the first divergence for a precise message.
				idx := firstDiff(got, want)
				t.Fatalf("partial overwrite %q corrupted untouched bytes; first diff at %d (got %d want %d)",
					c.name, idx, byteAt(got, idx), byteAt(want, idx))
			}
		})
	}
}

// TestPartialOverwriteOnPriorDirtyBlock: the read-modify-write must preserve untouched
// bytes when the block is ALREADY dirty (born or previously written), not just when it
// is fetched from a base. Two overlapping writes into the same block must compose; the
// second must not clobber the first's bytes outside its own range.
func TestPartialOverwriteOnPriorDirtyBlock(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	// First write establishes a dirty block 0 spanning [0,1000).
	first := bytes.Repeat([]byte{'A'}, 1000)
	writeAtPath(t, fs, "f", 0, first)
	// Second write overwrites a window in the MIDDLE; the surrounding 'A's must remain.
	mid := bytes.Repeat([]byte{'B'}, 100)
	writeAtPath(t, fs, "f", 400, mid)

	want := append([]byte(nil), first...)
	copy(want[400:500], mid)
	if got := readAllAt(t, fs, "f"); !bytes.Equal(got, want) {
		t.Fatalf("overlapping dirty-block writes diverged at %d", firstDiff(got, want))
	}

	// A third write EXTENDS block 0 within its trailing hole region then reads back: the
	// bytes between the old end and the new write are a hole (zeros), not stale data.
	writeAtPath(t, fs, "f", 2000, []byte("Z"))
	got := readAllAt(t, fs, "f")
	if int64(len(got)) != 2001 {
		t.Fatalf("size after extend = %d, want 2001", len(got))
	}
	for i := 1000; i < 2000; i++ {
		if got[i] != 0 {
			t.Fatalf("gap byte %d = %d, want 0 (hole)", i, got[i])
		}
	}
	if got[2000] != 'Z' {
		t.Fatalf("extended byte = %q, want Z", got[2000])
	}
}

// TestSparseWritesAcrossMultipleBlocksReadAsZeros: writes scattered into distinct,
// non-adjacent blocks of a born file leave every untouched block (and intra-block gap)
// reading as zero, and allocate ONLY the written blocks.
func TestSparseWritesAcrossMultipleBlocksReadAsZeros(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	// Write one byte into blocks 0, 2, and 5 (leaving 1, 3, 4 as holes).
	type p struct {
		off int64
		b   byte
	}
	writes := []p{{7, 'P'}, {2*blockSize + 9, 'Q'}, {5*blockSize + 3, 'R'}}
	for _, wr := range writes {
		writeAtPath(t, fs, "sparse.bin", wr.off, []byte{wr.b})
	}
	wantSize := int64(5*blockSize + 4)
	if fi, _ := fs.Stat("sparse.bin"); fi.Size() != wantSize {
		t.Fatalf("size = %d, want %d", fi.Size(), wantSize)
	}
	got := readAllAt(t, fs, "sparse.bin")
	written := map[int64]byte{7: 'P', 2*blockSize + 9: 'Q', 5*blockSize + 3: 'R'}
	for i := int64(0); i < wantSize; i++ {
		want := byte(0)
		if b, ok := written[i]; ok {
			want = b
		}
		if got[i] != want {
			t.Fatalf("sparse byte %d = %d, want %d", i, got[i], want)
		}
	}

	// Only blocks 0, 2, 5 are materialised (snapshot exposes the dirty block map).
	for _, e := range fs.Snapshot().Entries {
		if e.Path != "sparse.bin" {
			continue
		}
		if len(e.Blocks) != 3 {
			t.Fatalf("materialised %d blocks, want 3 (sparse holes must not allocate)", len(e.Blocks))
		}
		for _, bi := range []int64{0, 2, 5} {
			if _, ok := e.Blocks[bi]; !ok {
				t.Fatalf("block %d not materialised", bi)
			}
		}
	}
}

// TestReadPastEOFAndAtExactSize: a read whose offset is at OR past size returns
// (0, io.EOF); a read of the final byte returns it with io.EOF; a read window that
// overshoots size is clipped to the valid bytes.
func TestReadPastEOFAndAtExactSize(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte{'x'}, blockSize+5) // crosses a block boundary
	writeAtPath(t, fs, "f", 0, content)
	size := int64(len(content))

	f, err := fs.Open("f")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// At exact size: EOF, zero bytes.
	if n, err := f.ReadAt(make([]byte, 16), size); n != 0 || err != io.EOF {
		t.Fatalf("read at size: n=%d err=%v, want 0, EOF", n, err)
	}
	// Past size: EOF, zero bytes.
	if n, err := f.ReadAt(make([]byte, 16), size+blockSize); n != 0 || err != io.EOF {
		t.Fatalf("read past size: n=%d err=%v, want 0, EOF", n, err)
	}
	// Window overshoots size: clipped to the tail, EOF.
	buf := make([]byte, 100)
	n, err := f.ReadAt(buf, size-3)
	if err != io.EOF {
		t.Fatalf("overshoot read err=%v, want EOF", err)
	}
	if n != 3 || !bytes.Equal(buf[:n], []byte("xxx")) {
		t.Fatalf("overshoot read n=%d buf=%q, want 3 xxx", n, buf[:n])
	}
	// The exact final byte.
	one := make([]byte, 1)
	if n, err := f.ReadAt(one, size-1); n != 1 || (err != nil && err != io.EOF) || one[0] != 'x' {
		t.Fatalf("final-byte read n=%d err=%v b=%q", n, err, one)
	}
}

// TestReadAtExactBlockBoundaryOffsets: reads that begin exactly on a block boundary,
// one byte before it, and one byte after it reconstruct correctly from a backed file
// whose adjacent blocks hold DIFFERENT content (so a mis-placed block is detected).
func TestReadAtExactBlockBoundaryOffsets(t *testing.T) {
	// block0 = all 'A', block1 = all 'B', block2 = short tail of 'C'.
	base := make([]byte, 2*blockSize+100)
	for i := 0; i < blockSize; i++ {
		base[i] = 'A'
	}
	for i := blockSize; i < 2*blockSize; i++ {
		base[i] = 'B'
	}
	for i := 2 * blockSize; i < len(base); i++ {
		base[i] = 'C'
	}
	entry, blobs := blockChunkedBackedFile("abc.bin", base)
	w, _ := newWAL(t)
	fs, err := New([]backend.Entry{entry}, &fakeBlobs{data: blobs}, w)
	if err != nil {
		t.Fatal(err)
	}
	f, err := fs.Open("abc.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	check := func(off int64, want []byte) {
		buf := make([]byte, len(want))
		if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
			t.Fatalf("read at %d: %v", off, err)
		}
		if !bytes.Equal(buf, want) {
			t.Fatalf("read at %d = %q, want %q", off, buf, want)
		}
	}
	check(blockSize-1, []byte("ABB")) // last A, then two B's across the edge
	check(blockSize, []byte("BBB"))   // exactly block 1
	check(blockSize+1, []byte("BBB"))
	check(2*blockSize-1, []byte("BCC")) // last B, two C's across the second edge
	check(2*blockSize, []byte("CCC"))
}

// ---- truncate: grow / shrink / to-zero / boundary -----------------------------

// TestTruncateGrowShrinkAndToZero exercises every truncate regime against a backed
// multi-block file: shrink to a sub-block size, shrink to an exact block boundary,
// grow (the gap reads as a hole), truncate to 0 (born reset), and grow-from-zero.
func TestTruncateGrowShrinkAndToZero(t *testing.T) {
	const fileSize = 2*blockSize + 500
	base := make([]byte, fileSize)
	for i := range base {
		base[i] = byte('A' + i%26)
	}

	t.Run("shrink-into-block0", func(t *testing.T) {
		fs := backedFS(t, "f", base)
		truncate(t, fs, "f", 10)
		got := readAllAt(t, fs, "f")
		if !bytes.Equal(got, base[:10]) {
			t.Fatalf("shrink(10) = %q, want %q", got, base[:10])
		}
	})

	t.Run("shrink-to-exact-block-boundary", func(t *testing.T) {
		fs := backedFS(t, "f", base)
		truncate(t, fs, "f", blockSize)
		got := readAllAt(t, fs, "f")
		if int64(len(got)) != blockSize || !bytes.Equal(got, base[:blockSize]) {
			t.Fatalf("shrink to one block: len=%d, content mismatch=%v", len(got), !bytes.Equal(got, base[:blockSize]))
		}
		// A read at the new EOF is empty.
		f, _ := fs.Open("f")
		defer f.Close()
		if n, err := f.ReadAt(make([]byte, 4), blockSize); n != 0 || err != io.EOF {
			t.Fatalf("read at new EOF: n=%d err=%v", n, err)
		}
	})

	t.Run("shrink-by-one-byte", func(t *testing.T) {
		fs := backedFS(t, "f", base)
		truncate(t, fs, "f", fileSize-1)
		got := readAllAt(t, fs, "f")
		if !bytes.Equal(got, base[:fileSize-1]) {
			t.Fatalf("shrink by 1 mismatch at %d", firstDiff(got, base[:fileSize-1]))
		}
	})

	t.Run("grow-leaves-hole", func(t *testing.T) {
		fs := backedFS(t, "f", base)
		grown := int64(fileSize + blockSize + 9)
		truncate(t, fs, "f", grown)
		got := readAllAt(t, fs, "f")
		if int64(len(got)) != grown {
			t.Fatalf("grow size = %d, want %d", len(got), grown)
		}
		if !bytes.Equal(got[:fileSize], base) {
			t.Fatalf("grow corrupted original bytes at %d", firstDiff(got[:fileSize], base))
		}
		for i := int64(fileSize); i < grown; i++ {
			if got[i] != 0 {
				t.Fatalf("grown hole byte %d = %d, want 0", i, got[i])
			}
		}
	})

	t.Run("truncate-to-zero-is-born-reset", func(t *testing.T) {
		fs := backedFS(t, "f", base)
		truncate(t, fs, "f", 0)
		if fi, _ := fs.Stat("f"); fi.Size() != 0 {
			t.Fatalf("size after trunc(0) = %d, want 0", fi.Size())
		}
		// Reads return nothing; the snapshot shows the file dirty (born) with no source.
		f, _ := fs.Open("f")
		defer f.Close()
		if n, err := f.ReadAt(make([]byte, 4), 0); n != 0 || err != io.EOF {
			t.Fatalf("read empty: n=%d err=%v", n, err)
		}
		for _, e := range fs.Snapshot().Entries {
			if e.Path == "f" {
				if !e.Dirty || e.Source.Size != 0 || e.Size != 0 {
					t.Fatalf("trunc(0) entry = %+v, want dirty born-empty (no source)", e)
				}
			}
		}
		// Grow-from-zero then write near the end: a fresh hole + a single block.
		writeAtPath(t, fs, "f", blockSize+3, []byte("ZZ"))
		got := readAllAt(t, fs, "f")
		if int64(len(got)) != blockSize+5 {
			t.Fatalf("size after grow-from-zero = %d, want %d", len(got), blockSize+5)
		}
		for i := int64(0); i < blockSize+3; i++ {
			if got[i] != 0 {
				t.Fatalf("byte %d = %d, want 0 (born-reset hole)", i, got[i])
			}
		}
		if got[blockSize+3] != 'Z' || got[blockSize+4] != 'Z' {
			t.Fatalf("written bytes = %q%q, want ZZ", got[blockSize+3:blockSize+4], got[blockSize+4:blockSize+5])
		}
	})

	t.Run("truncate-to-same-size-is-noop", func(t *testing.T) {
		fs := backedFS(t, "f", base)
		truncate(t, fs, "f", fileSize)
		if got := readAllAt(t, fs, "f"); !bytes.Equal(got, base) {
			t.Fatalf("trunc to same size changed content at %d", firstDiff(got, base))
		}
	})
}

// TestTruncateThenReadFromBaseStillSeesBase: after shrinking a backed file to a size
// that still includes UN-materialised blocks, those blocks must still resolve from the
// base — truncate must not strand the base.
func TestTruncateThenReadFromBaseStillSeesBase(t *testing.T) {
	const fileSize = 3 * blockSize
	base := make([]byte, fileSize)
	for i := range base {
		base[i] = byte('a' + i%26)
	}
	fs := backedFS(t, "f", base)
	// Shrink to span exactly blocks 0..1 (block 2's data is dropped); blocks 0,1 are
	// never materialised so they must still come from the base after the truncate.
	truncate(t, fs, "f", 2*blockSize)
	got := readAllAt(t, fs, "f")
	if !bytes.Equal(got, base[:2*blockSize]) {
		t.Fatalf("post-shrink base read diverged at %d", firstDiff(got, base[:2*blockSize]))
	}
}

// ---- idempotency / delete-then-recreate / duplicate -----------------------------

// TestDeleteThenRecreateResetsContent: removing a file then creating it anew yields a
// fresh empty (born) file — none of the old bytes survive.
func TestDeleteThenRecreateResetsContent(t *testing.T) {
	const fileSize = blockSize + 256
	base := make([]byte, fileSize)
	for i := range base {
		base[i] = 'Z'
	}
	fs := backedFS(t, "doomed.bin", base)
	if err := fs.Remove("doomed.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat("doomed.bin"); err == nil {
		t.Fatal("file should be gone after remove")
	}
	// Recreate via CREATE without TRUNC: a brand-new empty file (the old inode is gone).
	f, err := fs.OpenFile("doomed.bin", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if got := readAllAt(t, fs, "doomed.bin"); string(got) != "new" {
		t.Fatalf("recreated file = %q, want new (old bytes leaked)", got)
	}
}

// TestDuplicateWriteRecordsAreExactlyOnceIdempotent: re-applying the SAME OpWrite
// record twice (a resend/duplicate) yields the same bytes — a write is positional, so
// replaying it is idempotent and never doubles or shifts data.
func TestDuplicateWriteRecordsAreExactlyOnceIdempotent(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	rec := []wal.Record{
		{Op: wal.OpCreate, Path: "f", Mode: 0o644},
		{Op: wal.OpWrite, Path: "f", Offset: blockSize - 2, Data: []byte("ABCD")}, // straddles a block edge
	}
	if err := fs.ApplyBatch(rec, ""); err != nil {
		t.Fatal(err)
	}
	// Resend the identical write batch (minus the create, which is also idempotent).
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpWrite, Path: "f", Offset: blockSize - 2, Data: []byte("ABCD")}}, ""); err != nil {
		t.Fatal(err)
	}
	got := readAllAt(t, fs, "f")
	want := make([]byte, blockSize+2)
	copy(want[blockSize-2:], []byte("ABCD"))
	if !bytes.Equal(got, want) {
		t.Fatalf("duplicate write not idempotent; diff at %d (size got=%d want=%d)", firstDiff(got, want), len(got), len(want))
	}
}

// TestApplyCreateIdempotentOverDirtyFilePreservesBlocks: an idempotent re-create over a
// file that already has DIRTY MULTI-BLOCK content must not drop a single block (the
// "stale cache → kernel issues CREATE" handoff hazard, at multi-block scale).
func TestApplyCreateIdempotentOverDirtyFilePreservesBlocks(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 2*blockSize+321)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := fs.ApplyBatch([]wal.Record{
		{Op: wal.OpCreate, Path: "db", Mode: 0o644},
		{Op: wal.OpWrite, Path: "db", Offset: 0, Data: payload},
	}, ""); err != nil {
		t.Fatal(err)
	}
	// Redundant create for the same path: must be a no-op, not a truncate.
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "db", Mode: 0o644}}, ""); err != nil {
		t.Fatal(err)
	}
	if got := readAllAt(t, fs, "db"); !bytes.Equal(got, payload) {
		t.Fatalf("redundant create clobbered multi-block content; diff at %d", firstDiff(got, payload))
	}
}

// ---- ApplyBatch all-or-nothing visibility + poisoned-record isolation -----------

// TestApplyBatchPublishesExactlyOncePerBatch: a large batch (more records than the
// per-record path would emit) publishes EXACTLY ONE invalidation set, even when one
// record in the middle is guard-rejected. No second publish, no torn visibility.
func TestApplyBatchPublishesExactlyOncePerBatch(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	sub, unsub := fs.Subscribe()
	defer unsub()

	batch := []wal.Record{
		{Op: wal.OpCreate, Path: "a", Mode: 0o644},
		{Op: wal.OpWrite, Path: "a", Offset: 0, Data: []byte("hi")},
		{Op: wal.OpMkdir, Path: "d", Mode: 0o755},
		// A guard-rejected record in the MIDDLE: rename a missing path. It must not abort the batch,
		// and — having changed nothing — must contribute NO invalidation. A no-op/rejected/idempotent
		// record that publishes a phantom name-change makes peers drop a dentry they didn't need to;
		// if that name is an in-use CWD directory it risks getcwd ENOENT -> SQLITE_CANTOPEN.
		{Op: wal.OpRename, Path: "does-not-exist", NewPath: "d/moved"},
		{Op: wal.OpCreate, Path: "b", Mode: 0o644},
	}
	if err := fs.ApplyBatch(batch, ""); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}
	// Exactly one publish, carrying only the affected paths of records that ACTUALLY changed the tree.
	select {
	case batchInvs := <-sub:
		paths := batchInvs.Invs
		// a, a, d, b = 4 paths; the guard-rejected rename (no-op) contributes none.
		if len(paths) != 4 {
			t.Fatalf("published %d paths %v, want 4 (no-op records must not publish)", len(paths), paths)
		}
	default:
		t.Fatal("batch must publish exactly one invalidation set; got none")
	}
	select {
	case extra := <-sub:
		t.Fatalf("batch published a SECOND time (%v) — torn visibility", extra)
	default:
	}

	// Survivors applied despite the bad record; the rejected rename left no trace.
	if got := readAllAt(t, fs, "a"); string(got) != "hi" {
		t.Fatalf("a = %q, want hi", got)
	}
	if _, err := fs.Lstat("b"); err != nil {
		t.Fatalf("b should exist after the batch with a poisoned record: %v", err)
	}
	if _, err := fs.Stat("d/moved"); err == nil {
		t.Fatal("a rejected rename must not create the destination")
	}
}

// TestApplyBatchPoisonedRecordDoesNotCorruptRest: a per-record applyMutation failure (a
// write to a path that does not exist) is isolated — every other record in the batch
// still lands correctly and the failed write touches nothing.
func TestApplyBatchPoisonedRecordDoesNotCorruptRest(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	good := bytes.Repeat([]byte{'G'}, blockSize+10) // multi-block survivor
	batch := []wal.Record{
		{Op: wal.OpCreate, Path: "keep", Mode: 0o644},
		{Op: wal.OpWrite, Path: "ghost", Offset: 0, Data: []byte("XXXX")}, // ghost never created → no-op
		{Op: wal.OpWrite, Path: "keep", Offset: 0, Data: good},
		{Op: wal.OpTruncate, Path: "ghost", Size: 99}, // also a no-op on the missing path
		{Op: wal.OpCreate, Path: "also", Mode: 0o644},
	}
	if err := fs.ApplyBatch(batch, ""); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}
	if got := readAllAt(t, fs, "keep"); !bytes.Equal(got, good) {
		t.Fatalf("survivor corrupted by a poisoned record; diff at %d", firstDiff(got, good))
	}
	if _, err := fs.Lstat("also"); err != nil {
		t.Fatalf("record after the poisoned one was dropped: %v", err)
	}
	if _, err := fs.Stat("ghost"); err == nil {
		t.Fatal("the poisoned write must not conjure the file into existence")
	}
}

// TestApplyBatchEmptyIsNoPublishNoError: an empty batch is a clean no-op (no publish,
// no error) — the early-return path.
func TestApplyBatchEmptyIsNoPublishNoError(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	sub, unsub := fs.Subscribe()
	defer unsub()
	if err := fs.ApplyBatch(nil, ""); err != nil {
		t.Fatalf("empty batch err = %v, want nil", err)
	}
	select {
	case p := <-sub:
		t.Fatalf("empty batch published %v, want nothing", p)
	default:
	}
}

// ---- create-over-directory must not destroy a subtree (multi-level) -------------

// TestCreateOverDirectoryDoesNotDestroyDeepSubtree: a bare file-create at a path that is
// a directory with a DEEP, multi-block-file subtree is a no-op; the whole subtree
// (including a large file's bytes) survives intact.
func TestCreateOverDirectoryDoesNotDestroyDeepSubtree(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	deep := make([]byte, blockSize+42)
	for i := range deep {
		deep[i] = byte(i % 97)
	}
	if err := fs.ApplyBatch([]wal.Record{
		{Op: wal.OpMkdir, Path: "proj/sub/leaf", Mode: 0o755},
		{Op: wal.OpCreate, Path: "proj/sub/leaf/big.bin", Mode: 0o644},
		{Op: wal.OpWrite, Path: "proj/sub/leaf/big.bin", Offset: 0, Data: deep},
	}, ""); err != nil {
		t.Fatal(err)
	}
	// A bare create AT the top-level directory path.
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "proj", Mode: 0o644}}, ""); err != nil {
		t.Fatal(err)
	}
	fi, err := fs.Lstat("proj")
	if err != nil || !fi.IsDir() {
		t.Fatalf("proj must remain a directory: fi=%v err=%v", fi, err)
	}
	if got := readAllAt(t, fs, "proj/sub/leaf/big.bin"); !bytes.Equal(got, deep) {
		t.Fatalf("deep subtree file destroyed/corrupted by create-over-dir; diff at %d", firstDiff(got, deep))
	}
}

// ---- rename / remove / chmod / chtimes / chown via the public API ---------------

// TestRenameRemoveChmodChtimesChownAcrossDirs sweeps the metadata mutations together,
// including the boundary cases: rename across directories preserves multi-block content,
// remove of a non-empty dir is rejected, and chmod/chtimes/chown land and read back.
func TestRenameRemoveChmodChtimesChownAcrossDirs(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.MkdirAll("src", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.MkdirAll("dst", 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{'M'}, blockSize+7)
	writeAtPath(t, fs, "src/file.bin", 0, payload)

	// chmod / chtimes / chown on the file, then rename it across directories: metadata
	// AND multi-block content must move together.
	if err := fs.Chmod("src/file.bin", 0o600); err != nil {
		t.Fatal(err)
	}
	mt := timeMillis(1_700_000_000_000)
	if err := fs.Chtimes("src/file.bin", mt, mt); err != nil {
		t.Fatal(err)
	}
	if err := fs.Chown("src/file.bin", 4242, 7); err != nil {
		t.Fatal(err)
	}
	if err := fs.Rename("src/file.bin", "dst/moved.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat("src/file.bin"); err == nil {
		t.Fatal("old name should be gone after rename")
	}
	fi, err := fs.Stat("dst/moved.bin")
	if err != nil {
		t.Fatalf("moved file missing: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after rename = %o, want 600", fi.Mode().Perm())
	}
	if fi.ModTime().UnixMilli() != mt.UnixMilli() {
		t.Fatalf("mtime after rename = %d, want %d", fi.ModTime().UnixMilli(), mt.UnixMilli())
	}
	if u, g := ownerOf(t, fs, "dst/moved.bin"); u != 4242 || g != 7 {
		t.Fatalf("owner after rename = %d:%d, want 4242:7", u, g)
	}
	if got := readAllAt(t, fs, "dst/moved.bin"); !bytes.Equal(got, payload) {
		t.Fatalf("multi-block content lost across rename; diff at %d", firstDiff(got, payload))
	}

	// Removing the now-non-empty dst must be rejected; removing the file then the dir works.
	if err := fs.Remove("dst"); err == nil {
		t.Fatal("removing a non-empty directory must fail")
	}
	if err := fs.Remove("dst/moved.bin"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Remove("dst"); err != nil {
		t.Fatalf("removing the now-empty dir should succeed: %v", err)
	}

	// chmod/chtimes/chown on a MISSING path is ErrNotExist (boundary).
	if err := fs.Chmod("nope", 0o644); err == nil {
		t.Fatal("chmod on a missing path should fail")
	}
	if err := fs.Chown("nope", 1, 1); err == nil {
		t.Fatal("chown on a missing path should fail")
	}
}

// TestChownPartialNegativeLeavesFieldUnchanged: a uid/gid of -1 means "leave unchanged"
// (POSIX); each field is independently settable.
func TestChownPartialNegativeLeavesFieldUnchanged(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := fs.Create("f")
	_ = f.Close()
	if err := fs.Chown("f", 11, 22); err != nil {
		t.Fatal(err)
	}
	if err := fs.Chown("f", 99, -1); err != nil { // change uid only
		t.Fatal(err)
	}
	if u, g := ownerOf(t, fs, "f"); u != 99 || g != 22 {
		t.Fatalf("owner = %d:%d, want 99:22 (gid must be preserved)", u, g)
	}
	if err := fs.Chown("f", -1, 33); err != nil { // change gid only
		t.Fatal(err)
	}
	if u, g := ownerOf(t, fs, "f"); u != 99 || g != 33 {
		t.Fatalf("owner = %d:%d, want 99:33 (uid must be preserved)", u, g)
	}
}

// ---- ReadDir layering: workfs lists EVERYTHING (reserved-hiding is a higher layer) --

// TestReadDirListsAllEntriesIncludingReservedNames documents the workfs ReadDir
// contract precisely: it returns ALL children, sorted, and performs NO reserved-name
// (".portablefs-*") filtering — that hiding lives in the fsproto server layer, not here. So a
// root-level ".portablefs-*" file IS listed by workfs, and (the case the FOCUS calls out) a
// ".portablefs-*" file in a SUBDIR is likewise listed. This locks the layering boundary: if
// reserved-hiding ever leaks down into workfs, this test breaks loudly.
func TestReadDirListsAllEntriesIncludingReservedNames(t *testing.T) {
	w, _ := newWAL(t)
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	// Root: a normal file, a reserved-looking watermark name, and a directory.
	mustCreate(t, fs, ".portablefs-session1") // reserved-looking, at ROOT
	mustCreate(t, fs, "zeta.txt")
	if err := fs.MkdirAll("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	mustCreate(t, fs, "sub/.portablefs-legit") // a user file legitimately named .portablefs-* in a SUBDIR
	mustCreate(t, fs, "sub/plain")

	rootNames := dirNames(t, fs, "")
	// workfs hides nothing: all three root entries are present, sorted.
	wantRoot := []string{".portablefs-session1", "sub", "zeta.txt"}
	if !equalStrings(rootNames, wantRoot) {
		t.Fatalf("ReadDir(root) = %v, want %v (workfs must not filter reserved names)", rootNames, wantRoot)
	}
	// The subdir ".portablefs-*" file is listed (the FOCUS's explicit case).
	subNames := dirNames(t, fs, "sub")
	wantSub := []string{".portablefs-legit", "plain"}
	if !equalStrings(subNames, wantSub) {
		t.Fatalf("ReadDir(sub) = %v, want %v (a subdir .portablefs-* file must be listed)", subNames, wantSub)
	}

	// ReadDir on a file is an error; on a missing path, ErrNotExist.
	if _, err := fs.ReadDir("zeta.txt"); err == nil {
		t.Fatal("ReadDir on a file should error")
	}
	if _, err := fs.ReadDir("missing"); err == nil {
		t.Fatal("ReadDir on a missing path should error")
	}
}

// ---- CONCURRENCY: ApplyBatch + readBlocks vs a flat-array reference (-race) ------

// TestConcurrentApplyBatchAndReadReconstructsFlatReference is the headline race test:
// while many writers apply batches of block-aligned and unaligned overwrites to a
// shared multi-block backed file, readers continuously reconstruct windows that must
// ALWAYS equal the authoritative serialized state at some consistent point — never a
// torn mix. Because ApplyBatch is the single atomic visibility unit and each batch
// rewrites a region to a single recognizable byte, every fully-applied region a reader
// sees must be internally consistent. Run under -race; also asserts the FINAL whole-file
// reconstruction equals a flat-array reference computed from the same ordered batches.
func TestConcurrentApplyBatchAndReadReconstructsFlatReference(t *testing.T) {
	const fileSize = 4*blockSize + 1000
	base := make([]byte, fileSize)
	for i := range base {
		base[i] = byte('a' + i%26)
	}
	entry, blobs := blockChunkedBackedFile("shared.bin", base)
	w, _ := newWAL(t)
	fs, err := New([]backend.Entry{entry}, &fakeBlobs{data: blobs}, w)
	if err != nil {
		t.Fatal(err)
	}

	// Deterministic plan of disjoint single-block overwrites: writer k owns block k and
	// fills it (full-block, no read-modify-write) with a unique marker byte. Disjoint
	// targets keep the reference unambiguous regardless of completion order while still
	// hammering ApplyBatch + readBlocks concurrently. The final reference is base with
	// each owned block replaced by its marker.
	const nBlocks = 4 // blocks 0..3 are full; block 4 (the short tail) stays base
	ref := append([]byte(nil), base...)
	markers := []byte{'0', '1', '2', '3'}
	for bi := 0; bi < nBlocks; bi++ {
		start := int64(bi) * blockSize
		for j := start; j < start+blockSize; j++ {
			ref[j] = markers[bi]
		}
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	readErr := make(chan error, 8)
	for r := 0; r < 6; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			f, err := fs.Open("shared.bin")
			if err != nil {
				readErr <- err
				return
			}
			defer f.Close()
			buf := make([]byte, blockSize+123) // a window that crosses block edges
			for {
				select {
				case <-stop:
					return
				default:
				}
				for bi := 0; bi < nBlocks; bi++ {
					off := int64(bi) * blockSize
					n, err := f.ReadAt(buf, off)
					if err != nil && err != io.EOF {
						readErr <- err
						return
					}
					// The first blockSize bytes lie wholly within block bi: each byte must be
					// EITHER the original base byte OR this block's marker — never a foreign
					// block's marker (which would mean a torn/cross-block read).
					lim := blockSize
					if lim > n {
						lim = n
					}
					for k := 0; k < lim; k++ {
						b := buf[k]
						if b != markers[bi] && b != base[off+int64(k)] {
							readErr <- fmt.Errorf("torn read in block %d at byte %d: got %q (want marker %q or base %q)",
								bi, k, b, markers[bi], base[off+int64(k)])
							return
						}
					}
				}
			}
		}()
	}

	var writers sync.WaitGroup
	for bi := 0; bi < nBlocks; bi++ {
		writers.Add(1)
		go func(bi int) {
			defer writers.Done()
			start := int64(bi) * blockSize
			full := bytes.Repeat([]byte{markers[bi]}, blockSize)
			// Split the block's full overwrite into a two-record batch (still one atomic
			// publish) to exercise multi-record ApplyBatch under contention.
			half := blockSize / 2
			batch := []wal.Record{
				{Op: wal.OpWrite, Path: "shared.bin", Offset: start, Data: full[:half]},
				{Op: wal.OpWrite, Path: "shared.bin", Offset: start + int64(half), Data: full[half:]},
			}
			if err := fs.ApplyBatch(batch, ""); err != nil {
				readErr <- err
			}
		}(bi)
	}
	writers.Wait()
	close(stop)
	readers.Wait()
	close(readErr)
	if err := <-readErr; err != nil {
		t.Fatalf("concurrent read/apply error: %v", err)
	}

	// Final whole-file reconstruction must equal the flat-array reference exactly.
	got := readAllAt(t, fs, "shared.bin")
	if !bytes.Equal(got, ref) {
		t.Fatalf("final reconstruction != flat reference; first diff at %d", firstDiff(got, ref))
	}
	// The untouched tail (block 4) still reads its base bytes.
	if !bytes.Equal(got[4*blockSize:], base[4*blockSize:]) {
		t.Fatalf("untouched tail diverged at %d", 4*blockSize+firstDiff(got[4*blockSize:], base[4*blockSize:]))
	}
}

// TestConcurrentReadModifyWriteConvergesToReference: many writers each do a small
// PARTIAL (read-modify-write) overwrite into its OWN disjoint slot of a shared backed
// multi-block file. Each slot's base must be preserved outside the written bytes, and
// the final file must equal the flat reference — under -race. This exercises the
// warm-base-outside-lock + writeBlocks read-modify-write path under contention.
func TestConcurrentReadModifyWriteConvergesToReference(t *testing.T) {
	const slots = 64
	const slotSize = 32
	// Lay slots out so consecutive slots fall on opposite sides of block boundaries.
	const fileSize = 2*blockSize + slots*slotSize + 9
	base := make([]byte, fileSize)
	for i := range base {
		base[i] = byte('a' + i%26)
	}
	entry, blobs := blockChunkedBackedFile("rmw.bin", base)
	w, _ := newWAL(t)
	fs, err := New([]backend.Entry{entry}, &fakeBlobs{data: blobs}, w)
	if err != nil {
		t.Fatal(err)
	}

	// Place slot s straddling the first block boundary region so some are pure base
	// read-modify-writes that cross a 4 MiB edge.
	slotOff := func(s int) int64 { return int64(blockSize-slots*slotSize/2) + int64(s)*slotSize }
	ref := append([]byte(nil), base...)
	for s := 0; s < slots; s++ {
		marker := bytes.Repeat([]byte{byte('A' + s%26)}, slotSize/2) // only overwrite HALF the slot
		copy(ref[slotOff(s):], marker)
	}

	var wg sync.WaitGroup
	for s := 0; s < slots; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			marker := bytes.Repeat([]byte{byte('A' + s%26)}, slotSize/2)
			if err := fs.writeAt("rmw.bin", slotOff(s), marker); err != nil {
				t.Errorf("write slot %d: %v", s, err)
			}
		}(s)
	}
	wg.Wait()

	got := readAllAt(t, fs, "rmw.bin")
	if !bytes.Equal(got, ref) {
		t.Fatalf("concurrent read-modify-write diverged from reference; first diff at %d", firstDiff(got, ref))
	}
}

// ---- small local helpers (kept distinct from the other test files' helpers) ------

// backedFS builds an FS whose single file `name` is backed by `content`, laid out as
// per-block chunks so unwritten blocks resolve from the base.
func backedFS(t *testing.T, name string, content []byte) *FS {
	t.Helper()
	entry, blobs := blockChunkedBackedFile(name, content)
	w, _ := newWAL(t)
	fs, err := New([]backend.Entry{entry}, &fakeBlobs{data: blobs}, w)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func truncate(t *testing.T, fs *FS, name string, size int64) {
	t.Helper()
	f, err := fs.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s for truncate: %v", name, err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatalf("truncate %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func mustCreate(t *testing.T, fs *FS, name string) {
	t.Helper()
	f, err := fs.Create(name)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func ownerOf(t *testing.T, fs *FS, name string) (uint32, uint32) {
	t.Helper()
	fi, err := fs.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	o, ok := fi.Sys().(interface{ OwnerIDs() (uint32, uint32) })
	if !ok {
		t.Fatalf("FileInfo for %s does not expose ownership", name)
	}
	return o.OwnerIDs()
}

func dirNames(t *testing.T, fs *FS, p string) []string {
	t.Helper()
	fis, err := fs.ReadDir(p)
	if err != nil {
		t.Fatalf("readdir %q: %v", p, err)
	}
	out := make([]string, 0, len(fis))
	for _, fi := range fis {
		out = append(out, fi.Name())
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// firstDiff returns the index of the first differing byte (or the shorter length if one
// is a prefix of the other); -1 if equal.
func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

// byteAt returns b[i] or -1 if out of range (for diagnostic messages).
func byteAt(b []byte, i int) int {
	if i < 0 || i >= len(b) {
		return -1
	}
	return int(b[i])
}
