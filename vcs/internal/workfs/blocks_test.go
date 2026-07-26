package workfs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// countingBlobs records how many times each digest is fetched, so a test can
// assert that a write touched only the blocks it needed.
type countingBlobs struct {
	mu      sync.Mutex
	data    map[string][]byte
	fetched map[string]int
}

func (c *countingBlobs) Blob(_ context.Context, d string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetched[d]++
	v, ok := c.data[d]
	if !ok {
		return nil, fmt.Errorf("no blob %s", d)
	}
	return v, nil
}

func (c *countingBlobs) count(d string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetched[d]
}

// TestPartialWriteFetchesOnlyTouchedBlock is the block-level efficiency
// guarantee: a one-byte write into one block of a large, chunked backed file
// fetches only that block's chunk — never the whole file.
func TestPartialWriteFetchesOnlyTouchedBlock(t *testing.T) {
	const nblk = 3
	data := map[string][]byte{}
	var chunks []backend.Chunk
	var chunkDg []string
	for i := 0; i < nblk; i++ {
		blk := bytes.Repeat([]byte{byte('A' + i)}, blockSize)
		d := digestOf(blk)
		chunkDg = append(chunkDg, d)
		data[d] = blk
		chunks = append(chunks, backend.Chunk{Digest: d, Size: blockSize, Offset: int64(i) * blockSize})
	}
	cb := &countingBlobs{data: data, fetched: map[string]int{}}
	entries := []backend.Entry{{
		Path: "big.bin", Kind: "file", Mode: 0o644, Size: int64(nblk) * blockSize, Chunks: chunks,
	}}
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(entries, cb, w)
	if err != nil {
		t.Fatal(err)
	}

	// Write one byte in the middle of block 1.
	off := int64(blockSize) + 100
	f, err := fs.OpenFile("big.bin", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{'Z'}); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if cb.count(chunkDg[1]) == 0 {
		t.Fatal("expected block 1 to be fetched for the partial write")
	}
	if c0, c2 := cb.count(chunkDg[0]), cb.count(chunkDg[2]); c0 != 0 || c2 != 0 {
		t.Fatalf("untouched blocks were fetched: c0=%d c2=%d (want 0,0)", c0, c2)
	}

	// The write is visible; an untouched block still reads its original content.
	rf, err := fs.Open("big.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	one := make([]byte, 1)
	if _, err := rf.ReadAt(one, off); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if one[0] != 'Z' {
		t.Fatalf("modified byte = %q, want Z", one)
	}
	if _, err := rf.ReadAt(one, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if one[0] != 'A' {
		t.Fatalf("block 0 byte = %q, want A (unchanged)", one)
	}
}

// TestSparseHolesReadZero: a write far past EOF leaves the gap as zeros, and
// allocates only the written block.
func TestSparseHolesReadZero(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.OpenFile("sparse.bin", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	off := int64(2*blockSize + 7)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("X")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if fi, _ := fs.Stat("sparse.bin"); fi.Size() != off+1 {
		t.Fatalf("size = %d, want %d", fi.Size(), off+1)
	}
	rf, _ := fs.Open("sparse.bin")
	defer rf.Close()
	hole := make([]byte, 100)
	n, _ := rf.ReadAt(hole, 0)
	for i := 0; i < n; i++ {
		if hole[i] != 0 {
			t.Fatalf("hole byte %d = %d, want 0", i, hole[i])
		}
	}
	one := make([]byte, 1)
	if _, err := rf.ReadAt(one, off); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if one[0] != 'X' {
		t.Fatalf("written byte = %q, want X", one)
	}
}

// TestWriteAcrossBlockBoundary: a write straddling two blocks lands correctly in
// both.
func TestWriteAcrossBlockBoundary(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.OpenFile("x.bin", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	off := int64(blockSize - 2)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("WXYZ")); err != nil { // WX in block 0, YZ in block 1
		t.Fatal(err)
	}
	_ = f.Close()

	rf, _ := fs.Open("x.bin")
	defer rf.Close()
	buf := make([]byte, 4)
	if _, err := rf.ReadAt(buf, off); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buf) != "WXYZ" {
		t.Fatalf("boundary read = %q, want WXYZ", buf)
	}
	if fi, _ := fs.Stat("x.bin"); fi.Size() != off+4 {
		t.Fatalf("size = %d, want %d", fi.Size(), off+4)
	}
}
