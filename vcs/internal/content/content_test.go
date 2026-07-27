package content

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
)

// mapReader is a BlobReader backed by an in-memory digest->bytes map.
type mapReader map[string][]byte

func (m mapReader) Blob(_ context.Context, digest string) ([]byte, error) {
	b, ok := m[digest]
	if !ok {
		return nil, fmt.Errorf("blob not found: %s", digest)
	}
	return append([]byte(nil), b...), nil
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// chunkOf stores b in the reader and returns a manifest chunk at offset.
func chunkOf(m mapReader, offset int64, b []byte) backend.Chunk {
	d := digestOf(b)
	m[d] = b
	return backend.Chunk{Digest: d, Size: int64(len(b)), Offset: offset}
}

// TestReadAtChunkedOutOfOrder is the regression for the silent-corruption bug:
// chunks that tile the file but are NOT in ascending slice order must still read
// correctly (the TS reader sorts; the Go reader must agree on the byte layout).
func TestReadAtChunkedOutOfOrder(t *testing.T) {
	m := mapReader{}
	a := []byte("AAAA")
	b := []byte("BBBB")
	c := []byte("CCCC")
	// Deliberately out of order: [8] then [0] then [4].
	src := Source{
		Size: 12,
		Chunks: []backend.Chunk{
			chunkOf(m, 8, c),
			chunkOf(m, 0, a),
			chunkOf(m, 4, b),
		},
	}
	out := make([]byte, 12)
	n, err := ReadAt(m, nil, src, out, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != 12 {
		t.Fatalf("n = %d, want 12", n)
	}
	if got, want := string(out), "AAAABBBBCCCC"; got != want {
		t.Fatalf("out = %q, want %q (out-of-order chunks were not reassembled correctly)", got, want)
	}
}

// TestReadAtChunkedSubRange reads a window that spans two chunks, out of order.
func TestReadAtChunkedSubRange(t *testing.T) {
	m := mapReader{}
	src := Source{
		Size: 12,
		Chunks: []backend.Chunk{
			chunkOf(m, 8, []byte("CCCC")),
			chunkOf(m, 0, []byte("AAAA")),
			chunkOf(m, 4, []byte("BBBB")),
		},
	}
	out := make([]byte, 6)
	n, err := ReadAt(m, nil, src, out, 3) // bytes [3,9): "ABBBBC"
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != 6 {
		t.Fatalf("n = %d, want 6", n)
	}
	if got, want := string(out), "ABBBBC"; got != want {
		t.Fatalf("out = %q, want %q", got, want)
	}
}

// TestReadAtChunkedGapErrors verifies a hole in the chunk coverage is a loud
// error, never a silently zero-filled (wrong) read reported as success.
func TestReadAtChunkedGapErrors(t *testing.T) {
	m := mapReader{}
	src := Source{
		Size: 12,
		Chunks: []backend.Chunk{
			chunkOf(m, 0, []byte("AAAA")),
			// gap at [4,8)
			chunkOf(m, 8, []byte("CCCC")),
		},
	}
	out := make([]byte, 12)
	if _, err := ReadAt(m, nil, src, out, 0); err == nil || err == io.EOF {
		t.Fatalf("expected a gap error, got %v (out=%q)", err, out)
	}
}

// TestReadAtChunkedNoBleedPastChunkSize verifies a chunk whose stored bytes
// exceed its declared Size cannot overwrite the following chunk's region.
func TestReadAtChunkedNoBleedPastChunkSize(t *testing.T) {
	m := mapReader{}
	// First chunk declares Size 4 but its blob is 8 bytes of 'X'.
	oversized := []byte("XXXXXXXX")
	d := digestOf(oversized)
	m[d] = oversized
	src := Source{
		Size: 8,
		Chunks: []backend.Chunk{
			{Digest: d, Size: 4, Offset: 0},
			chunkOf(m, 4, []byte("BBBB")),
		},
	}
	out := make([]byte, 8)
	n, err := ReadAt(m, nil, src, out, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != 8 {
		t.Fatalf("n = %d, want 8", n)
	}
	if got, want := string(out), "XXXXBBBB"; got != want {
		t.Fatalf("out = %q, want %q (oversized chunk bled past its declared size)", got, want)
	}
}

// TestWholeOutOfOrderAndCopy verifies Whole reassembles out-of-order chunks and
// returns a private (non-cache-aliased) buffer for the whole-blob path.
func TestWholeOutOfOrderAndCopy(t *testing.T) {
	m := mapReader{}
	src := Source{
		Size: 8,
		Chunks: []backend.Chunk{
			chunkOf(m, 4, []byte("BBBB")),
			chunkOf(m, 0, []byte("AAAA")),
		},
	}
	got, err := Whole(m, nil, src)
	if err != nil {
		t.Fatalf("Whole: %v", err)
	}
	if !bytes.Equal(got, []byte("AAAABBBB")) {
		t.Fatalf("Whole = %q, want %q", got, "AAAABBBB")
	}

	// Whole-blob path must return a copy, not the cache's slice.
	whole := []byte("hello world")
	wd := digestOf(whole)
	m[wd] = whole
	c := NewCache(1 << 20)
	src2 := Source{Size: int64(len(whole)), BlobDigest: wd}
	first, err := Whole(m, c, src2)
	if err != nil {
		t.Fatalf("Whole whole-blob: %v", err)
	}
	first[0] = 'H' // mutate the returned buffer
	second, err := Whole(m, c, src2)
	if err != nil {
		t.Fatalf("Whole whole-blob 2: %v", err)
	}
	if !bytes.Equal(second, whole) {
		t.Fatalf("cache was poisoned by a mutated Whole result: got %q", second)
	}
}

// TestWholeMalformedLayoutErrors verifies an out-of-range / gapped layout is a
// loud error rather than a panic or silent zero-fill.
func TestWholeMalformedLayoutErrors(t *testing.T) {
	m := mapReader{}
	// Chunk offset beyond Size — the old code panicked on copy(out[ch.Offset:], …).
	src := Source{
		Size: 4,
		Chunks: []backend.Chunk{
			{Digest: digestOf([]byte("ZZ")), Size: 2, Offset: 10},
		},
	}
	if _, err := Whole(m, nil, src); err == nil {
		t.Fatalf("expected malformed-layout error, got nil")
	}
}
