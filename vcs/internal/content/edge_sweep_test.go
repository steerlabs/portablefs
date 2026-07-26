package content

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
)

// This file is an exhaustive edge sweep of the content read + cache + chunking
// layer. It reuses the in-package harnesses (mapReader, countingReader, addr,
// digestOf, chunkOf, fileFor) defined in the sibling _test.go files.
//
// Themes: ReadAt across and exactly-at chunk boundaries, partial last chunk,
// reads past EOF, holes/zero regions (which this layer treats as a malformed
// manifest, not a silent zero-fill), single-blob reads, the byte-bounded LRU
// (hit/miss/eviction-at-the-bound/concurrent sharing), blob-error propagation,
// zero-size sources, and reconstruction-equals-original for random slices.

// ---------------------------------------------------------------------------
// Local harness helpers (do NOT collide with the sibling files' helpers).
// ---------------------------------------------------------------------------

// errReader is a BlobReader that fails for a designated set of digests and
// serves the rest from a map. It records how many fetches landed.
type errReader struct {
	mu    sync.Mutex
	data  map[string][]byte
	fail  map[string]error
	calls map[string]int
}

func newErrReader() *errReader {
	return &errReader{data: map[string][]byte{}, fail: map[string]error{}, calls: map[string]int{}}
}

func (e *errReader) put(b []byte) string {
	d := digestOf(b)
	e.mu.Lock()
	e.data[d] = b
	e.mu.Unlock()
	return d
}

func (e *errReader) Blob(_ context.Context, digest string) ([]byte, error) {
	e.mu.Lock()
	e.calls[digest]++
	err := e.fail[digest]
	b, ok := e.data[digest]
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("errReader: missing %s", digest)
	}
	return append([]byte(nil), b...), nil
}

func (e *errReader) count(d string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls[d]
}

// buildChunked tiles data into fixed-size chunks and returns a Source plus the
// backing mapReader. The final chunk is naturally partial when len(data) is not
// a multiple of chunkSize.
func buildChunked(t *testing.T, data []byte, chunkSize int64) (mapReader, Source) {
	t.Helper()
	m := mapReader{}
	var chunks []backend.Chunk
	for off := int64(0); off < int64(len(data)); off += chunkSize {
		end := off + chunkSize
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		chunks = append(chunks, chunkOf(m, off, data[off:end]))
	}
	return m, Source{Size: int64(len(data)), Chunks: chunks}
}

// readFull drains src via repeated ReadAt calls (honoring short reads), exactly
// as an os.File-style ReaderAt consumer would, and returns the assembled bytes.
// It guards against an infinite loop on a buggy zero-progress non-EOF return.
func readFull(t *testing.T, blobs BlobReader, cache Cache, src Source, bufSize int) []byte {
	t.Helper()
	var out []byte
	off := int64(0)
	for {
		p := make([]byte, bufSize)
		n, err := ReadAt(blobs, cache, src, p, off)
		out = append(out, p[:n]...)
		off += int64(n)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("ReadAt at off=%d: %v", off, err)
		}
		if n == 0 {
			t.Fatalf("ReadAt made no progress at off=%d without EOF", off)
		}
	}
}

// ---------------------------------------------------------------------------
// ReadAt: chunk boundaries (across, exactly-at, +/- 1).
// ---------------------------------------------------------------------------

func TestReadAtBoundarySweep(t *testing.T) {
	// 4 chunks of 4 bytes => offsets 0,4,8,12; total 16. Distinct bytes per
	// position so any mis-placement is visible.
	full := []byte("0123456789ABCDEF")
	m, src := buildChunked(t, full, 4)

	// Sweep every (off, length) with length up to a bit past the file. This
	// straddles every interior boundary, lands exactly on boundaries, and
	// goes one byte before/after each.
	for off := int64(0); off <= int64(len(full)); off++ {
		for ln := int64(0); ln <= int64(len(full))+3; ln++ {
			p := make([]byte, ln)
			n, err := ReadAt(m, nil, src, p, off)

			// Expected copied count: clamp [off, off+ln) to [0,Size).
			wantN := int64(0)
			if off < int64(len(full)) {
				end := off + ln
				if end > int64(len(full)) {
					end = int64(len(full))
				}
				wantN = end - off
			}
			if int64(n) != wantN {
				t.Fatalf("off=%d ln=%d: n=%d want %d (err=%v)", off, ln, n, wantN, err)
			}
			if !bytes.Equal(p[:n], full[off:off+int64(n)]) {
				t.Fatalf("off=%d ln=%d: bytes=%q want %q", off, ln, p[:n], full[off:off+int64(n)])
			}
			// EOF iff the read reached or passed the end (including a zero-length
			// read whose offset is already at/after EOF).
			reachedEnd := off >= int64(len(full)) || off+ln >= int64(len(full))
			if reachedEnd {
				if err != io.EOF {
					t.Fatalf("off=%d ln=%d: err=%v want io.EOF", off, ln, err)
				}
			} else if err != nil {
				t.Fatalf("off=%d ln=%d: err=%v want nil", off, ln, err)
			}
		}
	}
}

// TestReadAtExactlyAtChunkStart reads a single full chunk starting exactly on
// each chunk boundary (the +/- 1 around boundaries is the surrounding sweep).
func TestReadAtExactlyAtChunkStart(t *testing.T) {
	full := []byte("AAAABBBBCCCCDDDD")
	m, src := buildChunked(t, full, 4)
	for _, start := range []int64{0, 4, 8, 12} {
		p := make([]byte, 4)
		n, err := ReadAt(m, nil, src, p, start)
		if n != 4 {
			t.Fatalf("start=%d n=%d want 4 (err=%v)", start, n, err)
		}
		if !bytes.Equal(p, full[start:start+4]) {
			t.Fatalf("start=%d got %q want %q", start, p, full[start:start+4])
		}
		// A read ending exactly at a non-final boundary is NOT EOF; the final
		// chunk's read IS EOF.
		if start == 12 {
			if err != io.EOF {
				t.Fatalf("final chunk read should be EOF, got %v", err)
			}
		} else if err != nil {
			t.Fatalf("interior chunk read should not be EOF, got %v", err)
		}
	}
}

// TestReadAtPartialLastChunk exercises a file whose last chunk is short
// (Size not a multiple of chunk size): reads landing in and spanning into the
// stub chunk must return exactly the stub's bytes and EOF.
func TestReadAtPartialLastChunk(t *testing.T) {
	full := []byte("AAAABBBBCC") // chunks: [0,4) [4,8) [8,10) — last is 2 bytes
	m, src := buildChunked(t, full, 4)

	// Whole file in one buffer.
	if got := readFull(t, m, nil, src, 64); !bytes.Equal(got, full) {
		t.Fatalf("whole = %q want %q", got, full)
	}
	// A window that starts in chunk 1 and runs past EOF.
	p := make([]byte, 100)
	n, err := ReadAt(m, nil, src, p, 6)
	if err != io.EOF || string(p[:n]) != "BBCC" {
		t.Fatalf("tail read = %q,%v want %q,EOF", p[:n], err, "BBCC")
	}
	// A read entirely within the partial last chunk.
	p2 := make([]byte, 1)
	n2, err := ReadAt(m, nil, src, p2, 9)
	if n2 != 1 || p2[0] != 'C' || err != io.EOF {
		t.Fatalf("last-byte read = %q,%v want C,EOF", p2[:n2], err)
	}
}

// TestReadAtPastEOF covers reads at exactly EOF and well past it for both the
// chunked and single-blob layouts.
func TestReadAtPastEOF(t *testing.T) {
	full := []byte("hello world!!")
	chunked, csrc := buildChunked(t, full, 5)

	blob := mapReader{}
	bd := digestOf(full)
	blob[bd] = full
	bsrc := Source{Size: int64(len(full)), BlobDigest: bd}

	for name, tc := range map[string]struct {
		r   BlobReader
		src Source
	}{
		"chunked": {chunked, csrc},
		"blob":    {blob, bsrc},
	} {
		for _, off := range []int64{int64(len(full)), int64(len(full)) + 1, int64(len(full)) + 1000} {
			p := make([]byte, 8)
			n, err := ReadAt(tc.r, nil, tc.src, p, off)
			if n != 0 || err != io.EOF {
				t.Fatalf("%s off=%d: n=%d err=%v want 0,EOF", name, off, n, err)
			}
		}
		// Exactly-at-EOF with a zero-length buffer is also EOF.
		if n, err := ReadAt(tc.r, nil, tc.src, nil, int64(len(full))); n != 0 || err != io.EOF {
			t.Fatalf("%s zero-len at EOF: n=%d err=%v want 0,EOF", name, n, err)
		}
	}
}

// TestReadAtNegativeOffset documents behavior for a negative offset. off < Size
// is true, so the chunked path enters the loop. No chunk covers a negative
// cursor, so the very first "gap" check fires: this must be a loud error, not a
// panic or silent wrong read.
func TestReadAtNegativeOffset(t *testing.T) {
	full := []byte("ABCDEFGH")
	m, src := buildChunked(t, full, 4)
	p := make([]byte, 4)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ReadAt panicked on negative offset: %v", r)
		}
	}()
	if _, err := ReadAt(m, nil, src, p, -1); err == nil || err == io.EOF {
		t.Fatalf("negative offset should be a loud error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ReadAt: holes / zero regions. This layer does NOT zero-fill; a hole is a
// malformed manifest and must surface as an explicit error (never reported as a
// successful zero-filled read).
// ---------------------------------------------------------------------------

func TestReadAtHoleInteriorErrors(t *testing.T) {
	m := mapReader{}
	src := Source{
		Size: 12,
		Chunks: []backend.Chunk{
			chunkOf(m, 0, []byte("AAAA")),
			// hole at [4,8)
			chunkOf(m, 8, []byte("CCCC")),
		},
	}
	p := make([]byte, 12)
	n, err := ReadAt(m, nil, src, p, 0)
	if err == nil || err == io.EOF {
		t.Fatalf("interior hole must error, got n=%d err=%v out=%q", n, err, p)
	}
	// The error is reported before the hole is reached, and must not claim the
	// hole's region as copied.
	if n > 4 {
		t.Fatalf("copied=%d past the hole at 4 (zero-fill leaked through)", n)
	}
}

// TestReadAtHoleAtTailErrors covers a manifest whose chunks stop before Size
// (the file's tail is a hole). The read must fail rather than short-return as
// if EOF.
func TestReadAtHoleAtTailErrors(t *testing.T) {
	m := mapReader{}
	src := Source{
		Size:   12,                                                 // claims 12 bytes...
		Chunks: []backend.Chunk{chunkOf(m, 0, []byte("AAAABBBB"))}, // ...but only 8 are covered
	}
	p := make([]byte, 12)
	if _, err := ReadAt(m, nil, src, p, 0); err == nil || err == io.EOF {
		t.Fatalf("tail hole must error, got %v", err)
	}
	// A read fully inside the covered prefix is still fine.
	p2 := make([]byte, 4)
	if n, err := ReadAt(m, nil, src, p2, 0); err != nil || string(p2[:n]) != "AAAA" {
		t.Fatalf("covered-prefix read = %q,%v want AAAA,nil", p2[:n], err)
	}
}

// TestReadAtHoleAtFrontErrors covers a manifest whose first chunk does not start
// at offset 0 (a leading hole).
func TestReadAtHoleAtFrontErrors(t *testing.T) {
	m := mapReader{}
	src := Source{
		Size:   8,
		Chunks: []backend.Chunk{chunkOf(m, 4, []byte("CCCC"))}, // [0,4) is a hole
	}
	p := make([]byte, 8)
	if n, err := ReadAt(m, nil, src, p, 0); err == nil || err == io.EOF {
		t.Fatalf("leading hole must error, got n=%d err=%v", n, err)
	}
}

// ---------------------------------------------------------------------------
// ReadAt: single whole-file blob path edges.
// ---------------------------------------------------------------------------

func TestReadAtSingleBlobBoundaries(t *testing.T) {
	full := []byte("the quick brown fox")
	m := mapReader{}
	d := digestOf(full)
	m[d] = full
	src := Source{Size: int64(len(full)), BlobDigest: d}

	for off := int64(0); off <= int64(len(full)); off++ {
		for ln := int64(0); ln <= int64(len(full))+2; ln++ {
			p := make([]byte, ln)
			n, err := ReadAt(m, nil, src, p, off)
			wantEnd := off + ln
			if wantEnd > int64(len(full)) {
				wantEnd = int64(len(full))
			}
			wantN := int64(0)
			if off < int64(len(full)) {
				wantN = wantEnd - off
			}
			if int64(n) != wantN || !bytes.Equal(p[:n], full[off:off+int64(n)]) {
				t.Fatalf("blob off=%d ln=%d: n=%d bytes=%q (want n=%d %q)", off, ln, n, p[:n], wantN, full[off:off+int64(n)])
			}
			reachedEnd := off >= int64(len(full)) || off+ln >= int64(len(full))
			if reachedEnd && err != io.EOF {
				t.Fatalf("blob off=%d ln=%d: err=%v want EOF", off, ln, err)
			}
			if !reachedEnd && err != nil {
				t.Fatalf("blob off=%d ln=%d: err=%v want nil", off, ln, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Zero-size source (both layouts) and empty buffers.
// ---------------------------------------------------------------------------

func TestZeroSizeSource(t *testing.T) {
	// Chunked-but-empty.
	if n, err := ReadAt(mapReader{}, nil, Source{Size: 0}, make([]byte, 8), 0); n != 0 || err != io.EOF {
		t.Fatalf("zero-size chunked ReadAt = %d,%v want 0,EOF", n, err)
	}
	// Single-blob-but-empty: Size 0 short-circuits before any fetch, so a missing
	// blob digest is irrelevant.
	if n, err := ReadAt(mapReader{}, nil, Source{Size: 0, BlobDigest: addr("")}, make([]byte, 8), 0); n != 0 || err != io.EOF {
		t.Fatalf("zero-size blob ReadAt = %d,%v want 0,EOF", n, err)
	}
	// Whole of a zero-size source is (nil, nil) and must not touch the reader.
	got, err := Whole(failReader{}, nil, Source{Size: 0})
	if err != nil || got != nil {
		t.Fatalf("Whole(zero) = %q,%v want nil,nil", got, err)
	}
}

// failReader fails every fetch; used to prove a code path never fetches.
type failReader struct{}

func (failReader) Blob(context.Context, string) ([]byte, error) {
	return nil, errors.New("failReader: must not be called")
}

// TestReadAtEmptyBufferNonEmptySource: a zero-length p against a non-empty
// source copies nothing and reports nil (not EOF), since off=0 < Size and the
// window is empty.
func TestReadAtEmptyBufferNonEmptySource(t *testing.T) {
	full := []byte("data")
	m, src := buildChunked(t, full, 2)
	n, err := ReadAt(m, nil, src, nil, 0)
	if n != 0 || err != nil {
		t.Fatalf("empty buffer read = %d,%v want 0,nil", n, err)
	}
}

// ---------------------------------------------------------------------------
// Blob read errors propagate (both layouts; mid-stream chunk failure too).
// ---------------------------------------------------------------------------

func TestReadAtBlobErrorPropagates(t *testing.T) {
	// Single blob whose digest is absent.
	src := Source{Size: 4, BlobDigest: addr("xxxx")}
	if _, err := ReadAt(mapReader{}, nil, src, make([]byte, 4), 0); err == nil {
		t.Fatal("missing single blob should propagate an error")
	}

	// Chunked: first chunk OK, second chunk's fetch fails. The error propagates
	// and the partial copied count reflects only what was read before the failure.
	er := newErrReader()
	d0 := er.put([]byte("AAAA"))
	d1 := digestOf([]byte("BBBB"))
	er.fail[d1] = errors.New("backend exploded")
	csrc := Source{
		Size: 8,
		Chunks: []backend.Chunk{
			{Digest: d0, Size: 4, Offset: 0},
			{Digest: d1, Size: 4, Offset: 4},
		},
	}
	n, err := ReadAt(er, nil, csrc, make([]byte, 8), 0)
	if err == nil || err == io.EOF {
		t.Fatalf("chunk fetch failure should propagate, got n=%d err=%v", n, err)
	}
	if n != 4 {
		t.Fatalf("copied=%d want 4 (bytes read before the failing chunk)", n)
	}
}

// TestReadAtDigestMismatchPropagates: a backend that returns bytes not matching
// the requested digest (silent corruption / wrong object) is a hard read error,
// never served as file content.
func TestReadAtDigestMismatchPropagates(t *testing.T) {
	m := mapReader{}
	good := []byte("GOODGOOD")
	d := digestOf(good)
	m[d] = []byte("CORRUPTX") // same length, wrong content -> digest mismatch
	src := Source{Size: 8, BlobDigest: d}
	if _, err := ReadAt(m, nil, src, make([]byte, 8), 0); err == nil {
		t.Fatal("digest mismatch must be a read error")
	}
	// Same for a chunk.
	csrc := Source{Size: 8, Chunks: []backend.Chunk{{Digest: d, Size: 8, Offset: 0}}}
	if _, err := ReadAt(m, nil, csrc, make([]byte, 8), 0); err == nil {
		t.Fatal("digest mismatch in a chunk must be a read error")
	}
}

// TestWholeBlobErrorPropagates: Whole surfaces a fetch failure from any chunk.
func TestWholeBlobErrorPropagates(t *testing.T) {
	er := newErrReader()
	d0 := er.put([]byte("AAAA"))
	d1 := digestOf([]byte("BBBB"))
	er.fail[d1] = errors.New("nope")
	src := Source{
		Size: 8,
		Chunks: []backend.Chunk{
			{Digest: d0, Size: 4, Offset: 0},
			{Digest: d1, Size: 4, Offset: 4},
		},
	}
	if _, err := Whole(er, nil, src); err == nil {
		t.Fatal("Whole should surface a failing chunk fetch")
	}
}

// ---------------------------------------------------------------------------
// Cache: hit, miss, fetch-dedup-by-cache, eviction exactly at the byte bound.
// ---------------------------------------------------------------------------

// TestCacheHitAvoidsRefetch: once a blob is fetched and cached, ReadAt serves it
// from the cache without re-hitting the backend.
func TestCacheHitAvoidsRefetch(t *testing.T) {
	er := newErrReader()
	full := []byte("cache me if you can!")
	d := er.put(full)
	src := Source{Size: int64(len(full)), BlobDigest: d}
	c := NewCache(1 << 20)

	for i := 0; i < 5; i++ {
		p := make([]byte, len(full))
		if _, err := ReadAt(er, c, src, p, 0); err != io.EOF {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(p, full) {
			t.Fatalf("read %d mismatch", i)
		}
	}
	if got := er.count(d); got != 1 {
		t.Fatalf("backend fetched %d times, want 1 (cache should absorb the rest)", got)
	}
}

// TestCacheMissThenHit: a fresh cache misses (fetches), then hits.
func TestCacheMissThenHit(t *testing.T) {
	c := NewCache(1 << 20)
	if _, ok := c.Get(addr("nope")); ok {
		t.Fatal("empty cache must miss")
	}
	c.Add(addr("v"), []byte("v"))
	if v, ok := c.Get(addr("v")); !ok || string(v) != "v" {
		t.Fatalf("cache hit = %q,%v want v,true", v, ok)
	}
}

// TestCacheEvictionExactlyAtBound: an Add that brings curBytes to exactly
// maxBytes must NOT evict; one byte over must evict exactly enough.
func TestCacheEvictionExactlyAtBound(t *testing.T) {
	c := NewCache(8)
	a, b := addr("aaaa"), addr("bbbb")
	c.Add(a, []byte("aaaa")) // 4
	c.Add(b, []byte("bbbb")) // 4 -> total exactly 8 == bound, nothing evicted
	if _, ok := c.Get(a); !ok {
		t.Fatal("a evicted at exactly-the-bound (should fit)")
	}
	if _, ok := c.Get(b); !ok {
		t.Fatal("b evicted at exactly-the-bound (should fit)")
	}

	// Now push one byte over. b is currently LRU (we just Got a... actually Get(a)
	// then Get(b) above made b MRU). Re-establish a known order.
	c.Get(a) // a MRU, b LRU
	cc := addr("c")
	c.Add(cc, []byte("c")) // total 9 > 8 -> evict exactly LRU (b), now 5
	if _, ok := c.Get(b); ok {
		t.Fatal("b should be evicted when one byte over the bound")
	}
	if _, ok := c.Get(a); !ok {
		t.Fatal("a (MRU) must survive a single-entry eviction")
	}
	if _, ok := c.Get(cc); !ok {
		t.Fatal("freshly added entry must be present")
	}
}

// TestCacheEntryEqualToBudgetFits: an entry whose size equals the whole budget
// is cacheable (the reject is strictly greater-than).
func TestCacheEntryEqualToBudgetFits(t *testing.T) {
	c := NewCache(4)
	k := addr("abcd")
	c.Add(k, []byte("abcd")) // exactly 4 == budget
	if _, ok := c.Get(k); !ok {
		t.Fatal("entry equal to the budget should fit")
	}
	// Adding any second entry evicts the first (budget can hold only one).
	k2 := addr("e")
	c.Add(k2, []byte("e"))
	if _, ok := c.Get(k); ok {
		t.Fatal("first entry should have been evicted to fit the second")
	}
}

// TestCacheRefreshUpdatesByteAccounting: re-Adding an existing key with a
// different-sized value updates curBytes (so the bound stays correct).
func TestCacheRefreshUpdatesByteAccounting(t *testing.T) {
	c := NewCache(10)
	k := addr("aa")
	c.Add(k, []byte("aa"))       // 2
	c.Add(k, []byte("aaaaaaaa")) // grow same key to 8; curBytes must be 8, not 10
	// There is room for 2 more bytes.
	k2 := addr("zz")
	c.Add(k2, []byte("zz")) // 8+2 = 10 == bound, nothing evicted
	if _, ok := c.Get(k); !ok {
		t.Fatal("grown key evicted incorrectly (byte accounting drifted on refresh)")
	}
	if _, ok := c.Get(k2); !ok {
		t.Fatal("second key should fit exactly at the bound after refresh")
	}
}

// TestNilCacheGetIsNoop: a nil Cache (caching disabled) misses on Get and is
// safe to thread through ReadAt — the documented "no cache" mode, exercised by
// every existing ReadAt(_, nil, ...) call in the package.
func TestNilCacheGetIsNoop(t *testing.T) {
	var c Cache // nil *lruCache
	if _, ok := c.Get(addr("x")); ok {
		t.Fatal("nil cache must miss")
	}
	er := newErrReader()
	full := []byte("readme")
	d := er.put(full)
	src := Source{Size: int64(len(full)), BlobDigest: d}
	p := make([]byte, len(full))
	if _, err := ReadAt(er, c, src, p, 0); err != io.EOF || !bytes.Equal(p, full) {
		t.Fatalf("nil-cache read failed: %q %v", p, err)
	}
}

// TestNilCacheAddIsNoop: Add on a nil Cache should be a no-op, mirroring Get's
// `if c == nil` guard (a nil Cache is the package's "caching disabled" value).
//
// KNOWN BUG: Cache.Add lacks the nil-receiver guard that Cache.Get has. addRAM
// guards c==nil and returns, but Add then unconditionally reads c.disk
// (cache.go:92), dereferencing the nil *lruCache and panicking with a SIGSEGV.
func TestNilCacheAddIsNoop(t *testing.T) {
	var c Cache                   // nil *lruCache (the package's "caching disabled" value)
	c.Add(addr("x"), []byte("x")) // must be a no-op, not a nil-pointer panic (mirrors Get's guard)
	if _, ok := c.Get(addr("x")); ok {
		t.Fatal("nil cache must not store")
	}
}

// ---------------------------------------------------------------------------
// Cache: concurrent reads sharing one cache (run under -race).
// ---------------------------------------------------------------------------

// TestConcurrentReadsShareCache: many goroutines reading overlapping random
// windows of one chunked file through one shared cache must all get correct
// bytes, with no race and a bounded backend fetch count.
func TestConcurrentReadsShareCache(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))
	full := make([]byte, 1<<16) // 64 KiB
	rng.Read(full)
	er := newErrReader()
	// Build a chunked source over the shared errReader so we can count fetches.
	var chunks []backend.Chunk
	const chunkSize = 4096
	for off := 0; off < len(full); off += chunkSize {
		end := off + chunkSize
		if end > len(full) {
			end = len(full)
		}
		d := er.put(full[off:end])
		chunks = append(chunks, backend.Chunk{Digest: d, Size: int64(end - off), Offset: int64(off)})
	}
	src := Source{Size: int64(len(full)), Chunks: chunks}
	cache := NewCache(1 << 20) // comfortably holds the whole file

	var wg sync.WaitGroup
	var failures atomic.Int64
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			for i := 0; i < 200; i++ {
				off := int64(r.Intn(len(full) + 1))
				ln := int64(r.Intn(len(full)))
				p := make([]byte, ln)
				n, err := ReadAt(er, cache, src, p, off)
				if err != nil && err != io.EOF {
					failures.Add(1)
					return
				}
				if !bytes.Equal(p[:n], full[off:off+int64(n)]) {
					failures.Add(1)
					return
				}
			}
		}(int64(g))
	}
	wg.Wait()
	if f := failures.Load(); f != 0 {
		t.Fatalf("%d concurrent readers observed wrong bytes or errors", f)
	}
	// Each distinct chunk should be fetched at least once; the cache should keep
	// the total well below the ~24*200 read calls. (Exact dedup-to-one is not
	// guaranteed: concurrent misses for the same digest can both fetch before
	// either populates the cache. We only assert it's far below the no-cache
	// worst case.)
	total := 0
	for _, ch := range chunks {
		total += er.count(ch.Digest)
	}
	if total > len(chunks)*8 {
		t.Fatalf("backend fetched %d times across %d chunks; cache is not absorbing reads", total, len(chunks))
	}
}

// TestConcurrentCacheAddGet hammers the LRU's Add/Get with overlapping keys
// under -race to catch unsynchronized map/list access or byte-accounting drift.
func TestConcurrentCacheAddGet(t *testing.T) {
	c := NewCache(64) // small enough to force constant eviction
	keys := make([]string, 16)
	vals := make([][]byte, 16)
	for i := range keys {
		v := bytes.Repeat([]byte{byte('a' + i)}, 4)
		vals[i] = v
		keys[i] = digestOf(v)
	}
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			for i := 0; i < 1000; i++ {
				k := r.Intn(len(keys))
				if r.Intn(2) == 0 {
					c.Add(keys[k], vals[k])
				} else if v, ok := c.Get(keys[k]); ok && !bytes.Equal(v, vals[k]) {
					t.Errorf("cache returned wrong bytes for key %d", k)
					return
				}
			}
		}(int64(g) + 1)
	}
	wg.Wait()
}

// TestConcurrentWholeSharesCache runs Whole from many goroutines against one
// chunked source + shared cache; every result must equal the original bytes.
func TestConcurrentWholeSharesCache(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	full := make([]byte, 20000)
	rng.Read(full)
	m, src := buildChunked(t, full, 1500) // last chunk partial (20000 % 1500 != 0)
	cache := NewCache(1 << 20)

	var wg sync.WaitGroup
	var bad atomic.Int64
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := Whole(m, cache, src)
			if err != nil || !bytes.Equal(got, full) {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d Whole calls returned wrong/erroring bytes", bad.Load())
	}
}

// ---------------------------------------------------------------------------
// Reconstruction == original for random offset/length slices (chunked & blob),
// including the cached path.
// ---------------------------------------------------------------------------

func TestReconstructionEqualsOriginalRandomSlices(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBADC0DE))
	for _, size := range []int{0, 1, 2, 7, 8, 9, 4095, 4096, 4097, 12345} {
		full := make([]byte, size)
		rng.Read(full)

		for _, chunkSize := range []int64{1, 3, 8, 4096, int64(maxInt(size, 1))} {
			m, src := buildChunked(t, full, chunkSize)
			cache := NewCache(1 << 22)

			for iter := 0; iter < 40; iter++ {
				var off, ln int64
				if size == 0 {
					off, ln = 0, int64(rng.Intn(4))
				} else {
					off = int64(rng.Intn(size + 1))
					ln = int64(rng.Intn(size + 2))
				}
				// Read uncached then cached; both must equal the original slice.
				p1 := make([]byte, ln)
				n1, e1 := ReadAt(m, nil, src, p1, off)
				p2 := make([]byte, ln)
				n2, e2 := ReadAt(m, cache, src, p2, off)

				wantEnd := off + ln
				if wantEnd > int64(size) {
					wantEnd = int64(size)
				}
				wantN := int64(0)
				if off < int64(size) {
					wantN = wantEnd - off
				}
				if int64(n1) != wantN || int64(n2) != wantN {
					t.Fatalf("size=%d cs=%d off=%d ln=%d: n1=%d n2=%d want %d", size, chunkSize, off, ln, n1, n2, wantN)
				}
				if !bytes.Equal(p1[:n1], full[off:off+int64(n1)]) || !bytes.Equal(p2[:n2], full[off:off+int64(n2)]) {
					t.Fatalf("size=%d cs=%d off=%d ln=%d: reconstruction mismatch", size, chunkSize, off, ln)
				}
				for _, e := range []error{e1, e2} {
					reachedEnd := off >= int64(size) || off+ln >= int64(size)
					if reachedEnd && e != io.EOF {
						t.Fatalf("size=%d off=%d ln=%d: err=%v want EOF", size, off, ln, e)
					}
					if !reachedEnd && e != nil {
						t.Fatalf("size=%d off=%d ln=%d: err=%v want nil", size, off, ln, e)
					}
				}
			}

			// Whole must equal the original for every chunk size.
			if size > 0 {
				got, err := Whole(m, nil, src)
				if err != nil || !bytes.Equal(got, full) {
					t.Fatalf("Whole size=%d cs=%d mismatch (err=%v)", size, chunkSize, err)
				}
			}
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// TestReadFullEqualsWhole cross-checks the two read paths against each other: a
// sequential drain via ReadAt must equal Whole for assorted buffer sizes.
func TestReadFullEqualsWhole(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	full := make([]byte, 9999)
	rng.Read(full)
	m, src := buildChunked(t, full, 256)
	whole, err := Whole(m, nil, src)
	if err != nil || !bytes.Equal(whole, full) {
		t.Fatalf("Whole mismatch: %v", err)
	}
	for _, buf := range []int{1, 2, 255, 256, 257, 1000, 100000} {
		if got := readFull(t, m, nil, src, buf); !bytes.Equal(got, full) {
			t.Fatalf("readFull(buf=%d) != original", buf)
		}
	}
}

// ---------------------------------------------------------------------------
// Whole: malformed-layout sweep (overlap, gap, out-of-range, negative size,
// wrong total) — each must be a loud error, never a panic or silent fill.
// ---------------------------------------------------------------------------

func TestWholeMalformedLayouts(t *testing.T) {
	mk := func(chunks []backend.Chunk, size int64) Source { return Source{Size: size, Chunks: chunks} }
	d := digestOf([]byte("XX"))
	cases := map[string]Source{
		"overlap": mk([]backend.Chunk{
			{Digest: d, Size: 2, Offset: 0},
			{Digest: d, Size: 2, Offset: 1}, // overlaps previous
		}, 4),
		"gap": mk([]backend.Chunk{
			{Digest: d, Size: 2, Offset: 0},
			{Digest: d, Size: 2, Offset: 4}, // hole at [2,4)
		}, 6),
		"out-of-range": mk([]backend.Chunk{
			{Digest: d, Size: 2, Offset: 10},
		}, 4),
		"negative-size": mk([]backend.Chunk{
			{Digest: d, Size: -1, Offset: 0},
		}, 4),
		"under-covers": mk([]backend.Chunk{
			{Digest: d, Size: 2, Offset: 0}, // covers 2 of 4
		}, 4),
		"over-covers": mk([]backend.Chunk{
			{Digest: d, Size: 2, Offset: 0},
			{Digest: d, Size: 2, Offset: 2},
		}, 2), // chunks tile to 4 but Size says 2
	}
	m := mapReader{digestOf([]byte("XX")): []byte("XX")}
	for name, src := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: Whole panicked: %v", name, r)
				}
			}()
			if _, err := Whole(m, nil, src); err == nil {
				t.Fatalf("%s: expected a malformed-layout error, got nil", name)
			}
		}()
	}
}

// ---------------------------------------------------------------------------
// Out-of-order chunks: ReadAt and Whole must both reassemble correctly, and a
// random shuffle must equal the original (the TS/Go readers must agree).
// ---------------------------------------------------------------------------

func TestShuffledChunksReconstruct(t *testing.T) {
	rng := rand.New(rand.NewSource(2026))
	full := make([]byte, 5000)
	rng.Read(full)
	_, ordered := buildChunked(t, full, 137) // last chunk partial
	// Shuffle a copy of the chunk slice; the manifest order must not matter.
	shuffled := append([]backend.Chunk(nil), ordered.Chunks...)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	src := Source{Size: ordered.Size, Chunks: shuffled}
	// Rebuild the reader (chunkOf already stored bytes during buildChunked, but
	// use a fresh reader keyed by the same digests to be explicit).
	m := mapReader{}
	for off := 0; off < len(full); off += 137 {
		end := off + 137
		if end > len(full) {
			end = len(full)
		}
		m[digestOf(full[off:end])] = full[off:end]
	}

	if got, err := Whole(m, nil, src); err != nil || !bytes.Equal(got, full) {
		t.Fatalf("Whole on shuffled chunks: err=%v equal=%v", err, bytes.Equal(got, full))
	}
	if got := readFull(t, m, nil, src, 333); !bytes.Equal(got, full) {
		t.Fatal("readFull on shuffled chunks != original")
	}

	// orderedChunks must not mutate the caller's slice when it has to sort.
	before := append([]backend.Chunk(nil), shuffled...)
	_ = orderedChunks(shuffled)
	if !chunkSlicesEqual(shuffled, before) {
		t.Fatal("orderedChunks mutated the caller's slice")
	}
}

func chunkSlicesEqual(a, b []backend.Chunk) bool {
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

// ---------------------------------------------------------------------------
// Idempotent repeat / resend: reading the same window twice yields identical
// bytes and EOF state (exactly-once is about the cache fetch count, covered in
// TestCacheHitAvoidsRefetch; here we assert observable idempotence).
// ---------------------------------------------------------------------------

func TestRepeatedReadsAreIdempotent(t *testing.T) {
	full := []byte("idempotent-content-here")
	m, src := buildChunked(t, full, 5)
	c := NewCache(1 << 20)
	var first []byte
	var firstErr error
	for i := 0; i < 10; i++ {
		p := make([]byte, 7)
		n, err := ReadAt(m, c, src, p, 4)
		if i == 0 {
			first = append([]byte(nil), p[:n]...)
			firstErr = err
			continue
		}
		if !bytes.Equal(p[:n], first) || err != firstErr {
			t.Fatalf("read %d differs: %q,%v vs %q,%v", i, p[:n], err, first, firstErr)
		}
	}
}
