// Package content reads a file's bytes from the content-addressed backend,
// lazily and with caching: a whole-file blob is fetched once and cached; a
// chunked file fetches only the chunks a given range actually touches. Shared by
// the read-only (volfs) and read-write (workfs) filesystems.
package content

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
)

// fetchParallelism bounds concurrent chunk fetches (parallel I/O across the
// content store, like the multi-server reads).
const fetchParallelism = 8

var (
	bucketFetches      = metrics.Default.Counter("vcs_bucket_fetches")
	bucketFetchBytes   = metrics.Default.Counter("vcs_bucket_fetch_bytes")
	bucketFetchLatency = metrics.Default.Histogram("vcs_bucket_fetch_latency")
)

// BlobReader fetches content-addressed bytes (a blob or chunk) by digest.
type BlobReader interface {
	Blob(ctx context.Context, digest string) ([]byte, error)
}

// Ranger reads a verified logical byte range of one immutable base file.
// PFT2-backed sources implement it over lazy extent-tree walks; every fetched
// object is digest-verified before any byte is returned.
type Ranger interface {
	ReadRangeAt(ctx context.Context, p []byte, off int64) (int, error)
}

// Source describes where a file's bytes live in the backend. BlobDigest/Chunks
// and Size drive reads; the BlobSize/Compression/Packed fields let a checkpoint
// reproduce a clean file's exact manifest entry. A Ranger source (PFT2 base)
// reads through its own verified extent walk instead of blob digests.
type Source struct {
	BlobDigest      string
	BlobSize        int64
	BlobCompression string
	BlobPacked      bool
	Chunks          []backend.Chunk
	Size            int64
	Ranger          Ranger
}

// verifyDigest checks that data hashes to its content address. Content-addressed
// storage must verify on read: a corrupt or truncated blob (bit-rot in the bucket,
// a torn cache file, a misbehaving adapter) is then caught instead of being served
// as valid file bytes. All digests are "sha256:<hex>".
func verifyDigest(digest string, data []byte) error {
	want := strings.TrimPrefix(digest, "sha256:")
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("content: digest mismatch for %s (computed sha256:%s over %d bytes)", digest, got, len(data))
	}
	return nil
}

func fetch(blobs BlobReader, cache Cache, digest string) ([]byte, error) {
	if cache != nil {
		if b, ok := cache.Get(digest); ok {
			return b, nil
		}
	}
	start := time.Now()
	b, err := blobs.Blob(context.Background(), digest)
	bucketFetches.Inc()
	bucketFetchLatency.Time(start)
	if err != nil {
		return nil, err
	}
	// Verify the fetched bytes against their content address before trusting or
	// caching them; a mismatch is a hard read error, never silently-wrong content.
	if err := verifyDigest(digest, b); err != nil {
		return nil, err
	}
	bucketFetchBytes.Add(int64(len(b)))
	if cache != nil {
		cache.Add(digest, b)
	}
	return b, nil
}

// ReadAt copies bytes [off, off+len(p)) of src into p, fetching only what's
// needed. Returns io.EOF at or past end.
func ReadAt(blobs BlobReader, cache Cache, src Source, p []byte, off int64) (int, error) {
	// A negative offset (e.g. a crafted OpRead with Offset: -1) must never reach
	// the whole-blob slice below (data[off:] would panic). Reject it here so
	// every caller is covered, not just the ones that pre-validate.
	if off < 0 {
		return 0, fmt.Errorf("content: negative read offset %d", off)
	}
	if src.Size == 0 || off >= src.Size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if off+want > src.Size {
		want = src.Size - off
	}

	if src.Ranger != nil {
		n, err := src.Ranger.ReadRangeAt(context.Background(), p[:want], off)
		if err != nil {
			return n, err
		}
		if off+int64(n) >= src.Size {
			return n, io.EOF
		}
		return n, nil
	}

	if len(src.Chunks) > 0 {
		// Place each chunk by its absolute offset, in ascending order. The chunk
		// layout is keyed off ch.Offset, NOT off how many bytes we've copied — using
		// the copy count as the cursor silently drops bytes when chunks are not in
		// strictly-ascending order (the TS reader sorts its chunks; the two readers
		// must agree on the byte layout, so we sort here too).
		chunks := orderedChunks(src.Chunks)
		reqStart, reqEnd := off, off+want
		cursor := reqStart // next byte offset still needed
		copied := int64(0)
		for _, ch := range chunks {
			if cursor >= reqEnd {
				break
			}
			chStart, chEnd := ch.Offset, ch.Offset+ch.Size
			if chEnd <= reqStart || chStart >= reqEnd {
				continue // chunk does not overlap the request window
			}
			if chStart > cursor {
				// No chunk covers [cursor, chStart): a hole in the manifest. A faithful
				// read is impossible, so fail loudly rather than serve zero-filled bytes.
				return int(copied), fmt.Errorf("content: gap in chunk coverage at offset %d", cursor)
			}
			data, err := fetch(blobs, cache, ch.Digest)
			if err != nil {
				return int(copied), err
			}
			from := reqStart - chStart
			if from < 0 {
				from = 0
			}
			to := reqEnd - chStart
			if to > ch.Size { // never read past the chunk's declared size into the next chunk
				to = ch.Size
			}
			if to > int64(len(data)) {
				to = int64(len(data))
			}
			if from < to {
				dstStart := (chStart + from) - off
				copied += int64(copy(p[dstStart:], data[from:to]))
			}
			if chEnd > cursor {
				cursor = chEnd
			}
		}
		if cursor < reqEnd {
			// The request tail is not covered by any chunk — a malformed manifest.
			return int(copied), fmt.Errorf("content: chunk coverage ends at %d before %d", cursor, reqEnd)
		}
		if off+want >= src.Size {
			return int(copied), io.EOF
		}
		return int(copied), nil
	}

	// Single whole-file blob.
	data, err := fetch(blobs, cache, src.BlobDigest)
	if err != nil {
		return 0, err
	}
	if off >= int64(len(data)) {
		return 0, io.EOF
	}
	nc := copy(p[:want], data[off:])
	if off+int64(nc) >= src.Size {
		return nc, io.EOF
	}
	return nc, nil
}

// Whole fetches and concatenates a source's full bytes (used for materializing a
// backed file before a local write). Chunks are fetched in parallel.
func Whole(blobs BlobReader, cache Cache, src Source) ([]byte, error) {
	if src.Size == 0 {
		return nil, nil
	}
	if src.Ranger != nil {
		out := make([]byte, src.Size)
		if _, err := src.Ranger.ReadRangeAt(context.Background(), out, 0); err != nil && err != io.EOF {
			return nil, err
		}
		return out, nil
	}
	if len(src.Chunks) == 0 {
		data, err := fetch(blobs, cache, src.BlobDigest)
		if err != nil {
			return nil, err
		}
		// Return a private copy: fetch may hand back a cache-owned slice, and a
		// materialize-before-write caller is expected to mutate the result — mutating
		// the cache's slice in place would poison it for every other reader.
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	}
	// Validate that the chunks tile [0,Size) exactly (ascending, no gap, overlap, or
	// out-of-range) before trusting the assembled bytes. This makes the parallel
	// copies provably in-bounds (no panic) and turns a malformed layout into a loud
	// error instead of a silently zero-filled or corrupted file.
	chunks := orderedChunks(src.Chunks)
	var cursor int64
	for _, ch := range chunks {
		if ch.Size < 0 || ch.Offset != cursor || ch.Offset+ch.Size > src.Size {
			return nil, fmt.Errorf("content: malformed chunk layout (offset %d size %d at expected offset %d of %d)", ch.Offset, ch.Size, cursor, src.Size)
		}
		cursor = ch.Offset + ch.Size
	}
	if cursor != src.Size {
		return nil, fmt.Errorf("content: chunks cover %d of %d bytes", cursor, src.Size)
	}
	out := make([]byte, src.Size)
	sem := make(chan struct{}, fetchParallelism)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for _, ch := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(ch backend.Chunk) {
			defer wg.Done()
			defer func() { <-sem }()
			data, err := fetch(blobs, cache, ch.Digest)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			n := int64(len(data))
			if n > ch.Size { // never bleed past the declared chunk size into the next chunk
				n = ch.Size
			}
			copy(out[ch.Offset:ch.Offset+n], data[:n]) // ranges validated disjoint -> no lock
		}(ch)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// orderedChunks returns chunks sorted ascending by offset. The common case — the
// Go checkpoint already emits ascending chunks — returns the input unchanged; an
// out-of-order manifest (e.g. authored by the TS side, which also sorts) gets a
// sorted copy so both readers assemble an identical byte layout.
func orderedChunks(chunks []backend.Chunk) []backend.Chunk {
	for i := 1; i < len(chunks); i++ {
		if chunks[i].Offset < chunks[i-1].Offset {
			out := append([]backend.Chunk(nil), chunks...)
			sort.SliceStable(out, func(a, b int) bool { return out[a].Offset < out[b].Offset })
			return out
		}
	}
	return chunks
}
