package content

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/steerlabs/portablefs/vcs/internal/metrics"
)

var (
	prefetchBlobs = metrics.Default.Counter("vcs_prefetch_blobs")
	prefetchBytes = metrics.Default.Counter("vcs_prefetch_bytes")
)

// PrefetchSource is a blob to warm into the cache.
type PrefetchSource struct {
	Digest string
	Size   int64
}

// Prefetch warms the cache with the given sources — deduplicated, fetched in
// parallel (up to concurrency), and bounded by maxBytes so it never fetches more
// than the cache can hold (maxBytes <= 0 = unbounded). It stops on ctx
// cancellation (e.g. shutdown) and returns the number of blobs + bytes fetched.
// Failures are skipped (best-effort warming); on-demand reads still fall through
// to the source.
func Prefetch(
	ctx context.Context,
	blobs BlobReader,
	cache Cache,
	sources []PrefetchSource,
	concurrency int,
	maxBytes int64,
) (int, int64) {
	if cache == nil || len(sources) == 0 {
		return 0, 0
	}
	if concurrency < 1 {
		concurrency = 1
	}

	seen := make(map[string]struct{}, len(sources))
	planned := make([]PrefetchSource, 0, len(sources))
	var plannedBytes int64
	for _, s := range sources {
		if s.Digest == "" {
			continue
		}
		if _, ok := seen[s.Digest]; ok {
			continue
		}
		seen[s.Digest] = struct{}{}
		if maxBytes > 0 && plannedBytes+s.Size > maxBytes {
			continue // would not fit in the cache; skip rather than thrash
		}
		planned = append(planned, s)
		plannedBytes += s.Size
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var count, bytes atomic.Int64
	for _, s := range planned {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(s PrefetchSource) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			data, err := blobs.Blob(ctx, s.Digest)
			if err != nil {
				return
			}
			// Verify before warming the cache: never populate a tier with bytes that
			// don't match their content address (same guarantee as the on-demand path).
			if verifyDigest(s.Digest, data) != nil {
				return
			}
			cache.Add(s.Digest, data)
			count.Add(1)
			bytes.Add(int64(len(data)))
		}(s)
	}
	wg.Wait()

	n, b := int(count.Load()), bytes.Load()
	prefetchBlobs.Add(int64(n))
	prefetchBytes.Add(b)
	return n, b
}
