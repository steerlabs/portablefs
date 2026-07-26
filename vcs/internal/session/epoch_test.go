package session

import (
	"sync"
	"testing"
)

// TestNextEpochStrictlyMonotonic: session generation epochs must STRICTLY increase even
// under rapid back-to-back allocation (sub-nanosecond) — otherwise a fast re-acquire would
// reuse/decrease the epoch and the authority would silently drop the new generation's Seq-0
// writes (a repeated-write ordering bug). Time-based UnixNano alone does not guarantee this.
func TestNextEpochStrictlyMonotonic(t *testing.T) {
	prev := nextEpoch()
	for i := 0; i < 200000; i++ {
		e := nextEpoch()
		if e <= prev {
			t.Fatalf("nextEpoch not strictly monotonic at i=%d: %d <= %d", i, e, prev)
		}
		prev = e
	}
}

// TestNextEpochConcurrentUnique: concurrent allocators never collide (each session instance
// must get a distinct generation, or two could share a watermark).
func TestNextEpochConcurrentUnique(t *testing.T) {
	const G, N = 16, 5000
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[uint64]struct{}, G*N)
	dup := 0
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]uint64, 0, N)
			for i := 0; i < N; i++ {
				local = append(local, nextEpoch())
			}
			mu.Lock()
			for _, e := range local {
				if _, ok := seen[e]; ok {
					dup++
				}
				seen[e] = struct{}{}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if dup != 0 {
		t.Fatalf("nextEpoch produced %d duplicate epochs across %d goroutines (watermark collision risk)", dup, G)
	}
}
