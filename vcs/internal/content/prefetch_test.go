package content

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type countingReader struct {
	mu      sync.Mutex
	data    map[string][]byte
	fetched map[string]int
}

func (c *countingReader) Blob(_ context.Context, d string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetched[d]++
	b, ok := c.data[d]
	if !ok {
		return nil, errors.New("no blob")
	}
	return b, nil
}

func (c *countingReader) count(d string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetched[d]
}

// TestPrefetchWarmsAndDedups: prefetch warms the cache, deduplicates digests, and
// reports the fetched count/bytes.
func TestPrefetchWarmsAndDedups(t *testing.T) {
	da, db := addr("aaaa"), addr("bbbb")
	cb := &countingReader{
		data:    map[string][]byte{da: []byte("aaaa"), db: []byte("bbbb")},
		fetched: map[string]int{},
	}
	cache := NewCache(1024)
	sources := []PrefetchSource{
		{Digest: da, Size: 4},
		{Digest: db, Size: 4},
		{Digest: da, Size: 4}, // duplicate -> deduped
	}
	n, b := Prefetch(context.Background(), cb, cache, sources, 4, 0)
	if n != 2 || b != 8 {
		t.Fatalf("prefetch n=%d b=%d, want 2,8", n, b)
	}
	if _, ok := cache.Get(da); !ok {
		t.Fatal("a not warmed into cache")
	}
	if _, ok := cache.Get(db); !ok {
		t.Fatal("b not warmed into cache")
	}
	if cb.count(da) != 1 {
		t.Fatalf("a fetched %d times, want 1 (deduped)", cb.count(da))
	}
}

// TestPrefetchRespectsBudget: prefetch never fetches more than maxBytes.
func TestPrefetchRespectsBudget(t *testing.T) {
	da, db := addr("aaaaa"), addr("bbbbb")
	cb := &countingReader{
		data:    map[string][]byte{da: []byte("aaaaa"), db: []byte("bbbbb")},
		fetched: map[string]int{},
	}
	cache := NewCache(1024)
	sources := []PrefetchSource{{Digest: da, Size: 5}, {Digest: db, Size: 5}}
	n, b := Prefetch(context.Background(), cb, cache, sources, 4, 5) // budget fits only one
	if n != 1 || b != 5 {
		t.Fatalf("budgeted prefetch n=%d b=%d, want 1,5", n, b)
	}
}
