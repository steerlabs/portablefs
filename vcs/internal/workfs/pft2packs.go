package workfs

// Shared verified immutable PFT2 pack cache.
//
// One packed data object (up to pft2.MaxPackBytes = 4 MiB) backs up to 1024
// distinct 4 KiB cells. Reading a dense range therefore must never fetch the
// same pack once per cell: rangers group each operation's extents by exact
// pack reference and fetch every unique pack AT MOST once per operation, and
// this FS-wide cache makes repeated operations (including the partial-write
// warm path) free.
//
// Integrity and bounds:
//   - Keys are exact pft2.Ref values (32-byte digest + exact size) taken from
//     already digest-verified DataPage metadata — never free-form or
//     attacker-controlled strings — and every ref is size-bounded to the
//     frozen pack format before any allocation.
//   - An entry is inserted ONLY after the fetched bytes hash to the exact
//     reference, so a failed, truncated, or corrupt fetch can never poison
//     the cache; the error propagates and a retry refetches.
//   - Cached bytes are immutable and shared read-only; per-cell logical
//     verification (pft2.VerifyCellBytes: cell digest + terminal-zero tail)
//     runs on every read, so a pack that is object-digest-valid but carries
//     a lying cell never serves bytes — from the network or from the cache.
//   - Resident bytes are bounded by maxBytes with LRU eviction; identical
//     in-flight fetches coalesce on one flight (waiters honor cancellation,
//     the leader completes and publishes for everyone).

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
)

// isContextError reports whether err is a caller-cancellation artifact
// (never evidence about the fetched object or the store).
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// pft2PackCacheBytes bounds the FS-wide verified pack cache (16 packs at the
// 4 MiB format maximum). Tests may lower it through setMaxBytes.
const pft2PackCacheBytes = int64(64 << 20)

type pft2PackCache struct {
	fetcher pft2.Fetcher

	mu       sync.Mutex
	maxBytes int64
	curBytes int64
	ll       *list.List
	items    map[pft2.Ref]*list.Element
	flight   map[pft2.Ref]*packFlight
	fetches  uint64 // observability for tests: fetcher round-trips issued
}

type packFlight struct {
	done chan struct{}
	data []byte
	err  error
}

type packCacheEntry struct {
	ref  pft2.Ref
	data []byte
}

func newPft2PackCache(fetcher pft2.Fetcher, maxBytes int64) *pft2PackCache {
	return &pft2PackCache{
		fetcher:  fetcher,
		maxBytes: maxBytes,
		ll:       list.New(),
		items:    map[pft2.Ref]*list.Element{},
		flight:   map[pft2.Ref]*packFlight{},
	}
}

// setMaxBytes rebounds the cache (tests). Shrinking evicts immediately.
func (c *pft2PackCache) setMaxBytes(maxBytes int64) {
	c.mu.Lock()
	c.maxBytes = maxBytes
	c.evictLocked()
	c.mu.Unlock()
}

func (c *pft2PackCache) residentBytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.curBytes
}

func (c *pft2PackCache) fetchCount() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetches
}

// fetch returns the verified exact bytes of one immutable pack object,
// serving from cache when resident and coalescing concurrent misses.
func (c *pft2PackCache) fetch(ctx context.Context, ref pft2.Ref) ([]byte, error) {
	if ref.Size == 0 || ref.Size > pft2.MaxPackBytes {
		return nil, fmt.Errorf("workfs: pft2 pack ref size %d outside the frozen 1..%d pack bounds", ref.Size, pft2.MaxPackBytes)
	}
	for {
		c.mu.Lock()
		if el, ok := c.items[ref]; ok {
			c.ll.MoveToFront(el)
			data := el.Value.(*packCacheEntry).data
			c.mu.Unlock()
			return data, nil
		}
		if inflight, ok := c.flight[ref]; ok {
			c.mu.Unlock()
			select {
			case <-inflight.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if inflight.err != nil {
				// A leader that was CANCELED must not poison live waiters:
				// its context error says nothing about the object or the
				// store. The flight is already cleared, so a live waiter
				// simply becomes the next leader. Every other failure is
				// shared (the store/object really failed).
				if isContextError(inflight.err) && ctx.Err() == nil {
					continue
				}
				return nil, inflight.err
			}
			return inflight.data, nil
		}
		flight := &packFlight{done: make(chan struct{})}
		c.flight[ref] = flight
		c.fetches++
		c.mu.Unlock()

		data, err := c.fetcher.Fetch(ctx, ref)
		if err == nil && pft2.RefOf(data) != ref {
			err = fmt.Errorf("workfs: pft2 pack object does not hash to its exact reference (%s)", ref)
			data = nil
		}
		flight.data, flight.err = data, err

		c.mu.Lock()
		delete(c.flight, ref)
		if err == nil {
			c.addLocked(ref, data)
		}
		c.mu.Unlock()
		close(flight.done)
		return data, err
	}
}

// addLocked inserts one VERIFIED pack and evicts LRU overflow. Oversized
// entries (larger than the whole budget) are served but never retained.
func (c *pft2PackCache) addLocked(ref pft2.Ref, data []byte) {
	if c.maxBytes <= 0 || int64(len(data)) > c.maxBytes {
		return
	}
	if _, exists := c.items[ref]; exists {
		return
	}
	el := c.ll.PushFront(&packCacheEntry{ref: ref, data: data})
	c.items[ref] = el
	c.curBytes += int64(len(data))
	c.evictLocked()
}

func (c *pft2PackCache) evictLocked() {
	for c.curBytes > c.maxBytes {
		back := c.ll.Back()
		if back == nil {
			return
		}
		entry := back.Value.(*packCacheEntry)
		c.ll.Remove(back)
		delete(c.items, entry.ref)
		c.curBytes -= int64(len(entry.data))
	}
}
