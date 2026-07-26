package content

import (
	"container/list"
	"sync"

	"github.com/trendup-ai/portablefs/vcs/internal/metrics"
	"github.com/trendup-ai/portablefs/vcs/internal/secure"
)

// Metric handles resolved once (atomic ops on the hot read path, no registry lock).
var (
	cacheRAMHits  = metrics.Default.Counter("vcs_cache_ram_hits")
	cacheDiskHits = metrics.Default.Counter("vcs_cache_disk_hits")
	cacheMisses   = metrics.Default.Counter("vcs_cache_misses")
)

// Cache is a byte-bounded LRU of digest -> bytes, shared by the read paths.
// Bounding by total bytes (not entry count) keeps resident memory predictable
// when entries are large blocks — a 1024-entry cap of 4 MiB blocks would be 4 GiB.
type Cache = *lruCache

type lruCache struct {
	mu       sync.Mutex
	maxBytes int64
	curBytes int64
	ll       *list.List // front = most recently used
	items    map[string]*list.Element
	disk     *diskCache // optional second tier (local NVMe)
}

type cacheEntry struct {
	key string
	val []byte
}

// NewCache builds a byte-bounded in-memory cache. A non-positive budget disables
// caching.
func NewCache(maxBytes int64) Cache {
	return &lruCache{maxBytes: maxBytes, ll: list.New(), items: map[string]*list.Element{}}
}

// NewTieredCache builds an in-memory cache backed by a persistent disk tier at
// dir (capacity diskBytes), so the working set can exceed RAM and survives
// restarts. A non-positive diskBytes (or empty dir) yields a RAM-only cache. When
// enc is non-nil the disk tier is sealed with AES-256-GCM at rest.
func NewTieredCache(ramBytes int64, dir string, diskBytes int64, enc *secure.AtRest) (Cache, error) {
	c := NewCache(ramBytes)
	if dir == "" || diskBytes <= 0 {
		return c, nil
	}
	disk, err := newDiskCache(dir, diskBytes, enc)
	if err != nil {
		return nil, err
	}
	c.disk = disk
	return c, nil
}

// Get returns the cached bytes for key and marks it most-recently-used. On a RAM
// miss it consults the disk tier and promotes a hit back into RAM.
func (c *lruCache) Get(key string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	if c.maxBytes > 0 {
		c.mu.Lock()
		if el, ok := c.items[key]; ok {
			c.ll.MoveToFront(el)
			val := el.Value.(*cacheEntry).val
			c.mu.Unlock()
			cacheRAMHits.Inc()
			return val, true
		}
		c.mu.Unlock()
	}
	if c.disk != nil {
		if val, hit := c.disk.Get(key); hit {
			c.addRAM(key, val) // no-op if RAM is disabled
			cacheDiskHits.Inc()
			return val, true
		}
	}
	cacheMisses.Inc()
	return nil, false
}

// Add inserts (or refreshes) key -> val in RAM and the disk tier, evicting
// least-recently-used entries from each until within budget.
func (c *lruCache) Add(key string, val []byte) {
	if c == nil {
		return // mirror Get's nil-receiver guard: a nil Cache is a valid "no cache"
	}
	c.addRAM(key, val)
	if c.disk != nil {
		c.disk.Add(key, val)
	}
}

// addRAM updates only the in-memory tier (used by Add and by disk-hit promotion).
func (c *lruCache) addRAM(key string, val []byte) {
	if c == nil || c.maxBytes <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		ent := el.Value.(*cacheEntry)
		c.curBytes += int64(len(val)) - int64(len(ent.val))
		ent.val = val
		c.ll.MoveToFront(el)
	} else {
		if int64(len(val)) > c.maxBytes {
			return
		}
		c.items[key] = c.ll.PushFront(&cacheEntry{key: key, val: val})
		c.curBytes += int64(len(val))
	}
	for c.curBytes > c.maxBytes {
		back := c.ll.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*cacheEntry)
		c.ll.Remove(back)
		delete(c.items, ent.key)
		c.curBytes -= int64(len(ent.val))
	}
}
