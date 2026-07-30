package clientcore

import (
	"strings"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// AttrEntry is one version-gated metadata cache entry. Exists=false represents a cached ENOENT
// lookup, valid only when the authority supplied a parent-directory version for the miss.
type AttrEntry struct {
	Attr    fsproto.Attr
	Exists  bool
	Gen     uint64
	Version uint64
}

// MaxAttrEntries soft-bounds the cache. Readdir-plus fills eagerly, so the cache must stay a pure
// optimization: evicting an entry only costs a refetch, never correctness.
const MaxAttrEntries = 200_000

// AttrCache is the frontend-neutral, version-coherent attribute/lookup cache. Frontends keep their
// kernel entry TTLs coherent by version/invalidation; this cache absorbs the authority round-trips.
type AttrCache struct {
	mu sync.Mutex
	m  map[string]AttrEntry
}

// NewAttrCache returns an empty attribute cache.
func NewAttrCache() *AttrCache { return &AttrCache{m: map[string]AttrEntry{}} }

func (c *AttrCache) capLocked() {
	if len(c.m) <= MaxAttrEntries {
		return
	}
	for k := range c.m {
		delete(c.m, k)
		break
	}
}

// Get returns the cached entry for path iff it was cached under gen and its version is not behind
// curVer, the highest version the invalidation stream has recorded for path.
func (c *AttrCache) Get(gen, curVer uint64, path string) (AttrEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[path]
	if !ok || e.Gen != gen || e.Version < curVer {
		return AttrEntry{}, false
	}
	return e, true
}

// GetLookup is Get with the extra parent-version gate required for cached negatives. Positive
// entries are validated against the path's own version; negative entries are validated against the
// parent directory version that made the miss safe.
func (c *AttrCache) GetLookup(gen, pathCurVer, parentCurVer uint64, path string) (AttrEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[path]
	if !ok || e.Gen != gen {
		return AttrEntry{}, false
	}
	curVer := pathCurVer
	if !e.Exists {
		curVer = parentCurVer
	}
	if e.Version < curVer {
		return AttrEntry{}, false
	}
	return e, true
}

// PutAttr caches a positive lookup/getattr result at the given generation and coherence version.
func (c *AttrCache) PutAttr(gen, version uint64, path string, attr fsproto.Attr) {
	c.mu.Lock()
	c.m[path] = AttrEntry{Attr: attr, Exists: true, Gen: gen, Version: version}
	c.capLocked()
	c.mu.Unlock()
}

// PutNegative caches a version-gated ENOENT result. Callers must only use this when the authority
// returned a parent directory version for the miss; unversioned negatives are unsafe.
func (c *AttrCache) PutNegative(gen, version uint64, path string) {
	c.mu.Lock()
	c.m[path] = AttrEntry{Exists: false, Gen: gen, Version: version}
	c.capLocked()
	c.mu.Unlock()
}

// Evict drops one path after an invalidation or local mutation.
func (c *AttrCache) Evict(path string) {
	c.mu.Lock()
	delete(c.m, path)
	c.mu.Unlock()
}

// Clear drops every entry on FlushAll, generation change, or resubscribe.
func (c *AttrCache) Clear() {
	c.mu.Lock()
	c.m = map[string]AttrEntry{}
	c.mu.Unlock()
}

// Len returns the current number of cached lookup/attr entries for observability.
func (c *AttrCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// EvictPrefix drops every entry at or under subtree root rp.
func (c *AttrCache) EvictPrefix(rp string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rp == "" {
		c.m = map[string]AttrEntry{}
		return
	}
	pfx := rp + "/"
	for k := range c.m {
		if k == rp || strings.HasPrefix(k, pfx) {
			delete(c.m, k)
		}
	}
}
