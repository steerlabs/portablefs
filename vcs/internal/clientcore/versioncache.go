package clientcore

import "sync"

// VersionCache tracks, per path, the highest coherence version installed or applied within the
// current authority generation. It is the monotonic gate behind both metadata and content caching.
type VersionCache struct {
	mu  sync.Mutex
	gen uint64
	m   map[string]uint64
}

// NewVersionCache returns an empty cache anchored to no generation.
func NewVersionCache() *VersionCache { return &VersionCache{m: map[string]uint64{}} }

// SeenGen reports whether g is the currently anchored authority generation.
func (c *VersionCache) SeenGen(g uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen == g
}

// CurrentGen returns the generation the cache is anchored to. Zero means unknown.
func (c *VersionCache) CurrentGen() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// GenAndVersion returns the current generation and the highest version recorded for path.
func (c *VersionCache) GenAndVersion(path string) (gen, version uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen, c.m[path]
}

// RefreshAll adopts generation g and drops every remembered path version.
func (c *VersionCache) RefreshAll(g uint64) {
	c.mu.Lock()
	c.gen = g
	c.m = map[string]uint64{}
	c.mu.Unlock()
}

// Reset drops to an unknown generation.
func (c *VersionCache) Reset() { c.RefreshAll(0) }

// Apply returns true iff an incoming invalidation should evict path.
func (c *VersionCache) Apply(g uint64, path string, v uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if g != c.gen {
		return false
	}
	if v > c.m[path] {
		c.m[path] = v
		return true
	}
	return false
}

// FillOK records a read result's version if it is not older than the version already known.
func (c *VersionCache) FillOK(g uint64, path string, v uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if g != c.gen {
		return false
	}
	if v >= c.m[path] {
		c.m[path] = v
		return true
	}
	return false
}
