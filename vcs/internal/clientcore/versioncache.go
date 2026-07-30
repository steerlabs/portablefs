package clientcore

import (
	"strings"
	"sync"
	"sync/atomic"
)

// VersionCache tracks, per path, the highest coherence version installed or applied within the
// current authority generation. It is the monotonic gate behind both metadata and content caching.
type VersionCache struct {
	mu sync.RWMutex

	gen      uint64
	genEpoch uint64
	m        map[string]versionState
	genClock atomic.Uint64

	// Each delegation ownership transition installs a prefix fence. A
	// response may populate caches only when its operation began after the
	// newest fence covering that path. Retained version floors reject
	// delayed invalidations from before the transition.
	fenceSeq   uint64
	fences     map[string]uint64
	fenceClock atomic.Uint64
}

type versionState struct {
	version        uint64
	validatedFence uint64
}

// CacheToken is an operation-start snapshot used to reject late authority
// replies that cross either a generation change or a delegation fence.
// Fields stay private so callers cannot manufacture a fresher token.
type CacheToken struct {
	genEpoch uint64
	fenceSeq uint64
}

// maxPrefixFences bounds long-lived ownership history. Crossing the bound
// compacts to one conservative root fence, making existing cache entries
// globally cold once while keeping future read cost O(path depth).
const maxPrefixFences = 8192

// NewVersionCache returns an empty cache anchored to no generation.
func NewVersionCache() *VersionCache {
	return &VersionCache{
		m:      map[string]versionState{},
		fences: map[string]uint64{},
	}
}

// CaptureToken snapshots the cache epoch at the start of one read operation.
func (c *VersionCache) CaptureToken() CacheToken {
	return CacheToken{
		genEpoch: c.genClock.Load(),
		fenceSeq: c.fenceClock.Load(),
	}
}

// TokenForGeneration returns a coherent current token only when g is still
// the active authority generation. A valid subscription uses this to join a
// generation that a concurrent read adopted first; an old-generation stream
// cannot use it to re-anchor or roll the cache back.
func (c *VersionCache) TokenForGeneration(g uint64) (CacheToken, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if g == 0 || g != c.gen {
		return CacheToken{}, false
	}
	return CacheToken{genEpoch: c.genEpoch, fenceSeq: c.fenceSeq}, true
}

// SeenGen reports whether g is the currently anchored authority generation.
func (c *VersionCache) SeenGen(g uint64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gen == g
}

// CurrentGen returns the generation the cache is anchored to. Zero means unknown.
func (c *VersionCache) CurrentGen() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gen
}

// GenAndVersion returns the current generation and the highest version recorded for path.
func (c *VersionCache) GenAndVersion(path string) (gen, version uint64) {
	gen, version, _ = c.CacheState(path)
	return gen, version
}

// CacheState returns the current generation/version and whether path has been
// validated after the newest covering ownership fence. A physically retained
// cache entry must never be served when valid is false.
func (c *VersionCache) CacheState(path string) (gen, version uint64, valid bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state := c.m[path]
	if state.validatedFence < c.currentFenceLocked(path) {
		return c.gen, 0, false
	}
	return c.gen, state.version, true
}

// FenceClock is the current mount-wide ownership transition sequence. Complete
// directory listings embed child state and therefore use this conservative
// O(1) stamp rather than scanning every child fence at lookup time.
func (c *VersionCache) FenceClock() uint64 {
	return c.fenceClock.Load()
}

// RefreshAll adopts generation g and drops every remembered path version.
func (c *VersionCache) RefreshAll(g uint64) {
	c.mu.Lock()
	c.gen = g
	c.genEpoch++
	c.m = map[string]versionState{}
	c.genClock.Store(c.genEpoch)
	c.mu.Unlock()
}

// Reset drops to an unknown generation.
func (c *VersionCache) Reset() { c.RefreshAll(0) }

// FencePrefix makes cached versions under path unreachable until a response
// from an operation begun after this exact ownership boundary validates them.
// Version floors remain retained so a delayed pre-boundary invalidation
// cannot republish an older version after the fence.
func (c *VersionCache) FencePrefix(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fenceSeq++
	// A newer ancestor fence subsumes every older descendant boundary.
	// Compact them at the rare transition point so the hot read path stays
	// proportional to path depth, never historical grant count.
	if path == "" {
		c.fences = map[string]uint64{}
	} else {
		prefix := path + "/"
		for fencedPath := range c.fences {
			if strings.HasPrefix(fencedPath, prefix) {
				delete(c.fences, fencedPath)
			}
		}
	}
	c.fences[path] = c.fenceSeq
	if len(c.fences) > maxPrefixFences {
		c.fences = map[string]uint64{"": c.fenceSeq}
	}
	c.fenceClock.Store(c.fenceSeq)
}

func (c *VersionCache) currentFenceLocked(path string) uint64 {
	newest := c.fences[""]
	for path != "" {
		if seq := c.fences[path]; seq > newest {
			newest = seq
		}
		i := strings.LastIndexByte(path, '/')
		if i < 0 {
			break
		}
		path = path[:i]
	}
	return newest
}

// AcceptGeneration validates the operation epoch against responseGen. The
// first still-current response that observes a new authority generation
// atomically re-anchors the cache; older in-flight responses then carry a
// stale token and cannot flip the nonce back.
func (c *VersionCache) AcceptGeneration(token CacheToken, responseGen uint64) (CacheToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if responseGen == 0 || token.genEpoch != c.genEpoch {
		return token, false
	}
	if responseGen != c.gen {
		c.gen = responseGen
		c.genEpoch++
		c.m = map[string]versionState{}
		c.genClock.Store(c.genEpoch)
		token.genEpoch = c.genEpoch
	}
	return token, true
}

// FlushGeneration drops every version in g only when the subscription token
// still belongs to the current generation epoch. It returns the advanced
// token so the same ordered stream can continue; a stale stream cannot reset
// a generation established by a newer read or mutation observation.
func (c *VersionCache) FlushGeneration(token CacheToken, g uint64) (CacheToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if g == 0 || g != c.gen || token.genEpoch != c.genEpoch {
		return token, false
	}
	c.genEpoch++
	c.m = map[string]versionState{}
	c.genClock.Store(c.genEpoch)
	token.genEpoch = c.genEpoch
	return token, true
}

// FillOKToken records a read response only if its operation token remains
// current for both the authority generation and every prefix fence covering
// path.
func (c *VersionCache) FillOKToken(token CacheToken, g uint64, path string, v uint64) bool {
	return c.PublishOKToken(token, g, path, v, nil)
}

// PublishOKToken validates and records a read response, then publishes its
// in-memory cache entry while the same fence lock remains held. This makes
// validation + publication atomic with FencePrefix: a handoff either evicts
// an already-published entry or makes the token fail before publish runs.
func (c *VersionCache) PublishOKToken(token CacheToken, g uint64, path string, v uint64, publish func()) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if g == 0 || g != c.gen || token.genEpoch != c.genEpoch {
		return false
	}
	fence := c.currentFenceLocked(path)
	if token.fenceSeq < fence {
		return false
	}
	state := c.m[path]
	if v < state.version {
		return false
	}
	state.version = v
	state.validatedFence = fence
	c.m[path] = state
	if publish != nil {
		publish()
	}
	return true
}

// PublishDirectoryOKToken atomically validates and publishes one complete
// directory response. Readdir-plus embeds attributes for every child, so any
// ownership fence installed after the operation began can make some part of
// the response stale. Comparing the mount-wide fence clock is deliberately
// conservative and O(1): ownership transitions are rare, while large
// directory publication remains independent of entry count and path depth.
func (c *VersionCache) PublishDirectoryOKToken(token CacheToken, g, v uint64, parent string, publish func()) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if g == 0 || g != c.gen || token.genEpoch != c.genEpoch ||
		token.fenceSeq != c.fenceSeq {
		return false
	}
	fence := c.currentFenceLocked(parent)
	state := c.m[parent]
	if v < state.version {
		return false
	}
	state.version = v
	state.validatedFence = fence
	c.m[parent] = state
	if publish != nil {
		publish()
	}
	return true
}

// TokenCurrent reports whether token may still publish any observation for
// path in generation g. It is used for non-cacheable results such as ENOENT
// that still must not drive post-fence kernel decisions.
func (c *VersionCache) TokenCurrent(token CacheToken, g uint64, path string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return g != 0 &&
		g == c.gen &&
		token.genEpoch == c.genEpoch &&
		token.fenceSeq >= c.currentFenceLocked(path)
}

// Apply returns true iff an incoming invalidation is strictly newer than the
// retained path floor. It advances the floor and requests eviction, but does
// not validate a prefix fence: stream delivery can lag grant acquisition, so
// even a newer event may describe pre-grant state. Only a current operation
// token proves that a cache fill began after the ownership boundary.
func (c *VersionCache) Apply(g uint64, path string, v uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if g != c.gen {
		return false
	}
	state := c.m[path]
	if v > state.version {
		state.version = v
		c.m[path] = state
		return true
	}
	return false
}

// FillOK advances the retained floor for a non-read result. It deliberately
// does not validate a prefix fence: mutation replies can also be delayed
// across a concurrent ownership transition, and their callers evict rather
// than populate caches. A tokened post-fence read or a strictly newer
// invalidation makes the new version cache-reachable.
func (c *VersionCache) FillOK(g uint64, path string, v uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if g != c.gen {
		return false
	}
	state := c.m[path]
	if v >= state.version {
		state.version = v
		c.m[path] = state
		return true
	}
	return false
}
