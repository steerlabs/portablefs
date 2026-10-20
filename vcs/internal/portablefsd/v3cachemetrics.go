package portablefsd

import "github.com/steerlabs/portablefs/vcs/internal/pfslocal"

// Fixed result sets keep instrumentation independent of names and identities.
// Counters are per data plane and guarded by d.mu; status snapshots allocate
// only when requested through the daemon's existing control status surface.
type v3CacheResult uint8

const (
	v3CacheHit v3CacheResult = iota
	v3CacheCold
	v3CacheHeld
	v3CacheHorizon
	v3CacheAuthorization
	v3CacheUnknownName
	v3CacheResource
	v3CacheTerminal
	v3CacheClock
	v3CacheBypass
	v3CacheSearchPermission
	v3CacheResultCount
)

var v3CacheResultNames = [...]string{"hit", "cold", "held", "horizon", "authorization", "unknown_name", "resource", "terminal", "clock", "bypass", "search_permission"}

type v3CacheCounters struct {
	// Hits count physically written replies. Misses count the initial cache
	// decision or the final gate refusal; an authority retry adds neither a
	// second cache decision nor a second lookup polarity.
	reads  [2][v3CacheResultCount]uint64 // getattr, lookup
	lookup [3]uint64                     // positive, negative, error
}

type v3CacheMetrics struct {
	PendingResources v3PendingMetrics  `json:"pending_resources"`
	GetAttr          map[string]uint64 `json:"getattr"`
	Lookup           map[string]uint64 `json:"lookup"`
	LookupPolarity   map[string]uint64 `json:"lookupPolarity"`
}

func (d *v3DataPlane) recordCacheResult(metric int, result v3CacheResult) {
	d.mu.Lock()
	d.cacheCounters.reads[metric][result]++
	d.mu.Unlock()
}

func (d *v3DataPlane) recordLookupPolarity(body any, errno int32) {
	if _, lookup := body.(*pfslocal.LookupRequest); !lookup {
		return
	}
	polarity := 2
	if errno == 0 {
		polarity = 0
	} else if errno == darwinENOENT {
		polarity = 1
	}
	d.mu.Lock()
	d.cacheCounters.lookup[polarity]++
	d.mu.Unlock()
}

func (d *v3DataPlane) cacheMetrics() *v3CacheMetrics {
	d.mu.Lock()
	counts := d.cacheCounters
	d.mu.Unlock()
	result := &v3CacheMetrics{PendingResources: d.pending.metrics(), GetAttr: make(map[string]uint64), Lookup: make(map[string]uint64), LookupPolarity: make(map[string]uint64)}
	for i, name := range v3CacheResultNames {
		result.GetAttr[name], result.Lookup[name] = counts.reads[0][i], counts.reads[1][i]
	}
	for i, name := range [...]string{"positive", "negative", "error"} {
		result.LookupPolarity[name] = counts.lookup[i]
	}
	return result
}
