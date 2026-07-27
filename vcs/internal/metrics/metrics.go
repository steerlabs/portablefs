// Package metrics is a small, dependency-free metrics registry: named counters,
// gauges, and latency histograms, snapshot-able to JSON and Prometheus text. A
// process-wide Default registry lets any package emit metrics without threading a
// handle through every constructor (the standard metrics pattern), while tests can
// use an isolated registry.
package metrics

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Default is the process-wide registry.
var Default = NewRegistry()

// Registry holds named metrics.
type Registry struct {
	mu       sync.Mutex
	counters map[string]*Counter
	gauges   map[string]*Gauge
	hists    map[string]*Histogram
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		counters: map[string]*Counter{},
		gauges:   map[string]*Gauge{},
		hists:    map[string]*Histogram{},
	}
}

// Counter returns the named monotonic counter, creating it on first use.
func (r *Registry) Counter(name string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.counters[name]
	if !ok {
		c = &Counter{}
		r.counters[name] = c
	}
	return c
}

// Gauge returns the named gauge, creating it on first use.
func (r *Registry) Gauge(name string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.gauges[name]
	if !ok {
		g = &Gauge{}
		r.gauges[name] = g
	}
	return g
}

// Histogram returns the named latency histogram, creating it on first use.
func (r *Registry) Histogram(name string) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hists[name]
	if !ok {
		h = newHistogram()
		r.hists[name] = h
	}
	return h
}

// Counter is a monotonic count.
type Counter struct{ v atomic.Int64 }

func (c *Counter) Inc()         { c.v.Add(1) }
func (c *Counter) Add(n int64)  { c.v.Add(n) }
func (c *Counter) Value() int64 { return c.v.Load() }

// Gauge is a value that can go up or down.
type Gauge struct{ v atomic.Int64 }

func (g *Gauge) Set(n int64)  { g.v.Store(n) }
func (g *Gauge) Add(n int64)  { g.v.Add(n) }
func (g *Gauge) Value() int64 { return g.v.Load() }

// latencyBoundsMicros are fixed upper bounds (microseconds) for the histogram
// buckets — exponential-ish, covering sub-µs cache hits to multi-second fetches.
var latencyBoundsMicros = []int64{10, 50, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000}

// Histogram tracks a latency distribution via fixed buckets, plus count and sum
// (for the mean). Percentiles are estimated from bucket counts.
// Histogram is lock-free: Observe is on the hot path (every protocol op + bucket
// fetch), so it uses atomics instead of a mutex — at GB/s op rates a per-op lock is
// a real contention point. The three atomics are updated independently, so a
// concurrent snapshot may see a count one ahead of the bucket sums; that's a
// negligible approximation for latency percentiles.
type Histogram struct {
	count   atomic.Int64
	sumNs   atomic.Int64
	buckets []atomic.Int64 // counts, len == len(latencyBoundsMicros)+1 (last = overflow)
}

func newHistogram() *Histogram {
	return &Histogram{buckets: make([]atomic.Int64, len(latencyBoundsMicros)+1)}
}

// Observe records a duration (lock-free).
func (h *Histogram) Observe(d time.Duration) {
	micros := d.Microseconds()
	idx := sort.Search(len(latencyBoundsMicros), func(i int) bool { return latencyBoundsMicros[i] >= micros })
	h.count.Add(1)
	h.sumNs.Add(d.Nanoseconds())
	h.buckets[idx].Add(1)
}

// Time observes the elapsed time since start (use `defer h.Time(time.Now())`).
func (h *Histogram) Time(start time.Time) { h.Observe(time.Since(start)) }

func (h *Histogram) snapshot() map[string]any {
	count := h.count.Load()
	out := map[string]any{"count": count}
	if count == 0 {
		return out
	}
	out["mean_us"] = (h.sumNs.Load() / count) / 1000
	out["p50_us"] = h.quantile(0.50, count)
	out["p90_us"] = h.quantile(0.90, count)
	out["p99_us"] = h.quantile(0.99, count)
	return out
}

// quantile estimates a quantile as the upper bound of the bucket the quantile
// falls into, given a consistent count snapshot.
func (h *Histogram) quantile(q float64, count int64) int64 {
	target := int64(math.Ceil(float64(count) * q)) // the q-th observation (1-based)
	if target < 1 {
		target = 1
	}
	var cum int64
	for i := range h.buckets {
		cum += h.buckets[i].Load()
		if cum >= target {
			if i >= len(latencyBoundsMicros) {
				return latencyBoundsMicros[len(latencyBoundsMicros)-1] // overflow bucket
			}
			return latencyBoundsMicros[i]
		}
	}
	return 0
}

// Snapshot returns a JSON-able view of all metrics.
func (r *Registry) Snapshot() map[string]any {
	r.mu.Lock()
	counters := make(map[string]int64, len(r.counters))
	for name, c := range r.counters {
		counters[name] = c.Value()
	}
	gauges := make(map[string]int64, len(r.gauges))
	for name, g := range r.gauges {
		gauges[name] = g.Value()
	}
	hists := make(map[string]any, len(r.hists))
	for name, h := range r.hists {
		hists[name] = h.snapshot()
	}
	r.mu.Unlock()
	return map[string]any{"counters": counters, "gauges": gauges, "histograms": hists}
}

// Prometheus renders the registry in Prometheus text exposition format.
func (r *Registry) Prometheus() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	names := make([]string, 0, len(r.counters))
	for name := range r.counters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "%s %d\n", name, r.counters[name].Value())
	}
	gnames := make([]string, 0, len(r.gauges))
	for name := range r.gauges {
		gnames = append(gnames, name)
	}
	sort.Strings(gnames)
	for _, name := range gnames {
		fmt.Fprintf(&b, "%s %d\n", name, r.gauges[name].Value())
	}
	// Histograms as Prometheus summaries: <name>_count, <name>_sum (seconds), and quantiles.
	hnames := make([]string, 0, len(r.hists))
	for name := range r.hists {
		hnames = append(hnames, name)
	}
	sort.Strings(hnames)
	for _, name := range hnames {
		h := r.hists[name]
		count := h.count.Load()
		fmt.Fprintf(&b, "%s_count %d\n", name, count)
		fmt.Fprintf(&b, "%s_sum %g\n", name, float64(h.sumNs.Load())/1e9) // ns -> seconds
		if count > 0 {
			fmt.Fprintf(&b, "%s{quantile=\"0.5\"} %g\n", name, float64(h.quantile(0.50, count))/1e6)
			fmt.Fprintf(&b, "%s{quantile=\"0.9\"} %g\n", name, float64(h.quantile(0.90, count))/1e6)
			fmt.Fprintf(&b, "%s{quantile=\"0.99\"} %g\n", name, float64(h.quantile(0.99, count))/1e6)
		}
	}
	return b.String()
}
