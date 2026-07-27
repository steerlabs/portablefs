package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestRegistryCountersGaugesHistogram(t *testing.T) {
	r := NewRegistry()
	r.Counter("ops").Inc()
	r.Counter("ops").Add(4)
	if got := r.Counter("ops").Value(); got != 5 {
		t.Fatalf("counter = %d, want 5", got)
	}

	r.Gauge("conns").Set(3)
	r.Gauge("conns").Add(-1)
	if got := r.Gauge("conns").Value(); got != 2 {
		t.Fatalf("gauge = %d, want 2", got)
	}

	h := r.Histogram("lat")
	for i := 0; i < 100; i++ {
		h.Observe(time.Duration(i) * time.Microsecond)
	}

	snap := r.Snapshot()
	counters := snap["counters"].(map[string]int64)
	if counters["ops"] != 5 {
		t.Fatalf("snapshot counter ops = %d, want 5", counters["ops"])
	}
	hists := snap["histograms"].(map[string]any)
	lat := hists["lat"].(map[string]any)
	if lat["count"].(int64) != 100 {
		t.Fatalf("histogram count = %v, want 100", lat["count"])
	}
	if _, ok := lat["p99_us"]; !ok {
		t.Fatal("histogram snapshot missing p99_us")
	}

	prom := r.Prometheus()
	if !strings.Contains(prom, "ops 5") || !strings.Contains(prom, "conns 2") {
		t.Fatalf("prometheus output missing metrics:\n%s", prom)
	}
}

// TestHistogramPercentileSingleObservation: a single 200µs sample reports its own
// bucket (500µs) for every percentile — not the lowest bucket (the count*q floor bug).
func TestHistogramPercentileSingleObservation(t *testing.T) {
	h := NewRegistry().Histogram("lat")
	h.Observe(200 * time.Microsecond)
	snap := h.snapshot()
	if got := snap["p50_us"].(int64); got != 500 {
		t.Fatalf("p50 = %d, want 500 (the sample's bucket)", got)
	}
	if got := snap["p99_us"].(int64); got != 500 {
		t.Fatalf("p99 = %d, want 500", got)
	}
}

func TestHistogramEmpty(t *testing.T) {
	r := NewRegistry()
	lat := r.Histogram("lat").snapshot()
	if lat["count"].(int64) != 0 {
		t.Fatalf("empty histogram count = %v, want 0", lat["count"])
	}
	if _, ok := lat["mean_us"]; ok {
		t.Fatal("empty histogram should not report mean")
	}
}
