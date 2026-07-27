package metrics

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The bucket bounds are an implementation detail mirrored here so the boundary
// tests can reference exact upper bounds without re-deriving them.
var wantBounds = []int64{10, 50, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000}

// TestBoundsUnchanged guards the bound table the rest of this file assumes. If
// the production bounds drift, this fails loudly instead of the boundary tests
// failing in confusing ways.
func TestBoundsUnchanged(t *testing.T) {
	if len(latencyBoundsMicros) != len(wantBounds) {
		t.Fatalf("bound count = %d, want %d", len(latencyBoundsMicros), len(wantBounds))
	}
	for i := range wantBounds {
		if latencyBoundsMicros[i] != wantBounds[i] {
			t.Fatalf("bound[%d] = %d, want %d", i, latencyBoundsMicros[i], wantBounds[i])
		}
	}
}

// ----- Counter -----

func TestCounterZeroAndNegativeAndLarge(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("c")
	if got := c.Value(); got != 0 {
		t.Fatalf("fresh counter = %d, want 0", got)
	}
	// Counter is documented "monotonic" but Add accepts any int64; behavior with a
	// negative addend is to subtract (atomic.Add). Lock that in.
	c.Add(-3)
	if got := c.Value(); got != -3 {
		t.Fatalf("counter after Add(-3) = %d, want -3", got)
	}
	c.Add(0)
	if got := c.Value(); got != -3 {
		t.Fatalf("counter after Add(0) = %d, want -3", got)
	}
	c.Inc()
	if got := c.Value(); got != -2 {
		t.Fatalf("counter after Inc = %d, want -2", got)
	}
	// Large value near int64 max.
	big := r.Counter("big")
	big.Add(math.MaxInt64 - 1)
	big.Inc()
	if got := big.Value(); got != math.MaxInt64 {
		t.Fatalf("big counter = %d, want MaxInt64", got)
	}
}

func TestCounterSameNameSameInstance(t *testing.T) {
	r := NewRegistry()
	a := r.Counter("dup")
	b := r.Counter("dup")
	if a != b {
		t.Fatal("Counter(name) must return the same instance on repeat (idempotent registration)")
	}
	a.Inc()
	if b.Value() != 1 {
		t.Fatalf("aliased counter = %d, want 1", b.Value())
	}
}

// ----- Gauge -----

func TestGaugeUpDownZeroLarge(t *testing.T) {
	r := NewRegistry()
	g := r.Gauge("g")
	if g.Value() != 0 {
		t.Fatalf("fresh gauge = %d, want 0", g.Value())
	}
	g.Set(10)
	g.Add(-15)
	if got := g.Value(); got != -5 {
		t.Fatalf("gauge = %d, want -5", got)
	}
	g.Set(math.MinInt64)
	if got := g.Value(); got != math.MinInt64 {
		t.Fatalf("gauge = %d, want MinInt64", got)
	}
	g.Set(math.MaxInt64)
	if got := g.Value(); got != math.MaxInt64 {
		t.Fatalf("gauge = %d, want MaxInt64", got)
	}
	// Set overrides accumulated Add.
	g.Add(100)
	g.Set(7)
	if got := g.Value(); got != 7 {
		t.Fatalf("gauge after Set override = %d, want 7", got)
	}
}

// ----- Histogram bucket boundaries -----

// observeProbe records a single duration into a private histogram and returns the
// p50 (= the bucket's reported upper bound, since one sample lands the whole mass
// in one bucket and every quantile resolves to that bucket).
func observeBucketUpper(t *testing.T, micros int64) int64 {
	t.Helper()
	h := NewRegistry().Histogram("probe")
	h.Observe(time.Duration(micros) * time.Microsecond)
	snap := h.snapshot()
	return snap["p50_us"].(int64)
}

func TestHistogramBucketBoundaries(t *testing.T) {
	// For a single sample, quantile = upper bound of the bucket it lands in.
	// sort.Search finds first bound >= micros. Exactly-at a bound lands in that
	// bound's bucket; +1 over the top bound lands in overflow (reported as the top
	// bound). Sweep exactly-at and ±1 around every interior bound.
	cases := []struct {
		micros int64
		want   int64
		note   string
	}{
		{0, 10, "zero -> first bucket (bound 10)"},
		{1, 10, "below first bound"},
		{9, 10, "just below first bound"},
		{10, 10, "exactly first bound"},
		{11, 50, "just above first bound -> next bucket"},
		{49, 50, "just below second bound"},
		{50, 50, "exactly second bound"},
		{51, 100, "just above second bound"},
		{100, 100, "exactly third bound"},
		{101, 500, "just above third bound"},
		{500, 500, "exactly fourth bound"},
		{999, 1_000, "just below 1000 bound"},
		{1_000, 1_000, "exactly 1000 bound"},
		{1_001, 5_000, "just above 1000 bound"},
		{999_999, 1_000_000, "just below top bound"},
		{1_000_000, 1_000_000, "exactly top bound"},
		{1_000_001, 1_000_000, "above top bound -> overflow reported as top bound"},
		{50_000_000, 1_000_000, "far above top -> overflow reported as top bound"},
	}
	for _, c := range cases {
		if got := observeBucketUpper(t, c.micros); got != c.want {
			t.Fatalf("%s: observe %dµs -> p50 %d, want %d", c.note, c.micros, got, c.want)
		}
	}
}

// TestHistogramSubMicrosecondTruncation: Observe uses d.Microseconds() which
// truncates toward zero. A 999ns observation truncates to 0µs and lands in the
// first bucket; its nanosecond sum is still recorded exactly.
func TestHistogramSubMicrosecondTruncation(t *testing.T) {
	h := NewRegistry().Histogram("sub")
	h.Observe(999 * time.Nanosecond)
	snap := h.snapshot()
	if got := snap["count"].(int64); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
	if got := snap["p50_us"].(int64); got != 10 {
		t.Fatalf("sub-µs p50 = %d, want 10 (first bucket)", got)
	}
	// mean_us = (sumNs/count)/1000 = 999/1000 = 0 (integer division).
	if got := snap["mean_us"].(int64); got != 0 {
		t.Fatalf("mean_us = %d, want 0 (999ns truncates)", got)
	}
}

func TestHistogramMeanInteger(t *testing.T) {
	h := NewRegistry().Histogram("mean")
	// Three samples: 100µs, 200µs, 300µs -> sumNs = 600_000_000, count 3,
	// mean_us = (600_000_000/3)/1000 = 200.
	for _, us := range []int64{100, 200, 300} {
		h.Observe(time.Duration(us) * time.Microsecond)
	}
	snap := h.snapshot()
	if got := snap["mean_us"].(int64); got != 200 {
		t.Fatalf("mean_us = %d, want 200", got)
	}
	if got := snap["count"].(int64); got != 3 {
		t.Fatalf("count = %d, want 3", got)
	}
}

// TestHistogramQuantileMonotone: across a spread of samples, p50 <= p90 <= p99
// (quantiles are bucket upper bounds and target grows with q).
func TestHistogramQuantileMonotone(t *testing.T) {
	h := NewRegistry().Histogram("spread")
	// 100 samples spread across many buckets.
	for i := 0; i < 100; i++ {
		h.Observe(time.Duration((i+1)*1000) * time.Microsecond) // 1ms .. 100ms
	}
	snap := h.snapshot()
	p50 := snap["p50_us"].(int64)
	p90 := snap["p90_us"].(int64)
	p99 := snap["p99_us"].(int64)
	if !(p50 <= p90 && p90 <= p99) {
		t.Fatalf("quantiles not monotone: p50=%d p90=%d p99=%d", p50, p90, p99)
	}
}

// TestHistogramAllSameBucket: 1000 identical observations all in one bucket;
// every quantile is that bucket's bound, count is exact.
func TestHistogramAllSameBucket(t *testing.T) {
	h := NewRegistry().Histogram("same")
	for i := 0; i < 1000; i++ {
		h.Observe(300 * time.Microsecond) // bucket bound 500
	}
	snap := h.snapshot()
	if got := snap["count"].(int64); got != 1000 {
		t.Fatalf("count = %d, want 1000", got)
	}
	for _, k := range []string{"p50_us", "p90_us", "p99_us"} {
		if got := snap[k].(int64); got != 500 {
			t.Fatalf("%s = %d, want 500", k, got)
		}
	}
}

// TestHistogramNegativeObservation documents what happens with a negative
// duration: it is counted, lands in bucket 0 (since the first bound >= a negative
// micros), and DECREASES the nanosecond sum. This is surprising but is the actual
// behavior of Observe (no guard against negative durations).
func TestHistogramNegativeObservation(t *testing.T) {
	h := NewRegistry().Histogram("neg")
	h.Observe(-200 * time.Microsecond)
	snap := h.snapshot()
	if got := snap["count"].(int64); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
	if got := snap["p50_us"].(int64); got != 10 {
		t.Fatalf("negative observation p50 = %d, want 10 (bucket 0)", got)
	}
	// mean_us = (sumNs/count)/1000 = (-200000/1)/1000 = -200.
	if got := snap["mean_us"].(int64); got != -200 {
		t.Fatalf("negative mean_us = %d, want -200", got)
	}
}

// TestHistogramTime exercises the Time(start) convenience: it observes a
// non-negative elapsed and increments count.
func TestHistogramTime(t *testing.T) {
	h := NewRegistry().Histogram("timed")
	start := time.Now()
	h.Time(start)
	if got := h.snapshot()["count"].(int64); got != 1 {
		t.Fatalf("Time should record one observation, count = %d", got)
	}
}

// ----- Snapshot -----

func TestSnapshotEmptyRegistry(t *testing.T) {
	snap := NewRegistry().Snapshot()
	if c := snap["counters"].(map[string]int64); len(c) != 0 {
		t.Fatalf("empty counters, got %v", c)
	}
	if g := snap["gauges"].(map[string]int64); len(g) != 0 {
		t.Fatalf("empty gauges, got %v", g)
	}
	if hh := snap["histograms"].(map[string]any); len(hh) != 0 {
		t.Fatalf("empty histograms, got %v", hh)
	}
}

func TestSnapshotIsCopyNotLive(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("k")
	c.Add(5)
	snap := r.Snapshot()
	counters := snap["counters"].(map[string]int64)
	if counters["k"] != 5 {
		t.Fatalf("snapshot k = %d, want 5", counters["k"])
	}
	// Mutate after snapshot; the snapshot must not change.
	c.Add(100)
	if counters["k"] != 5 {
		t.Fatalf("snapshot mutated after the fact = %d, want frozen 5", counters["k"])
	}
}

func TestSnapshotHistogramEmptyOmitsDerived(t *testing.T) {
	r := NewRegistry()
	r.Histogram("h0") // created but never observed
	snap := r.Snapshot()
	h := snap["histograms"].(map[string]any)["h0"].(map[string]any)
	if h["count"].(int64) != 0 {
		t.Fatalf("count = %v, want 0", h["count"])
	}
	for _, k := range []string{"mean_us", "p50_us", "p90_us", "p99_us"} {
		if _, ok := h[k]; ok {
			t.Fatalf("empty histogram must omit %s", k)
		}
	}
}

// ----- Prometheus text rendering -----

// promLines splits the exposition text into a set of non-empty lines for
// order-independent membership checks, plus returns the raw text for ordering
// assertions.
func promLines(s string) map[string]bool {
	out := map[string]bool{}
	for _, ln := range strings.Split(s, "\n") {
		if ln != "" {
			out[ln] = true
		}
	}
	return out
}

func TestPrometheusCountersGaugesNegativeZeroLarge(t *testing.T) {
	r := NewRegistry()
	r.Counter("zero_c") // 0
	r.Counter("neg_c").Add(-42)
	r.Counter("big_c").Add(math.MaxInt64)
	r.Gauge("zero_g") // 0
	r.Gauge("neg_g").Set(-7)
	r.Gauge("big_g").Set(math.MinInt64)

	lines := promLines(r.Prometheus())
	want := []string{
		"zero_c 0",
		"neg_c -42",
		fmt.Sprintf("big_c %d", int64(math.MaxInt64)),
		"zero_g 0",
		"neg_g -7",
		fmt.Sprintf("big_g %d", int64(math.MinInt64)),
	}
	for _, w := range want {
		if !lines[w] {
			t.Fatalf("prometheus output missing line %q\nfull set: %v", w, lines)
		}
	}
}

func TestPrometheusSortedAndCountersBeforeGauges(t *testing.T) {
	r := NewRegistry()
	// Insert out of alphabetical order.
	r.Counter("c_b").Inc()
	r.Counter("c_a").Inc()
	r.Gauge("g_b").Set(1)
	r.Gauge("g_a").Set(1)
	out := r.Prometheus()

	idxCA := strings.Index(out, "c_a 1")
	idxCB := strings.Index(out, "c_b 1")
	idxGA := strings.Index(out, "g_a 1")
	idxGB := strings.Index(out, "g_b 1")
	if !(idxCA >= 0 && idxCB >= 0 && idxGA >= 0 && idxGB >= 0) {
		t.Fatalf("missing expected lines:\n%s", out)
	}
	if !(idxCA < idxCB) {
		t.Fatalf("counters not sorted: c_a at %d, c_b at %d\n%s", idxCA, idxCB, out)
	}
	if !(idxGA < idxGB) {
		t.Fatalf("gauges not sorted: g_a at %d, g_b at %d\n%s", idxGA, idxGB, out)
	}
	// All counters render before all gauges.
	if !(idxCB < idxGA) {
		t.Fatalf("counters should render before gauges:\n%s", out)
	}
}

// TestPrometheusHistogramSummary checks the histogram-as-summary rendering:
// <name>_count, <name>_sum (in seconds), and quantile lines for 0.5/0.9/0.99.
// An empty histogram emits _count and _sum but NO quantile lines.
func TestPrometheusHistogramSummary(t *testing.T) {
	r := NewRegistry()
	empty := r.Histogram("h_empty")
	_ = empty
	h := r.Histogram("h_full")
	// 1 sample at 500µs -> sum = 0.0005s, quantile bound 500µs -> 0.0005s.
	h.Observe(500 * time.Microsecond)

	out := r.Prometheus()
	lines := promLines(out)

	// Empty histogram: count and sum present, no quantiles.
	if !lines["h_empty_count 0"] {
		t.Fatalf("missing h_empty_count 0:\n%s", out)
	}
	if !lines["h_empty_sum 0"] {
		t.Fatalf("missing h_empty_sum 0:\n%s", out)
	}
	for _, q := range []string{"0.5", "0.9", "0.99"} {
		bad := fmt.Sprintf("h_empty{quantile=%q}", q)
		if strings.Contains(out, bad) {
			t.Fatalf("empty histogram must not emit quantile %s:\n%s", q, out)
		}
	}

	// Full histogram: count 1, sum 0.0005, three quantile lines all 0.0005.
	if !lines["h_full_count 1"] {
		t.Fatalf("missing h_full_count 1:\n%s", out)
	}
	wantSum := strconv.FormatFloat(0.0005, 'g', -1, 64) // %g of float64(500000)/1e9
	if !lines["h_full_sum "+wantSum] {
		t.Fatalf("missing h_full_sum %s:\n%s", wantSum, out)
	}
	wantQ := strconv.FormatFloat(float64(500)/1e6, 'g', -1, 64) // 0.0005
	for _, q := range []string{"0.5", "0.9", "0.99"} {
		line := fmt.Sprintf("h_full{quantile=%q} %s", q, wantQ)
		if !lines[line] {
			t.Fatalf("missing quantile line %q:\n%s", line, out)
		}
	}
}

// TestPrometheusSumSeconds verifies the ns->seconds conversion in _sum with a
// value that has a clean decimal: 2_000_000ns = 0.002s.
func TestPrometheusSumSeconds(t *testing.T) {
	r := NewRegistry()
	h := r.Histogram("h")
	h.Observe(2 * time.Millisecond) // 2,000,000 ns
	out := r.Prometheus()
	want := "h_sum " + strconv.FormatFloat(0.002, 'g', -1, 64)
	if !promLines(out)[want] {
		t.Fatalf("missing %q in:\n%s", want, out)
	}
}

// ----- Concurrency (-race) -----

func TestConcurrentCounterInc(t *testing.T) {
	r := NewRegistry()
	const goroutines, perG = 50, 2000
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := r.Counter("hot") // resolve the same counter concurrently (also races registry create)
			for j := 0; j < perG; j++ {
				c.Inc()
			}
		}()
	}
	wg.Wait()
	if got := r.Counter("hot").Value(); got != int64(goroutines*perG) {
		t.Fatalf("concurrent counter = %d, want %d", got, goroutines*perG)
	}
}

func TestConcurrentGaugeAdd(t *testing.T) {
	r := NewRegistry()
	const goroutines, perG = 40, 1000
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := r.Gauge("level")
			for j := 0; j < perG; j++ {
				g.Add(1)
				g.Add(-1)
			}
		}()
	}
	wg.Wait()
	if got := r.Gauge("level").Value(); got != 0 {
		t.Fatalf("balanced gauge = %d, want 0", got)
	}
}

func TestConcurrentHistogramObserve(t *testing.T) {
	r := NewRegistry()
	h := r.Histogram("lat")
	const goroutines, perG = 32, 5000
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				h.Observe(time.Duration((id+j)%2000+1) * time.Microsecond)
			}
		}(i)
	}
	wg.Wait()
	if got := h.snapshot()["count"].(int64); got != int64(goroutines*perG) {
		t.Fatalf("concurrent histogram count = %d, want %d", got, goroutines*perG)
	}
}

// TestConcurrentRegistryDistinctNames races creation of many distinct metric
// names through the registry mutex; every name must be createable and resolvable.
func TestConcurrentRegistryDistinctNames(t *testing.T) {
	r := NewRegistry()
	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "m" + strconv.Itoa(i)
			r.Counter(name).Inc()
			r.Gauge(name).Set(int64(i))
			r.Histogram(name).Observe(time.Microsecond)
		}(i)
	}
	wg.Wait()
	snap := r.Snapshot()
	if got := len(snap["counters"].(map[string]int64)); got != n {
		t.Fatalf("counters = %d, want %d", got, n)
	}
	if got := len(snap["gauges"].(map[string]int64)); got != n {
		t.Fatalf("gauges = %d, want %d", got, n)
	}
	if got := len(snap["histograms"].(map[string]any)); got != n {
		t.Fatalf("histograms = %d, want %d", got, n)
	}
}

// TestConcurrentSnapshotDuringWrites runs Snapshot and Prometheus concurrently
// with active writers; the race detector validates locking. We only assert no
// panic / no data race and that counts are within the legal range.
func TestConcurrentSnapshotDuringWrites(t *testing.T) {
	r := NewRegistry()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		c := r.Counter("c")
		h := r.Histogram("h")
		g := r.Gauge("g")
		for {
			select {
			case <-stop:
				return
			default:
				c.Inc()
				g.Add(1)
				h.Observe(time.Microsecond)
			}
		}
	}()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 1000; k++ {
				_ = r.Snapshot()
				_ = r.Prometheus()
			}
		}()
	}
	// Readers do a bounded amount of work; spin some snapshots in the main
	// goroutine too, then stop the writer and wait for everyone.
	for k := 0; k < 2000; k++ {
		_ = r.Snapshot()
	}
	close(stop)
	wg.Wait()

	final := r.Counter("c").Value()
	if final <= 0 {
		t.Fatalf("counter should have advanced, got %d", final)
	}
}
