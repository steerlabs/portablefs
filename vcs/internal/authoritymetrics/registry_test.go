package authoritymetrics

import (
	"bytes"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestRegistryPrometheusGolden(t *testing.T) {
	registry := NewRegistry()
	counter, err := registry.RegisterCounter("portablefs_test_events_total", "Events with a \\ and\na line break.",
		Label{Name: "volume", Value: "vol\"one\\two\nthree"})
	if err != nil {
		t.Fatal(err)
	}
	gauge, err := registry.RegisterGauge("portablefs_test_depth", "Current queue depth.")
	if err != nil {
		t.Fatal(err)
	}
	histogram, err := registry.RegisterHistogram("portablefs_test_duration_seconds", "Test duration.", []float64{0.1, 1},
		Label{Name: "kind", Value: "rpc"})
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(3)
	gauge.Set(-2)
	for _, observation := range []float64{0.05, 0.5, 2} {
		histogram.Observe(observation)
	}

	var rendered bytes.Buffer
	if err := registry.WritePrometheus(&rendered); err != nil {
		t.Fatal(err)
	}
	want := `# HELP portablefs_test_events_total Events with a \\ and\na line break.
# TYPE portablefs_test_events_total counter
portablefs_test_events_total{volume="vol\"one\\two\nthree"} 3
# HELP portablefs_test_depth Current queue depth.
# TYPE portablefs_test_depth gauge
portablefs_test_depth -2
# HELP portablefs_test_duration_seconds Test duration.
# TYPE portablefs_test_duration_seconds histogram
portablefs_test_duration_seconds_bucket{kind="rpc",le="0.1"} 1
portablefs_test_duration_seconds_bucket{kind="rpc",le="1"} 2
portablefs_test_duration_seconds_bucket{kind="rpc",le="+Inf"} 3
portablefs_test_duration_seconds_sum{kind="rpc"} 2.55
portablefs_test_duration_seconds_count{kind="rpc"} 3
`
	if rendered.String() != want {
		t.Fatalf("rendered metrics:\n%s\nwant:\n%s", rendered.String(), want)
	}
}

func TestHistogramExposition(t *testing.T) {
	for _, tc := range []struct {
		name         string
		bounds       []float64
		observations []float64
		buckets      []uint64
		sum          float64
	}{
		{"empty", []float64{1, 2, 5}, nil, []uint64{0, 0, 0, 0}, 0},
		{"inclusive bounds", []float64{1, 2, 5}, []float64{-1, 1, 1.5, 2, 5, 6}, []uint64{2, 4, 5, 6}, 14.5},
		{"negative bounds", []float64{-2, -1, 0}, []float64{-3, -2, -1.5, -1, -0.5, 0, 1}, []uint64{2, 4, 6, 7}, -7},
		{"NaN ignored", []float64{1}, []float64{math.NaN(), 1, math.NaN()}, []uint64{1, 1}, 1},
		{"positive infinity", []float64{1}, []float64{math.Inf(1)}, []uint64{0, 1}, math.Inf(1)},
		{"negative infinity", []float64{1}, []float64{math.Inf(-1)}, []uint64{1, 1}, math.Inf(-1)},
		{"opposite infinities", []float64{1}, []float64{math.Inf(-1), math.Inf(1)}, []uint64{1, 2}, math.NaN()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry()
			histogram, err := registry.RegisterHistogram("portablefs_test_values", "Values.", tc.bounds)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range tc.observations {
				histogram.Observe(value)
			}
			got := scrapeHistogram(t, registry)
			if !slices.Equal(got.buckets, tc.buckets) || got.count != tc.buckets[len(tc.buckets)-1] ||
				got.sum != tc.sum && !(math.IsNaN(got.sum) && math.IsNaN(tc.sum)) {
				t.Fatalf("snapshot = %+v, want buckets=%v count=%d sum=%v", got, tc.buckets, tc.buckets[len(tc.buckets)-1], tc.sum)
			}
		})
	}
}

type histogramExposition struct {
	buckets []uint64
	count   uint64
	sum     float64
}

func scrapeHistogram(t *testing.T, registry *Registry) histogramExposition {
	t.Helper()
	var output bytes.Buffer
	if err := registry.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	return parseHistogram(t, output.String())
}

func parseHistogram(t *testing.T, output string) histogramExposition {
	t.Helper()
	var result histogramExposition
	var haveCount, haveSum bool
	for _, line := range strings.Split(output, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("invalid sample %q", line)
		}
		switch {
		case strings.Contains(fields[0], "_bucket{"):
			count, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			result.buckets = append(result.buckets, count)
		case strings.HasSuffix(fields[0], "_count"):
			count, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			result.count, haveCount = count, true
		case strings.HasSuffix(fields[0], "_sum"):
			sum, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				t.Fatal(err)
			}
			result.sum, haveSum = sum, true
		default:
			t.Fatalf("unexpected sample %q", line)
		}
	}
	if len(result.buckets) == 0 || !haveCount || !haveSum {
		t.Fatalf("incomplete histogram:\n%s", output)
	}
	return result
}

func TestHistogramConcurrentExposition(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []float64
		min    float64
		max    float64
	}{
		{"constant", []float64{1}, 1, 1},
		{"mixed", []float64{-1, 0, 0.5, 1, 1.5, 2, 3, 4, 5}, -1, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bounds := []float64{0, 1, 2, 4}
			registry := NewRegistry()
			histogram, err := registry.RegisterHistogram("portablefs_test_values", "Values.", bounds)
			if err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			var workers, ready sync.WaitGroup
			ready.Add(16)
			for worker := range 16 {
				workers.Go(func() {
					histogram.Observe(tc.values[worker%len(tc.values)])
					ready.Done()
					for i := worker; ; i++ {
						select {
						case <-stop:
							return
						default:
							histogram.Observe(tc.values[i%len(tc.values)])
						}
					}
				})
			}
			defer func() {
				close(stop)
				workers.Wait()
			}()
			ready.Wait()
			for range 500 {
				got := scrapeHistogram(t, registry)
				if len(got.buckets) != len(bounds)+1 || got.buckets[len(bounds)] != got.count {
					t.Fatalf("+Inf != count: %+v", got)
				}
				var previous uint64
				var lowerSum, upperSum float64
				for i, cumulative := range got.buckets {
					if cumulative < previous {
						t.Fatalf("nonmonotone cumulative buckets: %+v", got)
					}
					lower, upper := tc.min, tc.max
					if i > 0 {
						lower = max(lower, bounds[i-1])
					}
					if i < len(bounds) {
						upper = min(upper, bounds[i])
					}
					count := float64(cumulative - previous)
					lowerSum += count * lower
					upperSum += count * upper
					previous = cumulative
				}
				// All test values are binary fractions, so these sums are exact.
				if math.IsNaN(got.sum) || got.sum < lowerSum || got.sum > upperSum {
					t.Fatalf("sum outside bucket bounds [%v, %v]: %+v", lowerSum, upperSum, got)
				}
			}
		})
	}
}

type observingWriter struct {
	bytes.Buffer
	observe func()
}

func (w *observingWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if w.observe != nil {
		observe := w.observe
		w.observe = nil
		observe()
	}
	return n, err
}

func TestHistogramSnapshotBeforeWriting(t *testing.T) {
	registry := NewRegistry()
	histogram, err := registry.RegisterHistogram("portablefs_test_values", "Values.", []float64{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	histogram.Observe(1)
	// Force another observation after the first bucket is formatted. This also
	// proves that formatting does not retain the observation mutex.
	writer := observingWriter{observe: func() { histogram.Observe(1) }}
	if err := histogram.writeTo(&writer, "portablefs_test_values"); err != nil {
		t.Fatal(err)
	}
	if got := parseHistogram(t, writer.String()); !slices.Equal(got.buckets, []uint64{1, 1, 1}) || got.count != 1 || got.sum != 1 {
		t.Fatalf("snapshot changed during formatting: %+v", got)
	}
	if got := scrapeHistogram(t, registry); !slices.Equal(got.buckets, []uint64{2, 2, 2}) || got.count != 2 || got.sum != 2 {
		t.Fatalf("next scrape omitted observation: %+v", got)
	}
}

func TestConcurrentAtomicUpdates(t *testing.T) {
	registry := NewRegistry()
	counter, err := registry.RegisterCounter("portablefs_test_concurrent_total", "Concurrent updates.")
	if err != nil {
		t.Fatal(err)
	}
	gauge, err := registry.RegisterGauge("portablefs_test_concurrent_gauge", "Concurrent gauge updates.")
	if err != nil {
		t.Fatal(err)
	}
	histogram, err := registry.RegisterHistogram("portablefs_test_concurrent_histogram", "Concurrent observations.", []float64{0.5, 1})
	if err != nil {
		t.Fatal(err)
	}
	const goroutines = 16
	const iterations = 5000
	var workers sync.WaitGroup
	workers.Add(goroutines)
	for range goroutines {
		go func() {
			defer workers.Done()
			for range iterations {
				counter.Inc()
				gauge.Inc()
				histogram.Observe(1)
			}
		}()
	}
	workers.Wait()
	want := uint64(goroutines * iterations)
	if counter.Value() != want || gauge.Value() != int64(want) {
		t.Fatalf("counter=%d gauge=%d, want %d", counter.Value(), gauge.Value(), want)
	}
	var output bytes.Buffer
	if err := histogram.writeTo(&output, "portablefs_test_concurrent_histogram"); err != nil {
		t.Fatal(err)
	}
	if got := parseHistogram(t, output.String()); got.count != want || got.sum != float64(want) || !slices.Equal(got.buckets, []uint64{0, want, want}) {
		t.Fatalf("histogram=%+v, want %d observations of 1", got, want)
	}
}

func TestRegistrationRejectsInconsistentFamiliesAndLabels(t *testing.T) {
	registry := NewRegistry()
	if _, err := registry.RegisterCounter("portablefs_test_total", "Counter.", Label{Name: "volume", Value: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RegisterGauge("portablefs_test_total", "Counter.", Label{Name: "volume", Value: "two"}); err == nil {
		t.Fatal("inconsistent metric type was accepted")
	}
	if _, err := registry.RegisterCounter("portablefs_test_total", "Counter.", Label{Name: "volume", Value: "one"}); err == nil {
		t.Fatal("duplicate label set was accepted")
	}
	if _, err := registry.RegisterCounter("portablefs_other_total", "Other.", Label{Name: "bad-name", Value: "one"}); err == nil {
		t.Fatal("invalid label name was accepted")
	}
	if _, err := registry.RegisterHistogram("portablefs_histogram", "Histogram.", []float64{1, 1}); err == nil {
		t.Fatal("non-increasing histogram bounds were accepted")
	}
}
