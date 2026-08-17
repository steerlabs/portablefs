package authoritymetrics

import (
	"bytes"
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

func TestHistogramBucketing(t *testing.T) {
	registry := NewRegistry()
	histogram, err := registry.RegisterHistogram("portablefs_test_values", "Values.", []float64{1, 2, 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range []float64{-1, 1, 1.5, 2, 5, 6} {
		histogram.Observe(observation)
	}
	if histogram.Count() != 6 || histogram.Sum() != 14.5 {
		t.Fatalf("count=%d sum=%v, want 6 and 14.5", histogram.Count(), histogram.Sum())
	}
	var rendered bytes.Buffer
	if err := registry.WritePrometheus(&rendered); err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{
		`portablefs_test_values_bucket{le="1"} 2`,
		`portablefs_test_values_bucket{le="2"} 4`,
		`portablefs_test_values_bucket{le="5"} 5`,
		`portablefs_test_values_bucket{le="+Inf"} 6`,
	} {
		if !strings.Contains(rendered.String(), sample+"\n") {
			t.Errorf("rendered metrics omit %q:\n%s", sample, rendered.String())
		}
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
	if counter.Value() != want || gauge.Value() != int64(want) || histogram.Count() != want || histogram.Sum() != float64(want) {
		t.Fatalf("counter=%d gauge=%d histogram=(%d,%v), want %d", counter.Value(), gauge.Value(), histogram.Count(), histogram.Sum(), want)
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
