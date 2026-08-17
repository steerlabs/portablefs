// Package authoritymetrics provides the dependency-free telemetry surface for
// one PortableFS authority worker. Metric handles are registered once during
// startup and update atomically; rendering is the only path that walks the
// registry or formats labels.
package authoritymetrics

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type Label struct {
	Name  string
	Value string
}

type metricType uint8

const (
	counterType metricType = iota + 1
	gaugeType
	histogramType
)

func (t metricType) String() string {
	switch t {
	case counterType:
		return "counter"
	case gaugeType:
		return "gauge"
	case histogramType:
		return "histogram"
	default:
		return "untyped"
	}
}

type metricSeries interface {
	writeTo(io.Writer, string) error
}

type metricFamily struct {
	name       string
	help       string
	typeName   metricType
	bounds     []float64
	series     []metricSeries
	seriesKeys map[string]struct{}
}

// Registry owns an immutable-after-startup set of metric handles. Registration
// takes a mutex because configuration errors should be reported cleanly even in
// tests; increments never touch it.
type Registry struct {
	mu       sync.RWMutex
	families []*metricFamily
	byName   map[string]*metricFamily
}

func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]*metricFamily)}
}

type Counter struct {
	labels string
	value  atomic.Uint64
}

func (c *Counter) Inc() {
	if c != nil {
		c.value.Add(1)
	}
}

func (c *Counter) Add(value uint64) {
	if c != nil {
		c.value.Add(value)
	}
}

func (c *Counter) Value() uint64 {
	if c == nil {
		return 0
	}
	return c.value.Load()
}

func (c *Counter) writeTo(w io.Writer, name string) error {
	_, err := fmt.Fprintf(w, "%s%s %d\n", name, c.labels, c.value.Load())
	return err
}

type Gauge struct {
	labels string
	value  atomic.Int64
}

func (g *Gauge) Add(delta int64) {
	if g != nil {
		g.value.Add(delta)
	}
}

func (g *Gauge) Inc() { g.Add(1) }
func (g *Gauge) Dec() { g.Add(-1) }

func (g *Gauge) Set(value int64) {
	if g != nil {
		g.value.Store(value)
	}
}

func (g *Gauge) SetMax(value int64) {
	if g == nil {
		return
	}
	for current := g.value.Load(); value > current; current = g.value.Load() {
		if g.value.CompareAndSwap(current, value) {
			return
		}
	}
}

func (g *Gauge) Value() int64 {
	if g == nil {
		return 0
	}
	return g.value.Load()
}

func (g *Gauge) writeTo(w io.Writer, name string) error {
	_, err := fmt.Fprintf(w, "%s%s %d\n", name, g.labels, g.value.Load())
	return err
}

// Histogram uses fixed, noncumulative counters internally. Observe performs a
// bounded linear bucket scan plus atomic updates; scrape-time rendering builds
// the cumulative Prometheus buckets.
type Histogram struct {
	labels  string
	bounds  []float64
	buckets []atomic.Uint64
	count   atomic.Uint64
	sum     atomic.Uint64
}

func (h *Histogram) Observe(value float64) {
	if h == nil || math.IsNaN(value) {
		return
	}
	bucket := len(h.bounds)
	for index, bound := range h.bounds {
		if value <= bound {
			bucket = index
			break
		}
	}
	h.buckets[bucket].Add(1)
	h.count.Add(1)
	for {
		current := h.sum.Load()
		next := math.Float64bits(math.Float64frombits(current) + value)
		if h.sum.CompareAndSwap(current, next) {
			return
		}
	}
}

func (h *Histogram) Count() uint64 {
	if h == nil {
		return 0
	}
	return h.count.Load()
}

func (h *Histogram) Sum() float64 {
	if h == nil {
		return 0
	}
	return math.Float64frombits(h.sum.Load())
}

func (h *Histogram) writeTo(w io.Writer, name string) error {
	cumulative := uint64(0)
	for index, bound := range h.bounds {
		cumulative += h.buckets[index].Load()
		if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", name, labelsWith(h.labels, "le", formatFloat(bound)), cumulative); err != nil {
			return err
		}
	}
	cumulative += h.buckets[len(h.bounds)].Load()
	if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", name, labelsWith(h.labels, "le", "+Inf"), cumulative); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s_sum%s %s\n", name, h.labels, formatFloat(h.Sum())); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%s_count%s %d\n", name, h.labels, h.count.Load())
	return err
}

func (r *Registry) RegisterCounter(name, help string, labels ...Label) (*Counter, error) {
	formatted, key, err := formatLabels(labels)
	if err != nil {
		return nil, err
	}
	series := &Counter{labels: formatted}
	if err := r.register(name, help, counterType, nil, key, series); err != nil {
		return nil, err
	}
	return series, nil
}

func (r *Registry) RegisterGauge(name, help string, labels ...Label) (*Gauge, error) {
	formatted, key, err := formatLabels(labels)
	if err != nil {
		return nil, err
	}
	series := &Gauge{labels: formatted}
	if err := r.register(name, help, gaugeType, nil, key, series); err != nil {
		return nil, err
	}
	return series, nil
}

func (r *Registry) RegisterHistogram(name, help string, bounds []float64, labels ...Label) (*Histogram, error) {
	if len(bounds) == 0 {
		return nil, errors.New("authoritymetrics: a histogram needs finite buckets")
	}
	for index, bound := range bounds {
		if math.IsNaN(bound) || math.IsInf(bound, 0) || index > 0 && bound <= bounds[index-1] {
			return nil, errors.New("authoritymetrics: histogram buckets must be finite and strictly increasing")
		}
	}
	formatted, key, err := formatLabels(labels)
	if err != nil {
		return nil, err
	}
	ownedBounds := append([]float64(nil), bounds...)
	series := &Histogram{labels: formatted, bounds: ownedBounds, buckets: make([]atomic.Uint64, len(ownedBounds)+1)}
	if err := r.register(name, help, histogramType, ownedBounds, key, series); err != nil {
		return nil, err
	}
	return series, nil
}

func (r *Registry) register(name, help string, kind metricType, bounds []float64, key string, series metricSeries) error {
	if r == nil || !validMetricName(name) || help == "" || strings.ContainsAny(help, "\r") {
		return errors.New("authoritymetrics: metric name and help are required and must be valid")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byName == nil {
		r.byName = make(map[string]*metricFamily)
	}
	family := r.byName[name]
	if family == nil {
		family = &metricFamily{name: name, help: help, typeName: kind, bounds: append([]float64(nil), bounds...), seriesKeys: make(map[string]struct{})}
		r.byName[name] = family
		r.families = append(r.families, family)
	} else if family.help != help || family.typeName != kind || !sameBounds(family.bounds, bounds) {
		return fmt.Errorf("authoritymetrics: inconsistent registration for %s", name)
	}
	if _, duplicate := family.seriesKeys[key]; duplicate {
		return fmt.Errorf("authoritymetrics: duplicate label set for %s", name)
	}
	family.seriesKeys[key] = struct{}{}
	family.series = append(family.series, series)
	return nil
}

// WritePrometheus renders Prometheus text exposition format 0.0.4.
func (r *Registry) WritePrometheus(w io.Writer) error {
	if r == nil || w == nil {
		return errors.New("authoritymetrics: registry and writer are required")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, family := range r.families {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", family.name, escapeHelp(family.help), family.name, family.typeName); err != nil {
			return err
		}
		for _, series := range family.series {
			if err := series.writeTo(w, family.name); err != nil {
				return err
			}
		}
	}
	return nil
}

func sameBounds(left, right []float64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validMetricName(value string) bool {
	if value == "" {
		return false
	}
	for index, char := range value {
		if char == '_' || char == ':' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || index > 0 && char >= '0' && char <= '9' {
			continue
		}
		return false
	}
	return true
}

func validLabelName(value string) bool {
	if value == "" {
		return false
	}
	for index, char := range value {
		if char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || index > 0 && char >= '0' && char <= '9' {
			continue
		}
		return false
	}
	return true
}

func formatLabels(labels []Label) (formatted, key string, err error) {
	if len(labels) == 0 {
		return "", "", nil
	}
	seen := make(map[string]struct{}, len(labels))
	var builder strings.Builder
	builder.WriteByte('{')
	for index, label := range labels {
		if !validLabelName(label.Name) {
			return "", "", fmt.Errorf("authoritymetrics: invalid label name %q", label.Name)
		}
		if _, duplicate := seen[label.Name]; duplicate {
			return "", "", fmt.Errorf("authoritymetrics: duplicate label name %q", label.Name)
		}
		seen[label.Name] = struct{}{}
		if index != 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(label.Name)
		builder.WriteString("=\"")
		builder.WriteString(escapeLabel(label.Value))
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	formatted = builder.String()
	return formatted, formatted, nil
}

func labelsWith(existing, name, value string) string {
	entry := name + "=\"" + escapeLabel(value) + "\""
	if existing == "" {
		return "{" + entry + "}"
	}
	return existing[:len(existing)-1] + "," + entry + "}"
}

func escapeHelp(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return strings.ReplaceAll(value, "\n", "\\n")
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}
