package authoritymetrics

import (
	"fmt"
	"io"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type coherenceSource struct {
	snapshot func() volumeserver.CoherenceStats
}

// BindCoherence samples the owner's bounded counters without adding work to
// filesystem requests. It is safe to bind as the first request initializes the
// coordinator while the admin endpoint is already accepting scrapes.
func (m *Metrics) BindCoherence(snapshot func() volumeserver.CoherenceStats) {
	if m != nil && snapshot != nil {
		m.coherenceSource.Store(&coherenceSource{snapshot: snapshot})
	}
}

type coherenceSample struct {
	labels string
	value  func(volumeserver.CoherenceStats) uint64
}

type sampledSeries struct {
	snapshot func() volumeserver.CoherenceStats
	samples  []coherenceSample
}

func (s sampledSeries) writeTo(w io.Writer, name string) error {
	// Lifecycle states partition the retained records. Sample once so a state
	// transition cannot count one record twice or omit it from this family.
	snapshot := s.snapshot()
	for _, sample := range s.samples {
		if _, err := fmt.Fprintf(w, "%s%s %d\n", name, sample.labels, sample.value(snapshot)); err != nil {
			return err
		}
	}
	return nil
}

func (m *Metrics) registerCoherenceMetrics(base Label) error {
	type sample = volumeserver.CoherenceStats
	type value struct {
		label Label
		value func(sample) uint64
	}
	for _, metric := range []struct {
		name, help string
		kind       metricType
		values     []value
	}{
		{"portablefs_authority_subscription_horizons", "Retained subscription cache horizons, including fenced horizons awaiting sweep.", gaugeType, []value{{Label{}, func(s sample) uint64 { return s.SubscriptionHorizons }}}},
		{"portablefs_authority_subscription_resets_total", "Cold subscription replacements.", counterType, []value{{Label{}, func(s sample) uint64 { return s.SubscriptionResets }}}},
		{"portablefs_authority_subscription_expirations_total", "Subscription cache horizons retired on expiry.", counterType, []value{{Label{}, func(s sample) uint64 { return s.SubscriptionExpirations }}}},
		{"portablefs_authority_change_log_entries", "Retained entries in the bounded coherence stream.", gaugeType, []value{{Label{}, func(s sample) uint64 { return s.PendingStreamEntries }}}},
		{"portablefs_authority_delegation_capacity_reservations", "Grant capacity reserved before a namespace mutation assigns an identity.", gaugeType, []value{{Label{}, func(s sample) uint64 { return s.DelegationCapacityReservations }}}},
		{"portablefs_authority_delegations", "Retained delegation records by lifecycle state.", gaugeType, []value{
			{Label{Name: "state", Value: "reserved"}, func(s sample) uint64 { return s.DelegationsReserved }},
			{Label{Name: "state", Value: "active"}, func(s sample) uint64 { return s.DelegationsActive }},
			{Label{Name: "state", Value: "recalling"}, func(s sample) uint64 { return s.DelegationsRecalling }},
			{Label{Name: "state", Value: "retiring"}, func(s sample) uint64 { return s.DelegationsRetiring }},
		}},
		{"portablefs_authority_delegation_recalls_total", "Delegation recalls completed or lost before acknowledgment.", counterType, []value{
			{Label{Name: "outcome", Value: "completed"}, func(s sample) uint64 { return s.RecallCompleted }},
			{Label{Name: "outcome", Value: "lost"}, func(s sample) uint64 { return s.RecallLost }},
		}},
		{"portablefs_authority_delegation_breaks_total", "Read breaks completed or lost before acknowledgment.", counterType, []value{
			{Label{Name: "outcome", Value: "completed"}, func(s sample) uint64 { return s.BreakCompleted }},
			{Label{Name: "outcome", Value: "lost"}, func(s sample) uint64 { return s.BreakLost }},
		}},
	} {
		series := sampledSeries{snapshot: func() volumeserver.CoherenceStats {
			if source := m.coherenceSource.Load(); source != nil {
				return source.snapshot()
			}
			return volumeserver.CoherenceStats{}
		}}
		var keys []string
		for _, value := range metric.values {
			labels := []Label{base}
			if value.label.Name != "" {
				labels = append(labels, value.label)
			}
			formatted, key, err := formatLabels(labels)
			if err != nil {
				return err
			}
			keys = append(keys, key)
			series.samples = append(series.samples, coherenceSample{labels: formatted, value: value.value})
		}
		if err := m.registry.register(metric.name, metric.help, metric.kind, nil, keys, series); err != nil {
			return err
		}
	}
	return nil
}
