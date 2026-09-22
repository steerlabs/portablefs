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

type sampledSeries struct {
	labels string
	sample func() uint64
}

func (s sampledSeries) writeTo(w io.Writer, name string) error {
	_, err := fmt.Fprintf(w, "%s%s %d\n", name, s.labels, s.sample())
	return err
}

func (m *Metrics) registerCoherenceMetrics(base Label) error {
	type sample = volumeserver.CoherenceStats
	for _, metric := range []struct {
		name, help string
		kind       metricType
		label      Label
		value      func(sample) uint64
	}{
		{"portablefs_authority_subscription_horizons", "Retained subscription cache horizons, including fenced horizons awaiting sweep.", gaugeType, Label{}, func(s sample) uint64 { return s.SubscriptionHorizons }},
		{"portablefs_authority_subscription_resets_total", "Cold subscription replacements.", counterType, Label{}, func(s sample) uint64 { return s.SubscriptionResets }},
		{"portablefs_authority_subscription_expirations_total", "Subscription cache horizons retired on expiry.", counterType, Label{}, func(s sample) uint64 { return s.SubscriptionExpirations }},
		{"portablefs_authority_change_log_entries", "Retained entries in the bounded coherence stream.", gaugeType, Label{}, func(s sample) uint64 { return s.PendingStreamEntries }},
		{"portablefs_authority_delegation_capacity_reservations", "Grant capacity reserved before a namespace mutation assigns an identity.", gaugeType, Label{}, func(s sample) uint64 { return s.DelegationCapacityReservations }},
		{"portablefs_authority_delegations", "Retained delegation records by lifecycle state.", gaugeType, Label{Name: "state", Value: "reserved"}, func(s sample) uint64 { return s.DelegationsReserved }},
		{"portablefs_authority_delegations", "Retained delegation records by lifecycle state.", gaugeType, Label{Name: "state", Value: "active"}, func(s sample) uint64 { return s.DelegationsActive }},
		{"portablefs_authority_delegations", "Retained delegation records by lifecycle state.", gaugeType, Label{Name: "state", Value: "recalling"}, func(s sample) uint64 { return s.DelegationsRecalling }},
		{"portablefs_authority_delegations", "Retained delegation records by lifecycle state.", gaugeType, Label{Name: "state", Value: "retiring"}, func(s sample) uint64 { return s.DelegationsRetiring }},
		{"portablefs_authority_delegation_recalls_total", "Delegation recalls completed or lost before acknowledgment.", counterType, Label{Name: "outcome", Value: "completed"}, func(s sample) uint64 { return s.RecallCompleted }},
		{"portablefs_authority_delegation_recalls_total", "Delegation recalls completed or lost before acknowledgment.", counterType, Label{Name: "outcome", Value: "lost"}, func(s sample) uint64 { return s.RecallLost }},
		{"portablefs_authority_delegation_breaks_total", "Read breaks completed or lost before acknowledgment.", counterType, Label{Name: "outcome", Value: "completed"}, func(s sample) uint64 { return s.BreakCompleted }},
		{"portablefs_authority_delegation_breaks_total", "Read breaks completed or lost before acknowledgment.", counterType, Label{Name: "outcome", Value: "lost"}, func(s sample) uint64 { return s.BreakLost }},
	} {
		labels := []Label{base}
		if metric.label.Name != "" {
			labels = append(labels, metric.label)
		}
		formatted, key, err := formatLabels(labels)
		if err != nil {
			return err
		}
		series := sampledSeries{labels: formatted, sample: func() uint64 {
			if source := m.coherenceSource.Load(); source != nil {
				return metric.value(source.snapshot())
			}
			return 0
		}}
		if err := m.registry.register(metric.name, metric.help, metric.kind, nil, key, series); err != nil {
			return err
		}
	}
	return nil
}
