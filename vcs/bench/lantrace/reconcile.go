package lantrace

import "sort"

// Reconciliation statuses.
const (
	ReconcileMatch            = "match"
	ReconcileMismatch         = "mismatch"
	ReconcileMissingCounter   = "missing_counter"
	ReconcileUnknownAggregate = "unknown_aggregate"
)

// ReconcileLine compares one product counter with one trace aggregate.
type ReconcileLine struct {
	Counter      string `json:"counter"`
	Aggregate    string `json:"aggregate"`
	CounterValue uint64 `json:"counter_value"`
	TraceValue   uint64 `json:"trace_value"`
	Status       string `json:"status"`
}

// Reconcile compares a counters snapshot (counter name to value) with the
// report's aggregates through a declared mapping (counter name to aggregate
// key). An aggregate the trace never produced is zero, which is why a mapping
// must name a key from AggregateKeys: a misspelled key would otherwise compare
// against zero. Lines are sorted by counter name; ok is true only when every
// line matches. A match on an attribution-invalid report is still only a
// coincidence of lower bounds, so callers must check AttributionValid too.
func Reconcile(rep *Report, counters map[string]uint64, mapping map[string]string) (lines []ReconcileLine, ok bool) {
	known := AggregateKeys()
	ok = true
	for counter, aggregate := range mapping {
		line := ReconcileLine{Counter: counter, Aggregate: aggregate, TraceValue: rep.Counters[aggregate]}
		value, have := counters[counter]
		line.CounterValue = value
		_, isKnown := known[aggregate]
		switch {
		case !isKnown:
			line.Status = ReconcileUnknownAggregate
		case !have:
			line.Status = ReconcileMissingCounter
		case value != line.TraceValue:
			line.Status = ReconcileMismatch
		default:
			line.Status = ReconcileMatch
		}
		ok = ok && line.Status == ReconcileMatch
		lines = append(lines, line)
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].Counter < lines[j].Counter })
	return lines, ok
}
