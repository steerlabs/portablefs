package authoritymetrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestAuthorityMetricInventoryUpdates(t *testing.T) {
	metrics, err := New("volume-a")
	if err != nil {
		t.Fatal(err)
	}
	metrics.ObserveRPC(OperationLookup, OutcomeNotFound, 2*time.Millisecond)
	metrics.SessionActivated()
	metrics.ObserveSessionItems(7)
	metrics.ObserveSessionItems(3)
	metrics.WriteTransactionAdmitted()
	metrics.WriteStagedBytes(4096)
	metrics.WriteAdmissionBlocked()
	metrics.WriteAdmissionFinished(5 * time.Millisecond)
	metrics.ObserveVisibilityBarrier(10*time.Millisecond, 2)
	metrics.Fence(FenceRepairDeadline)
	metrics.WriteStagedBytes(-4096)
	metrics.WriteTransactionReleased()
	metrics.SessionEnded()

	var rendered bytes.Buffer
	if err := metrics.Registry().WritePrometheus(&rendered); err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{
		`portablefs_authority_rpc_requests_total{volume="volume-a",opcode="lookup",outcome="not_found"} 1`,
		`portablefs_authority_rpc_duration_seconds_count{volume="volume-a",opcode="lookup"} 1`,
		`portablefs_authority_active_sessions{volume="volume-a"} 0`,
		`portablefs_authority_session_items_high_water{volume="volume-a"} 7`,
		`portablefs_authority_write_transactions_active{volume="volume-a"} 0`,
		`portablefs_authority_write_transactions_waiting{volume="volume-a"} 0`,
		`portablefs_authority_write_staged_bytes{volume="volume-a"} 0`,
		`portablefs_authority_write_admission_blocks_total{volume="volume-a"} 1`,
		`portablefs_authority_write_admission_wait_seconds_count{volume="volume-a"} 1`,
		`portablefs_authority_visibility_barrier_duration_seconds_count{volume="volume-a"} 1`,
		`portablefs_authority_visibility_barrier_audience_count{volume="volume-a"} 1`,
		`portablefs_authority_fence_events_total{volume="volume-a",reason="repair_deadline"} 1`,
	} {
		if !strings.Contains(rendered.String(), sample+"\n") {
			t.Errorf("rendered inventory omits %q", sample)
		}
	}
}
