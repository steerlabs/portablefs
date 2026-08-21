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
	metrics.ObserveFsyncBatch(3)
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
		`portablefs_authority_fsync_barrier_handles_total{volume="volume-a"} 3`,
		`portablefs_authority_fsync_storage_syncs_total{volume="volume-a"} 1`,
		`portablefs_authority_visibility_barrier_duration_seconds_count{volume="volume-a"} 1`,
		`portablefs_authority_visibility_barrier_audience_count{volume="volume-a"} 1`,
		`portablefs_authority_fence_events_total{volume="volume-a",reason="repair_deadline"} 1`,
	} {
		if !strings.Contains(rendered.String(), sample+"\n") {
			t.Errorf("rendered inventory omits %q", sample)
		}
	}
}

func TestProtocolSixTelemetryNamesDescribeActiveProfiles(t *testing.T) {
	for operation, want := range map[Operation]string{
		OperationWrite:            "positioned_write",
		OperationNextFskitRepair:  "next_fskit_repair",
		OperationAckFskitRepair:   "ack_fskit_repair",
		OperationFskitWriteBegin:  "fskit_write_begin",
		OperationFskitWriteData:   "fskit_write_data",
		OperationFskitWriteCommit: "fskit_write_commit",
		OperationFskitWriteAbort:  "fskit_write_abort",
	} {
		if got := operation.String(); got != want {
			t.Fatalf("operation %d = %q, want %q", operation, got, want)
		}
	}
	if got := OutcomeFskitRepairRetry.String(); got != "fskit_repair_retry" {
		t.Fatalf("FSKit repair retry outcome = %q", got)
	}
	if got := fenceReasonNames[FenceFskitWriteMismatch]; got != "fskit_write_mismatch" {
		t.Fatalf("FSKit write fence = %q", got)
	}
}
