package authoritymetrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestMetricLabelTablesAreCompleteAndUnique(t *testing.T) {
	for _, table := range []struct {
		name   string
		labels []string
	}{
		{"operations", operationNames[:]},
		{"outcomes", outcomeNames[:]},
	} {
		t.Run(table.name, func(t *testing.T) {
			seen := make(map[string]bool)
			for i, label := range table.labels {
				if label == "" || seen[label] {
					t.Fatalf("entry %d is empty or duplicated: %q", i, label)
				}
				seen[label] = true
			}
		})
	}
	for _, tc := range []struct {
		operation Operation
		want      string
	}{
		{OperationFallocate, "fallocate"}, {OperationFsync, "fsync"},
		{OperationSyncFS, "syncfs"}, {OperationWaitVisibility, "wait_visibility"},
	} {
		if got := tc.operation.String(); got != tc.want {
			t.Errorf("operation %d=%q, want %q", tc.operation, got, tc.want)
		}
	}
}

func TestAuthorityMetricInventoryUpdates(t *testing.T) {
	metrics, err := New("volume-a")
	if err != nil {
		t.Fatal(err)
	}
	metrics.ObserveRPC(OperationLookup, OutcomeNotFound, 2*time.Millisecond)
	metrics.ObserveRPC(OperationWaitVisibility, OutcomeSuccess, time.Millisecond)
	metrics.SessionActivated()
	metrics.ObserveSessionItems(7)
	metrics.ObserveSessionItems(3)
	metrics.ObserveFsyncBatch(3)
	metrics.ObserveMutation("executed")
	metrics.ObserveMutation("replayed")
	metrics.ObserveMutation("refused")
	for _, kind := range []string{"handle", "syncfs"} {
		metrics.ObserveFskitDurability(kind, time.Millisecond)
	}
	metrics.SessionEnded()

	var rendered bytes.Buffer
	if err := metrics.Registry().WritePrometheus(&rendered); err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{
		`portablefs_authority_rpc_requests_total{volume="volume-a",opcode="lookup",outcome="not_found"} 1`,
		`portablefs_authority_rpc_duration_seconds_count{volume="volume-a",opcode="lookup"} 1`,
		`portablefs_authority_rpc_requests_total{volume="volume-a",opcode="wait_visibility",outcome="success"} 1`,
		`portablefs_authority_active_sessions{volume="volume-a"} 0`,
		`portablefs_authority_session_items_high_water{volume="volume-a"} 7`,
		`portablefs_authority_fsync_barrier_handles_total{volume="volume-a"} 3`,
		`portablefs_authority_fsync_storage_syncs_total{volume="volume-a"} 1`,
		`portablefs_authority_mutations_total{volume="volume-a",disposition="executed"} 1`,
		`portablefs_authority_mutations_total{volume="volume-a",disposition="replayed"} 1`,
		`portablefs_authority_mutations_total{volume="volume-a",disposition="refused"} 1`,
		`portablefs_authority_fskit_durability_syncs_total{volume="volume-a",target="handle"} 1`,
		`portablefs_authority_fskit_durability_syncs_total{volume="volume-a",target="syncfs"} 1`,
		`portablefs_authority_fskit_durability_duration_seconds_count{volume="volume-a",target="handle"} 1`,
		`portablefs_authority_fskit_durability_duration_seconds_count{volume="volume-a",target="syncfs"} 1`,
	} {
		if !strings.Contains(rendered.String(), sample+"\n") {
			t.Errorf("rendered inventory omits %q", sample)
		}
	}
}

func TestPhysicalStorageSyncMetrics(t *testing.T) {
	metrics, err := New("physical")
	if err != nil {
		t.Fatal(err)
	}
	metrics.ObserveStorageSync("syncfs", time.Millisecond, 3)
	metrics.ObserveStorageSync("fsync", time.Millisecond, 1)
	var rendered bytes.Buffer
	if err := metrics.Registry().WritePrometheus(&rendered); err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{
		`portablefs_authority_storage_syncs_total{volume="physical",syscall="syncfs"} 1`,
		`portablefs_authority_storage_sync_waiters_total{volume="physical",syscall="syncfs"} 3`,
		`portablefs_authority_storage_sync_duration_seconds_count{volume="physical",syscall="syncfs"} 1`,
	} {
		if !strings.Contains(rendered.String(), sample+"\n") {
			t.Fatalf("missing %s", sample)
		}
	}
}
