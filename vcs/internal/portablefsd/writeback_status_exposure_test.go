package portablefsd

import (
	"encoding/json"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// TestWriteBackStatusExposesCreditControl pins the credit controller's
// observability contract: the drain-time pacing state the engine already
// computes must survive the projection onto the daemon's wire type and the
// JSON encoding, or a paced mount is indistinguishable from a hung flusher to
// everything outside the Go tests.
func TestWriteBackStatusExposesCreditControl(t *testing.T) {
	st := writeback.Status{
		PendingRecords:  7,
		PendingBytes:    4096,
		AdmittedThrough: 99,
		AppliedThrough:  90,
		OldestPendingMs: 1500,
		LastProgressMs:  250,
		WALBytes:        8192,
		WALBudget:       1 << 30,
		CreditSetpoint:  64 << 20,
		CreditDebt:      48 << 20,
		CreditCeiling:   128 << 20,
		AppliedRateBps:  1234.5,
		CreditWaiters:   3,
		DataLaneFull:    true,
	}

	wb := newWriteBackStatus(st)
	if wb == nil {
		t.Fatal("newWriteBackStatus returned nil")
	}
	if wb.CreditSetpoint != st.CreditSetpoint {
		t.Errorf("CreditSetpoint = %d, want %d", wb.CreditSetpoint, st.CreditSetpoint)
	}
	if wb.CreditDebt != st.CreditDebt {
		t.Errorf("CreditDebt = %d, want %d", wb.CreditDebt, st.CreditDebt)
	}
	if wb.CreditCeiling != st.CreditCeiling {
		t.Errorf("CreditCeiling = %d, want %d", wb.CreditCeiling, st.CreditCeiling)
	}
	if wb.AppliedRateBps != st.AppliedRateBps {
		t.Errorf("AppliedRateBps = %v, want %v", wb.AppliedRateBps, st.AppliedRateBps)
	}
	if wb.CreditWaiters != st.CreditWaiters {
		t.Errorf("CreditWaiters = %d, want %d", wb.CreditWaiters, st.CreditWaiters)
	}
	if !wb.DataLaneFull {
		t.Error("DataLaneFull = false, want true")
	}
	// A setpoint is unreadable without its cap and without the liveness signal
	// that separates "paced" from "stuck".
	if wb.WALBudget != st.WALBudget {
		t.Errorf("WALBudget = %d, want %d", wb.WALBudget, st.WALBudget)
	}
	if wb.LastProgressMs != st.LastProgressMs {
		t.Errorf("LastProgressMs = %d, want %d", wb.LastProgressMs, st.LastProgressMs)
	}

	blob, err := json.Marshal(wb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for key, want := range map[string]float64{
		"creditSetpoint": float64(st.CreditSetpoint),
		"creditDebt":     float64(st.CreditDebt),
		"creditCeiling":  float64(st.CreditCeiling),
		"appliedRateBps": st.AppliedRateBps,
		"creditWaiters":  float64(st.CreditWaiters),
		"walBudget":      float64(st.WALBudget),
		"lastProgressMs": float64(st.LastProgressMs),
	} {
		got, ok := generic[key]
		if !ok {
			t.Errorf("JSON is missing %q: %s", key, blob)
			continue
		}
		if got != want {
			t.Errorf("JSON %q = %v, want %v", key, got, want)
		}
	}
	if generic["dataLaneFull"] != true {
		t.Errorf("JSON dataLaneFull = %v, want true: %s", generic["dataLaneFull"], blob)
	}

	// The CLI decodes this same document; its field set must retain the credit
	// state rather than dropping it on the floor. This mirrors
	// cmd/portablefs/internal/cli.cliWriteBackStatus, which that package's
	// internal visibility keeps out of reach here.
	var cli struct {
		PendingRecords int     `json:"pendingRecords"`
		CreditSetpoint int64   `json:"creditSetpoint"`
		CreditDebt     int64   `json:"creditDebt"`
		CreditCeiling  int64   `json:"creditCeiling"`
		AppliedRateBps float64 `json:"appliedRateBps"`
		CreditWaiters  int     `json:"creditWaiters"`
		DataLaneFull   bool    `json:"dataLaneFull"`
		WALBudget      int64   `json:"walBudget"`
		LastProgressMs int64   `json:"lastProgressMs"`
	}
	if err := json.Unmarshal(blob, &cli); err != nil {
		t.Fatalf("CLI-shaped decode: %v", err)
	}
	if cli.CreditSetpoint != st.CreditSetpoint || cli.CreditDebt != st.CreditDebt ||
		cli.CreditCeiling != st.CreditCeiling || cli.AppliedRateBps != st.AppliedRateBps ||
		cli.CreditWaiters != st.CreditWaiters || !cli.DataLaneFull ||
		cli.WALBudget != st.WALBudget || cli.LastProgressMs != st.LastProgressMs {
		t.Errorf("CLI-shaped decode lost credit state: %+v", cli)
	}
}

// TestWriteBackStatusOmitsIdleCreditState keeps the wire quiet for an engine
// that is not pacing anything: the additive fields must not appear when zero.
func TestWriteBackStatusOmitsIdleCreditState(t *testing.T) {
	blob, err := json.Marshal(newWriteBackStatus(writeback.Status{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"creditSetpoint", "creditDebt", "creditCeiling", "appliedRateBps", "creditWaiters", "dataLaneFull", "walBudget", "lastProgressMs"} {
		if _, ok := generic[key]; ok {
			t.Errorf("idle status should omit %q: %s", key, blob)
		}
	}
	// The pre-existing always-present fields stay present.
	for _, key := range []string{"pendingRecords", "pendingBytes", "delegations"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("status must always carry %q: %s", key, blob)
		}
	}
}
