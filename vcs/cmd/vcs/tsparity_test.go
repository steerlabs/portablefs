package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/hapolicy"
	"github.com/steerlabs/portablefs/vcs/internal/managerlease"
)

// These tests pin the manager↔child wire contract against the TypeScript
// authority manager (apps/authority-manager/src/production-registry.ts and
// its fake-child frames in production.test.ts). The TS side validates every
// field of the one-shot bootstrap frame, delivers newline-delimited JSON v1
// lease frames, and cross-checks the /readyz identity payload — so the Go
// side must stay byte-compatible, not merely semantically similar.

// TestBootstrapFrameMatchesTSManagerByteLayout emits one bootstrap frame with
// the exact values the TS test harness scripts for its fake child
// (ProdVcsSim.bootstrapFrame) and asserts the EXACT byte layout: JSON object
// with the same member order JSON.stringify produces for the TS literal, no
// whitespace, one trailing newline, nothing else. consumeBootstrap on the TS
// side reads exactly one bounded line and refuses trailing bytes, so byte
// identity here is the interop proof.
func TestBootstrapFrameMatchesTSManagerByteLayout(t *testing.T) {
	var pipe bytes.Buffer
	frame := managerlease.Bootstrap{
		AuthorityInstanceID: "pfvcs_a",
		VolumeID:            "vol_1",
		Branch:              "main",
		ManagerEpoch:        "1",
		AuthorityRuntimeSeq: "1",
		AuthorityRuntimeID:  "pfrt_a",
		FSAddr:              "127.0.0.1:42001",
		MetricsAddr:         "127.0.0.1:43001",
		JournalGenerationID: "pfgen_sim_1",
		ProtocolVersion:     managedProtocolVersion,
		HAPolicyHash:        tsPinnedHAPolicyHash,
	}
	if err := managerlease.EmitBootstrap(&pipe, frame); err != nil {
		t.Fatalf("emit bootstrap: %v", err)
	}
	// JSON.stringify of the TS object literal: member order is insertion
	// order, no spaces, integers unquoted, every id/address a plain string.
	want := `{"v":1,` +
		`"authorityInstanceId":"pfvcs_a",` +
		`"volumeId":"vol_1",` +
		`"branch":"main",` +
		`"managerEpoch":"1",` +
		`"authorityRuntimeSeq":"1",` +
		`"authorityRuntimeId":"pfrt_a",` +
		`"fsAddr":"127.0.0.1:42001",` +
		`"metricsAddr":"127.0.0.1:43001",` +
		`"journalGenerationId":"pfgen_sim_1",` +
		`"protocolVersion":1,` +
		`"haPolicyHash":"` + tsPinnedHAPolicyHash + `"}` + "\n"
	if got := pipe.String(); got != want {
		t.Fatalf("bootstrap frame bytes diverge from the TS layout:\n got: %s\nwant: %s", got, want)
	}
}

// TestLeaseFrameParsesTSManagerBytes feeds ParseFrame the EXACT bytes the TS
// manager's flushHeartbeatFrame writes (JSON.stringify member order, integer
// millisecond facts) and asserts a Guard accepts them against the exact
// launch identity. The TS registry delivers frames latest-value/coalesced
// with a strictly monotonic per-child sequence starting at 1.
func TestLeaseFrameParsesTSManagerBytes(t *testing.T) {
	line := []byte(`{"v":1,` +
		`"seq":1,` +
		`"managerEpoch":"1",` +
		`"managerRuntimeId":"pfmgr_a",` +
		`"authorityInstanceId":"pfvcs_a",` +
		`"authorityRuntimeSeq":"1",` +
		`"authorityRuntimeId":"pfrt_a",` +
		`"dbTimeMs":1000000,` +
		`"leaseRemainingMs":30000}`)
	frame, err := managerlease.ParseFrame(line)
	if err != nil {
		t.Fatalf("the TS lease frame bytes must parse: %v", err)
	}
	if frame.Seq != 1 || frame.ManagerEpoch != "1" || frame.ManagerRuntimeID != "pfmgr_a" ||
		frame.AuthorityInstanceID != "pfvcs_a" || frame.AuthorityRuntimeSeq != "1" ||
		frame.AuthorityRuntimeID != "pfrt_a" || frame.DBTimeMs != 1_000_000 || frame.LeaseRemainingMs != 30_000 {
		t.Fatalf("parsed frame diverges from the TS facts: %+v", frame)
	}
	// The TS wire contract floors every millisecond fact to an integer
	// precisely because the Go guard fences on fractions.
	if _, err := managerlease.ParseFrame(bytes.Replace(line, []byte(`"dbTimeMs":1000000`), []byte(`"dbTimeMs":1000000.5`), 1)); err == nil {
		t.Fatal("a fractional dbTimeMs must be rejected (the TS side floors for exactly this reason)")
	}
}

// tsPinnedHAPolicyHash is TEST_HA_POLICY_HASH_PINNED from
// apps/authority-manager/src/production.test.ts: the literal the TS suite
// asserts canonicalHaPolicyHash produces for testHAPolicyJSON. The Go child
// reports hapolicy.Policy.Hash() through bootstrap and readiness, and the TS
// manager refuses adoption unless the two hashes are identical — so the two
// canonical JSON encoders must stay byte-identical.
const tsPinnedHAPolicyHash = "0bd3101de332afaa3e00d748e86d4e47387f1c67445777aba3ac5b2fa6cf7347"

func TestHAPolicyHashMatchesTSPinnedLiteral(t *testing.T) {
	policy, err := hapolicy.ParsePolicy(testHAPolicyJSON)
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	if got := policy.Hash(); got != tsPinnedHAPolicyHash {
		t.Fatalf("Go canonical policy hash %s diverges from the TS pinned literal %s", got, tsPinnedHAPolicyHash)
	}
}

// TestReadyzIdentityMatchesTSProcessReadyFields publishes the managed
// readiness identity and asserts /readyz carries EXACTLY the fields (names
// and values) the TS registry's processReady cross-checks before it will
// route to the child.
func TestReadyzIdentityMatchesTSProcessReadyFields(t *testing.T) {
	setReady(true)
	setRole("primary")
	readyIdentity.Store(&readinessIdentity{
		AuthorityInstanceID: "pfvcs_a",
		VolumeID:            "vol_1",
		Branch:              "main",
		Journal:             "remote",
		ManagerEpoch:        "1",
		AuthorityRuntimeSeq: "1",
		AuthorityRuntimeID:  "pfrt_a",
		JournalGenerationID: "pfgen_sim_1",
		ProtocolVersion:     managedProtocolVersion,
		HAPolicyHash:        tsPinnedHAPolicyHash,
		FSAddr:              "127.0.0.1:42001",
		MetricsAddr:         "127.0.0.1:43001",
	})
	t.Cleanup(func() {
		readyIdentity.Store(nil)
		setReady(false)
	})

	rec := httptest.NewRecorder()
	readinessHandler(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /readyz: %v", err)
	}
	// The exact identity cross-check from processReady in
	// production-registry.ts; protocolVersion arrives as a JSON number.
	for field, want := range map[string]any{
		"ready":               true,
		"authorityInstanceId": "pfvcs_a",
		"volumeId":            "vol_1",
		"branch":              "main",
		"journal":             "remote",
		"managerEpoch":        "1",
		"authorityRuntimeSeq": "1",
		"authorityRuntimeId":  "pfrt_a",
		"journalGenerationId": "pfgen_sim_1",
		"protocolVersion":     float64(managedProtocolVersion),
		"haPolicyHash":        tsPinnedHAPolicyHash,
		"fsAddr":              "127.0.0.1:42001",
		"metricsAddr":         "127.0.0.1:43001",
	} {
		if body[field] != want {
			t.Fatalf("/readyz %s = %v, want %v (TS processReady would refuse adoption)", field, body[field], want)
		}
	}
}
