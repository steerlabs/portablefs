package main

import (
	"strings"
	"testing"
)

// goodEvidence mirrors pfm.durability_evidence() for a healthy synchronous
// primary with two live sync standbys (migration 011 shape).
func goodEvidence() map[string]any {
	return map[string]any{
		"systemIdentifier":        "7300000000000000001",
		"database":                "portablefs",
		"serverVersion":           "16.4",
		"fsync":                   "on",
		"fullPageWrites":          "on",
		"synchronousCommit":       "on",
		"synchronousStandbyNames": "ANY 1 (standby_a, standby_b)",
		"inRecovery":              false,
		"transactionReadOnly":     "off",
		"walSenders":              float64(2),
		"streamingStandbys":       float64(2),
		"syncOrQuorumStandbys":    float64(2),
		"replicationVisible":      true,
		"ready":                   true,
		"testBypassActive":        false,
		"standbys": []any{
			map[string]any{"applicationName": "standby_a", "state": "streaming", "syncState": "sync"},
			map[string]any{"applicationName": "standby_b", "state": "streaming", "syncState": "quorum"},
		},
	}
}

func devJournalConfig() config {
	return config{journalDSN: "postgres://authority@127.0.0.1/portablefs"}
}

func managedJournalConfig() config {
	cfg := devJournalConfig()
	cfg.production = true
	cfg.writable = true
	cfg.journalHAPolicyJSON = testHAPolicyJSON
	return cfg
}

// TestEvaluateJournalDurabilityAcceptsOnAndRemoteApply: exactly on and
// remote_apply pass the structural floor; remote_apply also satisfies an
// "on" policy (the ratchet never rejects stronger evidence).
func TestEvaluateJournalDurabilityAcceptsOnAndRemoteApply(t *testing.T) {
	for _, commit := range []string{"on", "remote_apply"} {
		first, second := goodEvidence(), goodEvidence()
		first["synchronousCommit"] = commit
		second["synchronousCommit"] = commit
		if _, err := evaluateJournalDurability(devJournalConfig(), first, second); err != nil {
			t.Fatalf("synchronous_commit=%s must pass without a policy: %v", commit, err)
		}
		hash, err := evaluateJournalDurability(managedJournalConfig(), first, second)
		if err != nil {
			t.Fatalf("synchronous_commit=%s must satisfy the on policy: %v", commit, err)
		}
		if len(hash) != 64 {
			t.Fatalf("policy hash must be reported, got %q", hash)
		}
	}
}

// TestEvaluateJournalDurabilityRejectsWeakerCommitLevels: everything below
// `on` is refused in EVERY mode — even the no-policy development mode, even
// with the test bypass active.
func TestEvaluateJournalDurabilityRejectsWeakerCommitLevels(t *testing.T) {
	for _, commit := range []string{"off", "local", "remote_write", ""} {
		first, second := goodEvidence(), goodEvidence()
		first["synchronousCommit"] = commit
		second["synchronousCommit"] = commit
		first["testBypassActive"] = true
		if _, err := evaluateJournalDurability(devJournalConfig(), first, second); err == nil ||
			!strings.Contains(err.Error(), "synchronous_commit") {
			t.Fatalf("synchronous_commit=%q must be rejected, got %v", commit, err)
		}
	}
}

// TestEvaluateJournalDurabilityRequiresReadyVerdict: the database's own
// ready verdict must hold in BOTH samples — the same guard fences every SQL
// transaction, so serving on unready evidence only defers the failure. The
// superuser-only test bypass (single-node test databases) is honored exactly
// like pfm.require_durable_primary honors it.
func TestEvaluateJournalDurabilityRequiresReadyVerdict(t *testing.T) {
	first, second := goodEvidence(), goodEvidence()
	first["ready"] = false
	second["ready"] = false
	if _, err := evaluateJournalDurability(devJournalConfig(), first, second); err == nil ||
		!strings.Contains(err.Error(), "not ready") {
		t.Fatalf("unready evidence must be rejected, got %v", err)
	}

	// Ready in the first sample only: mid-check degradation is a refusal.
	first, second = goodEvidence(), goodEvidence()
	second["ready"] = false
	if _, err := evaluateJournalDurability(devJournalConfig(), first, second); err == nil ||
		!strings.Contains(err.Error(), "not ready") {
		t.Fatalf("evidence degrading between samples must be rejected, got %v", err)
	}

	// The test bypass (superuser-only in SQL) substitutes for ready in dev.
	first, second = goodEvidence(), goodEvidence()
	first["ready"] = false
	second["ready"] = false
	first["testBypassActive"] = true
	first["synchronousStandbyNames"] = ""
	second["synchronousStandbyNames"] = ""
	first["syncOrQuorumStandbys"] = float64(0)
	second["syncOrQuorumStandbys"] = float64(0)
	if _, err := evaluateJournalDurability(devJournalConfig(), first, second); err != nil {
		t.Fatalf("the explicit test bypass must be honored in development: %v", err)
	}
}

// TestEvaluateJournalDurabilityRequiresStableSystemIdentifier: missing or
// unstable cluster identity is refused — two samples answered by different
// clusters describe no durable primary at all.
func TestEvaluateJournalDurabilityRequiresStableSystemIdentifier(t *testing.T) {
	first, second := goodEvidence(), goodEvidence()
	first["systemIdentifier"] = ""
	if _, err := evaluateJournalDurability(devJournalConfig(), first, second); err == nil ||
		!strings.Contains(err.Error(), "system identifier") {
		t.Fatalf("missing system identifier must be rejected, got %v", err)
	}

	first, second = goodEvidence(), goodEvidence()
	delete(first, "systemIdentifier")
	if _, err := evaluateJournalDurability(devJournalConfig(), first, second); err == nil ||
		!strings.Contains(err.Error(), "system identifier") {
		t.Fatalf("absent system identifier must be rejected, got %v", err)
	}

	first, second = goodEvidence(), goodEvidence()
	second["systemIdentifier"] = "7300000000000000002"
	if _, err := evaluateJournalDurability(devJournalConfig(), first, second); err == nil ||
		!strings.Contains(err.Error(), "changed between evidence samples") {
		t.Fatalf("unstable system identifier must be rejected, got %v", err)
	}
}

// TestEvaluateJournalDurabilityRequiresReplicationVisibility: evidence that
// cannot see pg_stat_replication cannot prove standby liveness and is
// refused.
func TestEvaluateJournalDurabilityRequiresReplicationVisibility(t *testing.T) {
	first, second := goodEvidence(), goodEvidence()
	first["replicationVisible"] = false
	if _, err := evaluateJournalDurability(devJournalConfig(), first, second); err == nil ||
		!strings.Contains(err.Error(), "pg_stat_replication") {
		t.Fatalf("hidden replication state must be rejected, got %v", err)
	}
}

// TestEvaluateJournalDurabilityPolicyLayer: the structured policy evaluates
// on BOTH samples (a second sample violating it is a refusal), the on-never-
// satisfies-remote_apply ratchet holds end to end, and managed production
// without a policy is refused even at runtime.
func TestEvaluateJournalDurabilityPolicyLayer(t *testing.T) {
	remoteApplyPolicy := strings.Replace(testHAPolicyJSON,
		`"minSynchronousCommit":"on"`, `"minSynchronousCommit":"remote_apply"`, 1)
	cfg := managedJournalConfig()
	cfg.journalHAPolicyJSON = remoteApplyPolicy
	first, second := goodEvidence(), goodEvidence() // synchronous_commit=on
	if _, err := evaluateJournalDurability(cfg, first, second); err == nil ||
		!strings.Contains(err.Error(), "remote_apply") {
		t.Fatalf("on must never satisfy a remote_apply policy, got %v", err)
	}

	first["synchronousCommit"] = "remote_apply"
	second["synchronousCommit"] = "remote_apply"
	if _, err := evaluateJournalDurability(cfg, first, second); err != nil {
		t.Fatalf("remote_apply evidence must satisfy a remote_apply policy: %v", err)
	}

	// Second sample degrading below the policy is a refusal even though the
	// structural ready floor still held.
	cfg = managedJournalConfig()
	cfg.journalHAPolicyJSON = strings.Replace(testHAPolicyJSON,
		`"minDistinctFailureDomains":1`, `"minDistinctFailureDomains":2`, 1)
	first, second = goodEvidence(), goodEvidence()
	second["standbys"] = []any{
		map[string]any{"applicationName": "standby_a", "state": "streaming", "syncState": "sync"},
	}
	if _, err := evaluateJournalDurability(cfg, first, second); err == nil ||
		!strings.Contains(err.Error(), "second evidence sample") {
		t.Fatalf("a degrading second sample must be rejected, got %v", err)
	}

	// Live synchronous standbys outside the operator-attested domain mapping
	// prove no distinct domain.
	cfg = managedJournalConfig()
	cfg.journalHAPolicyJSON = strings.Replace(testHAPolicyJSON,
		`"standbyFailureDomains":{"standby_a":"zone-a","standby_b":"zone-b"}`,
		`"standbyFailureDomains":{"other_name":"zone-a"}`, 1)
	_, err := evaluateJournalDurability(cfg, goodEvidence(), goodEvidence())
	if err == nil || !strings.Contains(err.Error(), "operator-attested") {
		t.Fatalf("unattested live standbys must not satisfy the domain requirement, got %v", err)
	}

	// Managed production without a policy is refused at runtime too (belt to
	// validateConfig's suspenders).
	cfg = managedJournalConfig()
	cfg.journalHAPolicyJSON = ""
	if _, err := evaluateJournalDurability(cfg, goodEvidence(), goodEvidence()); err == nil ||
		!strings.Contains(err.Error(), "VCS_JOURNAL_HA_POLICY_JSON") {
		t.Fatalf("managed production without a policy must be refused, got %v", err)
	}
}
