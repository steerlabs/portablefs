package hapolicy

import (
	"strings"
	"testing"
)

// goodFacts mirrors pfm.durability_evidence() for a healthy synchronous
// primary with two live sync standbys in two attested failure domains.
func goodFacts() map[string]any {
	return map[string]any{
		"systemIdentifier":        "7300000000000000001",
		"database":                "portablefs",
		"fsync":                   "on",
		"fullPageWrites":          "on",
		"inRecovery":              false,
		"transactionReadOnly":     "off",
		"synchronousCommit":       "on",
		"synchronousStandbyNames": "ANY 1 (standby_a, standby_b)",
		"replicationVisible":      true,
		"standbys": []any{
			map[string]any{"applicationName": "standby_a", "state": "streaming", "syncState": "sync"},
			map[string]any{"applicationName": "standby_b", "state": "streaming", "syncState": "quorum"},
			map[string]any{"applicationName": "reporting", "state": "streaming", "syncState": "async"},
		},
	}
}

func basePolicy() Policy {
	return Policy{
		V:                        1,
		ExpectedSystemIdentifier: "7300000000000000001",
		ExpectedDatabase:         "portablefs",
		MinSynchronousCommit:     "on",
		MinSyncStandbys:          1,
		StandbyFailureDomains: map[string]string{
			"standby_a": "zone-a",
			"standby_b": "zone-b",
		},
		MinDistinctFailureDomains: 1,
	}
}

const validPolicyJSON = `{"v":1,"expectedSystemIdentifier":"7300000000000000001","expectedDatabase":"portablefs","minSynchronousCommit":"on","minSyncStandbys":1,"standbyFailureDomains":{"standby_a":"zone-a","standby_b":"zone-b"},"minDistinctFailureDomains":1}`

func TestParsePolicyValidatesStrictly(t *testing.T) {
	parsed, err := ParsePolicy(validPolicyJSON)
	if err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if parsed.StandbyFailureDomains["standby_a"] != "zone-a" {
		t.Fatalf("domain mapping lost: %+v", parsed)
	}

	cases := map[string]string{
		"wrong version":          strings.Replace(validPolicyJSON, `"v":1`, `"v":2`, 1),
		"unknown commit":         strings.Replace(validPolicyJSON, `"minSynchronousCommit":"on"`, `"minSynchronousCommit":"eventually"`, 1),
		"zero sync standbys":     strings.Replace(validPolicyJSON, `"minSyncStandbys":1`, `"minSyncStandbys":0`, 1),
		"unknown field":          strings.Replace(validPolicyJSON, `"minDistinctFailureDomains":1}`, `"minDistinctFailureDomains":1,"extra":true}`, 1),
		"not json":               `nope`,
		"trailing second doc":    validPolicyJSON + `{}`,
		"missing system id":      strings.Replace(validPolicyJSON, `"expectedSystemIdentifier":"7300000000000000001",`, ``, 1),
		"empty system id":        strings.Replace(validPolicyJSON, `"expectedSystemIdentifier":"7300000000000000001"`, `"expectedSystemIdentifier":""`, 1),
		"missing database":       strings.Replace(validPolicyJSON, `"expectedDatabase":"portablefs",`, ``, 1),
		"missing domain mapping": strings.Replace(validPolicyJSON, `"standbyFailureDomains":{"standby_a":"zone-a","standby_b":"zone-b"},`, ``, 1),
		"empty domain mapping":   strings.Replace(validPolicyJSON, `{"standby_a":"zone-a","standby_b":"zone-b"}`, `{}`, 1),
		"empty domain value":     strings.Replace(validPolicyJSON, `"standby_a":"zone-a"`, `"standby_a":""`, 1),
		"zero distinct domains":  strings.Replace(validPolicyJSON, `"minDistinctFailureDomains":1`, `"minDistinctFailureDomains":0`, 1),
		"domains exceed mapping": strings.Replace(validPolicyJSON, `"minDistinctFailureDomains":1`, `"minDistinctFailureDomains":3`, 1),
		"non-ascii domain":       strings.Replace(validPolicyJSON, `"zone-a"`, `"zóne"`, 1),
		"quote in domain":        strings.Replace(validPolicyJSON, `"zone-a"`, `"zo\"ne"`, 1),
	}
	for name, raw := range cases {
		if _, err := ParsePolicy(raw); err == nil {
			t.Fatalf("%s: policy %q must be rejected", name, raw)
		}
	}
}

// TestHashIsCanonicalDeterministicJSON: the hash covers actual deterministic
// JSON — fixed field order, name-sorted domain pairs — and is insensitive to
// source formatting/key order, sensitive to every value.
func TestHashIsCanonicalDeterministicJSON(t *testing.T) {
	a, err := ParsePolicy(validPolicyJSON)
	if err != nil {
		t.Fatal(err)
	}
	// Same policy, different source formatting and key order.
	reordered := `{
	  "standbyFailureDomains": {"standby_b":"zone-b", "standby_a":"zone-a"},
	  "minDistinctFailureDomains": 1,
	  "minSyncStandbys": 1,
	  "minSynchronousCommit": "on",
	  "expectedDatabase": "portablefs",
	  "expectedSystemIdentifier": "7300000000000000001",
	  "v": 1
	}`
	b, err := ParsePolicy(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash() != b.Hash() {
		t.Fatal("formatting/key order changed the canonical hash")
	}
	if len(a.Hash()) != 64 {
		t.Fatalf("hash must be sha256 hex, got %q", a.Hash())
	}
	c := basePolicy()
	c.StandbyFailureDomains = map[string]string{"standby_a": "zone-a", "standby_b": "zone-OTHER"}
	if c.Hash() == a.Hash() {
		t.Fatal("a different domain mapping must hash differently")
	}
	d := basePolicy()
	d.MinDistinctFailureDomains = 1
	d.MinSyncStandbys = 2
	if d.Hash() == a.Hash() {
		t.Fatal("different minimums must hash differently")
	}
}

func TestEvaluateAcceptsHealthySynchronousPrimary(t *testing.T) {
	summary, err := Evaluate(basePolicy(), goodFacts())
	if err != nil {
		t.Fatalf("healthy facts rejected: %v", err)
	}
	// The success summary states what is DB-observed versus operator-attested.
	for _, fragment := range []string{"DB-observed", "operator-attested", "standby_a", "zone-a"} {
		if !strings.Contains(summary, fragment) {
			t.Fatalf("summary %q must mention %q", summary, fragment)
		}
	}
}

func TestCommitStrengthRatchet(t *testing.T) {
	facts := goodFacts()
	facts["synchronousCommit"] = "remote_apply"
	if _, err := Evaluate(basePolicy(), facts); err != nil {
		t.Fatalf("remote_apply must satisfy an on policy: %v", err)
	}

	policy := basePolicy()
	policy.MinSynchronousCommit = "remote_apply"
	facts = goodFacts() // synchronous_commit=on
	_, err := Evaluate(policy, facts)
	if err == nil || !strings.Contains(err.Error(), "remote_apply") {
		t.Fatalf("on must never satisfy a remote_apply policy, got %v", err)
	}

	facts["synchronousCommit"] = "remote_apply"
	if _, err := Evaluate(policy, facts); err != nil {
		t.Fatalf("remote_apply facts must satisfy a remote_apply policy: %v", err)
	}
}

func TestEvaluateRejectsEachViolation(t *testing.T) {
	mutate := map[string]func(map[string]any){
		"weak synchronous_commit": func(f map[string]any) { f["synchronousCommit"] = "local" },
		"empty standby names":     func(f map[string]any) { f["synchronousStandbyNames"] = "  " },
		"in recovery":             func(f map[string]any) { f["inRecovery"] = true },
		"read only":               func(f map[string]any) { f["transactionReadOnly"] = "on" },
		"fsync off":               func(f map[string]any) { f["fsync"] = "off" },
		"full_page_writes":        func(f map[string]any) { f["fullPageWrites"] = "off" },
		"replication hidden":      func(f map[string]any) { f["replicationVisible"] = false },
		"foreign system id":       func(f map[string]any) { f["systemIdentifier"] = "999" },
		"foreign database":        func(f map[string]any) { f["database"] = "lookalike" },
		"no live sync standbys": func(f map[string]any) {
			f["standbys"] = []any{
				map[string]any{"applicationName": "standby_a", "state": "streaming", "syncState": "async"},
			}
		},
		"sync standby not streaming": func(f map[string]any) {
			f["standbys"] = []any{
				map[string]any{"applicationName": "standby_a", "state": "catchup", "syncState": "sync"},
			}
		},
	}
	for name, apply := range mutate {
		facts := goodFacts()
		apply(facts)
		if _, err := Evaluate(basePolicy(), facts); err == nil {
			t.Fatalf("%s: violation must fail the policy", name)
		}
	}
}

// TestEvaluateStrictFactTyping: missing or mistyped facts are violations,
// never silently defaulted passes.
func TestEvaluateStrictFactTyping(t *testing.T) {
	mutate := map[string]func(map[string]any){
		"missing synchronousCommit": func(f map[string]any) { delete(f, "synchronousCommit") },
		"numeric fsync":             func(f map[string]any) { f["fsync"] = 1 },
		"string inRecovery":         func(f map[string]any) { f["inRecovery"] = "false" },
		"missing standbys":          func(f map[string]any) { delete(f, "standbys") },
		"standbys not array":        func(f map[string]any) { f["standbys"] = "none" },
		"standby row not object":    func(f map[string]any) { f["standbys"] = []any{"row"} },
		"standby name not string": func(f map[string]any) {
			f["standbys"] = []any{map[string]any{"applicationName": 7, "state": "streaming", "syncState": "sync"}}
		},
	}
	for name, apply := range mutate {
		facts := goodFacts()
		apply(facts)
		if _, err := Evaluate(basePolicy(), facts); err == nil {
			t.Fatalf("%s: strict typing must fail the policy", name)
		}
	}
	// A stripped-null key on an ASYNC row is legal evidence (the row simply
	// cannot count as synchronous).
	facts := goodFacts()
	facts["standbys"] = []any{
		map[string]any{"applicationName": "standby_a", "state": "streaming", "syncState": "sync"},
		map[string]any{"applicationName": "archiver", "state": "streaming"},
	}
	if _, err := Evaluate(basePolicy(), facts); err != nil {
		t.Fatalf("an async row without syncState must not fail evidence typing: %v", err)
	}
}

// TestEvaluateDistinctFailureDomains: live synchronous standbys must cover
// the required number of DISTINCT operator-attested domains; unattested
// names and same-domain pairs do not count.
func TestEvaluateDistinctFailureDomains(t *testing.T) {
	policy := basePolicy()
	policy.MinDistinctFailureDomains = 2
	if _, err := Evaluate(policy, goodFacts()); err != nil {
		t.Fatalf("two live standbys in two attested domains must satisfy 2 domains: %v", err)
	}

	// Both live sync standbys in the SAME attested domain: only one domain.
	samePolicy := basePolicy()
	samePolicy.StandbyFailureDomains = map[string]string{
		"standby_a": "zone-a",
		"standby_b": "zone-a",
	}
	samePolicy.MinDistinctFailureDomains = 2
	_, err := Evaluate(samePolicy, goodFacts())
	if err == nil || !strings.Contains(err.Error(), "distinct operator-attested failure domain") {
		t.Fatalf("same-domain standbys must not satisfy 2 distinct domains, got %v", err)
	}

	// A live synchronous standby whose name is NOT attested counts toward
	// nothing, and the refusal says so.
	unattested := basePolicy()
	unattested.StandbyFailureDomains = map[string]string{"standby_a": "zone-a"}
	unattested.MinDistinctFailureDomains = 2
	_, err = Evaluate(unattested, goodFacts())
	if err == nil || !strings.Contains(err.Error(), "NOT in the operator-attested domain mapping") {
		t.Fatalf("unattested live standby must be reported, got %v", err)
	}
}

func TestEvaluateReportsEveryViolationAtOnce(t *testing.T) {
	facts := goodFacts()
	facts["synchronousCommit"] = "off"
	facts["synchronousStandbyNames"] = ""
	facts["standbys"] = []any{}
	_, err := Evaluate(basePolicy(), facts)
	if err == nil {
		t.Fatal("multiple violations must fail")
	}
	for _, fragment := range []string{"synchronous_commit", "synchronous_standby_names", "sync/quorum"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error must report %q, got %v", fragment, err)
		}
	}
}
