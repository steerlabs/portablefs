// Package hapolicy evaluates the journal database's VERIFIABLE durability
// evidence against a small, versioned, operator-authored policy.
//
// The policy is the readiness gate — never prose. Every requirement is
// checked fact by fact against pfj.durability_facts() (migration
// 011_journal_hardening, reading pfm.durability_evidence), with STRICT
// typing: a missing or mistyped fact is a violation, never a silently
// defaulted pass.
//
// WHAT IS OBSERVED VERSUS ATTESTED — stated honestly:
//
//   - DB-OBSERVED: the cluster's system identifier and database name, fsync,
//     full_page_writes, recovery/read-write state, synchronous_commit,
//     synchronous_standby_names, and the LIVE pg_stat_replication rows
//     (application_name, state, sync_state). These are live database facts.
//   - OPERATOR-ATTESTED: which standby application_name belongs to which
//     failure domain (StandbyFailureDomains). PostgreSQL cannot see racks or
//     zones; the operator attests the mapping, and the policy verifies the
//     LIVE synchronous standbys against it. A live sync/quorum standby whose
//     name is not in the attested mapping proves no distinct domain and does
//     not count.
//
// COMMIT-STRENGTH RATCHET: remote_apply satisfies a policy requiring on;
// on NEVER satisfies a policy requiring remote_apply.
//
// The canonical policy hash is ACTUAL deterministic JSON (fixed field order,
// domain mapping as a name-sorted array of pairs, no HTML escaping) — the
// TypeScript manager computes the identical bytes.
package hapolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PolicyVersion is the only supported policy schema version.
const PolicyVersion = 1

// asciiSafePattern keeps every hashed string byte-identical across the Go
// and TypeScript canonical encoders (no quotes, no backslashes, no control
// characters, ASCII only).
var asciiSafePattern = regexp.MustCompile(`^[ !#-[\]-~]*$`)

// Policy is the operator's structured HA requirement for the managed journal
// database (VCS_JOURNAL_HA_POLICY_JSON, issued by the manager from
// PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON).
type Policy struct {
	V int `json:"v"`
	// ExpectedSystemIdentifier pins pg_control_system().system_identifier.
	// REQUIRED: evidence that cannot name the exact cluster proves nothing.
	ExpectedSystemIdentifier string `json:"expectedSystemIdentifier"`
	// ExpectedDatabase pins current_database(). REQUIRED.
	ExpectedDatabase string `json:"expectedDatabase"`
	// MinSynchronousCommit is the weakest acceptable synchronous_commit:
	// "on" or "remote_apply". remote_apply evidence satisfies an "on" policy;
	// "on" evidence never satisfies a "remote_apply" policy.
	MinSynchronousCommit string `json:"minSynchronousCommit"`
	// MinSyncStandbys is the minimum number of LIVE streaming standbys in
	// sync/quorum state. At least 1.
	MinSyncStandbys int `json:"minSyncStandbys"`
	// StandbyFailureDomains is the OPERATOR-ATTESTED mapping of eligible
	// standby application_names to failure domains. REQUIRED nonempty; a
	// live synchronous standby not named here counts toward nothing.
	StandbyFailureDomains map[string]string `json:"standbyFailureDomains"`
	// MinDistinctFailureDomains is the minimum number of DISTINCT attested
	// failure domains that must be covered by currently LIVE sync/quorum
	// standbys. At least 1.
	MinDistinctFailureDomains int `json:"minDistinctFailureDomains"`
}

// ParsePolicy decodes and validates one strict policy JSON document.
func ParsePolicy(raw string) (Policy, error) {
	var policy Policy
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("hapolicy: policy is not strict JSON: %w", err)
	}
	if decoder.More() {
		return Policy{}, fmt.Errorf("hapolicy: policy must be exactly one JSON object")
	}
	if policy.V != PolicyVersion {
		return Policy{}, fmt.Errorf("hapolicy: unsupported policy version %d (this build supports %d)", policy.V, PolicyVersion)
	}
	requireASCII := func(name, value string) error {
		if !asciiSafePattern.MatchString(value) {
			return fmt.Errorf("hapolicy: %s must be printable ASCII without quotes or backslashes (it participates in the cross-language canonical hash)", name)
		}
		return nil
	}
	if policy.ExpectedSystemIdentifier == "" {
		return Policy{}, fmt.Errorf("hapolicy: expectedSystemIdentifier is required (pin the exact cluster; unpinned evidence proves nothing)")
	}
	if err := requireASCII("expectedSystemIdentifier", policy.ExpectedSystemIdentifier); err != nil {
		return Policy{}, err
	}
	if policy.ExpectedDatabase == "" {
		return Policy{}, fmt.Errorf("hapolicy: expectedDatabase is required (pin the exact database)")
	}
	if err := requireASCII("expectedDatabase", policy.ExpectedDatabase); err != nil {
		return Policy{}, err
	}
	if policy.MinSynchronousCommit != "on" && policy.MinSynchronousCommit != "remote_apply" {
		return Policy{}, fmt.Errorf("hapolicy: minSynchronousCommit must be on or remote_apply, got %q", policy.MinSynchronousCommit)
	}
	if policy.MinSyncStandbys < 1 {
		return Policy{}, fmt.Errorf("hapolicy: minSyncStandbys must be >= 1 (a policy accepting zero synchronous standbys is not HA)")
	}
	if len(policy.StandbyFailureDomains) == 0 {
		return Policy{}, fmt.Errorf("hapolicy: standbyFailureDomains is required: attest which standby application_names live in which failure domains (PostgreSQL cannot observe topology; unattested standbys prove no distinct domain)")
	}
	for name, domain := range policy.StandbyFailureDomains {
		if name == "" || domain == "" {
			return Policy{}, fmt.Errorf("hapolicy: standbyFailureDomains entries must map a nonempty application_name to a nonempty domain")
		}
		if err := requireASCII("standbyFailureDomains name", name); err != nil {
			return Policy{}, err
		}
		if err := requireASCII("standbyFailureDomains domain", domain); err != nil {
			return Policy{}, err
		}
	}
	if policy.MinDistinctFailureDomains < 1 {
		return Policy{}, fmt.Errorf("hapolicy: minDistinctFailureDomains must be >= 1")
	}
	if policy.MinDistinctFailureDomains > len(policy.StandbyFailureDomains) {
		return Policy{}, fmt.Errorf("hapolicy: minDistinctFailureDomains %d exceeds the %d attested standby(s)", policy.MinDistinctFailureDomains, len(policy.StandbyFailureDomains))
	}
	return policy, nil
}

// canonicalPolicy is the deterministic hash form: fixed field order and the
// domain mapping as a name-sorted array of [name, domain] pairs.
type canonicalPolicy struct {
	V                         int         `json:"v"`
	ExpectedSystemIdentifier  string      `json:"expectedSystemIdentifier"`
	ExpectedDatabase          string      `json:"expectedDatabase"`
	MinSynchronousCommit      string      `json:"minSynchronousCommit"`
	MinSyncStandbys           int         `json:"minSyncStandbys"`
	MinDistinctFailureDomains int         `json:"minDistinctFailureDomains"`
	StandbyFailureDomains     [][2]string `json:"standbyFailureDomains"`
}

// Hash is the canonical policy hash reported through bootstrap/readiness so
// the manager can verify the child evaluated EXACTLY the policy it issued.
// Deterministic JSON: fixed field order, name-sorted domain pairs, no HTML
// escaping (matching JSON.stringify byte for byte on the validated ASCII
// field contents).
func (p Policy) Hash() string {
	names := make([]string, 0, len(p.StandbyFailureDomains))
	for name := range p.StandbyFailureDomains {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([][2]string, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, [2]string{name, p.StandbyFailureDomains[name]})
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(canonicalPolicy{
		V:                         p.V,
		ExpectedSystemIdentifier:  p.ExpectedSystemIdentifier,
		ExpectedDatabase:          p.ExpectedDatabase,
		MinSynchronousCommit:      p.MinSynchronousCommit,
		MinSyncStandbys:           p.MinSyncStandbys,
		MinDistinctFailureDomains: p.MinDistinctFailureDomains,
		StandbyFailureDomains:     pairs,
	}); err != nil {
		// Marshalling a validated policy cannot fail; keep the impossible
		// path loud rather than silent.
		panic(fmt.Sprintf("hapolicy: canonical encode failed: %v", err))
	}
	canonical := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// commitStrength orders synchronous_commit levels for the ratchet. Only
// levels that make a commit durable on a synchronous standby count.
func commitStrength(level string) int {
	switch level {
	case "on":
		return 1
	case "remote_apply":
		return 2
	default:
		return 0
	}
}

// LiveStandby is one DB-observed replication row (strictly typed).
type LiveStandby struct {
	ApplicationName string
	State           string
	SyncState       string
}

// Evaluate checks one durability-facts snapshot against the policy with
// STRICT fact typing. Every violated requirement is reported (not just the
// first). On success it returns a one-line summary naming the observed live
// synchronous standbys and the attested domains they cover.
func Evaluate(policy Policy, facts map[string]any) (string, error) {
	var violations []string
	report := func(format string, args ...any) {
		violations = append(violations, fmt.Sprintf(format, args...))
	}
	stringFact := func(key string) string {
		value, ok := facts[key].(string)
		if !ok {
			report("fact %q is missing or not a string (strict typed evidence required)", key)
			return ""
		}
		return value
	}
	boolFact := func(key string) bool {
		value, ok := facts[key].(bool)
		if !ok {
			report("fact %q is missing or not a boolean (strict typed evidence required)", key)
			return false
		}
		return value
	}

	if got := stringFact("systemIdentifier"); got != policy.ExpectedSystemIdentifier {
		report("system identifier is %q, policy pins %q (DB-observed)", got, policy.ExpectedSystemIdentifier)
	}
	if got := stringFact("database"); got != policy.ExpectedDatabase {
		report("database is %q, policy pins %q (DB-observed)", got, policy.ExpectedDatabase)
	}
	if got := stringFact("fsync"); got != "on" {
		report("fsync is %q, must be on", got)
	}
	if got := stringFact("fullPageWrites"); got != "on" {
		report("full_page_writes is %q, must be on", got)
	}
	if inRecovery := boolFact("inRecovery"); inRecovery {
		report("database is in recovery (a replica); the journal requires the primary")
	}
	if got := stringFact("transactionReadOnly"); got != "off" {
		report("transactions are read-only (%q); the journal requires a read-write primary", got)
	}
	commit := stringFact("synchronousCommit")
	if commitStrength(commit) < commitStrength(policy.MinSynchronousCommit) {
		report("synchronous_commit is %q, policy requires at least %q (remote_apply satisfies on; on never satisfies remote_apply)",
			commit, policy.MinSynchronousCommit)
	}
	if names := stringFact("synchronousStandbyNames"); strings.TrimSpace(names) == "" {
		report("synchronous_standby_names is empty: commits are not replicated synchronously (enable synchronous replication; e.g. Patroni synchronous_mode defaults to OFF)")
	}
	if visible := boolFact("replicationVisible"); !visible {
		report("pg_stat_replication is not visible to the journal role; standby liveness cannot be verified")
	}

	standbys, standbyErr := parseStandbys(facts["standbys"])
	if standbyErr != nil {
		report("%v", standbyErr)
	}
	liveSync := make([]LiveStandby, 0, len(standbys))
	for _, standby := range standbys {
		if standby.State == "streaming" && (standby.SyncState == "sync" || standby.SyncState == "quorum") {
			liveSync = append(liveSync, standby)
		}
	}
	if len(liveSync) < policy.MinSyncStandbys {
		report("%d live streaming sync/quorum standby(s) observed, policy requires >= %d", len(liveSync), policy.MinSyncStandbys)
	}
	domains := map[string]string{}
	var unattested []string
	var covered []string
	for _, standby := range liveSync {
		domain, attested := policy.StandbyFailureDomains[standby.ApplicationName]
		if !attested {
			unattested = append(unattested, standby.ApplicationName)
			continue
		}
		if _, seen := domains[domain]; !seen {
			domains[domain] = standby.ApplicationName
		}
		covered = append(covered, fmt.Sprintf("%s(%s→%s)", standby.ApplicationName, standby.SyncState, domain))
	}
	if len(domains) < policy.MinDistinctFailureDomains {
		sort.Strings(unattested)
		extra := ""
		if len(unattested) > 0 {
			extra = fmt.Sprintf("; live synchronous standbys %v are NOT in the operator-attested domain mapping and prove no distinct domain", unattested)
		}
		report("live synchronous standbys cover %d distinct operator-attested failure domain(s), policy requires >= %d%s",
			len(domains), policy.MinDistinctFailureDomains, extra)
	}

	if len(violations) > 0 {
		return "", fmt.Errorf("hapolicy: journal durability evidence violates the HA policy: %s", strings.Join(violations, "; "))
	}
	sort.Strings(covered)
	summary := fmt.Sprintf(
		"synchronous_commit=%s; %d live sync/quorum standby(s) [DB-observed] covering %d distinct failure domain(s) [operator-attested]: %s",
		commit, len(liveSync), len(domains), strings.Join(covered, ", "))
	return summary, nil
}

// parseStandbys strictly types the DB-observed replication rows. A key may
// be ABSENT (pfm.durability_evidence strips nulls; such a row can never
// count as a live synchronous standby), but a present key of the wrong type
// is a hard evidence error.
func parseStandbys(value any) ([]LiveStandby, error) {
	rows, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("fact %q is missing or not an array (strict typed evidence required)", "standbys")
	}
	standbys := make([]LiveStandby, 0, len(rows))
	for index, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("standbys[%d] is not an object (strict typed evidence required)", index)
		}
		standby := LiveStandby{}
		for key, target := range map[string]*string{
			"applicationName": &standby.ApplicationName,
			"state":           &standby.State,
			"syncState":       &standby.SyncState,
		} {
			if fieldValue, present := row[key]; present {
				typed, ok := fieldValue.(string)
				if !ok {
					return nil, fmt.Errorf("standbys[%d].%s is not a string (strict typed evidence required)", index, key)
				}
				*target = typed
			}
		}
		standbys = append(standbys, standby)
	}
	return standbys, nil
}
