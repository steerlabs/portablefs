package remotejournal

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func leaseFactsLog(db *fakeJournalDB) *Log {
	return &Log{
		pool: db,
		life: context.Background(),
		cfg: Config{
			TenantID:            "tenant-1",
			VolumeID:            "volume-1",
			Branch:              "main",
			AuthorityRuntimeID:  "runtime-1",
			AuthorityCapability: "authority-capability-1",
		},
		managerEpoch: 7,
		runtimeSeq:   11,
		capability:   "authority-capability-1",
	}
}

// TestAuthorityLeaseFactsCallsCapabilityBoundSeam: the read goes through
// pfj.authority_lease_facts with the EXACT binding arguments (raw capability
// last), and the answer's claim facts decode exactly.
func TestAuthorityLeaseFactsCallsCapabilityBoundSeam(t *testing.T) {
	// The SQL seam emits every BIGINT as decimal TEXT (verify_authority_binding
	// + compat_011_authority_lease_facts).
	db := &fakeJournalDB{response: []byte(`{
		"managed": true, "current": true,
		"tenantKey": "t:tenant-1",
		"managerEpoch": "7", "managerRuntimeId": "pfmgr_live",
		"authorityRuntimeSeq": "11", "authorityRuntimeId": "runtime-1",
		"authorityInstanceId": "pfvcs_1",
		"dbTimeMs": "1000000", "expiresAtDbMs": "1030000"
	}`)}
	l := leaseFactsLog(db)
	facts, err := l.AuthorityLeaseFacts(context.Background())
	if err != nil {
		t.Fatalf("AuthorityLeaseFacts: %v", err)
	}
	if !strings.Contains(db.query, "pfj.authority_lease_facts") {
		t.Fatalf("query = %q", db.query)
	}
	want := []any{"tenant-1", "volume-1", "main", int64(7), int64(11), "runtime-1", "authority-capability-1"}
	if fmt.Sprint(db.args) != fmt.Sprint(want) {
		t.Fatalf("args = %v, want %v", db.args, want)
	}
	if !facts.Current || facts.DBTimeMs != 1_000_000 || facts.ExpiresAtDbMs != 1_030_000 ||
		facts.ManagerEpoch != "7" || facts.AuthorityRuntimeSeq != "11" ||
		facts.AuthorityRuntimeID != "runtime-1" || facts.AuthorityInstanceID != "pfvcs_1" {
		t.Fatalf("facts = %+v", facts)
	}
}

// TestAuthorityLeaseFactsPF001IsDefinitiveNotCurrent: a superseded/expired/
// fenced binding (PF001) is a definitive Current=false answer, never an
// ambiguous error.
func TestAuthorityLeaseFactsPF001IsDefinitiveNotCurrent(t *testing.T) {
	db := &fakeJournalDB{err: &pgconn.PgError{Code: "PF001", Message: "manager binding is no longer current"}}
	l := leaseFactsLog(db)
	facts, err := l.AuthorityLeaseFacts(context.Background())
	if err != nil {
		t.Fatalf("PF001 must be a definitive answer, got error %v", err)
	}
	if facts.Current {
		t.Fatalf("facts = %+v, want Current=false", facts)
	}
}

// TestAuthorityLeaseFactsAmbiguityIsAnError: transport failures and
// incomplete/foreign-shaped answers are ERRORS (the guard must not extend
// anything from them).
func TestAuthorityLeaseFactsAmbiguityIsAnError(t *testing.T) {
	cases := map[string]*fakeJournalDB{
		"transport error": {err: fmt.Errorf("connection reset")},
		"acl revoked":     {err: &pgconn.PgError{Code: "42501", Message: "permission denied for function authority_lease_facts"}},
		"unmanaged shape": {response: []byte(`{"managed": false, "dbTimeMs": "1"}`)},
		"missing expiry":  {response: []byte(`{"managed": true, "current": true, "managerEpoch": "7", "authorityRuntimeSeq": "11", "dbTimeMs": "1000000"}`)},
		"not json":        {response: []byte(`nonsense`)},
	}
	for name, db := range cases {
		l := leaseFactsLog(db)
		if _, err := l.AuthorityLeaseFacts(context.Background()); err == nil {
			t.Fatalf("%s: must be an error", name)
		}
	}
}

// TestAuthorityLeaseFactsReadOnlyRefused: a read-only journal handle holds
// no binding to prove.
func TestAuthorityLeaseFactsReadOnlyRefused(t *testing.T) {
	l := leaseFactsLog(&fakeJournalDB{})
	l.readOnly = true
	if _, err := l.AuthorityLeaseFacts(context.Background()); err == nil {
		t.Fatal("read-only lease facts must be refused")
	}
}
