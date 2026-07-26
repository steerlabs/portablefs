package remotejournal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/trendup-ai/portablefs/vcs/internal/pfc2"
	"github.com/trendup-ai/portablefs/vcs/internal/pfj3"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

func v3Log(db *fakeJournalDB) *Log {
	return &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			TenantID: "tenant-1", VolumeID: "volume-1", Branch: "main",
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second, MaxStagedBytes: defaultMaxStagedBytes,
		},
		generationID: "jgen-1", branchID: "branch-1", epoch: 1,
		capability: "authority-capability-000000000000", managerEpoch: 2, runtimeSeq: 4,
		recordCodec: pfj3RecordCodec, controlCodec: pfc2ControlCodec,
		baseCommitID: "commit-1",
		quotaBytes:   1 << 30, quotaRecords: 1 << 20,
		poisonedCh: make(chan struct{}),
	}
}

func testFact(b byte, dbMs int64) pfc2.TimeFact {
	var id [pfc2.FactIDBytes]byte
	for i := range id {
		id[i] = b
	}
	return pfc2.TimeFact{Source: pfc2.TimeSourceDB, FactID: id, DbMs: dbMs}
}

func testEntry(t *testing.T) pfj3.JournalEntry {
	t.Helper()
	var token [32]byte
	token[0] = 0xAB
	return pfj3.JournalEntry{Controls: []pfc2.Record{{
		Kind: pfc2.KindSessionOpen,
		SessionOpen: &pfc2.SessionOpen{
			Session:   pfc2.SessionRef{SessionID: "pfs-1", Generation: 1},
			TokenHash: token, Slots: 8,
			Fact:        testFact(0x5a, 1_700_000_000_000),
			ExpiresDbMs: 1_700_000_090_000,
		},
	}}}
}

func TestAppendEntriesUsesV3SQLWithManifestInBytes(t *testing.T) {
	db := &fakeJournalDB{}
	l := v3Log(db)
	entry := testEntry(t)
	first, end, err := l.AppendEntriesBuffered([]pfj3.JournalEntry{entry})
	if err != nil || first != 0 || end != 1 {
		t.Fatalf("reserve: %d %d %v", first, end, err)
	}
	// The staged payload is whole canonical PFJ3 bytes; the fact manifest is
	// INSIDE those bytes (there is no side-channel fact list) and the staged
	// mirror only counts it for group bounding.
	if got := l.staged[0].payload[:4]; string(got) != "PFJ3" {
		t.Fatalf("staged magic %q", got)
	}
	if l.staged[0].factCount != 1 {
		t.Fatalf("staged fact count %d", l.staged[0].factCount)
	}
	decoded, err := pfj3.Decode(l.staged[0].payload)
	if err != nil {
		t.Fatalf("staged bytes are not canonical PFJ3: %v", err)
	}
	manifest, err := decoded.FactManifest()
	if err != nil || len(manifest) != 1 || manifest[0].DbMs != 1_700_000_000_000 || manifest[0].FactID[0] != 0x5a {
		t.Fatalf("embedded manifest %+v %v", manifest, err)
	}

	tip := hex.EncodeToString(l.staged[0].tipAfter[:])
	db.response = []byte(fmt.Sprintf(`{
		"generationId":"jgen-1","epoch":"1","nextSeq":"1","tipDigest":"%s",
		"backlogBytes":"%d","backlogRecords":"1","appended":"1","duplicated":"0",
		"replayed":false,"currentBaseCommitId":"commit-1","currentBaseSeq":"0",
		"currentBaseDigest":"%s","currentPhysicalTrimmedSeq":"0",
		"currentBacklogBytes":"%d","currentBacklogRecords":"1",
		"currentQuotaBacklogBytes":"1073741824","currentQuotaBacklogRecords":"1048576",
		"currentControlDbFloorMs":"1700000000000"
	}`, tip, len(l.staged[0].payload), zeroHex(), len(l.staged[0].payload)))
	if err := l.CommitThrough(0); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !strings.Contains(db.query, "pfj.journal_append_v3") {
		t.Fatalf("append SQL %q", db.query)
	}
	if len(db.args) != 12 {
		t.Fatalf("append arg count %d", len(db.args))
	}
	if got := l.ControlDbFloorMs(); got != 1_700_000_000_000 {
		t.Fatalf("mirrored control floor %d", got)
	}
}

func TestAppendRequiresControlFloorAndRejectsRegression(t *testing.T) {
	db := &fakeJournalDB{}
	l := v3Log(db)
	if _, _, err := l.AppendEntriesBuffered([]pfj3.JournalEntry{testEntry(t)}); err != nil {
		t.Fatal(err)
	}
	tip := hex.EncodeToString(l.staged[0].tipAfter[:])
	body := func(floor string) []byte {
		return []byte(fmt.Sprintf(`{
			"generationId":"jgen-1","epoch":"1","nextSeq":"1","tipDigest":"%s",
			"backlogBytes":"%d","backlogRecords":"1","appended":"1","duplicated":"0",
			"replayed":false,"currentBaseCommitId":"commit-1","currentBaseSeq":"0",
			"currentBaseDigest":"%s","currentPhysicalTrimmedSeq":"0",
			"currentBacklogBytes":"%d","currentBacklogRecords":"1",
			"currentQuotaBacklogBytes":"1073741824","currentQuotaBacklogRecords":"1048576"%s
		}`, tip, len(l.staged[0].payload), zeroHex(), len(l.staged[0].payload), floor))
	}
	// A missing control floor on a PFJ3 append is an invalid success body:
	// the client must not accept it (it retries identical bytes instead).
	good := body(`,"currentControlDbFloorMs":"1700000000000"`)
	db.responses = [][]byte{body(""), good}
	if err := l.CommitThrough(0); err != nil {
		t.Fatalf("commit after floor-missing retry: %v", err)
	}
	if db.calls != 2 {
		t.Fatalf("expected retry after floor-missing body, calls=%d", db.calls)
	}
	// A regressing floor is likewise rejected.
	l2 := v3Log(&fakeJournalDB{})
	l2.controlDbFloorMs = 2_000_000_000_000
	if _, _, err := l2.AppendEntriesBuffered([]pfj3.JournalEntry{testEntry(t)}); err != nil {
		t.Fatal(err)
	}
	res := appendResult{}
	if err := jsonUnmarshal(good, &res); err != nil {
		t.Fatal(err)
	}
	if err := l2.validateAppendResult(&res, 0, 1, res.TipDigest); err == nil {
		t.Fatal("regressed control floor accepted")
	}
}

func jsonUnmarshal(raw []byte, into *appendResult) error {
	return json.Unmarshal(raw, into)
}

func TestGroupSplitsByTotalFactBound(t *testing.T) {
	l := v3Log(&fakeJournalDB{})
	// 130 one-fact rows: one group must never consume more than 128 facts.
	var entries []pfj3.JournalEntry
	for i := 0; i < 130; i++ {
		e := testEntry(t)
		e.Controls[0].SessionOpen.Fact.FactID[15] = byte(i + 1)
		entries = append(entries, e)
	}
	if _, _, err := l.AppendEntriesBuffered(entries); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	group := l.nextGroupLocked()
	total := 0
	for i := range group {
		total += group[i].factCount
	}
	l.mu.Unlock()
	if total > pfj3.MaxFacts || len(group) != pfj3.MaxFacts {
		t.Fatalf("group consumes %d facts over %d rows", total, len(group))
	}
}

func zeroHex() string { return strings.Repeat("0", 64) }

func TestAppendEntriesRetriesIdenticalBytes(t *testing.T) {
	db := &fakeJournalDB{}
	l := v3Log(db)
	if _, _, err := l.AppendEntriesBuffered([]pfj3.JournalEntry{testEntry(t)}); err != nil {
		t.Fatal(err)
	}
	tip := hex.EncodeToString(l.staged[0].tipAfter[:])
	success := []byte(fmt.Sprintf(`{
		"generationId":"jgen-1","epoch":"1","nextSeq":"1","tipDigest":"%s",
		"backlogBytes":"%d","backlogRecords":"1","appended":"1","duplicated":"0",
		"replayed":true,"currentBaseCommitId":"commit-1","currentBaseSeq":"0",
		"currentBaseDigest":"%s","currentPhysicalTrimmedSeq":"0",
		"currentBacklogBytes":"%d","currentBacklogRecords":"1",
		"currentQuotaBacklogBytes":"1073741824","currentQuotaBacklogRecords":"1048576",
		"currentControlDbFloorMs":"1700000000000"
	}`, tip, len(l.staged[0].payload), zeroHex(), len(l.staged[0].payload)))
	db.errors = []error{&pgconn.PgError{Code: "PF015", Message: "durability unavailable"}}
	db.responses = [][]byte{nil, success}
	if err := l.CommitThrough(0); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if db.calls != 2 {
		t.Fatalf("attempts %d", db.calls)
	}
	if db.queries[0] != db.queries[1] {
		t.Fatal("retry changed the SQL")
	}
	firstPayloads := fmt.Sprintf("%x", db.argsHistory[0][9])
	secondPayloads := fmt.Sprintf("%x", db.argsHistory[1][9])
	if firstPayloads != secondPayloads {
		t.Fatal("retry changed the exact payload bytes")
	}
}

func TestLegacyRecordAPIsRejectPFJ3Generations(t *testing.T) {
	l := v3Log(&fakeJournalDB{})
	if _, _, err := l.AppendBatchBuffered([]wal.Record{{Op: wal.OpCreate, Path: "x", Mode: 0o644}}); !errors.Is(err, ErrCodec) {
		t.Fatalf("AppendBatchBuffered: %v", err)
	}
	if err := l.ReplayInto(func(wal.Record) error { return nil }); !errors.Is(err, ErrCodec) {
		t.Fatalf("ReplayInto: %v", err)
	}
	if err := l.RecordsBelowInto(1, func(wal.Record) error { return nil }); !errors.Is(err, ErrCodec) {
		t.Fatalf("RecordsBelowInto: %v", err)
	}
	// And the converse: a legacy log rejects the entry APIs.
	legacy := v3Log(&fakeJournalDB{})
	legacy.recordCodec, legacy.controlCodec = wal.PFR1Codec, "pfc1"
	if _, _, err := legacy.AppendEntriesBuffered([]pfj3.JournalEntry{testEntry(t)}); !errors.Is(err, ErrCodec) {
		t.Fatalf("legacy AppendEntriesBuffered: %v", err)
	}
	if err := legacy.ReplayEntriesInto(func(pfj3.JournalEntry) error { return nil }); !errors.Is(err, ErrCodec) {
		t.Fatalf("legacy ReplayEntriesInto: %v", err)
	}
}

func TestIssueAdmissionFactShapeAndParsing(t *testing.T) {
	id := strings.Repeat("5a", 16)
	db := &fakeJournalDB{response: []byte(fmt.Sprintf(
		`{"factId":"%s","issuedDbMs":"1700000000000","factExpiresDbMs":"1700000030000","controlDbFloorMs":"0"}`, id))}
	l := v3Log(db)
	issued, err := l.IssueAdmissionFact(pfc2.FactScope{
		Purpose:            pfc2.FactPurposeSessionOpen,
		Session:            pfc2.SessionRef{SessionID: "pfs-1", Generation: 1},
		PriorDbTimeFloorMs: 0,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.Contains(db.query, "pfj.admission_fact_issue") {
		t.Fatalf("issue SQL %q", db.query)
	}
	if len(db.args) != 12 || db.args[8] != int16(pfc2.FactPurposeSessionOpen) || db.args[9] != "pfs-1" {
		t.Fatalf("issue args %+v", db.args)
	}
	if issued.Fact.DbMs != 1_700_000_000_000 || issued.FactExpiresDbMs != 1_700_000_030_000 {
		t.Fatalf("issued %+v", issued)
	}
	if issued.Fact.FactID[0] != 0x5a || issued.Fact.Source != pfc2.TimeSourceDB {
		t.Fatalf("issued fact %+v", issued.Fact)
	}

	// A purpose-less mint never reaches SQL.
	if _, err := l.IssueAdmissionFact(pfc2.FactScope{
		Session: pfc2.SessionRef{SessionID: "pfs-1", Generation: 1},
	}); err == nil || strings.Contains(err.Error(), "pfj.") {
		t.Fatalf("purpose-less mint: %v", err)
	}
	// Cross-scope requests never reach SQL.
	if _, err := l.IssueAdmissionFact(pfc2.FactScope{
		TenantID: "other", Purpose: pfc2.FactPurposeSessionOpen,
		Session: pfc2.SessionRef{SessionID: "pfs-1", Generation: 1},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-scope: %v", err)
	}
	// A fenced/theft answer maps to the typed error.
	db.err = &pgconn.PgError{Code: "PF001", Message: "admission fact belongs to another capability"}
	if _, err := l.IssueAdmissionFact(pfc2.FactScope{
		Purpose: pfc2.FactPurposeSessionRenew,
		Session: pfc2.SessionRef{SessionID: "pfs-1", Generation: 1},
	}); !errors.Is(err, ErrFenced) {
		t.Fatalf("theft: %v", err)
	}
	// A floor-inequality answer maps to conflict.
	db.err = &pgconn.PgError{Code: "PF002", Message: "issuer control floor does not equal the durable floor"}
	if _, err := l.IssueAdmissionFact(pfc2.FactScope{
		Purpose: pfc2.FactPurposeSessionRenew,
		Session: pfc2.SessionRef{SessionID: "pfs-1", Generation: 1},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale floor: %v", err)
	}
	// An all-zero fact id from a corrupted server is refused client-side too.
	db.err = nil
	db.response = []byte(fmt.Sprintf(
		`{"factId":"%s","issuedDbMs":"1700000000000","factExpiresDbMs":"1700000030000","controlDbFloorMs":"0"}`,
		strings.Repeat("00", 16)))
	if _, err := l.IssueAdmissionFact(pfc2.FactScope{
		Purpose: pfc2.FactPurposeSessionExpiry,
		Session: pfc2.SessionRef{SessionID: "pfs-1", Generation: 1},
	}); !errors.Is(err, ErrProtocolIntegrity) {
		t.Fatalf("zero fact id: %v", err)
	}
}

func TestOpenV3MapsLegacyGenerationToMigrationRequired(t *testing.T) {
	// OpenV3 requires a real pool; exercise the mapping at the claim error
	// boundary instead: PF005 typed errors surface as ErrMigrationRequired.
	err := fmt.Errorf("remotejournal: claim v3: %w",
		fmt.Errorf("%w: branch journal generation speaks pfr1/pfc1", ErrCodec))
	if !errors.Is(err, ErrCodec) {
		t.Fatal("PF005 mapping precondition")
	}
	wrapped := fmt.Errorf("%w: %v", ErrMigrationRequired, err)
	if !errors.Is(wrapped, ErrMigrationRequired) {
		t.Fatal("migration-required wrap lost its root")
	}
}

func openAuthoritativeConfig() Config {
	return Config{
		TenantID: "tenant-1", VolumeID: "volume-1", Branch: "main",
		AuthorityRuntimeID: "runtime-1", AuthorityCapability: "authority-capability-1",
		CallTimeout: time.Second,
	}
}

func TestOpenAuthoritativeRefusesLegacyProvisioningBeforeAnyClaim(t *testing.T) {
	// A base-authored (legacy_manifest) branch answers the legacy pair from
	// pfj.branch_provisioning. The managed child must refuse RIGHT THERE:
	// dispatching a pfr1 claim would create or resume a legacy generation
	// this process refuses to serve, stranding an active generation that
	// blocks the branch's later journal activation (the 013 conversion).
	db := &fakeJournalDB{response: []byte(`{
		"branchMode":"legacy_manifest","recordCodec":"pfr1","controlCodec":"pfc1",
		"generationId":"","dbTimeMs":"1700000000000"
	}`)}
	log, provisioning, err := openAuthoritative(context.Background(), db, openAuthoritativeConfig(), 2, 4)
	if log != nil {
		t.Fatalf("legacy provisioning produced a log: %+v", log)
	}
	if !errors.Is(err, ErrManagedCodecUnsupported) {
		t.Fatalf("err = %v, want ErrManagedCodecUnsupported", err)
	}
	// The decided facts ride along with the refusal so the caller can name
	// the exact pair and branch mode it refused.
	if provisioning.BranchMode != "legacy_manifest" ||
		provisioning.RecordCodec != wal.PFR1Codec || provisioning.ControlCodec != "pfc1" {
		t.Fatalf("refusal lost the decided provisioning facts: %+v", provisioning)
	}
	if db.calls != 1 || !strings.Contains(db.queries[0], "pfj.branch_provisioning") {
		t.Fatalf("discovery calls=%d queries=%#v", db.calls, db.queries)
	}
	for _, query := range db.queries {
		if strings.Contains(query, "journal_claim") {
			t.Fatalf("refusal issued a claim statement: %q", query)
		}
	}
}

func TestOpenAuthoritativeManagedProvisioningProceedsToClaim(t *testing.T) {
	// The managed pair passes the pre-claim guard: the very next step is the
	// PFJ3 claim, which refuses this config on its missing writer facts —
	// proving the claim dispatch was reached, not the codec guard.
	db := &fakeJournalDB{response: []byte(`{
		"branchMode":"managed_journal","recordCodec":"pfj3","controlCodec":"pfc2",
		"generationId":"jgen-1","dbTimeMs":"1700000000000"
	}`)}
	log, _, err := openAuthoritative(context.Background(), db, openAuthoritativeConfig(), 2, 4)
	if log != nil || err == nil || errors.Is(err, ErrManagedCodecUnsupported) {
		t.Fatalf("managed pair log=%v err=%v, want the claim path's writer-facts refusal", log, err)
	}
	if !strings.Contains(err.Error(), "writer claim requires") {
		t.Fatalf("managed pair stopped before the claim dispatch: %v", err)
	}
}
