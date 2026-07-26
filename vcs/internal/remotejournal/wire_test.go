package remotejournal

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

func TestGenerationJSONPreservesDecimalsAboveTwoToThe53(t *testing.T) {
	raw := []byte(`{
		"generationId":"jgen_test","tenantId":"t","volumeId":"v","branchId":"b",
		"epoch":"9007199254740993","recordCodec":"pfr1","controlCodec":"pfc1",
		"baseCommitId":"c","baseSeq":"9007199254740994",
		"baseDigest":"0000000000000000000000000000000000000000000000000000000000000000",
		"nextSeq":"9007199254740995",
		"tipDigest":"0000000000000000000000000000000000000000000000000000000000000000",
		"physicalTrimmedSeq":"0","status":"active","backlogBytes":"1","backlogRecords":"1",
		"quotaBacklogBytes":"2","quotaBacklogRecords":"2","writerFence":"9007199254740996",
		"claimedAt":"1","updatedAt":"1"
	}`)
	var got generationJSON
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode exact generation: %v", err)
	}
	if got.Epoch == nil || got.NextSeq == nil ||
		uint64(*got.Epoch) != 9007199254740993 || uint64(*got.NextSeq) != 9007199254740995 {
		t.Fatalf("decimal precision lost: epoch=%d next=%d", got.Epoch, got.NextSeq)
	}
	if got.WriterFence == nil || int64(*got.WriterFence) != 9007199254740996 {
		t.Fatalf("writer fence precision lost: %v", got.WriterFence)
	}
}

func TestExactIntegerJSONRejectsNumbersAndNonCanonicalDecimals(t *testing.T) {
	for _, raw := range []string{`1`, `""`, `"01"`, `"-1"`, `"1.0"`, `"+1"`} {
		var value decimalUint64
		if err := json.Unmarshal([]byte(raw), &value); err == nil {
			t.Fatalf("accepted non-canonical exact integer %s", raw)
		}
	}
	var max decimalUint64
	if err := json.Unmarshal([]byte(`"18446744073709551615"`), &max); err != nil {
		t.Fatalf("decode uint64 max: %v", err)
	}
	if uint64(max) != math.MaxUint64 {
		t.Fatalf("got %d, want uint64 max", max)
	}
}

func TestCheckedSQLBigintRejectsUint64Overflow(t *testing.T) {
	if _, err := checkedSQLBigint("lsn", uint64(math.MaxInt64)+1); err == nil {
		t.Fatal("accepted value above PostgreSQL BIGINT")
	}
	if got, err := checkedSQLBigint("lsn", uint64(math.MaxInt64)); err != nil || got != math.MaxInt64 {
		t.Fatalf("max int64 rejected: got=%d err=%v", got, err)
	}
}

func TestRuntimeBindingRequiresCanonicalManagerIssuedIdentity(t *testing.T) {
	valid := Config{
		ManagerEpoch:        "9007199254740993",
		AuthorityRuntimeSeq: "9007199254740994",
		AuthorityRuntimeID:  "runtime-1",
		AuthorityCapability: "authority-capability-1",
	}
	managerEpoch, runtimeSeq, err := runtimeBinding(valid)
	if err != nil || managerEpoch != 9007199254740993 || runtimeSeq != 9007199254740994 {
		t.Fatalf("valid exact binding rejected: epoch=%d runtime=%d err=%v", managerEpoch, runtimeSeq, err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.ManagerEpoch = "01" },
		func(c *Config) { c.AuthorityRuntimeSeq = "9223372036854775808" },
		func(c *Config) { c.AuthorityRuntimeID = "" },
		func(c *Config) { c.AuthorityCapability = "" },
	} {
		candidate := valid
		mutate(&candidate)
		if _, _, err := runtimeBinding(candidate); err == nil {
			t.Fatalf("accepted invalid runtime binding: %+v", candidate)
		}
	}
}

func TestProjectedQuotaFailureConsumesNoLSN(t *testing.T) {
	db := &fakeJournalDB{err: &pgconn.PgError{Code: "PF003", Message: "journal backlog quota exceeded"}}
	l := &Log{
		pool:           db,
		life:           context.Background(),
		cfg:            Config{MaxStagedBytes: 1 << 20, CallTimeout: time.Second},
		nextSeq:        17,
		backlogRecords: 1,
		quotaRecords:   1,
		poisonedCh:     make(chan struct{}),
	}
	records := []wal.Record{{Op: wal.OpCreate, Path: "blocked", Mode: 0o644}}
	_, _, err := l.AppendBatchBuffered(records)
	if !errors.Is(err, ErrQuota) {
		t.Fatalf("append error = %v, want ErrQuota", err)
	}
	if got := l.Watermark(); got != 17 {
		t.Fatalf("quota failure consumed an LSN: watermark=%d", got)
	}
	if len(l.staged) != 0 || l.stagedBytes != 0 {
		t.Fatalf("quota failure published staging: records=%d bytes=%d", len(l.staged), l.stagedBytes)
	}
	if records[0].Seq != 0 {
		t.Fatalf("quota failure exposed a reserved LSN on the caller record: %d", records[0].Seq)
	}
	if db.calls != 1 {
		t.Fatalf("quota slow path calls=%d, want one authoritative refresh", db.calls)
	}
}

func TestProjectedAccountingOverflowConsumesNoLSN(t *testing.T) {
	l := &Log{
		cfg:          Config{MaxStagedBytes: 1 << 20},
		nextSeq:      23,
		backlogBytes: math.MaxInt64,
		quotaBytes:   math.MaxInt64,
		poisonedCh:   make(chan struct{}),
	}
	records := []wal.Record{{Op: wal.OpCreate, Path: "overflow", Mode: 0o644}}
	_, _, err := l.AppendBatchBuffered(records)
	if !errors.Is(err, ErrBounds) {
		t.Fatalf("append error = %v, want ErrBounds", err)
	}
	if got := l.Watermark(); got != 23 || len(l.staged) != 0 || records[0].Seq != 0 {
		t.Fatalf("overflow admission mutated state: watermark=%d staged=%d callerSeq=%d",
			got, len(l.staged), records[0].Seq)
	}
	if !l.OverCapacity() || l.BacklogBytes() != math.MaxInt64 {
		t.Fatalf("overflow accounting did not fail closed: over=%v backlog=%d",
			l.OverCapacity(), l.BacklogBytes())
	}
}

func TestCanonicalFingerprintIsBoundarySafeAndStable(t *testing.T) {
	first := canonicalFingerprint("ab", "c")
	if first != canonicalFingerprint("ab", "c") {
		t.Fatal("fingerprint is not deterministic")
	}
	if first == canonicalFingerprint("a", "bc") {
		t.Fatal("length boundaries smeared distinct requests")
	}
}

func TestDurableHeadExcludesReservedStaging(t *testing.T) {
	durableTip := [32]byte{1, 2, 3}
	l := &Log{
		cfg:        Config{MaxStagedBytes: 1 << 20},
		nextSeq:    9,
		durableSeq: 7,
		durableTip: durableTip,
		poisonedCh: make(chan struct{}),
	}
	next, tip := l.DurableHead()
	if next != 7 || tip != "0102030000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("durable head = %d/%s", next, tip)
	}
}

func TestSuspendReceiptPreservesExactRevisionAboveTwoToThe53(t *testing.T) {
	var receipt suspendReceiptJSON
	err := json.Unmarshal([]byte(`{
		"operationId":"suspend-1","status":"suspended","generationId":"jgen_1",
		"epoch":"9007199254740993","nextSeq":"9007199254740994",
		"tipDigest":"0000000000000000000000000000000000000000000000000000000000000000",
		"writerFence":"9007199254740995","managerEpoch":"9007199254740996",
		"authorityRuntimeSeq":"9007199254740997","authorityRuntimeId":"runtime-1",
		"suspendedAtDbMs":"9007199254740998","replayed":true
	}`), &receipt)
	if err != nil {
		t.Fatalf("decode suspend receipt: %v", err)
	}
	if receipt.NextSeq == nil || receipt.AuthorityRuntimeSeq == nil ||
		uint64(*receipt.NextSeq) != 9007199254740994 ||
		int64(*receipt.AuthorityRuntimeSeq) != 9007199254740997 ||
		receipt.Replayed == nil || !*receipt.Replayed {
		t.Fatalf("lost exact suspend fields: %+v", receipt)
	}
}

func TestSQLRetryClassificationIsAllowlisted(t *testing.T) {
	for _, code := range []string{"08006", "40001", "40P01", "55P03", "57P01"} {
		if !retryableSQLFailure(&pgconn.PgError{Code: code}) {
			t.Fatalf("transient SQLSTATE %s was not retryable", code)
		}
	}
	for _, code := range []string{"28P01", "42501", "42883", "22P02", "0A000", "PF008", "PF015"} {
		if retryableSQLFailure(&pgconn.PgError{Code: code}) {
			t.Fatalf("deterministic SQLSTATE %s would loop", code)
		}
	}
	if mapped := typedError(&pgconn.PgError{Code: "PF015", Message: "no synchronous standby"}); !errors.Is(mapped, ErrDurabilityUnavailable) {
		t.Fatalf("PF015 mapped to %v, want ErrDurabilityUnavailable", mapped)
	}
}

func TestJSONEqualityPreservesExactNumberSemantics(t *testing.T) {
	if jsonEqual(
		[]byte(`{"n":9007199254740992}`),
		[]byte(`{"n":9007199254740993}`),
	) {
		t.Fatal("distinct integers above 2^53 compared equal")
	}
	if !jsonEqual([]byte(`{"n":1}`), []byte(`{"n":1.0}`)) {
		t.Fatal("numerically equal JSON numbers compared different")
	}
	if !jsonEqual([]byte(`{"a":1,"b":[2,3]}`), []byte(`{"b":[2.0,3e0],"a":1.00}`)) {
		t.Fatal("object order or exact equivalent number spelling changed equality")
	}
	if jsonEqual([]byte(`[1,2]`), []byte(`[2,1]`)) {
		t.Fatal("array order was ignored")
	}
}
