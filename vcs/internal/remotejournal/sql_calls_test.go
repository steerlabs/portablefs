package remotejournal

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

type fakeJournalDB struct {
	mu          sync.Mutex
	query       string
	args        []any
	response    []byte
	responses   [][]byte
	err         error
	errors      []error
	calls       int
	queries     []string
	argsHistory [][]any
	scanStarted chan<- struct{}
	scanRelease <-chan struct{}
}

func (f *fakeJournalDB) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.query = query
	f.args = append([]any(nil), args...)
	f.calls++
	f.queries = append(f.queries, query)
	f.argsHistory = append(f.argsHistory, append([]any(nil), args...))
	err := f.err
	if f.calls <= len(f.errors) {
		err = f.errors[f.calls-1]
	}
	response := f.response
	if f.calls <= len(f.responses) {
		response = f.responses[f.calls-1]
	}
	return fakeJournalRow{
		response: response, err: err,
		scanStarted: f.scanStarted, scanRelease: f.scanRelease,
	}
}

func (f *fakeJournalDB) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeJournalDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}

func (f *fakeJournalDB) Close() {}

type fakeJournalRow struct {
	response    []byte
	err         error
	scanStarted chan<- struct{}
	scanRelease <-chan struct{}
}

func (r fakeJournalRow) Scan(dest ...any) error {
	if r.scanStarted != nil {
		select {
		case r.scanStarted <- struct{}{}:
		default:
		}
	}
	if r.scanRelease != nil {
		<-r.scanRelease
	}
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return fmt.Errorf("fake row: got %d destinations", len(dest))
	}
	raw, ok := dest[0].(*[]byte)
	if !ok {
		return fmt.Errorf("fake row: destination is %T", dest[0])
	}
	*raw = append((*raw)[:0], r.response...)
	return nil
}

func TestSuspendExactCallCarriesFullBindingAndExpectedRevision(t *testing.T) {
	const nextSeq = uint64(9007199254740994)
	tip := [32]byte{1, 2, 3}
	tipHex := hex.EncodeToString(tip[:])
	validResponse := []byte(fmt.Sprintf(`{
		"operationId":"suspend-1","status":"suspended","tenantId":"tenant-1",
		"volumeId":"volume-1","branchId":"branch-1","generationId":"jgen-1",
		"epoch":"9007199254740993","nextSeq":"%d","tipDigest":"%s",
		"writerFence":"91","managerEpoch":"9007199254740995",
		"authorityRuntimeSeq":"9007199254740996","authorityRuntimeId":"runtime-1",
		"suspendedAtDbMs":"9007199254740997","replayed":false
	}`, nextSeq, tipHex))
	db := &fakeJournalDB{responses: [][]byte{[]byte(`{"broken":`), validResponse}}
	l := &Log{
		pool: db,
		life: context.Background(),
		cfg: Config{
			TenantID: "tenant-1", VolumeID: "volume-1", LeaseID: "lease-1", FencingToken: 91, CallTimeout: time.Second,
			AuthorityRuntimeID: "runtime-1",
		},
		generationID: "jgen-1",
		branchID:     "branch-1",
		epoch:        9007199254740993,
		capability:   "authority-capability-1",
		managerEpoch: 9007199254740995,
		runtimeSeq:   9007199254740996,
		durableSeq:   nextSeq,
		durableTip:   tip,
		poisonedCh:   make(chan struct{}),
	}
	receipt, err := l.SuspendExact(context.Background(), "suspend-1", nextSeq, tipHex)
	if err != nil {
		t.Fatalf("SuspendExact: %v", err)
	}
	if receipt.NextSeq != nextSeq || receipt.Replayed {
		t.Fatalf("receipt = %+v", receipt)
	}
	if db.calls != 2 || db.queries[0] != db.queries[1] ||
		fmt.Sprint(db.argsHistory[0]) != fmt.Sprint(db.argsHistory[1]) {
		t.Fatalf("ambiguous suspend response was not retried exactly: calls=%d queries=%#v args=%#v",
			db.calls, db.queries, db.argsHistory)
	}
	if l.IsPoisoned() {
		t.Fatal("one transient invalid suspend success poisoned the log")
	}
	if !strings.Contains(db.query, "pfj.journal_suspend_exact") || len(db.args) != 14 {
		t.Fatalf("query=%q args=%d", db.query, len(db.args))
	}
	want := []any{
		"jgen-1", int64(9007199254740993), "authority-capability-1", "lease-1", int64(91),
		"pfr1", "pfc1", int64(9007199254740995), int64(9007199254740996),
		"runtime-1", "suspend-1",
	}
	for i, value := range want {
		if db.args[i] != value {
			t.Fatalf("arg %d = %#v, want %#v", i+1, db.args[i], value)
		}
	}
	fingerprint, ok := db.args[11].(string)
	if !ok || len(fingerprint) != 64 {
		t.Fatalf("fingerprint arg = %#v", db.args[11])
	}
	if db.args[12] != int64(nextSeq) || db.args[13] != tipHex {
		t.Fatalf("expected revision args = %#v", db.args[12:])
	}
}

func TestThreeInvalidAppendSuccessBodiesFenceWithoutDiscardingStaging(t *testing.T) {
	tip := [32]byte{6, 2, 6}
	group := stagedRecord{
		seq: 0, payload: []byte("PFR1"), hashHex: strings.Repeat("a", 64), tipAfter: tip,
	}
	db := &fakeJournalDB{responses: [][]byte{[]byte(`{}`), []byte(`{}`), []byte(`{}`)}}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		baseCommitID: "base", nextSeq: 1,
		staged: []stagedRecord{group}, stagedBytes: int64(len(group.payload)),
		quotaBytes: 100, quotaRecords: 100,
		poisonedCh: make(chan struct{}),
	}
	err := l.CommitThrough(0)
	if !errors.Is(err, ErrProtocolIntegrity) || !l.IsPoisoned() || db.calls != 3 {
		t.Fatalf("invalid append successes err=%v poisoned=%v calls=%d", err, l.IsPoisoned(), db.calls)
	}
	if len(l.staged) != 1 || l.stagedBytes != int64(len(group.payload)) || l.durableSeq != 0 {
		t.Fatalf("protocol fence discarded/acknowledged staging: staged=%d bytes=%d durable=%d",
			len(l.staged), l.stagedBytes, l.durableSeq)
	}
}

func TestMissingAppendReceiptFailuresPoisonWithoutDiscardingStaging(t *testing.T) {
	tests := []struct {
		name string
		code string
		want error
	}{
		{"below-retained-floor", "PF014", ErrReceiptEvicted},
		{"durable-bytes-without-receipt", "PF010", ErrAccounting},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			durableTip := [32]byte{1, 2, 3}
			groupTip := [32]byte{4, 5, 6}
			group := stagedRecord{
				seq: 7, payload: []byte("PFR1"), hashHex: strings.Repeat("a", 64), tipAfter: groupTip,
			}
			db := &fakeJournalDB{err: &pgconn.PgError{Code: test.code, Message: "missing exact append receipt"}}
			l := &Log{
				pool: db, life: context.Background(),
				cfg: Config{
					LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
					CallTimeout: time.Second,
				},
				generationID: "jgen-1", epoch: 1,
				capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
				nextSeq: 8, durableSeq: 7, durableTip: durableTip,
				staged: []stagedRecord{group}, stagedBytes: int64(len(group.payload)),
				quotaBytes: 100, quotaRecords: 100,
				poisonedCh: make(chan struct{}),
			}
			err := l.CommitThrough(7)
			if !errors.Is(err, test.want) || !l.IsPoisoned() || db.calls != 1 {
				t.Fatalf("missing receipt err=%v want=%v poisoned=%v calls=%d",
					err, test.want, l.IsPoisoned(), db.calls)
			}
			if len(l.staged) != 1 || l.stagedBytes != int64(len(group.payload)) ||
				l.durableSeq != 7 || l.durableTip != durableTip {
				t.Fatalf("missing receipt changed staged/durable state: staged=%d bytes=%d durable=%d/%x",
					len(l.staged), l.stagedBytes, l.durableSeq, l.durableTip)
			}
		})
	}
}

func TestAppendResponseMismatchRetriesExactBytesAndValidatesAccounting(t *testing.T) {
	tip := [32]byte{9, 8, 7}
	tipHex := hex.EncodeToString(tip[:])
	bad := []byte(fmt.Sprintf(`{
		"generationId":"jgen-1","epoch":"1","nextSeq":"2","tipDigest":"%s","appended":"1","duplicated":"0","replayed":false,
		"currentBaseCommitId":"base","currentBaseSeq":"0",
		"currentBaseDigest":"%s","currentPhysicalTrimmedSeq":"0",
		"currentBacklogBytes":"4","currentBacklogRecords":"2",
		"currentQuotaBacklogBytes":"100","currentQuotaBacklogRecords":"100","currentCut":null
	}`, tipHex, strings.Repeat("0", 64)))
	good := []byte(fmt.Sprintf(`{
		"generationId":"jgen-1","epoch":"1","nextSeq":"1","tipDigest":"%s","appended":"1","duplicated":"0","replayed":false,
		"currentBaseCommitId":"base","currentBaseSeq":"0",
		"currentBaseDigest":"%s","currentPhysicalTrimmedSeq":"0",
		"currentBacklogBytes":"4","currentBacklogRecords":"1",
		"currentQuotaBacklogBytes":"100","currentQuotaBacklogRecords":"100","currentCut":null
	}`, tipHex, strings.Repeat("0", 64)))
	db := &fakeJournalDB{responses: [][]byte{bad, good}}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		quotaBytes: 100, quotaRecords: 100,
		poisonedCh: make(chan struct{}),
	}
	group := []stagedRecord{{
		seq: 0, payload: []byte("PFR1"), hashHex: strings.Repeat("a", 64), tipAfter: tip,
	}}
	res, err := l.appendGroup(group)
	if err != nil || res.NextSeq == nil || res.Appended == nil ||
		uint64(*res.NextSeq) != 1 || int64(*res.Appended) != 1 {
		t.Fatalf("append result=%+v err=%v", res, err)
	}
	if db.calls != 2 || db.queries[0] != db.queries[1] ||
		fmt.Sprint(db.argsHistory[0]) != fmt.Sprint(db.argsHistory[1]) {
		t.Fatalf("mismatched append response was not retried exactly: calls=%d", db.calls)
	}
	if l.IsPoisoned() {
		t.Fatal("one transient invalid append success poisoned the log")
	}
	if len(db.args) != 14 {
		t.Fatalf("one-cap append args=%d, want 14", len(db.args))
	}
	wantPrefix := []any{
		"jgen-1", int64(1), "authority-capability-1", "lease-1", int64(3),
		"pfr1", "pfc1", int64(2), int64(4), "runtime-1", int64(0),
	}
	for i, want := range wantPrefix {
		if db.args[i] != want {
			t.Fatalf("append arg %d=%#v, want %#v", i+1, db.args[i], want)
		}
	}
	capabilityCount := 0
	for _, arg := range db.args {
		if arg == "authority-capability-1" {
			capabilityCount++
		}
	}
	if capabilityCount != 1 {
		t.Fatalf("append carried raw capability %d times", capabilityCount)
	}
}

func TestAppendRetriesPF015WithoutPoisoningUntilDurabilityRecovers(t *testing.T) {
	tip := [32]byte{9, 1, 5}
	tipHex := hex.EncodeToString(tip[:])
	db := &fakeJournalDB{
		response: []byte(fmt.Sprintf(`{
			"generationId":"jgen-1","epoch":"1","nextSeq":"1","tipDigest":"%s","appended":"1","duplicated":"0","replayed":false,
			"currentBaseCommitId":"base","currentBaseSeq":"0",
			"currentBaseDigest":"%s","currentPhysicalTrimmedSeq":"0",
			"currentBacklogBytes":"4","currentBacklogRecords":"1",
			"currentQuotaBacklogBytes":"100","currentQuotaBacklogRecords":"100","currentCut":null
		}`, tipHex, strings.Repeat("0", 64))),
		errors: []error{&pgconn.PgError{Code: "PF015", Message: "synchronous durability unavailable"}, nil},
	}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		quotaBytes: 100, quotaRecords: 100,
		poisonedCh: make(chan struct{}),
	}
	group := []stagedRecord{{
		seq: 0, payload: []byte("PFR1"), hashHex: strings.Repeat("a", 64), tipAfter: tip,
	}}
	if _, err := l.appendGroup(group); err != nil {
		t.Fatalf("append did not recover from PF015: %v", err)
	}
	if db.calls != 2 || l.IsPoisoned() {
		t.Fatalf("PF015 recovery attempts=%d poisoned=%v", db.calls, l.IsPoisoned())
	}
	if db.queries[0] != db.queries[1] || fmt.Sprint(db.argsHistory[0]) != fmt.Sprint(db.argsHistory[1]) {
		t.Fatal("PF015 retry changed the exact append call")
	}
}

func TestAppendPF015ExitsAtLifecycleDeadlineWithoutPoisoning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	db := &fakeJournalDB{err: &pgconn.PgError{Code: "PF015", Message: "synchronous durability unavailable"}}
	l := &Log{
		pool: db, life: ctx,
		cfg: Config{
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		poisonedCh: make(chan struct{}),
	}
	group := []stagedRecord{{
		seq: 0, payload: []byte("PFR1"), hashHex: strings.Repeat("a", 64), tipAfter: [32]byte{1},
	}}
	_, err := l.appendGroup(group)
	if !errors.Is(err, ErrDurabilityUnavailable) || !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("append deadline error=%v, want durability unavailable + unknown outcome", err)
	}
	if db.calls != 1 || l.IsPoisoned() {
		t.Fatalf("PF015 deadline attempts=%d poisoned=%v", db.calls, l.IsPoisoned())
	}
}

func TestAppendReceiptReplayAfterTrimAdoptsCurrentFactsNotOriginalBacklog(t *testing.T) {
	tip := [32]byte{7, 7, 7}
	tipHex := hex.EncodeToString(tip[:])
	digest := "sha256:" + strings.Repeat("b", 64)
	db := &fakeJournalDB{response: []byte(fmt.Sprintf(`{
		"generationId":"jgen-1","epoch":"1","nextSeq":"1","tipDigest":"%s","appended":"1","duplicated":"0","replayed":true,
		"currentBaseCommitId":"commit-after-trim","currentBaseSeq":"1",
		"currentBaseDigest":"%s","currentPhysicalTrimmedSeq":"1",
		"currentBacklogBytes":"0","currentBacklogRecords":"0",
		"currentQuotaBacklogBytes":"100","currentQuotaBacklogRecords":"100",
		"currentCut":{
			"operationId":"cut-after-append","epoch":"1","status":"finalized","watermark":"1",
			"expectedHeadCommitId":"commit-before","treeHash":"%s",
			"canonicalRequestHash":"%s","commitId":"commit-after-trim"
		}
	}`, tipHex, tipHex, digest, digest))}
	group := stagedRecord{
		seq: 0, payload: []byte("PFR1"), hashHex: strings.Repeat("c", 64), tipAfter: tip,
	}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		baseCommitID: "commit-before",
		nextSeq:      1, durableSeq: 0,
		staged: []stagedRecord{group}, stagedBytes: int64(len(group.payload)),
		quotaBytes: 100, quotaRecords: 100,
		poisonedCh: make(chan struct{}),
	}
	if err := l.CommitThrough(0); err != nil {
		t.Fatalf("commit replay after trim: %v", err)
	}
	if l.durableSeq != 1 || l.baseSeq != 1 || l.physicalTrimmedSeq != 1 ||
		l.baseCommitID != "commit-after-trim" || l.backlogBytes != 0 || l.backlogRecords != 0 ||
		len(l.staged) != 0 || !l.hasCut || l.cut.Status != wal.CheckpointFinalized {
		t.Fatalf("trim replay installed stale/invalid facts: durable=%d base=%d/%d commit=%s backlog=%d/%d staged=%d cut=%+v",
			l.durableSeq, l.baseSeq, l.physicalTrimmedSeq, l.baseCommitID,
			l.backlogBytes, l.backlogRecords, len(l.staged), l.cut)
	}
}

func TestCommitMuPreventsLaterGroupCallUntilFirstResponseResolves(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	db := &fakeJournalDB{scanStarted: started, scanRelease: release}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second, MaxStagedBytes: 1 << 20,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		baseCommitID: "base", quotaBytes: 100000, quotaRecords: 100,
		poisonedCh: make(chan struct{}),
	}
	firstRecords := []wal.Record{{Op: wal.OpCreate, Path: "first", Mode: 0o644}}
	if _, _, err := l.AppendBatchBuffered(firstRecords); err != nil {
		t.Fatalf("stage first: %v", err)
	}
	firstGroup := l.staged[0]
	secondRecord := wal.Record{Seq: 1, Op: wal.OpCreate, Path: "second", Mode: 0o644}
	secondPayload, err := wal.EncodePFR1(&secondRecord)
	if err != nil {
		t.Fatalf("encode expected second record: %v", err)
	}
	secondTip := wal.ChainDigestBytes(firstGroup.tipAfter, secondPayload)
	zeroDigest := strings.Repeat("0", 64)
	response := func(next uint64, tip [32]byte, bytes, records int64) []byte {
		return []byte(fmt.Sprintf(`{
			"generationId":"jgen-1","epoch":"1","nextSeq":"%d","tipDigest":"%s",
			"appended":"1","duplicated":"0","replayed":false,
			"currentBaseCommitId":"base","currentBaseSeq":"0","currentBaseDigest":"%s",
			"currentPhysicalTrimmedSeq":"0","currentBacklogBytes":"%d","currentBacklogRecords":"%d",
			"currentQuotaBacklogBytes":"100000","currentQuotaBacklogRecords":"100","currentCut":null
		}`, next, hex.EncodeToString(tip[:]), zeroDigest, bytes, records))
	}
	db.mu.Lock()
	db.responses = [][]byte{
		response(1, firstGroup.tipAfter, int64(len(firstGroup.payload)), 1),
		response(2, secondTip, int64(len(firstGroup.payload)+len(secondPayload)), 2),
	}
	db.mu.Unlock()

	firstDone := make(chan error, 1)
	go func() { firstDone <- l.CommitThrough(0) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first append did not reach SQL")
	}
	secondRecords := []wal.Record{{Op: wal.OpCreate, Path: "second", Mode: 0o644}}
	if _, _, err := l.AppendBatchBuffered(secondRecords); err != nil {
		t.Fatalf("stage second while first response blocked: %v", err)
	}
	if len(l.staged) != 2 || string(l.staged[1].payload) != string(secondPayload) {
		t.Fatalf("later staging changed expected bytes: staged=%d", len(l.staged))
	}
	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondEntered)
		secondDone <- l.CommitThrough(1)
	}()
	<-secondEntered
	select {
	case err := <-secondDone:
		t.Fatalf("second commit completed before first response: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if calls := db.callCount(); calls != 1 {
		t.Fatalf("later group reached SQL before first response resolved: calls=%d", calls)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if db.callCount() != 2 || db.argsHistory[0][10] != int64(0) || db.argsHistory[1][10] != int64(1) {
		t.Fatalf("append SQL order/calls invalid: calls=%d args=%#v", db.callCount(), db.argsHistory)
	}
}

func TestExternalTrimRefreshRestoresAdmissionWithoutRestart(t *testing.T) {
	zeroDigest := strings.Repeat("0", 64)
	canonicalDigest := "sha256:" + strings.Repeat("a", 64)
	db := &fakeJournalDB{response: []byte(fmt.Sprintf(`{
		"allowed":true,"generationId":"jgen-1","branchName":"main","epoch":"1",
		"baseCommitId":"commit-after-trim","baseSeq":"8","baseDigest":"%s",
		"physicalTrimmedSeq":"8","cut":{
			"operationId":"cut-1","epoch":"1","status":"finalized","watermark":"8",
			"expectedHeadCommitId":"commit-before-trim","treeHash":"%s",
			"canonicalRequestHash":"%s","commitId":"commit-after-trim"
		},
		"backlogBytes":"50","backlogRecords":"9",
		"quotaBacklogBytes":"1000","quotaBacklogRecords":"100",
		"remainingBytes":"950","remainingRecords":"91"
	}`, zeroDigest, canonicalDigest, canonicalDigest))}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			Branch: "main", LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second, MaxStagedBytes: 1 << 20,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		baseCommitID: "commit-before-trim",
		baseSeq:      0, nextSeq: 17, durableSeq: 17,
		backlogBytes: 1000, backlogRecords: 17,
		quotaBytes: 1000, quotaRecords: 100,
		poisonedCh: make(chan struct{}),
	}
	records := []wal.Record{{Op: wal.OpCreate, Path: "after-trim", Mode: 0o644}}
	first, end, err := l.AppendBatchBuffered(records)
	if err != nil {
		t.Fatalf("append after external trim refresh: %v", err)
	}
	if first != 17 || end != 18 || records[0].Seq != 17 || l.baseSeq != 8 ||
		l.baseCommitID != "commit-after-trim" || l.backlogBytes != 50 {
		t.Fatalf("refreshed append first/end=%d/%d record=%d base=%d/%s backlog=%d",
			first, end, records[0].Seq, l.baseSeq, l.baseCommitID, l.backlogBytes)
	}
	if db.calls != 1 || !strings.Contains(db.query, "pfj.journal_check_append_quota") || len(db.args) != 12 {
		t.Fatalf("refresh query=%q calls=%d args=%d", db.query, db.calls, len(db.args))
	}
	if db.args[10] != int64(0) || db.args[11] != int64(0) {
		t.Fatalf("quota refresh modeled local staging in SQL: args=%#v", db.args[10:])
	}
}

func TestQuotaRefreshRejectsEmptyRangeDigestMismatchWithoutConsumingLSN(t *testing.T) {
	zeroDigest := strings.Repeat("0", 64)
	db := &fakeJournalDB{response: []byte(fmt.Sprintf(`{
		"allowed":true,"generationId":"jgen-1","branchName":"main","epoch":"1",
		"baseCommitId":"commit-before","baseSeq":"17","baseDigest":"%s",
		"physicalTrimmedSeq":"17","cut":null,
		"backlogBytes":"0","backlogRecords":"0",
		"quotaBacklogBytes":"1000","quotaBacklogRecords":"100",
		"remainingBytes":"1000","remainingRecords":"100"
	}`, zeroDigest))}
	durableTip := [32]byte{1}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			Branch: "main", LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second, MaxStagedBytes: 1 << 20,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		baseCommitID: "commit-before",
		baseSeq:      0, nextSeq: 17, durableSeq: 17, tip: durableTip, durableTip: durableTip,
		backlogBytes: 1000, backlogRecords: 17,
		quotaBytes: 1000, quotaRecords: 100,
		poisonedCh: make(chan struct{}),
	}
	records := []wal.Record{{Op: wal.OpCreate, Path: "blocked", Mode: 0o644}}
	_, _, err := l.AppendBatchBuffered(records)
	if !errors.Is(err, ErrAccounting) {
		t.Fatalf("quota refresh digest error=%v, want ErrAccounting", err)
	}
	if l.nextSeq != 17 || l.baseSeq != 0 || len(l.staged) != 0 || records[0].Seq != 0 {
		t.Fatalf("invalid quota refresh mutated state: next=%d base=%d staged=%d callerSeq=%d",
			l.nextSeq, l.baseSeq, len(l.staged), records[0].Seq)
	}
}

func TestCommonPathAdmissionHasNoQuotaRefreshRoundTrip(t *testing.T) {
	db := &fakeJournalDB{}
	l := &Log{
		pool: db, life: context.Background(),
		cfg:     Config{CallTimeout: time.Second, MaxStagedBytes: 1 << 20},
		nextSeq: 3, durableSeq: 3,
		quotaBytes: 1 << 20, quotaRecords: 100,
		poisonedCh: make(chan struct{}),
	}
	if _, _, err := l.AppendBatchBuffered([]wal.Record{{Op: wal.OpCreate, Path: "fast", Mode: 0o644}}); err != nil {
		t.Fatalf("common-path append: %v", err)
	}
	if db.calls != 0 {
		t.Fatalf("common-path admission performed %d SQL calls", db.calls)
	}
}

func TestOpstateCallsCarryOneCapabilityAndExactRuntime(t *testing.T) {
	loadDB := &fakeJournalDB{response: []byte("null")}
	l := &Log{
		pool: loadDB, life: context.Background(),
		cfg: Config{
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		poisonedCh: make(chan struct{}),
	}
	if _, _, found, err := l.OpStateDocument().Load(); err != nil || found {
		t.Fatalf("opstate load found=%v err=%v", found, err)
	}
	wantLoad := []any{
		"jgen-1", int64(1), "authority-capability-1", "lease-1", int64(3),
		int64(2), int64(4), "runtime-1",
	}
	if fmt.Sprint(loadDB.args) != fmt.Sprint(wantLoad) {
		t.Fatalf("opstate load args=%#v want=%#v", loadDB.args, wantLoad)
	}

	storeDB := &fakeJournalDB{response: []byte(`{"version":"8"}`)}
	l.pool = storeDB
	version, err := l.OpStateDocument().Store([]byte(`{"version":2}`), 7)
	if err != nil || version != 8 {
		t.Fatalf("opstate store version=%d err=%v", version, err)
	}
	wantStore := append(append([]any(nil), wantLoad...), int64(7), []byte(`{"version":2}`))
	if len(storeDB.args) != 10 || fmt.Sprint(storeDB.args[:9]) != fmt.Sprint(wantStore[:9]) ||
		!strings.EqualFold(string(storeDB.args[9].([]byte)), string(wantStore[9].([]byte))) {
		t.Fatalf("opstate store args=%#v want=%#v", storeDB.args, wantStore)
	}
}

func TestSuspendRetriesPF015WithoutPoisoningUntilDurabilityRecovers(t *testing.T) {
	tip := [32]byte{3, 1, 4}
	tipHex := hex.EncodeToString(tip[:])
	db := &fakeJournalDB{
		response: []byte(fmt.Sprintf(`{
			"operationId":"suspend-pf015","status":"suspended","tenantId":"tenant-1",
			"volumeId":"volume-1","branchId":"branch-1","generationId":"jgen-1",
			"epoch":"1","nextSeq":"0","tipDigest":"%s","writerFence":"3",
			"managerEpoch":"2","authorityRuntimeSeq":"4","authorityRuntimeId":"runtime-1",
			"suspendedAtDbMs":"5","replayed":false
		}`, tipHex)),
		errors: []error{&pgconn.PgError{Code: "PF015", Message: "synchronous durability unavailable"}, nil},
	}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			TenantID: "tenant-1", VolumeID: "volume-1", LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-1", epoch: 1,
		branchID:   "branch-1",
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		durableTip: tip,
		poisonedCh: make(chan struct{}),
	}
	if _, err := l.SuspendExact(context.Background(), "suspend-pf015", 0, tipHex); err != nil {
		t.Fatalf("suspend did not recover from PF015: %v", err)
	}
	if db.calls != 2 || l.IsPoisoned() || !l.suspended {
		t.Fatalf("PF015 recovery attempts=%d poisoned=%v suspended=%v", db.calls, l.IsPoisoned(), l.suspended)
	}
	if db.queries[0] != db.queries[1] || fmt.Sprint(db.argsHistory[0]) != fmt.Sprint(db.argsHistory[1]) {
		t.Fatal("PF015 retry changed the exact suspend call")
	}
}

func TestThreeInvalidSuspendSuccessBodiesFenceWithoutFabricatingReceipt(t *testing.T) {
	tip := [32]byte{8, 2, 8}
	tipHex := hex.EncodeToString(tip[:])
	db := &fakeJournalDB{responses: [][]byte{[]byte(`{}`), []byte(`{}`), []byte(`{}`)}}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		durableTip: tip,
		poisonedCh: make(chan struct{}),
	}
	receipt, err := l.SuspendExact(context.Background(), "suspend-invalid", 0, tipHex)
	if !errors.Is(err, ErrProtocolIntegrity) || !l.IsPoisoned() || db.calls != 3 {
		t.Fatalf("invalid suspend successes receipt=%+v err=%v poisoned=%v calls=%d",
			receipt, err, l.IsPoisoned(), db.calls)
	}
	if l.suspended || l.suspending {
		t.Fatalf("invalid suspend fabricated state: suspending=%v suspended=%v", l.suspending, l.suspended)
	}
}

func TestSuspendPF015ExitsAtLifecycleDeadlineWithoutPoisoning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tip := [32]byte{2, 7, 1}
	tipHex := hex.EncodeToString(tip[:])
	db := &fakeJournalDB{err: &pgconn.PgError{Code: "PF015", Message: "synchronous durability unavailable"}}
	l := &Log{
		pool: db, life: ctx,
		cfg: Config{
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-1", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		durableTip: tip,
		poisonedCh: make(chan struct{}),
	}
	_, err := l.SuspendExact(context.Background(), "suspend-pf015-deadline", 0, tipHex)
	if !errors.Is(err, ErrDurabilityUnavailable) || !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("suspend deadline error=%v, want durability unavailable + unknown outcome", err)
	}
	// An UNKNOWN outcome must not poison, but the suspend gate STAYS CLOSED:
	// the SQL may have committed the suspension, so no later append may race
	// it — only the exact replay of the same immutable request resolves it.
	if db.calls != 1 || l.IsPoisoned() || !l.suspending || l.suspended {
		t.Fatalf("PF015 deadline attempts=%d poisoned=%v suspending=%v suspended=%v",
			db.calls, l.IsPoisoned(), l.suspending, l.suspended)
	}
}

func TestSuspendGatePreventsAppendReservationDuringSQLCall(t *testing.T) {
	tip := [32]byte{4, 5, 6}
	tipHex := hex.EncodeToString(tip[:])
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	db := &fakeJournalDB{
		response: []byte(fmt.Sprintf(`{
			"operationId":"suspend-race","status":"suspended","tenantId":"tenant-1",
			"volumeId":"volume-1","branchId":"branch-1","generationId":"jgen-race",
			"epoch":"1","nextSeq":"0","tipDigest":"%s","writerFence":"3",
			"managerEpoch":"2","authorityRuntimeSeq":"4","authorityRuntimeId":"runtime-1",
			"suspendedAtDbMs":"5","replayed":false
		}`, tipHex)),
		scanStarted: started,
		scanRelease: release,
	}
	l := &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			TenantID: "tenant-1", VolumeID: "volume-1", LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second, MaxStagedBytes: 1 << 20,
		},
		generationID: "jgen-race", epoch: 1,
		branchID:   "branch-1",
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		durableTip: tip,
		poisonedCh: make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		_, err := l.SuspendExact(context.Background(), "suspend-race", 0, tipHex)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("suspend did not reach SQL")
	}
	_, _, err := l.AppendBatchBuffered([]wal.Record{{Op: wal.OpCreate, Path: "raced", Mode: 0o644}})
	if !errors.Is(err, ErrFenced) || l.Watermark() != 0 {
		t.Fatalf("append during suspend = %v, watermark=%d", err, l.Watermark())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("SuspendExact: %v", err)
	}
}

func TestBoundHeadCallCarriesManagerRuntimeCapability(t *testing.T) {
	db := &fakeJournalDB{response: []byte("null")}
	l := &Log{
		pool: db,
		life: context.Background(),
		cfg: Config{
			TenantID: "tenant-1", VolumeID: "volume-1", Branch: "main",
			AuthorityRuntimeID: "runtime-1", CallTimeout: time.Second,
		},
		managerEpoch: 7,
		runtimeSeq:   11,
		capability:   "authority-capability-1",
	}
	head, err := l.fetchHead()
	if err != nil || head != nil {
		t.Fatalf("fetchHead = %#v, %v", head, err)
	}
	if !strings.Contains(db.query, "pfj.journal_bound_head") {
		t.Fatalf("query = %q", db.query)
	}
	want := []any{"tenant-1", "volume-1", "main", int64(7), int64(11), "runtime-1", "authority-capability-1"}
	if fmt.Sprint(db.args) != fmt.Sprint(want) {
		t.Fatalf("args = %#v, want %#v", db.args, want)
	}
}

func TestDeterministicSQLFailureIsAttemptedOnce(t *testing.T) {
	db := &fakeJournalDB{err: &pgconn.PgError{Code: "42883", Message: "undefined function"}}
	l := &Log{
		pool: db,
		life: context.Background(),
		cfg:  Config{CallTimeout: time.Second},
	}
	_, err := l.callIdempotent("SELECT missing_signature($1)", "value")
	if err == nil || db.calls != 1 {
		t.Fatalf("err=%v attempts=%d, want deterministic one-shot failure", err, db.calls)
	}
}

func TestAmbiguousTransportFailureRetriesTheExactCall(t *testing.T) {
	db := &fakeJournalDB{
		response: []byte(`{"ok":true}`),
		errors:   []error{io.ErrUnexpectedEOF, nil},
	}
	l := &Log{
		pool: db,
		life: context.Background(),
		cfg:  Config{CallTimeout: time.Second},
	}
	raw, err := l.callIdempotent(
		"SELECT exact_operation($1,$2)",
		"operation-1", "fingerprint-1",
	)
	if err != nil || string(raw) != `{"ok":true}` || db.calls != 2 {
		t.Fatalf("raw=%s err=%v attempts=%d", raw, err, db.calls)
	}
	if db.query != "SELECT exact_operation($1,$2)" ||
		fmt.Sprint(db.args) != "[operation-1 fingerprint-1]" {
		t.Fatalf("retry changed exact call: query=%q args=%#v", db.query, db.args)
	}
}
