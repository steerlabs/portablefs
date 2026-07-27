package opstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := PathFor(filepath.Join(t.TempDir(), "primary.wal"))
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s, path
}

func op(id string, at int64) Operation {
	return Operation{
		ID: id, Kind: KindCheckpoint, Fingerprint: "sha256:fp-" + id,
		VolumeID: "vol_1", Branch: "main",
		AuthorityInstanceID: "pfai_1", HeadCommitID: "cmt_" + id, TreeHash: "sha256:aa",
		Committed: true, CompletedAtMs: at,
	}
}

func quiesceOp(id string, at int64) Operation {
	o := op(id, at)
	o.Kind = KindQuiesce
	return o
}

// TestRoundTripAcrossReopen: recorded operations, the quiesced marker, the
// lease-release fact, and the checkpoint intent are all readable from a FRESH
// Store over the same file — the resume-after-restart property every
// lost-response retry and crash reconciliation depends on.
func TestRoundTripAcrossReopen(t *testing.T) {
	s, path := tempStore(t)
	if err := s.RecordOperation(op("op-1", 10)); err != nil {
		t.Fatal(err)
	}
	marker := QuiesceMarker{
		VolumeID: "vol_1", Branch: "main", AuthorityInstanceID: "pfai_1",
		OperationID: "op-q", HeadCommitID: "cmt_final", TreeHash: "sha256:bb", CompletedAtMs: 20,
	}
	qop := quiesceOp("op-q", 20)
	qop.HeadCommitID, qop.TreeHash = marker.HeadCommitID, marker.TreeHash
	if err := s.SetQuiesced(marker, qop); err != nil {
		t.Fatal(err)
	}
	release := LeaseReleaseFact{
		VolumeID: "vol_1", Branch: "main", AuthorityInstanceID: "pfai_1",
		LeaseID: "lease_1", OperationID: "op-r", ReleasedAtMs: 30,
	}
	relOp := op("op-r", 30)
	relOp.Kind = KindReleaseLease
	relOp.HeadCommitID, relOp.TreeHash = marker.HeadCommitID, marker.TreeHash
	relOp.Committed = false
	relOp.LeaseID = "lease_1"
	relOp.LeaseReleased = true
	if err := s.SetLeaseReleased(release, relOp); err != nil {
		t.Fatal(err)
	}
	intent := CheckpointIntent{
		OperationID: "pfck_1", ExpectedHeadCommitID: "cmt_base", TreeHash: "sha256:cc",
		CanonicalRequestHash: "sha256:dd", AuxiliaryBlobDigestsHash: "sha256:aux", WALWatermark: 42, MutationCount: 3, ByteCount: 99, CreatedAtMs: 40,
	}
	if err := s.PutCheckpointIntent(intent); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := reopened.Operation("op-1")
	if !ok || got.HeadCommitID != "cmt_op-1" || got.Fingerprint != "sha256:fp-op-1" {
		t.Fatalf("op-1 after reopen: ok=%v %+v", ok, got)
	}
	if q, ok := reopened.Operation("op-q"); !ok || q.HeadCommitID != marker.HeadCommitID {
		t.Fatalf("quiesce op after reopen: ok=%v %+v", ok, q)
	}
	m := reopened.Quiesced()
	if m == nil || m.HeadCommitID != "cmt_final" || m.OperationID != "op-q" {
		t.Fatalf("marker after reopen: %+v", m)
	}
	f := reopened.LeaseRelease()
	if f == nil || f.LeaseID != "lease_1" || f.OperationID != "op-r" {
		t.Fatalf("lease-release fact after reopen: %+v", f)
	}
	i := reopened.CheckpointIntent()
	if i == nil || !i.Pending() || i.WALWatermark != 42 || i.ExpectedHeadCommitID != "cmt_base" || i.AuxiliaryBlobDigestsHash != "sha256:aux" {
		t.Fatalf("intent after reopen: %+v", i)
	}
	if err := reopened.ResolveCheckpointIntent("pfck_1", "committed", 50); err != nil {
		t.Fatal(err)
	}
	if err := reopened.FinalizeCheckpointIntent("pfck_1", 51); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if i := again.CheckpointIntent(); i == nil || i.Pending() || i.Resolution != "committed" || i.LocalFinalizedAtMs != 51 {
		t.Fatalf("resolved intent after second reopen: %+v", i)
	}
}

// TestClearQuiescedForForeignInstance: a marker belonging to the SAME instance
// (or an identity-less marker seen by an identity-less process) is preserved; a
// marker from a REPLACED instance is cleared for the new instance id — along
// with its dependent lease-release fact — while receipts stay answerable.
func TestClearQuiescedForForeignInstance(t *testing.T) {
	s, path := tempStore(t)
	marker := QuiesceMarker{VolumeID: "v", Branch: "b", AuthorityInstanceID: "pfai_old", OperationID: "op", HeadCommitID: "h", TreeHash: "sha256:aa", CompletedAtMs: 1}
	qop := quiesceOp("op", 1)
	qop.VolumeID, qop.Branch, qop.AuthorityInstanceID = marker.VolumeID, marker.Branch, marker.AuthorityInstanceID
	qop.HeadCommitID, qop.TreeHash = marker.HeadCommitID, marker.TreeHash
	if err := s.SetQuiesced(marker, qop); err != nil {
		t.Fatal(err)
	}

	// Same instance: kept.
	if err := s.ClearQuiescedForForeignInstance("pfai_old"); err != nil {
		t.Fatal(err)
	}
	if s.Quiesced() == nil {
		t.Fatal("marker for the same instance must be preserved")
	}
	// Empty new identity: kept (conservative).
	if err := s.ClearQuiescedForForeignInstance(""); err != nil {
		t.Fatal(err)
	}
	if s.Quiesced() == nil {
		t.Fatal("marker must be preserved when the new process has no identity")
	}
	// Foreign instance: cleared, durably; the quiesce RECEIPT survives.
	if err := s.ClearQuiescedForForeignInstance("pfai_new"); err != nil {
		t.Fatal(err)
	}
	if s.Quiesced() != nil {
		t.Fatal("marker from a replaced instance must be cleared")
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Quiesced() != nil {
		t.Fatal("marker clear was not persisted")
	}
	if _, ok := reopened.Operation("op"); !ok {
		t.Fatal("the quiesce receipt must survive the marker clear (late retries stay answerable)")
	}
}

// TestPruneLeavesExplicitTombstones: pruning past the retention bound never
// silently forgets an operation id — the pruned receipt becomes an explicit
// tombstone, so a late retry is told "expired" instead of re-executing.
func TestPruneLeavesExplicitTombstones(t *testing.T) {
	s, path := tempStore(t)
	for i := 0; i < maxOperations+10; i++ {
		if err := s.RecordOperation(op(fmt.Sprintf("op-%d", i), int64(i+1))); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.Operation("op-0"); ok {
		t.Fatal("oldest operation should have been pruned")
	}
	ts, ok := s.Tombstone("op-0")
	if !ok || ts.Fingerprint != "sha256:fp-op-0" || ts.Kind != KindCheckpoint {
		t.Fatalf("pruned receipt must leave an explicit tombstone: ok=%v %+v", ok, ts)
	}
	if _, ok := s.Operation(fmt.Sprintf("op-%d", maxOperations+9)); !ok {
		t.Fatal("newest operation must survive pruning")
	}
	// Re-recording a tombstoned id is refused (it can never be re-executed).
	if err := s.RecordOperation(op("op-0", 999)); err == nil {
		t.Fatal("re-recording an expired operation id must fail")
	}
	// Tombstones survive reopen.
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Tombstone("op-0"); !ok {
		t.Fatal("tombstones must be durable")
	}
}

func TestEvictReceiptsAreBoundedAndTombstoned(t *testing.T) {
	s, _ := tempStore(t)
	for i := 0; i < maxOperations+10; i++ {
		receipt := op(fmt.Sprintf("evict-%d", i), int64(i+1))
		receipt.Kind = KindEvict
		receipt.WALEpoch = 1
		receipt.AppliedLSN = uint64(i)
		receipt.CoherenceGeneration = 1
		receipt.State = "evicted"
		receipt.HeadCommitID, receipt.TreeHash, receipt.Committed = "", "", false
		if err := s.RecordOperation(receipt); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.Operation("evict-0"); ok {
		t.Fatal("oldest ordinary evict receipt should have been compacted")
	}
	if tombstone, ok := s.Tombstone("evict-0"); !ok || tombstone.Kind != KindEvict {
		t.Fatalf("evict compaction did not leave an exact tombstone: ok=%v %+v", ok, tombstone)
	}
}

// TestTerminalReceiptsAreNeverPruned: quiesce and lease-release receipts are the
// saga's completion facts; pruning drops only checkpoint receipts.
func TestTerminalReceiptsAreNeverPruned(t *testing.T) {
	s, _ := tempStore(t)
	marker := QuiesceMarker{
		VolumeID: "vol_1", Branch: "main", AuthorityInstanceID: "pfai_1",
		OperationID: "op-q", HeadCommitID: "cmt_q", TreeHash: "sha256:aa", CompletedAtMs: 1,
	}
	qop := quiesceOp("op-q", 1)
	qop.HeadCommitID, qop.TreeHash = marker.HeadCommitID, marker.TreeHash
	if err := s.SetQuiesced(marker, qop); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxOperations+16; i++ {
		if err := s.RecordOperation(op(fmt.Sprintf("op-%d", i), int64(i+2))); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.Operation("op-q"); !ok {
		t.Fatal("the terminal quiesce receipt must never be pruned")
	}
}

// TestOpenRejectsCorruptFile: torn/garbage stores, unknown versions, duplicate
// ids, missing fingerprints, and illegal transitions must all fail loudly on
// load — silently discarding saga state could re-execute a completed quiesce.
func TestOpenRejectsCorruptFile(t *testing.T) {
	write := func(t *testing.T, contents string) string {
		t.Helper()
		path := PathFor(filepath.Join(t.TempDir(), "primary.wal"))
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	mustFail := func(t *testing.T, name, contents string) {
		t.Helper()
		if _, err := Open(write(t, contents)); err == nil {
			t.Fatalf("%s: corrupt store must not open silently", name)
		}
	}

	mustFail(t, "not json", "{not json")
	mustFail(t, "unsupported version", `{"version":1,"operations":[]}`)
	mustFail(t, "missing fingerprint", `{"version":2,"operations":[{"id":"a","kind":"checkpoint","volumeId":"v","branch":"b","headCommitId":"h","treeHash":"t","completedAtMs":1}]}`)
	mustFail(t, "unknown kind", `{"version":2,"operations":[{"id":"a","kind":"explode","fingerprint":"f","volumeId":"v","branch":"b","completedAtMs":1}]}`)
	dup := `{"version":2,"operations":[` +
		`{"id":"a","kind":"checkpoint","fingerprint":"f","volumeId":"v","branch":"b","headCommitId":"h","treeHash":"t","completedAtMs":1},` +
		`{"id":"a","kind":"checkpoint","fingerprint":"f2","volumeId":"v","branch":"b","headCommitId":"h2","treeHash":"t2","completedAtMs":2}]}`
	mustFail(t, "duplicate ids", dup)
	dupTombstone := `{"version":2,"operations":[` +
		`{"id":"a","kind":"checkpoint","fingerprint":"f","volumeId":"v","branch":"b","headCommitId":"h","treeHash":"t","completedAtMs":1}],` +
		`"tombstones":[{"id":"a","kind":"checkpoint","fingerprint":"f","expiredAtMs":9}]}`
	mustFail(t, "duplicate across receipt+tombstone", dupTombstone)
	markerWithoutReceipt := `{"version":2,"operations":[],"quiesced":{"volumeId":"v","branch":"b","operationId":"ghost","headCommitId":"h","treeHash":"t","completedAtMs":1}}`
	mustFail(t, "marker naming an unanswerable operation", markerWithoutReceipt)
	releaseWithoutQuiesce := `{"version":2,"operations":[],"leaseRelease":{"volumeId":"v","branch":"b","operationId":"op","releasedAtMs":1}}`
	mustFail(t, "lease release without quiesce (illegal transition)", releaseWithoutQuiesce)
	finalizedPendingCheckpoint := `{"version":2,"operations":[],"checkpointIntent":{"operationId":"pfck","treeHash":"t","canonicalRequestHash":"c","walWatermark":1,"createdAtMs":1,"localFinalizedAtMs":2}}`
	mustFail(t, "checkpoint finalized before a landed outcome", finalizedPendingCheckpoint)
	unknownCheckpointOutcome := `{"version":2,"operations":[],"checkpointIntent":{"operationId":"pfck","treeHash":"t","canonicalRequestHash":"c","walWatermark":1,"createdAtMs":1,"resolution":"maybe","resolvedAtMs":2}}`
	mustFail(t, "unknown checkpoint outcome", unknownCheckpointOutcome)
	mustFail(t, "unknown top-level field", `{"version":2,"operations":[],"surprise":true}`)
	mustFail(t, "unknown operation field", `{"version":2,"operations":[{"id":"a","kind":"checkpoint","fingerprint":"f","volumeId":"v","branch":"b","headCommitId":"h","treeHash":"t","completedAtMs":1,"surprise":true}]}`)
	mustFail(t, "duplicate top-level member", `{"version":2,"version":2,"operations":[]}`)
	mustFail(t, "duplicate nested member", `{"version":2,"operations":[{"id":"a","id":"a","kind":"checkpoint","fingerprint":"f","volumeId":"v","branch":"b","headCommitId":"h","treeHash":"t","completedAtMs":1}]}`)
	mustFail(t, "numeric uint64 evict proof", `{"version":2,"operations":[{"id":"e","kind":"evict","fingerprint":"f","volumeId":"v","branch":"b","completedAtMs":1,"state":"evicted","walEpoch":18446744073709551615,"appliedLsn":"0","coherenceGeneration":"1","walPoisoned":false}]}`)
	mustFail(t, "incomplete evict proof", `{"version":2,"operations":[{"id":"e","kind":"evict","fingerprint":"f","volumeId":"v","branch":"b","completedAtMs":1,"state":"evicted","walEpoch":"1","appliedLsn":"0","walPoisoned":false}]}`)
	markerMismatch := `{"version":2,"operations":[{"id":"q","kind":"quiesce","fingerprint":"f","volumeId":"v","branch":"b","authorityInstanceId":"i","headCommitId":"h1","treeHash":"t","committed":true,"mutationCount":0,"byteCount":0,"completedAtMs":1,"state":"quiesced"}],"quiesced":{"volumeId":"v","branch":"b","authorityInstanceId":"i","operationId":"q","headCommitId":"h2","treeHash":"t","completedAtMs":1}}`
	mustFail(t, "quiesce marker mismatches receipt", markerMismatch)
	releaseMismatch := `{"version":2,"operations":[{"id":"q","kind":"quiesce","fingerprint":"fq","volumeId":"v","branch":"b","authorityInstanceId":"i","headCommitId":"h","treeHash":"t","committed":true,"mutationCount":0,"byteCount":0,"completedAtMs":1,"state":"quiesced"},{"id":"r","kind":"release-lease","fingerprint":"fr","volumeId":"v","branch":"b","authorityInstanceId":"i","headCommitId":"h","treeHash":"t","committed":false,"mutationCount":0,"byteCount":0,"completedAtMs":2,"state":"quiesced","leaseId":"lease-a","leaseReleased":true}],"quiesced":{"volumeId":"v","branch":"b","authorityInstanceId":"i","operationId":"q","headCommitId":"h","treeHash":"t","completedAtMs":1},"leaseRelease":{"volumeId":"v","branch":"b","authorityInstanceId":"i","leaseId":"lease-b","operationId":"r","releasedAtMs":2}}`
	mustFail(t, "lease fact mismatches receipt", releaseMismatch)
	oversizePath := PathFor(filepath.Join(t.TempDir(), "oversize.wal"))
	oversize, err := os.Create(oversizePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := oversize.Truncate(maxStoreBytes + 1); err != nil {
		_ = oversize.Close()
		t.Fatal(err)
	}
	if err := oversize.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(oversizePath); err == nil {
		t.Fatal("oversized store was read/decoded instead of rejected")
	}
}

// TestFingerprintMismatchOnRecord: reusing an operation id with a different
// canonical request is refused with the typed mismatch error.
func TestFingerprintMismatchOnRecord(t *testing.T) {
	s, _ := tempStore(t)
	if err := s.RecordOperation(op("dup", 1)); err != nil {
		t.Fatal(err)
	}
	conflicting := op("dup", 2)
	conflicting.Fingerprint = "sha256:other"
	err := s.RecordOperation(conflicting)
	var mismatch *ErrFingerprintMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("want ErrFingerprintMismatch, got %v", err)
	}
}

// TestReceiptIsImmutableForSameID: an exact replay is a no-op; changing result
// content under the same id/fingerprint is rejected.
func TestReceiptIsImmutableForSameID(t *testing.T) {
	s, _ := tempStore(t)
	original := op("dup", 1)
	if err := s.RecordOperation(original); err != nil {
		t.Fatal(err)
	}
	persistCalls := 0
	realPersist := s.persist
	s.persist = func(path string, candidate *state) (bool, error) {
		persistCalls++
		return realPersist(path, candidate)
	}
	if err := s.RecordOperation(original); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if persistCalls != 0 {
		t.Fatalf("exact immutable replay rewrote durable state %d times", persistCalls)
	}
	updated := op("dup", 2)
	updated.HeadCommitID = "cmt_v2"
	var mismatch *ErrReceiptMismatch
	if err := s.RecordOperation(updated); !errors.As(err, &mismatch) {
		t.Fatalf("changed immutable receipt = %v, want ErrReceiptMismatch", err)
	}
	got, ok := s.Operation("dup")
	if !ok || got != original {
		t.Fatalf("immutable receipt changed: ok=%v %+v", ok, got)
	}
}

// TestCheckpointIntentTransitions: a pending intent blocks a NEW intent for a
// different operation (the ambiguous dispatch must be reconciled first); a
// landed intent is replaceable only after its local WAL cut is finalized;
// resolving/finalizing both name the exact operation.
func TestCheckpointIntentTransitions(t *testing.T) {
	s, _ := tempStore(t)
	first := CheckpointIntent{OperationID: "pfck_1", TreeHash: "t", CanonicalRequestHash: "c", WALWatermark: 5, CreatedAtMs: 1}
	if err := s.PutCheckpointIntent(first); err != nil {
		t.Fatal(err)
	}
	changedSameID := first
	changedSameID.WALWatermark++
	if err := s.PutCheckpointIntent(changedSameID); err == nil {
		t.Fatal("the same operation id must not overwrite its durable intent content")
	}
	if err := s.PutCheckpointIntent(CheckpointIntent{OperationID: "pfck_2", TreeHash: "t2", CanonicalRequestHash: "c2", CreatedAtMs: 2}); err == nil {
		t.Fatal("a pending intent must not be silently replaced by a different operation")
	}
	if err := s.ResolveCheckpointIntent("pfck_other", "committed", 3); err == nil {
		t.Fatal("resolving a different operation id must fail")
	}
	if err := s.ResolveCheckpointIntent("pfck_1", "committed", 3); err != nil {
		t.Fatal(err)
	}
	if err := s.ResolveCheckpointIntent("pfck_1", "rejected", 4); err == nil {
		t.Fatal("a durable landed outcome must not be changed to rejected")
	}
	if err := s.PutCheckpointIntent(CheckpointIntent{OperationID: "pfck_2", TreeHash: "t2", CanonicalRequestHash: "c2", CreatedAtMs: 4}); err == nil {
		t.Fatal("a landed intent must not be replaced before its WAL cut is finalized")
	}
	if err := s.FinalizeCheckpointIntent("pfck_other", 4); err == nil {
		t.Fatal("finalizing a different operation id must fail")
	}
	if err := s.FinalizeCheckpointIntent("pfck_1", 4); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCheckpointIntent(CheckpointIntent{OperationID: "pfck_2", TreeHash: "t2", CanonicalRequestHash: "c2", CreatedAtMs: 4}); err != nil {
		t.Fatalf("a locally finalized intent must be replaceable: %v", err)
	}
}

func TestCheckpointIntentCannotFinalizeBeforeLandedOutcome(t *testing.T) {
	s, _ := tempStore(t)
	intent := CheckpointIntent{OperationID: "pfck_1", TreeHash: "t", CanonicalRequestHash: "c", WALWatermark: 5, CreatedAtMs: 1}
	if err := s.PutCheckpointIntent(intent); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeCheckpointIntent("pfck_1", 2); err == nil {
		t.Fatal("a pending dispatch cannot be locally finalized")
	}
	if err := s.ResolveCheckpointIntent("pfck_1", "rejected", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeCheckpointIntent("pfck_1", 3); err == nil {
		t.Fatal("a rejected dispatch has no committed WAL cut to finalize")
	}
}

// TestSetLeaseReleasedRequiresQuiesce: the lease-release fact is an illegal
// transition before the quiesced marker exists.
func TestSetLeaseReleasedRequiresQuiesce(t *testing.T) {
	s, _ := tempStore(t)
	relOp := op("op-r", 1)
	relOp.Kind = KindReleaseLease
	err := s.SetLeaseReleased(LeaseReleaseFact{VolumeID: "v", Branch: "b", OperationID: "op-r", ReleasedAtMs: 1}, relOp)
	if err == nil {
		t.Fatal("lease release before quiesce must be an illegal transition")
	}
}

// TestPersistedFileIsCanonicalJSON: sanity-check the on-disk contract the
// TypeScript authority manager parses (version 2, camelCase fields).
func TestPersistedFileIsCanonicalJSON(t *testing.T) {
	s, path := tempStore(t)
	if err := s.RecordOperation(op("op-1", 10)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["version"] != float64(CurrentVersion) {
		t.Fatalf("version = %v, want %d", decoded["version"], CurrentVersion)
	}
	ops, ok := decoded["operations"].([]any)
	if !ok || len(ops) != 1 {
		t.Fatalf("operations shape: %v", decoded["operations"])
	}
	entry := ops[0].(map[string]any)
	for _, key := range []string{"id", "kind", "fingerprint", "volumeId", "branch", "headCommitId", "completedAtMs"} {
		if _, ok := entry[key]; !ok {
			t.Fatalf("persisted operation missing %q: %v", key, entry)
		}
	}
}

func TestEvictRevisionUsesExactDecimalStringsAcrossReopen(t *testing.T) {
	s, path := tempStore(t)
	receipt := Operation{
		ID: "evict-max", Kind: KindEvict, Fingerprint: "sha256:evict-max",
		VolumeID: "vol_1", Branch: "main", AuthorityInstanceID: "pfai_1",
		CompletedAtMs: 123, State: "evicted",
		WALEpoch: ^uint64(0), AppliedLSN: ^uint64(0) - 1,
		CoherenceGeneration: ^uint64(0) - 2, WALPoisoned: false,
	}
	if err := s.RecordOperation(receipt); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, exact := range []string{
		`"walEpoch": "18446744073709551615"`,
		`"appliedLsn": "18446744073709551614"`,
		`"coherenceGeneration": "18446744073709551613"`,
		`"walPoisoned": false`,
	} {
		if !strings.Contains(string(raw), exact) {
			t.Fatalf("durable receipt lacks exact field %s:\n%s", exact, raw)
		}
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Operation(receipt.ID)
	if !ok || got != receipt {
		t.Fatalf("exact uint64 receipt changed across reopen: ok=%v\n got=%+v\nwant=%+v", ok, got, receipt)
	}
}

func TestDefinitePersistFailureDoesNotPublishCandidate(t *testing.T) {
	s, path := tempStore(t)
	baseline := op("baseline", 1)
	if err := s.RecordOperation(baseline); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("disk full before rename")
	s.persist = func(string, *state) (bool, error) { return false, sentinel }
	if err := s.RecordOperation(op("not-durable", 2)); !errors.Is(err, sentinel) {
		t.Fatalf("persist failure = %v, want sentinel", err)
	}
	if _, ok := s.Operation("not-durable"); ok {
		t.Fatal("failed candidate became visible in memory")
	}
	if err := s.Healthy(); err != nil {
		t.Fatalf("definite pre-rename failure must remain retryable: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Operation("not-durable"); ok {
		t.Fatal("failed candidate reached disk")
	}
}

func TestAmbiguousPersistFailurePoisonsUntilReopen(t *testing.T) {
	s, path := tempStore(t)
	if err := s.RecordOperation(op("baseline", 1)); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("directory fsync failed after rename")
	s.persist = func(path string, candidate *state) (bool, error) {
		replaced, err := persistState(path, candidate)
		if err != nil {
			return replaced, err
		}
		return true, sentinel
	}
	err := s.RecordOperation(op("ambiguous", 2))
	var poisoned *ErrStorePoisoned
	if !errors.As(err, &poisoned) || !errors.Is(err, sentinel) {
		t.Fatalf("ambiguous persist = %v, want poisoned sentinel", err)
	}
	if _, ok := s.Operation("ambiguous"); ok {
		t.Fatal("ambiguous candidate must not publish in the live Store")
	}
	if err := s.Healthy(); !errors.As(err, &poisoned) {
		t.Fatalf("store did not remain poisoned: %v", err)
	}
	if err := s.RecordOperation(op("later", 3)); !errors.As(err, &poisoned) {
		t.Fatalf("poisoned store admitted a later mutation: %v", err)
	}
	// Reopen is the reconciliation boundary: the complete renamed candidate is
	// either present, as here, or the previous complete image survives.
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Operation("ambiguous"); !ok {
		t.Fatal("reopen did not recover the complete renamed candidate")
	}
}

func TestBoundedTombstoneRolloverClosesExactGeneration(t *testing.T) {
	st := state{Version: CurrentVersion}
	for i := 0; i < maxTombstones; i++ {
		st.Tombstones = append(st.Tombstones, Tombstone{
			ID: fmt.Sprintf("old-%d", i), Kind: KindCheckpoint, Fingerprint: fmt.Sprintf("fp-%d", i),
			VolumeID: "vol_1", Branch: "main", AuthorityInstanceID: "pfai_1", ExpiredAtMs: int64(i + 1),
		})
	}
	for i := 0; i < maxOperations+1; i++ {
		st.Operations = append(st.Operations, op(fmt.Sprintf("live-%d", i), int64(maxTombstones+i+1)))
	}
	prune(&st, 10_000)
	if len(st.Operations) != maxOperations || len(st.Tombstones) != maxTombstones {
		t.Fatalf("retention is not bounded: operations=%d tombstones=%d", len(st.Operations), len(st.Tombstones))
	}
	if !st.scopeClosed("vol_1", "main", "pfai_1") {
		t.Fatal("dropping an exact tombstone did not close its authority generation")
	}
	if st.scopeClosed("vol_1", "main", "pfai_2") {
		t.Fatal("retention floor leaked into a replacement authority generation")
	}
	store := &Store{st: st, persist: persistState}
	if expired, err := store.UnknownExpired("vol_1", "main", "pfai_1"); err != nil || !expired {
		t.Fatalf("closed generation unknown lookup = (%v, %v), want expired", expired, err)
	}
	if expired, err := store.UnknownExpired("vol_1", "main", "pfai_2"); err != nil || expired {
		t.Fatalf("replacement generation unknown lookup = (%v, %v), want open", expired, err)
	}
	replacement := op("replacement-generation", 20_001)
	replacement.AuthorityInstanceID = "pfai_2"
	if _, err := upsert(&st, replacement); err != nil {
		t.Fatalf("replacement authority generation should remain open: %v", err)
	}
	if err := st.validate("retention-test"); err != nil {
		t.Fatalf("bounded retained state is invalid: %v", err)
	}
}

func TestLegacyUnscopedTombstoneRolloverFailsClosedGlobally(t *testing.T) {
	st := state{Version: CurrentVersion}
	for i := 0; i < maxTombstones; i++ {
		st.Tombstones = append(st.Tombstones, Tombstone{
			ID: fmt.Sprintf("legacy-%d", i), Kind: KindCheckpoint, Fingerprint: "legacy", ExpiredAtMs: int64(i + 1),
		})
	}
	for i := 0; i < maxOperations+1; i++ {
		st.Operations = append(st.Operations, op(fmt.Sprintf("live-global-%d", i), int64(maxTombstones+i+1)))
	}
	prune(&st, 20_000)
	if !st.RejectAllUnknown || !st.scopeClosed("any", "branch", "generation") {
		t.Fatal("forgetting a legacy unscoped tombstone must reject every unknown id")
	}
}

func TestOpenNormalizesLegacyVersion2BoundsWithoutLosingTerminalFacts(t *testing.T) {
	path := PathFor(filepath.Join(t.TempDir(), "legacy-bounds.wal"))
	marker := QuiesceMarker{
		VolumeID: "vol_1", Branch: "main", AuthorityInstanceID: "pfai_1",
		OperationID: "terminal-q", HeadCommitID: "cmt-terminal", TreeHash: "sha256:terminal", CompletedAtMs: 1,
	}
	qop := quiesceOp(marker.OperationID, marker.CompletedAtMs)
	qop.HeadCommitID, qop.TreeHash = marker.HeadCommitID, marker.TreeHash
	legacy := state{Version: CurrentVersion, Operations: []Operation{qop}, Quiesced: &marker}
	for i := 0; i < maxOperations; i++ {
		legacy.Operations = append(legacy.Operations, op(fmt.Sprintf("legacy-live-%d", i), int64(i+2)))
	}
	raw, err := json.MarshalIndent(&legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	normalized, err := Open(path)
	if err != nil {
		t.Fatalf("open legacy v2 over bound: %v", err)
	}
	if _, ok := normalized.Operation(marker.OperationID); !ok || normalized.Quiesced() == nil {
		t.Fatal("normalization discarded the canonical terminal fact")
	}
	if len(normalized.st.Operations) != maxOperations || len(normalized.st.Tombstones) != 1 {
		t.Fatalf("normalization bounds = operations %d tombstones %d", len(normalized.st.Operations), len(normalized.st.Tombstones))
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("normalized image did not survive reopen: %v", err)
	}
}
