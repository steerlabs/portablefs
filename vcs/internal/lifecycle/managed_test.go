package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/opstate"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// blobsFake is the minimal content.BlobReader the working tree needs; the
// managed harness starts from an empty manifest, so no blob is ever read.
type blobsFake struct{}

func (blobsFake) Blob(_ context.Context, d string) ([]byte, error) {
	return nil, fmt.Errorf("no blob %s", d)
}

type fakeLease struct {
	mu       sync.Mutex
	id       string
	err      error
	releases int
}

func (l *fakeLease) LeaseID() string { return l.id }
func (l *fakeLease) Release(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.releases++
	return nil
}

func (l *fakeLease) releaseCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.releases
}

// fakeStepDown is a JournalStepDown with injectable failures, mirroring the
// cmd/vcs adapter over remotejournal.Log: first call executes, replays return
// the identical proof.
type fakeStepDown struct {
	mu          sync.Mutex
	calls       int
	failNext    error
	proof       JournalSuspendProof
	sawDeadline bool
}

func (f *fakeStepDown) StepDown(ctx context.Context) (JournalSuspendProof, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if _, has := ctx.Deadline(); has {
		f.sawDeadline = true
	}
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return JournalSuspendProof{}, err
	}
	proof := f.proof
	proof.Replayed = f.calls > 1
	return proof, nil
}

func (f *fakeStepDown) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type managedHarness struct {
	fs         *workfs.FS
	w          *wal.WAL
	controller *Controller
	journal    *fakeStepDown
	lease      *fakeLease
	stops      atomic.Int32
}

// newManagedHarness builds the MANAGED controller shape: no in-process
// history materialization, a process-local memory store, and the journal
// step-down seam. The file WAL under the workfs stands in for the remote
// journal's DurableLog.
func newManagedHarness(t *testing.T) *managedHarness {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "managed.wal"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, blobsFake{}, w)
	if err != nil {
		t.Fatal(err)
	}
	h := &managedHarness{
		fs:      fs,
		w:       w,
		journal: &fakeStepDown{proof: JournalSuspendProof{NextSeq: 42, TipDigest: strings.Repeat("ab", 32)}},
		lease:   &fakeLease{id: "lease_1"},
	}
	h.controller = NewController(Deps{
		FS:            fs,
		StopDataPlane: func() { h.stops.Add(1) },
		Store:         opstate.NewMemory(),
		Identity:      Identity{VolumeID: "vol_1", Branch: "main", InstanceID: "pfvcs_1"},
		Lease:         h.lease,
		Journal:       h.journal,
	})
	return h
}

func (h *managedHarness) write(t *testing.T, path, content string) {
	t.Helper()
	if err := h.fs.ApplyBatch([]wal.Record{
		{Op: wal.OpCreate, Path: path, Mode: 0o644},
		{Op: wal.OpWrite, Path: path, Offset: 0, Data: []byte(content)},
	}, ""); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func managedReq(id string) OpRequest {
	return OpRequest{OperationID: id, VolumeID: "vol_1", Branch: "main", AuthorityInstanceID: "pfvcs_1"}
}

// TestManagedEvictExecutesExactJournalStepDown: the ordinary evict closes the
// one admission gate, drains, executes the step-down exactly once, and the
// receipt carries journalSuspended + the exact nextSeq/tipDigest. Replays
// under the same operation id repeat the receipt without another step-down;
// later appends fail sealed.
func TestManagedEvictExecutesExactJournalStepDown(t *testing.T) {
	h := newManagedHarness(t)
	h.write(t, "a.txt", "v1")

	op, oerr := h.controller.EvictOperation(context.Background(), managedReq("op-evict-1"))
	if oerr != nil {
		t.Fatalf("evict: %v", oerr)
	}
	if op.State != string(StateEvicted) || !op.JournalSuspended {
		t.Fatalf("evict receipt lacks the journal suspension: %+v", op)
	}
	if op.JournalNextSeq != 42 || op.JournalTipDigest != strings.Repeat("ab", 32) {
		t.Fatalf("evict receipt journal facts are not exact: %+v", op)
	}
	if op.HeadCommitID != "" || op.Committed {
		t.Fatalf("managed evict must make no checkpoint claims: %+v", op)
	}
	if h.journal.callCount() != 1 {
		t.Fatalf("step-down executed %d times, want 1", h.journal.callCount())
	}
	// The suspension is ALWAYS bounded: even an Evict caller with no deadline
	// of its own (context.Background at SIGTERM) hands the step-down a
	// deadline-bearing context (Deps.SuspendDeadline, default 30s).
	h.journal.mu.Lock()
	sawDeadline := h.journal.sawDeadline
	h.journal.mu.Unlock()
	if !sawDeadline {
		t.Fatal("the journal step-down ran without a bounded context")
	}
	if h.stops.Load() == 0 {
		t.Fatal("evict did not close the data plane")
	}

	// Lost-response replay: identical receipt, no second step-down.
	dup, oerr := h.controller.EvictOperation(context.Background(), managedReq("op-evict-1"))
	if oerr != nil {
		t.Fatalf("evict replay: %v", oerr)
	}
	if dup != op {
		t.Fatalf("evict replay differs:\n first=%+v\n replay=%+v", op, dup)
	}
	if h.journal.callCount() != 1 {
		t.Fatalf("replay re-executed the step-down: %d calls", h.journal.callCount())
	}

	// Admission is sealed forever in this process.
	err := h.fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "late.txt", Mode: 0o644}}, "")
	if !errors.Is(err, workfs.ErrSealed) {
		t.Fatalf("post-evict append must fail sealed, got %v", err)
	}
}

// TestManagedEvictSuspendFailureStaysSealedAndRetryable: a failed step-down
// fails the eviction closed (no cached success, admission sealed) and the
// SAME operation id retries the step-down and then succeeds — never a
// fabricated suspension.
func TestManagedEvictSuspendFailureStaysSealedAndRetryable(t *testing.T) {
	h := newManagedHarness(t)
	// A real journal epoch is always >= 1; the file-WAL stand-in mints its
	// epoch on the first write.
	h.write(t, "a.txt", "v1")
	h.journal.failNext = fmt.Errorf("journal unreachable")

	_, oerr := h.controller.EvictOperation(context.Background(), managedReq("op-evict-1"))
	if oerr == nil || oerr.Code != CodeSuspendFailed {
		t.Fatalf("failed step-down must fail the eviction with %s, got %v", CodeSuspendFailed, oerr)
	}
	if h.controller.State() != StateEvictFailed {
		t.Fatalf("state = %s, want %s", h.controller.State(), StateEvictFailed)
	}
	// Admission sealed even though the eviction failed (fail closed).
	err := h.fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "late.txt", Mode: 0o644}}, "")
	if !errors.Is(err, workfs.ErrSealed) {
		t.Fatalf("append after failed evict must fail sealed, got %v", err)
	}

	retried, oerr := h.controller.EvictOperation(context.Background(), managedReq("op-evict-1"))
	if oerr != nil {
		t.Fatalf("retried evict: %v", oerr)
	}
	if !retried.JournalSuspended || retried.JournalNextSeq != 42 {
		t.Fatalf("retried evict lacks the exact suspension: %+v", retried)
	}
	if h.journal.callCount() != 2 {
		t.Fatalf("step-down calls = %d, want 2 (one failure, one success)", h.journal.callCount())
	}
}

// TestManagedCheckpointQuiesceReleaseAnswerHistoryCutUnavailable: every
// history-materialization endpoint answers the explicit typed refusal (the
// managed shape) — never a nil-pointer crash, never a silent no-op — and
// nothing is sealed or stopped by asking.
func TestManagedCheckpointQuiesceReleaseAnswerHistoryCutUnavailable(t *testing.T) {
	h := newManagedHarness(t)
	for name, run := range map[string]func() (opstate.Operation, *OpError){
		"checkpoint": func() (opstate.Operation, *OpError) {
			return h.controller.Checkpoint(context.Background(), managedReq("op-ckpt"))
		},
		"quiesce": func() (opstate.Operation, *OpError) {
			return h.controller.Quiesce(context.Background(), managedReq("op-quiesce"))
		},
		"release-lease": func() (opstate.Operation, *OpError) {
			return h.controller.ReleaseLease(context.Background(), managedReq("op-release"))
		},
	} {
		_, oerr := run()
		if oerr == nil || oerr.Code != CodeHistoryCutUnavailable || oerr.Status != 501 {
			t.Fatalf("%s must answer %s/501, got %v", name, CodeHistoryCutUnavailable, oerr)
		}
	}
	if h.controller.State() != StateServing {
		t.Fatalf("history-cut refusals must not change lifecycle state, got %s", h.controller.State())
	}
	if h.stops.Load() != 0 {
		t.Fatal("history-cut refusals must not stop the data plane")
	}
	// The volume still serves writes afterwards.
	if err := h.fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "still-serving.txt", Mode: 0o644}}, ""); err != nil {
		t.Fatalf("write after refusals: %v", err)
	}
}

// TestReleaseAfterEvictHandshake: the ordinary early writer-claim release is
// legal exactly once, only after a completed release-safe eviction, and it
// closes terminal quiesce admission afterwards (a claim that may already be
// gone must never anchor a final cut).
func TestReleaseAfterEvictHandshake(t *testing.T) {
	h := newManagedHarness(t)
	h.write(t, "released.txt", "ordinary drain")

	// Before any eviction: refused.
	if err := h.controller.ReleaseAfterEvict(context.Background()); err == nil {
		t.Fatal("release before eviction must be refused")
	}

	if result, err := h.controller.Evict(context.Background()); err != nil || result.State != StateEvicted {
		t.Fatalf("evict = %+v, %v", result, err)
	}
	if err := h.controller.ReleaseAfterEvict(context.Background()); err != nil {
		t.Fatalf("release after evict: %v", err)
	}
	if h.lease.releaseCount() != 1 {
		t.Fatalf("writer releases = %d, want 1", h.lease.releaseCount())
	}
	// A second attempt is ambiguous and refused; the claim was touched once.
	if err := h.controller.ReleaseAfterEvict(context.Background()); err == nil {
		t.Fatal("second release attempt must be refused")
	}
	if h.lease.releaseCount() != 1 {
		t.Fatalf("writer releases = %d after refused retry, want 1", h.lease.releaseCount())
	}
	// A late terminal quiesce is refused by the release handshake, not by the
	// history-cut answer: the claim may already be gone.
	if _, oerr := h.controller.Quiesce(context.Background(), managedReq("op-too-late")); oerr == nil || oerr.Code != CodeNotWritable {
		t.Fatalf("late quiesce = %v, want %s", oerr, CodeNotWritable)
	}
}

// TestMemoryStoreExactReceipts: the managed in-process store keeps exact
// receipts (same id + fingerprint replays; different fingerprint conflicts)
// and never pretends to have checkpoint/quiesce durability domains.
func TestMemoryStoreExactReceipts(t *testing.T) {
	store := opstate.NewMemory()
	op := opstate.Operation{
		ID: "op-1", Kind: opstate.KindEvict, Fingerprint: "fp-1",
		VolumeID: "vol_1", Branch: "main", AuthorityInstanceID: "pfvcs_1",
		CompletedAtMs: 1, State: "evicted",
		WALEpoch: 1, AppliedLSN: 5, CoherenceGeneration: 2,
	}
	if err := store.RecordOperation(op); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, ok := store.Operation("op-1")
	if !ok || got.AppliedLSN != 5 {
		t.Fatalf("stored receipt not replayable: %+v ok=%v", got, ok)
	}
	conflicting := op
	conflicting.Fingerprint = "fp-2"
	if err := store.RecordOperation(conflicting); err == nil {
		t.Fatal("same id with a different fingerprint must conflict")
	}
	if expired, err := store.UnknownExpired("vol_1", "main", "pfvcs_1"); err != nil || expired {
		t.Fatalf("memory store never expires receipts, got expired=%v err=%v", expired, err)
	}
	if err := store.PutCheckpointIntent(opstate.CheckpointIntent{}); err == nil {
		t.Fatal("checkpoint intents must be refused loudly in managed mode")
	}
	if err := store.SetQuiesced(opstate.QuiesceMarker{}, op); err == nil {
		t.Fatal("quiesce markers must be refused loudly in managed mode")
	}
}
