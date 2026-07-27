package workfs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// fakeEntryLog is an honest in-memory PFJ3 entry log: it stores the exact
// encoded bytes at reservation, marks them durable at CommitThrough, replays
// by decoding those identical bytes, and enforces the admission-fact
// issue/freeze/consume contract exactly as the SQL append does (exact floor
// at issue, manifest-derived facts, purpose/session binding, deletion at
// consume, floor advancement).
type fakeEntryLog struct {
	mu      sync.Mutex
	rows    [][]byte
	durable uint64
	dbNow   int64
	floor   int64
	facts   map[[16]byte]*fakeFact
	failaAt int // if >0, fail the Nth AppendEntriesBuffered call
	appends int
}

type fakeFact struct {
	issued  int64
	expires int64
	purpose pfc2.FactPurpose
	session pfc2.SessionRef
}

func newFakeEntryLog() *fakeEntryLog {
	return &fakeEntryLog{dbNow: 1_700_000_000_000, facts: map[[16]byte]*fakeFact{}}
}

func (f *fakeEntryLog) RecordCodec() string  { return pfj3.RecordCodec }
func (f *fakeEntryLog) ControlCodec() string { return pfj3.ControlCodec }

func (f *fakeEntryLog) IssueAdmissionFact(scope pfc2.FactScope) (pfc2.IssuedFact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if scope.Session.SessionID == "" || scope.Session.Generation == 0 {
		return pfc2.IssuedFact{}, fmt.Errorf("fake: fact requires a session")
	}
	if !scope.Purpose.Valid() {
		return pfc2.IssuedFact{}, fmt.Errorf("fake: fact requires a known purpose")
	}
	if scope.PriorDbTimeFloorMs != f.floor {
		return pfc2.IssuedFact{}, fmt.Errorf("fake: issuer floor %d does not equal the durable floor %d",
			scope.PriorDbTimeFloorMs, f.floor)
	}
	f.dbNow += 7 // database time advances between admissions
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return pfc2.IssuedFact{}, err
	}
	f.facts[id] = &fakeFact{
		issued: f.dbNow, expires: f.dbNow + 30_000,
		purpose: scope.Purpose, session: scope.Session,
	}
	return pfc2.IssuedFact{
		Fact:            pfc2.TimeFact{Source: pfc2.TimeSourceDB, FactID: id, DbMs: f.dbNow},
		FactExpiresDbMs: f.dbNow + 30_000,
	}, nil
}

func (f *fakeEntryLog) AppendEntriesBuffered(entries []pfj3.JournalEntry) (uint64, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.appends++
	if f.failaAt > 0 && f.appends == f.failaAt {
		return 0, 0, fmt.Errorf("fake: injected append failure")
	}
	first := uint64(len(f.rows))
	staged := make([][]byte, 0, len(entries))
	consumed := map[[16]byte]bool{}
	floor := f.floor
	for i := range entries {
		entries[i].LSN = first + uint64(i)
		if entries[i].Tree != nil {
			entries[i].Tree.Seq = entries[i].LSN
		}
		// Validate + consume the manifest-derived facts exactly once, in
		// order, exactly as the SQL append transaction does.
		manifest, err := entries[i].FactManifest()
		if err != nil {
			return 0, 0, err
		}
		for _, ref := range manifest {
			fact := f.facts[ref.FactID]
			if fact == nil || consumed[ref.FactID] {
				return 0, 0, fmt.Errorf("fake: admission fact unknown or already consumed")
			}
			if fact.purpose != ref.Purpose || fact.session != ref.Session {
				return 0, 0, fmt.Errorf("fake: admission fact purpose/session mismatch")
			}
			if fact.issued != ref.DbMs || fact.expires <= f.dbNow || fact.issued < floor {
				return 0, 0, fmt.Errorf("fake: admission fact rejected")
			}
			consumed[ref.FactID] = true
			if fact.issued > floor {
				floor = fact.issued
			}
		}
		payload, err := pfj3.Encode(&entries[i])
		if err != nil {
			return 0, 0, err
		}
		staged = append(staged, payload)
	}
	for id := range consumed {
		delete(f.facts, id)
	}
	f.floor = floor
	f.rows = append(f.rows, staged...)
	return first, first + uint64(len(entries)), nil
}

func (f *fakeEntryLog) CommitThrough(seq uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if seq+1 > f.durable {
		f.durable = seq + 1
	}
	return nil
}

func (f *fakeEntryLog) ReplayEntriesInto(fn func(pfj3.JournalEntry) error) error {
	f.mu.Lock()
	rows := append([][]byte(nil), f.rows[:f.durable]...)
	f.mu.Unlock()
	for _, payload := range rows {
		entry, err := pfj3.Decode(payload)
		if err != nil {
			return err
		}
		if err := fn(entry); err != nil {
			return err
		}
	}
	return nil
}

// Record-shaped surface: never valid on a PFJ3 log.
func (f *fakeEntryLog) AppendBatchBuffered([]wal.Record) (uint64, uint64, error) {
	return 0, 0, fmt.Errorf("fake: PFJ3 log has no record append")
}
func (f *fakeEntryLog) ReplayInto(func(wal.Record) error) error {
	return fmt.Errorf("fake: PFJ3 log has no record replay")
}
func (f *fakeEntryLog) RecordsBelowInto(uint64, func(wal.Record) error) error {
	return fmt.Errorf("fake: PFJ3 log has no record replay")
}

func (f *fakeEntryLog) Watermark() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.durable
}
func (f *fakeEntryLog) Bounds() wal.LogBounds       { return wal.ProductionLogBounds() }
func (f *fakeEntryLog) OverCapacity() bool          { return false }
func (f *fakeEntryLog) SetCapacity(int64)           {}
func (f *fakeEntryLog) BacklogBytes() int64         { return 0 }
func (f *fakeEntryLog) CompactedThrough() uint64    { return 0 }
func (f *fakeEntryLog) Epoch() uint64               { return 1 }
func (f *fakeEntryLog) BaseCommitID() string        { return "" }
func (f *fakeEntryLog) Poison()                     {}
func (f *fakeEntryLog) IsPoisoned() bool            { return false }
func (f *fakeEntryLog) PoisonedCh() <-chan struct{} { return nil }
func (f *fakeEntryLog) CompactThrough(uint64) error { return fmt.Errorf("fake: no compaction") }
func (f *fakeEntryLog) PrepareCheckpointCut(cut wal.CheckpointCut) (wal.CheckpointCut, error) {
	return wal.CheckpointCut{}, fmt.Errorf("fake: no cuts")
}
func (f *fakeEntryLog) ResolveCheckpointCut(string, string, bool) error {
	return fmt.Errorf("fake: no cuts")
}
func (f *fakeEntryLog) FinalizeCheckpointCut(string) error { return fmt.Errorf("fake: no cuts") }
func (f *fakeEntryLog) CheckpointCutState() (wal.CheckpointCut, bool) {
	return wal.CheckpointCut{}, false
}
func (f *fakeEntryLog) CompactRecoveredCheckpoint(string) error { return fmt.Errorf("fake: no cuts") }
func (f *fakeEntryLog) RotateControlOnlyThrough(uint64, uint64) error {
	return fmt.Errorf("fake: no rotation")
}
func (f *fakeEntryLog) RecoverControlRotation() error { return nil }

var _ pfj3.EntryLog = (*fakeEntryLog)(nil)

// openManagedSession issues a fact and commits one SessionOpen row.
func openManagedSession(t *testing.T, fs *FS, id string, gen uint64) pfc2.SessionRef {
	t.Helper()
	ref := pfc2.SessionRef{SessionID: id, Generation: gen}
	issued, err := fs.IssueAdmissionFact(ref, pfc2.FactPurposeSessionOpen)
	if err != nil {
		t.Fatalf("issue fact: %v", err)
	}
	var token [pfc2.TokenHashBytes]byte
	token[0] = byte(gen) | 1
	open, err := pfc2.NewSessionOpenRecord(ref, "owner-"+id, token, 8, issued.Fact, 90*time.Second)
	if err != nil {
		t.Fatalf("build open: %v", err)
	}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{*open}, ""); err != nil {
		t.Fatalf("commit open: %v", err)
	}
	return ref
}

func managedDigest(t *testing.T, fs *FS) [32]byte {
	t.Helper()
	control, err := fs.ManagedControl()
	if err != nil {
		t.Fatal(err)
	}
	d, err := control.Project().Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestManagedCommitReplayEquivalence(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	ref := openManagedSession(t, fs, "pfs-m1", 1)

	// One exact enveloped tree write in its own row.
	reqHash := make([]byte, 32)
	reqHash[0] = 0x77
	tree := &wal.Record{
		Op: wal.OpCreate, Path: "a.txt", Mode: 0o644,
		Env: &wal.Envelope{SessionID: ref.SessionID, Generation: ref.Generation, Slot: 0, SlotSeq: 1, ReqHash: reqHash},
	}
	if _, err := fs.CommitEntry(tree, nil, ""); err != nil {
		t.Fatalf("commit tree: %v", err)
	}
	control, _ := fs.ManagedControl()
	var key pfc2.ExactKey
	key.Session, key.Slot, key.SlotSeq = ref, 0, 1
	copy(key.RequestHash[:], reqHash)
	if got := control.CheckExact(key); got.Disposition != pfc2.ExactReplay {
		t.Fatalf("exact disposition %v", got.Disposition)
	}

	// A control-only row: open pin.
	pin := pfc2.Record{Kind: pfc2.KindOpenPinChange, OpenPinChange: &pfc2.OpenPinChange{Session: ref, Ino: 2}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{pin}, ""); err != nil {
		t.Fatalf("commit pin: %v", err)
	}

	// Cold replay from the identical bytes rebuilds identical state.
	fs2, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("cold replay: %v", err)
	}
	if managedDigest(t, fs) != managedDigest(t, fs2) {
		t.Fatal("replayed control state diverged")
	}
	if _, err := fs2.Stat("a.txt"); err != nil {
		t.Fatalf("replayed tree missing file: %v", err)
	}
	// The replayed reducer replays the exact outcome too.
	control2, _ := fs2.ManagedControl()
	if got := control2.CheckExact(key); got.Disposition != pfc2.ExactReplay {
		t.Fatalf("replayed disposition %v", got.Disposition)
	}
}

func TestManagedStagingRollsBackAtomically(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	ref := openManagedSession(t, fs, "pfs-m2", 1)
	before := managedDigest(t, fs)
	reserved, _ := fs.ManagedReservedControl()
	beforeReserved, err := reserved.Project().Digest()
	if err != nil {
		t.Fatal(err)
	}

	// A row whose SECOND control is invalid (duplicate pin) must leave no
	// trace anywhere: reserved view, applied view, or journal.
	pin := pfc2.Record{Kind: pfc2.KindOpenPinChange, OpenPinChange: &pfc2.OpenPinChange{Session: ref, Ino: 9}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{pin, pin}, ""); err == nil {
		t.Fatal("duplicate pin row accepted")
	}
	if got := managedDigest(t, fs); got != before {
		t.Fatal("failed staging leaked into the applied view")
	}
	afterReserved, err := reserved.Project().Digest()
	if err != nil {
		t.Fatal(err)
	}
	if afterReserved != beforeReserved {
		t.Fatal("failed staging leaked into the reserved view")
	}

	// An append failure after clean staging also rolls back completely.
	log.failaAt = log.appends + 1
	if _, err := fs.CommitEntry(nil, []pfc2.Record{pin}, ""); err == nil {
		t.Fatal("injected append failure did not surface")
	}
	if got, _ := reserved.Project().Digest(); got != beforeReserved {
		t.Fatal("append failure leaked into the reserved view")
	}
	// And the same row commits cleanly afterwards (identity not consumed).
	if _, err := fs.CommitEntry(nil, []pfc2.Record{pin}, ""); err != nil {
		t.Fatalf("post-rollback commit: %v", err)
	}
}

func TestManagedFactConsumedExactlyOnce(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	ref := openManagedSession(t, fs, "pfs-m3", 1)

	// Re-journaling a record carrying an ALREADY-CONSUMED fact fails at the
	// append boundary (the fake enforces the same exactly-once rule SQL does).
	issued, err := fs.IssueAdmissionFact(ref, pfc2.FactPurposeSessionRenew)
	if err != nil {
		t.Fatal(err)
	}
	renew, err := pfc2.NewSessionRenewRecord(ref, func() (h [32]byte) { h[0] = 1 | byte(ref.Generation); return }(), issued.Fact, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{*renew}, ""); err != nil {
		t.Fatalf("renew: %v", err)
	}
	// Same fact, different (later) transition: the reducer would accept a
	// fresh renewal, but the consumed fact must be refused by append.
	issued2 := issued // stolen/replayed fact reference
	renew2, err := pfc2.NewSessionRenewRecord(ref, func() (h [32]byte) { h[0] = 1 | byte(ref.Generation); return }(), issued2.Fact, 91*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{*renew2}, ""); err == nil {
		t.Fatal("consumed fact appended twice")
	}
}

// legacyShapedLog claims the legacy codec pair over the fake implementation.
type legacyShapedLog struct{ *fakeEntryLog }

func (legacyShapedLog) RecordCodec() string  { return wal.PFR1Codec }
func (legacyShapedLog) ControlCodec() string { return "pfc1" }

func TestManagedRejectsLegacyPairLog(t *testing.T) {
	// A legacy-pair log can never construct a managed FS: managed serving
	// requires the PFJ3/PFC2 generation, and the only way there for an
	// existing writable branch is the exceptional retire + new-generation
	// migration.
	if _, err := NewManaged(nil, nil, legacyShapedLog{newFakeEntryLog()}); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("legacy pair accepted: %v", err)
	}
}

// fileWAL asserts the FS under test is the WAL-backed store and returns its
// file WAL (ported tests exercise both stores through one entry point).
func fileWAL(t *testing.T, fs *FS) *wal.WAL {
	t.Helper()
	if fs.wal == nil {
		t.Fatalf("test requires the file WAL, got a managed store")
	}
	return fs.wal
}
