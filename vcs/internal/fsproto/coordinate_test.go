package fsproto

// Protocol-level tests for the managed (journaled) coordination bridge:
// exact conditional creates, inode-keyed journaled locks, epoch'd checkouts,
// pin decisions, per-row flushes, the sync barrier, typed renewal no-ops,
// legacy-write refusal, lost-response replay, and cold-failover replay. All
// tests drive dispatchConn directly (deterministic in-process transport);
// live socket behavior is covered by the *_client tests.

import (
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// protoEntryLog is a compact honest PFJ3 entry log for protocol tests: exact
// encoded bytes at reservation, durable at CommitThrough, replay decodes the
// identical bytes. Fact issuance is monotonic database time (the strict
// fact-consume contract is covered by the workfs and remotejournal suites).
type protoEntryLog struct {
	mu       sync.Mutex
	rows     [][]byte
	durable  uint64
	dbNow    int64
	quotaErr error // when set, AppendEntriesBuffered fails with it
}

func newProtoEntryLog() *protoEntryLog {
	return &protoEntryLog{dbNow: 1_800_000_000_000}
}

func (f *protoEntryLog) RecordCodec() string  { return pfj3.RecordCodec }
func (f *protoEntryLog) ControlCodec() string { return pfj3.ControlCodec }

func (f *protoEntryLog) IssueAdmissionFact(scope pfc2.FactScope) (pfc2.IssuedFact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if scope.Session.SessionID == "" || !scope.Purpose.Valid() {
		return pfc2.IssuedFact{}, fmt.Errorf("proto fake: malformed fact scope")
	}
	f.dbNow += 13
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return pfc2.IssuedFact{}, err
	}
	return pfc2.IssuedFact{
		Fact:            pfc2.TimeFact{Source: pfc2.TimeSourceDB, FactID: id, DbMs: f.dbNow},
		FactExpiresDbMs: f.dbNow + 30_000,
	}, nil
}

func (f *protoEntryLog) AppendEntriesBuffered(entries []pfj3.JournalEntry) (uint64, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.quotaErr != nil {
		// Model the control reserve: the DATA quota only rejects
		// tree-bearing rows; control-only rows (durable rejection outcomes,
		// fences, barriers) always land so exactness stays recordable.
		for i := range entries {
			if entries[i].Tree != nil {
				return 0, 0, f.quotaErr
			}
		}
	}
	first := uint64(len(f.rows))
	staged := make([][]byte, 0, len(entries))
	for i := range entries {
		entries[i].LSN = first + uint64(i)
		if entries[i].Tree != nil {
			entries[i].Tree.Seq = entries[i].LSN
		}
		payload, err := pfj3.Encode(&entries[i])
		if err != nil {
			return 0, 0, err
		}
		staged = append(staged, payload)
	}
	f.rows = append(f.rows, staged...)
	return first, first + uint64(len(entries)), nil
}

func (f *protoEntryLog) CommitThrough(seq uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if seq+1 > f.durable {
		f.durable = seq + 1
	}
	return nil
}

// rowCount reports how many journal rows have been reserved (tests assert
// batch atomicity units and replay no-op-ness with it).
func (f *protoEntryLog) rowCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

func (f *protoEntryLog) ReplayEntriesInto(fn func(pfj3.JournalEntry) error) error {
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

func (f *protoEntryLog) AppendBatchBuffered([]wal.Record) (uint64, uint64, error) {
	return 0, 0, fmt.Errorf("proto fake: PFJ3 log has no record append")
}
func (f *protoEntryLog) ReplayInto(func(wal.Record) error) error {
	return fmt.Errorf("proto fake: no record replay")
}
func (f *protoEntryLog) RecordsBelowInto(uint64, func(wal.Record) error) error {
	return fmt.Errorf("proto fake: no record replay")
}
func (f *protoEntryLog) Watermark() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.durable
}
func (f *protoEntryLog) Bounds() wal.LogBounds       { return wal.ProductionLogBounds() }
func (f *protoEntryLog) OverCapacity() bool          { return false }
func (f *protoEntryLog) SetCapacity(int64)           {}
func (f *protoEntryLog) BacklogBytes() int64         { return 0 }
func (f *protoEntryLog) CompactedThrough() uint64    { return 0 }
func (f *protoEntryLog) Epoch() uint64               { return 1 }
func (f *protoEntryLog) BaseCommitID() string        { return "" }
func (f *protoEntryLog) Poison()                     {}
func (f *protoEntryLog) IsPoisoned() bool            { return false }
func (f *protoEntryLog) PoisonedCh() <-chan struct{} { return nil }
func (f *protoEntryLog) CompactThrough(uint64) error { return fmt.Errorf("proto fake: no compaction") }
func (f *protoEntryLog) PrepareCheckpointCut(wal.CheckpointCut) (wal.CheckpointCut, error) {
	return wal.CheckpointCut{}, fmt.Errorf("proto fake: no cuts")
}
func (f *protoEntryLog) ResolveCheckpointCut(string, string, bool) error {
	return fmt.Errorf("proto fake: no cuts")
}
func (f *protoEntryLog) FinalizeCheckpointCut(string) error { return fmt.Errorf("proto fake: no cuts") }
func (f *protoEntryLog) CheckpointCutState() (wal.CheckpointCut, bool) {
	return wal.CheckpointCut{}, false
}
func (f *protoEntryLog) CompactRecoveredCheckpoint(string) error {
	return fmt.Errorf("proto fake: no cuts")
}
func (f *protoEntryLog) RotateControlOnlyThrough(uint64, uint64) error {
	return fmt.Errorf("proto fake: no rotation")
}
func (f *protoEntryLog) RecoverControlRotation() error { return nil }

var _ pfj3.EntryLog = (*protoEntryLog)(nil)

// newManagedServer builds a managed (journaled) authority server over a fresh
// or replayed proto entry log.
func newManagedServer(t *testing.T, log *protoEntryLog) (*Server, *workfs.FS) {
	t.Helper()
	fs, err := workfs.NewManaged(nil, nopBlobs{}, log)
	if err != nil {
		t.Fatalf("new managed workfs: %v", err)
	}
	return NewServer(fs, fs), fs
}

// observedCoordinationWaitFS makes volatile wait entry observable without
// sleeping. Tests pre-record an exact outcome, so a correct duplicate replay
// never calls this method; a regression is deterministic instead of costing
// the production 45-second SETLKW wait budget.
type observedCoordinationWaitFS struct {
	*workfs.FS
	waitCalls int
}

func (fs *observedCoordinationWaitFS) WaitCoordinationClear(time.Time, func() bool) bool {
	fs.waitCalls++
	return false
}

func newObservedCoordinationWaitServer(t *testing.T) (*Server, *observedCoordinationWaitFS) {
	t.Helper()
	fs, err := workfs.NewManaged(nil, nopBlobs{}, newProtoEntryLog())
	if err != nil {
		t.Fatalf("new managed workfs: %v", err)
	}
	observed := &observedCoordinationWaitFS{FS: fs}
	return NewServer(observed, observed), observed
}

// openJournaledSession establishes a session on a managed authority. The
// negotiation is the version probe (OpProtocolVersion); a managed authority
// speaks the v8 baseline (journaled coordination is mandatory).
func openJournaledSession(t *testing.T, s *Server, id string, gen uint64, owner, token string, slots uint32) *connSession {
	t.Helper()
	cs := &connSession{}
	r := s.dispatchConn(cs, &Request{
		Op: OpSessionOpen, SessionID: id, SessionGen: gen, SessionToken: token,
		SessionSlots: slots, Owner: owner,
	})
	if r == nil || r.Status != OK {
		t.Fatalf("managed session open %s/%d: %+v", id, gen, r)
	}
	return cs
}

func TestManagedProbeAndLegacyWriteRefusal(t *testing.T) {
	s, _ := newManagedServer(t, newProtoEntryLog())

	probe := s.dispatch(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)})
	if probe.Status != OK || probe.ProtoVersion != ProtocolVersion {
		t.Fatalf("managed probe: status=%d version=%d", probe.Status, probe.ProtoVersion)
	}
	// A managed authority advertises every optional lane: atomic delegated
	// xattrs, durable birth-time/BSD-flag persistence, and post-op mutation
	// attributes.
	if want := FeatureDelegatedXattrs | FeatureFlagPersistence | FeatureMutationAttrs | FeatureWritebackLanes; probe.Features != want {
		t.Fatalf("managed features = %b, want %b", probe.Features, want)
	}

	// A managed generation NEVER admits envelope-less legacy writes and every
	// coordination op without an exact identity is refused.
	for _, req := range []*Request{
		{Op: OpLock, Path: "f", LkMode: LkSetlk, LkID: 1, LkEnd: 10},
		{Op: OpCheckout, Path: "p", Owner: "M"},
		{Op: OpMarkOpen, OpenIno: 2, OpenState: true},
		{Op: OpCreate, Path: "x", Mode: 0o644},
	} {
		if r := s.dispatch(req); r == nil || r.Status != EPERM {
			t.Fatalf("envelope-less %v on managed: %+v, want EPERM", req.Op, r)
		}
	}
	// Renewals are typed no-ops, and a GETLK probe (no identity) reads.
	if r := s.dispatch(&Request{Op: OpRenewOpenInodes, OpenInos: []uint64{2}}); r == nil || r.Status != OK {
		t.Fatalf("renew no-op: %+v", r)
	}
}

func TestManagedExclCreateRaceAndReplay(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-exA", 1, "MA", "tokA", 8)
	b := openJournaledSession(t, s, "pfs-exB", 1, "MB", "tokB", 8)

	reqA := &Request{Op: OpCreate, Path: "x.lock", Mode: 0o644, Excl: true}
	if r := exactDo(s, a, reqA, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("A excl create: %+v", r)
	}
	reqB := &Request{Op: OpCreate, Path: "x.lock", Mode: 0o644, Excl: true}
	rB := exactDo(s, b, reqB, 0, 1)
	if rB == nil || rB.Status != EEXIST {
		t.Fatalf("B excl create: %+v, want EEXIST", rB)
	}
	// Lost-response retry: the identical identity replays the stored outcome.
	if r := exactDo(s, b, reqB, 0, 1); r == nil || r.Status != EEXIST || !r.Duplicate {
		t.Fatalf("B replay: %+v, want duplicate EEXIST", r)
	}

	// Failover: a fresh authority over the SAME journal replays both
	// outcomes and the tree.
	s2, _ := newManagedServer(t, log)
	_ = openJournaledSession(t, s2, "pfs-exA", 1, "MA", "tokA", 8)
	b2 := &connSession{}
	if r := s2.dispatchConn(b2, &Request{
		Op: OpSessionResume, SessionID: "pfs-exB", SessionGen: 1, SessionToken: "tokB",
	}); r == nil || r.Status != OK {
		t.Fatalf("B resume after failover: %+v", r)
	}
	if r := exactDo(s2, b2, reqB, 0, 1); r == nil || r.Status != EEXIST || !r.Duplicate {
		t.Fatalf("B replay after failover: %+v", r)
	}
}

func TestManagedLockProtocolLifecycle(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-lkA", 1, "MA", "tokA", 8)
	b := openJournaledSession(t, s, "pfs-lkB", 1, "MB", "tokB", 8)

	if r := exactDo(s, a, &Request{Op: OpCreate, Path: "db", Mode: 0o644}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	lockReq := &Request{Op: OpLock, Path: "db", LkMode: LkSetlk, LkID: 7, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: true}
	if r := exactDo(s, a, lockReq, 1, 1); r == nil || r.Status != OK {
		t.Fatalf("A setlk: %+v", r)
	}
	// Lost grant response: the identical identity replays the grant.
	if r := exactDo(s, a, lockReq, 1, 1); r == nil || r.Status != OK || !r.Duplicate {
		t.Fatalf("A setlk replay: %+v", r)
	}
	// B's conflicting setlk is a durable EAGAIN; the identical resend replays.
	bReq := &Request{Op: OpLock, Path: "db", LkMode: LkSetlk, LkID: 9, LkStart: 5, LkEnd: 10, LkWrite: false}
	if r := exactDo(s, b, bReq, 0, 1); r == nil || r.Status != EAGAIN {
		t.Fatalf("B setlk: %+v, want EAGAIN", r)
	}
	if r := exactDo(s, b, bReq, 0, 1); r == nil || r.Status != EAGAIN || !r.Duplicate {
		t.Fatalf("B setlk replay: %+v, want duplicate EAGAIN", r)
	}
	// GETLK reports the conflict from the durable reducer (a pure read).
	getlk := s.dispatchConn(b, &Request{Op: OpLock, Path: "db", LkMode: LkGetlk, LkID: 9, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: false})
	if getlk == nil || !getlk.LkConflict || !getlk.LkWrite || getlk.LkEnd != kernelOffsetEOF {
		t.Fatalf("getlk: %+v", getlk)
	}
	// A releases only kernel owner 7's lock; B then acquires with a FRESH identity.
	unlockReq := &Request{Op: OpLock, Path: "db", LkMode: LkSetlk, LkID: 7, LkStart: 0, LkEnd: kernelOffsetEOF, LkUnlock: true}
	if r := exactDo(s, a, unlockReq, 1, 2); r == nil || r.Status != OK {
		t.Fatalf("A unlock: %+v", r)
	}
	if r := exactDo(s, b, bReq, 0, 2); r == nil || r.Status != OK {
		t.Fatalf("B setlk after release: %+v", r)
	}

	// Failover: the lock table replays; B's grant conflicts with a writer.
	s2, _ := newManagedServer(t, log)
	a2 := openJournaledSession(t, s2, "pfs-lkA", 1, "MA", "tokA", 8)
	g := s2.dispatchConn(a2, &Request{Op: OpLock, Path: "db", LkMode: LkGetlk, LkID: 7, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: true})
	if g == nil || !g.LkConflict || g.LkStart != 5 || g.LkEnd != 10 {
		t.Fatalf("getlk after failover: %+v", g)
	}
}

func TestManagedSetlkwBlocksVolatilelyThenGrants(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-swA", 1, "MA", "tokA", 8)
	b := openJournaledSession(t, s, "pfs-swB", 1, "MB", "tokB", 8)

	if r := exactDo(s, a, &Request{Op: OpCreate, Path: "w", Mode: 0o644}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	if r := exactDo(s, a, &Request{Op: OpLock, Path: "w", LkMode: LkSetlk, LkID: 1, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: true}, 1, 1); r == nil || r.Status != OK {
		t.Fatalf("A lock: %+v", r)
	}
	granted := make(chan *Response, 1)
	go func() {
		granted <- exactDo(s, b, &Request{Op: OpLock, Path: "w", LkMode: LkSetlkw, LkID: 2, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: true}, 0, 1)
	}()
	time.Sleep(60 * time.Millisecond)
	select {
	case r := <-granted:
		t.Fatalf("setlkw returned %+v while the conflicting hold was live", r)
	default:
	}
	if r := exactDo(s, a, &Request{Op: OpLock, Path: "w", LkMode: LkSetlk, LkID: 1, LkStart: 0, LkEnd: kernelOffsetEOF, LkUnlock: true}, 1, 2); r == nil || r.Status != OK {
		t.Fatalf("A unlock: %+v", r)
	}
	select {
	case r := <-granted:
		if r == nil || r.Status != OK {
			t.Fatalf("setlkw grant after release: %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setlkw did not grant after the release")
	}
}

// TestManagedSetlkwDuplicateSkipsVolatileWait models a response lost after
// the lock decision was durably recorded. Replaying the identical SETLKW
// identity must classify the slot and return its stored outcome before
// consulting current lock contention. Both outcomes are important: a stored
// EAGAIN remains prompt while its original holder is live, and a stored grant
// remains prompt even if later durable operations replaced it with a foreign
// conflicting hold.
func TestManagedSetlkwDuplicateSkipsVolatileWait(t *testing.T) {
	tests := []struct {
		name       string
		wantStatus int32
		prepare    func(t *testing.T, s *Server, fs *observedCoordinationWaitFS, holder, contender *connSession, ino uint64)
		after      func(t *testing.T, s *Server, holder, contender *connSession)
	}{
		{
			name:       "recorded EAGAIN under extant holder",
			wantStatus: EAGAIN,
			prepare: func(t *testing.T, s *Server, _ *observedCoordinationWaitFS, holder, _ *connSession, _ uint64) {
				t.Helper()
				if r := exactDo(s, holder, &Request{
					Op: OpLock, Path: "w", LkMode: LkSetlk,
					LkID: 1, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: true,
				}, 1, 1); r == nil || r.Status != OK {
					t.Fatalf("holder lock: %+v", r)
				}
			},
		},
		{
			name:       "recorded OK before later extant holder",
			wantStatus: OK,
			after: func(t *testing.T, s *Server, holder, contender *connSession) {
				t.Helper()
				if r := exactDo(s, contender, &Request{
					Op: OpLock, Path: "w", LkMode: LkSetlk,
					LkID: 2, LkStart: 0, LkEnd: kernelOffsetEOF, LkUnlock: true,
				}, 1, 1); r == nil || r.Status != OK {
					t.Fatalf("contender unlock after recorded grant: %+v", r)
				}
				if r := exactDo(s, holder, &Request{
					Op: OpLock, Path: "w", LkMode: LkSetlk,
					LkID: 1, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: true,
				}, 1, 1); r == nil || r.Status != OK {
					t.Fatalf("later holder lock: %+v", r)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, fs := newObservedCoordinationWaitServer(t)
			holder := openJournaledSession(t, s, "pfs-dup-holder", 1, "MH", "tokH", 8)
			contender := openJournaledSession(t, s, "pfs-dup-contender", 1, "MC", "tokC", 8)
			if r := exactDo(s, holder, &Request{Op: OpCreate, Path: "w", Mode: 0o644}, 0, 1); r == nil || r.Status != OK {
				t.Fatalf("create: %+v", r)
			}

			ino := s.resolveLockIno(&Request{Path: "w"})
			if ino == 0 {
				t.Fatal("resolve lock inode returned zero")
			}
			if tt.prepare != nil {
				tt.prepare(t, s, fs, holder, contender, ino)
			}

			env := &wal.Envelope{
				SessionID: contender.id, Generation: contender.gen,
				Slot: 0, SlotSeq: 1,
			}
			reqHash, err := workfs.LockChangeRequestHash(
				env, ino, 2, pfc2.LockSetWrite, 0, 0,
			)
			if err != nil {
				t.Fatalf("lock request hash: %v", err)
			}
			// Execute the one durable decision and deliberately discard its
			// response to model a transport loss after commit.
			recorded := s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
				return fs.ManagedLockDecide(full, ino, 2, pfc2.LockSetWrite, 0, 0)
			})
			if recorded == nil || recorded.Status != tt.wantStatus || recorded.Duplicate {
				t.Fatalf("recorded outcome: %+v, want fresh status %d", recorded, tt.wantStatus)
			}
			if tt.after != nil {
				tt.after(t, s, holder, contender)
			}

			fs.waitCalls = 0
			replay := s.dispatchConn(contender, &Request{
				Op: OpLock, Path: "w", LkMode: LkSetlkw,
				LkID: 2, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: true,
				Env: env,
			})
			if replay == nil || replay.Status != tt.wantStatus || !replay.Duplicate {
				t.Fatalf("lost-reply replay: %+v, want duplicate status %d", replay, tt.wantStatus)
			}
			if fs.waitCalls != 0 {
				t.Fatalf("duplicate replay entered volatile SETLKW wait %d time(s)", fs.waitCalls)
			}
		})
	}
}

func TestManagedCheckoutFlushProtocol(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-co", 1, "MA", "tokA", 8)

	// Only an existing directory is delegable: mkdir write-through first.
	if r := exactDo(s, a, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("mkdir ws: %+v", r)
	}
	co := exactDo(s, a, &Request{Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-1", Owner: "MA"}, 0, 2)
	if co == nil || co.Status != OK || co.CheckoutEpoch != "1" {
		t.Fatalf("delegation acquire: %+v", co)
	}
	// Lost grant reply: identical identity replays; the epoch is recovered
	// (the snapshot is not — the client re-seeds under the held grant).
	co2 := exactDo(s, a, &Request{Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-1", Owner: "MA"}, 0, 2)
	if co2 == nil || co2.Status != OK || !co2.Duplicate || co2.CheckoutEpoch != "1" {
		t.Fatalf("delegation replay: %+v", co2)
	}

	records := []wal.Record{
		{Seq: 1, Op: wal.OpCreate, Path: "ws/f", Mode: 0o644},
		{Seq: 2, Op: wal.OpWrite, Path: "ws/f", Data: []byte("data")},
	}
	prev := wbZeroDigest()
	end := wbTestDigest(t, prev, records)
	flush := &Request{
		Op: OpFlushBatch, SessionID: "wb-1", Owner: "MA",
		WBPrevDigest: prev[:], WBEndDigest: end[:],
		Records: records, WBScopes: []WBScope{{Path: "ws", Epoch: co.CheckoutEpoch, Through: 2}},
	}
	fr := s.dispatchConn(a, flush)
	if fr == nil || fr.Status != OK || fr.AppliedThrough != 2 {
		t.Fatalf("flush: %+v", fr)
	}
	// Retry of the identical flush converges on the durable watermark.
	fr2 := s.dispatchConn(a, flush)
	if fr2 == nil || fr2.Status != OK || fr2.AppliedThrough != 2 {
		t.Fatalf("flush retry: %+v", fr2)
	}
	// Records outside the granted subtree are refused.
	badRecords := []wal.Record{{Seq: 3, Op: wal.OpCreate, Path: "outside", Mode: 0o644}}
	badEnd := wbTestDigest(t, end, badRecords)
	bad := &Request{
		Op: OpFlushBatch, SessionID: "wb-1", Owner: "MA",
		WBPrevDigest: end[:], WBEndDigest: badEnd[:],
		Records: badRecords, WBScopes: []WBScope{{Path: "ws", Epoch: co.CheckoutEpoch, Through: 3}},
	}
	if r := s.dispatchConn(a, bad); r == nil || r.Status != EPERM {
		t.Fatalf("out-of-subtree flush: %+v", r)
	}
	// A ".."-traversal record whose raw wire path is byte-prefixed by the
	// grant ("ws/..") but canonicalizes outside it must be refused — the gate
	// tests the applied (cleaned) path, not the wire bytes.
	escRecords := []wal.Record{{Seq: 3, Op: wal.OpCreate, Path: "ws/../outside/f", Mode: 0o644}}
	escEnd := wbTestDigest(t, end, escRecords)
	esc := &Request{
		Op: OpFlushBatch, SessionID: "wb-1", Owner: "MA",
		WBPrevDigest: end[:], WBEndDigest: escEnd[:],
		Records: escRecords, WBScopes: []WBScope{{Path: "ws", Epoch: co.CheckoutEpoch, Through: 3}},
	}
	if r := s.dispatchConn(a, esc); r == nil || r.Status != EPERM {
		t.Fatalf("traversal-escape flush: %+v", r)
	}
	// The refused escape touched nothing: the durable watermark is still 2.
	if r := s.dispatchConn(a, flush); r == nil || r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("watermark after refused escape: %+v", r)
	}
	// Checkin with the wrong epoch is a durable ENOENT; the right epoch releases.
	if r := exactDo(s, a, &Request{Op: OpCheckin, Path: "ws", CheckoutEpoch: "9", Owner: "MA"}, 1, 1); r == nil || r.Status != ENOENT {
		t.Fatalf("wrong-epoch checkin: %+v", r)
	}
	if r := exactDo(s, a, &Request{Op: OpCheckin, Path: "ws", CheckoutEpoch: co.CheckoutEpoch, Owner: "MA"}, 1, 2); r == nil || r.Status != OK {
		t.Fatalf("checkin: %+v", r)
	}
	// A flush after release is fenced (ESTALE) — stale holders never write.
	lateRecords := []wal.Record{{Seq: 3, Op: wal.OpCreate, Path: "ws/late", Mode: 0o644}}
	lateEnd := wbTestDigest(t, end, lateRecords)
	late := &Request{
		Op: OpFlushBatch, SessionID: "wb-1", Owner: "MA",
		WBPrevDigest: end[:], WBEndDigest: lateEnd[:],
		Records: lateRecords, WBScopes: []WBScope{{Path: "ws", Epoch: co.CheckoutEpoch, Through: 3}},
	}
	if r := s.dispatchConn(a, late); r == nil || r.Status != ESTALE {
		t.Fatalf("stale flush: %+v", r)
	}
}

func TestManagedRebindConflictAuditSurvivesColdReplay(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	holder := openJournaledSession(t, s, "pfs-wb-holder", 1, "holder", "tok-holder", 8)
	if r := exactDo(s, holder, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("mkdir: %+v", r)
	}
	grant := exactDo(s, holder, &Request{
		Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-cold-audit",
	}, 0, 2)
	if grant == nil || grant.Status != OK {
		t.Fatalf("delegation acquire: %+v", grant)
	}
	records := []wal.Record{{Seq: 1, Op: wal.OpCreate, Path: "ws/file", Mode: 0o644}}
	zero := wbZeroDigest()
	end := wbTestDigest(t, zero, records)
	if r := s.dispatchConn(holder, &Request{
		Op:           OpFlushBatch,
		SessionID:    "wb-cold-audit",
		WBPrevDigest: zero[:],
		WBEndDigest:  end[:],
		Records:      records,
		WBScopes:     []WBScope{{Path: "ws", Epoch: grant.CheckoutEpoch, Through: 1}},
	}); r == nil || r.Status != OK {
		t.Fatalf("flush: %+v", r)
	}

	recovery := openJournaledSession(t, s, "pfs-wb-recovery", 1, "recovery", "tok-recovery", 8)
	req := &Request{
		Op:           OpWritebackRebind,
		SessionID:    "wb-cold-audit",
		WBScopes:     []WBScope{{Path: "ws", Epoch: grant.CheckoutEpoch}},
		WBThrough:    0,
		WBPrevDigest: zero[:],
	}
	first := exactDo(s, recovery, req, 0, 1)
	if first == nil || first.Status != EIO || len(first.WBConflicts) == 0 ||
		first.WBConflicts[0].Kind != "DIGEST_MISMATCH" {
		t.Fatalf("fresh rejected Rebind: %+v", first)
	}

	// A replacement authority has only the frozen exact EIO outcome. Its
	// duplicate path must reconstruct typed proof from the applied replay
	// state, not invent SCOPE_MISSING.
	s2, _ := newManagedServer(t, log)
	recovery2 := &connSession{}
	if r := s2.dispatchConn(recovery2, &Request{
		Op: OpSessionResume, SessionID: "pfs-wb-recovery", SessionGen: 1,
		SessionToken: "tok-recovery",
	}); r == nil || r.Status != OK {
		t.Fatalf("resume after cold replay: %+v", r)
	}
	replay := exactDo(s2, recovery2, req, 0, 1)
	if replay == nil || replay.Status != EIO || !replay.Duplicate ||
		len(replay.WBConflicts) == 0 || replay.WBConflicts[0].Kind != "DIGEST_MISMATCH" {
		t.Fatalf("cold duplicate Rebind: %+v", replay)
	}
}

func TestManagedPinBarrierAndRenewNoops(t *testing.T) {
	log := newProtoEntryLog()
	s, fs := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-pin", 1, "MA", "tokA", 8)

	cr := exactDo(s, a, &Request{Op: OpCreate, Path: "held", Mode: 0o644}, 0, 1)
	if cr == nil || cr.Status != OK || cr.Ino == 0 {
		t.Fatalf("create: %+v", cr)
	}
	ino := cr.Ino
	if r := exactDo(s, a, &Request{Op: OpMarkOpen, OpenIno: ino, OpenState: true}, 1, 1); r == nil || r.Status != OK {
		t.Fatalf("pin: %+v", r)
	}
	control, err := fs.ManagedControl()
	if err != nil {
		t.Fatal(err)
	}
	if !control.HasPin(pfc2.SessionRef{SessionID: "pfs-pin", Generation: 1}, ino) {
		t.Fatal("pin not durable")
	}
	// Renewals are typed no-ops that authorize nothing.
	if r := s.dispatchConn(a, &Request{Op: OpRenewOpenInodes, OpenInos: []uint64{ino}}); r == nil || r.Status != OK {
		t.Fatalf("renew open: %+v", r)
	}
	if r := s.dispatchConn(a, &Request{Op: OpRenewOrphanLeases, OrphanInos: []uint64{ino}}); r == nil || r.Status != OK {
		t.Fatalf("renew orphan: %+v", r)
	}
	// The sync barrier answers after everything reserved is applied.
	if r := s.dispatchConn(a, &Request{Op: OpFsync}); r == nil || r.Status != OK {
		t.Fatalf("sync barrier: %+v", r)
	}
	// Unpin; pin of a never-existing ino is a durable ENOENT decision.
	if r := exactDo(s, a, &Request{Op: OpMarkOpen, OpenIno: ino, OpenState: false}, 1, 2); r == nil || r.Status != OK {
		t.Fatalf("unpin: %+v", r)
	}
	gone := exactDo(s, a, &Request{Op: OpMarkOpen, OpenIno: 999_999, OpenState: true}, 1, 3)
	if gone == nil || gone.Status != ENOENT {
		t.Fatalf("pin of missing ino: %+v", gone)
	}
	if r := exactDo(s, a, &Request{Op: OpMarkOpen, OpenIno: 999_999, OpenState: true}, 1, 3); r == nil || r.Status != ENOENT || !r.Duplicate {
		t.Fatalf("pin ENOENT replay: %+v", r)
	}
}

func TestManagedQuotaRejectionIsDurable(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-q", 1, "MA", "tokA", 8)

	// Data quota is full: a tree-bearing create is a DURABLE EDQUOT outcome
	// (the rejection row rides the control reserve), NOT an unrecorded reply.
	log.mu.Lock()
	log.quotaErr = fmt.Errorf("proto fake: %w", wal.ErrJournalQuota)
	log.mu.Unlock()
	first := exactDo(s, a, &Request{Op: OpCreate, Path: "big", Mode: 0o644}, 0, 1)
	if first == nil || first.Status != EDQUOT {
		t.Fatalf("quota rejection: %+v, want durable EDQUOT", first)
	}
	dup := exactDo(s, a, &Request{Op: OpCreate, Path: "big", Mode: 0o644}, 0, 1)
	if dup == nil || dup.Status != EDQUOT || !dup.Duplicate {
		t.Fatalf("quota rejection replay: %+v, want duplicate EDQUOT", dup)
	}
	// After the quota clears, a FRESH identity (next sequence) succeeds.
	log.mu.Lock()
	log.quotaErr = nil
	log.mu.Unlock()
	if r := exactDo(s, a, &Request{Op: OpCreate, Path: "big", Mode: 0o644}, 0, 2); r == nil || r.Status != OK {
		t.Fatalf("create after quota clears: %+v", r)
	}
}

func TestManagedSessionTerminalReleasesCoordination(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-term", 1, "MA", "tokA", 8)
	b := openJournaledSession(t, s, "pfs-live", 1, "MB", "tokB", 8)

	if r := exactDo(s, a, &Request{Op: OpCreate, Path: "f", Mode: 0o644}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	if r := exactDo(s, a, &Request{Op: OpLock, Path: "f", LkMode: LkSetlk, LkID: 1, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: true}, 1, 1); r == nil || r.Status != OK {
		t.Fatalf("lock: %+v", r)
	}
	if r := exactDo(s, a, &Request{Op: OpCheckout, Path: "sub", Owner: "MA"}, 2, 1); r == nil || r.Status != OK {
		t.Fatalf("checkout: %+v", r)
	}
	// Voluntary terminal (clean unmount) releases locks and checkouts in the
	// same journal row; a socket flap would have released NOTHING.
	if r := s.dispatchConn(a, &Request{Op: OpSessionExpire, SessionID: "pfs-term", SessionGen: 1}); r == nil || r.Status != OK {
		t.Fatalf("expire: %+v", r)
	}
	// B can now take both.
	if r := exactDo(s, b, &Request{Op: OpLock, Path: "f", LkMode: LkSetlk, LkID: 2, LkStart: 0, LkEnd: kernelOffsetEOF, LkWrite: true}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("B lock after terminal: %+v", r)
	}
	if r := exactDo(s, b, &Request{Op: OpCheckout, Path: "sub", Owner: "MB"}, 1, 1); r == nil || r.Status != OK {
		t.Fatalf("B checkout after terminal: %+v", r)
	}
	// The fenced generation can never mutate again.
	if r := exactDo(s, a, &Request{Op: OpCreate, Path: "z", Mode: 0o644}, 3, 1); r == nil || r.Status != ESTALE {
		t.Fatalf("fenced create: %+v", r)
	}
}

// TestManagedFlushCapacityRefusalIsDefinite is the round-18g contract: a
// CAPACITY refusal on the WRITE-BACK FLUSH path must reach the client as the
// same DEFINITE outcome the exact path already answers, never as the
// "authority machinery is having a bad minute" EAGAIN.
//
// Both capacity classes are exercised, because both reach ManagedFlushApply
// and both were falling through to the EAGAIN catch-all:
//
//	dirty-RSS bound  (workfs.ErrDirtyRSSCapacity -> ErrWALCapacity) -> ENOSPC
//	journal quota    (wal.ErrJournalQuota)                          -> EDQUOT
//
// The production consequence of getting this wrong is not cosmetic. EAGAIN is
// a HOLD, so writeback/flush.go retries it forever; nothing on either side
// folds the authority's dirty pool for a live generation, so the retry never
// succeeds, the watermark freezes, the no-progress watchdog fires, and the
// whole mount goes to EIO — for a condition the application could have handled
// if it had simply been told "no space".
func TestManagedFlushCapacityRefusalIsDefinite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arm     func(log *protoEntryLog, fs *workfs.FS)
		want    int32
		wantMsg string
	}{
		{
			name: "resident dirty-block bound",
			arm: func(_ *protoEntryLog, fs *workfs.FS) {
				// Any write leaf reserves at least one whole block, so a
				// one-byte bound refuses the first one deterministically.
				fs.SetDirtyRSSMax(1)
			},
			want:    ENOSPC,
			wantMsg: "ENOSPC",
		},
		{
			name: "durable journal backlog quota",
			arm: func(log *protoEntryLog, _ *workfs.FS) {
				log.mu.Lock()
				log.quotaErr = fmt.Errorf("proto fake: %w", wal.ErrJournalQuota)
				log.mu.Unlock()
			},
			want:    EDQUOT,
			wantMsg: "EDQUOT",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := newProtoEntryLog()
			s, fs := newManagedServer(t, log)
			a := openJournaledSession(t, s, "pfs-cap", 1, "MA", "tokA", 8)

			if r := exactDo(s, a, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
				t.Fatalf("mkdir ws: %+v", r)
			}
			co := exactDo(s, a, &Request{Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-cap", Owner: "MA"}, 0, 2)
			if co == nil || co.Status != OK {
				t.Fatalf("delegation acquire: %+v", co)
			}
			tc.arm(log, fs)

			records := []wal.Record{
				{Seq: 1, Op: wal.OpWrite, Path: "ws/f", Data: []byte("payload")},
			}
			prev := wbZeroDigest()
			end := wbTestDigest(t, prev, records)
			flush := &Request{
				Op: OpFlushBatch, SessionID: "wb-cap", Owner: "MA",
				WBPrevDigest: prev[:], WBEndDigest: end[:],
				Records: records, WBScopes: []WBScope{{Path: "ws", Epoch: co.CheckoutEpoch, Through: 1}},
			}
			r := s.dispatchConn(a, flush)
			if r == nil {
				t.Fatalf("capacity refusal dropped the connection; want a definite %s", tc.wantMsg)
			}
			if r.Status == EAGAIN {
				t.Fatalf("capacity refusal answered EAGAIN: the client holds this as a "+
					"transient and retries forever against a bound nothing relieves. want %s", tc.wantMsg)
			}
			if r.Status != tc.want {
				t.Fatalf("capacity refusal status = %d, want %s (%d)", r.Status, tc.wantMsg, tc.want)
			}
			// A definite refusal applied NOTHING: the watermark is unmoved.
			if r.AppliedThrough != 0 {
				t.Fatalf("refused flush reported AppliedThrough=%d, want 0", r.AppliedThrough)
			}
		})
	}
}

// TestManagedFlushAtDirtyBoundStillAdmitsRelease is the AUTHORITY half of the
// documented recovery, isolated and pinned.
//
// dirtyrss.go promises that only tree WRITES are refused at the dirty-block
// bound, so an operation that RELEASES resident blocks stays admissible and
// reopens admission. That promise is true, and this proves it holds all the way
// through the write-back flush path — not just through the in-process
// CommitEntry the workfs suite exercises.
//
// It is deliberately a separate test from the client's behaviour, because the
// two halves failed differently. The authority never refused the remove; the
// MOUNT could no longer issue one, having been taken to EIO by the watchdog
// while it retried a capacity refusal it had been handed as EAGAIN. Pinning the
// authority half here is what makes that attribution honest: the escape hatch
// exists, and what broke was the client's ability to reach it.
func TestManagedFlushAtDirtyBoundStillAdmitsRelease(t *testing.T) {
	log := newProtoEntryLog()
	s, fs := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-relief", 1, "MA", "tokA", 8)

	if r := exactDo(s, a, &Request{Op: OpMkdir, Path: "ws", Mode: 0o755}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("mkdir ws: %+v", r)
	}
	co := exactDo(s, a, &Request{Op: OpDelegationAcquire, Path: "ws", SessionID: "wb-relief", Owner: "MA"}, 0, 2)
	if co == nil || co.Status != OK {
		t.Fatalf("delegation acquire: %+v", co)
	}
	epoch := co.CheckoutEpoch

	// One flush that lands: the volume now HOLDS resident dirty blocks, which
	// is the only state in which the bound means anything.
	seed := []wal.Record{
		{Seq: 1, Op: wal.OpCreate, Path: "ws/f", Mode: 0o644},
		{Seq: 2, Op: wal.OpWrite, Path: "ws/f", Data: []byte("resident")},
	}
	zero := wbZeroDigest()
	seedEnd := wbTestDigest(t, zero, seed)
	seedFlush := &Request{
		Op: OpFlushBatch, SessionID: "wb-relief", Owner: "MA",
		WBPrevDigest: zero[:], WBEndDigest: seedEnd[:],
		Records: seed, WBScopes: []WBScope{{Path: "ws", Epoch: epoch, Through: 2}},
	}
	if r := s.dispatchConn(a, seedFlush); r == nil || r.Status != OK {
		t.Fatalf("seed flush: %+v", r)
	}
	held := fs.DirtyBlockBytes()
	if held == 0 {
		t.Fatal("seed flush left no resident dirty blocks; the fixture proves nothing")
	}

	// The bound is now one block — the smallest bound under which a write can
	// ever be admitted, since every write leaf reserves its whole 4 MiB block.
	// With any residency at all, the next write no longer fits.
	const oneBlock = 4 << 20 // workfs blockSize
	fs.SetDirtyRSSMax(oneBlock)

	// A write is refused, definitely.
	over := []wal.Record{{Seq: 3, Op: wal.OpWrite, Path: "ws/f", Offset: 1 << 20, Data: []byte("more")}}
	overEnd := wbTestDigest(t, seedEnd, over)
	overFlush := &Request{
		Op: OpFlushBatch, SessionID: "wb-relief", Owner: "MA",
		WBPrevDigest: seedEnd[:], WBEndDigest: overEnd[:],
		Records: over, WBScopes: []WBScope{{Path: "ws", Epoch: epoch, Through: 3}},
	}
	if r := s.dispatchConn(a, overFlush); r == nil || r.Status != ENOSPC {
		t.Fatalf("write flush at the bound: %+v, want ENOSPC", r)
	}

	// The release is ADMITTED at the very same bound, and it actually frees
	// the memory. This is the whole content of the "recoverable, not wedged"
	// claim, and on this side of the wire it holds.
	//
	// Truncate, not remove, and the difference is not cosmetic. OpRemove is
	// equally admissible at the bound and it applies cleanly — it just does
	// not RELEASE anything on a managed authority. applyManagedMutation parks
	// the detached inode on EVERY successful unlink (OpReap is its sole
	// destruction transition, so live apply and cold replay cannot disagree
	// over a non-replicated open-handle observation), and a parked orphan
	// keeps every dirty block it had. So the escape dirtyrss.go used to
	// advertise — "truncate/remove releases blocks" — is half wrong here:
	// `rm` returns no memory at all until the last close reaps the inode.
	// Truncate is the operation that actually works, and this is it.
	release := []wal.Record{{Seq: 3, Op: wal.OpTruncate, Path: "ws/f", Size: 0}}
	releaseEnd := wbTestDigest(t, seedEnd, release)
	releaseFlush := &Request{
		Op: OpFlushBatch, SessionID: "wb-relief", Owner: "MA",
		WBPrevDigest: seedEnd[:], WBEndDigest: releaseEnd[:],
		Records: release, WBScopes: []WBScope{{Path: "ws", Epoch: epoch, Through: 3}},
	}
	if r := s.dispatchConn(a, releaseFlush); r == nil || r.Status != OK || r.AppliedThrough != 3 {
		t.Fatalf("release flush at the bound: %+v, want OK through 3", r)
	}
	if got := fs.DirtyBlockBytes(); got != 0 {
		t.Fatalf("release left %d resident dirty bytes, want 0", got)
	}

	// And admission is open again.
	after := []wal.Record{
		{Seq: 4, Op: wal.OpCreate, Path: "ws/g", Mode: 0o644},
		{Seq: 5, Op: wal.OpWrite, Path: "ws/g", Data: []byte("again")},
	}
	afterEnd := wbTestDigest(t, releaseEnd, after)
	afterFlush := &Request{
		Op: OpFlushBatch, SessionID: "wb-relief", Owner: "MA",
		WBPrevDigest: releaseEnd[:], WBEndDigest: afterEnd[:],
		Records: after, WBScopes: []WBScope{{Path: "ws", Epoch: epoch, Through: 5}},
	}
	if r := s.dispatchConn(a, afterFlush); r == nil || r.Status != OK || r.AppliedThrough != 5 {
		t.Fatalf("write flush after the release: %+v, want OK through 5", r)
	}
}
