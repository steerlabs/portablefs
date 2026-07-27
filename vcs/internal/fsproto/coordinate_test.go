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
	return NewServer(fs, fs, nil), fs
}

// openJournaledSession establishes a session on a managed authority. The
// negotiation is the version probe (OpProtocolVersion); a managed authority
// advertises ProtoVersionJournaledSessions + FeatJournaledCoordination.
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
	if probe.ProtoVersion != ProtoVersionJournaledSessions || probe.Features&FeatJournaledCoordination == 0 {
		t.Fatalf("managed probe: version=%d features=%b", probe.ProtoVersion, probe.Features)
	}
	if probe.Features&FeatReclaimGrace != 0 {
		t.Fatal("managed probe advertises reclaim grace")
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

func TestManagedCheckoutFlushProtocol(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-co", 1, "MA", "tokA", 8)

	co := exactDo(s, a, &Request{Op: OpCheckout, Path: "ws", Owner: "MA"}, 0, 1)
	if co == nil || co.Status != OK || co.CheckoutEpoch != "1" {
		t.Fatalf("checkout: %+v", co)
	}
	// Lost grant reply: identical identity replays; the epoch is recovered.
	co2 := exactDo(s, a, &Request{Op: OpCheckout, Path: "ws", Owner: "MA"}, 0, 1)
	if co2 == nil || co2.Status != OK || !co2.Duplicate || co2.CheckoutEpoch != "1" {
		t.Fatalf("checkout replay: %+v", co2)
	}

	flush := &Request{
		Op: OpFlushBatch, SessionID: "wb-1", Owner: "MA",
		CheckoutPath: "ws", CheckoutEpoch: co.CheckoutEpoch,
		Records: []wal.Record{
			{Seq: 1, Op: wal.OpMkdir, Path: "ws", Mode: 0o755},
			{Seq: 2, Op: wal.OpCreate, Path: "ws/f", Mode: 0o644},
			{Seq: 3, Op: wal.OpWrite, Path: "ws/f", Data: []byte("data")},
		},
	}
	fr := s.dispatchConn(a, flush)
	if fr == nil || fr.Status != OK || fr.AppliedThrough != 3 {
		t.Fatalf("flush: %+v", fr)
	}
	// Retry of the identical flush converges on the durable watermark.
	fr2 := s.dispatchConn(a, flush)
	if fr2 == nil || fr2.Status != OK || fr2.AppliedThrough != 3 {
		t.Fatalf("flush retry: %+v", fr2)
	}
	// Records outside the granted subtree are refused.
	bad := &Request{
		Op: OpFlushBatch, SessionID: "wb-1", Owner: "MA",
		CheckoutPath: "ws", CheckoutEpoch: co.CheckoutEpoch,
		Records: []wal.Record{{Seq: 4, Op: wal.OpCreate, Path: "outside", Mode: 0o644}},
	}
	if r := s.dispatchConn(a, bad); r == nil || r.Status != EPERM {
		t.Fatalf("out-of-subtree flush: %+v", r)
	}
	// Checkin with the wrong epoch is a durable ENOENT; the right epoch releases.
	if r := exactDo(s, a, &Request{Op: OpCheckin, Path: "ws", CheckoutEpoch: "9", Owner: "MA"}, 1, 1); r == nil || r.Status != ENOENT {
		t.Fatalf("wrong-epoch checkin: %+v", r)
	}
	if r := exactDo(s, a, &Request{Op: OpCheckin, Path: "ws", CheckoutEpoch: co.CheckoutEpoch, Owner: "MA"}, 1, 2); r == nil || r.Status != OK {
		t.Fatalf("checkin: %+v", r)
	}
	// A flush after release is fenced (ESTALE) — stale holders never write.
	late := &Request{
		Op: OpFlushBatch, SessionID: "wb-1", Owner: "MA",
		CheckoutPath: "ws", CheckoutEpoch: co.CheckoutEpoch,
		Records: []wal.Record{{Seq: 5, Op: wal.OpCreate, Path: "ws/late", Mode: 0o644}},
	}
	if r := s.dispatchConn(a, late); r == nil || r.Status != ESTALE {
		t.Fatalf("stale flush: %+v", r)
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
