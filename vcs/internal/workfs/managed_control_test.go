package workfs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// advanceDb moves the fake's database clock forward: the ONLY way any test
// can make a lease elapse, exactly like production (host clocks schedule,
// database facts decide).
func (f *fakeEntryLog) advanceDb(ms int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dbNow += ms
}

func newManagedFS(t *testing.T) (*FS, *fakeEntryLog) {
	t.Helper()
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	return fs, log
}

func TestManagedEstablishReplayConflictSupersede(t *testing.T) {
	fs, _ := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-a", 1, "owner-a", 8, "tok-a"); err != nil {
		t.Fatalf("establish: %v", err)
	}
	// Identical tuple: lost-reply replay answers success without a second row.
	if err := fs.EstablishSessionWithToken("pfs-a", 1, "owner-a", 8, "tok-a"); err != nil {
		t.Fatalf("identical replay: %v", err)
	}
	// Same generation, different tuple: credential conflict.
	if err := fs.EstablishSessionWithToken("pfs-a", 1, "owner-a", 8, "tok-b"); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("tuple conflict: %v", err)
	}
	// Higher generation supersedes; the lower generation is then stale.
	if err := fs.EstablishSessionWithToken("pfs-a", 2, "owner-a", 8, "tok-a2"); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	if err := fs.EstablishSessionWithToken("pfs-a", 1, "owner-a", 8, "tok-a"); !errors.Is(err, ErrSessionStale) {
		t.Fatalf("stale generation: %v", err)
	}
	info, ok := fs.CurrentSession("pfs-a")
	if !ok || info.Generation != 2 || info.Expired {
		t.Fatalf("current session %+v %v", info, ok)
	}
	// The supersede released generation 1 and left generation 2 live; its
	// deadline is an exact database time.
	if info.ExpiresMs <= 0 || info.DurableExpiresMs != info.ExpiresMs {
		t.Fatalf("managed deadlines %+v", info)
	}
}

func TestManagedResumeAdvancesDatabaseDeadline(t *testing.T) {
	fs, _ := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-r", 1, "o", 8, "tok"); err != nil {
		t.Fatal(err)
	}
	before, _ := fs.CurrentSession("pfs-r")
	info, err := fs.ResumeSession("pfs-r", 1, "tok")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if info.ExpiresMs <= before.ExpiresMs {
		t.Fatalf("renewal did not advance the durable deadline (%d -> %d)", before.ExpiresMs, info.ExpiresMs)
	}
	if _, err := fs.ResumeSession("pfs-r", 1, "wrong"); !errors.Is(err, ErrSessionStale) {
		t.Fatalf("wrong token resume: %v", err)
	}
	if _, err := fs.ResumeSession("pfs-r", 9, "tok"); !errors.Is(err, ErrSessionStale) {
		t.Fatalf("wrong generation resume: %v", err)
	}
	if _, err := fs.AuthenticateSession("pfs-r", "tok"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if _, err := fs.AuthenticateSession("pfs-r", "wrong"); !errors.Is(err, ErrSessionStale) {
		t.Fatalf("authenticate wrong token: %v", err)
	}
}

func TestManagedVoluntaryExpireReleasesCoordination(t *testing.T) {
	fs, _ := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-x", 1, "o", 8, "tok"); err != nil {
		t.Fatal(err)
	}
	ref := pfc2.SessionRef{SessionID: "pfs-x", Generation: 1}
	pin := pfc2.Record{Kind: pfc2.KindOpenPinChange, OpenPinChange: &pfc2.OpenPinChange{Session: ref, Ino: 7}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{pin}, ""); err != nil {
		t.Fatalf("pin: %v", err)
	}
	control, _ := fs.ManagedControl()
	if !control.HasPin(ref, 7) {
		t.Fatal("pin not applied")
	}
	if err := fs.ExpireSession("pfs-x", 1); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if control.HasPin(ref, 7) {
		t.Fatal("terminal transition did not release the open pin")
	}
	// Idempotent: expiring again (or fencing) is a no-op, not an error.
	if err := fs.ExpireSession("pfs-x", 1); err != nil {
		t.Fatalf("idempotent expire: %v", err)
	}
	if err := fs.FenceSession("pfs-x", 1); err != nil {
		t.Fatalf("idempotent fence: %v", err)
	}
	if info, ok := fs.CurrentSession("pfs-x"); !ok || !info.Expired {
		t.Fatalf("session view after expire %+v %v", info, ok)
	}
}

func TestManagedExpiryIsDatabaseTimeDecided(t *testing.T) {
	fs, log := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-e", 1, "o", 8, "tok"); err != nil {
		t.Fatal(err)
	}
	// The host clock (time.Now, year 2026) is far past the fake database
	// epoch (2023), so the sweeper heuristic ALWAYS nominates this session.
	// Database time has NOT elapsed the lease: no expiry may happen.
	if expired := fs.ExpiredSessions(time.Now()); len(expired) != 0 {
		t.Fatalf("host clock expired a live lease: %+v", expired)
	}
	if info, _ := fs.CurrentSession("pfs-e"); info.Expired {
		t.Fatal("session fenced by host time")
	}
	// Advance DATABASE time past the deadline: the fresh decision fact now
	// proves expiry and the conditional terminal row lands durably.
	log.advanceDb(SessionLeaseTTL().Milliseconds() + 1_000)
	expired := fs.ExpiredSessions(time.Now())
	if len(expired) != 1 || !expired[0].Expired || expired[0].SessionID != "pfs-e" {
		t.Fatalf("database-time expiry: %+v", expired)
	}
	if info, _ := fs.CurrentSession("pfs-e"); !info.Expired {
		t.Fatal("expiry did not fence the session")
	}
	// A fenced generation never renews.
	if _, err := fs.ResumeSession("pfs-e", 1, "tok"); !errors.Is(err, ErrSessionStale) {
		t.Fatalf("post-expiry resume: %v", err)
	}
}

func TestManagedExpirySweepIsConditional(t *testing.T) {
	// Reclaim grace, wall-time pruning, and ambient renewal are structurally
	// gone (the APIs no longer exist). What remains observable: a host clock
	// far in the future NOMINATES a session for expiry, but the database
	// admission fact decides — a live lease is only fenced once database time
	// reaches the durable deadline, never by the caller's clock alone.
	fs, log := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-g", 1, "o", 8, "tok"); err != nil {
		t.Fatal(err)
	}
	before := managedDigest(t, fs)
	if got := fs.ExpiredSessions(time.Now().Add(24 * time.Hour)); len(got) != 0 {
		t.Fatalf("host clock alone expired a live database lease: %+v", got)
	}
	if got := managedDigest(t, fs); got != before {
		t.Fatal("a refused expiry sweep mutated managed control state")
	}
	_ = log
}

func TestManagedCheckSlotDispositions(t *testing.T) {
	fs, _ := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-s", 1, "mount-1", 8, "tok"); err != nil {
		t.Fatal(err)
	}
	hash := make([]byte, 32)
	hash[0] = 0x11
	env := &wal.Envelope{SessionID: "pfs-s", Generation: 1, Slot: 0, SlotSeq: 1, ReqHash: hash}
	if res, _ := fs.CheckSlot(env); res != SlotNew {
		t.Fatalf("fresh identity: %v", res)
	}
	result, err := fs.MutateEnv(wal.Record{Op: wal.OpCreate, Path: "f.txt", Mode: 0o644, Env: env}, "mount-1")
	if err != nil {
		t.Fatalf("mutate: %v", err)
	}
	if result.Ino == 0 {
		t.Fatalf("mutation result %+v", result)
	}
	// Duplicate replays the durable outcome.
	res, outcome := fs.CheckSlot(env)
	if res != SlotDuplicate || outcome.Status != 0 || outcome.Ino != result.Ino {
		t.Fatalf("duplicate: %v %+v", res, outcome)
	}
	// Same identity, different bytes: conflict (fences at the protocol layer).
	otherHash := make([]byte, 32)
	otherHash[0] = 0x22
	if res, _ := fs.CheckSlot(&wal.Envelope{SessionID: "pfs-s", Generation: 1, Slot: 0, SlotSeq: 1, ReqHash: otherHash}); res != SlotConflict {
		t.Fatalf("conflict: %v", res)
	}
	// A sequence gap.
	if res, _ := fs.CheckSlot(&wal.Envelope{SessionID: "pfs-s", Generation: 1, Slot: 0, SlotSeq: 5, ReqHash: hash}); res != SlotGap {
		t.Fatalf("gap: %v", res)
	}
	// Unknown session.
	if res, _ := fs.CheckSlot(&wal.Envelope{SessionID: "pfs-none", Generation: 1, Slot: 0, SlotSeq: 1, ReqHash: hash}); res != SlotUnknownSession {
		t.Fatalf("unknown: %v", res)
	}
	// A definite static rejection advances the slot durably.
	env2 := &wal.Envelope{SessionID: "pfs-s", Generation: 1, Slot: 0, SlotSeq: 2, ReqHash: otherHash}
	if err := fs.RecordStaticOutcome(env2, 36); err != nil {
		t.Fatalf("static outcome: %v", err)
	}
	if res, outcome := fs.CheckSlot(env2); res != SlotDuplicate || outcome.Status != 36 {
		t.Fatalf("static duplicate: %v %+v", res, outcome)
	}
	// Acknowledging the floor retires the detail: the identity answers
	// OutcomeRetired (SlotRetired), never re-executes, never fences.
	floor := pfc2.Record{Kind: pfc2.KindOutcomeFloor, OutcomeFloor: &pfc2.OutcomeFloor{
		Session: pfc2.SessionRef{SessionID: "pfs-s", Generation: 1}, Slot: 0, Through: 2,
	}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{floor}, ""); err != nil {
		t.Fatalf("floor: %v", err)
	}
	if res, _ := fs.CheckSlot(env2); res != SlotRetired {
		t.Fatalf("retired: %v", res)
	}
	if res, _ := fs.CheckSlot(env); res != SlotRetired {
		t.Fatalf("retired older: %v", res)
	}
}

func TestManagedSessionLifecycleColdReplayEquivalence(t *testing.T) {
	fs, log := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-c", 1, "o", 8, "tok"); err != nil {
		t.Fatal(err)
	}
	hash := make([]byte, 32)
	hash[0] = 0x31
	env := &wal.Envelope{SessionID: "pfs-c", Generation: 1, Slot: 1, SlotSeq: 1, ReqHash: hash}
	if _, err := fs.MutateEnv(wal.Record{Op: wal.OpCreate, Path: "c.txt", Mode: 0o600, Env: env}, "o"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ResumeSession("pfs-c", 1, "tok"); err != nil {
		t.Fatal(err)
	}

	// A crashed child restarts EMPTY and replays every entry before serving:
	// identical control state, identical exact dispositions, same session.
	fs2, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("cold replay: %v", err)
	}
	if managedDigest(t, fs) != managedDigest(t, fs2) {
		t.Fatal("cold replay diverged")
	}
	if res, outcome := fs2.CheckSlot(env); res != SlotDuplicate || outcome.Ino == 0 {
		t.Fatalf("replayed duplicate: %v %+v", res, outcome)
	}
	info, ok := fs2.CurrentSession("pfs-c")
	if !ok || info.Expired || info.Generation != 1 {
		t.Fatalf("replayed session %+v %v", info, ok)
	}
	if _, err := fs2.Stat("c.txt"); err != nil {
		t.Fatalf("replayed tree: %v", err)
	}
	// Socket close released nothing; the replayed authority still
	// authenticates the same token.
	if _, err := fs2.AuthenticateSession("pfs-c", "tok"); err != nil {
		t.Fatalf("replayed authenticate: %v", err)
	}
}

// exactCtl builds an exact-keyed control (lock/checkout) with its request
// fingerprint filled in and a zero success outcome.
func lockControl(ref pfc2.SessionRef, slot uint32, seq uint64, ino, owner uint64, op pfc2.LockOp, start, length uint64) pfc2.Record {
	l := &pfc2.LockChange{
		Key: pfc2.ExactKey{Session: ref, Slot: slot, SlotSeq: seq},
		Ino: ino, KernelLockOwner: owner, Op: op, Start: start, Length: length,
	}
	l.Key.RequestHash = l.RequestHash()
	return pfc2.Record{Kind: pfc2.KindLockChange, LockChange: l}
}

func checkoutGrant(ref pfc2.SessionRef, slot uint32, seq uint64, path string, epoch pfc2.Epoch) pfc2.Record {
	c := &pfc2.CheckoutChange{
		Key: pfc2.ExactKey{Session: ref, Slot: slot, SlotSeq: seq},
		Op:  pfc2.CheckoutGrant, Path: path, Epoch: epoch,
	}
	c.Key.RequestHash = c.RequestHash()
	return pfc2.Record{Kind: pfc2.KindCheckoutChange, CheckoutChange: c}
}

// TestManagedCoordinationSurvivesColdReplay proves the POSIX foundation
// gap is closed for the durable substrate: a lock, a checkout, an open pin,
// and a flush watermark journaled as ordered PFC2 controls all survive a
// cold, empty-child replay byte-identically — no in-memory manager involved.
func TestManagedCoordinationSurvivesColdReplay(t *testing.T) {
	fs, log := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-co", 1, "o", 8, "tok"); err != nil {
		t.Fatal(err)
	}
	ref := pfc2.SessionRef{SessionID: "pfs-co", Generation: 1}

	// Open pin on a live inode, a write lock, and a checkout grant (each in
	// its own row so slot sequences advance cleanly).
	pin := pfc2.Record{Kind: pfc2.KindOpenPinChange, OpenPinChange: &pfc2.OpenPinChange{Session: ref, Ino: 5}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{pin}, ""); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{lockControl(ref, 0, 1, 5, 0xbeef, pfc2.LockSetWrite, 0, 0)}, ""); err != nil {
		t.Fatalf("lock: %v", err)
	}
	control, _ := fs.ManagedControl()
	grant := checkoutGrant(ref, 1, 1, "proj/data", control.NextCheckoutEpoch())
	grant.CheckoutChange.WritebackID = "wb-1"
	grant.CheckoutChange.Key.RequestHash = grant.CheckoutChange.RequestHash()
	if _, err := fs.CommitEntry(nil, []pfc2.Record{grant}, ""); err != nil {
		t.Fatalf("checkout: %v", err)
	}
	view, held := control.CheckoutAt("proj/data")
	if !held || view.Holder != ref {
		t.Fatalf("checkout not held: %+v %v", view, held)
	}
	// A stream watermark under the held grant, in one row (the write-back
	// flush pattern: user records + FlushAdvance in one PFJ3 entry).
	flush := pfc2.Record{Kind: pfc2.KindFlushAdvance, FlushAdvance: &pfc2.FlushAdvance{
		Session: ref, WritebackID: "wb-1", CheckoutPath: "proj/data",
		CheckoutEpoch: view.Epoch, Through: 42, Digest: [32]byte{0x42},
	}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{flush}, ""); err != nil {
		t.Fatalf("flush: %v", err)
	}

	before := managedDigest(t, fs)

	// Cold empty-child replay reconstructs every coordination object.
	fs2, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("cold replay: %v", err)
	}
	if managedDigest(t, fs2) != before {
		t.Fatal("coordination state diverged across cold replay")
	}
	control2, _ := fs2.ManagedControl()
	if !control2.HasPin(ref, 5) {
		t.Fatal("open pin did not survive failover")
	}
	if locks := control2.HeldLocks(5); len(locks) != 1 || !locks[0].Write || locks[0].Owner.Session != ref {
		t.Fatalf("held lock did not survive failover: %+v", locks)
	}
	if v, held := control2.CheckoutAt("proj/data"); !held || v.Holder != ref || v.Epoch != view.Epoch {
		t.Fatalf("checkout did not survive failover: %+v %v", v, held)
	}
	if sv, ok := control2.StreamState("wb-1"); !ok || sv.Through != 42 {
		t.Fatalf("stream watermark did not survive failover: %+v %v", sv, ok)
	}
	// The high-water dominates the pinned/locked inode 5 even though it is
	// not in the (empty) base tree: a fresh create can never reuse it.
	fs2.mu.Lock()
	next := fs2.alloc.maxInoSeen
	fs2.mu.Unlock()
	if next < 5 {
		t.Fatalf("inode high-water %d does not dominate pinned/locked inode 5", next)
	}
}

// TestManagedInoHighWaterFromBase proves a persisted MaxInoSeen (PFT2
// RecoveryRoot / 013 seam) lifts the allocator above ids the loaded tree no
// longer contains, so a compaction that dropped a high create cannot let a
// fresh create reuse that id.
func TestManagedInoHighWaterFromBase(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManagedFromBase(BaseImage{Entries: nil, MaxInoSeen: 9000}, nil, log, content.NewCache(defaultCacheBytes))
	if err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	got, aerr := fs.allocIno()
	fs.mu.Unlock()
	if aerr != nil {
		t.Fatal(aerr)
	}
	if got != 9001 {
		t.Fatalf("allocated %d; a persisted high-water of 9000 must hand out 9001", got)
	}
}

// TestManagedFsyncNeedsNoHistoryCut proves an ordinary durability barrier is
// exactly the authority commit/apply boundary: it touches no cut/checkpoint/
// snapshot surface (the fake fails those loudly) and succeeds while the log
// is live, failing closed only when sealed or poisoned.
func TestManagedFsyncNeedsNoHistoryCut(t *testing.T) {
	fs, _ := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-b", 1, "o", 8, "tok"); err != nil {
		t.Fatal(err)
	}
	hash := make([]byte, 32)
	hash[0] = 0x41
	env := &wal.Envelope{SessionID: "pfs-b", Generation: 1, Slot: 0, SlotSeq: 1, ReqHash: hash}
	if _, err := fs.MutateEnv(wal.Record{Op: wal.OpCreate, Path: "b.txt", Mode: 0o644, Env: env}, "o"); err != nil {
		t.Fatal(err)
	}
	// The barrier succeeds without any cut/checkpoint/object-store call (the
	// fake entry log panics/errs on those; reaching them would fail the test).
	if err := fs.DurabilityBarrier(); err != nil {
		t.Fatalf("durability barrier on a live authority: %v", err)
	}
	// Sealed authority fails the barrier closed.
	if err := fs.Seal(context.Background()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := fs.DurabilityBarrier(); !errors.Is(err, ErrSealed) {
		t.Fatalf("sealed barrier: %v", err)
	}
}

func TestManagedIssuanceBindsExactDurableFloor(t *testing.T) {
	fs, log := newManagedFS(t)
	if err := fs.EstablishSessionWithToken("pfs-f", 1, "o", 8, "tok"); err != nil {
		t.Fatal(err)
	}
	// Tamper the fake's durable floor: the next mint presents the applied
	// reducer's floor, which no longer EQUALS the durable floor, and the
	// issuance fails closed instead of minting against divergent state.
	log.mu.Lock()
	log.floor++
	log.mu.Unlock()
	ref := pfc2.SessionRef{SessionID: "pfs-f", Generation: 1}
	if _, err := fs.IssueAdmissionFact(ref, pfc2.FactPurposeSessionRenew); err == nil {
		t.Fatal("issuance accepted a non-exact floor")
	}
}
