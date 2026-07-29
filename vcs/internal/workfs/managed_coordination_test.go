package workfs

// Managed coordination semantics: inode-keyed journaled locks, epoch'd
// checkouts, open-pin decisions, per-row flush advances, the sync barrier,
// deterministic reap scheduling, and cold-replay equivalence — all against
// the honest in-memory PFJ3 entry log (fakeEntryLog).

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// coordEnv builds an exact envelope for a coordination decision, stamping the
// canonical hash the durable record must carry.
func coordEnv(ref pfc2.SessionRef, slot uint32, seq uint64, hash []byte) *wal.Envelope {
	return &wal.Envelope{
		SessionID: ref.SessionID, Generation: ref.Generation,
		Slot: slot, SlotSeq: seq, ReqHash: hash,
	}
}

func lockEnv(t *testing.T, ref pfc2.SessionRef, slot uint32, seq uint64, ino, owner uint64, op pfc2.LockOp, start, length uint64) *wal.Envelope {
	t.Helper()
	env := coordEnv(ref, slot, seq, nil)
	hash, err := LockChangeRequestHash(env, ino, owner, op, start, length)
	if err != nil {
		t.Fatalf("lock hash: %v", err)
	}
	env.ReqHash = hash
	return env
}

// managedCreateFile commits one exact create and returns its stable ino.
func managedCreateFile(t *testing.T, fs *FS, ref pfc2.SessionRef, slot uint32, seq uint64, path string) uint64 {
	t.Helper()
	hash := make([]byte, 32)
	hash[0], hash[1] = byte(seq), byte(slot)|0x10
	res, err := fs.MutateEnv(wal.Record{
		Op: wal.OpCreate, Path: path, Mode: 0o644,
		Env: coordEnv(ref, slot, seq, hash),
	}, "")
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if res.Ino == 0 {
		t.Fatalf("create %s returned no ino", path)
	}
	return res.Ino
}

func TestManagedLockLifecycleAndReplay(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-lockA", 1)
	b := openManagedSession(t, fs, "pfs-lockB", 1)
	ino := managedCreateFile(t, fs, a, 0, 1, "db.sqlite")

	lockDecide := func(env *wal.Envelope, kernelOwner uint64, op pfc2.LockOp, start, length uint64) CoordinationDecision {
		t.Helper()
		d, err := fs.ManagedLockDecide(env, ino, kernelOwner, op, start, length)
		if err != nil {
			t.Fatalf("lock decide: %v", err)
		}
		return d
	}
	// A takes a whole-file read lock (kernel owner 7) — one journal row.
	envA := lockEnv(t, a, 1, 1, ino, 7, pfc2.LockSetRead, 0, 0)
	if d := lockDecide(envA, 7, pfc2.LockSetRead, 0, 0); d.Status != 0 {
		t.Fatalf("A read lock status %d", d.Status)
	}
	// B's overlapping write lock is a durable EAGAIN in the SAME reservation
	// that observed the conflict; its duplicate retry replays EAGAIN.
	envB := lockEnv(t, b, 0, 1, ino, 9, pfc2.LockSetWrite, 10, 5)
	if d := lockDecide(envB, 9, pfc2.LockSetWrite, 10, 5); d.Status != int32(11) {
		t.Fatalf("B write lock status %d, want EAGAIN", d.Status)
	}
	if res, out := fs.CheckSlot(envB); res != SlotDuplicate || out.Status != 11 {
		t.Fatalf("EAGAIN replay: res=%v status=%d", res, out.Status)
	}
	// Same-session different kernel owner IS a different owner (POSIX): EAGAIN.
	envA2 := lockEnv(t, a, 2, 1, ino, 8, pfc2.LockSetWrite, 0, 4)
	if d := lockDecide(envA2, 8, pfc2.LockSetWrite, 0, 4); d.Status != int32(11) {
		t.Fatalf("same-session different-owner write status %d, want EAGAIN", d.Status)
	}
	// A duplicate of the GRANT replays success without a second row.
	if res, out := fs.CheckSlot(envA); res != SlotDuplicate || out.Status != 0 {
		t.Fatalf("grant replay: res=%v status=%d", res, out.Status)
	}
	// B can lock a NON-overlapping range... the whole file is read-locked by
	// A, so B takes a READ lock (shared) instead.
	envB2 := lockEnv(t, b, 1, 1, ino, 9, pfc2.LockSetRead, 100, 10)
	if d := lockDecide(envB2, 9, pfc2.LockSetRead, 100, 10); d.Status != 0 {
		t.Fatalf("B shared read status %d", d.Status)
	}
	// A unlocks a sub-range (split) — unlock always succeeds.
	envA3 := lockEnv(t, a, 3, 1, ino, 7, pfc2.LockUnlock, 10, 5)
	if d := lockDecide(envA3, 7, pfc2.LockUnlock, 10, 5); d.Status != 0 {
		t.Fatalf("A partial unlock status %d", d.Status)
	}
	// Now B's write lock over the freed hole succeeds with a FRESH identity.
	envB3 := lockEnv(t, b, 0, 2, ino, 9, pfc2.LockSetWrite, 10, 5)
	if d := lockDecide(envB3, 9, pfc2.LockSetWrite, 10, 5); d.Status != 0 {
		t.Fatalf("B write lock after unlock status %d", d.Status)
	}

	// Session terminal releases ALL of B's remaining locks deterministically.
	if err := fs.ExpireSession(b.SessionID, b.Generation); err != nil {
		t.Fatalf("terminal B: %v", err)
	}
	control, _ := fs.ManagedControl()
	for _, h := range control.HeldLocks(ino) {
		if h.Owner.Session == b {
			t.Fatalf("terminal left B's lock: %+v", h)
		}
	}

	// Cold replay rebuilds the identical lock table and outcomes.
	replayed, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if got, want := managedDigest(t, replayed), managedDigest(t, fs); got != want {
		t.Fatalf("replayed control digest diverged")
	}
	// A's grant identity replays durably; B's identities are fenced by the
	// terminal tombstone (exactness is never forgotten, only compacted).
	if res, out := replayed.CheckSlot(envA); res != SlotDuplicate || out.Status != 0 {
		t.Fatalf("replayed grant outcome: res=%v status=%d", res, out.Status)
	}
	if res, _ := replayed.CheckSlot(envB); res != SlotUnknownSession {
		t.Fatalf("terminated session identity: res=%v, want unknown-session fence", res)
	}
}

func TestManagedLockIdentityStableAcrossRenameAndUnlink(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-ren", 1)
	ino := managedCreateFile(t, fs, a, 0, 1, "before")

	env := lockEnv(t, a, 1, 1, ino, 3, pfc2.LockSetWrite, 0, 0)
	if d, err := fs.ManagedLockDecide(env, ino, 3, pfc2.LockSetWrite, 0, 0); err != nil || d.Status != 0 {
		t.Fatalf("lock: d=%+v err=%v", d, err)
	}
	// Rename the file: the lock identity (ino) is untouched.
	hash := make([]byte, 32)
	hash[0] = 0xAB
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpRename, Path: "before", NewPath: "after",
		Env: coordEnv(a, 0, 2, hash),
	}, ""); err != nil {
		t.Fatalf("rename: %v", err)
	}
	control, _ := fs.ManagedControl()
	if held := control.HeldLocks(ino); len(held) != 1 {
		t.Fatalf("lock lost across rename: %+v", held)
	}
	// Unlink (orphan) the file: the lock is still keyed by the parked ino.
	hash2 := make([]byte, 32)
	hash2[0] = 0xCD
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpOrphan, Path: "after",
		Env: coordEnv(a, 0, 3, hash2),
	}, ""); err != nil {
		t.Fatalf("orphan: %v", err)
	}
	if held := control.HeldLocks(ino); len(held) != 1 {
		t.Fatalf("lock lost across unlink: %+v", held)
	}
	// Unlock by ino after rename+unlink still works (owner-close cleanup).
	envU := lockEnv(t, a, 1, 2, ino, 3, pfc2.LockUnlock, 0, 0)
	if d, err := fs.ManagedLockDecide(envU, ino, 3, pfc2.LockUnlock, 0, 0); err != nil || d.Status != 0 {
		t.Fatalf("unlock: d=%+v err=%v", d, err)
	}
	if held := control.HeldLocks(ino); len(held) != 0 {
		t.Fatalf("unlock by ino failed: %+v", held)
	}
}

func TestManagedCheckoutEpochLifecycle(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-coA", 1)
	b := openManagedSession(t, fs, "pfs-coB", 1)

	grantHash := func(ref pfc2.SessionRef, slot uint32, seq uint64, path string) *wal.Envelope {
		env := coordEnv(ref, slot, seq, nil)
		h, err := CheckoutRequestHash(env, false, path, "")
		if err != nil {
			t.Fatalf("grant hash: %v", err)
		}
		env.ReqHash = h
		return env
	}
	releaseHash := func(ref pfc2.SessionRef, slot uint32, seq uint64, path, epoch string) *wal.Envelope {
		env := coordEnv(ref, slot, seq, nil)
		h, err := CheckoutRequestHash(env, true, path, epoch)
		if err != nil {
			t.Fatalf("release hash: %v", err)
		}
		env.ReqHash = h
		return env
	}

	d, err := fs.ManagedCheckoutDecide(grantHash(a, 0, 1, "proj"), "proj")
	if err != nil || d.Status != 0 {
		t.Fatalf("grant: d=%+v err=%v", d, err)
	}
	if d.Epoch != "1" {
		t.Fatalf("first epoch %q, want 1", d.Epoch)
	}
	// Overlapping grant (subtree) is a durable EBUSY in the SAME reservation.
	if d, err := fs.ManagedCheckoutDecide(grantHash(b, 0, 1, "proj/sub"), "proj/sub"); err != nil || d.Status != int32(16) {
		t.Fatalf("overlap grant: d=%+v err=%v, want EBUSY", d, err)
	}
	// A release naming the WRONG epoch is a durable ENOENT (not the caller's
	// live grant).
	if d, err := fs.ManagedCheckinDecide(releaseHash(a, 1, 1, "proj", "9"), "proj", "9"); err != nil || d.Status != int32(2) {
		t.Fatalf("wrong-epoch release: d=%+v err=%v, want ENOENT", d, err)
	}
	// Another session cannot release the holder's grant.
	if d, err := fs.ManagedCheckinDecide(releaseHash(b, 1, 1, "proj", "1"), "proj", "1"); err != nil || d.Status != int32(2) {
		t.Fatalf("foreign release: d=%+v err=%v, want ENOENT", d, err)
	}
	// The holder's exact release frees it; the next grant takes epoch 2.
	if d, err := fs.ManagedCheckinDecide(releaseHash(a, 2, 1, "proj", "1"), "proj", "1"); err != nil || d.Status != 0 {
		t.Fatalf("release: d=%+v err=%v", d, err)
	}
	d2, err := fs.ManagedCheckoutDecide(grantHash(b, 2, 1, "proj"), "proj")
	if err != nil || d2.Status != 0 {
		t.Fatalf("re-grant: d=%+v err=%v", d2, err)
	}
	if d2.Epoch != "2" {
		t.Fatalf("second epoch %q, want 2 (durable monotonic)", d2.Epoch)
	}
	// Terminal releases B's grant without any timeout force-transfer.
	if err := fs.ExpireSession(b.SessionID, b.Generation); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	if _, held, _ := fs.ManagedCheckoutAt("proj"); held {
		t.Fatal("terminal did not release the checkout")
	}
}

func TestManagedPinDecisionsAndReap(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-pin", 1)
	ino := managedCreateFile(t, fs, a, 0, 1, "held")

	pinHash := func(seed byte) []byte {
		h := make([]byte, 32)
		h[0] = seed
		return h
	}
	// Pin the live inode.
	h1 := pinHash(1)
	if err := fs.ManagedPinChange(coordEnv(a, 1, 1, h1), ino, false, h1); err != nil {
		t.Fatalf("pin: %v", err)
	}
	control, _ := fs.ManagedControl()
	if !control.HasPin(a, ino) {
		t.Fatal("pin not durable")
	}
	// Re-pin with a FRESH identity is protocol-idempotent: identity consumed,
	// no second pin row.
	h2 := pinHash(2)
	if err := fs.ManagedPinChange(coordEnv(a, 1, 2, h2), ino, false, h2); err != nil {
		t.Fatalf("idempotent pin: %v", err)
	}
	// Unlink while pinned: the inode parks as an orphan; reap sweep must NOT
	// destroy it while the durable pin holds.
	uh := pinHash(3)
	if _, err := fs.MutateEnv(wal.Record{Op: wal.OpOrphan, Path: "held", Env: coordEnv(a, 0, 2, uh)}, ""); err != nil {
		t.Fatalf("orphan: %v", err)
	}
	if reaped := fs.ManagedReapSweep(); reaped != 0 {
		t.Fatalf("sweep reaped %d while pinned", reaped)
	}
	if _, ok := fs.OrphanInfo(ino); !ok {
		t.Fatal("pinned orphan disappeared")
	}
	// Last unpin schedules the deterministic reap (the commit path kicks an
	// asynchronous sweep; the explicit sweep below covers a lost trigger —
	// either way the orphan must be reaped exactly once).
	h3 := pinHash(4)
	if err := fs.ManagedPinChange(coordEnv(a, 1, 3, h3), ino, true, h3); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	fs.ManagedReapSweep()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := fs.OrphanInfo(ino); !ok {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("orphan survived reap")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Pin of the reaped ino is a durable ENOENT decision.
	h4 := pinHash(5)
	err = fs.ManagedPinChange(coordEnv(a, 1, 4, h4), ino, false, h4)
	if !errors.Is(err, ErrPinTargetGone) {
		t.Fatalf("pin of reaped ino: %v, want ErrPinTargetGone", err)
	}
	if res, out := fs.CheckSlot(coordEnv(a, 1, 4, h4)); res != SlotDuplicate || out.Status != 2 {
		t.Fatalf("ENOENT pin outcome replay: res=%v status=%d", res, out.Status)
	}

	// Cold replay: the reap row replays; the orphan stays gone; outcomes match.
	replayed, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if _, ok := replayed.OrphanInfo(ino); ok {
		t.Fatal("replayed orphan resurrected")
	}
	if got, want := managedDigest(t, replayed), managedDigest(t, fs); got != want {
		t.Fatal("replayed control digest diverged")
	}
}

// TestManagedPinRefusesReservedReap freezes the reservation-order contract
// behind open(): once an OpReap row has won for an orphan, the applied tree
// may still contain that inode briefly, but a later pin must see it as
// logically gone. Otherwise open can acknowledge a handle that the lower-LSN
// reap is guaranteed to destroy before the first read.
func TestManagedPinRefusesReservedReap(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-reap-owner", 1)
	b := openManagedSession(t, fs, "pfs-reap-racer", 1)
	ino := managedCreateFile(t, fs, a, 0, 1, "retired")

	hash := func(seed byte) []byte {
		h := make([]byte, 32)
		h[0] = seed
		return h
	}
	pin := hash(1)
	if err := fs.ManagedPinChange(coordEnv(a, 1, 1, pin), ino, false, pin); err != nil {
		t.Fatalf("pin: %v", err)
	}
	orphan := hash(2)
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpOrphan, Path: "retired", Env: coordEnv(a, 0, 2, orphan),
	}, ""); err != nil {
		t.Fatalf("orphan: %v", err)
	}

	// Keep the automatic sweep parked so this test can model the exact
	// reservation/apply interval deterministically.
	fs.managed.sweepScheduled.Store(true)
	t.Cleanup(func() { fs.managed.sweepScheduled.Store(false) })
	unpin := hash(3)
	if err := fs.ManagedPinChange(coordEnv(a, 1, 2, unpin), ino, true, unpin); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	fs.mu.Lock()
	if fs.orphans[ino] == nil {
		fs.mu.Unlock()
		t.Fatal("orphan disappeared before reserved-reap model")
	}
	fs.pendingReaps[ino] = 1 // an OpReap row is reserved below the racing pin
	fs.mu.Unlock()

	race := hash(4)
	err = fs.ManagedPinChange(coordEnv(b, 0, 1, race), ino, false, race)
	if !errors.Is(err, ErrPinTargetGone) {
		t.Fatalf("pin behind reserved reap: %v, want ErrPinTargetGone", err)
	}
	if res, out := fs.CheckSlot(coordEnv(b, 0, 1, race)); res != SlotDuplicate || out.Status != 2 {
		t.Fatalf("reserved-reap ENOENT replay: res=%v status=%d", res, out.Status)
	}
	if err := fs.ManagedEnsureOpenPin(b, ino); !errors.Is(err, ErrPinTargetGone) {
		t.Fatalf("fused ensure behind reserved reap: %v, want ErrPinTargetGone", err)
	}
}

// flushDigests chains the stream digest over rows starting from prev,
// returning the end digest (the client-side computation).
func flushDigests(t *testing.T, prev [32]byte, rows []ManagedFlushRow) [32]byte {
	t.Helper()
	d := prev
	for _, row := range rows {
		var err error
		d, err = writebackStreamDigest(d, row.Seq, row.Record)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
	}
	return d
}

func TestManagedFlushRowsAdvanceAndRetry(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-flush", 1)
	epoch := grantDelegation(t, fs, a, 0, 1, "ws", "wb-1")

	// Dense global stream sequences from 1.
	rows := []ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpMkdir, Path: "ws", Mode: 0o755}},
		{Seq: 2, Record: wal.Record{Op: wal.OpCreate, Path: "ws/a", Mode: 0o644}},
		{Seq: 3, Record: wal.Record{Op: wal.OpWrite, Path: "ws/a", Data: []byte("hello")}},
		{Seq: 4, Record: wal.Record{Op: wal.OpMkdir, Path: "ws/dir", Mode: 0o755}},
	}
	prev := digestZeroStream()
	end := flushDigests(t, prev, rows)
	through, err := fs.ManagedFlushApply(a, "wb-1", "ws", epoch, prev, end, rows, "M")
	if err != nil || through != 4 {
		t.Fatalf("flush: through=%d err=%v", through, err)
	}
	if view, ok, _ := fs.ManagedWritebackState("wb-1"); !ok || view.Through != 4 || view.Digest != end {
		t.Fatalf("durable stream state %+v ok=%v", view, ok)
	}
	// A lost-reply retry of the identical batch converges without double
	// apply: everything at or below the durable watermark drops.
	through2, err := fs.ManagedFlushApply(a, "wb-1", "ws", epoch, prev, end, rows, "M")
	if err != nil || through2 != 4 {
		t.Fatalf("retry flush: through=%d err=%v", through2, err)
	}
	data := make([]byte, 16)
	n, err := fs.ReadHandleAt("ws/a", 0, data, 0)
	if (err != nil && !errors.Is(err, io.EOF)) || string(data[:n]) != "hello" {
		t.Fatalf("content after retry: %q err=%v", data[:n], err)
	}
	// A gapped continuation is the typed corrupt verdict, not a partial apply.
	gap := []ManagedFlushRow{{Seq: 6, Record: wal.Record{Op: wal.OpCreate, Path: "ws/gap", Mode: 0o644}}}
	if _, err := fs.ManagedFlushApply(a, "wb-1", "ws", epoch, end, flushDigests(t, end, gap), gap, "M"); !errors.Is(err, ErrWritebackCorrupt) {
		t.Fatalf("gapped flush: %v, want ErrWritebackCorrupt", err)
	}
	// A diverging digest at the same sequences fences too.
	forged := []ManagedFlushRow{{Seq: 5, Record: wal.Record{Op: wal.OpCreate, Path: "ws/forged", Mode: 0o644}}}
	if _, err := fs.ManagedFlushApply(a, "wb-1", "ws", epoch, end, end, forged, "M"); !errors.Is(err, ErrWritebackCorrupt) {
		t.Fatalf("digest-diverging flush: %v, want ErrWritebackCorrupt", err)
	}
	// A flush naming a released epoch is fenced; the STREAM watermark
	// survives the release (the mount stream spans grants).
	renv := coordEnv(a, 1, 1, nil)
	rh, err := CheckoutRequestHash(renv, true, "ws", epoch)
	if err != nil {
		t.Fatal(err)
	}
	renv.ReqHash = rh
	if d, err := fs.ManagedCheckinDecide(renv, "ws", epoch); err != nil || d.Status != 0 {
		t.Fatalf("release: d=%+v err=%v", d, err)
	}
	late := []ManagedFlushRow{{Seq: 5, Record: wal.Record{Op: wal.OpCreate, Path: "ws/late", Mode: 0o644}}}
	if _, err := fs.ManagedFlushApply(a, "wb-1", "ws", epoch, end, flushDigests(t, end, late), late, "M"); !errors.Is(err, ErrSessionStale) {
		t.Fatalf("stale-epoch flush: %v, want stale", err)
	}
	if view, ok, _ := fs.ManagedWritebackState("wb-1"); !ok || view.Through != 4 {
		t.Fatalf("stream watermark did not survive the release: %+v ok=%v", view, ok)
	}

	// Cold replay reproduces the stream state and the tree.
	replayed, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if view, ok, _ := replayed.ManagedWritebackState("wb-1"); !ok || view.Through != 4 {
		t.Fatalf("replayed stream state %+v ok=%v", view, ok)
	}
	n2, err := replayed.ReadHandleAt("ws/a", 0, data, 0)
	if (err != nil && !errors.Is(err, io.EOF)) || string(data[:n2]) != "hello" {
		t.Fatalf("replayed content: %q err=%v", data[:n2], err)
	}
}

// grantCheckout grants a plain checkout via the decide API and returns the
// epoch.
func grantCheckout(t *testing.T, fs *FS, ref pfc2.SessionRef, slot uint32, seq uint64, path string) string {
	t.Helper()
	env := coordEnv(ref, slot, seq, nil)
	h, err := CheckoutRequestHash(env, false, path, "")
	if err != nil {
		t.Fatalf("grant hash: %v", err)
	}
	env.ReqHash = h
	d, err := fs.ManagedCheckoutDecide(env, path)
	if err != nil || d.Status != 0 {
		t.Fatalf("grant checkout %q: d=%+v err=%v", path, d, err)
	}
	return d.Epoch
}

// grantDelegation grants a stream-bound delegation and returns the epoch.
func grantDelegation(t *testing.T, fs *FS, ref pfc2.SessionRef, slot uint32, seq uint64, path, writebackID string) string {
	t.Helper()
	env := coordEnv(ref, slot, seq, nil)
	h, err := DelegationRequestHash(env, path, writebackID)
	if err != nil {
		t.Fatalf("delegation hash: %v", err)
	}
	env.ReqHash = h
	d, err := fs.ManagedDelegationDecide(env, path, writebackID)
	if err != nil || d.Status != 0 {
		t.Fatalf("grant delegation %q: d=%+v err=%v", path, d, err)
	}
	return d.Epoch
}

func TestManagedFlushGroupCrashKeepsRowAtomicity(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-crash", 1)
	epoch := grantDelegation(t, fs, a, 0, 1, "ws", "wb")
	// Inject an append failure for the flush group: NOTHING becomes durable
	// (all-or-nothing reservation), the watermark stays put, and the retry
	// lands everything.
	log.mu.Lock()
	log.failaAt = log.appends + 1
	log.mu.Unlock()
	rows := []ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpMkdir, Path: "ws", Mode: 0o755}},
		{Seq: 2, Record: wal.Record{Op: wal.OpCreate, Path: "ws/x", Mode: 0o644}},
		{Seq: 3, Record: wal.Record{Op: wal.OpWrite, Path: "ws/x", Data: []byte("v1")}},
	}
	prev := digestZeroStream()
	end := flushDigests(t, prev, rows)
	if _, err := fs.ManagedFlushApply(a, "wb", "ws", epoch, prev, end, rows, "M"); err == nil {
		t.Fatal("injected append failure did not surface")
	}
	if _, ok, _ := fs.ManagedWritebackState("wb"); ok {
		t.Fatal("failed group advanced the stream ledger")
	}
	through, err := fs.ManagedFlushApply(a, "wb", "ws", epoch, prev, end, rows, "M")
	if err != nil || through != 3 {
		t.Fatalf("retry flush: through=%d err=%v", through, err)
	}
}

func TestManagedWritebackRecoveryLifecycle(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-dead", 1)
	epoch := grantDelegation(t, fs, a, 0, 1, "ws", "wb")
	rows := []ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpMkdir, Path: "ws", Mode: 0o755}},
		{Seq: 2, Record: wal.Record{Op: wal.OpCreate, Path: "ws/a", Mode: 0o644}},
	}
	prev := digestZeroStream()
	end := flushDigests(t, prev, rows)
	if _, err := fs.ManagedFlushApply(a, "wb", "ws", epoch, prev, end, rows, "M"); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// The holder dies without a clean release: the scope is recovery-
	// required, never silently released.
	if err := fs.ExpireSession(a.SessionID, a.Generation); err != nil {
		t.Fatalf("expire: %v", err)
	}
	views, _ := fs.ManagedOverlappingCheckouts("ws")
	if len(views) != 1 || !views[0].Recovery {
		t.Fatalf("scope after holder death: %+v", views)
	}

	// A recovering mount (fresh session, same stream identity) rebinds and
	// drains the tail under the SAME epoch.
	b := openManagedSession(t, fs, "pfs-reborn", 1)
	benv := coordEnv(b, 0, 1, nil)
	rh := []byte("recovery-rebind-hash-32-bytes...")[:32]
	benv.ReqHash = rh
	conflicts, err := fs.ManagedWritebackRebind(benv, rh, "wb", []WritebackScope{{Path: "ws", Epoch: epoch}}, 2, end)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("rebind: conflicts=%v err=%v", conflicts, err)
	}
	tail := []ManagedFlushRow{{Seq: 3, Record: wal.Record{Op: wal.OpWrite, Path: "ws/a", Data: []byte("recovered")}}}
	tailEnd := flushDigests(t, end, tail)
	if _, err := fs.ManagedFlushApply(b, "wb", "ws", epoch, end, tailEnd, tail, "M"); err != nil {
		t.Fatalf("recovery flush: %v", err)
	}
	data := make([]byte, 16)
	n, err := fs.ReadHandleAt("ws/a", 0, data, 0)
	if (err != nil && !errors.Is(err, io.EOF)) || string(data[:n]) != "recovered" {
		t.Fatalf("recovered content: %q err=%v", data[:n], err)
	}
	// A rebind claiming the WRONG digest is a typed conflict, never a merge.
	c := openManagedSession(t, fs, "pfs-liar", 1)
	cenv := coordEnv(c, 0, 1, nil)
	ch := []byte("conflicting-rebind-hash-32-byte.")[:32]
	cenv.ReqHash = ch
	conflicts, err = fs.ManagedWritebackRebind(cenv, ch, "wb", []WritebackScope{{Path: "ws", Epoch: epoch}}, 1, prev)
	if err != nil || len(conflicts) == 0 {
		t.Fatalf("conflicting rebind: conflicts=%v err=%v", conflicts, err)
	}
}

func TestManagedSyncBarrier(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-sync", 1)
	managedCreateFile(t, fs, a, 0, 1, "f")
	// The barrier covers every reserved row and never requires a checkpoint,
	// history cut, or object store (the fake log has none of them).
	if err := fs.SyncBarrier(); err != nil {
		t.Fatalf("sync barrier: %v", err)
	}
	fs.Seal(context.Background())
	if err := fs.SyncBarrier(); !errors.Is(err, ErrSealed) {
		t.Fatalf("sealed barrier: %v, want ErrSealed", err)
	}
}

func TestManagedConditionalOpsExactOutcomes(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-cond", 1)

	hash := func(seed byte) []byte {
		h := make([]byte, 32)
		h[0] = seed
		return h
	}
	// Each decision rides its own SLOT so every outcome stays the slot's
	// retained latest and replays after cold recovery (a slot retains only
	// its latest outcome by design).
	// Exclusive create: first wins, second (fresh identity) gets EEXIST as a
	// DURABLE outcome; its duplicate replays EEXIST byte-identically.
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpCreate, Path: "x", Mode: 0o644, Excl: true,
		Env: coordEnv(a, 0, 1, hash(1)),
	}, ""); err != nil {
		t.Fatalf("excl create: %v", err)
	}
	env2 := coordEnv(a, 1, 1, hash(2))
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpCreate, Path: "x", Mode: 0o644, Excl: true, Env: env2,
	}, ""); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second excl create: %v, want EEXIST", err)
	}
	if res, out := fs.CheckSlot(env2); res != SlotDuplicate || out.Status != 17 {
		t.Fatalf("EEXIST replay: res=%v status=%d", res, out.Status)
	}
	// Single-component mkdir: missing parent is ENOENT (never mkdir -p);
	// existing name is EEXIST.
	env3 := coordEnv(a, 2, 1, hash(3))
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpMkdir, Path: "missing/child", Mode: 0o755, Excl: true, Env: env3,
	}, ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mkdir under missing parent: %v, want ENOENT", err)
	}
	env4 := coordEnv(a, 3, 1, hash(4))
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpMkdir, Path: "d", Mode: 0o755, Excl: true, Env: env4,
	}, ""); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	env5 := coordEnv(a, 4, 1, hash(5))
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpMkdir, Path: "d", Mode: 0o755, Excl: true, Env: env5,
	}, ""); !errors.Is(err, os.ErrExist) {
		t.Fatalf("mkdir existing: %v, want EEXIST", err)
	}
	// Symlink is inherently exclusive.
	env6 := coordEnv(a, 5, 1, hash(6))
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpSymlink, Path: "x", Target: "d", Excl: true, Env: env6,
	}, ""); !errors.Is(err, os.ErrExist) {
		t.Fatalf("symlink over existing: %v, want EEXIST", err)
	}
	// RENAME_NOREPLACE: destination exists -> EEXIST, atomically at apply.
	env7 := coordEnv(a, 6, 1, hash(7))
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpRename, Path: "x", NewPath: "d", RenameNoReplace: true, Env: env7,
	}, ""); !errors.Is(err, os.ErrExist) {
		t.Fatalf("rename-no-replace onto existing: %v, want EEXIST", err)
	}
	env8 := coordEnv(a, 7, 1, hash(8))
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpRename, Path: "x", NewPath: "y", RenameNoReplace: true, Env: env8,
	}, ""); err != nil {
		t.Fatalf("rename-no-replace to fresh name: %v", err)
	}

	// All outcomes survive cold replay identically.
	replayed, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	for _, tc := range []struct {
		env    *wal.Envelope
		status int32
	}{
		{env2, 17}, {env3, 2}, {env5, 17}, {env6, 17}, {env7, 17}, {env8, 0},
	} {
		if res, out := replayed.CheckSlot(tc.env); res != SlotDuplicate || out.Status != tc.status {
			t.Fatalf("replayed outcome for seq %d: res=%v status=%d want %d",
				tc.env.SlotSeq, res, out.Status, tc.status)
		}
	}
	if _, err := replayed.Lstat("y"); err != nil {
		t.Fatalf("replayed tree missing y: %v", err)
	}
	if _, err := replayed.Lstat("x"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replayed tree still has x: %v", err)
	}
}

func TestManagedHardLinkNlinkAndLastLinkParking(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-link", 1)

	exact := func(slot uint32, seq uint64, seed byte, r wal.Record) MutationResult {
		t.Helper()
		hash := make([]byte, 32)
		hash[0], hash[1] = seed, byte(slot)
		r.Env = coordEnv(a, slot, seq, hash)
		res, err := fs.MutateEnv(r, "")
		if err != nil {
			t.Fatalf("op %v: %v", r.Op, err)
		}
		return res
	}
	// Create a file, then two hard links to it.
	src := exact(0, 1, 0x01, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	ino := src.Ino
	exact(1, 1, 0x02, wal.Record{Op: wal.OpLink, Path: "f", NewPath: "g"})
	exact(2, 1, 0x03, wal.Record{Op: wal.OpLink, Path: "g", NewPath: "h"})

	// All three names resolve to the same inode with nlink 3.
	for _, name := range []string{"f", "g", "h"} {
		fi, err := fs.Lstat(name)
		if err != nil {
			t.Fatalf("lstat %q: %v", name, err)
		}
		sys := fi.Sys().(interface {
			Ino() uint64
			LinkCount() uint32
		})
		if sys.Ino() != ino {
			t.Fatalf("%q ino %d, want shared %d", name, sys.Ino(), ino)
		}
		if sys.LinkCount() != 3 {
			t.Fatalf("%q nlink %d, want 3", name, sys.LinkCount())
		}
	}
	// A hard link to a directory is EPERM.
	exact(3, 1, 0x04, wal.Record{Op: wal.OpMkdir, Path: "d", Mode: 0o755, Excl: true})
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpLink, Path: "d", NewPath: "dlink",
		Env: coordEnv(a, 4, 1, func() []byte { h := make([]byte, 32); h[0] = 0x05; return h }()),
	}, ""); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("hard link to directory: %v, want EPERM", err)
	}
	// Link onto an existing name is EEXIST.
	if _, err := fs.MutateEnv(wal.Record{
		Op: wal.OpLink, Path: "f", NewPath: "g",
		Env: coordEnv(a, 5, 1, func() []byte { h := make([]byte, 32); h[0] = 0x06; return h }()),
	}, ""); !errors.Is(err, os.ErrExist) {
		t.Fatalf("link onto existing: %v, want EEXIST", err)
	}
	// Unlink two of the three names: the inode stays live (not parked) and
	// nlink drops to 1. The bytes remain readable under the surviving name.
	exact(0, 2, 0x07, wal.Record{Op: wal.OpWrite, Path: "f", Ino: ino, Data: []byte("shared")})
	exact(1, 2, 0x08, wal.Record{Op: wal.OpOrphan, Path: "f"})
	exact(2, 2, 0x09, wal.Record{Op: wal.OpOrphan, Path: "g"})
	if _, ok := fs.OrphanInfo(ino); ok {
		t.Fatal("inode parked while a hard link still referenced it")
	}
	fi, err := fs.Lstat("h")
	if err != nil {
		t.Fatalf("surviving link lstat: %v", err)
	}
	if fi.Sys().(interface{ LinkCount() uint32 }).LinkCount() != 1 {
		t.Fatalf("surviving nlink %d, want 1", fi.Sys().(interface{ LinkCount() uint32 }).LinkCount())
	}
	data := make([]byte, 16)
	n, _ := fs.ReadHandleAt("h", ino, data, 0)
	if string(data[:n]) != "shared" {
		t.Fatalf("surviving content %q, want shared", data[:n])
	}
	// The last-link unlink parks the inode (open-after-unlink).
	exact(0, 3, 0x0A, wal.Record{Op: wal.OpOrphan, Path: "h"})
	if _, ok := fs.OrphanInfo(ino); !ok {
		t.Fatal("last-link unlink did not park the inode")
	}

	// Cold replay reproduces the tree, nlink, and parked set identically.
	replayed, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if got, want := managedDigest(t, replayed), managedDigest(t, fs); got != want {
		t.Fatal("replayed control digest diverged")
	}
	if _, ok := replayed.OrphanInfo(ino); !ok {
		t.Fatal("replayed parked inode missing")
	}
}

func TestManagedLockWaitClearsVolatilely(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-waitA", 1)
	b := openManagedSession(t, fs, "pfs-waitB", 1)
	ino := managedCreateFile(t, fs, a, 0, 1, "w")

	envA := lockEnv(t, a, 1, 1, ino, 1, pfc2.LockSetWrite, 0, 0)
	if d, err := fs.ManagedLockDecide(envA, ino, 1, pfc2.LockSetWrite, 0, 0); err != nil || d.Status != 0 {
		t.Fatalf("A lock: d=%+v err=%v", d, err)
	}
	owner := pfc2.LockOwner{Session: b, KernelLockOwner: 2}
	// The wait is volatile: it clears once A unlocks, and consumed nothing.
	done := make(chan bool, 1)
	go func() {
		done <- fs.WaitCoordinationClear(time.Now().Add(2*time.Second), func() bool {
			_, conflicted, err := fs.ManagedLockConflict(ino, owner, 0, 0, true)
			return err == nil && !conflicted
		})
	}()
	time.Sleep(50 * time.Millisecond)
	envU := lockEnv(t, a, 1, 2, ino, 1, pfc2.LockUnlock, 0, 0)
	if d, err := fs.ManagedLockDecide(envU, ino, 1, pfc2.LockUnlock, 0, 0); err != nil || d.Status != 0 {
		t.Fatalf("A unlock: d=%+v err=%v", d, err)
	}
	if cleared := <-done; !cleared {
		t.Fatal("volatile wait did not observe the release")
	}
	envB := lockEnv(t, b, 0, 1, ino, 2, pfc2.LockSetWrite, 0, 0)
	if d, err := fs.ManagedLockDecide(envB, ino, 2, pfc2.LockSetWrite, 0, 0); err != nil || d.Status != 0 {
		t.Fatalf("B lock after wait: d=%+v err=%v", d, err)
	}
}
