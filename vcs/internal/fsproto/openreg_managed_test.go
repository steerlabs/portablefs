package fsproto

// Managed-generation open registration (FeatOpenRegistration on the
// journal-native server): the fused create+register, the batched last-close
// unmarks, duplicate-replay pin idempotence, the ENOENT degradation, and
// cold-failover replay of pins and their releases. Dispatch-level tests
// mirror coordinate_test.go (newManagedServer/openJournaledSession/exactDo);
// the socket tests drive a real *Client against serveManagedAuthorityFS so
// the feature bit alone is proven to light the client machinery up.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/pfc2"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// serveManagedAuthorityFS is serveManagedAuthority also returning the backing
// managed workfs, for tests that assert on the durable open-state surface.
func serveManagedAuthorityFS(t *testing.T) (string, *workfs.FS) {
	t.Helper()
	fs, err := workfs.NewManaged(nil, nopBlobs{}, newProtoEntryLog())
	if err != nil {
		t.Fatalf("new managed workfs: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := NewServer(fs, fs, nil)
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String(), fs
}

func managedPinState(t *testing.T, fs *workfs.FS) *pfc2.State {
	t.Helper()
	control, err := fs.ManagedControl()
	if err != nil {
		t.Fatalf("ManagedControl: %v", err)
	}
	return control
}

// waitReaped polls until the parked orphan is destroyed (the reap sweep is
// asynchronous; its decision re-validates atomically at its own staged
// position, so polling only waits for scheduling, never for correctness).
func waitReaped(t *testing.T, fs *workfs.FS, ino uint64) {
	t.Helper()
	fs.ManagedReapSweep()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := fs.OrphanInfo(ino); !ok {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("orphan %d survived the reap sweep", ino)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestManagedProbeAdvertisesOpenRegistration: the managed generation now
// earns FeatOpenRegistration (fused create+register, batched unmarks) next to
// its journaled-coordination bits.
func TestManagedProbeAdvertisesOpenRegistration(t *testing.T) {
	s, _ := newManagedServer(t, newProtoEntryLog())
	probe := s.dispatch(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)})
	if probe.ProtoVersion != ProtoVersionJournaledSessions {
		t.Fatalf("managed probe version = %d, want %d", probe.ProtoVersion, ProtoVersionJournaledSessions)
	}
	for _, feat := range []uint64{FeatOpenRegistration, FeatJournaledCoordination, FeatExactSessions} {
		if probe.Features&feat == 0 {
			t.Fatalf("managed probe features %b missing bit %b", probe.Features, feat)
		}
	}
}

// TestManagedFusedCreatePinsBeforeReply: the fused create's durable pin
// exists the moment the reply is issued, so a peer unlink ordered after the
// reply PARKS the inode instead of destroying it; the batched unmark then
// releases the pin and the reap destroys.
func TestManagedFusedCreatePinsBeforeReply(t *testing.T) {
	log := newProtoEntryLog()
	s, fs := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-orA", 1, "MA", "tokA", 8)
	b := openJournaledSession(t, s, "pfs-orB", 1, "MB", "tokB", 8)
	refA := pfc2.SessionRef{SessionID: "pfs-orA", Generation: 1}

	cr := exactDo(s, a, &Request{Op: OpCreate, Path: "fused", Mode: 0o644, RegisterOpen: true}, 0, 1)
	if cr == nil || cr.Status != OK || cr.Ino == 0 {
		t.Fatalf("fused create: %+v", cr)
	}
	ino := cr.Ino
	if !managedPinState(t, fs).HasPin(refA, ino) {
		t.Fatal("fused create replied without a durable open pin")
	}

	// Peer unlink after the reply: the pin makes the remove PARK.
	if r := exactDo(s, b, &Request{Op: OpRemove, Path: "fused"}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("peer remove: %+v", r)
	}
	if _, ok := fs.OrphanInfo(ino); !ok {
		t.Fatal("pinned inode was destroyed by the peer unlink, want parked")
	}
	if reaped := fs.ManagedReapSweep(); reaped != 0 {
		t.Fatalf("sweep reaped %d inodes while the fused pin is held", reaped)
	}
	if _, ok := fs.OrphanInfo(ino); !ok {
		t.Fatal("pinned orphan disappeared under the sweep")
	}

	// The batched unmark releases the pin in one exact row; the identical
	// resend replays the stored outcome without re-applying.
	un := &Request{Op: OpUnmarkOpenInodes, OpenInos: []uint64{ino}}
	if r := exactDo(s, a, un, 1, 1); r == nil || r.Status != OK {
		t.Fatalf("unmark batch: %+v", r)
	}
	if managedPinState(t, fs).HasPin(refA, ino) {
		t.Fatal("pin survived the batched unmark")
	}
	if r := exactDo(s, a, un, 1, 1); r == nil || r.Status != OK || !r.Duplicate {
		t.Fatalf("unmark batch replay: %+v, want duplicate OK", r)
	}
	waitReaped(t, fs, ino)

	// Envelope-less batched unmarks stay refused on this generation.
	if r := s.dispatch(&Request{Op: OpUnmarkOpenInodes, OpenInos: []uint64{ino}}); r == nil || r.Status != EPERM {
		t.Fatalf("envelope-less unmark: %+v, want EPERM", r)
	}
}

// TestManagedFusedCreateDuplicateReplayDoesNotDoublePin: a lost-reply retry
// of the fused create returns the stored outcome (Duplicate, same ino) and
// converges on exactly ONE durable pin — one batched unmark fully releases.
func TestManagedFusedCreateDuplicateReplayDoesNotDoublePin(t *testing.T) {
	log := newProtoEntryLog()
	s, fs := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-orDup", 1, "MA", "tokA", 8)
	refA := pfc2.SessionRef{SessionID: "pfs-orDup", Generation: 1}

	req := &Request{Op: OpCreate, Path: "dup", Mode: 0o644, RegisterOpen: true}
	first := exactDo(s, a, req, 0, 1)
	if first == nil || first.Status != OK || first.Ino == 0 {
		t.Fatalf("fused create: %+v", first)
	}
	rowsAfterFirst := log.rowCount()
	replay := exactDo(s, a, req, 0, 1)
	if replay == nil || replay.Status != OK || !replay.Duplicate || replay.Ino != first.Ino {
		t.Fatalf("fused create replay: %+v, want duplicate OK ino=%d", replay, first.Ino)
	}
	if got := log.rowCount(); got != rowsAfterFirst {
		t.Fatalf("duplicate replay journaled %d new rows, want 0 (pin ensure must be idempotent)", got-rowsAfterFirst)
	}
	if !managedPinState(t, fs).HasPin(refA, first.Ino) {
		t.Fatal("pin missing after duplicate replay")
	}
	// Exactly one pin: a single batched unmark leaves nothing behind.
	if r := exactDo(s, a, &Request{Op: OpUnmarkOpenInodes, OpenInos: []uint64{first.Ino}}, 1, 1); r == nil || r.Status != OK {
		t.Fatalf("unmark: %+v", r)
	}
	if managedPinState(t, fs).HasPin(refA, first.Ino) {
		t.Fatal("pin survived one unmark: the duplicate replay double-pinned")
	}
}

// TestManagedFusedCreateOverExistingPinsCurrentBinding: an idempotent fused
// create over an existing name pins the inode the name CURRENTLY binds
// (exactly the ino the two-RPC client would have re-stat'ed and marked), and
// an O_EXCL fused create that loses replies EEXIST without touching pins.
func TestManagedFusedCreateOverExistingPinsCurrentBinding(t *testing.T) {
	log := newProtoEntryLog()
	s, fs := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-orEx", 1, "MA", "tokA", 8)
	b := openJournaledSession(t, s, "pfs-orEy", 1, "MB", "tokB", 8)
	refA := pfc2.SessionRef{SessionID: "pfs-orEx", Generation: 1}

	made := exactDo(s, b, &Request{Op: OpCreate, Path: "shared", Mode: 0o644}, 0, 1)
	if made == nil || made.Status != OK || made.Ino == 0 {
		t.Fatalf("peer create: %+v", made)
	}
	fused := exactDo(s, a, &Request{Op: OpCreate, Path: "shared", Mode: 0o644, RegisterOpen: true}, 0, 1)
	if fused == nil || fused.Status != OK || fused.Ino != made.Ino {
		t.Fatalf("fused create over existing: %+v, want OK ino=%d", fused, made.Ino)
	}
	if !managedPinState(t, fs).HasPin(refA, made.Ino) {
		t.Fatal("fused create over existing did not pin the current binding")
	}
	excl := exactDo(s, a, &Request{Op: OpCreate, Path: "shared", Mode: 0o644, Excl: true, RegisterOpen: true}, 1, 1)
	if excl == nil || excl.Status != EEXIST {
		t.Fatalf("fused excl create over existing: %+v, want EEXIST", excl)
	}
	if holders := managedPinState(t, fs).PinHolders(made.Ino); len(holders) != 1 || holders[0] != refA {
		t.Fatalf("pin holders after failed excl create: %v, want exactly [%v]", holders, refA)
	}
}

// TestManagedFusedCreateDegradation covers both serializations of a fused
// create racing a peer unlink:
//
//   - unlink ordered BEFORE the create: the create binds a FRESH inode and
//     the pin rides that inode (identical to the two-RPC flow);
//   - inode destroyed before the pin could be ensured (lost-reply replay
//     after the pin was released and the reap landed): the reply degrades to
//     ENOENT exactly like create-then-MarkOpen against a reaped inode.
func TestManagedFusedCreateDegradation(t *testing.T) {
	log := newProtoEntryLog()
	s, fs := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-orDg", 1, "MA", "tokA", 8)
	b := openJournaledSession(t, s, "pfs-orDh", 1, "MB", "tokB", 8)
	refA := pfc2.SessionRef{SessionID: "pfs-orDg", Generation: 1}

	// Serialization 1: unlink first, fused create after -> fresh inode, pinned.
	old := exactDo(s, b, &Request{Op: OpCreate, Path: "raced", Mode: 0o644}, 0, 1)
	if old == nil || old.Status != OK {
		t.Fatalf("peer create: %+v", old)
	}
	if r := exactDo(s, b, &Request{Op: OpRemove, Path: "raced"}, 0, 2); r == nil || r.Status != OK {
		t.Fatalf("peer remove: %+v", r)
	}
	fresh := exactDo(s, a, &Request{Op: OpCreate, Path: "raced", Mode: 0o644, RegisterOpen: true}, 0, 1)
	if fresh == nil || fresh.Status != OK || fresh.Ino == 0 || fresh.Ino == old.Ino {
		t.Fatalf("fused create after unlink: %+v (old ino %d), want a fresh pinned inode", fresh, old.Ino)
	}
	if !managedPinState(t, fs).HasPin(refA, fresh.Ino) {
		t.Fatal("fresh fused create did not pin")
	}

	// Serialization 2: the stored create outcome names an inode that has
	// since been unpinned, unlinked, and reaped. The lost-reply replay must
	// degrade to ENOENT (create OK + pin ENOENT semantics), never hold a
	// destroyed inode.
	gone := &Request{Op: OpCreate, Path: "gone", Mode: 0o644, RegisterOpen: true}
	first := exactDo(s, a, gone, 1, 1)
	if first == nil || first.Status != OK || first.Ino == 0 {
		t.Fatalf("fused create: %+v", first)
	}
	if r := exactDo(s, a, &Request{Op: OpUnmarkOpenInodes, OpenInos: []uint64{first.Ino}}, 2, 1); r == nil || r.Status != OK {
		t.Fatalf("unmark: %+v", r)
	}
	if r := exactDo(s, b, &Request{Op: OpRemove, Path: "gone"}, 0, 3); r == nil || r.Status != OK {
		t.Fatalf("peer remove: %+v", r)
	}
	waitReaped(t, fs, first.Ino)
	replay := exactDo(s, a, gone, 1, 1)
	if replay == nil || replay.Status != ENOENT {
		t.Fatalf("fused create replay after reap: %+v, want ENOENT degradation", replay)
	}
	if managedPinState(t, fs).HasPin(refA, first.Ino) {
		t.Fatal("degraded replay left a pin on a destroyed inode")
	}
}

// TestManagedUnpinBatchAtomicOneRow: one batched unmark releases N pins in
// ONE journal row under ONE identity — unknown and duplicate inos are
// idempotently skipped, the row count proves the atomicity unit, and the
// identical resend replays without journaling anything new.
func TestManagedUnpinBatchAtomicOneRow(t *testing.T) {
	log := newProtoEntryLog()
	s, fs := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-orN", 1, "MA", "tokA", 8)
	refA := pfc2.SessionRef{SessionID: "pfs-orN", Generation: 1}

	var inos []uint64
	for seq, name := range []string{"n1", "n2", "n3"} {
		r := exactDo(s, a, &Request{Op: OpCreate, Path: name, Mode: 0o644, RegisterOpen: true}, 0, uint64(seq+1))
		if r == nil || r.Status != OK || r.Ino == 0 {
			t.Fatalf("fused create %s: %+v", name, r)
		}
		inos = append(inos, r.Ino)
	}
	// The batch carries a duplicate and a never-existing ino: both are
	// idempotent skips, exactly the legacy batch's per-ino semantics.
	batch := append(append([]uint64{}, inos...), inos[0], 999_999)
	before := log.rowCount()
	un := &Request{Op: OpUnmarkOpenInodes, OpenInos: batch}
	if r := exactDo(s, a, un, 1, 1); r == nil || r.Status != OK {
		t.Fatalf("unmark batch: %+v", r)
	}
	if got := log.rowCount() - before; got != 1 {
		t.Fatalf("batched unmark journaled %d rows, want exactly 1 (atomic batch)", got)
	}
	for _, ino := range inos {
		if managedPinState(t, fs).HasPin(refA, ino) {
			t.Fatalf("pin on %d survived the batch", ino)
		}
	}
	afterApply := log.rowCount()
	if r := exactDo(s, a, un, 1, 1); r == nil || r.Status != OK || !r.Duplicate {
		t.Fatalf("unmark batch replay: %+v, want duplicate OK", r)
	}
	if got := log.rowCount(); got != afterApply {
		t.Fatalf("duplicate unmark replay journaled %d new rows, want 0", got-afterApply)
	}
	// A reordered ino list at the same identity is a DIFFERENT request:
	// the changed fingerprint fences the generation.
	reordered := &Request{Op: OpUnmarkOpenInodes, OpenInos: []uint64{batch[1], batch[0]}}
	if r := exactDo(s, a, reordered, 1, 1); r == nil || r.Status != ESTALE {
		t.Fatalf("reordered unmark replay: %+v, want ESTALE fence", r)
	}
}

// TestManagedOpenRegistrationFailover: a replacement authority over the SAME
// journal replays pins and their releases exactly; the surviving pin still
// parks a peer unlink, and the fused create's identity still replays its
// stored outcome without double-pinning.
func TestManagedOpenRegistrationFailover(t *testing.T) {
	log := newProtoEntryLog()
	s, _ := newManagedServer(t, log)
	a := openJournaledSession(t, s, "pfs-orF", 1, "MA", "tokA", 8)
	refA := pfc2.SessionRef{SessionID: "pfs-orF", Generation: 1}

	// keep rides its own slot so its identity stays the slot's LATEST — a
	// lost-reply replay below must classify as a duplicate, not retired.
	keep := exactDo(s, a, &Request{Op: OpCreate, Path: "keep", Mode: 0o644, RegisterOpen: true}, 0, 1)
	if keep == nil || keep.Status != OK {
		t.Fatalf("fused create keep: %+v", keep)
	}
	drop := exactDo(s, a, &Request{Op: OpCreate, Path: "drop", Mode: 0o644, RegisterOpen: true}, 2, 1)
	if drop == nil || drop.Status != OK {
		t.Fatalf("fused create drop: %+v", drop)
	}
	if r := exactDo(s, a, &Request{Op: OpUnmarkOpenInodes, OpenInos: []uint64{drop.Ino}}, 1, 1); r == nil || r.Status != OK {
		t.Fatalf("unmark drop: %+v", r)
	}

	// Cold failover: rebuild over the same journal.
	s2, fs2 := newManagedServer(t, log)
	control := managedPinState(t, fs2)
	if !control.HasPin(refA, keep.Ino) {
		t.Fatal("held pin did not survive failover replay")
	}
	if control.HasPin(refA, drop.Ino) {
		t.Fatal("released pin resurrected across failover replay")
	}

	a2 := &connSession{}
	if r := s2.dispatchConn(a2, &Request{
		Op: OpSessionResume, SessionID: "pfs-orF", SessionGen: 1, SessionToken: "tokA",
	}); r == nil || r.Status != OK {
		t.Fatalf("session resume after failover: %+v", r)
	}
	// Lost-reply replay of the fused create against the replacement: stored
	// outcome, no new pin row.
	rows := log.rowCount()
	replay := exactDo(s2, a2, &Request{Op: OpCreate, Path: "keep", Mode: 0o644, RegisterOpen: true}, 0, 1)
	if replay == nil || replay.Status != OK || !replay.Duplicate || replay.Ino != keep.Ino {
		t.Fatalf("fused create replay after failover: %+v", replay)
	}
	if got := log.rowCount(); got != rows {
		t.Fatalf("failover replay journaled %d new rows, want 0", got-rows)
	}
	// The replayed pin still protects: a peer unlink parks instead of
	// destroying.
	b2 := openJournaledSession(t, s2, "pfs-orG", 1, "MB", "tokB", 8)
	if r := exactDo(s2, b2, &Request{Op: OpRemove, Path: "keep"}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("peer remove after failover: %+v", r)
	}
	if _, ok := fs2.OrphanInfo(keep.Ino); !ok {
		t.Fatal("pinned inode destroyed after failover, want parked")
	}
	if reaped := fs2.ManagedReapSweep(); reaped != 0 {
		t.Fatalf("sweep reaped %d inodes while the replayed pin is held", reaped)
	}
}

// TestClientOpenRegistrationAgainstManagedAuthority: the feature bit alone
// lights the client machinery up against a managed authority — a fused
// create+open costs ONE wire mutation (no OpMarkOpen), the pin is durable,
// a peer unlink parks, and the batched unmark (one OpUnmarkOpenInodes under
// an exact identity) releases the pin and lets the reap destroy.
func TestClientOpenRegistrationAgainstManagedAuthority(t *testing.T) {
	addr, fs := serveManagedAuthorityFS(t)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("MA")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("establish exact session: %v", err)
	}
	if !cli.ServerManaged() {
		t.Fatal("expected a managed authority (ServerManaged=true)")
	}
	if !cli.SupportsOpenRegistration() {
		t.Fatal("SupportsOpenRegistration must be true against a managed authority")
	}

	peer, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	peer.SetOwner("MB")
	if _, err := peer.EnsureExactSession(); err != nil {
		t.Fatalf("peer session: %v", err)
	}

	createBefore := counterValue("vcs_fsproto_op_create")
	markBefore := counterValue("vcs_fsproto_op_mark_open")
	a, gen, st, err := cli.CreateRegisterOpen("one.txt", 0o644)
	if err != nil || st != OK || a == nil || a.Ino == 0 {
		t.Fatalf("CreateRegisterOpen: attr=%+v gen=%d st=%d err=%v", a, gen, st, err)
	}
	if got := counterValue("vcs_fsproto_op_create") - createBefore; got != 1 {
		t.Fatalf("fused create+open cost %d create ops, want 1", got)
	}
	if got := counterValue("vcs_fsproto_op_mark_open") - markBefore; got != 0 {
		t.Fatalf("fused create+open sent %d OpMarkOpen round-trips, want 0", got)
	}
	if holders := managedPinState(t, fs).PinHolders(a.Ino); len(holders) != 1 {
		t.Fatalf("pin holders after fused create: %v, want exactly one", holders)
	}

	// Peer unlink after the fused create returned: parks, keeps serving.
	if _, st, err := cli.Write("one.txt", 0, []byte("held"), 0o644); err != nil || st != OK {
		t.Fatalf("write: st=%d err=%v", st, err)
	}
	if st, err := peer.Remove("one.txt"); err != nil || st != OK {
		t.Fatalf("peer remove: st=%d err=%v", st, err)
	}
	if data, st, err := cli.ReadOrphan(a.Ino, 0, 8); err != nil || st != OK || string(data) != "held" {
		t.Fatalf("parked inode must keep serving the creator's handle: %q st=%d err=%v", data, st, err)
	}

	// Batched unmark rides one exact identity; the released pin lets the
	// asynchronous reap destroy the orphan.
	unmarkBefore := counterValue("vcs_fsproto_op_unmark_open_inodes")
	if st, err := cli.UnmarkOpenBatch([]uint64{a.Ino}); err != nil || st != OK {
		t.Fatalf("UnmarkOpenBatch: st=%d err=%v", st, err)
	}
	if got := counterValue("vcs_fsproto_op_unmark_open_inodes") - unmarkBefore; got != 1 {
		t.Fatalf("batched unmark cost %d wire ops, want 1", got)
	}
	if holders := managedPinState(t, fs).PinHolders(a.Ino); len(holders) != 0 {
		t.Fatalf("pin holders after unmark: %v, want none", holders)
	}
	waitReaped(t, fs, a.Ino)

	// The two-RPC surface still works against managed through the same
	// client entry points (MarkOpen/UnmarkOpen now ride exact identities).
	b, _, st, err := cli.CreateRegisterOpen("two.txt", 0o644)
	if err != nil || st != OK {
		t.Fatalf("second fused create: st=%d err=%v", st, err)
	}
	if st, err := cli.UnmarkOpen(b.Ino); err != nil || st != OK {
		t.Fatalf("single unmark against managed: st=%d err=%v", st, err)
	}
	if st, _, err := cli.MarkOpenGen(b.Ino); err != nil || st != OK {
		t.Fatalf("single mark against managed: st=%d err=%v", st, err)
	}
	if holders := managedPinState(t, fs).PinHolders(b.Ino); len(holders) != 1 {
		t.Fatalf("pin holders after re-mark: %v, want exactly one", holders)
	}
}
