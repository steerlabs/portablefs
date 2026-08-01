package portablefsd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// Phase 2 of the drain-time credit controller: the pacing wait belongs in the
// FRONTEND, before any lock.
//
// The engine's write path paces internally, which is correct for a caller that
// holds nothing. This handler is not such a caller — it runs under
// a.nsMu.RLock, and Go's RWMutex is writer-preferring, so a paced writer on the
// read side blocks any pending nsMu.Lock (rename, remove, delegation reclaim)
// and every lookup/getattr/read that arrives after it. One slow uplink takes
// the whole namespace down, on paths that have nothing to do with the backlog.
// These tests pin the geometry that makes that impossible.

// writeCreditFixture is a real daemon attach over a real volume, with the
// data-lane credit ledger held at its operating setpoint.
//
// The ledger is occupied by TAKING credit and never giving it back, not by
// flooding the WAL. That is deliberate: it isolates the admission decision from
// hard-cap refusals, keeps the stream healthy so no test depends on framing
// arithmetic, and is exact — the setpoint is fully consumed, so every
// subsequent delegated acquisition queues and receives nothing.
type writeCreditFixture struct {
	a   *attach
	vol *clientcore.Volume
	// held is the credit occupying the lane; releasing it lets queued writers
	// through, which is how a test proves a paced write completes rather than
	// merely failing fast.
	held int
}

const (
	// delegatedPath sits under a directory this mount delegates, so writes to it
	// are WAL-backed and credit-governed.
	delegatedPath = "d/f"
	// writeThroughPath is created by a PEER mount and never mutated here, so
	// nothing delegates it: writes to it consume no stream budget and must not
	// be paced no matter how saturated the journal is.
	writeThroughPath = "wt/g"

	delegatedHandle    = uint64(11)
	writeThroughHandle = uint64(12)
)

func newWriteCreditFixture(t *testing.T) *writeCreditFixture {
	t.Helper()
	authority, _ := serveAuthorityServer(t)
	ctx := context.Background()

	// A peer mount creates the write-through target and leaves. Creating it
	// through the mount under test would delegate its parent scope, which is
	// exactly the lane this fixture needs to NOT have.
	peer, err := clientcore.Dial(ctx, clientcore.Options{
		Addr: authority, Pool: 2, Owner: "write-credit-peer",
		WALDir: privateTestDir(t) + "/peer-wal", VolumeID: "write-credit-volume",
	})
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	if _, st := peer.Mkdir(ctx, "wt", 0o755); st != fsproto.OK {
		t.Fatalf("peer mkdir wt: %d", st)
	}
	wtAttr, st := peer.Create(ctx, writeThroughPath, 0o644)
	if st != fsproto.OK {
		t.Fatalf("peer create %s: %d", writeThroughPath, st)
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("close peer: %v", err)
	}

	vol, err := clientcore.Dial(ctx, clientcore.Options{
		Addr: authority, Pool: 4, Owner: "write-credit-holder",
		WALDir: privateTestDir(t) + "/wal", VolumeID: "write-credit-volume",
	})
	if err != nil {
		t.Fatalf("dial volume: %v", err)
	}
	t.Cleanup(func() { _ = vol.Close() })

	if _, st := vol.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}
	if _, st := vol.Create(ctx, delegatedPath, 0o644); st != fsproto.OK {
		t.Fatalf("create %s: %d", delegatedPath, st)
	}
	dAttr, st := vol.Getattr(ctx, delegatedPath, nil)
	if st != fsproto.OK {
		t.Fatalf("getattr %s: %d", delegatedPath, st)
	}
	wtAttr, st = vol.Getattr(ctx, writeThroughPath, nil)
	if st != fsproto.OK {
		t.Fatalf("getattr %s: %d", writeThroughPath, st)
	}
	if !vol.Writeback().Covers(delegatedPath) {
		t.Fatalf("%s is not delegated; the credit lane is not under test", delegatedPath)
	}
	if vol.Writeback().Covers(writeThroughPath) {
		t.Fatalf("%s is delegated; the write-through lane is not under test", writeThroughPath)
	}

	a := &attach{
		vol:                    vol,
		items:                  map[uint64]*itemRecord{},
		paths:                  map[string]*itemRecord{},
		itemAliases:            map[uint64]map[string]struct{}{},
		authorityItems:         map[uint64]frontendItemIdentity{},
		awaitingAuthorityItems: map[uint64]struct{}{},
		handles:                map[uint64]*handleRecord{},
		retiredCloseErrnos:     map[uint64]int32{},
		subscribers:            map[*eventSubscriber]struct{}{},
		localVersions:          map[string]uint64{},
	}
	bind := func(path string, id uint64, attr fsproto.Attr, handle uint64) {
		state := clientcore.NewNodeState(attr.Ino, attr.Ino != 0)
		if st := vol.Open(ctx, path, state, true); st != fsproto.OK {
			t.Fatalf("open %s: %d", path, st)
		}
		rec := a.bindTestRecord(&itemRecord{
			item:  pfslocal.Item{ItemID: id, ItemGeneration: 1},
			path:  path,
			state: state,
			attr:  attr,
		})
		a.handles[handle] = &handleRecord{
			id: handle, itemID: rec.item.ItemID, path: path, openPath: path,
			state: state, write: true,
		}
	}
	bind(delegatedPath, 101, dAttr, delegatedHandle)
	bind(writeThroughPath, 102, wtAttr, writeThroughHandle)

	f := &writeCreditFixture{a: a, vol: vol}
	f.holdWholeDataLane(t)
	return f
}

// holdWholeDataLane takes the entire operating setpoint as credit and keeps it,
// so the lane is exactly full: every further delegated acquisition queues and
// the pump has zero headroom to serve it with.
func (f *writeCreditFixture) holdWholeDataLane(t *testing.T) {
	t.Helper()
	st := f.vol.WritebackStatus()
	want := int(st.CreditSetpoint - st.CreditDebt)
	if want <= 0 {
		t.Fatalf("no credit to hold: setpoint=%d debt=%d", st.CreditSetpoint, st.CreditDebt)
	}
	granted, err := f.vol.Writeback().AcquireDataCredit(context.Background(), want)
	if err != nil || granted != want {
		t.Fatalf("hold the data lane: granted=%d of %d err=%v", granted, want, err)
	}
	f.held = granted
	after := f.vol.WritebackStatus()
	if after.CreditDebt < after.CreditSetpoint {
		t.Fatalf("lane not saturated: debt=%d setpoint=%d", after.CreditDebt, after.CreditSetpoint)
	}
}

func (f *writeCreditFixture) releaseLane() {
	if f.held > 0 {
		f.vol.Writeback().ReleaseDataCredit(f.held)
		f.held = 0
	}
}

func (f *writeCreditFixture) waitForCreditWaiter(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f.vol.WritebackStatus().CreditWaiters > 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the frontend write never reached the credit queue; the fixture did not saturate the lane")
}

// TestPacedWriteDoesNotHoldTheNamespaceLock is the lock-geometry liveness test
// and the whole reason Phase 2 exists.
//
// A frontend write is parked on the credit gate against a lane with zero
// headroom. While it waits, the namespace must be completely free: an EXCLUSIVE
// nsMu.Lock — the shape a rename, a remove or a delegation reclaim takes, and
// the one that would queue every subsequent reader behind it — has to be
// grantable immediately, and unrelated getattr traffic has to keep flowing.
//
// Before this change the wait happened inside Engine.WriteAt, under
// a.nsMu.RLock: TryLock below would fail and every reader behind the pending
// writer would stall for as long as the uplink was slow.
func TestPacedWriteDoesNotHoldTheNamespaceLock(t *testing.T) {
	f := newWriteCreditFixture(t)
	ctx := context.Background()

	done := make(chan int32, 1)
	go func() {
		_, eno := f.a.write(ctx, &pfslocal.WriteRequest{
			Handle: delegatedHandle,
			Offset: 0,
			Data:   make([]byte, 256<<10),
		})
		done <- eno
	}()
	f.waitForCreditWaiter(t)

	// The exclusive acquisition. TryLock is the exact assertion: it fails if
	// ANY reader is inside, so a paced write that still held nsMu.RLock could
	// not hide behind a retry.
	if !f.a.nsMu.TryLock() {
		t.Fatal("a paced frontend write is holding nsMu: the credit wait is still inside the namespace lock, so one slow uplink stalls every lookup, getattr and rename on the mount")
	}
	f.a.nsMu.Unlock()

	// And the ordinary traffic that the writer-preferring queue would have
	// starved keeps answering.
	deadline := time.Now().Add(2 * time.Second)
	for i := 0; i < 50; i++ {
		start := time.Now()
		if _, eno := f.a.getattr(ctx, &pfslocal.GetAttrRequest{
			Item: f.a.paths[writeThroughPath].item, Handle: writeThroughHandle,
		}); eno != 0 {
			t.Fatalf("getattr while a write is paced: errno=%d", eno)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("getattr took %v behind a paced write", elapsed)
		}
		if time.Now().After(deadline) {
			t.Fatal("getattr loop outran its budget behind a paced write")
		}
	}

	// Releasing the lane must let the parked write through: the pacing is a
	// wait, not a refusal.
	f.releaseLane()
	select {
	case eno := <-done:
		if eno != 0 {
			t.Fatalf("paced write failed after credit became available: errno=%d", eno)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the paced write never completed after the lane was released")
	}
}

// TestWriteThroughIsNotThrottledByASaturatedDataLane is the lane rule. Credit
// governs the DELEGATED lane only, because that is the only lane whose bytes
// land in the bounded WAL. A write with no covering delegation consumes no
// stream budget and cannot help drain it, so pacing it would punish a workload
// for a backlog it did not create and cannot fix.
//
// The lane is decided at the frontend, before any lock, from the engine's own
// covering-delegation state — so this write never touches the credit queue at
// all while the delegated lane next door is completely full.
func TestWriteThroughIsNotThrottledByASaturatedDataLane(t *testing.T) {
	f := newWriteCreditFixture(t)
	ctx := context.Background()
	payload := []byte("write-through under a saturated journal")

	start := time.Now()
	reply, eno := f.a.write(ctx, &pfslocal.WriteRequest{
		Handle: writeThroughHandle,
		Offset: 0,
		Data:   payload,
	})
	elapsed := time.Since(start)
	if eno != 0 {
		t.Fatalf("write-through under saturation: errno=%d", eno)
	}
	if int(reply.Written) != len(payload) {
		t.Fatalf("write-through wrote %d of %d bytes", reply.Written, len(payload))
	}
	if elapsed > 3*time.Second {
		t.Fatalf("write-through took %v with the delegated lane saturated; it was paced against a backlog it does not contribute to", elapsed)
	}
	if w := f.vol.WritebackStatus().CreditWaiters; w != 0 {
		t.Fatalf("write-through queued on the credit gate (%d waiters)", w)
	}
}

// TestShortGrantRepliesAShortWrittenCount is the partial-grant contract end to
// end. With less headroom than the request needs, the frontend takes what the
// gate gives, writes exactly that prefix, and replies a SHORT WRITE. The kernel
// reissues the remainder as a fresh operation that is paced from scratch — the
// POSIX-correct way to apply back pressure, and the reason a partial grant is a
// healthy outcome rather than an error.
//
// The reply plumbing this depends on is already in place on both sides:
// pfslocal's WriteReply carries a written count (clientcore returns res.Count),
// and the FSKit adapter loops on it (VolumeCore.write breaks out on a short
// chunk and returns the running total, which OperationsAdapter hands back as
// bytesWritten). No Swift change was needed.
func TestShortGrantRepliesAShortWrittenCount(t *testing.T) {
	f := newWriteCreditFixture(t)
	ctx := context.Background()

	// Leave exactly one grant quantum of headroom, then ask for four.
	const quantum = 1 << 20
	f.vol.Writeback().ReleaseDataCredit(quantum)
	f.held -= quantum

	reply, eno := f.a.write(ctx, &pfslocal.WriteRequest{
		Handle: delegatedHandle,
		Offset: 0,
		Data:   make([]byte, 4*quantum),
	})
	if eno != 0 {
		t.Fatalf("short-grant write: errno=%d", eno)
	}
	if reply.Written == 0 {
		t.Fatal("a zero-length successful write is not a signal any kernel can act on; the frontend must report an error instead")
	}
	if int(reply.Written) >= 4*quantum {
		t.Fatalf("write reported %d bytes with only %d of headroom: the grant was not honoured", reply.Written, quantum)
	}
	if int(reply.Written) > quantum {
		t.Fatalf("write reported %d bytes, past the %d the gate could grant", reply.Written, quantum)
	}
	f.releaseLane()
}

// TestHealthyUplinkIsNeverReportedAsStalled is the wait policy's core claim: a
// frontend never SYNTHESISES a stall the engine has not declared.
//
// The distinction is not academic. writeback.AcquireDataCredit returns
// (0, nil) precisely when the no-progress watchdog has NOT declared a stall —
// "no credit yet, but the uplink IS making durable progress". A frontend that
// converts elapsed time into ErrUplinkStalled therefore reports a dead far end
// for a link the engine considers perfectly healthy, and the application sees
// EIO on a mount that is merely slow. Under the measured saturation profile
// that is not a corner case: healthy paced writes routinely block for tens of
// seconds while the kernel's aggregated dirty pages drain.
//
// Here the lane is held full by a credit holder while the authority is
// untouched, so the engine's verdict is unambiguously "not stalled". The write
// must not fail. It reaches a definite outcome by taking the OTHER lane — the
// authority lane consumes no stream budget, so it is admitted immediately — and
// the application gets its bytes written instead of an error it cannot act on.
func TestHealthyUplinkIsNeverReportedAsStalled(t *testing.T) {
	if testing.Short() {
		t.Skip("spends the whole credit admission budget by design")
	}
	f := newWriteCreditFixture(t)
	ctx := context.Background()
	payload := make([]byte, 256<<10)

	start := time.Now()
	reply, eno := f.a.write(ctx, &pfslocal.WriteRequest{
		Handle: delegatedHandle,
		Offset: 0,
		Data:   payload,
	})
	elapsed := time.Since(start)
	if eno != 0 {
		t.Fatalf("a write against a full lane on a HEALTHY uplink replied errno=%d; "+
			"the engine's watchdog never declared a stall, so the frontend invented one", eno)
	}
	if int(reply.Written) != len(payload) {
		t.Fatalf("write reported %d of %d bytes", reply.Written, len(payload))
	}
	if elapsed > creditAdmissionCeiling {
		t.Fatalf("the frontend held the operation open for %v, past any kernel's patience", elapsed)
	}
	f.releaseLane()
}

// creditAdmissionCeiling is the outer bound one daemon write op may take. The
// kernel can aggregate several ops into one write(2), so this has to stay well
// under the FSKit reply ceiling with room for a few of them.
const creditAdmissionCeiling = 50 * time.Second

// TestStalledUplinkWriteRepliesEIONotENOSPC is the errno contract, and it now
// tests it against a REAL stall rather than against elapsed time.
//
// A far end that stopped answering is EIO. Reporting ENOSPC instead teaches
// applications to delete files to fix a network partition, which is why the two
// are kept structurally distinct all the way from writeback.ErrUplinkStalled to
// the darwin errno. The verdict comes from the engine's no-progress watchdog
// and from nowhere else.
func TestStalledUplinkWriteRepliesEIONotENOSPC(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the engine's no-progress window by design")
	}
	f := newWriteCreditFixture(t)
	ctx := context.Background()

	// Admit real unshipped work, then take the whole lane, and only THEN kill
	// the uplink.
	//
	// The order is the test's own determinism, not a detail. Fencing the session
	// makes the flusher's next batch fail and SEALS the credit gate with the
	// fence error, so a hold taken after the fence is racing the flusher's
	// cadence for a gate that may already be closed — which is exactly how this
	// test used to fail about half the time (`hold the data lane: granted=0 ...
	// session fenced`). Saturating first cannot lose that race: the gate is
	// healthy, the setpoint is whole, and the hold is deterministic.
	f.releaseLane()
	if _, eno := f.a.write(ctx, &pfslocal.WriteRequest{
		Handle: delegatedHandle,
		Data:   make([]byte, 64<<10),
	}); eno != 0 {
		t.Fatalf("seed write: errno=%d", eno)
	}
	if pending, _ := f.vol.WriteBackPending(); pending == 0 {
		t.Skip("no unshipped backlog for the watchdog to judge")
	}
	f.holdWholeDataLane(t)
	f.vol.Client().ExpireSession()

	deadline := time.Now().Add(90 * time.Second)
	for {
		if !f.vol.Writeback().UplinkStalled() {
			if time.Now().After(deadline) {
				t.Skip("the watchdog did not declare a stall inside the test's patience")
			}
			time.Sleep(250 * time.Millisecond)
			continue
		}
		break
	}
	_, eno := f.a.write(ctx, &pfslocal.WriteRequest{
		Handle: delegatedHandle,
		Offset: 128 << 10,
		Data:   make([]byte, 256<<10),
	})
	if eno == darwinENOSPC {
		t.Fatal("a stalled uplink must never be reported as a full local store")
	}
	if eno != darwinEIO {
		t.Fatalf("a write against a STALLED uplink replied errno=%d, want EIO (%d)", eno, darwinEIO)
	}
	f.releaseLane()
}

// TestCreditErrnoKeepsENOSPCAndEIOStructurallyDistinct pins the mapping itself,
// independently of any timing. ErrNoSpace is the ONLY thing that becomes
// ENOSPC.
func TestCreditErrnoKeepsENOSPCAndEIOStructurallyDistinct(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int32
	}{
		{"oversized operation", writeback.ErrNoSpace, darwinENOSPC},
		{"stalled uplink", writeback.ErrUplinkStalled, darwinEIO},
		{"wrapped stalled uplink", errors.New("x: " + writeback.ErrUplinkStalled.Error()), darwinEIO},
		{"cancelled request", context.Canceled, darwinEINTR},
		{"expired request", context.DeadlineExceeded, darwinEINTR},
		{"engine fenced", writeback.ErrFenced, darwinEIO},
	}
	for _, tc := range cases {
		if got := creditErrno(tc.err); got != tc.want {
			t.Errorf("creditErrno(%s) = %d, want %d", tc.name, got, tc.want)
		}
	}
	if darwinEIO == darwinENOSPC {
		t.Fatal("EIO and ENOSPC collapsed onto one value")
	}
}
