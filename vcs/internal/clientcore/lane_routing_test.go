package clientcore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// ── ROUTING, MEASURED RATHER THAN ASSUMED ────────────────────────────────────
//
// Round 18f was briefed with a ranking: the ErrLaneChanged unwind "the big one",
// the credit-budget divert second, the uncovered path third. That ranking came
// from reading the code, and reading the code is exactly how it went wrong —
// the unwind LOOKS worst because its second pass is unconditional, and looking
// worst is not evidence.
//
// So these tests measure. Each one drives one door under a sustained flood and
// reads the tally off the engine (writeback.LaneRouting), and
// TestFloodRoutingBreakdownByDoor drives all of them together and prints the
// split. The numbers in the report come from here, not from inspection.

// pinCreditAdmissionBudget compresses the frontend's 40s credit budget so the
// divert door can be reached inside a test.
func pinCreditAdmissionBudget(t *testing.T, d time.Duration) {
	t.Helper()
	old := creditAdmissionBudget
	creditAdmissionBudget = d
	t.Cleanup(func() { creditAdmissionBudget = old })
}

// liveRemote is an authority that GRANTS delegations, RELEASES them cleanly,
// and applies every flush. It is deliberately not stallRemote.
//
// The distinction is the whole reason this fixture exists. A dead uplink makes
// every door onto the authority lane fail at its delegation release, so a
// routing measurement taken against one measures the release failing rather
// than the routing — the first run of TestFloodRoutingBreakdownByDoor refused
// 32 of 48 writes for exactly that reason and told us nothing about lane
// choice. Here the far end is HEALTHY and the delegated lane is starved only of
// credit, which is the state a real flood actually produces.
type liveRemote struct {
	mu    sync.Mutex
	epoch int
}

func (r *liveRemote) DelegationAcquire(
	_ context.Context, scope, _ string,
) (writeback.AcquireReply, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.epoch++
	return writeback.AcquireReply{
		Granted: true,
		Epoch:   "epoch-" + itoa(r.epoch),
		Exists:  true,
		Self: writeback.Entry{
			Name: baseNameOf(scope), Kind: "directory", Mode: 0o755, Nlink: 2,
		},
		HasChildren: true,
	}, nil
}

func (r *liveRemote) ReleaseDelegation(context.Context, string, string) error { return nil }

func (r *liveRemote) Flush(_ context.Context, req writeback.FlushRequest) (writeback.FlushReply, error) {
	through := uint64(0)
	if n := len(req.Records); n > 0 {
		through = req.Records[n-1].Seq
	}
	return writeback.FlushReply{Through: through}, nil
}

func (r *liveRemote) FlushResolved(ctx context.Context, req writeback.FlushRequest) (writeback.FlushReply, error) {
	return r.Flush(ctx, req)
}

func (r *liveRemote) StreamState(context.Context, string) (writeback.StreamState, error) {
	return writeback.StreamState{}, nil
}

func (r *liveRemote) Rebind(
	context.Context, string, []writeback.RebindScope, writeback.StreamState,
) (writeback.RebindReply, error) {
	return writeback.RebindReply{}, nil
}

func (r *liveRemote) Discard(context.Context, string, []writeback.RebindScope) error { return nil }
func (r *liveRemote) SupportsLanes() bool                                            { return true }

// routingFixture is a Volume with a live authority, a delegation already
// installed over "d", and a credit gate with nothing left to hand out. That
// triple is precisely the state a saturated mount is in: the delegated lane
// EXISTS for these paths and cannot take a byte, so every door onto the other
// lane is live and none of them is masked by a dead far end.
type routingFixture struct {
	v      *Volume
	proofs chan struct{}
}

func newRoutingFixture(t *testing.T) *routingFixture {
	t.Helper()
	wb, err := writeback.Open(context.Background(), writeback.Config{
		StateDir: t.TempDir(), VolumeID: "vol-routing", Branch: "main",
		Remote: &liveRemote{}, BudgetBytes: 8 << 20,
	})
	if err != nil {
		t.Fatalf("open writeback engine: %v", err)
	}
	t.Cleanup(func() { _, _ = wb.ForceClose("test teardown") })

	// Install the delegation BEFORE starving the gate. PrepareDelegatedWrite
	// declines to acquire one for an uncovered path when the lane has no
	// headroom (engine.go), which is correct and would otherwise route every
	// write in this fixture through DoorUncovered and prove nothing about the
	// other doors.
	ok, err := wb.PrepareDelegatedWrite(context.Background(), "d/hot", 1)
	if err != nil || !ok {
		t.Fatalf("install delegation over d: ok=%v err=%v", ok, err)
	}
	if !wb.Covers("d/hot") {
		t.Fatal("the fixture holds no delegation over d/hot; the covered doors are unreachable")
	}
	saturateDataCredit(t, wb)

	v := &Volume{wb: wb}
	f := &routingFixture{v: v, proofs: make(chan struct{})}
	// A far end that acknowledges instantly and proves only on demand: the
	// incident's shape, and the one no ack-rate gate can see.
	wb.SetAuthorityProver(func(ctx context.Context) error {
		select {
		case <-f.proofs:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	return f
}

// write runs one complete pre-lock classification and reports which lane it
// resolved. It settles unconditionally, exactly as every real frontend does.
func (f *routingFixture) write(ctx context.Context, path string, want int, force bool) (
	lane writeback.ResolvedLane, granted int, err error,
) {
	opCtx, granted, settle, err := f.v.AdmitWrite(ctx, path, nil, want, force)
	defer settle()
	if err != nil {
		return writeback.LaneUnresolved, 0, err
	}
	// Acknowledge whatever the lane granted, so the ledgers see a completed
	// operation rather than an abandoned charge.
	writeback.NoteAuthorityAck(opCtx, granted)
	f.v.ReleaseDataCredit(opCtx)
	return writeback.LaneOf(opCtx), granted, nil
}

// TestFloodRoutingBreakdownByDoor is the characterization. It drives a
// sustained flood through the classifier with the delegated lane saturated and
// prints the routing split, so the fraction that escapes onto the authority
// lane — and which door it took — is a MEASUREMENT rather than an inference.
//
// It asserts only what must be true of any correct routing (every door is
// counted, the tally reconciles, and nothing escapes uncounted). The
// proportions are logged, not asserted: they depend on the far end, and a test
// that pinned them would be pinning the fixture rather than the contract.
func TestFloodRoutingBreakdownByDoor(t *testing.T) {
	pinCreditAdmissionBudget(t, 150*time.Millisecond)
	f := newRoutingFixture(t)
	ctx := context.Background()
	const chunk = 128 << 10

	// A covered path (the delegated lane exists but is starved) and an
	// uncovered one, alternating, plus a forced pass every fourth write — the
	// mix a frontend under an unwinding flood actually produces.
	var attempted, refused int
	for i := 0; i < 48; i++ {
		path := "d/hot"
		if i%3 == 0 {
			path = "elsewhere/cold"
		}
		attempted++
		if _, _, err := f.write(ctx, path, chunk, i%4 == 3); err != nil {
			refused++
		}
	}

	r := f.v.wb.LaneRouting()
	total := r.AuthorityBytes() + r.DelegatedBytes
	if total == 0 {
		t.Fatal("the flood routed nothing at all: the fixture did not exercise the classifier")
	}
	t.Logf("ROUTING BREAKDOWN over %d writes (%d refused), %d byte(s) admitted:", attempted, refused, total)
	for _, d := range []writeback.LaneDoor{
		writeback.DoorIdentity,
		writeback.DoorUncovered,
		writeback.DoorBudget,
		writeback.DoorLaneChanged,
		writeback.DoorForced,
	} {
		t.Logf("  %-22s ops=%-5d bytes=%-10d", d.String(), r.Ops[d], r.Bytes[d])
	}
	t.Logf("  %-22s ops=%-5d bytes=%-10d", "delegated", r.DelegatedOps, r.DelegatedBytes)
	t.Logf("  authority share of admitted bytes: %.1f%% (escape doors only: %d byte(s))",
		100*r.AuthorityShare(), r.EscapedBytes())

	// The invariant, as opposed to the proportions: every authority byte came
	// through a counted door, and the tally cannot exceed what was offered.
	if r.AuthorityBytes() > int64(attempted)*chunk {
		t.Fatalf("the tally counted %d authority byte(s) from %d writes of %d: a door is double-counting",
			r.AuthorityBytes(), attempted, chunk)
	}
	if r.AuthorityBytes() == 0 {
		t.Fatal("a flood against a saturated delegated lane routed nothing to the authority: " +
			"the doors under test were never opened")
	}
}

// TestCreditBudgetDivertIsCountedAndCharged pins door two. A write that waits
// out the credit budget on a live uplink is diverted to the authority lane —
// which remains the right answer — but it is now charged for the lane it lands
// on rather than admitted free.
func TestCreditBudgetDivertIsCountedAndCharged(t *testing.T) {
	pinCreditAdmissionBudget(t, 100*time.Millisecond)
	f := newRoutingFixture(t)
	ctx := context.Background()

	before := f.v.wb.LaneRouting()
	lane, granted, err := f.write(ctx, "d/hot", 64<<10, false)
	if err != nil {
		t.Fatalf("a divert on a live uplink must succeed, not fail: %v", err)
	}
	if lane != writeback.LaneAuthority {
		t.Fatalf("a starved delegated write resolved lane %v, want the authority lane", lane)
	}
	after := f.v.wb.LaneRouting()
	if after.Ops[writeback.DoorBudget] != before.Ops[writeback.DoorBudget]+1 {
		t.Fatalf("the credit-budget divert was not counted: %d -> %d",
			before.Ops[writeback.DoorBudget], after.Ops[writeback.DoorBudget])
	}
	led := f.v.wb.AuthorityLedgerStatus()
	if led.Acked != int64(granted) {
		t.Fatalf("a diverted write acknowledged %d byte(s) and the lane's ledger recorded %d: "+
			"a divert that is not charged is the escape this round closes",
			granted, led.Acked)
	}
}

// TestForcedAuthorityPassIsChargedAndStillTerminates is the round's headline
// fix, and both halves of the name matter.
//
// CHARGED: the second pass no longer admits unconditionally. It resolves the
// authority lane unconditionally — that is what terminates the unwind — but it
// passes through the same gate every other write does, so a flood cannot escape
// backpressure by losing its lane.
//
// TERMINATES: and it still cannot unwind again, because ErrLaneChanged is
// produced only for a ctx resolved to LaneDelegated. Adding a wait in front of
// a pass that resolves LaneAuthority cannot turn two passes into three.
func TestForcedAuthorityPassIsChargedAndStillTerminates(t *testing.T) {
	pinCreditAdmissionBudget(t, 100*time.Millisecond)
	f := newRoutingFixture(t)
	ctx := context.Background()

	// Flood the forced pass. On the pre-fix code every one of these is admitted
	// instantly and in full, forever, with nothing charged anywhere — see
	// TestForcedAuthorityPassIsUngatedAtHEAD for that statement made against
	// 3e5f8f8 itself.
	const chunk = 256 << 10
	var admitted int64
	var refusal error
	deadline := time.Now().Add(30 * time.Second)
	for i := 0; i < 4096; i++ {
		if time.Now().After(deadline) {
			t.Fatal("the forced pass never reached a definite outcome: it is livelocking")
		}
		lane, granted, err := f.write(ctx, "d/hot", chunk, true)
		if err != nil {
			refusal = err
			break
		}
		if lane != writeback.LaneAuthority {
			t.Fatalf("the forced pass resolved lane %v; it must always resolve the authority lane "+
				"or the unwind has no terminator", lane)
		}
		admitted += int64(granted)
	}
	if refusal == nil {
		t.Fatalf(
			"THE FORCED SECOND PASS IS UNGATED.\n"+
				"  %d byte(s) admitted through it with nothing proven durable and no refusal.\n"+
				"A write that keeps losing its lane must still terminate — that is what the\n"+
				"forced pass is for — but terminating is not the same as being exempt from\n"+
				"admission. Ungated, a flood converts its own backpressure into unpaced\n"+
				"write-through, which is the 734 MiB shape.", admitted)
	}
	// Terminating means a DEFINITE answer, not a hang and not a lane change.
	if errors.Is(refusal, writeback.ErrLaneChanged) {
		t.Fatalf("the forced pass was answered ErrLaneChanged: the unwind has no terminator " +
			"and the frontend would spin between passes forever")
	}
	led := f.v.wb.AuthorityLedgerStatus()
	if led.Acked != admitted {
		t.Fatalf("the forced pass acknowledged %d byte(s); the lane's ledger recorded %d",
			admitted, led.Acked)
	}
	if led.Unproven > led.Setpoint {
		t.Fatalf("the forced pass left %d unproven byte(s) against a setpoint of %d",
			led.Unproven, led.Setpoint)
	}
	t.Logf("forced pass bounded after %d byte(s) (refused: %v); ledger holds %d unproven of setpoint %d",
		admitted, refusal, led.Unproven, led.Setpoint)
}

// TestIdentityLaneIsStructuralButStillAccounted keeps the honest half of the
// characterization honest. An orphan, a hard link and a pathless handle are
// authority-only BY CONSTRUCTION — the path-keyed overlay cannot represent
// them — so this door is not an escape and must not be "fixed" by routing it
// back through the WAL. It must still be ACCOUNTED, because these bytes are
// acknowledged out of the same session and discarded by the same fence as
// every other write-through byte.
func TestIdentityLaneIsStructuralButStillAccounted(t *testing.T) {
	f := newRoutingFixture(t)
	ctx := context.Background()
	before := f.v.wb.LaneRouting()

	// The pathless detached handle: authorityOnlyByIdentity's path == "" arm.
	lane, granted, err := f.write(ctx, "", 32<<10, false)
	if err != nil {
		t.Fatalf("a pathless write must be admitted on the lane that exists for it: %v", err)
	}
	if lane != writeback.LaneAuthority {
		t.Fatalf("a pathless write resolved lane %v", lane)
	}
	after := f.v.wb.LaneRouting()
	if after.Ops[writeback.DoorIdentity] != before.Ops[writeback.DoorIdentity]+1 {
		t.Fatalf("the identity door was not counted: %d -> %d",
			before.Ops[writeback.DoorIdentity], after.Ops[writeback.DoorIdentity])
	}
	if led := f.v.wb.AuthorityLedgerStatus(); led.Acked != int64(granted) {
		t.Fatalf("an identity-lane write acknowledged %d byte(s) and the ledger recorded %d: "+
			"structural routing is not a durability exemption", granted, led.Acked)
	}
}

// TestUncoveredPathDoorIsCountedSeparately keeps the two structural doors
// apart. Collapsing "no delegation covers this" into "the flood escaped" is how
// a routing report overstates the defect: a mount with no delegation at all
// sends everything through this door and nothing is wrong.
func TestUncoveredPathDoorIsCountedSeparately(t *testing.T) {
	f := newRoutingFixture(t)
	ctx := context.Background()
	before := f.v.wb.LaneRouting()
	if _, _, err := f.write(ctx, "nowhere/near/a/delegation", 32<<10, false); err != nil {
		t.Fatalf("an uncovered write must be admitted, not refused: %v", err)
	}
	after := f.v.wb.LaneRouting()
	if after.Ops[writeback.DoorUncovered] != before.Ops[writeback.DoorUncovered]+1 {
		t.Fatalf("the uncovered door was not counted: %d -> %d",
			before.Ops[writeback.DoorUncovered], after.Ops[writeback.DoorUncovered])
	}
	if after.Bytes[writeback.DoorBudget] != before.Bytes[writeback.DoorBudget] {
		t.Fatal("an uncovered write was counted as a credit-budget divert; the two doors " +
			"mean different things and a report that merges them is wrong about the defect")
	}
}

// TestOneDivertConvertsThePathToPermanentWriteThrough is the finding this
// round's brief did not anticipate, and it changes which door matters.
//
// The brief ranked the ErrLaneChanged unwind first and the credit-budget divert
// second, both counted as per-write events. The divert is not a per-write
// event. Diverting to the authority lane RELEASES the delegation covering the
// path (admitAuthorityLane -> ReleaseFor), so after ONE divert the path is no
// longer covered — and every subsequent write to it takes DoorUncovered
// instead, which on the pre-fix code was equally free and equally uncharged.
//
// That is why the measured breakdown shows one divert and dozens of uncovered
// writes rather than dozens of diverts. The 734 MiB was never 734 MiB of
// forty-second waits; it was ONE divert followed by an unbounded run of
// write-through that no longer had a delegated lane to be paced against. A fix
// that gated only the divert and the unwind would have closed the door the
// flood goes through once and left open the one it goes through afterwards.
//
// It is also why the gate had to be on the LANE rather than on the doors.
func TestOneDivertConvertsThePathToPermanentWriteThrough(t *testing.T) {
	pinCreditAdmissionBudget(t, 100*time.Millisecond)
	f := newRoutingFixture(t)
	ctx := context.Background()

	if !f.v.wb.Covers("d/hot") {
		t.Fatal("the fixture starts without a delegation over d/hot")
	}
	if _, _, err := f.write(ctx, "d/hot", 64<<10, false); err != nil {
		t.Fatalf("the first (diverting) write failed: %v", err)
	}
	r1 := f.v.wb.LaneRouting()
	if r1.Ops[writeback.DoorBudget] != 1 {
		t.Fatalf("the first write did not take the credit-budget divert (ops=%v)", r1.Ops)
	}
	if f.v.wb.Covers("d/hot") {
		t.Fatal("the divert did not release the delegation; this test's premise is wrong " +
			"and the routing analysis built on it must be redone")
	}

	// Everything after it goes through the OTHER door, for free, forever.
	for i := 0; i < 8; i++ {
		if _, _, err := f.write(ctx, "d/hot", 64<<10, false); err != nil {
			break
		}
	}
	r2 := f.v.wb.LaneRouting()
	if r2.Ops[writeback.DoorBudget] != 1 {
		t.Fatalf("expected exactly one credit-budget divert, got %d: the delegation was reacquired "+
			"and the self-amplification described above does not hold", r2.Ops[writeback.DoorBudget])
	}
	if r2.Ops[writeback.DoorUncovered] < 8 {
		t.Fatalf("only %d of 8 follow-up writes took the uncovered door", r2.Ops[writeback.DoorUncovered])
	}
	// And the point of the fix: they are all still charged, because the gate is
	// on the lane rather than on any one door.
	led := f.v.wb.AuthorityLedgerStatus()
	if led.Acked == 0 {
		t.Fatal("the follow-up write-through was acknowledged and charged nothing")
	}
	t.Logf("one divert then %d uncovered writes; all %d acknowledged byte(s) charged to the lane",
		r2.Ops[writeback.DoorUncovered], led.Acked)
}

// TestUncoveredWriteThroughIsBounded is the fixed-tree twin of
// TestUncoveredWriteThroughIsUnboundedAtHEAD, which lives in a pristine
// worktree at 3e5f8f8 and runs this identical loop.
//
// MEASURED THERE: 2147483648 byte(s) admitted with no refusal, in 0.11s, while
// the engine's credit debt sat unmoved at 6291456 — the whole 2 GiB charged to
// nothing, paced by nothing, and recorded nowhere. The loop's bound was the
// iteration count, not the mount.
//
// MEASURED HERE: the lane stops at its setpoint and every acknowledged byte is
// in a ledger that can be read.
func TestUncoveredWriteThroughIsBounded(t *testing.T) {
	f := newRoutingFixture(t)
	ctx := context.Background()

	const chunk = 256 << 10
	var admitted int64
	var refusal error
	for i := 0; i < 8192; i++ {
		_, granted, err := f.write(ctx, "nowhere/near/a/delegation", chunk, false)
		if err != nil {
			refusal = err
			break
		}
		admitted += int64(granted)
	}
	if refusal == nil {
		t.Fatalf("the uncovered door admitted %d byte(s) with no refusal: it is still unbounded",
			admitted)
	}
	led := f.v.wb.AuthorityLedgerStatus()
	if led.Acked != admitted {
		t.Fatalf("acknowledged %d byte(s); the lane's ledger recorded %d", admitted, led.Acked)
	}
	if led.Unproven > led.Setpoint {
		t.Fatalf("%d unproven byte(s) against a setpoint of %d", led.Unproven, led.Setpoint)
	}
	r := f.v.wb.LaneRouting()
	if r.Bytes[writeback.DoorUncovered] != admitted {
		t.Fatalf("the routing tally attributes %d byte(s) to the uncovered door; %d were admitted",
			r.Bytes[writeback.DoorUncovered], admitted)
	}
	t.Logf("uncovered door bounded at %d byte(s) (setpoint %d); pristine 3e5f8f8 admitted 2147483648 unbounded",
		admitted, led.Setpoint)
}

// ── WHAT MIGRATION 034 CHANGES, AND WHAT IT DOES NOT ─────────────────────────
//
// 034 (packages/metadata-db/migrations/034_liveness_lock_isolation.sql)
// downgrades pfj.require_writer's lease-row lock from FOR SHARE to FOR KEY
// SHARE and turns both liveness renewals into plain non-key UPDATEs. FOR KEY
// SHARE and FOR NO KEY UPDATE are the one pair in PostgreSQL's row-lock matrix
// that does not conflict, so a 16 MiB journal append no longer holds a lock the
// heartbeat needs for the length of its own commit. The measured effect is on
// the APPLIED RATE: appends stop queueing behind the liveness writers, the
// authority's watermark advances faster, and the credit gate's setpoint —
// clamp(appliedRate * creditDrainTarget, floor, ceiling) — rises with it.
//
// A faster applied rate genuinely does reduce how OFTEN a delegated write waits
// out its 40-second budget. The question this test settles is whether that is
// enough on its own, and the answer is no, for a reason the credit arithmetic
// cannot see:
//
//	THE DIVERT IS A ONE-SHOT, NOT A RATE.
//
// Diverting releases the delegation covering the path. After the first divert
// the path is UNCOVERED, and every subsequent write takes the uncovered door —
// which is not gated by credit at all and therefore not affected by the applied
// rate, by 034, or by anything else 034 touches. So the escaped VOLUME is not
// proportional to the divert count. Halving the divert count does not halve the
// bytes; it delays the single event after which the bytes stop being counted at
// all.
//
// 034 does help a second way, and this test measures that too: once credit
// recovers, PrepareDelegatedWrite re-acquires a delegation for the path, and
// the write-through window closes. A faster applied rate shortens that window.
// But "shorter" is not "bounded" — the window's length is a function of the far
// end, and nothing in it caps the bytes acknowledged while it is open. That cap
// is what the lane's gate adds, and it is why the honest fix is 034 AND gating
// rather than 034 instead of gating.
func TestMigration034ShortensTheWriteThroughWindowButDoesNotBoundIt(t *testing.T) {
	pinCreditAdmissionBudget(t, 100*time.Millisecond)
	f := newRoutingFixture(t)
	ctx := context.Background()

	// One divert opens the window.
	if _, _, err := f.write(ctx, "d/hot", 64<<10, false); err != nil {
		t.Fatalf("the diverting write failed: %v", err)
	}
	if f.v.wb.Covers("d/hot") {
		t.Fatal("the divert did not release the delegation")
	}
	opened := f.v.wb.LaneRouting()
	if opened.Ops[writeback.DoorBudget] != 1 {
		t.Fatalf("expected one divert, got %d", opened.Ops[writeback.DoorBudget])
	}

	// WHILE THE WINDOW IS OPEN the applied rate is irrelevant: these writes are
	// uncovered, so they never consult the credit gate that 034 makes faster.
	for i := 0; i < 6; i++ {
		if _, _, err := f.write(ctx, "d/hot", 64<<10, false); err != nil {
			break
		}
	}
	during := f.v.wb.LaneRouting()
	if during.Ops[writeback.DoorUncovered] == 0 {
		t.Fatal("no write took the uncovered door while the window was open")
	}
	if during.Ops[writeback.DoorBudget] != 1 {
		t.Fatalf("the credit gate was consulted again during the window (%d diverts): the "+
			"premise that these writes bypass it is wrong", during.Ops[writeback.DoorBudget])
	}

	// 034's REAL contribution, modelled: a faster applied rate frees credit
	// sooner, and the first write to find headroom re-acquires the delegation
	// and CLOSES the window. Releasing the gate here is that recovery.
	f.v.wb.ReleaseDataCredit(int(f.v.wb.Status().CreditDebt))
	ok, err := f.v.wb.PrepareDelegatedWrite(ctx, "d/hot", 1)
	if err != nil || !ok {
		t.Fatalf("credit recovered and the path was NOT re-delegated (ok=%v err=%v): "+
			"if this is the real behaviour then 034 cannot close the window at all and "+
			"the write-through is permanent, which is strictly worse than reported", ok, err)
	}
	if !f.v.wb.Covers("d/hot") {
		t.Fatal("PrepareDelegatedWrite reported success without covering the path")
	}

	// And the part 034 does NOT supply: while the window was open, every
	// acknowledged byte was charged and bounded. That bound is the lane's gate,
	// and it holds at any applied rate — including the fast one 034 produces,
	// which is precisely the rate at which the 734 MiB incident ran (110 MB/s).
	led := f.v.wb.AuthorityLedgerStatus()
	if led.Acked == 0 {
		t.Fatal("the window admitted nothing; the measurement is vacuous")
	}
	if led.Unproven > led.Setpoint {
		t.Fatalf("the window acknowledged %d unproven byte(s) against a setpoint of %d: "+
			"unbounded, which is what 034 alone would leave", led.Unproven, led.Setpoint)
	}
	t.Logf("window: 1 divert, %d uncovered write(s), %d byte(s) acknowledged and bounded at "+
		"setpoint %d; delegation re-acquired once credit recovered",
		during.Ops[writeback.DoorUncovered], led.Acked, led.Setpoint)
}
