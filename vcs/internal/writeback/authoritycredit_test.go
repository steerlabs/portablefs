package writeback

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── THE OTHER LANE'S CONTRACT ────────────────────────────────────────────────
//
// Every test here is about one sentence from the live incident
// (fsproto/session_client.go:414-419): "768 MiB written unpaced at 110 MB/s —
// every byte on the uncharged authority lane, so nothing paced it".
//
// Two words in it are separate defects and the fix has to answer both.
// UNCHARGED means the bytes were in no ledger, so when the session was fenced
// the size of the loss could only be found by subtracting a reattached file
// from a writer's log. UNPACED means nothing bounded how many of them could be
// acknowledged-and-unproven at once, so the loss had no ceiling.
//
// Note which one rate-limiting would have fixed: neither. The authority was
// running at 110 MB/s. A gate that paced against the observed ACK rate would
// have measured a healthy far end and admitted every byte. The quantity that
// was unbounded is acknowledged-but-UNPROVEN, and that is what these tests pin.

// pinAuthorityTimings compresses the authority gate's waits for tests.
func pinAuthorityTimings(t *testing.T, waitCap, poll, barrier time.Duration) {
	t.Helper()
	oldCap, oldPoll, oldBarrier := authorityWaitCap, authorityPollInterval, volumeBarrierBound
	authorityWaitCap, authorityPollInterval, volumeBarrierBound = waitCap, poll, barrier
	t.Cleanup(func() {
		authorityWaitCap, authorityPollInterval, volumeBarrierBound = oldCap, oldPoll, oldBarrier
	})
}

// authorityFixture is an engine whose authority lane has a prover the test
// drives by hand: the far end acknowledges instantly and proves only when the
// test says so. That is the incident's shape, and it is the shape no ack-rate
// gate can see.
type authorityFixture struct {
	e *Engine
	// proofs counts barrier attempts the gate initiated on its own.
	proofs atomic.Int64
	// allow, when closed, lets every pending and future barrier succeed.
	mu    sync.Mutex
	allow chan struct{}
}

func newAuthorityFixture(t *testing.T, budget int64) *authorityFixture {
	t.Helper()
	f := newSaturationFixture(t, budget)
	af := &authorityFixture{e: f.e, allow: make(chan struct{})}
	af.e.SetAuthorityProver(func(ctx context.Context) error {
		af.proofs.Add(1)
		af.mu.Lock()
		allow := af.allow
		af.mu.Unlock()
		select {
		case <-allow:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	return af
}

func (f *authorityFixture) letProofsSucceed() {
	f.mu.Lock()
	select {
	case <-f.allow:
	default:
		close(f.allow)
	}
	f.mu.Unlock()
}

// writeThrough is one complete authority-lane write: admit, "run the RPC",
// acknowledge what came back, settle. It is deliberately the whole cycle,
// because a test that only admits proves nothing about the ledger.
func (f *authorityFixture) writeThrough(ctx context.Context, n int64) (int64, error) {
	granted, err := f.e.AdmitAuthorityBytes(ctx, n)
	if err != nil {
		return 0, err
	}
	opCtx := WithAuthorityCharge(ctx, granted)
	NoteAuthorityAck(opCtx, int(granted)) // the far end acknowledges everything, instantly
	f.e.SettleAuthorityCharge(opCtx)
	return granted, nil
}

// TestUnprovenAuthorityBytesAreBoundedAndNamed is the round's central claim.
//
// FAILING-FIRST SHAPE: at 3e5f8f8 there is no authority ledger at all, so both
// halves of this assertion are unreachable — a flood is admitted in full at any
// volume (nothing to bound it) and AuthorityLedgerStatus does not exist
// (nothing to name it). The equivalent statement about the old code is
// TestForcedAuthorityPassIsUngatedAtHEAD in the pristine tree, which floods
// AdmitWrite(forceAuthority=true) and shows it never refuses at any volume.
//
// Here the far end behaves exactly as the incident's did: it acknowledges
// everything instantly and proves nothing. The mount must therefore stop —
// bounded by its own setpoint — rather than acknowledging an unbounded backlog
// it cannot account for.
func TestUnprovenAuthorityBytesAreBoundedAndNamed(t *testing.T) {
	pinAuthorityTimings(t, 200*time.Millisecond, 5*time.Millisecond, 2*time.Second)
	const budget = 8 << 20
	f := newAuthorityFixture(t, budget)
	ctx := context.Background()

	chunk := int64(256 << 10)
	var acknowledged int64
	var refusals int
	// Far more than the lane can hold: if anything is unbounded, this loop
	// finds it.
	for i := 0; i < 4096; i++ {
		got, err := f.writeThrough(ctx, chunk)
		if err != nil {
			refusals++
			break
		}
		acknowledged += got
	}
	if refusals == 0 {
		led := f.e.AuthorityLedgerStatus()
		t.Fatalf(
			"THE AUTHORITY LANE IS UNBOUNDED.\n"+
				"  acknowledged: %d byte(s) with nothing proven durable\n"+
				"  setpoint:     %d byte(s)\n"+
				"  unproven:     %d byte(s)\n"+
				"A far end that acknowledges and never proves can therefore take an\n"+
				"unlimited amount of data the mount cannot account for. This is the\n"+
				"734 MiB shape exactly: the loss had no ceiling because nothing\n"+
				"bounded the acknowledged-but-unproven backlog.",
			acknowledged, led.Setpoint, led.Unproven)
	}

	led := f.e.AuthorityLedgerStatus()
	// NAMED: the ledger accounts for every acknowledged byte. This is the
	// number the 18a incident had to reconstruct by subtracting a reattached
	// file from a writer's log.
	if led.Acked != acknowledged {
		t.Fatalf("the ledger recorded %d acknowledged byte(s); the writers were told %d",
			led.Acked, acknowledged)
	}
	if led.Unproven != acknowledged {
		t.Fatalf("nothing was proven, so all %d acknowledged byte(s) must be unproven; ledger says %d",
			acknowledged, led.Unproven)
	}
	// BOUNDED: and the bound is the setpoint, not the writer's patience.
	if led.Unproven > led.Setpoint {
		t.Fatalf("unproven backlog %d exceeded the setpoint %d it is supposed to be bounded by",
			led.Unproven, led.Setpoint)
	}
	if f.proofs.Load() == 0 {
		t.Fatal("the gate never asked for a barrier: a lane that waits for proof it " +
			"does not request wedges until an application happens to call fsync")
	}
	t.Logf("bounded at %d byte(s) acknowledged-unproven (setpoint %d, ceiling %d, %d barrier attempts)",
		led.Unproven, led.Setpoint, budget, f.proofs.Load())
}

// TestProofReleasesTheAuthorityLane is the other half: the bound must be a
// PACE, not a cliff. Once the far end proves its backlog the lane reopens and
// the same writers proceed — a mount that stopped permanently the first time a
// barrier was slow would be a worse failure than the one being fixed.
func TestProofReleasesTheAuthorityLane(t *testing.T) {
	pinAuthorityTimings(t, 200*time.Millisecond, 5*time.Millisecond, 2*time.Second)
	f := newAuthorityFixture(t, 8<<20)
	ctx := context.Background()

	chunk := int64(256 << 10)
	for {
		if _, err := f.writeThrough(ctx, chunk); err != nil {
			break
		}
	}
	blocked := f.e.AuthorityLedgerStatus()
	if blocked.Unproven == 0 {
		t.Fatal("the lane refused with nothing outstanding: the fixture never saturated it")
	}

	f.letProofsSucceed()
	// The gate schedules its own barrier; give the proof it produces time to
	// land rather than reaching in and clearing the ledger by hand.
	deadline := time.Now().Add(10 * time.Second)
	for f.e.AuthorityLedgerStatus().Unproven >= blocked.Unproven {
		if time.Now().After(deadline) {
			t.Fatalf("a far end that started proving never released the lane: still %d unproven",
				f.e.AuthorityLedgerStatus().Unproven)
		}
		_, _ = f.writeThrough(ctx, chunk) // keep driving so the trigger re-arms
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := f.writeThrough(ctx, chunk); err != nil {
		t.Fatalf("the lane did not reopen after proof: %v", err)
	}
	after := f.e.AuthorityLedgerStatus()
	if after.Proven == 0 {
		t.Fatal("the ledger proved nothing even though the barrier succeeded")
	}
	t.Logf("reopened after proof: %d proven, %d still unproven", after.Proven, after.Unproven)
}

// TestAuthorityAdmissionNeverReturnsZeroWithoutAnError pins the one outcome no
// kernel write path can act on. A short grant is progress and is fine; a
// zero-length success is a write that neither succeeded nor failed, and the
// caller has nothing to do with it but spin.
func TestAuthorityAdmissionNeverReturnsZeroWithoutAnError(t *testing.T) {
	pinAuthorityTimings(t, 100*time.Millisecond, 5*time.Millisecond, time.Second)
	f := newAuthorityFixture(t, 4<<20)
	ctx := context.Background()
	for i := 0; i < 2048; i++ {
		granted, err := f.e.AdmitAuthorityBytes(ctx, 128<<10)
		if err != nil {
			return // a definite refusal is the correct terminal outcome
		}
		if granted <= 0 {
			t.Fatalf("admission %d returned granted=%d with a nil error", i, granted)
		}
		opCtx := WithAuthorityCharge(ctx, granted)
		NoteAuthorityAck(opCtx, int(granted))
		f.e.SettleAuthorityCharge(opCtx)
	}
	t.Fatal("the lane never reached a definite outcome in 2048 admissions")
}

// TestAuthorityChargeSettlesExactlyOnce is what keeps the ledger from drifting.
// The settle func runs on every exit path of a frontend write, including paths
// that already settled, and a double settle would refund bytes twice — which
// reads as free headroom and re-opens the lane the bound just closed.
func TestAuthorityChargeSettlesExactlyOnce(t *testing.T) {
	f := newAuthorityFixture(t, 8<<20)
	ctx := context.Background()
	granted, err := f.e.AdmitAuthorityBytes(ctx, 64<<10)
	if err != nil || granted != 64<<10 {
		t.Fatalf("admit: granted=%d err=%v", granted, err)
	}
	opCtx := WithAuthorityCharge(ctx, granted)
	NoteAuthorityAck(opCtx, int(granted))
	before := f.e.AuthorityLedgerStatus()
	if before.InFlight != granted {
		t.Fatalf("charge did not reach the in-flight ledger: %d", before.InFlight)
	}
	for i := 0; i < 5; i++ {
		f.e.SettleAuthorityCharge(opCtx)
	}
	after := f.e.AuthorityLedgerStatus()
	if after.InFlight != 0 {
		t.Fatalf("in-flight is %d after settling; the charge did not close out", after.InFlight)
	}
	if after.Unproven != granted {
		t.Fatalf("five settles recorded %d unproven byte(s) for one %d-byte write",
			after.Unproven, granted)
	}
	if after.Acked != granted {
		t.Fatalf("five settles acknowledged %d byte(s) for one %d-byte write", after.Acked, granted)
	}
}

// TestRefusedAuthorityWriteAcknowledgesNothing is the negative half of the
// ledger. A write-through the authority REFUSED (ENOENT, EACCES, a transport
// error) was never acknowledged to the application, so charging it as unproven
// would inflate the loss figure and throttle the lane over bytes that do not
// exist. The charge is released whole.
func TestRefusedAuthorityWriteAcknowledgesNothing(t *testing.T) {
	f := newAuthorityFixture(t, 8<<20)
	ctx := context.Background()
	granted, err := f.e.AdmitAuthorityBytes(ctx, 256<<10)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	opCtx := WithAuthorityCharge(ctx, granted)
	// The RPC failed: NoteAuthorityAck is never called.
	f.e.SettleAuthorityCharge(opCtx)
	led := f.e.AuthorityLedgerStatus()
	if led.InFlight != 0 || led.Unproven != 0 || led.Acked != 0 {
		t.Fatalf("a refused write left inflight=%d unproven=%d acked=%d; nothing was acknowledged",
			led.InFlight, led.Unproven, led.Acked)
	}
}

// TestShortAuthorityAckChargesOnlyWhatTheAuthorityTook covers the partial
// reply. The application advances its offset by the COUNT, so the ledger must
// carry the count and not the request — the same prefix discipline 18e pinned
// on the delegated lane.
func TestShortAuthorityAckChargesOnlyWhatTheAuthorityTook(t *testing.T) {
	f := newAuthorityFixture(t, 8<<20)
	ctx := context.Background()
	granted, err := f.e.AdmitAuthorityBytes(ctx, 256<<10)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	short := int(granted) / 4
	opCtx := WithAuthorityCharge(ctx, granted)
	NoteAuthorityAck(opCtx, short)
	f.e.SettleAuthorityCharge(opCtx)
	led := f.e.AuthorityLedgerStatus()
	if led.Acked != int64(short) || led.Unproven != int64(short) {
		t.Fatalf("a %d-byte acknowledgement on a %d-byte grant recorded acked=%d unproven=%d",
			short, granted, led.Acked, led.Unproven)
	}
	if led.InFlight != 0 {
		t.Fatalf("in-flight is %d after settlement", led.InFlight)
	}
}

// TestSealedAuthorityGateRefusesDefinitely keeps teardown from hanging a
// writer: once the engine is fenced, the lane answers immediately rather than
// waiting out its cap on a proof that can no longer be produced.
func TestSealedAuthorityGateRefusesDefinitely(t *testing.T) {
	pinAuthorityTimings(t, 30*time.Second, 5*time.Millisecond, time.Second)
	f := newAuthorityFixture(t, 1<<20)
	f.e.authority.seal(ErrFenced)
	done := make(chan error, 1)
	go func() {
		_, err := f.e.AdmitAuthorityBytes(context.Background(), 64<<10)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrFenced) {
			t.Fatalf("a sealed gate answered %v, want ErrFenced", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a sealed authority gate did not refuse promptly; teardown would hang on it")
	}
}

// TestUnprovableLaneAdmitsAndSaysSo covers the mount that has no barrier to
// prove with. Blocking there would wedge on an event that cannot happen, so the
// gate settles on acknowledgement — and Status carries the fact, because a
// durability claim nobody can check must never be made silently.
func TestUnprovableLaneAdmitsAndSaysSo(t *testing.T) {
	pinAuthorityTimings(t, 100*time.Millisecond, 5*time.Millisecond, time.Second)
	f := newSaturationFixture(t, 1<<20)
	ctx := context.Background()
	if led := f.e.AuthorityLedgerStatus(); !led.Unprovable {
		t.Fatal("an engine with no prover installed reported itself provable")
	}
	total := int64(0)
	for i := 0; i < 64; i++ {
		granted, err := f.e.AdmitAuthorityBytes(ctx, 512<<10)
		if err != nil {
			t.Fatalf("an unprovable lane blocked at %d byte(s): it is waiting for a "+
				"proof no installed barrier can produce: %v", total, err)
		}
		opCtx := WithAuthorityCharge(ctx, granted)
		NoteAuthorityAck(opCtx, int(granted))
		f.e.SettleAuthorityCharge(opCtx)
		total += granted
	}
	if !f.e.AuthorityLedgerStatus().Unprovable {
		t.Fatal("Status stopped reporting the lane unprovable while it still was")
	}
}

// TestAuthorityBarrierBoundMatchesFrontend pins the one constant this package
// restates rather than imports. writeback must not depend on clientcore, so the
// barrier bound is duplicated; a duplicate that drifts is worse than an import,
// because the gate would abandon a barrier the frontend is still waiting on.
func TestAuthorityBarrierBoundMatchesFrontend(t *testing.T) {
	if volumeBarrierBound != 60*time.Second {
		t.Fatalf("volumeBarrierBound is %v; clientcore.volumeBarrierTimeout is 60s and the "+
			"two must agree (see clientcore/volume.go)", volumeBarrierBound)
	}
}
