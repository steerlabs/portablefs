package clientcore

// What the data lane does when its credit budget expires.
//
// The budget's expiry used to be read as a proof: noProgressWindow (30s) +
// creditWaitCap (5s) < creditAdmissionBudget (40s) was taken to mean that a
// genuinely stalled uplink had already been DECLARED stalled by the time the
// budget ran out, so expiry could only mean "healthy but slow" and the divert to
// the authority lane was unconditional. It is not a proof. The watchdog's window
// runs from the last watermark advance, not from the moment this write began to
// wait, so an advance at t39 leaves the verdict a full window away at t40 —
// and the divert would then send this write's release and RPC into a far end
// that may be applying nothing at all.
//
// These tests pin the fix: at expiry the gate ASKS
// writeback.Engine.StallVerdict, relays a stall verdict, and diverts only on a
// live one — with the whole admission still bounded by the single operation
// deadline.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// stallRemote is an authority that grants delegations and then never applies
// anything: every flush parks until the engine's lifetime context ends. It is
// the minimum needed to give the flusher a watched backlog, which is what a
// stall verdict is a statement about.
type stallRemote struct {
	mu    sync.Mutex
	epoch int
	gate  chan struct{}
}

func newStallRemote() *stallRemote {
	return &stallRemote{gate: make(chan struct{})}
}

func (r *stallRemote) DelegationAcquire(
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

func (r *stallRemote) ReleaseDelegation(ctx context.Context, _, _ string) error {
	// A release only reaches the authority after its scope has drained, and
	// nothing drains through this remote. Parking here keeps that honest: the
	// caller's own deadline is what ends the wait.
	<-ctx.Done()
	return ctx.Err()
}

func (r *stallRemote) Flush(
	ctx context.Context, _ writeback.FlushRequest,
) (writeback.FlushReply, error) {
	r.mu.Lock()
	gate := r.gate
	r.mu.Unlock()
	select {
	case <-gate:
	case <-ctx.Done():
	}
	return writeback.FlushReply{}, ctx.Err()
}

func (r *stallRemote) FlushResolved(
	ctx context.Context, req writeback.FlushRequest,
) (writeback.FlushReply, error) {
	return r.Flush(ctx, req)
}

func (r *stallRemote) StreamState(
	context.Context, string,
) (writeback.StreamState, error) {
	return writeback.StreamState{}, nil
}

func (r *stallRemote) Rebind(
	context.Context, string, []writeback.RebindScope, uint64, [32]byte,
) (writeback.RebindReply, error) {
	return writeback.RebindReply{}, nil
}

func (r *stallRemote) Discard(context.Context, string, []writeback.RebindScope) error {
	return nil
}

func baseNameOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// newStalledCreditVolume builds a Volume whose engine has (a) a watched backlog
// no authority will ever apply, and (b) a data-credit gate with nothing left to
// give. Both are what an expiring credit budget looks like from inside
// admitDelegatedLane; only the watchdog's window separates the two outcomes.
func newStalledCreditVolume(t *testing.T, window time.Duration) *Volume {
	t.Helper()
	// Registered BEFORE the engine exists, so it restores AFTER the engine's own
	// cleanup has stopped the goroutines that read it.
	t.Cleanup(writeback.SetNoProgressWindowForTest(window))

	remote := newStallRemote()
	wb, err := writeback.Open(context.Background(), writeback.Config{
		StateDir: t.TempDir(), VolumeID: "vol-stall", Branch: "main",
		Remote: remote, BudgetBytes: 4 << 20,
	})
	if err != nil {
		t.Fatalf("open writeback engine: %v", err)
	}
	t.Cleanup(func() { _, _ = wb.ForceClose("test teardown") })

	ctx := context.Background()
	for i := 0; i < 8; i++ {
		if _, handled, err := wb.Mkdir(ctx, "d/pending"+itoa(i), 0o755); err != nil || !handled {
			t.Fatalf("mkdir %d: handled=%v err=%v (the fixture needs a delegated "+
				"backlog for the watchdog to watch)", i, handled, err)
		}
	}
	if recs, _ := wb.Pending(); recs == 0 {
		t.Fatal("no pending records: the flusher has nothing to make a verdict about")
	}
	saturateDataCredit(t, wb)
	return &Volume{wb: wb}
}

// saturateDataCredit takes credit until the gate has none left to hand out
// inside a short window, which is exactly the state a write entering
// admitDelegatedLane finds when its budget is about to expire.
func saturateDataCredit(t *testing.T, wb *writeback.Engine) {
	t.Helper()
	const chunk = 64 << 10
	for i := 0; i < 1024; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		granted, err := wb.AcquireDataCredit(ctx, chunk)
		cancel()
		if granted == 0 {
			return // the gate is full; the collected credit is deliberately never released
		}
		if err != nil {
			t.Fatalf("saturating the credit gate: granted=%d err=%v", granted, err)
		}
	}
	t.Fatal("the credit gate never saturated")
}

// pinAdmissionBudgets compresses the two bounds whose EXPIRY shape is under
// test. Their landed values (40s credit inside a 50s operation) are proved
// elsewhere; here only the ordering matters — the credit stage must expire
// strictly first, or the arm never runs.
func pinAdmissionBudgets(t *testing.T, credit, operation time.Duration) {
	t.Helper()
	oldCredit, oldOperation := creditAdmissionBudget, operationAdmissionBudget
	creditAdmissionBudget, operationAdmissionBudget = credit, operation
	t.Cleanup(func() {
		creditAdmissionBudget, operationAdmissionBudget = oldCredit, oldOperation
	})
}

// TestDataCreditExpiryRelaysStallVerdict is the finding. With the watchdog
// holding a stall verdict, budget expiry must relay it — not divert a release
// and an authority RPC into a far end that is applying nothing.
func TestDataCreditExpiryRelaysStallVerdict(t *testing.T) {
	pinAdmissionBudgets(t, 150*time.Millisecond, 5*time.Second)
	v := newStalledCreditVolume(t, 50*time.Millisecond)
	waitForEngineStall(t, v.wb, true)

	opCtx, cancelDeadline := withOperationDeadline(context.Background())
	ctx, granted, settle, err := v.admitDelegatedLane(opCtx, cancelDeadline, "far/f", nil, 4<<10)
	settle()
	if !errors.Is(err, writeback.ErrUplinkStalled) {
		t.Fatalf("credit budget expiring against a STALLED watchdog = (granted=%d, "+
			"err=%v), want ErrUplinkStalled: expiry proves nothing about the far "+
			"end, and the live verdict says it is dead", granted, err)
	}
	if granted != 0 {
		t.Fatalf("a stalled outcome still granted %d bytes", granted)
	}
	if lane := writeback.LaneOf(ctx); lane == writeback.LaneAuthority {
		t.Fatal("the write was admitted onto the authority lane anyway; the release " +
			"it needs would drain into the dead far end this verdict names")
	}
	if got := DataCreditStatus(err); got != statusErr(writeback.ErrUplinkStalled) {
		t.Fatalf("DataCreditStatus of the relayed verdict = %d, want the EIO class "+
			"every lane gives a dead uplink", got)
	}
}

// TestDataCreditExpiryDivertsWithinOperationDeadline is the other half: a live
// uplink still gets the divert, and the divert is still bounded.
//
// The two subtests answer the two different questions the bound raises. The
// first is the ordinary case — the release the divert needs has nothing to drain,
// so it completes with the operation's deadline barely touched. The second is
// the case that cannot be answered by arithmetic at all: the release DOES have a
// backlog to drain through an uplink that is not moving. No remaining-time
// calculation makes that fit, and none is claimed to — what holds is that the
// divert runs under the SAME operation deadline, so it reaches a definite
// outcome AT it and never past it.
func TestDataCreditExpiryDivertsWithinOperationDeadline(t *testing.T) {
	t.Run("live uplink diverts to the authority lane", func(t *testing.T) {
		pinAdmissionBudgets(t, 150*time.Millisecond, 5*time.Second)
		// A window far wider than the budget: there is a real backlog and no
		// verdict about it — the state a t39 advance leaves behind.
		v := newStalledCreditVolume(t, time.Hour)
		waitForEngineStall(t, v.wb, false)

		start := time.Now()
		opCtx, cancelDeadline := withOperationDeadline(context.Background())
		deadline, ok := opCtx.Deadline()
		if !ok {
			t.Fatal("the operation carries no deadline")
		}
		// "far/f" is outside every held scope, so the divert's release has
		// nothing to drain: this measures the divert itself.
		ctx, granted, settle, err := v.admitDelegatedLane(opCtx, cancelDeadline, "far/f", nil, 4<<10)
		defer settle()
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("credit budget expiring against a LIVE watchdog = %v, want the "+
				"authority-lane divert", err)
		}
		if granted != 4<<10 {
			t.Fatalf("the divert granted %d of %d bytes", granted, 4<<10)
		}
		if lane := writeback.LaneOf(ctx); lane != writeback.LaneAuthority {
			t.Fatalf("diverted onto lane %v, want the authority lane", lane)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the divert completed %s past the operation deadline", time.Since(deadline))
		}
		// The bound is one deadline, not a sum of stages: the ctx the divert
		// returns must carry the SAME instant, or a later stage would be running
		// on a clock this admission re-armed.
		if got, ok := ctx.Deadline(); !ok || !got.Equal(deadline) {
			t.Fatalf("the admitted ctx's deadline is %v (ok=%v), want the operation's "+
				"own %v", got, ok, deadline)
		}
		if remaining := time.Until(deadline); remaining <= 0 {
			t.Fatalf("no operation-deadline time remained after a %s admission", elapsed)
		}
	})

	t.Run("a draining release is bounded by the operation deadline", func(t *testing.T) {
		pinAdmissionBudgets(t, 150*time.Millisecond, time.Second)
		v := newStalledCreditVolume(t, time.Hour)
		waitForEngineStall(t, v.wb, false)

		opCtx, cancelDeadline := withOperationDeadline(context.Background())
		deadline, _ := opCtx.Deadline()
		// "d/f" IS covered by the held delegation, so the divert's release must
		// drain the backlog first — through an uplink that is applying nothing.
		_, granted, settle, err := v.admitDelegatedLane(opCtx, cancelDeadline, "d/f", nil, 4<<10)
		settle()
		if err == nil {
			t.Fatalf("a release that had to drain a stopped uplink was admitted "+
				"anyway (granted=%d)", granted)
		}
		if errors.Is(err, writeback.ErrUplinkStalled) {
			t.Fatalf("the divert reported a stall the watchdog never declared: %v", err)
		}
		// Definite, and AT the bound rather than past it. This — not a
		// remaining-time calculation — is what makes the post-expiry divert safe:
		// it inherits the operation's single absolute deadline.
		if late := time.Since(deadline); late > 500*time.Millisecond {
			t.Fatalf("the divert's release returned %s past the operation deadline "+
				"(err=%v); the stage is composing its own bound again", late, err)
		}
	})
}

func waitForEngineStall(t *testing.T, wb *writeback.Engine, want bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		v := wb.StallVerdict()
		if v.Stalled == want {
			if !v.Pending {
				t.Fatalf("the engine holds no pending work, so verdict %+v is not "+
					"about a watched stream", v)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the watchdog verdict never reached Stalled=%v (now %+v)",
				want, wb.StallVerdict())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
