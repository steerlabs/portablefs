//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
)

// U1: an incomplete Suspend (cancelled by a newer generation, or handed an
// already-elapsed propagated deadline) followed by a later transition.
func TestOpusR2IncompleteSuspendThenLaterTransition(t *testing.T) {
	for _, variant := range []string{"cancel-then-recover", "cancel-retry-after-drain-deadline", "elapsed-deadline-then-retry"} {
		t.Run(variant, func(t *testing.T) {
			f, g, _ := coldFixture(t)
			f.lookup(t, 1, "warm")
			serial := g.Close(1)
			var o WorkspaceObservation
			var err error
			switch variant {
			case "elapsed-deadline-then-retry":
				o, err = f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(-time.Second))
			default:
				release := make(chan struct{})
				f.notify.mu.Lock()
				f.notify.block = release
				f.notify.mu.Unlock()
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				o, err = f.mount.SuspendWorkspace(ctx, 1, serial, continuous.Time().Add(400*time.Millisecond))
				cancel()
				f.notify.mu.Lock()
				f.notify.block = nil
				f.notify.mu.Unlock()
				close(release)
				if w := f.mount.workspaceLifecycle.withdrawal; w != nil {
					<-w.done
				}
			}
			t.Logf("first Suspend: cold=%v result=%v err=%v", o.ColdComplete, o.Result.Disposition, err)
			if err == nil && variant != "elapsed-deadline-then-retry" {
				t.Fatal("blocked Suspend unexpectedly completed")
			}
			if variant == "cancel-then-recover" {
				o, err = f.mount.RecoverWorkspace(t.Context(), 1, serial)
				t.Logf("Recover after cancelled Suspend: prepared=%v result=%v err=%v", o.Prepared, o.Result.Disposition, err)
				if err != nil || !o.Prepared {
					t.Errorf("FINDING cancel-then-recover: incomplete cut cannot be reconciled by Recover: %v", err)
				}
				return
			}
			time.Sleep(600 * time.Millisecond) // the first captured drain deadline elapses
			serial2 := g.Close(1)
			o, err = f.mount.SuspendWorkspace(t.Context(), 1, serial2, continuous.Time().Add(5*time.Second))
			t.Logf("retry Suspend (fresh deadline): cold=%v result=%v err=%v", o.ColdComplete, o.Result.Disposition, err)
			o2, err2 := f.mount.RecoverWorkspace(t.Context(), 1, serial2)
			t.Logf("Recover: prepared=%v result=%v err=%v", o2.Prepared, o2.Result.Disposition, err2)
			serial3 := g.Close(1)
			o3, err3 := f.mount.SuspendWorkspace(t.Context(), 1, serial3, continuous.Time().Add(5*time.Second))
			t.Logf("third Suspend (fresh deadline): cold=%v err=%v", o3.ColdComplete, err3)
			if err != nil || !o.ColdComplete || err2 != nil || !o2.Prepared || err3 != nil || !o3.ColdComplete {
				t.Errorf("FINDING %s: incarnation stranded after an incomplete Suspend: retry=%v recover=%v third=%v", variant, err, err2, err3)
			}
		})
	}
}

// U2: a published Prepared interval that served nothing is re-acknowledged cold
// without a fresh cut. Record what evidence that acknowledgment carries.
func TestOpusR2PreparedUnservedReacknowledgeEvidence(t *testing.T) {
	f, g, _ := coldFixture(t)
	f.lookup(t, 1, "warm")
	serial := g.Close(1)
	full, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
	if err != nil || !full.ColdComplete {
		t.Fatal(full, err)
	}
	if o, err := f.mount.RecoverWorkspace(t.Context(), 1, serial); err != nil || !o.Prepared {
		t.Fatal(o, err)
	}
	p, err := g.Recovery(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Prepared(p); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(1, serial); err != nil {
		t.Fatal(err)
	}
	w := f.mount.workspaceLifecycle
	f.mount.subscription.mu.RLock()
	activeBefore, proofBefore := f.mount.subscription.active, f.mount.subscription.workspaceProof != nil
	f.mount.subscription.mu.RUnlock()
	// Dark wake: the host sleeps again before any FUSE request is served.
	serial2 := g.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial2, continuous.Time().Add(5*time.Second))
	f.mount.subscription.mu.RLock()
	active, proof := f.mount.subscription.active, f.mount.subscription.workspaceProof != nil
	f.mount.subscription.mu.RUnlock()
	f.mount.delegations.epoch.RLock()
	writeback := f.mount.delegations.writebackStarted
	f.mount.delegations.epoch.RUnlock()
	t.Logf("full cut: workers=%d outcome=%v", len(full.Workers), full.Outcome)
	t.Logf("re-ack: cold=%v err=%v workers=%d parked=%d outcome=%v served=%v", o.ColdComplete, err, len(o.Workers), len(o.ParkedRequests), o.Outcome, w.servedSinceCold.Load())
	t.Logf("subscription before(active=%v proof=%v) after(active=%v proof=%v) writebackStarted=%v", activeBefore, proofBefore, active, proof, writeback)
	if err != nil || !o.ColdComplete {
		t.Fatal("re-ack failed", o.Result, err)
	}
	if len(o.Workers) == 0 {
		t.Errorf("FINDING: ColdComplete re-acknowledgment carries no worker dispositions (full cut carried %d)", len(full.Workers))
	}
	if o.ColdComplete && (active || proof || writeback) {
		t.Errorf("FINDING: re-acknowledged cold left subscription active=%v proof=%v writebackStarted=%v", active, proof, writeback)
	}
	o2, err := f.mount.RecoverWorkspace(t.Context(), 1, serial2)
	t.Logf("Recover after re-ack: prepared=%v err=%v", o2.Prepared, err)
	if err != nil || !o2.Prepared {
		t.Fatal("re-ack stranded recovery", o2.Result, err)
	}
}

type opusFlapClock struct{ unavailable atomic.Bool }

func (c *opusFlapClock) Wait(ctx context.Context, p mountenrollment.Permit) error {
	for c.unavailable.Load() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return nil
}
func (c *opusFlapClock) Check(mountenrollment.Permit) error {
	if c.unavailable.Load() {
		return errors.New("clock readiness lost (missed measurement)")
	}
	return nil
}

// U3: a transient clock-readiness loss while Recover is still retrying its
// same-session validation (network not yet back after wake).
func TestOpusR2ClockFlapDuringRecover(t *testing.T) {
	f, g, rpc := coldFixture(t)
	clock := &opusFlapClock{}
	f.mount.workspaceLifecycle.clock = clock
	serial := g.Close(1)
	if o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second)); err != nil || !o.ColdComplete {
		t.Fatal(o, err)
	}
	rpc.outageUntil = time.Now().Add(2 * time.Second)
	go func() {
		time.Sleep(500 * time.Millisecond)
		clock.unavailable.Store(true)
		time.Sleep(time.Second)
		clock.unavailable.Store(false)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	o, err := f.mount.RecoverWorkspace(ctx, 1, serial)
	t.Logf("Recover across a 1s readiness loss: prepared=%v result=%v err=%v", o.Prepared, o.Result.Disposition, err)
	if err != nil || !o.Prepared || o.Result.Disposition != authorityrpc.LifecycleCompleted {
		t.Errorf("FINDING: transient clock unavailability produced a Failed (incarnation-terminal) Recover result: %v", err)
	}
}
