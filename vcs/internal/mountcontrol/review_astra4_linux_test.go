//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
	"testing"
)

func TestR4FinalizationJoinsBootstrap(t *testing.T) {
	var b Bootstrap
	p := *phase()
	p.Witness.Kernel = ""
	if err := b.Begin(p); err != nil {
		t.Fatal(err)
	}
	// The child can have exited while the reserved root mount has not returned.
	b.ChildLost()
	if err := b.Finalize(Absence{true, true, true, true}); !errors.Is(err, ErrOccupied) {
		t.Errorf("finalized before mount owner joined: %v", err)
	}
	rights, fds := descriptors(t)
	if err := b.Finish(rights, witness()); err != nil {
		t.Error(err)
	}
	defer b.Finalize(Absence{true, true, true, true})
	if b.finalized && b.rights != nil {
		t.Errorf("late mount published descriptors after finalization: fds=%v kernel=%q", fds, b.action.Witness.Kernel)
	}
}
func TestR4BootstrapRetainsPartialWitness(t *testing.T) {
	var b Bootstrap
	p := *phase()
	p.Witness.Kernel = ""
	if err := b.Begin(p); err != nil {
		t.Fatal(err)
	}
	rights, _ := descriptors(t)
	unix.Close(rights.FDs[1])
	rights.FDs = rights.FDs[:1]
	// Mount acquired its kernel identity; opening the abort description failed.
	err := b.Finish(rights, witness())
	defer b.Finalize(Absence{true, true, true, true})
	if err == nil {
		t.Fatal("expected incomplete handoff failure")
	}
	if b.action.Witness.Kernel != witness().Kernel {
		t.Errorf("partial failure lost acquired kernel witness: %q", b.action.Witness.Kernel)
	}
}
func TestR4RecoverRequiresExactColdSuspension(t *testing.T) {
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.start.Operation == "workspace-suspend" {
			return j.Publish("cold", Facts{})
		}
		return errors.New("stop fixture")
	})
	q := request("workspace-suspend", 1, 1)
	transaction(t, &q)
	j := start(t, o, q)
	awaitResult(t, j.done)
	r := request("workspace-recover", 2, 2)
	transaction(t, &r)
	wrong := suspension(t)
	wrong.Nonce[0] ^= 0xff
	var err error
	r.Workspace.Transaction, err = EncodeTransaction(&pb.ResumeToken{Suspension: wrong, WakeNonce: []byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.ValidateWorkspace(); err != nil {
		t.Fatal(err)
	}
	if _, err = o.Do(context.Background(), r, &Rights{}); err == nil {
		t.Error("accepted ResumeToken for a different suspension nonce")
	}
}
func TestR4NewServingIntervalDoesNotReuseDurableOutcome(t *testing.T) {
	offered := make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		switch j.start.Operation {
		case "workspace-prepare":
			if err := j.OfferInstall(*phase()); err != nil {
				return err
			}
			close(offered)
			if err := j.WaitInstall(ctx); err != nil {
				return err
			}
			return j.Publish("prepared", readyFacts())
		case "workspace-recover":
			return j.Publish("prepared", readyFacts())
		case "workspace-suspend":
			if j.start.Workspace.Generation == "1" {
				return j.Publish("cold", Facts{Outcome: Outcome{"durable", "observed", "released", "0"}})
			}
			return j.Publish("cold", Facts{Outcome: Outcome{"lost", "observed", "abandoned", "2"}, Loss: []Loss{{Sequence: "1", AcceptedEntries: "1", AcceptedBytes: "4", Reason: "lost after resume"}}})
		}
		return errors.New("unexpected job")
	})
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	rights, _ := descriptors(t)
	do(t, o, installRequest(2, 1), rights)
	awaitResult(t, j.done)
	s := request("workspace-suspend", 3, 3)
	transaction(t, &s)
	j = start(t, o, s)
	awaitResult(t, j.done)
	r := request("workspace-recover", 4, 4)
	transaction(t, &r)
	j = start(t, o, r)
	awaitResult(t, j.done)
	snap := observe(t, o, 5, 4)
	if snap.Workspace.Outcome.Durability == "durable" {
		t.Errorf("new prepared interval retained prior cut: %+v", snap.Workspace.Outcome)
	}
	s = request("workspace-suspend", 6, 6)
	s.Workspace.Generation = "2"
	s.Workspace.HostRequestID = "8"
	s.Workspace.DrainBudgetNanos = "15000000000"
	tx := suspension(t)
	tx.Generation = 2
	s.Workspace.Transaction, _ = EncodeTransaction(tx)
	j = start(t, o, s)
	awaitResult(t, j.done)
	q := request("workspace-observe", 7, 6)
	q.Workspace.Generation = "2"
	snap = do(t, o, q, &Rights{})
	if len(snap.Workspace.Loss) != 1 {
		t.Errorf("later cut lost loss evidence: state=%s outcome=%+v loss=%v", snap.Workspace.State, snap.Workspace.Outcome, snap.Workspace.Loss)
	}
}
func TestR4LateRemovalDoesNotReviveFailedJob(t *testing.T) {
	offered, release := make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.OfferRemoval(Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup", Witness: witness()}); err != nil {
			return err
		}
		close(offered)
		<-release
		return errors.New("release failed while root was executing removal")
	})
	j := start(t, o, cleanupRequest(1, "voluntary"))
	awaitResult(t, offered)
	snap := observe(t, o, 2, 1)
	close(release)
	awaitResult(t, j.done)
	q := request("workspace-unmount-complete", 3, 1)
	q.Workspace.Phase = snap.Workspace.Phases.VoluntaryRemoval.Action.WithWitness(snap.Workspace.Witness)
	q.Workspace.Phase.Removal = &Removal{KernelAbsent: true}
	_, err := o.Do(context.Background(), q, &Rights{})
	if err != nil {
		t.Fatal(err)
	}
	snap, err = o.Do(context.Background(), request("workspace-observe", 4, 1), &Rights{})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Workspace.State != "failed" {
		t.Errorf("late removal erased failure: state=%s reason=%q running=%v", snap.Workspace.State, snap.Workspace.Reason, j.running)
	}
	if _, err = EncodeResponse(snap); err != nil {
		t.Errorf("retained observation no longer encodable: %v", err)
	}
}
