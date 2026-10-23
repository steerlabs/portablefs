//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"testing"
)

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
