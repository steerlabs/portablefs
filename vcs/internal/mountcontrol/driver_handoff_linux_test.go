//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"sync"
	"testing"
)

func TestColdObservationWaitsForActualLifecycleJoin(t *testing.T) {
	published, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.Publish("cold", Facts{}); err != nil {
			return err
		}
		close(published)
		<-release
		return nil
	})
	q := r5Transaction(t, "workspace-suspend", 1, 1)
	j := start(t, o, q)
	awaitResult(t, published)
	snap := observe(t, o, 2, 1)
	if snap.Workspace.State != "pending-suspend" || snap.Workspace.ColdComplete {
		t.Fatal("unjoined worker certified coldness", snap)
	}
	once.Do(func() { close(release) })
	awaitResult(t, j.done)
	snap = observe(t, o, 3, 1)
	if snap.Workspace.State != "cold" || !snap.Workspace.ColdComplete {
		t.Fatal(snap)
	}
}

func TestFailedINITRemovalDoesNotWaitForInstallWorker(t *testing.T) {
	var o *Owner
	installOffered := make(chan struct{})
	o = testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.OfferInstall(*phase()); err != nil {
			return err
		}
		close(installOffered)
		return j.WaitInstall(ctx)
	})
	o.Driver.Install = func(ctx context.Context, j *Job, rights *Rights) (Witness, error) {
		err := o.RequireRemoval(ctx, "terminal", "FUSE INIT failed")
		return witness(), errors.Join(errors.New("INIT refused"), err)
	}
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, installOffered)
	q := request("workspace-install-kernel", 2, 1)
	q.Workspace.Phase = phase()
	rights, fds := descriptors(t)
	if _, err := o.Do(context.Background(), q, rights); err != nil {
		t.Fatal(err)
	}
	var snap Response
	for {
		snap = observe(t, o, 3, 1)
		if snap.Workspace.Phases.TerminalRemoval.Progress == "offered" {
			break
		}
		select {
		case <-j.done:
			t.Fatal("install owner ended before root removal")
		default:
		}
	}
	if snap.Workspace.Phases.Install.Progress != "running" {
		t.Fatal("INIT handoff lost install worker ownership", snap)
	}
	q = request("workspace-unmount-complete", 4, 1)
	q.Workspace.Phase = snap.Workspace.Phases.TerminalRemoval.Action.WithWitness(snap.Workspace.Witness)
	q.Workspace.Phase.Removal = &Removal{KernelAbsent: true, AbortCompleted: true}
	if _, err := o.Do(context.Background(), q, &Rights{}); err != nil {
		t.Fatal("root removal blocked behind INIT worker", err)
	}
	awaitResult(t, j.done)
	snap = observe(t, o, 5, 1)
	if snap.Workspace.State != "failed" || snap.Workspace.Phases.Install.Progress != "failed" || snap.Workspace.Phases.TerminalRemoval.Progress != "complete" || snap.Workspace.Witness.Kernel != witness().Kernel {
		t.Fatal("failed INIT erased ownership or removal", snap)
	}
	o.Close()
	assertClosed(t, fds)
}

func TestPermitPollCancelsAttachWithoutSocketOrMountedFrontend(t *testing.T) {
	entered, joined := make(chan struct{}), make(chan struct{})
	o := testOwnerResult(t, func(ctx context.Context, j *Job) LifecycleResult {
		close(entered)
		<-ctx.Done()
		close(joined)
		return authorityrpc.LifecycleCompletion(ctx, ctx.Err())
	})
	current := true
	o.CheckPermit = func(Workspace) bool { return current }
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, entered)
	current = false
	o.PollPermit()
	awaitResult(t, joined)
	awaitResult(t, j.done)
	if o.servingFailure != "" {
		t.Fatal("serial overtaking became independent attach failure")
	}
}
