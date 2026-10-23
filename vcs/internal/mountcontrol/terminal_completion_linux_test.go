//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

func TestTerminalRemovalCannotReanimateJoinedLifecycle(t *testing.T) {
	o := testOwner(t, func(context.Context, *Job) error { return authorityrpc.ErrSessionEnded })
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, j.done)
	if err := o.Record(Facts{Witness: witness()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- o.RequireRemoval(ctx, "terminal", authorityrpc.ErrSessionEnded.Error()) }()
	var snap Response
	for {
		snap = observe(t, o, 2, 1)
		if snap.Workspace.Phases.TerminalRemoval.Progress == "offered" {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
	}
	if snap.Workspace.State != "failed" || snap.Workspace.Reason != authorityrpc.ErrSessionEnded.Error() {
		t.Fatal("joined failure was replaced by pending removal", snap)
	}
	q := request("workspace-unmount-complete", 3, 1)
	q.Workspace.Phase = snap.Workspace.Phases.TerminalRemoval.Action.WithWitness(snap.Workspace.Witness)
	q.Workspace.Phase.Removal = &Removal{KernelAbsent: true, AbortCompleted: true}
	if _, err := o.Do(ctx, q, &Rights{}); err != nil {
		t.Fatal(err)
	}
	if err := awaitResult(t, done); err != nil {
		t.Fatal(err)
	}
	if snap = observe(t, o, 4, 1); snap.Workspace.State != "failed" || !errors.Is(j.ctx.Err(), context.Canceled) {
		t.Fatal("removal erased final lifecycle disposition", snap)
	}
}
