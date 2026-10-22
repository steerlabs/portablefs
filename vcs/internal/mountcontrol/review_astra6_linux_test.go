//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// Imported from Astra r6; only the explicit driver result and exact refusal
// assertion change the original causal schedule.
func TestR6MixedRecoveryFailureSurvivesClose(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed=%v", mixed), func(t *testing.T) {
			offered, recovering, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			o := testOwnerResult(t, func(ctx context.Context, j *Job) LifecycleResult {
				switch j.Request().Operation {
				case "workspace-prepare":
					if err := j.OfferInstall(*phase()); err != nil {
						return lifecycleResult(err)
					}
					close(offered)
					if err := j.WaitInstall(ctx); err != nil {
						return lifecycleResult(err)
					}
					return lifecycleResult(j.Publish("prepared", readyFacts()))
				case "workspace-suspend":
					return lifecycleResult(j.Publish("cold", Facts{}))
				case "workspace-recover":
					if j.Request().Workspace.Generation == "1" {
						close(recovering)
						<-release
						if ctx.Err() == nil {
							return lifecycleResult(errors.New("probe did not cancel generation"))
						}
						if mixed {
							return lifecycleResult(errors.Join(ctx.Err(), errors.New("unrecoverable local recovery failure")))
						}
						return LifecycleResult{Disposition: LifecycleOvertaken, Err: fmt.Errorf("generation overtaken: %w", ctx.Err())}
					}
					return lifecycleResult(j.Publish("prepared", readyFacts()))
				}
				return lifecycleResult(errors.New("unexpected job"))
			})
			j := start(t, o, request("workspace-prepare", 1, 1))
			awaitResult(t, offered)
			rights, _ := descriptors(t)
			do(t, o, installRequest(2, 1), rights)
			awaitResult(t, j.done)
			j = start(t, o, r5Transaction(t, "workspace-suspend", 3, 1))
			awaitResult(t, j.done)
			j = start(t, o, r5Transaction(t, "workspace-recover", 4, 1))
			awaitResult(t, recovering)
			s := r5Transaction(t, "workspace-suspend", 6, 2)
			if err := o.AdmitFrame(s, &Rights{}); err != nil {
				t.Fatal(err)
			}
			close(release)
			awaitResult(t, j.done)
			t.Logf("after joined recovery: terminal latch=%q", o.servingFailure)
			j = start(t, o, s)
			awaitResult(t, j.done)
			q := r5Transaction(t, "workspace-recover", 7, 2)
			out, err := o.Do(context.Background(), q, &Rights{})
			if err != nil {
				if !mixed {
					t.Fatalf("legitimate cancellation prevented later recovery: %v", err)
				}
				if !errors.Is(err, ErrIncarnationTerminal) {
					t.Fatalf("terminal recovery refusal: %v", err)
				}
				refusal := WorkspaceRefusal(q, err)
				raw, encodeErr := EncodeResponse(refusal)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				decoded, decodeErr := DecodeResponse(raw, true)
				if decodeErr != nil || decoded.Workspace.Refusal != "incarnation-terminal" {
					t.Fatalf("terminal refusal round trip: %s %v", raw, decodeErr)
				}
				return
			}
			o.mu.Lock()
			j = o.job
			o.mu.Unlock()
			awaitResult(t, j.done)
			snap := observeGeneration(t, o, 8, 7, "2")
			t.Logf("later recovery: ack=%s state=%s install=%s", out.Workspace.State, snap.Workspace.State, snap.Workspace.Phases.Install.Progress)
			if mixed {
				t.Fatal("joined unrecoverable failure was discarded as cancellation; the same incarnation revived")
			}
			if snap.Workspace.State != "prepared" {
				t.Fatal(snap.Workspace.State)
			}
		})
	}
}

func TestR6UnrecordedContextCancellationIsTerminal(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	o := testOwnerResult(t, func(ctx context.Context, j *Job) LifecycleResult {
		close(entered)
		<-release
		return LifecycleResult{Disposition: LifecycleOvertaken, Err: ctx.Err()}
	})
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, entered)
	// Context state alone is not the owner's recorded overtaking decision.
	j.cancel()
	close(release)
	awaitResult(t, j.done)
	if o.servingFailure == "" {
		t.Fatal("unrecorded context cancellation escaped terminal latch")
	}
}
