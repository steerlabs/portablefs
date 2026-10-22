//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func r5Transaction(t *testing.T, op string, id, generation uint64) Request {
	t.Helper()
	q := request(op, id, id)
	transaction(t, &q)
	q.Workspace.Generation = strconv.FormatUint(generation, 10)
	s := suspension(t)
	s.Generation = generation
	var err error
	if op == "workspace-suspend" {
		q.Workspace.Transaction, err = EncodeTransaction(s)
	} else {
		q.Workspace.Transaction, err = EncodeTransaction(&pb.ResumeToken{Suspension: s, WakeNonce: []byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}})
	}
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func TestR5FailedRecoveryCannotReviveThroughNewSuspend(t *testing.T) {
	offered := make(chan struct{})
	removalOffered := make(chan struct{})
	withdrawing, finishWithdrawal := make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		switch j.Request().Operation {
		case "workspace-prepare":
			if err := j.OfferInstall(*phase()); err != nil {
				return err
			}
			close(offered)
			if err := j.WaitInstall(ctx); err != nil {
				return err
			}
			return j.Publish("prepared", readyFacts())
		case "workspace-suspend":
			if j.start.Workspace.Generation == "2" {
				close(withdrawing)
				<-finishWithdrawal
			}
			return j.Publish("cold", Facts{})
		case "workspace-cleanup":
			if err := j.OfferRemoval(Phase{ActionID: "77", Mode: "terminal", Reason: "failed incarnation", Witness: o5WitnessOf(j)}); err != nil {
				return err
			}
			close(removalOffered)
			if err := j.WaitRemoval(ctx, "terminal"); err != nil {
				return err
			}
			return j.Publish("cleanup-finalized", Facts{})
		case "workspace-recover":
			if j.Request().Workspace.Generation == "1" {
				return errors.New("unrecoverable local preparation failure")
			}
			return j.Publish("prepared", readyFacts())
		}
		return errors.New("unexpected job")
	})
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	rights, _ := descriptors(t)
	do(t, o, installRequest(2, 1), rights)
	awaitResult(t, j.done)
	j = start(t, o, r5Transaction(t, "workspace-suspend", 3, 1))
	awaitResult(t, j.done)
	j = start(t, o, r5Transaction(t, "workspace-recover", 4, 1))
	awaitResult(t, j.done)
	if snap := observe(t, o, 5, 4); snap.Workspace.State != "failed" {
		t.Fatal(snap)
	}
	// Exact cold withdrawal remains necessary after a real failure; it cannot revive this incarnation.
	j = start(t, o, r5Transaction(t, "workspace-suspend", 6, 2))
	awaitResult(t, withdrawing)
	during := observeGeneration(t, o, 8, 6, "2")
	if during.Workspace.State != "failed" || during.Workspace.Reason != o.servingFailure {
		t.Fatalf("withdrawal hid terminal failure: %+v", during.Workspace)
	}
	close(finishWithdrawal)
	awaitResult(t, j.done)
	q := request("workspace-observe", 8, 6)
	q.Workspace.Generation = "2"
	snap := do(t, o, q, &Rights{})
	if snap.Workspace.State != "failed" || snap.Workspace.Reason != o.servingFailure || o.servingFailure == "" || snap.ValidateWorkspace() != nil {
		t.Fatalf("later withdrawal erased terminal evidence: %+v", snap.Workspace)
	}
	out, err := o.Do(context.Background(), r5Transaction(t, "workspace-recover", 7, 2), &Rights{})
	if err == nil {
		o.mu.Lock()
		j = o.job
		o.mu.Unlock()
		awaitResult(t, j.done)
		q := request("workspace-observe", 8, 7)
		q.Workspace.Generation = "2"
		snap := do(t, o, q, &Rights{})
		t.Fatalf("real failure revived the same incarnation: ack=%s final=%s install=%s", out.Workspace.State, snap.Workspace.State, snap.Workspace.Phases.Install.Progress)
	}
	if !errors.Is(err, ErrGrammar) {
		t.Fatalf("recovery refusal: %v", err)
	}
	cleanup := cleanupRequest(9, "terminal")
	cleanup.Workspace.Generation = "2"
	j = start(t, o, cleanup)
	awaitResult(t, removalOffered)
	snap = observeGeneration(t, o, 10, 9, "2")
	removal := r4Unmount(11, 9, snap.Workspace.Phases.TerminalRemoval, snap.Workspace.Witness, true)
	removal.Workspace.Generation = "2"
	do(t, o, removal, &Rights{})
	awaitResult(t, j.done)
	snap = observeGeneration(t, o, 12, 9, "2")
	if snap.Workspace.State != "cleanup-finalized" || o.servingFailure == "" {
		t.Fatalf("exact cleanup failed or erased failure: %+v", snap.Workspace)
	}

}

func observeGeneration(t *testing.T, o *Owner, id, operation uint64, generation string) Response {
	t.Helper()
	q := request("workspace-observe", id, operation)
	q.Workspace.Generation = generation
	return do(t, o, q, &Rights{})
}

func TestR5ServingFailureDistinguishesGenerationCancellation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cancel   bool
		cause    error
		terminal bool
	}{
		{"real-failure", false, errors.New("prepare failed"), true},
		{"cancellation-with-live-context", false, context.Canceled, true},
		{"generation-canceled", true, context.Canceled, false},
		{"real-failure-races-close", true, errors.New("prepare failed"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, release := make(chan *Job, 1), make(chan struct{})
			o := testOwner(t, func(ctx context.Context, j *Job) error {
				if j.start.Operation == "workspace-suspend" {
					return j.Publish("cold", Facts{})
				}
				entered <- j
				<-release
				return tc.cause
			})
			j := start(t, o, request("workspace-prepare", 1, 1))
			<-entered
			s := r5Transaction(t, "workspace-suspend", 2, 1)
			if tc.cancel {
				if err := o.AdmitFrame(s, &Rights{}); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			awaitResult(t, j.done)
			if (o.servingFailure != "") != tc.terminal {
				t.Fatalf("terminal=%q want %v", o.servingFailure, tc.terminal)
			}
			j = start(t, o, s)
			awaitResult(t, j.done)
			if (o.servingFailure != "") != tc.terminal {
				t.Fatal("Suspend erased failure")
			}
		})
	}
}

func TestR5OvertakenPublicationDoesNotEndIncarnation(t *testing.T) {
	for _, mode := range []string{"close-frame", "permit-closed"} {
		t.Run(mode, func(t *testing.T) {
			offered, recovering, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var permit atomic.Bool
			permit.Store(true)
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
				case "workspace-suspend":
					return j.Publish("cold", Facts{})
				case "workspace-recover":
					if j.start.Workspace.Generation == "1" {
						close(recovering)
						<-release
					}
					return j.Publish("prepared", readyFacts())
				}
				return ErrGrammar
			})
			o.CheckPermit = func(Workspace) bool { return permit.Load() }
			j := start(t, o, request("workspace-prepare", 1, 1))
			awaitResult(t, offered)
			rights, _ := descriptors(t)
			do(t, o, installRequest(2, 1), rights)
			awaitResult(t, j.done)
			j = start(t, o, r5Transaction(t, "workspace-suspend", 3, 1))
			awaitResult(t, j.done)
			j = start(t, o, r5Transaction(t, "workspace-recover", 4, 1))
			awaitResult(t, recovering)
			s := r5Transaction(t, "workspace-suspend", 5, 2)
			if mode == "close-frame" {
				if err := o.AdmitFrame(s, &Rights{}); err != nil {
					t.Fatal(err)
				}
			} else {
				permit.Store(false)
			}
			close(release)
			awaitResult(t, j.done)
			if o.servingFailure != "" {
				t.Fatal("overtaken publication terminalized incarnation", o.servingFailure)
			}
			permit.Store(true)
			j = start(t, o, s)
			awaitResult(t, j.done)
			j = start(t, o, r5Transaction(t, "workspace-recover", 6, 2))
			awaitResult(t, j.done)
			if got := observeGeneration(t, o, 7, 6, "2"); got.Workspace.State != "prepared" {
				t.Fatalf("later generation did not recover: %+v", got.Workspace)
			}
		})
	}
}
