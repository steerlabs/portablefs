//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// Imported Astra r2 probe.go and Opus r2 N1. Both successful phase boundaries
// leave the logical job active; neither a concurrent nor late snapshot can
// reinstate the action. The old observation and phase receipts stay immutable.
func TestConsumedActionSurvivesSuccessfulPhaseOverlap(t *testing.T) {
	for _, op := range []string{"workspace-install-kernel", "workspace-unmount-complete"} {
		t.Run(op, func(t *testing.T) {
			r := &Replay{}
			defer r.Close()
			snapshot, releaseSnapshot := make(chan struct{}), make(chan struct{})
			phaseEntered, releasePhase := make(chan struct{}), make(chan struct{})
			var phases atomic.Int32
			var owner *Rights
			defer func() {
				if owner != nil {
					owner.Close()
				}
			}()
			action := phase()
			actionState, phaseState := "kernel-required", "install-complete"
			if op == "workspace-unmount-complete" {
				action.Mode, action.Reason, action.Options = "voluntary", "cleanup", nil
				actionState, phaseState = "unmount-required", "unmount-recorded"
			}
			h := handlerFunc(func(_ context.Context, q Request, d *Rights) (Response, error) {
				switch q.Operation {
				case "workspace-observe":
					out := response(q, actionState)
					out.Workspace.Action = action
					if q.Workspace.RequestID == "3" {
						close(snapshot)
						<-releaseSnapshot
					}
					return out, nil
				case op:
					phases.Add(1)
					owner = d.Take()
					close(phaseEntered)
					<-releasePhase
					out := response(q, phaseState)
					out.Workspace.Witness = witness()
					return out, nil
				}
				return response(q, "accepted"), nil
			})
			for _, q := range []Request{request("workspace-prepare", 1, 1), request("workspace-observe", 2, 1)} {
				if _, err := r.Do(context.Background(), q, &Rights{}, h); err != nil {
					t.Fatal(err)
				}
			}
			observed := make(chan Response, 1)
			go func() {
				out, err := r.Do(context.Background(), request("workspace-observe", 3, 1), &Rights{}, h)
				if err != nil {
					t.Error(err)
				}
				observed <- out
			}()
			awaitResult(t, snapshot)
			q := request(op, 4, 1)
			copy := *action
			q.Workspace.Phase = &copy
			if op == "workspace-unmount-complete" {
				q.Workspace.Phase.Removal = &Removal{KernelAbsent: true}
			}
			d, duplicates := &Rights{}, &Rights{}
			if op == "workspace-install-kernel" {
				d, _ = descriptors(t)
				for _, fd := range d.FDs {
					x, err := unix.Dup(fd)
					if err != nil {
						t.Fatal(err)
					}
					duplicates.FDs = append(duplicates.FDs, x)
				}
			}
			defer duplicates.Close()
			finished := make(chan Response, 1)
			go func() {
				out, err := r.Do(context.Background(), q, d, h)
				if err != nil {
					t.Error(err)
				}
				finished <- out
			}()
			awaitResult(t, phaseEntered)
			r.mu.Lock()
			reserved := r.consumedActions[action.ActionID] && r.nextAction == nil
			r.mu.Unlock()
			if !reserved {
				t.Error("in-flight action was not consumed")
			}
			close(releasePhase)
			receipt := awaitResult(t, finished)
			if receipt.Workspace.State != phaseState {
				t.Fatal(receipt)
			}
			close(releaseSnapshot)
			oldSnapshot := awaitResult(t, observed)
			replayed, err := r.Do(context.Background(), request("workspace-observe", 3, 1), &Rights{}, h)
			if err != nil || !reflect.DeepEqual(oldSnapshot, replayed) {
				t.Fatal("observation receipt changed", err)
			}
			replayed, err = r.Do(context.Background(), q, duplicates, h)
			if err != nil || !reflect.DeepEqual(receipt, replayed) || phases.Load() != 1 {
				t.Fatal("phase replay changed", err)
			}
			r.mu.Lock()
			active := r.active
			r.mu.Unlock()
			if !active {
				t.Fatal("successful phase prematurely ended job")
			}
			q.Workspace.RequestID = "5"
			d = &Rights{}
			if op == "workspace-install-kernel" {
				d, _ = descriptors(t)
			}
			if _, err := r.Do(context.Background(), q, d, h); !errors.Is(err, ErrGrammar) || phases.Load() != 1 {
				t.Fatal("late snapshot rearmed consumed action", err, phases.Load())
			}
		})
	}
}

// Imported Opus r2 N2: neither a handler error nor an observation's own
// deadline is a terminal result for the generation-owned preparation job.
func TestObservationRefusalLeavesJobRecoverable(t *testing.T) {
	for _, mode := range []string{"handler-error", "own-deadline"} {
		t.Run(mode, func(t *testing.T) {
			r := &Replay{}
			defer r.Close()
			var observations, installs atomic.Int32
			h := handlerFunc(func(ctx context.Context, q Request, _ *Rights) (Response, error) {
				switch q.Operation {
				case "workspace-observe":
					if observations.Add(1) == 1 {
						if mode == "handler-error" {
							return Response{}, errors.New("transient snapshot failure")
						}
						<-ctx.Done()
						return Response{}, ctx.Err()
					}
					out := response(q, "kernel-required")
					out.Workspace.Action = phase()
					return out, nil
				case "workspace-install-kernel":
					installs.Add(1)
					out := response(q, "install-complete")
					out.Workspace.Witness = witness()
					return out, nil
				}
				return response(q, "accepted"), nil
			})
			if _, err := r.Do(context.Background(), request("workspace-prepare", 1, 1), &Rights{}, h); err != nil {
				t.Fatal(err)
			}
			q := request("workspace-observe", 2, 1)
			q.Workspace.BudgetNanos = "20000000"
			first, err := r.Do(context.Background(), q, &Rights{}, h)
			if err != nil || first.OK || first.Workspace.State != "refused" {
				t.Fatal(first, err)
			}
			again, err := r.Do(context.Background(), q, &Rights{}, h)
			if err != nil || !reflect.DeepEqual(first, again) || observations.Load() != 1 {
				t.Fatal("refusal not immutable", again, err)
			}
			if _, err := r.Do(context.Background(), request("workspace-observe", 3, 1), &Rights{}, h); err != nil {
				t.Fatal(err)
			}
			q = request("workspace-install-kernel", 4, 1)
			q.Workspace.Phase = phase()
			d, _ := descriptors(t)
			if out, err := r.Do(context.Background(), q, d, h); err != nil || !out.OK || installs.Load() != 1 {
				t.Fatal("refused observation wedged job", out, err)
			}
		})
	}
}

func TestPrepareAcceptanceDeadlineDoesNotBecomeRecoveryResult(t *testing.T) {
	for _, lateAccepted := range []bool{false, true} {
		t.Run(fmt.Sprint(lateAccepted), func(t *testing.T) {
			r := &Replay{}
			defer r.Close()
			calls := 0
			h := handlerFunc(func(ctx context.Context, q Request, _ *Rights) (Response, error) {
				calls++
				if calls == 1 {
					<-ctx.Done()
					if lateAccepted {
						return response(q, "accepted"), nil
					}
					return Response{}, ctx.Err()
				}
				return response(q, "accepted"), nil
			})
			q := request("workspace-prepare", 1, 1)
			q.Workspace.BudgetNanos = "20000000"
			first, err := r.Do(context.Background(), q, &Rights{}, h)
			if err != nil || first.OK || first.Workspace.Refusal != "deadline" {
				t.Fatal(first, err)
			}
			again, err := r.Do(context.Background(), q, &Rights{}, h)
			if err != nil || !reflect.DeepEqual(first, again) || calls != 1 {
				t.Fatal("acceptance receipt changed", err)
			}
			if r.prepareStarted || r.active {
				t.Fatal("missed acceptance became a preparation result")
			}
			if out, err := r.Do(context.Background(), request("workspace-prepare", 2, 2), &Rights{}, h); err != nil || !out.OK || calls != 2 {
				t.Fatal("Prepare acceptance could not retry", out, err)
			}
		})
	}
}

// Imported Opus r2 N3: a pipe models the last-reference hangup of a FUSE
// connection. Replay must neither add owners nor close the handler's owners.
func TestInstallReceiptDoesNotKeepConnectionAlive(t *testing.T) {
	r := &Replay{}
	defer r.Close()
	var handlerOwner *Rights
	h := handlerFunc(func(_ context.Context, q Request, d *Rights) (Response, error) {
		switch q.Operation {
		case "workspace-observe":
			out := response(q, "kernel-required")
			out.Workspace.Action = phase()
			return out, nil
		case "workspace-install-kernel":
			handlerOwner = d.Take()
			out := response(q, "install-complete")
			out.Workspace.Witness = witness()
			return out, nil
		}
		return response(q, "accepted"), nil
	})
	for _, q := range []Request{request("workspace-prepare", 1, 1), request("workspace-observe", 2, 1)} {
		if _, err := r.Do(context.Background(), q, &Rights{}, h); err != nil {
			t.Fatal(err)
		}
	}
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[0])
	abort, err := os.CreateTemp(t.TempDir(), "abort")
	if err != nil {
		t.Fatal(err)
	}
	defer abort.Close()
	fd, err := unix.Dup(int(abort.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	q := request("workspace-install-kernel", 3, 1)
	q.Workspace.Phase = phase()
	if _, err := r.Do(context.Background(), q, &Rights{FDs: []int{pipe[1], fd}}, h); err != nil {
		t.Fatal(err)
	}
	defer handlerOwner.Close()
	poll := []unix.PollFd{{Fd: int32(pipe[0]), Events: unix.POLLIN}}
	if _, err := unix.Poll(poll, 0); err != nil || poll[0].Revents&unix.POLLHUP != 0 {
		t.Fatal("handler lost connection", err)
	}
	handlerOwner.Close()
	if _, err := unix.Poll(poll, 0); err != nil || poll[0].Revents&unix.POLLHUP == 0 {
		t.Fatal("receipt kept connection alive", err)
	}
	if _, err := r.Do(context.Background(), request("workspace-observe", 4, 1), &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Poll(poll, 0); err != nil || poll[0].Revents&unix.POLLHUP == 0 {
		t.Fatal("later observation kept connection alive", err)
	}
}

func TestExpiredAcceptanceConsumesNoReceipt(t *testing.T) {
	r := &Replay{Now: time.Now}
	defer r.Close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := r.Do(ctx, request("workspace-prepare", 1, 1), &Rights{}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if r.start != nil || r.prepareStarted || r.high != [3]uint64{} {
		t.Fatal("expired acceptance consumed state")
	}
}
