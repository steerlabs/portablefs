//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func awaitResult[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("replay did not progress")
		var zero T
		return zero
	}
}

// Imported Opus probe A: separate lanes must dispatch independently, and a
// spent waiter cannot cause a handler to receive an already-canceled context.
func TestObservationDoesNotWaitBehindPhase(t *testing.T) {
	r := &Replay{}
	defer r.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	h := handlerFunc(func(ctx context.Context, q Request, _ *Rights) (Response, error) {
		switch q.Operation {
		case "workspace-cleanup":
			close(entered)
			<-release
		case "workspace-observe":
			if ctx.Err() != nil {
				t.Error("observation dispatched canceled", ctx.Err())
			}
			return response(q, "preparing"), nil
		}
		return response(q, "accepted"), nil
	})
	r.Do(context.Background(), request("workspace-prepare", 1, 1), &Rights{}, h)
	cleanup := request("workspace-cleanup", 2, 2)
	cleanup.Workspace.Phase = &Phase{Mode: "voluntary", Witness: witness()}
	done := make(chan error, 1)
	go func() { _, err := r.Do(context.Background(), cleanup, &Rights{}, h); done <- err }()
	awaitResult(t, entered)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := r.Do(ctx, request("workspace-observe", 3, 2), &Rights{}, h)
	close(release)
	if err != nil {
		t.Fatal("observation blocked by phase", err)
	}
	if err := awaitResult(t, done); err != nil {
		t.Fatal(err)
	}
}

// Imported Opus probe B: an observation must not retire a phase that never ran.
func TestObservationHighWaterDoesNotRetireUnexecutedInstall(t *testing.T) {
	r := &Replay{}
	defer r.Close()
	installs := 0
	h := handlerFunc(func(_ context.Context, q Request, _ *Rights) (Response, error) {
		switch q.Operation {
		case "workspace-observe":
			out := response(q, "kernel-required")
			out.Workspace.Action = phase()
			return out, nil
		case "workspace-install-kernel":
			installs++
			out := response(q, "install-complete")
			out.Workspace.Witness = witness()
			return out, nil
		}
		return response(q, "accepted"), nil
	})
	r.Do(context.Background(), request("workspace-prepare", 1, 1), &Rights{}, h)
	r.Do(context.Background(), request("workspace-observe", 2, 1), &Rights{}, h)
	r.Do(context.Background(), request("workspace-observe", 4, 1), &Rights{}, h)
	q := request("workspace-install-kernel", 3, 1)
	q.Workspace.Phase = phase()
	d, _ := descriptors(t)
	if _, err := r.Do(context.Background(), q, d, h); err != nil || installs != 1 {
		t.Fatal("never executed phase retired", err, installs)
	}
}

// Imported Opus probe C: the first Suspend receipt deadline belongs only to
// that request; a final observation gets its own live socket budget.
func TestFinalObservationOutlivesSuspendReceiptDeadline(t *testing.T) {
	// Keep actual dispatch deadlines live while advancing only the replay
	// clock past the captured Suspend deadline. The deadline comparison below
	// falsifies inheritance without a one-millisecond acceptance race.
	clock := time.Now().Add(time.Hour)
	r := &Replay{Now: func() time.Time { return clock }}
	defer r.Close()
	var suspendDeadline time.Time
	h := handlerFunc(func(ctx context.Context, q Request, _ *Rights) (Response, error) {
		if q.Operation == "workspace-observe" {
			if ctx.Err() != nil {
				t.Error("final observation expired", ctx.Err())
			}
			d, _ := ctx.Deadline()
			if !d.After(suspendDeadline) {
				t.Error("inherited drain deadline")
			}
			out := response(q, "failed")
			out.Workspace.Reason = "drain overran"
			return out, nil
		}
		suspendDeadline, _ = ctx.Deadline()
		return response(q, "accepted"), nil
	})
	q := request("workspace-suspend", 1, 1)
	q.Workspace.BudgetNanos = "1000000"
	transaction(t, &q)
	if _, err := r.Do(context.Background(), q, &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	clock = suspendDeadline.Add(time.Second)
	out, err := r.Do(context.Background(), request("workspace-observe", 2, 1), &Rights{}, h)
	if err != nil || out.Workspace.State != "failed" {
		t.Fatal(out, err)
	}
}

// Imported Opus probe D: loss of a waiter after dispatch cannot freeze Prepare
// as context.Canceled, nor execute a second job on an exact retry.
func TestLostWaiterReconcilesJobOwnedPrepare(t *testing.T) {
	r := &Replay{}
	defer r.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	h := handlerFunc(func(ctx context.Context, q Request, _ *Rights) (Response, error) {
		calls.Add(1)
		close(entered)
		<-release
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return response(q, "accepted"), nil
	})
	q := request("workspace-prepare", 1, 1)
	lost, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := r.Do(lost, q, &Rights{}, h); done <- err }()
	awaitResult(t, entered)
	cancel()
	if err := awaitResult(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	out, err := r.Do(context.Background(), q, &Rights{}, h)
	if err != nil || out.Workspace.State != "accepted" || calls.Load() != 1 {
		t.Fatal(out, err, calls.Load())
	}
	// Cancellation before acceptance consumes no ID or operation at all.
	r2 := &Replay{}
	defer r2.Close()
	if _, err := r2.Do(lost, q, &Rights{}, h); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if r2.prepareStarted || r2.start != nil {
		t.Fatal("canceled pre-acceptance waiter consumed Prepare")
	}
}

// Imported Opus probe E: Suspend closes admission while an observation still
// owns its lane. No synchronous driver call may hold Replay.mu.
func TestSuspendClosesBeforeBlockedObservationFinishes(t *testing.T) {
	r := &Replay{}
	defer r.Close()
	entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	r.CloseAdmission = func() { closed <- struct{}{} }
	h := handlerFunc(func(_ context.Context, q Request, _ *Rights) (Response, error) {
		if q.Operation == "workspace-observe" {
			close(entered)
			<-release
			return response(q, "preparing"), nil
		}
		return response(q, "accepted"), nil
	})
	r.Do(context.Background(), request("workspace-prepare", 1, 1), &Rights{}, h)
	done := make(chan error, 1)
	go func() {
		_, err := r.Do(context.Background(), request("workspace-observe", 2, 1), &Rights{}, h)
		done <- err
	}()
	awaitResult(t, entered)
	q := request("workspace-suspend", 3, 3)
	transaction(t, &q)
	suspended := make(chan error, 1)
	go func() { _, err := r.Do(context.Background(), q, &Rights{}, h); suspended <- err }()
	awaitResult(t, closed)
	if err := awaitResult(t, suspended); err != nil {
		t.Error(err)
	}
	close(release)
	awaitResult(t, done)
}

// Imported Opus probe F: completion consumes the outstanding kernel action.
func TestCompletedJobClearsPendingKernelAction(t *testing.T) {
	for _, state := range []string{"prepared", "cold", "cleanup-finalized", "failed"} {
		t.Run(state, func(t *testing.T) {
			r := &Replay{}
			defer r.Close()
			observations, installs := 0, 0
			h := handlerFunc(func(_ context.Context, q Request, _ *Rights) (Response, error) {
				if q.Operation == "workspace-install-kernel" {
					installs++
				}
				if q.Operation != "workspace-observe" {
					return response(q, "accepted"), nil
				}
				observations++
				if observations == 1 {
					out := response(q, "kernel-required")
					out.Workspace.Action = phase()
					return out, nil
				}
				out := response(q, state)
				switch state {
				case "failed":
					out.Workspace.Reason = "unrecoverable"
				case "cold":
					out.Workspace.ColdComplete = true
				case "cleanup-finalized":
					out.Workspace.Witness = witness()
				case "prepared":
					out.Workspace.Witness = witness()
					out.Workspace.Witness.Session = "s"
					out.Workspace.AuthorizationDeadlineUnixNanos = "2000000000000000000"
					out.Workspace.Readiness = &Prepared{SessionValidated: true, AuthorizationValidated: true, Renewal: Renewal{"installed", "1"}, SubscriptionIncarnation: "1"}
				}
				return out, nil
			})
			for _, q := range []Request{request("workspace-prepare", 1, 1), request("workspace-observe", 2, 1), request("workspace-observe", 3, 1)} {
				if _, err := r.Do(context.Background(), q, &Rights{}, h); err != nil {
					t.Fatal(err)
				}
			}
			q := request("workspace-install-kernel", 4, 1)
			q.Workspace.Phase = phase()
			d, _ := descriptors(t)
			if _, err := r.Do(context.Background(), q, d, h); !errors.Is(err, ErrGrammar) || installs != 0 || r.nextAction != nil {
				t.Fatal("completed action dispatched", err, installs)
			}
		})
	}
}

// Astra P2-4: SCM_RIGHTS/dup copies retain an open description; fresh opens of
// the same inode do not. Every received duplicate closes on either verdict.
func TestInstallReplayBindsOpenDescriptions(t *testing.T) {
	r := &Replay{}
	defer r.Close()
	var closed atomic.Int32
	r.CloseAdmission = func() { closed.Add(1) }
	var handlerOwner *Rights
	defer func() {
		if handlerOwner != nil {
			handlerOwner.Close()
		}
	}()
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
	r.Do(context.Background(), request("workspace-prepare", 1, 1), &Rights{}, h)
	r.Do(context.Background(), request("workspace-observe", 2, 1), &Rights{}, h)
	owned, duplicates, fresh := &Rights{}, &Rights{}, &Rights{}
	for i := 0; i < 2; i++ {
		file, err := os.CreateTemp(t.TempDir(), "same-node")
		if err != nil {
			t.Fatal(err)
		}
		a, err := unix.Dup(int(file.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := unix.Dup(a)
		if err != nil {
			t.Fatal(err)
		}
		c, err := unix.Open(file.Name(), unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
		owned.FDs = append(owned.FDs, a)
		duplicates.FDs = append(duplicates.FDs, b)
		fresh.FDs = append(fresh.FDs, c)
	}
	q := request("workspace-install-kernel", 3, 1)
	q.Workspace.Phase = phase()
	if _, err := r.Do(context.Background(), q, owned, h); err != nil {
		t.Fatal(err)
	}
	dupFDs := append([]int{}, duplicates.FDs...)
	if _, err := r.Do(context.Background(), q, duplicates, h); err != nil {
		t.Fatal("dup refused", err)
	}
	assertClosed(t, dupFDs)
	freshFDs := append([]int{}, fresh.FDs...)
	if _, err := r.Do(context.Background(), q, fresh, h); !errors.Is(err, ErrGrammar) || closed.Load() != 1 {
		t.Fatal("same-inode substitute accepted", err, closed.Load())
	}
	assertClosed(t, freshFDs)
	handlerFDs := append([]int{}, handlerOwner.FDs...)
	r.Close()
	for _, fd := range handlerFDs {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Fatal("replay closed handler owner", err)
		}
	}
	handlerOwner.Close()
	assertClosed(t, handlerFDs)
}

func TestWorkspaceResponseMaximumIsBoundedBeforeDispatch(t *testing.T) {
	q := request("workspace-recover", 1, 1)
	transaction(t, &q)
	// Near-limit requests do not echo any transaction bytes in their response.
	q.Workspace.Transaction = strings.Repeat("x", MaxWorkspaceRequest-1024)
	out := response(q, "failed")
	out.Workspace.Reason = strings.Repeat("\x00", 256)
	out.Workspace.Witness.Target = strings.Repeat("\x00", 512)
	for i := 1; i <= 32; i++ {
		out.Workspace.Loss = append(out.Workspace.Loss, Loss{Sequence: strconv.FormatUint(uint64(i), 10), AcceptedEntries: "18446744073709551615", AcceptedBytes: "18446744073709551615", Reason: strings.Repeat("\x00", 256)})
	}
	raw, err := EncodeResponse(out)
	if err != nil || len(raw) > MaxWorkspaceResponse {
		t.Fatal("valid bounded evidence exceeded response frame", len(raw), err)
	}
	if strings.Contains(string(raw), strings.Repeat("x", 100)) {
		t.Fatal("transaction echoed")
	}
	// The largest action variant must fit with the same maximum loss ledger.
	action := response(q, "kernel-required")
	action.Workspace.Loss = out.Workspace.Loss
	action.Workspace.Witness = out.Workspace.Witness
	action.Workspace.Action = &Phase{ActionID: "18446744073709551615", Witness: Witness{Process: "p", Source: "s", Target: "/" + strings.Repeat("\x00", 509)}, Options: []string{strings.Repeat("\x00", 256)}}
	if raw, err := EncodeResponse(action); err != nil || len(raw) > MaxWorkspaceResponse {
		t.Fatal("maximum action exceeded frame", len(raw), err)
	}
	out.Workspace.Witness.Target += "x"
	if _, err := EncodeResponse(out); err == nil {
		t.Fatal("unbounded witness")
	}
}

func TestLateObservationCannotRestoreCompletedKernelAction(t *testing.T) {
	r := &Replay{}
	defer r.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	installs := 0
	h := handlerFunc(func(_ context.Context, q Request, _ *Rights) (Response, error) {
		switch q.Operation {
		case "workspace-observe":
			if q.Workspace.RequestID == "3" {
				close(entered)
				<-release
			}
			out := response(q, "kernel-required")
			out.Workspace.Action = phase()
			return out, nil
		case "workspace-install-kernel":
			installs++
			out := response(q, "failed")
			out.Workspace.Reason = "installation failed"
			return out, nil
		}
		return response(q, "accepted"), nil
	})
	for _, q := range []Request{request("workspace-prepare", 1, 1), request("workspace-observe", 2, 1)} {
		if _, err := r.Do(context.Background(), q, &Rights{}, h); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := r.Do(context.Background(), request("workspace-observe", 3, 1), &Rights{}, h)
		done <- err
	}()
	awaitResult(t, entered)
	q := request("workspace-install-kernel", 4, 1)
	q.Workspace.Phase = phase()
	d, _ := descriptors(t)
	if _, err := r.Do(context.Background(), q, d, h); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := awaitResult(t, done); err != nil {
		t.Fatal(err)
	}
	q.Workspace.RequestID = "5"
	d, _ = descriptors(t)
	if _, err := r.Do(context.Background(), q, d, h); !errors.Is(err, ErrGrammar) || installs != 1 || r.nextAction != nil {
		t.Fatal("late observation revived a completed action", err, installs)
	}
}
