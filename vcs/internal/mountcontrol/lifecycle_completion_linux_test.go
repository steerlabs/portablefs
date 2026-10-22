//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

func TestLifecycleAttemptFailureAtCancellationSetsTerminalLatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cause    error
		terminal bool
	}{
		{"local", errors.New("independent local failure"), true},
		{"protocol", authorityrpc.ErrTransportBinding, true},
		{"authorization", authorityrpc.ErrSessionEnded, true},
		{"mixed", errors.Join(io.EOF, errors.New("independent persistence failure")), true},
		{"transport-only", io.EOF, false},
		{"cancellation-only", context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			o := testOwnerResult(t, func(ctx context.Context, j *Job) LifecycleResult {
				return authorityrpc.RetryLifecycle(ctx, time.Second, func(context.Context) error { close(entered); <-release; return tc.cause })
			})
			j := start(t, o, request("workspace-prepare", 1, 1))
			<-entered
			if err := o.AdmitFrame(r5Transaction(t, "workspace-suspend", 2, 1), &Rights{}); err != nil {
				t.Fatal(err)
			}
			close(release)
			awaitResult(t, j.done)
			if (o.servingFailure != "") != tc.terminal {
				t.Fatalf("incarnation terminal latch=%q want %v", o.servingFailure, tc.terminal)
			}
		})
	}
}

// A cancelled sleep can consume a fresh token for the exact incomplete
// suspension. The frontend owns finishing withdrawal/fencing before Subscribe.
func TestRecoverReconcilesIncompleteSuspendWithFreshToken(t *testing.T) {
	entered := make(chan Request, 2)
	owner := testOwnerResult(t, func(ctx context.Context, j *Job) LifecycleResult {
		entered <- j.Request()
		return LifecycleResult{Disposition: LifecycleOvertaken, Err: context.Canceled}
	})
	suspend := r5Transaction(t, "workspace-suspend", 1, 1)
	job := start(t, owner, suspend)
	awaitResult(t, entered)
	awaitResult(t, job.done)
	recover := r5Transaction(t, "workspace-recover", 2, 1)
	job = start(t, owner, recover)
	if q := awaitResult(t, entered); q.Operation != "workspace-recover" {
		t.Fatal(q.Operation)
	}
	awaitResult(t, job.done)
}
