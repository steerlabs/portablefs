package authorityrpc

import (
	"context"
	"errors"
	"syscall"
	"testing"
)

type testPermitLoss struct{}

func (e testPermitLoss) Error() string { return "newer supervisor serial" }
func (e testPermitLoss) LifecyclePermitLoss() LifecyclePermitLoss {
	return LifecyclePermitLoss{Generation: 2, Serial: 3, Successor: 4}
}

func TestLifecyclePermitLossPreservesIndependentFailure(t *testing.T) {
	loss := testPermitLoss{}
	for _, tc := range []struct {
		name  string
		cause error
		want  LifecycleDisposition
	}{
		{"gate", loss, LifecycleOvertaken},
		{"gate-and-cancellation", errors.Join(loss, context.Canceled), LifecycleOvertaken},
		{"gate-and-storage", errors.Join(loss, syscall.ENOSPC), LifecycleFailed},
		{"gate-and-independent-cancellation", errors.Join(loss, &LifecycleIndependentFailure{Err: context.Canceled}), LifecycleFailed},
		{"gate-and-independent-deadline", errors.Join(loss, &LifecycleIndependentFailure{Err: context.DeadlineExceeded}), LifecycleFailed},
		{"gate-and-terminal", errors.Join(loss, ErrSessionEnded), LifecycleFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			result := LifecycleCompletion(ctx, tc.cause)
			if result.Disposition != tc.want || (result.PermitLoss != nil) != (tc.want == LifecycleOvertaken) {
				t.Fatal(result)
			}
		})
	}
}
