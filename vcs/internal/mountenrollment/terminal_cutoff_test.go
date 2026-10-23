package mountenrollment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

// A Manager attempt deadline becomes an independent terminal renewal verdict
// at the serving cutoff, while the lifecycle owner's context is still live.
func TestManagedRenewalRetainsDeadlineCutoff(t *testing.T) {
	start := time.Now().Truncate(time.Second).Add(time.Minute)
	clock := &fakeClock{now: start}
	deadline := start.Add(10 * time.Minute)
	r := &Renewer{Managed: true, Now: clock.Now, CheckPermit: func(Permit) bool { return true }}
	r.Source = sourceFunc(func(_ context.Context, session string, sequence uint64) (controlplane.MountAuthorization, error) {
		if sequence == 1 {
			return grantFor(session, sequence, deadline), nil
		}
		return controlplane.MountAuthorization{}, context.DeadlineExceeded
	})
	r.waitHook = func(ctx context.Context, target time.Time, _ <-chan struct{}) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		clock.Jump(target)
		return nil
	}
	permit := Permit{Generation: 2, GateSerial: 3}
	if err := r.Resume(permit); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := r.Run(ctx, "session", start.Add(5*time.Minute), func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil })
	if err == nil || r.Failure() != err || !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatal("renewal did not retain its independent cutoff", err, r.Failure(), ctx.Err())
	}
	if parkErr := r.Park(ctx); parkErr != nil {
		t.Fatal("completed renewal owner did not join", parkErr)
	}
	if r.Failure() != err || r.Resume(permit) != err {
		t.Fatal("parking or resuming erased the terminal cutoff", r.Failure())
	}
}
