package mountenrollment

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

func TestParkBeforeCutoffKeepsSameOwnerRecoverable(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	clock := &fakeClock{now: start}
	installed := make(chan RenewalEvent, 4)
	r := &Renewer{Managed: true, Now: clock.Now, CheckPermit: func(Permit) bool { return true }}
	r.Source = sourceFunc(func(_ context.Context, session string, sequence uint64) (controlplane.MountAuthorization, error) {
		return grantFor(session, sequence, clock.Now().Add(time.Minute)), nil
	})
	r.Observe = func(e RenewalEvent) {
		if e.Kind == RenewalSucceeded {
			installed <- e
		}
	}
	r.waitHook = func(ctx context.Context, _ time.Time, wake <-chan struct{}) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
			return nil
		}
	}
	if !r.ParkBefore().IsZero() {
		t.Fatal("uninitialized owner invented a cutoff")
	}
	if err := r.Resume(Permit{Generation: 1, GateSerial: 2}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "same-session", start.Add(time.Minute), func(_ context.Context, _ string, _ uint64, _ []byte) (time.Time, error) {
			return clock.Now().Add(time.Minute), nil
		})
	}()
	defer func() { cancel(); <-done }()
	first := await(t, installed)
	boundary := r.ParkBefore()
	if !boundary.After(start) || !boundary.Before(first.Status.AuthorizationDeadline.Add(-5*time.Second)) {
		t.Fatal("driver has no time to park before the existing safety cutoff", boundary, first)
	}
	clock.Jump(boundary)
	if r.Readiness().State != "installed" {
		t.Fatal("parking boundary already latched terminal cutoff")
	}
	if err := r.Park(t.Context()); err != nil {
		t.Fatal(err)
	}
	clock.Jump(start.Add(2 * time.Minute))
	r.WallCorrected()
	if r.Failure() != nil || r.Readiness().State != "pending" {
		t.Fatal("parked owner applied the old serving cutoff", r.Failure())
	}
	if err := r.Resume(Permit{Generation: 2, GateSerial: 4}); err != nil {
		t.Fatal("fresh closed recovery could not resume the same owner", err)
	}
	second := await(t, installed)
	if second.Status.Sequence != 2 || second.Status.Readiness.InstalledSequence != 2 || second.Status.Readiness.SessionID != "same-session" || r.Failure() != nil {
		t.Fatal("recovery changed renewal ownership or sequence", second)
	}
}
