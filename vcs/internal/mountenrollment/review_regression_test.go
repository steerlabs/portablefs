package mountenrollment

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

// Astra P1-1: an unknown remote install must remain reachable after both the
// old safety cutoff and the old authorization deadline, with identical bytes.
func TestManagedPendingRecoveryCrossesOldDeadline(t *testing.T) {
	for _, elapsed := range []time.Duration{56 * time.Second, 70 * time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			start := time.Now().Truncate(time.Second)
			var clock atomic.Int64
			now := func() time.Time { return start.Add(time.Duration(clock.Load())) }
			grantDeadline := start.Add(5 * time.Minute)
			var serial atomic.Uint64
			serial.Store(1)
			var refreshes, installs atomic.Int32
			entered := make(chan struct{})
			succeeded := make(chan struct{}, 1)
			r := &Renewer{Managed: true, Now: now, CheckPermit: func(p Permit) bool { return p.GateSerial == serial.Load() }}
			r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
				refreshes.Add(1)
				return grantFor(s, n, grantDeadline), nil
			})
			r.Observe = func(e RenewalEvent) {
				if e.Kind == RenewalSucceeded {
					succeeded <- struct{}{}
				}
			}
			if err := r.Resume(Permit{GateSerial: 1}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- r.Run(ctx, "session", start.Add(time.Minute), func(c context.Context, body string, n uint64, cert []byte) (time.Time, error) {
					if n != 1 || body != "exact-grant" || string(cert) != "exact-cert" {
						t.Error("pending grant changed")
					}
					if installs.Add(1) == 1 {
						close(entered)
						<-c.Done()
						return time.Time{}, errors.New("unknown remote outcome")
					}
					return grantDeadline, nil
				})
			}()
			await(t, entered)
			if err := r.Park(context.Background()); err != nil {
				t.Fatal(err)
			}
			serial.Store(2)
			clock.Store(int64(elapsed))
			if err := r.Resume(Permit{GateSerial: 2}); err != nil {
				t.Fatal(err)
			}
			await(t, succeeded)
			proof := r.Readiness()
			if installs.Load() != 2 || refreshes.Load() != 1 || !proof.Ready(false, Permit{GateSerial: 2}, "session", grantDeadline) {
				t.Fatal(installs.Load(), refreshes.Load(), proof)
			}
			cancel()
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagedTransientRecoveryOutlivesOldCutoff(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	now := start
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Renewer{Managed: true, Now: func() time.Time { return now }, CheckPermit: func(Permit) bool { return true }}
	r.waitHook = func(_ context.Context, target time.Time, _ <-chan struct{}) error { now = target; return nil }
	deadline := start.Add(5 * time.Minute)
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		calls++
		if now.Before(start.Add(70 * time.Second)) {
			return controlplane.MountAuthorization{}, errors.New("temporary unavailable")
		}
		return grantFor(s, n, deadline), nil
	})
	r.Observe = func(e RenewalEvent) {
		if e.Kind == RenewalSucceeded {
			cancel()
		}
	}
	if err := r.Run(ctx, "session", start.Add(time.Minute), func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil }); err != nil {
		t.Fatal(err)
	}
	if calls < 8 || now.Before(start.Add(70*time.Second)) {
		t.Fatal("recovery ended before injected old deadline", calls, now)
	}
}

// Astra P1-2: terminalization, not observer completion, withdraws readiness.
func TestTerminalOwnerInvalidatesReadinessBeforeObserver(t *testing.T) {
	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Renewer{}
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		if n > 1 {
			return controlplane.MountAuthorization{}, ErrDefinitiveDenial
		}
		return grantFor(s, n, deadline), nil
	})
	denied, release := make(chan struct{}), make(chan struct{})
	r.Observe = func(e RenewalEvent) {
		if e.Kind == RenewalSucceeded {
			r.RefreshNow()
		}
		if e.Kind == RenewalDenied {
			close(denied)
			<-release
		}
	}
	done := make(chan error, 1)
	install := func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil }
	go func() { done <- r.Run(ctx, "session", deadline, install) }()
	await(t, denied)
	if r.Readiness().State != "pending" {
		t.Error("terminal owner returned installed readiness")
	}
	if err := r.Resume(Permit{}); !errors.Is(err, ErrDefinitiveDenial) {
		t.Error(err)
	}
	if err := r.Run(ctx, "session", deadline, install); !errors.Is(err, ErrDefinitiveDenial) {
		t.Error(err)
	}
	close(release)
	if err := await(t, done); !errors.Is(err, ErrDefinitiveDenial) {
		t.Fatal(err)
	}
}

// Imported Opus zz_probe_test.go: a two-minute suspension of a one-hour grant
// must republish readiness immediately, without any rate-limited Manager call.
func TestResumeReusesInstalledGrantWithoutManagerConflict(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	var elapsed atomic.Int64
	now := func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
	var serial atomic.Uint64
	serial.Store(1)
	var refreshes, conflicts atomic.Int32
	deadline := start.Add(time.Hour)
	r := &Renewer{Managed: true, Now: now, CheckPermit: func(p Permit) bool { return p.GateSerial == serial.Load() }}
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		if n > 1 && now().Before(start.Add(15*time.Minute)) {
			conflicts.Add(1)
			return controlplane.MountAuthorization{}, errors.New("HTTP 409")
		}
		refreshes.Add(1)
		return grantFor(s, n, deadline), nil
	})
	// Block and acknowledge the scheduling decision for permit 2 itself. Old
	// wait notifications cannot satisfy this barrier, and an early Manager call
	// is a test failure even if Run has not dispatched it yet.
	initial, initialRelease := make(chan struct{}), make(chan struct{})
	initialSeen := false
	decision, release := make(chan time.Time, 1), make(chan struct{})
	r.scheduleHook = func(p Permit, next time.Time) {
		if p.GateSerial == 1 && !next.IsZero() && !initialSeen {
			initialSeen = true
			close(initial)
			<-initialRelease
		}
		if p.GateSerial == 2 {
			decision <- next
			<-release
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
	success := make(chan struct{}, 1)
	r.Observe = func(e RenewalEvent) {
		if e.Kind == RenewalSucceeded {
			success <- struct{}{}
		}
	}
	if err := r.Resume(Permit{GateSerial: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "session", deadline, func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil })
	}()
	await(t, success)
	await(t, initial)
	if err := r.Park(context.Background()); err != nil {
		t.Fatal(err)
	}
	serial.Store(2)
	elapsed.Store(int64(2 * time.Minute))
	if err := r.Resume(Permit{GateSerial: 2}); err != nil {
		t.Fatal(err)
	}
	r.RefreshNow()
	close(initialRelease)
	proof := r.Readiness()
	if !proof.Ready(false, Permit{GateSerial: 2}, "session", deadline) {
		t.Fatal(proof)
	}
	next := await(t, decision)
	if next.Before(start.Add(15 * time.Minute)) {
		t.Error("managed wake bypassed the Manager refresh schedule", next)
	}
	if refreshes.Load() != 1 || conflicts.Load() != 0 {
		t.Fatal("Resume forced a rate-limited refresh", refreshes.Load(), conflicts.Load())
	}
	cancel()
	close(release)
	await(t, done)
}

func TestStandaloneReadinessJSONContainsOnlyEvidence(t *testing.T) {
	raw, err := json.Marshal(RenewalReadiness{State: "not-required"})
	if err != nil || string(raw) != `{"state":"not-required"}` {
		t.Fatal(string(raw), err)
	}
}
