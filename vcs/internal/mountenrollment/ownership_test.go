package mountenrollment

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"sync/atomic"
	"testing"
	"time"
)

type sourceFunc func(context.Context, string, uint64) (controlplane.MountAuthorization, error)

func (f sourceFunc) Refresh(c context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
	return f(c, s, n)
}
func grantFor(s string, n uint64, deadline time.Time) controlplane.MountAuthorization {
	return controlplane.MountAuthorization{SessionID: s, Sequence: n, Capability: "exact-grant", ClientCertificatePEM: "exact-cert", ExpiresUnix: deadline.Unix()}
}
func await[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("owner did not progress")
		var z T
		return z
	}
}
func TestRenewalReadinessRequiresExplicitEvidence(t *testing.T) {
	now := time.Now()
	p := Permit{4, 7}
	for _, tc := range []struct {
		name, state      string
		seq              uint64
		standalone, want bool
	}{
		{"pending", "pending", 0, false, false}, {"zero", "installed", 0, false, false}, {"hosted", "installed", 1, false, true}, {"standalone", "not-required", 0, true, true}, {"hosted-refusal", "not-required", 0, false, false}, {"standalone-sequence", "not-required", 1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := RenewalReadiness{State: tc.state, InstalledSequence: tc.seq, Permit: p, SessionID: "session", AuthorizationDeadline: now}
			if r.Ready(tc.standalone, p, "session", now) != tc.want {
				t.Fatal(r)
			}
			if r.Ready(tc.standalone, Permit{4, 8}, "session", now) {
				t.Fatal("stale serial usable")
			}
		})
	}
}
func TestRenewerParkRetainsExactUnknownGrantAndSequence(t *testing.T) {
	deadline := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	var refreshes, installs atomic.Int32
	current := atomic.Uint64{}
	current.Store(1)
	entered := make(chan uint64, 3)
	release := make(chan struct{})
	succeeded := make(chan RenewalEvent, 3)
	r := &Renewer{Managed: true, CheckPermit: func(p Permit) bool { return p.Generation == 9 && p.GateSerial == current.Load() }}
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		refreshes.Add(1)
		return grantFor(s, n, deadline), nil
	})
	r.Observe = func(e RenewalEvent) {
		if e.Kind == RenewalSucceeded {
			succeeded <- e
		}
	}
	if err := r.Resume(Permit{9, 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "session", deadline, func(c context.Context, body string, n uint64, cert []byte) (time.Time, error) {
			call := installs.Add(1)
			if body != "exact-grant" || string(cert) != "exact-cert" {
				t.Error("grant changed")
			}
			entered <- n
			if call == 1 {
				<-release
				return time.Time{}, errors.New("unknown remote result")
			}
			return deadline, nil
		})
	}()
	if await(t, entered) != 1 {
		t.Fatal("initial sequence")
	}
	parked := make(chan error, 1)
	go func() { parked <- r.Park(context.Background()) }()
	// Park cannot acknowledge before the uncooperative installer actually joins.
	r.mu.Lock()
	inflight := r.attemptDone
	r.mu.Unlock()
	if inflight == nil {
		t.Fatal("lost installation owner")
	}
	close(release)
	if err := await(t, parked); err != nil {
		t.Fatal(err)
	}
	if r.Readiness().State != "pending" {
		t.Fatal("parked proof")
	}
	current.Store(2)
	if err := r.Resume(Permit{9, 1}); err == nil {
		t.Fatal("stale resume")
	}
	if err := r.Resume(Permit{9, 2}); err != nil {
		t.Fatal(err)
	}
	r.RefreshNow()
	if await(t, entered) != 1 {
		t.Fatal("unknown sequence was reset/advanced")
	}
	e := await(t, succeeded)
	if e.Status.Readiness.Permit != (Permit{9, 2}) || refreshes.Load() != 1 {
		t.Fatalf("grant was refreshed instead of reconciled: %+v, calls=%d", e, refreshes.Load())
	}
	r.RefreshNow()
	if await(t, entered) != 2 {
		t.Fatal("accepted sequence reset to one")
	}
	await(t, succeeded)
	cancel()
	await(t, done)
	if r.Readiness().State != "pending" {
		t.Fatal("stopped owner usable")
	}
}
func TestRenewerCloseAtEveryInstallationBoundary(t *testing.T) {
	for _, point := range []string{"source", "before-installer", "remote-success"} {
		t.Run(point, func(t *testing.T) {
			deadline := time.Now().Add(3 * time.Minute).Truncate(time.Second)
			var current atomic.Uint64
			current.Store(1)
			var installs atomic.Int32
			r := &Renewer{Managed: true, CheckPermit: func(p Permit) bool { return p.GateSerial == current.Load() }}
			r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
				if point == "source" {
					current.Store(2)
				}
				return grantFor(s, n, deadline), nil
			})
			if err := r.Resume(Permit{GateSerial: 1}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- r.Run(ctx, "session", deadline, func(context.Context, string, uint64, []byte) (time.Time, error) {
					if point == "before-installer" {
						current.Store(2)
						return time.Time{}, errors.New("installer permit refused")
					}
					installs.Add(1)
					current.Store(2)
					return deadline, nil
				})
			}()
			// The invalid permit parks dispatch. Joining Park synchronizes source and
			// result recording without relying on scheduler delay.
			for {
				r.mu.Lock()
				pending, seq := r.pending, r.sequence
				r.mu.Unlock()
				if point != "remote-success" && pending != nil || seq == 2 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if err := r.Park(context.Background()); err != nil {
				t.Fatal(err)
			}
			if r.Readiness().State != "pending" {
				t.Fatal("obsolete readiness")
			}
			if point != "remote-success" && installs.Load() != 0 {
				t.Fatal("stale installer dispatched")
			}
			r.mu.Lock()
			seq := r.sequence
			r.mu.Unlock()
			if point == "remote-success" && seq != 2 {
				t.Fatal("remote success forgotten")
			}
			cancel()
			await(t, done)
		})
	}
}
func TestRenewerDeadlineMismatchNeverPublishesReady(t *testing.T) {
	for _, offset := range []time.Duration{time.Nanosecond, time.Second, -time.Minute} {
		t.Run(offset.String(), func(t *testing.T) {
			deadline := time.Now().Add(2 * time.Minute).Truncate(time.Second)
			r := &Renewer{Source: sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
				return grantFor(s, n, deadline), nil
			})}
			err := r.Run(context.Background(), "session", deadline, func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline.Add(offset), nil })
			if err == nil || r.Readiness().State != "pending" {
				t.Fatal("unequal deadline ready")
			}
			r.mu.Lock()
			seq := r.sequence
			r.mu.Unlock()
			if seq != 2 {
				t.Fatal("known remote sequence forgotten")
			}
		})
	}
}
func TestRenewerTransientLogicalOutageExceeds45Seconds(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	now := start
	calls := 0
	deadline := start.Add(3 * time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Renewer{Now: func() time.Time { return now }}
	r.waitHook = func(_ context.Context, target time.Time, _ <-chan struct{}) error { now = target; return nil }
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		calls++
		if calls <= 7 {
			return controlplane.MountAuthorization{}, errors.New("transient outage")
		}
		return grantFor(s, n, deadline), nil
	})
	r.Observe = func(e RenewalEvent) {
		if e.Kind == RenewalSucceeded {
			if now.Sub(start) <= 45*time.Second {
				t.Error("outage fixture too short")
			}
			cancel()
		}
	}
	if err := r.Run(ctx, "session", deadline, func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 8 {
		t.Fatal(calls)
	}
}

func TestRenewerRefusesMalformedGrantBeforeInstaller(t *testing.T) {
	for _, field := range []string{"sequence", "session", "deadline"} {
		t.Run(field, func(t *testing.T) {
			deadline := time.Now().Add(time.Minute).Truncate(time.Second)
			r := &Renewer{Source: sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
				grant := grantFor(s, n, deadline)
				switch field {
				case "sequence":
					grant.Sequence = 0
				case "session":
					grant.SessionID = "other"
				case "deadline":
					grant.ExpiresUnix = 0
				}
				return grant, nil
			})}
			calls := 0
			err := r.Run(context.Background(), "session", deadline, func(context.Context, string, uint64, []byte) (time.Time, error) { calls++; return deadline, nil })
			if err == nil || calls != 0 || r.Readiness().State != "pending" {
				t.Fatal("malformed grant installed", err, calls)
			}
		})
	}
}

func TestRenewerRetainsKnownObsoleteInstallationWithoutReady(t *testing.T) {
	deadline := time.Now().Add(time.Minute).Truncate(time.Second)
	var serial atomic.Uint64
	serial.Store(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Renewer{Managed: true, CheckPermit: func(p Permit) bool { return p.GateSerial == serial.Load() }, Source: sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		return grantFor(s, n, deadline), nil
	})}
	if err := r.Resume(Permit{GateSerial: 1}); err != nil {
		t.Fatal(err)
	}
	err := r.Run(ctx, "session", deadline, func(context.Context, string, uint64, []byte) (time.Time, error) {
		serial.Store(2)
		cancel()
		return deadline, ErrObsoleteInstallation
	})
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	sequence, pending := r.sequence, r.pending
	r.mu.Unlock()
	if sequence != 2 || pending != nil || r.Readiness().State != "pending" {
		t.Fatal("obsolete remote success forgotten", sequence, pending)
	}
}
