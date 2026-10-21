package mountenrollment

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

// Imported Opus r2 N4 serving probe: both ordinary and managed serving
// owners terminate at the safety cutoff when Manager remains unavailable.
func TestManagedServingRetainsSafetyCutoff(t *testing.T) {
	for _, managed := range []bool{false, true} {
		var mu sync.Mutex
		start := time.Unix(1_800_000_000, 0)
		clock := start
		now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
		jump := func(to time.Time) {
			mu.Lock()
			if to.After(clock) {
				clock = to
			}
			mu.Unlock()
		}
		deadline1 := start.Add(10 * time.Minute)
		r := &Renewer{Managed: managed, Now: now, CheckPermit: func(Permit) bool { return true }}
		var refreshes atomic.Int32
		r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
			refreshes.Add(1)
			if n == 1 {
				return grantFor(s, n, deadline1), nil
			}
			return controlplane.MountAuthorization{}, errors.New("Manager mount enrollment refused with HTTP 503")
		})
		var kinds sync.Map
		r.Observe = func(e RenewalEvent) { kinds.Store(e.Kind, true) }
		cutoff := deadline1.Add(-time.Minute)
		var insideMargin []string
		ctx, cancel := context.WithCancel(context.Background())
		r.waitHook = func(c context.Context, target time.Time, wake <-chan struct{}) error {
			if c.Err() != nil {
				return c.Err()
			}
			if target.IsZero() {
				return nil
			}
			jump(target)
			t := now()
			if !t.Before(cutoff) && t.Before(deadline1) {
				insideMargin = append(insideMargin, r.Readiness().State)
			}
			if t.After(deadline1.Add(30 * time.Second)) {
				cancel()
			}
			return nil
		}
		if managed {
			if err := r.Resume(Permit{1, 1}); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() {
			done <- r.Run(ctx, "session", start.Add(5*time.Minute), func(context.Context, string, uint64, []byte) (time.Time, error) {
				return deadline1, nil
			})
		}()
		var err error
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			cancel()
			err = <-done
		}
		_, cut := kinds.Load(RenewalCutoff)
		if err == nil || !cut || !now().Before(cutoff) || r.Readiness().State != "pending" {
			t.Fatal("serving cutoff was not enforced", managed, err, cut, now(), refreshes.Load())
		}
		for _, state := range insideMargin {
			if state != "pending" {
				t.Fatal("serving proof inside withdrawal margin", state)
			}
		}
	}
}

// Imported Opus r2 N4 Resume probe: an installation with two seconds left
// cannot republish readiness inside its sixty-second withdrawal margin.
func TestResumeNearExpiryKeepsReadinessPending(t *testing.T) {
	var clock atomic.Int64
	start := time.Unix(1_800_000_000, 0)
	now := func() time.Time { return start.Add(time.Duration(clock.Load())) }
	var serial atomic.Uint64
	serial.Store(1)
	deadline := start.Add(10 * time.Minute)
	r := &Renewer{Managed: true, Now: now, CheckPermit: func(p Permit) bool { return p.GateSerial == serial.Load() }}
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		if n == 1 {
			return grantFor(s, n, deadline), nil
		}
		return controlplane.MountAuthorization{}, errors.New("transient")
	})
	installed := make(chan struct{}, 1)
	r.Observe = func(e RenewalEvent) {
		if e.Kind == RenewalSucceeded {
			select {
			case installed <- struct{}{}:
			default:
			}
		}
	}
	block := make(chan struct{})
	r.waitHook = func(c context.Context, target time.Time, wake <-chan struct{}) error {
		select {
		case <-wake:
			return nil
		case <-c.Done():
			return c.Err()
		case <-block:
			return nil
		}
	}
	r.Resume(Permit{GateSerial: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "session", start.Add(5*time.Minute), func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil })
	}()
	defer func() { cancel(); await(t, done) }()
	await(t, installed)
	r.Park(context.Background())
	serial.Store(2)
	clock.Store(int64(10*time.Minute - 2*time.Second))
	r.Resume(Permit{GateSerial: 2})
	p := r.Readiness()
	if p.State != "pending" {
		t.Fatal("Resume published inside withdrawal margin", p)
	}
	r.mu.Lock()
	serving, state := r.serving, r.readiness.State
	r.mu.Unlock()
	if serving || state != "pending" {
		t.Fatal("Resume retained serving permission", serving, state)
	}
}

// Readiness must withdraw synchronously even before the scheduling loop wakes.
func TestManagedReadinessWithdrawsAtServingCutoff(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	var elapsed atomic.Int64
	deadline := start.Add(10 * time.Minute)
	r := &Renewer{Managed: true, Now: func() time.Time { return start.Add(time.Duration(elapsed.Load())) }, CheckPermit: func(Permit) bool { return true }}
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		return grantFor(s, n, deadline), nil
	})
	installed := make(chan struct{}, 1)
	waiting, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.scheduleHook = func(_ Permit, next time.Time) {
		if !next.IsZero() {
			once.Do(func() { close(waiting) })
			<-release
		}
	}
	r.Observe = func(e RenewalEvent) {
		if e.Kind == RenewalSucceeded {
			installed <- struct{}{}
		}
	}
	r.waitHook = func(c context.Context, _ time.Time, wake <-chan struct{}) error {
		select {
		case <-c.Done():
			return c.Err()
		case <-wake:
			return nil
		}
	}
	if err := r.Resume(Permit{1, 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "session", deadline, func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil })
	}()
	defer func() { cancel(); close(release); await(t, done) }()
	await(t, installed)
	await(t, waiting)
	elapsed.Store(int64(9*time.Minute - time.Nanosecond))
	if r.Readiness().State != "installed" {
		t.Fatal("withdrew before cutoff")
	}
	elapsed.Store(int64(9 * time.Minute))
	if r.Readiness().State != "pending" {
		t.Fatal("published at serving cutoff")
	}
	if err := r.Resume(Permit{1, 1}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	serving := r.serving
	r.mu.Unlock()
	if !serving {
		t.Fatal("repeated Resume bypassed serving cutoff without Park")
	}
	elapsed.Store(int64(10*time.Minute + time.Second))
	if r.Readiness().State != "pending" {
		t.Fatal("extended serving permission")
	}
}
