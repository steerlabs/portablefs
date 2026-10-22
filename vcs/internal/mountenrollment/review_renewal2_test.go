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

// R1: a managed owner whose permit is current (serving) never reaches the
// ordinary safety cutoff; its installed proof stays "installed" inside the
// safety margin, and no Cutoff/terminal event is ever emitted.
func TestProbeR2ManagedServingHasNoSafetyCutoff(t *testing.T) {
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
		if err == nil || !cut {
			t.Fatalf("serving owner skipped cutoff: %v cutoff=%v", err, cut)
		}
		for _, state := range insideMargin {
			if state != "pending" {
				t.Errorf("readiness inside margin: %s", state)
			}
		}
		t.Logf("managed=%v: Run err=%v cutoffEvent=%v refreshes=%d finalClock=+%v readinessInsideSafetyMargin=%v",
			managed, err, cut, refreshes.Load(), now().Sub(start), insideMargin)
	}
}

// R2: Resume republishes an installed proof that is already inside the
// ordinary safety margin (2 s from its deadline).
func TestProbeR2ResumeRepublishesNearExpiryProof(t *testing.T) {
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
	go r.Run(ctx, "session", start.Add(5*time.Minute), func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil })
	<-installed
	r.Park(context.Background())
	serial.Store(2)
	clock.Store(int64(10*time.Minute - 2*time.Second))
	r.Resume(Permit{GateSerial: 2})
	p := r.Readiness()
	if p.State != "pending" {
		t.Fatalf("near-expiry proof published: %+v", p)
	}
	t.Logf("Resume 2s before deadline: state=%s seq=%d remaining=%v (ordinary cutoff margin is 60s)", p.State, p.InstalledSequence, p.AuthorizationDeadline.Sub(now()))
}

// R3: RefreshNow does not refresh a managed owner with a recorded install.
func TestProbeR2RefreshNowIsNoOpForManaged(t *testing.T) {
	start := time.Now()
	var refreshes atomic.Int32
	deadline := start.Add(time.Hour).Truncate(time.Second)
	r := &Renewer{Managed: true, CheckPermit: func(Permit) bool { return true }}
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		refreshes.Add(1)
		return grantFor(s, n, deadline), nil
	})
	r.Resume(Permit{1, 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, "session", start.Add(5*time.Minute), func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil })
	time.Sleep(100 * time.Millisecond)
	before := refreshes.Load()
	r.RefreshNow()
	time.Sleep(300 * time.Millisecond)
	if before != 1 || refreshes.Load() != before {
		t.Fatalf("managed refresh bypassed schedule: before=%d after=%d", before, refreshes.Load())
	}
	t.Logf("RefreshNow on managed owner: refreshes before=%d after=%d", before, refreshes.Load())
}
