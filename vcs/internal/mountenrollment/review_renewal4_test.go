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

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Jump(to time.Time) {
	c.mu.Lock()
	if to.After(c.now) {
		c.now = to
	}
	c.mu.Unlock()
}

// R3-R1: a serving managed owner that reaches its cutoff latches terminal.
// Park/Resume can no longer move it into closed recovery.
func TestR3ServingCutoffIsPermanentForManagedOwner(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	clock := &fakeClock{now: start}
	deadline1 := start.Add(10 * time.Minute)
	var serial atomic.Uint64
	serial.Store(1)
	r := &Renewer{Managed: true, Now: clock.Now, CheckPermit: func(p Permit) bool { return p.GateSerial == serial.Load() }}
	var managerUp atomic.Bool
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		if n == 1 || managerUp.Load() {
			return grantFor(s, n, clock.Now().Add(10*time.Minute).Truncate(time.Second)), nil
		}
		return controlplane.MountAuthorization{}, errors.New("Manager mount enrollment refused with HTTP 503")
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.waitHook = func(c context.Context, target time.Time, wake <-chan struct{}) error {
		if c.Err() != nil {
			return c.Err()
		}
		if target.IsZero() {
			select {
			case <-wake:
				return nil
			case <-c.Done():
				return c.Err()
			case <-time.After(200 * time.Millisecond):
				return nil
			}
		}
		clock.Jump(target)
		return nil
	}
	if err := r.Resume(Permit{GateSerial: 1}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "session", start.Add(5*time.Minute), func(_ context.Context, _ string, _ uint64, _ []byte) (time.Time, error) {
			return clock.Now().Add(10 * time.Minute).Truncate(time.Second), nil
		})
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serving owner did not reach cutoff")
	}
	_ = deadline1
	managerUp.Store(true)
	parkErr := r.Park(context.Background())
	serial.Store(2)
	resumeErr := r.Resume(Permit{GateSerial: 2})
	runErr := r.Run(ctx, "session", time.Time{}, func(context.Context, string, uint64, []byte) (time.Time, error) { return time.Time{}, nil })
	if err == nil || resumeErr == nil || runErr == nil || r.Readiness().State != "pending" {
		t.Fatalf("cutoff revived: run=%v resume=%v rerun=%v", err, resumeErr, runErr)
	}
	t.Logf("R3-R1: serving Run -> %v at +%v; after Manager recovery: Park=%v Resume=%v Run=%v", err, clock.Now().Sub(start), parkErr, resumeErr, runErr)
}

// R3-R2: Readiness gates on r.installed but returns r.readiness. A known
// installation that is not published (session-changed obsolete result under
// a still-current permit) leaves the previous proof published; it is then
// returned after its own deadline.
func TestR3ReadinessReturnsStaleProofAfterObsoleteInstall(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	clock := &fakeClock{now: start}
	window := 10 * time.Minute
	r := &Renewer{Managed: true, Now: clock.Now, CheckPermit: func(Permit) bool { return true }}
	var grants sync.Map
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		if n > 2 {
			return controlplane.MountAuthorization{}, errors.New("Manager mount enrollment refused with HTTP 503")
		}
		d := clock.Now().Add(window).Truncate(time.Second)
		grants.Store(n, d)
		return grantFor(s, n, d), nil
	})
	var observed []string
	var firstDeadline time.Time
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.waitHook = func(c context.Context, target time.Time, wake <-chan struct{}) error {
		if c.Err() != nil {
			return c.Err()
		}
		if target.IsZero() {
			return nil
		}
		clock.Jump(target)
		if !firstDeadline.IsZero() && clock.Now().After(firstDeadline) {
			p := r.Readiness()
			if p.State != "pending" {
				t.Errorf("obsolete installation returned proof: %+v", p)
			}
			r.mu.Lock()
			seq := r.installed.InstalledSequence
			r.mu.Unlock()
			if seq != 2 {
				t.Errorf("lost remote installation: %d", seq)
			}
			observed = append(observed, p.State+" seq="+itoa(p.InstalledSequence)+" deadlinePassed="+boolStr(!p.AuthorizationDeadline.IsZero() && !p.AuthorizationDeadline.After(clock.Now())))
			cancel()
		}
		return nil
	}
	if err := r.Resume(Permit{GateSerial: 1}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "session", start.Add(5*time.Minute), func(_ context.Context, _ string, seq uint64, _ []byte) (time.Time, error) {
			v, _ := grants.Load(seq)
			d := v.(time.Time)
			if seq == 1 {
				firstDeadline = d
				return d, nil
			}
			return d, ErrObsoleteInstallation // authorization session changed during install
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
	}
	if len(observed) == 0 {
		t.Fatal("probe never crossed first proof deadline")
	}
	t.Logf("REPRO R3-R2: Readiness after first proof's deadline passed: %v (first deadline +%v)", observed, firstDeadline.Sub(start))
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// R3-R3: Park/Resume/time stress. Invariant: whenever Readiness() reports
// installed, the returned proof is outside its own safety margin.
func TestR3ParkResumeStressReadinessNeverInsideMargin(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	clock := &fakeClock{now: start}
	var serial atomic.Uint64
	serial.Store(1)
	r := &Renewer{Managed: true, Now: clock.Now, CheckPermit: func(p Permit) bool { return p.GateSerial == serial.Load() }}
	var n atomic.Int64
	var granted sync.Map
	r.Source = sourceFunc(func(_ context.Context, s string, seq uint64) (controlplane.MountAuthorization, error) {
		if n.Add(1)%3 == 0 {
			return controlplane.MountAuthorization{}, errors.New("transient")
		}
		d := clock.Now().Add(2 * time.Minute).Truncate(time.Second)
		granted.Store(seq, d)
		return grantFor(s, seq, d), nil
	})
	r.waitHook = func(c context.Context, target time.Time, wake <-chan struct{}) error {
		select {
		case <-wake:
			return nil
		case <-c.Done():
			return c.Err()
		case <-time.After(time.Millisecond):
		}
		if !target.IsZero() {
			clock.Jump(target)
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	_ = r.Resume(Permit{GateSerial: 1})
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "session", start.Add(time.Minute), func(_ context.Context, _ string, seq uint64, _ []byte) (time.Time, error) {
			v, _ := granted.Load(seq)
			return v.(time.Time), nil
		})
	}()
	violations := 0
	stop := time.After(2 * time.Second)
loop:
	for i := 0; ; i++ {
		select {
		case <-stop:
			break loop
		case err := <-done:
			t.Logf("Run returned early: %v", err)
			done <- err
			break loop
		default:
		}
		switch i % 7 {
		case 0:
			_ = r.Park(context.Background())
			serial.Add(1)
			_ = r.Resume(Permit{GateSerial: serial.Load()})
		case 3:
			clock.Jump(clock.Now().Add(7 * time.Second))
		case 5:
			r.RefreshNow()
		}
		before := clock.Now()
		p := r.Readiness()
		if p.State == "installed" {
			// proof margin: window/10 bounded to [5s, 60s]; 2-minute windows give 12s
			if !before.Before(p.AuthorizationDeadline.Add(-5 * time.Second)) {
				violations++
			}
		}
		time.Sleep(50 * time.Microsecond)
	}
	cancel()
	<-done
	t.Logf("R3-R3: readiness violations inside minimum margin: %d", violations)
	if violations != 0 {
		t.Errorf("Readiness returned a proof inside its safety margin %d times", violations)
	}
}

func TestReadinessValidatesTheExactPublishedProof(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, field := range []string{"valid", "sequence", "session", "permit", "deadline", "state", "expired"} {
		t.Run(field, func(t *testing.T) {
			p := Permit{1, 1}
			deadline := now.Add(time.Hour)
			proof := RenewalReadiness{State: "installed", InstalledSequence: 2, Permit: p, SessionID: "session", AuthorizationDeadline: deadline}
			r := &Renewer{Managed: true, running: true, session: "session", permit: p, installed: proof, readiness: proof, installedPublishable: true, deadline: deadline, authorizedAt: now, Now: func() time.Time { return now }, CheckPermit: func(Permit) bool { return true }}
			switch field {
			case "sequence":
				r.readiness.InstalledSequence = 1
			case "session":
				r.readiness.SessionID = "foreign"
			case "permit":
				r.readiness.Permit.GateSerial = 2
			case "deadline":
				r.readiness.AuthorizationDeadline = deadline.Add(time.Hour)
			case "state":
				r.readiness.State = "pending"
			case "expired":
				r.readiness.AuthorizationDeadline = now.Add(-time.Second)
			}
			got := r.Readiness()
			if (got.State == "installed") != (field == "valid") {
				t.Fatalf("exact proof validation for %s: %+v", field, got)
			}
		})
	}
}
