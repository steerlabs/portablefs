package workspaceclock

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
)

type backend struct {
	mu               sync.Mutex
	rtc, wall        time.Time
	elapsed, latency time.Duration
	readErr, setErr  error
	sets             int
	noSet            bool
	readHook         func()
}

func (b *backend) ReadUTC() (time.Time, error) {
	if b.readHook != nil {
		b.readHook()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.elapsed += b.latency
	return b.rtc, b.readErr
}
func (b *backend) CorrectWall(t time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sets++
	if !b.noSet {
		b.wall = t
	}
	return b.setErr
}
func (b *backend) Wall() time.Time        { b.mu.Lock(); defer b.mu.Unlock(); return b.wall }
func (b *backend) Elapsed() time.Duration { b.mu.Lock(); defer b.mu.Unlock(); return b.elapsed }
func (b *backend) Close() error           { return nil }
func clockFixture(t *testing.T) (*Owner, *backend, *atomic.Int32) {
	t.Helper()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	b := &backend{rtc: now, wall: now.Add(-time.Hour)}
	closed := new(atomic.Int32)
	o := New(b, func() { closed.Add(1) })
	if err := o.Begin(0); err != nil {
		t.Fatal(err)
	}
	return o, b, closed
}
func TestClockIntervalCorrectionAndSynchronousFreshness(t *testing.T) {
	o, b, closed := clockFixture(t)
	m, err := o.Measure()
	if err != nil || m.Correction == 0 || b.sets != 1 {
		t.Fatalf("correction: %+v %v", m, err)
	}
	if err = o.Check(0); err != nil {
		t.Fatal(err)
	}
	if _, err = o.Measure(); err != nil || b.sets != 1 {
		t.Fatal("stepped a qualified uncertainty interval", err)
	}
	b.mu.Lock()
	b.elapsed += MaxMeasurementInterval
	b.wall = b.wall.Add(MaxMeasurementInterval)
	b.rtc = b.rtc.Add(MaxMeasurementInterval)
	b.mu.Unlock()
	if !errors.Is(o.Check(0), ErrUnavailable) || closed.Load() != 1 {
		t.Fatal("delayed maintenance retained readiness")
	}
	if _, err = o.Measure(); err != nil {
		t.Fatal(err)
	}
	if err = o.Check(0); err != nil {
		t.Fatal(err)
	}
}
func TestClockFailuresClearReadinessAndRecover(t *testing.T) {
	for _, name := range []string{"read", "set", "malformed", "fraction", "age", "ineffective-set", "drift", "elapsed"} {
		t.Run(name, func(t *testing.T) {
			o, b, closed := clockFixture(t)
			if _, err := o.Measure(); err != nil {
				t.Fatal(err)
			}
			b.mu.Lock()
			switch name {
			case "read":
				b.readErr = errors.New("read")
			case "set":
				b.wall = b.wall.Add(time.Hour)
				b.setErr = errors.New("set")
			case "malformed":
				b.rtc = time.Time{}
			case "fraction":
				b.rtc = b.rtc.Add(time.Nanosecond)
			case "age":
				b.latency = MaxSampleAge + 1
			case "ineffective-set":
				b.wall = b.wall.Add(time.Hour)
				b.noSet = true
			case "drift":
				b.wall = b.wall.Add(4 * time.Second)
			case "elapsed":
				b.elapsed = -1
			}
			b.mu.Unlock()
			if name == "drift" {
				if o.Check(0) == nil {
					t.Fatal("unbounded wall drift retained readiness")
				}
			} else {
				_, err := o.Measure()
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal(err)
				}
				if name == "read" && !errors.Is(err, b.readErr) {
					t.Fatal("shared clock read cause lost", err)
				}
			}
			o.mu.Lock()
			stillReady := o.ready
			o.mu.Unlock()
			if stillReady || closed.Load() != 1 || o.Check(0) == nil {
				t.Fatal("failure did not close readiness exactly once")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if o.Wait(ctx, 0) == nil {
				t.Fatal("cancellation bypassed readiness")
			}
		})
	}
}
func TestClockGenerationSerialAndDelayedCorrection(t *testing.T) {
	o, b, _ := clockFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	b.readHook = func() { close(entered); <-release }
	done := make(chan error, 1)
	go func() { _, err := o.Measure(); done <- err }()
	<-entered
	o.Pause()
	if err := o.Begin(1); err != nil {
		t.Fatal(err)
	}
	close(release)
	if !errors.Is(<-done, ErrObsolete) {
		t.Fatal("late correction published for a new generation")
	}
	b.readHook = nil
	if o.Check(1) == nil {
		t.Fatal("new generation borrowed old readiness")
	}
	if _, err := o.Measure(); err != nil {
		t.Fatal(err)
	}
	var serial atomic.Uint64
	serial.Store(2)
	bound := Binding{Owner: o, Generation: func() uint64 { return 1 }, Current: func(p mountenrollment.Permit) bool { return p.Generation == 1 && p.GateSerial == serial.Load() }}
	p := mountenrollment.Permit{Generation: 1, GateSerial: 2}
	if err := bound.Wait(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	serial.Store(3)
	if !errors.Is(bound.Check(p), ErrObsolete) {
		t.Fatal("repeated Close released obsolete work")
	}
	if err := bound.AwaitTLS(t.Context()); err != nil {
		t.Fatal("ready clock refused cleanup after Close", err)
	}
}
func TestClockAllMountsShareCorrectionAndWaitCancellation(t *testing.T) {
	o, _, _ := clockFixture(t)
	done := make(chan error, 64)
	for i := 0; i < 64; i++ {
		go func() { done <- o.Wait(t.Context(), 0) }()
	}
	if _, err := o.Measure(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	o.Pause()
	if o.Check(0) == nil {
		t.Fatal("pause retained readiness")
	}
	if err := o.Begin(1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	go func() { done <- o.Wait(ctx, 1) }()
	cancel()
	if !errors.Is(<-done, context.Canceled) {
		t.Fatal("wait did not cancel")
	}
}
