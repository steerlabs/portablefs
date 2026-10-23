package workspaceclock

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
)

func TestTLSCleanupAndBackgroundContextsAwaitOwnerClock(t *testing.T) {
	o, _, _ := clockFixture(t)
	if _, err := o.Measure(); err != nil {
		t.Fatal(err)
	}
	var generation, serial atomic.Uint64
	serial.Store(1)
	b := Binding{Owner: o, Generation: generation.Load, Current: func(p mountenrollment.Permit) bool {
		return p.Generation == generation.Load() && p.GateSerial == serial.Load()
	}}
	p := mountenrollment.Permit{GateSerial: 1}
	serial.Store(2) // Close defeats serving, but cleanup still owns the clock.
	if !errors.Is(b.Check(p), ErrObsolete) {
		t.Fatal("Close retained serving permission")
	}
	for _, ctx := range []context.Context{context.Background(), mountenrollment.WithPermit(context.Background(), p)} {
		if err := b.AwaitTLS(ctx); err != nil {
			t.Fatal("ready clock refused receipt/cleanup", err)
		}
	}
	o.Pause()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- b.AwaitTLS(ctx) }()
	select {
	case err := <-done:
		t.Fatal("cleanup bypassed paused clock", err)
	case <-time.After(10 * time.Millisecond):
	}
	generation.Store(1)
	if err := o.Begin(1); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatal("cleanup bypassed unmeasured generation", err)
	case <-time.After(10 * time.Millisecond):
	}
	if _, err := o.Measure(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	o.Pause()
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if !errors.Is(b.AwaitTLS(canceled), context.Canceled) {
		t.Fatal("cancellation bypassed clock")
	}
}
