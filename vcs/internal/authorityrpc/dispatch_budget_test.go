package authorityrpc

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestDispatchTimeoutStartsAfterReadiness(t *testing.T) {
	for _, budget := range []time.Duration{10 * time.Second, 45 * time.Second} {
		t.Run(budget.String(), func(t *testing.T) {
			h := &lifecycleVisibilityHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, started: make(chan struct{}), release: make(chan struct{})}
			close(h.release)
			address, tls, stop := startTestServer(t, h, testMaxInFlight, time.Minute)
			defer stop()
			cfg := coherentTestClientConfig(address, tls, "volume", 9, 9)
			cfg.AwaitTLS = func(context.Context) error { return nil } // Explicit test clock.
			cfg.DispatchFence = NewDispatchFence()
			var unavailable atomic.Bool
			checked := make(chan struct{})
			var checkOnce sync.Once
			check := func() error {
				if unavailable.Load() {
					checkOnce.Do(func() { close(checked) })
					return context.DeadlineExceeded
				}
				return nil
			}
			if err := cfg.DispatchFence.Resume(check); err != nil {
				t.Fatal(err)
			}
			client, err := DialClient(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			unavailable.Store(true)
			done := make(chan error, 1)
			go func() {
				r, err := client.CallIdempotent(WithDispatchTimeout(t.Context(), budget), &authoritypb.Request{Body: &authoritypb.Request_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityRequest{CutSequence: 23}}})
				if err == nil && r.GetWaitVisibility().GetVisibleSequence() != 23 {
					err = ErrTransportBinding
				}
				done <- err
			}()
			<-checked
			timer := time.NewTimer(budget + time.Second)
			select {
			case err := <-done:
				timer.Stop()
				t.Fatal("unsubmitted owner consumed network budget", err)
			case <-timer.C:
			}
			if client.SessionEndCause() != nil || h.calls.Load() != 0 {
				t.Fatal("readiness ended session or dispatched", client.SessionEndCause(), h.calls.Load())
			}
			unavailable.Store(false)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("original owner did not resume")
			}
			if h.calls.Load() != 1 {
				t.Fatal("logical request repeated", h.calls.Load())
			}
		})
	}
}
