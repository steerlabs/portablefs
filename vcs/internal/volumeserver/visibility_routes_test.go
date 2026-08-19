package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A topology reader is the admission ticket held by both filesystem requests
// and attaches. The writer must not even evaluate its compare-and-swap while
// one is paused; otherwise a request can be admitted under the old routes and
// run after the new routes commit. Strict registration is deliberately
// exercised while the topology reader is held to prove the topology and
// participant locks are independent rather than recursively deadlocking.
func TestTopologyReadGuardExcludesRouteCASForPausedRequestsAndAttaches(t *testing.T) {
	for _, operation := range []string{"request", "attach"} {
		t.Run(operation, func(t *testing.T) {
			h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
			id := SessionID{1}
			var cancel context.CancelFunc
			if operation == "request" {
				h.register(t, id, testRepairBudget)
				var ctx context.Context
				ctx, cancel = context.WithCancel(context.Background())
				go serviceVisibility(ctx, h.coordinator, id)
			}
			guard := h.coordinator.AcquireTopologyRead()
			if operation == "attach" {
				h.register(t, id, testRepairBudget)
				var ctx context.Context
				ctx, cancel = context.WithCancel(context.Background())
				go serviceVisibility(ctx, h.coordinator, id)
			}
			if cancel != nil {
				defer cancel()
			}

			checked := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				_, err := h.coordinator.ExecuteTopologyExclusive(context.Background(), func() (int, error) {
					close(checked)
					return 0, nil
				})
				done <- err
			}()
			select {
			case <-checked:
				t.Fatal("route CAS ran while old-topology admission was still pinned")
			case <-time.After(50 * time.Millisecond):
			}
			guard.Release()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("route writer did not resume after topology admission ended")
			}
		})
	}
}

// The route compare-and-swap runs inside the topology-exclusive section, which
// is the only thing that makes it a compare-and-swap at all: two callers that
// present the same old revision must be serialized before either can decide it
// still matches. Exactly one may win.
func TestTopologyExclusiveSerializesConcurrentRouteCompareAndSwap(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	var old, first, second [32]byte
	old[0], first[0], second[0] = 1, 2, 3
	active := old
	lost := errors.New("compare-and-swap lost")
	start := make(chan struct{})
	results := make(chan error, 2)
	apply := func(next [32]byte) {
		<-start
		_, err := h.coordinator.ExecuteTopologyExclusive(context.Background(), func() (int, error) {
			if active != old {
				return 0, lost
			}
			active = next
			return 0, nil
		})
		results <- err
	}
	go apply(first)
	go apply(second)
	close(start)
	var succeeded, refused int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, lost):
			refused++
		default:
			t.Fatalf("unexpected route apply result: %v", err)
		}
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("concurrent CAS results = %d success, %d lost; want exactly one of each", succeeded, refused)
	}
}
