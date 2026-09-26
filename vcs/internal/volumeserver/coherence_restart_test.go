package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPriorLinuxCacheHorizonDelaysMutationAndDelegationWithoutBlockingSubscribe(t *testing.T) {
	clock := newCV2Clock()
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: clock, PriorLinuxCaches: true})
	token := cv2Subscribe(t, c, 1)
	// Cold subscription and read admission remain available during the gap.
	guard, err := c.DataConsumed(t.Context(), token, [16]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	guard.Release()
	mutation := make(chan error, 1)
	reservation := make(chan *DelegationReservation, 1)
	reservationError := make(chan error, 1)
	go func() { mutation <- c.WaitPriorCacheHorizon(t.Context()) }()
	go func() {
		r, err := c.Reserve(t.Context(), token, [16]byte{8})
		reservation <- r
		reservationError <- err
	}()
	clock.waitForTimers(t, 2)
	clock.Advance(SubscriptionTTL - time.Nanosecond)
	select {
	case <-mutation:
		t.Fatal("mutation admitted before old cache horizon")
	default:
	}
	select {
	case <-reservation:
		t.Fatal("delegation admitted before old cache horizon")
	default:
	}
	c.mu.Lock()
	count := len(c.delegations)
	c.mu.Unlock()
	if count != 0 {
		t.Fatal("startup wait retained a delegation")
	}
	// Keep this new subscription live; the old authority's absolute bound stays fixed.
	if _, err := c.Renew(token); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Nanosecond)
	if err := <-mutation; err != nil {
		t.Fatal(err)
	}
	r := <-reservation
	if err := <-reservationError; err != nil {
		t.Fatal(err)
	}
	r.Abort()
}

func TestPriorLinuxCacheWaitCancellationLeavesNoDelegation(t *testing.T) {
	clock := newCV2Clock()
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: clock, PriorLinuxCaches: true})
	token := cv2Subscribe(t, c, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := c.Reserve(ctx, token, [16]byte{1}); done <- err }()
	clock.waitForTimers(t, 1)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.delegations) != 0 || len(c.subscribers[token.Session].held) != 0 {
		t.Fatal("cancel retained ownership")
	}
}
