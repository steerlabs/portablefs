//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type progressSubscriptionRPC struct {
	*subscriptionTestRPC
	pollCalls, ackCalls, subscribeCalls atomic.Int32
}

func (r *progressSubscriptionRPC) NextControlEvent(ctx context.Context, _, _, _ uint64) (*authoritypb.ControlEvent, error) {
	if r.pollCalls.Add(1) == 1 {
		return nil, syscall.EAGAIN
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r *progressSubscriptionRPC) AcknowledgeChanges(context.Context, uint64, uint64) error {
	if r.ackCalls.Add(1) == 1 {
		return syscall.EAGAIN
	}
	return nil
}

func (r *progressSubscriptionRPC) Subscribe(ctx context.Context, snapshot, after []byte) (*authoritypb.SubscribeReply, time.Time, error) {
	if r.subscribeCalls.Add(1) == 1 {
		return nil, time.Time{}, syscall.EAGAIN
	}
	return r.subscriptionTestRPC.Subscribe(ctx, snapshot, after)
}

func TestSubscriptionRetriesRequireActualControlProgress(t *testing.T) {
	for _, owner := range []string{"poll", "ack", "subscribe"} {
		t.Run(owner, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rpc := &progressSubscriptionRPC{subscriptionTestRPC: &subscriptionTestRPC{horizon: time.Now().Add(10 * time.Second), pages: []*authoritypb.SubscribeReply{{Watermark: 1, Incarnation: 9, HorizonNanos: uint64(10 * time.Second), SnapshotId: []byte("snapshot")}}}}
				s := newSubscriptionRegistryWithConfig(nil, rpc, nil, subscriptionConfig{clock: testActiveSubscriptionClock{}, invalidator: &subscriptionTestInvalidator{}})
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				var calls *atomic.Int32
				switch owner {
				case "poll":
					calls = &rpc.pollCalls
					go func() { done <- s.pollLoop(ctx, 9, newSubscriptionChangeQueue()) }()
				case "ack":
					calls = &rpc.ackCalls
					s.cacheUntil = time.Now().Add(time.Second)
					go func() { done <- s.ackChanges(ctx, 9, 1) }()
				case "subscribe":
					calls = &rpc.subscribeCalls
					go func() { done <- s.run(ctx) }()
				}
				synctest.Wait()
				time.Sleep(25 * time.Millisecond)
				synctest.Wait()
				if got := calls.Load(); got != 1 {
					t.Fatalf("%s retried without CONTROL progress: %d calls", owner, got)
				}
				s.madeProgress()
				synctest.Wait()
				if got := calls.Load(); got != 2 {
					t.Fatalf("%s did not consume actual CONTROL progress: %d calls", owner, got)
				}
				cancel()
				if err := <-done; owner == "ack" && err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestSubscriptionProgressCannotLoseAConcurrentContact(t *testing.T) {
	s := newSubscriptionRegistryWithConfig(nil, nil, nil, subscriptionConfig{})
	progress := s.progress()
	s.madeProgress()
	if err := s.waitProgress(t.Context(), progress); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.waitProgress(ctx, s.progress()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled progress wait = %v", err)
	}
}
