//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type workspaceRunnerRPC struct {
	*subscriptionTestRPC
	events       chan *authoritypb.ControlEvent
	polled       chan struct{}
	once         sync.Once
	ackEntered   chan struct{}
	ackRelease   chan struct{}
	renewEntered chan struct{}
	renewRelease chan struct{}
}

func (r *workspaceRunnerRPC) NextControlEvent(ctx context.Context, _, _, _ uint64) (*authoritypb.ControlEvent, error) {
	r.once.Do(func() { close(r.polled) })
	select {
	case event := <-r.events:
		return event, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (r *workspaceRunnerRPC) AcknowledgeChanges(ctx context.Context, i, p uint64) error {
	if r.ackEntered != nil {
		close(r.ackEntered)
		<-r.ackRelease
	}
	return r.subscriptionTestRPC.AcknowledgeChanges(ctx, i, p)
}
func (r *workspaceRunnerRPC) RenewSubscription(context.Context, uint64) (time.Time, error) {
	close(r.renewEntered)
	<-r.renewRelease
	return r.horizon.Add(time.Hour), nil
}
func workspaceRunner(t *testing.T, rpc *workspaceRunnerRPC, clock subscriptionClock) (*subscriptionRegistry, *subscriptionTestInvalidator, context.CancelFunc, <-chan error) {
	t.Helper()
	invalidator := &subscriptionTestInvalidator{}
	s := newSubscriptionRegistryWithConfig(nil, rpc, &subscriptionTestControl{}, subscriptionConfig{clock: clock, invalidator: invalidator})
	s.active, s.incarnation = true, 5
	s.horizon, s.cacheUntil = clock.Now().Add(time.Minute), clock.Now().Add(time.Minute)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.serveIncarnation(ctx) }()
	t.Cleanup(cancel)
	<-rpc.polled
	return s, invalidator, cancel, done
}
func TestWorkspaceLifecycleControlCutDrainsAck(t *testing.T) {
	rpc := &workspaceRunnerRPC{subscriptionTestRPC: &subscriptionTestRPC{}, events: make(chan *authoritypb.ControlEvent, 2), polled: make(chan struct{}), ackEntered: make(chan struct{}), ackRelease: make(chan struct{})}
	s, invalidator, cancel, done := workspaceRunner(t, rpc, continuousSubscriptionClock{})
	defer cancel()
	if err := s.takeWorkspaceOwnership(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity := subscriptionIdentity(7)
	rpc.events <- &authoritypb.ControlEvent{Incarnation: 5, Sequence: 1, Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{Incarnation: 5, Entries: []*authoritypb.ChangeEntry{{Position: 1, VolumeVersion: 1, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:]}}}}}
	<-rpc.ackEntered
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer stop()
	if err := s.parkWorkspaceControl(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unacknowledged cut parked", err)
	}
	select {
	case <-done:
		t.Fatal("bounded waiter canceled CONTROL owner")
	default:
	}
	close(rpc.ackRelease)
	if err := s.parkWorkspaceControl(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-done
	rpc.mu.Lock()
	acks := len(rpc.acks)
	rpc.mu.Unlock()
	invalidator.mu.Lock()
	all := invalidator.all
	invalidator.mu.Unlock()
	if acks != 1 || all != 0 || !s.active {
		t.Fatal("runner epilogue competed with lifecycle-owned CONTROL", acks, all, s.active)
	}
}
func TestWorkspaceLifecycleJoinsInFlightRenewal(t *testing.T) {
	timers := make(chan *subscriptionTestTimer, 4)
	clock := &subscriptionTestClock{now: time.Now(), timers: timers}
	rpc := &workspaceRunnerRPC{subscriptionTestRPC: &subscriptionTestRPC{horizon: clock.Now().Add(time.Minute)}, events: make(chan *authoritypb.ControlEvent), polled: make(chan struct{}), renewEntered: make(chan struct{}), renewRelease: make(chan struct{})}
	s, _, cancel, done := workspaceRunner(t, rpc, clock)
	defer cancel()
	for {
		timer := <-timers
		if timer.duration == volumeserver.SubscriptionRenewInterval {
			timer.fired <- clock.Now()
			break
		}
	}
	<-rpc.renewEntered
	old := s.horizon
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer stop()
	if err := s.takeWorkspaceOwnership(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("in-flight renewal was not joined", err)
	}
	close(rpc.renewRelease)
	if err := s.takeWorkspaceOwnership(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	horizon := s.horizon
	s.mu.RUnlock()
	if !horizon.Equal(old) {
		t.Fatal("late renewal extended captured permission")
	}
	if err := s.parkWorkspaceControl(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-done
}
