//go:build linux

package fusev3

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// The raw callback reader is the boundary that the mounted horizon test uses.
// A full buffer must fail the parked admission before subscribe waits on that
// reader; waiting for the request deadline changes the promised EIO to timeout.
func TestColdSubscriptionInterruptsCapacityBeforeCallbackDrain(t *testing.T) {
	m, err := newDelegationManager(&delegationFakeRPC{block: make(chan struct{})}, time.Second, 7, writeback.Options{MaxEntries: 1, FlushInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	identity := installDelegationForTest(t, m, 34, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), identity, 0, []byte("accepted"), false); err != nil {
		t.Fatal(err)
	}
	old := m.buf
	clock := &subscriptionTestClock{now: time.Unix(100, 0)}
	rpc := &subscriptionTestRPC{
		horizon: clock.Now().Add(10 * time.Second),
		pages:   []*authoritypb.SubscribeReply{{Watermark: 1, Incarnation: 8, HorizonNanos: uint64(10 * time.Second), SnapshotId: []byte("replacement")}},
	}
	registry := newSubscriptionTestRegistry(clock, rpc, &subscriptionTestInvalidator{}, m)
	mount := &Mount{delegations: m}
	registry.mount = mount
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	written := make(chan error, 1)
	mount.epochMu.RLock()
	go func() {
		_, err := m.Write(ctx, identity, 8, []byte("parked"), false)
		mount.epochMu.RUnlock()
		written <- err
	}()
	waitFor(t, "admission parked with callback reader", func() bool { return old.Stats().WaitingAdmissions == 1 })
	subscribed := make(chan error, 1)
	go func() { subscribed <- registry.subscribe(ctx) }()
	select {
	case err := <-written:
		if !errors.Is(err, writeback.ErrClosed) || delegationErrno(err) != syscall.EIO {
			t.Fatalf("parked callback write=%v (%v), want ErrClosed/EIO", err, delegationErrno(err))
		}
	case <-time.After(time.Second):
		cancel()
		<-written
		<-subscribed
		t.Fatal("cold subscription waited on capacity callback before interrupting it")
	}
	select {
	case err := <-subscribed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cold subscription did not follow callback drain")
	}
	if m.incarnation() != 8 || m.LossSequence() == 0 {
		t.Fatalf("replacement incarnation=%d loss=%d", m.incarnation(), m.LossSequence())
	}
}

func TestEpochRecoveryInterruptsCapacityBeforeCallbackDrain(t *testing.T) {
	m, err := newDelegationManager(&delegationFakeRPC{block: make(chan struct{})}, time.Second, 7, writeback.Options{MaxEntries: 1, FlushInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	provider := &recoveringFrontendTestRPC{fakeRPC: newFakeRPC(), next: newFakeRPC()}
	mount := newMount(context.Background(), provider, testConfig(32))
	mount.delegations.Stop()
	mount.delegations, mount.subscription.control = m, m
	t.Cleanup(func() { mount.cancel(); m.Stop() })
	newRawFileSystem(mount, &node{mount: mount, item: provider.Root(), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024})
	mount.setNotifier(&fakeNotifier{})
	identity := installDelegationForTest(t, m, 34, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), identity, 0, []byte("accepted"), false); err != nil {
		t.Fatal(err)
	}
	old := m.buf
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	written := make(chan error, 1)
	mount.epochMu.RLock()
	go func() {
		_, err := m.Write(ctx, identity, 8, []byte("parked"), false)
		mount.epochMu.RUnlock()
		written <- err
	}()
	waitFor(t, "epoch admission parked with callback reader", func() bool { return old.Stats().WaitingAdmissions == 1 })
	recovered := make(chan error, 1)
	go func() { recovered <- mount.recoverEpoch(ctx) }()
	select {
	case err := <-written:
		if !errors.Is(err, writeback.ErrClosed) || delegationErrno(err) != syscall.EIO {
			t.Fatalf("parked epoch write=%v (%v), want ErrClosed/EIO", err, delegationErrno(err))
		}
	case <-time.After(time.Second):
		cancel()
		<-written
		<-recovered
		t.Fatal("epoch recovery waited on capacity callback before interrupting it")
	}
	select {
	case err := <-recovered:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("epoch recovery did not follow callback drain")
	}
	if m.LossSequence() == 0 {
		t.Fatal("epoch recovery hid accepted dirty data loss")
	}
}
