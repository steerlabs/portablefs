//go:build linux

package fusev3

import (
	"context"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestReviewDeferredCloseRetryCannotAdoptSuccessorEpoch(t *testing.T) {
	var calls atomic.Int32
	waiting, resume := make(chan struct{}), make(chan struct{})
	fake := &releaseOutcomeRPC{}
	fake.close = func(batch *authoritypb.CloseBatchRequest) (*authoritypb.Response, error) {
		if calls.Add(1) == 1 {
			return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
		}
		// The successor authority cannot recognize a prior-session description.
		return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: []*authoritypb.CloseBatchResult{{Errno: int32(syscall.EBADF), Retired: true}}}}}, nil
	}
	m := newDelegationTestManager(t, fake)
	m.SetCleanupFailureReporter(func(error) {})
	m.SetCleanupRetryWaiter(func(ctx context.Context) error {
		close(waiting)
		select {
		case <-resume:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	id := delegationTestIdentity(45)
	if err := m.QueueClose(id, delegationTestToken(45, 2), 0, false); err != nil {
		t.Fatal(err)
	}
	<-waiting
	// The old CLOSE is out of the queue, awaiting cold recovery. A real epoch
	// replacement discards all old capabilities and installs a new grant.
	m.EpochChanged("review authority epoch replacement")
	successor := delegationTestGrant(94, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	successor.Generation = 2
	if err := m.Install(id, delegationTestToken(45, 3), delegationTestToken(45, 4), successor); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(t.Context(), id, 0, []byte("successor"), false); err != nil {
		t.Fatal(err)
	}
	loss := m.LossSequence()
	close(resume)
	waitUntil(t, time.Second, "old cleanup retires", func() bool { m.closeMu.Lock(); defer m.closeMu.Unlock(); return m.closePending == 0 })
	t.Logf("closes=%d owns=%v loss=%d->%d retained=%d", calls.Load(), m.Owns(id), loss, m.LossSequence(), m.buf.Stats().Bytes)
	if calls.Load() != 1 {
		t.Error("old description was sent again after being rebound to the successor epoch")
	}
	if !m.Owns(id) || m.LossSequence() != loss || m.buf.Stats().Entries != 1 {
		t.Fatal("old cleanup refusal discarded the successor grant and its accepted data")
	}
}

func TestDeferredCloseSurvivesColdSubscriptionWithoutOwningSuccessor(t *testing.T) {
	var calls atomic.Int32
	waiting, resume := make(chan struct{}), make(chan struct{})
	fake := &releaseOutcomeRPC{}
	fake.close = func(batch *authoritypb.CloseBatchRequest) (*authoritypb.Response, error) {
		if calls.Add(1) == 1 {
			return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
		}
		return fake.delegationFakeRPC.CallMutation(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_CloseBatch{CloseBatch: batch}})
	}
	m := newDelegationTestManager(t, fake)
	m.SetCleanupRetryWaiter(func(ctx context.Context) error {
		close(waiting)
		select {
		case <-resume:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	id := delegationTestIdentity(46)
	if err := m.QueueClose(id, delegationTestToken(46, 2), 0, false); err != nil {
		t.Fatal(err)
	}
	<-waiting
	m.FenceSubscription("cold same-session subscription")
	m.SetIncarnation(8)
	grant := delegationTestGrant(95, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	grant.Generation = 2
	if err := m.Install(id, delegationTestToken(46, 3), delegationTestToken(46, 4), grant); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(t.Context(), id, 0, []byte("successor"), false); err != nil {
		t.Fatal(err)
	}
	loss := m.LossSequence()
	close(resume)
	waitFor(t, "same-session descriptor cleanup", func() bool { m.closeMu.Lock(); defer m.closeMu.Unlock(); return m.closePending == 0 })
	if calls.Load() != 2 || !m.Owns(id) || m.LossSequence() != loss || m.buf.Stats().Accepted != 1 {
		t.Fatalf("closes=%d owns=%v loss=%d->%d stats=%+v", calls.Load(), m.Owns(id), loss, m.LossSequence(), m.buf.Stats())
	}
}
