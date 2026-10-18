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

func TestReviewCloseRetryCannotBlockOnItsOwnFullQueue(t *testing.T) {
	var calls atomic.Int32
	waiting, resume, retried := make(chan struct{}), make(chan struct{}), make(chan struct{})
	fake := &releaseOutcomeRPC{}
	fake.close = func(batch *authoritypb.CloseBatchRequest) (*authoritypb.Response, error) {
		call := calls.Add(1)
		if call == 1 {
			return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
		}
		if call == 2 {
			close(retried)
		}
		return fake.delegationFakeRPC.CallMutation(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_CloseBatch{CloseBatch: batch}})
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
	id := delegationTestIdentity(44)
	if err := m.QueueClose(id, delegationTestToken(44, 255, 255), 0, false); err != nil {
		t.Fatal(err)
	}
	<-waiting
	// RELEASE does not pass handle-allocation admission. All of these can be
	// pre-existing descriptors released while the only close worker is away.
	for i := 0; i < cap(m.closeQueue); i++ {
		if err := m.QueueClose(id, delegationTestToken(44, byte(i>>8), byte(i)), 0, false); err != nil {
			t.Fatal(err)
		}
	}
	close(resume)
	select {
	case <-retried:
		waitFor(t, "full queue cleanup", func() bool { m.closeMu.Lock(); defer m.closeMu.Unlock(); return m.closePending == 0 })
	case <-time.After(time.Second):
		m.closeMu.Lock()
		pending := m.closePending
		m.closeMu.Unlock()
		t.Fatalf("close owner cannot consume while blocked requeueing: calls=%d queue=%d/%d pending=%d", calls.Load(), len(m.closeQueue), cap(m.closeQueue), pending)
	}
}
