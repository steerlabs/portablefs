//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

func TestExpiredClosePreparationRetainsDescriptorThroughColdRecovery(t *testing.T) {
	var releases, closes atomic.Int32
	oldHandle := delegationTestToken(81, 2)
	fake := &releaseOutcomeRPC{
		release: func(context.Context) (*authoritypb.Response, error) {
			releases.Add(1)
			return nil, errors.Join(authorityrpc.ErrDispatchExpired, errSubscriptionExpired)
		},
		close: func(batch *authoritypb.CloseBatchRequest) (*authoritypb.Response, error) {
			closes.Add(1)
			if len(batch.Closes) != 1 || string(batch.Closes[0].Handle) != string(oldHandle) {
				t.Error("cold retry changed the retained descriptor")
			}
			return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: []*authoritypb.CloseBatchResult{{Retired: true}}}}}, nil
		},
	}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 81, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	waiting, retry := make(chan struct{}), make(chan struct{})
	m.SetCleanupRetryWaiter(func(ctx context.Context) error {
		close(waiting)
		select {
		case <-retry:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	reported := make(chan error, 8)
	m.SetCleanupFailureReporter(func(err error) { reported <- err })
	if err := m.QueueClose(id, oldHandle, 0, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("expired preparation terminalized or lost the descriptor")
	}
	var classified cleanupClassified
	if err := <-reported; !errors.As(err, &classified) || classified.cleanupFailureClass() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE || classified.cleanupIsTerminal() {
		t.Fatal("cache expiry became an unknown descriptor outcome", err)
	}
	if pendingCloses(m) != 1 || closes.Load() != 0 {
		t.Fatal("preparation discharged an unsubmitted CLOSE")
	}
	m.FenceSubscription("cold after expired cleanup preparation")
	m.SetIncarnation(8)
	newHandle := delegationTestToken(81, 4)
	grant := delegationTestGrant(82, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if err := m.Install(id, delegationTestToken(81, 3), newHandle, grant); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(t.Context(), id, 0, []byte("new interval"), false); err != nil {
		t.Fatal(err)
	}
	close(retry)
	waitUntil(t, time.Second, "retained descriptor cleanup", func() bool { return pendingCloses(m) == 0 })
	if releases.Load() != 1 || closes.Load() != 1 || !m.Owns(id) || !m.TracksHandle(id, newHandle) || m.LossSequence() != 0 || m.buf.Stats().Accepted != 1 {
		t.Fatalf("release=%d close=%d owns=%t loss=%d stats=%+v", releases.Load(), closes.Load(), m.Owns(id), m.LossSequence(), m.buf.Stats())
	}
}

func TestExpiredClosePreparationCannotHideIndependentFailure(t *testing.T) {
	for _, independent := range []error{errors.New("malformed release reply"), &authorityrpc.LifecycleIndependentFailure{Err: errSubscriptionExpired}} {
		t.Run(independent.Error(), func(t *testing.T) {
			fake := &releaseOutcomeRPC{release: func(context.Context) (*authoritypb.Response, error) {
				return nil, errors.Join(authorityrpc.ErrDispatchExpired, independent)
			}}
			m := newDelegationTestManager(t, fake)
			id := installDelegationForTest(t, m, 83, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(83, 2)}})
			var classified cleanupClassified
			if !errors.As(err, &classified) || !classified.cleanupIsTerminal() {
				t.Fatal("independent failure became cache retry", err)
			}
		})
	}
}
