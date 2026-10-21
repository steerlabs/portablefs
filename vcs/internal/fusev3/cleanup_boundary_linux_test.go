//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func pendingCloses(m *delegationManager) int {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	return m.closePending
}

func TestInterruptedClosePreparationRetainsSameSessionDebt(t *testing.T) {
	f := newStockFixture(t)
	m := f.mount.delegations
	n := testNode(f.mount)
	id, _ := delegationIdentity(n.item.GetStableIdentity())
	state := m.retainState(id, true)
	defer m.releaseState(state)
	admitted, releaseCallback, callbackDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCallback) }) }
	defer release()
	go func() {
		defer close(callbackDone)
		f.rawCall(func(unique uint64) fuse.Status {
			_, finish, status := f.raw.mutationContext(unique)
			if !status.Ok() {
				return status
			}
			defer finish()
			state.acquire.Lock()
			defer state.acquire.Unlock()
			close(admitted)
			<-releaseCallback
			return fuse.OK
		})
	}()
	<-admitted
	retry, waiting := make(chan struct{}), make(chan struct{})
	m.SetCleanupRetryWaiter(func(ctx context.Context) error {
		close(waiting)
		select {
		case <-retry:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	var closes atomic.Int32
	token := testToken(100)
	f.rpc.mu.Lock()
	f.rpc.unrecordedRefusals = true
	f.rpc.replyOverride = func(r *authoritypb.Request) (*authoritypb.Response, error) {
		if r.GetClose() != nil {
			return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
		}
		if batch := r.GetCloseBatch(); batch != nil {
			if len(batch.Closes) != 1 || string(batch.Closes[0].Handle) != string(token) {
				t.Error("cleanup changed exact handle")
			}
			closes.Add(1)
			return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: []*authoritypb.CloseBatchResult{{Retired: true}}}}}, nil
		}
		return &authoritypb.Response{}, nil
	}
	f.rpc.mu.Unlock()
	f.rawCall(func(unique uint64) fuse.Status {
		ctx, finish, status := f.raw.mutationContext(unique)
		if !status.Ok() {
			return status
		}
		defer finish()
		if outcome := (&fileHandle{node: n, token: token}).closeForCleanup(ctx, 0, false); outcome.failed() {
			t.Errorf("handoff: %v", outcome.cause)
		}
		return fuse.OK
	})
	waitUntil(t, time.Second, "preparation waits for admitted OPEN", func() bool {
		state.acquire.mu.Lock()
		defer state.acquire.mu.Unlock()
		return state.acquire.changed != nil
	})
	old, serial := m.buf, m.epochSerial
	m.InterruptSubscription()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("interrupted preparation lost its retry owner")
	}
	if m.buf != old || m.epochSerial != serial || pendingCloses(m) != 1 || closes.Load() != 0 {
		t.Fatal("interruption discharged debt before cold reset")
	}
	release()
	<-callbackDone
	m.FenceSubscription("cold activation after interrupted preparation")
	m.SetIncarnation(8)
	close(retry)
	waitUntil(t, time.Second, "exact descriptor retirement", func() bool { return pendingCloses(m) == 0 })
	if closes.Load() != 1 || f.mount.isRevoked() || f.rpc.SessionEndCause() != nil {
		t.Fatalf("closes=%d revoked=%t", closes.Load(), f.mount.isRevoked())
	}
}

func TestCloseHandoffReleasesEpochFenceBeforeQueueCapacity(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory_%t", directory), func(t *testing.T) {
			f := newStockFixture(t)
			f.mount.delegations.Stop()
			m, err := newDelegationManagerWithCloseCapacity(f.mount.rpc, time.Second, 7, writeback.Options{}, 1)
			if err != nil {
				t.Fatal(err)
			}
			f.mount.delegations = m
			f.mount.subscription.control = m
			waiting, active := make(chan struct{}), make(chan struct{})
			m.SetCleanupFailureReporter(func(error) {})
			m.SetCleanupRetryWaiter(func(ctx context.Context) error {
				close(waiting)
				select {
				case <-active:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			var calls atomic.Int32
			retired := make(map[string]int)
			f.rpc.mu.Lock()
			f.rpc.unrecordedRefusals = true
			f.rpc.replyOverride = func(r *authoritypb.Request) (*authoritypb.Response, error) {
				if r.GetClose() != nil || r.GetCloseBatch() != nil && calls.Add(1) == 1 {
					return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
				}
				if batch := r.GetCloseBatch(); batch != nil {
					results := make([]*authoritypb.CloseBatchResult, len(batch.Closes))
					for i, c := range batch.Closes {
						retired[string(c.Handle)]++
						results[i] = &authoritypb.CloseBatchResult{Retired: true}
					}
					return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: results}}}, nil
				}
				return &authoritypb.Response{}, nil
			}
			f.rpc.mu.Unlock()
			n := testNode(f.mount)
			for i := 0; i < 2; i++ {
				if err := m.QueueClose(n.item.StableIdentity, testToken(uint64(100+i)), 0, false); err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					select {
					case <-waiting:
					case <-time.After(time.Second):
						t.Fatal("worker did not await cold activation")
					}
				}
			}
			handed, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				f.rawCall(func(unique uint64) fuse.Status {
					ctx, finish, status := f.raw.mutationContext(unique)
					if !status.Ok() {
						return status
					}
					defer finish()
					var outcome resourceCleanupError
					if directory {
						outcome = (&dirHandle{node: n, token: testToken(102)}).closeForCleanup(ctx)
					} else {
						outcome = (&fileHandle{node: n, token: testToken(102)}).closeForCleanup(ctx, 0, false)
					}
					if outcome.failed() {
						t.Errorf("handoff: %v", outcome.cause)
					}
					close(handed)
					return fuse.OK
				})
			}()
			select {
			case <-handed:
			case <-time.After(time.Second):
				t.Fatal("full queue blocked ownership transfer under callback fence")
			}
			recovered := make(chan struct{})
			go func() {
				f.mount.epochMu.Lock()
				m.FenceSubscription("cold reset with full dispatch queue")
				m.SetIncarnation(8)
				f.mount.epochMu.Unlock()
				close(active)
				close(recovered)
			}()
			select {
			case <-recovered:
			case <-time.After(time.Second):
				m.cancel()
				t.Fatal("cleanup queue deadlocked cold activation")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("dispatch did not resume")
			}
			waitUntil(t, time.Second, "every cleanup debt settled", func() bool { return pendingCloses(m) == 0 })
			f.rpc.mu.Lock()
			for i := 0; i < 3; i++ {
				if count := retired[string(testToken(uint64(100+i)))]; count != 1 {
					t.Errorf("descriptor %d retired %d times", i, count)
				}
			}
			retiredCount := len(retired)
			f.rpc.mu.Unlock()
			if retiredCount != 3 || f.mount.isRevoked() || f.rpc.SessionEndCause() != nil {
				t.Fatal("cleanup did not preserve live session")
			}
		})
	}
}

func TestClosePreparationFailureRetainsDebtUntilTerminalCleanup(t *testing.T) {
	m, err := newDelegationManager(&delegationFakeRPC{}, 20*time.Millisecond, 7, writeback.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	id := delegationTestIdentity(47)
	parsed, _ := delegationIdentity(id)
	state := m.retainState(parsed, true)
	defer m.releaseState(state)
	state.acquire.Lock()
	defer state.acquire.Unlock()
	reported := make(chan error, 8)
	m.SetCleanupFailureReporter(func(err error) { reported <- err })
	if err := m.QueueClose(id, delegationTestToken(47, 2), 0, false); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-reported:
		var classified cleanupClassified
		if !errors.As(err, &classified) || !classified.cleanupIsTerminal() {
			t.Fatalf("preparation error not terminal: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("preparation failure unreported")
	}
	if pendingCloses(m) != 1 {
		t.Fatal("generic preparation failure erased live debt")
	}
	m.Stop()
	if pendingCloses(m) != 0 {
		t.Fatal("terminal cleanup retained debt")
	}
}
