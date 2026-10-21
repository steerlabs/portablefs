//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"github.com/hanwen/go-fuse/v2/fuse"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"google.golang.org/protobuf/proto"
)

type cleanupReplayRPC struct {
	delegationFakeRPC
	entered   chan context.Context
	release   chan struct{}
	operation string
	failure   error
	calls     atomic.Int32
	body      *authoritypb.Request
}

func (f *cleanupReplayRPC) CallMutation(ctx context.Context, r *authoritypb.Request) (*authoritypb.Response, error) {
	if f.operation == "close" && r.GetCloseBatch() != nil || f.operation == "barrier" && r.GetBarrier() != nil {
		f.calls.Add(1)
		f.body = proto.Clone(r).(*authoritypb.Request)
		f.entered <- ctx
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if !proto.Equal(f.body, r) {
			return nil, errors.New("assigned cleanup body changed")
		}
		if f.failure != nil {
			return nil, f.failure
		}
	}
	return f.delegationFakeRPC.CallMutation(ctx, r)
}

func TestSessionCleanupSurvivesInFlightColdReset(t *testing.T) {
	for _, operation := range []string{"close", "barrier"} {
		for _, unresolved := range []bool{false, true} {
			name := operation + "/resolved"
			if unresolved {
				name = operation + "/unprovable"
			}
			t.Run(name, func(t *testing.T) {
				f := &cleanupReplayRPC{entered: make(chan context.Context, 1), release: make(chan struct{}), operation: operation}
				if unresolved {
					f.failure = authorityrpc.ErrTransportUncertain
				}
				m, err := newDelegationManager(f, 50*time.Millisecond, 7, writeback.Options{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(m.Stop)
				failures := make(chan error, 8)
				m.SetCleanupFailureReporter(func(e error) { failures <- e })
				oldBuffer := m.buf
				barrierDone := make(chan struct{})
				if operation == "close" {
					if err := m.QueueClose(delegationTestIdentity(18), delegationTestToken(18, 2), 0, false); err != nil {
						t.Fatal(err)
					}
				} else {
					m.durabilityMu.Lock()
					m.appliedHigh = 1
					m.durabilityMu.Unlock()
					go func() { m.advanceDurability(); close(barrierDone) }()
				}
				var ctx context.Context
				select {
				case ctx = <-f.entered:
				case <-time.After(time.Second):
					t.Fatal("cleanup not submitted")
				}
				m.FenceSubscription("response lost across subscription expiry")
				m.SetIncarnation(8)
				if ctx.Err() != nil {
					t.Fatalf("cold reset canceled session-owned %s: %v", operation, ctx.Err())
				}
				if operation == "close" {
					m.closeMu.Lock()
					pending := m.closePending
					m.closeMu.Unlock()
					if pending != 1 {
						t.Fatalf("unresolved descriptor debt=%d", pending)
					}
				}
				if m.buf == oldBuffer {
					t.Fatal("cold reset did not replace the buffer")
				}
				// Cleanup must outlive the cache-work deadline, retaining one bounded owner.
				timer := time.NewTimer(2 * m.timeout)
				select {
				case <-ctx.Done():
					timer.Stop()
					t.Fatal("session cleanup inherited cache-work deadline")
				case <-timer.C:
				}
				close(f.release)
				if operation == "close" {
					if unresolved {
						waitUntil(t, time.Second, "terminal cleanup transfer", func() bool { return len(failures) != 0 })
						if pendingCloses(m) != 1 {
							t.Fatal("terminal cleanup lost counted descriptor debt")
						}
						m.Stop()
					}
					waitUntil(t, time.Second, "exact close resolution", func() bool { m.closeMu.Lock(); defer m.closeMu.Unlock(); return m.closePending == 0 })
				} else {
					select {
					case <-barrierDone:
					case <-time.After(time.Second):
						t.Fatal("barrier resolver did not finish")
					}
				}
				if unresolved {
					select {
					case e := <-failures:
						var classified cleanupClassified
						if !errors.As(e, &classified) || !classified.cleanupIsTerminal() {
							t.Fatalf("unprovable result not terminal: %v", e)
						}
					case <-time.After(time.Second):
						t.Fatal("unprovable result suppressed by reset")
					}
				} else {
					// Stop joins the background Barrier before examining its new-buffer cut.
					m.Stop()
					select {
					case e := <-failures:
						t.Fatalf("resolved cleanup poisoned mount: %v", e)
					default:
					}
					m.durabilityMu.Lock()
					applied, durable := m.appliedHigh, m.durableHigh
					m.durabilityMu.Unlock()
					if applied != 0 || durable != 0 || m.buf.Stats().Entries != 0 {
						t.Fatalf("old receipt revived successor buffer: applied=%d durable=%d stats=%+v", applied, durable, m.buf.Stats())
					}
				}
				if f.calls.Load() != 1 {
					t.Fatalf("cleanup resubmitted as new operation: %d", f.calls.Load())
				}
			})
		}
	}
}

func TestOldOpenResponseCannotRestoreCacheAuthority(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	mount := &Mount{delegations: m}
	p := &replyPublication{stamp: subscriptionStamp{incarnation: 7}}
	ctx := context.WithValue(t.Context(), mutationCallbackKey{}, &mutationCallback{publication: *p})
	if !mount.currentOpenResponse(ctx) {
		t.Fatal("current grant refused")
	}
	m.FenceSubscription("lost response")
	if mount.currentOpenResponse(ctx) {
		t.Fatal("expired grant remained eligible")
	}
	m.SetIncarnation(8)
	if mount.currentOpenResponse(ctx) {
		t.Fatal("old grant adopted replacement subscription")
	}
	if err := m.openedVisibility(ctx, delegationTestIdentity(18), &authoritypb.Response{AppliedSequence: 42}, false); err != nil {
		t.Fatal(err)
	}
	m.durabilityMu.Lock()
	defer m.durabilityMu.Unlock()
	if m.appliedHigh != 0 {
		t.Fatal("old application cut entered new buffer")
	}
}

func TestUnrecordedCloseRefusalRetainsSessionDescriptor(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory_%t", directory), func(t *testing.T) {
			f := newStockFixture(t)
			recovery := make(chan struct{})
			waiting := make(chan struct{})
			var batchCalls atomic.Int32
			f.mount.delegations.SetCleanupRetryWaiter(func(ctx context.Context) error {
				close(waiting)
				select {
				case <-recovery:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			f.rpc.mu.Lock()
			f.rpc.unrecordedRefusals = true
			f.rpc.replyOverride = func(r *authoritypb.Request) (*authoritypb.Response, error) {
				if r.GetClose() != nil {
					return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
				}
				if r.GetCloseBatch() != nil {
					if batchCalls.Add(1) == 1 {
						return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
					}
					return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: []*authoritypb.CloseBatchResult{{Retired: true}}}}}, nil
				}
				return &authoritypb.Response{}, nil
			}
			f.rpc.mu.Unlock()
			var outcome resourceCleanupError
			status := f.rawCall(func(unique uint64) fuse.Status {
				ctx, finish, status := f.raw.mutationContext(unique)
				if !status.Ok() {
					return status
				}
				defer finish()
				n := testNode(f.mount)
				if directory {
					outcome = (&dirHandle{node: n, token: testToken(100)}).closeForCleanup(ctx)
				} else {
					outcome = (&fileHandle{node: n, token: testToken(100)}).closeForCleanup(ctx, 0, false)
				}
				return fuse.OK
			})
			if !status.Ok() || outcome.failed() {
				t.Fatalf("descriptor ownership not transferred: status=%v outcome=%v", status, outcome.cause)
			}
			select {
			case <-waiting:
			case <-time.After(time.Second):
				t.Fatal("refused close not retained for cold recovery")
			}
			f.mount.delegations.closeMu.Lock()
			pending := f.mount.delegations.closePending
			f.mount.delegations.closeMu.Unlock()
			if pending != 1 {
				t.Fatalf("descriptor debt=%d", pending)
			}
			f.mount.delegations.FenceSubscription("cold recovery after definite CLOSE refusal")
			f.mount.delegations.SetIncarnation(8)
			close(recovery)
			waitUntil(t, time.Second, "session descriptor retired", func() bool {
				f.mount.delegations.closeMu.Lock()
				defer f.mount.delegations.closeMu.Unlock()
				return f.mount.delegations.closePending == 0
			})
			if batchCalls.Load() != 2 || f.mount.isRevoked() {
				t.Fatalf("cleanup calls=%d revoked=%t", batchCalls.Load(), f.mount.isRevoked())
			}
		})
	}
}
