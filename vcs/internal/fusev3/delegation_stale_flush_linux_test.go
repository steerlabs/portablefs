//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// The Authority's operation pin ends before transport delivery. Model a reply
// that arrives after a CONTROL deadline has retired its grant and a new OPEN
// has installed a successor on the same identity.
type staleFlushRPC struct {
	delegationFakeRPC
	ordered bool
	outcome string
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (f *staleFlushRPC) SupportsOrderedFlush() bool { return f.ordered }

func (f *staleFlushRPC) CallMutationSegments(ctx context.Context, request *authoritypb.Request, pieces [][]byte, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	if err := assigned(authorityrpc.MutationIdentity{Sequence: request.GetWrite().GetFlushSequence()}); err != nil {
		return nil, err
	}
	return f.CallMutation(ctx, request)
}

func (f *staleFlushRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		return nil, errors.New("hold durability for stale completion test")
	}
	if request.GetWrite() == nil && request.GetSetAttr() == nil {
		return f.delegationFakeRPC.CallMutation(ctx, request)
	}
	f.once.Do(func() { close(f.entered) })
	select {
	case <-f.resume:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	switch f.outcome {
	case "coherence":
		return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
	case "capacity":
		return &authoritypb.Response{Errno: int32(syscall.ENOSPC)}, nil
	case "uncertain":
		return nil, authorityrpc.ErrTransportUncertain
	case "success":
		response := &authoritypb.Response{AppliedSequence: 91, VolumeVersion: 91}
		if w := request.GetWrite(); w != nil {
			response.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{
				CommittedSize: uint64(w.Size), AssignedOffset: w.Position,
				PostAttr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Size: int64(w.Position) + int64(w.Size)},
			}}
		} else {
			set := request.GetSetAttr()
			response.PostState = &authoritypb.PostState{Objects: []*authoritypb.ObjectPostState{{
				StableIdentity: delegationTestIdentity(set.Handle[0]), ObjectVersion: 91,
				Attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Mode: set.GetMode()},
			}}}
		}
		return response, nil
	default:
		panic("unknown stale flush outcome")
	}
}

func TestDelegationDelayedFlushCannotMutateSuccessor(t *testing.T) {
	for _, path := range []string{"write", "metadata", "ordered"} {
		for _, outcome := range []string{"coherence", "capacity", "uncertain", "success"} {
			t.Run(path+"/"+outcome, func(t *testing.T) {
				fake := &staleFlushRPC{ordered: path == "ordered", outcome: outcome, entered: make(chan struct{}), resume: make(chan struct{})}
				manager := newDelegationTestManager(t, fake)
				id := installDelegationForTest(t, manager, 49, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
				parsed, _ := delegationIdentity(id)
				state := manager.retainState(parsed, false)
				defer manager.releaseState(state)
				var err error
				if path == "metadata" {
					_, err = manager.SetAttr(t.Context(), id, writeback.Attributes{HasMode: true, Mode: 0600})
				} else {
					_, err = manager.Write(t.Context(), id, 0, []byte("old"), false)
				}
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { _, err := manager.FlushIdentity(t.Context(), id); done <- err }()
				<-fake.entered
				old := delegationTestGrant(81, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
				manager.retireTimedOutControl(state, &authoritypb.DelegationRef{Id: old.Id, Generation: old.Generation})
				successor := delegationTestGrant(82, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
				successor.Generation = 2
				if err := manager.Install(id, delegationTestToken(49, 1), delegationTestToken(49, 3), successor); err != nil {
					t.Fatal(err)
				}
				if _, err := manager.Write(t.Context(), id, 0, []byte("successor"), false); err != nil {
					t.Fatal(err)
				}
				loss := manager.LossSequence()
				close(fake.resume)
				if err := <-done; !errors.Is(err, writeback.ErrLost) {
					t.Fatalf("old flush error = %v, want its original loss", err)
				}
				if !manager.Owns(id) || manager.LossSequence() != loss || manager.buf.Stats().Entries != 1 || manager.buf.Stats().Bytes != 9 {
					t.Fatalf("old reply changed successor: owns=%v loss=%d->%d stats=%+v", manager.Owns(id), loss, manager.LossSequence(), manager.buf.Stats())
				}
				state.meta.Lock()
				applied, appliedCut, ordinal, base := state.applied, state.appliedCut, state.flushOrdinal, state.base
				state.meta.Unlock()
				if applied != 0 || appliedCut != 0 || ordinal != 0 || base != nil {
					t.Fatalf("old receipt contaminated successor: applied=%d cut=%d ordinal=%d base=%v", applied, appliedCut, ordinal, base)
				}
				manager.tokenMu.Lock()
				tokens := len(state.flushTokens)
				manager.tokenMu.Unlock()
				if tokens != 0 {
					t.Fatalf("old completion resurrected %d replay records", tokens)
				}
			})
		}
	}
}

func TestDelegationCapacityWaiterCannotBlockLoss(t *testing.T) {
	for _, kind := range []string{"write", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			fake := &staleFlushRPC{outcome: "capacity", entered: make(chan struct{}), resume: make(chan struct{})}
			manager, err := newDelegationManager(fake, time.Second, 7, writeback.Options{MaxEntries: 1, FlushInterval: -1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(manager.Stop)
			id := installDelegationForTest(t, manager, 50, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			if _, err := manager.Write(t.Context(), id, 0, []byte("old"), false); err != nil {
				t.Fatal(err)
			}
			<-fake.entered
			done := make(chan error, 1)
			go func() {
				var err error
				if kind == "write" {
					_, err = manager.Write(t.Context(), id, 0, []byte("pending"), false)
				} else {
					_, err = manager.SetAttr(t.Context(), id, writeback.Attributes{HasMode: true, Mode: 0600})
				}
				done <- err
			}()
			deadline := time.Now().Add(time.Second)
			for manager.buf.Stats().WaitingAdmissions != 1 {
				if time.Now().After(deadline) {
					t.Fatal("write did not wait for retained-entry capacity")
				}
				time.Sleep(time.Millisecond)
			}
			close(fake.resume)
			select {
			case err := <-done:
				if !errors.Is(err, writeback.ErrLost) {
					t.Fatalf("old capacity waiter = %v, want ErrLost", err)
				}
			case <-time.After(time.Second):
				t.Fatal("capacity waiter blocked the flush refusal that should release it")
			}
			if !manager.Owns(id) || manager.LossSequence() != 1 || manager.buf.Stats().Entries != 0 {
				t.Fatalf("capacity refusal lost grant or admitted old waiter: owns=%v loss=%d stats=%+v", manager.Owns(id), manager.LossSequence(), manager.buf.Stats())
			}
		})
	}
}

func TestDelegationDelayedInvalidationCannotDropSuccessor(t *testing.T) {
	manager := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, manager, 51, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	parsed, _ := delegationIdentity(id)
	state := manager.retainState(parsed, false)
	defer manager.releaseState(state)
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	manager.SetFlushCycleInvalidator(func(context.Context, []byte) error {
		close(entered)
		<-resume
		return syscall.EIO
	})
	go func() { manager.FlushCycleCompleted(t.Context(), parsed); close(done) }()
	<-entered
	old := delegationTestGrant(83, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	manager.retireTimedOutControl(state, &authoritypb.DelegationRef{Id: old.Id, Generation: old.Generation})
	successor := delegationTestGrant(84, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	successor.Generation = 2
	if err := manager.Install(id, delegationTestToken(51, 1), delegationTestToken(51, 3), successor); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Write(t.Context(), id, 0, []byte("next"), false); err != nil {
		t.Fatal(err)
	}
	loss := manager.LossSequence()
	close(resume)
	<-done
	if !manager.Owns(id) || manager.LossSequence() != loss || manager.buf.Stats().Entries != 1 {
		t.Fatalf("old invalidation discarded successor: owns=%v loss=%d->%d stats=%+v", manager.Owns(id), loss, manager.LossSequence(), manager.buf.Stats())
	}
}

type staleCloseRPC struct{ delegationFakeRPC }

func (f *staleCloseRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		return nil, errors.New("hold durability for close scope test")
	}
	if request.GetCloseBatch() != nil {
		return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

func TestDelegationDeferredCloseFailureCannotDropSuccessor(t *testing.T) {
	manager := newDelegationTestManager(t, &staleCloseRPC{})
	id := installDelegationForTest(t, manager, 52, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := manager.Write(t.Context(), id, 0, []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	var scopes []delegationCloseScope
	err := manager.closeHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(52, 2), epoch: manager.epochSerial}}, &scopes)
	var cleanup delegationCleanupError
	if !errors.As(err, &cleanup) || len(scopes) != 1 {
		t.Fatalf("close did not capture the failed ownership: error=%v scopes=%v", err, scopes)
	}
	// closeHandles has now ended its releaseFlight. The deferred consumer of
	// its error can be descheduled while a newly opened handle takes ownership.
	successor := delegationTestGrant(85, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	successor.Generation = 2
	if err := manager.Install(id, delegationTestToken(52, 1), delegationTestToken(52, 3), successor); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Write(t.Context(), id, 0, []byte("next"), false); err != nil {
		t.Fatal(err)
	}
	loss, stats := manager.LossSequence(), manager.buf.Stats()
	manager.failCloseScopes(scopes, "deferred descriptor cleanup refused", true)
	manager.failCloseScopes(scopes, "asynchronous delegated close failed", false)
	if !manager.Owns(id) || manager.LossSequence() != loss || manager.buf.Stats().Entries != stats.Entries || manager.buf.Stats().Bytes != stats.Bytes {
		t.Fatalf("old close discarded successor: owns=%v loss=%d->%d stats=%+v", manager.Owns(id), loss, manager.LossSequence(), manager.buf.Stats())
	}
}
