//go:build linux

package fusev3

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type operationWaitContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *operationWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

// A truncating OPEN can await a peer withdrawal while that peer's read needs
// our CONTROL cut. Neither CONTROL progress nor foreground exclusion may rely
// on a timeout breaking that cycle.
func TestSynchronousOperationAllowsRequiredControlBeforeItsReply(t *testing.T) {
	for _, kind := range []string{"break", "recall", "mode"} {
		t.Run(kind, func(t *testing.T) {
			m := newDelegationTestManager(t, &delegationFakeRPC{})
			id := installDelegationForTest(t, m, 114, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			entered, resume := make(chan struct{}), make(chan struct{})
			finished := make(chan error, 1)
			go func() {
				_, err := m.Synchronous(t.Context(), id, func(*authoritypb.DelegationRef) (*authoritypb.Response, error) {
					close(entered)
					select {
					case <-resume:
						return &authoritypb.Response{}, nil
					case <-m.ctx.Done():
						return nil, m.ctx.Err()
					}
				})
				finished <- err
			}()
			<-entered
			var once sync.Once
			defer once.Do(func() { close(resume) })
			parsed, _ := delegationIdentity(id)
			state := m.retainState(parsed, false)
			defer m.releaseState(state)
			waitCtx := &operationWaitContext{Context: t.Context(), waiting: make(chan struct{})}
			next := make(chan error, 1)
			go func() {
				err := state.lockAfterRelease(waitCtx, delegationOperation)
				if err == nil {
					state.operation.Unlock()
				}
				next <- err
			}()
			select {
			case <-waitCtx.waiting:
			case <-time.After(time.Second):
				t.Fatal("later local operation did not wait for the synchronous owner")
			}
			ref := &authoritypb.DelegationRef{Id: delegationTestGrant(146, authoritypb.DelegationMode_DELEGATION_MODE_FULL).Id, Generation: 1}
			event := &authoritypb.ControlEvent{Incarnation: 7, Sequence: 1}
			switch kind {
			case "break":
				event.Event = &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{Identity: id, Delegation: ref, BudgetNanos: uint64(5 * time.Second)}}
			case "recall":
				event.Event = &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{Identity: id, Delegation: ref, BudgetNanos: uint64(5 * time.Second)}}
			case "mode":
				event.Event = &authoritypb.ControlEvent_DelegationModeChange{DelegationModeChange: &authoritypb.DelegationModeChange{Identity: id, Delegation: ref, Mode: authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH, BudgetNanos: uint64(5 * time.Second)}}
			}
			done := m.HandleControlEvent(t.Context(), event)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("CONTROL waited for the RPC that requires its acknowledgment")
			}
			if m.LossSequence() != 0 {
				t.Fatal("CONTROL completed by losing the grant")
			}
			select {
			case err := <-next:
				t.Fatalf("foreground exclusion ended before synchronous reply: %v", err)
			default:
			}
			once.Do(func() { close(resume) })
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("synchronous call did not complete")
			}
			select {
			case err := <-next:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("foreground owner was stranded")
			}
		})
	}
}

type openVisibilityRPC struct {
	delegationFakeRPC
	manager *delegationManager
	id      []byte
	grant   *authoritypb.Delegation
}

func (f *openVisibilityRPC) CallMutation(ctx context.Context, req *authoritypb.Request) (*authoritypb.Response, error) {
	if req.GetBarrier() != nil {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.delegationFakeRPC.CallMutation(ctx, req)
}

func (f *openVisibilityRPC) CallIdempotent(ctx context.Context, req *authoritypb.Request) (*authoritypb.Response, error) {
	if req.GetWaitVisibility() != nil {
		done := f.manager.HandleControlEvent(ctx, &authoritypb.ControlEvent{Incarnation: 7, Sequence: 2, Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{
			Identity: f.id, Delegation: &authoritypb.DelegationRef{Id: f.grant.Id, Generation: f.grant.Generation}, BudgetNanos: uint64(5 * time.Second),
		}}})
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.delegationFakeRPC.CallIdempotent(ctx, req)
}

func TestSynchronousOpenPublishesGrantBeforeWaitingForVisibility(t *testing.T) {
	fake := &openVisibilityRPC{}
	m := newDelegationTestManager(t, fake)
	fake.manager = m
	id := installDelegationForTest(t, m, 115, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	fake.id = id
	fake.grant = delegationTestGrant(147, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reply := make(chan *authoritypb.Response, 1)
	failure := make(chan error, 1)
	go func() {
		response, err := m.Synchronous(ctx, id, func(*authoritypb.DelegationRef) (*authoritypb.Response, error) {
			return &authoritypb.Response{AppliedSequence: 1, Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: delegationTestToken(115, 3), Delegation: fake.grant}}}, nil
		})
		if err != nil {
			failure <- err
			return
		}
		reply <- response
	}()
	var response *authoritypb.Response
	select {
	case response = <-reply:
	case err := <-failure:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("OPEN waited for visibility before registering its grant")
	}
	if err := m.Install(id, delegationTestToken(115, 1), response.GetOpen().Handle, response.GetOpen().Delegation); err != nil {
		t.Fatal(err)
	}
	visible := make(chan error, 1)
	go func() { visible <- m.openedVisibility(ctx, id, response) }()
	select {
	case err := <-visible:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("registered grant could not complete the visibility cut")
	}
	if fakeControlCount(&fake.delegationFakeRPC, func(req *authoritypb.Request) bool { return req.GetDelegationBreakAck() != nil }) != 1 {
		t.Fatal("visibility completed without the required break")
	}
}
