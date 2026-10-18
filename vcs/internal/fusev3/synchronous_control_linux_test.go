//go:build linux

package fusev3

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

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
	if err := m.install(id, delegationTestToken(115, 1), response.GetOpen().Handle, response.GetOpen().Delegation, response.GetAppliedSequence()); err != nil {
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

// The Authority returns the application receipt before awaiting peer cache
// withdrawal. That receipt must release the local operation lock before the
// explicit visibility wait, so CONTROL can finish the peer's pending read.
func TestSynchronousApplicationReceiptAllowsControlBeforeVisibility(t *testing.T) {
	fake := &openVisibilityRPC{}
	m := newDelegationTestManager(t, fake)
	fake.manager = m
	id := installDelegationForTest(t, m, 115, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	fake.id = id
	fake.grant = delegationTestGrant(147, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := m.Synchronous(ctx, id, func(*authoritypb.DelegationRef) (*authoritypb.Response, error) {
			return &authoritypb.Response{AppliedSequence: 1}, nil
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("synchronous application held CONTROL behind visibility")
	}
	if fakeControlCount(&fake.delegationFakeRPC, func(req *authoritypb.Request) bool { return req.GetDelegationBreakAck() != nil }) != 1 {
		t.Fatal("visibility completed without the required read cut")
	}
}

func TestOpenedApplicationCutBelongsToItsReturnedGrant(t *testing.T) {
	fake := &openVisibilityRPC{}
	m := newDelegationTestManager(t, fake)
	fake.manager = m
	fake.id = delegationTestIdentity(119)
	fake.grant = delegationTestGrant(152, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	response := &authoritypb.Response{AppliedSequence: 7, Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: delegationTestToken(119, 2), Delegation: fake.grant}}}
	if err := m.install(fake.id, delegationTestToken(119, 1), response.GetOpen().Handle, fake.grant, response.GetAppliedSequence()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.openedVisibility(ctx, fake.id, response) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("new OPEN's application cut could not satisfy its break")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, req := range fake.controls {
		if ack := req.GetDelegationBreakAck(); ack != nil {
			if ack.GetAppliedSequence() != 7 {
				t.Fatalf("break cut=%d want OPEN application 7", ack.GetAppliedSequence())
			}
			return
		}
	}
	t.Fatal("OPEN's visibility completed without a break")
}
