//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"

	"google.golang.org/protobuf/proto"
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

// Done observes the select boundary without changing time or cancelling a
// successful schedule. With uncontended locks it is the unreported-grant wait;
// with a synchronous apply pinned it is the operation-lock wait.
type allocatingControlContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *allocatingControlContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func allocatingResponse(create bool, id, handle []byte, grant *authoritypb.Delegation, ticket uint64) *authoritypb.Response {
	response := &authoritypb.Response{AppliedSequence: ticket}
	if create {
		response.Body = &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: &authoritypb.Item{StableIdentity: id}, Handle: handle, Delegation: grant}}
	} else {
		response.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: handle, Delegation: grant}}
	}
	return response
}

func awaitAllocatingControl(t *testing.T, done <-chan struct{}, boundary string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("did not reach %s", boundary)
	}
}

func requireAllocatingBreak(t *testing.T, fake *delegationFakeRPC, grant *authoritypb.Delegation, ticket, event uint64) {
	t.Helper()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var found int
	for _, req := range fake.controls {
		if ack := req.GetDelegationBreakAck(); ack != nil && ack.EventSequence == event {
			found++
			if !sameDelegation(ack.Delegation, &authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}) || ack.AppliedSequence != ticket || ack.Incarnation != 7 {
				t.Fatalf("break ack=%v, want exact grant, ticket %d, incarnation 7", ack, ticket)
			}
		}
	}
	if found != 1 {
		t.Fatalf("event %d acknowledged %d times", event, found)
	}
}

func TestAllocatingControlBeforeRegistrationInstallsExactApplicationCut(t *testing.T) {
	for _, create := range []bool{false, true} {
		name := "OPEN"
		if create {
			name = "CREATE"
		}
		t.Run(name, func(t *testing.T) {
			fake := &delegationFakeRPC{}
			m := newDelegationTestManager(t, fake)
			id, item, handle := delegationTestIdentity(120), delegationTestToken(120, 1), delegationTestToken(120, 2)
			grant := delegationTestGrant(153, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			response := allocatingResponse(create, id, handle, grant, 7)
			history, err := m.beginGrantRequest()
			if err != nil {
				t.Fatal(err)
			}
			defer m.endGrantRequest(history)
			parsed, _ := delegationIdentity(id)
			state := m.retainState(parsed, true)
			defer m.releaseState(state)
			controlCtx, cancelControl := context.WithCancel(t.Context())
			ctx := &allocatingControlContext{Context: controlCtx, waiting: make(chan struct{})}
			done := make(chan struct{})
			// The real event worker is invoked directly so its context exposes the
			// precise wait, rather than only observing a goroutine launch.
			go func() {
				defer close(done)
				m.handleControlEvent(ctx, controlBreakForTest(id, grant, 3), state, m.epochSerial)
			}()
			defer func() {
				cancelControl()
				awaitAllocatingControl(t, done, "CONTROL worker cleanup")
			}()
			awaitAllocatingControl(t, ctx.waiting, "CONTROL waiting for DATA registration")
			if !state.transition.TryLock() {
				t.Fatal("unreported grant wait holds transition")
			}
			state.transition.Unlock()
			if !state.operation.TryLock() {
				t.Fatal("unreported grant wait holds operation")
			}
			state.operation.Unlock()
			if fakeControlCount(fake, func(req *authoritypb.Request) bool { return req.GetDelegationBreakAck() != nil }) != 0 {
				t.Fatal("unseen grant was acknowledged")
			}
			if err := m.install(id, item, handle, grant, response.AppliedSequence); err != nil {
				t.Fatal(err)
			}
			awaitAllocatingControl(t, done, "exact application break")
			requireAllocatingBreak(t, fake, grant, 7, 3)
			if !m.Owns(id) || m.LossSequence() != 0 {
				t.Fatal("healthy DATA/CONTROL reordering lost ownership")
			}

			recall := &authoritypb.ControlEvent{Incarnation: 7, Sequence: 4, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{Identity: id, Delegation: &authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}, BudgetNanos: uint64(5 * time.Second)}}}
			awaitAllocatingControl(t, m.HandleControlEvent(t.Context(), recall), "retirement before delayed DATA")
			if err := m.install(id, item, handle, grant, response.AppliedSequence); !errors.Is(err, errDelegationRetired) {
				t.Fatalf("delayed DATA install=%v", err)
			}
			if m.Owns(id) || m.LossSequence() != 0 {
				t.Fatal("delayed DATA resurrected the retired grant or lost data")
			}
			successor := proto.Clone(grant).(*authoritypb.Delegation)
			successor.Generation++
			successor.Id = delegationTestIdentity(154)
			if err := m.install(id, item, delegationTestToken(120, 3), successor, 0); err != nil {
				t.Fatal(err)
			}
			awaitAllocatingControl(t, m.HandleControlEvent(t.Context(), controlBreakForTest(id, successor, 5)), "successor empty break")
			requireAllocatingBreak(t, fake, successor, 0, 5)
		})
	}
}

type allocatingVisibilityRPC struct {
	delegationFakeRPC
	waiting   chan struct{}
	withdrawn chan struct{}
}

func (f *allocatingVisibilityRPC) CallMutation(ctx context.Context, req *authoritypb.Request) (*authoritypb.Response, error) {
	if req.GetBarrier() != nil {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.delegationFakeRPC.CallMutation(ctx, req)
}
func (f *allocatingVisibilityRPC) CallIdempotent(ctx context.Context, req *authoritypb.Request) (*authoritypb.Response, error) {
	if req.GetWaitVisibility() != nil {
		close(f.waiting)
		select {
		case <-f.withdrawn:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.delegationFakeRPC.CallIdempotent(ctx, req)
}

func TestPublicAllocatingApplicationServicesControlBeforeWithdrawal(t *testing.T) {
	for _, create := range []bool{false, true} {
		name := "OPEN"
		if create {
			name = "CREATE"
		}
		t.Run(name, func(t *testing.T) {
			fake := &allocatingVisibilityRPC{waiting: make(chan struct{}), withdrawn: make(chan struct{})}
			m := newDelegationTestManager(t, fake)
			id := installDelegationForTest(t, m, 121, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			grant := delegationTestGrant(153, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			parsed, _ := delegationIdentity(id)
			state := m.retainState(parsed, false)
			defer m.releaseState(state)
			applying, apply := make(chan struct{}), make(chan struct{})
			applyCtx, cancelApply := context.WithCancel(t.Context())
			var applyOnce, withdrawalOnce sync.Once
			finishApply := func() { applyOnce.Do(func() { close(apply) }) }
			withdraw := func() { withdrawalOnce.Do(func() { close(fake.withdrawn) }) }
			defer cancelApply()
			defer withdraw()
			defer finishApply()
			outcome := make(chan error, 1)
			go func() {
				response, err := m.Synchronous(applyCtx, id, func(ref *authoritypb.DelegationRef) (*authoritypb.Response, error) {
					close(applying)
					<-apply
					return allocatingResponse(create, id, delegationTestToken(121, 3), grant, 7), nil
				})
				if err == nil {
					err = m.install(id, delegationTestToken(121, 1), delegationTestToken(121, 3), grant, response.AppliedSequence)
				}
				if err == nil {
					err = m.openedVisibility(applyCtx, id, response)
				}
				outcome <- err
			}()
			awaitAllocatingControl(t, applying, "synchronous application")
			controlCtx, cancelControl := context.WithCancel(t.Context())
			ctx := &allocatingControlContext{Context: controlCtx, waiting: make(chan struct{})}
			cut := make(chan struct{})
			go func() {
				defer close(cut)
				m.handleControlEvent(ctx, controlBreakForTest(id, grant, 6), state, m.epochSerial)
			}()
			defer func() {
				finishApply()
				cancelApply()
				cancelControl()
				awaitAllocatingControl(t, cut, "CONTROL worker cleanup")
			}()
			awaitAllocatingControl(t, ctx.waiting, "CONTROL behind real application")
			if fakeControlCount(&fake.delegationFakeRPC, func(req *authoritypb.Request) bool { return req.GetDelegationBreakAck() != nil }) != 0 {
				t.Fatal("CONTROL bypassed pending application")
			}
			finishApply()
			awaitAllocatingControl(t, cut, "application receipt releases CONTROL")
			requireAllocatingBreak(t, &fake.delegationFakeRPC, grant, 7, 6)
			awaitAllocatingControl(t, fake.waiting, "explicit visibility wait")
			select {
			case err := <-outcome:
				t.Fatalf("allocation completed before withdrawal: %v", err)
			default:
			}
			withdraw()
			select {
			case err := <-outcome:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("allocation did not finish after withdrawal")
			}
			if m.LossSequence() != 0 {
				t.Fatal("application/visibility ordering lost ownership")
			}
		})
	}
}
