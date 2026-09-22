//go:build linux

package fusev3

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func lifetimeGrantRequest(t *testing.T, m *delegationManager) uint64 {
	t.Helper()
	request, err := m.beginGrantRequest()
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func lifetimeIdentity(n uint64) []byte {
	id := make([]byte, 16)
	binary.LittleEndian.PutUint64(id, n)
	return id
}

func awaitDelegationCollection(t *testing.T, m *delegationManager, identity []byte) {
	t.Helper()
	id, _ := delegationIdentity(identity)
	deadline := time.Now().Add(time.Second)
	for {
		m.reapIdleStates()
		m.mu.RLock()
		state := m.byID[id]
		m.mu.RUnlock()
		if state == nil {
			if generation, _ := m.buf.RetainedGeneration(id); generation != 0 {
				t.Fatalf("collected delegation retained buffer generation %d", generation)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("idle delegation was not collected")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDelegationLifetimeCleanIdentityChurn(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	for n := uint64(1); n <= 1000; n++ {
		id, handle := lifetimeIdentity(n), lifetimeIdentity(n+1000)
		if err := m.Install(id, id, handle, delegationTestGrant(1, authoritypb.DelegationMode_DELEGATION_MODE_FULL)); err != nil {
			t.Fatal(err)
		}
		if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: handle}}); err != nil {
			t.Fatal(err)
		}
		awaitDelegationCollection(t, m, id)
	}
	m.EpochChanged("clean churn")
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.byID) != 0 || len(m.identityLoss) != 0 || len(m.observers) != 0 || len(m.reclaim) != 0 {
		t.Fatalf("clean churn retained states=%d loss=%d observers=%d candidates=%d", len(m.byID), len(m.identityLoss), len(m.observers), len(m.reclaim))
	}
}

func TestDelegationLifetimeGenerationChurnWithOpenObserver(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := lifetimeIdentity(1)
	m.beginLossObserver(id)
	for n := uint64(1); n <= 500; n++ {
		grant := delegationTestGrant(1, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
		grant.Generation = n
		handle := lifetimeIdentity(n + 1000)
		if err := m.Install(id, id, handle, grant); err != nil {
			t.Fatal(err)
		}
		if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: handle}}); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "obsolete generation bindings to retire", func() bool {
			m.reapIdleStates()
			sid, _ := delegationIdentity(id)
			state := m.retainState(sid, false)
			if state == nil {
				t.Fatal("live observer lost its identity state")
			}
			state.admission.RLock()
			bindings := len(state.bindings)
			state.admission.RUnlock()
			m.releaseState(state)
			return bindings <= 1
		})
	}
	m.endLossObserver(id)
	awaitDelegationCollection(t, m, id)
}

func TestDelegationLifetimeLossSurvivesResetUntilLastObserver(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 41, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	first, second := m.beginLossObserver(id), m.beginLossObserver(id)
	if _, err := m.Write(t.Context(), id, 0, []byte("retained"), false); err != nil {
		t.Fatal(err)
	}
	m.EpochChanged("observer loss")
	loss := m.LossSequence()
	if got, _ := m.IdentityFailure(id, first); got != loss || got == first {
		t.Fatalf("first observer loss=%d, want %d after %d", got, loss, first)
	}
	m.endLossObserver(id)
	m.EpochChanged("second reset")
	if got, _ := m.IdentityFailure(id, second); got != loss || got == second {
		t.Fatalf("remaining observer loss=%d, want %d after %d", got, loss, second)
	}
	m.endLossObserver(id)
	m.mu.RLock()
	history, observers := len(m.identityLoss), len(m.observers)
	m.mu.RUnlock()
	if history != 0 || observers != 0 || m.LossSequence() != loss {
		t.Fatalf("history=%d observers=%d mount loss=%d, want 0,0,%d", history, observers, m.LossSequence(), loss)
	}
	if err := m.Barrier(t.Context(), first); !errors.Is(err, writeback.ErrLost) {
		t.Fatalf("collection hid root barrier loss: %v", err)
	}
}

func TestDelegationLifetimeCreateAndPublicationPins(t *testing.T) {
	for _, kind := range []string{"create response", "holder publication"} {
		t.Run(kind, func(t *testing.T) {
			m := newDelegationTestManager(t, &delegationFakeRPC{})
			id := installDelegationForTest(t, m, 42, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			sid, _ := delegationIdentity(id)
			var state *delegationState
			var request uint64
			if kind == "create response" {
				request = lifetimeGrantRequest(t, m)
			} else {
				state = m.retainState(sid, false)
			}
			if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(42, 2)}}); err != nil {
				t.Fatal(err)
			}
			m.reapIdleStates()
			if m.lookupState(sid) == nil {
				t.Fatal("collected state before pending registration/publication settled")
			}
			if err := m.Install(id, id, lifetimeIdentity(99), delegationTestGrant(74, authoritypb.DelegationMode_DELEGATION_MODE_FULL)); !errors.Is(err, errDelegationRetired) {
				t.Fatalf("late retired grant accepted: %v", err)
			}
			if kind == "create response" {
				m.endGrantRequest(request)
			} else {
				m.releaseState(state)
			}
			awaitDelegationCollection(t, m, id)
		})
	}
}

func TestDelegationLifetimeLaterCreatesDoNotExtendRetirementCut(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 46, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	older := lifetimeGrantRequest(t, m)
	if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(46, 2)}}); err != nil {
		t.Fatal(err)
	}
	m.reapIdleStates()
	sid, _ := delegationIdentity(id)
	if m.lookupState(sid) == nil {
		t.Fatal("forgot tombstone while an older grant request could still register")
	}
	later := lifetimeGrantRequest(t, m)
	defer m.endGrantRequest(later)
	m.endGrantRequest(older)
	awaitDelegationCollection(t, m, id)
}

type lifetimeBlockedWriteRPC struct {
	delegationFakeRPC
	started chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (f *lifetimeBlockedWriteRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetWrite() != nil {
		f.once.Do(func() { close(f.started) })
		select {
		case <-f.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

func TestDelegationLifetimeConcurrentFlushRecallCloseAndReopen(t *testing.T) {
	fake := &lifetimeBlockedWriteRPC{started: make(chan struct{}), resume: make(chan struct{})}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 43, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	sid, _ := delegationIdentity(id)
	if _, err := m.Write(t.Context(), id, 0, []byte("accepted"), false); err != nil {
		t.Fatal(err)
	}
	flush := make(chan error, 1)
	go func() { _, err := m.FlushIdentity(t.Context(), id); flush <- err }()
	select {
	case <-fake.started:
	case <-time.After(time.Second):
		t.Fatal("flush did not start")
	}
	state := m.retainState(sid, false)
	closed := make(chan error, 1)
	go func() {
		closed <- m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(43, 2)}})
	}()
	grant := delegationTestGrant(75, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	recalled := m.HandleControlEvent(t.Context(), &authoritypb.ControlEvent{Incarnation: 7, Sequence: 99, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{Delegation: cloneDelegationRef(&authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}), Identity: id, BudgetNanos: uint64(time.Second)}}})
	m.reapIdleStates()
	if m.lookupState(sid) != state {
		t.Fatal("in-flight flush/close/recall split identity state")
	}
	close(fake.resume)
	if err := <-flush; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	<-recalled
	grant.Generation++
	newHandle := lifetimeIdentity(900)
	if err := m.Install(id, id, newHandle, grant); err != nil {
		t.Fatal(err)
	}
	if m.lookupState(sid) != state {
		t.Fatal("reopen replaced a state still in use")
	}
	m.releaseState(state)
	if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: newHandle}}); err != nil {
		t.Fatal(err)
	}
	m.VisibleSequence(^uint64(0))
	m.DurableSequence(^uint64(0))
	awaitDelegationCollection(t, m, id)
}

func TestDelegationLifetimeStaleCloseReleasesLossObserver(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 44, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	n := &node{mount: &Mount{delegations: m}, item: &authoritypb.Item{StableIdentity: id, Token: id}}
	handle := &fileHandle{node: n, token: delegationTestToken(44, 2)}
	if err := n.registerDelegatedHandle(handle, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(t.Context(), id, 0, []byte("lost"), false); err != nil {
		t.Fatal(err)
	}
	m.EpochChanged("old handle")
	handle.stale.Store(true)
	for range 2 {
		if errno := handle.close(t.Context(), 0, false); errno != syscall.EIO {
			t.Fatalf("stale close=%v", errno)
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.observers) != 0 || len(m.identityLoss) != 0 {
		t.Fatal("stale close retained observation or released it more than once")
	}
}

type lifetimeFileDurabilityRPC struct{ delegationFakeRPC }

func (f *lifetimeFileDurabilityRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		return nil, errors.New("unrelated durability cut is stalled")
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}

func (f *lifetimeFileDurabilityRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetFsync() != nil {
		// A different inode can keep the common durable prefix at zero while
		// this descriptor's successful FSYNC retires its own records.
		return &authoritypb.Response{Body: &authoritypb.Response_Fsync{Fsync: &authoritypb.FsyncReply{}}}, nil
	}
	return f.delegationFakeRPC.CallIdempotent(ctx, request)
}

func TestDelegationLifetimeFileFsyncRetiresReplayProgress(t *testing.T) {
	m := newDelegationTestManager(t, &lifetimeFileDurabilityRPC{})
	id := installDelegationForTest(t, m, 45, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	for range 100 {
		if _, err := m.Write(t.Context(), id, 0, []byte("durable"), false); err != nil {
			t.Fatal(err)
		}
		if err := m.Fsync(t.Context(), id, false); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "file durability replay progress to retire", func() bool {
			m.reapIdleStates()
			m.tokenMu.Lock()
			defer m.tokenMu.Unlock()
			return len(m.tokens) == 0
		})
	}
}

func lifetimeControlEvent(kind string, identity []byte, ref *authoritypb.DelegationRef) *authoritypb.ControlEvent {
	event := &authoritypb.ControlEvent{Incarnation: 7, Sequence: 1}
	switch kind {
	case "recall":
		event.Event = &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{Identity: identity, Delegation: ref, BudgetNanos: uint64(time.Millisecond)}}
	case "break":
		event.Event = &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{Identity: identity, Delegation: ref, BudgetNanos: uint64(time.Millisecond)}}
	case "mode":
		event.Event = &authoritypb.ControlEvent_DelegationModeChange{DelegationModeChange: &authoritypb.DelegationModeChange{Identity: identity, Delegation: ref, BudgetNanos: uint64(time.Millisecond), Mode: authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH}}
	}
	return event
}

func TestDelegationLifetimeTimedOutUnseenControlRejectsLateGrant(t *testing.T) {
	for _, kind := range []string{"recall", "break", "mode"} {
		t.Run(kind, func(t *testing.T) {
			m := newDelegationTestManager(t, &delegationFakeRPC{})
			request := lifetimeGrantRequest(t, m)
			defer m.endGrantRequest(request)
			id := lifetimeIdentity(501)
			grant := delegationTestGrant(17, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			ref := &authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}
			<-m.HandleControlEvent(t.Context(), lifetimeControlEvent(kind, id, ref))
			if err := m.Install(id, id, lifetimeIdentity(502), grant); !errors.Is(err, errDelegationRetired) {
				t.Fatalf("grant whose %s budget elapsed was installed: %v", kind, err)
			}
		})
	}
}

func TestDelegationLifetimeControlTimeoutWhileOperationIsBusyDropsMatchingGrant(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 47, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("accepted"), false); err != nil {
		t.Fatal(err)
	}
	sid, _ := delegationIdentity(id)
	state := m.retainState(sid, false)
	defer m.releaseState(state)
	state.operation.Lock()
	defer state.operation.Unlock()
	grant := delegationTestGrant(79, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	ref := &authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}
	<-m.HandleControlEvent(t.Context(), lifetimeControlEvent("recall", id, ref))
	if m.Owns(id) || m.IdentityLoss(id) == 0 || m.buf.Stats().Entries != 0 {
		t.Fatal("control lock timeout retained grant or failed to account for accepted loss")
	}
}

func TestDelegationLifetimeControlTimeoutPreservesNewerGrant(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := lifetimeIdentity(503)
	grant := delegationTestGrant(18, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	grant.Generation = 2
	if err := m.Install(id, id, lifetimeIdentity(504), grant); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(t.Context(), id, 0, []byte("successor"), false); err != nil {
		t.Fatal(err)
	}
	sid, _ := delegationIdentity(id)
	state := m.retainState(sid, false)
	defer m.releaseState(state)
	m.epoch.RLock()
	m.retireTimedOutControl(state, &authoritypb.DelegationRef{Id: grant.Id, Generation: 1})
	m.epoch.RUnlock()
	if !m.Owns(id) || m.IdentityLoss(id) != 0 || m.buf.Stats().Entries != 1 {
		t.Fatal("old control timeout discarded a newer grant or its accepted writes")
	}
}

func TestDelegationLifetimeControlTimeoutRenewsRetirementCut(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := lifetimeIdentity(505)
	sid, _ := delegationIdentity(id)
	state := m.retainState(sid, true)
	older := lifetimeGrantRequest(t, m)
	m.mu.Lock()
	state.collectCut, state.collectThrough = true, older
	m.mu.Unlock()
	m.endGrantRequest(older)
	request := lifetimeGrantRequest(t, m)
	grant := delegationTestGrant(19, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	ref := &authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}
	<-m.HandleControlEvent(t.Context(), lifetimeControlEvent("recall", id, ref))
	m.releaseState(state)
	waitFor(t, "control state release", func() bool { return state.users.Load() == 0 })
	m.reapIdleStates()
	if m.lookupState(sid) != state {
		t.Fatal("new control tombstone inherited a completed older request cut")
	}
	if err := m.Install(id, id, lifetimeIdentity(506), grant); !errors.Is(err, errDelegationRetired) {
		t.Fatalf("newly timed-out grant was resurrected: %v", err)
	}
	m.endGrantRequest(request)
	awaitDelegationCollection(t, m, id)
}

func TestDelegationLifetimeGrantRequestSerialCannotWrap(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	m.mu.Lock()
	m.grantSerial = ^uint64(0)
	m.mu.Unlock()
	if request, err := m.beginGrantRequest(); err == nil || request != 0 {
		t.Fatalf("exhausted grant request serial=(%d, %v)", request, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.grantRequests) != 0 || m.grantSerial != ^uint64(0) {
		t.Fatal("serial exhaustion mutated request tracking")
	}
}

func TestDelegationLifetimeOldIncarnationControlCannotRetireCurrentGrant(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 48, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	sid, _ := delegationIdentity(id)
	state := m.retainState(sid, false)
	defer m.releaseState(state)
	grant := delegationTestGrant(80, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	ref := &authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}
	event := lifetimeControlEvent("recall", id, ref)
	m.SetIncarnation(8)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// Model a previously validated event whose worker starts after the current
	// incarnation changes. Even its expired budget cannot create a tombstone.
	m.handleControlEvent(ctx, event, state, m.epochSerial)
	if !m.Owns(id) || m.IdentityLoss(id) != 0 {
		t.Fatal("old-incarnation control retired the current grant")
	}
	state.admission.RLock()
	retired := state.retiredGeneration
	state.admission.RUnlock()
	if retired != 0 {
		t.Fatalf("old-incarnation control installed retirement generation %d", retired)
	}
}
