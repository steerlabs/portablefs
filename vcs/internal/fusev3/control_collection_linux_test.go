//go:build linux

package fusev3

import (
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func controlBreakForTest(id []byte, grant *authoritypb.Delegation, sequence uint64) *authoritypb.ControlEvent {
	return &authoritypb.ControlEvent{Incarnation: 7, Sequence: sequence, Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{Identity: id, Delegation: &authoritypb.DelegationRef{Id: grant.Id, Generation: grant.Generation}, BudgetNanos: uint64(5 * time.Second)}}}
}

func TestCollectedGrantRejectsDelayedControlDuringSuccessorOpen(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 116, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(116, 2)}}); err != nil {
		t.Fatal(err)
	}
	parsed, _ := delegationIdentity(id)
	waitFor(t, "retired identity collection", func() bool { m.reapIdleStates(); m.mu.RLock(); defer m.mu.RUnlock(); return m.byID[parsed] == nil })
	history, err := m.beginGrantRequest()
	if err != nil {
		t.Fatal(err)
	}
	defer m.endGrantRequest(history)
	// The next OPEN may be waiting for a peer read which this stale event
	// overtook. Waiting for its new grant here would form another five-second
	// cycle. No elapsed-time allowance is needed to identify the retired grant.
	done := m.HandleControlEvent(t.Context(), controlBreakForTest(id, delegationTestGrant(148, authoritypb.DelegationMode_DELEGATION_MODE_FULL), 1))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("collected grant was mistaken for an unreported successor")
	}
	successor := delegationTestGrant(149, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	successor.Generation = 2
	if err := m.Install(id, delegationTestToken(116, 1), delegationTestToken(116, 3), successor); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(t.Context(), id, 0, []byte("successor"), false); err != nil {
		t.Fatal(err)
	}
	if !m.Owns(id) || m.LossSequence() != 0 || m.buf.Stats().Accepted != 1 {
		t.Fatal("stale control affected successor ownership")
	}
}

func TestCollectionFloorWaitsForUnreportedGrantsAndPreservesLiveOlderGrant(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	history, err := m.beginGrantRequest()
	if err != nil {
		t.Fatal(err)
	}
	id := delegationTestIdentity(117)
	high := delegationTestGrant(150, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	high.Generation = 4
	if err := m.Install(id, delegationTestToken(117, 1), delegationTestToken(117, 2), high); err != nil {
		t.Fatal(err)
	}
	if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(117, 2)}}); err != nil {
		t.Fatal(err)
	}
	m.reapIdleStates()
	m.mu.RLock()
	floor := m.retiredGrantFloor
	m.mu.RUnlock()
	if floor != 0 {
		t.Fatalf("collection passed an unreported grant: floor=%d", floor)
	}
	lowerID := delegationTestIdentity(118)
	lower := delegationTestGrant(151, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	lower.Generation = 3
	done := m.HandleControlEvent(t.Context(), controlBreakForTest(lowerID, lower, 1))
	if err := m.Install(lowerID, delegationTestToken(118, 1), delegationTestToken(118, 2), lower); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unreported older grant did not receive its CONTROL cut")
	}
	m.endGrantRequest(history)
	waitFor(t, "global retired floor", func() bool { m.reapIdleStates(); m.mu.RLock(); defer m.mu.RUnlock(); return m.retiredGrantFloor == 4 })
	done = m.HandleControlEvent(t.Context(), controlBreakForTest(lowerID, lower, 2))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("live older grant was hidden by collection floor")
	}
	if fakeControlCount(fake, func(req *authoritypb.Request) bool { return req.GetDelegationBreakAck() != nil }) != 2 {
		t.Fatal("collection floor skipped a live grant's cut")
	}
}
