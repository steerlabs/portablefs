package volumeserver

import (
	"errors"
	"testing"
	"time"
)

type mountLifecycleMembership struct {
	active      map[SessionID]struct{}
	activateErr error
	removeErr   error
	activates   int
	deactivates int
}

func (m *mountLifecycleMembership) Activate(id SessionID) error {
	m.activates++
	if m.activateErr != nil {
		return m.activateErr
	}
	if m.active == nil {
		m.active = make(map[SessionID]struct{})
	}
	m.active[id] = struct{}{}
	return nil
}

func (m *mountLifecycleMembership) Deactivate(id SessionID) error {
	m.deactivates++
	if m.removeErr != nil {
		return m.removeErr
	}
	delete(m.active, id)
	return nil
}

func TestMountLifecycleSolelyOwnsFskitDurableMembership(t *testing.T) {
	now := time.Unix(100, 0)
	membership := &mountLifecycleMembership{}
	lifecycle, err := NewMountLifecycle(MountLifecycleConfig{
		Membership: membership, Prior: PriorEpochStrictMountsFenced, Now: func() time.Time { return now }, ClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	fencer := newTestFencer()
	visibility, err := NewVisibilityCoordinator(VisibilityConfig{
		Membership: membership, Prior: PriorEpochStrictMountsFenced, Fencer: fencer,
		MaxCachedNameCapacity: testCacheCapacity, MaxRepairBudget: testRepairBudget, MaxClockSkew: time.Second,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	id := leaseTestID(9)
	terminal := fencer.attach(id)
	if err := lifecycle.Activate(id, func() error {
		_, activateErr := visibility.ActivateParticipantInMemory(
			id, CoherenceStrict, terminal, testVisibilityCommitment(), nil, func() {},
		)
		return activateErr
	}); err != nil {
		t.Fatal(err)
	}
	if membership.activates != 1 {
		t.Fatalf("durable Activate calls = %d, want exactly 1", membership.activates)
	}
	proof := MountAbsenceProof{Component: "test", Observation: []byte{1}, ObservedUnixNanos: now.UnixNano()}
	if err := lifecycle.CleanDetach(id, proof, func() error {
		return visibility.CleanDetachInMemory(id, proof)
	}); err != nil {
		t.Fatal(err)
	}
	if membership.deactivates != 1 {
		t.Fatalf("durable Deactivate calls = %d, want exactly 1", membership.deactivates)
	}

	failingID := leaseTestID(10)
	failingTerminal := fencer.attach(failingID)
	publishErr := errors.New("retain activation reply")
	if err := lifecycle.Activate(failingID, func() error {
		_, activateErr := visibility.ActivateParticipantInMemory(
			failingID, CoherenceStrict, failingTerminal, testVisibilityCommitment(),
			func(VisibilityCursor) ([][16]byte, error) { return nil, publishErr }, func() {},
		)
		return activateErr
	}); !errors.Is(err, publishErr) {
		t.Fatalf("failed activation = %v, want %v", err, publishErr)
	}
	if membership.activates != 2 || membership.deactivates != 2 {
		t.Fatalf("activation rollback calls = %d/%d, want 2/2", membership.activates, membership.deactivates)
	}
}

func TestMountLifecyclePriorUnprovenOnlyBlocksRouteChanges(t *testing.T) {
	membership := &mountLifecycleMembership{}
	lifecycle, err := NewMountLifecycle(MountLifecycleConfig{Membership: membership, Prior: PriorEpochUnproven})
	if err != nil {
		t.Fatal(err)
	}
	id := leaseTestID(1)
	if err := lifecycle.Activate(id, func() error { return nil }); err != nil {
		t.Fatalf("Activate during prior uncertainty: %v", err)
	}
	if err := lifecycle.RequireCleanRouteAbsence(); !errors.Is(err, ErrLeaseRoutesLive) {
		t.Fatalf("route absence = %v, want %v", err, ErrLeaseRoutesLive)
	}
	if _, ok := membership.active[id]; !ok {
		t.Fatal("new activation was not durably recorded")
	}
}

func TestMountLifecycleActivationRollbackAndExactCleanDetach(t *testing.T) {
	now := time.Unix(100, 0)
	membership := &mountLifecycleMembership{}
	lifecycle, err := NewMountLifecycle(MountLifecycleConfig{
		Membership: membership, Prior: PriorEpochStrictMountsFenced, Now: func() time.Time { return now }, ClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := leaseTestID(1)
	publishErr := errors.New("publish failed")
	if err := lifecycle.Activate(id, func() error { return publishErr }); !errors.Is(err, publishErr) {
		t.Fatalf("failed Activate = %v, want %v", err, publishErr)
	}
	if _, ok := membership.active[id]; ok {
		t.Fatal("failed activation remained durable")
	}
	if err := lifecycle.Activate(id, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.CleanDetach(id, MountAbsenceProof{}, func() error { return nil }); !errors.Is(err, ErrVisibilityProof) {
		t.Fatalf("incomplete CleanDetach = %v, want %v", err, ErrVisibilityProof)
	}
	removed := false
	proof := MountAbsenceProof{ObservedUnixNanos: now.UnixNano(), Observation: []byte("mount gone"), Component: "test"}
	if err := lifecycle.CleanDetach(id, proof, func() error { removed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("clean detach did not remove process-local holder")
	}
	if _, ok := membership.active[id]; ok {
		t.Fatal("clean detach retained durable membership")
	}
	if err := lifecycle.RequireCleanRouteAbsence(); err != nil {
		t.Fatalf("route remained blocked after clean absence: %v", err)
	}
}

func TestMountLifecycleFailedDurableActivationRollbackBlocksRoutes(t *testing.T) {
	membership := &mountLifecycleMembership{}
	lifecycle, err := NewMountLifecycle(MountLifecycleConfig{Membership: membership, Prior: PriorEpochStrictMountsFenced})
	if err != nil {
		t.Fatal(err)
	}
	membership.removeErr = errors.New("durable deactivate failed")
	publishErr := errors.New("runtime publish failed")
	if err := lifecycle.Activate(leaseTestID(1), func() error { return publishErr }); !errors.Is(err, publishErr) || !errors.Is(err, membership.removeErr) {
		t.Fatalf("Activate error = %v, want joined publish and rollback failures", err)
	}
	if err := lifecycle.RequireCleanRouteAbsence(); !errors.Is(err, ErrLeaseRoutesLive) {
		t.Fatalf("route absence after failed durable rollback = %v, want %v", err, ErrLeaseRoutesLive)
	}
}
