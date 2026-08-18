package volumeserver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func testInodeDependencies(ids ...byte) MutationDependencies {
	keys := make([][]byte, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, inodeKey([16]byte{id}))
	}
	return newMutationDependencies(keys...)
}

func waitForMutationSequencerQueue(t *testing.T, sequencer *mutationSequencer, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for sequencer.queued() != want {
		if time.Now().After(deadline) {
			t.Fatalf("queued mutation dependency sets = %d, want %d", sequencer.queued(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForVisibilityLaneWaiters(t *testing.T, coordinator *VisibilityCoordinator, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		coordinator.mu.Lock()
		got := len(coordinator.laneWaiters)
		coordinator.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("visibility lane waiters = %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMutationSequencerGrantsDisjointSetAlongsideOwner(t *testing.T) {
	sequencer := newMutationSequencer()
	owner, err := sequencer.acquire(t.Context(), testInodeDependencies(1))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.release()

	disjoint, err := sequencer.acquire(t.Context(), testInodeDependencies(2, 3))
	if err != nil {
		t.Fatal(err)
	}
	disjoint.release()
}

func TestMutationSequencerIsFIFOPerKeyWithoutLeapfrog(t *testing.T) {
	sequencer := newMutationSequencer()
	owner, err := sequencer.acquire(context.Background(), testInodeDependencies(1))
	if err != nil {
		t.Fatal(err)
	}

	first := sequencer.enqueue(testInodeDependencies(1, 2))
	second := sequencer.enqueue(testInodeDependencies(2))
	third := sequencer.enqueue(testInodeDependencies(3))
	select {
	case <-third.ready:
		third.release()
	case <-time.After(2 * time.Second):
		t.Fatal("disjoint waiter did not pass blocked dependency chain")
	}
	select {
	case <-second.ready:
		t.Fatal("later waiter leapfrogged an earlier waiter on a shared key")
	default:
	}

	owner.release()
	select {
	case <-first.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("first conflicting waiter was not granted")
	}
	first.release()
	select {
	case <-second.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("second conflicting waiter was not granted")
	}
	second.release()
}

func TestMutationSequencerCancellationRemovesMultiKeyWaiter(t *testing.T) {
	sequencer := newMutationSequencer()
	owner, err := sequencer.acquire(context.Background(), testInodeDependencies(1))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, acquireErr := sequencer.acquire(ctx, testInodeDependencies(1, 2))
		result <- acquireErr
	}()
	waitForMutationSequencerQueue(t, sequencer, 1)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
	owner.release()

	probe, err := sequencer.acquire(t.Context(), testInodeDependencies(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	probe.release()
}

func TestMutationSequencerRequeueKeepsOrdinalAndClosesBindingGap(t *testing.T) {
	sequencer := newMutationSequencer()
	inodeOwner, err := sequencer.acquire(context.Background(), testInodeDependencies(2))
	if err != nil {
		t.Fatal(err)
	}
	waiter, err := sequencer.acquire(context.Background(), testInodeDependencies(1))
	if err != nil {
		t.Fatal(err)
	}
	later := sequencer.enqueue(testInodeDependencies(1))

	waiter.requeue(testInodeDependencies(1, 2))
	select {
	case <-later.ready:
		t.Fatal("later binding mutation entered during dependency requeue")
	default:
	}
	inodeOwner.release()
	select {
	case <-waiter.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("requeued dependency set did not complete")
	}
	waiter.release()
	select {
	case <-later.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("later binding mutation did not follow requeued owner")
	}
	later.release()
}

func TestMutationSequencerReservationNeverBlocksAbsentClaimant(t *testing.T) {
	sequencer := newMutationSequencer()
	_ = sequencer.reserveOrdinal()
	waiter, err := sequencer.acquire(t.Context(), testInodeDependencies(1))
	if err != nil {
		t.Fatal(err)
	}
	waiter.release()
}

func TestMutationSequencerBindingVersionsLiveOnlyForActiveDeclarations(t *testing.T) {
	sequencer := newMutationSequencer()
	dependencies := newMutationDependencies(nameKey(modelInode(1), []byte("child")))
	snapshot := sequencer.snapshot(dependencies)
	waiter, err := sequencer.acquire(t.Context(), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	waiter.release()
	if sequencer.unchanged(snapshot) {
		t.Fatal("binding mutation was not visible to its pre-resolution declaration")
	}
	sequencer.mu.Lock()
	retained := len(sequencer.versions)
	sequencer.mu.Unlock()
	if retained != 0 {
		t.Fatalf("idle dependency versions retained = %d, want zero", retained)
	}
}

func TestMutationDependenciesCoverageRequiresNamespaceObservationKeys(t *testing.T) {
	parent, bound := modelInode(1), modelInode(2)
	targets := []VisibilityTarget{{
		Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("child"),
		RelatedIdentities: [][16]byte{bound},
	}}
	partial := newMutationDependencies(targets[0].key(), inodeKey(parent))
	if partial.covers(targets) {
		t.Fatal("namespace footprint without its bound inode passed dependency coverage")
	}
	if complete := mutationDependenciesForTargets(targets); !complete.covers(targets) {
		t.Fatal("canonical namespace dependency footprint did not cover its target")
	}
}

func TestVisibilityNamespaceRevalidationRepeatsAfterOlderReservation(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.register(t, source, testRepairBudget)

	gate := testSourcePublicationGate("child")
	var oldIdentity, intermediateIdentity, finalIdentity [16]byte
	oldIdentity[0], intermediateIdentity[0], finalIdentity[0] = 0x31, 0x32, 0x33
	gate.Targets[0].BoundIdentities = [][16]byte{oldIdentity}
	declaration := h.coordinator.DeclareSourceGate(gate)
	binding := bindingDependenciesForSourceGate(gate)

	// Make the pre-resolution declaration stale, then reserve an ordinal before
	// Execute enqueues. The reserved waiter is claimed only during the first
	// refresh, which models a dormant frontend fairness credit becoming active.
	changed, err := h.coordinator.sequencer.acquire(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	changed.release()
	reserved := h.coordinator.sequencer.reserveOrdinal()
	current := intermediateIdentity
	var refreshes atomic.Int32
	refresh := func() (SourcePublicationGate, error) {
		refreshed := cloneSourcePublicationGate(gate)
		refreshed.Targets[0].BoundIdentities = [][16]byte{current}
		if refreshes.Add(1) == 1 {
			older := h.coordinator.sequencer.enqueueFor(binding, reserved)
			go func() {
				<-older.ready
				current = finalIdentity
				older.release()
			}()
		}
		return refreshed, nil
	}
	targets := testVisibilityTargets("child")
	err = h.coordinator.ExecuteWithSourceGate(
		context.Background(), source, MutationID{Sequence: 1}, declaration, gate, refresh,
		func() ([]VisibilityTarget, error) { return targets, nil },
		func() ([]VisibilityTarget, bool) { return targets, true },
		func() ([]VisibilityResolution, error) { return nil, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := refreshes.Load(); got != 3 {
		t.Fatalf("namespace refreshes = %d, want initial correction, older-waiter correction, and stable proof", got)
	}

	h.coordinator.mu.Lock()
	participant := h.coordinator.participants[source]
	hasIntermediate := participant.index.contains(inodeKey(intermediateIdentity))
	hasFinal := participant.index.contains(inodeKey(finalIdentity))
	h.coordinator.mu.Unlock()
	if hasIntermediate || !hasFinal {
		t.Fatalf("source index intermediate/final binding = %t/%t, want false/true", hasIntermediate, hasFinal)
	}
}
