package volumeserver

import (
	"context"
	"errors"
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
	targets := []MutationTarget{{
		Scope: MutationNamespace, ParentIdentity: parent, Name: []byte("child"),
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

func TestMutationNamespaceRevalidationRepeatsAfterBindingChange(t *testing.T) {
	storage := NewStorageSequencer()
	footprint := testMutationFootprint("child")
	deps := bindingDependenciesForFootprint(footprint)
	declaration := storage.Declare(deps)
	release, err := storage.Acquire(t.Context(), deps)
	if err != nil {
		t.Fatal(err)
	}
	release()
	release, unchanged, err := storage.AcquireDeclared(t.Context(), deps, declaration)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if unchanged {
		t.Fatal("changed binding accepted under its old declaration")
	}
	declaration = storage.Declare(deps)
	release, unchanged, err = storage.AcquireDeclared(t.Context(), deps, declaration)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if !unchanged {
		t.Fatal("stable refreshed binding was refused")
	}
}
