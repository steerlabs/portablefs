package volumeserver

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type dependencyModelOperation struct {
	name         string
	dependencies MutationDependencies
	observations map[string]struct{}
}

func modelInode(id byte) [16]byte { return [16]byte{id} }

func modelObservations(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func modelInodeObservation(id byte) string { return fmt.Sprintf("inode:%02x", id) }

func modelNameObservation(parent byte, name string) string {
	return fmt.Sprintf("name:%02x:%s", parent, name)
}

func modelItemOperation(name string, identities ...byte) dependencyModelOperation {
	gate := SourcePublicationGate{}
	observations := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		gate.Targets = append(gate.Targets, SourcePublicationTarget{
			Identity: modelInode(identity), Attributes: true, Data: true,
		})
		observations[modelInodeObservation(identity)] = struct{}{}
	}
	sort.Slice(gate.Targets, func(i, j int) bool {
		return compareSourcePublicationTargets(gate.Targets[i], gate.Targets[j]) < 0
	})
	return dependencyModelOperation{name: name, dependencies: mutationDependenciesForSourceGate(gate), observations: observations}
}

func modelNamespaceOperation(name string, parent byte, binding string, bound ...byte) dependencyModelOperation {
	target := SourcePublicationTarget{
		ParentIdentity: modelInode(parent), Name: []byte(binding), BoundAttributes: true,
	}
	observations := modelObservations(
		modelInodeObservation(parent),
		modelNameObservation(parent, binding),
	)
	for _, identity := range bound {
		target.BoundIdentities = append(target.BoundIdentities, modelInode(identity))
		observations[modelInodeObservation(identity)] = struct{}{}
	}
	return dependencyModelOperation{
		name:         name,
		dependencies: mutationDependenciesForSourceGate(SourcePublicationGate{Targets: []SourcePublicationTarget{target}}),
		observations: observations,
	}
}

func modelLinkOperation(parent byte, binding string, existing byte) dependencyModelOperation {
	gate := SourcePublicationGate{Targets: []SourcePublicationTarget{
		{Identity: modelInode(existing), Attributes: true},
		{ParentIdentity: modelInode(parent), Name: []byte(binding), BoundAttributes: true},
	}}
	return dependencyModelOperation{
		name:         "link",
		dependencies: mutationDependenciesForSourceGate(gate),
		observations: modelObservations(modelInodeObservation(parent), modelNameObservation(parent, binding), modelInodeObservation(existing)),
	}
}

func modelRenameOperation(oldParent byte, oldName string, newParent byte, newName string, moved byte, replaced ...byte) dependencyModelOperation {
	oldTarget := SourcePublicationTarget{
		ParentIdentity: modelInode(oldParent), Name: []byte(oldName), BoundAttributes: true,
		BoundIdentities: [][16]byte{modelInode(moved)},
	}
	newTarget := SourcePublicationTarget{
		ParentIdentity: modelInode(newParent), Name: []byte(newName), BoundAttributes: true,
	}
	observations := modelObservations(
		modelInodeObservation(oldParent), modelNameObservation(oldParent, oldName),
		modelInodeObservation(newParent), modelNameObservation(newParent, newName),
		modelInodeObservation(moved),
	)
	for _, identity := range replaced {
		newTarget.BoundIdentities = append(newTarget.BoundIdentities, modelInode(identity))
		observations[modelInodeObservation(identity)] = struct{}{}
	}
	gate := SourcePublicationGate{Targets: []SourcePublicationTarget{oldTarget, newTarget}}
	sort.Slice(gate.Targets, func(i, j int) bool {
		return compareSourcePublicationTargets(gate.Targets[i], gate.Targets[j]) < 0
	})
	return dependencyModelOperation{name: "rename", dependencies: mutationDependenciesForSourceGate(gate), observations: observations}
}

func modelOperationsConflict(left, right dependencyModelOperation) bool {
	for observation := range left.observations {
		if _, ok := right.observations[observation]; ok {
			return true
		}
	}
	return false
}

func dependencySetsOverlap(left, right MutationDependencies) bool {
	for _, key := range left.keys {
		if right.contains([]byte(key)) {
			return true
		}
	}
	return false
}

func TestMutationDependencySchemaCoversCachedObservationClasses(t *testing.T) {
	tests := []struct {
		name       string
		left       dependencyModelOperation
		right      dependencyModelOperation
		wantShared bool
	}{
		{
			name:  "rename versus create at target",
			left:  modelRenameOperation(1, "old", 2, "target", 9, 10),
			right: modelNamespaceOperation("create", 2, "target"), wantShared: true,
		},
		{
			name:  "unlink versus write of bound inode",
			left:  modelNamespaceOperation("unlink", 1, "victim", 9),
			right: modelItemOperation("write", 9), wantShared: true,
		},
		{
			name:  "two renames sharing directory attrs",
			left:  modelRenameOperation(1, "a", 2, "b", 9),
			right: modelRenameOperation(3, "c", 1, "d", 10), wantShared: true,
		},
		{
			name:  "rmdir versus create in removed directory",
			left:  modelNamespaceOperation("rmdir", 1, "dir", 7),
			right: modelNamespaceOperation("create child", 7, "child"), wantShared: true,
		},
		{
			name:  "copy source versus source write",
			left:  modelItemOperation("copy_file_range", 8, 9),
			right: modelItemOperation("write source", 8), wantShared: true,
		},
		{
			name:  "copy destination versus destination fallocate",
			left:  modelItemOperation("copy_file_range", 8, 9),
			right: modelItemOperation("fallocate destination", 9), wantShared: true,
		},
		{
			name:  "link versus inode setattr",
			left:  modelLinkOperation(2, "hardlink", 9),
			right: modelItemOperation("setattr", 9), wantShared: true,
		},
		{
			name:  "disjoint inode writes",
			left:  modelItemOperation("write one", 8),
			right: modelItemOperation("write two", 9), wantShared: false,
		},
		{
			name:  "different names still share directory attrs",
			left:  modelNamespaceOperation("create a", 2, "a"),
			right: modelNamespaceOperation("create b", 2, "b"), wantShared: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := modelOperationsConflict(test.left, test.right); got != test.wantShared {
				t.Fatalf("modeled observation conflict = %t, want %t", got, test.wantShared)
			}
			if got := dependencySetsOverlap(test.left.dependencies, test.right.dependencies); got != test.wantShared {
				t.Fatalf("dependency overlap = %t, want %t", got, test.wantShared)
			}
		})
	}
}

func randomDependencyModelOperation(random *rand.Rand, index int) dependencyModelOperation {
	parent := byte(1 + random.Intn(6))
	otherParent := byte(1 + random.Intn(6))
	identity := byte(16 + random.Intn(12))
	otherIdentity := byte(16 + random.Intn(12))
	name := fmt.Sprintf("n%d", random.Intn(8))
	otherName := fmt.Sprintf("n%d", random.Intn(8))
	switch random.Intn(9) {
	case 0:
		return modelItemOperation(fmt.Sprintf("write-%d", index), identity)
	case 1:
		return modelItemOperation(fmt.Sprintf("setattr-%d", index), identity)
	case 2:
		return modelItemOperation(fmt.Sprintf("copy-%d", index), identity, otherIdentity)
	case 3:
		return modelNamespaceOperation(fmt.Sprintf("create-%d", index), parent, name)
	case 4:
		return modelNamespaceOperation(fmt.Sprintf("unlink-%d", index), parent, name, identity)
	case 5:
		return modelNamespaceOperation(fmt.Sprintf("mkdir-%d", index), parent, name)
	case 6:
		return modelNamespaceOperation(fmt.Sprintf("rmdir-%d", index), parent, name, identity)
	case 7:
		return modelLinkOperation(parent, name, identity)
	default:
		return modelRenameOperation(parent, name, otherParent, otherName, identity, otherIdentity)
	}
}

func TestMutationDependencySchemaRandomizedModel(t *testing.T) {
	for seed := int64(1); seed <= 32; seed++ {
		random := rand.New(rand.NewSource(seed))
		operations := make([]dependencyModelOperation, 128)
		for index := range operations {
			operations[index] = randomDependencyModelOperation(random, index)
		}
		for left := range operations {
			for right := left + 1; right < len(operations); right++ {
				if modelOperationsConflict(operations[left], operations[right]) &&
					!dependencySetsOverlap(operations[left].dependencies, operations[right].dependencies) {
					t.Fatalf("seed %d operations %q and %q share a cached observation but no dependency key",
						seed, operations[left].name, operations[right].name)
				}
			}
		}
	}
}

func TestMutationSequencerRandomizedSchedulingModel(t *testing.T) {
	for seed := int64(1); seed <= 16; seed++ {
		random := rand.New(rand.NewSource(seed))
		operations := make([]dependencyModelOperation, 96)
		sequencer := newMutationSequencer()
		waiters := make([]*mutationSequencerWaiter, len(operations))
		for index := range operations {
			operations[index] = randomDependencyModelOperation(random, index)
			waiters[index] = sequencer.enqueue(operations[index].dependencies)
		}

		var sequence atomic.Uint64
		var modelMu sync.Mutex
		active := make(map[string]uint64)
		lastOrdinal := make(map[string]uint64)
		lastSequence := make(map[string]uint64)
		errorsSeen := make(chan error, len(operations)*16)
		completed := make(chan struct{})
		var group sync.WaitGroup
		group.Add(len(operations))
		for index, waiter := range waiters {
			index, waiter := index, waiter
			go func() {
				defer group.Done()
				<-waiter.ready
				chosen := sequence.Add(1)
				modelMu.Lock()
				for _, key := range operations[index].dependencies.keys {
					if owner := active[key]; owner != 0 {
						errorsSeen <- fmt.Errorf("seed %d key %x concurrently owned by ordinals %d and %d", seed, key, owner, waiter.ordinal)
					}
					if prior := lastOrdinal[key]; prior >= waiter.ordinal {
						errorsSeen <- fmt.Errorf("seed %d key %x ordinal regressed from %d to %d", seed, key, prior, waiter.ordinal)
					}
					if prior := lastSequence[key]; prior >= chosen {
						errorsSeen <- fmt.Errorf("seed %d key %x sequence regressed from %d to %d", seed, key, prior, chosen)
					}
					active[key] = waiter.ordinal
					lastOrdinal[key] = waiter.ordinal
					lastSequence[key] = chosen
				}
				modelMu.Unlock()

				for count := 0; count < index%5; count++ {
					runtime.Gosched()
				}
				if index%7 == 0 {
					time.Sleep(time.Microsecond)
				}

				modelMu.Lock()
				for _, key := range operations[index].dependencies.keys {
					delete(active, key)
				}
				modelMu.Unlock()
				waiter.release()
			}()
		}
		go func() {
			group.Wait()
			close(completed)
		}()
		select {
		case <-completed:
		case <-time.After(5 * time.Second):
			t.Fatalf("seed %d dependency mix deadlocked", seed)
		}
		close(errorsSeen)
		for err := range errorsSeen {
			t.Error(err)
		}
	}
}

func TestVisibilityCoordinatorAppliesDisjointInodesConcurrently(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	leftSource, rightSource := SessionID{1}, SessionID{2}
	h.register(t, leftSource, testRepairBudget)
	h.register(t, rightSource, testRepairBudget)

	release := make(chan struct{})
	entered := make(chan byte, 2)
	sequences := make(chan uint64, 2)
	results := make(chan error, 2)
	start := func(source SessionID, identity byte) {
		gate := SourcePublicationGate{Targets: []SourcePublicationTarget{{
			Identity: modelInode(identity), Attributes: true, Data: true,
		}}}
		declaration := h.coordinator.DeclareSourceGate(gate)
		go func() {
			sequence, err := h.coordinator.ExecuteWithSourceGateSequence(
				context.Background(), source, MutationID{Sequence: uint64(identity)}, declaration, gate,
				func() (SourcePublicationGate, error) { return gate, nil },
				func() ([]VisibilityTarget, error) {
					return []VisibilityTarget{{Scope: VisibilityData, Identity: modelInode(identity)}}, nil
				},
				func(chosen uint64) ([]VisibilityTarget, bool) {
					entered <- identity
					<-release
					return []VisibilityTarget{{Scope: VisibilityData, Identity: modelInode(identity)}}, true
				},
				func() ([]VisibilityResolution, error) { return nil, nil },
			)
			sequences <- sequence
			results <- err
		}()
	}
	start(leftSource, 21)
	start(rightSource, 22)
	for count := 0; count < 2; count++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("disjoint inode mutations did not reach apply concurrently")
		}
	}
	close(release)
	for count := 0; count < 2; count++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	leftSequence, rightSequence := <-sequences, <-sequences
	if leftSequence == 0 || rightSequence == 0 || leftSequence == rightSequence {
		t.Fatalf("disjoint visibility sequences = %d, %d", leftSequence, rightSequence)
	}
}

func TestVisibilityDisjointPeerBarriersAndStabilizeProceedIndependently(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	leftPeer, rightPeer, observer := SessionID{1}, SessionID{2}, SessionID{3}
	h.register(t, leftPeer, testRepairBudget)
	h.register(t, rightPeer, testRepairBudget)
	h.register(t, observer, testRepairBudget)
	leftIdentity, rightIdentity := modelInode(41), modelInode(42)
	h.coordinator.RecordResolvedInode(leftPeer, leftIdentity)
	h.coordinator.RecordResolvedInode(rightPeer, rightIdentity)

	leftRelease, rightRelease := make(chan struct{}), make(chan struct{})
	leftApplied, rightApplied := make(chan struct{}), make(chan struct{})
	results := make(chan error, 2)
	start := func(source SessionID, identity [16]byte, applied chan<- struct{}, release <-chan struct{}) {
		targets := []VisibilityTarget{{Scope: VisibilityData, Identity: identity, KernelIno: uint64(identity[0]), Device: 1}}
		go func() {
			results <- h.coordinator.Execute(
				context.Background(), source, MutationID{Sequence: uint64(identity[0])},
				mutationDependenciesForTargets(targets),
				func() ([]VisibilityTarget, error) { return targets, nil },
				func() ([]VisibilityTarget, bool) {
					close(applied)
					<-release
					return targets, true
				},
			)
		}()
	}
	start(SessionID{8}, leftIdentity, leftApplied, leftRelease)
	start(SessionID{9}, rightIdentity, rightApplied, rightRelease)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	leftPrepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, leftPeer)
	if err != nil {
		t.Fatal(err)
	}
	rightPrepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, rightPeer)
	if err != nil {
		t.Fatal("right disjoint PREPARE did not open beside left PREPARE:", err)
	}

	type stabilizeResult struct {
		identity byte
		waited   bool
		err      error
	}
	stabilized := make(chan stabilizeResult, 2)
	for _, identity := range [][16]byte{leftIdentity, rightIdentity} {
		identity := identity
		go func() {
			waited, stabilizeErr := h.coordinator.Stabilize(ctx, observer, VisibilityResolution{Identity: identity})
			stabilized <- stabilizeResult{identity: identity[0], waited: waited, err: stabilizeErr}
		}()
	}
	select {
	case got := <-stabilized:
		t.Fatalf("observer stabilized inode %d before its apply: %+v", got.identity, got)
	case <-time.After(20 * time.Millisecond):
	}

	if err := h.coordinator.Ack(leftPeer, leftPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	<-leftApplied
	close(leftRelease)
	got := <-stabilized
	if got.identity != leftIdentity[0] || !got.waited || got.err != nil {
		t.Fatalf("left stabilization = %+v, want inode %d after wait", got, leftIdentity[0])
	}
	select {
	case got := <-stabilized:
		t.Fatalf("right stabilization escaped when only left applied: %+v", got)
	case <-time.After(20 * time.Millisecond):
	}
	leftComplete, err := h.coordinator.Next(ctx, leftPeer, leftPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(leftPeer, leftComplete.Cursor); err != nil {
		t.Fatal(err)
	}

	if err := h.coordinator.Ack(rightPeer, rightPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	<-rightApplied
	close(rightRelease)
	got = <-stabilized
	if got.identity != rightIdentity[0] || !got.waited || got.err != nil {
		t.Fatalf("right stabilization = %+v, want inode %d after wait", got, rightIdentity[0])
	}
	rightComplete, err := h.coordinator.Next(ctx, rightPeer, rightPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightPeer, rightComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	for count := 0; count < 2; count++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkMutationSequencerDisjointScaling(b *testing.B) {
	const turnWork = 50 * time.Microsecond
	b.Run("global_turn_model", func(b *testing.B) {
		var turn sync.Mutex
		b.RunParallel(func(parallel *testing.PB) {
			for parallel.Next() {
				turn.Lock()
				time.Sleep(turnWork)
				turn.Unlock()
			}
		})
	})
	b.Run("dependency_keys", func(b *testing.B) {
		sequencer := newMutationSequencer()
		var worker atomic.Uint32
		b.RunParallel(func(parallel *testing.PB) {
			identity := byte(worker.Add(1))
			dependencies := testInodeDependencies(identity)
			for parallel.Next() {
				waiter, err := sequencer.acquire(context.Background(), dependencies)
				if err != nil {
					b.Fatal(err)
				}
				time.Sleep(turnWork)
				waiter.release()
			}
		})
	})
}
