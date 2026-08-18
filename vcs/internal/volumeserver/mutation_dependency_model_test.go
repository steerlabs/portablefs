package volumeserver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type dependencyModelOperation struct {
	name     string
	gate     SourcePublicationGate
	targets  []VisibilityTarget
	produces [16]byte
}

func modelInode(id byte) [16]byte { return [16]byte{id} }

func modelInodeTarget(scope VisibilityScope, identity [16]byte) VisibilityTarget {
	return VisibilityTarget{Scope: scope, Identity: identity, KernelIno: uint64(identity[0]), Device: 1}
}

func modelNameTarget(parent [16]byte, name string, related ...[16]byte) VisibilityTarget {
	return VisibilityTarget{
		Scope: VisibilityNamespace, ParentIdentity: parent, ParentKernelIno: uint64(parent[0]), Device: 1,
		Name: []byte(name), RelatedIdentities: append([][16]byte(nil), related...),
	}
}

func (operation dependencyModelOperation) dependencies() MutationDependencies {
	return mutationDependenciesForSourceGate(operation.gate)
}

// observationKeys derives the read side independently from the exact
// coordinates Stabilize publishes. It deliberately does not inspect the
// mutation dependency builder: deleting parent or RelatedIdentities coverage
// there makes this model fail.
func (operation dependencyModelOperation) observationKeys() map[string]struct{} {
	resolutions := make([]VisibilityResolution, 0, len(operation.targets)*2)
	for _, target := range operation.targets {
		if target.Scope == VisibilityNamespace {
			resolutions = append(resolutions, VisibilityResolution{Parent: target.ParentIdentity, Name: target.Name})
			for _, identity := range target.RelatedIdentities {
				resolutions = append(resolutions, VisibilityResolution{Identity: identity})
			}
			continue
		}
		resolutions = append(resolutions, VisibilityResolution{Identity: target.Identity})
	}
	keys := make(map[string]struct{}, len(resolutions)*2)
	for _, resolution := range resolutions {
		for _, key := range resolution.keys() {
			keys[string(key)] = struct{}{}
		}
	}
	return keys
}

func modelItemOperation(name string, identities ...byte) dependencyModelOperation {
	targets := make([]VisibilityTarget, 0, len(identities))
	gate := SourcePublicationGate{}
	for _, identity := range identities {
		targets = append(targets, modelInodeTarget(VisibilityData, modelInode(identity)))
		gate.Targets = append(gate.Targets, SourcePublicationTarget{
			Identity: modelInode(identity), Attributes: true, Data: true,
		})
	}
	return dependencyModelOperation{name: name, gate: gate, targets: targets}
}

func modelCreateOperation(name string, parent byte, binding string, created byte) dependencyModelOperation {
	return dependencyModelOperation{
		name: name,
		gate: SourcePublicationGate{Targets: []SourcePublicationTarget{
			{Identity: modelInode(parent), Attributes: true},
			{ParentIdentity: modelInode(parent), Name: []byte(binding), BoundAttributes: true},
		}},
		targets: []VisibilityTarget{
			modelNameTarget(modelInode(parent), binding),
			modelInodeTarget(VisibilityAttributes, modelInode(parent)),
		},
		// The identity is learned only after apply. No other operation can name
		// it until this namespace publication completes, so it is a result, not
		// a pre-apply dependency.
		produces: modelInode(created),
	}
}

func modelRemoveOperation(name string, parent byte, binding string, bound byte) dependencyModelOperation {
	return dependencyModelOperation{
		name: name,
		gate: SourcePublicationGate{Targets: []SourcePublicationTarget{
			{Identity: modelInode(parent), Attributes: true},
			{
				ParentIdentity: modelInode(parent), Name: []byte(binding), BoundAttributes: true,
				BoundIdentities: [][16]byte{modelInode(bound)},
			},
		}},
		targets: []VisibilityTarget{
			modelNameTarget(modelInode(parent), binding, modelInode(bound)),
			modelInodeTarget(VisibilityAttributes, modelInode(parent)),
			modelInodeTarget(VisibilityAttributes, modelInode(bound)),
		},
	}
}

func modelLinkOperation(parent byte, binding string, existing byte) dependencyModelOperation {
	return dependencyModelOperation{
		name: "link",
		gate: SourcePublicationGate{Targets: []SourcePublicationTarget{
			{Identity: modelInode(existing), Attributes: true},
			{Identity: modelInode(parent), Attributes: true},
			{ParentIdentity: modelInode(parent), Name: []byte(binding), BoundAttributes: true},
		}},
		targets: []VisibilityTarget{
			modelNameTarget(modelInode(parent), binding, modelInode(existing)),
			modelInodeTarget(VisibilityAttributes, modelInode(parent)),
			modelInodeTarget(VisibilityAttributes, modelInode(existing)),
		},
	}
}

func modelRenameOperation(oldParent byte, oldName string, newParent byte, newName string, moved byte, replaced ...byte) dependencyModelOperation {
	oldTarget := modelNameTarget(modelInode(oldParent), oldName, modelInode(moved))
	newTarget := modelNameTarget(modelInode(newParent), newName, modelInode(moved))
	targets := []VisibilityTarget{
		oldTarget,
		newTarget,
		modelInodeTarget(VisibilityAttributes, modelInode(oldParent)),
		modelInodeTarget(VisibilityAttributes, modelInode(newParent)),
		modelInodeTarget(VisibilityAttributes, modelInode(moved)),
	}
	for _, identity := range replaced {
		newTarget.RelatedIdentities = append(newTarget.RelatedIdentities, modelInode(identity))
		targets = append(targets, modelInodeTarget(VisibilityAttributes, modelInode(identity)))
	}
	targets[1] = newTarget
	oldGateTarget := SourcePublicationTarget{
		ParentIdentity: modelInode(oldParent), Name: []byte(oldName), BoundAttributes: true,
		BoundIdentities: [][16]byte{modelInode(moved)},
	}
	newGateTarget := SourcePublicationTarget{
		ParentIdentity: modelInode(newParent), Name: []byte(newName), BoundAttributes: true,
	}
	for _, identity := range replaced {
		newGateTarget.BoundIdentities = append(newGateTarget.BoundIdentities, modelInode(identity))
	}
	return dependencyModelOperation{
		name: "rename",
		gate: SourcePublicationGate{Targets: []SourcePublicationTarget{
			{Identity: modelInode(oldParent), Attributes: true},
			{Identity: modelInode(newParent), Attributes: true},
			oldGateTarget,
			newGateTarget,
		}},
		targets: targets,
	}
}

func modelOperationsConflict(left, right dependencyModelOperation) bool {
	rightObservations := right.observationKeys()
	for observation := range left.observationKeys() {
		if _, ok := rightObservations[observation]; ok {
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
			right: modelCreateOperation("create", 2, "target", 11), wantShared: true,
		},
		{
			name:  "unlink versus write of bound inode",
			left:  modelRemoveOperation("unlink", 1, "victim", 9),
			right: modelItemOperation("write", 9), wantShared: true,
		},
		{
			name:  "two renames sharing directory attrs",
			left:  modelRenameOperation(1, "a", 2, "b", 9),
			right: modelRenameOperation(3, "c", 1, "d", 10), wantShared: true,
		},
		{
			name:  "rmdir versus create in removed directory",
			left:  modelRemoveOperation("rmdir", 1, "dir", 7),
			right: modelCreateOperation("create child", 7, "child", 11), wantShared: true,
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
			left:  modelCreateOperation("create a", 2, "a", 8),
			right: modelCreateOperation("create b", 2, "b", 9), wantShared: true,
		},
		{
			name:  "symlink versus negative lookup at same binding",
			left:  modelCreateOperation("symlink", 2, "missing", 8),
			right: modelCreateOperation("create", 2, "missing", 9), wantShared: true,
		},
		{
			name:  "copy endpoint versus rename replacement",
			left:  modelItemOperation("copy_file_range", 8, 9),
			right: modelRenameOperation(1, "old", 2, "target", 10, 9), wantShared: true,
		},
		{
			name:  "setattr directory versus child create",
			left:  modelItemOperation("setattr parent", 7),
			right: modelCreateOperation("create child", 7, "child", 11), wantShared: true,
		},
		{
			name:  "fresh identity is not a pre-apply dependency",
			left:  modelCreateOperation("create", 2, "fresh", 11),
			right: modelItemOperation("later write", 11), wantShared: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := modelOperationsConflict(test.left, test.right); got != test.wantShared {
				t.Fatalf("modeled observation conflict = %t, want %t", got, test.wantShared)
			}
			if got := dependencySetsOverlap(test.left.dependencies(), test.right.dependencies()); got != test.wantShared {
				t.Fatalf("dependency overlap = %t, want %t", got, test.wantShared)
			}
		})
	}
}

func randomDependencyModelOperation(random *rand.Rand, index int) dependencyModelOperation {
	// Parents, bound children, and item mutations intentionally draw from one
	// pool. Directory identities are ordinary inode identities: separating the
	// pools would hide parent-setattr and rmdir/child-create conflicts.
	identityFromPool := func() byte { return byte(1 + random.Intn(12)) }
	parent := identityFromPool()
	otherParent := identityFromPool()
	identity := identityFromPool()
	otherIdentity := identityFromPool()
	createdIdentity := identityFromPool()
	name := fmt.Sprintf("n%d", random.Intn(8))
	otherName := fmt.Sprintf("n%d", random.Intn(8))
	switch random.Intn(12) {
	case 0:
		return modelItemOperation(fmt.Sprintf("write-%d", index), identity)
	case 1:
		return modelItemOperation(fmt.Sprintf("setattr-%d", index), identity)
	case 2:
		return modelItemOperation(fmt.Sprintf("copy-%d", index), identity, otherIdentity)
	case 3:
		return modelCreateOperation(fmt.Sprintf("create-%d", index), parent, name, createdIdentity)
	case 4:
		return modelRemoveOperation(fmt.Sprintf("unlink-%d", index), parent, name, identity)
	case 5:
		return modelCreateOperation(fmt.Sprintf("mkdir-%d", index), parent, name, createdIdentity)
	case 6:
		return modelRemoveOperation(fmt.Sprintf("rmdir-%d", index), parent, name, identity)
	case 7:
		return modelLinkOperation(parent, name, identity)
	case 8:
		return modelRenameOperation(parent, name, otherParent, otherName, identity, otherIdentity)
	case 9:
		return modelCreateOperation(fmt.Sprintf("symlink-%d", index), parent, name, createdIdentity)
	case 10:
		return modelItemOperation(fmt.Sprintf("fallocate-%d", index), identity)
	default:
		return modelItemOperation(fmt.Sprintf("truncate-%d", index), identity)
	}
}

func TestMutationDependencySchemaRandomizedModel(t *testing.T) {
	for seed := int64(1); seed <= 32; seed++ {
		random := rand.New(rand.NewSource(seed))
		operations := make([]dependencyModelOperation, 128)
		for index := range operations {
			operations[index] = randomDependencyModelOperation(random, index)
			if dependencies := operations[index].dependencies(); !dependencies.covers(operations[index].targets) {
				t.Fatalf("seed %d operation %q source gate does not cover its visibility targets", seed, operations[index].name)
			}
		}
		for left := range operations {
			for right := left + 1; right < len(operations); right++ {
				if modelOperationsConflict(operations[left], operations[right]) &&
					!dependencySetsOverlap(operations[left].dependencies(), operations[right].dependencies()) {
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

		// Cancellation of several multi-key waiters must remove every reservation
		// before the common owner is released.
		cancelOwner, err := sequencer.acquire(t.Context(), testInodeDependencies(250))
		if err != nil {
			t.Fatal(err)
		}
		cancelContexts := make([]context.CancelFunc, 8)
		cancelResults := make(chan error, len(cancelContexts))
		for index := range cancelContexts {
			ctx, cancel := context.WithCancel(t.Context())
			cancelContexts[index] = cancel
			go func(identity byte) {
				_, acquireErr := sequencer.acquire(ctx, testInodeDependencies(250, identity))
				cancelResults <- acquireErr
			}(byte(index + 1))
		}
		waitForMutationSequencerQueue(t, sequencer, len(cancelContexts))
		for _, cancel := range cancelContexts {
			cancel()
		}
		for range cancelContexts {
			if cancelErr := <-cancelResults; !errors.Is(cancelErr, context.Canceled) {
				t.Fatalf("seed %d canceled acquisition = %v, want context.Canceled", seed, cancelErr)
			}
		}
		waitForMutationSequencerQueue(t, sequencer, 0)
		cancelOwner.release()

		// Hold every identity in the shared model pool so all delayed enqueueFor
		// claimants are present before the randomized schedule begins. This makes
		// the intended ordinal order observable without imposing a global key on
		// the operations themselves.
		poolOwners := make([]*mutationSequencerWaiter, 12)
		for index := range poolOwners {
			poolOwners[index], err = sequencer.acquire(t.Context(), testInodeDependencies(byte(index+1)))
			if err != nil {
				t.Fatal(err)
			}
		}

		waiters := make([]*mutationSequencerWaiter, len(operations))
		dependencies := make([]MutationDependencies, len(operations))
		reserved := make([]uint64, len(operations))
		for index := range operations {
			operations[index] = randomDependencyModelOperation(random, index)
			dependencies[index] = operations[index].dependencies()
			if index%11 == 0 {
				reserved[index] = sequencer.reserveOrdinal()
			}
		}
		var enqueueGroup sync.WaitGroup
		enqueueGroup.Add(len(operations))
		for index := range operations {
			index := index
			go func() {
				defer enqueueGroup.Done()
				for count := 0; count < index%7; count++ {
					runtime.Gosched()
				}
				waiters[index] = sequencer.enqueueFor(dependencies[index], reserved[index])
			}()
		}
		enqueueGroup.Wait()

		var sequence atomic.Uint64
		var modelMu sync.Mutex
		active := make(map[string]uint64)
		lastBaseOrdinal := make(map[string]uint64)
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
				requeued := false
				if index%9 == 0 {
					requeued = true
					correctionRandom := rand.New(rand.NewSource(seed*1000 + int64(index) + 1))
					correction := randomDependencyModelOperation(correctionRandom, index+len(operations)).dependencies()
					keys := make([][]byte, 0, len(dependencies[index].keys)+len(correction.keys))
					for _, key := range dependencies[index].keys {
						keys = append(keys, []byte(key))
					}
					for _, key := range correction.keys {
						keys = append(keys, []byte(key))
					}
					dependencies[index] = newMutationDependencies(keys...)
					waiter.requeue(dependencies[index])
					<-waiter.ready
				}
				chosen := sequence.Add(1)
				modelMu.Lock()
				for _, key := range dependencies[index].keys {
					if owner := active[key]; owner != 0 {
						errorsSeen <- fmt.Errorf("seed %d key %x concurrently owned by ordinals %d and %d", seed, key, owner, waiter.ordinal)
					}
					if !requeued {
						if prior := lastBaseOrdinal[key]; prior >= waiter.ordinal {
							errorsSeen <- fmt.Errorf("seed %d key %x base ordinal regressed from %d to %d", seed, key, prior, waiter.ordinal)
						}
						lastBaseOrdinal[key] = waiter.ordinal
					}
					if prior := lastSequence[key]; prior >= chosen {
						errorsSeen <- fmt.Errorf("seed %d key %x sequence regressed from %d to %d", seed, key, prior, chosen)
					}
					active[key] = waiter.ordinal
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
				for _, key := range dependencies[index].keys {
					delete(active, key)
				}
				modelMu.Unlock()
				waiter.release()
			}()
		}
		for _, owner := range poolOwners {
			owner.release()
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

func TestVisibilityStabilizeUnwindsCrossMountPrepareCycle(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	leftMount, rightMount := SessionID{1}, SessionID{2}
	const budget = 500 * time.Millisecond
	h.register(t, leftMount, budget)
	h.register(t, rightMount, budget)
	leftIdentity, rightIdentity := modelInode(51), modelInode(52)
	h.coordinator.RecordResolvedInode(leftMount, leftIdentity)
	h.coordinator.RecordResolvedInode(rightMount, rightIdentity)

	results := make(chan error, 2)
	start := func(source SessionID, identity [16]byte) {
		targets := []VisibilityTarget{{Scope: VisibilityData, Identity: identity, KernelIno: uint64(identity[0]), Device: 1}}
		go func() {
			results <- h.coordinator.Execute(
				context.Background(), source, MutationID{Sequence: uint64(identity[0])},
				mutationDependenciesForTargets(targets),
				func() ([]VisibilityTarget, error) { return targets, nil },
				func() ([]VisibilityTarget, bool) { return targets, true },
			)
		}()
	}
	start(SessionID{8}, leftIdentity)
	start(SessionID{9}, rightIdentity)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	leftPrepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, leftMount)
	if err != nil {
		t.Fatal(err)
	}
	rightPrepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, rightMount)
	if err != nil {
		t.Fatal(err)
	}

	type stabilizeResult struct {
		mount  SessionID
		waited bool
		err    error
	}
	stabilized := make(chan stabilizeResult, 2)
	for _, mount := range []SessionID{leftMount, rightMount} {
		mount := mount
		go func() {
			waited, stabilizeErr := h.coordinator.Stabilize(ctx, mount,
				VisibilityResolution{Identity: leftIdentity},
				VisibilityResolution{Identity: rightIdentity},
			)
			stabilized <- stabilizeResult{mount: mount, waited: waited, err: stabilizeErr}
		}()
	}
	for count := 0; count < 2; count++ {
		select {
		case got := <-stabilized:
			if !got.waited || got.err != nil {
				t.Fatalf("mount %x cross-PREPARE stabilization = waited %t, err %v", got.mount, got.waited, got.err)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("cross-mount Stabilize/PREPARE cycle did not unwind before the repair deadline")
		}
	}

	// The raced reads were discarded, so neither mount may advertise the inode
	// owned only by the concurrent mutation's audience.
	h.coordinator.mu.Lock()
	leftPublishedRight := h.coordinator.participants[leftMount].index.contains(inodeKey(rightIdentity))
	rightPublishedLeft := h.coordinator.participants[rightMount].index.contains(inodeKey(leftIdentity))
	h.coordinator.mu.Unlock()
	if leftPublishedRight || rightPublishedLeft {
		t.Fatalf("raced cross-mount reads entered visibility index: left/right=%t/%t", leftPublishedRight, rightPublishedLeft)
	}

	if err := h.coordinator.Ack(leftMount, leftPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightMount, rightPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	leftComplete, err := h.coordinator.Next(ctx, leftMount, leftPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	rightComplete, err := h.coordinator.Next(ctx, rightMount, rightPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(leftMount, leftComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightMount, rightComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	for count := 0; count < 2; count++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if h.fencer.wasFenced(leftMount) || h.fencer.wasFenced(rightMount) {
		t.Fatalf("healthy mounts fenced while breaking cross-PREPARE cycle: left=%v right=%v",
			h.fenceReasonFor(leftMount), h.fenceReasonFor(rightMount))
	}
}

func TestVisibilityLaneTicketsPreventMultiAudienceStarvation(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	leftMount, rightMount := SessionID{1}, SessionID{2}
	h.register(t, leftMount, testRepairBudget)
	h.register(t, rightMount, testRepairBudget)

	leftBlocker, rightBlocker := modelInode(61), modelInode(62)
	leftLater, rightLater := modelInode(63), modelInode(64)
	h.coordinator.RecordResolvedInode(leftMount, leftBlocker)
	h.coordinator.RecordResolvedInode(leftMount, leftLater)
	h.coordinator.RecordResolvedInode(rightMount, rightBlocker)
	h.coordinator.RecordResolvedInode(rightMount, rightLater)
	renameOldParent, renameNewParent := modelInode(65), modelInode(66)
	moved, replaced := modelInode(67), modelInode(68)
	h.coordinator.RecordResolvedName(leftMount, renameOldParent, []byte("old"))
	h.coordinator.RecordResolvedName(rightMount, renameNewParent, []byte("new"))
	renameTargets := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: renameOldParent, ParentKernelIno: 65, Device: 1, Name: []byte("old"), RelatedIdentities: [][16]byte{moved}},
		{Scope: VisibilityNamespace, ParentIdentity: renameNewParent, ParentKernelIno: 66, Device: 1, Name: []byte("new"), RelatedIdentities: [][16]byte{moved, replaced}},
		{Scope: VisibilityAttributes, Identity: renameOldParent, KernelIno: 65, Device: 1},
		{Scope: VisibilityAttributes, Identity: renameNewParent, KernelIno: 66, Device: 1},
		{Scope: VisibilityAttributes, Identity: moved, KernelIno: 67, Device: 1},
		{Scope: VisibilityAttributes, Identity: replaced, KernelIno: 68, Device: 1},
	}

	type mutationRun struct {
		sequence uint64
		result   <-chan error
	}
	start := func(ctx context.Context, source SessionID, sequence uint64, targets []VisibilityTarget) mutationRun {
		result := make(chan error, 1)
		go func() {
			result <- h.coordinator.Execute(
				ctx, source, MutationID{Sequence: sequence}, mutationDependenciesForTargets(targets),
				func() ([]VisibilityTarget, error) { return targets, nil },
				func() ([]VisibilityTarget, bool) { return targets, true },
			)
		}()
		return mutationRun{sequence: sequence, result: result}
	}
	inodeTargets := func(identity [16]byte) []VisibilityTarget {
		return []VisibilityTarget{{Scope: VisibilityData, Identity: identity, KernelIno: uint64(identity[0]), Device: 1}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	leftFirst := start(ctx, SessionID{8}, 1, inodeTargets(leftBlocker))
	rightFirst := start(ctx, SessionID{9}, 2, inodeTargets(rightBlocker))
	leftPrepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, leftMount)
	if err != nil {
		t.Fatal(err)
	}
	rightPrepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, rightMount)
	if err != nil {
		t.Fatal(err)
	}

	rename := start(ctx, SessionID{10}, 100, renameTargets)
	waitForVisibilityLaneWaiters(t, h.coordinator, 1)
	leftQueued := start(ctx, SessionID{11}, 101, inodeTargets(leftLater))
	rightQueued := start(ctx, SessionID{12}, 102, inodeTargets(rightLater))
	waitForVisibilityLaneWaiters(t, h.coordinator, 3)

	if err := h.coordinator.Ack(leftMount, leftPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightMount, rightPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	leftComplete, err := h.coordinator.Next(ctx, leftMount, leftPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	rightComplete, err := h.coordinator.Next(ctx, rightMount, rightPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(leftMount, leftComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightMount, rightComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-leftFirst.result; err != nil {
		t.Fatal(err)
	}
	if err := <-rightFirst.result; err != nil {
		t.Fatal(err)
	}

	leftRenamePrepare, err := h.coordinator.Next(ctx, leftMount, leftComplete.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	rightRenamePrepare, err := h.coordinator.Next(ctx, rightMount, rightComplete.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if leftRenamePrepare.MutationSequence != rename.sequence || rightRenamePrepare.MutationSequence != rename.sequence ||
		leftRenamePrepare.Cursor != rightRenamePrepare.Cursor {
		t.Fatalf("later single-lane barriers overtook rename: left=%+v right=%+v", leftRenamePrepare, rightRenamePrepare)
	}
	if err := h.coordinator.Ack(leftMount, leftRenamePrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightMount, rightRenamePrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	leftRenameComplete, err := h.coordinator.Next(ctx, leftMount, leftRenamePrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	rightRenameComplete, err := h.coordinator.Next(ctx, rightMount, rightRenamePrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(leftMount, leftRenameComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightMount, rightRenameComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-rename.result; err != nil {
		t.Fatal(err)
	}

	leftLaterPrepare, err := h.coordinator.Next(ctx, leftMount, leftRenameComplete.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	rightLaterPrepare, err := h.coordinator.Next(ctx, rightMount, rightRenameComplete.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if leftLaterPrepare.MutationSequence != leftQueued.sequence || rightLaterPrepare.MutationSequence != rightQueued.sequence {
		t.Fatalf("queued single-lane mutations = left %d right %d, want %d/%d",
			leftLaterPrepare.MutationSequence, rightLaterPrepare.MutationSequence, leftQueued.sequence, rightQueued.sequence)
	}
	if err := h.coordinator.Ack(leftMount, leftLaterPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightMount, rightLaterPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	leftLaterComplete, err := h.coordinator.Next(ctx, leftMount, leftLaterPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	rightLaterComplete, err := h.coordinator.Next(ctx, rightMount, rightLaterPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(leftMount, leftLaterComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightMount, rightLaterComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-leftQueued.result; err != nil {
		t.Fatal(err)
	}
	if err := <-rightQueued.result; err != nil {
		t.Fatal(err)
	}
}

func TestVisibilityLaneWaitCancellationReleasesReservation(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	leftMount, rightMount := SessionID{1}, SessionID{2}
	h.register(t, leftMount, testRepairBudget)
	h.register(t, rightMount, testRepairBudget)
	leftHeld, sharedLeft, sharedRight, rightLater := modelInode(71), modelInode(72), modelInode(73), modelInode(74)
	h.coordinator.RecordResolvedInode(leftMount, leftHeld)
	h.coordinator.RecordResolvedInode(leftMount, sharedLeft)
	h.coordinator.RecordResolvedInode(rightMount, sharedRight)
	h.coordinator.RecordResolvedInode(rightMount, rightLater)
	inodeTargets := func(identities ...[16]byte) []VisibilityTarget {
		targets := make([]VisibilityTarget, 0, len(identities))
		for _, identity := range identities {
			targets = append(targets, VisibilityTarget{Scope: VisibilityData, Identity: identity, KernelIno: uint64(identity[0]), Device: 1})
		}
		return targets
	}
	start := func(ctx context.Context, source SessionID, sequence uint64, targets []VisibilityTarget) <-chan error {
		result := make(chan error, 1)
		go func() {
			result <- h.coordinator.Execute(ctx, source, MutationID{Sequence: sequence}, mutationDependenciesForTargets(targets),
				func() ([]VisibilityTarget, error) { return targets, nil },
				func() ([]VisibilityTarget, bool) { return targets, true })
		}()
		return result
	}

	ctx, cancelAll := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelAll()
	leftResult := start(ctx, SessionID{8}, 1, inodeTargets(leftHeld))
	leftPrepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, leftMount)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancelWait := context.WithCancel(ctx)
	sharedResult := start(waitCtx, SessionID{9}, 2, inodeTargets(sharedLeft, sharedRight))
	waitForVisibilityLaneWaiters(t, h.coordinator, 1)
	rightResult := start(ctx, SessionID{10}, 3, inodeTargets(rightLater))
	waitForVisibilityLaneWaiters(t, h.coordinator, 2)

	cancelWait()
	if err := <-sharedResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled multi-lane mutation = %v, want context.Canceled", err)
	}
	rightPrepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, rightMount)
	if err != nil {
		t.Fatalf("right lane stayed reserved after cancellation: %v", err)
	}
	if rightPrepare.MutationSequence != 3 {
		t.Fatalf("right event after cancellation = mutation %d, want 3", rightPrepare.MutationSequence)
	}
	if err := h.coordinator.Ack(rightMount, rightPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	rightComplete, err := h.coordinator.Next(ctx, rightMount, rightPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(rightMount, rightComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-rightResult; err != nil {
		t.Fatal(err)
	}

	if err := h.coordinator.Ack(leftMount, leftPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	leftComplete, err := h.coordinator.Next(ctx, leftMount, leftPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(leftMount, leftComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-leftResult; err != nil {
		t.Fatal(err)
	}
	waitForVisibilityLaneWaiters(t, h.coordinator, 0)
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
