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
	gate     MutationFootprint
	targets  []MutationTarget
	produces [16]byte
}

func modelInode(id byte) [16]byte { return [16]byte{id} }

func modelInodeTarget(scope MutationScope, identity [16]byte) MutationTarget {
	return MutationTarget{Scope: scope, Identity: identity, KernelIno: uint64(identity[0]), Device: 1}
}

func modelNameTarget(parent [16]byte, name string, related ...[16]byte) MutationTarget {
	return MutationTarget{
		Scope: MutationNamespace, ParentIdentity: parent, ParentKernelIno: uint64(parent[0]), Device: 1,
		Name: []byte(name), RelatedIdentities: append([][16]byte(nil), related...),
	}
}

func (operation dependencyModelOperation) dependencies() MutationDependencies {
	return MutationDependenciesForFootprint(operation.gate)
}

// observationKeys derives the read side independently from the exact
// coordinates a completed mutation publishes. It deliberately does not inspect the
// mutation dependency builder: deleting parent or RelatedIdentities coverage
// there makes this model fail.
func (operation dependencyModelOperation) observationKeys() map[string]struct{} {
	keys := make(map[string]struct{})
	for _, target := range operation.targets {
		if target.Scope == MutationNamespace {
			keys[string(nameKey(target.ParentIdentity, target.Name))] = struct{}{}
			keys[string(inodeKey(target.ParentIdentity))] = struct{}{}
			for _, identity := range target.RelatedIdentities {
				keys[string(inodeKey(identity))] = struct{}{}
			}
		} else {
			keys[string(inodeKey(target.Identity))] = struct{}{}
		}
	}
	return keys
}

func modelItemOperation(name string, identities ...byte) dependencyModelOperation {
	targets := make([]MutationTarget, 0, len(identities))
	gate := MutationFootprint{}
	for _, identity := range identities {
		targets = append(targets, modelInodeTarget(MutationData, modelInode(identity)))
		gate.Targets = append(gate.Targets, FootprintTarget{
			Identity: modelInode(identity), Attributes: true, Data: true,
		})
	}
	return dependencyModelOperation{name: name, gate: gate, targets: targets}
}

func modelCreateOperation(name string, parent byte, binding string, created byte) dependencyModelOperation {
	return dependencyModelOperation{
		name: name,
		gate: MutationFootprint{Targets: []FootprintTarget{
			{Identity: modelInode(parent), Attributes: true},
			{ParentIdentity: modelInode(parent), Name: []byte(binding), BoundAttributes: true},
		}},
		targets: []MutationTarget{
			modelNameTarget(modelInode(parent), binding),
			modelInodeTarget(MutationAttributes, modelInode(parent)),
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
		gate: MutationFootprint{Targets: []FootprintTarget{
			{Identity: modelInode(parent), Attributes: true},
			{
				ParentIdentity: modelInode(parent), Name: []byte(binding), BoundAttributes: true,
				BoundIdentities: [][16]byte{modelInode(bound)},
			},
		}},
		targets: []MutationTarget{
			modelNameTarget(modelInode(parent), binding, modelInode(bound)),
			modelInodeTarget(MutationAttributes, modelInode(parent)),
			modelInodeTarget(MutationAttributes, modelInode(bound)),
		},
	}
}

func modelLinkOperation(parent byte, binding string, existing byte) dependencyModelOperation {
	return dependencyModelOperation{
		name: "link",
		gate: MutationFootprint{Targets: []FootprintTarget{
			{Identity: modelInode(existing), Attributes: true},
			{Identity: modelInode(parent), Attributes: true},
			{ParentIdentity: modelInode(parent), Name: []byte(binding), BoundAttributes: true},
		}},
		targets: []MutationTarget{
			modelNameTarget(modelInode(parent), binding, modelInode(existing)),
			modelInodeTarget(MutationAttributes, modelInode(parent)),
			modelInodeTarget(MutationAttributes, modelInode(existing)),
		},
	}
}

func modelRenameOperation(oldParent byte, oldName string, newParent byte, newName string, moved byte, replaced ...byte) dependencyModelOperation {
	oldTarget := modelNameTarget(modelInode(oldParent), oldName, modelInode(moved))
	newTarget := modelNameTarget(modelInode(newParent), newName, modelInode(moved))
	targets := []MutationTarget{
		oldTarget,
		newTarget,
		modelInodeTarget(MutationAttributes, modelInode(oldParent)),
		modelInodeTarget(MutationAttributes, modelInode(newParent)),
		modelInodeTarget(MutationAttributes, modelInode(moved)),
	}
	for _, identity := range replaced {
		newTarget.RelatedIdentities = append(newTarget.RelatedIdentities, modelInode(identity))
		targets = append(targets, modelInodeTarget(MutationAttributes, modelInode(identity)))
	}
	targets[1] = newTarget
	oldGateTarget := FootprintTarget{
		ParentIdentity: modelInode(oldParent), Name: []byte(oldName), BoundAttributes: true,
		BoundIdentities: [][16]byte{modelInode(moved)},
	}
	newGateTarget := FootprintTarget{
		ParentIdentity: modelInode(newParent), Name: []byte(newName), BoundAttributes: true,
	}
	for _, identity := range replaced {
		newGateTarget.BoundIdentities = append(newGateTarget.BoundIdentities, modelInode(identity))
	}
	return dependencyModelOperation{
		name: "rename",
		gate: MutationFootprint{Targets: []FootprintTarget{
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
