package volumeserver

import (
	"container/list"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// The index is asked in the unsafe direction: a "no" that is wrong lets a mount
// keep serving a name the volume already changed. Everything ever recorded must
// still be answered "may hold", including far past the declared capacity, and
// memory must not move while that happens.
func TestResolvedIndexHasNoFalseNegativesUnderLoad(t *testing.T) {
	const capacity = 4096
	index := newResolvedIndex(capacity, 0x9e3779b97f4a7c15)
	words := index.words

	parent := testVisibilityParent()
	key := func(i int) []byte { return nameKey(parent, []byte(fmt.Sprintf("entry-%d", i))) }

	// Ten times the declared capacity, which is well past the design point.
	const total = capacity * 10
	for i := range total {
		index.add(key(i))
	}
	for i := range total {
		if !index.contains(key(i)) {
			t.Fatalf("false negative: coordinate %d of %d was dropped", i, total)
		}
	}

	// Memory is fixed by the declared capacity, not by how much was recorded.
	if uint64(len(index.filter)) != words || index.words != words {
		t.Fatalf("index grew: filter=%d words=%d, want %d", len(index.filter), index.words, words)
	}
	if index.words > capacity {
		t.Fatalf("index used %d words for a %d coordinate capacity", index.words, capacity)
	}

	// Inodes and names live in the same filter, so they must be domain
	// separated: a 16-byte identity must not be findable as a name.
	var identity [16]byte
	identity[0] = 7
	index.add(inodeKey(identity))
	if !index.contains(inodeKey(identity)) {
		t.Fatal("false negative on an inode coordinate")
	}
}

// Precision at the design point is the whole reason to size the filter from the
// declared capacity. This is a performance property, not a correctness one, so
// it is asserted loosely - but a filter that answered yes to everything at its
// own capacity would make scoped fan-out pointless.
func TestResolvedIndexIsSelectiveAtItsDeclaredCapacity(t *testing.T) {
	const capacity = 8192
	index := newResolvedIndex(capacity, 0x452821e638d01377)
	parent := testVisibilityParent()
	for i := range capacity {
		index.add(nameKey(parent, []byte(fmt.Sprintf("resolved-%d", i))))
	}
	falsePositives := 0
	const probes = 20000
	for i := range probes {
		if index.contains(nameKey(parent, []byte(fmt.Sprintf("never-resolved-%d", i)))) {
			falsePositives++
		}
	}
	if rate := float64(falsePositives) / probes; rate > 0.05 {
		t.Fatalf("false-positive rate at the declared capacity = %.3f, want well under 5%%", rate)
	}
}

// The property that matters is stated against the thing the index models: a
// frontend cache bounded at the capacity it declared. This drives a real LRU of
// that capacity through a workload with hits, misses, and heavy repetition -
// only the misses reach the authority and reach the index - and asserts after
// every single operation that everything the cache still holds is still
// answered "may hold". That is the no-false-negative property end to end.
func TestResolvedIndexCoversEveryEntryABoundedCacheCanHold(t *testing.T) {
	const capacity = 512
	const keySpace = 20000
	const operations = 200000

	index := newResolvedIndex(capacity, 0x243f6a8885a308d3)
	parent := testVisibilityParent()
	cache := list.New()
	resident := make(map[string]*list.Element, capacity)

	// A deterministic xorshift keeps the workload reproducible without pulling
	// in a seeded generator whose stream could change between releases.
	state := uint64(0x2545f4914f6cdd1d)
	next := func() uint64 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return state
	}

	for op := range operations {
		// A skewed workload: a small hot set is looked up far more often than
		// the rest, which is what makes repeated resolutions the common case.
		var which uint64
		if next()%4 != 0 {
			which = next() % 64
		} else {
			which = next() % keySpace
		}
		name := fmt.Sprintf("entry-%d", which)
		if element, hit := resident[name]; hit {
			// A cache hit never reaches the authority, so the index learns
			// nothing from it. This is the case that would break an index that
			// counted resolutions instead of distinct ones.
			cache.MoveToFront(element)
			continue
		}
		index.add(nameKey(parent, []byte(name)))
		resident[name] = cache.PushFront(name)
		if cache.Len() > capacity {
			oldest := cache.Back()
			cache.Remove(oldest)
			delete(resident, oldest.Value.(string))
		}
		if op%997 != 0 {
			continue
		}
		for cached := range resident {
			if !index.contains(nameKey(parent, []byte(cached))) {
				t.Fatalf("false negative at operation %d: cache still holds %q", op, cached)
			}
		}
	}
	for cached := range resident {
		if !index.contains(nameKey(parent, []byte(cached))) {
			t.Fatalf("false negative at the end: cache still holds %q", cached)
		}
	}
	if cache.Len() != capacity {
		t.Fatalf("modelled cache held %d entries, want the declared %d", cache.Len(), capacity)
	}
}

func TestResolvedIndexCountsDistinctKeysOnly(t *testing.T) {
	const capacity = 64
	index := newResolvedIndex(capacity, 1)
	parent := testVisibilityParent()
	first := nameKey(parent, []byte("kept"))
	index.add(first)
	for range capacity * 4 {
		index.add(first)
	}
	if index.distinct != 1 {
		t.Fatalf("distinct coordinate count = %d after repeating one key, want 1", index.distinct)
	}
	if !index.contains(first) {
		t.Fatal("repeating one key dropped it")
	}
}

// A participant that leaves cleanly must not leave a goroutine parked on its
// terminal channel for the rest of the epoch.
func TestVisibilityDepartedParticipantLeavesNoWatchdog(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	settle := func() int {
		for range 50 {
			runtime.Gosched()
			time.Sleep(2 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}
	before := settle()
	for i := 1; i <= 32; i++ {
		id := SessionID{byte(i)}
		terminal := h.fencer.attach(id)
		commitment := VisibilityCommitment{CachedNameCapacity: testCacheCapacity, RepairBudget: testRepairBudget, NamespaceRepair: NamespaceRepairParentExclusive}
		if err := h.coordinator.Register(id, CoherenceStrict, terminal, commitment); err != nil {
			t.Fatalf("register: %v", err)
		}
		if err := h.coordinator.CleanDetach(id, testMountAbsence(time.Now())); err != nil {
			t.Fatalf("clean detach: %v", err)
		}
	}
	after := settle()
	if after > before+4 {
		t.Fatalf("goroutines %d -> %d after 32 clean detaches; watchdogs outlived their participants", before, after)
	}
}
