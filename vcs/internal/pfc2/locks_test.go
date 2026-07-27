package pfc2

import (
	"math/rand"
	"reflect"
	"testing"
)

func owner(id string, gen, lk uint64) LockOwner {
	return LockOwner{Session: ref(id, gen), KernelLockOwner: lk}
}

func TestLockSetSplitMergeReplace(t *testing.T) {
	a := owner("a", 1, 1)
	var set []HeldLock

	// Whole-file read lock.
	set = setLockRange(set, a, 0, LockRangeEOF, false)
	want := []HeldLock{{Owner: a, Start: 0, End: LockRangeEOF, Write: false}}
	if !reflect.DeepEqual(set, want) {
		t.Fatalf("whole-file read: %+v", set)
	}

	// Upgrade the middle to write: POSIX replace splits the read lock.
	set = setLockRange(set, a, 100, 199, true)
	want = []HeldLock{
		{Owner: a, Start: 0, End: 99, Write: false},
		{Owner: a, Start: 100, End: 199, Write: true},
		{Owner: a, Start: 200, End: LockRangeEOF, Write: false},
	}
	if !reflect.DeepEqual(set, want) {
		t.Fatalf("upgrade split: %+v", set)
	}

	// Downgrade back to read: the three pieces must merge into one again.
	set = setLockRange(set, a, 100, 199, false)
	want = []HeldLock{{Owner: a, Start: 0, End: LockRangeEOF, Write: false}}
	if !reflect.DeepEqual(set, want) {
		t.Fatalf("downgrade merge: %+v", set)
	}

	// Partial unlock splits.
	set = unlockRange(set, a, 50, 59)
	want = []HeldLock{
		{Owner: a, Start: 0, End: 49, Write: false},
		{Owner: a, Start: 60, End: LockRangeEOF, Write: false},
	}
	if !reflect.DeepEqual(set, want) {
		t.Fatalf("partial unlock: %+v", set)
	}

	// Re-lock the gap: adjacency merges all three back into one.
	set = setLockRange(set, a, 50, 59, false)
	want = []HeldLock{{Owner: a, Start: 0, End: LockRangeEOF, Write: false}}
	if !reflect.DeepEqual(set, want) {
		t.Fatalf("gap merge: %+v", set)
	}

	// Unlock everything.
	set = unlockRange(set, a, 0, LockRangeEOF)
	if len(set) != 0 {
		t.Fatalf("unlock all: %+v", set)
	}
}

func TestLockConflictRules(t *testing.T) {
	a, b := owner("a", 1, 1), owner("b", 1, 1)
	set := setLockRange(nil, a, 0, 99, false)

	// Shared read locks coexist.
	if _, c := lockConflict(set, b, 0, 99, false); c {
		t.Fatal("read/read conflicted")
	}
	// Writer conflicts with another owner's read.
	if _, c := lockConflict(set, b, 50, 149, true); !c {
		t.Fatal("write over foreign read did not conflict")
	}
	// Disjoint write does not conflict.
	if _, c := lockConflict(set, b, 100, 199, true); c {
		t.Fatal("disjoint write conflicted")
	}
	// An owner never conflicts with itself.
	if _, c := lockConflict(set, a, 0, LockRangeEOF, true); c {
		t.Fatal("self conflict")
	}
	// Same session, different kernel lock owner IS a different owner.
	a2 := owner("a", 1, 2)
	if _, c := lockConflict(set, a2, 0, 9, true); !c {
		t.Fatal("same-session different-lock-owner write did not conflict")
	}

	set = setLockRange(set, b, 100, 199, true)
	if _, c := lockConflict(set, a, 199, LockRangeEOF, false); !c {
		t.Fatal("read over foreign write did not conflict")
	}
}

func TestLockNormalizationInvariant(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	owners := []LockOwner{owner("a", 1, 1), owner("a", 1, 2), owner("b", 2, 1)}
	var set []HeldLock
	for i := 0; i < 3000; i++ {
		o := owners[rng.Intn(len(owners))]
		start := uint64(rng.Intn(500))
		end := start + uint64(rng.Intn(100))
		if rng.Intn(8) == 0 {
			end = LockRangeEOF
		}
		switch rng.Intn(3) {
		case 0, 1:
			write := rng.Intn(2) == 0
			if _, c := lockConflict(set, o, start, end, write); !c {
				set = setLockRange(set, o, start, end, write)
			}
		case 2:
			set = unlockRange(set, o, start, end)
		}
		if !isNormalizedLocks(set) {
			t.Fatalf("iteration %d produced a non-normalized set: %+v", i, set)
		}
	}
}
