package clientcore

// Unit contract for the reference-counted exclusion owner that implements the
// park-transfer invariant.

import (
	"sync"
	"sync/atomic"
	"testing"
)

// The reference counting itself: the operation and every park hold one
// reference each, the underlying release runs once when the last drops, and
// repeated end()/drop() calls are inert.
func TestExclusionReleaseRunsExactlyOnceAfterLastReference(t *testing.T) {
	var released atomic.Int64
	guard := newExclusionRelease(func() { released.Add(1) })

	parkA := guard.acquire()
	parkB := guard.acquire()
	guard.end()
	guard.end() // idempotent caller
	if released.Load() != 0 {
		t.Fatalf("released with %d parked references outstanding", 2)
	}
	if !guard.held() {
		t.Fatal("exclusion reported free while parked references remain")
	}
	parkA()
	parkA() // double release from one park must be inert
	if released.Load() != 0 {
		t.Fatal("released before the last parked reference dropped")
	}
	parkB()
	if got := released.Load(); got != 1 {
		t.Fatalf("underlying release ran %d times, want exactly 1", got)
	}
	if guard.held() {
		t.Fatal("exclusion still reported held after the final release")
	}
	// A stray late acquire cannot resurrect or re-release it.
	guard.acquire()()
	if got := released.Load(); got != 1 {
		t.Fatalf("underlying release ran %d times after a late acquire, want 1", got)
	}

	// Concurrent drops stay exactly-once under -race.
	var wg sync.WaitGroup
	guard2 := newExclusionRelease(func() { released.Add(1) })
	drops := []func(){guard2.acquire(), guard2.acquire(), guard2.end}
	for _, drop := range drops {
		wg.Add(1)
		go func(fn func()) { defer wg.Done(); fn() }(drop)
	}
	wg.Wait()
	if got := released.Load(); got != 2 {
		t.Fatalf("concurrent drops ran the release to a total of %d, want 2", got)
	}
}
