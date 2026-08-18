package xfsstore

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestFsyncGroupRaceSafety is platform-neutral so the required race lane
// exercises the batching state machine when the host cannot execute Linux.
func TestFsyncGroupRaceSafety(t *testing.T) {
	var state inodeFsyncState
	var syncs atomic.Uint64
	syncCall := func(int) error {
		syncs.Add(1)
		return nil
	}
	const goroutines = 24
	const iterations = 100
	var workers sync.WaitGroup
	workers.Add(goroutines)
	for worker := range goroutines {
		go func() {
			defer workers.Done()
			for iteration := range iterations {
				state.applied()
				if _, err := state.barrier(worker, (worker+iteration)%2 == 0, syncCall, syncCall); err != nil {
					t.Errorf("barrier: %v", err)
				}
			}
		}()
	}
	workers.Wait()
	if syncs.Load() == 0 {
		t.Fatal("race exercise issued no storage syncs")
	}
}
