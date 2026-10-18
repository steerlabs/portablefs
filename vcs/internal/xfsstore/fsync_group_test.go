package xfsstore

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestSyncGroupFailureReleasesAllWaitersWithoutRetry(t *testing.T) {
	var state syncGroup
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	cause := errors.New("terminal writeback failure")
	syncCall := func(int) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return cause
		}
		return nil // The kernel's error cursor would now appear successful.
	}
	first, followers := make(chan error, 1), make(chan error, 4)
	go func() { _, err := state.barrier(1, true, syncCall, syncCall); first <- err }()
	<-entered
	for range 4 {
		go func() { _, err := state.barrier(2, false, syncCall, syncCall); followers <- err }()
	}
	deadline := time.Now().Add(time.Second)
	for {
		state.mu.Lock()
		pending := len(state.pending)
		state.mu.Unlock()
		if pending == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiters did not join the next batch")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	if err := <-first; err != cause {
		t.Fatal(err)
	}
	for range 4 {
		if err := <-followers; err != cause {
			t.Fatal(err)
		}
	}
	if _, err := state.barrier(3, false, syncCall, syncCall); err != cause {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("syscalls = %d", calls.Load())
	}
}
