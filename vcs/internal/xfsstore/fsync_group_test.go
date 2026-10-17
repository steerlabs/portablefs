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

func TestFsyncGroupDurabilityPolicySurvivesOrdinaryLeader(t *testing.T) {
	var state inodeFsyncState
	var calls, policies atomic.Int32
	firstEntered, secondEntered := make(chan struct{}), make(chan struct{})
	firstRelease, secondRelease := make(chan struct{}), make(chan struct{})
	cause, fatal := errors.New("writeback ENOSPC"), errors.New("terminal durability failure")
	syncCall := func(int) error {
		switch calls.Add(1) {
		case 1:
			close(firstEntered)
			<-firstRelease
		case 2:
			close(secondEntered)
			<-secondRelease
			return cause
		}
		return nil
	}
	failure := func(err error) error {
		if !errors.Is(err, cause) {
			t.Errorf("failure policy cause = %v", err)
		}
		policies.Add(1)
		return fatal
	}
	waitPending := func(want int) {
		t.Helper()
		until := time.Now().Add(time.Second)
		for time.Now().Before(until) {
			state.mu.Lock()
			got := len(state.pending)
			state.mu.Unlock()
			if got == want {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("pending waiters never reached %d", want)
	}
	initial, ordinary, required, later := make(chan error, 1), make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() { _, err := state.barrier(1, false, syncCall, syncCall); initial <- err }()
	<-firstEntered
	go func() { _, err := state.barrier(2, true, syncCall, syncCall); ordinary <- err }()
	waitPending(1)
	go func() { _, err := state.barrierWithFailure(3, false, syncCall, syncCall, failure); required <- err }()
	waitPending(2)
	close(firstRelease)
	<-secondEntered
	go func() { _, err := state.barrierWithFailure(4, false, syncCall, syncCall, failure); later <- err }()
	waitPending(1)
	close(secondRelease)
	if err := <-initial; err != nil {
		t.Fatal(err)
	}
	for _, result := range []chan error{ordinary, required, later} {
		if err := <-result; !errors.Is(err, fatal) {
			t.Fatalf("waiter escaped terminal batch failure: %v", err)
		}
	}

	if policies.Load() != 2 || calls.Load() != 3 {
		t.Fatalf("failure policies/sync attempts=%d/%d", policies.Load(), calls.Load())
	}
}
