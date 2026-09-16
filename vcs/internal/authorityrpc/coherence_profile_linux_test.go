//go:build linux

package authorityrpc

import (
	"runtime"
	"testing"
	"time"
)

func TestCoherenceProfileGateSharedAdmissionOverlaps(t *testing.T) {
	var gate coherenceProfileGate
	gate.RLock()
	defer gate.RUnlock()

	acquired := make(chan struct{})
	released := make(chan struct{})
	go func() {
		gate.RLock()
		close(acquired)
		gate.RUnlock()
		close(released)
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("unrelated shared admission did not overlap")
	}
	<-released

	if !gate.mu.TryLock() {
		t.Fatal("shared permit retained the gate mutex across caller work")
	}
	gate.mu.Unlock()
}

func TestCoherenceProfileGateExclusiveAdmissionHasWriterPriority(t *testing.T) {
	var gate coherenceProfileGate
	gate.RLock()

	writerAcquired := make(chan struct{})
	releaseWriter := make(chan struct{})
	go func() {
		gate.Lock()
		close(writerAcquired)
		<-releaseWriter
		gate.Unlock()
	}()

	deadline := time.Now().Add(time.Second)
	for {
		gate.mu.Lock()
		waiting := gate.writersWaiting != 0
		gate.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			gate.RUnlock()
			t.Fatal("exclusive admission did not enter the writer queue")
		}
		runtime.Gosched()
	}

	readerAcquired := make(chan struct{})
	go func() {
		gate.RLock()
		close(readerAcquired)
		gate.RUnlock()
	}()
	select {
	case <-readerAcquired:
		gate.RUnlock()
		t.Fatal("new shared admission passed a queued exclusive admission")
	case <-time.After(20 * time.Millisecond):
	}

	gate.RUnlock()
	select {
	case <-writerAcquired:
	case <-time.After(time.Second):
		t.Fatal("exclusive admission did not follow the last active reader")
	}
	select {
	case <-readerAcquired:
		t.Fatal("shared admission passed an active exclusive admission")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseWriter)
	select {
	case <-readerAcquired:
	case <-time.After(time.Second):
		t.Fatal("shared admission did not resume after exclusive release")
	}
}
