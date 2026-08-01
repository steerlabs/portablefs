package portablefsd

// The dispatcher-ordering contract (frontend.go).
//
//	PHASE 0 deadline → PHASE 1 admission (holding NOTHING) →
//	PHASE 2 publication membership + frontend mirrors →
//	PHASE 3 nonblocking revalidate + mutate
//
// Phase 1 used to sit inside phase 2. lockFrontendRequest takes the frontend
// serialization lock, the name stripes and a per-handle frontend RLock; mutation
// admission could then park for a full metadata admission budget while holding
// all three. close(2) on the same descriptor needs that handle gate EXCLUSIVELY,
// so it queued behind a request waiting on the authority — close-behind-backlog,
// reached by a different route than the one the close-is-local-bookkeeping work
// closed.

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// dispatcherTestConn builds a frontend connection whose replies are drained, so
// a handler that answers never blocks on the pipe.
func dispatcherTestConn(t *testing.T) *frontendConn {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		_ = serverSide.Close()
		_ = clientSide.Close()
	})
	go func() { _, _ = io.Copy(io.Discard, clientSide) }()
	return &frontendConn{conn: serverSide}
}

// TestMutationAdmissionHoldsNoFrontendLock is the finding-5 reproduction.
//
// A setattr parks in pre-lock admission; a close(2) on the same descriptor must
// still be able to take the exclusive per-handle frontend gate. Nothing about a
// close depends on the authority — admitted data belongs to the engine and
// drains in the background — so a close that queues behind a request waiting on
// the uplink is the backlog stall reappearing.
func TestMutationAdmissionHoldsNoFrontendLock(t *testing.T) {
	a := newAttach("att_dispatch_order", "key", ensureAttachRequest{
		VolumeID: "vol-dispatch-order", Branch: "main",
		MountPath: "/Volumes/DispatchOrder",
	}, privateTestDir(t))

	const handleID = uint64(7)
	a.mu.Lock()
	if a.handles == nil {
		a.handles = map[uint64]*handleRecord{}
	}
	a.handles[handleID] = &handleRecord{operationLocks: &handleOperationLocks{}}
	a.mu.Unlock()

	admitting := make(chan struct{})
	releaseAdmission := make(chan struct{})
	entered := false
	a.testMutationAdmissionBarrier = func() {
		if entered {
			return
		}
		entered = true
		close(admitting)
		<-releaseAdmission
	}

	conn := dispatcherTestConn(t)
	initialize, ok := conn.reserveLogicalOperation(1, true)
	if !ok || !initialize {
		t.Fatalf("reserve logical operation = (%v, %v)", initialize, ok)
	}
	size := uint64(4)
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		conn.handleAttached(context.Background(), a, 1, 1, true, &pfslocal.SetAttrRequest{
			Item:   pfslocal.Item{ItemID: 42, ItemGeneration: 1},
			Handle: handleID,
			Size:   &size,
		})
	}()

	select {
	case <-admitting:
	case <-time.After(5 * time.Second):
		close(releaseAdmission)
		t.Fatal("the request never reached mutation admission")
	}

	// The setattr is parked in admission. A close(2) on the same descriptor
	// needs the EXCLUSIVE per-handle frontend gate.
	acquired := make(chan func(), 1)
	go func() {
		acquired <- a.lockFrontendRequest(&pfslocal.CloseRequest{Handle: handleID})
	}()
	select {
	case unlock := <-acquired:
		unlock()
	case <-time.After(2 * time.Second):
		close(releaseAdmission)
		<-handlerDone
		t.Fatal("close(2) could not take the per-handle frontend gate while a " +
			"setattr was parked in mutation admission: admission is being waited " +
			"on underneath the frontend mirror locks, so a slow uplink blocks a " +
			"close that depends on nothing remote")
	}

	close(releaseAdmission)
	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the dispatched request never completed")
	}
}

// TestUnwindReAdmitsWithEveryFrontendLockReleased pins the other half of the
// contract. The unwind's second pass takes a fresh transition claim and releases
// every operand — exactly as unbounded as the first pass — so it must be paid in
// the same place: outside the mirrors, with this request suspended out of the
// publication set.
func TestUnwindReAdmitsWithEveryFrontendLockReleased(t *testing.T) {
	a := newAttach("att_dispatch_unwind", "key", ensureAttachRequest{
		VolumeID: "vol-dispatch-unwind", Branch: "main",
		MountPath: "/Volumes/DispatchUnwind",
	}, privateTestDir(t))

	const handleID = uint64(11)
	a.mu.Lock()
	if a.handles == nil {
		a.handles = map[uint64]*handleRecord{}
	}
	a.handles[handleID] = &handleRecord{operationLocks: &handleOperationLocks{}}
	a.mu.Unlock()

	// Every admission pass reports whether the frontend's per-handle gate is
	// takeable exclusively at that instant, which it can only be if this request
	// is holding none of the frontend mirrors.
	var passHeldLocks []bool
	a.testMutationAdmissionBarrier = func() {
		gate := a.handles[handleID].operationLocks
		free := make(chan struct{})
		go func() {
			gate.frontend.Lock()
			gate.frontend.Unlock()
			close(free)
		}()
		select {
		case <-free:
			passHeldLocks = append(passHeldLocks, false)
		case <-time.After(500 * time.Millisecond):
			// Deliberately does NOT wait for the prober: under the defect it is
			// parked behind this very request's mirror lock, so waiting would
			// deadlock the test instead of reporting the defect. It unblocks and
			// exits when the dispatched request finishes.
			passHeldLocks = append(passHeldLocks, true)
		}
	}

	conn := dispatcherTestConn(t)
	initialize, ok := conn.reserveLogicalOperation(1, true)
	if !ok || !initialize {
		t.Fatalf("reserve logical operation = (%v, %v)", initialize, ok)
	}
	size := uint64(4)
	conn.handleAttached(context.Background(), a, 1, 1, true, &pfslocal.SetAttrRequest{
		Item:   pfslocal.Item{ItemID: 42, ItemGeneration: 1},
		Handle: handleID,
		Size:   &size,
	})

	if len(passHeldLocks) == 0 {
		t.Fatal("the request never reached mutation admission")
	}
	for i, held := range passHeldLocks {
		if held {
			t.Fatalf("admission pass %d ran with a frontend mirror lock held; "+
				"every pass's claim and delegation release must be paid holding "+
				"nothing", i+1)
		}
	}
}
