package portablefsd

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// closeContinuationConn builds the exact shape the incident produced: a
// framework callback that already published cacheable state (operation 1),
// whose remaining requests — including the close — share its operation ID.
func closeContinuationConn(
	t *testing.T,
	a *attach,
	op *frontendOperation,
) *frontendConn {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = serverSide.Close(); _ = clientSide.Close() })
	ready := make(chan struct{})
	close(ready)
	return &frontendConn{
		conn: serverSide,
		operations: map[uint64]*frontendOperationEntry{
			1: {ready: ready, op: op, activeRequests: 2},
		},
		lastOperationID: 1,
	}
}

// TestCloseContinuationNeverWaitsForADelegationHandoff is the §6 defect-1
// reproduction.
//
// close(2) publishes nothing, but the pfslocal client shares one operation ID
// across every request a framework callback issues, so a close arrived as a
// continuation of a publishing callback. As an ordinary participant its
// re-entry into the publication gate waited for every overlapping delegation
// handoff to end — a window that spans the release's authority round trips
// and is unbounded on a slow or dead uplink. That is how closing a handle with
// an admitted write-back backlog ended up serialized behind its own scope's
// drain. The identical close carrying no operation ID returned instantly.
func TestCloseContinuationNeverWaitsForADelegationHandoff(t *testing.T) {
	a := &attach{}
	// The publishing sibling owns the logical operation and is parked on an
	// authority wait, so the handoff below is admitted.
	siblingCtx, op := a.beginFrontendPaths(context.Background(), []string{"d/f"})
	resumeSibling := a.suspendFrontendOperation(siblingCtx)
	if resumeSibling == nil {
		t.Fatal("publishing sibling did not join the publication gate")
	}
	conn := closeContinuationConn(t, a, op)

	handoffCtx, cancelHandoff := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelHandoff()
	if err := a.startFrontendHandoff(handoffCtx, "d"); err != nil {
		t.Fatalf("start delegation handoff over the closing scope: %v", err)
	}

	type outcome struct {
		participates bool
		publishes    bool
		err          error
	}
	done := make(chan outcome, 1)
	go func() {
		// Exactly what handleAttached does for a continuation.
		ctx, participant, participates, publishes, err := conn.beginLogicalOperation(
			context.Background(), a, 1, false, &pfslocal.CloseRequest{Handle: 1},
		)
		if err == nil {
			resume := a.suspendFrontendOperation(ctx)
			if resume != nil {
				resume()
			}
			a.finishFrontendParticipant(participant)
		}
		done <- outcome{participates: participates, publishes: publishes, err: err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("close continuation failed: %v", got.err)
		}
		if got.publishes {
			t.Fatal("close was classified as publishing cacheable state")
		}
		if !got.participates {
			t.Fatal("close did not join its logical operation at all; a recall holding a namespace mirror lock could deadlock against it")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close(2) waited on the delegation handoff: an admitted backlog drains inside the frontend op pipeline")
	}

	a.endFrontendHandoff("d")
	resumeSibling()
	a.finishFrontendOperation(op)
}

// TestCloseContinuationDoesNotBlockALaterDelegationHandoff is the other half
// of the contract: a nonpublishing continuation must not become a member of
// the active publication set either, or a close would hold every overlapping
// handoff open for as long as it runs.
func TestCloseContinuationDoesNotBlockALaterDelegationHandoff(t *testing.T) {
	a := &attach{}
	siblingCtx, op := a.beginFrontendPaths(context.Background(), []string{"d/f"})
	resumeSibling := a.suspendFrontendOperation(siblingCtx)
	if resumeSibling == nil {
		t.Fatal("publishing sibling did not join the publication gate")
	}
	conn := closeContinuationConn(t, a, op)

	_, participant, participates, _, err := conn.beginLogicalOperation(
		context.Background(), a, 1, false, &pfslocal.CloseRequest{Handle: 1},
	)
	if err != nil {
		t.Fatalf("close continuation failed: %v", err)
	}
	if !participates {
		t.Fatal("close continuation did not join its logical operation")
	}

	handoff := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		handoff <- a.startFrontendHandoff(ctx, "d")
	}()
	select {
	case err := <-handoff:
		if err != nil {
			t.Fatalf("handoff blocked behind a running close: %v", err)
		}
		a.endFrontendHandoff("d")
	case <-time.After(3 * time.Second):
		t.Fatal("a running close(2) held the delegation handoff open")
	}

	a.finishFrontendParticipant(participant)
	resumeSibling()
	a.finishFrontendOperation(op)
}

// parkedHandlerConn models the terminal incident state: a handler is parked
// inside the very drain the delegation release is performing, and the
// frontend connection dies underneath it.
func parkedHandlerConn(
	t *testing.T,
	a *attach,
	op *frontendOperation,
	release <-chan struct{},
) *frontendConn {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close() })
	ready := make(chan struct{})
	close(ready)
	conn := &frontendConn{
		conn: serverSide,
		operations: map[uint64]*frontendOperationEntry{
			1: {ready: ready, op: op, activeRequests: 1},
		},
		lastOperationID: 1,
	}
	conn.handlerWG.Add(1)
	go func() {
		defer conn.handlerWG.Done()
		<-release
	}()
	return conn
}

// TestFrontendDisconnectResolvesAPublicationAckAHandlerCannotFinish is the §6
// defect-2 reproduction.
//
// Release completion waits for every outstanding publication acknowledgment.
// A dead frontend can never send one, and connection teardown only retired
// those operations AFTER joining its handlers — so when a handler was parked
// inside the drain the release was performing, the disconnect waited for the
// handler, the handler waited for the drain, and the drain waited for the
// disconnect. The acknowledged tail stranded with no failure recorded.
//
// A dead frontend has no kernel state to keep coherent: the barrier is
// vacuously satisfied and must resolve immediately and definitively.
func TestFrontendDisconnectResolvesAPublicationAckAHandlerCannotFinish(t *testing.T) {
	a := &attach{}
	_, op := a.beginFrontendPaths(context.Background(), []string{"d/f"})
	releaseHandler := make(chan struct{})
	conn := parkedHandlerConn(t, a, op, releaseHandler)

	closeDone := make(chan struct{})
	go func() {
		conn.close()
		close(closeDone)
	}()

	handoff := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		handoff <- a.startFrontendHandoff(ctx, "d")
	}()

	select {
	case err := <-handoff:
		if err != nil {
			t.Fatalf("release aborted instead of resolving the dead frontend's barrier: %v", err)
		}
		a.endFrontendHandoff("d")
	case <-time.After(5 * time.Second):
		close(releaseHandler)
		t.Fatal("frontend death left the drain waiting on a publication acknowledgment it can never receive")
	}

	// The drain has completed; the parked handler may now unwind and the
	// attach can tear its connection down cleanly.
	close(releaseHandler)
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("connection teardown never completed after its handler unwound")
	}
}

// TestFrontendDisconnectDuringFsyncResolvesTheBarrierGate covers the fsync
// caller disappearing mid-barrier: the fsync handler is still draining, the
// connection is gone, and nothing may leak the gate.
func TestFrontendDisconnectDuringFsyncResolvesTheBarrierGate(t *testing.T) {
	a := &attach{}
	_, op := a.beginFrontendPaths(context.Background(), []string{"d/f"})
	fsyncRunning := make(chan struct{})
	conn := parkedHandlerConn(t, a, op, fsyncRunning)

	done := make(chan struct{})
	go func() {
		conn.close()
		close(done)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.startFrontendHandoff(ctx, "d"); err != nil {
		t.Fatalf("handoff blocked on a barrier whose caller is gone: %v", err)
	}
	a.endFrontendHandoff("d")

	close(fsyncRunning)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("teardown leaked after the fsync handler unwound")
	}
	if err := frontendGateErrorOf(a); err != nil {
		t.Fatalf("an unexposed barrier request poisoned the attach gate: %v", err)
	}
}

// TestFrontendDisconnectWithNoOutstandingPublicationIsANoOp: the zero-pending
// edge. Nothing to resolve, nothing poisoned, teardown immediate.
func TestFrontendDisconnectWithNoOutstandingPublicationIsANoOp(t *testing.T) {
	a := &attach{}
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	conn := &frontendConn{conn: serverSide}
	done := make(chan struct{})
	go func() {
		conn.close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("teardown with nothing outstanding did not complete")
	}
	if err := frontendGateErrorOf(a); err != nil {
		t.Fatalf("empty teardown poisoned the attach gate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.startFrontendHandoff(ctx, ""); err != nil {
		t.Fatalf("handoff refused after an empty teardown: %v", err)
	}
	a.endFrontendHandoff("")
}

// TestDoubleFrontendDisconnectIsIdempotent: teardown runs once, and a second
// detach attempt after the drain has completed must not wedge or double-retire
// anything.
func TestDoubleFrontendDisconnectIsIdempotent(t *testing.T) {
	a := &attach{}
	_, op := a.beginFrontendPaths(context.Background(), []string{"d/f"})
	released := make(chan struct{})
	close(released)
	conn := parkedHandlerConn(t, a, op, released)
	conn.close()
	conn.close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.startFrontendHandoff(ctx, "d"); err != nil {
		t.Fatalf("second teardown left the gate closed: %v", err)
	}
	a.endFrontendHandoff("d")
}

// frontendGateErrorOf reads the attach's terminal publication verdict.
func frontendGateErrorOf(a *attach) error {
	a.frontendGateMu.Lock()
	defer a.frontendGateMu.Unlock()
	return a.frontendGateErr
}

// TestFrontendDeathMidReleaseLetsTheAttachDetachCleanly is the end of the §6
// recovery story. In the incident the release stalled forever after the
// frontend died, so the attach could not be detached through the CLI at all —
// the only way out was calling the daemon control API directly. Once the
// dead frontend's publication acknowledgments resolve definitively, the
// release completes and an ordinary detach (and a repeat of it) succeeds.
func TestFrontendDeathMidReleaseLetsTheAttachDetachCleanly(t *testing.T) {
	a := newAttach(testFSKitAttachRef, "close-drain-liveness", ensureAttachRequest{
		AttachRef:          testFSKitAttachRef,
		VolumeID:           "vol-close-drain-liveness",
		Branch:             "main",
		MountPath:          "/Volumes/PortableFSCloseDrainTest",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
	}, privateTestDir(t))

	_, op := a.beginFrontendPaths(context.Background(), []string{"d/f"})
	parked := make(chan struct{})
	conn := parkedHandlerConn(t, a, op, parked)
	closeDone := make(chan struct{})
	go func() {
		conn.close()
		close(closeDone)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.startFrontendHandoff(ctx, "d"); err != nil {
		t.Fatalf("release stalled after the frontend died: %v", err)
	}
	a.endFrontendHandoff("d")

	close(parked)
	select {
	case <-closeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("connection teardown never finished")
	}

	if _, err := a.detachWithFinalizer(func() error { return nil }); err != nil {
		t.Fatalf("detach after frontend death: %v", err)
	}
	if _, err := a.detachWithFinalizer(func() error { return nil }); err != nil {
		t.Fatalf("second detach was not idempotent: %v", err)
	}
	a.mu.RLock()
	detached := a.detached
	a.mu.RUnlock()
	if !detached {
		t.Fatal("detach did not publish terminal state")
	}
}
