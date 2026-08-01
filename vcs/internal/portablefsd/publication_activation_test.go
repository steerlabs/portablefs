package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// valuesOnlyContext reproduces writeback.valueOverlayContext: the engine owns
// a delegation release's cancellation, but it forwards the TRIGGERING request's
// values, "so frontend handoff hooks can identify their own in-flight operation
// without allowing request cancellation to interrupt Checkin"
// (writeback.prepareReleaseLocked). Reproducing it here is what makes these
// tests a faithful stand-in for a real ReleaseFor reaching OnHandoffStart.
type valuesOnlyContext struct {
	context.Context
	values context.Context
}

func (c valuesOnlyContext) Value(key any) any {
	if c.values != nil {
		if value := c.values.Value(key); value != nil {
			return value
		}
	}
	return c.Context.Value(key)
}

// activationTestAttach builds an attach with one frontend handle, the shape
// both publication-gate tests drive.
func activationTestAttach(t *testing.T, name string, handleID uint64) *attach {
	t.Helper()
	a := newAttach(name, "key", ensureAttachRequest{
		VolumeID: "vol-" + name, Branch: "main",
		MountPath: "/Volumes/" + name,
	}, privateTestDir(t))
	a.mu.Lock()
	if a.handles == nil {
		a.handles = map[uint64]*handleRecord{}
	}
	a.handles[handleID] = &handleRecord{operationLocks: &handleOperationLocks{}}
	a.mu.Unlock()
	return a
}

func activationTestSetAttr(handleID uint64) *pfslocal.SetAttrRequest {
	size := uint64(4)
	return &pfslocal.SetAttrRequest{
		Item:   pfslocal.Item{ItemID: 42, ItemGeneration: 1},
		Handle: handleID,
		Size:   &size,
	}
}

// TestContinuationAdmissionNeverWaitsOnItsOwnPublication is the finding-2
// reproduction.
//
// A CONTINUATION runs phase 1 before it joins its logical operation, so its
// admission context carried no publication identity. When classification
// released a delegation for an operand, OnHandoffStart (registry.go wires it
// to startFrontendHandoff) saw the continuation's OWN already-active logical
// operation as a foreign member of the publication set and waited for it to
// finish — which it cannot, because this continuation is one of its in-flight
// requests. A bounded deadlock resolved only by the operation deadline, paid
// as an EINTR and a spurious drain error.
//
// The identity must be reserved BEFORE phase 1, permanently suspended and
// holding no mirrors, so admission's handoff recognises its own operation.
func TestContinuationAdmissionNeverWaitsOnItsOwnPublication(t *testing.T) {
	const handleID = uint64(21)
	a := activationTestAttach(t, "att_continuation_admit", handleID)
	conn := dispatcherTestConn(t)

	// The initializing request publishes the logical operation and returns.
	// The operation stays in the active publication set: FSKit has not
	// acknowledged the reply yet, so its continuations are still to come.
	if initialize, ok := conn.reserveLogicalOperation(1, true); !ok || !initialize {
		t.Fatalf("reserve logical operation = (%v, %v)", initialize, ok)
	}
	conn.handleAttached(context.Background(), a, 1, 1, true, activationTestSetAttr(handleID))

	// The continuation. Its phase-1 classification performs a REAL delegation
	// release for an operand scope, which reaches OnHandoffStart.
	if initialize, ok := conn.reserveLogicalOperation(1, true); !ok || initialize {
		t.Fatalf("reserve continuation = (%v, %v)", initialize, ok)
	}
	handoffErr := make(chan error, 1)
	a.testMutationAdmissionBarrier = func(admitCtx context.Context) {
		// Exactly the shape writeback.prepareReleaseLocked builds for
		// OnHandoffStart: engine-owned cancellation, but the triggering
		// request's VALUES, so the hook can identify its own operation.
		handoffCtx, cancel := context.WithTimeout(
			valuesOnlyContext{Context: context.Background(), values: admitCtx},
			3*time.Second,
		)
		defer cancel()
		err := a.startFrontendHandoff(handoffCtx, "")
		handoffErr <- err
		if err == nil {
			a.endFrontendHandoff("")
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleAttached(context.Background(), a, 2, 1, false, activationTestSetAttr(handleID))
	}()

	select {
	case err := <-handoffErr:
		if err != nil {
			t.Fatalf("a continuation's own first-pass admission deadlocked against its own "+
				"publication operation: the delegation release's handoff waited for the "+
				"logical operation this very request belongs to: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the continuation never reached mutation admission")
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the continuation never completed")
	}
}

// TestPublicationActivationNeverWaitsUnderFrontendMirrors is the finding-3
// reproduction.
//
// Phase 2 took the frontend mirrors and THEN waited for the publication gate
// to open. That wait spans a delegation handoff, which spans the release's
// authority round trips — unbounded on a slow or dead uplink — so a write
// holding the per-handle frontend RLock while waiting blocks the close(2) that
// needs the same gate exclusively and depends on nothing remote.
//
// Activation must be ATTEMPTED under the mirrors, never waited for: join
// suspended, take the mirrors, try to activate; if a handoff blocks it, drop
// the mirrors, wait suspended, and retry.
func TestPublicationActivationNeverWaitsUnderFrontendMirrors(t *testing.T) {
	const handleID = uint64(23)
	a := activationTestAttach(t, "att_activation_mirrors", handleID)
	conn := dispatcherTestConn(t)

	// A delegation handoff owns the mount-wide scope. Nothing is publication
	// active yet, so it is granted immediately and held for the whole test.
	if err := a.startFrontendHandoff(context.Background(), ""); err != nil {
		t.Fatalf("start handoff: %v", err)
	}
	handoffEnded := false
	endHandoff := func() {
		if !handoffEnded {
			handoffEnded = true
			a.endFrontendHandoff("")
		}
	}
	defer endHandoff()

	if initialize, ok := conn.reserveLogicalOperation(1, true); !ok || !initialize {
		t.Fatalf("reserve logical operation = (%v, %v)", initialize, ok)
	}
	reachedPhase1 := make(chan struct{})
	a.testMutationAdmissionBarrier = func(context.Context) {
		select {
		case <-reachedPhase1:
		default:
			close(reachedPhase1)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleAttached(context.Background(), a, 1, 1, true, activationTestSetAttr(handleID))
	}()

	select {
	case <-reachedPhase1:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never reached mutation admission")
	}

	// The request is now in phase 2, blocked on the publication gate the
	// handoff holds shut. A close(2) on the same descriptor needs the
	// EXCLUSIVE per-handle frontend gate and waits on nothing remote.
	acquired := make(chan func(), 1)
	go func() {
		acquired <- a.lockFrontendRequest(&pfslocal.CloseRequest{Handle: handleID})
	}()
	select {
	case unlock := <-acquired:
		unlock()
	case <-time.After(3 * time.Second):
		endHandoff()
		<-done
		t.Fatal("close(2) could not take the per-handle frontend gate while a request " +
			"waited for the publication gate: phase 2 is waiting for a delegation " +
			"handoff with the frontend mirrors held, so a slow uplink blocks a close " +
			"that depends on nothing remote")
	}

	endHandoff()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never completed after the handoff ended")
	}
}

// TestContinuationActivationNeverWaitsUnderFrontendMirrors is the same
// discipline on the continuation arm, where the wait lived in the resume half
// of the suspend/mirrors/resume sequence instead of in the gate entry.
func TestContinuationActivationNeverWaitsUnderFrontendMirrors(t *testing.T) {
	const handleID = uint64(25)
	a := activationTestAttach(t, "att_activation_continuation", handleID)
	conn := dispatcherTestConn(t)

	if initialize, ok := conn.reserveLogicalOperation(1, true); !ok || !initialize {
		t.Fatalf("reserve logical operation = (%v, %v)", initialize, ok)
	}
	conn.handleAttached(context.Background(), a, 1, 1, true, activationTestSetAttr(handleID))

	if initialize, ok := conn.reserveLogicalOperation(1, true); !ok || initialize {
		t.Fatalf("reserve continuation = (%v, %v)", initialize, ok)
	}
	// The continuation's own admission takes the handoff and HOLDS it, so the
	// continuation reaches phase 2 with the publication gate shut.
	reachedPhase1 := make(chan struct{})
	handoffHeld := false
	a.testMutationAdmissionBarrier = func(admitCtx context.Context) {
		if handoffHeld {
			return
		}
		handoffCtx, cancel := context.WithTimeout(
			valuesOnlyContext{Context: context.Background(), values: admitCtx},
			3*time.Second,
		)
		defer cancel()
		if err := a.startFrontendHandoff(handoffCtx, ""); err != nil {
			t.Errorf("continuation admission could not start its own handoff: %v", err)
			close(reachedPhase1)
			return
		}
		handoffHeld = true
		close(reachedPhase1)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleAttached(context.Background(), a, 2, 1, false, activationTestSetAttr(handleID))
	}()

	select {
	case <-reachedPhase1:
	case <-time.After(10 * time.Second):
		t.Fatal("the continuation never reached mutation admission")
	}
	if !handoffHeld {
		t.Fatal("the continuation's admission handoff did not start")
	}

	acquired := make(chan func(), 1)
	go func() {
		acquired <- a.lockFrontendRequest(&pfslocal.CloseRequest{Handle: handleID})
	}()
	select {
	case unlock := <-acquired:
		unlock()
	case <-time.After(3 * time.Second):
		a.endFrontendHandoff("")
		<-done
		t.Fatal("close(2) could not take the per-handle frontend gate while a " +
			"continuation resumed into the publication set: the resume wait is " +
			"being paid with the frontend mirrors held")
	}

	a.endFrontendHandoff("")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the continuation never completed after the handoff ended")
	}
}
