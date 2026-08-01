package portablefsd

import (
	"context"
	"testing"
	"time"
)

// TestFrontendHandoffReachesAVerdictAgainstAnUnacknowledgedPublication is the
// round-4 live-stress reproduction (branch stress-dde043b-*, HEAD dde043b).
//
// LIVE SHAPE: on an FSKit mount, `mkdir d; touch d/f; rm d/f; rmdir d` in a
// brand-new (cold) top-level directory wedges the rmdir for exactly the 50s
// operation budget, answers EIO, and leaves the WHOLE attach permanently
// degraded with
//
//	kernel coherence barrier failed closed: frontend disconnected before
//	acknowledging an exposed kernel publication
//
// `rm -rf` of any freshly-created tree hits the same shape. The same sequence
// with an 8s pause before the rmdir is clean.
//
// MECHANISM: the rmdir needs an exact operation, which releases the scope's
// delegation. writeback.(*Engine).finishRelease calls OnHandoffStart ==
// attach.startFrontendHandoff with attempt.eventCtx, which overlays only the
// triggering request's VALUES onto the engine-lifetime context — it carries no
// deadline and no cancellation. startFrontendHandoff then waits on
// frontendGateCond until every member of frontendActive that overlaps the
// scope has left. A publishing operation leaves frontendActive only when the
// frontend acknowledges its exposed publication (acknowledgePublication) or
// the connection dies. So an operation whose handler has already returned but
// whose publication ack has not arrived pins the handoff FOREVER.
//
// The drain immediately above it in finishRelease was bounded in round 3
// (drainThrough consults the flusher watchdog and answers ErrUplinkStalled);
// the handoff below it was not. This test states the same contract for the
// handoff: a release attempt must reach a verdict, never wait without bound
// on a condition only the frontend can satisfy.
//
// Site: vcs/internal/writeback/delegation.go:461 (the unbounded OnHandoffStart
// call) and vcs/internal/portablefsd/coherence_refresh.go:820 (the wait).
func TestFrontendHandoffReachesAVerdictAgainstAnUnacknowledgedPublication(t *testing.T) {
	a := &attach{}

	// A publishing frontend operation over "d/f" whose handler has returned
	// but whose exposed publication has not been acknowledged. It is an
	// ordinary, unsuspended member of the active publication set: exactly the
	// state acknowledgePublication would retire and nothing else will.
	_, op := a.beginFrontendPaths(context.Background(), []string{"d/f"})
	if op == nil {
		t.Fatal("publishing operation did not join the publication gate")
	}

	// finishRelease's own call site: the engine lifetime context, with no
	// deadline of its own.
	engineCtx := context.Background()

	done := make(chan error, 1)
	go func() { done <- a.startFrontendHandoff(engineCtx, "d") }()

	select {
	case err := <-done:
		// Either outcome is acceptable: a definite typed refusal, or success
		// once the gate proves the operation cannot publish anything more.
		t.Logf("handoff reached a verdict: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("delegation release handoff waited without bound on an " +
			"unacknowledged frontend publication: the release can never " +
			"reach a verdict, the triggering syscall burns its whole 50s " +
			"operation budget and answers EIO, and the attach is left " +
			"permanently degraded")
	}

	a.endFrontendHandoff("d")
	a.finishFrontendOperation(op)
}
