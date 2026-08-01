package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestSettleWindowIsNotRearmedByUnrelatedPublications is the livelock.
//
// The settle window bounds a wait on an event the daemon does not produce, and
// it is measured from PROGRESS so it cannot fire on a busy-but-advancing gate.
// Progress used to be a MOUNT-WIDE retraction counter: every operation leaving
// the active set anywhere rearmed every waiting handoff. So a steady trickle of
// publications in a DISJOINT subtree — x/*, nothing to do with d — reset the
// clock forever while d's own blocker never moved, and the handoff never
// returned at all. The release's 20s budget could not save it either: it was
// checked only BETWEEN calls to OnHandoffStart.
//
// Progress must be a fact about THIS scope's barrier.
func TestSettleWindowIsNotRearmedByUnrelatedPublications(t *testing.T) {
	restore := publicationSettleWindow
	publicationSettleWindow = 150 * time.Millisecond
	t.Cleanup(func() { publicationSettleWindow = restore })

	a := &attach{}
	conn := &frontendConn{}

	// The blocker for scope "d": a reply the daemon has exposed and the
	// frontend has not acknowledged. Nothing about it will ever change.
	const blockerOp uint64 = 1
	_, blocker, _, _, err := beginTestLogicalOperation(
		t, conn, a, blockerOp, &pfslocal.GetAttrRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	blocker.op.paths = []string{"d"}
	a.finishFrontendParticipant(blocker)
	conn.finishLogicalRequest(blockerOp)
	exposeTestLogicalOperation(t, conn, blockerOp)

	// Unrelated traffic in a disjoint subtree, retiring faster than the settle
	// window. Under the mount-wide clock this is what kept the wait alive.
	churnStop := make(chan struct{})
	churnDone := make(chan struct{})
	go func() {
		defer close(churnDone)
		for id := uint64(100); ; id++ {
			select {
			case <-churnStop:
				return
			case <-time.After(publicationSettleWindow / 5):
			}
			op, participant := a.reserveFrontendOperation([]string{"x"}, 0)
			if ok, _ := a.tryActivateFrontendParticipant(participant); !ok {
				a.finishFrontendOperation(op)
				continue
			}
			a.finishFrontendParticipant(participant)
			a.finishFrontendOperation(op)
		}
	}()
	t.Cleanup(func() {
		close(churnStop)
		<-churnDone
	})

	handoff := make(chan error, 1)
	go func() { handoff <- a.startFrontendHandoff(context.Background(), "d") }()

	select {
	case err := <-handoff:
		if !PublicationUnsettled(err) {
			t.Fatalf("handoff verdict = %v, want a bounded publication-settle refusal", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the handoff for scope \"d\" never reached a verdict: unrelated " +
			"publications in a disjoint subtree kept rearming its settle window " +
			"while its own blocker never changed")
	}
}

// TestHandoffBudgetIsEnforcedInsideTheWait pins the second half of the same
// defect: the release's 20s budget was checked only BETWEEN OnHandoffStart
// calls, so ONE invocation could exceed it without bound. The deadline now
// travels on the wait's own context, and reaching it produces the same
// transient, scope-local refusal the settle window produces — never a
// cancellation error, which the release classifies as terminal.
func TestHandoffBudgetIsEnforcedInsideTheWait(t *testing.T) {
	restore := publicationSettleWindow
	// Far longer than the budget: only the budget can end this wait.
	publicationSettleWindow = time.Minute
	t.Cleanup(func() { publicationSettleWindow = restore })

	a := &attach{}
	conn := &frontendConn{}
	const blockerOp uint64 = 1
	_, blocker, _, _, err := beginTestLogicalOperation(
		t, conn, a, blockerOp, &pfslocal.GetAttrRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	blocker.op.paths = []string{"d"}
	a.finishFrontendParticipant(blocker)
	conn.finishLogicalRequest(blockerOp)
	exposeTestLogicalOperation(t, conn, blockerOp)

	ctx, cancel := context.WithDeadline(
		context.Background(), time.Now().Add(150*time.Millisecond),
	)
	defer cancel()

	handoff := make(chan error, 1)
	go func() { handoff <- a.startFrontendHandoff(ctx, "d") }()
	select {
	case err := <-handoff:
		if !PublicationUnsettled(err) {
			t.Fatalf("handoff verdict = %v, want a bounded publication-settle refusal "+
				"(a cancellation error here is terminal to the release)", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the release's absolute budget was not enforced on the wait itself")
	}
	a.frontendGateMu.Lock()
	registered := len(a.frontendHandoffs)
	a.frontendGateMu.Unlock()
	if registered != 0 {
		t.Fatalf("a refused handoff left %d scope(s) registered: the subtree stays "+
			"blocked for the life of the mount", registered)
	}
}

// TestHandoffDoesNotCrossALiveSiblingParticipant is the barrier hole.
//
// One FSKit framework callback can have several requests in flight at once.
// When one of them (A) triggers a delegation release, the handoff excluded A's
// whole OPERATION from the publication barrier — so a sibling B that was still
// executing, and whose reply had not been written yet, was not a blocker. The
// handoff completed, the delegation changed hands, and B then published a
// pre-handoff view of state the new holder believes is exclusively theirs.
//
// Self-exclusion has to be per PARTICIPANT: A is inside the release and waiting
// for it would self-deadlock; B is not.
func TestHandoffDoesNotCrossALiveSiblingParticipant(t *testing.T) {
	restore := publicationSettleWindow
	publicationSettleWindow = 2 * time.Second
	t.Cleanup(func() { publicationSettleWindow = restore })

	a := &attach{}
	conn := &frontendConn{}
	const operationID uint64 = 1

	// A: the participant that will trigger the delegation release.
	initiatorCtx, initiator, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.WriteRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	initiator.op.paths = []string{"d"}

	// B: a pipelined sibling of the SAME framework callback, still executing.
	// Its reply is still ahead of it, so a handoff must not cross it.
	initializeSibling, ok := conn.reserveLogicalOperation(operationID, true)
	if !ok || initializeSibling {
		t.Fatalf("sibling reservation = (initialize=%v, ok=%v)", initializeSibling, ok)
	}
	siblingCtx, sibling, _, _, err := conn.beginLogicalOperation(
		context.Background(), a, operationID, false, &pfslocal.GetAttrRequest{},
	)
	if err != nil || sibling == nil {
		t.Fatalf("sibling admission failed: %v", err)
	}
	if err := activateTestParticipant(siblingCtx, a, sibling); err != nil {
		t.Fatal(err)
	}

	// A enters the release: it suspends, exactly as OnReleaseWait does.
	resume := a.suspendFrontendOperation(initiatorCtx)
	if resume == nil {
		t.Fatal("the initiator did not suspend for its release")
	}

	handoff := make(chan error, 1)
	go func() { handoff <- a.startFrontendHandoff(initiatorCtx, "d") }()

	select {
	case err := <-handoff:
		t.Fatalf("the handoff for scope \"d\" completed (%v) while a sibling "+
			"participant of the initiating callback was still executing: it will "+
			"publish a pre-handoff view across the delegation transition", err)
	case <-time.After(150 * time.Millisecond):
	}

	// B finishes and the callback is acknowledged. Only now may the barrier open.
	a.finishFrontendParticipant(sibling)
	conn.finishLogicalRequest(operationID)
	a.finishFrontendParticipant(initiator)
	conn.finishLogicalRequest(operationID)
	exposeTestLogicalOperation(t, conn, operationID)
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("publication acknowledgement was rejected")
	}

	select {
	case err := <-handoff:
		if err != nil {
			t.Fatalf("handoff after the callback was acknowledged: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the handoff never opened after its only blocker was acknowledged")
	}
	a.endFrontendHandoff("d")
}

// TestHandoffIsNotBlockedByItsOwnSoleParticipant is the regression guard on the
// other side of the same rule: the initiator must never block itself, or every
// release taken from a single-request callback deadlocks until the settle
// window expires.
func TestHandoffIsNotBlockedByItsOwnSoleParticipant(t *testing.T) {
	restore := publicationSettleWindow
	publicationSettleWindow = 500 * time.Millisecond
	t.Cleanup(func() { publicationSettleWindow = restore })

	a := &attach{}
	conn := &frontendConn{}
	const operationID uint64 = 1
	ctx, participant, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.WriteRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	participant.op.paths = []string{"d"}
	resume := a.suspendFrontendOperation(ctx)

	done := make(chan error, 1)
	go func() { done <- a.startFrontendHandoff(ctx, "d") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a release's own participant blocked its handoff: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a release's own participant blocked its handoff")
	}
	a.endFrontendHandoff("d")
	if resume != nil {
		resume()
	}
	a.finishFrontendParticipant(participant)
}
