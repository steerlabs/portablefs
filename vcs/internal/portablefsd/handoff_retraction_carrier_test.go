package portablefsd

import (
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// ── FINDING 3 (ROUND 11): THE VERDICT AND ITS CARRIER MUST BE ONE EVENT ──────
//
// The retraction has exactly one delivery mechanism: it rides a reply. Round 10
// built the reply by SAMPLING op.retracted and then writing the frame, which
// leaves a gap between the verdict and its only carrier — and a delegation
// handoff fits into that gap precisely, because the state it crosses (published,
// no runnable participant, every participant parked) is the state a permanently
// suspended non-publishing participant's final reply is written from.
//
// The sequence is: replyWithPublication reads retracted == false; a handoff
// crosses and sets retracted = true; the frame — already built — goes out
// without the bit; the framework installs the pre-handoff view; and the only
// carrier the retraction had has been spent. The exact-refresh backstop then
// reintroduces exactly the inconsistency window retraction exists to remove.
//
// The fix is an atomic gate transition: under frontendGateMu the reply either
// observes an existing retraction or registers itself as a CARRIER a future
// crossing must block on until the frame is written.

// TestNoHandoffCrossesAnOperationWhileItsCarrierIsInFlight drives the exact
// interleaving through the test hook the auditor asked for: it fires between
// the verdict capture and the frame write, which is the only place a test can
// stand.
func TestNoHandoffCrossesAnOperationWhileItsCarrierIsInFlight(t *testing.T) {
	restore := publicationSettleWindow
	// Long enough that the gate's hold on the crossing is never mistaken for the
	// settle window expiring.
	publicationSettleWindow = 30 * time.Second
	t.Cleanup(func() { publicationSettleWindow = restore })

	a, conn, initiatorCtx, initiator, operationID := newExposedSiblingFixture(t)
	daemonSide, frontendSide := net.Pipe()
	t.Cleanup(func() { _ = daemonSide.Close(); _ = frontendSide.Close() })
	conn.conn = daemonSide
	op := initiator.op

	// The initiator has suspended for its own release, which is the production
	// ordering and the state publicationBlockersLocked crosses.
	resume := a.suspendFrontendOperation(initiatorCtx)
	if resume == nil {
		t.Fatal("the initiator did not suspend for its release")
	}
	t.Cleanup(resume)

	handoffDone := make(chan struct{})
	var handoffErr error
	crossedBeforeTheFrame := false
	conn.testAfterRetractionCapture = func(uint64) {
		conn.testAfterRetractionCapture = nil
		go func() {
			handoffErr = a.startFrontendHandoff(initiatorCtx, "d")
			close(handoffDone)
		}()
		// Give the crossing every chance to complete while this frame is still
		// unwritten. If it can, the retraction it installs has no carrier left.
		select {
		case <-handoffDone:
			crossedBeforeTheFrame = true
		case <-time.After(time.Second):
			// The gate held: the crossing is waiting for this frame to leave.
		}
	}

	go conn.replyWithPublication(9, operationID, &pfslocal.RemoveReply{}, false)
	env := readEnvelope(t, frontendSide)

	if crossedBeforeTheFrame && !env.PublicationRetracted {
		t.Fatal("a delegation handoff crossed an operation while the reply carrying " +
			"its retraction was already built and not yet written: the frame went out " +
			"stamped with the pre-crossing verdict, the framework installs the " +
			"pre-handoff view, and the retraction's only carrier has been spent")
	}

	// LIVENESS. Blocking the crossing on a frame is only sound because the frame
	// always leaves: the peer is waiting for it. The handoff must complete.
	select {
	case <-handoffDone:
		if handoffErr != nil {
			t.Fatalf("the handoff never completed after its carrier was released: %v — "+
				"blocking on a reply-in-flight must be bounded by that one socket "+
				"write, never by the acknowledgement the fence exists for", handoffErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handoff stalled behind a carrier that had already been written")
	}
	a.endFrontendHandoff("d")

	a.frontendGateMu.Lock()
	retracted := op.retracted
	carriers := op.carriers
	a.frontendGateMu.Unlock()
	if !retracted {
		t.Fatal("the crossing did not record a retraction")
	}
	if carriers != 0 {
		t.Fatalf("a written frame left %d carrier(s) registered: every later handoff "+
			"on this scope would block forever", carriers)
	}

	// And the retraction still reaches the frontend, on the next reply the
	// operation receives — the ordering the whole mechanism depends on.
	go conn.replyWithPublication(10, operationID, &pfslocal.RemoveReply{}, false)
	if next := readEnvelope(t, frontendSide); !next.PublicationRetracted {
		t.Fatal("a reply written after the crossing did not carry the retraction")
	}
}

// TestRetractionAlreadyTakenIsCarriedWithoutRegisteringACarrier pins the other
// arm of the gate transition. An operation that is ALREADY retracted registers
// nothing: the crossing it would block has completed, so blocking a future one
// would be a pure stall.
func TestRetractionAlreadyTakenIsCarriedWithoutRegisteringACarrier(t *testing.T) {
	a, conn, initiatorCtx, initiator, operationID := newExposedSiblingFixture(t)
	daemonSide, frontendSide := net.Pipe()
	t.Cleanup(func() { _ = daemonSide.Close(); _ = frontendSide.Close() })
	conn.conn = daemonSide

	op := crossOneExposedSibling(t, a, initiatorCtx, initiator)

	observed := -1
	conn.testAfterRetractionCapture = func(uint64) {
		a.frontendGateMu.Lock()
		observed = op.carriers
		a.frontendGateMu.Unlock()
	}
	go conn.replyWithPublication(9, operationID, &pfslocal.RemoveReply{}, false)
	if env := readEnvelope(t, frontendSide); !env.PublicationRetracted {
		t.Fatal("a crossed operation's reply did not carry its retraction")
	}
	if observed != 0 {
		t.Fatalf("an already-retracted operation registered %d carrier(s): the "+
			"crossing it would block on has already happened", observed)
	}
}
