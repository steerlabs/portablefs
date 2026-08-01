package portablefsd

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// ── FINDING 2 (ROUND 10): A CROSSING MUST NOT LEAVE AN INSTALLABLE STALE VIEW ─
//
// Round 9 established that a handoff may cross an operation whose participants
// are all parked and which has already exposed a reply, because the
// acknowledgement it would otherwise wait for is unreachable by construction. It
// answered the resulting divergence with a RECORDED debt repaired when the
// acknowledgement lands.
//
// Two things were wrong with that answer.
//
//	1. IT WAS NOT ORDERED. Even a prompt repair names a window in which the
//	   kernel holds — and an application can read — a value the daemon already
//	   knows is wrong. The mount's model is version-anchored with a zero TTL, so
//	   a window is not a smaller violation of it; it is the violation.
//	2. IT WAS NOT CONNECTED. The repair published pfslocal invalidation events,
//	   which reach a connection only after SubscribeEventsRequest — and the FSKit
//	   extension never sends one. On the frontend the whole mechanism exists for,
//	   the repair fanned out to an empty subscriber set and the crossed value was
//	   never contradicted at all.
//
// The answer is RETRACTION: the frontend is told, on a reply that provably
// precedes the framework install, that the crossed operation's collected values
// must be discarded rather than returned. Nothing stale is installed, so there
// is no window to bound. The fence survives as a backstop and is now an ordered
// repair through the daemon's own kernel refresh — the mechanism FSKit coherence
// actually uses.

// readEnvelope decodes one frame from the frontend side of a socket pair.
func readEnvelope(t *testing.T, r net.Conn) *pfslocal.Envelope {
	t.Helper()
	type result struct {
		env *pfslocal.Envelope
		err error
	}
	done := make(chan result, 1)
	go func() {
		env, err := pfslocal.ReadFrame(r)
		done <- result{env, err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("read frame: %v", got.err)
		}
		return got.env
	case <-time.After(4 * time.Second):
		t.Fatal("no reply frame arrived")
		return nil
	}
}

// crossOneExposedSibling drives newExposedSiblingFixture's operation all the way
// to a completed handoff over scope "d", which is the state a crossing leaves
// behind. It returns the crossed operation.
func crossOneExposedSibling(
	t *testing.T,
	a *attach,
	initiatorCtx context.Context,
	initiator *frontendOperationParticipant,
) *frontendOperation {
	t.Helper()
	restore := publicationSettleWindow
	publicationSettleWindow = 300 * time.Millisecond
	t.Cleanup(func() { publicationSettleWindow = restore })

	resume := a.suspendFrontendOperation(initiatorCtx)
	if resume == nil {
		t.Fatal("the initiator did not suspend for its release")
	}
	t.Cleanup(resume)
	handoff := make(chan error, 1)
	go func() { handoff <- a.startFrontendHandoff(initiatorCtx, "d") }()
	select {
	case err := <-handoff:
		if err != nil {
			t.Fatalf("the release could not open its handoff: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the handoff never reached a verdict")
	}
	a.endFrontendHandoff("d")
	return initiator.op
}

// TestCrossedPublicationRetractsEveryRemainingReply is the property the whole
// finding reduces to: after a handoff has crossed an operation, no reply that
// operation still receives may let the frontend install what it collected.
//
// The reply under test is the INITIATOR's — the request parked inside the
// release. That is the reply the framework callback is waiting for, so it is the
// last thing that happens before the install, and stamping the retraction on it
// is what makes the retraction ordered before the install rather than racing it.
// It is also deliberately a NON-publishing reply path here, because whether the
// request that unblocks the callback happens to publish is unrelated to whether
// it is the carrier the retraction needs.
func TestCrossedPublicationRetractsEveryRemainingReply(t *testing.T) {
	a, conn, initiatorCtx, initiator, operationID := newExposedSiblingFixture(t)
	daemonSide, frontendSide := net.Pipe()
	t.Cleanup(func() { _ = daemonSide.Close(); _ = frontendSide.Close() })
	conn.conn = daemonSide

	op := crossOneExposedSibling(t, a, initiatorCtx, initiator)
	a.frontendGateMu.Lock()
	retracted := op.retracted
	a.frontendGateMu.Unlock()
	if !retracted {
		t.Fatal("a handoff crossed an exposed, unacknowledged publication without " +
			"retracting it: the frontend will hand the pre-handoff view to the " +
			"framework after a new delegation holder has already mutated, and an " +
			"application can read it")
	}

	go conn.replyWithPublication(9, operationID, &pfslocal.RemoveReply{}, false)
	env := readEnvelope(t, frontendSide)
	if !env.PublicationRetracted {
		t.Fatal("the reply that unblocks the crossed operation's framework callback " +
			"did not carry the retraction: it is the last frame before the install, " +
			"so a retraction that misses it has no carrier that precedes the install " +
			"at all")
	}

	// A reply for an operation nothing crossed must be untouched. The retraction
	// is a statement about one operation, and a frontend that discarded every
	// operation's results would be a mount that caches nothing.
	other := uint64(2)
	if initialize, ok := conn.reserveLogicalOperation(other, true); !ok || !initialize {
		t.Fatalf("second operation reservation = (initialize=%v, ok=%v)", initialize, ok)
	}
	go conn.replyWithPublication(10, other, &pfslocal.RemoveReply{}, false)
	if env := readEnvelope(t, frontendSide); env.PublicationRetracted {
		t.Fatal("an operation no handoff crossed was told to discard its publications")
	}
}

// TestEveryCrossedPublicationIsRecordedNotJustTheLastOneSeen is the second
// defect in the same decision. The crossing used to be collected into a single
// slot, overwritten by each matching operation the map iteration reached, so two
// overlapping all-parked publications left ONE of them crossed with no record at
// all — not retracted, not repaired, and permanently stale. Map iteration order
// decided which, so it was unreproducible by construction.
func TestEveryCrossedPublicationIsRecordedNotJustTheLastOneSeen(t *testing.T) {
	restore := publicationSettleWindow
	publicationSettleWindow = 300 * time.Millisecond
	t.Cleanup(func() { publicationSettleWindow = restore })

	a, conn, initiatorCtx, initiator, _ := newExposedSiblingFixture(t)

	// A SECOND framework callback, entirely separate, with the same shape: an
	// exposed publication over the same scope and every participant parked.
	victim := a.bindScopeTestItem(11, "d/g")
	secondID := uint64(2)
	secondCtx, second, _, _, err := beginTestLogicalOperation(
		t, conn, a, secondID, &pfslocal.GetAttrRequest{Item: victim},
	)
	if err != nil || second == nil {
		t.Fatalf("second operation admission failed: %v", err)
	}
	exposeTestLogicalOperation(t, conn, secondID)
	if resume := a.suspendFrontendOperation(secondCtx); resume != nil {
		t.Cleanup(resume)
	} else {
		t.Fatal("the second operation did not suspend")
	}

	op := crossOneExposedSibling(t, a, initiatorCtx, initiator)

	a.frontendGateMu.Lock()
	firstFenced := len(op.fenced)
	firstRetracted := op.retracted
	secondFenced := len(second.op.fenced)
	secondRetracted := second.op.retracted
	a.frontendGateMu.Unlock()

	if !firstRetracted || firstFenced == 0 {
		t.Fatalf("the initiator's own crossed operation was not recorded "+
			"(retracted=%v fenced=%d)", firstRetracted, firstFenced)
	}
	if !secondRetracted || secondFenced == 0 {
		t.Fatalf("a second crossed publication over the same scope was not recorded "+
			"(retracted=%v fenced=%d): the handoff crossed it anyway, so its "+
			"pre-handoff view reaches the kernel with nothing to contradict it",
			secondRetracted, secondFenced)
	}
}

// TestCrossedPublicationRepairDrivesTheKernelRefresh pins the backstop to the
// mechanism that actually reaches an FSKit vnode.
//
// The repair used to be an invalidation event and nothing else. pfslocal events
// are delivered only to connections that sent SubscribeEventsRequest, and the
// production extension never sends one, so on the frontend this exists for the
// repair was a fan-out to an empty set: the crossed value was installed and
// never contradicted. What reaches the kernel is the daemon's own exact refresh
// — the same call the authority invalidation watcher makes for a peer change,
// and with the same fail-closed verdict when it cannot be completed.
func TestCrossedPublicationRepairDrivesTheKernelRefresh(t *testing.T) {
	a, conn, initiatorCtx, initiator, operationID := newExposedSiblingFixture(t)

	refreshed := make(chan uint64, 8)
	a.testExactKernelRefresh = func(_ context.Context, itemID uint64) error {
		refreshed <- itemID
		return nil
	}

	op := crossOneExposedSibling(t, a, initiatorCtx, initiator)
	a.frontendGateMu.Lock()
	crossed := len(op.fenced) != 0
	a.frontendGateMu.Unlock()
	if !crossed {
		t.Fatal("the fixture did not reach a crossing")
	}

	a.finishFrontendParticipant(initiator)
	conn.finishLogicalRequest(operationID)
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("publication acknowledgement was rejected")
	}

	select {
	case <-refreshed:
	case <-time.After(4 * time.Second):
		t.Fatal("the crossing's repair never drove a kernel refresh: it published an " +
			"invalidation event to a subscriber set an FSKit mount is never in, so " +
			"the crossed state was left in the kernel with nothing to contradict it")
	}

	a.frontendGateMu.Lock()
	remaining := len(op.fenced)
	stillRetracted := op.retracted
	a.frontendGateMu.Unlock()
	if remaining != 0 || stillRetracted {
		t.Fatalf("the crossing was still outstanding after the repair "+
			"(fenced=%d retracted=%v)", remaining, stillRetracted)
	}
}

// TestRetractionNeverRidesAnOperationsFirstReply pins the invariant the
// frontend's acknowledgement depends on.
//
// The frontend learns which connection owes the acknowledgement from the
// operation's earlier ack-required reply. A retraction arriving as an
// operation's FIRST reply would therefore leave it holding no connection to
// acknowledge on, and the daemon would wait out its whole settle window for an
// acknowledgement nobody was in a position to send — a hang, not a wrong
// answer, which is exactly the kind of failure that is worth checking rather
// than reasoning about.
//
// It cannot happen: a crossing only ever nominates an operation that has
// already exposed a reply. This asserts the guard that makes that a property of
// the code rather than of the argument.
func TestRetractionNeverRidesAnOperationsFirstReply(t *testing.T) {
	a := newScopeTestAttach()
	conn := &frontendConn{}
	victim := a.bindScopeTestItem(5, "d/f")

	const operationID = uint64(1)
	_, participant, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.GetAttrRequest{Item: victim},
	)
	if err != nil || participant == nil {
		t.Fatalf("admission failed: %v", err)
	}

	// Retract an operation that has exposed NOTHING. Production cannot reach
	// this state; the guard is what keeps that true across future rearrangement.
	a.frontendGateMu.Lock()
	participant.op.retracted = true
	a.frontendGateMu.Unlock()

	if conn.publicationRetracted(operationID) {
		t.Fatal("a retraction was stamped on an operation that had exposed no reply: " +
			"the frontend has no connection to acknowledge on, so the daemon would " +
			"wait out its settle window for an acknowledgement nobody could send")
	}

	// Once a reply IS exposed, the same operation carries the retraction.
	exposeTestLogicalOperation(t, conn, operationID)
	if !conn.publicationRetracted(operationID) {
		t.Fatal("an exposed, crossed operation did not carry its retraction")
	}
}

// TestCrossedOperationRefusesItsOwnMutationBeforeExecutingIt is what makes the
// retraction safe for a mutation, and it is the half that is easy to get wrong.
//
// The retraction fails the whole framework callback, so if the initiator's own
// request had already RUN, that failure would be a lie about a mutation that
// really happened. The shape that reaches a crossing is precisely a callback
// whose last request needed the delegation released — FSKit's removeItem — so
// `rm` would remove the file, be reported as interrupted, and answer ENOENT on
// the retry the interruption asks for.
//
// So the initiator refuses before executing. It can, and this is the whole
// reason the design is not the round-4 wedge: by the time the refusal is
// reached the release has ALREADY COMPLETED, so the retry has no delegation
// left to release and cannot reach this state a second time. A refusal taken
// before the release would leave the delegation in place, and the retry would
// run the identical callback, expose the identical sibling publication, and be
// refused again forever.
func TestCrossedOperationRefusesItsOwnMutationBeforeExecutingIt(t *testing.T) {
	a, _, initiatorCtx, initiator, _ := newExposedSiblingFixture(t)
	op := crossOneExposedSibling(t, a, initiatorCtx, initiator)

	a.frontendGateMu.Lock()
	retracted := op.retracted
	a.frontendGateMu.Unlock()
	if !retracted {
		t.Fatal("the fixture did not reach a retracting crossing")
	}
	if !a.publicationRetracted(initiator.op) {
		t.Fatal("the initiator cannot see that its own operation was crossed, so it " +
			"goes on to execute a mutation whose result the frontend will discard: " +
			"the file is removed and the application is told the call was interrupted")
	}

	// And the verdict clears with the crossing, so the retry — a fresh operation
	// with no delegation left to release — is not refused in turn.
	a.finishFrontendParticipant(initiator)
	a.dischargeFrontendPublicationFence(op)
	if a.publicationRetracted(op) {
		t.Fatal("the retraction outlived the crossing it described: the operation " +
			"would keep refusing requests after the state that caused it was repaired")
	}
}

// TestDisconnectRepairsACrossingRatherThanDroppingIt closes the crash-safety
// half. A crossing's debt lived only in memory on a connection that was about to
// be torn down, and the teardown retired the operation without repairing it.
//
// The justification was that a lost connection takes the frontend's cache with
// it. That is true of the ACKNOWLEDGEMENT and false of the cache: an FSKit mount
// outlives the daemon connection — an extension reconnects to a restarted daemon
// and keeps every vnode it holds — so a scope the handoff crossed can still be
// cached in a kernel this daemon goes on serving.
func TestDisconnectRepairsACrossingRatherThanDroppingIt(t *testing.T) {
	a, conn, initiatorCtx, initiator, _ := newExposedSiblingFixture(t)
	daemonSide, frontendSide := net.Pipe()
	t.Cleanup(func() { _ = frontendSide.Close() })
	conn.conn = daemonSide

	refreshed := make(chan uint64, 8)
	a.testExactKernelRefresh = func(_ context.Context, itemID uint64) error {
		refreshed <- itemID
		return nil
	}

	op := crossOneExposedSibling(t, a, initiatorCtx, initiator)
	a.frontendGateMu.Lock()
	crossed := len(op.fenced) != 0
	a.frontendGateMu.Unlock()
	if !crossed {
		t.Fatal("the fixture did not reach a crossing")
	}

	conn.close()

	select {
	case <-refreshed:
	case <-time.After(4 * time.Second):
		t.Fatal("a frontend disconnect retired a crossed operation without repairing " +
			"the scope it had crossed, leaving stale state in a kernel whose mount " +
			"outlives this connection")
	}
}
