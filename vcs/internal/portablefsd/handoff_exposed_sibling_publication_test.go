package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// ── FINDING 5: A HANDOFF CROSSED AN EXPOSED BUT UNACKNOWLEDGED SIBLING REPLY ─
//
// Round 8 established that a delegation handoff must not cross a LIVE sibling
// participant of the callback that triggered the release. It did not establish
// anything about a sibling that has already REPLIED, and the publication gate
// treated that case as settled on the strength of one sentence in
// publicationBlockersLocked: a reply a sibling has already exposed "happened
// BEFORE the handoff — nothing can cross it now".
//
// It is not before the handoff in the only ordering that matters. Exposure is
// the daemon WRITING the reply. The extension holds those values until its
// framework callback returns; the callback cannot return until the initiator is
// answered; the initiator is parked in the release. So the kernel installs the
// sibling's pre-handoff view AFTER Checkin and AFTER a new delegation holder has
// mutated — and permanently, because the peer's invalidation was delivered and
// applied before that install, so nothing ever contradicts it again.
//
// The live shape is ordinary, not exotic: FSKit's removeItem callback issues a
// publishing getattr on the victim and THEN the remove that needs the delegation
// transition. `rm` inside a delegated subtree is the reproduction.
//
// Two doors were open, and only one of them was the exception named above:
//
//	DOOR 1  the ALL-SUSPENDED RETRACTION. The sibling replies and retires; the
//	        initiator suspends for its own release (OnReleaseWait); the operation
//	        now has participants == suspended and was retracted from the active
//	        publication set outright, so it was not a blocker at all.
//	DOOR 2  the `liveHandlers <= 0 { continue }` exception, reached when the
//	        release goroutine runs before the initiator suspends — which is the
//	        ORDINARY ordering, since prepareReleaseLocked spawns finishRelease
//	        before its caller ever reaches OnReleaseWait.
//
// Both are closed by making EXPOSURE, not participant liveness, the thing that
// creates the obligation. What the handoff does about that obligation depends on
// whether it can ever be discharged; see the two tests below.

// newExposedSiblingFixture builds the removeItem shape: one logical FSKit
// callback whose first request (B) publishes and replies, and whose second
// request (A) is the one that will trigger the delegation release.
//
// The paths are REAL registry bindings rather than a poke at op.paths, because
// the fence this defect is repaired with is an invalidation of exactly those
// paths: a fixture that faked them would prove nothing about the repair.
func newExposedSiblingFixture(t *testing.T) (
	a *attach,
	conn *frontendConn,
	initiatorCtx context.Context,
	initiator *frontendOperationParticipant,
	operationID uint64,
) {
	t.Helper()
	a = newScopeTestAttach()
	// The repair is published as ordinary invalidation events, so the fixture
	// needs the event fan-out newScopeTestAttach leaves nil.
	a.subscribers = map[*eventSubscriber]struct{}{}
	dir := a.bindScopeTestItem(2, "d")
	victim := a.bindScopeTestItem(7, "d/f")
	conn = &frontendConn{}
	operationID = 1

	// B: the publishing getattr on the victim. It is the FIRST request, so it
	// creates the logical operation, exactly as removeItem does.
	siblingCtx, sibling, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.GetAttrRequest{Item: victim},
	)
	if err != nil || sibling == nil {
		t.Fatalf("sibling admission failed: %v", err)
	}
	_ = siblingCtx

	// A: the remove, joining the same callback.
	initializeInitiator, ok := conn.reserveLogicalOperation(operationID, true)
	if !ok || initializeInitiator {
		t.Fatalf("initiator reservation = (initialize=%v, ok=%v)",
			initializeInitiator, ok)
	}
	initiatorCtx, initiator, _, _, err = conn.beginLogicalOperation(
		context.Background(), a, operationID, false,
		&pfslocal.RemoveRequest{Dir: dir, Name: []byte("f")},
	)
	if err != nil || initiator == nil {
		t.Fatalf("initiator admission failed: %v", err)
	}
	if err := activateTestParticipant(initiatorCtx, a, initiator); err != nil {
		t.Fatal(err)
	}

	// B writes its reply and its handler returns. The reply is EXPOSED; the
	// PublicationAck cannot follow it, because the framework callback that owns
	// it is still running A.
	exposeTestLogicalOperation(t, conn, operationID)
	a.finishFrontendParticipant(sibling)
	conn.finishLogicalRequest(operationID)
	_ = victim
	return a, conn, initiatorCtx, initiator, operationID
}

// TestHandoffNeverCrossesAnExposedSiblingPublicationSilently is the barrier
// hole itself, driven through DOOR 1 — the production ordering, in which the
// initiator has already suspended for its release when the gate is consulted.
//
// Before the fix the operation had been retracted from the active publication
// set by that suspension and startFrontendHandoff returned nil INSTANTLY,
// leaving no trace anywhere that a publication had been crossed. That is the
// state a new delegation holder mutates in.
//
// The handoff still has to complete — the acknowledgement it would be waiting
// for is unreachable by construction, so blocking is a deterministic cycle
// rather than a wait (see TestHandoffWithAnUnreachableAckDoesNotStall) — but it
// may only complete against a RECORDED crossing, and that record must turn into
// a real repair the instant the acknowledgement lands.
func TestHandoffNeverCrossesAnExposedSiblingPublicationSilently(t *testing.T) {
	restore := publicationSettleWindow
	publicationSettleWindow = 300 * time.Millisecond
	t.Cleanup(func() { publicationSettleWindow = restore })

	a, conn, initiatorCtx, initiator, operationID := newExposedSiblingFixture(t)
	op := initiator.op

	// The exposed publication must survive the suspension that DOOR 1 used to
	// erase it. An operation that owes an acknowledgement is not idle just
	// because none of its requests is running.
	resume := a.suspendFrontendOperation(initiatorCtx)
	if resume == nil {
		t.Fatal("the initiator did not suspend for its release")
	}
	a.frontendGateMu.Lock()
	_, stillActive := a.frontendActive[op]
	a.frontendGateMu.Unlock()
	if !stillActive {
		t.Fatal("an operation with an exposed, unacknowledged reply was retracted " +
			"from the active publication set when its last participant suspended: " +
			"the handoff barrier can no longer see the publication it must not cross")
	}

	handoff := make(chan error, 1)
	go func() { handoff <- a.startFrontendHandoff(initiatorCtx, "d") }()
	select {
	case err := <-handoff:
		if err != nil {
			t.Fatalf("the release could not open its handoff: %v — the acknowledgement "+
				"it is waiting for cannot arrive while the initiator is parked inside "+
				"this very release, so every rm that releases a delegation would fail", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the handoff never reached a verdict")
	}

	// THE PROPERTY. The crossing is recorded against the operation that owed
	// the acknowledgement, naming the scope that was handed off.
	a.frontendGateMu.Lock()
	fenced := append([]string(nil), op.fenced...)
	a.frontendGateMu.Unlock()
	if len(fenced) != 1 || fenced[0] != "d" {
		t.Fatalf("crossed publication fence = %q, want [\"d\"]: the handoff completed "+
			"across an exposed, unacknowledged sibling reply without recording it, so "+
			"the kernel installs that pre-handoff view after the new delegation holder "+
			"has mutated and nothing ever contradicts it", fenced)
	}

	// AND THE REPAIR. The acknowledgement is the first instant at which the
	// daemon knows the frontend has installed the crossed state, so it is the
	// instant the repair must be issued.
	sub := a.subscribe(0)
	a.endFrontendHandoff("d")
	if resume != nil {
		resume()
	}
	a.finishFrontendParticipant(initiator)
	conn.finishLogicalRequest(operationID)
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("publication acknowledgement was rejected")
	}

	a.frontendGateMu.Lock()
	remaining := len(op.fenced)
	a.frontendGateMu.Unlock()
	if remaining != 0 {
		t.Fatalf("the crossing fence was still owed (%d scope(s)) after the "+
			"publication was acknowledged", remaining)
	}

	invalidated := map[string]bool{}
	deadline := time.After(2 * time.Second)
collect:
	for {
		select {
		case ev := <-sub.ch:
			inv, ok := ev.Kind.(*pfslocal.Invalidation)
			if !ok {
				continue
			}
			for _, rec := range []*itemRecord{a.paths["d"], a.paths["d/f"]} {
				if rec != nil && rec.item.ItemID == inv.Item.ItemID {
					invalidated[rec.path] = true
				}
			}
			if invalidated["d"] && invalidated["d/f"] {
				break collect
			}
		case <-deadline:
			break collect
		}
	}
	if !invalidated["d/f"] {
		t.Fatalf("acknowledging a CROSSED publication did not invalidate the state it "+
			"published (%v): the kernel keeps the pre-handoff view of d/f forever, "+
			"because the peer's own invalidation was applied before the install",
			invalidated)
	}
	if !invalidated["d"] {
		t.Fatalf("acknowledging a CROSSED publication did not invalidate the parent "+
			"scope it published (%v)", invalidated)
	}
}

// TestHandoffWithAnUnreachableAckDoesNotStall is the liveness half, and it is
// the reason the crossing is FENCED rather than waited for.
//
// The acknowledgement this handoff would wait for is emitted by the extension
// after its whole framework callback returns; the callback cannot return until
// the initiator's request is answered; the initiator's request is not answered
// until this release reaches a verdict. That is a cycle, and it is closed by
// construction rather than by timing — so "just block on it" is not a bound at
// all, it is a guaranteed settle-window stall followed by a failed release, and
// it would fail every `rm` that has to release a delegation.
//
// Driven through DOOR 2: the release goroutine reaches the gate before the
// initiator suspends, which is the ordinary ordering because
// prepareReleaseLocked spawns finishRelease before its caller reaches
// OnReleaseWait.
func TestHandoffWithAnUnreachableAckDoesNotStall(t *testing.T) {
	restore := publicationSettleWindow
	// Long enough that a stall is unmistakably a stall and not a slow machine.
	publicationSettleWindow = 30 * time.Second
	t.Cleanup(func() { publicationSettleWindow = restore })

	a, _, initiatorCtx, initiator, _ := newExposedSiblingFixture(t)

	handoff := make(chan error, 1)
	start := time.Now()
	go func() { handoff <- a.startFrontendHandoff(initiatorCtx, "d") }()
	select {
	case err := <-handoff:
		if err != nil {
			t.Fatalf("handoff verdict = %v, want success against a fenced crossing", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the handoff stalled on an acknowledgement that cannot arrive: the " +
			"initiator's own callback cannot return while its request is parked in " +
			"this release, so the release burns its whole budget and fails")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the handoff took %s against an unreachable acknowledgement: it "+
			"waited rather than fencing", elapsed)
	}
	a.frontendGateMu.Lock()
	fenced := append([]string(nil), initiator.op.fenced...)
	a.frontendGateMu.Unlock()
	if len(fenced) != 1 || fenced[0] != "d" {
		t.Fatalf("crossed publication fence = %q, want [\"d\"]", fenced)
	}
	a.endFrontendHandoff("d")
}

// TestMountWideExposedPublicationIsFencedAtTheRootNotRefused pins the fence's
// fallback, and it exists because the obvious "only cross what you can name"
// rule is WRONG here.
//
// Lookup and Enumerate publish at the conservative mount-wide scope (see
// frontendOperationPaths: a hard link can alias the published inode under a
// scope whose handoff has already passed), so an operation that includes one
// has no narrow set of paths to repair. Declining to cross it looks like the
// safe choice and is not: a refusal in this arm is retried by
// startHandoffBounded against a verdict that cannot change, failRelease then
// records a definite failure, and the syscall answers EIO. That is the round-4
// wedge, reached by a new route — and it would fire on the continuation shapes
// round 6 fixed, which run mount-wide handoffs against their own operation as a
// matter of course.
//
// So the crossing is taken and repaired at the root, which is what the
// conservative publication scope already names.
func TestMountWideExposedPublicationIsFencedAtTheRootNotRefused(t *testing.T) {
	restore := publicationSettleWindow
	publicationSettleWindow = 200 * time.Millisecond
	t.Cleanup(func() { publicationSettleWindow = restore })

	a := newScopeTestAttach()
	a.subscribers = map[*eventSubscriber]struct{}{}
	root := a.bindScopeTestItem(1, "")
	dir := a.bindScopeTestItem(2, "d")
	conn := &frontendConn{}
	const operationID uint64 = 1

	// A lookup: mount-wide publication scope.
	_, sibling, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.LookupRequest{Dir: dir, Name: []byte("f")},
	)
	if err != nil || sibling == nil {
		t.Fatalf("sibling admission failed: %v", err)
	}
	initializeInitiator, ok := conn.reserveLogicalOperation(operationID, true)
	if !ok || initializeInitiator {
		t.Fatalf("initiator reservation = (initialize=%v, ok=%v)",
			initializeInitiator, ok)
	}
	initiatorCtx, initiator, _, _, err := conn.beginLogicalOperation(
		context.Background(), a, operationID, false,
		&pfslocal.RemoveRequest{Dir: dir, Name: []byte("f")},
	)
	if err != nil || initiator == nil {
		t.Fatalf("initiator admission failed: %v", err)
	}
	if err := activateTestParticipant(initiatorCtx, a, initiator); err != nil {
		t.Fatal(err)
	}
	exposeTestLogicalOperation(t, conn, operationID)
	a.finishFrontendParticipant(sibling)
	conn.finishLogicalRequest(operationID)

	handoff := make(chan error, 1)
	go func() { handoff <- a.startFrontendHandoff(initiatorCtx, "") }()
	select {
	case err := <-handoff:
		if err != nil {
			t.Fatalf("handoff verdict = %v: a mount-wide publication the release's own "+
				"callback owes cannot be waited for, and refusing it wedges the release "+
				"and answers EIO to the syscall", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the handoff never reached a verdict")
	}
	a.frontendGateMu.Lock()
	fenced := append([]string(nil), initiator.op.fenced...)
	a.frontendGateMu.Unlock()
	if len(fenced) != 1 {
		t.Fatalf("crossed publication fence = %q, want the mount-wide scope recorded",
			fenced)
	}

	sub := a.subscribe(0)
	a.endFrontendHandoff("")
	a.finishFrontendParticipant(initiator)
	conn.finishLogicalRequest(operationID)
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("publication acknowledgement was rejected")
	}
	rootInvalidated := false
	deadline := time.After(2 * time.Second)
collect:
	for {
		select {
		case ev := <-sub.ch:
			if inv, ok := ev.Kind.(*pfslocal.Invalidation); ok &&
				inv.Item.ItemID == root.ItemID {
				rootInvalidated = true
				break collect
			}
		case <-deadline:
			break collect
		}
	}
	if !rootInvalidated {
		t.Fatal("a crossed mount-wide publication was never repaired: the frontend " +
			"keeps a pre-handoff view the daemon knowingly let a new delegation " +
			"holder mutate underneath")
	}
}
