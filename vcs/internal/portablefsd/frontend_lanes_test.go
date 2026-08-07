package portablefsd

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// The live failure this pins: the frontend's control lane (visibility
// acknowledgments, liveness) deliberately overtakes queued ordinary requests,
// so under a mutation storm a barrier acknowledgment legally arrives with a
// LOWER request id than an ordinary frame already received. A single global
// watermark read that as replay and closed the connection — killing the mount
// the moment it was busy enough for the ack to overtake anything.
func TestControlLaneMayOvertakeOrdinaryRequests(t *testing.T) {
	var lastRequest, lastControl uint64
	admit := func(body any, id uint64) bool {
		_, ok := admitLaneRequestID(body, id, &lastRequest, &lastControl)
		return ok
	}
	lookup := &pfslocal.LookupRequest{}
	ack := &pfslocal.VisibilityAckRequest{}
	liveness := &pfslocal.V3LivenessRequest{}

	if !admit(lookup, 5) {
		t.Fatal("ordinary request 5 refused")
	}
	// The storm shape: the ack was allocated id 3 before the burst but its
	// lane delivered it after ordinary id 5.
	if !admit(ack, 3) {
		t.Fatal("a control frame with a lower id than the ordinary watermark was refused; the priority lane's whole point is overtaking the request burst")
	}
	if !admit(lookup, 6) {
		t.Fatal("ordinary request 6 refused after a control frame")
	}
	if !admit(liveness, 4) {
		t.Fatal("liveness with a lower id than the ordinary watermark was refused")
	}

	// Replay protection survives per lane.
	if admit(lookup, 6) {
		t.Fatal("a replayed ordinary id was admitted")
	}
	if admit(ack, 4) {
		t.Fatal("a replayed control id was admitted")
	}
	if admit(lookup, 0) {
		t.Fatal("request id zero was admitted")
	}
}

func publicationTestOperation(
	t *testing.T,
	c *frontendConn,
	a *attach,
	operationID uint64,
) (*frontendOperation, *frontendOperationParticipant) {
	t.Helper()
	initialize, ok := c.reserveLogicalOperation(operationID, true)
	if !ok || !initialize {
		t.Fatal("publishing operation was not reserved")
	}
	if bridge := a.v3CoherenceBridge(); bridge != nil {
		bridge.reserveFrontendPublication(operationID)
	}
	_, participant, participates, publishes, err := c.beginLogicalOperation(
		context.Background(), a, operationID, true, &pfslocal.GetAttrRequest{},
	)
	if err != nil || !participates || !publishes || participant == nil {
		t.Fatalf(
			"begin publishing operation = participant=%v participates=%v publishes=%v error=%v",
			participant, participates, publishes, err,
		)
	}
	c.publicationMu.Lock()
	op := c.operations[operationID].op
	c.publicationMu.Unlock()
	if op == nil {
		t.Fatal("publishing operation has no gate record")
	}
	return op, participant
}

func publicationTestAttach(t *testing.T) (*attach, *v3DataPlane) {
	t.Helper()
	d := testV3DataPlane(t, newFakeV3DataClient())
	a := &attach{
		ref:         "publication-test",
		v3Data:      d,
		v3Coherence: d.bridge,
	}
	return a, d
}

// A request-local frontend timeout can acknowledge the callback while its
// daemon handler is still running. If that handler later produces a publishing
// reply, no callback remains to install it and no second PublicationAck can
// exist. The reply must not be written or counted as a safe publication; the
// exact mount incarnation is terminal synchronously.
func TestPublishingReplyAfterCallbackAcknowledgementFencesBeforeExposure(t *testing.T) {
	const operationID = uint64(301)
	a, d := publicationTestAttach(t)
	c := &frontendConn{attach: a}
	op, participant := publicationTestOperation(t, c, a, operationID)

	if !c.acknowledgePublication(operationID) {
		t.Fatal("early callback acknowledgement was refused")
	}
	if !d.bridge.acknowledgePublication(operationID) {
		t.Fatal("early callback acknowledgement missed the authority publication ledger")
	}
	if c.markPublicationReplyExposed(operationID) {
		t.Fatal("late publishing reply was treated as deliverable")
	}

	terminal := d.terminalError()
	if !errors.Is(terminal, errFrontendPublicationUnprovable) ||
		!strings.Contains(terminal.Error(), "after its callback acknowledged") {
		t.Fatalf("terminal cause = %v", terminal)
	}
	c.publicationMu.Lock()
	exposed := c.operations[operationID].replyExposed
	c.publicationMu.Unlock()
	if exposed {
		t.Fatal("late reply was recorded as an exposed publication")
	}
	a.frontendGateMu.Lock()
	completed := op.completed
	_, active := a.frontendActive[op]
	a.frontendGateMu.Unlock()
	if !completed || active {
		t.Fatalf("gate retired before fence = completed=%v active=%v", completed, active)
	}

	a.finishFrontendParticipant(participant)
	c.finishLogicalRequest(operationID)
}

// The socket can disappear after the daemon pinned a publishing reply but
// before FSKit's PublicationAck. Teardown must first retire the publication
// gate (waking any handoff cycle), then synchronously fence the v3 session; it
// must not park forever waiting for handlers or invent a later repair.
func TestFrontendDisconnectWithExposedPublicationRetiresThenFences(t *testing.T) {
	const operationID = uint64(302)
	a, d := publicationTestAttach(t)
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	op, participant := publicationTestOperation(t, c, a, operationID)
	if !c.markPublicationReplyExposed(operationID) {
		t.Fatal("publishing reply was not exposed")
	}
	// Model the visibility subscriber's generic disconnect verdict exactly at
	// connection cancellation. The publication-loss cause must already own the
	// data plane's one-shot terminal slot by then.
	c.cancel = func() { a.fenceV3(context.Canceled) }

	closed := make(chan struct{})
	go func() {
		c.close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("frontend close deadlocked behind its publication gate")
	}

	terminal := d.terminalError()
	if !errors.Is(terminal, errFrontendPublicationUnprovable) ||
		!strings.Contains(terminal.Error(), "without PublicationAck") {
		t.Fatalf("terminal cause = %v", terminal)
	}
	a.frontendGateMu.Lock()
	completed := op.completed
	_, active := a.frontendActive[op]
	a.frontendGateMu.Unlock()
	if !completed || active {
		t.Fatalf("disconnect gate retirement = completed=%v active=%v", completed, active)
	}
	a.finishFrontendParticipant(participant)
}

// Visible mutation replies carry both a PublicationAck obligation and a
// provisional item capability. Abandoning the item is itself terminal because
// source COMPLETE may have assumed it was published, but on disconnect the
// missing publication acknowledgement is the earlier and more exact failure.
// Closing the resource table must prevent new transfers without allowing the
// generic visible-abandon cause to steal failOnce.
func TestLostPublicationCauseWinsVisibleProvisionalAbandonment(t *testing.T) {
	const operationID = uint64(304)
	a, d := publicationTestAttach(t)
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	_, participant := publicationTestOperation(t, c, a, operationID)
	if !c.markPublicationReplyExposed(operationID) {
		t.Fatal("visible mutation reply was not exposed")
	}

	collector := &v3ReplyResourceCollector{d: d, visible: true}
	record := collectTestItem(
		t, d, collector,
		authorityTestItem(2, authoritypb.Attr_DIRECTORY, 0x6a, 0x7a),
	)
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	if !c.registerProvisionalResource(404, resources) {
		t.Fatal("visible provisional reply was not registered")
	}
	c.cancel = func() { a.fenceV3(context.Canceled) }

	c.close()
	terminal := d.terminalError()
	if !errors.Is(terminal, errFrontendPublicationUnprovable) ||
		!strings.Contains(terminal.Error(), "without PublicationAck") {
		t.Fatalf("terminal cause = %v", terminal)
	}
	if strings.Contains(terminal.Error(), "successful visible resource reply") {
		t.Fatalf("visible abandonment stole the exact publication cause: %v", terminal)
	}
	c.resourceMu.Lock()
	resourceClosed := c.resourceClosed
	provisionalReplies := len(c.provisional)
	c.resourceMu.Unlock()
	d.mu.Lock()
	_, itemReachable := d.itemsByID[record.item.ItemID]
	_, identityReachable := d.itemsByIdentity[record.item.StableIdentity]
	provisionalClaims := record.provisional
	d.mu.Unlock()
	if !resourceClosed || provisionalReplies != 0 || itemReachable ||
		identityReachable || provisionalClaims != 0 {
		t.Fatalf(
			"post-close resources: tableClosed=%v replies=%d item=%v identity=%v claims=%d",
			resourceClosed, provisionalReplies, itemReachable, identityReachable, provisionalClaims,
		)
	}
	a.finishFrontendParticipant(participant)
}

// Closing a connection does not itself turn an unexposed request, or a reply
// whose callback already acknowledged it, into a publication-loss verdict.
// The strict visibility stream independently owns unexpected subscriber loss;
// this ledger must fence only when its own cache proof is genuinely missing.
func TestFrontendDisconnectDoesNotFenceHarmlessPublicationStates(t *testing.T) {
	for _, test := range []struct {
		name        string
		expose      bool
		acknowledge bool
	}{
		{name: "unexposed"},
		{name: "exposed and acknowledged", expose: true, acknowledge: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const operationID = uint64(303)
			a, d := publicationTestAttach(t)
			server, peer := net.Pipe()
			defer peer.Close()
			c := &frontendConn{conn: server, attach: a}
			_, participant := publicationTestOperation(t, c, a, operationID)
			if test.expose && !c.markPublicationReplyExposed(operationID) {
				t.Fatal("publishing reply was not exposed")
			}
			if test.acknowledge {
				if !c.acknowledgePublication(operationID) ||
					!d.bridge.acknowledgePublication(operationID) {
					t.Fatal("publication acknowledgement was refused")
				}
			}

			c.close()
			if terminal := d.terminalError(); terminal != nil {
				t.Fatalf("harmless teardown fenced v3 session: %v", terminal)
			}
			a.finishFrontendParticipant(participant)
		})
	}
}

func TestSourcePhaseQueueabilityWireShape(t *testing.T) {
	for _, test := range []struct {
		name        string
		body        any
		operationID uint64
		queueable   bool
		want        bool
	}{
		{name: "absent ordinary", body: &pfslocal.GetAttrRequest{}, want: true},
		{name: "absent ordered", body: &pfslocal.WriteRequest{}, want: true},
		{name: "ordered identified", body: &pfslocal.WriteRequest{}, operationID: 9, queueable: true, want: true},
		{name: "ordered unidentified", body: &pfslocal.WriteRequest{}, queueable: true},
		{name: "ordinary identified", body: &pfslocal.GetAttrRequest{}, operationID: 9, queueable: true},
		{name: "nonpublishing identified", body: &pfslocal.OpenRequest{}, operationID: 9, queueable: true},
		{name: "hello control body", body: &pfslocal.Hello{}, operationID: 9, queueable: true},
		{name: "resolve control body", body: &pfslocal.ResolveRequest{}, operationID: 9, queueable: true},
		{name: "visibility ack control body", body: &pfslocal.VisibilityAckRequest{}, operationID: 9, queueable: true},
		{name: "publication ack control body", body: &pfslocal.PublicationAck{}, operationID: 9, queueable: true},
		{name: "liveness control body", body: &pfslocal.V3LivenessRequest{}, operationID: 9, queueable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validFrontendSourcePhaseQueueability(
				test.body, test.operationID, test.queueable,
			); got != test.want {
				t.Fatalf("validity = %v, want %v", got, test.want)
			}
		})
	}
}

// The live op91 failure landed in this exact interval: the serial reader had
// consumed and reserved the publishing request, then the frontend's priority
// writer delivered the callback acknowledgement before the handler goroutine
// entered beginLogicalOperation. Reservation, not goroutine scheduling, is the
// protocol boundary. Every handler whose frame was reserved before the ack must
// still run; frames observed after it must not join the spent operation.
func TestPublicationAckBetweenReservationAndBeginKeepsReservedHandlers(t *testing.T) {
	const operationID = uint64(91)
	c := &frontendConn{}
	a := &attach{}

	initialize, ok := c.reserveLogicalOperation(operationID, true)
	if !ok || !initialize {
		t.Fatal("first publishing frame did not reserve the logical operation")
	}
	continuationInitialize, ok := c.reserveLogicalOperation(operationID, false)
	if !ok || continuationInitialize {
		t.Fatal("already-arrived continuation did not join the reservation")
	}

	c.publicationMu.Lock()
	entry := c.operations[operationID]
	if entry == nil || entry.op != nil || entry.activeRequests != 2 {
		c.publicationMu.Unlock()
		t.Fatalf("pre-handler reservation = %+v, want op=nil activeRequests=2", entry)
	}
	c.publicationMu.Unlock()

	if !c.acknowledgePublication(operationID) {
		t.Fatal("acknowledgement of a serial-reader reservation was refused")
	}
	if c.acknowledgePublication(operationID) {
		t.Fatal("duplicate acknowledgement was accepted")
	}
	if _, ok := c.reserveLogicalOperation(operationID, true); ok {
		t.Fatal("a frame arriving after acknowledgement joined the spent operation")
	}

	_, first, participates, publishes, err := c.beginLogicalOperation(
		context.Background(), a, operationID, true, &pfslocal.GetAttrRequest{},
	)
	if err != nil || !participates || !publishes || first == nil {
		t.Fatalf("reserved initializer after ack = participant=%v participates=%v publishes=%v error=%v", first, participates, publishes, err)
	}
	_, second, participates, publishes, err := c.beginLogicalOperation(
		context.Background(), a, operationID, false, &pfslocal.FsyncRequest{},
	)
	if err != nil || !participates || publishes || second == nil {
		t.Fatalf("reserved continuation after ack = participant=%v participates=%v publishes=%v error=%v", second, participates, publishes, err)
	}

	a.finishFrontendParticipant(second)
	c.finishLogicalRequest(operationID)
	a.finishFrontendParticipant(first)
	c.finishLogicalRequest(operationID)
	c.publicationMu.Lock()
	_, retained := c.operations[operationID]
	c.publicationMu.Unlock()
	if retained {
		t.Fatal("acknowledged operation remained after every reserved handler retired")
	}
}
