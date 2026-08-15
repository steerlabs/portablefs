package portablefsd

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
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

type countingV3ResponseConsumption struct{ count *atomic.Int32 }

func (c *countingV3ResponseConsumption) Consume() {
	if c != nil && c.count != nil {
		c.count.Add(1)
	}
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
	if !acknowledgeBridgePublished(t, d.bridge, operationID) {
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
	gate, err := v3ItemSourceGate(testV3PublicationItem(1, 0x5a), true)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := d.bridge.sourcePublication.acquireSource(context.Background(), operationID, gate)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.markAssigned(); err != nil {
		t.Fatal(err)
	}
	if err := lease.markCommitted(); err != nil {
		t.Fatal(err)
	}
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
	d.bridge.sourcePublication.mu.Lock()
	released, sourceTerminal := lease.released, d.bridge.sourcePublication.terminal
	d.bridge.sourcePublication.mu.Unlock()
	if released || sourceTerminal == nil {
		t.Fatalf("disconnect reopened source lease: released=%t terminal=%v", released, sourceTerminal)
	}
	a.finishFrontendParticipant(participant)
}

// A successful authority COMMIT is not consumed at the Go return boundary.
// The receipt remains owned by the exact logical operation while its pfslocal
// frame is written and while the callback owes PublicationAck. Only the joint
// Ack + handler-retirement boundary may send the terminal delivery receipt.
func TestV3RetainedMutationReceiptWaitsForPhysicalReplyAndPublicationAck(t *testing.T) {
	const operationID = uint64(305)
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "receipt-test", v3Data: d, v3Coherence: d.bridge}
	_, handle := openTestV3File(t, d, false)

	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	_, participant := publicationTestOperation(t, c, a, operationID)

	reply, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{
		Handle: handle, Data: []byte("receipt"),
	})
	if errno != 0 || reply == nil {
		t.Fatalf("write=(%#v,%d)", reply, errno)
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("authority return consumed receipt %d time(s), want 0", got)
	}

	readResult := make(chan error, 1)
	go func() {
		envelope, err := pfslocal.ReadFrame(peer)
		if err == nil && (!envelope.PublicationAckRequired || envelope.RequestID != 1) {
			err = errors.New("physical reply omitted its publication identity")
		}
		readResult <- err
	}()
	if !c.replyWithPublication(1, operationID, reply, true) {
		t.Fatal("write reply was not physically exposed")
	}
	if err := <-readResult; err != nil {
		t.Fatal(err)
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("physical reply consumed receipt %d time(s) before PublicationAck", got)
	}

	if !acknowledgeBridgePublished(t, d.bridge, operationID) ||
		!c.acknowledgePublication(operationID) {
		t.Fatal("PublicationAck was refused")
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("PublicationAck consumed receipt %d time(s) before handler retirement", got)
	}
	a.finishFrontendParticipant(participant)
	c.finishLogicalRequest(operationID)
	if got := consumed.Load(); got != 3 {
		t.Fatalf("completed logical publication consumed receipt %d time(s), want BEGIN+DATA+COMMIT=3", got)
	}
	if err := d.bridge.finishFrontendPublication(operationID); err != nil {
		t.Fatal(err)
	}
	if got := consumed.Load(); got != 3 {
		t.Fatalf("duplicate finish consumed receipt %d time(s), want exactly 3", got)
	}
}

// If the authority's bounded terminal drain expires before PublicationAck,
// its force callback must revoke the strict data plane synchronously. Only
// after connection teardown retires the revoked logical operation may its
// retained response be consumed.
func TestV3RetainedMutationReceiptTimeoutRevokesBeforeConsumption(t *testing.T) {
	const operationID = uint64(306)
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "receipt-timeout-test", v3Data: d, v3Coherence: d.bridge}
	_, handle := openTestV3File(t, d, false)

	var consumed atomic.Int32
	var forceCallback func(error)
	client.newConsumption = func(force func(error)) authorityrpc.ResponseConsumption {
		forceCallback = force
		return &countingV3ResponseConsumption{count: &consumed}
	}
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	_, participant := publicationTestOperation(t, c, a, operationID)
	var revoked atomic.Bool
	revokeStarted := make(chan struct{})
	dispatchCtx := context.WithValue(
		context.Background(),
		v3ResponseConsumptionRevokerContextKey{},
		v3ResponseConsumptionRevoker(func(cause error) {
			close(revokeStarted)
			c.revokeV3ResponseConsumption(a, cause)
			revoked.Store(true)
		}),
	)
	if reply, errno := d.dispatchFrontend(dispatchCtx, operationID, &pfslocal.WriteRequest{
		Handle: handle, Data: []byte("timeout"),
	}); errno != 0 || reply == nil {
		t.Fatalf("write=(%#v,%d)", reply, errno)
	}
	if forceCallback == nil {
		t.Fatal("retained mutation omitted its bounded-drain force callback")
	}
	c.writeMu.Lock()
	forced := make(chan struct{})
	go func() {
		forceCallback(errors.New("terminal receipt deadline"))
		close(forced)
	}()
	<-revokeStarted
	select {
	case <-forced:
		c.writeMu.Unlock()
		t.Fatal("forced receipt drain crossed an active pfslocal frame writer")
	default:
	}
	c.writeMu.Unlock()
	select {
	case <-forced:
	case <-time.After(time.Second):
		t.Fatal("forced receipt drain did not finish after the pfslocal writer retired")
	}
	if !revoked.Load() {
		t.Fatal("forced receipt drain returned before revoking the pfslocal serving boundary")
	}
	if terminal := d.terminalError(); terminal == nil ||
		!strings.Contains(terminal.Error(), "frontend delivery bound") {
		t.Fatalf("forced receipt drain did not revoke the data plane: %v", terminal)
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("forced revocation consumed receipt %d time(s) before local teardown", got)
	}

	a.finishFrontendParticipant(participant)
	c.close()
	if got := consumed.Load(); got != 3 {
		t.Fatalf("revoked logical publication consumed receipt %d time(s), want BEGIN+DATA+COMMIT=3", got)
	}
}

func TestV3PlainResponseReceiptWaitsForPhysicalFrontendFrame(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "plain-receipt-test", v3Data: d, v3Coherence: d.bridge}
	var consumed atomic.Int32
	created := make(chan struct{}, 1)
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		created <- struct{}{}
		return &countingV3ResponseConsumption{count: &consumed}
	}
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	done := make(chan struct{})
	go func() {
		c.handleV3Attached(context.Background(), a, 401, 0, false, &pfslocal.StatfsRequest{})
		close(done)
	}()
	<-created
	if got := consumed.Load(); got != 0 {
		t.Fatalf("plain authority response consumed before frontend frame: %d", got)
	}
	if _, err := pfslocal.ReadFrame(peer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("plain frontend handler did not retire after frame write")
	}
	if got := consumed.Load(); got != 1 {
		t.Fatalf("plain response consumption after physical frame = %d, want 1", got)
	}
}

func TestV3PublishingReadReceiptWaitsForFrameAckAndHandlerRetirement(t *testing.T) {
	const operationID = uint64(404)
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "publishing-read-receipt-test", v3Data: d, v3Coherence: d.bridge}
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{
		Dir: d.resolveReply().Root, Name: []byte("file"),
	})
	if errno != 0 {
		t.Fatalf("lookup errno=%d", errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	initialize, ok := c.reserveLogicalOperation(operationID, true)
	if !ok || !initialize {
		t.Fatal("publishing read operation was not reserved")
	}
	d.bridge.reserveFrontendPublication(operationID)
	done := make(chan struct{})
	go func() {
		c.handleV3Attached(context.Background(), a, 404, operationID, initialize, &pfslocal.GetAttrRequest{Item: file})
		close(done)
	}()
	envelope, err := pfslocal.ReadFrame(peer)
	if err != nil {
		t.Fatal(err)
	}
	if !envelope.PublicationAckRequired || envelope.OperationID != operationID {
		t.Fatalf("publishing read frame = %+v, want exact PublicationAck identity", envelope)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publishing read handler did not retire after frame write")
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("publishing read consumed receipt before PublicationAck: %d", got)
	}
	if !c.acknowledgePublication(operationID) {
		t.Fatal("publishing read PublicationAck was refused")
	}
	if got := consumed.Load(); got != 1 {
		t.Fatalf("publishing read receipt consumption after frame, Ack, and retirement = %d, want 1", got)
	}
}

// FSKit can cancel a callback after the daemon dispatched its authority read
// but before that read returns. Its NOT_PUBLISHED acknowledgement is a complete
// verdict for that callback: a later healthy read must be discarded, its
// receipt must still retire at the callback boundary, and the mount must remain
// usable. Treating the late result like an applied mutation turns every benign
// request timeout into a volume-wide outage.
func TestV3LateHealthyReadAfterNotPublishedAckIsDiscarded(t *testing.T) {
	const operationID = uint64(406)
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "late-read-receipt-test", v3Data: d, v3Coherence: d.bridge}
	file, _ := openTestV3File(t, d, false)

	started := make(chan struct{})
	release := make(chan struct{})
	client.read = func(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetGetAttr() == nil {
			return nil, errors.New("unexpected authority request in late-read test")
		}
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &authoritypb.Response{Body: &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{
			Attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2, Mode: 0o644, Nlink: 1},
		}}}, nil
	}
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	initialize, ok := c.reserveLogicalOperation(operationID, true)
	if !ok || !initialize {
		t.Fatal("late read operation was not reserved")
	}
	d.bridge.reserveFrontendPublication(operationID)
	done := make(chan struct{})
	go func() {
		c.handleV3Attached(context.Background(), a, 406, operationID, initialize, &pfslocal.GetAttrRequest{Item: file})
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("authority read was not dispatched")
	}
	known, err := d.bridge.acknowledgePublication(
		operationID, pfslocal.PublicationSemanticCommitNotPublished,
	)
	if err != nil || !known {
		t.Fatalf("early NOT_PUBLISHED bridge ack = (%t,%v)", known, err)
	}
	if !c.acknowledgePublication(operationID) {
		t.Fatal("early NOT_PUBLISHED frontend ack was refused")
	}
	close(release)

	_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if envelope, err := pfslocal.ReadFrame(peer); err == nil {
		t.Fatalf("late read exposed a frame after NOT_PUBLISHED: %+v", envelope)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("late read handler did not retire")
	}
	if terminal := d.terminalError(); terminal != nil {
		t.Fatalf("late healthy read fenced the session: %v", terminal)
	}
	if got := consumed.Load(); got != 1 {
		t.Fatalf("late read receipt consumed %d time(s), want exactly once after handler retirement", got)
	}
	c.publicationMu.Lock()
	_, retained := c.operations[operationID]
	c.publicationMu.Unlock()
	if retained {
		t.Fatal("late read operation remained after ack and handler retirement")
	}
}

func TestV3LateLookupAfterNotPublishedAckWithdrawsProvisionalItem(t *testing.T) {
	const operationID = uint64(407)
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "late-lookup-resource-test", v3Data: d, v3Coherence: d.bridge}
	started := make(chan struct{})
	release := make(chan struct{})
	client.mutation = func(ctx context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetReclaim() != nil {
			return exactTestMutationReply(identity), nil
		}
		if request.GetLookup() == nil {
			return nil, errors.New("unexpected authority mutation in late-lookup test")
		}
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		response := exactTestMutationReply(identity)
		response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{
			Item: authorityTestItem(2, authoritypb.Attr_REGULAR, 0x30, 0x40),
		}}
		return response, nil
	}
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	initialize, ok := c.reserveLogicalOperation(operationID, true)
	if !ok || !initialize {
		t.Fatal("late lookup operation was not reserved")
	}
	d.bridge.reserveFrontendPublication(operationID)
	done := make(chan struct{})
	go func() {
		c.handleV3Attached(context.Background(), a, 407, operationID, initialize, &pfslocal.LookupRequest{
			Dir: d.resolveReply().Root, Name: []byte("late"),
		})
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("authority lookup was not dispatched")
	}
	known, err := d.bridge.acknowledgePublication(
		operationID, pfslocal.PublicationSemanticCommitNotPublished,
	)
	if err != nil || !known {
		t.Fatalf("early NOT_PUBLISHED bridge ack = (%t,%v)", known, err)
	}
	if !c.acknowledgePublication(operationID) {
		t.Fatal("early NOT_PUBLISHED frontend ack was refused")
	}
	close(release)

	_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if envelope, err := pfslocal.ReadFrame(peer); err == nil {
		t.Fatalf("late lookup exposed a frame after NOT_PUBLISHED: %+v", envelope)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("late lookup handler did not retire")
	}
	if terminal := d.terminalError(); terminal != nil {
		t.Fatalf("late healthy lookup fenced the session: %v", terminal)
	}
	if got := consumed.Load(); got != 1 {
		t.Fatalf("late lookup receipt consumed %d time(s), want exactly once", got)
	}
	d.mu.Lock()
	itemCount := len(d.itemsByID)
	_, retainedItem := d.itemsByID[2]
	d.mu.Unlock()
	if retainedItem || itemCount != 1 {
		t.Fatalf("discarded lookup retained provisional item: retained=%t item_count=%d", retainedItem, itemCount)
	}
}

func TestV3TerminalPlainResponsesRevokeBeforeConsumptionAndWriteNoFrame(t *testing.T) {
	for _, test := range []struct {
		name string
		body any
	}{
		{name: "read", body: &pfslocal.StatfsRequest{}},
		{name: "replay mutation", body: &pfslocal.SyncVolumeRequest{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			a := &attach{ref: "terminal-plain-receipt-test", v3Data: d, v3Coherence: d.bridge}
			if test.name == "read" {
				client.read = func(context.Context, *authoritypb.Request) (*authoritypb.Response, error) {
					return &authoritypb.Response{Errno: int32(errnos.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_STORAGE}, nil
				}
			} else {
				client.mutation = func(context.Context, authorityrpc.MutationIdentity, *authoritypb.Request) (*authoritypb.Response, error) {
					return &authoritypb.Response{Errno: int32(errnos.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_STORAGE}, nil
				}
			}
			var consumed atomic.Int32
			client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
				return &fakeV3ResponseConsumption{consume: func() {
					if d.terminalError() == nil {
						t.Error("terminal plain response consumed before data-plane revocation")
					}
					consumed.Add(1)
				}}
			}
			server, peer := net.Pipe()
			defer peer.Close()
			c := &frontendConn{conn: server, attach: a}
			done := make(chan struct{})
			go func() {
				c.handleV3Attached(context.Background(), a, 405, 0, false, test.body)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("terminal plain response did not finish")
			}
			if got := consumed.Load(); got != 1 {
				t.Fatalf("terminal plain response consumed %d time(s), want once after revoke", got)
			}
			if d.terminalError() == nil {
				t.Fatal("terminal plain response did not revoke data plane")
			}
			_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := pfslocal.ReadFrame(peer); err == nil {
				t.Fatal("terminal plain response exposed a pfslocal frame")
			}
		})
	}
}

func TestV3OpenReceiptWaitsForResourceDisposition(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "open-receipt-test", v3Data: d, v3Coherence: d.bridge}
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{
		Dir: d.resolveReply().Root, Name: []byte("file"),
	})
	if errno != 0 {
		t.Fatalf("lookup errno=%d", errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	done := make(chan struct{})
	go func() {
		c.handleV3Attached(context.Background(), a, 402, 0, false, &pfslocal.OpenRequest{
			Item: file, Mode: pfslocal.OpenModeReadWrite,
		})
		close(done)
	}()
	if _, err := pfslocal.ReadFrame(peer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Open handler did not retire after frame write")
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("Open receipt consumed at physical frame before disposition: %d", got)
	}
	if !c.settleProvisionalResource(&pfslocal.ResourceReplyDisposition{
		TargetRequestID: 402, AcceptHandles: true,
	}) {
		t.Fatal("valid Open resource disposition was refused")
	}
	if got := consumed.Load(); got != 1 {
		t.Fatalf("Open receipt consumption after resource disposition = %d, want 1", got)
	}
}

func TestV3InvalidResourceDispositionRevokesBeforeReceiptConsumption(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "invalid-disposition-test", v3Data: d, v3Coherence: d.bridge}
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{
		Dir: d.resolveReply().Root, Name: []byte("file"),
	})
	if errno != 0 {
		t.Fatalf("lookup errno=%d", errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &fakeV3ResponseConsumption{consume: func() {
			if d.terminalError() == nil {
				t.Error("invalid disposition consumed receipt before fencing data plane")
			}
			consumed.Add(1)
		}}
	}
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	done := make(chan struct{})
	go func() {
		c.handleV3Attached(context.Background(), a, 403, 0, false, &pfslocal.OpenRequest{
			Item: file, Mode: pfslocal.OpenModeReadWrite,
		})
		close(done)
	}()
	envelope, err := pfslocal.ReadFrame(peer)
	if err != nil {
		t.Fatal(err)
	}
	openReply, ok := envelope.Body.(*pfslocal.OpenReply)
	if !ok || openReply.Handle == 0 {
		t.Fatalf("Open reply = %#v", envelope.Body)
	}
	handleID := openReply.Handle
	<-done
	if c.settleProvisionalResource(&pfslocal.ResourceReplyDisposition{
		TargetRequestID: 403, AcceptHandles: true, AcceptedItemCount: 1,
	}) {
		t.Fatal("invalid Open disposition was accepted")
	}
	if got := consumed.Load(); got != 1 {
		t.Fatalf("invalid disposition consumed receipt %d time(s), want 1 after revoke", got)
	}
	if d.terminalError() == nil {
		t.Fatal("invalid disposition did not fence data plane")
	}
	c.resourceMu.Lock()
	_, provisional := c.provisional[403]
	c.resourceMu.Unlock()
	d.mu.Lock()
	_, handleLive := d.handles[handleID]
	d.mu.Unlock()
	if provisional || handleLive {
		t.Fatalf("invalid disposition leaked resources: provisional=%t handle_live=%t", provisional, handleLive)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := pfslocal.ReadFrame(peer); err == nil {
		t.Fatal("pfslocal connection remained writable after invalid disposition")
	}
}

// A malformed parsed COMMIT can itself carry the terminal delivery token. It
// must take the same synchronized local-revocation path as the bounded force
// callback before the callMutation defer consumes (and therefore receipts)
// that response.
func TestV3MalformedRetainedMutationRevokesBeforeReceiptConsumption(t *testing.T) {
	const operationID = uint64(307)
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	a := &attach{ref: "receipt-malformed-test", v3Data: d, v3Coherence: d.bridge}
	_, handle := openTestV3File(t, d, false)

	var consumed atomic.Int32
	var revoked atomic.Bool
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		response := exactTestWriteCommit(identity, request)
		response.Uncertain = true
		return response, nil
	}
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{conn: server, attach: a}
	_, participant := publicationTestOperation(t, c, a, operationID)
	dispatchCtx := context.WithValue(
		context.Background(),
		v3ResponseConsumptionRevokerContextKey{},
		v3ResponseConsumptionRevoker(func(cause error) {
			if got := consumed.Load(); got != 0 {
				t.Errorf("receipt was consumed %d time(s) before local revocation", got)
			}
			c.revokeV3ResponseConsumption(a, cause)
			revoked.Store(true)
		}),
	)
	if reply, errno := d.dispatchFrontend(dispatchCtx, operationID, &pfslocal.WriteRequest{
		Handle: handle, Data: []byte("malformed"),
	}); errno != darwinEIO || reply != nil {
		t.Fatalf("malformed retained result=(%#v,%d), want terminal EIO", reply, errno)
	}
	if !revoked.Load() {
		t.Fatal("malformed retained result did not revoke the pfslocal boundary")
	}
	if got := consumed.Load(); got != 1 {
		t.Fatalf("malformed retained result consumed receipt %d time(s), want 1 after revocation", got)
	}
	a.finishFrontendParticipant(participant)
	c.close()
}

// Visible mutation replies carry both a PublicationAck obligation and a
// provisional item capability. Abandoning the item is itself terminal because
// its source gate remains fail-closed, but on disconnect the missing
// publication acknowledgement is the earlier and more exact failure.
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
					!acknowledgeBridgePublished(t, d.bridge, operationID) {
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
