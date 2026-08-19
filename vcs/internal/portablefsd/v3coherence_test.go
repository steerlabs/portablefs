package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
	"google.golang.org/protobuf/proto"
)

type v3VisibilityResult struct {
	event *authoritypb.VisibilityEvent
	err   error
}

type fakeV3VisibilityClient struct {
	epoch   []byte
	session []byte
	initial *authoritypb.VisibilityCursor
	budget  time.Duration
	next    chan v3VisibilityResult
	done    chan struct{}

	mu         sync.Mutex
	acked      []*authoritypb.VisibilityCursor
	contention []bool
	closed     bool
	err        error
}

func newFakeV3VisibilityClient() *fakeV3VisibilityClient {
	return &fakeV3VisibilityClient{
		epoch: bytes.Repeat([]byte{0x11}, 16), session: bytes.Repeat([]byte{0x22}, 16),
		initial: &authoritypb.VisibilityCursor{Sequence: 10, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE},
		budget:  time.Minute, next: make(chan v3VisibilityResult, 8), done: make(chan struct{}),
	}
}

func (f *fakeV3VisibilityClient) Epoch() []byte     { return append([]byte(nil), f.epoch...) }
func (f *fakeV3VisibilityClient) SessionID() []byte { return append([]byte(nil), f.session...) }
func (f *fakeV3VisibilityClient) InitialVisibilityCursor() *authoritypb.VisibilityCursor {
	return cloneAuthorityCursor(f.initial)
}
func (f *fakeV3VisibilityClient) VisibilityRepairBudget() time.Duration { return f.budget }
func (f *fakeV3VisibilityClient) NextVisibility(ctx context.Context, _ *authoritypb.VisibilityCursor) (*authoritypb.VisibilityEvent, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-f.next:
		return result.event, result.err
	}
}
func (f *fakeV3VisibilityClient) AckVisibility(ctx context.Context, cursor *authoritypb.VisibilityCursor) error {
	return f.AckVisibilityWithContention(ctx, cursor, false)
}
func (f *fakeV3VisibilityClient) AckVisibilityWithContention(_ context.Context, cursor *authoritypb.VisibilityCursor, contended bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, cloneAuthorityCursor(cursor))
	f.contention = append(f.contention, contended)
	return nil
}
func (f *fakeV3VisibilityClient) SessionDone() <-chan struct{} { return f.done }
func (f *fakeV3VisibilityClient) SessionError() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}
func (f *fakeV3VisibilityClient) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.done)
	}
	return nil
}

func (f *fakeV3VisibilityClient) ackedCursors() []*authoritypb.VisibilityCursor {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*authoritypb.VisibilityCursor, len(f.acked))
	for i := range f.acked {
		out[i] = cloneAuthorityCursor(f.acked[i])
	}
	return out
}

func testV3Event(client *fakeV3VisibilityClient, sequence uint64, phase authoritypb.VisibilityPhase) *authoritypb.VisibilityEvent {
	return &authoritypb.VisibilityEvent{
		Cursor:             &authoritypb.VisibilityCursor{Sequence: sequence, Phase: phase},
		InitiatorSessionId: bytes.Repeat([]byte{0x44}, 16), MutationSlot: 3, MutationSequence: 9,
		Targets: []*authoritypb.VisibilityTarget{
			visibilitywire.Namespace(bytes.Repeat([]byte{0x55}, 16), []byte("entry"), 42, 0x700000001),
		},
	}
}

func TestV3CoherenceBridgeContractIsExactAndCloned(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, nil)
	if err != nil {
		t.Fatal(err)
	}
	contract := bridge.resolveContract()
	if contract.AuthorityProtocolMajor != authorityrpc.ProtocolMajor ||
		contract.CachePolicy != v3CachePolicyFSKit || contract.RepairBudgetMillis != 60_000 ||
		!bytes.Equal(contract.AuthorityEpoch, client.epoch) || !bytes.Equal(contract.SessionID, client.session) ||
		contract.InitialCursor == nil || *contract.InitialCursor != (pfslocal.VisibilityCursor{Sequence: 10, Phase: pfslocal.VisibilityPhaseComplete}) {
		t.Fatalf("unexpected v3 contract: %#v", contract)
	}
	contract.AuthorityEpoch[0] ^= 0xff
	contract.SessionID[0] ^= 0xff
	again := bridge.resolveContract()
	if !bytes.Equal(again.AuthorityEpoch, client.epoch) || !bytes.Equal(again.SessionID, client.session) {
		t.Fatal("resolve contract exposed mutable bridge identity")
	}
}

func TestV3CoherenceBridgeRefusesIncompleteContracts(t *testing.T) {
	for name, mutate := range map[string]func(*fakeV3VisibilityClient){
		"epoch":   func(client *fakeV3VisibilityClient) { client.epoch = client.epoch[:15] },
		"session": func(client *fakeV3VisibilityClient) { client.session = client.session[:15] },
		"budget":  func(client *fakeV3VisibilityClient) { client.budget = time.Microsecond },
		"cursor": func(client *fakeV3VisibilityClient) {
			client.initial.Phase = authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := newFakeV3VisibilityClient()
			mutate(client)
			if _, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, nil); err == nil {
				t.Fatal("malformed authority contract was accepted")
			}
		})
	}
	client := newFakeV3VisibilityClient()
	if _, err := newV3CoherenceBridge(client, "automatic-fallback", nil); err == nil {
		t.Fatal("an undeclared cache policy was accepted")
	}
	genesis := newFakeV3VisibilityClient()
	genesis.initial = nil
	bridge, err := newV3CoherenceBridge(genesis, v3CachePolicyFSKit, nil)
	if err != nil {
		t.Fatalf("fresh-participant genesis was refused: %v", err)
	}
	if bridge.resolveContract().InitialCursor != nil {
		t.Fatal("fresh-participant genesis was serialized as an invalid zero cursor")
	}
}

func TestV3CoherenceBridgeFrontendDisconnectFailsTheStrictSession(t *testing.T) {
	client := newFakeV3VisibilityClient()
	failures := make(chan error, 1)
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, func(err error) { failures <- err })
	if err != nil {
		t.Fatal(err)
	}
	client.next <- v3VisibilityResult{event: testV3Event(client, 11, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE)}

	ctx, cancel := context.WithCancel(context.Background())
	delivered := make(chan *pfslocal.V3VisibilityEvent, 1)
	done := make(chan error, 1)
	go func() {
		done <- bridge.run(ctx, func(event *pfslocal.Event) error {
			delivered <- event.Kind.(*pfslocal.V3VisibilityEvent)
			return nil
		})
	}()
	<-delivered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("subscriber exit = %v, want cancellation", err)
	}
	select {
	case <-failures:
	case <-time.After(time.Second):
		t.Fatal("frontend disconnect did not publish a terminal failure")
	}
	if err := bridge.bind(); !errors.Is(err, errV3VisibilityTerminal) {
		t.Fatalf("strict bridge rebound after disconnect: %v", err)
	}
	if got := client.ackedCursors(); len(got) != 0 {
		t.Fatalf("disconnect falsely acknowledged %#v", got)
	}
}

func TestV3CoherenceBridgeKeepsAuthorityAliveForPlannedKernelDetach(t *testing.T) {
	client := newFakeV3VisibilityClient()
	failures := make(chan error, 1)
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, func(err error) { failures <- err })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.run(ctx, func(*pfslocal.Event) error { return nil }) }()
	deadline := time.Now().Add(time.Second)
	for {
		bridge.mu.Lock()
		subscribed := bridge.subscribed
		bridge.mu.Unlock()
		if subscribed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("visibility stream did not subscribe")
		}
		time.Sleep(time.Millisecond)
	}
	if err := bridge.beginDetach(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("planned detach stream exit=%v", err)
	}
	select {
	case err := <-failures:
		t.Fatalf("planned detach fenced the authority session: %v", err)
	default:
	}
	client.mu.Lock()
	closed := client.closed
	client.mu.Unlock()
	if closed {
		t.Fatal("planned detach closed the authority before mount-absence proof delivery")
	}
	if err := bridge.bind(); !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("planned detach accepted a replacement frontend: %v", err)
	}
	_ = client.Close()
}

func TestV3CoherenceBridgeFencesIfPlannedDetachAbortsAfterFrontendExit(t *testing.T) {
	client := newFakeV3VisibilityClient()
	failures := make(chan error, 1)
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, func(err error) { failures <- err })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.run(ctx, func(*pfslocal.Event) error { return nil }) }()
	deadline := time.Now().Add(time.Second)
	for {
		bridge.mu.Lock()
		subscribed := bridge.subscribed
		bridge.mu.Unlock()
		if subscribed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("visibility stream did not subscribe")
		}
		time.Sleep(time.Millisecond)
	}
	if err := bridge.beginDetach(); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	bridge.abortDetach(syscall.EIO)
	select {
	case <-failures:
	case <-time.After(time.Second):
		t.Fatal("aborted detach resumed after losing its frontend")
	}
	if err := bridge.bind(); !errors.Is(err, errV3VisibilityTerminal) {
		t.Fatalf("aborted detach did not fence the bridge: %v", err)
	}
}

func TestV3CoherenceBridgeRejectsAnyFilesystemSourceEvent(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	failures := make(chan error, 1)
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, func(err error) { failures <- err })
	if err != nil {
		t.Fatal(err)
	}
	event := testV3Event(client, 11, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE)
	event.InitiatorSessionId = append([]byte(nil), client.session...)
	client.next <- v3VisibilityResult{event: event}
	if err := bridge.run(context.Background(), func(*pfslocal.Event) error {
		t.Fatal("source filesystem event reached the frontend")
		return nil
	}); err == nil {
		t.Fatal("source filesystem event did not terminate the bridge")
	}
	select {
	case <-failures:
	case <-time.After(time.Second):
		t.Fatal("source filesystem event did not publish a terminal failure")
	}
}

func TestV3CoherenceBridgeBindsContentionFeedbackToExactPeerComplete(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyMacOS26, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.next <- v3VisibilityResult{event: testV3Event(client, 11, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE)}
	client.next <- v3VisibilityResult{event: testV3Event(client, 11, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE)}

	ctx, cancel := context.WithCancel(context.Background())
	delivered := make(chan *pfslocal.V3VisibilityEvent, 2)
	done := make(chan error, 1)
	go func() {
		done <- bridge.run(ctx, func(event *pfslocal.Event) error {
			delivered <- event.Kind.(*pfslocal.V3VisibilityEvent)
			return nil
		})
	}()
	prepare := <-delivered
	if err := bridge.acknowledge(context.Background(), &pfslocal.VisibilityAckRequest{
		AuthorityEpoch: client.epoch, Cursor: prepare.Cursor, OrderedAdmissionContended: true,
	}); err != nil {
		t.Fatal(err)
	}
	complete := <-delivered
	if err := bridge.acknowledge(context.Background(), &pfslocal.VisibilityAckRequest{
		AuthorityEpoch: client.epoch, Cursor: complete.Cursor, OrderedAdmissionContended: true,
	}); err != nil {
		t.Fatal(err)
	}
	// A response-lost retry repeats the safety Ack but never repeats its hint.
	if err := bridge.acknowledge(context.Background(), &pfslocal.VisibilityAckRequest{
		AuthorityEpoch: client.epoch, Cursor: complete.Cursor, OrderedAdmissionContended: true,
	}); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	got := append([]bool(nil), client.contention...)
	client.mu.Unlock()
	want := []bool{false, true, false}
	if !slices.Equal(got, want) {
		t.Fatalf("forwarded contention = %v, want %v", got, want)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("subscriber exit = %v, want cancellation", err)
	}
}

func TestV3CoherenceBridgeReportsDaemonLocalPeerFirstContentionAndHoldsCutThroughCompleteAck(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyMacOS26, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.next <- v3VisibilityResult{event: testV3Event(client, 11, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE)}
	client.next <- v3VisibilityResult{event: testV3Event(client, 11, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	delivered := make(chan *pfslocal.V3VisibilityEvent, 2)
	done := make(chan error, 1)
	go func() {
		done <- bridge.run(ctx, func(event *pfslocal.Event) error {
			delivered <- event.Kind.(*pfslocal.V3VisibilityEvent)
			return nil
		})
	}()
	prepare := <-delivered
	if sequence, held := peerV3PublicationState(bridge.sourcePublication); sequence != 11 || held != 1 {
		t.Fatalf("delivered PREPARE did not own its local cut: sequence=%d held=%d", sequence, held)
	}
	gate, err := v3NamespaceSourceGate(
		testV3PublicationItem(1, 0x55), []byte("entry"), false,
	)
	if err != nil {
		t.Fatal(err)
	}
	bridge.reserveFrontendPublication(401)
	if lease, err := bridge.sourcePublication.acquireSource(context.Background(), 401, gate); lease != nil || !errors.Is(err, errV3SourcePublicationInterrupted) {
		t.Fatalf("peer-first callback = (%#v, %v), want definite local refusal", lease, err)
	}
	if err := bridge.acknowledge(context.Background(), &pfslocal.VisibilityAckRequest{
		AuthorityEpoch: client.epoch, Cursor: prepare.Cursor,
	}); err != nil {
		t.Fatal(err)
	}
	complete := <-delivered
	if sequence, held := peerV3PublicationState(bridge.sourcePublication); sequence != 11 || held != 1 {
		t.Fatalf("COMPLETE publication lost PREPARE cut before Ack: sequence=%d held=%d", sequence, held)
	}
	if err := bridge.acknowledge(context.Background(), &pfslocal.VisibilityAckRequest{
		AuthorityEpoch: client.epoch, Cursor: complete.Cursor,
	}); err != nil {
		t.Fatal(err)
	}
	if sequence, held := peerV3PublicationState(bridge.sourcePublication); sequence != 0 || held != 0 {
		t.Fatalf("successful COMPLETE Ack retained local cut: sequence=%d held=%d", sequence, held)
	}
	client.mu.Lock()
	contention := append([]bool(nil), client.contention...)
	client.mu.Unlock()
	if want := []bool{false, true}; !slices.Equal(contention, want) {
		t.Fatalf("daemon-local contention feedback = %v, want %v", contention, want)
	}
	if !acknowledgeBridgePublished(t, bridge, 401) {
		t.Fatal("refused callback PublicationAck was not accepted")
	}
	bridge.releaseFrontendPublication(401)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("subscriber exit = %v, want cancellation", err)
	}
}

func TestV3CoherenceBridgeEarlyPublicationAckPreventsSourceLeaseReopen(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, nil)
	if err != nil {
		t.Fatal(err)
	}

	const operationID = uint64(91)
	bridge.reserveFrontendPublication(operationID)
	if !acknowledgeBridgePublished(t, bridge, operationID) {
		t.Fatal("publication acknowledgement did not find the serial-reader reservation")
	}
	gate, err := v3ItemSourceGate(pfslocal.Item{
		ItemID: 1, StableIdentity: [16]byte{1},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.sourcePublication.acquireSource(context.Background(), operationID, gate); err == nil {
		t.Fatal("early PublicationAck allowed a source lease to reopen")
	}
}

func TestV3CoherenceBridgeBoundsNonmutationPublicationReservations(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, nil)
	if err != nil {
		t.Fatal(err)
	}

	// ACK before handler retirement: the channel is closed, then the absence of
	// any authority ticket proves this was read-only and retirement removes it.
	bridge.reserveFrontendPublication(101)
	if !acknowledgeBridgePublished(t, bridge, 101) {
		t.Fatal("early read-only acknowledgement was refused")
	}
	bridge.releaseFrontendPublication(101)

	// Handler retirement before ACK: minor 15 retains the bounded operation fact
	// until the explicit semantic verdict arrives, even when no source lease was
	// acquired. Otherwise a healthy read-only callback's mandatory Ack would be
	// indistinguishable from an unknown operation.
	bridge.reserveFrontendPublication(102)
	bridge.releaseFrontendPublication(102)
	if !acknowledgeBridgePublished(t, bridge, 102) {
		t.Fatal("finish-before-ack lost its read-only semantic-verdict state")
	}

	bridge.sourcePublication.mu.Lock()
	operations := len(bridge.sourcePublication.operations)
	bridge.sourcePublication.mu.Unlock()
	if operations != 0 {
		t.Fatalf("read-only operations leaked %d source-publication operation(s)", operations)
	}
}

func TestV3CoherenceBridgeReactivatesSequentialContinuationBeforeEarlyAck(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, nil)
	if err != nil {
		t.Fatal(err)
	}

	const operationID = uint64(103)
	// Request one is a completed read. The frontend operation remains available
	// for a sequential continuation and its bounded semantic-verdict state stays
	// dormant while no handler is active.
	bridge.reserveFrontendPublication(operationID)
	bridge.releaseFrontendPublication(operationID)

	// The serial reader sees request two before launching its handler and
	// idempotently reactivates the same operation ID. Its ACK may then overtake
	// handler scheduling; a later source lease must be refused before assignment.
	bridge.reserveFrontendPublication(operationID)
	if !acknowledgeBridgePublished(t, bridge, operationID) {
		t.Fatal("continuation acknowledgement did not find the reactivated reservation")
	}
	gate, err := v3ItemSourceGate(pfslocal.Item{
		ItemID: 1, StableIdentity: [16]byte{1},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.sourcePublication.acquireSource(context.Background(), operationID, gate); err == nil {
		t.Fatal("continuation mutation reopened after its callback acknowledgement")
	}

	bridge.releaseFrontendPublication(operationID)
	bridge.sourcePublication.mu.Lock()
	operations := len(bridge.sourcePublication.operations)
	bridge.sourcePublication.mu.Unlock()
	if operations != 0 {
		t.Fatalf("sequential continuation leaked %d operation(s)", operations)
	}
}

func TestV3CoherenceBridgeMissedBudgetClosesAuthoritySession(t *testing.T) {
	client := newFakeV3VisibilityClient()
	client.budget = 20 * time.Millisecond
	failures := make(chan error, 1)
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, func(err error) { failures <- err })
	if err != nil {
		t.Fatal(err)
	}
	client.next <- v3VisibilityResult{event: testV3Event(client, 11, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE)}
	delivered := make(chan struct{})
	go func() {
		_ = bridge.run(context.Background(), func(*pfslocal.Event) error {
			close(delivered)
			return nil
		})
	}()
	<-delivered
	select {
	case err := <-failures:
		if err == nil {
			t.Fatal("deadline failure was nil")
		}
	case <-time.After(time.Second):
		t.Fatal("missed visibility deadline did not fail closed")
	}
	client.mu.Lock()
	closed := client.closed
	client.mu.Unlock()
	if !closed {
		t.Fatal("missed visibility deadline left the authority session open")
	}
}

func TestV3VisibilityTranslationValidatesEveryScope(t *testing.T) {
	epoch := bytes.Repeat([]byte{0xa1}, 16)
	base := &authoritypb.VisibilityEvent{
		Cursor:             &authoritypb.VisibilityCursor{Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE},
		InitiatorSessionId: bytes.Repeat([]byte{0xa2}, 16), MutationSequence: 1,
	}
	for _, target := range []*authoritypb.VisibilityTarget{
		visibilitywire.Namespace(bytes.Repeat([]byte{1}, 16), []byte("name"), 42, 0x700000001),
		visibilitywire.Data(bytes.Repeat([]byte{2}, 16), 7, 0x700000001, 42),
		visibilitywire.Attributes(bytes.Repeat([]byte{3}, 16), 7, 0x700000001),
	} {
		event := proto.Clone(base).(*authoritypb.VisibilityEvent)
		event.Targets = []*authoritypb.VisibilityTarget{target}
		if _, err := translateV3VisibilityEvent(epoch, event); err != nil {
			t.Fatalf("valid target %v: %v", target.GetScope(), err)
		}
	}
	postComplete := proto.Clone(base).(*authoritypb.VisibilityEvent)
	postComplete.Cursor.Phase = authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE
	postTarget := visibilitywire.Namespace(bytes.Repeat([]byte{1}, 16), []byte("alias"), 42, 0x700000001)
	postTarget.PostIdentity = bytes.Repeat([]byte{4}, 16)
	postComplete.Targets = []*authoritypb.VisibilityTarget{postTarget}
	translatedPost, err := translateV3VisibilityEvent(epoch, postComplete)
	if err != nil || len(translatedPost.Targets) != 1 ||
		!bytes.Equal(translatedPost.Targets[0].PostIdentity, postTarget.PostIdentity) {
		t.Fatalf("valid COMPLETE post-binding = %#v, %v", translatedPost, err)
	}

	invalid := []*authoritypb.VisibilityEvent{}
	badCursor := proto.Clone(base).(*authoritypb.VisibilityEvent)
	badCursor.Cursor = &authoritypb.VisibilityCursor{Sequence: 1}
	invalid = append(invalid, badCursor)
	badInitiator := proto.Clone(base).(*authoritypb.VisibilityEvent)
	badInitiator.InitiatorSessionId = []byte{1}
	badInitiator.Targets = []*authoritypb.VisibilityTarget{visibilitywire.Data(bytes.Repeat([]byte{2}, 16), 7, 0x700000001, 0)}
	invalid = append(invalid, badInitiator)
	badName := proto.Clone(base).(*authoritypb.VisibilityEvent)
	badName.Targets = []*authoritypb.VisibilityTarget{visibilitywire.Namespace(bytes.Repeat([]byte{1}, 16), []byte("a/b"), 42, 0x700000001)}
	invalid = append(invalid, badName)
	badData := proto.Clone(base).(*authoritypb.VisibilityEvent)
	badData.Targets = []*authoritypb.VisibilityTarget{visibilitywire.Data(bytes.Repeat([]byte{2}, 16), 7, 0x700000001, -1)}
	invalid = append(invalid, badData)
	// The historical launch-blocking defect: an unused identity serialized as
	// sixteen zero bytes instead of left absent. The daemon must refuse it.
	zeroPadded := proto.Clone(base).(*authoritypb.VisibilityEvent)
	paddedTarget := visibilitywire.Namespace(bytes.Repeat([]byte{1}, 16), []byte("name"), 42, 0x700000001)
	paddedTarget.Identity = make([]byte, 16)
	zeroPadded.Targets = []*authoritypb.VisibilityTarget{paddedTarget}
	invalid = append(invalid, zeroPadded)
	badPreparePost := proto.Clone(base).(*authoritypb.VisibilityEvent)
	preparePostTarget := visibilitywire.Namespace(bytes.Repeat([]byte{1}, 16), []byte("alias"), 42, 0x700000001)
	preparePostTarget.PostIdentity = bytes.Repeat([]byte{4}, 16)
	badPreparePost.Targets = []*authoritypb.VisibilityTarget{preparePostTarget}
	invalid = append(invalid, badPreparePost)
	for i, event := range invalid {
		if _, err := translateV3VisibilityEvent(epoch, event); err == nil {
			t.Fatalf("invalid visibility case %d was accepted", i)
		}
	}
}

func TestV3CoherenceBridgeRefusesAnAcknowledgementForAnotherAuthorityEpoch(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyMacOS26, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.acknowledge(context.Background(), &pfslocal.VisibilityAckRequest{
		AuthorityEpoch: []byte("wrong"), Cursor: pfslocal.VisibilityCursor{Sequence: 10, Phase: pfslocal.VisibilityPhaseComplete},
	}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("wrong epoch ack = %v, want EINVAL", err)
	}
	client.mu.Lock()
	closedAfterViolation := client.closed
	client.mu.Unlock()
	if !closedAfterViolation {
		t.Fatal("cursor/epoch violation did not terminate the authority session")
	}
}
