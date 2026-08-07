package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"io"
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
	blocked    []*authoritypb.VisibilityCursor
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
func (f *fakeV3VisibilityClient) ReportVisibilityBlocked(_ context.Context, cursor *authoritypb.VisibilityCursor, _ []uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked = append(f.blocked, cloneAuthorityCursor(cursor))
	return errors.New("test authority fenced blocked mount")
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

func TestV3CoherenceBridgeMapsAndRetiresTheSourcePublicationIdentity(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.registerMutation(7, 31, 99); err != nil {
		t.Fatal(err)
	}
	makeSource := func(phase authoritypb.VisibilityPhase) *authoritypb.VisibilityEvent {
		event := testV3Event(client, 11, phase)
		event.InitiatorSessionId = append([]byte(nil), client.session...)
		event.MutationSlot = 7
		event.MutationSequence = 31
		return event
	}
	client.next <- v3VisibilityResult{event: makeSource(authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE)}
	client.next <- v3VisibilityResult{event: makeSource(authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE)}

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
	if prepare.LocalOperationID != 99 {
		t.Fatalf("PREPARE local operation = %d, want 99", prepare.LocalOperationID)
	}
	if err := bridge.acknowledge(context.Background(), &pfslocal.VisibilityAckRequest{AuthorityEpoch: client.epoch, Cursor: prepare.Cursor}); err != nil {
		t.Fatal(err)
	}
	complete := <-delivered
	if complete.LocalOperationID != 99 {
		t.Fatalf("COMPLETE local operation = %d, want 99", complete.LocalOperationID)
	}
	completeAck := make(chan error, 1)
	go func() {
		completeAck <- bridge.acknowledge(context.Background(), &pfslocal.VisibilityAckRequest{
			AuthorityEpoch: client.epoch, Cursor: complete.Cursor,
		})
	}()
	select {
	case err := <-completeAck:
		t.Fatalf("source COMPLETE advanced before publication: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if got := client.ackedCursors(); len(got) != 1 {
		t.Fatalf("authority saw %d acks before source publication, want only PREPARE", len(got))
	}
	if !bridge.acknowledgePublication(99) {
		t.Fatal("source callback publication was not accepted")
	}
	if err := <-completeAck; err != nil {
		t.Fatal(err)
	}
	bridge.mu.Lock()
	remaining := len(bridge.operations)
	remainingPublications := len(bridge.publications)
	bridge.mu.Unlock()
	if remaining != 0 || remainingPublications != 0 {
		t.Fatalf("source ledger retained %d ticket(s), %d publication(s)", remaining, remainingPublications)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("subscriber exit = %v, want cancellation", err)
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

func TestV3CoherenceBridgeAcceptsPublicationBeforeMutationRegistration(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyFSKit, nil)
	if err != nil {
		t.Fatal(err)
	}

	const operationID = uint64(91)
	bridge.reserveFrontendPublication(operationID)
	if !bridge.acknowledgePublication(operationID) {
		t.Fatal("publication acknowledgement did not find the serial-reader reservation")
	}
	if err := bridge.registerMutation(7, 31, operationID); err != nil {
		t.Fatal(err)
	}

	bridge.mu.Lock()
	published := bridge.publications[operationID]
	_, active := bridge.publicationReservations[operationID]
	bridge.mu.Unlock()
	if published == nil || !active {
		t.Fatal("mutation registration did not reuse the acknowledged frontend state")
	}
	select {
	case <-published:
	default:
		t.Fatal("early acknowledgement was lost when the mutation registered")
	}

	// Frontend retirement alone cannot discard a registered mutation's source
	// publication witness. The authority ticket owns it until that ticket is
	// abandoned or reaches source COMPLETE.
	bridge.releaseFrontendPublication(operationID)
	bridge.mu.Lock()
	_, retained := bridge.publications[operationID]
	bridge.mu.Unlock()
	if !retained {
		t.Fatal("frontend retirement discarded a registered mutation witness")
	}
	bridge.abandonMutation(7, 31, operationID)
	bridge.mu.Lock()
	_, retained = bridge.publications[operationID]
	bridge.mu.Unlock()
	if retained {
		t.Fatal("settled mutation retained its publication witness")
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
	if !bridge.acknowledgePublication(101) {
		t.Fatal("early read-only acknowledgement was refused")
	}
	bridge.releaseFrontendPublication(101)

	// Handler retirement before ACK: no mutation can register after the last
	// handler exits, so the bridge may discard the reservation immediately. The
	// later frontend ACK remains valid in the connection ledger and has nothing
	// authority-side to release.
	bridge.reserveFrontendPublication(102)
	bridge.releaseFrontendPublication(102)
	if bridge.acknowledgePublication(102) {
		t.Fatal("finish-before-ack recreated a retired read-only bridge state")
	}

	bridge.mu.Lock()
	publications := len(bridge.publications)
	reservations := len(bridge.publicationReservations)
	bridge.mu.Unlock()
	if publications != 0 || reservations != 0 {
		t.Fatalf("read-only operations leaked %d publication(s), %d reservation(s)", publications, reservations)
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
	// for a sequential continuation, but no handler is active, so its bounded
	// bridge state is gone.
	bridge.reserveFrontendPublication(operationID)
	bridge.releaseFrontendPublication(operationID)

	// The serial reader sees request two before launching its handler and
	// idempotently reactivates the same operation ID. Its ACK may then overtake
	// handler scheduling without losing the later authority registration.
	bridge.reserveFrontendPublication(operationID)
	if !bridge.acknowledgePublication(operationID) {
		t.Fatal("continuation acknowledgement did not find the reactivated reservation")
	}
	if err := bridge.registerMutation(9, 41, operationID); err != nil {
		t.Fatal(err)
	}
	bridge.mu.Lock()
	published := bridge.publications[operationID]
	bridge.mu.Unlock()
	select {
	case <-published:
	default:
		t.Fatal("continuation mutation registration lost the early acknowledgement")
	}

	bridge.releaseFrontendPublication(operationID)
	bridge.abandonMutation(9, 41, operationID)
	bridge.mu.Lock()
	publications := len(bridge.publications)
	reservations := len(bridge.publicationReservations)
	bridge.mu.Unlock()
	if publications != 0 || reservations != 0 {
		t.Fatalf("sequential continuation leaked %d publication(s), %d reservation(s)", publications, reservations)
	}
}

func TestV3CoherenceBridgeFailsClosedWhenSourceTicketIsUnknown(t *testing.T) {
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
	if err := bridge.run(context.Background(), func(*pfslocal.Event) error { return nil }); err == nil {
		t.Fatal("unknown source ticket did not fail the bridge")
	}
	select {
	case <-failures:
	case <-time.After(time.Second):
		t.Fatal("unknown source ticket did not publish a terminal failure")
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

func TestV3CoherenceBridgeTerminatesActualZeroTicketRoutePrepare(t *testing.T) {
	client := newFakeV3VisibilityClient()
	defer client.Close()
	failures := make(chan error, 1)
	bridge, err := newV3CoherenceBridge(client, v3CachePolicyMacOS26, func(err error) {
		failures <- err
	})
	if err != nil {
		t.Fatal(err)
	}
	event := &authoritypb.VisibilityEvent{
		Cursor: &authoritypb.VisibilityCursor{
			Sequence: 11, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE,
		},
		InitiatorSessionId: make([]byte, 16),
		Routes: &authoritypb.RoutesChange{
			Revision: bytes.Repeat([]byte{0x51}, 32), Rules: []byte("/cache\n"),
		},
		// Route events carry the zero session identity and no mutation replay ticket.
	}
	client.next <- v3VisibilityResult{event: event}
	delivered := false
	err = bridge.run(context.Background(), func(*pfslocal.Event) error {
		delivered = true
		return nil
	})
	if !errors.Is(err, authorityrpc.ErrRoutesMismatch) {
		t.Fatalf("route PREPARE = %v, want ErrRoutesMismatch", err)
	}
	if delivered {
		t.Fatal("route PREPARE was forwarded to FSKit")
	}
	client.mu.Lock()
	closed := client.closed
	acks := len(client.acked)
	client.mu.Unlock()
	if !closed || acks != 0 {
		t.Fatalf("route PREPARE left client closed=%v with %d Ack(s)", closed, acks)
	}
	select {
	case failure := <-failures:
		if !errors.Is(failure, authorityrpc.ErrRoutesMismatch) {
			t.Fatalf("terminal route failure = %v", failure)
		}
	default:
		t.Fatal("route PREPARE did not publish its terminal failure")
	}
	if err := bridge.bind(); !errors.Is(err, errV3VisibilityTerminal) {
		t.Fatalf("route-terminated bridge rebound: %v", err)
	}
}

func TestV3VisibilityTranslationValidatesEveryScopeAndRoutes(t *testing.T) {
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

	routes := proto.Clone(base).(*authoritypb.VisibilityEvent)
	routes.InitiatorSessionId = make([]byte, 16)
	routes.MutationSequence = 0
	routes.Routes = &authoritypb.RoutesChange{Revision: bytes.Repeat([]byte{4}, 32), Rules: []byte("/cache\n")}
	if got, err := translateV3VisibilityEvent(epoch, routes); err != nil || got.Routes == nil {
		t.Fatalf("valid route event = %#v, %v", got, err)
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
	badRoutes := proto.Clone(routes).(*authoritypb.VisibilityEvent)
	badRoutes.Targets = []*authoritypb.VisibilityTarget{visibilitywire.Attributes(bytes.Repeat([]byte{3}, 16), 7, 0x700000001)}
	invalid = append(invalid, badRoutes)
	for i, event := range invalid {
		if _, err := translateV3VisibilityEvent(epoch, event); err == nil {
			t.Fatalf("invalid visibility case %d was accepted", i)
		}
	}
}

func TestV3CoherenceBridgeRefusesWrongAndBlockedAcknowledgements(t *testing.T) {
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

	client = newFakeV3VisibilityClient()
	defer client.Close()
	bridge, err = newV3CoherenceBridge(client, v3CachePolicyMacOS26, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.next <- v3VisibilityResult{event: testV3Event(client, 11, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	delivered := make(chan *pfslocal.V3VisibilityEvent, 1)
	go func() {
		_ = bridge.run(ctx, func(event *pfslocal.Event) error {
			delivered <- event.Kind.(*pfslocal.V3VisibilityEvent)
			return nil
		})
	}()
	event := <-delivered
	err = bridge.acknowledge(context.Background(), &pfslocal.VisibilityAckRequest{
		AuthorityEpoch: client.epoch, Cursor: event.Cursor, Blocked: true, Reason: "proven parent-lock cycle",
	})
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("blocked report returned %v", err)
	}
	client.mu.Lock()
	blocked := len(client.blocked)
	client.mu.Unlock()
	if blocked != 1 {
		t.Fatalf("authority received %d blocked reports, want 1", blocked)
	}
}
