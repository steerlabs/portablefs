package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
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

	mu      sync.Mutex
	acked   []*authoritypb.VisibilityCursor
	blocked []*authoritypb.VisibilityCursor
	closed  bool
	err     error
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
func (f *fakeV3VisibilityClient) AckVisibility(_ context.Context, cursor *authoritypb.VisibilityCursor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, cloneAuthorityCursor(cursor))
	return nil
}
func (f *fakeV3VisibilityClient) ReportVisibilityBlocked(_ context.Context, cursor *authoritypb.VisibilityCursor) error {
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
		Targets: []*authoritypb.VisibilityTarget{{
			Scope:          authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE,
			ParentIdentity: bytes.Repeat([]byte{0x55}, 16), Name: []byte("entry"),
		}},
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

func TestV3VisibilityTranslationValidatesEveryScopeAndRoutes(t *testing.T) {
	epoch := bytes.Repeat([]byte{0xa1}, 16)
	base := &authoritypb.VisibilityEvent{
		Cursor:             &authoritypb.VisibilityCursor{Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE},
		InitiatorSessionId: bytes.Repeat([]byte{0xa2}, 16), MutationSequence: 1,
	}
	for _, target := range []*authoritypb.VisibilityTarget{
		{Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE, ParentIdentity: bytes.Repeat([]byte{1}, 16), Name: []byte("name")},
		{Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, Identity: bytes.Repeat([]byte{2}, 16), Size: 42},
		{Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, Identity: bytes.Repeat([]byte{3}, 16)},
	} {
		event := proto.Clone(base).(*authoritypb.VisibilityEvent)
		event.Targets = []*authoritypb.VisibilityTarget{target}
		if _, err := translateV3VisibilityEvent(epoch, event); err != nil {
			t.Fatalf("valid target %v: %v", target.GetScope(), err)
		}
	}
	routes := proto.Clone(base).(*authoritypb.VisibilityEvent)
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
	badInitiator.Targets = []*authoritypb.VisibilityTarget{{Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, Identity: bytes.Repeat([]byte{2}, 16)}}
	invalid = append(invalid, badInitiator)
	badName := proto.Clone(base).(*authoritypb.VisibilityEvent)
	badName.Targets = []*authoritypb.VisibilityTarget{{Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE, ParentIdentity: bytes.Repeat([]byte{1}, 16), Name: []byte("a/b")}}
	invalid = append(invalid, badName)
	badData := proto.Clone(base).(*authoritypb.VisibilityEvent)
	badData.Targets = []*authoritypb.VisibilityTarget{{Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, Identity: bytes.Repeat([]byte{2}, 16), Size: -1}}
	invalid = append(invalid, badData)
	badRoutes := proto.Clone(routes).(*authoritypb.VisibilityEvent)
	badRoutes.Targets = []*authoritypb.VisibilityTarget{{Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, Identity: bytes.Repeat([]byte{3}, 16)}}
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
