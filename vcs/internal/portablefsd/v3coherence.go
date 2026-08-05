package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

const (
	v3CachePolicyMacOS26 = "macos26-synchronous-vfs-repair-v1"
	v3CachePolicyFSKit   = "fskit-native-revocation-v1"
)

// V3CachePolicyMacOS26 is the macOS 26 synchronous-VFS-repair coherence
// policy a v3 ensure request declares. Exported because the CLI builds that
// request and the policy string is a contract between the two processes, not
// something either side may spell on its own.
const V3CachePolicyMacOS26 = v3CachePolicyMacOS26

var (
	errV3VisibilitySubscriber = errors.New("portablefsd: a v3 coherence stream already has a frontend subscriber")
	errV3VisibilityTerminal   = errors.New("portablefsd: v3 coherence stream is terminal")
)

// v3VisibilityClient is the authority state portablefsd owns on behalf of one
// FSKit mount. The extension never sees the mutual-TLS identity, access token,
// replay secrets, or authority connection; pfslocal carries only the derived
// cache contract and ordered visibility obligations.
type v3VisibilityClient interface {
	Epoch() []byte
	SessionID() []byte
	InitialVisibilityCursor() *authoritypb.VisibilityCursor
	VisibilityRepairBudget() time.Duration
	NextVisibility(context.Context, *authoritypb.VisibilityCursor) (*authoritypb.VisibilityEvent, error)
	AckVisibility(context.Context, *authoritypb.VisibilityCursor) error
	ReportVisibilityBlocked(context.Context, *authoritypb.VisibilityCursor) error
	SessionDone() <-chan struct{}
	SessionError() error
	Close() error
}

type v3PendingVisibility struct {
	event       *pfslocal.V3VisibilityEvent
	cursor      *authoritypb.VisibilityCursor
	deadline    time.Time
	advanced    chan struct{}
	advanceOnce sync.Once
}

func (p *v3PendingVisibility) advance() { p.advanceOnce.Do(func() { close(p.advanced) }) }

type v3MutationTicket struct {
	slot     uint32
	sequence uint64
}

// v3CoherenceBridge is the lossless local half of one strict authority
// participant. At most one event is outstanding. It remains pending until the
// authority accepts the exact cursor; a frontend socket loss is terminal for
// the mount because a replacement extension process cannot prove what the
// kernel published before that loss.
type v3CoherenceBridge struct {
	client   v3VisibilityClient
	contract pfslocal.V3CoherenceContract
	budget   time.Duration

	mu           sync.Mutex
	ackMu        sync.Mutex
	cursor       *authoritypb.VisibilityCursor
	pending      *v3PendingVisibility
	operations   map[v3MutationTicket]uint64
	visible      map[v3MutationTicket]bool
	publications map[uint64]chan struct{}
	subscribed   bool
	terminal     error
	failOnce     sync.Once
	onFailure    func(error)
}

func newV3CoherenceBridge(client v3VisibilityClient, cachePolicy string, onFailure func(error)) (*v3CoherenceBridge, error) {
	if client == nil {
		return nil, errors.New("portablefsd: v3 coherence needs an authority client")
	}
	if cachePolicy != v3CachePolicyMacOS26 && cachePolicy != v3CachePolicyFSKit {
		return nil, fmt.Errorf("portablefsd: unsupported macOS v3 cache policy %q", cachePolicy)
	}
	epoch, session := client.Epoch(), client.SessionID()
	if len(epoch) != 16 || len(session) != 16 {
		return nil, errors.New("portablefsd: v3 authority omitted its 16-byte epoch or session identity")
	}
	budget := client.VisibilityRepairBudget()
	if budget < time.Millisecond {
		return nil, errors.New("portablefsd: v3 authority client has no representable repair budget")
	}
	initial := cloneAuthorityCursor(client.InitialVisibilityCursor())
	if initial != nil {
		if err := validateAuthorityCursor(initial); err != nil {
			return nil, fmt.Errorf("portablefsd: invalid initial visibility cursor: %w", err)
		}
		if initial.GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
			return nil, errors.New("portablefsd: initial visibility cursor is not COMPLETE")
		}
	}
	b := &v3CoherenceBridge{
		client:       client,
		budget:       budget,
		cursor:       initial,
		operations:   make(map[v3MutationTicket]uint64),
		visible:      make(map[v3MutationTicket]bool),
		publications: make(map[uint64]chan struct{}),
		onFailure:    onFailure,
		contract: pfslocal.V3CoherenceContract{
			AuthorityProtocolMajor: authorityrpc.ProtocolMajor,
			AuthorityEpoch:         append([]byte(nil), epoch...),
			SessionID:              append([]byte(nil), session...),
			CachePolicy:            cachePolicy,
			RepairBudgetMillis:     uint64(budget / time.Millisecond),
		},
	}
	if initial != nil {
		cursor := localVisibilityCursor(initial)
		b.contract.InitialCursor = &cursor
	}
	go b.watchSession()
	return b, nil
}

// registerMutation links an authority replay identity to the pfslocal
// publication unit that initiated it. The authorityrpc observer calls this
// before it writes the mutation request, so PREPARE cannot arrive first.
func (b *v3CoherenceBridge) registerMutation(slot uint32, sequence, localOperationID uint64) error {
	if sequence == 0 || localOperationID == 0 {
		return syscall.EINVAL
	}
	key := v3MutationTicket{slot: slot, sequence: sequence}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminal != nil {
		return errors.Join(errV3VisibilityTerminal, b.terminal)
	}
	if existing := b.operations[key]; existing != 0 && existing != localOperationID {
		return errors.New("portablefsd: authority mutation ticket was bound to two local operations")
	}
	b.operations[key] = localOperationID
	if b.publications[localOperationID] == nil {
		b.publications[localOperationID] = make(chan struct{})
	}
	return nil
}

// acknowledgePublication is called from the existing pfslocal PublicationAck
// retirement point. Source COMPLETE cannot reach the authority before this
// exact callback has crossed the FSKit framework publication boundary.
func (b *v3CoherenceBridge) acknowledgePublication(localOperationID uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	published := b.publications[localOperationID]
	if published == nil {
		return false
	}
	select {
	case <-published:
		return false
	default:
		close(published)
		return true
	}
}

// abandonMutation removes a ticket only when authorityrpc proves the request
// was refused before recording or entering visibility. It must never be used
// for an uncertain outcome or after a PREPARE was observed.
func (b *v3CoherenceBridge) abandonMutation(slot uint32, sequence, localOperationID uint64) {
	key := v3MutationTicket{slot: slot, sequence: sequence}
	b.mu.Lock()
	if b.operations[key] == localOperationID &&
		(b.pending == nil || b.pending.event.MutationSlot != slot || b.pending.event.MutationSequence != sequence) {
		delete(b.operations, key)
		b.retirePublicationLocked(localOperationID)
	}
	b.mu.Unlock()
}

// completeMutation settles the local half of an assigned replay identity once
// authorityrpc has a definite result. A visible mutation keeps its ticket until
// source COMPLETE crosses the FSKit publication boundary; a recorded mutation
// which emitted no PREPARE can be retired immediately. The latter is safe only
// because v3 data-plane admission requires this bridge to be bound: the
// authority cannot return a visible mutation before this same bridge has
// received and acknowledged its source PREPARE.
func (b *v3CoherenceBridge) completeMutation(
	identity authorityrpc.MutationIdentity,
	localOperationID uint64,
	response *authoritypb.Response,
	callErr error,
) error {
	key := v3MutationTicket{slot: identity.Slot, sequence: identity.Sequence}
	if callErr != nil || response == nil || response.GetUncertain() ||
		response.GetRoutesMismatch().GetSessionRefused() {
		if callErr == nil {
			callErr = errors.New("portablefsd: authority mutation ended without a definite session-safe result")
		}
		return b.fail(callErr)
	}
	b.mu.Lock()
	if b.terminal != nil {
		err := errors.Join(errV3VisibilityTerminal, b.terminal)
		b.mu.Unlock()
		return err
	}
	if b.operations[key] != localOperationID {
		b.mu.Unlock()
		return b.fail(errors.New("portablefsd: authority mutation result lost its local publication identity"))
	}
	state := response.GetMutation()
	if state != nil && (state.GetSlot() != identity.Slot || state.GetAcceptedSequence() != identity.Sequence) {
		b.mu.Unlock()
		return b.fail(errors.New("portablefsd: authority mutation result changed its assigned replay identity"))
	}
	// No MutationState means the authority refused before recording anything.
	// A recorded result with no observed PREPARE is a successful or failed
	// non-visible operation such as Open, Close, or ReadDir.
	if state == nil || !b.visible[key] {
		delete(b.operations, key)
		delete(b.visible, key)
		b.retirePublicationLocked(localOperationID)
	}
	b.mu.Unlock()
	return nil
}

// readyForOperations closes the attach-ordering gap between Resolve and the
// event subscription. Strict operations cannot reach the authority until the
// one lossless visibility consumer is bound; otherwise a source PREPARE could
// block the authority while no local component owns its repair deadline.
func (b *v3CoherenceBridge) readyForOperations() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminal != nil {
		return errors.Join(errV3VisibilityTerminal, b.terminal)
	}
	if !b.subscribed {
		return syscall.EAGAIN
	}
	return nil
}

func (b *v3CoherenceBridge) resolveContract() *pfslocal.V3CoherenceContract {
	b.mu.Lock()
	defer b.mu.Unlock()
	contract := b.contract
	contract.AuthorityEpoch = append([]byte(nil), contract.AuthorityEpoch...)
	contract.SessionID = append([]byte(nil), contract.SessionID...)
	if contract.InitialCursor != nil {
		cursor := *contract.InitialCursor
		contract.InitialCursor = &cursor
	}
	return &contract
}

// run binds the one subscribed pfslocal connection for this mount incarnation.
// Any disconnect is terminal and must fence/self-unmount the mount. The repair
// deadline belongs to the pending authority phase and cannot be restarted by
// reconnecting a new frontend.
func (b *v3CoherenceBridge) run(ctx context.Context, deliver func(*pfslocal.Event) error) error {
	if deliver == nil {
		return syscall.EINVAL
	}
	if err := b.bind(); err != nil {
		return err
	}
	defer b.unbind()
	for {
		pending, err := b.next(ctx)
		if err != nil {
			return err
		}
		if err := deliver(&pfslocal.Event{Kind: cloneLocalVisibilityEvent(pending.event)}); err != nil {
			return b.fail(err)
		}
		select {
		case <-ctx.Done():
			return b.fail(ctx.Err())
		case <-pending.advanced:
		case <-b.client.SessionDone():
			return b.fail(sessionFailure(b.client))
		}
	}
}

func (b *v3CoherenceBridge) bind() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminal != nil {
		return errors.Join(errV3VisibilityTerminal, b.terminal)
	}
	if b.subscribed {
		return errV3VisibilitySubscriber
	}
	b.subscribed = true
	return nil
}

func (b *v3CoherenceBridge) unbind() {
	b.mu.Lock()
	b.subscribed = false
	b.mu.Unlock()
}

func (b *v3CoherenceBridge) next(ctx context.Context) (*v3PendingVisibility, error) {
	b.mu.Lock()
	if b.terminal != nil {
		err := errors.Join(errV3VisibilityTerminal, b.terminal)
		b.mu.Unlock()
		return nil, err
	}
	if b.pending != nil {
		pending := b.pending
		b.mu.Unlock()
		return pending, nil
	}
	after := cloneAuthorityCursor(b.cursor)
	b.mu.Unlock()

	event, err := b.client.NextVisibility(ctx, after)
	if err != nil {
		return nil, b.fail(err)
	}
	local, err := translateV3VisibilityEvent(b.contract.AuthorityEpoch, event)
	if err != nil {
		return nil, b.fail(err)
	}
	if local.Routes != nil {
		// Routing is part of the mount's admitted topology, not cache state. No
		// FSKit invalidation can turn an already-mounted namespace into a
		// different routing graph, so a route event ends this incarnation rather
		// than being acknowledged as though it were a repair.
		return nil, b.fail(authorityrpc.ErrRoutesMismatch)
	}
	pending := &v3PendingVisibility{
		event:    local,
		cursor:   cloneAuthorityCursor(event.GetCursor()),
		deadline: time.Now().Add(b.budget),
		advanced: make(chan struct{}),
	}
	b.mu.Lock()
	if b.terminal != nil {
		err := errors.Join(errV3VisibilityTerminal, b.terminal)
		b.mu.Unlock()
		return nil, err
	}
	// Only one subscriber may poll, so another pending event here is an
	// internal state-machine violation rather than a race to resolve.
	if b.pending != nil {
		b.mu.Unlock()
		return nil, b.fail(errors.New("portablefsd: concurrent v3 visibility poll installed two pending events"))
	}
	if bytes.Equal(local.InitiatorSessionID, b.contract.SessionID) {
		key := v3MutationTicket{
			slot: local.MutationSlot, sequence: local.MutationSequence,
		}
		local.LocalOperationID = b.operations[key]
		if local.LocalOperationID == 0 {
			b.mu.Unlock()
			return nil, b.fail(errors.New("portablefsd: source visibility event has no local publication identity"))
		}
		b.visible[key] = true
	}
	b.pending = pending
	b.mu.Unlock()
	go b.watchDeadline(pending)
	return pending, nil
}

// acknowledge advances the authority and local cursor as one serialized step.
// A duplicate of the last accepted cursor is forwarded idempotently, covering
// the case where the authority accepted the ack but the local reply was lost.
func (b *v3CoherenceBridge) acknowledge(ctx context.Context, request *pfslocal.VisibilityAckRequest) error {
	if request == nil || !bytes.Equal(request.AuthorityEpoch, b.contract.AuthorityEpoch) {
		return b.protocolViolation("visibility acknowledgement has no request or names a different authority epoch")
	}
	if len(request.Reason) > 1024 {
		return b.protocolViolation("visibility blocked reason exceeds 1024 bytes")
	}
	if !request.Blocked && request.Reason != "" {
		return b.protocolViolation("successful visibility acknowledgement carries a failure reason")
	}
	cursor, err := authorityVisibilityCursor(request.Cursor)
	if err != nil {
		return b.protocolViolation("visibility acknowledgement has an invalid cursor")
	}

	b.ackMu.Lock()
	defer b.ackMu.Unlock()
	b.mu.Lock()
	if b.terminal != nil {
		err := errors.Join(errV3VisibilityTerminal, b.terminal)
		b.mu.Unlock()
		return err
	}
	pending := b.pending
	current := cloneAuthorityCursor(b.cursor)
	b.mu.Unlock()

	if pending == nil {
		if request.Blocked || !authorityCursorsEqual(current, cursor) {
			return b.protocolViolation("visibility acknowledgement does not repeat the last accepted cursor")
		}
		if err := b.client.AckVisibility(ctx, cursor); err != nil {
			return b.fail(err)
		}
		return nil
	}
	if !authorityCursorsEqual(pending.cursor, cursor) {
		return b.protocolViolation("visibility acknowledgement does not match the outstanding cursor")
	}
	if request.Blocked {
		reportErr := b.client.ReportVisibilityBlocked(ctx, cursor)
		if reportErr == nil {
			reportErr = errors.New("portablefsd: authority accepted a blocked visibility report without fencing the session")
		}
		return b.fail(reportErr)
	}
	if cursor.GetPhase() == authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE &&
		bytes.Equal(pending.event.InitiatorSessionID, b.contract.SessionID) {
		b.mu.Lock()
		published := b.publications[pending.event.LocalOperationID]
		deadline := pending.deadline
		b.mu.Unlock()
		if published == nil {
			return b.fail(errors.New("portablefsd: source COMPLETE lost its local publication ledger"))
		}
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-published:
		case <-ctx.Done():
			return b.fail(ctx.Err())
		case <-timer.C:
			return b.fail(errors.New("portablefsd: source COMPLETE reached its deadline before callback publication"))
		case <-b.client.SessionDone():
			return b.fail(sessionFailure(b.client))
		}
	}
	if err := b.client.AckVisibility(ctx, cursor); err != nil {
		return b.fail(err)
	}
	b.mu.Lock()
	if b.terminal != nil {
		err := errors.Join(errV3VisibilityTerminal, b.terminal)
		b.mu.Unlock()
		return err
	}
	if b.pending == pending {
		b.cursor = cloneAuthorityCursor(cursor)
		b.pending = nil
		if cursor.GetPhase() == authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE &&
			bytes.Equal(pending.event.InitiatorSessionID, b.contract.SessionID) {
			operationID := pending.event.LocalOperationID
			delete(b.operations, v3MutationTicket{
				slot: pending.event.MutationSlot, sequence: pending.event.MutationSequence,
			})
			delete(b.visible, v3MutationTicket{
				slot: pending.event.MutationSlot, sequence: pending.event.MutationSequence,
			})
			b.retirePublicationLocked(operationID)
		}
		pending.advance()
	}
	b.mu.Unlock()
	return nil
}

func (b *v3CoherenceBridge) protocolViolation(detail string) error {
	return b.fail(fmt.Errorf("%w: %s", syscall.EINVAL, detail))
}

func (b *v3CoherenceBridge) retirePublicationLocked(localOperationID uint64) {
	for _, operationID := range b.operations {
		if operationID == localOperationID {
			return
		}
	}
	delete(b.publications, localOperationID)
}

func (b *v3CoherenceBridge) watchDeadline(pending *v3PendingVisibility) {
	timer := time.NewTimer(time.Until(pending.deadline))
	defer timer.Stop()
	select {
	case <-pending.advanced:
		return
	case <-b.client.SessionDone():
		_ = b.fail(sessionFailure(b.client))
	case <-timer.C:
		_ = b.fail(fmt.Errorf("portablefsd: FSKit missed the v3 visibility repair budget at sequence %d phase %d",
			pending.event.Cursor.Sequence, pending.event.Cursor.Phase))
	}
}

func (b *v3CoherenceBridge) watchSession() {
	<-b.client.SessionDone()
	_ = b.fail(sessionFailure(b.client))
}

func (b *v3CoherenceBridge) fail(cause error) error {
	if cause == nil {
		cause = errV3VisibilityTerminal
	}
	b.failOnce.Do(func() {
		b.mu.Lock()
		b.terminal = cause
		if b.pending != nil {
			b.pending.advance()
		}
		b.mu.Unlock()
		_ = b.client.Close()
		if b.onFailure != nil {
			b.onFailure(cause)
		}
	})
	return cause
}

func sessionFailure(client v3VisibilityClient) error {
	if err := client.SessionError(); err != nil {
		return err
	}
	return io.ErrClosedPipe
}

func translateV3VisibilityEvent(epoch []byte, event *authoritypb.VisibilityEvent) (*pfslocal.V3VisibilityEvent, error) {
	if len(epoch) != 16 || event == nil {
		return nil, errors.New("portablefsd: malformed v3 visibility envelope")
	}
	if err := validateAuthorityCursor(event.GetCursor()); err != nil {
		return nil, err
	}
	if len(event.GetInitiatorSessionId()) != 16 || event.GetMutationSequence() == 0 {
		return nil, errors.New("portablefsd: visibility event omitted its initiator ticket")
	}
	if event.GetRoutes() != nil {
		if len(event.GetTargets()) != 0 || len(event.GetRoutes().GetRevision()) != 32 {
			return nil, errors.New("portablefsd: malformed routing visibility event")
		}
	} else if len(event.GetTargets()) == 0 && event.GetCursor().GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
		// A definite failed or no-op visible mutation can legitimately finish
		// with no coordinates changed. PREPARE must still name what is drained;
		// only its paired COMPLETE may be targetless.
		return nil, errors.New("portablefsd: targetless visibility PREPARE")
	}

	local := &pfslocal.V3VisibilityEvent{
		AuthorityEpoch:     append([]byte(nil), epoch...),
		Cursor:             localVisibilityCursor(event.GetCursor()),
		InitiatorSessionID: append([]byte(nil), event.GetInitiatorSessionId()...),
		MutationSlot:       event.GetMutationSlot(),
		MutationSequence:   event.GetMutationSequence(),
	}
	for _, target := range event.GetTargets() {
		translated, err := translateV3VisibilityTarget(target)
		if err != nil {
			return nil, err
		}
		local.Targets = append(local.Targets, translated)
	}
	if routes := event.GetRoutes(); routes != nil {
		local.Routes = &pfslocal.RoutesChange{
			Revision: append([]byte(nil), routes.GetRevision()...),
			Rules:    append([]byte(nil), routes.GetRules()...),
		}
	}
	return local, nil
}

func translateV3VisibilityTarget(target *authoritypb.VisibilityTarget) (pfslocal.VisibilityTarget, error) {
	if target == nil {
		return pfslocal.VisibilityTarget{}, errors.New("portablefsd: nil visibility target")
	}
	local := pfslocal.VisibilityTarget{
		Identity:       append([]byte(nil), target.GetIdentity()...),
		ParentIdentity: append([]byte(nil), target.GetParentIdentity()...),
		Name:           append([]byte(nil), target.GetName()...),
		Size:           target.GetSize(),
	}
	switch target.GetScope() {
	case authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE:
		if len(local.Identity) != 0 || len(local.ParentIdentity) != 16 || !validV3Name(local.Name) || local.Size != 0 {
			return pfslocal.VisibilityTarget{}, errors.New("portablefsd: malformed namespace visibility target")
		}
		local.Scope = pfslocal.VisibilityScopeNamespace
	case authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA:
		if len(local.Identity) != 16 || len(local.ParentIdentity) != 0 || len(local.Name) != 0 || local.Size < 0 {
			return pfslocal.VisibilityTarget{}, errors.New("portablefsd: malformed data visibility target")
		}
		local.Scope = pfslocal.VisibilityScopeData
	case authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES:
		if len(local.Identity) != 16 || len(local.ParentIdentity) != 0 || len(local.Name) != 0 || local.Size != 0 {
			return pfslocal.VisibilityTarget{}, errors.New("portablefsd: malformed attribute visibility target")
		}
		local.Scope = pfslocal.VisibilityScopeAttributes
	default:
		return pfslocal.VisibilityTarget{}, errors.New("portablefsd: visibility target has an unknown scope")
	}
	return local, nil
}

func validV3Name(name []byte) bool {
	return len(name) > 0 && len(name) <= 255 && !bytes.Equal(name, []byte(".")) &&
		!bytes.Equal(name, []byte("..")) && !bytes.ContainsAny(name, "\x00/")
}

func validateAuthorityCursor(cursor *authoritypb.VisibilityCursor) error {
	if cursor == nil || cursor.GetSequence() == 0 ||
		(cursor.GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE &&
			cursor.GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE) {
		return errors.New("portablefsd: invalid visibility cursor")
	}
	return nil
}

func localVisibilityCursor(cursor *authoritypb.VisibilityCursor) pfslocal.VisibilityCursor {
	phase := pfslocal.VisibilityPhaseUnspecified
	if cursor != nil {
		switch cursor.GetPhase() {
		case authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE:
			phase = pfslocal.VisibilityPhasePrepare
		case authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE:
			phase = pfslocal.VisibilityPhaseComplete
		}
	}
	if cursor == nil {
		return pfslocal.VisibilityCursor{}
	}
	return pfslocal.VisibilityCursor{Sequence: cursor.GetSequence(), Phase: phase}
}

func authorityVisibilityCursor(cursor pfslocal.VisibilityCursor) (*authoritypb.VisibilityCursor, error) {
	phase := authoritypb.VisibilityPhase_VISIBILITY_PHASE_UNSPECIFIED
	switch cursor.Phase {
	case pfslocal.VisibilityPhasePrepare:
		phase = authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE
	case pfslocal.VisibilityPhaseComplete:
		phase = authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE
	default:
		return nil, syscall.EINVAL
	}
	authority := &authoritypb.VisibilityCursor{Sequence: cursor.Sequence, Phase: phase}
	if err := validateAuthorityCursor(authority); err != nil {
		return nil, syscall.EINVAL
	}
	return authority, nil
}

func cloneAuthorityCursor(cursor *authoritypb.VisibilityCursor) *authoritypb.VisibilityCursor {
	if cursor == nil {
		return nil
	}
	return &authoritypb.VisibilityCursor{Sequence: cursor.GetSequence(), Phase: cursor.GetPhase()}
}

func authorityCursorsEqual(left, right *authoritypb.VisibilityCursor) bool {
	return left != nil && right != nil && left.GetSequence() == right.GetSequence() && left.GetPhase() == right.GetPhase()
}

func cloneLocalVisibilityEvent(event *pfslocal.V3VisibilityEvent) *pfslocal.V3VisibilityEvent {
	if event == nil {
		return nil
	}
	clone := *event
	clone.AuthorityEpoch = append([]byte(nil), event.AuthorityEpoch...)
	clone.InitiatorSessionID = append([]byte(nil), event.InitiatorSessionID...)
	clone.Targets = make([]pfslocal.VisibilityTarget, len(event.Targets))
	for i := range event.Targets {
		clone.Targets[i] = event.Targets[i]
		clone.Targets[i].Identity = append([]byte(nil), event.Targets[i].Identity...)
		clone.Targets[i].ParentIdentity = append([]byte(nil), event.Targets[i].ParentIdentity...)
		clone.Targets[i].Name = append([]byte(nil), event.Targets[i].Name...)
	}
	if event.Routes != nil {
		clone.Routes = &pfslocal.RoutesChange{
			Revision: append([]byte(nil), event.Routes.Revision...),
			Rules:    append([]byte(nil), event.Routes.Rules...),
		}
	}
	return &clone
}
