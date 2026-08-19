package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
)

const (
	v3CachePolicyMacOS26V1 = "macos26-synchronous-vfs-repair-v1"
	v3CachePolicyMacOS26   = "macos26-synchronous-vfs-repair-v2"
	v3CachePolicyFSKit     = "fskit-native-revocation-v1"
)

// The exported policy names are the exact contracts a v3 ensure request may
// declare. They are exported because the CLI builds that request and the
// policy string is a contract between two processes, not something either
// side may spell on its own.
const (
	V3CachePolicyMacOS26V1 = v3CachePolicyMacOS26V1
	V3CachePolicyMacOS26   = v3CachePolicyMacOS26
	V3CachePolicyFSKit     = v3CachePolicyFSKit
)

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
	AckVisibilityWithContention(context.Context, *authoritypb.VisibilityCursor, bool) error
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

// v3CoherenceBridge is the lossless local half of one strict authority
// participant. At most one event is outstanding. It remains pending until the
// authority accepts the exact cursor; a frontend socket loss is terminal for
// the mount because a replacement extension process cannot prove what the
// kernel published before that loss.
type v3CoherenceBridge struct {
	client   v3VisibilityClient
	contract pfslocal.V3CoherenceContract
	budget   time.Duration

	mu      sync.Mutex
	ackMu   sync.Mutex
	cursor  *authoritypb.VisibilityCursor
	pending *v3PendingVisibility
	// sourcePublication owns the exact stable-coordinate cut between source
	// callbacks and peer repair. Source filesystem mutations never enter the event
	// stream: the callback acquired this gate before its DATA request could be
	// assigned. A PUBLISHED Ack plus handler retirement releases it locally; a
	// NOT_PUBLISHED Ack after authority commit terminally freezes it.
	sourcePublication   *v3SourcePublicationCoordinator
	subscribed          bool
	detaching           bool
	detachHadSubscriber bool
	// detachStreamEnding records that the subscribed frontend connection
	// actually began ending under a planned kernel detach. If that detach then
	// aborts, the mount has lost the only frontend that could prove its cache
	// state and must become terminal instead of silently resuming.
	detachStreamEnding bool
	terminal           error
	failOnce           sync.Once
	onFailure          func(error)
}

func newV3CoherenceBridge(client v3VisibilityClient, cachePolicy string, onFailure func(error)) (*v3CoherenceBridge, error) {
	if client == nil {
		return nil, errors.New("portablefsd: v3 coherence needs an authority client")
	}
	if cachePolicy != v3CachePolicyMacOS26V1 && cachePolicy != v3CachePolicyMacOS26 && cachePolicy != v3CachePolicyFSKit {
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
		client:            client,
		budget:            budget,
		cursor:            initial,
		sourcePublication: newV3SourcePublicationCoordinator(),
		onFailure:         onFailure,
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

// reserveFrontendPublication publishes the serial reader's callback identity
// before its handler can run. An early PublicationAck can therefore close the
// operation before a delayed handler attempts to acquire a source gate; that
// handler is refused before replay assignment instead of reopening a callback
// that FSKit has already completed.
func (b *v3CoherenceBridge) reserveFrontendPublication(localOperationID uint64) {
	b.sourcePublication.reserve(localOperationID)
}

// releaseFrontendPublication closes only the handler reservation. The logical
// operation remains until PublicationAck even when it acquired no source lease:
// minor 15 makes the callback semantic verdict mandatory and the daemon must
// reject an unknown, omitted, or duplicate verdict rather than infer success.
func (b *v3CoherenceBridge) releaseFrontendPublication(localOperationID uint64) {
	b.sourcePublication.retire(localOperationID)
}

// finishFrontendPublication is later than source-gate retirement: the
// frontend has received the exact PublicationAck and has retired the broader
// logical operation which carried the pfslocal reply. Only this boundary may
// send an authority terminal-delivery receipt. If the frontend ledger and the
// source ledger disagree, revoke the strict mount first and only then consume
// the retained response under that fail-closed verdict.
func (b *v3CoherenceBridge) finishFrontendPublication(localOperationID uint64) error {
	consumptions, err := b.sourcePublication.finishFrontendPublication(localOperationID)
	if err != nil {
		err = b.fail(err)
		// fail marks the source coordinator terminal. That terminal state is the
		// proof that local serving was revoked, so the second finish is allowed
		// to transfer any response which the malformed lifecycle stranded.
		consumptions, _ = b.sourcePublication.finishFrontendPublication(localOperationID)
	}
	for _, consumption := range consumptions {
		if consumption != nil {
			consumption.Consume()
		}
	}
	return err
}

// acknowledgePublication is called from the existing pfslocal PublicationAck
// retirement point. PUBLISHED releases the exact source gate after handler
// retirement. NOT_PUBLISHED is safe only when no visible authority mutation in
// the operation committed; otherwise this call terminalizes the mount. There
// is no source visibility event or authority acknowledgement to wait for.
func (b *v3CoherenceBridge) acknowledgePublication(
	localOperationID uint64,
	semanticCommit pfslocal.PublicationSemanticCommit,
) (bool, error) {
	known, err := b.sourcePublication.acknowledge(localOperationID, semanticCommit)
	if err != nil {
		return known, b.fail(err)
	}
	return known, nil
}

// readyForOperations closes the attach-ordering gap between Resolve and the
// event subscription. Strict operations cannot reach the authority until the
// one lossless visibility consumer is bound; otherwise a peer PREPARE could
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
			if b.acceptPlannedDetachCancellation(ctx.Err()) {
				return ctx.Err()
			}
			return b.fail(ctx.Err())
		case <-pending.advanced:
		case <-b.client.SessionDone():
			return b.fail(sessionFailure(b.client))
		}
	}
}

// beginDetach distinguishes the one intentional frontend disconnect from a
// crash. A pending visibility event still owns a repair obligation, so detach
// refuses until it is acknowledged rather than abandoning an in-flight cache
// transition.
func (b *v3CoherenceBridge) beginDetach() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminal != nil {
		return errors.Join(errV3VisibilityTerminal, b.terminal)
	}
	if b.pending != nil || b.detaching {
		return syscall.EBUSY
	}
	b.detaching = true
	b.detachHadSubscriber = b.subscribed
	b.detachStreamEnding = false
	return nil
}

func (b *v3CoherenceBridge) acceptPlannedDetachCancellation(cause error) bool {
	if cause == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.detaching || b.terminal != nil {
		return false
	}
	b.detachStreamEnding = true
	return true
}

// abortDetach returns an untouched frontend to service. If the FSKit stream
// already started ending, there is no safe frontend to resume and the strict
// authority session is fenced through the ordinary terminal path.
func (b *v3CoherenceBridge) abortDetach(cause error) {
	b.mu.Lock()
	streamLost := b.detachStreamEnding || b.detachHadSubscriber && !b.subscribed
	b.detaching = false
	b.detachHadSubscriber = false
	b.detachStreamEnding = false
	b.mu.Unlock()
	select {
	case <-b.client.SessionDone():
		streamLost = true
	default:
	}
	if streamLost {
		_ = b.fail(fmt.Errorf("planned kernel detach aborted after the FSKit frontend disconnected: %w", cause))
	}
}

func (b *v3CoherenceBridge) bind() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminal != nil {
		return errors.Join(errV3VisibilityTerminal, b.terminal)
	}
	if b.detaching {
		return syscall.EBUSY
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

	// The authority long poll must not inherit the frontend socket's lifetime
	// during a planned kernel detach. FSKit closes that socket from its unmount
	// callback before the daemon can observe exact kernel absence and deliver
	// the proof. Canceling the authority call at that point races away the very
	// strict session needed to leave the barrier cleanly. The detached poll is
	// bounded by the authority session itself; successful Detach ends it, while
	// every non-planned frontend loss closes the client immediately below.
	type nextResult struct {
		event *authoritypb.VisibilityEvent
		err   error
	}
	pollCtx, cancelPoll := context.WithCancel(context.Background())
	polled := make(chan nextResult, 1)
	go func() {
		// The planned-detach branch deliberately leaves this poll alive until
		// DetachAfterUnmount ends the authority session. Whichever event ends the
		// poll still releases the child context here; cancellation is idempotent,
		// so the ordinary-loss branch may also call it to wake NextVisibility.
		defer cancelPoll()
		event, err := b.client.NextVisibility(pollCtx, after)
		polled <- nextResult{event: event, err: err}
	}()
	var event *authoritypb.VisibilityEvent
	var err error
	select {
	case result := <-polled:
		event, err = result.event, result.err
	case <-ctx.Done():
		if b.acceptPlannedDetachCancellation(ctx.Err()) {
			// Do not cancel pollCtx: DetachAfterUnmount uses another authority
			// lane, then ends the session and releases this one goroutine.
			return nil, ctx.Err()
		}
		cancelPoll()
		return nil, b.fail(ctx.Err())
	}
	if err != nil {
		return nil, b.fail(err)
	}
	local, err := translateV3VisibilityEvent(b.contract.AuthorityEpoch, event)
	if err != nil {
		return nil, b.fail(err)
	}
	if bytes.Equal(local.InitiatorSessionID, b.contract.SessionID) {
		return nil, b.fail(errors.New("portablefsd: authority delivered a filesystem visibility phase to its source participant"))
	}
	pending := &v3PendingVisibility{
		event:    local,
		cursor:   cloneAuthorityCursor(event.GetCursor()),
		deadline: time.Now().Add(b.budget),
		advanced: make(chan struct{}),
	}
	switch local.Cursor.Phase {
	case pfslocal.VisibilityPhasePrepare:
		gateContext, cancelGate := context.WithDeadline(ctx, pending.deadline)
		err = b.sourcePublication.acquirePeer(
			gateContext, local.Cursor.Sequence, event.GetTargets(),
		)
		cancelGate()
		if err != nil {
			return nil, b.fail(err)
		}
	case pfslocal.VisibilityPhaseComplete:
		if err := b.sourcePublication.validateComplete(local.Cursor.Sequence); err != nil {
			return nil, b.fail(err)
		}
	default:
		return nil, b.fail(errors.New("portablefsd: visibility event has no publication phase"))
	}
	b.mu.Lock()
	if b.terminal != nil {
		err := errors.Join(errV3VisibilityTerminal, b.terminal)
		b.mu.Unlock()
		return nil, err
	}
	if b.detaching {
		// beginDetach won the race with this long poll. The authority event
		// remains unacknowledged while exact kernel absence is established; the
		// successful DetachAfterUnmount then removes this participant entirely.
		b.detachStreamEnding = true
		b.mu.Unlock()
		return nil, context.Canceled
	}
	// Only one subscriber may poll, so another pending event here is an
	// internal state-machine violation rather than a race to resolve.
	if b.pending != nil {
		b.mu.Unlock()
		return nil, b.fail(errors.New("portablefsd: concurrent v3 visibility poll installed two pending events"))
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
		if !authorityCursorsEqual(current, cursor) {
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
	orderedAdmissionContended := request.OrderedAdmissionContended &&
		b.contract.CachePolicy == v3CachePolicyMacOS26 &&
		cursor.GetPhase() == authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE
	if b.contract.CachePolicy == v3CachePolicyMacOS26 &&
		cursor.GetPhase() == authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE &&
		b.sourcePublication.peerContention(cursor.GetSequence()) {
		orderedAdmissionContended = true
	}
	if err := b.client.AckVisibilityWithContention(ctx, cursor, orderedAdmissionContended); err != nil {
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
		if cursor.GetPhase() == authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
			if err := b.sourcePublication.releasePeer(cursor.GetSequence()); err != nil {
				b.mu.Unlock()
				return b.fail(err)
			}
		}
		pending.advance()
	}
	b.mu.Unlock()
	return nil
}

func (b *v3CoherenceBridge) protocolViolation(detail string) error {
	return b.fail(fmt.Errorf("%w: %s", syscall.EINVAL, detail))
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
	b.mu.Lock()
	detaching := b.detaching
	b.mu.Unlock()
	if detaching {
		return
	}
	_ = b.fail(sessionFailure(b.client))
}

// abandonBeforeMount retires constructor-side state without closing the
// authority transport. Before FSKit publication, only Client.ReleaseBeforeMount
// may end ACTIVE membership: it observes the attempt-unique kernel source and
// sends the authenticated clean detach. Marking this bridge as detaching makes
// its session watcher stand down when that transition closes the client.
func (b *v3CoherenceBridge) abandonBeforeMount() {
	b.mu.Lock()
	b.detaching = true
	if b.pending != nil {
		b.pending.advance()
	}
	b.mu.Unlock()
}

func (b *v3CoherenceBridge) fail(cause error) error {
	if cause == nil {
		cause = errV3VisibilityTerminal
	}
	b.failOnce.Do(func() {
		// The cause is logged here, at the one point that always holds it.
		// Callers propagate the terminal sentinel, and a log line built from
		// what a caller happens to see reports the wrapper instead of the
		// reason the stream died — which is the only thing an operator needs.
		log.Printf("portablefsd: v3 coherence stream failed terminally: %v", cause)
		b.mu.Lock()
		b.terminal = cause
		if b.pending != nil {
			b.pending.advance()
		}
		b.mu.Unlock()
		b.sourcePublication.fail(cause)
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
	if len(event.GetTargets()) == 0 && event.GetCursor().GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
		// A definite failed or no-op visible mutation can legitimately finish
		// with no coordinates changed. PREPARE must still name what is drained;
		// only its paired COMPLETE may be targetless.
		return nil, errors.New("portablefsd: targetless visibility PREPARE")
	}
	if err := visibilitywire.ValidateEventTargets(event.GetCursor().GetPhase(), event.GetCursor().GetSequence(), event.GetTargets()); err != nil {
		return nil, fmt.Errorf("portablefsd: %w", err)
	}

	local := &pfslocal.V3VisibilityEvent{
		AuthorityEpoch:     append([]byte(nil), epoch...),
		Cursor:             localVisibilityCursor(event.GetCursor()),
		InitiatorSessionID: append([]byte(nil), event.GetInitiatorSessionId()...),
		MutationSlot:       event.GetMutationSlot(),
		MutationSequence:   event.GetMutationSequence(),
	}
	for _, target := range event.GetTargets() {
		if event.GetCursor().GetPhase() == authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE &&
			len(target.GetPostIdentity()) != 0 {
			return nil, errors.New("portablefsd: visibility PREPARE attested an unapplied post-binding")
		}
		translated, err := translateV3VisibilityTarget(target)
		if err != nil {
			return nil, err
		}
		local.Targets = append(local.Targets, translated)
	}
	return local, nil
}

// translateV3VisibilityTarget admits a target only through the shared wire
// contract, then keeps the fields this daemon's frontends repair by. FSKit
// indexes kernel state by stable item identity, so the kernel-inode
// coordination facts a Linux FUSE frontend consumes are validated and dropped
// here rather than forwarded.
func translateV3VisibilityTarget(target *authoritypb.VisibilityTarget) (pfslocal.VisibilityTarget, error) {
	if err := visibilitywire.ValidateTarget(target); err != nil {
		return pfslocal.VisibilityTarget{}, fmt.Errorf("portablefsd: %w", err)
	}
	local := pfslocal.VisibilityTarget{
		Identity:       append([]byte(nil), target.GetIdentity()...),
		ParentIdentity: append([]byte(nil), target.GetParentIdentity()...),
		Name:           append([]byte(nil), target.GetName()...),
		Size:           target.GetSize(),
		PostIdentity:   append([]byte(nil), target.GetPostIdentity()...),
	}
	switch target.GetScope() {
	case authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE:
		local.Scope = pfslocal.VisibilityScopeNamespace
	case authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA:
		local.Scope = pfslocal.VisibilityScopeData
	case authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES:
		local.Scope = pfslocal.VisibilityScopeAttributes
	default:
		return pfslocal.VisibilityTarget{}, errors.New("portablefsd: visibility target has an unknown scope")
	}
	return local, nil
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
	return &clone
}
