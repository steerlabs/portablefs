// Package-internal frontend publication gate.
//
// One frontend request is one logical operation. The gate is the ledger that
// tracks which operations have replies exposed to FSKit, which replies have
// been acknowledged, and which are retracted — the ordering contract the
// authority's visibility barrier is proven against. It is transport-neutral:
// it reasons about pfslocal request bodies and path scopes only, never about
// the data plane serving them.

package portablefsd

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// FSKit reserves inode values 0, 1, and 2 for invalid, parent-of-root, and
// root. The Swift adapter exposes every durable pfslocal item ID through the
// checked successor mapping (root 1 -> 2), so kernel-side identity proofs must
// apply the exact same boundary translation.
func fskitItemID(itemID uint64) (uint64, bool) {
	if itemID == 0 || itemID == ^uint64(0) {
		return 0, false
	}
	return itemID + 1, true
}

type frontendOperation struct {
	attach       *attach
	paths        []string
	pathEpoch    uint64
	gateActive   bool
	participants int
	suspended    int
	completed    bool
	// published records that at least one reply belonging to this logical
	// operation has been WRITTEN with PublicationAckRequired.
	//
	// ── EXPOSURE IS THE OBLIGATION; PARTICIPANT LIVENESS IS NOT ─────────────
	//
	// Everything else about a logical operation's membership of the active
	// publication set is derived from its participants: it activates when a
	// request enters, it retracts when every request has suspended or retired.
	// That derivation used participant liveness as a PROXY for "this operation
	// still owes the kernel-coherence barrier something", and the proxy is
	// simply false once a reply is on the wire. The daemon's own side of a
	// publication ends when the bytes are written; the obligation — that the
	// frontend has installed or discarded the state those bytes describe —
	// begins there and is discharged only by the PublicationAck, or by the
	// connection dying (which resolves it terminally, failing coherence
	// closed).
	//
	// So exposure PINS the operation into the active set, and the pin is
	// independent of whether any request is still running. Two doors were open
	// before it existed, and a delegation handoff walked through both:
	//
	//	1. the ALL-SUSPENDED RETRACTION. A sibling replies and retires, the
	//	   initiator suspends for its own release, and the operation now has
	//	   participants == suspended — so it was retracted from the active set
	//	   and stopped being a blocker ENTIRELY. The handoff then completed
	//	   instantly and silently, with the sibling's reply still in flight.
	//	2. the initiator's own-operation exception in publicationBlockersLocked
	//	   (see there), which reached the same state by the other route when
	//	   the release goroutine ran before the initiator suspended —
	//	   prepareReleaseLocked spawns finishRelease BEFORE its caller reaches
	//	   OnReleaseWait, so that ordering is ordinary, not exotic.
	published bool
	// retracted says a handoff crossed this operation, so nothing it has
	// published may be installed. Every remaining reply the operation receives
	// carries it (frontendConn.replyWithPublication), and the frontend answers
	// by discarding what it collected and failing the framework callback rather
	// than returning values the daemon no longer stands behind.
	//
	// ── WHY REFUSING TO INSTALL, AND NOT REPAIRING AFTER ────────────────────
	//
	// The mount's coherence model is version-anchored with a zero TTL: a value
	// the frontend holds is either current or it is not there. "Install it and
	// invalidate afterwards" is a TTL by another name — it names a window in
	// which an application reads a value the daemon already knows is wrong —
	// and it is the model, not the length of the window, that forbids it. A
	// value that will have to be retracted must never be installed.
	//
	// ── WHY THIS DOES NOT LIVELOCK, AND REFUSING THE MUTATION WOULD ─────────
	//
	// The alternative considered was to refuse the initiating mutation before
	// it executes and let the syscall retry. It does not terminate. The shape
	// that reaches this case is one framework callback issuing a publishing
	// request and then a mutation needing the delegation released — FSKit's
	// removeItem is exactly that. A refusal leaves the delegation in place, so
	// the retry runs the SAME callback, exposes the SAME sibling publication,
	// and is refused again, forever: the state the retry is waiting to change
	// is the state the refusal prevents from changing.
	//
	// Retraction inverts that. The handoff COMPLETES — the delegation really is
	// released — and only the crossed operation's results are thrown away. The
	// retry therefore finds nothing left to release, takes the authority lane
	// directly, never reaches this case, and converges in one attempt.
	//
	// Guarded by frontendGateMu.
	retracted bool
	// carriers counts the replies of this operation whose retraction verdict has
	// been CAPTURED and whose frame has not yet been written.
	//
	// ── WHY SAMPLING THE VERDICT IS NOT ENOUGH ──────────────────────────────
	//
	// The retraction is delivered by riding a reply, so the reply is the only
	// carrier it has, and the verdict was read a moment BEFORE the frame went
	// out. That gap is a real interleaving and it is the worst one available: a
	// non-publishing participant of an operation whose other participants are
	// all permanently suspended reads retracted==false, and before its frame
	// reaches the socket a handoff sees exactly the state
	// publicationBlockersLocked crosses (published, no runnable participant,
	// everything parked), crosses it, and sets retracted. The frame that goes
	// out is the one built before the crossing; the framework installs the
	// pre-handoff view; and the only mechanism that could have prevented the
	// install has already been used up.
	//
	// So capturing the verdict is a GATE TRANSITION, not a read: under
	// frontendGateMu the reply either observes an existing retraction, or it
	// registers itself here — and a handoff must then block on it rather than
	// cross it. The registration is released when the frame has been written, so
	// the wait is bounded by one socket write on a connection whose peer is
	// waiting for that very frame; it never becomes a wait on the acknowledgement
	// (which is the unreachable one the fence exists for). Guarded by
	// frontendGateMu.
	carriers int
}

// publicationRetracted reports whether a handoff has crossed op, so every reply
// still owed to it must tell the frontend to discard what it has collected.
//
// It is the read-only form, for a caller deciding what to DO (the initiator
// refusing its own mutation). A caller about to WRITE a frame stamped with the
// verdict must use captureRetractionCarrier instead: the answer has to be
// ordered against the crossing, not merely sampled before it.
func (a *attach) publicationRetracted(op *frontendOperation) bool {
	if op == nil || op.attach != a {
		return false
	}
	a.frontendGateMu.Lock()
	defer a.frontendGateMu.Unlock()
	return op.retracted
}

// captureRetractionCarrier is the ATOMIC GATE TRANSITION for one reply frame.
//
// Under frontendGateMu the reply either observes a retraction that has already
// happened — in which case it carries it and registers nothing, because the
// crossing it would have to block is already complete — or it commits itself
// into op.carriers, a state a future handoff must block on until the frame is
// written. Both outcomes are decided under the same lock the crossing takes, so
// there is no instant at which a reply has decided "not retracted" and a
// crossing is free to happen behind it.
//
// The returned release must be called after the frame has left, and never
// before: the whole point of the registration is that it spans the write.
func (a *attach) captureRetractionCarrier(op *frontendOperation) (retracted bool, release func()) {
	if op == nil || op.attach != a {
		return false, func() {}
	}
	a.frontendGateMu.Lock()
	if op.retracted {
		a.frontendGateMu.Unlock()
		return true, func() {}
	}
	op.carriers++
	a.frontendGateMu.Unlock()
	var once sync.Once
	return false, func() {
		once.Do(func() {
			a.frontendGateMu.Lock()
			if op.carriers > 0 {
				op.carriers--
			}
			if a.frontendGateCond != nil {
				a.frontendGateCond.Broadcast()
			}
			a.frontendGateMu.Unlock()
		})
	}
}

type frontendOperationContextKey struct{}

type frontendOperationParticipant struct {
	op           *frontendOperation
	suspendDepth int
	finished     bool
	// nonpublishing marks a participant that entered the logical operation
	// permanently suspended because its request exposes no cacheable state.
	// It is accounted for (the operation is not finished while it runs) but
	// is never a member of the active publication set.
	nonpublishing bool
	// pendingPaths/pendingEpoch are an EXTENSION's own operand scopes, held
	// on the participant until the instant it activates.
	//
	// A reserved participant is suspended, so it contributes no scope to the
	// publication set and no handoff can be waiting on it. Merging its scopes
	// into op.paths at reservation time would widen an ALREADY ACTIVE
	// operation into a scope a handoff owns — the case the extension rule in
	// activationBlockedLocked holds back. So the merge is part of activation,
	// taken under the gate at the moment the operation proves no handoff owns
	// the new scopes.
	//
	// merged is true from the start for the participant that CREATED the
	// operation: its paths are the operation's paths already.
	pendingPaths []string
	pendingEpoch uint64
	merged       bool
}

// retractFromPublicationSetLocked removes op from the active publication set
// and advances the gate's progress clock. Every retraction goes through here so
// a handoff's settle verdict is measured against real progress rather than
// against elapsed time (see publicationSettleWindow). Caller holds
// frontendGateMu.
func (a *attach) retractFromPublicationSetLocked(op *frontendOperation) {
	if _, ok := a.frontendActive[op]; !ok {
		return
	}
	delete(a.frontendActive, op)
	a.frontendGateProgress++
}

// retractIdleOperationLocked applies the ONE rule by which a live logical
// operation leaves the active publication set without being finished: every
// one of its requests is suspended, so none of them can publish anything and a
// handoff has nothing to wait for.
//
// It is a single function because the rule has one exception and that
// exception must not be re-derived at each of the four call sites that used to
// spell the predicate out (suspendFrontendParticipant,
// joinFrontendOperationSuspended, finishFrontendParticipant and the resume half
// of suspendFrontendOperation). The exception is frontendOperation.published:
// an operation that has already WRITTEN an acknowledgement-required reply owes
// the kernel-coherence barrier a settlement that no amount of suspending can
// discharge, so "nobody is running" is not the same statement as "nothing is
// outstanding". Retracting it there dropped a real, unsettled publication out
// of the barrier and let a delegation handoff cross it silently.
//
// Caller holds frontendGateMu. Returns whether the operation was retracted.
func (a *attach) retractIdleOperationLocked(op *frontendOperation) bool {
	if op.completed || !op.gateActive || op.published {
		return false
	}
	if op.participants <= 0 || op.suspended != op.participants {
		return false
	}
	a.retractFromPublicationSetLocked(op)
	op.gateActive = false
	return true
}

// notePublicationExposed records that a reply belonging to op has been written
// with PublicationAckRequired, and pins op into the active publication set for
// the whole life of that obligation.
//
// It is called from frontendConn.replyWithPublication BEFORE the bytes reach
// the socket, which is the only order that works: once the reply is on the wire
// the daemon has already lost the ability to decide whether a handoff may cross
// it, so the pin has to be installed while the decision is still the daemon's
// to make.
//
// The pin re-enters the set even for an operation whose requests are all
// suspended. That looks like it contradicts the activation protocol's liveness
// rule ("a handoff never waits on a suspended participant"), and it does not:
// that rule is about REQUESTS, which can be made to wait and therefore must
// never be waited on while they hold a mirror. This is about a REPLY that has
// already left, which no lock can be holding and which no request can be asked
// to retract.
func (a *attach) notePublicationExposed(op *frontendOperation) {
	if op == nil || op.attach != a {
		return
	}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	if !op.completed && !op.published {
		op.published = true
		if !op.gateActive {
			a.frontendActive[op] = struct{}{}
			op.gateActive = true
		}
	}
	a.frontendGateCond.Broadcast()
	a.frontendGateMu.Unlock()
}

func (a *attach) initFrontendGateLocked() {
	if a.frontendGateCond == nil {
		a.frontendGateCond = sync.NewCond(&a.frontendGateMu)
	}
	if a.frontendActive == nil {
		a.frontendActive = map[*frontendOperation]struct{}{}
	}
	if a.frontendHandoffs == nil {
		a.frontendHandoffs = map[string]int{}
	}
}

func scopesOverlap(a, b string) bool {
	return pathWithinScope(a, b) || pathWithinScope(b, a)
}

func operationOverlapsScope(paths []string, scope string) bool {
	for _, path := range paths {
		if scopesOverlap(path, scope) {
			return true
		}
	}
	return false
}

// reserveFrontendOperation creates a logical operation with its first
// participant already suspended. It never waits: the created operation is not
// a member of the active publication set until it activates.
func (a *attach) reserveFrontendOperation(
	paths []string,
	pathEpoch uint64,
) (*frontendOperation, *frontendOperationParticipant) {
	op := &frontendOperation{attach: a, paths: paths, pathEpoch: pathEpoch}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	op.participants = 1
	op.suspended = 1
	a.frontendGateMu.Unlock()
	return op, &frontendOperationParticipant{
		op:           op,
		suspendDepth: 1,
		// The creating participant's paths ARE the operation's paths.
		merged: true,
	}
}

// reserveFrontendExtension admits another request belonging to an already live
// logical FSKit callback, suspended and without waiting. Its operand scopes
// stay on the participant until activation merges them (see pendingPaths).
//
// It never RETRACTS the operation's existing membership. A reservation is only
// a statement about the arriving request — that IT is not yet a member — and
// says nothing about the callback, whose earlier reply may already be exposed
// and unacknowledged. Deactivating here (the rule finishFrontendParticipant and
// suspendFrontendOperation apply when an ACTIVE participant leaves the set)
// would let a delegation handoff cross that unacknowledged reply, and would
// then leave this reservation unable to activate at all, since the handoff it
// released now owns the scope. The active set is retracted only by a
// participant that was in it.
func (a *attach) reserveFrontendExtension(
	op *frontendOperation,
	paths []string,
	pathEpoch uint64,
) (*frontendOperationParticipant, error) {
	if op == nil || op.attach != a {
		return nil, fmt.Errorf("portablefsd: invalid logical frontend operation")
	}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	if op.completed {
		a.frontendGateMu.Unlock()
		return nil, net.ErrClosed
	}
	op.participants++
	op.suspended++
	a.frontendGateMu.Unlock()
	return &frontendOperationParticipant{
		op:           op,
		suspendDepth: 1,
		pendingPaths: paths,
		pendingEpoch: pathEpoch,
	}, nil
}

// activationBlockedLocked reports whether a handoff currently owns a scope this
// participant needs. It reproduces, exactly, the two predicates the blocking
// entry points used before the split:
//
//   - an unmerged EXTENSION uses the extension rule — a handoff that already
//     waits on this operation must let its later requests through
//     (alreadyOwned), or the callback could never reach its one publication
//     acknowledgement; a handoff disjoint from the operation's original scope
//     still holds back a newly overlapping extension until ownership is stable;
//   - a merged participant (the operation's creator, or a request resuming
//     after an unwind) uses the gate-entry rule over the operation's own scopes.
func (a *attach) activationBlockedLocked(participant *frontendOperationParticipant) bool {
	op := participant.op
	currentEpoch := a.frontendPathEpoch.Load()
	for scope := range a.frontendHandoffs {
		if participant.merged {
			if op.pathEpoch != currentEpoch || operationOverlapsScope(op.paths, scope) {
				return true
			}
			continue
		}
		newOverlaps := participant.pendingEpoch != currentEpoch ||
			operationOverlapsScope(participant.pendingPaths, scope)
		alreadyOwned := op.gateActive &&
			(op.pathEpoch != currentEpoch || operationOverlapsScope(op.paths, scope))
		if newOverlaps && !alreadyOwned {
			return true
		}
	}
	return false
}

func (a *attach) mergeParticipantPathsLocked(participant *frontendOperationParticipant) {
	if participant.merged {
		return
	}
	op := participant.op
	seen := make(map[string]struct{}, len(op.paths)+len(participant.pendingPaths))
	for _, path := range op.paths {
		seen[path] = struct{}{}
	}
	for _, path := range participant.pendingPaths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		op.paths = append(op.paths, path)
	}
	if op.pathEpoch != participant.pendingEpoch {
		// Zero cannot equal a real namespace epoch, so any later handoff
		// conservatively treats this logical operation as mount-wide.
		op.pathEpoch = 0
	}
	participant.merged = true
	participant.pendingPaths = nil
}

// tryActivateFrontendParticipant attempts, WITHOUT WAITING, to make a reserved
// participant a member of the active publication set. It is the only call the
// dispatcher makes with the frontend mirrors held.
//
// ok reports membership: true means the request may proceed to its handler.
// A nonpublishing participant is permanently suspended and reports true without
// ever joining the set.
func (a *attach) tryActivateFrontendParticipant(
	participant *frontendOperationParticipant,
) (ok bool, err error) {
	if participant == nil || participant.op == nil || participant.op.attach != a {
		return true, nil
	}
	if participant.nonpublishing {
		return true, nil
	}
	op := participant.op
	a.frontendGateMu.Lock()
	defer a.frontendGateMu.Unlock()
	a.initFrontendGateLocked()
	if op.completed {
		return false, net.ErrClosed
	}
	if participant.finished || participant.suspendDepth == 0 {
		// Already active (or retired); nothing to do.
		return true, nil
	}
	if participant.suspendDepth > 1 {
		// A nested suspend inside a handler owns the outer depth; it resumes
		// through its own closure, not here.
		participant.suspendDepth--
		return true, nil
	}
	if a.activationBlockedLocked(participant) {
		return false, nil
	}
	a.mergeParticipantPathsLocked(participant)
	participant.suspendDepth = 0
	if op.suspended > 0 {
		op.suspended--
	}
	if !op.gateActive {
		a.frontendActive[op] = struct{}{}
		op.gateActive = true
	}
	a.frontendGateCond.Broadcast()
	return true, nil
}

// awaitFrontendActivation waits, holding NO frontend mirror, until this
// participant's activation could succeed. It does not activate: the caller
// retakes the mirrors and reattempts, so the window between them is covered by
// the retry rather than by holding a lock across the wait.
func (a *attach) awaitFrontendActivation(
	ctx context.Context,
	participant *frontendOperationParticipant,
) error {
	if participant == nil || participant.op == nil ||
		participant.op.attach != a || participant.nonpublishing {
		return nil
	}
	op := participant.op
	a.frontendGateMu.Lock()
	defer a.frontendGateMu.Unlock()
	a.initFrontendGateLocked()
	stopWake := context.AfterFunc(ctx, func() {
		a.frontendGateMu.Lock()
		a.frontendGateCond.Broadcast()
		a.frontendGateMu.Unlock()
	})
	defer stopWake()
	for {
		if op.completed {
			return net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if participant.finished || participant.suspendDepth == 0 {
			return nil
		}
		if !a.activationBlockedLocked(participant) {
			return nil
		}
		a.frontendGateCond.Wait()
	}
}

// suspendFrontendParticipant returns an ACTIVE participant to the reserved,
// suspended state. The ErrLaneChanged unwind uses it so the second pass's
// claim and delegation release are paid exactly where the first pass's were:
// holding nothing, out of the publication set.
func (a *attach) suspendFrontendParticipant(participant *frontendOperationParticipant) {
	if participant == nil || participant.op == nil ||
		participant.op.attach != a || participant.nonpublishing {
		return
	}
	op := participant.op
	a.frontendGateMu.Lock()
	if !op.completed && !participant.finished && participant.suspendDepth == 0 {
		participant.suspendDepth = 1
		op.suspended++
		a.retractIdleOperationLocked(op)
		a.frontendGateCond.Broadcast()
	}
	a.frontendGateMu.Unlock()
}

// joinFrontendOperationSuspended admits a NONPUBLISHING request into an
// already active logical FSKit callback without ever making it a member of
// the active publication set.
//
// close(2) is the motivating case. FSKit lets one framework callback issue
// several daemon requests, and the pfslocal client shares that callback's
// operation ID with every one of them — including requests that publish
// nothing. Admitting those as ordinary participants coupled them to
// delegation handoffs in both directions: they blocked handoffs while active,
// and the resume half of suspendFrontendOperation held them until every
// overlapping handoff ended. A handoff spans the release's authority round
// trips, so with a slow or dead uplink that wait is unbounded and a close(2)
// with an admitted write-back backlog stalls behind its own scope's drain.
//
// A request that cannot publish cacheable state has nothing to keep coherent,
// so it enters already suspended and stays that way for its whole lifetime.
// It still counts as a participant, which is what prevents a recall that owns
// a namespace mirror lock from deadlocking against the operation it is
// waiting to publish, and finishFrontendParticipant retires both counters.
func (a *attach) joinFrontendOperationSuspended(
	op *frontendOperation,
) (*frontendOperationParticipant, error) {
	if op == nil || op.attach != a {
		return nil, fmt.Errorf("portablefsd: invalid logical frontend operation")
	}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	if op.completed {
		a.frontendGateMu.Unlock()
		return nil, net.ErrClosed
	}
	op.participants++
	op.suspended++
	a.retractIdleOperationLocked(op)
	a.frontendGateCond.Broadcast()
	a.frontendGateMu.Unlock()
	return &frontendOperationParticipant{
		op:            op,
		suspendDepth:  1,
		nonpublishing: true,
	}, nil
}

func (a *attach) finishFrontendOperation(op *frontendOperation) {
	if op == nil {
		return
	}
	a.frontendGateMu.Lock()
	if !op.completed {
		op.completed = true
		if op.gateActive {
			a.retractFromPublicationSetLocked(op)
			op.gateActive = false
		}
		if a.frontendGateCond != nil {
			a.frontendGateCond.Broadcast()
		}
	}
	a.frontendGateMu.Unlock()
}

func (a *attach) finishFrontendParticipant(participant *frontendOperationParticipant) {
	if participant == nil || participant.op == nil || participant.op.attach != a {
		return
	}
	a.frontendGateMu.Lock()
	if participant.finished {
		a.frontendGateMu.Unlock()
		return
	}
	participant.finished = true
	op := participant.op
	if participant.suspendDepth > 0 {
		participant.suspendDepth = 0
		if op.suspended > 0 {
			op.suspended--
		}
	}
	if op.participants > 0 {
		op.participants--
	}
	a.retractIdleOperationLocked(op)
	a.frontendGateCond.Broadcast()
	a.frontendGateMu.Unlock()
}

// frontendRequestPublishes is the Go-side copy of the frozen pfslocal
// publication classification. These requests may install namespace,
// metadata, xattr, or content state in a frontend cache and therefore require
// a logical operation ID and one post-callback acknowledgement.
func frontendRequestPublishes(body any) bool {
	switch body.(type) {
	case *pfslocal.LookupRequest,
		*pfslocal.EnumerateRequest,
		*pfslocal.GetAttrRequest,
		*pfslocal.SetAttrRequest,
		*pfslocal.ReadRequest,
		*pfslocal.WriteRequest,
		*pfslocal.CreateRequest,
		*pfslocal.MkdirRequest,
		*pfslocal.RemoveRequest,
		*pfslocal.RenameRequest,
		*pfslocal.SymlinkRequest,
		*pfslocal.ReadlinkRequest,
		*pfslocal.HardLinkRequest,
		*pfslocal.XattrGetRequest,
		*pfslocal.XattrSetRequest,
		*pfslocal.XattrListRequest,
		*pfslocal.XattrRemoveRequest:
		return true
	default:
		return false
	}
}

// frontendRequestIsOrderedMutation is the daemon-side validation boundary for
// Envelope.SourcePhaseQueueable. Only requests the authority executes through
// its visibility coordinator may carry that progress proof. Keeping the list
// beside frontendRequestPublishes makes wire admission and the v3 data-plane
// mutation switch share one explicit contract.
func frontendRequestIsOrderedMutation(body any) bool {
	switch body.(type) {
	case *pfslocal.SetAttrRequest,
		*pfslocal.WriteRequest,
		*pfslocal.CreateRequest,
		*pfslocal.MkdirRequest,
		*pfslocal.RemoveRequest,
		*pfslocal.RenameRequest,
		*pfslocal.SymlinkRequest,
		*pfslocal.HardLinkRequest,
		*pfslocal.XattrSetRequest,
		*pfslocal.XattrRemoveRequest:
		return true
	default:
		return false
	}
}

func validFrontendSourcePhaseQueueability(
	body any,
	operationID uint64,
	sourcePhaseQueueable bool,
) bool {
	return !sourcePhaseQueueable ||
		(operationID != 0 && frontendRequestIsOrderedMutation(body))
}

// frontendOperationPaths derives the publication SCOPE of one frontend
// request: which paths a reply to it may install cacheable state under.
//
// An authority-v3 attach keeps no daemon-side path registry — the v3 data
// plane binds items to authority handles, and the daemon never learns a
// pathname it could narrow a scope to (see v3dataplane.go). So every
// publishing request takes the conservative mount-wide scope, spelled as the
// root path, and every non-publishing one takes none. The path epoch still
// rides along so an operation's scope snapshot is comparable at handoff.
func (a *attach) frontendOperationPaths(body any) ([]string, uint64, bool) {
	pathEpoch := a.frontendPathEpoch.Load()
	if !frontendRequestPublishes(body) {
		// Open/close/fsync/sync/statfs/reclaim/event operations do not
		// publish namespace, metadata, xattr, or content cache state.
		return nil, pathEpoch, false
	}
	return []string{""}, pathEpoch, true
}

func pathWithinScope(p, scope string) bool {
	return scope == "" || p == scope || strings.HasPrefix(p, scope+"/")
}
