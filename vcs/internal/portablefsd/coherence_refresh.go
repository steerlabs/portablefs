package portablefsd

// Remote-change coherence for live kernel vnodes (macOS FSKit).
//
// macOS UserFS models single-writer media: a live vnode's SIZE is set when
// the kernel first materializes it and is updated only by local write and
// setattr paths — never by getattr (stat refreshes, reads stay capped at the
// stale EOF, mmap zero-fills past it), and FSKit gives the extension no
// invalidation API. The kernel also pins name->item bindings: answering
// ENOENT or ESTALE for a retired item wedges the path until remount, so
// identity rebinding is not an option either (both proven empirically).
//
// The two levers that DO work, both kernel-sanctioned and driveable by the
// unsandboxed daemon through its own mount:
//
//   - ftruncate(2) on a descriptor securely resolved beneath the mount is a
//     VNOP_SETATTR: on success the kernel adopts the new size for the vnode.
//     The daemon truncates to the AUTHORITATIVE size and its own setattr
//     handler consumes the marked request without touching the authority — a
//     pure kernel-state refresh.
//   - msync(MS_INVALIDATE) over a shared mapping is the POSIX contract for
//     "discard cached copies": it drops the stale pages so the next read
//     faults through the extension to the daemon.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// expectedTruncate marks one kernel-size refresh the daemon is issuing through
// its own mount, so the setattr handler can recognise the resulting FSKit
// upcall as coherence bookkeeping instead of an application truncate.
//
// The distinction is the whole point, and it must be a fact about PROVENANCE,
// never about elapsed time. A daemon-originated refresh and a user truncate to
// the same size are byte-identical on the wire; the only thing that separates
// them is that this process issued one of them and is still inside the
// ftruncate(2) that produced it. So the marker is PINNED for exactly that
// window (see pinned below) and is retired by the refresh that installed it.
type expectedTruncate struct {
	itemID uint64
	size   int64
	// pinned is true for the whole of the daemon's own synchronous ftruncate.
	//
	// ftruncate(2) is synchronous with its VNOP_SETATTR upcall, but the upcall
	// is not synchronous with the daemon's ANSWER to it: the request travels the
	// frontend dispatcher, where metadata-lane backpressure can pace it for up
	// to a full admission budget. A wall-clock TTL therefore decided the
	// question "is this the daemon's own refresh?" using a quantity that has
	// nothing to do with provenance — and when admission outran the TTL the
	// handler reclassified the daemon's own no-op as an APPLICATION truncate and
	// sent it to the authority, destroying every byte a concurrent local write
	// had appended past the sampled size.
	//
	// While pinned, the marker's validity is exactly "the refresh that installed
	// it has not returned yet", which is the true statement, is unforgeable by
	// anything outside applyKernelRefresh, and cannot be outrun by any amount of
	// admission latency.
	pinned bool
	// deadline bounds an UNPINNED marker only. No marker should ever be found
	// unpinned — applyKernelRefresh retires its own on every exit path — so this
	// is a sweeper for a marker that outlived its refresh through a path that
	// does not exist today, never the primary decision.
	deadline time.Time
	// seq identifies this exact marker, so the refresh that installed it retires
	// that one and not a successor installed for the same path in between.
	seq uint64
}

const (
	// refreshCoalesce absorbs a burst of remote-write invalidations for one
	// file into a single kernel refresh.
	refreshCoalesce = 25 * time.Millisecond
	// staleSampleRetries bounds how long a refresh waits for the authority
	// sample to catch up with state the daemon has already seen (see
	// refreshLocalSample). 40 × refreshCoalesce ≈ 1s, comfortably past a flush.
	staleSampleRetries = 40
)

// truncateNoteTTL is the sweeper bound on an UNPINNED marker. The pin (see
// expectedTruncate.pinned) is what actually decides whether a request is the
// daemon's own refresh; this only stops a marker that somehow outlived its
// refresh from lingering. An application truncate to the exact same (already
// current) size inside a pinned window is answered locally as a no-op — its
// only observable loss is an mtime bump the remote edit has already superseded
// — and, crucially, it does NOT consume the window: provenance belongs to the
// refresh that opened it, not to whichever request matches it first (see
// refreshWindowOpenLocked).
//
// A var so failure-shape tests can compress it and drive the case where a
// request's admission outlasts the TTL; production never changes it.
var truncateNoteTTL = 5 * time.Second

type refreshSampleOutcome uint8

const (
	refreshSampleRetry refreshSampleOutcome = iota
	// refreshSampleTerminal means the sampled name is absent. An ordinary
	// namespace-local refresh may settle that transition, but an
	// identity-required refresh must keep the barrier closed: another name
	// may still expose the exact regular-file inode whose vnode needs its
	// pages refreshed.
	refreshSampleTerminal
	// refreshSampleNonRegular means the sampled name resolved successfully
	// to the expected identity, but that identity is not a regular file.
	// Directories and symlinks have no regular-file page cache to truncate or
	// invalidate, so this is a proved, successful exact-refresh outcome.
	refreshSampleNonRegular
	// refreshSampleObsolete means the sampled name resolves to a different
	// authority inode than the frontend Item being refreshed. Its size must
	// never be applied to that Item's cached vnode.
	refreshSampleObsolete
	refreshSampleReady
)

type kernelRefreshOutcome uint8

const (
	kernelRefreshApplied kernelRefreshOutcome = iota
	// kernelRefreshObsolete means the scheduled name no longer resolves to
	// the expected regular-file identity. Namespace coherence owns that
	// transition; retrying the retired binding would be incorrect.
	kernelRefreshObsolete
	// kernelRefreshRetry means the expected binding may still be live but a
	// syscall did not complete. Ordinary convergence retries it, while an
	// exact delegation handoff fails closed before Checkin.
	kernelRefreshRetry
)

// refreshKernelItemStateComposed pushes the current composed size into the
// kernel vnode via a marked no-op truncate, then drops the vnode's cached
// pages. It reports whether the pass left the kernel on the settled state;
// false means the bounded exact transaction must run another pass. The
// refresh truncate races application writes traveling through the same
// kernel: a local write can land between the sample and the truncate — its
// own echo is invalidation-suppressed, so without the post-apply verify the
// clamp would wedge the kernel on the superseded sample forever. Verifying
// both the composed size and shared-lane authority version makes the caller
// converge on the final state instead.
func (a *attach) refreshKernelItemStateComposed(mount string, itemID uint64) bool {
	return a.refreshKernelItemStateComposedModeContext(
		context.Background(), mount, itemID, true,
	)
}

func (a *attach) refreshKernelItemStateComposedMode(
	mount string,
	itemID uint64,
	requireAuthorityIdentity bool,
) bool {
	return a.refreshKernelItemStateComposedModeContext(
		context.Background(), mount, itemID, requireAuthorityIdentity,
	)
}

func (a *attach) refreshKernelItemStateComposedModeContext(
	ctx context.Context,
	mount string,
	itemID uint64,
	requireAuthorityIdentity bool,
) bool {
	vol, eno := a.volOrErr()
	if eno != 0 {
		return false
	}
	a.mu.RLock()
	rec := a.items[itemID]
	if rec != nil {
		p := rec.path
		rec = &itemRecord{
			item: rec.item, path: p, state: rec.state, attr: rec.attr, graft: rec.graft,
		}
	}
	a.mu.RUnlock()
	if rec == nil {
		return true
	}
	p := rec.path
	var authorityIno uint64
	if rec.state != nil {
		authorityIno = rec.state.AuthorityIno()
	}
	sample := func() (int64, uint64, uint64, refreshSampleOutcome) {
		if a.localDirFor(p) != "" {
			return a.refreshGraftSample(rec)
		}
		return refreshLocalSampleAuthorityContext(ctx, vol, p, authorityIno)
	}
	size, version, generation, outcome := sample()
	switch outcome {
	case refreshSampleTerminal:
		if requireAuthorityIdentity {
			return false
		}
		if a.frontendItemMoved(rec.item, p) {
			return false
		}
		return true // gone or non-file: namespace handling owns convergence
	case refreshSampleNonRegular:
		return true
	case refreshSampleObsolete:
		// Namespace replacement owns an ordinary stale-name transition, but
		// a RelatedInos refresh is an explicit claim that this exact inode is
		// live somewhere. It cannot settle until a matching alias is known.
		return a.obsoleteRefreshSettled(rec.item, p, requireAuthorityIdentity)
	case refreshSampleRetry:
		return false
	}
	applyOutcome, _ := a.applyKernelRefresh(mount, p, rec, size)
	if applyOutcome != kernelRefreshApplied {
		if applyOutcome == kernelRefreshRetry {
			return false
		}
		if a.frontendItemMoved(rec.item, p) {
			return false
		}
		return true
	}
	afterSize, afterVersion, afterGeneration, afterOutcome := sample()
	switch afterOutcome {
	case refreshSampleTerminal:
		if requireAuthorityIdentity {
			return false
		}
		if a.frontendItemMoved(rec.item, p) {
			return false
		}
		return true
	case refreshSampleNonRegular:
		return true
	case refreshSampleObsolete:
		return a.obsoleteRefreshSettled(rec.item, p, requireAuthorityIdentity)
	case refreshSampleRetry:
		// Never declare a raced marked truncate settled when its verification
		// sample failed transiently. Own-write echoes may be suppressed, so
		// this worker is the only convergence trigger.
		return false
	}
	if afterSize != size {
		return false
	}
	return refreshSamplesSettled(version, generation, afterVersion, afterGeneration)
}

func (a *attach) obsoleteRefreshSettled(
	item pfslocal.Item,
	sampledPath string,
	requireAuthorityIdentity bool,
) bool {
	return !requireAuthorityIdentity && !a.frontendItemMoved(item, sampledPath)
}

// refreshGraftSample resolves an exact local-dir Item through the confined
// backing root. Grafts shadow the authority by definition, so sampling the
// remote Volume would either false-freeze on ENOENT or, worse, apply the size
// of a different shadowed inode to this vnode.
func (a *attach) refreshGraftSample(rec *itemRecord) (int64, uint64, uint64, refreshSampleOutcome) {
	if rec == nil {
		return 0, 0, 0, refreshSampleTerminal
	}
	a.mu.RLock()
	current := a.items[rec.item.ItemID]
	bound := a.paths[rec.path]
	live := current != nil &&
		current.item.ItemGeneration == rec.item.ItemGeneration &&
		bound != nil && bound.item == rec.item
	a.mu.RUnlock()
	if !live {
		return 0, 0, 0, refreshSampleTerminal
	}
	attr, eno := a.statLocal(rec.path)
	if eno != 0 {
		if eno == darwinENOENT || eno == darwinENOTDIR {
			return 0, 0, 0, refreshSampleTerminal
		}
		return 0, 0, 0, refreshSampleRetry
	}
	if attr.Kind != "file" {
		return 0, 0, 0, refreshSampleNonRegular
	}
	a.mu.RLock()
	current = a.items[rec.item.ItemID]
	bound = a.paths[rec.path]
	live = current != nil &&
		current.item.ItemGeneration == rec.item.ItemGeneration &&
		bound != nil && bound.item == rec.item
	a.mu.RUnlock()
	if !live {
		return 0, 0, 0, refreshSampleRetry
	}
	return attr.Size, 0, 0, refreshSampleReady
}

func (a *attach) frontendItemMoved(item pfslocal.Item, sampledPath string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	current := a.items[item.ItemID]
	return current != nil &&
		current.item.ItemGeneration == item.ItemGeneration &&
		current.path != sampledPath
}

func refreshSamplesSettled(version, generation, afterVersion, afterGeneration uint64) bool {
	if generation == 0 || afterGeneration == 0 {
		return generation == 0 && afterGeneration == 0
	}
	if generation != afterGeneration {
		return false
	}
	if version == 0 || afterVersion == 0 {
		return version == 0 && afterVersion == 0
	}
	return afterVersion <= version
}

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

func (a *attach) applyKernelRefresh(mount, p string, rec *itemRecord, size int64) (kernelRefreshOutcome, error) {
	expectedKernelItemID, ok := fskitItemID(rec.item.ItemID)
	if !ok {
		return kernelRefreshRetry, fmt.Errorf(
			"portablefsd: item %d cannot be represented by FSKit",
			rec.item.ItemID,
		)
	}
	a.mu.Lock()
	if a.expectedTruncates == nil {
		a.expectedTruncates = map[string]expectedTruncate{}
	}
	a.expectedTruncateSeq++
	// PINNED from here until the ftruncate below returns. That window is the
	// exact extent of the daemon's own syscall, and while it is open no amount
	// of admission latency in the frontend dispatcher can turn this request into
	// an application truncate (see expectedTruncate.pinned).
	note := expectedTruncate{
		itemID: rec.item.ItemID, size: size,
		pinned:   true,
		deadline: time.Now().Add(truncateNoteTTL),
		seq:      a.expectedTruncateSeq,
	}
	if current := a.items[rec.item.ItemID]; current != nil &&
		current.item.ItemGeneration == rec.item.ItemGeneration {
		current.attr.Size = size
	}
	a.expectedTruncates[p] = note
	a.mu.Unlock()
	refresh := refreshKernelFile
	if a.testRefreshKernelFile != nil {
		refresh = a.testRefreshKernelFile
	}
	outcome, err := refresh(mount, p, expectedKernelItemID, size)
	// The syscall has returned, so the pin's premise no longer holds. If the
	// setattr callback did not consume this exact note (for example, the vnode
	// size already matched and only page invalidation was needed), retire it
	// now; a later application truncate must never match a stale daemon marker.
	// Identity is the sequence number, so a successor installed for the same
	// path by a concurrent pass is never retired by this one.
	a.retireExpectedTruncate(p, note.seq)
	if outcome != kernelRefreshApplied {
		// A failed safe-open means the name disappeared, changed identity,
		// became a symlink, or is inaccessible. Do not spin on that stale
		// binding: namespace changes publish their own invalidations and the
		// next path resolution or content invalidation schedules the current
		// FSItem. Retrying this obsolete item would be both wasteful and
		// incorrect for a permanent rename-over.
		return outcome, err
	}
	return kernelRefreshApplied, nil
}

type frontendOperation struct {
	attach       *attach
	paths        []string
	pathEpoch    uint64
	gateActive   bool
	participants int
	suspended    int
	completed    bool
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

func (a *attach) beginFrontendPaths(ctx context.Context, paths []string) (context.Context, *frontendOperation) {
	return a.beginFrontendPathsAtEpoch(ctx, paths, a.frontendPathEpoch.Load())
}

func (a *attach) beginFrontendPathsAtEpoch(
	ctx context.Context,
	paths []string,
	pathEpoch uint64,
) (context.Context, *frontendOperation) {
	op, err := a.beginFrontendPathsAtEpochContext(ctx, paths, pathEpoch)
	if err != nil {
		return ctx, nil
	}
	participant := &frontendOperationParticipant{op: op}
	return context.WithValue(ctx, frontendOperationContextKey{}, participant), op
}

func (a *attach) beginFrontendPathsAtEpochContext(
	ctx context.Context,
	paths []string,
	pathEpoch uint64,
) (*frontendOperation, error) {
	op := &frontendOperation{attach: a, paths: paths, pathEpoch: pathEpoch}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	stopWake := context.AfterFunc(ctx, func() {
		a.frontendGateMu.Lock()
		a.frontendGateCond.Broadcast()
		a.frontendGateMu.Unlock()
	})
	defer stopWake()
	for {
		if err := ctx.Err(); err != nil {
			a.frontendGateMu.Unlock()
			return nil, err
		}
		blocked := false
		for scope := range a.frontendHandoffs {
			if op.pathEpoch != a.frontendPathEpoch.Load() ||
				operationOverlapsScope(paths, scope) {
				blocked = true
				break
			}
		}
		if !blocked {
			break
		}
		a.frontendGateCond.Wait()
	}
	a.frontendActive[op] = struct{}{}
	op.gateActive = true
	op.participants = 1
	a.frontendGateMu.Unlock()
	return op, nil
}

// ── THE PUBLICATION ACTIVATION PROTOCOL ─────────────────────────────────────
//
// Membership of the active publication set is acquired in two separable steps,
// and the split is the whole point:
//
//	RESERVE   (reserveFrontendOperation / reserveFrontendExtension)
//	          The request joins its logical operation SUSPENDED. It counts as
//	          a participant — so the operation is not finished while it runs,
//	          which is what keeps a recall holding a namespace mirror from
//	          deadlocking against the operation it is waiting to publish — but
//	          it is not a member of the active set, so it blocks no handoff and
//	          waits for none. Reservation waits for NOTHING and holds NOTHING.
//	          It happens BEFORE admission, so every admission callback (in
//	          particular the delegation release that reaches OnHandoffStart)
//	          carries this operation's identity and cannot wait on it.
//
//	ACTIVATE  (tryActivateFrontendParticipant / awaitFrontendActivation)
//	          Becoming a member is ATTEMPTED, never waited for, while the
//	          frontend mirrors are held. If a handoff owns an operand scope the
//	          attempt fails, the caller drops the mirrors, waits SUSPENDED for
//	          the gate to open, and retries.
//
// The discipline both halves enforce: no gate wait is ever paid with the
// frontend serialization lock, a name stripe or a per-handle gate held. Phase 2
// used to take the mirrors and then wait — for a handoff that spans a
// delegation release's authority round trips — so a write holding the per-handle
// frontend RLock blocked the close(2) that needs it exclusively and depends on
// nothing remote. It is the same unwind discipline ErrLaneChanged already obeys,
// applied to the publication gate.
//
// Liveness: a suspended participant is never a member of the active set, so a
// handoff waiting on the active set always makes progress while a reservation
// waits. Each retry can only be defeated by a NEW handoff starting in the
// window between the wait returning and the mirrors being retaken, and the
// operation deadline (phase 0) bounds the whole loop regardless.

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

// enterFrontendMirrors is phase 2, once, for every request.
//
// It takes the frontend mirrors and makes this request a member of the active
// publication set, and it does so in the only order that never waits under a
// mirror:
//
//	take the mirrors (this request is SUSPENDED, so it blocks no handoff)
//	ATTEMPT activation, nonblocking
//	if blocked: drop the mirrors, wait SUSPENDED, retry
//
// Taking the mirrors first is what makes this safe. The alternative — activate
// first, then take the mirrors — puts this request in the active publication
// set while it waits for a name stripe or a handle gate, so a handoff started
// by a recall that already holds a namespace mirror waits on this request while
// this request waits on that recall. Suspended-while-holding-mirrors closes that
// cycle: a handoff never waits on a suspended participant, so it always
// completes and always lets the retry through.
//
// The returned unlock is nil only when the request takes no mirrors at all.
func (a *attach) enterFrontendMirrors(
	ctx context.Context,
	body any,
	participant *frontendOperationParticipant,
) (func(), error) {
	for {
		unlockRequest := a.lockFrontendRequest(body)
		activated, err := a.tryActivateFrontendParticipant(participant)
		if err != nil {
			if unlockRequest != nil {
				unlockRequest()
			}
			return nil, err
		}
		if activated {
			return unlockRequest, nil
		}
		if unlockRequest != nil {
			unlockRequest()
		}
		if err := a.awaitFrontendActivation(ctx, participant); err != nil {
			return nil, err
		}
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
		if op.gateActive && op.participants > 0 && op.suspended == op.participants {
			delete(a.frontendActive, op)
			op.gateActive = false
		}
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
	if op.gateActive && op.participants > 0 && op.suspended == op.participants {
		delete(a.frontendActive, op)
		op.gateActive = false
	}
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
			delete(a.frontendActive, op)
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
	if !op.completed && op.gateActive &&
		op.participants > 0 && op.suspended == op.participants {
		delete(a.frontendActive, op)
		op.gateActive = false
	}
	a.frontendGateCond.Broadcast()
	a.frontendGateMu.Unlock()
}

// suspendFrontendOperation moves a request that is about to wait for a
// delegation release out of the pre-handoff publication set. The operation
// itself runs only after that release, so its eventual reply belongs to the
// post-handoff view. Re-entry blocks until the release hook has reopened the
// overlapping scopes, preventing both self-deadlock and joined-waiter cycles.
func (a *attach) suspendFrontendOperation(ctx context.Context) func() {
	participant, ok := ctx.Value(frontendOperationContextKey{}).(*frontendOperationParticipant)
	if !ok || participant.op == nil || participant.op.attach != a {
		return nil
	}
	op := participant.op
	a.frontendGateMu.Lock()
	if !op.completed && !participant.finished {
		if participant.suspendDepth == 0 {
			op.suspended++
		}
		participant.suspendDepth++
	}
	if !op.completed && op.gateActive &&
		op.participants > 0 && op.suspended == op.participants {
		delete(a.frontendActive, op)
		op.gateActive = false
		a.frontendGateCond.Broadcast()
	}
	a.frontendGateMu.Unlock()
	resumed := false
	return func() {
		a.frontendGateMu.Lock()
		defer a.frontendGateMu.Unlock()
		if resumed {
			return
		}
		resumed = true
		stopWake := context.AfterFunc(ctx, func() {
			a.frontendGateMu.Lock()
			a.frontendGateCond.Broadcast()
			a.frontendGateMu.Unlock()
		})
		defer stopWake()
		if participant.finished || participant.suspendDepth == 0 {
			return
		}
		participant.suspendDepth--
		if participant.suspendDepth > 0 {
			return
		}
		if participant.nonpublishing {
			// A nonpublishing participant is suspended for its whole
			// lifetime and never re-enters the active publication set, so it
			// must never wait for an overlapping handoff to end.
			participant.suspendDepth = 1
			return
		}
		for !op.completed {
			if ctx.Err() != nil {
				if op.suspended > 0 {
					op.suspended--
				}
				a.frontendGateCond.Broadcast()
				return
			}
			blocked := false
			for scope := range a.frontendHandoffs {
				if op.pathEpoch != a.frontendPathEpoch.Load() ||
					operationOverlapsScope(op.paths, scope) {
					blocked = true
					break
				}
			}
			if !blocked {
				if op.suspended > 0 {
					op.suspended--
				}
				if !op.gateActive {
					a.frontendActive[op] = struct{}{}
					op.gateActive = true
				}
				a.frontendGateCond.Broadcast()
				return
			}
			a.frontendGateCond.Wait()
		}
	}
}

func (a *attach) startFrontendHandoff(ctx context.Context, scope string) error {
	var own *frontendOperation
	if participant, ok := ctx.Value(frontendOperationContextKey{}).(*frontendOperationParticipant); ok &&
		participant.op != nil && participant.op.attach == a {
		own = participant.op
	}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	if a.frontendGateErr != nil {
		err := a.frontendGateErr
		a.frontendGateMu.Unlock()
		return err
	}
	stopWake := context.AfterFunc(ctx, func() {
		a.frontendGateMu.Lock()
		a.frontendGateCond.Broadcast()
		a.frontendGateMu.Unlock()
	})
	defer stopWake()
	for {
		if a.frontendGateErr != nil {
			err := a.frontendGateErr
			a.frontendGateMu.Unlock()
			return err
		}
		if err := ctx.Err(); err != nil {
			a.frontendGateMu.Unlock()
			return err
		}
		overlap := false
		for activeScope := range a.frontendHandoffs {
			if scopesOverlap(activeScope, scope) {
				overlap = true
				break
			}
		}
		if !overlap {
			break
		}
		a.frontendGateCond.Wait()
	}
	a.frontendHandoffs[scope]++
	removeHandoff := func() {
		if a.frontendHandoffs[scope] <= 1 {
			delete(a.frontendHandoffs, scope)
		} else {
			a.frontendHandoffs[scope]--
		}
		a.frontendGateCond.Broadcast()
	}
	for {
		if a.frontendGateErr != nil {
			err := a.frontendGateErr
			removeHandoff()
			a.frontendGateMu.Unlock()
			return err
		}
		if err := ctx.Err(); err != nil {
			removeHandoff()
			a.frontendGateMu.Unlock()
			return err
		}
		blocked := false
		for op := range a.frontendActive {
			if op != own &&
				(op.pathEpoch != a.frontendPathEpoch.Load() ||
					operationOverlapsScope(op.paths, scope)) {
				blocked = true
				break
			}
		}
		if !blocked {
			break
		}
		a.frontendGateCond.Wait()
	}
	a.frontendGateMu.Unlock()
	return nil
}

func (a *attach) endFrontendHandoff(scope string) {
	a.frontendGateMu.Lock()
	if a.frontendHandoffs[scope] <= 1 {
		delete(a.frontendHandoffs, scope)
	} else {
		a.frontendHandoffs[scope]--
	}
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

func (a *attach) frontendOperationPaths(body any) ([]string, uint64, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	pathEpoch := a.frontendPathEpoch.Load()
	itemPath := func(item pfslocal.Item) (string, bool) {
		rec := a.items[item.ItemID]
		if rec == nil || rec.item.ItemGeneration != item.ItemGeneration {
			return "", false
		}
		return rec.path, true
	}
	itemPaths := func(item pfslocal.Item) ([]string, bool) {
		rec := a.items[item.ItemID]
		if rec == nil || rec.item.ItemGeneration != item.ItemGeneration {
			return nil, false
		}
		aliases := a.itemAliases[item.ItemID]
		paths := make([]string, 0, len(aliases))
		for path := range aliases {
			paths = append(paths, path)
		}
		return paths, len(paths) != 0
	}
	handlePaths := func(handle uint64) ([]string, bool) {
		rec := a.handles[handle]
		if rec == nil {
			return nil, false
		}
		if rec.itemID == 0 {
			return []string{rec.path}, true
		}
		aliases := a.itemAliases[rec.itemID]
		paths := make([]string, 0, len(aliases))
		for path := range aliases {
			paths = append(paths, path)
		}
		if len(paths) == 0 {
			// The retained path on an unlinked or overwritten open handle is
			// only an authority addressing hint. It may now name another
			// inode, so treating it as publication scope would let a detached
			// write cross a handoff for a real replacement. Unknown is the
			// exact conservative scope until a genuine alias is discovered.
			paths = append(paths, "")
		}
		return paths, true
	}
	child := func(dir pfslocal.Item, name []byte) (string, string, bool) {
		parent, ok := itemPath(dir)
		if !ok {
			return "", "", false
		}
		path, eno := cleanChild(parent, name)
		return parent, path, eno == 0
	}
	known := func(paths ...string) ([]string, uint64, bool) {
		return paths, pathEpoch, true
	}
	knownSlice := func(paths []string) ([]string, uint64, bool) {
		return paths, pathEpoch, true
	}
	// unknown is the conservative mount-wide scope: a request whose
	// publication target cannot be resolved from the current bindings (a
	// stale Item generation, an unresolvable child name, a handle with no
	// live alias) and the per-inode read publishers (Lookup, Enumerate)
	// whose path-narrowed scopes would race already-passed handoffs of
	// hard-link aliases.
	unknown := func() ([]string, uint64, bool) { return []string{""}, pathEpoch, true }
	withKnownAliases := func(paths []string, candidates ...string) []string {
		seen := make(map[string]struct{}, len(paths))
		for _, path := range paths {
			seen[path] = struct{}{}
		}
		for _, candidate := range candidates {
			rec := a.paths[candidate]
			if rec == nil {
				continue
			}
			for alias := range a.itemAliases[rec.item.ItemID] {
				if _, ok := seen[alias]; ok {
					continue
				}
				seen[alias] = struct{}{}
				paths = append(paths, alias)
			}
		}
		return paths
	}

	switch req := body.(type) {
	case *pfslocal.LookupRequest:
		// Deliberately mount-wide, NOT the looked-up name. A lookup (and a
		// readdir-plus page) publishes per-INODE attributes obtained through a
		// per-PATH delegation, and a hard link can alias that inode under a
		// scope whose handoff has ALREADY passed this gate — a passed handoff
		// cannot be re-blocked, so a path-narrowed scope here can publish a
		// pre-handoff view of an inode the new delegation holder believes is
		// exclusively theirs. The path epoch only widens operations that
		// install NEW bindings; it cannot protect aliases that were already
		// known. Until an inode-identity gate exists that both handoffs and
		// reply publication join, these two read publishers stay mount-wide.
		return unknown()
	case *pfslocal.EnumerateRequest:
		// Mount-wide for the same inode-aliasing reason as Lookup: a
		// readdir-plus page publishes child attributes, and any child can be
		// hard-linked under an already-handed-off scope.
		return unknown()
	case *pfslocal.GetAttrRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.SetAttrRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.ReadRequest:
		paths, ok := handlePaths(req.Handle)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.WriteRequest:
		paths, ok := handlePaths(req.Handle)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.CreateRequest:
		parent, path, ok := child(req.Dir, req.Name)
		if !ok {
			return unknown()
		}
		return known(parent, path)
	case *pfslocal.MkdirRequest:
		parent, path, ok := child(req.Dir, req.Name)
		if !ok {
			return unknown()
		}
		return known(parent, path)
	case *pfslocal.RemoveRequest:
		parent, path, ok := child(req.Dir, req.Name)
		if !ok {
			return unknown()
		}
		return knownSlice(withKnownAliases([]string{parent, path}, path))
	case *pfslocal.RenameRequest:
		fromParent, from, fromOK := child(req.FromDir, req.FromName)
		toParent, to, toOK := child(req.ToDir, req.ToName)
		if !fromOK || !toOK {
			return unknown()
		}
		return knownSlice(withKnownAliases(
			[]string{fromParent, from, toParent, to},
			from,
			to,
		))
	case *pfslocal.SymlinkRequest:
		parent, path, ok := child(req.Dir, req.Name)
		if !ok {
			return unknown()
		}
		return known(parent, path)
	case *pfslocal.ReadlinkRequest:
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.HardLinkRequest:
		sources, sourceOK := itemPaths(req.Item)
		parent, path, targetOK := child(req.Dir, req.Name)
		if !sourceOK || !targetOK {
			return unknown()
		}
		return known(append(sources, parent, path)...)
	case *pfslocal.XattrGetRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.XattrSetRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.XattrListRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.XattrRemoveRequest:
		if req.Handle != 0 {
			paths, ok := handlePaths(req.Handle)
			if !ok {
				return unknown()
			}
			return knownSlice(paths)
		}
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	default:
		// Open/close/fsync/sync/statfs/reclaim/event operations do not
		// publish namespace, metadata, xattr, or content cache state.
		if frontendRequestPublishes(body) {
			return unknown()
		}
		return nil, pathEpoch, false
	}
}

func pathWithinScope(p, scope string) bool {
	return scope == "" || p == scope || strings.HasPrefix(p, scope+"/")
}

func (a *attach) refreshKernelItemExact(ctx context.Context, itemID uint64) error {
	return a.refreshKernelItemExactMode(ctx, itemID, true)
}

func (a *attach) refreshKernelItemExactMode(
	ctx context.Context,
	itemID uint64,
	requireAuthorityIdentity bool,
) error {
	// A concurrent application write can advance the composed view between
	// sample, marked truncate, and verification. Re-run that optimistic
	// transaction a bounded number of times; this is ordering against a live
	// writer, not recovery or a fallback. Failure to establish one stable
	// point fail-freezes the attach at the caller.
	for attempt := 0; attempt <= staleSampleRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("portablefsd: exact kernel refresh item %d: %w", itemID, err)
		}
		if a.refreshKernelItemStateComposedModeContext(
			ctx, a.mountPath, itemID, requireAuthorityIdentity,
		) {
			return nil
		}
		if attempt != staleSampleRetries {
			select {
			case <-ctx.Done():
				return fmt.Errorf("portablefsd: exact kernel refresh item %d: %w", itemID, ctx.Err())
			case <-time.After(refreshCoalesce):
			}
		}
	}
	return fmt.Errorf(
		"portablefsd: exact kernel refresh item %d did not converge after %d ordered attempts",
		itemID, staleSampleRetries+1,
	)
}

func (a *attach) exactKernelRefresh(ctx context.Context, itemID uint64) error {
	return a.exactKernelRefreshMode(ctx, itemID, true)
}

func (a *attach) exactKernelRefreshMode(
	ctx context.Context,
	itemID uint64,
	requireAuthorityIdentity bool,
) error {
	release, err := a.acquireKernelRefreshGate(ctx, itemID)
	if err != nil {
		return err
	}
	defer release()
	if a.testExactKernelRefresh != nil {
		return a.testExactKernelRefresh(ctx, itemID)
	}
	return a.refreshKernelItemExactMode(ctx, itemID, requireAuthorityIdentity)
}

func (a *attach) acquireKernelRefreshGate(
	ctx context.Context,
	itemID uint64,
) (func(), error) {
	stripe := itemID & 63
	a.kernelRefreshGateMu.Lock()
	gate := a.kernelRefreshGates[stripe]
	if gate == nil {
		gate = make(chan struct{}, 1)
		gate <- struct{}{}
		a.kernelRefreshGates[stripe] = gate
	}
	a.kernelRefreshGateMu.Unlock()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"portablefsd: exact kernel refresh item %d gate: %w", itemID, ctx.Err(),
		)
	case <-gate:
		return func() { gate <- struct{}{} }, nil
	}
}

// refreshLocalSample reads the exact composed size for p. It keeps the
// version-floor guard on the shared lane and returns immediately for
// a delegated overlay sample (version zero), whose read permit already fenced
// the release handoff.
func refreshLocalSample(vol *clientcore.Volume, p string) (size int64, version uint64, generation uint64, outcome refreshSampleOutcome) {
	return refreshLocalSampleAuthority(vol, p, 0)
}

func refreshLocalSampleAuthority(
	vol *clientcore.Volume,
	p string,
	expectedAuthorityIno uint64,
) (size int64, version uint64, generation uint64, outcome refreshSampleOutcome) {
	return refreshLocalSampleAuthorityContext(
		context.Background(), vol, p, expectedAuthorityIno,
	)
}

func refreshLocalSampleAuthorityContext(
	ctx context.Context,
	vol *clientcore.Volume,
	p string,
	expectedAuthorityIno uint64,
) (size int64, version uint64, generation uint64, outcome refreshSampleOutcome) {
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return 0, 0, 0, refreshSampleRetry
		}
		attr, ver, gen, st := vol.CoherenceSample(ctx, p)
		if st != fsproto.OK {
			if st == fsproto.ENOENT || st == fsproto.ENOTDIR {
				return 0, 0, 0, refreshSampleTerminal
			}
			return 0, 0, 0, refreshSampleRetry
		}
		// Only regular files have kernel content pages and a size that may
		// safely be refreshed. In particular, never drive truncate through a
		// symlink: its target may name a host path.
		if expectedAuthorityIno != 0 && attr.Ino != expectedAuthorityIno {
			return 0, 0, 0, refreshSampleObsolete
		}
		if attr.Kind != "file" {
			return 0, 0, 0, refreshSampleNonRegular
		}
		knownGen, knownVer := vol.VersionCache.GenAndVersion(p)
		if ver == 0 && gen == 0 {
			return attr.Size, 0, 0, refreshSampleReady
		}
		if gen != 0 && gen == knownGen && ver >= knownVer {
			return attr.Size, ver, gen, refreshSampleReady
		}
		if attempt >= staleSampleRetries {
			return 0, 0, 0, refreshSampleRetry
		}
		select {
		case <-ctx.Done():
			return 0, 0, 0, refreshSampleRetry
		case <-time.After(refreshCoalesce):
		}
	}
}

// retireExpectedTruncate removes the marker installed under seq, if it is still
// the marker bound to p. Identity is the sequence number: a successor installed
// for the same path by a concurrent refresh pass belongs to that pass.
func (a *attach) retireExpectedTruncate(p string, seq uint64) {
	a.mu.Lock()
	if current, exists := a.expectedTruncates[p]; exists && current.seq == seq {
		delete(a.expectedTruncates, p)
	}
	a.mu.Unlock()
}

// expectedTruncateLive reports whether note is still a valid claim of
// daemon provenance at now.
//
// A PINNED note is valid unconditionally: the refresh that installed it has not
// returned, so the request being classified against it can only be that
// refresh's own upcall. Elapsed time says nothing about provenance and must
// never be allowed to overrule it — that reinterpretation is exactly how an
// internal refresh became a real truncate of a file another writer had extended.
func expectedTruncateLive(note expectedTruncate, now time.Time) bool {
	return note.pinned || now.Before(note.deadline)
}

// matchesExpectedTruncate reports whether req is a pure size set that could be
// the daemon's own refresh. Anything touching mode, ownership or flags is a
// real application setattr: the daemon's refresh never carries one.
func matchesExpectedTruncate(req *pfslocal.SetAttrRequest) bool {
	// SetFlags disqualifies the request like any other real attribute group:
	// the daemon's own refresh never carries one, so a request that does is a
	// genuine chflags whose intent must not be swallowed by the no-op arm.
	return req.Size != nil && req.Mode == nil && req.UID == nil &&
		req.GID == nil && !req.SetFlags
}

// refreshWindowOpenLocked reports whether an (itemID, size) size-set falls
// inside a PINNED refresh window this daemon is executing right now.
//
// It is THE provenance predicate, and it is deliberately the only one. Both
// call sites — admission (internalRefreshPending) and the setattr handler
// (consumeExpectedTruncate) — ask it the same question and must get the same
// answer for the same request, because a request one of them calls daemon
// bookkeeping and the other calls an application mutation is precisely how a
// refresh becomes a data-destroying truncate.
//
// It CONSUMES NOTHING. Provenance is a property of the open window, never a
// token some other request can spend: a marker was a single-use token once,
// and an application ftruncate to the same item and the same size — byte
// identical on the wire, reaching the dispatcher first, possibly through a
// hard-link alias — could spend it. The daemon's own upcall then arrived
// markerless, was classified as an application mutation, and truncated
// whatever a concurrent write had appended past the sampled size. While the
// window is open EVERY matching size-set is answered locally; the marker is
// retired only by the refresh that installed it (retireExpectedTruncate, by
// seq), on every exit path of applyKernelRefresh.
//
// The accepted cost is unchanged and already documented on truncateNoteTTL: an
// application truncate to the already-current size inside the window is
// answered as a no-op, losing only an mtime bump the remote edit has superseded.
// A truncate to any OTHER size, or one carrying a real attribute group, does
// not match the window and reaches the authority as it must.
func (a *attach) refreshWindowOpenLocked(itemID uint64, size int64) bool {
	for _, note := range a.expectedTruncates {
		if note.pinned && note.itemID == itemID && note.size == size {
			return true
		}
	}
	return false
}

// internalRefreshPending answers, WITHOUT consuming anything, whether body is
// the upcall of a kernel-state refresh this daemon is issuing right now.
//
// It is the dispatcher's provenance test. A daemon-originated refresh is
// coherence bookkeeping, not an application mutation: it publishes state the
// authority has ALREADY applied, it is consumed by the setattr handler and never
// reaches the authority, and it appends nothing to the write-back stream. Pacing
// it against the metadata lane therefore throttles an operation that is not
// responsible for the backlog and cannot help drain it — the same argument that
// keeps the authority lane off the credit ledger — and, worse, the pacing delay
// is precisely what used to let the marker's meaning change underneath it.
//
// The predicate is unforgeable in the only sense that matters: the markers it
// reads are installed exclusively by applyKernelRefresh, only for the duration
// of its own syscall, and a request that matches one is by construction a
// request this daemon is about to answer locally.
func (a *attach) internalRefreshPending(body any) bool {
	req, ok := body.(*pfslocal.SetAttrRequest)
	if !ok || !matchesExpectedTruncate(req) {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.refreshWindowOpenLocked(req.Item.ItemID, int64(*req.Size))
}

// consumeExpectedTruncate reports whether req is the daemon's own pending
// kernel-size refresh for path. Only a pure size set (optionally with the
// times the kernel attaches to truncates) can match; anything touching mode or
// ownership is a real application setattr.
//
// A PINNED window answers first and is NOT consumed — see
// refreshWindowOpenLocked. This is the same decision admission already made
// for the same request, and keeping it non-consuming is what stops one
// request from spending another's provenance.
//
// Below the window sits the UNPINNED sweeper arm, which is single-use and
// deadline-bounded. No marker should ever be found unpinned —
// applyKernelRefresh retires its own on every exit path — so this is a
// backstop for a marker that outlived its refresh through a path that does not
// exist today, never the primary decision. A size mismatch retires an unpinned
// note: the kernel is performing a REAL truncate that must reach the
// authority, and the stale note must not linger. A pinned note is never
// retired here even on mismatch; it belongs to the refresh that installed it.
func (a *attach) consumeExpectedTruncate(p string, req *pfslocal.SetAttrRequest) bool {
	if !matchesExpectedTruncate(req) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refreshWindowOpenLocked(req.Item.ItemID, int64(*req.Size)) {
		return true
	}
	now := time.Now()
	if note, ok := a.expectedTruncates[p]; ok {
		if note.pinned {
			// A pinned marker that did not match the window is a DIFFERENT
			// refresh's. Leave it alone and let this real setattr through.
			return false
		}
		delete(a.expectedTruncates, p)
		return expectedTruncateLive(note, now) &&
			note.itemID == req.Item.ItemID &&
			int64(*req.Size) == note.size
	}
	// ftruncate addresses an already-open FSItem, not a pathname. A rename
	// can therefore move that item after the secure open/fstat but before its
	// setattr upcall reaches us. Find the exact item marker so the daemon's
	// refresh remains a no-op at the authority rather than becoming a real
	// truncate of the item's new name. Multiple hard-link aliases retain
	// separate path markers and are consumed one at a time.
	//
	// Only UNPINNED markers are reachable here: the pinned window was tested
	// first, over every marker, on exactly this (itemID, size), so a pinned
	// marker matching the condition below would already have returned true.
	// The guard states that rather than relying on it.
	for notedPath, note := range a.expectedTruncates {
		if note.pinned {
			continue
		}
		if !expectedTruncateLive(note, now) {
			delete(a.expectedTruncates, notedPath)
			continue
		}
		if note.itemID == req.Item.ItemID && int64(*req.Size) == note.size {
			delete(a.expectedTruncates, notedPath)
			return true
		}
	}
	return false
}
