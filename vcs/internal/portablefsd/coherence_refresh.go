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

type expectedTruncate struct {
	itemID   uint64
	size     int64
	deadline time.Time
}

const (
	// refreshCoalesce absorbs a burst of remote-write invalidations for one
	// file into a single kernel refresh.
	refreshCoalesce = 25 * time.Millisecond
	// truncateNoteTTL bounds how long a marked refresh may stay pending. An
	// application truncate to the exact same (already current) size inside
	// this window is also consumed — its only observable loss is an mtime
	// bump the remote edit has already superseded.
	truncateNoteTTL = 5 * time.Second
	// staleSampleRetries bounds how long a refresh waits for the authority
	// sample to catch up with state the daemon has already seen (see
	// refreshLocalSample). 40 × refreshCoalesce ≈ 1s, comfortably past a flush.
	staleSampleRetries = 40
)

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
	note := expectedTruncate{
		itemID: rec.item.ItemID, size: size,
		deadline: time.Now().Add(truncateNoteTTL),
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
	// ftruncate is synchronous with its FSKit setattr callback. If that
	// callback did not consume this exact note (for example, the vnode size
	// already matched and only page invalidation was needed), retire it now;
	// a later application truncate must never match a stale daemon marker.
	a.mu.Lock()
	if current, exists := a.expectedTruncates[p]; exists && current == note {
		delete(a.expectedTruncates, p)
	}
	a.mu.Unlock()
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
	op        *frontendOperation
	suspended bool
	finished  bool
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

func (a *attach) beginFrontendOperation(ctx context.Context, body any) (context.Context, *frontendOperation) {
	paths, pathEpoch, publishes := a.frontendOperationPaths(body)
	if !publishes {
		return ctx, nil
	}
	return a.beginFrontendPathsAtEpoch(ctx, paths, pathEpoch)
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

// extendFrontendOperation admits another request belonging to an already
// active logical FSKit callback. A handoff that is already waiting on this
// operation must allow its later pages/RPCs through, otherwise the callback
// can never reach its one publication acknowledgement. A handoff that was
// disjoint from the operation's original scope still blocks a newly-overlapping
// extension until ownership is stable.
func (a *attach) extendFrontendOperation(
	ctx context.Context,
	op *frontendOperation,
	paths []string,
	pathEpoch uint64,
) (*frontendOperationParticipant, error) {
	if op == nil || op.attach != a {
		return nil, fmt.Errorf("portablefsd: invalid logical frontend operation")
	}
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
		if op.completed {
			a.frontendGateMu.Unlock()
			return nil, net.ErrClosed
		}
		blocked := false
		for scope := range a.frontendHandoffs {
			currentEpoch := a.frontendPathEpoch.Load()
			newOverlaps := pathEpoch != currentEpoch ||
				operationOverlapsScope(paths, scope)
			alreadyOwned := op.gateActive &&
				(op.pathEpoch != currentEpoch ||
					operationOverlapsScope(op.paths, scope))
			if newOverlaps && !alreadyOwned {
				blocked = true
				break
			}
		}
		if !blocked {
			break
		}
		a.frontendGateCond.Wait()
	}
	seen := make(map[string]struct{}, len(op.paths)+len(paths))
	for _, path := range op.paths {
		seen[path] = struct{}{}
	}
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		op.paths = append(op.paths, path)
	}
	if op.pathEpoch != pathEpoch {
		// Zero cannot equal a real namespace epoch, so any later handoff
		// conservatively treats this logical operation as mount-wide.
		op.pathEpoch = 0
	}
	op.participants++
	a.frontendGateMu.Unlock()
	return &frontendOperationParticipant{op: op}, nil
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
	if participant.suspended {
		participant.suspended = false
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
	if !op.completed && !participant.finished && !participant.suspended {
		participant.suspended = true
		op.suspended++
	}
	if !op.completed && op.gateActive &&
		op.participants > 0 && op.suspended == op.participants {
		delete(a.frontendActive, op)
		op.gateActive = false
		a.frontendGateCond.Broadcast()
	}
	a.frontendGateMu.Unlock()
	return func() {
		a.frontendGateMu.Lock()
		defer a.frontendGateMu.Unlock()
		stopWake := context.AfterFunc(ctx, func() {
			a.frontendGateMu.Lock()
			a.frontendGateCond.Broadcast()
			a.frontendGateMu.Unlock()
		})
		defer stopWake()
		if participant.finished || !participant.suspended {
			return
		}
		for !op.completed {
			if ctx.Err() != nil {
				participant.suspended = false
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
				participant.suspended = false
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
			paths = append(paths, rec.path)
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
		_, _, ok := child(req.Dir, req.Name)
		if !ok {
			return unknown()
		}
		// Lookup may discover that a previously unseen name is a hard-link
		// alias of an FSItem already live elsewhere. Until the authority reply
		// identifies that inode, its publication scope is unknowable.
		return unknown()
	case *pfslocal.EnumerateRequest:
		if _, ok := itemPath(req.Dir); !ok {
			return unknown()
		}
		// Readdir-plus can publish attributes for unseen aliases. Treat the
		// operation as mount-wide only during the rare handoff interval.
		return unknown()
	case *pfslocal.GetAttrRequest:
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.SetAttrRequest:
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
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.XattrSetRequest:
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.XattrListRequest:
		paths, ok := itemPaths(req.Item)
		if !ok {
			return unknown()
		}
		return knownSlice(paths)
	case *pfslocal.XattrRemoveRequest:
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

// consumeExpectedTruncate reports whether req is the daemon's own pending
// kernel-size refresh for path, consuming the note on a match. Only a pure
// size set (optionally with the times the kernel attaches to truncates) can
// match; anything touching mode or ownership is a real application setattr.
// A size mismatch retires the note: the kernel is performing a REAL truncate
// that must reach the authority, and the stale note must not linger.
func (a *attach) consumeExpectedTruncate(p string, req *pfslocal.SetAttrRequest) bool {
	if req.Size == nil || req.Mode != nil || req.UID != nil || req.GID != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if note, ok := a.expectedTruncates[p]; ok {
		delete(a.expectedTruncates, p)
		return now.Before(note.deadline) &&
			note.itemID == req.Item.ItemID &&
			int64(*req.Size) == note.size
	}
	// ftruncate addresses an already-open FSItem, not a pathname. A rename
	// can therefore move that item after the secure open/fstat but before its
	// setattr upcall reaches us. Find the exact item marker so the daemon's
	// refresh remains a no-op at the authority rather than becoming a real
	// truncate of the item's new name. Multiple hard-link aliases retain
	// separate path markers and are consumed one at a time.
	for notedPath, note := range a.expectedTruncates {
		if !now.Before(note.deadline) {
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
