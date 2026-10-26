//go:build linux

package fusev3

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// Managed callbacks retain their logical owner while dispatch is locally
// unavailable. Each submitted attempt gets its bounded network budget only
// after fence admission; mount cancellation still releases the callback.
func (m *Mount) operationContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if m == nil || m.workspace == nil {
		return context.WithTimeout(parent, timeout)
	}
	ctx, cancel := context.WithCancel(parent)
	return authorityrpc.WithDispatchTimeout(ctx, timeout), cancel
}

// Construction selects admission dispatch once. Embedding promotes the exact
// physical-reply interfaces discovered by go-fuse, without an ordinary entry
// wrapper or a second implementation of the cache handlers.
type workspaceFileSystem struct{ *rawFileSystem }

var _ fuse.RawFileSystem = (*workspaceFileSystem)(nil)
var _ fuse.ReplyWriteLifecycle = (*workspaceFileSystem)(nil)
var _ fuse.ReplyPayloadPreparer = (*workspaceFileSystem)(nil)

func (r *rawFileSystem) fileSystemForServer() fuse.RawFileSystem {
	if r.mount.workspace == nil {
		return r
	}
	return &workspaceFileSystem{rawFileSystem: r}
}

func (m *Mount) workspaceFS() *workspaceFileSystem {
	if m.workspace == nil {
		return nil
	}
	return &workspaceFileSystem{rawFileSystem: m.raw}
}

// Requests waiting for a new serving interval own no callback, publication or
// buffer admission. In particular, they cannot extend the fixed cold-drain
// cohort or hold an epoch reader needed by its withdrawal. The shared page has
// no child notification; resampling also observes terminal teardown.
func (m *Mount) awaitWorkspaceServing(ctx context.Context, interrupted ...<-chan struct{}) error {
	return m.awaitWorkspaceEntry(ctx, true, interrupted...)
}

func (m *Mount) awaitWorkspaceEntry(ctx context.Context, safeForWithdrawal bool, interrupted ...<-chan struct{}) error {
	if m.workspace == nil {
		return nil
	}
	// A gate alone promises refusal, not recovery. Waiting requires the
	// lifecycle owner which can reopen or terminalize this mount.
	if m.workspaceLifecycle == nil {
		_, err := m.workspace.Check()
		if err == nil && !m.workspacePermissionLive() {
			return workspaceadmission.ErrClosed
		}
		return err
	}
	var cancel <-chan struct{}
	if len(interrupted) != 0 {
		cancel = interrupted[0]
	}
	for {
		select {
		case <-cancel:
			return syscall.EINTR
		default:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.ctx.Err(); err != nil {
			return err
		}
		if err := m.fatalError(); err != nil {
			return err
		}
		if m.isRevoked() {
			return syscall.EIO
		}
		if err := m.rpc.SessionEndCause(); err != nil {
			return err
		}
		if m.workspaceServing() {
			return nil
		}
		if !safeForWithdrawal && !m.workspaceLifecycle.kernelColdReady.Load() {
			// Namespace callbacks can hold the parent inode lock needed by
			// EntryNotify; buffered READ can hold a folio needed by InodeNotify.
			// They must release those kernel locks before the cold proof. Once
			// the kernel is cold, no retained notification can need their locks.
			return workspaceadmission.ErrClosed
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-cancel:
			timer.Stop()
			return syscall.EINTR
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-m.workspace.Done():
			timer.Stop()
			return workspaceadmission.ErrClosed
		case <-timer.C:
		}
	}
}

func (r *workspaceFileSystem) Lookup(cancel <-chan struct{}, header *fuse.InHeader, name string, out *fuse.EntryOut) fuse.Status {
	entry, status := r.beginWorkspaceEntry(header.Unique, cancel)
	if !status.Ok() {
		return status
	}
	defer r.finishWorkspaceEntry(header.Unique, entry)
	return r.rawFileSystem.Lookup(cancel, header, name, out)
}

func (r *workspaceFileSystem) GetAttr(cancel <-chan struct{}, input *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
	entry, status := r.beginWorkspaceEntry(input.Unique, cancel)
	if !status.Ok() {
		return status
	}
	defer r.finishWorkspaceEntry(input.Unique, entry)
	return r.rawFileSystem.GetAttr(cancel, input, out)
}

func (r *rawFileSystem) recycleReplyLocked(p *replyPublication) {
	if p.cachedArena {
		*p = replyPublication{cachedNext: r.cachedReplyFree}
		r.cachedReplyFree = p
	}
}

// workspaceReplyCohort is a fixed cut. Refusals and exact cleanup arriving after
// closure cannot replenish a join. A cancelled waiter retains every owner.
type workspaceReplyCohort struct{ replies []<-chan struct{} }

func (r *workspaceFileSystem) captureWorkspaceReplies() workspaceReplyCohort {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var cut workspaceReplyCohort
	for _, p := range r.replyPublications {
		if p.workspaceDone == nil {
			continue
		}
		// The existing physical settlement owner remains indexed through source
		// release, rollback and response consumption, including terminalization.
		cut.replies = append(cut.replies, p.workspaceDone)
	}
	return cut
}
func (cut workspaceReplyCohort) wait(ctx context.Context) error {
	for _, done := range cut.replies {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// No manager/index lock is acquired by this predicate. Buffer invokes it under
// its mutex at acceptance, including after each capacity wait.
func workspaceAcceptance(ctx context.Context) error {
	p := replyPublicationFromContext(ctx)
	if p != nil && p.workspaceBound {
		if err := p.workspace.Check(); err != nil {
			return err
		}
		if !p.owner.mount.workspaceClockReady() || !p.owner.mount.workspacePermissionLive() {
			return workspaceadmission.ErrClosed
		}
		return p.workspace.Check()
	}
	return nil
}

// Ordinary mounts retain their original context and allocate no gate closure.
func workspaceAdmissionContext(ctx context.Context) context.Context {
	if check := workspaceAcceptanceCheck(ctx); check != nil {
		return writeback.WithAdmissionCheck(ctx, check)
	}
	return ctx
}

func workspaceAcceptanceCheck(ctx context.Context) func() error {
	p := replyPublicationFromContext(ctx)
	if p != nil && p.workspaceBound {
		check, m := p.workspace.Check, p.owner.mount
		return func() error {
			if err := check(); err != nil {
				return err
			}
			if !m.workspaceClockReady() || !m.workspacePermissionLive() {
				return workspaceadmission.ErrClosed
			}
			return check()
		}
	}
	return nil
}

func (m *Mount) workspaceServing() bool {
	if m == nil || m.workspace == nil {
		return true
	}
	_, err := m.workspace.Check()
	if err != nil || !m.workspaceClockReady() || !m.workspacePermissionLive() {
		return false
	}
	if m.workspaceLifecycle != nil {
		_, _, _, live := m.subscription.currentIncarnation()
		return live
	}
	return true
}

func (m *Mount) workspacePermissionLive() bool {
	if m == nil || m.workspaceRTC == nil {
		return true
	}
	return m.subscription != nil && m.subscription.workspaceRemaining() > 0
}

// TLS readiness can withdraw between observer ticks. Denial at use prevents a
// delayed root observation from admitting another write. It supplies no RTC
// lease time; authority/subscription horizons still use the ordinary clocks.
func (m *Mount) workspaceClockReady() bool {
	w := m.workspaceLifecycle
	if w == nil {
		return true
	}
	if w.clock == nil {
		return false
	}
	p := w.initialPermit
	if prior := w.observation.Load(); prior != nil {
		p = mountenrollment.Permit{Generation: prior.Generation, GateSerial: prior.GateSerial}
	}
	return w.clock.Check(p) == nil
}

// A drain never asks the current manager for a successor buffer/incarnation or
// a refreshed horizon. It names the captured cut and its actual old deadline.
type workspaceDrainPermit struct {
	registry    *subscriptionRegistry
	manager     *delegationManager
	buffer      *writeback.Buffer
	incarnation uint64
	deadline    time.Time
}

func (p workspaceDrainPermit) allows(buffer *writeback.Buffer, incarnation uint64, now time.Time) bool {
	return p.buffer != nil && p.buffer == buffer && p.incarnation != 0 && p.incarnation == incarnation && now.Before(p.deadline) && (p.registry == nil || p.registry.delegationHorizonLive(incarnation))
}

// Recovery is kept on the subscription owner. Closing serving does not erase
// its control liveness or the identity needed by release and reclaim.
type workspaceRecoveryKey struct{}

// beginWorkspaceEntry reserves one existing physical-reply owner before the
// first answer or effect. The slow callback transfers this owner explicitly.
func (r *workspaceFileSystem) beginWorkspaceEntry(unique uint64, interrupted ...<-chan struct{}) (*replyPublication, fuse.Status) {
	return r.beginWorkspaceEntryPolicy(unique, false, interrupted...)
}

// Regular-file direct writes and fsync hold no parent inode lock or page-cache
// folio needed by cold invalidation. Other kernel operations wait only after
// the complete cold proof, so none can deadlock its reverse notifications.
func (r *workspaceFileSystem) beginWorkspaceFileEntry(unique uint64, interrupted <-chan struct{}) (*replyPublication, fuse.Status) {
	return r.beginWorkspaceEntryPolicy(unique, true, interrupted)
}
func (r *workspaceFileSystem) beginWorkspaceEntryPolicy(unique uint64, safeForWithdrawal bool, interrupted ...<-chan struct{}) (*replyPublication, fuse.Status) {
	for {
		if err := r.mount.awaitWorkspaceEntry(r.opContext(), safeForWithdrawal, interrupted...); err != nil {
			return nil, fuse.Status(errnoOfError(err))
		}
		p, status := r.tryWorkspaceEntry(unique)
		if status != fuse.Status(syscall.EAGAIN) { // Closure raced the wait; no entry was admitted.
			return p, status
		}
	}
}
func (r *workspaceFileSystem) tryWorkspaceEntry(unique uint64) (*replyPublication, fuse.Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if unique == 0 || r.replyTerminal || r.replyTerminalizing || r.replyPublications[unique] != nil {
		return nil, fuse.EIO
	}
	var p *replyPublication
	if r.cachedReplyFree != nil {
		p = r.cachedReplyFree
		r.cachedReplyFree = p.cachedNext
		*p = replyPublication{cachedArena: true}
	} else {
		p = &replyPublication{}
	}
	p.owner, p.requestUnique = r.rawFileSystem, unique
	p.workspaceDone = make(chan struct{})
	r.replyPublications[unique] = p
	permit, err := r.mount.workspace.Check()
	if err != nil || !r.mount.workspaceServing() {
		delete(r.replyPublications, unique)
		r.recycleReplyLocked(p)
		return nil, fuse.Status(syscall.EAGAIN)
	}
	if life := r.mount.workspaceLifecycle; life != nil {
		life.kernelColdReady.Store(false)
		life.servedSinceCold.Store(true)
	}
	p.workspace, p.workspaceBound = permit, true
	return p, fuse.OK
}
func (r *workspaceFileSystem) finishWorkspaceEntry(unique uint64, entry *replyPublication) {
	if entry == nil {
		return
	}
	r.mu.RLock()
	p := r.replyPublications[unique]
	callbackOwned := p != nil && p.callbackOwned
	r.mu.RUnlock()
	if p == nil || callbackOwned {
		return
	}
	r.finishReplyPublicationRegistration(unique, p)
}

// Only a WRITE refused before delegation acquisition or with a zero accepted cut may use this
// transition. No filesystem effect or kernel candidate belongs to that attempt;
// the original FUSE request remains unanswered and can await fresh admission.
// This is callback retirement, never a fabricated physical reply completion.
func (r *rawFileSystem) retireUnacceptedWorkspaceWrite(unique uint64) error {
	r.mu.Lock()
	p := r.replyPublications[unique]
	if p == nil || !p.callbackOwned || !p.workspaceBound || p.originalFinalized || p.settlementClaimed ||
		len(p.names) != 0 || len(p.attrs) != 0 || len(p.data) != 0 || len(p.unlicensed) != 0 ||
		p.postState != nil || len(p.expectedPostState) != 0 || p.retainedAnswer || p.lookupReference != nil ||
		p.dirPlusLookups != nil || p.completeDirectoryCount != 0 || p.cachedCount != 0 || p.payloadError != nil {
		r.mu.Unlock()
		return fmt.Errorf("fusev3: unaccepted workspace write retained publication effects")
	}
	if source := p.source; source != nil && (!source.ready || source.revoked || source.released) {
		r.mu.Unlock()
		return fmt.Errorf("fusev3: unaccepted workspace write retained an unresolved source")
	}
	delete(r.replyPublications, unique)
	claim := r.settleReplyPublicationLocked(p, false)
	p.closeOriginalDoneLocked()
	r.mu.Unlock()
	if p.source != nil {
		p.source.release()
	}
	consumeClaimedAuthorityResponses(claim)
	r.mu.Lock()
	close(p.workspaceDone)
	r.signalSourceChangedLocked()
	r.mu.Unlock()
	return nil
}

func (r *rawFileSystem) transferReplyPublication(unique uint64, serving bool, next *replyPublication) error {
	if r.mount.workspace == nil {
		next.callbackOwned = true
		return r.registerReplyPublication(unique, next)
	}
	r.mu.Lock()
	if r.replyTerminal || r.replyTerminalizing {
		r.mu.Unlock()
		return fmt.Errorf("fusev3: reply publication transferred after terminal settlement")
	}
	p := r.replyPublications[unique]
	if p != nil {
		if p.callbackOwned {
			r.mu.Unlock()
			return fmt.Errorf("fusev3: duplicate reply owner %d", unique)
		}
		// Slow callbacks retain their original heap lifetime. Their contexts also
		// reach counted descriptor cleanup after physical settlement; an arena slot
		// cannot be reused while those callbacks still identify this operation.
		*next = *p
		next.cachedArena, next.cachedNext = false, nil
		next.callbackOwned = true
		next.responseConsumptionOwner = responseConsumptionPublication
		if next.responseConsumptionDone == nil {
			next.responseConsumptionDone = make(chan struct{})
		}
		next.stamp = r.mount.subscription.stamp()
		r.replyPublications[unique] = next
		r.recycleReplyLocked(p)
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	p = next
	p.callbackOwned = true
	if serving {
		p.workspaceDone = make(chan struct{})
	}
	if err := r.registerReplyPublication(unique, p); err != nil {
		return err
	}
	if serving && r.mount.workspace != nil {
		r.mu.Lock()
		permit, err := r.mount.workspace.Check()
		if err != nil {
			delete(r.replyPublications, unique)
			p.closeOriginalDoneLocked()
			claim, _ := r.takeAuthorityResponsesLocked(p)
			r.mu.Unlock()
			consumeClaimedAuthorityResponses(claim)
			close(p.workspaceDone)
			return err
		}
		if life := r.mount.workspaceLifecycle; life != nil {
			life.kernelColdReady.Store(false)
			life.servedSinceCold.Store(true)
		}
		p.workspace, p.workspaceBound = permit, true
		r.mu.Unlock()
	}
	return nil
}

// The lifecycle owner captures this before retiring the old buffer. Control
// and cleanup keep that exact identity/deadline, independently of serving.
func (r *workspaceFileSystem) captureWorkspaceDrain(deadline time.Time) workspaceDrainPermit {
	m := r.mount.delegations
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	s := m.subscription
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.workspaceDrain != nil {
		return *s.workspaceDrain
	}
	s.workspaceOwned = true
	if deadline.IsZero() || s.cacheUntil.Before(deadline) {
		deadline = s.cacheUntil
	}
	p := workspaceDrainPermit{registry: s, manager: m, buffer: m.buf, incarnation: s.incarnation, deadline: deadline}
	s.workspaceDrain = &p
	return p
}
func (r *workspaceFileSystem) drainIncarnation(p workspaceDrainPermit) uint64 {
	m := r.mount.delegations
	if p.manager != m || m.subscription == nil || !p.allows(p.buffer, p.incarnation, m.subscription.config.clock.Now()) {
		return 0
	}
	return p.incarnation
}
