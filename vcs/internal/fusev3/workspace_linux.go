//go:build linux

package fusev3

import (
	"context"
	"fmt"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func (r *rawFileSystem) recycleReplyLocked(p *replyPublication) {
	if p.cachedArena {
		*p = replyPublication{cachedNext: r.cachedReplyFree}
		r.cachedReplyFree = p
	}
}

// workspaceReplyCohort is a fixed cut. Refusals and exact cleanup arriving after
// closure cannot replenish a join. A cancelled waiter retains every owner.
type workspaceReplyCohort struct{ replies []<-chan struct{} }

func (r *rawFileSystem) captureWorkspaceReplies() workspaceReplyCohort {
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
		return p.workspace.Check
	}
	return nil
}

func (m *Mount) workspaceServing() bool {
	if m == nil || m.workspace == nil {
		return true
	}
	_, err := m.workspace.Check()
	return err == nil
}

// A drain never asks the current manager for a successor buffer/incarnation or
// a refreshed horizon. It names the captured cut and its actual old deadline.
type workspaceDrainPermit struct {
	manager     *delegationManager
	buffer      *writeback.Buffer
	incarnation uint64
	deadline    time.Time
}

func (p workspaceDrainPermit) allows(buffer *writeback.Buffer, incarnation uint64, now time.Time) bool {
	return p.buffer != nil && p.buffer == buffer && p.incarnation != 0 && p.incarnation == incarnation && now.Before(p.deadline)
}

// Recovery is kept on the subscription owner. Closing serving does not erase
// its control liveness or the identity needed by release and reclaim.
type workspaceRecoveryKey struct{}

// beginWorkspaceEntry reserves one existing physical-reply owner before the
// first answer or effect. The slow callback transfers this owner explicitly.
func (r *rawFileSystem) beginWorkspaceEntry(unique uint64) (*replyPublication, fuse.Status) {
	if r.mount.workspace == nil {
		return nil, fuse.OK
	}
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
	p.owner, p.requestUnique = r, unique
	p.workspaceDone = make(chan struct{})
	r.replyPublications[unique] = p
	if r.mount.workspace != nil {
		permit, err := r.mount.workspace.Check()
		if err != nil {
			delete(r.replyPublications, unique)
			r.recycleReplyLocked(p)
			return nil, fuse.EIO
		}
		p.workspace, p.workspaceBound = permit, true
	}
	return p, fuse.OK
}
func (r *rawFileSystem) finishWorkspaceEntry(unique uint64, entry *replyPublication) {
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
		p.workspace, p.workspaceBound = permit, true
		r.mu.Unlock()
	}
	return nil
}

// The lifecycle owner captures this before retiring the old buffer. Control
// and cleanup keep that exact identity/deadline, independently of serving.
func (m *delegationManager) captureWorkspaceDrain(deadline time.Time) workspaceDrainPermit {
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	s := m.subscription
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cacheUntil.Before(deadline) {
		deadline = s.cacheUntil
	}
	p := workspaceDrainPermit{manager: m, buffer: m.buf, incarnation: s.incarnation, deadline: deadline}
	s.workspaceDrain = &p
	return p
}
func (m *delegationManager) drainIncarnation(p workspaceDrainPermit) uint64 {
	if p.manager != m || m.subscription == nil || !p.allows(p.buffer, p.incarnation, m.subscription.config.clock.Now()) {
		return 0
	}
	return p.incarnation
}
