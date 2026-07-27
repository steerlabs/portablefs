// Package delegation coordinates exclusive write access to subtrees of a volume —
// delegation-based checkout/checkin. The single-authority VCS holds the registry; a
// client (agent) checks out a path before editing and checks in when done.
// Subtree semantics: a delegation on /a covers everything under /a, so it
// conflicts with any overlapping checkout held by a different owner. The owner is
// a caller-provided identity (e.g. an agent id), so a checkout survives across the
// separate processes that check out and later check in.
//
// Recall: a holder keeps its delegation indefinitely (no time-based release). When a
// DIFFERENT owner contends for an overlapping path, the authority recalls the holder
// (out of band, via the invalidation stream) and waits — AwaitFree — for the holder to
// flush + check in; if the holder is unresponsive, ForceCheckout revokes it after a
// bound. This is the delegation model: hand off exactly when contended, never on a timer.
package delegation

import (
	"context"
	"path"
	"strings"
	"sync"
)

// Manager is the per-volume delegation registry.
type Manager struct {
	mu   sync.Mutex
	held map[string]string // path -> owner
	// fenced records subtrees whose holder was FORCE-revoked (presumed dead): subtree -> the
	// revoked owner. A force-revoked holder may still have an in-flight write-back flush; while
	// the new holder holds the subtree pathOwnerOK already rejects that flush, but after the new
	// holder checks in the subtree is free and the stale flush would otherwise apply over it. The
	// fence rejects the revoked owner's flushes under the subtree until that owner re-establishes
	// (a fresh checkout, at a strictly-higher session epoch the watermark then supersedes).
	fenced map[string]string
	free   chan struct{} // closed+replaced whenever a delegation is released, to wake AwaitFree waiters
}

// New returns an empty Manager.
func New() *Manager {
	return &Manager{held: map[string]string{}, fenced: map[string]string{}, free: make(chan struct{})}
}

func clean(p string) string { return strings.Trim(path.Clean("/"+p), "/") }

// covers reports whether a delegation at path `a` covers path `b` (a == b or a is
// an ancestor of b).
func covers(a, b string) bool {
	if a == b {
		return true
	}
	if a == "" {
		return true // a checkout at the root covers everything
	}
	return strings.HasPrefix(b, a+"/")
}

// overlaps reports whether delegations at a and b conflict (either covers the other).
func overlaps(a, b string) bool { return covers(a, b) || covers(b, a) }

// signalFreeLocked wakes every AwaitFree waiter (a delegation was just released). Caller holds mu.
func (m *Manager) signalFreeLocked() {
	close(m.free)
	m.free = make(chan struct{})
}

// Checkout grants exclusive write on path to owner. It fails if a different owner
// already holds an overlapping delegation (path, an ancestor, or a descendant),
// returning that owner. Re-checkout by the same owner is idempotent.
func (m *Manager) Checkout(p, owner string) (granted bool, heldBy string) {
	p = clean(p)
	m.mu.Lock()
	defer m.mu.Unlock()
	for held, o := range m.held {
		if o == owner {
			continue
		}
		if overlaps(held, p) {
			return false, o
		}
	}
	m.held[p] = owner
	// This owner re-established a checkout overlapping any subtree it was previously force-revoked
	// from: lift those fences. It is alive, and its fresh session runs at a strictly-higher epoch,
	// so the watermark now supersedes any straggler flush from the revoked session by epoch alone.
	for s, fo := range m.fenced {
		if fo == owner && overlaps(s, p) {
			delete(m.fenced, s)
		}
	}
	return true, ""
}

// Checkin releases owner's delegation on path. It returns false if owner did not
// hold it.
func (m *Manager) Checkin(p, owner string) bool {
	p = clean(p)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.held[p] == owner {
		delete(m.held, p)
		m.signalFreeLocked()
		return true
	}
	return false
}

// HeldBy returns the owner of the delegation covering path (path or an ancestor),
// or "" if none.
func (m *Manager) HeldBy(p string) (owner, at string) {
	p = clean(p)
	m.mu.Lock()
	defer m.mu.Unlock()
	for held, o := range m.held {
		if covers(held, p) {
			return o, held
		}
	}
	return "", ""
}

// AwaitFree blocks until no delegation overlaps path (so a contender can then check it
// out), or until ctx is cancelled. Returns true if it became free, false on cancellation
// — the caller then escalates to ForceCheckout. Used by Checkout-contention: after
// recalling the holder, the authority waits here for the holder's checkin.
func (m *Manager) AwaitFree(ctx context.Context, p string) bool {
	p = clean(p)
	for {
		m.mu.Lock()
		free := true
		for held, o := range m.held {
			_ = o
			if overlaps(held, p) {
				free = false
				break
			}
		}
		ch := m.free
		m.mu.Unlock()
		if free {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ch:
		}
	}
}

// ForceCheckout revokes every overlapping delegation held by another owner and grants path
// to owner. Used when a recalled holder did not relinquish within the bound (presumed dead);
// its un-acked writes are lost, and it discovers the revocation on its next op. Returns the
// owners that were revoked (so the authority can fence them).
func (m *Manager) ForceCheckout(p, owner string) (revoked []string) {
	p = clean(p)
	m.mu.Lock()
	defer m.mu.Unlock()
	for held, o := range m.held {
		if o != owner && overlaps(held, p) {
			revoked = append(revoked, o)
			delete(m.held, held)
			m.fenced[held] = o // fence the revoked (presumed-dead) owner's stale flushes under this subtree
		}
	}
	m.held[p] = owner
	if len(revoked) > 0 {
		m.signalFreeLocked()
	}
	return revoked
}

// IsFenced reports whether owner is fenced from flushing under path — i.e. it was
// force-revoked from a subtree covering path and has not re-established a checkout there.
// The authority rejects such a flush (ESTALE) so a presumed-dead holder's in-flight
// write-back cannot apply over the subtree after the new holder hands it back.
func (m *Manager) IsFenced(owner, p string) bool {
	p = clean(p)
	m.mu.Lock()
	defer m.mu.Unlock()
	for s, fo := range m.fenced {
		if fo == owner && covers(s, p) {
			return true
		}
	}
	return false
}

// ReleaseOwner drops every delegation held by owner.
func (m *Manager) ReleaseOwner(owner string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	freed := false
	for p, o := range m.held {
		if o == owner {
			delete(m.held, p)
			freed = true
		}
	}
	if freed {
		m.signalFreeLocked()
	}
}
