package fsproto

// The delegation peer gate and the adaptive grant policy.
//
// Gate: every read-class op, write-through mutation, and lock acquisition
// that overlaps a FOREIGN active delegation publishes a recall and waits
// bounded for the release — a peer is never answered from stale
// pre-delegation state (the holder may have acknowledged newer bytes
// locally). A recovery-required scope (dead holder, possibly dirty) answers
// retryable EAGAIN until the stream rebinds and drains or an operator
// discards it: sacrificing availability there is the correct trade.
//
// Write-through MUTATIONS additionally do not bypass the gate for the
// holder's own session: a same-session mutation ordered after a grant must
// recall it (the engine drains + releases) rather than slip past the
// holder's authoritative snapshot — this is what makes the grant-time
// children snapshot exact against same-session races.
//
// Policy: ONE canonical recall cooldown. The durable overlap decision lives
// in ManagedDelegationDecide (journaled); the cooldown only spaces re-grants
// of a scope that was recently recalled for contention. Paths are
// canonicalized ONCE at the coordinate boundary — alias spellings share one
// cooldown entry and cannot induce delegation churn.

import (
	"path"
	"strings"
	"sync"
	"time"
)

// policyContentionWindow: no grant while the scope was recalled for
// contention this recently. A var so tests can compress it; production never
// changes it.
var policyContentionWindow = 30 * time.Second

// policyMapBound caps the volatile cooldown table.
const policyMapBound = 65536

// SetAdaptivePolicyContentionWindowForTest compresses the recall cooldown so
// acceptance tests exercise contention degrade + re-grant deterministically
// without multi-second waits. Test-only; never called in production.
func SetAdaptivePolicyContentionWindowForTest(contention time.Duration) {
	policyContentionWindow = contention
}

// policyClock is stubbed by contention tests to compress the window.
var policyClock = time.Now

// delegationPolicy tracks the one volatile adaptive-policy input: the
// per-scope contention-recall cooldown, keyed by canonical path.
type delegationPolicy struct {
	mu      sync.Mutex
	recalls map[string]time.Time // canonical scope -> last contention recall
}

// noteContention records a contention recall of the canonical scope.
func (p *delegationPolicy) noteContention(scope string) {
	p.mu.Lock()
	if p.recalls == nil {
		p.recalls = map[string]time.Time{}
	}
	if len(p.recalls) > policyMapBound {
		p.recalls = map[string]time.Time{}
	}
	p.recalls[scope] = policyClock()
	p.mu.Unlock()
}

// policyVerdict is the volatile half of the grant decision: OK admits the
// durable overlap decision; EBUSY declines (the client runs write-through
// and backs off). scope must already be canonical. The durable overlap check
// happens inside the journaled decision, never here.
func (p *delegationPolicy) policyVerdict(scope string) int32 {
	now := policyClock()
	p.mu.Lock()
	defer p.mu.Unlock()
	// The scope's — or any ancestor's — recent contention recall declines:
	// the recalled holder covered this subtree.
	for dir := scope; ; dir = parentOf(dir) {
		if at, ok := p.recalls[dir]; ok && now.Sub(at) < policyContentionWindow {
			return EBUSY
		}
		if dir == "" {
			break
		}
	}
	return OK
}

// delegationGate blocks an operation that overlaps a foreign delegation
// until the holder releases (recall) or the bounded wait expires. Returns OK
// to proceed or the retryable EAGAIN. selfBypass lets the holder's own READS
// pass (composed reads under the grant are the holder's right); write-through
// MUTATIONS never bypass — they recall the holder's own grant so they order
// after its drained, released state.
func (s *Server) delegationGate(cs *connSession, selfBypass bool, paths ...string) int32 {
	store := s.coordStore()
	if store == nil {
		return OK
	}
	session := ""
	if selfBypass && cs.attached() {
		session = cs.id
	}
	canonical := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" && len(paths) > 1 {
			continue
		}
		canonical = append(canonical, cleanWirePath(p))
	}
	blocked := func() []string {
		var scopes []string
		for _, p := range canonical {
			for _, g := range store.ManagedDelegationsOverlapping(p) {
				if g.Holder.SessionID == session && session != "" && !g.Recovery {
					continue
				}
				scopes = append(scopes, g.Path)
				if g.Recovery {
					scopes[len(scopes)-1] = "\x00recovery:" + g.Path
				}
			}
		}
		return scopes
	}
	scopes := blocked()
	if len(scopes) == 0 {
		return OK
	}
	publish := func(scopes []string) (recovery bool) {
		for _, sc := range scopes {
			if strings.HasPrefix(sc, "\x00recovery:") {
				recovery = true
				continue
			}
			// A live holder: publish the recall and remember the contention
			// so the adaptive policy declines re-grants for the cooldown.
			s.delegations.noteContention(sc)
			if s.recaller != nil {
				s.recaller.PublishRecall(sc)
			}
		}
		return recovery
	}
	if publish(scopes) {
		// The only current bytes may be on an unavailable holder: retryable,
		// never stale.
		return EAGAIN
	}
	// Wait in slices, re-publishing the recall each round: delivery is a
	// broadcast to the CURRENT subscriber set, and a holder whose stream is
	// (re)subscribing right now must still hear it.
	deadline := time.Now().Add(recallTimeout)
	for {
		slice := time.Until(deadline)
		if slice <= 0 {
			return EAGAIN
		}
		if slice > time.Second {
			slice = time.Second
		}
		cleared := store.WaitCoordinationClear(time.Now().Add(slice), func() bool {
			return len(blocked()) == 0
		})
		if cleared {
			return OK
		}
		if publish(blocked()) {
			return EAGAIN
		}
	}
}

// cleanWirePath canonicalizes a wire path the same way the authority
// resolves it, so gate decisions, policy stamps, and grants agree on one
// identity. Canonicalize ONCE at the coordinate boundary and pass only the
// canonical value downstream.
func cleanWirePath(p string) string {
	return strings.Trim(path.Clean("/"+p), "/")
}
