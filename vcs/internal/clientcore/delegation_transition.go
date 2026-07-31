package clientcore

import (
	"context"
	"strings"
	"sync"
)

// delegationTransitionKind distinguishes the two sides of one ownership
// transition. Claims on the same side never exclude one another: unrelated
// authority mutations and unrelated delegation acquisitions remain fully
// concurrent. Opposite claims exclude only when a pathname subtree or
// authority inode identity overlaps.
type delegationTransitionKind uint8

const (
	authorityTransition delegationTransitionKind = iota + 1
	acquireTransition
)

type delegationTransitionTargets struct {
	paths []string
	inos  map[uint64]struct{}
}

type delegationTransitionClaim struct {
	gate    *delegationTransitionGate
	kind    delegationTransitionKind
	targets delegationTransitionTargets
	startSeq uint64
	ended   bool
}

type delegationTransitionWaiter struct {
	kind    delegationTransitionKind
	targets delegationTransitionTargets
}

// delegationTransitionGate is a cancellable, overlap-aware ownership gate.
//
// A remote delegation resolver owns an acquire claim from before its RPC
// through local grant installation. A path-bearing authority mutation owns
// an authority claim from its final delegation recheck through its RPC. The
// two therefore have one deterministic order for every overlapping subtree
// or hard-linked inode, without serializing independent directories.
//
// Waiting claims also respect earlier conflicting waiters, preventing a hot
// stream of same-side operations from starving ownership transfer.
type delegationTransitionGate struct {
	mu      sync.Mutex
	changed chan struct{}
	active  map[*delegationTransitionClaim]struct{}
	waiters []*delegationTransitionWaiter

	// authoritySeq and lastAuthorityIno retain exactly the completion history
	// needed by currently active acquire claims. A delayed acquire reply may
	// contain a snapshot taken before a disjoint hardlink alias mutated; its
	// inode promotion is rejected when that completion is newer than the
	// claim's start sequence. History is cleared as soon as no older acquire
	// can observe it, so the map is bounded by mutations concurrent with
	// live remote acquire resolutions rather than mount lifetime.
	authoritySeq    uint64
	lastAuthorityIno map[uint64]uint64
}

func (g *delegationTransitionGate) begin(
	ctx context.Context,
	kind delegationTransitionKind,
	paths []string,
	inos []uint64,
) (*delegationTransitionClaim, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	waiter := &delegationTransitionWaiter{
		kind:    kind,
		targets: makeDelegationTransitionTargets(paths, inos),
	}
	g.mu.Lock()
	g.waiters = append(g.waiters, waiter)
	for {
		if err := ctx.Err(); err != nil {
			g.removeWaiterLocked(waiter)
			g.signalLocked()
			g.mu.Unlock()
			return nil, err
		}
		if !g.waiterBlockedLocked(waiter) {
			g.removeWaiterLocked(waiter)
			claim := &delegationTransitionClaim{
				gate:    g,
				kind:    kind,
				targets: waiter.targets,
			}
			if kind == acquireTransition {
				claim.startSeq = g.authoritySeq
			}
			if g.active == nil {
				g.active = make(map[*delegationTransitionClaim]struct{})
			}
			g.active[claim] = struct{}{}
			g.signalLocked()
			g.mu.Unlock()
			return claim, nil
		}
		changed := g.changeSignalLocked()
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			g.mu.Lock()
			g.removeWaiterLocked(waiter)
			g.signalLocked()
			g.mu.Unlock()
			return nil, ctx.Err()
		}
		g.mu.Lock()
	}
}

// extend adds reply-discovered identities or newly snapshotted aliases to an
// active claim. It retains the claim's existing targets while waiting. That
// is safe because only acquisition claims extend dynamically; an authority
// claim is admitted atomically with every identity it can already know, so
// it never waits on an acquisition whose path it is already excluding.
func (c *delegationTransitionClaim) extend(
	ctx context.Context,
	paths []string,
	inos []uint64,
) error {
	if c == nil || c.gate == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	added := makeDelegationTransitionTargets(paths, inos)
	g := c.gate
	g.mu.Lock()
	for {
		if err := ctx.Err(); err != nil {
			g.mu.Unlock()
			return err
		}
		if c.ended {
			g.mu.Unlock()
			return context.Canceled
		}
		candidate := mergeDelegationTransitionTargets(c.targets, added)
		if !g.conflictsWithActiveLocked(c.kind, candidate, c) {
			c.targets = candidate
			g.signalLocked()
			g.mu.Unlock()
			return nil
		}
		changed := g.changeSignalLocked()
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
		g.mu.Lock()
	}
}

// reconcileAcquire atomically promotes a path-only acquire claim with the
// authority identities discovered in its complete reply and publishes those
// observations under the coordinator→hardlink-index lock order. If a
// disjoint path aliases an active authority mutation, the grant is refused
// locally and released without ever becoming visible to engine readers.
func (c *delegationTransitionClaim) reconcileAcquire(
	paths []string,
	inos []uint64,
	publish func(),
) bool {
	if c == nil || c.gate == nil {
		if publish != nil {
			publish()
		}
		return true
	}
	g := c.gate
	added := makeDelegationTransitionTargets(paths, inos)
	g.mu.Lock()
	defer g.mu.Unlock()
	if c.ended {
		return false
	}
	candidate := mergeDelegationTransitionTargets(c.targets, added)
	for active := range g.active {
		if active == c || active.kind != authorityTransition {
			continue
		}
		if delegationTransitionTargetsOverlap(active.targets, candidate) {
			if publish != nil {
				publish()
			}
			return false
		}
	}
	for ino := range candidate.inos {
		if g.lastAuthorityIno[ino] > c.startSeq {
			if publish != nil {
				publish()
			}
			return false
		}
	}
	c.targets = candidate
	if publish != nil {
		publish()
	}
	g.signalLocked()
	return true
}

func (c *delegationTransitionClaim) end() {
	if c == nil || c.gate == nil {
		return
	}
	g := c.gate
	g.mu.Lock()
	if !c.ended {
		c.ended = true
		if c.kind == authorityTransition {
			g.authoritySeq++
			if g.hasActiveAcquireLocked(c) {
				if g.lastAuthorityIno == nil {
					g.lastAuthorityIno = make(map[uint64]uint64)
				}
				for ino := range c.targets.inos {
					g.lastAuthorityIno[ino] = g.authoritySeq
				}
			}
		}
		delete(g.active, c)
		g.pruneAuthorityHistoryLocked()
		g.signalLocked()
	}
	g.mu.Unlock()
}

func (g *delegationTransitionGate) hasActiveAcquireLocked(
	except *delegationTransitionClaim,
) bool {
	for claim := range g.active {
		if claim != except && claim.kind == acquireTransition && !claim.ended {
			return true
		}
	}
	return false
}

func (g *delegationTransitionGate) pruneAuthorityHistoryLocked() {
	var (
		minStart uint64
		found    bool
	)
	for claim := range g.active {
		if claim.ended || claim.kind != acquireTransition {
			continue
		}
		if !found || claim.startSeq < minStart {
			minStart = claim.startSeq
			found = true
		}
	}
	if !found {
		clear(g.lastAuthorityIno)
		return
	}
	for ino, completedAt := range g.lastAuthorityIno {
		if completedAt <= minStart {
			delete(g.lastAuthorityIno, ino)
		}
	}
}

func (g *delegationTransitionGate) waiterBlockedLocked(
	waiter *delegationTransitionWaiter,
) bool {
	if g.conflictsWithActiveLocked(waiter.kind, waiter.targets, nil) {
		return true
	}
	for _, earlier := range g.waiters {
		if earlier == waiter {
			return false
		}
		if delegationTransitionKindsConflict(earlier.kind, waiter.kind) &&
			delegationTransitionTargetsOverlap(earlier.targets, waiter.targets) {
			return true
		}
	}
	return false
}

func (g *delegationTransitionGate) conflictsWithActiveLocked(
	kind delegationTransitionKind,
	targets delegationTransitionTargets,
	except *delegationTransitionClaim,
) bool {
	for claim := range g.active {
		if claim == except || !delegationTransitionKindsConflict(claim.kind, kind) {
			continue
		}
		if delegationTransitionTargetsOverlap(claim.targets, targets) {
			return true
		}
	}
	return false
}

func delegationTransitionKindsConflict(
	a delegationTransitionKind,
	b delegationTransitionKind,
) bool {
	// Authority mutations share their lane. Acquisitions exclude overlapping
	// acquisitions too: the authority can decide only one overlapping scope,
	// and serializing that rare overlap avoids redundant exact requests.
	return a != authorityTransition || b != authorityTransition
}

func (g *delegationTransitionGate) removeWaiterLocked(
	target *delegationTransitionWaiter,
) {
	for i, waiter := range g.waiters {
		if waiter != target {
			continue
		}
		copy(g.waiters[i:], g.waiters[i+1:])
		g.waiters[len(g.waiters)-1] = nil
		g.waiters = g.waiters[:len(g.waiters)-1]
		return
	}
}

func (g *delegationTransitionGate) changeSignalLocked() <-chan struct{} {
	if g.changed == nil {
		g.changed = make(chan struct{})
	}
	return g.changed
}

func (g *delegationTransitionGate) signalLocked() {
	if g.changed != nil {
		close(g.changed)
		g.changed = nil
	}
}

func makeDelegationTransitionTargets(
	paths []string,
	inos []uint64,
) delegationTransitionTargets {
	targets := delegationTransitionTargets{inos: make(map[uint64]struct{})}
	seenPaths := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		path := cleanVolumePath(raw)
		if path == "" {
			continue
		}
		if _, ok := seenPaths[path]; ok {
			continue
		}
		seenPaths[path] = struct{}{}
		targets.paths = append(targets.paths, path)
	}
	for _, ino := range inos {
		if ino != 0 {
			targets.inos[ino] = struct{}{}
		}
	}
	return targets
}

func mergeDelegationTransitionTargets(
	current delegationTransitionTargets,
	added delegationTransitionTargets,
) delegationTransitionTargets {
	paths := append([]string(nil), current.paths...)
	seenPaths := make(map[string]struct{}, len(paths)+len(added.paths))
	for _, path := range paths {
		seenPaths[path] = struct{}{}
	}
	for _, path := range added.paths {
		if _, ok := seenPaths[path]; ok {
			continue
		}
		seenPaths[path] = struct{}{}
		paths = append(paths, path)
	}
	inos := make(map[uint64]struct{}, len(current.inos)+len(added.inos))
	for ino := range current.inos {
		inos[ino] = struct{}{}
	}
	for ino := range added.inos {
		inos[ino] = struct{}{}
	}
	return delegationTransitionTargets{paths: paths, inos: inos}
}

func delegationTransitionTargetsOverlap(
	a delegationTransitionTargets,
	b delegationTransitionTargets,
) bool {
	for ino := range a.inos {
		if _, ok := b.inos[ino]; ok {
			return true
		}
	}
	for _, left := range a.paths {
		for _, right := range b.paths {
			if delegationTransitionPathsOverlap(left, right) {
				return true
			}
		}
	}
	return false
}

func delegationTransitionPathsOverlap(a, b string) bool {
	return a == b ||
		strings.HasPrefix(a, b+"/") ||
		strings.HasPrefix(b, a+"/")
}
