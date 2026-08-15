package volumeserver

import (
	"context"
	"errors"
)

// ExecuteRoutes installs one volume-wide machine-local routing revision through
// the same two-phase barrier an ordinary mutation uses. It is deliberately not
// a second consensus mechanism: it claims the same sequence counter, builds the
// same deliveries, waits on the same per-participant repair budgets, and fences
// through the same participant-scoped path. The only things it does differently
// are the two that are actually different about a routing change.
//
// The first is the audience. A mutation addresses the mounts that may hold the
// coordinates it changes, and the resolved-name index answers that exactly.
// Routing topology is not a coordinate: every mount runs it, so every strict
// participant is in the audience unconditionally. There is nothing an index
// could rule out.
//
// The second is exclusion. Ordinary mutations and attaches share the
// registration read lock; a routing change takes the write side. Holding it
// across the whole change prevents any request or attach from straddling the
// revision switch, while the peer-only phases close every active frontend's
// publication admission around the commit.
//
// commit installs the new rules durably and returns the revision that is active
// afterwards. It runs between the two phases, with every strict frontend's
// publication admission closed, exactly where a mutation's apply runs. If it
// fails it must return the revision that is still active. COMPLETE carries that
// truthful active declaration to any participant that actually ACKed PREPARE
// and remained live, allowing a future explicitly reversible frontend to reopen.
// It does not resurrect a participant that already revoked and left.
//
// Current production frontends treat a changed route PREPARE as terminal:
// Linux reports blocked and macOS fails its strict bridge, so both are fenced
// before commit and re-attach under the active revision. A successful change
// therefore normally completes against an audience those participants have
// already left. On commit failure, COMPLETE carries whichever revision commit
// reports actually active — old for a definite pre-publication failure, next for
// a post-rename durability-uncertain failure — only to nonterminal protocol
// participants; it is not a claim that current
// production mounts survived PREPARE. A blocked report avoids the phase
// deadline; `awaitAll` waits only the required post-fence kernel-watchdog grace
// before commit.
func (c *VisibilityCoordinator) ExecuteRoutes(ctx context.Context, next RoutesChange, commit func() (RoutesChange, error)) (int, error) {
	return c.ExecuteRoutesChecked(ctx, next, nil, commit)
}

// ExecuteRoutesChecked is ExecuteRoutes with an authoritative precondition.
// check runs after the topology and registration write locks are held and
// before PREPARE is visible to any participant. Returning apply=false performs
// no barrier and no commit. RoutesController uses this point for compare-and-
// swap and same-revision detection: two callers that presented the same old
// revision are serialized before either can decide it still matches.
func (c *VisibilityCoordinator) ExecuteRoutesChecked(ctx context.Context, next RoutesChange, check func() (apply bool, err error), commit func() (RoutesChange, error)) (int, error) {
	if ctx == nil || commit == nil {
		return 0, errors.New("volumeserver: routing change needs a context and a durable commit")
	}
	c.topology.Lock()
	defer c.topology.Unlock()
	c.registration.Lock()
	defer c.registration.Unlock()
	c.mu.Lock()
	ready, poisoned := c.startupReady, c.poisoned
	c.mu.Unlock()
	if !ready {
		return 0, &VisibilityBarrierError{Err: ErrVisibilityStartup}
	}
	if poisoned != nil {
		return 0, &VisibilityBarrierError{Err: poisoned}
	}
	if check != nil {
		apply, err := check()
		if err != nil || !apply {
			return 0, err
		}
	}
	// The write lock already excludes every Execute, so this normally grants
	// immediately. It is taken anyway because a routing change claiming a
	// sequence out of mutation order would make the per-participant cursor
	// non-monotonic.
	turn, err := c.order.acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer turn.release()
	ticket := VisibilityEvent{Routes: next.clone()}
	audience, deliveries, err := c.openRoutesBarrier(&ticket)
	if err != nil {
		return 0, &VisibilityBarrierError{Err: err}
	}
	if err := c.awaitAll(deliveries); err != nil {
		return 0, &VisibilityBarrierError{Err: err}
	}

	active, commitErr := commit()
	applied := active.Revision == next.Revision
	ticket.Cursor.Phase = VisibilityComplete
	ticket.Routes = active.clone()
	complete, err := c.dispatch(ticket, audience, nil)
	if err != nil {
		return 0, &VisibilityBarrierError{Applied: applied, Err: errors.Join(commitErr, err)}
	}
	if err := c.awaitAll(complete); err != nil {
		return 0, &VisibilityBarrierError{Applied: applied, Err: errors.Join(commitErr, err)}
	}
	if commitErr != nil {
		return 0, &VisibilityBarrierError{Applied: applied, Err: commitErr}
	}
	return c.liveAudience(audience), nil
}

// openRoutesBarrier claims the sequence and addresses every strict participant.
// No coordinate is published as in flight: a routing change alters no name and
// no inode, so a concurrent read has nothing to race against and must not be
// made to wait.
func (c *VisibilityCoordinator) openRoutesBarrier(ticket *VisibilityEvent) (visibilityAudience, []*visibilityDelivery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.poisoned != nil {
		return visibilityAudience{}, nil, c.poisoned
	}
	c.next++
	ticket.Cursor = VisibilityCursor{Sequence: c.next, Phase: VisibilityPrepare}
	var audience visibilityAudience
	for _, p := range c.participants {
		audience.members = append(audience.members, p)
	}
	deliveries, err := c.dispatchLocked(*ticket, audience, nil)
	if err != nil {
		return visibilityAudience{}, nil, err
	}
	return audience, deliveries, nil
}

// liveAudience counts the members of an audience that are still participants.
// The difference between it and the audience size is exactly the number of
// mounts this change fenced.
func (c *VisibilityCoordinator) liveAudience(audience visibilityAudience) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := 0
	for _, p := range audience.members {
		if c.participants[p.id] == p {
			live++
		}
	}
	return live
}
