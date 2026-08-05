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
// The second is exclusion. A mutation shares the registration read lock, so
// mutations run concurrently when no strict mount exists. A routing change takes
// the write side. That is what makes the revision switch airtight for mounts
// that are not barrier participants at all: an uncached mount never receives an
// event, so the only thing that can keep it from operating under a topology it
// does not run is the fact that no request of its own can be executing at the
// instant the active revision changes, and no attach can be in progress either.
// Holding the write lock across the whole change is exactly that instant being
// empty. What refuses the uncached mount afterwards is its recorded attach
// revision no longer matching the active one - see the authority handler - which
// is authority-held state rather than a value the mount echoes back, so a mount
// cannot present agreement it does not have.
//
// commit installs the new rules durably and returns the revision that is active
// afterwards. It runs between the two phases, with every strict frontend's
// publication admission closed, exactly where a mutation's apply runs. If it
// fails it must return the revision that is still active: COMPLETE is delivered
// either way, because it is what reopens the frontends' gates, and it must tell
// them the truth about which topology they are running.
//
// The two outcomes reach different audiences. Route topology is fixed for the
// life of a mount, so a strict frontend that sees a *changed* revision in
// PREPARE reports itself blocked — which fences it immediately — and revokes;
// a successful change therefore normally completes against an audience those
// participants have already left, and each returns by re-attaching under the
// new revision. When commit fails, the revision is unchanged, no frontend
// treats the event as terminal, and COMPLETE reopens the survivors' gates.
// Neither outcome may wait out a repair budget for a mount that already said
// it cannot serve.
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
	// The write lock already excludes every Execute, so this cannot block on a
	// mutation. It is taken anyway because the deferred source acknowledgment of
	// the previous mutation is drained under it, and because a routing change
	// claiming a sequence out of band from mutation order would make the
	// per-participant cursor non-monotonic.
	select {
	case c.serial <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-c.serial }()
	if err := c.waitDeferred(ctx); err != nil {
		return 0, &VisibilityBarrierError{Err: err}
	}

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
