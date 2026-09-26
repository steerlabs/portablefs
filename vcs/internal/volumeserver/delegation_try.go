package volumeserver

import "context"

// TryDataConsumed is the nonblocking read admission used while a namespace
// identity probe owns its parent turn. It never waits for a peer or request.
func (c *CoherenceCoordinator) TryDataConsumed(ctx context.Context, token SubscriptionToken, identity [16]byte) (*DataGuard, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if identity == ([16]byte{}) {
		return nil, false, ErrCoherenceIdentity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	if _, err := c.subscriberLocked(token); err != nil {
		return nil, false, err
	}
	r := c.delegations[identity]
	if r != nil && !r.retired && r.owner.token == token {
		return &DataGuard{}, true, nil
	}
	if r != nil && !r.retired && r.grant.State == DelegationReserved && !r.closingReaders {
		r.readers++
		return &DataGuard{coordinator: c, record: r}, true, nil
	}
	if r != nil {
		return nil, false, nil
	}
	turn := c.requests.enqueue(delegationDependencies(identity))
	select {
	case <-turn.ready:
		return &DataGuard{turn: turn}, true, nil
	default:
		turn.abandon()
		return nil, false, nil
	}
}
