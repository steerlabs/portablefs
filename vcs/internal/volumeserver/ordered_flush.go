package volumeserver

import "context"

const OrderedFlushWindow = 4

// OrderedFlush holds a place in a delegation's accepted WRITE sequence. Exact
// replay must be resolved before registration. A ticket is completed on every
// recorded outcome, including definite no-apply errors. An unrecorded refusal
// aborts the delegation instead of leaving successors behind an unfillable gap.
type OrderedFlush struct {
	coordinator    *CoherenceCoordinator
	record         *delegationRecord
	sequence       uint64
	started, ended bool // coordinator.mu
}

func (c *CoherenceCoordinator) BeginOrderedFlush(token SubscriptionToken, id, generation, sequence uint64, mutation MutationID) (*OrderedFlush, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return nil, err
	}
	r := c.delegationsByID[id]
	if r == nil || r.retired || r.owner != s || r.grant.Generation != generation || r.grant.State == DelegationReserved {
		return nil, ErrDelegationStale
	}
	if r.pending != nil && !c.clock.Now().Before(r.pending.deadline) {
		c.dropDelegationLocked(r, true)
		return nil, ErrDelegationStale
	}
	if sequence == 0 || sequence <= r.flushSequence || sequence-r.flushSequence > OrderedFlushWindow || r.ordered[sequence] != nil {
		return nil, ErrDelegationAck
	}
	if r.ordered == nil {
		r.ordered = make(map[uint64]*OrderedFlush, OrderedFlushWindow)
	}
	ticket := &OrderedFlush{coordinator: c, record: r, sequence: sequence}
	r.ordered[sequence] = ticket
	r.active++
	return ticket, nil
}

// Wait must precede all storage dependency acquisition. CONTROL and the
// predecessor's replay slot remain free to complete while a successor waits.
func (t *OrderedFlush) Wait(ctx context.Context) error {
	for {
		c := t.coordinator
		c.mu.Lock()
		c.expireLocked()
		r := t.record
		if t.ended || r.retired || r.owner.fenced {
			c.mu.Unlock()
			return ErrDelegationStale
		}
		deadline := r.owner.horizon
		if r.pending != nil {
			deadline = minTime(deadline, r.pending.deadline)
		}
		if !c.clock.Now().Before(deadline) {
			c.dropDelegationLocked(r, true)
			c.mu.Unlock()
			return ErrDelegationStale
		}
		if t.sequence == r.flushSequence+1 {
			t.started = true
			c.mu.Unlock()
			return nil
		}
		changed := c.notificationLocked()
		c.mu.Unlock()
		if err := c.wait(ctx, changed, deadline); err != nil {
			return err
		}
	}
}

func (t *OrderedFlush) Complete() {
	if t == nil {
		return
	}
	c := t.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	if t.ended {
		return
	}
	if !t.started {
		t.abortLocked()
		return
	}
	t.ended = true
	r := t.record
	delete(r.ordered, t.sequence)
	r.flushSequence = t.sequence
	r.active--
	c.finishRetiredLocked(r)
	c.signalLocked()
}
func (t *OrderedFlush) Abort() {
	if t == nil {
		return
	}
	c := t.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	t.abortLocked()
}
func (t *OrderedFlush) abortLocked() {
	if t.ended {
		return
	}
	t.ended = true
	r := t.record
	c := t.coordinator
	delete(r.ordered, t.sequence)
	c.dropDelegationLocked(r, true)
	r.active--
	c.finishRetiredLocked(r)
	c.signalLocked()
}

// AbortOrderedFlushes is the authenticated pre-replay refusal boundary. There
// is no recorded result to consume this ordinal; retire the exact grant so all
// already-dispatched successors fail rather than apply across the missing write.
func (c *CoherenceCoordinator) AbortOrderedFlushes(session SessionID, id, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r := c.delegationsByID[id]; r != nil && r.owner.token.Session == session && r.grant.Generation == generation {
		c.dropDelegationLocked(r, true)
	}
}
