package volumeserver

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"
)

// DataConsumedSet retains one atomic request footprint for a directory page.
// Reservation readers bypass the corresponding request keys: a reservation
// owns that key until Grant, which itself must join those readers.
func (c *CoherenceCoordinator) DataConsumedSet(ctx context.Context, token SubscriptionToken, identities [][16]byte) (*DataGuard, error) {
	return c.consumeSet(ctx, &token, identities)
}

// BreakForReadSet is the authenticated CACHELESS_READER form. Unlike the
// single-identity compatibility helper, its guard covers the storage sample.
func (c *CoherenceCoordinator) BreakForReadSet(ctx context.Context, identities [][16]byte) (*DataGuard, error) {
	return c.consumeSet(ctx, nil, identities)
}

func (c *CoherenceCoordinator) consumeSet(ctx context.Context, token *SubscriptionToken, identities [][16]byte) (*DataGuard, error) {
	pending := slices.Clone(identities)
	slices.SortFunc(pending, func(a, b [16]byte) int { return bytes.Compare(a[:], b[:]) })
	pending = slices.Compact(pending)
	if len(pending) == 0 || pending[0] == ([16]byte{}) {
		return nil, ErrCoherenceIdentity
	}
	guard := &DataGuard{coordinator: c}
	success := false
	defer func() {
		if !success {
			if guard.turn != nil {
				guard.turn.abandon()
				guard.turn = nil
			}
			guard.Release()
		}
	}()
	var completed map[*delegationRecord]bool
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.expireLocked()
		deadline := c.clock.Now().Add(SubscriptionTTL)
		if token != nil {
			subscriber, err := c.subscriberLocked(*token)
			if err != nil {
				c.mu.Unlock()
				return nil, err
			}
			deadline = subscriber.horizon
		}
		changedFootprint := false
		retained := pending[:0]
		for _, identity := range pending {
			r := c.delegations[identity]
			own := r != nil && token != nil && r.owner.token == *token && r.grant.State != DelegationReserved
			if r != nil && !r.retired && (own || r.grant.State == DelegationReserved && !r.closingReaders) {
				r.readers++
				guard.records = append(guard.records, r)
				changedFootprint = true
			} else {
				retained = append(retained, identity)
			}
		}
		pending = retained
		if changedFootprint && guard.turn != nil {
			// A reservation can appear after our first scan but before its owner
			// releases a previously acquired turn. Rebuild under the coordinator
			// lock so its reader pin cannot wait behind that same reservation.
			guard.turn.abandon()
			guard.turn = nil
		}
		if len(pending) != 0 && guard.turn == nil {
			keys := make([][]byte, 0, len(pending))
			for _, identity := range pending {
				keys = append(keys, inodeKey(identity))
			}
			guard.turn = c.requests.enqueue(newMutationDependencies(keys...))
		}
		ready := guard.turn == nil
		if !ready {
			select {
			case <-guard.turn.ready:
				ready = true
			default:
			}
		}
		var cut *delegationRecord
		blocked := false
		for _, r := range guard.records {
			if !r.retired {
				deadline = minTime(deadline, r.owner.horizon)
			}
		}
		for _, identity := range pending {
			r := c.delegations[identity]
			if r == nil {
				continue
			}
			if !r.retired {
				deadline = minTime(deadline, r.owner.horizon)
			}
			if !ready {
				continue
			}
			if r.retired || r.grant.State == DelegationReserved {
				blocked = true
			} else if !completed[r] && cut == nil {
				cut = r
			}
		}
		if ready && !blocked && cut == nil {
			c.mu.Unlock()
			success = true
			return guard, nil
		}
		changed := c.notificationLocked()
		c.mu.Unlock()
		if cut != nil {
			sequence, err := c.cut(ctx, cut, false)
			if errors.Is(err, errDelegationRetry) {
				continue
			}
			if err != nil {
				return nil, err
			}
			guard.AppliedSequence = max(guard.AppliedSequence, sequence)
			if completed == nil {
				completed = make(map[*delegationRecord]bool)
			}
			completed[cut] = true
			continue
		}
		// Retired active pins have no remaining lease deadline. Avoid spinning
		// once the subscriber/holder clock expires while their storage call drains.
		if !deadline.After(c.clock.Now()) {
			deadline = time.Time{}
		}
		if ready {
			if err := c.wait(ctx, changed, deadline); err != nil {
				return nil, err
			}
		} else {
			var timer CoherenceTimer
			var tick <-chan time.Time
			if !deadline.IsZero() {
				timer = c.clock.NewTimer(deadline.Sub(c.clock.Now()))
				tick = timer.C()
			}
			select {
			case <-guard.turn.ready:
			case <-changed:
			case <-tick:
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return nil, ctx.Err()
			}
			if timer != nil {
				timer.Stop()
			}
		}
	}
}
