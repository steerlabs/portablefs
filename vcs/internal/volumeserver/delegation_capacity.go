package volumeserver

import "errors"

var (
	ErrSessionDelegationLimit = errors.New("volumeserver: session delegation capacity exhausted")
	ErrVolumeDelegationLimit  = errors.New("volumeserver: volume delegation capacity exhausted")
)

// DelegationCapacity charges one future identity before an operation can create
// it in storage. ReserveNew transfers the charge; Release returns it on all
// other outcomes. A cold subscription or terminal session cannot free capacity
// while an admitted storage operation may still use it.
type DelegationCapacity struct {
	coordinator *CoherenceCoordinator
	owner       *changeSubscriber
	consumed    bool // coordinator.mu
}

func (c *CoherenceCoordinator) ReserveDelegationCapacity(token SubscriptionToken) (*DelegationCapacity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return nil, err
	}
	return c.chargeDelegationLocked(s)
}

func (c *CoherenceCoordinator) chargeDelegationLocked(s *changeSubscriber) (*DelegationCapacity, error) {
	if c.delegationCharges[s.token.Session] >= c.maxDelegationsPerSession {
		return nil, ErrSessionDelegationLimit
	}
	if len(c.delegations)+int(c.stats.DelegationCapacityReservations) >= c.maxDelegations {
		return nil, ErrVolumeDelegationLimit
	}
	c.delegationCharges[s.token.Session]++
	c.stats.DelegationCapacityReservations++
	return &DelegationCapacity{coordinator: c, owner: s}, nil
}

func (c *CoherenceCoordinator) releaseDelegationChargeLocked(id SessionID) {
	if c.delegationCharges[id] <= 0 {
		panic("volumeserver: delegation capacity underflow")
	}
	c.delegationCharges[id]--
	if c.delegationCharges[id] == 0 {
		delete(c.delegationCharges, id)
	}
}

func (capacity *DelegationCapacity) Release() {
	if capacity == nil {
		return
	}
	c := capacity.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	if !capacity.consumed {
		capacity.consumed = true
		c.stats.DelegationCapacityReservations--
		c.releaseDelegationChargeLocked(capacity.owner.token.Session)
	}
}

func (capacity *DelegationCapacity) ReserveNew(identity [16]byte) (*DelegationReservation, error) {
	if capacity == nil {
		return nil, ErrDelegationStale
	}
	c := capacity.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	if capacity.consumed {
		return nil, ErrDelegationStale
	}
	if identity == ([16]byte{}) {
		return nil, ErrCoherenceIdentity
	}
	if _, err := c.subscriberLocked(capacity.owner.token); err != nil {
		return nil, err
	}
	if c.delegations[identity] != nil {
		return nil, ErrDelegationBusy
	}
	return c.reserveChargedLocked(capacity, identity, nil, false), nil
}

func (c *CoherenceCoordinator) setDelegationStateLocked(r *delegationRecord, state DelegationState) {
	adjust := func(value DelegationState, delta int) {
		var counter *uint64
		switch value {
		case DelegationReserved:
			counter = &c.stats.DelegationsReserved
		case DelegationActive:
			counter = &c.stats.DelegationsActive
		case DelegationRecalling:
			counter = &c.stats.DelegationsRecalling
		}
		if counter != nil {
			if delta < 0 {
				if *counter == 0 {
					panic("volumeserver: delegation state count underflow")
				}
				*counter--
			} else {
				*counter++
			}
		}
	}
	adjust(r.grant.State, -1)
	r.grant.State = state
	adjust(state, 1)
}
