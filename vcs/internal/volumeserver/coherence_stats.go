package volumeserver

// CoherenceStats is one constant-time snapshot of retained coordination state.
// Scraping neither expires authority nor changes a lease. SubscriptionHorizons
// includes fenced readers whose last cache promise has not been swept yet.
type CoherenceStats struct {
	SubscriptionHorizons           uint64
	SubscriptionResets             uint64
	SubscriptionExpirations        uint64
	PendingStreamEntries           uint64
	DelegationCapacityReservations uint64
	DelegationsReserved            uint64
	DelegationsActive              uint64
	DelegationsRecalling           uint64
	DelegationsRetiring            uint64
	RecallCompleted                uint64
	RecallLost                     uint64
	BreakCompleted                 uint64
	BreakLost                      uint64
}

func (c *CoherenceCoordinator) Stats() CoherenceStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	stats := c.stats
	stats.SubscriptionHorizons = uint64(c.horizons.Len())
	stats.PendingStreamEntries = c.position - c.first + 1
	return stats
}
