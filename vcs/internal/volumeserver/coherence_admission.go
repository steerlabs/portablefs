package volumeserver

// CheckCompatibilityWriter refuses a writer while another FSKit mount owns
// the compatibility exclusion. The handler holds its activation admission
// guard across this check and the operation which can establish write intent.
func (c *VisibilityCoordinator) CheckCompatibilityWriter(source SessionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, p := range c.participants {
		if id != source && p.compatibilityWriter {
			return ErrCompatibilityWriterLease
		}
	}
	return nil
}

// DelegatedIdentities is a point snapshot used when a Mac compatibility mount
// takes exclusive writer admission. It includes reservations: those must also
// retire before an unrevocable Mac cache can become active.
func (c *CoherenceCoordinator) DelegatedIdentities() [][16]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([][16]byte, 0, len(c.delegations))
	for identity := range c.delegations {
		result = append(result, identity)
	}
	return result
}
