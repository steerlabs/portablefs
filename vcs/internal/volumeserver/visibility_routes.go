package volumeserver

import (
	"context"
	"errors"
)

// ExecuteTopologyExclusive runs one protocol-6 route transition while no
// filesystem request, attach, or competing route change can straddle the
// revision switch. LeaseCoordinator owns event delivery; this coordinator
// retains only the topology/registration exclusion and startup proof.
func (c *VisibilityCoordinator) ExecuteTopologyExclusive(ctx context.Context, execute func() (int, error)) (int, error) {
	if ctx == nil || execute == nil {
		return 0, errors.New("volumeserver: topology transition needs a context and executor")
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
	return execute()
}
