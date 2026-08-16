package main

import (
	"errors"
	"fmt"
)

const (
	defaultMaxSessions                 = 1024
	transportConnectionsPerLiveSession = 4
	defaultMaxConnections              = defaultMaxSessions * transportConnectionsPerLiveSession
)

// validateConnectionCapacity keeps physical transport admission ahead of the
// logical session limit. Protocol 5 holds one DATA and one CONTROL connection
// for every live mount. Exact pair recovery must authenticate both replacement
// roles before either old generation can be retired, so it can transiently hold
// old and candidate DATA/CONTROL pairs at the same time. Four is therefore the
// protocol's structural recovery bound, not discretionary handshake headroom.
func validateConnectionCapacity(maxSessions uint, maxConnections int) error {
	if maxSessions == 0 || maxConnections <= 0 {
		return errors.New("max-sessions and max-connections must be positive")
	}
	if uint64(maxSessions) > ^uint64(0)/transportConnectionsPerLiveSession {
		return errors.New("max-sessions is too large to size transport capacity")
	}
	minimum := uint64(maxSessions) * transportConnectionsPerLiveSession
	if uint64(maxConnections) < minimum {
		return fmt.Errorf("max-connections must be at least %d (4 per max-session: current and recovering DATA/CONTROL pairs)", minimum)
	}
	return nil
}
