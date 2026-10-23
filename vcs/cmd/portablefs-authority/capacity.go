package main

import (
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

const (
	defaultMaxSessions                 = 1024
	transportConnectionsPerLiveSession = 4
	defaultMaxConnections              = defaultMaxSessions * transportConnectionsPerLiveSession
	defaultMaxInFlight                 = 256
	defaultMaxWriteBytes               = 1 << 20
	defaultMaxFrameBytesInFlight       = 512 << 20
	// The authority has no item-capacity negotiation. This must remain at least
	// mountv3.NameCacheCapacity so a stock mount can retain its declared cache.
	defaultMaxItemsPerSession = 1 << 18
	// Leave descriptor headroom under the service's 1,048,576-fd limit for
	// opens, transport pairs and bounded directory-page probes.
	defaultMaxItems = 1 << 19
)

// validateConnectionCapacity keeps physical transport admission ahead of the
// logical session limit. Protocol 8 holds one DATA and one CONTROL connection
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

func validateExecutionCapacity(maxInFlight int, replaySlots uint, maxFrame uint, retained uint64) error {
	if maxInFlight < authorityrpc.MinimumLinuxInFlight || replaySlots < authorityrpc.MinimumLinuxInFlight {
		return errors.New("Linux authority needs at least nine execution lanes and replay slots")
	}
	// One maximal outcome plus the fixed replies for every ordered flush must
	// fit together. These are retained bytes, independent of inbound frame memory.
	minimum := uint64(maxFrame) + 4*uint64(authorityrpc.MinimumFrameBytes)
	if minimum < uint64(maxFrame) || retained < minimum {
		return fmt.Errorf("max-retained-reply-bytes must be at least %d for a maximal reply and four ordered flushes", minimum)
	}
	return nil
}
