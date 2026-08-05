package authorityrpc

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// A blocking lock wait parks for as long as the conflicting holder chooses.
// Classifying it as a topology request would hold the coordinator's read
// guard across that unbounded park, so one waiter plus one queued ApplyRoutes
// writer would stall every guarded request on the volume. The wait never
// reaches XFS — the lock table is authority-epoch runtime state — so it is
// admitted through the ordinary session-routes check instead. Non-blocking
// lock calls complete immediately and keep the guard.
func TestRequestUsesTopologyReleasesBlockingLockWaits(t *testing.T) {
	setLock := func(wait, unlock bool) *authoritypb.Request {
		return &authoritypb.Request{Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{
			Lock: &authoritypb.LockSpec{Write: true, Range: &authoritypb.LockRange{}}, Wait: wait, Unlock: unlock,
		}}}
	}
	if requestUsesTopology(setLock(true, false)) {
		t.Fatal("a blocking lock wait must not hold the topology read guard")
	}
	if !requestUsesTopology(setLock(false, false)) {
		t.Fatal("a non-blocking lock call completes immediately and keeps the guard")
	}
	if !requestUsesTopology(setLock(true, true)) {
		t.Fatal("an unlock never blocks and keeps the guard")
	}
	if !requestUsesTopology(&authoritypb.Request{Body: &authoritypb.Request_GetLock{GetLock: &authoritypb.GetLockRequest{}}}) {
		t.Fatal("a lock query completes immediately and keeps the guard")
	}
}
