package mountv3

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// Both Linux frontends attach with these defaults. A default below the Linux
// minimum would be refused by the transport before Activate, so every shipped
// mount would fail closed; replay slots must also cover every in-flight
// mutation, including the four ordered flushes.
func TestDefaultsAdmitTheMandatoryLinuxLanes(t *testing.T) {
	if MaxInFlight < authorityrpc.MinimumLinuxInFlight {
		t.Fatalf("MaxInFlight = %d, below the Linux minimum %d", MaxInFlight, authorityrpc.MinimumLinuxInFlight)
	}
	if uint64(ReplaySlots) < uint64(MaxInFlight) {
		t.Fatalf("ReplaySlots = %d cannot cover MaxInFlight = %d", ReplaySlots, MaxInFlight)
	}
	if MaxFrame < authorityrpc.MinimumFrameBytes {
		t.Fatalf("MaxFrame = %d, below the transport minimum %d", MaxFrame, authorityrpc.MinimumFrameBytes)
	}
	if NameCacheCapacity <= 0 || WithdrawalTimeout <= 0 || RequestTimeout <= 0 || DialTimeout <= 0 || CancelDrainTimeout <= 0 || ReclaimQueue <= 0 {
		t.Fatal("local bounds must be positive")
	}
}
