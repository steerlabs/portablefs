//go:build !linux

package volumeserver

import (
	"testing"
	"time"
)

func TestUnsupportedContinuousClockRequiresExplicitInjection(t *testing.T) {
	if _, err := continuousNow(); err == nil {
		t.Fatal("unsupported platform supplied an unqualified clock")
	}
	cfg := Config{SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1}
	if _, err := New("clock", cfg); err == nil {
		t.Fatal("authority accepted an unqualified clock")
	}
	cfg.ContinuousNow = testContinuousNow
	if _, err := New("clock", cfg); err != nil {
		t.Fatalf("explicit test clock: %v", err)
	}
}
