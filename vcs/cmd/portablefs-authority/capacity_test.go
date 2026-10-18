package main

import (
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

func TestShippedDefaultFrameCapacity(t *testing.T) {
	// These are the constants used by main_linux.go's flag registrations, not
	// a reduced connection-count fixture that could hide a default startup refusal.
	if err := validateConnectionCapacity(defaultMaxSessions, defaultMaxConnections); err != nil {
		t.Fatal(err)
	}
	minimum := authorityrpc.MinimumFrameBytesInFlight(defaultMaxWriteBytes + authorityrpc.FramePayloadReserve)
	if defaultMaxFrameBytesInFlight < minimum {
		t.Fatalf("shipped frame budget %d < startup floor %d (connections %d)", defaultMaxFrameBytesInFlight, minimum, defaultMaxConnections)
	}
}

func TestValidateConnectionCapacity(t *testing.T) {
	tests := []struct {
		name           string
		maxSessions    uint
		maxConnections int
		wantErr        string
	}{
		{name: "default", maxSessions: defaultMaxSessions, maxConnections: defaultMaxConnections},
		{name: "custom boundary", maxSessions: 7, maxConnections: 28},
		{name: "old two lane default cannot recover a pair", maxSessions: 1024, maxConnections: 2048, wantErr: "at least 4096"},
		{name: "old three lane default cannot recover a pair", maxSessions: 1024, maxConnections: 3072, wantErr: "at least 4096"},
		{name: "one below boundary", maxSessions: 7, maxConnections: 27, wantErr: "at least 28"},
		{name: "zero sessions", maxConnections: 4, wantErr: "must be positive"},
		{name: "zero connections", maxSessions: 1, wantErr: "must be positive"},
		{name: "negative connections", maxSessions: 1, maxConnections: -1, wantErr: "must be positive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConnectionCapacity(test.maxSessions, test.maxConnections)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("valid capacity rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestLinuxExecutionCapacityIncludesOrderedReplay(t *testing.T) {
	const frame = 1 << 20
	minimum := uint64(frame) + 4*uint64(authorityrpc.MinimumFrameBytes)
	for _, test := range []struct {
		flight int
		slots  uint
		bytes  uint64
		ok     bool
	}{
		{9, 9, minimum, true}, {8, 9, minimum, false}, {9, 8, minimum, false}, {9, 9, minimum - 1, false},
	} {
		if err := validateExecutionCapacity(test.flight, test.slots, frame, test.bytes); (err == nil) != test.ok {
			t.Fatalf("%+v: %v", test, err)
		}
	}
}
