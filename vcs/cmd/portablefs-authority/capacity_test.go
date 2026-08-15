package main

import (
	"strings"
	"testing"
)

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
