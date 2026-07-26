package main

import (
	"os"
	"testing"
	"time"
)

// envDurationMs backs the mount's opt-in cache knobs (PORTABLEFS_SESSION_TTL_MS).
// The parse must fail SAFE: anything unparseable or negative falls back to the
// default, because these env vars gate coherence-sensitive kernel caching and a
// typo must never silently enable a TTL.
func TestEnvDurationMs(t *testing.T) {
	const key = "PFS_TEST_DURATION_MS"
	cases := []struct {
		val  string
		def  time.Duration
		want time.Duration
	}{
		{"", 0, 0},
		{"", 5 * time.Millisecond, 5 * time.Millisecond},
		{"250", 0, 250 * time.Millisecond},
		{"0", time.Second, 0},
		{"garbage", 0, 0},
		{"garbage", time.Second, time.Second},
		{"-5", time.Second, time.Second},
		{"1.5", time.Second, time.Second}, // fractional ms is not accepted
	}
	for _, tc := range cases {
		t.Setenv(key, tc.val)
		if got := envDurationMs(key, tc.def); got != tc.want {
			t.Errorf("envDurationMs(%q, %v) = %v, want %v", tc.val, tc.def, got, tc.want)
		}
	}
}

// The compiled-in default MUST stay 0 (coherence by version/invalidation, never
// by time) when the env var is unset — the handoff data-loss postmortem baked
// into the sessionTTL comment depends on it.
func TestSessionTTLDefaultsToZero(t *testing.T) {
	if env := os.Getenv("PORTABLEFS_SESSION_TTL_MS"); env != "" {
		t.Skipf("PORTABLEFS_SESSION_TTL_MS=%q set in the test environment", env)
	}
	if sessionTTL != 0 {
		t.Fatalf("sessionTTL default = %v, want 0", sessionTTL)
	}
}

// PORTABLEFS_NEGATIVE_CACHE keeps working in both directions around the new
// capability-auto default: "1" forces on, "0" forces off, anything else
// (including unset) leaves the decision to the authority handshake.
func TestNegCacheEnvTriState(t *testing.T) {
	cases := []struct {
		val               string
		forceOn, forceOff bool
	}{
		{"", false, false},
		{"1", true, false},
		{"0", false, true},
		{"yes", false, false}, // unrecognized: auto, never a silent force
	}
	for _, tc := range cases {
		on, off := negCacheEnv(tc.val)
		if on != tc.forceOn || off != tc.forceOff {
			t.Errorf("negCacheEnv(%q) = (%v,%v), want (%v,%v)", tc.val, on, off, tc.forceOn, tc.forceOff)
		}
	}
}

// PORTABLEFS_OPEN_RETENTION_ENTRIES: unset/garbage = clientcore default,
// "0" = retention disabled (pre-retention behavior), N>0 = LRU cap.
func TestOpenRetentionEntriesEnv(t *testing.T) {
	const key = "PORTABLEFS_OPEN_RETENTION_ENTRIES"
	cases := []struct {
		val  string
		want int
	}{
		{"", 0},
		{"0", -1},
		{"1000", 1000},
		{"garbage", 0},
		{"-5", 0},
	}
	for _, tc := range cases {
		t.Setenv(key, tc.val)
		if got := openRetentionEntries(); got != tc.want {
			t.Errorf("openRetentionEntries with %q = %d, want %d", tc.val, got, tc.want)
		}
	}
}
