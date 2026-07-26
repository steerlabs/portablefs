package fsproto

import (
	"testing"
	"time"
)

// TestBackoffBoundGrowthAndCap pins the full-jitter schedule deterministically
// by making the jitter draw its maximum: bounds double from the base and clamp
// at the cap.
func TestBackoffBoundGrowthAndCap(t *testing.T) {
	b := NewBackoff(250*time.Millisecond, 15*time.Second)
	b.rand = func(n int64) int64 { return n - 1 } // max draw = bound-1ns
	want := []time.Duration{
		250 * time.Millisecond,
		500 * time.Millisecond,
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		15 * time.Second, // 16s clamps to the cap
		15 * time.Second, // and stays there
	}
	for i, w := range want {
		if got := b.Next(); got != w-time.Nanosecond {
			t.Fatalf("attempt %d: bound = %v, want %v", i, got+time.Nanosecond, w)
		}
	}
}

// TestBackoffResetRestartsFromBase: success resets the schedule so the next
// failure's first retry is fast again.
func TestBackoffResetRestartsFromBase(t *testing.T) {
	b := NewBackoff(250*time.Millisecond, 15*time.Second)
	b.rand = func(n int64) int64 { return n - 1 }
	for i := 0; i < 10; i++ {
		_ = b.Next()
	}
	b.Reset()
	if got := b.Next(); got != 250*time.Millisecond-time.Nanosecond {
		t.Fatalf("post-reset bound = %v, want the base again", got+time.Nanosecond)
	}
}

// TestBackoffJitterWithinBounds: real draws are full-jitter — anywhere in
// [0, bound), never at or above it.
func TestBackoffJitterWithinBounds(t *testing.T) {
	b := NewBackoff(250*time.Millisecond, 15*time.Second)
	for i := 0; i < 200; i++ {
		d := b.Next()
		bound := b.bound(i)
		if d < 0 || d >= bound {
			t.Fatalf("attempt %d: draw %v outside [0, %v)", i, d, bound)
		}
	}
	// Zero-jitter floor: the minimum draw is genuinely 0 (full jitter, not a
	// jittered floor).
	b.Reset()
	b.rand = func(int64) int64 { return 0 }
	if got := b.Next(); got != 0 {
		t.Fatalf("min draw = %v, want 0", got)
	}
}

// TestBackoffDefaults: non-positive arguments fall back to the shared
// reconnect parameters so every reconnect path uses the same numbers.
func TestBackoffDefaults(t *testing.T) {
	b := NewBackoff(0, 0)
	if b.base != DefaultReconnectBase || b.limit != DefaultReconnectCap {
		t.Fatalf("defaults = base %v cap %v", b.base, b.limit)
	}
	if b := NewBackoff(time.Second, time.Millisecond); b.limit != time.Second {
		t.Fatalf("cap below base must clamp up to the base, got %v", b.limit)
	}
}
