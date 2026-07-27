package delegation

import (
	"context"
	"testing"
	"time"
)

// AwaitFree returns at once when nothing overlaps, blocks while a different owner holds an
// overlapping path, and wakes the instant that holder checks in (the recall handoff).
func TestAwaitFreeWakesOnCheckin(t *testing.T) {
	m := New()
	// Free immediately when uncontended.
	if !m.AwaitFree(context.Background(), "ws/app.db") {
		t.Fatal("AwaitFree on a free path should return true at once")
	}
	// A holds the covering subtree; a contender's wait blocks until A checks in.
	m.Checkout("ws", "A")
	woke := make(chan bool, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		woke <- m.AwaitFree(ctx, "ws/app.db")
	}()
	select {
	case <-woke:
		t.Fatal("AwaitFree returned while A still held the subtree")
	case <-time.After(100 * time.Millisecond):
	}
	m.Checkin("ws", "A") // recall satisfied: A relinquishes
	select {
	case ok := <-woke:
		if !ok {
			t.Fatal("AwaitFree should report free after A's checkin")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AwaitFree did not wake on A's checkin")
	}
}

// AwaitFree returns false when the holder never relinquishes within the caller's deadline — the
// authority then escalates to ForceCheckout.
func TestAwaitFreeTimesOut(t *testing.T) {
	m := New()
	m.Checkout("ws", "A")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if m.AwaitFree(ctx, "ws/app.db") {
		t.Fatal("AwaitFree should time out while A holds and never checks in")
	}
}

// ForceCheckout revokes an unresponsive holder's overlapping delegation and grants the contender.
func TestForceCheckoutRevokes(t *testing.T) {
	m := New()
	m.Checkout("ws", "A")
	revoked := m.ForceCheckout("ws/app.db", "B")
	if len(revoked) != 1 || revoked[0] != "A" {
		t.Fatalf("ForceCheckout revoked %v, want [A]", revoked)
	}
	if o, _ := m.HeldBy("ws/app.db"); o != "B" {
		t.Fatalf("after force, ws/app.db held by %q, want B", o)
	}
	// A's stale delegation is gone: A re-checkout of the old path must now contend with B.
	if ok, by := m.Checkout("ws", "A"); ok || by != "B" {
		t.Fatalf("A re-checkout = (%v,%q), want conflict with B", ok, by)
	}
}

func TestCheckoutExclusiveAndSubtree(t *testing.T) {
	m := New()

	// A checks out a subtree.
	if ok, _ := m.Checkout("work/build", "agent-A"); !ok {
		t.Fatal("A checkout should grant")
	}
	// A re-checkout is idempotent.
	if ok, _ := m.Checkout("work/build", "agent-A"); !ok {
		t.Fatal("A re-checkout should grant")
	}
	// B cannot take the same path.
	if ok, by := m.Checkout("work/build", "agent-B"); ok || by != "agent-A" {
		t.Fatalf("B checkout = (%v, %q), want (false, agent-A)", ok, by)
	}
	// B cannot take a descendant (A's subtree covers it).
	if ok, by := m.Checkout("work/build/out", "agent-B"); ok || by != "agent-A" {
		t.Fatalf("B descendant checkout = (%v, %q), want conflict with A", ok, by)
	}
	// B cannot take an ancestor (would cover A's held path).
	if ok, by := m.Checkout("work", "agent-B"); ok || by != "agent-A" {
		t.Fatalf("B ancestor checkout = (%v, %q), want conflict with A", ok, by)
	}
	// B CAN take a disjoint path.
	if ok, _ := m.Checkout("data", "agent-B"); !ok {
		t.Fatal("B disjoint checkout should grant")
	}

	// HeldBy reports the covering owner.
	if o, at := m.HeldBy("work/build/out/x"); o != "agent-A" || at != "work/build" {
		t.Fatalf("HeldBy = (%q,%q), want (agent-A, work/build)", o, at)
	}

	// After A checks in, B can take the path.
	if !m.Checkin("work/build", "agent-A") {
		t.Fatal("A checkin should succeed")
	}
	if ok, _ := m.Checkout("work/build", "agent-B"); !ok {
		t.Fatal("B checkout after A checkin should grant")
	}
}

func TestCheckinWrongOwnerAndRelease(t *testing.T) {
	m := New()
	m.Checkout("a", "A")
	m.Checkout("b", "A")
	if m.Checkin("a", "B") {
		t.Fatal("checkin by non-owner should fail")
	}
	m.ReleaseOwner("A") // e.g. on crash/cleanup
	if o, _ := m.HeldBy("a"); o != "" {
		t.Fatalf("after release, a held by %q, want none", o)
	}
	if ok, _ := m.Checkout("a", "B"); !ok {
		t.Fatal("checkout after release should grant")
	}
}
