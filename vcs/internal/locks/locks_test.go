package locks

import (
	"context"
	"testing"
	"time"
)

func TestExclusiveConflictAndOwnerExemption(t *testing.T) {
	m := New()
	a := Owner{Mount: "A", LkID: 1}
	b := Owner{Mount: "B", LkID: 1}

	if !m.Setlk("db", a, 0, EOF, true, false) {
		t.Fatal("A should get an exclusive whole-file lock on an unlocked file")
	}
	// B's exclusive lock conflicts.
	if m.Setlk("db", b, 0, EOF, true, false) {
		t.Fatal("B's exclusive lock must conflict with A's")
	}
	// B's read lock also conflicts with A's WRITE lock.
	if m.Setlk("db", b, 0, EOF, false, false) {
		t.Fatal("B's read lock must conflict with A's write lock")
	}
	// A refining its OWN lock never conflicts.
	if !m.Setlk("db", a, 0, 10, true, false) {
		t.Fatal("A must be able to (re)lock within its own range")
	}
	// Getlk reports the conflicting holder to B.
	if h, c := m.Getlk("db", b, 0, EOF, true); !c || h.Owner != a {
		t.Fatalf("Getlk should report A as the conflict, got %+v conflict=%v", h, c)
	}
}

func TestSharedLocksCoexistWritersExcluded(t *testing.T) {
	m := New()
	a := Owner{Mount: "A", LkID: 1}
	b := Owner{Mount: "B", LkID: 1}
	c := Owner{Mount: "C", LkID: 1}
	if !m.Setlk("f", a, 0, 100, false, false) {
		t.Fatal("A read lock")
	}
	if !m.Setlk("f", b, 0, 100, false, false) {
		t.Fatal("B read lock must coexist with A's read lock")
	}
	// A writer over the shared range conflicts.
	if m.Setlk("f", c, 50, 60, true, false) {
		t.Fatal("a writer must be excluded while readers hold the range")
	}
	// A non-overlapping writer is fine.
	if !m.Setlk("f", c, 200, 300, true, false) {
		t.Fatal("a non-overlapping writer must be granted")
	}
}

func TestUnlockSplitsRange(t *testing.T) {
	m := New()
	a := Owner{Mount: "A", LkID: 1}
	b := Owner{Mount: "B", LkID: 1}
	if !m.Setlk("f", a, 0, 100, true, false) {
		t.Fatal("A locks [0,100]")
	}
	// Unlock the middle [40,60]; the lock must split into [0,39] and [61,100].
	if !m.Setlk("f", a, 40, 60, false, true) {
		t.Fatal("unlock should succeed")
	}
	// B can now lock the freed middle...
	if !m.Setlk("f", b, 45, 55, true, false) {
		t.Fatal("B should lock the freed middle range")
	}
	// ...but not the still-held ends.
	if m.Setlk("f", b, 0, 5, true, false) {
		t.Fatal("the [0,39] prefix must still be held by A")
	}
	if m.Setlk("f", b, 90, 95, true, false) {
		t.Fatal("the [61,100] suffix must still be held by A")
	}
}

func TestSetlkwBlocksThenGrantsOnRelease(t *testing.T) {
	m := New()
	a := Owner{Mount: "A", LkID: 1}
	b := Owner{Mount: "B", LkID: 1}
	if !m.Setlk("db", a, 0, EOF, true, false) {
		t.Fatal("A locks")
	}
	got := make(chan bool, 1)
	go func() { got <- m.Setlkw(context.Background(), "db", b, 0, EOF, true) }()
	// B must still be blocked while A holds the lock.
	select {
	case <-got:
		t.Fatal("Setlkw must block while A holds the conflicting lock")
	case <-time.After(50 * time.Millisecond):
	}
	// A releases (via ReleaseOwner, e.g. a disconnect) → B's blocked Setlkw must now grant.
	m.ReleaseOwner("A")
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("Setlkw should have granted after release")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Setlkw did not wake after the conflicting lock was released")
	}
}

func TestSetlkwCancels(t *testing.T) {
	m := New()
	a := Owner{Mount: "A", LkID: 1}
	b := Owner{Mount: "B", LkID: 1}
	m.Setlk("db", a, 0, EOF, true, false)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan bool, 1)
	go func() { got <- m.Setlkw(ctx, "db", b, 0, EOF, true) }()
	cancel()
	select {
	case ok := <-got:
		if ok {
			t.Fatal("a cancelled Setlkw must return false (not granted)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled Setlkw did not return")
	}
}
