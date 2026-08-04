package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLockReplacementSplitAndCoalesce(t *testing.T) {
	table := NewLockTable(64)
	object := ObjectKey{1}
	owner := LockOwner{Session: SessionID{1}, Kernel: 1}
	if err := table.Set(Lock{Object: object, Owner: owner, Type: LockWrite, Range: LockRange{Start: 0, End: 99}}); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(Lock{Object: object, Owner: owner, Type: LockRead, Range: LockRange{Start: 25, End: 74}}); err != nil {
		t.Fatal(err)
	}
	got := table.locks[object]
	if len(got) != 3 || got[0].Range != (LockRange{0, 24}) || got[1].Type != LockRead || got[2].Range != (LockRange{75, 99}) {
		t.Fatalf("split locks = %#v", got)
	}
	if err := table.Set(Lock{Object: object, Owner: owner, Type: LockWrite, Range: LockRange{Start: 25, End: 74}}); err != nil {
		t.Fatal(err)
	}
	got = table.locks[object]
	if len(got) != 1 || got[0].Range != (LockRange{0, 99}) || got[0].Type != LockWrite {
		t.Fatalf("coalesced = %#v", got)
	}
}

func TestLockAliasesConflictByObject(t *testing.T) {
	table := NewLockTable(64)
	object := ObjectKey{1}
	a := LockOwner{Session: SessionID{1}}
	b := LockOwner{Session: SessionID{2}}
	if err := table.Set(Lock{Object: object, Owner: a, Type: LockRead, Range: ToEOF(0)}); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(Lock{Object: object, Owner: b, Type: LockWrite, Range: LockRange{0, 0}}); !errors.Is(err, ErrLockConflict) {
		t.Fatalf("Set=%v", err)
	}
}

func TestPOSIXAndFlockNamespacesAreIndependent(t *testing.T) {
	table := NewLockTable(64)
	object := ObjectKey{1}
	posix := LockOwner{Session: SessionID{1}, Kernel: 7}
	flock := LockOwner{Session: SessionID{2}, Kernel: 8, Flock: true}
	if err := table.Set(Lock{Object: object, Owner: posix, Type: LockWrite, Range: ToEOF(0)}); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(Lock{Object: object, Owner: flock, Type: LockWrite, Range: ToEOF(0)}); err != nil {
		t.Fatalf("flock conflicted with independent POSIX namespace: %v", err)
	}
	if err := table.Unlock(object, posix, ToEOF(0)); err != nil {
		t.Fatal(err)
	}
	if got := table.locks[object]; len(got) != 1 || got[0].Owner != flock {
		t.Fatalf("POSIX flush removed flock: %#v", got)
	}
}

func TestWaitLockCancellationAndRelease(t *testing.T) {
	table := NewLockTable(64)
	object := ObjectKey{1}
	a := LockOwner{Session: SessionID{1}}
	b := LockOwner{Session: SessionID{2}}
	lock := func(owner LockOwner) Lock {
		return Lock{Object: object, Owner: owner, Type: LockWrite, Range: ToEOF(0)}
	}
	if err := table.Set(lock(a)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- table.Wait(ctx, lock(b)) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled waiter did not exit")
	}

	ctx = context.Background()
	go func() { done <- table.Wait(ctx, lock(b)) }()
	table.ReleaseSession(a.Session)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not acquire")
	}
}

func TestLockRecordAdmissionPreservesExistingState(t *testing.T) {
	table := NewLockTable(1)
	object := ObjectKey{1}
	owner := LockOwner{Session: SessionID{1}}
	original := Lock{Object: object, Owner: owner, Type: LockWrite, Range: LockRange{Start: 0, End: 99}}
	if err := table.Set(original); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(Lock{Object: ObjectKey{2}, Owner: owner, Type: LockWrite, Range: ToEOF(0)}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("second Set = %v, want ErrAdmission", err)
	}
	// Punching a hole would split one record into two. It must fail without
	// silently broadening or weakening the held range.
	if err := table.Unlock(object, owner, LockRange{Start: 25, End: 74}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("fragmenting Unlock = %v, want ErrAdmission", err)
	}
	if got := table.locks[object]; len(got) != 1 || got[0] != original {
		t.Fatalf("lock changed after refused fragmentation: %#v", got)
	}
}

func TestDisjointWaiterBypassesBlockedRange(t *testing.T) {
	table := NewLockTable(64)
	object := ObjectKey{1}
	heldOwner := LockOwner{Session: SessionID{1}}
	blockedOwner := LockOwner{Session: SessionID{2}}
	disjointOwner := LockOwner{Session: SessionID{3}}
	if err := table.Set(Lock{Object: object, Owner: heldOwner, Type: LockWrite, Range: LockRange{Start: 0, End: 9}}); err != nil {
		t.Fatal(err)
	}

	blocked := make(chan error, 1)
	go func() {
		blocked <- table.Wait(context.Background(), Lock{Object: object, Owner: blockedOwner, Type: LockWrite, Range: LockRange{Start: 0, End: 9}})
	}()
	deadline := time.Now().Add(time.Second)
	for {
		table.mu.Lock()
		queued := len(table.waiters[object]) == 1
		table.mu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("conflicting waiter was not queued")
		}
		time.Sleep(time.Millisecond)
	}

	disjoint := make(chan error, 1)
	go func() {
		disjoint <- table.Wait(context.Background(), Lock{Object: object, Owner: disjointOwner, Type: LockWrite, Range: LockRange{Start: 10, End: 19}})
	}()
	select {
	case err := <-disjoint:
		if err != nil {
			t.Fatalf("disjoint Wait = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("disjoint waiter was blocked behind an unrelated byte range")
	}

	table.ReleaseSession(heldOwner.Session)
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("blocked Wait = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("conflicting waiter did not acquire after release")
	}
}

func TestReleaseSessionWakesWaiterBehindCancelledHead(t *testing.T) {
	table := NewLockTable(64)
	object := ObjectKey{1}
	heldOwner := LockOwner{Session: SessionID{1}}
	cancelledOwner := LockOwner{Session: SessionID{2}}
	nextOwner := LockOwner{Session: SessionID{3}}
	lock := func(owner LockOwner) Lock {
		return Lock{Object: object, Owner: owner, Type: LockWrite, Range: ToEOF(0)}
	}
	if err := table.Set(lock(heldOwner)); err != nil {
		t.Fatal(err)
	}

	cancelled := make(chan error, 1)
	next := make(chan error, 1)
	go func() { cancelled <- table.Wait(context.Background(), lock(cancelledOwner)) }()
	deadline := time.Now().Add(time.Second)
	for {
		table.mu.Lock()
		queued := len(table.waiters[object]) == 1
		table.mu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first waiter was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	go func() { next <- table.Wait(context.Background(), lock(nextOwner)) }()
	deadline = time.Now().Add(time.Second)
	for {
		table.mu.Lock()
		queued := len(table.waiters[object]) == 2
		table.mu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second waiter was not queued")
		}
		time.Sleep(time.Millisecond)
	}

	table.ReleaseSession(cancelledOwner.Session)
	select {
	case err := <-cancelled:
		if !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("cancelled Wait = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled waiter did not exit")
	}
	table.ReleaseSession(heldOwner.Session)
	select {
	case err := <-next:
		if err != nil {
			t.Fatalf("next Wait = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("newly exposed waiter was not woken")
	}

	table.ReleaseSession(nextOwner.Session)
	table.mu.Lock()
	defer table.mu.Unlock()
	if len(table.locks) != 0 || len(table.waiters) != 0 {
		t.Fatalf("empty lock-table keys retained: locks=%v waiters=%v", table.locks, table.waiters)
	}
}
