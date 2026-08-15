package volumeserver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func testLockTable(t *testing.T, maxRecords, maxPerSession uint32, sessions ...SessionID) *LockTable {
	t.Helper()
	table := NewLockTable(maxRecords, maxPerSession, time.Now)
	for _, id := range sessions {
		table.RegisterSession(id, time.Now().Add(time.Hour))
	}
	return table
}

// heldRecords returns the object's records in byte order.
func heldRecords(table *LockTable, object ObjectKey) []Lock {
	table.mu.Lock()
	defer table.mu.Unlock()
	var out []Lock
	if o := table.objects[object]; o != nil {
		o.held.all(func(n *intervalNode[Lock]) bool {
			out = append(out, n.value)
			return true
		})
	}
	return out
}

func ownerRecords(table *LockTable, object ObjectKey, owner LockOwner) []Lock {
	var out []Lock
	for _, held := range heldRecords(table, object) {
		if held.Owner == owner {
			out = append(out, held)
		}
	}
	return out
}

func queuedCount(table *LockTable, object ObjectKey) int {
	table.mu.Lock()
	defer table.mu.Unlock()
	if o := table.objects[object]; o != nil {
		return o.waiting.size
	}
	return 0
}

func waitForQueued(t *testing.T, table *LockTable, object ObjectKey, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if queuedCount(table, object) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("queued waiters on %x = %d, want %d", object, queuedCount(table, object), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func writeLock(object ObjectKey, owner LockOwner, r LockRange) Lock {
	return Lock{Object: object, Owner: owner, Type: LockWrite, Range: r}
}

func readLock(object ObjectKey, owner LockOwner, r LockRange) Lock {
	return Lock{Object: object, Owner: owner, Type: LockRead, Range: r}
}

// --------------------------------------------------------------------------
// POSIX record algebra
// --------------------------------------------------------------------------

func TestLockReplacementSplitAndCoalesce(t *testing.T) {
	owner := LockOwner{Session: SessionID{1}, Kernel: 1}
	table := testLockTable(t, 64, 64, owner.Session)
	object := ObjectKey{1}
	if err := table.Set(writeLock(object, owner, LockRange{Start: 0, End: 99})); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(readLock(object, owner, LockRange{Start: 25, End: 74})); err != nil {
		t.Fatal(err)
	}
	got := heldRecords(table, object)
	if len(got) != 3 || got[0].Range != (LockRange{0, 24}) || got[1].Type != LockRead || got[2].Range != (LockRange{75, 99}) {
		t.Fatalf("split locks = %#v", got)
	}
	if err := table.Set(writeLock(object, owner, LockRange{Start: 25, End: 74})); err != nil {
		t.Fatal(err)
	}
	got = heldRecords(table, object)
	if len(got) != 1 || got[0].Range != (LockRange{0, 99}) || got[0].Type != LockWrite {
		t.Fatalf("coalesced = %#v", got)
	}
}

func TestLockAliasesConflictByObject(t *testing.T) {
	a := LockOwner{Session: SessionID{1}}
	b := LockOwner{Session: SessionID{2}}
	table := testLockTable(t, 64, 64, a.Session, b.Session)
	object := ObjectKey{1}
	if err := table.Set(readLock(object, a, ToEOF(0))); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(writeLock(object, b, LockRange{0, 0})); !errors.Is(err, ErrLockConflict) {
		t.Fatalf("Set=%v", err)
	}
}

func TestPOSIXAndFlockNamespacesAreIndependent(t *testing.T) {
	posix := LockOwner{Session: SessionID{1}, Kernel: 7}
	flock := LockOwner{Session: SessionID{2}, Kernel: 8, Flock: true}
	table := testLockTable(t, 64, 64, posix.Session, flock.Session)
	object := ObjectKey{1}
	if err := table.Set(writeLock(object, posix, ToEOF(0))); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(writeLock(object, flock, ToEOF(0))); err != nil {
		t.Fatalf("flock conflicted with independent POSIX namespace: %v", err)
	}
	if err := table.Unlock(object, posix, ToEOF(0)); err != nil {
		t.Fatal(err)
	}
	if got := heldRecords(table, object); len(got) != 1 || got[0].Owner != flock {
		t.Fatalf("POSIX flush removed flock: %#v", got)
	}
}

// TestUnlockSplitPreservesEveryOtherRecord covers the slice-aliasing corruption:
// Unlock used to rewrite its input slice in place, so the two records a hole
// punch produces overwrote the neighbouring entries — usually another session's
// live lock — and reported success. Nothing in the old suite ever unlocked an
// object holding more than one record, which is exactly why it survived.
func TestUnlockSplitPreservesEveryOtherRecord(t *testing.T) {
	a := LockOwner{Session: SessionID{1}, Kernel: 1}
	b := LockOwner{Session: SessionID{2}, Kernel: 2}
	c := LockOwner{Session: SessionID{3}, Kernel: 3}
	table := testLockTable(t, 64, 64, a.Session, b.Session, c.Session)
	object := ObjectKey{9}

	// Shared reads so all three owners coexist on one object.
	for _, held := range []Lock{
		readLock(object, a, LockRange{Start: 0, End: 99}),
		readLock(object, b, LockRange{Start: 100, End: 199}),
		readLock(object, c, LockRange{Start: 200, End: 299}),
	} {
		if err := table.Set(held); err != nil {
			t.Fatal(err)
		}
	}
	if got := heldRecords(table, object); len(got) != 3 {
		t.Fatalf("setup = %#v", got)
	}

	// One record in, two records out.
	if err := table.Unlock(object, a, LockRange{Start: 40, End: 59}); err != nil {
		t.Fatal(err)
	}

	got := heldRecords(table, object)
	want := []Lock{
		readLock(object, a, LockRange{Start: 0, End: 39}),
		readLock(object, a, LockRange{Start: 60, End: 99}),
		readLock(object, b, LockRange{Start: 100, End: 199}),
		readLock(object, c, LockRange{Start: 200, End: 299}),
	}
	if len(got) != len(want) {
		t.Fatalf("records after hole punch = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("record %d = %#v, want %#v (full set %#v)", i, got[i], want[i], got)
		}
	}

	// The corruption's real consequence: another session's exclusion silently
	// disappearing, so a third party can take a range a live holder still owns.
	intruder := LockOwner{Session: SessionID{4}, Kernel: 4}
	table.RegisterSession(intruder.Session, time.Now().Add(time.Hour))
	if err := table.Set(writeLock(object, intruder, LockRange{Start: 150, End: 150})); !errors.Is(err, ErrLockConflict) {
		t.Fatalf("write into a surviving holder's range = %v, want ErrLockConflict", err)
	}
	if err := table.Set(writeLock(object, intruder, LockRange{Start: 250, End: 250})); !errors.Is(err, ErrLockConflict) {
		t.Fatalf("write into a surviving holder's range = %v, want ErrLockConflict", err)
	}
}

// TestCoalescesAcrossAnInterleavedOwner: coalescing used to depend on two of an
// owner's records being adjacent in a slice sorted by (Start, Session, ...), so
// any other owner's record sorting between them permanently fragmented the
// first owner and wasted records against the cap.
func TestCoalescesAcrossAnInterleavedOwner(t *testing.T) {
	a := LockOwner{Session: SessionID{1}}
	b := LockOwner{Session: SessionID{2}}
	table := testLockTable(t, 64, 64, a.Session, b.Session)
	object := ObjectKey{3}
	for _, held := range []Lock{
		readLock(object, a, LockRange{Start: 0, End: 9}),
		readLock(object, b, LockRange{Start: 5, End: 30}),
		readLock(object, a, LockRange{Start: 20, End: 29}),
	} {
		if err := table.Set(held); err != nil {
			t.Fatal(err)
		}
	}
	if err := table.Set(readLock(object, a, LockRange{Start: 10, End: 19})); err != nil {
		t.Fatal(err)
	}
	got := ownerRecords(table, object, a)
	if len(got) != 1 || got[0].Range != (LockRange{Start: 0, End: 29}) {
		t.Fatalf("owner records = %#v, want one [0,29]", got)
	}
	if others := ownerRecords(table, object, b); len(others) != 1 || others[0].Range != (LockRange{Start: 5, End: 30}) {
		t.Fatalf("interleaved owner disturbed: %#v", others)
	}
}

// --------------------------------------------------------------------------
// admission
// --------------------------------------------------------------------------

func TestLockRecordAdmissionPreservesExistingState(t *testing.T) {
	owner := LockOwner{Session: SessionID{1}}
	table := testLockTable(t, 1, 1, owner.Session)
	object := ObjectKey{1}
	original := writeLock(object, owner, LockRange{Start: 0, End: 99})
	if err := table.Set(original); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(writeLock(ObjectKey{2}, owner, ToEOF(0))); !errors.Is(err, ErrAdmission) {
		t.Fatalf("second Set = %v, want ErrAdmission", err)
	}
	// Punching a hole would split one record into two. It must fail without
	// silently broadening or weakening the held range.
	if err := table.Unlock(object, owner, LockRange{Start: 25, End: 74}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("fragmenting Unlock = %v, want ErrAdmission", err)
	}
	if got := heldRecords(table, object); len(got) != 1 || got[0] != original {
		t.Fatalf("lock changed after refused fragmentation: %#v", got)
	}
}

// TestPerSessionBudgetIsolatesSessions: the table used to have only a global
// record cap, so one session taking 1-byte locks until the cap was reached made
// the next mount's very first lock on an unrelated file fail.
func TestPerSessionBudgetIsolatesSessions(t *testing.T) {
	greedy := LockOwner{Session: SessionID{1}}
	fresh := LockOwner{Session: SessionID{2}}
	table := testLockTable(t, 8, 2, greedy.Session, fresh.Session)

	for i := 0; i < 2; i++ {
		if err := table.Set(writeLock(ObjectKey{byte(i)}, greedy, LockRange{Start: 0, End: 0})); err != nil {
			t.Fatalf("record %d within budget: %v", i, err)
		}
	}
	if err := table.Set(writeLock(ObjectKey{9}, greedy, LockRange{Start: 0, End: 0})); !errors.Is(err, ErrAdmission) {
		t.Fatalf("record past the per-session budget = %v, want ErrAdmission", err)
	}
	// The whole point: an unrelated session's first lock on an unrelated file.
	if err := table.Set(writeLock(ObjectKey{200}, fresh, ToEOF(0))); err != nil {
		t.Fatalf("unrelated session's first lock: %v", err)
	}
}

// TestPerSessionBudgetBoundsQueuedRequests: waiters never expire on their own,
// so an unbounded per-session waiter count lets one client pin the table's whole
// budget in requests that will never be satisfied.
func TestPerSessionBudgetBoundsQueuedRequests(t *testing.T) {
	holder := LockOwner{Session: SessionID{1}}
	greedy := LockOwner{Session: SessionID{2}}
	other := LockOwner{Session: SessionID{3}}
	table := testLockTable(t, 16, 2, holder.Session, greedy.Session, other.Session)
	object := ObjectKey{1}
	if err := table.Set(writeLock(object, holder, LockRange{Start: 0, End: 999})); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- table.Wait(ctx, writeLock(object, greedy, LockRange{Start: 0, End: 9})) }()
	waitForQueued(t, table, object, 1)
	go func() { second <- table.Wait(ctx, writeLock(object, greedy, LockRange{Start: 10, End: 19})) }()
	waitForQueued(t, table, object, 2)

	if err := table.Wait(ctx, writeLock(object, greedy, LockRange{Start: 20, End: 29})); !errors.Is(err, ErrAdmission) {
		t.Fatalf("queued request past the per-session budget = %v, want ErrAdmission", err)
	}
	// A different session still gets its own budget.
	third := make(chan error, 1)
	go func() { third <- table.Wait(ctx, writeLock(object, other, LockRange{Start: 20, End: 29})) }()
	waitForQueued(t, table, object, 3)

	cancel()
	for _, done := range []chan error{first, second, third} {
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled Wait = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancelled waiter did not exit")
		}
	}
}

// --------------------------------------------------------------------------
// queue discipline
// --------------------------------------------------------------------------

func TestWaitLockCancellationAndRelease(t *testing.T) {
	a := LockOwner{Session: SessionID{1}}
	b := LockOwner{Session: SessionID{2}}
	table := testLockTable(t, 64, 64, a.Session, b.Session)
	object := ObjectKey{1}
	lock := func(owner LockOwner) Lock { return writeLock(object, owner, ToEOF(0)) }
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
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled waiter did not exit")
	}

	go func() { done <- table.Wait(context.Background(), lock(b)) }()
	table.ReleaseSession(a.Session)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not acquire")
	}
}

func TestInterruptWaitersRetiresWholeQueueBeforeAnyGrant(t *testing.T) {
	holder := LockOwner{Session: SessionID{1}}
	waiting := []LockOwner{
		{Session: SessionID{2}, Kernel: 1},
		{Session: SessionID{3}, Kernel: 2},
	}
	table := testLockTable(t, 64, 64, holder.Session, waiting[0].Session, waiting[1].Session)
	object := ObjectKey{1}
	if err := table.Set(writeLock(object, holder, ToEOF(0))); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, len(waiting))
	for _, owner := range waiting {
		owner := owner
		go func() { done <- table.Wait(context.Background(), writeLock(object, owner, ToEOF(0))) }()
	}
	waitForQueued(t, table, object, len(waiting))

	table.InterruptWaiters(ErrSessionExpired)
	for range waiting {
		select {
		case err := <-done:
			if !errors.Is(err, ErrSessionExpired) {
				t.Fatalf("interrupted waiter = %v, want ErrSessionExpired", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("interrupted waiter did not exit")
		}
	}
	if got := heldRecords(table, object); len(got) != 1 || got[0].Owner != holder {
		t.Fatalf("interrupt changed held records: %#v", got)
	}
	table.mu.Lock()
	queued := table.waiting
	table.mu.Unlock()
	if queued != 0 {
		t.Fatalf("interrupt left %d queued records", queued)
	}

	// Releasing the holder after the global interruption must not resurrect a
	// request from the retired queue.
	if err := table.Unlock(object, holder, ToEOF(0)); err != nil {
		t.Fatal(err)
	}
	if got := heldRecords(table, object); len(got) != 0 {
		t.Fatalf("retired waiter was granted after holder release: %#v", got)
	}
}

func TestDisjointWaiterBypassesBlockedRange(t *testing.T) {
	held := LockOwner{Session: SessionID{1}}
	blocked := LockOwner{Session: SessionID{2}}
	disjoint := LockOwner{Session: SessionID{3}}
	table := testLockTable(t, 64, 64, held.Session, blocked.Session, disjoint.Session)
	object := ObjectKey{1}
	if err := table.Set(writeLock(object, held, LockRange{Start: 0, End: 9})); err != nil {
		t.Fatal(err)
	}

	blockedDone := make(chan error, 1)
	go func() {
		blockedDone <- table.Wait(context.Background(), writeLock(object, blocked, LockRange{Start: 0, End: 9}))
	}()
	waitForQueued(t, table, object, 1)

	disjointDone := make(chan error, 1)
	go func() {
		disjointDone <- table.Wait(context.Background(), writeLock(object, disjoint, LockRange{Start: 10, End: 19}))
	}()
	select {
	case err := <-disjointDone:
		if err != nil {
			t.Fatalf("disjoint Wait = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("disjoint waiter was blocked behind an unrelated byte range")
	}

	table.ReleaseSession(held.Session)
	select {
	case err := <-blockedDone:
		if err != nil {
			t.Fatalf("blocked Wait = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("conflicting waiter did not acquire after release")
	}
}

func TestReleaseSessionWakesWaiterBehindCancelledHead(t *testing.T) {
	held := LockOwner{Session: SessionID{1}}
	cancelled := LockOwner{Session: SessionID{2}}
	next := LockOwner{Session: SessionID{3}}
	table := testLockTable(t, 64, 64, held.Session, cancelled.Session, next.Session)
	object := ObjectKey{1}
	lock := func(owner LockOwner) Lock { return writeLock(object, owner, ToEOF(0)) }
	if err := table.Set(lock(held)); err != nil {
		t.Fatal(err)
	}

	cancelledDone := make(chan error, 1)
	nextDone := make(chan error, 1)
	go func() { cancelledDone <- table.Wait(context.Background(), lock(cancelled)) }()
	waitForQueued(t, table, object, 1)
	go func() { nextDone <- table.Wait(context.Background(), lock(next)) }()
	waitForQueued(t, table, object, 2)

	table.ReleaseSession(cancelled.Session)
	select {
	case err := <-cancelledDone:
		if !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("cancelled Wait = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled waiter did not exit")
	}
	table.ReleaseSession(held.Session)
	select {
	case err := <-nextDone:
		if err != nil {
			t.Fatalf("next Wait = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("newly exposed waiter was not woken")
	}

	table.ReleaseSession(next.Session)
	table.mu.Lock()
	defer table.mu.Unlock()
	if len(table.objects) != 0 || table.held != 0 || table.waiting != 0 {
		t.Fatalf("empty lock-table keys retained: objects=%d held=%d waiting=%d", len(table.objects), table.held, table.waiting)
	}
}

// TestDowngradeWakesBlockedWaiter: Set was the only mutating path that never
// woke anyone, so an owner weakening its own write lock to a read lock made a
// queued reader eligible without ever telling it, and F_SETLKW slept forever.
func TestDowngradeWakesBlockedWaiter(t *testing.T) {
	holder := LockOwner{Session: SessionID{1}}
	reader := LockOwner{Session: SessionID{2}}
	table := testLockTable(t, 64, 64, holder.Session, reader.Session)
	object := ObjectKey{1}
	if err := table.Set(writeLock(object, holder, LockRange{Start: 0, End: 99})); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- table.Wait(context.Background(), readLock(object, reader, LockRange{Start: 0, End: 99}))
	}()
	waitForQueued(t, table, object, 1)

	if err := table.Set(readLock(object, holder, LockRange{Start: 0, End: 99})); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waiter after downgrade = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("downgrade left an eligible waiter asleep")
	}
	if got := len(heldRecords(table, object)); got != 2 {
		t.Fatalf("records after downgrade and grant = %d, want 2", got)
	}
}

// TestNonBlockingSetDoesNotJumpQueuedRequests: Set consulted only the record
// set, never the queue, so a stream of non-blocking callers could hand a shared
// read lock among themselves forever while a queued writer never ran.
func TestNonBlockingSetDoesNotJumpQueuedRequests(t *testing.T) {
	reader := LockOwner{Session: SessionID{1}}
	writer := LockOwner{Session: SessionID{2}}
	barger := LockOwner{Session: SessionID{3}}
	table := testLockTable(t, 64, 64, reader.Session, writer.Session, barger.Session)
	object := ObjectKey{1}
	if err := table.Set(readLock(object, reader, LockRange{Start: 0, End: 99})); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- table.Wait(context.Background(), writeLock(object, writer, LockRange{Start: 0, End: 99}))
	}()
	waitForQueued(t, table, object, 1)

	if err := table.Set(readLock(object, barger, LockRange{Start: 0, End: 99})); !errors.Is(err, ErrLockConflict) {
		t.Fatalf("non-blocking Set past a queued writer = %v, want ErrLockConflict", err)
	}
	// A disjoint range is still free: fairness is per contended range, not per
	// inode.
	if err := table.Set(readLock(object, barger, LockRange{Start: 200, End: 299})); err != nil {
		t.Fatalf("disjoint non-blocking Set: %v", err)
	}
	// Re-asserting coverage the owner already holds acquires nothing and is
	// never subject to queue order.
	if err := table.Set(readLock(object, reader, LockRange{Start: 0, End: 99})); err != nil {
		t.Fatalf("re-assertion of a held range: %v", err)
	}

	if err := table.Unlock(object, reader, LockRange{Start: 0, End: 99}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("queued writer = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued writer never ran")
	}
}

// TestBlockingCycleIsRefusedWithEDEADLK: two mounts each holding what the other
// waits for used to wedge permanently, and their sessions could never be
// cleaned up because the blocked waiters held the session pins.
func TestBlockingCycleIsRefusedWithEDEADLK(t *testing.T) {
	a := LockOwner{Session: SessionID{1}}
	b := LockOwner{Session: SessionID{2}}
	table := testLockTable(t, 64, 64, a.Session, b.Session)
	object := ObjectKey{1}
	low := LockRange{Start: 0, End: 9}
	high := LockRange{Start: 10, End: 19}
	if err := table.Set(writeLock(object, a, low)); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(writeLock(object, b, high)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { first <- table.Wait(ctx, writeLock(object, a, high)) }()
	waitForQueued(t, table, object, 1)

	if err := table.Wait(ctx, writeLock(object, b, low)); !errors.Is(err, ErrDeadlock) {
		t.Fatalf("cycle-closing Wait = %v, want ErrDeadlock", err)
	}
	if !errors.Is(ErrDeadlock, syscall.EDEADLK) {
		t.Fatalf("ErrDeadlock does not carry EDEADLK")
	}
	if queued := queuedCount(table, object); queued != 1 {
		t.Fatalf("refused request stayed queued: %d", queued)
	}

	// The surviving request still completes once the real holder releases.
	if err := table.Unlock(object, b, high); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-first:
		if err != nil {
			t.Fatalf("non-cyclic Wait = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("non-cyclic waiter never ran")
	}
}

func TestBlockingCycleAcrossObjectsIsRefused(t *testing.T) {
	a := LockOwner{Session: SessionID{1}}
	b := LockOwner{Session: SessionID{2}}
	table := testLockTable(t, 64, 64, a.Session, b.Session)
	first, second := ObjectKey{1}, ObjectKey{2}
	full := ToEOF(0)
	if err := table.Set(writeLock(first, a, full)); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(writeLock(second, b, full)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- table.Wait(ctx, writeLock(second, a, full)) }()
	waitForQueued(t, table, second, 1)

	if err := table.Wait(ctx, writeLock(first, b, full)); !errors.Is(err, ErrDeadlock) {
		t.Fatalf("cross-object cycle = %v, want ErrDeadlock", err)
	}
}

// --------------------------------------------------------------------------
// session binding
// --------------------------------------------------------------------------

func TestUnregisteredSessionCannotTouchTheTable(t *testing.T) {
	owner := LockOwner{Session: SessionID{1}}
	table := testLockTable(t, 64, 64)
	object := ObjectKey{1}
	if err := table.Set(writeLock(object, owner, ToEOF(0))); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Set for an unregistered session = %v, want ErrSessionExpired", err)
	}
	if _, _, err := table.Get(writeLock(object, owner, ToEOF(0))); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Get = %v", err)
	}
	if err := table.Unlock(object, owner, ToEOF(0)); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Unlock = %v", err)
	}
	if err := table.Wait(context.Background(), writeLock(object, owner, ToEOF(0))); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Wait = %v", err)
	}
	if len(heldRecords(table, object)) != 0 {
		t.Fatal("a refused operation created state")
	}
}

func TestExpiredLeaseCannotAcquireOrBeGranted(t *testing.T) {
	holder := LockOwner{Session: SessionID{1}}
	expiring := LockOwner{Session: SessionID{2}}
	clock := time.Unix(1_000, 0)
	table := NewLockTable(64, 64, func() time.Time { return clock })
	table.RegisterSession(holder.Session, clock.Add(time.Hour))
	lease := table.RegisterSession(expiring.Session, clock.Add(time.Minute))
	object := ObjectKey{1}
	if err := table.Set(writeLock(object, holder, ToEOF(0))); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- table.Wait(context.Background(), writeLock(object, expiring, ToEOF(0))) }()
	waitForQueued(t, table, object, 1)

	// The lease runs out while the request is queued. Nothing has swept it yet.
	clock = clock.Add(2 * time.Minute)
	if err := table.Unlock(object, holder, ToEOF(0)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("grant to an expired lease = %v, want ErrSessionExpired", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expired waiter was never retired")
	}
	if got := heldRecords(table, object); len(got) != 0 {
		t.Fatalf("expired session acquired a record: %#v", got)
	}
	if err := table.Set(writeLock(object, expiring, ToEOF(0))); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Set on an expired lease = %v", err)
	}
	// Renewal restores it without re-registering.
	lease.Renew(clock.Add(time.Hour))
	if err := table.Set(writeLock(object, expiring, ToEOF(0))); err != nil {
		t.Fatalf("Set after renewal: %v", err)
	}
}

// --------------------------------------------------------------------------
// scale
// --------------------------------------------------------------------------

// TestManyRecordsOnOneObjectStayLinear pins the record index. Every operation
// used to rebuild the object's slice and re-sort it under the table mutex, so
// installing n records cost O(n^2 log n) in total and the whole volume's lock
// service was capped at roughly a thousand operations a second on one inode.
func TestManyRecordsOnOneObjectStayLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	const records = 40_000
	owner := LockOwner{Session: SessionID{1}}
	table := testLockTable(t, records+16, records+16, owner.Session)
	object := ObjectKey{1}

	start := time.Now()
	for i := 0; i < records; i++ {
		// Gaps keep the records from coalescing.
		at := uint64(2 * i)
		if err := table.Set(writeLock(object, owner, LockRange{Start: at, End: at})); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	if got := len(heldRecords(table, object)); got != records {
		t.Fatalf("records = %d, want %d", got, records)
	}
	// The slice-and-re-sort implementation needs 10.1s for this on the machine
	// this bound was calibrated on; the index needs about ten milliseconds. The
	// bound sits between them with two orders of magnitude of headroom for a
	// race-instrumented run.
	if elapsed > 5*time.Second {
		t.Fatalf("installing %d records took %v", records, elapsed)
	}
	t.Logf("installed %d records in %v", records, elapsed)

	// A query against a full object must not scan it.
	other := LockOwner{Session: SessionID{2}}
	table.RegisterSession(other.Session, time.Now().Add(time.Hour))
	start = time.Now()
	for i := 0; i < 1_000; i++ {
		if _, _, err := table.Get(writeLock(object, other, LockRange{Start: uint64(2 * i), End: uint64(2 * i)})); err != nil {
			t.Fatal(err)
		}
	}
	if probe := time.Since(start); probe > 5*time.Second {
		t.Fatalf("1000 conflict probes against %d records took %v", records, probe)
	}
}

// TestDisjointWaiterDrainIsNotQuadratic pins the waiter index. Waking used to
// walk every waiter on the inode and, for each, rescan every held record plus
// the whole earlier-waiter prefix, so draining four thousand disjoint requests
// on one file — the product's intended workload — took a minute of wall clock
// while cycling the table mutex throughout.
func TestDisjointWaiterDrainIsNotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	const waiters = 4_000
	holder := LockOwner{Session: SessionID{1}}
	pending := SessionID{2}
	table := testLockTable(t, 2*waiters+16, 2*waiters+16, holder.Session, pending)
	object := ObjectKey{1}
	if err := table.Set(writeLock(object, holder, LockRange{Start: 0, End: 2*waiters + 1})); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		owner := LockOwner{Session: pending, Kernel: uint64(i + 1)}
		at := uint64(2 * i)
		go func() {
			done <- table.Wait(context.Background(), writeLock(object, owner, LockRange{Start: at, End: at + 1}))
		}()
	}
	waitForQueued(t, table, object, waiters)

	start := time.Now()
	if err := table.Unlock(object, holder, LockRange{Start: 0, End: 2*waiters + 1}); err != nil {
		t.Fatal(err)
	}
	release := time.Since(start)
	for i := 0; i < waiters; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("waiter %d = %v", i, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("only %d of %d waiters drained", i, waiters)
		}
	}
	drain := time.Since(start)
	t.Logf("release %v, full drain %v", release, drain)
	if drain > 20*time.Second {
		t.Fatalf("draining %d disjoint waiters took %v", waiters, drain)
	}
	if got := len(heldRecords(table, object)); got != waiters {
		t.Fatalf("records after drain = %d, want %d", got, waiters)
	}
}

// --------------------------------------------------------------------------
// index invariants
// --------------------------------------------------------------------------

func TestIntervalTreeOverlapMatchesLinearScan(t *testing.T) {
	var tree intervalTree[int]
	type entry struct{ start, end uint64 }
	var entries []entry
	// A deterministic, adversarially ordered set: increasing, decreasing, and
	// nested spans interleaved.
	next := uint64(1)
	for i := 0; i < 500; i++ {
		next = splitmix64(next)
		start := next % 1_000
		next = splitmix64(next)
		end := start + next%200
		entries = append(entries, entry{start, end})
		tree.insert(start, end, uint64(i), i)
	}
	if tree.size != len(entries) {
		t.Fatalf("size = %d, want %d", tree.size, len(entries))
	}
	probe := func(r LockRange) []int {
		var got []int
		tree.overlap(r, func(n *intervalNode[int]) bool {
			got = append(got, n.value)
			return true
		})
		return got
	}
	for _, r := range []LockRange{{0, 0}, {0, 2000}, {500, 500}, {300, 700}, {999, 1200}, {1_000_000, math.MaxUint64}} {
		want := map[int]bool{}
		for i, e := range entries {
			if e.start <= r.End && r.Start <= e.end {
				want[i] = true
			}
		}
		got := probe(r)
		if len(got) != len(want) {
			t.Fatalf("overlap %v returned %d entries, want %d", r, len(got), len(want))
		}
		for _, id := range got {
			if !want[id] {
				t.Fatalf("overlap %v returned non-overlapping entry %d", r, id)
			}
		}
		for i := 1; i < len(got); i++ {
			if entries[got[i-1]].start > entries[got[i]].start {
				t.Fatalf("overlap %v returned entries out of key order", r)
			}
		}
	}
	// Removal keeps the augmentation consistent.
	for i := 0; i < len(entries); i += 2 {
		if !tree.remove(entries[i].start, entries[i].end, uint64(i)) {
			t.Fatalf("remove %d", i)
		}
	}
	if tree.size != len(entries)-(len(entries)+1)/2 {
		t.Fatalf("size after removal = %d", tree.size)
	}
	for _, id := range probe(LockRange{0, 2000}) {
		if id%2 == 0 {
			t.Fatalf("removed entry %d still reachable", id)
		}
	}
}

func TestSubtractCoverage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		r       LockRange
		covered []LockRange
		want    []LockRange
	}{
		{"none", LockRange{10, 20}, nil, []LockRange{{10, 20}}},
		{"exact", LockRange{10, 20}, []LockRange{{10, 20}}, nil},
		{"wider", LockRange{10, 20}, []LockRange{{0, 30}}, nil},
		{"hole", LockRange{10, 20}, []LockRange{{12, 14}}, []LockRange{{10, 11}, {15, 20}}},
		{"prefix", LockRange{10, 20}, []LockRange{{0, 14}}, []LockRange{{15, 20}}},
		{"suffix", LockRange{10, 20}, []LockRange{{15, 40}}, []LockRange{{10, 14}}},
		{"two holes", LockRange{0, 20}, []LockRange{{2, 3}, {10, 11}}, []LockRange{{0, 1}, {4, 9}, {12, 20}}},
		{"to eof", ToEOF(0), []LockRange{{0, 5}}, []LockRange{{6, math.MaxUint64}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := subtractCoverage(tc.r, tc.covered)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("subtractCoverage = %v, want %v", got, tc.want)
			}
		})
	}
}

// checkInvariants verifies the properties the table is supposed to make
// structurally impossible to break, rather than any particular outcome.
func checkInvariants(t *testing.T, table *LockTable) {
	t.Helper()
	table.mu.Lock()
	defer table.mu.Unlock()

	var held, waiting uint64
	perSession := make(map[SessionID]uint64)
	for key, o := range table.objects {
		if o.held.size == 0 && o.waiting.size == 0 {
			t.Fatalf("object %x retained with no records and no waiters", key)
		}
		var records []Lock
		o.held.all(func(n *intervalNode[Lock]) bool {
			records = append(records, n.value)
			return true
		})
		if len(records) != o.held.size {
			t.Fatalf("object %x: traversal yielded %d of %d records", key, len(records), o.held.size)
		}
		held += uint64(o.held.size)
		waiting += uint64(o.waiting.size)
		for i, a := range records {
			if a.Range.Start > a.Range.End {
				t.Fatalf("object %x: inverted record %#v", key, a)
			}
			if i > 0 && records[i-1].Range.Start > a.Range.Start {
				t.Fatalf("object %x: records out of key order", key)
			}
			if _, live := table.sessions[a.Owner.Session]; !live {
				t.Fatalf("object %x: record held by an unregistered session: %#v", key, a)
			}
			perSession[a.Owner.Session]++
			for _, b := range records[i+1:] {
				if a.Owner == b.Owner {
					if overlaps(a.Range, b.Range) {
						t.Fatalf("object %x: one owner holds overlapping records %#v %#v", key, a, b)
					}
					if a.Type == b.Type && adjacent(a.Range, b.Range) {
						t.Fatalf("object %x: one owner holds uncoalesced adjacent records %#v %#v", key, a, b)
					}
				}
				if conflicts(a, b) {
					t.Fatalf("object %x: conflicting records both held: %#v %#v", key, a, b)
				}
			}
		}
		o.waiting.all(func(n *intervalNode[*lockWaiter]) bool {
			w := n.value
			if w.settled {
				t.Fatalf("object %x: settled waiter still queued", key)
			}
			if _, live := table.sessions[w.lock.Owner.Session]; !live {
				t.Fatalf("object %x: waiter of an unregistered session still queued", key)
			}
			perSession[w.lock.Owner.Session]++
			return true
		})
	}
	if held != table.held || waiting != table.waiting {
		t.Fatalf("counters: held %d/%d waiting %d/%d", table.held, held, table.waiting, waiting)
	}
	if table.held+table.waiting > table.maxRecords {
		t.Fatalf("global bound exceeded: %d > %d", table.held+table.waiting, table.maxRecords)
	}
	for id, s := range table.sessions {
		if s.records != perSession[id] {
			t.Fatalf("session %x records = %d, counted %d", id, s.records, perSession[id])
		}
		if s.records > table.maxPerSession {
			t.Fatalf("session %x exceeded its budget: %d > %d", id, s.records, table.maxPerSession)
		}
	}
	if table.waking || len(table.pendingWake) != 0 {
		t.Fatalf("wake cascade left running: waking=%t pending=%d", table.waking, len(table.pendingWake))
	}
}

// TestConcurrentOperationsPreserveTableInvariants drives every mutating path at
// once and then asserts the structural properties, rather than any particular
// interleaving's outcome.
func TestConcurrentOperationsPreserveTableInvariants(t *testing.T) {
	const (
		sessions   = 6
		perSession = 4
		objects    = 3
		rounds     = 400
	)
	table := NewLockTable(sessions*16, 16, time.Now)
	ids := make([]SessionID, sessions)
	for i := range ids {
		ids[i] = SessionID{byte(i + 1)}
		table.RegisterSession(ids[i], time.Now().Add(time.Hour))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var sets, unlocks, grants, conflicts atomic.Uint64
	for s := 0; s < sessions; s++ {
		for k := 0; k < perSession; k++ {
			owner := LockOwner{Session: ids[s], Kernel: uint64(k)}
			seed := uint64(s*perSession + k + 1)
			go func() {
				defer func() { done <- struct{}{} }()
				rnd := seed
				for i := 0; i < rounds; i++ {
					rnd = splitmix64(rnd)
					object := ObjectKey{byte(rnd % objects)}
					start := (rnd >> 8) % 64
					span := (rnd >> 16) % 16
					r := LockRange{Start: start, End: start + span}
					mode := LockRead
					if rnd&(1<<24) != 0 {
						mode = LockWrite
					}
					lock := Lock{Object: object, Owner: owner, Type: mode, Range: r}
					switch (rnd >> 25) % 4 {
					case 0, 1:
						switch err := table.Set(lock); {
						case err == nil:
							sets.Add(1)
						case errors.Is(err, ErrLockConflict):
							conflicts.Add(1)
						}
					case 2:
						if err := table.Unlock(object, owner, r); err == nil {
							unlocks.Add(1)
						}
					default:
						waitCtx, waitCancel := context.WithTimeout(ctx, 2*time.Millisecond)
						if err := table.Wait(waitCtx, lock); err == nil {
							grants.Add(1)
						}
						waitCancel()
					}
				}
			}()
		}
	}
	for i := 0; i < sessions*perSession; i++ {
		<-done
	}
	cancel()
	checkInvariants(t, table)
	t.Logf("sets=%d unlocks=%d grants=%d conflicts=%d", sets.Load(), unlocks.Load(), grants.Load(), conflicts.Load())
	// Guard against the exercise silently degenerating into a no-op.
	if sets.Load() == 0 || unlocks.Load() == 0 || grants.Load() == 0 || conflicts.Load() == 0 {
		t.Fatalf("stress exercise did not reach every path: sets=%d unlocks=%d grants=%d conflicts=%d",
			sets.Load(), unlocks.Load(), grants.Load(), conflicts.Load())
	}

	for _, id := range ids {
		table.ReleaseSession(id)
	}
	checkInvariants(t, table)
	table.mu.Lock()
	empty := len(table.objects) == 0 && table.held == 0 && table.waiting == 0 && len(table.sessions) == 0
	table.mu.Unlock()
	if !empty {
		t.Fatal("releasing every session left state behind")
	}
}
