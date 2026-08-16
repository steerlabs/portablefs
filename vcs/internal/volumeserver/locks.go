package volumeserver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	ErrLockConflict = errors.New("volumeserver: byte range lock conflicts")
	// ErrDeadlock reports that granting a blocking request would close a cycle
	// in the wait-for graph. It wraps syscall.EDEADLK so the protocol boundary's
	// generic errno mapping reports the value POSIX defines for F_SETLKW.
	ErrDeadlock = fmt.Errorf("volumeserver: blocking byte range lock request would deadlock: %w", syscall.EDEADLK)

	errInvalidLock        = errors.New("volumeserver: invalid lock")
	errInvalidUnlockRange = errors.New("volumeserver: invalid unlock range")
)

type ObjectKey [16]byte

type LockOwner struct {
	Session SessionID
	Kernel  uint64
	Flock   bool
}

type LockType uint8

const (
	LockRead LockType = iota + 1
	LockWrite
)

// LockRange is inclusive. End=math.MaxUint64 represents POSIX "to EOF".
type LockRange struct {
	Start uint64
	End   uint64
}

func ToEOF(start uint64) LockRange { return LockRange{Start: start, End: math.MaxUint64} }

type Lock struct {
	Object ObjectKey
	Owner  LockOwner
	Type   LockType
	Range  LockRange
}

func validLock(lock Lock) bool {
	return (lock.Type == LockRead || lock.Type == LockWrite) && lock.Range.Start <= lock.Range.End
}

func overlaps(a, b LockRange) bool { return a.Start <= b.End && b.Start <= a.End }

func adjacent(a, b LockRange) bool {
	return (a.End != math.MaxUint64 && a.End+1 == b.Start) || (b.End != math.MaxUint64 && b.End+1 == a.Start)
}

// coverRange is the smallest range containing both inputs.
func coverRange(a, b LockRange) LockRange {
	if b.Start < a.Start {
		a.Start = b.Start
	}
	if b.End > a.End {
		a.End = b.End
	}
	return a
}

func conflicts(a, b Lock) bool {
	return a.Owner.Flock == b.Owner.Flock && a.Owner != b.Owner && overlaps(a.Range, b.Range) && (a.Type == LockWrite || b.Type == LockWrite)
}

// satisfies reports whether a record already held at mode `held` covers a
// request for mode `want`.
func satisfies(held, want LockType) bool { return held == LockWrite || want == LockRead }

// subtractLock returns what remains of held once cut is removed from it.
func subtractLock(held Lock, cut LockRange) []Lock {
	var out []Lock
	if cut.Start > held.Range.Start {
		left := held
		left.Range.End = cut.Start - 1
		out = append(out, left)
	}
	if cut.End < held.Range.End {
		right := held
		right.Range.Start = cut.End + 1
		out = append(out, right)
	}
	return out
}

// ---------------------------------------------------------------------------
// interval index
// ---------------------------------------------------------------------------

// intervalNode is one entry of a treap ordered by (start, end, id) and
// augmented with the largest end in its subtree. The augmentation turns "every
// entry intersecting this range" into an O(log n + k) traversal, which is the
// only reason one inode carrying tens of thousands of disjoint records stays
// usable: no operation ever rebuilds, re-sorts, or rescans the whole set.
type intervalNode[T any] struct {
	start, end  uint64
	id          uint64
	maxEnd      uint64
	priority    uint64
	value       T
	left, right *intervalNode[T]
}

type intervalTree[T any] struct {
	root *intervalNode[T]
	size int
}

// splitmix64 derives a treap priority from the entry's unique id. Ids are
// assigned monotonically, and splitmix64 spreads them well enough that the tree
// keeps its expected logarithmic depth without carrying a random source.
func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func intervalKeyLess(aStart, aEnd, aID, bStart, bEnd, bID uint64) bool {
	if aStart != bStart {
		return aStart < bStart
	}
	if aEnd != bEnd {
		return aEnd < bEnd
	}
	return aID < bID
}

func (n *intervalNode[T]) update() {
	n.maxEnd = n.end
	if n.left != nil && n.left.maxEnd > n.maxEnd {
		n.maxEnd = n.left.maxEnd
	}
	if n.right != nil && n.right.maxEnd > n.maxEnd {
		n.maxEnd = n.right.maxEnd
	}
}

func rotateIntervalRight[T any](n *intervalNode[T]) *intervalNode[T] {
	pivot := n.left
	n.left = pivot.right
	pivot.right = n
	n.update()
	pivot.update()
	return pivot
}

func rotateIntervalLeft[T any](n *intervalNode[T]) *intervalNode[T] {
	pivot := n.right
	n.right = pivot.left
	pivot.left = n
	n.update()
	pivot.update()
	return pivot
}

func insertInterval[T any](n, fresh *intervalNode[T]) *intervalNode[T] {
	if n == nil {
		return fresh
	}
	if intervalKeyLess(fresh.start, fresh.end, fresh.id, n.start, n.end, n.id) {
		n.left = insertInterval(n.left, fresh)
		if n.left.priority > n.priority {
			n = rotateIntervalRight(n)
		}
	} else {
		n.right = insertInterval(n.right, fresh)
		if n.right.priority > n.priority {
			n = rotateIntervalLeft(n)
		}
	}
	n.update()
	return n
}

// insert adds one entry. id must be unique within the tree.
func (t *intervalTree[T]) insert(start, end, id uint64, value T) {
	fresh := &intervalNode[T]{start: start, end: end, id: id, maxEnd: end, priority: splitmix64(id), value: value}
	t.root = insertInterval(t.root, fresh)
	t.size++
}

func mergeIntervals[T any](a, b *intervalNode[T]) *intervalNode[T] {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case a.priority > b.priority:
		a.right = mergeIntervals(a.right, b)
		a.update()
		return a
	default:
		b.left = mergeIntervals(a, b.left)
		b.update()
		return b
	}
}

func removeInterval[T any](n *intervalNode[T], start, end, id uint64) (*intervalNode[T], bool) {
	if n == nil {
		return nil, false
	}
	switch {
	case n.start == start && n.end == end && n.id == id:
		return mergeIntervals(n.left, n.right), true
	case intervalKeyLess(start, end, id, n.start, n.end, n.id):
		child, removed := removeInterval(n.left, start, end, id)
		n.left = child
		n.update()
		return n, removed
	default:
		child, removed := removeInterval(n.right, start, end, id)
		n.right = child
		n.update()
		return n, removed
	}
}

func (t *intervalTree[T]) remove(start, end, id uint64) bool {
	root, removed := removeInterval(t.root, start, end, id)
	t.root = root
	if removed {
		t.size--
	}
	return removed
}

func overlapWalk[T any](n *intervalNode[T], r LockRange, visit func(*intervalNode[T]) bool) bool {
	if n == nil || n.maxEnd < r.Start {
		return true
	}
	if !overlapWalk(n.left, r, visit) {
		return false
	}
	// Entries are visited in key order, so once a start is past r every
	// remaining entry is too.
	if n.start > r.End {
		return false
	}
	if n.end >= r.Start && !visit(n) {
		return false
	}
	return overlapWalk(n.right, r, visit)
}

// overlap visits, in key order, every entry intersecting r. visit returns false
// to stop. The tree must not be mutated during a traversal; callers collect
// first and mutate afterwards.
func (t *intervalTree[T]) overlap(r LockRange, visit func(*intervalNode[T]) bool) {
	overlapWalk(t.root, r, visit)
}

// all visits every entry in key order.
func (t *intervalTree[T]) all(visit func(*intervalNode[T]) bool) {
	t.overlap(LockRange{Start: 0, End: math.MaxUint64}, visit)
}

// ---------------------------------------------------------------------------
// lock table
// ---------------------------------------------------------------------------

// lockWaiter is one queued blocking request. A waiter is settled exactly once,
// under LockTable.mu, by whichever of grant, cancellation, or session release
// reaches it first; done is closed at that instant so the blocked goroutine
// observes a decision that can no longer change.
type lockWaiter struct {
	lock    Lock
	seq     uint64
	session *lockSession
	done    chan struct{}
	settled bool
	err     error
}

// objectLocks is the coordination state of one inode identity: the records held
// on it and the requests queued for it, both indexed by byte range.
type objectLocks struct {
	held    intervalTree[Lock]
	waiting intervalTree[*lockWaiter]
}

// LockLease is the lock table's view of one session's renewable lease. The
// authority renews it on every admitted request without taking the table's
// mutex, and the table reads it at every point where a record could be
// installed or handed out. A session whose lease has run out therefore cannot
// acquire, keep acquiring, or be granted a byte-range lock even in the interval
// between its expiry and the sweep that removes it.
type LockLease struct{ expires atomic.Int64 }

// Renew publishes the session's current renewable lease boundary.
func (l *LockLease) Renew(expires time.Time) { l.expires.Store(expires.UnixNano()) }

func (l *LockLease) live(now time.Time) bool { return now.UnixNano() < l.expires.Load() }

// lockSession is the lock table's record of one live session. Every held record
// and every queued waiter belongs to exactly one of these, and a session that is
// not in LockTable.sessions has neither: releasing a session removes its
// registration, its records, and its waiters in one critical section, so there
// is no interval in which a dead session can hold or be handed a lock.
type lockSession struct {
	lease *LockLease
	// records counts held records plus queued waiters, the same unit the table
	// bounds globally.
	records uint64
	objects map[ObjectKey]uint64
	// waiters is keyed by lock owner because that is the node type of the
	// wait-for graph: deadlock detection expands one owner at a time and must
	// not have to scan a whole session's queue to do it.
	waiters map[LockOwner]map[*lockWaiter]struct{}
}

type wakeRequest struct {
	object ObjectKey
	span   LockRange
}

// LockTable is authority-epoch state. It keys aliases by object identity, not
// path, implements POSIX same-owner replacement/split/coalesce behavior, and
// binds every record and waiter to a registered session.
type LockTable struct {
	mu       sync.Mutex
	objects  map[ObjectKey]*objectLocks
	sessions map[SessionID]*lockSession

	held    uint64
	waiting uint64
	nextID  uint64
	nextSeq uint64

	maxRecords    uint64
	maxPerSession uint64
	now           func() time.Time

	// waking serializes the wake cascade so a grant that itself weakens
	// coverage queues more work instead of recursing.
	waking      bool
	pendingWake []wakeRequest
}

// NewLockTable bounds the table globally and per session. Both bounds count
// held records plus queued waiters. maxPerSession is what makes one session
// unable to consume the budget every other session depends on; it must be
// positive and no larger than maxRecords. now is the authority's clock and must
// be the same one the sessions' leases are computed against.
func NewLockTable(maxRecords, maxPerSession uint32, now func() time.Time) *LockTable {
	if maxRecords == 0 || maxPerSession == 0 || maxPerSession > maxRecords {
		panic("volumeserver: lock table bounds must be positive with a per-session bound inside the global bound")
	}
	if now == nil {
		now = time.Now
	}
	return &LockTable{
		objects:       make(map[ObjectKey]*objectLocks),
		sessions:      make(map[SessionID]*lockSession),
		maxRecords:    uint64(maxRecords),
		maxPerSession: uint64(maxPerSession),
		now:           now,
	}
}

// RegisterSession admits a session to the lock table and returns the handle the
// authority renews its lease through. Only a registered session whose lease is
// still live can hold, acquire, or wait for a lock.
func (t *LockTable) RegisterSession(id SessionID, expires time.Time) *LockLease {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing := t.sessions[id]; existing != nil {
		return existing.lease
	}
	lease := &LockLease{}
	lease.Renew(expires)
	t.sessions[id] = &lockSession{lease: lease, objects: make(map[ObjectKey]uint64), waiters: make(map[LockOwner]map[*lockWaiter]struct{})}
	return lease
}

// liveSessionLocked resolves the session an operation is acting for. It is the
// single gate every acquisition, release, query, and grant passes through, so
// "this session may own locks" and "the authority still recognises this
// session" are one fact rather than two that have to be kept in agreement.
func (t *LockTable) liveSessionLocked(id SessionID) *lockSession {
	s := t.sessions[id]
	if s == nil || !s.lease.live(t.now()) {
		return nil
	}
	return s
}

// ReleaseSession removes a session and everything it owns. The authority calls
// it at the instant a session becomes terminal — before its in-flight
// operations have drained — so that no operation admitted under the old
// liveness can still acquire, and no waiter can still be granted, under a
// session the authority has already given up on.
func (t *LockTable) ReleaseSession(id SessionID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[id]
	if s == nil {
		return
	}
	delete(t.sessions, id)

	touched := make(map[ObjectKey]LockRange, len(s.objects)+1)
	extend := func(object ObjectKey, r LockRange) {
		if current, ok := touched[object]; ok {
			touched[object] = coverRange(current, r)
		} else {
			touched[object] = r
		}
	}

	// Waiters are cancelled before any record is dropped. Dropping records first
	// would run the wake cascade while this session's own waiters were still
	// queued, which is exactly how a swept session used to be handed a grant.
	for _, byOwner := range s.waiters {
		for waiter := range byOwner {
			if o := t.objects[waiter.lock.Object]; o != nil {
				t.removeWaiterLocked(o, waiter)
			}
			t.settleWaiterLocked(waiter, ErrSessionExpired)
			extend(waiter.lock.Object, waiter.lock.Range)
		}
	}

	for object := range s.objects {
		o := t.objects[object]
		if o == nil {
			continue
		}
		var doomed []*intervalNode[Lock]
		o.held.all(func(n *intervalNode[Lock]) bool {
			if n.value.Owner.Session == id {
				doomed = append(doomed, n)
			}
			return true
		})
		for _, n := range doomed {
			o.held.remove(n.start, n.end, n.id)
			t.held--
			extend(object, n.value.Range)
		}
	}
	s.records, s.objects, s.waiters = 0, nil, nil

	for object, span := range touched {
		t.wakeEligibleLocked(object, span)
	}
	for object := range touched {
		t.pruneObjectLocked(object)
	}
}

// Get reports the record that would prevent want from being acquired. It
// reports held records only, matching F_GETLK: a queued waiter is not a lock.
func (t *LockTable) Get(want Lock) (Lock, bool, error) {
	if !validLock(want) {
		return Lock{}, false, errInvalidLock
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.liveSessionLocked(want.Owner.Session) == nil {
		return Lock{}, false, ErrSessionExpired
	}
	held, ok := conflictLocked(t.objects[want.Object], want)
	return held, ok, nil
}

// Set is the non-blocking acquisition (F_SETLK). It fails rather than jumping
// queued blocking requests: without that, any stream of non-blocking callers
// starves a queued writer forever, because queue order would only ever be
// enforced between waiters.
func (t *LockTable) Set(lock Lock) error {
	if !validLock(lock) {
		return errInvalidLock
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.liveSessionLocked(lock.Owner.Session)
	if s == nil {
		return ErrSessionExpired
	}
	o := t.objects[lock.Object]
	if _, conflict := conflictLocked(o, lock); conflict {
		return ErrLockConflict
	}
	// Only coverage the owner does not already hold at a sufficient mode is
	// subject to queue order. A re-assertion or a downgrade acquires nothing and
	// must never be refused because someone is queued behind the owner.
	residual := residualLocked(o, lock)
	if len(residual) > 0 && queuedAheadLocked(o, lock, residual, math.MaxUint64) != nil {
		return ErrLockConflict
	}
	plan := planAcquireLocked(o, lock)
	err := t.applyPlanLocked(lock.Object, s, plan)
	t.pruneObjectLocked(lock.Object)
	return err
}

// Wait is the blocking acquisition (F_SETLKW). A queued request is handed its
// lock by the operation that made it eligible, inside that operation's critical
// section, so a grant cannot be stolen between the wake and the acquisition.
func (t *LockTable) Wait(ctx context.Context, lock Lock) error {
	wait, err := t.BeginWait(lock)
	if err != nil {
		return err
	}
	return wait.Await(ctx)
}

// PendingLock is one admitted blocking acquisition. BeginWait publishes the
// waiter into the table before returning it, so a topology writer can exclude
// new admissions, retire every already-published waiter in one table critical
// section, and then change routing without holding a volume-wide filesystem
// reader for the duration of F_SETLKW.
//
// A PendingLock has exactly one consumer. It is deliberately not a future that
// can be copied or awaited by several goroutines: the kernel request that owns
// it is the only operation allowed to observe the grant.
type PendingLock struct {
	table  *LockTable
	waiter *lockWaiter
}

// BeginWait atomically either grants lock or publishes its waiter. The caller
// may surround this short admission with another ordering guard and release
// that guard before Await blocks.
func (t *LockTable) BeginWait(lock Lock) (*PendingLock, error) {
	if !validLock(lock) {
		return nil, errInvalidLock
	}
	t.mu.Lock()
	s := t.liveSessionLocked(lock.Owner.Session)
	if s == nil {
		t.mu.Unlock()
		return nil, ErrSessionExpired
	}
	t.nextSeq++
	w := &lockWaiter{lock: lock, seq: t.nextSeq, session: s, done: make(chan struct{})}
	o := t.objects[lock.Object]
	if waiterEligibleLocked(o, w) {
		plan := planAcquireLocked(o, lock)
		err := t.applyPlanLocked(lock.Object, s, plan)
		t.pruneObjectLocked(lock.Object)
		t.settleWaiterLocked(w, err)
		t.mu.Unlock()
		return &PendingLock{table: t, waiter: w}, nil
	}
	if t.held+t.waiting+1 > t.maxRecords || s.records+1 > t.maxPerSession {
		t.mu.Unlock()
		return nil, ErrAdmission
	}
	t.insertWaiterLocked(t.objectLocked(lock.Object), w)
	if t.deadlockLocked(w) {
		t.cancelWaiterLocked(w, ErrDeadlock)
		err := w.err
		t.mu.Unlock()
		return nil, err
	}
	t.mu.Unlock()
	return &PendingLock{table: t, waiter: w}, nil
}

// Await waits for the one decision made for an admitted lock request. A grant
// that was installed before context cancellation wins, matching POSIX lock
// ownership; an interrupted queued waiter is removed before the error returns.
func (w *PendingLock) Await(ctx context.Context) error {
	if w == nil || w.table == nil || w.waiter == nil {
		return errInvalidLock
	}
	select {
	case <-w.waiter.done:
	case <-ctx.Done():
		w.table.mu.Lock()
		// A grant that landed before the cancellation wins: the record already
		// exists, and reporting a failure would leave the caller believing it
		// holds nothing while the table says otherwise.
		if !w.waiter.settled {
			w.table.cancelWaiterLocked(w.waiter, ctx.Err())
		}
		err := w.waiter.err
		w.table.mu.Unlock()
		return err
	}
	w.table.mu.Lock()
	err := w.waiter.err
	w.table.mu.Unlock()
	return err
}

// InterruptWaiters atomically retires every queued acquisition without
// disturbing held records. Routing uses this at the topology transition
// boundary: all old-revision waits become ESTALE before fencing any holder can
// release a record and wake them. Removing the complete queue before running a
// wake cascade is essential; cancelling one waiter at a time could grant the
// next stale waiter in between cancellations.
func (t *LockTable) InterruptWaiters(err error) {
	if err == nil {
		err = ErrSessionExpired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var waiters []*lockWaiter
	for _, session := range t.sessions {
		for _, byOwner := range session.waiters {
			for waiter := range byOwner {
				waiters = append(waiters, waiter)
			}
		}
	}
	touched := make(map[ObjectKey]struct{}, len(waiters))
	for _, waiter := range waiters {
		if o := t.objects[waiter.lock.Object]; o != nil {
			t.removeWaiterLocked(o, waiter)
		}
		t.settleWaiterLocked(waiter, err)
		touched[waiter.lock.Object] = struct{}{}
	}
	for object := range touched {
		t.pruneObjectLocked(object)
	}
}

// Unlock removes owner's coverage of r, splitting records where r punches a
// hole. It never rewrites a record belonging to any other owner.
func (t *LockTable) Unlock(object ObjectKey, owner LockOwner, r LockRange) error {
	if r.Start > r.End {
		return errInvalidUnlockRange
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.liveSessionLocked(owner.Session)
	if s == nil {
		return ErrSessionExpired
	}
	plan := planReleaseLocked(t.objects[object], owner, r)
	if len(plan.remove) == 0 {
		return nil
	}
	err := t.applyPlanLocked(object, s, plan)
	t.pruneObjectLocked(object)
	return err
}

// ---------------------------------------------------------------------------
// queries
// ---------------------------------------------------------------------------

func conflictLocked(o *objectLocks, want Lock) (Lock, bool) {
	if o == nil {
		return Lock{}, false
	}
	var blocker Lock
	found := false
	o.held.overlap(want.Range, func(n *intervalNode[Lock]) bool {
		if conflicts(want, n.value) {
			blocker, found = n.value, true
			return false
		}
		return true
	})
	return blocker, found
}

// residualLocked returns the parts of lock.Range that lock.Owner does not
// already hold at a mode satisfying lock.Type.
func residualLocked(o *objectLocks, lock Lock) []LockRange {
	if o == nil {
		return []LockRange{lock.Range}
	}
	var covered []LockRange
	o.held.overlap(lock.Range, func(n *intervalNode[Lock]) bool {
		if n.value.Owner == lock.Owner && satisfies(n.value.Type, lock.Type) {
			covered = append(covered, n.value.Range)
		}
		return true
	})
	return subtractCoverage(lock.Range, covered)
}

// subtractCoverage removes covered (key-ordered, pairwise disjoint) from r.
func subtractCoverage(r LockRange, covered []LockRange) []LockRange {
	var out []LockRange
	cursor := r.Start
	for _, c := range covered {
		if c.End < cursor {
			continue
		}
		if c.Start > cursor {
			out = append(out, LockRange{Start: cursor, End: c.Start - 1})
		}
		if c.End >= r.End {
			return out
		}
		cursor = c.End + 1
	}
	if cursor <= r.End {
		out = append(out, LockRange{Start: cursor, End: r.End})
	}
	return out
}

// queuedAheadLocked returns a waiter queued before `before` that conflicts with
// any residual segment lock would newly acquire.
func queuedAheadLocked(o *objectLocks, lock Lock, residual []LockRange, before uint64) *lockWaiter {
	if o == nil || o.waiting.size == 0 {
		return nil
	}
	var found *lockWaiter
	for _, segment := range residual {
		probe := lock
		probe.Range = segment
		o.waiting.overlap(segment, func(n *intervalNode[*lockWaiter]) bool {
			if n.value.seq < before && conflicts(probe, n.value.lock) {
				found = n.value
				return false
			}
			return true
		})
		if found != nil {
			return found
		}
	}
	return nil
}

func waiterEligibleLocked(o *objectLocks, w *lockWaiter) bool {
	if _, conflict := conflictLocked(o, w.lock); conflict {
		return false
	}
	residual := residualLocked(o, w.lock)
	if len(residual) == 0 {
		return true
	}
	return queuedAheadLocked(o, w.lock, residual, w.seq) == nil
}

// ---------------------------------------------------------------------------
// mutation plans
// ---------------------------------------------------------------------------

// lockPlan is a complete description of one record-set change, computed before
// anything is touched. Admission is decided against the plan, so a refused
// operation cannot have already modified the table.
type lockPlan struct {
	remove []*intervalNode[Lock]
	insert []Lock
	// touched spans every byte whose coverage the plan changes.
	touched LockRange
	// weakens is set when the plan can drop coverage some waiter is blocked on.
	weakens bool
}

// planAcquireLocked computes the POSIX replacement for installing next: the
// owner's overlapping records are split around it, and its same-mode
// neighbours — overlapping or merely adjacent — are absorbed into it. Records
// of every other owner are untouched, and neighbours are found by range rather
// than by position in a sorted list, so an unrelated owner's record lying
// between two of this owner's records no longer defeats coalescing.
func planAcquireLocked(o *objectLocks, next Lock) lockPlan {
	plan := lockPlan{touched: next.Range}
	merged := next
	var keep []Lock
	if o != nil {
		query := next.Range
		if query.Start > 0 {
			query.Start--
		}
		if query.End < math.MaxUint64 {
			query.End++
		}
		var candidates []*intervalNode[Lock]
		o.held.overlap(query, func(n *intervalNode[Lock]) bool {
			if n.value.Owner == next.Owner {
				candidates = append(candidates, n)
			}
			return true
		})
		for _, n := range candidates {
			held := n.value
			if !overlaps(held.Range, next.Range) && !(held.Type == next.Type && adjacent(held.Range, next.Range)) {
				continue
			}
			plan.remove = append(plan.remove, n)
			plan.touched = coverRange(plan.touched, held.Range)
			if overlaps(held.Range, next.Range) {
				if held.Type == LockWrite && next.Type == LockRead {
					plan.weakens = true
				}
				keep = append(keep, subtractLock(held, next.Range)...)
			} else {
				keep = append(keep, held)
			}
		}
	}
	for {
		absorbed := false
		var remaining []Lock
		for _, candidate := range keep {
			if candidate.Type == merged.Type && (overlaps(candidate.Range, merged.Range) || adjacent(candidate.Range, merged.Range)) {
				merged.Range = coverRange(merged.Range, candidate.Range)
				absorbed = true
				continue
			}
			remaining = append(remaining, candidate)
		}
		keep = remaining
		if !absorbed {
			break
		}
	}
	plan.insert = append(plan.insert, keep...)
	plan.insert = append(plan.insert, merged)
	plan.touched = coverRange(plan.touched, merged.Range)
	return plan
}

// planReleaseLocked computes the removal of owner's coverage of r.
func planReleaseLocked(o *objectLocks, owner LockOwner, r LockRange) lockPlan {
	plan := lockPlan{touched: r}
	if o == nil {
		return plan
	}
	var candidates []*intervalNode[Lock]
	o.held.overlap(r, func(n *intervalNode[Lock]) bool {
		if n.value.Owner == owner {
			candidates = append(candidates, n)
		}
		return true
	})
	for _, n := range candidates {
		plan.remove = append(plan.remove, n)
		plan.touched = coverRange(plan.touched, n.value.Range)
		plan.insert = append(plan.insert, subtractLock(n.value, r)...)
	}
	plan.weakens = len(plan.remove) > 0
	return plan
}

// applyPlanLocked is the only path that changes a record set. It admits the
// plan first and mutates second, and every plan that can weaken coverage
// schedules a wake — including a write-to-read downgrade, which is a mutation
// no waiter would otherwise be told about.
func (t *LockTable) applyPlanLocked(object ObjectKey, s *lockSession, plan lockPlan) error {
	removed, added := uint64(len(plan.remove)), uint64(len(plan.insert))
	if added > removed {
		delta := added - removed
		if t.held+t.waiting+delta > t.maxRecords {
			return ErrAdmission
		}
		if s.records+delta > t.maxPerSession {
			return ErrAdmission
		}
	}
	o := t.objectLocked(object)
	for _, n := range plan.remove {
		o.held.remove(n.start, n.end, n.id)
	}
	for _, lock := range plan.insert {
		t.nextID++
		o.held.insert(lock.Range.Start, lock.Range.End, t.nextID, lock)
	}
	t.held = t.held - removed + added
	s.records = s.records - removed + added
	if count := s.objects[object] - removed + added; count == 0 {
		delete(s.objects, object)
	} else {
		s.objects[object] = count
	}
	if plan.weakens {
		t.wakeEligibleLocked(object, plan.touched)
	}
	return nil
}

// ---------------------------------------------------------------------------
// waiter queue
// ---------------------------------------------------------------------------

func (t *LockTable) objectLocked(key ObjectKey) *objectLocks {
	o := t.objects[key]
	if o == nil {
		o = &objectLocks{}
		t.objects[key] = o
	}
	return o
}

func (t *LockTable) pruneObjectLocked(key ObjectKey) {
	if o := t.objects[key]; o != nil && o.held.size == 0 && o.waiting.size == 0 {
		delete(t.objects, key)
	}
}

func (t *LockTable) insertWaiterLocked(o *objectLocks, w *lockWaiter) {
	o.waiting.insert(w.lock.Range.Start, w.lock.Range.End, w.seq, w)
	byOwner := w.session.waiters[w.lock.Owner]
	if byOwner == nil {
		byOwner = make(map[*lockWaiter]struct{})
		w.session.waiters[w.lock.Owner] = byOwner
	}
	byOwner[w] = struct{}{}
	w.session.records++
	t.waiting++
}

func (t *LockTable) removeWaiterLocked(o *objectLocks, w *lockWaiter) {
	if !o.waiting.remove(w.lock.Range.Start, w.lock.Range.End, w.seq) {
		return
	}
	if byOwner := w.session.waiters[w.lock.Owner]; byOwner != nil {
		delete(byOwner, w)
		if len(byOwner) == 0 {
			delete(w.session.waiters, w.lock.Owner)
		}
	}
	w.session.records--
	t.waiting--
}

func (t *LockTable) settleWaiterLocked(w *lockWaiter, err error) {
	if w.settled {
		return
	}
	w.settled, w.err = true, err
	close(w.done)
}

// cancelWaiterLocked removes a queued request without granting it. Dropping a
// queue entry can make later requests eligible, so it always schedules a wake
// over the vacated range.
func (t *LockTable) cancelWaiterLocked(w *lockWaiter, err error) {
	if o := t.objects[w.lock.Object]; o != nil {
		t.removeWaiterLocked(o, w)
		t.settleWaiterLocked(w, err)
		t.wakeEligibleLocked(w.lock.Object, w.lock.Range)
		t.pruneObjectLocked(w.lock.Object)
		return
	}
	t.settleWaiterLocked(w, err)
}

// wakeEligibleLocked grants every queued request that the change over span made
// eligible. Re-entrant calls — a grant that itself weakens coverage — queue more
// work for the outermost drain instead of recursing, so the cascade terminates
// after at most one pass per grant.
func (t *LockTable) wakeEligibleLocked(object ObjectKey, span LockRange) {
	t.pendingWake = append(t.pendingWake, wakeRequest{object: object, span: span})
	if t.waking {
		return
	}
	t.waking = true
	for i := 0; i < len(t.pendingWake); i++ {
		request := t.pendingWake[i]
		t.grantEligibleLocked(request.object, request.span)
	}
	t.pendingWake = t.pendingWake[:0]
	t.waking = false
}

func (t *LockTable) grantEligibleLocked(object ObjectKey, span LockRange) {
	o := t.objects[object]
	if o == nil || o.waiting.size == 0 {
		return
	}
	var candidates []*lockWaiter
	o.waiting.overlap(span, func(n *intervalNode[*lockWaiter]) bool {
		candidates = append(candidates, n.value)
		return true
	})
	// Queue order is decided here, once, over the requests the change could have
	// freed — not by rescanning every waiter on the inode.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].seq < candidates[j].seq })
	now := t.now()
	for _, w := range candidates {
		if w.settled {
			continue
		}
		o = t.objects[object]
		if o == nil {
			return
		}
		// A request whose session outlived its lease is retired here rather than
		// handed a grant. Waking is the only moment a queued request can become
		// a held record, so this is the point at which the two must agree.
		if !w.session.lease.live(now) {
			t.cancelWaiterLocked(w, ErrSessionExpired)
			continue
		}
		if !waiterEligibleLocked(o, w) {
			continue
		}
		plan := planAcquireLocked(o, w.lock)
		session := w.session
		t.removeWaiterLocked(o, w)
		if err := t.applyPlanLocked(object, session, plan); err != nil {
			t.settleWaiterLocked(w, err)
			t.wakeEligibleLocked(object, w.lock.Range)
			continue
		}
		t.settleWaiterLocked(w, nil)
	}
}

// ---------------------------------------------------------------------------
// deadlock detection
// ---------------------------------------------------------------------------

// deadlockLocked reports whether w's owner is, transitively, already blocking
// itself: the wait-for graph edge set is "owner X waits for owner Y" derived
// from the records and queue entries that actually block each request.
func (t *LockTable) deadlockLocked(w *lockWaiter) bool {
	origin := w.lock.Owner
	visited := make(map[LockOwner]struct{})
	frontier := t.blockersLocked(w)
	for len(frontier) > 0 {
		owner := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if owner == origin {
			return true
		}
		if _, seen := visited[owner]; seen {
			continue
		}
		visited[owner] = struct{}{}
		s := t.sessions[owner.Session]
		if s == nil {
			continue
		}
		for other := range s.waiters[owner] {
			if other == w {
				continue
			}
			frontier = append(frontier, t.blockersLocked(other)...)
		}
	}
	return false
}

// blockersLocked returns the owners w cannot proceed without: the holders of
// conflicting records, and every queue entry ahead of w that conflicts with the
// coverage w still needs.
func (t *LockTable) blockersLocked(w *lockWaiter) []LockOwner {
	o := t.objects[w.lock.Object]
	if o == nil {
		return nil
	}
	var out []LockOwner
	o.held.overlap(w.lock.Range, func(n *intervalNode[Lock]) bool {
		if conflicts(w.lock, n.value) {
			out = append(out, n.value.Owner)
		}
		return true
	})
	for _, segment := range residualLocked(o, w.lock) {
		probe := w.lock
		probe.Range = segment
		o.waiting.overlap(segment, func(n *intervalNode[*lockWaiter]) bool {
			if n.value.seq < w.seq && conflicts(probe, n.value.lock) {
				out = append(out, n.value.lock.Owner)
			}
			return true
		})
	}
	return out
}
