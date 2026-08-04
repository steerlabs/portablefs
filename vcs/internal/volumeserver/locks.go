package volumeserver

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
)

var ErrLockConflict = errors.New("volumeserver: byte range lock conflicts")

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

type lockWaiter struct {
	lock      Lock
	wake      chan struct{}
	cancelled bool
}

// LockTable is authority-epoch state. It keys aliases by object identity, not
// path, and implements POSIX same-owner replacement/split/coalesce behavior.
type LockTable struct {
	mu         sync.Mutex
	locks      map[ObjectKey][]Lock
	waiters    map[ObjectKey][]*lockWaiter
	maxRecords uint32
}

func NewLockTable(maxRecords uint32) *LockTable {
	return &LockTable{locks: make(map[ObjectKey][]Lock), waiters: make(map[ObjectKey][]*lockWaiter), maxRecords: maxRecords}
}

func validLock(lock Lock) bool {
	return (lock.Type == LockRead || lock.Type == LockWrite) && lock.Range.Start <= lock.Range.End
}

func overlaps(a, b LockRange) bool { return a.Start <= b.End && b.Start <= a.End }

func conflicts(a, b Lock) bool {
	return a.Owner.Flock == b.Owner.Flock && a.Owner != b.Owner && overlaps(a.Range, b.Range) && (a.Type == LockWrite || b.Type == LockWrite)
}

func (t *LockTable) conflictLocked(want Lock) (Lock, bool) {
	for _, held := range t.locks[want.Object] {
		if conflicts(want, held) {
			return held, true
		}
	}
	return Lock{}, false
}

func (t *LockTable) Get(want Lock) (Lock, bool, error) {
	if !validLock(want) {
		return Lock{}, false, errors.New("volumeserver: invalid lock")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	held, ok := t.conflictLocked(want)
	return held, ok, nil
}

func (t *LockTable) Set(lock Lock) error {
	if !validLock(lock) {
		return errors.New("volumeserver: invalid lock")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, conflict := t.conflictLocked(lock); conflict {
		return ErrLockConflict
	}
	return t.replaceOwnerRangeLocked(lock)
}

func (t *LockTable) Wait(ctx context.Context, lock Lock) error {
	if !validLock(lock) {
		return errors.New("volumeserver: invalid lock")
	}
	w := &lockWaiter{lock: lock, wake: make(chan struct{}, 1)}
	t.mu.Lock()
	if t.recordCountLocked() >= uint64(t.maxRecords) {
		t.mu.Unlock()
		return ErrAdmission
	}
	t.waiters[lock.Object] = append(t.waiters[lock.Object], w)
	for {
		if w.cancelled {
			t.mu.Unlock()
			return ErrSessionExpired
		}
		if t.waiterCanAcquireLocked(w) {
			t.removeWaiterLocked(w)
			err := t.replaceOwnerRangeLocked(lock)
			t.wakeEligibleLocked(lock.Object)
			t.mu.Unlock()
			return err
		}
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			t.mu.Lock()
			t.removeWaiterLocked(w)
			t.wakeEligibleLocked(lock.Object)
			t.mu.Unlock()
			return ctx.Err()
		case <-w.wake:
			t.mu.Lock()
		}
	}
}

func (t *LockTable) Unlock(object ObjectKey, owner LockOwner, r LockRange) error {
	if r.Start > r.End {
		return errors.New("volumeserver: invalid unlock range")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.locks[object]
	out := current[:0]
	for _, held := range current {
		if held.Owner != owner || !overlaps(held.Range, r) {
			out = append(out, held)
			continue
		}
		out = append(out, subtractLock(held, r)...)
	}
	next := normalizeLocks(out)
	if t.recordCountLocked()-uint64(len(current))+uint64(len(next)) > uint64(t.maxRecords) {
		return ErrAdmission
	}
	if len(next) == 0 {
		delete(t.locks, object)
	} else {
		t.locks[object] = next
	}
	t.wakeEligibleLocked(object)
	return nil
}

func (t *LockTable) ReleaseSession(session SessionID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	touched := make(map[ObjectKey]struct{})
	for object, current := range t.locks {
		out := current[:0]
		for _, held := range current {
			if held.Owner.Session != session {
				out = append(out, held)
			}
		}
		if len(out) != len(current) {
			touched[object] = struct{}{}
		}
		if len(out) == 0 {
			delete(t.locks, object)
		} else {
			t.locks[object] = out
		}
	}
	for object, queue := range t.waiters {
		for _, waiter := range append([]*lockWaiter(nil), queue...) {
			if waiter.lock.Owner.Session == session {
				waiter.cancelled = true
				t.removeWaiterLocked(waiter)
				touched[object] = struct{}{}
				select {
				case waiter.wake <- struct{}{}:
				default:
				}
			}
		}
	}
	for object := range touched {
		t.wakeEligibleLocked(object)
	}
}

func (t *LockTable) replaceOwnerRangeLocked(next Lock) error {
	current := t.locks[next.Object]
	out := make([]Lock, 0, len(current)+1)
	for _, held := range current {
		if held.Owner == next.Owner && overlaps(held.Range, next.Range) {
			out = append(out, subtractLock(held, next.Range)...)
		} else {
			out = append(out, held)
		}
	}
	out = append(out, next)
	out = normalizeLocks(out)
	if t.recordCountLocked()-uint64(len(current))+uint64(len(out)) > uint64(t.maxRecords) {
		return ErrAdmission
	}
	t.locks[next.Object] = out
	return nil
}

func (t *LockTable) recordCountLocked() uint64 {
	var count uint64
	for object, held := range t.locks {
		count += uint64(len(held) + len(t.waiters[object]))
	}
	for object, waiters := range t.waiters {
		if _, exists := t.locks[object]; !exists {
			count += uint64(len(waiters))
		}
	}
	return count
}

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

func normalizeLocks(locks []Lock) []Lock {
	sort.Slice(locks, func(i, j int) bool {
		if locks[i].Range.Start != locks[j].Range.Start {
			return locks[i].Range.Start < locks[j].Range.Start
		}
		if locks[i].Owner.Session != locks[j].Owner.Session {
			return string(locks[i].Owner.Session[:]) < string(locks[j].Owner.Session[:])
		}
		if locks[i].Owner.Kernel != locks[j].Owner.Kernel {
			return locks[i].Owner.Kernel < locks[j].Owner.Kernel
		}
		return !locks[i].Owner.Flock && locks[j].Owner.Flock
	})
	out := locks[:0]
	for _, lock := range locks {
		if len(out) > 0 {
			last := &out[len(out)-1]
			adjacent := last.Range.End != math.MaxUint64 && last.Range.End+1 == lock.Range.Start
			if last.Owner == lock.Owner && last.Type == lock.Type && (overlaps(last.Range, lock.Range) || adjacent) {
				if lock.Range.End > last.Range.End {
					last.Range.End = lock.Range.End
				}
				continue
			}
		}
		out = append(out, lock)
	}
	return out
}

func (t *LockTable) removeWaiterLocked(target *lockWaiter) {
	object := target.lock.Object
	queue := t.waiters[object]
	for i, waiter := range queue {
		if waiter == target {
			next := append(queue[:i], queue[i+1:]...)
			if len(next) == 0 {
				delete(t.waiters, object)
			} else {
				t.waiters[object] = next
			}
			return
		}
	}
}

// waiterCanAcquireLocked preserves FIFO order only between waiters whose byte
// ranges actually conflict. Independent ranges must not head-of-line block one
// another merely because they belong to the same inode.
func (t *LockTable) waiterCanAcquireLocked(target *lockWaiter) bool {
	if _, conflict := t.conflictLocked(target.lock); conflict {
		return false
	}
	for _, earlier := range t.waiters[target.lock.Object] {
		if earlier == target {
			return true
		}
		if conflicts(target.lock, earlier.lock) {
			return false
		}
	}
	return false
}

func (t *LockTable) wakeEligibleLocked(object ObjectKey) {
	for _, waiter := range t.waiters[object] {
		if !t.waiterCanAcquireLocked(waiter) {
			continue
		}
		select {
		case waiter.wake <- struct{}{}:
		default:
		}
	}
}
