// Package locks is the authority's single-point advisory byte-range lock table (POSIX fcntl /
// flock). Because every client locks through the one VCS authority, cross-client conflicts are
// detected correctly — the coordination shared workloads (e.g. SQLite, or any app using
// flock/fcntl) need across machines, which a per-client kernel lock table cannot provide.
//
// Semantics: a lock is a byte range [start,end] (inclusive; end == EOF for "to end of file"),
// shared (read) or exclusive (write). Two locks CONFLICT iff they have different owners, their
// ranges overlap, and at least one is exclusive. A lock owner is (mount-owner, kernel-lock-id):
// a process never conflicts with its own locks (it may refine/upgrade them). Unlocking a sub-range
// splits any covering lock, matching POSIX. Setlkw blocks until grantable or the caller's context
// is cancelled; a dropped mount's locks are all released (ReleaseOwner), so a crash frees them.
package locks

import (
	"context"
	"sync"
)

// EOF is the end value for a lock that extends to the end of the file.
const EOF = ^uint64(0)

// Owner uniquely identifies a lock owner across clients.
type Owner struct {
	Mount string // the mount's checkout-owner id (unique per mount)
	LkID  uint64 // the kernel's per-open lock owner id
}

// Held is a granted lock (also the value Getlk reports for a conflict).
type Held struct {
	Owner Owner
	Start uint64
	End   uint64 // inclusive; EOF = to end of file
	Write bool   // true = exclusive (F_WRLCK); false = shared (F_RDLCK)
}

// Manager is the authority's lock table.
type Manager struct {
	mu     sync.Mutex
	byPath map[string][]Held
	waitCh map[string]chan struct{} // per-path "a lock was released" signal for Setlkw waiters
}

// New returns an empty lock table.
func New() *Manager {
	return &Manager{byPath: map[string][]Held{}, waitCh: map[string]chan struct{}{}}
}

func overlaps(s1, e1, s2, e2 uint64) bool { return s1 <= e2 && s2 <= e1 }

func conflict(a Held, owner Owner, start, end uint64, write bool) bool {
	if a.Owner == owner {
		return false // a process never conflicts with itself
	}
	if !overlaps(a.Start, a.End, start, end) {
		return false
	}
	return a.Write || write // a conflict needs at least one exclusive lock
}

func (m *Manager) conflictsLocked(path string, owner Owner, start, end uint64, write bool) (Held, bool) {
	for _, h := range m.byPath[path] {
		if conflict(h, owner, start, end, write) {
			return h, true
		}
	}
	return Held{}, false
}

func (m *Manager) addLocked(path string, owner Owner, start, end uint64, write bool) {
	m.byPath[path] = append(m.byPath[path], Held{Owner: owner, Start: start, End: end, Write: write})
}

// removeLocked drops owner's locks overlapping [start,end], splitting any that extend beyond it
// (POSIX partial unlock), and wakes Setlkw waiters on the path.
func (m *Manager) removeLocked(path string, owner Owner, start, end uint64) {
	cur := m.byPath[path]
	var kept []Held
	for _, h := range cur {
		if h.Owner != owner || !overlaps(h.Start, h.End, start, end) {
			kept = append(kept, h)
			continue
		}
		if h.Start < start { // keep the prefix outside the unlock range
			kept = append(kept, Held{Owner: h.Owner, Start: h.Start, End: start - 1, Write: h.Write})
		}
		if h.End > end { // keep the suffix outside the unlock range
			kept = append(kept, Held{Owner: h.Owner, Start: end + 1, End: h.End, Write: h.Write})
		}
	}
	if len(kept) == 0 {
		delete(m.byPath, path)
	} else {
		m.byPath[path] = kept
	}
	m.wakeLocked(path)
}

func (m *Manager) waitChLocked(path string) chan struct{} {
	ch, ok := m.waitCh[path]
	if !ok {
		ch = make(chan struct{})
		m.waitCh[path] = ch
	}
	return ch
}

func (m *Manager) wakeLocked(path string) {
	if ch, ok := m.waitCh[path]; ok {
		close(ch)
		delete(m.waitCh, path) // a fresh waiter makes a new channel
	}
}

// Getlk reports a lock that WOULD conflict with the proposed lock (for F_GETLK), or ok=false.
func (m *Manager) Getlk(path string, owner Owner, start, end uint64, write bool) (Held, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conflictsLocked(path, owner, start, end, write)
}

// Setlk acquires (write/read) or releases (unlock) a lock WITHOUT blocking. It returns true if the
// operation is granted; false means a conflict (the caller maps it to EAGAIN).
func (m *Manager) Setlk(path string, owner Owner, start, end uint64, write, unlock bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if unlock {
		m.removeLocked(path, owner, start, end)
		return true
	}
	if _, c := m.conflictsLocked(path, owner, start, end, write); c {
		return false
	}
	m.addLocked(path, owner, start, end, write)
	return true
}

// Setlkw acquires a lock, blocking until it is grantable or ctx is cancelled (the FUSE op was
// interrupted). It returns true on grant, false if cancelled.
func (m *Manager) Setlkw(ctx context.Context, path string, owner Owner, start, end uint64, write bool) bool {
	for {
		m.mu.Lock()
		if _, c := m.conflictsLocked(path, owner, start, end, write); !c {
			m.addLocked(path, owner, start, end, write)
			m.mu.Unlock()
			return true
		}
		ch := m.waitChLocked(path)
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-ch:
		}
	}
}

// ReleaseOwner drops every lock held by a mount (all kernel-lock-ids under it) across all paths —
// crash cleanup when a mount's liveness stream drops, so its locks never wedge other clients.
func (m *Manager) ReleaseOwner(mount string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for path, locks := range m.byPath {
		var kept []Held
		for _, h := range locks {
			if h.Owner.Mount != mount {
				kept = append(kept, h)
			}
		}
		if len(kept) == 0 {
			delete(m.byPath, path)
		} else {
			m.byPath[path] = kept
		}
		m.wakeLocked(path)
	}
}
