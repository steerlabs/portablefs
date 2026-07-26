package pfc2

import "sort"

// POSIX byte-range lock intervals, keyed by stable inode, owned by
// (SessionRef, kernel lock owner id). Intervals are kept NORMALIZED per inode:
//
//   - sorted by (start, end, owner, write) — a deterministic total order;
//   - one owner's intervals never overlap;
//   - one owner's adjacent same-type intervals are merged.
//
// Interval replacement, split, and merge are deterministic pure functions of
// (previous normalized set, operation), so replaying the same LockChange
// records always rebuilds byte-identical projections. Wait queues are
// deliberately absent: they are volatile and clients retry after restart.

// LockRangeEOF is the inclusive end offset of a lock that extends through EOF
// (POSIX l_len = 0).
const LockRangeEOF = ^uint64(0)

// LockOwner identifies one lock owner: the authenticated exact session plus
// the kernel's per-open lock owner id. Client Owner strings are display
// labels and can never authorize locks.
type LockOwner struct {
	Session         SessionRef
	KernelLockOwner uint64
}

// HeldLock is one normalized granted interval (also the shape Getlk-style
// conflict queries report).
type HeldLock struct {
	Owner LockOwner
	Start uint64
	End   uint64 // inclusive; LockRangeEOF = through EOF
	Write bool
}

func lockOwnerLess(a, b LockOwner) bool {
	if a.Session.SessionID != b.Session.SessionID {
		return a.Session.SessionID < b.Session.SessionID
	}
	if a.Session.Generation != b.Session.Generation {
		return a.Session.Generation < b.Session.Generation
	}
	return a.KernelLockOwner < b.KernelLockOwner
}

func heldLess(a, b HeldLock) bool {
	if a.Start != b.Start {
		return a.Start < b.Start
	}
	if a.End != b.End {
		return a.End < b.End
	}
	if a.Owner != b.Owner {
		return lockOwnerLess(a.Owner, b.Owner)
	}
	return !a.Write && b.Write
}

func rangesOverlap(s1, e1, s2, e2 uint64) bool { return s1 <= e2 && s2 <= e1 }

// sortLocks orders intervals by the canonical deterministic order.
func sortLocks(set []HeldLock) {
	sort.Slice(set, func(i, j int) bool { return heldLess(set[i], set[j]) })
}

// normalizeLocks merges each owner's adjacent same-type intervals (even when
// another owner's interval interleaves in the global order) and returns the
// canonical sorted set. It requires (and preserves) per-owner non-overlap.
func normalizeLocks(set []HeldLock) []HeldLock {
	byOwner := map[LockOwner][]HeldLock{}
	for _, h := range set {
		byOwner[h.Owner] = append(byOwner[h.Owner], h)
	}
	out := make([]HeldLock, 0, len(set))
	for _, spans := range byOwner {
		sortLocks(spans)
		merged := spans[:0]
		for _, h := range spans {
			if n := len(merged); n > 0 {
				prev := &merged[n-1]
				if prev.Write == h.Write && prev.End != LockRangeEOF && prev.End+1 == h.Start {
					prev.End = h.End
					continue
				}
			}
			merged = append(merged, h)
		}
		out = append(out, merged...)
	}
	sortLocks(out)
	return out
}

// isNormalizedLocks reports whether set already satisfies every normalization
// invariant (canonical order, per-owner non-overlap, maximal merging). Used
// when validating projection entries streamed from a control root.
func isNormalizedLocks(set []HeldLock) bool {
	ownerSpans := map[LockOwner][]HeldLock{}
	for i, h := range set {
		if h.Start > h.End {
			return false
		}
		if i > 0 && !heldLess(set[i-1], h) {
			return false
		}
		ownerSpans[h.Owner] = append(ownerSpans[h.Owner], h)
	}
	for _, spans := range ownerSpans {
		sortLocks(spans)
		for i := 1; i < len(spans); i++ {
			prev, cur := spans[i-1], spans[i]
			if rangesOverlap(prev.Start, prev.End, cur.Start, cur.End) {
				return false
			}
			if prev.Write == cur.Write && prev.End != LockRangeEOF && prev.End+1 == cur.Start {
				return false // unmerged adjacency is non-canonical
			}
		}
	}
	return true
}

// lockConflict returns a lock that blocks owner acquiring [start,end] with the
// given exclusivity: different owner, overlapping range, at least one side
// exclusive. Deterministic: the first conflict in canonical order.
func lockConflict(set []HeldLock, owner LockOwner, start, end uint64, write bool) (HeldLock, bool) {
	for _, h := range set {
		if h.Owner == owner {
			continue
		}
		if !rangesOverlap(h.Start, h.End, start, end) {
			continue
		}
		if h.Write || write {
			return h, true
		}
	}
	return HeldLock{}, false
}

// removeOwnedRange drops owner's coverage of [start,end], splitting boundary
// intervals (POSIX partial unlock). Other owners' intervals pass through.
func removeOwnedRange(set []HeldLock, owner LockOwner, start, end uint64) []HeldLock {
	out := make([]HeldLock, 0, len(set)+2)
	for _, h := range set {
		if h.Owner != owner || !rangesOverlap(h.Start, h.End, start, end) {
			out = append(out, h)
			continue
		}
		if h.Start < start {
			out = append(out, HeldLock{Owner: owner, Start: h.Start, End: start - 1, Write: h.Write})
		}
		if h.End > end { // implies end < LockRangeEOF, so end+1 cannot overflow
			out = append(out, HeldLock{Owner: owner, Start: end + 1, End: h.End, Write: h.Write})
		}
	}
	return out
}

// setLockRange replaces owner's coverage of [start,end] with one interval of
// the requested type (POSIX setlk replace/upgrade/downgrade), then normalizes.
// The caller has already established that no other owner conflicts.
func setLockRange(set []HeldLock, owner LockOwner, start, end uint64, write bool) []HeldLock {
	out := removeOwnedRange(set, owner, start, end)
	out = append(out, HeldLock{Owner: owner, Start: start, End: end, Write: write})
	return normalizeLocks(out)
}

// unlockRange removes owner's coverage of [start,end], then normalizes.
func unlockRange(set []HeldLock, owner LockOwner, start, end uint64) []HeldLock {
	return normalizeLocks(removeOwnedRange(set, owner, start, end))
}
