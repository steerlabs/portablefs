package main

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// POSIX advisory-lock types (the FUSE l_type protocol values — 0/1/2 — which are GOOS-independent,
// unlike syscall.F_*).
const (
	lockRead   = clientcore.LockRead
	lockWrite  = clientcore.LockWrite
	lockUnlock = clientcore.LockUnlock
)

// lockHandle is the FileHandle for an open file. It records the advisory locks taken through THIS
// open-file-description so they can be released when the description is closed. We must reconstruct
// release-on-close ourselves: go-fuse drops the kernel lock_owner (and the FLOCK_UNLOCK flag) on
// FLUSH/RELEASE, so a held lock would otherwise leak at the authority until the mount disconnects.
// flock locks are per-open-file-description, so per-handle tracking is the exact model; for fcntl it
// matches "closing the fd drops the lock". An open that never locks carries an empty handle (cheap).
type lockHandle struct {
	// openPath is the file's path at Open time. Release decrements the open-count and releases this
	// description's advisory locks against THIS path (not the live tree-path) so a rename between
	// open and close stays symmetric with the path-addressed authority — which does not rekey
	// opens/locks on rename. Decrementing the live (post-rename) path would leave the open-time
	// path's count pinned forever (blocking idle-release/handoff of its subtree) and leak the lock
	// under the old name until the mount disconnects.
	openPath string
	// append is immutable open-file-description state. The kernel-provided
	// write offset is only advisory for O_APPEND; the authority resolves EOF
	// in its serialized mutation order.
	append bool
	core   clientcore.LockHandle
}

type heldLock struct {
	owner      uint64 // the kernel lock owner that took it (sent to the authority as LkID)
	start, end uint64
	path       string // path the lock was ACQUIRED at; release targets this (the authority holds it here and does not rekey on rename)
}

func (h *lockHandle) add(owner, start, end uint64, path string) {
	// The per-handle record exists for release-on-close; the lock TYPE only
	// matters for reclaim re-assertion, which conservatively re-asserts write.
	h.core.Add(owner, start, end, path, true)
}

// remove drops owner's locks overlapping [start,end] from the record (discarding where they were
// held). Kept for the unit tests; unlockPaths is the release-aware variant used by the unlock path.
func (h *lockHandle) remove(owner, start, end uint64) {
	h.core.Remove(owner, start, end)
}

// unlockPaths applies an explicit F_UNLCK [start,end] to the per-handle record and returns the
// DISTINCT paths the release must be forwarded to. Each lock is held at the path it was ACQUIRED at
// (the authority is path-keyed and does not rekey on rename), so the caller releases [start,end]
// there — correct even if the file was renamed between acquire and unlock. Matching is by OVERLAP,
// not containment, and it mirrors the authority's own partial-unlock split (keep the prefix/suffix
// outside [start,end]) so the record stays accurate and a later close re-releases only what remains.
// This is the fix for the partial-unlock-after-rename leak: a partial F_UNLCK of a larger held range
// is forwarded to the acquire path instead of falling back to the live (renamed) name.
func (h *lockHandle) unlockPaths(owner, start, end uint64) []string {
	return h.core.UnlockPaths(owner, start, end)
}

// drain returns and clears every held lock; the close path releases them at the authority. Clearing
// makes the second close notification (FLUSH then RELEASE both fire) a no-op rather than a re-unlock.
func (h *lockHandle) drain() []heldLock {
	core := h.core.Drain()
	out := make([]heldLock, 0, len(core))
	for _, l := range core {
		out = append(out, heldLock{owner: l.Owner, start: l.Start, end: l.End, path: l.Path})
	}
	return out
}

// recordLock remembers a lock acquired through this open file so it can be released on close. It is
// only ever called for ACQUIRES — Setlk/Setlkw route an F_UNLCK through n.unlock before reaching here
// — and is a no-op when fh is not a *lockHandle (a lock on a handle we did not mint).
func recordLock(fh fs.FileHandle, owner uint64, lk *fuse.FileLock, path string) {
	h, ok := fh.(*lockHandle)
	if !ok {
		return
	}
	h.core.Add(owner, lk.Start, lk.End, path, lk.Typ == lockWrite)
}

// unlock handles an explicit F_UNLCK. It forwards the release of [start,end] to the path each
// overlapping held lock was ACQUIRED at, not the live tree-path: the authority is path-keyed and does
// not rekey locks on rename, so a rename between acquire and unlock must not redirect the release to
// the new name (which would no-op there and strand the lock under the old name until the mount
// disconnects). The authority splits a partially-unlocked range itself, so forwarding the whole
// [start,end] to each acquire path is correct. A range with no overlapping per-handle record (a handle
// we did not mint, or a lock the kernel tracked but we did not) falls back to the live path —
// best-effort, matching the pre-identity behavior, and safe because a stray release is owner-scoped.
func (n *node) unlock(fh fs.FileHandle, owner, start, end uint64, live string) {
	h, ok := fh.(*lockHandle)
	if !ok {
		_, _ = n.core().Setlk(context.Background(), nil, live, owner, start, end, false, true)
		return
	}
	_, _ = n.core().Setlk(context.Background(), &h.core, live, owner, start, end, false, true)
}

// Getlk/Setlk/Setlkw forward POSIX advisory locks (flock/fcntl) to the single VCS authority, so
// they are coordinated ACROSS machines — a per-client kernel lock table cannot see other mounts'
// locks. The lock owner is (this mount, the kernel's per-open owner id); the authority frees a
// mount's locks if its liveness stream drops (crash cleanup), and the mount frees a handle's locks
// when it is closed (clean cleanup).

// Getlk reports a lock that would conflict with lk (F_GETLK).
func (n *node) Getlk(ctx context.Context, fh fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	res, err := n.core().Getlk(n.curPath(), owner, lk.Start, lk.End, lk.Typ == lockWrite)
	if err != nil {
		return syscall.EIO
	}
	if !res.Conflict {
		out.Typ = lockUnlock // no conflicting lock
		return 0
	}
	out.Typ = lockRead
	if res.CWrite {
		out.Typ = lockWrite
	}
	out.Start, out.End = res.CStart, res.CEnd
	out.Pid = 0 // the holder is on another machine; a local pid is not meaningful
	return 0
}

// Setlk acquires/releases a lock without blocking (F_SETLK): EAGAIN on contention.
func (n *node) Setlk(ctx context.Context, fh fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	p := n.curPath()
	var h *clientcore.LockHandle
	if lh, ok := fh.(*lockHandle); ok {
		h = &lh.core
	}
	if lk.Typ == lockUnlock {
		// An unlock RPC failure must NOT surface to the app (P2): a stray/failed release is reclaimed
		// by the authority's ReleaseOwner when the mount disconnects, and returning EIO from F_UNLCK is
		// a behavior regression (apps expect unlock to always succeed). Log and report success.
		if _, err := n.core().Setlk(ctx, h, p, owner, lk.Start, lk.End, false, true); err != nil {
			dbg("Setlk unlock %q: %v", p, err)
		}
		return 0
	}
	res, err := n.core().Setlk(ctx, h, p, owner, lk.Start, lk.End, lk.Typ == lockWrite, false)
	if err != nil {
		dbg("Setlk %q: %v", p, err)
		return syscall.EIO
	}
	if res.Status == fsproto.EAGAIN {
		return syscall.EAGAIN
	}
	if res.Status != fsproto.OK {
		return errno(res.Status)
	}
	return 0
}

// Setlkw acquires a lock, blocking until grantable (F_SETLKW). The mount owns the wait: it polls a
// non-blocking acquire on lockPollInterval and re-checks the FUSE op's context each tick, so a
// cancelled wait (flock/fcntl `-w` timeout, or a killed waiter) returns EINTR promptly instead of
// blocking on the authority until the lock happens to free. On a grant that races the cancellation,
// it releases the just-acquired lock so a caller that already gave up never leaves one orphaned.
func (n *node) Setlkw(ctx context.Context, fh fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	p := n.curPath() // capture once: a rename mid-wait must not split acquire/release across two authority keys
	var h *clientcore.LockHandle
	if lh, ok := fh.(*lockHandle); ok {
		h = &lh.core
	}
	if lk.Typ == lockUnlock {
		// Same as Setlk (P2): an unlock RPC failure is logged and reported as success, never EIO.
		if _, err := n.core().Setlk(ctx, h, p, owner, lk.Start, lk.End, false, true); err != nil {
			dbg("Setlkw unlock %q: %v", p, err)
		}
		return 0
	}
	res, err := n.core().Setlkw(ctx, h, p, owner, lk.Start, lk.End, lk.Typ == lockWrite)
	if err != nil {
		if ctx.Err() != nil {
			return syscall.EINTR
		}
		return syscall.EIO
	}
	if res.Status != fsproto.OK {
		return errno(res.Status)
	}
	return 0
}

// releaseHandleLocks releases every advisory lock taken through fh — called from Release, when the
// open-file-description is fully closed (FUSE RELEASE / refcount 0). It reconstructs the unlock
// go-fuse cannot forward (it drops the kernel lock_owner). We release HERE, not on FLUSH: FLUSH
// fires on every fd close including a forked child's inherited fd, which would drop an flock lock
// while a peer fd still holds the description. A failed unlock is reclaimed by the authority's
// ReleaseOwner when the mount disconnects.
func (n *node) releaseHandleLocks(fh fs.FileHandle) {
	h, ok := fh.(*lockHandle)
	if !ok {
		return
	}
	clientcore.ReleaseHandleLocks(n.core().LockAuth(), &h.core)
}

// Release frees a closed open-file-description's advisory locks (flock release arrives here, via
// RELEASE+FLOCK_UNLOCK, with the owner stripped — we recover it from the handle record) and drops
// the open-handle count so the file's subtree becomes idle-releasable once nothing holds it open.
func (n *node) Release(ctx context.Context, fh fs.FileHandle) syscall.Errno {
	n.releaseHandleLocks(fh)
	if h, ok := fh.(*lockHandle); ok {
		n.core().CloseHandle(h.openPath, n.coreState()) // symmetric with Open's inc(openPath): a rename-before-close must not leak the pin
	} else {
		n.core().CloseHandle(n.curPath(), n.coreState())
	}
	return 0
}
