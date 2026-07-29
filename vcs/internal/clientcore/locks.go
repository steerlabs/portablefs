package clientcore

import (
	"context"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// LockPollInterval paces a blocking advisory-lock acquisition (F_SETLKW). The
// frontend re-issues a NON-blocking acquire at this cadence rather than parking
// the request on the authority, so request cancellation is honored within one
// tick instead of waiting on a server-side block.
const LockPollInterval = 25 * time.Millisecond

// POSIX advisory-lock types as carried by FUSE and most frontend shims.
const (
	LockRead   = 0 // F_RDLCK
	LockWrite  = 1 // F_WRLCK
	LockUnlock = 2 // F_UNLCK
)

// LockAuthority is the fsproto lock surface used by clientcore. fsproto.Client
// implements it directly, but tests and future frontends can supply a narrower
// adapter.
type LockAuthority interface {
	Lock(path string, mode uint8, lkID, start, end uint64, write, unlock bool) (fsproto.LockResult, error)
}

// lockRouter routes lock mutations through the journaled exact-identity lock
// op; getlk is a pure read. handleIno 0 keeps locks path-keyed at decision
// time.
type lockRouter struct{ cli *fsproto.Client }

func (r lockRouter) Lock(path string, mode uint8, lkID, start, end uint64, write, unlock bool) (fsproto.LockResult, error) {
	if mode != fsproto.LkGetlk {
		return r.cli.LockManaged(path, 0, mode, lkID, start, end, write, unlock)
	}
	return r.cli.Lock(path, mode, lkID, start, end, write, unlock)
}

// HeldLock records one advisory lock that was acquired through a frontend's
// open-file-description. The authority is path-keyed and does not rekey locks on
// rename, so cleanup must release at Path, the acquire-time name. Write is kept
// so a post-failover reclaim can re-assert the exact lock type.
type HeldLock struct {
	Owner      uint64
	Start, End uint64
	Path       string
	Write      bool
}

// LockHandle tracks advisory locks taken through one open-file-description.
// Frontends need this because close/release notifications often omit the kernel
// lock owner; the handle record reconstructs owner-scoped unlocks at cleanup.
type LockHandle struct {
	mu   sync.Mutex
	held []HeldLock
}

// Add remembers an acquired lock so it can be released later at its acquire
// path (and re-asserted with the right type during reclaim).
func (h *LockHandle) Add(owner, start, end uint64, path string, write bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.held = append(h.held, HeldLock{Owner: owner, Start: start, End: end, Path: path, Write: write})
}

// Snapshot returns a copy of the currently held locks (for reclaim).
func (h *LockHandle) Snapshot() []HeldLock {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]HeldLock(nil), h.held...)
}

// Remove applies an explicit unlock to the local handle record. It is owner- and
// overlap-scoped and mirrors the authority's range split.
func (h *LockHandle) Remove(owner, start, end uint64) {
	h.UnlockPaths(owner, start, end)
}

// UnlockPaths applies an explicit unlock to the handle record and returns the
// distinct acquire-time paths that must receive the forwarded unlock.
func (h *LockHandle) UnlockPaths(owner, start, end uint64) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := map[string]bool{}
	var paths []string
	var kept []HeldLock
	for _, l := range h.held {
		if l.Owner != owner || l.End < start || end < l.Start {
			kept = append(kept, l)
			continue
		}
		if !seen[l.Path] {
			seen[l.Path] = true
			paths = append(paths, l.Path)
		}
		if l.Start < start {
			kept = append(kept, HeldLock{Owner: l.Owner, Start: l.Start, End: start - 1, Path: l.Path})
		}
		if l.End > end {
			kept = append(kept, HeldLock{Owner: l.Owner, Start: end + 1, End: l.End, Path: l.Path})
		}
	}
	h.held = kept
	return paths
}

// Drain returns and clears every held lock. Release paths call this once; a
// second close notification becomes a no-op.
func (h *LockHandle) Drain() []HeldLock {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.held
	h.held = nil
	return out
}

// Unlock forwards an explicit unlock to every path where the matching lock was
// acquired. If the handle has no matching record, it falls back to the live path;
// the release is owner-scoped at the authority, so a stray unlock is safe.
func Unlock(auth LockAuthority, h *LockHandle, owner, start, end uint64, live string) error {
	if h == nil {
		_, err := auth.Lock(live, fsproto.LkSetlk, owner, start, end, false, true)
		return err
	}
	paths := h.UnlockPaths(owner, start, end)
	if len(paths) == 0 {
		_, err := auth.Lock(live, fsproto.LkSetlk, owner, start, end, false, true)
		return err
	}
	var first error
	for _, p := range paths {
		if _, err := auth.Lock(p, fsproto.LkSetlk, owner, start, end, false, true); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// SetLock attempts a non-blocking acquire and records successful acquisitions on
// the handle. Unlock requests are routed through Unlock so rename-before-unlock
// releases the authority lock at its acquire path.
func SetLock(auth LockAuthority, h *LockHandle, path string, owner, start, end uint64, write, unlock bool) (fsproto.LockResult, error) {
	if unlock {
		return fsproto.LockResult{Status: fsproto.OK}, Unlock(auth, h, owner, start, end, path)
	}
	res, err := auth.Lock(path, fsproto.LkSetlk, owner, start, end, write, false)
	if err != nil {
		return res, err
	}
	if res.Status == fsproto.OK && h != nil {
		h.Add(owner, start, end, path, write)
	}
	return res, nil
}

// WaitSetLock owns a blocking lock wait by polling non-blocking authority
// acquires. On cancellation after a grant, it releases the just-acquired range so
// a caller that already gave up never leaves an orphaned lock.
func WaitSetLock(ctx context.Context, auth LockAuthority, h *LockHandle, path string, owner, start, end uint64, write bool) (fsproto.LockResult, error) {
	for {
		res, err := auth.Lock(path, fsproto.LkSetlk, owner, start, end, write, false)
		if err != nil {
			return res, err
		}
		if res.Status == fsproto.OK {
			select {
			case <-ctx.Done():
				_, _ = auth.Lock(path, fsproto.LkSetlk, owner, start, end, false, true)
				return res, ctx.Err()
			default:
			}
			if h != nil {
				h.Add(owner, start, end, path, write)
			}
			return res, nil
		}
		if res.Status != fsproto.EAGAIN {
			return res, nil
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(LockPollInterval):
		}
	}
}

// ReleaseHandleLocks releases every advisory lock remembered on h.
func ReleaseHandleLocks(auth LockAuthority, h *LockHandle) {
	if h == nil {
		return
	}
	for _, l := range h.Drain() {
		_, _ = auth.Lock(l.Path, fsproto.LkSetlk, l.Owner, l.Start, l.End, false, true)
	}
}
