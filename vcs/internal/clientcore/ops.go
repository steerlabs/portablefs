package clientcore

import (
	"context"
	"errors"
	"os"
	"sort"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/modebits"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

const statusExactRetry Status = -4096

func statusErr(err error) Status {
	switch {
	case err == nil:
		return fsproto.OK
	case errors.Is(err, writeback.ErrDelegatedBindingMismatch):
		return statusExactRetry
	case errors.Is(err, os.ErrNotExist):
		return fsproto.ENOENT
	case errors.Is(err, os.ErrExist):
		return fsproto.EEXIST
	case errors.Is(err, syscall.ENOTEMPTY):
		return fsproto.ENOTEMPTY
	case errors.Is(err, writeback.ErrNoXattr):
		return fsproto.ENODATA
	case errors.Is(err, writeback.ErrNoSpace):
		return fsproto.ENOSPC
	default:
		return fsproto.EIO
	}
}

func (v *Volume) debug(format string, a ...any) {
	if v.debugf != nil {
		v.debugf(format, a...)
	}
}

func (v *Volume) cachedGetattr(ctx context.Context, view *readView, path string) (fsproto.Attr, Status) {
	if gen, curVer, pathValid := v.VersionCache.CacheState(path); gen != 0 && pathValid {
		dir, _ := splitPath(path)
		_, parentCurVer, parentValid := v.VersionCache.CacheState(dir)
		// Positive entries are served only when their path version is at least
		// the current version. Negative entries are served only when their
		// parent-directory version is at least the current parent version. The
		// server samples the parent version BEFORE its Lstat (C1) and stamps
		// ENOENT with parentVersion+1, so the negative is ordered no later than
		// the miss; a create that wins after the miss carries a strictly greater
		// parent version, whose invalidation raises parentCurVer and makes this
		// comparison reject the stale negative. If the invalidation is delayed,
		// the miss is concurrent with the create and returning ENOENT is a valid
		// ordering for that syscall; once the bumped version is observed the
		// negative can never shadow the created name.
		if parentValid {
			if e, ok := v.AttrCache.GetLookup(gen, curVer, parentCurVer, path); ok {
				if !e.Exists {
					return fsproto.Attr{}, fsproto.ENOENT
				}
				v.observeHardlink(path, e.Attr)
				return e.Attr, fsproto.OK
			}
		}
	}
	observation := v.hardlinks.beginObservation()
	defer observation.Close()
	covered := v.wb != nil && view.Covers(path)
	var resume func()
	if !covered {
		resume = v.suspendAuthorityPublication(ctx)
	}
	a, rver, rgen, parentVersion, st, err := v.client.GetattrVContext(ctx, path)
	if resume != nil {
		resume()
	}
	if err != nil {
		v.debug("CachedGetattr GetattrV %q: %v", path, err)
		return fsproto.Attr{}, fsproto.EIO
	}
	token, cacheOK := v.VersionCache.AcceptGeneration(view.cacheToken, rgen)
	if cacheOK {
		view.cacheToken = token
	}
	if cacheOK && st == fsproto.OK {
		v.VersionCache.PublishOKToken(token, rgen, path, rver, func() {
			v.AttrCache.PutAttr(rgen, rver, path, a)
		})
	}
	if v.negativeCache && cacheOK && st == fsproto.ENOENT && parentVersion != 0 {
		dir, _ := splitPath(path)
		pver := parentVersion - 1
		v.VersionCache.PublishOKToken(token, rgen, dir, pver, func() {
			v.AttrCache.PutNegative(rgen, pver, path)
		})
	}
	if st == fsproto.OK {
		observation.Observe(path, a)
	}
	return a, st
}

func (v *Volume) observeHardlink(path string, a fsproto.Attr) {
	v.hardlinks.observe(path, a)
}

// provenAbsent reports whether the version-gated negative cache currently
// proves path does not exist — the same ordering proof CachedGetattr serves
// ENOENT from. The create path uses it to skip the adopt-or-create probe.
func (v *Volume) provenAbsent(path string) bool {
	gen, curVer, pathValid := v.VersionCache.CacheState(path)
	if gen == 0 || !pathValid {
		return false
	}
	dir, _ := splitPath(path)
	_, parentCurVer, parentValid := v.VersionCache.CacheState(dir)
	if !parentValid {
		return false
	}
	e, ok := v.AttrCache.GetLookup(gen, curVer, parentCurVer, path)
	return ok && !e.Exists
}

// RememberHardlinkAlias restores an already-proven alias binding from a
// frontend's durable item table. It is used when portablefsd restarts under a
// still-mounted FSKit volume, before the kernel necessarily issues a fresh
// getattr, so writes cannot accidentally enter the delegated write-back lane.
func (v *Volume) RememberHardlinkAlias(path string, ino uint64) {
	v.observeHardlink(path, fsproto.Attr{Ino: ino, Nlink: 2})
}

func (v *Volume) isHardlink(n *NodeState) bool {
	return n != nil && v.hardlinks.contains(n.AuthorityIno())
}

// engineAttr converts an engine entry to the served attr. A locally-born
// entry keeps Ino == 0 (no authority identity yet): frontends substitute
// their own stable path-derived inode, and handle-addressed RPCs must NOT
// treat it as an authority ino.
func engineAttr(path string, e writeback.Entry) fsproto.Attr {
	_ = path
	return attrFromEntry(e)
}

func (v *Volume) Lookup(ctx context.Context, path string) (fsproto.Attr, Status) {
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer permit.Close()
	return v.lookup(ctx, &permit, path)
}

func (v *Volume) lookup(ctx context.Context, permit *readView, path string) (fsproto.Attr, Status) {
	if v.wb != nil {
		if ent, res := permit.Lookup(path); res == writeback.LookupHit {
			a := engineAttr(path, ent)
			v.observeHardlink(path, a)
			return a, fsproto.OK
		} else if res == writeback.LookupNegative {
			return fsproto.Attr{}, fsproto.ENOENT
		}
		if dir, _ := splitPath(path); permit.Covers(dir) {
			// The engine covers the parent but cannot decide the name yet.
			// Seed the complete listing (ONE readdir instead of one getattr
			// per name) so this and every later lookup under the directory —
			// including proven ENOENT for names about to be created — is
			// answered locally for the life of the delegation.
			if _, st := v.readdir(ctx, permit, dir); st == fsproto.OK {
				if ent, res := permit.Lookup(path); res == writeback.LookupHit {
					a := engineAttr(path, ent)
					v.observeHardlink(path, a)
					return a, fsproto.OK
				} else if res == writeback.LookupNegative {
					return fsproto.Attr{}, fsproto.ENOENT
				}
			}
		}
	}
	return v.cachedGetattr(ctx, permit, path)
}

func (v *Volume) Getattr(ctx context.Context, path string, n *NodeState) (fsproto.Attr, Status) {
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer permit.Close()
	return v.getattr(ctx, &permit, path, n)
}

// GetattrExactHandle stats the object retained by an open descriptor without
// consulting path caches or write-back views. The empty path is deliberate:
// after unlink or rename-over the former name is not namespace evidence and
// may already identify a replacement.
func (v *Volume) GetattrExactHandle(ctx context.Context, n *NodeState) (fsproto.Attr, Status) {
	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer end()
	ino := authHandleIno(n)
	if n == nil || !n.IsOpen() || ino == 0 {
		return fsproto.Attr{}, fsproto.ENOENT
	}
	var a *fsproto.Attr
	var st int32
	if oi := n.Orphan(); oi != 0 {
		a, st, err = v.client.GetattrOrphanContext(authorityCtx, oi)
	} else {
		a, st, err = v.client.GetattrHandleContext(authorityCtx, "", ino)
	}
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	return *a, fsproto.OK
}

// GetattrOpenHandle reports an open descriptor's exact object identity while
// using a genuine current alias only as write-back scope. Under a retained
// delegation that alias's overlay is authoritative; on the shared lane the
// authority inode is addressed explicitly and pathname caches are bypassed.
func (v *Volume) GetattrOpenHandle(ctx context.Context, path string, n *NodeState) (fsproto.Attr, Status) {
	path = cleanVolumePath(path)
	if path == "" {
		return v.GetattrExactHandle(ctx, n)
	}
	if n == nil || !n.IsOpen() {
		return fsproto.Attr{}, fsproto.ENOENT
	}
	ino := authHandleIno(n)
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer permit.Close()
	if v.wb != nil && permit.Covers(path) {
		if ent, result := permit.Lookup(path); result == writeback.LookupHit {
			if ent.Ino != 0 && ent.Ino != ino {
				permit.Close()
				return v.GetattrExactHandle(ctx, n)
			}
			a := engineAttr(path, ent)
			v.observeHardlink(path, a)
			return a, fsproto.OK
		}
		permit.Close()
		return v.GetattrExactHandle(ctx, n)
	}
	if ino == 0 {
		return fsproto.Attr{}, fsproto.ENOENT
	}
	resume := v.suspendAuthorityPublication(ctx)
	a, st, err := v.client.GetattrHandleContext(ctx, path, ino)
	resume()
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	return *a, fsproto.OK
}

func (v *Volume) getattr(ctx context.Context, permit *readView, path string, n *NodeState) (fsproto.Attr, Status) {
	if oi := n.Orphan(); oi != 0 {
		a, st, err := v.client.GetattrOrphanContext(v.authorityWaitContext(ctx), oi)
		if err != nil {
			return fsproto.Attr{}, fsproto.EIO
		}
		if st != fsproto.OK {
			return fsproto.Attr{}, st
		}
		return *a, fsproto.OK
	}
	if v.wb != nil {
		if ent, res := permit.Lookup(path); res == writeback.LookupHit {
			a := engineAttr(path, ent)
			v.observeHardlink(path, a)
			return a, fsproto.OK
		} else if res == writeback.LookupNegative {
			return fsproto.Attr{}, fsproto.ENOENT
		}
	}
	a, st := v.cachedGetattr(ctx, permit, path)
	if st == fsproto.ENOENT {
		if oi := v.RedirectToOrphan(ctx, n); oi != 0 {
			if oa, ost, oerr := v.client.GetattrOrphanContext(v.authorityWaitContext(ctx), oi); oerr == nil && ost == fsproto.OK {
				return *oa, fsproto.OK
			}
		}
	}
	return a, st
}

func (v *Volume) Readdir(ctx context.Context, dir string) ([]DirEntry, Status) {
	permit, err := v.beginRead(ctx, dir)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer permit.Close()
	return v.readdir(ctx, &permit, dir)
}

func (v *Volume) readdir(ctx context.Context, permit *readView, dir string) ([]DirEntry, Status) {
	covered := v.wb != nil && permit.Covers(dir)
	if covered {
		// A held dir with a complete children set serves locally: the
		// delegation excludes peer mutations, and the engine's own
		// mutations are folded into the set. Zero RPCs.
		if ents, ok := permit.Readdir(dir); ok {
			out := engineEntriesToDir(dir, ents)
			v.observeDirectoryHardlinks(dir, out)
			return out, fsproto.OK
		}
		if ent, res := permit.Lookup(dir); res == writeback.LookupHit && ent.Kind != "directory" {
			return nil, fsproto.ENOTDIR
		} else if res == writeback.LookupNegative {
			return nil, fsproto.ENOENT
		}
	}
	if gen, curVer, valid := v.VersionCache.CacheState(dir); gen != 0 && valid && !covered {
		fenceSeq := v.VersionCache.FenceClock()
		v.dirMu.Lock()
		if e, ok := v.dirCache[dir]; ok &&
			e.gen == gen &&
			e.version >= curVer &&
			e.fenceSeq == fenceSeq {
			out := append([]DirEntry(nil), e.entries...)
			v.dirMu.Unlock()
			return out, fsproto.OK
		}
		v.dirMu.Unlock()
	}
	observation := v.hardlinks.beginObservation()
	defer observation.Close()
	var resume func()
	if !covered {
		resume = v.suspendAuthorityPublication(ctx)
	}
	ents, gen, dirVersion, st, err := v.client.ReaddirVContext(ctx, dir)
	if resume != nil {
		resume()
	}
	if err != nil {
		return nil, fsproto.EIO
	}
	if st != fsproto.OK {
		return nil, st
	}
	token, cacheOK := v.VersionCache.AcceptGeneration(permit.cacheToken, gen)
	if cacheOK {
		permit.cacheToken = token
	}
	fillCache := !v.noReaddirPlus && cacheOK && !covered
	out := make([]DirEntry, 0, len(ents))
	for _, e := range ents {
		cp := e.Name
		if dir != "" {
			cp = dir + "/" + e.Name
		}
		ino := e.Attr.Ino
		if ino == 0 {
			ino = InoOf(cp)
		}
		out = append(out, DirEntry{Name: e.Name, Attr: e.Attr, Ino: ino})
		observation.Observe(cp, e.Attr)
		if fillCache && e.Version != 0 {
			ver := e.Version - 1
			v.VersionCache.PublishOKToken(token, gen, cp, ver, func() {
				v.AttrCache.PutAttr(gen, ver, cp, e.Attr)
			})
		}
	}
	if covered {
		// Seed the engine's complete children set from this authority
		// readdir and answer from the merged (overlay-over-base) view; later
		// lookups and listings under dir are then local.
		merged := permit.MergeReaddir(dir, dirEntriesToEngine(out))
		out = engineEntriesToDir(dir, merged)
		v.observeDirectoryHardlinks(dir, out)
		return out, fsproto.OK
	}
	// A non-delegated directory has no unflushed local children (every
	// create directly under it was write-through), so the authority listing
	// is authoritative — keep it as-is, preserving the readdir-plus versions
	// that fill the attr cache. Store it only when not delegated: a held
	// dir's version never advances for our own writes, so a cache entry
	// would go stale invisibly.
	if cacheOK {
		cached := append([]DirEntry(nil), out...)
		v.VersionCache.PublishDirectoryOKToken(token, gen, dirVersion, dir, func() {
			v.dirMu.Lock()
			v.dirCache[dir] = dirCacheEntry{
				gen: gen, version: dirVersion, fenceSeq: token.fenceSeq, entries: cached,
			}
			if len(v.dirCache) > maxDirCacheEntries {
				for cachedDir := range v.dirCache {
					if cachedDir == dir {
						continue
					}
					delete(v.dirCache, cachedDir)
					break
				}
			}
			v.dirMu.Unlock()
		})
	}
	return out, fsproto.OK
}

func dirEntriesToEngine(ents []DirEntry) []writeback.Entry {
	out := make([]writeback.Entry, 0, len(ents))
	for _, e := range ents {
		out = append(out, entryFromAttr(e.Name, e.Attr))
	}
	return out
}

func engineEntriesToDir(dir string, ents []writeback.Entry) []DirEntry {
	out := make([]DirEntry, 0, len(ents))
	for _, e := range ents {
		cp := e.Name
		if dir != "" {
			cp = dir + "/" + e.Name
		}
		attr := attrFromEntry(e)
		// DirEntry.Ino is the frontend's inode number (path-derived fallback
		// for locally-born entries); Attr.Ino stays the authority identity.
		ino := attr.Ino
		if ino == 0 {
			ino = InoOf(cp)
		}
		out = append(out, DirEntry{Name: e.Name, Attr: attr, Ino: ino})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (v *Volume) observeDirectoryHardlinks(dir string, entries []DirEntry) {
	for _, entry := range entries {
		path := entry.Name
		if dir != "" {
			path = dir + "/" + entry.Name
		}
		v.observeHardlink(path, entry.Attr)
	}
}

func (v *Volume) clearDirCache() {
	v.dirMu.Lock()
	v.dirCache = map[string]dirCacheEntry{}
	v.dirMu.Unlock()
}

func (v *Volume) evictDirCache(dir string) {
	v.dirMu.Lock()
	delete(v.dirCache, dir)
	v.dirMu.Unlock()
}

// evictDirCachePrefix drops the listing for rp and every directory under it. Used on delegation
// grant/release so a listing cached while a subtree was (or was about to become) exclusively held
// cannot survive the ownership change and serve a stale enumeration.
func (v *Volume) evictDirCachePrefix(rp string) {
	v.dirMu.Lock()
	defer v.dirMu.Unlock()
	if rp == "" {
		v.dirCache = map[string]dirCacheEntry{}
		return
	}
	parent, _ := splitPath(rp)
	delete(v.dirCache, parent)
	pfx := rp + "/"
	for k := range v.dirCache {
		if k == rp || len(k) > len(pfx) && k[:len(pfx)] == pfx {
			delete(v.dirCache, k)
		}
	}
}

func (v *Volume) Open(ctx context.Context, path string, n *NodeState, writeIntent bool) Status {
	if err := v.beginMutation(ctx); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	released, err := v.opens.Inc(ctx, path, n)
	if err != nil {
		return fsproto.EIO
	}
	if released && (n == nil || n.AuthorityIno() == 0) {
		if st := v.resolveOpenAfterHandoff(ctx, path, n); st != fsproto.OK {
			v.rollbackTrackedOpen(path, n)
			return st
		}
		v.opens.FinishInc(path, n, true, n != nil)
		return fsproto.OK
	}
	st, registered := v.incOpen(path, n)
	if st != fsproto.OK {
		v.rollbackTrackedOpen(path, n)
		return st
	}
	v.opens.FinishInc(path, n, true, registered)
	return fsproto.OK
}

func (v *Volume) RegisterOpened(ctx context.Context, path string, n *NodeState) Status {
	if err := v.beginMutation(ctx); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	released, err := v.opens.Inc(ctx, path, n)
	if err != nil {
		return fsproto.EIO
	}
	if released && (n == nil || n.AuthorityIno() == 0) {
		if st := v.resolveOpenAfterHandoff(ctx, path, n); st != fsproto.OK {
			v.rollbackTrackedOpen(path, n)
			return st
		}
		v.opens.FinishInc(path, n, true, n != nil)
		return fsproto.OK
	}
	st, registered := v.incOpen(path, n)
	if st != fsproto.OK {
		v.rollbackTrackedOpen(path, n)
		return st
	}
	v.opens.FinishInc(path, n, true, registered)
	return fsproto.OK
}

// resolveOpenAfterHandoff closes the barrier wake-up race: this owner was
// blocked before it could join the delegated snapshot, but the authority has
// now accepted the release. Resolve and pin the shared-mode inode before the
// open becomes visible to the caller.
func (v *Volume) resolveOpenAfterHandoff(ctx context.Context, path string, n *NodeState) Status {
	resume := v.suspendAuthorityPublication(ctx)
	a, _, _, _, st, err := v.client.GetattrVContext(ctx, path)
	resume()
	if err != nil {
		return fsproto.EIO
	}
	if st != fsproto.OK {
		return st
	}
	if a.Ino == 0 {
		return fsproto.EIO
	}
	if st := v.openReg.Open(path, a.Ino); st != fsproto.OK {
		return st
	}
	if n == nil {
		installed, ok := v.opens.InstallOrJoinAnonymousPin(path, a.Ino)
		if !ok {
			v.openReg.Close(path, a.Ino, true)
			return fsproto.EIO
		}
		if !installed {
			// One boolean authority pin covers every anonymous handle owned by
			// this path. Drop the per-open ref acquired above; the tracker will
			// retire its shared ref atomically with the final close.
			v.openReg.Close(path, a.Ino, false)
		}
		return fsproto.OK
	}
	if !n.RecordAuthorityIno(a.Ino) {
		v.openReg.Close(path, a.Ino, true)
		return fsproto.EIO
	}
	n.mu.Lock()
	n.nopen++
	n.mu.Unlock()
	return fsproto.OK
}

// incOpen counts one open handle on n and registers the inode's open hold at
// the authority through the open registry (openreg.go): only the FIRST open
// of an unregistered inode round-trips; concurrent opens join that in-flight
// registration, and re-opens of a registered (live or retained) inode cost
// nothing. Any registration failure propagates to the caller: an open may
// return only after the authority has confirmed its inode hold.
func (v *Volume) incOpen(path string, n *NodeState) (Status, bool) {
	if n == nil {
		return fsproto.OK, false
	}
	n.mu.Lock()
	n.nopen++
	n.mu.Unlock()
	if ino := n.AuthorityIno(); ino != 0 {
		if st := v.openReg.Open(path, ino); st != fsproto.OK {
			n.mu.Lock()
			n.nopen--
			n.mu.Unlock()
			return st, false
		}
		return fsproto.OK, true
	}
	return fsproto.OK, false
}

func (v *Volume) rollbackTrackedOpen(path string, n *NodeState) {
	remaining, pin, pinned := v.opens.FinishInc(path, n, false, false)
	if remaining != 0 {
		return
	}
	// Delegation release may have observed the tracker reservation while
	// incOpen was waiting on registration. If the open ultimately fails,
	// return that release-time pin because no CloseHandle will follow.
	if pinned {
		v.openReg.Close(pin.path, pin.ino, n != nil && n.Orphan() != 0)
	}
}

func (v *Volume) CloseHandle(path string, n *NodeState) Status {
	if err := v.beginSharedOperation(); err != nil {
		return fsproto.EIO
	}
	defer v.endSharedOperation()

	v.openStateMu.Lock()
	if currentPath, found := v.opens.CurrentPath(path, n); found {
		path = currentPath
	}
	remaining, currentPath, found, closeRegistered, pin, pinned := v.opens.Dec(path, n)
	if found {
		// Re-read under the decrement lock in case a concurrent rename won
		// after the pre-barrier lookup.
		path = currentPath
	}
	orphaned := v.closeOne(path, n, closeRegistered)
	if remaining == 0 {
		// Last local handle owned by this NodeState: retire any
		// delegation-release pin
		// through the standard registry flows (retained when the file still
		// exists; unmarked when it was orphaned, so the reap proceeds).
		if pinned {
			v.openReg.Close(pin.path, pin.ino, orphaned)
		}
	}
	v.openStateMu.Unlock()
	return fsproto.OK
}

func (v *Volume) closeOne(path string, n *NodeState, closeRegistered bool) bool {
	if n == nil {
		return false
	}
	var orphanIno uint64
	var orphaned, hadOpen bool
	n.mu.Lock()
	if n.nopen > 0 {
		hadOpen = true
		n.nopen--
	}
	lastClose := hadOpen && n.nopen == 0
	orphaned = n.orphanIno != 0
	if lastClose && orphaned {
		orphanIno = n.orphanIno
		n.orphanIno = 0
	}
	if hadOpen && closeRegistered {
		if fino := n.AuthorityIno(); fino != 0 {
			// Publish the NodeState count and registry ref transition as one
			// per-inode critical section. ReleaseNameChange takes this same
			// node lock before deciding destroy-vs-orphan, so it can never
			// observe nopen==0 while the closing ref still looks live. Close
			// is local-only here; any unmark it queues runs asynchronously.
			v.openReg.Close(path, fino, orphaned)
		}
	}
	n.mu.Unlock()
	if orphanIno != 0 {
		v.openOrphans.Remove(orphanIno)
	}
	return orphaned
}

func (v *Volume) RedirectToOrphan(ctx context.Context, n *NodeState) uint64 {
	if n == nil || !n.IsOpen() {
		return 0
	}
	ino := authHandleIno(n)
	if ino == 0 {
		return 0
	}
	if _, st, err := v.client.GetattrOrphanContext(v.authorityWaitContext(ctx), ino); err != nil || st != fsproto.OK {
		return 0
	}
	n.MarkOrphan(ino, v.openOrphans)
	return ino
}

func (v *Volume) Read(ctx context.Context, path string, n *NodeState, off int64, length int) ([]byte, Status) {
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer permit.Close()
	return v.read(ctx, &permit, path, n, off, length)
}

// ReadExactHandle is the detached-descriptor read lane. It intentionally
// bypasses the former pathname's overlay and caches, which could now belong to
// a replacement inode.
func (v *Volume) ReadExactHandle(ctx context.Context, n *NodeState, off int64, length int) ([]byte, Status) {
	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer end()
	ino := authHandleIno(n)
	if n == nil || !n.IsOpen() || ino == 0 {
		return nil, fsproto.ENOENT
	}
	var data []byte
	var st int32
	if oi := n.Orphan(); oi != 0 {
		data, st, err = v.client.ReadOrphanContext(authorityCtx, oi, off, int64(length))
	} else {
		data, _, _, st, err = v.client.ReadVHandleContext(authorityCtx, "", ino, off, int64(length))
	}
	if err != nil {
		return nil, fsproto.EIO
	}
	return data, st
}

// ReadOpenHandle composes a genuine alias's delegated view only when that
// view still binds the alias to the descriptor inode. A delayed peer
// rename-over may leave the frontend registry temporarily stale; an inode
// mismatch therefore switches to the pathless exact barrier instead of
// reading the replacement's overlay.
func (v *Volume) ReadOpenHandle(ctx context.Context, path string, n *NodeState, off int64, length int) ([]byte, Status) {
	path = cleanVolumePath(path)
	if path == "" {
		return v.ReadExactHandle(ctx, n, off, length)
	}
	if n == nil || !n.IsOpen() {
		return nil, fsproto.ENOENT
	}
	ino := authHandleIno(n)
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return nil, fsproto.EIO
	}
	defer permit.Close()
	if v.wb != nil && permit.Covers(path) {
		ent, result := permit.Lookup(path)
		if result != writeback.LookupHit || (ent.Ino != 0 && ent.Ino != ino) {
			permit.Close()
			return v.ReadExactHandle(ctx, n, off, length)
		}
		return v.read(ctx, &permit, path, n, off, length)
	}
	if ino == 0 {
		return nil, fsproto.ENOENT
	}
	resume := v.suspendAuthorityPublication(ctx)
	data, _, _, st, err := v.client.ReadVHandleContext(ctx, path, ino, off, int64(length))
	resume()
	if err != nil {
		return nil, fsproto.EIO
	}
	return data, st
}

func (v *Volume) read(ctx context.Context, permit *readView, path string, n *NodeState, off int64, length int) ([]byte, Status) {
	if oi := n.Orphan(); oi != 0 {
		data, st, err := v.client.ReadOrphanContext(v.authorityWaitContext(ctx), oi, off, int64(length))
		if err != nil {
			return nil, fsproto.EIO
		}
		return data, st
	}
	if v.wb != nil && !v.isHardlink(n) {
		dst := make([]byte, length)
		nRead, handled, err := permit.ReadAt(path, dst, off, func(basePath string, boff int64, bdst []byte) (int, error) {
			// basePath is where the authority CURRENTLY serves this view's
			// clean ranges (it trails a local rename until the rename
			// applies — reading the new name early would serve the previous
			// file's bytes).
			data, st := v.readBase(ctx, permit, basePath, n, boff, len(bdst))
			if st != fsproto.OK {
				// A base miss composes as zeros; the dirty extents and the
				// engine-tracked size still bound the result.
				return 0, nil
			}
			return copy(bdst, data), nil
		})
		if handled {
			if err != nil {
				v.debug("Read composed %q off=%d: %v", path, off, err)
				return nil, fsproto.EIO
			}
			return dst[:nRead], fsproto.OK
		}
	}
	return v.readBase(ctx, permit, path, n, off, length)
}

// readBase is the shared/clean read path: version-gated disk cache first,
// then the authority. A path under a HELD delegation never touches the disk
// cache: our own flushed mutations are owner-suppressed on the invalidation
// stream, so the version gate cannot advance for them — a cached block would
// serve the PREVIOUS flushed content after the overlay folds. Covered reads
// go to the authority (whose applied state is exactly what we acknowledged);
// the cache resumes when the delegation releases and versions flow again.
func (v *Volume) readBase(ctx context.Context, permit *readView, path string, n *NodeState, off int64, length int) ([]byte, Status) {
	handleIno := authHandleIno(n)
	covered := v.wb != nil && permit.Covers(path)
	if v.DiskCache != nil && handleIno != 0 && !covered {
		if gen, knownVersion := v.VersionCache.GenAndVersion(path); gen != 0 && knownVersion != 0 {
			if data, ok := v.DiskCache.GetRange(v.volumeID, gen, handleIno, off, length, knownVersion); ok {
				return data, fsproto.OK
			}
		}
	}
	var resume func()
	if !covered {
		resume = v.suspendAuthorityPublication(ctx)
	}
	data, version, gen, st, err := v.client.ReadVHandleContext(ctx, path, handleIno, off, int64(length))
	if resume != nil {
		resume()
	}
	if err != nil {
		return nil, fsproto.EIO
	}
	if st == fsproto.ENOENT {
		if oi := v.RedirectToOrphan(ctx, n); oi != 0 {
			d, ost, oerr := v.client.ReadOrphanContext(v.authorityWaitContext(ctx), oi, off, int64(length))
			if oerr == nil && ost == fsproto.OK {
				return d, fsproto.OK
			}
		}
	}
	if st != fsproto.OK {
		return nil, st
	}
	if oi := n.Orphan(); oi != 0 {
		if d, ost, oerr := v.client.ReadOrphanContext(v.authorityWaitContext(ctx), oi, off, int64(length)); oerr == nil && ost == fsproto.OK {
			return d, fsproto.OK
		}
	}
	token, cacheOK := v.VersionCache.AcceptGeneration(permit.cacheToken, gen)
	if cacheOK {
		permit.cacheToken = token
	}
	// P1: fire the kernel FOPEN_KEEP_CACHE flush backup exactly once per new generation, tracked
	// SEPARATELY from the version-cache re-anchor above. A getattr/readdir may have re-anchored the
	// version cache first (they RefreshAll but do not flush the kernel), so gating this on SeenGen —
	// as the pre-restore code did — would silently drop the read's content flush after a failover.
	if v.onFlushAll != nil && v.markKernelFlushed(gen) {
		go v.onFlushAll("")
	}
	fillOK := cacheOK && v.VersionCache.FillOKToken(token, gen, path, version)
	if !fillOK && v.onInvalidate != nil {
		go v.onInvalidate(path, true)
	}
	if fillOK && v.DiskCache != nil && handleIno != 0 && !covered {
		v.DiskCache.PutRange(v.volumeID, gen, handleIno, off, version, data, length)
	}
	return data, fsproto.OK
}

func (v *Volume) Write(ctx context.Context, path string, n *NodeState, off int64, data []byte) (int, Status) {
	ctx = withHardlinkAdmissionIdentities(ctx, n)
	if err := v.beginMutation(ctx); err != nil {
		return 0, fsproto.EIO
	}
	defer v.endMutation()

	if oi := n.Orphan(); oi != 0 {
		cnt, st, err := v.client.WriteOrphanContext(v.authorityWaitContext(ctx), oi, off, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	if v.wb != nil && v.isHardlink(n) {
		if err := v.releaseHardlinkScopes(ctx, []*NodeState{n}, path); err != nil {
			return 0, statusErr(err)
		}
	}
	if v.wb != nil && !v.isHardlink(n) {
		n.mu.Lock()
		if oi := n.orphanIno; oi != 0 {
			n.mu.Unlock()
			cnt, st, werr := v.client.WriteOrphanContext(v.authorityWaitContext(ctx), oi, off, data)
			if werr != nil {
				return 0, fsproto.EIO
			}
			return cnt, st
		}
		// Never retain the node lock while write-back admission may wait for a
		// delegation release. Open-pin protection reads the same orphan state
		// during that release; holding n.mu here would make the writer wait for
		// the release while the release waits for the writer. If admission
		// falls through, the shared lane rechecks orphan state below.
		n.mu.Unlock()
		res, handled, werr := v.wb.WriteAt(ctx, path, off, data)
		if handled {
			if werr != nil {
				v.debug("Write engine %q off=%d: %v", path, off, werr)
				return 0, statusErr(werr)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, true)
			return res.Count, fsproto.OK
		}
		if werr != nil {
			return 0, statusErr(werr)
		}
	}
	authorityCtx, endAuthority, releaseErr := v.beginAuthorityMutation(
		ctx, []*NodeState{n}, path,
	)
	if releaseErr != nil {
		return 0, statusErr(releaseErr)
	}
	defer endAuthority()
	n.mu.Lock()
	if oi := n.orphanIno; oi != 0 {
		n.mu.Unlock()
		cnt, st, err := v.client.WriteOrphanContext(authorityCtx, oi, off, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	handleIno := authHandleIno(n)
	cnt, version, gen, st, err := v.client.WriteVHandleContext(authorityCtx, path, handleIno, off, data, 0o644)
	n.mu.Unlock()
	if err != nil {
		return 0, fsproto.EIO
	}
	if st == fsproto.ENOENT {
		if oi := v.RedirectToOrphan(authorityCtx, n); oi != 0 {
			c2, ost, oerr := v.client.WriteOrphanContext(authorityCtx, oi, off, data)
			if oerr != nil {
				return 0, fsproto.EIO
			}
			return c2, ost
		}
	}
	if st != fsproto.OK {
		return 0, st
	}
	v.recent.record(path)
	v.VersionCache.FillOK(gen, path, version)
	v.AttrCache.Evict(path)
	if v.isHardlink(n) {
		v.invalidateRelatedInodes([]uint64{n.AuthorityIno()}, path, gen, version, false)
	}
	return cnt, fsproto.OK
}

// WriteExactHandle is the detached-descriptor mutation lane. A mount-wide
// release is rare but necessary: with an unseen surviving hard link there is
// no trustworthy pathname scope to release more narrowly.
func (v *Volume) WriteExactHandle(ctx context.Context, n *NodeState, off int64, data []byte) (int, Status) {
	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		return 0, fsproto.EIO
	}
	defer end()
	ino := authHandleIno(n)
	if n == nil || !n.IsOpen() || ino == 0 {
		return 0, fsproto.ENOENT
	}
	if oi := n.Orphan(); oi != 0 {
		count, st, err := v.client.WriteOrphanContext(authorityCtx, oi, off, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return count, st
	}
	count, _, _, st, err := v.client.WriteVHandleContext(authorityCtx, "", ino, off, data, 0o644)
	if err != nil {
		return 0, fsproto.EIO
	}
	return count, st
}

// WriteOpenHandle validates any delegated snapshot against the descriptor
// inode before local admission. The authority fallthrough already carries
// the stable inode handle, so a stale alias can never redirect the write to a
// rename-over replacement.
func (v *Volume) WriteOpenHandle(ctx context.Context, path string, n *NodeState, off int64, data []byte) (int, Status) {
	path = cleanVolumePath(path)
	if path == "" {
		return v.WriteExactHandle(ctx, n, off, data)
	}
	ctx = withDelegatedBindingExpectation(ctx, path, n)
	count, st := v.Write(ctx, path, n, off, data)
	if st == statusExactRetry {
		return v.WriteExactHandle(ctx, n, off, data)
	}
	return count, st
}

// WriteAppend executes O_APPEND. Under a delegation the local size is
// authoritative (the grant is exclusive), so the append is acknowledged
// locally at the exact EOF; otherwise the authority resolves EOF in
// sequencer order.
func (v *Volume) WriteAppend(ctx context.Context, path string, n *NodeState, legacyOff int64, data []byte) (int, Status) {
	ctx = withHardlinkAdmissionIdentities(ctx, n)
	if err := v.beginMutation(ctx); err != nil {
		return 0, fsproto.EIO
	}
	defer v.endMutation()

	if oi := n.Orphan(); oi != 0 {
		cnt, _, st, err := v.client.AppendOrphanContext(v.authorityWaitContext(ctx), oi, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	if v.wb != nil && v.isHardlink(n) {
		if err := v.releaseHardlinkScopes(ctx, []*NodeState{n}, path); err != nil {
			return 0, statusErr(err)
		}
	}
	if v.wb != nil && !v.isHardlink(n) {
		n.mu.Lock()
		if oi := n.orphanIno; oi != 0 {
			n.mu.Unlock()
			cnt, _, st, werr := v.client.AppendOrphanContext(v.authorityWaitContext(ctx), oi, data)
			if werr != nil {
				return 0, fsproto.EIO
			}
			return cnt, st
		}
		// See Write: delegation admission can wait for open-pin protection,
		// which must be able to inspect this NodeState.
		n.mu.Unlock()
		res, handled, werr := v.wb.WriteAppend(ctx, path, data)
		if handled {
			if werr != nil {
				v.debug("WriteAppend engine %q: %v", path, werr)
				return 0, statusErr(werr)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, true)
			return res.Count, fsproto.OK
		}
		if werr != nil {
			return 0, statusErr(werr)
		}
	}
	authorityCtx, endAuthority, releaseErr := v.beginAuthorityMutation(
		ctx, []*NodeState{n}, path,
	)
	if releaseErr != nil {
		return 0, statusErr(releaseErr)
	}
	defer endAuthority()
	n.mu.Lock()
	if oi := n.orphanIno; oi != 0 {
		n.mu.Unlock()
		cnt, _, st, err := v.client.AppendOrphanContext(authorityCtx, oi, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	handleIno := authHandleIno(n)
	cnt, _, version, gen, st, err := v.client.AppendVHandleContext(authorityCtx, path, handleIno, data, 0o644)
	n.mu.Unlock()
	if err != nil {
		return 0, fsproto.EIO
	}
	if st == fsproto.ENOENT {
		if oi := v.RedirectToOrphan(authorityCtx, n); oi != 0 {
			c2, _, ost, oerr := v.client.AppendOrphanContext(authorityCtx, oi, data)
			if oerr != nil {
				return 0, fsproto.EIO
			}
			return c2, ost
		}
	}
	if st != fsproto.OK {
		return 0, st
	}
	v.recent.record(path)
	v.VersionCache.FillOK(gen, path, version)
	v.AttrCache.Evict(path)
	if v.isHardlink(n) {
		v.invalidateRelatedInodes([]uint64{n.AuthorityIno()}, path, gen, version, false)
	}
	return cnt, fsproto.OK
}

func (v *Volume) Create(ctx context.Context, path string, mode uint32) (fsproto.Attr, Status) {
	return v.createCommon(ctx, path, mode, false)
}

// CreateExcl is Create with O_EXCL semantics enforced at the strongest layer
// available: under a complete delegated view the exclusivity decision is
// local and authoritative; otherwise it is made atomically inside the
// ordered journal (wire Excl).
func (v *Volume) CreateExcl(ctx context.Context, path string, mode uint32) (fsproto.Attr, Status) {
	return v.createCommon(ctx, path, mode, true)
}

func (v *Volume) createCommon(ctx context.Context, path string, mode uint32, excl bool) (fsproto.Attr, Status) {
	if err := v.beginMutation(ctx); err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer v.endMutation()

	mode = modebits.CleanUnix(mode)
	if v.wb != nil {
		// The kernel lookup that precedes every create already proved ENOENT;
		// when that proof survives in the version-gated negative cache, the
		// engine can acknowledge the create locally even before its parent
		// view is complete.
		knownAbsent := v.provenAbsent(path)
		res, handled, err := v.wb.Create(ctx, path, mode, excl, knownAbsent)
		if handled {
			if err != nil {
				return fsproto.Attr{}, statusErr(err)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, false)
			return engineAttr(path, res.Entry), fsproto.OK
		}
		if err != nil {
			return fsproto.Attr{}, statusErr(err)
		}
	}
	a, st := v.createWriteThrough(ctx, path, mode, excl)
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	v.recent.record(path)
	dir, _ := splitPath(path)
	v.AttrCache.Evict(dir)
	v.evictDirCache(dir)
	return a, fsproto.OK
}

// createWriteThrough issues the authority create. Every in-tree caller of
// Create immediately opens the result (the kernel CREATE is create+open), so
// the open registration rides the create RPC itself (RegisterOpen): the hold
// is applied before the create returns — the open-vs-unlink decision point
// is unchanged — and the follow-up RegisterOpened becomes a zero-RPC
// registry hit on the seeded hold.
func (v *Volume) createWriteThrough(
	ctx context.Context,
	path string,
	mode uint32,
	excl bool,
) (fsproto.Attr, Status) {
	var a *fsproto.Attr
	var gen uint64
	var st int32
	var err error
	authorityCtx, end, releaseErr := v.beginAuthorityMutation(
		ctx, nil, path,
	)
	if releaseErr != nil {
		return fsproto.Attr{}, statusErr(releaseErr)
	}
	if excl {
		a, gen, st, err = v.client.CreateExclRegisterOpenContext(authorityCtx, path, mode)
	} else {
		a, gen, st, err = v.client.CreateRegisterOpenContext(authorityCtx, path, mode)
	}
	end()
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	if a.Ino != 0 {
		v.openReg.SeedRegistered(path, a.Ino, gen)
	}
	return *a, fsproto.OK
}

func (v *Volume) Mkdir(ctx context.Context, path string, mode uint32) (fsproto.Attr, Status) {
	if err := v.beginMutation(ctx); err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer v.endMutation()

	mode = modebits.CleanUnix(mode)
	if v.wb != nil {
		res, handled, err := v.wb.Mkdir(ctx, path, mode)
		if handled {
			if err != nil {
				return fsproto.Attr{}, statusErr(err)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, false)
			return engineAttr(path, res.Entry), fsproto.OK
		}
		if err != nil {
			return fsproto.Attr{}, statusErr(err)
		}
	}
	var (
		a   *fsproto.Attr
		st  int32
		err error
	)
	authorityCtx, end, releaseErr := v.beginAuthorityMutation(
		ctx, nil, path,
	)
	if releaseErr != nil {
		return fsproto.Attr{}, statusErr(releaseErr)
	}
	a, st, err = v.client.MkdirContext(authorityCtx, path, mode)
	end()
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	v.recent.record(path)
	dir, _ := splitPath(path)
	v.AttrCache.Evict(dir)
	v.evictDirCache(dir)
	return *a, fsproto.OK
}

func (v *Volume) Remove(ctx context.Context, path string, child *NodeState) Status {
	ctx = withHardlinkAdmissionIdentities(ctx, child)
	if err := v.beginMutation(ctx); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	// A remove's park-vs-destroy decision at the authority reads OUR open
	// holds too: release any zero-ref retained registration on the target
	// first (synchronously — the op-order dependency deferred unmarks have),
	// or this mount's own remove of a recently-closed file would spuriously
	// park the inode until lease GC. Live handles are untouched; the open
	// paths below own those.
	v.openReg.ReleaseNameChange(path, authHandleIno(child))
	if v.wb != nil && v.isHardlink(child) {
		if err := v.releaseHardlinkScopes(ctx, []*NodeState{child}, path); err != nil {
			return statusErr(err)
		}
	}
	if v.wb != nil && !v.isHardlink(child) {
		// Unlink-while-open needs the write-through orphan protocol, which
		// never runs INSIDE a held delegation: the covering scope drains and
		// releases first, then the orphan proceeds on the shared lane.
		openHandle := false
		if child != nil {
			child.mu.Lock()
			openHandle = child.nopen > 0 && child.orphanIno == 0
			child.mu.Unlock()
		}
		if openHandle && v.wb.Covers(path) {
			if err := v.wb.ReleaseFor(ctx, path); err != nil {
				return statusErr(err)
			}
		} else if !openHandle {
			res, handled, err := v.wb.Remove(ctx, path)
			if handled {
				_ = res
				if err != nil {
					return statusErr(err)
				}
				v.recent.record(path)
				v.noteSelfMutation(path, 0, 0, false)
				return fsproto.OK
			}
			if err != nil {
				return statusErr(err)
			}
		}
	}
	var st Status
	authorityCtx, end, releaseErr := v.beginAuthorityMutation(
		ctx, []*NodeState{child}, path,
	)
	if releaseErr != nil {
		return statusErr(releaseErr)
	}
	st = v.removeWriteThrough(authorityCtx, path, child)
	end()
	return st
}

// removeWriteThrough performs the authority-side remove/orphan transaction.
// Its caller has already released every overlapping local delegation and
// keeps delegation acquisition excluded until this transaction returns.
func (v *Volume) removeWriteThrough(ctx context.Context, path string, child *NodeState) Status {
	if child != nil {
		child.mu.Lock()
		if child.nopen > 0 && child.orphanIno == 0 {
			ino, st, err := v.client.OrphanContext(ctx, path)
			if err != nil {
				child.mu.Unlock()
				return fsproto.EIO
			}
			if st == fsproto.OK {
				child.markOrphanLocked(ino, v.openOrphans)
			}
			child.mu.Unlock()
			if st == fsproto.OK {
				v.recent.record(path)
				v.AttrCache.Evict(path)
				dir, _ := splitPath(path)
				v.AttrCache.Evict(dir)
				v.evictDirCache(dir)
				v.invalidateRelatedInodes([]uint64{child.AuthorityIno()}, path, 0, 0, false)
				v.hardlinks.removePath(path)
			}
			return st
		}
		if child.nopen == 0 {
			// ReleaseFor deliberately leaves closes responsive while it
			// prepares open pins. Re-decide under the target NodeState lock:
			// either a racing close already won, in which case its prepared
			// or retained hold must be synchronously unmarked before Remove,
			// or a later close waits and the explicit orphan arm above owns
			// the inode. Only this inode is serialized across the matching
			// authority mutation.
			v.openReg.ReleaseNameChange(path, child.AuthorityIno())
			st, err := v.client.RemoveContext(ctx, path)
			child.mu.Unlock()
			if err != nil {
				return fsproto.EIO
			}
			v.recent.record(path)
			if st == fsproto.OK {
				dir, _ := splitPath(path)
				v.AttrCache.Evict(dir)
				v.evictDirCache(dir)
				v.invalidateRelatedInodes([]uint64{child.AuthorityIno()}, path, 0, 0, false)
				v.hardlinks.removePath(path)
			}
			return st
		}
		child.mu.Unlock()
	}
	st, err := v.client.RemoveContext(ctx, path)
	if err != nil {
		return fsproto.EIO
	}
	v.recent.record(path)
	if st == fsproto.OK {
		dir, _ := splitPath(path)
		v.AttrCache.Evict(dir)
		v.evictDirCache(dir)
		if child != nil {
			v.invalidateRelatedInodes([]uint64{child.AuthorityIno()}, path, 0, 0, false)
		}
		v.hardlinks.removePath(path)
	}
	return st
}

func lockTwo(a, b *NodeState) {
	switch {
	case a == nil:
		if b != nil {
			b.mu.Lock()
		}
	case b == nil || a == b:
		a.mu.Lock()
	case a.StableIno() <= b.StableIno():
		a.mu.Lock()
		b.mu.Lock()
	default:
		b.mu.Lock()
		a.mu.Lock()
	}
}

func unlockTwo(a, b *NodeState) {
	if a != nil {
		a.mu.Unlock()
	}
	if b != nil && b != a {
		b.mu.Unlock()
	}
}

func (v *Volume) Rename(ctx context.Context, oldp, newp string, src, dst *NodeState) Status {
	ctx = withHardlinkAdmissionIdentities(ctx, src, dst)
	if err := v.beginMutation(ctx); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	sameAuthorityInode := sameAuthorityIdentity(src, dst)
	// Rename-over reads OUR open holds on the replaced destination the same
	// way remove does: release any zero-ref retained registration on newp
	// first, so replacing a recently-closed file destroys it (as it always
	// did) instead of spuriously parking it against our stale hold. An OPEN
	// destination takes the explicit orphan-target arm below, untouched. Two
	// names already bound to the same authority inode are a POSIX no-op: do
	// not retire either name's registration.
	if !sameAuthorityInode {
		v.openReg.ReleaseNameChange(newp, authHandleIno(dst))
	}
	if v.wb != nil && (sameAuthorityInode || v.isHardlink(src) || v.isHardlink(dst)) {
		if err := v.releaseHardlinkScopes(ctx, []*NodeState{src, dst}, oldp, newp); err != nil {
			return statusErr(err)
		}
	}
	if v.wb != nil && !sameAuthorityInode && !v.isHardlink(src) && !v.isHardlink(dst) {
		// Rename-over an open destination needs the orphan protocol, which
		// runs write-through — never inside a held delegation. Release the
		// covering scopes first, then take the shared lane below.
		openDst := false
		if dst != nil {
			lockTwo(src, dst)
			openDst = dst.nopen > 0 && dst.orphanIno == 0
			unlockTwo(src, dst)
		}
		if openDst && (v.wb.Covers(oldp) || v.wb.Covers(newp)) {
			if err := v.wb.ReleaseFor(ctx, oldp, newp); err != nil {
				return statusErr(err)
			}
		} else if !openDst {
			res, handled, err := v.wb.Rename(ctx, oldp, newp, func() {
				v.noteOpenRename(oldp, newp, src, dst)
			})
			if handled {
				_ = res
				if err != nil {
					return statusErr(err)
				}
				v.recent.record(oldp, newp)
				v.evictRename(oldp, newp)
				return fsproto.OK
			}
			if err != nil {
				return statusErr(err)
			}
		}
	}
	var st Status
	authorityCtx, end, releaseErr := v.beginAuthorityMutation(
		ctx,
		[]*NodeState{src, dst},
		oldp,
		newp,
	)
	if releaseErr != nil {
		return statusErr(releaseErr)
	}
	st = v.renameWriteThrough(authorityCtx, oldp, newp, src, dst, sameAuthorityInode)
	end()
	return st
}

// renameWriteThrough performs the authority-side rename with the
// open-destination orphan protocol and full cache/registry bookkeeping.
func (v *Volume) renameWriteThrough(
	ctx context.Context,
	oldp, newp string,
	src, dst *NodeState,
	sameAuthorityInode bool,
) Status {
	if sameAuthorityInode {
		// POSIX rename(old,new) is a semantic no-op when both names already
		// identify the same inode. Still ask the authority to validate the
		// current namespace, but never detach/rekey either frontend name,
		// open owner, retained registration, or alias observation.
		st, _, err := v.client.RenameWithOrphanTargetContext(ctx, oldp, newp, false)
		if err != nil {
			return fsproto.EIO
		}
		return st
	}
	if dst != nil {
		lockTwo(src, dst)
		if dst.nopen > 0 && dst.orphanIno == 0 {
			st, orphanIno, err := v.client.RenameWithOrphanTargetContext(ctx, oldp, newp, true)
			if err != nil {
				unlockTwo(src, dst)
				return fsproto.EIO
			}
			if st == fsproto.OK && orphanIno != 0 {
				dst.markOrphanLocked(orphanIno, v.openOrphans)
			}
			unlockTwo(src, dst)
			if st == fsproto.OK {
				v.evictRename(oldp, newp)
				v.noteOpenRename(oldp, newp, src, dst)
			}
			v.recent.record(oldp, newp)
			return st
		}
		if dst.nopen == 0 {
			// A destination close can race the delegation prepare while
			// remaining responsive. Serialize its final state decision and
			// the matching authority rename on the two participating
			// NodeStates. A close that already won is synchronously unmarked;
			// a close that arrives later waits and the open-destination arm
			// above provides explicit orphan semantics.
			v.openReg.ReleaseNameChange(newp, dst.AuthorityIno())
			st, _, err := v.client.RenameWithOrphanTargetContext(ctx, oldp, newp, false)
			unlockTwo(src, dst)
			if err != nil {
				return fsproto.EIO
			}
			if st == fsproto.OK {
				v.evictRename(oldp, newp)
				v.noteOpenRename(oldp, newp, src, dst)
			}
			v.recent.record(oldp, newp)
			return st
		}
		unlockTwo(src, dst)
	}
	st, _, err := v.client.RenameWithOrphanTargetContext(ctx, oldp, newp, false)
	if err != nil {
		return fsproto.EIO
	}
	if st == fsproto.OK {
		v.evictRename(oldp, newp)
		v.noteOpenRename(oldp, newp, src, dst)
	}
	v.recent.record(oldp, newp)
	return st
}

func (v *Volume) noteOpenRename(oldPath, newPath string, src, dst *NodeState) {
	v.openStateMu.Lock()
	defer v.openStateMu.Unlock()
	if dst == src {
		dst = nil
	}
	v.opens.ApplyRename(oldPath, newPath, dst)
	v.openReg.NotePathMoved(oldPath, newPath)
}

func (v *Volume) evictRename(oldp, newp string) {
	v.invalidateRelatedInodes(v.hardlinks.inosForPaths(oldp, newp), "", 0, 0, false)
	v.hardlinks.rekey(oldp, newp)
	v.evictNamespacePaths(oldp, newp)
}

func (v *Volume) evictNamespacePaths(oldp, newp string) {
	v.AttrCache.EvictPrefix(oldp)
	v.AttrCache.EvictPrefix(newp)
	olddir, _ := splitPath(oldp)
	newdir, _ := splitPath(newp)
	v.AttrCache.Evict(olddir)
	v.AttrCache.Evict(newdir)
	v.evictDirCache(olddir)
	v.evictDirCache(newdir)
}

func (v *Volume) Symlink(ctx context.Context, target, path string) (fsproto.Attr, Status) {
	if err := v.beginMutation(ctx); err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer v.endMutation()

	if v.wb != nil {
		res, handled, err := v.wb.Symlink(ctx, path, target)
		if handled {
			if err != nil {
				return fsproto.Attr{}, statusErr(err)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, false)
			return engineAttr(path, res.Entry), fsproto.OK
		}
		if err != nil {
			return fsproto.Attr{}, statusErr(err)
		}
	}
	var (
		a   *fsproto.Attr
		st  int32
		err error
	)
	authorityCtx, end, releaseErr := v.beginAuthorityMutation(
		ctx, nil, path,
	)
	if releaseErr != nil {
		return fsproto.Attr{}, statusErr(releaseErr)
	}
	a, st, err = v.client.SymlinkContext(authorityCtx, target, path)
	end()
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	v.recent.record(path)
	dir, _ := splitPath(path)
	v.AttrCache.Evict(dir)
	v.evictDirCache(dir)
	return *a, fsproto.OK
}

// Link creates newp as another name for oldp's inode. Hard links use the
// write-through lane: one hard-linked inode may span delegation scopes, so
// any delegation covering either end drains and RELEASES first — the link
// then orders after the released state and never mutates inside a held
// scope.
func (v *Volume) Link(ctx context.Context, oldp, newp string, src *NodeState) (fsproto.Attr, Status) {
	if err := v.beginMutation(ctx); err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer v.endMutation()

	if v.wb != nil {
		if err := v.releaseHardlinkScopes(ctx, []*NodeState{src}, oldp, newp); err != nil {
			return fsproto.Attr{}, statusErr(err)
		}
	}
	var (
		a   *fsproto.Attr
		st  int32
		err error
	)
	authorityCtx, end, releaseErr := v.beginAuthorityMutation(
		ctx,
		[]*NodeState{src},
		oldp,
		newp,
	)
	if releaseErr != nil {
		return fsproto.Attr{}, statusErr(releaseErr)
	}
	if src != nil {
		src.mu.Lock()
		defer src.mu.Unlock()
	}
	a, st, err = v.client.LinkContext(authorityCtx, oldp, newp)
	end()
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	if a.Ino == 0 && src != nil && src.AuthIno() {
		a.Ino = src.AuthorityIno()
	}
	if src != nil && !src.RecordAuthorityIno(a.Ino) {
		return fsproto.Attr{}, fsproto.EIO
	}
	v.observeHardlink(oldp, *a)
	v.observeHardlink(newp, *a)
	v.recent.record(oldp, newp)
	v.evictNamespacePaths(oldp, newp)
	return *a, fsproto.OK
}

func (v *Volume) Readlink(ctx context.Context, path string) (string, Status) {
	permit, err := v.beginRead(ctx, path)
	if err != nil {
		return "", fsproto.EIO
	}
	defer permit.Close()
	return v.readlink(ctx, &permit, path)
}

func (v *Volume) readlink(ctx context.Context, permit *readView, path string) (string, Status) {
	// An engine-covered path answers from the overlay: a just-created symlink
	// may not have flushed to the authority yet, so resolving there would
	// race the flusher.
	if v.wb != nil {
		if target, kind, ok := permit.Readlink(path); ok {
			switch kind {
			case "symlink":
				return target, fsproto.OK
			case "":
				return "", fsproto.ENOENT
			default:
				return "", fsproto.EINVAL
			}
		}
	}
	covered := v.wb != nil && permit.Covers(path)
	var resume func()
	if !covered {
		resume = v.suspendAuthorityPublication(ctx)
	}
	t, st, err := v.client.ReadlinkContext(ctx, path)
	if resume != nil {
		resume()
	}
	if err != nil {
		return "", fsproto.EIO
	}
	return t, st
}

func (v *Volume) Setattr(ctx context.Context, path string, n *NodeState, req SetattrRequest) (fsproto.Attr, Status) {
	ctx = withHardlinkAdmissionIdentities(ctx, n)
	if err := v.beginMutation(ctx); err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer v.endMutation()

	if oi := n.Orphan(); oi != 0 {
		return v.setattrOrphan(ctx, oi, req)
	}
	if v.wb != nil && v.isHardlink(n) {
		if err := v.releaseHardlinkScopes(ctx, []*NodeState{n}, path); err != nil {
			return fsproto.Attr{}, statusErr(err)
		}
	}
	if v.wb != nil && !v.isHardlink(n) {
		n.mu.Lock()
		if oi := n.orphanIno; oi != 0 {
			n.mu.Unlock()
			return v.setattrOrphan(ctx, oi, req)
		}
		n.mu.Unlock()
		var last writeback.Result
		handledAll := true
		mutated := false
		if req.SetSize {
			res, handled, err := v.wb.Truncate(ctx, path, req.Size)
			if !handled {
				handledAll = false
			} else if err != nil {
				return fsproto.Attr{}, statusErr(err)
			} else {
				last, mutated = res, true
			}
		}
		if handledAll && (req.SetMode || req.SetMTime || req.SetATime || req.SetUID || req.SetGID) {
			engReq := writeback.SetattrRequest{
				SetMode: req.SetMode, Mode: modebits.CleanUnix(req.Mode),
				SetTime: req.SetMTime, MtimeMs: req.MtimeMs,
				SetATime: req.SetATime, AtimeMs: req.AtimeMs,
				SetUID: req.SetUID, UID: req.UID,
				SetGID: req.SetGID, GID: req.GID,
			}
			res, handled, err := v.wb.Setattr(ctx, path, engReq)
			if !handled {
				handledAll = false
			} else if err != nil {
				return fsproto.Attr{}, statusErr(err)
			} else {
				last, mutated = res, true
			}
		}
		if handledAll && mutated {
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, true)
			return engineAttr(path, last.Entry), fsproto.OK
		}
		if handledAll && !mutated {
			// Nothing requested: report the current view, but still join the
			// read handoff barrier. This path is reachable from a size-refresh
			// setattr whose fields were consumed by the daemon.
			permit, err := v.beginRead(ctx, path)
			if err != nil {
				return fsproto.Attr{}, fsproto.EIO
			}
			defer permit.Close()
			if ent, res := permit.Lookup(path); res == writeback.LookupHit {
				a := engineAttr(path, ent)
				v.observeHardlink(path, a)
				return a, fsproto.OK
			}
		}
	}
	authorityCtx, endAuthority, releaseErr := v.beginAuthorityMutation(
		ctx, []*NodeState{n}, path,
	)
	if releaseErr != nil {
		return fsproto.Attr{}, statusErr(releaseErr)
	}
	defer endAuthority()
	n.mu.Lock()
	if oi := n.orphanIno; oi != 0 {
		n.mu.Unlock()
		return v.setattrOrphan(authorityCtx, oi, req)
	}
	handleIno := authHandleIno(n)
	if req.SetSize {
		st, err := v.client.TruncateHandleContext(authorityCtx, path, handleIno, req.Size)
		if err != nil {
			n.mu.Unlock()
			return fsproto.Attr{}, fsproto.EIO
		}
		if st != fsproto.OK {
			n.mu.Unlock()
			return fsproto.Attr{}, st
		}
		v.recent.record(path)
	}
	if req.SetMode || req.SetMTime || req.SetATime || req.SetUID || req.SetGID {
		st, err := v.client.SetattrTimesHandleContext(
			authorityCtx,
			path, handleIno,
			modebits.CleanUnix(req.Mode), req.SetMode,
			req.MtimeMs, req.SetMTime,
			req.AtimeMs, req.SetATime,
			req.UID, req.GID, req.SetUID, req.SetGID,
		)
		if err != nil {
			n.mu.Unlock()
			return fsproto.Attr{}, fsproto.EIO
		}
		if st != fsproto.OK {
			n.mu.Unlock()
			return fsproto.Attr{}, st
		}
		v.recent.record(path)
	}
	a, st, err := v.client.GetattrHandleContext(authorityCtx, path, handleIno)
	n.mu.Unlock()
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	v.observeHardlink(path, *a)
	if v.isHardlink(n) {
		v.invalidateRelatedInodes([]uint64{n.AuthorityIno()}, path, 0, 0, false)
	}
	return *a, fsproto.OK
}

// SetattrExactHandle applies descriptor metadata without using the former
// pathname. It covers both a parked last-link orphan and a detached inode that
// still has an authority-only hard-link alias unknown to this frontend.
func (v *Volume) SetattrExactHandle(ctx context.Context, n *NodeState, req SetattrRequest) (fsproto.Attr, Status) {
	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer end()
	ino := authHandleIno(n)
	if n == nil || !n.IsOpen() || ino == 0 {
		return fsproto.Attr{}, fsproto.ENOENT
	}
	orphanIno := n.Orphan()
	if req.SetSize {
		var st int32
		var err error
		if orphanIno != 0 {
			st, err = v.client.TruncateOrphanContext(authorityCtx, orphanIno, req.Size)
		} else {
			st, err = v.client.TruncateHandleContext(authorityCtx, "", ino, req.Size)
		}
		if err != nil {
			return fsproto.Attr{}, fsproto.EIO
		}
		if st != fsproto.OK {
			return fsproto.Attr{}, st
		}
	}
	if req.SetMode || req.SetMTime || req.SetATime || req.SetUID || req.SetGID {
		st, err := v.client.SetattrTimesHandleContext(
			authorityCtx,
			"", ino,
			modebits.CleanUnix(req.Mode), req.SetMode,
			req.MtimeMs, req.SetMTime,
			req.AtimeMs, req.SetATime,
			req.UID, req.GID, req.SetUID, req.SetGID,
		)
		if err != nil {
			return fsproto.Attr{}, fsproto.EIO
		}
		if st != fsproto.OK {
			return fsproto.Attr{}, st
		}
	}
	var a *fsproto.Attr
	var st int32
	if orphanIno != 0 {
		a, st, err = v.client.GetattrOrphanContext(authorityCtx, orphanIno)
	} else {
		a, st, err = v.client.GetattrHandleContext(authorityCtx, "", ino)
	}
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	return *a, fsproto.OK
}

func (v *Volume) SetattrOpenHandle(ctx context.Context, path string, n *NodeState, req SetattrRequest) (fsproto.Attr, Status) {
	path = cleanVolumePath(path)
	if path == "" {
		return v.SetattrExactHandle(ctx, n, req)
	}
	ctx = withDelegatedBindingExpectation(ctx, path, n)
	attr, st := v.Setattr(ctx, path, n, req)
	if st == statusExactRetry {
		return v.SetattrExactHandle(ctx, n, req)
	}
	return attr, st
}

func (v *Volume) setattrOrphan(ctx context.Context, ino uint64, req SetattrRequest) (fsproto.Attr, Status) {
	authorityCtx := v.authorityWaitContext(ctx)
	if req.SetSize {
		if st, err := v.client.TruncateOrphanContext(authorityCtx, ino, req.Size); err != nil {
			return fsproto.Attr{}, fsproto.EIO
		} else if st != fsproto.OK {
			return fsproto.Attr{}, st
		}
	}
	if req.SetMode || req.SetMTime || req.SetATime || req.SetUID || req.SetGID {
		// The parked inode is the identity. An empty path deliberately avoids
		// presenting the removed or overwritten name as namespace evidence;
		// exact-protocol handle addressing applies the metadata to ino.
		st, err := v.client.SetattrTimesHandleContext(
			authorityCtx,
			"", ino,
			modebits.CleanUnix(req.Mode), req.SetMode,
			req.MtimeMs, req.SetMTime,
			req.AtimeMs, req.SetATime,
			req.UID, req.GID, req.SetUID, req.SetGID,
		)
		if err != nil {
			return fsproto.Attr{}, fsproto.EIO
		}
		if st != fsproto.OK {
			return fsproto.Attr{}, st
		}
	}
	a, st, err := v.client.GetattrOrphanContext(authorityCtx, ino)
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	return *a, fsproto.OK
}

func authHandleIno(n *NodeState) uint64 {
	if n == nil {
		return 0
	}
	return n.AuthorityIno()
}

func sameAuthorityIdentity(a, b *NodeState) bool {
	if a == nil || b == nil {
		return false
	}
	aIno := a.AuthorityIno()
	return aIno != 0 && aIno == b.AuthorityIno()
}

func (v *Volume) FsyncPath(path string) Status {
	if err := v.Fsync(path); err != nil {
		return fsproto.EIO
	}
	return fsproto.OK
}

func (v *Volume) FsyncHandle(path string, n *NodeState) Status {
	if err := v.beginSharedOperation(); err != nil {
		return fsproto.EIO
	}
	defer v.endSharedOperation()

	if err := v.fsync(path); err != nil {
		return fsproto.EIO
	}
	return fsproto.OK
}

func (v *Volume) Getlk(ctx context.Context, path string, owner, start, end uint64, write bool) (fsproto.LockResult, error) {
	return v.LockAuth().Lock(ctx, path, fsproto.LkGetlk, owner, start, end, write, false)
}

func (v *Volume) Setlk(ctx context.Context, h *LockHandle, path string, owner, start, end uint64, write, unlock bool) (fsproto.LockResult, error) {
	v.registerLockHandle(h)
	return SetLock(ctx, v.LockAuth(), h, path, owner, start, end, write, unlock)
}

func (v *Volume) Setlkw(ctx context.Context, h *LockHandle, path string, owner, start, end uint64, write bool) (fsproto.LockResult, error) {
	v.registerLockHandle(h)
	return WaitSetLock(ctx, v.LockAuth(), h, path, owner, start, end, write)
}
