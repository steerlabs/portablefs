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

func statusErr(err error) Status {
	switch {
	case err == nil:
		return fsproto.OK
	case errors.Is(err, os.ErrNotExist):
		return fsproto.ENOENT
	case errors.Is(err, os.ErrExist):
		return fsproto.EEXIST
	case errors.Is(err, syscall.ENOTEMPTY):
		return fsproto.ENOTEMPTY
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

func (v *Volume) CachedGetattr(path string) (fsproto.Attr, Status) {
	if gen, curVer := v.VersionCache.GenAndVersion(path); gen != 0 {
		dir, _ := splitPath(path)
		_, parentCurVer := v.VersionCache.GenAndVersion(dir)
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
		if e, ok := v.AttrCache.GetLookup(gen, curVer, parentCurVer, path); ok {
			if !e.Exists {
				return fsproto.Attr{}, fsproto.ENOENT
			}
			v.observeHardlink(path, e.Attr)
			return e.Attr, fsproto.OK
		}
	}
	a, rver, rgen, parentVersion, st, err := v.client.GetattrV(path)
	if err != nil {
		v.debug("CachedGetattr GetattrV %q: %v", path, err)
		return fsproto.Attr{}, fsproto.EIO
	}
	if rgen != 0 && !v.VersionCache.SeenGen(rgen) {
		v.VersionCache.RefreshAll(rgen)
	}
	if rgen != 0 && st == fsproto.OK && v.VersionCache.FillOK(rgen, path, rver) {
		v.AttrCache.PutAttr(rgen, rver, path, a)
	}
	if v.negativeCache && rgen != 0 && st == fsproto.ENOENT && parentVersion != 0 {
		dir, _ := splitPath(path)
		pver := parentVersion - 1
		if v.VersionCache.FillOK(rgen, dir, pver) {
			v.AttrCache.PutNegative(rgen, pver, path)
		}
	}
	if st == fsproto.OK {
		v.observeHardlink(path, a)
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
	gen, curVer := v.VersionCache.GenAndVersion(path)
	if gen == 0 {
		return false
	}
	dir, _ := splitPath(path)
	_, parentCurVer := v.VersionCache.GenAndVersion(dir)
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
	return n != nil && v.hardlinks.contains(n.StableIno())
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
	if v.wb != nil {
		if ent, res := v.wb.Lookup(path); res == writeback.LookupHit {
			a := engineAttr(path, ent)
			if a.Nlink > 1 {
				v.observeHardlink(path, a)
			}
			return a, fsproto.OK
		} else if res == writeback.LookupNegative {
			return fsproto.Attr{}, fsproto.ENOENT
		}
		if dir, _ := splitPath(path); v.wb.Covers(dir) {
			// The engine covers the parent but cannot decide the name yet.
			// Seed the complete listing (ONE readdir instead of one getattr
			// per name) so this and every later lookup under the directory —
			// including proven ENOENT for names about to be created — is
			// answered locally for the life of the delegation.
			if _, st := v.Readdir(ctx, dir); st == fsproto.OK {
				if ent, res := v.wb.Lookup(path); res == writeback.LookupHit {
					return engineAttr(path, ent), fsproto.OK
				} else if res == writeback.LookupNegative {
					return fsproto.Attr{}, fsproto.ENOENT
				}
			}
		}
	}
	return v.CachedGetattr(path)
}

func (v *Volume) Getattr(ctx context.Context, path string, n *NodeState) (fsproto.Attr, Status) {
	if oi := n.Orphan(); oi != 0 {
		a, st, err := v.client.GetattrOrphan(oi)
		if err != nil {
			return fsproto.Attr{}, fsproto.EIO
		}
		if st != fsproto.OK {
			return fsproto.Attr{}, st
		}
		return *a, fsproto.OK
	}
	if v.wb != nil {
		if ent, res := v.wb.Lookup(path); res == writeback.LookupHit {
			return engineAttr(path, ent), fsproto.OK
		} else if res == writeback.LookupNegative {
			return fsproto.Attr{}, fsproto.ENOENT
		}
	}
	a, st := v.CachedGetattr(path)
	if st == fsproto.ENOENT {
		if oi := v.RedirectToOrphan(n); oi != 0 {
			if oa, ost, oerr := v.client.GetattrOrphan(oi); oerr == nil && ost == fsproto.OK {
				return *oa, fsproto.OK
			}
		}
	}
	return a, st
}

func (v *Volume) Readdir(ctx context.Context, dir string) ([]DirEntry, Status) {
	covered := v.wb != nil && v.wb.Covers(dir)
	if covered {
		// A held dir with a complete children set serves locally: the
		// delegation excludes peer mutations, and the engine's own
		// mutations are folded into the set. Zero RPCs.
		if ents, ok := v.wb.Readdir(dir); ok {
			return engineEntriesToDir(dir, ents), fsproto.OK
		}
		if ent, res := v.wb.Lookup(dir); res == writeback.LookupHit && ent.Kind != "directory" {
			return nil, fsproto.ENOTDIR
		} else if res == writeback.LookupNegative {
			return nil, fsproto.ENOENT
		}
	}
	if gen, curVer := v.VersionCache.GenAndVersion(dir); gen != 0 && !covered {
		v.dirMu.Lock()
		if e, ok := v.dirCache[dir]; ok && e.gen == gen && e.version >= curVer {
			out := append([]DirEntry(nil), e.entries...)
			v.dirMu.Unlock()
			return out, fsproto.OK
		}
		v.dirMu.Unlock()
	}
	ents, gen, dirVersion, st, err := v.client.ReaddirV(dir)
	if err != nil {
		return nil, fsproto.EIO
	}
	if st != fsproto.OK {
		return nil, st
	}
	if gen != 0 && !v.VersionCache.SeenGen(gen) {
		v.VersionCache.RefreshAll(gen)
	}
	fillCache := !v.noReaddirPlus && gen != 0 && !covered
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
		v.observeHardlink(cp, e.Attr)
		if fillCache && e.Version != 0 {
			ver := e.Version - 1
			if v.VersionCache.FillOK(gen, cp, ver) {
				v.AttrCache.PutAttr(gen, ver, cp, e.Attr)
			}
		}
	}
	if covered {
		// Seed the engine's complete children set from this authority
		// readdir and answer from the merged (overlay-over-base) view; later
		// lookups and listings under dir are then local.
		merged := v.wb.MergeReaddir(dir, dirEntriesToEngine(out))
		return engineEntriesToDir(dir, merged), fsproto.OK
	}
	// A non-delegated directory has no unflushed local children (every
	// create directly under it was write-through), so the authority listing
	// is authoritative — keep it as-is, preserving the readdir-plus versions
	// that fill the attr cache. Store it only when not delegated: a held
	// dir's version never advances for our own writes, so a cache entry
	// would go stale invisibly.
	if gen != 0 && v.VersionCache.FillOK(gen, dir, dirVersion) {
		v.dirMu.Lock()
		v.dirCache[dir] = dirCacheEntry{gen: gen, version: dirVersion, entries: append([]DirEntry(nil), out...)}
		v.dirMu.Unlock()
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
	pfx := rp + "/"
	for k := range v.dirCache {
		if k == rp || len(k) > len(pfx) && k[:len(pfx)] == pfx {
			delete(v.dirCache, k)
		}
	}
}

func (v *Volume) Open(ctx context.Context, path string, n *NodeState, writeIntent bool) Status {
	if err := v.beginMutation(); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	v.opens.Inc(path, n)
	if st := v.incOpen(path, n); st != fsproto.OK {
		v.rollbackTrackedOpen(path, n)
		return st
	}
	return fsproto.OK
}

func (v *Volume) RegisterOpened(path string, n *NodeState) Status {
	if err := v.beginMutation(); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	v.opens.Inc(path, n)
	if st := v.incOpen(path, n); st != fsproto.OK {
		v.rollbackTrackedOpen(path, n)
		return st
	}
	return fsproto.OK
}

// incOpen counts one open handle on n and registers the inode's open hold at
// the authority through the open registry (openreg.go): only the FIRST open
// of an unregistered inode round-trips; concurrent opens join that in-flight
// registration, and re-opens of a registered (live or retained) inode cost
// nothing. Any registration failure propagates to the caller: an open may
// return only after the authority has confirmed its inode hold.
func (v *Volume) incOpen(path string, n *NodeState) Status {
	if n == nil {
		return fsproto.OK
	}
	n.mu.Lock()
	n.nopen++
	n.mu.Unlock()
	if ino := n.StableIno(); ino != 0 && n.AuthIno() {
		if st := v.openReg.Open(path, ino); st != fsproto.OK {
			n.mu.Lock()
			n.nopen--
			n.mu.Unlock()
			return st
		}
	}
	return fsproto.OK
}

func (v *Volume) rollbackTrackedOpen(path string, n *NodeState) {
	owner := openOwnerFor(path, n)
	remaining, _, _ := v.opens.Dec(path, n)
	if remaining != 0 {
		return
	}
	// Delegation release may have observed the tracker reservation while
	// incOpen was waiting on registration. If the open ultimately fails,
	// return that release-time pin because no CloseHandle will follow.
	v.releasePinMu.Lock()
	pin, ok := v.releasePins[owner]
	if ok {
		delete(v.releasePins, owner)
	}
	v.releasePinMu.Unlock()
	if ok {
		v.openReg.Close(pin.path, pin.ino, n != nil && n.Orphan() != 0)
	}
}

func (v *Volume) CloseHandle(path string, n *NodeState) Status {
	if err := v.beginLifecycleOperation(); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	if currentPath, found := v.opens.CurrentPath(path, n); found {
		path = currentPath
	}
	owner := openOwnerFor(path, n)
	remaining, currentPath, found := v.opens.Dec(path, n)
	if found {
		// Re-read under the decrement lock in case a concurrent rename won
		// after the pre-barrier lookup.
		path = currentPath
	}
	orphaned := v.closeOne(path, n)
	if remaining == 0 {
		// Last local handle owned by this NodeState: retire any
		// delegation-release pin
		// through the standard registry flows (retained when the file still
		// exists; unmarked when it was orphaned, so the reap proceeds).
		v.releasePinMu.Lock()
		pin, ok := v.releasePins[owner]
		if ok {
			delete(v.releasePins, owner)
		}
		v.releasePinMu.Unlock()
		if ok {
			v.openReg.Close(pin.path, pin.ino, orphaned)
		}
	}
	return fsproto.OK
}

func (v *Volume) closeOne(path string, n *NodeState) bool {
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
	n.mu.Unlock()
	if orphanIno != 0 {
		v.openOrphans.Remove(orphanIno)
	}
	if hadOpen {
		if fino := n.StableIno(); fino != 0 && n.AuthIno() {
			// Every successful Open owns one registry ref. An orphaned
			// inode's final transition is discarded; a live zero-ref entry
			// is retained for RPC-free re-opens.
			v.openReg.Close(path, fino, orphaned)
		}
	}
	return orphaned
}

func (v *Volume) RedirectToOrphan(n *NodeState) uint64 {
	if n == nil || !n.IsOpen() {
		return 0
	}
	ino := authHandleIno(n)
	if ino == 0 {
		return 0
	}
	if _, st, err := v.client.GetattrOrphan(ino); err != nil || st != fsproto.OK {
		return 0
	}
	n.MarkOrphan(ino, v.openOrphans)
	return ino
}

func (v *Volume) Read(ctx context.Context, path string, n *NodeState, off int64, length int) ([]byte, Status) {
	if oi := n.Orphan(); oi != 0 {
		data, st, err := v.client.ReadOrphan(oi, off, int64(length))
		if err != nil {
			return nil, fsproto.EIO
		}
		return data, st
	}
	if v.wb != nil && !v.isHardlink(n) {
		dst := make([]byte, length)
		nRead, handled, err := v.wb.ReadAt(path, dst, off, func(basePath string, boff int64, bdst []byte) (int, error) {
			// basePath is where the authority CURRENTLY serves this view's
			// clean ranges (it trails a local rename until the rename
			// applies — reading the new name early would serve the previous
			// file's bytes).
			data, st := v.readBase(basePath, n, boff, len(bdst))
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
	return v.readBase(path, n, off, length)
}

// readBase is the shared/clean read path: version-gated disk cache first,
// then the authority. A path under a HELD delegation never touches the disk
// cache: our own flushed mutations are owner-suppressed on the invalidation
// stream, so the version gate cannot advance for them — a cached block would
// serve the PREVIOUS flushed content after the overlay folds. Covered reads
// go to the authority (whose applied state is exactly what we acknowledged);
// the cache resumes when the delegation releases and versions flow again.
func (v *Volume) readBase(path string, n *NodeState, off int64, length int) ([]byte, Status) {
	handleIno := authHandleIno(n)
	covered := v.wb != nil && v.wb.Covers(path)
	if v.DiskCache != nil && handleIno != 0 && !covered {
		if gen, knownVersion := v.VersionCache.GenAndVersion(path); gen != 0 && knownVersion != 0 {
			if data, ok := v.DiskCache.GetRange(v.volumeID, gen, handleIno, off, length, knownVersion); ok {
				return data, fsproto.OK
			}
		}
	}
	data, version, gen, st, err := v.client.ReadVHandle(path, handleIno, off, int64(length))
	if err != nil {
		return nil, fsproto.EIO
	}
	if st == fsproto.ENOENT {
		if oi := v.RedirectToOrphan(n); oi != 0 {
			d, ost, oerr := v.client.ReadOrphan(oi, off, int64(length))
			if oerr == nil && ost == fsproto.OK {
				return d, fsproto.OK
			}
		}
	}
	if st != fsproto.OK {
		return nil, st
	}
	if oi := n.Orphan(); oi != 0 {
		if d, ost, oerr := v.client.ReadOrphan(oi, off, int64(length)); oerr == nil && ost == fsproto.OK {
			return d, fsproto.OK
		}
	}
	if gen != 0 && !v.VersionCache.SeenGen(gen) {
		v.VersionCache.RefreshAll(gen)
	}
	// P1: fire the kernel FOPEN_KEEP_CACHE flush backup exactly once per new generation, tracked
	// SEPARATELY from the version-cache re-anchor above. A getattr/readdir may have re-anchored the
	// version cache first (they RefreshAll but do not flush the kernel), so gating this on SeenGen —
	// as the pre-restore code did — would silently drop the read's content flush after a failover.
	if v.onFlushAll != nil && v.markKernelFlushed(gen) {
		go v.onFlushAll("")
	}
	if !v.VersionCache.FillOK(gen, path, version) && v.onInvalidate != nil {
		go v.onInvalidate(path, true)
	}
	if v.DiskCache != nil && handleIno != 0 && !covered {
		v.DiskCache.PutRange(v.volumeID, gen, handleIno, off, version, data, length)
	}
	return data, fsproto.OK
}

func (v *Volume) Write(ctx context.Context, path string, n *NodeState, off int64, data []byte) (int, Status) {
	if err := v.beginMutation(); err != nil {
		return 0, fsproto.EIO
	}
	defer v.endMutation()

	if oi := n.Orphan(); oi != 0 {
		cnt, st, err := v.client.WriteOrphan(oi, off, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	if v.wb != nil && !v.isHardlink(n) {
		n.mu.Lock()
		if oi := n.orphanIno; oi != 0 {
			n.mu.Unlock()
			cnt, st, werr := v.client.WriteOrphan(oi, off, data)
			if werr != nil {
				return 0, fsproto.EIO
			}
			return cnt, st
		}
		res, handled, werr := v.wb.WriteAt(ctx, path, off, data)
		n.mu.Unlock()
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
	n.mu.Lock()
	if oi := n.orphanIno; oi != 0 {
		n.mu.Unlock()
		cnt, st, err := v.client.WriteOrphan(oi, off, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	handleIno := authHandleIno(n)
	cnt, version, gen, st, err := v.client.WriteVHandle(path, handleIno, off, data, 0o644)
	n.mu.Unlock()
	if err != nil {
		return 0, fsproto.EIO
	}
	if st == fsproto.ENOENT {
		if oi := v.RedirectToOrphan(n); oi != 0 {
			c2, ost, oerr := v.client.WriteOrphan(oi, off, data)
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
		v.invalidateRelatedInodes([]uint64{n.StableIno()}, path)
	}
	return cnt, fsproto.OK
}

// WriteAppend executes O_APPEND. Under a delegation the local size is
// authoritative (the grant is exclusive), so the append is acknowledged
// locally at the exact EOF; otherwise the authority resolves EOF in
// sequencer order.
func (v *Volume) WriteAppend(ctx context.Context, path string, n *NodeState, legacyOff int64, data []byte) (int, Status) {
	if err := v.beginMutation(); err != nil {
		return 0, fsproto.EIO
	}
	defer v.endMutation()

	if oi := n.Orphan(); oi != 0 {
		cnt, _, st, err := v.client.AppendOrphan(oi, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	if v.wb != nil && !v.isHardlink(n) {
		n.mu.Lock()
		if oi := n.orphanIno; oi != 0 {
			n.mu.Unlock()
			cnt, _, st, werr := v.client.AppendOrphan(oi, data)
			if werr != nil {
				return 0, fsproto.EIO
			}
			return cnt, st
		}
		res, handled, werr := v.wb.WriteAppend(ctx, path, data)
		n.mu.Unlock()
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
	n.mu.Lock()
	if oi := n.orphanIno; oi != 0 {
		n.mu.Unlock()
		cnt, _, st, err := v.client.AppendOrphan(oi, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	handleIno := authHandleIno(n)
	cnt, _, version, gen, st, err := v.client.AppendVHandle(path, handleIno, data, 0o644)
	n.mu.Unlock()
	if err != nil {
		return 0, fsproto.EIO
	}
	if st == fsproto.ENOENT {
		if oi := v.RedirectToOrphan(n); oi != 0 {
			c2, _, ost, oerr := v.client.AppendOrphan(oi, data)
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
		v.invalidateRelatedInodes([]uint64{n.StableIno()}, path)
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
	if err := v.beginMutation(); err != nil {
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
	a, st := v.createWriteThrough(path, mode, excl)
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
func (v *Volume) createWriteThrough(path string, mode uint32, excl bool) (fsproto.Attr, Status) {
	var a *fsproto.Attr
	var gen uint64
	var st int32
	var err error
	if excl {
		a, gen, st, err = v.client.CreateExclRegisterOpen(path, mode)
	} else {
		a, gen, st, err = v.client.CreateRegisterOpen(path, mode)
	}
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
	if err := v.beginMutation(); err != nil {
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
	a, st, err := v.client.Mkdir(path, mode)
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
	if err := v.beginMutation(); err != nil {
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
	if child != nil {
		child.mu.Lock()
		if child.nopen > 0 && child.orphanIno == 0 {
			ino, st, err := v.client.Orphan(path)
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
				v.invalidateRelatedInodes([]uint64{child.StableIno()}, path)
				v.hardlinks.removePath(path)
			}
			return st
		}
		child.mu.Unlock()
	}
	st, err := v.client.Remove(path)
	if err != nil {
		return fsproto.EIO
	}
	v.recent.record(path)
	if st == fsproto.OK {
		dir, _ := splitPath(path)
		v.AttrCache.Evict(dir)
		v.evictDirCache(dir)
		if child != nil {
			v.invalidateRelatedInodes([]uint64{child.StableIno()}, path)
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
	if err := v.beginMutation(); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	// Rename-over reads OUR open holds on the replaced destination the same
	// way remove does: release any zero-ref retained registration on newp
	// first, so replacing a recently-closed file destroys it (as it always
	// did) instead of spuriously parking it against our stale hold. An OPEN
	// destination takes the explicit orphan-target arm below, untouched.
	v.openReg.ReleaseNameChange(newp, authHandleIno(dst))
	if v.wb != nil && !v.isHardlink(src) && !v.isHardlink(dst) {
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
			res, handled, err := v.wb.Rename(ctx, oldp, newp)
			if handled {
				_ = res
				if err != nil {
					return statusErr(err)
				}
				v.recent.record(oldp, newp)
				v.evictRename(oldp, newp)
				v.noteOpenRename(oldp, newp, src, dst)
				return fsproto.OK
			}
			if err != nil {
				return statusErr(err)
			}
		}
	}
	return v.renameWriteThrough(oldp, newp, src, dst)
}

// renameWriteThrough performs the authority-side rename with the
// open-destination orphan protocol and full cache/registry bookkeeping.
func (v *Volume) renameWriteThrough(oldp, newp string, src, dst *NodeState) Status {
	if dst != nil {
		lockTwo(src, dst)
		if dst.nopen > 0 && dst.orphanIno == 0 {
			st, orphanIno, err := v.client.RenameWithOrphanTarget(oldp, newp, true)
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
		unlockTwo(src, dst)
	}
	st, _, err := v.client.RenameWithOrphanTarget(oldp, newp, false)
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
	if dst != nil && dst != src {
		v.opens.Unname(dst)
	}
	v.opens.RekeyPrefix(oldPath, newPath)
	v.rekeyReleasePins(oldPath, newPath)
	v.openReg.NotePathMoved(oldPath, newPath)
}

func (v *Volume) rekeyReleasePins(oldPath, newPath string) {
	v.releasePinMu.Lock()
	defer v.releasePinMu.Unlock()
	type move struct {
		owner openOwner
		pin   releasePin
	}
	var moves []move
	for owner, pin := range v.releasePins {
		moved, ok := rekeyPathPrefix(pin.path, oldPath, newPath)
		if !ok {
			continue
		}
		pin.path = moved
		moves = append(moves, move{owner: owner, pin: pin})
	}
	for _, move := range moves {
		owner := move.owner
		if owner.node == nil {
			delete(v.releasePins, owner)
			owner = openOwnerFor(move.pin.path, nil)
		}
		v.releasePins[owner] = move.pin
	}
}

func (v *Volume) evictRename(oldp, newp string) {
	v.invalidateRelatedInodes(v.hardlinks.inosForPaths(oldp, newp), "")
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
	if err := v.beginMutation(); err != nil {
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
	a, st, err := v.client.Symlink(target, path)
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
	if err := v.beginMutation(); err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer v.endMutation()

	if v.wb != nil {
		if err := v.wb.ReleaseFor(ctx, oldp, newp); err != nil {
			return fsproto.Attr{}, statusErr(err)
		}
	}
	if src != nil {
		src.mu.Lock()
		defer src.mu.Unlock()
	}
	a, st, err := v.client.Link(oldp, newp)
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	if a.Ino == 0 && src != nil && src.AuthIno() {
		a.Ino = src.StableIno()
	}
	v.observeHardlink(oldp, *a)
	v.observeHardlink(newp, *a)
	v.recent.record(oldp, newp)
	v.evictNamespacePaths(oldp, newp)
	return *a, fsproto.OK
}

func (v *Volume) Readlink(ctx context.Context, path string) (string, Status) {
	// An engine-covered path answers from the overlay: a just-created symlink
	// may not have flushed to the authority yet, so resolving there would
	// race the flusher.
	if v.wb != nil {
		if target, kind, ok := v.wb.Readlink(path); ok {
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
	t, st, err := v.client.Readlink(path)
	if err != nil {
		return "", fsproto.EIO
	}
	return t, st
}

func (v *Volume) Setattr(ctx context.Context, path string, n *NodeState, req SetattrRequest) (fsproto.Attr, Status) {
	if err := v.beginMutation(); err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	defer v.endMutation()

	if oi := n.Orphan(); oi != 0 {
		if req.SetSize {
			if st, err := v.client.TruncateOrphan(oi, req.Size); err != nil {
				return fsproto.Attr{}, fsproto.EIO
			} else if st != fsproto.OK {
				return fsproto.Attr{}, st
			}
		}
		return fsproto.Attr{}, fsproto.OK
	}
	if v.wb != nil && !v.isHardlink(n) {
		n.mu.Lock()
		if oi := n.orphanIno; oi != 0 {
			n.mu.Unlock()
			if req.SetSize {
				if st, err := v.client.TruncateOrphan(oi, req.Size); err != nil {
					return fsproto.Attr{}, fsproto.EIO
				} else if st != fsproto.OK {
					return fsproto.Attr{}, st
				}
			}
			return fsproto.Attr{}, fsproto.OK
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
		if handledAll && (req.SetMode || req.SetMTime || req.SetUID || req.SetGID) {
			engReq := writeback.SetattrRequest{
				SetMode: req.SetMode, Mode: modebits.CleanUnix(req.Mode),
				SetTime: req.SetMTime, MtimeMs: req.MtimeMs,
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
			// Nothing requested: report the current view.
			if ent, res := v.wb.Lookup(path); res == writeback.LookupHit {
				return engineAttr(path, ent), fsproto.OK
			}
		}
	}
	n.mu.Lock()
	if oi := n.orphanIno; oi != 0 {
		n.mu.Unlock()
		if req.SetSize {
			if st, err := v.client.TruncateOrphan(oi, req.Size); err != nil {
				return fsproto.Attr{}, fsproto.EIO
			} else if st != fsproto.OK {
				return fsproto.Attr{}, st
			}
		}
		return fsproto.Attr{}, fsproto.OK
	}
	handleIno := authHandleIno(n)
	if req.SetSize {
		st, err := v.client.TruncateHandle(path, handleIno, req.Size)
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
	if req.SetMode || req.SetMTime || req.SetUID || req.SetGID {
		st, err := v.client.SetattrHandle(path, handleIno, modebits.CleanUnix(req.Mode), req.SetMode, req.MtimeMs, req.SetMTime, req.UID, req.GID, req.SetUID, req.SetGID)
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
	a, st, err := v.client.GetattrHandle(path, handleIno)
	n.mu.Unlock()
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	v.observeHardlink(path, *a)
	if v.isHardlink(n) {
		v.invalidateRelatedInodes([]uint64{n.StableIno()}, path)
	}
	return *a, fsproto.OK
}

func authHandleIno(n *NodeState) uint64 {
	if n == nil || !n.AuthIno() {
		return 0
	}
	return n.StableIno()
}

func (v *Volume) FsyncPath(path string) Status {
	if err := v.Fsync(path); err != nil {
		return fsproto.EIO
	}
	return fsproto.OK
}

func (v *Volume) FsyncHandle(path string, n *NodeState) Status {
	if err := v.beginLifecycleOperation(); err != nil {
		return fsproto.EIO
	}
	defer v.endMutation()

	if err := v.fsync(path); err != nil {
		return fsproto.EIO
	}
	return fsproto.OK
}

func (v *Volume) Getlk(path string, owner, start, end uint64, write bool) (fsproto.LockResult, error) {
	return v.LockAuth().Lock(path, fsproto.LkGetlk, owner, start, end, write, false)
}

func (v *Volume) Setlk(ctx context.Context, h *LockHandle, path string, owner, start, end uint64, write, unlock bool) (fsproto.LockResult, error) {
	v.registerLockHandle(h)
	return SetLock(v.LockAuth(), h, path, owner, start, end, write, unlock)
}

func (v *Volume) Setlkw(ctx context.Context, h *LockHandle, path string, owner, start, end uint64, write bool) (fsproto.LockResult, error) {
	v.registerLockHandle(h)
	return WaitSetLock(ctx, v.LockAuth(), h, path, owner, start, end, write)
}
