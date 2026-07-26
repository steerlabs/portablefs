package clientcore

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/modebits"
	"github.com/trendup-ai/portablefs/vcs/internal/session"
)

func statusErr(err error) Status {
	if err == nil {
		return fsproto.OK
	}
	if errors.Is(err, session.ErrReleased) {
		return fsproto.EAGAIN
	}
	if errors.Is(err, os.ErrNotExist) {
		return fsproto.ENOENT
	}
	return fsproto.EIO
}

func (v *Volume) debug(format string, a ...any) {
	if v.debugf != nil {
		v.debugf(format, a...)
	}
}

func (v *Volume) CachedGetattr(path string) (fsproto.Attr, Status) {
	if v.sessions != nil {
		v.sessions.AwaitRelease(path)
	}
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

// RememberHardlinkAlias restores an already-proven alias binding from a
// frontend's durable item table. It is used when portablefsd restarts under a
// still-mounted FSKit volume, before the kernel necessarily issues a fresh
// getattr, so writes cannot accidentally enter the path-keyed write-back lane.
func (v *Volume) RememberHardlinkAlias(path string, ino uint64) {
	v.observeHardlink(path, fsproto.Attr{Ino: ino, Nlink: 2})
}

func (v *Volume) isHardlink(n *NodeState) bool {
	return n != nil && v.hardlinks.contains(n.StableIno())
}

func (v *Volume) Lookup(ctx context.Context, path string) (fsproto.Attr, Status) {
	if v.sessions != nil {
		if s := v.sessions.For(path); s != nil {
			if kind, mode, size, mtimeMs, uid, gid, ok := s.LocalStat(path); ok {
				if kind == "" {
					return fsproto.Attr{}, fsproto.ENOENT
				}
				return *sessAttr(kind, mode, size, mtimeMs, uid, gid), fsproto.OK
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
	if v.sessions != nil {
		if s := v.sessions.For(path); s != nil {
			if kind, mode, size, mtimeMs, uid, gid, ok := s.LocalStat(path); ok {
				if kind == "" {
					return fsproto.Attr{}, fsproto.ENOENT
				}
				return *sessAttr(kind, mode, size, mtimeMs, uid, gid), fsproto.OK
			}
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

// dirSession returns the write-back session that exclusively owns dir, if any. Such a directory's
// listing must never be served from (or stored into) the dirCache: the authority owner-suppresses
// self-write invalidations, so versions.m[dir] never advances for the mount's OWN create/remove, and
// a cached listing would hide the mount's just-created files until the session releases. This mirrors
// the attr-fill session gate in Readdir below.
func (v *Volume) dirSession(dir string) *session.Session {
	if v.sessions == nil {
		return nil
	}
	return v.sessions.For(dir)
}

func (v *Volume) Readdir(ctx context.Context, dir string) ([]DirEntry, Status) {
	held := v.dirSession(dir)
	if st, ok := localReaddirDirStatus(held, dir); ok {
		return nil, st
	}
	if gen, curVer := v.VersionCache.GenAndVersion(dir); gen != 0 && held == nil {
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
		if held == nil {
			return nil, st
		}
		if localSt, ok := localReaddirDirStatus(held, dir); ok {
			return nil, localSt
		}
		if kind, _, _, _, _, _, ok := held.LocalStat(dir); !ok {
			return nil, st
		} else if kind != "directory" {
			return nil, fsproto.ENOTDIR
		}
		ents = nil
		gen, dirVersion = 0, 0
	} else if st, ok := localReaddirDirStatus(held, dir); ok {
		return nil, st
	}
	if gen != 0 && !v.VersionCache.SeenGen(gen) {
		v.VersionCache.RefreshAll(gen)
	}
	fillCache := !v.noReaddirPlus && gen != 0 && held == nil
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
	if held != nil {
		out = mergeLocalReaddir(dir, out, held)
	}
	// Store the listing only when the directory is not session-held (same reason as the get gate):
	// a session-held dir's version never advances for our own writes, so a cache entry would go stale
	// invisibly. FillOK still records the version for coherence; only the dir listing is skipped.
	if gen != 0 && v.VersionCache.FillOK(gen, dir, dirVersion) && held == nil {
		v.dirMu.Lock()
		v.dirCache[dir] = dirCacheEntry{gen: gen, version: dirVersion, entries: append([]DirEntry(nil), out...)}
		v.dirMu.Unlock()
	}
	return out, fsproto.OK
}

func localReaddirDirStatus(held *session.Session, dir string) (Status, bool) {
	if held == nil {
		return 0, false
	}
	kind, _, _, _, _, _, ok := held.LocalStat(dir)
	if !ok {
		return 0, false
	}
	if kind == "" {
		return fsproto.ENOENT, true
	}
	if kind != "directory" {
		return fsproto.ENOTDIR, true
	}
	return 0, false
}

func mergeLocalReaddir(dir string, authority []DirEntry, held *session.Session) []DirEntry {
	present, deleted := held.LocalReaddir(dir)
	if len(present) == 0 && len(deleted) == 0 {
		return authority
	}
	deletedNames := make(map[string]struct{}, len(deleted))
	for _, name := range deleted {
		deletedNames[name] = struct{}{}
	}
	presentByName := make(map[string]session.LocalDirEntry, len(present))
	for _, e := range present {
		presentByName[e.Name] = e
	}
	out := make([]DirEntry, 0, len(authority)+len(present))
	usedOverlay := make(map[string]struct{}, len(present))
	for _, e := range authority {
		if _, deleted := deletedNames[e.Name]; deleted {
			continue
		}
		if local, ok := presentByName[e.Name]; ok {
			out = append(out, localDirEntry(dir, local))
			usedOverlay[e.Name] = struct{}{}
			continue
		}
		out = append(out, e)
	}
	for _, local := range present {
		if _, used := usedOverlay[local.Name]; used {
			continue
		}
		out = append(out, localDirEntry(dir, local))
	}
	// Session-held listings are sorted by name after merging. This is deterministic across calls
	// and gives portablefsd's name-based enumerate cookies a stable order even when overlay-only
	// children are appended to an authority listing.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func localDirEntry(dir string, e session.LocalDirEntry) DirEntry {
	cp := e.Name
	if dir != "" {
		cp = dir + "/" + e.Name
	}
	attr := *sessAttr(e.Kind, e.Mode, e.Size, e.MtimeMs, e.UID, e.GID)
	return DirEntry{Name: e.Name, Attr: attr, Ino: InoOf(cp)}
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

// evictDirCachePrefix drops the listing for rp and every directory under it. Used on session
// release/acquire so a listing cached while a subtree was (or was about to become) exclusively held
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
		if k == rp || strings.HasPrefix(k, pfx) {
			delete(v.dirCache, k)
		}
	}
}

func (v *Volume) Open(ctx context.Context, path string, n *NodeState, writeIntent bool) Status {
	if v.sessions != nil && writeIntent && v.sessions.For(path) == nil && v.onFlushAll != nil {
		dir, _ := splitPath(path)
		go v.onFlushAll(dir)
	}
	v.opens.Inc(path)
	if v.incOpen(path, n) {
		v.opens.Dec(path)
		return fsproto.ENOENT
	}
	return fsproto.OK
}

func (v *Volume) RegisterOpened(path string, n *NodeState) Status {
	v.opens.Inc(path)
	if v.incOpen(path, n) {
		v.opens.Dec(path)
		return fsproto.ENOENT
	}
	return fsproto.OK
}

// incOpen counts one open handle on n and registers the inode's open hold at
// the authority through the open registry (openreg.go): only the FIRST open
// of an unregistered inode round-trips; concurrent opens join that in-flight
// registration, and re-opens of a registered (live or retained) inode cost
// nothing. gone == true means the inode was already destroyed by a peer
// unlink that won the race — the caller fails the open with ENOENT, exactly
// as when every open sent its own MarkOpen.
func (v *Volume) incOpen(path string, n *NodeState) (gone bool) {
	if n == nil {
		return false
	}
	n.mu.Lock()
	n.nopen++
	n.mu.Unlock()
	if ino := n.StableIno(); ino != 0 && n.AuthIno() {
		if v.openReg.Open(path, ino) == fsproto.ENOENT {
			n.mu.Lock()
			n.nopen--
			n.mu.Unlock()
			return true
		}
	}
	return false
}

func (v *Volume) CloseHandle(path string, n *NodeState) {
	v.opens.Dec(path)
	v.closeOne(path, n)
}

func (v *Volume) closeOne(path string, n *NodeState) {
	if n == nil {
		return
	}
	var ino uint64
	n.mu.Lock()
	if n.nopen > 0 {
		n.nopen--
	}
	lastClose := n.nopen == 0
	if lastClose && n.orphanIno != 0 {
		ino = n.orphanIno
		n.orphanIno = 0
	}
	n.mu.Unlock()
	if ino != 0 {
		v.openOrphans.Remove(ino)
	}
	if lastClose {
		if fino := n.StableIno(); fino != 0 && n.AuthIno() {
			// An orphaned inode's registration is discarded (no name can
			// resolve to it again); a live one is retained for RPC-free
			// re-opens, with its unmark deferred to a batch.
			v.openReg.Close(path, fino, ino != 0)
		}
	}
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
	if v.sessions != nil && !v.isHardlink(n) {
		if s := v.sessions.For(path); s != nil {
			data, ok, err := s.Read(path, off, int64(length))
			if err != nil {
				v.debug("Read session %q off=%d: %v", path, off, err)
				return nil, fsproto.EIO
			}
			if ok {
				return data, fsproto.OK
			}
		}
		v.sessions.AwaitRelease(path)
	}
	handleIno := authHandleIno(n)
	if v.DiskCache != nil && handleIno != 0 {
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
	if v.DiskCache != nil && handleIno != 0 {
		v.DiskCache.PutRange(v.volumeID, gen, handleIno, off, version, data, length)
	}
	return data, fsproto.OK
}

func (v *Volume) Write(ctx context.Context, path string, n *NodeState, off int64, data []byte) (int, Status) {
	if oi := n.Orphan(); oi != 0 {
		cnt, st, err := v.client.WriteOrphan(oi, off, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	if v.sessions != nil && !v.isHardlink(n) {
		for attempt := 0; attempt < 3; attempt++ {
			s, err := v.sessions.EnsureContext(ctx, path)
			if err != nil {
				var busy *session.BusyError
				if errors.As(err, &busy) {
					return 0, fsproto.EAGAIN
				}
				v.debug("Write Ensure %q: %v", path, err)
				return 0, fsproto.EIO
			}
			n.mu.Lock()
			if oi := n.orphanIno; oi != 0 {
				n.mu.Unlock()
				cnt, st, werr := v.client.WriteOrphan(oi, off, data)
				if werr != nil {
					return 0, fsproto.EIO
				}
				return cnt, st
			}
			nw, werr := s.Write(path, off, data)
			n.mu.Unlock()
			if errors.Is(werr, session.ErrReleased) {
				continue
			}
			if errors.Is(werr, session.ErrOrphaned) {
				return v.rerouteOrphanedWrite(n, off, data)
			}
			if werr != nil {
				v.debug("Write s.Write %q off=%d: %v", path, off, werr)
				return 0, fsproto.EIO
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, true)
			return nw, fsproto.OK
		}
		return 0, fsproto.EAGAIN
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

// WriteAppend executes O_APPEND as one authority mutation. The kernel-supplied
// offset is used only for compatibility with an older authority that did not
// advertise FeatAtomicAppend; current authorities choose EOF in sequencer
// order. A write-back checkout records append intent in its durable local
// flush log, retaining the existing batched/local-latency fast path; its
// exclusive subtree grant keeps the local overlay's EOF coherent until flush.
func (v *Volume) WriteAppend(ctx context.Context, path string, n *NodeState, legacyOff int64, data []byte) (int, Status) {
	if !v.client.SupportsAtomicAppend() {
		return v.Write(ctx, path, n, legacyOff, data)
	}
	if oi := n.Orphan(); oi != 0 {
		cnt, _, st, err := v.client.AppendOrphan(oi, data)
		if err != nil {
			return 0, fsproto.EIO
		}
		return cnt, st
	}
	if v.sessions != nil && !v.isHardlink(n) {
		for attempt := 0; attempt < 3; attempt++ {
			s, err := v.sessions.EnsureContext(ctx, path)
			if err != nil {
				var busy *session.BusyError
				if errors.As(err, &busy) {
					return 0, fsproto.EAGAIN
				}
				v.debug("WriteAppend Ensure %q: %v", path, err)
				return 0, fsproto.EIO
			}
			n.mu.Lock()
			if oi := n.orphanIno; oi != 0 {
				n.mu.Unlock()
				cnt, _, st, werr := v.client.AppendOrphan(oi, data)
				if werr != nil {
					return 0, fsproto.EIO
				}
				return cnt, st
			}
			nw, werr := s.WriteAppend(path, data)
			n.mu.Unlock()
			if errors.Is(werr, session.ErrReleased) {
				continue
			}
			if errors.Is(werr, session.ErrOrphaned) {
				return v.rerouteOrphanedAppend(n, data)
			}
			if werr != nil {
				v.debug("WriteAppend s.WriteAppend %q: %v", path, werr)
				return 0, fsproto.EIO
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, true)
			return nw, fsproto.OK
		}
		return 0, fsproto.EAGAIN
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

func (v *Volume) rerouteOrphanedAppend(n *NodeState, data []byte) (int, Status) {
	oi := n.Orphan()
	if oi == 0 {
		oi = v.RedirectToOrphan(n)
	}
	if oi == 0 {
		return 0, fsproto.EIO
	}
	cnt, _, st, err := v.client.AppendOrphan(oi, data)
	if err != nil {
		return 0, fsproto.EIO
	}
	return cnt, st
}

// rerouteOrphanedWrite handles a write whose session write was rejected with ErrOrphaned (the path
// was orphaned-while-open and sealed). P3: prefer this node's PARKED orphanIno directly — the
// concurrent unlink set it under n.mu, so reading it here synchronizes with that park and gives the
// authoritative target. Only if it is somehow unset do we fall back to the RedirectToOrphan probe
// (which re-derives via the node's STABLE ino), then fail safe rather than resurrect the deleted name.
// Probing RedirectToOrphan FIRST (the pre-restore behavior) EIOs on an uncommitted write-back file:
// its stable ino is a path-hash the authority can't resolve as an orphan, so the probe misses where
// the parked ino would have worked.
func (v *Volume) rerouteOrphanedWrite(n *NodeState, off int64, data []byte) (int, Status) {
	oi := n.Orphan()
	if oi == 0 {
		oi = v.RedirectToOrphan(n)
	}
	if oi == 0 {
		return 0, fsproto.EIO
	}
	cnt, st, err := v.client.WriteOrphan(oi, off, data)
	if err != nil {
		return 0, fsproto.EIO
	}
	return cnt, st
}

func (v *Volume) Create(ctx context.Context, path string, mode uint32) (fsproto.Attr, Status) {
	return v.createCommon(ctx, path, mode, false)
}

// CreateExcl is Create with O_EXCL semantics enforced at the strongest layer
// the deployment offers. Against a managed authority the exclusivity decision
// is made atomically inside the ordered journal (wire Excl) — two machines
// cannot both win the create — while a legacy authority ignores the wire flag
// and a write-back mount decides against its local overlay, both of which
// degrade to the classic lookup-then-create pre-check these callers used to
// inline (racy across machines, exactly as before).
func (v *Volume) CreateExcl(ctx context.Context, path string, mode uint32) (fsproto.Attr, Status) {
	return v.createCommon(ctx, path, mode, true)
}

func (v *Volume) createCommon(ctx context.Context, path string, mode uint32, excl bool) (fsproto.Attr, Status) {
	mode = modebits.CleanUnix(mode)
	if v.sessions != nil {
		if excl {
			if _, st := v.Lookup(ctx, path); st == fsproto.OK {
				return fsproto.Attr{}, fsproto.EEXIST
			}
		}
		for attempt := 0; attempt < 3; attempt++ {
			s, err := v.sessions.EnsureContext(ctx, path)
			if err != nil {
				var busy *session.BusyError
				if errors.As(err, &busy) {
					return fsproto.Attr{}, fsproto.EAGAIN
				}
				return fsproto.Attr{}, fsproto.EIO
			}
			if err := s.Create(path, mode); err != nil {
				if errors.Is(err, session.ErrReleased) {
					continue
				}
				return fsproto.Attr{}, fsproto.EIO
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, false)
			_, _, sz, _, _, _, _ := s.LocalStat(path)
			now := time.Now().UnixMilli()
			return fsproto.Attr{Kind: "file", Mode: mode, Size: sz, MtimeMs: now, CtimeMs: now, AtimeMs: now}, fsproto.OK
		}
		return fsproto.Attr{}, fsproto.EAGAIN
	}
	if excl && !v.client.ServerManaged() {
		// The legacy wire ignores Excl; pre-check like the callers always did.
		if _, st := v.Lookup(ctx, path); st == fsproto.OK {
			return fsproto.Attr{}, fsproto.EEXIST
		}
	}
	a, st := v.createWriteThrough(path, mode, excl && v.client.ServerManaged())
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
// when the authority supports it the open registration rides the create RPC
// itself (RegisterOpen): the hold is applied before the create returns — the
// open-vs-unlink decision point is unchanged — and the follow-up
// RegisterOpened becomes a zero-RPC registry hit on the seeded hold. ENOENT
// from the fused form means a peer unlinked the just-created name inside the
// registration window; the caller surfaces it exactly like the two-RPC flow
// (create OK, MarkOpen ENOENT) did.
func (v *Volume) createWriteThrough(path string, mode uint32, excl bool) (fsproto.Attr, Status) {
	if v.openReg.FusedCreate() {
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
	var a *fsproto.Attr
	var st int32
	var err error
	if excl {
		a, st, err = v.client.CreateExcl(path, mode)
	} else {
		a, st, err = v.client.Create(path, mode)
	}
	if err != nil {
		return fsproto.Attr{}, fsproto.EIO
	}
	if st != fsproto.OK {
		return fsproto.Attr{}, st
	}
	return *a, fsproto.OK
}

func (v *Volume) Mkdir(ctx context.Context, path string, mode uint32) (fsproto.Attr, Status) {
	mode = modebits.CleanUnix(mode)
	if v.sessions != nil {
		for attempt := 0; attempt < 3; attempt++ {
			s, err := v.sessions.EnsureContext(ctx, path)
			if err != nil {
				var busy *session.BusyError
				if errors.As(err, &busy) {
					return fsproto.Attr{}, fsproto.EAGAIN
				}
				return fsproto.Attr{}, fsproto.EIO
			}
			if err := s.Mkdir(path, mode); err != nil {
				if errors.Is(err, session.ErrReleased) {
					continue
				}
				return fsproto.Attr{}, statusErr(err)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, false)
			now := time.Now().UnixMilli()
			return fsproto.Attr{Kind: "directory", Mode: mode, MtimeMs: now, CtimeMs: now, AtimeMs: now, Nlink: 2}, fsproto.OK
		}
		return fsproto.Attr{}, fsproto.EAGAIN
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
	// A remove's park-vs-destroy decision at the authority reads OUR open
	// holds too: release any zero-ref retained registration on the target
	// first (synchronously — the op-order dependency deferred unmarks have),
	// or this mount's own remove of a recently-closed file would spuriously
	// park the inode until lease GC. Live handles are untouched; the open
	// paths below own those.
	v.openReg.ReleaseNameChange(path, authHandleIno(child))
	if v.sessions != nil && !v.isHardlink(child) {
		for attempt := 0; attempt < 3; attempt++ {
			s, err := v.sessions.EnsureContext(ctx, path)
			if err != nil {
				var busy *session.BusyError
				if errors.As(err, &busy) {
					return fsproto.EAGAIN
				}
				return fsproto.EIO
			}
			if child != nil {
				child.mu.Lock()
				if child.nopen > 0 && child.orphanIno == 0 {
					if err := s.Materialize(path); err != nil {
						child.mu.Unlock()
						if errors.Is(err, session.ErrReleased) {
							continue
						}
						return statusErr(err)
					}
					ino, st, err := v.client.Orphan(path)
					if err != nil {
						s.Unseal(path)
						child.mu.Unlock()
						return fsproto.EIO
					}
					if st == fsproto.OK {
						s.Forget(path)
						child.markOrphanLocked(ino, v.openOrphans)
						v.recent.record(path)
						v.AttrCache.Evict(path)
						dir, _ := splitPath(path)
						v.AttrCache.Evict(dir)
						v.evictDirCache(dir)
					} else {
						s.Unseal(path)
					}
					child.mu.Unlock()
					return st
				}
				child.mu.Unlock()
			}
			if err := s.Remove(path); err != nil {
				if errors.Is(err, session.ErrReleased) {
					continue
				}
				return statusErr(err)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, false)
			return fsproto.OK
		}
		return fsproto.EAGAIN
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
	// Rename-over reads OUR open holds on the replaced destination the same
	// way remove does: release any zero-ref retained registration on newp
	// first, so replacing a recently-closed file destroys it (as it always
	// did) instead of spuriously parking it against our stale hold. An OPEN
	// destination takes the explicit orphan-target arm below, untouched.
	v.openReg.ReleaseNameChange(newp, authHandleIno(dst))
	if v.sessions != nil && !v.isHardlink(src) && !v.isHardlink(dst) {
		so, sn := v.sessions.For(oldp), v.sessions.For(newp)
		if so != nil || sn != nil {
			if so != sn {
				// The two names live under different write-back roots — with
				// file-grain roots on managed authorities this is the everyday
				// atomic-write pattern at the volume root (tmp -> final) — so no
				// single session can journal the rename. Make both sides durable,
				// then let the authority rename atomically write-through; each
				// session forgets its half so later reads see the moved name.
				// (EXDEV here would break rename(2) callers that never fall back
				// to copy+delete.)
				if so != nil {
					if err := so.Flush(); err != nil {
						return fsproto.EIO
					}
				}
				if sn != nil {
					if err := sn.Flush(); err != nil {
						return fsproto.EIO
					}
				}
				st := v.renameWriteThrough(oldp, newp, src, dst)
				if st == fsproto.OK {
					if so != nil {
						so.Forget(oldp)
					}
					if sn != nil {
						sn.Forget(newp)
					}
				}
				return st
			}
			if dst != nil {
				lockTwo(src, dst)
				if dst.nopen > 0 && dst.orphanIno == 0 {
					if err := so.Flush(); err != nil {
						unlockTwo(src, dst)
						return fsproto.EIO
					}
					st, orphanIno, err := v.client.RenameWithOrphanTarget(oldp, newp, true)
					if err != nil {
						unlockTwo(src, dst)
						return fsproto.EIO
					}
					if st == fsproto.OK {
						so.Forget(oldp)
						so.Forget(newp)
						dst.markOrphanLocked(orphanIno, v.openOrphans)
						v.recent.record(oldp, newp)
						v.evictRename(oldp, newp)
						v.openReg.NotePathMoved(oldp, newp)
					}
					unlockTwo(src, dst)
					return st
				}
				unlockTwo(src, dst)
			}
			if err := so.Rename(oldp, newp); err != nil {
				return statusErr(err)
			}
			v.recent.record(oldp, newp)
			v.evictRename(oldp, newp)
			v.openReg.NotePathMoved(oldp, newp)
			return fsproto.OK
		}
	}
	return v.renameWriteThrough(oldp, newp, src, dst)
}

// renameWriteThrough performs the authority-side rename with the
// open-destination orphan protocol and full cache/registry bookkeeping. It is
// the terminal arm of Rename on write-through volumes and the atomic execution
// step for renames that cross write-back session roots (both sides flushed by
// the caller first).
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
				v.openReg.NotePathMoved(oldp, newp)
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
		v.openReg.NotePathMoved(oldp, newp)
	}
	v.recent.record(oldp, newp)
	return st
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
	if v.sessions != nil {
		if s := v.sessions.For(path); s != nil {
			if err := s.Symlink(path, target); err != nil {
				return fsproto.Attr{}, statusErr(err)
			}
			v.recent.record(path)
			v.noteSelfMutation(path, 0, 0, false)
			now := time.Now().UnixMilli()
			return fsproto.Attr{Kind: "symlink", Mode: 0o777, Size: int64(len(target)), MtimeMs: now, CtimeMs: now, AtimeMs: now}, fsproto.OK
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

// SupportsHardLinks reports whether this attachment negotiated the atomic
// authority hard-link surface.
func (v *Volume) SupportsHardLinks() bool { return v.client.SupportsHardLinks() }

// Link creates newp as another name for oldp's inode. Hard links use the
// ordered write-through lane even on --fast mounts: the general write-back
// overlay is path-keyed, while one hard-linked inode may span checkout roots.
// Flushing the source/destination sessions first preserves their acknowledged
// bytes, and marking the stable inode keeps all later alias mutations coherent.
func (v *Volume) Link(ctx context.Context, oldp, newp string, src *NodeState) (fsproto.Attr, Status) {
	if !v.SupportsHardLinks() {
		return fsproto.Attr{}, fsproto.EOPNOTSUPP
	}
	if src != nil {
		src.mu.Lock()
		defer src.mu.Unlock()
	}
	if v.sessions != nil {
		seen := map[*session.Session]struct{}{}
		for _, s := range []*session.Session{v.sessions.For(oldp), v.sessions.For(newp)} {
			if s == nil {
				continue
			}
			if _, ok := seen[s]; !ok {
				if err := s.Flush(); err != nil {
					return fsproto.Attr{}, statusErr(err)
				}
				seen[s] = struct{}{}
			}
			s.Forget(oldp)
			s.Forget(newp)
		}
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
	// A session-covered path answers from the overlay: a just-created symlink may not have
	// flushed to the authority yet, so resolving there would race the flusher (observed as
	// ENOENT for ~one flush interval on write-back mounts). Mirrors LocalStat's routing.
	if v.sessions != nil {
		if s := v.sessions.For(path); s != nil {
			if target, kind, ok := s.LocalReadlink(path); ok {
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
	}
	t, st, err := v.client.Readlink(path)
	if err != nil {
		return "", fsproto.EIO
	}
	return t, st
}

func (v *Volume) Setattr(ctx context.Context, path string, n *NodeState, req SetattrRequest) (fsproto.Attr, Status) {
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
	if v.sessions != nil && !v.isHardlink(n) {
		if s := v.sessions.For(path); s != nil {
			n.mu.Lock()
			mutated := false
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
			if req.SetSize {
				if err := s.Truncate(path, req.Size); err != nil {
					n.mu.Unlock()
					return fsproto.Attr{}, statusErr(err)
				}
				v.recent.record(path)
				mutated = true
			}
			if req.SetMode {
				if err := s.Chmod(path, modebits.CleanUnix(req.Mode)); err != nil {
					n.mu.Unlock()
					return fsproto.Attr{}, statusErr(err)
				}
				v.recent.record(path)
				mutated = true
			}
			if req.SetMTime {
				if err := s.Chtimes(path, req.MtimeMs); err != nil {
					n.mu.Unlock()
					return fsproto.Attr{}, statusErr(err)
				}
				v.recent.record(path)
				mutated = true
			}
			if req.SetUID || req.SetGID {
				uid, gid := req.UID, req.GID
				if !req.SetUID || !req.SetGID {
					a, st, err := v.client.Getattr(path)
					if err != nil || st != fsproto.OK {
						n.mu.Unlock()
						return fsproto.Attr{}, fsproto.EIO
					}
					if !req.SetUID {
						uid = a.Uid
					}
					if !req.SetGID {
						gid = a.Gid
					}
				}
				if err := s.Chown(path, uid, gid); err != nil {
					n.mu.Unlock()
					return fsproto.Attr{}, statusErr(err)
				}
				v.recent.record(path)
				mutated = true
			}
			if mutated {
				v.noteSelfMutation(path, 0, 0, true)
			}
			if kind, mode, size, mtimeMs, uid, gid, ok := s.LocalStat(path); ok && kind != "" {
				a := sessAttr(kind, mode, size, mtimeMs, uid, gid)
				n.mu.Unlock()
				return *a, fsproto.OK
			}
			n.mu.Unlock()
			if a, st, err := v.client.Getattr(path); err == nil && st == fsproto.OK {
				return *a, fsproto.OK
			}
			return fsproto.Attr{}, fsproto.OK
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
