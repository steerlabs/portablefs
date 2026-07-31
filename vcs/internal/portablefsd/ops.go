package portablefsd

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"sort"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

const (
	enumerateCookieMarker  = uint64(1) << 63
	enumerateCookieIDBits  = 31
	enumerateCookiePosBits = 30
	// Cookies are [marker:1][enumID:31][position:30][reserved:2]. The daemon emits only reserved=0.
	enumerateCookieReservedMask = uint64(0x3)
	enumerateCookieMaxID        = (uint64(1) << enumerateCookieIDBits) - 1
	enumerateCookieMaxPos       = (uint64(1) << enumerateCookiePosBits) - 1
	maxLiveEnumerations         = 64
	enumerationTTL              = 5 * time.Minute
)

func fsAttrToLocal(a fsproto.Attr, item pfslocal.Item, parent *pfslocal.Item) pfslocal.Attr {
	return fsAttrToLocalNlink(a, item, parent, false)
}

func fsAttrToLocalNlink(
	a fsproto.Attr,
	item pfslocal.Item,
	parent *pfslocal.Item,
	preserveZero bool,
) pfslocal.Attr {
	kind := pfslocal.ItemKindFile
	switch a.Kind {
	case "directory":
		kind = pfslocal.ItemKindDirectory
	case "symlink":
		kind = pfslocal.ItemKindSymlink
	}
	nlink := a.Nlink
	if nlink == 0 && !preserveZero {
		nlink = 1
	}
	var parentCopy *pfslocal.Item
	if parent != nil {
		value := *parent
		parentCopy = &value
	}
	return pfslocal.Attr{
		Item: item, Kind: kind, Mode: a.Mode, Nlink: nlink, UID: a.Uid, GID: a.Gid,
		Size: uint64(max64(a.Size, 0)), MtimeMs: a.MtimeMs, CtimeMs: a.CtimeMs, AtimeMs: a.AtimeMs,
		BirthtimeMs: a.BirthtimeMs, ContentVersion: 0, Parent: parentCopy, Flags: a.Flags,
		AllocSize: uint64(max64(a.AllocSize, 0)),
	}
}

// parentItemLocked returns the frontend identity of the concrete live parent
// binding for p. The root and retained-but-unlinked Items intentionally have no
// protocol parent; FSKit maps those states to parent-of-root and invalid.
func (a *attach) parentItemLocked(p string) *pfslocal.Item {
	if p == "" {
		return nil
	}
	parent := a.paths[parentPath(p)]
	if parent == nil {
		return nil
	}
	item := parent.item
	return &item
}

func (a *attach) localAttrForRecordLocked(
	attr fsproto.Attr,
	rec *itemRecord,
	detached bool,
) pfslocal.Attr {
	return a.localAttrForRecordPathLocked(attr, rec, rec.path, detached)
}

// authorityAttrDefaults fills the POSIX fields the authority's metadata model
// does not carry. PortableFS charges logical stored bytes, so an absent
// allocation IS the file's size — sparse allocation is not a concept the
// authority represents, and reporting zero makes st_blocks (and du) claim the
// file occupies nothing. An absent birth time reports mtime, the convention
// network filesystems use for an unknown creation time; epoch 0 would show up
// in Finder as 1 Jan 1970. Machine-local grafts stat real backing files and
// are never normalized here: their zeros are measurements, not omissions.
func authorityAttrDefaults(a fsproto.Attr) fsproto.Attr {
	if a.AllocSize == 0 && a.Size > 0 {
		a.AllocSize = a.Size
	}
	if a.BirthtimeMs == 0 {
		a.BirthtimeMs = a.MtimeMs
	}
	return a
}

func (a *attach) localAttrForRecordPathLocked(
	attr fsproto.Attr,
	rec *itemRecord,
	scope string,
	detached bool,
) pfslocal.Attr {
	var parent *pfslocal.Item
	if !detached {
		if scope == "" {
			scope = rec.path
		}
		parent = a.parentItemLocked(scope)
	}
	if !rec.graft {
		attr = authorityAttrDefaults(attr)
	}
	return fsAttrToLocalNlink(attr, rec.item, parent, detached)
}

func (a *attach) localAttrForRecord(
	attr fsproto.Attr,
	rec *itemRecord,
	detached bool,
) pfslocal.Attr {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.localAttrForRecordLocked(attr, rec, detached)
}

func (a *attach) localAttrForRecordPath(
	attr fsproto.Attr,
	rec *itemRecord,
	scope string,
	detached bool,
) pfslocal.Attr {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.localAttrForRecordPathLocked(attr, rec, scope, detached)
}

func (a *attach) rootReply(ctx context.Context) (pfslocal.ResolveReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	changed := false
	a.mu.RLock()
	if a.detached || a.detachPrepared || a.detachForce {
		a.mu.RUnlock()
		return pfslocal.ResolveReply{}, darwinENXIO
	}
	root := a.root
	vol := a.vol
	a.mu.RUnlock()
	if root == nil {
		if vol == nil {
			a.mu.Lock()
			root = a.root
			if root == nil {
				root = a.registerLocked("", syntheticRootAttr())
				if root == nil {
					a.mu.Unlock()
					return pfslocal.ResolveReply{}, darwinEIO
				}
				changed = true
			}
			a.mu.Unlock()
		}
	}
	if root == nil {
		attr, st := vol.Getattr(ctx, "", clientcore.NewNodeState(1, true))
		if st != fsproto.OK {
			return pfslocal.ResolveReply{}, toDarwinErr(st)
		}
		a.mu.Lock()
		root = a.registerLocked("", attr)
		if root == nil {
			a.mu.Unlock()
			return pfslocal.ResolveReply{}, darwinEIO
		}
		changed = true
		a.mu.Unlock()
	}
	if changed {
		if eno := a.persistStateOrEIO("resolve root identity"); eno != 0 {
			return pfslocal.ResolveReply{}, eno
		}
	}
	// Xattrs is a PER-ATTACH capability: true exactly when the attached
	// authority serves xattrs natively (baseline in v5) —
	// never hardcoded, so an attach to an older authority keeps the frontend
	// on its fallback behavior (AppleDouble sidecars) while a native-capable
	// attach serves xattrs first-class.
	return pfslocal.ResolveReply{
		Root: root.item, RootAttr: a.localAttrForRecord(root.attr, root, false),
		VolumeID: a.volumeID, Branch: a.branch, VolumeName: a.volumeName,
		Capabilities: pfslocal.Capabilities{
			Symlinks: true, HardLinks: true, Xattrs: true, CaseSensitive: true,
			MaxNameBytes: 255, PreferredIOSize: 1 << 20,
		},
	}, 0
}

func (a *attach) lookup(ctx context.Context, req *pfslocal.LookupRequest) (*pfslocal.LookupReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	dir, eno := a.item(req.Dir)
	if eno != 0 {
		return nil, eno
	}
	p, eno := cleanChild(dir.path, req.Name)
	if eno != 0 {
		return nil, eno
	}
	if graft := a.localDirFor(p); graft != "" {
		attr, eno := a.statLocal(p)
		if eno != 0 {
			return nil, eno
		}
		rec := a.registerLocal(p, attr)
		if eno := a.flushBindingDelta(); eno != 0 {
			return nil, eno
		}
		return &pfslocal.LookupReply{Attr: a.localAttrForRecord(attr, rec, false)}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	attr, st := vol.Lookup(ctx, p)
	if a.testLookupAfterVolume != nil {
		a.testLookupAfterVolume(p)
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	rec := a.registerLocked(p, attr)
	a.mu.Unlock()
	if rec == nil {
		return nil, darwinEIO
	}
	if eno := a.flushBindingDelta(); eno != 0 {
		return nil, eno
	}
	return &pfslocal.LookupReply{Attr: a.localAttrForRecord(attr, rec, false)}, 0
}

func (a *attach) enumerate(ctx context.Context, req *pfslocal.EnumerateRequest) (*pfslocal.EnumerateReply, int32) {
	// Enumeration cookies are daemon-opaque continuation tokens. Issued cookies always have the
	// high bit set and low reserved bits clear; frontend adapters must pass them back unchanged.
	// Cookie 0 starts a fresh snapshot and terminal replies use next_cookie=0. Unknown, expired,
	// low-bit/sentinel, or otherwise malformed nonzero cookies return ESTALE so the frontend can
	// discard its cursor and restart from 0.
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	dir, eno := a.item(req.Dir)
	if eno != 0 {
		return nil, eno
	}
	limit := int(req.MaxEntries)
	if req.Cookie == 0 {
		ents, dirVersion, eno := a.freshDirListing(ctx, dir.path)
		if eno != 0 {
			return nil, eno
		}
		sort.SliceStable(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })
		rep, eno := a.enumerateFreshLocked(dir.path, ents, dirVersion, limit)
		if eno != 0 {
			return nil, eno
		}
		if rep != nil && len(rep.Entries) > 0 {
			if eno := a.flushBindingDelta(); eno != 0 {
				return nil, eno
			}
		}
		return rep, 0
	}

	rep, eno := a.enumerateResumeLocked(dir.path, req.Cookie, limit)
	if eno != 0 {
		return nil, eno
	}
	if rep != nil && len(rep.Entries) > 0 {
		if eno := a.flushBindingDelta(); eno != 0 {
			return nil, eno
		}
	}
	return rep, 0
}

// freshDirListing produces the entries and version for a cookie-0 enumeration.
// Grafted directories list from machine-local backing, graft parents merge the
// authority listing with graft roots (grafts shadow same-named volume
// entries), and everything else is a plain authority readdir.
func (a *attach) freshDirListing(ctx context.Context, dir string) ([]clientcore.DirEntry, uint64, int32) {
	if graft := a.localDirFor(dir); graft != "" {
		ents, eno := a.readLocalDir(dir)
		if eno != 0 {
			return nil, 0, eno
		}
		a.mu.RLock()
		version := a.localVersionLocked(dir)
		a.mu.RUnlock()
		return ents, version, 0
	}

	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, 0, eno
	}
	ents, st := vol.Readdir(ctx, dir)
	if st != fsproto.OK {
		return nil, 0, toDarwinErr(st)
	}
	_, dirVersion := vol.VersionCache.GenAndVersion(dir)

	graftRoots := a.graftRootsUnder(dir)
	if len(graftRoots) == 0 {
		return ents, dirVersion, 0
	}
	// A graft root appearing or vanishing changes this listing without any
	// authority-side change, so the enumeration verifier must see the merged
	// version (authority + local overlay counter), the same version namespace
	// invalidations publish.
	a.mu.RLock()
	dirVersion = a.mergedDirVersionLocked(dir)
	a.mu.RUnlock()
	shadowed := map[string]bool{}
	for _, root := range graftRoots {
		shadowed[path.Base(root)] = true
	}
	merged := make([]clientcore.DirEntry, 0, len(ents)+len(graftRoots))
	for _, e := range ents {
		if !shadowed[e.Name] {
			merged = append(merged, e)
		}
	}
	for _, root := range graftRoots {
		attr, eno := a.statLocal(root)
		if eno == darwinENOENT {
			// The rule owns the name but nothing has created the directory
			// yet; it is simply absent (no phantom entries).
			continue
		}
		if eno != 0 {
			return nil, 0, eno
		}
		merged = append(merged, clientcore.DirEntry{Name: path.Base(root), Attr: attr})
	}
	return merged, dirVersion, 0
}

func (a *attach) enumerateFreshLocked(dir string, ents []clientcore.DirEntry, dirVersion uint64, limit int) (*pfslocal.EnumerateReply, int32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.pruneEnumerationsLocked(now)
	if len(ents) <= 1 {
		return a.enumeratePageLocked(nil, dir, 0, ents, dirVersion, limit)
	}
	rec, err := a.newEnumerationRecordLocked(dir, ents, dirVersion, now)
	if err != nil {
		return nil, darwinEIO
	}
	return a.enumeratePageLocked(rec, rec.dir, 0, rec.entries, rec.dirVersion, limit)
}

func (a *attach) enumerateResumeLocked(dir string, cookie uint64, limit int) (*pfslocal.EnumerateReply, int32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.pruneEnumerationsLocked(now)
	if cookie&enumerateCookieMarker == 0 {
		return nil, darwinESTALE
	}
	enumID, pos, ok := decodeEnumerationCookie(cookie)
	if !ok {
		return nil, darwinESTALE
	}
	rec := a.enumRecords[enumID]
	if rec == nil || rec.dir != dir || pos < 0 || pos > len(rec.entries) {
		// Continuation cookies are self-describing high-bit tokens issued by this daemon.
		// Low-bit frontend sentinels, expired/LRU-evicted tokens, and tokens from a pre-restart
		// daemon are stale. Return ESTALE so the frontend restarts from 0.
		return nil, darwinESTALE
	}
	rec.lastUsed = now
	return a.enumeratePageLocked(rec, rec.dir, pos, rec.entries, rec.dirVersion, limit)
}

func (a *attach) enumeratePageLocked(enumRec *enumerationRecord, dir string, start int, ents []clientcore.DirEntry, dirVersion uint64, limit int) (*pfslocal.EnumerateReply, int32) {
	if start > len(ents) {
		start = len(ents)
	}
	if limit <= 0 || start+limit > len(ents) {
		limit = len(ents) - start
	}
	out := make([]pfslocal.DirEntry, 0, limit)
	for i := start; i < start+limit; i++ {
		e := ents[i]
		p := e.Name
		if dir != "" {
			p = dir + "/" + e.Name
		}
		var rec *itemRecord
		if a.localDirForLocked(p) != "" {
			// Grafted entries carry no authority inode; mint daemon-local
			// identity instead of the recyclable path-hash fallback.
			rec = a.registerLocalLocked(p, e.Attr)
		} else {
			rec = a.registerLocked(p, e.Attr)
		}
		if rec == nil {
			return nil, darwinEIO
		}
		cookie := uint64(0)
		if enumRec != nil && i < len(ents)-1 {
			var ok bool
			cookie, ok = encodeEnumerationCookie(enumRec.id, i+1)
			if !ok {
				return nil, darwinEIO
			}
		}
		out = append(out, pfslocal.DirEntry{
			Name:   []byte(e.Name),
			Attr:   a.localAttrForRecordLocked(e.Attr, rec, false),
			Cookie: cookie,
		})
	}
	next := uint64(0)
	if len(out) > 0 {
		next = out[len(out)-1].Cookie
	}
	if next == 0 && enumRec != nil {
		a.dropEnumerationLocked(enumRec.id)
	}
	return &pfslocal.EnumerateReply{Entries: out, NextCookie: next, DirVersion: dirVersion}, 0
}

func (a *attach) newEnumerationRecordLocked(dir string, ents []clientcore.DirEntry, dirVersion uint64, now time.Time) (*enumerationRecord, error) {
	for len(a.enumRecords) >= maxLiveEnumerations {
		a.evictOldestEnumerationLocked()
	}
	id := a.nextEnumerationIDLocked()
	rec := &enumerationRecord{
		id: id, dir: dir,
		entries:    append([]clientcore.DirEntry(nil), ents...),
		dirVersion: dirVersion,
		lastUsed:   now,
	}
	a.enumRecords[id] = rec
	return rec, nil
}

func (a *attach) nextEnumerationIDLocked() uint64 {
	for {
		a.nextEnumID++
		if a.nextEnumID == 0 {
			a.nextEnumID++
		}
		if a.nextEnumID > enumerateCookieMaxID {
			a.nextEnumID = 1
		}
		if _, exists := a.enumRecords[a.nextEnumID]; !exists {
			return a.nextEnumID
		}
	}
}

func encodeEnumerationCookie(enumID uint64, pos int) (uint64, bool) {
	if enumID == 0 || enumID > enumerateCookieMaxID || pos <= 0 || uint64(pos) > enumerateCookieMaxPos {
		return 0, false
	}
	return enumerateCookieMarker | (enumID << (enumerateCookiePosBits + 2)) | (uint64(pos) << 2), true
}

func decodeEnumerationCookie(cookie uint64) (uint64, int, bool) {
	if cookie&enumerateCookieMarker == 0 {
		return 0, 0, false
	}
	if cookie&enumerateCookieReservedMask != 0 {
		return 0, 0, false
	}
	enumID := (cookie >> (enumerateCookiePosBits + 2)) & enumerateCookieMaxID
	pos := (cookie >> 2) & enumerateCookieMaxPos
	if enumID == 0 || pos == 0 {
		return 0, 0, false
	}
	return enumID, int(pos), true
}

func (a *attach) pruneEnumerationsLocked(now time.Time) {
	for id, rec := range a.enumRecords {
		if now.Sub(rec.lastUsed) > enumerationTTL {
			a.dropEnumerationLocked(id)
		}
	}
}

func (a *attach) evictOldestEnumerationLocked() {
	var oldest *enumerationRecord
	for _, rec := range a.enumRecords {
		if oldest == nil || rec.lastUsed.Before(oldest.lastUsed) {
			oldest = rec
		}
	}
	if oldest != nil {
		a.dropEnumerationLocked(oldest.id)
	}
}

func (a *attach) dropEnumerationLocked(id uint64) {
	delete(a.enumRecords, id)
}

func (a *attach) getattr(ctx context.Context, req *pfslocal.GetAttrRequest) (*pfslocal.GetAttrReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, false)
	defer unlockIfPresent(unlockHandle)
	target, eno := a.objectTarget(req.Item, req.Handle)
	if eno != 0 {
		return nil, eno
	}
	rec := target.rec
	if rec.graft {
		var attr fsproto.Attr
		if target.handle != nil {
			if target.handle.file == nil {
				return nil, darwinEIO
			}
			fi, err := target.handle.file.Stat()
			if err != nil {
				return nil, localErrno(err)
			}
			attr = localAttr(fi)
			a.mu.Lock()
			rec = a.registerHandleAttrLocked(target.handle, attr)
			a.mu.Unlock()
		} else {
			attr, eno = a.statLocal(rec.path)
			if eno != 0 {
				return nil, eno
			}
			rec = a.registerLocal(rec.path, attr)
		}
		if rec == nil {
			return nil, darwinEIO
		}
		if eno := a.flushBindingDelta(); eno != 0 {
			return nil, eno
		}
		return &pfslocal.GetAttrReply{
			Attr: a.localAttrForRecordPath(attr, rec, target.scope, target.detached),
		}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	var attr fsproto.Attr
	var st clientcore.Status
	if target.handle != nil {
		attr, st = vol.GetattrOpenHandle(ctx, target.scope, rec.state)
	} else {
		attr, st = vol.Getattr(ctx, rec.path, rec.state)
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	if target.handle != nil {
		rec = a.registerHandleAttrLocked(target.handle, attr)
	} else {
		rec = a.registerLocked(rec.path, attr)
	}
	a.mu.Unlock()
	if rec == nil {
		return nil, darwinEIO
	}
	if eno := a.flushBindingDelta(); eno != 0 {
		return nil, eno
	}
	return &pfslocal.GetAttrReply{
		Attr: a.localAttrForRecordPath(attr, rec, target.scope, target.detached),
	}, 0
}

func (a *attach) setattr(ctx context.Context, req *pfslocal.SetAttrRequest) (*pfslocal.SetAttrReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, false)
	defer unlockIfPresent(unlockHandle)
	target, eno := a.objectTarget(req.Item, req.Handle)
	if eno != 0 {
		return nil, eno
	}
	rec := target.rec
	if req.Size != nil && target.detached && target.handle != nil && !target.handle.write {
		return nil, darwinEBADF
	}
	if rec.graft {
		exactHandle := target.handle
		if !target.detached && req.Size != nil &&
			exactHandle != nil && !exactHandle.write {
			// A linked item setattr is pathname-authorized by FSKit. A
			// coincidental read descriptor must not turn truncate into EBADF;
			// open a purpose-scoped writable local file for this bound name.
			exactHandle = nil
		}
		return a.setattrLocal(rec, exactHandle, target.scope, target.detached, req)
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	// A size-only setattr the daemon itself issued to refresh the kernel's
	// stale vnode state (see exactKernelRefresh) must not reach the
	// authority: consume the note and answer with current attributes.
	if a.consumeExpectedTruncate(rec.path, req) {
		a.mu.RLock()
		current := a.items[rec.item.ItemID]
		if current == nil || current.item.ItemGeneration != rec.item.ItemGeneration {
			a.mu.RUnlock()
			return nil, darwinESTALE
		}
		attr := current.attr
		local := a.localAttrForRecordPathLocked(
			attr,
			current,
			target.scope,
			target.detached,
		)
		a.mu.RUnlock()
		return &pfslocal.SetAttrReply{Attr: local}, 0
	}
	cr := clientcore.SetattrRequest{}
	if req.Mode != nil {
		cr.Mode, cr.SetMode = *req.Mode, true
	}
	if req.UID != nil {
		cr.UID, cr.SetUID = *req.UID, true
	}
	if req.GID != nil {
		cr.GID, cr.SetGID = *req.GID, true
	}
	if req.Size != nil {
		cr.Size, cr.SetSize = int64(*req.Size), true
	}
	if req.MtimeMs != nil {
		cr.MtimeMs, cr.SetMTime = *req.MtimeMs, true
	}
	if req.AtimeMs != nil {
		cr.AtimeMs, cr.SetATime = *req.AtimeMs, true
	}
	var attr fsproto.Attr
	var st clientcore.Status
	if target.handle != nil {
		attr, st = vol.SetattrOpenHandle(ctx, target.scope, rec.state, cr)
	} else {
		attr, st = vol.Setattr(ctx, rec.path, rec.state, cr)
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	if attr.Kind == "" {
		if target.handle != nil {
			attr, st = vol.GetattrOpenHandle(ctx, target.scope, rec.state)
		} else {
			attr, st = vol.Getattr(ctx, rec.path, rec.state)
		}
		if st != fsproto.OK {
			return nil, toDarwinErr(st)
		}
	}
	a.mu.Lock()
	if target.handle != nil {
		rec = a.registerHandleAttrLocked(target.handle, attr)
	} else {
		rec = a.registerLocked(rec.path, attr)
	}
	a.mu.Unlock()
	if rec == nil {
		return nil, darwinEIO
	}
	if eno := a.flushBindingDelta(); eno != 0 {
		return nil, eno
	}
	return &pfslocal.SetAttrReply{
		Attr: a.localAttrForRecordPath(attr, rec, target.scope, target.detached),
	}, 0
}

func (a *attach) open(ctx context.Context, req *pfslocal.OpenRequest) (*pfslocal.OpenReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if rec.graft {
		write := req.Mode == pfslocal.OpenModeWrite || req.Mode == pfslocal.OpenModeReadWrite
		flags := localOpenFlags(req.Mode)
		file, err := a.localFS.OpenFile(rec.path, flags, 0)
		if err != nil && flags != os.O_RDONLY {
			// Directories only support read-only descriptors; retain parity
			// with the kernel retry behavior instead of failing dir opens.
			if fi, statErr := a.localFS.Lstat(rec.path); statErr == nil && fi.IsDir() {
				file, err = a.localFS.OpenFile(rec.path, os.O_RDONLY, 0)
			}
		}
		if err != nil {
			return nil, localErrno(err)
		}
		a.mu.Lock()
		h := a.newLocalHandleLocked(rec.path, rec.item.ItemID, file, write)
		a.mu.Unlock()
		return &pfslocal.OpenReply{Handle: h}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	write := req.Mode == pfslocal.OpenModeWrite || req.Mode == pfslocal.OpenModeReadWrite
	if st := vol.Open(ctx, rec.path, rec.state, write); st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	h := a.newHandleLocked(rec.path, rec.item.ItemID, rec.state, write)
	a.mu.Unlock()
	return &pfslocal.OpenReply{Handle: h}, 0
}

func (a *attach) close(req *pfslocal.CloseRequest) (*pfslocal.CloseReply, int32) {
	// Descriptor operations serialize on this handle. The shared namespace
	// lock keeps item reclamation exclusive without globally blocking
	// unrelated handles behind one close.
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, true)
	defer unlockIfPresent(unlockHandle)
	if err := a.controlAdmissionError(); err != nil {
		return nil, darwinENXIO
	}
	h, eno := a.handle(req.Handle)
	if eno != 0 {
		if eno == darwinEINVAL {
			if reply, retired := a.replayRetiredClose(req.Handle); retired {
				return reply, 0
			}
		}
		return nil, eno
	}
	if h.file != nil {
		err := h.file.Close()
		a.closeHandle(req.Handle)
		reply := &pfslocal.CloseReply{Retired: true}
		if err != nil {
			reply.CloseErrno = localErrno(err)
			a.recordRetiredCloseError(req.Handle, reply.CloseErrno)
		}
		return reply, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	closePath := h.openPath
	if closePath == "" {
		closePath = h.path
	}
	if st := vol.CloseHandle(closePath, h.state); st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.closeHandle(req.Handle)
	return &pfslocal.CloseReply{Retired: true}, 0
}

func (a *attach) read(ctx context.Context, req *pfslocal.ReadRequest) (*pfslocal.ReadReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, false)
	defer unlockIfPresent(unlockHandle)
	h, scope, eno := a.handleTarget(req.Handle)
	if eno != 0 {
		return nil, eno
	}
	detached := scope == ""
	if req.Length > 8<<20 {
		return nil, darwinEINVAL
	}
	if h.file != nil {
		data := make([]byte, int(req.Length))
		n, err := h.file.ReadAt(data, int64(req.Offset))
		if err != nil && err != io.EOF {
			return nil, localErrno(err)
		}
		return &pfslocal.ReadReply{Data: data[:n]}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	var data []byte
	var st clientcore.Status
	if detached {
		data, st = vol.ReadExactHandle(ctx, h.state, int64(req.Offset), int(req.Length))
	} else {
		data, st = vol.ReadOpenHandle(ctx, scope, h.state, int64(req.Offset), int(req.Length))
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.ReadReply{Data: data}, 0
}

func (a *attach) write(ctx context.Context, req *pfslocal.WriteRequest) (*pfslocal.WriteReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, false)
	defer unlockIfPresent(unlockHandle)
	h, scope, eno := a.handleTarget(req.Handle)
	if eno != 0 {
		return nil, eno
	}
	detached := scope == ""
	if !h.write {
		return nil, darwinEBADF
	}
	if h.file != nil {
		if _, err := h.file.WriteAt(req.Data, int64(req.Offset)); err != nil {
			return nil, localErrno(err)
		}
		fi, err := h.file.Stat()
		if err != nil {
			return nil, localErrno(err)
		}
		attr := localAttr(fi)
		a.mu.Lock()
		rec := a.registerHandleAttrLocked(h, attr)
		a.mu.Unlock()
		if rec == nil {
			return nil, darwinEIO
		}
		if eno := a.flushBindingDelta(); eno != 0 {
			return nil, eno
		}
		return &pfslocal.WriteReply{
			Written: uint32(len(req.Data)),
			Attr:    a.localAttrForRecordPath(attr, rec, scope, detached),
		}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	var n int
	var st clientcore.Status
	if detached {
		n, st = vol.WriteExactHandle(ctx, h.state, int64(req.Offset), req.Data)
	} else {
		n, st = vol.WriteOpenHandle(ctx, scope, h.state, int64(req.Offset), req.Data)
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	var attr fsproto.Attr
	attr, st = vol.GetattrOpenHandle(ctx, scope, h.state)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	rec := a.registerHandleAttrLocked(h, attr)
	a.mu.Unlock()
	if rec == nil {
		return nil, darwinEIO
	}
	if eno := a.flushBindingDelta(); eno != 0 {
		return nil, eno
	}
	return &pfslocal.WriteReply{
		Written: uint32(n),
		Attr:    a.localAttrForRecordPath(attr, rec, scope, detached),
	}, 0
}

func (a *attach) fsync(_ context.Context, req *pfslocal.FsyncRequest) int32 {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, false)
	defer unlockIfPresent(unlockHandle)
	h, scope, eno := a.handleTarget(req.Handle)
	if eno != 0 {
		return eno
	}
	if h.file != nil {
		if err := h.file.Sync(); err != nil {
			return localErrno(err)
		}
		return 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return eno
	}
	return toDarwinErr(vol.FsyncHandle(scope, h.state))
}

func (a *attach) create(ctx context.Context, req *pfslocal.CreateRequest) (*pfslocal.CreateReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	dir, eno := a.item(req.Dir)
	if eno != 0 {
		return nil, eno
	}
	p, eno := cleanChild(dir.path, req.Name)
	if eno != 0 {
		return nil, eno
	}
	defer a.lockNames(entryKey(p))()
	if graft := a.localDirFor(p); graft != "" {
		if p == graft {
			// A graft rule is a directory rule: the root can only ever be a
			// directory (mkdir), never a file or symlink.
			return nil, darwinEISDIR
		}
		flags := os.O_CREATE | os.O_RDWR
		if req.Exclusive {
			flags |= os.O_EXCL
		}
		file, err := a.localFS.OpenFile(p, flags, os.FileMode(req.Mode)&os.ModePerm)
		if err != nil {
			return nil, localErrno(err)
		}
		fi, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, localErrno(err)
		}
		attr := localAttr(fi)
		a.mu.Lock()
		rec := a.registerLocalLocked(p, attr)
		a.bumpLocalVersionLocked(parentPath(p))
		h := a.newLocalHandleLocked(p, rec.item.ItemID, file, true)
		a.mu.Unlock()
		if eno := a.flushBindingDelta(); eno != 0 {
			_ = file.Close()
			return nil, eno
		}
		return &pfslocal.CreateReply{
			Attr:   a.localAttrForRecord(attr, rec, false),
			Handle: h,
		}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	var attr fsproto.Attr
	var st clientcore.Status
	if req.Exclusive {
		// Wire-enforced on managed authorities: the journal decides
		// exclusivity atomically, so two machines cannot both win O_EXCL
		// (and the old lookup pre-check round trip is gone).
		attr, st = vol.CreateExcl(ctx, p, req.Mode)
	} else {
		attr, st = vol.Create(ctx, p, req.Mode)
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	rec := a.registerCreatedLocked(p, attr)
	a.mu.Unlock()
	if rec == nil {
		return nil, darwinEIO
	}
	if eno := a.flushBindingDelta(); eno != 0 {
		return nil, eno
	}
	if st := vol.RegisterOpened(ctx, p, rec.state); st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	h := a.newHandleLocked(p, rec.item.ItemID, rec.state, true)
	a.mu.Unlock()
	return &pfslocal.CreateReply{
		Attr:   a.localAttrForRecord(attr, rec, false),
		Handle: h,
	}, 0
}

func (a *attach) mkdir(ctx context.Context, req *pfslocal.MkdirRequest) (*pfslocal.MkdirReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	dir, eno := a.item(req.Dir)
	if eno != 0 {
		return nil, eno
	}
	p, eno := cleanChild(dir.path, req.Name)
	if eno != 0 {
		return nil, eno
	}
	defer a.lockNames(entryKey(p))()
	if graft := a.localDirFor(p); graft != "" {
		if p == graft {
			// Creating the graft root itself needs the machine-local scaffold
			// directories that lead up to its backing path.
			if err := a.ensureLocalScaffold(p); err != nil {
				return nil, localErrno(err)
			}
		}
		if err := a.localFS.Mkdir(p, os.FileMode(req.Mode)&os.ModePerm); err != nil {
			return nil, localErrno(err)
		}
		attr, eno := a.statLocal(p)
		if eno != 0 {
			return nil, eno
		}
		a.mu.Lock()
		rec := a.registerLocalLocked(p, attr)
		a.bumpLocalVersionLocked(parentPath(p))
		a.mu.Unlock()
		if eno := a.flushBindingDelta(); eno != 0 {
			return nil, eno
		}
		return &pfslocal.MkdirReply{Attr: a.localAttrForRecord(attr, rec, false)}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	attr, st := vol.Mkdir(ctx, p, req.Mode)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	rec := a.registerCreatedLocked(p, attr)
	a.mu.Unlock()
	if rec == nil {
		return nil, darwinEIO
	}
	if eno := a.flushBindingDelta(); eno != 0 {
		return nil, eno
	}
	return &pfslocal.MkdirReply{Attr: a.localAttrForRecord(attr, rec, false)}, 0
}

func (a *attach) remove(ctx context.Context, req *pfslocal.RemoveRequest) int32 {
	if req.Directory {
		// rmdir holds nsMu EXCLUSIVELY (like rename): its emptiness check
		// must be atomic against a racing create INSIDE the dir, which
		// per-(dir,name) stripes cannot exclude.
		a.nsMu.Lock()
		defer a.nsMu.Unlock()
	} else {
		a.nsMu.RLock()
		defer a.nsMu.RUnlock()
	}
	dir, eno := a.item(req.Dir)
	if eno != 0 {
		return eno
	}
	p, eno := cleanChild(dir.path, req.Name)
	if eno != 0 {
		return eno
	}
	if !req.Directory {
		defer a.lockNames(entryKey(p))()
	}
	if graft := a.localDirFor(p); graft != "" {
		return a.removeLocal(p, req.Directory)
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return eno
	}
	attr, st := vol.Lookup(ctx, p)
	if st != fsproto.OK {
		return toDarwinErr(st)
	}
	isDir := attr.Kind == "directory"
	// RemoveRequest is the pfslocal unlink/rmdir boundary. Enforce the caller's intent before
	// recording a write-back tombstone; otherwise a misclassified unlink can hide and later delete
	// a directory tree even though the frontend never issued rmdir for it.
	if req.Directory {
		if !isDir {
			return darwinENOTDIR
		}
		ents, st := vol.Readdir(ctx, p)
		if st != fsproto.OK {
			return toDarwinErr(st)
		}
		if len(ents) > 0 {
			return darwinENOTEMPTY
		}
	} else if isDir {
		return darwinEISDIR
	}
	child := a.itemByPath(p)
	var state *clientcore.NodeState
	if child != nil {
		state = child.state
	}
	st = vol.Remove(ctx, p, state)
	if st != fsproto.OK {
		return toDarwinErr(st)
	}
	a.mu.Lock()
	a.removePathLocked(p)
	a.mu.Unlock()
	return a.flushBindingDelta()
}

func (a *attach) rename(ctx context.Context, req *pfslocal.RenameRequest) int32 {
	// Exclusive: a rename can rekey an entire subtree of paths (and carry
	// grafts with it), so every path resolved under a shared nsMu must stay
	// valid for the duration of its op. File-grain mutations instead hold
	// nsMu shared plus a per-directory stripe (see lockNames).
	a.nsMu.Lock()
	defer a.nsMu.Unlock()
	fromDir, eno := a.item(req.FromDir)
	if eno != 0 {
		return eno
	}
	toDir, eno := a.item(req.ToDir)
	if eno != 0 {
		return eno
	}
	oldp, eno := cleanChild(fromDir.path, req.FromName)
	if eno != 0 {
		return eno
	}
	newp, eno := cleanChild(toDir.path, req.ToName)
	if eno != 0 {
		return eno
	}
	fromGraft := a.localDirFor(oldp)
	toGraft := a.localDirFor(newp)
	if fromGraft != "" || toGraft != "" {
		if fromGraft == "" || toGraft == "" || fromGraft != toGraft {
			// A rename across the graft boundary crosses filesystems; EXDEV
			// makes callers fall back to copy+delete, exactly like a bind
			// mount would.
			return darwinEXDEV
		}
		return a.renameLocal(oldp, newp, req.NoReplace)
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return eno
	}
	if req.NoReplace {
		if _, st := vol.Lookup(ctx, newp); st == fsproto.OK {
			return darwinEEXIST
		}
	}
	// Snapshot the daemon-side identities under a.mu, but never hold that
	// mutex across the authority RPC. Rename can wait for a delegation recall;
	// the invalidation consumers need a.mu to apply and acknowledge the
	// batches that let the holder's drain/barrier finish. Holding it here
	// creates a closed recall -> invalidation ack -> a.mu -> rename cycle.
	//
	// nsMu is exclusive for the whole operation, so no local frontend
	// namespace mutation can change these bindings between the snapshot and
	// the commit below. Authority invalidations may inspect the registry in
	// parallel, which is precisely why a.mu must remain available.
	a.mu.Lock()
	if a.detached {
		a.mu.Unlock()
		return darwinENXIO
	}
	src := a.paths[oldp]
	dst := a.paths[newp]
	var srcState, dstState *clientcore.NodeState
	if src != nil {
		srcState = src.state
	}
	if dst != nil {
		dstState = dst.state
	}
	sameIdentity := src != nil && dst != nil &&
		(src.item == dst.item || src.state == dst.state ||
			(src.state != nil && dst.state != nil &&
				src.state.AuthorityIno() != 0 &&
				src.state.AuthorityIno() == dst.state.AuthorityIno()))
	a.mu.Unlock()
	st := vol.Rename(ctx, oldp, newp, srcState, dstState)
	if st != fsproto.OK {
		return toDarwinErr(st)
	}
	if sameIdentity {
		// POSIX rename(old,new) is a no-op when both names already refer to
		// the same inode. The authority left both links intact; mirror that
		// exact result instead of deleting the destination and rekeying the
		// source in the frontend registry.
		return 0
	}
	a.mu.Lock()
	if dst != nil {
		a.removePathLocked(newp)
	}
	a.renamePathLocked(oldp, newp)
	a.mu.Unlock()
	return a.flushBindingDelta()
}

func (a *attach) hardLink(ctx context.Context, req *pfslocal.HardLinkRequest) (*pfslocal.HardLinkReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()

	src, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	dir, eno := a.item(req.Dir)
	if eno != 0 {
		return nil, eno
	}
	newp, eno := cleanChild(dir.path, req.Name)
	if eno != 0 {
		return nil, eno
	}
	unlock := a.lockNames(entryKey(src.path), entryKey(newp))
	defer unlock()

	fromGraft := a.localDirFor(src.path)
	toGraft := a.localDirFor(newp)
	if fromGraft != "" || toGraft != "" {
		if fromGraft == "" || toGraft == "" || fromGraft != toGraft {
			return nil, darwinEXDEV
		}
		fi, err := a.localFS.Lstat(src.path)
		if err != nil {
			return nil, localErrno(err)
		}
		if fi.IsDir() {
			return nil, darwinEPERM
		}
		if err := a.localFS.Link(src.path, newp); err != nil {
			return nil, localErrno(err)
		}
		attr, eno := a.statLocal(newp)
		if eno != 0 {
			_ = a.localFS.Remove(newp)
			return nil, eno
		}
		a.mu.Lock()
		rec := a.registerLocalAliasLocked(newp, src, attr)
		a.bumpLocalVersionLocked(dir.path)
		a.mu.Unlock()
		if eno := a.flushBindingDelta(); eno != 0 {
			return nil, eno
		}
		return &pfslocal.HardLinkReply{
			Name: append([]byte(nil), req.Name...),
			Attr: a.localAttrForRecord(attr, rec, false),
		}, 0
	}

	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	attr, st := vol.Link(ctx, src.path, newp, src.state)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	rec := a.registerHardLinkAliasLocked(newp, src, attr)
	a.mu.Unlock()
	if eno := a.flushBindingDelta(); eno != 0 {
		return nil, eno
	}
	return &pfslocal.HardLinkReply{
		Name: append([]byte(nil), req.Name...),
		Attr: a.localAttrForRecord(attr, rec, false),
	}, 0
}

func (a *attach) symlink(ctx context.Context, req *pfslocal.SymlinkRequest) (*pfslocal.SymlinkReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	dir, eno := a.item(req.Dir)
	if eno != 0 {
		return nil, eno
	}
	p, eno := cleanChild(dir.path, req.Name)
	if eno != 0 {
		return nil, eno
	}
	defer a.lockNames(entryKey(p))()
	if graft := a.localDirFor(p); graft != "" {
		if p == graft {
			// A graft rule is a directory rule: the root can only ever be a
			// directory (mkdir), never a file or symlink.
			return nil, darwinEISDIR
		}
		if err := a.localFS.Symlink(string(req.Target), p); err != nil {
			return nil, localErrno(err)
		}
		attr, eno := a.statLocal(p)
		if eno != 0 {
			return nil, eno
		}
		a.mu.Lock()
		rec := a.registerLocalLocked(p, attr)
		a.bumpLocalVersionLocked(parentPath(p))
		a.mu.Unlock()
		if eno := a.flushBindingDelta(); eno != 0 {
			return nil, eno
		}
		return &pfslocal.SymlinkReply{Attr: a.localAttrForRecord(attr, rec, false)}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	attr, st := vol.Symlink(ctx, string(req.Target), p)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	rec := a.registerCreatedLocked(p, attr)
	a.mu.Unlock()
	if rec == nil {
		return nil, darwinEIO
	}
	if eno := a.flushBindingDelta(); eno != 0 {
		return nil, eno
	}
	return &pfslocal.SymlinkReply{Attr: a.localAttrForRecord(attr, rec, false)}, 0
}

func (a *attach) readlink(ctx context.Context, req *pfslocal.ReadlinkRequest) (*pfslocal.ReadlinkReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if rec.graft {
		target, err := a.localFS.Readlink(rec.path)
		if err != nil {
			return nil, localErrno(err)
		}
		return &pfslocal.ReadlinkReply{Target: []byte(target)}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	target, st := vol.Readlink(ctx, rec.path)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.ReadlinkReply{Target: []byte(target)}, 0
}

func (a *attach) statfs() (*pfslocal.StatfsReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	st := vol.Statfs()
	return &pfslocal.StatfsReply{
		BlockSize: uint64(st.Bsize), TotalBlocks: st.Blocks, FreeBlocks: st.Bfree,
		TotalFiles: st.Files, FreeFiles: st.Ffree,
	}, 0
}

// syncVolume serves the frontend's REAL volume barrier (FSKit synchronize):
// authority-durable, applied, and acknowledged by every live protocol
// subscriber at its supported frontend boundary — or an ERROR. There is no
// degraded local-only success. Local WAL sync failure seals mutation
// admission; any barrier failure surfaces on attach state and to the kernel.
func (a *attach) syncVolume(_ context.Context) (*pfslocal.SyncVolumeReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	if err := vol.SyncVolume(); err != nil {
		recs, bytes := vol.WriteBackPending()
		log.Printf("portablefsd: %s: volume sync FAILED: %v (%d records / %d bytes remain pending; no barrier success claimed)", a.ref, err, recs, bytes)
		a.setErr(err)
		return nil, darwinEIO
	}
	return &pfslocal.SyncVolumeReply{}, 0
}

func (a *attach) reclaim(req *pfslocal.ReclaimRequest) int32 {
	a.nsMu.Lock()
	defer a.nsMu.Unlock()
	// Reclaim IS teardown: unmount(2) drives every cached vnode through this
	// handler, including while a prepared detach is mid-flight. It retires
	// identity records and creates no new durability debt, so no admission
	// quarantine may refuse it — a refused reclaim starves the kernel detach
	// the quarantine exists to protect.
	a.mu.Lock()
	if a.detached {
		a.mu.Unlock()
		return 0
	}
	rec := a.items[req.Item.ItemID]
	if rec == nil || rec.item.ItemGeneration != req.Item.ItemGeneration {
		// Reclaim is idempotent for an already-retired generation. A reused
		// ItemID's newer generation and its handles are unrelated.
		a.mu.Unlock()
		return 0
	}
	for _, h := range a.handles {
		if h != nil && h.itemID == req.Item.ItemID {
			a.mu.Unlock()
			return darwinEBUSY
		}
	}
	// The bound-descendant refusal protects steady-state parent identity
	// (a reclaimed directory must not strand children with no reportable
	// parent). During a detach, unmount(2)'s vflush may reclaim vnodes in
	// any order and every binding is being retired wholesale, so refusing
	// there would starve the kernel detach.
	if !(a.detachPrepared || a.detachForce) && a.hasBoundDescendantsLocked(rec) {
		a.mu.Unlock()
		return darwinEBUSY
	}
	if a.reclaimItemLocked(req.Item) {
		// Reclaim is the durable Item lifetime tombstone. Without it, a
		// daemon crash after removing the in-memory detached identity but
		// before full-state compaction could replay its prior detach entry
		// and resurrect an Item generation FSKit has explicitly retired.
		a.pendingBindings = append(a.pendingBindings, bindingJournalEntry{
			Ref: a.ref, Op: "reclaim",
			ID: req.Item.ItemID, Gen: req.Item.ItemGeneration,
		})
	}
	a.mu.Unlock()
	return a.flushBindingDelta()
}

func (a *attach) synthesizeFrontendMutation(body any, origin uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch req := body.(type) {
	case *pfslocal.CreateRequest:
		if p, ok := a.childPathLocked(req.Dir, req.Name); ok {
			a.publishNamespaceInvalidationLocked(p, 0, origin)
			a.publishContentInvalidationLocked(p, 0, origin)
		}
	case *pfslocal.MkdirRequest:
		if p, ok := a.childPathLocked(req.Dir, req.Name); ok {
			a.publishNamespaceInvalidationLocked(p, 0, origin)
		}
	case *pfslocal.SymlinkRequest:
		if p, ok := a.childPathLocked(req.Dir, req.Name); ok {
			a.publishNamespaceInvalidationLocked(p, 0, origin)
		}
	case *pfslocal.HardLinkRequest:
		if rec := a.items[req.Item.ItemID]; rec != nil && rec.item.ItemGeneration == req.Item.ItemGeneration {
			a.publishContentInvalidationLocked(rec.path, 0, origin)
		}
		if p, ok := a.childPathLocked(req.Dir, req.Name); ok {
			a.publishNamespaceInvalidationLocked(p, 0, origin)
		}
	case *pfslocal.RemoveRequest:
		if p, ok := a.childPathLocked(req.Dir, req.Name); ok {
			a.publishNamespaceInvalidationLocked(p, 0, origin)
		}
	case *pfslocal.RenameRequest:
		if p, ok := a.childPathLocked(req.FromDir, req.FromName); ok {
			a.publishNamespaceInvalidationLocked(p, 0, origin)
		}
		if p, ok := a.childPathLocked(req.ToDir, req.ToName); ok {
			a.publishNamespaceInvalidationLocked(p, 0, origin)
		}
	case *pfslocal.WriteRequest:
		if h := a.handles[req.Handle]; h != nil {
			if rec := a.items[h.itemID]; rec != nil {
				a.publishItemContentInvalidationLocked(rec.item, origin)
			}
		}
	case *pfslocal.SetAttrRequest:
		a.publishItemContentInvalidationLocked(req.Item, origin)
	case *pfslocal.XattrSetRequest:
		a.publishItemContentInvalidationLocked(req.Item, origin)
	case *pfslocal.XattrRemoveRequest:
		a.publishItemContentInvalidationLocked(req.Item, origin)
	}
}

func (a *attach) childPathLocked(dir pfslocal.Item, name []byte) (string, bool) {
	rec := a.items[dir.ItemID]
	if rec == nil || rec.item.ItemGeneration != dir.ItemGeneration {
		return "", false
	}
	p, eno := cleanChild(rec.path, name)
	return p, eno == 0
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// Extended attributes: forwarded natively to the authority when the attach
// serves xattrs natively (see rootReply's per-attach capability). Reads hold
// nsMu shared like getattr; mutations additionally take the item's parent
// directory stripe (lockNames) like the other file-grain mutations, so the
// daemon-local registry view stays stable across the authority round trip.
// Machine-local grafted paths do not participate (ENOTSUP): their backing is
// a plain local directory and this surface does not bridge OS xattrs.

func (a *attach) xattrGet(ctx context.Context, req *pfslocal.XattrGetRequest) (*pfslocal.XattrGetReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, false)
	defer unlockIfPresent(unlockHandle)
	target, eno := a.objectTarget(req.Item, req.Handle)
	if eno != 0 {
		return nil, eno
	}
	rec := target.rec
	if rec.graft {
		return nil, darwinENOTSUP
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	var value []byte
	var st clientcore.Status
	if target.handle != nil {
		value, st = vol.GetxattrOpenHandle(ctx, target.scope, rec.state, req.Name)
	} else {
		value, st = vol.Getxattr(ctx, rec.path, rec.state, req.Name)
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.XattrGetReply{Value: value}, 0
}

func (a *attach) xattrList(ctx context.Context, req *pfslocal.XattrListRequest) (*pfslocal.XattrListReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, false)
	defer unlockIfPresent(unlockHandle)
	target, eno := a.objectTarget(req.Item, req.Handle)
	if eno != 0 {
		return nil, eno
	}
	rec := target.rec
	if rec.graft {
		return nil, darwinENOTSUP
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	var names []string
	var st clientcore.Status
	if target.handle != nil {
		names, st = vol.ListxattrOpenHandle(ctx, target.scope, rec.state)
	} else {
		names, st = vol.Listxattr(ctx, rec.path, rec.state)
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.XattrListReply{Names: names}, 0
}

func (a *attach) xattrSet(ctx context.Context, req *pfslocal.XattrSetRequest) (*pfslocal.XattrSetReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, false)
	defer unlockIfPresent(unlockHandle)
	target, eno := a.objectTarget(req.Item, req.Handle)
	if eno != 0 {
		return nil, eno
	}
	rec := target.rec
	if rec.graft {
		return nil, darwinENOTSUP
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	defer a.lockNames(entryKey(rec.path))()
	var flags uint8
	if req.CreateOnly {
		flags |= wal.XattrCreate
	}
	if req.ReplaceOnly {
		flags |= wal.XattrReplace
	}
	var st clientcore.Status
	if target.handle != nil {
		st = vol.SetxattrOpenHandle(ctx, target.scope, rec.state, req.Name, req.Value, flags)
	} else {
		st = vol.SetxattrFlags(ctx, rec.path, rec.state, req.Name, req.Value, flags)
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.XattrSetReply{}, 0
}

func (a *attach) xattrRemove(ctx context.Context, req *pfslocal.XattrRemoveRequest) (*pfslocal.XattrRemoveReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	unlockHandle := a.lockHandleOperation(req.Handle, false)
	defer unlockIfPresent(unlockHandle)
	target, eno := a.objectTarget(req.Item, req.Handle)
	if eno != 0 {
		return nil, eno
	}
	rec := target.rec
	if rec.graft {
		return nil, darwinENOTSUP
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	defer a.lockNames(entryKey(rec.path))()
	var st clientcore.Status
	if target.handle != nil {
		st = vol.RemovexattrOpenHandle(ctx, target.scope, rec.state, req.Name)
	} else {
		st = vol.Removexattr(ctx, rec.path, rec.state, req.Name)
	}
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.XattrRemoveReply{}, 0
}

func errMessage(op string, eno int32) string {
	return fmt.Sprintf("%s failed: errno %d", op, eno)
}
