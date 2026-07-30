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

func fsAttrToLocal(a fsproto.Attr, item pfslocal.Item) pfslocal.Attr {
	kind := pfslocal.ItemKindFile
	switch a.Kind {
	case "directory":
		kind = pfslocal.ItemKindDirectory
	case "symlink":
		kind = pfslocal.ItemKindSymlink
	}
	nlink := a.Nlink
	if nlink == 0 {
		nlink = 1
	}
	return pfslocal.Attr{
		Item: item, Kind: kind, Mode: a.Mode, Nlink: nlink, UID: a.Uid, GID: a.Gid,
		Size: uint64(max64(a.Size, 0)), MtimeMs: a.MtimeMs, CtimeMs: a.CtimeMs, AtimeMs: a.AtimeMs,
		ContentVersion: 0,
	}
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
		Root: root.item, RootAttr: fsAttrToLocal(root.attr, root.item),
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
		a.flushBindingDelta()
		return &pfslocal.LookupReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
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
	a.flushBindingDelta()
	return &pfslocal.LookupReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
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
			a.flushBindingDelta()
		}
		return rep, 0
	}

	rep, eno := a.enumerateResumeLocked(dir.path, req.Cookie, limit)
	if eno != 0 {
		return nil, eno
	}
	if rep != nil && len(rep.Entries) > 0 {
		a.flushBindingDelta()
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
		cookie := uint64(0)
		if enumRec != nil && i < len(ents)-1 {
			var ok bool
			cookie, ok = encodeEnumerationCookie(enumRec.id, i+1)
			if !ok {
				return nil, darwinEIO
			}
		}
		out = append(out, pfslocal.DirEntry{Name: []byte(e.Name), Attr: fsAttrToLocal(e.Attr, rec.item), Cookie: cookie})
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
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if graft := a.localDirFor(rec.path); graft != "" {
		attr, eno := a.statLocal(rec.path)
		if eno != 0 {
			return nil, eno
		}
		rec = a.registerLocal(rec.path, attr)
		a.flushBindingDelta()
		return &pfslocal.GetAttrReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	attr, st := vol.Getattr(ctx, rec.path, rec.state)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	rec = a.registerLocked(rec.path, attr)
	a.mu.Unlock()
	a.flushBindingDelta()
	return &pfslocal.GetAttrReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
}

func (a *attach) setattr(ctx context.Context, req *pfslocal.SetAttrRequest) (*pfslocal.SetAttrReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if graft := a.localDirFor(rec.path); graft != "" {
		return a.setattrLocal(rec, req)
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	// A size-only setattr the daemon itself issued to refresh the kernel's
	// stale vnode state (see scheduleCoherenceRefresh) must not reach the
	// authority: consume the note and answer with current attributes.
	if a.consumeExpectedTruncate(rec.path, req) {
		attr, st := vol.Getattr(ctx, rec.path, rec.state)
		if st != fsproto.OK {
			return nil, toDarwinErr(st)
		}
		a.mu.Lock()
		rec = a.registerLocked(rec.path, attr)
		a.mu.Unlock()
		a.flushBindingDelta()
		return &pfslocal.SetAttrReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
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
	attr, st := vol.Setattr(ctx, rec.path, rec.state, cr)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	if attr.Kind == "" {
		attr, st = vol.Getattr(ctx, rec.path, rec.state)
		if st != fsproto.OK {
			return nil, toDarwinErr(st)
		}
	}
	a.mu.Lock()
	rec = a.registerLocked(rec.path, attr)
	a.mu.Unlock()
	a.flushBindingDelta()
	return &pfslocal.SetAttrReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
}

func (a *attach) open(ctx context.Context, req *pfslocal.OpenRequest) (*pfslocal.OpenReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if a.localDirFor(rec.path) != "" {
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
		h := a.newLocalHandleLocked(rec.path, file, write)
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
	h := a.newHandleLocked(rec.path, rec.state, write)
	a.mu.Unlock()
	return &pfslocal.OpenReply{Handle: h}, 0
}

func (a *attach) close(req *pfslocal.CloseRequest) (int32, error) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	if err := a.controlAdmissionError(); err != nil {
		return darwinENXIO, nil
	}
	h := a.closeHandle(req.Handle)
	if h == nil {
		return darwinEINVAL, nil
	}
	if h.file != nil {
		if err := h.file.Close(); err != nil {
			return localErrno(err), nil
		}
		return 0, nil
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return eno, nil
	}
	closePath := h.openPath
	if closePath == "" {
		closePath = h.path
	}
	return toDarwinErr(vol.CloseHandle(closePath, h.state)), nil
}

func (a *attach) read(ctx context.Context, req *pfslocal.ReadRequest) (*pfslocal.ReadReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	h, eno := a.handle(req.Handle)
	if eno != 0 {
		return nil, eno
	}
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
	data, st := vol.Read(ctx, h.path, h.state, int64(req.Offset), int(req.Length))
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.ReadReply{Data: data}, 0
}

func (a *attach) write(ctx context.Context, req *pfslocal.WriteRequest) (*pfslocal.WriteReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	h, eno := a.handle(req.Handle)
	if eno != 0 {
		return nil, eno
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
		rec := a.registerLocal(h.path, attr)
		a.flushBindingDelta()
		return &pfslocal.WriteReply{Written: uint32(len(req.Data)), Attr: fsAttrToLocal(attr, rec.item)}, 0
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	n, st := vol.Write(ctx, h.path, h.state, int64(req.Offset), req.Data)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	attr, st := vol.Getattr(ctx, h.path, h.state)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	rec := a.registerLocked(h.path, attr)
	a.mu.Unlock()
	a.flushBindingDelta()
	return &pfslocal.WriteReply{Written: uint32(n), Attr: fsAttrToLocal(attr, rec.item)}, 0
}

func (a *attach) fsync(_ context.Context, req *pfslocal.FsyncRequest) int32 {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	h, eno := a.handle(req.Handle)
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
	return toDarwinErr(vol.FsyncHandle(h.path, h.state))
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
		h := a.newLocalHandleLocked(p, file, true)
		a.mu.Unlock()
		a.flushBindingDelta()
		return &pfslocal.CreateReply{Attr: fsAttrToLocal(attr, rec.item), Handle: h}, 0
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
	a.flushBindingDelta()
	if st := vol.RegisterOpened(ctx, p, rec.state); st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	a.mu.Lock()
	h := a.newHandleLocked(p, rec.state, true)
	a.mu.Unlock()
	return &pfslocal.CreateReply{Attr: fsAttrToLocal(attr, rec.item), Handle: h}, 0
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
		a.flushBindingDelta()
		return &pfslocal.MkdirReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
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
	a.flushBindingDelta()
	return &pfslocal.MkdirReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
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
	a.flushBindingDelta()
	return 0
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
	a.mu.Unlock()
	st := vol.Rename(ctx, oldp, newp, srcState, dstState)
	if st != fsproto.OK {
		return toDarwinErr(st)
	}
	a.mu.Lock()
	if dst != nil {
		a.removePathLocked(newp)
	}
	a.renamePathLocked(oldp, newp)
	a.mu.Unlock()
	a.flushBindingDelta()
	return 0
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
		a.flushBindingDelta()
		return &pfslocal.HardLinkReply{
			Name: append([]byte(nil), req.Name...),
			Attr: fsAttrToLocal(attr, rec.item),
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
	a.flushBindingDelta()
	return &pfslocal.HardLinkReply{
		Name: append([]byte(nil), req.Name...),
		Attr: fsAttrToLocal(attr, rec.item),
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
		a.flushBindingDelta()
		return &pfslocal.SymlinkReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
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
	a.flushBindingDelta()
	return &pfslocal.SymlinkReply{Attr: fsAttrToLocal(attr, rec.item)}, 0
}

func (a *attach) readlink(ctx context.Context, req *pfslocal.ReadlinkRequest) (*pfslocal.ReadlinkReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if a.localDirFor(rec.path) != "" {
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
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	if err := a.controlAdmissionError(); err != nil {
		return darwinENXIO
	}
	a.mu.Lock()
	if rec := a.items[req.Item.ItemID]; rec != nil && rec.item.ItemGeneration == req.Item.ItemGeneration && rec.path != "" {
		for p, alias := range a.paths {
			if alias.item == rec.item {
				a.removePathLocked(p)
			}
		}
	}
	a.mu.Unlock()
	a.flushBindingDelta()
	return 0
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
			a.publishContentInvalidationLocked(h.path, 0, origin)
		}
	case *pfslocal.SetAttrRequest:
		if rec := a.items[req.Item.ItemID]; rec != nil && rec.item.ItemGeneration == req.Item.ItemGeneration {
			a.publishContentInvalidationLocked(rec.path, 0, origin)
		}
	case *pfslocal.XattrSetRequest:
		if rec := a.items[req.Item.ItemID]; rec != nil && rec.item.ItemGeneration == req.Item.ItemGeneration {
			a.publishContentInvalidationLocked(rec.path, 0, origin)
		}
	case *pfslocal.XattrRemoveRequest:
		if rec := a.items[req.Item.ItemID]; rec != nil && rec.item.ItemGeneration == req.Item.ItemGeneration {
			a.publishContentInvalidationLocked(rec.path, 0, origin)
		}
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
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if a.localDirFor(rec.path) != "" {
		return nil, darwinENOTSUP
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	value, st := vol.Getxattr(ctx, rec.path, rec.state, req.Name)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.XattrGetReply{Value: value}, 0
}

func (a *attach) xattrList(ctx context.Context, req *pfslocal.XattrListRequest) (*pfslocal.XattrListReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if a.localDirFor(rec.path) != "" {
		return nil, darwinENOTSUP
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	names, st := vol.Listxattr(ctx, rec.path, rec.state)
	if st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.XattrListReply{Names: names}, 0
}

func (a *attach) xattrSet(ctx context.Context, req *pfslocal.XattrSetRequest) (*pfslocal.XattrSetReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if a.localDirFor(rec.path) != "" {
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
	if st := vol.SetxattrFlags(ctx, rec.path, rec.state, req.Name, req.Value, flags); st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.XattrSetReply{}, 0
}

func (a *attach) xattrRemove(ctx context.Context, req *pfslocal.XattrRemoveRequest) (*pfslocal.XattrRemoveReply, int32) {
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	rec, eno := a.item(req.Item)
	if eno != 0 {
		return nil, eno
	}
	if a.localDirFor(rec.path) != "" {
		return nil, darwinENOTSUP
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	defer a.lockNames(entryKey(rec.path))()
	if st := vol.Removexattr(ctx, rec.path, rec.state, req.Name); st != fsproto.OK {
		return nil, toDarwinErr(st)
	}
	return &pfslocal.XattrRemoveReply{}, 0
}

func errMessage(op string, eno int32) string {
	return fmt.Sprintf("%s failed: errno %d", op, eno)
}
