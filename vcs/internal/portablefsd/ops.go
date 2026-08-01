package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"os"
	"path"
	"sort"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

const (
	enumerateCookieMarker = uint64(1) << 63
	// Cookies are [marker:1][cursor:61][tag:2].
	//
	// The cursor is a pure function of the entry NAME, so a cookie is a stable
	// resumption point in the directory's total enumeration order rather than a
	// position in some server-side snapshot. Any daemon, before or after a
	// restart, resolves a cookie by re-listing the directory and continuing at
	// the first entry whose cursor is strictly greater. That is what makes
	// paging tolerant of concurrent creates, deletes, and rename-ins: entries
	// that survive are returned exactly once, and no cookie can ever fail to
	// resolve mid-enumeration.
	//
	// tag distinguishes this format from the pre-fix positional format
	// ([marker][enumID:31][pos:30][reserved:2], tag == 0), whose cookies died
	// with the snapshot record they indexed. Rejecting tag != cursor keeps a
	// cookie minted by an older daemon (or any foreign sentinel) fail-safe
	// across an upgrade instead of being misread as a cursor.
	enumerateCookieTagMask   = uint64(0x3)
	enumerateCookieTagCursor = uint64(0x1)
	enumerateCursorBits      = 61
	enumerateCursorMax       = (uint64(1) << enumerateCursorBits) - 1
	// Cursors are drawn from [1, enumerateCursorSpace]; the reserved headroom
	// above it absorbs the strictly-increasing fixup applied to the (vanishing)
	// case of two names hashing to the same cursor.
	enumerateCursorSpace = enumerateCursorMax - (uint64(1) << 20)
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
	//
	// FlagsSupported is per-attach for the same reason and rides the SAME
	// reply, but it describes the ATTACHED AUTHORITY only: whether that
	// authority durably stores a flag word. It is not a volume-wide verdict on
	// chflags(2), because this attach's namespace is not all authority — a
	// machine-local graft's backing is a real host inode and chflags on it
	// needs no authority feature at all (see setattrLocal). The frontend is
	// told this so it can report the truth, not so it can gate on it.
	// A nil vol is the synthetic-root attach (no authority yet): false is the
	// honest answer, and it is the conservative one.
	flagsSupported := vol.SupportsFlagPersistence()
	return pfslocal.ResolveReply{
		Root: root.item, RootAttr: a.localAttrForRecord(root.attr, root, false),
		VolumeID: a.volumeID, Branch: a.branch, VolumeName: a.volumeName,
		Capabilities: pfslocal.Capabilities{
			Symlinks: true, HardLinks: true, Xattrs: true, CaseSensitive: true,
			MaxNameBytes: 255, PreferredIOSize: 1 << 20,
			FlagsSupported: flagsSupported,
			// FlagsUnderstood is UNCONDITIONALLY true here and must stay that
			// way: it says only that this daemon parses
			// SetAttrRequest.SetFlags/Flags, which this build demonstrably
			// does a few hundred lines down. It is the frontend's forwarding
			// gate precisely because it is the one fact no reply content can
			// express — a daemon predating those appended fields cannot set
			// it, so it decodes false and the frontend refuses rather than
			// letting the change be silently discarded. Making it conditional
			// on anything (the authority's features, the attach's grafts)
			// would resurrect the volume-wide refusal this replaced.
			FlagsUnderstood: true,
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
	// Enumeration cookies are daemon-opaque continuation tokens carrying a
	// name-derived cursor in the directory's total enumeration order; frontend
	// adapters must pass them back unchanged. Cookie 0 starts at the beginning
	// and terminal replies use next_cookie=0. Every cookie this daemon issues
	// resolves for as long as the directory exists — there is no per-enumeration
	// server state to expire, evict, or lose across a restart. Only foreign
	// cookies (missing marker, wrong format tag, out-of-range cursor) return
	// ESTALE so the frontend restarts from 0.
	a.nsMu.RLock()
	defer a.nsMu.RUnlock()
	dir, eno := a.item(req.Dir)
	if eno != 0 {
		return nil, eno
	}
	resume := uint64(0)
	if req.Cookie != 0 {
		cursor, ok := decodeEnumerationCookie(req.Cookie)
		if !ok {
			return nil, darwinESTALE
		}
		resume = cursor
	}
	ents, dirVersion, eno := a.freshDirListing(ctx, dir.path)
	if eno != 0 {
		return nil, eno
	}
	ordered := orderEnumeration(ents)
	start := sort.Search(len(ordered), func(i int) bool { return ordered[i].cursor > resume })
	rep, eno := a.enumeratePage(dir.path, ordered, start, dirVersion, int(req.MaxEntries))
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

// enumerationEntry pairs a merged directory entry with its resumption cursor.
type enumerationEntry struct {
	entry  clientcore.DirEntry
	cursor uint64
}

// enumerationCursor maps an entry name to its key in the directory's total
// enumeration order. It is a pure function of the name: independent of the
// listing it was computed from, of any snapshot, and of the daemon process, so
// a cookie minted from it stays meaningful while entries around it come and go.
func enumerationCursor(name string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return 1 + h.Sum64()%enumerateCursorSpace
}

// orderEnumeration puts the merged listing into the daemon's enumeration order
// -- ascending name cursor, ties broken by name -- and hands every entry a
// strictly increasing key. Enumeration order is therefore a deterministic
// function of the name set alone (POSIX leaves readdir order to the file
// system; every consumer that wants alphabetical order sorts for itself).
//
// The strictly-increasing fixup only ever fires when two names collide in the
// 61-bit cursor space; it keeps "resume at the first cursor greater than the
// cookie" from skipping the colliding twin. The one residual case it cannot
// cover is a colliding pair whose FIRST member is deleted while a cookie
// naming it is outstanding, which drops the survivor back to its natural
// cursor and skips it: that needs a 61-bit hash collision inside a single
// directory and a concurrent delete on exactly that name.
func orderEnumeration(ents []clientcore.DirEntry) []enumerationEntry {
	ordered := make([]enumerationEntry, 0, len(ents))
	for _, e := range ents {
		ordered = append(ordered, enumerationEntry{entry: e, cursor: enumerationCursor(e.Name)})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].cursor != ordered[j].cursor {
			return ordered[i].cursor < ordered[j].cursor
		}
		return ordered[i].entry.Name < ordered[j].entry.Name
	})
	for i := 1; i < len(ordered); i++ {
		if ordered[i].cursor <= ordered[i-1].cursor {
			ordered[i].cursor = ordered[i-1].cursor + 1
		}
	}
	return ordered
}

func (a *attach) enumeratePage(dir string, ordered []enumerationEntry, start int, dirVersion uint64, limit int) (*pfslocal.EnumerateReply, int32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if start > len(ordered) {
		start = len(ordered)
	}
	if limit <= 0 || start+limit > len(ordered) {
		limit = len(ordered) - start
	}
	out := make([]pfslocal.DirEntry, 0, limit)
	for i := start; i < start+limit; i++ {
		e := ordered[i].entry
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
		// The final entry of the listing carries cookie 0: end of directory.
		// Every other entry carries its own cursor, which resumes strictly
		// after it.
		cookie := uint64(0)
		if i < len(ordered)-1 {
			var ok bool
			cookie, ok = encodeEnumerationCookie(ordered[i].cursor)
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
	return &pfslocal.EnumerateReply{Entries: out, NextCookie: next, DirVersion: dirVersion}, 0
}

func encodeEnumerationCookie(cursor uint64) (uint64, bool) {
	if cursor == 0 || cursor > enumerateCursorMax {
		return 0, false
	}
	return enumerateCookieMarker | (cursor << 2) | enumerateCookieTagCursor, true
}

func decodeEnumerationCookie(cookie uint64) (uint64, bool) {
	if cookie&enumerateCookieMarker == 0 {
		return 0, false
	}
	if cookie&enumerateCookieTagMask != enumerateCookieTagCursor {
		return 0, false
	}
	cursor := (cookie &^ enumerateCookieMarker) >> 2
	if cursor == 0 {
		return 0, false
	}
	return cursor, true
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
	if req.SetFlags && !vol.SupportsFlagPersistence() {
		// AUTHORITY-BACKED arm only: control reaches here exactly when the
		// target is NOT a graft (the rec.graft branch above returned already,
		// and it must stay above this — a graft's backing is a real host inode
		// whose chflags(2) needs no authority feature, so routing it through
		// this check would refuse a change that works).
		//
		// This authority has nowhere to store a flag word. Refuse the WHOLE
		// setattr before anything is applied: consuming the other groups and
		// dropping this one would report a success the next getattr
		// contradicts.
		//
		// This is the PER-TARGET decision, and it is the daemon's alone —
		// only this layer knows what backs the object. The frontend's own
		// gate answers a different question (does the daemon on the wire
		// PARSE set_flags at all — Capabilities.FlagsUnderstood), because a
		// daemon predating those appended fields discards a forwarded flags
		// change entirely and answers success, a refusal only the frontend is
		// positioned to make. Neither gate substitutes for the other.
		return nil, darwinENOTSUP
	}
	cr := clientcore.SetattrRequest{}
	if req.SetFlags {
		cr.Flags, cr.SetFlags = req.Flags, true
	}
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
		if req.Append && write {
			// A graft is a machine-local path: the host kernel enforces
			// O_APPEND atomicity for it, so carry the flag onto the real fd.
			flags |= os.O_APPEND
		}
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
		h := a.newLocalHandleLocked(rec.path, rec.item.ItemID, file, write, req.Append && write)
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
	h := a.newHandleLocked(rec.path, rec.item.ItemID, rec.state, write, req.Append && write)
	a.mu.Unlock()
	return &pfslocal.OpenReply{Handle: h}, 0
}

// close retires one descriptor. IT IS BOUNDED LOCAL BOOKKEEPING AND NEVER A
// DRAIN BARRIER: admitted write-back belongs to the engine and ships in the
// background, so close(2) returns after WAL admission exactly like every other
// filesystem. fsync, synchronize (the FSKit volume barrier), unmount and a
// delegation recall remain the only places a caller waits for the tail.
// Because the pfslocal client shares one framework callback's operation ID
// with every request that callback issues, a close can arrive as a
// continuation of a publishing callback; beginLogicalOperation admits such
// requests permanently suspended so they can never queue behind an
// overlapping delegation handoff and, through it, behind that scope's drain.
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

// write executes a request whose lane, credit and every delegation transition
// the DISPATCHER already resolved — before a single frontend lock, in the same
// phase 1 every namespace mutation is admitted in (frontend.go).
//
// The write path had its own admission loop here, one layer below the frontend
// mirrors, and that was an order inversion the moment metadata admission moved
// above them: a write held a name-stripe mirror while waiting for a transition
// claim, and a namespace mutation held a conflicting claim while waiting for
// that same stripe. There is one admission point for the whole daemon, and it is
// the dispatcher's; the unwind loop lives there too.
func (a *attach) write(ctx context.Context, req *pfslocal.WriteRequest) (*pfslocal.WriteReply, int32) {
	return a.writeLocked(ctx, req, writeGrantOf(ctx, req.Data))
}

func (a *attach) writeLocked(
	ctx context.Context,
	req *pfslocal.WriteRequest,
	data []byte,
) (*pfslocal.WriteReply, int32) {
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
	// O_APPEND is a property of the open file description OR of this one
	// request. Either way the offset is resolved at EOF by whoever owns the
	// serialization (host kernel for a graft, authority/delegation otherwise)
	// — never by the frontend, which can only ever hold a cached size. Two
	// machines that each compute "EOF" from their own view write the same
	// byte range and one record is destroyed; that is exactly the
	// cross-machine append corruption this routing exists to prevent.
	//
	// PLATFORM CONSTRAINT: macOS FSKit cannot set this bit. It surfaces no
	// append intent to an extension — FSVolumeOpenModes is Read|Write only,
	// and writeContents:toFile:atOffset: carries an off_t the KERNEL already
	// resolved against its own cached vnode size. Appends from that frontend
	// therefore arrive here as ordinary positional writes and stay exposed to
	// the collision. Frontends that DO hold the intent (FUSE today, any
	// future FSKit that surfaces it) opt in and get serialized,
	// authority-assigned offsets.
	appendWrite := h.appendOnly || req.Append
	if h.file != nil {
		var wrote int
		var err error
		switch {
		case h.appendOnly:
			// The fd carries O_APPEND, so the host kernel resolves EOF and
			// commits atomically. WriteAt is invalid on such an fd (ESPIPE on
			// Darwin); Write is the only positionless form.
			wrote, err = h.file.Write(data)
		case appendWrite:
			// Per-request append on a descriptor that was not opened O_APPEND.
			// A graft is machine-local, so the worst exposure is two handles
			// on this one daemon; resolve EOF as late as possible.
			var end int64
			if end, err = h.file.Seek(0, io.SeekEnd); err == nil {
				wrote, err = h.file.WriteAt(data, end)
			}
		default:
			wrote, err = h.file.WriteAt(data, int64(req.Offset))
		}
		// A host short write reports both a count and an error. The count is
		// committed progress and outranks the error for exactly the reason a
		// post-commit failure does: reporting zero invites a retry that
		// duplicates an append.
		if err != nil && wrote <= 0 {
			return nil, localErrno(err)
		}
		var attr fsproto.Attr
		fi, serr := h.file.Stat()
		if serr == nil {
			attr = localAttr(fi)
		} else if wrote <= 0 {
			return nil, localErrno(serr)
		}
		return a.writeReplyWithAttr(h, scope, detached, wrote, attr, serr == nil)
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return nil, eno
	}
	var n int
	var st clientcore.Status
	switch {
	case appendWrite && detached:
		n, st = vol.AppendExactHandle(ctx, h.state, data)
	case appendWrite:
		n, st = vol.WriteAppendOpenHandle(ctx, scope, h.state, data)
	case detached:
		n, st = vol.WriteExactHandle(ctx, h.state, int64(req.Offset), data)
	default:
		n, st = vol.WriteOpenHandle(ctx, scope, h.state, int64(req.Offset), data)
	}
	if n <= 0 {
		if clientcore.LaneChanged(st) {
			// The classifier's lane no longer holds and the engine refused to
			// transition under these locks. Nothing was attempted; unwind.
			return nil, errnoLaneChanged
		}
		if st != fsproto.OK {
			return nil, toDarwinErr(st)
		}
		if len(data) > 0 {
			// A non-empty write that committed NOTHING and reported no error.
			//
			// There is no such POSIX outcome. write(2) returns a positive count,
			// or -1 with an errno; a successful zero is a statement the caller
			// cannot act on — it is not a short write (no progress to resume
			// from) and it is not a refusal (no reason to report), so a writer
			// loop either spins forever or silently drops the buffer. The
			// pre-lock classifier already refuses to hand out a zero-length
			// grant for exactly this reason (clientcore.AdmitWrite).
			//
			// So zero progress on a non-empty payload is EIO, and the guard is
			// on len(data) rather than on the count: a genuine write(fd, buf, 0)
			// is a legitimate successful zero-byte write and must stay one.
			// Positive counts remain short writes, which resume correctly.
			//
			// The FUSE frontend applies the identical rule in
			// fuseNode.writeOnce; the two frontends must not disagree about what
			// "nothing happened" looks like to an application.
			return nil, darwinEIO
		}
		// An empty payload: nothing was asked for and nothing committed. The
		// attribute half is answered on its own terms below.
	}
	return a.writeReply(ctx, vol, h, scope, detached, n)
}

// writeReply builds the reply for a write that has already run, and is the one
// place the write path's two halves are separated.
//
// `Written` is the POSIX outcome. Once the bytes are committed it is DECIDED,
// and no step after the commit may change it. `Attr` is a cache fill, produced
// by operations that fail on their own terms — an attribute round trip, a
// registry lookup, the binding journal.
//
// Collapsing the two is a data-corruption bug, not a cosmetic one. The daemon
// answers with a body or an errno, never both, so returning an errno after a
// commit tells the application "this write did nothing" about bytes that are
// already in the WAL. The application retries, and on an O_APPEND descriptor
// the retry resolves EOF a second time — it cannot land on the first copy — so
// the record appears TWICE and no layer below can tell it was one write. A
// transient disk error must not be able to duplicate an append.
//
// When the attribute half cannot be refreshed the reply carries the attributes
// already registered for the handle's own item. That is truthful about what the
// daemon knows and publishes NO new identity: the item is the one the kernel
// addressed this very write with, so it is already known and already binding-
// durable. The staleness costs nothing, because the daemon never serves
// getattr(2) from this record — every getattr goes to the volume (see
// attach.getattr) — so the next attribute read corrects it. If even that record
// is gone the reply carries no attributes at all rather than inventing any; the
// frontends already treat a write reply's attributes as a hint and fall back to
// their own snapshot.
func (a *attach) writeReply(
	ctx context.Context,
	vol *clientcore.Volume,
	h *handleRecord,
	scope string,
	detached bool,
	n int,
) (*pfslocal.WriteReply, int32) {
	attr, st := vol.GetattrOpenHandle(ctx, scope, h.state)
	if st != fsproto.OK && n <= 0 {
		return nil, toDarwinErr(st)
	}
	return a.writeReplyWithAttr(h, scope, detached, n, attr, st == fsproto.OK)
}

// writeReplyWithAttr is writeReply's shared tail, reached once the write's own
// count and its attribute refresh have each reported independently. refreshed
// says whether attr is a fresh observation or must be replaced by what the
// daemon already holds.
func (a *attach) writeReplyWithAttr(
	h *handleRecord,
	scope string,
	detached bool,
	n int,
	attr fsproto.Attr,
	refreshed bool,
) (*pfslocal.WriteReply, int32) {
	committed := n > 0

	a.mu.Lock()
	var rec *itemRecord
	if refreshed {
		rec = a.registerHandleAttrLocked(h, attr)
	}
	if rec == nil {
		// No refresh, or the handle's binding no longer resolves: answer from
		// the item the kernel already holds for this handle.
		if known := a.items[h.itemID]; known != nil {
			rec, attr = known, known.attr
		}
	}
	var reply pfslocal.Attr
	if rec != nil {
		reply = a.localAttrForRecordPathLocked(attr, rec, scope, detached)
	}
	a.mu.Unlock()

	if rec == nil && !committed {
		return nil, darwinEIO
	}
	// The binding journal's own contract makes a failed append a correctness
	// failure that fails the frontend gate closed (failBindingPersistence), so
	// the mount is already going down and the next operation gets a definite
	// error. That is exactly why this reply must still be honest about the
	// bytes: it is the application's last chance to learn they are committed.
	if eno := a.flushBindingDelta(); eno != 0 && !committed {
		return nil, eno
	}
	return &pfslocal.WriteReply{Written: uint32(n), Attr: reply}, 0
}

// errnoLaneChanged is the internal unwind signal. It is not an errno: it is
// negative, so it can never collide with a Darwin errno, and it never leaves
// attach.write.
const errnoLaneChanged int32 = -1

// admitWrite runs one write request's COMPLETE lane resolution before the
// handler takes a.nsMu, the handle operation gate, or a.mu for anything but the
// two non-waiting lookups it needs to identify the request.
//
// Why here and not in the engine. Engine.WriteAt/WriteAppend resolve their own
// lane, which is correct for a caller holding nothing — but this handler calls
// them under a.nsMu.RLock. Go's RWMutex is writer-preferring: anything that
// blocks on the read side parks the next nsMu.Lock (rename, remove, delegation
// reclaim), and every lookup, getattr and read arriving after it queues behind
// THAT. One slow uplink becomes a namespace-wide stall on paths with nothing to
// do with the backlog.
//
// And the lane resolution is exactly what blocks. Reaching the delegated lane
// can mean draining an ancestor grant's whole unshipped tail and releasing it
// durably, or acquiring a grant over an authority round trip; reaching the
// authority lane can mean releasing whatever covers the path — the same drain.
// Moving the credit wait alone was not enough, because those transitions stayed
// behind. What crosses into the locked region now is a fully decided answer.
//
// It returns the operation context, the prefix of the request the caller may
// write, a settle that releases everything the classification took, and an
// errno for a definite refusal. settle is always non-nil and must be deferred
// BEFORE the errno is checked.
//
// Requests that cannot reach the write-back WAL are identified here and passed
// through unclassified, so the handler produces its own exact errno instead of
// inheriting one from admission: an empty payload, a graft handle writing a
// host file directly, an unwritable handle, and a request whose handle or
// volume no longer resolves. Everything else goes to Volume.AdmitWrite, which
// decides the lane from NODE IDENTITY as well as delegation state — a pathname
// alone cannot see that an inode is orphaned or hard linked, and both of those
// are authority-only by construction.
//
// forceAuthority is the unwind's terminator: on the second pass the authority
// lane is taken unconditionally, so that attempt has no lane left to lose.
func (a *attach) admitWrite(
	ctx context.Context,
	req *pfslocal.WriteRequest,
	forceAuthority bool,
) (context.Context, func(), int32, bool) {
	noop := func() {}
	if len(req.Data) == 0 {
		return ctx, noop, 0, false
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		return ctx, noop, 0, false
	}
	h, scope, herr := a.handleTarget(req.Handle)
	if herr != 0 || h.file != nil || !h.write {
		return ctx, noop, 0, false
	}
	opCtx, granted, settle, err := vol.AdmitWrite(ctx, scope, h.state, len(req.Data), forceAuthority)
	if err != nil {
		settle()
		return ctx, noop, creditErrno(err), true
	}
	// A short grant is a healthy outcome, not a failure: the handler writes
	// exactly the granted prefix and the reply's written count tells the kernel
	// to reissue the rest as a fresh operation, classified from scratch. The
	// FSKit adapter already loops on a short count (VolumeCore.write) and FUSE
	// replies support short writes natively.
	return context.WithValue(opCtx, writeGrantKey{}, granted), settle, 0, true
}

// writeGrantKey carries the admitted byte count from the dispatcher's pre-lock
// admission to the handler that runs under the locks.
type writeGrantKey struct{}

func writeGrantOf(ctx context.Context, data []byte) []byte {
	granted, ok := ctx.Value(writeGrantKey{}).(int)
	if !ok || granted >= len(data) {
		return data
	}
	return data[:granted]
}

// creditErrno is the frontend's POSIX classification of a refused admission.
// ENOSPC means this store can never fit the operation. A far end that stopped
// answering is EIO — never ENOSPC, or an application learns to delete files to
// fix a network partition. A cancelled request is EINTR, which is what the
// kernel already means by an interrupted operation.
func creditErrno(err error) int32 {
	switch {
	case errors.Is(err, writeback.ErrNoSpace):
		return darwinENOSPC
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return darwinEINTR
	default:
		// writeback.ErrUplinkStalled and every lifecycle refusal.
		return darwinEIO
	}
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
		if req.Append {
			flags |= os.O_APPEND
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
		h := a.newLocalHandleLocked(p, rec.item.ItemID, file, true, req.Append)
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
	h := a.newHandleLocked(p, rec.item.ItemID, rec.state, true, req.Append)
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
