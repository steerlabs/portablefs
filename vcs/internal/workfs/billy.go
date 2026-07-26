package workfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"time"

	"github.com/go-git/go-billy/v5"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// ---- os.FileInfo (value snapshot, immutable) ----

type fileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	mtime   time.Time
	ctime   time.Time
	atime   time.Time
	uid     uint32
	gid     uint32
	nlink   uint32
	ino     uint64
	version uint64
}

func (fi fileInfo) Name() string       { return fi.name }
func (fi fileInfo) Size() int64        { return fi.size }
func (fi fileInfo) Mode() os.FileMode  { return fi.mode }
func (fi fileInfo) ModTime() time.Time { return fi.mtime }
func (fi fileInfo) IsDir() bool        { return fi.mode.IsDir() }
func (fi fileInfo) ChangeTime() time.Time {
	return fi.ctime
}
func (fi fileInfo) AccessTime() time.Time {
	return fi.atime
}

// OwnerIDs exposes POSIX ownership via Sys(); a consumer (the FUSE protocol layer)
// type-asserts this interface. Sys returns the fileInfo itself so the assertion
// succeeds; the NFS server, which expects a *syscall.Stat_t, simply falls back to
// root as before (no regression).
func (fi fileInfo) OwnerIDs() (uint32, uint32) { return fi.uid, fi.gid }

// LinkCount exposes the POSIX hard-link count via Sys() (same type-assert pattern as
// OwnerIDs). A live inode MUST report a non-zero count: a zero st_nlink reads as
// "unlinked while open" to the kernel and to apps like SQLite, which then discard their
// view of the file. See linkCount for the value.
func (fi fileInfo) LinkCount() uint32 { return fi.nlink }

// Ino exposes the stable inode identity via Sys() (same type-assert pattern as OwnerIDs/LinkCount),
// so the FUSE protocol layer can report st_ino = the authority-assigned id rather than a path hash.
func (fi fileInfo) Ino() uint64 { return fi.ino }
func (fi fileInfo) Sys() any    { return fi }

// Version exposes the inode's per-inode version (same Sys() type-assert pattern as Ino), so the
// readdir handler can stamp each Dirent for the mount's version-safe readdir-plus attr cache fill.
func (fi fileInfo) Version() uint64 { return fi.version }

func (fs *FS) infoOf(n *inode) fileInfo {
	mtime, ctime, atime := inodeTimes(n)
	return fileInfo{name: n.name, size: n.curSize(), mode: n.mode, mtime: mtime, ctime: ctime, atime: atime, uid: n.uid, gid: n.gid, nlink: fs.liveLinkCountLocked(n), ino: n.ino, version: n.version}
}

// direntName is the entry name a path-addressed stat reports: the final
// component of the cleaned path ("" for the root). Inodes carry no unique
// name once hard links exist, so a handle-addressed FileInfo name derives
// from the dirent/path the caller resolved through.
func direntName(name string) string {
	clean := cleanPath(name)
	if clean == "" {
		return ""
	}
	return path.Base(clean)
}

// infoOfNamed builds a FileInfo reporting the entry name the caller resolved
// through, so a hard-linked inode reachable by several names stats correctly
// under each name (its stable ino is identical, its nlink is the shared
// reference count).
func (fs *FS) infoOfNamed(n *inode, name string) fileInfo {
	mtime, ctime, atime := inodeTimes(n)
	return fileInfo{name: name, size: n.curSize(), mode: n.mode, mtime: mtime, ctime: ctime, atime: atime, uid: n.uid, gid: n.gid, nlink: fs.liveLinkCountLocked(n), ino: n.ino, version: n.version}
}

// liveLinkCountLocked is linkCount with open-after-unlink truth: a PARKED
// non-directory inode has ZERO directory entries and must report st_nlink 0
// (POSIX fstat after the last unlink; SQLite and kernels key off it), while
// a NAMED inode keeps the legacy zero-means-unset coercion to 1 so a live
// pre-nlink manifest inode is never mistaken for unlinked. Caller holds
// fs.mu (read or write).
func (fs *FS) liveLinkCountLocked(n *inode) uint32 {
	if n.kind != "directory" && fs.orphans[n.ino] == n {
		return 0
	}
	return linkCount(n)
}

// linkCount returns the POSIX hard-link count of an inode: for a file or
// symlink the tracked reference count (the number of directory entries that
// name it — 1 unless OpLink added aliases; a zero legacy/unset value reads as
// 1 so a live inode is never mistaken for an unlinked one), and for a
// directory 2 + (number of child subdirectories): its own "." entry, the
// parent's named entry for it, and one ".." back-reference from each child
// directory. The accurate directory count keeps GNU find's leaf optimization
// (subdir_count == nlink-2) correct. Caller holds fs.mu (read or write).
func linkCount(n *inode) uint32 {
	if n.kind != "directory" {
		if n.nlink == 0 {
			return 1
		}
		return n.nlink
	}
	if n.base != nil {
		// Lazily bound base directory: the subdirectory count is unknown
		// until enumeration completes. Report the conventional "do not
		// trust nlink-2" value 1 (btrfs-style), which readdir consumers
		// treat as an explicit unknown, instead of an undercount that
		// would wrongly enable the leaf optimization.
		return 1
	}
	nlink := uint32(2)
	for _, c := range n.children {
		if c.kind == "directory" {
			nlink++
		}
	}
	return nlink
}

// ---- billy.File ----

type file struct {
	fs       *FS
	n        *inode
	name     string
	pos      int64
	writable bool
}

func (f *file) Name() string { return f.name }

func (f *file) Read(p []byte) (int, error) {
	nr, err := f.fs.readAt(f.n, p, f.pos)
	f.pos += int64(nr)
	return nr, err
}

func (f *file) ReadAt(p []byte, off int64) (int, error) { return f.fs.readAt(f.n, p, off) }

func (f *file) Write(p []byte) (int, error) {
	if !f.writable {
		return 0, os.ErrPermission
	}
	if err := f.fs.writeAt(f.name, f.pos, p); err != nil {
		return 0, err
	}
	f.pos += int64(len(p))
	return len(p), nil
}

func (f *file) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		f.pos = offset
	case io.SeekCurrent:
		f.pos += offset
	case io.SeekEnd:
		f.pos = f.fs.size(f.n) + offset
	default:
		return 0, os.ErrInvalid
	}
	if f.pos < 0 {
		f.pos = 0
	}
	return f.pos, nil
}

func (f *file) Truncate(size int64) error {
	if !f.writable {
		return os.ErrPermission
	}
	return f.fs.mutate(wal.Record{Op: wal.OpTruncate, Path: f.name, Size: size})
}

func (f *file) Close() error  { return nil }
func (f *file) Lock() error   { return nil }
func (f *file) Unlock() error { return nil }

// ---- FS helpers used by file ----

func (fs *FS) writeAt(name string, off int64, data []byte) error {
	// Warm the base blocks this write read-modifies into the content cache OUTSIDE
	// fs.mu, so the apply below doesn't fetch from the backend while holding the lock
	// (which would stall every other writer for a backend round-trip).
	fs.warmBaseForWrite(name, off, int64(len(data)))
	return fs.mutate(wal.Record{Op: wal.OpWrite, Path: name, Offset: off, Data: append([]byte(nil), data...)})
}

func (fs *FS) size(n *inode) int64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return n.curSize()
}

// ---- billy.Filesystem ----

func (fs *FS) Open(name string) (billy.File, error) { return fs.OpenFile(name, os.O_RDONLY, 0) }

func (fs *FS) OpenFile(name string, flag int, perm os.FileMode) (billy.File, error) {
	writable := flag&(os.O_WRONLY|os.O_RDWR) != 0
	var n *inode
	if err := fs.withReadPath(name, func(resolved *inode) error {
		n = resolved
		return nil
	}); err != nil {
		return nil, err
	}

	if n == nil {
		if flag&os.O_CREATE == 0 {
			return nil, os.ErrNotExist
		}
		if perm == 0 {
			perm = 0o644
		}
		if err := fs.mutate(wal.Record{Op: wal.OpCreate, Path: name, Mode: modeToUnix(perm)}); err != nil {
			return nil, err
		}
		fs.mu.RLock()
		n = fs.resolve(name)
		fs.mu.RUnlock()
		if n == nil {
			return nil, os.ErrInvalid
		}
		writable = true
	} else if flag&os.O_TRUNC != 0 && writable {
		if err := fs.mutate(wal.Record{Op: wal.OpTruncate, Path: name, Size: 0}); err != nil {
			return nil, err
		}
	}

	f := &file{fs: fs, n: n, name: name, writable: writable}
	if flag&os.O_APPEND != 0 {
		f.pos = fs.size(n)
	}
	return f, nil
}

func (fs *FS) Create(name string) (billy.File, error) {
	return fs.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
}

func (fs *FS) Stat(name string) (os.FileInfo, error) { return fs.Lstat(name) }

func (fs *FS) Lstat(name string) (os.FileInfo, error) {
	var fi os.FileInfo
	err := fs.withReadPath(name, func(n *inode) error {
		if n == nil {
			return os.ErrNotExist
		}
		fi = fs.infoOfNamed(n, direntName(name))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fi, nil
}

func (fs *FS) ReadDir(p string) ([]os.FileInfo, error) {
	// Resolve (hydrating lazy path components), then — for a lazily bound
	// base directory — enumerate its remaining base pages OUTSIDE the lock
	// before listing. Completion is monotone: a completed directory never
	// regains a lazy binding, so one load suffices.
	var dir *inode
	if err := fs.withReadPath(p, func(n *inode) error {
		if n == nil {
			return os.ErrNotExist
		}
		if n.kind != "directory" {
			return errors.New("vcs: not a directory")
		}
		dir = n
		return nil
	}); err != nil {
		return nil, err
	}
	if err := fs.completeDirForRead(dir); err != nil {
		return nil, err
	}
	n := dir
	fs.mu.RLock()
	mtime, ctime, atime := n.mtime, n.ctime, n.atime
	names := make([]string, 0, len(n.children))
	for name := range n.children {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]os.FileInfo, 0, len(names))
	for _, name := range names {
		// Report the DIRENT name, not the inode's primary name: a
		// hard-linked inode appears correctly under each of its names.
		out = append(out, fs.infoOfNamed(n.children[name], name))
	}
	fs.mu.RUnlock()
	fs.updateAtimeRelatime(n, mtime, ctime, atime)
	return out, nil
}

func (fs *FS) Readlink(link string) (string, error) {
	var target string
	var n *inode
	var mtime, ctime, atime time.Time
	err := fs.withReadPath(link, func(resolved *inode) error {
		if resolved == nil {
			return os.ErrNotExist
		}
		if resolved.kind != "symlink" {
			return errors.New("vcs: not a symlink")
		}
		n = resolved
		target = resolved.linkTarget
		mtime, ctime, atime = resolved.mtime, resolved.ctime, resolved.atime
		return nil
	})
	if err != nil {
		return "", err
	}
	fs.updateAtimeRelatime(n, mtime, ctime, atime)
	return target, nil
}

func (fs *FS) Rename(oldName, newName string) error {
	return fs.mutate(wal.Record{Op: wal.OpRename, Path: oldName, NewPath: newName})
}

func (fs *FS) Remove(name string) error {
	return fs.mutate(wal.Record{Op: wal.OpRemove, Path: name})
}

func (fs *FS) MkdirAll(name string, perm os.FileMode) error {
	return fs.mutate(wal.Record{Op: wal.OpMkdir, Path: name, Mode: modeToUnix(perm)})
}

func (fs *FS) Symlink(target, link string) error {
	return fs.mutate(wal.Record{Op: wal.OpSymlink, Path: link, Target: target})
}

// Link creates a hard link newPath referencing the same inode as the existing
// non-directory oldPath (POSIX link(2)). EEXIST if newPath exists, EPERM for a
// directory source, ENOENT for a missing source or destination parent.
func (fs *FS) Link(oldPath, newPath string) error {
	return fs.LinkAs(oldPath, newPath, "")
}

// LinkAs is Link with an originating owner stamped on the published
// invalidation (race-free self-suppression), matching MutateAs.
func (fs *FS) LinkAs(oldPath, newPath, owner string) error {
	return fs.MutateAs(wal.Record{Op: wal.OpLink, Path: oldPath, NewPath: newPath}, owner)
}

// ---- billy.Change: chmod / chtimes / chown persist (uid/gid are carried through the
// manifest and tree hash). Routed by both the NFS server and the custom protocol. ----

var _ billy.Change = (*FS)(nil)

func (fs *FS) Chmod(name string, mode os.FileMode) error {
	return fs.mutate(wal.Record{Op: wal.OpChmod, Path: name, Mode: modeToUnix(mode)})
}

func (fs *FS) Chtimes(name string, atime, mtime time.Time) error {
	return fs.mutate(wal.Record{Op: wal.OpChtimes, Path: name, MtimeMs: mtime.UnixMilli()})
}

// Chown sets a file's owner/group. A uid or gid of -1 means "leave unchanged"
// (POSIX), so the current value is preserved. Symlinks are inert in this tree, so
// Lchown is equivalent. The read of the current uid/gid and the apply are performed
// under a SINGLE fs.mu hold (via commitMutationLocked) so a concurrent chown+chgrp
// cannot read the same baseline and clobber each other's field (a lost update).
func (fs *FS) Chown(name string, uid, gid int) error { return fs.ChownAs(name, uid, gid, "") }

// ChownAs is Chown with the originating owner stamped on the published invalidation (so the
// authority source-suppresses the echo back to that mount). The read of the current uid/gid
// and the apply stay under one fs.mu hold, so a concurrent chown+chgrp cannot clobber each
// other's field (a lost update).
func (fs *FS) ChownAs(name string, uid, gid int, owner string) error {
	return fs.ChownHandleAs(name, 0, uid, gid, owner)
}

// ChownHandleAs is ChownAs addressed by stable ino when ino is non-zero. It is used by
// write-through open-fd setattr so a stale path cannot target a recreated inode generation.
func (fs *FS) ChownHandleAs(name string, ino uint64, uid, gid int, owner string) error {
	fs.mu.Lock()
	n := fs.resolveForRW(name, ino)
	if n == nil {
		fs.mu.Unlock()
		return os.ErrNotExist
	}
	newUID, newGID := n.uid, n.gid
	if uid >= 0 {
		newUID = uint32(uid)
	}
	if gid >= 0 {
		newGID = uint32(gid)
	}
	r := wal.Record{Op: wal.OpChown, Path: name, Ino: ino, UID: newUID, GID: newGID}
	_, err := fs.commitMutationLocked(r, owner) // resolves the read-modify-write under one fs.mu hold
	return err
}

// CreateAs ensures name exists (creating it if absent), stamping the originating owner on the
// OpCreate echo so the authority source-suppresses it back to that mount. Mirrors the
// create-if-absent branch of OpenFile; a no-op (no mutation, no echo) if name already exists.
func (fs *FS) CreateAs(name string, perm os.FileMode, owner string) error {
	fs.mu.RLock()
	exists := fs.resolve(name) != nil
	fs.mu.RUnlock()
	if exists {
		return nil
	}
	if perm == 0 {
		perm = 0o644
	}
	return fs.MutateAs(wal.Record{Op: wal.OpCreate, Path: name, Mode: modeToUnix(perm)}, owner)
}

// TruncateAs truncates an existing file to size, stamping the originating owner on the
// OpTruncate echo.
func (fs *FS) TruncateAs(name string, size int64, owner string) error {
	return fs.TruncateHandleAs(name, 0, size, owner)
}

// TruncateHandleAs truncates an existing file by stable ino when ino is non-zero, carrying Path only
// as the coherence invalidation name. A missing ino/path returns ErrNotExist and never creates.
func (fs *FS) TruncateHandleAs(name string, ino uint64, size int64, owner string) error {
	fs.mu.RLock()
	exists := fs.resolveForRW(name, ino) != nil
	fs.mu.RUnlock()
	if !exists {
		return os.ErrNotExist
	}
	return fs.MutateAs(wal.Record{Op: wal.OpTruncate, Path: name, Ino: ino, Size: size}, owner)
}

func (fs *FS) Lchown(name string, uid, gid int) error { return fs.Chown(name, uid, gid) }

func (fs *FS) TempFile(dir, prefix string) (billy.File, error) {
	name := path.Join(dir, fmt.Sprintf("%s%d", prefix, time.Now().UnixNano()))
	return fs.Create(name)
}

func (fs *FS) Join(elem ...string) string { return path.Join(elem...) }
func (fs *FS) Root() string               { return "/" }

func (fs *FS) Chroot(p string) (billy.Filesystem, error) {
	if cleanPath(p) == "" {
		return fs, nil
	}
	return nil, errors.New("vcs: chroot to a subdirectory is not supported on a writable mount")
}

func (fs *FS) Capabilities() billy.Capability {
	return billy.WriteCapability | billy.ReadCapability | billy.SeekCapability | billy.TruncateCapability
}
