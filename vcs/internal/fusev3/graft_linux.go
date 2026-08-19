//go:build linux

package fusev3

import (
	"errors"
	"math"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"golang.org/x/sys/unix"
)

const (
	// graftEntryTimeout is the kernel entry and attribute lifetime published for
	// a machine-local path. The authority side of this mount pays for its
	// lifetimes by joining the visibility barrier; a graft owes nothing to that
	// barrier and takes nothing from it, because there is no second machine that
	// can change its backing. Every mutation of a graft flows through this one
	// kernel, which updates its own dcache and attribute cache synchronously
	// from the reply to the syscall that made it, so a time box here can never
	// serve a result another machine has already invalidated. One second is the
	// conventional loopback-filesystem value and is what the CLI mount publishes
	// for the same paths, so the two clients agree.
	//
	// It is deliberately independent of authority cache lifetimes. A graft has
	// no state the authority or another machine can change underneath this
	// kernel, so re-deriving its local-only facts through the authority would be
	// both impossible and wasteful.
	graftEntryTimeout = time.Second

	// graftDirOffsetBase reserves the top bit of the READDIR offset space for
	// the route roots merged into a volume directory's listing. The authority
	// numbers its directory cookies from zero upwards, so the two spaces cannot
	// meet; a cookie that ever did carry this bit is refused rather than
	// silently aliased onto a merged entry.
	graftDirOffsetBase = uint64(1) << 63

	// graftPathDepthLimit bounds the walk that turns an interned object back
	// into a volume path. The parent chain is a tree by construction, so this is
	// reached only if that invariant has already been broken, and it is far
	// beyond any real directory nesting.
	graftPathDepthLimit = 4096

	// graftXattrErrno is what an extended-attribute request against a
	// machine-local path answers. No PortableFS client carries extended
	// attributes across the route boundary, so reporting that this filesystem
	// does not support them is the truth rather than a claim that the attribute
	// merely does not exist.
	graftXattrErrno = syscall.EOPNOTSUPP
)

// graftHandle is one open machine-local file. The descriptor is the mount's
// own, duplicated out of the confined backing capability, so it keeps working
// after the route root is removed and recreated -- exactly like an open fd on a
// local filesystem, which is the whole point of serving these paths locally.
type graftHandle struct {
	fd   int
	once sync.Once
}

func (h *graftHandle) close() syscall.Errno {
	var errno syscall.Errno
	h.once.Do(func() {
		if err := unix.Close(h.fd); err != nil {
			errno = errnoOfError(err)
		}
	})
	return errno
}

// graftDirHandle is one open machine-local directory. The listing is a snapshot
// taken at OPENDIR, which is the same guarantee an ordinary local filesystem
// gives a directory stream and what makes offset-based resumption exact.
type graftDirHandle struct {
	mu      sync.Mutex
	entries []fuse.DirEntry
	index   int
}

func errnoOfError(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	if errno, ok := err.(syscall.Errno); ok {
		return errno
	}
	return syscall.EIO
}

// graftKind maps a backing stat mode onto the object kind this frontend interns
// by. Kind is part of the interning key so that a backing inode number reused
// for a different object type cannot be confused with the old one.
func graftKind(mode uint32) authoritypb.Attr_Kind {
	switch mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		return authoritypb.Attr_DIRECTORY
	case syscall.S_IFLNK:
		return authoritypb.Attr_SYMLINK
	default:
		return authoritypb.Attr_REGULAR
	}
}

// fillGraftAttr converts a backing stat into the kernel attribute shape.
//
// The inode number is minted into the marked machine-local range so a grafted
// object and a volume object can never collide in this kernel's caches, and the
// owner is the identity this mount presents for every path it serves: a graft
// is not a different filesystem to the user, and reporting the backing store's
// own ownership would make `ls -l` disagree across the boundary for no reason
// the user can act on.
func fillGraftAttr(st *syscall.Stat_t, out *fuse.Attr, uid, gid uint32) {
	out.FromStat(st)
	out.Ino = localdirs.LocalIno(st.Ino)
	out.Uid, out.Gid = uid, gid
	out.Flags = 0
}

// publishGraftEntry hands one machine-local directory entry to the kernel.
//
// It deliberately does not pass through publishEntry. The cached-name registry
// is the exact set of bindings this mount owes the authority a repair for, and
// a grafted name is not one of them: no authority mutation can ever name it, no
// visibility target can ever resolve to it, and self-revocation must not spend
// its bounded budget withdrawing names nothing could have invalidated. Admitting
// a grafted name there would make the registry an over-estimate, which is the
// one property the repair path is built on it not being.
func (r *rawFileSystem) publishGraftEntry(out *fuse.EntryOut, record *inodeRecord, st *syscall.Stat_t) {
	out.NodeId = record.id
	out.Generation = 1
	out.SetEntryTimeout(graftEntryTimeout)
	out.SetAttrTimeout(graftEntryTimeout)
	fillGraftAttr(st, &out.Attr, r.mount.uid, r.mount.gid)
}

// pathLocked resolves an interned object back to one live volume-relative path.
//
// Paths are what a route matcher decides on, and the authority protocol has
// none: it names objects by capability. The parent chain that answers this is
// therefore maintained for exactly the two kinds of object whose path decides
// how an operation on them is routed -- directories, which have exactly one
// parent and so exactly one path, and machine-local objects.
func (r *rawFileSystem) pathLocked(record *inodeRecord) (string, bool) {
	if record == nil {
		return "", false
	}
	if record.root {
		return "", true
	}
	var reversed []string
	for current := record; !current.root; {
		var key nameKey
		var parent *inodeRecord
		for candidate, candidateParent := range current.aliases {
			key, parent = candidate, candidateParent
			break
		}
		if parent == nil || key.name == "" {
			return "", false
		}
		if len(reversed) == graftPathDepthLimit {
			return "", false
		}
		reversed = append(reversed, key.name)
		current = parent
	}
	total := len(reversed) - 1
	for _, element := range reversed {
		total += len(element)
	}
	path := make([]byte, 0, total)
	for i := len(reversed) - 1; i >= 0; i-- {
		if len(path) != 0 {
			path = append(path, '/')
		}
		path = append(path, reversed[i]...)
	}
	return string(path), true
}

func (r *rawFileSystem) path(record *inodeRecord) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pathLocked(record)
}

// childPath is the volume-relative path of one name in one directory.
func (r *rawFileSystem) childPath(parent *inodeRecord, name string) (string, bool) {
	base, ok := r.path(parent)
	if !ok {
		return "", false
	}
	if base == "" {
		return name, true
	}
	return base + "/" + name, true
}

// dropAliasLocked removes one name from an object's live alias set. A graft
// inode with no remaining name is also removed from the backing-inode index
// immediately. The kernel may retain its NodeID or an open handle after unlink,
// but the backing filesystem is then free to reuse the inode number; leaving the
// dead object indexed would merge that later inode into the stale NodeID.
func (r *rawFileSystem) dropAliasLocked(record *inodeRecord, key nameKey) {
	if record == nil {
		return
	}
	if r.namedRecords[key] == record {
		delete(r.namedRecords, key)
	}
	delete(record.aliases, key)
	if record.graft && len(record.aliases) == 0 && r.graftsByKey[record.key] == record {
		delete(r.graftsByKey, record.key)
	}
}

// bindPathLocked records one live name for an object. Directories have one
// namespace path and converge on the newest binding. Machine-local
// non-directories retain an alias set because hard links are real POSIX aliases,
// not repeated lookups of one preferred path.
func (r *rawFileSystem) bindPathLocked(record *inodeRecord, parent *inodeRecord, name string) {
	if record == nil || parent == nil || record.root || name == "" {
		return
	}
	if !record.graft && record.key.kind != authoritypb.Attr_DIRECTORY {
		// A file's path is never consulted: authority-backed files are named by
		// capability, and a file with several links has no single path to keep.
		return
	}
	key := nameKey{parent: parent.key.inode, name: name}
	if displaced := r.namedRecords[key]; displaced != nil && displaced != record {
		r.dropAliasLocked(displaced, key)
	}
	if record.key.kind == authoritypb.Attr_DIRECTORY {
		for previous := range record.aliases {
			if previous != key {
				r.dropAliasLocked(record, previous)
			}
		}
	}
	if record.aliases == nil {
		record.aliases = make(map[nameKey]*inodeRecord)
	}
	record.aliases[key] = parent
	r.namedRecords[key] = record
	if record.graft {
		r.graftsByKey[record.key] = record
	}
}

// bindPath is called on every operation that resolves or creates a name. It is
// not conditional on routes being configured: a directory's path is also the
// only thing that turns the fencing a parked mount is handed into a message
// naming the directory it was parked in.
func (r *rawFileSystem) bindPath(record *inodeRecord, parent *inodeRecord, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindPathLocked(record, parent, name)
}

// unbindPath forgets where a name used to lead. The object's record survives
// until the kernel forgets it, but the name is gone, and letting the record keep
// claiming it would let an operation on a dead object be routed into whatever
// takes that name next.
func (r *rawFileSystem) unbindPath(parent *inodeRecord, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := nameKey{parent: parent.key.inode, name: name}
	record := r.namedRecords[key]
	if record == nil {
		return
	}
	r.dropAliasLocked(record, key)
}

// rebindRenamed follows a rename this mount performed. The kernel moves the
// dentry without re-resolving it, so nothing else would ever correct the moved
// directory's path, and every route decision under it would keep being made
// against where it used to be.
func (r *rawFileSystem) rebindRenamed(oldParent *inodeRecord, oldName string, newParent *inodeRecord, newName string, exchange bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	from := nameKey{parent: oldParent.key.inode, name: oldName}
	to := nameKey{parent: newParent.key.inode, name: newName}
	moved, replaced := r.namedRecords[from], r.namedRecords[to]
	// Renaming one hard link over another link to the same inode is a no-op: both
	// bindings remain. Treating it as replacement would incorrectly discard one.
	if moved != nil && moved == replaced {
		return
	}
	r.dropAliasLocked(moved, from)
	r.dropAliasLocked(replaced, to)
	if moved != nil {
		r.bindPathLocked(moved, newParent, newName)
	}
	if exchange && replaced != nil {
		r.bindPathLocked(replaced, oldParent, oldName)
	}
}

// internGraft installs one kernel lookup reference for a machine-local object.
//
// Machine-local objects are interned in their own table. Nothing else may find
// them: the visibility machinery resolves coordination identities against the
// authority table, and a graft that appeared there would be a candidate for an
// invalidation it can never need and a repair it can never owe.
func (r *rawFileSystem) internGraft(parent *inodeRecord, name string, st *syscall.Stat_t) (*inodeRecord, syscall.Errno) {
	key := inodeKey{inode: localdirs.LocalIno(st.Ino), kind: graftKind(uint32(st.Mode))}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.graftsByKey[key]; existing != nil {
		if existing.lookups == math.MaxUint64 {
			return nil, syscall.EIO
		}
		existing.lookups++
		r.bindPathLocked(existing, parent, name)
		return existing, 0
	}
	if r.nextNodeID == 0 || r.nextNodeID == fuse.FUSE_ROOT_ID {
		return nil, syscall.EIO
	}
	id := r.nextNodeID
	r.nextNodeID++
	record := &inodeRecord{id: id, key: key, lookups: 1, graft: true}
	r.nodesByID[id] = record
	r.graftsByKey[key] = record
	r.bindPathLocked(record, parent, name)
	return record, 0
}

// route is one name's routing decision: its volume-relative path, and the route
// root that owns it (empty when the authority serves it).
type route struct {
	path string
	root string
}

// routeFor decides which layer serves one name in one directory.
//
// It is the single place the question is asked, and it is asked on every path
// that carries a name -- which is exactly what makes a directory created at a
// matching path a graft root from the instant it is created rather than from
// the next remount.
func (r *rawFileSystem) routeFor(parent *inodeRecord, name string) (route, syscall.Errno) {
	path, ok := r.childPath(parent, name)
	if !ok {
		// A machine-local object or a directory with no resolvable path cannot
		// be routed, and routing it to the authority would send an operation
		// under a graft to the volume. There is no safe default here.
		return route{}, syscall.EIO
	}
	root := r.grafts.Owner(path)
	if root == "" {
		if parent.graft {
			return route{}, syscall.EIO
		}
		return route{path: path}, 0
	}
	if !parent.graft && root != path {
		// The matcher says an ancestor of this name is a route root, but the
		// name was reached through a volume directory -- which can only happen
		// if the two disagree about the topology. Fail closed.
		return route{}, syscall.EIO
	}
	return route{path: path, root: root}, 0
}

// graftLookup resolves one name that a route owns. handled is false only when
// the name belongs to the authority.
func (r *rawFileSystem) graftLookup(parent *inodeRecord, name string, out *fuse.EntryOut) (bool, fuse.Status) {
	resolved, errno := r.routeFor(parent, name)
	if errno != 0 {
		return true, fuse.Status(errno)
	}
	if resolved.root == "" {
		return false, fuse.OK
	}
	st, errno := r.grafts.Lstat(resolved.path)
	if errno != 0 {
		// A rule owns the NAME whether or not anything has created it, so the
		// volume's same-named subtree stays shadowed and this is an honest
		// local negative rather than a fall-through to the authority. Its class
		// bit makes the successful zero-nodeid base reply distinguishable from a
		// SHARED stamped negative without inventing a publication obligation.
		if errno != syscall.ENOENT {
			return true, fuse.Status(errno)
		}
		*out = fuse.EntryOut{}
		out.Attr.Flags = 0
		return true, fuse.OK
	}
	record, errno := r.internGraft(parent, name, &st)
	if errno != 0 {
		return true, fuse.Status(errno)
	}
	r.publishGraftEntry(out, record, &st)
	return true, fuse.OK
}

// graftGetattr answers a stat about a machine-local object.
func (r *rawFileSystem) graftGetattr(record *inodeRecord, fd int, out *fuse.AttrOut) fuse.Status {
	var st syscall.Stat_t
	if fd >= 0 {
		// The descriptor is preferred: a grafted file that has been unlinked
		// while open has no path left, and stat(2) through its fd is exactly
		// what a local filesystem answers.
		if err := syscall.Fstat(fd, &st); err != nil {
			return fuse.Status(errnoOfError(err))
		}
	} else {
		path, ok := r.path(record)
		if !ok {
			return fuse.Status(syscall.ESTALE)
		}
		value, errno := r.grafts.Lstat(path)
		if errno != 0 {
			return fuse.Status(errno)
		}
		st = value
	}
	fillGraftAttr(&st, &out.Attr, r.mount.uid, r.mount.gid)
	out.SetTimeout(graftEntryTimeout)
	return fuse.OK
}

// graftSetattr applies metadata changes to a machine-local object.
func (r *rawFileSystem) graftSetattr(record *inodeRecord, fd int, input *fuse.SetAttrIn, out *fuse.AttrOut) fuse.Status {
	request := localdirs.SetattrRequest{}
	if value, ok := input.GetMode(); ok {
		request.SetMode, request.Mode = true, value
	}
	if value, ok := input.GetUID(); ok && value != r.mount.uid {
		return fuse.Status(syscall.EPERM)
	}
	if value, ok := input.GetGID(); ok && value != r.mount.gid {
		return fuse.Status(syscall.EPERM)
	}
	if value, ok := input.GetSize(); ok {
		if value > math.MaxInt64 {
			return fuse.Status(syscall.EFBIG)
		}
		request.SetSize, request.Size = true, int64(value)
	}
	if value, ok := input.GetATime(); ok {
		request.SetAtime, request.AtimeMs = true, value.UnixMilli()
	}
	if value, ok := input.GetMTime(); ok {
		request.SetMtime, request.MtimeMs = true, value.UnixMilli()
	}
	path, ok := r.path(record)
	if !ok {
		return fuse.Status(syscall.ESTALE)
	}
	if errno := r.grafts.Setattr(path, request); errno != 0 {
		return fuse.Status(errno)
	}
	return r.graftGetattr(record, fd, out)
}

// graftOpen opens a machine-local file. The flags reach the backing filesystem
// unaltered, which is what makes O_APPEND, O_TRUNC and O_NONBLOCK behave the
// way they do on any local file rather than the way an authority protocol
// happens to model them.
func (r *rawFileSystem) graftOpen(record *inodeRecord, flags uint32) (*graftHandle, uint32, syscall.Errno) {
	path, ok := r.path(record)
	if !ok {
		return nil, 0, syscall.ESTALE
	}
	fd, errno := r.grafts.Open(path, flags)
	if errno != 0 {
		return nil, 0, errno
	}
	// FOPEN_KEEP_CACHE is correct here and direct I/O would not be. The whole
	// claim behind FOPEN_DIRECT_IO on the volume is that another machine can
	// change a file this kernel has cached pages for. A graft has no other
	// machine: its backing is per-machine by construction, every write to it
	// goes through this kernel, and this kernel updates its own page cache from
	// those writes. Refusing the page cache here would cost every dependency
	// tree read a round trip through FUSE for nothing.
	return &graftHandle{fd: fd}, fuse.FOPEN_KEEP_CACHE, 0
}

// graftCreate creates and opens a machine-local file.
func (r *rawFileSystem) graftCreate(parent *inodeRecord, resolved route, flags, mode uint32, out *fuse.EntryOut) (*inodeRecord, *graftHandle, uint32, syscall.Errno) {
	fd, errno := r.grafts.Create(resolved.path, flags, mode)
	if errno != 0 {
		// localdirs answers EISDIR at the route root itself: a rule is a
		// directory rule, so the root can only ever be created by mkdir.
		return nil, nil, 0, errno
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, nil, 0, errnoOfError(err)
	}
	record, errno := r.internGraft(parent, baseName(resolved.path), &st)
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, nil, 0, errno
	}
	r.publishGraftEntry(out, record, &st)
	return record, &graftHandle{fd: fd}, fuse.FOPEN_KEEP_CACHE, 0
}

// graftMkdir creates a machine-local directory.
//
// This is the whole of dynamic instantiation: the matcher is consulted on the
// mkdir itself, so a node_modules created five levels down, at a path nothing
// enumerated at mount time, is served locally from the instant it exists and
// the authority never sees an operation under it. localdirs creates the
// machine-local scaffold leading to a route root's backing as part of the same
// call.
func (r *rawFileSystem) graftMkdir(parent *inodeRecord, resolved route, mode uint32, out *fuse.EntryOut) (*inodeRecord, syscall.Errno) {
	if errno := r.grafts.Mkdir(resolved.path, mode); errno != 0 {
		return nil, errno
	}
	st, errno := r.grafts.Lstat(resolved.path)
	if errno != 0 {
		return nil, errno
	}
	record, errno := r.internGraft(parent, baseName(resolved.path), &st)
	if errno != 0 {
		return nil, errno
	}
	r.publishGraftEntry(out, record, &st)
	return record, 0
}

// graftSymlink creates a machine-local symlink.
func (r *rawFileSystem) graftSymlink(parent *inodeRecord, resolved route, target string, out *fuse.EntryOut) (*inodeRecord, syscall.Errno) {
	if errno := r.grafts.Symlink(target, resolved.path); errno != 0 {
		return nil, errno
	}
	st, errno := r.grafts.Lstat(resolved.path)
	if errno != 0 {
		return nil, errno
	}
	record, errno := r.internGraft(parent, baseName(resolved.path), &st)
	if errno != 0 {
		return nil, errno
	}
	r.publishGraftEntry(out, record, &st)
	return record, 0
}

// graftReaddir snapshots a machine-local directory listing.
func (r *rawFileSystem) graftReaddir(record *inodeRecord) (*graftDirHandle, syscall.Errno) {
	path, ok := r.path(record)
	if !ok {
		return nil, syscall.ESTALE
	}
	entries, errno := r.grafts.ReadDirNames(path)
	if errno != 0 {
		return nil, errno
	}
	listing := make([]fuse.DirEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			// The name raced a concurrent delete on this same machine. Skipping
			// it is what any local directory stream does.
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		listing = append(listing, fuse.DirEntry{
			Name: entry.Name(), Mode: uint32(st.Mode) & syscall.S_IFMT,
			Ino: localdirs.LocalIno(st.Ino), Off: uint64(len(listing)) + 1,
		})
	}
	return &graftDirHandle{entries: listing}, 0
}

func (h *graftDirHandle) seek(offset uint64) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	if offset > uint64(len(h.entries)) {
		return syscall.EINVAL
	}
	h.index = int(offset)
	return 0
}

func (h *graftDirHandle) peek() *fuse.DirEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.index >= len(h.entries) {
		return nil
	}
	entry := h.entries[h.index]
	return &entry
}

func (h *graftDirHandle) consume() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.index < len(h.entries) {
		h.index++
	}
}

// graftStatfs reports the BACKING filesystem's capacity for a machine-local
// path. A tool that preflights free space before a dependency install must see
// the real machine-local numbers, not the volume's virtual ones.
func (r *rawFileSystem) graftStatfs(out *fuse.StatfsOut) fuse.Status {
	var st syscall.Statfs_t
	// The backing tree is one directory this process created and owns, and no
	// path under it is ever a mount point, so the whole tree is one filesystem
	// and the root of it answers for every graft.
	if err := syscall.Statfs(r.backing, &st); err != nil {
		return fuse.Status(errnoOfError(err))
	}
	out.FromStatfsT(&st)
	return fuse.OK
}

// mergedRoots is the set of route roots this mount contributes to one volume
// directory's listing: the roots directly under it whose machine-local backing
// exists, each appearing exactly once.
//
// Shadowing is decided separately, per volume entry, because a rule owns a name
// whether or not anything has created it: a volume subtree must never become
// visible merely because the graft that owns its name is empty.
func (r *rawFileSystem) mergedRoots(dir string) ([]fuse.DirEntry, syscall.Errno) {
	active, errno := r.grafts.ActiveRootsUnder(dir)
	if errno != 0 {
		return nil, errno
	}
	entries := make([]fuse.DirEntry, 0, len(active))
	for _, root := range active {
		if parentOf(root) != dir {
			// A root deeper in the subtree is inside some directory of its own
			// and belongs to that directory's listing, not to this one.
			continue
		}
		st, errno := r.grafts.Lstat(root)
		if errno == syscall.ENOENT {
			continue
		}
		if errno != 0 {
			return nil, errno
		}
		entries = append(entries, fuse.DirEntry{
			Name: baseName(root), Mode: uint32(st.Mode) & syscall.S_IFMT,
			Ino: localdirs.LocalIno(st.Ino), Off: graftDirOffsetBase | uint64(len(entries)+1),
		})
	}
	return entries, 0
}

// shadowedIn reports, for one volume directory, whether a name it contains is
// owned by a route rule and must therefore not be listed from the volume.
func (r *rawFileSystem) shadowedIn(dir string) func(string) bool {
	if r.grafts == nil {
		return nil
	}
	prefix := dir
	if prefix != "" {
		prefix += "/"
	}
	return func(name string) bool { return r.grafts.Owner(prefix+name) != "" }
}

// graftRename performs a rename with both endpoints inside one route root.
func (r *rawFileSystem) graftRename(oldPath, newPath string, flags uint32) syscall.Errno {
	return r.grafts.Rename(oldPath, newPath, flags)
}

// graftRemove unlinks or removes a machine-local name. The route root itself is
// removed like any other directory, which is what makes the wholesale rebuild a
// dependency installer performs -- remove the tree, create it again -- work
// unchanged.
func (r *rawFileSystem) graftRemove(path string, directory bool) syscall.Errno {
	return r.grafts.Remove(path, directory)
}

func (r *rawFileSystem) graftReadlink(record *inodeRecord) ([]byte, fuse.Status) {
	path, ok := r.path(record)
	if !ok {
		return nil, fuse.Status(syscall.ESTALE)
	}
	target, errno := r.grafts.Readlink(path)
	if errno != 0 {
		return nil, fuse.Status(errno)
	}
	return []byte(target), fuse.OK
}

// graftLink creates a hard link with both endpoints inside one route root.
func (r *rawFileSystem) graftLink(source *inodeRecord, parent *inodeRecord, name string, out *fuse.EntryOut) (bool, fuse.Status) {
	resolved, errno := r.routeFor(parent, name)
	if errno != 0 {
		return true, fuse.Status(errno)
	}
	sourcePath, sourceRoot := "", ""
	var anonymous *graftHandle
	var anonymousRecord *handleRecord
	if source.graft {
		path, ok := r.path(source)
		if !ok {
			r.mu.Lock()
			anonymousFh, root := source.graftAnonymousFh, source.graftAnonymousRoot
			r.mu.Unlock()
			if anonymousFh == 0 || root == "" {
				return true, fuse.Status(syscall.ESTALE)
			}
			anonymousRecord, anonymous = r.acquireGraftFileHandle(anonymousFh)
			if anonymous == nil || anonymousRecord.inode != source {
				if anonymousRecord != nil {
					r.releaseHandleOperation(anonymousRecord)
				}
				return true, fuse.Status(syscall.ESTALE)
			}
			defer r.releaseHandleOperation(anonymousRecord)
			sourceRoot = root
		} else {
			sourcePath = path
			if sourceRoot = r.grafts.Owner(path); sourceRoot == "" {
				return true, fuse.EIO
			}
		}
	}
	if sourceRoot == "" && resolved.root == "" {
		return false, fuse.OK
	}
	if sourceRoot != resolved.root {
		// One endpoint is on the volume and the other is machine-local, or the
		// two are in different grafts. Either way this is a link across
		// filesystems, which POSIX has exactly one answer for.
		return true, fuse.Status(syscall.EXDEV)
	}
	var linkErr syscall.Errno
	if anonymous != nil {
		linkErr = r.grafts.LinkTmpfile(sourceRoot, anonymous.fd, resolved.path)
	} else {
		linkErr = r.grafts.Link(sourcePath, resolved.path)
	}
	if linkErr != 0 {
		return true, fuse.Status(linkErr)
	}
	var st syscall.Stat_t
	if anonymous != nil {
		if err := syscall.Fstat(anonymous.fd, &st); err != nil {
			r.mount.revoke(errors.New("fusev3: linked LOCAL tmpfile lost its retained descriptor identity"))
			return true, fuse.Status(syscall.ENOTCONN)
		}
	} else {
		var statErr syscall.Errno
		st, statErr = r.grafts.Lstat(resolved.path)
		if statErr != 0 {
			return true, fuse.Status(statErr)
		}
	}
	record, errno := r.internGraft(parent, name, &st)
	if errno != 0 {
		if anonymous != nil {
			// The directory entry now exists. Returning an ordinary error would
			// invite the caller to retry a mutation that already happened while
			// leaving our inode table unaware of it. Fail the mount closed instead.
			r.mount.revoke(errors.New("fusev3: linked LOCAL tmpfile could not be interned after the link was applied"))
			return true, fuse.Status(syscall.ENOTCONN)
		}
		return true, fuse.Status(errno)
	}
	r.publishGraftEntry(out, record, &st)
	return true, fuse.OK
}

// graftLock applies a file lock to the backing descriptor.
//
// Forwarding it to the authority would be wrong twice over: the authority must
// never see an operation under a graft, and the exclusion a caller is asking for
// is against other processes on THIS machine, which is exactly what the local
// kernel's lock manager provides and the only thing that can be provided for a
// per-machine file.
func graftLock(fd int, lock *fuse.FileLock, flags uint32, wait bool) syscall.Errno {
	unlock := lock.Typ == syscall.F_UNLCK
	if flags&uint32(fuse.FUSE_LK_FLOCK) != 0 {
		operation := unix.LOCK_EX
		switch {
		case unlock:
			operation = unix.LOCK_UN
		case lock.Typ == syscall.F_RDLCK:
			operation = unix.LOCK_SH
		}
		if !wait {
			operation |= unix.LOCK_NB
		}
		return errnoOfError(unix.Flock(fd, operation))
	}
	command := unix.F_SETLK
	if wait {
		command = unix.F_SETLKW
	}
	descriptor := &unix.Flock_t{Type: int16(lock.Typ), Whence: 0, Start: int64(lock.Start), Len: lockLength(lock)}
	return errnoOfError(unix.FcntlFlock(uintptr(fd), command, descriptor))
}

func graftGetlock(fd int, lock *fuse.FileLock, out *fuse.FileLock) syscall.Errno {
	descriptor := &unix.Flock_t{Type: int16(lock.Typ), Whence: 0, Start: int64(lock.Start), Len: lockLength(lock)}
	if errno := errnoOfError(unix.FcntlFlock(uintptr(fd), unix.F_GETLK, descriptor)); errno != 0 {
		return errno
	}
	out.Typ = uint32(descriptor.Type)
	out.Start = uint64(descriptor.Start)
	out.End = uint64(descriptor.Start + descriptor.Len)
	if descriptor.Len == 0 {
		out.End = math.MaxUint64
	}
	out.Pid = uint32(descriptor.Pid)
	return 0
}

func lockLength(lock *fuse.FileLock) int64 {
	if lock.End == math.MaxUint64 || lock.End < lock.Start {
		return 0
	}
	length := lock.End - lock.Start
	if length > math.MaxInt64 {
		return 0
	}
	return int64(length)
}

func baseName(path string) string {
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		return path[index+1:]
	}
	return path
}

// parentOf is the directory one volume-relative path lives in; the volume root
// is the empty string.
func parentOf(path string) string {
	index := strings.LastIndexByte(path, '/')
	if index < 0 {
		return ""
	}
	return path[:index]
}
