package localdirs

import (
	"context"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// localTTL is the kernel entry/attr timeout for grafted paths. The volume
// side runs TTL 0 because peers mutate it; a graft is machine-local by
// construction — every mutation of its backing flows through this same
// kernel, which updates its own dentry/attr caches synchronously on its own
// operations — so a short time box can never serve a cross-machine stale
// result. 1s matches the conventional loopback-filesystem default.
const localTTL = time.Second

// Node is the go-fuse node for a path owned by a graft. All its operations go
// straight to the machine-local backing filesystem: no fsproto round trips,
// no write-back sessions, no invalidation subscriptions. File I/O runs on the
// backing fd via fs.NewLoopbackFile handles (reads, writes, fsync, flock all
// straight through), so open handles keep working across rm -rf of the graft
// root exactly like on a local filesystem.
type Node struct {
	fs.Inode
	g *Grafts
}

var (
	_ fs.NodeLookuper   = (*Node)(nil)
	_ fs.NodeGetattrer  = (*Node)(nil)
	_ fs.NodeSetattrer  = (*Node)(nil)
	_ fs.NodeReaddirer  = (*Node)(nil)
	_ fs.NodeOpener     = (*Node)(nil)
	_ fs.NodeCreater    = (*Node)(nil)
	_ fs.NodeMkdirer    = (*Node)(nil)
	_ fs.NodeUnlinker   = (*Node)(nil)
	_ fs.NodeRmdirer    = (*Node)(nil)
	_ fs.NodeRenamer    = (*Node)(nil)
	_ fs.NodeLinker     = (*Node)(nil)
	_ fs.NodeSymlinker  = (*Node)(nil)
	_ fs.NodeReadlinker = (*Node)(nil)
	_ fs.NodeFsyncer    = (*Node)(nil)
	_ fs.NodeStatfser   = (*Node)(nil)
)

// IsLocalNode reports whether a go-fuse inode is served by a graft. The
// volume adapters use it to keep blanket kernel-cache flushes (resubscribe /
// overflow) from evicting valid machine-local state.
func IsLocalNode(ops fs.InodeEmbedder) bool {
	_, ok := ops.(*Node)
	return ok
}

// path returns this node's workspace-relative path, derived from the live
// go-fuse tree so it follows renames of grafted files and of volume ancestors.
func (n *Node) path() string {
	return n.Path(nil)
}

func (n *Node) childPath(name string) string {
	p := n.path()
	if p == "" {
		return name
	}
	return p + "/" + name
}

// fillFuseAttr converts a backing stat into the kernel attr shape, minting
// the marked local inode number.
func fillFuseAttr(st *syscall.Stat_t, out *fuse.Attr) {
	out.FromStat(st)
	out.Ino = LocalIno(st.Ino)
}

// stableAttrFor is the kernel identity for a grafted path: the backing
// filesystem's inode (marked into the local range) plus its type bits.
// Backing inode identity is stable across graft-internal renames and shared
// by hard links, exactly like a loopback mount.
func stableAttrFor(st *syscall.Stat_t) fs.StableAttr {
	return fs.StableAttr{Mode: uint32(st.Mode) & syscall.S_IFMT, Ino: LocalIno(st.Ino)}
}

// attachChild returns the go-fuse inode for a grafted path under parent
// (creating or reusing per StableAttr identity).
func (g *Grafts) attachChild(ctx context.Context, parent *fs.Inode, st *syscall.Stat_t) *fs.Inode {
	return parent.NewInode(ctx, &Node{g: g}, stableAttrFor(st))
}

// LookupChild resolves a graft-owned child path for any parent node (the
// volume node holding a graft root, or a Node inside one). A graft root whose
// backing does not exist is an honest ENOENT: rules own names, they do not
// synthesize directories.
func (g *Grafts) LookupChild(ctx context.Context, parent *fs.Inode, cp string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	st, eno := g.Lstat(cp)
	if eno != 0 {
		return nil, eno
	}
	fillFuseAttr(&st, &out.Attr)
	out.SetEntryTimeout(localTTL)
	out.SetAttrTimeout(localTTL)
	return g.attachChild(ctx, parent, &st), 0
}

// MkdirChild creates a graft-owned directory (including the graft root
// itself) under any parent node.
func (g *Grafts) MkdirChild(ctx context.Context, parent *fs.Inode, cp string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if eno := g.Mkdir(cp, mode); eno != 0 {
		return nil, eno
	}
	st, eno := g.Lstat(cp)
	if eno != 0 {
		return nil, eno
	}
	fillFuseAttr(&st, &out.Attr)
	out.SetEntryTimeout(localTTL)
	out.SetAttrTimeout(localTTL)
	return g.attachChild(ctx, parent, &st), 0
}

// CreateChild creates and opens a graft-owned file under any parent node
// (EISDIR at the graft root: a rule is a directory rule).
func (g *Grafts) CreateChild(ctx context.Context, parent *fs.Inode, cp string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	fd, eno := g.Create(cp, flags, mode)
	if eno != 0 {
		return nil, nil, 0, eno
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return nil, nil, 0, errnoOf(err)
	}
	fillFuseAttr(&st, &out.Attr)
	out.SetEntryTimeout(localTTL)
	out.SetAttrTimeout(localTTL)
	return g.attachChild(ctx, parent, &st), fs.NewLoopbackFile(fd), fuse.FOPEN_KEEP_CACHE, 0
}

// SymlinkChild creates a graft-owned symlink under any parent node (EISDIR at
// the graft root).
func (g *Grafts) SymlinkChild(ctx context.Context, parent *fs.Inode, target, cp string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if eno := g.Symlink(target, cp); eno != 0 {
		return nil, eno
	}
	st, eno := g.Lstat(cp)
	if eno != 0 {
		return nil, eno
	}
	fillFuseAttr(&st, &out.Attr)
	out.SetEntryTimeout(localTTL)
	out.SetAttrTimeout(localTTL)
	return g.attachChild(ctx, parent, &st), 0
}

// LinkChild links target at name under parent when both endpoints are owned
// by the same graft; Grafts.Link returns EXDEV for every boundary crossing.
func (g *Grafts) LinkChild(ctx context.Context, parent *fs.Inode, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	oldp := target.EmbeddedInode().Path(nil)
	newp := name
	if pp := parent.Path(nil); pp != "" {
		newp = pp + "/" + name
	}
	if eno := g.Link(oldp, newp); eno != 0 {
		return nil, eno
	}
	st, eno := g.Lstat(newp)
	if eno != 0 {
		_ = g.root.Remove(newp)
		return nil, eno
	}
	fillFuseAttr(&st, &out.Attr)
	out.SetEntryTimeout(localTTL)
	out.SetAttrTimeout(localTTL)
	return g.attachChild(ctx, parent, &st), 0
}

func (n *Node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return n.g.LookupChild(ctx, n.EmbeddedInode(), n.childPath(name), out)
}

func (n *Node) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	// Prefer the handle: an unlinked-but-open grafted file has no path
	// anymore, but its fd stats fine (plain POSIX open-after-unlink).
	if fga, ok := fh.(fs.FileGetattrer); ok {
		if eno := fga.Getattr(ctx, out); eno == 0 {
			out.SetTimeout(localTTL)
			return 0
		}
	}
	st, eno := n.g.Lstat(n.path())
	if eno != 0 {
		return eno
	}
	fillFuseAttr(&st, &out.Attr)
	out.SetTimeout(localTTL)
	return 0
}

func (n *Node) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	req := SetattrRequest{}
	if mode, ok := in.GetMode(); ok {
		req.SetMode, req.Mode = true, mode
	}
	if sz, ok := in.GetSize(); ok {
		req.SetSize, req.Size = true, int64(sz)
	}
	if mt, ok := in.GetMTime(); ok {
		req.SetMtime, req.MtimeMs = true, mt.UnixMilli()
	}
	if at, ok := in.GetATime(); ok {
		req.SetAtime, req.AtimeMs = true, at.UnixMilli()
	}
	// Ownership changes are accepted and ignored, matching the volume's
	// noowners semantics and portablefsd's grafted setattr.
	p := n.path()
	eno := n.g.Setattr(p, req)
	if eno == syscall.ENOENT {
		// Unlinked-but-open: apply what we can through the fd. Owner bits are
		// stripped so the ignore-ownership contract holds on this path too.
		if fsa, ok := fh.(fs.FileSetattrer); ok {
			cp := *in
			cp.Valid &^= fuse.FATTR_UID | fuse.FATTR_GID
			if feno := fsa.Setattr(ctx, &cp, out); feno == 0 {
				out.SetTimeout(localTTL)
				return 0
			}
		}
		return eno
	}
	if eno != 0 {
		return eno
	}
	st, eno := n.g.Lstat(p)
	if eno != 0 {
		return eno
	}
	fillFuseAttr(&st, &out.Attr)
	out.SetTimeout(localTTL)
	return 0
}

func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entries, eno := n.g.ReadDirNames(n.path())
	if eno != 0 {
		return nil, eno
	}
	list := make([]fuse.DirEntry, 0, len(entries))
	for _, entry := range entries {
		fi, err := entry.Info()
		if err != nil {
			// The entry raced a concurrent delete; skip it rather than
			// failing the whole listing.
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		list = append(list, fuse.DirEntry{Name: entry.Name(), Mode: uint32(st.Mode) & syscall.S_IFMT, Ino: LocalIno(st.Ino)})
	}
	return fs.NewListDirStream(list), 0
}

func (n *Node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	fd, eno := n.g.Open(n.path(), flags)
	if eno != 0 {
		return nil, 0, eno
	}
	// KEEP_CACHE is safe here for the same reason localTTL is: only this
	// kernel writes the backing, and its own writes update its page cache.
	return fs.NewLoopbackFile(fd), fuse.FOPEN_KEEP_CACHE, 0
}

func (n *Node) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	return n.g.CreateChild(ctx, n.EmbeddedInode(), n.childPath(name), flags, mode, out)
}

func (n *Node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return n.g.MkdirChild(ctx, n.EmbeddedInode(), n.childPath(name), mode, out)
}

func (n *Node) Unlink(ctx context.Context, name string) syscall.Errno {
	return n.g.Remove(n.childPath(name), false)
}

func (n *Node) Rmdir(ctx context.Context, name string) syscall.Errno {
	return n.g.Remove(n.childPath(name), true)
}

func (n *Node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	np, ok := newParent.(*Node)
	if !ok {
		// The destination parent is a volume directory: the rename leaves the
		// graft, which crosses filesystems.
		return syscall.EXDEV
	}
	return n.g.Rename(n.childPath(name), np.childPath(newName), flags)
}

func (n *Node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return n.g.SymlinkChild(ctx, n.EmbeddedInode(), target, n.childPath(name), out)
}

func (n *Node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	target, eno := n.g.Readlink(n.path())
	if eno != 0 {
		return nil, eno
	}
	return []byte(target), 0
}

func (n *Node) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return n.g.LinkChild(ctx, n.EmbeddedInode(), target, name, out)
}

func (n *Node) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	// The loopback handle fsyncs its fd (works for unlinked-open files); the
	// path fallback covers fsyncdir and handle-less fsync.
	if ff, ok := fh.(fs.FileFsyncer); ok {
		return ff.Fsync(ctx, flags)
	}
	return n.g.Fsync(n.path())
}

// Statfs reports the BACKING filesystem's capacity: tools that preflight free
// space before large dependency installs must see real machine-local numbers,
// not the volume's virtual capacity.
func (n *Node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	var st syscall.Statfs_t
	f, err := n.g.root.Open(n.path())
	if err != nil {
		f, err = n.g.root.Open(".")
	}
	if err != nil {
		return errnoOf(err)
	}
	defer f.Close()
	if err := syscall.Fstatfs(int(f.Fd()), &st); err != nil {
		return errnoOf(err)
	}
	out.FromStatfsT(&st)
	return 0
}
