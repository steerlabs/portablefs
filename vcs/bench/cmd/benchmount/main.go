// Command benchmount is the benchmark harness's raw FUSE mount: it mounts a
// PortableFS authority (a plain fsproto address, no control plane, no mount
// session) so pfsbench's fuse transport can measure real kernel-path numbers.
//
// BENCH-ONLY. It is not the product mount — that is `portablefs mount`
// (cli/fusemount.go) — and it reads no product environment variables: every
// knob the harness sweeps is an explicit flag.
//
//	benchmount -addr 127.0.0.1:2050 -mount /mnt/bench \
//	  [-pool 16] [-writeback] [-flush-ms 250] [-flush-max-records N]
//	  [-flush-max-bytes N] [-negcache] [-no-readdirplus] [-session-ttl-ms N]
//
// SIGTERM/SIGINT runs the bounded unmount flush barrier and detaches; the
// harness relies on that to drain write-back sessions between phases.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/modebits"
)

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

func errno(st clientcore.Status) syscall.Errno { return syscall.Errno(st) }

func typeBits(kind string) uint32 {
	switch kind {
	case "directory":
		return fuse.S_IFDIR
	case "symlink":
		return fuse.S_IFLNK
	default:
		return fuse.S_IFREG
	}
}

func fillAttr(path string, a *fsproto.Attr, out *fuse.Attr) {
	out.Ino = a.Ino
	if out.Ino == 0 {
		out.Ino = clientcore.InoOf(path)
	}
	out.Size = uint64(a.Size)
	out.Mode = typeBits(a.Kind) | modebits.CleanUnix(a.Mode)
	out.Nlink = a.Nlink
	if out.Nlink == 0 {
		out.Nlink = 1
	}
	out.Mtime = uint64(a.MtimeMs / 1000)
	out.Mtimensec = uint32((a.MtimeMs % 1000) * 1e6)
	ctimeMs := a.CtimeMs
	if ctimeMs == 0 {
		ctimeMs = a.MtimeMs
	}
	out.Ctime = uint64(ctimeMs / 1000)
	out.Ctimensec = uint32((ctimeMs % 1000) * 1e6)
	atimeMs := a.AtimeMs
	if atimeMs == 0 {
		atimeMs = a.MtimeMs
	}
	out.Atime = uint64(atimeMs / 1000)
	out.Atimensec = uint32((atimeMs % 1000) * 1e6)
	out.Uid = a.Uid
	out.Gid = a.Gid
}

// benchNode is a path-addressed FUSE node backed by a clientcore.Volume — the
// CLI's fuseNode without machine-local grafts. The authority holds all state;
// open-after-unlink routing lives in state.
type benchNode struct {
	fs.Inode
	v     *clientcore.Volume
	path  string // creation-time path; curPath follows renames via the live tree
	state *clientcore.NodeState
}

// benchHandle records the open-time path (release must decrement the same key
// even across renames) and the advisory locks taken through this description.
type benchHandle struct {
	openPath string
	append   bool
	lock     clientcore.LockHandle
}

func (n *benchNode) curPath() string {
	if p := n.Path(nil); p != "" {
		return p
	}
	return n.path
}

func (n *benchNode) child(name string) string {
	p := n.curPath()
	if p == "" {
		return name
	}
	return p + "/" + name
}

func (n *benchNode) childState(name string) *clientcore.NodeState {
	ch := n.GetChild(name)
	if ch == nil {
		return nil
	}
	cn, ok := ch.Operations().(*benchNode)
	if !ok {
		return nil
	}
	return cn.state
}

func (n *benchNode) newChild(ctx context.Context, name string, a *fsproto.Attr) *fs.Inode {
	cp := n.child(name)
	ino := a.Ino
	if ino == 0 {
		ino = clientcore.InoOf(cp)
	}
	child := &benchNode{v: n.v, path: cp, state: clientcore.NewNodeState(ino, a.Ino != 0)}
	return n.NewInode(ctx, child, fs.StableAttr{Mode: typeBits(a.Kind), Ino: ino})
}

var (
	_ fs.NodeLookuper   = (*benchNode)(nil)
	_ fs.NodeGetattrer  = (*benchNode)(nil)
	_ fs.NodeReaddirer  = (*benchNode)(nil)
	_ fs.NodeOpener     = (*benchNode)(nil)
	_ fs.NodeReader     = (*benchNode)(nil)
	_ fs.NodeWriter     = (*benchNode)(nil)
	_ fs.NodeCreater    = (*benchNode)(nil)
	_ fs.NodeMkdirer    = (*benchNode)(nil)
	_ fs.NodeUnlinker   = (*benchNode)(nil)
	_ fs.NodeRmdirer    = (*benchNode)(nil)
	_ fs.NodeRenamer    = (*benchNode)(nil)
	_ fs.NodeLinker     = (*benchNode)(nil)
	_ fs.NodeSymlinker  = (*benchNode)(nil)
	_ fs.NodeReadlinker = (*benchNode)(nil)
	_ fs.NodeSetattrer  = (*benchNode)(nil)
	_ fs.NodeFsyncer    = (*benchNode)(nil)
	_ fs.NodeFlusher    = (*benchNode)(nil)
	_ fs.NodeReleaser   = (*benchNode)(nil)
	_ fs.NodeGetlker    = (*benchNode)(nil)
	_ fs.NodeSetlker    = (*benchNode)(nil)
	_ fs.NodeSetlkwer   = (*benchNode)(nil)
	_ fs.NodeStatfser   = (*benchNode)(nil)
)

func (n *benchNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	st := n.v.Statfs()
	out.Blocks = st.Blocks
	out.Bfree = st.Bfree
	out.Bavail = st.Bavail
	out.Bsize = st.Bsize
	out.Frsize = st.Frsize
	out.Files = st.Files
	out.Ffree = st.Ffree
	out.NameLen = st.NameLen
	return 0
}

func (n *benchNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cp := n.child(name)
	a, st := n.v.Lookup(ctx, cp)
	if st != fsproto.OK {
		out.SetEntryTimeout(n.v.AttrValidFor(cp))
		return nil, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(n.v.AttrValidFor(cp))
	out.SetAttrTimeout(n.v.AttrValidFor(cp))
	return n.newChild(ctx, name, &a), 0
}

func (n *benchNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	p := n.curPath()
	a, st := n.v.Getattr(ctx, p, n.state)
	if st != fsproto.OK {
		return errno(st)
	}
	fillAttr(p, &a, &out.Attr)
	out.SetTimeout(n.v.AttrValidFor(p))
	return 0
}

func (n *benchNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	dir := n.curPath()
	ents, st := n.v.Readdir(ctx, dir)
	if st != fsproto.OK {
		return nil, errno(st)
	}
	list := make([]fuse.DirEntry, 0, len(ents))
	for _, e := range ents {
		list = append(list, fuse.DirEntry{Name: e.Name, Mode: typeBits(e.Attr.Kind), Ino: e.Ino})
	}
	return fs.NewListDirStream(list), 0
}

func (n *benchNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	p := n.curPath()
	writeIntent := flags&uint32(syscall.O_ACCMODE) != uint32(syscall.O_RDONLY)
	if st := n.v.Open(ctx, p, n.state, writeIntent); st != fsproto.OK {
		return nil, 0, errno(st)
	}
	return &benchHandle{
		openPath: p,
		append:   flags&uint32(syscall.O_APPEND) != 0,
	}, fuse.FOPEN_KEEP_CACHE, 0
}

func (n *benchNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	data, st := n.v.Read(ctx, n.curPath(), n.state, off, len(dest))
	if st != fsproto.OK {
		return nil, errno(st)
	}
	return fuse.ReadResultData(data), 0
}

func (n *benchNode) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	var cnt int
	var st clientcore.Status
	if h, ok := fh.(*benchHandle); ok && h.append {
		cnt, st = n.v.WriteAppend(ctx, n.curPath(), n.state, off, data)
	} else {
		cnt, st = n.v.Write(ctx, n.curPath(), n.state, off, data)
	}
	if st != fsproto.OK {
		return 0, errno(st)
	}
	return uint32(cnt), 0
}

func (n *benchNode) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	cp := n.child(name)
	var a fsproto.Attr
	var st clientcore.Status
	if flags&syscall.O_EXCL != 0 {
		a, st = n.v.CreateExcl(ctx, cp, mode)
	} else {
		a, st = n.v.Create(ctx, cp, mode)
	}
	if st != fsproto.OK {
		return nil, nil, 0, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(n.v.AttrValidFor(cp))
	out.SetAttrTimeout(n.v.AttrValidFor(cp))
	ch := n.newChild(ctx, name, &a)
	if cn, ok := ch.Operations().(*benchNode); ok {
		// Count the just-opened handle so a peer unlink parks the inode
		// (delete-on-last-close) instead of breaking the fresh fd.
		if n.v.RegisterOpened(cp, cn.state) == fsproto.ENOENT {
			return nil, nil, 0, syscall.ENOENT
		}
	}
	return ch, &benchHandle{
		openPath: cp,
		append:   flags&uint32(syscall.O_APPEND) != 0,
	}, fuse.FOPEN_KEEP_CACHE, 0
}

func (n *benchNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cp := n.child(name)
	a, st := n.v.Mkdir(ctx, cp, mode)
	if st != fsproto.OK {
		return nil, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(n.v.AttrValidFor(cp))
	out.SetAttrTimeout(n.v.AttrValidFor(cp))
	return n.newChild(ctx, name, &a), 0
}

func (n *benchNode) Unlink(ctx context.Context, name string) syscall.Errno {
	return errno(n.v.Remove(ctx, n.child(name), n.childState(name)))
}

func (n *benchNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	return errno(n.v.Remove(ctx, n.child(name), n.childState(name)))
}

func (n *benchNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	np, ok := newParent.(*benchNode)
	if !ok {
		return syscall.EXDEV
	}
	oldp, newp := n.child(name), np.child(newName)
	return errno(n.v.Rename(ctx, oldp, newp, n.childState(name), np.childState(newName)))
}

func (n *benchNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cp := n.child(name)
	a, st := n.v.Symlink(ctx, target, cp)
	if st != fsproto.OK {
		return nil, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(n.v.AttrValidFor(cp))
	out.SetAttrTimeout(n.v.AttrValidFor(cp))
	return n.newChild(ctx, name, &a), 0
}

func (n *benchNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	src, ok := target.(*benchNode)
	if !ok {
		return nil, syscall.EXDEV
	}
	oldp := target.EmbeddedInode().Path(nil)
	newp := n.child(name)
	a, st := n.v.Link(ctx, oldp, newp, src.state)
	if st != fsproto.OK {
		return nil, errno(st)
	}
	fillAttr(newp, &a, &out.Attr)
	out.SetEntryTimeout(n.v.AttrValidFor(newp))
	out.SetAttrTimeout(n.v.AttrValidFor(newp))
	return n.newChild(ctx, name, &a), 0
}

func (n *benchNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	t, st := n.v.Readlink(ctx, n.curPath())
	if st != fsproto.OK {
		return nil, errno(st)
	}
	return []byte(t), 0
}

func (n *benchNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	p := n.curPath()
	var req clientcore.SetattrRequest
	if sz, ok := in.GetSize(); ok {
		req.Size = int64(sz)
		req.SetSize = true
	}
	if mode, ok := in.GetMode(); ok {
		req.Mode = mode
		req.SetMode = true
	}
	if mt, ok := in.GetMTime(); ok {
		req.MtimeMs = mt.UnixMilli()
		req.SetMTime = true
	}
	if uid, ok := in.GetUID(); ok {
		req.UID = uid
		req.SetUID = true
	}
	if gid, ok := in.GetGID(); ok {
		req.GID = gid
		req.SetGID = true
	}
	a, st := n.v.Setattr(ctx, p, n.state, req)
	if st != fsproto.OK {
		return errno(st)
	}
	if a.Kind != "" {
		fillAttr(p, &a, &out.Attr)
	}
	out.SetTimeout(n.v.AttrValidFor(p))
	return 0
}

func (n *benchNode) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	return errno(n.v.FsyncPath(n.curPath()))
}

// Flush runs on every close(2), including intermediate closes of shared
// descriptions; advisory locks are released in Release (final close) only.
func (n *benchNode) Flush(ctx context.Context, fh fs.FileHandle) syscall.Errno { return 0 }

func (n *benchNode) Release(ctx context.Context, fh fs.FileHandle) syscall.Errno {
	if h, ok := fh.(*benchHandle); ok {
		clientcore.ReleaseHandleLocks(n.v.LockAuth(), &h.lock)
		n.v.CloseHandle(h.openPath, n.state)
		return 0
	}
	n.v.CloseHandle(n.curPath(), n.state)
	return 0
}

func (n *benchNode) lockHandle(fh fs.FileHandle) *clientcore.LockHandle {
	if h, ok := fh.(*benchHandle); ok {
		return &h.lock
	}
	return nil
}

func (n *benchNode) Getlk(ctx context.Context, fh fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	res, err := n.v.Getlk(n.curPath(), owner, lk.Start, lk.End, lk.Typ == clientcore.LockWrite)
	if err != nil {
		return syscall.EIO
	}
	if !res.Conflict {
		out.Typ = clientcore.LockUnlock
		return 0
	}
	out.Typ = clientcore.LockRead
	if res.CWrite {
		out.Typ = clientcore.LockWrite
	}
	out.Start, out.End = res.CStart, res.CEnd
	out.Pid = 0
	return 0
}

func (n *benchNode) Setlk(ctx context.Context, fh fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	p := n.curPath()
	if lk.Typ == clientcore.LockUnlock {
		_, _ = n.v.Setlk(ctx, n.lockHandle(fh), p, owner, lk.Start, lk.End, false, true)
		return 0
	}
	res, err := n.v.Setlk(ctx, n.lockHandle(fh), p, owner, lk.Start, lk.End, lk.Typ == clientcore.LockWrite, false)
	if err != nil {
		return syscall.EIO
	}
	if res.Status == fsproto.EAGAIN {
		return syscall.EAGAIN
	}
	return errno(res.Status)
}

func (n *benchNode) Setlkw(ctx context.Context, fh fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	p := n.curPath()
	if lk.Typ == clientcore.LockUnlock {
		_, _ = n.v.Setlk(ctx, n.lockHandle(fh), p, owner, lk.Start, lk.End, false, true)
		return 0
	}
	res, err := n.v.Setlkw(ctx, n.lockHandle(fh), p, owner, lk.Start, lk.End, lk.Typ == clientcore.LockWrite)
	if err != nil {
		if ctx.Err() != nil {
			return syscall.EINTR
		}
		return syscall.EIO
	}
	return errno(res.Status)
}

// ---- kernel-cache invalidation, driven by the authority push stream ----

func splitDirBase(p string) (dir, base string) {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

func walkInode(root *fs.Inode, path string) *fs.Inode {
	cur := root
	if path == "" {
		return cur
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		if cur = cur.GetChild(part); cur == nil {
			return nil
		}
	}
	return cur
}

// invalidatePath drops a remotely-changed path from the kernel cache: always
// the content, and the parent dentry only for a name-binding change.
func invalidatePath(root *fs.Inode, path string, inPlace bool) {
	if path == "" {
		return
	}
	dir, base := splitDirBase(path)
	parent := walkInode(root, dir)
	if parent == nil {
		return
	}
	if child := parent.GetChild(base); child != nil {
		_ = child.NotifyContent(0, 0)
	}
	if !inPlace {
		_ = parent.NotifyEntry(base)
	}
}

// flushAll drops cached content for a whole subtree (resubscribe/overflow).
// Content-only: entry timeouts are 0, so existence coherence comes from
// lookup revalidation, and dentry drops would break in-use CWDs.
func flushAll(n *fs.Inode) {
	for _, child := range n.Children() {
		_ = child.NotifyContent(0, 0)
		flushAll(child)
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:2050", "fsproto authority address")
	mountpoint := flag.String("mount", "", "directory to mount the volume on")
	pool := flag.Int("pool", 16, "connection pool size (concurrent in-flight ops)")
	writeThrough := flag.Bool("write-through", false, "debug: never delegate (PORTABLEFS_DEBUG_WRITE_THROUGH)")
	negCache := flag.Bool("negcache", false, "force the version-gated negative lookup cache on")
	noRDP := flag.Bool("no-readdirplus", false, "disable readdir-plus attr-cache fill")
	sessionTTLMs := flag.Int("session-ttl-ms", 0, "kernel attr/entry TTL while a subtree delegation is held (0 = off)")
	flag.Parse()
	if *mountpoint == "" {
		log.Fatal("benchmount: -mount is required")
	}
	if *writeThrough {
		_ = os.Setenv("PORTABLEFS_DEBUG_WRITE_THROUGH", "1")
	}

	walDir, err := os.MkdirTemp("", "benchmount-wb-")
	if err != nil {
		log.Fatalf("benchmount: write-back state dir: %v", err)
	}
	defer os.RemoveAll(walDir)

	var rootHolder struct {
		mu   sync.Mutex
		node *benchNode
	}
	rootInode := func() *fs.Inode {
		rootHolder.mu.Lock()
		defer rootHolder.mu.Unlock()
		if rootHolder.node == nil {
			return nil
		}
		return rootHolder.node.EmbeddedInode()
	}
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr:          *addr,
		Pool:          *pool,
		Owner:         "benchmount-" + randomID(),
		WALDir:        walDir,
		NegativeCache: *negCache,
		NoReaddirPlus: *noRDP,
		SessionTTL:    time.Duration(*sessionTTLMs) * time.Millisecond,
		OnFlushAll: func(path string) {
			root := rootInode()
			if root == nil {
				return
			}
			if path == "" {
				flushAll(root)
				return
			}
			if in := walkInode(root, path); in != nil {
				flushAll(in)
			}
		},
		OnInvalidate: func(path string, inPlace bool) {
			if root := rootInode(); root != nil {
				invalidatePath(root, path, inPlace)
			}
		},
		OnMarkOrphan: func(path string, ino uint64) {
			root := rootInode()
			if root == nil {
				return
			}
			if in := walkInode(root, path); in != nil {
				if cn, ok := in.Operations().(*benchNode); ok {
					cn.state.MarkOrphan(ino, cn.v.OpenOrphans())
				}
			}
		},
	})
	if err != nil {
		log.Fatalf("benchmount: connect to authority %s: %v", *addr, err)
	}

	// Kernel caching mirrors the product mount's default mode: file data is
	// cached and kept across opens, attrs and existence revalidate every time
	// (ttl 0); coherence comes from push invalidations, never timers.
	ttl := time.Duration(0)
	entryTTL := time.Duration(0)
	opts := &fs.Options{
		AttrTimeout:     &ttl,
		EntryTimeout:    &entryTTL,
		NullPermissions: true,
		MountOptions: fuse.MountOptions{
			FsName:        "benchmount",
			Name:          "portablefs",
			MaxWrite:      1 << 20,
			MaxReadAhead:  1 << 20,
			MaxBackground: 256,
			EnableLocks:   true,
		},
	}
	root := &benchNode{v: vol, state: clientcore.NewNodeState(1, true)}
	rootHolder.mu.Lock()
	rootHolder.node = root
	rootHolder.mu.Unlock()
	server, err := fs.Mount(*mountpoint, root, opts)
	if err != nil {
		log.Fatalf("benchmount: mount %s: %v", *mountpoint, err)
	}
	log.Printf("benchmount: mounted %s via %s (pool=%d writeThrough=%v)", *mountpoint, *addr, *pool, *writeThrough)

	ctx, stop := context.WithCancel(context.Background())
	var renewWG sync.WaitGroup
	renewWG.Add(1)
	go func() {
		defer renewWG.Done()
		vol.RunOpenLeaseRenewal(ctx, 20*time.Second, nil)
	}()
	go vol.StartInvalidations(ctx, false)

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		log.Print("benchmount: unmounting...")
		stop()
		flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := vol.FlushToAuthority(flushCtx); err != nil {
			log.Printf("benchmount: unmount flush barrier FAILED: %v", err)
		}
		cancel()
		_ = server.Unmount()
	}()
	server.Wait()
	stop()
	renewWG.Wait()
	_ = vol.Close()
}
