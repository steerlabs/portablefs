package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/fusefrontend"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/modebits"
	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// This file is the product FUSE frontend: it forwards kernel ops through
// clientcore.Volume — the coherence, open-after-unlink, and cache logic all
// live in clientcore — and keeps only the go-fuse node adapter here. (The
// bench harness carries its own trimmed copy in bench/cmd/benchmount.)

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

// fuseNode is a path-addressed FUSE node backed by a clientcore.Volume. The
// authority holds all state; open-after-unlink routing lives in state.
type fuseNode struct {
	fs.Inode
	v     *clientcore.Volume
	path  string // creation-time path; curPath follows renames via the live tree
	state *clientcore.NodeState
	// replyGate extends delegation content handoff through the kernel's
	// ReadResult.Done publication hook without blocking unrelated subtrees.
	// Metadata is deliberately zero-TTL: go-fuse exposes no corresponding
	// post-write hook for metadata replies.
	replyGate *fusefrontend.ReplyGate
	// g is the mount's machine-local dirs (grafts); nil when none are
	// configured, so the non-graft hot path pays only nil checks.
	g *localdirs.Grafts
}

// fuseHandle records the open-time path (release must decrement the same key
// even across renames) and the advisory locks taken through this description.
type fuseHandle struct {
	openPath string
	append   bool
	lock     clientcore.LockHandle
}

func (n *fuseNode) curPath() string {
	if p := n.Path(nil); p != "" {
		return p
	}
	return n.path
}

func (n *fuseNode) child(name string) string {
	p := n.curPath()
	if p == "" {
		return name
	}
	return p + "/" + name
}

// gateOp binds one kernel request to the mount's publication gate. Every op
// that can reach an authority-bound wait inside clientcore installs it, so the
// OnOperationWait hook can take that request's admitted replies out of the
// handoff drain set for the duration of the wait. For a request holding no
// admission — every op but Read — it is inert by construction, which is the
// point: the record is the operation's identity, not a promise that it
// publishes.
func (n *fuseNode) gateOp(ctx context.Context) context.Context {
	return n.replyGate.Operation(ctx)
}

func (n *fuseNode) childState(name string) *clientcore.NodeState {
	ch := n.GetChild(name)
	if ch == nil {
		return nil
	}
	cn, ok := ch.Operations().(*fuseNode)
	if !ok {
		return nil
	}
	return cn.state
}

func (n *fuseNode) newChild(ctx context.Context, name string, a *fsproto.Attr) *fs.Inode {
	cp := n.child(name)
	ino := a.Ino
	if ino == 0 {
		ino = clientcore.InoOf(cp)
	}
	child := &fuseNode{v: n.v, path: cp, state: clientcore.NewNodeState(ino, a.Ino != 0), g: n.g, replyGate: n.replyGate}
	return n.NewInode(ctx, child, fs.StableAttr{Mode: typeBits(a.Kind), Ino: ino})
}

var (
	_ fs.NodeLookuper   = (*fuseNode)(nil)
	_ fs.NodeGetattrer  = (*fuseNode)(nil)
	_ fs.NodeReaddirer  = (*fuseNode)(nil)
	_ fs.NodeOpener     = (*fuseNode)(nil)
	_ fs.NodeReader     = (*fuseNode)(nil)
	_ fs.NodeWriter     = (*fuseNode)(nil)
	_ fs.NodeCreater    = (*fuseNode)(nil)
	_ fs.NodeMkdirer    = (*fuseNode)(nil)
	_ fs.NodeUnlinker   = (*fuseNode)(nil)
	_ fs.NodeRmdirer    = (*fuseNode)(nil)
	_ fs.NodeRenamer    = (*fuseNode)(nil)
	_ fs.NodeLinker     = (*fuseNode)(nil)
	_ fs.NodeSymlinker  = (*fuseNode)(nil)
	_ fs.NodeReadlinker = (*fuseNode)(nil)
	_ fs.NodeSetattrer  = (*fuseNode)(nil)
	_ fs.NodeFsyncer    = (*fuseNode)(nil)
	_ fs.NodeFlusher    = (*fuseNode)(nil)
	_ fs.NodeReleaser   = (*fuseNode)(nil)
	_ fs.NodeGetlker    = (*fuseNode)(nil)
	_ fs.NodeSetlker    = (*fuseNode)(nil)
	_ fs.NodeSetlkwer   = (*fuseNode)(nil)
	_ fs.NodeStatfser   = (*fuseNode)(nil)

	_ fs.NodeGetxattrer    = (*fuseNode)(nil)
	_ fs.NodeSetxattrer    = (*fuseNode)(nil)
	_ fs.NodeListxattrer   = (*fuseNode)(nil)
	_ fs.NodeRemovexattrer = (*fuseNode)(nil)
)

// xattrErrno maps a wire xattr status to the local syscall errno. The wire
// space is Linux-numbered; going through the syscall constants keeps the
// values right on every GOOS this frontend builds for.
func xattrErrno(st clientcore.Status) syscall.Errno {
	switch st {
	case fsproto.ENODATA:
		return syscall.ENODATA
	case fsproto.E2BIG:
		return syscall.E2BIG
	case fsproto.ERANGE:
		return syscall.ERANGE
	case fsproto.EOPNOTSUPP:
		return syscall.ENOTSUP
	default:
		return errno(st)
	}
}

// setxattrFlagBits returns the kernel's XATTR_CREATE/XATTR_REPLACE bits for
// this platform (Linux 0x1/0x2; Darwin 0x2/0x4).
func setxattrFlagBits() (create, replace uint32) {
	if runtime.GOOS == "darwin" {
		return 0x2, 0x4
	}
	return 0x1, 0x2
}

func (n *fuseNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	ctx = n.gateOp(ctx)
	value, st := n.v.Getxattr(ctx, n.curPath(), n.state, attr)
	if st != fsproto.OK {
		return 0, xattrErrno(st)
	}
	if len(dest) < len(value) {
		return uint32(len(value)), syscall.ERANGE // size probe / short buffer: report the needed size
	}
	copy(dest, value)
	return uint32(len(value)), 0
}

func (n *fuseNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	ctx = n.gateOp(ctx)
	names, st := n.v.Listxattr(ctx, n.curPath(), n.state)
	if st != fsproto.OK {
		return 0, xattrErrno(st)
	}
	total := 0
	for _, name := range names {
		total += len(name) + 1 // NUL-terminated concatenation (listxattr(2))
	}
	if len(dest) < total {
		return uint32(total), syscall.ERANGE
	}
	off := 0
	for _, name := range names {
		off += copy(dest[off:], name)
		dest[off] = 0
		off++
	}
	return uint32(total), 0
}

// Setxattr forwards XATTR_CREATE/XATTR_REPLACE to the authority so the
// existence predicate and mutation are one ordered, durable operation across
// every mount. There is intentionally no client-side probe/TOCTOU window.
func (n *fuseNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	ctx = n.gateOp(ctx)
	p := n.curPath()
	createBit, replaceBit := setxattrFlagBits()
	if flags & ^(createBit|replaceBit) != 0 {
		return syscall.EINVAL
	}
	var wireFlags uint8
	if flags&createBit != 0 {
		wireFlags |= wal.XattrCreate
	}
	if flags&replaceBit != 0 {
		wireFlags |= wal.XattrReplace
	}
	return xattrErrno(fuseMutateStatus(ctx, n, fuseNodes(n.state), []string{p},
		func(c context.Context) clientcore.Status {
			return n.v.SetxattrFlags(c, p, n.state, attr, data, wireFlags)
		}))
}

func (n *fuseNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	ctx = n.gateOp(ctx)
	p := n.curPath()
	return xattrErrno(fuseMutateStatus(ctx, n, fuseNodes(n.state), []string{p},
		func(c context.Context) clientcore.Status {
			return n.v.Removexattr(c, p, n.state, attr)
		}))
}

// ─── the FUSE frontend's pre-lock mutation admission ─────────────────────────
//
// FUSE has no namespace lock of its own, but the same argument as the daemon's
// applies one layer down: clientcore takes NodeState and exact locks and the
// engine takes e.mu, and a delegation transition or a backpressure wait inside
// either blocks the open-pin and delegation-release machinery that must be able
// to inspect those nodes. Resolving out here holds nothing.
//
// It is also the only place the namespace lane's BACKPRESSURE can be taken. A
// delegated create/mkdir/rename/unlink/setattr/xattr that finds the metadata
// lane momentarily full is answered ErrLaneChanged by the engine — never an
// instant EIO — precisely so the wait happens here, where it costs one
// operation instead of a mount.
//
// The loop is the unwind, not a retry-until-it-works: a lane resolved before
// the call can be invalidated during it, and the second pass resolves the
// authority lane unconditionally, which is not a claim about a grant. Every
// pass shares ONE absolute operation deadline, so the loop terminates on a
// definite interrupted outcome rather than on a pass count.

// fuseMutate runs one value-returning namespace mutation under the classifier.
func fuseMutate[T any](
	ctx context.Context,
	n *fuseNode,
	nodes []*clientcore.NodeState,
	paths []string,
	run func(context.Context) (T, clientcore.Status),
) (T, clientcore.Status) {
	var zero T
	opCtx, cancel := clientcore.WithOperationDeadline(ctx)
	defer cancel()
	for forceAuthority := false; ; forceAuthority = true {
		mctx, settle, err := n.v.AdmitMutation(opCtx, nodes, forceAuthority, paths...)
		if err != nil {
			settle()
			return zero, clientcore.MutationAdmissionStatus(err)
		}
		out, st := run(mctx)
		settle()
		if !clientcore.LaneChanged(st) {
			return out, st
		}
	}
}

// fuseMutateStatus is fuseMutate for the mutations that answer with a status
// and nothing else.
func fuseMutateStatus(
	ctx context.Context,
	n *fuseNode,
	nodes []*clientcore.NodeState,
	paths []string,
	run func(context.Context) clientcore.Status,
) clientcore.Status {
	_, st := fuseMutate(ctx, n, nodes, paths, func(c context.Context) (struct{}, clientcore.Status) {
		return struct{}{}, run(c)
	})
	return st
}

func fuseNodes(states ...*clientcore.NodeState) []*clientcore.NodeState {
	out := make([]*clientcore.NodeState, 0, len(states))
	for _, s := range states {
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

func (n *fuseNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
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

func (n *fuseNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	ctx = n.gateOp(ctx)
	cp := n.child(name)
	if n.g.Owner(cp) != "" {
		// The name is grafted: resolve against machine-local backing and
		// shadow whatever the volume has — no authority round trip.
		return n.g.LookupChild(ctx, n.EmbeddedInode(), cp, out)
	}
	a, st := n.v.Lookup(ctx, cp)
	if st != fsproto.OK {
		out.SetEntryTimeout(0)
		return nil, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	// go-fuse publishes metadata after this node callback returns, so no
	// callback-scoped mutex can extend through the kernel write. Zero TTL is
	// the exact contract: a reply may satisfy its overlapping syscall, but it
	// can never repopulate persistent metadata after a delegation handoff.
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	return n.newChild(ctx, name, &a), 0
}

func (n *fuseNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	ctx = n.gateOp(ctx)
	p := n.curPath()
	a, st := n.v.Getattr(ctx, p, n.state)
	if st != fsproto.OK {
		return errno(st)
	}
	fillAttr(p, &a, &out.Attr)
	out.SetTimeout(0)
	return 0
}

func (n *fuseNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	ctx = n.gateOp(ctx)
	dir := n.curPath()
	ents, st := n.v.Readdir(ctx, dir)
	if st != fsproto.OK {
		return nil, errno(st)
	}
	if n.g != nil {
		// Graft roots under this directory merge in exactly once (shadowing
		// same-named volume entries) and only when their backing exists.
		merged, eno := n.g.MergeParentListing(dir, ents)
		if eno != 0 {
			return nil, eno
		}
		ents = merged
	}
	list := make([]fuse.DirEntry, 0, len(ents))
	for _, e := range ents {
		list = append(list, fuse.DirEntry{Name: e.Name, Mode: typeBits(e.Attr.Kind), Ino: e.Ino})
	}
	return fs.NewListDirStream(list), 0
}

func (n *fuseNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	ctx = n.gateOp(ctx)
	p := n.curPath()
	writeIntent := flags&uint32(syscall.O_ACCMODE) != uint32(syscall.O_RDONLY)
	if st := n.v.Open(ctx, p, n.state, writeIntent); st != fsproto.OK {
		return nil, 0, errno(st)
	}
	return &fuseHandle{
		openPath: p,
		append:   flags&uint32(syscall.O_APPEND) != 0,
	}, fuse.FOPEN_KEEP_CACHE, 0
}

func (n *fuseNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	ctx = n.gateOp(ctx)
	p := n.curPath()
	admission, err := n.replyGate.BeginRead(ctx, p)
	if err != nil {
		return nil, syscall.EINTR
	}
	data, st := n.v.Read(ctx, p, n.state, off, len(dest))
	if st != fsproto.OK {
		admission.Abort()
		return nil, errno(st)
	}
	if admission.Revoked() {
		// The request was interrupted while suspended for an authority wait,
		// so it never got back into the publication order. Answering EINTR is
		// the same answer an interrupt before admission already produces; the
		// one thing that must not happen is publishing a reply the gate can no
		// longer prove is on the current side of a handoff.
		admission.Abort()
		return nil, syscall.EINTR
	}
	return admission.Wrap(fuse.ReadResultData(data)), 0
}

// Write resolves the request's lane outside the volume call, then executes it.
//
// FUSE has no namespace lock of its own here, but the same argument as the
// daemon's applies one layer down: clientcore's write path takes the NodeState
// lock and the engine takes e.mu, and a delegation transition or a pacing wait
// inside either blocks the open-pin and delegation-release machinery that must
// be able to inspect this node. Resolving out here holds nothing.
//
// The two passes are the unwind: a lane resolved before the call can be
// invalidated during it by a recall this frontend does not control, and the
// engine reports that rather than transitioning under the locks. The second
// pass takes the authority lane unconditionally, and that lane consumes no
// stream budget at all, so a recall has nothing left to invalidate.
func (n *fuseNode) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	ctx = n.gateOp(ctx)
	for forceAuthority := false; ; forceAuthority = true {
		cnt, eno, unwound := n.writeOnce(ctx, fh, data, off, forceAuthority)
		if !unwound {
			return cnt, eno
		}
	}
}

func (n *fuseNode) writeOnce(
	ctx context.Context,
	fh fs.FileHandle,
	data []byte,
	off int64,
	forceAuthority bool,
) (uint32, syscall.Errno, bool) {
	p := n.curPath()
	// gateOp is applied by the caller and left untouched: the operation context
	// wraps the gated one, so suspension and publication wiring see the
	// identical operation identity they did before.
	opCtx, granted, settle, err := n.v.AdmitWrite(ctx, p, n.state, len(data), forceAuthority)
	defer settle()
	if err != nil {
		return 0, creditErrno(err), false
	}
	// A short grant becomes a short write, which FUSE replies natively; the
	// kernel reissues the remainder as a new request, classified from scratch.
	data = data[:granted]
	var cnt int
	var st clientcore.Status
	if h, ok := fh.(*fuseHandle); ok && h.append {
		cnt, st = n.v.WriteAppend(opCtx, p, n.state, off, data)
	} else {
		cnt, st = n.v.Write(opCtx, p, n.state, off, data)
	}
	if clientcore.LaneChanged(st) {
		return 0, 0, true
	}
	if st != fsproto.OK {
		return 0, errno(st), false
	}
	if len(data) > 0 && cnt <= 0 {
		// Zero committed progress for a non-empty payload is NOT a short
		// write. A short write is progress an application can build on: it
		// advances its buffer and issues the rest. Zero progress with no error
		// is the one reply it cannot act on — the buffer is unchanged, nothing
		// says why, and every libc write loop and io.Writer-shaped caller
		// answers it by reissuing the identical request. That is a livelock on
		// the positional lane and a duplication hazard on the appending one,
		// where the retry resolves EOF a second time and cannot land on the
		// first copy.
		//
		// The same rule already governs the count going the other way: this
		// operation's admission (Volume.AdmitWrite) refuses to hand back a
		// zero-byte grant without an error, because a zero-length successful
		// write is not a signal any kernel write path can act on. What was
		// GRANTED and what was COMMITTED answer to one contract, so the write
		// ends in an errno rather than a success that made no progress.
		//
		// Positive counts stay short writes: those are correct, and the kernel
		// reissues the remainder as a fresh request classified from scratch.
		return 0, syscall.EIO, false
	}
	return uint32(cnt), 0, false
}

// creditErrno maps a refused data-lane admission to the errno FUSE replies.
// ENOSPC only for an operation this store can never fit; a far end that stopped
// answering (writeback.ErrUplinkStalled) is EIO, and a cancelled request is
// EINTR. The daemon frontend makes the identical classification in
// portablefsd.creditErrno — the two frontends must not disagree about what a
// stalled uplink looks like to an application.
func creditErrno(err error) syscall.Errno {
	switch {
	case errors.Is(err, writeback.ErrNoSpace):
		return syscall.ENOSPC
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return syscall.EINTR
	default:
		return syscall.EIO
	}
}

func (n *fuseNode) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	ctx = n.gateOp(ctx)
	cp := n.child(name)
	if n.g.Owner(cp) != "" {
		// At a volume parent this can only be the graft root itself, which is
		// a directory rule: EISDIR (CreateChild enforces it).
		return n.g.CreateChild(ctx, n.EmbeddedInode(), cp, flags, mode, out)
	}
	a, st := fuseMutate(ctx, n, nil, []string{cp},
		func(c context.Context) (fsproto.Attr, clientcore.Status) {
			if flags&syscall.O_EXCL != 0 {
				return n.v.CreateExcl(c, cp, mode)
			}
			return n.v.Create(c, cp, mode)
		})
	if st != fsproto.OK {
		return nil, nil, 0, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	ch := n.newChild(ctx, name, &a)
	if cn, ok := ch.Operations().(*fuseNode); ok {
		// Count the just-opened handle so a peer unlink parks the inode
		// (delete-on-last-close) instead of breaking the fresh fd.
		if n.v.RegisterOpened(ctx, cp, cn.state) == fsproto.ENOENT {
			return nil, nil, 0, syscall.ENOENT
		}
	}
	return ch, &fuseHandle{
		openPath: cp,
		append:   flags&uint32(syscall.O_APPEND) != 0,
	}, fuse.FOPEN_KEEP_CACHE, 0
}

func (n *fuseNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	ctx = n.gateOp(ctx)
	cp := n.child(name)
	if n.g.Owner(cp) != "" {
		// mkdir of the graft root creates it machine-local (with scaffold);
		// this is the only way a graft root comes into existence.
		return n.g.MkdirChild(ctx, n.EmbeddedInode(), cp, mode, out)
	}
	a, st := fuseMutate(ctx, n, nil, []string{cp},
		func(c context.Context) (fsproto.Attr, clientcore.Status) {
			return n.v.Mkdir(c, cp, mode)
		})
	if st != fsproto.OK {
		return nil, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	return n.newChild(ctx, name, &a), 0
}

func (n *fuseNode) Unlink(ctx context.Context, name string) syscall.Errno {
	ctx = n.gateOp(ctx)
	cp := n.child(name)
	if n.g.Owner(cp) != "" {
		return n.g.Remove(cp, false)
	}
	child := n.childState(name)
	return errno(fuseMutateStatus(ctx, n, fuseNodes(child), []string{cp},
		func(c context.Context) clientcore.Status { return n.v.Remove(c, cp, child) }))
}

func (n *fuseNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	ctx = n.gateOp(ctx)
	cp := n.child(name)
	if n.g.Owner(cp) != "" {
		// rmdir of the graft root removes it like any directory (ENOTEMPTY
		// while it has contents) — the npm-ci wholesale-rebuild path.
		return n.g.Remove(cp, true)
	}
	child := n.childState(name)
	return errno(fuseMutateStatus(ctx, n, fuseNodes(child), []string{cp},
		func(c context.Context) clientcore.Status { return n.v.Remove(c, cp, child) }))
}

func (n *fuseNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	ctx = n.gateOp(ctx)
	np, ok := newParent.(*fuseNode)
	if !ok {
		return syscall.EXDEV
	}
	oldp, newp := n.child(name), np.child(newName)
	if eno, handled := n.g.VolumeRenameCheck(oldp, newp); handled {
		return eno
	}
	src, dst := n.childState(name), np.childState(newName)
	st := fuseMutateStatus(ctx, n, fuseNodes(src, dst), []string{oldp, newp},
		func(c context.Context) clientcore.Status {
			return n.v.Rename(c, oldp, newp, src, dst)
		})
	if st == fsproto.OK {
		// A volume rename of a graft root's ancestor carries the graft and
		// its machine-local backing to the new location.
		n.g.RemapForRename(oldp, newp)
	}
	return errno(st)
}

func (n *fuseNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	ctx = n.gateOp(ctx)
	cp := n.child(name)
	if n.g.Owner(cp) != "" {
		// At a volume parent this can only be the graft root: EISDIR.
		return n.g.SymlinkChild(ctx, n.EmbeddedInode(), target, cp, out)
	}
	a, st := fuseMutate(ctx, n, nil, []string{cp},
		func(c context.Context) (fsproto.Attr, clientcore.Status) {
			return n.v.Symlink(c, target, cp)
		})
	if st != fsproto.OK {
		return nil, errno(st)
	}
	fillAttr(cp, &a, &out.Attr)
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	return n.newChild(ctx, name, &a), 0
}

func (n *fuseNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	ctx = n.gateOp(ctx)
	oldp := target.EmbeddedInode().Path(nil)
	newp := n.child(name)
	if n.g.Owner(oldp) != "" || n.g.Owner(newp) != "" {
		return n.g.LinkChild(ctx, n.EmbeddedInode(), target, name, out)
	}
	src, ok := target.(*fuseNode)
	if !ok {
		return nil, syscall.EXDEV
	}
	a, st := fuseMutate(ctx, n, fuseNodes(src.state), []string{oldp, newp},
		func(c context.Context) (fsproto.Attr, clientcore.Status) {
			return n.v.Link(c, oldp, newp, src.state)
		})
	if st != fsproto.OK {
		return nil, errno(st)
	}
	fillAttr(newp, &a, &out.Attr)
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	return n.newChild(ctx, name, &a), 0
}

func (n *fuseNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	ctx = n.gateOp(ctx)
	t, st := n.v.Readlink(ctx, n.curPath())
	if st != fsproto.OK {
		return nil, errno(st)
	}
	return []byte(t), 0
}

func (n *fuseNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	ctx = n.gateOp(ctx)
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
	a, st := fuseMutate(ctx, n, fuseNodes(n.state), []string{p},
		func(c context.Context) (fsproto.Attr, clientcore.Status) {
			return n.v.Setattr(c, p, n.state, req)
		})
	if st != fsproto.OK {
		return errno(st)
	}
	if a.Kind != "" {
		fillAttr(p, &a, &out.Attr)
	}
	out.SetTimeout(0)
	return 0
}

func (n *fuseNode) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	return errno(n.v.FsyncHandle(n.curPath(), n.state))
}

// Flush runs on every close(2), including intermediate closes of shared
// descriptions; advisory locks are released in Release (final close) only.
func (n *fuseNode) Flush(ctx context.Context, fh fs.FileHandle) syscall.Errno { return 0 }

func (n *fuseNode) Release(ctx context.Context, fh fs.FileHandle) syscall.Errno {
	if h, ok := fh.(*fuseHandle); ok {
		clientcore.ReleaseHandleLocks(n.v.LockAuth(), &h.lock)
		return errno(n.v.CloseHandle(h.openPath, n.state))
	}
	return errno(n.v.CloseHandle(n.curPath(), n.state))
}

func (n *fuseNode) lockHandle(fh fs.FileHandle) *clientcore.LockHandle {
	if h, ok := fh.(*fuseHandle); ok {
		return &h.lock
	}
	return nil
}

func (n *fuseNode) Getlk(ctx context.Context, fh fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	ctx = n.gateOp(ctx)
	res, err := n.v.Getlk(ctx, n.curPath(), owner, lk.Start, lk.End, lk.Typ == clientcore.LockWrite)
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
	out.Pid = 0 // holder may be on another machine; a local pid is meaningless
	return 0
}

func (n *fuseNode) Setlk(ctx context.Context, fh fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	ctx = n.gateOp(ctx)
	p := n.curPath()
	if lk.Typ == clientcore.LockUnlock {
		// Unlock never fails toward the app; a lost release is reclaimed by the
		// authority when this mount's liveness stream drops.
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

func (n *fuseNode) Setlkw(ctx context.Context, fh fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	ctx = n.gateOp(ctx)
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
// the content, and the parent dentry only for a name-binding change. In-place
// changes must not drop dentries — disconnecting a CWD dentry breaks
// concurrent getcwd() in processes running inside the mount.
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
// Deliberately content-only: entry timeouts are 0, so existence coherence
// comes from lookup revalidation, and dentry drops would break in-use CWDs.
// Grafted subtrees are skipped: their kernel cache is backed by machine-local
// disk that no authority event can invalidate.
func flushAll(n *fs.Inode) {
	_ = flushAllExact(n)
}

// flushAllExact is the delegation-handoff boundary: success means every
// currently materialized non-grafted vnode under n accepted its content
// invalidation before the authority grant is released.
func flushAllExact(n *fs.Inode) error {
	if localdirs.IsLocalNode(n.Operations()) {
		return nil
	}
	if errno := n.NotifyContent(0, 0); errno != 0 {
		return errno
	}
	for _, child := range n.Children() {
		if err := flushAllExact(child); err != nil {
			return err
		}
	}
	return nil
}

// fuseMount is one live in-process FUSE mount.
type fuseMount struct {
	server    *fuse.Server
	vol       *clientcore.Volume
	stop      context.CancelFunc
	renewWG   sync.WaitGroup
	mountPath string
	grafts    *localdirs.Grafts
	// localDirs is the effective graft set served by this mount (flags +
	// persisted state + the volume's .portablefs/local-dirs file).
	localDirs []string
	// detachExact proves and removes this server's recorded kernel mount with
	// the one persisted mechanism. It never asks go-fuse to resolve PATH.
	detachExact func() error
}

// localDirsMountConfig configures machine-local dirs for one FUSE mount.
type localDirsMountConfig struct {
	// dirs are the flag/persistence-level graft roots (already validated).
	dirs []string
	// backingRoot is <stateBase>/local/<storageID>; required when any graft
	// can apply (the volume config file may add dirs even when dirs is empty).
	backingRoot string
	// disableVolumeFile skips the volume's .portablefs/local-dirs declaration
	// (--no-local-dirs: grafts fully off for this mount).
	disableVolumeFile bool
	// onChange observes remaps (ancestor renames) so the CLI can persist the
	// carried names.
	onChange func([]string)
}

// mountFUSE dials the authority and mounts it at mountPath, wiring push
// invalidation, open-lease renewal, and the default cache options. tokens
// serves the one live lease's credential to reconnect handshakes.
func mountFUSE(addr string, tokens *sessionTokenSource, transport dataPlaneTransport, mountPath, mountInstanceID, mountMechanism, fuseHelperPath string, perf perfOptions, localCfg localDirsMountConfig) (*fuseMount, error) {
	if mountMechanism != "direct" && mountMechanism != "helper" {
		return nil, fmt.Errorf("invalid deterministic FUSE mount mechanism %q", mountMechanism)
	}
	if mountMechanism == "direct" && fuseHelperPath != "" {
		return nil, fmt.Errorf("direct FUSE mount must not carry a helper path")
	}
	tlsCfg, err := transport.tlsConfig()
	if err != nil {
		return nil, fmt.Errorf("data-plane transport: %w", err)
	}
	var rootHolder struct {
		mu   sync.Mutex
		node *fuseNode
	}
	var frontendReplies fusefrontend.ReplyGate
	rootInode := func() *fs.Inode {
		rootHolder.mu.Lock()
		defer rootHolder.mu.Unlock()
		if rootHolder.node == nil {
			return nil
		}
		return rootHolder.node.EmbeddedInode()
	}
	// grafts is assigned after Dial (the volume's .portablefs/local-dirs file
	// contributes) and before any invalidation goroutine starts; the closures
	// below only run from those goroutines.
	var grafts *localdirs.Grafts
	flushFrontend := func(path string) {
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
	}
	flushFrontendExact := func(path string) error {
		root := rootInode()
		if root == nil {
			return nil
		}
		if path == "" {
			return flushAllExact(root)
		}
		if in := walkInode(root, path); in != nil {
			return flushAllExact(in)
		}
		return nil
	}
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr:             addr,
		Pool:             16,
		TLSConfig:        tlsCfg,
		Owner:            "portablefs-" + randomID(),
		CredentialSource: tokens.get,
		// A router token rejection fails closed. The lease keeper owns the
		// sole credential-advance path and never mints a replacement lease.
		// The write-back engine's durable state: keyed by (volume, branch)
		// so a parked stream recovers on the next mount at ANY path.
		WALDir:          perf.writebackDir,
		VolumeID:        perf.volumeID,
		Branch:          perf.branch,
		NegativeCache:   perf.negativeCache,
		NoNegativeCache: perf.negativeCacheOff,
		OnFlushAll:      flushFrontend,
		OnHandoffStart:  frontendReplies.BeginHandoff,
		OnHandoffEnd:    frontendReplies.EndHandoff,
		OnHandoffFlush:  flushFrontendExact,
		// Publication suspension. Without it the drain above can wait on a
		// request that is itself waiting on the authority — a foreign
		// delegation recall, this mount's own release, or a blocking
		// advisory-lock acquire — which is the two-machine deadlock geometry.
		OnOperationWait: frontendReplies.SuspendOperation,
		OnInvalidate: func(path string, inPlace bool) {
			if grafts.Owner(path) != "" {
				// Volume changes under a graft are shadowed by machine-local
				// backing; surfacing them would evict valid local kernel state.
				return
			}
			if root := rootInode(); root != nil {
				invalidatePath(root, path, inPlace)
			}
		},
		OnMarkOrphan: func(path string, ino uint64) {
			if grafts.Owner(path) != "" {
				return
			}
			root := rootInode()
			if root == nil {
				return
			}
			if in := walkInode(root, path); in != nil {
				if cn, ok := in.Operations().(*fuseNode); ok {
					cn.state.MarkOrphan(ino, cn.v.OpenOrphans())
				}
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("connect to authority %s: %w", addr, err)
	}

	// Effective grafts = flag/persisted dirs ∪ the volume's declaration file.
	// Union semantics are permissive (dedupe, outer graft wins over nested)
	// because the sources are independent; each flag list was already
	// strictly validated at parse time.
	var volumeDirs []string
	if !localCfg.disableVolumeFile {
		volumeDirs = localdirs.ReadVolumeConfig(context.Background(), vol, func(format string, args ...any) {
			log.Printf("portablefs mount: "+format, args...)
		})
	}
	effectiveDirs, err := localdirs.Normalize(append(append([]string(nil), localCfg.dirs...), volumeDirs...))
	if err != nil {
		_ = vol.Close()
		return nil, fmt.Errorf("resolve local dirs: %w", err)
	}
	if len(effectiveDirs) > 0 {
		grafts, err = localdirs.New(localCfg.backingRoot, effectiveDirs, localCfg.onChange)
		if err != nil {
			_ = vol.Close()
			return nil, fmt.Errorf("configure local dirs: %w", err)
		}
		log.Printf("machine-local dirs: %s (backing %s)", strings.Join(effectiveDirs, ", "), localCfg.backingRoot)
	}

	// Kernel caching default: file data is cached and
	// kept across opens, attrs and existence revalidate every time (ttl 0);
	// coherence comes from the authority's push invalidations, never timers.
	ttl := time.Duration(0)
	entryTTL := time.Duration(0)
	opts := &fs.Options{
		AttrTimeout:  &ttl,
		EntryTimeout: &entryTTL,
		// chmod 000 must stick; without this go-fuse rewrites null permissions.
		NullPermissions: true,
		MountOptions: fuse.MountOptions{
			FsName:            "portablefs:" + mountInstanceID,
			Name:              "portablefs",
			DirectMountStrict: mountMechanism == "direct",
			MaxWrite:          1 << 20,
			MaxReadAhead:      1 << 20,
			MaxBackground:     256,
			EnableLocks:       true,
		},
	}
	root := &fuseNode{v: vol, state: clientcore.NewNodeState(1, true), g: grafts, replyGate: &frontendReplies}
	if mountMechanism == "helper" {
		if err := validateSelectedFUSEHelper(fuseHelperPath, mounthost.FUSEHelper); err != nil {
			_ = grafts.Close()
			_ = vol.Close()
			return nil, err
		}
	}
	server, err := mountNodeFS(mountPath, root, opts, mountMechanism, fuseHelperPath, func() {
		// NewNodeFS has initialized the embedded inode and NewServer has
		// installed the notification bridge, but Serve has not begun. Publish
		// in this exact gap: asynchronous handoff flushes can safely traverse
		// the tree before the first kernel reply can populate a cache.
		rootHolder.mu.Lock()
		rootHolder.node = root
		rootHolder.mu.Unlock()
	})
	if err != nil {
		rootHolder.mu.Lock()
		if rootHolder.node == root {
			rootHolder.node = nil
		}
		rootHolder.mu.Unlock()
		_ = grafts.Close()
		_ = vol.Close()
		return nil, fmt.Errorf("mount %s: %w", mountPath, err)
	}

	ctx, stop := context.WithCancel(context.Background())
	m := &fuseMount{server: server, vol: vol, stop: stop, mountPath: mountPath, grafts: grafts, localDirs: effectiveDirs}
	m.renewWG.Add(1)
	go func() {
		defer m.renewWG.Done()
		// Volume-owned renewal: confirmations feed the open registry so
		// retained open registrations stay reusable (see clientcore/openreg.go).
		vol.RunOpenLeaseRenewal(ctx, 20*time.Second, nil)
	}()
	go vol.StartInvalidations(ctx, false)
	return m, nil
}

func validateSelectedFUSEHelper(selected string, resolve func() (string, bool)) error {
	return validateSelectedFUSEHelperWith(selected, mounthost.ValidateFUSEHelper, resolve)
}

func validateSelectedFUSEHelperWith(selected string, validate func(string) error, resolve func() (string, bool)) error {
	if err := validate(selected); err != nil {
		return fmt.Errorf("selected FUSE helper is not trusted at mount boundary: %w", err)
	}
	resolved, ok := resolve()
	if !ok {
		return fmt.Errorf("selected FUSE helper %s disappeared before mount", selected)
	}
	if resolved != selected {
		return fmt.Errorf("FUSE helper resolution changed before mount: selected %s, now %s", selected, resolved)
	}
	return nil
}

// Unmount runs the full drain barrier and detaches only on success: a
// normal unmount can never succeed with an unshipped acknowledged tail. On
// failure the kernel mount STAYS UP and the error is returned — the caller
// retries, or uses the explicit force path (which parks the tail as a
// durable recovery job).
func (m *fuseMount) Unmount() error {
	err := m.vol.CloseWithFinalizer(func() error {
		if m.detachExact == nil {
			return fmt.Errorf("exact kernel detach callback is not installed")
		}
		if err := m.detachExact(); err != nil {
			return err
		}
		m.stop()
		return nil
	})
	if err != nil {
		log.Printf("unmount REFUSED: final drain or kernel detach failed: %v — the mount stays attached; retry when the authority answers, or `portablefs umount --force` parks the tail as a durable recovery job", err)
		return err
	}
	return nil
}

// ForceUnmount is the explicit journal-first teardown. It first makes the
// write-back recovery job durable, then durably publishes the caller's ack,
// and only then proves and removes the exact kernel mount.
func (m *fuseMount) ForceUnmount(publishAck func(string) error) error {
	jobID, err := m.vol.CloseJournalDurable()
	if err != nil {
		return fmt.Errorf("durably park forced write-back tail: %w", err)
	}
	if err := publishAck(jobID); err != nil {
		return fmt.Errorf("publish durable force-park acknowledgement: %w", err)
	}
	if m.detachExact == nil {
		return fmt.Errorf("exact kernel detach callback is not installed")
	}
	if err := m.detachExact(); err != nil {
		return err
	}
	m.stop()
	return nil
}

// Wait blocks until the kernel mount is gone, then releases client resources.
func (m *fuseMount) Wait() error {
	m.server.Wait()
	m.stop()
	m.renewWG.Wait()
	return errors.Join(m.vol.Close(), m.grafts.Close())
}
