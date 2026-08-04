//go:build linux

// Package fusev3 is the branchless PortableFS v3 Linux mount frontend. It is
// intentionally thin: the authority owns every open file description and all
// filesystem state, while the kernel-facing process retains no dirty data.
package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const (
	renameNoReplace = 1
	renameExchange  = 2
)

// RPC is the exact authority contract required by the mount. Keeping this
// interface narrow makes kernel mapping independently fault-testable.
type RPC interface {
	Root() *authoritypb.Item
	IOLimits() (uint32, uint32)
	SessionLease() time.Duration
	SessionDone() <-chan struct{}
	SessionError() error
	CallRead(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallMutation(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	Close() error
}

type Config struct {
	FSName         string
	RequestTimeout time.Duration
	MaxBackground  int
	ReclaimQueue   int
	PresentedUID   uint32
	PresentedGID   uint32
}

type Mount struct {
	server   *fuse.Server
	frontend *rawFileSystem
	rpc      RPC
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool
	abort    sync.Once
	fatalMu  sync.Mutex
	fatalErr error
	reclaim  chan []byte
	uid      uint32
	gid      uint32
}

// MountVolume mounts one authority session without a write-back cache. Direct
// I/O plus zero attr/entry TTLs is the correctness-first coherence contract:
// every completed read has gone through the one active volume authority.
// Shared mmap is intentionally unavailable because the mount cannot revoke
// kernel-cached pages coherently when another machine mutates the same file.
func MountVolume(parent context.Context, mountpoint string, rpc RPC, cfg Config) (*Mount, error) {
	if mountpoint == "" || rpc == nil || cfg.FSName == "" || cfg.RequestTimeout <= 0 || cfg.MaxBackground <= 0 || cfg.ReclaimQueue <= 0 {
		return nil, errors.New("fusev3: complete mount configuration is required")
	}
	rootItem := rpc.Root()
	if rootItem == nil || rootItem.GetAttr() == nil || len(rootItem.GetToken()) == 0 {
		return nil, errors.New("fusev3: authority omitted root identity")
	}
	maxRead, maxWrite := rpc.IOLimits()
	lease := rpc.SessionLease()
	if maxRead == 0 || maxWrite == 0 || lease <= 0 || rpc.SessionDone() == nil {
		return nil, errors.New("fusev3: invalid negotiated authority bounds")
	}
	ctx, cancel := context.WithCancel(parent)
	m := &Mount{rpc: rpc, ctx: ctx, cancel: cancel, reclaim: make(chan []byte, cfg.ReclaimQueue), uid: cfg.PresentedUID, gid: cfg.PresentedGID}
	root := &node{mount: m, item: cloneItem(rootItem), requestTimeout: cfg.RequestTimeout, maxRead: maxRead, maxWrite: maxWrite}
	frontend := newRawFileSystem(m, root)
	server, err := fuse.NewServer(frontend, mountpoint, mountOptions(cfg, maxWrite))
	if err != nil {
		cancel()
		_ = rpc.Close()
		return nil, fmt.Errorf("mount PortableFS v3: %w", err)
	}
	m.server = server
	m.frontend = frontend
	go server.Serve()
	if err := server.WaitMount(); err != nil {
		// NewServer has already installed the kernel mount. If INIT or the
		// readiness probe fails, remove it before releasing the authority
		// session so callers can never observe a mounted but unserved path.
		_ = server.Unmount()
		server.Wait()
		cancel()
		_ = rpc.Close()
		return nil, fmt.Errorf("initialize PortableFS v3 mount: %w", err)
	}
	m.wg.Add(3)
	go m.keepAlive(ctx, lease)
	go m.reclaimLoop(ctx, cfg.RequestTimeout)
	go m.watchSession(ctx, rpc.SessionDone())
	return m, nil
}

func mountOptions(cfg Config, maxWrite uint32) *fuse.MountOptions {
	return &fuse.MountOptions{
		FsName:             cfg.FSName,
		Name:               "portablefs",
		MaxReadAhead:       0,
		MaxWrite:           int(maxWrite),
		MaxBackground:      cfg.MaxBackground,
		EnableLocks:        true,
		DisableReadDirPlus: true,
		Options:            []string{"default_permissions"},
	}
}

func (m *Mount) keepAlive(ctx context.Context, lease time.Duration) {
	defer m.wg.Done()
	interval := lease / 3
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			callCtx, cancel := context.WithTimeout(ctx, interval)
			response, err := m.rpc.CallRead(callCtx, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
			cancel()
			if err != nil || responseErrno(response) != 0 {
				// A failed renewal is terminal. Keeping the path mounted would let
				// callers observe a long tail of unrelated per-operation failures.
				if err == nil {
					err = fmt.Errorf("keepalive refused: %w", responseErrno(response))
				}
				m.failAsync(fmt.Errorf("fusev3: authority keepalive failed: %w", err))
				return
			}
		}
	}
}

func (m *Mount) watchSession(ctx context.Context, done <-chan struct{}) {
	defer m.wg.Done()
	select {
	case <-ctx.Done():
		return
	case <-done:
		if ctx.Err() == nil {
			err := m.rpc.SessionError()
			if err == nil {
				err = errors.New("authority session ended")
			}
			m.failAsync(fmt.Errorf("fusev3: %w", err))
		}
	}
}

func (m *Mount) reclaimLoop(ctx context.Context, timeout time.Duration) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case token := <-m.reclaim:
			callCtx, cancel := context.WithTimeout(ctx, timeout)
			response, err := m.rpc.CallRead(callCtx, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: token}}})
			cancel()
			if err != nil || responseErrno(response) != 0 {
				if err == nil {
					err = fmt.Errorf("reclaim refused: %w", responseErrno(response))
				}
				m.failAsync(fmt.Errorf("fusev3: object reclaim failed: %w", err))
				return
			}
		}
	}
}

func (m *Mount) Wait() { m.server.Wait() }

func (m *Mount) Unmount() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	if err := m.server.Unmount(); err != nil {
		return err
	}
	return m.closeLocked()
}

// Close releases the authority session after the kernel mount has already
// disappeared (for example, an administrator unmounted it externally).
func (m *Mount) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeLocked()
}

func (m *Mount) closeLocked() error {
	if m.closed {
		return m.fatalError()
	}
	m.closed = true
	m.cancel()
	m.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = m.rpc.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{}}})
	cancel()
	return errors.Join(m.fatalError(), m.rpc.Close())
}

func (m *Mount) fatalError() error {
	m.fatalMu.Lock()
	defer m.fatalMu.Unlock()
	return m.fatalErr
}

type node struct {
	mount          *Mount
	item           *authoritypb.Item
	requestTimeout time.Duration
	maxRead        uint32
	maxWrite       uint32
}

type fileHandle struct {
	node   *node
	token  []byte
	append bool
	once   sync.Once
}

type dirHandle struct {
	node     *node
	token    []byte
	mu       sync.Mutex
	cookie   []byte
	verifier []byte
	page     []*authoritypb.Dirent
	index    int
	eof      bool
	once     sync.Once
}

func (n *node) opContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, n.requestTimeout)
}

func (n *node) read(parent context.Context, request *authoritypb.Request) (*authoritypb.Response, syscall.Errno) {
	ctx, cancel := n.opContext(parent)
	defer cancel()
	response, err := n.mount.rpc.CallRead(ctx, request)
	return response, rpcErrno(response, err)
}

func (n *node) mutate(parent context.Context, request *authoritypb.Request) (*authoritypb.Response, syscall.Errno) {
	ctx, cancel := n.opContext(parent)
	defer cancel()
	response, err := n.mount.rpc.CallMutation(ctx, request)
	return response, rpcErrno(response, err)
}

func (n *node) Lookup(ctx context.Context, name string) (*authoritypb.Item, syscall.Errno) {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name)}}})
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLookup().GetItem()
	if item == nil || item.GetAttr() == nil {
		return nil, syscall.EIO
	}
	return cloneItem(item), 0
}

func (n *node) Getattr(ctx context.Context, fh *fileHandle, out *fuse.AttrOut) syscall.Errno {
	req := &authoritypb.GetAttrRequest{Item: cloneBytes(n.item.GetToken())}
	if fh != nil {
		req.Item, req.Handle = nil, cloneBytes(fh.token)
	}
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: req}})
	if errno != 0 {
		return errno
	}
	attr := response.GetGetAttr().GetAttr()
	if attr == nil {
		return syscall.EIO
	}
	fillAttr(attr, &out.Attr, n.mount.uid, n.mount.gid)
	out.SetTimeout(0)
	return 0
}

func (n *node) Open(ctx context.Context, flags uint32) (*fileHandle, uint32, syscall.Errno) {
	openFlags, errno := protocolOpenFlags(flags)
	if errno != 0 {
		return nil, 0, errno
	}
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytes(n.item.GetToken()), Flags: openFlags}}})
	if errno != 0 {
		return nil, 0, errno
	}
	if response.GetOpen() == nil || len(response.GetOpen().GetHandle()) == 0 {
		return nil, 0, syscall.EIO
	}
	return &fileHandle{node: n, token: cloneBytes(response.GetOpen().GetHandle()), append: openFlags.GetAppend()}, fuse.FOPEN_DIRECT_IO, 0
}

func (n *node) Read(ctx context.Context, handle *fileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if handle == nil || off < 0 {
		return nil, syscall.EBADF
	}
	written := 0
	for written < len(dest) {
		length := min(len(dest)-written, int(n.maxRead))
		response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: cloneBytes(handle.token), Offset: uint64(off) + uint64(written), Length: uint32(length)}}})
		if errno != 0 {
			return nil, errno
		}
		if response.GetRead() == nil {
			return nil, syscall.EIO
		}
		chunk := response.GetRead().GetData()
		if len(chunk) > length {
			return nil, syscall.EIO
		}
		copy(dest[written:], chunk)
		written += len(chunk)
		if len(chunk) < length {
			break
		}
	}
	return fuse.ReadResultData(dest[:written]), 0
}

func (n *node) Write(ctx context.Context, handle *fileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	if handle == nil || off < 0 {
		return 0, syscall.EBADF
	}
	if len(data) == 0 {
		return 0, 0
	}
	// MaxWrite is negotiated with the kernel at mount time. Splitting one
	// kernel write here would turn it into multiple independently ordered
	// authority mutations and violate the operation boundary.
	if n.maxWrite == 0 || uint64(len(data)) > uint64(n.maxWrite) {
		return 0, syscall.EIO
	}
	ctx, cancel := n.opContext(ctx)
	defer cancel()
	requestOffset := uint64(off)
	if handle.append {
		requestOffset = 0
	}
	response, err := n.mount.rpc.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: cloneBytes(handle.token), Offset: requestOffset, Data: cloneBytes(data), Append: handle.append}}})
	if err != nil {
		return 0, rpcErrno(response, err)
	}
	errno := responseErrno(response)
	if response == nil || response.GetWrite() == nil {
		if errno != 0 {
			return 0, errno
		}
		return 0, syscall.EIO
	}
	count := response.GetWrite().GetCount()
	if count > uint32(len(data)) {
		return 0, syscall.EIO
	}
	if count > 0 {
		// Linux cannot return both positive progress and errno from write(2).
		// Preserve the committed prefix; a caller may retry the remainder.
		return count, 0
	}
	if errno != 0 {
		return 0, errno
	}
	return 0, syscall.EIO
}

func (n *node) Fsync(ctx context.Context, handle *fileHandle, flags uint32) syscall.Errno {
	if handle == nil {
		return syscall.EBADF
	}
	_, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: cloneBytes(handle.token), DataOnly: flags != 0}}})
	return errno
}

func (n *node) Flush(ctx context.Context, handle *fileHandle, lockOwner uint64) syscall.Errno {
	if handle == nil {
		return syscall.EBADF
	}
	_, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Flush{Flush: &authoritypb.FlushRequest{Handle: cloneBytes(handle.token), LockOwner: lockOwner}}})
	return errno
}

func (n *node) Release(ctx context.Context, handle *fileHandle) syscall.Errno {
	if handle == nil {
		return syscall.EBADF
	}
	return handle.close(ctx, 0, false)
}

func (h *fileHandle) close(ctx context.Context, lockOwner uint64, flockUnlock bool) syscall.Errno {
	var errno syscall.Errno
	h.once.Do(func() {
		_, errno = h.node.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytes(h.token), LockOwner: lockOwner, FlockUnlock: flockUnlock}}})
	})
	return errno
}

func (n *node) OpendirHandle(ctx context.Context, flags uint32) (*dirHandle, uint32, syscall.Errno) {
	if flags&uint32(syscall.O_ACCMODE) != uint32(syscall.O_RDONLY) {
		return nil, 0, syscall.EISDIR
	}
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytes(n.item.GetToken()), Flags: &authoritypb.OpenFlags{Read: true}}}})
	if errno != 0 {
		return nil, 0, errno
	}
	return &dirHandle{node: n, token: cloneBytes(response.GetOpen().GetHandle())}, 0, 0
}

func (h *dirHandle) Readdirent(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for h.index >= len(h.page) {
		if h.eof {
			return nil, 0
		}
		response, errno := h.node.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: cloneBytes(h.token), Cookie: cloneBytes(h.cookie), Verifier: cloneBytes(h.verifier), MaxEntries: 256}}})
		if errno != 0 {
			return nil, errno
		}
		page := response.GetReadDir()
		if page == nil || len(page.GetVerifier()) == 0 {
			return nil, syscall.EIO
		}
		h.page, h.index, h.eof = page.GetEntries(), 0, page.GetEof()
		h.verifier = cloneBytes(page.GetVerifier())
		if len(h.page) == 0 && !h.eof {
			return nil, syscall.EIO
		}
	}
	entry := h.page[h.index]
	h.index++
	attr := entry.GetAttr()
	if attr == nil {
		return nil, syscall.EIO
	}
	h.cookie = cloneBytes(entry.GetNextCookie())
	return &fuse.DirEntry{Name: string(entry.GetName()), Mode: kindMode(attr.GetKind()), Ino: attr.GetInode(), Off: decodeCookie(entry.GetNextCookie())}, 0
}

func (h *dirHandle) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cookie = encodeCookie(off)
	if off == 0 {
		h.verifier = nil
	}
	h.page, h.index, h.eof = nil, 0, false
	return 0
}

func (h *dirHandle) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	_, errno := h.node.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: cloneBytes(h.token), DataOnly: flags != 0}}})
	return errno
}

func (h *dirHandle) Releasedir(ctx context.Context, _ uint32) { _ = h.close(ctx) }

func (h *dirHandle) close(ctx context.Context) syscall.Errno {
	var errno syscall.Errno
	h.once.Do(func() {
		_, errno = h.node.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytes(h.token)}}})
	})
	return errno
}

func (n *node) Create(ctx context.Context, name string, flags, mode uint32) (*authoritypb.Item, *fileHandle, uint32, syscall.Errno) {
	openFlags, errno := protocolOpenFlags(flags)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Mode: mode & 0o7777, Flags: openFlags, Exclusive: flags&uint32(syscall.O_EXCL) != 0}}})
	if errno != 0 {
		return nil, nil, 0, errno
	}
	created := response.GetCreate()
	if created == nil || created.GetItem() == nil || created.GetItem().GetAttr() == nil || len(created.GetHandle()) == 0 {
		return nil, nil, 0, syscall.EIO
	}
	item := cloneItem(created.GetItem())
	child := &node{mount: n.mount, item: item, requestTimeout: n.requestTimeout, maxRead: n.maxRead, maxWrite: n.maxWrite}
	return item, &fileHandle{node: child, token: cloneBytes(created.GetHandle()), append: openFlags.GetAppend()}, fuse.FOPEN_DIRECT_IO, 0
}

func (n *node) Mkdir(ctx context.Context, name string, mode uint32) (*authoritypb.Item, syscall.Errno) {
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Mode: mode & 0o7777}}})
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLookup().GetItem()
	if item == nil || item.GetAttr() == nil {
		return nil, syscall.EIO
	}
	return cloneItem(item), 0
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name)}}})
	return errno
}

func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Directory: true}}})
	return errno
}

func (n *node) Rename(ctx context.Context, name string, parent *node, newName string, flags uint32) syscall.Errno {
	if parent == nil || flags&^(renameNoReplace|renameExchange) != 0 || flags == renameNoReplace|renameExchange {
		return syscall.EINVAL
	}
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{OldParent: cloneBytes(n.item.GetToken()), OldName: []byte(name), NewParent: cloneBytes(parent.item.GetToken()), NewName: []byte(newName), NoReplace: flags&renameNoReplace != 0, Exchange: flags&renameExchange != 0}}})
	return errno
}

func (n *node) Link(ctx context.Context, source *node, name string) (*authoritypb.Item, syscall.Errno) {
	if source == nil {
		return nil, syscall.EXDEV
	}
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{ExistingItem: cloneBytes(source.item.GetToken()), NewParent: cloneBytes(n.item.GetToken()), NewName: []byte(name)}}})
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLink().GetItem()
	if item == nil || item.GetAttr() == nil || !bytes.Equal(item.GetToken(), source.item.GetToken()) {
		return nil, syscall.EIO
	}
	return cloneItem(item), 0
}

func (n *node) Symlink(ctx context.Context, target, name string) (*authoritypb.Item, syscall.Errno) {
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{Parent: cloneBytes(n.item.GetToken()), Name: []byte(name), Target: []byte(target)}}})
	if errno != 0 {
		return nil, errno
	}
	item := response.GetLookup().GetItem()
	if item == nil || item.GetAttr() == nil {
		return nil, syscall.EIO
	}
	return cloneItem(item), 0
}

func (n *node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Readlink{Readlink: &authoritypb.ReadlinkRequest{Item: cloneBytes(n.item.GetToken())}}})
	if errno != 0 {
		return nil, errno
	}
	return cloneBytes(response.GetReadlink().GetTarget()), 0
}

func (n *node) Setattr(ctx context.Context, fh *fileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	request := &authoritypb.SetAttrRequest{Item: cloneBytes(n.item.GetToken())}
	if fh != nil {
		request.Handle = cloneBytes(fh.token)
	}
	if value, ok := in.GetMode(); ok {
		request.Mode = &value
	}
	if value, ok := in.GetUID(); ok {
		if value != n.mount.uid {
			return syscall.EPERM
		}
	}
	if value, ok := in.GetGID(); ok {
		if value != n.mount.gid {
			return syscall.EPERM
		}
	}
	if value, ok := in.GetSize(); ok {
		converted := int64(value)
		if converted < 0 {
			return syscall.EFBIG
		}
		request.Size = &converted
	}
	if in.Valid&fuse.FATTR_ATIME_NOW != 0 {
		request.AtimeNow = true
	} else if value, ok := in.GetATime(); ok {
		ns := value.UnixNano()
		request.AtimeNs = &ns
	}
	if in.Valid&fuse.FATTR_MTIME_NOW != 0 {
		request.MtimeNow = true
	} else if value, ok := in.GetMTime(); ok {
		ns := value.UnixNano()
		request.MtimeNs = &ns
	}
	if request.Mode == nil && request.Size == nil && request.AtimeNs == nil && request.MtimeNs == nil && !request.GetAtimeNow() && !request.GetMtimeNow() {
		return n.Getattr(ctx, fh, out)
	}
	response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: request}})
	if errno != 0 {
		return errno
	}
	if response.GetPostAttr() == nil {
		return syscall.EIO
	}
	fillAttr(response.GetPostAttr(), &out.Attr, n.mount.uid, n.mount.gid)
	out.SetTimeout(0)
	return 0
}

func (n *node) Getxattr(ctx context.Context, name string, dest []byte) (uint32, syscall.Errno) {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetXattr{GetXattr: &authoritypb.GetXattrRequest{Item: cloneBytes(n.item.GetToken()), Name: []byte(name)}}})
	if errno != 0 {
		return 0, errno
	}
	value := response.GetGetXattr().GetValue()
	if len(dest) == 0 {
		return uint32(len(value)), 0
	}
	if len(dest) < len(value) {
		return uint32(len(value)), syscall.ERANGE
	}
	copy(dest, value)
	return uint32(len(value)), 0
}

func (n *node) Setxattr(ctx context.Context, name string, value []byte, flags uint32) syscall.Errno {
	mode := authoritypb.SetXattrRequest_UPSERT
	switch flags {
	case 0:
	case unix.XATTR_CREATE:
		mode = authoritypb.SetXattrRequest_CREATE
	case unix.XATTR_REPLACE:
		mode = authoritypb.SetXattrRequest_REPLACE
	default:
		return syscall.EINVAL
	}
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{Item: cloneBytes(n.item.GetToken()), Name: []byte(name), Value: cloneBytes(value), Mode: mode}}})
	return errno
}

func (n *node) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_ListXattr{ListXattr: &authoritypb.ListXattrRequest{Item: cloneBytes(n.item.GetToken())}}})
	if errno != 0 {
		return 0, errno
	}
	total := 0
	for _, name := range response.GetListXattr().GetNames() {
		total += len(name) + 1
	}
	if len(dest) == 0 {
		return uint32(total), 0
	}
	if len(dest) < total {
		return uint32(total), syscall.ERANGE
	}
	offset := 0
	for _, name := range response.GetListXattr().GetNames() {
		offset += copy(dest[offset:], name)
		dest[offset] = 0
		offset++
	}
	return uint32(total), 0
}

func (n *node) Removexattr(ctx context.Context, name string) syscall.Errno {
	_, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: &authoritypb.RemoveXattrRequest{Item: cloneBytes(n.item.GetToken()), Name: []byte(name)}}})
	return errno
}

func (n *node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}}})
	if errno != 0 {
		return errno
	}
	stat := response.GetStatFs()
	if stat == nil {
		return syscall.EIO
	}
	out.Blocks, out.Bfree, out.Bavail = stat.GetBlocks(), stat.GetBlocksFree(), stat.GetBlocksAvailable()
	out.Files, out.Ffree = stat.GetFiles(), stat.GetFilesFree()
	out.Bsize, out.Frsize, out.NameLen = uint32(stat.GetBlockSize()), uint32(stat.GetBlockSize()), stat.GetNameMax()
	return 0
}

func (n *node) Getlk(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if flags&^uint32(fuse.FUSE_LK_FLOCK) != 0 {
		return syscall.EINVAL
	}
	response, errno := n.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetLock{GetLock: &authoritypb.GetLockRequest{Lock: lockRequest(n.item.GetToken(), owner, lock, flags)}}})
	if errno != 0 {
		return errno
	}
	reply := response.GetGetLock()
	if reply == nil || !reply.GetConflict() {
		out.Typ = syscall.F_UNLCK
		return 0
	}
	held := reply.GetHeld()
	out.Start, out.End, out.Pid = held.GetRange().GetStart(), held.GetRange().GetEnd(), 0
	out.Typ = syscall.F_RDLCK
	if held.GetWrite() {
		out.Typ = syscall.F_WRLCK
	}
	return 0
}

func (n *node) Setlk(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setLock(ctx, owner, lock, flags, false)
}

func (n *node) Setlkw(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setLock(ctx, owner, lock, flags, true)
}

func (n *node) setLock(ctx context.Context, owner uint64, lock *fuse.FileLock, flags uint32, wait bool) syscall.Errno {
	if lock.Typ != syscall.F_RDLCK && lock.Typ != syscall.F_WRLCK && lock.Typ != syscall.F_UNLCK || flags&^uint32(fuse.FUSE_LK_FLOCK) != 0 {
		return syscall.EINVAL
	}
	request := &authoritypb.Request{Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{Lock: lockRequest(n.item.GetToken(), owner, lock, flags), Wait: wait, Unlock: lock.Typ == syscall.F_UNLCK}}}
	if !wait {
		_, errno := n.mutate(ctx, request)
		return errno
	}
	response, err := n.mount.rpc.CallMutation(ctx, request)
	return rpcErrno(response, err)
}

func protocolOpenFlags(flags uint32) (*authoritypb.OpenFlags, syscall.Errno) {
	result := &authoritypb.OpenFlags{}
	switch flags & uint32(syscall.O_ACCMODE) {
	case uint32(syscall.O_RDONLY):
		result.Read = true
	case uint32(syscall.O_WRONLY):
		result.Write = true
	case uint32(syscall.O_RDWR):
		result.Read, result.Write = true, true
	default:
		return nil, syscall.EINVAL
	}
	result.Append = flags&uint32(syscall.O_APPEND) != 0
	result.Truncate = flags&uint32(syscall.O_TRUNC) != 0
	result.Sync = flags&uint32(syscall.O_SYNC) != 0
	result.DataSync = flags&uint32(unix.O_DSYNC) != 0 && !result.Sync
	return result, 0
}

func lockRequest(item []byte, owner uint64, lock *fuse.FileLock, flags uint32) *authoritypb.LockSpec {
	return &authoritypb.LockSpec{Item: cloneBytes(item), Owner: owner, Write: lock.Typ == syscall.F_WRLCK, Range: &authoritypb.LockRange{Start: lock.Start, End: lock.End}, Flock: flags&uint32(fuse.FUSE_LK_FLOCK) != 0}
}

func fillAttr(attr *authoritypb.Attr, out *fuse.Attr, uid, gid uint32) {
	out.Ino = attr.GetInode()
	out.Size = uint64(max(attr.GetSize(), 0))
	out.Blocks = attr.GetBlocks()
	out.Mode = kindMode(attr.GetKind()) | attr.GetMode()
	out.Nlink = attr.GetNlink()
	out.Uid, out.Gid = uid, gid
	setTime(attr.GetAtimeNs(), &out.Atime, &out.Atimensec)
	setTime(attr.GetMtimeNs(), &out.Mtime, &out.Mtimensec)
	setTime(attr.GetCtimeNs(), &out.Ctime, &out.Ctimensec)
}

func setTime(ns int64, seconds *uint64, nanos *uint32) {
	if ns < 0 {
		return
	}
	*seconds, *nanos = uint64(ns/1e9), uint32(ns%1e9)
}

func kindMode(kind authoritypb.Attr_Kind) uint32 {
	switch kind {
	case authoritypb.Attr_DIRECTORY:
		return fuse.S_IFDIR
	case authoritypb.Attr_SYMLINK:
		return fuse.S_IFLNK
	default:
		return fuse.S_IFREG
	}
}

func rpcErrno(response *authoritypb.Response, err error) syscall.Errno {
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return syscall.EINTR
		case errors.Is(err, authorityrpc.ErrAuthorityChanged):
			return syscall.ESTALE
		default:
			return syscall.EIO
		}
	}
	return responseErrno(response)
}

func responseErrno(response *authoritypb.Response) syscall.Errno {
	if response == nil || response.GetUncertain() {
		return syscall.EIO
	}
	if response.GetErrno() < 0 {
		return syscall.EIO
	}
	return syscall.Errno(response.GetErrno())
}

func cloneItem(item *authoritypb.Item) *authoritypb.Item {
	if item == nil {
		return nil
	}
	return proto.Clone(item).(*authoritypb.Item)
}

func cloneBytes(value []byte) []byte { return append([]byte(nil), value...) }

func encodeCookie(value uint64) []byte {
	if value == 0 {
		return nil
	}
	return []byte{byte(value >> 56), byte(value >> 48), byte(value >> 40), byte(value >> 32), byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
}

func decodeCookie(value []byte) uint64 {
	if len(value) != 8 {
		return 0
	}
	var result uint64
	for _, part := range value {
		result = result<<8 | uint64(part)
	}
	return result
}
