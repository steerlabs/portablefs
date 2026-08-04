//go:build linux

package fusev3

import (
	"context"
	"errors"
	"math"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type inodeKey struct {
	inode uint64
	kind  authoritypb.Attr_Kind
}

type inodeRecord struct {
	id        uint64
	key       inodeKey
	node      *node
	lookups   uint64
	inFlight  uint64
	pins      uint64
	root      bool
	reclaimed bool
}

type handleRecord struct {
	inode    *inodeRecord
	file     *fileHandle
	dir      *dirHandle
	inFlight uint64
	closing  bool
	done     chan struct{}
}

// rawFileSystem owns the exact NodeID and lookup-reference accounting exposed
// to the kernel. It deliberately does not delegate inode identity to go-fuse's
// high-level layer: the authority returns a fresh capability on every Lookup,
// and only this table knows whether that candidate won or must be reclaimed.
type rawFileSystem struct {
	fuse.RawFileSystem
	mount *Mount

	mu         sync.Mutex
	nextNodeID uint64
	nodesByID  map[uint64]*inodeRecord
	nodesByKey map[inodeKey]*inodeRecord
	nextHandle uint64
	handles    map[uint64]*handleRecord
}

var _ fuse.RawFileSystem = (*rawFileSystem)(nil)

func newRawFileSystem(mount *Mount, root *node) *rawFileSystem {
	key := itemKey(root.item)
	record := &inodeRecord{id: fuse.FUSE_ROOT_ID, key: key, node: root, root: true}
	return &rawFileSystem{
		RawFileSystem: fuse.NewDefaultRawFileSystem(),
		mount:         mount,
		nextNodeID:    fuse.FUSE_ROOT_ID + 1,
		nodesByID:     map[uint64]*inodeRecord{fuse.FUSE_ROOT_ID: record},
		nodesByKey:    map[inodeKey]*inodeRecord{key: record},
		nextHandle:    1,
		handles:       make(map[uint64]*handleRecord),
	}
}

func itemKey(item *authoritypb.Item) inodeKey {
	return inodeKey{inode: item.GetAttr().GetInode(), kind: item.GetAttr().GetKind()}
}

func validItem(item *authoritypb.Item) bool {
	return item != nil && item.GetAttr() != nil && item.GetAttr().GetInode() != 0 && len(item.GetToken()) != 0
}

// intern installs one kernel lookup reference. The caller's item capability is
// consumed on success: it becomes the record's retained capability, or is
// queued for reclaim if another goroutine already interned the same object.
func (r *rawFileSystem) intern(item *authoritypb.Item) (*inodeRecord, bool) {
	if !validItem(item) {
		return nil, false
	}
	key := itemKey(item)
	var discarded []byte
	r.mu.Lock()
	if existing := r.nodesByKey[key]; existing != nil {
		if existing.lookups == math.MaxUint64 {
			r.mu.Unlock()
			r.mount.abortAsync()
			return nil, false
		}
		existing.lookups++
		discarded = cloneBytes(item.GetToken())
		r.mu.Unlock()
		if !r.mount.enqueueReclaim(discarded) {
			r.rollbackLookup(existing)
			return nil, false
		}
		return existing, true
	}
	if r.nextNodeID == 0 || r.nextNodeID == fuse.FUSE_ROOT_ID {
		r.mu.Unlock()
		r.mount.abortAsync()
		return nil, false
	}
	id := r.nextNodeID
	r.nextNodeID++
	n := &node{mount: r.mount, item: cloneItem(item), requestTimeout: r.mountRequestTimeout(), maxRead: r.mountMaxRead(), maxWrite: r.mountMaxWrite()}
	record := &inodeRecord{id: id, key: key, node: n, lookups: 1}
	r.nodesByID[id] = record
	r.nodesByKey[key] = record
	r.mu.Unlock()
	return record, true
}

func (r *rawFileSystem) rollbackLookup(record *inodeRecord) {
	var reclaim []byte
	r.mu.Lock()
	if record != nil && !record.reclaimed && record.lookups > 0 {
		record.lookups--
		if record.lookups == 0 && record.pins == 0 && r.nodesByKey[record.key] == record {
			delete(r.nodesByKey, record.key)
		}
		reclaim = r.collectLocked(record)
	}
	r.mu.Unlock()
	if len(reclaim) != 0 {
		r.mount.enqueueReclaim(reclaim)
	}
}

// addLookupExisting is used by LINK: its Oldnodeid already names a retained
// authority capability, so creating the new kernel lookup ref must not pretend
// that capability is a fresh candidate and reclaim it.
func (r *rawFileSystem) addLookupExisting(record *inodeRecord) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if record == nil || record.reclaimed || r.nodesByID[record.id] != record || record.lookups == math.MaxUint64 {
		return false
	}
	record.lookups++
	r.nodesByKey[record.key] = record
	return true
}

func (r *rawFileSystem) mountRequestTimeout() time.Duration {
	root := r.nodesByID[fuse.FUSE_ROOT_ID]
	return root.node.requestTimeout
}

func (r *rawFileSystem) mountMaxRead() uint32 {
	return r.nodesByID[fuse.FUSE_ROOT_ID].node.maxRead
}

func (r *rawFileSystem) mountMaxWrite() uint32 {
	return r.nodesByID[fuse.FUSE_ROOT_ID].node.maxWrite
}

func (r *rawFileSystem) acquire(nodeID uint64) *inodeRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	record := r.nodesByID[nodeID]
	if record == nil || record.reclaimed || (!record.root && record.lookups == 0 && record.pins == 0) || record.inFlight == math.MaxUint64 {
		return nil
	}
	record.inFlight++
	return record
}

func (r *rawFileSystem) release(record *inodeRecord) {
	var reclaim []byte
	r.mu.Lock()
	if record != nil && record.inFlight > 0 {
		record.inFlight--
		reclaim = r.collectLocked(record)
	}
	r.mu.Unlock()
	if len(reclaim) != 0 {
		r.mount.enqueueReclaim(reclaim)
	}
}

func (r *rawFileSystem) Forget(nodeID, nlookup uint64) {
	var reclaim []byte
	corrupt := false
	r.mu.Lock()
	record := r.nodesByID[nodeID]
	if record != nil && !record.root && !record.reclaimed {
		if nlookup > record.lookups {
			record.lookups = 0
			corrupt = true
		} else {
			record.lookups -= nlookup
		}
		if record.lookups == 0 && record.pins == 0 && r.nodesByKey[record.key] == record {
			delete(r.nodesByKey, record.key)
		}
		reclaim = r.collectLocked(record)
	}
	r.mu.Unlock()
	if len(reclaim) != 0 {
		r.mount.enqueueReclaim(reclaim)
	}
	if corrupt {
		r.mount.abortAsync()
	}
}

func (r *rawFileSystem) collectLocked(record *inodeRecord) []byte {
	if record == nil || record.root || record.reclaimed || record.lookups != 0 || record.inFlight != 0 || record.pins != 0 {
		return nil
	}
	record.reclaimed = true
	delete(r.nodesByID, record.id)
	if r.nodesByKey[record.key] == record {
		delete(r.nodesByKey, record.key)
	}
	return cloneBytes(record.node.item.GetToken())
}

func (r *rawFileSystem) addHandle(record *inodeRecord, handle *handleRecord) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if record == nil || record.reclaimed || r.nodesByID[record.id] != record || record.pins == math.MaxUint64 || r.nextHandle == 0 {
		return 0, false
	}
	id := r.nextHandle
	r.nextHandle++
	record.pins++
	r.nodesByKey[record.key] = record
	handle.inode = record
	handle.done = make(chan struct{})
	r.handles[id] = handle
	return id, true
}

func (r *rawFileSystem) acquireFileHandle(id uint64) (*handleRecord, *fileHandle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	handle := r.handles[id]
	if handle == nil || handle.file == nil || handle.closing || handle.inFlight == math.MaxUint64 {
		return nil, nil
	}
	handle.inFlight++
	return handle, handle.file
}

func (r *rawFileSystem) acquireDirHandle(id uint64) (*handleRecord, *dirHandle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	handle := r.handles[id]
	if handle == nil || handle.dir == nil || handle.closing || handle.inFlight == math.MaxUint64 {
		return nil, nil
	}
	handle.inFlight++
	return handle, handle.dir
}

func (r *rawFileSystem) releaseHandleOperation(handle *handleRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if handle == nil || handle.inFlight == 0 {
		return
	}
	handle.inFlight--
	if handle.closing && handle.inFlight == 0 {
		close(handle.done)
	}
}

func (r *rawFileSystem) takeHandle(id uint64, directory bool) (*handleRecord, bool) {
	r.mu.Lock()
	handle := r.handles[id]
	if handle == nil || (directory && handle.dir == nil) || (!directory && handle.file == nil) {
		r.mu.Unlock()
		return nil, false
	}
	delete(r.handles, id)
	handle.closing = true
	if handle.inFlight == 0 {
		close(handle.done)
	}
	done := handle.done
	r.mu.Unlock()
	<-done
	return handle, true
}

func (r *rawFileSystem) unpin(record *inodeRecord) {
	var reclaim []byte
	r.mu.Lock()
	if record != nil && record.pins > 0 {
		record.pins--
		if record.lookups == 0 && record.pins == 0 && r.nodesByKey[record.key] == record {
			delete(r.nodesByKey, record.key)
		}
		reclaim = r.collectLocked(record)
	}
	r.mu.Unlock()
	if len(reclaim) != 0 {
		r.mount.enqueueReclaim(reclaim)
	}
}

func (r *rawFileSystem) requestContext(cancel <-chan struct{}) (context.Context, context.CancelFunc) {
	parent := r.mount.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := context.WithCancel(parent)
	if cancel != nil {
		go func() {
			select {
			case <-cancel:
				stop()
			case <-ctx.Done():
			}
		}()
	}
	return ctx, stop
}

func (r *rawFileSystem) Lookup(cancel <-chan struct{}, header *fuse.InHeader, name string, out *fuse.EntryOut) fuse.Status {
	parent := r.acquire(header.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	item, errno := parent.node.Lookup(ctx, name)
	if errno != 0 {
		out.SetEntryTimeout(0)
		return fuse.Status(errno)
	}
	record, ok := r.intern(item)
	if !ok {
		return fuse.EIO
	}
	fillEntry(out, record.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	return fuse.OK
}

func (r *rawFileSystem) GetAttr(cancel <-chan struct{}, input *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	var handle *fileHandle
	if input.Flags()&fuse.FUSE_GETATTR_FH != 0 {
		handleRecord, acquired := r.acquireFileHandle(input.Fh())
		handle = acquired
		if handle == nil {
			return fuse.EBADF
		}
		defer r.releaseHandleOperation(handleRecord)
		if handleRecord.inode != record {
			return fuse.EBADF
		}
	}
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(record.node.Getattr(ctx, handle, out))
}

func (r *rawFileSystem) SetAttr(cancel <-chan struct{}, input *fuse.SetAttrIn, out *fuse.AttrOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	var handle *fileHandle
	if id, ok := input.GetFh(); ok {
		handleRecord, acquired := r.acquireFileHandle(id)
		handle = acquired
		if handle == nil {
			return fuse.EBADF
		}
		defer r.releaseHandleOperation(handleRecord)
		if handleRecord.inode != record {
			return fuse.EBADF
		}
	}
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(record.node.Setattr(ctx, handle, input, out))
}

func (r *rawFileSystem) Open(cancel <-chan struct{}, input *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	handle, flags, errno := record.node.Open(ctx, input.Flags)
	if errno != 0 {
		return fuse.Status(errno)
	}
	id, ok := r.addHandle(record, &handleRecord{file: handle})
	if !ok {
		_ = handle.close(ctx, 0, false)
		return fuse.EIO
	}
	out.Fh, out.OpenFlags = id, flags
	return fuse.OK
}

func (r *rawFileSystem) Read(cancel <-chan struct{}, input *fuse.ReadIn, buf []byte) (fuse.ReadResult, fuse.Status) {
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return nil, fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	if input.Offset > math.MaxInt64 {
		return nil, fuse.EINVAL
	}
	ctx, stop := r.requestContext(cancel)
	defer stop()
	result, errno := handle.node.Read(ctx, handle, buf, int64(input.Offset))
	return result, fuse.Status(errno)
}

func (r *rawFileSystem) Write(cancel <-chan struct{}, input *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return 0, fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	if input.Offset > math.MaxInt64 {
		return 0, fuse.EINVAL
	}
	ctx, stop := r.requestContext(cancel)
	defer stop()
	written, errno := handle.node.Write(ctx, handle, data, int64(input.Offset))
	return written, fuse.Status(errno)
}

func (r *rawFileSystem) Flush(cancel <-chan struct{}, input *fuse.FlushIn) fuse.Status {
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(handle.node.Flush(ctx, handle, input.LockOwner))
}

func (r *rawFileSystem) Fsync(cancel <-chan struct{}, input *fuse.FsyncIn) fuse.Status {
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(handle.node.Fsync(ctx, handle, input.FsyncFlags))
}

func (r *rawFileSystem) Release(cancel <-chan struct{}, input *fuse.ReleaseIn) {
	handle, ok := r.takeHandle(input.Fh, false)
	if !ok {
		return
	}
	ctx, stop := r.requestContext(cancel)
	_ = handle.file.close(ctx, input.LockOwner, input.ReleaseFlags&fuse.FUSE_RELEASE_FLOCK_UNLOCK != 0)
	stop()
	r.unpin(handle.inode)
}

func (r *rawFileSystem) Create(cancel <-chan struct{}, input *fuse.CreateIn, name string, out *fuse.CreateOut) fuse.Status {
	parent := r.acquire(input.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	item, handle, flags, errno := parent.node.Create(ctx, name, input.Flags, input.Mode)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, ok := r.intern(item)
	if !ok {
		_ = handle.close(ctx, 0, false)
		return fuse.EIO
	}
	handle.node = record.node
	id, ok := r.addHandle(record, &handleRecord{file: handle})
	if !ok {
		r.Forget(record.id, 1)
		_ = handle.close(ctx, 0, false)
		return fuse.EIO
	}
	fillEntry(&out.EntryOut, record.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	out.Fh, out.OpenFlags = id, flags
	return fuse.OK
}

func (r *rawFileSystem) Mkdir(cancel <-chan struct{}, input *fuse.MkdirIn, name string, out *fuse.EntryOut) fuse.Status {
	parent := r.acquire(input.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	item, errno := parent.node.Mkdir(ctx, name, input.Mode)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, ok := r.intern(item)
	if !ok {
		return fuse.EIO
	}
	fillEntry(out, record.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	return fuse.OK
}

func (r *rawFileSystem) Unlink(cancel <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
	return r.unlink(cancel, header, name, false)
}

func (r *rawFileSystem) Rmdir(cancel <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
	return r.unlink(cancel, header, name, true)
}

func (r *rawFileSystem) unlink(cancel <-chan struct{}, header *fuse.InHeader, name string, directory bool) fuse.Status {
	parent := r.acquire(header.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	if directory {
		return fuse.Status(parent.node.Rmdir(ctx, name))
	}
	return fuse.Status(parent.node.Unlink(ctx, name))
}

func (r *rawFileSystem) Rename(cancel <-chan struct{}, input *fuse.RenameIn, oldName, newName string) fuse.Status {
	oldParent := r.acquire(input.NodeId)
	if oldParent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(oldParent)
	newParent := r.acquire(input.Newdir)
	if newParent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(newParent)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(oldParent.node.Rename(ctx, oldName, newParent.node, newName, input.Flags))
}

func (r *rawFileSystem) Link(cancel <-chan struct{}, input *fuse.LinkIn, name string, out *fuse.EntryOut) fuse.Status {
	newParent := r.acquire(input.NodeId)
	if newParent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(newParent)
	source := r.acquire(input.Oldnodeid)
	if source == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(source)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	item, errno := newParent.node.Link(ctx, source.node, name)
	if errno != 0 {
		return fuse.Status(errno)
	}
	if !r.addLookupExisting(source) {
		return fuse.EIO
	}
	fillEntry(out, source.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	return fuse.OK
}

func (r *rawFileSystem) Symlink(cancel <-chan struct{}, header *fuse.InHeader, pointedTo, linkName string, out *fuse.EntryOut) fuse.Status {
	parent := r.acquire(header.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	item, errno := parent.node.Symlink(ctx, pointedTo, linkName)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, ok := r.intern(item)
	if !ok {
		return fuse.EIO
	}
	fillEntry(out, record.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	return fuse.OK
}

func (r *rawFileSystem) Readlink(cancel <-chan struct{}, header *fuse.InHeader) ([]byte, fuse.Status) {
	record := r.acquire(header.NodeId)
	if record == nil {
		return nil, fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	value, errno := record.node.Readlink(ctx)
	return value, fuse.Status(errno)
}

func (r *rawFileSystem) GetXAttr(cancel <-chan struct{}, header *fuse.InHeader, name string, dest []byte) (uint32, fuse.Status) {
	record := r.acquire(header.NodeId)
	if record == nil {
		return 0, fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	size, errno := record.node.Getxattr(ctx, name, dest)
	return size, fuse.Status(errno)
}

func (r *rawFileSystem) SetXAttr(cancel <-chan struct{}, input *fuse.SetXAttrIn, name string, data []byte) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(record.node.Setxattr(ctx, name, data, input.Flags))
}

func (r *rawFileSystem) ListXAttr(cancel <-chan struct{}, header *fuse.InHeader, dest []byte) (uint32, fuse.Status) {
	record := r.acquire(header.NodeId)
	if record == nil {
		return 0, fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	size, errno := record.node.Listxattr(ctx, dest)
	return size, fuse.Status(errno)
}

func (r *rawFileSystem) RemoveXAttr(cancel <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
	record := r.acquire(header.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(record.node.Removexattr(ctx, name))
}

func (r *rawFileSystem) OpenDir(cancel <-chan struct{}, input *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	handle, flags, errno := record.node.OpendirHandle(ctx, input.Flags)
	if errno != 0 {
		return fuse.Status(errno)
	}
	id, ok := r.addHandle(record, &handleRecord{dir: handle})
	if !ok {
		_ = handle.close(ctx)
		return fuse.EIO
	}
	out.Fh, out.OpenFlags = id, flags
	return fuse.OK
}

func (r *rawFileSystem) ReadDir(cancel <-chan struct{}, input *fuse.ReadIn, out *fuse.DirEntryList) fuse.Status {
	handleRecord, handle := r.acquireDirHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	if errno := handle.Seekdir(ctx, input.Offset); errno != 0 {
		return fuse.Status(errno)
	}
	for {
		entry, errno := handle.Readdirent(ctx)
		if errno != 0 {
			return fuse.Status(errno)
		}
		if entry == nil || !out.AddDirEntry(*entry) {
			return fuse.OK
		}
	}
}

func (r *rawFileSystem) ReadDirPlus(<-chan struct{}, *fuse.ReadIn, *fuse.DirEntryList) fuse.Status {
	return fuse.ENOSYS
}

func (r *rawFileSystem) FsyncDir(cancel <-chan struct{}, input *fuse.FsyncIn) fuse.Status {
	handleRecord, handle := r.acquireDirHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(handle.Fsyncdir(ctx, input.FsyncFlags))
}

func (r *rawFileSystem) ReleaseDir(input *fuse.ReleaseIn) {
	handle, ok := r.takeHandle(input.Fh, true)
	if !ok {
		return
	}
	parent := r.mount.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, handle.dir.node.requestTimeout)
	_ = handle.dir.close(ctx)
	cancel()
	r.unpin(handle.inode)
}

func (r *rawFileSystem) StatFs(cancel <-chan struct{}, header *fuse.InHeader, out *fuse.StatfsOut) fuse.Status {
	record := r.acquire(header.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(record.node.Statfs(ctx, out))
}

func (r *rawFileSystem) GetLk(cancel <-chan struct{}, input *fuse.LkIn, out *fuse.LkOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	if handleRecord.inode != record {
		return fuse.EBADF
	}
	ctx, stop := r.requestContext(cancel)
	defer stop()
	return fuse.Status(record.node.Getlk(ctx, input.Owner, &input.Lk, input.LkFlags, &out.Lk))
}

func (r *rawFileSystem) SetLk(cancel <-chan struct{}, input *fuse.LkIn) fuse.Status {
	return r.setLock(cancel, input, false)
}

func (r *rawFileSystem) SetLkw(cancel <-chan struct{}, input *fuse.LkIn) fuse.Status {
	return r.setLock(cancel, input, true)
}

func (r *rawFileSystem) setLock(cancel <-chan struct{}, input *fuse.LkIn, wait bool) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	if handleRecord.inode != record {
		return fuse.EBADF
	}
	ctx, stop := r.requestContext(cancel)
	defer stop()
	if wait {
		return fuse.Status(record.node.Setlkw(ctx, input.Owner, &input.Lk, input.LkFlags))
	}
	return fuse.Status(record.node.Setlk(ctx, input.Owner, &input.Lk, input.LkFlags))
}

func (r *rawFileSystem) OnUnmount() {
	go func() { _ = r.mount.Close() }()
}

func fillEntry(out *fuse.EntryOut, nodeID uint64, attr *authoritypb.Attr, uid, gid uint32) {
	out.NodeId = nodeID
	out.Generation = 1
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	fillAttr(attr, &out.Attr, uid, gid)
}

func (m *Mount) enqueueReclaim(token []byte) bool {
	if len(token) == 0 {
		return true
	}
	if m.ctx != nil {
		select {
		case <-m.ctx.Done():
			return false
		default:
		}
	}
	select {
	case m.reclaim <- cloneBytes(token):
		return true
	default:
		m.abortAsync()
		return false
	}
}

// abortAsync is safe from FORGET: it only cancels local contexts and schedules
// unmount/detach I/O on a separate goroutine.
func (m *Mount) abortAsync() {
	m.failAsync(errors.New("fusev3: frontend ownership invariant failed"))
}

func (m *Mount) failAsync(err error) {
	if err == nil {
		err = errors.New("fusev3: mount aborted")
	}
	m.abort.Do(func() {
		m.fatalMu.Lock()
		m.fatalErr = err
		m.fatalMu.Unlock()
		if m.cancel != nil {
			m.cancel()
		}
		go func() {
			if m.server != nil {
				_ = m.Unmount()
			}
			_ = m.Close()
		}()
	})
}
