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

	// The negotiated per-mount bounds are copied once at construction. Reading
	// them back out of nodesByID would be a map access whose safety depended on
	// an unstated assumption about which lock the caller happened to hold.
	requestTimeout time.Duration
	maxRead        uint32
	maxWrite       uint32

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
		RawFileSystem:  fuse.NewDefaultRawFileSystem(),
		mount:          mount,
		requestTimeout: root.requestTimeout,
		maxRead:        root.maxRead,
		maxWrite:       root.maxWrite,
		nextNodeID:     fuse.FUSE_ROOT_ID + 1,
		nodesByID:      map[uint64]*inodeRecord{fuse.FUSE_ROOT_ID: record},
		nodesByKey:     map[inodeKey]*inodeRecord{key: record},
		nextHandle:     1,
		handles:        make(map[uint64]*handleRecord),
	}
}

func itemKey(item *authoritypb.Item) inodeKey {
	return inodeKey{inode: item.GetAttr().GetInode(), kind: item.GetAttr().GetKind()}
}

func validItem(item *authoritypb.Item) bool {
	return item != nil && item.GetAttr() != nil && item.GetAttr().GetInode() != 0 && len(item.GetToken()) != 0
}

func (r *rawFileSystem) newNode(item *authoritypb.Item) *node {
	return &node{mount: r.mount, item: cloneItem(item), requestTimeout: r.requestTimeout, maxRead: r.maxRead, maxWrite: r.maxWrite}
}

// intern installs one kernel lookup reference. The caller's item capability is
// consumed on success: it becomes the record's retained capability, or is
// queued for reclaim if another goroutine already interned the same object.
//
// Interning is the only way an inode record is created, and every record ends
// in exactly one reclaim, so this is also the only place where cleanup debt is
// created at a rate the kernel controls. Admission therefore happens here:
// backpressure that slows a lookup is correct, discarding a capability is not,
// and neither is destroying the mount because the backlog grew.
func (r *rawFileSystem) intern(ctx context.Context, item *authoritypb.Item) (*inodeRecord, syscall.Errno) {
	if !validItem(item) {
		return nil, syscall.EIO
	}
	// Admission is bounded by the same deadline as any other authority round
	// trip, so a stalled cleanup lane slows lookups and then reports a timeout;
	// it can never leave a process blocked in the kernel indefinitely.
	admitCtx, stopAdmit := context.WithTimeout(ctx, r.requestTimeout)
	err := r.mount.reclaim.admit(admitCtx)
	stopAdmit()
	if err != nil {
		return nil, contextErrno(err)
	}
	key := itemKey(item)
	r.mu.Lock()
	if existing := r.nodesByKey[key]; existing != nil {
		if existing.lookups == math.MaxUint64 {
			r.mu.Unlock()
			r.mount.abortAsync()
			return nil, syscall.EIO
		}
		existing.lookups++
		discarded := cloneBytes(item.GetToken())
		r.mu.Unlock()
		// The authority mints a new capability on every Lookup. This one lost
		// the race for the record, so it is dead the moment it was created.
		r.mount.deferReclaim(discarded)
		return existing, 0
	}
	if r.nextNodeID == 0 || r.nextNodeID == fuse.FUSE_ROOT_ID {
		r.mu.Unlock()
		r.mount.abortAsync()
		return nil, syscall.EIO
	}
	id := r.nextNodeID
	r.nextNodeID++
	record := &inodeRecord{id: id, key: key, node: r.newNode(item), lookups: 1}
	r.nodesByID[id] = record
	r.nodesByKey[key] = record
	r.mu.Unlock()
	return record, 0
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
	r.mount.deferReclaim(reclaim)
}

// Forget must never block and must never issue an RPC: go-fuse deliberately
// does not spawn a replacement reader for FORGET or BATCH_FORGET, so blocking
// here would stall the entire kernel request loop.
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
	r.mount.deferReclaim(reclaim)
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
	r.mount.deferReclaim(reclaim)
}

// opContext derives the context for one kernel request.
//
// The kernel's INTERRUPT channel is deliberately not wired in. Cancelling an
// authority call is defined by the transport to be terminal for the session:
// an interrupted mutation has a genuinely uncertain outcome, so the client
// poisons itself and the mount is torn down. Honouring INTERRUPT would
// therefore mean that a Ctrl-C on one `mkdir` against a slow or partitioned
// authority unmounts the volume for every unrelated process on the machine.
// FUSE explicitly permits a filesystem to ignore INTERRUPT and complete the
// operation normally, and for a path where cancellation is defined as fatal
// that is the only correct behaviour. RequestTimeout remains the bound.
func (r *rawFileSystem) opContext() context.Context {
	if r.mount.ctx == nil {
		return context.Background()
	}
	return r.mount.ctx
}

func (r *rawFileSystem) Lookup(_ <-chan struct{}, header *fuse.InHeader, name string, out *fuse.EntryOut) fuse.Status {
	parent := r.acquire(header.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx := r.opContext()
	item, errno := parent.node.Lookup(ctx, name)
	if errno != 0 {
		out.SetEntryTimeout(0)
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	fillEntry(out, record.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	return fuse.OK
}

func (r *rawFileSystem) GetAttr(_ <-chan struct{}, input *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
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
	return fuse.Status(record.node.Getattr(r.opContext(), handle, out))
}

func (r *rawFileSystem) SetAttr(_ <-chan struct{}, input *fuse.SetAttrIn, out *fuse.AttrOut) fuse.Status {
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
	return fuse.Status(record.node.Setattr(r.opContext(), handle, input, out))
}

func (r *rawFileSystem) Open(_ <-chan struct{}, input *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx := r.opContext()
	handle, flags, errno := record.node.Open(ctx, input.Flags)
	if errno != 0 {
		return fuse.Status(errno)
	}
	id, ok := r.addHandle(record, &handleRecord{file: handle})
	if !ok {
		r.closeOrphanedFile(ctx, handle)
		return fuse.EIO
	}
	out.Fh, out.OpenFlags = id, flags
	return fuse.OK
}

// closeOrphanedFile releases an authority open file description the frontend
// created but can no longer hand to the kernel. It uses the one cleanup policy
// this mount has: a refused release means the two sides no longer agree about
// who owns the object.
func (r *rawFileSystem) closeOrphanedFile(ctx context.Context, handle *fileHandle) {
	if errno := handle.close(ctx, 0, false); errno != 0 {
		r.mount.cleanupFailed("open-file close", errno)
	}
}

func (r *rawFileSystem) Read(_ <-chan struct{}, input *fuse.ReadIn, buf []byte) (fuse.ReadResult, fuse.Status) {
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return nil, fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	if input.Offset > math.MaxInt64 {
		return nil, fuse.EINVAL
	}
	result, errno := handle.node.Read(r.opContext(), handle, buf, int64(input.Offset))
	return result, fuse.Status(errno)
}

func (r *rawFileSystem) Write(_ <-chan struct{}, input *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return 0, fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	if input.Offset > math.MaxInt64 {
		return 0, fuse.EINVAL
	}
	written, errno := handle.node.Write(r.opContext(), handle, data, int64(input.Offset))
	return written, fuse.Status(errno)
}

func (r *rawFileSystem) Flush(_ <-chan struct{}, input *fuse.FlushIn) fuse.Status {
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	return fuse.Status(handle.node.Flush(r.opContext(), handle, input.LockOwner))
}

func (r *rawFileSystem) Fsync(_ <-chan struct{}, input *fuse.FsyncIn) fuse.Status {
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	return fuse.Status(handle.node.Fsync(r.opContext(), handle, input.FsyncFlags))
}

func (r *rawFileSystem) Release(_ <-chan struct{}, input *fuse.ReleaseIn) {
	handle, ok := r.takeHandle(input.Fh, false)
	if !ok {
		return
	}
	ctx := r.opContext()
	// RELEASE has no reply, so the kernel has already forgotten this file
	// description. Discarding a failed close here would leave the authority
	// holding the open file description and its resources.opens entry for the
	// rest of the session, and the only symptom would be later open() calls
	// failing with an admission error that names nothing.
	if errno := handle.file.close(ctx, input.LockOwner, input.ReleaseFlags&fuse.FUSE_RELEASE_FLOCK_UNLOCK != 0); errno != 0 {
		r.mount.cleanupFailed("open-file close", errno)
	}
	r.unpin(handle.inode)
}

func (r *rawFileSystem) Create(_ <-chan struct{}, input *fuse.CreateIn, name string, out *fuse.CreateOut) fuse.Status {
	parent := r.acquire(input.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx := r.opContext()
	item, handle, flags, errno := parent.node.Create(ctx, name, input.Flags, input.Mode)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		r.closeOrphanedFile(ctx, handle)
		return fuse.Status(errno)
	}
	handle.node = record.node
	id, ok := r.addHandle(record, &handleRecord{file: handle})
	if !ok {
		r.Forget(record.id, 1)
		r.closeOrphanedFile(ctx, handle)
		return fuse.EIO
	}
	fillEntry(&out.EntryOut, record.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	out.Fh, out.OpenFlags = id, flags
	return fuse.OK
}

// Mknod is implemented rather than left to the embedded default, which answers
// ENOSYS. mkfifo(3) and bind(2) on a unix domain socket both arrive here, and
// build systems, container runtimes, and agent sockets all do one or the other.
func (r *rawFileSystem) Mknod(_ <-chan struct{}, input *fuse.MknodIn, name string, out *fuse.EntryOut) fuse.Status {
	parent := r.acquire(input.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx := r.opContext()
	item, errno := parent.node.Mknod(ctx, name, input.Mode, input.Rdev)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	fillEntry(out, record.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	return fuse.OK
}

func (r *rawFileSystem) Mkdir(_ <-chan struct{}, input *fuse.MkdirIn, name string, out *fuse.EntryOut) fuse.Status {
	parent := r.acquire(input.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx := r.opContext()
	item, errno := parent.node.Mkdir(ctx, name, input.Mode)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
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

func (r *rawFileSystem) unlink(_ <-chan struct{}, header *fuse.InHeader, name string, directory bool) fuse.Status {
	parent := r.acquire(header.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx := r.opContext()
	if directory {
		return fuse.Status(parent.node.Rmdir(ctx, name))
	}
	return fuse.Status(parent.node.Unlink(ctx, name))
}

func (r *rawFileSystem) Rename(_ <-chan struct{}, input *fuse.RenameIn, oldName, newName string) fuse.Status {
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
	return fuse.Status(oldParent.node.Rename(r.opContext(), oldName, newParent.node, newName, input.Flags))
}

func (r *rawFileSystem) Link(_ <-chan struct{}, input *fuse.LinkIn, name string, out *fuse.EntryOut) fuse.Status {
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
	item, errno := newParent.node.Link(r.opContext(), source.node, name)
	if errno != 0 {
		return fuse.Status(errno)
	}
	if !r.addLookupExisting(source) {
		return fuse.EIO
	}
	fillEntry(out, source.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	return fuse.OK
}

func (r *rawFileSystem) Symlink(_ <-chan struct{}, header *fuse.InHeader, pointedTo, linkName string, out *fuse.EntryOut) fuse.Status {
	parent := r.acquire(header.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	ctx := r.opContext()
	item, errno := parent.node.Symlink(ctx, pointedTo, linkName)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	fillEntry(out, record.id, item.GetAttr(), r.mount.uid, r.mount.gid)
	return fuse.OK
}

func (r *rawFileSystem) Readlink(_ <-chan struct{}, header *fuse.InHeader) ([]byte, fuse.Status) {
	record := r.acquire(header.NodeId)
	if record == nil {
		return nil, fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	value, errno := record.node.Readlink(r.opContext())
	return value, fuse.Status(errno)
}

func (r *rawFileSystem) GetXAttr(_ <-chan struct{}, header *fuse.InHeader, name string, dest []byte) (uint32, fuse.Status) {
	record := r.acquire(header.NodeId)
	if record == nil {
		return 0, fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	size, errno := record.node.Getxattr(r.opContext(), name, dest)
	return size, fuse.Status(errno)
}

func (r *rawFileSystem) SetXAttr(_ <-chan struct{}, input *fuse.SetXAttrIn, name string, data []byte) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	return fuse.Status(record.node.Setxattr(r.opContext(), name, data, input.Flags))
}

func (r *rawFileSystem) ListXAttr(_ <-chan struct{}, header *fuse.InHeader, dest []byte) (uint32, fuse.Status) {
	record := r.acquire(header.NodeId)
	if record == nil {
		return 0, fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	size, errno := record.node.Listxattr(r.opContext(), dest)
	return size, fuse.Status(errno)
}

func (r *rawFileSystem) RemoveXAttr(_ <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
	record := r.acquire(header.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	return fuse.Status(record.node.Removexattr(r.opContext(), name))
}

func (r *rawFileSystem) OpenDir(_ <-chan struct{}, input *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	ctx := r.opContext()
	handle, flags, errno := record.node.OpendirHandle(ctx, input.Flags)
	if errno != 0 {
		return fuse.Status(errno)
	}
	id, ok := r.addHandle(record, &handleRecord{dir: handle})
	if !ok {
		if errno := handle.close(ctx); errno != 0 {
			r.mount.cleanupFailed("open-directory close", errno)
		}
		return fuse.EIO
	}
	out.Fh, out.OpenFlags = id, flags
	return fuse.OK
}

func (r *rawFileSystem) ReadDir(_ <-chan struct{}, input *fuse.ReadIn, out *fuse.DirEntryList) fuse.Status {
	handleRecord, handle := r.acquireDirHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	ctx := r.opContext()
	if errno := handle.Seekdir(ctx, input.Offset); errno != 0 {
		return fuse.Status(errno)
	}
	for {
		entry, errno := handle.peek(ctx)
		if errno != 0 {
			return fuse.Status(errno)
		}
		// An entry that does not fit is left buffered for the next READDIR
		// rather than consumed and lost.
		if entry == nil || !out.AddDirEntry(*entry) {
			return fuse.OK
		}
		handle.consume()
	}
}

func (r *rawFileSystem) ReadDirPlus(<-chan struct{}, *fuse.ReadIn, *fuse.DirEntryList) fuse.Status {
	return fuse.ENOSYS
}

func (r *rawFileSystem) FsyncDir(_ <-chan struct{}, input *fuse.FsyncIn) fuse.Status {
	handleRecord, handle := r.acquireDirHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	return fuse.Status(handle.Fsyncdir(r.opContext(), input.FsyncFlags))
}

func (r *rawFileSystem) ReleaseDir(input *fuse.ReleaseIn) {
	handle, ok := r.takeHandle(input.Fh, true)
	if !ok {
		return
	}
	if errno := handle.dir.close(r.opContext()); errno != 0 {
		r.mount.cleanupFailed("open-directory close", errno)
	}
	r.unpin(handle.inode)
}

func (r *rawFileSystem) StatFs(_ <-chan struct{}, header *fuse.InHeader, out *fuse.StatfsOut) fuse.Status {
	record := r.acquire(header.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	return fuse.Status(record.node.Statfs(r.opContext(), out))
}

func (r *rawFileSystem) GetLk(_ <-chan struct{}, input *fuse.LkIn, out *fuse.LkOut) fuse.Status {
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
	return fuse.Status(record.node.Getlk(r.opContext(), input.Owner, &input.Lk, input.LkFlags, &out.Lk))
}

func (r *rawFileSystem) SetLk(cancel <-chan struct{}, input *fuse.LkIn) fuse.Status {
	return r.setLock(cancel, input, false)
}

func (r *rawFileSystem) SetLkw(cancel <-chan struct{}, input *fuse.LkIn) fuse.Status {
	return r.setLock(cancel, input, true)
}

func (r *rawFileSystem) setLock(_ <-chan struct{}, input *fuse.LkIn, wait bool) fuse.Status {
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
	ctx := r.opContext()
	if wait {
		return fuse.Status(record.node.Setlkw(ctx, input.Owner, &input.Lk, input.LkFlags))
	}
	return fuse.Status(record.node.Setlk(ctx, input.Owner, &input.Lk, input.LkFlags))
}

func (r *rawFileSystem) OnUnmount() {
	go func() { _ = r.mount.Close() }()
}

// fillEntry publishes one dentry to the kernel with no cache lifetime at all.
//
// This is the most expensive property of the design and it is deliberate. A
// nonzero entry timeout would let this kernel resolve a path component without
// the authority, so a rename or unlink performed by another machine would be
// invisible here until the timeout expired: `open("/mnt/a/b")` would keep
// resolving to the object `b` used to name, and because open-after-unlink is a
// supported property of this filesystem the stale capability would still work,
// producing wrong data with no error. A nonzero attribute timeout has the same
// shape for stat(2). The architecture forbids repairing this with an
// asynchronous invalidation stream, because a peer can read stale state before
// it processes the event, and this protocol has no authority-to-client
// direction at all: the only correct caching scheme would be synchronous
// revocation, which needs a protocol change this frontend cannot make alone.
// Until then the cost of a path walk is one authority round trip per component,
// and the frontend's job is to make sure that is the *only* cost -- see
// intern's admission and the reclaim lane for the multiplier that is avoidable.
func fillEntry(out *fuse.EntryOut, nodeID uint64, attr *authoritypb.Attr, uid, gid uint32) {
	out.NodeId = nodeID
	out.Generation = 1
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	fillAttr(attr, &out.Attr, uid, gid)
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
