//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"golang.org/x/sys/unix"
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
	// names are the kernel-cached bindings that resolve to this object. They
	// are tracked per record so that the kernel forgetting an inode -- which
	// happens only after it has evicted every dentry naming it -- is exactly
	// what reclaims the frontend's cached-name budget. Nothing else has to
	// guess when the kernel dropped a name.
	names map[nameKey]struct{}

	// graft marks an object served from machine-local backing. Such an object
	// holds no authority capability, is interned in its own table, and can
	// never be the target of a visibility repair.
	graft bool
	// aliases are the live namespace bindings whose paths can reach this object.
	// Authority-backed non-directories need none because their capability, not a
	// path, names them. Directories have one binding, while a machine-local file
	// may have several hard links and must retain every one: reducing those links
	// to one mutable path makes unlinking either alias strand the shared NodeID or,
	// worse, route it into a later inode that reuses the old name.
	aliases map[nameKey]*inodeRecord
}

// handleKind names which of the four open-object shapes a handle record holds.
// Authority handles carry a capability the authority must be told about;
// machine-local handles carry a descriptor this process owns outright.
type handleKind uint8

const (
	handleAuthorityFile handleKind = iota
	handleAuthorityDir
	handleLocalFile
	handleLocalDir
)

type handleRecord struct {
	inode     *inodeRecord
	file      *fileHandle
	dir       *dirHandle
	graftFile *graftHandle
	graftDir  *graftDirHandle
	inFlight  uint64
	closing   bool
	done      chan struct{}
}

func (h *handleRecord) is(kind handleKind) bool {
	switch kind {
	case handleAuthorityFile:
		return h.file != nil
	case handleAuthorityDir:
		return h.dir != nil
	case handleLocalFile:
		return h.graftFile != nil
	case handleLocalDir:
		return h.graftDir != nil
	}
	return false
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

	// profile and the two lifetimes are the cache contract this mount attached
	// with. An uncached mount publishes zero lifetimes and keeps no registry,
	// which is what makes that profile a genuine deployment choice rather than
	// a disabled version of the strict one.
	profile      CoherenceProfile
	entryTimeout time.Duration
	attrTimeout  time.Duration
	nameCapacity int

	// grafts serves the volume's machine-local routes, nil when it declares
	// none. Every routing decision starts with this nil check, so a mount
	// without routes pays one predictable branch per named operation and nothing
	// else. backing is the per-machine tree those routes live in; it answers
	// statfs for grafted paths, which must report real local capacity rather
	// than the volume's virtual numbers.
	grafts  *localdirs.Grafts
	backing string

	mu         sync.Mutex
	nextNodeID uint64
	nodesByID  map[uint64]*inodeRecord
	nodesByKey map[inodeKey]*inodeRecord
	// graftsByKey interns machine-local objects. It is deliberately a separate
	// table from nodesByKey: the visibility machinery resolves coordination
	// identities against nodesByKey, and a graft that could be found there would
	// be a candidate for an invalidation it can never need.
	graftsByKey map[inodeKey]*inodeRecord
	// namedRecords indexes the objects whose path is maintained, so that a
	// rename this mount performs can correct the moved object's path -- the
	// kernel moves the dentry without re-resolving it, so nothing else would.
	namedRecords map[nameKey]*inodeRecord
	nextHandle   uint64
	handles      map[uint64]*handleRecord

	// cachedNames is the exact set of (parent inode, name) bindings this
	// frontend has published to its kernel with a nonzero lifetime. It is what
	// makes a repair precise: a binding that was never cached needs no
	// notification, and one that was must get one.
	cachedNames map[nameKey]*inodeRecord
	// heldNames and heldInodes are closed to cache admission between PREPARE
	// and COMPLETE. heldPhase is the exact set the current PREPARE installed,
	// because COMPLETE's target set is allowed to differ from PREPARE's.
	heldNames  map[nameKey]struct{}
	heldInodes map[uint64]struct{}
	heldPhase  visibilityKeys
	// publishingNames and publishingInodes count publications that were already
	// admitted to the cache and have not finished being written. PREPARE waits
	// them out so that no entry decided before admission closed can be
	// installed after COMPLETE has repaired.
	publishingNames  map[nameKey]int
	publishingInodes map[uint64]int
	published        chan struct{}

	// parked is the set of directories whose kernel i_rwsem this mount is
	// holding for an authority mutation that has not been answered yet.
	//
	// It exists because of the one condition a strict Linux FUSE mount cannot
	// repair its way out of: making a cached binding unservable needs the parent
	// directory's i_rwsem for write (fs/fuse/dir.c, unconditional), and a
	// namespace syscall holds that same semaphore across the whole authority
	// round trip. If a peer's COMPLETE asks this mount to invalidate a name in a
	// directory it is parked in, the wait is a closed cycle and the authority
	// fences this participant rather than stalling the volume. The authority can
	// prove that from the identities it already holds; what it cannot do is say
	// WHICH directory in terms a person can act on. This mount can, so the
	// message it dies with names it.
	parked map[*inodeRecord]int

	// identityDevice pins the one filesystem a volume is, as the authority's
	// explicit major<<32|minor device fact. The kernel inode number alone keys
	// this frontend's tables, so a second device would silently alias two
	// objects.
	identityDevice      uint64
	identityDeviceKnown bool
}

var _ fuse.RawFileSystem = (*rawFileSystem)(nil)

func newRawFileSystem(mount *Mount, root *node) *rawFileSystem {
	key := itemKey(root.item)
	record := &inodeRecord{id: fuse.FUSE_ROOT_ID, key: key, node: root, root: true}
	r := &rawFileSystem{
		RawFileSystem:  fuse.NewDefaultRawFileSystem(),
		mount:          mount,
		requestTimeout: root.requestTimeout,
		maxRead:        root.maxRead,
		maxWrite:       root.maxWrite,
		profile:        mount.profile,
		nameCapacity:   mount.nameCapacity,
		grafts:         mount.grafts,
		backing:        mount.backing,
		nextNodeID:     fuse.FUSE_ROOT_ID + 1,
		nodesByID:      map[uint64]*inodeRecord{fuse.FUSE_ROOT_ID: record},
		nodesByKey:     map[inodeKey]*inodeRecord{key: record},
		graftsByKey:    make(map[inodeKey]*inodeRecord),
		namedRecords:   make(map[nameKey]*inodeRecord),
		nextHandle:     1,
		handles:        make(map[uint64]*handleRecord),

		cachedNames:      make(map[nameKey]*inodeRecord),
		heldNames:        make(map[nameKey]struct{}),
		heldInodes:       make(map[uint64]struct{}),
		parked:           make(map[*inodeRecord]int),
		publishingNames:  make(map[nameKey]int),
		publishingInodes: make(map[uint64]int),
		published:        make(chan struct{}),
	}
	if r.profile == CoherenceStrict {
		r.entryTimeout, r.attrTimeout = strictEntryTimeout, strictAttrTimeout
	}
	mount.raw = r
	return r
}

// directoryLocked resolves a coordination inode number to the directory record
// the kernel knows. Directories are unique by inode within one volume, so this
// is exact rather than a search.
func (r *rawFileSystem) directoryLocked(inode uint64) *inodeRecord {
	return r.nodesByKey[inodeKey{inode: inode, kind: authoritypb.Attr_DIRECTORY}]
}

// byInodeLocked resolves a coordination inode number to whichever record this
// frontend holds for it. Kind is part of the interning key only so that an
// inode number reused for a different object type cannot be confused with the
// old one; at most one of the three can be live at a time.
func (r *rawFileSystem) byInodeLocked(inode uint64) *inodeRecord {
	for _, kind := range [...]authoritypb.Attr_Kind{authoritypb.Attr_REGULAR, authoritypb.Attr_DIRECTORY, authoritypb.Attr_SYMLINK} {
		if record := r.nodesByKey[inodeKey{inode: inode, kind: kind}]; record != nil {
			return record
		}
	}
	return nil
}

// identityIndexLocked is the interning table one record belongs to. Machine-
// local objects are interned apart from authority objects so that nothing which
// resolves a coordination identity can ever reach one.
func (r *rawFileSystem) identityIndexLocked(record *inodeRecord) map[inodeKey]*inodeRecord {
	if record.graft {
		return r.graftsByKey
	}
	return r.nodesByKey
}

func (r *rawFileSystem) dropCachedNameLocked(key nameKey) {
	record := r.cachedNames[key]
	if record == nil {
		return
	}
	delete(r.cachedNames, key)
	delete(record.names, key)
}

// admitNameLocked decides the lifetime one directory binding is published with
// and records the binding when it is cacheable. Uncacheable is always a legal
// answer: it costs a later LOOKUP and can never be wrong.
func (r *rawFileSystem) admitNameLocked(parent uint64, name string, record *inodeRecord) (time.Duration, nameKey, bool) {
	key := nameKey{parent: parent, name: name}
	if r.profile != CoherenceStrict || record == nil {
		return 0, key, false
	}
	if _, held := r.heldNames[key]; held {
		return 0, key, false
	}
	if _, held := r.heldInodes[record.key.inode]; held {
		return 0, key, false
	}
	if _, already := r.cachedNames[key]; !already && len(r.cachedNames) >= r.nameCapacity {
		// The declared capacity is a promise about how much state this mount
		// can withdraw, so it is a hard bound. Beyond it the frontend keeps
		// answering, uncached.
		return 0, key, false
	}
	if record.names == nil {
		record.names = make(map[nameKey]struct{})
	}
	r.cachedNames[key] = record
	record.names[key] = struct{}{}
	r.publishingNames[key]++
	return r.entryTimeout, key, true
}

func (r *rawFileSystem) admitAttrLocked(inode uint64) (time.Duration, bool) {
	if r.profile != CoherenceStrict {
		return 0, false
	}
	if _, held := r.heldInodes[inode]; held {
		return 0, false
	}
	r.publishingInodes[inode]++
	return r.attrTimeout, true
}

// settle ends one admitted publication. PREPARE's drain is waiting on exactly
// this transition, so the wakeup happens under the same lock that decides it.
func (r *rawFileSystem) settle(key nameKey, name bool, inode uint64, attr bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name {
		if r.publishingNames[key]--; r.publishingNames[key] <= 0 {
			delete(r.publishingNames, key)
		}
	}
	if attr {
		if r.publishingInodes[inode]--; r.publishingInodes[inode] <= 0 {
			delete(r.publishingInodes, inode)
		}
	}
	close(r.published)
	r.published = make(chan struct{})
}

// publishEntry hands one directory entry to the kernel with the lifetime this
// mount's cache contract allows for it.
func (r *rawFileSystem) publishEntry(out *fuse.EntryOut, parent uint64, name string, record *inodeRecord, attr *authoritypb.Attr) {
	r.mu.Lock()
	entry, key, cachedName := r.admitNameLocked(parent, name, record)
	inode := attr.GetInode()
	attrLifetime := time.Duration(0)
	cachedAttr := false
	if cachedName {
		attrLifetime, cachedAttr = r.admitAttrLocked(inode)
	}
	r.mu.Unlock()
	out.NodeId = record.id
	out.Generation = 1
	out.SetEntryTimeout(entry)
	out.SetAttrTimeout(attrLifetime)
	fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
	if cachedName || cachedAttr {
		r.settle(key, cachedName, inode, cachedAttr)
	}
}

// unbindSelf records that this mount's own namespace mutation removed a
// binding. The VFS drops the dentry from the same operation's reply, so there
// is nothing left for a later repair to invalidate.
func (r *rawFileSystem) unbindSelf(parent uint64, name string) {
	if r.profile != CoherenceStrict {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropCachedNameLocked(nameKey{parent: parent, name: name})
}

// moveSelf follows a rename. The kernel moves the dentry, keeping the lifetime
// it was published with, so the binding is still cached -- under its new name.
func (r *rawFileSystem) moveSelf(oldParent uint64, oldName string, newParent uint64, newName string, exchange bool) {
	if r.profile != CoherenceStrict {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	from, to := nameKey{parent: oldParent, name: oldName}, nameKey{parent: newParent, name: newName}
	moved, replaced := r.cachedNames[from], r.cachedNames[to]
	r.dropCachedNameLocked(from)
	r.dropCachedNameLocked(to)
	bind := func(key nameKey, record *inodeRecord) {
		if record == nil || len(r.cachedNames) >= r.nameCapacity {
			return
		}
		if record.names == nil {
			record.names = make(map[nameKey]struct{})
		}
		r.cachedNames[key] = record
		record.names[key] = struct{}{}
	}
	bind(to, moved)
	if exchange {
		bind(from, replaced)
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
	r.identityIndexLocked(record)[record.key] = record
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
		if index := r.identityIndexLocked(record); record.lookups == 0 && record.pins == 0 && index[record.key] == record {
			delete(index, record.key)
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
	if index := r.identityIndexLocked(record); index[record.key] == record {
		delete(index, record.key)
	}
	for key := range record.aliases {
		if r.namedRecords[key] == record {
			delete(r.namedRecords, key)
		}
	}
	record.aliases = nil
	// The kernel sends FORGET only after it has evicted every dentry naming
	// this object, so the bindings it held are gone and the cached-name budget
	// they occupied is free again. No timer or estimate is involved.
	for key := range record.names {
		if r.cachedNames[key] == record {
			delete(r.cachedNames, key)
		}
	}
	record.names = nil
	if record.graft {
		// A machine-local object holds no authority capability, so there is
		// nothing for the cleanup lane to hand back.
		return nil
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
	r.identityIndexLocked(record)[record.key] = record
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

// enterParked declares the directories this mount's kernel is holding for one
// unanswered namespace mutation. The returned function must be called exactly
// once when the mutation is no longer outstanding.
//
// It mirrors, on this side, what the authority derives from the request itself.
// Declaring it here costs one map update per namespace mutation and buys the
// one thing the authority cannot produce: a path, in a message a person reads.
func (r *rawFileSystem) enterParked(records ...*inodeRecord) func() {
	if r.profile != CoherenceStrict {
		return func() {}
	}
	r.mu.Lock()
	for _, record := range records {
		if record != nil {
			r.parked[record]++
		}
	}
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			for _, record := range records {
				if record == nil {
					continue
				}
				if r.parked[record]--; r.parked[record] <= 0 {
					delete(r.parked, record)
				}
			}
		})
	}
}

// parkedDirectories names the directories this mount is currently holding for
// an unanswered authority mutation, deepest information first: the volume path
// when it is known, and the coordination inode when it is not.
func (r *rawFileSystem) parkedDirectories() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.parked) == 0 {
		return nil
	}
	names := make([]string, 0, len(r.parked))
	for record := range r.parked {
		if path, ok := r.pathLocked(record); ok {
			if path == "" {
				path = "/"
			}
			names = append(names, path)
			continue
		}
		names = append(names, fmt.Sprintf("inode %d", record.key.inode))
	}
	sort.Strings(names)
	return names
}

// acquireGraftFileHandle admits one operation on an open machine-local file.
func (r *rawFileSystem) acquireGraftFileHandle(id uint64) (*handleRecord, *graftHandle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	handle := r.handles[id]
	if handle == nil || handle.graftFile == nil || handle.closing || handle.inFlight == math.MaxUint64 {
		return nil, nil
	}
	handle.inFlight++
	return handle, handle.graftFile
}

// acquireGraftDirHandle admits one operation on an open machine-local
// directory.
func (r *rawFileSystem) acquireGraftDirHandle(id uint64) (*handleRecord, *graftDirHandle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	handle := r.handles[id]
	if handle == nil || handle.graftDir == nil || handle.closing || handle.inFlight == math.MaxUint64 {
		return nil, nil
	}
	handle.inFlight++
	return handle, handle.graftDir
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

func (r *rawFileSystem) takeHandle(id uint64, kind handleKind) (*handleRecord, bool) {
	r.mu.Lock()
	handle := r.handles[id]
	if handle == nil || !handle.is(kind) {
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
		// The root is excluded exactly as it is in Forget. It is never looked
		// up, so its lookup count is permanently zero, and dropping it from the
		// identity index the first time anything opens and closes the mount
		// directory would leave the mount unable to resolve any coordination
		// identity rooted there -- silently turning every later namespace
		// repair into a no-op.
		if index := r.identityIndexLocked(record); !record.root && record.lookups == 0 && record.pins == 0 && index[record.key] == record {
			delete(index, record.key)
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
	if r.grafts != nil {
		if handled, status := r.graftLookup(parent, name, out); handled {
			return status
		}
	}
	ctx := r.opContext()
	item, errno := parent.node.Lookup(ctx, name)
	if errno != 0 {
		// A negative result is never cached. The authority emits a namespace
		// event when a name comes into existence, but a cached negative dentry
		// is state this frontend would have to repair for a name it has no
		// record of, so it is simply never created.
		out.SetEntryTimeout(0)
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	r.bindPath(record, parent, name)
	r.publishEntry(out, parent.key.inode, name, record, item.GetAttr())
	return fuse.OK
}

// graftDescriptor resolves the machine-local descriptor a GETATTR or SETATTR
// may carry. It returns -1 when the request names no handle, which is the
// path-based case.
func (r *rawFileSystem) graftDescriptor(id uint64, present bool, record *inodeRecord) (int, *handleRecord, fuse.Status) {
	if !present {
		return -1, nil, fuse.OK
	}
	handleRecord, handle := r.acquireGraftFileHandle(id)
	if handle == nil {
		return -1, nil, fuse.EBADF
	}
	if handleRecord.inode != record {
		r.releaseHandleOperation(handleRecord)
		return -1, nil, fuse.EBADF
	}
	return handle.fd, handleRecord, fuse.OK
}

func (r *rawFileSystem) GetAttr(_ <-chan struct{}, input *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	if record.graft {
		fd, held, status := r.graftDescriptor(input.Fh(), input.Flags()&fuse.FUSE_GETATTR_FH != 0, record)
		if !status.Ok() {
			return status
		}
		if held != nil {
			defer r.releaseHandleOperation(held)
		}
		return r.graftGetattr(record, fd, out)
	}
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
	if record.graft {
		id, present := input.GetFh()
		fd, held, status := r.graftDescriptor(id, present, record)
		if !status.Ok() {
			return status
		}
		if held != nil {
			defer r.releaseHandleOperation(held)
		}
		return r.graftSetattr(record, fd, input, out)
	}
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
	ctx, finish := r.mutationContext()
	defer finish()
	return fuse.Status(record.node.Setattr(ctx, handle, input, out))
}

func (r *rawFileSystem) Open(_ <-chan struct{}, input *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	if record.graft {
		handle, flags, errno := r.graftOpen(record, input.Flags)
		if errno != 0 {
			return fuse.Status(errno)
		}
		id, ok := r.addHandle(record, &handleRecord{graftFile: handle})
		if !ok {
			_ = handle.close()
			return fuse.EIO
		}
		out.Fh, out.OpenFlags = id, flags
		return fuse.OK
	}
	ctx, finish := r.mutationContext()
	defer finish()
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
	if input.Offset > math.MaxInt64 {
		return nil, fuse.EINVAL
	}
	if r.grafts != nil {
		if held, handle := r.acquireGraftFileHandle(input.Fh); handle != nil {
			defer r.releaseHandleOperation(held)
			// The read goes straight to the backing descriptor: no authority
			// round trip, no bulk-lane admission, no operation deadline. There
			// is nothing on the other end of it that can be slow for a reason
			// this mount does not control.
			count, err := unix.Pread(handle.fd, buf, int64(input.Offset))
			if err != nil {
				return nil, fuse.Status(errnoOfError(err))
			}
			return fuse.ReadResultData(buf[:count]), fuse.OK
		}
	}
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return nil, fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	result, errno := handle.node.Read(r.opContext(), handle, buf, int64(input.Offset))
	return result, fuse.Status(errno)
}

func (r *rawFileSystem) Write(_ <-chan struct{}, input *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	if input.Offset > math.MaxInt64 {
		return 0, fuse.EINVAL
	}
	if r.grafts != nil {
		if held, handle := r.acquireGraftFileHandle(input.Fh); handle != nil {
			defer r.releaseHandleOperation(held)
			count, err := unix.Pwrite(handle.fd, data, int64(input.Offset))
			if err != nil {
				return 0, fuse.Status(errnoOfError(err))
			}
			return uint32(count), fuse.OK
		}
	}
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return 0, fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	ctx, finish := r.mutationContext()
	defer finish()
	written, errno := handle.node.Write(ctx, handle, data, int64(input.Offset))
	return written, fuse.Status(errno)
}

func (r *rawFileSystem) Flush(_ <-chan struct{}, input *fuse.FlushIn) fuse.Status {
	if r.grafts != nil {
		if held, handle := r.acquireGraftFileHandle(input.Fh); handle != nil {
			defer r.releaseHandleOperation(held)
			// close(2) on a machine-local file has nothing to report to anyone:
			// the data is already in the backing filesystem's page cache, which
			// is where an ordinary local close leaves it too.
			_ = handle
			return fuse.OK
		}
	}
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	return fuse.Status(handle.node.Flush(r.opContext(), handle, input.LockOwner))
}

func (r *rawFileSystem) Fsync(_ <-chan struct{}, input *fuse.FsyncIn) fuse.Status {
	if r.grafts != nil {
		if held, handle := r.acquireGraftFileHandle(input.Fh); handle != nil {
			defer r.releaseHandleOperation(held)
			if input.FsyncFlags&fsyncDataOnly != 0 {
				return fuse.Status(errnoOfError(unix.Fdatasync(handle.fd)))
			}
			return fuse.Status(errnoOfError(unix.Fsync(handle.fd)))
		}
	}
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	return fuse.Status(handle.node.Fsync(r.opContext(), handle, input.FsyncFlags))
}

func (r *rawFileSystem) Release(_ <-chan struct{}, input *fuse.ReleaseIn) {
	if r.grafts != nil {
		if held, ok := r.takeHandle(input.Fh, handleLocalFile); ok {
			// A failed close(2) has released the descriptor regardless, and
			// RELEASE has no reply to carry the deferred write-back error it
			// reports, so there is nothing to escalate: unlike an authority
			// close, no second party is still holding the object.
			_ = held.graftFile.close()
			r.unpin(held.inode)
			return
		}
	}
	handle, ok := r.takeHandle(input.Fh, handleAuthorityFile)
	if !ok {
		return
	}
	ctx, finish := r.mutationContext()
	defer finish()
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
	if r.grafts != nil {
		resolved, errno := r.routeFor(parent, name)
		if errno != 0 {
			return fuse.Status(errno)
		}
		if resolved.root != "" {
			record, handle, flags, errno := r.graftCreate(parent, resolved, input.Flags, input.Mode, &out.EntryOut)
			if errno != 0 {
				return fuse.Status(errno)
			}
			id, ok := r.addHandle(record, &handleRecord{graftFile: handle})
			if !ok {
				_ = handle.close()
				r.Forget(record.id, 1)
				return fuse.EIO
			}
			out.Fh, out.OpenFlags = id, flags
			return fuse.OK
		}
	}
	ctx, finish := r.mutationContext()
	defer finish()
	defer r.enterParked(parent)()
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
	r.bindPath(record, parent, name)
	r.publishEntry(&out.EntryOut, parent.key.inode, name, record, item.GetAttr())
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
	if r.grafts != nil {
		resolved, errno := r.routeFor(parent, name)
		if errno != 0 {
			return fuse.Status(errno)
		}
		if resolved.root != "" {
			// The machine-local side answers mknod exactly as the authority
			// side does, so the errno a caller sees does not depend on which
			// side of a route boundary the name happens to fall on.
			switch input.Mode & syscall.S_IFMT {
			case 0, syscall.S_IFREG:
			case syscall.S_IFIFO, syscall.S_IFSOCK:
				return fuse.Status(syscall.EOPNOTSUPP)
			default:
				return fuse.Status(syscall.EPERM)
			}
			if input.Rdev != 0 {
				return fuse.Status(syscall.EPERM)
			}
			_, handle, _, errno := r.graftCreate(parent, resolved, uint32(syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL), input.Mode, out)
			if errno != 0 {
				return fuse.Status(errno)
			}
			// mknod(2) hands the caller no open file description, so the one
			// this created is released immediately.
			_ = handle.close()
			return fuse.OK
		}
	}
	ctx, finish := r.mutationContext()
	defer finish()
	defer r.enterParked(parent)()
	item, errno := parent.node.Mknod(ctx, name, input.Mode, input.Rdev)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	r.bindPath(record, parent, name)
	r.publishEntry(out, parent.key.inode, name, record, item.GetAttr())
	return fuse.OK
}

func (r *rawFileSystem) Mkdir(_ <-chan struct{}, input *fuse.MkdirIn, name string, out *fuse.EntryOut) fuse.Status {
	parent := r.acquire(input.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	if r.grafts != nil {
		resolved, errno := r.routeFor(parent, name)
		if errno != 0 {
			return fuse.Status(errno)
		}
		if resolved.root != "" {
			// This is where a route root comes into existence. The matcher is
			// consulted on the mkdir itself, so the directory is machine-local
			// from the instant it exists and the authority is never told about
			// it or about anything created under it afterwards.
			if _, errno := r.graftMkdir(parent, resolved, input.Mode, out); errno != 0 {
				return fuse.Status(errno)
			}
			return fuse.OK
		}
	}
	ctx, finish := r.mutationContext()
	defer finish()
	defer r.enterParked(parent)()
	item, errno := parent.node.Mkdir(ctx, name, input.Mode)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	r.bindPath(record, parent, name)
	r.publishEntry(out, parent.key.inode, name, record, item.GetAttr())
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
	if r.grafts != nil {
		resolved, errno := r.routeFor(parent, name)
		if errno != 0 {
			return fuse.Status(errno)
		}
		if resolved.root != "" {
			// The route root is removed like any other directory, contents and
			// all. A dependency installer that rebuilds its tree wholesale --
			// remove node_modules, create it again -- has to be able to do this.
			errno := r.graftRemove(resolved.path, directory)
			if errno == 0 {
				r.unbindPath(parent, name)
			}
			return fuse.Status(errno)
		}
	}
	ctx, finish := r.mutationContext()
	defer finish()
	defer r.enterParked(parent)()
	var errno syscall.Errno
	if directory {
		errno = parent.node.Rmdir(ctx, name)
	} else {
		errno = parent.node.Unlink(ctx, name)
	}
	if errno == 0 {
		// The VFS drops the dentry from this operation's own reply, under the
		// parent's i_rwsem. The binding is gone from the kernel, so this
		// frontend no longer owes a repair for it -- and must not attempt one,
		// because the notification would need the same lock this syscall holds.
		r.unbindSelf(parent.key.inode, name)
		r.unbindPath(parent, name)
	}
	return fuse.Status(errno)
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
	oldPath, newPath := "", ""
	if r.grafts != nil {
		resolvedOld, errno := r.routeFor(oldParent, oldName)
		if errno != 0 {
			return fuse.Status(errno)
		}
		resolvedNew, errno := r.routeFor(newParent, newName)
		if errno != 0 {
			return fuse.Status(errno)
		}
		oldPath, newPath = resolvedOld.path, resolvedNew.path
		if resolvedOld.root != "" && resolvedOld.root == resolvedNew.root {
			errno := r.graftRename(oldPath, newPath, input.Flags)
			if errno == 0 {
				r.rebindRenamed(oldParent, oldName, newParent, newName, input.Flags&renameExchange != 0)
			}
			return fuse.Status(errno)
		}
		// localdirs owns the boundary answers: EXDEV for a crossing, and EBUSY
		// both for a shared directory whose subtree still holds machine-local
		// backing and for a rename that would change which paths the rules
		// match. EXDEV would be actively wrong for those two, because the
		// copy-and-delete fallback it invites would move per-machine content
		// into shared storage.
		if errno, handled := r.grafts.VolumeRenameCheck(oldPath, newPath); handled {
			return fuse.Status(errno)
		}
	}
	ctx, finish := r.mutationContext()
	defer finish()
	defer r.enterParked(oldParent, newParent)()
	errno := oldParent.node.Rename(ctx, oldName, newParent.node, newName, input.Flags)
	if errno == 0 {
		// The route set is a pure function of the declaration, so a rename that
		// was allowed to happen changed no routing and there is nothing to
		// remap. What does change is where the moved directory IS, and every
		// later routing decision under it is made from that.
		r.rebindRenamed(oldParent, oldName, newParent, newName, input.Flags&renameExchange != 0)
		// d_move carries the dentry, and the lifetime it was published with, to
		// the new name. The binding is still cached; it is cached somewhere
		// else, and the registry has to say so or a later remote change to the
		// new name would go unrepaired.
		r.moveSelf(oldParent.key.inode, oldName, newParent.key.inode, newName, input.Flags&renameExchange != 0)
	}
	return fuse.Status(errno)
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
	if r.grafts != nil {
		if handled, status := r.graftLink(source, newParent, name, out); handled {
			return status
		}
	}
	ctx, finish := r.mutationContext()
	defer finish()
	defer r.enterParked(newParent)()
	item, errno := newParent.node.Link(ctx, source.node, name)
	if errno != 0 {
		return fuse.Status(errno)
	}
	if !r.addLookupExisting(source) {
		// The authority applied the link. Answering with an ordinary error
		// would misreport a completed mutation as failed — a lost mutation
		// from the caller's view — and the in-flight pin on source means this
		// is reachable only against a concurrent revocation or a saturated
		// lookup count, both of which end the mount's ability to account for
		// kernel references at all. Revoke, which is the one answer that does
		// not claim the link was refused.
		r.mount.revoke(fmt.Errorf("fusev3: link %q applied at the authority but source inode %d can no longer accept a kernel reference", name, input.Oldnodeid))
		return fuse.Status(syscall.ENOTCONN)
	}
	r.publishEntry(out, newParent.key.inode, name, source, item.GetAttr())
	return fuse.OK
}

func (r *rawFileSystem) Symlink(_ <-chan struct{}, header *fuse.InHeader, pointedTo, linkName string, out *fuse.EntryOut) fuse.Status {
	parent := r.acquire(header.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	if r.grafts != nil {
		resolved, errno := r.routeFor(parent, linkName)
		if errno != 0 {
			return fuse.Status(errno)
		}
		if resolved.root != "" {
			if _, errno := r.graftSymlink(parent, resolved, pointedTo, out); errno != 0 {
				return fuse.Status(errno)
			}
			return fuse.OK
		}
	}
	ctx, finish := r.mutationContext()
	defer finish()
	defer r.enterParked(parent)()
	item, errno := parent.node.Symlink(ctx, pointedTo, linkName)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	r.bindPath(record, parent, linkName)
	r.publishEntry(out, parent.key.inode, linkName, record, item.GetAttr())
	return fuse.OK
}

func (r *rawFileSystem) Readlink(_ <-chan struct{}, header *fuse.InHeader) ([]byte, fuse.Status) {
	record := r.acquire(header.NodeId)
	if record == nil {
		return nil, fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	if record.graft {
		return r.graftReadlink(record)
	}
	value, errno := record.node.Readlink(r.opContext())
	return value, fuse.Status(errno)
}

func (r *rawFileSystem) GetXAttr(_ <-chan struct{}, header *fuse.InHeader, name string, dest []byte) (uint32, fuse.Status) {
	record := r.acquire(header.NodeId)
	if record == nil {
		return 0, fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	if record.graft {
		return 0, fuse.Status(graftXattrErrno)
	}
	size, errno := record.node.Getxattr(r.opContext(), name, dest)
	return size, fuse.Status(errno)
}

func (r *rawFileSystem) SetXAttr(_ <-chan struct{}, input *fuse.SetXAttrIn, name string, data []byte) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	if record.graft {
		return fuse.Status(graftXattrErrno)
	}
	ctx, finish := r.mutationContext()
	defer finish()
	return fuse.Status(record.node.Setxattr(ctx, name, data, input.Flags))
}

func (r *rawFileSystem) ListXAttr(_ <-chan struct{}, header *fuse.InHeader, dest []byte) (uint32, fuse.Status) {
	record := r.acquire(header.NodeId)
	if record == nil {
		return 0, fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	if record.graft {
		return 0, fuse.Status(graftXattrErrno)
	}
	size, errno := record.node.Listxattr(r.opContext(), dest)
	return size, fuse.Status(errno)
}

func (r *rawFileSystem) RemoveXAttr(_ <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
	record := r.acquire(header.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	if record.graft {
		return fuse.Status(graftXattrErrno)
	}
	ctx, finish := r.mutationContext()
	defer finish()
	return fuse.Status(record.node.Removexattr(ctx, name))
}

func (r *rawFileSystem) OpenDir(_ <-chan struct{}, input *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	if record.graft {
		if input.Flags&uint32(syscall.O_ACCMODE) != uint32(syscall.O_RDONLY) {
			return fuse.Status(syscall.EISDIR)
		}
		handle, errno := r.graftReaddir(record)
		if errno != 0 {
			return fuse.Status(errno)
		}
		id, ok := r.addHandle(record, &handleRecord{graftDir: handle})
		if !ok {
			return fuse.EIO
		}
		out.Fh, out.OpenFlags = id, 0
		return fuse.OK
	}
	ctx, finish := r.mutationContext()
	defer finish()
	handle, flags, errno := record.node.OpendirHandle(ctx, input.Flags)
	if errno != 0 {
		return fuse.Status(errno)
	}
	if r.grafts != nil {
		// The route roots this directory contains are decided once, when the
		// stream is opened, exactly like the volume page the authority hands
		// back. A listing that recomputed them per READDIR could show a root
		// twice or not at all across the reply boundary.
		dir, ok := r.path(record)
		if !ok {
			if errno := handle.close(ctx); errno != 0 {
				r.mount.cleanupFailed("open-directory close", errno)
			}
			return fuse.EIO
		}
		local, errno := r.mergedRoots(dir)
		if errno != 0 {
			if errno := handle.close(ctx); errno != 0 {
				r.mount.cleanupFailed("open-directory close", errno)
			}
			return fuse.Status(errno)
		}
		handle.local, handle.shadow = local, r.shadowedIn(dir)
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
	if r.grafts != nil {
		if held, handle := r.acquireGraftDirHandle(input.Fh); handle != nil {
			defer r.releaseHandleOperation(held)
			if errno := handle.seek(input.Offset); errno != 0 {
				return fuse.Status(errno)
			}
			for {
				entry := handle.peek()
				if entry == nil || !out.AddDirEntry(*entry) {
					return fuse.OK
				}
				handle.consume()
			}
		}
	}
	handleRecord, handle := r.acquireDirHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	ctx, finish := r.mutationContext()
	defer finish()
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
	if r.grafts != nil {
		if held, handle := r.acquireGraftDirHandle(input.Fh); handle != nil {
			defer r.releaseHandleOperation(held)
			path, ok := r.path(held.inode)
			if !ok {
				return fuse.Status(syscall.ESTALE)
			}
			return fuse.Status(r.grafts.Fsync(path))
		}
	}
	handleRecord, handle := r.acquireDirHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	return fuse.Status(handle.Fsyncdir(r.opContext(), input.FsyncFlags))
}

func (r *rawFileSystem) ReleaseDir(input *fuse.ReleaseIn) {
	if r.grafts != nil {
		if held, ok := r.takeHandle(input.Fh, handleLocalDir); ok {
			// The snapshot is memory this process owns; nothing outside it is
			// holding anything on behalf of this stream.
			r.unpin(held.inode)
			return
		}
	}
	handle, ok := r.takeHandle(input.Fh, handleAuthorityDir)
	if !ok {
		return
	}
	ctx, finish := r.mutationContext()
	defer finish()
	if errno := handle.dir.close(ctx); errno != 0 {
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
	if record.graft {
		return r.graftStatfs(out)
	}
	return fuse.Status(record.node.Statfs(r.opContext(), out))
}

func (r *rawFileSystem) GetLk(_ <-chan struct{}, input *fuse.LkIn, out *fuse.LkOut) fuse.Status {
	record := r.acquire(input.NodeId)
	if record == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(record)
	if record.graft {
		held, handle := r.acquireGraftFileHandle(input.Fh)
		if handle == nil {
			return fuse.EBADF
		}
		defer r.releaseHandleOperation(held)
		if held.inode != record {
			return fuse.EBADF
		}
		return fuse.Status(graftGetlock(handle.fd, &input.Lk, &out.Lk))
	}
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
	if record.graft {
		held, handle := r.acquireGraftFileHandle(input.Fh)
		if handle == nil {
			return fuse.EBADF
		}
		defer r.releaseHandleOperation(held)
		if held.inode != record {
			return fuse.EBADF
		}
		return fuse.Status(graftLock(handle.fd, &input.Lk, input.LkFlags, wait))
	}
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	if handleRecord.inode != record {
		return fuse.EBADF
	}
	ctx, finish := r.mutationContext()
	defer finish()
	if wait {
		return fuse.Status(record.node.Setlkw(ctx, input.Owner, &input.Lk, input.LkFlags))
	}
	return fuse.Status(record.node.Setlk(ctx, input.Owner, &input.Lk, input.LkFlags))
}

func (r *rawFileSystem) OnUnmount() {
	go func() { _ = r.mount.Close() }()
}

// publishAttr answers a stat with the lifetime this mount's cache contract
// allows. It is the attribute-side twin of publishEntry: the same gate, the
// same drain, and the same rule that uncacheable is always a legal answer.
//
// Before this mount joined the authority's visibility barrier the answer here
// was unconditionally zero, and that was the correct choice at the time: a
// nonzero lifetime would have let this kernel answer stat(2) about an object
// another machine had already changed, with nothing able to take the answer
// back. What changed is not the risk assessment, it is the protocol -- there is
// now an authority-to-frontend direction, and every change to this inode is
// repaired through it before the mutating call returns on the machine that made
// it.
func (r *rawFileSystem) publishAttr(out *fuse.AttrOut, attr *authoritypb.Attr) {
	inode := attr.GetInode()
	r.mu.Lock()
	lifetime, cached := r.admitAttrLocked(inode)
	r.mu.Unlock()
	fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
	out.SetTimeout(lifetime)
	if cached {
		r.settle(nameKey{}, false, inode, true)
	}
}

// withParkedContext names the directories this mount was holding for an
// unanswered authority mutation when it died.
//
// It is what makes the one failure a strict Linux FUSE mount cannot repair its
// way out of diagnosable. The authority fences a participant whose COMPLETE
// provably cannot run because that participant's own kernel holds the affected
// directory exclusively -- and the authority knows that directory only as a
// coordination identity. This mount knows its path. Saying it here is the
// difference between "your mount was fenced" and "your mount was fenced while
// it was in the middle of a mkdir in <path>".
func (m *Mount) withParkedContext(err error) error {
	if m.profile != CoherenceStrict || m.raw == nil {
		return err
	}
	directories := m.raw.parkedDirectories()
	if len(directories) == 0 {
		return err
	}
	return fmt.Errorf("%w (this mount was holding %s for an authority mutation it had not been answered for; a strict Linux mount cannot invalidate a name in a directory its own unanswered namespace operation is holding)",
		err, strings.Join(directories, ", "))
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
	err = m.withParkedContext(err)
	m.abort.Do(func() {
		m.fatalMu.Lock()
		m.fatalErr = err
		m.fatalMu.Unlock()
		if m.cancel != nil {
			m.cancel()
		}
		go func() {
			// A strict mount owes the volume more than a tidy exit: it has
			// published names and attributes that nothing can correct any more,
			// so it withdraws them and makes itself unreachable before it even
			// tries an ordinary unmount.
			if m.profile == CoherenceStrict {
				m.withdrawKernelState()
			}
			if m.server != nil {
				_ = m.Unmount()
			}
			_ = m.Close()
		}()
	})
}
