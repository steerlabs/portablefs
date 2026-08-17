//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"golang.org/x/sys/unix"
)

type inodeKey struct {
	inode uint64
	kind  authoritypb.Attr_Kind
}

type inodeRecord struct {
	id  uint64
	key inodeKey
	// identity is the stable filesystem identity used for coherence. Kernel
	// inode numbers remain an implementation detail of the FUSE tables; source
	// publication gates never key correctness on a number the kernel may reuse.
	identity  publicationIdentity
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

	// A LOCAL O_TMPFILE has no namespace alias before its first LINK. The live
	// open description is the only honest source capability for linkat with
	// AT_EMPTY_PATH; retaining it here lets graftLink perform that operation
	// without inventing a path. The handle owns/ultimately closes the descriptor.
	graftAnonymousFh   uint64
	graftAnonymousRoot string
}

type replyNamePublication struct {
	key        nameKey
	stable     publicationNamespace
	record     *inodeRecord
	coordinate publicationCoordinate
	reserved   bool
}

type replyAttrPublication struct {
	inode      uint64
	coordinate publicationCoordinate
}

// replyPublication is everything one kernel response can make cacheable or
// must keep source-serialized. It is registered by request Unique before the
// RawFileSystem method returns. Definite no-change replies settle after their
// physical /dev/fuse write; state-bearing replies settle only after the
// kernel's later post-VFS PFS_PUBLISH receipt is physically acknowledged.
type replyPublication struct {
	names         []replyNamePublication
	attrs         []replyAttrPublication
	source        *sourcePublicationLease
	writeKernelTx uint64
	// responseConsumptions prevent authority transport EOF from exposing the
	// session terminal edge until every authority response contributing to this
	// kernel result is either physically published through PFS_PUBLISH or
	// fail-closed locally. One FUSE callback may require several bounded read or
	// staged-write RPCs, so this is deliberately a collection rather than one
	// token.
	responseConsumptions []authorityrpc.ResponseConsumption

	// Generic post-VFS publication receipt state, protected by
	// rawFileSystem.mu. The original response write only signals
	// originalDone. Cache/source ownership remains retained through the
	// physical FUSE_PFS_PUBLISH acknowledgment.
	requestUnique  uint64
	nodeid         uint64
	opcode         uint32
	marked         bool
	needsPostVFS   bool
	originalDone   chan struct{}
	originalWrote  bool
	originalStatus fuse.Status
	publicationID  uint64
	publishUnique  uint64
}

func (p *replyPublication) empty() bool {
	return p == nil || len(p.names) == 0 && len(p.attrs) == 0 && p.source == nil &&
		p.writeKernelTx == 0 && len(p.responseConsumptions) == 0 && !p.needsPostVFS
}

func (p *replyPublication) consumeAuthorityResponse() {
	if p == nil {
		return
	}
	for _, consumption := range p.responseConsumptions {
		if consumption != nil {
			consumption.Consume()
		}
	}
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

type writeTransaction struct {
	kernelTxid     uint64
	authorityTxid  uint64
	nodeID         uint64
	handleID       uint64
	handleRecord   *handleRecord
	handle         *fileHandle
	begun          bool
	requestedSize  uint64
	stagedSize     uint64
	position       uint64
	rlimitFsize    uint64
	fileMaxSize    uint64
	lockOwner      uint64
	writeFlags     uint32
	flags          uint32
	committedSize  uint64
	assignedOffset uint64
	postSize       uint64
	sequence       uint64
	lease          *sourcePublicationLease
	commitResolved bool
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

	// writeBeginMu linearizes the mapping from connection-local kernel txids
	// to the session-monotonic transaction sequence the authority retains for
	// bounded replay. BEGIN dispatch order is therefore deterministic even when
	// kernel callbacks arrive concurrently.
	writeBeginMu sync.Mutex
	writeMu      sync.Mutex
	nextWriteTx  uint64
	writeTx      map[uint64]*writeTransaction

	// The two lifetimes are the single protocol-5 cache contract. Every mount
	// owns the corresponding repair registry and visibility participation.
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
	cachedNames       map[nameKey]*inodeRecord
	cachedStableNames map[publicationNamespace]*inodeRecord
	cachedNameStable  map[nameKey]publicationNamespace
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
	publishingNames     map[nameKey]int
	publishingInodes    map[uint64]int
	pendingNames        int
	published           chan struct{}
	replyPublications   map[uint64]*replyPublication
	publishAcks         map[uint64]*replyPublication
	replyLifecycleArmed bool

	// Source-owned gates close publication before the mutation gets a replay
	// identity or can put bytes on the wire. Unlike peer visibility state, these
	// maps are keyed only by stable filesystem identities and exact names.
	sourceHolds                 map[publicationCoordinate]*sourcePublicationLease
	sourcePublishing            map[publicationCoordinate]int
	peerHolds                   map[publicationCoordinate]int
	sourceUnresolvedAttributes  map[*sourcePublicationLease]int
	sourceUnresolvedData        map[*sourcePublicationLease]int
	peerHeldPhase               []publicationCoordinate
	sourceChanged               chan struct{}
	completedVisibilitySequence uint64

	// identityDevice pins the one filesystem a volume is, as the authority's
	// explicit major<<32|minor device fact. The kernel inode number alone keys
	// this frontend's tables, so a second device would silently alias two
	// objects.
	identityDevice      uint64
	identityDeviceKnown bool
}

var _ fuse.RawFileSystem = (*rawFileSystem)(nil)
var _ fuse.ReplyWriteLifecycle = (*rawFileSystem)(nil)

func newRawFileSystem(mount *Mount, root *node) *rawFileSystem {
	key := itemKey(root.item)
	identity, _ := publicationIdentityFromItem(root.item)
	record := &inodeRecord{id: fuse.FUSE_ROOT_ID, key: key, identity: identity, node: root, root: true}
	r := &rawFileSystem{
		RawFileSystem:  fuse.NewDefaultRawFileSystem(),
		mount:          mount,
		requestTimeout: root.requestTimeout,
		maxRead:        root.maxRead,
		maxWrite:       root.maxWrite,
		entryTimeout:   strictEntryTimeout,
		attrTimeout:    strictAttrTimeout,
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

		cachedNames:                make(map[nameKey]*inodeRecord),
		cachedStableNames:          make(map[publicationNamespace]*inodeRecord),
		cachedNameStable:           make(map[nameKey]publicationNamespace),
		heldNames:                  make(map[nameKey]struct{}),
		heldInodes:                 make(map[uint64]struct{}),
		publishingNames:            make(map[nameKey]int),
		publishingInodes:           make(map[uint64]int),
		published:                  make(chan struct{}),
		replyPublications:          make(map[uint64]*replyPublication),
		publishAcks:                make(map[uint64]*replyPublication),
		nextWriteTx:                1,
		writeTx:                    make(map[uint64]*writeTransaction),
		sourceHolds:                make(map[publicationCoordinate]*sourcePublicationLease),
		sourcePublishing:           make(map[publicationCoordinate]int),
		peerHolds:                  make(map[publicationCoordinate]int),
		sourceUnresolvedAttributes: make(map[*sourcePublicationLease]int),
		sourceUnresolvedData:       make(map[*sourcePublicationLease]int),
		sourceChanged:              make(chan struct{}),
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
	if stable, exists := r.cachedNameStable[key]; exists {
		if r.cachedStableNames[stable] == record {
			delete(r.cachedStableNames, stable)
		}
		delete(r.cachedNameStable, key)
	}
	delete(record.names, key)
}

func (r *rawFileSystem) bindCachedNameLocked(key nameKey, stable publicationNamespace, record *inodeRecord) {
	if record == nil {
		return
	}
	// Publication admission reserved capacity before the reply write. Replace
	// an earlier binding only after the new reply has physically reached the
	// kernel, preserving the old repair obligation if that write fails.
	r.dropCachedNameLocked(key)
	if record.names == nil {
		record.names = make(map[nameKey]struct{})
	}
	r.cachedNames[key] = record
	r.cachedStableNames[stable] = record
	r.cachedNameStable[key] = stable
	record.names[key] = struct{}{}
}

// admitNameLocked decides the lifetime one directory binding is published with
// and records the binding when it is cacheable. Uncacheable is always a legal
// answer: it costs a later LOOKUP and can never be wrong.
func (r *rawFileSystem) admitNameLocked(ctx context.Context, parent *inodeRecord, name string, record *inodeRecord) (time.Duration, replyNamePublication, bool) {
	key := nameKey{parent: parent.key.inode, name: name}
	stable := publicationNamespace{parent: parent.identity, name: name}
	coordinate := publicationCoordinate{kind: publicationNamespaceName, parent: stable.parent, name: name}
	publication := replyNamePublication{key: key, stable: stable, record: record, coordinate: coordinate}
	if record == nil {
		return 0, publication, false
	}
	if _, held := r.heldNames[key]; held {
		return 0, publication, false
	}
	if _, held := r.heldInodes[record.key.inode]; held {
		return 0, publication, false
	}
	if !r.sourcePublicationAllowedLocked(coordinate, sourceLeaseFromContext(ctx)) {
		return 0, publication, false
	}
	_, already := r.cachedNames[key]
	if !already && len(r.cachedNames)+r.pendingNames >= r.nameCapacity {
		// The declared capacity is a promise about how much state this mount
		// can withdraw, so it is a hard bound. Beyond it the frontend keeps
		// answering with a zero lifetime.
		return 0, publication, false
	}
	publication.reserved = !already
	if publication.reserved {
		r.pendingNames++
	}
	r.publishingNames[key]++
	r.admitSourcePublicationLocked(coordinate)
	return r.entryTimeout, publication, true
}

func (r *rawFileSystem) admitAttrLocked(ctx context.Context, inode uint64, identity publicationIdentity) (time.Duration, publicationCoordinate, bool) {
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: identity}
	if _, held := r.heldInodes[inode]; held {
		return 0, coordinate, false
	}
	if !r.sourcePublicationAllowedLocked(coordinate, sourceLeaseFromContext(ctx)) {
		return 0, coordinate, false
	}
	r.publishingInodes[inode]++
	r.admitSourcePublicationLocked(coordinate)
	return r.attrTimeout, coordinate, true
}

// settle ends one admitted publication. PREPARE's drain is waiting on exactly
// this transition, so the wakeup happens under the same lock that decides it.
// publishEntry hands one directory entry to the kernel with the lifetime this
// mount's cache contract allows for it.
func (r *rawFileSystem) publishEntry(ctx context.Context, out *fuse.EntryOut, parent *inodeRecord, name string, record *inodeRecord, attr *authoritypb.Attr) error {
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		return errors.New("fusev3: entry result escaped its post-VFS reply-publication lifecycle")
	}
	// Even a zero-lifetime reply is installed transiently by fuse_iget/d_add
	// after the daemon response wakes the requester. It therefore needs the
	// generic post-VFS receipt even when it creates no durable cache obligation.
	publication.needsPostVFS = true
	if owner := sourceLeaseFromContext(ctx); owner != nil {
		if err := owner.attachBinding(ctx, publicationNamespace{parent: parent.identity, name: name}, record.identity); err != nil {
			return err
		}
	}
	r.mu.Lock()
	entry, namePublication, cachedName := r.admitNameLocked(ctx, parent, name, record)
	inode := attr.GetInode()
	attrLifetime := time.Duration(0)
	var attrCoordinate publicationCoordinate
	cachedAttr := false
	if cachedName {
		attrLifetime, attrCoordinate, cachedAttr = r.admitAttrLocked(ctx, inode, record.identity)
	}
	r.mu.Unlock()
	if cachedName {
		publication.names = append(publication.names, namePublication)
	}
	if cachedAttr {
		publication.attrs = append(publication.attrs, replyAttrPublication{inode: inode, coordinate: attrCoordinate})
	}
	out.NodeId = record.id
	out.Generation = 1
	out.SetEntryTimeout(entry)
	out.SetAttrTimeout(attrLifetime)
	fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
	return nil
}

// publishAnonymousEntry publishes the inode/attribute half of TMPFILE without
// inventing a namespace binding. Even an attr lifetime of zero still updates
// kernel inode state after the reply wakes the requester, so SHARED results
// retain the same generic post-VFS receipt as every other state-bearing reply.
func (r *rawFileSystem) publishAnonymousEntry(ctx context.Context, out *fuse.EntryOut, record *inodeRecord, attr *authoritypb.Attr) error {
	publication := replyPublicationFromContext(ctx)
	if publication == nil || record == nil || attr == nil {
		return errors.New("fusev3: anonymous entry escaped its post-VFS reply-publication lifecycle")
	}
	publication.needsPostVFS = true
	r.mu.Lock()
	lifetime, coordinate, cached := r.admitAttrLocked(ctx, attr.GetInode(), record.identity)
	r.mu.Unlock()
	if cached {
		publication.attrs = append(publication.attrs, replyAttrPublication{inode: attr.GetInode(), coordinate: coordinate})
	}
	out.NodeId, out.Generation = record.id, 1
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(lifetime)
	fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
	return nil
}

func (r *rawFileSystem) settleNamePublicationLocked(publication replyNamePublication, successful bool) {
	if publication.reserved && r.pendingNames > 0 {
		r.pendingNames--
	}
	if successful {
		r.bindCachedNameLocked(publication.key, publication.stable, publication.record)
	}
	if r.publishingNames[publication.key]--; r.publishingNames[publication.key] <= 0 {
		delete(r.publishingNames, publication.key)
	}
	r.settleSourcePublicationLocked(publication.coordinate)
}

func (r *rawFileSystem) settleAttrPublicationLocked(publication replyAttrPublication) {
	if r.publishingInodes[publication.inode]--; r.publishingInodes[publication.inode] <= 0 {
		delete(r.publishingInodes, publication.inode)
	}
	r.settleSourcePublicationLocked(publication.coordinate)
}

func (r *rawFileSystem) settleReplyPublicationLocked(publication *replyPublication, successful bool) {
	for _, name := range publication.names {
		r.settleNamePublicationLocked(name, successful)
	}
	for _, attr := range publication.attrs {
		r.settleAttrPublicationLocked(attr)
	}
	if len(publication.names) != 0 || len(publication.attrs) != 0 {
		close(r.published)
		r.published = make(chan struct{})
	}
}

func (r *rawFileSystem) registerReplyPublication(unique uint64, publication *replyPublication) error {
	if unique == 0 || unique >= fuse.PFS_UNIQUE_PUBLISH || unique&1 != 0 {
		return fmt.Errorf("fusev3: a publication-capable FUSE callback has invalid request identity %#x", unique)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replyPublications[unique] != nil || r.publishAcks[unique] != nil {
		return fmt.Errorf("fusev3: FUSE request identity %d registered publication twice", unique)
	}
	publication.requestUnique = unique
	publication.originalDone = make(chan struct{})
	r.replyPublications[unique] = publication
	return nil
}

func (r *rawFileSystem) finishReplyPublicationRegistration(unique uint64, publication *replyPublication) {
	r.mu.Lock()
	if r.replyPublications[unique] != publication {
		r.mu.Unlock()
		r.mount.revoke(fmt.Errorf("fusev3: FUSE request identity %d lost its reserved reply-publication ownership", unique))
		return
	}
	if publication.empty() {
		delete(r.replyPublications, unique)
	}
	r.mu.Unlock()
}

// ReplyWriteOrdered joins cache/source-bearing replies to go-fuse's ordered
// writer boundary. A definite no-change source reply needs only the physical
// boundary; a state-bearing reply additionally opts into PFS_PUBLISH below.
func (r *rawFileSystem) ReplyWriteOrdered(unique uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.replyPublications[unique] != nil || r.publishAcks[unique] != nil
}

// ReplyPublishMarked freezes a state-bearing original kernel request identity
// immediately before go-fuse writes its response. Definite no-change replies
// deliberately return false: there is no kernel state to publish. The patched
// kernel echoes marked identities in PFS_PUBLISH after real VFS postprocessing.
func (r *rawFileSystem) ReplyPublishMarked(unique uint64, nodeid uint64, opcode uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.publishAcks[unique] != nil {
		return false
	}
	publication := r.replyPublications[unique]
	if publication == nil || publication.empty() || !publication.needsPostVFS {
		return false
	}
	if publication.marked || nodeid == 0 || opcode == 0 {
		return false
	}
	publication.nodeid, publication.opcode, publication.marked = nodeid, opcode, true
	return true
}

// ReplyWritten is called by the maintained go-fuse fork only after the real
// /dev/fuse write attempt and after its ordering mutex has been released.
func (r *rawFileSystem) ReplyWritten(unique uint64, status fuse.Status) {
	r.mu.Lock()
	if publication := r.publishAcks[unique]; publication != nil {
		delete(r.publishAcks, unique)
		if publication.publishUnique != unique || r.replyPublications[publication.requestUnique] != publication {
			r.mu.Unlock()
			if publication.source != nil {
				publication.source.revoke()
			}
			r.mount.revoke(fmt.Errorf("fusev3: PFS_PUBLISH reply %d lost retained ownership", unique))
			publication.consumeAuthorityResponse()
			return
		}
		delete(r.replyPublications, publication.requestUnique)
		r.settleReplyPublicationLocked(publication, status.Ok())
		r.mu.Unlock()
		if !status.Ok() {
			if publication.source != nil {
				publication.source.revoke()
			}
			if !r.mount.replyWriteLostAfterObservedUnmount(status) {
				r.mount.revoke(fmt.Errorf("fusev3: write PFS_PUBLISH acknowledgment %d: %v", unique, status))
			}
			publication.consumeAuthorityResponse()
			return
		}
		r.finishWriteTransactionPublication(publication, unique)
		if publication.source != nil {
			publication.source.release()
		}
		publication.consumeAuthorityResponse()
		return
	}
	publication := r.replyPublications[unique]
	if publication == nil || publication.originalWrote || publication.needsPostVFS && !publication.marked || !publication.needsPostVFS && publication.marked {
		r.mu.Unlock()
		r.mount.revoke(fmt.Errorf("fusev3: ordered FUSE reply %d lost its publication ownership", unique))
		return
	}
	publication.originalWrote = true
	publication.originalStatus = status
	close(publication.originalDone)
	if !status.Ok() {
		delete(r.replyPublications, unique)
		if publication.publishUnique != 0 && r.publishAcks[publication.publishUnique] == publication {
			delete(r.publishAcks, publication.publishUnique)
		}
		r.settleReplyPublicationLocked(publication, false)
		r.mu.Unlock()
		if publication.source != nil {
			publication.source.revoke()
		}
		if !r.mount.replyWriteLostAfterObservedUnmount(status) {
			r.mount.revoke(fmt.Errorf("fusev3: publish FUSE reply %d to the kernel: %v", unique, status))
		}
		publication.consumeAuthorityResponse()
		return
	}
	if !publication.needsPostVFS {
		delete(r.replyPublications, unique)
		r.settleReplyPublicationLocked(publication, true)
		r.mu.Unlock()
		r.finishWriteTransactionPublication(publication, unique)
		if publication.source != nil {
			publication.source.release()
		}
		publication.consumeAuthorityResponse()
		return
	}
	r.mu.Unlock()
}

func (r *rawFileSystem) finishWriteTransactionPublication(publication *replyPublication, unique uint64) {
	if publication == nil || publication.writeKernelTx == 0 {
		return
	}
	r.writeMu.Lock()
	tx := r.writeTx[publication.writeKernelTx]
	if tx == nil || tx.lease != publication.source || !tx.commitResolved {
		r.writeMu.Unlock()
		if publication.source != nil {
			publication.source.revoke()
		}
		r.mount.revoke(fmt.Errorf("fusev3: write publication %d lost transaction ownership", unique))
		return
	}
	delete(r.writeTx, publication.writeKernelTx)
	r.writeMu.Unlock()
	r.releaseHandleOperation(tx.handleRecord)
}

func (r *rawFileSystem) Init(server *fuse.Server) {
	armed := server != nil && server.ReplyWriteLifecycleArmed()
	r.mu.Lock()
	r.replyLifecycleArmed = armed
	r.mu.Unlock()
	if !armed {
		r.mount.revoked.Store(true)
		r.mount.recordFatalCause(errors.New("fusev3: strict cache publication requires the post-/dev/fuse-reply lifecycle"))
		if r.mount.cancel != nil {
			r.mount.cancel()
		}
	}
}

func (r *rawFileSystem) replyLifecycleReady() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.replyLifecycleArmed
}

// unbindSelf records that this mount's own namespace mutation removed a
// binding. The VFS drops the dentry from the same operation's reply, so there
// is nothing left for a later repair to invalidate.
func (r *rawFileSystem) unbindSelf(parent uint64, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropCachedNameLocked(nameKey{parent: parent, name: name})
}

// moveSelf follows a rename. The kernel moves the dentry, keeping the lifetime
// it was published with, so the binding is still cached -- under its new name.
func (r *rawFileSystem) moveSelf(oldParent *inodeRecord, oldName string, newParent *inodeRecord, newName string, exchange bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	from, to := nameKey{parent: oldParent.key.inode, name: oldName}, nameKey{parent: newParent.key.inode, name: newName}
	moved, replaced := r.cachedNames[from], r.cachedNames[to]
	r.dropCachedNameLocked(from)
	r.dropCachedNameLocked(to)
	r.bindCachedNameLocked(to, publicationNamespace{parent: newParent.identity, name: newName}, moved)
	if exchange {
		r.bindCachedNameLocked(from, publicationNamespace{parent: oldParent.identity, name: oldName}, replaced)
	}
}

func itemKey(item *authoritypb.Item) inodeKey {
	return inodeKey{inode: item.GetAttr().GetInode(), kind: item.GetAttr().GetKind()}
}

func validItem(item *authoritypb.Item) bool {
	return item != nil && item.GetAttr() != nil && item.GetAttr().GetInode() != 0 && len(item.GetToken()) != 0 && len(item.GetStableIdentity()) == len(publicationIdentity{})
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
	identity, ok := publicationIdentityFromItem(item)
	if !ok {
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
		if existing.identity != identity {
			r.mu.Unlock()
			r.mount.abortAsync()
			return nil, syscall.EIO
		}
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
	record := &inodeRecord{id: id, key: key, identity: identity, node: r.newNode(item), lookups: 1}
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
			r.dropCachedNameLocked(key)
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
			// A missing route name directly below an authority directory is a
			// negative result in that SHARED parent. The returned child class
			// selects positive LOOKUP publication, but ENOENT has no child attr,
			// so its class is necessarily the parent's. A miss below an already
			// LOCAL graft directory remains entirely local and unmarked.
			if status == fuse.Status(syscall.ENOENT) && !parent.graft {
				ctx, finish, lifecycle := r.mutationContext(header.Unique)
				if !lifecycle.Ok() {
					return lifecycle
				}
				publication := replyPublicationFromContext(ctx)
				if publication == nil {
					finish()
					r.mount.revoke(errors.New("fusev3: negative graft-root lookup escaped its post-VFS reply-publication lifecycle"))
					return fuse.Status(syscall.ENOTCONN)
				}
				publication.needsPostVFS = true
				finish()
			}
			return status
		}
	}
	ctx, finish, lifecycle := r.mutationContext(header.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	item, errno := parent.node.Lookup(ctx, name)
	if errno != 0 {
		// A strict shared ENOENT is still a kernel-visible publication:
		// d_lookup_done installs the negative lookup result after this response
		// wakes the requester, even with a zero lifetime. Retain its ordering
		// record until the generic post-VFS receipt. Other errors describe no
		// namespace fact and remain ordinary unmarked replies.
		out.SetEntryTimeout(0)
		if errno == syscall.ENOENT {
			publication := replyPublicationFromContext(ctx)
			if publication == nil {
				r.mount.revoke(errors.New("fusev3: negative lookup escaped its post-VFS reply-publication lifecycle"))
				return fuse.Status(syscall.ENOTCONN)
			}
			publication.needsPostVFS = true
		}
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	r.bindPath(record, parent, name)
	if err := r.publishEntry(ctx, out, parent, name, record, item.GetAttr()); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	return fuse.Status(record.node.Getattr(ctx, handle, out))
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	if errno := record.node.Setattr(ctx, handle, input, out); errno != 0 {
		return fuse.Status(errno)
	}
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	return fuse.OK
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
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
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return nil, lifecycle
	}
	defer finish()
	result, errno := handle.node.Read(ctx, handle, buf, int64(input.Offset))
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
	r.releaseHandleOperation(handleRecord)
	r.mount.revoke(errors.New("fusev3: kernel sent stock FUSE_WRITE for a SHARED handle under strict coherence"))
	return 0, fuse.Status(syscall.ENOTCONN)
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	return fuse.Status(handle.node.Flush(ctx, handle, input.LockOwner))
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	return fuse.Status(handle.node.Fsync(ctx, handle, input.FsyncFlags))
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return
	}
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
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
	if err := r.publishEntry(ctx, &out.EntryOut, parent, name, record, item.GetAttr()); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	out.Fh, out.OpenFlags = id, flags
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	return fuse.OK
}

func (r *rawFileSystem) Tmpfile(_ <-chan struct{}, input *fuse.CreateIn, name string, out *fuse.CreateOut) fuse.Status {
	if name != "/" {
		r.mount.revoke(fmt.Errorf("fusev3: TMPFILE carried noncanonical slash name %q", name))
		return fuse.Status(syscall.ENOTCONN)
	}
	parent := r.acquire(input.NodeId)
	if parent == nil {
		return fuse.Status(syscall.ESTALE)
	}
	defer r.release(parent)
	if parent.key.kind != authoritypb.Attr_DIRECTORY {
		return fuse.Status(syscall.ENOTDIR)
	}
	if parent.graft {
		path, ok := r.path(parent)
		if !ok {
			return fuse.Status(syscall.ESTALE)
		}
		fd, errno := r.grafts.Tmpfile(path, input.Flags, input.Mode)
		if errno != 0 {
			return fuse.Status(errno)
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return fuse.Status(errnoOfError(err))
		}
		record, errno := r.internGraft(parent, "", &st)
		if errno != 0 {
			_ = unix.Close(fd)
			return fuse.Status(errno)
		}
		handle := &graftHandle{fd: fd}
		id, ok := r.addHandle(record, &handleRecord{graftFile: handle})
		if !ok {
			_ = handle.close()
			r.Forget(record.id, 1)
			return fuse.EIO
		}
		r.mu.Lock()
		record.graftAnonymousFh, record.graftAnonymousRoot = id, r.grafts.Owner(path)
		r.mu.Unlock()
		r.publishGraftEntry(&out.EntryOut, record, &st)
		out.Fh, out.OpenFlags = id, fuse.FOPEN_KEEP_CACHE|fuse.FOPEN_PFS_LOCAL
		return fuse.OK
	}

	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	item, handle, flags, errno := parent.node.Tmpfile(ctx, input.Flags, input.Mode)
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
	if err := r.publishAnonymousEntry(ctx, &out.EntryOut, record, item.GetAttr()); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	item, errno := parent.node.Mknod(ctx, name, input.Mode, input.Rdev)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	r.bindPath(record, parent, name)
	if err := r.publishEntry(ctx, out, parent, name, record, item.GetAttr()); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	item, errno := parent.node.Mkdir(ctx, name, input.Mode)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	r.bindPath(record, parent, name)
	if err := r.publishEntry(ctx, out, parent, name, record, item.GetAttr()); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
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
	ctx, finish, lifecycle := r.mutationContext(header.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	var errno syscall.Errno
	if directory {
		errno = parent.node.Rmdir(ctx, name)
	} else {
		errno = parent.node.Unlink(ctx, name)
	}
	if errno == 0 {
		// The VFS drops the dentry from this operation's own reply, under the
		// parent's i_rwsem. The binding is gone from the kernel, so this
		// frontend no longer owes a repair for it; its source-publication gate
		// already retains the exact post-VFS boundary for peers.
		r.unbindSelf(parent.key.inode, name)
		r.unbindPath(parent, name)
		if err := completeSourcePublication(ctx); err != nil {
			r.mount.revoke(err)
			return fuse.Status(syscall.ENOTCONN)
		}
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	oldRemains, errno := oldParent.node.Rename(ctx, oldName, newParent.node, newName, input.Flags)
	if errno == 0 {
		// The route set is a pure function of the declaration, so a rename that
		// was allowed to happen changed no routing and there is nothing to
		// remap. What does change is where the moved directory IS, and every
		// later routing decision under it is made from that.
		exchange := input.Flags&renameExchange != 0
		if exchange || !oldRemains {
			r.rebindRenamed(oldParent, oldName, newParent, newName, exchange)
		}
		// d_move carries the dentry, and the lifetime it was published with, to
		// the new name. The binding is still cached; it is cached somewhere
		// else, and the registry has to say so or a later remote change to the
		// new name would go unrepaired.
		if exchange || !oldRemains {
			r.moveSelf(oldParent, oldName, newParent, newName, exchange)
		}
		if err := completeSourcePublication(ctx); err != nil {
			r.mount.revoke(err)
			return fuse.Status(syscall.ENOTCONN)
		}
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
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
	if err := r.publishEntry(ctx, out, newParent, name, source, item.GetAttr()); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
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
	ctx, finish, lifecycle := r.mutationContext(header.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	item, errno := parent.node.Symlink(ctx, pointedTo, linkName)
	if errno != 0 {
		return fuse.Status(errno)
	}
	record, errno := r.intern(ctx, item)
	if errno != 0 {
		return fuse.Status(errno)
	}
	r.bindPath(record, parent, linkName)
	if err := r.publishEntry(ctx, out, parent, linkName, record, item.GetAttr()); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
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
	ctx, finish, lifecycle := r.mutationContext(header.Unique)
	if !lifecycle.Ok() {
		return nil, lifecycle
	}
	defer finish()
	value, errno := record.node.Readlink(ctx)
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
	ctx, finish, lifecycle := r.mutationContext(header.Unique)
	if !lifecycle.Ok() {
		return 0, lifecycle
	}
	defer finish()
	size, errno := record.node.Getxattr(ctx, name, dest)
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
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
	ctx, finish, lifecycle := r.mutationContext(header.Unique)
	if !lifecycle.Ok() {
		return 0, lifecycle
	}
	defer finish()
	size, errno := record.node.Listxattr(ctx, dest)
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
	ctx, finish, lifecycle := r.mutationContext(header.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	if errno := record.node.Removexattr(ctx, name); errno != 0 {
		return fuse.Status(errno)
	}
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	return fuse.OK
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
		out.Fh, out.OpenFlags = id, fuse.FOPEN_PFS_LOCAL
		return fuse.OK
	}
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	return fuse.Status(handle.Fsyncdir(ctx, input.FsyncFlags))
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return
	}
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
	ctx, finish, lifecycle := r.mutationContext(header.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	return fuse.Status(record.node.Statfs(ctx, out))
}

// SyncFS creates one authority replay mutation which is ordered after every
// earlier accepted mutation and durably flushes the volume. It deliberately
// carries no source-publication gate and requests no post-VFS PUBLISH receipt:
// syncfs changes no local inode, dentry, or attribute state.
func (r *rawFileSystem) SyncFS(_ <-chan struct{}, input *fuse.SyncFSIn) fuse.Status {
	if input == nil || input.Padding != 0 || input.NodeId != fuse.FUSE_ROOT_ID {
		r.mount.revoke(errors.New("fusev3: malformed FUSE_SYNCFS request"))
		return fuse.Status(syscall.ENOTCONN)
	}
	root := r.acquire(fuse.FUSE_ROOT_ID)
	if root == nil || root.graft {
		if root != nil {
			r.release(root)
		}
		r.mount.revoke(errors.New("fusev3: FUSE_SYNCFS lost the authority root"))
		return fuse.Status(syscall.ENOTCONN)
	}
	defer r.release(root)
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	response, errno := root.node.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_SyncFs{SyncFs: &authoritypb.SyncFSRequest{}}})
	if errno != 0 {
		return fuse.Status(errno)
	}
	if response.GetSyncFs() == nil {
		r.mount.revoke(errors.New("fusev3: authority returned malformed SyncFS success"))
		return fuse.Status(syscall.ENOTCONN)
	}
	return fuse.OK
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	return fuse.Status(record.node.Getlk(ctx, input.Owner, &input.Lk, input.LkFlags, &out.Lk))
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
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
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
func (r *rawFileSystem) publishAttr(ctx context.Context, out *fuse.AttrOut, identity publicationIdentity, attr *authoritypb.Attr) {
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		r.mount.revoke(errors.New("fusev3: attribute result escaped its post-VFS reply-publication lifecycle"))
		fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
		out.SetTimeout(0)
		return
	}
	// Attribute postprocessing updates the inode even when its validity is zero;
	// retain the reply until that update is on the far side of PFS_PUBLISH.
	publication.needsPostVFS = true
	inode := attr.GetInode()
	r.mu.Lock()
	lifetime, coordinate, cached := r.admitAttrLocked(ctx, inode, identity)
	r.mu.Unlock()
	fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
	out.SetTimeout(lifetime)
	if cached {
		publication.attrs = append(publication.attrs, replyAttrPublication{inode: inode, coordinate: coordinate})
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
	// Failure discovery and teardown ownership are separate. Several terminal
	// edges can race (for example SessionDone can arrive while coherence already
	// holds a route-specific cause). The first edge owns cancellation and
	// teardown, but every edge owns diagnostic truth and must remain observable.
	m.recordFatalCause(err)
	m.scheduleAbort()
}

// replyWriteLostAfterObservedUnmount distinguishes an expected terminal
// /dev/fuse reply race from a live-mount publication failure. ENOENT/ENODEV is
// clean only after the exact recorded mount identity is already absent from
// mountinfo. A lazy unmount may still have retained file references at that
// instant, so the frontend closes admission and aborts the remaining FUSE
// connection; clean Detach is still delayed until that connection actually
// terminates. Every other write error, and the same errno while the mount is
// installed, remains fatal.
func (m *Mount) replyWriteLostAfterObservedUnmount(status fuse.Status) bool {
	if m == nil || status != fuse.ENOENT && status != fuse.Status(syscall.ENODEV) || m.kernelMount.point == "" {
		return false
	}
	if _, err := m.kernelMount.absent(); err != nil {
		return false
	}
	m.revoked.Store(true)
	m.scheduleAbort()
	return true
}

func (m *Mount) scheduleAbort() {
	m.abort.Do(func() {
		if m.cancel != nil {
			m.cancel()
		}
		go func() {
			// A strict mount owes the volume more than a tidy exit: it has
			// published names and attributes that nothing can correct any more,
			// so it withdraws them and makes itself unreachable before it even
			// tries an ordinary unmount.
			outcome := m.withdrawKernelState()
			// Report first. Everything below can block — the ordinary unmount,
			// the serving-connection wait inside Close, the authority round trip
			// — and a revocation the supervisor never hears about is exactly the
			// hole this path closes.
			m.reportRevocation(outcome)
			// The ordinary unmount is attempted only when the escalation ladder
			// could NOT prove this mount gone. After a proven withdrawal it is
			// pure noise: the mountpoint is already detached, so it would fail
			// on every single revocation and poison the recorded verdict with a
			// duplicate. When the ladder failed it is the last thing left to
			// try, and its failure is diagnostic truth worth recording.
			if m.server != nil && !(outcome.installed && outcome.withdrawn) {
				if err := m.Unmount(); err != nil {
					m.recordFatalCause(fmt.Errorf(
						"fusev3: revoked mount could not be withdrawn from the kernel and the ordinary unmount also failed: %w", err))
				}
			}
			// Close runs the clean-detach absence proof (see Mount.detach). A
			// proven withdrawal is what makes that proof obtainable, so a
			// successful escalation discharges the authority's durable strict
			// membership automatically instead of leaving it for an operator.
			_ = m.Close()
		}()
	})
}

func (m *Mount) recordFatalCause(err error) {
	if err == nil {
		return
	}
	m.fatalMu.Lock()
	m.fatalErr = errors.Join(m.fatalErr, err)
	m.fatalMu.Unlock()
}
