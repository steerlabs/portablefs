//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"encoding/binary"
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
	"google.golang.org/protobuf/proto"
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
	key    nameKey
	stable publicationNamespace
	record *inodeRecord
	// negative marks a published absence. It carries no record, and it settles
	// into the negative registry rather than the binding registry.
	negative      bool
	negativeState *negativeNamePublication
	coordinate    publicationCoordinate
	reserved      bool
	reservation   *cacheInstallReservation
}

// negativeNamePublication is the mutable part of an admitted absence. A
// materializing mutation marks it superseded before either merged receipt may
// arrive, so a late receipt cannot put the old absence back in the registry.
// All fields are protected by rawFileSystem.mu.
type negativeNamePublication struct {
	owner      *rawFileSystem
	reply      *replyPublication
	coordinate publicationCoordinate
	superseded bool
}

type replyAttrPublication struct {
	inode       uint64
	identity    publicationIdentity
	record      *inodeRecord
	coordinate  publicationCoordinate
	reservation *cacheInstallReservation
	reserved    bool
}

type replyDirPlusPublication struct {
	entry           *fuse.EntryOut
	nameReservation *cacheInstallReservation
	attrReservation *cacheInstallReservation
}

type stagedDirPlusLookup struct {
	record *inodeRecord
	parent *inodeRecord
	name   string
}

// dirPlusLookupTransaction owns every provisional resource used to construct
// one READDIRPLUS page. The authority capabilities and daemon lookup counts
// exist before the kernel can own them, so the physical reply write is the
// single commit edge for the whole collection.
type dirPlusLookupTransaction struct {
	cursor       *dirPlusCursorTransaction
	handleRecord *handleRecord
	lookups      []stagedDirPlusLookup
	ready        bool
	settled      bool
}

type cacheReservationState uint8

const (
	cacheReservationPending cacheReservationState = iota + 1
	cacheReservationFinalized
)

type cacheInstallReservation struct {
	publication      *replyPublication
	coordinate       publicationCoordinate
	snapshot         uint64
	state            cacheReservationState
	revoked          bool
	capacityReserved bool
}

// replyDataPublication is one OPEN reply's declaration that this kernel may
// retain the inode's file data. It carries the record as well as the inode
// number because the withdrawal it obliges is addressed by kernel NodeID.
type replyDataPublication struct {
	inode      uint64
	record     *inodeRecord
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
	data          []replyDataPublication
	source        *sourcePublicationLease
	writeKernelTx uint64
	writeHandle   *handleRecord
	// responseConsumptions prevent authority transport EOF from exposing the
	// session terminal edge until every authority response contributing to this
	// kernel result is either physically published through PFS_PUBLISH or
	// fail-closed locally. One FUSE callback may require several bounded read or
	// staged-write RPCs, so this is deliberately a collection rather than one
	// token.
	responseConsumptions []authorityrpc.ResponseConsumption
	postState            *authoritypb.PostState
	expectedPostState    map[publicationIdentity]uint32
	cacheStamp           *fuse.PFSCacheStamp
	droppedAttrs         map[publicationIdentity]bool
	dirPlus              []replyDirPlusPublication
	dirPlusLookups       *dirPlusLookupTransaction
	snapshotSequence     uint64
	payloadError         error

	// Generic post-VFS publication receipt state, protected by
	// rawFileSystem.mu. The original response write signals originalDone and
	// releases bounded capacity; sequence-addressable cache reservations and
	// source ownership remain through the physical PFS_PUBLISH acknowledgment.
	owner          *rawFileSystem
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
	return p == nil || len(p.names) == 0 && len(p.attrs) == 0 && len(p.data) == 0 && p.source == nil &&
		p.writeKernelTx == 0 && p.writeHandle == nil && len(p.responseConsumptions) == 0 && !p.needsPostVFS &&
		p.postState == nil && p.cacheStamp == nil && p.snapshotSequence == 0 && p.payloadError == nil && p.dirPlusLookups == nil
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
	attrCapacity int
	// negativeCapacity is the part of nameCapacity that may be spent on cached
	// absences. See negativeNameShare for why absences need their own bound
	// inside the declared total rather than competing freely with bindings.
	negativeCapacity int

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
	// cachedNegatives is the same registry for the other half of the namespace:
	// the (parent inode, name) coordinates this frontend published to its
	// kernel as cacheable absences. It is a set rather than a map to a record
	// because an absence names nothing -- which is also why it can never be
	// reclaimed by FORGET, and must therefore leave only through a repair or
	// through self-revocation.
	cachedNegatives map[nameKey]struct{}
	// cachedAttrs is the exact set of inode attributes this daemon has allowed
	// its kernel to retain. It gives attribute candidates the same bounded,
	// repairable accounting as positive and negative names.
	cachedAttrs map[publicationIdentity]*inodeRecord
	// cachedData is the exact set of authority inodes whose file data this
	// frontend has told its kernel it may keep. It is keyed by the
	// coordination inode number a VisibilityTarget carries, and it is the
	// third kernel cache this mount owes a withdrawal for.
	//
	// Unlike a name or an attribute, retained data is not something the kernel
	// asks about again: with FOPEN_KEEP_CACHE a read of a resident folio is
	// answered inside the kernel with no request this frontend could refuse.
	// So this registry exists for exactly one purpose -- self-revocation has to
	// be able to name every inode whose pages must be dropped before a fenced
	// mount is left running. Entries are added when an OPEN reply publishes
	// cacheability and removed only by FORGET, because a live open description
	// can refault at any moment after a repair.
	cachedData map[uint64]*inodeRecord
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
	pendingNames     int
	// pendingNegatives is the same reservation counter for absences. It is
	// separate so a burst of probes cannot silently consume the reservations
	// that bindings were counted against, and vice versa.
	pendingNegatives    int
	pendingAttrs        int
	published           chan struct{}
	replyPublications   map[uint64]*replyPublication
	publishAcks         map[uint64]*replyPublication
	replyLifecycleArmed bool

	// Source-owned gates close publication before the mutation gets a replay
	// identity or can put bytes on the wire. Unlike peer visibility state, these
	// maps are keyed only by stable filesystem identities and exact names.
	sourceHolds                 map[publicationCoordinate]*sourcePublicationLease
	sourcePublishing            map[publicationCoordinate]int
	publishingNegativeNames     map[publicationCoordinate]map[*negativeNamePublication]struct{}
	peerHolds                   map[publicationCoordinate]int
	sourceUnresolvedAttributes  map[*sourcePublicationLease]int
	sourceUnresolvedData        map[*sourcePublicationLease]int
	peerHeldPhase               []publicationCoordinate
	sourceChanged               chan struct{}
	completedVisibilitySequence uint64
	lastPeerRepairSequence      map[publicationCoordinate]uint64
	repairingCoordinates        map[publicationCoordinate]bool
	cacheReservations           map[publicationCoordinate]map[*cacheInstallReservation]struct{}

	// identityDevice pins the one filesystem a volume is, as the authority's
	// explicit major<<32|minor device fact. The kernel inode number alone keys
	// this frontend's tables, so a second device would silently alias two
	// objects.
	identityDevice      uint64
	identityDeviceKnown bool
}

var _ fuse.RawFileSystem = (*rawFileSystem)(nil)
var _ fuse.ReplyWriteLifecycle = (*rawFileSystem)(nil)
var _ fuse.ReplyPayloadPreparer = (*rawFileSystem)(nil)

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
		attrCapacity:   mount.nameCapacity,
		// A declared capacity too small to divide still admits one absence:
		// refusing every negative entry would be a silent behaviour change for
		// a mount that declared a tiny cache, not a bound anything relies on.
		negativeCapacity: max(mount.nameCapacity/negativeNameShare, 1),
		grafts:           mount.grafts,
		backing:          mount.backing,
		nextNodeID:       fuse.FUSE_ROOT_ID + 1,
		nodesByID:        map[uint64]*inodeRecord{fuse.FUSE_ROOT_ID: record},
		nodesByKey:       map[inodeKey]*inodeRecord{key: record},
		graftsByKey:      make(map[inodeKey]*inodeRecord),
		namedRecords:     make(map[nameKey]*inodeRecord),
		nextHandle:       1,
		handles:          make(map[uint64]*handleRecord),

		cachedNames:                make(map[nameKey]*inodeRecord),
		cachedStableNames:          make(map[publicationNamespace]*inodeRecord),
		cachedNameStable:           make(map[nameKey]publicationNamespace),
		cachedNegatives:            make(map[nameKey]struct{}),
		cachedAttrs:                make(map[publicationIdentity]*inodeRecord),
		cachedData:                 make(map[uint64]*inodeRecord),
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
		publishingNegativeNames:    make(map[publicationCoordinate]map[*negativeNamePublication]struct{}),
		peerHolds:                  make(map[publicationCoordinate]int),
		sourceUnresolvedAttributes: make(map[*sourcePublicationLease]int),
		sourceUnresolvedData:       make(map[*sourcePublicationLease]int),
		sourceChanged:              make(chan struct{}),
		lastPeerRepairSequence:     make(map[publicationCoordinate]uint64),
		repairingCoordinates:       make(map[publicationCoordinate]bool),
		cacheReservations:          make(map[publicationCoordinate]map[*cacheInstallReservation]struct{}),
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

func (r *rawFileSystem) dropCachedNegativeLocked(key nameKey) {
	delete(r.cachedNegatives, key)
}

// supersedeNegativeNameLocked records the stronger fact installed by this
// mount's own materializing mutation. The registry drop covers an already
// settled absence; marking admitted absences covers a lookup receipt which the
// kernel deliberately deferred into the enclosing mutation scope.
func (r *rawFileSystem) supersedeNegativeNameLocked(key nameKey, coordinate publicationCoordinate) {
	r.dropCachedNegativeLocked(key)
	for publication := range r.publishingNegativeNames[coordinate] {
		if publication.owner == r {
			publication.superseded = true
		}
	}
}

// bindCachedNegativeLocked records one published absence. It withdraws any
// binding recorded under the same name first: the kernel holds one dentry per
// name, so the absence it has just installed replaced whatever was there, and a
// binding registration the kernel no longer holds would later address a
// NotifyDelete at a child that is not under that name -- which the strict
// kernel refuses as protocol corruption rather than ignoring.
func (r *rawFileSystem) bindCachedNegativeLocked(key nameKey) {
	r.dropCachedNameLocked(key)
	r.cachedNegatives[key] = struct{}{}
}

func (r *rawFileSystem) bindCachedNameLocked(key nameKey, stable publicationNamespace, record *inodeRecord) {
	// The mirror of bindCachedNegativeLocked: a binding the kernel has
	// installed replaces the absence this mount had published for the name.
	r.supersedeNegativeNameLocked(key, publicationCoordinate{kind: publicationNamespaceName, parent: stable.parent, name: stable.name})
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
func cacheCandidateSnapshot(publication *replyPublication) uint64 {
	if publication == nil {
		return 0
	}
	if publication.postState != nil {
		return publication.postState.GetSnapshotSequence()
	}
	if publication.cacheStamp != nil {
		return publication.cacheStamp.SnapshotSequence
	}
	if publication.snapshotSequence != 0 {
		return publication.snapshotSequence
	}
	return 0
}

func (r *rawFileSystem) reserveCacheCandidateLocked(publication *replyPublication, coordinate publicationCoordinate) (*cacheInstallReservation, bool) {
	snapshot := cacheCandidateSnapshot(publication)
	if snapshot == 0 || r.repairingCoordinates[coordinate] || snapshot <= r.lastPeerRepairSequence[coordinate] {
		return nil, false
	}
	reservation := &cacheInstallReservation{
		publication: publication, coordinate: coordinate, snapshot: snapshot,
		state: cacheReservationPending,
	}
	if r.cacheReservations[coordinate] == nil {
		r.cacheReservations[coordinate] = make(map[*cacheInstallReservation]struct{})
	}
	r.cacheReservations[coordinate][reservation] = struct{}{}
	return reservation, true
}

func (r *rawFileSystem) admitNameLocked(ctx context.Context, parent *inodeRecord, name string, record *inodeRecord) (time.Duration, replyNamePublication, bool) {
	key := nameKey{parent: parent.key.inode, name: name}
	stable := publicationNamespace{parent: parent.identity, name: name}
	coordinate := publicationCoordinate{kind: publicationNamespaceName, parent: stable.parent, name: name}
	publication := replyNamePublication{key: key, stable: stable, record: record, coordinate: coordinate}
	if record == nil {
		return 0, publication, false
	}
	// The kernel installs this binding from the same reply, replacing any
	// absence this mount published for the name. That transition happens
	// whether or not the binding itself turns out to be cacheable, so the
	// negative registration is withdrawn here rather than at settle. It has to
	// be: when the mutation that filled the name is this mount's own, the
	// authority deliberately delivers this mount no repair phase for it, so
	// this is the only moment at which that absence can be taken back.
	r.supersedeNegativeNameLocked(key, coordinate)
	if _, held := r.heldNames[key]; held {
		return 0, publication, false
	}
	if _, held := r.heldInodes[record.key.inode]; held {
		return 0, publication, false
	}
	if !r.sourcePublicationAllowedLocked(coordinate, sourceLeaseFromContext(ctx)) {
		return 0, publication, false
	}
	reservation, admitted := r.reserveCacheCandidateLocked(replyPublicationFromContext(ctx), coordinate)
	if !admitted {
		return 0, publication, false
	}
	_, already := r.cachedNames[key]
	if !already && r.cachedNameTotalLocked() >= r.nameCapacity {
		// The declared capacity is a promise about how much state this mount
		// can withdraw, so it is a hard bound. Beyond it the frontend keeps
		// answering with a zero lifetime.
		r.removeCacheReservationLocked(reservation)
		return 0, publication, false
	}
	publication.reservation = reservation
	publication.reserved = !already
	if publication.reserved {
		r.pendingNames++
	}
	r.publishingNames[key]++
	r.admitSourcePublicationLocked(coordinate)
	return r.entryTimeout, publication, true
}

// cachedNameTotalLocked is the whole name-cache footprint this mount would have
// to withdraw right now: every recorded answer plus every reservation an
// in-flight reply already holds. Bindings and absences are summed because the
// declared capacity is one promise about kernel state, not two.
func (r *rawFileSystem) cachedNameTotalLocked() int {
	return len(r.cachedNames) + len(r.cachedNegatives) + r.pendingNames + r.pendingNegatives
}

// admitNegativeNameLocked decides the lifetime one proven absence is published
// with, and records it when it is cacheable. It is deliberately the same
// decision as admitNameLocked -- the same PREPARE-time held cut, the same
// source publication gate, the same declared capacity -- because an absence
// this kernel serves from cache is exactly as much of a repair obligation as a
// binding it serves from cache. There is no held-inode check because an absence
// names no inode.
func (r *rawFileSystem) admitNegativeNameLocked(ctx context.Context, parent *inodeRecord, name string) (time.Duration, replyNamePublication, bool) {
	key := nameKey{parent: parent.key.inode, name: name}
	stable := publicationNamespace{parent: parent.identity, name: name}
	coordinate := publicationCoordinate{kind: publicationNamespaceName, parent: stable.parent, name: name}
	publication := replyNamePublication{key: key, stable: stable, negative: true, coordinate: coordinate}
	if _, held := r.heldNames[key]; held {
		return 0, publication, false
	}
	if !r.sourcePublicationAllowedLocked(coordinate, sourceLeaseFromContext(ctx)) {
		return 0, publication, false
	}
	reservation, admitted := r.reserveCacheCandidateLocked(replyPublicationFromContext(ctx), coordinate)
	if !admitted {
		return 0, publication, false
	}
	_, already := r.cachedNegatives[key]
	if !already {
		if len(r.cachedNegatives)+r.pendingNegatives >= r.negativeCapacity ||
			r.cachedNameTotalLocked() >= r.nameCapacity {
			r.removeCacheReservationLocked(reservation)
			return 0, publication, false
		}
		publication.reserved = true
		r.pendingNegatives++
	}
	publication.reservation = reservation
	r.publishingNames[key]++
	r.admitSourcePublicationLocked(coordinate)
	state := &negativeNamePublication{owner: r, reply: replyPublicationFromContext(ctx), coordinate: coordinate}
	publication.negativeState = state
	if r.publishingNegativeNames[coordinate] == nil {
		r.publishingNegativeNames[coordinate] = make(map[*negativeNamePublication]struct{})
	}
	r.publishingNegativeNames[coordinate][state] = struct{}{}
	return r.entryTimeout, publication, true
}

// cachedDataHolds reports whether this mount currently owes a page-cache
// withdrawal for one coordination inode. It exists so tests can assert the
// obligation directly rather than inferring it from a notification the
// withdrawal happens to emit.
func (r *rawFileSystem) cachedDataHolds(inode uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cachedData[inode] != nil
}

// admitDataLocked decides whether one OPEN reply may declare this inode's file
// data retainable, and is the exact peer of admitNameLocked/admitAttrLocked for
// the third kernel cache a strict mount owns.
//
// It differs from them in the one way that matters: a name or an attribute has
// an uncacheable form -- publish it with a zero lifetime and nothing is left
// behind -- while the open flag pair is exact, so "cacheable" is the only reply
// this frontend is allowed to give. Refusal therefore cannot degrade the reply;
// it can only mean "not yet", and awaitDataAdmission parks the callback until
// the cut reopens. That is safe precisely where blocking a READ would not be:
// OPEN holds no folio lock and no mapping->invalidate_lock, so it can never be
// the thing a COMPLETE repair is waiting behind.
//
// heldInodes is the PREPARE-time cut, and DATA dominates ATTRIBUTES for the
// same kernel inode in translate(), so a DATA target closes this coordinate
// through exactly the same key an attribute target does. publishingInodes is
// what drainPublications waits out, so an OPEN admitted before the cut closed
// still reaches the kernel before PREPARE is acknowledged.
func (r *rawFileSystem) admitDataLocked(ctx context.Context, inode uint64, identity publicationIdentity) (publicationCoordinate, bool) {
	coordinate := publicationCoordinate{kind: publicationItemData, item: identity}
	if _, held := r.heldInodes[inode]; held {
		return coordinate, false
	}
	if !r.sourcePublicationAllowedLocked(coordinate, sourceLeaseFromContext(ctx)) {
		return coordinate, false
	}
	r.publishingInodes[inode]++
	r.admitSourcePublicationLocked(coordinate)
	return coordinate, true
}

// awaitDataAdmission blocks until this inode's cached-data coordinate is open,
// then admits it. The wait ends when a peer COMPLETE releases the held cut or
// an overlapping source lease releases; both signal sourceChanged under r.mu.
//
// This cannot deadlock against the repair it is waiting for. A peer COMPLETE's
// reverse notifications take mapping->invalidate_lock and per-folio locks; this
// callback holds neither, and it is not counted in publishingInodes until the
// moment it is admitted, so PREPARE's drain never waits on a parked OPEN.
func (r *rawFileSystem) awaitDataAdmission(ctx context.Context, inode uint64, identity publicationIdentity) (publicationCoordinate, error) {
	for {
		r.mu.Lock()
		coordinate, admitted := r.admitDataLocked(ctx, inode, identity)
		if admitted {
			r.mu.Unlock()
			return coordinate, nil
		}
		changed := r.sourceChanged
		r.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return coordinate, fmt.Errorf("fusev3: wait to publish retainable file data for inode %d: %w", inode, ctx.Err())
		}
	}
}

func (r *rawFileSystem) admitAttrLocked(ctx context.Context, inode uint64, identity publicationIdentity) (time.Duration, publicationCoordinate, *cacheInstallReservation, bool) {
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: identity}
	if _, held := r.heldInodes[inode]; held {
		return 0, coordinate, nil, false
	}
	if !r.sourcePublicationAllowedLocked(coordinate, sourceLeaseFromContext(ctx)) {
		return 0, coordinate, nil, false
	}
	reservation, admitted := r.reserveCacheCandidateLocked(replyPublicationFromContext(ctx), coordinate)
	if !admitted {
		return 0, coordinate, nil, false
	}
	if _, already := r.cachedAttrs[identity]; !already {
		if len(r.cachedAttrs)+r.pendingAttrs >= r.attrCapacity {
			r.removeCacheReservationLocked(reservation)
			return 0, coordinate, nil, false
		}
		reservation.capacityReserved = true
		r.pendingAttrs++
	}
	r.publishingInodes[inode]++
	r.admitSourcePublicationLocked(coordinate)
	return r.attrTimeout, coordinate, reservation, true
}

func (r *rawFileSystem) removeCacheReservationLocked(reservation *cacheInstallReservation) {
	if reservation == nil {
		return
	}
	set := r.cacheReservations[reservation.coordinate]
	delete(set, reservation)
	if len(set) == 0 {
		delete(r.cacheReservations, reservation.coordinate)
	}
}

func (r *rawFileSystem) releaseReplyReservationsLocked(publication *replyPublication) {
	for coordinate, set := range r.cacheReservations {
		for reservation := range set {
			if reservation.publication == publication {
				delete(set, reservation)
			}
		}
		if len(set) == 0 {
			delete(r.cacheReservations, coordinate)
		}
	}
}

// releaseReplyCapacityLocked releases only the bounded admission charge. The
// reservation itself is a separate ordering object and remains in
// cacheReservations until receipt, failure, or teardown removes revocability.
func (r *rawFileSystem) releaseReplyCapacityLocked(publication *replyPublication) {
	if publication == nil {
		return
	}
	for index := range publication.names {
		candidate := &publication.names[index]
		if !candidate.reserved {
			continue
		}
		if candidate.negative {
			if r.pendingNegatives > 0 {
				r.pendingNegatives--
			}
		} else if r.pendingNames > 0 {
			r.pendingNames--
		}
		candidate.reserved = false
	}
	for _, candidate := range publication.attrs {
		reservation := candidate.reservation
		if reservation == nil || !reservation.capacityReserved {
			continue
		}
		if r.pendingAttrs > 0 {
			r.pendingAttrs--
		}
		reservation.capacityReserved = false
	}
}

// terminalizeReplyCacheOwnership is the teardown edge for the two independent
// candidate resources. It is idempotent with a concurrent physical write or
// receipt: mutable capacity flags and map membership are each consumed under
// r.mu exactly once.
func (r *rawFileSystem) terminalizeReplyCacheOwnership() {
	r.mu.Lock()
	seen := make(map[*replyPublication]struct{}, len(r.replyPublications)+len(r.publishAcks))
	for _, publication := range r.replyPublications {
		seen[publication] = struct{}{}
	}
	for _, publication := range r.publishAcks {
		seen[publication] = struct{}{}
	}
	for publication := range seen {
		r.releaseReplyCapacityLocked(publication)
		r.releaseReplyReservationsLocked(publication)
	}
	r.signalSourceChangedLocked()
	r.mu.Unlock()
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
	if cachedName && publication.postState == nil {
		var attrReservation *cacheInstallReservation
		attrLifetime, attrCoordinate, attrReservation, cachedAttr = r.admitAttrLocked(ctx, inode, record.identity)
		if cachedAttr {
			publication.attrs = append(publication.attrs, replyAttrPublication{inode: inode, identity: record.identity, record: record, coordinate: attrCoordinate, reservation: attrReservation})
		}
	}
	r.mu.Unlock()
	if cachedName {
		publication.names = append(publication.names, namePublication)
	}
	out.NodeId = record.id
	out.Generation = 1
	out.SetEntryTimeout(entry)
	out.SetAttrTimeout(attrLifetime)
	fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
	return nil
}

type dirPlusCandidate struct {
	entry  *fuse.EntryOut
	dirent *authoritypb.Dirent
	item   *authoritypb.Item
	record *inodeRecord
}

type dirPlusLookupCompletion struct {
	tx       *dirPlusLookupTransaction
	commit   bool
	reclaims [][]byte
	corrupt  bool
}

func (r *rawFileSystem) attachDirPlusLookupTransaction(ctx context.Context, cursor *dirPlusCursorTransaction, handle *handleRecord) error {
	publication := replyPublicationFromContext(ctx)
	if publication == nil || cursor == nil || handle == nil {
		return errors.New("fusev3: READDIRPLUS lookup transaction escaped its reply lifecycle")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replyPublications[publication.requestUnique] != publication || publication.dirPlusLookups != nil {
		return errors.New("fusev3: READDIRPLUS lookup transaction lost its reply ownership")
	}
	publication.dirPlusLookups = &dirPlusLookupTransaction{cursor: cursor, handleRecord: handle}
	return nil
}

func (r *rawFileSystem) stageDirPlusLookup(ctx context.Context, record, parent *inodeRecord, name string) error {
	publication := replyPublicationFromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if publication == nil || r.replyPublications[publication.requestUnique] != publication ||
		publication.dirPlusLookups == nil || publication.dirPlusLookups.settled || publication.dirPlusLookups.ready ||
		record == nil || record.reclaimed || r.nodesByID[record.id] != record || record.lookups == 0 || parent == nil {
		return errors.New("fusev3: READDIRPLUS lookup could not join its page transaction")
	}
	publication.dirPlusLookups.lookups = append(publication.dirPlusLookups.lookups, stagedDirPlusLookup{
		record: record, parent: parent, name: name,
	})
	return nil
}

func (r *rawFileSystem) commitDirPlusLookupTransaction(ctx context.Context) error {
	publication := replyPublicationFromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if publication == nil || r.replyPublications[publication.requestUnique] != publication ||
		publication.dirPlusLookups == nil || publication.dirPlusLookups.settled || publication.dirPlusLookups.ready {
		return errors.New("fusev3: READDIRPLUS page could not reach its physical-write commit edge")
	}
	publication.dirPlusLookups.ready = true
	return nil
}

// settleDirPlusLookupTransactionLocked transfers the staged lookup references
// to the kernel only when a complete successful page reached /dev/fuse. Cache
// publication still waits for PFS_PUBLISH; lookup and path ownership do not,
// because the kernel owns those references as soon as it accepts the page.
func (r *rawFileSystem) settleDirPlusLookupTransactionLocked(publication *replyPublication, physicalWrite bool) dirPlusLookupCompletion {
	if publication == nil || publication.dirPlusLookups == nil || publication.dirPlusLookups.settled {
		return dirPlusLookupCompletion{}
	}
	tx := publication.dirPlusLookups
	tx.settled = true
	commit := physicalWrite && tx.ready
	completion := dirPlusLookupCompletion{tx: tx, commit: commit}
	if commit {
		for _, lookup := range tx.lookups {
			r.bindPathLocked(lookup.record, lookup.parent, lookup.name)
		}
		return completion
	}
	for _, lookup := range tx.lookups {
		record := lookup.record
		if record == nil || record.root || record.reclaimed || r.nodesByID[record.id] != record || record.lookups == 0 {
			completion.corrupt = true
			continue
		}
		record.lookups--
		if index := r.identityIndexLocked(record); record.lookups == 0 && record.pins == 0 && index[record.key] == record {
			delete(index, record.key)
		}
		if reclaim := r.collectLocked(record); len(reclaim) != 0 {
			completion.reclaims = append(completion.reclaims, reclaim)
		}
	}
	return completion
}

func (r *rawFileSystem) finishDirPlusLookupCompletion(completion dirPlusLookupCompletion) {
	if completion.tx == nil {
		return
	}
	cursorSettled := completion.tx.cursor.finish(completion.commit)
	for _, reclaim := range completion.reclaims {
		r.mount.deferReclaim(reclaim)
	}
	r.releaseHandleOperation(completion.tx.handleRecord)
	if completion.corrupt || !cursorSettled {
		r.mount.revoke(errors.New("fusev3: READDIRPLUS settlement lost staged lookup or cursor ownership"))
	}
}

// publishDirPlusPage reserves an authority page as one admission unit. The
// page is already serialized with zero lifetimes; only a successful preflight
// for every name and attr turns any of them on. This keeps the bounded registry
// invariant independent of READDIRPLUS concurrency and avoids a partially
// cached page when one registry reaches capacity.
func (r *rawFileSystem) publishDirPlusPage(ctx context.Context, parent *inodeRecord, candidates []dirPlusCandidate) error {
	publication := replyPublicationFromContext(ctx)
	if publication == nil || parent == nil {
		return errors.New("fusev3: READDIRPLUS escaped its reply-publication lifecycle")
	}
	if len(candidates) == 0 {
		return nil
	}
	snapshot := candidates[0].dirent.GetSnapshotSequence()
	if snapshot == 0 || publication.snapshotSequence != 0 || publication.cacheStamp != nil || publication.postState != nil {
		return errors.New("fusev3: malformed READDIRPLUS page stamp")
	}
	for _, candidate := range candidates {
		item := candidate.item
		if candidate.entry == nil || candidate.record == nil || item == nil || item.GetAttr() == nil ||
			candidate.dirent.GetSnapshotSequence() != snapshot || candidate.dirent.GetObjectVersion() == 0 ||
			candidate.dirent.GetObjectVersion() > snapshot || item.GetSnapshotSequence() != snapshot ||
			item.GetObjectVersion() != candidate.dirent.GetObjectVersion() || !bytes.Equal(item.GetStableIdentity(), candidate.record.identity[:]) {
			return errors.New("fusev3: inconsistent READDIRPLUS page record")
		}
	}
	publication.needsPostVFS = true
	publication.snapshotSequence = snapshot

	r.mu.Lock()
	defer r.mu.Unlock()
	newNames := make(map[nameKey]struct{}, len(candidates))
	newAttrs := make(map[publicationIdentity]struct{}, len(candidates))
	admissible := true
	for _, candidate := range candidates {
		name := string(candidate.dirent.GetName())
		key := nameKey{parent: parent.key.inode, name: name}
		stable := publicationNamespace{parent: parent.identity, name: name}
		nameCoordinate := publicationCoordinate{kind: publicationNamespaceName, parent: stable.parent, name: name}
		attrCoordinate := publicationCoordinate{kind: publicationItemAttributes, item: candidate.record.identity}
		r.supersedeNegativeNameLocked(key, nameCoordinate)
		_, nameHeld := r.heldNames[key]
		_, inodeHeld := r.heldInodes[candidate.record.key.inode]
		if nameHeld || inodeHeld {
			admissible = false
		}
		if !r.sourcePublicationAllowedLocked(nameCoordinate, nil) || !r.sourcePublicationAllowedLocked(attrCoordinate, nil) ||
			r.repairingCoordinates[nameCoordinate] || snapshot <= r.lastPeerRepairSequence[nameCoordinate] ||
			r.repairingCoordinates[attrCoordinate] || snapshot <= r.lastPeerRepairSequence[attrCoordinate] {
			admissible = false
		}
		if _, exists := r.cachedNames[key]; !exists {
			newNames[key] = struct{}{}
		}
		if _, exists := r.cachedAttrs[candidate.record.identity]; !exists {
			newAttrs[candidate.record.identity] = struct{}{}
		}
	}
	if r.cachedNameTotalLocked()+len(newNames) > r.nameCapacity || len(r.cachedAttrs)+r.pendingAttrs+len(newAttrs) > r.attrCapacity {
		admissible = false
	}
	if !admissible {
		return nil
	}

	reservedNames := make(map[nameKey]bool, len(newNames))
	reservedAttrs := make(map[publicationIdentity]bool, len(newAttrs))
	for _, candidate := range candidates {
		name := string(candidate.dirent.GetName())
		key := nameKey{parent: parent.key.inode, name: name}
		stable := publicationNamespace{parent: parent.identity, name: name}
		nameCoordinate := publicationCoordinate{kind: publicationNamespaceName, parent: stable.parent, name: name}
		attrCoordinate := publicationCoordinate{kind: publicationItemAttributes, item: candidate.record.identity}
		nameReservation, _ := r.reserveCacheCandidateLocked(publication, nameCoordinate)
		attrReservation, _ := r.reserveCacheCandidateLocked(publication, attrCoordinate)
		namePublication := replyNamePublication{key: key, stable: stable, record: candidate.record, coordinate: nameCoordinate, reservation: nameReservation}
		if _, needed := newNames[key]; needed && !reservedNames[key] {
			namePublication.reserved = true
			reservedNames[key] = true
			r.pendingNames++
		}
		if _, needed := newAttrs[candidate.record.identity]; needed && !reservedAttrs[candidate.record.identity] {
			attrReservation.capacityReserved = true
			reservedAttrs[candidate.record.identity] = true
			r.pendingAttrs++
		}
		r.publishingNames[key]++
		r.publishingInodes[candidate.record.key.inode]++
		r.admitSourcePublicationLocked(nameCoordinate)
		r.admitSourcePublicationLocked(attrCoordinate)
		publication.names = append(publication.names, namePublication)
		publication.attrs = append(publication.attrs, replyAttrPublication{
			inode: candidate.record.key.inode, identity: candidate.record.identity, record: candidate.record,
			coordinate: attrCoordinate, reservation: attrReservation,
		})
		publication.dirPlus = append(publication.dirPlus, replyDirPlusPublication{
			entry: candidate.entry, nameReservation: nameReservation, attrReservation: attrReservation,
		})
		candidate.entry.SetEntryTimeout(r.entryTimeout)
		candidate.entry.SetAttrTimeout(r.attrTimeout)
	}
	return nil
}

// publishNegativeEntry answers a name that does not exist with the lifetime
// this mount's cache contract allows for its absence.
//
// A cacheable absence is published the way FUSE defines one: a successful reply
// whose NodeId is zero, which the kernel reads as "no such entry, and that
// answer is valid for this long". Replying ENOENT is the uncacheable form. The
// kernel installs a negative dentry either way, but only the zero-NodeId reply
// carries a lifetime, so ENOENT costs one full authority round trip per probe,
// forever -- which is what every SQLite transaction (`-journal`, `-wal`), every
// interpreter's import scan, and every linker's search path spend most of their
// syscalls on.
//
// Absence is cacheable for exactly the reason existence is, and by exactly the
// same mechanism. A create or rename that fills the name is a visible mutation,
// the authority's audience for it includes this mount because the failed
// resolution entered that mount's resolved index just as a successful one would
// (see lookupForSession), and the barrier expires this entry here before the
// mutating syscall returns on the machine that made it. The 60s lifetime is not
// what makes it safe; the repair is.
func (r *rawFileSystem) publishNegativeEntry(ctx context.Context, out *fuse.EntryOut, parent *inodeRecord, name string) (fuse.Status, error) {
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		return fuse.Status(syscall.ENOTCONN), errors.New("fusev3: negative lookup escaped its post-VFS reply-publication lifecycle")
	}
	// Even an uncacheable absence is a kernel-visible publication: d_lookup_done
	// installs the negative result after this response wakes the requester, with
	// a zero lifetime as much as with a real one. The receipt is therefore
	// retained whichever lifetime this reply ends up carrying.
	publication.needsPostVFS = true
	r.mu.Lock()
	lifetime, namePublication, cached := r.admitNegativeNameLocked(ctx, parent, name)
	r.mu.Unlock()
	if !cached {
		*out = fuse.EntryOut{}
		out.SetEntryTimeout(0)
		return fuse.OK, nil
	}
	publication.names = append(publication.names, namePublication)
	// A zero-NodeId reply carries no object, so every other field is written
	// out fresh rather than left at whatever the pooled request buffer held.
	*out = fuse.EntryOut{}
	out.SetEntryTimeout(lifetime)
	return fuse.OK, nil
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
	lifetime, coordinate, reservation, cached := r.admitAttrLocked(ctx, attr.GetInode(), record.identity)
	r.mu.Unlock()
	if cached {
		publication.attrs = append(publication.attrs, replyAttrPublication{inode: attr.GetInode(), identity: record.identity, record: record, coordinate: coordinate, reservation: reservation})
	}
	out.NodeId, out.Generation = record.id, 1
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(lifetime)
	fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
	return nil
}

func (r *rawFileSystem) settleNamePublicationLocked(publication replyNamePublication, successful bool) {
	if successful && (publication.reservation == nil || !publication.reservation.revoked) {
		if publication.negative {
			// A materializing callback may have superseded this mount's absence
			// before the kernel returned the lookup's merged receipt. Settling still
			// releases publication ownership, but must not resurrect the negative.
			if publication.negativeState == nil || !publication.negativeState.superseded {
				r.bindCachedNegativeLocked(publication.key)
			}
		} else {
			r.bindCachedNameLocked(publication.key, publication.stable, publication.record)
		}
	}
	if publication.negativeState != nil {
		states := r.publishingNegativeNames[publication.negativeState.coordinate]
		delete(states, publication.negativeState)
		if len(states) == 0 {
			delete(r.publishingNegativeNames, publication.negativeState.coordinate)
		}
	}
	if r.publishingNames[publication.key]--; r.publishingNames[publication.key] <= 0 {
		delete(r.publishingNames, publication.key)
	}
	r.settleSourcePublicationLocked(publication.coordinate)
}

func (r *rawFileSystem) settleAttrPublicationLocked(publication replyAttrPublication, successful bool) {
	if successful && (publication.reservation == nil || !publication.reservation.revoked) && publication.record != nil && !publication.record.reclaimed {
		r.cachedAttrs[publication.identity] = publication.record
	}
	if r.publishingInodes[publication.inode]--; r.publishingInodes[publication.inode] <= 0 {
		delete(r.publishingInodes, publication.inode)
	}
	r.settleSourcePublicationLocked(publication.coordinate)
}

// settleDataPublicationLocked ends one retained-data declaration. The registry
// entry is recorded only when the OPEN reply physically reached the kernel: a
// reply that never landed handed out no cacheability, and recording a
// withdrawal obligation for it would make self-revocation address an inode this
// kernel was never told to keep.
func (r *rawFileSystem) settleDataPublicationLocked(publication replyDataPublication, successful bool) {
	if r.publishingInodes[publication.inode]--; r.publishingInodes[publication.inode] <= 0 {
		delete(r.publishingInodes, publication.inode)
	}
	if successful && publication.record != nil && !publication.record.reclaimed {
		r.cachedData[publication.inode] = publication.record
	}
	r.settleSourcePublicationLocked(publication.coordinate)
}

func (r *rawFileSystem) settleReplyPublicationLocked(publication *replyPublication, successful bool) {
	// Failure before the physical edge and receipt settlement both pass here.
	// The former still owns capacity; the latter finds it already consumed.
	r.releaseReplyCapacityLocked(publication)
	for _, name := range publication.names {
		r.settleNamePublicationLocked(name, successful)
	}
	for _, attr := range publication.attrs {
		r.settleAttrPublicationLocked(attr, successful)
	}
	for _, data := range publication.data {
		r.settleDataPublicationLocked(data, successful)
	}
	// A successful original write can still be superseded before its merged
	// PFS_PUBLISH receipt. Keep every candidate addressable until this terminal
	// settlement; physical failure reaches the same point with successful=false.
	r.releaseReplyReservationsLocked(publication)
	if len(publication.names) != 0 || len(publication.attrs) != 0 || len(publication.data) != 0 {
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
	publication.owner = r
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
	if err := validateExpectedPostState(publication); err != nil {
		publication.payloadError = err
	} else if publication.postState != nil {
		if err := validateMutationPostState(publication.postState); err != nil {
			publication.payloadError = err
		} else {
			publication.droppedAttrs = make(map[publicationIdentity]bool)
			for _, object := range publication.postState.GetObjects() {
				identity, ok := publicationIdentityFromBytes(object.GetStableIdentity())
				if !ok {
					publication.payloadError = errors.New("fusev3: post-state object carried an invalid stable identity")
					break
				}
				record := r.byIdentityLocked(identity)
				if record == nil || record.id == 0 || object.GetAttr().GetInode() != record.key.inode || object.GetAttr().GetKind() != record.key.kind {
					publication.payloadError = fmt.Errorf("fusev3: post-state object %x has no matching canonical live node", identity)
					break
				}
				coordinate := publicationCoordinate{kind: publicationItemAttributes, item: identity}
				if held := r.sourceHolds[coordinate]; r.peerHolds[coordinate] != 0 || r.repairingCoordinates[coordinate] || held != nil && held != publication.source {
					publication.droppedAttrs[identity] = true
					continue
				}
				reservation, admitted := r.reserveCacheCandidateLocked(publication, coordinate)
				if !admitted {
					publication.droppedAttrs[identity] = true
					continue
				}
				if _, already := r.cachedAttrs[identity]; !already {
					if len(r.cachedAttrs)+r.pendingAttrs >= r.attrCapacity {
						r.removeCacheReservationLocked(reservation)
						publication.droppedAttrs[identity] = true
						continue
					}
					reservation.capacityReserved = true
					r.pendingAttrs++
				}
				r.publishingInodes[record.key.inode]++
				r.admitSourcePublicationLocked(coordinate)
				publication.attrs = append(publication.attrs, replyAttrPublication{
					inode: record.key.inode, identity: identity, record: record, coordinate: coordinate, reservation: reservation,
				})
			}
		}
	}
	if publication.empty() {
		delete(r.replyPublications, unique)
	}
	r.mu.Unlock()
}

func (r *rawFileSystem) byIdentityLocked(identity publicationIdentity) *inodeRecord {
	var found *inodeRecord
	for _, record := range r.nodesByID {
		if record == nil || record.graft || record.reclaimed || record.identity != identity {
			continue
		}
		if found != nil && found != record {
			return nil
		}
		found = record
	}
	return found
}

// ReplyWriteOrdered joins cache/source-bearing replies to go-fuse's ordered
// writer boundary. A definite no-change source reply needs only the physical
// boundary; a state-bearing reply additionally opts into PFS_PUBLISH below.
func (r *rawFileSystem) ReplyWriteOrdered(unique uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.replyPublications[unique] != nil || r.publishAcks[unique] != nil
}

// PrepareReplyPayload is the PENDING-to-FINALIZED transition. It runs under
// go-fuse's physical writer mutex, so no notification can overtake the bytes
// whose lifetimes and DROP decisions are frozen here.
func (r *rawFileSystem) PrepareReplyPayload(unique, _ uint64, opcode uint32, outData, payload []byte, payloadSize int) (int, fuse.Status) {
	r.mu.Lock()
	publication := r.replyPublications[unique]
	if publication == nil {
		r.mu.Unlock()
		if opcode == 44 { // READDIRPLUS
			return payloadSize, fuse.OK
		}
		return 0, fuse.OK
	}
	if publication.payloadError != nil {
		err := publication.payloadError
		r.mu.Unlock()
		r.mount.revoke(err)
		return 0, fuse.EIO
	}
	for _, set := range r.cacheReservations {
		for reservation := range set {
			if reservation.publication != publication {
				continue
			}
			if reservation.state != cacheReservationPending {
				r.mu.Unlock()
				r.mount.revoke(errors.New("fusev3: cache reservation finalized more than once"))
				return 0, fuse.EIO
			}
			reservation.state = cacheReservationFinalized
		}
	}
	nameDropped, attrDropped := false, make(map[publicationIdentity]bool)
	for _, candidate := range publication.names {
		if candidate.reservation != nil && candidate.reservation.revoked {
			nameDropped = true
		}
	}
	for identity, dropped := range publication.droppedAttrs {
		attrDropped[identity] = dropped
	}
	for _, candidate := range publication.attrs {
		if candidate.reservation != nil && candidate.reservation.revoked {
			attrDropped[candidate.identity] = true
		}
	}
	for _, candidate := range publication.dirPlus {
		if candidate.entry == nil {
			continue
		}
		if candidate.nameReservation != nil && candidate.nameReservation.revoked {
			candidate.entry.SetEntryTimeout(0)
		}
		if candidate.attrReservation != nil && candidate.attrReservation.revoked {
			candidate.entry.SetAttrTimeout(0)
		}
	}
	r.mu.Unlock()

	if nameDropped {
		zeroEntryLifetime(opcode, outData)
	}
	if publication.cacheStamp != nil {
		if len(payload) < fuse.PFSCacheStampSize {
			return 0, fuse.EIO
		}
		if len(publication.attrs) != 0 && attrDropped[publication.attrs[0].identity] {
			zeroAttrLifetime(opcode, outData)
		}
		if !fuse.EncodePFSCacheStamp(payload, publication.cacheStamp) {
			return 0, fuse.EIO
		}
		return fuse.PFSCacheStampSize, fuse.OK
	}
	if publication.postState == nil {
		if opcode == 44 { // READDIRPLUS
			return payloadSize, fuse.OK
		}
		return 0, fuse.OK
	}
	state := publication.postState
	if err := validateMutationPostStateForOpcode(opcode, state); err != nil {
		r.mount.revoke(err)
		return 0, fuse.EIO
	}
	needed := fuse.PFSPostStateHeaderSize + len(state.GetObjects())*fuse.PFSObjectStateSize
	if len(payload) < needed {
		return 0, fuse.EIO
	}
	binary.LittleEndian.PutUint64(payload[0:8], state.GetVisibilitySequence())
	binary.LittleEndian.PutUint64(payload[8:16], state.GetSnapshotSequence())
	binary.LittleEndian.PutUint64(payload[16:24], uint64(r.attrTimeout))
	binary.LittleEndian.PutUint32(payload[24:28], uint32(len(state.GetObjects())))
	binary.LittleEndian.PutUint32(payload[28:32], 0)
	offset := fuse.PFSPostStateHeaderSize
	r.mu.Lock()
	for _, object := range state.GetObjects() {
		identity, _ := publicationIdentityFromBytes(object.GetStableIdentity())
		record := r.byIdentityLocked(identity)
		if record == nil {
			r.mu.Unlock()
			return 0, fuse.EIO
		}
		var attr fuse.Attr
		fillAttr(object.GetAttr(), &attr, r.mount.uid, r.mount.gid)
		var wireAttr [fuse.PFSWireAttrSize]byte
		encodeFuseAttr(wireAttr[:], &attr)
		wireObject := &fuse.PFSObjectState{
			Nodeid: record.id, ObjectVersion: object.GetObjectVersion(), Attr: wireAttr,
			Roles: object.GetRoles(), InodeFlags: object.GetAttr().GetFlags(),
			BirthTimeNS: object.GetAttr().GetBirthTimeNs(), PFSClass: 1,
		}
		copy(wireObject.StableIdentity[:], object.GetStableIdentity())
		if attrDropped[identity] {
			wireObject.RecordFlags = 1
		}
		if !fuse.EncodePFSObjectState(payload[offset:offset+fuse.PFSObjectStateSize], wireObject) {
			r.mu.Unlock()
			return 0, fuse.EIO
		}
		offset += fuse.PFSObjectStateSize
	}
	r.mu.Unlock()
	return needed, fuse.OK
}

func zeroEntryLifetime(opcode uint32, out []byte) {
	switch opcode {
	case 1, 6, 8, 9, 13, 35, 51: // LOOKUP, SYMLINK, MKNOD, MKDIR, LINK, CREATE, TMPFILE
		if len(out) >= 40 {
			clear(out[16:24])
			clear(out[32:36])
		}
	}
}

func zeroAttrLifetime(opcode uint32, out []byte) {
	switch opcode {
	case 1, 6, 8, 9, 13, 35, 51:
		if len(out) >= 40 {
			clear(out[24:32])
			clear(out[36:40])
		}
	case 3, 4: // GETATTR, SETATTR
		if len(out) >= 12 {
			clear(out[0:12])
		}
	}
}

func encodeFuseAttr(out []byte, attr *fuse.Attr) {
	binary.LittleEndian.PutUint64(out[0:8], attr.Ino)
	binary.LittleEndian.PutUint64(out[8:16], attr.Size)
	binary.LittleEndian.PutUint64(out[16:24], attr.Blocks)
	binary.LittleEndian.PutUint64(out[24:32], attr.Atime)
	binary.LittleEndian.PutUint64(out[32:40], attr.Mtime)
	binary.LittleEndian.PutUint64(out[40:48], attr.Ctime)
	binary.LittleEndian.PutUint32(out[48:52], attr.Atimensec)
	binary.LittleEndian.PutUint32(out[52:56], attr.Mtimensec)
	binary.LittleEndian.PutUint32(out[56:60], attr.Ctimensec)
	binary.LittleEndian.PutUint32(out[60:64], attr.Mode)
	binary.LittleEndian.PutUint32(out[64:68], attr.Nlink)
	binary.LittleEndian.PutUint32(out[68:72], attr.Uid)
	binary.LittleEndian.PutUint32(out[72:76], attr.Gid)
	binary.LittleEndian.PutUint32(out[76:80], attr.Rdev)
	binary.LittleEndian.PutUint32(out[80:84], attr.Blksize)
	binary.LittleEndian.PutUint32(out[84:88], attr.Flags)
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
			r.finishOneShotWritePublication(publication)
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
			r.finishOneShotWritePublication(publication)
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
	if status.Ok() {
		// Capacity bounds how many reply writers may be admitted, not how long a
		// physically written candidate remains addressable for peer revocation.
		r.releaseReplyCapacityLocked(publication)
	}
	// A same-mount source gate may be waiting for exactly this physical edge:
	// once a negative reply is in the kernel's hands, its enclosing mutation may
	// supersede it even though the merged post-VFS receipt is still outstanding.
	r.signalSourceChangedLocked()
	dirPlusCompletion := r.settleDirPlusLookupTransactionLocked(publication, status.Ok())
	if !status.Ok() {
		delete(r.replyPublications, unique)
		if publication.publishUnique != 0 && r.publishAcks[publication.publishUnique] == publication {
			delete(r.publishAcks, publication.publishUnique)
		}
		r.settleReplyPublicationLocked(publication, false)
		r.mu.Unlock()
		r.finishDirPlusLookupCompletion(dirPlusCompletion)
		r.finishOneShotWritePublication(publication)
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
		r.finishDirPlusLookupCompletion(dirPlusCompletion)
		r.finishWriteTransactionPublication(publication, unique)
		if publication.source != nil {
			publication.source.release()
		}
		publication.consumeAuthorityResponse()
		return
	}
	r.mu.Unlock()
	r.finishDirPlusLookupCompletion(dirPlusCompletion)
}

func (r *rawFileSystem) finishWriteTransactionPublication(publication *replyPublication, unique uint64) {
	if publication == nil {
		return
	}
	r.finishOneShotWritePublication(publication)
	if publication.writeKernelTx == 0 {
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

func (r *rawFileSystem) finishOneShotWritePublication(publication *replyPublication) {
	if publication == nil {
		return
	}
	if publication.writeHandle != nil {
		r.releaseHandleOperation(publication.writeHandle)
		publication.writeHandle = nil
	}
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
	// FORGET also proves the kernel dropped this inode, and an inode it does
	// not hold has no page cache. The data registry is released on exactly the
	// same evidence as the name budget rather than on a repair, because a
	// repair drops the pages a live open description can immediately refault.
	if r.cachedData[record.key.inode] == record {
		delete(r.cachedData, record.key.inode)
	}
	if r.cachedAttrs[record.identity] == record {
		delete(r.cachedAttrs, record.identity)
	}
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
		// A strict shared ENOENT states a namespace fact, and one this kernel
		// may serve from cache; publishNegativeEntry decides its lifetime and
		// retains the ordering record either way. Other errors describe no
		// namespace fact and remain ordinary unmarked replies.
		if errno == syscall.ENOENT {
			status, err := r.publishNegativeEntry(ctx, out, parent, name)
			if err != nil {
				r.mount.revoke(err)
				return fuse.Status(syscall.ENOTCONN)
			}
			return status
		}
		out.SetEntryTimeout(0)
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

// publishRetainedData declares that this kernel may keep the inode's file data
// resident across the handle it is about to receive.
//
// It is the OPEN half of the cache contract, and it is deliberately admitted
// through the same source-publication gate and PREPARE cut that a name or an
// attribute reply passes. The declaration cannot be softened -- the strict
// kernel accepts exactly one open flag pair for a SHARED regular file -- so a
// closed cut parks the callback rather than downgrading the reply.
//
// Not calling this and replying anyway would still hand the kernel a retainable
// cache; it would just hand it one no revocation could name. That is the defect
// this function exists to prevent, which is why the caller treats a failure as
// terminal rather than as a reason to reply uncached.
func (r *rawFileSystem) publishRetainedData(ctx context.Context, record *inodeRecord, attr *authoritypb.Attr) error {
	publication := replyPublicationFromContext(ctx)
	if publication == nil || record == nil || attr == nil {
		return errors.New("fusev3: retained-data declaration escaped its post-VFS reply-publication lifecycle")
	}
	inode := attr.GetInode()
	if inode == 0 {
		return errors.New("fusev3: retained-data declaration has no coordination inode")
	}
	// Deliberately no post-VFS receipt. The kernel forbids marking an ordinary
	// OPEN reply, and it is right to: this declaration installs no state a
	// repair could miss. It grants permission to retain data whose every folio
	// is separately ordered against the barrier by mapping->invalidate_lock, so
	// a COMPLETE that lands between the reply write and fuse_finish_open()
	// simply leaves KEEP_CACHE describing an already-empty cache. Settling on
	// the physical response write is therefore the exact boundary: it is what
	// proves the kernel was told it may retain anything at all.
	coordinate, err := r.awaitDataAdmission(ctx, inode, record.identity)
	if err != nil {
		return err
	}
	publication.data = append(publication.data, replyDataPublication{inode: inode, record: record, coordinate: coordinate})
	return nil
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
	if err := r.publishRetainedData(ctx, record, record.node.item.GetAttr()); err != nil {
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
	if err := r.publishRetainedData(ctx, record, item.GetAttr()); err != nil {
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
	if err := r.publishRetainedData(ctx, record, item.GetAttr()); err != nil {
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
		entry, _, errno := handle.peek(ctx, false)
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

func (r *rawFileSystem) ReadDirPlus(_ <-chan struct{}, input *fuse.ReadIn, out *fuse.DirEntryList) fuse.Status {
	// Mixed authority/local directories do not negotiate READDIRPLUS, so seeing
	// a local handle here means the kernel violated the negotiated capability.
	if r.grafts != nil {
		if held, handle := r.acquireGraftDirHandle(input.Fh); handle != nil {
			r.releaseHandleOperation(held)
			return fuse.EIO
		}
	}
	handleRecord, handle := r.acquireDirHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	releaseHandle := true
	defer func() {
		if releaseHandle {
			r.releaseHandleOperation(handleRecord)
		}
	}()
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	cursor, errno := handle.beginDirPlus(ctx, input.Offset)
	if errno != 0 {
		return fuse.Status(errno)
	}
	if err := r.attachDirPlusLookupTransaction(ctx, cursor, handleRecord); err != nil {
		_ = cursor.finish(false)
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	// The reply transaction now retains this handle operation until the
	// physical write commits or rolls back the staged page.
	releaseHandle = false
	candidates := make([]dirPlusCandidate, 0, 32)
	for {
		entry, dirent, errno := handle.peek(ctx, true)
		if errno != 0 {
			return fuse.Status(errno)
		}
		if entry == nil || dirent == nil {
			break
		}
		item := dirent.GetItem()
		if item == nil || item.GetAttr() == nil || !proto.Equal(item.GetAttr(), dirent.GetAttr()) {
			r.mount.revoke(errors.New("fusev3: authority READDIRPLUS record omitted or disagreed with its item"))
			return fuse.Status(syscall.ENOTCONN)
		}
		if !out.PFSDirLookupEntryFits(entry.Name) {
			if len(candidates) == 0 {
				return fuse.Status(syscall.EOVERFLOW)
			}
			break
		}
		record, internErrno := r.intern(ctx, item)
		if internErrno != 0 {
			return fuse.Status(internErrno)
		}
		if err := r.stageDirPlusLookup(ctx, record, handleRecord.inode, entry.Name); err != nil {
			r.Forget(record.id, 1)
			r.mount.revoke(err)
			return fuse.Status(syscall.ENOTCONN)
		}
		transferred := handle.consumePlus()
		if transferred != item {
			r.mount.revoke(errors.New("fusev3: READDIRPLUS capability transfer lost its pending item"))
			return fuse.Status(syscall.ENOTCONN)
		}
		entry.Ino = record.key.inode
		entryOut, stamp := out.AddPFSDirLookupEntry(*entry)
		if entryOut == nil || stamp == nil {
			return fuse.EIO
		}
		entryOut.NodeId, entryOut.Generation = record.id, 1
		entryOut.SetEntryTimeout(0)
		entryOut.SetAttrTimeout(0)
		fillAttr(item.GetAttr(), &entryOut.Attr, r.mount.uid, r.mount.gid)
		stamp.SnapshotSequence = dirent.GetSnapshotSequence()
		stamp.ObjectVersion = dirent.GetObjectVersion()
		stamp.BirthTimeNS = item.GetAttr().GetBirthTimeNs()
		stamp.InodeFlags = item.GetAttr().GetFlags()
		candidates = append(candidates, dirPlusCandidate{entry: entryOut, dirent: dirent, item: item, record: record})
		if handle.authorityPageExhausted() {
			break
		}
	}
	if err := r.publishDirPlusPage(ctx, handleRecord.inode, candidates); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	if err := r.commitDirPlusLookupTransaction(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	return fuse.OK
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
	record := r.byIdentityLocked(identity)
	lifetime, coordinate, reservation, cached := r.admitAttrLocked(ctx, inode, identity)
	r.mu.Unlock()
	fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
	out.SetTimeout(lifetime)
	if cached {
		publication.attrs = append(publication.attrs, replyAttrPublication{inode: inode, identity: identity, record: record, coordinate: coordinate, reservation: reservation})
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
			// SessionDone is an enforcement certificate, not the trigger for this
			// work. Publish it only after the bounded ladder has revoked admission,
			// detached the namespace, attempted every name/data withdrawal, and
			// aborted the serving connection. Failures remain in outcome, but cannot
			// leave the public terminal edge waiting forever.
			m.rpc.FinishLocalSessionEnforcement()
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
