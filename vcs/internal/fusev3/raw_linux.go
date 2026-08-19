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
	"unsafe"

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
	// never be the target of an authority cache lease.
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
	lease         leaseStamp
	snapshot      uint64
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
	inode         uint64
	identity      publicationIdentity
	record        *inodeRecord
	coordinate    publicationCoordinate
	reservation   *cacheInstallReservation
	reserved      bool
	lease         leaseStamp
	attr          *authoritypb.Attr
	objectVersion uint64
	snapshot      uint64
}

type leaseStamp struct {
	epoch          uint64
	issuedSequence uint64
}

type cachedAttrPayload struct {
	lease         leaseStamp
	attr          *authoritypb.Attr
	objectVersion uint64
	snapshot      uint64
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

type responseConsumptionOwnership uint8

const (
	responseConsumptionUnregistered responseConsumptionOwnership = iota
	responseConsumptionPublication
	responseConsumptionTransferred
)

type responseConsumptionClaim struct {
	consumptions []authorityrpc.ResponseConsumption
	done         chan struct{}
}

type cacheSnapshot struct {
	SnapshotSequence uint64
	ObjectVersion    uint64
	BirthTimeNS      int64
	InodeFlags       uint32
}

// replyDataPublication is one OPEN reply's declaration that this kernel may
// retain the inode's file data. It carries the record as well as the inode
// number because the withdrawal it obliges is addressed by kernel NodeID.
type replyDataPublication struct {
	inode      uint64
	record     *inodeRecord
	coordinate publicationCoordinate
	revoked    bool
}

// replyPublication is everything one kernel response can make cacheable or
// must keep source-serialized. It is registered by request Unique before the
// RawFileSystem method returns. They settle after their physical /dev/fuse
// write, which is the stock-kernel publication edge available to userspace.
type replyPublication struct {
	names  []replyNamePublication
	attrs  []replyAttrPublication
	data   []replyDataPublication
	source *sourcePublicationLease
	// responseConsumptions prevent authority transport EOF from exposing the
	// session terminal edge until every authority response contributing to this
	// kernel result is either physically written or fail-closed locally. One
	// FUSE callback may require several bounded read or
	// staged-write RPCs, so this is deliberately a collection rather than one
	// token. The slice and its ownership state are protected by rawFileSystem.mu
	// after registration.
	responseConsumptions     []authorityrpc.ResponseConsumption
	responseConsumptionOwner responseConsumptionOwnership
	responseConsumptionDone  chan struct{}
	postState                *authoritypb.PostState
	leaseGrants              []validatedLeaseGrant
	sourceLeaseDischarge     *authoritypb.SourceLeaseDischarge
	sourceLeasePrepared      bool
	expectedPostState        map[publicationIdentity]uint32
	cacheStamp               *cacheSnapshot
	dirPlus                  []replyDirPlusPublication
	dirPlusLookups           *dirPlusLookupTransaction
	snapshotSequence         uint64
	payloadError             error

	// Physical reply state is protected by rawFileSystem.mu.
	owner             *rawFileSystem
	requestUnique     uint64
	nodeid            uint64
	opcode            uint32
	originalDone      chan struct{}
	originalFinalized bool
	originalWrote     bool
	originalStatus    fuse.Status
}

func (p *replyPublication) empty() bool {
	return p == nil || len(p.names) == 0 && len(p.attrs) == 0 && len(p.data) == 0 && p.source == nil &&
		len(p.responseConsumptions) == 0 &&
		p.postState == nil && p.cacheStamp == nil && p.snapshotSequence == 0 && p.payloadError == nil && p.dirPlusLookups == nil
}

func (p *replyPublication) consumeAuthorityResponse() {
	if p == nil || p.owner == nil {
		return
	}
	p.owner.claimAndConsumeAuthorityResponses(p)
}

// takeAuthorityResponsesLocked is the sole handoff from reply ownership to a
// settlement path. Clearing the retained slice is not an idempotence trick: it
// records that callback cleanup, normal settlement, or teardown won exclusive
// ownership of every response currently attached to this publication. A later
// response cannot join a transferred publication.
func (r *rawFileSystem) takeAuthorityResponsesLocked(publication *replyPublication) (responseConsumptionClaim, bool) {
	if publication == nil || publication.owner != r || publication.responseConsumptionOwner != responseConsumptionPublication {
		return responseConsumptionClaim{}, false
	}
	publication.responseConsumptionOwner = responseConsumptionTransferred
	claim := responseConsumptionClaim{
		consumptions: publication.responseConsumptions,
		done:         publication.responseConsumptionDone,
	}
	publication.responseConsumptions = nil
	return claim, true
}

func (r *rawFileSystem) claimAndConsumeAuthorityResponses(publication *replyPublication) {
	r.mu.Lock()
	claim, claimed := r.takeAuthorityResponsesLocked(publication)
	done := publication.responseConsumptionDone
	r.mu.Unlock()
	if claimed {
		consumeClaimedAuthorityResponses(claim)
		return
	}
	// A competing settlement path already owns the responses. Callback cleanup
	// still cannot return until that one owner has finished the terminal
	// consumption promised by the authority-response lifecycle.
	if done != nil {
		<-done
	}
}

func consumeClaimedAuthorityResponses(claim responseConsumptionClaim) {
	if claim.done == nil {
		return
	}
	defer close(claim.done)
	for _, consumption := range claim.consumptions {
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

	// These lifetimes are local policy ceilings. Exact reply-local leases bound
	// actual validity, and kernel entry validity is always zero.
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
	// table from nodesByKey: lease coordinates resolve authority identities
	// against nodesByKey, and a graft must never become an invalidation target.
	graftsByKey map[inodeKey]*inodeRecord
	// namedRecords indexes the objects whose path is maintained, so that a
	// rename this mount performs can correct the moved object's path -- the
	// kernel moves the dentry without re-resolving it, so nothing else would.
	namedRecords map[nameKey]*inodeRecord
	nextHandle   uint64
	handles      map[uint64]*handleRecord

	// cachedNames is the exact set of daemon-resident (parent inode, name)
	// bindings held under N leases. Kernel entry validity is always zero in the
	// portable profile, so recall only has to drop this local binding.
	cachedNames       map[nameKey]*inodeRecord
	cachedStableNames map[publicationNamespace]*inodeRecord
	cachedNameStable  map[nameKey]publicationNamespace
	cachedNameLeases  map[nameKey]leaseStamp
	// cachedNegatives is the same daemon-local registry for the other half of
	// the namespace. It is a set rather than a map to a record because an
	// absence names nothing.
	cachedNegatives      map[nameKey]struct{}
	cachedNegativeLeases map[nameKey]leaseStamp
	// cachedAttrs is the exact set of inode attributes this daemon has allowed
	// its kernel to retain. It gives attribute candidates the same bounded,
	// repairable accounting as positive and negative names.
	cachedAttrs        map[publicationIdentity]*inodeRecord
	cachedAttrPayloads map[publicationIdentity]cachedAttrPayload
	// cachedData is the exact set of authority inodes whose file data this
	// frontend has told its kernel it may keep. It is keyed by coordination
	// inode number and is the third kernel cache this mount owes a withdrawal.
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
	replyTerminalizing  bool
	replyTerminal       bool
	replyTerminalDone   chan struct{}
	replyLifecycleArmed bool

	// Source-owned gates close publication before the mutation gets a replay
	// identity or can put bytes on the wire. They are keyed only by stable
	// filesystem identities and exact names.
	sourceHolds                map[publicationCoordinate]*sourcePublicationLease
	sourcePublishing           map[publicationCoordinate]int
	publishingNegativeNames    map[publicationCoordinate]map[*negativeNamePublication]struct{}
	sourceUnresolvedAttributes map[*sourcePublicationLease]int
	sourceUnresolvedData       map[*sourcePublicationLease]int
	sourceChanged              chan struct{}
	repairingCoordinates       map[publicationCoordinate]bool
	cacheReservations          map[publicationCoordinate]map[*cacheInstallReservation]struct{}
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
		cachedNameLeases:           make(map[nameKey]leaseStamp),
		cachedNegatives:            make(map[nameKey]struct{}),
		cachedNegativeLeases:       make(map[nameKey]leaseStamp),
		cachedAttrs:                make(map[publicationIdentity]*inodeRecord),
		cachedAttrPayloads:         make(map[publicationIdentity]cachedAttrPayload),
		cachedData:                 make(map[uint64]*inodeRecord),
		publishingNames:            make(map[nameKey]int),
		publishingInodes:           make(map[uint64]int),
		published:                  make(chan struct{}),
		replyPublications:          make(map[uint64]*replyPublication),
		sourceHolds:                make(map[publicationCoordinate]*sourcePublicationLease),
		sourcePublishing:           make(map[publicationCoordinate]int),
		publishingNegativeNames:    make(map[publicationCoordinate]map[*negativeNamePublication]struct{}),
		sourceUnresolvedAttributes: make(map[*sourcePublicationLease]int),
		sourceUnresolvedData:       make(map[*sourcePublicationLease]int),
		sourceChanged:              make(chan struct{}),
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
	delete(r.cachedNameLeases, key)
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
	delete(r.cachedNegativeLeases, key)
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
func (r *rawFileSystem) bindCachedNegativeLocked(key nameKey, lease leaseStamp) {
	r.dropCachedNameLocked(key)
	r.cachedNegatives[key] = struct{}{}
	r.cachedNegativeLeases[key] = lease
}

func (r *rawFileSystem) bindCachedNameLocked(key nameKey, stable publicationNamespace, record *inodeRecord, lease leaseStamp) {
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
	r.cachedNameLeases[key] = lease
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

func cacheCandidateVersion(publication *replyPublication) (uint64, uint64) {
	if publication == nil || publication.cacheStamp == nil {
		return 0, cacheCandidateSnapshot(publication)
	}
	return publication.cacheStamp.ObjectVersion, publication.cacheStamp.SnapshotSequence
}

func (r *rawFileSystem) reserveCacheCandidateLocked(publication *replyPublication, coordinate publicationCoordinate) (*cacheInstallReservation, bool) {
	snapshot := cacheCandidateSnapshot(publication)
	if snapshot == 0 || r.repairingCoordinates[coordinate] {
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
	grant, granted := replyPublicationFromContext(ctx).leaseGrant(
		authoritypb.LeaseFamily_LEASE_FAMILY_NAME, authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ,
		publicationIdentity{}, parent.identity, name, time.Now())
	leaseLifetime := grant.cacheDeadline.Sub(time.Now())
	if record == nil {
		return 0, publication, false
	}
	if !granted || leaseLifetime <= 0 {
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
	publication.lease = leaseStamp{epoch: grant.epoch, issuedSequence: grant.issuedSequence}
	publication.snapshot = cacheCandidateSnapshot(replyPublicationFromContext(ctx))
	publication.reserved = !already
	if publication.reserved {
		r.pendingNames++
	}
	r.publishingNames[key]++
	r.admitSourcePublicationLocked(coordinate)
	return leaseBound(r.entryTimeout, leaseLifetime), publication, true
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
	grant, granted := replyPublicationFromContext(ctx).leaseGrant(
		authoritypb.LeaseFamily_LEASE_FAMILY_NAME, authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ,
		publicationIdentity{}, parent.identity, name, time.Now())
	leaseLifetime := grant.cacheDeadline.Sub(time.Now())
	if !granted || leaseLifetime <= 0 {
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
	publication.lease = leaseStamp{epoch: grant.epoch, issuedSequence: grant.issuedSequence}
	publication.snapshot = cacheCandidateSnapshot(replyPublicationFromContext(ctx))
	r.publishingNames[key]++
	r.admitSourcePublicationLocked(coordinate)
	state := &negativeNamePublication{owner: r, reply: replyPublicationFromContext(ctx), coordinate: coordinate}
	publication.negativeState = state
	if r.publishingNegativeNames[coordinate] == nil {
		r.publishingNegativeNames[coordinate] = make(map[*negativeNamePublication]struct{})
	}
	r.publishingNegativeNames[coordinate][state] = struct{}{}
	return leaseBound(r.entryTimeout, leaseLifetime), publication, true
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

func (r *rawFileSystem) admitAttrLocked(ctx context.Context, inode uint64, identity publicationIdentity) (time.Duration, publicationCoordinate, *cacheInstallReservation, bool) {
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: identity}
	leaseLifetime := replyPublicationFromContext(ctx).leaseRemaining(
		authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ,
		identity, publicationIdentity{}, "", time.Now())
	if leaseLifetime <= 0 {
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
	return leaseBound(r.attrTimeout, leaseLifetime), coordinate, reservation, true
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

type terminalReplyCompletion struct {
	publication         *replyPublication
	dirPlus             dirPlusLookupCompletion
	responseConsumption responseConsumptionClaim
	physical            bool
}

// terminalizeReplyCacheOwnership joins physical writer callbacks only until
// deadline. A false result leaves the table terminalizing while an
// already-finalized writer may still report its physical result. The caller
// must then terminate
// the device connection, prove it absent, and call
// terminalizeReplyCacheOwnershipAfterConnectionGone.
func (r *rawFileSystem) terminalizeReplyCacheOwnership(deadline time.Time) bool {
	r.mu.Lock()
	if r.replyTerminal {
		r.mu.Unlock()
		return true
	}
	if !r.replyTerminalizing {
		r.replyTerminalizing = true
		r.replyTerminalDone = make(chan struct{})
	}
	seen := make(map[*replyPublication]struct{}, len(r.replyPublications))
	for _, publication := range r.replyPublications {
		seen[publication] = struct{}{}
	}
	originalWrites := make([]<-chan struct{}, 0, len(seen))
	for publication := range seen {
		if publication.originalFinalized && !publication.originalWrote {
			originalWrites = append(originalWrites, publication.originalDone)
		}
	}
	r.mu.Unlock()

	// The writer callback runs only after go-fuse releases writeMu. Waiting
	// without rawFileSystem.mu lets every reply which froze its final bytes
	// report whether those bytes physically reached the kernel. No withdrawal
	// snapshot may precede this join.
	for _, originalDone := range originalWrites {
		if !waitReplyTerminal(originalDone, deadline) {
			return false
		}
	}
	return r.finishReplyCacheTerminalization(false)
}

func waitReplyTerminal(done <-chan struct{}, deadline time.Time) bool {
	wait := time.Until(deadline)
	if wait <= 0 {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// terminalizeReplyCacheOwnershipAfterConnectionGone is the only settlement
// edge for a finalized writer which never reports. Connection absence, not a
// guessed write result, proves that no kernel cache or lookup ownership can
// survive, so every retained candidate is rolled back exactly once.
func (r *rawFileSystem) terminalizeReplyCacheOwnershipAfterConnectionGone() {
	r.finishReplyCacheTerminalization(true)
}

func (r *rawFileSystem) finishReplyCacheTerminalization(connectionGone bool) bool {
	r.mu.Lock()
	if r.replyTerminal {
		r.mu.Unlock()
		return true
	}
	if !r.replyTerminalizing {
		r.mu.Unlock()
		return false
	}
	seen := make(map[*replyPublication]struct{}, len(r.replyPublications))
	for _, publication := range r.replyPublications {
		seen[publication] = struct{}{}
	}
	completions := make([]terminalReplyCompletion, 0, len(seen))
	for publication := range seen {
		delete(r.replyPublications, publication.requestUnique)
		physical := !connectionGone && publication.originalWrote && publication.originalStatus.Ok()
		if connectionGone && !publication.originalWrote {
			close(publication.originalDone)
		}
		dirPlus := r.settleDirPlusLookupTransactionLocked(publication, physical)
		responseConsumption := r.settleReplyPublicationLocked(publication, physical)
		completions = append(completions, terminalReplyCompletion{
			publication:         publication,
			dirPlus:             dirPlus,
			responseConsumption: responseConsumption,
			physical:            physical,
		})
	}
	r.replyTerminal = true
	r.replyTerminalizing = false
	close(r.replyTerminalDone)
	r.signalSourceChangedLocked()
	r.mu.Unlock()

	for _, completion := range completions {
		r.finishDirPlusLookupCompletion(completion.dirPlus)
		if completion.publication.source != nil {
			completion.publication.source.revoke()
		}
		consumeClaimedAuthorityResponses(completion.responseConsumption)
	}
	return true
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
			attrGrant, _ := publication.leaseGrant(authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ,
				record.identity, publicationIdentity{}, "", time.Now())
			objectVersion, snapshot := cacheCandidateVersion(publication)
			publication.attrs = append(publication.attrs, replyAttrPublication{
				inode: inode, identity: record.identity, record: record, coordinate: attrCoordinate, reservation: attrReservation,
				lease: leaseStamp{epoch: attrGrant.epoch, issuedSequence: attrGrant.issuedSequence}, attr: proto.Clone(attr).(*authoritypb.Attr),
				objectVersion: objectVersion, snapshot: snapshot,
			})
		}
	}
	r.mu.Unlock()
	if cachedName {
		publication.names = append(publication.names, namePublication)
	}
	out.NodeId = record.id
	out.Generation = 1
	// N leases cover the daemon's name cache only. Stock rename can transplant
	// an existing dentry timeout to a new name, so kernel entry_valid is always
	// zero even when this answer remains reusable inside the daemon.
	_ = entry
	out.SetEntryTimeout(0)
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
// validity is governed separately by the exact reply-local leases; lookup and
// path ownership transfer as soon as the kernel accepts the page.
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
		if !r.sourcePublicationAllowedLocked(nameCoordinate, nil) || !r.sourcePublicationAllowedLocked(attrCoordinate, nil) ||
			r.repairingCoordinates[nameCoordinate] || r.repairingCoordinates[attrCoordinate] {
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

// publishNegativeEntry retains a proven absence in the daemon under N-R while
// giving the kernel zero entry validity. Repeated path walks still avoid an
// authority round trip, but stock rename can never transplant a cached negative
// lifetime to a different name.
func (r *rawFileSystem) publishNegativeEntry(ctx context.Context, out *fuse.EntryOut, parent *inodeRecord, name string) (fuse.Status, error) {
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		return fuse.Status(syscall.ENOTCONN), errors.New("fusev3: negative lookup escaped its post-VFS reply-publication lifecycle")
	}
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
	_ = lifetime
	out.SetEntryTimeout(0)
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
	r.mu.Lock()
	lifetime, coordinate, reservation, cached := r.admitAttrLocked(ctx, attr.GetInode(), record.identity)
	r.mu.Unlock()
	if cached {
		attrGrant, _ := publication.leaseGrant(authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ,
			record.identity, publicationIdentity{}, "", time.Now())
		objectVersion, snapshot := cacheCandidateVersion(publication)
		publication.attrs = append(publication.attrs, replyAttrPublication{
			inode: attr.GetInode(), identity: record.identity, record: record, coordinate: coordinate, reservation: reservation,
			lease: leaseStamp{epoch: attrGrant.epoch, issuedSequence: attrGrant.issuedSequence}, attr: proto.Clone(attr).(*authoritypb.Attr),
			objectVersion: objectVersion, snapshot: snapshot,
		})
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
				r.bindCachedNegativeLocked(publication.key, publication.lease)
			}
		} else {
			r.bindCachedNameLocked(publication.key, publication.stable, publication.record, publication.lease)
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
		if publication.lease.epoch != 0 && publication.attr != nil && publication.objectVersion != 0 && publication.snapshot != 0 {
			r.cachedAttrPayloads[publication.identity] = cachedAttrPayload{
				lease: publication.lease, attr: proto.Clone(publication.attr).(*authoritypb.Attr),
				objectVersion: publication.objectVersion, snapshot: publication.snapshot,
			}
		} else {
			delete(r.cachedAttrPayloads, publication.identity)
		}
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

func (r *rawFileSystem) settleReplyPublicationLocked(publication *replyPublication, successful bool) responseConsumptionClaim {
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
	// Keep every candidate addressable until physical settlement; physical
	// failure reaches the same point with successful=false.
	r.releaseReplyReservationsLocked(publication)
	if len(publication.names) != 0 || len(publication.attrs) != 0 || len(publication.data) != 0 {
		close(r.published)
		r.published = make(chan struct{})
	}
	claim, _ := r.takeAuthorityResponsesLocked(publication)
	return claim
}

func (r *rawFileSystem) registerReplyPublication(unique uint64, publication *replyPublication) error {
	if unique == 0 {
		return fmt.Errorf("fusev3: a publication-capable FUSE callback has invalid request identity %#x", unique)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replyTerminal || r.replyTerminalizing {
		return errors.New("fusev3: reply publication registered after terminal settlement")
	}
	if r.replyPublications[unique] != nil {
		return fmt.Errorf("fusev3: FUSE request identity %d registered publication twice", unique)
	}
	if publication == nil || publication.owner != nil || publication.responseConsumptionOwner != responseConsumptionUnregistered {
		return errors.New("fusev3: reply publication reused response ownership")
	}
	publication.requestUnique = unique
	publication.owner = r
	publication.responseConsumptionOwner = responseConsumptionPublication
	publication.responseConsumptionDone = make(chan struct{})
	publication.originalDone = make(chan struct{})
	r.replyPublications[unique] = publication
	return nil
}

func (r *rawFileSystem) finishReplyPublicationRegistration(unique uint64, publication *replyPublication) {
	r.mu.Lock()
	if r.replyTerminal || r.replyTerminalizing {
		r.mu.Unlock()
		return
	}
	if r.replyPublications[unique] != publication {
		r.mu.Unlock()
		r.mount.revoke(fmt.Errorf("fusev3: FUSE request identity %d lost its reserved reply-publication ownership", unique))
		return
	}
	if err := validateExpectedPostState(publication); err != nil {
		publication.payloadError = err
	} else if publication.postState != nil {
		publication.payloadError = validateMutationPostState(publication.postState)
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
// physical writer boundary.
func (r *rawFileSystem) ReplyWriteOrdered(unique uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replyTerminal || r.replyTerminalizing {
		return false
	}
	return r.replyPublications[unique] != nil
}

// PrepareReplyPayload is the PENDING-to-FINALIZED transition. It runs under
// go-fuse's physical writer mutex, so no notification can overtake the bytes
// whose lifetimes and DROP decisions are frozen here.
func (r *rawFileSystem) PrepareReplyPayload(unique, _ uint64, opcode uint32, outData, payload []byte, payloadSize int) (int, fuse.Status, fuse.Status) {
	r.mu.Lock()
	if r.replyTerminal || r.replyTerminalizing {
		r.mu.Unlock()
		return 0, fuse.OK, fuse.Status(syscall.ENOTCONN)
	}
	publication := r.replyPublications[unique]
	if publication == nil {
		// Nothing was published for this reply, so there is no cache admission
		// to finalize and no reason to touch the bytes. The payload length must
		// be returned unchanged: a reply this frontend answered out of state it
		// already holds - a buffered READDIR page, a served READ - carries a real
		// payload that no publication decision applies to, and shortening it is
		// indistinguishable to the kernel from end-of-data.
		r.mu.Unlock()
		return payloadSize, fuse.OK, fuse.OK
	}
	if publication.payloadError != nil {
		err := publication.payloadError
		r.mu.Unlock()
		r.mount.revoke(err)
		return 0, fuse.OK, fuse.EIO
	}
	for _, set := range r.cacheReservations {
		for reservation := range set {
			if reservation.publication != publication {
				continue
			}
			if reservation.state != cacheReservationPending {
				r.mu.Unlock()
				r.mount.revoke(errors.New("fusev3: cache reservation finalized more than once"))
				return 0, fuse.OK, fuse.EIO
			}
			reservation.state = cacheReservationFinalized
		}
	}
	publication.originalFinalized = true
	nameDropped, attrDropped := false, make(map[publicationIdentity]bool)
	for _, candidate := range publication.names {
		if candidate.reservation != nil && candidate.reservation.revoked {
			nameDropped = true
		}
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
	dropKeepCache := false
	retryRead := false
	if len(publication.data) != 0 {
		retained := publication.data[:0]
		for _, candidate := range publication.data {
			if candidate.revoked || publication.leaseRemaining(
				authoritypb.LeaseFamily_LEASE_FAMILY_DATA, authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ,
				candidate.record.identity, publicationIdentity{}, "", time.Now()) <= 0 {
				r.settleDataPublicationLocked(candidate, false)
				if opcode == 15 { // READ
					retryRead = true
				} else {
					dropKeepCache = true
				}
				continue
			}
			retained = append(retained, candidate)
		}
		publication.data = retained
	}
	r.mu.Unlock()

	if nameDropped {
		zeroEntryLifetime(opcode, outData)
	}
	if len(publication.attrs) != 0 && attrDropped[publication.attrs[0].identity] {
		zeroAttrLifetime(opcode, outData)
	}
	if dropKeepCache {
		disableKeepCache(opcode, outData)
	}
	// Exact post-state is consumed by the daemon cache. Stock FUSE replies do
	// not carry PortableFS trailers; returning the original payload length is
	// what preserves the upstream wire shape.
	if retryRead {
		return 0, fuse.EAGAIN, fuse.OK
	}
	return payloadSize, fuse.OK, fuse.OK
}

func disableKeepCache(opcode uint32, out []byte) {
	offset := uintptr(0)
	switch opcode {
	case 14: // OPEN
		offset = unsafe.Offsetof(fuse.OpenOut{}.OpenFlags)
	case 35, 51: // CREATE, TMPFILE
		offset = unsafe.Offsetof(fuse.CreateOut{}.OpenOut) + unsafe.Offsetof(fuse.OpenOut{}.OpenFlags)
	default:
		return
	}
	if offset+4 > uintptr(len(out)) {
		return
	}
	flags := binary.LittleEndian.Uint32(out[offset : offset+4])
	flags &^= fuse.FOPEN_KEEP_CACHE
	binary.LittleEndian.PutUint32(out[offset:offset+4], flags)
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

// ReplyWritten is called by the maintained go-fuse fork only after the real
// /dev/fuse write attempt and after its ordering mutex has been released.
func (r *rawFileSystem) ReplyWritten(unique uint64, status fuse.Status) {
	r.mu.Lock()
	if r.replyTerminal {
		r.mu.Unlock()
		return
	}
	if r.replyTerminalizing {
		publication := r.replyPublications[unique]
		if publication != nil && publication.originalFinalized && !publication.originalWrote {
			publication.originalWrote = true
			publication.originalStatus = status
			close(publication.originalDone)
			if status.Ok() {
				r.releaseReplyCapacityLocked(publication)
			}
			r.signalSourceChangedLocked()
		}
		r.mu.Unlock()
		return
	}
	publication := r.replyPublications[unique]
	if publication == nil || publication.originalWrote {
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
	r.signalSourceChangedLocked()
	dirPlusCompletion := r.settleDirPlusLookupTransactionLocked(publication, status.Ok())
	delete(r.replyPublications, unique)
	responseConsumption := r.settleReplyPublicationLocked(publication, status.Ok())
	r.mu.Unlock()
	r.finishDirPlusLookupCompletion(dirPlusCompletion)
	var sourceDischargeErr error
	if publication.source != nil && publication.sourceLeaseDischarge != nil && status.Ok() {
		if !publication.sourceLeasePrepared {
			sourceDischargeErr = errors.New("fusev3: source lease discharge reached the writer edge before local purge")
		} else {
			sourceDischargeErr = r.mount.dischargeSourceLeases(publication.sourceLeaseDischarge)
		}
		if sourceDischargeErr != nil {
			r.mount.revoke(sourceDischargeErr)
		}
	}
	if publication.source != nil {
		if status.Ok() && sourceDischargeErr == nil {
			publication.source.release()
		} else {
			publication.source.revoke()
		}
	}
	if !status.Ok() && !r.mount.replyWriteLostAfterObservedUnmount(status) {
		r.mount.revoke(fmt.Errorf("fusev3: publish FUSE reply %d to the kernel: %v", unique, status))
	}
	consumeClaimedAuthorityResponses(responseConsumption)
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
	key := nameKey{parent: parent, name: name}
	record := r.cachedNames[key]
	r.dropCachedNameLocked(key)
	reclaim := r.collectLocked(record)
	r.mu.Unlock()
	r.mount.deferReclaim(reclaim)
}

// moveSelf withdraws both daemon N-cache payloads touched by a rename. An N
// grant is bound to one exact parent/name coordinate, so neither the payload
// nor its epoch may follow d_move to another coordinate. The path identity
// index is maintained independently by rebindRenamed.
func (r *rawFileSystem) moveSelf(oldParent *inodeRecord, oldName string, newParent *inodeRecord, newName string, exchange bool) {
	r.mu.Lock()
	from, to := nameKey{parent: oldParent.key.inode, name: oldName}, nameKey{parent: newParent.key.inode, name: newName}
	moved, replaced := r.cachedNames[from], r.cachedNames[to]
	r.dropCachedNameLocked(from)
	r.dropCachedNegativeLocked(from)
	r.dropCachedNameLocked(to)
	r.dropCachedNegativeLocked(to)
	movedReclaim := r.collectLocked(moved)
	var replacedReclaim []byte
	if replaced != moved {
		replacedReclaim = r.collectLocked(replaced)
	}
	r.mu.Unlock()
	r.mount.deferReclaim(movedReclaim)
	r.mount.deferReclaim(replacedReclaim)
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
	if record == nil || record.root || record.reclaimed || record.lookups != 0 || record.inFlight != 0 || record.pins != 0 || len(record.names) != 0 {
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
		delete(r.cachedAttrPayloads, record.identity)
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

// cachedLookup resolves an N-R-covered name entirely inside the daemon. A
// positive hit additionally needs A-R because the FUSE reply itself carries
// attributes even though both kernel validity fields remain zero.
func (r *rawFileSystem) cachedLookup(parent *inodeRecord, name string) (*inodeRecord, *authoritypb.Attr, bool) {
	if parent == nil {
		return nil, nil, false
	}
	now := time.Now()
	nameLease := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_NAME, parent: parent.identity, name: name}
	key := nameKey{parent: parent.key.inode, name: name}
	r.mu.Lock()
	record := r.cachedNames[key]
	_, negative := r.cachedNegatives[key]
	nameStamp := r.cachedNameLeases[key]
	if negative {
		nameStamp = r.cachedNegativeLeases[key]
	}
	var attrPayload cachedAttrPayload
	if record != nil {
		attrPayload = r.cachedAttrPayloads[record.identity]
	}
	r.mu.Unlock()
	if !r.mount.leases.matches(nameLease, authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ, nameStamp, now) {
		return nil, nil, false
	}
	if negative {
		return nil, nil, true
	}
	if record == nil || !r.mount.leases.matches(leaseKey{
		family: authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, identity: record.identity,
	}, authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ, attrPayload.lease, now) {
		return nil, nil, false
	}
	r.mu.Lock()
	currentAttr := r.cachedAttrPayloads[record.identity]
	if r.cachedNames[key] != record || r.cachedNameLeases[key] != nameStamp || r.cachedAttrs[record.identity] != record ||
		currentAttr.lease != attrPayload.lease || currentAttr.objectVersion != attrPayload.objectVersion || currentAttr.snapshot != attrPayload.snapshot ||
		currentAttr.attr == nil || record.reclaimed ||
		r.nodesByID[record.id] != record || record.lookups == math.MaxUint64 {
		r.mu.Unlock()
		return nil, nil, false
	}
	record.lookups++
	r.identityIndexLocked(record)[record.key] = record
	attr := proto.Clone(currentAttr.attr).(*authoritypb.Attr)
	r.mu.Unlock()
	return record, attr, false
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
	if record, attr, negative := r.cachedLookup(parent, name); negative {
		*out = fuse.EntryOut{}
		out.SetEntryTimeout(0)
		return fuse.OK
	} else if record != nil {
		r.bindPath(record, parent, name)
		out.NodeId, out.Generation = record.id, 1
		out.SetEntryTimeout(0)
		out.SetAttrTimeout(0)
		fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
		return fuse.OK
	}
	item, errno := parent.node.Lookup(ctx, name)
	if errno != 0 {
		// A strict shared ENOENT states a namespace fact which the daemon may
		// retain under N-R. Other errors describe no
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

// beginBufferedRead registers the possible page-cache install before issuing
// the authority RPC. It never waits: a request arriving after a recall cut
// must return retryable instead of parking while it may hold a kernel folio
// lock needed by the invalidation that will reopen the cut.
func (r *rawFileSystem) beginBufferedRead(ctx context.Context, record *inodeRecord) bool {
	publication := replyPublicationFromContext(ctx)
	if publication == nil || record == nil || record.id == 0 {
		return false
	}
	coordinate := publicationCoordinate{kind: publicationItemData, item: record.identity}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.repairingCoordinates[coordinate] || !r.sourcePublicationAllowedLocked(coordinate, sourceLeaseFromContext(ctx)) {
		return false
	}
	r.publishingInodes[record.key.inode]++
	r.admitSourcePublicationLocked(coordinate)
	publication.data = append(publication.data, replyDataPublication{inode: record.key.inode, record: record, coordinate: coordinate})
	return true
}

func (r *rawFileSystem) cancelBufferedRead(ctx context.Context, record *inodeRecord) {
	publication := replyPublicationFromContext(ctx)
	if publication == nil || record == nil {
		return
	}
	r.mu.Lock()
	for index := len(publication.data) - 1; index >= 0; index-- {
		candidate := publication.data[index]
		if candidate.record != record {
			continue
		}
		publication.data = append(publication.data[:index], publication.data[index+1:]...)
		r.settleDataPublicationLocked(candidate, false)
		break
	}
	r.mu.Unlock()
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
	readOnly := input.Flags&uint32(syscall.O_ACCMODE) == uint32(syscall.O_RDONLY) && input.Flags&uint32(syscall.O_TRUNC) == 0
	dataAdmitted := false
	if readOnly {
		dataAdmitted = r.beginBufferedRead(ctx, record)
		if !dataAdmitted {
			return fuse.EAGAIN
		}
	}
	handle, flags, errno := record.node.Open(ctx, input.Flags)
	if errno != 0 {
		if dataAdmitted {
			r.cancelBufferedRead(ctx, record)
		}
		return fuse.Status(errno)
	}
	id, ok := r.addHandle(record, &handleRecord{file: handle})
	if !ok {
		if dataAdmitted {
			r.cancelBufferedRead(ctx, record)
		}
		r.closeOrphanedFile(ctx, handle)
		return fuse.EIO
	}
	if flags&fuse.FOPEN_KEEP_CACHE == 0 && dataAdmitted {
		r.cancelBufferedRead(ctx, record)
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
	if handle.buffered && !r.beginBufferedRead(ctx, handleRecord.inode) {
		return nil, fuse.EAGAIN
	}
	result, errno := handle.node.Read(ctx, handle, buf, int64(input.Offset))
	if handle.buffered && (errno != 0 || result == nil || result.Size() == 0) {
		r.cancelBufferedRead(ctx, handleRecord.inode)
	}
	return result, fuse.Status(errno)
}

func (r *rawFileSystem) Write(_ <-chan struct{}, input *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	if input == nil || input.Offset > math.MaxInt64 || uint64(len(data)) != uint64(input.Size) || input.Size == 0 || input.Size > r.maxWrite {
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
	if input.WriteFlags&fuse.WRITE_CACHE != 0 || input.WriteFlags&^(uint32(fuse.WRITE_LOCKOWNER)|uint32(fuse.WRITE_KILL_SUIDGID)) != 0 {
		r.mount.revoke(errors.New("fusev3: stock FUSE_WRITE violated the negotiated direct write-through profile"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	return r.writeStock(input, data)
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
		out.Fh, out.OpenFlags = id, fuse.FOPEN_KEEP_CACHE
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
		// Kernel entry validity is always zero. The daemon cache is withdrawn at
		// both coordinates because N lease epochs are not transferable across
		// rename, even though the VFS moves its transient dentry object.
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
		out.Fh, out.OpenFlags = id, 0
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
	r.mount.kernelConnectionTerminated()
}

// kernelConnectionTerminated distinguishes an external unmount from a FUSE
// connection which failed while its namespace mount remained installed.  The
// latter must enter the revocation ladder before OnUnmount returns: Serve
// closes kernelConnectionDone immediately afterwards, and a clean Close racing
// from here could otherwise consume terminal ownership and strand the mount.
func (m *Mount) kernelConnectionTerminated() {
	if m.kernelMount.point != "" {
		if _, err := m.withdrawalOps().absent(m.kernelMount); err != nil {
			m.failAsync(fmt.Errorf(
				"fusev3: FUSE serving connection terminated while its kernel mount remained installed: %w", err))
			return
		}
	}
	// Close waits for kernelConnectionDone, which cannot close until this
	// callback returns.  The proven-absent path therefore remains asynchronous.
	go func() { _ = m.Close() }()
}

// publishAttr answers a stat with the lifetime this mount's cache contract
// allows. It is the attribute-side twin of publishEntry: the same gate, the
// same drain, and the same rule that uncacheable is always a legal answer.
//
// A nonzero lifetime is legal only under the exact reply-local A-R grant. The
// authority recalls that coordinate and waits for this mount's invalidation
// before a conflicting mutation can return.
func (r *rawFileSystem) publishAttr(ctx context.Context, out *fuse.AttrOut, identity publicationIdentity, attr *authoritypb.Attr) {
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		r.mount.revoke(errors.New("fusev3: attribute result escaped its post-VFS reply-publication lifecycle"))
		fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
		out.SetTimeout(0)
		return
	}
	inode := attr.GetInode()
	r.mu.Lock()
	record := r.byIdentityLocked(identity)
	lifetime, coordinate, reservation, cached := r.admitAttrLocked(ctx, inode, identity)
	r.mu.Unlock()
	fillAttr(attr, &out.Attr, r.mount.uid, r.mount.gid)
	out.SetTimeout(lifetime)
	if cached {
		attrGrant, _ := publication.leaseGrant(authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ,
			identity, publicationIdentity{}, "", time.Now())
		objectVersion, snapshot := cacheCandidateVersion(publication)
		publication.attrs = append(publication.attrs, replyAttrPublication{
			inode: inode, identity: identity, record: record, coordinate: coordinate, reservation: reservation,
			lease: leaseStamp{epoch: attrGrant.epoch, issuedSequence: attrGrant.issuedSequence}, attr: proto.Clone(attr).(*authoritypb.Attr),
			objectVersion: objectVersion, snapshot: snapshot,
		})
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
