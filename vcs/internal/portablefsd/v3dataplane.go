package portablefsd

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pathcomponent"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

const (
	v3RootItemID  = uint64(1)
	v3FirstItemID = uint64(2)
	// Item handles and file IDs are independent non-reusing UInt64 domains.
	v3RootFileID   = uint64(1)
	v3FirstFileID  = uint64(2)
	v3FileIDLimit  = uint64(math.MaxUint64)
	v3CookieFloor  = uint64(1) << 63
	v3MaxCookies   = 1 << 16
	v3MaxLocalRead = pfslocal.MaxFrameBytes - 1024
	// FSKit does not expose the kernel's per-call killpriv decision, so every
	// non-empty write requests the safe HANDLE_KILLPRIV_V2 behavior.
	v3WriteFlagKillSUIDGID uint32 = 1 << 2
)

// v3DataPlaneClient is the SDK-independent authority surface needed by the
// pfslocal adapter. Credentials and attach/resume state remain wholly inside
// authorityrpc.Client and are never copied into the local socket protocol.
type v3DataPlaneClient interface {
	v3SessionClient
	Root() *authoritypb.Item
	IOLimits() (uint32, uint32)
	SessionLease() time.Duration
	DataPlaneOperationLimit() int
	// KeepAlive renews the session and returns its validated relative cache
	// proof (see authorityrpc.Client.KeepAlive).
	KeepAlive(context.Context) (time.Duration, error)
	// AuthorizationDeadline is the currently installed signed deadline.
	AuthorizationDeadline() time.Time
	// BeginLocalPublication and LocalAdmissionOpen are the client's immediate
	// admission boundary for replies served from daemon state.
	BeginLocalPublication(func(error)) (authorityrpc.ResponseConsumption, error)
	LocalAdmissionOpen() bool
	CallRead(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallReadRetained(context.Context, *authoritypb.Request, func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error)
	CallMutationWithIdentity(context.Context, *authoritypb.Request, authorityrpc.MutationAssigned) (*authoritypb.Response, error)
	CallMutationWithIdentityRetained(context.Context, *authoritypb.Request, authorityrpc.MutationAssigned, func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error)
}

type v3DataPlaneConfig struct {
	Client         v3DataPlaneClient
	VolumeID       string
	VolumeName     string
	ItemGeneration uint64
	PrincipalUID   uint32
	PrincipalGID   uint32
	// Clock reads the sleep-inclusive continuous clock in nanoseconds; nil is
	// the platform clock. Tests inject a controlled one.
	Clock func() (uint64, error)
}

// v3ItemRecord is one retained authority item capability. A record is live
// exactly while it is reachable from both itemsByID and itemsByIdentity;
// retirement detaches it from both before its capability is reclaimed, so a
// concurrent lookup of the same file interns a fresh record under a new handle
// and the retired record's completion cannot touch it.
type v3ItemRecord struct {
	item  pfslocal.Item
	token []byte
	// fileID, inode, and kind are fixed by the stable identity.
	fileID uint64
	inode  uint64
	kind   authoritypb.Attr_Kind
	root   bool
	// accepted means at least one completed frontend callback owns this local
	// item. provisional counts resource-bearing replies whose final framework
	// verdict has not arrived.
	accepted    bool
	provisional uint32
	// Metadata cache state (see v3cache.go). attr is the retained observation
	// and valid says whether it may serve a hit; version is the last accepted
	// object version, and snapshot is the observation's storage snapshot while
	// valid or the minimum admissible snapshot while not. bindings contains the
	// observed names for the record. A directory also caches remembered
	// children, authoritative absences, and its name watermark. Everything here
	// lives exactly as long as the record and is protected by v3DataPlane.mu.
	attr      *authoritypb.Attr
	valid     bool
	version   uint64
	snapshot  uint64
	bindings  map[v3Binding]struct{}
	children  map[string]*v3ItemRecord
	negatives map[string]struct{}
	watermark uint64
	// mkdirWitness retains only the evaluated permission and exact committed
	// snapshot; completeness consumes it only at an unsuperseded cut.
	mkdirWitness  *v3MkdirWitness
	complete      *v3DirectoryCertificate
	permissionCut uint64
	// Only proven permission at the current cut authorizes absence; unknown
	// and denied both leave searchPermitted false.
	searchPermitted bool
}

// v3MkdirWitness is the authority's evaluated observation at creation.
type v3MkdirWitness struct {
	identity        [16]byte
	snapshot        uint64
	searchPermitted bool
}

// v3Binding names one coordinate in an exact parent incarnation. Both the
// parent's children and the child's bindings contain it, or neither does.
type v3Binding struct {
	parent *v3ItemRecord
	name   string
}

// v3ParentBinding is one live parent of a record: the parent's ownership
// handle and its file ID.
type v3ParentBinding struct {
	item   pfslocal.Item
	fileID uint64
}

func v3ParentOf(parent *v3ItemRecord) *v3ParentBinding {
	if parent == nil {
		return nil
	}
	return &v3ParentBinding{item: parent.item, fileID: parent.fileID}
}

type v3HandleRecord struct {
	mu    sync.RWMutex
	id    uint64
	token []byte
	// item is the full identity of the item the handle was opened on.
	item   pfslocal.Item
	append bool
}

type v3ReplyResourceCollector struct {
	reservation          *v3PendingReservation
	d                    *v3DataPlane
	items                []*v3ItemRecord
	handles              []*v3HandleRecord
	responseConsumptions []authorityrpc.ResponseConsumption
	visible              bool
	err                  error
	taken                bool
	// cached is set when the reply came from the metadata cache; the frontend
	// revalidates it at the physical write boundary. bypassCache forces the
	// coherent authority path for a retry after a refused revalidation.
	cached      *v3CachedReply
	bypassCache bool
}

type v3ReplyResourceContextKey struct{}

type v3ResponseConsumptionRevoker func(error)
type v3ResponseConsumptionRevokerContextKey struct{}

type v3ProvisionalResources struct {
	reservation          *v3PendingReservation
	settled              bool
	d                    *v3DataPlane
	items                []*v3ItemRecord
	handles              []*v3HandleRecord
	responseConsumptions []authorityrpc.ResponseConsumption
	visible              bool
}

type v3CookieRecord struct {
	dirID    uint64
	handleID uint64
	cookie   []byte
	verifier []byte
	batchID  uint64
}

type v3CookieBatch struct {
	dirID    uint64
	handleID uint64
	cookies  []uint64
	order    *list.Element
}

type v3DataPlane struct {
	client v3DataPlaneClient
	cfg    v3DataPlaneConfig
	bridge *v3CoherenceBridge

	ctx    context.Context
	cancel context.CancelFunc
	ops    chan struct{}

	// rootIdentity is fixed before the data plane is shared.
	rootIdentity [16]byte
	releases     *v3ReleaseOwner
	// Serialize release verdicts with the transfer to exact-absence teardown.
	releaseMu           sync.Mutex
	releaseSessionOwned bool
	// Pending requests, including abandoned cleanup, cover at most 2*1024
	// tokens. The release owner's accepted batches add at most 2*B; accepted
	// live items and descriptions remain independently charged to their owners.
	pending       *v3PendingBudget
	cacheCounters v3CacheCounters

	mu              sync.Mutex
	terminal        error
	itemsByID       map[uint64]*v3ItemRecord
	itemsByIdentity map[[16]byte]*v3ItemRecord
	// coldFloor is C, the greatest validated mutation snapshot processed,
	// starting at the storage baseline 1. A newly interned record cannot adopt
	// a sample older than it (see v3cache.go). Reclaim never lowers it.
	coldFloor uint64
	// Positive bindings have an independent mount-wide count and byte bound;
	// none owns an additional item capability.
	bindingDirs  map[*v3ItemRecord]struct{}
	bindingNames int
	bindingBytes int
	// negativeDirs indexes directories holding cached absences, bounded in
	// total by negativeNames and negativeBytes.
	negativeDirs    map[*v3ItemRecord]struct{}
	negativeNames   int
	negativeBytes   int
	completeDirs    int
	completeNames   int
	completeBytes   int
	nextItemID      uint64
	handles         map[uint64]*v3HandleRecord
	nextHandleID    uint64
	cookies         map[uint64]v3CookieRecord
	cookieBatches   map[uint64]*v3CookieBatch
	cookieOrder     list.List
	nextCookieID    uint64
	nextCookieBatch uint64
	nameMax         uint32
	maxRead         uint32
	maxWrite        uint32
	reauthMu        sync.Mutex
	reauthSequence  uint64
	// The cache-serving horizon, on the continuous clock. horizon is the latest
	// instant an explicit KeepAlive proof of this session/epoch makes safe; zero
	// means no usable proof.
	// authorizationDeadline is the installed signed deadline, an additional
	// wall-clock denial check (zero: none). All are protected by mu.
	renewalMu             sync.Mutex
	clock                 func() (uint64, error)
	clockFault            error
	horizon               uint64
	authorizationDeadline time.Time

	failOnce sync.Once

	// testBeforeHandleLock runs between resolving a handle pointer and taking
	// its shared lock, the window a competing Close can win. Nil in production.
	testBeforeHandleLock func(*v3HandleRecord)
}

type v3ReauthorizingClient interface {
	Reauthorize(context.Context, []byte, uint64) (time.Time, error)
}

type v3SessionIdentityClient interface {
	AuthorizationSessionID() volumeserver.SessionID
}

func (d *v3DataPlane) authorizationSessionID() string {
	client, ok := d.client.(v3SessionIdentityClient)
	if !ok {
		return ""
	}
	id := client.AuthorizationSessionID()
	if id == (volumeserver.SessionID{}) {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(id[:])
}

func (d *v3DataPlane) reauthorize(ctx context.Context, token []byte, sequence uint64) (time.Time, error) {
	client, ok := d.client.(v3ReauthorizingClient)
	if !ok {
		return time.Time{}, syscall.EOPNOTSUPP
	}
	d.reauthMu.Lock()
	defer d.reauthMu.Unlock()
	if sequence < d.reauthSequence || sequence > d.reauthSequence+1 {
		return time.Time{}, errors.New("reauthorization sequence is not current or exactly next")
	}
	deadline, err := client.Reauthorize(ctx, token, sequence)
	if err == nil && !deadline.After(time.Now()) {
		err = errors.New("reauthorization returned an expired deadline")
	}
	d.mu.Lock()
	if err == nil {
		d.authorizationDeadline = deadline
		if d.bridge != nil {
			d.bridge.publishCacheHorizon(d.horizon, uint64(deadline.UnixNano()))
		}
	}
	d.mu.Unlock()
	if err != nil {
		return time.Time{}, err
	}
	d.reauthSequence = sequence
	return deadline, nil
}

func newV3DataPlane(parent context.Context, cfg v3DataPlaneConfig) (*v3DataPlane, error) {
	if parent == nil || cfg.Client == nil || cfg.VolumeID == "" || cfg.VolumeName == "" ||
		cfg.ItemGeneration == 0 {
		return nil, errors.New("portablefsd: complete branchless v3 data-plane configuration is required")
	}
	limit := cfg.Client.DataPlaneOperationLimit()
	if limit < 1 {
		return nil, errors.New("portablefsd: v3 authority has no operation capacity after visibility and liveness reserves")
	}
	maxRead, maxWrite := cfg.Client.IOLimits()
	if maxRead == 0 || maxWrite == 0 {
		return nil, errors.New("portablefsd: v3 authority omitted I/O limits")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = v3ContinuousNanos
	}
	if _, err := clock(); err != nil {
		return nil, fmt.Errorf("portablefsd: v3 data plane needs a sleep-inclusive continuous clock: %w", err)
	}
	if _, usable := v3HorizonCandidate(0, min(cfg.Client.SessionLease(), authorityrpc.MaxCacheProof)); !usable {
		return nil, fmt.Errorf("portablefsd: v3 session lease %s cannot carry a usable cache proof", cfg.Client.SessionLease())
	}
	ctx, cancel := context.WithCancel(parent)
	d := &v3DataPlane{
		client: cfg.Client, cfg: cfg, ctx: ctx, cancel: cancel, clock: clock,
		ops: make(chan struct{}, limit), itemsByID: make(map[uint64]*v3ItemRecord),
		itemsByIdentity: make(map[[16]byte]*v3ItemRecord), nextItemID: v3FirstItemID, coldFloor: 1,
		bindingDirs: make(map[*v3ItemRecord]struct{}), negativeDirs: make(map[*v3ItemRecord]struct{}),
		handles: make(map[uint64]*v3HandleRecord), nextHandleID: 1,
		cookies: make(map[uint64]v3CookieRecord), cookieBatches: make(map[uint64]*v3CookieBatch),
		nextCookieID: v3CookieFloor, nextCookieBatch: 1,
		nameMax: 255, maxRead: maxRead, maxWrite: maxWrite,
		authorizationDeadline: cfg.Client.AuthorizationDeadline(),
	}
	d.pending = newV3PendingBudget(v3PendingRequestLimit)
	d.releases = newV3ReleaseOwner(v3ReleaseLimit(maxWrite), d.sendReleaseBatch)
	bridge, err := newV3CoherenceBridge(cfg.Client, d.recordTerminal)
	if err != nil {
		cancel()
		return nil, err
	}
	d.bridge = bridge
	root, err := d.installRoot(cfg.Client.Root())
	if err != nil {
		d.abandonBeforeMount(err)
		return nil, err
	}
	if root.attr.GetKind() != authoritypb.Attr_DIRECTORY {
		err := errors.New("portablefsd: authority root is not a directory")
		d.abandonBeforeMount(err)
		return nil, err
	}
	// StatFS is a read-only attach preflight. It gives the frontend the actual
	// name bound before any operation can be admitted.
	response, callErr := cfg.Client.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}}})
	if callErr != nil || response == nil || response.GetUncertain() || response.GetErrno() != 0 || response.GetStatFs() == nil {
		err := fmt.Errorf("portablefsd: v3 statfs preflight failed: response=%v error=%w", response, callErr)
		d.abandonBeforeMount(err)
		return nil, err
	}
	if response.GetStatFs().GetNameMax() == 0 {
		err := errors.New("portablefsd: authority statfs omitted NAME_MAX")
		d.abandonBeforeMount(err)
		return nil, err
	}
	d.nameMax = response.GetStatFs().GetNameMax()
	if err := d.renewHorizon(ctx); err != nil {
		d.abandonBeforeMount(err)
		return nil, fmt.Errorf("initial authority cache proof: %w", err)
	}
	d.mu.Lock()
	usable := d.cacheAdmissionLocked() == v3CacheHit
	d.mu.Unlock()
	if !usable {
		err := errors.New("initial authority proof is unusable")
		d.abandonBeforeMount(err)
		return nil, err
	}
	go d.keepAlive()
	return d, nil
}

func (d *v3DataPlane) installRoot(candidate *authoritypb.Item) (*v3ItemRecord, error) {
	identity, err := authorityIdentity(candidate)
	if err != nil {
		return nil, err
	}
	// The root is recognized by its activated identity, never by its physical
	// inode number, wherever a file ID is derived.
	d.rootIdentity = identity
	record, err := d.recordFromAuthority(candidate, v3RootItemID)
	if err != nil {
		return nil, err
	}
	record.root = true
	record.accepted = true
	// Activation attrs render the attach's bootstrap root only. They carry no
	// storage stamp, so the first coherent GetAttr or applicable PostState is
	// what makes the root cacheable.
	record.attr = cloneAuthorityAttr(candidate.GetAttr())
	record.snapshot, record.watermark = d.coldFloor, d.coldFloor
	d.mu.Lock()
	d.itemsByID[record.item.ItemID] = record
	d.itemsByIdentity[record.item.StableIdentity] = record
	d.mu.Unlock()
	return record, nil
}

func (d *v3DataPlane) resolveReply() *pfslocal.ResolveReply {
	d.mu.Lock()
	root := d.itemsByID[v3RootItemID]
	nameMax := d.nameMax
	var rootAttr *authoritypb.Attr
	if root != nil {
		rootAttr = root.attr
	}
	d.mu.Unlock()
	if root == nil {
		return nil
	}
	preferred := min(d.maxRead, d.maxWrite)
	attr, _ := d.localAttr(root, rootAttr, nil)
	return &pfslocal.ResolveReply{
		Root: root.item, RootAttr: attr, VolumeID: d.cfg.VolumeID,
		VolumeName: d.cfg.VolumeName,
		Capabilities: pfslocal.Capabilities{
			MaxNameBytes: nameMax, MaxFileSize: math.MaxInt64, PreferredIOSize: preferred,
		},
	}
}

func (d *v3DataPlane) dispatchFrontend(
	ctx context.Context,
	operationID uint64,
	body any,
) (any, int32) {
	if ctx == nil || body == nil {
		return nil, darwinEINVAL
	}
	if v3RequestProducesResources(body) {
		collector, _ := ctx.Value(v3ReplyResourceContextKey{}).(*v3ReplyResourceCollector)
		if collector == nil || collector.d != d || collector.taken || collector.reservation != nil {
			return d.malformed("resource request has no unique reservation owner")
		}
		admissionCtx := ctx
		if original, ok := ctx.Value(v3PendingAdmissionContextKey{}).(context.Context); ok {
			admissionCtx = original
		}
		reservation, err := d.pending.reserve(admissionCtx)
		if err != nil {
			return nil, v3LocalErrno(err)
		}
		collector.reservation = reservation
	}
	if err := d.bridge.readyForOperations(); err != nil {
		if errors.Is(err, syscall.EAGAIN) {
			return nil, darwinEAGAIN
		}
		return nil, darwinEIO
	}
	select {
	case d.ops <- struct{}{}:
		defer func() { <-d.ops }()
	case <-ctx.Done():
		return nil, v3LocalErrno(ctx.Err())
	case <-d.ctx.Done():
		return nil, darwinEIO
	}
	if err := d.terminalError(); err != nil {
		return nil, darwinEIO
	}
	switch request := body.(type) {
	case *pfslocal.LookupRequest:
		return d.lookup(ctx, operationID, request)
	case *pfslocal.EnumerateEntriesRequest:
		return d.enumerateEntries(ctx, operationID, request)
	case *pfslocal.GetAttrRequest:
		return d.getattr(ctx, operationID, request)
	case *pfslocal.SetAttrRequest:
		return d.setattr(ctx, operationID, request)
	case *pfslocal.OpenRequest:
		return d.open(ctx, operationID, request)
	case *pfslocal.CloseRequest:
		return d.closeHandle(ctx, operationID, request)
	case *pfslocal.ReadRequest:
		return d.read(ctx, operationID, request)
	case *pfslocal.WriteRequest:
		return d.write(ctx, operationID, request)
	case *pfslocal.CreateRequest:
		return d.create(ctx, operationID, request)
	case *pfslocal.MkdirRequest:
		return d.mkdir(ctx, operationID, request)
	case *pfslocal.RemoveRequest:
		return d.remove(ctx, operationID, request)
	case *pfslocal.RenameRequest:
		return d.rename(ctx, operationID, request)
	case *pfslocal.SymlinkRequest:
		return d.symlink(ctx, operationID, request)
	case *pfslocal.ReadlinkRequest:
		return d.readlink(ctx, operationID, request)
	case *pfslocal.HardLinkRequest:
		return d.hardlink(ctx, operationID, request)
	case *pfslocal.XattrGetRequest:
		return d.xattrGet(ctx, operationID, request)
	case *pfslocal.XattrListRequest:
		return d.xattrList(ctx, operationID, request)
	case *pfslocal.XattrRemoveRequest:
		return d.xattrRemove(ctx, operationID, request)
	case *pfslocal.StatfsRequest:
		return d.statfs(ctx)
	case *pfslocal.ReclaimRequest:
		return d.reclaim(ctx, request)
	case *pfslocal.SyncVolumeRequest:
		return d.syncVolume(ctx)
	case *pfslocal.SubscribeEventsRequest:
		return nil, darwinENOTSUP
	default:
		return nil, darwinENOTSUP
	}
}

func (d *v3DataPlane) lookup(ctx context.Context, operationID uint64, request *pfslocal.LookupRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 || !pathcomponent.ValidName(request.Name) {
		if errno == 0 {
			errno = darwinEINVAL
		}
		return nil, errno
	}
	if reply, errno, hit := d.serveCachedLookup(ctx, operationID, parent, string(request.Name)); hit {
		return reply, errno
	}
	response, errno := d.callNonVisibleMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name)}}})
	if errno != 0 {
		return nil, d.settleNameErrno(parent, request.Name, errno)
	}
	if response.GetLookup() == nil {
		return d.malformed("lookup omitted reply")
	}
	// A negative lookup is a successful answer, not a missing one: errno 0, no
	// item, and the storage snapshot at which the name was proved absent. That
	// coherent sample may fill a negative entry through this exact parent; an
	// EACCES, ESTALE, cancellation, or transport error never does.
	item := response.GetLookup().GetItem()
	if item == nil {
		snapshot := response.GetLookup().GetNegativeSnapshotSequence()
		if snapshot == 0 {
			return d.malformed("lookup omitted both its item and its negative snapshot sequence")
		}
		d.mu.Lock()
		d.fillLookupLocked(parent, string(request.Name), nil, snapshot)
		d.mu.Unlock()
		return nil, darwinENOENT
	}
	if err := v3ReadStamp(item.GetObjectVersion(), item.GetSnapshotSequence()); err != nil {
		return d.malformed("lookup " + err.Error())
	}
	// Adoption of the returned capability is separate from cache application:
	// a capability for an identity the cold floor has overtaken is still owned,
	// but its stale attributes and name are not cached.
	record, errno := d.intern(ctx, item)
	if errno != 0 {
		return nil, errno
	}
	d.mu.Lock()
	var err error
	if d.terminal == nil && d.itemsByID[record.item.ItemID] == record {
		err = d.observeLocked(record, item.GetAttr(), item.GetObjectVersion(), item.GetSnapshotSequence())
	}
	if err == nil {
		d.fillLookupLocked(parent, string(request.Name), record, item.GetSnapshotSequence())
	}
	d.mu.Unlock()
	if err != nil {
		return d.malformed(err.Error())
	}
	// A rejected fill does not rewrite the result of this RPC.
	attr, err := d.localAttr(record, item.GetAttr(), v3ParentOf(parent))
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.LookupReply{Attr: attr}, 0
}

func (d *v3DataPlane) getattr(ctx context.Context, operationID uint64, request *pfslocal.GetAttrRequest) (any, int32) {
	item, errno := d.item(request.Item)
	if errno != 0 {
		return nil, errno
	}
	var handle *v3HandleRecord
	if request.Handle != 0 {
		var release func()
		handle, release, errno = d.acquireHandle(request.Handle, item)
		if errno != 0 {
			return nil, errno
		}
		defer release()
	}
	attr, errno := d.currentAttr(ctx, operationID, item, handle)
	if errno != 0 {
		return nil, errno
	}
	return &pfslocal.GetAttrReply{Attr: attr}, 0
}

// currentAttr is the one attribute retrieval path for GetAttr, a no-op
// SetAttr, and a zero-length Write. A non-nil handle is held under its shared
// lock by the caller, so no path here reacquires it behind a waiting Close.
func (d *v3DataPlane) currentAttr(ctx context.Context, operationID uint64, item *v3ItemRecord, handle *v3HandleRecord) (pfslocal.Attr, int32) {
	if attr, hit, errno := d.serveCachedAttr(ctx, operationID, item, handle); hit {
		return attr, errno
	}
	query := &authoritypb.GetAttrRequest{Item: cloneBytesV3(item.token)}
	if handle != nil {
		query.Handle = cloneBytesV3(handle.token)
	}
	response, errno := d.callRead(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: query}})
	if errno != 0 {
		return pfslocal.Attr{}, errno
	}
	reply := response.GetGetAttr()
	if reply == nil || reply.GetAttr() == nil {
		_, errno := d.malformed("getattr omitted attr")
		return pfslocal.Attr{}, errno
	}
	if err := v3ReadStamp(reply.GetObjectVersion(), reply.GetSnapshotSequence()); err != nil {
		_, errno := d.malformed("getattr " + err.Error())
		return pfslocal.Attr{}, errno
	}
	attr, err := d.localAttr(item, reply.GetAttr(), d.parentOf(item))
	if err == nil {
		err = d.observeHeld(item, reply.GetAttr(), reply.GetObjectVersion(), reply.GetSnapshotSequence())
	}
	if err != nil {
		_, errno := d.malformed(err.Error())
		return pfslocal.Attr{}, errno
	}
	return attr, 0
}

func (d *v3DataPlane) setattr(ctx context.Context, operationID uint64, request *pfslocal.SetAttrRequest) (any, int32) {
	item, errno := d.item(request.Item)
	if errno != 0 {
		return nil, errno
	}
	if request.SetFlags {
		return nil, darwinENOTSUP
	}
	set := &authoritypb.SetAttrRequest{Item: cloneBytesV3(item.token), Mode: request.Mode}
	if request.UID != nil && *request.UID != d.cfg.PrincipalUID {
		return nil, darwinEPERM
	}
	if request.GID != nil && *request.GID != d.cfg.PrincipalGID {
		return nil, darwinEPERM
	}
	if request.Size != nil {
		if *request.Size > math.MaxInt64 {
			return nil, darwinEFBIG
		}
		v := int64(*request.Size)
		set.Size = &v
	}
	var ok bool
	if request.MtimeMs != nil {
		set.MtimeNs, ok = millisToNanos(request.MtimeMs)
		if !ok {
			return nil, darwinEOVERFLOW
		}
	}
	if request.AtimeMs != nil {
		set.AtimeNs, ok = millisToNanos(request.AtimeMs)
		if !ok {
			return nil, darwinEOVERFLOW
		}
	}
	var handle *v3HandleRecord
	if request.Handle != 0 {
		var release func()
		handle, release, errno = d.acquireHandle(request.Handle, item)
		if errno != 0 {
			return nil, errno
		}
		defer release()
		set.Handle = cloneBytesV3(handle.token)
	}
	if set.Mode == nil && set.Size == nil && set.MtimeNs == nil && set.AtimeNs == nil {
		attr, errno := d.currentAttr(ctx, operationID, item, handle)
		if errno != 0 {
			return nil, errno
		}
		return &pfslocal.SetAttrReply{Attr: attr}, 0
	}
	gate, err := v3ItemSourceGate(item.item, set.Size != nil)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno, finish := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: set}}, gate)
	defer finish()
	if errno != 0 {
		return nil, errno
	}
	effect, target, err := v3TargetEffect(response.GetPostState(), item)
	if err == nil {
		err = errors.Join(v3ReplyBody(response, nil), d.representableEffect(effect))
	}
	if err != nil {
		return d.malformed("setattr " + err.Error())
	}
	if set.Mode != nil || set.Uid != nil || set.Gid != nil {
		effect.permissionTarget = item
	}
	if err := d.applyMutation(effect); err != nil {
		return d.malformed(err.Error())
	}
	attr, err := d.localAttr(item, target.GetAttr(), d.parentOf(item))
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.SetAttrReply{Attr: attr}, 0
}

func (d *v3DataPlane) open(ctx context.Context, _ uint64, request *pfslocal.OpenRequest) (any, int32) {
	item, errno := d.item(request.Item)
	if errno != 0 {
		return nil, errno
	}
	flags, ok := v3OpenFlags(request.Mode, request.Append)
	if !ok {
		return nil, darwinEINVAL
	}
	response, errno := d.callNonVisibleMutation(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytesV3(item.token), Flags: flags}}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetOpen() == nil || len(response.GetOpen().GetHandle()) != 16 {
		return d.malformed("open omitted its authority handle")
	}
	handle, err := d.installHandle(response.GetOpen().GetHandle(), item.item, request.Append)
	if err != nil {
		return d.malformed(err.Error())
	}
	collectV3ReplyHandle(ctx, handle)
	return &pfslocal.OpenReply{Handle: handle.id}, 0
}

// closeHandle ends local handle ownership and transfers the authority close to
// the release owner. Close is not fsync: a successful reply means the handle is
// retired locally and its release was accepted; a later release failure ends
// the mount instead of being reported against this callback.
func (d *v3DataPlane) closeHandle(ctx context.Context, _ uint64, request *pfslocal.CloseRequest) (any, int32) {
	d.mu.Lock()
	handle := d.handles[request.Handle]
	retired := request.Handle != 0 && request.Handle < d.nextHandleID
	d.mu.Unlock()
	if handle == nil {
		if retired {
			return &pfslocal.CloseReply{Retired: true}, 0
		}
		return nil, darwinEBADF
	}
	// The exclusive lock waits for every admitted call on this handle. Each of
	// them revalidated liveness under its shared lock, so none can use the token
	// after it leaves the index below.
	handle.mu.Lock()
	defer handle.mu.Unlock()
	reservation, err := d.releases.reserve(ctx, 1)
	if err != nil && !errors.Is(err, errV3ReleaseClosed) {
		return nil, v3ReleaseErrno(err)
	}
	if !d.detachHandle(handle) {
		// A duplicate Close or an abandoned disposition already retired it.
		reservation.cancel()
		return &pfslocal.CloseReply{Retired: true}, 0
	}
	reservation.commit([][]byte{handle.token}, nil)
	return &pfslocal.CloseReply{Retired: true}, 0
}

// detachHandle removes a live handle and its directory cookies from every
// local index, exactly once.
func (d *v3DataPlane) detachHandle(handle *v3HandleRecord) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.detachHandleLocked(handle)
}

func (d *v3DataPlane) detachHandleLocked(handle *v3HandleRecord) bool {
	if d.handles[handle.id] != handle {
		return false
	}
	delete(d.handles, handle.id)
	for batchID, batch := range d.cookieBatches {
		if batch.handleID == handle.id {
			d.removeCookieBatchLocked(batchID)
		}
	}
	return true
}

// v3ReleaseErrno maps a refused release reservation. Nothing was detached, so
// a canceled or expired callback may retry; the remaining refusal is the
// owner's sticky failure, which has already ended the mount.
func v3ReleaseErrno(err error) int32 {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return v3LocalErrno(err)
	}
	return darwinEIO
}

func (d *v3DataPlane) read(ctx context.Context, operationID uint64, request *pfslocal.ReadRequest) (any, int32) {
	if request.Length > v3MaxLocalRead {
		return nil, darwinEOVERFLOW
	}
	handle, release, errno := d.acquireHandle(request.Handle, nil)
	if errno != 0 {
		return nil, errno
	}
	defer release()
	remaining := request.Length
	offset := request.Offset
	out := make([]byte, 0, request.Length)
	for remaining > 0 {
		chunk := min(remaining, d.maxRead)
		response, errno := d.callRead(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: cloneBytesV3(handle.token), Offset: offset, Length: chunk}}})
		if errno != 0 {
			return nil, errno
		}
		if response.GetRead() == nil || uint32(len(response.GetRead().GetData())) > chunk {
			return d.malformed("read returned an oversized or missing payload")
		}
		data := response.GetRead().GetData()
		out = append(out, data...)
		if uint32(len(data)) < chunk {
			break
		}
		if offset > math.MaxUint64-uint64(len(data)) {
			return nil, darwinEOVERFLOW
		}
		offset += uint64(len(data))
		remaining -= uint32(len(data))
	}
	return &pfslocal.ReadReply{Data: out}, 0
}

// write sends one framework write chunk as one positioned authority WRITE.
// The frontend already bounds chunks by the advertised preferred I/O size, so
// one chunk is one replay mutation with exact short-write semantics: a lost
// reply replays the same mutation and nothing here ever re-sends bytes.
func (d *v3DataPlane) write(ctx context.Context, operationID uint64, request *pfslocal.WriteRequest) (any, int32) {
	size := uint64(len(request.Data))
	if size > uint64(d.maxWrite) {
		return nil, darwinEINVAL
	}
	if request.Offset >= math.MaxInt64 || size > math.MaxInt64-request.Offset {
		return nil, darwinEFBIG
	}
	handle, release, errno := d.acquireHandle(request.Handle, nil)
	if errno != 0 {
		return nil, errno
	}
	defer release()
	item, errno := d.item(handle.item)
	if errno != 0 {
		return d.malformed("write handle lost its item")
	}
	if size == 0 {
		// A zero-length write has no mutation or append-position semantics.
		// The current attributes keep the FSKit reply exact without a mutation.
		attr, errno := d.currentAttr(ctx, operationID, item, handle)
		if errno != 0 {
			return nil, errno
		}
		return &pfslocal.WriteReply{Attr: attr}, 0
	}
	if handle.append || request.Append {
		// FSKit supplies only a kernel-chosen position here; it cannot carry
		// the authority-owned append intent required for atomic cross-client
		// append. Refuse an explicit append bit rather than silently routing it
		// through a positional write. Ordinary macOS O_APPEND remains inside
		// the documented best-effort platform boundary.
		return nil, darwinENOTSUP
	}
	gate, err := v3ItemSourceGate(item.item, true)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno, finish := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
		Handle: cloneBytesV3(handle.token), Position: request.Offset, Size: uint32(size),
		Data: request.Data, WriteFlags: v3WriteFlagKillSUIDGID,
	}}}, gate)
	defer finish()
	if errno != 0 {
		return nil, errno
	}
	// callMutation has recorded the commit; from here every defect is terminal.
	reply := response.GetWrite()
	if reply != nil && reply.GetError() != 0 {
		if reply.GetError() < 0 && reply.GetPostAttr() != nil {
			// A well-formed post-apply outcome ends local serving, but the
			// authority session is intact. Keep its transport so the supervisor
			// can deliver the exact unmount absence proof and release the writer
			// lease; closing it here would strand the volume's Mac membership.
			_ = d.stopServing(fmt.Errorf("portablefsd: authority committed %d write bytes but FSKit cannot publish post-apply errno %d", reply.GetCommittedSize(), -reply.GetError()))
			return nil, darwinEIO
		}
		return d.malformed("write reply carried an errno without a definite shape")
	}
	effect, postAttr, err := v3WriteCommitted(item, request.Offset, size, response)
	if err == nil {
		err = d.representableEffect(effect)
	}
	if err != nil {
		return d.malformed(err.Error())
	}
	if err := d.applyMutation(effect); err != nil {
		return d.malformed(err.Error())
	}
	attr, err := d.localAttr(item, postAttr, d.parentOf(item))
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.WriteReply{Written: uint32(reply.GetCommittedSize()), Attr: attr}, 0
}

// v3WriteRejection recognizes a WRITE the authority recorded but definitely
// did not apply: a negative errno inside the reply, a zero envelope errno, and
// no committed size, offset, or post-state. A post-apply failure always
// carries its post-attr, so the two can never be confused.
func v3WriteRejection(request *authoritypb.Request, response *authoritypb.Response) (int32, bool) {
	reply := response.GetWrite()
	if request.GetWrite() == nil || reply == nil || response.GetErrno() != 0 || response.GetPostState() != nil ||
		reply.GetPostAttr() != nil || reply.GetCommittedSize() != 0 || reply.GetAssignedOffset() != 0 ||
		reply.GetError() > -1 || reply.GetError() < -4095 {
		return 0, false
	}
	return -reply.GetError(), true
}

// v3UnadmittedWrite recognizes the authority's refusal of a WRITE whose reply
// could not be admitted to the replay cache: the rejection shape with ENOMEM
// and no MutationState, because the authority recorded nothing for it.
func v3UnadmittedWrite(request *authoritypb.Request, response *authoritypb.Response) bool {
	if response.GetMutation() != nil || response.GetUncertain() ||
		response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED ||
		len(response.GetTerminalDeliveryToken()) != 0 {
		return false
	}
	errno, rejected := v3WriteRejection(request, response)
	return rejected && errno == errnos.ENOMEM
}

// v3WriteCommitted validates a successful WRITE reply against its request:
// a committed prefix in (0, size] placed exactly at the position, and one
// post-write attr, carried identically in the reply and in the whole
// post-state's single target, this item, that covers the committed bytes.
func v3WriteCommitted(item *v3ItemRecord, position, size uint64, response *authoritypb.Response) (*v3MutationEffect, *authoritypb.Attr, error) {
	reply := response.GetWrite()
	if reply == nil || reply.GetCommittedSize() == 0 || reply.GetCommittedSize() > size ||
		reply.GetAssignedOffset() != position {
		return nil, nil, errors.New("write omitted its exact committed result")
	}
	if item.kind != authoritypb.Attr_REGULAR {
		return nil, nil, errors.New("write post-attr names a different object")
	}
	effect, target, err := v3TargetEffect(response.GetPostState(), item)
	if err != nil {
		return nil, nil, fmt.Errorf("write %w", err)
	}
	postAttr := reply.GetPostAttr()
	if postAttr == nil || !proto.Equal(postAttr, target.GetAttr()) {
		return nil, nil, errors.New("write post-attr is missing or disagrees with its post-state target")
	}
	if postAttr.GetSize() < 0 || uint64(postAttr.GetSize()) < position+reply.GetCommittedSize() {
		return nil, nil, errors.New("write post-attr does not cover the committed bytes")
	}
	return effect, postAttr, nil
}

func (d *v3DataPlane) create(ctx context.Context, operationID uint64, request *pfslocal.CreateRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if !pathcomponent.ValidName(request.Name) {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno, finish := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
		Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Mode: request.Mode,
		Flags: &authoritypb.OpenFlags{Read: true, Write: true, Append: request.Append}, Exclusive: request.Exclusive,
	}}}, gate)
	defer finish()
	if errno != 0 {
		return nil, d.settleNameErrno(parent, request.Name, errno)
	}
	created := response.GetCreate()
	if created == nil || created.GetItem() == nil || len(created.GetHandle()) != 16 {
		return d.malformed("create omitted item or handle")
	}
	identity, err := authorityIdentity(created.GetItem())
	if err != nil {
		return d.malformed(err.Error())
	}
	effect, err := v3BindingEffect(response.GetPostState(), parent, request.Name, created.GetItem(), authoritypb.Attr_REGULAR,
		v3PostStateRoleCreated, v3PostStateRoleTarget)
	if err == nil {
		err = d.representableEffect(effect)
	}
	if err != nil {
		return d.malformed("create " + err.Error())
	}
	record, errno := d.intern(ctx, created.GetItem())
	if errno != 0 {
		return nil, errno
	}
	handle, err := d.installHandle(created.GetHandle(), record.item, request.Append)
	if err != nil {
		return d.malformed(err.Error())
	}
	collectV3ReplyHandle(ctx, handle)
	if err := d.applyMutation(effect); err != nil {
		return d.malformed(err.Error())
	}
	if err := d.bridge.sourcePublication.operationLease(v3Callback(ctx, operationID)).attachBinding(
		gate,
		v3PublicationNamespace{parent: v3PublicationIdentity(parent.item.StableIdentity), name: string(request.Name)},
		v3PublicationIdentity(identity),
	); err != nil {
		return d.malformed(err.Error())
	}
	attr, err := d.localAttr(record, created.GetItem().GetAttr(), v3ParentOf(parent))
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.CreateReply{Attr: attr, Handle: handle.id}, 0
}

func (d *v3DataPlane) mkdir(ctx context.Context, operationID uint64, request *pfslocal.MkdirRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if !pathcomponent.ValidName(request.Name) {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno, finish := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Mode: request.Mode}}}, gate)
	defer finish()
	if errno != 0 {
		return nil, d.settleNameErrno(parent, request.Name, errno)
	}
	record, errno := d.adoptCreated(ctx, operationID, gate, response, parent, request.Name, authoritypb.Attr_DIRECTORY)
	if errno != 0 {
		return nil, errno
	}
	attr, err := d.localAttr(record, response.GetMkdir().GetItem().GetAttr(), v3ParentOf(parent))
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.MkdirReply{Attr: attr}, 0
}

func (d *v3DataPlane) remove(ctx context.Context, operationID uint64, request *pfslocal.RemoveRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if !pathcomponent.ValidName(request.Name) {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno, finish := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Directory: request.Directory}}}, gate)
	defer finish()
	if errno != 0 {
		return nil, d.settleNameErrno(parent, request.Name, errno)
	}
	effect, err := v3RemoveEffect(response.GetPostState(), parent, request.Name, request.Directory)
	if err == nil {
		err = errors.Join(v3ReplyBody(response, nil), d.representableEffect(effect))
	}
	if err != nil {
		return d.malformed("unlink " + err.Error())
	}
	if err := d.applyMutation(effect); err != nil {
		return d.malformed(err.Error())
	}
	if err := d.bridge.sourcePublication.operationLease(v3Callback(ctx, operationID)).resolveNoBinding(
		gate,
		v3PublicationNamespace{parent: v3PublicationIdentity(parent.item.StableIdentity), name: string(request.Name)},
	); err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.RemoveReply{}, 0
}

func (d *v3DataPlane) rename(ctx context.Context, operationID uint64, request *pfslocal.RenameRequest) (any, int32) {
	from, errno := d.item(request.FromDir)
	if errno != 0 {
		return nil, errno
	}
	to, errno := d.item(request.ToDir)
	if errno != 0 {
		return nil, errno
	}
	if !pathcomponent.ValidName(request.FromName) || !pathcomponent.ValidName(request.ToName) {
		return nil, darwinEINVAL
	}
	gate, err := v3RenameSourceGate(from.item, request.FromName, to.item, request.ToName)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno, finish := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
		OldParent: cloneBytesV3(from.token), OldName: cloneBytesV3(request.FromName), NewParent: cloneBytesV3(to.token), NewName: cloneBytesV3(request.ToName), NoReplace: request.NoReplace,
	}}}, gate)
	defer finish()
	if errno != 0 {
		d.settleNameErrno(from, request.FromName, errno)
		return nil, d.settleNameErrno(to, request.ToName, errno)
	}
	rename := response.GetRename()
	if rename == nil {
		return d.malformed("rename omitted its authoritative post-bindings")
	}
	newIdentity, err := requiredV3PublicationIdentity(rename.GetNewPostIdentity(), "rename destination")
	if err != nil {
		return d.malformed(err.Error())
	}
	oldIdentity, oldBound, err := optionalV3PublicationIdentity(rename.GetOldPostIdentity(), "rename source")
	if err != nil {
		return d.malformed(err.Error())
	}
	effect, err := v3RenameEffect(response.GetPostState(), from, request.FromName, to, request.ToName, newIdentity, oldIdentity, oldBound)
	if err == nil {
		err = d.representableEffect(effect)
	}
	if err != nil {
		return d.malformed(err.Error())
	}
	if err := d.applyMutation(effect); err != nil {
		return d.malformed(err.Error())
	}
	lease := d.bridge.sourcePublication.operationLease(v3Callback(ctx, operationID))
	oldNamespace := v3PublicationNamespace{parent: v3PublicationIdentity(from.item.StableIdentity), name: string(request.FromName)}
	newNamespace := v3PublicationNamespace{parent: v3PublicationIdentity(to.item.StableIdentity), name: string(request.ToName)}
	if err := lease.attachBinding(gate, newNamespace, newIdentity); err != nil {
		return d.malformed(err.Error())
	}
	if oldNamespace == newNamespace {
		if oldBound && oldIdentity != newIdentity {
			return d.malformed("same-coordinate rename returned inconsistent post-bindings")
		}
	} else if oldBound {
		if err := lease.attachBinding(gate, oldNamespace, oldIdentity); err != nil {
			return d.malformed(err.Error())
		}
	} else if err := lease.resolveNoBinding(gate, oldNamespace); err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.RenameReply{
		NewPostIdentity: cloneBytesV3(rename.GetNewPostIdentity()),
		OldPostIdentity: cloneBytesV3(rename.GetOldPostIdentity()),
	}, 0
}

// adoptCreated validates a MKDIR or SYMLINK result as a whole, adopts its
// capability, applies its effect, and only then resolves the source claim.
func (d *v3DataPlane) adoptCreated(
	ctx context.Context,
	operationID uint64,
	gate *v3SourceGate,
	response *authoritypb.Response,
	parent *v3ItemRecord,
	name []byte,
	kind authoritypb.Attr_Kind,
) (*v3ItemRecord, int32) {
	created := response.GetLookup().GetItem()
	if kind == authoritypb.Attr_DIRECTORY {
		created = response.GetMkdir().GetItem()
	}
	identity, err := authorityIdentity(created)
	if err != nil {
		_, errno := d.malformed(fmt.Sprintf("%s reply: %v", kind, err))
		return nil, errno
	}
	effect, err := v3BindingEffect(response.GetPostState(), parent, name, created, kind, v3PostStateRoleCreated)
	if err == nil {
		err = d.representableEffect(effect)
	}
	if err != nil {
		_, errno := d.malformed(fmt.Sprintf("%s %v", kind, err))
		return nil, errno
	}
	record, errno := d.intern(ctx, created)
	if errno != 0 {
		return nil, errno
	}
	if kind == authoritypb.Attr_DIRECTORY {
		effect.mkdir = record
		effect.mkdirWitness = &v3MkdirWitness{identity: identity, snapshot: response.GetPostState().GetSnapshotSequence(), searchPermitted: response.GetMkdir().GetChildSearchPermitted()}
	}
	if err := d.applyMutation(effect); err != nil {
		_, errno := d.malformed(err.Error())
		return nil, errno
	}
	if err := d.bridge.sourcePublication.operationLease(v3Callback(ctx, operationID)).attachBinding(
		gate,
		v3PublicationNamespace{parent: v3PublicationIdentity(parent.item.StableIdentity), name: string(name)},
		v3PublicationIdentity(identity),
	); err != nil {
		_, errno := d.malformed(err.Error())
		return nil, errno
	}
	return record, 0
}

func (d *v3DataPlane) symlink(ctx context.Context, operationID uint64, request *pfslocal.SymlinkRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if !pathcomponent.ValidName(request.Name) || bytes.IndexByte(request.Target, 0) >= 0 {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno, finish := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Target: cloneBytesV3(request.Target)}}}, gate)
	defer finish()
	if errno != 0 {
		return nil, d.settleNameErrno(parent, request.Name, errno)
	}
	record, errno := d.adoptCreated(ctx, operationID, gate, response, parent, request.Name, authoritypb.Attr_SYMLINK)
	if errno != 0 {
		return nil, errno
	}
	attr, err := d.localAttr(record, response.GetLookup().GetItem().GetAttr(), v3ParentOf(parent))
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.SymlinkReply{Attr: attr}, 0
}

func (d *v3DataPlane) readlink(ctx context.Context, operationID uint64, request *pfslocal.ReadlinkRequest) (any, int32) {
	item, errno := d.item(request.Item)
	if errno != 0 {
		return nil, errno
	}
	response, errno := d.callRead(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Readlink{Readlink: &authoritypb.ReadlinkRequest{Item: cloneBytesV3(item.token)}}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetReadlink() == nil {
		return d.malformed("readlink omitted target")
	}
	return &pfslocal.ReadlinkReply{Target: cloneBytesV3(response.GetReadlink().GetTarget())}, 0
}

func (d *v3DataPlane) hardlink(ctx context.Context, operationID uint64, request *pfslocal.HardLinkRequest) (any, int32) {
	item, errno := d.item(request.Item)
	if errno != 0 {
		return nil, errno
	}
	parent, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if !pathcomponent.ValidName(request.Name) {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false, item.item)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno, finish := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{ExistingItem: cloneBytesV3(item.token), NewParent: cloneBytesV3(parent.token), NewName: cloneBytesV3(request.Name)}}}, gate)
	defer finish()
	if errno != 0 {
		return nil, d.settleNameErrno(parent, request.Name, errno)
	}
	linked := response.GetLink()
	if linked == nil || linked.GetItem() == nil {
		return d.malformed("hard link omitted item")
	}
	identity, err := authorityIdentity(linked.GetItem())
	if err != nil || identity != item.item.StableIdentity {
		return d.malformed("hard link changed stable identity")
	}
	effect, err := v3BindingEffect(response.GetPostState(), parent, request.Name, linked.GetItem(), item.kind, v3PostStateRoleTarget)
	if err == nil {
		err = d.representableEffect(effect)
	}
	if err != nil {
		return d.malformed("link " + err.Error())
	}
	if errno := d.adoptAlias(item, linked.GetItem()); errno != 0 {
		return nil, errno
	}
	if err := d.applyMutation(effect); err != nil {
		return d.malformed(err.Error())
	}
	if err := d.bridge.sourcePublication.operationLease(v3Callback(ctx, operationID)).attachBinding(
		gate,
		v3PublicationNamespace{parent: v3PublicationIdentity(parent.item.StableIdentity), name: string(request.Name)},
		v3PublicationIdentity(identity),
	); err != nil {
		return d.malformed(err.Error())
	}
	attr, err := d.localAttr(item, linked.GetItem().GetAttr(), v3ParentOf(parent))
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.HardLinkReply{Name: cloneBytesV3(request.Name), Attr: attr}, 0
}

func (d *v3DataPlane) xattrGet(ctx context.Context, operationID uint64, request *pfslocal.XattrGetRequest) (any, int32) {
	item, handle, release, errno := d.itemAndOptionalHandle(request.Item, request.Handle)
	if errno != 0 {
		return nil, errno
	}
	defer release()
	if !validXattrName(request.Name) {
		return nil, darwinEINVAL
	}
	if errno := v3StaticXattrErrno(request.Name); errno != 0 {
		return nil, errno
	}
	query := &authoritypb.GetXattrRequest{Item: cloneBytesV3(item.token), Name: []byte(request.Name)}
	if handle != nil {
		query.Handle = cloneBytesV3(handle.token)
	}
	response, errno := d.callRead(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_GetXattr{GetXattr: query}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetGetXattr() == nil {
		return d.malformed("getxattr omitted value")
	}
	return &pfslocal.XattrGetReply{Value: cloneBytesV3(response.GetGetXattr().GetValue())}, 0
}

func (d *v3DataPlane) xattrList(ctx context.Context, operationID uint64, request *pfslocal.XattrListRequest) (any, int32) {
	item, handle, release, errno := d.itemAndOptionalHandle(request.Item, request.Handle)
	if errno != 0 {
		return nil, errno
	}
	defer release()
	query := &authoritypb.ListXattrRequest{Item: cloneBytesV3(item.token)}
	if handle != nil {
		query.Handle = cloneBytesV3(handle.token)
	}
	response, errno := d.callRead(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_ListXattr{ListXattr: query}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetListXattr() == nil {
		return d.malformed("listxattr omitted reply")
	}
	names := make([]string, 0, len(response.GetListXattr().GetNames()))
	for _, raw := range response.GetListXattr().GetNames() {
		if !utf8.Valid(raw) || !validXattrName(string(raw)) {
			return d.malformed("listxattr returned an invalid name")
		}
		names = append(names, string(raw))
	}
	return &pfslocal.XattrListReply{Names: names}, 0
}

func (d *v3DataPlane) xattrRemove(ctx context.Context, operationID uint64, request *pfslocal.XattrRemoveRequest) (any, int32) {
	item, handle, release, errno := d.itemAndOptionalHandle(request.Item, request.Handle)
	if errno != 0 {
		return nil, errno
	}
	defer release()
	if !validXattrName(request.Name) {
		return nil, darwinEINVAL
	}
	if errno := v3StaticXattrErrno(request.Name); errno != 0 {
		return nil, errno
	}
	query := &authoritypb.RemoveXattrRequest{Item: cloneBytesV3(item.token), Name: []byte(request.Name)}
	if handle != nil {
		query.Handle = cloneBytesV3(handle.token)
	}
	gate, err := v3ItemSourceGate(item.item, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno, finish := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: query}}, gate)
	defer finish()
	if errno != 0 {
		return nil, errno
	}
	effect, _, err := v3TargetEffect(response.GetPostState(), item)
	if err == nil {
		err = errors.Join(v3ReplyBody(response, nil), d.representableEffect(effect))
	}
	if err != nil {
		return d.malformed("removexattr " + err.Error())
	}
	if err := d.applyMutation(effect); err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.XattrRemoveReply{}, 0
}

func (d *v3DataPlane) statfs(ctx context.Context) (any, int32) {
	response, errno := d.callRead(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}}})
	if errno != 0 {
		return nil, errno
	}
	stat := response.GetStatFs()
	if stat == nil || stat.GetBlockSize() == 0 {
		return d.malformed("statfs omitted reply")
	}
	return &pfslocal.StatfsReply{BlockSize: stat.GetBlockSize(), TotalBlocks: stat.GetBlocks(), FreeBlocks: stat.GetBlocksAvailable(), TotalFiles: stat.GetFiles(), FreeFiles: stat.GetFilesFree()}, 0
}

func (d *v3DataPlane) syncVolume(ctx context.Context) (any, int32) {
	response, errno := d.callNonVisibleMutation(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_SyncFs{SyncFs: &authoritypb.SyncFSRequest{}}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetSyncFs() == nil {
		return d.malformed("syncfs barrier omitted reply")
	}
	return &pfslocal.SyncVolumeReply{}, 0
}

// reclaim retires the frontend's ownership of an item. The reply follows local
// retirement and the release owner's acceptance of the capability, not its
// authority round trip, so serial kernel reclamation proceeds at local speed.
func (d *v3DataPlane) reclaim(ctx context.Context, request *pfslocal.ReclaimRequest) (any, int32) {
	record, errno := d.item(request.Item)
	if errno != 0 {
		if errno == darwinESTALE {
			return &pfslocal.ReclaimReply{}, 0
		}
		return nil, errno
	}
	if record.root {
		return &pfslocal.ReclaimReply{}, 0
	}
	reservation, err := d.releases.reserve(ctx, 1)
	if err != nil && !errors.Is(err, errV3ReleaseClosed) {
		return nil, v3ReleaseErrno(err)
	}
	d.mu.Lock()
	if d.itemsByID[record.item.ItemID] != record {
		d.mu.Unlock()
		reservation.cancel()
		return &pfslocal.ReclaimReply{}, 0
	}
	if record.provisional != 0 {
		// The current FSItem is gone, but an overlapping resource reply may be
		// about to transfer the same canonical local item back into VolumeCore.
		// Leave the authority capability live until that exact disposition; the
		// final abandon reclaims it, while an accept becomes its new owner.
		record.accepted = false
		d.mu.Unlock()
		reservation.cancel()
		return &pfslocal.ReclaimReply{}, 0
	}
	d.detachItemLocked(record)
	d.mu.Unlock()
	reservation.commit(nil, [][]byte{record.token})
	return &pfslocal.ReclaimReply{}, 0
}

// detachItemLocked retires a record from every local index before its
// capability is reclaimed. Every observed name goes with it, and a retired
// directory takes every name, absence, and child parent reference beneath it,
// so nothing can render or fill through the old local handle. d.mu must be
// held.
func (d *v3DataPlane) detachItemLocked(record *v3ItemRecord) {
	delete(d.itemsByID, record.item.ItemID)
	delete(d.itemsByIdentity, record.item.StableIdentity)
	for binding := range record.bindings {
		d.dropBindingLocked(binding.parent, binding.name)
	}
	d.forgetNamesLocked(record)
	d.dropCompletenessLocked(record)
	for batchID, batch := range d.cookieBatches {
		if batch.dirID == record.item.ItemID {
			d.removeCookieBatchLocked(batchID)
		}
	}
}

// enumerateEntries lists one directory page as non-owning entry snapshots.
// The authority is asked for no Items, so the listing transfers and retains no
// capability: an entry is a name, a file ID, and attributes, and a later
// lookup of it acquires its own ownership handle.
func (d *v3DataPlane) enumerateEntries(ctx context.Context, operationID uint64, request *pfslocal.EnumerateEntriesRequest) (any, int32) {
	dir, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if request.MaxEntries == 0 || request.MaxEntries > 4096 {
		return nil, darwinEINVAL
	}
	handle, release, errno := d.acquireHandle(request.Handle, dir)
	if errno != 0 {
		return nil, errno
	}
	defer release()
	// Authority enumeration cookies are positions on one retained XFS open
	// directory description. Keep that exact handle alive and immutable across
	// the read: opening a fresh authority handle for each pfslocal page resets
	// its cursor high-water mark to zero, so every nonzero continuation is
	// correctly rejected as ESTALE. FSKit already gives directory walks an
	// open/close lifecycle; VolumeCore carries that existing read handle here.
	var position v3CookieRecord
	if request.Cookie != 0 {
		var ok bool
		position, ok = d.resolveCookie(dir.item.ItemID, request.Handle, request.Cookie)
		if !ok {
			return nil, darwinESTALE
		}
	}
	response, errno := d.callNonVisibleMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{
		Handle: cloneBytesV3(handle.token), Cookie: cloneBytesV3(position.cookie), Verifier: cloneBytesV3(position.verifier), MaxEntries: request.MaxEntries,
	}}})
	if errno != 0 {
		return nil, errno
	}
	page := response.GetReadDir()
	if page == nil || len(page.GetVerifier()) != 16 || len(page.GetEntries()) == 0 && !page.GetEof() {
		return d.malformed("readdir returned a malformed page")
	}
	reply := &pfslocal.EnumerateEntriesReply{DirVersion: v3VerifierVersion(page.GetVerifier())}
	positions := make([]v3CookieRecord, 0, len(page.GetEntries()))
	entries := make([]*pfslocal.DirEntry, 0, len(page.GetEntries()))
	for _, entry := range page.GetEntries() {
		if entry == nil || !pathcomponent.ValidName(entry.GetName()) || len(entry.GetNextCookie()) == 0 || entry.GetAttr() == nil {
			return d.malformed("readdir omitted name, cookie, or attributes")
		}
		if entry.GetItem() != nil {
			return d.malformed("readdir issued an item capability that was not requested")
		}
		positions = append(positions, v3CookieRecord{
			dirID: dir.item.ItemID, handleID: request.Handle,
			cookie:   cloneBytesV3(entry.GetNextCookie()),
			verifier: cloneBytesV3(page.GetVerifier()),
		})
		if len(entry.GetStableIdentity()) == 0 {
			// An opaque entry: the authority lists a name whose inode it never
			// exposes (a device node, FIFO, socket, or foreign-owned inode
			// another writer placed in the tree). There is nothing to publish
			// to FSKit, but enumeration must still advance past the name, so
			// its cookie is recorded without a directory entry, the same shape
			// as a local readdir listing a name whose stat then fails.
			entries = append(entries, nil)
			continue
		}
		identity, err := v3EntryIdentity(entry.GetStableIdentity())
		if err == nil {
			err = v3ReadStamp(entry.GetObjectVersion(), entry.GetSnapshotSequence())
		}
		if err != nil {
			return d.malformed("readdir entry " + err.Error())
		}
		attr, err := d.entryAttr(identity, entry, dir, request.WantAttrs)
		if err != nil {
			return d.malformed(err.Error())
		}
		entries = append(entries, &pfslocal.DirEntry{Name: cloneBytesV3(entry.GetName()), Attr: attr})
	}
	cookies, err := d.issueCookieBatch(positions)
	if err != nil {
		return nil, darwinEOVERFLOW
	}
	for index, entry := range entries {
		if entry != nil {
			entry.Cookie = cookies[index]
			reply.Entries = append(reply.Entries, *entry)
		}
		reply.NextCookie = cookies[index]
	}
	if page.GetEof() {
		reply.NextCookie = 0
		// pfslocal's enumeration contract carries EOF in both places: the
		// reply-level continuation and the final emitted entry. Swift maps the
		// latter to FSKit's terminal cookie, so leaving an opaque cookie here
		// makes the kernel ask for one unnecessary continuation after EOF. An
		// opaque authority tail may mean the final raw entry was not emitted;
		// in that case the last entry we did emit is still the correct terminal
		// one because the authority proved there are no later visible entries.
		if len(reply.Entries) != 0 {
			reply.Entries[len(reply.Entries)-1].Cookie = 0
		}
	}
	return reply, 0
}

func v3EntryIdentity(raw []byte) ([16]byte, error) {
	var identity [16]byte
	if len(raw) != len(identity) {
		return identity, fmt.Errorf("readdir entry stable identity is %d bytes, want %d", len(raw), len(identity))
	}
	copy(identity[:], raw)
	if identity == ([16]byte{}) {
		return identity, errors.New("readdir entry used the zero stable identity")
	}
	return identity, nil
}

func (d *v3DataPlane) callRead(ctx context.Context, operationID uint64, request *authoritypb.Request) (*authoritypb.Response, int32) {
	collector, _ := ctx.Value(v3ReplyResourceContextKey{}).(*v3ReplyResourceCollector)
	if operationID == 0 && collector == nil {
		response, err := d.client.CallRead(ctx, request)
		return d.classify(response, err, false)
	}
	response, consumption, callErr := d.client.CallReadRetained(ctx, request, func(cause error) {
		d.revokeRetainedResponse(ctx, errors.Join(
			errors.New("portablefsd: retained authority read crossed its frontend delivery bound"),
			cause,
		))
	})
	retained := false
	defer func() {
		if consumption != nil && !retained {
			consumption.Consume()
		}
	}()
	if consumption == nil {
		if callErr == nil && response != nil {
			d.revokeRetainedResponse(ctx, errors.New("portablefsd: parsed publishing read omitted its response consumption"))
			return nil, darwinEIO
		}
		return d.classify(response, callErr, false)
	}
	if cause := retainedV3ResponseTerminalCause(response, callErr); cause != nil {
		d.revokeRetainedResponse(ctx, cause)
		return nil, darwinEIO
	}
	if operationID == 0 {
		if err := retainV3HandlerResponse(collector, consumption); err != nil {
			d.revokeRetainedResponse(ctx, err)
			return nil, darwinEIO
		}
		retained = true
	} else {
		if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(v3Callback(ctx, operationID), consumption); err != nil {
			d.revokeRetainedResponse(ctx, err)
			return nil, darwinEIO
		}
		retained = true
	}
	return d.classify(response, nil, false)
}

func retainedV3ResponseTerminalCause(response *authoritypb.Response, callErr error) error {
	if callErr != nil {
		return callErr
	}
	if response == nil {
		return errors.New("portablefsd: retained authority response was nil")
	}
	if response.GetUncertain() ||
		response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_STORAGE ||
		response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE ||
		v3SuccessCarriesFailure(response) ||
		response.GetRoutesMismatch().GetSessionRefused() {
		return errors.New("portablefsd: authority returned a terminal retained outcome")
	}
	return nil
}

// v3SuccessCarriesFailure recognizes a contradictory outcome: no errno, yet a
// failure class. The authority classifies failures only beside an errno or an
// uncertain outcome, so a "success" that carries one is malformed.
func v3SuccessCarriesFailure(response *authoritypb.Response) bool {
	return response.GetErrno() == 0 && response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED
}

// v3ReplyBody requires a successful reply to carry exactly the operation's
// body type: want is a typed nil of the expected oneof wrapper, or nil for an
// operation whose success has no body.
func v3ReplyBody(response *authoritypb.Response, want any) error {
	if reflect.TypeOf(response.GetBody()) != reflect.TypeOf(want) {
		return fmt.Errorf("reply carried body %T, want %T", response.GetBody(), want)
	}
	return nil
}

func (d *v3DataPlane) revokeRetainedResponse(ctx context.Context, cause error) {
	if cause == nil {
		cause = errors.New("portablefsd: retained authority response could not be published")
	}
	if ctx != nil {
		if revoke, ok := ctx.Value(v3ResponseConsumptionRevokerContextKey{}).(v3ResponseConsumptionRevoker); ok && revoke != nil {
			revoke(cause)
			return
		}
	}
	_ = d.fail(cause)
}

// callMutation runs one visible mutation under its source-publication lease.
// Its caller defers the returned settlement until the whole handler returns.
func (d *v3DataPlane) callMutation(ctx context.Context, operationID uint64, request *authoritypb.Request, gate *v3SourceGate) (*authoritypb.Response, int32, func()) {
	finish := func() {}
	if operationID == 0 || request == nil {
		return nil, darwinEINVAL, finish
	}
	lease, err := d.bridge.sourcePublication.acquireSource(ctx, v3Callback(ctx, operationID), gate)
	if err != nil {
		return nil, v3LocalErrno(err), finish
	}
	finish = lease.finishRequest
	var assigned authorityrpc.MutationIdentity
	response, consumption, callErr := d.client.CallMutationWithIdentityRetained(ctx, request, func(identity authorityrpc.MutationIdentity) error {
		if err := lease.markAssigned(); err != nil {
			return err
		}
		assigned = identity
		return nil
	}, func(cause error) {
		// The authority holds a terminal response until this callback proves the
		// FSKit frontend has either published it or revoked its serving
		// boundary. A forced drain therefore kills the whole strict incarnation
		// synchronously; returning while FSKit could still issue callbacks would
		// turn a delivery timeout into a stale-serving window.
		cause = errors.Join(errors.New("portablefsd: retained authority response crossed its frontend delivery bound"), cause)
		d.revokeRetainedResponse(ctx, cause)
	})
	retained := false
	defer func() {
		if consumption != nil && !retained {
			// No successful visible result owns this receipt. Definite rejection
			// and pre-publication failure cannot install state in FSKit; terminal
			// failures have already revoked the serving boundary in classify/fail.
			consumption.Consume()
		}
	}()
	// refuse settles a definite pre-apply refusal: the call produced no
	// binding, and its response stays retained only until the callback
	// publishes the error.
	refuse := func(errno int32) (*authoritypb.Response, int32, func()) {
		if err := lease.resolveNoBindings(gate); err != nil {
			d.revokeRetainedResponse(ctx, err)
			return nil, darwinEIO, finish
		}
		if consumption != nil {
			if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(v3Callback(ctx, operationID), consumption); err != nil {
				d.revokeRetainedResponse(ctx, err)
				return nil, darwinEIO, finish
			}
			retained = true
		}
		return nil, errno, finish
	}
	if assigned.Sequence == 0 && callErr != nil && d.terminalError() != nil {
		// Local withdrawal can win between source admission and replay
		// assignment. No authority request owns this callback's outcome yet.
		return nil, darwinEIO, finish
	}
	if assigned.Sequence != 0 {
		if callErr != nil || response == nil || response.GetUncertain() ||
			response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_STORAGE ||
			response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE ||
			v3SuccessCarriesFailure(response) ||
			response.GetRoutesMismatch().GetSessionRefused() {
			if callErr == nil {
				callErr = fmt.Errorf(
					"portablefsd: assigned source mutation ended without a definite session-safe result: nil_response=%t uncertain=%t failure=%d session_refused=%t slot=%d sequence=%d operation_id=%d",
					response == nil, response != nil && response.GetUncertain(),
					response.GetFailure(),
					response != nil && response.GetRoutesMismatch().GetSessionRefused(),
					assigned.Slot, assigned.Sequence, operationID,
				)
			}
			d.revokeRetainedResponse(ctx, callErr)
			return nil, darwinEIO, finish
		}
		if v3UnadmittedWrite(request, response) {
			// Replay admission refused the WRITE before recording its identity:
			// nothing was applied and the client slot stays where it was.
			return refuse(darwinENOMEM)
		}
		state := response.GetMutation()
		if state == nil || state.GetSlot() != assigned.Slot || state.GetAcceptedSequence() != assigned.Sequence {
			d.revokeRetainedResponse(ctx, errors.New("portablefsd: assigned source mutation changed its replay identity"))
			return nil, darwinEIO, finish
		}
	}
	if response != nil && response.GetErrno() != 0 {
		if response.GetBody() != nil || response.GetPostState() != nil {
			d.revokeRetainedResponse(ctx, errors.New("portablefsd: definite source refusal carried an applied outcome"))
			return nil, darwinEIO, finish
		}
		if err := lease.resolveNoBindings(gate); err != nil {
			d.revokeRetainedResponse(ctx, err)
			return nil, darwinEIO, finish
		}
	}
	// A parsed visible response is retained until the frontend publishes or
	// revokes it. classify's generic terminal path closes the authority client;
	// that would start teardown before the pfslocal write boundary had been
	// revoked. Classify the exact terminal shapes here so the retained revoker
	// owns ordering against c.writeMu.
	if callErr != nil || response == nil || response.GetUncertain() ||
		response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_STORAGE ||
		response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE ||
		v3SuccessCarriesFailure(response) ||
		response.GetRoutesMismatch().GetSessionRefused() {
		cause := callErr
		if cause == nil {
			cause = errors.New("portablefsd: authority returned a terminal or malformed retained mutation outcome")
		}
		d.revokeRetainedResponse(ctx, cause)
		return nil, darwinEIO, finish
	}
	classified, errno := d.classify(response, nil, true)
	if errno != 0 {
		if consumption != nil {
			if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(v3Callback(ctx, operationID), consumption); err != nil {
				d.revokeRetainedResponse(ctx, err)
				return nil, darwinEIO, finish
			}
			retained = true
		}
		return classified, errno, finish
	}
	if assigned.Sequence == 0 {
		d.revokeRetainedResponse(ctx, errors.New("portablefsd: successful source mutation omitted replay assignment"))
		return nil, darwinEIO, finish
	}
	if errno, rejected := v3WriteRejection(request, classified); rejected {
		return refuse(linuxToDarwin(errno))
	}
	if err := lease.markCommitted(); err != nil {
		d.revokeRetainedResponse(ctx, err)
		return nil, darwinEIO, finish
	}
	if err := lease.retainResponseConsumption(consumption); err != nil {
		d.revokeRetainedResponse(ctx, err)
		return nil, darwinEIO, finish
	}
	retained = true
	return classified, 0, finish
}

// callNonVisibleMutation keeps authority replay identity without inventing a
// pfslocal publication identity. Open-without-truncate, Close, and ReadDir do
// not publish namespace/data/attribute state and therefore omit the mandatory
// visible-mutation source gate.
func (d *v3DataPlane) callNonVisibleMutation(ctx context.Context, operationID uint64, request *authoritypb.Request) (*authoritypb.Response, int32) {
	var assigned authorityrpc.MutationIdentity
	assignedCallback := func(identity authorityrpc.MutationIdentity) error {
		assigned = identity
		return nil
	}
	var (
		response    *authoritypb.Response
		consumption authorityrpc.ResponseConsumption
		callErr     error
		retained    bool
	)
	collector, _ := ctx.Value(v3ReplyResourceContextKey{}).(*v3ReplyResourceCollector)
	if operationID == 0 && collector == nil {
		response, callErr = d.client.CallMutationWithIdentity(ctx, request, assignedCallback)
	} else {
		response, consumption, callErr = d.client.CallMutationWithIdentityRetained(
			ctx, request, assignedCallback, func(cause error) {
				d.revokeRetainedResponse(ctx, errors.Join(
					errors.New("portablefsd: retained authority replay response crossed its frontend delivery bound"),
					cause,
				))
			},
		)
		defer func() {
			if consumption != nil && !retained {
				consumption.Consume()
			}
		}()
		if consumption == nil {
			if callErr == nil && response != nil {
				d.revokeRetainedResponse(ctx, errors.New("portablefsd: parsed publishing replay response omitted its response consumption"))
				return nil, darwinEIO
			}
		} else {
			if cause := retainedV3ResponseTerminalCause(response, callErr); cause != nil {
				d.revokeRetainedResponse(ctx, cause)
				return nil, darwinEIO
			}
			if operationID == 0 {
				if err := retainV3HandlerResponse(collector, consumption); err != nil {
					d.revokeRetainedResponse(ctx, err)
					return nil, darwinEIO
				}
				retained = true
			} else {
				if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(v3Callback(ctx, operationID), consumption); err != nil {
					d.revokeRetainedResponse(ctx, err)
					return nil, darwinEIO
				}
				retained = true
			}
		}
	}
	response, errno := d.classify(response, callErr, true)
	if errno != 0 {
		return response, errno
	}
	state := response.GetMutation()
	if assigned.Sequence == 0 || state == nil || state.GetSlot() != assigned.Slot || state.GetAcceptedSequence() != assigned.Sequence {
		_ = d.fail(errors.New("portablefsd: non-visible mutation lost its exact replay assignment"))
		return nil, darwinEIO
	}
	return response, 0
}

func (d *v3DataPlane) classify(response *authoritypb.Response, callErr error, mutation bool) (*authoritypb.Response, int32) {
	if callErr != nil {
		if !mutation && (errors.Is(callErr, context.Canceled) || errors.Is(callErr, context.DeadlineExceeded)) {
			return nil, v3LocalErrno(callErr)
		}
		_ = d.fail(callErr)
		return nil, darwinEIO
	}
	if response == nil || response.GetUncertain() || response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_STORAGE || response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE || response.GetRoutesMismatch().GetSessionRefused() {
		_ = d.fail(errors.New("portablefsd: authority returned a terminal or malformed outcome"))
		return nil, darwinEIO
	}
	if v3SuccessCarriesFailure(response) {
		_ = d.fail(fmt.Errorf("portablefsd: authority success carried failure class %d", response.GetFailure()))
		return nil, darwinEIO
	}
	if response.GetErrno() != 0 {
		return response, linuxToDarwin(response.GetErrno())
	}
	return response, 0
}

// intern adopts an authority item capability: it resolves the canonical local
// record and takes the reply's provisional reference in the same critical
// section. A record is therefore never visible to reclaim without an owner:
// reclaim either finds the reference and defers to its disposition, or has
// already detached the record, in which case this reply interns a fresh record
// under a new handle. A capability that duplicates the canonical one is
// transferred to the release owner. Adoption writes no cached attribute or
// name: a fresh record starts invalid at the cold floor, so the caller's
// separate cache application decides what the reply may fill.
func (d *v3DataPlane) intern(ctx context.Context, candidate *authoritypb.Item) (*v3ItemRecord, int32) {
	collector, _ := ctx.Value(v3ReplyResourceContextKey{}).(*v3ReplyResourceCollector)
	if collector == nil || collector.d != d || collector.taken {
		_, errno := d.malformed("authority item reached no reply that can own it")
		return nil, errno
	}
	parsed, err := d.recordFromAuthority(candidate, 0)
	if err != nil {
		_, errno := d.malformed(err.Error())
		return nil, errno
	}
	d.mu.Lock()
	record := d.itemsByIdentity[parsed.item.StableIdentity]
	duplicate := false
	if record != nil {
		if record.inode != parsed.inode || record.kind != parsed.kind {
			d.mu.Unlock()
			_, errno := d.malformed("authority identity changed its inode or kind while held")
			return nil, errno
		}
		duplicate = !bytes.Equal(record.token, parsed.token)
	} else {
		if d.nextItemID == 0 {
			d.mu.Unlock()
			_, errno := d.malformed("local item handle space exhausted")
			return nil, errno
		}
		record = parsed
		record.item.ItemID = d.nextItemID
		record.snapshot, record.watermark = d.coldFloor, d.coldFloor
		d.nextItemID++
		d.itemsByID[record.item.ItemID] = record
		d.itemsByIdentity[record.item.StableIdentity] = record
	}
	if record.provisional == math.MaxUint32 {
		d.mu.Unlock()
		_, errno := d.malformed("local item provisional ownership overflowed")
		return nil, errno
	}
	record.provisional++
	collector.items = append(collector.items, record)
	d.mu.Unlock()
	if duplicate {
		if err := d.submitPendingRelease(nil, [][]byte{parsed.token}); err != nil {
			return nil, darwinEIO
		}
	}
	return record, 0
}

// adoptAlias accepts LINK's returned capability for an item the frontend
// already owns. LINK returns the same stable identity, so the canonical record
// must still be the one the callback named; the capability is either that
// record's own or a duplicate the release owner retires. The new binding is
// part of the mutation's cache application, not of adoption.
func (d *v3DataPlane) adoptAlias(item *v3ItemRecord, linked *authoritypb.Item) int32 {
	parsed, err := d.recordFromAuthority(linked, 0)
	if err != nil {
		_, errno := d.malformed(err.Error())
		return errno
	}
	d.mu.Lock()
	if parsed.item.StableIdentity != item.item.StableIdentity || d.itemsByID[item.item.ItemID] != item ||
		parsed.inode != item.inode || parsed.kind != item.kind {
		d.mu.Unlock()
		_, errno := d.malformed("hard link did not return its live source item")
		return errno
	}
	duplicate := !bytes.Equal(item.token, parsed.token)
	d.mu.Unlock()
	if duplicate {
		if err := d.submitPendingRelease(nil, [][]byte{parsed.token}); err != nil {
			return darwinEIO
		}
	}
	return 0
}

func (d *v3DataPlane) recordFromAuthority(candidate *authoritypb.Item, itemID uint64) (*v3ItemRecord, error) {
	identity, err := authorityIdentity(candidate)
	if err != nil {
		return nil, err
	}
	attr := candidate.GetAttr()
	fileID, err := d.representableAttr(identity, attr)
	if err != nil {
		return nil, fmt.Errorf("authority item: %w", err)
	}
	return &v3ItemRecord{
		item:  pfslocal.Item{ItemID: itemID, ItemGeneration: d.cfg.ItemGeneration, StableIdentity: identity},
		token: cloneBytesV3(candidate.GetToken()), fileID: fileID, inode: attr.GetInode(), kind: attr.GetKind(),
	}, nil
}

// representableAttr is the one rule for attributes the daemon can own, cache,
// or render: a known kind, a nonzero inode inside the file-ID range (the root
// excepted), a nonnegative size, and an allocation that renders in bytes. Every
// owning, read, and PostState path applies it before using a sample.
func (d *v3DataPlane) representableAttr(identity [16]byte, attr *authoritypb.Attr) (uint64, error) {
	if attr == nil || attr.GetInode() == 0 || attr.GetSize() < 0 || !validAuthorityKind(attr.GetKind()) ||
		attr.GetBlocks() > math.MaxUint64/512 {
		return 0, errors.New("authority attributes are malformed or unrepresentable")
	}
	return d.fileIDFor(identity, attr.GetInode())
}

// representableEffect applies representableAttr to every object of a whole
// mutation result, held or not, before anything is adopted or applied.
func (d *v3DataPlane) representableEffect(effect *v3MutationEffect) error {
	for _, object := range effect.objects {
		if _, err := d.representableAttr(object.identity, object.attr); err != nil {
			return fmt.Errorf("mutation post-state object: %w", err)
		}
	}
	return nil
}

func (d *v3DataPlane) fileIDFor(identity [16]byte, inode uint64) (uint64, error) {
	if identity == d.rootIdentity {
		return v3RootFileID, nil
	}
	if inode < v3FirstFileID || inode >= v3FileIDLimit {
		return 0, fmt.Errorf("authority inode %d is outside the file-ID range [2, UInt64.max)", inode)
	}
	return inode, nil
}

// localAttr renders an authority attr for a record. The attr must describe
// the record's own inode and kind, so the file ID it carries is never derived
// from a different object than the one the handle owns.
func (d *v3DataPlane) localAttr(record *v3ItemRecord, attr *authoritypb.Attr, parent *v3ParentBinding) (pfslocal.Attr, error) {
	if record == nil || attr == nil {
		return pfslocal.Attr{}, errors.New("malformed authority attr")
	}
	if attr.GetInode() != record.inode || attr.GetKind() != record.kind {
		return pfslocal.Attr{}, errors.New("authority attr names a different object than its item")
	}
	result, err := d.renderAttr(attr)
	if err != nil {
		return pfslocal.Attr{}, err
	}
	result.Item, result.FileID = record.item, record.fileID
	// An object with no links has no live parent binding, whatever binding the
	// record last observed.
	if parent != nil && attr.GetNlink() != 0 {
		parentItem := parent.item
		result.Parent, result.ParentFileID = &parentItem, parent.fileID
	}
	return result, nil
}

// entryAttr renders a non-owning directory entry: kind and file ID always,
// full attributes only when requested, and the listed directory as parent.
// The entry's coherent sample may refresh a held identity's cached attrs
// through the ordinary ordering rules; enumeration never creates items,
// names, or negatives.
func (d *v3DataPlane) entryAttr(identity [16]byte, entry *authoritypb.Dirent, dir *v3ItemRecord, full bool) (pfslocal.Attr, error) {
	attr := entry.GetAttr()
	fileID, err := d.representableAttr(identity, attr)
	if err != nil {
		return pfslocal.Attr{}, fmt.Errorf("readdir entry: %w", err)
	}
	// A snapshot carries no identity for the frontend to check, so the daemon
	// holds it to the same immutability rule as an owning reply.
	d.mu.Lock()
	if held := d.itemsByIdentity[identity]; held != nil && d.terminal == nil {
		err = d.observeLocked(held, attr, entry.GetObjectVersion(), entry.GetSnapshotSequence())
	}
	d.mu.Unlock()
	if err != nil {
		return pfslocal.Attr{}, fmt.Errorf("readdir entry for a held identity: %w", err)
	}
	result, err := d.renderAttr(attr)
	if err != nil {
		return pfslocal.Attr{}, err
	}
	if !full {
		result = pfslocal.Attr{Kind: result.Kind}
	}
	result.FileID, result.ParentFileID = fileID, dir.fileID
	return result, nil
}

func (d *v3DataPlane) renderAttr(attr *authoritypb.Attr) (pfslocal.Attr, error) {
	kind, ok := localItemKind(attr.GetKind())
	if !ok {
		return pfslocal.Attr{}, errors.New("unknown authority item kind")
	}
	if attr.GetSize() < 0 {
		return pfslocal.Attr{}, errors.New("authority attr has a negative size")
	}
	if attr.GetBlocks() > math.MaxUint64/512 {
		return pfslocal.Attr{}, errors.New("authority allocation size overflow")
	}
	return pfslocal.Attr{
		Kind: kind, Mode: attr.GetMode(), Nlink: attr.GetNlink(), UID: d.cfg.PrincipalUID, GID: d.cfg.PrincipalGID,
		Size: uint64(attr.GetSize()), MtimeMs: nanosToMillis(attr.GetMtimeNs()), CtimeMs: nanosToMillis(attr.GetCtimeNs()),
		AtimeMs: nanosToMillis(attr.GetAtimeNs()), BirthtimeMs: nanosToMillis(attr.GetBirthTimeNs()), AllocSize: attr.GetBlocks() * 512,
	}, nil
}

// parentOf selects a representative live parent for item-only attributes.
// Namespace replies instead render the parent the caller actually named.
func (d *v3DataPlane) parentOf(record *v3ItemRecord) *v3ParentBinding {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.parentOfLocked(record)
}

func (d *v3DataPlane) parentOfLocked(record *v3ItemRecord) *v3ParentBinding {
	for binding := range record.bindings {
		return v3ParentOf(binding.parent)
	}
	return nil
}

func (d *v3DataPlane) item(item pfslocal.Item) (*v3ItemRecord, int32) {
	if item.ItemID == 0 || item.ItemGeneration != d.cfg.ItemGeneration {
		return nil, darwinESTALE
	}
	d.mu.Lock()
	record := d.itemsByID[item.ItemID]
	d.mu.Unlock()
	if record == nil || record.item != item {
		return nil, darwinESTALE
	}
	return record, 0
}

// handle resolves a live daemon handle. A non-nil owner requires the handle
// to have been opened on exactly that item identity.
func (d *v3DataPlane) handle(id uint64, owner *v3ItemRecord) (*v3HandleRecord, int32) {
	if id == 0 {
		return nil, darwinEBADF
	}
	d.mu.Lock()
	handle := d.handles[id]
	d.mu.Unlock()
	if handle == nil || owner != nil && handle.item != owner.item {
		return nil, darwinEBADF
	}
	return handle, 0
}

// itemAndOptionalHandle resolves an item and, when named, acquires its live
// handle; release is always callable.
func (d *v3DataPlane) itemAndOptionalHandle(itemValue pfslocal.Item, handleID uint64) (*v3ItemRecord, *v3HandleRecord, func(), int32) {
	item, errno := d.item(itemValue)
	if errno != 0 {
		return nil, nil, func() {}, errno
	}
	if handleID == 0 {
		return item, nil, func() {}, 0
	}
	handle, release, errno := d.acquireHandle(handleID, item)
	if errno != 0 {
		return nil, nil, func() {}, errno
	}
	return item, handle, release, 0
}

// acquireHandle resolves a live handle and takes its shared lock, then
// revalidates liveness under that lock. Close detaches a handle only while
// holding the exclusive lock, and abandoned cleanup takes it before releasing
// the token, so a call admitted here owns a live token until release; resolving
// the pointer before the lock is not enough when a competing Close wins.
func (d *v3DataPlane) acquireHandle(id uint64, owner *v3ItemRecord) (*v3HandleRecord, func(), int32) {
	handle, errno := d.handle(id, owner)
	if errno != 0 {
		return nil, nil, errno
	}
	if d.testBeforeHandleLock != nil {
		d.testBeforeHandleLock(handle)
	}
	handle.mu.RLock()
	d.mu.Lock()
	live := d.handles[id] == handle
	d.mu.Unlock()
	if !live {
		handle.mu.RUnlock()
		return nil, nil, darwinEBADF
	}
	return handle, handle.mu.RUnlock, 0
}

func (d *v3DataPlane) installHandle(token []byte, item pfslocal.Item, appendMode bool) (*v3HandleRecord, error) {
	if len(token) != 16 {
		return nil, errors.New("malformed authority handle")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nextHandleID == 0 {
		return nil, errors.New("local handle identifier space exhausted")
	}
	handle := &v3HandleRecord{id: d.nextHandleID, token: cloneBytesV3(token), item: item, append: appendMode}
	d.nextHandleID++
	d.handles[handle.id] = handle
	return handle, nil
}

// issueCookieBatch allocates every continuation from one authority page as one
// atomic ownership unit. Capacity eviction removes whole oldest pages in O(page
// size), never one record at a time by repeatedly scanning the full table.
// This keeps concurrent walks isolated and makes allocation all-or-nothing at
// identifier exhaustion.
func (d *v3DataPlane) issueCookieBatch(positions []v3CookieRecord) ([]uint64, error) {
	if len(positions) == 0 {
		return nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	dirID := positions[0].dirID
	handleID := positions[0].handleID
	for _, position := range positions {
		if dirID == 0 || handleID == 0 || position.dirID != dirID || position.handleID != handleID || len(position.cookie) == 0 ||
			len(position.verifier) != 16 || position.batchID != 0 {
			return nil, errors.New("directory cookie batch is malformed")
		}
	}
	if len(positions) > v3MaxCookies ||
		uint64(len(positions)) > math.MaxUint64-d.nextCookieID {
		return nil, errors.New("directory cookie table exhausted")
	}
	if d.nextCookieBatch == 0 || d.nextCookieBatch == math.MaxUint64 {
		return nil, errors.New("directory cookie batch space exhausted")
	}
	for len(d.cookies)+len(positions) > v3MaxCookies {
		oldest := d.cookieOrder.Front()
		if oldest == nil {
			return nil, errors.New("directory cookie index is inconsistent")
		}
		d.removeCookieBatchLocked(oldest.Value.(uint64))
	}
	batchID := d.nextCookieBatch
	d.nextCookieBatch++
	cookies := make([]uint64, len(positions))
	for index, position := range positions {
		cookie := d.nextCookieID
		d.nextCookieID++
		position.batchID = batchID
		d.cookies[cookie] = position
		cookies[index] = cookie
	}
	d.cookieBatches[batchID] = &v3CookieBatch{
		dirID: dirID, handleID: handleID, cookies: cookies,
		order: d.cookieOrder.PushBack(batchID),
	}
	return cookies, nil
}

// resolveCookie translates one opaque local directory position without
// consuming it. FSKit may reuse the last cookie it accepted after the extension
// has already prefetched a later authority page: if that later page does not fit
// the current kernel buffer, the next callback resumes from the earlier cookie.
// One-shot cookies therefore truncate large directories exactly at a packer
// boundary. Whole pages remain isolated ownership units for bounded LRU
// eviction and directory reclaim; a genuinely expired cookie fails closed with
// ESTALE.
func (d *v3DataPlane) resolveCookie(dirID, handleID, cookie uint64) (v3CookieRecord, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	position, ok := d.cookies[cookie]
	if !ok || position.dirID != dirID || position.handleID != handleID || len(position.cookie) == 0 || len(position.verifier) != 16 || position.batchID == 0 {
		return v3CookieRecord{}, false
	}
	batch := d.cookieBatches[position.batchID]
	if batch == nil || batch.dirID != dirID || batch.handleID != handleID || batch.order == nil {
		return v3CookieRecord{}, false
	}
	d.cookieOrder.MoveToBack(batch.order)
	return position, true
}

func (d *v3DataPlane) removeCookieBatchLocked(batchID uint64) {
	batch := d.cookieBatches[batchID]
	if batch == nil {
		return
	}
	for _, cookie := range batch.cookies {
		delete(d.cookies, cookie)
	}
	if batch.order != nil {
		d.cookieOrder.Remove(batch.order)
	}
	delete(d.cookieBatches, batchID)
}

func collectV3ReplyHandle(ctx context.Context, handle *v3HandleRecord) {
	collector, _ := ctx.Value(v3ReplyResourceContextKey{}).(*v3ReplyResourceCollector)
	if collector == nil || collector.d == nil || handle == nil {
		return
	}
	for _, existing := range collector.handles {
		if existing == handle {
			return
		}
	}
	collector.d.mu.Lock()
	live := collector.d.handles[handle.id] == handle
	collector.d.mu.Unlock()
	if !live {
		if collector.err == nil {
			collector.err = errors.New("portablefsd: reply handle is not claimable")
		}
		return
	}
	collector.handles = append(collector.handles, handle)
}

func retainV3HandlerResponse(
	collector *v3ReplyResourceCollector,
	consumption authorityrpc.ResponseConsumption,
) error {
	if collector == nil || collector.d == nil || collector.taken || consumption == nil {
		return errors.New("portablefsd: retained authority response escaped its frontend handler")
	}
	collector.responseConsumptions = append(collector.responseConsumptions, consumption)
	return nil
}

func consumeV3ResponseConsumptions(consumptions []authorityrpc.ResponseConsumption) {
	for _, consumption := range consumptions {
		if consumption != nil {
			consumption.Consume()
		}
	}
}

func consumeV3ProvisionalResponses(resources *v3ProvisionalResources) {
	if resources == nil {
		return
	}
	consumeV3ResponseConsumptions(resources.responseConsumptions)
	resources.responseConsumptions = nil
}

// prepareReplyResources converts resources collected while building one
// successful reply into provisional ownership. The frontend's final callback
// verdict, not socket delivery, decides whether these capabilities remain
// live. Installing the provisional counts atomically also lets overlapping
// replies share one item without an abandoned reply reclaiming it from a reply
// that is still deciding.
func (d *v3DataPlane) prepareReplyResources(collector *v3ReplyResourceCollector) (*v3ProvisionalResources, error) {
	if collector == nil || collector.d != d || collector.taken {
		return nil, errors.New("portablefsd: invalid reply resource collector")
	}
	collector.taken = true
	resources := &v3ProvisionalResources{
		d: d, items: append([]*v3ItemRecord(nil), collector.items...),
		handles:              append([]*v3HandleRecord(nil), collector.handles...),
		responseConsumptions: append([]authorityrpc.ResponseConsumption(nil), collector.responseConsumptions...),
		visible:              collector.visible,
		reservation:          collector.reservation,
	}
	collector.responseConsumptions = nil
	collector.reservation = nil
	return resources, collector.err
}

// abandonCollectedReplyResources rolls back resources acquired before reply
// construction failed. intern claims its reply reference when it resolves the
// record and handlers collect handles as they install them, so a later attr or
// encoding failure cannot leave an unreachable local capability even though no
// successful reply was registered for disposition.
func (d *v3DataPlane) abandonCollectedReplyResources(
	collector *v3ReplyResourceCollector,
) (*v3ResourceCleanup, error) {
	resources, prepareErr := d.prepareReplyResources(collector)
	if resources == nil {
		return nil, prepareErr
	}
	cleanup, dispositionErr := d.applyReplyResourceDisposition(resources, false, 0)
	// This is a pre-frame rollback, not the frontend's ownership verdict. Move
	// any retained authority response back to the handler collector so its
	// eventual error frame (or synchronized revocation) remains the consumption
	// boundary.
	collector.responseConsumptions = resources.responseConsumptions
	resources.responseConsumptions = nil
	return cleanup, errors.Join(prepareErr, dispositionErr)
}

type v3ResourceCleanup struct {
	d              *v3DataPlane
	items          []*v3ItemRecord
	handles        []*v3HandleRecord
	terminalReason error
	reservation    *v3PendingReservation
	once           sync.Once
	err            error
}

func (cleanup *v3ResourceCleanup) required() bool {
	return cleanup != nil &&
		(len(cleanup.items) != 0 || len(cleanup.handles) != 0 || cleanup.terminalReason != nil)
}

// applyReplyResourceDisposition is the in-memory ownership transition. It is
// deliberately separate from finish: the serial pfslocal reader applies this
// half before processing the next PublicationAck/control message, while slow
// authority Close/Reclaim compensation runs asynchronously afterwards.
func (d *v3DataPlane) applyReplyResourceDisposition(
	resources *v3ProvisionalResources,
	acceptHandles bool,
	acceptedItemCount uint32,
) (*v3ResourceCleanup, error) {
	if resources == nil || resources.d != d {
		return nil, errors.New("portablefsd: invalid provisional resource settlement")
	}
	if uint64(acceptedItemCount) > uint64(len(resources.items)) {
		return nil, errors.New("portablefsd: resource disposition has an invalid item prefix")
	}
	if acceptHandles && len(resources.handles) == 0 {
		return nil, errors.New("portablefsd: resource disposition accepted a nonexistent handle")
	}
	cleanup := &v3ResourceCleanup{d: d}
	if resources.visible && (uint64(acceptedItemCount) != uint64(len(resources.items)) ||
		len(resources.handles) != 0 && !acceptHandles) {
		cleanup.terminalReason = errors.New("portablefsd: successful visible resource reply was not fully published to FSKit")
	}
	d.mu.Lock()
	if resources.settled {
		d.mu.Unlock()
		return nil, errors.New("portablefsd: resource disposition settled twice")
	}
	for _, item := range resources.items {
		if item.provisional == 0 {
			d.mu.Unlock()
			return nil, errors.New("portablefsd: provisional item ownership settled twice")
		}
	}
	resources.settled = true
	cleanup.reservation, resources.reservation = resources.reservation, nil
	for index, item := range resources.items {
		item.provisional--
		acceptItem := uint32(index) < acceptedItemCount
		if acceptItem {
			item.accepted = true
		} else if !item.accepted && item.provisional == 0 && d.itemsByID[item.item.ItemID] == item {
			d.detachItemLocked(item)
			cleanup.items = append(cleanup.items, item)
		}
	}
	if !acceptHandles {
		for _, handle := range resources.handles {
			if d.detachHandleLocked(handle) {
				cleanup.handles = append(cleanup.handles, handle)
			}
		}
	}
	d.mu.Unlock()
	if !cleanup.required() {
		cleanup.reservation.retire()
		cleanup.reservation = nil
	}
	if cleanup.terminalReason != nil {
		// Revoke local publication immediately. The original authority session
		// still owns its capabilities until exact kernel-absence proof retires it.
		_ = d.stopServing(cleanup.terminalReason)
	}
	return cleanup, nil
}

// finish retains the pending reservation until every token is accepted by
// the existing release owner, or exact/terminal teardown takes ownership.
// It runs off the serial reader. Once guards both tokens and reservation.
func (cleanup *v3ResourceCleanup) finish() error {
	if cleanup == nil || cleanup.d == nil {
		return nil
	}
	cleanup.once.Do(func() {
		started := time.Now()
		defer func() {
			if r := cleanup.reservation; r != nil {
				elapsed := time.Since(started)
				r.budget.mu.Lock()
				r.budget.stats.CleanupWaitNS += uint64(elapsed)
				r.budget.mu.Unlock()
				r.retire()
			}
		}()
		closes := make([][]byte, 0, len(cleanup.handles))
		for _, handle := range cleanup.handles {
			// Previously admitted I/O retains the token until it unlocks.
			handle.mu.Lock()
			handle.mu.Unlock()
			closes = append(closes, handle.token)
		}
		reclaims := make([][]byte, 0, len(cleanup.items))
		for _, item := range cleanup.items {
			reclaims = append(reclaims, item.token)
		}
		cleanup.err = cleanup.d.releases.submit(closes, reclaims)
	})
	return cleanup.err
}

// sendReleaseBatch is the release owner's work batch: at most one CloseBatch,
// then at most one Reclaim. Each request owns an exact replay assignment, so it
// runs on the data plane's lifetime rather than any caller's: a lost reply
// replays the same mutation inside the client, and local withdrawal cannot
// cancel it. Before transfer to session teardown, every outcome other than
// complete success is terminal.
func (d *v3DataPlane) sendReleaseBatch(closes, reclaims [][]byte) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(d.ctx), operationAdmissionBudgetValue())
	defer cancel()
	if len(closes) != 0 {
		batch := &authoritypb.CloseBatchRequest{Closes: make([]*authoritypb.CloseRequest, len(closes))}
		for index, token := range closes {
			batch.Closes[index] = &authoritypb.CloseRequest{Handle: cloneBytesV3(token)}
		}
		if err := d.sendRelease(ctx, &authoritypb.Request{Body: &authoritypb.Request_CloseBatch{CloseBatch: batch}}, len(closes)); err != nil {
			return err
		}
	}
	if len(reclaims) != 0 {
		return d.sendRelease(ctx, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: reclaims}}}, 0)
	}
	return nil
}

// sendRelease preserves the original transport on a definite, well-formed
// refusal. Once exact absence transfers ownership to session teardown, a late
// DATA outcome cannot turn an accepted CONTROL Detach into a transport failure.
func (d *v3DataPlane) sendRelease(ctx context.Context, request *authoritypb.Request, closes int) (err error) {
	d.releaseMu.Lock()
	transferred := d.releaseSessionOwned
	d.releaseMu.Unlock()
	if transferred {
		return nil
	}
	var assigned authorityrpc.MutationIdentity
	response, callErr := d.client.CallMutationWithIdentity(ctx, request, func(identity authorityrpc.MutationIdentity) error {
		assigned = identity
		return nil
	})
	d.releaseMu.Lock()
	defer func() {
		// Record the classified failure before transfer can take ownership,
		// rather than waiting for the worker to record it after this returns.
		if err != nil {
			d.releases.mu.Lock()
			if d.releases.failure == nil {
				d.releases.failure = err
			}
			d.releases.mu.Unlock()
		}
		d.releaseMu.Unlock()
	}()
	if d.releaseSessionOwned {
		return nil
	}
	response, errno := d.classify(response, callErr, true)
	if response == nil {
		return d.terminalError()
	}
	state := response.GetMutation()
	if assigned.Sequence == 0 || errno == 0 && state == nil || state != nil && (state.GetSlot() != assigned.Slot || state.GetAcceptedSequence() != assigned.Sequence) {
		return d.fail(errors.New("portablefsd: release lost its exact replay assignment"))
	}
	if errno != 0 {
		if response.GetBody() != nil || response.GetPostState() != nil || len(response.GetTerminalDeliveryToken()) != 0 ||
			!v3DefiniteReleaseFailure(response.GetFailure()) {
			return d.fail(errors.New("portablefsd: malformed release refusal"))
		}
		return d.stopServing(fmt.Errorf("portablefsd: authority release refused with errno %d", errno))
	}
	if closes == 0 {
		if err := v3ReleaseSucceeded(response, false); err != nil {
			return d.fail(err)
		}
		return nil
	}
	if err := v3ReleaseSucceeded(response, true); err != nil {
		return d.fail(err)
	}
	results := response.GetCloseBatch().GetResults()
	if len(results) != closes {
		return d.fail(fmt.Errorf("portablefsd: batched close of %d handles returned %d results", closes, len(results)))
	}
	var refusal error
	for index, result := range results {
		if result == nil || result.GetErrno() < 0 || !result.GetRetired() && result.GetErrno() == 0 ||
			!v3DefiniteReleaseFailure(result.GetFailure()) ||
			result.GetErrno() == 0 && result.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED {
			return d.fail(fmt.Errorf("portablefsd: malformed or terminal close result %d: %v", index, result))
		}
		if result.GetErrno() != 0 {
			refusal = fmt.Errorf("portablefsd: batched close entry %d refused with errno %d", index, result.GetErrno())
		}
	}
	if refusal != nil {
		return d.stopServing(refusal)
	}
	return nil
}

func v3DefiniteReleaseFailure(class authoritypb.FailureClass) bool {
	switch class {
	case authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED, authoritypb.FailureClass_FAILURE_CLASS_INTERNAL,
		authoritypb.FailureClass_FAILURE_CLASS_ROUTES, authoritypb.FailureClass_FAILURE_CLASS_RESTORE:
		return true
	default:
		return false
	}
}

// transferReleases closes admission without waiting on DATA. Session teardown
// owns unsent tokens; the worker retains its in-flight request until it returns.
// Only a failure classified before this transfer is a cleanup diagnostic.
func (d *v3DataPlane) transferReleases() error {
	d.releaseMu.Lock()
	defer d.releaseMu.Unlock()
	d.releaseSessionOwned = true
	d.releases.abandon()
	d.pending.takeForTeardown()
	d.releases.mu.Lock()
	defer d.releases.mu.Unlock()
	if d.releases.failure != nil {
		return d.releases.failure
	}
	return nil
}

// v3ReleaseSucceeded requires the whole success outcome of one release request
// before its batch counts as settled: no errno, failure class, uncertainty,
// post-state, or terminal-delivery token, and exactly the operation's own
// reply body (none for Reclaim, CloseBatch's for CloseBatch).
func v3ReleaseSucceeded(response *authoritypb.Response, closeBatch bool) error {
	if response == nil || response.GetErrno() != 0 || response.GetUncertain() ||
		response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED ||
		response.GetPostState() != nil || len(response.GetTerminalDeliveryToken()) != 0 {
		return fmt.Errorf("release outcome is not a plain success: errno=%d failure=%d", response.GetErrno(), response.GetFailure())
	}
	switch response.GetBody().(type) {
	case nil:
		if !closeBatch {
			return nil
		}
	case *authoritypb.Response_CloseBatch:
		if closeBatch {
			return nil
		}
	}
	return fmt.Errorf("release outcome carried the wrong reply body %T", response.GetBody())
}

func (d *v3DataPlane) malformed(detail string) (any, int32) {
	_ = d.fail(errors.New("portablefsd: " + detail))
	return nil, darwinEIO
}
func (d *v3DataPlane) terminalError() error { d.mu.Lock(); defer d.mu.Unlock(); return d.terminal }
func (d *v3DataPlane) recordTerminal(err error) {
	d.failOnce.Do(func() {
		d.mu.Lock()
		// Terminal is irreversible: no later proof, hit, or connection revives
		// cache eligibility for this data plane.
		d.terminal = err
		d.horizon = 0
		for _, record := range d.itemsByID {
			d.dropCompletenessLocked(record)
		}
		d.mu.Unlock()
		// Session cleanup, not item-by-item replay, owns every release this
		// data plane has not already put in flight.
		if d.releases != nil {
			d.releases.abandon()
		}
		if d.pending != nil {
			d.pending.takeForTeardown()
		}
		d.cancel()
	})
}

func (d *v3DataPlane) abandonBeforeMount(err error) {
	if err == nil {
		err = errors.New("portablefsd: v3 data-plane construction abandoned")
	}
	if d.bridge != nil {
		d.bridge.abandonBeforeMount()
	}
	d.recordTerminal(err)
}

func (d *v3DataPlane) fail(err error) error {
	if err == nil {
		err = errors.New("portablefsd: v3 data plane failed")
	}
	d.recordTerminal(err)
	if d.bridge != nil {
		return d.bridge.fail(err)
	}
	_ = d.client.Close()
	return err
}

func (d *v3DataPlane) stopServing(err error) error {
	if err == nil {
		err = errors.New("portablefsd: frontend serving ended")
	}
	d.recordTerminal(err)
	if d.bridge != nil {
		return d.bridge.stopServing(err)
	}
	return err
}

// keepAlive is the sole periodic renewal owner. Completion starts the next
// interval; slow requests never accumulate a ticker backlog or overlap.
func (d *v3DataPlane) keepAlive() {
	d.keepAliveWithTimer(func(interval time.Duration) (<-chan time.Time, func()) {
		timer := time.NewTimer(interval)
		return timer.C, func() { timer.Stop() }
	})
}

func (d *v3DataPlane) keepAliveWithTimer(newTimer func(time.Duration) (<-chan time.Time, func())) {
	interval := v3KeepAliveInterval(d.client.SessionLease())
	if interval <= 0 {
		_ = d.fail(errors.New("invalid authority renewal interval"))
		return
	}
	for {
		tick, stop := newTimer(interval)
		select {
		case <-d.client.SessionDone():
			stop()
			return
		case <-tick:
			stop()
		}
		if !d.scheduledRenewal() {
			return
		}
	}
}
func v3KeepAliveInterval(lease time.Duration) time.Duration {
	if lease <= 0 {
		return 0
	}
	return min(lease/3, 5*time.Second, authorityrpc.MaxCacheProof/3).Truncate(time.Millisecond)
}

// renewHorizon bounds local waiting with a Go context and anchors H on the
// continuous clock before client admission. Only a usable proof grants H.
func (d *v3DataPlane) renewHorizon(parent context.Context) error {
	d.renewalMu.Lock()
	defer d.renewalMu.Unlock()
	wallStart := time.Now()
	d.mu.Lock()
	authorization := d.authorizationDeadline
	d.mu.Unlock()
	if !authorization.IsZero() && !wallStart.Before(authorization) {
		return errors.New("installed authority authorization expired")
	}
	deadline := wallStart.Add(d.client.SessionLease())
	if !authorization.IsZero() && authorization.Before(deadline) {
		deadline = authorization
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	// The context bounds local waiting on Go's monotonic clock.
	// Only the continuous-clock sample below anchors the cache proof.
	d.mu.Lock()
	start, startErr := d.readClockLocked()
	d.mu.Unlock()
	if startErr != nil {
		_ = d.endOnClockFault()
		// Renewal preserves the original session for later absence evidence.
		// A broken cache clock must not end that independent transport owner.
	}
	proof, err := d.client.KeepAlive(ctx)
	if err != nil {
		return err
	}
	if proof <= 0 || proof%time.Millisecond != 0 || proof > authorityrpc.MaxCacheProof || proof > d.client.SessionLease() {
		return errors.New("authority renewal returned an invalid proof")
	}
	d.mu.Lock()
	now, nowErr := d.readClockLocked()
	candidate, usable := v3HorizonCandidate(start, proof)
	if usable && d.clockFault == nil && now < candidate && d.terminal == nil && (d.authorizationDeadline.IsZero() || time.Now().Before(d.authorizationDeadline)) && candidate > d.horizon {
		d.horizon = candidate
	}
	horizon := d.horizon
	var authorizationNanos uint64
	if !d.authorizationDeadline.IsZero() {
		authorizationNanos = uint64(d.authorizationDeadline.UnixNano())
	}
	if d.bridge != nil {
		d.bridge.publishCacheHorizon(horizon, authorizationNanos)
	}
	d.mu.Unlock()
	if nowErr != nil {
		_ = d.endOnClockFault()
	}
	// Scalar-valid answers can outlive their entire cache horizon in transit.
	// They renew the session but grant no cache eligibility; this is not a
	// transport or proof-format failure. Startup checks usability separately.
	return nil
}

// readClockLocked invalidates the horizon on an actual clock API or
// representation error. The caller hands that error to stopServing only after
// releasing the snapshot locks. Supported platform monotonicity is a premise.
func (d *v3DataPlane) readClockLocked() (uint64, error) {
	now, err := d.clock()
	if err != nil {
		if d.clockFault == nil {
			d.clockFault = err
		}
		d.horizon = 0
		return 0, err
	}
	return now, nil
}

// endOnClockFault ends serving if a clock fault has been latched. Every horizon
// is measured on that clock, so a fault voids them all and there is no uncached
// mode to continue in; the original transport stays for the exact absence
// proof. It must run with no snapshot lock held, before any fallback.
func (d *v3DataPlane) endOnClockFault() error {
	d.mu.Lock()
	fault := d.clockFault
	d.mu.Unlock()
	if fault != nil {
		_ = d.stopServing(fmt.Errorf("portablefsd: continuous clock unusable: %w", fault))
	}
	return fault
}

// v3HorizonCandidate is start + R - epsilon(R) with
// epsilon(R) = 1s + ceil(R/1000), in checked arithmetic. The rate term budgets
// 1,000 ppm of aggregate relative clock-rate error between this Mac and the
// authority; the one-second term budgets measurement and rounding uncertainty.
// These are explicit supported-clock assumptions, not an RTT estimate. A proof
// no longer than its own epsilon is unusable.
func v3HorizonCandidate(start uint64, proof time.Duration) (uint64, bool) {
	if proof <= 0 {
		return 0, false
	}
	r := uint64(proof)
	epsilon := uint64(time.Second) + r/1000
	if r%1000 != 0 {
		epsilon++
	}
	if r <= epsilon || start > math.MaxUint64-(r-epsilon) {
		return 0, false
	}
	return start + (r - epsilon), true
}
func authorityIdentity(item *authoritypb.Item) ([16]byte, error) {
	var out [16]byte
	// Naming the exact field is the difference between a one-line diagnosis and
	// an afternoon: a nil item means the caller never had one to validate,
	// which is a different defect from an authority that sent a short field.
	if item == nil {
		return out, errors.New("authority item is absent")
	}
	if len(item.GetToken()) != 16 {
		return out, fmt.Errorf("authority item capability is %d bytes, want 16", len(item.GetToken()))
	}
	if len(item.GetStableIdentity()) != len(out) {
		return out, fmt.Errorf(
			"authority item stable identity is %d bytes, want %d",
			len(item.GetStableIdentity()), len(out),
		)
	}
	copy(out[:], item.GetStableIdentity())
	if out == ([16]byte{}) {
		return out, errors.New("authority item used the zero stable identity")
	}
	return out, nil
}

func requiredV3PublicationIdentity(raw []byte, coordinate string) (v3PublicationIdentity, error) {
	var identity v3PublicationIdentity
	if len(raw) != len(identity) {
		return identity, fmt.Errorf("%s omitted its exact 16-byte post identity", coordinate)
	}
	copy(identity[:], raw)
	if identity == (v3PublicationIdentity{}) {
		return identity, fmt.Errorf("%s returned the zero post identity", coordinate)
	}
	return identity, nil
}

func optionalV3PublicationIdentity(raw []byte, coordinate string) (v3PublicationIdentity, bool, error) {
	if len(raw) == 0 {
		return v3PublicationIdentity{}, false, nil
	}
	identity, err := requiredV3PublicationIdentity(raw, coordinate)
	return identity, err == nil, err
}

func cloneAuthorityAttr(attr *authoritypb.Attr) *authoritypb.Attr {
	if attr == nil {
		return nil
	}
	return proto.Clone(attr).(*authoritypb.Attr)
}
func cloneBytesV3(value []byte) []byte                   { return append([]byte(nil), value...) }
func validAuthorityKind(kind authoritypb.Attr_Kind) bool { _, ok := localItemKind(kind); return ok }
func localItemKind(kind authoritypb.Attr_Kind) (pfslocal.ItemKind, bool) {
	switch kind {
	case authoritypb.Attr_REGULAR:
		return pfslocal.ItemKindFile, true
	case authoritypb.Attr_DIRECTORY:
		return pfslocal.ItemKindDirectory, true
	case authoritypb.Attr_SYMLINK:
		return pfslocal.ItemKindSymlink, true
	default:
		return 0, false
	}
}
func v3OpenFlags(mode pfslocal.OpenMode, appendMode bool) (*authoritypb.OpenFlags, bool) {
	flags := &authoritypb.OpenFlags{Append: appendMode}
	switch mode {
	case pfslocal.OpenModeRead:
		flags.Read = true
	case pfslocal.OpenModeWrite:
		flags.Write = true
	case pfslocal.OpenModeReadWrite:
		flags.Read, flags.Write = true, true
	default:
		return nil, false
	}
	return flags, true
}
func millisToNanos(value *int64) (*int64, bool) {
	if value == nil {
		return nil, true
	}
	if *value > math.MaxInt64/int64(time.Millisecond) || *value < math.MinInt64/int64(time.Millisecond) {
		return nil, false
	}
	converted := *value * int64(time.Millisecond)
	return &converted, true
}
func nanosToMillis(value int64) int64 {
	quotient, remainder := value/int64(time.Millisecond), value%int64(time.Millisecond)
	if value < 0 && remainder != 0 {
		quotient--
	}
	return quotient
}
func v3VerifierVersion(verifier []byte) uint64 {
	digest := sha256.Sum256(verifier)
	value := uint64(0)
	for _, part := range digest[:8] {
		value = value<<8 | uint64(part)
	}
	if value == 0 {
		return 1
	}
	return value
}
func validXattrName(name string) bool {
	return name != "" && len(name) <= 255 && utf8.ValidString(name) && !bytes.ContainsRune([]byte(name), 0)
}

// v3StaticXattrErrno answers a name the authority refuses by fixed policy
// without the round trip, with the Darwin errno that round trip produces: the
// predicate is the authority's own and its errno crosses the same wire
// mapping. It runs after local item and name validation so a stale item or a
// malformed name keeps its own errno.
func v3StaticXattrErrno(name string) int32 {
	if err := xfsstore.ValidateXattr(name); err != nil {
		return linuxToDarwin(errnos.Of(err))
	}
	return 0
}

func linuxToDarwin(value int32) int32 {
	switch value {
	case errnos.EPERM:
		return darwinEPERM
	case errnos.ENOENT:
		return darwinENOENT
	case errnos.EINTR:
		return darwinEINTR
	case errnos.EIO:
		return darwinEIO
	case errnos.ENXIO:
		return darwinENXIO
	case errnos.E2BIG:
		return darwinE2BIG
	case errnos.EBADF:
		return darwinEBADF
	case errnos.EAGAIN:
		return darwinEAGAIN
	case errnos.ENOMEM:
		return darwinENOMEM
	case errnos.EACCES:
		return darwinEACCES
	case errnos.EBUSY:
		return darwinEBUSY
	case errnos.EEXIST:
		return darwinEEXIST
	case errnos.EXDEV:
		return darwinEXDEV
	case errnos.ENODEV:
		return darwinENODEV
	case errnos.ENOTDIR:
		return darwinENOTDIR
	case errnos.EISDIR:
		return darwinEISDIR
	case errnos.EINVAL:
		return darwinEINVAL
	case errnos.ENFILE:
		return darwinENFILE
	case errnos.EMFILE:
		return darwinEMFILE
	case errnos.ENOTTY:
		return darwinENOTTY
	case errnos.ETXTBSY:
		return darwinETXTBSY
	case errnos.EFBIG:
		return darwinEFBIG
	case errnos.ENOSPC:
		return darwinENOSPC
	case errnos.ESPIPE:
		return darwinESPIPE
	case errnos.EROFS:
		return darwinEROFS
	case errnos.EMLINK:
		return darwinEMLINK
	case errnos.EPIPE:
		return darwinEPIPE
	case errnos.ERANGE:
		return darwinERANGE
	case errnos.ENAMETOOLONG:
		return darwinENAMETOOLONG
	case errnos.ENOSYS:
		return darwinENOSYS
	case errnos.ENOTEMPTY:
		return darwinENOTEMPTY
	case errnos.ELOOP:
		return darwinELOOP
	case errnos.ENODATA:
		return darwinENOATTR
	case errnos.EOVERFLOW:
		return darwinEOVERFLOW
	case errnos.EOPNOTSUPP:
		return darwinENOTSUP
	case errnos.ETIMEDOUT:
		return darwinETIMEDOUT
	case errnos.ESTALE:
		return darwinESTALE
	case errnos.EDQUOT:
		return darwinEDQUOT
	default:
		return darwinEIO
	}
}
func v3LocalErrno(err error) int32 {
	if errors.Is(err, context.DeadlineExceeded) {
		return darwinETIMEDOUT
	}
	if errors.Is(err, context.Canceled) {
		return darwinEINTR
	}
	return darwinEIO
}

// scheduledRenewal keeps local cancellation separate from session failure.
// KeepAlive must report terminal transport outcomes independently of ctx.Err().
func (d *v3DataPlane) scheduledRenewal() bool {
	err := d.renewHorizon(context.Background())
	d.mu.Lock()
	authorization := d.authorizationDeadline
	d.mu.Unlock()
	if !authorization.IsZero() && !time.Now().Before(authorization) {
		_ = d.fail(errors.New("installed authority authorization expired"))
		return false
	}
	if err == nil {
		return true
	}
	if (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) && d.client.SessionError() == nil && d.client.LocalAdmissionOpen() {
		select {
		case <-d.client.SessionDone():
			return false
		default:
		}
		return true
	}
	_ = d.fail(err)
	return false
}
