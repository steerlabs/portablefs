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
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

const (
	v3RootItemID  = uint64(1)
	v3FirstItemID = uint64(2)
	// The daemon owns the low half of the raw pfslocal item-ID space. The
	// extension owns the high half for synthetic macOS 26 repair vnodes. FSKit
	// adds one at its boundary, so these become 2...2^63 and
	// 2^63+1...MaxUint64 respectively. Keep
	// this boundary identical to PfsFSKitMapping.localRepairIdentifierFloor:
	// a smaller rolling band exhausted during an ordinary peer-create soak,
	// while unequal boundaries could make a valid daemon item unrepresentable
	// at the FSKit boundary.
	v3RepairItemFloor = uint64(1) << 63
	v3CookieFloor     = uint64(1) << 63
	v3MaxCookies      = 1 << 16
	v3MaxLocalRead    = pfslocal.MaxFrameBytes - 1024
)

// v3DataPlaneClient is the SDK-independent authority surface needed by the
// pfslocal adapter. Credentials and attach/resume state remain wholly inside
// authorityrpc.Client and are never copied into the local socket protocol.
type v3DataPlaneClient interface {
	v3VisibilityClient
	Root() *authoritypb.Item
	IOLimits() (uint32, uint32)
	MaxWriteTransactionBytes() uint64
	SessionLease() time.Duration
	DataPlaneOperationLimit() int
	CallRead(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallReadRetained(context.Context, *authoritypb.Request, func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error)
	CallIdempotent(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallIdempotentRetained(context.Context, *authoritypb.Request, func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error)
	CallMutationWithIdentity(context.Context, *authoritypb.Request, authorityrpc.MutationAssigned) (*authoritypb.Response, error)
	CallMutationWithIdentityRetained(context.Context, *authoritypb.Request, authorityrpc.MutationAssigned, func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error)
}

type v3DataPlaneConfig struct {
	Client         v3DataPlaneClient
	VolumeID       string
	VolumeName     string
	Branch         string
	ItemGeneration uint64
	PrincipalUID   uint32
	PrincipalGID   uint32
	CachePolicy    string
}

type v3ItemRecord struct {
	item   pfslocal.Item
	token  []byte
	attr   *authoritypb.Attr
	root   bool
	parent *pfslocal.Item
	// accepted means at least one completed frontend callback owns this local
	// item. provisional counts resource-bearing replies whose final framework
	// verdict has not arrived yet. Both are protected by v3DataPlane.mu.
	accepted    bool
	provisional uint32
	retiring    bool
}

type v3HandleRecord struct {
	mu     sync.RWMutex
	id     uint64
	token  []byte
	itemID uint64
	append bool
}

type v3ReplyResourceCollector struct {
	d                    *v3DataPlane
	items                []*v3ItemRecord
	handles              []*v3HandleRecord
	responseConsumptions []authorityrpc.ResponseConsumption
	visible              bool
	err                  error
	taken                bool
}

type v3ReplyResourceContextKey struct{}

type v3ResponseConsumptionRevoker func(error)
type v3ResponseConsumptionRevokerContextKey struct{}

type v3ProvisionalResources struct {
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

// v3DataPlane is intentionally not wired into registry.Resolve yet. It is the
// complete, independently testable authority-v3 backend boundary; making it
// constructible does not advertise a live FSKit mount or expose credentials.
type v3DataPlane struct {
	client v3DataPlaneClient
	cfg    v3DataPlaneConfig
	bridge *v3CoherenceBridge

	ctx    context.Context
	cancel context.CancelFunc
	ops    chan struct{}

	mu                   sync.Mutex
	terminal             error
	itemsByID            map[uint64]*v3ItemRecord
	itemsByIdentity      map[[16]byte]*v3ItemRecord
	nextItemID           uint64
	handles              map[uint64]*v3HandleRecord
	nextHandleID         uint64
	cookies              map[uint64]v3CookieRecord
	cookieBatches        map[uint64]*v3CookieBatch
	cookieOrder          list.List
	nextCookieID         uint64
	nextCookieBatch      uint64
	nameMax              uint32
	maxRead              uint32
	maxWrite             uint32
	maxWriteTransaction  uint64
	writeBeginMu         sync.Mutex
	nextWriteTransaction uint64
	reauthMu             sync.Mutex
	reauthSequence       uint64

	failOnce sync.Once
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
	if err != nil {
		return time.Time{}, err
	}
	if !deadline.After(time.Now()) {
		return time.Time{}, errors.New("reauthorization returned an expired deadline")
	}
	d.reauthSequence = sequence
	return deadline, nil
}

func newV3DataPlane(parent context.Context, cfg v3DataPlaneConfig) (*v3DataPlane, error) {
	if parent == nil || cfg.Client == nil || cfg.VolumeID == "" || cfg.VolumeName == "" ||
		cfg.ItemGeneration == 0 || cfg.Branch != "" {
		return nil, errors.New("portablefsd: complete branchless v3 data-plane configuration is required")
	}
	limit := cfg.Client.DataPlaneOperationLimit()
	if limit < 1 {
		return nil, errors.New("portablefsd: v3 authority has no operation capacity after visibility and liveness reserves")
	}
	maxRead, maxWrite := cfg.Client.IOLimits()
	maxWriteTransaction := cfg.Client.MaxWriteTransactionBytes()
	if maxRead == 0 || maxWrite == 0 || maxWriteTransaction < uint64(maxWrite) {
		return nil, errors.New("portablefsd: v3 authority omitted I/O limits")
	}
	ctx, cancel := context.WithCancel(parent)
	d := &v3DataPlane{
		client: cfg.Client, cfg: cfg, ctx: ctx, cancel: cancel,
		ops: make(chan struct{}, limit), itemsByID: make(map[uint64]*v3ItemRecord),
		itemsByIdentity: make(map[[16]byte]*v3ItemRecord), nextItemID: v3FirstItemID,
		handles: make(map[uint64]*v3HandleRecord), nextHandleID: 1,
		cookies: make(map[uint64]v3CookieRecord), cookieBatches: make(map[uint64]*v3CookieBatch),
		nextCookieID: v3CookieFloor, nextCookieBatch: 1,
		nameMax: 255, maxRead: maxRead, maxWrite: maxWrite,
		maxWriteTransaction: maxWriteTransaction, nextWriteTransaction: 1,
	}
	bridge, err := newV3CoherenceBridge(cfg.Client, cfg.CachePolicy, d.recordTerminal)
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
	go d.keepAlive()
	return d, nil
}

func (d *v3DataPlane) installRoot(candidate *authoritypb.Item) (*v3ItemRecord, error) {
	record, err := d.recordFromAuthority(candidate, v3RootItemID, true, nil)
	if err != nil {
		return nil, err
	}
	record.accepted = true
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
	d.mu.Unlock()
	if root == nil {
		return nil
	}
	preferred := min(d.maxRead, d.maxWrite)
	attr, _ := d.localAttr(root, root.attr, nil)
	return &pfslocal.ResolveReply{
		Root: root.item, RootAttr: attr, VolumeID: d.cfg.VolumeID,
		Branch: d.cfg.Branch, VolumeName: d.cfg.VolumeName,
		Capabilities: pfslocal.Capabilities{
			Symlinks: true, HardLinks: true, Xattrs: true, CaseSensitive: true,
			MaxNameBytes: nameMax, MaxFileSize: math.MaxInt64, PreferredIOSize: preferred,
			FlagsSupported: false, FlagsUnderstood: true, XattrSetSupported: false,
		},
		V3Coherence: d.bridge.resolveContract(),
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
	if err := d.bridge.readyForOperations(); err != nil {
		if errors.Is(err, syscall.EAGAIN) {
			return nil, darwinEAGAIN
		}
		return nil, darwinEIO
	}
	// Liveness is intentionally outside ordinary data-plane admission. The
	// authority client routes KeepAlive onto its separately reserved liveness
	// lane, so a saturated operation pool cannot make a healthy strict session
	// look dead to FSKit.
	if request, ok := body.(*pfslocal.V3LivenessRequest); ok {
		return d.v3Liveness(ctx, request)
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
	case *pfslocal.EnumerateRequest:
		return d.enumerate(ctx, operationID, request)
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
	case *pfslocal.FsyncRequest:
		return d.fsync(ctx, request)
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
	case *pfslocal.XattrSetRequest:
		return d.xattrSet(ctx, operationID, request)
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

func (d *v3DataPlane) v3Liveness(ctx context.Context, request *pfslocal.V3LivenessRequest) (any, int32) {
	epoch, session := d.client.Epoch(), d.client.SessionID()
	if request == nil || len(request.AuthorityEpoch) != 16 || len(request.SessionID) != 16 ||
		!bytes.Equal(request.AuthorityEpoch, epoch) || !bytes.Equal(request.SessionID, session) {
		return nil, darwinEINVAL
	}
	if d.terminalError() != nil {
		return nil, darwinEIO
	}
	response, errno := d.callRead(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if errno != 0 || response == nil || response.GetUncertain() || response.GetErrno() != 0 ||
		response.GetRoutesMismatch().GetSessionRefused() {
		_ = d.fail(errors.New("portablefsd: authority liveness proof was refused"))
		return nil, darwinEIO
	}
	return &pfslocal.V3LivenessReply{
		AuthorityEpoch: cloneBytesV3(epoch),
		SessionID:      cloneBytesV3(session),
	}, 0
}

func (d *v3DataPlane) lookup(ctx context.Context, operationID uint64, request *pfslocal.LookupRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 || !visibilitywire.ValidName(request.Name) {
		if errno == 0 {
			errno = darwinEINVAL
		}
		return nil, errno
	}
	response, errno := d.callNonVisibleMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name)}}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetLookup() == nil {
		return d.malformed("lookup omitted reply")
	}
	record, errno := d.intern(ctx, response.GetLookup().GetItem(), &parent.item)
	if errno != 0 {
		return nil, errno
	}
	collectV3ReplyItem(ctx, record)
	attr, err := d.localAttr(record, response.GetLookup().GetItem().GetAttr(), &parent.item)
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
	query := &authoritypb.GetAttrRequest{Item: cloneBytesV3(item.token)}
	var handle *v3HandleRecord
	if request.Handle != 0 {
		handle, errno = d.handle(request.Handle, item.item.ItemID)
		if errno != 0 {
			return nil, errno
		}
		handle.mu.RLock()
		defer handle.mu.RUnlock()
		query.Handle = cloneBytesV3(handle.token)
	}
	response, errno := d.callRead(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: query}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetGetAttr() == nil || response.GetGetAttr().GetAttr() == nil {
		return d.malformed("getattr omitted attr")
	}
	attr, err := d.localAttr(item, response.GetGetAttr().GetAttr(), item.parent)
	if err != nil {
		return d.malformed(err.Error())
	}
	d.updateAttr(item, response.GetGetAttr().GetAttr())
	return &pfslocal.GetAttrReply{Attr: attr}, 0
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
		handle, errno = d.handle(request.Handle, item.item.ItemID)
		if errno != 0 {
			return nil, errno
		}
		handle.mu.RLock()
		defer handle.mu.RUnlock()
		set.Handle = cloneBytesV3(handle.token)
	}
	if set.Mode == nil && set.Size == nil && set.MtimeNs == nil && set.AtimeNs == nil {
		return d.getattr(ctx, operationID, &pfslocal.GetAttrRequest{Item: request.Item, Handle: request.Handle})
	}
	gate, err := v3ItemSourceGate(item.item, set.Size != nil)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: set}}, gate)
	if errno != 0 {
		return nil, errno
	}
	if v3PostAttr(response) == nil {
		return d.malformed("setattr omitted committed post-attr")
	}
	attr, err := d.localAttr(item, v3PostAttr(response), item.parent)
	if err != nil {
		return d.malformed(err.Error())
	}
	d.updateAttr(item, v3PostAttr(response))
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
	handle, err := d.installHandle(response.GetOpen().GetHandle(), item.item.ItemID, request.Append)
	if err != nil {
		return d.malformed(err.Error())
	}
	collectV3ReplyHandle(ctx, handle)
	return &pfslocal.OpenReply{Handle: handle.id}, 0
}

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
	handle.mu.Lock()
	defer handle.mu.Unlock()
	response, errno := d.callNonVisibleMutation(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytesV3(handle.token)}}})
	if errno != 0 {
		return nil, errno
	}
	_ = response
	d.mu.Lock()
	if d.handles[request.Handle] == handle {
		delete(d.handles, request.Handle)
		for batchID, batch := range d.cookieBatches {
			if batch.handleID == request.Handle {
				d.removeCookieBatchLocked(batchID)
			}
		}
	}
	d.mu.Unlock()
	return &pfslocal.CloseReply{Retired: true}, 0
}

func (d *v3DataPlane) read(ctx context.Context, operationID uint64, request *pfslocal.ReadRequest) (any, int32) {
	if request.Length > v3MaxLocalRead {
		return nil, darwinEOVERFLOW
	}
	handle, errno := d.handle(request.Handle, 0)
	if errno != 0 {
		return nil, errno
	}
	handle.mu.RLock()
	defer handle.mu.RUnlock()
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

func (d *v3DataPlane) write(ctx context.Context, operationID uint64, request *pfslocal.WriteRequest) (any, int32) {
	if uint64(len(request.Data)) > d.maxWriteTransaction {
		return nil, darwinEINVAL
	}
	if request.Offset >= math.MaxInt64 {
		return nil, darwinEFBIG
	}
	handle, errno := d.handle(request.Handle, 0)
	if errno != 0 {
		return nil, errno
	}
	d.mu.Lock()
	item := d.itemsByID[handle.itemID]
	d.mu.Unlock()
	if item == nil {
		return d.malformed("write handle lost its item")
	}
	if len(request.Data) == 0 {
		// A zero-length write has no mutation or append-position semantics. Ask
		// the authority for the current attributes so the FSKit reply remains
		// exact without allocating or staging a transaction identity.
		getattrAny, errno := d.getattr(ctx, operationID, &pfslocal.GetAttrRequest{
			Item:   item.item,
			Handle: request.Handle,
		})
		if errno != 0 {
			return nil, errno
		}
		return &pfslocal.WriteReply{Attr: getattrAny.(*pfslocal.GetAttrReply).Attr}, 0
	}
	handle.mu.RLock()
	defer handle.mu.RUnlock()
	appendWrite := handle.append || request.Append
	if appendWrite {
		// Server-positioned append is a mandatory patched-Linux transaction.
		// The macOS 26 FSKit API supplies only a kernel-chosen position here;
		// it cannot carry the authority-owned append intent required for atomic
		// cross-client append. Refuse an explicit append bit rather than silently
		// routing it through positional Write. Ordinary macOS O_APPEND remains
		// inside the documented best-effort platform boundary.
		return nil, darwinENOTSUP
	}
	gate, err := v3ItemSourceGate(item.item, true)
	if err != nil {
		return d.malformed(err.Error())
	}
	tx := v3WriteTransaction{
		handle: cloneBytesV3(handle.token), requestedSize: uint64(len(request.Data)),
		position: request.Offset, rlimitFsize: math.MaxUint64, fileMaxSize: math.MaxInt64,
		writeFlags: v3WriteFlagKillSUIDGID,
	}
	response, errno := d.executeWriteTransaction(ctx, operationID, &tx, request.Data, gate)
	if errno != 0 {
		return nil, errno
	}
	reply := response.GetWriteTransaction()
	if err := validV3WriteCommit(tx, response); err != nil {
		return d.malformed(err.Error())
	}
	if v3PostAttr(response).GetInode() != item.attr.GetInode() {
		return d.malformed("write transaction changed its inode identity")
	}
	attr, err := d.localAttr(item, v3PostAttr(response), item.parent)
	if err != nil {
		return d.malformed(err.Error())
	}
	d.updateAttr(item, v3PostAttr(response))
	if reply.GetFlags() == v3WriteReplyCommitted|v3WriteReplyPostApply {
		_ = d.fail(fmt.Errorf("portablefsd: authority committed %d write bytes but macOS 26 FSKit cannot publish post-apply errno %d", reply.GetCommittedSize(), reply.GetError()))
		return nil, darwinEIO
	}
	return &pfslocal.WriteReply{Written: uint32(reply.GetCommittedSize()), Attr: attr}, 0
}

func (d *v3DataPlane) fsync(ctx context.Context, request *pfslocal.FsyncRequest) (any, int32) {
	handle, errno := d.handle(request.Handle, 0)
	if errno != 0 {
		return nil, errno
	}
	handle.mu.RLock()
	defer handle.mu.RUnlock()
	response, errno := d.callRead(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: cloneBytesV3(handle.token)}}})
	if errno != 0 {
		return nil, errno
	}
	_ = response
	return &pfslocal.FsyncReply{}, 0
}

func (d *v3DataPlane) create(ctx context.Context, operationID uint64, request *pfslocal.CreateRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if !visibilitywire.ValidName(request.Name) {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
		Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Mode: request.Mode,
		Flags: &authoritypb.OpenFlags{Read: true, Write: true, Append: request.Append}, Exclusive: request.Exclusive,
	}}}, gate)
	if errno != 0 {
		return nil, errno
	}
	created := response.GetCreate()
	if created == nil || created.GetItem() == nil || len(created.GetHandle()) != 16 {
		return d.malformed("create omitted item or handle")
	}
	identity, err := authorityIdentity(created.GetItem())
	if err != nil {
		return d.malformed(err.Error())
	}
	if err := d.bridge.sourcePublication.operationLease(operationID).attachBinding(
		gate,
		v3PublicationNamespace{parent: v3PublicationIdentity(parent.item.StableIdentity), name: string(request.Name)},
		v3PublicationIdentity(identity),
	); err != nil {
		return d.malformed(err.Error())
	}
	record, errno := d.intern(ctx, created.GetItem(), &parent.item)
	if errno != 0 {
		return nil, errno
	}
	handle, err := d.installHandle(created.GetHandle(), record.item.ItemID, request.Append)
	if err != nil {
		return d.malformed(err.Error())
	}
	collectV3ReplyItem(ctx, record)
	collectV3ReplyHandle(ctx, handle)
	attr, err := d.localAttr(record, created.GetItem().GetAttr(), &parent.item)
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
	if !visibilitywire.ValidName(request.Name) {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Mode: request.Mode}}}, gate)
	if errno != 0 {
		return nil, errno
	}
	if response.GetLookup() == nil {
		return d.malformed("mkdir omitted item")
	}
	identity, err := authorityIdentity(response.GetLookup().GetItem())
	if err != nil {
		return d.malformed(err.Error())
	}
	if err := d.bridge.sourcePublication.operationLease(operationID).attachBinding(
		gate,
		v3PublicationNamespace{parent: v3PublicationIdentity(parent.item.StableIdentity), name: string(request.Name)},
		v3PublicationIdentity(identity),
	); err != nil {
		return d.malformed(err.Error())
	}
	record, errno := d.intern(ctx, response.GetLookup().GetItem(), &parent.item)
	if errno != 0 {
		return nil, errno
	}
	collectV3ReplyItem(ctx, record)
	attr, err := d.localAttr(record, response.GetLookup().GetItem().GetAttr(), &parent.item)
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
	if !visibilitywire.ValidName(request.Name) {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	_, errno = d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Directory: request.Directory}}}, gate)
	if errno != 0 {
		return nil, errno
	}
	if err := d.bridge.sourcePublication.operationLease(operationID).resolveNoBinding(
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
	if !visibilitywire.ValidName(request.FromName) || !visibilitywire.ValidName(request.ToName) {
		return nil, darwinEINVAL
	}
	gate, err := v3RenameSourceGate(from.item, request.FromName, to.item, request.ToName)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
		OldParent: cloneBytesV3(from.token), OldName: cloneBytesV3(request.FromName), NewParent: cloneBytesV3(to.token), NewName: cloneBytesV3(request.ToName), NoReplace: request.NoReplace,
	}}}, gate)
	if errno != 0 {
		return nil, errno
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
	lease := d.bridge.sourcePublication.operationLease(operationID)
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

func (d *v3DataPlane) symlink(ctx context.Context, operationID uint64, request *pfslocal.SymlinkRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if !visibilitywire.ValidName(request.Name) || bytes.IndexByte(request.Target, 0) >= 0 {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Target: cloneBytesV3(request.Target)}}}, gate)
	if errno != 0 {
		return nil, errno
	}
	if response.GetLookup() == nil {
		return d.malformed("symlink omitted item")
	}
	identity, err := authorityIdentity(response.GetLookup().GetItem())
	if err != nil {
		return d.malformed(err.Error())
	}
	if err := d.bridge.sourcePublication.operationLease(operationID).attachBinding(
		gate,
		v3PublicationNamespace{parent: v3PublicationIdentity(parent.item.StableIdentity), name: string(request.Name)},
		v3PublicationIdentity(identity),
	); err != nil {
		return d.malformed(err.Error())
	}
	record, errno := d.intern(ctx, response.GetLookup().GetItem(), &parent.item)
	if errno != 0 {
		return nil, errno
	}
	collectV3ReplyItem(ctx, record)
	attr, err := d.localAttr(record, response.GetLookup().GetItem().GetAttr(), &parent.item)
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
	if !visibilitywire.ValidName(request.Name) {
		return nil, darwinEINVAL
	}
	gate, err := v3NamespaceSourceGate(parent.item, request.Name, false, item.item)
	if err != nil {
		return d.malformed(err.Error())
	}
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{ExistingItem: cloneBytesV3(item.token), NewParent: cloneBytesV3(parent.token), NewName: cloneBytesV3(request.Name)}}}, gate)
	if errno != 0 {
		return nil, errno
	}
	linked := response.GetLink()
	if linked == nil || linked.GetItem() == nil {
		return d.malformed("hard link omitted item")
	}
	identity, err := authorityIdentity(linked.GetItem())
	if err != nil || identity != item.item.StableIdentity {
		return d.malformed("hard link changed stable identity")
	}
	if err := d.bridge.sourcePublication.operationLease(operationID).attachBinding(
		gate,
		v3PublicationNamespace{parent: v3PublicationIdentity(parent.item.StableIdentity), name: string(request.Name)},
		v3PublicationIdentity(identity),
	); err != nil {
		return d.malformed(err.Error())
	}
	record, errno := d.intern(ctx, linked.GetItem(), &parent.item)
	if errno != 0 {
		return nil, errno
	}
	if record.item != item.item {
		return d.malformed("hard-link alias acquired a different local item")
	}
	attr, err := d.localAttr(record, linked.GetItem().GetAttr(), &parent.item)
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.HardLinkReply{Name: cloneBytesV3(request.Name), Attr: attr}, 0
}

func (d *v3DataPlane) xattrGet(ctx context.Context, operationID uint64, request *pfslocal.XattrGetRequest) (any, int32) {
	item, handle, errno := d.itemAndOptionalHandle(request.Item, request.Handle)
	if errno != 0 {
		return nil, errno
	}
	if !validXattrName(request.Name) {
		return nil, darwinEINVAL
	}
	if handle != nil {
		handle.mu.RLock()
		defer handle.mu.RUnlock()
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

func (d *v3DataPlane) xattrSet(ctx context.Context, operationID uint64, request *pfslocal.XattrSetRequest) (any, int32) {
	item, handle, errno := d.itemAndOptionalHandle(request.Item, request.Handle)
	if errno != 0 {
		return nil, errno
	}
	if !validXattrName(request.Name) || request.CreateOnly && request.ReplaceOnly {
		return nil, darwinEINVAL
	}
	if handle != nil {
		handle.mu.RLock()
		defer handle.mu.RUnlock()
	}
	mode := authoritypb.SetXattrRequest_UPSERT
	if request.CreateOnly {
		mode = authoritypb.SetXattrRequest_CREATE
	}
	if request.ReplaceOnly {
		mode = authoritypb.SetXattrRequest_REPLACE
	}
	query := &authoritypb.SetXattrRequest{Item: cloneBytesV3(item.token), Name: []byte(request.Name), Value: cloneBytesV3(request.Value), Mode: mode}
	if handle != nil {
		query.Handle = cloneBytesV3(handle.token)
	}
	gate, err := v3ItemSourceGate(item.item, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	_, errno = d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_SetXattr{SetXattr: query}}, gate)
	if errno != 0 {
		return nil, errno
	}
	return &pfslocal.XattrSetReply{}, 0
}

func (d *v3DataPlane) xattrList(ctx context.Context, operationID uint64, request *pfslocal.XattrListRequest) (any, int32) {
	item, handle, errno := d.itemAndOptionalHandle(request.Item, request.Handle)
	if errno != 0 {
		return nil, errno
	}
	if handle != nil {
		handle.mu.RLock()
		defer handle.mu.RUnlock()
	}
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
	item, handle, errno := d.itemAndOptionalHandle(request.Item, request.Handle)
	if errno != 0 {
		return nil, errno
	}
	if !validXattrName(request.Name) {
		return nil, darwinEINVAL
	}
	if handle != nil {
		handle.mu.RLock()
		defer handle.mu.RUnlock()
	}
	query := &authoritypb.RemoveXattrRequest{Item: cloneBytesV3(item.token), Name: []byte(request.Name)}
	if handle != nil {
		query.Handle = cloneBytesV3(handle.token)
	}
	gate, err := v3ItemSourceGate(item.item, false)
	if err != nil {
		return d.malformed(err.Error())
	}
	_, errno = d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: query}}, gate)
	if errno != 0 {
		return nil, errno
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
	return &pfslocal.SyncVolumeReply{Degraded: false}, 0
}

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
	d.mu.Lock()
	if d.itemsByID[record.item.ItemID] != record {
		d.mu.Unlock()
		return &pfslocal.ReclaimReply{}, 0
	}
	if record.provisional != 0 {
		// The current FSItem is gone, but an overlapping resource reply may be
		// about to transfer the same canonical local item back into VolumeCore.
		// Leave the authority capability live until that exact disposition; the
		// final abandon reclaims it, while an accept becomes its new owner.
		record.accepted = false
		d.mu.Unlock()
		return &pfslocal.ReclaimReply{}, 0
	}
	if record.retiring {
		d.mu.Unlock()
		return &pfslocal.ReclaimReply{}, 0
	}
	record.retiring = true
	d.mu.Unlock()
	response, errno := d.callNonVisibleMutation(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: cloneBytesV3(record.token)}}})
	if errno != 0 {
		d.mu.Lock()
		if d.itemsByID[record.item.ItemID] == record {
			record.retiring = false
		}
		d.mu.Unlock()
		return nil, errno
	}
	_ = response
	d.mu.Lock()
	if d.itemsByID[record.item.ItemID] == record {
		delete(d.itemsByID, record.item.ItemID)
		delete(d.itemsByIdentity, record.item.StableIdentity)
		for batchID, batch := range d.cookieBatches {
			if batch.dirID == record.item.ItemID {
				d.removeCookieBatchLocked(batchID)
			}
		}
	}
	d.mu.Unlock()
	return &pfslocal.ReclaimReply{}, 0
}

func (d *v3DataPlane) enumerate(ctx context.Context, operationID uint64, request *pfslocal.EnumerateRequest) (result any, errno int32) {
	dir, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if request.MaxEntries == 0 || request.MaxEntries > 4096 {
		return nil, darwinEINVAL
	}
	handle, errno := d.handle(request.Handle, dir.item.ItemID)
	if errno != 0 {
		return nil, errno
	}
	// Authority enumeration cookies are positions on one retained XFS open
	// directory description. Keep that exact handle alive and immutable across
	// the read: opening a fresh authority handle for each pfslocal page resets
	// its cursor high-water mark to zero, so every nonzero continuation is
	// correctly rejected as ESTALE. FSKit already gives directory walks an
	// open/close lifecycle; VolumeCore carries that existing read handle here.
	handle.mu.RLock()
	defer handle.mu.RUnlock()
	var position v3CookieRecord
	if request.Cookie != 0 {
		var ok bool
		position, ok = d.resolveCookie(dir.item.ItemID, request.Handle, request.Cookie)
		if !ok {
			return nil, darwinESTALE
		}
	}
	response, errno := d.callNonVisibleMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{
		Handle: cloneBytesV3(handle.token), Cookie: cloneBytesV3(position.cookie), Verifier: cloneBytesV3(position.verifier), MaxEntries: request.MaxEntries, WantItems: true,
	}}})
	if errno != 0 {
		return nil, errno
	}
	page := response.GetReadDir()
	if page == nil || len(page.GetVerifier()) != 16 || len(page.GetEntries()) == 0 && !page.GetEof() {
		return d.malformed("readdir-plus returned a malformed page")
	}
	reply := &pfslocal.EnumerateReply{DirVersion: v3VerifierVersion(page.GetVerifier())}
	type pendingDirectoryEntry struct {
		name []byte
		attr *pfslocal.Attr
	}
	positions := make([]v3CookieRecord, 0, len(page.GetEntries()))
	pendingEntries := make([]pendingDirectoryEntry, 0, len(page.GetEntries()))
	for _, entry := range page.GetEntries() {
		if entry == nil || !visibilitywire.ValidName(entry.GetName()) || len(entry.GetNextCookie()) == 0 || entry.GetAttr() == nil {
			return d.malformed("readdir-plus omitted name, cookie, or attributes")
		}
		positions = append(positions, v3CookieRecord{
			dirID: dir.item.ItemID, handleID: request.Handle,
			cookie:   cloneBytesV3(entry.GetNextCookie()),
			verifier: cloneBytesV3(page.GetVerifier()),
		})
		if entry.GetItem() == nil {
			// An opaque entry: the authority lists a name whose inode it never
			// exposes (a device node, FIFO, socket, or foreign-owned inode
			// another writer placed in the tree) and issues no capability for
			// it. There is no item to publish to FSKit, but enumeration must
			// still advance past the name, so its cookie is recorded without a
			// directory entry — the same shape as a local readdir listing a
			// name whose stat then fails.
			pendingEntries = append(pendingEntries, pendingDirectoryEntry{})
			continue
		}
		if entry.GetItem().GetAttr() == nil || entry.GetAttr().GetInode() != entry.GetItem().GetAttr().GetInode() || entry.GetAttr().GetKind() != entry.GetItem().GetAttr().GetKind() {
			return d.malformed("readdir-plus item and dirent attr disagree")
		}
		record, localErrno := d.intern(ctx, entry.GetItem(), &dir.item)
		if localErrno != 0 {
			return nil, localErrno
		}
		collectV3ReplyItem(ctx, record)
		attr, err := d.localAttr(record, entry.GetItem().GetAttr(), &dir.item)
		if err != nil {
			return d.malformed(err.Error())
		}
		pendingEntries = append(pendingEntries, pendingDirectoryEntry{
			name: cloneBytesV3(entry.GetName()), attr: &attr,
		})
	}
	cookies, err := d.issueCookieBatch(positions)
	if err != nil {
		return nil, darwinEOVERFLOW
	}
	for index, pending := range pendingEntries {
		cookie := cookies[index]
		if pending.attr != nil {
			reply.Entries = append(reply.Entries, pfslocal.DirEntry{
				Name: pending.name, Attr: *pending.attr, Cookie: cookie,
			})
		}
		reply.NextCookie = cookie
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
		if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(operationID, consumption); err != nil {
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
		response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY ||
		response.GetVisibilityRetrySequence() != 0 ||
		response.GetRoutesMismatch().GetSessionRefused() {
		return errors.New("portablefsd: authority returned a terminal retained outcome")
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

func (d *v3DataPlane) callMutation(ctx context.Context, operationID uint64, request *authoritypb.Request, gate *authoritypb.SourcePublicationGate) (*authoritypb.Response, int32) {
	if operationID == 0 || request == nil {
		return nil, darwinEINVAL
	}
	if request.GetVisibilityRetryAfterSequence() != 0 {
		_ = d.fail(errors.New("portablefsd: callback-serialized mutation carried a Linux-only visibility retry proof"))
		return nil, darwinEIO
	}
	lease, err := d.bridge.sourcePublication.acquireSource(ctx, operationID, gate)
	if err != nil {
		if errors.Is(err, errV3SourcePublicationInterrupted) && d.cfg.CachePolicy == v3CachePolicyMacOS26 {
			return nil, darwinECANCELED
		}
		return nil, v3LocalErrno(err)
	}
	request.SourcePublicationGate = gate
	// Carry the exact pfslocal publication/callback identity into authority
	// scheduling as retry-fairness metadata. Publication ownership itself is
	// represented only by the canonical gate above; there is no source phase.
	request.FrontendOperationId = operationID
	var assigned authorityrpc.MutationIdentity
	response, consumption, callErr := d.client.CallMutationWithIdentityRetained(ctx, request, func(identity authorityrpc.MutationIdentity) error {
		assigned = identity
		return lease.markAssigned()
	}, func(cause error) {
		// The authority holds a terminal response until this callback proves the
		// qualification frontend has either published it or revoked its serving
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
	if assigned.Sequence != 0 {
		if callErr != nil || response == nil || response.GetUncertain() ||
			response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_STORAGE ||
			response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE ||
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
			return nil, darwinEIO
		}
		state := response.GetMutation()
		if state == nil || state.GetSlot() != assigned.Slot || state.GetAcceptedSequence() != assigned.Sequence {
			d.revokeRetainedResponse(ctx, errors.New("portablefsd: assigned source mutation changed its replay identity"))
			return nil, darwinEIO
		}
	}
	if response != nil && response.GetErrno() != 0 {
		if err := lease.resolveNoBindings(gate); err != nil {
			d.revokeRetainedResponse(ctx, err)
			return nil, darwinEIO
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
		response.GetRoutesMismatch().GetSessionRefused() {
		cause := callErr
		if cause == nil {
			cause = errors.New("portablefsd: authority returned a terminal or malformed retained mutation outcome")
		}
		d.revokeRetainedResponse(ctx, cause)
		return nil, darwinEIO
	}
	classified, errno := d.classify(response, nil, true)
	if errno != 0 {
		if consumption != nil {
			if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(operationID, consumption); err != nil {
				d.revokeRetainedResponse(ctx, err)
				return nil, darwinEIO
			}
			retained = true
		}
		return classified, errno
	}
	if assigned.Sequence == 0 {
		d.revokeRetainedResponse(ctx, errors.New("portablefsd: successful source mutation omitted replay assignment"))
		return nil, darwinEIO
	}
	if _, rejected := exactV3WriteRejection(request, classified); rejected {
		if err := lease.resolveNoBindings(gate); err != nil {
			d.revokeRetainedResponse(ctx, err)
			return nil, darwinEIO
		}
		if consumption != nil {
			if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(operationID, consumption); err != nil {
				d.revokeRetainedResponse(ctx, err)
				return nil, darwinEIO
			}
			retained = true
		}
		return classified, 0
	}
	if err := lease.markCommitted(); err != nil {
		d.revokeRetainedResponse(ctx, err)
		return nil, darwinEIO
	}
	if err := lease.retainResponseConsumption(consumption); err != nil {
		d.revokeRetainedResponse(ctx, err)
		return nil, darwinEIO
	}
	retained = true
	return classified, 0
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
				if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(operationID, consumption); err != nil {
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
	if response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY || response.GetVisibilityRetrySequence() != 0 {
		_ = d.fail(errors.New("portablefsd: authority returned a Linux-only visibility retry to a callback-serialized frontend"))
		return nil, darwinEIO
	}
	if response.GetErrno() != 0 {
		if response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_INTERRUPTED {
			if response.GetErrno() != errnos.EINTR {
				_ = d.fail(errors.New("portablefsd: authority returned a malformed visibility interruption"))
				return nil, darwinEIO
			}
			// v1's frozen contract exposed the authority's definite-preapply
			// EINTR unchanged. v2 translates the same proof to ECANCELED: the
			// callback must release FSKit's namespace lane so the repair that
			// caused the refusal can enter, but macOS 26 must not silently replay
			// it as it does EINTR, EBUSY, and EAGAIN. Retrying inside this callback
			// deadlocks because the nested repair uses that same lane.
			if d.cfg.CachePolicy == v3CachePolicyMacOS26 {
				return response, darwinECANCELED
			}
		}
		return response, linuxToDarwin(response.GetErrno())
	}
	return response, 0
}

func (d *v3DataPlane) intern(ctx context.Context, candidate *authoritypb.Item, parent *pfslocal.Item) (*v3ItemRecord, int32) {
	parsed, err := d.recordFromAuthority(candidate, 0, false, parent)
	if err != nil {
		_, errno := d.malformed(err.Error())
		return nil, errno
	}
	d.mu.Lock()
	if existing := d.itemsByIdentity[parsed.item.StableIdentity]; existing != nil {
		if existing.retiring {
			// Reclaim has detached the old authority capability, but the inode may
			// be resolved again before that exact Reclaim round trip finishes.
			// Replace the retiring carrier while preserving the canonical local ID;
			// the old completion deletes only its own pointer and therefore cannot
			// erase this new ownership generation.
			parsed.item.ItemID = existing.item.ItemID
			d.itemsByID[parsed.item.ItemID] = parsed
			d.itemsByIdentity[parsed.item.StableIdentity] = parsed
			d.mu.Unlock()
			return parsed, 0
		}
		existing.attr = parsed.attr
		if parent != nil {
			copyParent := *parent
			existing.parent = &copyParent
		}
		retained := bytes.Equal(existing.token, parsed.token)
		d.mu.Unlock()
		if !retained {
			_, errno := d.callNonVisibleMutation(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: parsed.token}}})
			if errno != 0 {
				_ = d.fail(errors.New("portablefsd: could not reclaim duplicate item capability"))
				return nil, darwinEIO
			}
		}
		return existing, 0
	}
	if d.nextItemID >= v3RepairItemFloor {
		d.mu.Unlock()
		_, errno := d.malformed("local item identifier space exhausted")
		return nil, errno
	}
	parsed.item.ItemID = d.nextItemID
	d.nextItemID++
	d.itemsByID[parsed.item.ItemID] = parsed
	d.itemsByIdentity[parsed.item.StableIdentity] = parsed
	d.mu.Unlock()
	return parsed, 0
}

func (d *v3DataPlane) recordFromAuthority(candidate *authoritypb.Item, itemID uint64, root bool, parent *pfslocal.Item) (*v3ItemRecord, error) {
	identity, err := authorityIdentity(candidate)
	if err != nil {
		return nil, err
	}
	if candidate.GetAttr() == nil || candidate.GetAttr().GetInode() == 0 || candidate.GetAttr().GetSize() < 0 || !validAuthorityKind(candidate.GetAttr().GetKind()) {
		return nil, errors.New("authority item has malformed attributes")
	}
	record := &v3ItemRecord{item: pfslocal.Item{ItemID: itemID, ItemGeneration: d.cfg.ItemGeneration, StableIdentity: identity}, token: cloneBytesV3(candidate.GetToken()), attr: cloneAuthorityAttr(candidate.GetAttr()), root: root}
	if parent != nil {
		copied := *parent
		record.parent = &copied
	}
	return record, nil
}

func (d *v3DataPlane) localAttr(record *v3ItemRecord, attr *authoritypb.Attr, parent *pfslocal.Item) (pfslocal.Attr, error) {
	if record == nil || attr == nil || attr.GetInode() == 0 || attr.GetSize() < 0 {
		return pfslocal.Attr{}, errors.New("malformed authority attr")
	}
	kind, ok := localItemKind(attr.GetKind())
	if !ok {
		return pfslocal.Attr{}, errors.New("unknown authority item kind")
	}
	if attr.GetBlocks() > math.MaxUint64/512 {
		return pfslocal.Attr{}, errors.New("authority allocation size overflow")
	}
	result := pfslocal.Attr{Item: record.item, Kind: kind, Mode: attr.GetMode(), Nlink: attr.GetNlink(), UID: d.cfg.PrincipalUID, GID: d.cfg.PrincipalGID, Size: uint64(attr.GetSize()), MtimeMs: nanosToMillis(attr.GetMtimeNs()), CtimeMs: nanosToMillis(attr.GetCtimeNs()), AtimeMs: nanosToMillis(attr.GetAtimeNs()), BirthtimeMs: nanosToMillis(attr.GetBirthTimeNs()), AllocSize: attr.GetBlocks() * 512}
	if parent != nil {
		copied := *parent
		result.Parent = &copied
	} else if record.parent != nil {
		copied := *record.parent
		result.Parent = &copied
	}
	return result, nil
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

func (d *v3DataPlane) handle(id, itemID uint64) (*v3HandleRecord, int32) {
	if id == 0 {
		return nil, darwinEBADF
	}
	d.mu.Lock()
	handle := d.handles[id]
	d.mu.Unlock()
	if handle == nil || itemID != 0 && handle.itemID != itemID {
		return nil, darwinEBADF
	}
	return handle, 0
}

func (d *v3DataPlane) itemAndOptionalHandle(itemValue pfslocal.Item, handleID uint64) (*v3ItemRecord, *v3HandleRecord, int32) {
	item, errno := d.item(itemValue)
	if errno != 0 {
		return nil, nil, errno
	}
	if handleID == 0 {
		return item, nil, 0
	}
	handle, errno := d.handle(handleID, item.item.ItemID)
	return item, handle, errno
}

func (d *v3DataPlane) installHandle(token []byte, itemID uint64, appendMode bool) (*v3HandleRecord, error) {
	if len(token) != 16 {
		return nil, errors.New("malformed authority handle")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nextHandleID == 0 {
		return nil, errors.New("local handle identifier space exhausted")
	}
	handle := &v3HandleRecord{id: d.nextHandleID, token: cloneBytesV3(token), itemID: itemID, append: appendMode}
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

func (d *v3DataPlane) updateAttr(record *v3ItemRecord, attr *authoritypb.Attr) {
	d.mu.Lock()
	if d.itemsByID[record.item.ItemID] == record {
		record.attr = cloneAuthorityAttr(attr)
	}
	d.mu.Unlock()
}

func collectV3ReplyItem(ctx context.Context, item *v3ItemRecord) {
	collector, _ := ctx.Value(v3ReplyResourceContextKey{}).(*v3ReplyResourceCollector)
	if collector == nil || collector.d == nil || item == nil {
		return
	}
	collector.d.mu.Lock()
	defer collector.d.mu.Unlock()
	if collector.d.itemsByID[item.item.ItemID] != item || item.retiring || item.provisional == math.MaxUint32 {
		if collector.err == nil {
			collector.err = errors.New("portablefsd: reply item is not claimable")
		}
		return
	}
	// Each enumeration occurrence is a distinct provisional transfer even when
	// two hard-link names share one local item ID. The final prefix count is in
	// this exact order, so duplicates must not be collapsed here.
	item.provisional++
	collector.items = append(collector.items, item)
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
	}
	collector.responseConsumptions = nil
	return resources, collector.err
}

// abandonCollectedReplyResources rolls back resources acquired before reply
// construction failed. Handlers collect immediately after intern/install, so
// a later attr/cookie/encoding failure cannot leave an unreachable local
// capability even though no successful reply was registered for disposition.
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
	for _, item := range resources.items {
		if item.provisional == 0 {
			d.mu.Unlock()
			return nil, errors.New("portablefsd: provisional item ownership settled twice")
		}
	}
	for index, item := range resources.items {
		item.provisional--
		acceptItem := uint32(index) < acceptedItemCount
		if acceptItem {
			item.accepted = true
		} else if !item.accepted && item.provisional == 0 && !item.retiring && d.itemsByID[item.item.ItemID] == item {
			item.retiring = true
			delete(d.itemsByID, item.item.ItemID)
			delete(d.itemsByIdentity, item.item.StableIdentity)
			for batchID, batch := range d.cookieBatches {
				if batch.dirID == item.item.ItemID {
					d.removeCookieBatchLocked(batchID)
				}
			}
			cleanup.items = append(cleanup.items, item)
		}
	}
	if !acceptHandles {
		for _, handle := range resources.handles {
			if d.handles[handle.id] == handle {
				delete(d.handles, handle.id)
				for batchID, batch := range d.cookieBatches {
					if batch.handleID == handle.id {
						d.removeCookieBatchLocked(batchID)
					}
				}
				cleanup.handles = append(cleanup.handles, handle)
			}
		}
	}
	d.mu.Unlock()
	if cleanup.terminalReason != nil {
		// Record the missing callback publication before the serial frontend
		// reader can process a following PublicationAck. Closing the authority
		// session retires all capabilities, so terminal cleanup does not race a
		// best-effort per-resource RPC against that close.
		_ = d.fail(cleanup.terminalReason)
	}
	return cleanup, nil
}

func (cleanup *v3ResourceCleanup) finish() error {
	if cleanup == nil || cleanup.d == nil {
		return nil
	}
	if cleanup.terminalReason != nil {
		return cleanup.terminalReason
	}
	if len(cleanup.handles) == 0 && len(cleanup.items) == 0 {
		return nil
	}
	d := cleanup.d
	ctx, cancel := context.WithTimeout(d.ctx, operationAdmissionBudgetValue())
	defer cancel()
	for _, handle := range cleanup.handles {
		handle.mu.Lock()
		response, errno := d.callNonVisibleMutation(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytesV3(handle.token)}}})
		handle.mu.Unlock()
		if errno != 0 {
			return d.fail(fmt.Errorf("portablefsd: abandon provisional handle %d failed with errno %d", handle.id, errno))
		}
		_ = response
	}
	for _, item := range cleanup.items {
		response, errno := d.callNonVisibleMutation(ctx, 0, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: cloneBytesV3(item.token)}}})
		if errno != 0 {
			return d.fail(fmt.Errorf("portablefsd: abandon provisional item %d failed with errno %d", item.item.ItemID, errno))
		}
		_ = response
	}
	return nil
}

func (d *v3DataPlane) malformed(detail string) (any, int32) {
	_ = d.fail(errors.New("portablefsd: " + detail))
	return nil, darwinEIO
}
func (d *v3DataPlane) terminalError() error { d.mu.Lock(); defer d.mu.Unlock(); return d.terminal }
func (d *v3DataPlane) recordTerminal(err error) {
	d.failOnce.Do(func() { d.mu.Lock(); d.terminal = err; d.mu.Unlock(); d.cancel() })
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

func (d *v3DataPlane) keepAlive() {
	interval := v3KeepAliveInterval(d.client.SessionLease(), d.client.VisibilityRepairBudget())
	if interval <= 0 {
		_ = d.fail(errors.New("portablefsd: invalid authority liveness interval"))
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(d.ctx, interval)
			response, err := d.client.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
			cancel()
			if d.ctx.Err() != nil {
				return
			}
			if err != nil || response == nil || response.GetUncertain() || response.GetErrno() != 0 {
				if err == nil {
					err = errors.New("authority keepalive refused")
				}
				_ = d.fail(err)
				return
			}
		}
	}
}

func v3KeepAliveInterval(lease, repairBudget time.Duration) time.Duration {
	if lease <= 0 || repairBudget <= 0 {
		return 0
	}
	return min(lease/3, repairBudget/3)
}
func authorityIdentity(item *authoritypb.Item) ([16]byte, error) {
	var out [16]byte
	if item == nil || len(item.GetToken()) != 16 || len(item.GetStableIdentity()) != len(out) {
		return out, errors.New("authority item omitted its 16-byte capability or stable identity")
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
