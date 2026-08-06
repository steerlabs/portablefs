package portablefsd

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"google.golang.org/protobuf/proto"
)

const (
	v3RootItemID      = uint64(1)
	v3FirstItemID     = uint64(2)
	v3RepairItemFloor = ^uint64(0) - 4096
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
	SessionLease() time.Duration
	DataPlaneOperationLimit() int
	CallRead(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallMutationWithIdentity(context.Context, *authoritypb.Request, authorityrpc.MutationAssigned) (*authoritypb.Response, error)
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
}

type v3HandleRecord struct {
	mu     sync.RWMutex
	id     uint64
	token  []byte
	itemID uint64
	append bool
}

type v3CookieRecord struct {
	dirID    uint64
	cookie   []byte
	verifier []byte
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

	mu              sync.Mutex
	terminal        error
	itemsByID       map[uint64]*v3ItemRecord
	itemsByIdentity map[[16]byte]*v3ItemRecord
	nextItemID      uint64
	handles         map[uint64]*v3HandleRecord
	nextHandleID    uint64
	cookies         map[uint64]v3CookieRecord
	nextCookieID    uint64
	nameMax         uint32
	maxRead         uint32
	maxWrite        uint32

	failOnce sync.Once
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
	if maxRead == 0 || maxWrite == 0 {
		return nil, errors.New("portablefsd: v3 authority omitted I/O limits")
	}
	ctx, cancel := context.WithCancel(parent)
	d := &v3DataPlane{
		client: cfg.Client, cfg: cfg, ctx: ctx, cancel: cancel,
		ops: make(chan struct{}, limit), itemsByID: make(map[uint64]*v3ItemRecord),
		itemsByIdentity: make(map[[16]byte]*v3ItemRecord), nextItemID: v3FirstItemID,
		handles: make(map[uint64]*v3HandleRecord), nextHandleID: 1,
		cookies: make(map[uint64]v3CookieRecord), nextCookieID: v3CookieFloor,
		nameMax: 255, maxRead: maxRead, maxWrite: maxWrite,
	}
	bridge, err := newV3CoherenceBridge(cfg.Client, cfg.CachePolicy, d.recordTerminal)
	if err != nil {
		cancel()
		_ = cfg.Client.Close()
		return nil, err
	}
	d.bridge = bridge
	root, err := d.installRoot(cfg.Client.Root())
	if err != nil {
		_ = d.fail(err)
		return nil, err
	}
	if root.attr.GetKind() != authoritypb.Attr_DIRECTORY {
		err := errors.New("portablefsd: authority root is not a directory")
		_ = d.fail(err)
		return nil, err
	}
	// StatFS is a read-only attach preflight. It gives the frontend the actual
	// name bound before any operation can be admitted.
	response, callErr := cfg.Client.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}}})
	if callErr != nil || response == nil || response.GetUncertain() || response.GetErrno() != 0 || response.GetStatFs() == nil {
		err := fmt.Errorf("portablefsd: v3 statfs preflight failed: response=%v error=%w", response, callErr)
		_ = d.fail(err)
		return nil, err
	}
	if response.GetStatFs().GetNameMax() == 0 {
		err := errors.New("portablefsd: authority statfs omitted NAME_MAX")
		_ = d.fail(err)
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
			FlagsSupported: false, FlagsUnderstood: true,
		},
		V3Coherence: d.bridge.resolveContract(),
	}
}

func (d *v3DataPlane) dispatch(ctx context.Context, operationID uint64, body any) (any, int32) {
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
		return d.lookup(ctx, request)
	case *pfslocal.EnumerateRequest:
		return d.enumerate(ctx, operationID, request)
	case *pfslocal.GetAttrRequest:
		return d.getattr(ctx, request)
	case *pfslocal.SetAttrRequest:
		return d.setattr(ctx, operationID, request)
	case *pfslocal.OpenRequest:
		return d.open(ctx, operationID, request)
	case *pfslocal.CloseRequest:
		return d.closeHandle(ctx, operationID, request)
	case *pfslocal.ReadRequest:
		return d.read(ctx, request)
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
		return d.readlink(ctx, request)
	case *pfslocal.HardLinkRequest:
		return d.hardlink(ctx, operationID, request)
	case *pfslocal.XattrGetRequest:
		return d.xattrGet(ctx, request)
	case *pfslocal.XattrSetRequest:
		return d.xattrSet(ctx, operationID, request)
	case *pfslocal.XattrListRequest:
		return d.xattrList(ctx, request)
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
	response, err := d.client.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if err != nil || response == nil || response.GetUncertain() || response.GetErrno() != 0 ||
		response.GetRoutesMismatch().GetSessionRefused() {
		if err == nil {
			err = errors.New("portablefsd: authority liveness proof was refused")
		}
		_ = d.fail(err)
		return nil, darwinEIO
	}
	return &pfslocal.V3LivenessReply{
		AuthorityEpoch: cloneBytesV3(epoch),
		SessionID:      cloneBytesV3(session),
	}, 0
}

func (d *v3DataPlane) lookup(ctx context.Context, request *pfslocal.LookupRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 || !visibilitywire.ValidName(request.Name) {
		if errno == 0 {
			errno = darwinEINVAL
		}
		return nil, errno
	}
	response, errno := d.callRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name)}}})
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
	attr, err := d.localAttr(record, response.GetLookup().GetItem().GetAttr(), &parent.item)
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.LookupReply{Attr: attr}, 0
}

func (d *v3DataPlane) getattr(ctx context.Context, request *pfslocal.GetAttrRequest) (any, int32) {
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
	response, errno := d.callRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: query}})
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
		return d.getattr(ctx, &pfslocal.GetAttrRequest{Item: request.Item, Handle: request.Handle})
	}
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: set}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetPostAttr() == nil {
		return d.malformed("setattr omitted committed post-attr")
	}
	attr, err := d.localAttr(item, response.GetPostAttr(), item.parent)
	if err != nil {
		return d.malformed(err.Error())
	}
	d.updateAttr(item, response.GetPostAttr())
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
	response, errno := d.callNonVisibleMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytesV3(item.token), Flags: flags}}})
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
	response, errno := d.callNonVisibleMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytesV3(handle.token)}}})
	if errno != 0 {
		return nil, errno
	}
	_ = response
	d.mu.Lock()
	if d.handles[request.Handle] == handle {
		delete(d.handles, request.Handle)
	}
	d.mu.Unlock()
	return &pfslocal.CloseReply{Retired: true}, 0
}

func (d *v3DataPlane) read(ctx context.Context, request *pfslocal.ReadRequest) (any, int32) {
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
		response, errno := d.callRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: cloneBytesV3(handle.token), Offset: offset, Length: chunk}}})
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
	if uint32(len(request.Data)) > d.maxWrite || (request.Append && request.Offset != 0) {
		return nil, darwinEINVAL
	}
	handle, errno := d.handle(request.Handle, 0)
	if errno != 0 {
		return nil, errno
	}
	handle.mu.RLock()
	defer handle.mu.RUnlock()
	appendWrite := handle.append || request.Append
	offset := request.Offset
	if appendWrite {
		offset = 0
	}
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: cloneBytesV3(handle.token), Offset: offset, Data: cloneBytesV3(request.Data), Append: appendWrite}}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetWrite() == nil || response.GetWrite().GetCount() > uint32(len(request.Data)) || response.GetPostAttr() == nil {
		return d.malformed("write omitted its exact count or committed post-attr")
	}
	d.mu.Lock()
	item := d.itemsByID[handle.itemID]
	d.mu.Unlock()
	if item == nil {
		return d.malformed("write handle lost its item")
	}
	attr, err := d.localAttr(item, response.GetPostAttr(), item.parent)
	if err != nil {
		return d.malformed(err.Error())
	}
	d.updateAttr(item, response.GetPostAttr())
	return &pfslocal.WriteReply{Written: response.GetWrite().GetCount(), Attr: attr}, 0
}

func (d *v3DataPlane) fsync(ctx context.Context, request *pfslocal.FsyncRequest) (any, int32) {
	handle, errno := d.handle(request.Handle, 0)
	if errno != 0 {
		return nil, errno
	}
	handle.mu.RLock()
	defer handle.mu.RUnlock()
	response, errno := d.callRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: cloneBytesV3(handle.token)}}})
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
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
		Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Mode: request.Mode,
		Flags: &authoritypb.OpenFlags{Read: true, Write: true, Append: request.Append}, Exclusive: request.Exclusive,
	}}})
	if errno != 0 {
		return nil, errno
	}
	created := response.GetCreate()
	if created == nil || created.GetItem() == nil || len(created.GetHandle()) != 16 {
		return d.malformed("create omitted item or handle")
	}
	record, errno := d.intern(ctx, created.GetItem(), &parent.item)
	if errno != 0 {
		return nil, errno
	}
	handle, err := d.installHandle(created.GetHandle(), record.item.ItemID, request.Append)
	if err != nil {
		return d.malformed(err.Error())
	}
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
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Mode: request.Mode}}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetLookup() == nil {
		return d.malformed("mkdir omitted item")
	}
	record, errno := d.intern(ctx, response.GetLookup().GetItem(), &parent.item)
	if errno != 0 {
		return nil, errno
	}
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
	_, errno = d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Directory: request.Directory}}})
	if errno != 0 {
		return nil, errno
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
	_, errno = d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
		OldParent: cloneBytesV3(from.token), OldName: cloneBytesV3(request.FromName), NewParent: cloneBytesV3(to.token), NewName: cloneBytesV3(request.ToName), NoReplace: request.NoReplace,
	}}})
	if errno != 0 {
		return nil, errno
	}
	return &pfslocal.RenameReply{}, 0
}

func (d *v3DataPlane) symlink(ctx context.Context, operationID uint64, request *pfslocal.SymlinkRequest) (any, int32) {
	parent, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if !visibilitywire.ValidName(request.Name) || bytes.IndexByte(request.Target, 0) >= 0 {
		return nil, darwinEINVAL
	}
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{Parent: cloneBytesV3(parent.token), Name: cloneBytesV3(request.Name), Target: cloneBytesV3(request.Target)}}})
	if errno != 0 {
		return nil, errno
	}
	if response.GetLookup() == nil {
		return d.malformed("symlink omitted item")
	}
	record, errno := d.intern(ctx, response.GetLookup().GetItem(), &parent.item)
	if errno != 0 {
		return nil, errno
	}
	attr, err := d.localAttr(record, response.GetLookup().GetItem().GetAttr(), &parent.item)
	if err != nil {
		return d.malformed(err.Error())
	}
	return &pfslocal.SymlinkReply{Attr: attr}, 0
}

func (d *v3DataPlane) readlink(ctx context.Context, request *pfslocal.ReadlinkRequest) (any, int32) {
	item, errno := d.item(request.Item)
	if errno != 0 {
		return nil, errno
	}
	response, errno := d.callRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_Readlink{Readlink: &authoritypb.ReadlinkRequest{Item: cloneBytesV3(item.token)}}})
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
	response, errno := d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{ExistingItem: cloneBytesV3(item.token), NewParent: cloneBytesV3(parent.token), NewName: cloneBytesV3(request.Name)}}})
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

func (d *v3DataPlane) xattrGet(ctx context.Context, request *pfslocal.XattrGetRequest) (any, int32) {
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
	response, errno := d.callRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetXattr{GetXattr: query}})
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
	_, errno = d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_SetXattr{SetXattr: query}})
	if errno != 0 {
		return nil, errno
	}
	return &pfslocal.XattrSetReply{}, 0
}

func (d *v3DataPlane) xattrList(ctx context.Context, request *pfslocal.XattrListRequest) (any, int32) {
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
	response, errno := d.callRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_ListXattr{ListXattr: query}})
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
	_, errno = d.callMutation(ctx, operationID, &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: query}})
	if errno != 0 {
		return nil, errno
	}
	return &pfslocal.XattrRemoveReply{}, 0
}

func (d *v3DataPlane) statfs(ctx context.Context) (any, int32) {
	response, errno := d.callRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}}})
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
	response, errno := d.callNonVisibleMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_SyncFs{SyncFs: &authoritypb.SyncFSRequest{}}})
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
	response, errno := d.callNonVisibleMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: cloneBytesV3(record.token)}}})
	if errno != 0 {
		return nil, errno
	}
	_ = response
	d.mu.Lock()
	if d.itemsByID[record.item.ItemID] == record {
		delete(d.itemsByID, record.item.ItemID)
		delete(d.itemsByIdentity, record.item.StableIdentity)
		for cookie, position := range d.cookies {
			if position.dirID == record.item.ItemID {
				delete(d.cookies, cookie)
			}
		}
	}
	d.mu.Unlock()
	return &pfslocal.ReclaimReply{}, 0
}

func (d *v3DataPlane) enumerate(ctx context.Context, _ uint64, request *pfslocal.EnumerateRequest) (result any, errno int32) {
	dir, errno := d.item(request.Dir)
	if errno != 0 {
		return nil, errno
	}
	if request.MaxEntries == 0 || request.MaxEntries > 4096 {
		return nil, darwinEINVAL
	}
	var position v3CookieRecord
	if request.Cookie != 0 {
		var ok bool
		position, ok = d.consumeCookie(dir.item.ItemID, request.Cookie)
		if !ok {
			return nil, darwinESTALE
		}
	}
	openResponse, errno := d.callNonVisibleMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytesV3(dir.token), Flags: &authoritypb.OpenFlags{Read: true}}}})
	if errno != 0 {
		return nil, errno
	}
	if openResponse.GetOpen() == nil || len(openResponse.GetOpen().GetHandle()) != 16 {
		return d.malformed("enumeration open omitted handle")
	}
	authorityHandle := cloneBytesV3(openResponse.GetOpen().GetHandle())
	defer func() {
		cleanupBound := v3KeepAliveInterval(d.client.SessionLease(), d.client.VisibilityRepairBudget())
		cleanupCtx, cancel := context.WithTimeout(d.ctx, cleanupBound)
		defer cancel()
		closeResponse, closeErrno := d.callNonVisibleMutation(cleanupCtx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: authorityHandle}}})
		_ = closeResponse
		if closeErrno != 0 {
			_ = d.fail(errors.New("portablefsd: hidden enumeration handle could not be closed"))
			result, errno = nil, darwinEIO
		}
	}()
	response, errno := d.callNonVisibleMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{
		Handle: authorityHandle, Cookie: cloneBytesV3(position.cookie), Verifier: cloneBytesV3(position.verifier), MaxEntries: request.MaxEntries, WantItems: true,
	}}})
	if errno != 0 {
		return nil, errno
	}
	page := response.GetReadDir()
	if page == nil || len(page.GetVerifier()) != 16 || len(page.GetEntries()) == 0 && !page.GetEof() {
		return d.malformed("readdir-plus returned a malformed page")
	}
	reply := &pfslocal.EnumerateReply{DirVersion: v3VerifierVersion(page.GetVerifier())}
	for _, entry := range page.GetEntries() {
		if entry == nil || !visibilitywire.ValidName(entry.GetName()) || len(entry.GetNextCookie()) == 0 || entry.GetAttr() == nil {
			return d.malformed("readdir-plus omitted name, cookie, or attributes")
		}
		if entry.GetItem() == nil {
			// An opaque entry: the authority lists a name whose inode it never
			// exposes (a device node, FIFO, socket, or foreign-owned inode
			// another writer placed in the tree) and issues no capability for
			// it. There is no item to publish to FSKit, but enumeration must
			// still advance past the name, so its cookie is recorded without a
			// directory entry — the same shape as a local readdir listing a
			// name whose stat then fails.
			cookie, err := d.issueCookie(v3CookieRecord{dirID: dir.item.ItemID, cookie: cloneBytesV3(entry.GetNextCookie()), verifier: cloneBytesV3(page.GetVerifier())})
			if err != nil {
				return nil, darwinEOVERFLOW
			}
			reply.NextCookie = cookie
			continue
		}
		if entry.GetItem().GetAttr() == nil || entry.GetAttr().GetInode() != entry.GetItem().GetAttr().GetInode() || entry.GetAttr().GetKind() != entry.GetItem().GetAttr().GetKind() {
			return d.malformed("readdir-plus item and dirent attr disagree")
		}
		record, localErrno := d.intern(ctx, entry.GetItem(), &dir.item)
		if localErrno != 0 {
			return nil, localErrno
		}
		attr, err := d.localAttr(record, entry.GetItem().GetAttr(), &dir.item)
		if err != nil {
			return d.malformed(err.Error())
		}
		cookie, err := d.issueCookie(v3CookieRecord{dirID: dir.item.ItemID, cookie: cloneBytesV3(entry.GetNextCookie()), verifier: cloneBytesV3(page.GetVerifier())})
		if err != nil {
			return nil, darwinEOVERFLOW
		}
		reply.Entries = append(reply.Entries, pfslocal.DirEntry{Name: cloneBytesV3(entry.GetName()), Attr: attr, Cookie: cookie})
		reply.NextCookie = cookie
	}
	if page.GetEof() {
		reply.NextCookie = 0
	}
	return reply, 0
}

func (d *v3DataPlane) callRead(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, int32) {
	response, err := d.client.CallRead(ctx, request)
	return d.classify(response, err, false)
}

func (d *v3DataPlane) callMutation(ctx context.Context, operationID uint64, request *authoritypb.Request) (*authoritypb.Response, int32) {
	if operationID == 0 {
		return nil, darwinEINVAL
	}
	var assigned authorityrpc.MutationIdentity
	response, callErr := d.client.CallMutationWithIdentity(ctx, request, func(identity authorityrpc.MutationIdentity) error {
		assigned = identity
		return d.bridge.registerMutation(identity.Slot, identity.Sequence, operationID)
	})
	if assigned.Sequence != 0 {
		if err := d.bridge.completeMutation(assigned, operationID, response, callErr); err != nil {
			return nil, darwinEIO
		}
	}
	return d.classify(response, callErr, true)
}

// callNonVisibleMutation keeps authority replay identity without inventing a
// pfslocal publication identity. Open-without-truncate, Close, and ReadDir do
// not publish namespace/data/attribute state; if the authority ever emits a
// source PREPARE for one, the bridge has no ticket and terminates the mount.
func (d *v3DataPlane) callNonVisibleMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, int32) {
	var assigned authorityrpc.MutationIdentity
	response, callErr := d.client.CallMutationWithIdentity(ctx, request, func(identity authorityrpc.MutationIdentity) error {
		assigned = identity
		return nil
	})
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
	if response.GetErrno() != 0 {
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
		existing.attr = parsed.attr
		if parent != nil {
			copyParent := *parent
			existing.parent = &copyParent
		}
		retained := bytes.Equal(existing.token, parsed.token)
		d.mu.Unlock()
		if !retained {
			_, errno := d.callNonVisibleMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: parsed.token}}})
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

func (d *v3DataPlane) issueCookie(position v3CookieRecord) (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nextCookieID == math.MaxUint64 {
		return 0, errors.New("directory cookie table exhausted")
	}
	if len(d.cookies) >= v3MaxCookies {
		oldest := uint64(math.MaxUint64)
		for cookie := range d.cookies {
			if cookie < oldest {
				oldest = cookie
			}
		}
		delete(d.cookies, oldest)
	}
	cookie := d.nextCookieID
	d.nextCookieID++
	d.cookies[cookie] = position
	return cookie, nil
}

// consumeCookie translates one opaque local directory position and retires
// every older position for the same directory/verifier stream. This keeps a
// sequential walk bounded while making delayed seeks fail closed with ESTALE
// instead of accidentally resuming at a position from another directory or
// directory incarnation.
func (d *v3DataPlane) consumeCookie(dirID, cookie uint64) (v3CookieRecord, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	position, ok := d.cookies[cookie]
	if !ok || position.dirID != dirID || len(position.cookie) == 0 || len(position.verifier) != 16 {
		return v3CookieRecord{}, false
	}
	for candidateCookie, candidate := range d.cookies {
		if candidate.dirID == position.dirID &&
			bytes.Equal(candidate.verifier, position.verifier) &&
			candidateCookie <= cookie {
			delete(d.cookies, candidateCookie)
		}
	}
	return position, true
}

func (d *v3DataPlane) updateAttr(record *v3ItemRecord, attr *authoritypb.Attr) {
	d.mu.Lock()
	if d.itemsByID[record.item.ItemID] == record {
		record.attr = cloneAuthorityAttr(attr)
	}
	d.mu.Unlock()
}

func (d *v3DataPlane) malformed(detail string) (any, int32) {
	_ = d.fail(errors.New("portablefsd: " + detail))
	return nil, darwinEIO
}
func (d *v3DataPlane) terminalError() error { d.mu.Lock(); defer d.mu.Unlock(); return d.terminal }
func (d *v3DataPlane) recordTerminal(err error) {
	d.failOnce.Do(func() { d.mu.Lock(); d.terminal = err; d.mu.Unlock(); d.cancel() })
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
