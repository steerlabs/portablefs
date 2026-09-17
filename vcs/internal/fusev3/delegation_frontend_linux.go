//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"google.golang.org/protobuf/proto"
)

func bufferErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return syscall.EIO
}

func captureServedVersion(ctx context.Context, response *authoritypb.Response) {
	if response == nil {
		return
	}
	if p := replyPublicationFromContext(ctx); p != nil {
		version := response.GetVolumeVersion()
		if version != 0 && (p.servedVersion == 0 || version < p.servedVersion) {
			p.servedVersion = version
		}
	}
}

func (n *node) registerDelegatedHandle(handle *fileHandle, grant *authoritypb.Delegation) error {
	manager := n.mount.delegations
	if grant != nil {
		if err := manager.Install(n.item.GetStableIdentity(), n.item.GetToken(), handle.token, grant); err != nil && !errors.Is(err, errDelegationRetired) {
			return err
		}
	} else {
		if err := manager.AddHandle(n.item.GetStableIdentity(), n.item.GetToken(), handle.token, handle.openFlags&syscall.O_ACCMODE != syscall.O_RDONLY); err != nil && !errors.Is(err, errDelegationRetired) {
			return err
		}
	}
	handle.lossObserved = manager.IdentityLoss(n.item.GetStableIdentity())
	return nil
}

type acquiredDelegationHandleKey struct{}
type acquiredDelegationHandle struct{ token []byte }

// A recalled open description remains usable. A subsequent mutation obtains a
// fresh grant, but the old grant is never used to admit another buffer entry.
func (n *node) ensureWriteDelegation(ctx context.Context, handle *fileHandle) error {
	if n.stale.Load() || (handle != nil && handle.stale.Load()) {
		return syscall.EIO
	}
	id, err := delegationIdentity(n.item.GetStableIdentity())
	if err != nil {
		return err
	}
	state := n.mount.delegations.state(id)
	if err := state.lockAfterRelease(ctx, delegationAcquire); err != nil {
		return err
	}
	defer state.acquire.Unlock()
	if n.mount.delegations.Owns(n.item.GetStableIdentity()) {
		return nil
	}
	for {
		response, errno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytes(n.item.GetToken()), Flags: &authoritypb.OpenFlags{Write: true}, WriteIntent: true}}})
		if errno != 0 {
			return errno
		}
		opened := response.GetOpen()
		if opened == nil || opened.GetDelegation() == nil || len(opened.GetHandle()) == 0 {
			return syscall.EIO
		}
		token := opened.GetHandle()
		if handle != nil {
			token = handle.token
		}
		if err := n.mount.delegations.Install(n.item.GetStableIdentity(), n.item.GetToken(), token, opened.GetDelegation()); err != nil {
			_, closeErrno := n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytes(opened.GetHandle())}}})
			if closeErrno != 0 {
				return closeErrno
			}
			if errors.Is(err, errDelegationRetired) {
				continue
			}
			return err
		}
		if handle == nil {
			if acquired, _ := ctx.Value(acquiredDelegationHandleKey{}).(*acquiredDelegationHandle); acquired != nil {
				acquired.token = cloneBytes(token)
			}
		}
		if handle != nil {
			_, errno = n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: cloneBytes(opened.GetHandle())}}})
			if errno != 0 {
				return errno
			}
		}
		return nil
	}
}

func (n *node) withWriteDelegation(ctx context.Context, handle *fileHandle, call func(*authoritypb.DelegationRef) (*authoritypb.Response, error)) (*authoritypb.Response, error) {
	for {
		if err := n.ensureWriteDelegation(ctx, handle); err != nil {
			return nil, err
		}
		response, err := n.mount.delegations.Synchronous(ctx, n.item.GetStableIdentity(), call)
		if !errors.Is(err, errDelegationNotOwned) {
			return response, err
		}
	}
}

func (m *Mount) overlayProtoAttr(identity []byte, base *authoritypb.Attr, version uint64) (*authoritypb.Attr, error) {
	if base == nil {
		return nil, syscall.EIO
	}
	manager := m.delegations
	id, err := delegationIdentity(identity)
	if err != nil {
		return nil, err
	}
	manager.epoch.RLock()
	defer manager.epoch.RUnlock()
	state := manager.lookupState(id)
	if manager.incarnation() == 0 || state == nil {
		return proto.Clone(base).(*authoritypb.Attr), nil
	}
	state.admission.RLock()
	defer state.admission.RUnlock()
	if state.ref == nil {
		return proto.Clone(base).(*authoritypb.Attr), nil
	}
	// The base and retained overlay are one read snapshot. A flush updates the
	// base before durability can retire its records; holding meta across overlay
	// sampling prevents an old base from being paired with an empty overlay.
	state.meta.Lock()
	defer state.meta.Unlock()
	state.installBaseLocked(base, version)
	if state.base != nil && state.baseVersion >= version {
		base = state.base
	}
	attrs := manager.buf.OverlayAttributes(id, writeback.Attributes{
		Mode: base.GetMode(), Size: base.GetSize(), ATimeNS: base.GetAtimeNs(), MTimeNS: base.GetMtimeNs(), CTimeNS: base.GetCtimeNs(),
		HasMode: true, HasSize: true, HasATime: true, HasMTime: true, HasCTime: true,
	})
	attr := proto.Clone(base).(*authoritypb.Attr)
	if attrs.HasMode {
		attr.Mode = attrs.Mode
	}
	if attrs.HasSize {
		attr.Size = attrs.Size
	}
	if attrs.HasATime {
		attr.AtimeNs = attrs.ATimeNS
	}
	if attrs.HasMTime {
		attr.MtimeNs = attrs.MTimeNS
	}
	if attrs.HasCTime {
		attr.CtimeNs = attrs.CTimeNS
	}
	return attr, nil
}

func (n *node) overlayAttr(base *authoritypb.Attr, out *fuse.AttrOut) syscall.Errno {
	attr, err := n.mount.overlayProtoAttr(n.item.GetStableIdentity(), base, 0)
	if err != nil {
		return bufferErrno(err)
	}
	fillAttr(attr, &out.Attr, n.mount.uid, n.mount.gid)
	out.SetTimeout(0)
	return 0
}

func (n *node) invalidateOwnData(ctx context.Context, offset, length int64) error {
	r := n.mount.raw
	if r == nil {
		return nil
	}
	identity, ok := publicationIdentityFromItem(n.item)
	if !ok {
		return syscall.EIO
	}
	coordinate := publicationCoordinate{kind: publicationItemData, item: identity}
	lease, err := r.closeCacheCoordinate(ctx, coordinate)
	if err != nil {
		return err
	}
	defer lease.Open()
	var byteRange *authoritypb.ByteRange
	if offset >= 0 && length > 0 {
		byteRange = &authoritypb.ByteRange{Offset: uint64(offset), Length: uint64(length)}
	}
	budget := n.mount.subscription.config.repairLead
	if budget <= 0 {
		budget = time.Second
	}
	repairCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	deadline := n.mount.subscription.config.clock.Now().Add(budget)
	if err := n.mount.subscription.retry(repairCtx, deadline, func() error {
		return r.invalidateCacheCoordinateContext(repairCtx, coordinate, byteRange)
	}); err != nil {
		r.markIdentityStale(identity)
		return err
	}
	return nil
}

// F4 uses the same exact namespace cut as source publication. A cold name is
// resolved before flushing; it must never make a dirty inode invisible to the
// dependency check simply because its daemon name payload was evicted.
func (m *Mount) flushNamespaceDependencies(ctx context.Context, request *authoritypb.Request, lease *sourcePublicationLease) error {
	type named struct {
		parent   []byte
		name     []byte
		identity publicationIdentity
	}
	var names []named
	switch body := request.GetBody().(type) {
	case *authoritypb.Request_Unlink:
		names = append(names, named{body.Unlink.Parent, body.Unlink.Name, publicationIdentity{}})
	case *authoritypb.Request_Rename:
		names = append(names, named{body.Rename.OldParent, body.Rename.OldName, publicationIdentity{}}, named{body.Rename.NewParent, body.Rename.NewName, publicationIdentity{}})
	case *authoritypb.Request_Link:
		for coordinate := range lease.coordinates {
			if coordinate.kind == publicationItemAttributes {
				if _, err := m.delegations.FlushIdentity(ctx, coordinate.item[:]); err != nil {
					return err
				}
			}
		}
		return nil
	default:
		return nil
	}
	allKnown := len(lease.preBindings) == len(lease.names)
	if allKnown {
		for _, identity := range lease.preBindings {
			if _, err := m.delegations.FlushIdentity(ctx, identity[:]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, name := range names {
		m.raw.mu.Lock()
		for namespace := range lease.names {
			if namespace.name != string(name.name) {
				continue
			}
			parent := m.raw.byIdentityLocked(namespace.parent)
			if parent != nil && bytes.Equal(parent.node.item.GetToken(), name.parent) {
				name.identity = lease.preBindings[namespace]
				break
			}
		}
		m.raw.mu.Unlock()
		if name.identity != (publicationIdentity{}) {
			if _, err := m.delegations.FlushIdentity(ctx, name.identity[:]); err != nil {
				return err
			}
			continue
		}
		response, err := m.rpc.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: cloneBytes(name.parent), Name: cloneBytes(name.name)}}})
		if err != nil {
			return err
		}
		errno := responseErrno(response)
		if errno == syscall.ENOENT {
			continue
		}
		if errno != 0 {
			return errno
		}
		item := response.GetLookup().GetItem()
		if item == nil {
			continue
		}
		_, flushErr := m.delegations.FlushIdentity(ctx, item.GetStableIdentity())
		m.deferReclaim(item.GetToken())
		if flushErr != nil {
			return flushErr
		}
	}
	return nil
}
