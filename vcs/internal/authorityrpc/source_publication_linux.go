//go:build linux

package authorityrpc

import (
	"bytes"
	"errors"
	"io/fs"
	"sort"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// sourceIdentityResolver resolves each capability at most once while deriving
// the source cut. Derivation intentionally happens before mutation order: the
// coordinator needs current namespace bindings to detect a peer-first cycle,
// and no client-supplied stable identity is trusted for that decision.
type sourceIdentityResolver struct {
	h     *VolumeHandler
	id    volumeserver.SessionID
	items map[string]sourceResolvedIdentity
	opens map[string]sourceResolvedIdentity
}

type sourceResolvedIdentity struct {
	cap      xfsstore.Capability
	identity [16]byte
}

func newSourceIdentityResolver(h *VolumeHandler, id volumeserver.SessionID) *sourceIdentityResolver {
	return &sourceIdentityResolver{
		h: h, id: id,
		items: make(map[string]sourceResolvedIdentity),
		opens: make(map[string]sourceResolvedIdentity),
	}
}

func (r *sourceIdentityResolver) item(raw []byte) (sourceResolvedIdentity, error) {
	if resolved, ok := r.items[string(raw)]; ok {
		return resolved, nil
	}
	capability, err := r.h.item(r.id, raw)
	if err != nil {
		return sourceResolvedIdentity{}, err
	}
	identity, err := r.h.Store.Identity(capability)
	if err != nil {
		return sourceResolvedIdentity{}, err
	}
	if identity == ([16]byte{}) {
		return sourceResolvedIdentity{}, syscall.EIO
	}
	resolved := sourceResolvedIdentity{cap: capability, identity: identity}
	r.items[string(raw)] = resolved
	return resolved, nil
}

func (r *sourceIdentityResolver) open(raw []byte) (sourceResolvedIdentity, error) {
	if resolved, ok := r.opens[string(raw)]; ok {
		return resolved, nil
	}
	capability, err := r.h.open(r.id, raw)
	if err != nil {
		return sourceResolvedIdentity{}, err
	}
	identity, err := r.h.Store.IdentityOpen(capability)
	if err != nil {
		return sourceResolvedIdentity{}, err
	}
	if identity == ([16]byte{}) {
		return sourceResolvedIdentity{}, syscall.EIO
	}
	resolved := sourceResolvedIdentity{cap: capability, identity: identity}
	r.opens[string(raw)] = resolved
	return resolved, nil
}

func (r *sourceIdentityResolver) bound(parent xfsstore.Capability, name []byte) ([16]byte, bool, error) {
	if err := namespaceName(name); err != nil {
		return [16]byte{}, false, err
	}
	item, _, err := r.h.Store.Lookup(parent, string(name))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return [16]byte{}, false, nil
	}
	if err != nil {
		return [16]byte{}, false, err
	}
	identity, identityErr := r.h.Store.Identity(item)
	forgetErr := r.h.Store.Forget(item)
	if identityErr != nil {
		return [16]byte{}, false, identityErr
	}
	if forgetErr != nil {
		return [16]byte{}, false, forgetErr
	}
	if identity == ([16]byte{}) {
		return [16]byte{}, false, syscall.EIO
	}
	return identity, true, nil
}

type sourceGateBuilder struct {
	targets []volumeserver.SourcePublicationTarget
}

func (b *sourceGateBuilder) addItem(identity [16]byte, attributes, data bool) {
	target := volumeserver.SourcePublicationTarget{Identity: identity, Attributes: attributes || data, Data: data}
	b.merge(target)
}

func (b *sourceGateBuilder) addNamespace(parent [16]byte, name []byte, boundAttributes, boundData bool, bound ...[16]byte) {
	target := volumeserver.SourcePublicationTarget{
		ParentIdentity:  parent,
		Name:            append([]byte(nil), name...),
		BoundAttributes: boundAttributes || boundData,
		BoundData:       boundData,
	}
	for _, identity := range bound {
		if identity != ([16]byte{}) {
			target.BoundIdentities = append(target.BoundIdentities, identity)
		}
	}
	b.merge(target)
}

func (b *sourceGateBuilder) merge(target volumeserver.SourcePublicationTarget) {
	for index := range b.targets {
		if compareSourcePublicationTarget(b.targets[index], target) != 0 {
			continue
		}
		existing := &b.targets[index]
		existing.Attributes = existing.Attributes || target.Attributes
		existing.Data = existing.Data || target.Data
		existing.BoundAttributes = existing.BoundAttributes || target.BoundAttributes
		existing.BoundData = existing.BoundData || target.BoundData
		existing.BoundIdentities = append(existing.BoundIdentities, target.BoundIdentities...)
		return
	}
	b.targets = append(b.targets, target)
}

func (b *sourceGateBuilder) finish() volumeserver.SourcePublicationGate {
	sort.Slice(b.targets, func(i, j int) bool { return compareSourcePublicationTarget(b.targets[i], b.targets[j]) < 0 })
	for index := range b.targets {
		target := &b.targets[index]
		sort.Slice(target.BoundIdentities, func(i, j int) bool {
			return bytes.Compare(target.BoundIdentities[i][:], target.BoundIdentities[j][:]) < 0
		})
		write := 0
		for _, identity := range target.BoundIdentities {
			if write != 0 && identity == target.BoundIdentities[write-1] {
				continue
			}
			target.BoundIdentities[write] = identity
			write++
		}
		target.BoundIdentities = target.BoundIdentities[:write]
	}
	return volumeserver.SourcePublicationGate{Targets: b.targets}
}

func (h *VolumeHandler) deriveSourcePublicationGate(req *authoritypb.Request, id volumeserver.SessionID) (volumeserver.SourcePublicationGate, error) {
	resolver := newSourceIdentityResolver(h, id)
	var builder sourceGateBuilder
	addNamespace := func(parentRaw, name []byte, boundAttributes, boundData bool) error {
		parent, err := resolver.item(parentRaw)
		if err != nil {
			return err
		}
		bound, found, err := resolver.bound(parent.cap, name)
		if err != nil {
			return err
		}
		builder.addItem(parent.identity, true, false)
		if found {
			builder.addNamespace(parent.identity, name, boundAttributes, boundData, bound)
		} else {
			builder.addNamespace(parent.identity, name, boundAttributes, boundData)
		}
		return nil
	}

	switch body := req.GetBody().(type) {
	case *authoritypb.Request_SetAttr:
		set := body.SetAttr
		var identity [16]byte
		if len(set.GetItem()) != 0 {
			resolved, err := resolver.item(set.GetItem())
			if err != nil {
				return volumeserver.SourcePublicationGate{}, err
			}
			identity = resolved.identity
		}
		if len(set.GetHandle()) != 0 {
			resolved, err := resolver.open(set.GetHandle())
			if err != nil {
				return volumeserver.SourcePublicationGate{}, err
			}
			if identity != ([16]byte{}) && identity != resolved.identity {
				return volumeserver.SourcePublicationGate{}, syscall.EINVAL
			}
			identity = resolved.identity
		}
		if identity == ([16]byte{}) {
			return volumeserver.SourcePublicationGate{}, syscall.EINVAL
		}
		builder.addItem(identity, true, set.Size != nil)
	case *authoritypb.Request_WriteTransaction:
		if body.WriteTransaction.GetPhase() != authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT {
			return volumeserver.SourcePublicationGate{}, syscall.EINVAL
		}
		gate, _, err := h.writeTransactionGate(id, body.WriteTransaction)
		return gate, err
	case *authoritypb.Request_OneShotWrite:
		resolved, err := resolver.open(body.OneShotWrite.GetHandle())
		if err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		builder.addItem(resolved.identity, true, true)
	case *authoritypb.Request_Fallocate:
		resolved, err := resolver.open(body.Fallocate.GetHandle())
		if err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		builder.addItem(resolved.identity, true, true)
	case *authoritypb.Request_CopyFileRange:
		source, err := resolver.open(body.CopyFileRange.GetInputHandle())
		if err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		destination, err := resolver.open(body.CopyFileRange.GetOutputHandle())
		if err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		builder.addItem(source.identity, true, true)
		builder.addItem(destination.identity, true, true)
	case *authoritypb.Request_Open:
		if body.Open.GetFlags() == nil || !body.Open.GetFlags().GetTruncate() {
			return volumeserver.SourcePublicationGate{}, syscall.EINVAL
		}
		resolved, err := resolver.item(body.Open.GetItem())
		if err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		builder.addItem(resolved.identity, true, true)
	case *authoritypb.Request_Create:
		truncate := body.Create.GetFlags() != nil && body.Create.GetFlags().GetTruncate()
		if err := addNamespace(body.Create.GetParent(), body.Create.GetName(), true, truncate); err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
	case *authoritypb.Request_Mkdir:
		if err := addNamespace(body.Mkdir.GetParent(), body.Mkdir.GetName(), true, false); err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
	case *authoritypb.Request_Unlink:
		if err := addNamespace(body.Unlink.GetParent(), body.Unlink.GetName(), true, false); err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
	case *authoritypb.Request_Symlink:
		if err := addNamespace(body.Symlink.GetParent(), body.Symlink.GetName(), true, false); err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
	case *authoritypb.Request_Rename:
		if err := addNamespace(body.Rename.GetOldParent(), body.Rename.GetOldName(), true, false); err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		if err := addNamespace(body.Rename.GetNewParent(), body.Rename.GetNewName(), true, false); err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
	case *authoritypb.Request_Link:
		source, err := resolver.item(body.Link.GetExistingItem())
		if err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		builder.addItem(source.identity, true, false)
		if err := addNamespace(body.Link.GetNewParent(), body.Link.GetNewName(), true, false); err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
	case *authoritypb.Request_SetXattr:
		identity, err := resolver.xattrIdentity(body.SetXattr.GetItem(), body.SetXattr.GetHandle())
		if err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		builder.addItem(identity, true, false)
	case *authoritypb.Request_RemoveXattr:
		identity, err := resolver.xattrIdentity(body.RemoveXattr.GetItem(), body.RemoveXattr.GetHandle())
		if err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		builder.addItem(identity, true, false)
	default:
		return volumeserver.SourcePublicationGate{}, syscall.EINVAL
	}
	return builder.finish(), nil
}

func (r *sourceIdentityResolver) xattrIdentity(itemRaw, handleRaw []byte) ([16]byte, error) {
	if len(itemRaw) == 0 {
		// The storage mutation APIs are item-relative. A handle may corroborate
		// the item but cannot silently select a different object.
		return [16]byte{}, syscall.EINVAL
	}
	item, err := r.item(itemRaw)
	if err != nil {
		return [16]byte{}, err
	}
	if len(handleRaw) != 0 {
		handle, err := r.open(handleRaw)
		if err != nil {
			return [16]byte{}, err
		}
		if handle.identity != item.identity {
			return [16]byte{}, syscall.EINVAL
		}
	}
	return item.identity, nil
}

func sourcePublicationGatesEqual(declared, expected *volumeserver.SourcePublicationGate) bool {
	if declared == nil || expected == nil || len(declared.Targets) != len(expected.Targets) {
		return false
	}
	for index := range declared.Targets {
		left, right := declared.Targets[index], expected.Targets[index]
		if left.Identity != right.Identity || left.ParentIdentity != right.ParentIdentity ||
			!bytes.Equal(left.Name, right.Name) || left.Attributes != right.Attributes || left.Data != right.Data ||
			left.BoundAttributes != right.BoundAttributes || left.BoundData != right.BoundData {
			return false
		}
	}
	return true
}

func sourcePublicationGateHasNamespace(gate volumeserver.SourcePublicationGate) bool {
	for _, target := range gate.Targets {
		if target.ParentIdentity != ([16]byte{}) {
			return true
		}
	}
	return false
}

// sourcePublicationResolutions extracts only identities the successful
// ordinary response can newly publish. It runs while mutation order is still
// held, so a following peer mutation cannot choose its audience before this
// monotone index update. Exact replays do not re-run it: the first execution
// installed the identity even if its DATA response was lost.
func sourcePublicationResolutions(req *authoritypb.Request, resp *authoritypb.Response) ([]volumeserver.VisibilityResolution, error) {
	if resp == nil {
		return nil, syscall.EIO
	}
	if resp.GetErrno() != 0 {
		return nil, nil
	}
	var item *authoritypb.Item
	switch req.GetBody().(type) {
	case *authoritypb.Request_Create:
		item = resp.GetCreate().GetItem()
	case *authoritypb.Request_Mkdir, *authoritypb.Request_Symlink:
		item = resp.GetLookup().GetItem()
	case *authoritypb.Request_Link:
		item = resp.GetLink().GetItem()
	case *authoritypb.Request_Rename:
		rename := resp.GetRename()
		if rename == nil || len(rename.GetNewPostIdentity()) != 16 {
			return nil, syscall.EIO
		}
		var moved [16]byte
		copy(moved[:], rename.GetNewPostIdentity())
		if moved == ([16]byte{}) {
			return nil, syscall.EIO
		}
		resolutions := []volumeserver.VisibilityResolution{{Identity: moved}}
		if req.GetRename().GetExchange() {
			if len(rename.GetOldPostIdentity()) != 16 {
				return nil, syscall.EIO
			}
			var exchanged [16]byte
			copy(exchanged[:], rename.GetOldPostIdentity())
			if exchanged == ([16]byte{}) {
				return nil, syscall.EIO
			}
			if exchanged != moved {
				resolutions = append(resolutions, volumeserver.VisibilityResolution{Identity: exchanged})
			}
		} else if len(rename.GetOldPostIdentity()) != 0 {
			// A normal rename leaves old bound only for the POSIX same-inode
			// hard-link no-op (including the identical-name case).
			if len(rename.GetOldPostIdentity()) != 16 || !bytes.Equal(rename.GetOldPostIdentity(), rename.GetNewPostIdentity()) {
				return nil, syscall.EIO
			}
		}
		return resolutions, nil
	default:
		return nil, nil
	}
	if item == nil || len(item.GetStableIdentity()) != 16 {
		return nil, syscall.EIO
	}
	var identity [16]byte
	copy(identity[:], item.GetStableIdentity())
	if identity == ([16]byte{}) {
		return nil, syscall.EIO
	}
	return []volumeserver.VisibilityResolution{{Identity: identity}}, nil
}
