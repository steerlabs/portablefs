//go:build linux

package authorityrpc

import (
	"bytes"
	"sort"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type footprintBuilder struct {
	targets []volumeserver.FootprintTarget
}

func (b *footprintBuilder) addItem(identity [16]byte, attributes, data bool) {
	target := volumeserver.FootprintTarget{Identity: identity, Attributes: attributes || data, Data: data}
	b.merge(target)
}

func (b *footprintBuilder) addNamespace(parent [16]byte, name []byte, boundAttributes, boundData bool, bound ...[16]byte) {
	target := volumeserver.FootprintTarget{
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

func (b *footprintBuilder) merge(target volumeserver.FootprintTarget) {
	for index := range b.targets {
		if compareFootprintTarget(b.targets[index], target) != 0 {
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

func (b *footprintBuilder) finish() volumeserver.MutationFootprint {
	sort.Slice(b.targets, func(i, j int) bool { return compareFootprintTarget(b.targets[i], b.targets[j]) < 0 })
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
	return volumeserver.MutationFootprint{Targets: b.targets}
}

func (resolver *operationResolutionContext) deriveMutationFootprint(req *authoritypb.Request) (volumeserver.MutationFootprint, error) {
	var builder footprintBuilder
	addNamespace := func(parentRaw, name []byte, boundAttributes, boundData, resolveBound bool) error {
		parent, err := resolver.item(parentRaw)
		if err != nil {
			return err
		}
		builder.addItem(parent.identity, true, false)
		if !resolveBound {
			builder.addNamespace(parent.identity, name, boundAttributes, boundData)
			return nil
		}
		bound, err := resolver.namespace(parent.cap, name)
		if err != nil {
			return err
		}
		if bound.found {
			builder.addNamespace(parent.identity, name, boundAttributes, boundData, bound.coordinate.identity)
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
				return volumeserver.MutationFootprint{}, err
			}
			identity = resolved.identity
		}
		if len(set.GetHandle()) != 0 {
			resolved, err := resolver.open(set.GetHandle())
			if err != nil {
				return volumeserver.MutationFootprint{}, err
			}
			if identity != ([16]byte{}) && identity != resolved.identity {
				return volumeserver.MutationFootprint{}, syscall.EINVAL
			}
			identity = resolved.identity
		}
		if identity == ([16]byte{}) {
			return volumeserver.MutationFootprint{}, syscall.EINVAL
		}
		builder.addItem(identity, true, set.Size != nil)
	case *authoritypb.Request_Write:
		resolved, err := resolver.open(body.Write.GetHandle())
		if err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		builder.addItem(resolved.identity, true, true)
	case *authoritypb.Request_Fallocate:
		resolved, err := resolver.open(body.Fallocate.GetHandle())
		if err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		builder.addItem(resolved.identity, true, true)
	case *authoritypb.Request_CopyFileRange:
		source, err := resolver.open(body.CopyFileRange.GetInputHandle())
		if err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		destination, err := resolver.open(body.CopyFileRange.GetOutputHandle())
		if err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		builder.addItem(source.identity, true, true)
		builder.addItem(destination.identity, true, true)
	case *authoritypb.Request_Open:
		if body.Open.GetFlags() == nil || !body.Open.GetFlags().GetTruncate() {
			return volumeserver.MutationFootprint{}, syscall.EINVAL
		}
		resolved, err := resolver.item(body.Open.GetItem())
		if err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		builder.addItem(resolved.identity, true, true)
	case *authoritypb.Request_Create:
		truncate := body.Create.GetFlags() != nil && body.Create.GetFlags().GetTruncate()
		if err := addNamespace(body.Create.GetParent(), body.Create.GetName(), true, truncate, !body.Create.GetExclusive()); err != nil {
			return volumeserver.MutationFootprint{}, err
		}
	case *authoritypb.Request_Mkdir:
		if err := addNamespace(body.Mkdir.GetParent(), body.Mkdir.GetName(), true, false, true); err != nil {
			return volumeserver.MutationFootprint{}, err
		}
	case *authoritypb.Request_Unlink:
		if err := addNamespace(body.Unlink.GetParent(), body.Unlink.GetName(), true, false, true); err != nil {
			return volumeserver.MutationFootprint{}, err
		}
	case *authoritypb.Request_Symlink:
		if err := addNamespace(body.Symlink.GetParent(), body.Symlink.GetName(), true, false, true); err != nil {
			return volumeserver.MutationFootprint{}, err
		}
	case *authoritypb.Request_Rename:
		if err := addNamespace(body.Rename.GetOldParent(), body.Rename.GetOldName(), true, false, true); err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		if err := addNamespace(body.Rename.GetNewParent(), body.Rename.GetNewName(), true, false, true); err != nil {
			return volumeserver.MutationFootprint{}, err
		}
	case *authoritypb.Request_Link:
		source, err := resolver.item(body.Link.GetExistingItem())
		if err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		builder.addItem(source.identity, true, false)
		if err := addNamespace(body.Link.GetNewParent(), body.Link.GetNewName(), true, false, true); err != nil {
			return volumeserver.MutationFootprint{}, err
		}
	case *authoritypb.Request_Tmpfile:
		parent, err := resolver.item(body.Tmpfile.GetParent())
		if err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		builder.addItem(parent.identity, true, false)
	case *authoritypb.Request_SetXattr:
		identity, err := resolver.xattrIdentity(body.SetXattr.GetItem(), body.SetXattr.GetHandle())
		if err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		builder.addItem(identity, true, false)
	case *authoritypb.Request_RemoveXattr:
		identity, err := resolver.xattrIdentity(body.RemoveXattr.GetItem(), body.RemoveXattr.GetHandle())
		if err != nil {
			return volumeserver.MutationFootprint{}, err
		}
		builder.addItem(identity, true, false)
	default:
		return volumeserver.MutationFootprint{}, syscall.EINVAL
	}
	return builder.finish(), nil
}

func (r *operationResolutionContext) xattrIdentity(itemRaw, handleRaw []byte) ([16]byte, error) {
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

func mutationFootprintsEqual(declared, expected *volumeserver.MutationFootprint) bool {
	if declared == nil || expected == nil || len(declared.Targets) != len(expected.Targets) {
		return false
	}
	for index := range declared.Targets {
		left, right := declared.Targets[index], expected.Targets[index]
		if left.Identity != right.Identity || left.ParentIdentity != right.ParentIdentity ||
			!bytes.Equal(left.Name, right.Name) || left.Attributes != right.Attributes || left.Data != right.Data ||
			left.BoundAttributes != right.BoundAttributes || left.BoundData != right.BoundData || len(left.BoundIdentities) != len(right.BoundIdentities) {
			return false
		}
		for i := range left.BoundIdentities {
			if left.BoundIdentities[i] != right.BoundIdentities[i] {
				return false
			}
		}
	}
	return true
}

func compareFootprintTarget(left, right volumeserver.FootprintTarget) int {
	leftNamespace, rightNamespace := left.ParentIdentity != ([16]byte{}), right.ParentIdentity != ([16]byte{})
	if leftNamespace != rightNamespace {
		if leftNamespace {
			return 1
		}
		return -1
	}
	if !leftNamespace {
		return bytes.Compare(left.Identity[:], right.Identity[:])
	}
	if c := bytes.Compare(left.ParentIdentity[:], right.ParentIdentity[:]); c != 0 {
		return c
	}
	return bytes.Compare(left.Name, right.Name)
}
