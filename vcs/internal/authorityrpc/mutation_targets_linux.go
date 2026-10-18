//go:build linux

package authorityrpc

import (
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/pathcomponent"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

const maxResolutionAttempts = 8

func namespaceName(name []byte) error {
	return xfsstore.ValidateComponent(string(name))
}
func mutationObjectPostState(object *authoritypb.ObjectPostState) *volumeserver.MutationObjectPostState {
	if object == nil || len(object.GetStableIdentity()) != 16 || object.GetAttr() == nil {
		return nil
	}
	attr := object.GetAttr()
	state := &volumeserver.MutationObjectPostState{
		ObjectVersion: object.GetObjectVersion(), Roles: object.GetRoles(),
		Attr: volumeserver.MutationAttr{
			Kind: uint32(attr.GetKind()), Inode: attr.GetInode(), Size: attr.GetSize(),
			Blocks: attr.GetBlocks(), Mode: attr.GetMode(), UID: attr.GetUid(), GID: attr.GetGid(),
			Nlink: attr.GetNlink(), ATimeNS: attr.GetAtimeNs(), MTimeNS: attr.GetMtimeNs(),
			CTimeNS: attr.GetCtimeNs(), BirthTimeNS: attr.GetBirthTimeNs(), Rdev: attr.GetRdev(),
			Blksize: attr.GetBlksize(), Flags: attr.GetFlags(),
		},
	}
	copy(state.StableIdentity[:], object.GetStableIdentity())
	return state
}
func appendUniqueIdentities(dst, src [][16]byte) [][16]byte {
	if len(dst) == 0 && len(src) == 0 {
		return nil
	}
	unique := make([][16]byte, 0, len(dst)+len(src))
	seen := make(map[[16]byte]struct{}, len(dst)+len(src))
	for _, identities := range [][][16]byte{dst, src} {
		for _, identity := range identities {
			if _, exists := seen[identity]; exists {
				continue
			}
			seen[identity] = struct{}{}
			unique = append(unique, identity)
		}
	}
	return unique
}
func validateAuthorityMutationTarget(target volumeserver.MutationTarget) error {
	zero := [16]byte{}
	if target.Device == 0 {
		return errors.New("mutation target carries no backing device")
	}
	switch target.Scope {
	case volumeserver.MutationNamespace:
		if target.ParentIdentity == zero {
			return errors.New("namespace target carries no parent identity")
		}
		if target.Identity != zero {
			return errors.New("namespace target carries an object identity")
		}
		if !pathcomponent.ValidName(target.Name) {
			return errors.New("namespace target name is not a single valid component")
		}
		if target.Size != 0 {
			return errors.New("namespace target carries a size")
		}
		if target.KernelIno != 0 {
			return errors.New("namespace target carries an object kernel inode")
		}
		if target.ExactPostState != nil {
			return errors.New("namespace target carries exact object post-state")
		}
		if target.ParentKernelIno == 0 {
			return errors.New("namespace target carries no parent kernel inode")
		}
		postIsDependency := target.PostIdentity == zero
		for _, identity := range target.RelatedIdentities {
			if identity == zero {
				return errors.New("namespace target carries a zero related identity")
			}
			postIsDependency = postIsDependency || identity == target.PostIdentity
		}
		if !postIsDependency {
			return errors.New("namespace post identity is not a declared dependency")
		}
	case volumeserver.MutationData, volumeserver.MutationAttributes:
		if target.Identity == zero {
			return errors.New("inode target carries no identity")
		}
		if target.ParentIdentity != zero {
			return errors.New("inode target carries a parent identity")
		}
		if len(target.Name) != 0 {
			return errors.New("inode target carries a name")
		}
		if target.PostIdentity != zero {
			return errors.New("inode target carries a namespace post identity")
		}
		if len(target.RelatedIdentities) != 0 {
			return errors.New("inode target carries namespace dependencies")
		}
		if target.KernelIno == 0 {
			return errors.New("inode target carries no kernel inode")
		}
		if target.ParentKernelIno != 0 {
			return errors.New("inode target carries a parent kernel inode")
		}
		if exact := target.ExactPostState; exact != nil {
			if exact.StableIdentity != target.Identity || exact.ObjectVersion == 0 ||
				exact.Attr.Inode != target.KernelIno || exact.Roles == 0 ||
				(target.Scope == volumeserver.MutationData && exact.Attr.Size != target.Size) {
				return errors.New("inode target carries mismatched exact object post-state")
			}
		}
		if target.Scope == volumeserver.MutationData && target.Size < 0 {
			return errors.New("data target carries a negative size")
		}
		if target.Scope == volumeserver.MutationAttributes && target.Size != 0 {
			return errors.New("attributes target carries a size")
		}
	default:
		return fmt.Errorf("mutation target carries scope %d", target.Scope)
	}
	return nil
}

type mutationCoordinate struct {
	identity [16]byte
	ino      uint64
	device   uint64
}

func attrCoordinate(identity [16]byte, attr xfsstore.Attr) mutationCoordinate {
	return mutationCoordinate{identity: identity, ino: attr.Ino, device: attrDevice(attr)}
}

func attrDevice(attr xfsstore.Attr) uint64 {
	return uint64(attr.DeviceMajor)<<32 | uint64(attr.DeviceMinor)
}

func objectCoordinate(coordinate xfsstore.ObjectCoordinate) mutationCoordinate {
	return mutationCoordinate{
		identity: coordinate.Stable,
		ino:      coordinate.Ino,
		device:   uint64(coordinate.DeviceMajor)<<32 | uint64(coordinate.DeviceMinor),
	}
}

// coordinateItem reads the immutable coordinate retained by the store. Call
// sites that already hold an Attr may still use attrCoordinate when that is
// the value whose equivalence they need to attest.
func (h *VolumeHandler) coordinateItem(item xfsstore.Capability) (mutationCoordinate, error) {
	coordinate, err := h.Store.CoordinateItem(item)
	if err != nil {
		return mutationCoordinate{}, err
	}
	return objectCoordinate(coordinate), nil
}

func (h *VolumeHandler) coordinateOpen(handle xfsstore.Capability) (mutationCoordinate, error) {
	coordinate, err := h.Store.CoordinateOpen(handle)
	if err != nil {
		return mutationCoordinate{}, err
	}
	return objectCoordinate(coordinate), nil
}

func namespaceTarget(parent mutationCoordinate, name []byte) volumeserver.MutationTarget {
	return namespaceTargetRelated(parent, name)
}

func namespaceTargetPost(parent mutationCoordinate, name []byte, post mutationCoordinate) volumeserver.MutationTarget {
	target := namespaceTargetRelated(parent, name, post)
	target.PostIdentity = post.identity
	return target
}

func namespaceTargetRelated(parent mutationCoordinate, name []byte, related ...mutationCoordinate) volumeserver.MutationTarget {
	target := volumeserver.MutationTarget{
		Scope: volumeserver.MutationNamespace, ParentIdentity: parent.identity,
		ParentKernelIno: parent.ino, Device: parent.device, Name: append([]byte(nil), name...),
	}
	for _, coordinate := range related {
		if coordinate.identity != ([16]byte{}) {
			target.RelatedIdentities = append(target.RelatedIdentities, coordinate.identity)
		}
	}
	return target
}

func inodeTarget(scope volumeserver.MutationScope, coordinate mutationCoordinate, size int64) volumeserver.MutationTarget {
	return volumeserver.MutationTarget{
		Scope: scope, Identity: coordinate.identity,
		KernelIno: coordinate.ino, Device: coordinate.device, Size: size,
	}
}

func visibilityChanged(resp *authoritypb.Response) bool {
	if resp == nil {
		return false
	}
	if write := resp.GetWrite(); write != nil {
		return write.GetPostAttr() != nil
	}
	if fallocate := resp.GetFallocate(); fallocate != nil {
		return fallocate.GetFlags()&rangeReplyApplied != 0
	}
	if copyRange := resp.GetCopyFileRange(); copyRange != nil {
		return copyRange.GetFlags()&rangeReplyApplied != 0
	}
	return resp.GetErrno() == 0 || resp.GetUncertain()
}

func uncertainMutationTargets(resp *authoritypb.Response, targets []volumeserver.MutationTarget) []volumeserver.MutationTarget {
	if resp != nil && resp.GetUncertain() {
		return targets
	}
	return nil
}

func mountAbsenceProof(proof *authoritypb.MountAbsenceProof) volumeserver.MountAbsenceProof {
	if proof == nil {
		return volumeserver.MountAbsenceProof{}
	}
	return volumeserver.MountAbsenceProof{
		ObservedUnixNanos: proof.GetObservedUnixNanos(),
		Observation:       append([]byte(nil), proof.GetObservation()...),
		Component:         proof.GetComponent(),
	}
}

func isMutationFailure(err error) bool {
	return errors.Is(err, volumeserver.ErrMutationPoisoned) || errors.Is(err, volumeserver.ErrMutationTargets)
}
