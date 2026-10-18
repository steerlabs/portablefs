package volumeserver

import (
	"bytes"
	"errors"
)

type PriorEpochDisposition uint8

const (
	PriorEpochUnproven PriorEpochDisposition = iota
	PriorEpochStrictMountsFenced
)

// DurableMountMembership is outside the disposable authority runtime.
// Activate must durably record a strict mount before attach returns. Deactivate
// must durably record an authenticated clean detach or host fencing before the
// authority drops the mount's barrier obligation.
type DurableMountMembership interface {
	Activate(SessionID) error
	Deactivate(SessionID) error
}

type SessionFencer interface {
	FenceSession(SessionID)
}

// MutationScope identifies one storage observation affected by an operation.
type MutationScope uint8

const (
	MutationNamespace MutationScope = iota + 1
	MutationData
	MutationAttributes
)

// MutationTarget describes a prepared or committed storage coordinate. Names
// include the bound inode dependencies; inode targets retain exact post-state
// after application. These are internal invariants, never peer instructions.
type MutationTarget struct {
	Scope          MutationScope
	Identity       [16]byte
	ParentIdentity [16]byte
	Name           []byte
	Size           int64
	// PostIdentity attests the committed binding when the operation knows it.
	PostIdentity [16]byte
	// Kernel-cache coordination facts, distinct from the stable identities
	// above. The stable identity is the exact XFS export handle — type, inode
	// and generation, never a device — and names the object for frontends
	// that index by item identity. A FUSE frontend keys its kernel caches by
	// the inode number the authority publishes in attributes, so that number
	// and the one backing device travel explicitly instead of being parsed
	// out of a layout that does not contain them.
	KernelIno       uint64
	ParentKernelIno uint64
	Device          uint64
	// RelatedIdentities complete the namespace storage footprint.
	RelatedIdentities [][16]byte
	// ExactPostState is assigned before releasing the storage turn.
	ExactPostState *MutationObjectPostState
}

// MutationObjectPostState validates completion without a protobuf dependency.
type MutationObjectPostState struct {
	StableIdentity [16]byte
	ObjectVersion  uint64
	Attr           MutationAttr
	Roles          uint32
}

// MutationAttr contains the operation's retained statx sample.
type MutationAttr struct {
	Kind        uint32
	Inode       uint64
	Size        int64
	Blocks      uint64
	Mode        uint32
	UID         uint32
	GID         uint32
	Nlink       uint32
	ATimeNS     int64
	MTimeNS     int64
	CTimeNS     int64
	BirthTimeNS int64
	Rdev        uint32
	Blksize     uint32
	Flags       uint32
}

// MutationFootprint is independently resolved by the authority before storage
// admission, then revalidated while the complete dependency turn is held.
type MutationFootprint struct {
	Targets []FootprintTarget
}

func (t FootprintTarget) namespace() bool {
	return t.ParentIdentity != ([16]byte{})
}

func (t MutationTarget) key() []byte {
	if t.Scope == MutationNamespace {
		return nameKey(t.ParentIdentity, t.Name)
	}
	return inodeKey(t.Identity)
}

type MountAbsenceProof struct {
	ObservedUnixNanos int64
	Observation       []byte
	Component         string
}

// Bounds on the retained evidence. The authority keeps none of it, but a
// detach must not be a channel for unbounded work either.
const (
	maxMountAbsenceObservation = 4096
	maxMountAbsenceComponent   = 128
)

func mutationTargetKeys(targets []MutationTarget) [][]byte {
	keys := make([][]byte, 0, len(targets))
	for _, target := range targets {
		keys = append(keys, target.key())
	}
	return keys
}

func mutationTargetKeySet(targets []MutationTarget) map[string]struct{} {
	keys := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		keys[string(target.key())] = struct{}{}
	}
	return keys
}

func mutationTargetsCovered(complete, prepared []MutationTarget) bool {
	covered := make(map[string]struct{}, len(prepared))
	for _, target := range prepared {
		covered[string(target.key())] = struct{}{}
	}
	for _, target := range complete {
		if _, ok := covered[string(target.key())]; !ok {
			return false
		}
	}
	return true
}

func validateMutationTargets(targets []MutationTarget) error {
	if len(targets) == 0 {
		return ErrMutationTargets
	}
	zero := [16]byte{}
	for _, target := range targets {
		switch target.Scope {
		case MutationNamespace:
			if target.ParentIdentity == zero || target.Identity != zero || target.Size != 0 ||
				target.ExactPostState != nil || !legalMutationName(target.Name) {
				return ErrMutationTargets
			}
			postIsDependency := target.PostIdentity == zero
			for _, identity := range target.RelatedIdentities {
				if identity == zero {
					return ErrMutationTargets
				}
				postIsDependency = postIsDependency || identity == target.PostIdentity
			}
			if !postIsDependency {
				return ErrMutationTargets
			}
		case MutationData:
			if target.Identity == zero || target.ParentIdentity != zero || len(target.Name) != 0 || target.Size < 0 || target.PostIdentity != zero || len(target.RelatedIdentities) != 0 {
				return ErrMutationTargets
			}
		case MutationAttributes:
			if target.Identity == zero || target.ParentIdentity != zero || len(target.Name) != 0 || target.Size != 0 || target.PostIdentity != zero || len(target.RelatedIdentities) != 0 {
				return ErrMutationTargets
			}
		default:
			return ErrMutationTargets
		}
		if exact := target.ExactPostState; exact != nil {
			if exact.StableIdentity != target.Identity || exact.ObjectVersion == 0 ||
				exact.Attr.Inode != target.KernelIno || exact.Roles == 0 ||
				(target.Scope == MutationData && exact.Attr.Size != target.Size) {
				return ErrMutationTargets
			}
		}
	}
	return nil
}

func legalMutationName(name []byte) bool {
	return len(name) != 0 && len(name) <= 255 && !bytes.Equal(name, []byte(".")) && !bytes.Equal(name, []byte("..")) &&
		!bytes.ContainsRune(name, '/') && !bytes.ContainsRune(name, 0)
}

func nameKey(parent [16]byte, name []byte) []byte {
	key := make([]byte, 0, 1+len(parent)+len(name))
	key = append(key, 'n')
	key = append(key, parent[:]...)
	return append(key, name...)
}

func inodeKey(identity [16]byte) []byte {
	key := make([]byte, 0, 1+len(identity))
	key = append(key, 'i')
	return append(key, identity[:]...)
}

var (
	ErrWriterExcluded            = errors.New("volumeserver: exclusive Mac writer admission is retained")
	ErrMutationDependencyRefresh = errors.New("volumeserver: mutation dependencies changed during locked revalidation")
	ErrMutationTargets           = errors.New("volumeserver: invalid mutation footprint")
	ErrMutationPoisoned          = errors.New("volumeserver: authority mutation invariant failed")
	ErrMountProof                = errors.New("volumeserver: detach did not prove the kernel mount is absent")
	ErrMountProfile              = errors.New("volumeserver: invalid mount profile")
)

// FootprintTarget is derived from current authority capabilities and bindings.
// Bound identities contribute storage keys; the peer supplies none of them.
type FootprintTarget struct {
	Identity        [16]byte
	ParentIdentity  [16]byte
	Name            []byte
	Attributes      bool
	Data            bool
	BoundAttributes bool
	BoundData       bool
	BoundIdentities [][16]byte
}
