//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// maxStabilizeAttempts bounds the retries of a read that learned its own
// coordinate only by reading and then found that read had raced a mutation.
// Each attempt makes progress against one completed mutation, so a caller that
// exhausts them is contending with a continuous stream of mutations on the same
// name and is told to come back rather than being starved silently.
const maxStabilizeAttempts = 8

// maxSkippedReaddirBatches bounds how many consecutive enumeration batches a
// readdir may pass over when every entry in them raced away (unlinked or
// renamed between enumeration and stat). Each skipped batch advances the
// cookie by a full page, so exhausting this bound means the directory is
// being churned faster than it can be listed; the caller is told to come
// back rather than the server scanning without limit.
const maxSkippedReaddirBatches = 8

// namespaceName is the precondition every namespace-mutating request checks
// before it constructs a visibility target. It is the store's own directory
// entry predicate, and it accepts exactly the names the target validator
// accepts, so a request that gets past it can never turn a malformed name into
// a target-construction defect. Some paths used to inherit this check from the
// lookup they happened to perform first; inheriting a precondition from an
// unrelated call is how mkdir, link, and symlink came to have no check at all.
func namespaceName(name []byte) error {
	return xfsstore.ValidateComponent(string(name))
}

// strictCache returns the one protocol-5 coherence coordinator. A missing or
// non-coherent session returns nil only on an already-invalid runtime path; no
// attach can activate such a session.
func (h *VolumeHandler) strictCache(id volumeserver.SessionID) *volumeserver.VisibilityCoordinator {
	if h.Visibility == nil || !h.strictSession(id) {
		return nil
	}
	return h.Visibility
}

// stabilizeItem guards one read-path answer about an inode this session already
// holds a capability for. The coordinate is known before anything is read, so
// the reported wait carries no information the caller needs.
func (h *VolumeHandler) stabilizeItem(ctx context.Context, id volumeserver.SessionID, item xfsstore.Capability) error {
	coordinator := h.strictCache(id)
	if coordinator == nil {
		return nil
	}
	identity, err := h.Store.Identity(item)
	if err != nil {
		return err
	}
	_, err = coordinator.Stabilize(ctx, id, volumeserver.VisibilityResolution{Identity: identity})
	return err
}

func (h *VolumeHandler) stabilizeOpen(ctx context.Context, id volumeserver.SessionID, handle xfsstore.Capability) error {
	coordinator := h.strictCache(id)
	if coordinator == nil {
		return nil
	}
	identity, err := h.Store.IdentityOpen(handle)
	if err != nil {
		return err
	}
	_, err = coordinator.Stabilize(ctx, id, volumeserver.VisibilityResolution{Identity: identity})
	return err
}

// lookupForSession answers one name resolution. For a strict mount the answer
// is what the kernel will cache - including a negative one, which the kernel
// caches too - so the binding is recorded either way, and the inode the name
// resolved to is recorded as well because it is only knowable after the read.
// A read that raced a mutation on either coordinate is discarded and retried.
func (h *VolumeHandler) lookupForSession(ctx context.Context, id volumeserver.SessionID, parent xfsstore.Capability, name []byte) (xfsstore.Capability, xfsstore.Attr, error) {
	coordinator := h.strictCache(id)
	if coordinator == nil {
		return h.Store.Lookup(parent, string(name))
	}
	parentIdentity, err := h.Store.Identity(parent)
	if err != nil {
		return xfsstore.Capability{}, xfsstore.Attr{}, err
	}
	for range maxStabilizeAttempts {
		item, attr, lookupErr := h.Store.Lookup(parent, string(name))
		resolution := volumeserver.VisibilityResolution{Parent: parentIdentity, Name: name}
		if lookupErr == nil {
			identity, identityErr := h.Store.Identity(item)
			if identityErr != nil {
				_ = h.Store.Forget(item)
				return xfsstore.Capability{}, xfsstore.Attr{}, identityErr
			}
			resolution.Identity = identity
		}
		waited, err := coordinator.Stabilize(ctx, id, resolution)
		if err == nil && !waited {
			return item, attr, lookupErr
		}
		if lookupErr == nil {
			_ = h.Store.Forget(item)
		}
		if err != nil {
			return xfsstore.Capability{}, xfsstore.Attr{}, err
		}
	}
	return xfsstore.Capability{}, xfsstore.Attr{}, syscall.EAGAIN
}

// stabilizeDirectoryPage covers one page of an enumeration. A strict frontend
// caches the names it enumerated and the state of the inodes behind them, so
// every one of those coordinates is resolved and recorded before the page is
// built. Resolving each child costs an extra open/stat/close, which is why it
// only happens for a strict mount.
func (h *VolumeHandler) stabilizeDirectoryPage(ctx context.Context, id volumeserver.SessionID, dir xfsstore.Capability, parent xfsstore.Capability, entries []xfsstore.Dirent) (bool, error) {
	coordinator := h.strictCache(id)
	if coordinator == nil {
		return false, nil
	}
	directory, err := h.Store.IdentityOpen(dir)
	if err != nil {
		return false, err
	}
	if parent == (xfsstore.Capability{}) {
		return false, syscall.ESTALE
	}
	resolutions := make([]volumeserver.VisibilityResolution, 0, len(entries)+1)
	resolutions = append(resolutions, volumeserver.VisibilityResolution{Identity: directory})
	for _, entry := range entries {
		resolution := volumeserver.VisibilityResolution{Parent: directory, Name: []byte(entry.Name)}
		// An entry whose inode cannot be resolved - it was unlinked under the
		// enumeration, or it is a type this authority never exposes as an object
		// - contributes its name and nothing else. There is no inode state the
		// frontend could be caching for it, so omitting the inode coordinate
		// cannot hide one. The reply loop and the trailing verifier check still
		// report the entry itself as stale if it really went away.
		if coordinate, found, err := h.lookupCoordinate(parent, []byte(entry.Name)); err == nil && found {
			resolution.Identity = coordinate.identity
		}
		resolutions = append(resolutions, resolution)
	}
	return coordinator.Stabilize(ctx, id, resolutions...)
}

func coherenceProfile(profile authoritypb.CoherenceProfile) (volumeserver.CoherenceProfile, error) {
	switch profile {
	case authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT:
		return volumeserver.CoherenceStrict, nil
	default:
		// Zero is both protobuf's omitted value and the value emitted by the
		// retired UNCACHED profile. Protocol 5 never normalizes it into the one
		// coherent contract: an old frontend has not installed source gates or
		// peer visibility and must be refused before activation.
		return 0, syscall.EINVAL
	}
}

func visibilityCursor(cursor *authoritypb.VisibilityCursor) (volumeserver.VisibilityCursor, error) {
	if cursor == nil {
		return volumeserver.VisibilityCursor{}, nil
	}
	phase, err := visibilityPhase(cursor.GetPhase())
	if err != nil {
		return volumeserver.VisibilityCursor{}, err
	}
	if cursor.GetSequence() == 0 || phase == 0 {
		return volumeserver.VisibilityCursor{}, syscall.EINVAL
	}
	return volumeserver.VisibilityCursor{Sequence: cursor.GetSequence(), Phase: phase}, nil
}

func visibilityPhase(phase authoritypb.VisibilityPhase) (volumeserver.VisibilityPhase, error) {
	switch phase {
	case authoritypb.VisibilityPhase_VISIBILITY_PHASE_UNSPECIFIED:
		return 0, nil
	case authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE:
		return volumeserver.VisibilityPrepare, nil
	case authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE:
		return volumeserver.VisibilityComplete, nil
	default:
		return 0, syscall.EINVAL
	}
}

func visibilityEventProto(event volumeserver.VisibilityEvent) *authoritypb.VisibilityEvent {
	targets := make([]*authoritypb.VisibilityTarget, len(event.Targets))
	for i, target := range event.Targets {
		targets[i] = visibilityTargetProto(target)
	}
	return &authoritypb.VisibilityEvent{
		Cursor:             visibilityCursorProto(event.Cursor),
		InitiatorSessionId: append([]byte(nil), event.Initiator[:]...),
		MutationSlot:       event.MutationSlot,
		MutationSequence:   event.MutationSequence,
		Targets:            targets,
		Routes:             routesChangeProto(event.Routes),
	}
}

// routesChangeProto carries a routing-topology change on the event that
// announces it. It is a distinct field rather than a namespace target because
// it is not a cache coordinate: there is no parent and no name a frontend could
// invalidate to discharge it, and encoding it as one would let a frontend
// satisfy it by dropping a dentry instead of by swapping its routing table.
func routesChangeProto(change *volumeserver.RoutesChange) *authoritypb.RoutesChange {
	if change == nil {
		return nil
	}
	return &authoritypb.RoutesChange{
		Revision: append([]byte(nil), change.Revision[:]...),
		Rules:    append([]byte(nil), change.Canonical...),
	}
}

func visibilityCursorProto(cursor volumeserver.VisibilityCursor) *authoritypb.VisibilityCursor {
	if cursor == (volumeserver.VisibilityCursor{}) {
		return nil
	}
	return &authoritypb.VisibilityCursor{Sequence: cursor.Sequence, Phase: visibilityPhaseProto(cursor.Phase)}
}

// visibilityTargetProto emits the scope-exact wire shape through the
// visibilitywire constructors. The coordinator's struct carries both identity
// arrays because Go arrays have no absent state; the wire does, and a decoder
// is entitled to refuse a target whose unused identity is sixteen zero bytes
// rather than absent. Emitting a field the scope does not define is therefore
// an encoder defect, not decoder pedantry.
func visibilityTargetProto(target volumeserver.VisibilityTarget) *authoritypb.VisibilityTarget {
	switch target.Scope {
	case volumeserver.VisibilityNamespace:
		wire := visibilitywire.Namespace(target.ParentIdentity[:], target.Name, target.ParentKernelIno, target.Device)
		if target.PostIdentity != ([16]byte{}) {
			wire.PostIdentity = append([]byte(nil), target.PostIdentity[:]...)
		}
		return wire
	case volumeserver.VisibilityData:
		return visibilitywire.Data(target.Identity[:], target.KernelIno, target.Device, target.Size)
	case volumeserver.VisibilityAttributes:
		return visibilitywire.Attributes(target.Identity[:], target.KernelIno, target.Device)
	default:
		// An unknown scope cannot be encoded as anything a decoder would act
		// on. Emit only the unspecified scope so every receiver fails closed
		// on this exact target instead of repairing a guessed coordinate.
		return &authoritypb.VisibilityTarget{}
	}
}

// normalizeVisibilityTargets gives every cache coordinate exactly one repair
// instruction before the coordinator indexes, projects, and serializes it. A
// DATA repair subsumes an ATTRIBUTES repair for the same stable identity; its
// size is the authoritative post-mutation EOF and must survive regardless of
// which scope appeared first. Duplicate namespace coordinates union their
// dependency identities in first-occurrence order.
//
// Validate the complete raw list first. Normalizing as validation proceeds
// would let a valid DATA target hide a malformed ATTRIBUTES target that it
// dominates. It would also make the accepted language depend on target order.
func normalizeVisibilityTargets(targets []volumeserver.VisibilityTarget) ([]volumeserver.VisibilityTarget, error) {
	for index, target := range targets {
		if err := validateAuthorityVisibilityTarget(target); err != nil {
			return nil, fmt.Errorf("%w: target %d: %v", volumeserver.ErrVisibilityTargets, index, err)
		}
	}
	if len(targets) == 0 {
		return targets, nil
	}

	normalized := make([]volumeserver.VisibilityTarget, 0, len(targets))
	inodeIndexes := make(map[[16]byte]int)
	type namespaceKey struct {
		parent [16]byte
		name   string
	}
	namespaceIndexes := make(map[namespaceKey]int)
	for _, target := range targets {
		if target.Scope == volumeserver.VisibilityNamespace {
			key := namespaceKey{parent: target.ParentIdentity, name: string(target.Name)}
			index, exists := namespaceIndexes[key]
			if !exists {
				namespaceIndexes[key] = len(normalized)
				target.RelatedIdentities = appendUniqueVisibilityIdentities(nil, target.RelatedIdentities)
				normalized = append(normalized, target)
				continue
			}
			prior := &normalized[index]
			if prior.ParentKernelIno != target.ParentKernelIno || prior.Device != target.Device {
				return nil, fmt.Errorf(
					"%w: namespace coordinate %x/%q has conflicting kernel coordinates",
					volumeserver.ErrVisibilityTargets, target.ParentIdentity, target.Name,
				)
			}
			if prior.PostIdentity != target.PostIdentity {
				return nil, fmt.Errorf(
					"%w: namespace coordinate %x/%q has conflicting post identities",
					volumeserver.ErrVisibilityTargets, target.ParentIdentity, target.Name,
				)
			}
			prior.RelatedIdentities = appendUniqueVisibilityIdentities(prior.RelatedIdentities, target.RelatedIdentities)
			continue
		}
		index, exists := inodeIndexes[target.Identity]
		if !exists {
			inodeIndexes[target.Identity] = len(normalized)
			normalized = append(normalized, target)
			continue
		}

		prior := normalized[index]
		if prior.KernelIno != target.KernelIno || prior.Device != target.Device {
			return nil, fmt.Errorf(
				"%w: inode identity %x has conflicting kernel coordinates",
				volumeserver.ErrVisibilityTargets, target.Identity,
			)
		}
		switch {
		case prior.Scope == volumeserver.VisibilityData && target.Scope == volumeserver.VisibilityData:
			if prior.Size != target.Size {
				return nil, fmt.Errorf(
					"%w: inode identity %x has conflicting authoritative sizes %d and %d",
					volumeserver.ErrVisibilityTargets, target.Identity, prior.Size, target.Size,
				)
			}
			// Exact duplicate DATA target.
		case prior.Scope == volumeserver.VisibilityAttributes && target.Scope == volumeserver.VisibilityData:
			// Keep the coordinate's first position but replace its weaker repair
			// with DATA, including DATA's authoritative size.
			normalized[index] = target
		case prior.Scope == volumeserver.VisibilityData && target.Scope == volumeserver.VisibilityAttributes:
			// DATA already dominates this exact ATTRIBUTES coordinate.
		case prior.Scope == volumeserver.VisibilityAttributes && target.Scope == volumeserver.VisibilityAttributes:
			// Exact duplicate ATTRIBUTES target.
		default:
			// Validation above makes this unreachable. Keep it fail-closed so a
			// future scope cannot silently inherit today's dominance rule.
			return nil, fmt.Errorf("%w: inode identity %x has incompatible scopes", volumeserver.ErrVisibilityTargets, target.Identity)
		}
	}
	return normalized, nil
}

func appendUniqueVisibilityIdentities(dst, src [][16]byte) [][16]byte {
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

// validateAuthorityVisibilityTarget is the in-memory half of the exact wire
// shape. It includes RelatedIdentities, which are authority-private and cannot
// be checked after visibilityTargetProto deliberately omits them.
func validateAuthorityVisibilityTarget(target volumeserver.VisibilityTarget) error {
	zero := [16]byte{}
	if target.Device == 0 {
		return errors.New("visibility target carries no backing device")
	}
	switch target.Scope {
	case volumeserver.VisibilityNamespace:
		if target.ParentIdentity == zero {
			return errors.New("namespace target carries no parent identity")
		}
		if target.Identity != zero {
			return errors.New("namespace target carries an object identity")
		}
		if !visibilitywire.ValidName(target.Name) {
			return errors.New("namespace target name is not a single valid component")
		}
		if target.Size != 0 {
			return errors.New("namespace target carries a size")
		}
		if target.KernelIno != 0 {
			return errors.New("namespace target carries an object kernel inode")
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
	case volumeserver.VisibilityData, volumeserver.VisibilityAttributes:
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
		if target.Scope == volumeserver.VisibilityData && target.Size < 0 {
			return errors.New("data target carries a negative size")
		}
		if target.Scope == volumeserver.VisibilityAttributes && target.Size != 0 {
			return errors.New("attributes target carries a size")
		}
	default:
		return fmt.Errorf("visibility target carries scope %d", target.Scope)
	}
	return nil
}

func visibilityPhaseProto(phase volumeserver.VisibilityPhase) authoritypb.VisibilityPhase {
	switch phase {
	case volumeserver.VisibilityPrepare:
		return authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE
	case volumeserver.VisibilityComplete:
		return authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE
	default:
		return authoritypb.VisibilityPhase_VISIBILITY_PHASE_UNSPECIFIED
	}
}

// visibilityCoordinate is everything one visibility target has to say to name
// an object: the stable XFS export-handle identity the coordinator indexes by,
// and the kernel-cache facts a FUSE frontend repairs by — the attr inode
// number and the one backing device. The two travel together because the
// stable identity's layout deliberately does not contain either fact, and
// parsing it as though it did is exactly the defect this type removes.
type visibilityCoordinate struct {
	identity [16]byte
	ino      uint64
	device   uint64
}

func attrCoordinate(identity [16]byte, attr xfsstore.Attr) visibilityCoordinate {
	return visibilityCoordinate{identity: identity, ino: attr.Ino, device: attrDevice(attr)}
}

func attrDevice(attr xfsstore.Attr) uint64 {
	return uint64(attr.DeviceMajor)<<32 | uint64(attr.DeviceMinor)
}

// coordinateItem fetches an object's stable identity together with the
// attributes that carry its kernel-cache facts. Call sites that already hold
// the Attr build the coordinate with attrCoordinate instead of statting twice.
func (h *VolumeHandler) coordinateItem(item xfsstore.Capability) (visibilityCoordinate, error) {
	identity, err := h.Store.Identity(item)
	if err != nil {
		return visibilityCoordinate{}, err
	}
	attr, err := h.Store.Getattr(item)
	if err != nil {
		return visibilityCoordinate{}, err
	}
	return attrCoordinate(identity, attr), nil
}

func (h *VolumeHandler) coordinateOpen(handle xfsstore.Capability) (visibilityCoordinate, error) {
	identity, err := h.Store.IdentityOpen(handle)
	if err != nil {
		return visibilityCoordinate{}, err
	}
	attr, err := h.Store.GetattrOpen(handle)
	if err != nil {
		return visibilityCoordinate{}, err
	}
	return attrCoordinate(identity, attr), nil
}

func namespaceTarget(parent visibilityCoordinate, name []byte) volumeserver.VisibilityTarget {
	return namespaceTargetRelated(parent, name)
}

func namespaceTargetPost(parent visibilityCoordinate, name []byte, post visibilityCoordinate) volumeserver.VisibilityTarget {
	target := namespaceTargetRelated(parent, name, post)
	target.PostIdentity = post.identity
	return target
}

func namespaceTargetRelated(parent visibilityCoordinate, name []byte, related ...visibilityCoordinate) volumeserver.VisibilityTarget {
	target := volumeserver.VisibilityTarget{
		Scope: volumeserver.VisibilityNamespace, ParentIdentity: parent.identity,
		ParentKernelIno: parent.ino, Device: parent.device, Name: append([]byte(nil), name...),
	}
	for _, coordinate := range related {
		if coordinate.identity != ([16]byte{}) {
			target.RelatedIdentities = append(target.RelatedIdentities, coordinate.identity)
		}
	}
	return target
}

func inodeTarget(scope volumeserver.VisibilityScope, coordinate visibilityCoordinate, size int64) volumeserver.VisibilityTarget {
	return volumeserver.VisibilityTarget{
		Scope: scope, Identity: coordinate.identity,
		KernelIno: coordinate.ino, Device: coordinate.device, Size: size,
	}
}

func visibilityChanged(resp *authoritypb.Response) bool {
	if resp == nil {
		return false
	}
	if transaction := resp.GetWriteTransaction(); transaction != nil {
		// A structured REJECTED result has outer errno zero so it can carry the
		// private kernel rejection reason, but it is explicit proof that XFS did
		// not change. Only COMMITTED opens a DATA/ATTR COMPLETE phase.
		return transaction.GetFlags()&writeTransactionReplyCommitted != 0
	}
	if fallocate := resp.GetFallocate(); fallocate != nil {
		return fallocate.GetFlags()&rangeReplyApplied != 0
	}
	if copyRange := resp.GetCopyFileRange(); copyRange != nil {
		return copyRange.GetFlags()&rangeReplyApplied != 0
	}
	return resp.GetErrno() == 0 || resp.GetUncertain()
}

func uncertainVisibilityTargets(resp *authoritypb.Response, targets []volumeserver.VisibilityTarget) []volumeserver.VisibilityTarget {
	if resp != nil && resp.GetUncertain() {
		return targets
	}
	return nil
}

// isVisibilityFailure selects the errors that are about the volume's cache
// coherence as a whole: an authority defect that poisoned the epoch, a
// startup that could not prove prior mounts fenced, and a target-construction
// defect. These are the only ones that may be allowed to end the process.
func isVisibilityFailure(err error) bool {
	return errors.Is(err, volumeserver.ErrVisibilityPoisoned) ||
		errors.Is(err, volumeserver.ErrVisibilityStartup) || errors.Is(err, volumeserver.ErrVisibilityTargets)
}

// isVisibilityFenced selects the errors that are about exactly one mount. A
// laptop that slept, a mount that blew its repair budget, and a frontend that
// violated the phase cursor are all this session's problem and nobody else's;
// the volume keeps serving. The mount is told its session is gone so it revokes
// itself, which is what ESTALE means to a frontend.
func isVisibilityFenced(err error) bool {
	return errors.Is(err, volumeserver.ErrVisibilityLost) || errors.Is(err, volumeserver.ErrVisibilityDeadline) ||
		errors.Is(err, volumeserver.ErrVisibilitySequence) || errors.Is(err, volumeserver.ErrVisibilityBlocked)
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
