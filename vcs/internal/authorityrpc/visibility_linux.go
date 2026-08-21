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

// strictCache returns the FSKit synchronous-repair coordinator. A missing or
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
// a classified visibility retry can unwind the authority request before state
// is published. The daemon consumes that internal response, waits for the exact
// pending repair, and reissues the request inside the same FUSE callback.
func (h *VolumeHandler) stabilizeItem(ctx context.Context, id volumeserver.SessionID, item xfsstore.Capability) error {
	_, err := h.stabilizeItemSequence(ctx, id, item)
	return err
}

func (h *VolumeHandler) stabilizeItemSequence(ctx context.Context, id volumeserver.SessionID, item xfsstore.Capability) (uint64, error) {
	coordinator := h.strictCache(id)
	if coordinator == nil {
		return 1, nil
	}
	identity, err := h.Store.Identity(item)
	if err != nil {
		return 0, err
	}
	_, sequence, err := coordinator.StabilizeSequence(ctx, id, volumeserver.VisibilityResolution{Identity: identity})
	return sequence, err
}

func (h *VolumeHandler) stabilizeOpen(ctx context.Context, id volumeserver.SessionID, handle xfsstore.Capability) error {
	_, err := h.stabilizeOpenSequence(ctx, id, handle)
	return err
}

func (h *VolumeHandler) stabilizeOpenSequence(ctx context.Context, id volumeserver.SessionID, handle xfsstore.Capability) (uint64, error) {
	coordinator := h.strictCache(id)
	if coordinator == nil {
		return 1, nil
	}
	identity, err := h.Store.IdentityOpen(handle)
	if err != nil {
		return 0, err
	}
	_, sequence, err := coordinator.StabilizeSequence(ctx, id, volumeserver.VisibilityResolution{Identity: identity})
	return sequence, err
}

// lookupForSession answers one name resolution. For a strict mount the answer
// is what the kernel will cache - including a negative one, which the kernel
// caches too - so the binding is recorded either way, and the inode the name
// resolved to is recorded as well because it is only knowable after the read.
// A read that raced a mutation on either coordinate is discarded and retried.
func (h *VolumeHandler) lookupForSession(ctx context.Context, id volumeserver.SessionID, parent xfsstore.Capability, name []byte) (xfsstore.Capability, xfsstore.Attr, uint64, error) {
	coordinator := h.strictCache(id)
	if coordinator == nil {
		item, attr, err := h.Store.Lookup(parent, string(name))
		return item, attr, 1, err
	}
	parentIdentity, err := h.Store.Identity(parent)
	if err != nil {
		return xfsstore.Capability{}, xfsstore.Attr{}, 0, err
	}
	for range maxStabilizeAttempts {
		item, attr, lookupErr := h.Store.Lookup(parent, string(name))
		resolution := volumeserver.VisibilityResolution{Parent: parentIdentity, Name: name}
		if lookupErr == nil {
			identity, identityErr := h.Store.Identity(item)
			if identityErr != nil {
				_ = h.Store.Forget(item)
				return xfsstore.Capability{}, xfsstore.Attr{}, 0, identityErr
			}
			resolution.Identity = identity
		}
		waited, sequence, err := coordinator.StabilizeSequence(ctx, id, resolution)
		if errors.Is(err, volumeserver.ErrVisibilityRetry) {
			// Lookup already owns a bounded discard-and-reread loop. Unlike item
			// reads, no answer has left this authority request, so let the concurrent
			// CONTROL Ack clear the pending phase before the next attempt.
			waited, err = true, nil
		}
		if err == nil && !waited {
			return item, attr, sequence, lookupErr
		}
		if lookupErr == nil {
			_ = h.Store.Forget(item)
		}
		if err != nil {
			return xfsstore.Capability{}, xfsstore.Attr{}, 0, err
		}
	}
	return xfsstore.Capability{}, xfsstore.Attr{}, 0, syscall.EAGAIN
}

// stabilizeDirectoryPage takes one cut over the complete candidate page. The
// caller has already sampled every name, identity, attr, and object version;
// after this cut it revalidates those same facts before publishing any of them.
//
// Two things happen here and they are separate. The visibility coordinator
// decides *when* the cut may be taken: it blocks while a conflicting barrier is
// in flight and records the page's resolutions in this participant's monotone
// index. The cut's *value* is the volume's storage cut, which is a different
// counter and deliberately not the coordinator's own barrier sequence -- the
// caller compares it against each entry's ObjectVersion, and those are stamped
// from the storage cut. Returning the barrier sequence here made a sync-repair
// readdir compare two unrelated counters, so on any volume a Linux mount had
// written to, every entry looked like it was from the future and the page could
// never stabilize.
func (h *VolumeHandler) stabilizeDirectoryPage(ctx context.Context, id volumeserver.SessionID, dir xfsstore.Capability, candidates []directoryPageCandidate) (bool, uint64, error) {
	coordinator := h.strictCache(id)
	if coordinator == nil {
		return false, h.storageCut(), nil
	}
	directory, err := h.Store.IdentityOpen(dir)
	if err != nil {
		return false, 0, err
	}
	resolutions := make([]volumeserver.VisibilityResolution, 0, len(candidates)+1)
	resolutions = append(resolutions, volumeserver.VisibilityResolution{Identity: directory})
	for _, candidate := range candidates {
		resolution := volumeserver.VisibilityResolution{
			Parent: directory, Name: []byte(candidate.enumerated.Name),
			Identity: candidate.identity,
		}
		resolutions = append(resolutions, resolution)
	}
	waited, _, err := coordinator.StabilizeSequence(ctx, id, resolutions...)
	if errors.Is(err, volumeserver.ErrVisibilityRetry) {
		// Readdir's caller discards the page and repeats this bounded loop while
		// the independent CONTROL lane acknowledges the pending PREPARE.
		return true, 0, nil
	}
	if err != nil || waited {
		return waited, 0, err
	}
	// Sampled here rather than before the wait: StabilizeSequence returns only
	// once no barrier conflicting with this page is in flight, so the cut read
	// at this point is one no covered entry can already be ahead of. Sampling
	// before the wait would let a mutation commit during it and make a
	// legitimate entry look like an ordering defect.
	return false, h.storageCut(), nil
}

// storageCut is the volume's object-version domain: the latest completed
// storage cut. Object versions are stamped from it -- finalizeMutationPostState
// records the lease commit sequence, and LeaseReadAdmission.SnapshotSequence
// publishes the same counter -- so a page stabilized against it is directly
// comparable to the versions its entries carry, for either frontend profile.
//
// It floors at 1 for the same reason sampledObjectVersion floors an unstamped
// object at 1: before anything has committed, the domain's first value is 1.
// Returning 0 would make every unstamped entry look like it came from the
// future on a volume nothing had written to yet.
func (h *VolumeHandler) storageCut() uint64 {
	if h.Leases == nil {
		return 1
	}
	if cut := h.Leases.CommittedSequence(); cut != 0 {
		return cut
	}
	return 1
}

func coherenceProfile(profile authoritypb.CoherenceProfile) (volumeserver.CoherenceProfile, error) {
	switch profile {
	case authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT:
		return volumeserver.CoherenceStrict, nil
	default:
		// Zero is both protobuf's omitted value and the value emitted by the
		// retired UNCACHED profile. Protocol 6 never normalizes it into the strict
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
	withExact := func(wire *authoritypb.VisibilityTarget) *authoritypb.VisibilityTarget {
		if target.ExactPostState != nil {
			wire.ExactPostState = visibilityObjectPostStateProto(target.ExactPostState)
		}
		return wire
	}
	switch target.Scope {
	case volumeserver.VisibilityNamespace:
		wire := visibilitywire.Namespace(target.ParentIdentity[:], target.Name, target.ParentKernelIno, target.Device)
		if target.PostIdentity != ([16]byte{}) {
			wire.PostIdentity = append([]byte(nil), target.PostIdentity[:]...)
		}
		return wire
	case volumeserver.VisibilityData:
		return withExact(visibilitywire.Data(target.Identity[:], target.KernelIno, target.Device, target.Size))
	case volumeserver.VisibilityAttributes:
		return withExact(visibilitywire.Attributes(target.Identity[:], target.KernelIno, target.Device))
	default:
		// An unknown scope cannot be encoded as anything a decoder would act
		// on. Emit only the unspecified scope so every receiver fails closed
		// on this exact target instead of repairing a guessed coordinate.
		return &authoritypb.VisibilityTarget{}
	}
}

func visibilityObjectPostStateProto(state *volumeserver.VisibilityObjectPostState) *authoritypb.ObjectPostState {
	if state == nil {
		return nil
	}
	attr := state.Attr
	return &authoritypb.ObjectPostState{
		StableIdentity: append([]byte(nil), state.StableIdentity[:]...),
		ObjectVersion:  state.ObjectVersion,
		Roles:          state.Roles,
		Attr: &authoritypb.Attr{
			Kind: authoritypb.Attr_Kind(attr.Kind), Inode: attr.Inode, Size: attr.Size,
			Blocks: attr.Blocks, Mode: attr.Mode, Uid: attr.UID, Gid: attr.GID,
			Nlink: attr.Nlink, AtimeNs: attr.ATimeNS, MtimeNs: attr.MTimeNS,
			CtimeNs: attr.CTimeNS, BirthTimeNs: attr.BirthTimeNS, Rdev: attr.Rdev,
			Blksize: attr.Blksize, Flags: attr.Flags,
		},
	}
}

func visibilityObjectPostState(object *authoritypb.ObjectPostState) *volumeserver.VisibilityObjectPostState {
	if object == nil || len(object.GetStableIdentity()) != 16 || object.GetAttr() == nil {
		return nil
	}
	attr := object.GetAttr()
	state := &volumeserver.VisibilityObjectPostState{
		ObjectVersion: object.GetObjectVersion(), Roles: object.GetRoles(),
		Attr: volumeserver.VisibilityAttr{
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

// attachExactRepairPostState binds each repaired inode coordinate to the exact
// object record already retained for the source reply. The visibility event is
// constructed before that reply is released, so this never takes a second
// snapshot and never guesses which object a coordinate names.
func attachExactRepairPostState(
	targets []volumeserver.VisibilityTarget,
	state *authoritypb.PostState,
	sequence uint64,
	changedIdentities map[[16]byte]struct{},
) error {
	if !validPostStateShape(state, true) || state.GetVisibilitySequence() != sequence {
		return errors.New("authorityrpc: visible mutation has no exact repair post-state")
	}
	if changedIdentities == nil {
		return fmt.Errorf("%w: exact mutation record omitted its changed-identity set", volumeserver.ErrVisibilityTargets)
	}
	coverage := make(map[[16]byte]volumeserver.VisibilityTarget, len(targets))
	for _, target := range targets {
		if target.Scope == volumeserver.VisibilityNamespace {
			continue
		}
		coverage[target.Identity] = target
	}
	objects := make(map[[16]byte]*authoritypb.ObjectPostState, len(state.GetObjects()))
	for _, object := range state.GetObjects() {
		var identity [16]byte
		copy(identity[:], object.GetStableIdentity())
		objects[identity] = object
	}
	for identity := range changedIdentities {
		object := objects[identity]
		target, ok := coverage[identity]
		if object == nil || !ok ||
			target.KernelIno != object.GetAttr().GetInode() ||
			target.Scope == volumeserver.VisibilityData && target.Size != object.GetAttr().GetSize() {
			return fmt.Errorf("%w: changed post-state object %x has no matching COMPLETE repair target", volumeserver.ErrVisibilityTargets, identity)
		}
	}
	exactCount := 0
	for index := range targets {
		target := &targets[index]
		if target.Scope == volumeserver.VisibilityNamespace {
			if target.ExactPostState != nil {
				return errors.New("authorityrpc: namespace repair carried attribute post-state")
			}
			continue
		}
		exactCount++
		object := objects[target.Identity]
		if object == nil || object.GetObjectVersion() == 0 || object.GetObjectVersion() > sequence || object.GetAttr().GetInode() != target.KernelIno ||
			target.Scope == volumeserver.VisibilityData && object.GetAttr().GetSize() != target.Size {
			return fmt.Errorf("%w: repair coordinate %x has no matching exact mutation record", volumeserver.ErrVisibilityTargets, target.Identity)
		}
		target.ExactPostState = visibilityObjectPostState(object)
	}
	if exactCount > 4 {
		return errors.New("authorityrpc: exact repair exceeds four object records")
	}
	return nil
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
		if exact := target.ExactPostState; exact != nil {
			if exact.StableIdentity != target.Identity || exact.ObjectVersion == 0 ||
				exact.Attr.Inode != target.KernelIno || exact.Roles == 0 ||
				(target.Scope == volumeserver.VisibilityData && exact.Attr.Size != target.Size) {
				return errors.New("inode target carries mismatched exact object post-state")
			}
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

func objectCoordinate(coordinate xfsstore.ObjectCoordinate) visibilityCoordinate {
	return visibilityCoordinate{
		identity: coordinate.Stable,
		ino:      coordinate.Ino,
		device:   uint64(coordinate.DeviceMajor)<<32 | uint64(coordinate.DeviceMinor),
	}
}

// coordinateItem reads the immutable coordinate retained by the store. Call
// sites that already hold an Attr may still use attrCoordinate when that is
// the value whose equivalence they need to attest.
func (h *VolumeHandler) coordinateItem(item xfsstore.Capability) (visibilityCoordinate, error) {
	coordinate, err := h.Store.CoordinateItem(item)
	if err != nil {
		return visibilityCoordinate{}, err
	}
	return objectCoordinate(coordinate), nil
}

func (h *VolumeHandler) coordinateOpen(handle xfsstore.Capability) (visibilityCoordinate, error) {
	coordinate, err := h.Store.CoordinateOpen(handle)
	if err != nil {
		return visibilityCoordinate{}, err
	}
	return objectCoordinate(coordinate), nil
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
		errors.Is(err, volumeserver.ErrVisibilitySequence)
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
