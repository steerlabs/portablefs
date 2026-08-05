//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
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

// strictCache returns the coordinator to record into, or nil when this session
// keeps no kernel cache the barrier has to reason about. An uncached mount is a
// supported deployment profile, not a degraded one: it has no remote repair
// obligation, so none of this work applies to it.
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

// recordReplyItem indexes the inode a mutation reply just handed this mount.
// The coordinator already indexes the coordinates the mutation named, but a
// create names a parent and a name, not the inode it produced, and that inode
// is exactly what the reply asks the frontend to cache.
func (h *VolumeHandler) recordReplyItem(id volumeserver.SessionID, resp *authoritypb.Response) {
	coordinator := h.strictCache(id)
	if coordinator == nil || resp == nil || resp.GetErrno() != 0 {
		return
	}
	var token []byte
	switch {
	case resp.GetCreate() != nil:
		token = resp.GetCreate().GetItem().GetToken()
	case resp.GetLookup() != nil:
		token = resp.GetLookup().GetItem().GetToken()
	case resp.GetLink() != nil:
		token = resp.GetLink().GetItem().GetToken()
	default:
		return
	}
	item, err := capability(token)
	if err != nil {
		return
	}
	if identity, err := h.Store.Identity(item); err == nil {
		coordinator.RecordResolvedInode(id, identity)
	}
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
	case authoritypb.CoherenceProfile_COHERENCE_PROFILE_UNCACHED:
		return volumeserver.CoherenceUncached, nil
	case authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT:
		return volumeserver.CoherenceStrict, nil
	default:
		return 0, syscall.EOPNOTSUPP
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

func visibilityTargetProto(target volumeserver.VisibilityTarget) *authoritypb.VisibilityTarget {
	return &authoritypb.VisibilityTarget{
		Scope:           visibilityScopeProto(target.Scope),
		Identity:        append([]byte(nil), target.Identity[:]...),
		ParentIdentity:  append([]byte(nil), target.ParentIdentity[:]...),
		Name:            append([]byte(nil), target.Name...),
		Size:            target.Size,
		KernelIno:       target.KernelIno,
		ParentKernelIno: target.ParentKernelIno,
		Device:          target.Device,
	}
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

func visibilityScopeProto(scope volumeserver.VisibilityScope) authoritypb.VisibilityScope {
	switch scope {
	case volumeserver.VisibilityNamespace:
		return authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE
	case volumeserver.VisibilityData:
		return authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA
	case volumeserver.VisibilityAttributes:
		return authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES
	default:
		return authoritypb.VisibilityScope_VISIBILITY_SCOPE_UNSPECIFIED
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
	return volumeserver.VisibilityTarget{
		Scope: volumeserver.VisibilityNamespace, ParentIdentity: parent.identity,
		ParentKernelIno: parent.ino, Device: parent.device, Name: append([]byte(nil), name...),
	}
}

func inodeTarget(scope volumeserver.VisibilityScope, coordinate visibilityCoordinate, size int64) volumeserver.VisibilityTarget {
	return volumeserver.VisibilityTarget{
		Scope: scope, Identity: coordinate.identity,
		KernelIno: coordinate.ino, Device: coordinate.device, Size: size,
	}
}

func visibilityChanged(resp *authoritypb.Response) bool {
	return resp != nil && (resp.GetErrno() == 0 || resp.GetUncertain())
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
