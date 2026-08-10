//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"log"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var errInternal = errors.New("authorityrpc: internal handler failure")

// readDirReplyOverhead bounds the fixed part of a directory reply: the 16-byte
// verifier, the EOF flag, and the protobuf tags wrapping the reply inside a
// Response. Entries are budgeted against the remainder.
const readDirReplyOverhead uint32 = 64

// Authorizer validates a short-lived control-plane capability. Implementations
// must bind it to the authenticated TLS peer and exact volume; the data-plane
// handler has no development-token or anonymous mode.
type Authorizer interface {
	Authorize(context.Context, string, []byte) (volumeserver.Authorization, error)
}

type Reauthorizer interface {
	Reauthorize(context.Context, string, volumeserver.SessionID, uint64, []byte) (volumeserver.Authorization, [32]byte, error)
}

// volumeStore is the complete syscall-backed authority surface. Keeping the
// handler dependent on this contract (rather than the concrete XFS carrier)
// makes the pre-apply admission boundary fault-injectable while production has
// exactly one implementation: *xfsstore.Volume.
type volumeStore interface {
	Root() (xfsstore.Capability, error)
	Fence(error)
	Lookup(xfsstore.Capability, string) (xfsstore.Capability, xfsstore.Attr, error)
	Forget(xfsstore.Capability) error
	Getattr(xfsstore.Capability) (xfsstore.Attr, error)
	Identity(xfsstore.Capability) ([16]byte, error)
	IdentityOpen(xfsstore.Capability) ([16]byte, error)
	OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error)
	CloseOpen(xfsstore.Capability) error
	ReadAt(xfsstore.Capability, []byte, int64) (int, error)
	WriteAt(xfsstore.Capability, []byte, int64) (int, error)
	Append(xfsstore.Capability, []byte) (int, int64, error)
	Truncate(xfsstore.Capability, int64) error
	Fsync(xfsstore.Capability, bool) error
	GetattrOpen(xfsstore.Capability) (xfsstore.Attr, error)
	SyncFS() error
	ReadDirOpen(xfsstore.Capability, uint64, [16]byte, int) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error)
	StatOpenDirChild(xfsstore.Capability, string) (xfsstore.Attr, error)
	Chmod(xfsstore.Capability, fs.FileMode) error
	Chown(xfsstore.Capability, int, int) error
	SetTimes(xfsstore.Capability, *int64, *int64, bool, bool) error
	TruncateObject(xfsstore.Capability, int64) error
	GetXattr(xfsstore.Capability, string) ([]byte, error)
	SetXattr(xfsstore.Capability, string, []byte, xfsstore.XattrMode) error
	RemoveXattr(xfsstore.Capability, string) error
	ListXattr(xfsstore.Capability) ([]string, error)
	StatFS() (xfsstore.FSStat, error)
	Create(xfsstore.Capability, string, fs.FileMode, bool) (xfsstore.Capability, xfsstore.Attr, error)
	Mkdir(xfsstore.Capability, string, fs.FileMode) (xfsstore.Capability, xfsstore.Attr, error)
	Symlink(xfsstore.Capability, string, string) (xfsstore.Capability, xfsstore.Attr, error)
	Readlink(xfsstore.Capability) (string, error)
	Unlink(xfsstore.Capability, string, bool) error
	Rename(xfsstore.Capability, string, xfsstore.Capability, string, xfsstore.RenameFlags) error
	Link(xfsstore.Capability, xfsstore.Capability, string) (xfsstore.Attr, error)
}

type VolumeHandler struct {
	Store       volumeStore
	Runtime     *volumeserver.Authority
	Authorizer  Authorizer
	MaxFrame    uint32
	MaxRead     uint32
	MaxWrite    uint32
	MaxInFlight uint32
	// Descriptor-backed capabilities have independent per-session and
	// per-worker admission bounds. These limits exclude the one shared root
	// descriptor owned by xfsstore.
	MaxItemsPerSession uint32
	MaxOpensPerSession uint32
	MaxItems           uint32
	MaxOpens           uint32
	// MaxRetainedReplyBytes bounds the real quantity the replay cache consumes:
	// the total encoded bytes retained across every live session's replay
	// slots. Slot counts are not a proxy for it; one directory listing is five
	// orders of magnitude larger than one create.
	MaxRetainedReplyBytes uint64
	// Visibility coordinates frontends that explicitly declare strict kernel
	// caches. Uncached Linux mounts do not join its barrier.
	Visibility *volumeserver.VisibilityCoordinator
	// Routes owns the volume's active machine-local routing revision. It is
	// required: a volume with no loaded revision cannot tell an agreeing mount
	// from a disagreeing one, and admitting mounts in that state is exactly the
	// silent topology skew this exists to prevent.
	Routes *RoutesController
	// OnStorageFailure is called once after an EIO fences the store. Production
	// uses it to terminate this epoch instead of remaining deceptively ready.
	OnStorageFailure   func(error)
	OnCoherenceFailure func(error)

	cleanupOnce          sync.Once
	storageFailureOnce   sync.Once
	coherenceFailureOnce sync.Once
	resourcesMu          sync.Mutex
	resources            map[volumeserver.SessionID]*sessionResources
	totalItems           uint32
	totalOpens           uint32
	// retainedReplyBytes is the exact number of bytes currently held in replay
	// slots; reservedReplyBytes covers mutations that are executing and whose
	// reply size is not yet known.
	retainedReplyBytes uint64
	reservedReplyBytes uint64
}

type sessionResources struct {
	ended bool
	// root is the one shared volume-root capability. It is owned by xfsstore,
	// not by this session, so it is never forgotten during cleanup.
	root xfsstore.Capability
	// items and opens map a capability this session holds to whether it is
	// inside the protected .portablefs/ namespace. Protection is a property of
	// the capability rather than of a path because a path is not what the
	// protocol carries; see protected_linux.go.
	items map[xfsstore.Capability]bool
	opens map[xfsstore.Capability]bool
	// Reservations are capacity already charged to this session for an
	// operation that has not reached XFS yet. Charging before apply is what
	// makes admission refusal a definite, retryable outcome: Create/Mkdir/
	// Symlink and truncating Open may not discover a full descriptor table
	// after they have changed durable state.
	reservedItems uint32
	reservedOpens uint32
	// reply holds the retained reply size for each of this session's replay
	// slots. Its length is the slot count the runtime admitted.
	reply     []uint32
	coherence volumeserver.CoherenceProfile
	// routes is the machine-local routing revision this session was admitted
	// against. It is held here, by the authority, rather than echoed on each
	// request: a mount cannot present agreement it does not have, and a routing
	// change makes every session whose revision is no longer active refuse its
	// next request without any extra field on the wire.
	routes [32]byte
}

type trackedCapability struct {
	value     xfsstore.Capability
	protected bool
}

// capabilityReservation owns descriptor-table capacity from immediately
// before an operation reaches xfsstore until the returned capabilities are
// atomically installed in the session sets. totalItems/totalOpens include both
// live capabilities and these reservations, so the worker-wide bound cannot be
// oversubscribed by concurrent applies.
type capabilityReservation struct {
	h         *VolumeHandler
	id        volumeserver.SessionID
	resources *sessionResources
	items     uint32
	opens     uint32
	active    bool
}

// Epoch implements Handler. It is what the transport stamps on any response it
// has to synthesize itself.
func (h *VolumeHandler) Epoch() []byte {
	if h.Runtime == nil {
		return nil
	}
	epoch := h.Runtime.Epoch()
	return append([]byte(nil), epoch[:]...)
}

// Bounds implements Handler. These are exactly the values advertised in Hello,
// so the server refuses to run with a transport that enforces anything else.
func (h *VolumeHandler) Bounds() TransportBounds {
	request := uint64(h.MaxWrite) + uint64(FramePayloadReserve)
	if request > uint64(h.MaxFrame) {
		request = uint64(h.MaxFrame)
	}
	return TransportBounds{MaxFrame: h.MaxFrame, MaxRequestFrame: uint32(request), MaxInFlight: int(h.MaxInFlight)}
}

// maxReplyBytes is the largest operation reply this authority can both retain
// and put on the wire: whatever fits in a frame once the response envelope the
// transport adds back is accounted for.
func (h *VolumeHandler) maxReplyBytes() uint32 { return h.MaxFrame - responseEnvelopeReserve }

func (h *VolumeHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	if h.Runtime != nil {
		h.cleanupOnce.Do(func() { h.Runtime.OnSessionEnd(h.closeSessionResources) })
	}
	if req == nil {
		return h.errorResponse(0, fs.ErrInvalid, false)
	}
	// This is an authority trust boundary, not merely a daemon assertion. A
	// mount credential authenticates the caller but does not entitle it to mark
	// arbitrary requests safe to queue behind an own-source visibility phase.
	if !validSourcePhaseQueueability(req) {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	if hello := req.GetHello(); hello != nil {
		return h.hello(req.GetRequestId(), hello)
	}
	if attach := req.GetAttach(); attach != nil {
		return h.attach(ctx, req.GetRequestId(), attach)
	}
	if h.Store == nil || h.Runtime == nil || h.Authorizer == nil || h.Routes == nil {
		return h.errorResponse(req.GetRequestId(), errInternal, false)
	}
	if req.GetCancel() != nil {
		return h.cancelAcknowledgment(ctx, req)
	}
	cred, err := h.credential(ctx, req)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	if reauthorize := req.GetReauthorize(); reauthorize != nil {
		verifier, ok := h.Authorizer.(Reauthorizer)
		if !ok || reauthorize.GetSequence() == 0 || len(reauthorize.GetAccessToken()) == 0 {
			return h.errorResponse(req.GetRequestId(), syscall.EOPNOTSUPP, false)
		}
		authorization, proof, err := verifier.Reauthorize(ctx, h.Runtime.VolumeID(), cred.ID, reauthorize.GetSequence(), reauthorize.GetAccessToken())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.Runtime.Reauthorize(cred, authorization, reauthorize.GetSequence(), proof); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_Reauthorize{Reauthorize: &authoritypb.ReauthorizeReply{
			Sequence: reauthorize.GetSequence(), AuthorizationDeadlineUnixNanos: authorization.Deadline.UnixNano(),
		}}
		return resp
	}
	use, err := h.Runtime.Begin(cred)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	defer use.End()
	access := use.Access()
	if access&volumeserver.AccessRead == 0 {
		return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
	}
	if requestRequiresWrite(req) && access&volumeserver.AccessWrite == 0 {
		return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
	}
	if requestRequiresAdmin(req) && access&volumeserver.AccessAdmin == 0 {
		return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
	}
	topologyAdmitted := false
	if requestUsesTopology(req) {
		// Admission and execution are one topology critical section. Without this,
		// an old-revision request can pass the check below, pause while ApplyRoutes
		// commits, and then reach XFS under the topology the frontend used before
		// the switch.
		guard, err := h.beginTopologyRequest(cred.ID)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		defer guard.Release()
		topologyAdmitted = true
	}
	// A routing change makes every session that was admitted against the old
	// revision refuse from here on. The comparison is against what this
	// authority recorded at attach, not against anything the peer sends now, so
	// a mount cannot present agreement it does not have; and ApplyRoutes holds
	// the barrier's registration write side across the switch, so no request can
	// straddle it.
	//
	// Four bodies are exempt, all because the gate would be answering a question
	// they do not ask. A mount being refused still has to be able to leave the
	// barrier cleanly, and leaving cannot skew a topology. ApplyRoutes is not
	// a filesystem operation under a topology at all: it carries its own
	// compare-and-swap against the active revision, which is a stricter check
	// than this one, so gating it here would only force an administrator to
	// remount between two changes. And the visibility stream is barrier
	// control, not filesystem work: the barrier that installs a new revision
	// still needs its participants' acknowledgments and blocked reports after
	// the commit point, so refusing them here would convert every routing
	// change into one full repair-budget stall per strict participant.
	if !topologyAdmitted && req.GetDetach() == nil && req.GetApplyRoutes() == nil &&
		req.GetNextVisibility() == nil && req.GetAckVisibility() == nil {
		if err := h.admitSessionRoutes(cred.ID); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
	}
	// .portablefs/ is refused to mounts entirely for mutation. It is checked
	// once, here, rather than inside each operation, so a mutating body cannot
	// be added with its own idea of what is protected.
	if err := h.refuseProtectedNamespace(cred.ID, req); err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}

	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Resume, *authoritypb.Request_KeepAlive:
		if err := h.Runtime.Resume(cred); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_Detach:
		profile, err := h.sessionCoherence(cred.ID)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if profile == volumeserver.CoherenceStrict {
			// credential() authenticated this request as cred.ID and DetachRequest
			// contains no caller-selected session. CleanDetach therefore trusts
			// only the official supervisor for this exact mount. A frontend that
			// cannot establish terminal kernel state sends no observation and lets
			// the session die fenced, leaving durable membership active.
			if h.Visibility == nil {
				return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
			}
			if err := h.Visibility.CleanDetach(cred.ID, mountAbsenceProof(body.Detach.GetMountAbsence())); err != nil {
				return h.errorResponse(req.GetRequestId(), err, false)
			}
		}
		if err := h.Runtime.Detach(cred); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_NextVisibility:
		if h.Visibility == nil || !h.strictSession(cred.ID) {
			return h.errorResponse(req.GetRequestId(), syscall.EOPNOTSUPP, false)
		}
		cursor, err := visibilityCursor(body.NextVisibility.GetAfter())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		event, err := h.Visibility.Next(ctx, cred.ID, cursor)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_Visibility{Visibility: visibilityEventProto(event)}
		return resp
	case *authoritypb.Request_AckVisibility:
		if h.Visibility == nil || !h.strictSession(cred.ID) {
			return h.errorResponse(req.GetRequestId(), syscall.EOPNOTSUPP, false)
		}
		cursor, err := visibilityCursor(body.AckVisibility.GetCursor())
		if err != nil || cursor == (volumeserver.VisibilityCursor{}) {
			return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
		}
		if body.AckVisibility.GetBlocked() {
			// For an ordinary parent-exclusive namespace COMPLETE, this installs
			// a scoped pre-apply interruption and the same mount goes on to repair
			// and Ack. A routes report remains terminal because topology cannot be
			// repaired by releasing one kernel parent lock.
			if err := h.Visibility.ReportBlocked(ctx, cred.ID, cursor, body.AckVisibility.GetBlockedParentKernelInos()); err != nil {
				return h.errorResponse(req.GetRequestId(), err, false)
			}
			return h.success(req.GetRequestId())
		}
		if err := h.Visibility.AckWithContention(cred.ID, cursor, body.AckVisibility.GetOrderedAdmissionContended()); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_ApplyRoutes:
		expected, err := routesRevision(body.ApplyRoutes.GetExpectedRevision())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		// ApplyRoutes deliberately does not take a replay slot. Its identity is
		// the compare-and-swap: re-submitting an applied change finds the
		// expected revision no longer active and comes back naming the one that
		// is, which is a more useful answer than a retained reply and needs no
		// per-session slot bookkeeping in an admin tool.
		reply, err := h.Routes.Apply(ctx, body.ApplyRoutes.GetRules(), expected)
		if err != nil {
			var barrier *volumeserver.VisibilityBarrierError
			uncertain := errors.As(err, &barrier) && barrier.Applied
			return h.errorResponse(req.GetRequestId(), err, uncertain)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_ApplyRoutes{ApplyRoutes: reply}
		return resp
	case *authoritypb.Request_Lookup:
		// Lookup allocates and transfers an authority item capability. It is
		// read-only in XFS, but not side-effect-free in this session: replaying a
		// response lost after trackItem would allocate a second unreachable
		// capability. Exact replay therefore owns the transfer just as it owns an
		// Open handle; the frontend's later Reclaim retires it idempotently.
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			parent, err := h.item(cred.ID, body.Lookup.GetParent())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			// Resolving a name under the protected namespace is the only way a
			// capability inside it can enter this session, so it is the only place
			// the mark has to be applied for the set to be closed at every depth.
			protected := h.protectedChild(cred.ID, parent, body.Lookup.GetName())
			item, attr, err := h.lookupForSession(ctx, cred.ID, parent, body.Lookup.GetName())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if err := h.trackItem(cred.ID, item, protected); err != nil {
				return h.errorResponse(0, err, false)
			}
			identity, err := h.Store.Identity(item)
			if err != nil {
				h.untrackItem(cred.ID, item)
				h.forgetItem(item)
				return h.errorResponse(0, err, false)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemProto(item, attr, identity)}}
			return resp
		})
	case *authoritypb.Request_GetAttr:
		attr, err := h.getattr(ctx, cred.ID, body.GetAttr)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: attrProto(attr)}}
		return resp
	case *authoritypb.Request_SetAttr:
		set := body.SetAttr
		var item, handle xfsstore.Capability
		var coordinate visibilityCoordinate
		var mode fs.FileMode
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			if set.Mode == nil && set.Uid == nil && set.Gid == nil && set.Size == nil && set.AtimeNs == nil && set.MtimeNs == nil && !set.GetAtimeNow() && !set.GetMtimeNow() {
				return nil, syscall.EINVAL
			}
			var err error
			if len(set.GetItem()) != 0 {
				item, err = h.item(cred.ID, set.GetItem())
				if err != nil {
					return nil, err
				}
			}
			if len(set.GetHandle()) != 0 {
				handle, err = h.open(cred.ID, set.GetHandle())
				if err != nil {
					return nil, err
				}
			}
			if item == (xfsstore.Capability{}) && handle == (xfsstore.Capability{}) {
				return nil, syscall.EINVAL
			}
			if set.Mode != nil {
				var valid bool
				mode, valid = modeFromProtocol(set.GetMode())
				if !valid || item == (xfsstore.Capability{}) {
					return nil, syscall.EINVAL
				}
			}
			if (set.Uid != nil || set.Gid != nil) && (item == (xfsstore.Capability{}) ||
				(set.Uid != nil && set.GetUid() == ^uint32(0)) || (set.Gid != nil && set.GetGid() == ^uint32(0))) {
				return nil, syscall.EINVAL
			}
			if set.Size != nil && set.GetSize() < 0 {
				return nil, syscall.EINVAL
			}
			if set.AtimeNs != nil && set.GetAtimeNow() || set.MtimeNs != nil && set.GetMtimeNow() {
				return nil, syscall.EINVAL
			}
			if (set.AtimeNs != nil || set.MtimeNs != nil || set.GetAtimeNow() || set.GetMtimeNow()) && item == (xfsstore.Capability{}) {
				return nil, syscall.EINVAL
			}
			if handle != (xfsstore.Capability{}) {
				coordinate, err = h.coordinateOpen(handle)
			} else {
				coordinate, err = h.coordinateItem(item)
			}
			if err != nil {
				return nil, err
			}
			targets := []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
			if set.Size != nil {
				targets = append(targets, inodeTarget(volumeserver.VisibilityData, coordinate, set.GetSize()))
			}
			return targets, nil
		}
		completeTargets := func() []volumeserver.VisibilityTarget {
			var attr xfsstore.Attr
			var err error
			if handle != (xfsstore.Capability{}) {
				attr, err = h.Store.GetattrOpen(handle)
			} else {
				attr, err = h.Store.Getattr(item)
			}
			if err != nil {
				return []volumeserver.VisibilityTarget{}
			}
			targets := []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
			if set.Size != nil {
				targets = append(targets, inodeTarget(volumeserver.VisibilityData, coordinate, attr.Size))
			}
			return targets
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			changed := false
			var err error
			if set.Mode != nil {
				err = h.Store.Chmod(item, mode)
				if err != nil {
					return h.errorResponse(0, err, changed), completeTargets()
				}
				changed = true
			}
			if set.Uid != nil || set.Gid != nil {
				uid, gid := -1, -1
				if set.Uid != nil {
					uid = int(set.GetUid())
				}
				if set.Gid != nil {
					gid = int(set.GetGid())
				}
				err = h.Store.Chown(item, uid, gid)
				if err != nil {
					return h.errorResponse(0, err, changed), completeTargets()
				}
				changed = true
			}
			if set.Size != nil {
				if handle != (xfsstore.Capability{}) {
					err = h.Store.Truncate(handle, set.GetSize())
				} else {
					err = h.Store.TruncateObject(item, set.GetSize())
				}
				if err != nil {
					return h.errorResponse(0, err, changed), completeTargets()
				}
				changed = true
			}
			if set.AtimeNs != nil || set.MtimeNs != nil || set.GetAtimeNow() || set.GetMtimeNow() {
				err = h.Store.SetTimes(item, set.AtimeNs, set.MtimeNs, set.GetAtimeNow(), set.GetMtimeNow())
				if err != nil {
					return h.errorResponse(0, err, changed), completeTargets()
				}
				changed = true
			}
			var attr xfsstore.Attr
			if handle != (xfsstore.Capability{}) {
				attr, err = h.Store.GetattrOpen(handle)
			} else {
				attr, err = h.Store.Getattr(item)
			}
			if err != nil {
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			resp := h.success(0)
			resp.PostAttr = attrProto(attr)
			return resp, completeTargets()
		})
	case *authoritypb.Request_Create:
		var parent xfsstore.Capability
		var parentCoordinate, existingCoordinate visibilityCoordinate
		var existingSize int64
		var existed bool
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Create.GetName()); err != nil {
				return nil, err
			}
			var err error
			parent, err = h.item(cred.ID, body.Create.GetParent())
			if err != nil {
				return nil, err
			}
			parentCoordinate, err = h.coordinateItem(parent)
			if err != nil {
				return nil, err
			}
			existingCoordinate, existingSize, existed, err = h.lookupCoordinateSizeOptional(parent, body.Create.GetName())
			if err != nil {
				return nil, err
			}
			if !existed {
				return []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Create.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}, nil
			}
			// Opening an existing name does not mutate its parent or binding. Keep
			// the unavoidable replay-ordered no-op barrier scoped to the existing
			// inode; O_TRUNC adds data, while a plain existing create completes with
			// no targets and therefore performs no peer repair.
			targets := []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, existingCoordinate, 0)}
			if body.Create.GetFlags() != nil && body.Create.GetFlags().GetTruncate() {
				targets = append([]volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, existingCoordinate, existingSize)}, targets...)
			}
			return targets, nil
		}
		createdTargets := func(item xfsstore.Capability) []volumeserver.VisibilityTarget {
			if !existed {
				return []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Create.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
			}
			if body.Create.GetFlags() == nil || !body.Create.GetFlags().GetTruncate() {
				return nil
			}
			attr, err := h.Store.Getattr(item)
			if err != nil {
				return []volumeserver.VisibilityTarget{}
			}
			return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, existingCoordinate, attr.Size), inodeTarget(volumeserver.VisibilityAttributes, existingCoordinate, 0)}
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			mode, valid := modeFromProtocol(body.Create.GetMode())
			if !valid {
				return h.errorResponse(0, syscall.EINVAL, false), nil
			}
			reservation, err := h.reserveCapabilities(cred.ID, 1, 1)
			if err != nil {
				return h.errorResponse(0, err, false), nil
			}
			defer reservation.release()
			item, attr, err := h.Store.Create(parent, string(body.Create.GetName()), mode, body.Create.GetExclusive())
			if err != nil {
				resp := h.errorResponse(0, err, false)
				return resp, uncertainVisibilityTargets(resp, createdTargets(xfsstore.Capability{}))
			}
			handle, err := h.Store.OpenFile(item, openFlags(body.Create.GetFlags()))
			if err != nil {
				targets := createdTargets(item)
				h.forgetItem(item)
				return h.errorResponse(0, err, targets != nil), targets
			}
			if err := reservation.commit(
				[]trackedCapability{{value: item}},
				[]trackedCapability{{value: handle}},
			); err != nil {
				targets := createdTargets(item)
				h.closeOpen(handle)
				h.forgetItem(item)
				return h.errorResponse(0, err, targets != nil), targets
			}
			cleanupUndeliverable := func() {
				h.untrackOpen(cred.ID, handle)
				h.closeOpen(handle)
				h.untrackItem(cred.ID, item)
				h.forgetItem(item)
			}
			if body.Create.GetFlags() != nil && body.Create.GetFlags().GetTruncate() {
				post, err := h.Store.GetattrOpen(handle)
				if err != nil {
					targets := createdTargets(item)
					cleanupUndeliverable()
					return h.errorResponse(0, err, true), targets
				}
				attr = post
			}
			itemIdentity, identityErr := h.Store.Identity(item)
			if identityErr != nil {
				targets := createdTargets(item)
				cleanupUndeliverable()
				return h.errorResponse(0, identityErr, true), targets
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: itemProto(item, attr, itemIdentity), Handle: handle[:]}}
			if existed {
				if body.Create.GetFlags() == nil || !body.Create.GetFlags().GetTruncate() {
					return resp, nil
				}
				return resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, existingCoordinate, attr.Size), inodeTarget(volumeserver.VisibilityAttributes, existingCoordinate, 0)}
			}
			return resp, []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Create.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
		})
	case *authoritypb.Request_Mkdir:
		var parent xfsstore.Capability
		var parentCoordinate visibilityCoordinate
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Mkdir.GetName()); err != nil {
				return nil, err
			}
			var err error
			parent, err = h.item(cred.ID, body.Mkdir.GetParent())
			if err == nil {
				parentCoordinate, err = h.coordinateItem(parent)
			}
			return []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Mkdir.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}, err
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			mode, valid := modeFromProtocol(body.Mkdir.GetMode())
			if !valid {
				return h.errorResponse(0, syscall.EINVAL, false), nil
			}
			reservation, err := h.reserveCapabilities(cred.ID, 1, 0)
			if err != nil {
				return h.errorResponse(0, err, false), nil
			}
			defer reservation.release()
			item, attr, err := h.Store.Mkdir(parent, string(body.Mkdir.GetName()), mode)
			if err != nil {
				resp := h.errorResponse(0, err, false)
				targets := []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Mkdir.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
				return resp, uncertainVisibilityTargets(resp, targets)
			}
			if err := reservation.commit([]trackedCapability{{value: item}}, nil); err != nil {
				h.forgetItem(item)
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Mkdir.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
			}
			itemIdentity, identityErr := h.Store.Identity(item)
			if identityErr != nil {
				h.untrackItem(cred.ID, item)
				h.forgetItem(item)
				return h.errorResponse(0, identityErr, true), []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Mkdir.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemProto(item, attr, itemIdentity)}}
			return resp, []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Mkdir.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
		})
	case *authoritypb.Request_Unlink:
		var parent xfsstore.Capability
		var parentCoordinate, removedCoordinate visibilityCoordinate
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Unlink.GetName()); err != nil {
				return nil, err
			}
			var err error
			parent, err = h.item(cred.ID, body.Unlink.GetParent())
			if err == nil {
				parentCoordinate, err = h.coordinateItem(parent)
			}
			if err == nil {
				removedCoordinate, _, err = h.lookupCoordinate(parent, body.Unlink.GetName())
			}
			return []volumeserver.VisibilityTarget{namespaceTargetRelated(parentCoordinate, body.Unlink.GetName(), removedCoordinate), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0), inodeTarget(volumeserver.VisibilityAttributes, removedCoordinate, 0)}, err
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			if err := h.Store.Unlink(parent, string(body.Unlink.GetName()), body.Unlink.GetDirectory()); err != nil {
				resp := h.errorResponse(0, err, false)
				targets := []volumeserver.VisibilityTarget{namespaceTargetRelated(parentCoordinate, body.Unlink.GetName(), removedCoordinate), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0), inodeTarget(volumeserver.VisibilityAttributes, removedCoordinate, 0)}
				return resp, uncertainVisibilityTargets(resp, targets)
			}
			targets := []volumeserver.VisibilityTarget{namespaceTargetRelated(parentCoordinate, body.Unlink.GetName(), removedCoordinate), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0), inodeTarget(volumeserver.VisibilityAttributes, removedCoordinate, 0)}
			return h.success(0), targets
		})
	case *authoritypb.Request_Rename:
		var oldParent, newParent xfsstore.Capability
		var oldParentCoordinate, newParentCoordinate, movedCoordinate, replacedCoordinate visibilityCoordinate
		var replaced bool
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Rename.GetOldName()); err != nil {
				return nil, err
			}
			if err := namespaceName(body.Rename.GetNewName()); err != nil {
				return nil, err
			}
			var err error
			oldParent, err = h.item(cred.ID, body.Rename.GetOldParent())
			if err == nil {
				newParent, err = h.item(cred.ID, body.Rename.GetNewParent())
			}
			if err == nil {
				oldParentCoordinate, err = h.coordinateItem(oldParent)
			}
			if err == nil {
				newParentCoordinate, err = h.coordinateItem(newParent)
			}
			if err == nil {
				movedCoordinate, _, err = h.lookupCoordinate(oldParent, body.Rename.GetOldName())
			}
			if err == nil {
				replacedCoordinate, replaced, err = h.lookupCoordinateOptional(newParent, body.Rename.GetNewName())
			}
			targets := renameVisibilityTargets(body.Rename, oldParentCoordinate, newParentCoordinate, movedCoordinate, replacedCoordinate, replaced, false)
			return targets, err
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			var flags xfsstore.RenameFlags
			if body.Rename.GetNoReplace() {
				flags |= xfsstore.RenameNoReplace
			}
			if body.Rename.GetExchange() {
				flags |= xfsstore.RenameExchange
			}
			if err := h.Store.Rename(oldParent, string(body.Rename.GetOldName()), newParent, string(body.Rename.GetNewName()), flags); err != nil {
				resp := h.errorResponse(0, err, false)
				return resp, uncertainVisibilityTargets(resp, renameVisibilityTargets(body.Rename, oldParentCoordinate, newParentCoordinate, movedCoordinate, replacedCoordinate, replaced, false))
			}
			return h.success(0), renameVisibilityTargets(body.Rename, oldParentCoordinate, newParentCoordinate, movedCoordinate, replacedCoordinate, replaced, true)
		})
	case *authoritypb.Request_Link:
		var source, parent xfsstore.Capability
		var sourceCoordinate, parentCoordinate visibilityCoordinate
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Link.GetNewName()); err != nil {
				return nil, err
			}
			var err error
			source, err = h.item(cred.ID, body.Link.GetExistingItem())
			if err == nil {
				parent, err = h.item(cred.ID, body.Link.GetNewParent())
			}
			if err == nil {
				sourceCoordinate, err = h.coordinateItem(source)
			}
			if err == nil {
				parentCoordinate, err = h.coordinateItem(parent)
			}
			return linkVisibilityTargets(body.Link.GetNewName(), parentCoordinate, sourceCoordinate, false), err
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			attr, err := h.Store.Link(source, parent, string(body.Link.GetNewName()))
			if err != nil {
				resp := h.errorResponse(0, err, false)
				targets := linkVisibilityTargets(body.Link.GetNewName(), parentCoordinate, sourceCoordinate, false)
				return resp, uncertainVisibilityTargets(resp, targets)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Link{Link: &authoritypb.LinkReply{Item: itemProto(source, attr, sourceCoordinate.identity)}}
			targets := linkVisibilityTargets(body.Link.GetNewName(), parentCoordinate, sourceCoordinate, true)
			return resp, targets
		})
	case *authoritypb.Request_Symlink:
		var parent xfsstore.Capability
		var parentCoordinate visibilityCoordinate
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Symlink.GetName()); err != nil {
				return nil, err
			}
			var err error
			parent, err = h.item(cred.ID, body.Symlink.GetParent())
			if err == nil {
				parentCoordinate, err = h.coordinateItem(parent)
			}
			return []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Symlink.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}, err
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			reservation, err := h.reserveCapabilities(cred.ID, 1, 0)
			if err != nil {
				return h.errorResponse(0, err, false), nil
			}
			defer reservation.release()
			item, attr, err := h.Store.Symlink(parent, string(body.Symlink.GetName()), string(body.Symlink.GetTarget()))
			if err != nil {
				resp := h.errorResponse(0, err, false)
				targets := []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Symlink.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
				return resp, uncertainVisibilityTargets(resp, targets)
			}
			if err := reservation.commit([]trackedCapability{{value: item}}, nil); err != nil {
				h.forgetItem(item)
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Symlink.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
			}
			itemIdentity, identityErr := h.Store.Identity(item)
			if identityErr != nil {
				h.untrackItem(cred.ID, item)
				h.forgetItem(item)
				return h.errorResponse(0, identityErr, true), []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Symlink.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemProto(item, attr, itemIdentity)}}
			return resp, []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Symlink.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
		})
	case *authoritypb.Request_Readlink:
		item, err := h.item(cred.ID, body.Readlink.GetItem())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.stabilizeItem(ctx, cred.ID, item); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		target, err := h.Store.Readlink(item)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_Readlink{Readlink: &authoritypb.ReadlinkReply{Target: []byte(target)}}
		return resp
	case *authoritypb.Request_Open:
		var openedHandle xfsstore.Capability
		cleanupOpenedHandle := func() {
			if openedHandle == (xfsstore.Capability{}) {
				return
			}
			h.untrackOpen(cred.ID, openedHandle)
			h.closeOpen(openedHandle)
			openedHandle = xfsstore.Capability{}
		}
		openApply := func(item xfsstore.Capability) *authoritypb.Response {
			// A handle inherits its object's protection, so a read-only open of
			// the declaration cannot be turned into a write by presenting the
			// handle in place of the item.
			protected := h.protectedCapability(cred.ID, item)
			reservation, err := h.reserveCapabilities(cred.ID, 0, 1)
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			defer reservation.release()
			handle, err := h.Store.OpenFile(item, openFlags(body.Open.GetFlags()))
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if err := reservation.commit(nil, []trackedCapability{{value: handle, protected: protected}}); err != nil {
				h.closeOpen(handle)
				uncertain := body.Open.GetFlags() != nil && body.Open.GetFlags().GetTruncate()
				return h.errorResponse(0, err, uncertain)
			}
			openedHandle = handle
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: handle[:]}}
			return resp
		}
		if body.Open.GetFlags() == nil || !body.Open.GetFlags().GetTruncate() {
			return h.mutate(ctx, req, cred, func() *authoritypb.Response {
				item, err := h.item(cred.ID, body.Open.GetItem())
				if err != nil {
					return h.errorResponse(0, err, false)
				}
				return openApply(item)
			})
		}
		var item xfsstore.Capability
		var coordinate visibilityCoordinate
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			var err error
			item, err = h.item(cred.ID, body.Open.GetItem())
			if err == nil {
				coordinate, err = h.coordinateItem(item)
			}
			return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, coordinate, 0), inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}, err
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			resp := openApply(item)
			if !visibilityChanged(resp) {
				return resp, nil
			}
			attr, err := h.Store.Getattr(item)
			if err != nil {
				cleanupOpenedHandle()
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			return resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, coordinate, attr.Size), inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
		})
	case *authoritypb.Request_Close:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			handle, err := h.open(cred.ID, body.Close.GetHandle())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if body.Close.GetFlockUnlock() {
				if err := h.unlockOpenOwner(cred, handle, body.Close.GetLockOwner(), true); err != nil {
					return h.errorResponse(0, err, false)
				}
			}
			if err := h.Store.CloseOpen(handle); err != nil {
				return h.errorResponse(0, err, false)
			}
			h.untrackOpen(cred.ID, handle)
			return h.success(0)
		})
	case *authoritypb.Request_Flush:
		handle, err := h.open(cred.ID, body.Flush.GetHandle())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.unlockOpenOwner(cred, handle, body.Flush.GetLockOwner(), false); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_Read:
		if body.Read.GetLength() > h.MaxRead {
			return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
		}
		handle, err := h.open(cred.ID, body.Read.GetHandle())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.stabilizeOpen(ctx, cred.ID, handle); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		buf := make([]byte, body.Read.GetLength())
		n, err := h.Store.ReadAt(handle, buf, int64(body.Read.GetOffset()))
		if err != nil && !errors.Is(err, io.EOF) {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_Read{Read: &authoritypb.ReadReply{Data: buf[:n]}}
		return resp
	case *authoritypb.Request_Write:
		if uint32(len(body.Write.GetData())) > h.MaxWrite {
			return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
		}
		var handle xfsstore.Capability
		var coordinate visibilityCoordinate
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			if body.Write.GetAppend() && body.Write.GetOffset() != 0 {
				return nil, syscall.EINVAL
			}
			var err error
			handle, err = h.open(cred.ID, body.Write.GetHandle())
			if err != nil {
				return nil, err
			}
			identity, err := h.Store.IdentityOpen(handle)
			if err != nil {
				return nil, err
			}
			attr, err := h.Store.GetattrOpen(handle)
			coordinate = attrCoordinate(identity, attr)
			return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, coordinate, attr.Size), inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}, err
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			var err error
			var n int
			var assigned int64
			if body.Write.GetAppend() {
				n, assigned, err = h.Store.Append(handle, body.Write.GetData())
			} else {
				n, err = h.Store.WriteAt(handle, body.Write.GetData(), int64(body.Write.GetOffset()))
			}
			resp := h.writeOutcome(n, assigned, err)
			if visibilityChanged(resp) {
				// A positive short count is already authoritative XFS progress even
				// when the store then dies. COMPLETE must carry the actual resulting
				// EOF; protobuf's default zero is not evidence and would let a peer
				// truncate its cached object incorrectly. Failure to read EOF after
				// apply returns an empty completion, which poisons the epoch closed.
				attr, attrErr := h.Store.GetattrOpen(handle)
				if attrErr != nil {
					if n != 0 || resp.GetUncertain() {
						return h.errorResponse(0, attrErr, true), []volumeserver.VisibilityTarget{}
					}
					return h.errorResponse(0, attrErr, false), nil
				}
				resp.PostAttr = attrProto(attr)
			}
			if !visibilityChanged(resp) {
				return resp, nil
			}
			return resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, coordinate, resp.GetPostAttr().GetSize()), inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
		})
	case *authoritypb.Request_Fsync:
		handle, err := h.open(cred.ID, body.Fsync.GetHandle())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.Store.Fsync(handle, body.Fsync.GetDataOnly()); err != nil {
			return h.errorResponse(req.GetRequestId(), err, true)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_ReadDir:
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			if body.ReadDir.GetMaxEntries() == 0 || body.ReadDir.GetMaxEntries() > 4096 {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			handle, err := h.open(cred.ID, body.ReadDir.GetHandle())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			cookie, err := decodeCookie(body.ReadDir.GetCookie())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			var verifier [16]byte
			if len(body.ReadDir.GetVerifier()) != 0 {
				if len(body.ReadDir.GetVerifier()) != len(verifier) {
					return h.errorResponse(0, syscall.EINVAL, false)
				}
				copy(verifier[:], body.ReadDir.GetVerifier())
			}
			var entries []xfsstore.Dirent
			var current [16]byte
			var eof bool
			var directory xfsstore.Capability
			result := &authoritypb.ReadDirReply{}
			// The reply is built to the same byte budget that was reserved for
			// it, so a directory listing can never be the reply that does not
			// fit in a frame. Stopping early is an ordinary short readdir: the
			// caller resumes from the last entry's cookie.
			budget := h.readDirEntryBudget(body.ReadDir.GetMaxEntries())
			used := uint64(0)
			type issuedItem struct {
				item xfsstore.Capability
				name []byte
			}
			var issued []issuedItem
			forgetIssued := func() {
				for _, held := range issued {
					h.forgetItem(held.item)
				}
				issued = nil
			}
			budgetExhausted := false
			// A page carries at least one entry unless it is the final one: an
			// empty non-final page advances no client cursor, so a batch whose
			// every entry raced away is skipped over rather than published.
			for batch := 0; ; batch++ {
				// An enumeration is the one read that learns its own coordinates by
				// reading. A page that raced a mutation on any of them is discarded
				// and re-enumerated rather than published.
				for attempt := 0; ; attempt++ {
					entries, _, current, eof, directory, err = h.Store.ReadDirOpen(handle, cookie, verifier, int(body.ReadDir.GetMaxEntries()))
					if err != nil {
						forgetIssued()
						return h.errorResponse(0, err, false)
					}
					waited, err := h.stabilizeDirectoryPage(ctx, cred.ID, handle, directory, entries)
					if err != nil {
						forgetIssued()
						return h.errorResponse(0, err, false)
					}
					if !waited {
						break
					}
					if attempt+1 >= maxStabilizeAttempts {
						forgetIssued()
						return h.errorResponse(0, syscall.EAGAIN, false)
					}
				}
				result.Verifier, result.Eof = current[:], eof
				for i, entry := range entries {
					nextCookie := encodeCookie(cookie + uint64(i) + 1)
					attr, statErr := h.Store.StatOpenDirChild(handle, entry.Name)
					if statErr != nil {
						switch {
						case errors.Is(statErr, syscall.ENOENT), errors.Is(statErr, xfsstore.ErrStaleObject):
							// The name was unlinked or renamed away between
							// enumeration and stat. Omitting it is the legal
							// after-state observation of that overlapping
							// mutation; failing the page would turn a peer's
							// ordinary churn into a readdir error, which no
							// local directory listing produces.
							continue
						case errors.Is(statErr, xfsstore.ErrForbiddenType), errors.Is(statErr, xfsstore.ErrProjectIsolation):
							// An inode this authority never exposes — a device
							// node, FIFO, socket, or foreign-owned inode some
							// other writer placed in the tree — is listed
							// opaquely with no capability, exactly as a local
							// readdir lists a name whose later stat fails. One
							// non-portable inode must not make the whole
							// directory unreadable.
							attr = xfsstore.Attr{Kind: xfsstore.KindOpaque, Ino: entry.Ino}
						default:
							forgetIssued()
							return h.errorResponse(0, statErr, false)
						}
					}
					dirent := &authoritypb.Dirent{Name: []byte(entry.Name), Attr: attrProto(attr), NextCookie: nextCookie}
					var candidate xfsstore.Capability
					if body.ReadDir.GetWantItems() && attr.Kind != xfsstore.KindOpaque {
						var itemAttr xfsstore.Attr
						candidate, itemAttr, err = h.lookupForSession(ctx, cred.ID, directory, []byte(entry.Name))
						switch {
						case errors.Is(err, syscall.ENOENT), errors.Is(err, xfsstore.ErrStaleObject):
							continue
						case errors.Is(err, xfsstore.ErrForbiddenType), errors.Is(err, xfsstore.ErrProjectIsolation):
							dirent.Attr = attrProto(xfsstore.Attr{Kind: xfsstore.KindOpaque, Ino: entry.Ino})
						case err != nil:
							forgetIssued()
							return h.errorResponse(0, err, false)
						case itemAttr.Ino != entry.Ino || itemAttr.Kind != entry.Kind:
							// Replaced between enumeration and lookup: neither
							// the enumerated binding nor its replacement is
							// this page's to publish. The replacement is the
							// next enumeration's ordinary entry.
							h.forgetItem(candidate)
							candidate = xfsstore.Capability{}
							continue
						default:
							dirent.Attr = attrProto(itemAttr)
							identity, identityErr := h.Store.Identity(candidate)
							if identityErr != nil {
								h.forgetItem(candidate)
								forgetIssued()
								return h.errorResponse(0, identityErr, false)
							}
							dirent.Item = itemProto(candidate, itemAttr, identity)
						}
					}
					cost := direntCost(dirent)
					if used+cost > uint64(budget) {
						if candidate != (xfsstore.Capability{}) && dirent.Item != nil {
							h.forgetItem(candidate)
						}
						result.Eof = false
						budgetExhausted = true
						break
					}
					used += cost
					result.Entries = append(result.Entries, dirent)
					if candidate != (xfsstore.Capability{}) && dirent.Item != nil {
						issued = append(issued, issuedItem{item: candidate, name: dirent.Name})
					}
				}
				if len(result.Entries) != 0 || result.Eof || budgetExhausted {
					break
				}
				if len(entries) == 0 {
					break
				}
				cookie += uint64(len(entries))
				if batch+1 >= maxSkippedReaddirBatches {
					forgetIssued()
					return h.errorResponse(0, syscall.EAGAIN, false)
				}
			}
			if budgetExhausted && len(result.Entries) == 0 {
				// A single entry larger than the whole budget would make this
				// directory unreadable at any cookie. Say so instead of
				// returning an empty page forever.
				forgetIssued()
				return h.errorResponse(0, syscall.EOVERFLOW, false)
			}
			parentAttr, err := h.Store.GetattrOpen(handle)
			if err != nil || !verifierMatches(current, parentAttr) {
				forgetIssued()
				return h.errorResponse(0, syscall.ESTALE, false)
			}
			tracked := 0
			for i, held := range issued {
				if err := h.trackItem(cred.ID, held.item, h.protectedChild(cred.ID, directory, held.name)); err != nil {
					for _, prior := range issued[:tracked] {
						h.untrackItem(cred.ID, prior.item)
						h.forgetItem(prior.item)
					}
					for _, unheld := range issued[i+1:] {
						h.forgetItem(unheld.item)
					}
					return h.errorResponse(0, err, false)
				}
				tracked++
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_ReadDir{ReadDir: result}
			return resp
		})
	case *authoritypb.Request_Reclaim:
		// Reclaim changes the session's retained-capability accounting. It must
		// use exact replay even though it does not change visible filesystem
		// state: if the first success reply is lost, re-executing a read-style
		// retry would resolve an already-retired capability as ESTALE.
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			item, err := h.item(cred.ID, body.Reclaim.GetItem())
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if err := h.Store.Forget(item); err != nil && !errors.Is(err, xfsstore.ErrStaleObject) {
				return h.errorResponse(0, err, false)
			}
			h.untrackItem(cred.ID, item)
			return h.success(0)
		})
	case *authoritypb.Request_GetXattr:
		item, err := h.item(cred.ID, body.GetXattr.GetItem())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.stabilizeItem(ctx, cred.ID, item); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		value, err := h.Store.GetXattr(item, string(body.GetXattr.GetName()))
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_GetXattr{GetXattr: &authoritypb.GetXattrReply{Value: value}}
		return resp
	case *authoritypb.Request_SetXattr:
		var item xfsstore.Capability
		var coordinate visibilityCoordinate
		var mode xfsstore.XattrMode
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			var valid bool
			mode, valid = xattrMode(body.SetXattr.GetMode())
			if !valid {
				return nil, syscall.EINVAL
			}
			var err error
			item, err = h.item(cred.ID, body.SetXattr.GetItem())
			if err == nil {
				coordinate, err = h.coordinateItem(item)
			}
			return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}, err
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			if err := h.Store.SetXattr(item, string(body.SetXattr.GetName()), body.SetXattr.GetValue(), mode); err != nil {
				resp := h.errorResponse(0, err, false)
				return resp, uncertainVisibilityTargets(resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)})
			}
			return h.success(0), []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
		})
	case *authoritypb.Request_RemoveXattr:
		var item xfsstore.Capability
		var coordinate visibilityCoordinate
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			var err error
			item, err = h.item(cred.ID, body.RemoveXattr.GetItem())
			if err == nil {
				coordinate, err = h.coordinateItem(item)
			}
			return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}, err
		}
		return h.mutateVisible(ctx, req, cred, prepare, func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			if err := h.Store.RemoveXattr(item, string(body.RemoveXattr.GetName())); err != nil {
				resp := h.errorResponse(0, err, false)
				return resp, uncertainVisibilityTargets(resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)})
			}
			return h.success(0), []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
		})
	case *authoritypb.Request_ListXattr:
		item, err := h.item(cred.ID, body.ListXattr.GetItem())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if err := h.stabilizeItem(ctx, cred.ID, item); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		names, err := h.Store.ListXattr(item)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		encoded := make([][]byte, len(names))
		for i := range names {
			encoded[i] = []byte(names[i])
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_ListXattr{ListXattr: &authoritypb.ListXattrReply{Names: encoded}}
		return resp
	case *authoritypb.Request_StatFs:
		stat, err := h.Store.StatFS()
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{BlockSize: stat.BlockSize, Blocks: stat.Blocks, BlocksFree: stat.BlocksFree, BlocksAvailable: stat.BlocksAvailable, Files: stat.Files, FilesFree: stat.FilesFree, NameMax: stat.NameMax}}
		return resp
	case *authoritypb.Request_SyncFs:
		// SyncFS participates in exact replay/mutation order even though it
		// changes no cache coordinate. That makes it a true volume cut: every
		// earlier accepted mutation has applied before syncfs(2) runs.
		return h.mutate(ctx, req, cred, func() *authoritypb.Response {
			if err := h.Store.SyncFS(); err != nil {
				return h.errorResponse(0, err, false)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_SyncFs{SyncFs: &authoritypb.SyncFSReply{}}
			return resp
		})
	case *authoritypb.Request_GetLock:
		return h.getLock(req.GetRequestId(), cred, body.GetLock)
	case *authoritypb.Request_SetLock:
		return h.setLock(ctx, req, cred, body.SetLock)
	default:
		return h.errorResponse(req.GetRequestId(), syscall.EOPNOTSUPP, false)
	}
}

// cancelAcknowledgment answers a cancellation without pinning or renewing the
// session. The transport has already delivered the cancellation to the target
// operation on this authenticated connection; the reply is only an
// acknowledgment, and running it through the ordinary lease-renewing path would
// let a peer hold a session open indefinitely using cancels alone.
func (h *VolumeHandler) cancelAcknowledgment(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	if _, ok := PeerIdentity(ctx); !ok {
		return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
	}
	var epoch volumeserver.Epoch
	if len(req.GetEpoch()) != len(epoch) {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	copy(epoch[:], req.GetEpoch())
	if epoch != h.Runtime.Epoch() {
		return h.errorResponse(req.GetRequestId(), volumeserver.ErrEpochMismatch, false)
	}
	return h.success(req.GetRequestId())
}

// writeOutcome turns one store write into exactly one reported outcome. A
// write that made partial progress reports the short count and nothing else:
// n bytes are already durable in XFS, so reporting a count together with an
// errno would let the application conclude that nothing was written while the
// file has already grown. The next write on the same range re-encounters the
// condition and reports it with a zero count, which is what Linux does.
func (h *VolumeHandler) writeOutcome(n int, assigned int64, err error) *authoritypb.Response {
	if n == 0 {
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		// A zero-length write is a legal no-op, not a failure.
		resp := h.success(0)
		resp.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{}}
		return resp
	}
	h.recordStorageFailure(err)
	resp := h.success(0)
	resp.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Count: uint32(n), AssignedOffset: uint64(assigned)}}
	if uncertainFailure(err) {
		// The store itself is gone. The count is still exact, but this mount
		// cannot continue, so the outcome stays explicitly uncertain.
		resp.Uncertain = true
		resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_STORAGE
	}
	return resp
}

func direntCost(dirent *authoritypb.Dirent) uint64 {
	size := uint64(proto.Size(dirent))
	return 1 + uint64(protowire.SizeVarint(size)) + size
}

func decodeCookie(raw []byte) (uint64, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	if len(raw) != 8 {
		return 0, syscall.EINVAL
	}
	return binary.BigEndian.Uint64(raw), nil
}

func encodeCookie(value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return raw[:]
}

func verifierMatches(verifier [16]byte, attr xfsstore.Attr) bool {
	return binary.BigEndian.Uint64(verifier[0:8]) == attr.Ino && binary.BigEndian.Uint64(verifier[8:16]) == uint64(attr.CTimeNS)
}

func (h *VolumeHandler) hello(requestID uint64, hello *authoritypb.HelloRequest) *authoritypb.Response {
	if hello.GetProtocolMajor() != ProtocolMajor {
		return h.errorResponse(requestID, syscall.EOPNOTSUPP, false)
	}
	if !hasFeatures(hello.GetFeatures(), requiredHelloFeatures) {
		return h.errorResponse(requestID, syscall.EOPNOTSUPP, false)
	}
	if !h.validBounds() {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	bounds := h.Bounds()
	features := append([]string(nil), requiredHelloFeatures...)
	features = append(features, peerCompleteFIFOFeedbackFeature, sessionReauthorizationFeature, mountEnrollmentReauthorizationFeature)
	resp := h.success(requestID)
	resp.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{
		ProtocolMajor: ProtocolMajor, Features: features,
		MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: h.MaxRead, MaxWriteBytes: h.MaxWrite,
		MaxInFlight: uint32(bounds.MaxInFlight),
	}}
	return resp
}

func (h *VolumeHandler) attach(ctx context.Context, requestID uint64, attach *authoritypb.AttachRequest) *authoritypb.Response {
	if h.Store == nil || h.Runtime == nil || h.Authorizer == nil || attach.GetVolumeId() != h.Runtime.VolumeID() {
		return h.errorResponse(requestID, syscall.EPERM, false)
	}
	if !h.validResourceLimits() || !h.validBounds() {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	if h.Routes == nil {
		return h.errorResponse(requestID, errInternal, false)
	}
	profile, err := coherenceProfile(attach.GetCoherenceProfile())
	if err != nil || profile == volumeserver.CoherenceStrict && h.Visibility == nil {
		return h.errorResponse(requestID, syscall.EOPNOTSUPP, false)
	}
	// Reject every peer-controlled, allocation-shaping attach value before the
	// single-use capability is presented. These checks are deliberately pure;
	// session-count and durable-membership admission remain after authorization.
	if err := h.Runtime.ValidateAttachSlots(attach.GetReplaySlots()); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	var commitment volumeserver.VisibilityCommitment
	if profile == volumeserver.CoherenceStrict {
		repair, err := namespaceRepair(attach.GetNamespaceRepair())
		if err != nil || attach.GetRepairBudgetMillis() > uint64((time.Duration(1<<63-1))/time.Millisecond) {
			return h.errorResponse(requestID, syscall.EINVAL, false)
		}
		commitment = volumeserver.VisibilityCommitment{
			CachedNameCapacity: attach.GetCachedNameCapacity(),
			RepairBudget:       time.Duration(attach.GetRepairBudgetMillis()) * time.Millisecond,
			NamespaceRepair:    repair,
		}
		if err := h.Visibility.ValidateCommitment(commitment); err != nil {
			return h.errorResponse(requestID, err, false)
		}
	}
	// The routing check runs BEFORE the capability is presented for
	// verification, and the ordering is load-bearing rather than tidy.
	//
	// A volume capability is single use: volumecap.Verify spends its nonce as
	// the last step of an otherwise successful verification. A mount cannot know
	// the volume's routing revision before it has read the declaration, and it
	// cannot read the declaration without a session, so the first attach of a
	// mount that has never seen this volume is expected to be refused - that
	// refusal is the bootstrap, and it carries the active rules for exactly that
	// reason. If it were reached only after Authorize, the bootstrap would burn
	// the capability and the mount would need a second one to complete the
	// handshake it just learned how to complete. Checking first makes a
	// refused-for-revision attach cost nothing: the same capability re-attaches.
	//
	// What this exposes to a peer that has not yet proven a capability is the
	// routing revision and the declaration itself. That peer already holds a
	// client certificate this volume's CA issued - the listener requires and
	// verifies one - and the declaration is readable by every mount of this
	// volume, so it is not a secret being traded for the property above.
	//
	// Both profiles are checked. An uncached mount joins no barrier, but it
	// routes exactly as much of the tree to local disk as a strict one does, so
	// admitting it against a topology this volume does not run would hide a
	// subtree from every peer with no error anywhere.
	presented, declared, err := attachRoutesRevision(attach.GetRoutesRevision())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	// An attach pins this revision until all session resources and, for a strict
	// mount, durable visibility membership are installed. An uncached mount needs
	// the same guard: routing, rather than cache behavior, is the invariant.
	topology := h.Routes.AcquireTopologyRead()
	defer topology.Release()
	if err := h.Routes.Admit(presented, declared, "attach", false); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	authorization, err := h.Authorizer.Authorize(ctx, attach.GetVolumeId(), attach.GetAccessToken())
	if err != nil {
		return h.errorResponse(requestID, syscall.EPERM, false)
	}
	peer, ok := PeerIdentity(ctx)
	if !ok {
		return h.errorResponse(requestID, syscall.EPERM, false)
	}
	root, err := h.Store.Root()
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	cred, err := h.Runtime.Attach(attach.GetReplaySlots(), volumeserver.PeerIdentity(peer), authorization)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	attached := true
	defer func() {
		if attached {
			_ = h.Runtime.Detach(cred)
		}
	}()
	// The runtime accepted this exact slot count, so the per-slot reply
	// accounting has the same length as the session's replay slots.
	if err := h.startSessionResources(cred.ID, root, attach.GetReplaySlots(), presented, profile); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	// Re-checked after the revision is recorded, not because the first check was
	// insufficient - every later request compares against this recording, so a
	// change that lands between the two checks refuses the session's first
	// operation anyway - but because a session that attaches and can then do
	// nothing is a worse answer than a refused attach. After the recording, a
	// change can only reach the active revision through ApplyRoutes, and the
	// recording is what it will be compared against from here on.
	if err := h.Routes.Admit(presented, declared, "attach", false); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	attr, err := h.Store.Getattr(root)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	rootIdentity, err := h.Store.Identity(root)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	var initialCursor *authoritypb.VisibilityCursor
	if profile == volumeserver.CoherenceStrict {
		terminal, err := h.Runtime.SessionTerminal(cred.ID)
		if err != nil {
			return h.errorResponse(requestID, err, false)
		}
		if err := h.Visibility.Register(cred.ID, profile, terminal, commitment); err != nil {
			return h.errorResponse(requestID, err, false)
		}
		initial, err := h.Visibility.InitialCursor(cred.ID)
		if err != nil {
			return h.errorResponse(requestID, err, false)
		}
		initialCursor = visibilityCursorProto(initial)
		// The root is the one coordinate every mount holds from attach onward.
		h.Visibility.RecordResolvedInode(cred.ID, rootIdentity)
	}
	resp := h.success(requestID)
	features := append([]string(nil), requiredAttachFeatures...)
	features = append(features, sessionReauthorizationFeature, mountEnrollmentReauthorizationFeature)
	if profile == volumeserver.CoherenceStrict {
		features = append(features, requiredStrictAttachFeatures...)
	}
	resp.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{SessionId: cred.ID[:], SessionGeneration: cred.Generation, ResumeSecret: cred.Secret[:], Root: itemProto(root, attr, rootIdentity), Features: features, SessionLeaseMilliseconds: uint64(h.Runtime.SessionLease() / time.Millisecond), VisibilityCursor: initialCursor, RoutesRevision: append([]byte(nil), presented[:]...), AuthorizationDeadlineUnixNanos: authorization.Deadline.UnixNano()}}
	attached = false
	return resp
}

func (h *VolumeHandler) validResourceLimits() bool {
	return h.MaxItemsPerSession > 0 && h.MaxOpensPerSession > 0 && h.MaxItems > 0 && h.MaxOpens > 0 &&
		h.MaxItemsPerSession <= h.MaxItems && h.MaxOpensPerSession <= h.MaxOpens
}

func (h *VolumeHandler) validBounds() bool {
	return h.MaxFrame >= MinimumFrameBytes && h.MaxRead > 0 && h.MaxWrite > 0 && h.MaxInFlight >= 2 &&
		uint64(h.MaxRead)+uint64(FramePayloadReserve) <= uint64(h.MaxFrame) &&
		uint64(h.MaxWrite)+uint64(FramePayloadReserve) <= uint64(h.MaxFrame) &&
		h.MaxRetainedReplyBytes >= uint64(h.maxReplyBytes())
}

// readDirEntryBudget is the byte budget available to directory entries. It is
// a pure function of the request, so the reservation taken before the operation
// runs and the budget the reply is built to are necessarily the same number.
func (h *VolumeHandler) readDirEntryBudget(maxEntries uint32) uint32 {
	return h.replyReserve(maxEntries) - readDirReplyOverhead
}

// replyReserve bounds the reply of one directory listing. Every other mutation
// reply has a fixed shape (an item, an attribute block, a handle, a count).
func (h *VolumeHandler) replyReserve(readDirMaxEntries uint32) uint32 {
	if readDirMaxEntries == 0 {
		return fixedMutationReplyBytes
	}
	budget := uint64(readDirMaxEntries)*uint64(maxDirentBytes) + uint64(readDirReplyOverhead)
	if budget < uint64(fixedMutationReplyBytes) {
		budget = uint64(fixedMutationReplyBytes)
	}
	if limit := uint64(h.maxReplyBytes()); budget > limit {
		budget = limit
	}
	return uint32(budget)
}

func (h *VolumeHandler) requestReplyReserve(req *authoritypb.Request) uint32 {
	if dir := req.GetReadDir(); dir != nil {
		return h.replyReserve(dir.GetMaxEntries())
	}
	return fixedMutationReplyBytes
}

func (h *VolumeHandler) mutate(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential, apply func() *authoritypb.Response) *authoritypb.Response {
	return h.mutateOperation(ctx, req, cred, func(volumeserver.MutationID) *authoritypb.Response { return apply() })
}

func (h *VolumeHandler) mutateVisible(
	ctx context.Context,
	req *authoritypb.Request,
	cred volumeserver.SessionCredential,
	prepare func() ([]volumeserver.VisibilityTarget, error),
	apply func() (*authoritypb.Response, []volumeserver.VisibilityTarget),
) *authoritypb.Response {
	return h.mutateOperation(ctx, req, cred, func(id volumeserver.MutationID) *authoritypb.Response {
		if h.Visibility == nil {
			if _, err := prepare(); err != nil {
				return h.errorResponse(0, err, false)
			}
			resp, _ := apply()
			return resp
		}
		held, err := h.heldDirectories(cred.ID, req)
		if err != nil {
			// Failing closed here is a liveness requirement, not only input
			// validation. Silently dropping a parent would hide the exact kernel
			// lock that a peer COMPLETE may need and recreate the cycle the
			// interruption protocol exists to break.
			return h.errorResponse(0, err, false)
		}
		var resp *authoritypb.Response
		err = h.Visibility.ExecuteWithHeldParents(ctx, cred.ID, id, held, prepare, func() ([]volumeserver.VisibilityTarget, bool) {
			var complete []volumeserver.VisibilityTarget
			resp, complete = apply()
			// nil is the explicit no-visible-change result. A non-nil empty
			// slice means apply changed XFS but target construction failed;
			// the coordinator detects and poisons that post-apply defect.
			return complete, complete != nil && visibilityChanged(resp)
		})
		if err != nil {
			var barrier *volumeserver.VisibilityBarrierError
			uncertain := errors.As(err, &barrier) && barrier.Applied
			if uncertain {
				log.Printf(
					"portablefs-authority: visible mutation applied but cache completion failed source=%x slot=%d sequence=%d frontend_operation_id=%d: %v",
					cred.ID, id.Slot, id.Sequence, id.FrontendOperationID, err,
				)
			}
			return h.errorResponse(0, err, uncertain)
		}
		// The initiating mount caches the inode it just created, and that
		// coordinate is knowable only from the reply.
		h.recordReplyItem(cred.ID, resp)
		return resp
	})
}

func (h *VolumeHandler) mutateOperation(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential, apply func(volumeserver.MutationID) *authoritypb.Response) *authoritypb.Response {
	access, err := h.Runtime.Access(cred)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	if requestRequiresWrite(req) && access&volumeserver.AccessWrite == 0 {
		return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
	}
	mutation := req.GetMutation()
	if mutation == nil || len(mutation.GetRequestHash()) != sha256.Size {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	hash, err := canonicalHash(req)
	if err != nil || !bytes.Equal(hash[:], mutation.GetRequestHash()) {
		return h.errorResponse(req.GetRequestId(), volumeserver.ErrRequestMismatch, false)
	}
	// Admission is taken against the bytes this outcome may retain, before the
	// operation reaches XFS. Refusing here is retryable; refusing after the
	// filesystem changed would not be.
	reserve := h.requestReplyReserve(req)
	id := volumeserver.MutationID{
		Slot: mutation.GetSlot(), Sequence: mutation.GetSequence(), Hash: hash,
		FrontendOperationID:  req.GetFrontendOperationId(),
		SourcePhaseQueueable: req.GetSourcePhaseQueueable(),
	}
	reserved, err := h.reserveReplyBytes(cred.ID, id.Slot, reserve)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	settled := false
	defer func() {
		if !settled {
			h.releaseReplyReservation(reserved)
		}
	}()
	out, err := h.Runtime.ExecuteMutation(ctx, cred, id, func(context.Context) volumeserver.Outcome {
		resp := apply(id)
		encoded, encodeErr := marshalOutcome(resp)
		if encodeErr != nil || uint32(len(encoded)) > reserve {
			resp = h.errorResponse(0, syscall.EOVERFLOW, true)
			encoded, encodeErr = marshalOutcome(resp)
			if encodeErr != nil || uint32(len(encoded)) > reserve {
				return volumeserver.Outcome{Errno: errnos.EIO}
			}
		}
		h.settleReplyBytes(cred.ID, id.Slot, uint32(len(encoded)), reserved)
		settled = true
		return volumeserver.Outcome{Errno: resp.GetErrno(), Reply: encoded}
	})
	if err != nil {
		// Nothing was recorded for this identity, so the response deliberately
		// carries no MutationState and the peer's slot stays where it is.
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	resp := new(authoritypb.Response)
	if err := proto.Unmarshal(out.Reply, resp); err != nil {
		return h.errorResponse(req.GetRequestId(), errInternal, true)
	}
	epoch := h.Runtime.Epoch()
	resp.RequestId, resp.Epoch, resp.Errno = req.GetRequestId(), epoch[:], out.Errno
	// ExecuteMutation returning without error means this exact identity is the
	// one recorded in the slot, whether it just executed or replayed. Reporting
	// it is what keeps the peer's slot state a copy rather than an inference.
	resp.Mutation = &authoritypb.MutationState{Slot: id.Slot, AcceptedSequence: id.Sequence}
	return resp
}

// marshalOutcome encodes the retained form of a reply: the envelope the
// transport restores on every delivery is stripped, so a replay and its
// original are byte-identical bodies.
func marshalOutcome(resp *authoritypb.Response) ([]byte, error) {
	resp.RequestId, resp.Epoch, resp.Mutation = 0, nil, nil
	return proto.MarshalOptions{Deterministic: true}.Marshal(resp)
}

// reserveReplyBytes admits one mutation against the bytes its outcome may add
// to the replay cache. The slot's current outcome is replaced, not appended to,
// so only the growth beyond what that slot already holds has to be reserved:
// re-running an operation on a slot that is already at the budget is admitted,
// while a slot that would grow the total past it is refused.
func (h *VolumeHandler) reserveReplyBytes(id volumeserver.SessionID, slot, n uint32) (uint32, error) {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	held := uint32(0)
	if resources := h.resources[id]; resources != nil && !resources.ended && uint64(slot) < uint64(len(resources.reply)) {
		held = resources.reply[slot]
	}
	if held >= n {
		return 0, nil
	}
	growth := n - held
	if h.retainedReplyBytes+h.reservedReplyBytes+uint64(growth) > h.MaxRetainedReplyBytes {
		return 0, volumeserver.ErrAdmission
	}
	h.reservedReplyBytes += uint64(growth)
	return growth, nil
}

func (h *VolumeHandler) releaseReplyReservation(n uint32) {
	h.resourcesMu.Lock()
	h.reservedReplyBytes -= uint64(n)
	h.resourcesMu.Unlock()
}

// settleReplyBytes converts a reservation into the exact retained size of the
// outcome now held in the slot. A session that ended while the operation ran
// has already had its whole slot array released, so its bytes are not counted.
func (h *VolumeHandler) settleReplyBytes(id volumeserver.SessionID, slot uint32, size, reserve uint32) {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	h.reservedReplyBytes -= uint64(reserve)
	resources := h.resources[id]
	if resources == nil || resources.ended || uint64(slot) >= uint64(len(resources.reply)) {
		return
	}
	h.retainedReplyBytes += uint64(size) - uint64(resources.reply[slot])
	resources.reply[slot] = size
}

func (h *VolumeHandler) credential(ctx context.Context, req *authoritypb.Request) (volumeserver.SessionCredential, error) {
	var cred volumeserver.SessionCredential
	if len(req.GetEpoch()) != len(cred.Epoch) || req.GetSession() == nil || len(req.GetSession().GetId()) != len(cred.ID) || len(req.GetSession().GetResumeSecret()) != len(cred.Secret) {
		return cred, syscall.EINVAL
	}
	copy(cred.Epoch[:], req.GetEpoch())
	copy(cred.ID[:], req.GetSession().GetId())
	copy(cred.Secret[:], req.GetSession().GetResumeSecret())
	cred.Generation = req.GetSession().GetGeneration()
	peer, ok := PeerIdentity(ctx)
	if !ok {
		return cred, syscall.EPERM
	}
	cred.Peer = volumeserver.PeerIdentity(peer)
	return cred, nil
}

func capability(raw []byte) (xfsstore.Capability, error) {
	var cap xfsstore.Capability
	if len(raw) != len(cap) {
		return cap, syscall.EINVAL
	}
	copy(cap[:], raw)
	return cap, nil
}

// item resolves an object capability that this session actually holds. A
// capability is a volume-epoch bearer token; scoping resolution to the issuing
// session is what keeps one session from reclaiming another session's objects.
func (h *VolumeHandler) item(id volumeserver.SessionID, raw []byte) (xfsstore.Capability, error) {
	cap, err := capability(raw)
	if err != nil {
		return cap, err
	}
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		return xfsstore.Capability{}, volumeserver.ErrSessionExpired
	}
	if cap == resources.root {
		return cap, nil
	}
	if _, held := resources.items[cap]; !held {
		return xfsstore.Capability{}, xfsstore.ErrStaleObject
	}
	return cap, nil
}

// open resolves an open-handle capability that this session actually holds.
func (h *VolumeHandler) open(id volumeserver.SessionID, raw []byte) (xfsstore.Capability, error) {
	cap, err := capability(raw)
	if err != nil {
		return cap, err
	}
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		return xfsstore.Capability{}, volumeserver.ErrSessionExpired
	}
	if _, held := resources.opens[cap]; !held {
		return xfsstore.Capability{}, xfsstore.ErrStaleOpen
	}
	return cap, nil
}

func openFlags(flags *authoritypb.OpenFlags) xfsstore.OpenFlags {
	if flags == nil {
		return xfsstore.OpenFlags{}
	}
	return xfsstore.OpenFlags{Read: flags.GetRead(), Write: flags.GetWrite(), Append: flags.GetAppend(), Truncate: flags.GetTruncate(), Sync: flags.GetSync(), DataSync: flags.GetDataSync()}
}

func itemProto(item xfsstore.Capability, attr xfsstore.Attr, identity [16]byte) *authoritypb.Item {
	return &authoritypb.Item{Token: item[:], Attr: attrProto(attr), StableIdentity: identity[:]}
}
func attrProto(attr xfsstore.Attr) *authoritypb.Attr {
	return &authoritypb.Attr{Kind: attrKindProto(attr.Kind), Inode: attr.Ino, Size: attr.Size, Blocks: attr.Blocks, Mode: modeToProtocol(attr.Mode), Uid: attr.UID, Gid: attr.GID, Nlink: attr.Nlink, AtimeNs: attr.ATimeNS, MtimeNs: attr.MTimeNS, CtimeNs: attr.CTimeNS, BirthTimeNs: attr.BirthTimeNS}
}

// attrKindProto and xattrMode translate between two independently numbered
// enumerations. They are written out so that renumbering either side is a
// compile-time or test failure rather than a silent reinterpretation.
func attrKindProto(kind xfsstore.Kind) authoritypb.Attr_Kind {
	switch kind {
	case xfsstore.KindRegular:
		return authoritypb.Attr_REGULAR
	case xfsstore.KindDirectory:
		return authoritypb.Attr_DIRECTORY
	case xfsstore.KindSymlink:
		return authoritypb.Attr_SYMLINK
	default:
		return authoritypb.Attr_KIND_UNSPECIFIED
	}
}

func xattrMode(mode authoritypb.SetXattrRequest_Mode) (xfsstore.XattrMode, bool) {
	switch mode {
	case authoritypb.SetXattrRequest_UPSERT:
		return xfsstore.XattrUpsert, true
	case authoritypb.SetXattrRequest_CREATE:
		return xfsstore.XattrCreate, true
	case authoritypb.SetXattrRequest_REPLACE:
		return xfsstore.XattrReplace, true
	default:
		return 0, false
	}
}

func modeFromProtocol(mode uint32) (fs.FileMode, bool) {
	if mode&^0o7777 != 0 {
		return 0, false
	}
	result := fs.FileMode(mode & 0o777)
	if mode&0o4000 != 0 {
		result |= fs.ModeSetuid
	}
	if mode&0o2000 != 0 {
		result |= fs.ModeSetgid
	}
	if mode&0o1000 != 0 {
		result |= fs.ModeSticky
	}
	return result, true
}

func modeToProtocol(mode fs.FileMode) uint32 {
	result := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		result |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		result |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		result |= 0o1000
	}
	return result
}

func (h *VolumeHandler) getattr(ctx context.Context, id volumeserver.SessionID, req *authoritypb.GetAttrRequest) (xfsstore.Attr, error) {
	if len(req.GetHandle()) != 0 {
		handle, err := h.open(id, req.GetHandle())
		if err != nil {
			return xfsstore.Attr{}, err
		}
		if err := h.stabilizeOpen(ctx, id, handle); err != nil {
			return xfsstore.Attr{}, err
		}
		return h.Store.GetattrOpen(handle)
	}
	item, err := h.item(id, req.GetItem())
	if err != nil {
		return xfsstore.Attr{}, err
	}
	if err := h.stabilizeItem(ctx, id, item); err != nil {
		return xfsstore.Attr{}, err
	}
	return h.Store.Getattr(item)
}

func (h *VolumeHandler) getLock(requestID uint64, cred volumeserver.SessionCredential, request *authoritypb.GetLockRequest) *authoritypb.Response {
	lock, err := h.lock(cred, request.GetLock())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	held, conflict, err := h.Runtime.Locks().Get(lock)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	resp := h.success(requestID)
	reply := &authoritypb.GetLockReply{Conflict: conflict}
	if conflict {
		reply.Held = lockProto(held)
	}
	resp.Body = &authoritypb.Response_GetLock{GetLock: reply}
	return resp
}

func (h *VolumeHandler) setLock(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential, request *authoritypb.SetLockRequest) *authoritypb.Response {
	return h.mutate(ctx, req, cred, func() *authoritypb.Response {
		lock, err := h.lock(cred, request.GetLock())
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		if request.GetUnlock() {
			err = h.Runtime.Locks().Unlock(lock.Object, lock.Owner, lock.Range)
		} else if request.GetWait() {
			err = h.Runtime.Locks().Wait(ctx, lock)
		} else {
			err = h.Runtime.Locks().Set(lock)
		}
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		return h.success(0)
	})
}

func (h *VolumeHandler) lock(cred volumeserver.SessionCredential, spec *authoritypb.LockSpec) (volumeserver.Lock, error) {
	if spec == nil || spec.GetRange() == nil {
		return volumeserver.Lock{}, syscall.EINVAL
	}
	item, err := h.item(cred.ID, spec.GetItem())
	if err != nil {
		return volumeserver.Lock{}, err
	}
	identity, err := h.Store.Identity(item)
	if err != nil {
		return volumeserver.Lock{}, err
	}
	type_ := volumeserver.LockRead
	if spec.GetWrite() {
		type_ = volumeserver.LockWrite
	}
	return volumeserver.Lock{Object: identity, Owner: volumeserver.LockOwner{Session: cred.ID, Kernel: spec.GetOwner(), Flock: spec.GetFlock()}, Type: type_, Range: volumeserver.LockRange{Start: spec.GetRange().GetStart(), End: spec.GetRange().GetEnd()}}, nil
}
func lockProto(lock volumeserver.Lock) *authoritypb.LockSpec {
	// item is a request capability. The runtime's inode identity is deliberately
	// not exposed as a token-shaped value in a conflict response.
	return &authoritypb.LockSpec{Owner: lock.Owner.Kernel, Write: lock.Type == volumeserver.LockWrite, Range: &authoritypb.LockRange{Start: lock.Range.Start, End: lock.Range.End}, Flock: lock.Owner.Flock}
}

func (h *VolumeHandler) unlockOpenOwner(cred volumeserver.SessionCredential, handle xfsstore.Capability, owner uint64, flock bool) error {
	identity, err := h.Store.IdentityOpen(handle)
	if err != nil {
		return err
	}
	return h.Runtime.Locks().Unlock(identity, volumeserver.LockOwner{Session: cred.ID, Kernel: owner, Flock: flock}, volumeserver.ToEOF(0))
}

func (h *VolumeHandler) success(requestID uint64) *authoritypb.Response {
	return &authoritypb.Response{RequestId: requestID, Epoch: h.Epoch()}
}

func (h *VolumeHandler) errorResponse(requestID uint64, err error, uncertain bool) *authoritypb.Response {
	h.recordStorageFailure(err)
	h.recordCoherenceFailure(err)
	if uncertainFailure(err) {
		uncertain = true
	}
	// A routing disagreement is answered with both revisions attached. The
	// errno alone cannot say which two configurations disagreed, and that is
	// the only thing an operator holding two files needs to know.
	var mismatch *RoutesMismatchError
	if errors.As(err, &mismatch) {
		resp := h.success(requestID)
		resp.Errno, resp.Uncertain = errnos.EPERM, uncertain
		resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_ROUTES
		resp.RoutesMismatch = mismatch.proto()
		return resp
	}
	errno := wireErrno(err)
	switch {
	case errors.Is(err, volumeserver.ErrEpochMismatch), errors.Is(err, volumeserver.ErrSessionExpired), errors.Is(err, volumeserver.ErrSessionFenced):
		errno = errnos.ESTALE
	case errors.Is(err, volumeserver.ErrSequenceGap), errors.Is(err, volumeserver.ErrRequestMismatch), errors.Is(err, volumeserver.ErrSlotRange),
		errors.Is(err, volumeserver.ErrAuthorizationSequence), errors.Is(err, volumeserver.ErrAuthorizationBroadened),
		errors.Is(err, volumeserver.ErrAuthorizationOwner):
		errno = errnos.EINVAL
	case errors.Is(err, volumeserver.ErrAdmission):
		errno = errnos.EAGAIN
	case errors.Is(err, volumeserver.ErrVisibilityInterrupted):
		// This is a definite pre-apply interruption, not a coherence
		// failure. Linux consumes EINTR to release the execution lane needed
		// by its pending repair. The explicit class lets an FSKit frontend
		// translate it to ECANCELED: macOS 26 may replay mutating callbacks on
		// EINTR, EBUSY, or EAGAIN, and that replay has a new operation identity.
		errno = errnos.EINTR
		resp := h.success(requestID)
		resp.Errno, resp.Uncertain = errno, uncertain
		resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_INTERRUPTED
		return resp
	case isVisibilityFenced(err):
		// One mount left the barrier. Its session is gone and it must revoke
		// its own kernel mount; the volume itself is unaffected, so this is a
		// stale-session answer and never a volume-wide I/O failure.
		errno = errnos.ESTALE
	case errors.Is(err, volumeserver.ErrVisibilityProof):
		errno = errnos.EPERM
	case errors.Is(err, volumeserver.ErrVisibilityProfile):
		errno = errnos.EOPNOTSUPP
	case errors.Is(err, errRoutesInvalid):
		errno = errnos.EINVAL
	case isVisibilityFailure(err):
		errno = errnos.EIO
	case errors.Is(err, errInternal):
		errno = errnos.EIO
	case errors.Is(err, volumeserver.ErrLockConflict):
		errno = errnos.EAGAIN
	case errors.Is(err, xfsstore.ErrStaleObject), errors.Is(err, xfsstore.ErrStaleOpen):
		errno = errnos.ESTALE
	case errors.Is(err, xfsstore.ErrFenced):
		errno = errnos.EIO
	case errors.Is(err, xfsstore.ErrOutcomeUncertain) && errno == errnos.OK:
		errno = errnos.EIO
	}
	resp := h.success(requestID)
	resp.Errno, resp.Uncertain = errno, uncertain
	if errno == errnos.EIO {
		// EIO alone cannot say whether the filesystem is gone or the authority
		// merely failed to recognise one of its own errors. The client needs
		// that difference: one requires a remount, the other does not.
		resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_INTERNAL
		if storageFailure(err) {
			resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_STORAGE
		} else if isVisibilityFailure(err) {
			resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_COHERENCE
		}
	} else if fatalStorageErrno(err) || errors.Is(err, xfsstore.ErrFenced) {
		// Corruption and shutdown errnos keep their exact kernel identity on
		// the wire, but they are storage-fatal all the same, and the client
		// must not have to enumerate them to learn that the volume is gone.
		resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_STORAGE
	}
	return resp
}

func (h *VolumeHandler) recordCoherenceFailure(err error) {
	if !isVisibilityFailure(err) || h.OnCoherenceFailure == nil {
		return
	}
	h.coherenceFailureOnce.Do(func() { h.OnCoherenceFailure(err) })
}

// fatalStorageErrno reports the errnos with which the kernel says the
// filesystem itself is gone, not just this one operation. EIO is the classic
// device failure; EUCLEAN is how XFS surfaces detected metadata corruption
// (EFSCORRUPTED shares its value); ESHUTDOWN is a filesystem the kernel has
// already shut down after an earlier failure; ENOTRECOVERABLE is terminal
// state loss. Continuing to mutate after any of them would run requests
// against a store whose durable state can no longer be trusted, so they all
// fence the volume — not only EIO.
func fatalStorageErrno(err error) bool {
	return errors.Is(err, syscall.EIO) || errors.Is(err, syscall.EUCLEAN) ||
		errors.Is(err, syscall.ESHUTDOWN) || errors.Is(err, syscall.ENOTRECOVERABLE)
}

// storageFailure reports whether an error came from the authoritative store
// itself rather than from this handler's own logic.
func storageFailure(err error) bool {
	return fatalStorageErrno(err) || errors.Is(err, xfsstore.ErrFenced) || errors.Is(err, xfsstore.ErrOutcomeUncertain)
}

func uncertainFailure(err error) bool {
	return fatalStorageErrno(err) || errors.Is(err, xfsstore.ErrOutcomeUncertain)
}

func (h *VolumeHandler) recordStorageFailure(err error) {
	if h.Store == nil || !fatalStorageErrno(err) {
		return
	}
	h.Store.Fence(err)
	if h.OnStorageFailure != nil {
		h.storageFailureOnce.Do(func() { h.OnStorageFailure(err) })
	}
}

func wireErrno(err error) int32 {
	var errno syscall.Errno
	if errors.As(err, &errno) && errno > 0 {
		return int32(errno)
	}
	return errnos.Of(err)
}

func (h *VolumeHandler) startSessionResources(id volumeserver.SessionID, root xfsstore.Capability, slots uint32, routes [32]byte, profiles ...volumeserver.CoherenceProfile) error {
	profile := volumeserver.CoherenceUncached
	if len(profiles) == 1 {
		profile = profiles[0]
	} else if len(profiles) > 1 {
		return volumeserver.ErrVisibilityProfile
	}
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	if h.resources == nil {
		h.resources = make(map[volumeserver.SessionID]*sessionResources)
	}
	if _, exists := h.resources[id]; exists {
		return volumeserver.ErrAdmission
	}
	h.resources[id] = &sessionResources{
		root:      root,
		items:     make(map[xfsstore.Capability]bool),
		opens:     make(map[xfsstore.Capability]bool),
		reply:     make([]uint32, slots),
		coherence: profile,
		routes:    routes,
	}
	return nil
}

func (h *VolumeHandler) sessionCoherence(id volumeserver.SessionID) (volumeserver.CoherenceProfile, error) {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		return 0, volumeserver.ErrSessionExpired
	}
	return resources.coherence, nil
}

func (h *VolumeHandler) strictSession(id volumeserver.SessionID) bool {
	profile, err := h.sessionCoherence(id)
	return err == nil && profile == volumeserver.CoherenceStrict
}

func (h *VolumeHandler) lookupCoordinate(parent xfsstore.Capability, name []byte) (visibilityCoordinate, bool, error) {
	item, attr, err := h.Store.Lookup(parent, string(name))
	if err != nil {
		return visibilityCoordinate{}, false, err
	}
	identity, identityErr := h.Store.Identity(item)
	forgetErr := h.Store.Forget(item)
	if identityErr != nil {
		return visibilityCoordinate{}, false, identityErr
	}
	if forgetErr != nil {
		return visibilityCoordinate{}, false, forgetErr
	}
	return attrCoordinate(identity, attr), true, nil
}

func (h *VolumeHandler) lookupCoordinateOptional(parent xfsstore.Capability, name []byte) (visibilityCoordinate, bool, error) {
	coordinate, found, err := h.lookupCoordinate(parent, name)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return visibilityCoordinate{}, false, nil
	}
	return coordinate, found, err
}

func (h *VolumeHandler) lookupCoordinateSizeOptional(parent xfsstore.Capability, name []byte) (visibilityCoordinate, int64, bool, error) {
	item, attr, err := h.Store.Lookup(parent, string(name))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return visibilityCoordinate{}, 0, false, nil
	}
	if err != nil {
		return visibilityCoordinate{}, 0, false, err
	}
	identity, identityErr := h.Store.Identity(item)
	forgetErr := h.Store.Forget(item)
	if identityErr != nil {
		return visibilityCoordinate{}, 0, false, identityErr
	}
	if forgetErr != nil {
		return visibilityCoordinate{}, 0, false, forgetErr
	}
	return attrCoordinate(identity, attr), attr.Size, true, nil
}

func linkVisibilityTargets(
	newName []byte,
	parent, source visibilityCoordinate,
	attestPostBinding bool,
) []volumeserver.VisibilityTarget {
	nameTarget := namespaceTargetRelated(parent, newName, source)
	if attestPostBinding {
		nameTarget = namespaceTargetPost(parent, newName, source)
	}
	return []volumeserver.VisibilityTarget{
		nameTarget,
		inodeTarget(volumeserver.VisibilityAttributes, parent, 0),
		inodeTarget(volumeserver.VisibilityAttributes, source, 0),
	}
}

func renameVisibilityTargets(
	rename *authoritypb.RenameRequest,
	oldParent, newParent, moved, replaced visibilityCoordinate,
	hasReplacement, attestPostBindings bool,
) []volumeserver.VisibilityTarget {
	oldNameTarget := namespaceTargetRelated(oldParent, rename.GetOldName(), moved)
	newNameTarget := namespaceTargetRelated(newParent, rename.GetNewName(), moved)
	if attestPostBindings {
		newNameTarget = namespaceTargetPost(newParent, rename.GetNewName(), moved)
		if rename.GetExchange() && hasReplacement {
			oldNameTarget = namespaceTargetPost(oldParent, rename.GetOldName(), replaced)
		}
	}
	if hasReplacement {
		newNameTarget.RelatedIdentities = append(newNameTarget.RelatedIdentities, replaced.identity)
	}
	targets := []volumeserver.VisibilityTarget{
		oldNameTarget,
		newNameTarget,
		inodeTarget(volumeserver.VisibilityAttributes, oldParent, 0),
		inodeTarget(volumeserver.VisibilityAttributes, newParent, 0),
		inodeTarget(volumeserver.VisibilityAttributes, moved, 0),
	}
	if hasReplacement {
		targets = append(targets, inodeTarget(volumeserver.VisibilityAttributes, replaced, 0))
	}
	return targets
}

// add inserts a capability and keeps the worker-wide counter in step with the
// set in one place, so the two can never diverge and no clamp is needed when
// they are taken apart again.
func trackCapability(set map[xfsstore.Capability]bool, cap xfsstore.Capability, protected bool, total *uint32) {
	if _, exists := set[cap]; exists {
		// Protection only ever widens. A capability that reached this session
		// through the protected namespace stays protected however else it is
		// later resolved, because the object it names is the same object.
		set[cap] = set[cap] || protected
		return
	}
	set[cap] = protected
	*total++
}

func untrackCapability(set map[xfsstore.Capability]bool, cap xfsstore.Capability, total *uint32) {
	if _, exists := set[cap]; !exists {
		return
	}
	delete(set, cap)
	*total--
}

func (h *VolumeHandler) reserveCapabilities(id volumeserver.SessionID, items, opens uint32) (*capabilityReservation, error) {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	resources := h.resources[id]
	switch {
	case resources == nil || resources.ended:
		return nil, volumeserver.ErrSessionExpired
	case uint64(len(resources.items))+uint64(resources.reservedItems)+uint64(items) > uint64(h.MaxItemsPerSession) ||
		uint64(h.totalItems)+uint64(items) > uint64(h.MaxItems) ||
		uint64(len(resources.opens))+uint64(resources.reservedOpens)+uint64(opens) > uint64(h.MaxOpensPerSession) ||
		uint64(h.totalOpens)+uint64(opens) > uint64(h.MaxOpens):
		return nil, volumeserver.ErrAdmission
	}
	resources.reservedItems += items
	resources.reservedOpens += opens
	h.totalItems += items
	h.totalOpens += opens
	return &capabilityReservation{
		h: h, id: id, resources: resources, items: items, opens: opens, active: true,
	}, nil
}

func (r *capabilityReservation) release() {
	if r == nil || r.h == nil {
		return
	}
	r.h.resourcesMu.Lock()
	defer r.h.resourcesMu.Unlock()
	if !r.active {
		return
	}
	// Session cleanup is deferred until every admitted handler exits, so the
	// resource record must still be the one the reservation was charged to.
	// Keep the identity check nevertheless: violating that lifetime invariant
	// must not corrupt a replacement session's accounting.
	if r.h.resources[r.id] == r.resources && !r.resources.ended {
		r.resources.reservedItems -= r.items
		r.resources.reservedOpens -= r.opens
		r.h.totalItems -= r.items
		r.h.totalOpens -= r.opens
	}
	r.active = false
}

func (r *capabilityReservation) commit(items, opens []trackedCapability) error {
	if r == nil || r.h == nil || uint32(len(items)) != r.items || uint32(len(opens)) != r.opens {
		return errInternal
	}
	r.h.resourcesMu.Lock()
	defer r.h.resourcesMu.Unlock()
	if !r.active {
		return errInternal
	}
	resources := r.h.resources[r.id]
	if resources != r.resources || resources == nil || resources.ended {
		return volumeserver.ErrSessionExpired
	}
	resources.reservedItems -= r.items
	resources.reservedOpens -= r.opens
	for _, item := range items {
		if current, exists := resources.items[item.value]; exists {
			resources.items[item.value] = current || item.protected
			// The reservation was charged as a new descriptor but this session
			// already owned the capability, so return the redundant charge.
			r.h.totalItems--
		} else {
			resources.items[item.value] = item.protected
		}
	}
	for _, open := range opens {
		if current, exists := resources.opens[open.value]; exists {
			resources.opens[open.value] = current || open.protected
			r.h.totalOpens--
		} else {
			resources.opens[open.value] = open.protected
		}
	}
	r.active = false
	return nil
}

func (h *VolumeHandler) trackItem(id volumeserver.SessionID, item xfsstore.Capability, protected bool) error {
	h.resourcesMu.Lock()
	resources := h.resources[id]
	alreadyTracked := false
	if resources != nil {
		_, alreadyTracked = resources.items[item]
	}
	var err error
	switch {
	case resources == nil || resources.ended:
		err = volumeserver.ErrSessionExpired
	case alreadyTracked:
		resources.items[item] = resources.items[item] || protected
	case uint64(len(resources.items))+uint64(resources.reservedItems) >= uint64(h.MaxItemsPerSession) || h.totalItems >= h.MaxItems:
		err = volumeserver.ErrAdmission
	default:
		trackCapability(resources.items, item, protected, &h.totalItems)
	}
	h.resourcesMu.Unlock()
	if err != nil {
		h.forgetItem(item)
	}
	return err
}

func (h *VolumeHandler) untrackItem(id volumeserver.SessionID, item xfsstore.Capability) {
	h.resourcesMu.Lock()
	if resources := h.resources[id]; resources != nil {
		untrackCapability(resources.items, item, &h.totalItems)
	}
	h.resourcesMu.Unlock()
}

func (h *VolumeHandler) trackOpen(id volumeserver.SessionID, handle xfsstore.Capability, protected bool) error {
	h.resourcesMu.Lock()
	resources := h.resources[id]
	alreadyTracked := false
	if resources != nil {
		_, alreadyTracked = resources.opens[handle]
	}
	var err error
	switch {
	case resources == nil || resources.ended:
		err = volumeserver.ErrSessionExpired
	case alreadyTracked:
		resources.opens[handle] = resources.opens[handle] || protected
	case uint64(len(resources.opens))+uint64(resources.reservedOpens) >= uint64(h.MaxOpensPerSession) || h.totalOpens >= h.MaxOpens:
		err = volumeserver.ErrAdmission
	default:
		trackCapability(resources.opens, handle, protected, &h.totalOpens)
	}
	h.resourcesMu.Unlock()
	if err != nil {
		h.closeOpen(handle)
	}
	return err
}

func (h *VolumeHandler) untrackOpen(id volumeserver.SessionID, handle xfsstore.Capability) {
	h.resourcesMu.Lock()
	if resources := h.resources[id]; resources != nil {
		untrackCapability(resources.opens, handle, &h.totalOpens)
	}
	h.resourcesMu.Unlock()
}

func (h *VolumeHandler) closeSessionResources(id volumeserver.SessionID) {
	h.resourcesMu.Lock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		h.resourcesMu.Unlock()
		return
	}
	resources.ended = true
	handles := make([]xfsstore.Capability, 0, len(resources.opens))
	for handle := range resources.opens {
		handles = append(handles, handle)
	}
	items := make([]xfsstore.Capability, 0, len(resources.items))
	for item := range resources.items {
		items = append(items, item)
	}
	// Every insertion or pre-apply reservation incremented these counters
	// exactly once, so the subtraction is exact even if cleanup follows a
	// handler that was interrupted between reservation and commit.
	h.totalOpens -= uint32(len(handles)) + resources.reservedOpens
	h.totalItems -= uint32(len(items)) + resources.reservedItems
	for _, size := range resources.reply {
		h.retainedReplyBytes -= uint64(size)
	}
	resources.opens = nil
	resources.items = nil
	resources.reservedItems = 0
	resources.reservedOpens = 0
	resources.reply = nil
	h.resourcesMu.Unlock()
	for _, handle := range handles {
		h.closeOpen(handle)
	}
	for _, item := range items {
		h.forgetItem(item)
	}
	h.resourcesMu.Lock()
	if h.resources[id] == resources {
		delete(h.resources, id)
	}
	h.resourcesMu.Unlock()
}

func (h *VolumeHandler) closeOpen(handle xfsstore.Capability) {
	if h.Store == nil {
		return
	}
	if err := h.Store.CloseOpen(handle); err != nil && !errors.Is(err, xfsstore.ErrStaleOpen) && !errors.Is(err, xfsstore.ErrClosed) {
		h.recordStorageFailure(err)
	}
}

func (h *VolumeHandler) forgetItem(item xfsstore.Capability) {
	if h.Store == nil {
		return
	}
	if err := h.Store.Forget(item); err != nil && !errors.Is(err, xfsstore.ErrStaleObject) && !errors.Is(err, xfsstore.ErrClosed) {
		h.recordStorageFailure(err)
	}
}
