//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritymetrics"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var (
	errInternal            = errors.New("authorityrpc: internal handler failure")
	errCapabilityTableFull = errnos.Sentinel("authorityrpc: descriptor-backed capability table full", syscall.ENFILE)
)

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
	CoordinateItem(xfsstore.Capability) (xfsstore.ObjectCoordinate, error)
	IdentityOpen(xfsstore.Capability) ([16]byte, error)
	CoordinateOpen(xfsstore.Capability) (xfsstore.ObjectCoordinate, error)
	OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error)
	CloseOpen(xfsstore.Capability) error
	ReadAt(xfsstore.Capability, []byte, int64) (int, error)
	WriteAt(xfsstore.Capability, []byte, int64) (int, error)
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
	SetAttr(xfsstore.Capability, xfsstore.Capability, xfsstore.SetAttrSpec) (xfsstore.Attr, error)
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

// writeTransactionStore is deliberately narrower than volumeStore. A write
// transaction pins a stable inode target across inert BEGIN/DATA staging and
// source-gated COMMIT; no ordinary handle operation may approximate that
// lifetime. Production's *xfsstore.Volume is the sole implementation.
type writeTransactionStore interface {
	PinWriteTarget(xfsstore.Capability) (xfsstore.WriteTarget, error)
}

type coalescingFsyncStore interface {
	FsyncCoalesced(xfsstore.Capability, bool) (int, error)
}

type tmpfileStore interface {
	Tmpfile(xfsstore.Capability, fs.FileMode, bool) (xfsstore.Capability, xfsstore.Attr, error)
}

type mutationLockStore interface {
	LockMutation([][16]byte) func()
}

func lockMutationStore(store volumeStore, identities ...[16]byte) (func(), error) {
	locker, ok := store.(mutationLockStore)
	if !ok {
		return nil, errInternal
	}
	return locker.LockMutation(identities), nil
}

type VolumeHandler struct {
	Store       volumeStore
	Runtime     *volumeserver.Authority
	Authorizer  Authorizer
	Metrics     *authoritymetrics.Metrics
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
	postStateMu        sync.Mutex
	objectVersions     map[[16]byte]uint64
	// MaxRetainedReplyBytes bounds the real quantity the replay cache consumes:
	// the total encoded bytes retained across every live session's replay
	// slots. Slot counts are not a proxy for it; one directory listing is five
	// orders of magnitude larger than one create.
	MaxRetainedReplyBytes uint64
	// WriteStaging is a required private O_TMPFILE arena for the one
	// syscall-scoped shared-write protocol. All four bounds are explicit: a
	// byte bound alone would let one-byte transactions exhaust maps/fds, while a
	// count bound alone would let a few MAX_RW_COUNT calls exhaust disk.
	WriteStaging                    *WriteTransactionStaging
	MaxWriteTransactionBytes        uint64
	MaxWriteStagingBytesPerSession  uint64
	MaxWriteStagingBytes            uint64
	MaxWriteTransactionsPerSession  uint32
	MaxWriteTransactions            uint32
	WriteTransactionProgressTimeout time.Duration
	WriteTransactionAbsoluteTimeout time.Duration
	TerminalDeliveryTimeout         time.Duration
	// Visibility coordinates every protocol-5 frontend's kernel publications.
	// There is no active session outside this barrier.
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

	cleanupOnce            sync.Once
	storageFailureOnce     sync.Once
	coherenceFailureOnce   sync.Once
	terminalFailureMu      sync.Mutex
	terminalDraining       bool
	terminalQuiesce        chan struct{}
	terminalTimeoutArmed   bool
	terminalForced         bool
	terminalActive         uint64
	terminalHandlerFrames  map[*authoritypb.Response]struct{}
	terminalAdmittedFrames map[*authoritypb.Response]struct{}
	terminalFrames         map[*authoritypb.Response]struct{}
	// terminalReceiptFrames is the exact response-instance set which directly
	// carried a terminal storage/coherence outcome. Sibling requests admitted
	// before the fence are still held through their physical frame write, but
	// only these terminal results need a cross-process frontend publication
	// receipt. Pointer identity avoids both protobuf-body collisions and request-
	// dialect guesses (some protocol clients have no deferred publication API).
	terminalReceiptFrames map[*authoritypb.Response]struct{}
	terminalResponses     map[[16]byte]struct{}
	terminalTokenReader   io.Reader
	terminalStorageErr    error
	terminalCoherenceErr  error
	resourcesMu           sync.Mutex
	resources             map[volumeserver.SessionID]*sessionResources
	totalItems            uint32
	totalOpens            uint32
	// retainedReplyBytes is the exact number of bytes currently held in replay
	// slots; reservedReplyBytes covers mutations that are executing and whose
	// reply size is not yet known.
	retainedReplyBytes     uint64
	reservedReplyBytes     uint64
	writeCapacityMu        sync.Mutex
	writeCapacityHead      *writeTransactionCapacityWaiter
	writeCapacityTail      *writeTransactionCapacityWaiter
	totalWriteStagingBytes uint64
	totalWriteTransactions uint32
}

type sessionResources struct {
	ended bool
	// attempt identifies the one protocol-5 attach transaction that owns these
	// resources. Attach retries may race, but the runtime binds an attempt ID to
	// one canonical request before this record is installed, so an exact retry
	// observes this same record instead of allocating a second reply table.
	attempt volumeserver.AttachAttemptID
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
	reply      []uint32
	coherence  volumeserver.CoherenceProfile
	commitment volumeserver.VisibilityCommitment
	// authorizationDeadline comes from the runtime's retained result, never
	// from the local Authorize invocation: on an exact concurrent Attach replay
	// only the first caller executes that invocation.
	authorizationDeadline time.Time
	// activation serializes the failure-atomic transition and the retained
	// reply. The transport also serializes lifecycle requests, but keeping the
	// invariant here makes direct handler use and tests obey the same contract.
	activationMu    sync.Mutex
	activationReply *authoritypb.ActivateReply
	// routes is the machine-local routing revision this session was admitted
	// against. It is held here, by the authority, rather than echoed on each
	// request: a mount cannot present agreement it does not have, and a routing
	// change makes every session whose revision is no longer active refuse its
	// next request without any extra field on the wire.
	routes [32]byte

	// writeMu owns only the session's inert transaction registry and monotonic
	// accounting. It is never held across O_TMPFILE allocation, target pinning,
	// DATA I/O, per-transaction waits, or Close; each registered transaction has
	// its own serialization and lifetime barrier. Runtime.Begin additionally
	// keeps this record alive while an admitted request is executing.
	writeMu               sync.Mutex
	writeTransactions     map[uint64]*writeTransaction
	writeHighWater        uint64
	writeTerminal         *writeTransactionTerminal
	writeReservedBytes    uint64
	writeTransactionCount uint32
	writeCapacityEnded    bool
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

func (h *VolumeHandler) SessionStateForTransport(id volumeserver.SessionID) (volumeserver.SessionState, bool) {
	if h.Runtime == nil {
		return volumeserver.SessionStateUnknown, false
	}
	return h.Runtime.SessionStateByID(id)
}

func (h *VolumeHandler) SessionTerminalForTransport(id volumeserver.SessionID) (<-chan struct{}, bool) {
	if h.Runtime == nil {
		return nil, false
	}
	terminal, err := h.Runtime.SessionTerminal(id)
	return terminal, err == nil
}

// maxReplyBytes is the largest operation reply this authority can both retain
// and put on the wire: whatever fits in a frame once the response envelope the
// transport adds back is accounted for.
func (h *VolumeHandler) maxReplyBytes() uint32 { return h.MaxFrame - responseEnvelopeReserve }

func (h *VolumeHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	return h.handle(ctx, req, false)
}

// HandleForTransport retains the admitted-handler accounting through the
// immutable response boundary. The server transfers that ownership to the
// physical frame in FinishHandlerResponse before allowing terminal teardown.
func (h *VolumeHandler) HandleForTransport(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	return h.handle(ctx, req, true)
}

func (h *VolumeHandler) handle(ctx context.Context, req *authoritypb.Request, retainForTransport bool) (response *authoritypb.Response) {
	requestID := uint64(0)
	if req != nil {
		requestID = req.GetRequestId()
	}
	if !h.beginTerminalRequest(req) {
		return h.errorResponse(requestID, xfsstore.ErrFenced, false)
	}
	defer func() {
		if retainForTransport {
			h.retainTerminalHandlerResponse(response)
			return
		}
		h.endTerminalRequest()
	}()
	if terminalQuiesceCancelable(req) {
		select {
		case <-h.TerminalQuiescing():
			// A request admitted after the terminal edge must not begin a new
			// unbounded wait. Existing waits are canceled by the server's
			// quiesce hook; this closes the complementary post-edge race.
			return h.errorResponse(requestID, xfsstore.ErrFenced, false)
		default:
		}
	}
	if h.Runtime != nil {
		h.cleanupOnce.Do(func() { h.Runtime.OnSessionEnd(h.closeSessionResources) })
	}
	if req == nil {
		return h.errorResponse(0, fs.ErrInvalid, false)
	}
	if !validSourcePublicationGatePresence(req) {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	decodedGate, err := decodeSourcePublicationGate(req)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	if !validVisibilityRetryRequestShape(req, decodedGate) {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	if hello := req.GetHello(); hello != nil {
		return h.hello(req.GetRequestId(), hello)
	}
	if attach := req.GetAttach(); attach != nil {
		return h.attach(ctx, req)
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
	if receipt := req.GetTerminalDeliveryReceipt(); receipt != nil {
		return h.terminalDeliveryReceipt(req.GetRequestId(), receipt)
	}
	// These are the only requests a provisional credential can authorize. They
	// must run before Begin: Begin intentionally gates every ordinary operation
	// on ACTIVE, and neither Resume(PROVISIONAL) nor Abort may renew or publish a
	// provisional session as executable.
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Resume:
		return h.resume(ctx, req.GetRequestId(), cred)
	case *authoritypb.Request_Activate:
		return h.activate(ctx, req.GetRequestId(), cred, body.Activate)
	case *authoritypb.Request_AbortAttach:
		return h.abortAttach(ctx, req.GetRequestId(), cred, body.AbortAttach)
	}
	use, err := h.Runtime.Begin(cred)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), err, false)
	}
	defer use.End()
	// Reauthorization is an ordinary ACTIVE-session operation. Pin the runtime
	// first, before presenting its signed token to an external verifier: a
	// provisional credential must not consume or validate anything beyond its
	// three lifecycle operations (Resume, Activate, AbortAttach).
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
		req.GetNextVisibility() == nil && req.GetAckVisibility() == nil &&
		(req.GetWriteTransaction() == nil || req.GetWriteTransaction().GetPhase() != authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT) {
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
	case *authoritypb.Request_KeepAlive:
		if err := h.Runtime.Resume(cred); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		return h.success(req.GetRequestId())
	case *authoritypb.Request_Detach:
		profile, err := h.sessionCoherence(cred.ID)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		if profile != volumeserver.CoherenceStrict || h.Visibility == nil {
			return h.errorResponse(req.GetRequestId(), syscall.EPERM, false)
		}
		// credential() authenticated this request as cred.ID and DetachRequest
		// contains no caller-selected session. CleanDetach therefore trusts only
		// the official supervisor for this exact mount. A frontend that cannot
		// establish terminal kernel state sends no observation and lets the
		// session die fenced, leaving durable membership active.
		if err := h.Visibility.CleanDetach(cred.ID, mountAbsenceProof(body.Detach.GetMountAbsence())); err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
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
		if body.NextVisibility.GetAcknowledgeAfter() {
			if cursor == (volumeserver.VisibilityCursor{}) {
				return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
			}
			if err := h.Visibility.AckWithContention(cred.ID, cursor, body.NextVisibility.GetOrderedAdmissionContended()); err != nil {
				return h.errorResponse(req.GetRequestId(), err, false)
			}
		} else if body.NextVisibility.GetOrderedAdmissionContended() {
			return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
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
			item, attr, snapshot, err := h.lookupForSession(ctx, cred.ID, parent, body.Lookup.GetName())
			if errors.Is(err, syscall.ENOENT) {
				resp := h.success(0)
				resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: snapshot}}
				return resp
			}
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
			itemReply := itemProto(item, attr, identity)
			itemReply.SnapshotSequence = snapshot
			itemReply.ObjectVersion = h.sampledObjectVersion(identity, snapshot)
			resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemReply}}
			return resp
		})
	case *authoritypb.Request_GetAttr:
		attr, identity, snapshot, err := h.getattr(ctx, cred.ID, body.GetAttr)
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		resp := h.success(req.GetRequestId())
		resp.Body = &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: attrProto(attr), ObjectVersion: h.sampledObjectVersion(identity, snapshot), SnapshotSequence: snapshot}}
		return resp
	case *authoritypb.Request_SetAttr:
		set := body.SetAttr
		var item, handle xfsstore.Capability
		var coordinate visibilityCoordinate
		var mode fs.FileMode
		var releaseMutation func()
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
			if item != (xfsstore.Capability{}) && handle != (xfsstore.Capability{}) {
				itemIdentity, identityErr := h.Store.Identity(item)
				if identityErr != nil {
					return nil, identityErr
				}
				handleIdentity, identityErr := h.Store.IdentityOpen(handle)
				if identityErr != nil {
					return nil, identityErr
				}
				if itemIdentity != handleIdentity {
					return nil, syscall.EINVAL
				}
			}
			if handle != (xfsstore.Capability{}) {
				coordinate, err = h.coordinateOpen(handle)
			} else {
				coordinate, err = h.coordinateItem(item)
			}
			if err != nil {
				return nil, err
			}
			releaseMutation, err = lockMutationStore(h.Store, coordinate.identity)
			if err != nil {
				return nil, err
			}
			targets := []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
			if set.Size != nil {
				targets = append(targets, inodeTarget(volumeserver.VisibilityData, coordinate, set.GetSize()))
			}
			return targets, nil
		}
		completeTargets := func(attr xfsstore.Attr) []volumeserver.VisibilityTarget {
			targets := []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
			if set.Size != nil {
				targets = append(targets, inodeTarget(volumeserver.VisibilityData, coordinate, attr.Size))
			}
			return targets
		}
		response := h.mutateVisibleSequence(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			var modePtr *fs.FileMode
			if set.Mode != nil {
				modePtr = &mode
			}
			attr, err := h.Store.SetAttr(item, handle, xfsstore.SetAttrSpec{
				Mode: modePtr, UID: set.Uid, GID: set.Gid, Size: set.Size,
				ATimeNS: set.AtimeNs, MTimeNS: set.MtimeNs,
				ATimeNow: set.GetAtimeNow(), MTimeNow: set.GetMtimeNow(),
			})
			if err != nil {
				uncertain := uncertainFailure(err)
				resp := h.errorResponse(0, err, uncertain)
				if uncertain {
					resp.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: coordinate.identity, attr: attr, roles: postStateRoleTarget, changed: true})
					return resp, completeTargets(attr)
				}
				return resp, nil
			}
			resp := h.success(0)
			resp.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: coordinate.identity, attr: attr, roles: postStateRoleTarget, changed: true})
			return resp, completeTargets(attr)
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
	case *authoritypb.Request_Tmpfile:
		var parent xfsstore.Capability
		var parentCoordinate visibilityCoordinate
		var releaseMutation func()
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			var err error
			parent, err = h.item(cred.ID, body.Tmpfile.GetParent())
			if err != nil {
				return nil, err
			}
			parentCoordinate, err = h.coordinateItem(parent)
			if err != nil {
				return nil, err
			}
			releaseMutation, err = lockMutationStore(h.Store, parentCoordinate.identity)
			if err != nil {
				return nil, err
			}
			return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}, nil
		}
		response := h.mutateVisibleSequence(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			store, ok := h.Store.(tmpfileStore)
			flags := body.Tmpfile.GetFlags()
			mode, valid := modeFromProtocol(body.Tmpfile.GetMode())
			if !ok || !valid || flags == nil || !flags.GetWrite() || flags.GetTruncate() {
				return h.errorResponse(0, syscall.EINVAL, false), nil
			}
			reservation, err := h.reserveCapabilities(cred.ID, 1, 1)
			if err != nil {
				return h.errorResponse(0, err, false), nil
			}
			defer reservation.release()
			item, attr, err := store.Tmpfile(parent, mode, body.Tmpfile.GetExclusive())
			if err != nil {
				resp := h.errorResponse(0, err, uncertainFailure(err))
				return resp, uncertainVisibilityTargets(resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)})
			}
			handle, err := h.Store.OpenFile(item, openFlags(flags))
			if err != nil {
				h.forgetItem(item)
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			if err := reservation.commit(
				[]trackedCapability{{value: item}},
				[]trackedCapability{{value: handle}},
			); err != nil {
				h.closeOpen(handle)
				h.forgetItem(item)
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			cleanupUndeliverable := func() {
				h.untrackOpen(cred.ID, handle)
				h.closeOpen(handle)
				h.untrackItem(cred.ID, item)
				h.forgetItem(item)
			}
			identity, err := h.Store.Identity(item)
			if err != nil {
				cleanupUndeliverable()
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			resp := h.success(0)
			itemReply := itemProto(item, attr, identity)
			itemReply.ObjectVersion, itemReply.SnapshotSequence = sequence, sequence
			resp.Body = &authoritypb.Response_Tmpfile{Tmpfile: &authoritypb.TmpfileReply{
				Item: itemReply, Handle: append([]byte(nil), handle[:]...),
			}}
			parentAttr, parentErr := h.Store.Getattr(parent)
			if parentErr != nil {
				cleanupUndeliverable()
				return h.errorResponse(0, parentErr, true), []volumeserver.VisibilityTarget{}
			}
			resp.PostState = h.mutationPostState(sequence,
				postStateSnapshot{identity: identity, attr: attr, roles: postStateRoleCreated, changed: true},
				postStateSnapshot{identity: parentCoordinate.identity, attr: parentAttr, roles: postStateRoleParent, changed: true},
			)
			return resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
	case *authoritypb.Request_Create:
		var parent xfsstore.Capability
		var parentCoordinate, existingCoordinate visibilityCoordinate
		var existingSize int64
		var existed bool
		var releaseMutation func()
		bindingRefreshes := 0
		prepare := func(resolutions *operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Create.GetName()); err != nil {
				return nil, err
			}
			resolvedParent, err := resolutions.item(body.Create.GetParent())
			if err != nil {
				return nil, err
			}
			parent, parentCoordinate = resolvedParent.cap, resolvedParent.coordinate
			resolvedName, err := resolutions.namespace(parent, body.Create.GetName())
			if err != nil {
				return nil, err
			}
			existingCoordinate, existingSize, existed = resolvedName.coordinate, resolvedName.size, resolvedName.found
			lockIdentities := [][16]byte{parentCoordinate.identity}
			if existed {
				lockIdentities = append(lockIdentities, existingCoordinate.identity)
			}
			releaseMutation, err = lockMutationStore(h.Store, lockIdentities...)
			if err != nil {
				return nil, err
			}
			// The source gate prevents an authority namespace writer from passing
			// while this dependency turn is held. Re-read under the complete XFS
			// writer-stripe set as a negative control against a stale resolution;
			// if the binding changed, this turn's target-identity dependency is no
			// longer complete and the whole request must resolve again.
			resolutions.invalidateNamespaceBindings()
			lockedName, lookupErr := resolutions.namespace(parent, body.Create.GetName())
			if lookupErr != nil || lockedName.found != existed || existed && lockedName.coordinate != existingCoordinate {
				releaseMutation()
				releaseMutation = nil
				if lookupErr != nil {
					return nil, lookupErr
				}
				bindingRefreshes++
				if bindingRefreshes >= maxStabilizeAttempts {
					return nil, syscall.EAGAIN
				}
				return nil, volumeserver.ErrVisibilityDependencyRefresh
			}
			if existed {
				existingSize = lockedName.size
			}
			if !existed {
				return []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Create.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}, nil
			}
			// Existing-name CREATE publishes an exact name snapshot and both object
			// records even when opening the target is a no-op. The source gate already
			// covers this complete set; O_TRUNC additionally covers target data.
			targets := []volumeserver.VisibilityTarget{
				namespaceTarget(parentCoordinate, body.Create.GetName()),
				inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0),
				inodeTarget(volumeserver.VisibilityAttributes, existingCoordinate, 0),
			}
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
		response := h.mutateVisibleSequenceResolved(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
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
			if existed || body.Create.GetFlags() != nil && body.Create.GetFlags().GetTruncate() {
				post, snapshotErr := h.Store.GetattrOpen(handle)
				if snapshotErr != nil {
					targets := createdTargets(item)
					cleanupUndeliverable()
					return h.errorResponse(0, snapshotErr, true), targets
				}
				attr = post
			}
			itemIdentity, identityErr := h.Store.Identity(item)
			if identityErr != nil {
				targets := createdTargets(item)
				cleanupUndeliverable()
				return h.errorResponse(0, identityErr, true), targets
			}
			if existed {
				parentAttr, parentErr := h.Store.Getattr(parent)
				if parentErr != nil {
					cleanupUndeliverable()
					return h.errorResponse(0, parentErr, true), []volumeserver.VisibilityTarget{}
				}
				truncated := body.Create.GetFlags() != nil && body.Create.GetFlags().GetTruncate()
				resp := h.success(0)
				resp.PostState = h.mutationPostState(sequence,
					postStateSnapshot{identity: itemIdentity, attr: attr, roles: postStateRoleTarget, changed: truncated},
					postStateSnapshot{identity: parentCoordinate.identity, attr: parentAttr, roles: postStateRoleParent, changed: false},
				)
				itemReply := itemProto(item, attr, itemIdentity)
				for _, object := range resp.PostState.GetObjects() {
					if bytes.Equal(object.GetStableIdentity(), itemIdentity[:]) {
						itemReply.ObjectVersion = object.GetObjectVersion()
						break
					}
				}
				itemReply.SnapshotSequence = sequence
				resp.Body = &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: itemReply, Handle: handle[:]}}
				if !truncated {
					return resp, nil
				}
				return resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, existingCoordinate, attr.Size), inodeTarget(volumeserver.VisibilityAttributes, existingCoordinate, 0)}
			}
			parentAttr, parentErr := h.Store.Getattr(parent)
			if parentErr != nil {
				cleanupUndeliverable()
				return h.errorResponse(0, parentErr, true), []volumeserver.VisibilityTarget{}
			}
			resp := h.success(0)
			resp.PostState = h.mutationPostState(sequence,
				postStateSnapshot{identity: itemIdentity, attr: attr, roles: postStateRoleCreated, changed: true},
				postStateSnapshot{identity: parentCoordinate.identity, attr: parentAttr, roles: postStateRoleParent, changed: true},
			)
			itemReply := itemProto(item, attr, itemIdentity)
			itemReply.ObjectVersion, itemReply.SnapshotSequence = sequence, sequence
			resp.Body = &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: itemReply, Handle: handle[:]}}
			return resp, []volumeserver.VisibilityTarget{
				namespaceTargetPost(parentCoordinate, body.Create.GetName(), visibilityCoordinate{identity: itemIdentity, ino: attr.Ino}),
				inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0),
			}
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
	case *authoritypb.Request_Mkdir:
		var parent xfsstore.Capability
		var parentCoordinate visibilityCoordinate
		var releaseMutation func()
		prepare := func(resolutions *operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Mkdir.GetName()); err != nil {
				return nil, err
			}
			resolvedParent, err := resolutions.item(body.Mkdir.GetParent())
			parent, parentCoordinate = resolvedParent.cap, resolvedParent.coordinate
			if err == nil {
				releaseMutation, err = lockMutationStore(h.Store, parentCoordinate.identity)
			}
			return []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Mkdir.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}, err
		}
		response := h.mutateVisibleSequenceResolved(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
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
			itemReply := itemProto(item, attr, itemIdentity)
			itemReply.ObjectVersion, itemReply.SnapshotSequence = sequence, sequence
			resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemReply}}
			parentAttr, parentErr := h.Store.Getattr(parent)
			if parentErr != nil {
				h.untrackItem(cred.ID, item)
				h.forgetItem(item)
				return h.errorResponse(0, parentErr, true), []volumeserver.VisibilityTarget{}
			}
			resp.PostState = h.mutationPostState(sequence,
				postStateSnapshot{identity: itemIdentity, attr: attr, roles: postStateRoleCreated, changed: true},
				postStateSnapshot{identity: parentCoordinate.identity, attr: parentAttr, roles: postStateRoleParent, changed: true},
			)
			return resp, []volumeserver.VisibilityTarget{
				namespaceTargetPost(parentCoordinate, body.Mkdir.GetName(), visibilityCoordinate{identity: itemIdentity, ino: attr.Ino}),
				inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0),
			}
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
	case *authoritypb.Request_Unlink:
		var parent xfsstore.Capability
		var parentCoordinate, removedCoordinate visibilityCoordinate
		var releaseMutation func()
		prepare := func(resolutions *operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Unlink.GetName()); err != nil {
				return nil, err
			}
			resolvedParent, err := resolutions.item(body.Unlink.GetParent())
			if err != nil {
				return nil, err
			}
			parent, parentCoordinate = resolvedParent.cap, resolvedParent.coordinate
			resolvedName, err := resolutions.namespace(parent, body.Unlink.GetName())
			if err == nil && !resolvedName.found {
				err = syscall.ENOENT
			}
			removedCoordinate = resolvedName.coordinate
			if err == nil {
				releaseMutation, err = lockMutationStore(h.Store, parentCoordinate.identity, removedCoordinate.identity)
			}
			return []volumeserver.VisibilityTarget{namespaceTargetRelated(parentCoordinate, body.Unlink.GetName(), removedCoordinate), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0), inodeTarget(volumeserver.VisibilityAttributes, removedCoordinate, 0)}, err
		}
		response := h.mutateVisibleSequenceResolved(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			removed, _, lookupErr := h.Store.Lookup(parent, string(body.Unlink.GetName()))
			if lookupErr != nil {
				return h.errorResponse(0, lookupErr, false), nil
			}
			defer h.forgetItem(removed)
			if err := h.Store.Unlink(parent, string(body.Unlink.GetName()), body.Unlink.GetDirectory()); err != nil {
				resp := h.errorResponse(0, err, false)
				targets := []volumeserver.VisibilityTarget{namespaceTargetRelated(parentCoordinate, body.Unlink.GetName(), removedCoordinate), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0), inodeTarget(volumeserver.VisibilityAttributes, removedCoordinate, 0)}
				return resp, uncertainVisibilityTargets(resp, targets)
			}
			targets := []volumeserver.VisibilityTarget{namespaceTargetRelated(parentCoordinate, body.Unlink.GetName(), removedCoordinate), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0), inodeTarget(volumeserver.VisibilityAttributes, removedCoordinate, 0)}
			removedAttr, removedErr := h.Store.Getattr(removed)
			parentAttr, parentErr := h.Store.Getattr(parent)
			if err := errors.Join(removedErr, parentErr); err != nil {
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			resp := h.success(0)
			resp.PostState = h.mutationPostState(sequence,
				postStateSnapshot{identity: removedCoordinate.identity, attr: removedAttr, roles: postStateRoleRemoved, changed: true},
				postStateSnapshot{identity: parentCoordinate.identity, attr: parentAttr, roles: postStateRoleParent, changed: true},
			)
			return resp, targets
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
	case *authoritypb.Request_Rename:
		var oldParent, newParent xfsstore.Capability
		var oldParentCoordinate, newParentCoordinate, movedCoordinate, replacedCoordinate visibilityCoordinate
		var replaced bool
		var releaseMutation func()
		prepare := func(resolutions *operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Rename.GetOldName()); err != nil {
				return nil, err
			}
			if err := namespaceName(body.Rename.GetNewName()); err != nil {
				return nil, err
			}
			resolvedOldParent, err := resolutions.item(body.Rename.GetOldParent())
			if err != nil {
				return nil, err
			}
			resolvedNewParent, err := resolutions.item(body.Rename.GetNewParent())
			if err != nil {
				return nil, err
			}
			oldParent, oldParentCoordinate = resolvedOldParent.cap, resolvedOldParent.coordinate
			newParent, newParentCoordinate = resolvedNewParent.cap, resolvedNewParent.coordinate
			moved, err := resolutions.namespace(oldParent, body.Rename.GetOldName())
			if err == nil && !moved.found {
				err = syscall.ENOENT
			}
			movedCoordinate = moved.coordinate
			if err == nil {
				var replacement namespaceResolution
				replacement, err = resolutions.namespace(newParent, body.Rename.GetNewName())
				replacedCoordinate, replaced = replacement.coordinate, replacement.found
			}
			if err == nil {
				identities := [][16]byte{oldParentCoordinate.identity, newParentCoordinate.identity, movedCoordinate.identity}
				if replaced {
					identities = append(identities, replacedCoordinate.identity)
				}
				releaseMutation, err = lockMutationStore(h.Store, identities...)
			}
			targets := renameVisibilityTargets(body.Rename, oldParentCoordinate, newParentCoordinate, movedCoordinate, replacedCoordinate, replaced, visibilityCoordinate{}, false, false)
			return targets, err
		}
		response := h.mutateVisibleSequenceResolved(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			var flags xfsstore.RenameFlags
			if body.Rename.GetNoReplace() {
				flags |= xfsstore.RenameNoReplace
			}
			if body.Rename.GetExchange() {
				flags |= xfsstore.RenameExchange
			}
			moved, _, lookupErr := h.Store.Lookup(oldParent, string(body.Rename.GetOldName()))
			if lookupErr != nil {
				return h.errorResponse(0, lookupErr, false), nil
			}
			defer h.forgetItem(moved)
			var overwritten xfsstore.Capability
			if replaced && (body.Rename.GetExchange() || replacedCoordinate.identity != movedCoordinate.identity) {
				overwritten, _, lookupErr = h.Store.Lookup(newParent, string(body.Rename.GetNewName()))
				if lookupErr != nil {
					return h.errorResponse(0, lookupErr, false), nil
				}
				defer h.forgetItem(overwritten)
			}
			if err := h.Store.Rename(oldParent, string(body.Rename.GetOldName()), newParent, string(body.Rename.GetNewName()), flags); err != nil {
				resp := h.errorResponse(0, err, false)
				return resp, uncertainVisibilityTargets(resp, renameVisibilityTargets(body.Rename, oldParentCoordinate, newParentCoordinate, movedCoordinate, replacedCoordinate, replaced, visibilityCoordinate{}, false, false))
			}
			// The dependency set held both authoritative pre-bindings fixed through
			// the syscall. POSIX therefore determines the exact post-state without
			// another filesystem round trip: exchange swaps the two bindings; a
			// normal rename whose names already bind the same inode is a no-op; any
			// other successful normal rename removes old and binds new to moved.
			// The identity comparison, not the flag alone, is the crucial no-op
			// discriminator for distinct hard-link names.
			newPostCoordinate := movedCoordinate
			var oldPostCoordinate visibilityCoordinate
			var oldPostBound bool
			switch {
			case body.Rename.GetExchange():
				oldPostCoordinate, oldPostBound = replacedCoordinate, replaced
			case replaced && replacedCoordinate.identity == movedCoordinate.identity:
				oldPostCoordinate, oldPostBound = movedCoordinate, true
			}
			rename := &authoritypb.RenameReply{
				NewPostIdentity: append([]byte(nil), newPostCoordinate.identity[:]...),
			}
			if oldPostBound {
				rename.OldPostIdentity = append([]byte(nil), oldPostCoordinate.identity[:]...)
			}
			resp := h.success(0)
			resp.Body = &authoritypb.Response_Rename{Rename: rename}
			movedAttr, movedErr := h.Store.Getattr(moved)
			oldParentAttr, oldParentErr := h.Store.Getattr(oldParent)
			newParentAttr, newParentErr := h.Store.Getattr(newParent)
			if err := errors.Join(movedErr, oldParentErr, newParentErr); err != nil {
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			noChange := !body.Rename.GetExchange() && replaced && replacedCoordinate.identity == movedCoordinate.identity
			snapshots := []postStateSnapshot{
				{identity: movedCoordinate.identity, attr: movedAttr, roles: postStateRoleSource | postStateRoleDestination, changed: !noChange},
				{identity: oldParentCoordinate.identity, attr: oldParentAttr, roles: postStateRoleOldParent, changed: !noChange},
				{identity: newParentCoordinate.identity, attr: newParentAttr, roles: postStateRoleNewParent, changed: !noChange},
			}
			if replaced && (body.Rename.GetExchange() || replacedCoordinate.identity != movedCoordinate.identity) {
				replacedAttr, replacedErr := h.Store.Getattr(overwritten)
				if replacedErr != nil {
					return h.errorResponse(0, replacedErr, true), []volumeserver.VisibilityTarget{}
				}
				roles := postStateRoleOverwritten
				if body.Rename.GetExchange() {
					roles = postStateRoleSource | postStateRoleDestination | postStateRoleExchanged
					snapshots[0].roles |= postStateRoleExchanged
				}
				snapshots = append(snapshots, postStateSnapshot{identity: replacedCoordinate.identity, attr: replacedAttr, roles: roles, changed: !noChange})
			}
			resp.PostState = h.mutationPostState(sequence, snapshots...)
			return resp, renameVisibilityTargets(body.Rename, oldParentCoordinate, newParentCoordinate, movedCoordinate, replacedCoordinate, replaced, oldPostCoordinate, oldPostBound, true)
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
	case *authoritypb.Request_Link:
		var source, parent xfsstore.Capability
		var sourceCoordinate, parentCoordinate visibilityCoordinate
		var releaseMutation func()
		prepare := func(resolutions *operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Link.GetNewName()); err != nil {
				return nil, err
			}
			resolvedSource, err := resolutions.item(body.Link.GetExistingItem())
			if err != nil {
				return nil, err
			}
			resolvedParent, err := resolutions.item(body.Link.GetNewParent())
			source, sourceCoordinate = resolvedSource.cap, resolvedSource.coordinate
			parent, parentCoordinate = resolvedParent.cap, resolvedParent.coordinate
			if err == nil {
				releaseMutation, err = lockMutationStore(h.Store, sourceCoordinate.identity, parentCoordinate.identity)
			}
			return linkVisibilityTargets(body.Link.GetNewName(), parentCoordinate, sourceCoordinate, false), err
		}
		response := h.mutateVisibleSequenceResolved(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			attr, err := h.Store.Link(source, parent, string(body.Link.GetNewName()))
			if err != nil {
				resp := h.errorResponse(0, err, false)
				targets := linkVisibilityTargets(body.Link.GetNewName(), parentCoordinate, sourceCoordinate, false)
				return resp, uncertainVisibilityTargets(resp, targets)
			}
			resp := h.success(0)
			itemReply := itemProto(source, attr, sourceCoordinate.identity)
			itemReply.ObjectVersion, itemReply.SnapshotSequence = sequence, sequence
			resp.Body = &authoritypb.Response_Link{Link: &authoritypb.LinkReply{Item: itemReply}}
			parentAttr, parentErr := h.Store.Getattr(parent)
			if parentErr != nil {
				return h.errorResponse(0, parentErr, true), []volumeserver.VisibilityTarget{}
			}
			resp.PostState = h.mutationPostState(sequence,
				postStateSnapshot{identity: sourceCoordinate.identity, attr: attr, roles: postStateRoleTarget, changed: true},
				postStateSnapshot{identity: parentCoordinate.identity, attr: parentAttr, roles: postStateRoleParent, changed: true},
			)
			targets := linkVisibilityTargets(body.Link.GetNewName(), parentCoordinate, sourceCoordinate, true)
			return resp, targets
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
	case *authoritypb.Request_Symlink:
		var parent xfsstore.Capability
		var parentCoordinate visibilityCoordinate
		var releaseMutation func()
		prepare := func(resolutions *operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
			if err := namespaceName(body.Symlink.GetName()); err != nil {
				return nil, err
			}
			resolvedParent, err := resolutions.item(body.Symlink.GetParent())
			parent, parentCoordinate = resolvedParent.cap, resolvedParent.coordinate
			if err == nil {
				releaseMutation, err = lockMutationStore(h.Store, parentCoordinate.identity)
			}
			return []volumeserver.VisibilityTarget{namespaceTarget(parentCoordinate, body.Symlink.GetName()), inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0)}, err
		}
		response := h.mutateVisibleSequenceResolved(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
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
			itemReply := itemProto(item, attr, itemIdentity)
			itemReply.ObjectVersion, itemReply.SnapshotSequence = sequence, sequence
			resp.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemReply}}
			parentAttr, parentErr := h.Store.Getattr(parent)
			if parentErr != nil {
				h.untrackItem(cred.ID, item)
				h.forgetItem(item)
				return h.errorResponse(0, parentErr, true), []volumeserver.VisibilityTarget{}
			}
			resp.PostState = h.mutationPostState(sequence,
				postStateSnapshot{identity: itemIdentity, attr: attr, roles: postStateRoleCreated, changed: true},
				postStateSnapshot{identity: parentCoordinate.identity, attr: parentAttr, roles: postStateRoleParent, changed: true},
			)
			return resp, []volumeserver.VisibilityTarget{
				namespaceTargetPost(parentCoordinate, body.Symlink.GetName(), visibilityCoordinate{identity: itemIdentity, ino: attr.Ino}),
				inodeTarget(volumeserver.VisibilityAttributes, parentCoordinate, 0),
			}
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
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
		var releaseMutation func()
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			var err error
			item, err = h.item(cred.ID, body.Open.GetItem())
			if err == nil {
				coordinate, err = h.coordinateItem(item)
			}
			if err == nil {
				releaseMutation, err = lockMutationStore(h.Store, coordinate.identity)
			}
			return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, coordinate, 0), inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}, err
		}
		response := h.mutateVisibleSequence(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			resp := openApply(item)
			if !visibilityChanged(resp) {
				return resp, nil
			}
			attr, err := h.Store.Getattr(item)
			if err != nil {
				cleanupOpenedHandle()
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			resp.PostState = h.mutationPostState(sequence, postStateSnapshot{
				identity: coordinate.identity, attr: attr, roles: postStateRoleTarget, changed: true,
			})
			return resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityData, coordinate, attr.Size), inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
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
	case *authoritypb.Request_WriteTransaction:
		if body.WriteTransaction.GetPhase() == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT {
			return h.commitWriteTransaction(ctx, req, cred, body.WriteTransaction)
		}
		return h.handleWriteTransaction(ctx, req, cred, body.WriteTransaction)
	case *authoritypb.Request_OneShotWrite:
		return h.handleOneShotWrite(ctx, req, cred, body.OneShotWrite)
	case *authoritypb.Request_Fallocate:
		return h.handleFallocate(ctx, req, cred, body.Fallocate)
	case *authoritypb.Request_CopyFileRange:
		return h.handleCopyFileRange(ctx, req, cred, body.CopyFileRange)
	case *authoritypb.Request_Fsync:
		handle, err := h.open(cred.ID, body.Fsync.GetHandle())
		if err != nil {
			return h.errorResponse(req.GetRequestId(), err, false)
		}
		group := 0
		if store, ok := h.Store.(coalescingFsyncStore); ok {
			group, err = store.FsyncCoalesced(handle, body.Fsync.GetDataOnly())
		} else {
			err = h.Store.Fsync(handle, body.Fsync.GetDataOnly())
		}
		if group != 0 && h.Metrics != nil {
			h.Metrics.ObserveFsyncBatch(group)
		}
		if err != nil {
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
			var pageSnapshot uint64
			result := &authoritypb.ReadDirReply{}
			// The reply is built to the same byte budget that was reserved for
			// it, so a directory listing can never be the reply that does not
			// fit in a frame. Stopping early is an ordinary short readdir: the
			// caller resumes from the last entry's cookie.
			budget := h.readDirEntryBudget(body.ReadDir.GetMaxEntries())
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
				var candidates []directoryPageCandidate
				stabilized := false
				for attempt := 0; attempt < maxStabilizeAttempts; attempt++ {
					entries, _, current, eof, directory, err = h.Store.ReadDirOpen(handle, cookie, verifier, int(body.ReadDir.GetMaxEntries()))
					if err != nil {
						forgetIssued()
						return h.errorResponse(0, err, false)
					}
					var conflict bool
					candidates, budgetExhausted, conflict, err = h.constructDirectoryPage(
						directory, entries, cookie, body.ReadDir.GetWantItems(), budget,
					)
					if err != nil {
						forgetIssued()
						return h.errorResponse(0, err, false)
					}
					if conflict {
						continue
					}
					waited, snapshot, stabilizeErr := h.stabilizeDirectoryPage(ctx, cred.ID, handle, directory, candidates)
					if stabilizeErr != nil {
						h.forgetDirectoryCandidates(candidates)
						forgetIssued()
						return h.errorResponse(0, stabilizeErr, false)
					}
					if waited {
						h.forgetDirectoryCandidates(candidates)
						continue
					}
					futureVersion := false
					for _, candidate := range candidates {
						if candidate.item != (xfsstore.Capability{}) && candidate.dirent.GetObjectVersion() > snapshot {
							futureVersion = true
							break
						}
					}
					if futureVersion {
						h.forgetDirectoryCandidates(candidates)
						continue
					}
					valid, verifyErr := h.revalidateDirectoryPage(
						handle, directory, cookie, verifier, current,
						int(body.ReadDir.GetMaxEntries()), entries, eof, candidates,
					)
					if verifyErr != nil {
						h.forgetDirectoryCandidates(candidates)
						forgetIssued()
						return h.errorResponse(0, verifyErr, false)
					}
					if !valid {
						h.forgetDirectoryCandidates(candidates)
						continue
					}
					pageSnapshot = snapshot
					stabilized = true
					break
				}
				if !stabilized {
					forgetIssued()
					return h.errorResponse(0, syscall.EAGAIN, false)
				}
				result.Verifier, result.Eof = current[:], eof && !budgetExhausted
				for _, candidate := range candidates {
					candidate.dirent.SnapshotSequence = pageSnapshot
					if candidate.dirent.GetItem() != nil {
						candidate.dirent.Item.ObjectVersion = candidate.dirent.GetObjectVersion()
						candidate.dirent.Item.SnapshotSequence = pageSnapshot
						issued = append(issued, issuedItem{item: candidate.item, name: candidate.dirent.GetName()})
					} else if candidate.item != (xfsstore.Capability{}) {
						h.forgetItem(candidate.item)
					}
					result.Entries = append(result.Entries, candidate.dirent)
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
		var releaseMutation func()
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
			if err == nil {
				releaseMutation, err = lockMutationStore(h.Store, coordinate.identity)
			}
			return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}, err
		}
		response := h.mutateVisibleSequence(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			if err := h.Store.SetXattr(item, string(body.SetXattr.GetName()), body.SetXattr.GetValue(), mode); err != nil {
				resp := h.errorResponse(0, err, false)
				return resp, uncertainVisibilityTargets(resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)})
			}
			attr, err := h.Store.Getattr(item)
			if err != nil {
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			resp := h.success(0)
			resp.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: coordinate.identity, attr: attr, roles: postStateRoleTarget, changed: true})
			return resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
	case *authoritypb.Request_RemoveXattr:
		var item xfsstore.Capability
		var coordinate visibilityCoordinate
		var releaseMutation func()
		prepare := func() ([]volumeserver.VisibilityTarget, error) {
			var err error
			item, err = h.item(cred.ID, body.RemoveXattr.GetItem())
			if err == nil {
				coordinate, err = h.coordinateItem(item)
			}
			if err == nil {
				releaseMutation, err = lockMutationStore(h.Store, coordinate.identity)
			}
			return []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}, err
		}
		response := h.mutateVisibleSequence(ctx, req, cred, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			if err := h.Store.RemoveXattr(item, string(body.RemoveXattr.GetName())); err != nil {
				resp := h.errorResponse(0, err, false)
				return resp, uncertainVisibilityTargets(resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)})
			}
			attr, err := h.Store.Getattr(item)
			if err != nil {
				return h.errorResponse(0, err, true), []volumeserver.VisibilityTarget{}
			}
			resp := h.success(0)
			resp.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: coordinate.identity, attr: attr, roles: postStateRoleTarget, changed: true})
			return resp, []volumeserver.VisibilityTarget{inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)}
		})
		if releaseMutation != nil {
			releaseMutation()
		}
		return response
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

type directoryPageCandidate struct {
	enumerated xfsstore.Dirent
	dirent     *authoritypb.Dirent
	item       xfsstore.Capability
	identity   [16]byte
	attr       xfsstore.Attr
}

func (h *VolumeHandler) forgetDirectoryCandidates(candidates []directoryPageCandidate) {
	for _, candidate := range candidates {
		if candidate.item != (xfsstore.Capability{}) {
			h.forgetItem(candidate.item)
		}
	}
}

func (h *VolumeHandler) constructDirectoryPage(
	directory xfsstore.Capability,
	entries []xfsstore.Dirent,
	cookie uint64,
	wantItems bool,
	budget uint32,
) ([]directoryPageCandidate, bool, bool, error) {
	candidates := make([]directoryPageCandidate, 0, len(entries))
	used := uint64(0)
	for i, entry := range entries {
		candidate := directoryPageCandidate{enumerated: entry}
		attr := xfsstore.Attr{Kind: xfsstore.KindOpaque, Ino: entry.Ino}
		if entry.Kind != xfsstore.KindOpaque {
			item, itemAttr, err := h.Store.Lookup(directory, entry.Name)
			switch {
			case errors.Is(err, syscall.ENOENT), errors.Is(err, xfsstore.ErrStaleObject):
				h.forgetDirectoryCandidates(candidates)
				return nil, false, true, nil
			case errors.Is(err, xfsstore.ErrForbiddenType), errors.Is(err, xfsstore.ErrProjectIsolation):
				// The namespace fact remains exact, but this authority never
				// exposes the object's metadata or a retained capability.
			case err != nil:
				h.forgetDirectoryCandidates(candidates)
				return nil, false, false, err
			case itemAttr.Ino != entry.Ino || itemAttr.Kind != entry.Kind:
				h.forgetItem(item)
				h.forgetDirectoryCandidates(candidates)
				return nil, false, true, nil
			default:
				identity, identityErr := h.Store.Identity(item)
				if identityErr != nil {
					h.forgetItem(item)
					h.forgetDirectoryCandidates(candidates)
					return nil, false, false, identityErr
				}
				candidate.item, candidate.identity, candidate.attr = item, identity, itemAttr
				attr = itemAttr
			}
		}
		dirent := &authoritypb.Dirent{
			Name: []byte(entry.Name), Attr: attrProto(attr),
			NextCookie: encodeCookie(cookie + uint64(i) + 1),
		}
		if candidate.item != (xfsstore.Capability{}) {
			dirent.ObjectVersion = h.sampledObjectVersion(candidate.identity, ^uint64(0))
			if wantItems {
				dirent.Item = itemProto(candidate.item, candidate.attr, candidate.identity)
			}
		}
		candidate.dirent = dirent
		cost := direntCost(dirent)
		if used+cost > uint64(budget) {
			if candidate.item != (xfsstore.Capability{}) {
				h.forgetItem(candidate.item)
			}
			return candidates, true, false, nil
		}
		used += cost
		candidates = append(candidates, candidate)
	}
	return candidates, false, false, nil
}

func sameDirectoryEnumeration(left, right []xfsstore.Dirent) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (h *VolumeHandler) revalidateDirectoryPage(
	handle, directory xfsstore.Capability,
	cookie uint64,
	verifier, current [16]byte,
	maxEntries int,
	entries []xfsstore.Dirent,
	eof bool,
	candidates []directoryPageCandidate,
) (bool, error) {
	checkEntries, _, checkVerifier, checkEOF, checkDirectory, err := h.Store.ReadDirOpen(handle, cookie, verifier, maxEntries)
	if err != nil {
		return false, err
	}
	if checkDirectory != directory || checkVerifier != current || checkEOF != eof || !sameDirectoryEnumeration(checkEntries, entries) {
		return false, nil
	}
	parentAttr, err := h.Store.GetattrOpen(handle)
	if err != nil {
		return false, err
	}
	if !verifierMatches(current, parentAttr) {
		return false, nil
	}
	for _, candidate := range candidates {
		if candidate.item == (xfsstore.Capability{}) {
			continue
		}
		item, attr, lookupErr := h.Store.Lookup(directory, candidate.enumerated.Name)
		if errors.Is(lookupErr, syscall.ENOENT) || errors.Is(lookupErr, xfsstore.ErrStaleObject) ||
			errors.Is(lookupErr, xfsstore.ErrForbiddenType) || errors.Is(lookupErr, xfsstore.ErrProjectIsolation) {
			return false, nil
		}
		if lookupErr != nil {
			return false, lookupErr
		}
		identity, identityErr := h.Store.Identity(item)
		forgetErr := h.Store.Forget(item)
		if identityErr != nil {
			return false, identityErr
		}
		if forgetErr != nil {
			return false, forgetErr
		}
		if identity != candidate.identity || attr != candidate.attr ||
			h.sampledObjectVersion(identity, ^uint64(0)) != candidate.dirent.GetObjectVersion() {
			return false, nil
		}
	}
	return true, nil
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
		MaxInFlight: uint32(bounds.MaxInFlight), MaxWriteTransactionBytes: h.MaxWriteTransactionBytes,
	}}
	return resp
}

func (h *VolumeHandler) attach(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	requestID := req.GetRequestId()
	attach := req.GetAttach()
	if h.Store == nil || h.Runtime == nil || h.Authorizer == nil || attach.GetVolumeId() != h.Runtime.VolumeID() {
		return h.errorResponse(requestID, syscall.EPERM, false)
	}
	if !h.validResourceLimits() || !h.validBounds() {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	if h.Routes == nil {
		return h.errorResponse(requestID, errInternal, false)
	}
	attemptID, err := attachAttemptID(attach.GetAttachAttemptId())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	fingerprint, err := canonicalFingerprint(h.Runtime, req)
	if err != nil {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	profile, err := coherenceProfile(attach.GetCoherenceProfile())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	if h.Visibility == nil {
		return h.errorResponse(requestID, syscall.EOPNOTSUPP, false)
	}
	// Reject every peer-controlled, allocation-shaping attach value before the
	// single-use capability is presented. These checks are deliberately pure;
	// session-count and durable-membership admission remain after authorization.
	if err := h.Runtime.ValidateAttachSlots(attach.GetReplaySlots()); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	repair, err := namespaceRepair(attach.GetNamespaceRepair())
	if err != nil || attach.GetRepairBudgetMillis() > uint64((time.Duration(1<<63-1))/time.Millisecond) {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	commitment := volumeserver.VisibilityCommitment{
		CachedNameCapacity: attach.GetCachedNameCapacity(),
		RepairBudget:       time.Duration(attach.GetRepairBudgetMillis()) * time.Millisecond,
		NamespaceRepair:    repair,
		CompatibilityWriter: repair == volumeserver.NamespaceRepairCallbackSerialized ||
			repair == volumeserver.NamespaceRepairCallbackSerializedPipelined,
	}
	if err := h.Visibility.ValidateCommitment(commitment); err != nil {
		return h.errorResponse(requestID, err, false)
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
	// Every coherent mount is checked. Admitting it against a topology this
	// volume does not run would hide a subtree from every peer with no error.
	presented, declared, err := attachRoutesRevision(attach.GetRoutesRevision())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	// An attach pins this revision until all session resources and durable
	// visibility membership are installed.
	topology := h.Routes.AcquireTopologyRead()
	defer topology.Release()
	if err := h.Routes.Admit(presented, declared, "attach", false); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	peer, ok := PeerIdentity(ctx)
	if !ok {
		return h.errorResponse(requestID, syscall.EPERM, false)
	}
	root, err := h.Store.Root()
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	// PrepareAttach owns both admission and exact replay. It reserves the bounded
	// attempt/session record before invoking Authorize, so a full authority never
	// spends a single-use capability. Every other fallible, non-authorization
	// prerequisite above is prepared first for the same reason.
	cred, err := h.Runtime.PrepareAttach(
		ctx,
		attemptID,
		volumeserver.AttachRequestFingerprint(fingerprint),
		attach.GetReplaySlots(),
		volumeserver.PeerIdentity(peer),
		func(authorizeContext context.Context) (volumeserver.Authorization, error) {
			authorization, authorizeErr := h.Authorizer.Authorize(authorizeContext, attach.GetVolumeId(), attach.GetAccessToken())
			if authorizeErr != nil {
				return volumeserver.Authorization{}, syscall.EPERM
			}
			return authorization, nil
		},
	)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	provisionalDeadline, err := h.Runtime.ProvisionalDeadline(cred, attemptID)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	authorizationDeadline, err := h.Runtime.AuthorizationDeadline(cred, attemptID)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	// The runtime accepted this exact slot count, so the per-slot reply
	// accounting has the same length as the session's replay slots. Concurrent
	// exact Attach deliveries converge on one resource record; a changed reuse
	// was already rejected by PrepareAttach before this point.
	if _, err := h.ensureProvisionalSessionResources(sessionResourceSpec{
		credential: cred, id: cred.ID, attempt: attemptID, root: root,
		slots: attach.GetReplaySlots(), routes: presented,
		coherence: profile, commitment: commitment, authorizationDeadline: authorizationDeadline,
	}); err != nil {
		// No ACTIVE transition is possible on the transport while Attach owns the
		// pair transaction. Releasing this failed provisional allocation is the
		// exact rollback; there is no legacy Detach fallback.
		_ = h.Runtime.AbortProvisional(ctx, cred, attemptID)
		return h.errorResponse(requestID, err, false)
	}
	resp := h.success(requestID)
	resp.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
		SessionId: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:],
		ProvisionalDeadlineUnixNanos: provisionalDeadline.UnixNano(),
	}}
	return resp
}

func attachAttemptID(raw []byte) (volumeserver.AttachAttemptID, error) {
	var attempt volumeserver.AttachAttemptID
	if len(raw) != len(attempt) {
		return attempt, syscall.EINVAL
	}
	copy(attempt[:], raw)
	if attempt == (volumeserver.AttachAttemptID{}) {
		return attempt, syscall.EINVAL
	}
	return attempt, nil
}

func sessionStateProto(state volumeserver.SessionState) (authoritypb.SessionState, error) {
	switch state {
	case volumeserver.SessionStateProvisional:
		return authoritypb.SessionState_SESSION_STATE_PROVISIONAL, nil
	case volumeserver.SessionStateActive:
		return authoritypb.SessionState_SESSION_STATE_ACTIVE, nil
	case volumeserver.SessionStateAborted:
		return authoritypb.SessionState_SESSION_STATE_ABORTED, nil
	case volumeserver.SessionStateTerminal:
		return authoritypb.SessionState_SESSION_STATE_TERMINAL, nil
	default:
		return authoritypb.SessionState_SESSION_STATE_UNSPECIFIED, volumeserver.ErrSessionFenced
	}
}

func (h *VolumeHandler) resume(_ context.Context, requestID uint64, cred volumeserver.SessionCredential) *authoritypb.Response {
	resources, err := h.sessionResources(cred.ID)
	if err != nil || resources.attempt == (volumeserver.AttachAttemptID{}) {
		return h.errorResponse(requestID, volumeserver.ErrSessionExpired, false)
	}
	state, err := h.Runtime.SessionState(cred, resources.attempt)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	if state == volumeserver.SessionStateActive {
		// Only ACTIVE Resume renews the renewable lease. A provisional deadline
		// is absolute: reconnecting cannot keep an abandoned attach alive.
		if err := h.Runtime.Resume(cred); err != nil {
			return h.errorResponse(requestID, err, false)
		}
	}
	wireState, err := sessionStateProto(state)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	resp := h.success(requestID)
	resp.Body = &authoritypb.Response_Resume{Resume: &authoritypb.ResumeReply{State: wireState}}
	return resp
}

func (h *VolumeHandler) activate(ctx context.Context, requestID uint64, cred volumeserver.SessionCredential, request *authoritypb.ActivateRequest) *authoritypb.Response {
	if request == nil || request.GetDataBindingGeneration() == 0 || request.GetControlBindingGeneration() == 0 {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	attempt, err := attachAttemptID(request.GetAttachAttemptId())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	resources, err := h.sessionResources(cred.ID)
	if err != nil || resources.attempt != attempt {
		return h.errorResponse(requestID, volumeserver.ErrRequestMismatch, false)
	}
	resources.activationMu.Lock()
	defer resources.activationMu.Unlock()
	if _, err := h.exactSessionResources(cred.ID, attempt); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	h.resourcesMu.Lock()
	retained := resources.activationReply
	if retained != nil {
		retained = proto.Clone(retained).(*authoritypb.ActivateReply)
	}
	h.resourcesMu.Unlock()
	token, err := h.Runtime.PrepareActivation(ctx, cred, attempt)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	if token.Replay() {
		if retained == nil {
			return h.errorResponse(requestID, errInternal, false)
		}
		resp := h.success(requestID)
		resp.Body = &authoritypb.Response_Activate{Activate: retained}
		return resp
	}
	committed := false
	defer func() {
		if !committed {
			h.Runtime.CancelActivation(token)
		}
	}()
	// Activation rechecks the pinned revision under the topology read side. An
	// ApplyRoutes commit can happen after provisional Attach but can never fit
	// between this check and ACTIVE publication. An already-ACTIVE exact replay
	// returned above: it must reproduce its retained reply even if a later route
	// switch has made ordinary work from that session stale.
	topology := h.Routes.AcquireTopologyRead()
	defer topology.Release()
	if err := h.Routes.Admit(resources.routes, true, "activation", false); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	terminal, err := h.Runtime.SessionTerminal(cred.ID)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	if resources.coherence != volumeserver.CoherenceStrict || h.Visibility == nil {
		return h.errorResponse(requestID, errInternal, false)
	}
	var reply *authoritypb.ActivateReply
	_, err = h.Visibility.ActivateParticipant(
		cred.ID, resources.coherence, terminal, resources.commitment,
		func(initial volumeserver.VisibilityCursor) ([][16]byte, error) {
			// The root read and participant cache fact share registration's
			// exclusion boundary. A mutation therefore cannot slip between the
			// attributes returned to the new mount and the participant index that
			// makes that mutation target it.
			rootAttr, readErr := h.Store.Getattr(resources.root)
			if readErr != nil {
				return nil, readErr
			}
			rootIdentity, readErr := h.Store.Identity(resources.root)
			if readErr != nil {
				return nil, readErr
			}
			reply = h.newActivationReply(resources, rootAttr, rootIdentity, visibilityCursorProto(initial))
			if retainErr := h.retainActivationReply(cred.ID, resources, reply); retainErr != nil {
				return nil, retainErr
			}
			return [][16]byte{rootIdentity}, nil
		},
		func() { h.Runtime.CommitActivation(token) },
	)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	committed = true
	resp := h.success(requestID)
	resp.Body = &authoritypb.Response_Activate{Activate: reply}
	return resp
}

func (h *VolumeHandler) newActivationReply(resources *sessionResources, rootAttr xfsstore.Attr, rootIdentity [16]byte, cursor *authoritypb.VisibilityCursor) *authoritypb.ActivateReply {
	features := append([]string(nil), requiredAttachFeatures...)
	features = append(features, sessionReauthorizationFeature, mountEnrollmentReauthorizationFeature)
	features = append(features, requiredStrictAttachFeatures...)
	return &authoritypb.ActivateReply{
		Root: itemProto(resources.root, rootAttr, rootIdentity), Features: features,
		SessionLeaseMilliseconds: uint64(h.Runtime.SessionLease() / time.Millisecond), VisibilityCursor: cursor,
		RoutesRevision:                 append([]byte(nil), resources.routes[:]...),
		AuthorizationDeadlineUnixNanos: resources.authorizationDeadline.UnixNano(),
		State:                          authoritypb.SessionState_SESSION_STATE_ACTIVE,
	}
}

// retainActivationReply runs before the infallible runtime commit. For a
// strict session it is the visibility transaction's precommit step, after the
// exact initial cursor exists but before either membership or runtime ACTIVE
// can escape. Thus there is no state in which an active session exists without
// the response needed to recover a lost Activate write.
func (h *VolumeHandler) retainActivationReply(id volumeserver.SessionID, resources *sessionResources, reply *authoritypb.ActivateReply) error {
	if reply == nil {
		return errInternal
	}
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	if resources.ended || h.resources[id] != resources {
		return volumeserver.ErrSessionExpired
	}
	if resources.activationReply != nil {
		if !proto.Equal(resources.activationReply, reply) {
			return volumeserver.ErrRequestMismatch
		}
		return nil
	}
	resources.activationReply = proto.Clone(reply).(*authoritypb.ActivateReply)
	return nil
}

func (h *VolumeHandler) abortAttach(ctx context.Context, requestID uint64, cred volumeserver.SessionCredential, request *authoritypb.AbortAttachRequest) *authoritypb.Response {
	if request == nil {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	attempt, err := attachAttemptID(request.GetAttachAttemptId())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	// If resources still exist, share activation's local serialization. They may
	// already be gone on an exact Abort replay; the runtime keeps the bounded
	// attempt tombstone and is the authority for idempotence in that case.
	resources, _ := h.sessionResources(cred.ID)
	if resources != nil {
		resources.activationMu.Lock()
		defer resources.activationMu.Unlock()
	}
	if err := h.Runtime.AbortProvisional(ctx, cred, attempt); err != nil {
		return h.errorResponse(requestID, err, false)
	}
	resp := h.success(requestID)
	resp.Body = &authoritypb.Response_AbortAttach{AbortAttach: &authoritypb.AbortAttachReply{State: authoritypb.SessionState_SESSION_STATE_ABORTED}}
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
		h.MaxRetainedReplyBytes >= uint64(h.maxReplyBytes()) && h.WriteStaging != nil &&
		h.MaxWriteTransactionBytes > 0 && h.MaxWriteTransactionBytes <= math.MaxInt64 &&
		h.MaxWriteStagingBytesPerSession >= h.MaxWriteTransactionBytes &&
		h.MaxWriteStagingBytes >= h.MaxWriteStagingBytesPerSession &&
		h.MaxWriteTransactionsPerSession > 0 && h.MaxWriteTransactions >= h.MaxWriteTransactionsPerSession &&
		h.WriteTransactionProgressTimeout > 0 && h.WriteTransactionAbsoluteTimeout >= h.WriteTransactionProgressTimeout
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
	return h.mutateVisibleSequence(ctx, req, cred, prepare, func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		return apply()
	})
}

func (h *VolumeHandler) mutateVisibleResolved(
	ctx context.Context,
	req *authoritypb.Request,
	cred volumeserver.SessionCredential,
	prepare func(*operationResolutionContext) ([]volumeserver.VisibilityTarget, error),
	apply func() (*authoritypb.Response, []volumeserver.VisibilityTarget),
) *authoritypb.Response {
	return h.mutateVisibleSequenceResolved(ctx, req, cred, prepare, func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		return apply()
	})
}

func (h *VolumeHandler) mutateVisibleSequence(
	ctx context.Context,
	req *authoritypb.Request,
	cred volumeserver.SessionCredential,
	prepare func() ([]volumeserver.VisibilityTarget, error),
	apply func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget),
) *authoritypb.Response {
	return h.mutateVisibleSequenceResolved(ctx, req, cred, func(*operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
		return prepare()
	}, apply)
}

func (h *VolumeHandler) mutateVisibleSequenceResolved(
	ctx context.Context,
	req *authoritypb.Request,
	cred volumeserver.SessionCredential,
	prepare func(*operationResolutionContext) ([]volumeserver.VisibilityTarget, error),
	apply func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget),
) *authoritypb.Response {
	var writeCommitOwner *writeTransactionCommitOwner
	defer func() {
		if body := req.GetWriteTransaction(); body != nil {
			h.finishWriteTransactionCommit(cred.ID, body, writeCommitOwner)
		}
	}()
	return h.mutateOperation(ctx, req, cred, func(id volumeserver.MutationID) *authoritypb.Response {
		definiteRejection := func(err error) *authoritypb.Response {
			if req.GetOneShotWrite() != nil {
				return oneShotWriteRejection(err, false)
			}
			return h.errorResponse(0, err, false)
		}
		writeCommit := req.GetWriteTransaction()
		if writeCommit != nil {
			terminal, found, err := h.rejectedWriteTransactionTerminal(req, cred.ID, writeCommit)
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			if found {
				return terminal
			}
		}
		declaredGate, err := decodeSourcePublicationGate(req)
		if err != nil || declaredGate == nil {
			return definiteRejection(syscall.EINVAL)
		}
		resolutions := newOperationResolutionContext(h, cred.ID)
		expectedGate, err := resolutions.deriveSourcePublicationGate(req, false)
		if err != nil {
			return definiteRejection(err)
		}
		if !sourcePublicationGatesEqual(declaredGate, &expectedGate) {
			return definiteRejection(syscall.EINVAL)
		}
		if h.Visibility == nil {
			if writeCommit != nil {
				writeCommitOwner, err = h.markWriteTransactionCommitting(cred.ID, req, writeCommit)
				if err != nil {
					return h.errorResponse(0, err, false)
				}
			}
			if _, err := prepare(resolutions); err != nil {
				if writeCommit != nil {
					if rejected := h.rejectPendingWriteTransaction(cred.ID, writeCommit, err); rejected != nil {
						return rejected
					}
				}
				return definiteRejection(err)
			}
			resp, _ := apply(1)
			if visibilityChanged(resp) && !validMutationPostStateRoles(req, resp.GetPostState()) {
				return h.errorResponse(0, errInternal, true)
			}
			return resp
		}
		declaration := h.Visibility.DeclareSourceGate(expectedGate)
		defer declaration.Release()
		if sourcePublicationGateHasNamespace(expectedGate) {
			// Dependency sequencing needs the current bound inode identities before
			// admission. The declaration above snapshots the binding-key versions
			// before this lookup, allowing the coordinator to prove an uncontended
			// result current or refresh it after a preceding binding mutation.
			expectedGate, err = resolutions.deriveSourcePublicationGate(req, true)
			if err != nil {
				return definiteRejection(err)
			}
			if !sourcePublicationGatesEqual(declaredGate, &expectedGate) {
				return definiteRejection(syscall.EINVAL)
			}
		}
		var resp *authoritypb.Response
		normalizedPrepare := func() ([]volumeserver.VisibilityTarget, error) {
			targets, prepareErr := prepare(resolutions)
			if prepareErr != nil {
				return nil, prepareErr
			}
			return normalizeVisibilityTargets(targets)
		}
		var completeNormalizationErr error
		refreshGate := func() (volumeserver.SourcePublicationGate, error) {
			// Stable item and open-handle identities are immutable for the epoch.
			// Only namespace bindings can change while this request waits for its
			// dependency set, so item-only hot paths (especially Write) reuse the gate
			// already independently derived before enqueue instead of issuing a
			// second identity syscall.
			if !sourcePublicationGateHasNamespace(expectedGate) {
				return expectedGate, nil
			}
			// Namespace bindings are the only operation facts that can change
			// while this request waits for its dependency set. Discard the stale
			// cache exactly here; the refreshed answers remain authoritative
			// through prepare and apply under the acquired set.
			resolutions.invalidateNamespaceBindings()
			refreshed, refreshErr := resolutions.deriveSourcePublicationGate(req, true)
			if refreshErr != nil {
				return volumeserver.SourcePublicationGate{}, refreshErr
			}
			if !sourcePublicationGatesEqual(declaredGate, &refreshed) {
				return volumeserver.SourcePublicationGate{}, syscall.EINVAL
			}
			return refreshed, nil
		}
		if writeCommit != nil {
			writeCommitOwner, err = h.markWriteTransactionCommitting(cred.ID, req, writeCommit)
			if err != nil {
				return h.errorResponse(0, err, false)
			}
		}
		_, err = h.Visibility.ExecuteWithSourceGateSequence(ctx, cred.ID, id, declaration, expectedGate, refreshGate, normalizedPrepare, func(sequence uint64) ([]volumeserver.VisibilityTarget, bool) {
			var complete []volumeserver.VisibilityTarget
			resp, complete = apply(sequence)
			changed := visibilityChanged(resp)
			if changed && !validMutationPostStateRoles(req, resp.GetPostState()) {
				completeNormalizationErr = errors.New("authorityrpc: applied mutation produced an invalid exact post-state object/role set")
				return []volumeserver.VisibilityTarget{}, true
			}
			// nil is the explicit no-visible-change result. A non-nil empty
			// slice means apply changed XFS but target construction failed;
			// the coordinator detects and poisons that post-apply defect.
			normalized, normalizeErr := normalizeVisibilityTargets(complete)
			if normalizeErr != nil {
				completeNormalizationErr = normalizeErr
				return []volumeserver.VisibilityTarget{}, true
			}
			if changed {
				if attachErr := attachExactRepairPostState(normalized, resp.GetPostState(), sequence); attachErr != nil {
					completeNormalizationErr = attachErr
					return []volumeserver.VisibilityTarget{}, true
				}
			}
			return normalized, normalized != nil && changed
		}, func() ([]volumeserver.VisibilityResolution, error) {
			return sourcePublicationResolutions(req, resp)
		})
		if err != nil {
			// The coordinator has already poisoned itself after the deliberately
			// invalid completion above. Preserve the specific authority defect in
			// the retained response and log while keeping the post-apply boundary.
			if completeNormalizationErr != nil {
				err = &volumeserver.VisibilityBarrierError{Applied: true, Err: completeNormalizationErr}
			}
			var barrier *volumeserver.VisibilityBarrierError
			uncertain := errors.As(err, &barrier) && barrier.Applied
			if req.GetOneShotWrite() != nil && uncertain && markOneShotWritePostApplyFailure(resp, err) {
				h.deferStorageFailure(resp, err)
				h.deferCoherenceFailure(resp, err)
				return resp
			}
			if body := req.GetWriteTransaction(); body != nil && body.GetPhase() == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT {
				if uncertain && markWriteTransactionPostApplyFailure(resp, err) {
					h.deferStorageFailure(resp, err)
					h.deferCoherenceFailure(resp, err)
					return resp
				}
				if !uncertain {
					if errors.Is(err, volumeserver.ErrVisibilityRetry) {
						if resetErr := h.resetWriteTransactionForRetry(cred.ID, body); resetErr != nil {
							return h.errorResponse(0, resetErr, false)
						}
						return h.errorResponse(0, err, false)
					}
					if rejected := h.rejectPendingWriteTransaction(cred.ID, body, err); rejected != nil {
						return rejected
					}
				}
			}
			if uncertain && markRangePostApplyFailure(resp, err) {
				h.deferStorageFailure(resp, err)
				h.deferCoherenceFailure(resp, err)
				return resp
			}
			if uncertain {
				log.Printf(
					"portablefs-authority: visible mutation applied but cache completion failed source=%x slot=%d sequence=%d frontend_operation_id=%d: %v",
					cred.ID, id.Slot, id.Sequence, id.FrontendOperationID, err,
				)
			}
			if req.GetOneShotWrite() != nil && !errors.Is(err, volumeserver.ErrVisibilityRetry) {
				return oneShotWriteRejection(err, false)
			}
			return h.errorResponse(0, err, uncertain)
		}
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
	if mutation == nil {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	fingerprint, err := canonicalFingerprintFromFrame(ctx, h.Runtime, req)
	if err != nil {
		return h.errorResponse(req.GetRequestId(), syscall.EINVAL, false)
	}
	// Admission is taken against the bytes this outcome may retain, before the
	// operation reaches XFS. Refusing here is retryable; refusing after the
	// filesystem changed would not be. The runtime invokes this admission while
	// holding the exact replay-slot mutex, so a pipelined successor prices itself
	// against this operation's settled outcome rather than the same stale one.
	reserve := h.requestReplyReserve(req)
	id := volumeserver.MutationID{
		Slot: mutation.GetSlot(), Sequence: mutation.GetSequence(), Fingerprint: fingerprint,
		FrontendOperationID:          req.GetFrontendOperationId(),
		VisibilityRetryAfterSequence: req.GetVisibilityRetryAfterSequence(),
	}
	var reserved uint32
	settled := false
	defer func() {
		if !settled {
			h.releaseReplyReservation(reserved)
		}
	}()
	out, err := h.Runtime.ExecuteMutationAdmitted(ctx, cred, id, func() error {
		var reserveErr error
		reserved, reserveErr = h.reserveReplyBytes(cred.ID, id.Slot, reserve)
		return reserveErr
	}, func(context.Context) volumeserver.Outcome {
		resp := apply(id)
		terminalDeliveryRequired := h.takeTerminalReceiptFrame(resp)
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
		return volumeserver.Outcome{
			Errno: resp.GetErrno(), Reply: encoded,
			TerminalDeliveryRequired: terminalDeliveryRequired,
		}
	})
	if err != nil {
		if body := req.GetWriteTransaction(); body != nil &&
			body.GetPhase() == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT &&
			errors.Is(err, volumeserver.ErrAdmission) {
			return writeTransactionResponseWithEnvelope(h, req.GetRequestId(), h.rejectUnadmittedWriteTransaction(req, cred.ID, body))
		}
		if req.GetOneShotWrite() != nil && errors.Is(err, volumeserver.ErrAdmission) {
			return writeTransactionResponseWithEnvelope(h, req.GetRequestId(), oneShotWriteRejection(syscall.ENOMEM, false))
		}
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
	if out.TerminalDeliveryRequired {
		h.terminalFailureMu.Lock()
		h.retainTerminalReceiptFrameLocked(resp)
		h.terminalFailureMu.Unlock()
	}
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
	return &authoritypb.Attr{Kind: attrKindProto(attr.Kind), Inode: attr.Ino, Size: attr.Size, Blocks: attr.Blocks, Mode: modeToProtocol(attr.Mode), Uid: attr.UID, Gid: attr.GID, Nlink: attr.Nlink, AtimeNs: attr.ATimeNS, MtimeNs: attr.MTimeNS, CtimeNs: attr.CTimeNS, BirthTimeNs: attr.BirthTimeNS, Rdev: attr.Rdev, Blksize: attr.BlockSize, Flags: attr.Flags}
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

func (h *VolumeHandler) getattr(ctx context.Context, id volumeserver.SessionID, req *authoritypb.GetAttrRequest) (xfsstore.Attr, [16]byte, uint64, error) {
	if len(req.GetHandle()) != 0 {
		handle, err := h.open(id, req.GetHandle())
		if err != nil {
			return xfsstore.Attr{}, [16]byte{}, 0, err
		}
		snapshot, err := h.stabilizeOpenSequence(ctx, id, handle)
		if err != nil {
			return xfsstore.Attr{}, [16]byte{}, 0, err
		}
		identity, err := h.Store.IdentityOpen(handle)
		if err != nil {
			return xfsstore.Attr{}, [16]byte{}, 0, err
		}
		attr, err := h.Store.GetattrOpen(handle)
		return attr, identity, snapshot, err
	}
	item, err := h.item(id, req.GetItem())
	if err != nil {
		return xfsstore.Attr{}, [16]byte{}, 0, err
	}
	snapshot, err := h.stabilizeItemSequence(ctx, id, item)
	if err != nil {
		return xfsstore.Attr{}, [16]byte{}, 0, err
	}
	identity, err := h.Store.Identity(item)
	if err != nil {
		return xfsstore.Attr{}, [16]byte{}, 0, err
	}
	attr, err := h.Store.Getattr(item)
	return attr, identity, snapshot, err
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
			wait, waitErr := h.Routes.beginLockWait(func() error {
				return h.admitSessionRoutes(cred.ID)
			}, lock)
			if waitErr != nil {
				err = waitErr
			} else {
				err = wait.Await(ctx)
			}
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

func (h *VolumeHandler) errorResponse(requestID uint64, err error, uncertain bool) (response *authoritypb.Response) {
	// Generic errors carry no exact applied state for a frontend to publish.
	// They still start and fence the terminal drain, but only the structured
	// WRITE/FALLOCATE/CFR post-apply paths may bind a cross-process delivery
	// receipt to a response instance.
	defer func() { h.deferStorageFailure(nil, err) }()
	defer func() { h.deferCoherenceFailure(nil, err) }()
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
		errors.Is(err, volumeserver.ErrAuthorizationOwner), errors.Is(err, volumeserver.ErrAttachAttemptMismatch):
		errno = errnos.EINVAL
	case errors.Is(err, volumeserver.ErrSessionProvisional):
		// An ordinary operation cannot be queued as a hidden activation retry. The
		// mount must finish the explicit CONTROL activation transaction first.
		errno = errnos.EAGAIN
	case errors.Is(err, volumeserver.ErrSessionActive):
		// AbortAttach is a provisional-only operation. Once ACTIVE, normal Detach
		// is the sole lifecycle transition and carries the mount-absence proof.
		errno = errnos.EBUSY
	case errors.Is(err, volumeserver.ErrAdmission):
		errno = errnos.EAGAIN
	case errors.Is(err, volumeserver.ErrVisibilityRetry):
		// This is internal protocol flow, not an application-visible EINTR. The
		// Linux frontend releases its source gate and resubmits inside the
		// same FUSE callback. The separate class proves a staged COMMIT remained
		// reusable and prevents confusing it with a callback/namespace unwind.
		sequence, ok := volumeserver.VisibilityRetrySequence(err)
		if !ok {
			return h.errorResponse(requestID, fmt.Errorf("%w: visibility retry omitted its sequence", errInternal), true)
		}
		errno = errnos.EINTR
		resp := h.success(requestID)
		resp.Errno, resp.Uncertain = errno, uncertain
		resp.Failure = authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY
		resp.VisibilityRetrySequence = sequence
		return resp
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

// beginTerminalRequest admits only requests that arrived before the first
// volume-terminal failure. That first failure fences XFS immediately, but the
// handlers which were already admitted must be allowed to finish: another one
// may also have changed XFS and need to register its own exact terminal reply.
func terminalControlRequest(req *authoritypb.Request) bool {
	if req == nil {
		return false
	}
	switch req.GetBody().(type) {
	case *authoritypb.Request_NextVisibility, *authoritypb.Request_AckVisibility,
		*authoritypb.Request_Cancel, *authoritypb.Request_TerminalDeliveryReceipt:
		return true
	default:
		return false
	}
}

func (h *VolumeHandler) beginTerminalRequest(req *authoritypb.Request) bool {
	if h == nil {
		return false
	}
	h.terminalFailureMu.Lock()
	defer h.terminalFailureMu.Unlock()
	if h.terminalDraining && !terminalControlRequest(req) {
		return false
	}
	h.terminalActive++
	return true
}

func (h *VolumeHandler) TerminalQuiescing() <-chan struct{} {
	h.terminalFailureMu.Lock()
	defer h.terminalFailureMu.Unlock()
	if h.terminalQuiesce == nil {
		h.terminalQuiesce = make(chan struct{})
		if h.terminalDraining {
			close(h.terminalQuiesce)
		}
	}
	return h.terminalQuiesce
}

func (h *VolumeHandler) startTerminalDrainLocked() {
	if h.terminalDraining {
		return
	}
	h.terminalDraining = true
	if h.terminalQuiesce == nil {
		h.terminalQuiesce = make(chan struct{})
	}
	close(h.terminalQuiesce)
	if !h.terminalTimeoutArmed && h.TerminalDeliveryTimeout > 0 {
		h.terminalTimeoutArmed = true
		time.AfterFunc(h.TerminalDeliveryTimeout, h.forceTerminalTimeout)
	}
}

func (h *VolumeHandler) forceTerminalTimeout() {
	if h == nil {
		return
	}
	h.terminalFailureMu.Lock()
	if !h.terminalDraining || h.terminalStorageErr == nil && h.terminalCoherenceErr == nil {
		h.terminalFailureMu.Unlock()
		return
	}
	var storage, coherence error
	if h.terminalStorageErr != nil {
		storage = errors.Join(h.terminalStorageErr, context.DeadlineExceeded)
	}
	if h.terminalCoherenceErr != nil {
		coherence = errors.Join(h.terminalCoherenceErr, context.DeadlineExceeded)
	}
	h.terminalForced = true
	h.terminalStorageErr, h.terminalCoherenceErr = nil, nil
	h.terminalResponses = nil
	h.terminalAdmittedFrames = nil
	h.terminalFrames = nil
	h.terminalReceiptFrames = nil
	h.terminalFailureMu.Unlock()
	h.runTerminalCallbacks(storage, coherence)
}

func (h *VolumeHandler) retainTerminalHandlerResponse(response *authoritypb.Response) {
	if h == nil {
		return
	}
	h.terminalFailureMu.Lock()
	if h.terminalHandlerFrames == nil {
		h.terminalHandlerFrames = make(map[*authoritypb.Response]struct{})
	}
	h.terminalHandlerFrames[response] = struct{}{}
	h.terminalFailureMu.Unlock()
}

func (h *VolumeHandler) endTerminalRequest() {
	if h == nil {
		return
	}
	h.terminalFailureMu.Lock()
	if h.terminalActive == 0 {
		h.terminalFailureMu.Unlock()
		panic("authorityrpc: terminal request accounting underflow")
	}
	h.terminalActive--
	storage, coherence := h.terminalCallbacksLocked()
	h.terminalFailureMu.Unlock()
	h.runTerminalCallbacks(storage, coherence)
}

// terminalCallbacksLocked transfers terminal causes only after every handler
// admitted before the fence has returned and every exact terminal response it
// registered has reached a physical frame-write attempt.
func (h *VolumeHandler) terminalCallbacksLocked() (storage, coherence error) {
	if !h.terminalDraining || h.terminalForced || h.terminalActive != 0 || len(h.terminalFrames) != 0 || len(h.terminalResponses) != 0 {
		return nil, nil
	}
	storage, coherence = h.terminalStorageErr, h.terminalCoherenceErr
	h.terminalStorageErr, h.terminalCoherenceErr = nil, nil
	return storage, coherence
}

func (h *VolumeHandler) runTerminalCallbacks(storage, coherence error) {
	if storage != nil && h.OnStorageFailure != nil {
		h.storageFailureOnce.Do(func() { h.OnStorageFailure(storage) })
	}
	if coherence != nil && h.OnCoherenceFailure != nil {
		h.coherenceFailureOnce.Do(func() { h.OnCoherenceFailure(coherence) })
	}
}

func (h *VolumeHandler) deferCoherenceFailure(response *authoritypb.Response, err error) {
	if !isVisibilityFailure(err) || h.OnCoherenceFailure == nil {
		return
	}
	h.terminalFailureMu.Lock()
	h.startTerminalDrainLocked()
	h.terminalCoherenceErr = errors.Join(h.terminalCoherenceErr, err)
	h.retainTerminalReceiptFrameLocked(response)
	storage, coherence := h.terminalCallbacksLocked()
	h.terminalFailureMu.Unlock()
	h.runTerminalCallbacks(storage, coherence)
}

func (h *VolumeHandler) recordCoherenceFailure(err error) {
	h.deferCoherenceFailure(nil, err)
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
	return fatalStorageErrno(err) || errors.Is(err, xfsstore.ErrFenced) || errors.Is(err, xfsstore.ErrOutcomeUncertain) ||
		errors.Is(err, xfsstore.ErrWritePrivilege)
}

func uncertainFailure(err error) bool {
	return fatalStorageErrno(err) || errors.Is(err, xfsstore.ErrOutcomeUncertain)
}

func (h *VolumeHandler) fenceStorageFailure(err error) bool {
	if h.Store == nil || !fatalStorageErrno(err) && !errors.Is(err, xfsstore.ErrWritePrivilege) &&
		!errors.Is(err, xfsstore.ErrOutcomeUncertain) {
		return false
	}
	h.Store.Fence(err)
	return true
}

func (h *VolumeHandler) deferStorageFailure(response *authoritypb.Response, err error) {
	if h.Store == nil || !fatalStorageErrno(err) && !errors.Is(err, xfsstore.ErrWritePrivilege) &&
		!errors.Is(err, xfsstore.ErrOutcomeUncertain) {
		return
	}
	if h.OnStorageFailure == nil {
		h.Store.Fence(err)
		return
	}
	// Do not synchronously stop the server here. A post-apply response may be
	// carrying the only exact size/offset the source kernel can publish; closing
	// the connection from inside Handle would race that response write. Track its
	// exact retained bytes so marshal/unmarshal and replay cannot lose ownership.
	h.terminalFailureMu.Lock()
	h.startTerminalDrainLocked()
	h.terminalStorageErr = errors.Join(h.terminalStorageErr, err)
	h.retainTerminalReceiptFrameLocked(response)
	h.terminalFailureMu.Unlock()
	// Close admission before fencing the store. Otherwise a fresh filesystem
	// request can slip between Fence and terminalDraining and become a hidden
	// pre-fence operation.
	h.Store.Fence(err)
	h.terminalFailureMu.Lock()
	storage, coherence := h.terminalCallbacksLocked()
	h.terminalFailureMu.Unlock()
	h.runTerminalCallbacks(storage, coherence)
}

func (h *VolumeHandler) recordStorageFailure(err error) {
	h.deferStorageFailure(nil, err)
}

func (h *VolumeHandler) retainTerminalReceiptFrameLocked(response *authoritypb.Response) {
	if response == nil {
		return
	}
	if !terminalReceiptCarriesExactAppliedState(response) {
		// A direct terminal receipt is meaningful only for a response whose exact
		// post-apply state the frontend can install and publish. Preserve an
		// impossible obligation so an accidental caller fails closed at the
		// bounded terminal timeout instead of silently weakening that contract.
		if h.terminalResponses == nil {
			h.terminalResponses = make(map[[16]byte]struct{})
		}
		h.terminalResponses[[16]byte{}] = struct{}{}
		log.Printf("portablefs-authority: refusing terminal receipt for non-postapply response")
		return
	}
	if h.terminalReceiptFrames == nil {
		h.terminalReceiptFrames = make(map[*authoritypb.Response]struct{})
	}
	h.terminalReceiptFrames[response] = struct{}{}
}

func (h *VolumeHandler) takeTerminalReceiptFrame(response *authoritypb.Response) bool {
	if h == nil || response == nil {
		return false
	}
	h.terminalFailureMu.Lock()
	_, retained := h.terminalReceiptFrames[response]
	delete(h.terminalReceiptFrames, response)
	h.terminalFailureMu.Unlock()
	return retained
}

func terminalReceiptCarriesExactAppliedState(response *authoritypb.Response) bool {
	if response == nil || response.GetErrno() != 0 || response.GetUncertain() ||
		!validPostStateShape(response.GetPostState(), true) {
		return false
	}
	target := postStateTargetAttr(response.GetPostState())
	if target == nil || target.GetKind() != authoritypb.Attr_REGULAR || target.GetSize() < 0 {
		return false
	}
	validError := func(value int32) bool { return value < 0 && value >= -4095 }
	postSize := uint64(target.GetSize())
	if reply := response.GetWriteTransaction(); reply != nil {
		return reply.GetFlags() == writeTransactionReplyCommitted|writeTransactionReplyPostApply &&
			validError(reply.GetError()) && reply.GetVisibilitySequence() > 0 && reply.GetPostSize() == postSize
	}
	if reply := response.GetFallocate(); reply != nil {
		return reply.GetFlags() == rangeReplyApplied|rangeReplyPostApply && reply.GetResultSize() == 0 &&
			validError(reply.GetError()) && reply.GetVisibilitySequence() > 0 && reply.GetPostSize() == postSize
	}
	if reply := response.GetCopyFileRange(); reply != nil {
		return reply.GetFlags() == rangeReplyApplied|rangeReplyPostApply &&
			validError(reply.GetError()) && reply.GetVisibilitySequence() > 0 && reply.GetPostSize() == postSize
	}
	return false
}

func (h *VolumeHandler) terminalDeliveryReceipt(requestID uint64, receipt *authoritypb.TerminalDeliveryReceipt) *authoritypb.Response {
	response := h.success(requestID)
	response.Body = &authoritypb.Response_TerminalDeliveryReceipt{TerminalDeliveryReceipt: &authoritypb.TerminalDeliveryReceiptReply{}}
	if receipt == nil || len(receipt.GetToken()) != 16 {
		response.Errno = int32(syscall.EINVAL)
		return response
	}
	var token [16]byte
	copy(token[:], receipt.GetToken())
	if token == ([16]byte{}) {
		response.Errno = int32(syscall.EINVAL)
		return response
	}
	h.terminalFailureMu.Lock()
	if _, pending := h.terminalResponses[token]; !pending {
		h.terminalFailureMu.Unlock()
		response.Errno = int32(syscall.ESTALE)
		return response
	}
	delete(h.terminalResponses, token)
	h.terminalFailureMu.Unlock()
	// This handler itself remains active until its ACK is physically written.
	// executeTransportTerminalReceipt owns the final endTerminalRequest call.
	return response
}

// PrepareResponseWrite runs at the immutable outer response boundary, after a
// retained outcome has been reconstructed and after visibility COMPLETE. It
// mints an opaque receipt only for an exact structured post-apply response
// whose retained replay outcome carries the terminal-delivery bit; body
// equality can never let an unrelated response consume this obligation.
func (h *VolumeHandler) PrepareResponseWrite(request *authoritypb.Request, response *authoritypb.Response) {
	h.prepareResponseWrite(request, response, false)
}

func (h *VolumeHandler) prepareResponseWrite(request *authoritypb.Request, response *authoritypb.Response, admitted bool) {
	if h == nil || response == nil {
		return
	}
	h.terminalFailureMu.Lock()
	if h.terminalForced {
		h.terminalFailureMu.Unlock()
		return
	}
	if h.terminalFrames == nil {
		h.terminalFrames = make(map[*authoritypb.Response]struct{})
	}
	h.terminalFrames[response] = struct{}{}
	if admitted {
		if h.terminalAdmittedFrames == nil {
			h.terminalAdmittedFrames = make(map[*authoritypb.Response]struct{})
		}
		h.terminalAdmittedFrames[response] = struct{}{}
	}
	if !h.terminalDraining {
		h.terminalFailureMu.Unlock()
		return
	}
	if _, wasAdmitted := h.terminalAdmittedFrames[response]; !wasAdmitted {
		// A request refused after terminal admission closed carries no applied
		// state. Track its physical frame if one is attempted, but never mint a
		// receipt which the already-poisoned frontend cannot owe.
		h.terminalFailureMu.Unlock()
		return
	}
	if _, receiptRequired := h.terminalReceiptFrames[response]; !receiptRequired {
		h.terminalFailureMu.Unlock()
		return
	}
	if request == nil || request.GetTerminalDeliveryReceipt() != nil || terminalControlRequest(request) {
		h.terminalFailureMu.Unlock()
		return
	}
	if len(response.GetTerminalDeliveryToken()) != 0 {
		h.terminalFailureMu.Unlock()
		return
	}
	if h.terminalResponses == nil {
		h.terminalResponses = make(map[[16]byte]struct{})
	}
	tokenReader := h.terminalTokenReader
	if tokenReader == nil {
		tokenReader = rand.Reader
	}
	var token [16]byte
	for {
		if _, err := io.ReadFull(tokenReader, token[:]); err != nil {
			// Keep an impossible receipt outstanding so teardown reaches the
			// bounded terminal timeout instead of silently losing publication
			// ownership after an entropy-source failure.
			h.terminalResponses[[16]byte{}] = struct{}{}
			h.terminalFailureMu.Unlock()
			return
		}
		if token == ([16]byte{}) {
			continue
		}
		if _, collision := h.terminalResponses[token]; collision {
			continue
		}
		break
	}
	h.terminalResponses[token] = struct{}{}
	response.TerminalDeliveryToken = append([]byte(nil), token[:]...)
	h.terminalFailureMu.Unlock()
}

// FinishHandlerResponse transfers one admitted handler into an immutable
// transport-owned delivery obligation. It must run before terminalActive is
// decremented; otherwise the first terminal response can trigger process stop
// in the gap before the server registers its token.
func (h *VolumeHandler) FinishHandlerResponse(request *authoritypb.Request, response *authoritypb.Response) {
	if h == nil {
		return
	}
	h.terminalFailureMu.Lock()
	if _, retained := h.terminalHandlerFrames[response]; !retained {
		h.terminalFailureMu.Unlock()
		return
	}
	delete(h.terminalHandlerFrames, response)
	h.terminalFailureMu.Unlock()
	h.prepareResponseWrite(request, response, true)
	h.endTerminalRequest()
}

// ResponseWritten observes only physical authority frame failures. A success
// remains pending until the frontend returns TerminalDeliveryReceipt after its
// kernel publication boundary; a failed frame can never be receipted, so it is
// retired here and teardown proceeds once every other exact result settles.
func (h *VolumeHandler) ResponseWritten(response *authoritypb.Response, writeErr error) {
	if h == nil {
		return
	}
	h.terminalFailureMu.Lock()
	if _, frame := h.terminalFrames[response]; !frame {
		h.terminalFailureMu.Unlock()
		return
	}
	delete(h.terminalFrames, response)
	delete(h.terminalAdmittedFrames, response)
	delete(h.terminalReceiptFrames, response)
	if writeErr != nil && len(response.GetTerminalDeliveryToken()) == 16 {
		var token [16]byte
		copy(token[:], response.GetTerminalDeliveryToken())
		delete(h.terminalResponses, token)
	}
	storage, coherence := h.terminalCallbacksLocked()
	h.terminalFailureMu.Unlock()
	h.runTerminalCallbacks(storage, coherence)
}

func wireErrno(err error) int32 {
	// Visibility interruption is a deliberate definite-preapply yield. Keep the
	// mapping here, at the common error-to-wire boundary, so both ordinary
	// envelopes and structured WRITE rejections tell Linux EINTR. The latter is
	// essential when two mounts race on one inode: Linux releases the losing
	// callback lane and retries after the winner's repair without surfacing a
	// false EIO to the application.
	if errors.Is(err, volumeserver.ErrVisibilityInterrupted) || errors.Is(err, volumeserver.ErrVisibilityRetry) {
		return errnos.EINTR
	}
	if errors.Is(err, volumeserver.ErrCompatibilityWriterLease) {
		return errnos.EBUSY
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno > 0 {
		return int32(errno)
	}
	return errnos.Of(err)
}

type sessionResourceSpec struct {
	credential            volumeserver.SessionCredential
	id                    volumeserver.SessionID
	attempt               volumeserver.AttachAttemptID
	root                  xfsstore.Capability
	slots                 uint32
	routes                [32]byte
	coherence             volumeserver.CoherenceProfile
	commitment            volumeserver.VisibilityCommitment
	authorizationDeadline time.Time
}

func (h *VolumeHandler) ensureProvisionalSessionResources(spec sessionResourceSpec) (*sessionResources, error) {
	if h.Runtime == nil || spec.credential.ID != spec.id || spec.id == (volumeserver.SessionID{}) || spec.attempt == (volumeserver.AttachAttemptID{}) ||
		spec.slots == 0 || spec.authorizationDeadline.IsZero() {
		return nil, volumeserver.ErrRequestMismatch
	}
	h.resourcesMu.Lock()
	if h.resources == nil {
		h.resources = make(map[volumeserver.SessionID]*sessionResources)
	}
	resources := h.resources[spec.id]
	installed := false
	if resources != nil {
		existing := resources
		if existing.ended || existing.attempt != spec.attempt || existing.root != spec.root ||
			uint32(len(existing.reply)) != spec.slots || existing.routes != spec.routes ||
			existing.coherence != spec.coherence || existing.commitment != spec.commitment ||
			!existing.authorizationDeadline.Equal(spec.authorizationDeadline) {
			h.resourcesMu.Unlock()
			return nil, volumeserver.ErrRequestMismatch
		}
	} else {
		resources = &sessionResources{
			attempt: spec.attempt, root: spec.root, items: make(map[xfsstore.Capability]bool),
			opens: make(map[xfsstore.Capability]bool), reply: make([]uint32, spec.slots),
			coherence: spec.coherence, commitment: spec.commitment, routes: spec.routes,
			authorizationDeadline: spec.authorizationDeadline,
		}
		h.resources[spec.id] = resources
		installed = true
	}

	// PrepareAttach necessarily publishes the runtime session before this
	// handler can publish its descriptor/replay tables. Reconcile while holding
	// resourcesMu, immediately after installation: an end hook that ran before
	// installation is caught by these authoritative runtime facts, while an end
	// after installation blocks on this mutex and then removes the exact record.
	// Acquiring the terminal channel before the point state query closes the
	// state-after-query race; the final nonblocking read covers an end between
	// those two observations. Runtime end hooks never retain Authority locks
	// while calling here, so this lock order has no callback cycle.
	terminal, terminalErr := h.Runtime.SessionTerminal(spec.id)
	state, stateErr := h.Runtime.SessionState(spec.credential, spec.attempt)
	reconcileErr := terminalErr
	if reconcileErr == nil {
		reconcileErr = stateErr
	}
	if reconcileErr == nil {
		switch state {
		case volumeserver.SessionStateProvisional:
		case volumeserver.SessionStateActive:
			// ACTIVE is valid only for an exact Attach replay after another
			// delivery returned the provisional credential and completed Activate.
			// A first resource installation cannot be reached in that order.
			if installed {
				reconcileErr = volumeserver.ErrSessionFenced
			}
		case volumeserver.SessionStateAborted:
			reconcileErr = volumeserver.ErrSessionExpired
		default:
			reconcileErr = volumeserver.ErrSessionFenced
		}
	}
	if reconcileErr == nil {
		select {
		case <-terminal:
			reconcileErr = volumeserver.ErrSessionExpired
		default:
		}
	}
	if reconcileErr != nil {
		cleanup, taken := h.takeSessionResourcesLocked(spec.id, resources)
		h.resourcesMu.Unlock()
		if taken {
			h.finishSessionResourceCleanup(cleanup)
		}
		return nil, reconcileErr
	}
	h.resourcesMu.Unlock()
	return resources, nil
}

func (h *VolumeHandler) sessionResources(id volumeserver.SessionID) (*sessionResources, error) {
	h.resourcesMu.Lock()
	defer h.resourcesMu.Unlock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		return nil, volumeserver.ErrSessionExpired
	}
	return resources, nil
}

func (h *VolumeHandler) exactSessionResources(id volumeserver.SessionID, attempt volumeserver.AttachAttemptID) (*sessionResources, error) {
	resources, err := h.sessionResources(id)
	if err != nil {
		return nil, err
	}
	if resources.attempt != attempt {
		return nil, volumeserver.ErrRequestMismatch
	}
	return resources, nil
}

// startSessionResources is the direct-runtime test helper. Protocol 5 uses
// ensureProvisionalSessionResources and cannot create an ACTIVE session here.
func (h *VolumeHandler) startSessionResources(id volumeserver.SessionID, root xfsstore.Capability, slots uint32, routes [32]byte, profiles ...volumeserver.CoherenceProfile) error {
	profile := volumeserver.CoherenceStrict
	if len(profiles) == 1 {
		profile = profiles[0]
	} else if len(profiles) > 1 {
		return volumeserver.ErrVisibilityProfile
	}
	if profile != volumeserver.CoherenceStrict {
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
	hasReplacement bool,
	oldPost visibilityCoordinate,
	hasOldPost, attestPostBindings bool,
) []volumeserver.VisibilityTarget {
	oldNameTarget := namespaceTargetRelated(oldParent, rename.GetOldName(), moved)
	newNameTarget := namespaceTargetRelated(newParent, rename.GetNewName(), moved)
	if attestPostBindings {
		newNameTarget = namespaceTargetPost(newParent, rename.GetNewName(), moved)
		if hasOldPost {
			oldNameTarget = namespaceTargetPost(oldParent, rename.GetOldName(), oldPost)
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
		// These are descriptor tables, not a transient execution queue. Waiting
		// would let lookup/readdir storms pin workers, while EAGAIN is not a legal
		// blocking pathname result. ENFILE reports the exhausted authority-managed
		// file table without pretending the caller's own descriptor limit was hit.
		return nil, errCapabilityTableFull
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
	if r.h.Metrics != nil {
		r.h.Metrics.ObserveSessionItems(len(resources.items))
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
		err = errCapabilityTableFull
	default:
		trackCapability(resources.items, item, protected, &h.totalItems)
		if h.Metrics != nil {
			h.Metrics.ObserveSessionItems(len(resources.items))
		}
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
		err = errCapabilityTableFull
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

type sessionResourceCleanup struct {
	handles []xfsstore.Capability
	items   []xfsstore.Capability
	writes  []writeTransactionCleanup
}

// takeSessionResourcesLocked transfers cleanup ownership for the exact record.
// expected may be nil only for the runtime's authoritative by-ID end hook; a
// reconciler always supplies its pointer so a stale observation cannot erase a
// newer exact-replay record.
func (h *VolumeHandler) takeSessionResourcesLocked(id volumeserver.SessionID, expected *sessionResources) (sessionResourceCleanup, bool) {
	resources := h.resources[id]
	if resources == nil || resources.ended || expected != nil && resources != expected {
		return sessionResourceCleanup{}, false
	}
	resources.ended = true
	h.endWriteTransactionCapacityWaits(resources)
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
	writes := closeWriteTransactions(h, resources)
	delete(h.resources, id)
	return sessionResourceCleanup{handles: handles, items: items, writes: writes}, true
}

func (h *VolumeHandler) finishSessionResourceCleanup(cleanup sessionResourceCleanup) {
	for _, write := range cleanup.writes {
		write.finish()
	}
	for _, handle := range cleanup.handles {
		h.closeOpen(handle)
	}
	for _, item := range cleanup.items {
		h.forgetItem(item)
	}
}

func (h *VolumeHandler) closeExactSessionResources(id volumeserver.SessionID, expected *sessionResources) {
	h.resourcesMu.Lock()
	cleanup, taken := h.takeSessionResourcesLocked(id, expected)
	h.resourcesMu.Unlock()
	if taken {
		h.finishSessionResourceCleanup(cleanup)
	}
}

func (h *VolumeHandler) closeSessionResources(id volumeserver.SessionID) {
	h.closeExactSessionResources(id, nil)
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
