package authorityrpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

var (
	ErrTransportUncertain = errors.New("authorityrpc: connection ended before the operation outcome was received")
	ErrAuthorityChanged   = errors.New("authorityrpc: authority epoch changed; remount is required")
	ErrSessionEnded       = errors.New("authorityrpc: authority session ended; remount is required")
	// ErrReplayDesynchronized is terminal. It means the authority recorded a
	// replay identity this client did not submit, which invalidates exact-once
	// delivery for the whole session.
	ErrReplayDesynchronized = errors.New("authorityrpc: authority recorded a different replay identity; remount is required")
	// ErrRoutesMismatch means this mount is running a machine-local routing
	// topology that is not the volume's active one. It is terminal for the
	// mount: continuing would hide a subtree from every peer, so the mount must
	// reconcile its declaration and remount rather than retry.
	ErrRoutesMismatch = errors.New("authorityrpc: mount routing revision is not the volume's active one")
)

type ClientConfig struct {
	Address     string
	TLS         *tls.Config
	VolumeID    string
	AccessToken []byte
	ReplaySlots uint32
	MaxFrame    uint32
	DialTimeout time.Duration
	// CancelDrainTimeout bounds how long an interrupted caller waits for the
	// authority to return the exact canceled-or-completed outcome.
	CancelDrainTimeout time.Duration
	MaxInFlight        int
	CoherenceProfile   authoritypb.CoherenceProfile
	// CachedNameCapacity is how many distinct resolutions this mount's kernel
	// cache is expected to hold; it sizes the authority's per-session resolved
	// index and costs only precision if it is low. RepairBudget is the longest
	// this mount may take to acknowledge one visibility phase; the authority
	// fences this mount on it and the frontend must revoke its own mount on it,
	// so it must be a number the frontend actually enforces. Both are required
	// for a strict profile.
	CachedNameCapacity uint64
	RepairBudget       time.Duration
	// NamespaceRepair states how this mount's kernel makes a cached name
	// binding unservable. Required for a strict profile: the authority uses it
	// to tell a proven repair cycle from a slow lock, and there is no safe
	// default for it. Ignored for an uncached profile, which caches no binding.
	NamespaceRepair authoritypb.NamespaceRepair
	// RoutesRevision is the 32-byte digest of the canonical machine-local
	// routing rules this mount will run. Required for every profile: a mount
	// that routes a subtree to local disk hides it from every peer, so the
	// authority refuses any mount whose topology is not the volume's active one.
	RoutesRevision [32]byte
}

// MutationIdentity is the replay identity assigned to one authority mutation.
// A frontend that has a separate kernel-publication protocol uses it to link
// the authority's PREPARE/COMPLETE initiator ticket to the exact local callback
// that submitted the mutation.
type MutationIdentity struct {
	Slot     uint32
	Sequence uint64
}

// MutationAssigned runs synchronously after a mutation has its final replay
// identity and canonical hash, but before any bytes can reach the authority.
// It must be fast, nonblocking, and must not re-enter Client. Returning an error
// sends nothing and leaves the replay slot unadvanced.
type MutationAssigned func(MutationIdentity) error

type callResult struct {
	response *authoritypb.Response
	err      error
}

// lane is one admission class. Ordinary operations and blocking POSIX lock
// waits never share permits, and each lane owns a private, disjoint range of
// replay slots sized at least as large as its own permit count. A caller takes
// its permit before it takes a slot index, so at most one caller can hold any
// slot at a time: slot ownership cannot contend, and a parked lock waiter can
// neither consume an ordinary permit nor stall an ordinary mutation.
type lane struct {
	permits  chan struct{}
	slots    []clientSlot
	nextSlot atomic.Uint32
	base     uint32
}

type Client struct {
	cfg ClientConfig

	lifecycle        sync.Mutex
	conn             net.Conn
	writeMu          sync.Mutex
	pendingMu        sync.Mutex
	pending          map[uint64]chan callResult
	nextID           atomic.Uint64
	ordinary         lane
	blocking         lane
	visibility       lane
	liveness         lane
	epoch            []byte
	proof            *authoritypb.SessionProof
	root             *authoritypb.Item
	maxRead          uint32
	maxWrite         uint32
	lease            time.Duration
	visibilityCursor *authoritypb.VisibilityCursor
	frameMax         atomic.Uint32
	poisoned         atomic.Bool
	closed           bool
	fatalOnce        sync.Once
	fatalMu          sync.Mutex
	fatalErr         error
	fatalDone        chan struct{}
}

type clientSlot struct {
	mu sync.Mutex
	// sequence mirrors what the authority reported as recorded for this slot.
	// It is only ever assigned from a MutationState the authority returned, so
	// the two counters cannot drift apart.
	sequence uint64
}

func DialClient(ctx context.Context, cfg ClientConfig) (*Client, error) {
	if cfg.Address == "" || cfg.TLS == nil || cfg.VolumeID == "" || len(cfg.AccessToken) == 0 ||
		cfg.ReplaySlots == 0 || cfg.MaxFrame == 0 || cfg.MaxInFlight <= 0 || cfg.DialTimeout <= 0 || cfg.CancelDrainTimeout <= 0 {
		return nil, errors.New("authorityrpc: complete client configuration is required")
	}
	if cfg.MaxInFlight < 2 {
		return nil, errors.New("authorityrpc: max-in-flight must admit an ordinary request and a blocking lock wait independently")
	}
	if uint64(cfg.ReplaySlots) < uint64(cfg.MaxInFlight) {
		return nil, errors.New("authorityrpc: replay slots must cover every possible in-flight mutation")
	}
	if cfg.MaxFrame < MinimumFrameBytes {
		return nil, fmt.Errorf("authorityrpc: frame bound must be at least %d bytes", MinimumFrameBytes)
	}
	if cfg.TLS.InsecureSkipVerify || cfg.TLS.ServerName == "" {
		return nil, errors.New("authorityrpc: verified TLS server name is required")
	}
	if cfg.CoherenceProfile != authoritypb.CoherenceProfile_COHERENCE_PROFILE_UNCACHED &&
		cfg.CoherenceProfile != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
		return nil, errors.New("authorityrpc: unsupported coherence profile")
	}
	cfg.TLS = cfg.TLS.Clone()
	cfg.TLS.MinVersion = tls.VersionTLS13
	cfg.TLS.NextProtos = []string{protocolALPN}
	ordinaryLimit, blockingLimit := blockingWaitLane(cfg.MaxInFlight)
	if cfg.CoherenceProfile == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT && ordinaryLimit < 3 {
		return nil, errors.New("authorityrpc: strict coherence requires distinct visibility, liveness, and ordinary request lanes")
	}
	if cfg.CoherenceProfile == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT &&
		(cfg.CachedNameCapacity == 0 || cfg.RepairBudget <= 0) {
		return nil, errors.New("authorityrpc: strict coherence requires a declared kernel-cache capacity and repair budget")
	}
	if cfg.CoherenceProfile == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT &&
		cfg.NamespaceRepair == authoritypb.NamespaceRepair_NAMESPACE_REPAIR_UNSPECIFIED {
		return nil, errors.New("authorityrpc: strict coherence requires a declared namespace-repair model")
	}
	ordinaryPermits := ordinaryLimit
	if cfg.CoherenceProfile == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
		ordinaryPermits -= 2
	}
	slots := make([]clientSlot, cfg.ReplaySlots)
	split := cfg.ReplaySlots - uint32(blockingLimit)
	c := &Client{
		cfg: cfg, pending: make(map[uint64]chan callResult), fatalDone: make(chan struct{}),
		ordinary:   lane{permits: make(chan struct{}, ordinaryPermits), slots: slots[:split], base: 0},
		blocking:   lane{permits: make(chan struct{}, blockingLimit), slots: slots[split:], base: split},
		visibility: lane{permits: make(chan struct{}, 1)},
		liveness:   lane{permits: make(chan struct{}, 1)},
	}
	if err := c.connect(ctx, false); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: c.cfg.DialTimeout, KeepAlive: 15 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", c.cfg.Address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, c.cfg.TLS.Clone())
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol != protocolALPN {
		_ = conn.Close()
		return nil, errors.New("authorityrpc: TLS peer did not negotiate the PortableFS authority protocol")
	}
	return conn, nil
}

func (c *Client) connect(ctx context.Context, resume bool) error {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if resume {
		c.pendingMu.Lock()
		live := c.conn != nil
		c.pendingMu.Unlock()
		if live {
			return nil
		}
	}
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
	defer handshakeCancel()
	conn, err := c.dial(handshakeCtx)
	if err != nil {
		return err
	}
	fail := func(err error) error { _ = conn.Close(); return err }
	handshakeDeadline, _ := handshakeCtx.Deadline()
	if err := conn.SetDeadline(handshakeDeadline); err != nil {
		return fail(err)
	}
	helloReq := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor}}}
	if err := writeFrame(conn, c.cfg.MaxFrame, helloReq); err != nil {
		return fail(err)
	}
	var hello authoritypb.Response
	if err := readFrame(conn, c.cfg.MaxFrame, nil, 0, &hello); err != nil {
		return fail(err)
	}
	if hello.GetRequestId() != helloReq.GetRequestId() || hello.GetErrno() != 0 || hello.GetHello() == nil || hello.GetHello().GetProtocolMajor() != ProtocolMajor {
		return fail(fmt.Errorf("authorityrpc: protocol handshake refused with errno %d", hello.GetErrno()))
	}
	if !hasFeatures(hello.GetHello().GetFeatures(), requiredHelloFeatures) {
		return fail(errors.New("authorityrpc: authority omitted required current-state features"))
	}
	if len(hello.GetEpoch()) != len(volumeserver.Epoch{}) {
		return fail(errors.New("authorityrpc: protocol handshake omitted a valid authority epoch"))
	}
	negotiatedFrame := hello.GetHello().GetMaxFrameBytes()
	if negotiatedFrame == 0 || hello.GetHello().GetMaxReadBytes() == 0 || hello.GetHello().GetMaxWriteBytes() == 0 || hello.GetHello().GetMaxInFlight() == 0 {
		return fail(errors.New("authorityrpc: authority omitted allocation bounds"))
	}
	if uint64(c.cfg.MaxInFlight) > uint64(hello.GetHello().GetMaxInFlight()) {
		return fail(errors.New("authorityrpc: client max-in-flight exceeds the authority connection bound"))
	}
	if negotiatedFrame > c.cfg.MaxFrame {
		negotiatedFrame = c.cfg.MaxFrame
	}
	if uint64(hello.GetHello().GetMaxReadBytes())+uint64(FramePayloadReserve) > uint64(negotiatedFrame) ||
		uint64(hello.GetHello().GetMaxWriteBytes())+uint64(FramePayloadReserve) > uint64(negotiatedFrame) {
		return fail(errors.New("authorityrpc: I/O payload bounds exceed the negotiated frame"))
	}
	c.frameMax.Store(negotiatedFrame)
	if resume {
		if !equalBytes(hello.GetEpoch(), c.epoch) {
			c.signalSessionEnd(ErrAuthorityChanged)
			return fail(ErrAuthorityChanged)
		}
		request := &authoritypb.Request{RequestId: 2, Epoch: append([]byte(nil), c.epoch...), Session: cloneProof(c.proof), Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}}
		if err := writeFrame(conn, c.frameMax.Load(), request); err != nil {
			return fail(err)
		}
		var response authoritypb.Response
		if err := readFrame(conn, c.frameMax.Load(), nil, 0, &response); err != nil {
			return fail(err)
		}
		if response.GetRequestId() != request.GetRequestId() || !equalBytes(response.GetEpoch(), c.epoch) {
			c.signalSessionEnd(ErrAuthorityChanged)
			return fail(ErrAuthorityChanged)
		}
		if response.GetErrno() != 0 {
			c.signalSessionEnd(ErrSessionEnded)
			return fail(fmt.Errorf("%w: resume refused with errno %d", ErrSessionEnded, response.GetErrno()))
		}
	} else {
		attach := &authoritypb.AttachRequest{
			VolumeId: c.cfg.VolumeID, AccessToken: append([]byte(nil), c.cfg.AccessToken...),
			ReplaySlots: c.cfg.ReplaySlots, CoherenceProfile: c.cfg.CoherenceProfile,
			RoutesRevision: append([]byte(nil), c.cfg.RoutesRevision[:]...),
		}
		if c.cfg.CoherenceProfile == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
			attach.CachedNameCapacity = c.cfg.CachedNameCapacity
			attach.RepairBudgetMillis = uint64(c.cfg.RepairBudget / time.Millisecond)
			attach.NamespaceRepair = c.cfg.NamespaceRepair
		}
		request := &authoritypb.Request{RequestId: 2, Body: &authoritypb.Request_Attach{Attach: attach}}
		if err := writeFrame(conn, c.frameMax.Load(), request); err != nil {
			return fail(err)
		}
		var response authoritypb.Response
		if err := readFrame(conn, c.frameMax.Load(), nil, 0, &response); err != nil {
			return fail(err)
		}
		if response.GetRequestId() != request.GetRequestId() || response.GetErrno() != 0 || response.GetAttach() == nil {
			// A routing disagreement is the one attach refusal a caller can act
			// on directly: the refusal carries the volume's active revision AND
			// its declaration, which is the whole bootstrap for a mount that has
			// never seen this volume. It is returned whole, not rendered to a
			// string, because a caller cannot adopt a sentence. It still unwraps
			// to ErrRoutesMismatch for callers that only classify.
			if mismatch := routesMismatchError(response.GetRoutesMismatch()); mismatch != nil {
				return fail(mismatch)
			}
			return fail(fmt.Errorf("authorityrpc: attach refused with errno %d", response.GetErrno()))
		}
		if !hasFeatures(response.GetAttach().GetFeatures(), requiredAttachFeatures) {
			return fail(errors.New("authorityrpc: authority omitted required ordinary-filesystem features"))
		}
		if c.cfg.CoherenceProfile == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT &&
			!hasFeatures(response.GetAttach().GetFeatures(), []string{"strict-two-phase-visibility"}) {
			return fail(errors.New("authorityrpc: authority omitted strict visibility barriers"))
		}
		if !equalBytes(response.GetEpoch(), hello.GetEpoch()) ||
			len(response.GetAttach().GetSessionId()) != len(volumeserver.SessionID{}) ||
			len(response.GetAttach().GetResumeSecret()) != len(volumeserver.ResumeSecret{}) ||
			response.GetAttach().GetSessionGeneration() == 0 ||
			response.GetAttach().GetRoot() == nil ||
			len(response.GetAttach().GetRoot().GetToken()) != len(xfsstore.Capability{}) ||
			len(response.GetAttach().GetRoot().GetStableIdentity()) != 16 ||
			response.GetAttach().GetRoot().GetAttr() == nil ||
			response.GetAttach().GetRoot().GetAttr().GetKind() != authoritypb.Attr_DIRECTORY ||
			response.GetAttach().GetRoot().GetAttr().GetInode() == 0 {
			return fail(errors.New("authorityrpc: attach returned malformed session state"))
		}
		c.epoch = append([]byte(nil), response.GetEpoch()...)
		c.proof = &authoritypb.SessionProof{Id: append([]byte(nil), response.GetAttach().GetSessionId()...), Generation: response.GetAttach().GetSessionGeneration(), ResumeSecret: append([]byte(nil), response.GetAttach().GetResumeSecret()...)}
		c.root = proto.Clone(response.GetAttach().GetRoot()).(*authoritypb.Item)
		c.maxRead = hello.GetHello().GetMaxReadBytes()
		c.maxWrite = hello.GetHello().GetMaxWriteBytes()
		c.lease = time.Duration(response.GetAttach().GetSessionLeaseMilliseconds()) * time.Millisecond
		if c.lease <= 0 {
			return fail(errors.New("authorityrpc: authority omitted session lease"))
		}
		if c.cfg.CoherenceProfile == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
			if initial := response.GetAttach().GetVisibilityCursor(); initial != nil {
				if initial.GetSequence() == 0 || initial.GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
					return fail(errors.New("authorityrpc: authority returned an invalid initial visibility cursor"))
				}
				c.visibilityCursor = proto.Clone(initial).(*authoritypb.VisibilityCursor)
			}
		}
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	// The request-ID counter is reset before the connection is published, so a
	// concurrent caller can never register a pending entry under a pre-reset ID.
	c.nextID.Store(2)
	c.pendingMu.Lock()
	c.conn = conn
	c.pendingMu.Unlock()
	go c.readLoop(conn)
	return nil
}

// Reconnect resumes only the same authority epoch. A changed epoch is a hard
// mount boundary; the caller must not replay an uncertain mutation.
func (c *Client) Reconnect(ctx context.Context) error { return c.connect(ctx, true) }

func (c *Client) Root() *authoritypb.Item {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if c.root == nil {
		return nil
	}
	return proto.Clone(c.root).(*authoritypb.Item)
}

// Epoch is the authority incarnation this client attached to. A strict
// frontend carries it across its local cache-coherence boundary and echoes it
// on every visibility acknowledgement; an acknowledgement for any other epoch
// is stale by definition and must never reach the authority.
func (c *Client) Epoch() []byte {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return append([]byte(nil), c.epoch...)
}

// IOLimits returns the authority-negotiated maximum payload sizes. Mount
// frontends must split larger kernel requests instead of relying on a shared
// compile-time constant.
func (c *Client) IOLimits() (maxRead, maxWrite uint32) {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return c.maxRead, c.maxWrite
}

// DataPlaneOperationLimit is the number of ordinary filesystem calls a mount
// may issue concurrently. Strict clients have already carved distinct
// visibility and liveness permits out of the negotiated ordinary server bound.
func (c *Client) DataPlaneOperationLimit() int {
	return cap(c.ordinary.permits)
}

// SessionID is the authority-assigned session ID from the attach reply. A
// strict frontend needs it to recognise its own mutations in a visibility
// event's initiator field: that comparison is what exempts the frontend's own
// in-flight callback from its own PREPARE drain, so without it a strict mount
// would deadlock against itself and must refuse to run.
func (c *Client) SessionID() []byte {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if c.proof == nil {
		return nil
	}
	return append([]byte(nil), c.proof.GetId()...)
}

func (c *Client) SessionLease() time.Duration {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return c.lease
}

func (c *Client) InitialVisibilityCursor() *authoritypb.VisibilityCursor {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if c.visibilityCursor == nil {
		return nil
	}
	return proto.Clone(c.visibilityCursor).(*authoritypb.VisibilityCursor)
}

// NextVisibility long-polls the exact next two-phase cache event. after is the
// last cursor whose Ack the authority accepted.
func (c *Client) NextVisibility(ctx context.Context, after *authoritypb.VisibilityCursor) (*authoritypb.VisibilityEvent, error) {
	if c.cfg.CoherenceProfile != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
		return nil, syscall.EOPNOTSUPP
	}
	response, err := c.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_NextVisibility{NextVisibility: &authoritypb.NextVisibilityRequest{After: after}}})
	if err != nil {
		return nil, err
	}
	if response.GetErrno() != 0 {
		return nil, c.endStrictMount(syscall.Errno(response.GetErrno()))
	}
	if response.GetVisibility() == nil {
		return nil, c.endStrictMount(errors.New("authorityrpc: visibility poll returned no event"))
	}
	return proto.Clone(response.GetVisibility()).(*authoritypb.VisibilityEvent), nil
}

// endStrictMount is the client half of participant-scoped fencing. The
// authority fences one mount by ending its session, so any refusal on this
// mount's visibility stream means it is no longer in the barrier and must stop
// serving from its kernel cache. Continuing on any other footing would be the
// stale-name failure the barrier exists to prevent.
func (c *Client) endStrictMount(cause error) error {
	c.signalSessionEnd(ErrSessionEnded)
	return cause
}

// AckVisibility is idempotent for the last accepted cursor, including when its
// response was lost and a later phase is already pending.
func (c *Client) AckVisibility(ctx context.Context, cursor *authoritypb.VisibilityCursor) error {
	if c.cfg.CoherenceProfile != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT || cursor == nil {
		return syscall.EINVAL
	}
	response, err := c.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_AckVisibility{AckVisibility: &authoritypb.AckVisibilityRequest{Cursor: cursor}}})
	if err != nil {
		return err
	}
	if response.GetErrno() != 0 {
		return c.endStrictMount(syscall.Errno(response.GetErrno()))
	}
	return nil
}

// ApplyRoutes installs a new machine-local routing declaration for the whole
// volume. It needs admin scope, and it is not a mount operation: it takes no
// replay slot because its identity is the compare-and-swap on expected, which
// is a better answer to a retry than a retained reply - a caller that resubmits
// an applied change is told which revision is active now.
func (c *Client) ApplyRoutes(ctx context.Context, rules []byte, expected [32]byte) (*authoritypb.ApplyRoutesReply, error) {
	request := &authoritypb.Request{Body: &authoritypb.Request_ApplyRoutes{ApplyRoutes: &authoritypb.ApplyRoutesRequest{
		Rules:            append([]byte(nil), rules...),
		ExpectedRevision: append([]byte(nil), expected[:]...),
	}}}
	// Deliberately not CallRead: a routing change reaches the volume, so a
	// transport break must not be retried behind the caller's back.
	response, err := c.Call(ctx, request)
	if err != nil {
		return nil, err
	}
	if mismatch := routesMismatchError(response.GetRoutesMismatch()); mismatch != nil {
		// The compare-and-swap lost. It carries the revision that is active now,
		// which is what a caller needs to re-read and retry against.
		return nil, mismatch
	}
	if response.GetErrno() != 0 {
		return nil, syscall.Errno(response.GetErrno())
	}
	if response.GetApplyRoutes() == nil {
		return nil, errors.New("authorityrpc: apply routes returned no revision")
	}
	return proto.Clone(response.GetApplyRoutes()).(*authoritypb.ApplyRoutesReply), nil
}

// ReportVisibilityBlocked tells the authority this mount cannot service the
// phase it is holding, because the repair would wait on a kernel lock one of
// this mount's own unanswered requests holds. It always ends this session, so
// the caller must revoke locally on a return of any kind. The authority retains
// the current obligation for one full fencing grace before the peer mutation
// can finish; reporting does not shorten that safety window.
//
// It may only be sent when BOTH halves are true: this mount has an unanswered
// namespace mutation in the affected parent, and it actually holds a cached
// binding this phase names. A mount with nothing cached to repair must
// acknowledge normally; the authority checks the half it can see and treats an
// unsupported report as a cursor violation.
func (c *Client) ReportVisibilityBlocked(ctx context.Context, cursor *authoritypb.VisibilityCursor) error {
	if c.cfg.CoherenceProfile != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT || cursor == nil {
		return syscall.EINVAL
	}
	response, err := c.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_AckVisibility{
		AckVisibility: &authoritypb.AckVisibilityRequest{Cursor: cursor, Blocked: true},
	}})
	if err != nil {
		c.signalSessionEnd(ErrSessionEnded)
		return err
	}
	if response.GetErrno() != 0 {
		return c.endStrictMount(syscall.Errno(response.GetErrno()))
	}
	// The authority is required to end this session, so a success is the one
	// answer that means this client and that authority disagree about what just
	// happened. Continuing to serve a cache on that footing is not an option.
	return c.endStrictMount(errors.New("authorityrpc: authority accepted a blocked visibility report without fencing this mount"))
}

// VisibilityRepairBudget is the per-phase deadline this mount committed to at
// attach. A strict frontend must revoke its own kernel mount rather than
// acknowledge a phase later than this, because the authority may already have
// fenced its session and begun the separate grace before the volume moves on.
func (c *Client) VisibilityRepairBudget() time.Duration { return c.cfg.RepairBudget }

// DetachAfterUnmount leaves the barrier against evidence that this mount's
// kernel mount is gone. The proof is produced by whichever local component can
// observe that absence; this client deliberately cannot synthesize one, because
// the previous design's unconditional boolean is exactly what made a detach an
// assertion instead of an observation. A strict caller with no proof to present
// must close instead and let its session die, which fences it.
func (c *Client) DetachAfterUnmount(ctx context.Context, proof *authoritypb.MountAbsenceProof) error {
	request := &authoritypb.DetachRequest{}
	if c.cfg.CoherenceProfile == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
		if proof == nil || len(proof.GetObservation()) == 0 || proof.GetComponent() == "" || proof.GetObservedUnixNanos() <= 0 {
			return syscall.EPERM
		}
		request.MountAbsence = proto.Clone(proof).(*authoritypb.MountAbsenceProof)
	}
	response, err := c.Call(ctx, &authoritypb.Request{Body: &authoritypb.Request_Detach{Detach: request}})
	if err != nil {
		return err
	}
	if response.GetErrno() != 0 {
		return syscall.Errno(response.GetErrno())
	}
	return nil
}

// SessionDone closes when this client can no longer safely continue the mount:
// an idle connection died without an in-flight call to drive same-epoch
// recovery, the authority epoch changed, an exact outcome became uncertain, or
// the client was closed. SessionError returns the terminal cause after closure.
func (c *Client) SessionDone() <-chan struct{} { return c.fatalDone }

func (c *Client) SessionError() error {
	c.fatalMu.Lock()
	defer c.fatalMu.Unlock()
	return c.fatalErr
}

func (c *Client) signalSessionEnd(err error) {
	if err == nil {
		err = ErrTransportUncertain
	}
	c.fatalOnce.Do(func() {
		c.poisoned.Store(true)
		c.fatalMu.Lock()
		c.fatalErr = err
		close(c.fatalDone)
		c.fatalMu.Unlock()
	})
}

func (c *Client) laneFor(request *authoritypb.Request) *lane {
	if request.GetKeepAlive() != nil && c.cfg.CoherenceProfile == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
		return &c.liveness
	}
	if request.GetNextVisibility() != nil || request.GetAckVisibility() != nil {
		return &c.visibility
	}
	if blockingWait(request) {
		return &c.blocking
	}
	return &c.ordinary
}

// Call submits one request under this client's admission bounds. Mutations
// must go through CallMutation, which owns the replay identity.
func (c *Client) Call(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request == nil || request.GetHello() != nil || request.GetAttach() != nil {
		return nil, syscall.EINVAL
	}
	admitted := c.laneFor(request)
	select {
	case admitted.permits <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-admitted.permits }()
	return c.dispatch(ctx, request)
}

// dispatch performs one round trip. Admission is the caller's responsibility so
// that a replay slot is never taken before the permit that bounds it.
func (c *Client) dispatch(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	request = protoCloneRequest(request)
	request.RequestId = c.nextID.Add(1)
	request.Epoch = append([]byte(nil), c.epoch...)
	request.Session = cloneProof(c.proof)
	result := make(chan callResult, 1)
	c.pendingMu.Lock()
	if c.closed {
		c.pendingMu.Unlock()
		return nil, net.ErrClosed
	}
	if c.conn == nil {
		terminal := c.poisoned.Load()
		c.pendingMu.Unlock()
		if terminal {
			if err := c.SessionError(); err != nil {
				return nil, err
			}
			return nil, ErrSessionEnded
		}
		// Nothing was written. Classifying this as a transport break lets the
		// read and mutation wrappers safely establish the same epoch and submit
		// the operation once, while their replay identity remains unchanged.
		return nil, ErrTransportUncertain
	}
	c.pending[request.RequestId] = result
	conn := c.conn
	c.pendingMu.Unlock()

	err := c.writeRequest(ctx, conn, request)
	if err != nil {
		c.failConnection(conn, ErrTransportUncertain)
	}
	select {
	case <-ctx.Done():
		c.sendCancel(request.RequestId, conn)
		timer := time.NewTimer(c.cfg.CancelDrainTimeout)
		defer timer.Stop()
		select {
		case completed := <-result:
			return c.completeCall(request, completed)
		case <-timer.C:
			c.failConnection(conn, ErrTransportUncertain)
			return nil, ctx.Err()
		}
	case completed := <-result:
		return c.completeCall(request, completed)
	}
}

func (c *Client) completeCall(request *authoritypb.Request, completed callResult) (*authoritypb.Response, error) {
	if completed.err == nil && completed.response != nil && completed.response.GetErrno() == int32(syscall.ESTALE) && request.GetKeepAlive() != nil {
		c.signalSessionEnd(ErrSessionEnded)
	}
	return completed.response, completed.err
}

func (c *Client) sendCancel(target uint64, conn net.Conn) {
	request := &authoritypb.Request{
		RequestId: c.nextID.Add(1), Epoch: append([]byte(nil), c.epoch...), Session: cloneProof(c.proof),
		Body: &authoritypb.Request_Cancel{Cancel: &authoritypb.CancelRequest{TargetRequestId: target}},
	}
	err := c.writeRequest(context.Background(), conn, request)
	if err != nil {
		c.failConnection(conn, ErrTransportUncertain)
	}
}

func (c *Client) writeRequest(ctx context.Context, conn net.Conn, request *authoritypb.Request) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	deadline := time.Now().Add(c.cfg.CancelDrainTimeout)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return writeFrame(conn, c.frameMax.Load(), request)
}

// CallRead retries a side-effect-free operation once after reconnecting to the
// same epoch. A new epoch is always returned to the mount as a hard boundary.
func (c *Client) CallRead(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if c.poisoned.Load() {
		return nil, ErrTransportUncertain
	}
	response, err := c.Call(ctx, request)
	if !errors.Is(err, ErrTransportUncertain) {
		return response, err
	}
	if err := c.Reconnect(ctx); err != nil {
		c.signalSessionEnd(err)
		return nil, err
	}
	return c.Call(ctx, request)
}

// CallMutation assigns one replay slot/sequence from this request's admission
// lane, reconnects and replays only against the same live authority epoch, and
// then synchronizes the slot to the state the authority reports it recorded.
// The client never infers that the authority advanced a slot: every rejection
// the authority makes before recording an outcome leaves both counters equal.
// Cancellation after send poisons the client because the outcome is genuinely
// uncertain to the caller.
func (c *Client) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	return c.CallMutationWithIdentity(ctx, request, nil)
}

// CallMutationWithIdentity is CallMutation with one pre-dispatch identity
// publication point. The callback is invoked exactly once, before the first
// dispatch, and is not repeated if the same request is replayed after a
// same-epoch reconnect.
func (c *Client) CallMutationWithIdentity(ctx context.Context, request *authoritypb.Request, assigned MutationAssigned) (*authoritypb.Response, error) {
	if c.poisoned.Load() {
		return nil, ErrTransportUncertain
	}
	admitted := c.laneFor(request)
	select {
	case admitted.permits <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-admitted.permits }()

	// The permit is held, so at most cap(permits) callers can be between here
	// and the matching release, and the lane owns at least that many slots.
	// Round-robin therefore hands every concurrent caller a distinct slot.
	local := (admitted.nextSlot.Add(1) - 1) % uint32(len(admitted.slots))
	slot := &admitted.slots[local]
	index := admitted.base + local
	slot.mu.Lock()
	defer slot.mu.Unlock()

	request = protoCloneRequest(request)
	sequence := slot.sequence + 1
	request.Mutation = &authoritypb.Mutation{Slot: index, Sequence: sequence}
	hash, err := canonicalHash(request)
	if err != nil {
		return nil, err
	}
	request.Mutation.RequestHash = append([]byte(nil), hash[:]...)
	if assigned != nil {
		if err := assigned(MutationIdentity{Slot: index, Sequence: sequence}); err != nil {
			return nil, err
		}
	}
	response, err := c.dispatch(ctx, request)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		c.signalSessionEnd(ErrTransportUncertain)
		return nil, ErrTransportUncertain
	}
	if errors.Is(err, ErrTransportUncertain) {
		if reconnectErr := c.Reconnect(ctx); reconnectErr != nil {
			c.signalSessionEnd(reconnectErr)
			return nil, reconnectErr
		}
		response, err = c.dispatch(ctx, request)
	}
	if err != nil {
		return nil, err
	}
	if err := synchronizeSlot(slot, index, sequence, response.GetMutation()); err != nil {
		c.signalSessionEnd(err)
		return nil, err
	}
	if response.GetUncertain() {
		c.signalSessionEnd(ErrTransportUncertain)
	}
	return response, nil
}

// synchronizeSlot copies the authority's recorded slot state. An absent state
// means the authority refused the request before recording anything, so the
// slot legitimately stays where it is and the next mutation reuses the same
// sequence. Any other value is a desynchronization, not a recoverable error.
func synchronizeSlot(slot *clientSlot, index uint32, sequence uint64, state *authoritypb.MutationState) error {
	if state == nil {
		return nil
	}
	if state.GetSlot() != index || state.GetAcceptedSequence() != sequence {
		return fmt.Errorf("%w: submitted slot %d sequence %d, authority recorded slot %d sequence %d",
			ErrReplayDesynchronized, index, sequence, state.GetSlot(), state.GetAcceptedSequence())
	}
	slot.sequence = sequence
	return nil
}

func (c *Client) readLoop(conn net.Conn) {
	for {
		var response authoritypb.Response
		if err := readFrame(conn, c.frameMax.Load(), nil, 0, &response); err != nil {
			c.failConnection(conn, ErrTransportUncertain)
			return
		}
		if !equalBytes(response.GetEpoch(), c.epoch) {
			c.signalSessionEnd(ErrAuthorityChanged)
			c.failConnection(conn, ErrAuthorityChanged)
			return
		}
		if response.GetUncertain() {
			c.signalSessionEnd(ErrTransportUncertain)
		}
		if response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
			c.signalSessionEnd(ErrSessionEnded)
		}
		// The volume's routing topology moved under this mount. Continuing would
		// mean serving a tree whose local subtrees no longer match the volume's,
		// so this is terminal for the mount rather than a retryable refusal. It
		// is keyed on the authority's explicit flag, not on comparing revisions,
		// because an ApplyRoutes that lost its compare-and-swap carries the same
		// two values and is terminal for nobody.
		if response.GetRoutesMismatch().GetSessionRefused() {
			c.signalSessionEnd(ErrRoutesMismatch)
		}
		c.pendingMu.Lock()
		waiter := c.pending[response.GetRequestId()]
		delete(c.pending, response.GetRequestId())
		c.pendingMu.Unlock()
		if waiter != nil {
			waiter <- callResult{response: &response}
		}
	}
}

func (c *Client) failConnection(conn net.Conn, err error) {
	c.pendingMu.Lock()
	if c.conn != conn {
		c.pendingMu.Unlock()
		return
	}
	c.conn = nil
	pending := c.pending
	c.pending = make(map[uint64]chan callResult)
	idle := len(pending) == 0 && !c.closed
	if idle {
		c.signalSessionEnd(err)
	}
	c.pendingMu.Unlock()
	_ = conn.Close()
	for _, waiter := range pending {
		waiter <- callResult{err: err}
	}
}

func (c *Client) Close() error {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	c.pendingMu.Lock()
	if c.closed {
		c.pendingMu.Unlock()
		return nil
	}
	c.closed = true
	conn := c.conn
	c.conn = nil
	pending := c.pending
	c.pending = make(map[uint64]chan callResult)
	c.pendingMu.Unlock()
	for _, waiter := range pending {
		waiter <- callResult{err: net.ErrClosed}
	}
	if conn != nil {
		err := conn.Close()
		c.signalSessionEnd(net.ErrClosed)
		return err
	}
	c.signalSessionEnd(net.ErrClosed)
	return nil
}

func protoCloneRequest(request *authoritypb.Request) *authoritypb.Request {
	return proto.Clone(request).(*authoritypb.Request)
}
func cloneProof(proof *authoritypb.SessionProof) *authoritypb.SessionProof {
	if proof == nil {
		return nil
	}
	return &authoritypb.SessionProof{Id: append([]byte(nil), proof.GetId()...), Generation: proof.GetGeneration(), ResumeSecret: append([]byte(nil), proof.GetResumeSecret()...)}
}
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}
