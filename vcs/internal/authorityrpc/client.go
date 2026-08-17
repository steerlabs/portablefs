package authorityrpc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

// PreKernelMountAbsenceObserver produces the supervisor's exact local evidence
// that this mount attempt has not installed its kernel source. Implementations
// must bind the observation to a unique attempt identity, not merely to a path.
type PreKernelMountAbsenceObserver func(context.Context) (*authoritypb.MountAbsenceProof, error)

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
	// binding unservable. Required by the one coherent profile: the authority
	// uses it to tell a proven repair cycle from a slow lock, and there is no
	// safe default for it.
	NamespaceRepair authoritypb.NamespaceRepair
	// RoutesRevision is the 32-byte digest of the canonical machine-local
	// routing rules this mount will run. Required for every profile: a mount
	// that routes a subtree to local disk hides it from every peer, so the
	// authority refuses any mount whose topology is not the volume's active one.
	RoutesRevision [32]byte
	// RequireMountEnrollmentReauthorization makes automatic hosted renewal an
	// attach-time contract. A mount configured with a Manager enrollment never
	// starts against an authority that cannot verify enrollment-backed grants.
	RequireMountEnrollmentReauthorization bool
	// ObservePreKernelMountAbsence is the strict mount supervisor's exact local
	// observation that this mount attempt has not installed its kernel source.
	// It is mandatory for strict coherence and is invoked only after the
	// authority has committed ACTIVE membership but before ownership has passed
	// to a kernel mount. The callback must identify this exact attempt rather
	// than infer absence from the mountpoint alone. A refusal or observation
	// failure is fail-closed: the durable strict-membership record is preserved.
	ObservePreKernelMountAbsence PreKernelMountAbsenceObserver
}

// MutationIdentity is the replay identity assigned to one authority mutation.
// A frontend uses the synchronous assignment boundary to make its exact local
// source-publication lease own every possible send and replay of the request.
type MutationIdentity struct {
	Slot     uint32
	Sequence uint64
}

// MutationAssigned runs synchronously after a mutation has its final replay
// identity, but before any bytes can reach the authority.
// It must be fast, nonblocking, and must not re-enter Client. Returning an error
// sends nothing and leaves the replay slot unadvanced.
type MutationAssigned func(MutationIdentity) error

// ResponseConsumption retains one parsed authority mutation response through
// the frontend boundary which makes that response locally observable. For a
// strict Linux state-bearing result, that boundary is the physical
// FUSE_PFS_PUBLISH ACK; for a definite no-change result it is the physical
// write of the ordinary kernel reply. Consume is idempotent.
//
// A terminal response may carry an authority delivery token. Consume then
// sends the exact CONTROL receipt and waits for its acknowledgment before
// releasing the local terminal hold. This keeps SessionDone behind both the
// frontend's physical kernel boundary and the authority's proof of delivery.
type ResponseConsumption interface {
	Consume()
}

type responseConsumption struct {
	client        *Client
	once          sync.Once
	forceOnce     sync.Once
	force         func(error)
	terminalToken []byte
}

// Consume acknowledges that the frontend has either physically published the
// exact response or revoked its local serving boundary without publishing it.
func (r *responseConsumption) Consume() {
	if r == nil || r.client == nil {
		return
	}
	r.once.Do(func() { r.client.consumeResponse(r) })
}

func (r *responseConsumption) revoke(cause error) {
	if r == nil || r.force == nil {
		return
	}
	r.forceOnce.Do(func() { r.force(cause) })
}

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

	// lifecycle protects shared session state and the reconnect TLS identity.
	// Physical connection state is never placed under it: DATA and CONTROL must
	// be able to reconnect and make progress independently.
	lifecycle              sync.Mutex
	data                   *clientTransport
	control                *clientTransport
	connectionSetID        [32]byte
	attachAttemptID        [32]byte
	ordinary               lane
	blocking               lane
	visibility             lane
	liveness               lane
	epoch                  []byte
	helloFeatures          []string
	negotiatedFrame        uint32
	negotiatedInFlight     uint32
	proof                  *authoritypb.SessionProof
	root                   *authoritypb.Item
	authorizationDeadline  time.Time
	maxRead                uint32
	maxWrite               uint32
	maxWriteTransaction    uint64
	lease                  time.Duration
	visibilityCursor       *authoritypb.VisibilityCursor
	peerCompleteFeedback   atomic.Bool
	sessionReauthorization atomic.Bool
	poisoned               atomic.Bool
	closed                 atomic.Bool
	fatalMu                sync.Mutex
	fatalErr               error
	fatalDone              chan struct{}
	fatalPending           bool
	fatalPublished         bool
	fatalDrainTimer        *time.Timer
	responseConsumptions   map[*responseConsumption]struct{}
	preMountReleaseMu      sync.Mutex
	preMountReleaseDone    chan struct{}
	preMountReleaseErr     error
	// testAfterResponseParsed pauses the retained mutation path after readLoop
	// has delivered a complete frame but before the frontend caller can consume
	// it. Nil in production.
	testAfterResponseParsed func()
}

type clientSlot struct {
	mu sync.Mutex
	// sequence mirrors what the authority reported as recorded for this slot.
	// It is only ever assigned from a MutationState the authority returned, so
	// the two counters cannot drift apart.
	sequence uint64
}

// clientSessionCacheEntries bounds the TLS 1.3 tickets one client keeps. Every
// dial this client makes uses the same authority server name, so the cache holds
// one live entry and the remainder is headroom for the tickets an authority
// issues alongside it. The cache belongs to the Client rather than to the caller
// supplied *tls.Config: resumption then can never carry one mount's proven
// identity into another's handshake.
const clientSessionCacheEntries = 8

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
	if cfg.CoherenceProfile != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
		return nil, errors.New("authorityrpc: protocol 5 requires the coherent mount profile")
	}
	if cfg.ObservePreKernelMountAbsence == nil {
		return nil, errors.New("authorityrpc: strict coherence requires an exact pre-kernel mount-absence observer")
	}
	cfg.TLS = cfg.TLS.Clone()
	cfg.TLS.MinVersion = tls.VersionTLS13
	cfg.TLS.NextProtos = []string{protocolALPN}
	cfg.TLS.ClientSessionCache = tls.NewLRUClientSessionCache(clientSessionCacheEntries)
	ordinaryLimit, blockingLimit := blockingWaitLane(cfg.MaxInFlight)
	if cfg.CachedNameCapacity == 0 || cfg.RepairBudget <= 0 {
		return nil, errors.New("authorityrpc: strict coherence requires a declared kernel-cache capacity and repair budget")
	}
	if cfg.NamespaceRepair == authoritypb.NamespaceRepair_NAMESPACE_REPAIR_UNSPECIFIED {
		return nil, errors.New("authorityrpc: strict coherence requires a declared namespace-repair model")
	}
	slots := make([]clientSlot, cfg.ReplaySlots)
	split := cfg.ReplaySlots - uint32(blockingLimit)
	c := &Client{
		cfg: cfg, fatalDone: make(chan struct{}),
		data:       newClientTransport(authoritypb.TransportRole_TRANSPORT_ROLE_DATA),
		control:    newClientTransport(authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL),
		ordinary:   lane{permits: make(chan struct{}, ordinaryLimit), slots: slots[:split], base: 0},
		blocking:   lane{permits: make(chan struct{}, blockingLimit), slots: slots[split:], base: split},
		visibility: lane{permits: make(chan struct{}, 1)},
		liveness:   lane{permits: make(chan struct{}, 1)},
	}
	connectionSetID, err := randomProtocolIdentity()
	if err != nil {
		return nil, fmt.Errorf("authorityrpc: create connection-set identity: %w", err)
	}
	attachAttemptID, err := randomProtocolIdentity()
	if err != nil {
		return nil, fmt.Errorf("authorityrpc: create attach-attempt identity: %w", err)
	}
	c.connectionSetID = connectionSetID
	c.attachAttemptID = attachAttemptID
	if err := c.attachAndActivate(ctx); err != nil {
		_ = c.closeTransports()
		return nil, err
	}
	return c, nil
}

func (c *Client) attachAndActivate(ctx context.Context) error {
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
	defer handshakeCancel()
	data, control, err := c.openInitialPair(handshakeCtx)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		closeNegotiations(data, control)
		return err
	}
	c.lifecycle.Lock()
	c.epoch = append([]byte(nil), data.epoch...)
	c.helloFeatures = append([]string(nil), data.features...)
	c.negotiatedFrame = data.maxFrame
	c.negotiatedInFlight = data.maxInFlight
	c.maxRead = data.maxRead
	c.maxWrite = data.maxWrite
	c.maxWriteTransaction = data.maxWriteTransaction
	c.lifecycle.Unlock()
	c.peerCompleteFeedback.Store(hasFeatures(data.features, []string{peerCompleteFIFOFeedbackFeature}))
	c.sessionReauthorization.Store(hasFeatures(data.features, []string{sessionReauthorizationFeature}))

	attach := &authoritypb.AttachRequest{
		VolumeId: c.cfg.VolumeID, AccessToken: append([]byte(nil), c.cfg.AccessToken...),
		ReplaySlots: c.cfg.ReplaySlots, CoherenceProfile: c.cfg.CoherenceProfile,
		RoutesRevision:  append([]byte(nil), c.cfg.RoutesRevision[:]...),
		AttachAttemptId: append([]byte(nil), c.attachAttemptID[:]...),
	}
	attach.CachedNameCapacity = c.cfg.CachedNameCapacity
	attach.RepairBudgetMillis = uint64(c.cfg.RepairBudget / time.Millisecond)
	attach.NamespaceRepair = c.cfg.NamespaceRepair
	attachRequest := &authoritypb.Request{RequestId: 2, Body: &authoritypb.Request_Attach{Attach: attach}}
	response, err := rawRoundTrip(data.conn, data.maxFrame, attachRequest)
	for err != nil {
		// The provisional result is keyed by attach_attempt_id. Reconnect both
		// roles with the same set and replay that exact Attach; this learns the
		// credential instead of leaking it until its deadline or inventing a
		// second session.
		closeNegotiations(data, control)
		data, control, err = c.reopenInitialPair(handshakeCtx)
		if err != nil {
			return fail(fmt.Errorf("%w: provisional Attach recovery failed: %v", ErrTransportUncertain, err))
		}
		response, err = rawRoundTrip(data.conn, data.maxFrame, attachRequest)
	}
	if !equalBytes(response.GetEpoch(), data.epoch) {
		return fail(ErrAuthorityChanged)
	}
	if response.GetErrno() != 0 || response.GetAttach() == nil {
		if mismatch := routesMismatchError(response.GetRoutesMismatch()); mismatch != nil {
			return fail(mismatch)
		}
		return fail(fmt.Errorf("authorityrpc: attach refused with errno %d", response.GetErrno()))
	}
	provisional := response.GetAttach()
	if len(provisional.GetSessionId()) != len(volumeserver.SessionID{}) ||
		len(provisional.GetResumeSecret()) != len(volumeserver.ResumeSecret{}) || provisional.GetGeneration() == 0 {
		return fail(errors.New("authorityrpc: attach returned malformed provisional session state"))
	}
	c.lifecycle.Lock()
	c.proof = &authoritypb.SessionProof{
		Id: append([]byte(nil), provisional.GetSessionId()...), Generation: provisional.GetGeneration(),
		ResumeSecret: append([]byte(nil), provisional.GetResumeSecret()...),
	}
	c.lifecycle.Unlock()
	if provisional.GetProvisionalDeadlineUnixNanos() <= time.Now().UnixNano() ||
		provisional.GetDataBindingGeneration() == 0 || provisional.GetControlBindingGeneration() == 0 {
		_ = c.abortProvisional(control, 3)
		return fail(errors.New("authorityrpc: attach returned malformed provisional transport state"))
	}

	activateRequest := func(id uint64, dataGeneration, controlGeneration uint64) *authoritypb.Request {
		epoch, proof := c.sessionEnvelope()
		return &authoritypb.Request{RequestId: id, Epoch: epoch, Session: proof, Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId:       append([]byte(nil), c.attachAttemptID[:]...),
			DataBindingGeneration: dataGeneration, ControlBindingGeneration: controlGeneration,
		}}}
	}
	dataGeneration := provisional.GetDataBindingGeneration()
	controlGeneration := provisional.GetControlBindingGeneration()
	requestID := uint64(2)
	activateResponse, err := rawRoundTrip(control.conn, control.maxFrame, activateRequest(requestID, dataGeneration, controlGeneration))
	for err != nil {
		// Once any Activate frame may have reached the authority, Abort is
		// forbidden. Rebind both roles with proof, because loss of DATA can be
		// the reason CONTROL's activation response disappeared, then replay the
		// same attempt until its exact committed/refused result is learned.
		closeNegotiations(data, control)
		data, control, err = c.resumeRawPairForActivation(handshakeCtx)
		if err != nil {
			return fail(fmt.Errorf("%w: activation recovery failed: %v", ErrTransportUncertain, err))
		}
		dataGeneration = data.bindingGeneration()
		controlGeneration = control.bindingGeneration()
		requestID = 3
		activateResponse, err = rawRoundTrip(control.conn, control.maxFrame, activateRequest(requestID, dataGeneration, controlGeneration))
	}
	if !equalBytes(activateResponse.GetEpoch(), data.epoch) {
		return fail(ErrAuthorityChanged)
	}
	if activateResponse.GetErrno() != 0 || activateResponse.GetActivate() == nil {
		activationErr := fmt.Errorf("authorityrpc: activation refused with errno %d", activateResponse.GetErrno())
		// Even if an earlier response was lost, this exact replay has now
		// learned the attempt's non-committed result. Abort is safe only after
		// that definite verdict; it is never sent from the uncertainty loop.
		_ = c.abortProvisional(control, 4)
		return fail(activationErr)
	}
	active := activateResponse.GetActivate()
	// A successful Activate response is the commit witness: the server validates
	// ACTIVE and commits strict membership before that response can be written.
	// Every local body validation after this point, including State, therefore
	// owns an authenticated Detach if publication cannot finish.
	if err := c.publishCommittedActivation(active, data, control, dataGeneration, controlGeneration, requestID+1); err != nil {
		return fail(err)
	}
	return nil
}

// publishCommittedActivation is the single ownership boundary between a
// server-committed ACTIVE session and a locally usable Client. Every failure
// here must release that ownership with exact mount-absence evidence.
func (c *Client) publishCommittedActivation(
	active *authoritypb.ActivateReply,
	data, control *transportNegotiation,
	dataGeneration, controlGeneration, cleanupRequestID uint64,
) error {
	if err := c.installActiveState(active); err != nil {
		return c.releaseCommittedBeforePublication(err, control, cleanupRequestID)
	}
	if err := c.publishInitialPair(data, control, dataGeneration, controlGeneration); err != nil {
		return c.releaseCommittedBeforePublication(err, control, cleanupRequestID)
	}
	return nil
}

// releaseCommittedBeforePublication owns the narrow failure boundary after an
// exact ACTIVE verdict but before DialClient can hand a usable Client to its
// caller. AbortAttach is forbidden after ACTIVE. The only clean transition is
// an authenticated Detach carrying the supervisor's exact observation that no
// kernel mount for this attempt exists yet.
func (c *Client) releaseCommittedBeforePublication(cause error, control *transportNegotiation, requestID uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.CancelDrainTimeout)
	defer cancel()
	proof, observeErr := c.observePreKernelMountAbsence(ctx)
	if observeErr != nil {
		return errors.Join(cause, fmt.Errorf("authorityrpc: observe ACTIVE session before client publication: %w", observeErr))
	}
	if detachErr := c.detachActiveRaw(ctx, control, requestID, proof); detachErr != nil {
		return errors.Join(cause, fmt.Errorf("authorityrpc: release ACTIVE session before client publication: %w", detachErr))
	}
	return cause
}

func (c *Client) observePreKernelMountAbsence(ctx context.Context) (*authoritypb.MountAbsenceProof, error) {
	observer := c.cfg.ObservePreKernelMountAbsence
	if observer == nil {
		return nil, errors.New("authorityrpc: exact pre-kernel mount-absence observer is unavailable")
	}
	proof, err := observer(ctx)
	if err != nil {
		return nil, err
	}
	if !completeMountAbsenceProof(proof) {
		return nil, errors.New("authorityrpc: exact pre-kernel mount-absence observer returned incomplete evidence")
	}
	return proto.Clone(proof).(*authoritypb.MountAbsenceProof), nil
}

func (c *Client) detachActiveRaw(ctx context.Context, control *transportNegotiation, requestID uint64, proof *authoritypb.MountAbsenceProof) error {
	if control == nil || control.conn == nil || requestID == 0 {
		return ErrTransportBinding
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.cfg.CancelDrainTimeout)
	}
	if err := control.conn.SetDeadline(deadline); err != nil {
		return err
	}
	epoch, session := c.sessionEnvelope()
	detach := &authoritypb.DetachRequest{}
	if proof != nil {
		detach.MountAbsence = proto.Clone(proof).(*authoritypb.MountAbsenceProof)
	}
	request := &authoritypb.Request{
		RequestId: requestID, Epoch: epoch, Session: session,
		Body: &authoritypb.Request_Detach{Detach: detach},
	}
	response, err := rawRoundTrip(control.conn, control.maxFrame, request)
	if err != nil {
		return err
	}
	if !equalBytes(response.GetEpoch(), epoch) {
		return ErrAuthorityChanged
	}
	if response.GetErrno() != 0 {
		return syscall.Errno(response.GetErrno())
	}
	return nil
}

func (c *Client) abortProvisional(control *transportNegotiation, requestID uint64) error {
	if control == nil || control.conn == nil {
		return ErrTransportBinding
	}
	epoch, proof := c.sessionEnvelope()
	request := &authoritypb.Request{RequestId: requestID, Epoch: epoch, Session: proof, Body: &authoritypb.Request_AbortAttach{AbortAttach: &authoritypb.AbortAttachRequest{
		AttachAttemptId: append([]byte(nil), c.attachAttemptID[:]...),
	}}}
	response, err := rawRoundTrip(control.conn, control.maxFrame, request)
	if err != nil {
		return err
	}
	if !equalBytes(response.GetEpoch(), epoch) || response.GetErrno() != 0 || response.GetAbortAttach() == nil ||
		response.GetAbortAttach().GetState() != authoritypb.SessionState_SESSION_STATE_ABORTED {
		return errors.New("authorityrpc: provisional AbortAttach was not confirmed")
	}
	return nil
}

func (c *Client) installActiveState(active *authoritypb.ActivateReply) error {
	if active == nil || active.GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		return errors.New("authorityrpc: authority omitted ACTIVE session state")
	}
	if !hasFeatures(active.GetFeatures(), requiredAttachFeatures) {
		return errors.New("authorityrpc: authority omitted required ordinary-filesystem features")
	}
	if c.cfg.RequireMountEnrollmentReauthorization && !hasFeatures(
		active.GetFeatures(), []string{mountEnrollmentReauthorizationFeature},
	) {
		return errors.New("authorityrpc: activation omitted Manager-enrolled mount reauthorization")
	}
	authorizationDeadline := time.Unix(0, active.GetAuthorizationDeadlineUnixNanos())
	if c.cfg.RequireMountEnrollmentReauthorization && !authorizationDeadline.After(time.Now()) {
		return errors.New("authorityrpc: automatic mount activation omitted its signed authorization deadline")
	}
	if !hasFeatures(active.GetFeatures(), requiredStrictAttachFeatures) {
		return errors.New("authorityrpc: authority omitted required strict visibility semantics")
	}
	root := active.GetRoot()
	if root == nil || len(root.GetToken()) != len(xfsstore.Capability{}) || len(root.GetStableIdentity()) != 16 ||
		root.GetAttr() == nil || root.GetAttr().GetKind() != authoritypb.Attr_DIRECTORY || root.GetAttr().GetInode() == 0 {
		return errors.New("authorityrpc: activation returned malformed root state")
	}
	lease := time.Duration(active.GetSessionLeaseMilliseconds()) * time.Millisecond
	if lease <= 0 {
		return errors.New("authorityrpc: authority omitted session lease")
	}
	if len(active.GetRoutesRevision()) != len(c.cfg.RoutesRevision) ||
		!equalBytes(active.GetRoutesRevision(), c.cfg.RoutesRevision[:]) {
		return errors.New("authorityrpc: activation did not confirm the exact routing revision")
	}
	initial := active.GetVisibilityCursor()
	if initial == nil || initial.GetSequence() == 0 || initial.GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
		return errors.New("authorityrpc: authority returned an invalid initial visibility cursor")
	}
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	c.root = proto.Clone(root).(*authoritypb.Item)
	c.lease = lease
	if active.GetAuthorizationDeadlineUnixNanos() != 0 {
		c.authorizationDeadline = authorizationDeadline
	}
	if initial != nil {
		c.visibilityCursor = proto.Clone(initial).(*authoritypb.VisibilityCursor)
	}
	return nil
}

func (opened *transportNegotiation) bindingGeneration() uint64 {
	if opened == nil {
		return 0
	}
	return opened.resumedBindingGeneration
}

// Reconnect restores whichever exact physical role is missing. A healthy role
// is never churned as collateral damage, and a changed epoch remains a hard
// mount boundary on either lane.
func (c *Client) Reconnect(ctx context.Context) error {
	if !c.transportIsLive(c.data) {
		if err := c.reconnectTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_DATA); err != nil {
			return err
		}
	}
	if !c.transportIsLive(c.control) {
		return c.reconnectTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	}
	return nil
}

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

// MaxWriteTransactionBytes returns the authority-negotiated bound for one
// staged SHARED write transaction. A production Linux mount compares it with
// its local kernel's MAX_RW_COUNT before exposing the mount.
func (c *Client) MaxWriteTransactionBytes() uint64 {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return c.maxWriteTransaction
}

// DataPlaneOperationLimit is the number of ordinary filesystem calls a mount
// may issue concurrently on DATA. Protocol 5 gives visibility and liveness a
// separate physical CONTROL transport, so those operations consume neither a
// DATA socket permit nor a DATA replay slot.
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

// Reauthorize rotates the signed decision underneath an existing mount. The
// manager assigns sequence and returns the same token for an idempotency key;
// the authority accepts an exact retry and refuses gaps or broadened access.
func (c *Client) Reauthorize(ctx context.Context, token []byte, sequence uint64) (time.Time, error) {
	if len(token) == 0 || sequence == 0 {
		return time.Time{}, syscall.EINVAL
	}
	if !c.sessionReauthorization.Load() {
		return time.Time{}, syscall.EOPNOTSUPP
	}
	response, err := c.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_Reauthorize{Reauthorize: &authoritypb.ReauthorizeRequest{
		AccessToken: append([]byte(nil), token...), Sequence: sequence,
	}}})
	if err != nil {
		return time.Time{}, err
	}
	if response.GetErrno() != 0 {
		if response.GetErrno() == int32(syscall.ESTALE) || response.GetErrno() == int32(syscall.EINVAL) {
			c.signalSessionEnd(ErrSessionEnded)
		}
		return time.Time{}, syscall.Errno(response.GetErrno())
	}
	if response.GetReauthorize() == nil || response.GetReauthorize().GetSequence() != sequence {
		c.signalSessionEnd(ErrSessionEnded)
		return time.Time{}, ErrSessionEnded
	}
	deadline := time.Unix(0, response.GetReauthorize().GetAuthorizationDeadlineUnixNanos())
	if !deadline.After(time.Now()) {
		c.signalSessionEnd(ErrSessionEnded)
		return time.Time{}, ErrSessionEnded
	}
	return deadline, nil
}

// ReauthorizeWithCertificate validates a manager-renewed certificate for the
// mount-local private key, rotates the live authorization, and only then makes
// the certificate visible to a future transport resume. The exact current
// connection performs Reauthorize under its still-valid identity; a failed
// authority decision never changes the reconnect identity.
func (c *Client) ReauthorizeWithCertificate(ctx context.Context, token []byte, sequence uint64, certificatePEM []byte, now time.Time) (time.Time, error) {
	replacement, err := c.replacementClientCertificate(certificatePEM, now)
	if err != nil {
		return time.Time{}, err
	}
	deadline, err := c.Reauthorize(ctx, token, sequence)
	if err != nil {
		return time.Time{}, err
	}
	c.lifecycle.Lock()
	c.cfg.TLS.Certificates = []tls.Certificate{*replacement}
	// A resumed TLS session carries the identity proven in the full handshake
	// that minted its ticket, so tickets held from the retired certificate would
	// keep authenticating later transports as the retired identity. Drop them
	// with the rotation: the renewed certificate is the only identity a future
	// resume may present.
	c.cfg.TLS.ClientSessionCache = tls.NewLRUClientSessionCache(clientSessionCacheEntries)
	c.lifecycle.Unlock()
	return deadline, nil
}

func (c *Client) replacementClientCertificate(certificatePEM []byte, now time.Time) (*tls.Certificate, error) {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if c.cfg.TLS == nil || len(c.cfg.TLS.Certificates) != 1 || c.cfg.TLS.Certificates[0].PrivateKey == nil {
		return nil, errors.New("authorityrpc: client identity is unavailable")
	}
	var chain [][]byte
	rest := bytes.TrimSpace(certificatePEM)
	for len(rest) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("authorityrpc: renewed identity must contain only CERTIFICATE PEM blocks")
		}
		chain = append(chain, append([]byte(nil), block.Bytes...))
		rest = bytes.TrimSpace(remaining)
	}
	if len(chain) == 0 {
		return nil, errors.New("authorityrpc: renewed identity contains no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("authorityrpc: parse renewed client certificate: %w", err)
	}
	signer, ok := c.cfg.TLS.Certificates[0].PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("authorityrpc: client private key is not a signer")
	}
	want, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	got, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(want, got) {
		return nil, errors.New("authorityrpc: renewed certificate does not match the mount-local private key")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || !certificatePermitsClientAuth(leaf.ExtKeyUsage) {
		return nil, errors.New("authorityrpc: renewed certificate is not currently valid for client authentication")
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: signer, Leaf: leaf}, nil
}

func certificatePermitsClientAuth(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// AuthorizationSessionID exposes the non-secret session identifier needed to
// bind a manager reauthorization grant. The resume secret remains private to
// this client and is never returned.
func (c *Client) AuthorizationSessionID() volumeserver.SessionID {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	var id volumeserver.SessionID
	if c.proof != nil && len(c.proof.GetId()) == len(id) {
		copy(id[:], c.proof.GetId())
	}
	return id
}

func (c *Client) InitialAuthorizationDeadline() time.Time {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return c.authorizationDeadline
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

// NextVisibilityAfterAck atomically acknowledges the repaired phase and waits
// for its successor in one authority request. The cursor is still the exact
// safety boundary: a lost response can repeat this request because Ack accepts
// the last recorded cursor idempotently, while Next never advances it.
func (c *Client) NextVisibilityAfterAck(ctx context.Context, after *authoritypb.VisibilityCursor, orderedAdmissionContended bool) (*authoritypb.VisibilityEvent, error) {
	if c.cfg.CoherenceProfile != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT || after == nil {
		return nil, syscall.EINVAL
	}
	makeRequest := func() *authoritypb.Request {
		return &authoritypb.Request{Body: &authoritypb.Request_NextVisibility{NextVisibility: &authoritypb.NextVisibilityRequest{
			After:                     after,
			AcknowledgeAfter:          true,
			OrderedAdmissionContended: orderedAdmissionContended && c.peerCompleteFeedback.Load(),
		}}}
	}
	if c.poisoned.Load() {
		return nil, ErrTransportUncertain
	}
	response, err := c.Call(ctx, makeRequest())
	if errors.Is(err, ErrTransportUncertain) {
		if reconnectErr := c.reconnectTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL); reconnectErr != nil {
			c.signalSessionEnd(reconnectErr)
			return nil, reconnectErr
		}
		response, err = c.Call(ctx, makeRequest())
	}
	if err != nil {
		return nil, err
	}
	if response.GetErrno() != 0 {
		return nil, c.endStrictMount(syscall.Errno(response.GetErrno()))
	}
	if response.GetVisibility() == nil {
		return nil, c.endStrictMount(errors.New("authorityrpc: combined visibility advance returned no event"))
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
	return c.AckVisibilityWithContention(ctx, cursor, false)
}

// AckVisibilityWithContention carries an optional liveness-only hint on the
// exact successful COMPLETE Ack. If the authority did not advertise support,
// the field remains absent and the frozen Ack encoding is preserved.
func (c *Client) AckVisibilityWithContention(ctx context.Context, cursor *authoritypb.VisibilityCursor, orderedAdmissionContended bool) error {
	if c.cfg.CoherenceProfile != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT || cursor == nil {
		return syscall.EINVAL
	}
	makeRequest := func() *authoritypb.Request {
		return &authoritypb.Request{Body: &authoritypb.Request_AckVisibility{AckVisibility: &authoritypb.AckVisibilityRequest{
			Cursor: cursor,
			OrderedAdmissionContended: orderedAdmissionContended &&
				c.peerCompleteFeedback.Load(),
		}}}
	}
	if c.poisoned.Load() {
		return ErrTransportUncertain
	}
	response, err := c.Call(ctx, makeRequest())
	if errors.Is(err, ErrTransportUncertain) {
		if reconnectErr := c.reconnectTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL); reconnectErr != nil {
			c.signalSessionEnd(reconnectErr)
			return reconnectErr
		}
		// Rebuild after reconnect: the optional field is legal only when the
		// exact newly active connection advertised it.
		response, err = c.Call(ctx, makeRequest())
	}
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

// ReportVisibilityBlocked is the terminal inability report for a routing
// revision. A fixed mount topology cannot adopt a new declaration in place, so
// the participant says so before revocation and the authority can fence it
// without waiting the full repair budget. Ordinary Linux namespace phases never
// call this method: the admitted kernel profile expires dentries locklessly.
// Nonempty parentKernelInos are retained only to reject the retired development
// profile deterministically.
func (c *Client) ReportVisibilityBlocked(ctx context.Context, cursor *authoritypb.VisibilityCursor, parentKernelInos []uint64) error {
	if c.cfg.CoherenceProfile != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT || cursor == nil {
		return syscall.EINVAL
	}
	response, err := c.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_AckVisibility{
		AckVisibility: &authoritypb.AckVisibilityRequest{
			Cursor: cursor, Blocked: true, BlockedParentKernelInos: append([]uint64(nil), parentKernelInos...),
		},
	}})
	if err != nil {
		c.signalSessionEnd(ErrSessionEnded)
		return err
	}
	if response.GetErrno() != 0 {
		return c.endStrictMount(syscall.Errno(response.GetErrno()))
	}
	return nil
}

// VisibilityRepairBudget is the per-phase deadline this mount committed to at
// attach. A strict frontend must revoke its own kernel mount rather than
// acknowledge a phase later than this, because the authority may already have
// fenced its session and begun the separate grace before the volume moves on.
func (c *Client) VisibilityRepairBudget() time.Duration { return c.cfg.RepairBudget }

// DetachAfterUnmount leaves the barrier with the official supervisor's local
// observation that this mount is terminal. The request is authenticated as this
// exact session by Call; there is no session selector in DetachRequest. This
// client deliberately cannot synthesize an observation. A strict caller that
// cannot establish its platform's terminal conditions closes instead and lets
// its session die fenced.
func (c *Client) DetachAfterUnmount(ctx context.Context, proof *authoritypb.MountAbsenceProof) error {
	if !completeMountAbsenceProof(proof) {
		return syscall.EPERM
	}
	request := &authoritypb.DetachRequest{MountAbsence: proto.Clone(proof).(*authoritypb.MountAbsenceProof)}
	response, err := c.Call(ctx, &authoritypb.Request{Body: &authoritypb.Request_Detach{Detach: request}})
	if err != nil {
		return err
	}
	if response.GetErrno() != 0 {
		return syscall.Errno(response.GetErrno())
	}
	return nil
}

func completeMountAbsenceProof(proof *authoritypb.MountAbsenceProof) bool {
	return proof != nil && len(proof.GetObservation()) != 0 && proof.GetComponent() != "" && proof.GetObservedUnixNanos() > 0
}

// ReleaseBeforeMount cleanly gives back an ACTIVE session before this attempt
// installs its kernel mount. It is the ownership handoff companion to
// DialClient: callers must invoke it, rather than Close, on every failure after
// DialClient succeeds and before the kernel source becomes observable.
//
// For a strict session the configured observer supplies exact attempt-scoped
// absence evidence, and CONTROL carries the authenticated Detach. The method
// is idempotent: one caller owns the observation and wire transition; concurrent
// or later callers observe that same result. It never substitutes AbortAttach
// after ACTIVE and never manufactures evidence when observation fails.
func (c *Client) ReleaseBeforeMount(ctx context.Context) error {
	if ctx == nil {
		return syscall.EINVAL
	}
	c.preMountReleaseMu.Lock()
	if done := c.preMountReleaseDone; done != nil {
		c.preMountReleaseMu.Unlock()
		select {
		case <-done:
			c.preMountReleaseMu.Lock()
			err := c.preMountReleaseErr
			c.preMountReleaseMu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan struct{})
	c.preMountReleaseDone = done
	c.preMountReleaseMu.Unlock()

	var releaseErr error
	if c.closed.Load() {
		releaseErr = net.ErrClosed
	} else {
		proof, err := c.observePreKernelMountAbsence(ctx)
		if err != nil {
			releaseErr = fmt.Errorf("authorityrpc: observe pre-kernel mount absence: %w", err)
		} else if err := c.DetachAfterUnmount(ctx, proof); err != nil {
			releaseErr = fmt.Errorf("authorityrpc: detach ACTIVE session before kernel mount: %w", err)
		}
	}
	releaseErr = errors.Join(releaseErr, c.Close())
	c.preMountReleaseMu.Lock()
	c.preMountReleaseErr = releaseErr
	close(done)
	c.preMountReleaseMu.Unlock()
	return releaseErr
}

// SessionDone closes when this client can no longer safely continue the mount:
// an idle connection died without an in-flight call to drive same-epoch
// recovery, the authority epoch changed, an exact outcome became uncertain, or
// the client was closed. A terminal edge poisons new admission immediately,
// but its public signal waits for every already-parsed retained response to
// cross the frontend's physical publication boundary. SessionError returns the
// terminal cause as soon as it is known, including during that bounded drain.
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
	c.poisoned.Store(true)
	c.fatalMu.Lock()
	if c.fatalErr == nil {
		c.fatalErr = err
	}
	if c.fatalPublished {
		c.fatalMu.Unlock()
		return
	}
	c.fatalPending = true
	if len(c.responseConsumptions) == 0 {
		c.publishSessionEndLocked()
		c.fatalMu.Unlock()
		return
	}
	if c.fatalDrainTimer == nil {
		timeout := c.cfg.CancelDrainTimeout
		if timeout <= 0 {
			// DialClient requires a positive bound. Keep directly constructed test
			// clients fail-closed without an unbounded terminal drain.
			timeout = time.Second
		}
		c.fatalDrainTimer = time.AfterFunc(timeout, c.forceResponseConsumptionDrain)
	}
	c.fatalMu.Unlock()
}

func (c *Client) beginResponseConsumption(force func(error)) (*responseConsumption, error) {
	if force == nil {
		return nil, syscall.EINVAL
	}
	c.fatalMu.Lock()
	defer c.fatalMu.Unlock()
	if c.poisoned.Load() || c.fatalPending || c.fatalPublished || c.closed.Load() {
		if c.fatalErr != nil {
			return nil, c.fatalErr
		}
		if c.closed.Load() {
			return nil, net.ErrClosed
		}
		return nil, ErrSessionEnded
	}
	receipt := &responseConsumption{client: c, force: force}
	if c.responseConsumptions == nil {
		c.responseConsumptions = make(map[*responseConsumption]struct{})
	}
	c.responseConsumptions[receipt] = struct{}{}
	return receipt, nil
}

func (c *Client) finishResponseConsumption(receipt *responseConsumption) {
	c.fatalMu.Lock()
	delete(c.responseConsumptions, receipt)
	if c.fatalPending && !c.fatalPublished && len(c.responseConsumptions) == 0 {
		c.publishSessionEndLocked()
	}
	c.fatalMu.Unlock()
}

const terminalDeliveryTokenBytes = 16

func validTerminalDeliveryToken(token []byte) bool {
	if len(token) != terminalDeliveryTokenBytes {
		return false
	}
	var nonzero byte
	for _, value := range token {
		nonzero |= value
	}
	return nonzero != 0
}

func (c *Client) bindResponseConsumption(receipt *responseConsumption, response *authoritypb.Response) error {
	if receipt == nil || response == nil {
		return syscall.EINVAL
	}
	token := response.GetTerminalDeliveryToken()
	if len(token) == 0 {
		return nil
	}
	if !validTerminalDeliveryToken(token) {
		return errors.New("authorityrpc: terminal delivery response carried an invalid token")
	}
	receipt.terminalToken = append([]byte(nil), token...)
	return nil
}

// consumeResponse completes the client-to-authority half of terminal exact
// delivery. A token is present only when the authority fenced the volume while
// producing this response. The frontend calls Consume after its physical
// kernel boundary, so acknowledging any earlier would reintroduce the very
// cross-lane teardown race the token closes.
func (c *Client) consumeResponse(receipt *responseConsumption) {
	defer c.finishResponseConsumption(receipt)
	if len(receipt.terminalToken) == 0 {
		return
	}
	timeout := c.cfg.CancelDrainTimeout
	if timeout <= 0 {
		timeout = time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	response, err := c.dispatchTerminalDeliveryReceipt(ctx, receipt.terminalToken)
	if err == nil && !validTerminalDeliveryReceiptResponse(response) {
		err = errors.New("authorityrpc: authority returned a malformed terminal delivery receipt acknowledgment")
	}
	if err == nil {
		return
	}
	// Receipt failure cannot change the already-published local result. It does
	// mean the authority cannot prove delivery, so revoke the serving boundary
	// before allowing the terminal session edge to become observable.
	receipt.revoke(err)
	c.signalSessionEnd(err)
}

// dispatchTerminalDeliveryReceipt is the sole post-poison request path. It
// uses only the already-bound CONTROL generation and current session envelope:
// reconnecting after the authority declared a terminal drain could bind a
// different process edge and falsely acknowledge delivery to the wrong owner.
// Keeping this separate from Call also prevents terminal mode from becoming a
// general exception to new-operation admission.
func (c *Client) dispatchTerminalDeliveryReceipt(ctx context.Context, token []byte) (*authoritypb.Response, error) {
	if !validTerminalDeliveryToken(token) || !c.poisoned.Load() {
		return nil, syscall.EINVAL
	}
	select {
	case c.liveness.permits <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.liveness.permits }()
	request := &authoritypb.Request{Body: &authoritypb.Request_TerminalDeliveryReceipt{
		TerminalDeliveryReceipt: &authoritypb.TerminalDeliveryReceipt{Token: append([]byte(nil), token...)},
	}}
	return c.dispatchOwned(ctx, request)
}

func validTerminalDeliveryReceiptResponse(response *authoritypb.Response) bool {
	return response != nil && response.GetErrno() == 0 && !response.GetUncertain() &&
		response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED &&
		response.GetPostAttr() == nil && response.GetMutation() == nil && response.GetRoutesMismatch() == nil &&
		len(response.GetTerminalDeliveryToken()) == 0 && response.GetTerminalDeliveryReceipt() != nil
}

func (c *Client) publishSessionEndLocked() {
	if c.fatalPublished {
		return
	}
	c.fatalPublished = true
	if c.fatalDrainTimer != nil {
		c.fatalDrainTimer.Stop()
		c.fatalDrainTimer = nil
	}
	close(c.fatalDone)
}

// forceResponseConsumptionDrain is the bounded fail-closed escape for a
// frontend which received an exact authority response but never completed its
// local publication handshake. Every retained caller supplies a synchronous
// force callback. Run all callbacks before publishing SessionDone so the local
// FUSE serving boundary is already revoked when its ordinary session watcher
// begins teardown.
func (c *Client) forceResponseConsumptionDrain() {
	c.fatalMu.Lock()
	if !c.fatalPending || c.fatalPublished || len(c.responseConsumptions) == 0 {
		c.fatalDrainTimer = nil
		c.fatalMu.Unlock()
		return
	}
	cause := c.fatalErr
	receipts := make([]*responseConsumption, 0, len(c.responseConsumptions))
	for receipt := range c.responseConsumptions {
		receipts = append(receipts, receipt)
	}
	c.fatalMu.Unlock()

	for _, receipt := range receipts {
		receipt.revoke(cause)
	}

	c.fatalMu.Lock()
	if c.fatalPending && !c.fatalPublished {
		c.publishSessionEndLocked()
	}
	c.fatalMu.Unlock()
}

func (c *Client) laneFor(request *authoritypb.Request) *lane {
	if request.GetNextVisibility() != nil || request.GetAckVisibility() != nil {
		return &c.visibility
	}
	if request.GetReauthorize() != nil || request.GetKeepAlive() != nil || request.GetDetach() != nil ||
		request.GetTerminalDeliveryReceipt() != nil {
		return &c.liveness
	}
	if blockingWait(request) {
		return &c.blocking
	}
	return &c.ordinary
}

// Call submits one request under this client's admission bounds and takes
// ownership of it for the duration of the call: the physical envelope
// (request_id, epoch, session) is stamped in place, and stamped again if the
// same body is replayed after a same-epoch reconnect. The caller must not read
// or mutate request concurrently, and must not reuse the value afterwards
// except by handing it back to another call. Mutations must go through
// CallMutation, which owns the replay identity.
//
// Ownership is the contract on every path here because it is the one every
// caller already satisfies: each constructs a request for one synchronous call
// and drops it. Copying that request first isolated nothing and made a maximal
// write pay for a second megabyte.
func (c *Client) Call(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	admitted, err := c.admitCall(ctx, request)
	if err != nil {
		return nil, err
	}
	defer func() { <-admitted.permits }()
	return c.dispatchOwned(ctx, request)
}

// admitCall is the single shape and concurrency boundary for non-mutation
// requests. Keeping it ahead of dispatch means a canceled caller never stamps or
// serializes a request it did not submit. Mutation calls have their own
// replay-slot admission because the permit and slot lifetime are intentionally
// coupled.
func (c *Client) admitCall(ctx context.Context, request *authoritypb.Request) (*lane, error) {
	if request == nil || request.GetHello() != nil || request.GetAttach() != nil || request.GetResume() != nil ||
		request.GetActivate() != nil || request.GetAbortAttach() != nil || request.GetCancel() != nil {
		return nil, syscall.EINVAL
	}
	if _, err := roleForRequest(request); err != nil {
		return nil, syscall.EINVAL
	}
	admitted := c.laneFor(request)
	select {
	case admitted.permits <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return admitted, nil
}

// dispatchOwned performs one round trip, stamping and sending a request the
// client owns. Admission is the caller's responsibility so that a replay slot is
// never taken before the permit that bounds it. Mutation dispatch assigns its
// replay identity once and may need to resend those exact bytes after a
// same-epoch reconnect; copying for each attempt only duplicated large write
// payloads without adding isolation.
func (c *Client) dispatchOwned(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	role, err := roleForRequest(request)
	if err != nil {
		return nil, syscall.EINVAL
	}
	transport := c.transportForRole(role)
	// An idle DATA failure has no coherence meaning. Rebind it lazily before a
	// new filesystem request; this is a transport repair, not an application
	// replay, because no bytes for this request have been assigned or sent yet.
	if role == authoritypb.TransportRole_TRANSPORT_ROLE_DATA && !c.transportIsLive(transport) && !c.poisoned.Load() {
		if err := c.reconnectTransport(ctx, role); err != nil {
			return nil, err
		}
	}
	// Request IDs are physical-connection envelopes, not replay identities. A
	// same-session mutation retry keeps its Mutation slot/sequence and body but
	// must take a fresh ID on the replacement socket; another caller may already
	// have consumed the old numeric ID there.
	request.RequestId = transport.nextID.Add(1)
	request.Epoch, request.Session = c.sessionEnvelope()
	result := make(chan callResult, 1)
	transport.pendingMu.Lock()
	if c.closed.Load() {
		transport.pendingMu.Unlock()
		return nil, net.ErrClosed
	}
	if transport.conn == nil {
		terminal := c.poisoned.Load()
		transport.pendingMu.Unlock()
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
	transport.pending[request.RequestId] = result
	conn := transport.conn
	transport.pendingMu.Unlock()

	err = c.writeRequest(ctx, transport, conn, request)
	if err != nil {
		c.failConnection(transport, conn, ErrTransportUncertain)
	}
	select {
	case <-ctx.Done():
		c.sendCancel(transport, request.RequestId, conn)
		timer := time.NewTimer(c.cfg.CancelDrainTimeout)
		defer timer.Stop()
		select {
		case completed := <-result:
			return c.completeCall(request, completed)
		case <-timer.C:
			c.failConnection(transport, conn, ErrTransportUncertain)
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

func (c *Client) sendCancel(transport *clientTransport, target uint64, conn net.Conn) {
	epoch, proof := c.sessionEnvelope()
	request := &authoritypb.Request{
		RequestId: transport.nextID.Add(1), Epoch: epoch, Session: proof,
		Body: &authoritypb.Request_Cancel{Cancel: &authoritypb.CancelRequest{TargetRequestId: target}},
	}
	err := c.writeRequest(context.Background(), transport, conn, request)
	if err != nil {
		c.failConnection(transport, conn, ErrTransportUncertain)
	}
}

func (c *Client) writeRequest(ctx context.Context, transport *clientTransport, conn net.Conn, request *authoritypb.Request) error {
	transport.writeMu.Lock()
	defer transport.writeMu.Unlock()
	deadline := time.Now().Add(c.cfg.CancelDrainTimeout)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return writeFrame(conn, transport.frameMax.Load(), request)
}

// CallRead retries a side-effect-free operation once after reconnecting to the
// same epoch. A new epoch is always returned to the mount as a hard boundary.
func (c *Client) CallRead(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	return c.CallIdempotent(ctx, request)
}

// CallReadRetained is CallRead with a response-consumption receipt registered
// before dispatch. Strict FUSE callbacks use it because any already-admitted
// DATA response can become the final exact response of a fenced volume. The
// receipt therefore has to exist before a sibling CONTROL EOF can race that
// response's parsing.
func (c *Client) CallReadRetained(
	ctx context.Context,
	request *authoritypb.Request,
	force func(error),
) (*authoritypb.Response, ResponseConsumption, error) {
	return c.callRetained(force, func() (*authoritypb.Response, error) {
		return c.CallRead(ctx, request)
	})
}

// CallIdempotent retries one same-epoch operation whose protocol definition
// makes duplicate delivery harmless. In addition to reads, PortableFS write
// BEGIN, DATA, and ABORT use this path: they mutate only bounded session-owned
// staging and are idempotent by transaction identity. COMMIT must never use it;
// COMMIT is replay-retained through CallMutationWithIdentity.
func (c *Client) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if c.poisoned.Load() {
		return nil, ErrTransportUncertain
	}
	response, err := c.Call(ctx, request)
	if !errors.Is(err, ErrTransportUncertain) {
		return response, err
	}
	role, roleErr := roleForRequest(request)
	if roleErr != nil {
		return nil, syscall.EINVAL
	}
	if err := c.reconnectTransport(ctx, role); err != nil {
		if role == authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL {
			c.signalSessionEnd(err)
		}
		return nil, err
	}
	return c.Call(ctx, request)
}

// CallIdempotentRetained is the staged-write counterpart to
// CallReadRetained. BEGIN/DATA/ABORT are transport-idempotent but their kernel
// callback still owns any terminal response until its physical reply write.
// A parsed response remains retained until the frontend physically exposes the
// corresponding ordinary reply (or revokes that serving boundary). COMMIT
// still uses the replay-slot mutation API.
func (c *Client) CallIdempotentRetained(
	ctx context.Context,
	request *authoritypb.Request,
	force func(error),
) (*authoritypb.Response, ResponseConsumption, error) {
	return c.callRetained(force, func() (*authoritypb.Response, error) {
		return c.CallIdempotent(ctx, request)
	})
}

func (c *Client) callRetained(
	force func(error),
	call func() (*authoritypb.Response, error),
) (*authoritypb.Response, ResponseConsumption, error) {
	consumption, err := c.beginResponseConsumption(force)
	if err != nil {
		return nil, nil, err
	}
	parsed := false
	defer func() {
		if !parsed {
			consumption.Consume()
		}
	}()
	response, err := call()
	if err != nil || response == nil {
		return response, nil, err
	}
	parsed = true
	if bindErr := c.bindResponseConsumption(consumption, response); bindErr != nil {
		consumption.revoke(bindErr)
		c.signalSessionEnd(bindErr)
		return response, consumption, bindErr
	}
	return response, consumption, nil
}

// CallMutation takes ownership of request for the duration of the call, assigns
// one replay slot/sequence from its admission lane, reconnects and replays only
// against the same live authority epoch, and then synchronizes the slot to the
// state the authority reports it recorded. Callers must not mutate request
// concurrently. Every production caller constructs one request for one
// synchronous call, so copying a large write here provided no isolation and
// made write throughput a memory-copy benchmark.
//
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
	response, consumption, err := c.CallMutationWithIdentityRetained(ctx, request, assigned, func(error) {})
	if consumption != nil {
		consumption.Consume()
	}
	return response, err
}

// CallMutationWithIdentityRetained returns a one-shot response-consumption
// receipt for a frontend whose local publication boundary occurs after this Go
// call returns. force is called synchronously if a terminal authority edge has
// waited the configured drain bound without receipt consumption; it must revoke
// the frontend's serving boundary before returning. Requests which never yield
// a parsed response consume their internal receipt before this method returns.
func (c *Client) CallMutationWithIdentityRetained(
	ctx context.Context,
	request *authoritypb.Request,
	assigned MutationAssigned,
	force func(error),
) (*authoritypb.Response, ResponseConsumption, error) {
	if c.poisoned.Load() {
		return nil, nil, ErrTransportUncertain
	}
	role, err := roleForRequest(request)
	if err != nil || role != authoritypb.TransportRole_TRANSPORT_ROLE_DATA {
		return nil, nil, syscall.EINVAL
	}
	admitted := c.laneFor(request)
	select {
	case admitted.permits <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
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

	sequence := slot.sequence + 1
	request.Mutation = &authoritypb.Mutation{Slot: index, Sequence: sequence}
	consumption, err := c.beginResponseConsumption(force)
	if err != nil {
		return nil, nil, err
	}
	parsed := false
	defer func() {
		if !parsed {
			consumption.Consume()
		}
	}()
	if assigned != nil {
		if err := assigned(MutationIdentity{Slot: index, Sequence: sequence}); err != nil {
			return nil, nil, err
		}
	}
	response, err := c.dispatchOwned(ctx, request)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		c.signalSessionEnd(ErrTransportUncertain)
		return nil, nil, ErrTransportUncertain
	}
	if errors.Is(err, ErrTransportUncertain) {
		if reconnectErr := c.reconnectTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_DATA); reconnectErr != nil {
			c.signalSessionEnd(reconnectErr)
			return nil, nil, reconnectErr
		}
		response, err = c.dispatchOwned(ctx, request)
	}
	if err != nil {
		return nil, nil, err
	}
	parsed = true
	if bindErr := c.bindResponseConsumption(consumption, response); bindErr != nil {
		consumption.revoke(bindErr)
		c.signalSessionEnd(bindErr)
		return response, consumption, bindErr
	}
	if c.testAfterResponseParsed != nil {
		c.testAfterResponseParsed()
	}
	if err := synchronizeSlot(slot, index, sequence, response.GetMutation()); err != nil {
		c.signalSessionEnd(err)
		return response, consumption, err
	}
	if response.GetUncertain() {
		c.signalSessionEnd(ErrTransportUncertain)
	}
	return response, consumption, nil
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

func (c *Client) readLoop(transport *clientTransport, conn net.Conn) {
	for {
		var response authoritypb.Response
		if err := readFrame(conn, transport.frameMax.Load(), nil, 0, &response); err != nil {
			c.failConnection(transport, conn, ErrTransportUncertain)
			return
		}
		// A dead generation can finish a buffered read after its replacement is
		// published. Pending maps and request IDs are connection-scoped, so that
		// response must not be interpreted—or delivered—against the new map.
		transport.pendingMu.Lock()
		if transport.conn != conn {
			transport.pendingMu.Unlock()
			return
		}
		if !equalBytes(response.GetEpoch(), c.sessionEpoch()) {
			c.signalSessionEnd(ErrAuthorityChanged)
			transport.pendingMu.Unlock()
			c.failConnection(transport, conn, ErrAuthorityChanged)
			return
		}
		if response.GetUncertain() {
			c.signalSessionEnd(ErrTransportUncertain)
		}
		if token := response.GetTerminalDeliveryToken(); len(token) != 0 {
			if validTerminalDeliveryToken(token) {
				c.signalSessionEnd(ErrSessionEnded)
			} else {
				c.signalSessionEnd(errors.New("authorityrpc: authority response carried a malformed terminal delivery token"))
			}
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
		waiter := transport.pending[response.GetRequestId()]
		delete(transport.pending, response.GetRequestId())
		transport.pendingMu.Unlock()
		if waiter != nil {
			waiter <- callResult{response: &response}
		}
	}
}

func (c *Client) failConnection(transport *clientTransport, conn net.Conn, err error) {
	transport.pendingMu.Lock()
	if transport.conn != conn {
		transport.pendingMu.Unlock()
		return
	}
	transport.conn = nil
	pending := transport.pending
	transport.pending = make(map[uint64]chan callResult)
	idle := len(pending) == 0 && !c.closed.Load()
	// Losing an idle DATA socket is only a transport event: the next safe read
	// or exact mutation replay lazily resumes that one role. CONTROL owns the
	// visibility/liveness contract, so an idle loss still ends the mount under
	// the existing fail-closed safety rule.
	if idle && transport.role == authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL {
		c.signalSessionEnd(err)
	}
	transport.pendingMu.Unlock()
	_ = conn.Close()
	for _, waiter := range pending {
		waiter <- callResult{err: err}
	}
}

func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := c.closeTransports()
	c.signalSessionEnd(net.ErrClosed)
	return err
}

func (c *Client) closeTransports() error {
	var first error
	for _, transport := range []*clientTransport{c.data, c.control} {
		if transport == nil {
			continue
		}
		transport.pendingMu.Lock()
		conn := transport.conn
		transport.conn = nil
		pending := transport.pending
		transport.pending = make(map[uint64]chan callResult)
		transport.pendingMu.Unlock()
		for _, waiter := range pending {
			waiter <- callResult{err: net.ErrClosed}
		}
		if conn != nil {
			if err := conn.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
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
