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

	lifecycle sync.Mutex
	conn      net.Conn
	writeMu   sync.Mutex
	pendingMu sync.Mutex
	pending   map[uint64]chan callResult
	nextID    atomic.Uint64
	ordinary  lane
	blocking  lane
	epoch     []byte
	proof     *authoritypb.SessionProof
	root      *authoritypb.Item
	maxRead   uint32
	maxWrite  uint32
	lease     time.Duration
	frameMax  atomic.Uint32
	poisoned  atomic.Bool
	closed    bool
	fatalOnce sync.Once
	fatalMu   sync.Mutex
	fatalErr  error
	fatalDone chan struct{}
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
	cfg.TLS = cfg.TLS.Clone()
	cfg.TLS.MinVersion = tls.VersionTLS13
	cfg.TLS.NextProtos = []string{protocolALPN}
	ordinaryLimit, blockingLimit := blockingWaitLane(cfg.MaxInFlight)
	slots := make([]clientSlot, cfg.ReplaySlots)
	split := cfg.ReplaySlots - uint32(blockingLimit)
	c := &Client{
		cfg: cfg, pending: make(map[uint64]chan callResult), fatalDone: make(chan struct{}),
		ordinary: lane{permits: make(chan struct{}, ordinaryLimit), slots: slots[:split], base: 0},
		blocking: lane{permits: make(chan struct{}, blockingLimit), slots: slots[split:], base: split},
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
		request := &authoritypb.Request{RequestId: 2, Body: &authoritypb.Request_Attach{Attach: &authoritypb.AttachRequest{VolumeId: c.cfg.VolumeID, AccessToken: append([]byte(nil), c.cfg.AccessToken...), ReplaySlots: c.cfg.ReplaySlots}}}
		if err := writeFrame(conn, c.frameMax.Load(), request); err != nil {
			return fail(err)
		}
		var response authoritypb.Response
		if err := readFrame(conn, c.frameMax.Load(), nil, 0, &response); err != nil {
			return fail(err)
		}
		if response.GetRequestId() != request.GetRequestId() || response.GetErrno() != 0 || response.GetAttach() == nil {
			return fail(fmt.Errorf("authorityrpc: attach refused with errno %d", response.GetErrno()))
		}
		if !hasFeatures(response.GetAttach().GetFeatures(), requiredAttachFeatures) {
			return fail(errors.New("authorityrpc: authority omitted required ordinary-filesystem features"))
		}
		if !equalBytes(response.GetEpoch(), hello.GetEpoch()) ||
			len(response.GetAttach().GetSessionId()) != len(volumeserver.SessionID{}) ||
			len(response.GetAttach().GetResumeSecret()) != len(volumeserver.ResumeSecret{}) ||
			response.GetAttach().GetSessionGeneration() == 0 ||
			response.GetAttach().GetRoot() == nil || len(response.GetAttach().GetRoot().GetToken()) != len(xfsstore.Capability{}) {
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

// IOLimits returns the authority-negotiated maximum payload sizes. Mount
// frontends must split larger kernel requests instead of relying on a shared
// compile-time constant.
func (c *Client) IOLimits() (maxRead, maxWrite uint32) {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return c.maxRead, c.maxWrite
}

func (c *Client) SessionLease() time.Duration {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return c.lease
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
