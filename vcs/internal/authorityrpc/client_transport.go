package authorityrpc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// clientTransport is one physical protocol-5 lane. Everything whose identity
// is scoped to a TCP/TLS connection lives here: publication, serialization,
// request IDs, waiters, reconnect exclusion, and negotiated frame accounting.
// Session identity is deliberately not duplicated here; both transports prove
// the one session owned by Client.
type clientTransport struct {
	role authoritypb.TransportRole

	lifecycle   sync.Mutex
	writeMu     sync.Mutex
	pendingMu   sync.Mutex
	conn        net.Conn
	pending     map[uint64]chan callResult
	nextID      atomic.Uint64
	frameMax    atomic.Uint32
	maxInFlight atomic.Uint32
	binding     atomic.Uint64
}

type transportNegotiation struct {
	conn                net.Conn
	epoch               []byte
	features            []string
	maxFrame            uint32
	maxRead             uint32
	maxWrite            uint32
	maxWriteTransaction uint64
	maxInFlight         uint32
	role                authoritypb.TransportRole
	// Set only by proof-bearing Resume during pre-publication activation
	// recovery. Hello itself never conveys a binding generation.
	resumedBindingGeneration uint64
}

func (c *Client) resumeRawForActivation(ctx context.Context, role authoritypb.TransportRole) (*transportNegotiation, error) {
	var last error
	for {
		if err := ctx.Err(); err != nil {
			if last != nil {
				return nil, fmt.Errorf("%v: %w", last, err)
			}
			return nil, err
		}
		opened, err := c.openTransport(ctx, role)
		if err == nil {
			if err = c.validateReconnectNegotiation(opened); err == nil {
				epoch, proof := c.sessionEnvelope()
				request := &authoritypb.Request{RequestId: 2, Epoch: epoch, Session: proof, Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}}
				var response *authoritypb.Response
				response, err = rawRoundTrip(opened.conn, opened.maxFrame, request)
				if err == nil && !equalBytes(response.GetEpoch(), epoch) {
					err = ErrAuthorityChanged
				}
				if err == nil {
					resume := response.GetResume()
					if response.GetErrno() != 0 || resume == nil || resume.GetRole() != role ||
						resume.GetBindingGeneration() == 0 ||
						(resume.GetState() != authoritypb.SessionState_SESSION_STATE_PROVISIONAL &&
							resume.GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE) {
						err = fmt.Errorf("authorityrpc: provisional %s resume refused with errno %d", role, response.GetErrno())
					} else {
						opened.resumedBindingGeneration = resume.GetBindingGeneration()
						return opened, nil
					}
				}
			}
			closeNegotiations(opened)
			if errors.Is(err, ErrAuthorityChanged) {
				return nil, err
			}
		}
		last = err
		if err := waitTransportRetry(ctx); err != nil {
			return nil, fmt.Errorf("%v: %w", last, err)
		}
	}
}

func waitTransportRetry(ctx context.Context) error {
	timer := time.NewTimer(5 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) resumeRawPairForActivation(ctx context.Context) (*transportNegotiation, *transportNegotiation, error) {
	for {
		data, err := c.resumeRawForActivation(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
		if err != nil {
			return nil, nil, err
		}
		control, err := c.resumeRawForActivation(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
		if err == nil {
			return data, control, nil
		}
		closeNegotiations(data)
		if waitErr := waitTransportRetry(ctx); waitErr != nil {
			return nil, nil, fmt.Errorf("%v: %w", err, waitErr)
		}
	}
}

func newClientTransport(role authoritypb.TransportRole) *clientTransport {
	return &clientTransport{role: role, pending: make(map[uint64]chan callResult)}
}

func randomProtocolIdentity() ([32]byte, error) {
	var id [32]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, err
	}
	if id == ([32]byte{}) {
		return id, errors.New("authorityrpc: random protocol identity was zero")
	}
	return id, nil
}

func (c *Client) tlsConfig() *tls.Config {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return c.cfg.TLS.Clone()
}

func (c *Client) dialTLS(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: c.cfg.DialTimeout, KeepAlive: 15 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", c.cfg.Address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, c.tlsConfig())
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

// openTransport performs the mandatory bare Hello and leaves the connection
// private to its caller. Publication happens only after Attach + Activate has
// made the session ACTIVE, or after a proof-bearing Resume has promoted this
// exact binding.
func (c *Client) openTransport(ctx context.Context, role authoritypb.TransportRole) (*transportNegotiation, error) {
	if !validTransportRole(role) {
		return nil, ErrTransportBinding
	}
	conn, err := c.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*transportNegotiation, error) {
		_ = conn.Close()
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.cfg.DialTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fail(err)
	}
	request := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{
		ProtocolMajor:   ProtocolMajor,
		Features:        append([]string(nil), requiredHelloFeatures...),
		Role:            role,
		ConnectionSetId: append([]byte(nil), c.connectionSetID[:]...),
	}}}
	if err := writeFrame(conn, c.cfg.MaxFrame, request); err != nil {
		return fail(err)
	}
	var response authoritypb.Response
	if err := readFrame(conn, c.cfg.MaxFrame, nil, 0, &response); err != nil {
		return fail(err)
	}
	hello := response.GetHello()
	if response.GetRequestId() != request.GetRequestId() || response.GetErrno() != 0 || hello == nil ||
		hello.GetProtocolMajor() != ProtocolMajor {
		return fail(fmt.Errorf("authorityrpc: %s protocol handshake refused with errno %d", role, response.GetErrno()))
	}
	if hello.GetRole() != role || !equalBytes(hello.GetConnectionSetId(), c.connectionSetID[:]) {
		return fail(fmt.Errorf("authorityrpc: %s Hello did not echo its exact transport binding", role))
	}
	if !hasFeatures(hello.GetFeatures(), requiredHelloFeatures) {
		return fail(errors.New("authorityrpc: authority omitted required current-state features"))
	}
	if c.cfg.RequireMountEnrollmentReauthorization && !hasFeatures(
		hello.GetFeatures(), []string{mountEnrollmentReauthorizationFeature},
	) {
		return fail(errors.New("authorityrpc: authority does not support Manager-enrolled mount reauthorization"))
	}
	if len(response.GetEpoch()) != len(volumeserver.Epoch{}) {
		return fail(errors.New("authorityrpc: protocol handshake omitted a valid authority epoch"))
	}
	if hello.GetMaxFrameBytes() == 0 || hello.GetMaxReadBytes() == 0 || hello.GetMaxWriteBytes() == 0 || hello.GetMaxInFlight() == 0 {
		return fail(errors.New("authorityrpc: authority omitted allocation bounds"))
	}
	if got := hello.GetMaxWriteTransactionBytes(); got != RequiredWriteTransactionBytes {
		return fail(fmt.Errorf(
			"authorityrpc: authority write-transaction bound is %d, require exactly %d",
			got, RequiredWriteTransactionBytes,
		))
	}
	if uint64(c.cfg.MaxInFlight) > uint64(hello.GetMaxInFlight()) {
		return fail(errors.New("authorityrpc: client max-in-flight exceeds the authority connection bound"))
	}
	negotiatedFrame := hello.GetMaxFrameBytes()
	if negotiatedFrame > c.cfg.MaxFrame {
		negotiatedFrame = c.cfg.MaxFrame
	}
	if uint64(hello.GetMaxReadBytes())+uint64(FramePayloadReserve) > uint64(negotiatedFrame) ||
		uint64(hello.GetMaxWriteBytes())+uint64(FramePayloadReserve) > uint64(negotiatedFrame) {
		return fail(errors.New("authorityrpc: I/O payload bounds exceed the negotiated frame"))
	}
	// The two bounds are configured independently on the authority but they are
	// not independent at the mount: a Linux mount sizes max_write from the write
	// bound and the kernel derives max_read from max_write, so the kernel issues
	// reads the read bound cannot answer in one request. A smaller read bound
	// therefore does not make reads smaller, it multiplies the round trips every
	// read costs, and it does so silently. Refuse it here rather than normalize:
	// the deployment that wrote the two numbers is the only place the intended
	// one is known.
	if hello.GetMaxReadBytes() < hello.GetMaxWriteBytes() {
		return fail(fmt.Errorf(
			"authorityrpc: authority read bound %d is below its write bound %d; the kernel sizes reads from the write bound, so every read would be split across round trips",
			hello.GetMaxReadBytes(), hello.GetMaxWriteBytes(),
		))
	}
	return &transportNegotiation{
		conn: conn, epoch: append([]byte(nil), response.GetEpoch()...),
		features: append([]string(nil), hello.GetFeatures()...), maxFrame: negotiatedFrame,
		maxRead: hello.GetMaxReadBytes(), maxWrite: hello.GetMaxWriteBytes(), maxWriteTransaction: hello.GetMaxWriteTransactionBytes(),
		maxInFlight: hello.GetMaxInFlight(), role: role,
	}, nil
}

func validateNegotiationPair(data, control *transportNegotiation) error {
	if data == nil || control == nil || data.role != authoritypb.TransportRole_TRANSPORT_ROLE_DATA ||
		control.role != authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL {
		return errors.New("authorityrpc: incomplete transport pair")
	}
	if !equalBytes(data.epoch, control.epoch) || !slices.Equal(data.features, control.features) ||
		data.maxFrame != control.maxFrame || data.maxRead != control.maxRead ||
		data.maxWrite != control.maxWrite || data.maxWriteTransaction != control.maxWriteTransaction || data.maxInFlight != control.maxInFlight {
		return errors.New("authorityrpc: DATA and CONTROL negotiated different authority state")
	}
	return nil
}

func (c *Client) openInitialPair(ctx context.Context) (*transportNegotiation, *transportNegotiation, error) {
	data, err := c.openTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	if err != nil {
		return nil, nil, err
	}
	control, err := c.openTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	if err != nil {
		closeNegotiations(data)
		return nil, nil, err
	}
	if err := validateNegotiationPair(data, control); err != nil {
		closeNegotiations(data, control)
		return nil, nil, err
	}
	return data, control, nil
}

// reopenInitialPair retries one exact unactivated connection set. It is used
// only after an Attach response was lost: no proof exists locally yet, so DATA
// must replay the exact attempt to promote both newly authenticated bindings.
func (c *Client) reopenInitialPair(ctx context.Context) (*transportNegotiation, *transportNegotiation, error) {
	var last error
	for {
		if err := ctx.Err(); err != nil {
			if last != nil {
				return nil, nil, fmt.Errorf("%v: %w", last, err)
			}
			return nil, nil, err
		}
		data, control, err := c.openInitialPair(ctx)
		if err == nil {
			if err = c.validateReconnectNegotiation(data); err == nil {
				if err = c.validateReconnectNegotiation(control); err == nil {
					return data, control, nil
				}
			}
			closeNegotiations(data, control)
			if errors.Is(err, ErrAuthorityChanged) {
				return nil, nil, err
			}
		}
		last = err
		if err := waitTransportRetry(ctx); err != nil {
			return nil, nil, fmt.Errorf("%v: %w", last, err)
		}
	}
}

func (c *Client) validateReconnectNegotiation(opened *transportNegotiation) error {
	if opened == nil || !equalBytes(opened.epoch, c.sessionEpoch()) {
		return ErrAuthorityChanged
	}
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if !slices.Equal(opened.features, c.helloFeatures) || opened.maxFrame != c.negotiatedFrame ||
		opened.maxRead != c.maxRead || opened.maxWrite != c.maxWrite || opened.maxWriteTransaction != c.maxWriteTransaction || opened.maxInFlight != c.negotiatedInFlight {
		return errors.New("authorityrpc: resumed transport negotiated different authority state")
	}
	return nil
}

func (c *Client) sessionEnvelope() ([]byte, *authoritypb.SessionProof) {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return append([]byte(nil), c.epoch...), cloneProof(c.proof)
}

func (c *Client) sessionEpoch() []byte {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	return append([]byte(nil), c.epoch...)
}

func rawRoundTrip(conn net.Conn, frameMax uint32, request *authoritypb.Request) (*authoritypb.Response, error) {
	if err := writeFrame(conn, frameMax, request); err != nil {
		return nil, err
	}
	response := new(authoritypb.Response)
	if err := readFrame(conn, frameMax, nil, 0, response); err != nil {
		return nil, err
	}
	if response.GetRequestId() != request.GetRequestId() {
		return nil, errors.New("authorityrpc: handshake response carried a foreign request ID")
	}
	return response, nil
}

func closeNegotiations(opened ...*transportNegotiation) {
	for _, transport := range opened {
		if transport != nil && transport.conn != nil {
			_ = transport.conn.Close()
		}
	}
}

func (c *Client) transportForRole(role authoritypb.TransportRole) *clientTransport {
	switch role {
	case authoritypb.TransportRole_TRANSPORT_ROLE_DATA:
		return c.data
	case authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL:
		return c.control
	default:
		return nil
	}
}

func roleForRequest(request *authoritypb.Request) (authoritypb.TransportRole, error) {
	class, err := classifyTransportRequest(request)
	if err != nil {
		return authoritypb.TransportRole_TRANSPORT_ROLE_UNSPECIFIED, err
	}
	switch class {
	case transportRequestData:
		return authoritypb.TransportRole_TRANSPORT_ROLE_DATA, nil
	case transportRequestControl:
		return authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, nil
	default:
		return authoritypb.TransportRole_TRANSPORT_ROLE_UNSPECIFIED, ErrTransportBinding
	}
}

func (c *Client) publishTransport(transport *clientTransport, opened *transportNegotiation, generation uint64, nextID uint64) error {
	if transport == nil || opened == nil || opened.conn == nil || transport.role != opened.role || generation == 0 {
		return ErrTransportBinding
	}
	if err := opened.conn.SetDeadline(time.Time{}); err != nil {
		_ = opened.conn.Close()
		return err
	}
	transport.pendingMu.Lock()
	if c.closed.Load() || transport.conn != nil {
		transport.pendingMu.Unlock()
		_ = opened.conn.Close()
		if c.closed.Load() {
			return net.ErrClosed
		}
		return errors.New("authorityrpc: attempted to replace a live transport")
	}
	transport.frameMax.Store(opened.maxFrame)
	transport.maxInFlight.Store(opened.maxInFlight)
	transport.binding.Store(generation)
	transport.nextID.Store(nextID)
	transport.conn = opened.conn
	transport.pendingMu.Unlock()
	go c.readLoop(transport, opened.conn)
	return nil
}

func (c *Client) publishInitialPair(data, control *transportNegotiation, dataGeneration, controlGeneration uint64) error {
	if data == nil || control == nil || data.conn == nil || control.conn == nil ||
		data.role != authoritypb.TransportRole_TRANSPORT_ROLE_DATA ||
		control.role != authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL ||
		dataGeneration == 0 || controlGeneration == 0 {
		return ErrTransportBinding
	}
	if err := data.conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if err := control.conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	c.data.pendingMu.Lock()
	c.control.pendingMu.Lock()
	if c.closed.Load() || c.data.conn != nil || c.control.conn != nil {
		c.control.pendingMu.Unlock()
		c.data.pendingMu.Unlock()
		if c.closed.Load() {
			return net.ErrClosed
		}
		return errors.New("authorityrpc: attempted to replace a live transport pair")
	}
	c.data.frameMax.Store(data.maxFrame)
	c.data.maxInFlight.Store(data.maxInFlight)
	c.data.binding.Store(dataGeneration)
	c.data.nextID.Store(2)
	c.data.conn = data.conn
	c.control.frameMax.Store(control.maxFrame)
	c.control.maxInFlight.Store(control.maxInFlight)
	c.control.binding.Store(controlGeneration)
	c.control.nextID.Store(2)
	c.control.conn = control.conn
	c.control.pendingMu.Unlock()
	c.data.pendingMu.Unlock()
	go c.readLoop(c.data, data.conn)
	go c.readLoop(c.control, control.conn)
	return nil
}

func (c *Client) reconnectTransport(ctx context.Context, role authoritypb.TransportRole) error {
	transport := c.transportForRole(role)
	if transport == nil {
		return ErrTransportBinding
	}
	if c.poisoned.Load() {
		if err := c.SessionError(); err != nil {
			return err
		}
		return ErrSessionEnded
	}
	transport.lifecycle.Lock()
	defer transport.lifecycle.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	transport.pendingMu.Lock()
	live := transport.conn != nil
	transport.pendingMu.Unlock()
	if live {
		return nil
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
	defer cancel()
	opened, err := c.openTransport(handshakeCtx, role)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		closeNegotiations(opened)
		switch {
		case errors.Is(err, ErrAuthorityChanged):
			c.signalSessionEnd(ErrAuthorityChanged)
		case errors.Is(err, ErrSessionEnded):
			c.signalSessionEnd(ErrSessionEnded)
		}
		return err
	}
	if err := c.validateReconnectNegotiation(opened); err != nil {
		return fail(err)
	}
	epoch, proof := c.sessionEnvelope()
	request := &authoritypb.Request{RequestId: 2, Epoch: epoch, Session: proof, Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}}
	response, err := rawRoundTrip(opened.conn, opened.maxFrame, request)
	if err != nil {
		return fail(err)
	}
	if !equalBytes(response.GetEpoch(), epoch) {
		return fail(ErrAuthorityChanged)
	}
	resume := response.GetResume()
	if response.GetErrno() != 0 || resume == nil || resume.GetRole() != role ||
		resume.GetBindingGeneration() == 0 || resume.GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		return fail(fmt.Errorf("%w: %s resume refused with errno %d", ErrSessionEnded, role, response.GetErrno()))
	}
	return c.publishTransport(transport, opened, resume.GetBindingGeneration(), 2)
}

func (c *Client) transportIsLive(transport *clientTransport) bool {
	transport.pendingMu.Lock()
	defer transport.pendingMu.Unlock()
	return transport.conn != nil
}
