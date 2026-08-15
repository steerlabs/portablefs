package authorityrpc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type peerIdentityKey struct{}

// PeerIdentity returns SHA-256(SPKI) for the mutually authenticated peer.
func PeerIdentity(ctx context.Context) ([32]byte, bool) {
	identity, ok := ctx.Value(peerIdentityKey{}).([32]byte)
	return identity, ok
}

// TransportBounds are the limits a handler advertises to its clients. The
// server refuses to run unless it enforces exactly these, so a client can
// never be sized to a bound the server kills it for exceeding, and the server
// can never retain a reply the transport is unable to write.
type TransportBounds struct {
	// MaxFrame is the largest frame either direction may carry.
	MaxFrame uint32
	// MaxRequestFrame is the largest frame a well-formed request can occupy.
	// It is smaller than MaxFrame because only replies carry bulk read and
	// directory data, and it is what bounds inbound allocation.
	MaxRequestFrame uint32
	// MaxInFlight is the per-connection concurrent execution bound.
	MaxInFlight int
}

type Handler interface {
	// Epoch is the current authority epoch. The server stamps it on every
	// response it has to generate itself, so a transport-level substitution is
	// never read by a client as an authority failover.
	Epoch() []byte
	// Bounds are the limits this handler advertises during Hello.
	Bounds() TransportBounds
	// SessionStateForTransport closes the terminal-before-bind race. After a
	// provisional result is bound into the registry, the server rechecks the
	// runtime before exposing either lane; a terminal transition is therefore
	// observed either by this query or by the runtime-owned terminal edge.
	SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool)
	// SessionTerminalForTransport exposes the runtime-owned terminal edge. It
	// closes at fencing, before admitted filesystem work drains and before
	// descriptor cleanup, so physical generations are revoked immediately.
	SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool)
	Handle(context.Context, *authoritypb.Request) *authoritypb.Response
}

// responseWriteObserver is an optional handler extension for terminal failures
// whose response carries the only exact post-apply filesystem state. The
// authoritative store is fenced before Handle returns, so no later operation
// can enter XFS; process-wide teardown is deferred until the transport has made
// exactly one physical attempt to deliver that retained response. This keeps a
// security- or storage-fatal post-apply result from racing its own socket close.
type responseWriteObserver interface {
	PrepareResponseWrite(*authoritypb.Request, *authoritypb.Response)
	ResponseWritten(*authoritypb.Response, error)
}

type terminalQuiescer interface {
	TerminalQuiescing() <-chan struct{}
}

type handlerResponseFinisher interface {
	FinishHandlerResponse(*authoritypb.Request, *authoritypb.Response)
}

type transportResponseHandler interface {
	HandleForTransport(context.Context, *authoritypb.Request) *authoritypb.Response
}

func handleTransportRequest(handler Handler, ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	if retained, ok := handler.(transportResponseHandler); ok {
		return retained.HandleForTransport(ctx, request)
	}
	return handler.Handle(ctx, request)
}

func finishHandlerResponse(handler Handler, request *authoritypb.Request, response *authoritypb.Response) func() {
	if finisher, ok := handler.(handlerResponseFinisher); ok {
		finisher.FinishHandlerResponse(request, response)
	}
	// Lifecycle validation can abandon a response after Handle transferred it
	// into terminal frame ownership but before writeResponse is called. Invoke
	// this cleanup on every enclosing-path exit. After an observed write it is
	// an idempotent no-op; on abandonment it retires the unreachable frame and
	// any delivery token associated with that failed physical attempt.
	return func() {
		if observer, ok := handler.(responseWriteObserver); ok {
			observer.ResponseWritten(response, ErrTransportBinding)
		}
	}
}

func writeObservedResponse(conn net.Conn, maxFrame uint32, timeout time.Duration, handler Handler, request *authoritypb.Request, response *authoritypb.Response) (err error) {
	requestID := uint64(0)
	if request != nil {
		requestID = request.GetRequestId()
	}
	if response == nil {
		// A handler that produced nothing is an internal defect, never an epoch
		// change: stamp the live epoch so the client is not told to remount after
		// a failover that did not happen.
		response = &authoritypb.Response{
			RequestId: requestID, Epoch: handler.Epoch(),
			Errno: int32(syscall.EIO), Uncertain: true, Failure: authoritypb.FailureClass_FAILURE_CLASS_INTERNAL,
		}
	}
	writtenResponse := response
	var observedErr error
	if observer, ok := handler.(responseWriteObserver); ok {
		observer.PrepareResponseWrite(request, writtenResponse)
		defer func() { observer.ResponseWritten(writtenResponse, observedErr) }()
	}
	if err = conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		observedErr = err
		return err
	}
	err = writeFrame(conn, maxFrame, response)
	observedErr = err
	if errors.Is(err, ErrFrameBounds) {
		// The replacement must carry the same epoch and the same recorded
		// replay-slot state as the reply it stands in for. Dropping either would
		// report a failover or desynchronize the client's slot.
		response = &authoritypb.Response{
			RequestId: response.GetRequestId(), Epoch: handler.Epoch(),
			Mutation: response.GetMutation(), Errno: int32(syscall.EOVERFLOW), Uncertain: true,
		}
		err = writeFrame(conn, maxFrame, response)
	}
	return err
}

type Server struct {
	Handler        Handler
	MaxFrame       uint32
	MaxInFlight    int
	MaxConnections int
	// MaxFrameBytesInFlight bounds the bytes this worker will have allocated
	// for inbound frame payloads at any instant, across all connections.
	MaxFrameBytesInFlight uint64
	HandshakeTimeout      time.Duration
	IdleTimeout           time.Duration
	WriteTimeout          time.Duration

	budget *frameBudget

	registryMu sync.Mutex
	registry   *transportRegistry
}

func (s *Server) validate() (TransportBounds, error) {
	if s.Handler == nil || s.MaxFrame == 0 || s.MaxInFlight <= 0 || s.MaxConnections <= 0 ||
		s.MaxFrameBytesInFlight == 0 || s.HandshakeTimeout <= 0 || s.IdleTimeout <= 0 || s.WriteTimeout <= 0 {
		return TransportBounds{}, errors.New("authorityrpc: handler, admission bounds, allocation budget, and connection timeouts are required")
	}
	if s.MaxInFlight < 2 {
		return TransportBounds{}, errors.New("authorityrpc: max-in-flight must admit an ordinary request and a blocking lock wait independently")
	}
	if s.MaxConnections < 2 {
		return TransportBounds{}, errors.New("authorityrpc: protocol 5 requires capacity for one DATA/CONTROL connection pair")
	}
	bounds := s.Handler.Bounds()
	if bounds.MaxFrame != s.MaxFrame || bounds.MaxInFlight != s.MaxInFlight {
		return TransportBounds{}, fmt.Errorf("authorityrpc: handler advertises frame %d/in-flight %d but the transport enforces %d/%d",
			bounds.MaxFrame, bounds.MaxInFlight, s.MaxFrame, s.MaxInFlight)
	}
	if bounds.MaxRequestFrame == 0 || bounds.MaxRequestFrame > s.MaxFrame {
		return TransportBounds{}, errors.New("authorityrpc: advertised request-frame bound must be positive and within the transport frame")
	}
	if s.MaxFrameBytesInFlight < uint64(bounds.MaxRequestFrame) {
		return TransportBounds{}, errors.New("authorityrpc: frame allocation budget cannot admit one maximal request")
	}
	return bounds, nil
}

func (s *Server) Serve(ctx context.Context, listener net.Listener, tlsConfig *tls.Config) error {
	bounds, err := s.validate()
	if err != nil {
		return err
	}
	if tlsConfig == nil || tlsConfig.MinVersion < tls.VersionTLS13 || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil {
		return errors.New("authorityrpc: TLS 1.3 and CA-verified client certificates are required")
	}
	s.budget = newFrameBudget(s.MaxFrameBytesInFlight)
	if err := s.initializeTransportRegistry(); err != nil {
		return err
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{protocolALPN}
	tlsListener := tls.NewListener(listener, tlsConfig)
	serveCtx, cancel := context.WithCancel(ctx)
	connections := make(chan struct{}, s.MaxConnections)
	var connectionWorkers sync.WaitGroup
	defer func() {
		cancel()
		_ = tlsListener.Close()
		connectionWorkers.Wait()
	}()
	go func() {
		<-serveCtx.Done()
		_ = tlsListener.Close()
	}()
	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			if serveCtx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case connections <- struct{}{}:
			connectionWorkers.Add(1)
			go func() {
				defer connectionWorkers.Done()
				defer func() { <-connections }()
				_ = s.serveConn(serveCtx, conn, bounds)
			}()
		default:
			_ = conn.Close()
		}
	}
}

// serveConn owns the authenticated boundary. It accepts only a TLS connection:
// peer identity is not an optional decoration on this protocol, and every
// authorization decision downstream reads it from the request context.
func (s *Server) serveConn(parent context.Context, conn net.Conn, bounds TransportBounds) error {
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return errors.New("authorityrpc: authority connections must be mutually authenticated TLS")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	if err := conn.SetDeadline(time.Now().Add(s.HandshakeTimeout)); err != nil {
		return err
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("authorityrpc: authenticated peer certificate is missing")
	}
	if state.NegotiatedProtocol != protocolALPN {
		return errors.New("authorityrpc: TLS peer did not negotiate the PortableFS authority protocol")
	}
	identity := volumeserver.PeerIdentity(sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo))
	return s.serveSession(ctx, cancel, conn, bounds, identity)
}

// serveSession multiplexes one authenticated connection. It is separate from
// serveConn so the transport can be exercised without standing up TLS, while
// the exported path stays fail-closed.
func (s *Server) serveSession(ctx context.Context, cancel context.CancelFunc, conn net.Conn, bounds TransportBounds, identity volumeserver.PeerIdentity) error {
	if err := s.initializeTransportRegistry(); err != nil {
		return err
	}
	var workers sync.WaitGroup
	var entry *transportConnection
	defer func() {
		cancel()
		_ = conn.Close()
		workers.Wait()
		if entry != nil {
			s.registry.unregister(entry)
		}
	}()
	var requestCtx context.Context
	var err error
	entry, requestCtx, err = s.acceptTransportHello(ctx, cancel, conn, bounds, identity)
	if err != nil {
		return err
	}
	ordinaryLimit, blockingLimit := blockingWaitLane(s.MaxInFlight)
	ordinary := make(chan struct{}, ordinaryLimit)
	blocking := make(chan struct{}, blockingLimit)
	var writers sync.Mutex
	writeResponse := func(request *authoritypb.Request, response *authoritypb.Response) error {
		writers.Lock()
		defer writers.Unlock()
		return writeObservedResponse(conn, s.MaxFrame, s.WriteTimeout, s.Handler, request, response)
	}
	type inflightRequest struct {
		request *authoritypb.Request
		cancel  context.CancelFunc
	}
	var inflightMu sync.Mutex
	inflight := make(map[uint64]inflightRequest)
	if quiescer, ok := s.Handler.(terminalQuiescer); ok {
		go func() {
			select {
			case <-ctx.Done():
				return
			case <-quiescer.TerminalQuiescing():
			}
			inflightMu.Lock()
			for _, operation := range inflight {
				if terminalQuiesceCancelable(operation.request) {
					operation.cancel()
				}
			}
			inflightMu.Unlock()
		}()
	}
	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.IdleTimeout)); err != nil {
			return err
		}
		request := new(authoritypb.Request)
		releaseFrame, err := readFrameRetained(conn, bounds.MaxRequestFrame, s.budget, s.WriteTimeout, request)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if request.GetRequestId() == 0 {
			releaseFrame()
			return errors.New("authorityrpc: request ID zero is reserved")
		}
		if err := requestAllowedOnRole(request, entry.role); err != nil {
			releaseFrame()
			return err
		}
		if cancelRequest := request.GetCancel(); cancelRequest != nil {
			session, sessionErr := sessionIDFromRequest(request)
			if sessionErr != nil {
				releaseFrame()
				return sessionErr
			}
			_, pin, err := s.registry.pinCurrent(entry, session)
			if err != nil {
				releaseFrame()
				return err
			}
			inflightMu.Lock()
			cancelTarget := inflight[cancelRequest.GetTargetRequestId()].cancel
			inflightMu.Unlock()
			if cancelTarget != nil {
				cancelTarget()
			}
			// Cancellation must remain processable when every normal execution
			// slot is occupied. Its handler only validates the epoch and returns
			// the acknowledgment, so execute it inline outside the normal slots.
			response := handleTransportRequest(s.Handler, requestCtx, request)
			finishResponse := finishHandlerResponse(s.Handler, request, response)
			writeErr := writeResponse(request, response)
			finishResponse()
			pin.Release()
			if writeErr != nil {
				releaseFrame()
				return writeErr
			}
			releaseFrame()
			continue
		}
		// A blocking POSIX lock wait parks until an unrelated session releases a
		// lock. It gets its own lane so it can never occupy the last ordinary
		// slot, which is what the client's keepalive needs to stay live.
		lane := ordinary
		if blockingWait(request) {
			lane = blocking
		}
		admissionTimer := time.NewTimer(s.WriteTimeout)
		select {
		case lane <- struct{}{}:
			if !admissionTimer.Stop() {
				select {
				case <-admissionTimer.C:
				default:
				}
			}
		case <-ctx.Done():
			admissionTimer.Stop()
			releaseFrame()
			return nil
		case <-admissionTimer.C:
			// A peer that exceeds the advertised connection bound loses only its
			// connection after a bounded wait. Closing is safe: same-epoch
			// mutations use replay identities, while unknown results remain
			// explicitly uncertain.
			releaseFrame()
			return errors.New("authorityrpc: connection in-flight bound exceeded")
		}
		opCtx, opCancel := context.WithCancel(requestCtx)
		inflightMu.Lock()
		if _, duplicate := inflight[request.GetRequestId()]; duplicate {
			inflightMu.Unlock()
			opCancel()
			<-lane
			releaseFrame()
			return errors.New("authorityrpc: duplicate in-flight request ID")
		}
		inflight[request.GetRequestId()] = inflightRequest{request: request, cancel: opCancel}
		inflightMu.Unlock()
		workers.Add(1)
		go func(req *authoritypb.Request, opCtx context.Context, opCancel context.CancelFunc, lane chan struct{}, releaseFrame func()) {
			defer workers.Done()
			defer func() { <-lane }()
			defer releaseFrame()
			defer opCancel()
			defer func() {
				inflightMu.Lock()
				delete(inflight, req.GetRequestId())
				inflightMu.Unlock()
			}()
			if err := s.executeTransportRequest(opCtx, entry, req, writeResponse); err != nil {
				cancel()
				_ = conn.Close()
			}
		}(request, opCtx, opCancel, lane, releaseFrame)
	}
}
