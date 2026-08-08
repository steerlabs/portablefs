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
	Handle(context.Context, *authoritypb.Request) *authoritypb.Response
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
}

func (s *Server) validate() (TransportBounds, error) {
	if s.Handler == nil || s.MaxFrame == 0 || s.MaxInFlight <= 0 || s.MaxConnections <= 0 ||
		s.MaxFrameBytesInFlight == 0 || s.HandshakeTimeout <= 0 || s.IdleTimeout <= 0 || s.WriteTimeout <= 0 {
		return TransportBounds{}, errors.New("authorityrpc: handler, admission bounds, allocation budget, and connection timeouts are required")
	}
	if s.MaxInFlight < 2 {
		return TransportBounds{}, errors.New("authorityrpc: max-in-flight must admit an ordinary request and a blocking lock wait independently")
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
	identity := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return s.serveSession(ctx, cancel, conn, bounds, identity)
}

// serveSession multiplexes one authenticated connection. It is separate from
// serveConn so the transport can be exercised without standing up TLS, while
// the exported path stays fail-closed.
func (s *Server) serveSession(ctx context.Context, cancel context.CancelFunc, conn net.Conn, bounds TransportBounds, identity [32]byte) error {
	requestCtx := context.WithValue(ctx, peerIdentityKey{}, identity)
	ordinaryLimit, blockingLimit := blockingWaitLane(s.MaxInFlight)
	ordinary := make(chan struct{}, ordinaryLimit)
	blocking := make(chan struct{}, blockingLimit)
	var writers sync.Mutex
	writeResponse := func(requestID uint64, response *authoritypb.Response) error {
		if response == nil {
			// A handler that produced nothing is an internal defect, never an
			// epoch change: stamp the live epoch so the client is not told to
			// remount after a failover that did not happen.
			response = &authoritypb.Response{
				RequestId: requestID, Epoch: s.Handler.Epoch(),
				Errno: int32(syscall.EIO), Uncertain: true, Failure: authoritypb.FailureClass_FAILURE_CLASS_INTERNAL,
			}
		}
		writers.Lock()
		defer writers.Unlock()
		if err := conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout)); err != nil {
			return err
		}
		err := writeFrame(conn, s.MaxFrame, response)
		if errors.Is(err, ErrFrameBounds) {
			// The replacement must carry the same epoch and the same recorded
			// replay-slot state as the reply it stands in for. Dropping either
			// would report a failover or desynchronize the client's slot.
			response = &authoritypb.Response{
				RequestId: response.GetRequestId(), Epoch: s.Handler.Epoch(),
				Mutation: response.GetMutation(), Errno: int32(syscall.EOVERFLOW), Uncertain: true,
			}
			err = writeFrame(conn, s.MaxFrame, response)
		}
		return err
	}
	var workers sync.WaitGroup
	var inflightMu sync.Mutex
	inflight := make(map[uint64]context.CancelFunc)
	defer func() {
		cancel()
		_ = conn.Close()
		workers.Wait()
	}()
	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.IdleTimeout)); err != nil {
			return err
		}
		request := new(authoritypb.Request)
		if err := readFrame(conn, bounds.MaxRequestFrame, s.budget, s.WriteTimeout, request); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if request.GetRequestId() == 0 {
			return errors.New("authorityrpc: request ID zero is reserved")
		}
		if cancelRequest := request.GetCancel(); cancelRequest != nil {
			inflightMu.Lock()
			cancelTarget := inflight[cancelRequest.GetTargetRequestId()]
			inflightMu.Unlock()
			if cancelTarget != nil {
				cancelTarget()
			}
			// Cancellation must remain processable when every normal execution
			// slot is occupied. Its handler only validates the epoch and returns
			// the acknowledgment, so execute it inline outside the normal slots.
			if err := writeResponse(request.GetRequestId(), s.Handler.Handle(requestCtx, request)); err != nil {
				return err
			}
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
			return nil
		case <-admissionTimer.C:
			// A peer that exceeds the advertised connection bound loses only its
			// connection after a bounded wait. Closing is safe: same-epoch
			// mutations use replay identities, while unknown results remain
			// explicitly uncertain.
			return errors.New("authorityrpc: connection in-flight bound exceeded")
		}
		opCtx, opCancel := context.WithCancel(requestCtx)
		inflightMu.Lock()
		if _, duplicate := inflight[request.GetRequestId()]; duplicate {
			inflightMu.Unlock()
			opCancel()
			<-lane
			return errors.New("authorityrpc: duplicate in-flight request ID")
		}
		inflight[request.GetRequestId()] = opCancel
		inflightMu.Unlock()
		workers.Add(1)
		go func(req *authoritypb.Request, opCtx context.Context, opCancel context.CancelFunc, lane chan struct{}) {
			defer workers.Done()
			defer func() { <-lane }()
			defer opCancel()
			defer func() {
				inflightMu.Lock()
				delete(inflight, req.GetRequestId())
				inflightMu.Unlock()
			}()
			if err := writeResponse(req.GetRequestId(), s.Handler.Handle(opCtx, req)); err != nil {
				cancel()
				_ = conn.Close()
			}
		}(request, opCtx, opCancel, lane)
	}
}
