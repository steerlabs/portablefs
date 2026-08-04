package authorityrpc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
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

type Handler interface {
	Handle(context.Context, *authoritypb.Request) *authoritypb.Response
}

type Server struct {
	Handler          Handler
	MaxFrame         uint32
	MaxInFlight      int
	MaxConnections   int
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	WriteTimeout     time.Duration
}

func (s *Server) Serve(ctx context.Context, listener net.Listener, tlsConfig *tls.Config) error {
	if s.Handler == nil || s.MaxFrame == 0 || s.MaxInFlight <= 0 || s.MaxConnections <= 0 ||
		s.HandshakeTimeout <= 0 || s.IdleTimeout <= 0 || s.WriteTimeout <= 0 {
		return errors.New("authorityrpc: handler, admission bounds, and connection timeouts are required")
	}
	if tlsConfig == nil || tlsConfig.MinVersion < tls.VersionTLS13 || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil {
		return errors.New("authorityrpc: TLS 1.3 and CA-verified client certificates are required")
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
				_ = s.serveConn(serveCtx, conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) serveConn(parent context.Context, conn net.Conn) error {
	ctx, cancel := context.WithCancel(parent)
	requestCtx := ctx
	defer cancel()
	defer conn.Close()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	if tlsConn, ok := conn.(*tls.Conn); ok {
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
		requestCtx = context.WithValue(ctx, peerIdentityKey{}, identity)
	}
	sem := make(chan struct{}, s.MaxInFlight)
	var writers sync.Mutex
	writeResponse := func(response *authoritypb.Response) error {
		if response == nil {
			response = &authoritypb.Response{Errno: int32(syscall.EIO), Uncertain: true}
		}
		writers.Lock()
		defer writers.Unlock()
		if err := conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout)); err != nil {
			return err
		}
		err := writeFrame(conn, s.MaxFrame, response)
		if errors.Is(err, ErrFrameBounds) {
			response = &authoritypb.Response{
				RequestId: response.GetRequestId(), Epoch: append([]byte(nil), response.GetEpoch()...),
				Errno: int32(syscall.EOVERFLOW), Uncertain: true,
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
		if err := readFrame(conn, s.MaxFrame, request); err != nil {
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
			// slot is occupied. Its handler only validates the session and returns
			// the acknowledgment, so execute it inline outside the normal slots.
			if err := writeResponse(s.Handler.Handle(requestCtx, request)); err != nil {
				return err
			}
			continue
		}
		admissionTimer := time.NewTimer(s.WriteTimeout)
		select {
		case sem <- struct{}{}:
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
		if request.GetCancel() == nil {
			inflightMu.Lock()
			if _, duplicate := inflight[request.GetRequestId()]; duplicate {
				inflightMu.Unlock()
				opCancel()
				<-sem
				return errors.New("authorityrpc: duplicate in-flight request ID")
			}
			inflight[request.GetRequestId()] = opCancel
			inflightMu.Unlock()
		}
		workers.Add(1)
		go func(req *authoritypb.Request, opCtx context.Context, opCancel context.CancelFunc) {
			defer workers.Done()
			defer func() { <-sem }()
			defer opCancel()
			if req.GetCancel() == nil {
				defer func() {
					inflightMu.Lock()
					delete(inflight, req.GetRequestId())
					inflightMu.Unlock()
				}()
			}
			response := s.Handler.Handle(opCtx, req)
			if response == nil {
				response = &authoritypb.Response{RequestId: req.GetRequestId(), Errno: 5, Uncertain: true}
			}
			err := writeResponse(response)
			if err != nil {
				cancel()
				_ = conn.Close()
			}
		}(request, opCtx, opCancel)
	}
}
