package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type transportResponseWriter func(*authoritypb.Request, *authoritypb.Response) error

func (s *Server) initializeTransportRegistry() error {
	s.registryMu.Lock()
	if s.registry == nil {
		registry, err := newTransportRegistry(s.MaxConnections)
		if err != nil {
			s.registryMu.Unlock()
			return err
		}
		s.registry = registry
	}
	s.registryMu.Unlock()
	return nil
}

// acceptTransportHello consumes the one mandatory first frame, validates its
// transport identity before publishing it, and echoes the server-owned role
// binding. No other request is allowed to enter the multiplexed loop until
// this transition succeeds.
func (s *Server) acceptTransportHello(
	ctx context.Context,
	cancel context.CancelFunc,
	conn net.Conn,
	bounds TransportBounds,
	peer volumeserver.PeerIdentity,
) (*transportConnection, context.Context, error) {
	if err := conn.SetReadDeadline(time.Now().Add(s.HandshakeTimeout)); err != nil {
		return nil, nil, err
	}
	request := new(authoritypb.Request)
	release, err := readFrameRetained(conn, bounds.MaxRequestFrame, s.budget, s.WriteTimeout, request)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	hello := request.GetHello()
	if request.GetRequestId() == 0 || hello == nil || request.GetBody() == nil ||
		len(request.GetEpoch()) != 0 || request.GetSession() != nil || request.GetMutation() != nil ||
		request.GetFrontendOperationId() != 0 || request.GetSourcePublicationGate() != nil ||
		request.GetVisibilityRetryAfterSequence() != 0 {
		return nil, nil, fmt.Errorf("%w: first frame must be a bare nonzero Hello", ErrTransportBinding)
	}
	if !validTransportRole(hello.GetRole()) {
		return nil, nil, fmt.Errorf("%w: Hello omitted a valid role", ErrTransportBinding)
	}
	setID, err := parseConnectionSetID(hello.GetConnectionSetId())
	if err != nil {
		return nil, nil, err
	}
	peerContext := context.WithValue(ctx, peerIdentityKey{}, [32]byte(peer))
	// Hello cannot touch the volume or produce a terminal applied-state result.
	// Keep it outside the retained transport-response lifecycle because the
	// handshake uses its own writer before the observed session writer exists.
	response := s.Handler.Handle(peerContext, request)
	if response == nil {
		return nil, nil, fmt.Errorf("%w: Hello handler returned no response", ErrTransportBinding)
	}
	if response.GetRequestId() != request.GetRequestId() || response.GetHello() == nil {
		return nil, nil, fmt.Errorf("%w: malformed Hello response", ErrTransportBinding)
	}
	if response.GetErrno() != 0 {
		if err := writeServerFrame(conn, s.MaxFrame, s.WriteTimeout, response); err != nil {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("%w: Hello refused with errno %d", ErrTransportBinding, response.GetErrno())
	}
	response.GetHello().Role = hello.GetRole()
	response.GetHello().ConnectionSetId = append([]byte(nil), hello.GetConnectionSetId()...)
	entry, err := s.registry.register(peer, setID, hello.GetRole(), cancel, conn.Close)
	if err != nil {
		return nil, nil, err
	}
	if err := writeServerFrame(conn, s.MaxFrame, s.WriteTimeout, response); err != nil {
		s.registry.unregister(entry)
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.registry.unregister(entry)
		return nil, nil, err
	}
	requestContext := withTransportConnection(peerContext, entry)
	return entry, requestContext, nil
}

func writeServerFrame(conn net.Conn, max uint32, timeout time.Duration, response *authoritypb.Response) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return writeFrame(conn, max, response)
}

func sessionIDFromRequest(request *authoritypb.Request) (volumeserver.SessionID, error) {
	var id volumeserver.SessionID
	proof := request.GetSession()
	if proof == nil || len(proof.GetId()) != len(id) {
		return id, fmt.Errorf("%w: request omitted a valid session proof", ErrTransportBinding)
	}
	copy(id[:], proof.GetId())
	if id == (volumeserver.SessionID{}) {
		return id, fmt.Errorf("%w: zero session identity", ErrTransportBinding)
	}
	return id, nil
}

func responseSucceeded(response *authoritypb.Response) bool {
	return response != nil && response.GetErrno() == 0
}

func (s *Server) bindRuntimeTerminal(entry *transportConnection, session volumeserver.SessionID) error {
	terminal, ok := s.Handler.SessionTerminalForTransport(session)
	if !ok || terminal == nil {
		terminateTransportConnections(s.registry.markTerminal(session, authoritypb.SessionState_SESSION_STATE_TERMINAL)...)
		return fmt.Errorf("%w: runtime omitted the bound session terminal edge", ErrTransportBinding)
	}
	installed, err := s.registry.bindTerminal(entry, session, terminal)
	if err != nil {
		terminateTransportConnections(s.registry.markTerminal(session, authoritypb.SessionState_SESSION_STATE_TERMINAL)...)
		return err
	}
	if installed {
		go func() {
			<-terminal
			terminateTransportConnections(s.registry.markTerminal(session, authoritypb.SessionState_SESSION_STATE_TERMINAL)...)
		}()
	}
	select {
	case <-terminal:
		terminateTransportConnections(s.registry.markTerminal(session, authoritypb.SessionState_SESSION_STATE_TERMINAL)...)
		return fmt.Errorf("%w: runtime session ended before transport exposure", ErrTransportBinding)
	default:
		return nil
	}
}

// executeTransportRequest owns the role/state transition around one handler
// invocation. State-changing requests hold only this pair's operation mutex;
// the global registry mutex is acquired in short validation/commit calls and
// never across handler work, filesystem I/O, or socket writes.
func (s *Server) executeTransportRequest(
	ctx context.Context,
	entry *transportConnection,
	request *authoritypb.Request,
	writeResponse transportResponseWriter,
) error {
	if err := requestAllowedOnRole(request, entry.role); err != nil {
		return err
	}
	session, sessionErr := sessionIDFromRequest(request)
	switch request.GetBody().(type) {
	case *authoritypb.Request_Attach:
		return s.executeTransportAttach(ctx, entry, request, writeResponse)
	case *authoritypb.Request_Resume:
		if sessionErr != nil {
			return sessionErr
		}
		return s.executeTransportResume(ctx, entry, session, request, writeResponse)
	case *authoritypb.Request_Activate:
		if sessionErr != nil {
			return sessionErr
		}
		return s.executeTransportActivate(ctx, entry, session, request, writeResponse)
	case *authoritypb.Request_AbortAttach:
		if sessionErr != nil {
			return sessionErr
		}
		return s.executeTransportAbort(ctx, entry, session, request, writeResponse)
	case *authoritypb.Request_Detach:
		if sessionErr != nil {
			return sessionErr
		}
		return s.executeTransportDetach(ctx, entry, session, request, writeResponse)
	case *authoritypb.Request_AckVisibility:
		if sessionErr != nil {
			return sessionErr
		}
		if request.GetAckVisibility().GetBlocked() {
			return s.executeTransportBlockedReport(ctx, entry, session, request, writeResponse)
		}
		if _, pin, err := s.registry.pinActive(entry, session); err != nil {
			return err
		} else {
			defer pin.Release()
		}
		response := handleTransportRequest(s.Handler, ctx, request)
		defer finishHandlerResponse(s.Handler, request, response)()
		return writeResponse(request, response)
	default:
		if sessionErr != nil {
			return sessionErr
		}
		if _, pin, err := s.registry.pinActive(entry, session); err != nil {
			return err
		} else {
			defer pin.Release()
		}
		response := handleTransportRequest(s.Handler, ctx, request)
		defer finishHandlerResponse(s.Handler, request, response)()
		return writeResponse(request, response)
	}
}

// executeTransportBlockedReport preserves the one exact response attempt for a
// report which may synchronously fence its own runtime session. A namespace
// cycle report normally succeeds and leaves the session active; a route-change
// report (or malformed report) deliberately fences it. Without the response
// hold, SessionTerminal closes CONTROL from inside Handler before the caller can
// receive the reason it must unmount, collapsing a definite coherence verdict
// into an unrelated transport-uncertain error.
func (s *Server) executeTransportBlockedReport(
	ctx context.Context,
	entry *transportConnection,
	session volumeserver.SessionID,
	request *authoritypb.Request,
	writeResponse transportResponseWriter,
) error {
	pair := entry.pair
	pair.operation.Lock()
	defer pair.operation.Unlock()
	if _, err := s.registry.activeWitness(entry, session); err != nil {
		return err
	}
	if err := s.registry.beginTerminalResponse(entry, session); err != nil {
		return err
	}
	response := handleTransportRequest(s.Handler, ctx, request)
	defer finishHandlerResponse(s.Handler, request, response)()
	writeErr := writeResponse(request, response)
	if s.registry.finishTerminalResponse(entry) {
		terminateTransportConnections(entry)
	} else {
		s.registry.cancelTerminalResponse(entry)
	}
	return writeErr
}

func (s *Server) executeTransportAttach(ctx context.Context, entry *transportConnection, request *authoritypb.Request, writeResponse transportResponseWriter) error {
	pair := entry.pair
	pair.operation.Lock()
	if _, err := s.registry.attachWitness(entry); err != nil {
		pair.operation.Unlock()
		return err
	}
	response := handleTransportRequest(s.Handler, ctx, request)
	defer finishHandlerResponse(s.Handler, request, response)()
	if !responseSucceeded(response) {
		pair.operation.Unlock()
		return writeResponse(request, response)
	}
	attach := response.GetAttach()
	if attach == nil || len(attach.GetSessionId()) != len(volumeserver.SessionID{}) ||
		attach.GetGeneration() == 0 || len(attach.GetResumeSecret()) != len(volumeserver.ResumeSecret{}) ||
		attach.GetProvisionalDeadlineUnixNanos() <= 0 {
		pair.operation.Unlock()
		return fmt.Errorf("%w: malformed provisional Attach response", ErrTransportBinding)
	}
	var session volumeserver.SessionID
	copy(session[:], attach.GetSessionId())
	snapshot, replaced, err := s.registry.bindProvisional(entry, session)
	if err != nil {
		pair.operation.Unlock()
		return err
	}
	attach.DataBindingGeneration = snapshot.dataGeneration
	attach.ControlBindingGeneration = snapshot.controlGeneration
	if err := s.bindRuntimeTerminal(entry, session); err != nil {
		pair.operation.Unlock()
		return err
	}
	// Promotion atomically closes predecessor admission. Lifecycle requests do
	// not pin and are serialized on pair.operation, so it remains held while we
	// close the old sockets and wait only for already-admitted ordinary work.
	// Request cancellation cannot abandon this proof; only the runtime terminal
	// edge may end it, in which case no successor is exposed.
	if !retireTransportConnections(pair, replaced...) {
		pair.operation.Unlock()
		return ErrTransportBinding
	}
	defer pair.operation.Unlock()
	// A provisional deadline may have expired after the handler minted this
	// exact result but before bindProvisional published it. The runtime hook could
	// not find an unbound session then, so this post-bind query is the other half
	// of the handshake: termination is observed either here or by the terminal
	// edge. Keeping pair.operation through this query, exposure, and reply also
	// prevents an exact Attach replay from mistaking a concurrent Activate for
	// a dead provisional session.
	state, live := s.Handler.SessionStateForTransport(session)
	if !live || state != volumeserver.SessionStateProvisional {
		// The terminal edge owns runtime-to-transport cleanup. In particular, do
		// not destroy a live ACTIVE session merely because a defective handler
		// reported an impossible state at this provisional boundary.
		return fmt.Errorf("%w: provisional session ended before transport exposure", ErrTransportBinding)
	}
	if err := s.registry.exposeCurrentPair(entry, session); err != nil {
		return err
	}
	err = writeResponse(request, response)
	return err
}

func (s *Server) executeTransportResume(ctx context.Context, entry *transportConnection, session volumeserver.SessionID, request *authoritypb.Request, writeResponse transportResponseWriter) error {
	pair := entry.pair
	pair.operation.Lock()
	before, err := s.registry.resumeWitness(entry, session)
	if err != nil {
		pair.operation.Unlock()
		return err
	}
	response := handleTransportRequest(s.Handler, ctx, request)
	defer finishHandlerResponse(s.Handler, request, response)()
	if !responseSucceeded(response) {
		pair.operation.Unlock()
		return writeResponse(request, response)
	}
	resume := response.GetResume()
	if resume == nil || resume.GetState() != before.state {
		pair.operation.Unlock()
		return fmt.Errorf("%w: runtime and transport disagree on resumed session state", ErrTransportBinding)
	}
	after, replaced, err := s.registry.promoteResume(entry, session, resume.GetState())
	if err != nil {
		pair.operation.Unlock()
		return err
	}
	resume.Role = entry.role
	resume.BindingGeneration = after.bindingGeneration
	if !retireTransportConnections(pair, replaced) {
		pair.operation.Unlock()
		return ErrTransportBinding
	}
	if err := s.registry.exposeResumed(entry, session, resume.GetState()); err != nil {
		pair.operation.Unlock()
		return err
	}
	err = writeResponse(request, response)
	pair.operation.Unlock()
	return err
}

func (s *Server) executeTransportActivate(ctx context.Context, entry *transportConnection, session volumeserver.SessionID, request *authoritypb.Request, writeResponse transportResponseWriter) error {
	pair := entry.pair
	pair.operation.Lock()
	defer pair.operation.Unlock()
	activate := request.GetActivate()
	if activate == nil {
		return ErrTransportBinding
	}
	if _, err := s.registry.activationWitness(entry, session, activate.GetDataBindingGeneration(), activate.GetControlBindingGeneration()); err != nil {
		return err
	}
	response := handleTransportRequest(s.Handler, ctx, request)
	defer finishHandlerResponse(s.Handler, request, response)()
	if !responseSucceeded(response) {
		return writeResponse(request, response)
	}
	if response.GetActivate() == nil || response.GetActivate().GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		return fmt.Errorf("%w: activation returned no ACTIVE result", ErrTransportBinding)
	}
	if err := s.registry.markActive(entry, session); err != nil {
		return err
	}
	return writeResponse(request, response)
}

func (s *Server) executeTransportAbort(ctx context.Context, entry *transportConnection, session volumeserver.SessionID, request *authoritypb.Request, writeResponse transportResponseWriter) error {
	pair := entry.pair
	pair.operation.Lock()
	defer pair.operation.Unlock()
	if _, err := s.registry.provisionalControlWitness(entry, session); err != nil {
		return err
	}
	if err := s.registry.beginTerminalResponse(entry, session); err != nil {
		return err
	}
	response := handleTransportRequest(s.Handler, ctx, request)
	defer finishHandlerResponse(s.Handler, request, response)()
	if responseSucceeded(response) {
		if response.GetAbortAttach() == nil || response.GetAbortAttach().GetState() != authoritypb.SessionState_SESSION_STATE_ABORTED {
			s.registry.cancelTerminalResponse(entry)
			return fmt.Errorf("%w: abort returned no ABORTED result", ErrTransportBinding)
		}
		// Test handlers may not own a runtime, while production's runtime hook may
		// already have performed this exact transition. It is idempotent either way.
		terminateTransportConnections(s.registry.markTerminal(session, authoritypb.SessionState_SESSION_STATE_ABORTED)...)
	}
	writeErr := writeResponse(request, response)
	if s.registry.finishTerminalResponse(entry) {
		terminateTransportConnections(entry)
	} else {
		s.registry.cancelTerminalResponse(entry)
	}
	return writeErr
}

func (s *Server) executeTransportDetach(ctx context.Context, entry *transportConnection, session volumeserver.SessionID, request *authoritypb.Request, writeResponse transportResponseWriter) error {
	pair := entry.pair
	pair.operation.Lock()
	defer pair.operation.Unlock()
	if _, err := s.registry.activeWitness(entry, session); err != nil {
		return err
	}
	if err := s.registry.beginTerminalResponse(entry, session); err != nil {
		return err
	}
	response := handleTransportRequest(s.Handler, ctx, request)
	defer finishHandlerResponse(s.Handler, request, response)()
	if responseSucceeded(response) {
		terminateTransportConnections(s.registry.markTerminal(session, authoritypb.SessionState_SESSION_STATE_TERMINAL)...)
	}
	writeErr := writeResponse(request, response)
	if s.registry.finishTerminalResponse(entry) {
		terminateTransportConnections(entry)
	} else {
		s.registry.cancelTerminalResponse(entry)
	}
	return writeErr
}

func transportProtocolErrorResponse(handler Handler, requestID uint64) *authoritypb.Response {
	return &authoritypb.Response{
		RequestId: requestID, Epoch: handler.Epoch(), Errno: int32(syscall.EPROTO),
		Failure: authoritypb.FailureClass_FAILURE_CLASS_INTERNAL,
	}
}

func isTransportProtocolError(err error) bool {
	return errors.Is(err, ErrTransportBinding)
}
