package authorityrpc

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type observedResponseWrite struct {
	response *authoritypb.Response
	err      error
}

type responseObserverTestHandler struct {
	*lifecycleTestHandler
	written chan observedResponseWrite
}

func (*responseObserverTestHandler) PrepareResponseWrite(*authoritypb.Request, *authoritypb.Response) {
}

func (*responseObserverTestHandler) TerminalQuiescing() <-chan struct{} {
	return make(chan struct{})
}

func (h *responseObserverTestHandler) ResponseWritten(response *authoritypb.Response, err error) {
	h.written <- observedResponseWrite{response: response, err: err}
}

func TestResponseObserverRunsOnlyAfterPhysicalWriteAttempt(t *testing.T) {
	base := newLifecycleTestHandler(volumeserver.SessionStateActive)
	handler := &responseObserverTestHandler{lifecycleTestHandler: base, written: make(chan observedResponseWrite, 1)}
	response := &authoritypb.Response{RequestId: 7, Epoch: base.Epoch()}
	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		done <- writeObservedResponse(writer, 4096, time.Second, handler, &authoritypb.Request{RequestId: response.GetRequestId()}, response)
	}()
	select {
	case observed := <-handler.written:
		t.Fatalf("observer ran before the peer consumed the frame: %+v", observed)
	case <-time.After(20 * time.Millisecond):
	}
	var decoded authoritypb.Response
	if err := readFrame(reader, 4096, nil, 0, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case observed := <-handler.written:
		if observed.response != response || observed.err != nil {
			t.Fatalf("observed write = %+v", observed)
		}
	case <-time.After(time.Second):
		t.Fatal("observer did not run after the physical frame write")
	}

	failingWriter, failingReader := net.Pipe()
	_ = failingReader.Close()
	failure := writeObservedResponse(failingWriter, 4096, time.Second, handler, &authoritypb.Request{RequestId: response.GetRequestId()}, response)
	_ = failingWriter.Close()
	if failure == nil {
		t.Fatal("closed peer write unexpectedly succeeded")
	}
	select {
	case observed := <-handler.written:
		if observed.response != response || observed.err == nil {
			t.Fatalf("failed observed write = %+v", observed)
		}
	case <-time.After(time.Second):
		t.Fatal("observer did not run after the failed physical write attempt")
	}
}

type lifecycleTestHandler struct {
	terminal      chan struct{}
	terminalCalls atomic.Int32
	state         atomic.Int32
	handle        func(context.Context, *authoritypb.Request) *authoritypb.Response
}

func newLifecycleTestHandler(state volumeserver.SessionState) *lifecycleTestHandler {
	h := &lifecycleTestHandler{terminal: make(chan struct{})}
	h.state.Store(int32(state))
	return h
}

func (*lifecycleTestHandler) Epoch() []byte { return make([]byte, 16) }

func (*lifecycleTestHandler) Bounds() TransportBounds {
	return TransportBounds{MaxFrame: 4096, MaxRequestFrame: 4096, MaxInFlight: 4}
}

func (h *lifecycleTestHandler) SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return volumeserver.SessionState(h.state.Load()), true
}

func (h *lifecycleTestHandler) SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool) {
	h.terminalCalls.Add(1)
	return h.terminal, true
}

func (h *lifecycleTestHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	if h.handle != nil {
		return h.handle(ctx, request)
	}
	return &authoritypb.Response{RequestId: request.GetRequestId(), Epoch: h.Epoch()}
}

func lifecyclePair(t *testing.T, registry *transportRegistry, session volumeserver.SessionID) (*transportConnection, *atomic.Int32, *transportConnection, *atomic.Int32, transportPairSnapshot) {
	t.Helper()
	data, dataClosed := testTransportRegistration(t, registry, 0x41, 0x42, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	control, controlClosed := testTransportRegistration(t, registry, 0x41, 0x42, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	snapshot, replaced, err := registry.bindProvisional(data, session)
	if err != nil || len(replaced) != 0 {
		t.Fatalf("bind provisional = %+v, replaced=%v, err=%v", snapshot, replaced, err)
	}
	if err := registry.exposeCurrentPair(data, session); err != nil {
		t.Fatal(err)
	}
	return data, dataClosed, control, controlClosed, snapshot
}

func lifecycleAttachResponse(requestID uint64, session volumeserver.SessionID) *authoritypb.Response {
	return &authoritypb.Response{
		RequestId: requestID,
		Body: &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: append([]byte(nil), session[:]...), Generation: 1,
			ResumeSecret: make([]byte, 32), ProvisionalDeadlineUnixNanos: time.Now().Add(time.Minute).UnixNano(),
		}},
	}
}

func TestTransportAttachReplayAndActivateSerializeExactBoundary(t *testing.T) {
	registry, err := newTransportRegistry(1)
	if err != nil {
		t.Fatal(err)
	}
	session := volumeserver.SessionID{0x31}
	data, _, control, _, snapshot := lifecyclePair(t, registry, session)
	handler := newLifecycleTestHandler(volumeserver.SessionStateProvisional)
	attachEntered := make(chan struct{})
	releaseAttach := make(chan struct{})
	activateEntered := make(chan struct{})
	var attachOnce sync.Once
	handler.handle = func(_ context.Context, request *authoritypb.Request) *authoritypb.Response {
		switch {
		case request.GetAttach() != nil:
			attachOnce.Do(func() { close(attachEntered) })
			<-releaseAttach
			return lifecycleAttachResponse(request.GetRequestId(), session)
		case request.GetActivate() != nil:
			close(activateEntered)
			handler.state.Store(int32(volumeserver.SessionStateActive))
			return &authoritypb.Response{RequestId: request.GetRequestId(), Body: &authoritypb.Response_Activate{
				Activate: &authoritypb.ActivateReply{State: authoritypb.SessionState_SESSION_STATE_ACTIVE},
			}}
		default:
			return &authoritypb.Response{RequestId: request.GetRequestId()}
		}
	}
	server := &Server{Handler: handler, registry: registry}
	attachRequest := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Attach{Attach: &authoritypb.AttachRequest{}}}
	activateRequest := &authoritypb.Request{RequestId: 2, Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
		DataBindingGeneration: snapshot.dataGeneration, ControlBindingGeneration: snapshot.controlGeneration,
	}}}
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- server.executeTransportAttach(context.Background(), data, attachRequest, func(*authoritypb.Request, *authoritypb.Response) error { return nil })
	}()
	select {
	case <-attachEntered:
	case <-time.After(time.Second):
		t.Fatal("Attach replay did not enter the handler")
	}
	activateDone := make(chan error, 1)
	go func() {
		activateDone <- server.executeTransportActivate(context.Background(), control, session, activateRequest, func(*authoritypb.Request, *authoritypb.Response) error { return nil })
	}()
	select {
	case <-activateEntered:
		t.Fatal("Activate crossed the exact Attach replay boundary")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseAttach)
	if err := <-attachDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-activateEntered:
	case <-time.After(time.Second):
		t.Fatal("Activate did not proceed after Attach exposure")
	}
	if err := <-activateDone; err != nil {
		t.Fatal(err)
	}
	close(handler.terminal)
}

func TestTransportExecutionPinDrainsUnderContinuousLifecycleLock(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	session := volumeserver.SessionID{0x35}
	data, _, _, _, _ := lifecyclePair(t, registry, session)
	if err := registry.markActive(data, session); err != nil {
		t.Fatal(err)
	}
	_, pin, err := registry.pinActive(data, session)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := testTransportRegistration(t, registry, 0x41, 0x42, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	promoted := make(chan struct{})
	transitionDone := make(chan error, 1)
	go func() {
		data.pair.operation.Lock()
		_, predecessor, err := registry.promoteResume(candidate, session, authoritypb.SessionState_SESSION_STATE_ACTIVE)
		if err != nil {
			data.pair.operation.Unlock()
			transitionDone <- err
			return
		}
		close(promoted)
		if !retireTransportConnections(data.pair, predecessor) {
			data.pair.operation.Unlock()
			transitionDone <- ErrTransportBinding
			return
		}
		err = registry.exposeResumed(candidate, session, authoritypb.SessionState_SESSION_STATE_ACTIVE)
		data.pair.operation.Unlock()
		transitionDone <- err
	}()
	select {
	case <-promoted:
	case <-time.After(time.Second):
		t.Fatal("replacement did not generation-fence its predecessor")
	}
	if _, _, err := registry.pinActive(data, session); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("old generation admitted a pin after promotion: %v", err)
	}
	select {
	case err := <-transitionDone:
		t.Fatalf("replacement crossed an outstanding execution pin: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	lifecycleQueued := make(chan struct{})
	go func() {
		data.pair.operation.Lock()
		close(lifecycleQueued)
		data.pair.operation.Unlock()
	}()
	select {
	case <-lifecycleQueued:
		t.Fatal("pair operation lock was released during predecessor drain")
	case <-time.After(20 * time.Millisecond):
	}
	pin.Release()
	if err := <-transitionDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-lifecycleQueued:
	case <-time.After(time.Second):
		t.Fatal("queued lifecycle request did not proceed after execution drain")
	}
	if _, err := registry.activeWitness(candidate, session); err != nil {
		t.Fatalf("successor was not exposed after exact drain proof: %v", err)
	}
}

func TestTransportTerminalEdgeEndsExecutionDrainWithoutExposure(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	session := volumeserver.SessionID{0x36}
	data, _, _, _, _ := lifecyclePair(t, registry, session)
	if err := registry.markActive(data, session); err != nil {
		t.Fatal(err)
	}
	_, pin, err := registry.pinActive(data, session)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := testTransportRegistration(t, registry, 0x41, 0x42, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	promoted := make(chan struct{})
	drainResult := make(chan bool, 1)
	go func() {
		data.pair.operation.Lock()
		_, predecessor, promoteErr := registry.promoteResume(candidate, session, authoritypb.SessionState_SESSION_STATE_ACTIVE)
		if promoteErr != nil {
			data.pair.operation.Unlock()
			drainResult <- true
			return
		}
		close(promoted)
		result := retireTransportConnections(data.pair, predecessor)
		if result {
			_ = registry.exposeResumed(candidate, session, authoritypb.SessionState_SESSION_STATE_ACTIVE)
		}
		data.pair.operation.Unlock()
		drainResult <- result
	}()
	select {
	case <-promoted:
	case <-time.After(time.Second):
		t.Fatal("replacement did not start")
	}
	terminateTransportConnections(registry.markTerminal(session, authoritypb.SessionState_SESSION_STATE_TERMINAL)...)
	select {
	case exposed := <-drainResult:
		if exposed {
			t.Fatal("terminal pair authorized successor exposure")
		}
	case <-time.After(time.Second):
		t.Fatal("terminal edge did not release the execution drain")
	}
	pin.Release()
	if _, err := registry.snapshot(candidate); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("terminal successor remained registered: %v", err)
	}
}

func TestTransportTerminalIdentityInstallsOneWatcherAcrossAttachReplay(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	session := volumeserver.SessionID{0x32}
	data, dataClosed, _, controlClosed, _ := lifecyclePair(t, registry, session)
	handler := newLifecycleTestHandler(volumeserver.SessionStateProvisional)
	server := &Server{Handler: handler, registry: registry}
	if err := server.bindRuntimeTerminal(data, session); err != nil {
		t.Fatal(err)
	}
	if err := server.bindRuntimeTerminal(data, session); err != nil {
		t.Fatal(err)
	}
	if got := handler.terminalCalls.Load(); got != 2 {
		t.Fatalf("runtime terminal lookups = %d, want one per exact bind reconciliation", got)
	}
	data.pair.operation.Lock()
	installed, err := registry.bindTerminal(data, session, handler.terminal)
	data.pair.operation.Unlock()
	if err != nil || installed {
		t.Fatalf("duplicate terminal identity installed=%t err=%v", installed, err)
	}
	close(handler.terminal)
	waitForLifecycleCondition(t, func() bool {
		pairs, sessions := lifecycleRegistryCounts(registry)
		return dataClosed.Load() == 1 && controlClosed.Load() == 1 && pairs == 0 && sessions == 0
	}, "terminal watcher cleanup")
}

func TestTransportTerminalEdgeReleasesRegistryCapacity(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	session := volumeserver.SessionID{0x33}
	data, _, _, _, _ := lifecyclePair(t, registry, session)
	handler := newLifecycleTestHandler(volumeserver.SessionStateProvisional)
	server := &Server{Handler: handler, registry: registry}
	if err := server.bindRuntimeTerminal(data, session); err != nil {
		t.Fatal(err)
	}
	close(handler.terminal)
	waitForLifecycleCondition(t, func() bool {
		pairs, sessions := lifecycleRegistryCounts(registry)
		return pairs == 0 && sessions == 0
	}, "terminal capacity release")
	if replacement, _ := testTransportRegistration(t, registry, 0x51, 0x52, authoritypb.TransportRole_TRANSPORT_ROLE_DATA); replacement == nil {
		t.Fatal("terminal pair did not release bounded registry capacity")
	}
}

func TestTransportPlannedTerminalReplyAttemptsWriteBeforeResponderClose(t *testing.T) {
	for _, test := range []struct {
		name   string
		active bool
	}{
		{name: "abort provisional"},
		{name: "detach active", active: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry, _ := newTransportRegistry(1)
			session := volumeserver.SessionID{0x34}
			data, dataClosed, control, controlClosed, _ := lifecyclePair(t, registry, session)
			handlerState := volumeserver.SessionStateProvisional
			if test.active {
				if err := registry.markActive(control, session); err != nil {
					t.Fatal(err)
				}
				handlerState = volumeserver.SessionStateActive
			}
			handler := newLifecycleTestHandler(handlerState)
			var terminalOnce sync.Once
			handler.handle = func(_ context.Context, request *authoritypb.Request) *authoritypb.Response {
				terminalOnce.Do(func() { close(handler.terminal) })
				response := &authoritypb.Response{RequestId: request.GetRequestId()}
				if request.GetAbortAttach() != nil {
					response.Body = &authoritypb.Response_AbortAttach{AbortAttach: &authoritypb.AbortAttachReply{State: authoritypb.SessionState_SESSION_STATE_ABORTED}}
				}
				return response
			}
			server := &Server{Handler: handler, registry: registry}
			if err := server.bindRuntimeTerminal(data, session); err != nil {
				t.Fatal(err)
			}
			lostWrite := errors.New("simulated lost terminal reply")
			writeResponse := func(*authoritypb.Request, *authoritypb.Response) error {
				pairs, sessions := lifecycleRegistryCounts(registry)
				if pairs != 0 || sessions != 0 {
					t.Fatal("terminal transition did not release registry before reply attempt")
				}
				if dataClosed.Load() != 1 {
					t.Fatalf("DATA close count at reply = %d, want 1", dataClosed.Load())
				}
				if controlClosed.Load() != 0 {
					t.Fatalf("planned responder closed %d times before reply", controlClosed.Load())
				}
				return lostWrite
			}
			var err error
			if test.active {
				err = server.executeTransportDetach(context.Background(), control, session, &authoritypb.Request{
					RequestId: 2, Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{}},
				}, writeResponse)
			} else {
				err = server.executeTransportAbort(context.Background(), control, session, &authoritypb.Request{
					RequestId: 1, Body: &authoritypb.Request_AbortAttach{AbortAttach: &authoritypb.AbortAttachRequest{}},
				}, writeResponse)
			}
			if !errors.Is(err, lostWrite) {
				t.Fatalf("terminal result = %v, want simulated lost reply", err)
			}
			if controlClosed.Load() != 1 {
				t.Fatalf("planned responder close count after reply = %d, want 1", controlClosed.Load())
			}
		})
	}
}

func TestTransportBlockedReportDeliversTerminalReasonBeforeControlCloses(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	session := volumeserver.SessionID{0x44}
	data, dataClosed, control, controlClosed, _ := lifecyclePair(t, registry, session)
	if err := registry.markActive(control, session); err != nil {
		t.Fatal(err)
	}
	handler := newLifecycleTestHandler(volumeserver.SessionStateActive)
	handler.handle = func(_ context.Context, request *authoritypb.Request) *authoritypb.Response {
		close(handler.terminal)
		// Force the runtime-terminal watcher to win before Handler returns. This
		// is the exact race that used to close CONTROL before its definite reply.
		waitForLifecycleCondition(t, func() bool {
			pairs, sessions := lifecycleRegistryCounts(registry)
			return pairs == 0 && sessions == 0
		}, "blocked-report terminal transition")
		return &authoritypb.Response{
			RequestId: request.GetRequestId(), Errno: 116,
			Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE,
		}
	}
	server := &Server{Handler: handler, registry: registry}
	if err := server.bindRuntimeTerminal(data, session); err != nil {
		t.Fatal(err)
	}
	var wrote *authoritypb.Response
	err := server.executeTransportRequest(context.Background(), control, &authoritypb.Request{
		RequestId: 7,
		Session:   &authoritypb.SessionProof{Id: append([]byte(nil), session[:]...)},
		Body: &authoritypb.Request_AckVisibility{AckVisibility: &authoritypb.AckVisibilityRequest{
			Blocked: true,
		}},
	}, func(_ *authoritypb.Request, response *authoritypb.Response) error {
		pairs, sessions := lifecycleRegistryCounts(registry)
		if pairs != 0 || sessions != 0 {
			t.Fatalf("terminal report retained registry at reply: pairs=%d sessions=%d", pairs, sessions)
		}
		if dataClosed.Load() != 1 || controlClosed.Load() != 0 {
			t.Fatalf("close counts at reply = DATA %d CONTROL %d, want 1/0", dataClosed.Load(), controlClosed.Load())
		}
		wrote = response
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if wrote == nil || wrote.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE || wrote.GetErrno() != 116 {
		t.Fatalf("blocked-report response = %+v", wrote)
	}
	if controlClosed.Load() != 1 {
		t.Fatalf("CONTROL close count after reply = %d, want 1", controlClosed.Load())
	}
}

func TestTransportBlockedReportSuccessKeepsActivePairServing(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	session := volumeserver.SessionID{0x45}
	data, dataClosed, control, controlClosed, _ := lifecyclePair(t, registry, session)
	if err := registry.markActive(control, session); err != nil {
		t.Fatal(err)
	}
	handler := newLifecycleTestHandler(volumeserver.SessionStateActive)
	server := &Server{Handler: handler, registry: registry}
	var wrote *authoritypb.Response
	err := server.executeTransportRequest(context.Background(), control, &authoritypb.Request{
		RequestId: 8,
		Session:   &authoritypb.SessionProof{Id: append([]byte(nil), session[:]...)},
		Body: &authoritypb.Request_AckVisibility{AckVisibility: &authoritypb.AckVisibilityRequest{
			Blocked:                 true,
			BlockedParentKernelInos: []uint64{101},
		}},
	}, func(_ *authoritypb.Request, response *authoritypb.Response) error {
		wrote = response
		if _, err := registry.activeWitness(control, session); err != nil {
			t.Fatalf("CONTROL stopped serving before nonterminal blocked reply: %v", err)
		}
		if _, err := registry.activeWitness(data, session); err != nil {
			t.Fatalf("DATA stopped serving before nonterminal blocked reply: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if wrote == nil || wrote.GetErrno() != 0 {
		t.Fatalf("nonterminal blocked-report response = %+v", wrote)
	}
	if dataClosed.Load() != 0 || controlClosed.Load() != 0 {
		t.Fatalf("nonterminal blocked report closed DATA/CONTROL = %d/%d", dataClosed.Load(), controlClosed.Load())
	}
	if _, pin, err := registry.pinActive(data, session); err != nil {
		t.Fatalf("DATA was not executable after nonterminal blocked report: %v", err)
	} else {
		pin.Release()
	}
	registry.mu.Lock()
	responder := data.pair.terminalResponder
	state := data.pair.state
	registry.mu.Unlock()
	if responder != nil || state != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		t.Fatalf("post-report pair state = %s responder=%p, want ACTIVE/nil", state, responder)
	}
}

func TestTransportBlockedReportExcludesConcurrentControlResumeUntilReply(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	session := volumeserver.SessionID{0x46}
	data, dataClosed, control, controlClosed, _ := lifecyclePair(t, registry, session)
	if err := registry.markActive(control, session); err != nil {
		t.Fatal(err)
	}
	candidate, candidateClosed := testTransportRegistration(t, registry, 0x41, 0x42, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)

	blockedEntered := make(chan struct{})
	releaseBlocked := make(chan struct{})
	resumeStarted := make(chan struct{})
	resumeEntered := make(chan struct{})
	blockedWrote := make(chan struct{})
	var resumeCrossedResponse atomic.Bool
	handler := newLifecycleTestHandler(volumeserver.SessionStateActive)
	handler.handle = func(_ context.Context, request *authoritypb.Request) *authoritypb.Response {
		switch {
		case request.GetAckVisibility() != nil:
			close(blockedEntered)
			<-releaseBlocked
			return &authoritypb.Response{RequestId: request.GetRequestId()}
		case request.GetResume() != nil:
			select {
			case <-blockedWrote:
			default:
				resumeCrossedResponse.Store(true)
			}
			close(resumeEntered)
			return &authoritypb.Response{RequestId: request.GetRequestId(), Body: &authoritypb.Response_Resume{
				Resume: &authoritypb.ResumeReply{State: authoritypb.SessionState_SESSION_STATE_ACTIVE},
			}}
		default:
			return &authoritypb.Response{RequestId: request.GetRequestId()}
		}
	}
	server := &Server{Handler: handler, registry: registry}
	blockedDone := make(chan error, 1)
	go func() {
		blockedDone <- server.executeTransportRequest(context.Background(), control, &authoritypb.Request{
			RequestId: 9,
			Session:   &authoritypb.SessionProof{Id: append([]byte(nil), session[:]...)},
			Body: &authoritypb.Request_AckVisibility{AckVisibility: &authoritypb.AckVisibilityRequest{
				Blocked: true,
			}},
		}, func(_ *authoritypb.Request, response *authoritypb.Response) error {
			close(blockedWrote)
			if response == nil || response.GetErrno() != 0 {
				return errors.New("blocked report returned a failure response")
			}
			registry.mu.Lock()
			current := data.pair.control.current
			responder := data.pair.terminalResponder
			registry.mu.Unlock()
			if current != control || responder != control {
				return errors.New("CONTROL changed during blocked response write")
			}
			return nil
		})
	}()
	select {
	case <-blockedEntered:
	case <-time.After(time.Second):
		t.Fatal("blocked report did not enter handler")
	}

	resumeDone := make(chan error, 1)
	go func() {
		close(resumeStarted)
		resumeDone <- server.executeTransportRequest(context.Background(), candidate, &authoritypb.Request{
			RequestId: 2,
			Session:   &authoritypb.SessionProof{Id: append([]byte(nil), session[:]...)},
			Body:      &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}},
		}, func(_ *authoritypb.Request, response *authoritypb.Response) error {
			if response.GetResume() == nil || response.GetResume().GetRole() != authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL ||
				response.GetResume().GetBindingGeneration() != candidate.generation {
				return errors.New("CONTROL Resume returned malformed binding proof")
			}
			return nil
		})
	}()
	<-resumeStarted
	select {
	case <-resumeEntered:
		t.Fatal("CONTROL Resume crossed the blocked-report handler/reply transaction")
	default:
	}
	if controlClosed.Load() != 0 || candidateClosed.Load() != 0 {
		t.Fatalf("CONTROL generations closed while responder held: current=%d candidate=%d", controlClosed.Load(), candidateClosed.Load())
	}
	if snapshot, err := registry.snapshot(candidate); err != nil || !snapshot.candidate || snapshot.current || snapshot.serving {
		t.Fatalf("queued CONTROL candidate snapshot = %+v, err=%v", snapshot, err)
	}

	close(releaseBlocked)
	if err := <-blockedDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-resumeEntered:
	case <-time.After(time.Second):
		t.Fatal("CONTROL Resume did not enter after blocked response completed")
	}
	if err := <-resumeDone; err != nil {
		t.Fatal(err)
	}
	if resumeCrossedResponse.Load() {
		t.Fatal("CONTROL Resume handler ran before the blocked response write")
	}
	if controlClosed.Load() != 1 || candidateClosed.Load() != 0 || dataClosed.Load() != 0 {
		t.Fatalf("post-Resume close counts DATA/current CONTROL/candidate CONTROL = %d/%d/%d", dataClosed.Load(), controlClosed.Load(), candidateClosed.Load())
	}
	if _, err := registry.activeWitness(candidate, session); err != nil {
		t.Fatalf("CONTROL successor was not ACTIVE/serving after response boundary: %v", err)
	}
}

func lifecycleRegistryCounts(registry *transportRegistry) (int, int) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.pairs), len(registry.bySession)
}

func waitForLifecycleCondition(t *testing.T, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}
