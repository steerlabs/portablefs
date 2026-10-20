package authorityrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

type controlProgressHandler struct{ echoHandler }

func (h controlProgressHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	if req.GetResume() != nil {
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), Body: &authoritypb.Response_Resume{Resume: &authoritypb.ResumeReply{State: authoritypb.SessionState_SESSION_STATE_ACTIVE}}}
	}
	return h.echoHandler.Handle(ctx, req)
}

func TestDataBudgetSaturationPreservesControlAndBootstrap(t *testing.T) {
	server := &Server{Handler: controlProgressHandler{echoHandler{epoch: []byte("epoch")}}, MaxFrame: 4096, MaxInFlight: 9, MaxConnections: 8, MaxFrameBytesInFlight: controlFrameReserve() + 1<<20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
	pair := startActiveTestPair(t, server)
	defer pair.close(t)
	// Reading Activate's response can precede its worker releasing the frame.
	// Start saturation only after that bootstrap reservation has retired.
	deadline := time.Now().Add(time.Second)
	for {
		server.budget.mu.Lock()
		idle := server.budget.available == server.MaxFrameBytesInFlight
		server.budget.mu.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bootstrap frame did not retire")
		}
		time.Sleep(time.Millisecond)
	}
	remaining := server.MaxFrameBytesInFlight - controlFrameReserve()
	if err := server.budget.acquire(t.Context(), uint32(remaining), time.Second, true); err != nil {
		t.Fatal(err)
	}
	defer server.budget.release(uint32(remaining))
	if err := server.budget.acquire(t.Context(), 1, 10*time.Millisecond, true); !errors.Is(err, ErrFrameBudget) {
		t.Fatalf("DATA consumed CONTROL reserve: %v", err)
	}
	for index, body := range []any{
		&authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}},
		&authoritypb.Request_ChangeAck{ChangeAck: &authoritypb.ChangeAck{}},
		&authoritypb.Request_TerminalDeliveryReceipt{TerminalDeliveryReceipt: &authoritypb.TerminalDeliveryReceipt{Token: bytes.Repeat([]byte{1}, 16)}},
		&authoritypb.Request_Reauthorize{Reauthorize: &authoritypb.ReauthorizeRequest{}},
	} {
		request := &authoritypb.Request{RequestId: uint64(index + 10), Epoch: pair.epoch, Session: proto.Clone(pair.proof).(*authoritypb.SessionProof)}
		// Every body is deliberately explicit so the role allowlist remains the
		// same boundary used by production, rather than a byte-budget-only fake.
		switch b := body.(type) {
		case *authoritypb.Request_KeepAlive:
			request.Body = b
		case *authoritypb.Request_ChangeAck:
			request.Body = b
		case *authoritypb.Request_TerminalDeliveryReceipt:
			request.Body = b
		case *authoritypb.Request_Reauthorize:
			request.Body = b
		}
		if err := pair.control.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := writeFrame(pair.control, 4096, request); err != nil {
			t.Fatal(err)
		}
		var response authoritypb.Response
		if err := readFrame(pair.control, 4096, nil, 0, &response); err != nil {
			t.Fatalf("%T blocked by DATA saturation: %v", body, err)
		}
		if response.GetRequestId() != request.GetRequestId() {
			t.Fatalf("control response=%v", &response)
		}
	}
	for _, role := range []authoritypb.TransportRole{authoritypb.TransportRole_TRANSPORT_ROLE_DATA, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL} {
		client, peer := net.Pipe()
		done := testServeSession(t, server, peer)
		if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		set := make([]byte, 32)
		set[0] = 7
		hello := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor, Role: role, ConnectionSetId: set}}}
		if err := writeFrame(client, 4096, hello); err != nil {
			t.Fatal(err)
		}
		var response authoritypb.Response
		if err := readFrame(client, 4096, nil, 0, &response); err != nil {
			t.Fatalf("replacement %s Hello blocked: %v", role, err)
		}
		resume := &authoritypb.Request{RequestId: 2, Epoch: pair.epoch, Session: proto.Clone(pair.proof).(*authoritypb.SessionProof), Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}}
		if err := writeFrame(client, 4096, resume); err != nil {
			t.Fatal(err)
		}
		if err := readFrame(client, 4096, nil, 0, &response); err != nil {
			t.Fatalf("%s Resume blocked by saturated DATA: %v", role, err)
		}
		if response.GetResume().GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE {
			t.Fatalf("Resume=%v", &response)
		}
		_ = client.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestControlBulkIsRejectedBeforeAllocation(t *testing.T) {
	var header [frameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[:4], 1)
	binary.BigEndian.PutUint32(header[4:], 1<<20)
	budget := newFrameBudget(0, 0)
	_, _, err := readFrameWithContext(t.Context(), bytes.NewReader(header[:]), 2<<20, budget, time.Second, new(authoritypb.Request), true, true, false)
	if !errors.Is(err, ErrFramePayload) {
		t.Fatalf("CONTROL bulk refusal=%v", err)
	}
}

func TestFrameBudgetAcquisitionUsesCancellationAndAllocationClass(t *testing.T) {
	for _, size := range []int{4096, framePoolGranularity + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			request := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Size: uint32(size), Data: make([]byte, size)}}}
			var wire bytes.Buffer
			if err := writeFrame(&wire, 1<<20, request); err != nil {
				t.Fatal(err)
			}
			total := uint32(wire.Len() - frameHeaderBytes)
			allocated := frameAllocationBytes(total)
			budget := newFrameBudget(uint64(allocated), 0)
			release, _, err := readFrameWithContext(t.Context(), bytes.NewReader(wire.Bytes()), 1<<20, budget, time.Second, new(authoritypb.Request), true, true, true)
			if err != nil {
				t.Fatal(err)
			}
			if budget.available != 0 {
				t.Fatalf("pool allocation charged %d, actual %d", total, allocated)
			}
			release()
			if budget.available != uint64(allocated) {
				t.Fatal("allocation leaked")
			}
			if err := budget.acquire(t.Context(), allocated, time.Second, true); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			_, _, err = readFrameWithContext(ctx, bytes.NewReader(wire.Bytes()), 1<<20, budget, time.Second, new(authoritypb.Request), true, true, true)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled budget acquire=%v", err)
			}
		})
	}
}

func TestInboundBudgetRequiresDataAndFixedControlReserve(t *testing.T) {
	for _, test := range []struct {
		frame uint32
		want  uint64
	}{
		{1, 1}, {4096, 4096}, {framePoolGranularity + 1, 2 * framePoolGranularity}, {1 << 20, 1 << 20},
	} {
		if got := MinimumFrameBytesInFlight(test.frame); got != test.want+12<<20 {
			t.Fatalf("frame %d minimum=%d want %d", test.frame, got, test.want+12<<20)
		}
	}
	server := &Server{Handler: echoHandler{}, MaxFrame: 4096, MaxInFlight: 9, MaxConnections: 4, MaxFrameBytesInFlight: MinimumFrameBytesInFlight(4096) - 1, HandshakeTimeout: time.Second, IdleTimeout: time.Second, WriteTimeout: time.Second}
	if _, err := server.validate(); err == nil {
		t.Fatal("accepted total without DATA and reserve capacity")
	}
	server.MaxFrameBytesInFlight++
	if _, err := server.validate(); err != nil {
		t.Fatal(err)
	}
	server.MaxConnections = 4096
	if _, err := server.validate(); err != nil {
		t.Fatalf("connection count changed the frame floor: %v", err)
	}
}

func TestSharedBudgetControlCanUseAnyAvailableBytes(t *testing.T) {
	budget := newFrameBudget(controlFrameReserve()+4096, controlFrameReserve())
	if err := budget.acquire(t.Context(), 4096, time.Second, true); err != nil {
		t.Fatal(err)
	}
	for range reservedControlFrames {
		if err := budget.acquire(t.Context(), frameAllocationBytes(maxControlFrameBytes), time.Second, false); err != nil {
			t.Fatal(err)
		}
	}
	if budget.available != 0 {
		t.Fatalf("CONTROL did not consume the shared reserve: %d", budget.available)
	}
	if err := budget.acquire(t.Context(), 1, 10*time.Millisecond, false); !errors.Is(err, ErrFrameBudget) {
		t.Fatalf("CONTROL exceeded worker total: %v", err)
	}
	budget.release(uint32(controlFrameReserve()))
	budget.release(4096)
	if err := budget.acquire(t.Context(), uint32(budget.available), time.Second, false); err != nil {
		t.Fatalf("CONTROL could not borrow unused DATA capacity: %v", err)
	}
}

func TestControlAndBootstrapOversizeRefusedBeforeReservation(t *testing.T) {
	for _, hello := range []bool{false, true} {
		t.Run(map[bool]string{false: "CONTROL", true: "bootstrap Hello"}[hello], func(t *testing.T) {
			var header [frameHeaderBytes]byte
			binary.BigEndian.PutUint32(header[:4], maxControlFrameBytes+1)
			// There is no body and no budget. A reader that reserves or reads
			// payload before enforcing the cap returns another error.
			budget := newFrameBudget(0, 0)
			var err error
			if hello {
				server := &Server{HandshakeTimeout: time.Second, WriteTimeout: time.Second}
				client, peer := net.Pipe()
				defer client.Close()
				defer peer.Close()
				go func() { _, _ = client.Write(header[:]) }()
				server.budget = budget
				_, _, err = server.acceptTransportHello(t.Context(), func() {}, peer, TransportBounds{MaxRequestFrame: 1 << 20}, [32]byte{1})
			} else {
				_, _, err = readRequestFrameRetained(t.Context(), bytes.NewReader(header[:]), 1<<20, budget, time.Second, new(authoritypb.Request), false)
			}
			if !errors.Is(err, ErrFrameBounds) {
				t.Fatalf("oversized frame = %v", err)
			}
			if budget.available != 0 {
				t.Fatal("oversized frame changed budget")
			}
		})
	}
}

func TestControlCapAccommodatesLargestDelegationRelease(t *testing.T) {
	req := &authoritypb.Request{RequestId: ^uint64(0), Epoch: make([]byte, 16), Session: &authoritypb.SessionProof{Id: make([]byte, 16), Generation: ^uint64(0), ResumeSecret: make([]byte, 32)}, Body: &authoritypb.Request_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseRequest{Incarnation: ^uint64(0), ReleaseSequence: ^uint64(0), CompletedReleaseThrough: ^uint64(0)}}}
	for i := range maxWireRepeatedElements {
		id := make([]byte, 16)
		binary.BigEndian.PutUint64(id[8:], uint64(i+1))
		req.GetDelegationRelease().Delegations = append(req.GetDelegationRelease().Delegations, &authoritypb.DelegationRelease{Delegation: &authoritypb.DelegationRef{Id: id, Generation: ^uint64(0)}, AppliedSequence: ^uint64(0)})
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, maxControlFrameBytes, req); err != nil {
		t.Fatal(err)
	}
	budget := newFrameBudget(uint64(maxControlFrameBytes), 0)
	release, _, err := readRequestFrameRetained(t.Context(), &frame, 1<<20, budget, time.Second, new(authoritypb.Request), false)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if budget.available == uint64(maxControlFrameBytes) {
		t.Fatal("CONTROL released its reservation before execution")
	}
	release()
	if budget.available != uint64(maxControlFrameBytes) {
		t.Fatal("CONTROL leaked its reservation")
	}
}

type disconnectBootstrapHandler struct {
	echoHandler
	entered, canceled chan struct{}
	blockAttach       bool
}

func (h disconnectBootstrapHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	if req.GetAttach() != nil && h.blockAttach || req.GetResume() != nil {
		close(h.entered)
		<-ctx.Done()
		close(h.canceled)
		return &authoritypb.Response{RequestId: req.GetRequestId()}
	}
	return h.echoHandler.Handle(ctx, req)
}

func TestBootstrapDisconnectCancelsAttachAndResume(t *testing.T) {
	for _, attach := range []bool{false, true} {
		t.Run(map[bool]string{false: "Resume", true: "Attach"}[attach], func(t *testing.T) {
			handler := disconnectBootstrapHandler{echoHandler: echoHandler{epoch: []byte("epoch")}, entered: make(chan struct{}), canceled: make(chan struct{}), blockAttach: attach}
			server := &Server{Handler: handler, MaxFrame: 4096, MaxInFlight: 9, MaxConnections: 4, MaxFrameBytesInFlight: controlFrameReserve() + 1<<20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
			var proof *authoritypb.SessionProof
			setID := make([]byte, 32)
			setID[0] = 7
			if !attach {
				pair := startActiveTestPair(t, server)
				defer pair.close(t)
				proof = pair.proof
			} else {
				client, peer := net.Pipe()
				done := testServeSession(t, server, peer)
				defer func() { _ = client.Close(); <-done }()
				if err := writeFrame(client, 4096, &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor, Role: authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, ConnectionSetId: setID}}}); err != nil {
					t.Fatal(err)
				}
				var response authoritypb.Response
				if err := readFrame(client, 4096, nil, 0, &response); err != nil {
					t.Fatal(err)
				}
			}
			client, peer := net.Pipe()
			done := testServeSession(t, server, peer)
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			hello := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor, Role: authoritypb.TransportRole_TRANSPORT_ROLE_DATA, ConnectionSetId: setID}}}
			if err := writeFrame(client, 4096, hello); err != nil {
				t.Fatal(err)
			}
			var response authoritypb.Response
			if err := readFrame(client, 4096, nil, 0, &response); err != nil {
				t.Fatal(err)
			}
			req := &authoritypb.Request{RequestId: 2, Epoch: []byte("epoch"), Session: proof, Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}}
			if attach {
				req.Epoch = nil
				req.Session = nil
				req.Body = &authoritypb.Request_Attach{Attach: &authoritypb.AttachRequest{AttachAttemptId: bytes.Repeat([]byte{4}, 32)}}
			}
			if err := writeFrame(client, 4096, req); err != nil {
				t.Fatal(err)
			}
			select {
			case <-handler.entered:
			case <-time.After(time.Second):
				t.Fatal("bootstrap handler did not enter")
			}
			_ = client.Close()
			select {
			case <-handler.canceled:
			case <-time.After(time.Second):
				t.Fatal("disconnect did not cancel bootstrap")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("session did not exit")
			}
		})
	}
}

func TestTrickledBootstrapFramesLeaveSharedCapacityForReconnect(t *testing.T) {
	server := &Server{Handler: echoHandler{epoch: []byte("epoch")}, MaxFrame: 4096, MaxInFlight: 9, MaxConnections: 8, MaxFrameBytesInFlight: controlFrameReserve() + 1<<20, HandshakeTimeout: time.Minute, IdleTimeout: time.Minute, WriteTimeout: time.Second}
	var header [frameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[:4], 4096)
	for range 4 {
		client, peer := net.Pipe()
		done := testServeSession(t, server, peer)
		t.Cleanup(func() { _ = client.Close(); <-done })
		if err := client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		// Hold one maximum-sized bootstrap allocation without sending a body.
		if _, err := client.Write(header[:]); err != nil {
			t.Fatal(err)
		}
	}
	client, peer := net.Pipe()
	done := testServeSession(t, server, peer)
	defer func() { _ = client.Close(); <-done }()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	hello := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor, Role: authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, ConnectionSetId: bytes.Repeat([]byte{7}, 32)}}}
	if err := writeFrame(client, 4096, hello); err != nil {
		t.Fatal(err)
	}
	var response authoritypb.Response
	if err := readFrame(client, 4096, nil, 0, &response); err != nil {
		t.Fatalf("reconnect Hello starved by other connections: %v", err)
	}
	if response.GetHello() == nil {
		t.Fatalf("Hello = %v", &response)
	}
}
