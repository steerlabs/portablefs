package authorityrpc

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// fskitProofTestHandler is an FSKit authority whose KeepAlive reply
// and per-request extras are controlled by the test.
type fskitProofTestHandler struct {
	fskitProfileTestHandler
	mu           *sync.Mutex
	proof        *uint64
	keepAlive    *func(*authoritypb.Response) // adjusts the KeepAlive reply
	ackProof     *uint64                      // stamped on a bodyless resource acknowledgement
	reauthorized int64
}

func newFskitProofTestHandler() fskitProofTestHandler {
	return fskitProofTestHandler{
		fskitProfileTestHandler: fskitProfileTestHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}},
		mu:                      &sync.Mutex{}, proof: new(uint64), keepAlive: new(func(*authoritypb.Response)), ackProof: new(uint64),
	}
}

func (h fskitProofTestHandler) set(proof uint64, keepAlive func(*authoritypb.Response), ackProof uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.proof, *h.keepAlive, *h.ackProof = proof, keepAlive, ackProof
}

func (h fskitProofTestHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	h.mu.Lock()
	proof, keepAlive, ackProof := *h.proof, *h.keepAlive, *h.ackProof
	h.mu.Unlock()
	switch req.GetBody().(type) {
	case *authoritypb.Request_KeepAlive:
		response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), SessionValidForNanos: proof}
		if keepAlive != nil {
			keepAlive(response)
		}
		return response
	case *authoritypb.Request_Reclaim:
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), SessionValidForNanos: ackProof}
	case *authoritypb.Request_Reauthorize:
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), Body: &authoritypb.Response_Reauthorize{
			Reauthorize: &authoritypb.ReauthorizeReply{Sequence: req.GetReauthorize().GetSequence(), AuthorizationDeadlineUnixNanos: h.reauthorized},
		}}
	}
	response := h.fskitProfileTestHandler.Handle(ctx, req)
	return response
}

func dialFskitProofTestClient(t *testing.T, handler Handler, configure func(*ClientConfig)) (*Client, error) {
	t.Helper()
	address, tls, stop := startTestServer(t, handler, 9, time.Minute)
	t.Cleanup(stop)
	cfg := coherentTestClientConfig(address, tls, "fskit", 9, 9)
	cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE
	if configure != nil {
		configure(&cfg)
	}
	client, err := DialClient(t.Context(), cfg)
	if err == nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err
}

// The client owns the session-dependent half of the proof: present and
// positive on every successful FSKit renewal, and never beyond the
// advertised lease. An overgrant ends the session; it is never clamped. The
// proof's own grammar (whole milliseconds, at most MaxCacheProof, plain success
// envelope) is the frame layer's and is covered by
// TestKeepAliveProofCanonicalFrame.
func TestFskitKeepAliveValidatesTheSessionProof(t *testing.T) {
	const lease = 30 * time.Second // clientTestHandler's advertised lease
	for _, test := range []struct {
		name  string
		proof uint64
		valid bool
	}{
		{name: "lease", proof: uint64(lease), valid: true},
		{name: "one-millisecond", proof: uint64(time.Millisecond), valid: true},
		{name: "missing", proof: 0},
		{name: "beyond-lease", proof: uint64(lease + time.Millisecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := newFskitProofTestHandler()
			handler.set(test.proof, nil, 0)
			client, err := dialFskitProofTestClient(t, handler, nil)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := client.KeepAlive(t.Context())
			if test.valid {
				if err != nil || proof != time.Duration(test.proof) || !client.LocalAdmissionOpen() {
					t.Fatalf("keepalive = (%s,%v) admission=%t, want %s", proof, err, client.LocalAdmissionOpen(), time.Duration(test.proof))
				}
				return
			}
			if !errors.Is(err, ErrTransportBinding) || proof != 0 || client.LocalAdmissionOpen() {
				t.Fatalf("keepalive with proof %d = (%s,%v) admission=%t, want a terminal refusal", test.proof, proof, err, client.LocalAdmissionOpen())
			}
		})
	}
}

// Only the complete KeepAlive success shape renews. Inject contradictory peer
// replies as raw bytes so egress validation cannot hide an ingress defect.
func TestKeepAliveRequiresTheCompleteSuccessShape(t *testing.T) {
	for _, test := range []struct {
		name   string
		fskit  bool
		mutate func(*authoritypb.Response)
	}{
		{name: "FSKit-with-replay-state", fskit: true, mutate: func(r *authoritypb.Response) {
			r.Mutation = &authoritypb.MutationState{Slot: 1, AcceptedSequence: 1}
		}},
		{name: "FSKit-with-route-record", fskit: true, mutate: func(r *authoritypb.Response) {
			r.RoutesMismatch = &authoritypb.RoutesMismatch{ActiveRevision: make([]byte, 32), PresentedRevision: make([]byte, 32)}
		}},
		{name: "linux-failure-class", mutate: func(r *authoritypb.Response) { r.Failure = authoritypb.FailureClass_FAILURE_CLASS_INTERNAL }},
		{name: "linux-body", mutate: func(r *authoritypb.Response) {
			r.Body = &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{}}
		}},
		{name: "linux-restore-detail", mutate: func(r *authoritypb.Response) { r.RestoreDetail = "restored" }},
		{name: "linux-applied-sequence", mutate: func(r *authoritypb.Response) { r.AppliedSequence = 1 }},
		{name: "linux-visible-sequence", mutate: func(r *authoritypb.Response) { r.VisibleSequence = 1 }},
		{name: "linux-volume-version", mutate: func(r *authoritypb.Response) { r.VolumeVersion = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var client *Client
			var err error
			if test.fskit {
				handler := newFskitProofTestHandler()
				handler.set(uint64(time.Second), nil, 0)
				client, err = dialFskitProofTestClient(t, handler, nil)
			} else {
				client, err = dialLinuxKeepAliveTestClient(t, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			response := &authoritypb.Response{}
			if test.fskit {
				response.SessionValidForNanos = uint64(time.Second)
			}
			test.mutate(response)
			if proof, err := injectKeepAliveReply(t, client, response); err == nil || proof != 0 || client.LocalAdmissionOpen() {
				t.Fatalf("contradicting keepalive = (%s,%v) admission=%t, want a terminal refusal", proof, err, client.LocalAdmissionOpen())
			}
		})
	}
}

// A received frame outside the wire grammar is a proven authority defect, not
// transport loss: it ends the session at once, so no reconnect can replay past
// it, and a later request to the still-healthy authority cannot revive it.
func TestMalformedAuthorityFrameEndsTheSession(t *testing.T) {
	for _, test := range []struct {
		name  string
		proof time.Duration
		bulk  []byte
	}{
		{name: "proof-beyond-max-cache-proof", proof: MaxCacheProof + time.Millisecond},
		{name: "bulk-without-a-carrier", proof: time.Second, bulk: []byte{1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := newFskitProofTestHandler()
			handler.set(uint64(time.Second), nil, 0)
			client, err := dialFskitProofTestClient(t, handler, nil)
			if err != nil {
				t.Fatal(err)
			}
			local, peer := net.Pipe()
			defer peer.Close()
			client.control.pendingMu.Lock()
			old := client.control.conn
			client.control.conn = local
			client.control.pendingMu.Unlock()
			_ = old.Close()
			go client.readLoop(client.control, local)

			type result struct {
				proof time.Duration
				err   error
			}
			done := make(chan result, 1)
			go func() {
				proof, err := client.KeepAlive(t.Context())
				done <- result{proof, err}
			}()
			request := new(authoritypb.Request)
			if err := readFrame(peer, testMaxFrame, nil, 0, request); err != nil {
				t.Fatal(err)
			}
			frame, err := rawResponseFrame(&authoritypb.Response{
				RequestId: request.GetRequestId(), Epoch: client.Epoch(), SessionValidForNanos: uint64(test.proof),
			}, test.bulk)
			if err != nil {
				t.Fatal(err)
			}
			// The client refuses an uncarried bulk before reading it, so the
			// write of those bytes may find the pipe already closed.
			_ = writeAll(peer, frame)
			got := <-done
			if got.err == nil || got.proof != 0 || client.LocalAdmissionOpen() {
				t.Fatalf("malformed keepalive frame = (%s,%v) admission=%t, want a terminal refusal", got.proof, got.err, client.LocalAdmissionOpen())
			}
			select {
			case <-client.SessionDone():
			case <-time.After(5 * time.Second):
				t.Fatal("a malformed authority frame did not end the session")
			}
			if err := client.SessionError(); !errors.Is(err, ErrTransportBinding) {
				t.Fatalf("session error = %v, want a transport binding defect", err)
			}
			if proof, err := client.KeepAlive(t.Context()); err == nil || proof != 0 {
				t.Fatalf("keepalive after the defect = (%s,%v), want the ended session", proof, err)
			}
		})
	}
}

// keepAliveTestHandler is a Linux-profile authority whose KeepAlive reply the
// test adjusts.
type keepAliveTestHandler struct {
	clientTestHandler
	mutate func(*authoritypb.Response)
}

func (h keepAliveTestHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := h.clientTestHandler.Handle(ctx, req)
	if req.GetKeepAlive() != nil && h.mutate != nil {
		h.mutate(response)
	}
	return response
}

func dialLinuxKeepAliveTestClient(t *testing.T, mutate func(*authoritypb.Response)) (*Client, error) {
	t.Helper()
	address, tls, stop := startTestServer(t, keepAliveTestHandler{clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, mutate}, 9, time.Minute)
	t.Cleanup(stop)
	cfg := coherentTestClientConfig(address, tls, "linux", 9, 9)
	cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX
	client, err := DialClient(t.Context(), cfg)
	if err == nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err
}

// The frame layer cannot see the request or the profile: a proof on a
// reply to anything but KeepAlive, or to a session that never FSKit the
// profile, is refused by the client as a terminal defect.
func TestSessionProofRequiresFSKitKeepAlive(t *testing.T) {
	t.Run("non-keepalive-request", func(t *testing.T) {
		handler := newFskitProofTestHandler()
		handler.set(uint64(time.Second), nil, uint64(time.Second))
		client, err := dialFskitProofTestClient(t, handler, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.CallIdempotent(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{make([]byte, 16)}}}})
		if !errors.Is(err, ErrTransportBinding) || client.LocalAdmissionOpen() {
			t.Fatalf("proof on a resource acknowledgement = %v admission=%t, want terminal refusal", err, client.LocalAdmissionOpen())
		}
	})
	t.Run("non-FSKit-session", func(t *testing.T) {
		client, err := dialLinuxKeepAliveTestClient(t, func(r *authoritypb.Response) { r.SessionValidForNanos = uint64(time.Second) })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.KeepAlive(t.Context()); !errors.Is(err, ErrTransportBinding) || client.LocalAdmissionOpen() {
			t.Fatalf("proof to a non-FSKit session = %v, want terminal refusal", err)
		}
	})
}

// Reauthorization installs the replacement deadline for the local denial
// check; the initial accessor keeps describing activation.
func TestReauthorizeInstallsTheCurrentAuthorizationDeadline(t *testing.T) {
	handler := newFskitProofTestHandler()
	handler.mountEnrollment = true
	renewed := time.Now().Add(3 * time.Minute).Truncate(time.Second)
	handler.reauthorized = renewed.UnixNano()
	client, err := dialFskitProofTestClient(t, handler, func(cfg *ClientConfig) {
		cfg.RequireMountEnrollmentReauthorization = true
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := client.InitialAuthorizationDeadline()
	if !client.AuthorizationDeadline().Equal(initial) || initial.IsZero() {
		t.Fatalf("current deadline %s, want the activation deadline %s", client.AuthorizationDeadline(), initial)
	}
	deadline, err := client.Reauthorize(t.Context(), []byte("token"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !deadline.Equal(renewed) || !client.AuthorizationDeadline().Equal(renewed) || !client.InitialAuthorizationDeadline().Equal(initial) {
		t.Fatalf("after reauthorization current=%s initial=%s, want current %s and unchanged initial", client.AuthorizationDeadline(), client.InitialAuthorizationDeadline(), renewed)
	}
}

// A locally served reply is admitted like an authority response: refused once
// the session is poisoned, and holding back the terminal edge until consumed.
func TestLocalPublicationParticipatesInTerminalRevocation(t *testing.T) {
	handler := newFskitProofTestHandler()
	client, err := dialFskitProofTestClient(t, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	var forced atomic.Int32
	receipt, err := client.BeginLocalPublication(func(error) { forced.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	client.signalSessionEnd(ErrSessionEnded)
	if client.LocalAdmissionOpen() {
		t.Fatal("admission stayed open after the terminal edge")
	}
	if _, err := client.BeginLocalPublication(func(error) {}); err == nil {
		t.Fatal("a poisoned session admitted a local publication")
	}
	select {
	case <-client.SessionEndPending():
		t.Fatal("the terminal edge was published before the local reply was consumed")
	case <-time.After(20 * time.Millisecond):
	}
	receipt.Consume()
	select {
	case <-client.SessionEndPending():
	case <-time.After(2 * time.Second):
		t.Fatal("consuming the local reply did not release the terminal edge")
	}
	if forced.Load() != 0 {
		t.Fatal("a consumed local reply was force-revoked")
	}
}

// Swap only the established CONTROL generation, then inject a peer response
// without passing it through the authority's outgoing validation.
func injectKeepAliveReply(t *testing.T, client *Client, response *authoritypb.Response) (time.Duration, error) {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	client.control.pendingMu.Lock()
	old := client.control.conn
	client.control.conn = local
	client.control.pendingMu.Unlock()
	_ = old.Close()
	go client.readLoop(client.control, local)
	done := make(chan error, 1)
	go func() {
		_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
		request := new(authoritypb.Request)
		if err := readFrame(peer, testMaxFrame, nil, 0, request); err != nil {
			done <- err
			return
		}
		response.RequestId, response.Epoch = request.GetRequestId(), client.Epoch()
		frame, err := rawResponseFrame(response, nil)
		if err == nil {
			_, err = peer.Write(frame)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	proof, err := client.KeepAlive(ctx)
	if sendErr := <-done; sendErr != nil {
		t.Fatal(sendErr)
	}
	return proof, err
}

func TestAuthorityEncodingDefectReturnsTerminalRefusal(t *testing.T) {
	handler := newFskitProofTestHandler()
	handler.set(uint64(time.Second), func(response *authoritypb.Response) {
		response.Mutation = &authoritypb.MutationState{Slot: 1, AcceptedSequence: 1}
	}, 0)
	client, err := dialFskitProofTestClient(t, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response, err := client.Call(ctx, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if err != nil || response == nil || response.GetErrno() != int32(syscall.EIO) || !response.GetUncertain() ||
		response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_INTERNAL || response.GetSessionValidForNanos() != 0 ||
		response.GetMutation() != nil || client.LocalAdmissionOpen() {
		t.Fatalf("encoding defect = (%v, %v), admission=%t, want terminal internal refusal", response, err, client.LocalAdmissionOpen())
	}
}
