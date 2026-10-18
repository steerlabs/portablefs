package authorityrpc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// fskitProofTestHandler is a negotiated FSKit authority whose KeepAlive reply
// and per-request extras are controlled by the test.
type fskitProofTestHandler struct {
	fskitFeatureTestHandler
	mu           *sync.Mutex
	proof        *uint64
	keepAlive    *func(*authoritypb.Response) // adjusts the KeepAlive reply
	ackProof     *uint64                      // stamped on a bodyless repair acknowledgement
	helloOffered *atomic.Value
	reauthorized int64
}

func newFskitProofTestHandler() fskitProofTestHandler {
	offered := &atomic.Value{}
	offered.Store([]string(nil))
	return fskitProofTestHandler{
		fskitFeatureTestHandler: fskitFeatureTestHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 4}},
		mu:                      &sync.Mutex{}, proof: new(uint64), keepAlive: new(func(*authoritypb.Response)), ackProof: new(uint64),
		helloOffered: offered,
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
	case *authoritypb.Request_Hello:
		h.helloOffered.Store(append([]string(nil), req.GetHello().GetFeatures()...))
	case *authoritypb.Request_KeepAlive:
		response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), SessionValidForNanos: proof}
		if keepAlive != nil {
			keepAlive(response)
		}
		return response
	case *authoritypb.Request_AckFskitRepair:
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), SessionValidForNanos: ackProof}
	case *authoritypb.Request_Reauthorize:
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), Body: &authoritypb.Response_Reauthorize{
			Reauthorize: &authoritypb.ReauthorizeReply{Sequence: req.GetReauthorize().GetSequence(), AuthorizationDeadlineUnixNanos: h.reauthorized},
		}}
	}
	response := h.fskitFeatureTestHandler.Handle(ctx, req)
	if h.mountEnrollment {
		enrollment := []string{sessionReauthorizationFeature, mountEnrollmentReauthorizationFeature}
		if hello := response.GetHello(); hello != nil {
			hello.Features = append(hello.Features, enrollment...)
		}
		if active := response.GetActivate(); active != nil {
			active.Features = append(active.Features, enrollment...)
		}
	}
	return response
}

func dialFskitProofTestClient(t *testing.T, handler Handler, configure func(*ClientConfig)) (*Client, error) {
	t.Helper()
	address, tls, stop := startTestServer(t, handler, 4, time.Minute)
	t.Cleanup(stop)
	cfg := coherentTestClientConfig(address, tls, "fskit", 4, 4)
	cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR
	cfg.FskitCachedNameCapacity = 16
	cfg.FskitRepairBudget = time.Second
	cfg.FskitNamespaceRepair = authoritypb.NamespaceRepair_NAMESPACE_REPAIR_CALLBACK_SERIALIZED
	if configure != nil {
		configure(&cfg)
	}
	client, err := DialClient(t.Context(), cfg)
	if err == nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err
}

// The FSKit client offers fskit-versioned-metadata-v1 in Hello and requires
// both the Hello echo and the Activate confirmation; a mismatch refuses the
// session before any daemon can serve from a cache.
func TestFskitClientNegotiatesVersionedMetadataInHelloAndActivate(t *testing.T) {
	handler := newFskitProofTestHandler()
	if _, err := dialFskitProofTestClient(t, handler, nil); err != nil {
		t.Fatal(err)
	}
	if offered := handler.helloOffered.Load().([]string); !slices.Contains(offered, fskitVersionedMetadataFeature) {
		t.Fatalf("FSKit Hello offered %v, want %s", offered, fskitVersionedMetadataFeature)
	}

	mismatch := newFskitProofTestHandler()
	mismatch.omitActivate = fskitVersionedMetadataFeature
	if _, err := dialFskitProofTestClient(t, mismatch, nil); err == nil ||
		!strings.Contains(err.Error(), fskitVersionedMetadataFeature) {
		t.Fatalf("Hello/Activate mismatch = %v, want a precise refusal", err)
	}
}

func TestLinuxClientNeverOffersVersionedMetadata(t *testing.T) {
	handler := newFskitProofTestHandler()
	address, tls, stop := startTestServer(t, recordingHelloHandler{clientTestHandler{epoch: make([]byte, 16), maxInFlight: 4}, handler.helloOffered}, 4, time.Minute)
	defer stop()
	cfg := coherentTestClientConfig(address, tls, "linux", 4, 4)
	cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES
	client, err := DialClient(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if offered := handler.helloOffered.Load().([]string); slices.Contains(offered, fskitVersionedMetadataFeature) {
		t.Fatalf("Linux Hello offered %v", offered)
	}
	if proof, err := client.KeepAlive(t.Context()); err != nil || proof != 0 {
		t.Fatalf("Linux keepalive = (%s,%v), want no proof", proof, err)
	}
}

type recordingHelloHandler struct {
	clientTestHandler
	offered *atomic.Value
}

func (h recordingHelloHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	if hello := req.GetHello(); hello != nil {
		h.offered.Store(append([]string(nil), hello.GetFeatures()...))
	}
	return h.clientTestHandler.Handle(ctx, req)
}

// The client owns the session-dependent half of the proof: present and
// positive on every successful negotiated renewal, and never beyond the
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

// Only the complete KeepAlive success shape renews. A reply the frame layer
// admits but that contradicts success (replay state, a route record, or, with
// no proof to trip the frame grammar, a failure class or a body) ends the
// session and never yields a proof.
func TestKeepAliveRequiresTheCompleteSuccessShape(t *testing.T) {
	for _, test := range []struct {
		name   string
		fskit  bool
		mutate func(*authoritypb.Response)
	}{
		{name: "negotiated-with-replay-state", fskit: true, mutate: func(r *authoritypb.Response) {
			r.Mutation = &authoritypb.MutationState{Slot: 1, AcceptedSequence: 1}
		}},
		{name: "negotiated-with-route-record", fskit: true, mutate: func(r *authoritypb.Response) {
			r.RoutesMismatch = &authoritypb.RoutesMismatch{ActiveRevision: make([]byte, 32), PresentedRevision: make([]byte, 32)}
		}},
		{name: "linux-failure-class", mutate: func(r *authoritypb.Response) { r.Failure = authoritypb.FailureClass_FAILURE_CLASS_INTERNAL }},
		{name: "linux-body", mutate: func(r *authoritypb.Response) {
			r.Body = &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var client *Client
			var err error
			if test.fskit {
				handler := newFskitProofTestHandler()
				handler.set(uint64(time.Second), test.mutate, 0)
				client, err = dialFskitProofTestClient(t, handler, nil)
			} else {
				client, err = dialLinuxKeepAliveTestClient(t, test.mutate)
			}
			if err != nil {
				t.Fatal(err)
			}
			if proof, err := client.KeepAlive(t.Context()); err == nil || proof != 0 || client.LocalAdmissionOpen() {
				t.Fatalf("contradicting keepalive = (%s,%v) admission=%t, want a terminal refusal", proof, err, client.LocalAdmissionOpen())
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
	address, tls, stop := startTestServer(t, keepAliveTestHandler{clientTestHandler{epoch: make([]byte, 16), maxInFlight: 4}, mutate}, 4, time.Minute)
	t.Cleanup(stop)
	cfg := coherentTestClientConfig(address, tls, "linux", 4, 4)
	cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES
	client, err := DialClient(t.Context(), cfg)
	if err == nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err
}

// The frame layer cannot see the request or the negotiation: a proof on a
// reply to anything but KeepAlive, or to a session that never negotiated the
// feature, is refused by the client as a terminal defect.
func TestSessionProofOutsideANegotiatedKeepAliveIsRefused(t *testing.T) {
	t.Run("non-keepalive-request", func(t *testing.T) {
		handler := newFskitProofTestHandler()
		handler.set(uint64(time.Second), nil, uint64(time.Second))
		client, err := dialFskitProofTestClient(t, handler, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = client.AckVisibility(t.Context(), &authoritypb.VisibilityCursor{Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE})
		if !errors.Is(err, ErrTransportBinding) || client.LocalAdmissionOpen() {
			t.Fatalf("proof on a repair acknowledgement = %v admission=%t, want terminal refusal", err, client.LocalAdmissionOpen())
		}
	})
	t.Run("non-negotiated-session", func(t *testing.T) {
		client, err := dialLinuxKeepAliveTestClient(t, func(r *authoritypb.Response) { r.SessionValidForNanos = uint64(time.Second) })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.KeepAlive(t.Context()); !errors.Is(err, ErrTransportBinding) || client.LocalAdmissionOpen() {
			t.Fatalf("proof to a non-negotiated session = %v, want terminal refusal", err)
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
