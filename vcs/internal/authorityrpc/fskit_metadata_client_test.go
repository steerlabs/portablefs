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

// fskitProofTestHandler is a negotiated FSKit authority whose KeepAlive proof
// and per-request extras are controlled by the test.
type fskitProofTestHandler struct {
	fskitFeatureTestHandler
	mu           *sync.Mutex
	proof        *uint64
	readProof    *uint64 // stamped on a non-KeepAlive reply
	failProof    *bool   // stamp the proof on a refused KeepAlive
	helloOffered *atomic.Value
	dropEcho     *atomic.Bool // stop echoing the metadata feature in Hello
	reauthorized int64
}

func newFskitProofTestHandler() fskitProofTestHandler {
	proof, readProof, failProof := new(uint64), new(uint64), new(bool)
	offered := &atomic.Value{}
	offered.Store([]string(nil))
	return fskitProofTestHandler{
		fskitFeatureTestHandler: fskitFeatureTestHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 4}},
		mu:                      &sync.Mutex{}, proof: proof, readProof: readProof, failProof: failProof, helloOffered: offered,
		dropEcho: &atomic.Bool{},
	}
}

func (h fskitProofTestHandler) set(proof, readProof uint64, failProof bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.proof, *h.readProof, *h.failProof = proof, readProof, failProof
}

func (h fskitProofTestHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	h.mu.Lock()
	proof, readProof, failProof := *h.proof, *h.readProof, *h.failProof
	h.mu.Unlock()
	switch req.GetBody().(type) {
	case *authoritypb.Request_Hello:
		h.helloOffered.Store(append([]string(nil), req.GetHello().GetFeatures()...))
	case *authoritypb.Request_KeepAlive:
		response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), SessionValidForNanos: proof}
		if failProof {
			response.Errno = 5
		}
		return response
	case *authoritypb.Request_Reauthorize:
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), Body: &authoritypb.Response_Reauthorize{
			Reauthorize: &authoritypb.ReauthorizeReply{Sequence: req.GetReauthorize().GetSequence(), AuthorizationDeadlineUnixNanos: h.reauthorized},
		}}
	case *authoritypb.Request_GetAttr:
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch(), SessionValidForNanos: readProof,
			Body: &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: testAuthorityRoot().GetAttr()}}}
	}
	response := h.fskitFeatureTestHandler.Handle(ctx, req)
	if hello := response.GetHello(); hello != nil && h.dropEcho.Load() {
		hello.Features = slices.DeleteFunc(hello.Features, func(feature string) bool { return feature == fskitVersionedMetadataFeature })
	}
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

// A negotiated KeepAlive must carry a positive whole-millisecond proof within
// both the advertised lease and MaxCacheProof. An overgrant is a protocol
// defect that ends the session; it is never clamped.
func TestFskitKeepAliveValidatesTheSessionProof(t *testing.T) {
	const lease = 30 * time.Second // clientTestHandler's advertised lease
	for _, test := range []struct {
		name  string
		proof uint64
		valid bool
	}{
		{name: "lease", proof: uint64(lease), valid: true},
		{name: "one-millisecond", proof: uint64(time.Millisecond), valid: true},
		{name: "zero", proof: 0},
		{name: "sub-millisecond", proof: uint64(lease) - 1},
		{name: "beyond-lease", proof: uint64(lease + time.Millisecond)},
		{name: "beyond-max-cache-proof", proof: uint64(MaxCacheProof + time.Millisecond)},
		{name: "overflow", proof: ^uint64(0) &^ (uint64(time.Millisecond) - 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := newFskitProofTestHandler()
			handler.set(test.proof, 0, false)
			client, err := dialFskitProofTestClient(t, handler, nil)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := client.KeepAlive(t.Context())
			if test.valid {
				if err != nil || proof != time.Duration(test.proof) {
					t.Fatalf("keepalive = (%s,%v), want %s", proof, err, time.Duration(test.proof))
				}
				if !client.LocalAdmissionOpen() {
					t.Fatal("a valid proof closed admission")
				}
				return
			}
			if err == nil || proof != 0 {
				t.Fatalf("keepalive with proof %d = (%s,%v), want a protocol refusal", test.proof, proof, err)
			}
			if client.LocalAdmissionOpen() {
				t.Fatal("a malformed negotiated proof left the session admitting requests")
			}
		})
	}
}

// The authority caps every proof at MaxCacheProof even under a longer lease;
// the client enforces the same frozen ceiling.
func TestFskitKeepAliveRefusesAProofBeyondMaxCacheProofUnderALongLease(t *testing.T) {
	handler := newFskitProofTestHandler()
	handler.set(uint64(MaxCacheProof+time.Second), 0, false)
	client, err := dialFskitProofTestClient(t, longLeaseHandler{handler}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lease := client.SessionLease(); lease <= MaxCacheProof+time.Second {
		t.Fatalf("lease = %s, want longer than the proof", lease)
	}
	if _, err := client.KeepAlive(t.Context()); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("keepalive beyond MaxCacheProof = %v, want a protocol refusal", err)
	}
}

type longLeaseHandler struct{ fskitProofTestHandler }

func (h longLeaseHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := h.fskitProofTestHandler.Handle(ctx, req)
	if active := response.GetActivate(); active != nil {
		active.SessionLeaseMilliseconds = uint64((10 * time.Minute) / time.Millisecond)
	}
	return response
}

// The proof field is admitted only on a successful negotiated KeepAlive: on
// any other reply, or on a refused renewal, it is a terminal defect.
func TestFskitSessionProofOutsideASuccessfulKeepAliveIsRefused(t *testing.T) {
	t.Run("ordinary-read", func(t *testing.T) {
		handler := newFskitProofTestHandler()
		handler.set(uint64(time.Second), uint64(time.Second), false)
		client, err := dialFskitProofTestClient(t, handler, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.CallRead(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: make([]byte, 16)}}})
		if !errors.Is(err, ErrTransportBinding) || client.LocalAdmissionOpen() {
			t.Fatalf("proof on GetAttr = %v admission=%t, want terminal refusal", err, client.LocalAdmissionOpen())
		}
	})
	t.Run("refused-keepalive", func(t *testing.T) {
		handler := newFskitProofTestHandler()
		handler.set(uint64(time.Second), 0, true)
		client, err := dialFskitProofTestClient(t, handler, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.KeepAlive(t.Context()); !errors.Is(err, ErrTransportBinding) || client.LocalAdmissionOpen() {
			t.Fatalf("proof on refused keepalive = %v, want terminal refusal", err)
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

// Same-session transport recovery must renegotiate the identical contract: a
// resumed transport whose Hello no longer echoes the metadata feature is
// refused instead of silently continuing without it.
func TestFskitTransportRecoveryRefusesAChangedMetadataContract(t *testing.T) {
	handler := newFskitProofTestHandler()
	client, err := dialFskitProofTestClient(t, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.dropEcho.Store(true)
	client.data.pendingMu.Lock()
	old := client.data.conn
	client.data.pendingMu.Unlock()
	client.failConnection(client.data, old, ErrTransportUncertain)
	_, err = client.CallRead(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: make([]byte, 16)}}})
	if err == nil || !strings.Contains(err.Error(), fskitVersionedMetadataFeature) {
		t.Fatalf("recovery with a changed contract = %v, want a refusal naming the feature", err)
	}
}
