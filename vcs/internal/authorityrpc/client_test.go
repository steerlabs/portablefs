package authorityrpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

const (
	testMaxFrame    uint32 = 4 << 20
	testMaxInFlight int    = 8
)

func testAuthorityRoot() *authoritypb.Item {
	return &authoritypb.Item{
		Token: bytes.Repeat([]byte{0x31}, 16), StableIdentity: bytes.Repeat([]byte{0x42}, 16),
		Attr: &authoritypb.Attr{Kind: authoritypb.Attr_DIRECTORY, Inode: 1},
	}
}

func testBounds(maxInFlight int) TransportBounds {
	return TransportBounds{MaxFrame: testMaxFrame, MaxRequestFrame: (1 << 20) + FramePayloadReserve, MaxInFlight: maxInFlight}
}

type mutationAssignmentHandler struct {
	clientTestHandler
	assigned  <-chan struct{}
	mutations atomic.Int32
	ordered   atomic.Bool
}

func (h *mutationAssignmentHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	if req.GetMutation() != nil {
		h.mutations.Add(1)
		select {
		case <-h.assigned:
			h.ordered.Store(true)
		default:
		}
	}
	return h.clientTestHandler.Handle(ctx, req)
}

func TestMutationIdentityIsPublishedOnceBeforeDispatch(t *testing.T) {
	assignedOnWire := make(chan struct{})
	handler := &mutationAssignmentHandler{
		clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 3},
		assigned:          assignedOnWire,
	}
	address, clientTLS, stop := startTestServer(t, handler, 3, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 3, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 3,
		CoherenceProfile: authoritypb.CoherenceProfile_COHERENCE_PROFILE_UNCACHED,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var first MutationIdentity
	callbackCalls := 0
	_, err = client.CallMutationWithIdentity(context.Background(), &authoritypb.Request{
		Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Name: []byte("one")}},
	}, func(identity MutationIdentity) error {
		callbackCalls++
		first = identity
		close(assignedOnWire)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callbackCalls != 1 || first.Sequence != 1 || !handler.ordered.Load() || handler.mutations.Load() != 1 {
		t.Fatalf("assignment calls=%d identity=%+v ordered=%v mutations=%d",
			callbackCalls, first, handler.ordered.Load(), handler.mutations.Load())
	}

	wantErr := errors.New("local publication ledger refused mutation")
	var refused MutationIdentity
	_, err = client.CallMutationWithIdentity(context.Background(), &authoritypb.Request{
		Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Name: []byte("two")}},
	}, func(identity MutationIdentity) error {
		refused = identity
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("assignment refusal = %v, want %v", err, wantErr)
	}
	if handler.mutations.Load() != 1 {
		t.Fatal("a mutation reached the authority after its assignment callback refused it")
	}

	if refused.Slot < client.ordinary.base || refused.Slot >= client.ordinary.base+uint32(len(client.ordinary.slots)) {
		t.Fatalf("refused identity names slot %d outside the ordinary lane", refused.Slot)
	}
	slot := &client.ordinary.slots[refused.Slot-client.ordinary.base]
	slot.mu.Lock()
	recorded := slot.sequence
	slot.mu.Unlock()
	if recorded != 0 {
		t.Fatalf("assignment refusal advanced slot %d to sequence %d", refused.Slot, recorded)
	}
}

type clientTestHandler struct {
	epoch             []byte
	started           chan struct{}
	once              *sync.Once
	omitHelloFeature  bool
	omitAttachFeature bool
	keepAliveErrno    int32
	maxInFlight       int
}

func (h clientTestHandler) Epoch() []byte { return append([]byte(nil), h.epoch...) }

func (h clientTestHandler) Bounds() TransportBounds { return testBounds(h.maxInFlight) }

func (h clientTestHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch()}
	switch req.GetBody().(type) {
	case *authoritypb.Request_Hello:
		features := append([]string(nil), requiredHelloFeatures...)
		if h.omitHelloFeature {
			features = features[1:]
		}
		bounds := h.Bounds()
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{ProtocolMajor: ProtocolMajor, Features: features, MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxInFlight: uint32(bounds.MaxInFlight)}}
	case *authoritypb.Request_Attach:
		features := append([]string(nil), requiredAttachFeatures...)
		if h.omitAttachFeature {
			features = features[1:]
		}
		if req.GetAttach().GetCoherenceProfile() == authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT {
			features = append(features, "strict-two-phase-visibility")
		}
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{SessionId: make([]byte, 16), SessionGeneration: 1, ResumeSecret: make([]byte, 32), Root: testAuthorityRoot(), Features: features, SessionLeaseMilliseconds: 30_000}}
	case *authoritypb.Request_Resume:
	case *authoritypb.Request_KeepAlive:
		response.Errno = h.keepAliveErrno
	case *authoritypb.Request_Cancel:
	case *authoritypb.Request_StatFs:
		if h.started != nil {
			h.once.Do(func() { close(h.started) })
		}
		<-ctx.Done()
		response.Errno = 4
	default:
		if req.GetMutation() != nil {
			// Acknowledge the replay identity exactly as submitted; the client
			// synchronizes its slot to whatever the authority reports.
			response.Mutation = &authoritypb.MutationState{Slot: req.GetMutation().GetSlot(), AcceptedSequence: req.GetMutation().GetSequence()}
			return response
		}
		response.Errno = 95
	}
	return response
}

func TestStrictClientReservesAnIndependentVisibilityLane(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), maxInFlight: 5}, 5, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 4096, RepairBudget: 2 * time.Second,
		NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if cap(client.ordinary.permits) != 1 || cap(client.visibility.permits) != 1 || cap(client.liveness.permits) != 1 || cap(client.blocking.permits) != 2 {
		t.Fatalf("strict lanes ordinary/visibility/liveness/blocking = %d/%d/%d/%d, want 1/1/1/2",
			cap(client.ordinary.permits), cap(client.visibility.permits), cap(client.liveness.permits), cap(client.blocking.permits))
	}
	next := &authoritypb.Request{Body: &authoritypb.Request_NextVisibility{NextVisibility: &authoritypb.NextVisibilityRequest{}}}
	ack := &authoritypb.Request{Body: &authoritypb.Request_AckVisibility{AckVisibility: &authoritypb.AckVisibilityRequest{}}}
	if client.laneFor(next) != &client.visibility || client.laneFor(ack) != &client.visibility {
		t.Fatal("visibility control calls did not use the reserved lane")
	}
	keepalive := &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}}
	if client.laneFor(keepalive) != &client.liveness {
		t.Fatal("keepalive did not use the strict liveness lane")
	}
}

// strictContractHandler records exactly what a strict mount put on the wire.
type strictContractHandler struct {
	epoch       []byte
	maxInFlight int
	mu          sync.Mutex
	attach      *authoritypb.AttachRequest
	detach      *authoritypb.DetachRequest
}

func (h *strictContractHandler) Epoch() []byte { return append([]byte(nil), h.epoch...) }

func (h *strictContractHandler) Bounds() TransportBounds { return testBounds(h.maxInFlight) }

func (h *strictContractHandler) Handle(_ context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch()}
	switch {
	case req.GetHello() != nil:
		bounds := h.Bounds()
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{
			ProtocolMajor: ProtocolMajor, Features: append([]string(nil), requiredHelloFeatures...),
			MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxInFlight: uint32(bounds.MaxInFlight),
		}}
	case req.GetAttach() != nil:
		h.mu.Lock()
		h.attach = req.GetAttach()
		h.mu.Unlock()
		features := append([]string(nil), requiredAttachFeatures...)
		features = append(features, "strict-two-phase-visibility")
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: make([]byte, 16), SessionGeneration: 1, ResumeSecret: make([]byte, 32),
			Root: testAuthorityRoot(), Features: features, SessionLeaseMilliseconds: 30_000,
		}}
	case req.GetDetach() != nil:
		h.mu.Lock()
		h.detach = req.GetDetach()
		h.mu.Unlock()
	default:
		response.Errno = 95
	}
	return response
}

func (h *strictContractHandler) recordedDetach() *authoritypb.DetachRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.detach
}

// A strict mount has to state the two numbers the authority reasons from. It
// cannot be given defaults here: the authority sizes its resolved-name index
// from one and fences this mount on the other, and it can check neither.
func TestStrictClientMustDeclareItsCacheContract(t *testing.T) {
	handler := &strictContractHandler{epoch: bytes.Repeat([]byte{0x42}, 16), maxInFlight: 5}
	address, clientTLS, stop := startTestServer(t, handler, 5, time.Minute)
	defer stop()
	base := ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 4096, RepairBudget: 2 * time.Second,
		NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE,
	}
	for _, missing := range []ClientConfig{
		func() ClientConfig { c := base; c.CachedNameCapacity = 0; return c }(),
		func() ClientConfig { c := base; c.RepairBudget = 0; return c }(),
		// The third is how this mount's kernel makes a cached binding
		// unservable. Without it the authority cannot tell a mount that
		// provably cannot repair from one that is merely slow, so it has to be
		// stated too.
		func() ClientConfig {
			c := base
			c.NamespaceRepair = authoritypb.NamespaceRepair_NAMESPACE_REPAIR_UNSPECIFIED
			return c
		}(),
	} {
		if _, err := DialClient(context.Background(), missing); err == nil {
			t.Fatal("a strict mount dialled without declaring its cache contract")
		}
	}

	client, err := DialClient(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	epoch := client.Epoch()
	if !bytes.Equal(epoch, handler.epoch) {
		t.Fatalf("client epoch = %x, want %x", epoch, handler.epoch)
	}
	epoch[0] ^= 0xff
	if bytes.Equal(client.Epoch(), epoch) {
		t.Fatal("Epoch exposed mutable client session state")
	}
	handler.mu.Lock()
	attach := handler.attach
	handler.mu.Unlock()
	if attach.GetCachedNameCapacity() != 4096 || attach.GetRepairBudgetMillis() != 2000 {
		t.Fatalf("attach carried capacity %d budget %dms, want 4096 and 2000",
			attach.GetCachedNameCapacity(), attach.GetRepairBudgetMillis())
	}
	if attach.GetNamespaceRepair() != authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE {
		t.Fatalf("attach carried namespace repair %v, want PARENT_EXCLUSIVE", attach.GetNamespaceRepair())
	}
	// Every profile declares the topology it runs, so the authority can refuse
	// a mount that would hide a subtree from its peers.
	if len(attach.GetRoutesRevision()) != 32 {
		t.Fatalf("attach carried a %d-byte routing revision, want 32", len(attach.GetRoutesRevision()))
	}
}

// The client cannot manufacture the evidence a clean detach needs. It used to
// set an unconditional boolean, which meant a mount that could not repair its
// cache could still leave the barrier just by asking.
func TestStrictDetachRequiresSuppliedEvidence(t *testing.T) {
	handler := &strictContractHandler{epoch: make([]byte, 16), maxInFlight: 5}
	address, clientTLS, stop := startTestServer(t, handler, 5, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 4096, RepairBudget: 2 * time.Second,
		NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	empty := []*authoritypb.MountAbsenceProof{
		nil,
		{},
		{ObservedUnixNanos: time.Now().UnixNano(), Component: "observer"},
		{ObservedUnixNanos: time.Now().UnixNano(), Observation: []byte("fsid")},
		{Observation: []byte("fsid"), Component: "observer"},
	}
	for i, proof := range empty {
		if err := client.DetachAfterUnmount(context.Background(), proof); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("case %d: detach without evidence = %v, want EPERM", i, err)
		}
		if handler.recordedDetach() != nil {
			t.Fatalf("case %d: an evidence-free detach reached the authority", i)
		}
	}

	proof := &authoritypb.MountAbsenceProof{
		ObservedUnixNanos: time.Now().UnixNano(),
		Observation:       []byte("fsid=0x2f1a mount-table-generation=41"),
		Component:         "test-mount-observer",
	}
	if err := client.DetachAfterUnmount(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	sent := handler.recordedDetach()
	if sent == nil || sent.GetMountAbsence().GetComponent() != proof.GetComponent() ||
		string(sent.GetMountAbsence().GetObservation()) != string(proof.GetObservation()) ||
		sent.GetMountAbsence().GetObservedUnixNanos() != proof.GetObservedUnixNanos() {
		t.Fatalf("detach carried %+v, want the supplied observation", sent.GetMountAbsence())
	}
}

func startTestServer(t *testing.T, handler Handler, maxInFlight int, idle time.Duration) (string, *tls.Config, func()) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		Handler: handler, MaxFrame: testMaxFrame, MaxInFlight: maxInFlight, MaxConnections: 8,
		MaxFrameBytesInFlight: 8 << 20, HandshakeTimeout: time.Second, IdleTimeout: idle, WriteTimeout: time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener, serverTLS) }()
	return listener.Addr().String(), clientTLS, func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("authority server: %v", err)
		}
	}
}

func TestClientSignalsTerminalSessionOnExpiredKeepAlive(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), keepAliveErrno: int32(syscall.ESTALE), maxInFlight: testMaxInFlight}, testMaxInFlight, time.Minute)
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 4, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if err != nil || response.GetErrno() != int32(syscall.ESTALE) {
		t.Fatalf("KeepAlive = %v, %v", response, err)
	}
	select {
	case <-client.SessionDone():
		if !errors.Is(client.SessionError(), ErrSessionEnded) {
			t.Fatalf("SessionError = %v", client.SessionError())
		}
	case <-time.After(time.Second):
		t.Fatal("terminal session signal was not delivered")
	}
	_ = client.Close()
	stop()
}

func TestIdleConnectionClosureSignalsTerminalSession(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), maxInFlight: testMaxInFlight}, testMaxInFlight, 50*time.Millisecond)
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 4, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.SessionDone():
		if !errors.Is(client.SessionError(), ErrTransportUncertain) {
			t.Fatalf("SessionError = %v", client.SessionError())
		}
	case <-time.After(time.Second):
		t.Fatal("idle connection death was not signaled")
	}
	_ = client.Close()
	stop()
}

func TestClientRequiresArchitectureFeatures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler clientTestHandler
	}{
		{name: "hello", handler: clientTestHandler{epoch: make([]byte, 16), omitHelloFeature: true, maxInFlight: testMaxInFlight}},
		{name: "attach", handler: clientTestHandler{epoch: make([]byte, 16), omitAttachFeature: true, maxInFlight: testMaxInFlight}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, clientTLS, stop := startTestServer(t, tc.handler, testMaxInFlight, time.Minute)
			_, err := DialClient(context.Background(), ClientConfig{Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"), ReplaySlots: 4, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 4})
			if err == nil {
				t.Fatal("DialClient accepted an authority missing a required feature")
			}
			stop()
		})
	}
}

func TestClientCancellationDrainsAuthorityOutcome(t *testing.T) {
	started := make(chan struct{})
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), started: started, once: new(sync.Once), maxInFlight: 2}, 2, time.Minute)
	client, err := DialClient(context.Background(), ClientConfig{Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"), ReplaySlots: 2, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 2})
	if err != nil {
		t.Fatal(err)
	}
	callCtx, cancel := context.WithCancel(context.Background())
	result := make(chan callResult, 1)
	go func() {
		response, err := client.CallRead(callCtx, &authoritypb.Request{Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}}})
		result <- callResult{response: response, err: err}
	}()
	<-started
	cancel()
	select {
	case outcome := <-result:
		if outcome.err != nil || outcome.response.GetErrno() != 4 {
			t.Fatalf("canceled call = (%v, %v), want exact EINTR response", outcome.response, outcome.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled call did not drain")
	}
	_ = client.Close()
	stop()
}

func TestTLSClientAttachAndMultiplexedCall(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), maxInFlight: testMaxInFlight}, testMaxInFlight, time.Minute)
	client, err := DialClient(context.Background(), ClientConfig{Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"), ReplaySlots: 4, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 4})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Call(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if err != nil || response.GetErrno() != 0 || response.GetRequestId() == 0 {
		t.Fatalf("Call = %v, %v", response, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	stop()
}

func TestConcurrentCallsReconnectWhenConnectionIsTransientlyMissing(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), maxInFlight: testMaxInFlight}, testMaxInFlight, time.Minute)
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 4, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Model a transport break that had an in-flight caller. It is recoverable in
	// the same epoch, unlike an idle break, and leaves a short conn==nil window.
	client.pendingMu.Lock()
	oldConn := client.conn
	fakePending := make(chan callResult, 1)
	client.pending[999] = fakePending
	client.pendingMu.Unlock()
	client.failConnection(oldConn, ErrTransportUncertain)
	<-fakePending

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		response, err := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
		if err == nil && response.GetErrno() != 0 {
			err = syscall.Errno(response.GetErrno())
		}
		results <- err
	}()
	go func() {
		<-start
		response, err := client.CallMutation(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Name: []byte("x")}}})
		if err == nil && response.GetErrno() != 0 {
			err = syscall.Errno(response.GetErrno())
		}
		results <- err
	}()
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("same-epoch concurrent reconnect call: %v", err)
		}
	}
	select {
	case <-client.SessionDone():
		t.Fatalf("recoverable connection gap ended session: %v", client.SessionError())
	default:
	}
	_ = client.Close()
	stop()
}

// replayHandler is a miniature authority built on the real volumeserver runtime.
// It reproduces the exact order in which the production handler rejects work:
// a write on a read-only session is refused before ExecuteMutation is reached,
// so the runtime's replay slot is never touched.
type replayHandler struct {
	runtime *volumeserver.Authority
	access  volumeserver.Access
	// suppressState drops the recorded slot state from the reply, which is the
	// pre-fix behaviour the client used to compensate for by guessing.
	suppressState bool
	// Optional lost-reply controls. The first mutation parks after the runtime
	// has recorded its outcome but before the handler returns it to the wire.
	afterExecution chan struct{}
	releaseFirst   chan struct{}
	mutationCalls  atomic.Int32
	applyCalls     atomic.Int32
}

func (h *replayHandler) Epoch() []byte {
	epoch := h.runtime.Epoch()
	return append([]byte(nil), epoch[:]...)
}

func (h *replayHandler) Bounds() TransportBounds { return testBounds(testMaxInFlight) }

func (h *replayHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	epoch := h.Epoch()
	fail := func(errno int32) *authoritypb.Response {
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch, Errno: errno}
	}
	switch req.GetBody().(type) {
	case *authoritypb.Request_Hello:
		bounds := h.Bounds()
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch, Body: &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{
			ProtocolMajor: ProtocolMajor, Features: append([]string(nil), requiredHelloFeatures...),
			MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxInFlight: uint32(bounds.MaxInFlight),
		}}}
	case *authoritypb.Request_Attach:
		peer, ok := PeerIdentity(ctx)
		if !ok {
			return fail(int32(syscall.EPERM))
		}
		cred, err := h.runtime.Attach(req.GetAttach().GetReplaySlots(), volumeserver.PeerIdentity(peer), volumeserver.Authorization{Access: h.access, Deadline: time.Now().Add(time.Hour)})
		if err != nil {
			return fail(int32(syscall.EPERM))
		}
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch, Body: &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: cred.ID[:], SessionGeneration: cred.Generation, ResumeSecret: cred.Secret[:],
			Root: testAuthorityRoot(), Features: append([]string(nil), requiredAttachFeatures...),
			SessionLeaseMilliseconds: uint64(h.runtime.SessionLease() / time.Millisecond),
		}}}
	case *authoritypb.Request_Resume:
		var cred volumeserver.SessionCredential
		if len(req.GetEpoch()) != len(cred.Epoch) || req.GetSession() == nil {
			return fail(int32(syscall.EINVAL))
		}
		copy(cred.Epoch[:], req.GetEpoch())
		copy(cred.ID[:], req.GetSession().GetId())
		copy(cred.Secret[:], req.GetSession().GetResumeSecret())
		cred.Generation = req.GetSession().GetGeneration()
		peer, ok := PeerIdentity(ctx)
		if !ok {
			return fail(int32(syscall.EPERM))
		}
		cred.Peer = volumeserver.PeerIdentity(peer)
		if err := h.runtime.Resume(cred); err != nil {
			return fail(int32(syscall.ESTALE))
		}
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch}
	}
	var cred volumeserver.SessionCredential
	if len(req.GetEpoch()) != len(cred.Epoch) || req.GetSession() == nil {
		return fail(int32(syscall.EINVAL))
	}
	copy(cred.Epoch[:], req.GetEpoch())
	copy(cred.ID[:], req.GetSession().GetId())
	copy(cred.Secret[:], req.GetSession().GetResumeSecret())
	cred.Generation = req.GetSession().GetGeneration()
	peer, ok := PeerIdentity(ctx)
	if !ok {
		return fail(int32(syscall.EPERM))
	}
	cred.Peer = volumeserver.PeerIdentity(peer)
	use, err := h.runtime.Begin(cred)
	if err != nil {
		return fail(int32(syscall.ESTALE))
	}
	defer use.End()
	if req.GetKeepAlive() != nil {
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch}
	}
	// This is the boundary the defect lives on: a write refused here never
	// reaches ExecuteMutation, so the runtime slot keeps its old sequence.
	if requestRequiresWrite(req) && use.Access()&volumeserver.AccessWrite == 0 {
		return fail(int32(syscall.EPERM))
	}
	mutation := req.GetMutation()
	if mutation == nil {
		return fail(int32(syscall.EINVAL))
	}
	hash, err := canonicalHash(req)
	if err != nil {
		return fail(int32(syscall.EINVAL))
	}
	id := volumeserver.MutationID{Slot: mutation.GetSlot(), Sequence: mutation.GetSequence(), Hash: hash}
	mutationCall := h.mutationCalls.Add(1)
	_, err = h.runtime.ExecuteMutation(ctx, cred, id, func(context.Context) volumeserver.Outcome {
		h.applyCalls.Add(1)
		return volumeserver.Outcome{}
	})
	if err != nil {
		switch {
		case errors.Is(err, volumeserver.ErrSequenceGap), errors.Is(err, volumeserver.ErrRequestMismatch), errors.Is(err, volumeserver.ErrSlotRange):
			return fail(int32(syscall.EINVAL))
		default:
			return fail(int32(syscall.ESTALE))
		}
	}
	if mutationCall == 1 && h.afterExecution != nil {
		close(h.afterExecution)
		<-h.releaseFirst
	}
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch}
	if !h.suppressState {
		response.Mutation = &authoritypb.MutationState{Slot: id.Slot, AcceptedSequence: id.Sequence}
	}
	return response
}

func TestReclaimLostReplyReplaysExactOutcome(t *testing.T) {
	runtime, err := volumeserver.New("reclaim-replay-volume", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 8, MaxSessions: 4, MaxLockRecords: 16})
	if err != nil {
		t.Fatal(err)
	}
	handler := &replayHandler{
		runtime: runtime, access: volumeserver.AccessRead,
		afterExecution: make(chan struct{}), releaseFirst: make(chan struct{}),
	}
	address, clientTLS, stop := startTestServer(t, handler, testMaxInFlight, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "reclaim-replay-volume", AccessToken: []byte("cap"),
		ReplaySlots: 4, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	type result struct {
		response *authoritypb.Response
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		response, err := client.CallMutation(context.Background(), &authoritypb.Request{
			Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: bytes.Repeat([]byte{0x91}, 16)}},
		})
		completed <- result{response: response, err: err}
	}()
	select {
	case <-handler.afterExecution:
	case <-time.After(time.Second):
		t.Fatal("reclaim did not reach its recorded-outcome boundary")
	}
	client.pendingMu.Lock()
	oldConn := client.conn
	client.pendingMu.Unlock()
	client.failConnection(oldConn, ErrTransportUncertain)
	close(handler.releaseFirst)

	select {
	case got := <-completed:
		if got.err != nil || got.response == nil || got.response.GetErrno() != 0 || got.response.GetMutation() == nil {
			t.Fatalf("replayed reclaim=(%v,%v)", got.response, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reclaim did not reconnect and replay after its lost reply")
	}
	if calls, applies := handler.mutationCalls.Load(), handler.applyCalls.Load(); calls != 2 || applies != 1 {
		t.Fatalf("reclaim wire calls=%d apply calls=%d, want 2 and 1", calls, applies)
	}
}

// Defect 1: a read-only mount refuses a write before the authority records
// anything, but the client used to advance its slot on any exact reply. The
// next mutation that landed on the same slot then arrived one sequence ahead,
// the authority raised a sequence gap, fenced the session, and every later
// request returned ESTALE until the mount was torn down.
func TestReadOnlyRejectionKeepsReplaySlotsSynchronized(t *testing.T) {
	runtime, err := volumeserver.New("read-only-volume", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 8, MaxSessions: 4, MaxLockRecords: 16})
	if err != nil {
		t.Fatal(err)
	}
	handler := &replayHandler{runtime: runtime, access: volumeserver.AccessRead}
	address, clientTLS, stop := startTestServer(t, handler, testMaxInFlight, time.Minute)
	defer stop()
	// Two replay slots and two in-flight permits put every ordinary mutation on
	// the same slot, which is what makes the desynchronization observable
	// immediately instead of after a full slot cycle.
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "read-only-volume", AccessToken: []byte("cap"),
		ReplaySlots: 2, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	mkdir := &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: make([]byte, 16), Name: []byte("x"), Mode: 0o755}}}
	refused, err := client.CallMutation(context.Background(), mkdir)
	if err != nil || refused.GetErrno() != int32(syscall.EPERM) {
		t.Fatalf("mkdir on a read-only mount = (%v, %v), want EPERM", refused, err)
	}
	if refused.GetMutation() != nil {
		t.Fatal("a refusal that recorded nothing must not report a recorded slot state")
	}

	// Every later legal mutation lands on the same slot. Each must be accepted;
	// under the defect the second one raised ErrSequenceGap and fenced.
	for i := range 8 {
		reclaim := &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: make([]byte, 16), LockOwner: uint64(i)}}}
		response, err := client.CallMutation(context.Background(), reclaim)
		if err != nil {
			t.Fatalf("legal mutation %d after a refused write: %v", i, err)
		}
		if response.GetErrno() != 0 {
			t.Fatalf("legal mutation %d = errno %d, want success (a sequence gap fences the session and every later request returns ESTALE)", i, response.GetErrno())
		}
	}
	select {
	case <-client.SessionDone():
		t.Fatalf("session ended after a refused write: %v", client.SessionError())
	default:
	}
}

// The same scenario with the authoritative slot state withheld reproduces the
// original failure, which is what makes the fix load-bearing rather than
// incidental: without the reported state the client has to guess.
func TestSuppressedSlotStateStillCannotDesynchronize(t *testing.T) {
	runtime, err := volumeserver.New("suppressed-volume", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 8, MaxSessions: 4, MaxLockRecords: 16})
	if err != nil {
		t.Fatal(err)
	}
	handler := &replayHandler{runtime: runtime, access: volumeserver.AccessRead | volumeserver.AccessWrite, suppressState: true}
	address, clientTLS, stop := startTestServer(t, handler, testMaxInFlight, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "suppressed-volume", AccessToken: []byte("cap"),
		ReplaySlots: 2, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// The authority records sequence 1 but reports nothing, so the client keeps
	// sequence 0 and resubmits 1. That is a replay of the same identity, which
	// the runtime answers from the slot; it never becomes a gap.
	for i := range 4 {
		response, err := client.CallMutation(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: make([]byte, 16)}}})
		if err != nil || response.GetErrno() != 0 {
			t.Fatalf("mutation %d without reported slot state = (%v, %v)", i, response, err)
		}
	}
}

func TestSlotSynchronizationRejectsAForeignIdentity(t *testing.T) {
	slot := &clientSlot{sequence: 4}
	if err := synchronizeSlot(slot, 1, 5, nil); err != nil || slot.sequence != 4 {
		t.Fatalf("absent state = %v, sequence %d, want no advance", err, slot.sequence)
	}
	if err := synchronizeSlot(slot, 1, 5, &authoritypb.MutationState{Slot: 1, AcceptedSequence: 5}); err != nil || slot.sequence != 5 {
		t.Fatalf("matching state = %v, sequence %d, want advance to 5", err, slot.sequence)
	}
	if err := synchronizeSlot(slot, 1, 6, &authoritypb.MutationState{Slot: 2, AcceptedSequence: 6}); !errors.Is(err, ErrReplayDesynchronized) {
		t.Fatalf("foreign slot = %v, want ErrReplayDesynchronized", err)
	}
	if err := synchronizeSlot(slot, 1, 6, &authoritypb.MutationState{Slot: 1, AcceptedSequence: 9}); !errors.Is(err, ErrReplayDesynchronized) {
		t.Fatalf("foreign sequence = %v, want ErrReplayDesynchronized", err)
	}
}

// blockingLockHandler parks every waiting SetLock until the test releases it.
type blockingLockHandler struct {
	epoch   []byte
	release chan struct{}
	parked  chan struct{}
}

func (h *blockingLockHandler) Epoch() []byte           { return append([]byte(nil), h.epoch...) }
func (h *blockingLockHandler) Bounds() TransportBounds { return testBounds(4) }
func (h *blockingLockHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch()}
	switch req.GetBody().(type) {
	case *authoritypb.Request_Hello:
		bounds := h.Bounds()
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{ProtocolMajor: ProtocolMajor, Features: append([]string(nil), requiredHelloFeatures...), MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxInFlight: uint32(bounds.MaxInFlight)}}
	case *authoritypb.Request_Attach:
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{SessionId: make([]byte, 16), SessionGeneration: 1, ResumeSecret: make([]byte, 32), Root: testAuthorityRoot(), Features: append([]string(nil), requiredAttachFeatures...), SessionLeaseMilliseconds: 30_000}}
	case *authoritypb.Request_SetLock:
		select {
		case h.parked <- struct{}{}:
		default:
		}
		select {
		case <-h.release:
		case <-ctx.Done():
		}
		if mutation := req.GetMutation(); mutation != nil {
			response.Mutation = &authoritypb.MutationState{Slot: mutation.GetSlot(), AcceptedSequence: mutation.GetSequence()}
		}
	}
	return response
}

// Defect 8: blocking POSIX lock waits took ordinary in-flight permits with no
// deadline, so enough F_SETLKW waiters starved the keepalive and the mount was
// torn down while the authority was healthy.
func TestBlockingLockWaitsCannotStarveTheOrdinaryLane(t *testing.T) {
	handler := &blockingLockHandler{epoch: make([]byte, 16), release: make(chan struct{}), parked: make(chan struct{}, 8)}
	address, clientTLS, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 4, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: 2 * time.Second, MaxInFlight: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	waitCtx, cancelWaits := context.WithCancel(context.Background())
	defer cancelWaits()
	var waiters sync.WaitGroup
	// Far more blocking waiters than the whole in-flight bound.
	for range 12 {
		waiters.Add(1)
		go func() {
			defer waiters.Done()
			_, _ = client.CallMutation(waitCtx, &authoritypb.Request{Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{
				Wait: true, Lock: &authoritypb.LockSpec{Item: make([]byte, 16), Write: true, Range: &authoritypb.LockRange{End: 1}},
			}}})
		}()
	}
	<-handler.parked

	// The keepalive is an ordinary read. It must still complete promptly.
	for range 4 {
		callCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		response, err := client.CallRead(callCtx, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
		cancel()
		if err != nil || response.GetErrno() != 0 {
			t.Fatalf("keepalive behind blocked lock waits = (%v, %v)", response, err)
		}
	}
	close(handler.release)
	cancelWaits()
	waiters.Wait()
}

func TestDialClientRefusesLanelessAdmission(t *testing.T) {
	_, err := DialClient(context.Background(), ClientConfig{
		Address: "127.0.0.1:1", TLS: &tls.Config{ServerName: "x"}, VolumeID: "v", AccessToken: []byte("c"),
		ReplaySlots: 1, MaxFrame: testMaxFrame, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 1,
	})
	if err == nil {
		t.Fatal("DialClient accepted an in-flight bound with no room for a blocking lock wait")
	}
}

func TestCanonicalHashIsIndependentOfTheEnvelope(t *testing.T) {
	body := &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: make([]byte, 16), Name: []byte("dir"), Mode: 0o755}}
	bare := &authoritypb.Request{Body: body}
	stamped := &authoritypb.Request{
		RequestId: 91, Epoch: make([]byte, 16),
		Session:  &authoritypb.SessionProof{Id: make([]byte, 16), Generation: 3, ResumeSecret: make([]byte, 32)},
		Mutation: &authoritypb.Mutation{Slot: 5, Sequence: 9, RequestHash: make([]byte, 32)},
		Body:     body,
	}
	first, err := canonicalHash(bare)
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonicalHash(stamped)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("the replay identity must not depend on the envelope")
	}
	different, err := canonicalHash(&authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: make([]byte, 16), Name: []byte("dir"), Mode: 0o700}}})
	if err != nil {
		t.Fatal(err)
	}
	if first == different {
		t.Fatal("a different operation must have a different replay identity")
	}
}

// Defect 11: the canonical form relied on protobuf-go's Deterministic option,
// which is documented as unstable across library versions. The encoding is now
// this package's own, so it can be pinned by value.
func TestCanonicalFormIsPinnedByValue(t *testing.T) {
	request := &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: []byte{1, 2, 3}}}}
	encoded, err := canonicalBytes(request.ProtoReflect())
	if err != nil {
		t.Fatal(err)
	}
	// field 36 (reclaim), length 5; nested field 1 (item), length 3.
	want := []byte{0xA2, 0x02, 0x05, 0x0A, 0x03, 0x01, 0x02, 0x03}
	if fmt.Sprintf("%x", encoded) != fmt.Sprintf("%x", want) {
		t.Fatalf("canonical encoding = %x, want %x", encoded, want)
	}
	unknown := &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: []byte{1}}}}
	unknown.ProtoReflect().SetUnknown([]byte{0xF8, 0x3F, 0x01})
	if _, err := canonicalHash(unknown); !errors.Is(err, errNonCanonical) {
		t.Fatalf("unknown fields = %v, want a refusal", err)
	}
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PortableFS test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, name string, usages []x509.ExtKeyUsage, dns []string) tls.Certificate {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: dns, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	serverCert := issue(2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	clientCert := issue(3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{serverCert}}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{clientCert}, ServerName: "localhost"}
}
