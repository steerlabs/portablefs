package authorityrpc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
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

func testPreKernelMountAbsence(context.Context) (*authoritypb.MountAbsenceProof, error) {
	return &authoritypb.MountAbsenceProof{
		ObservedUnixNanos: time.Now().UnixNano(),
		Observation:       []byte("test exact mount source absent before kernel publication"),
		Component:         "authorityrpc/client-test",
	}, nil
}

// coherentTestClientConfig keeps ordinary transport tests on the one protocol-5
// mount contract. Individual tests override only the field whose behavior they
// exercise; an omitted coherence declaration must never accidentally turn a
// transport test into a configuration-validation test.
func coherentTestClientConfig(address string, clientTLS *tls.Config, volumeID string, replaySlots uint32, maxInFlight int) ClientConfig {
	return ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: volumeID, AccessToken: []byte("cap"),
		ReplaySlots: replaySlots, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: maxInFlight,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 128, RepairBudget: time.Second,
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	}
}

func testBounds(maxInFlight int) TransportBounds {
	return TransportBounds{MaxFrame: testMaxFrame, MaxRequestFrame: (1 << 20) + FramePayloadReserve, MaxInFlight: maxInFlight}
}

type mutationAssignmentHandler struct {
	clientTestHandler
	assigned          <-chan struct{}
	mutations         atomic.Int32
	frontendOperation atomic.Uint64
	ordered           atomic.Bool
}

func (h *mutationAssignmentHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	if req.GetMutation() != nil {
		h.mutations.Add(1)
		h.frontendOperation.Store(req.GetFrontendOperationId())
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
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 128, RepairBudget: time.Second,
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var first MutationIdentity
	callbackCalls := 0
	_, err = client.CallMutationWithIdentity(context.Background(), &authoritypb.Request{
		FrontendOperationId: 77,
		Body:                &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Name: []byte("one")}},
	}, func(identity MutationIdentity) error {
		callbackCalls++
		first = identity
		close(assignedOnWire)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callbackCalls != 1 || first.Sequence != 1 || !handler.ordered.Load() ||
		handler.mutations.Load() != 1 || handler.frontendOperation.Load() != 77 {
		t.Fatalf("assignment calls=%d identity=%+v ordered=%v mutations=%d frontend_operation_id=%d",
			callbackCalls, first, handler.ordered.Load(), handler.mutations.Load(),
			handler.frontendOperation.Load())
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
	epoch                 []byte
	started               chan struct{}
	once                  *sync.Once
	omitHelloFeature      bool
	legacyHello           bool
	omitAttachFeature     bool
	omitExactRepair       bool
	attachCount           *atomic.Int32
	writeTransactionBound *uint64
	readBound             *uint32
	keepAliveErrno        int32
	maxInFlight           int
	mountEnrollment       bool
}

const clientTestWriteTransactionReplyStaged uint32 = 1 << 1

var clientTestNeverTerminal = make(chan struct{})

type clientReauthorizationHandler struct {
	clientTestHandler
	requests atomic.Int32
}

func (h *clientReauthorizationHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	response := h.clientTestHandler.Handle(ctx, request)
	if hello := response.GetHello(); hello != nil {
		hello.Features = append(hello.Features, sessionReauthorizationFeature)
	}
	if reauthorization := request.GetReauthorize(); reauthorization != nil {
		h.requests.Add(1)
		response.Errno = 0
		response.Body = &authoritypb.Response_Reauthorize{Reauthorize: &authoritypb.ReauthorizeReply{
			Sequence:                       reauthorization.GetSequence(),
			AuthorizationDeadlineUnixNanos: time.Now().Add(10 * time.Minute).UnixNano(),
		}}
	}
	return response
}

func TestClientReauthorizationInstallsOnlyAValidatedReplacementCertificate(t *testing.T) {
	handler := &clientReauthorizationHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 4}}
	address, clientTLS, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 4, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 4,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 128, RepairBudget: time.Second,
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	renewed := renewedCertificateForExistingKey(t, clientTLS.Certificates[0], 9001)
	deadline, err := client.ReauthorizeWithCertificate(context.Background(), []byte("renewed"), 1, renewed, time.Now())
	if err != nil || !deadline.After(time.Now()) || handler.requests.Load() != 1 {
		t.Fatalf("reauthorize deadline=%v requests=%d err=%v", deadline, handler.requests.Load(), err)
	}
	if got := client.cfg.TLS.Certificates[0].Leaf; got == nil || got.SerialNumber.Int64() != 9001 {
		t.Fatalf("installed certificate = %+v", got)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := certificateForSigner(t, otherKey, 9002)
	if _, err := client.ReauthorizeWithCertificate(context.Background(), []byte("wrong"), 2, wrong, time.Now()); err == nil {
		t.Fatal("reauthorization accepted a certificate for another private key")
	}
	if handler.requests.Load() != 1 {
		t.Fatal("invalid replacement reached the authority")
	}
}

func renewedCertificateForExistingKey(t *testing.T, existing tls.Certificate, serial int64) []byte {
	t.Helper()
	signer, ok := existing.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("test client key is not a signer")
	}
	return certificateForSigner(t, signer, serial)
}

func certificateForSigner(t *testing.T, signer crypto.Signer, serial int64) []byte {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "renewed-client"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (h clientTestHandler) Epoch() []byte { return append([]byte(nil), h.epoch...) }

func (h clientTestHandler) Bounds() TransportBounds { return testBounds(h.maxInFlight) }

func (h clientTestHandler) RegisterSessionEndHook(func(volumeserver.SessionID)) {}
func (h clientTestHandler) SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return volumeserver.SessionStateProvisional, true
}
func (h clientTestHandler) SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool) {
	return clientTestNeverTerminal, true
}

func (h clientTestHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch()}
	switch req.GetBody().(type) {
	case *authoritypb.Request_Hello:
		features := append([]string(nil), requiredHelloFeatures...)
		if h.mountEnrollment {
			features = append(features, sessionReauthorizationFeature, mountEnrollmentReauthorizationFeature)
		}
		if h.omitHelloFeature {
			features = features[1:]
		}
		if h.legacyHello {
			features = []string{"xfs-current-state", "session-exact-epoch", "direct-write"}
		}
		bounds := h.Bounds()
		writeTransactionBound := RequiredWriteTransactionBytes
		if h.writeTransactionBound != nil {
			writeTransactionBound = *h.writeTransactionBound
		}
		readBound := uint32(1 << 20)
		if h.readBound != nil {
			readBound = *h.readBound
		}
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{
			ProtocolMajor: ProtocolMajor, Features: features,
			MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: readBound, MaxWriteBytes: 1 << 20,
			MaxInFlight: uint32(bounds.MaxInFlight), MaxWriteTransactionBytes: writeTransactionBound,
		}}
	case *authoritypb.Request_Attach:
		if h.attachCount != nil {
			h.attachCount.Add(1)
		}
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: bytes.Repeat([]byte{0x51}, 16), Generation: 1, ResumeSecret: bytes.Repeat([]byte{0x61}, 32),
			ProvisionalDeadlineUnixNanos: time.Now().Add(time.Minute).UnixNano(),
		}}
	case *authoritypb.Request_Activate:
		features := append([]string(nil), requiredAttachFeatures...)
		if h.mountEnrollment {
			features = append(features, sessionReauthorizationFeature, mountEnrollmentReauthorizationFeature)
		}
		if h.omitAttachFeature {
			features = features[1:]
		}
		features = append(features, requiredStrictAttachFeatures...)
		if h.omitExactRepair {
			features = features[:len(features)-1]
		}
		deadline := int64(0)
		if h.mountEnrollment {
			deadline = time.Now().Add(time.Minute).UnixNano()
		}
		response.Body = &authoritypb.Response_Activate{Activate: &authoritypb.ActivateReply{
			Root: testAuthorityRoot(), Features: features, SessionLeaseMilliseconds: 30_000,
			AuthorizationDeadlineUnixNanos: deadline, RoutesRevision: append([]byte(nil), req.GetSession().GetId()...),
			VisibilityCursor: &authoritypb.VisibilityCursor{Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE},
			State:            authoritypb.SessionState_SESSION_STATE_ACTIVE,
		}}
		// Routes are an attach property. The common test configuration uses the
		// all-zero 32-byte revision, which remains an explicit declaration.
		response.GetActivate().RoutesRevision = make([]byte, 32)
	case *authoritypb.Request_Resume:
		response.Body = &authoritypb.Response_Resume{Resume: &authoritypb.ResumeReply{State: authoritypb.SessionState_SESSION_STATE_ACTIVE}}
	case *authoritypb.Request_AbortAttach:
		response.Body = &authoritypb.Response_AbortAttach{AbortAttach: &authoritypb.AbortAttachReply{State: authoritypb.SessionState_SESSION_STATE_ABORTED}}
	case *authoritypb.Request_KeepAlive:
		response.Errno = h.keepAliveErrno
	case *authoritypb.Request_Cancel:
	case *authoritypb.Request_WriteTransaction:
		transaction := req.GetWriteTransaction()
		response.Body = &authoritypb.Response_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionReply{
			TransactionId: transaction.GetTransactionId(),
			CommittedSize: transaction.GetFragmentOffset() + uint64(len(transaction.GetData())),
			Flags:         clientTestWriteTransactionReplyStaged,
		}}
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
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if cap(client.ordinary.permits) != 3 || cap(client.visibility.permits) != 1 || cap(client.liveness.permits) != 1 || cap(client.blocking.permits) != 2 {
		t.Fatalf("strict lanes ordinary/visibility/liveness/blocking = %d/%d/%d/%d, want 3/1/1/2",
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

func TestStrictClientRequiresExactParentRepairSemantics(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{
		epoch: make([]byte, 16), maxInFlight: 5, omitExactRepair: true,
	}, 5, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 4096, RepairBudget: 2 * time.Second,
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("strict client attached to an authority with the old terminal blocked-report semantics")
	}
}

func TestClientRefusesLegacyHelloBeforeAttachSideEffects(t *testing.T) {
	var attaches atomic.Int32
	address, clientTLS, stop := startTestServer(t, clientTestHandler{
		epoch: make([]byte, 16), maxInFlight: 5, legacyHello: true, attachCount: &attaches,
	}, 5, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("single-use-capability"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 4096, RepairBudget: 2 * time.Second,
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("new client accepted an authority whose Hello predates exact repair semantics")
	}
	if got := attaches.Load(); got != 0 {
		t.Fatalf("legacy Hello refusal reached Attach %d times and could spend its capability", got)
	}
}

func TestClientRefusesWrongWriteTransactionBoundBeforeAttachSideEffects(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bound uint64
	}{
		{name: "omitted", bound: 0},
		{name: "smaller", bound: RequiredWriteTransactionBytes - 1},
		{name: "larger", bound: RequiredWriteTransactionBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attaches atomic.Int32
			bound := tc.bound
			address, clientTLS, stop := startTestServer(t, clientTestHandler{
				epoch: bytes.Repeat([]byte{0x45}, 16), maxInFlight: 5,
				writeTransactionBound: &bound, attachCount: &attaches,
			}, 5, time.Minute)
			defer stop()
			client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 5, 5))
			if err == nil {
				_ = client.Close()
				t.Fatalf("client accepted write-transaction bound %d", bound)
			}
			if !strings.Contains(err.Error(), "write-transaction bound") {
				t.Fatalf("DialClient error = %v, want write-transaction bound refusal", err)
			}
			if got := attaches.Load(); got != 0 {
				t.Fatalf("write-transaction bound refusal reached Attach %d times", got)
			}
		})
	}
}

// The authority configures its read and write bounds separately, but a Linux
// mount sizes max_write from the write bound and the kernel then sizes max_read
// from max_write. A read bound below the write bound therefore does not shrink
// reads, it splits each one across round trips, and nothing on either side
// reports that it happened. Negotiation is the only place both numbers are
// visible, so it is where the pairing is refused.
func TestClientRefusesAReadBoundBelowTheWriteBound(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bound   uint32
		refused bool
	}{
		{name: "below", bound: (1 << 20) - 4096, refused: true},
		{name: "halved", bound: 1 << 19, refused: true},
		{name: "equal", bound: 1 << 20},
		{name: "above", bound: 2 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attaches atomic.Int32
			bound := tc.bound
			address, clientTLS, stop := startTestServer(t, clientTestHandler{
				epoch: bytes.Repeat([]byte{0x2c}, 16), maxInFlight: 4,
				readBound: &bound, attachCount: &attaches,
			}, 4, time.Minute)
			defer stop()
			client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
			if !tc.refused {
				if err != nil {
					t.Fatal(err)
				}
				gotRead, gotWrite := client.IOLimits()
				_ = client.Close()
				if gotRead != tc.bound || gotWrite != 1<<20 {
					t.Fatalf("IOLimits() = (%d, %d), want (%d, %d)", gotRead, gotWrite, tc.bound, 1<<20)
				}
				return
			}
			if err == nil {
				_ = client.Close()
				t.Fatalf("client accepted read bound %d under a %d write bound", tc.bound, 1<<20)
			}
			if !strings.Contains(err.Error(), "read bound") {
				t.Fatalf("DialClient error = %v, want a read-bound refusal", err)
			}
			if got := attaches.Load(); got != 0 {
				t.Fatalf("read-bound refusal reached Attach %d times", got)
			}
		})
	}
}

// Both transports reconnect independently and lazily, so a mount that runs for
// a day pays for however many handshakes its network produced. The resumption
// cache belongs to the Client, not to the caller-supplied config, and has to
// survive the per-dial Clone or it resumes nothing.
func TestClientResumesItsTLSSessionAcrossTransportReconnects(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{
		epoch: bytes.Repeat([]byte{0x2d}, 16), maxInFlight: 5,
	}, 5, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 5, 5))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if clientTLS.ClientSessionCache != nil {
		t.Fatal("DialClient installed its resumption cache on the caller's config")
	}
	cache := client.tlsConfig().ClientSessionCache
	if cache == nil {
		t.Fatal("client dialed the authority without a TLS session cache")
	}
	if again := client.tlsConfig().ClientSessionCache; again != cache {
		t.Fatal("each dial takes a private cache, so no ticket can outlive one connection")
	}

	client.data.pendingMu.Lock()
	old := client.data.conn
	client.data.pendingMu.Unlock()
	client.failConnection(client.data, old, ErrTransportUncertain)
	response, err := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}})
	if err != nil || response.GetErrno() != 95 {
		t.Fatalf("DATA call after transport loss = (%v, %v)", response, err)
	}
	client.data.pendingMu.Lock()
	resumed, _ := client.data.conn.(*tls.Conn)
	client.data.pendingMu.Unlock()
	if resumed == nil {
		t.Fatal("DATA did not reconnect")
	}
	if !resumed.ConnectionState().DidResume {
		t.Fatal("the reconnected DATA transport paid a full TLS handshake")
	}
}

func TestReauthorizedCertificateDropsResumableTLSSessions(t *testing.T) {
	handler := &clientReauthorizationHandler{clientTestHandler: clientTestHandler{
		epoch: bytes.Repeat([]byte{0x2e}, 16), maxInFlight: 4,
	}}
	address, clientTLS, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	retired := client.tlsConfig().ClientSessionCache
	renewed := renewedCertificateForExistingKey(t, clientTLS.Certificates[0], 9002)
	if _, err := client.ReauthorizeWithCertificate(context.Background(), []byte("renewed"), 1, renewed, time.Now()); err != nil {
		t.Fatal(err)
	}
	// A resumed session authenticates as the identity that completed the full
	// handshake behind its ticket. Keeping those tickets would let a later
	// transport present the certificate this rotation just retired.
	if rotated := client.tlsConfig().ClientSessionCache; rotated == nil || rotated == retired {
		t.Fatal("a rotated client identity left the retired certificate's tickets resumable")
	}
}

// strictContractHandler records exactly what a strict mount put on the wire.
type strictContractHandler struct {
	epoch                    []byte
	maxInFlight              int
	advertiseContentionHints bool
	mu                       sync.Mutex
	attach                   *authoritypb.AttachRequest
	detach                   *authoritypb.DetachRequest
	blocked                  *authoritypb.AckVisibilityRequest
	ack                      *authoritypb.AckVisibilityRequest
}

func (h *strictContractHandler) Epoch() []byte { return append([]byte(nil), h.epoch...) }

func (h *strictContractHandler) Bounds() TransportBounds { return testBounds(h.maxInFlight) }

func (h *strictContractHandler) RegisterSessionEndHook(func(volumeserver.SessionID)) {}
func (h *strictContractHandler) SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return volumeserver.SessionStateProvisional, true
}
func (h *strictContractHandler) SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool) {
	return clientTestNeverTerminal, true
}

func (h *strictContractHandler) Handle(_ context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch()}
	switch {
	case req.GetHello() != nil:
		bounds := h.Bounds()
		features := append([]string(nil), requiredHelloFeatures...)
		if h.advertiseContentionHints {
			features = append(features, peerCompleteFIFOFeedbackFeature)
		}
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{
			ProtocolMajor: ProtocolMajor, Features: features,
			MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxInFlight: uint32(bounds.MaxInFlight),
			MaxWriteTransactionBytes: RequiredWriteTransactionBytes,
		}}
	case req.GetAttach() != nil:
		h.mu.Lock()
		h.attach = proto.Clone(req.GetAttach()).(*authoritypb.AttachRequest)
		h.mu.Unlock()
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: bytes.Repeat([]byte{0x52}, 16), Generation: 1, ResumeSecret: bytes.Repeat([]byte{0x62}, 32),
			ProvisionalDeadlineUnixNanos: time.Now().Add(time.Minute).UnixNano(),
		}}
	case req.GetActivate() != nil:
		features := append([]string(nil), requiredAttachFeatures...)
		features = append(features, requiredStrictAttachFeatures...)
		response.Body = &authoritypb.Response_Activate{Activate: &authoritypb.ActivateReply{
			Root: testAuthorityRoot(), Features: features, SessionLeaseMilliseconds: 30_000,
			RoutesRevision: make([]byte, 32), State: authoritypb.SessionState_SESSION_STATE_ACTIVE,
			VisibilityCursor: &authoritypb.VisibilityCursor{
				Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE,
			},
		}}
	case req.GetResume() != nil:
		response.Body = &authoritypb.Response_Resume{Resume: &authoritypb.ResumeReply{State: authoritypb.SessionState_SESSION_STATE_ACTIVE}}
	case req.GetAbortAttach() != nil:
		response.Body = &authoritypb.Response_AbortAttach{AbortAttach: &authoritypb.AbortAttachReply{State: authoritypb.SessionState_SESSION_STATE_ABORTED}}
	case req.GetDetach() != nil:
		h.mu.Lock()
		h.detach = req.GetDetach()
		h.mu.Unlock()
	case req.GetAckVisibility() != nil && req.GetAckVisibility().GetBlocked():
		h.mu.Lock()
		h.blocked = proto.Clone(req.GetAckVisibility()).(*authoritypb.AckVisibilityRequest)
		h.mu.Unlock()
	case req.GetAckVisibility() != nil:
		h.mu.Lock()
		h.ack = proto.Clone(req.GetAckVisibility()).(*authoritypb.AckVisibilityRequest)
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

func (h *strictContractHandler) recordedBlocked() *authoritypb.AckVisibilityRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.blocked
}

func (h *strictContractHandler) recordedAck() *authoritypb.AckVisibilityRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ack
}

// committedCleanupHandler models only the ownership boundary under test: an
// ACTIVE response means the strict membership is durable, and only a
// successful authenticated Detach removes it. Transport state transitions are
// still exercised by the real protocol-5 Server around this handler.
type committedCleanupHandler struct {
	clientTestHandler
	mutateActive    func(*authoritypb.ActivateReply)
	refuseActivate  bool
	detachErrno     int32
	loseDetachReply bool
	active          atomic.Bool
	detaches        atomic.Int32
	aborts          atomic.Int32
	mu              sync.Mutex
	proof           *authoritypb.MountAbsenceProof
}

func (h *committedCleanupHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	switch {
	case request.GetActivate() != nil:
		if h.refuseActivate {
			return &authoritypb.Response{RequestId: request.GetRequestId(), Epoch: h.Epoch(), Errno: int32(syscall.EPERM)}
		}
		response := h.clientTestHandler.Handle(ctx, request)
		if h.mutateActive != nil {
			h.mutateActive(response.GetActivate())
		}
		h.active.Store(true)
		return response
	case request.GetDetach() != nil:
		h.detaches.Add(1)
		h.mu.Lock()
		if proof := request.GetDetach().GetMountAbsence(); proof != nil {
			h.proof = proto.Clone(proof).(*authoritypb.MountAbsenceProof)
		}
		h.mu.Unlock()
		response := &authoritypb.Response{RequestId: request.GetRequestId(), Epoch: h.Epoch(), Errno: h.detachErrno}
		if h.detachErrno == 0 {
			h.active.Store(false)
		}
		if h.loseDetachReply {
			entry, _ := transportConnectionFromContext(ctx)
			_ = entry.close()
		}
		return response
	case request.GetAbortAttach() != nil:
		h.aborts.Add(1)
	}
	return h.clientTestHandler.Handle(ctx, request)
}

func (h *committedCleanupHandler) recordedProof() *authoritypb.MountAbsenceProof {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.proof == nil {
		return nil
	}
	return proto.Clone(h.proof).(*authoritypb.MountAbsenceProof)
}

func strictCleanupClientConfig(address string, clientTLS *tls.Config, observer func(context.Context) (*authoritypb.MountAbsenceProof, error)) ClientConfig {
	return ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("single-use-cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 128, RepairBudget: time.Second,
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: observer,
	}
}

func TestCommittedActiveLocalValidationFailureDetachesWithExactPreKernelEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*authoritypb.ActivateReply)
	}{
		{name: "features", mutate: func(reply *authoritypb.ActivateReply) { reply.Features = nil }},
		{name: "root", mutate: func(reply *authoritypb.ActivateReply) { reply.Root = nil }},
		{name: "lease", mutate: func(reply *authoritypb.ActivateReply) { reply.SessionLeaseMilliseconds = 0 }},
		{name: "routes", mutate: func(reply *authoritypb.ActivateReply) { reply.RoutesRevision[0] = 1 }},
		{name: "cursor", mutate: func(reply *authoritypb.ActivateReply) {
			reply.VisibilityCursor = &authoritypb.VisibilityCursor{Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &committedCleanupHandler{
				clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x71}, 16), maxInFlight: 5},
				mutateActive:      test.mutate,
			}
			address, clientTLS, stop := startTestServer(t, handler, 5, time.Minute)
			defer stop()
			var observations atomic.Int32
			proof := &authoritypb.MountAbsenceProof{
				ObservedUnixNanos: time.Now().UnixNano(), Observation: []byte("source=portablefs:test present=false"),
				Component: "test-exact-kernel-inventory",
			}
			observer := func(context.Context) (*authoritypb.MountAbsenceProof, error) {
				observations.Add(1)
				return proto.Clone(proof).(*authoritypb.MountAbsenceProof), nil
			}
			client, err := DialClient(context.Background(), strictCleanupClientConfig(address, clientTLS, observer))
			if err == nil {
				_ = client.Close()
				t.Fatal("corrupt ACTIVE state produced a usable client")
			}
			if observations.Load() != 1 || handler.detaches.Load() != 1 || handler.aborts.Load() != 0 {
				t.Fatalf("observations/detaches/aborts = %d/%d/%d, want 1/1/0",
					observations.Load(), handler.detaches.Load(), handler.aborts.Load())
			}
			if handler.active.Load() {
				t.Fatal("local ACTIVE validation failure left strict membership active")
			}
			if got := handler.recordedProof(); !proto.Equal(got, proof) {
				t.Fatalf("cleanup carried proof %+v, want %+v", got, proof)
			}
		})
	}
}

func TestSuccessfulActivateWithCorruptStateUsesCommittedCleanupBoundary(t *testing.T) {
	clientConn, authorityConn := net.Pipe()
	defer clientConn.Close()
	defer authorityConn.Close()

	epoch := bytes.Repeat([]byte{0x76}, 16)
	proof := &authoritypb.SessionProof{Id: bytes.Repeat([]byte{0x77}, 16), Generation: 4, ResumeSecret: bytes.Repeat([]byte{0x78}, 32)}
	absence, err := testPreKernelMountAbsence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var observations atomic.Int32
	client := &Client{
		cfg: ClientConfig{
			CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
			CancelDrainTimeout: time.Second,
			ObservePreKernelMountAbsence: func(context.Context) (*authoritypb.MountAbsenceProof, error) {
				observations.Add(1)
				return proto.Clone(absence).(*authoritypb.MountAbsenceProof), nil
			},
		},
		epoch: append([]byte(nil), epoch...), proof: cloneProof(proof),
	}

	requestResult := make(chan *authoritypb.Request, 1)
	authorityErr := make(chan error, 1)
	go func() {
		request := new(authoritypb.Request)
		if err := readFrame(authorityConn, testMaxFrame, nil, 0, request); err != nil {
			authorityErr <- err
			return
		}
		requestResult <- request
		authorityErr <- writeFrame(authorityConn, testMaxFrame, &authoritypb.Response{
			RequestId: request.GetRequestId(), Epoch: append([]byte(nil), epoch...),
		})
	}()

	// errno=0 plus an Activate body is the wire-level commit witness. State is
	// deliberately corrupt here to prove it is validated inside, not before,
	// the committed-ownership cleanup guard.
	err = client.publishCommittedActivation(
		&authoritypb.ActivateReply{State: authoritypb.SessionState_SESSION_STATE_PROVISIONAL},
		nil,
		&transportNegotiation{conn: clientConn, maxFrame: testMaxFrame},
		0, 0, 19,
	)
	if err == nil || !strings.Contains(err.Error(), "omitted ACTIVE session state") {
		t.Fatalf("corrupt State validation = %v", err)
	}
	if err := <-authorityErr; err != nil {
		t.Fatal(err)
	}
	request := <-requestResult
	if request.GetRequestId() != 19 || request.GetDetach() == nil || request.GetAbortAttach() != nil ||
		!proto.Equal(request.GetSession(), proof) || !proto.Equal(request.GetDetach().GetMountAbsence(), absence) {
		t.Fatalf("committed cleanup request = %+v", request)
	}
	if observations.Load() != 1 {
		t.Fatalf("mount-absence observations = %d, want 1", observations.Load())
	}
}

func TestCommittedActiveCleanupFailureNeverInventsFallback(t *testing.T) {
	observerFailure := errors.New("exact kernel inventory unavailable")
	tests := []struct {
		name             string
		observer         func(context.Context) (*authoritypb.MountAbsenceProof, error)
		detachErrno      int32
		loseReply        bool
		want             error
		wantDetachCalls  int32
		wantServerActive bool
	}{
		{
			name: "observer failure",
			observer: func(context.Context) (*authoritypb.MountAbsenceProof, error) {
				return nil, observerFailure
			},
			want: observerFailure, wantServerActive: true,
		},
		{
			name: "detach refused", observer: testPreKernelMountAbsence,
			detachErrno: int32(syscall.EPERM), want: syscall.EPERM, wantDetachCalls: 1, wantServerActive: true,
		},
		{
			name: "detach reply lost", observer: testPreKernelMountAbsence,
			loseReply: true, wantDetachCalls: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &committedCleanupHandler{
				clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x72}, 16), maxInFlight: 5},
				mutateActive:      func(reply *authoritypb.ActivateReply) { reply.Root = nil },
				detachErrno:       test.detachErrno, loseDetachReply: test.loseReply,
			}
			address, clientTLS, stop := startTestServer(t, handler, 5, time.Minute)
			defer stop()
			client, err := DialClient(context.Background(), strictCleanupClientConfig(address, clientTLS, test.observer))
			if err == nil {
				_ = client.Close()
				t.Fatal("cleanup failure produced a usable client")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("cleanup error = %v, want %v", err, test.want)
			}
			if test.loseReply && !strings.Contains(err.Error(), "release ACTIVE session") {
				t.Fatalf("lost Detach reply error = %v", err)
			}
			if handler.detaches.Load() != test.wantDetachCalls || handler.aborts.Load() != 0 {
				t.Fatalf("detach/abort calls = %d/%d, want %d/0", handler.detaches.Load(), handler.aborts.Load(), test.wantDetachCalls)
			}
			if got := handler.active.Load(); got != test.wantServerActive {
				t.Fatalf("server membership active = %v, want %v", got, test.wantServerActive)
			}
			if test.loseReply && handler.active.Load() {
				t.Fatal("lost Detach reply was not distinguished from server-side Detach acceptance")
			}
		})
	}
}

func TestPreActivationFailuresNeverObservePreKernelAbsence(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler *committedCleanupHandler
	}{
		{
			name: "Hello refusal",
			handler: &committedCleanupHandler{clientTestHandler: clientTestHandler{
				epoch: bytes.Repeat([]byte{0x73}, 16), maxInFlight: 5, omitHelloFeature: true,
			}},
		},
		{
			name: "Activate refusal",
			handler: &committedCleanupHandler{
				clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x74}, 16), maxInFlight: 5},
				refuseActivate:    true,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, clientTLS, stop := startTestServer(t, test.handler, 5, time.Minute)
			defer stop()
			var observations atomic.Int32
			observer := func(ctx context.Context) (*authoritypb.MountAbsenceProof, error) {
				observations.Add(1)
				return testPreKernelMountAbsence(ctx)
			}
			client, err := DialClient(context.Background(), strictCleanupClientConfig(address, clientTLS, observer))
			if err == nil {
				_ = client.Close()
				t.Fatal("pre-ACTIVE refusal produced a client")
			}
			if observations.Load() != 0 || test.handler.detaches.Load() != 0 {
				t.Fatalf("pre-ACTIVE refusal observations/detaches = %d/%d, want 0/0", observations.Load(), test.handler.detaches.Load())
			}
			wantAborts := int32(0)
			if test.handler.refuseActivate {
				wantAborts = 1
			}
			if test.handler.aborts.Load() != wantAborts {
				t.Fatalf("pre-ACTIVE refusal aborts = %d, want %d", test.handler.aborts.Load(), wantAborts)
			}
		})
	}
}

func TestReleaseBeforeMountIsOneAuthenticatedIdempotentTransition(t *testing.T) {
	handler := &committedCleanupHandler{
		clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x75}, 16), maxInFlight: 5},
	}
	address, clientTLS, stop := startTestServer(t, handler, 5, time.Minute)
	defer stop()
	var observations atomic.Int32
	observer := func(ctx context.Context) (*authoritypb.MountAbsenceProof, error) {
		observations.Add(1)
		return testPreKernelMountAbsence(ctx)
	}
	client, err := DialClient(context.Background(), strictCleanupClientConfig(address, clientTLS, observer))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReleaseBeforeMount(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.ReleaseBeforeMount(context.Background()); err != nil {
		t.Fatalf("idempotent release = %v", err)
	}
	if observations.Load() != 1 || handler.detaches.Load() != 1 || handler.aborts.Load() != 0 || handler.active.Load() {
		t.Fatalf("observations/detaches/aborts/active = %d/%d/%d/%v, want 1/1/0/false",
			observations.Load(), handler.detaches.Load(), handler.aborts.Load(), handler.active.Load())
	}
}

func TestBlockedVisibilityReportCarriesExactParentsAndKeepsSessionLive(t *testing.T) {
	handler := &strictContractHandler{epoch: make([]byte, 16), maxInFlight: 5}
	address, clientTLS, stop := startTestServer(t, handler, 5, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 4096, RepairBudget: 2 * time.Second,
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cursor := &authoritypb.VisibilityCursor{Sequence: 7, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE}
	if err := client.ReportVisibilityBlocked(context.Background(), cursor, []uint64{17, 23}); err != nil {
		t.Fatal(err)
	}
	report := handler.recordedBlocked()
	if report == nil || !report.GetBlocked() || !proto.Equal(report.GetCursor(), cursor) ||
		!slices.Equal(report.GetBlockedParentKernelInos(), []uint64{17, 23}) {
		t.Fatalf("blocked report = %+v, want cursor and exact parent inodes", report)
	}
	select {
	case <-client.SessionDone():
		t.Fatalf("accepted ordinary blocked report ended strict session: %v", client.SessionError())
	default:
	}
}

func TestVisibilityContentionFeedbackRequiresAdvertisedAuthorityFeature(t *testing.T) {
	for _, tc := range []struct {
		name      string
		advertise bool
		want      bool
	}{
		{name: "advertised", advertise: true, want: true},
		{name: "older authority", advertise: false, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := &strictContractHandler{
				epoch: make([]byte, 16), maxInFlight: 5,
				advertiseContentionHints: tc.advertise,
			}
			address, clientTLS, stop := startTestServer(t, handler, 5, time.Minute)
			defer stop()
			client, err := DialClient(context.Background(), ClientConfig{
				Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
				ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
				CancelDrainTimeout: time.Second, MaxInFlight: 5,
				CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
				CachedNameCapacity: 4096, RepairBudget: 2 * time.Second,
				NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_CALLBACK_SERIALIZED_PIPELINED,
				ObservePreKernelMountAbsence: testPreKernelMountAbsence,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			cursor := &authoritypb.VisibilityCursor{
				Sequence: 7, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE,
			}
			if err := client.AckVisibilityWithContention(context.Background(), cursor, true); err != nil {
				t.Fatal(err)
			}
			if got := handler.recordedAck().GetOrderedAdmissionContended(); got != tc.want {
				t.Fatalf("contention field = %v, want %v", got, tc.want)
			}
		})
	}
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
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
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
		func() ClientConfig { c := base; c.ObservePreKernelMountAbsence = nil; return c }(),
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
	if attach.GetNamespaceRepair() != authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION {
		t.Fatalf("attach carried namespace repair %v, want LOCKLESS_EXPIRATION", attach.GetNamespaceRepair())
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
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
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
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
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
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
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
			_, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
			if err == nil {
				t.Fatal("DialClient accepted an authority missing a required feature")
			}
			stop()
		})
	}
}

func TestClientConfiguredForMountEnrollmentRefusesAnOlderV3Authority(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), maxInFlight: testMaxInFlight}, testMaxInFlight, time.Minute)
	defer stop()
	cfg := coherentTestClientConfig(address, clientTLS, "volume", 4, 4)
	cfg.RequireMountEnrollmentReauthorization = true
	_, err := DialClient(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "Manager-enrolled") {
		t.Fatalf("automatic mount against older v3 authority = %v", err)
	}
}

func TestClientConfiguredForMountEnrollmentPinsAuthorityDeadline(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), maxInFlight: testMaxInFlight, mountEnrollment: true}, testMaxInFlight, time.Minute)
	defer stop()
	cfg := coherentTestClientConfig(address, clientTLS, "volume", 4, 4)
	cfg.RequireMountEnrollmentReauthorization = true
	client, err := DialClient(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := client.InitialAuthorizationDeadline()
	if !deadline.After(time.Now()) || deadline.After(time.Now().Add(2*time.Minute)) {
		t.Fatalf("authority-pinned initial deadline = %s", deadline)
	}
}

func TestClientCancellationDrainsAuthorityOutcome(t *testing.T) {
	started := make(chan struct{})
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), started: started, once: new(sync.Once), maxInFlight: 2}, 2, time.Minute)
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 2, 2))
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
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
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

func TestMutationAPIRefusesControlTraffic(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: bytes.Repeat([]byte{0x09}, 16), maxInFlight: 4}, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.CallMutation(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("CallMutation(CONTROL) = %v, want EINVAL", err)
	}
	if _, err := client.CallMutation(context.Background(), nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("CallMutation(nil) = %v, want EINVAL", err)
	}
}

type transportTraceHandler struct {
	clientTestHandler
	mu     sync.Mutex
	events []string
}

type splitNegotiationHandler struct {
	clientTestHandler
	attachCount atomic.Int32
}

func (h *splitNegotiationHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	response := h.clientTestHandler.Handle(ctx, request)
	if hello := request.GetHello(); hello != nil && hello.GetRole() == authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL {
		// Raise rather than lower the bound: a read bound below the write bound
		// is refused on its own Hello, which would leave the pair comparison
		// untested.
		response.GetHello().MaxReadBytes++
	}
	if request.GetAttach() != nil {
		h.attachCount.Add(1)
	}
	return response
}

func TestClientRefusesSplitRoleNegotiationBeforeAttach(t *testing.T) {
	handler := &splitNegotiationHandler{clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x10}, 16), maxInFlight: 4}}
	address, clientTLS, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	cfg := coherentTestClientConfig(address, clientTLS, "volume", 4, 4)
	cfg.AccessToken = []byte("single-use-cap")
	client, err := DialClient(context.Background(), cfg)
	if err == nil {
		_ = client.Close()
		t.Fatal("client accepted different DATA and CONTROL allocation bounds")
	}
	if got := handler.attachCount.Load(); got != 0 {
		t.Fatalf("split negotiation reached Attach %d times", got)
	}
}

func (h *transportTraceHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	event := ""
	switch {
	case request.GetHello() != nil:
		event = "hello:" + request.GetHello().GetRole().String()
	case request.GetAttach() != nil:
		entry, _ := transportConnectionFromContext(ctx)
		event = "attach:" + entry.role.String()
	case request.GetActivate() != nil:
		entry, _ := transportConnectionFromContext(ctx)
		event = "activate:" + entry.role.String()
	}
	if event != "" {
		h.mu.Lock()
		h.events = append(h.events, event)
		h.mu.Unlock()
	}
	return h.clientTestHandler.Handle(ctx, request)
}

func TestClientCompletesBothHellosBeforeDataAttachAndControlActivate(t *testing.T) {
	handler := &transportTraceHandler{clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x11}, 16), maxInFlight: 4}}
	address, clientTLS, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	handler.mu.Lock()
	got := append([]string(nil), handler.events...)
	handler.mu.Unlock()
	want := []string{
		"hello:TRANSPORT_ROLE_DATA", "hello:TRANSPORT_ROLE_CONTROL",
		"attach:TRANSPORT_ROLE_DATA", "activate:TRANSPORT_ROLE_CONTROL",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("transport handshake order = %v, want %v", got, want)
	}
}

type attachActivationRecoveryHandler struct {
	clientTestHandler
	closeFirstAttach   bool
	closeFirstActivate bool
	refuseActivate     bool
	mu                 sync.Mutex
	attachAttempts     [][]byte
	activations        int
	aborts             int
}

func (h *attachActivationRecoveryHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	switch {
	case request.GetAttach() != nil:
		h.mu.Lock()
		h.attachAttempts = append(h.attachAttempts, append([]byte(nil), request.GetAttach().GetAttachAttemptId()...))
		closeThis := h.closeFirstAttach && len(h.attachAttempts) == 1
		h.mu.Unlock()
		response := h.clientTestHandler.Handle(ctx, request)
		if closeThis {
			entry, _ := transportConnectionFromContext(ctx)
			_ = entry.close()
		}
		return response
	case request.GetActivate() != nil:
		h.mu.Lock()
		h.activations++
		attempt := h.activations
		refuse := h.refuseActivate
		closeThis := h.closeFirstActivate && attempt == 1
		h.mu.Unlock()
		if refuse {
			return &authoritypb.Response{RequestId: request.GetRequestId(), Epoch: h.Epoch(), Errno: int32(syscall.EPERM)}
		}
		response := h.clientTestHandler.Handle(ctx, request)
		if closeThis {
			entry, _ := transportConnectionFromContext(ctx)
			_ = entry.close()
		}
		return response
	case request.GetAbortAttach() != nil:
		h.mu.Lock()
		h.aborts++
		h.mu.Unlock()
	}
	return h.clientTestHandler.Handle(ctx, request)
}

func TestLostProvisionalAttachReplyReplaysTheExactAttempt(t *testing.T) {
	handler := &attachActivationRecoveryHandler{
		clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x21}, 16), maxInFlight: 4},
		closeFirstAttach:  true,
	}
	address, clientTLS, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	cfg := coherentTestClientConfig(address, clientTLS, "volume", 4, 4)
	cfg.AccessToken = []byte("single-use-cap")
	cfg.DialTimeout = 2 * time.Second
	client, err := DialClient(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	handler.mu.Lock()
	attempts := slices.Clone(handler.attachAttempts)
	activations, aborts := handler.activations, handler.aborts
	handler.mu.Unlock()
	if len(attempts) != 2 || len(attempts[0]) != 32 || !bytes.Equal(attempts[0], attempts[1]) {
		t.Fatalf("attach attempts = %x, want two copies of one exact 32-byte identity", attempts)
	}
	if activations != 1 || aborts != 0 {
		t.Fatalf("activation/abort calls = %d/%d, want 1/0", activations, aborts)
	}
}

func TestLostActivateReplyResumesBothRolesAndNeverAborts(t *testing.T) {
	handler := &attachActivationRecoveryHandler{
		clientTestHandler:  clientTestHandler{epoch: bytes.Repeat([]byte{0x22}, 16), maxInFlight: 4},
		closeFirstActivate: true,
	}
	address, clientTLS, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	cfg := coherentTestClientConfig(address, clientTLS, "volume", 4, 4)
	cfg.DialTimeout = 2 * time.Second
	client, err := DialClient(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	handler.mu.Lock()
	activations, aborts := handler.activations, handler.aborts
	handler.mu.Unlock()
	if activations != 2 || aborts != 0 {
		t.Fatalf("uncertain activation calls/aborts = %d/%d, want exact replay and no abort", activations, aborts)
	}
	if client.data.binding.Load() <= 1 || client.control.binding.Load() <= 2 {
		t.Fatalf("recovered binding generations DATA=%d CONTROL=%d, want both roles rebound", client.data.binding.Load(), client.control.binding.Load())
	}
}

func TestDefiniteActivationRefusalAbortsTheProvisionalAttempt(t *testing.T) {
	handler := &attachActivationRecoveryHandler{
		clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x23}, 16), maxInFlight: 4},
		refuseActivate:    true,
	}
	address, clientTLS, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err == nil {
		_ = client.Close()
		t.Fatal("client published after a definite activation refusal")
	}
	handler.mu.Lock()
	activations, aborts := handler.activations, handler.aborts
	handler.mu.Unlock()
	if activations != 1 || aborts != 1 {
		t.Fatalf("refused activation calls/aborts = %d/%d, want 1/1", activations, aborts)
	}
}

func startWrongHelloEchoServer(t *testing.T, mutate func(*authoritypb.HelloReply)) (string, *tls.Config, func()) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS = serverTLS.Clone()
	serverTLS.NextProtos = []string{protocolALPN}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, serverTLS)
		if err := conn.Handshake(); err != nil {
			done <- err
			return
		}
		request := new(authoritypb.Request)
		if err := readFrame(conn, testMaxFrame, nil, 0, request); err != nil {
			done <- err
			return
		}
		helloRequest := request.GetHello()
		if helloRequest == nil {
			done <- errors.New("test peer received a non-Hello first frame")
			return
		}
		hello := &authoritypb.HelloReply{
			ProtocolMajor: ProtocolMajor, Features: append([]string(nil), requiredHelloFeatures...),
			MaxFrameBytes: testMaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20,
			MaxInFlight: 4, MaxWriteTransactionBytes: RequiredWriteTransactionBytes, Role: helloRequest.GetRole(),
			ConnectionSetId: append([]byte(nil), helloRequest.GetConnectionSetId()...),
		}
		mutate(hello)
		done <- writeFrame(conn, testMaxFrame, &authoritypb.Response{
			RequestId: request.GetRequestId(), Epoch: bytes.Repeat([]byte{0x31}, 16),
			Body: &authoritypb.Response_Hello{Hello: hello},
		})
	}()
	return listener.Addr().String(), clientTLS, func() {
		_ = listener.Close()
		if err := <-done; err != nil {
			t.Errorf("wrong-Hello test server: %v", err)
		}
	}
}

func TestClientRefusesWrongHelloTransportEcho(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*authoritypb.HelloReply)
	}{
		{name: "role", mutate: func(reply *authoritypb.HelloReply) {
			reply.Role = authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL
		}},
		{name: "connection set", mutate: func(reply *authoritypb.HelloReply) {
			reply.ConnectionSetId[0] ^= 0xFF
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, clientTLS, stop := startWrongHelloEchoServer(t, tc.mutate)
			defer stop()
			client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
			if err == nil {
				_ = client.Close()
				t.Fatal("client accepted a Hello that changed its physical transport identity")
			}
			if !strings.Contains(err.Error(), "did not echo") {
				t.Fatalf("wrong Hello echo error = %v", err)
			}
		})
	}
}

type dualPendingHandler struct {
	clientTestHandler
	reached chan authoritypb.TransportRole
	release chan struct{}
}

func (h *dualPendingHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	if request.GetStatFs() == nil && request.GetKeepAlive() == nil {
		return h.clientTestHandler.Handle(ctx, request)
	}
	entry, ok := transportConnectionFromContext(ctx)
	if !ok {
		return nil
	}
	h.reached <- entry.role
	select {
	case <-h.release:
	case <-ctx.Done():
	}
	return &authoritypb.Response{RequestId: request.GetRequestId(), Epoch: h.Epoch()}
}

func TestDataAndControlOwnIndependentPendingNamespaces(t *testing.T) {
	handler := &dualPendingHandler{
		clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{0x12}, 16), maxInFlight: 4},
		reached:           make(chan authoritypb.TransportRole, 2), release: make(chan struct{}),
	}
	address, clientTLS, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	results := make(chan error, 2)
	go func() {
		_, err := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}}})
		results <- err
	}()
	go func() {
		_, err := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
		results <- err
	}()
	seen := map[authoritypb.TransportRole]bool{}
	for range 2 {
		select {
		case role := <-handler.reached:
			seen[role] = true
		case <-time.After(time.Second):
			t.Fatal("both physical lanes did not reach the handler")
		}
	}
	if !seen[authoritypb.TransportRole_TRANSPORT_ROLE_DATA] || !seen[authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL] {
		t.Fatalf("handler roles = %v, want DATA and CONTROL", seen)
	}
	client.data.pendingMu.Lock()
	dataWaiter := client.data.pending[3]
	client.data.pendingMu.Unlock()
	client.control.pendingMu.Lock()
	controlWaiter := client.control.pending[3]
	client.control.pendingMu.Unlock()
	if dataWaiter == nil || controlWaiter == nil || dataWaiter == controlWaiter {
		t.Fatalf("request ID 3 waiters DATA=%p CONTROL=%p, want distinct nonnil namespaces", dataWaiter, controlWaiter)
	}
	close(handler.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestBlockedMaximumDataFrameCannotBlockControlProgress(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: bytes.Repeat([]byte{0x13}, 16), maxInFlight: 4}, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Hold the exact DATA serialization point. A maximum negotiated write can
	// register its DATA waiter but cannot put one byte on that socket.
	client.data.writeMu.Lock()
	dataDone := make(chan error, 1)
	go func() {
		response, err := client.CallIdempotent(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
			Data: bytes.Repeat([]byte{0xA5}, 1<<20),
		}}})
		if err == nil && response.GetErrno() != 0 {
			err = syscall.Errno(response.GetErrno())
		}
		dataDone <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		client.data.pendingMu.Lock()
		waiting := len(client.data.pending)
		client.data.pendingMu.Unlock()
		if waiting == 1 {
			break
		}
		if time.Now().After(deadline) {
			client.data.writeMu.Unlock()
			t.Fatal("maximum DATA write did not reach its private writer")
		}
		time.Sleep(time.Millisecond)
	}
	controlCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	response, err := client.CallRead(controlCtx, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if err != nil || response.GetErrno() != 0 {
		client.data.writeMu.Unlock()
		t.Fatalf("CONTROL behind blocked maximum DATA frame = (%v, %v)", response, err)
	}
	client.data.writeMu.Unlock()
	if err := <-dataDone; err != nil {
		t.Fatalf("maximum DATA write after release: %v", err)
	}
}

func TestIdempotentWritePhaseSkipsDefensiveRequestClone(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{
		epoch: bytes.Repeat([]byte{0x7d}, 16), maxInFlight: 4,
	}, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	newDataRequest := func(transactionID uint64) *authoritypb.Request {
		return &authoritypb.Request{Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: transactionID,
			Phase:         authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
			Data:          bytes.Repeat([]byte{byte(transactionID)}, 1<<20),
		}}}
	}

	// Every entry point now transfers ownership, so the general idempotent API
	// stamps the caller's message in place. That in-place envelope is the
	// executable proof that a 1 MiB DATA field is not copied before
	// serialization.
	general := newDataRequest(1)
	if _, err := client.CallIdempotent(context.Background(), general); err != nil {
		t.Fatal(err)
	}
	if general.GetRequestId() == 0 || !bytes.Equal(general.GetEpoch(), client.Epoch()) || general.GetSession() == nil {
		t.Fatalf("request envelope was not stamped in place: %+v", general)
	}
	if got := general.GetWriteTransaction().GetData(); len(got) != 1<<20 || got[0] != 1 || got[len(got)-1] != 1 {
		t.Fatal("DATA payload changed during dispatch")
	}

	owned := newDataRequest(2)
	response, consumption, err := client.CallIdempotentRetained(context.Background(), owned, func(error) {})
	if err != nil || response == nil || consumption == nil {
		t.Fatalf("owned retained call = (%v, %T, %v)", response, consumption, err)
	}
	defer consumption.Consume()
	if owned.GetRequestId() == 0 || !bytes.Equal(owned.GetEpoch(), client.Epoch()) || owned.GetSession() == nil {
		t.Fatalf("owned request envelope was not stamped in place: %+v", owned)
	}
	if got := owned.GetWriteTransaction().GetData(); len(got) != 1<<20 || got[0] != 2 || got[len(got)-1] != 2 {
		t.Fatal("owned DATA payload changed during dispatch")
	}
}

func TestIdleDataLossReconnectsOnlyDataRole(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: bytes.Repeat([]byte{0x14}, 16), maxInFlight: 5}, 5, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 128, RepairBudget: time.Second,
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.data.pendingMu.Lock()
	oldData := client.data.conn
	oldDataGeneration := client.data.binding.Load()
	client.data.pendingMu.Unlock()
	client.control.pendingMu.Lock()
	oldControl := client.control.conn
	client.control.pendingMu.Unlock()
	client.failConnection(client.data, oldData, ErrTransportUncertain)
	select {
	case <-client.SessionDone():
		t.Fatalf("idle DATA loss ended a live strict session: %v", client.SessionError())
	default:
	}
	response, err := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}})
	// RPC errno values are Linux ABI numbers even when this unit test runs on
	// Darwin; clientTestHandler deliberately returns Linux EOPNOTSUPP (95).
	if err != nil || response.GetErrno() != 95 {
		t.Fatalf("first DATA call after idle loss = (%v, %v)", response, err)
	}
	client.data.pendingMu.Lock()
	newData := client.data.conn
	client.data.pendingMu.Unlock()
	client.control.pendingMu.Lock()
	newControl := client.control.conn
	client.control.pendingMu.Unlock()
	if newData == nil || newData == oldData || client.data.binding.Load() <= oldDataGeneration {
		t.Fatal("DATA did not resume as a new binding generation")
	}
	if newControl != oldControl {
		t.Fatal("DATA recovery churned the healthy CONTROL transport")
	}
}

func TestInFlightControlLossReconnectsOnlyControlRole(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: bytes.Repeat([]byte{0x15}, 16), maxInFlight: 4}, 4, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.data.pendingMu.Lock()
	oldData := client.data.conn
	client.data.pendingMu.Unlock()
	client.control.pendingMu.Lock()
	oldControl := client.control.conn
	oldControlGeneration := client.control.binding.Load()
	fakePending := make(chan callResult, 1)
	client.control.pending[999] = fakePending
	client.control.pendingMu.Unlock()
	client.failConnection(client.control, oldControl, ErrTransportUncertain)
	if result := <-fakePending; !errors.Is(result.err, ErrTransportUncertain) {
		t.Fatalf("failed CONTROL waiter = %v", result.err)
	}
	select {
	case <-client.SessionDone():
		t.Fatalf("recoverable in-flight CONTROL loss ended session: %v", client.SessionError())
	default:
	}
	response, err := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if err != nil || response.GetErrno() != 0 {
		t.Fatalf("CONTROL call after recoverable loss = (%v, %v)", response, err)
	}
	client.data.pendingMu.Lock()
	newData := client.data.conn
	client.data.pendingMu.Unlock()
	client.control.pendingMu.Lock()
	newControl := client.control.conn
	client.control.pendingMu.Unlock()
	if newControl == nil || newControl == oldControl || client.control.binding.Load() <= oldControlGeneration {
		t.Fatal("CONTROL did not resume as a new binding generation")
	}
	if newData != oldData {
		t.Fatal("CONTROL recovery churned the healthy DATA transport")
	}
}

func TestDeadConnectionResponseCannotEnterReplacementPendingMap(t *testing.T) {
	oldClient, oldPeer := net.Pipe()
	newClient, newPeer := net.Pipe()
	defer oldClient.Close()
	defer oldPeer.Close()
	defer newClient.Close()
	defer newPeer.Close()
	transport := newClientTransport(authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	transport.frameMax.Store(testMaxFrame)
	transport.conn = newClient
	waiter := make(chan callResult, 1)
	transport.pending[3] = waiter
	client := &Client{data: transport, epoch: bytes.Repeat([]byte{0x41}, 16), fatalDone: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		client.readLoop(transport, oldClient)
		close(done)
	}()
	if err := writeFrame(oldPeer, testMaxFrame, &authoritypb.Response{RequestId: 3, Epoch: client.Epoch()}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dead connection reader did not retire")
	}
	select {
	case result := <-waiter:
		t.Fatalf("dead generation delivered into replacement pending map: %+v", result)
	default:
	}
	transport.pendingMu.Lock()
	stillWaiting := transport.pending[3] == waiter
	transport.pendingMu.Unlock()
	if !stillWaiting {
		t.Fatal("dead generation removed the replacement connection's waiter")
	}
}

type firstReadGateConn struct {
	net.Conn
	gate <-chan struct{}
	once sync.Once
}

func (c *firstReadGateConn) Read(buffer []byte) (int, error) {
	c.once.Do(func() { <-c.gate })
	return c.Conn.Read(buffer)
}

func newTerminalDrainTestClient(dataConn, controlConn net.Conn, drain time.Duration) *Client {
	data := newClientTransport(authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	data.frameMax.Store(testMaxFrame)
	data.conn = dataConn
	control := newClientTransport(authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	control.frameMax.Store(testMaxFrame)
	control.conn = controlConn
	return &Client{
		cfg:  ClientConfig{CancelDrainTimeout: drain},
		data: data, control: control,
		ordinary:   lane{permits: make(chan struct{}, 1), slots: make([]clientSlot, 1)},
		blocking:   lane{permits: make(chan struct{}, 1), slots: make([]clientSlot, 1)},
		visibility: lane{permits: make(chan struct{}, 1)},
		liveness:   lane{permits: make(chan struct{}, 1)},
		epoch:      bytes.Repeat([]byte{0x5a}, 16), fatalDone: make(chan struct{}),
	}
}

func terminalAppliedMutationResponse(request *authoritypb.Request) *authoritypb.Response {
	return &authoritypb.Response{
		RequestId: request.GetRequestId(), Epoch: append([]byte(nil), request.GetEpoch()...),
		Mutation: &authoritypb.MutationState{
			Slot: request.GetMutation().GetSlot(), AcceptedSequence: request.GetMutation().GetSequence(),
		},
		Body: &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
			PostSize: 8, VisibilitySequence: 9, Flags: 1 | 4, Error: -int32(syscall.EIO),
		}},
	}
}

func terminalAppliedMutationResponseWithToken(request *authoritypb.Request, token []byte) *authoritypb.Response {
	response := terminalAppliedMutationResponse(request)
	response.TerminalDeliveryToken = append([]byte(nil), token...)
	return response
}

func terminalAppliedMutationRequest() *authoritypb.Request {
	return &authoritypb.Request{Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{
		Handle: bytes.Repeat([]byte{0x31}, 16), Length: 8, RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	}}}
}

func waitForClientTerminalCause(t *testing.T, client *Client) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for client.SessionError() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if client.SessionError() == nil {
		t.Fatal("client did not observe the terminal transport edge")
	}
}

func TestTerminalDeliveryTokenAndAcknowledgmentShapesAreExact(t *testing.T) {
	validToken := bytes.Repeat([]byte{0x7c}, terminalDeliveryTokenBytes)
	for _, test := range []struct {
		name  string
		token []byte
		want  bool
	}{
		{name: "absent"},
		{name: "short", token: validToken[:terminalDeliveryTokenBytes-1]},
		{name: "all zero", token: make([]byte, terminalDeliveryTokenBytes)},
		{name: "exact", token: validToken, want: true},
		{name: "long", token: append(append([]byte(nil), validToken...), 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validTerminalDeliveryToken(test.token); got != test.want {
				t.Fatalf("validTerminalDeliveryToken(%x) = %t, want %t", test.token, got, test.want)
			}
		})
	}
	valid := &authoritypb.Response{Body: &authoritypb.Response_TerminalDeliveryReceipt{
		TerminalDeliveryReceipt: &authoritypb.TerminalDeliveryReceiptReply{},
	}}
	if !validTerminalDeliveryReceiptResponse(valid) {
		t.Fatal("exact terminal delivery receipt acknowledgment was rejected")
	}
	for _, malformed := range []*authoritypb.Response{
		nil,
		{},
		{Errno: int32(syscall.EIO), Body: valid.GetBody()},
		{Uncertain: true, Body: valid.GetBody()},
		{Failure: authoritypb.FailureClass_FAILURE_CLASS_STORAGE, Body: valid.GetBody()},
		{Mutation: &authoritypb.MutationState{Slot: 1, AcceptedSequence: 1}, Body: valid.GetBody()},
		{TerminalDeliveryToken: validToken, Body: valid.GetBody()},
	} {
		if validTerminalDeliveryReceiptResponse(malformed) {
			t.Fatalf("malformed terminal receipt acknowledgment accepted: %+v", malformed)
		}
	}
}

func TestTerminalControlEOFCannotOvertakeBufferedDataResponse(t *testing.T) {
	dataClient, dataPeer := net.Pipe()
	controlClient, controlPeer := net.Pipe()
	gate := make(chan struct{})
	client := newTerminalDrainTestClient(&firstReadGateConn{Conn: dataClient, gate: gate}, controlClient, time.Second)
	defer dataPeer.Close()
	defer controlPeer.Close()
	go client.readLoop(client.data, client.data.conn)
	go client.readLoop(client.control, controlClient)

	type retainedResult struct {
		response    *authoritypb.Response
		consumption ResponseConsumption
		err         error
	}
	result := make(chan retainedResult, 1)
	go func() {
		response, consumption, err := client.CallMutationWithIdentityRetained(
			context.Background(), terminalAppliedMutationRequest(), nil, func(error) {
				t.Error("bounded terminal force ran while the exact DATA response was only buffered")
			},
		)
		result <- retainedResult{response: response, consumption: consumption, err: err}
	}()
	request := new(authoritypb.Request)
	if err := readFrame(dataPeer, testMaxFrame, nil, 0, request); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeFrame(dataPeer, testMaxFrame, terminalAppliedMutationResponse(request)) }()

	// The sibling CONTROL lane closes while DATA's exact terminal frame is
	// already being written but its reader is deliberately paused.
	if err := controlPeer.Close(); err != nil {
		t.Fatal(err)
	}
	waitForClientTerminalCause(t, client)
	select {
	case <-client.SessionDone():
		t.Fatal("CONTROL EOF exposed SessionDone before buffered DATA was parsed")
	default:
	}
	close(gate)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	completed := <-result
	if completed.err != nil || completed.response.GetFallocate() == nil || completed.consumption == nil {
		t.Fatalf("retained terminal response = (%+v, %T, %v)", completed.response, completed.consumption, completed.err)
	}
	select {
	case <-client.SessionDone():
		t.Fatal("parsed DATA response was not retained for frontend publication")
	default:
	}
	completed.consumption.Consume()
	select {
	case <-client.SessionDone():
	case <-time.After(time.Second):
		t.Fatal("consuming the terminal response did not publish SessionDone")
	}
}

func TestTerminalEOFCannotOvertakeDeliveredResponseCallback(t *testing.T) {
	dataClient, dataPeer := net.Pipe()
	controlClient, controlPeer := net.Pipe()
	client := newTerminalDrainTestClient(dataClient, controlClient, time.Second)
	defer dataPeer.Close()
	defer controlPeer.Close()
	parsed := make(chan struct{})
	releaseCallback := make(chan struct{})
	client.testAfterResponseParsed = func() {
		close(parsed)
		<-releaseCallback
	}
	go client.readLoop(client.data, dataClient)
	go client.readLoop(client.control, controlClient)

	type retainedResult struct {
		consumption ResponseConsumption
		err         error
	}
	result := make(chan retainedResult, 1)
	go func() {
		_, consumption, err := client.CallMutationWithIdentityRetained(
			context.Background(), terminalAppliedMutationRequest(), nil, func(error) {},
		)
		result <- retainedResult{consumption: consumption, err: err}
	}()
	request := new(authoritypb.Request)
	if err := readFrame(dataPeer, testMaxFrame, nil, 0, request); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(dataPeer, testMaxFrame, terminalAppliedMutationResponse(request)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-parsed:
	case <-time.After(time.Second):
		t.Fatal("retained call did not reach its paused post-parse callback boundary")
	}
	if err := controlPeer.Close(); err != nil {
		t.Fatal(err)
	}
	waitForClientTerminalCause(t, client)
	select {
	case <-client.SessionDone():
		t.Fatal("terminal EOF overtook an exact response delivered to a paused callback")
	default:
	}
	close(releaseCallback)
	completed := <-result
	if completed.err != nil || completed.consumption == nil {
		t.Fatalf("paused retained callback = (%T, %v)", completed.consumption, completed.err)
	}
	select {
	case <-client.SessionDone():
		t.Fatal("callback return consumed the response before local publication")
	default:
	}
	completed.consumption.Consume()
	select {
	case <-client.SessionDone():
	case <-time.After(time.Second):
		t.Fatal("physical-publication consumption did not release terminal drain")
	}
}

func TestTerminalDrainRevokesBeforeForcedSessionDone(t *testing.T) {
	dataClient, dataPeer := net.Pipe()
	controlClient, controlPeer := net.Pipe()
	client := newTerminalDrainTestClient(dataClient, controlClient, 20*time.Millisecond)
	defer dataPeer.Close()
	defer controlPeer.Close()
	go client.readLoop(client.data, dataClient)
	go client.readLoop(client.control, controlClient)
	var revoked atomic.Bool
	forced := make(chan struct{}, 1)
	result := make(chan ResponseConsumption, 1)
	go func() {
		_, consumption, _ := client.CallMutationWithIdentityRetained(
			context.Background(), terminalAppliedMutationRequest(), nil, func(error) {
				revoked.Store(true)
				forced <- struct{}{}
			},
		)
		result <- consumption
	}()
	request := new(authoritypb.Request)
	if err := readFrame(dataPeer, testMaxFrame, nil, 0, request); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(dataPeer, testMaxFrame, terminalAppliedMutationResponse(request)); err != nil {
		t.Fatal(err)
	}
	if consumption := <-result; consumption == nil {
		t.Fatal("terminal response omitted its retained consumption receipt")
	}
	if err := controlPeer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-forced:
	case <-time.After(time.Second):
		t.Fatal("bounded terminal drain did not force local revocation")
	}
	select {
	case <-client.SessionDone():
		if !revoked.Load() {
			t.Fatal("forced SessionDone became observable before local revocation")
		}
	case <-time.After(time.Second):
		t.Fatal("bounded terminal drain did not publish SessionDone")
	}
}

func TestTerminalDeliveryReceiptWaitsForExactControlAcknowledgment(t *testing.T) {
	dataClient, dataPeer := net.Pipe()
	controlClient, controlPeer := net.Pipe()
	client := newTerminalDrainTestClient(dataClient, controlClient, time.Second)
	defer dataPeer.Close()
	defer controlPeer.Close()
	go client.readLoop(client.data, dataClient)
	go client.readLoop(client.control, controlClient)

	token := bytes.Repeat([]byte{0xa7}, terminalDeliveryTokenBytes)
	type retainedResult struct {
		consumption ResponseConsumption
		err         error
	}
	result := make(chan retainedResult, 1)
	go func() {
		_, consumption, err := client.CallMutationWithIdentityRetained(
			context.Background(), terminalAppliedMutationRequest(), nil,
			func(error) { t.Error("valid terminal delivery was forced before its receipt deadline") },
		)
		result <- retainedResult{consumption: consumption, err: err}
	}()
	request := new(authoritypb.Request)
	if err := readFrame(dataPeer, testMaxFrame, nil, 0, request); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(dataPeer, testMaxFrame, terminalAppliedMutationResponseWithToken(request, token)); err != nil {
		t.Fatal(err)
	}
	completed := <-result
	if completed.err != nil || completed.consumption == nil {
		t.Fatalf("terminal response = (%T, %v)", completed.consumption, completed.err)
	}
	waitForClientTerminalCause(t, client)
	select {
	case <-client.SessionDone():
		t.Fatal("terminal token exposed SessionDone before frontend consumption")
	default:
	}

	consumed := make(chan struct{})
	go func() {
		completed.consumption.Consume()
		close(consumed)
	}()
	receiptRequest := new(authoritypb.Request)
	if err := readFrame(controlPeer, testMaxFrame, nil, 0, receiptRequest); err != nil {
		t.Fatal(err)
	}
	if receiptRequest.GetTerminalDeliveryReceipt() == nil ||
		!bytes.Equal(receiptRequest.GetTerminalDeliveryReceipt().GetToken(), token) ||
		receiptRequest.GetMutation() != nil || receiptRequest.GetSourcePublicationGate() != nil {
		t.Fatalf("terminal receipt request = %+v", receiptRequest)
	}
	select {
	case <-consumed:
		t.Fatal("Consume returned before the authority acknowledged the receipt")
	case <-client.SessionDone():
		t.Fatal("SessionDone overtook the terminal receipt acknowledgment")
	default:
	}
	if err := writeFrame(controlPeer, testMaxFrame, &authoritypb.Response{
		RequestId: receiptRequest.GetRequestId(), Epoch: append([]byte(nil), receiptRequest.GetEpoch()...),
		Body: &authoritypb.Response_TerminalDeliveryReceipt{TerminalDeliveryReceipt: &authoritypb.TerminalDeliveryReceiptReply{}},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-consumed:
	case <-time.After(time.Second):
		t.Fatal("Consume did not finish after the exact receipt acknowledgment")
	}
	select {
	case <-client.SessionDone():
	case <-time.After(time.Second):
		t.Fatal("terminal receipt acknowledgment did not release SessionDone")
	}
}

func TestTerminalDeliveryReceiptFailureRevokesBeforeSessionDone(t *testing.T) {
	dataClient, dataPeer := net.Pipe()
	controlClient, controlPeer := net.Pipe()
	client := newTerminalDrainTestClient(dataClient, controlClient, time.Second)
	defer dataPeer.Close()
	go client.readLoop(client.data, dataClient)
	go client.readLoop(client.control, controlClient)

	token := bytes.Repeat([]byte{0xb8}, terminalDeliveryTokenBytes)
	var revoked atomic.Bool
	result := make(chan ResponseConsumption, 1)
	go func() {
		_, consumption, _ := client.CallMutationWithIdentityRetained(
			context.Background(), terminalAppliedMutationRequest(), nil,
			func(error) { revoked.Store(true) },
		)
		result <- consumption
	}()
	request := new(authoritypb.Request)
	if err := readFrame(dataPeer, testMaxFrame, nil, 0, request); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(dataPeer, testMaxFrame, terminalAppliedMutationResponseWithToken(request, token)); err != nil {
		t.Fatal(err)
	}
	consumption := <-result
	if consumption == nil {
		t.Fatal("terminal response omitted its consumption receipt")
	}
	consumed := make(chan struct{})
	go func() {
		consumption.Consume()
		close(consumed)
	}()
	receiptRequest := new(authoritypb.Request)
	if err := readFrame(controlPeer, testMaxFrame, nil, 0, receiptRequest); err != nil {
		t.Fatal(err)
	}
	if receiptRequest.GetTerminalDeliveryReceipt() == nil {
		t.Fatal("client did not send a terminal delivery receipt on CONTROL")
	}
	if err := controlPeer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-consumed:
	case <-time.After(time.Second):
		t.Fatal("failed terminal receipt did not finish its local drain")
	}
	select {
	case <-client.SessionDone():
		if !revoked.Load() {
			t.Fatal("receipt transport failure exposed SessionDone before local revocation")
		}
	case <-time.After(time.Second):
		t.Fatal("receipt transport failure did not publish SessionDone")
	}
}

func TestMalformedTerminalDeliveryTokenRevokesBeforeLocalDrain(t *testing.T) {
	dataClient, dataPeer := net.Pipe()
	controlClient, controlPeer := net.Pipe()
	client := newTerminalDrainTestClient(dataClient, controlClient, time.Second)
	defer dataPeer.Close()
	defer controlPeer.Close()
	go client.readLoop(client.data, dataClient)
	go client.readLoop(client.control, controlClient)

	var revoked atomic.Bool
	type retainedResult struct {
		consumption ResponseConsumption
		err         error
	}
	result := make(chan retainedResult, 1)
	go func() {
		_, consumption, err := client.CallMutationWithIdentityRetained(
			context.Background(), terminalAppliedMutationRequest(), nil,
			func(error) { revoked.Store(true) },
		)
		result <- retainedResult{consumption: consumption, err: err}
	}()
	request := new(authoritypb.Request)
	if err := readFrame(dataPeer, testMaxFrame, nil, 0, request); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(dataPeer, testMaxFrame, terminalAppliedMutationResponseWithToken(request, []byte{1})); err != nil {
		t.Fatal(err)
	}
	completed := <-result
	if completed.err == nil || completed.consumption == nil || !revoked.Load() {
		t.Fatalf("malformed terminal token = (receipt %T, err %v, revoked %t)", completed.consumption, completed.err, revoked.Load())
	}
	select {
	case <-client.SessionDone():
		t.Fatal("malformed token published SessionDone before local consumption")
	default:
	}
	completed.consumption.Consume()
	select {
	case <-client.SessionDone():
	case <-time.After(time.Second):
		t.Fatal("malformed-token local drain did not publish SessionDone")
	}
}

func TestConcurrentCallsReconnectWhenConnectionIsTransientlyMissing(t *testing.T) {
	address, clientTLS, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), maxInFlight: testMaxInFlight}, testMaxInFlight, time.Minute)
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 4, 4))
	if err != nil {
		t.Fatal(err)
	}

	// Model a transport break that had an in-flight caller. It is recoverable in
	// the same epoch, unlike an idle break, and leaves a short conn==nil window.
	client.data.pendingMu.Lock()
	oldConn := client.data.conn
	fakePending := make(chan callResult, 1)
	client.data.pending[999] = fakePending
	client.data.pendingMu.Unlock()
	client.failConnection(client.data, oldConn, ErrTransportUncertain)
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
	mu      sync.Mutex
	attempt map[volumeserver.SessionID]volumeserver.AttachAttemptID
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

func (h *replayHandler) RegisterSessionEndHook(hook func(volumeserver.SessionID)) {
	h.runtime.OnSessionEnd(hook)
}
func (h *replayHandler) SessionStateForTransport(id volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return h.runtime.SessionStateByID(id)
}
func (h *replayHandler) SessionTerminalForTransport(id volumeserver.SessionID) (<-chan struct{}, bool) {
	terminal, err := h.runtime.SessionTerminal(id)
	return terminal, err == nil
}

func prepareFixtureAttach(ctx context.Context, runtime *volumeserver.Authority, request *authoritypb.Request, access volumeserver.Access) (volumeserver.SessionCredential, volumeserver.AttachAttemptID, time.Time, error) {
	var zero volumeserver.SessionCredential
	attach := request.GetAttach()
	if attach == nil {
		return zero, volumeserver.AttachAttemptID{}, time.Time{}, syscall.EINVAL
	}
	attempt, err := fixtureAttachAttemptID(attach.GetAttachAttemptId())
	if err != nil {
		return zero, attempt, time.Time{}, err
	}
	fingerprint, err := canonicalFingerprint(runtime, request)
	if err != nil {
		return zero, attempt, time.Time{}, err
	}
	peer, ok := PeerIdentity(ctx)
	if !ok {
		return zero, attempt, time.Time{}, syscall.EPERM
	}
	credential, err := runtime.PrepareAttach(
		ctx, attempt, volumeserver.AttachRequestFingerprint(fingerprint), attach.GetReplaySlots(),
		volumeserver.PeerIdentity(peer), func(context.Context) (volumeserver.Authorization, error) {
			return volumeserver.Authorization{Access: access, Deadline: time.Now().Add(time.Hour)}, nil
		},
	)
	if err != nil {
		return zero, attempt, time.Time{}, err
	}
	deadline, err := runtime.ProvisionalDeadline(credential, attempt)
	return credential, attempt, deadline, err
}

func fixtureAttachAttemptID(raw []byte) (volumeserver.AttachAttemptID, error) {
	var attempt volumeserver.AttachAttemptID
	if len(raw) != len(attempt) {
		return attempt, syscall.EINVAL
	}
	copy(attempt[:], raw)
	if attempt == (volumeserver.AttachAttemptID{}) {
		return attempt, syscall.EINVAL
	}
	return attempt, nil
}

func fixtureSessionState(runtime *volumeserver.Authority, credential volumeserver.SessionCredential, attempt volumeserver.AttachAttemptID) (authoritypb.SessionState, error) {
	state, err := runtime.SessionState(credential, attempt)
	if err != nil {
		return authoritypb.SessionState_SESSION_STATE_UNSPECIFIED, err
	}
	switch state {
	case volumeserver.SessionStateProvisional:
		return authoritypb.SessionState_SESSION_STATE_PROVISIONAL, nil
	case volumeserver.SessionStateActive:
		return authoritypb.SessionState_SESSION_STATE_ACTIVE, nil
	default:
		return authoritypb.SessionState_SESSION_STATE_TERMINAL, volumeserver.ErrSessionFenced
	}
}

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
			MaxWriteTransactionBytes: RequiredWriteTransactionBytes,
		}}}
	case *authoritypb.Request_Attach:
		cred, attempt, deadline, err := prepareFixtureAttach(ctx, h.runtime, req, h.access)
		if err != nil {
			return fail(int32(syscall.EPERM))
		}
		h.mu.Lock()
		if h.attempt == nil {
			h.attempt = make(map[volumeserver.SessionID]volumeserver.AttachAttemptID)
		}
		h.attempt[cred.ID] = attempt
		h.mu.Unlock()
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch, Body: &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:],
			ProvisionalDeadlineUnixNanos: deadline.UnixNano(),
		}}}
	case *authoritypb.Request_Activate:
		cred, err := ackNextReplayCredential(ctx, req)
		if err != nil {
			return fail(int32(syscall.EINVAL))
		}
		attempt, err := fixtureAttachAttemptID(req.GetActivate().GetAttachAttemptId())
		if err != nil {
			return fail(int32(syscall.EINVAL))
		}
		token, err := h.runtime.PrepareActivation(ctx, cred, attempt)
		if err != nil {
			return fail(int32(syscall.ESTALE))
		}
		if !token.Replay() {
			h.runtime.CommitActivation(token)
		}
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch, Body: &authoritypb.Response_Activate{Activate: &authoritypb.ActivateReply{
			Root: testAuthorityRoot(), Features: append(append([]string(nil), requiredAttachFeatures...), requiredStrictAttachFeatures...),
			SessionLeaseMilliseconds: uint64(h.runtime.SessionLease() / time.Millisecond),
			RoutesRevision:           make([]byte, 32), State: authoritypb.SessionState_SESSION_STATE_ACTIVE,
			VisibilityCursor: &authoritypb.VisibilityCursor{
				Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE,
			},
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
		h.mu.Lock()
		attempt := h.attempt[cred.ID]
		h.mu.Unlock()
		state, err := fixtureSessionState(h.runtime, cred, attempt)
		if err != nil {
			return fail(int32(syscall.ESTALE))
		}
		if state == authoritypb.SessionState_SESSION_STATE_ACTIVE {
			if err := h.runtime.Resume(cred); err != nil {
				return fail(int32(syscall.ESTALE))
			}
		}
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch, Body: &authoritypb.Response_Resume{Resume: &authoritypb.ResumeReply{State: state}}}
	case *authoritypb.Request_AbortAttach:
		cred, err := ackNextReplayCredential(ctx, req)
		if err != nil {
			return fail(int32(syscall.EINVAL))
		}
		attempt, err := fixtureAttachAttemptID(req.GetAbortAttach().GetAttachAttemptId())
		if err != nil || h.runtime.AbortProvisional(ctx, cred, attempt) != nil {
			return fail(int32(syscall.ESTALE))
		}
		return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: epoch, Body: &authoritypb.Response_AbortAttach{AbortAttach: &authoritypb.AbortAttachReply{State: authoritypb.SessionState_SESSION_STATE_ABORTED}}}
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
	fingerprint, err := canonicalFingerprint(h.runtime, req)
	if err != nil {
		return fail(int32(syscall.EINVAL))
	}
	id := volumeserver.MutationID{Slot: mutation.GetSlot(), Sequence: mutation.GetSequence(), Fingerprint: fingerprint}
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
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "reclaim-replay-volume", 4, 4))
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
	client.data.pendingMu.Lock()
	oldConn := client.data.conn
	client.data.pendingMu.Unlock()
	client.failConnection(client.data, oldConn, ErrTransportUncertain)
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
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "read-only-volume", 2, 2))
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
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "suppressed-volume", 2, 2))
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
func (h *blockingLockHandler) RegisterSessionEndHook(func(volumeserver.SessionID)) {
}
func (h *blockingLockHandler) SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return volumeserver.SessionStateProvisional, true
}
func (h *blockingLockHandler) SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool) {
	return clientTestNeverTerminal, true
}
func (h *blockingLockHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch()}
	switch req.GetBody().(type) {
	case *authoritypb.Request_Hello:
		bounds := h.Bounds()
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{
			ProtocolMajor: ProtocolMajor, Features: append([]string(nil), requiredHelloFeatures...),
			MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20,
			MaxInFlight: uint32(bounds.MaxInFlight), MaxWriteTransactionBytes: RequiredWriteTransactionBytes,
		}}
	case *authoritypb.Request_Attach:
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: bytes.Repeat([]byte{0x53}, 16), Generation: 1, ResumeSecret: bytes.Repeat([]byte{0x63}, 32),
			ProvisionalDeadlineUnixNanos: time.Now().Add(time.Minute).UnixNano(),
		}}
	case *authoritypb.Request_Activate:
		response.Body = &authoritypb.Response_Activate{Activate: &authoritypb.ActivateReply{
			Root: testAuthorityRoot(), Features: append(append([]string(nil), requiredAttachFeatures...), requiredStrictAttachFeatures...),
			SessionLeaseMilliseconds: 30_000, RoutesRevision: make([]byte, 32),
			State: authoritypb.SessionState_SESSION_STATE_ACTIVE,
			VisibilityCursor: &authoritypb.VisibilityCursor{
				Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE,
			},
		}}
	case *authoritypb.Request_Resume:
		response.Body = &authoritypb.Response_Resume{Resume: &authoritypb.ResumeReply{State: authoritypb.SessionState_SESSION_STATE_ACTIVE}}
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
	cfg := coherentTestClientConfig(address, clientTLS, "volume", 4, 4)
	cfg.CancelDrainTimeout = 2 * time.Second
	client, err := DialClient(context.Background(), cfg)
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

func TestCanonicalFingerprintIsIndependentOfTheEnvelope(t *testing.T) {
	runtime, err := volumeserver.New("fingerprint", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1})
	if err != nil {
		t.Fatal(err)
	}
	body := &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: make([]byte, 16), Name: []byte("dir"), Mode: 0o755}}
	bare := &authoritypb.Request{Body: body}
	stamped := &authoritypb.Request{
		RequestId: 91, Epoch: make([]byte, 16), FrontendOperationId: 77,
		Session:  &authoritypb.SessionProof{Id: make([]byte, 16), Generation: 3, ResumeSecret: make([]byte, 32)},
		Mutation: &authoritypb.Mutation{Slot: 5, Sequence: 9},
		Body:     body,
	}
	first, err := canonicalFingerprint(runtime, bare)
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonicalFingerprint(runtime, stamped)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("the replay identity must not depend on the envelope")
	}
	different, err := canonicalFingerprint(runtime, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: make([]byte, 16), Name: []byte("dir"), Mode: 0o700}}})
	if err != nil {
		t.Fatal(err)
	}
	if first == different {
		t.Fatal("a different operation must have a different replay identity")
	}
}

func testFingerprintSourceItem(identity byte) *authoritypb.SourcePublicationTarget {
	stable := make([]byte, 16)
	stable[0] = identity
	return &authoritypb.SourcePublicationTarget{
		Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
			Identity: stable, Attributes: true,
		}},
	}
}

// The source publication cut is part of retained mutation identity. A lost
// reply may be replayed only with the exact same cut; changing that cut cannot
// retrieve or execute the retained operation under different local coherence
// state. Non-canonical order and duplicates are refused before fingerprinting.
func TestCanonicalFingerprintIncludesCanonicalSourcePublicationGate(t *testing.T) {
	runtime, err := volumeserver.New("source-gate-fingerprint", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{
		Item: []byte{1}, Name: []byte("user.test"), Value: []byte("value"),
	}}
	request := &authoritypb.Request{
		SourcePublicationGate: &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{
			testFingerprintSourceItem(1),
		}},
		Body: body,
	}
	first, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	exactReplay := proto.Clone(request).(*authoritypb.Request)
	exact, err := canonicalFingerprint(runtime, exactReplay)
	if err != nil {
		t.Fatal(err)
	}
	if first != exact {
		t.Fatal("exact source-gate replay changed fingerprint")
	}

	changedGate := proto.Clone(request).(*authoritypb.Request)
	changedGate.SourcePublicationGate.Targets[0] = testFingerprintSourceItem(2)
	changed, err := canonicalFingerprint(runtime, changedGate)
	if err != nil {
		t.Fatal(err)
	}
	if first == changed {
		t.Fatal("gate-only mutation did not change replay fingerprint")
	}

	for _, test := range []struct {
		name    string
		targets []*authoritypb.SourcePublicationTarget
	}{
		{name: "reordered", targets: []*authoritypb.SourcePublicationTarget{
			testFingerprintSourceItem(2), testFingerprintSourceItem(1),
		}},
		{name: "duplicate", targets: []*authoritypb.SourcePublicationTarget{
			testFingerprintSourceItem(1), testFingerprintSourceItem(1),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := &authoritypb.Request{
				SourcePublicationGate: &authoritypb.SourcePublicationGate{Targets: test.targets},
				Body:                  body,
			}
			if _, err := canonicalFingerprint(runtime, invalid); !errors.Is(err, errNonCanonical) {
				t.Fatalf("non-canonical source gate = %v, want refusal", err)
			}
		})
	}
}

// Defect 11: the canonical form relied on protobuf-go's Deterministic option,
// which is documented as unstable across library versions. The encoding is now
// this package's own, so it can be pinned by value.
func TestCanonicalFormIsPinnedByValue(t *testing.T) {
	runtime, err := volumeserver.New("canonical-form", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1})
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err := canonicalFingerprint(runtime, unknown); !errors.Is(err, errNonCanonical) {
		t.Fatalf("top-level unknown fields = %v, want a refusal", err)
	}
	nestedBody := &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: []byte{1}}}}
	nestedBody.GetReclaim().ProtoReflect().SetUnknown([]byte{0xF8, 0x3F, 0x01})
	if _, err := canonicalFingerprint(runtime, nestedBody); !errors.Is(err, errNonCanonical) {
		t.Fatalf("nested body unknown fields = %v, want a refusal", err)
	}
	nestedSession := &authoritypb.Request{
		Session: &authoritypb.SessionProof{Id: make([]byte, 16), Generation: 1, ResumeSecret: make([]byte, 32)},
		Body:    &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: []byte{1}}},
	}
	nestedSession.GetSession().ProtoReflect().SetUnknown([]byte{0xF8, 0x3F, 0x01})
	if _, err := canonicalFingerprint(runtime, nestedSession); !errors.Is(err, errNonCanonical) {
		t.Fatalf("nested stripped-envelope unknown fields = %v, want a refusal", err)
	}
}

type ackNextReplayMembership struct{}

func (ackNextReplayMembership) Activate(volumeserver.SessionID) error   { return nil }
func (ackNextReplayMembership) Deactivate(volumeserver.SessionID) error { return nil }

// ackNextReplayHandler is the smallest real visibility authority needed to
// exercise the transport recovery boundary. It uses the production
// VisibilityCoordinator for cursor ownership and acknowledgement semantics;
// only capability authorization and XFS are omitted because this test sends no
// filesystem request through the RPC handler.
type ackNextReplayHandler struct {
	runtime    *volumeserver.Authority
	visibility *volumeserver.VisibilityCoordinator
	mu         sync.Mutex
	initial    *authoritypb.VisibilityCursor
	routes     []byte
	attempt    volumeserver.AttachAttemptID
	commitment volumeserver.VisibilityCommitment

	participant  chan volumeserver.SessionID
	ackAccepted  chan struct{}
	retryWaiting chan struct{}

	completeOneAttempts atomic.Int32
	ackAcceptedOnce     sync.Once
	retryWaitingOnce    sync.Once
}

func (h *ackNextReplayHandler) Epoch() []byte {
	epoch := h.runtime.Epoch()
	return append([]byte(nil), epoch[:]...)
}

func (h *ackNextReplayHandler) Bounds() TransportBounds { return testBounds(testMaxInFlight) }

func (h *ackNextReplayHandler) RegisterSessionEndHook(hook func(volumeserver.SessionID)) {
	h.runtime.OnSessionEnd(hook)
}
func (h *ackNextReplayHandler) SessionStateForTransport(id volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return h.runtime.SessionStateByID(id)
}
func (h *ackNextReplayHandler) SessionTerminalForTransport(id volumeserver.SessionID) (<-chan struct{}, bool) {
	terminal, err := h.runtime.SessionTerminal(id)
	return terminal, err == nil
}

func (h *ackNextReplayHandler) response(requestID uint64) *authoritypb.Response {
	return &authoritypb.Response{RequestId: requestID, Epoch: h.Epoch()}
}

func (h *ackNextReplayHandler) failure(requestID uint64, err error) *authoritypb.Response {
	response := h.response(requestID)
	response.Errno = int32(syscall.EINVAL)
	if errors.Is(err, volumeserver.ErrEpochMismatch) || errors.Is(err, volumeserver.ErrSessionExpired) || errors.Is(err, volumeserver.ErrSessionFenced) {
		response.Errno = int32(syscall.ESTALE)
	}
	return response
}

func ackNextReplayCredential(ctx context.Context, request *authoritypb.Request) (volumeserver.SessionCredential, error) {
	var credential volumeserver.SessionCredential
	proof := request.GetSession()
	if len(request.GetEpoch()) != len(credential.Epoch) || proof == nil ||
		len(proof.GetId()) != len(credential.ID) || len(proof.GetResumeSecret()) != len(credential.Secret) {
		return credential, syscall.EINVAL
	}
	copy(credential.Epoch[:], request.GetEpoch())
	copy(credential.ID[:], proof.GetId())
	copy(credential.Secret[:], proof.GetResumeSecret())
	credential.Generation = proof.GetGeneration()
	peer, ok := PeerIdentity(ctx)
	if !ok {
		return credential, syscall.EPERM
	}
	credential.Peer = volumeserver.PeerIdentity(peer)
	return credential, nil
}

func ackNextReplayCursor(cursor *authoritypb.VisibilityCursor) (volumeserver.VisibilityCursor, error) {
	if cursor == nil {
		return volumeserver.VisibilityCursor{}, nil
	}
	if cursor.GetSequence() == 0 {
		return volumeserver.VisibilityCursor{}, syscall.EINVAL
	}
	switch cursor.GetPhase() {
	case authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE:
		return volumeserver.VisibilityCursor{Sequence: cursor.GetSequence(), Phase: volumeserver.VisibilityPrepare}, nil
	case authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE:
		return volumeserver.VisibilityCursor{Sequence: cursor.GetSequence(), Phase: volumeserver.VisibilityComplete}, nil
	default:
		return volumeserver.VisibilityCursor{}, syscall.EINVAL
	}
}

func ackNextReplayCursorProto(cursor volumeserver.VisibilityCursor) *authoritypb.VisibilityCursor {
	if cursor == (volumeserver.VisibilityCursor{}) {
		return nil
	}
	phase := authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE
	if cursor.Phase == volumeserver.VisibilityComplete {
		phase = authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE
	}
	return &authoritypb.VisibilityCursor{Sequence: cursor.Sequence, Phase: phase}
}

func ackNextReplayEventProto(event volumeserver.VisibilityEvent) *authoritypb.VisibilityEvent {
	targets := make([]*authoritypb.VisibilityTarget, len(event.Targets))
	for i, target := range event.Targets {
		targets[i] = &authoritypb.VisibilityTarget{
			Scope:    authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES,
			Identity: append([]byte(nil), target.Identity[:]...), KernelIno: target.KernelIno, Device: target.Device,
		}
	}
	return &authoritypb.VisibilityEvent{
		Cursor: ackNextReplayCursorProto(event.Cursor), InitiatorSessionId: append([]byte(nil), event.Initiator[:]...),
		MutationSlot: event.MutationSlot, MutationSequence: event.MutationSequence, Targets: targets,
	}
}

func (h *ackNextReplayHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	response := h.response(request.GetRequestId())
	if request.GetHello() != nil {
		bounds := h.Bounds()
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{
			ProtocolMajor: ProtocolMajor,
			Features:      append(append([]string(nil), requiredHelloFeatures...), peerCompleteFIFOFeedbackFeature),
			MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20,
			MaxInFlight: uint32(bounds.MaxInFlight), MaxWriteTransactionBytes: RequiredWriteTransactionBytes,
		}}
		return response
	}
	if attach := request.GetAttach(); attach != nil {
		credential, attempt, deadline, err := prepareFixtureAttach(
			ctx, h.runtime, request, volumeserver.AccessRead|volumeserver.AccessWrite,
		)
		if err != nil {
			return h.failure(request.GetRequestId(), err)
		}
		commitment := volumeserver.VisibilityCommitment{
			CachedNameCapacity: attach.GetCachedNameCapacity(),
			RepairBudget:       time.Duration(attach.GetRepairBudgetMillis()) * time.Millisecond,
			NamespaceRepair:    volumeserver.NamespaceRepairCallbackSerializedPipelined,
		}
		h.mu.Lock()
		h.attempt = attempt
		h.commitment = commitment
		h.routes = append([]byte(nil), attach.GetRoutesRevision()...)
		h.mu.Unlock()
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: credential.ID[:], Generation: credential.Generation, ResumeSecret: credential.Secret[:],
			ProvisionalDeadlineUnixNanos: deadline.UnixNano(),
		}}
		return response
	}

	credential, err := ackNextReplayCredential(ctx, request)
	if err != nil {
		return h.failure(request.GetRequestId(), err)
	}
	if request.GetResume() != nil {
		h.mu.Lock()
		attempt := h.attempt
		h.mu.Unlock()
		state, err := fixtureSessionState(h.runtime, credential, attempt)
		if err != nil {
			return h.failure(request.GetRequestId(), err)
		}
		if state == authoritypb.SessionState_SESSION_STATE_ACTIVE {
			if err := h.runtime.Resume(credential); err != nil {
				return h.failure(request.GetRequestId(), err)
			}
		}
		response.Body = &authoritypb.Response_Resume{Resume: &authoritypb.ResumeReply{State: state}}
		return response
	}
	if request.GetActivate() != nil {
		attempt, err := fixtureAttachAttemptID(request.GetActivate().GetAttachAttemptId())
		if err != nil {
			return h.failure(request.GetRequestId(), err)
		}
		h.mu.Lock()
		if attempt != h.attempt {
			h.mu.Unlock()
			return h.failure(request.GetRequestId(), volumeserver.ErrRequestMismatch)
		}
		initial := h.initial
		routes := append([]byte(nil), h.routes...)
		commitment := h.commitment
		h.mu.Unlock()
		token, err := h.runtime.PrepareActivation(ctx, credential, attempt)
		if err != nil {
			return h.failure(request.GetRequestId(), err)
		}
		if !token.Replay() {
			committed := false
			defer func() {
				if !committed {
					h.runtime.CancelActivation(token)
				}
			}()
			terminal, err := h.runtime.SessionTerminal(credential.ID)
			if err != nil {
				return h.failure(request.GetRequestId(), err)
			}
			cursor, err := h.visibility.ActivateParticipant(
				credential.ID, volumeserver.CoherenceStrict, terminal, commitment,
				func(cursor volumeserver.VisibilityCursor) ([][16]byte, error) {
					h.mu.Lock()
					h.initial = ackNextReplayCursorProto(cursor)
					h.mu.Unlock()
					return nil, nil
				},
				func() {
					h.runtime.CommitActivation(token)
					committed = true
				},
			)
			if err != nil {
				return h.failure(request.GetRequestId(), err)
			}
			initial = ackNextReplayCursorProto(cursor)
			h.participant <- credential.ID
		}
		response.Body = &authoritypb.Response_Activate{Activate: &authoritypb.ActivateReply{
			Root:                     testAuthorityRoot(),
			Features:                 append(append([]string(nil), requiredAttachFeatures...), requiredStrictAttachFeatures...),
			SessionLeaseMilliseconds: uint64(h.runtime.SessionLease() / time.Millisecond),
			VisibilityCursor:         initial, RoutesRevision: routes,
			State: authoritypb.SessionState_SESSION_STATE_ACTIVE,
		}}
		return response
	}
	if request.GetKeepAlive() != nil {
		if err := h.runtime.Resume(credential); err != nil {
			return h.failure(request.GetRequestId(), err)
		}
		return response
	}
	use, err := h.runtime.Begin(credential)
	if err != nil {
		return h.failure(request.GetRequestId(), err)
	}
	defer use.End()

	if next := request.GetNextVisibility(); next != nil {
		cursor, err := ackNextReplayCursor(next.GetAfter())
		if err != nil {
			return h.failure(request.GetRequestId(), err)
		}
		if next.GetAcknowledgeAfter() {
			if err := h.visibility.AckWithContention(credential.ID, cursor, next.GetOrderedAdmissionContended()); err != nil {
				return h.failure(request.GetRequestId(), err)
			}
			// Activation owns the real COMPLETE(1) baseline. Lose the first
			// combined request that acknowledges the first mutation's COMPLETE(2),
			// after the coordinator has accepted its exact cursor but before Next
			// can produce a response. The automatic client retry repeats this Ack.
			if cursor == (volumeserver.VisibilityCursor{Sequence: 2, Phase: volumeserver.VisibilityComplete}) {
				attempt := h.completeOneAttempts.Add(1)
				if attempt == 1 {
					h.ackAcceptedOnce.Do(func() { close(h.ackAccepted) })
					<-ctx.Done()
					return h.failure(request.GetRequestId(), ctx.Err())
				}
				if attempt == 2 {
					h.retryWaitingOnce.Do(func() { close(h.retryWaiting) })
				}
			}
		} else if next.GetOrderedAdmissionContended() {
			return h.failure(request.GetRequestId(), syscall.EINVAL)
		}
		event, err := h.visibility.Next(ctx, credential.ID, cursor)
		if err != nil {
			return h.failure(request.GetRequestId(), err)
		}
		response.Body = &authoritypb.Response_Visibility{Visibility: ackNextReplayEventProto(event)}
		return response
	}
	if ack := request.GetAckVisibility(); ack != nil {
		cursor, err := ackNextReplayCursor(ack.GetCursor())
		if err != nil {
			return h.failure(request.GetRequestId(), err)
		}
		if err := h.visibility.AckWithContention(credential.ID, cursor, ack.GetOrderedAdmissionContended()); err != nil {
			return h.failure(request.GetRequestId(), err)
		}
		return response
	}
	return h.failure(request.GetRequestId(), syscall.EOPNOTSUPP)
}

func TestNextVisibilityAfterAckReconnectsAfterAcceptedAckLostBeforeNext(t *testing.T) {
	runtime, err := volumeserver.New("ack-next-replay", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 8, MaxSessions: 4, MaxLockRecords: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: ackNextReplayMembership{}, Fencer: runtime,
		MaxCachedNameCapacity: 64, MaxRepairBudget: 5 * time.Second, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := &ackNextReplayHandler{
		runtime: runtime, visibility: visibility, participant: make(chan volumeserver.SessionID, 1),
		ackAccepted: make(chan struct{}), retryWaiting: make(chan struct{}),
	}
	address, clientTLS, stop := startTestServer(t, handler, testMaxInFlight, time.Minute)
	defer stop()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: address, TLS: clientTLS, VolumeID: "ack-next-replay", AccessToken: []byte("cap"),
		ReplaySlots: 5, MaxFrame: testMaxFrame, DialTimeout: time.Second,
		CancelDrainTimeout: time.Second, MaxInFlight: 5,
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 32, RepairBudget: 5 * time.Second,
		NamespaceRepair:              authoritypb.NamespaceRepair_NAMESPACE_REPAIR_CALLBACK_SERIALIZED_PIPELINED,
		ObservePreKernelMountAbsence: testPreKernelMountAbsence,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	participant := <-handler.participant
	target := volumeserver.VisibilityTarget{
		Scope: volumeserver.VisibilityAttributes, Identity: [16]byte{7}, KernelIno: 7, Device: 1,
	}
	visibility.RecordResolvedInode(participant, target.Identity)

	execute := func(source volumeserver.SessionID, sequence uint64) <-chan error {
		result := make(chan error, 1)
		go func() {
			result <- visibility.Execute(context.Background(), source, volumeserver.MutationID{Sequence: sequence},
				func() ([]volumeserver.VisibilityTarget, error) { return []volumeserver.VisibilityTarget{target}, nil },
				func() ([]volumeserver.VisibilityTarget, bool) { return []volumeserver.VisibilityTarget{target}, true })
		}()
		return result
	}
	firstExecution := execute(volumeserver.SessionID{0x91}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prepareOne, err := client.NextVisibility(ctx, client.InitialVisibilityCursor())
	if err != nil || prepareOne.GetCursor().GetSequence() != 2 || prepareOne.GetCursor().GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE {
		t.Fatalf("first visibility event = (%+v, %v), want PREPARE(2)", prepareOne, err)
	}
	completeOne, err := client.NextVisibilityAfterAck(ctx, prepareOne.GetCursor(), false)
	if err != nil || completeOne.GetCursor().GetSequence() != 2 || completeOne.GetCursor().GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
		t.Fatalf("first combined advance = (%+v, %v), want COMPLETE(2)", completeOne, err)
	}

	type visibilityResult struct {
		event *authoritypb.VisibilityEvent
		err   error
	}
	advanced := make(chan visibilityResult, 1)
	go func() {
		event, err := client.NextVisibilityAfterAck(ctx, completeOne.GetCursor(), true)
		advanced <- visibilityResult{event: event, err: err}
	}()
	select {
	case <-handler.ackAccepted:
	case <-ctx.Done():
		t.Fatal("combined COMPLETE acknowledgment was not accepted before timeout")
	}
	client.control.pendingMu.Lock()
	lostConnection := client.control.conn
	client.control.pendingMu.Unlock()
	client.failConnection(client.control, lostConnection, ErrTransportUncertain)
	select {
	case <-handler.retryWaiting:
	case <-ctx.Done():
		t.Fatal("client did not reconnect and retry the accepted combined acknowledgment")
	}
	if err := <-firstExecution; err != nil {
		t.Fatalf("first mutation after accepted COMPLETE: %v", err)
	}

	secondExecution := execute(volumeserver.SessionID{0x92}, 2)
	var prepareTwo *authoritypb.VisibilityEvent
	select {
	case got := <-advanced:
		if got.err != nil {
			t.Fatalf("combined acknowledgment replay: %v", got.err)
		}
		prepareTwo = got.event
	case <-ctx.Done():
		t.Fatal("combined acknowledgment replay did not return its successor")
	}
	if prepareTwo.GetCursor().GetSequence() != 3 || prepareTwo.GetCursor().GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE {
		t.Fatalf("successor after replay = %+v, want PREPARE(3)", prepareTwo)
	}
	completeTwo, err := client.NextVisibilityAfterAck(ctx, prepareTwo.GetCursor(), false)
	if err != nil || completeTwo.GetCursor().GetSequence() != 3 || completeTwo.GetCursor().GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
		t.Fatalf("second combined advance = (%+v, %v), want COMPLETE(3)", completeTwo, err)
	}
	if err := client.AckVisibility(ctx, completeTwo.GetCursor()); err != nil {
		t.Fatalf("final visibility acknowledgment: %v", err)
	}
	if err := <-secondExecution; err != nil {
		t.Fatalf("second mutation after replay: %v", err)
	}
	if got := handler.completeOneAttempts.Load(); got != 2 {
		t.Fatalf("first-mutation COMPLETE(2) combined attempts = %d, want exactly lost request plus one replay", got)
	}
	keepAlive, err := client.CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if err != nil || keepAlive.GetErrno() != 0 {
		t.Fatalf("session after duplicate accepted Ack = (%+v, %v), want live", keepAlive, err)
	}
	select {
	case <-client.SessionDone():
		t.Fatalf("idempotent combined acknowledgment replay fenced the client: %v", client.SessionError())
	default:
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
