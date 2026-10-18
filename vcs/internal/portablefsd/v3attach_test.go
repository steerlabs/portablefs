package portablefsd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/mountrecord"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// v3TestPKI is one private trust domain: a CA, an authority server identity
// for "localhost", and a mount client identity — the same three artifacts the
// production manager issues.
type v3TestPKI struct {
	ca            *x509.Certificate
	caKey         ed25519.PrivateKey
	caPEM         string
	caSHA256      string
	serverTLS     *tls.Config
	clientCertPEM string
	clientKeyPEM  string
}

func newV3TestPKI(t *testing.T) v3TestPKI {
	t.Helper()
	now := time.Now()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PortableFS v3 test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, name string, usages []x509.ExtKeyUsage, dns []string) (tls.Certificate, string, string) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: dns,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return cert, string(certPEM), string(keyPEM)
	}
	serverCert, _, _ := issue(2, "authority", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	_, clientCertPEM, clientKeyPEM := issue(3, "mount", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	caSum := sha256.Sum256([]byte(caPEM))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return v3TestPKI{
		ca: ca, caKey: caKey, caPEM: caPEM,
		caSHA256: hex.EncodeToString(caSum[:]),
		serverTLS: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		},
		clientCertPEM: clientCertPEM,
		clientKeyPEM:  clientKeyPEM,
	}
}

func (pki v3TestPKI) enrollmentCertificateForClientKey(t *testing.T, enrollmentID string, now time.Time) (string, time.Time) {
	t.Helper()
	keyBlock, rest := pem.Decode([]byte(pki.clientKeyPEM))
	if keyBlock == nil || len(rest) != 0 {
		t.Fatal("test client key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("test client key is not Ed25519")
	}
	identity, err := url.Parse("spiffe://portablefs/mount-enrollment/" + enrollmentID)
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: enrollmentID},
		NotBefore: now.Add(-time.Minute), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{identity},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, pki.ca, key.Public(), pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), expires
}

// v3TestAuthority is an in-process strict authority behind the real
// authorityrpc server transport: mutual TLS, the full Hello/Attach handshake,
// and enough of the operation surface for the daemon's v3 data plane.
type v3TestAuthority struct {
	epoch           []byte
	session         []byte
	leaseMillis     uint64
	maxFskitWrite   uint64
	mountEnrollment bool
	// omitDirectWrite/omitDurableMutations/omitBatchedClose model an
	// authority that predates the FSKit direct-write, durable-mutation, and
	// FSKit CloseBatch contracts.
	omitDirectWrite              bool
	omitDurableMutations         bool
	omitBatchedClose             bool
	omitVersionedMetadata        bool
	initialAuthorizationDeadline int64
	renewedAuthorizationDeadline int64
	releaseStarted               chan struct{}
	releaseFinish                chan struct{}
	releaseErrno                 int32
	detachErrno                  int32

	mu               sync.Mutex
	keepAliveErrno   int32
	keepAliveHook    func(context.Context, *authoritypb.Request)
	statfsNameMax    uint32
	attach           *authoritypb.AttachRequest
	detach           *authoritypb.DetachRequest
	lookups          int
	statfsCalls      int
	reauthorizations int
}

var v3TestNeverTerminal = make(chan struct{})

func newV3TestAuthority() *v3TestAuthority {
	return &v3TestAuthority{
		epoch:       bytes.Repeat([]byte{0x5a}, 16),
		session:     bytes.Repeat([]byte{0x6b}, 16),
		leaseMillis: 30_000,

		statfsNameMax: 255,
	}
}

func (h *v3TestAuthority) Epoch() []byte                                       { return append([]byte(nil), h.epoch...) }
func (h *v3TestAuthority) RegisterSessionEndHook(func(volumeserver.SessionID)) {}
func (h *v3TestAuthority) SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return volumeserver.SessionStateProvisional, true
}
func (h *v3TestAuthority) SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool) {
	return v3TestNeverTerminal, true
}

func (h *v3TestAuthority) Bounds() authorityrpc.TransportBounds {
	return authorityrpc.TransportBounds{
		MaxFrame:        v3AttachMaxFrame,
		MaxRequestFrame: (1 << 20) + authorityrpc.FramePayloadReserve,
		MaxInFlight:     v3AttachMaxInFlight,
	}
}

func (h *v3TestAuthority) recordedAttach() *authoritypb.AttachRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.attach
}

func (h *v3TestAuthority) recordedDetach() *authoritypb.DetachRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.detach
}

func (h *v3TestAuthority) authorityCalls() (lookups, statfs int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lookups, h.statfsCalls
}

func (h *v3TestAuthority) reauthorizationCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reauthorizations
}

func (h *v3TestAuthority) failKeepAlives() {
	h.mu.Lock()
	h.keepAliveErrno = 5
	h.mu.Unlock()
}

func (h *v3TestAuthority) rootItem() *authoritypb.Item {
	return &authoritypb.Item{
		Token: bytes.Repeat([]byte{0x31}, 16), StableIdentity: bytes.Repeat([]byte{0x42}, 16),
		Attr: &authoritypb.Attr{Kind: authoritypb.Attr_DIRECTORY, Inode: 1, Mode: 0o755, Nlink: 1},
	}
}

func (h *v3TestAuthority) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch()}
	switch req.GetBody().(type) {
	case *authoritypb.Request_Hello:
		bounds := h.Bounds()
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{
			ProtocolMajor: authorityrpc.ProtocolMajor,
			Role:          req.GetHello().GetRole(), ConnectionSetId: append([]byte(nil), req.GetHello().GetConnectionSetId()...),
			FrontendProfile: req.GetHello().GetFrontendProfile(),
			MaxFrameBytes:   bounds.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20,
			MaxInFlight: uint32(bounds.MaxInFlight),
		}}
	case *authoritypb.Request_Attach:
		h.mu.Lock()
		h.attach = req.GetAttach()
		h.mu.Unlock()
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: append([]byte(nil), h.session...), Generation: 1,
			ResumeSecret: make([]byte, 32), ProvisionalDeadlineUnixNanos: time.Now().Add(time.Minute).UnixNano(),
		}}
	case *authoritypb.Request_Activate:
		response.Body = &authoritypb.Response_Activate{Activate: &authoritypb.ActivateReply{
			Root: h.rootItem(),

			SessionLeaseMilliseconds:       h.leaseMillis,
			AuthorizationDeadlineUnixNanos: h.initialAuthorizationDeadline,
			RoutesRevision:                 bytes.Repeat([]byte{0xab}, 32),
			State:                          authoritypb.SessionState_SESSION_STATE_ACTIVE,
			Purpose:                        authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
			FrontendProfile:                authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE,
		}}
	case *authoritypb.Request_Resume:
		response.Body = &authoritypb.Response_Resume{Resume: &authoritypb.ResumeReply{State: authoritypb.SessionState_SESSION_STATE_ACTIVE}}
	case *authoritypb.Request_AbortAttach:
		response.Body = &authoritypb.Response_AbortAttach{AbortAttach: &authoritypb.AbortAttachReply{State: authoritypb.SessionState_SESSION_STATE_ABORTED}}
	case *authoritypb.Request_Reauthorize:
		h.mu.Lock()
		h.reauthorizations++
		h.mu.Unlock()
		response.Body = &authoritypb.Response_Reauthorize{Reauthorize: &authoritypb.ReauthorizeReply{
			Sequence: req.GetReauthorize().GetSequence(), AuthorizationDeadlineUnixNanos: h.renewedAuthorizationDeadline,
		}}
	case *authoritypb.Request_KeepAlive:
		h.mu.Lock()
		response.Errno = h.keepAliveErrno
		hook := h.keepAliveHook
		h.mu.Unlock()
		if hook != nil {
			hook(ctx, req)
		}
		if response.Errno == 0 {
			response.SessionValidForNanos = uint64(min(time.Duration(h.leaseMillis)*time.Millisecond, authorityrpc.MaxCacheProof))
		}
	case *authoritypb.Request_StatFs:
		h.mu.Lock()
		h.statfsCalls++
		nameMax := h.statfsNameMax
		h.mu.Unlock()
		response.Body = &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{
			BlockSize: 4096, Blocks: 1 << 20, BlocksAvailable: 1 << 19, NameMax: nameMax,
		}}
	case *authoritypb.Request_Lookup:
		h.mu.Lock()
		h.lookups++
		h.mu.Unlock()
		if mutation := req.GetMutation(); mutation != nil {
			response.Mutation = &authoritypb.MutationState{
				Slot: mutation.GetSlot(), AcceptedSequence: mutation.GetSequence(),
			}
		}
		response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{
			Item: &authoritypb.Item{
				Token: bytes.Repeat([]byte{0x33}, 16), StableIdentity: bytes.Repeat([]byte{0x44}, 16),
				Attr:          &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2, Mode: 0o644, Nlink: 1},
				ObjectVersion: 1, SnapshotSequence: 1,
			},
		}}
	case *authoritypb.Request_CloseBatch:
		if h.releaseStarted != nil {
			close(h.releaseStarted)
		}
		if h.releaseFinish != nil {
			select {
			case <-h.releaseFinish:
			case <-ctx.Done():
			}
		}
		response.Mutation = &authoritypb.MutationState{Slot: req.GetMutation().GetSlot(), AcceptedSequence: req.GetMutation().GetSequence()}
		response.Errno = h.releaseErrno
		if response.Errno == 0 {
			results := make([]*authoritypb.CloseBatchResult, len(req.GetCloseBatch().GetCloses()))
			for i := range results {
				results[i] = &authoritypb.CloseBatchResult{Retired: true}
			}
			response.Body = &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: results}}
		}
	case *authoritypb.Request_Detach:
		response.Errno = h.detachErrno
		h.mu.Lock()
		h.detach = req.GetDetach()
		h.mu.Unlock()
	case *authoritypb.Request_Cancel:
	default:
		if req.GetMutation() != nil {
			response.Mutation = &authoritypb.MutationState{
				Slot: req.GetMutation().GetSlot(), AcceptedSequence: req.GetMutation().GetSequence(),
			}
			return response
		}
		response.Errno = 95
	}
	return response
}

func startV3TestAuthority(t *testing.T, handler *v3TestAuthority, serverTLS *tls.Config) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &authorityrpc.Server{
		Handler: handler, MaxFrame: v3AttachMaxFrame, MaxInFlight: v3AttachMaxInFlight,
		MaxConnections: 8, MaxFrameBytesInFlight: 64 << 20,
		HandshakeTimeout: 5 * time.Second, IdleTimeout: time.Minute, WriteTimeout: 5 * time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener, serverTLS) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("v3 test authority: %v", err)
		}
	})
	return listener.Addr().String()
}

func v3TestEnsureRequest(address string, pki v3TestPKI, mountPath string) ensureAttachRequest {
	req := ensureAttachRequest{
		VolumeID:            "vol-v3",
		AuthorityURL:        address,
		AuthToken:           "capability",
		DataPlaneTransport:  "tls-private-ca",
		DataPlaneServerName: "localhost",
		TLSCAPEM:            pki.caPEM,
		TLSCASHA256:         pki.caSHA256,
		MountPath:           mountPath,
		V3: &v3AttachRequest{
			ClientCertPEM: pki.clientCertPEM,
			ClientKeyPEM:  pki.clientKeyPEM,

			RoutesRevision: strings.Repeat("ab", 32),
		},
	}
	req.observePreKernelMountAbsence = func(context.Context) (*authoritypb.MountAbsenceProof, error) {
		return &authoritypb.MountAbsenceProof{
			ObservedUnixNanos: time.Now().UnixNano(),
			Observation:       []byte("test getfsstat exact attach source present=false stage=startup"),
			Component:         "portablefsd-test/exact-mount-inventory",
		}, nil
	}
	return req
}

func ensureV3TestAttach(t *testing.T, r *registry, req ensureAttachRequest) *attach {
	t.Helper()
	a, created, err := r.ensure(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("v3 ensure did not create the attach")
	}
	t.Cleanup(func() { a.fenceV3(errors.New("test cleanup")) })
	return a
}

func TestV3AutomaticEnrollmentOwnsRenewalWithoutManualFallback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newV3TestPKI(t)
	enrollmentID := "22222222-2222-4222-8222-222222222222"
	enrollmentCertificate, enrollmentExpires := pki.enrollmentCertificateForClientKey(t, enrollmentID, now)
	initialDeadline := now.Add(2 * time.Minute)
	renewedDeadline := now.Add(10 * time.Minute)
	handler := newV3TestAuthority()
	handler.mountEnrollment = true
	handler.initialAuthorizationDeadline = initialDeadline.UnixNano()
	handler.renewedAuthorizationDeadline = renewedDeadline.UnixNano()
	authorityAddress := startV3TestAuthority(t, handler, pki.serverTLS)

	refreshes := make(chan struct{}, 1)
	managerHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || len(request.TLS.PeerCertificates[0].URIs) != 1 ||
			request.TLS.PeerCertificates[0].URIs[0].String() != "spiffe://portablefs/mount-enrollment/"+enrollmentID {
			http.Error(writer, "wrong enrollment identity", http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(request.URL.Path, "/reauthorizations"):
			var body controlplane.RefreshMountEnrollmentRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.Sequence != 1 || body.ClientCSRPEM == "" {
				http.Error(writer, "bad refresh", http.StatusBadRequest)
				return
			}
			wantSession := base64.RawURLEncoding.EncodeToString(handler.session)
			if body.SessionID != wantSession {
				http.Error(writer, "wrong session", http.StatusBadRequest)
				return
			}
			select {
			case refreshes <- struct{}{}:
			default:
			}
			_ = json.NewEncoder(writer).Encode(controlplane.MountAuthorization{
				VolumeID: "vol-v3", AuthorityEndpoint: authorityAddress, AuthorityServerName: "localhost",
				AuthorityCAPEM: pki.caPEM, ClientCertificatePEM: pki.clientCertPEM, Capability: "renewed-capability",
				Access: []string{"write"}, ExpiresUnix: renewedDeadline.Unix(), CertificateExpiresUnix: enrollmentExpires.Unix(),
				AuthorityGeneration: 7, SessionID: body.SessionID, Sequence: body.Sequence, ReleaseID: "test",
			})
		case strings.HasSuffix(request.URL.Path, "/close"):
			_ = json.NewEncoder(writer).Encode(controlplane.MountEnrollment{ID: enrollmentID, State: controlplane.MountEnrollmentClosed})
		default:
			http.NotFound(writer, request)
		}
	})
	manager := httptest.NewUnstartedServer(managerHandler)
	manager.TLS = pki.serverTLS.Clone()
	manager.StartTLS()
	t.Cleanup(manager.Close)

	req := v3TestEnsureRequest(authorityAddress, pki, "/Volumes/PortableFSV3Automatic")
	req.AuthTokenExpiresAtMs = initialDeadline.UnixMilli()
	req.V3.Enrollment = &v3MountEnrollmentRequest{
		ManagerURL: manager.URL, ManagerServerName: "localhost", ManagerCAPEM: pki.caPEM,
		EnrollmentID: enrollmentID, EnrollmentCertificatePEM: enrollmentCertificate,
		AuthorityGeneration:             7,
		InitialAuthorizationExpiresAtMs: initialDeadline.UnixMilli(),
	}
	// Automatic enrollment uses the same operational protocol-7 FSKit profile
	// and registry path as an ordinary direct attach.
	stateDir := privateTestDir(t)
	r := newRegistry(stateDir)
	a := ensureV3TestAttach(t, r, req)
	t.Cleanup(a.lifeCancel)

	select {
	case <-refreshes:
	case <-time.After(5 * time.Second):
		t.Fatal("portablefsd automatic owner never refreshed its enrollment")
	}
	deadline := time.Now().Add(5 * time.Second)
	var installedDeadline int64
	for {
		a.mu.RLock()
		installedDeadline = a.authorizationDeadlineAtMs
		a.mu.RUnlock()
		if installedDeadline == renewedDeadline.UnixMilli() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("portablefsd automatic owner never installed the renewed authority grant: calls=%d deadline=%d want=%d",
				handler.reauthorizationCalls(), installedDeadline, renewedDeadline.UnixMilli())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if handler.reauthorizationCalls() == 0 {
		t.Fatal("automatic status advanced without installing the authority grant")
	}
	logPath := mountrecord.LogPath(stateDir, req.MountPath)
	deadline = time.Now().Add(5 * time.Second)
	for {
		body, readErr := os.ReadFile(logPath)
		if readErr == nil && bytes.Contains(body, []byte(`"kind":"renewal.succeeded"`)) &&
			bytes.Contains(body, []byte(`"component":"macos-fskit"`)) &&
			bytes.Contains(body, []byte(`"mountIdentity":"`+a.ref+`"`)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("per-mount renewal log = %q, err = %v", body, readErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, handled, err := a.rotateLiveCredential(context.Background(), "manual", renewedDeadline.UnixMilli(), 2, pki.clientCertPEM, false); !handled || err == nil || !strings.Contains(err.Error(), "automatic reauthorization owner") {
		t.Fatalf("manual fallback against automatic owner: handled=%t err=%v", handled, err)
	}
	if found, err := r.delete(context.Background(), a.ref, true); err != nil || !found {
		t.Fatalf("detach automatic renewal owner: found=%t err=%v", found, err)
	}
	select {
	case <-a.renewalDone:
	default:
		t.Fatal("detach returned before the automatic renewal owner stopped")
	}
	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"kind":"renewal.stopped"`)) {
		t.Fatalf("per-mount log has no terminal owner event: %q", body)
	}
}

func TestV3ManualReauthorizationUsesAuthorityDeadline(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki := newV3TestPKI(t)
	initialDeadline := now.Add(2 * time.Minute)
	authorityDeadline := now.Add(10 * time.Minute)
	callerClaimedDeadline := now.Add(30 * time.Minute)
	handler := newV3TestAuthority()
	handler.mountEnrollment = true
	handler.initialAuthorizationDeadline = initialDeadline.UnixNano()
	handler.renewedAuthorizationDeadline = authorityDeadline.UnixNano()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	req := v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3ManualReauthorization")
	req.AuthTokenExpiresAtMs = initialDeadline.UnixMilli()
	a := ensureV3TestAttach(t, r, req)

	done, handled, err := a.rotateLiveCredential(
		context.Background(), "renewed-capability", callerClaimedDeadline.UnixMilli(), 1, pki.clientCertPEM, false,
	)
	if err != nil || !handled || !done {
		t.Fatalf("manual reauthorization = done %t, handled %t, error %v", done, handled, err)
	}
	a.credMu.RLock()
	installedCredentialDeadline := a.tokenExpiresAtMs
	a.credMu.RUnlock()
	if installedCredentialDeadline != authorityDeadline.UnixMilli() {
		t.Fatalf("installed credential deadline = %d, want authority deadline %d (caller claimed %d)",
			installedCredentialDeadline, authorityDeadline.UnixMilli(), callerClaimedDeadline.UnixMilli())
	}
	if got := a.authorizationDeadline(); got != authorityDeadline.UnixMilli() {
		t.Fatalf("reported authorization deadline = %d, want %d", got, authorityDeadline.UnixMilli())
	}
	status := a.status()
	if status.AuthorizationDeadlineAtMs != authorityDeadline.UnixMilli() || status.LastReauthorizationAtMs == 0 {
		t.Fatalf("manual reauthorization status = %+v", status)
	}
}

func TestV3AttachResolveCarriesContractAndOpsRouteToV3Backend(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3"))

	// The daemon — not the frontend — declared the strict barrier contract.
	admitted := handler.recordedAttach()
	if admitted == nil ||
		admitted.GetFrontendProfile() != authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE ||
		hex.EncodeToString(admitted.GetRoutesRevision()) != strings.Repeat("ab", 32) ||
		string(admitted.GetAccessToken()) != "capability" {
		t.Fatalf("authority admitted contract %+v", admitted)
	}
	if !a.hasLiveVolume() {
		t.Fatal("v3 attach did not install its authority session")
	}

	// The whole pfslocal surface through the real frontend connection.
	s := NewServer(Config{Version: "portablefsd-v3-test"})
	s.registry = r
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	fc := &frontendConn{srv: s, conn: serverConn}
	serveDone := make(chan struct{})
	go func() { fc.serve(ctx); close(serveDone) }()
	t.Cleanup(func() {
		cancel()
		_ = clientConn.Close()
		<-serveDone
	})
	client := &pfsTestClient{t: t, conn: clientConn}
	client.call(&pfslocal.Hello{ProtocolMajor: pfslocal.ProtocolMajor, ClientName: "v3-test"})
	resolvedAny := client.call(&pfslocal.ResolveRequest{AttachRef: a.ref})
	resolved, ok := resolvedAny.(*pfslocal.ResolveReply)
	if !ok {
		t.Fatalf("resolve reply = %T", resolvedAny)
	}
	if resolved.Root.ItemID != v3RootItemID ||
		resolved.Root.StableIdentity != ([16]byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}) {
		t.Fatalf("v3 resolve root = %+v", resolved)
	}
	// Binding the visibility subscriber is what admits strict operations.
	client.call(&pfslocal.SubscribeEventsRequest{})
	d := a.v3Backend()
	if d == nil {
		t.Fatal("no v3 data plane installed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for d.bridge.readyForOperations() != nil {
		if time.Now().After(deadline) {
			t.Fatal("v3 visibility subscriber never bound")
		}
		time.Sleep(5 * time.Millisecond)
	}

	lookupAny := client.call(&pfslocal.LookupRequest{Dir: resolved.Root, Name: []byte("file")})
	lookup, ok := lookupAny.(*pfslocal.LookupReply)
	if !ok {
		t.Fatalf("lookup reply = %T", lookupAny)
	}
	if lookup.Attr.Item.StableIdentity != ([16]byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}) {
		t.Fatalf("lookup attr = %+v", lookup.Attr)
	}
	statfsAny := client.call(&pfslocal.StatfsRequest{})
	statfs, ok := statfsAny.(*pfslocal.StatfsReply)
	if !ok || statfs.BlockSize != 4096 {
		t.Fatalf("statfs reply = %#v", statfsAny)
	}
	lookups, statfsCalls := handler.authorityCalls()
	// The attach preflight issues one StatFS of its own; the frontend requests
	// must have added theirs, which is what proves the ops surface is served by
	// the authority-v3 backend.
	if lookups == 0 || statfsCalls < 2 {
		t.Fatalf("authority served lookups=%d statfs=%d", lookups, statfsCalls)
	}
}

func TestV3AttachEnsureRefusesUnsupportedShapes(t *testing.T) {
	pki := newV3TestPKI(t)
	base := v3TestEnsureRequest("127.0.0.1:1", pki, "/Volumes/PortableFSV3Refuse")
	for name, mutate := range map[string]func(*ensureAttachRequest){
		"plaintext": func(req *ensureAttachRequest) {
			req.DataPlaneTransport = "plaintext"
			req.DataPlaneServerName, req.TLSCAPEM, req.TLSCASHA256 = "", "", ""
		},
		"missing capability": func(req *ensureAttachRequest) { req.AuthToken = "" },
		"routes revision":    func(req *ensureAttachRequest) { req.V3.RoutesRevision = "AB" },
		"identity":           func(req *ensureAttachRequest) { req.V3.ClientKeyPEM = "not a key" },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRegistry(privateTestDir(t))
			req := base
			v3 := *base.V3
			req.V3 = &v3
			mutate(&req)
			if _, _, err := r.ensure(context.Background(), req); err == nil {
				t.Fatal("unsupported v3 ensure shape was accepted")
			}
			if len(r.list()) != 0 {
				t.Fatal("refused v3 ensure left an attach registered")
			}
		})
	}
}

func TestV3AttachTransportModeIsEnforcedExactly(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)

	t.Run("foreign CA refused", func(t *testing.T) {
		r := newRegistry(privateTestDir(t))
		foreign := newV3TestPKI(t)
		req := v3TestEnsureRequest(address, foreign, "/Volumes/PortableFSV3WrongCA")
		if _, _, err := r.ensure(context.Background(), req); err == nil {
			t.Fatal("an authority outside the declared private CA was accepted")
		}
		if len(r.list()) != 0 {
			t.Fatal("failed v3 attach stayed registered")
		}
	})
	t.Run("wrong exact server name refused", func(t *testing.T) {
		r := newRegistry(privateTestDir(t))
		req := v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3WrongName")
		req.DataPlaneServerName = "other.example"
		if _, _, err := r.ensure(context.Background(), req); err == nil {
			t.Fatal("a certificate for a different exact name was accepted")
		}
		if len(r.list()) != 0 {
			t.Fatal("failed v3 attach stayed registered")
		}
	})
	if handler.recordedAttach() != nil {
		t.Fatal("a refused transport still reached the authority attach")
	}
}

// The daemon sends one ordinary WRITE per chunk and acknowledges FSKit
// mutations as durable, so an authority that lacks either contract must be
// refused before a mount exists, never served with weaker semantics.

func TestV3DataPlanePreflightFailureReleasesActiveSessionBeforeFSKitMount(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	// Zero NAME_MAX is an exact, post-ACTIVE constructor failure: the authority
	// session exists, but portablefsd has not exposed this attach to FSKit.
	handler.statfsNameMax = 0
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	req := v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3PreflightFailure")
	if _, _, err := r.ensure(context.Background(), req); err == nil || !strings.Contains(err.Error(), "NAME_MAX") {
		t.Fatalf("v3 preflight failure = %v, want NAME_MAX refusal", err)
	}
	if len(r.list()) != 0 {
		t.Fatal("failed pre-FSKit v3 attach stayed registered")
	}
	proof := handler.recordedDetach()
	if proof == nil || proof.GetMountAbsence() == nil ||
		proof.GetMountAbsence().GetObservedUnixNanos() == 0 ||
		proof.GetMountAbsence().GetComponent() != "portablefsd-test/exact-mount-inventory" ||
		!strings.Contains(string(proof.GetMountAbsence().GetObservation()), "stage=startup") {
		t.Fatalf("pre-FSKit ACTIVE cleanup delivered proof %+v", proof)
	}
}

func TestV3DetachDeliversMountAbsenceProofBeforeRelease(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3Detach"))

	var mu sync.Mutex
	unmounted := false
	detachesBeforeUnmount := 0
	var kernelDetachModes []bool
	ops := fskitKernelOps{
		present: func(path, ref string) (bool, error) {
			if path != a.mountPath || ref != a.ref {
				t.Errorf("unexpected exact identity %q %q", path, ref)
			}
			mu.Lock()
			defer mu.Unlock()
			return !unmounted, nil
		},
		unmountExact: func(path, ref string, force bool) error {
			mu.Lock()
			defer mu.Unlock()
			kernelDetachModes = append(kernelDetachModes, force)
			unmounted = true
			if handler.recordedDetach() != nil {
				detachesBeforeUnmount++
			}
			return nil
		},
	}
	found, err := r.unmountFSKitWith(a.ref, false, ops)
	if err != nil || !found {
		t.Fatalf("v3 unmount=(%v,%v)", found, err)
	}
	if detachesBeforeUnmount != 0 {
		t.Fatal("mount-absence proof reached the authority before the kernel detach")
	}
	if len(kernelDetachModes) != 1 || kernelDetachModes[0] {
		t.Fatalf("kernel detach modes=%v, want one unforced attempt", kernelDetachModes)
	}
	sent := handler.recordedDetach()
	proof := sent.GetMountAbsence()
	if sent == nil || proof == nil ||
		proof.GetComponent() != v3DetachProofComponent ||
		proof.GetObservedUnixNanos() == 0 ||
		!strings.Contains(string(proof.GetObservation()), a.mountPath) {
		t.Fatalf("authority detach evidence = %+v", sent)
	}
	if r.get(a.ref) != nil {
		t.Fatal("detached v3 attach is still registered")
	}
	if d := a.v3Backend(); d == nil || !errors.Is(d.terminalError(), errV3AttachDetached) {
		t.Fatal("clean v3 detach did not terminate the data plane with the detach cause")
	}
	if !a.isDetached() {
		t.Fatal("v3 attach did not publish its terminal detach state")
	}
}

func TestV3NormalDetachNeverForcesPastASynchronizeFailure(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	a := ensureV3TestAttach(t, r, v3TestEnsureRequest(
		address,
		pki,
		"/Volumes/PortableFSV3SyncFailure",
	))

	var kernelDetachModes []bool
	found, err := r.unmountFSKitWith(a.ref, false, fskitKernelOps{
		present: func(_, _ string) (bool, error) { return true, nil },
		unmountExact: func(_, _ string, force bool) error {
			kernelDetachModes = append(kernelDetachModes, force)
			return syscall.EIO
		},
	})
	if !found || !errors.Is(err, syscall.EIO) {
		t.Fatalf("v3 normal unmount=(%v,%v), want exact sync failure", found, err)
	}
	if len(kernelDetachModes) != 1 || kernelDetachModes[0] {
		t.Fatalf("kernel detach modes=%v, want one synchronized attempt", kernelDetachModes)
	}
	if handler.recordedDetach() != nil {
		t.Fatal("sync failure produced a false mount-absence proof")
	}
	if r.get(a.ref) == nil || a.isDetached() {
		t.Fatal("sync failure did not leave the v3 attach live and retryable")
	}
}

func TestV3DetachWithoutAbsenceProofEndsFenced(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3Fence"))

	var mu sync.Mutex
	unmounted := false
	ops := fskitKernelOps{
		present: func(_, _ string) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			if unmounted {
				return false, errors.New("mount table unreadable")
			}
			return true, nil
		},
		unmountExact: func(_, _ string, _ bool) error {
			mu.Lock()
			defer mu.Unlock()
			unmounted = true
			return nil
		},
	}
	found, err := r.unmountFSKitWith(a.ref, false, ops)
	if !found || err == nil {
		t.Fatalf("unprovable v3 detach = (%v, %v), want a definite refusal", found, err)
	}
	if handler.recordedDetach() != nil {
		t.Fatal("an unproven absence still reached the authority as evidence")
	}
	if r.get(a.ref) == nil {
		t.Fatal("unproven detach silently released the attach")
	}
	d := a.v3Backend()
	if d == nil || d.terminalError() == nil {
		t.Fatal("unprovable mount absence did not fence the strict session")
	}

	// A retry that can finally observe the absence completes the release, and
	// the fenced session — already dead at the authority — is never presented
	// with late evidence.
	mu.Lock()
	unmounted = false
	mu.Unlock()
	absent := fskitKernelOps{
		present:      func(_, _ string) (bool, error) { return false, nil },
		unmountExact: func(_, _ string, _ bool) error { return errors.New("nothing to detach") },
	}
	if found, err := r.unmountFSKitWith(a.ref, false, absent); err == nil || !found {
		t.Fatalf("fenced v3 detach retry = (%v, %v)", found, err)
	}
	if r.get(a.ref) != nil || !a.isDetached() {
		t.Fatal("completed fenced teardown remained registered")
	}
	if handler.recordedDetach() != nil {
		t.Fatal("a fenced session delivered detach evidence")
	}
}

func TestV3FrontendLossDeliversAbsenceProofBeforeClosingAuthority(t *testing.T) {
	for name, initiallyPresent := range map[string]bool{"already-absent": false, "mounted": true} {
		t.Run(name, func(t *testing.T) {
			pki := newV3TestPKI(t)
			handler := newV3TestAuthority()
			address := startV3TestAuthority(t, handler, pki.serverTLS)
			r := newRegistry(privateTestDir(t))
			a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/PortableFSFrontendLoss"))
			d := a.v3Backend()
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			done := make(chan error, 1)
			go func() { done <- d.bridge.run(ctx, func(*pfslocal.Event) error { return nil }) }()
			deadline := time.Now().Add(time.Second)
			for {
				d.bridge.mu.Lock()
				subscribed := d.bridge.subscribed
				d.bridge.mu.Unlock()
				if subscribed {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("frontend did not subscribe")
				}
				time.Sleep(time.Millisecond)
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("frontend loss = %v", err)
			}
			if d.terminalError() == nil {
				t.Fatal("frontend loss did not stop local serving")
			}
			select {
			case <-d.client.SessionDone():
				t.Fatal("frontend loss closed the authority before the supervisor observed unmount")
			default:
			}
			mounted := initiallyPresent
			ops := fskitKernelOps{
				present: func(_, _ string) (bool, error) { return mounted, nil },
				unmountExact: func(_, _ string, force bool) error {
					if !mounted || !force {
						return errors.New("terminal teardown must force only the existing mount")
					}
					mounted = false
					return nil
				},
			}
			if found, err := r.unmountFSKitWith(a.ref, true, ops); !found || err != nil {
				t.Fatalf("retire frontend loss = (%v, %v)", found, err)
			}
			if detach := handler.recordedDetach(); detach == nil || detach.GetMountAbsence() == nil {
				t.Fatal("authority did not receive the exact session's mount-absence proof")
			}
			if r.get(a.ref) != nil {
				t.Fatal("proved retirement left the attach registered")
			}
			select {
			case <-d.client.SessionDone():
			default:
				t.Fatal("proved retirement did not close its authority transport")
			}

		})
	}
}

func TestV3TerminalSessionMarksAttachTerminal(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	req := v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3Terminal")
	a := ensureV3TestAttach(t, r, req)
	d := a.v3Backend()
	if d == nil {
		t.Fatal("no v3 data plane installed")
	}
	handler.failKeepAlives()
	deadline := time.Now().Add(10 * time.Second)
	for d.terminalError() == nil {
		if time.Now().After(deadline) {
			t.Fatal("failed liveness did not terminate the v3 session")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, eno := a.v3RootReply(); eno != darwinENOTCONN {
		t.Fatalf("terminal v3 resolve errno=%d, want %d", eno, darwinENOTCONN)
	}
	status := a.status()
	if status.State != "degraded" || !strings.Contains(status.LastError, "TERMINAL") {
		t.Fatalf("terminal v3 status = %+v", status)
	}
	// The revocation watchdog branches on the boolean, never on the prose.
	if !status.SessionTerminal {
		t.Fatalf("terminal v3 status did not set the machine-readable verdict: %+v", status)
	}
	// Never a silent retry, never a fallback: the terminal attach refuses
	// reactivation and names the unmount as the one exit.
	if err := a.activate(context.Background(), "fresh-capability", 0, 1, ""); err == nil ||
		!strings.Contains(err.Error(), "unmount") {
		t.Fatalf("terminal v3 attach reactivation = %v, want an unmount-directing refusal", err)
	}
}

func TestV3AttachRevivesForExactUnmountOnly(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	stateDir := privateTestDir(t)
	first := newRegistry(stateDir)
	a := ensureV3TestAttach(t, first, v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3Revive"))
	ref := a.ref
	// The previous daemon process is gone; its strict session dies with it.
	a.fenceV3(errors.New("previous daemon process exited"))

	revived := newRegistry(stateDir)
	if revived.loadErr != nil {
		t.Fatal(revived.loadErr)
	}
	b := revived.get(ref)
	if b == nil || b.v3Config == nil || !b.v3Config.revived {
		t.Fatalf("revived v3 attach = %+v", b)
	}
	if err := b.activate(context.Background(), "capability", 0, 1, ""); err == nil ||
		!strings.Contains(err.Error(), "unmount") {
		t.Fatalf("revived v3 activation = %v, want an unmount-directing refusal", err)
	}
	if _, eno := b.v3RootReply(); eno != darwinEIO {
		t.Fatalf("revived v3 resolve errno=%d, want %d", eno, darwinEIO)
	}
	found, err := revived.unmountFSKitWith(ref, false, fskitKernelOps{
		present:      func(_, _ string) (bool, error) { return false, nil },
		unmountExact: func(_, _ string, _ bool) error { return errors.New("nothing to detach") },
	})
	if err != nil || !found {
		t.Fatalf("revived v3 unmount=(%v,%v)", found, err)
	}
	if revived.get(ref) != nil {
		t.Fatal("revived v3 attach was not released by the exact unmount")
	}
}

// Only a release failure recorded before transfer is a separate diagnostic.
// Accepted exact absence also retires forming and in-flight release obligations.
func TestV3DetachSeparatesReleaseDiagnosticsFromAcceptedAbsence(t *testing.T) {
	for _, test := range []struct {
		name    string
		wantErr bool
		inject  func(*v3ReleaseOwner)
	}{
		{name: "sticky-release-failure", wantErr: true, inject: func(r *v3ReleaseOwner) {
			r.failure = errors.New("injected release failure")
		}},
		{name: "in-flight", inject: func(r *v3ReleaseOwner) {
			// DATA ownership does not delay or fail exact absence.
			r.running = true
		}},
		{name: "forming", inject: func(r *v3ReleaseOwner) {
			r.forming = &v3ReleaseBatch{reclaims: v3ReleaseTokens("item")}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pki := newV3TestPKI(t)
			handler := newV3TestAuthority()
			address := startV3TestAuthority(t, handler, pki.serverTLS)
			r := newRegistry(privateTestDir(t))
			a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3DrainFailure"))
			d := a.v3Backend()
			d.releases.mu.Lock()
			test.inject(d.releases)
			d.releases.mu.Unlock()
			var mu sync.Mutex
			unmounted := false
			ops := fskitKernelOps{
				present: func(string, string) (bool, error) {
					mu.Lock()
					defer mu.Unlock()
					return !unmounted, nil
				},
				unmountExact: func(string, string, bool) error {
					mu.Lock()
					defer mu.Unlock()
					unmounted = true
					return nil
				},
			}
			found, err := r.unmountFSKitWith(a.ref, false, ops)
			if !found || (err != nil) != test.wantErr || err != nil && !strings.Contains(err.Error(), "authority release cleanup") {
				t.Fatalf("unmount = (%v,%v), want release diagnostic=%t", found, err, test.wantErr)
			}
			if handler.recordedDetach().GetMountAbsence() == nil {
				t.Fatal("release cleanup withheld the exact absence proof")
			}
			if !a.isDetached() || d.terminalError() == nil {
				t.Fatal("local teardown did not complete")
			}
			if r.get(a.ref) != nil {
				t.Fatal("completed teardown remained registered")
			}
			reloaded := newRegistry(r.stateDir)
			if reloaded.loadErr != nil || reloaded.get(a.ref) != nil {
				t.Fatalf("registry removal was not durable: load=%v attach=%v", reloaded.loadErr, reloaded.get(a.ref))
			}
		})
	}
}

func TestV3ExactAbsenceUsesControlDespiteReleaseFailure(t *testing.T) {
	for _, name := range []string{"definite-refusal", "stalled-data", "proof-refused"} {
		t.Run(name, func(t *testing.T) {
			pki := newV3TestPKI(t)
			handler := newV3TestAuthority()
			handler.releaseStarted = make(chan struct{})
			if name == "definite-refusal" {
				handler.releaseErrno = errnos.EINVAL
			} else {
				handler.releaseFinish = make(chan struct{})
			}
			if name == "proof-refused" {
				handler.detachErrno = errnos.EPERM
			}
			address := startV3TestAuthority(t, handler, pki.serverTLS)
			r := newRegistry(privateTestDir(t))
			a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/PortableFSReleaseControl"))
			d := a.v3Backend()
			if err := d.releases.submit(v3ReleaseTokens("h"), nil); err != nil {
				t.Fatal(err)
			}
			<-handler.releaseStarted
			if name == "definite-refusal" {
				waitV3ReleasesIdle(t, d)
			}
			done := make(chan error, 1)
			go func() {
				_, err := r.unmountFSKitWith(a.ref, true, fskitKernelOps{present: func(string, string) (bool, error) { return false, nil }})
				done <- err
			}()
			select {
			case err := <-done:
				if name == "stalled-data" {
					if err != nil {
						t.Fatalf("accepted absence with transferred DATA release: %v", err)
					}
				} else {
					want := "authority release cleanup"
					if name == "proof-refused" {
						want = "deliver v3 mount-absence proof"
					}
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("detach result = %v, want %q", err, want)
					}
				}
			case <-time.After(2 * time.Second):
				t.Fatal("CONTROL absence proof waited for stalled DATA release")
			}
			if handler.recordedDetach().GetMountAbsence() == nil {
				t.Fatal("exact absence withheld")
			}
			if handler.releaseFinish != nil {
				close(handler.releaseFinish)
			}
			waitV3ReleasesIdle(t, d)
			if r.get(a.ref) != nil || !a.isDetached() {
				t.Fatal("completed detach remained registered")
			}
		})
	}
}
