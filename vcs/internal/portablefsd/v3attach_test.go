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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// v3TestPKI is one private trust domain: a CA, an authority server identity
// for "localhost", and a mount client identity — the same three artifacts the
// production manager issues.
type v3TestPKI struct {
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
		caPEM:    caPEM,
		caSHA256: hex.EncodeToString(caSum[:]),
		serverTLS: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		},
		clientCertPEM: clientCertPEM,
		clientKeyPEM:  clientKeyPEM,
	}
}

// v3TestAuthority is an in-process strict authority behind the real
// authorityrpc server transport: mutual TLS, the full Hello/Attach handshake,
// and enough of the operation surface for the daemon's v3 data plane.
type v3TestAuthority struct {
	epoch       []byte
	session     []byte
	leaseMillis uint64

	mu             sync.Mutex
	keepAliveErrno int32
	attach         *authoritypb.AttachRequest
	detach         *authoritypb.DetachRequest
	lookups        int
	statfsCalls    int
}

func newV3TestAuthority() *v3TestAuthority {
	return &v3TestAuthority{
		epoch:       bytes.Repeat([]byte{0x5a}, 16),
		session:     bytes.Repeat([]byte{0x6b}, 16),
		leaseMillis: 30_000,
	}
}

func (h *v3TestAuthority) Epoch() []byte { return append([]byte(nil), h.epoch...) }

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
			Features:      []string{"xfs-current-state", "session-exact-epoch", "direct-write"},
			MaxFrameBytes: bounds.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20,
			MaxInFlight: uint32(bounds.MaxInFlight),
		}}
	case *authoritypb.Request_Attach:
		h.mu.Lock()
		h.attach = req.GetAttach()
		h.mu.Unlock()
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: append([]byte(nil), h.session...), SessionGeneration: 1,
			ResumeSecret: make([]byte, 32), Root: h.rootItem(),
			Features: []string{
				"write-through", "no-history", "no-branches", "direct-io-no-file-mmap",
				"user-xattr-readonly", "single-principal", "distributed-posix-locks",
				"stable-item-identity", "readdir-plus-items", "volume-syncfs-barrier",
				"strict-two-phase-visibility",
			},
			SessionLeaseMilliseconds: h.leaseMillis,
		}}
	case *authoritypb.Request_KeepAlive:
		h.mu.Lock()
		response.Errno = h.keepAliveErrno
		h.mu.Unlock()
	case *authoritypb.Request_StatFs:
		h.mu.Lock()
		h.statfsCalls++
		h.mu.Unlock()
		response.Body = &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{
			BlockSize: 4096, Blocks: 1 << 20, BlocksAvailable: 1 << 19, NameMax: 255,
		}}
	case *authoritypb.Request_Lookup:
		h.mu.Lock()
		h.lookups++
		h.mu.Unlock()
		response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{
			Item: &authoritypb.Item{
				Token: bytes.Repeat([]byte{0x33}, 16), StableIdentity: bytes.Repeat([]byte{0x44}, 16),
				Attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2, Mode: 0o644, Nlink: 1},
			},
		}}
	case *authoritypb.Request_NextVisibility:
		// The strict long-poll: nothing becomes visible in these tests, so the
		// poll parks until the session ends.
		<-ctx.Done()
		response.Errno = 4
	case *authoritypb.Request_Detach:
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
	return ensureAttachRequest{
		VolumeID:            "vol-v3",
		AuthorityURL:        address,
		AuthToken:           "capability",
		DataPlaneTransport:  "tls-private-ca",
		DataPlaneServerName: "localhost",
		TLSCAPEM:            pki.caPEM,
		TLSCASHA256:         pki.caSHA256,
		MountPath:           mountPath,
		V3: &v3AttachRequest{
			ClientCertPEM:      pki.clientCertPEM,
			ClientKeyPEM:       pki.clientKeyPEM,
			CachedNameCapacity: 1024,
			RepairBudgetMillis: 60_000,
			CachePolicy:        v3CachePolicyMacOS26,
			RoutesRevision:     strings.Repeat("ab", 32),
		},
	}
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

func TestV3AttachResolveCarriesContractAndOpsRouteToV3Backend(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	t.Cleanup(r.stopPersister)
	a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3"))

	// The daemon — not the frontend — declared the strict barrier contract.
	admitted := handler.recordedAttach()
	if admitted == nil ||
		admitted.GetCoherenceProfile() != authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT ||
		admitted.GetCachedNameCapacity() != 1024 ||
		admitted.GetRepairBudgetMillis() != 60_000 ||
		admitted.GetNamespaceRepair() != authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE ||
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
	if resolved.Branch != "" || resolved.Root.ItemID != v3RootItemID ||
		resolved.Root.StableIdentity != ([16]byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}) {
		t.Fatalf("v3 resolve root = %+v", resolved)
	}
	contract := resolved.V3Coherence
	if contract == nil ||
		!bytes.Equal(contract.AuthorityEpoch, handler.epoch) ||
		!bytes.Equal(contract.SessionID, handler.session) ||
		contract.AuthorityProtocolMajor != authorityrpc.ProtocolMajor ||
		contract.CachePolicy != v3CachePolicyMacOS26 ||
		contract.RepairBudgetMillis != 60_000 {
		t.Fatalf("v3 resolve contract = %+v", contract)
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
		"branch": func(req *ensureAttachRequest) { req.Branch = "main" },
		"plaintext": func(req *ensureAttachRequest) {
			req.DataPlaneTransport = "plaintext"
			req.DataPlaneServerName, req.TLSCAPEM, req.TLSCASHA256 = "", "", ""
		},
		"missing capability": func(req *ensureAttachRequest) { req.AuthToken = "" },
		"local dirs":         func(req *ensureAttachRequest) { req.Options.LocalDirs = []string{"cache"} },
		"prefetch":           func(req *ensureAttachRequest) { req.Options.Prefetch = true },
		"disk cache":         func(req *ensureAttachRequest) { req.Options.DiskCacheMB = 1 },
		"cache policy":       func(req *ensureAttachRequest) { req.V3.CachePolicy = "automatic" },
		"routes revision":    func(req *ensureAttachRequest) { req.V3.RoutesRevision = "AB" },
		"repair budget":      func(req *ensureAttachRequest) { req.V3.RepairBudgetMillis = 0 },
		"name capacity":      func(req *ensureAttachRequest) { req.V3.CachedNameCapacity = 0 },
		"identity":           func(req *ensureAttachRequest) { req.V3.ClientKeyPEM = "not a key" },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRegistry(privateTestDir(t))
			t.Cleanup(r.stopPersister)
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
		t.Cleanup(r.stopPersister)
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
		t.Cleanup(r.stopPersister)
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

func TestV3DetachDeliversMountAbsenceProofBeforeRelease(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	t.Cleanup(r.stopPersister)
	a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3Detach"))

	var mu sync.Mutex
	unmounted := false
	detachesBeforeUnmount := 0
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
			if force {
				t.Error("normal v3 unmount reached the kernel as a force")
			}
			unmounted = true
			if handler.recordedDetach() != nil {
				detachesBeforeUnmount++
			}
			return nil
		},
	}
	found, jobID, err := r.unmountFSKitWith(a.ref, false, ops)
	if err != nil || !found || jobID != "" {
		t.Fatalf("v3 unmount=(%v,%q,%v)", found, jobID, err)
	}
	if detachesBeforeUnmount != 0 {
		t.Fatal("mount-absence proof reached the authority before the kernel detach")
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

func TestV3DetachWithoutAbsenceProofEndsFenced(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	t.Cleanup(r.stopPersister)
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
	found, _, err := r.unmountFSKitWith(a.ref, false, ops)
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
	if found, _, err := r.unmountFSKitWith(a.ref, false, absent); err != nil || !found {
		t.Fatalf("fenced v3 detach retry = (%v, %v)", found, err)
	}
	if r.get(a.ref) != nil {
		t.Fatal("fenced v3 attach was not released after the exact absence observation")
	}
	if handler.recordedDetach() != nil {
		t.Fatal("a fenced session delivered detach evidence")
	}
}

func TestV3TerminalSessionMarksAttachTerminal(t *testing.T) {
	pki := newV3TestPKI(t)
	handler := newV3TestAuthority()
	address := startV3TestAuthority(t, handler, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	t.Cleanup(r.stopPersister)
	req := v3TestEnsureRequest(address, pki, "/Volumes/PortableFSV3Terminal")
	// A short repair budget makes the liveness pulse fast (min(lease,budget)/3)
	// without touching any production constant.
	req.V3.RepairBudgetMillis = 300
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
	// Never a silent retry, never a fallback: the terminal attach refuses
	// reactivation and names the unmount as the one exit.
	if err := a.activate(context.Background(), "fresh-capability", 0); err == nil ||
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
	first.stopPersister()
	// The previous daemon process is gone; its strict session dies with it.
	a.fenceV3(errors.New("previous daemon process exited"))

	revived := newRegistry(stateDir)
	t.Cleanup(revived.stopPersister)
	if revived.loadErr != nil {
		t.Fatal(revived.loadErr)
	}
	b := revived.get(ref)
	if b == nil || !b.isV3() || b.v3Config == nil || !b.v3Config.revived {
		t.Fatalf("revived v3 attach = %+v", b)
	}
	if err := b.activate(context.Background(), "capability", 0); err == nil ||
		!strings.Contains(err.Error(), "unmount") {
		t.Fatalf("revived v3 activation = %v, want an unmount-directing refusal", err)
	}
	if _, eno := b.v3RootReply(); eno != darwinEIO {
		t.Fatalf("revived v3 resolve errno=%d, want %d", eno, darwinEIO)
	}
	found, jobID, err := revived.unmountFSKitWith(ref, false, fskitKernelOps{
		present:      func(_, _ string) (bool, error) { return false, nil },
		unmountExact: func(_, _ string, _ bool) error { return errors.New("nothing to detach") },
	})
	if err != nil || !found || jobID != "" {
		t.Fatalf("revived v3 unmount=(%v,%q,%v)", found, jobID, err)
	}
	if revived.get(ref) != nil {
		t.Fatal("revived v3 attach was not released by the exact unmount")
	}
}
