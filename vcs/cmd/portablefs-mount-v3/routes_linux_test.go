//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// The attach path a default mount actually takes.
//
// The credential here is a REAL volumecap capability, single-use exactly as the
// control plane mints them: its nonce is spent the moment a token is accepted.
// That is the whole point of this fixture. A mount is issued one capability, so
// any design in which the mount attaches more than once successfully -- a
// bootstrap session to read the routing declaration, say -- consumes it and
// leaves the real attach with nothing. The property under test is that a default
// mount, with no flags and no environment escape hatch, attaches on a volume
// that declares routes and on one that does not, spending one capability either
// way.

const (
	attachVolumeID = "attach-volume"
	envXFSRoot     = "PORTABLEFS_XFS_TEST_ROOT"
	envXFSProject  = "PORTABLEFS_XFS_TEST_PROJECT"
	envRequired    = "PORTABLEFS_XFS_TEST_REQUIRED"
)

type attachFixture struct {
	t              *testing.T
	address        string
	clientTLS      *tls.Config
	capability     []byte
	routes         *authorityrpc.RoutesController
	attaches       *attachCounter
	stop           context.CancelFunc
	served         chan error
	listener       net.Listener
	store          *xfsstore.Volume
	writeAdmission *authorityrpc.WriteAdmission
}

// attachCounter records every attach the authority was asked to perform and how
// it answered. "refused for routing" is the answer that must not cost a
// capability.
type attachCounter struct {
	inner authorityrpc.Handler

	mu       sync.Mutex
	attempts int
	refusals int
}

func (c *attachCounter) Epoch() []byte                        { return c.inner.Epoch() }
func (c *attachCounter) Bounds() authorityrpc.TransportBounds { return c.inner.Bounds() }
func (c *attachCounter) SessionStateForTransport(id volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return c.inner.SessionStateForTransport(id)
}
func (c *attachCounter) SessionTerminalForTransport(id volumeserver.SessionID) (<-chan struct{}, bool) {
	return c.inner.SessionTerminalForTransport(id)
}

func (c *attachCounter) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	attach := request.GetAttach() != nil
	response := c.inner.Handle(ctx, request)
	if !attach {
		return response
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	if response.GetRoutesMismatch() != nil {
		c.refusals++
	}
	return response
}

func (c *attachCounter) counts() (attempts, refusals int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attempts, c.refusals
}

func newAttachFixture(t *testing.T, declaration string) *attachFixture {
	t.Helper()
	root, project := os.Getenv(envXFSRoot), os.Getenv(envXFSProject)
	if root == "" || project == "" {
		if os.Getenv(envRequired) == "1" {
			t.Fatalf("%s=1 but %s=%q %s=%q", envRequired, envXFSRoot, root, envXFSProject, project)
		}
		t.Skipf("privileged gates are not configured; set %s and %s", envXFSRoot, envXFSProject)
	}
	projectID, err := strconv.ParseUint(project, 10, 32)
	if err != nil {
		t.Fatalf("%s=%q is not a uint32: %v", envXFSProject, project, err)
	}
	f := &attachFixture{t: t}

	volumeRoot := filepath.Join(root, "attach-"+randomSuffix(t))
	if err := os.Mkdir(volumeRoot, 0o700); err != nil {
		t.Fatalf("create volume root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(volumeRoot) })
	store, err := xfsstore.Open(volumeRoot, xfsstore.Config{
		ExpectedProjectID: uint32(projectID),
		ExpectedOwnerUID:  uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid()),
	})
	if err != nil {
		t.Fatalf("open XFS volume: %v", err)
	}
	f.store = store
	writeAdmissionRoot := volumeRoot + ".write-admission"
	if err := os.Mkdir(writeAdmissionRoot, 0o700); err != nil {
		t.Fatalf("create write admission root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(writeAdmissionRoot) })
	f.writeAdmission, err = authorityrpc.OpenWriteAdmission(writeAdmissionRoot)
	if err != nil {
		t.Fatalf("open write admission root: %v", err)
	}
	t.Cleanup(func() {
		if f.writeAdmission != nil {
			if err := f.writeAdmission.Close(); err != nil {
				t.Errorf("close write admission: %v", err)
			}
			f.writeAdmission = nil
		}
	})

	authority, err := volumeserver.New(attachVolumeID, volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 64, MaxSessions: 8, MaxLockRecords: 1024,
	})
	if err != nil {
		t.Fatalf("create authority epoch: %v", err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noMembership{}, Fencer: authority,
		MaxCachedNameCapacity: 4096, MaxRepairBudget: time.Minute, MaxClockSkew: time.Minute,
	})
	if err != nil {
		t.Fatalf("create visibility coordinator: %v", err)
	}
	routes, err := authorityrpc.NewRoutesController(store, visibility, authority.Locks())
	if err != nil {
		t.Fatalf("create routing controller: %v", err)
	}
	if err := routes.Load(); err != nil {
		t.Fatalf("load routing: %v", err)
	}
	active, err := routes.Revision()
	if err != nil {
		t.Fatalf("read active routing revision: %v", err)
	}
	if _, err := routes.Apply(context.Background(), []byte(declaration), active); err != nil {
		t.Fatalf("install the routing declaration: %v", err)
	}
	f.routes = routes

	serverTLS, clientTLS, clientSPKI := attachTLS(t)
	f.clientTLS = clientTLS

	// A real capability, bound to this client's key, valid once.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, err := volumecap.Sign(private, volumecap.Claims{
		VolumeID: attachVolumeID, Subject: "mount", Access: []string{"write"},
		NotBefore: now.Add(-time.Minute).Unix(), Expires: now.Add(10 * time.Minute).Unix(),
		PeerSPKI: base64.RawURLEncoding.EncodeToString(clientSPKI[:]), Nonce: "attach-" + randomSuffix(t),
	})
	if err != nil {
		t.Fatalf("mint capability: %v", err)
	}
	f.capability = token

	handler := &authorityrpc.VolumeHandler{
		Store: store, Runtime: authority, Visibility: visibility, Routes: routes,
		Authorizer: &volumecap.Authorizer{
			PublicKey: public, MaxLifetime: 15 * time.Minute, MaxRetainedNonces: 64,
		},
		MaxFrame: 4 << 20, MaxRead: 1 << 20, MaxWrite: 1 << 20, MaxInFlight: 64,
		MaxItemsPerSession: 1024, MaxOpensPerSession: 1024, MaxItems: 4096, MaxOpens: 4096,
		MaxRetainedReplyBytes:         32 << 20,
		WriteAdmission:                f.writeAdmission,
		MaxWriteBytesPerSession:       16 << 30,
		MaxWriteBytesInFlight:         64 << 30,
		MaxWritesPerSession:           8,
		MaxWrites:                     64,
		WriteAdmissionProgressTimeout: 2 * time.Minute,
		WriteAbsoluteTimeout:          30 * time.Minute,
		TerminalDeliveryTimeout:       45 * time.Second,
	}
	f.attaches = &attachCounter{inner: handler}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f.listener, f.address = listener, listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	f.stop, f.served = cancel, make(chan error, 1)
	served := f.served
	go func() {
		served <- (&authorityrpc.Server{
			Handler: f.attaches, MaxFrame: 4 << 20, MaxInFlight: 64, MaxConnections: 8,
			MaxFrameBytesInFlight: 32 << 20, HandshakeTimeout: 5 * time.Second,
			IdleTimeout: time.Minute, WriteTimeout: 30 * time.Second,
		}).Serve(ctx, listener, serverTLS)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(30 * time.Second):
			t.Error("authority server did not stop")
		}
		_ = listener.Close()
		if err := store.Close(); err != nil {
			t.Errorf("close XFS volume: %v", err)
		}
	})
	return f
}

// attachConfig is exactly what the mount binary builds for a default strict
// mount: no flags, no environment, one capability.
func (f *attachFixture) attachConfig() authorityrpc.ClientConfig {
	return authorityrpc.ClientConfig{
		Purpose:         authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES,
		Address:         f.address, TLS: f.clientTLS.Clone(), VolumeID: attachVolumeID,
		AccessToken: f.capability, ReplaySlots: 64, MaxFrame: 4 << 20,
		DialTimeout: 10 * time.Second, CancelDrainTimeout: 5 * time.Second, MaxInFlight: 64,
		ObservePreKernelMountAbsence: func(context.Context) (*authoritypb.MountAbsenceProof, error) {
			return &authoritypb.MountAbsenceProof{
				ObservedUnixNanos: time.Now().UnixNano(),
				Observation:       []byte("test exact unique FUSE source present=false before mount"),
				Component:         "portablefs-mount-v3-test/mount-inventory",
			}, nil
		},
	}
}

type noMembership struct{}

func (noMembership) Activate(volumeserver.SessionID) error   { return nil }
func (noMembership) Deactivate(volumeserver.SessionID) error { return nil }

func randomSuffix(t *testing.T) string {
	t.Helper()
	var value [6]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value[:])
}

func releaseTestClientBeforeMount(t *testing.T, client *authorityrpc.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.ReleaseBeforeMount(ctx); err != nil {
		t.Errorf("release ACTIVE test session before mount: %v", err)
	}
}

// --- a volume with no declaration: one attach, no retry ---

func TestADefaultMountAttachesOnceOnAVolumeWithNoRoutes(t *testing.T) {
	f := newAttachFixture(t, "")
	client, rules, err := attachWithRoutes(context.Background(), f.attachConfig(), true)
	if err != nil {
		t.Fatalf("default mount could not attach to a volume with no routing declaration: %v", err)
	}
	defer releaseTestClientBeforeMount(t, client)
	if !rules.Empty() {
		t.Fatalf("a volume with no declaration produced rules %v", rules.Patterns())
	}
	attempts, refusals := f.attaches.counts()
	if attempts != 1 || refusals != 0 {
		t.Fatalf("attach attempts = %d (%d refused for routing), want exactly 1 and none refused; the ordinary case must cost no extra round trip",
			attempts, refusals)
	}
}

// --- a volume that declares routes: refused once, adopted, attached ---

func TestADefaultMountAdoptsTheVolumesRoutesOnOneCapability(t *testing.T) {
	const declaration = "node_modules/\n/target/\n"
	f := newAttachFixture(t, declaration)
	client, rules, err := attachWithRoutes(context.Background(), f.attachConfig(), true)
	if err != nil {
		t.Fatalf("default mount could not attach to a volume that declares routes: %v\n"+
			"if this is EPERM, the capability was spent by the refused attach and the authority half of the fix has not landed", err)
	}
	defer releaseTestClientBeforeMount(t, client)

	expected, err := localroutes.Parse([]byte(declaration))
	if err != nil {
		t.Fatal(err)
	}
	if rules.Revision() != expected.Revision() {
		t.Fatalf("adopted routing %v (revision %x), want %v (revision %x)",
			rules.Patterns(), rules.Revision(), expected.Patterns(), expected.Revision())
	}
	attempts, refusals := f.attaches.counts()
	if attempts != 2 || refusals != 1 {
		t.Fatalf("attach attempts = %d (%d refused for routing), want exactly 2 with the first refused; a mount learns the topology from the refusal and never from a second session",
			attempts, refusals)
	}
}

// --- the refusal is the only thing that may teach a mount its routing ---

func TestARoutingRefusalDoesNotSpendTheCapability(t *testing.T) {
	f := newAttachFixture(t, "node_modules/\n")
	attach := f.attachConfig()
	// One attach with the wrong revision, exactly as a fresh mount makes it.
	attach.RoutesRevision = localroutes.RuleSet{}.Revision()
	if _, err := authorityrpc.DialClient(context.Background(), attach); err == nil {
		t.Fatal("a mount running the empty rule set was admitted to a volume that routes node_modules")
	} else if !errors.Is(err, authorityrpc.ErrRoutesMismatch) {
		t.Fatalf("attach refusal = %v, want a routing mismatch", err)
	}
	// The same capability must still work once the revision is right. If it
	// does not, a mount can never attach at all: it has exactly one.
	adopted, err := localroutes.Parse([]byte("node_modules/\n"))
	if err != nil {
		t.Fatal(err)
	}
	attach = f.attachConfig()
	attach.RoutesRevision = adopted.Revision()
	client, err := authorityrpc.DialClient(context.Background(), attach)
	if err != nil {
		t.Fatalf("the capability was spent by a refusal it was never accepted for: %v", err)
	}
	releaseTestClientBeforeMount(t, client)
}

func TestARoutingRefusalCarriesTheVolumesDeclaration(t *testing.T) {
	const declaration = "node_modules/\n"
	f := newAttachFixture(t, declaration)
	attach := f.attachConfig()
	attach.RoutesRevision = localroutes.RuleSet{}.Revision()
	_, err := authorityrpc.DialClient(context.Background(), attach)
	if err == nil {
		t.Fatal("a mount running the empty rule set was admitted to a volume that routes node_modules")
	}
	var mismatch *authorityrpc.RoutesMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("attach refusal %v does not carry the volume's routing; a fresh mount cannot read %s without a session and cannot get a session without the revision, so the refusal is the only thing that can break the circle",
			err, localroutes.ConfigPath)
	}
	expected, parseErr := localroutes.Parse([]byte(declaration))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if mismatch.Active != expected.Revision() {
		t.Fatalf("refusal names active revision %x, want %x", mismatch.Active, expected.Revision())
	}
	// The bytes it carries must be exactly what this mount compiles back into
	// the same routing, or adopting them would attach against a topology it did
	// not derive.
	adopted, parseErr := localroutes.Parse(mismatch.Canonical)
	if parseErr != nil {
		t.Fatalf("the canonical rules the authority sent do not compile: %v", parseErr)
	}
	if adopted.Revision() != mismatch.Active {
		t.Fatalf("the canonical rules hash to %x but the refusal calls %x active", adopted.Revision(), mismatch.Active)
	}
	if !strings.EqualFold(adopted.RevisionHex(), expected.RevisionHex()) {
		t.Fatalf("adopted routing %v, want %v", adopted.Patterns(), expected.Patterns())
	}
}

// --- -no-local-dirs refuses rather than silently serving a shared subtree ---

func TestNoLocalDirsRefusesAVolumeThatDeclaresRoutes(t *testing.T) {
	f := newAttachFixture(t, "node_modules/\n")
	client, _, err := attachWithRoutes(context.Background(), f.attachConfig(), false)
	if err == nil {
		releaseTestClientBeforeMount(t, client)
		t.Fatal("-no-local-dirs mounted a volume that routes node_modules; the subtree would have been served from shared storage on this machine and machine-local on every other")
	}
	if !strings.Contains(err.Error(), localroutes.ConfigPath) {
		t.Fatalf("refusal %q does not name the declaration that has to be reconciled", err)
	}
}

func attachTLS(t *testing.T) (*tls.Config, *tls.Config, [32]byte) {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "attach CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, name string, usages []x509.ExtKeyUsage, dns []string) (tls.Certificate, [32]byte) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: dns,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyBytes, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		certificate, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return certificate, sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	}
	serverCertificate, _ := issue(2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	clientCertificate, clientSPKI := issue(3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
			MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: pool, Certificates: []tls.Certificate{serverCertificate},
		}, &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: pool,
			Certificates: []tls.Certificate{clientCertificate}, ServerName: "localhost",
		}, clientSPKI
}
