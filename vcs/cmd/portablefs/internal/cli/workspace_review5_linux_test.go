//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	pb "github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	rpc "github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func r5TLSConfigs(t testing.TB) (*tls.Config, *tls.Config, string) {
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
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{serverCert}}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{clientCert}, ServerName: "localhost"}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

type r5ActivationHandler struct {
	entered, release, never chan struct{}
	once                    sync.Once
	committed               atomic.Bool
	detaches                atomic.Int32
	exact                   atomic.Bool
	refuse                  bool
}

func (h *r5ActivationHandler) Epoch() []byte { return bytes.Repeat([]byte{1}, 16) }
func (h *r5ActivationHandler) Bounds() rpc.TransportBounds {
	return rpc.TransportBounds{MaxFrame: mountv3.MaxFrame, MaxRequestFrame: (1 << 20) + rpc.FramePayloadReserve, MaxInFlight: mountv3.MaxInFlight}
}
func (h *r5ActivationHandler) SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return volumeserver.SessionStateProvisional, true
}
func (h *r5ActivationHandler) SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool) {
	return h.never, true
}
func (h *r5ActivationHandler) Handle(ctx context.Context, q *pb.Request) *pb.Response {
	r := &pb.Response{RequestId: q.RequestId, Epoch: h.Epoch()}
	switch {
	case q.GetHello() != nil:
		if h.committed.Load() {
			h.once.Do(func() { close(h.release) })
		}
		x := q.GetHello()
		r.Body = &pb.Response_Hello{Hello: &pb.HelloReply{ProtocolMajor: 8, MaxFrameBytes: mountv3.MaxFrame, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxInFlight: mountv3.MaxInFlight, Role: x.Role, ConnectionSetId: x.ConnectionSetId, FrontendProfile: x.FrontendProfile}}
	case q.GetAttach() != nil:
		r.Body = &pb.Response_Attach{Attach: &pb.AttachReply{SessionId: bytes.Repeat([]byte{0x51}, 16), Generation: 1, ResumeSecret: bytes.Repeat([]byte{0x61}, 32), ProvisionalDeadlineUnixNanos: time.Now().Add(time.Minute).UnixNano()}}
	case q.GetActivate() != nil:
		first := !h.committed.Swap(true)
		if first {
			close(h.entered)
			<-h.release
		}
		rules := localroutes.RuleSet{}
		revision := rules.Revision()
		r.Body = &pb.Response_Activate{Activate: &pb.ActivateReply{State: pb.SessionState_SESSION_STATE_ACTIVE, Purpose: pb.SessionPurpose_SESSION_PURPOSE_MOUNT, FrontendProfile: pb.FrontendProfile_FRONTEND_PROFILE_LINUX, SessionLeaseMilliseconds: 30000, RoutesRevision: revision[:], Root: &pb.Item{Token: bytes.Repeat([]byte{0x31}, 16), StableIdentity: bytes.Repeat([]byte{0x42}, 16), Attr: &pb.Attr{Kind: pb.Attr_DIRECTORY, Inode: 1}}}}
	case q.GetResume() != nil:
		r.Body = &pb.Response_Resume{Resume: &pb.ResumeReply{State: pb.SessionState_SESSION_STATE_ACTIVE}}
	case q.GetDetach() != nil:
		proof := q.GetDetach().GetMountAbsence()
		h.exact.Store(bytes.Equal(q.GetSession().GetId(), bytes.Repeat([]byte{0x51}, 16)) && proof != nil && proof.ObservedUnixNanos > 0 && len(proof.Observation) > 0 && proof.Component != "")
		h.detaches.Add(1)
		if h.refuse {
			r.Errno = int32(syscall.EPERM)
		}
	}
	return r
}
func TestR5OrdinaryMountPreservesActivationCleanupDisposition(t *testing.T) {
	for _, refused := range []bool{false, true} {
		name := "detached"
		if refused {
			name = "detach-refused"
		}
		t.Run(name, func(t *testing.T) {
			serverTLS, clientTLS, ca := r5TLSConfigs(t)
			h := &r5ActivationHandler{entered: make(chan struct{}), release: make(chan struct{}), never: make(chan struct{}), refuse: refused}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			serveCtx, stop := context.WithCancel(context.Background())
			defer stop()
			s := &rpc.Server{Handler: h, MaxFrame: mountv3.MaxFrame, MaxInFlight: mountv3.MaxInFlight, MaxConnections: 8, MaxFrameBytesInFlight: 64 << 20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
			serverDone := make(chan error, 1)
			go func() { serverDone <- s.Serve(serveCtx, listener, serverTLS) }()
			defer func() {
				h.once.Do(func() { close(h.release) })
				stop()
				if err := <-serverDone; err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				attached bool
				clean    bool
				err      error
			}
			done := make(chan result, 1)
			go func() {
				m, attached, clean, err := mountFUSEv3(ctx, fuseV3Config{addr: listener.Addr().String(), token: "test", transport: dataPlaneTransport{Mode: dataPlaneTransportTLSPrivateCA, ServerName: "localhost", CAPEM: ca, CASHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(ca)))}, identity: &clientTLSIdentity{certificate: clientTLS.Certificates[0]}, volumeID: "volume", mountPath: t.TempDir(), mountInstanceID: "mnt_0000000000000000000001"})
				if m != nil {
					panic("unexpected mount")
				}
				done <- result{attached, clean, err}
			}()
			select {
			case <-h.entered:
				cancel()
			case got := <-done:
				t.Fatalf("did not reach Activate: %v", got.err)
			case <-time.After(3 * time.Second):
				t.Fatal("did not reach Activate")
			}
			var got result
			select {
			case got = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("startup did not reconcile")
			}
			if h.detaches.Load() != 1 || !h.exact.Load() {
				t.Fatalf("expected one exact Detach, got %d: %v", h.detaches.Load(), got.err)
			}
			uncertain := errors.Is(got.err, rpc.ErrTransportUncertain)
			clean := got.clean
			t.Logf("refused=%v attached=%v clean=%v uncertain=%v enrollmentMayClose=%v error=%v", refused, got.attached, clean, uncertain, automaticEnrollmentCanCloseAfterStartupFailure(got.attached, clean), got.err)
			if refused {
				if !uncertain {
					t.Fatal("client did not preserve uncertainty")
				}
				if automaticEnrollmentCanCloseAfterStartupFailure(got.attached, clean) {
					t.Error("possibly committed session misclassified as never attached; enrollment closure is allowed")
				}
			} else if !clean || !automaticEnrollmentCanCloseAfterStartupFailure(got.attached, clean) {
				t.Error("confirmed pre-kernel Detach lost its cleanup verdict; ordinary startup cannot finalize its intent")
			}
		})
	}
}
