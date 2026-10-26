package workspacemount

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

func request() *pb.IdentityRequest {
	return &pb.IdentityRequest{AuthorityId: bytes.Repeat([]byte{1}, 32), VolumeId: "volume"}
}
func store(t *testing.T) (*Store, *pb.IdentityReply) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "identities"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	r, err := s.EnsureIdentity(request())
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}
func signingCA(t *testing.T, name string) *controlplane.CertificateAuthority {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := controlplane.ParseCertificateAuthority(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func provision(t *testing.T, r *pb.IdentityReply, hosted bool, validity ...time.Time) *pb.Provision {
	t.Helper()
	now := time.Now()
	authorityCA, clientCA := signingCA(t, "authority-server"), signingCA(t, "mount-client")
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: r.Csr})
	signingTime, lifetime := now, time.Hour
	if len(validity) == 2 {
		signingTime = validity[0].Add(time.Minute)
		lifetime = validity[1].Sub(signingTime)
	}
	client, _, err := clientCA.SignCSR(csr, "peer", nil, true, signingTime, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	p := &pb.Provision{Mount: r.Mount, AuthorityEndpoint: "authority.example:7443", ServerName: "authority.example", CaCertificate: []byte(authorityCA.CertificatePEM), ClientCertificate: []byte(client), PublicKey: r.PublicKey, Capability: []byte("test signed grant"), RoutesRevision: bytes.Repeat([]byte{2}, 32)}
	if hosted {
		enrollmentCA, httpsCA := signingCA(t, "enrollment"), signingCA(t, "manager-https")
		id := "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"
		uri, _ := url.Parse("spiffe://portablefs/mount-enrollment/" + id)
		enrollment, _, err := enrollmentCA.SignClientCSR(csr, id, uri, signingTime, lifetime)
		if err != nil {
			t.Fatal(err)
		}
		p.HostedEnrollment = &pb.HostedEnrollment{ManagerOrigin: "https://manager.example", ManagerServerName: "manager.example", ManagerCa: []byte(httpsCA.CertificatePEM), EnrollmentId: id, EnrollmentCertificate: []byte(enrollment), AuthorityGeneration: 1, AuthorizationDeadlineUnix: uint64(now.Add(time.Minute).Unix())}
		peer := sha256.Sum256(r.PublicKey)
		product, err := productauth.Sign(clientCA.Signer.(ed25519.PrivateKey), productauth.Claims{Issuer: "test", Audience: "portablefs-manager", AuthorizationDomain: "test", Owner: "test", Subject: "test", VolumeID: r.Mount.VolumeId, Access: []string{"read", "write"}, PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "test-product", NotBefore: now.Add(-time.Second).Unix(), Expires: now.Add(time.Minute).Unix(), RenewalScope: RenewalScope(r), RenewalEpoch: r.RenewalEpoch})
		if err != nil {
			t.Fatal(err)
		}
		p.Capability, err = volumecap.Sign(clientCA.Signer.(ed25519.PrivateKey), volumecap.Claims{VolumeID: r.Mount.VolumeId, Subject: "test", Access: []string{"read", "write"}, NotBefore: now.Add(-time.Second).Unix(), Expires: int64(p.HostedEnrollment.AuthorizationDeadlineUnix), PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "test-capability", CellID: "11111111-1111-4111-8111-111111111111", AuthorityID: p.ServerName, AuthorityGeneration: 1, MountEnrollmentID: id, ProductAuthorization: string(product)})
		if err != nil {
			t.Fatal(err)
		}
	}
	return p
}
func ready(context.Context) error { return nil }
func TestIdentityPersistenceScopeEpochAndMountNonce(t *testing.T) {
	s, r := store(t)
	csr, err := x509.ParseCertificateRequest(r.Csr)
	if err != nil || csr.CheckSignature() != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, r.PublicKey) {
		t.Fatal("CSR did not prove the same guest key", err)
	}
	again, err := s.EnsureIdentity(request())
	if err != nil || !proto.Equal(r, again) {
		t.Fatal("repeat identity changed", err)
	}
	other := request()
	other.VolumeId = "another"
	second, err := s.EnsureIdentity(other)
	if err != nil || bytes.Equal(second.PublicKey, r.PublicKey) || RenewalScope(second) == RenewalScope(r) {
		t.Fatal("volumes shared identity", err)
	}
	if _, err = Open(s.directory); err == nil {
		t.Fatal("two identity owners")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := reopened.EnsureIdentity(request())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(next.PublicKey, r.PublicKey) || RenewalScope(next) != RenewalScope(r) || next.RenewalEpoch != r.RenewalEpoch || bytes.Equal(next.Mount.Incarnation, r.Mount.Incarnation) {
		t.Fatal("boot changed persistent identity or retained mount nonce")
	}
	for _, name := range []string{"guest.json", volumeKey(r.Mount.AuthorityId, r.Mount.VolumeId) + ".json"} {
		st, err := os.Stat(filepath.Join(s.directory, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("identity mode", err)
		}
	}
	if !strings.HasPrefix(RenewalScope(r), "portablefs-linux-workspace/8/") {
		t.Fatal("scope borrowed Mac identity")
	}
}
func TestProvisionStandaloneAndHostedWithDistinctIssuerCAs(t *testing.T) {
	for _, hosted := range []bool{false, true} {
		t.Run(map[bool]string{false: "standalone", true: "hosted"}[hosted], func(t *testing.T) {
			s, r := store(t)
			p := provision(t, r, hosted)
			if err := s.AcceptProvision(t.Context(), p, ready); err != nil {
				t.Fatal(err)
			}
			if err := s.AcceptProvision(t.Context(), p, ready); err != nil {
				t.Fatal(err)
			}
			cert, err := s.TLSIdentity(request())
			if err != nil || cert.PrivateKey == nil {
				t.Fatal(err)
			}
			issue, err := IssueRequest(r, "test product authorization", []string{"read", "write"})
			if err != nil || !issue.AutomaticReauthorization || issue.VolumeID != r.Mount.VolumeId {
				t.Fatal(err)
			}
		})
	}
}
func TestProvisionRejectsClockKeyCertificateEndpointAndRoute(t *testing.T) {
	for _, name := range []string{"clock", "key", "cert-key", "CA", "endpoint", "route", "mount", "server", "hosted-origin", "hosted-cert", "hosted-deadline", "server-CA-leaf", "manager-CA-leaf", "client-EKU", "enrollment-EKU", "malformed-chain"} {
		t.Run(name, func(t *testing.T) {
			s, r := store(t)
			p := provision(t, r, true)
			wait := ready
			switch name {
			case "clock":
				wait = func(context.Context) error { return errors.New("clock unavailable") }
			case "key":
				p.PublicKey = []byte("another")
			case "cert-key":
				_, other := store(t)
				p.ClientCertificate = provision(t, other, false).ClientCertificate
			case "CA":
				p.CaCertificate = []byte("invalid")
			case "endpoint":
				p.AuthorityEndpoint = "https://authority.example"
			case "route":
				p.RoutesRevision = nil
			case "mount":
				p.Mount = proto.Clone(p.Mount).(*pb.MountID)
				p.Mount.Incarnation = nonce()
			case "server":
				p.ServerName = "bad/name"
			case "hosted-origin":
				p.HostedEnrollment.ManagerOrigin += "/path"
			case "hosted-cert":
				p.HostedEnrollment.EnrollmentCertificate = p.ClientCertificate
			case "server-CA-leaf":
				p.CaCertificate = p.ClientCertificate
			case "manager-CA-leaf":
				p.HostedEnrollment.ManagerCa = p.HostedEnrollment.EnrollmentCertificate
			case "malformed-chain":
				p.ClientCertificate = append(p.ClientCertificate, []byte("invalid trailing certificate")...)
			case "client-EKU", "enrollment-EKU":
				ca := signingCA(t, "wrong-EKU")
				spki, err := x509.ParsePKIXPublicKey(r.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
				if name == "enrollment-EKU" {
					leaf.URIs = []*url.URL{{Scheme: "spiffe", Host: "portablefs", Path: "/mount-enrollment/" + p.HostedEnrollment.EnrollmentId}}
				}
				der, err := x509.CreateCertificate(rand.Reader, leaf, ca.Certificate, spki, ca.Signer)
				if err != nil {
					t.Fatal(err)
				}
				raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
				if name == "client-EKU" {
					p.ClientCertificate = raw
				} else {
					p.HostedEnrollment.EnrollmentCertificate = raw
				}
			case "hosted-deadline":
				p.HostedEnrollment.AuthorizationDeadlineUnix = 1
			}
			err := s.AcceptProvision(t.Context(), p, wait)
			if err == nil {
				t.Fatal("invalid provision accepted")
			}
			if strings.Contains(err.Error(), string(p.Capability)) {
				t.Fatal("credential in diagnostic")
			}
			if _, err = s.TLSIdentity(request()); err == nil {
				t.Fatal("rejection persisted credentials")
			}
		})
	}
}
func TestReissueCleanupAndRevocationAreDurableAndVolumeScoped(t *testing.T) {
	s, r := store(t)
	p := provision(t, r, true)
	if err := s.AcceptProvision(t.Context(), p, ready); err != nil {
		t.Fatal(err)
	}
	changed := proto.Clone(p).(*pb.Provision)
	changed.Capability = []byte("replacement grant")
	if s.AcceptProvision(t.Context(), changed, ready) == nil {
		t.Fatal("reissue before cleanup")
	}
	denied := errors.New("cleanup not proven")
	if !errors.Is(s.Reissue(request(), true, func() error { return denied }), denied) {
		t.Fatal("cleanup failure ignored")
	}
	unchanged, _ := s.EnsureIdentity(request())
	if unchanged.RenewalEpoch != 1 {
		t.Fatal("failed cleanup advanced epoch")
	}
	other := request()
	other.VolumeId = "another"
	a, _ := s.EnsureIdentity(other)
	if err := s.Reissue(request(), false, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	same, _ := s.EnsureIdentity(request())
	if same.RenewalEpoch != 1 || RenewalScope(same) != RenewalScope(r) {
		t.Fatal("ordinary replacement rotated scope")
	}
	if err := s.Reissue(request(), true, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	next, _ := s.EnsureIdentity(request())
	b, _ := s.EnsureIdentity(other)
	if next.RenewalEpoch != 2 || !bytes.Equal(next.PublicKey, r.PublicKey) || b.RenewalEpoch != a.RenewalEpoch {
		t.Fatal("revocation epoch not volume scoped")
	}
}
func TestIdentityCorruptionAndPersistenceFailureRefuse(t *testing.T) {
	s, r := store(t)
	name := filepath.Join(s.directory, volumeKey(r.Mount.AuthorityId, r.Mount.VolumeId)+".json")
	if err := os.Chmod(name, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureIdentity(request()); err == nil {
		t.Fatal("insecure identity mode accepted")
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("guest.json", name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureIdentity(request()); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Rename(s.directory, s.directory+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := s.commit("transaction", struct{}{}); err == nil {
		t.Fatal("failed write succeeded")
	}
	if s.failed == nil {
		t.Fatal("persistence failure did not latch")
	}
}

func TestCertificateValidityBoundariesStayClosed(t *testing.T) {
	s, r := store(t)
	now := time.Now()
	future := provision(t, r, false, now.Add(time.Hour), now.Add(2*time.Hour))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.AcceptProvision(ctx, future, ready) }()
	time.Sleep(10 * time.Millisecond)
	if _, err := s.TLSIdentity(request()); err == nil {
		t.Fatal("NotBefore published provisioning")
	}
	cancel()
	if !errors.Is(<-done, context.Canceled) {
		t.Fatal("NotBefore wait ignored generation cancellation")
	}
	expired := provision(t, r, false, now.Add(-time.Hour), now.Add(-time.Second))
	if err := s.AcceptProvision(t.Context(), expired, ready); err == nil {
		t.Fatal("NotAfter accepted")
	}
	valid := provision(t, r, false, now.Add(-time.Second), now.Add(time.Hour))
	if err := s.AcceptProvision(t.Context(), valid, ready); err != nil {
		t.Fatal(err)
	}
}
