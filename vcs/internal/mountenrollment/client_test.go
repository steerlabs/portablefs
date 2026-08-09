package mountenrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

func TestClientUsesExactMTLSEnrollmentAndDeterministicRefresh(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caCert, caKey, caPEM := testEnrollmentCA(t, now)
	managerCert, _ := testSignedCertificate(t, caCert, caKey, now, "manager", nil, []string{"manager.test"}, false)
	enrollmentID := "22222222-2222-4222-8222-222222222222"
	enrollmentURI, _ := url.Parse("spiffe://portablefs/mount-enrollment/" + enrollmentID)
	enrollmentCert, mountKeyPEM := testSignedCertificate(t, caCert, caKey, now, enrollmentID, enrollmentURI, nil, true)
	replacementCert, _ := testSignedCertificateForKey(t, caCert, caKey, now, "mount-client", nil, nil, true, mountKeyPEM)

	var mu sync.Mutex
	var refreshKeys []string
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 ||
			len(request.TLS.PeerCertificates[0].URIs) != 1 || request.TLS.PeerCertificates[0].URIs[0].String() != enrollmentURI.String() {
			http.Error(writer, "wrong mTLS identity", http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(request.URL.Path, "/reauthorizations"):
			var body controlplane.RefreshMountEnrollmentRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.SessionID != "session" || body.Sequence != 1 || body.ClientCSRPEM == "" {
				http.Error(writer, "bad refresh", http.StatusBadRequest)
				return
			}
			mu.Lock()
			refreshKeys = append(refreshKeys, request.Header.Get("Idempotency-Key"))
			mu.Unlock()
			_ = json.NewEncoder(writer).Encode(controlplane.MountAuthorization{
				VolumeID: "volume", AuthorityEndpoint: "authority.test:2049", AuthorityServerName: "authority.test",
				AuthorityCAPEM: caPEM, ClientCertificatePEM: replacementCert, Capability: "capability",
				Access: []string{"write"}, ExpiresUnix: now.Add(time.Minute).Unix(), CertificateExpiresUnix: now.Add(time.Hour).Unix(),
				AuthorityGeneration: 7, SessionID: "session", Sequence: 1, ReleaseID: "test",
			})
		case strings.HasSuffix(request.URL.Path, "/close"):
			_ = json.NewEncoder(writer).Encode(controlplane.MountEnrollment{ID: enrollmentID, State: controlplane.MountEnrollmentClosed})
		default:
			http.NotFound(writer, request)
		}
	})
	server := httptest.NewUnstartedServer(handler)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(caCert)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{managerCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	}
	server.StartTLS()
	defer server.Close()

	client, err := NewClient(Config{
		ManagerURL: server.URL, ManagerServerName: "manager.test", ManagerCAPEM: []byte(caPEM),
		EnrollmentID: enrollmentID, EnrollmentCertificatePEM: []byte(certificatePEM(enrollmentCert.Certificate[0])),
		ClientKeyPEM: []byte(mountKeyPEM), VolumeID: "volume", AuthorityGeneration: 7,
		EnrollmentExpires: now.Add(time.Hour), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		grant, err := client.Refresh(t.Context(), "session", 1)
		if err != nil || grant.Capability != "capability" {
			t.Fatalf("refresh = %+v, %v", grant, err)
		}
	}
	mu.Lock()
	if len(refreshKeys) != 2 || refreshKeys[0] == "" || refreshKeys[0] != refreshKeys[1] {
		t.Fatalf("refresh idempotency keys = %v", refreshKeys)
	}
	mu.Unlock()
	if err := client.Close(t.Context(), "mount detached"); err != nil {
		t.Fatal(err)
	}
}

func testEnrollmentCA(t *testing.T, now time.Time) (*x509.Certificate, ed25519.PrivateKey, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, private, certificatePEM(der)
}

func testSignedCertificate(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time, name string, identity *url.URL, dns []string, client bool) (tls.Certificate, string) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	certPEM, _ := testSignedCertificateForKey(t, ca, caKey, now, name, identity, dns, client, keyPEM)
	identityPair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return identityPair, keyPEM
}

func testSignedCertificateForKey(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time, name string, identity *url.URL, dns []string, client bool, keyPEM string) (string, time.Time) {
	t.Helper()
	block, _ := pem.Decode([]byte(keyPEM))
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	private := parsed.(ed25519.PrivateKey)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns,
	}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if identity != nil {
			template.URIs = []*url.URL{identity}
		}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, private.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return certificatePEM(der), template.NotAfter
}

func certificatePEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
