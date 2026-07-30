package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testDataPlaneCAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PortableFS test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func privateCATransport(t *testing.T) dataPlaneTransport {
	t.Helper()
	ca := testDataPlaneCAPEM(t)
	sum := sha256.Sum256([]byte(ca))
	return dataPlaneTransport{
		Mode:       dataPlaneTransportTLSPrivateCA,
		ServerName: "router.example",
		CAPEM:      ca,
		CASHA256:   hex.EncodeToString(sum[:]),
	}
}

func TestDataPlaneTransportModes(t *testing.T) {
	private := privateCATransport(t)
	cfg, err := private.tlsConfig()
	if err != nil {
		t.Fatalf("private CA transport: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.ServerName != "router.example" || cfg.RootCAs == nil {
		t.Fatalf("private CA TLS config = %+v", cfg)
	}

	system := dataPlaneTransport{Mode: dataPlaneTransportTLSSystemPKI, ServerName: "router.example"}
	cfg, err = system.tlsConfig()
	if err != nil {
		t.Fatalf("system PKI transport: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.ServerName != "router.example" || cfg.RootCAs != nil {
		t.Fatalf("system PKI TLS config = %+v", cfg)
	}

	plain := dataPlaneTransport{Mode: dataPlaneTransportPlaintext}
	cfg, err = plain.tlsConfig()
	if err != nil || cfg != nil {
		t.Fatalf("plaintext config = %+v, %v", cfg, err)
	}
}

func TestDataPlaneTransportRejectsIncompleteConflictingAndFingerprintMismatch(t *testing.T) {
	private := privateCATransport(t)
	private.CASHA256 = strings.Repeat("0", 64)
	cases := []dataPlaneTransport{
		{},
		{Mode: "future"},
		{Mode: dataPlaneTransportPlaintext, ServerName: "router.example"},
		{Mode: dataPlaneTransportTLSSystemPKI},
		{Mode: dataPlaneTransportTLSSystemPKI, ServerName: "router.example", CAPEM: "unexpected"},
		{Mode: dataPlaneTransportTLSPrivateCA, ServerName: "router.example"},
		private,
	}
	for _, transport := range cases {
		if err := transport.validate(); err == nil {
			t.Errorf("transport %+v unexpectedly validated", transport)
		}
	}
}

func TestPrivateCAMaterializationIsContentAddressed(t *testing.T) {
	transport := privateCATransport(t)
	path, digest, err := transport.materializePrivateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if digest != transport.CASHA256 || !strings.HasSuffix(path, digest+".pem") {
		t.Fatalf("materialized %q digest %q", path, digest)
	}
	path2, digest2, err := transport.materializePrivateCA(strings.TrimSuffix(path, "/ca/"+digest+".pem"))
	if err != nil || path2 != path || digest2 != digest {
		t.Fatalf("idempotent materialization = %q %q %v", path2, digest2, err)
	}
}

func TestDirectTransportMustBeExplicit(t *testing.T) {
	if _, err := directDataPlaneTransport("", "", ""); err == nil {
		t.Fatal("direct transport inferred from empty flags")
	}
	plain, err := directDataPlaneTransport(dataPlaneTransportPlaintext, "", "")
	if err != nil || plain.Mode != dataPlaneTransportPlaintext {
		t.Fatalf("explicit plaintext = %+v, %v", plain, err)
	}
	if _, err := directDataPlaneTransport(dataPlaneTransportPlaintext, "router.example", ""); err == nil {
		t.Fatal("plaintext accepted a conflicting TLS name")
	}
	if _, err := directDataPlaneTransport(dataPlaneTransportTLSSystemPKI, "", ""); err == nil {
		t.Fatal("system PKI accepted no verification name")
	}
}
