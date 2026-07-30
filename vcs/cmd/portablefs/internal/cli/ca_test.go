package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

func testCertificatePEM(t *testing.T, serial int64) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "PortableFS test CA"},
		NotBefore:             time.Unix(1, 0),
		NotAfter:              time.Unix(2_000_000_000, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestValidateCertificatePEMRejectsEveryMalformedBoundary(t *testing.T) {
	valid := testCertificatePEM(t, 1)
	for name, body := range map[string]string{
		"empty":          "",
		"trailing":       valid + "garbage",
		"leading":        "garbage\n" + valid,
		"wrong block":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})),
		"invalid cert":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")})),
		"valid then bad": valid + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")})),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := strictCACertificates([]byte(body)); err == nil {
				t.Fatal("malformed CA accepted")
			}
		})
	}
	if _, err := strictCACertificates([]byte("\n" + valid + "\t")); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
}

func TestLeaseCAsAreImmutableAndContentAddressed(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "mounts")
	first := testCertificatePEM(t, 1)
	second := testCertificatePEM(t, 2)
	firstSum := sha256.Sum256([]byte(first))
	secondSum := sha256.Sum256([]byte(second))
	firstTransport := dataPlaneTransport{
		Mode: dataPlaneTransportTLSPrivateCA, ServerName: "router.example",
		CAPEM: first, CASHA256: hex.EncodeToString(firstSum[:]),
	}
	secondTransport := dataPlaneTransport{
		Mode: dataPlaneTransportTLSPrivateCA, ServerName: "router.example",
		CAPEM: second, CASHA256: hex.EncodeToString(secondSum[:]),
	}
	path1, digest1, err := firstTransport.materializePrivateCA(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	path2, digest2, err := secondTransport.materializePrivateCA(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if path1 == path2 || digest1 == digest2 {
		t.Fatalf("different CAs aliased: (%s,%s) (%s,%s)", path1, digest1, path2, digest2)
	}
	if filepath.Base(path1) != digest1+".pem" || filepath.Base(path2) != digest2+".pem" {
		t.Fatal("CA path is not derived from its digest")
	}

	if err := privatepath.WriteFileAtomic(path1, []byte(second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := firstTransport.materializePrivateCA(stateDir); err == nil {
		t.Fatal("tampered immutable CA was overwritten or accepted")
	}
}
