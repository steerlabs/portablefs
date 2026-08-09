package portablefsd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestV3ReplacementCertificateKeepsLocalKeyAndUpdatesReconnectIdentity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	initialPEM := issueClientCertificatePEM(t, publicKey, privateKey, now, 1)
	initial, err := tls.X509KeyPair([]byte(initialPEM), pem.EncodeToMemory(testPrivateKeyPEM(t, privateKey)))
	if err != nil {
		t.Fatal(err)
	}
	config := &v3AttachConfig{identity: &initial}
	replacementPEM := issueClientCertificatePEM(t, publicKey, privateKey, now, 2)
	replacement, err := config.replacementCertificate(replacementPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	config.installReplacementCertificate(replacement)
	got, err := config.clientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	gotPrivate, ok := got.PrivateKey.(ed25519.PrivateKey)
	if leaf.SerialNumber.Cmp(big.NewInt(2)) != 0 || !ok || !bytes.Equal(gotPrivate, privateKey) {
		t.Fatalf("replacement identity serial=%s private key preserved=%v", leaf.SerialNumber, ok && bytes.Equal(gotPrivate, privateKey))
	}

	otherPublic, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	wrongPEM := issueClientCertificatePEM(t, otherPublic, otherPrivate, now, 3)
	if _, err := config.replacementCertificate(wrongPEM, now); err == nil {
		t.Fatal("certificate for a different private key was accepted")
	}
}

func issueClientCertificatePEM(t *testing.T, publicKey ed25519.PublicKey, signer ed25519.PrivateKey, now time.Time, serial int64) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "mount"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func testPrivateKeyPEM(t *testing.T, privateKey ed25519.PrivateKey) *pem.Block {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return &pem.Block{Type: "PRIVATE KEY", Bytes: der}
}
