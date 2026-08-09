package hostedauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/productauth"
)

func TestPublicProductSignerBindsAProofOfPossessionCSR(t *testing.T) {
	productPublic, productPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, clientPrivate, _ := ed25519.GenerateKey(rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	peerText, err := CSRPeerSPKI(csr)
	if err != nil {
		t.Fatal(err)
	}
	peerBytes, err := base64.RawURLEncoding.DecodeString(peerText)
	if err != nil {
		t.Fatal(err)
	}
	var peer [32]byte
	copy(peer[:], peerBytes)
	now := time.Unix(1_900_000_000, 0)
	claims := ProductClaims{
		Issuer: "opensteer", Audience: ManagerAudience, AuthorizationDomain: "org", Owner: "owner", Subject: "user",
		VolumeID: "22222222-2222-4222-8222-222222222222", Access: []string{"write"}, PeerSPKI: peerText,
		Nonce: "one-use-product-decision", NotBefore: now.Add(-time.Second).Unix(), Expires: now.Add(10 * time.Minute).Unix(),
	}
	token, err := SignProductAuthorization(productPrivate, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := productauth.Verify(productPublic, []byte(token), productauth.Expectations{
		Issuer: claims.Issuer, Audience: ManagerAudience, AuthorizationDomain: claims.AuthorizationDomain,
		Owner: claims.Owner, VolumeID: claims.VolumeID, PeerSPKI: peer, Now: now,
		ClockSkew: time.Second, MaxLifetime: 15 * time.Minute,
	}); err != nil {
		t.Fatalf("manager verifier rejected public signer output: %v", err)
	}
}
