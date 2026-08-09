// Package hostedauth contains the small public surface a product integration
// needs to authorize PortableFS hosted mounts. It does not call the manager or
// hold PortableFS infrastructure keys.
package hostedauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/steerlabs/portablefs/vcs/internal/productauth"
)

const ManagerAudience = "portablefs-manager"

// ProductClaims is the product's independent user authorization decision. The
// manager and authority both verify it; neither treats control-channel mTLS as
// a substitute for this signed, client-key-bound decision.
type ProductClaims = productauth.Claims

// SignProductAuthorization signs one exact product decision. The manager
// validates all claims and time bounds before issuing infrastructure identity.
func SignProductAuthorization(privateKey ed25519.PrivateKey, claims ProductClaims) (string, error) {
	token, err := productauth.Sign(privateKey, claims)
	return string(token), err
}

// CSRPeerSPKI returns the unpadded base64url SHA-256 SPKI value used in
// ProductClaims.PeerSPKI. It verifies the CSR proof of possession first.
func CSRPeerSPKI(csrPEM []byte) (string, error) {
	block, rest := pem.Decode(csrPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "CERTIFICATE REQUEST" {
		return "", errors.New("hostedauth: CSR must contain one CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return "", errors.New("hostedauth: CSR proof of possession is invalid")
	}
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
