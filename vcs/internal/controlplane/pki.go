package controlplane

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

type CertificateAuthority struct {
	Certificate    *x509.Certificate
	Signer         crypto.Signer
	CertificatePEM string
}

func ParseCertificateAuthority(certificatePEM, privateKeyPEM []byte) (*CertificateAuthority, error) {
	certBlock, rest := pem.Decode(certificatePEM)
	if certBlock == nil || len(rest) != 0 || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("CA certificate must contain one CERTIFICATE PEM block")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("CA certificate is not a certificate-signing CA")
	}
	keyBlock, rest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || len(rest) != 0 {
		return nil, errors.New("CA private key must contain one PEM block")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); rsaErr == nil {
			privateKey = rsaKey
		} else {
			return nil, fmt.Errorf("parse CA private key: %w", err)
		}
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA private key is not a signer")
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, err
	}
	signerPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !equalBytes(certificatePublic, signerPublic) {
		return nil, errors.New("CA certificate and private key do not match")
	}
	return &CertificateAuthority{Certificate: certificate, Signer: signer, CertificatePEM: string(certificatePEM)}, nil
}

func (ca *CertificateAuthority) SignCSR(csrPEM []byte, commonName string, dnsNames []string, client bool, now time.Time, lifetime time.Duration) (string, time.Time, error) {
	if ca == nil || ca.Certificate == nil || ca.Signer == nil || commonName == "" || now.IsZero() || lifetime <= 0 {
		return "", time.Time{}, ErrInvalid
	}
	if now.Before(ca.Certificate.NotBefore) || !now.Before(ca.Certificate.NotAfter) {
		return "", time.Time{}, errors.New("CA certificate is not currently valid")
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE REQUEST" {
		return "", time.Time{}, errors.New("CSR must contain one CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return "", time.Time{}, errors.New("CSR proof of possession is invalid")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 159)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", time.Time{}, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	notBefore := now.Add(-time.Minute)
	if notBefore.Before(ca.Certificate.NotBefore) {
		notBefore = ca.Certificate.NotBefore
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(ca.Certificate.NotAfter) {
		notAfter = ca.Certificate.NotAfter
	}
	if !notAfter.After(now) {
		return "", time.Time{}, errors.New("CA expires before the requested certificate can be issued")
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if _, rsaKey := csr.PublicKey.(*rsa.PublicKey); rsaKey {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		identity, _ := url.Parse("spiffe://portablefs/client/" + commonName)
		template.URIs = []*url.URL{identity}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = append([]string(nil), dnsNames...)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, csr.PublicKey, ca.Signer)
	if err != nil {
		return "", time.Time{}, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), notAfter, nil
}

func ParseCSRSPKI(csrPEM []byte) ([32]byte, error) {
	var out [32]byte
	block, rest := pem.Decode(csrPEM)
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE REQUEST" {
		return out, errors.New("CSR must contain one CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return out, errors.New("CSR proof of possession is invalid")
	}
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return out, err
	}
	return x509SPKIHash(spki), nil
}

func x509SPKIHash(spki []byte) [32]byte {
	return sha256.Sum256(spki)
}

func PublicKeyPEM(publicKey ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
