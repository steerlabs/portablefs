package portablefsd

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
)

const maxDataPlaneCABytes = 256 << 10

type dataPlaneTransport struct {
	mode       string
	serverName string
	caPEM      string
	caSHA256   string
}

func strictDataPlaneCertificates(data []byte) ([]*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("certificate bundle contains no certificates")
	}
	if len(data) > maxDataPlaneCABytes {
		return nil, fmt.Errorf("certificate bundle exceeds %d bytes", maxDataPlaneCABytes)
	}
	var certificates []*x509.Certificate
	rest := data
	for {
		rest = bytes.TrimSpace(rest)
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("data exists outside CERTIFICATE PEM blocks")
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("invalid unadorned CERTIFICATE PEM block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", len(certificates)+1, err)
		}
		certificates = append(certificates, certificate)
		rest = next
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("certificate bundle contains no certificates")
	}
	return certificates, nil
}

func validateDataPlaneName(name string) error {
	if name == "" || name != strings.TrimSpace(name) || len(name) > 253 ||
		strings.ContainsAny(name, "\x00/\\") || strings.HasPrefix(name, "[") || strings.HasSuffix(name, "]") {
		return fmt.Errorf("invalid exact TLS server name")
	}
	if net.ParseIP(name) != nil {
		return nil
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid exact TLS server name")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("invalid exact TLS server name")
			}
		}
	}
	return nil
}

func (t dataPlaneTransport) validate() error {
	switch t.mode {
	case "tls-private-ca":
		if err := validateDataPlaneName(t.serverName); err != nil {
			return err
		}
		if _, err := strictDataPlaneCertificates([]byte(t.caPEM)); err != nil {
			return fmt.Errorf("invalid private CA: %w", err)
		}
		sum := sha256.Sum256([]byte(t.caPEM))
		actual := hex.EncodeToString(sum[:])
		if len(t.caSHA256) != 64 || t.caSHA256 != strings.ToLower(t.caSHA256) {
			return fmt.Errorf("private CA SHA-256 must be 64 lowercase hexadecimal characters")
		}
		if _, err := hex.DecodeString(t.caSHA256); err != nil {
			return fmt.Errorf("invalid private CA SHA-256: %w", err)
		}
		if actual != t.caSHA256 {
			return fmt.Errorf("private CA SHA-256 mismatch: declared %s, received %s", t.caSHA256, actual)
		}
	case "tls-system-pki":
		if err := validateDataPlaneName(t.serverName); err != nil {
			return err
		}
		if t.caPEM != "" || t.caSHA256 != "" {
			return fmt.Errorf("tls-system-pki must not include private CA fields")
		}
	case "plaintext":
		if t.serverName != "" || t.caPEM != "" || t.caSHA256 != "" {
			return fmt.Errorf("plaintext must not include TLS fields")
		}
	case "":
		return fmt.Errorf("missing dataPlaneTransport")
	default:
		return fmt.Errorf("unsupported dataPlaneTransport %q", t.mode)
	}
	return nil
}

func (t dataPlaneTransport) tlsConfig() (*tls.Config, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	switch t.mode {
	case "plaintext":
		return nil, nil
	case "tls-system-pki":
		return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: t.serverName}, nil
	case "tls-private-ca":
		certificates, err := strictDataPlaneCertificates([]byte(t.caPEM))
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		for _, certificate := range certificates {
			pool.AddCert(certificate)
		}
		return &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: t.serverName,
			RootCAs:    pool,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported dataPlaneTransport %q", t.mode)
	}
}
