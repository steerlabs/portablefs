package cli

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
)

const (
	maxRouterCABytes               = 256 << 10
	dataPlaneTransportTLSPrivateCA = "tls-private-ca"
	dataPlaneTransportTLSSystemPKI = "tls-system-pki"
	dataPlaneTransportPlaintext    = "plaintext"
)

// dataPlaneTransport is the lease-bound transport contract emitted by the
// authority manager. No field is inferred: an empty CA is never a synonym for
// plaintext, and TLS always carries an exact verification name.
type dataPlaneTransport struct {
	Mode       string `json:"mode"`
	ServerName string `json:"serverName,omitempty"`
	CAPEM      string `json:"caPem,omitempty"`
	CASHA256   string `json:"caSha256,omitempty"`
}

func validateDataPlaneServerName(name string) error {
	if name == "" || name != strings.TrimSpace(name) || len(name) > 253 {
		return fmt.Errorf("serverName must contain 1-253 characters without surrounding whitespace")
	}
	if strings.ContainsAny(name, "\x00/\\") {
		return fmt.Errorf("serverName contains a forbidden character")
	}
	if strings.HasPrefix(name, "[") || strings.HasSuffix(name, "]") {
		return fmt.Errorf("serverName must not bracket an IP address")
	}
	if ip := net.ParseIP(name); ip != nil {
		return nil
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("serverName is not a valid DNS name")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("serverName is not a valid DNS name")
			}
		}
	}
	return nil
}

func strictCACertificates(data []byte) ([]*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("certificate bundle contains no certificates")
	}
	if len(data) > maxRouterCABytes {
		return nil, fmt.Errorf("certificate bundle exceeds %d bytes", maxRouterCABytes)
	}
	rest := data
	var certificates []*x509.Certificate
	for {
		rest = bytes.TrimSpace(rest)
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("non-whitespace data exists outside CERTIFICATE PEM blocks")
		}
		block, next := pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM encoding")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("PEM block must be an unadorned CERTIFICATE")
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

func (t dataPlaneTransport) validate() error {
	switch t.Mode {
	case dataPlaneTransportTLSPrivateCA:
		if err := validateDataPlaneServerName(t.ServerName); err != nil {
			return fmt.Errorf("tls-private-ca %w", err)
		}
		if _, err := strictCACertificates([]byte(t.CAPEM)); err != nil {
			return fmt.Errorf("tls-private-ca caPem: %w", err)
		}
		sum := sha256.Sum256([]byte(t.CAPEM))
		actual := hex.EncodeToString(sum[:])
		if t.CASHA256 == "" || t.CASHA256 != strings.ToLower(t.CASHA256) || len(t.CASHA256) != 64 {
			return fmt.Errorf("tls-private-ca caSha256 must be 64 lowercase hexadecimal characters")
		}
		if _, err := hex.DecodeString(t.CASHA256); err != nil {
			return fmt.Errorf("tls-private-ca caSha256: %w", err)
		}
		if actual != t.CASHA256 {
			return fmt.Errorf("tls-private-ca CA fingerprint mismatch: manager declared %s, received %s", t.CASHA256, actual)
		}
	case dataPlaneTransportTLSSystemPKI:
		if err := validateDataPlaneServerName(t.ServerName); err != nil {
			return fmt.Errorf("tls-system-pki %w", err)
		}
		if t.CAPEM != "" || t.CASHA256 != "" {
			return fmt.Errorf("tls-system-pki must not include private CA fields")
		}
	case dataPlaneTransportPlaintext:
		if t.ServerName != "" || t.CAPEM != "" || t.CASHA256 != "" {
			return fmt.Errorf("plaintext must not include TLS fields")
		}
	case "":
		return fmt.Errorf("manager omitted authority.dataPlaneTransport; upgrade the authority manager before mounting with this PortableFS client")
	default:
		return fmt.Errorf("manager returned unsupported data-plane transport mode %q; upgrade PortableFS so client and manager agree", t.Mode)
	}
	return nil
}

func (t dataPlaneTransport) tlsConfig() (*tls.Config, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	switch t.Mode {
	case dataPlaneTransportPlaintext:
		return nil, nil
	case dataPlaneTransportTLSSystemPKI:
		return &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: t.ServerName,
		}, nil
	case dataPlaneTransportTLSPrivateCA:
		certificates, err := strictCACertificates([]byte(t.CAPEM))
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		for _, certificate := range certificates {
			pool.AddCert(certificate)
		}
		return &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: t.ServerName,
			RootCAs:    pool,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported data-plane transport mode %q", t.Mode)
	}
}

// materializePrivateCA publishes the manager-provided CA under its verified
// digest so mount state can name immutable trust material without mutable
// profile or environment indirection.
func (t dataPlaneTransport) materializePrivateCA(stateDir string) (path, digest string, err error) {
	if err := t.validate(); err != nil {
		return "", "", err
	}
	if t.Mode != dataPlaneTransportTLSPrivateCA {
		return "", "", nil
	}
	path = filepath.Join(stateDir, "ca", t.CASHA256+".pem")
	existing, readErr := privatepath.ReadFile(path)
	switch {
	case readErr == nil:
		if !bytes.Equal(existing, []byte(t.CAPEM)) {
			return "", "", fmt.Errorf("content-addressed data-plane CA %s does not match its SHA-256 name", path)
		}
	case os.IsNotExist(readErr):
		if writeErr := privatepath.WriteFileAtomic(path, []byte(t.CAPEM)); writeErr != nil {
			return "", "", fmt.Errorf("write immutable lease-bound data-plane CA: %w", writeErr)
		}
	default:
		return "", "", fmt.Errorf("read immutable lease-bound data-plane CA: %w", readErr)
	}
	return path, t.CASHA256, nil
}

func directDataPlaneTransport(mode, serverName, caPath string) (dataPlaneTransport, error) {
	transport := dataPlaneTransport{Mode: mode, ServerName: serverName}
	if mode == dataPlaneTransportTLSPrivateCA {
		if caPath == "" {
			return dataPlaneTransport{}, fmt.Errorf("--data-plane-ca is required with --data-plane-transport tls-private-ca")
		}
		fd, err := unix.Open(caPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return dataPlaneTransport{}, fmt.Errorf("open --data-plane-ca without following links: %w", err)
		}
		file := os.NewFile(uintptr(fd), caPath)
		if file == nil {
			_ = unix.Close(fd)
			return dataPlaneTransport{}, fmt.Errorf("open --data-plane-ca: invalid file descriptor")
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return dataPlaneTransport{}, fmt.Errorf("inspect --data-plane-ca: %w", err)
		}
		if !info.Mode().IsRegular() {
			_ = file.Close()
			return dataPlaneTransport{}, fmt.Errorf("--data-plane-ca must name a regular, non-symlink file")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxRouterCABytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return dataPlaneTransport{}, fmt.Errorf("read --data-plane-ca: %w", readErr)
		}
		if closeErr != nil {
			return dataPlaneTransport{}, fmt.Errorf("close --data-plane-ca: %w", closeErr)
		}
		if len(data) > maxRouterCABytes {
			return dataPlaneTransport{}, fmt.Errorf("--data-plane-ca exceeds %d bytes", maxRouterCABytes)
		}
		sum := sha256.Sum256(data)
		transport.CAPEM = string(data)
		transport.CASHA256 = hex.EncodeToString(sum[:])
	} else if caPath != "" {
		return dataPlaneTransport{}, fmt.Errorf("--data-plane-ca is valid only with --data-plane-transport tls-private-ca")
	}
	if err := transport.validate(); err != nil {
		return dataPlaneTransport{}, fmt.Errorf("invalid direct data-plane transport: %w", err)
	}
	return transport, nil
}
