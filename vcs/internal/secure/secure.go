// Package secure builds TLS configs for the custom FS protocol and the WAL
// replication channel, so file data and journals are encrypted in transit when a
// client (FUSE mount) or standby is on a different machine / across the internet.
// TLS is opt-in via env; unset means plaintext (e.g. a trusted LAN or behind
// WireGuard). The in-kernel NFS path can't do TLS and is secured at the network
// layer instead.
package secure

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// ServerTLS builds a server TLS config from VCS_TLS_CERT + VCS_TLS_KEY (PEM file
// paths). If VCS_TLS_CLIENT_CA is set, client certificates are required and
// verified (mutual TLS). Returns nil when TLS is not configured.
func ServerTLS() (*tls.Config, error) {
	certFile, keyFile := os.Getenv("VCS_TLS_CERT"), os.Getenv("VCS_TLS_KEY")
	if certFile == "" || keyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if ca := os.Getenv("VCS_TLS_CLIENT_CA"); ca != "" {
		pool, err := loadCA(ca)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// ClientTLS builds a client TLS config from VCS_TLS_CA (the CA that signs the
// server's cert). Optional VCS_TLS_CERT/KEY add a client certificate for mutual
// TLS. VCS_TLS_INSECURE=1 skips verification (trusted networks / testing only).
// Returns nil when TLS is not configured.
func ClientTLS() (*tls.Config, error) {
	caFile := os.Getenv("VCS_TLS_CA")
	insecure := os.Getenv("VCS_TLS_INSECURE") == "1"
	if caFile == "" && !insecure {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: insecure} //nolint:gosec // opt-in via env
	if caFile != "" {
		pool, err := loadCA(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if certFile, keyFile := os.Getenv("VCS_TLS_CERT"), os.Getenv("VCS_TLS_KEY"); certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func loadCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}
