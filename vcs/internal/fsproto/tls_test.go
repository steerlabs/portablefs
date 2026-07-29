package fsproto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// TestTLSRoundTrip: with TLS configured, file ops succeed over an encrypted
// connection, and a plaintext client cannot talk to the TLS server.
func TestTLSRoundTrip(t *testing.T) {
	cert, caPool := selfSignedCert(t)

	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = NewServer(fs, fs).Serve(ctx, tlsLn) }()
	addr := ln.Addr().String()

	// Encrypted client trusts the CA -> ops succeed.
	cli, err := DialTLS(addr, 2, &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer cli.Close()
	if _, st, _ := cli.Create("x", 0o644); st != OK {
		t.Fatalf("create over TLS st=%d", st)
	}
	if _, st, _ := cli.Write("x", 0, []byte("secret"), 0o644); st != OK {
		t.Fatalf("write over TLS st=%d", st)
	}
	if data, st, _ := cli.Read("x", 0, 64); st != OK || string(data) != "secret" {
		t.Fatalf("read over TLS = %q (st=%d)", data, st)
	}

	// A plaintext client cannot speak to the TLS server.
	plain, err := Dial(addr, 1)
	if err == nil {
		if _, _, opErr := plain.Create("y", 0o644); opErr == nil {
			t.Fatal("plaintext op against a TLS server should fail")
		}
		_ = plain.Close()
	}
}
