package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellagent"
	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"golang.org/x/sys/unix"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "portablefs-cell-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "print exact release identity and exit")
	cellID := flag.String("cell-id", "", "stable cell UUID")
	managerURL := flag.String("manager-url", "", "PortableFS manager HTTPS origin")
	managerServerName := flag.String("manager-server-name", "", "manager TLS DNS name")
	clientCert := flag.String("tls-cert", "", "cell control-client certificate PEM")
	clientKey := flag.String("tls-key", "", "cell control-client private key PEM")
	managerCA := flag.String("manager-ca", "", "manager control TLS CA PEM")
	planPublicKey := flag.String("plan-public-key", "", "manager cell-plan Ed25519 public key PEM")
	helperSocket := flag.String("helper-socket", "/run/portablefs-cell-helper/default.sock", "local root-helper Unix socket")
	pollInterval := flag.Duration("poll-interval", 10*time.Second, "desired-state poll interval")
	planLifetime := flag.Duration("plan-max-lifetime", 15*time.Minute, "maximum accepted cell-plan lifetime")
	clockSkew := flag.Duration("clock-skew", 5*time.Second, "maximum authenticated clock disagreement")
	flag.Parse()
	if *showVersion {
		_, _ = fmt.Fprintln(os.Stdout, version)
		return nil
	}
	if flag.NArg() != 0 || !cellplan.ValidID(*cellID) || *managerURL == "" || *managerServerName == "" ||
		*clientCert == "" || *clientKey == "" || *managerCA == "" || *planPublicKey == "" || *pollInterval <= 0 ||
		*planLifetime <= 0 || *clockSkew < 0 || !filepath.IsAbs(*helperSocket) || filepath.Clean(*helperSocket) != *helperSocket {
		return errors.New("cell identity, manager identity, mTLS files, plan key, helper socket, and valid intervals are required")
	}
	if os.Geteuid() == 0 {
		return errors.New("refuses to run as root")
	}
	for _, path := range []string{*clientCert, *clientKey, *managerCA, *planPublicKey} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("path must be clean and absolute: %q", path)
		}
	}
	planKey, err := readEd25519PublicKey(*planPublicKey)
	if err != nil {
		return fmt.Errorf("plan public key: %w", err)
	}
	tlsConfig, err := clientTLSConfig(*clientCert, *clientKey, *managerCA, *managerServerName)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	managerTransport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 90 * time.Second,
	}
	helperTransport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", *helperSocket)
		},
		MaxIdleConns: 2, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second,
	}
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	agent, err := cellagent.New(cellagent.Config{
		CellID: *cellID, ManagerURL: *managerURL, PlanPublicKey: planKey, PlanLifetime: *planLifetime,
		ClockSkew: *clockSkew, PollInterval: *pollInterval, ReleaseID: version,
		ManagerClient: &http.Client{Transport: managerTransport, Timeout: 45 * time.Second, CheckRedirect: noRedirect},
		HelperClient:  &http.Client{Transport: helperTransport, Timeout: 45 * time.Second, CheckRedirect: noRedirect},
		ReportError:   func(err error) { _, _ = fmt.Fprintln(os.Stderr, "portablefs-cell-agent: reconcile:", err) },
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx)
}

func clientTLSConfig(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := readPrivateFile(keyPath)
	if err != nil {
		return nil, err
	}
	identity, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("manager CA bundle has no certificates")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots,
		Certificates: []tls.Certificate{identity}, NextProtos: []string{"h2", "http/1.1"},
	}, nil
}

func readEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("key must contain one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("key is not Ed25519")
	}
	return key, nil
}

func readPrivateFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, syscall.EBADF
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key must be a private regular file")
	}
	return io.ReadAll(file)
}
