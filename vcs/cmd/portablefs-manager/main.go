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
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
	"github.com/steerlabs/portablefs/vcs/internal/archiveverify"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"golang.org/x/sys/unix"
)

var version = "dev"

type issuerKeyFlags []string

func (values *issuerKeyFlags) String() string { return strings.Join(*values, ",") }
func (values *issuerKeyFlags) Set(value string) error {
	if !strings.Contains(value, "=") {
		return errors.New("product issuer key must be issuer=/absolute/public-key.pem")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "portablefs-manager:", err)
		os.Exit(1)
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "print exact release identity and exit")
	var productKeys issuerKeyFlags
	listen := flag.String("listen", "", "mTLS control address")
	stateFile := flag.String("state-file", "", "absolute durable manager state path")
	serverCert := flag.String("tls-cert", "", "manager TLS server certificate PEM")
	serverKey := flag.String("tls-key", "", "manager TLS server private key PEM")
	controlCA := flag.String("control-client-ca", "", "control-channel client CA bundle PEM")
	planKey := flag.String("plan-signing-key", "", "Ed25519 cell-plan private key PEM")
	capabilityKey := flag.String("capability-signing-key", "", "Ed25519 mount-capability private key PEM")
	authorityCACert := flag.String("authority-ca-cert", "", "authority TLS CA certificate PEM")
	authorityCAKey := flag.String("authority-ca-key", "", "authority TLS CA private key PEM")
	clientCACert := flag.String("mount-client-ca-cert", "", "mount client CA certificate PEM")
	clientCAKey := flag.String("mount-client-ca-key", "", "mount client CA private key PEM")
	enrollmentCACert := flag.String("mount-enrollment-ca-cert", "", "Manager-facing mount enrollment CA certificate PEM")
	enrollmentCAKey := flag.String("mount-enrollment-ca-key", "", "Manager-facing mount enrollment CA private key PEM")
	flag.Var(&productKeys, "product-issuer-key", "trusted product authorization key as issuer=/absolute/public-key.pem; repeatable")
	archiveCredentials := flag.String("archive-credentials", "", "archive-store credentials file enabling seal verification and purge (optional)")
	planLifetime := flag.Duration("plan-lifetime", 15*time.Minute, "signed cell plan lifetime")
	grantLifetime := flag.Duration("grant-lifetime", 10*time.Minute, "mount grant lifetime")
	enrollmentLease := flag.Duration("mount-enrollment-lease", 30*time.Minute, "sliding lease for one key-bound automatic mount enrollment")
	productLifetime := flag.Duration("product-authorization-max-lifetime", 15*time.Minute, "maximum product assertion lifetime")
	clientCertLifetime := flag.Duration("mount-client-cert-lifetime", time.Hour, "mount client certificate lifetime")
	authorityCertLifetime := flag.Duration("authority-cert-lifetime", 24*time.Hour, "authority server certificate lifetime")
	observedStale := flag.Duration("observed-stale-after", 2*time.Minute, "maximum cell observation age for mount issuance")
	maxArchivingPerCell := flag.Int("max-archiving-per-cell", 2, "maximum concurrent archive cycles doing cell-side work on one cell")
	maxRestoringPerCell := flag.Int("max-restoring-per-cell", 4, "maximum concurrent restores placed on one cell")
	clockSkew := flag.Duration("clock-skew", 5*time.Second, "maximum authenticated clock disagreement")
	flag.Parse()
	if *showVersion {
		_, _ = fmt.Fprintln(os.Stdout, version)
		return nil
	}
	if *maxArchivingPerCell <= 0 || *maxRestoringPerCell <= 0 {
		return errors.New("max-archiving-per-cell and max-restoring-per-cell must be positive")
	}
	if flag.NArg() != 0 || *listen == "" || *stateFile == "" || *serverCert == "" || *serverKey == "" ||
		*controlCA == "" || *planKey == "" || *capabilityKey == "" || *authorityCACert == "" ||
		*authorityCAKey == "" || *clientCACert == "" || *clientCAKey == "" ||
		*enrollmentCACert == "" || *enrollmentCAKey == "" || len(productKeys) == 0 {
		return errors.New("listen, state, TLS, control CA, signing keys, authority, mount-client, mount-enrollment CAs, and at least one product issuer key are required")
	}
	if os.Geteuid() == 0 {
		return errors.New("refuses to run as root")
	}
	for _, path := range []string{*stateFile, *serverCert, *serverKey, *controlCA, *planKey, *capabilityKey,
		*authorityCACert, *authorityCAKey, *clientCACert, *clientCAKey, *enrollmentCACert, *enrollmentCAKey} {
		if !cleanAbsolutePath(path) {
			return fmt.Errorf("path must be clean and absolute: %q", path)
		}
	}
	store, err := controlplane.OpenStore(*stateFile)
	if err != nil {
		return err
	}
	defer store.Close()
	planPrivate, err := readEd25519PrivateKey(*planKey)
	if err != nil {
		return fmt.Errorf("plan signing key: %w", err)
	}
	capabilityPrivate, err := readEd25519PrivateKey(*capabilityKey)
	if err != nil {
		return fmt.Errorf("capability signing key: %w", err)
	}
	issuers := make(map[string]ed25519.PublicKey, len(productKeys))
	for _, value := range productKeys {
		parts := strings.SplitN(value, "=", 2)
		if parts[0] == "" || parts[1] == "" {
			return errors.New("product issuer key must name an issuer and path")
		}
		if !cleanAbsolutePath(parts[1]) {
			return fmt.Errorf("product issuer key path must be clean and absolute: %q", parts[1])
		}
		key, err := readEd25519PublicKey(parts[1])
		if err != nil {
			return fmt.Errorf("product issuer %s: %w", parts[0], err)
		}
		if _, duplicate := issuers[parts[0]]; duplicate {
			return fmt.Errorf("duplicate product issuer %q", parts[0])
		}
		issuers[parts[0]] = key
	}
	authorityCA, err := readCA(*authorityCACert, *authorityCAKey)
	if err != nil {
		return fmt.Errorf("authority CA: %w", err)
	}
	clientCA, err := readCA(*clientCACert, *clientCAKey)
	if err != nil {
		return fmt.Errorf("mount client CA: %w", err)
	}
	enrollmentCA, err := readCA(*enrollmentCACert, *enrollmentCAKey)
	if err != nil {
		return fmt.Errorf("mount enrollment CA: %w", err)
	}
	// The archive store is optional deployment capability: without it the
	// Manager serves normally and refuses archive/destroy operations with
	// ErrArchiveStoreUnavailable rather than pretending.
	var archiveVerifier controlplane.ArchiveVerifier
	var archivePurger controlplane.ArchivePurger
	if *archiveCredentials != "" {
		if !cleanAbsolutePath(*archiveCredentials) {
			return fmt.Errorf("archive credentials path must be clean and absolute: %q", *archiveCredentials)
		}
		storeConfig, err := archivestore.LoadConfigFile(*archiveCredentials)
		if err != nil {
			return fmt.Errorf("archive credentials: %w", err)
		}
		client, err := archivestore.New(storeConfig)
		if err != nil {
			return fmt.Errorf("archive store: %w", err)
		}
		verify, err := archiveverify.New(client)
		if err != nil {
			return err
		}
		archiveVerifier, archivePurger = verify, verify
	}
	manager, err := controlplane.NewManager(controlplane.ManagerConfig{
		Store: store, PlanPrivateKey: planPrivate, CapabilityPrivateKey: capabilityPrivate,
		ProductIssuers: issuers, AuthorityCA: authorityCA, ClientCA: clientCA, EnrollmentCA: enrollmentCA,
		ReleaseID: version, PlanLifetime: *planLifetime, GrantLifetime: *grantLifetime,
		EnrollmentLease:    *enrollmentLease,
		ProductMaxLifetime: *productLifetime, ClientCertLifetime: *clientCertLifetime,
		AuthorityCertLifetime: *authorityCertLifetime, ObservedStaleAfter: *observedStale, ClockSkew: *clockSkew,
		MaxArchivingPerCell: *maxArchivingPerCell, MaxRestoringPerCell: *maxRestoringPerCell,
		ArchiveVerifier: archiveVerifier, ArchivePurger: archivePurger,
	})
	if err != nil {
		return err
	}
	tlsConfig, err := controlTLSConfig(*serverCert, *serverKey, *controlCA, *enrollmentCACert)
	if err != nil {
		return err
	}
	controlCAPEM, err := os.ReadFile(*controlCA)
	if err != nil {
		return err
	}
	enrollmentCAPEM, err := os.ReadFile(*enrollmentCACert)
	if err != nil {
		return err
	}
	authenticate, err := controlplane.NewRoleBoundMTLSAuthenticator(controlCAPEM, enrollmentCAPEM)
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", *listen, tlsConfig)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{
		Handler: &controlplane.HTTPHandler{Manager: manager, Authenticate: authenticate}, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Archive-seal verification is deliberately not performed inside the
	// observation transaction: the store lock must never be held across
	// archive-store network I/O. This loop drives every volume waiting at the
	// "verifying" cursor through the unlocked two-phase commit; failures stay
	// at the cursor and retry on the next tick (a visible, non-destructive
	// stall — XFS remains canonical until the commit).
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pending, err := manager.PendingVerifications()
				if err != nil {
					continue
				}
				for _, volumeID := range pending {
					if err := manager.NoteVerify(volumeID); err != nil {
						log.Printf("portablefs-manager: archive verification for %s: %v", volumeID, err)
					}
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = serveManager(server, listener, notifySystemdReady)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func serveManager(server *http.Server, listener net.Listener, notifyReady func() error) error {
	// The listener is already bound here. Notify immediately before Serve enters
	// its accept loop so systemd cannot report startup before the control plane
	// can receive connections.
	if err := notifyReady(); err != nil {
		return fmt.Errorf("notify systemd readiness: %w", err)
	}
	return server.Serve(listener)
}

func notifySystemdReady() error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	address := systemdNotifyAddress(socket)
	connection, err := net.DialUnix("unixgram", nil, address)
	if err != nil {
		return err
	}
	defer connection.Close()
	_, err = connection.Write([]byte("READY=1"))
	return err
}

func systemdNotifyAddress(socket string) *net.UnixAddr {
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	return &net.UnixAddr{Name: socket, Net: "unixgram"}
}

func cleanAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func controlTLSConfig(certPath, keyPath string, clientCAPaths ...string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readPrivateFile(keyPath)
	if err != nil {
		return nil, err
	}
	identity, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	clientCAs := x509.NewCertPool()
	for _, clientCAPath := range clientCAPaths {
		clientCAPEM, err := os.ReadFile(clientCAPath)
		if err != nil {
			return nil, err
		}
		if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
			return nil, fmt.Errorf("client CA %s has no certificates", clientCAPath)
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientCAs, Certificates: []tls.Certificate{identity}, NextProtos: []string{"h2", "http/1.1"},
	}, nil
}

func readCA(certPath, keyPath string) (*controlplane.CertificateAuthority, error) {
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	privateKey, err := readPrivateFile(keyPath)
	if err != nil {
		return nil, err
	}
	return controlplane.ParseCertificateAuthority(certificate, privateKey)
}

func readEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readPrivateFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("key must contain one PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not Ed25519")
	}
	return key, nil
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
	if !ok {
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
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key must be a regular file unreadable by group and other users")
	}
	return io.ReadAll(file)
}
