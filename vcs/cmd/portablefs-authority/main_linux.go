//go:build linux

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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"golang.org/x/sys/unix"
)

type options struct {
	listen, volumeID, root                         string
	projectID                                      uint
	tlsCert, tlsKey, clientCA, capabilityPublicKey string
	maxFrame, maxRead, maxWrite                    uint
	replaySlots                                    uint
	maxSessions, maxLockRecords                    uint
	maxItemsPerSession, maxOpensPerSession         uint
	maxItems, maxOpens                             uint
	sessionLease                                   time.Duration
	maxInFlight, maxConnections                    int
	handshakeTimeout, idleTimeout, writeTimeout    time.Duration
}

func run() error {
	var o options
	flag.StringVar(&o.listen, "listen", "", "TCP address to listen on")
	flag.StringVar(&o.volumeID, "volume-id", "", "exact volume identity served by this process")
	flag.StringVar(&o.root, "root", "", "absolute provisioned XFS project-directory root")
	flag.UintVar(&o.projectID, "project-id", 0, "expected nonzero XFS project ID")
	flag.StringVar(&o.tlsCert, "tls-cert", "", "server certificate PEM")
	flag.StringVar(&o.tlsKey, "tls-key", "", "server private key PEM")
	flag.StringVar(&o.clientCA, "client-ca", "", "client CA bundle PEM")
	flag.StringVar(&o.capabilityPublicKey, "capability-public-key", "", "Ed25519 capability public key PEM")
	flag.UintVar(&o.maxFrame, "max-frame-bytes", 16<<20, "hard protobuf frame allocation bound")
	flag.UintVar(&o.maxRead, "max-read-bytes", 1<<20, "maximum bytes in one read reply")
	flag.UintVar(&o.maxWrite, "max-write-bytes", 1<<20, "maximum bytes in one write request")
	flag.UintVar(&o.replaySlots, "max-replay-slots", 256, "maximum concurrent retry slots per session")
	flag.UintVar(&o.maxSessions, "max-sessions", 1024, "maximum live mount sessions for this volume worker")
	flag.UintVar(&o.maxLockRecords, "max-lock-records", 65536, "maximum held and waiting POSIX lock records")
	flag.UintVar(&o.maxItemsPerSession, "max-items-per-session", 8192, "maximum descriptor-backed item capabilities per session")
	flag.UintVar(&o.maxOpensPerSession, "max-opens-per-session", 4096, "maximum open file descriptions per session")
	flag.UintVar(&o.maxItems, "max-items", 65536, "maximum descriptor-backed item capabilities for the worker")
	flag.UintVar(&o.maxOpens, "max-opens", 32768, "maximum open file descriptions for the worker")
	flag.DurationVar(&o.sessionLease, "session-lease", 2*time.Minute, "renewable session lease")
	flag.IntVar(&o.maxInFlight, "max-in-flight", 256, "requests concurrently executing per TLS connection")
	flag.IntVar(&o.maxConnections, "max-connections", 2048, "maximum accepted TLS connections for the worker")
	flag.DurationVar(&o.handshakeTimeout, "tls-handshake-timeout", 10*time.Second, "maximum TLS handshake duration")
	flag.DurationVar(&o.idleTimeout, "connection-idle-timeout", 5*time.Minute, "maximum interval without a complete request frame")
	flag.DurationVar(&o.writeTimeout, "connection-write-timeout", 30*time.Second, "maximum response frame write duration")
	flag.Parse()
	if os.Geteuid() == 0 {
		return errors.New("portablefs-authority refuses to run as root; provision XFS first, then run as the volume service owner")
	}
	if o.listen == "" || o.volumeID == "" || o.root == "" || o.projectID == 0 ||
		o.tlsCert == "" || o.tlsKey == "" || o.clientCA == "" || o.capabilityPublicKey == "" {
		return errors.New("listen, volume-id, root, nonzero project-id, TLS files, client CA, and capability public key are required")
	}
	maxUint32 := uint(^uint32(0))
	if o.projectID > maxUint32 || o.maxFrame == 0 || o.maxFrame > maxUint32 ||
		o.maxRead == 0 || o.maxRead > maxUint32 || o.maxWrite == 0 || o.maxWrite > maxUint32 ||
		o.replaySlots == 0 || o.replaySlots > maxUint32 || o.sessionLease < time.Second ||
		o.maxSessions == 0 || o.maxSessions > maxUint32 || o.maxLockRecords == 0 || o.maxLockRecords > maxUint32 ||
		o.maxItemsPerSession == 0 || o.maxItemsPerSession > maxUint32 || o.maxOpensPerSession == 0 || o.maxOpensPerSession > maxUint32 ||
		o.maxItems == 0 || o.maxItems > maxUint32 || o.maxOpens == 0 || o.maxOpens > maxUint32 ||
		o.maxItemsPerSession > o.maxItems || o.maxOpensPerSession > o.maxOpens ||
		o.maxInFlight <= 0 || uint64(o.maxInFlight) > uint64(maxUint32) || o.maxConnections <= 0 || o.handshakeTimeout <= 0 || o.idleTimeout <= o.sessionLease || o.writeTimeout <= 0 {
		return errors.New("protocol allocation and replay bounds must be positive uint32 values")
	}
	if uint64(o.maxRead)+1024 > uint64(o.maxFrame) || uint64(o.maxWrite)+1024 > uint64(o.maxFrame) {
		return errors.New("max-frame-bytes must leave at least 1024 bytes around each read/write payload")
	}

	store, err := xfsstore.Open(o.root, xfsstore.Config{
		ExpectedProjectID: uint32(o.projectID),
		ExpectedOwnerUID:  uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid()),
	})
	if err != nil {
		return fmt.Errorf("open authoritative XFS volume: %w", err)
	}
	defer store.Close()
	runtime, err := volumeserver.New(o.volumeID, volumeserver.Config{
		SessionLease: o.sessionLease, MaxReplaySlots: uint32(o.replaySlots),
		MaxSessions: uint32(o.maxSessions), MaxLockRecords: uint32(o.maxLockRecords),
	})
	if err != nil {
		return err
	}
	publicKey, err := readEd25519PublicKey(o.capabilityPublicKey)
	if err != nil {
		return err
	}
	authorizer := &volumecap.Authorizer{PublicKey: publicKey, ClockSkew: 5 * time.Second}
	tlsConfig, err := serverTLSConfig(o.tlsCert, o.tlsKey, o.clientCA)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	storageFailure := make(chan error, 1)
	handler := &authorityrpc.VolumeHandler{
		Store: store, Runtime: runtime, Authorizer: authorizer,
		MaxFrame: uint32(o.maxFrame), MaxRead: uint32(o.maxRead), MaxWrite: uint32(o.maxWrite), MaxInFlight: uint32(o.maxInFlight),
		MaxItemsPerSession: uint32(o.maxItemsPerSession), MaxOpensPerSession: uint32(o.maxOpensPerSession),
		MaxItems: uint32(o.maxItems), MaxOpens: uint32(o.maxOpens),
		OnStorageFailure: func(err error) {
			select {
			case storageFailure <- err:
			default:
			}
			stop()
		},
	}
	server := &authorityrpc.Server{
		Handler: handler, MaxFrame: uint32(o.maxFrame), MaxInFlight: o.maxInFlight, MaxConnections: o.maxConnections,
		HandshakeTimeout: o.handshakeTimeout, IdleTimeout: o.idleTimeout, WriteTimeout: o.writeTimeout,
	}
	listener, err := net.Listen("tcp", o.listen)
	if err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(o.sessionLease / 4)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runtime.Sweep()
			}
		}
	}()
	serveErr := server.Serve(ctx, listener, tlsConfig)
	select {
	case failure := <-storageFailure:
		return fmt.Errorf("authoritative storage failed and this epoch was fenced: %w", failure)
	default:
		return serveErr
	}
}

func serverTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read server TLS certificate: %w", err)
	}
	keyPEM, err := readPrivateFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read server TLS private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server TLS identity: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("client CA contains no certificates")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: pool, Certificates: []tls.Certificate{certificate},
		NextProtos: []string{"portablefs-authority-v1"},
	}, nil
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

func readEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read capability public key: %w", err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("capability public key must be one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("capability public key is not Ed25519")
	}
	return key, nil
}
