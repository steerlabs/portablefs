//go:build linux

package main

import (
	"bytes"
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
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"golang.org/x/sys/unix"
)

var version = "dev"

type options struct {
	listen, volumeID, root                         string
	projectID                                      uint
	tlsCert, tlsKey, clientCA, capabilityPublicKey string
	productAuthorizationPublicKey                  string
	productIssuer, productAudience                 string
	authorizationDomain, owner                     string
	cellID, authorityID                            string
	authorityGeneration                            uint64
	maxFrame, maxRead, maxWrite                    uint
	replaySlots                                    uint
	maxSessions, maxLockRecords                    uint
	maxItemsPerSession, maxOpensPerSession         uint
	maxItems, maxOpens                             uint
	maxRetainedReplyBytes, maxFrameBytesInFlight   uint64
	writeStaging                                   string
	maxWriteStagingBytesPerSession                 uint64
	maxWriteStagingBytes                           uint64
	maxWriteTransactionsPerSession                 uint
	maxWriteTransactions                           uint
	writeTransactionProgressTimeout                time.Duration
	writeTransactionAbsoluteTimeout                time.Duration
	terminalDeliveryTimeout                        time.Duration
	capabilityLifetime                             time.Duration
	capabilityNonces                               uint
	sessionLease                                   time.Duration
	maxInFlight, maxConnections                    int
	handshakeTimeout, idleTimeout, writeTimeout    time.Duration
	visibilityMembership                           string
	priorStrictMountsFenced                        bool
	maxCachedNameCapacity                          uint64
	maxRepairBudget, visibilityClockSkew           time.Duration
}

func run() error {
	var o options
	showVersion := flag.Bool("version", false, "print exact release identity and exit")
	flag.StringVar(&o.listen, "listen", "", "TCP address to listen on")
	flag.StringVar(&o.volumeID, "volume-id", "", "exact volume identity served by this process")
	flag.StringVar(&o.root, "root", "", "absolute provisioned XFS project-directory root")
	flag.UintVar(&o.projectID, "project-id", 0, "expected nonzero XFS project ID")
	flag.StringVar(&o.tlsCert, "tls-cert", "", "server certificate PEM")
	flag.StringVar(&o.tlsKey, "tls-key", "", "server private key PEM")
	flag.StringVar(&o.clientCA, "client-ca", "", "client CA bundle PEM")
	flag.StringVar(&o.capabilityPublicKey, "capability-public-key", "", "Ed25519 capability public key PEM")
	flag.StringVar(&o.productAuthorizationPublicKey, "product-authorization-public-key", "", "hosted mode: Ed25519 product authorization public key PEM")
	flag.StringVar(&o.productIssuer, "product-issuer", "", "hosted mode: exact trusted product issuer")
	flag.StringVar(&o.productAudience, "product-audience", "portablefs-manager", "hosted mode: exact product authorization audience")
	flag.StringVar(&o.authorizationDomain, "authorization-domain", "", "hosted mode: immutable volume authorization domain")
	flag.StringVar(&o.owner, "owner", "", "hosted mode: immutable volume owner")
	flag.StringVar(&o.cellID, "cell-id", "", "hosted mode: exact storage cell identity")
	flag.StringVar(&o.authorityID, "authority-id", "", "hosted mode: exact authority routing identity")
	flag.Uint64Var(&o.authorityGeneration, "authority-generation", 0, "hosted mode: monotonic authority generation")
	flag.UintVar(&o.maxFrame, "max-frame-bytes", 16<<20, "hard protobuf frame allocation bound")
	flag.UintVar(&o.maxRead, "max-read-bytes", 1<<20, "maximum bytes in one read reply")
	flag.UintVar(&o.maxWrite, "max-write-bytes", 1<<20, "maximum bytes in one write request")
	flag.UintVar(&o.replaySlots, "max-replay-slots", 256, "maximum concurrent retry slots per session")
	flag.UintVar(&o.maxSessions, "max-sessions", defaultMaxSessions, "maximum live mount sessions for this volume worker")
	flag.UintVar(&o.maxLockRecords, "max-lock-records", 65536, "maximum held and waiting POSIX lock records")
	flag.UintVar(&o.maxItemsPerSession, "max-items-per-session", defaultMaxItemsPerSession, "maximum descriptor-backed item capabilities per session")
	flag.UintVar(&o.maxOpensPerSession, "max-opens-per-session", 4096, "maximum open file descriptions per session")
	flag.UintVar(&o.maxItems, "max-items", 65536, "maximum descriptor-backed item capabilities for the worker")
	flag.UintVar(&o.maxOpens, "max-opens", 32768, "maximum open file descriptions for the worker")
	flag.Uint64Var(&o.maxRetainedReplyBytes, "max-retained-reply-bytes", 512<<20, "total bytes this worker may hold in replay slots")
	flag.Uint64Var(&o.maxFrameBytesInFlight, "max-frame-bytes-in-flight", 512<<20, "total bytes this worker may have allocated for inbound frames")
	flag.StringVar(&o.writeStaging, "write-staging-dir", "", "absolute private 0700 directory for unnamed transactional-write staging")
	flag.Uint64Var(&o.maxWriteStagingBytesPerSession, "max-write-staging-bytes-per-session", 16<<30, "staging bytes reserved by one session")
	flag.Uint64Var(&o.maxWriteStagingBytes, "max-write-staging-bytes", 64<<30, "staging bytes reserved by this worker")
	flag.UintVar(&o.maxWriteTransactionsPerSession, "max-write-transactions-per-session", defaultWriteTransactionsPerSession(defaultMaxInFlight, defaultMaxWriteTransactions), "inert or committing write transactions owned by one session")
	flag.UintVar(&o.maxWriteTransactions, "max-write-transactions", defaultMaxWriteTransactions, "inert or committing write transactions owned by this worker")
	flag.DurationVar(&o.writeTransactionProgressTimeout, "write-transaction-progress-timeout", 2*time.Minute, "maximum idle interval between write transaction phases")
	flag.DurationVar(&o.writeTransactionAbsoluteTimeout, "write-transaction-absolute-timeout", 30*time.Minute, "absolute lifetime of a write transaction")
	flag.DurationVar(&o.terminalDeliveryTimeout, "terminal-delivery-timeout", 45*time.Second, "maximum drain from a terminal exact result through peer repair and source kernel publication receipt")
	flag.DurationVar(&o.capabilityLifetime, "capability-max-lifetime", 15*time.Minute, "longest capability validity window this authority will honour")
	flag.UintVar(&o.capabilityNonces, "capability-nonce-records", 65536, "single-use capability records retained until expiry")
	flag.DurationVar(&o.sessionLease, "session-lease", 2*time.Minute, "renewable session lease")
	flag.IntVar(&o.maxInFlight, "max-in-flight", defaultMaxInFlight, "requests concurrently executing per TLS connection")
	flag.IntVar(&o.maxConnections, "max-connections", defaultMaxConnections, "maximum accepted TLS connections for the worker; must be at least 4 times max-sessions")
	flag.DurationVar(&o.handshakeTimeout, "tls-handshake-timeout", 10*time.Second, "maximum TLS handshake duration")
	flag.DurationVar(&o.idleTimeout, "connection-idle-timeout", 5*time.Minute, "maximum interval without a complete request frame")
	flag.DurationVar(&o.writeTimeout, "connection-write-timeout", 30*time.Second, "maximum response frame write duration")
	flag.StringVar(&o.visibilityMembership, "visibility-membership-file", "", "absolute durable strict-mount membership file")
	flag.BoolVar(&o.priorStrictMountsFenced, "prior-strict-mounts-fenced", false, "control plane proved every recorded prior strict kernel mount unusable")
	flag.Uint64Var(&o.maxCachedNameCapacity, "max-cached-name-capacity", 1<<16, "largest kernel-cache bound a strict mount may declare; sizes the per-session resolved index")
	// The default must admit the mount's own default repair budget, or a stock
	// mount cannot attach to a stock authority at all. Both defaults are stated
	// against each other rather than chosen independently.
	flag.DurationVar(&o.maxRepairBudget, "max-repair-budget", 30*time.Second, "longest per-phase cache-repair deadline a strict mount may commit to before it is fenced; must be at least the mount's -repair-budget")
	flag.DurationVar(&o.visibilityClockSkew, "visibility-clock-skew", 5*time.Second, "clock disagreement tolerated when a mount timestamps its own kernel-mount absence")
	flag.Parse()
	writeTransactionLimitOverridden := false
	flag.Visit(func(value *flag.Flag) {
		if value.Name == "max-write-transactions-per-session" {
			writeTransactionLimitOverridden = true
		}
	})
	if !writeTransactionLimitOverridden {
		o.maxWriteTransactionsPerSession = defaultWriteTransactionsPerSession(o.maxInFlight, o.maxWriteTransactions)
	}
	if *showVersion {
		_, _ = fmt.Fprintln(os.Stdout, version)
		return nil
	}
	if os.Geteuid() == 0 {
		return errors.New("portablefs-authority refuses to run as root; provision XFS first, then run as the volume service owner")
	}
	if (o.listen == "" && !systemdSocketAvailable()) || o.volumeID == "" || o.root == "" || o.projectID == 0 ||
		o.tlsCert == "" || o.tlsKey == "" || o.clientCA == "" || o.capabilityPublicKey == "" || o.visibilityMembership == "" || o.writeStaging == "" {
		return errors.New("a listen address or one systemd socket, volume-id, root, nonzero project-id, TLS files, client CA, capability public key, visibility membership file, and write staging directory are required")
	}
	hosted := o.productAuthorizationPublicKey != "" || o.productIssuer != "" || o.authorizationDomain != "" ||
		o.owner != "" || o.cellID != "" || o.authorityID != "" || o.authorityGeneration != 0
	if hosted && (o.productAuthorizationPublicKey == "" || o.productIssuer == "" || o.productAudience == "" ||
		o.authorizationDomain == "" || o.owner == "" || o.cellID == "" || o.authorityID == "" || o.authorityGeneration == 0) {
		return errors.New("hosted authority requires product key, issuer, audience, authorization domain, owner, cell, authority identity, and nonzero generation together")
	}
	maxUint32 := uint(^uint32(0))
	if o.projectID > maxUint32 || o.maxFrame == 0 || o.maxFrame > maxUint32 ||
		o.maxRead == 0 || o.maxRead > maxUint32 || o.maxWrite == 0 || o.maxWrite > maxUint32 ||
		o.replaySlots == 0 || o.replaySlots > maxUint32 || o.sessionLease < time.Second ||
		o.maxSessions == 0 || o.maxSessions > maxUint32 || o.maxLockRecords == 0 || o.maxLockRecords > maxUint32 ||
		o.maxItemsPerSession == 0 || o.maxItemsPerSession > maxUint32 || o.maxOpensPerSession == 0 || o.maxOpensPerSession > maxUint32 ||
		o.maxItems == 0 || o.maxItems > maxUint32 || o.maxOpens == 0 || o.maxOpens > maxUint32 ||
		o.maxItemsPerSession > o.maxItems || o.maxOpensPerSession > o.maxOpens ||
		o.maxWriteStagingBytesPerSession < authorityrpc.RequiredWriteTransactionBytes ||
		o.maxWriteStagingBytes < o.maxWriteStagingBytesPerSession ||
		o.maxWriteTransactionsPerSession == 0 || o.maxWriteTransactionsPerSession > maxUint32 ||
		o.maxWriteTransactions == 0 || o.maxWriteTransactions > maxUint32 || o.maxWriteTransactionsPerSession > o.maxWriteTransactions ||
		o.writeTransactionProgressTimeout <= 0 || o.writeTransactionAbsoluteTimeout < o.writeTransactionProgressTimeout || o.terminalDeliveryTimeout < o.maxRepairBudget ||
		o.capabilityLifetime <= 0 || o.capabilityNonces == 0 || o.capabilityNonces > uint(^uint32(0)) ||
		o.maxInFlight < 2 || uint64(o.maxInFlight) > uint64(maxUint32) || o.maxConnections <= 0 || o.handshakeTimeout <= 0 || o.idleTimeout <= o.sessionLease || o.writeTimeout <= 0 {
		return errors.New("protocol allocation and replay bounds must be positive uint32 values, and max-in-flight must admit an ordinary request alongside a blocking lock wait")
	}
	if err := validateConnectionCapacity(o.maxSessions, o.maxConnections); err != nil {
		return err
	}
	// The reserve straddles a process boundary: the client checks the bounds it
	// is told against the same constant, so both sides must read it from the
	// protocol package rather than repeat a literal.
	reserve := uint64(authorityrpc.FramePayloadReserve)
	if o.maxFrame < uint(authorityrpc.MinimumFrameBytes) {
		return fmt.Errorf("max-frame-bytes must be at least %d so a fixed-shape reply always fits", authorityrpc.MinimumFrameBytes)
	}
	if uint64(o.maxRead)+reserve > uint64(o.maxFrame) || uint64(o.maxWrite)+reserve > uint64(o.maxFrame) {
		return fmt.Errorf("max-frame-bytes must leave at least %d bytes around each read/write payload", reserve)
	}
	// A directory listing is built to a byte budget derived from the frame, so
	// no configuration can produce a volume whose directories cannot be listed.
	// What must still be sized explicitly is how many reply bytes the worker may
	// retain and how many inbound frame bytes it may have allocated at once.
	if o.maxRetainedReplyBytes < uint64(o.maxFrame) {
		return errors.New("max-retained-reply-bytes must admit at least one maximal reply")
	}
	if o.maxFrameBytesInFlight < uint64(o.maxWrite)+reserve {
		return errors.New("max-frame-bytes-in-flight must admit at least one maximal request")
	}

	store, err := xfsstore.Open(o.root, xfsstore.Config{
		ExpectedProjectID: uint32(o.projectID),
		ExpectedOwnerUID:  uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid()),
	})
	if err != nil {
		return fmt.Errorf("open authoritative XFS volume: %w", err)
	}
	defer store.Close()
	writeStaging, err := authorityrpc.OpenWriteTransactionStaging(o.writeStaging)
	if err != nil {
		return err
	}
	defer writeStaging.Close()
	runtime, err := volumeserver.New(o.volumeID, volumeserver.Config{
		SessionLease: o.sessionLease, MaxReplaySlots: uint32(o.replaySlots),
		MaxSessions: uint32(o.maxSessions), MaxLockRecords: uint32(o.maxLockRecords),
	})
	if err != nil {
		return err
	}
	if o.maxCachedNameCapacity == 0 || o.maxRepairBudget <= 0 || o.visibilityClockSkew < 0 {
		return errors.New("max-cached-name-capacity and max-repair-budget must be positive and visibility-clock-skew must not be negative")
	}
	membership, priorDisposition, err := volumeserver.OpenFileVisibilityMembership(o.visibilityMembership, o.volumeID, o.priorStrictMountsFenced)
	if err != nil {
		return fmt.Errorf("open durable visibility membership: %w", err)
	}
	defer membership.Close()
	// -prior-strict-mounts-fenced is an unverified operator assertion and the
	// only input that can erase this authority's memory of an unsafe mount. It
	// is durably audited inside the membership record; saying it out loud here
	// as well means nobody has to read a file to learn that it happened.
	for _, cleared := range membership.ClearedByOperatorAssertion() {
		fmt.Fprintf(os.Stderr, "portablefs-authority: operator asserted prior strict mount %x fenced; cleared from durable membership for volume %s\n", cleared, o.volumeID)
	}
	if priorDisposition != volumeserver.PriorEpochStrictMountsFenced {
		return errors.New("prior strict mounts remain active; fence their kernel mounts before starting a new authority epoch")
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: priorDisposition, Membership: membership, Fencer: runtime,
		MaxCachedNameCapacity: o.maxCachedNameCapacity,
		MaxRepairBudget:       o.maxRepairBudget,
		MaxClockSkew:          o.visibilityClockSkew,
		OnFence: func(id volumeserver.SessionID, reason error) {
			// One mount left the barrier. This is deliberately not a process
			// failure: the volume keeps serving every other mount.
			fmt.Fprintf(os.Stderr, "portablefs-authority: fenced strict mount %x: %v\n", id, reason)
		},
		OnRefusedCommitment: func(id volumeserver.SessionID, reason error) {
			// The mount only learns an errno, so this is the one place an
			// operator can see which declared number exceeded which bound.
			fmt.Fprintf(os.Stderr, "portablefs-authority: refused strict attach %x: %v\n", id, reason)
		},
	})
	if err != nil {
		return err
	}
	// The authority is the source of truth for the machine-local routing
	// topology, so it reads the declaration out of its own volume root before it
	// serves anything. A volume with no loaded revision cannot tell an agreeing
	// mount from a disagreeing one, so a declaration that will not parse stops
	// the process here rather than admitting mounts against a topology this
	// volume does not have.
	routes, err := authorityrpc.NewRoutesController(store, visibility, runtime.Locks())
	if err != nil {
		return err
	}
	if err := routes.Load(); err != nil {
		return fmt.Errorf("load machine-local routing declaration: %w", err)
	}
	if revision, err := routes.Revision(); err == nil {
		fmt.Fprintf(os.Stderr, "portablefs-authority: volume %s routing revision %x\n", o.volumeID, revision)
	}
	publicKey, err := readEd25519PublicKey(o.capabilityPublicKey)
	if err != nil {
		return err
	}
	var productPublicKey ed25519.PublicKey
	var productAudience string
	if hosted {
		productPublicKey, err = readEd25519PublicKey(o.productAuthorizationPublicKey)
		if err != nil {
			return fmt.Errorf("read product authorization public key: %w", err)
		}
		productAudience = o.productAudience
	}
	authorizer := &volumecap.Authorizer{
		PublicKey: publicKey, ClockSkew: 5 * time.Second,
		MaxLifetime: o.capabilityLifetime, MaxRetainedNonces: int(o.capabilityNonces),
		ProductPublicKey: productPublicKey, ProductIssuer: o.productIssuer, ProductAudience: productAudience,
		AuthorizationDomain: o.authorizationDomain, Owner: o.owner, CellID: o.cellID,
		AuthorityID: o.authorityID, AuthorityGeneration: o.authorityGeneration,
	}
	tlsConfig, err := serverTLSConfig(o.tlsCert, o.tlsKey, o.clientCA)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	storageFailure := make(chan error, 1)
	coherenceFailure := make(chan error, 1)
	// The transport bound and the advertised bound are one value here, and
	// Serve refuses to start if the handler ever advertises anything else.
	maxFrame, maxInFlight := uint32(o.maxFrame), o.maxInFlight
	handler := &authorityrpc.VolumeHandler{
		Store: store, Runtime: runtime, Authorizer: authorizer,
		Visibility: visibility, Routes: routes,
		MaxFrame: maxFrame, MaxRead: uint32(o.maxRead), MaxWrite: uint32(o.maxWrite), MaxInFlight: uint32(maxInFlight),
		MaxItemsPerSession: uint32(o.maxItemsPerSession), MaxOpensPerSession: uint32(o.maxOpensPerSession),
		MaxItems: uint32(o.maxItems), MaxOpens: uint32(o.maxOpens),
		MaxRetainedReplyBytes: o.maxRetainedReplyBytes,
		WriteStaging:          writeStaging, MaxWriteTransactionBytes: authorityrpc.RequiredWriteTransactionBytes,
		MaxWriteStagingBytesPerSession: o.maxWriteStagingBytesPerSession, MaxWriteStagingBytes: o.maxWriteStagingBytes,
		MaxWriteTransactionsPerSession: uint32(o.maxWriteTransactionsPerSession), MaxWriteTransactions: uint32(o.maxWriteTransactions),
		WriteTransactionProgressTimeout: o.writeTransactionProgressTimeout, WriteTransactionAbsoluteTimeout: o.writeTransactionAbsoluteTimeout,
		TerminalDeliveryTimeout: o.terminalDeliveryTimeout,
		OnStorageFailure: func(err error) {
			select {
			case storageFailure <- err:
			default:
			}
			stop()
		},
		OnCoherenceFailure: func(err error) {
			select {
			case coherenceFailure <- err:
			default:
			}
			stop()
		},
	}
	server := &authorityrpc.Server{
		Handler: handler, MaxFrame: maxFrame, MaxInFlight: maxInFlight, MaxConnections: o.maxConnections,
		MaxFrameBytesInFlight: o.maxFrameBytesInFlight,
		HandshakeTimeout:      o.handshakeTimeout, IdleTimeout: o.idleTimeout, WriteTimeout: o.writeTimeout,
	}
	listener, err := authorityListener(o.listen)
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
				handler.SweepWriteTransactions(time.Now())
			}
		}
	}()
	serveErr := server.Serve(ctx, listener, tlsConfig)
	select {
	case failure := <-storageFailure:
		return fmt.Errorf("authoritative storage failed and this epoch was fenced: %w", failure)
	case failure := <-coherenceFailure:
		return fmt.Errorf("strict cache coherence failed and this epoch was fenced: %w", failure)
	default:
		return serveErr
	}
}

func systemdSocketAvailable() bool {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return false
	}
	fds, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	return err == nil && fds == 1
}

func authorityListener(address string) (net.Listener, error) {
	if !systemdSocketAvailable() {
		return net.Listen("tcp", address)
	}
	file := os.NewFile(uintptr(3), "systemd-authority-listener")
	if file == nil {
		return nil, errors.New("systemd listener fd 3 is unavailable")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("adopt systemd authority listener: %w", err)
	}
	if _, ok := listener.(*net.TCPListener); !ok {
		_ = listener.Close()
		return nil, errors.New("systemd authority listener is not TCP")
	}
	return listener, nil
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
	var identityMu sync.Mutex
	cachedPEM := append([]byte(nil), certPEM...)
	cachedIdentity := certificate
	loadIdentity := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		currentPEM, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("reload server TLS certificate: %w", err)
		}
		identityMu.Lock()
		defer identityMu.Unlock()
		if !bytes.Equal(currentPEM, cachedPEM) {
			current, err := tls.X509KeyPair(currentPEM, keyPEM)
			if err != nil {
				return nil, fmt.Errorf("reload server TLS identity: %w", err)
			}
			cachedPEM = append(cachedPEM[:0], currentPEM...)
			cachedIdentity = current
		}
		identity := cachedIdentity
		identity.Certificate = cloneTLSChain(cachedIdentity.Certificate)
		return &identity, nil
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: pool, GetCertificate: loadIdentity,
		NextProtos: []string{authorityrpc.ProtocolALPN},
	}, nil
}

func cloneTLSChain(chain [][]byte) [][]byte {
	copy := make([][]byte, len(chain))
	for index := range chain {
		copy[index] = append([]byte(nil), chain[index]...)
	}
	return copy
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
