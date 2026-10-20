//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		authority          = flag.String("authority", "", "authority host:port")
		volumeID           = flag.String("volume-id", "", "exact volume identity")
		mountpoint         = flag.String("mountpoint", "", "existing empty mount directory")
		accessTokenFile    = flag.String("access-token-file", "", "file containing a short-lived volume capability; re-read for reauthorization whenever its issuer rotates it in place")
		clientCert         = flag.String("tls-cert", "", "client TLS certificate PEM")
		clientKey          = flag.String("tls-key", "", "client TLS private key PEM")
		serverCA           = flag.String("tls-server-ca", "", "authority CA certificate PEM")
		serverName         = flag.String("tls-server-name", "", "authority certificate DNS name")
		maxFrame           = flag.Uint("max-frame-bytes", uint(mountv3.MaxFrame), "hard protobuf frame bound")
		replaySlots        = flag.Uint("replay-slots", uint(mountv3.ReplaySlots), "same-epoch in-flight mutation replay slots")
		maxInFlight        = flag.Int("max-in-flight", mountv3.MaxInFlight, fmt.Sprintf("maximum concurrent authority calls (at least %d: ordinary and blocking work plus the ordered-flush lane)", authorityrpc.MinimumLinuxInFlight))
		maxBackground      = flag.Int("max-background", 128, "maximum FUSE background requests")
		reclaimQueue       = flag.Int("reclaim-queue", mountv3.ReclaimQueue, "bounded forgotten-object cleanup queue")
		dialTimeout        = flag.Duration("dial-timeout", mountv3.DialTimeout, "authority dial and TLS timeout")
		cancelDrainTimeout = flag.Duration("cancel-drain-timeout", mountv3.CancelDrainTimeout, "time to obtain an exact result after interrupting an in-flight request")
		requestTimeout     = flag.Duration("request-timeout", mountv3.RequestTimeout, "non-blocking filesystem operation timeout")
		nameCacheCapacity  = flag.Int("name-cache-capacity", mountv3.NameCacheCapacity, "local bound on cached names, absences and attributes")
		withdrawalTimeout  = flag.Duration("withdrawal-timeout", mountv3.WithdrawalTimeout, "local deadline for withdrawing kernel cache state before the mount revokes itself")
		localBacking       = flag.String("local-backing", "", "per-machine directory holding the volume's machine-local route subtrees")
		noLocalDirs        = flag.Bool("no-local-dirs", false, "refuse to mount a volume that declares machine-local routes in "+fusev3.LocalDirsPath)
	)
	flag.Parse()
	if flag.NArg() != 0 || *authority == "" || *volumeID == "" || *mountpoint == "" || *accessTokenFile == "" || *clientCert == "" || *clientKey == "" || *serverCA == "" || *serverName == "" {
		return errors.New("authority, volume-id, mountpoint, access-token-file, tls-cert, tls-key, tls-server-ca, and tls-server-name are required")
	}
	if *maxFrame == 0 || *maxFrame > uint(^uint32(0)) || *replaySlots == 0 || *replaySlots > uint(^uint32(0)) || *maxInFlight <= 0 || *maxBackground <= 0 || *reclaimQueue <= 0 || *dialTimeout <= 0 || *cancelDrainTimeout <= 0 || *requestTimeout <= 0 || *nameCacheCapacity <= 0 || *withdrawalTimeout <= 0 {
		return errors.New("protocol, concurrency, queue, cache, and timeout bounds must be positive and representable")
	}
	if *maxInFlight < authorityrpc.MinimumLinuxInFlight {
		return fmt.Errorf("max-in-flight must be at least %d to carry the ordered-flush lane beside ordinary and blocking work", authorityrpc.MinimumLinuxInFlight)
	}
	if uint64(*replaySlots) < uint64(*maxInFlight) {
		return errors.New("replay-slots must be at least max-in-flight")
	}
	if !filepath.IsAbs(*mountpoint) || filepath.Clean(*mountpoint) != *mountpoint {
		return errors.New("mountpoint must be a clean absolute path")
	}
	absoluteMount := *mountpoint
	info, err := os.Lstat(absoluteMount)
	if err != nil {
		return fmt.Errorf("stat mountpoint: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("mountpoint must be a real directory, not a symlink")
	}
	directory, err := os.Open(absoluteMount)
	if err != nil {
		return fmt.Errorf("open mountpoint: %w", err)
	}
	entries, readErr := directory.Readdirnames(1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("inspect mountpoint: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close mountpoint: %w", closeErr)
	}
	if len(entries) != 0 {
		return errors.New("mountpoint must be empty")
	}
	tlsConfig, err := loadTLS(*clientCert, *clientKey, *serverCA, *serverName)
	if err != nil {
		return err
	}
	token, err := readPrivateFile(*accessTokenFile)
	if err != nil {
		return fmt.Errorf("read access token: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) == 0 {
		return errors.New("access token file is empty")
	}
	mountInstanceID, err := mountid.NewMountInstance()
	if err != nil {
		return fmt.Errorf("create unique mount identity: %w", err)
	}
	preKernelAbsence, err := mountv3.PreKernelMountAbsenceObserver(absoluteMount, mountInstanceID)
	if err != nil {
		return fmt.Errorf("bind pre-kernel mount-absence observer: %w", err)
	}
	requests := make(chan os.Signal, 1)
	signal.Notify(requests, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(requests)
	ctx := context.Background()
	attach := authorityrpc.ClientConfig{
		Purpose:         authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX,
		Address:         *authority, TLS: tlsConfig, VolumeID: *volumeID,
		AccessToken: token, ReplaySlots: uint32(*replaySlots),
		MaxFrame: uint32(*maxFrame), DialTimeout: *dialTimeout, CancelDrainTimeout: *cancelDrainTimeout, MaxInFlight: *maxInFlight,
		ObservePreKernelMountAbsence: preKernelAbsence,
	}
	// One attach, and at most one more if this mount had never seen the volume's
	// routing. The refusal that teaches it carries the declaration and does not
	// spend the single-use capability, so no second credential and no second
	// session is involved.
	client, routes, err := attachWithRoutes(ctx, attach, !*noLocalDirs)
	if err != nil {
		// A routing refusal names both revisions and the volume's declaration.
		// It is surfaced exactly as it arrived: the operator is told what the
		// volume routes and what this mount asked for, and retrying in a loop
		// against a volume that is being reconfigured is not an answer.
		return err
	}
	if !routes.Empty() && *localBacking == "" {
		cause := fmt.Errorf("this volume declares machine-local routes in %s (%s); -local-backing must name the per-machine directory that serves them",
			fusev3.LocalDirsPath, strings.Join(routes.Patterns(), " "))
		return releaseClientBeforeKernelMount(client, *cancelDrainTimeout, cause)
	}
	transport := mountv3.NewTransport(client)
	mount, err := fusev3.MountVolume(context.Background(), absoluteMount, transport, fusev3.Config{
		MountInstanceID: mountInstanceID, RequestTimeout: *requestTimeout,
		MaxBackground: *maxBackground, MaxInFlight: *maxInFlight, ReclaimQueue: *reclaimQueue,
		PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid()),
		NameCacheCapacity: *nameCacheCapacity, WithdrawalTimeout: *withdrawalTimeout,
		Routes: routes, LocalBacking: *localBacking,
	})
	if err != nil {
		return err
	}
	log.Printf("PortableFS v3 volume %s mounted at %s", *volumeID, absoluteMount)
	// The capability this mount attached with is short lived, and ordinary lease
	// renewal never extends a signed authorization deadline. Renewal re-reads the
	// same file, so a credential manager that rotates it in place keeps the mount
	// alive and one that does not still fails closed.
	done := make(chan struct{})
	go func() { mount.Wait(); close(done) }()
	renewal, err := startCredentialRenewal(mount, *accessTokenFile, token)
	var renewalFailed <-chan error
	if err != nil {
		failed := make(chan error, 1)
		failed <- err
		renewalFailed = failed
	} else {
		defer renewal.Close()
		renewalFailed = renewal.failed
	}
	return superviseMount(mount, done, requests, renewalFailed, func(err error) {
		log.Printf("mount %s: %v", absoluteMount, err)
	})
}

func releaseClientBeforeKernelMount(client *authorityrpc.Client, timeout time.Duration, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return errors.Join(cause, client.ReleaseBeforeMount(ctx))
}

// The supervisor owns serving until the exact connection is terminal. Only an
// explicit signal requests a normal unmount; a refusal leaves every serving
// and enforcement owner alive. Renewal failure is diagnostic here: the mount's
// authorization/session enforcement owner still withdraws expired authority.
func superviseMount(mount interface {
	UnmountKernel() error
	Close() error
}, done <-chan struct{}, requests <-chan os.Signal, renewalFailed <-chan error, report func(error)) error {
	var renewalErr error
	for {
		// Prefer a terminal connection over another queued request. Close owns
		// the identity/absence proof and must report its own cleanup result.
		select {
		case <-done:
			return errors.Join(renewalErr, mount.Close())
		default:
		}
		select {
		case <-done:
			return errors.Join(renewalErr, mount.Close())
		case <-requests:
			if err := mount.UnmountKernel(); err != nil {
				report(fmt.Errorf("normal unmount refused; mount remains supervised: %w", err))
			}
		case err := <-renewalFailed:
			renewalFailed = nil
			renewalErr = err
			report(fmt.Errorf("automatic reauthorization failed; authorization enforcement remains active: %w", err))
		}
	}
}

func loadTLS(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read client TLS certificate: %w", err)
	}
	keyPEM, err := readPrivateFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read client TLS private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client TLS identity: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read authority CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("authority CA file contains no usable certificate")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, Certificates: []tls.Certificate{certificate}}, nil
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
		return nil, errors.New("credential must be a regular file unreadable by group and other users")
	}
	return io.ReadAll(file)
}
