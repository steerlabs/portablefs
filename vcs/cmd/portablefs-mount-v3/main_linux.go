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
		maxInFlight        = flag.Int("max-in-flight", mountv3.MaxInFlight, "maximum concurrent authority calls")
		maxBackground      = flag.Int("max-background", 128, "maximum FUSE background requests")
		reclaimQueue       = flag.Int("reclaim-queue", mountv3.ReclaimQueue, "bounded forgotten-object cleanup queue")
		dialTimeout        = flag.Duration("dial-timeout", mountv3.DialTimeout, "authority dial and TLS timeout")
		cancelDrainTimeout = flag.Duration("cancel-drain-timeout", mountv3.CancelDrainTimeout, "time to obtain an exact result after interrupting an in-flight request")
		requestTimeout     = flag.Duration("request-timeout", mountv3.RequestTimeout, "non-blocking filesystem operation timeout")
		coherence          = flag.String("coherence", "strict", "kernel cache contract: strict (the only protocol-5 coherence mode)")
		cachedNames        = flag.Int("cached-name-capacity", mountv3.CachedNameCapacity, "directory bindings a strict mount may leave resident in its kernel")
		repairBudget       = flag.Duration("repair-budget", mountv3.RepairBudget, "per-phase deadline a strict mount commits to before revoking itself")
		localBacking       = flag.String("local-backing", "", "per-machine directory holding the volume's machine-local route subtrees")
		noLocalDirs        = flag.Bool("no-local-dirs", false, "refuse to mount a volume that declares machine-local routes in "+fusev3.LocalDirsPath)
	)
	var localDirs stringList
	flag.Var(&localDirs, "local-dir", "refused: machine-local routes are declared volume-wide in "+fusev3.LocalDirsPath)
	flag.Parse()
	if flag.NArg() != 0 || *authority == "" || *volumeID == "" || *mountpoint == "" || *accessTokenFile == "" || *clientCert == "" || *clientKey == "" || *serverCA == "" || *serverName == "" {
		return errors.New("authority, volume-id, mountpoint, access-token-file, tls-cert, tls-key, tls-server-ca, and tls-server-name are required")
	}
	if *maxFrame == 0 || *maxFrame > uint(^uint32(0)) || *replaySlots == 0 || *replaySlots > uint(^uint32(0)) || *maxInFlight <= 0 || *maxBackground <= 0 || *reclaimQueue <= 0 || *dialTimeout <= 0 || *cancelDrainTimeout <= 0 || *requestTimeout <= 0 {
		return errors.New("protocol, concurrency, queue, and timeout bounds must be positive and representable")
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
	profile, protocolProfile, err := mountv3.Profile(*coherence)
	if err != nil {
		return err
	}
	if *cachedNames <= 0 || *repairBudget <= 0 {
		return errors.New("strict coherence requires a positive cached-name capacity and repair budget; both are declared to the authority")
	}
	mountInstanceID, err := mountid.NewMountInstance()
	if err != nil {
		return fmt.Errorf("create unique mount identity: %w", err)
	}
	preKernelAbsence, err := mountv3.PreKernelMountAbsenceObserver(absoluteMount, mountInstanceID)
	if err != nil {
		return fmt.Errorf("bind pre-kernel mount-absence observer: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	attach := authorityrpc.ClientConfig{
		Address: *authority, TLS: tlsConfig, VolumeID: *volumeID,
		AccessToken: token, ReplaySlots: uint32(*replaySlots),
		MaxFrame: uint32(*maxFrame), DialTimeout: *dialTimeout, CancelDrainTimeout: *cancelDrainTimeout, MaxInFlight: *maxInFlight,
		// The two numbers a strict mount declares are the two the authority
		// needs to size the barrier: how much cached state this frontend can be
		// holding, and how long it may take to withdraw it.
		CoherenceProfile: protocolProfile, CachedNameCapacity: uint64(*cachedNames), RepairBudget: *repairBudget,
		ObservePreKernelMountAbsence: preKernelAbsence,
	}
	// How this frontend's kernel makes a cached binding unservable. It is
	// declared rather than inferred because the authority cannot observe a
	// remote kernel. The strict Linux answer is load-bearing: its private
	// reverse notification expires one exact binding under dcache locks without
	// taking the parent inode's i_rwsem. A stock parent-lock implementation is
	// refused rather than translated into synthetic application EINTR.
	attach.NamespaceRepair = authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION
	if len(localDirs) != 0 {
		return fmt.Errorf("machine-local routes are declared volume-wide in %s; -local-dir would add a route only this machine knows about, which desynchronizes the routing topology the authority pins every mount to", fusev3.LocalDirsPath)
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
		Coherence: profile, CachedNameCapacity: *cachedNames, RepairBudget: *repairBudget,
		Routes: routes, LocalBacking: *localBacking,
	})
	if err != nil {
		return err
	}
	log.Printf("PortableFS v3 volume %s mounted at %s (%s coherence)", *volumeID, absoluteMount, profile)
	// The capability this mount attached with is short lived, and ordinary lease
	// renewal never extends a signed authorization deadline. Renewal re-reads the
	// same file, so a credential manager that rotates it in place keeps the mount
	// alive and one that does not still fails closed.
	done := make(chan struct{})
	go func() { mount.Wait(); close(done) }()
	renewal, err := startCredentialRenewal(client, *accessTokenFile, token)
	if err != nil {
		return errors.Join(err, shutdown(mount, done, absoluteMount))
	}
	defer renewal.Close()
	select {
	case <-done:
		return mount.Close()
	case err := <-renewal.failed:
		// The mount still holds a valid authorization for the safety margin the
		// renewer reserved. Withdrawing it now is the difference between an
		// orderly unmount and every open file failing when the deadline passes.
		log.Printf("automatic reauthorization failed closed: %v; unmounting %s", err, absoluteMount)
		return errors.Join(err, shutdown(mount, done, absoluteMount))
	case <-ctx.Done():
		return shutdown(mount, done, absoluteMount)
	}
}

func releaseClientBeforeKernelMount(client *authorityrpc.Client, timeout time.Duration, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return errors.Join(cause, client.ReleaseBeforeMount(ctx))
}

// shutdown removes the kernel mount before this process exits.
//
// Exiting while the mount is still installed is strictly worse than waiting:
// /dev/fuse would close, every process under the mountpoint would see ENOTCONN
// with no way to recover, the stale mount would still be listed, and the
// authority session would be dropped without a Detach. EBUSY simply means some
// process still holds a file under the mountpoint, so the only correct answer
// is to keep serving and try again.
func shutdown(mount *fusev3.Mount, done <-chan struct{}, mountpoint string) error {
	const (
		firstRetry = 250 * time.Millisecond
		maxRetry   = 30 * time.Second
	)
	for delay := firstRetry; ; delay = min(2*delay, maxRetry) {
		err := mount.Unmount()
		if err == nil {
			<-done
			return nil
		}
		select {
		case <-done:
			// The kernel mount disappeared underneath us (an external
			// fusermount -u, for example). Release the authority session.
			return mount.Close()
		default:
		}
		log.Printf("unmount %s: %v; the mount is still in use and remains served, retrying in %s", mountpoint, err, delay)
		select {
		case <-done:
			return mount.Close()
		case <-time.After(delay):
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
