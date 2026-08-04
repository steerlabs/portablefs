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

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
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
		accessTokenFile    = flag.String("access-token-file", "", "file containing a short-lived volume capability")
		clientCert         = flag.String("tls-cert", "", "client TLS certificate PEM")
		clientKey          = flag.String("tls-key", "", "client TLS private key PEM")
		serverCA           = flag.String("tls-server-ca", "", "authority CA certificate PEM")
		serverName         = flag.String("tls-server-name", "", "authority certificate DNS name")
		maxFrame           = flag.Uint("max-frame-bytes", 4<<20, "hard protobuf frame bound")
		replaySlots        = flag.Uint("replay-slots", 128, "same-epoch in-flight mutation replay slots")
		maxInFlight        = flag.Int("max-in-flight", 128, "maximum concurrent authority calls")
		maxBackground      = flag.Int("max-background", 128, "maximum FUSE background requests")
		reclaimQueue       = flag.Int("reclaim-queue", 4096, "bounded forgotten-object cleanup queue")
		dialTimeout        = flag.Duration("dial-timeout", 10*time.Second, "authority dial and TLS timeout")
		cancelDrainTimeout = flag.Duration("cancel-drain-timeout", 10*time.Second, "time to obtain an exact result after interrupting an in-flight request")
		requestTimeout     = flag.Duration("request-timeout", 45*time.Second, "non-blocking filesystem operation timeout")
	)
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	client, err := authorityrpc.DialClient(ctx, authorityrpc.ClientConfig{
		Address: *authority, TLS: tlsConfig, VolumeID: *volumeID,
		AccessToken: token, ReplaySlots: uint32(*replaySlots),
		MaxFrame: uint32(*maxFrame), DialTimeout: *dialTimeout, CancelDrainTimeout: *cancelDrainTimeout, MaxInFlight: *maxInFlight,
	})
	if err != nil {
		return fmt.Errorf("attach authority: %w", err)
	}
	mount, err := fusev3.MountVolume(context.Background(), absoluteMount, client, fusev3.Config{
		FSName: "portablefs:" + *volumeID, RequestTimeout: *requestTimeout,
		MaxBackground: *maxBackground, MaxInFlight: *maxInFlight, ReclaimQueue: *reclaimQueue,
		PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid()),
	})
	if err != nil {
		return err
	}
	log.Printf("PortableFS v3 volume %s mounted at %s", *volumeID, absoluteMount)
	done := make(chan struct{})
	go func() { mount.Wait(); close(done) }()
	select {
	case <-done:
		return mount.Close()
	case <-ctx.Done():
		return shutdown(mount, done, absoluteMount)
	}
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
