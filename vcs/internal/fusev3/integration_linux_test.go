//go:build linux

package fusev3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"golang.org/x/sys/unix"
)

type integrationAuthorizer struct{}

func (integrationAuthorizer) Authorize(context.Context, string, []byte) (volumeserver.Authorization, error) {
	return volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour)}, nil
}

func TestTwoKernelMountsShareAuthoritativeXFS(t *testing.T) {
	root := os.Getenv("PORTABLEFS_XFS_TEST_ROOT")
	projectRaw := os.Getenv("PORTABLEFS_XFS_TEST_PROJECT")
	if root == "" || projectRaw == "" || os.Getenv("PORTABLEFS_FUSE_TEST") != "1" {
		t.Skip("privileged XFS and FUSE gates are not configured")
	}
	project, err := strconv.ParseUint(projectRaw, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	store, err := xfsstore.Open(root, xfsstore.Config{
		ExpectedProjectID: uint32(project),
		ExpectedOwnerUID:  uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid()),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runtime, err := volumeserver.New("integration-volume", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 64, MaxSessions: 8, MaxLockRecords: 4096})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := integrationTLS(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	handler := &authorityrpc.VolumeHandler{
		Store: store, Runtime: runtime, Authorizer: integrationAuthorizer{}, MaxFrame: 4 << 20, MaxRead: 1 << 20, MaxWrite: 1 << 20, MaxInFlight: 128,
		MaxItemsPerSession: 4096, MaxOpensPerSession: 4096, MaxItems: 16384, MaxOpens: 16384,
	}
	go func() {
		serverDone <- (&authorityrpc.Server{
			Handler: handler, MaxFrame: 4 << 20, MaxInFlight: 128, MaxConnections: 16,
			HandshakeTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute, WriteTimeout: 30 * time.Second,
		}).Serve(serverCtx, listener, serverTLS)
	}()
	defer func() {
		stopServer()
		if err := <-serverDone; err != nil {
			t.Errorf("authority server: %v", err)
		}
	}()

	newClient := func() *authorityrpc.Client {
		client, err := authorityrpc.DialClient(context.Background(), authorityrpc.ClientConfig{
			Address: listener.Addr().String(), TLS: clientTLS.Clone(), VolumeID: "integration-volume",
			AccessToken: []byte("test-capability"), ReplaySlots: 64,
			MaxFrame: 4 << 20, DialTimeout: 5 * time.Second, CancelDrainTimeout: 5 * time.Second, MaxInFlight: 64,
		})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	mountRoot := t.TempDir()
	pathA, pathB := filepath.Join(mountRoot, "a"), filepath.Join(mountRoot, "b")
	if err := os.Mkdir(pathA, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pathB, 0o700); err != nil {
		t.Fatal(err)
	}
	mountA, err := MountVolume(context.Background(), pathA, newClient(), Config{FSName: "portablefs-test-a", RequestTimeout: 10 * time.Second, MaxBackground: 64, ReclaimQueue: 1024, PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mountA.Unmount() }()
	mountB, err := MountVolume(context.Background(), pathB, newClient(), Config{FSName: "portablefs-test-b", RequestTimeout: 10 * time.Second, MaxBackground: 64, ReclaimQueue: 1024, PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mountB.Unmount() }()

	fileA, fileB := filepath.Join(pathA, "shared"), filepath.Join(pathB, "shared")
	if err := os.WriteFile(fileA, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(fileB); err != nil || string(got) != "one" {
		t.Fatalf("cross-mount read = %q, %v", got, err)
	}

	opened, err := os.Open(fileA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fileB); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(opened); err != nil || string(got) != "one" {
		t.Fatalf("open-after-unlink read = %q, %v", got, err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	fileA, fileB = filepath.Join(pathA, "mapped"), filepath.Join(pathB, "mapped")
	mappedPayload := make([]byte, 4096)
	mappedPayload[0] = 0x5a
	if err := os.WriteFile(fileA, mappedPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	mappedFile, err := os.OpenFile(fileA, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := unix.Mmap(int(mappedFile.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err == nil {
		_ = unix.Munmap(mapped)
		_ = mappedFile.Close()
		t.Fatal("shared writable mmap unexpectedly succeeded on a coherent direct-I/O mount")
	}
	if !errors.Is(err, syscall.ENODEV) && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOSYS) {
		_ = mappedFile.Close()
		t.Fatalf("shared writable mmap = %v, want ENODEV, EINVAL, or ENOSYS", err)
	}
	mapped, err = unix.Mmap(int(mappedFile.Fd()), 0, 4096, unix.PROT_READ, unix.MAP_SHARED)
	if err == nil {
		_ = unix.Munmap(mapped)
		_ = mappedFile.Close()
		t.Fatal("shared read-only mmap unexpectedly succeeded on a coherent direct-I/O mount")
	}
	if !errors.Is(err, syscall.ENODEV) && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOSYS) {
		_ = mappedFile.Close()
		t.Fatalf("shared read-only mmap = %v, want ENODEV, EINVAL, or ENOSYS", err)
	}
	// MAP_PRIVATE is an ordinary process-local copy-on-write view. It is not a
	// shared write channel and POSIX does not promise that later external file
	// changes become visible through it, so allowing it cannot violate the
	// cross-mount coherence contract.
	mapped, err = unix.Mmap(int(mappedFile.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		_ = mappedFile.Close()
		t.Fatalf("private mmap = %v", err)
	}
	if mapped[0] != 0x5a {
		_ = unix.Munmap(mapped)
		_ = mappedFile.Close()
		t.Fatalf("private mmap initial byte = %#x, want 0x5a", mapped[0])
	}
	mapped[0] = 0x33
	if err := unix.Munmap(mapped); err != nil {
		_ = mappedFile.Close()
		t.Fatal(err)
	}
	underlying := []byte{0}
	if _, err := mappedFile.ReadAt(underlying, 0); err != nil {
		_ = mappedFile.Close()
		t.Fatal(err)
	}
	if underlying[0] != 0x5a {
		_ = mappedFile.Close()
		t.Fatalf("private mmap modified underlying file: got %#x, want 0x5a", underlying[0])
	}
	if err := mappedFile.Close(); err != nil {
		t.Fatal(err)
	}

	permissionFile := filepath.Join(pathA, "permissions")
	if err := os.WriteFile(permissionFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(permissionFile, 0); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if denied, err := os.Open(permissionFile); !errors.Is(err, syscall.EACCES) {
			if denied != nil {
				_ = denied.Close()
			}
			t.Fatalf("open chmod-000 file = %v, want EACCES", err)
		}
		if err := unix.Access(permissionFile, unix.R_OK); !errors.Is(err, syscall.EACCES) {
			t.Fatalf("access chmod-000 file = %v, want EACCES", err)
		}
	}

	if err := unix.Setxattr(fileA, "user.portablefs-test", []byte("value"), 0); !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("setxattr = %v, want EOPNOTSUPP", err)
	}

	lockA, err := os.OpenFile(fileA, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	lockB, err := os.OpenFile(fileB, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	lock := &unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(os.SEEK_SET), Start: 0, Len: 1}
	if err := unix.FcntlFlock(lockA.Fd(), unix.F_SETLK, lock); err != nil {
		t.Fatal(err)
	}
	if err := unix.FcntlFlock(lockB.Fd(), unix.F_SETLK, lock); !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("conflicting cross-mount lock = %v", err)
	}
	if err := lockA.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.FcntlFlock(lockB.Fd(), unix.F_SETLK, lock); err != nil {
		t.Fatalf("POSIX lock survived owner close/flush: %v", err)
	}
	lock.Type = unix.F_UNLCK
	if err := unix.FcntlFlock(lockB.Fd(), unix.F_SETLK, lock); err != nil {
		t.Fatal(err)
	}
	if err := lockB.Close(); err != nil {
		t.Fatal(err)
	}

	flockA, err := os.OpenFile(fileA, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	flockB, err := os.OpenFile(fileB, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(flockA.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(flockB.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("conflicting cross-mount flock = %v", err)
	}
	if err := flockA.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		err = unix.Flock(int(flockB.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("flock survived final release: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := unix.Flock(int(flockB.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := flockB.Close(); err != nil {
		t.Fatal(err)
	}

	directory := filepath.Join(pathA, "many")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 600 {
		if err := os.WriteFile(filepath.Join(directory, strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(pathB, "many"))
	if err != nil || len(entries) != 600 {
		t.Fatalf("paged readdir count = %d, %v", len(entries), err)
	}

	if os.Getenv("PORTABLEFS_WORKLOAD_TEST") == "1" {
		repository := filepath.Join(pathA, "repo")
		runWorkload(t, "git", "init", repository)
		runWorkload(t, "git", "-C", repository, "config", "user.email", "portablefs@example.invalid")
		runWorkload(t, "git", "-C", repository, "config", "user.name", "PortableFS Test")
		if err := os.WriteFile(filepath.Join(repository, "source.txt"), []byte("content\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runWorkload(t, "git", "-C", repository, "add", "source.txt")
		runWorkload(t, "git", "-C", repository, "commit", "-m", "exercise PortableFS")
		runWorkload(t, "git", "-C", filepath.Join(pathB, "repo"), "fsck", "--full")

		databaseA, databaseB := filepath.Join(pathA, "sqlite.db"), filepath.Join(pathB, "sqlite.db")
		runWorkload(t, "sqlite3", databaseA, "PRAGMA journal_mode=DELETE; CREATE TABLE items(value TEXT); INSERT INTO items VALUES ('portable'); PRAGMA integrity_check;")
		command := exec.Command("sqlite3", databaseB, "SELECT value FROM items;")
		output, err := command.CombinedOutput()
		if err != nil || string(output) != "portable\n" {
			t.Fatalf("sqlite cross-mount query = %q, %v", output, err)
		}
	}
}

func runWorkload(t *testing.T, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, output)
	}
}

func integrationTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PortableFS integration CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, name string, usages []x509.ExtKeyUsage, dns []string) tls.Certificate {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: dns, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		certificate, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	serverCertificate := issue(2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	clientCertificate := issue(3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{serverCertificate}}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{clientCertificate}, ServerName: "localhost"}
}
