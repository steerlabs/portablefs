package cli

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxClientIdentityBytes bounds each identity PEM file. A real manager-issued
// certificate or key is a few kilobytes; anything near this bound is not one.
const maxClientIdentityBytes = 256 << 10

// clientTLSIdentity is the manager-issued mutual-TLS identity a v3 mount
// presents to the authority. Both the parsed pair (the Linux dial installs it
// into the transport's TLS configuration) and the raw PEM bytes (the macOS
// ensure request carries them to portablefsd, which owns the dial) are kept,
// because the two platforms hand the identity to different processes.
type clientTLSIdentity struct {
	certPEM     []byte
	keyPEM      []byte
	certificate tls.Certificate
}

// loadClientTLSIdentity reads and proves one client certificate/key pair.
// The private key must be a regular file unreadable by group and other users:
// a world-readable mount identity is a misconfiguration to stop on, not a
// warning to scroll past.
func loadClientTLSIdentity(certPath, keyPath string) (*clientTLSIdentity, error) {
	certPEM, err := readBoundedRegularFile(certPath, false)
	if err != nil {
		return nil, fmt.Errorf("read --client-cert: %w", err)
	}
	keyPEM, err := readBoundedRegularFile(keyPath, true)
	if err != nil {
		return nil, fmt.Errorf("read --client-key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load mutual-TLS client identity: %w", err)
	}
	return &clientTLSIdentity{certPEM: certPEM, keyPEM: keyPEM, certificate: certificate}, nil
}

// readBoundedRegularFile opens path without following symlinks and returns
// its bytes. private additionally requires the 0?00-group/other permission
// shape a credential file must have.
func readBoundedRegularFile(path string, private bool) ([]byte, error) {
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
	if !info.Mode().IsRegular() {
		return nil, errors.New("must be a regular, non-symlink file")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("credential must be unreadable by group and other users (chmod 600)")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxClientIdentityBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxClientIdentityBytes {
		return nil, fmt.Errorf("exceeds %d bytes", maxClientIdentityBytes)
	}
	return data, nil
}
