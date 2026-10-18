//go:build linux

package cellhost

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/mountmembership"
	"golang.org/x/sys/unix"
)

// StrictMembershipEmpty reports whether the volume's durable strict-mount
// membership record holds no active session.
//
// This is not the primary quiesce gate. Emptiness is asserted by the authority
// itself, which owns the membership lock and can close strict-attach admission
// before it looks: the helper writes a nonce request (WriteQuiesceRequest) and
// the authority answers with a durable proof (ReadQuiesceProof). A read of
// this file by the helper alone can only ever be a snapshot of a set the
// running authority is free to change a microsecond later.
//
// Its role is defense in depth, after the fact: once the authority has been
// stopped and proved absent, nothing can mutate the record, and the helper
// re-reads it here. The authority's proof and this read must agree - a proof
// of emptiness over a record that still lists sessions means one of the two is
// wrong, and the archive fails closed rather than guessing which.
//
// A missing record means no strict mount was ever admitted, so it is empty. A
// record that does not parse, is not private, or belongs to another volume is
// an error and never an emptiness claim: this answer gates destroying data.
func (host *Host) StrictMembershipEmpty(volumeID string) (bool, error) {
	if !cellplan.ValidID(volumeID) {
		return false, ErrInvalid
	}
	path := filepath.Join(host.cfg.StateRoot, volumeID, mountmembership.Filename)
	if !safeRoot(path) {
		return false, errors.New("cellhost: derived membership path failed validation")
	}
	// Pin each service-controlled component. O_NOFOLLOW on the final file
	// alone would still follow a substituted volume directory; O_NONBLOCK
	// ensures a planted FIFO cannot block before the regular-file check.
	rootFD, err := unix.Open(host.cfg.StateRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, fmt.Errorf("cellhost: open membership state root: %w", err)
	}
	defer unix.Close(rootFD)
	volumeFD, err := unix.Openat(rootFD, volumeID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return true, nil
		}
		return false, fmt.Errorf("cellhost: open membership volume directory: %w", err)
	}
	defer unix.Close(volumeFD)
	fd, err := unix.Openat(volumeFD, mountmembership.Filename, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return true, nil
		}
		return false, fmt.Errorf("cellhost: open strict-mount membership: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return false, syscall.EBADF
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return false, errors.New("cellhost: strict-mount membership must be a private regular file")
	}
	if info.Size() > mountmembership.MaxBytes {
		return false, errors.New("cellhost: strict-mount membership is implausibly large")
	}
	data, err := io.ReadAll(io.LimitReader(file, mountmembership.MaxBytes+1))
	if err != nil {
		return false, fmt.Errorf("cellhost: read mount membership: %w", err)
	}
	records, err := mountmembership.Decode(data, volumeID)
	if err != nil {
		return false, fmt.Errorf("cellhost: decode mount membership: %w", err)
	}
	return len(records) == 0, nil
}
