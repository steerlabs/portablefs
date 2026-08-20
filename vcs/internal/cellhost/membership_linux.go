//go:build linux

package cellhost

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"golang.org/x/sys/unix"
)

// The durable strict-mount membership record is written and owned by the
// authority; these constants mirror its on-disk format exactly as implemented
// in vcs/internal/volumeserver/visibility_membership.go (header at :15, the
// writer at persistLocked :211-262, the reader at load :170-209) with the
// session identifier width from volumeserver/session.go:31.
//
// The helper deliberately re-implements the read side instead of importing
// volumeserver: volumeserver is the authority's package, the authority is the
// only writer of this file, and the helper must not gain a build-time
// dependency on the serving process to answer a control-plane question. The
// duplication is eight lines of parsing and it is pinned by a test that builds
// the bytes in the writer's format.
const (
	visibilityMembershipName    = "visibility.membership"
	visibilityMembershipHeader  = "PFS-VISIBILITY-1"
	visibilityMembershipIDBytes = 16
	// A membership line is 33 bytes, so this bound admits roughly 32k
	// concurrent strict mounts - orders of magnitude above any real volume -
	// and refuses a file that has stopped being a membership record.
	visibilityMembershipMaxBytes = 1 << 20
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
	path := filepath.Join(host.cfg.StateRoot, volumeID, visibilityMembershipName)
	if !safeRoot(path) {
		return false, errors.New("cellhost: derived membership path failed validation")
	}
	// O_NOFOLLOW, like readPrivate: the helper runs as root, so a symlink
	// planted in the volume's state directory by the service user would
	// otherwise redirect this read to a file the service user does not own.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
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
	if info.Size() > visibilityMembershipMaxBytes {
		return false, errors.New("cellhost: strict-mount membership is implausibly large")
	}
	active, err := parseStrictMembership(file, volumeID)
	if err != nil {
		return false, err
	}
	return active == 0, nil
}

// parseStrictMembership mirrors FileVisibilityMembership.load: header line,
// then the hex encoding of the volume ID's own bytes (the identity binding -
// the file names the volume it belongs to, so a record moved or copied between
// volumes is rejected rather than believed), then one hex session ID per
// active line. Every deviation is an error; nothing is skipped.
func parseStrictMembership(reader io.Reader, volumeID string) (int, error) {
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() || scanner.Text() != visibilityMembershipHeader {
		return 0, errors.New("cellhost: invalid strict-mount membership header")
	}
	if !scanner.Scan() || scanner.Text() != hex.EncodeToString([]byte(volumeID)) {
		return 0, errors.New("cellhost: strict-mount membership belongs to a different volume")
	}
	seen := make(map[[visibilityMembershipIDBytes]byte]struct{})
	for scanner.Scan() {
		raw, err := hex.DecodeString(scanner.Text())
		if err != nil || len(raw) != visibilityMembershipIDBytes {
			return 0, errors.New("cellhost: invalid strict-mount membership record")
		}
		var id [visibilityMembershipIDBytes]byte
		copy(id[:], raw)
		if id == ([visibilityMembershipIDBytes]byte{}) {
			return 0, errors.New("cellhost: zero strict-mount membership record")
		}
		if _, duplicate := seen[id]; duplicate {
			return 0, errors.New("cellhost: duplicate strict-mount membership record")
		}
		seen[id] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("cellhost: read strict-mount membership: %w", err)
	}
	return len(seen), nil
}
