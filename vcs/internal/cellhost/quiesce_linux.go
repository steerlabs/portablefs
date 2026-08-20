//go:build linux

package cellhost

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"golang.org/x/sys/unix"
)

// WriteQuiesceRequest asks the volume's authority to close strict-attach
// admission and prove its strict-mount membership empty.
//
// The request is a fresh nonce, and a fresh request supersedes any older one:
// the point of the nonce is that a proof written before this request cannot
// contain it, so an archive attempt can never be satisfied by a stale proof
// from an earlier attempt.
//
// The file is root-owned and group-readable by the volume's service group,
// because that is the only way the authority can read it: it sees the
// ConfigRoot read-only at /run/portablefs-volume and runs as the service user.
// The service GID is a parameter rather than something this package looks up -
// it comes from the signed assignment, the same value provisioning used, and
// the helper must never learn an identity from the filesystem it is about to
// hand a request to.
func (host *Host) WriteQuiesceRequest(volumeID string, serviceGID uint32) (string, error) {
	if !cellplan.ValidID(volumeID) || serviceGID < 1000 {
		return "", ErrInvalid
	}
	var nonce [quiesceNonceBytes]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("cellhost: generate quiesce nonce: %w", err)
	}
	encoded := hex.EncodeToString(nonce[:])
	payload, err := json.Marshal(quiesceRequest{Nonce: encoded, RequestedUnix: host.cfg.Now().UTC().Unix()})
	if err != nil {
		return "", err
	}
	path := filepath.Join(host.cfg.ConfigRoot, volumeID, quiesceRequestName)
	if err := writeAtomic(path, payload, 0, int(serviceGID), 0o440); err != nil {
		return "", err
	}
	return encoded, nil
}

// ClearQuiesceRequest withdraws the request. An archive that is abandoned
// during quiesce returns the volume to serving, and a stale request must not
// keep an authority's admission closed.
func (host *Host) ClearQuiesceRequest(volumeID string) error {
	if !cellplan.ValidID(volumeID) {
		return ErrInvalid
	}
	if err := removeTreeBeneath(filepath.Join(host.cfg.ConfigRoot, volumeID), quiesceRequestName); err != nil {
		return err
	}
	return removeTreeBeneath(filepath.Join(host.cfg.StateRoot, volumeID), quiesceProofName)
}

// ReadQuiesceProof reads the authority's durable quiesce proof.
//
// It returns ErrQuiesceProofAbsent when no proof has been written yet, which
// is the ordinary state while the volume is still draining mounts, and an
// error for anything that exists but is not a well-formed proof for this
// volume. The caller must still apply QuiesceProof.Proves against the nonce it
// wrote: this function proves the file's shape, not its freshness.
func (host *Host) ReadQuiesceProof(volumeID string) (QuiesceProof, error) {
	if !cellplan.ValidID(volumeID) {
		return QuiesceProof{}, ErrInvalid
	}
	path := filepath.Join(host.cfg.StateRoot, volumeID, quiesceProofName)
	if !safeRoot(path) {
		return QuiesceProof{}, errors.New("cellhost: derived quiesce proof path failed validation")
	}
	// O_NOFOLLOW: the proof lives in a directory the service user owns, so the
	// name could be a symlink to a file it does not own.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return QuiesceProof{}, fmt.Errorf("%w: %s", ErrQuiesceProofAbsent, volumeID)
		}
		return QuiesceProof{}, fmt.Errorf("cellhost: open quiesce proof: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return QuiesceProof{}, syscall.EBADF
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > quiesceProofMaxBytes {
		return QuiesceProof{}, errors.New("cellhost: quiesce proof must be a bounded regular file")
	}
	// A record anyone but its owner can rewrite is not evidence of anything.
	if info.Mode().Perm()&0o022 != 0 {
		return QuiesceProof{}, errors.New("cellhost: quiesce proof is writable by another identity")
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var proof QuiesceProof
	if err := decoder.Decode(&proof); err != nil {
		return QuiesceProof{}, fmt.Errorf("cellhost: decode quiesce proof: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return QuiesceProof{}, errors.New("cellhost: quiesce proof has trailing data")
	}
	if proof.VolumeID != volumeID || proof.AuthorityEpoch == 0 || proof.WrittenUnix <= 0 ||
		!validQuiesceNonce(proof.Nonce) || !validWireSessionEpoch(proof.WireSessionEpochHex) {
		return QuiesceProof{}, errors.New("cellhost: quiesce proof is incomplete or belongs to another volume")
	}
	return proof, nil
}
