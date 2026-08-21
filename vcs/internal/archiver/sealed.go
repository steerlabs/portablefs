package archiver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
)

// SealedVersion is the only archive-sealed.json version this build writes or
// accepts.
const SealedVersion uint32 = 1

// MaxSealedBytes bounds the result record. It is far above what an archive of
// the format's 1024-pack ceiling produces and exists so a corrupt or hostile
// file cannot be read unboundedly.
const MaxSealedBytes = 1 << 20

// ObjectRef is one uploaded object's identity, in the exact JSON shape the
// helper forwards and the Manager verifies (controlplane.ObjectRef). Keys are
// recorded because the helper echoes the seal onward verbatim; they are always
// keys this process derived locally from {volumeID, epoch, attempt} and the
// root-pinned prefix, never keys taken from the network.
type ObjectRef struct {
	Key       string `json:"key"`
	SizeBytes uint64 `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	CRC64NVME string `json:"crc64nvme,omitempty"`
}

// Sealed is the pinned archive-sealed.json record (restore-mode.md, "Pinned
// result records"): the ArchiveSealed the helper reads durably before it
// observes, written only after the complete read-back verification.
//
// The field names of the shared subset are exactly
// controlplane.ArchiveSealedObservation's, so the helper's observation is a
// re-marshal rather than a translation; the four additional fields (version,
// volume_id, cell_id, sealed_epoch) bind the record to one attempt of one
// volume so a stale file from an earlier attempt can never be mistaken for this
// one. A compatibility test pins the shared subset against the control-plane
// type.
type Sealed struct {
	Version              uint32      `json:"version"`
	VolumeID             string      `json:"volume_id"`
	CellID               string      `json:"cell_id"`
	SealedEpoch          uint64      `json:"sealed_epoch"`
	Attempt              string      `json:"attempt"`
	Manifest             ObjectRef   `json:"manifest"`
	Packs                []ObjectRef `json:"packs"`
	RootDigest           string      `json:"root_digest_sha256"`
	LogicalBytes         uint64      `json:"logical_bytes"`
	LogicalInodes        uint64      `json:"logical_inodes"`
	SealedAllocatedBytes uint64      `json:"sealed_allocated_bytes"`
	SealedInodes         uint64      `json:"sealed_inodes"`
	FormatVersion        uint32      `json:"format_version"`
	ChunkSizeBytes       uint32      `json:"chunk_size_bytes"`
	KeyVersion           string      `json:"key_version"`
	WrittenUnix          int64       `json:"written_unix"`
}

// Validate proves the record is self-consistent and complete. It runs on both
// sides: before writing, so an incomplete seal is never durable, and after
// reading, so a truncated or foreign file is never mistaken for a seal.
func (s *Sealed) Validate() error {
	switch {
	case s.Version != SealedVersion:
		return fmt.Errorf("%w: sealed record version %d is not %d", ErrInvalid, s.Version, SealedVersion)
	case s.VolumeID == "" || s.Attempt == "" || s.CellID == "":
		return fmt.Errorf("%w: sealed record is missing an identity", ErrInvalid)
	case s.SealedEpoch == 0:
		return fmt.Errorf("%w: sealed record has no epoch", ErrInvalid)
	case len(s.Packs) == 0:
		return fmt.Errorf("%w: sealed record names no pack objects", ErrInvalid)
	case !validSHA256Hex(s.RootDigest):
		return fmt.Errorf("%w: sealed record root digest is not a SHA-256", ErrInvalid)
	case s.FormatVersion == 0 || s.ChunkSizeBytes == 0 || s.KeyVersion == "":
		return fmt.Errorf("%w: sealed record is missing format identity", ErrInvalid)
	case s.SealedInodes == 0 || s.SealedAllocatedBytes == 0:
		return fmt.Errorf("%w: sealed record has empty allocation totals", ErrInvalid)
	case s.WrittenUnix <= 0:
		return fmt.Errorf("%w: sealed record has no write time", ErrInvalid)
	}
	if err := validateObjectRef(s.Manifest); err != nil {
		return err
	}
	for _, pack := range s.Packs {
		if err := validateObjectRef(pack); err != nil {
			return err
		}
	}
	return nil
}

// Describes reports whether the record is this exact attempt's seal. The helper
// may restart a crashed unit; a record that describes a different volume,
// epoch, or attempt is a stale file, and the run fails rather than reporting
// someone else's seal as its own.
func (s *Sealed) Describes(config LaunchConfig) error {
	if s.VolumeID != config.VolumeID || s.Attempt != config.Attempt ||
		s.SealedEpoch != config.AuthorityEpoch || s.CellID != config.CellID {
		return fmt.Errorf("%w: existing sealed record describes volume %s epoch %d attempt %s, not volume %s epoch %d attempt %s",
			ErrInvalid, s.VolumeID, s.SealedEpoch, s.Attempt, config.VolumeID, config.AuthorityEpoch, config.Attempt)
	}
	if s.ChunkSizeBytes != config.ChunkSizeBytes || s.KeyVersion != config.KeyVersion {
		return fmt.Errorf("%w: existing sealed record was built with different archive parameters", ErrInvalid)
	}
	return nil
}

func validateObjectRef(ref ObjectRef) error {
	if ref.Key == "" || ref.SizeBytes == 0 || !validSHA256Hex(ref.SHA256) {
		return fmt.Errorf("%w: sealed record object reference is incomplete", ErrInvalid)
	}
	if ref.CRC64NVME != "" && !validLowerHex(ref.CRC64NVME, 16) {
		return fmt.Errorf("%w: sealed record CRC64NVME is not 16 lowercase hex characters", ErrInvalid)
	}
	return nil
}

func validSHA256Hex(value string) bool { return validLowerHex(value, 64) }

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ReadSealed loads and validates an existing result record. A missing file is
// reported as os.ErrNotExist so the caller can distinguish "no seal yet" from
// "a seal that does not parse", which are opposite outcomes: the first means
// archive, the second means fail.
func ReadSealed(path string) (Sealed, error) {
	payload, err := readSmallFile(path, MaxSealedBytes)
	if err != nil {
		return Sealed{}, err
	}
	var sealed Sealed
	if err := decodeStrict(payload, &sealed); err != nil {
		return Sealed{}, fmt.Errorf("archiver: sealed record: %w", err)
	}
	if err := sealed.Validate(); err != nil {
		return Sealed{}, err
	}
	return sealed, nil
}

// WriteSealed writes the result record atomically and durably: a private
// temporary file in the same directory, fsynced, renamed over the final name,
// and the directory fsynced after the rename. The helper reads this file to
// decide that a volume is sealed, so a torn or unsynced record would be a
// correctness failure, not a cosmetic one.
func WriteSealed(path string, sealed Sealed) error {
	if err := sealed.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(sealed)
	if err != nil {
		return fmt.Errorf("archiver: encode sealed record: %w", err)
	}
	if len(payload) > MaxSealedBytes {
		return fmt.Errorf("%w: sealed record exceeds %d bytes", ErrInvalid, MaxSealedBytes)
	}
	payload = append(payload, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".archive-sealed-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := writeAndSync(temporary, payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return fsyncDirectory(directory)
}

func writeAndSync(file *os.File, payload []byte) error {
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	return file.Sync()
}

// packObjectName and manifestObjectName delegate to the pinned definitions
// beside the key grammar, so this writer, the hydrator's reader, and the
// Manager's verifier derive object names from exactly one place.
func packObjectName(index int) string {
	return archivestore.PackObjectName(index)
}

const manifestObjectName = archivestore.ManifestObjectName

func sealedPath(resultDir string) string {
	return filepath.Join(resultDir, SealedName)
}

// keyPrefixOf reports the attempt's key prefix for diagnostics only; it is
// never used to address an object.
func keyPrefixOf(manifestKey string) string {
	if index := strings.LastIndexByte(manifestKey, '/'); index >= 0 {
		return manifestKey[:index]
	}
	return manifestKey
}
