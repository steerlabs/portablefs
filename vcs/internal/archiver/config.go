package archiver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

// ErrInvalid is the root of every rejection this package makes locally: a
// malformed launch configuration, a tree the format cannot carry, a result
// record that does not describe this attempt. Store-side failures keep their
// own archivestore error type.
var ErrInvalid = errors.New("archiver: invalid")

// LaunchConfigName and SealedName are the pinned file names of
// restore-mode.md: the helper writes the first into the volume's ConfigRoot
// bind and reads the second out of the archive result bind.
const (
	LaunchConfigName = "archiver.json"
	SealedName       = "archive-sealed.json"

	// MaxLaunchConfigBytes is the pinned 4 KiB bound on every helper-written
	// launch configuration (identity-lifecycle-and-capacity.md section 1).
	MaxLaunchConfigBytes = 4 << 10

	// LaunchConfigVersion is the only launch-configuration version this build
	// accepts. An unknown version is refused whole, never partially applied.
	LaunchConfigVersion uint32 = 1
)

// LaunchConfig is the pinned ARCHIVE-phase launch configuration
// (restore-mode.md, "Pinned launch configuration"). It is root-written, strict
// JSON, and carries identities only: no object key, no endpoint, and no path is
// ever selected by anything but root-provisioned cell configuration.
type LaunchConfig struct {
	Version           uint32 `json:"version"`
	VolumeID          string `json:"volume_id"`
	CellID            string `json:"cell_id"`
	AuthorityEpoch    uint64 `json:"authority_epoch"`
	PlacementSequence uint64 `json:"placement_sequence"`
	Attempt           string `json:"attempt"`
	KeyVersion        string `json:"key_version"`
	ChunkSizeBytes    uint32 `json:"chunk_size_bytes"`
}

// MaxChunkSizeBytes bounds the deployable chunk size below the format's own
// 1 GiB ceiling.
//
// The reason is the hydrator's pinned wire frame: a CHUNK reply carries one
// chunk's stored bytes plus its extent list — up to 4096 extents of 16 bytes —
// inside a frame bounded at 16 MiB + 64 KiB (restore-mode.md, "Authority <->
// hydrator socket protocol"), which leaves 16 MiB + 64 KiB - 65541 bytes for
// the content and therefore 8 MiB as the largest power of two that fits. A
// deployment that configured a larger chunk would build an archive whose chunks
// cannot be served, and it would discover that only at wake; refusing it at
// export is the fail-closed reading of the same contract. 8 MiB is also the
// format's default, so this bound constrains nothing that exists today.
const MaxChunkSizeBytes uint32 = 8 << 20

// Validate applies every rule the launch configuration is held to. It is total:
// a configuration that passes here can address every object this process
// writes.
func (c *LaunchConfig) Validate() error {
	switch {
	case c.Version != LaunchConfigVersion:
		return fmt.Errorf("%w: launch configuration version %d is not %d", ErrInvalid, c.Version, LaunchConfigVersion)
	case !cellplan.ValidID(c.VolumeID):
		return fmt.Errorf("%w: volume ID must be a lowercase canonical UUID", ErrInvalid)
	case !cellplan.ValidID(c.CellID):
		return fmt.Errorf("%w: cell ID must be a lowercase canonical UUID", ErrInvalid)
	case !cellplan.ValidID(c.Attempt):
		return fmt.Errorf("%w: attempt must be a lowercase canonical UUID", ErrInvalid)
	case c.AuthorityEpoch == 0:
		return fmt.Errorf("%w: authority epoch must be non-zero", ErrInvalid)
	case c.PlacementSequence == 0:
		return fmt.Errorf("%w: placement sequence must be non-zero", ErrInvalid)
	case !validKeyVersion(c.KeyVersion):
		return fmt.Errorf("%w: key version must be 1..64 printable ASCII characters without spaces", ErrInvalid)
	case c.ChunkSizeBytes < archive.MinChunkSizeBytes || c.ChunkSizeBytes > MaxChunkSizeBytes ||
		c.ChunkSizeBytes&(c.ChunkSizeBytes-1) != 0:
		return fmt.Errorf("%w: chunk size must be a power of two within [%d, %d]",
			ErrInvalid, archive.MinChunkSizeBytes, MaxChunkSizeBytes)
	}
	return nil
}

func validKeyVersion(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// LoadLaunchConfig reads and validates the pinned launch configuration. The
// file is opened without following a final symlink, must be a regular file, and
// must be no larger than the pinned bound; the JSON is parsed strictly, so an
// unknown field, a duplicate document, or trailing content is a configuration
// error rather than something to interpret generously.
func LoadLaunchConfig(path string) (LaunchConfig, error) {
	payload, err := readSmallFile(path, MaxLaunchConfigBytes)
	if err != nil {
		return LaunchConfig{}, fmt.Errorf("archiver: read launch configuration: %w", err)
	}
	var config LaunchConfig
	if err := decodeStrict(payload, &config); err != nil {
		return LaunchConfig{}, fmt.Errorf("archiver: launch configuration: %w", err)
	}
	if err := config.Validate(); err != nil {
		return LaunchConfig{}, err
	}
	return config, nil
}

// readSmallFile reads a bounded regular file through a descriptor that never
// followed a symlink at the final component.
func readSmallFile(path string, limit int64) ([]byte, error) {
	file, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalid, path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, path, limit)
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, path, limit)
	}
	return payload, nil
}

// decodeStrict refuses unknown fields, a non-object document, and any trailing
// content after the first JSON value.
func decodeStrict(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing content after the JSON document", ErrInvalid)
	}
	return nil
}

// parseUUIDBytes returns the 16 RFC 4122 bytes of a lowercase canonical UUID.
// The manifest binds an archive to {volume, epoch, attempt} as raw bytes, so
// the text form is converted exactly once, here, after cellplan's grammar has
// already accepted it.
func parseUUIDBytes(value string) ([16]byte, error) {
	var out [16]byte
	if !cellplan.ValidID(value) {
		return out, fmt.Errorf("%w: %q is not a lowercase canonical UUID", ErrInvalid, value)
	}
	compact := make([]byte, 0, 32)
	for i := 0; i < len(value); i++ {
		if value[i] != '-' {
			compact = append(compact, value[i])
		}
	}
	decoded, err := hex.DecodeString(string(compact))
	if err != nil || len(decoded) != 16 {
		return out, fmt.Errorf("%w: %q is not a UUID", ErrInvalid, value)
	}
	copy(out[:], decoded)
	return out, nil
}

// fsyncDirectory flushes a directory entry change (a rename) to disk. It is the
// second half of every atomic write in this package: the file's own bytes are
// fsynced before the rename, the directory after it.
func fsyncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
