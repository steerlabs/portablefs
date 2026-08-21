package hydrator

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

// ErrInvalid is the root of every local rejection: a malformed launch
// configuration, a manifest that does not describe this volume, a tree that is
// not empty, a wire frame outside its bounds.
var ErrInvalid = errors.New("hydrator: invalid")

// The pinned names of restore-mode.md.
const (
	LaunchConfigName = "hydrator.json"
	// ReadyName is the namespace-ready marker, written into the volume's state
	// directory beside the bindings table.
	ReadyName = "restore-namespace-ready.json"
	// BindingsName is the manifest-entry to inode-identity table the authority
	// loads at restore-mode start.
	BindingsName = "restore-bindings"
	// SocketName is the AF_UNIX socket the authority connects to in serve mode.
	SocketName = "hydrator.sock"

	// MaxLaunchConfigBytes is the pinned 4 KiB bound on a helper-written launch
	// configuration.
	MaxLaunchConfigBytes = 4 << 10
	// LaunchConfigVersion and ReadyVersion are the only versions this build
	// writes or accepts.
	LaunchConfigVersion uint32 = 1
	ReadyVersion        uint32 = 1

	// ModeRestoreNamespace materializes the namespace with the authority
	// absent; ModeServe answers the authority's chunk fetches.
	ModeRestoreNamespace = "restore-namespace"
	ModeServe            = "serve"
)

// MaxChunkSizeBytes bounds the chunk size the hydrator will serve.
//
// It follows from the pinned wire frame of 16 MiB + 64 KiB (restore-mode.md).
// One CHUNK reply carries the type byte, a u32 extent count, up to 4096 extents
// of 16 bytes each, and the chunk's stored bytes, so the largest servable chunk
// is 16 MiB + 64 KiB - 65541 bytes. The chunk size is a power of two, which
// makes 8 MiB — the format's default — the largest deployable value. The
// archiver refuses to build a larger one and the hydrator refuses to open one,
// so the bound fails closed from both ends.
const MaxChunkSizeBytes uint32 = 8 << 20

// LaunchConfig is the pinned RESTORE-phase launch configuration
// (restore-mode.md, "Pinned launch configuration"). The manifest's identity
// travels here rather than its key: the key is derived locally from
// {volumeID, sealedEpoch, attempt} and the root-pinned prefix, so no path is
// ever selected by the network, while the digest and size let the manifest be
// verified before it is parsed.
type LaunchConfig struct {
	Version           uint32 `json:"version"`
	VolumeID          string `json:"volume_id"`
	CellID            string `json:"cell_id"`
	SealedEpoch       uint64 `json:"sealed_epoch"`
	Attempt           string `json:"attempt"`
	Mode              string `json:"mode"`
	ManifestSHA256    string `json:"manifest_sha256"`
	ManifestSizeBytes uint64 `json:"manifest_size_bytes"`
	ManifestCRC64NVME string `json:"manifest_crc64nvme"`
	ChunkSizeBytes    uint32 `json:"chunk_size_bytes"`
}

// Validate applies every rule the launch configuration is held to.
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
	case c.SealedEpoch == 0:
		return fmt.Errorf("%w: sealed epoch must be non-zero", ErrInvalid)
	case c.Mode != ModeRestoreNamespace && c.Mode != ModeServe:
		return fmt.Errorf("%w: mode must be %q or %q", ErrInvalid, ModeRestoreNamespace, ModeServe)
	case !validLowerHex(c.ManifestSHA256, 64):
		return fmt.Errorf("%w: manifest SHA-256 must be 64 lowercase hex characters", ErrInvalid)
	case !validLowerHex(c.ManifestCRC64NVME, 16):
		return fmt.Errorf("%w: manifest CRC64NVME must be 16 lowercase hex characters", ErrInvalid)
	case c.ManifestSizeBytes == 0 || c.ManifestSizeBytes > archive.MaxManifestBytes:
		return fmt.Errorf("%w: manifest size must be within (0, %d]", ErrInvalid, archive.MaxManifestBytes)
	case c.ChunkSizeBytes < archive.MinChunkSizeBytes || c.ChunkSizeBytes > MaxChunkSizeBytes ||
		c.ChunkSizeBytes&(c.ChunkSizeBytes-1) != 0:
		return fmt.Errorf("%w: chunk size must be a power of two within [%d, %d]",
			ErrInvalid, archive.MinChunkSizeBytes, MaxChunkSizeBytes)
	}
	return nil
}

// LoadLaunchConfig reads and strictly parses the pinned launch configuration.
func LoadLaunchConfig(path string) (LaunchConfig, error) {
	payload, err := readSmallFile(path, MaxLaunchConfigBytes)
	if err != nil {
		return LaunchConfig{}, fmt.Errorf("hydrator: read launch configuration: %w", err)
	}
	var config LaunchConfig
	if err := decodeStrict(payload, &config); err != nil {
		return LaunchConfig{}, fmt.Errorf("hydrator: launch configuration: %w", err)
	}
	if err := config.Validate(); err != nil {
		return LaunchConfig{}, err
	}
	return config, nil
}

// Ready is the pinned restore-namespace-ready.json record: written after the
// namespace is fully materialized and fsynced, beside the bindings table.
type Ready struct {
	Version     uint32 `json:"version"`
	VolumeID    string `json:"volume_id"`
	SealedEpoch uint64 `json:"sealed_epoch"`
	Attempt     string `json:"attempt"`
	Entries     uint64 `json:"entries"`
	WrittenUnix int64  `json:"written_unix"`
}

func (r *Ready) Validate() error {
	switch {
	case r.Version != ReadyVersion:
		return fmt.Errorf("%w: ready marker version %d is not %d", ErrInvalid, r.Version, ReadyVersion)
	case !cellplan.ValidID(r.VolumeID) || !cellplan.ValidID(r.Attempt):
		return fmt.Errorf("%w: ready marker identities must be lowercase canonical UUIDs", ErrInvalid)
	case r.SealedEpoch == 0 || r.Entries == 0 || r.WrittenUnix <= 0:
		return fmt.Errorf("%w: ready marker is incomplete", ErrInvalid)
	}
	return nil
}

// Describes reports whether the marker is this exact phase's marker. A marker
// naming another volume, epoch, or attempt is a stale file: the run fails
// rather than reporting someone else's namespace as ready.
func (r *Ready) Describes(config LaunchConfig) error {
	if r.VolumeID != config.VolumeID || r.Attempt != config.Attempt || r.SealedEpoch != config.SealedEpoch {
		return fmt.Errorf("%w: existing ready marker describes volume %s epoch %d attempt %s, not volume %s epoch %d attempt %s",
			ErrInvalid, r.VolumeID, r.SealedEpoch, r.Attempt, config.VolumeID, config.SealedEpoch, config.Attempt)
	}
	return nil
}

// marshalReady renders the ready marker with a trailing newline, so the file is
// a well-formed text line as well as a well-formed JSON document.
func marshalReady(ready Ready) ([]byte, error) {
	payload, err := json.Marshal(ready)
	if err != nil {
		return nil, fmt.Errorf("hydrator: encode ready marker: %w", err)
	}
	return append(payload, '\n'), nil
}

// ReadReady loads and validates an existing ready marker. A missing file is
// reported as os.ErrNotExist so "not restored yet" and "a marker that does not
// parse" stay distinguishable.
func ReadReady(path string) (Ready, error) {
	payload, err := readSmallFile(path, MaxLaunchConfigBytes)
	if err != nil {
		return Ready{}, err
	}
	var ready Ready
	if err := decodeStrict(payload, &ready); err != nil {
		return Ready{}, fmt.Errorf("hydrator: ready marker: %w", err)
	}
	if err := ready.Validate(); err != nil {
		return Ready{}, err
	}
	return ready, nil
}

// writeAtomic writes one state file atomically and durably: a private temporary
// file in the same directory, fsynced, renamed over the final name, and the
// directory fsynced after the rename.
func writeAtomic(path string, payload []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".hydrator-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()
	return handle.Sync()
}

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

// parseUUIDBytes returns the 16 RFC 4122 bytes of a lowercase canonical UUID,
// which is how the manifest header records volume and attempt identity.
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
