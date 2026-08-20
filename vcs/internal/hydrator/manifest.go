package hydrator

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
)

// ManifestObjectName is the pinned last component of the manifest key. It is
// the only entry point into an archive attempt: the store is never listed, and
// every other object is named by the manifest itself.
const ManifestObjectName = "manifest"

// ManifestKey derives this attempt's manifest key under the client's root
// pinned prefix.
func ManifestKey(client *archivestore.Client, config LaunchConfig) (string, error) {
	return client.KeyFor(config.VolumeID, config.SealedEpoch, config.Attempt, ManifestObjectName)
}

// LoadManifest downloads, verifies, and decodes the sealed manifest.
//
// The download is bounded by the size the launch configuration pins, so a store
// that offered a larger object cannot make this process allocate for it. The
// object's SHA-256 and CRC-64/NVME are then checked against the configuration
// before a single byte is parsed: the manifest is the one input that names
// every other object, so it is proved to be the exact object the archiver
// sealed before it is given any authority over what happens next. The decoder
// re-derives every structural invariant on top of that.
func LoadManifest(ctx context.Context, client *archivestore.Client, config LaunchConfig) (*archive.Manifest, error) {
	key, err := ManifestKey(client, config)
	if err != nil {
		return nil, err
	}
	payload, err := client.GetObject(ctx, key, int64(config.ManifestSizeBytes))
	if err != nil {
		return nil, fmt.Errorf("hydrator: fetch manifest: %w", err)
	}
	if uint64(len(payload)) != config.ManifestSizeBytes {
		return nil, fmt.Errorf("%w: manifest is %d bytes, the launch configuration pins %d",
			ErrInvalid, len(payload), config.ManifestSizeBytes)
	}
	digest := sha256.Sum256(payload)
	want, err := hex.DecodeString(config.ManifestSHA256)
	if err != nil || subtle.ConstantTimeCompare(digest[:], want) != 1 {
		return nil, fmt.Errorf("%w: manifest digest does not match the launch configuration", ErrInvalid)
	}
	if checksum := archivestore.CRC64Hex(archivestore.ChecksumCRC64NVME(payload)); checksum != config.ManifestCRC64NVME {
		return nil, fmt.Errorf("%w: manifest checksum %s does not match the launch configuration's %s",
			ErrInvalid, checksum, config.ManifestCRC64NVME)
	}
	manifest, err := archive.Decode(payload)
	if err != nil {
		return nil, fmt.Errorf("hydrator: decode manifest: %w", err)
	}
	if err := manifestDescribes(manifest, config); err != nil {
		return nil, err
	}
	return manifest, nil
}

// manifestDescribes proves the decoded manifest is this volume's, this epoch's,
// and this attempt's. A manifest whose digest matched but whose identity does
// not is a key-derivation or provisioning fault, and continuing would restore
// the wrong volume's tree.
func manifestDescribes(manifest *archive.Manifest, config LaunchConfig) error {
	volumeID, err := parseUUIDBytes(config.VolumeID)
	if err != nil {
		return err
	}
	attempt, err := parseUUIDBytes(config.Attempt)
	if err != nil {
		return err
	}
	header := &manifest.Header
	switch {
	case header.VolumeID != volumeID:
		return fmt.Errorf("%w: manifest names another volume", ErrInvalid)
	case header.Attempt != attempt:
		return fmt.Errorf("%w: manifest names another attempt", ErrInvalid)
	case header.SealedEpoch != config.SealedEpoch:
		return fmt.Errorf("%w: manifest names epoch %d, the launch configuration names %d",
			ErrInvalid, header.SealedEpoch, config.SealedEpoch)
	case header.ChunkSizeBytes != config.ChunkSizeBytes:
		return fmt.Errorf("%w: manifest chunk size %d does not match the launch configuration's %d",
			ErrInvalid, header.ChunkSizeBytes, config.ChunkSizeBytes)
	case header.ChunkSizeBytes > MaxChunkSizeBytes:
		return fmt.Errorf("%w: manifest chunk size %d exceeds the servable maximum %d",
			ErrInvalid, header.ChunkSizeBytes, MaxChunkSizeBytes)
	}
	return nil
}
