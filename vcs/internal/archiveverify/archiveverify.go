// Package archiveverify implements the Manager's independent archive
// verification and purge over the archive store. It is the concrete
// controlplane.ArchiveVerifier / controlplane.ArchivePurger: verification is
// the gate before any DESTROY plan may exist, so it trusts nothing the cell
// reported — it fetches the manifest itself, re-derives every object key from
// the identities inside the sealed manifest, and cross-checks the observed
// record field by field. The division of labor with the cell TCB is
// deliberate: the archiver's read-back pass proves pack *content*; this
// package proves the manifest end to end plus the object inventory (size, and
// the store's full-object CRC64NVME where the store supports it).
//
// All calls here run outside the Manager's store lock (the Manager's
// two-phase verify guarantees that); latency is bounded by the client's own
// timeouts.
package archiveverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

// maxManifestBytes mirrors the format bound: a manifest object above 2 GiB is
// refused before allocation, never streamed into memory.
const maxManifestBytes = int64(2) << 30

// opTimeout bounds each store operation. The verify pass may issue one GET
// plus one HeadObject per pack; a stall surfaces as a retryable verification
// failure at the Manager's "verifying" cursor, never an unbounded hang.
const opTimeout = 2 * time.Minute

type Store struct {
	client *archivestore.Client
}

func New(client *archivestore.Client) (*Store, error) {
	if client == nil {
		return nil, errors.New("archiveverify: an archive-store client is required")
	}
	return &Store{client: client}, nil
}

// Verify implements controlplane.ArchiveVerifier.
func (s *Store) Verify(record controlplane.ArchiveRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if record.Manifest.SizeBytes == 0 || int64(record.Manifest.SizeBytes) > maxManifestBytes {
		return fmt.Errorf("archiveverify: recorded manifest size %d is outside bounds", record.Manifest.SizeBytes)
	}
	raw, err := s.client.GetObject(ctx, record.Manifest.Key, int64(record.Manifest.SizeBytes))
	if err != nil {
		return fmt.Errorf("archiveverify: fetch manifest: %w", err)
	}
	if uint64(len(raw)) != record.Manifest.SizeBytes {
		return fmt.Errorf("archiveverify: manifest is %d bytes, record says %d", len(raw), record.Manifest.SizeBytes)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != strings.ToLower(record.Manifest.SHA256) {
		return errors.New("archiveverify: manifest digest does not match the record")
	}
	manifest, err := archive.Decode(raw)
	if err != nil {
		return fmt.Errorf("archiveverify: decode manifest: %w", err)
	}
	volumeID := uuidString(manifest.Header.VolumeID)
	attempt := uuidString(manifest.Header.Attempt)
	if attempt != strings.ToLower(record.Attempt) {
		return errors.New("archiveverify: manifest attempt does not match the record")
	}
	if manifest.Header.SealedEpoch != record.SealedEpoch {
		return errors.New("archiveverify: manifest sealed epoch does not match the record")
	}
	if manifest.Header.FormatVersion != record.FormatVersion || manifest.Header.ChunkSizeBytes != record.ChunkSizeBytes {
		return errors.New("archiveverify: manifest format parameters do not match the record")
	}
	if manifest.Header.LogicalBytes != record.LogicalBytes || manifest.Header.LogicalInodes != record.LogicalInodes ||
		manifest.Header.SealedAllocatedBytes != record.SealedAllocatedBytes || manifest.Header.SealedInodes != record.SealedInodes {
		return errors.New("archiveverify: manifest totals do not match the record")
	}
	if archive.RootDigestHex(manifest) != strings.ToLower(record.RootDigest) {
		return errors.New("archiveverify: manifest root digest does not match the record")
	}
	// The record's keys must be exactly the locally derived, prefix-pinned
	// keys for the manifest's own identities — a record cannot point the
	// destroy gate at somebody else's objects.
	manifestKey, err := s.client.KeyFor(volumeID, record.SealedEpoch, attempt, "manifest")
	if err != nil {
		return fmt.Errorf("archiveverify: derive manifest key: %w", err)
	}
	if manifestKey != record.Manifest.Key {
		return errors.New("archiveverify: recorded manifest key is not the derived key for its identities")
	}
	if len(manifest.Header.Packs) != len(record.Packs) {
		return fmt.Errorf("archiveverify: manifest has %d packs, record has %d", len(manifest.Header.Packs), len(record.Packs))
	}
	for index, pack := range manifest.Header.Packs {
		recorded := record.Packs[index]
		key, err := s.client.KeyFor(volumeID, record.SealedEpoch, attempt, fmt.Sprintf("pack-%d", index))
		if err != nil {
			return fmt.Errorf("archiveverify: derive pack key %d: %w", index, err)
		}
		if key != recorded.Key {
			return fmt.Errorf("archiveverify: recorded key for pack %d is not the derived key", index)
		}
		if pack.SizeBytes != recorded.SizeBytes {
			return fmt.Errorf("archiveverify: pack %d size disagreement between manifest and record", index)
		}
		if hex.EncodeToString(pack.SHA256[:]) != strings.ToLower(recorded.SHA256) {
			return fmt.Errorf("archiveverify: pack %d digest disagreement between manifest and record", index)
		}
		if archivestore.CRC64Hex(pack.CRC64NVME) != strings.ToLower(recorded.CRC64NVME) {
			return fmt.Errorf("archiveverify: pack %d checksum disagreement between manifest and record", index)
		}
		info, err := s.client.HeadObject(ctx, key)
		if err != nil {
			return fmt.Errorf("archiveverify: head pack %d: %w", index, err)
		}
		if info.Size < 0 || uint64(info.Size) != pack.SizeBytes {
			return fmt.Errorf("archiveverify: pack %d is %d bytes in the store, manifest says %d", index, info.Size, pack.SizeBytes)
		}
		if s.client.ChecksumsEnabled() {
			if info.CRC64NVMEHex == "" {
				return fmt.Errorf("archiveverify: the store returned no full-object checksum for pack %d but the deployment declares the capability", index)
			}
			if !strings.EqualFold(info.CRC64NVMEHex, archivestore.CRC64Hex(pack.CRC64NVME)) {
				return fmt.Errorf("archiveverify: pack %d full-object checksum disagrees with the manifest", index)
			}
		}
	}
	return nil
}

// Purge implements controlplane.ArchivePurger. Idempotent by construction:
// DeleteObject treats an absent object as success, so a crash between
// deletion and the durable state record simply re-deletes nothing.
func (s *Store) Purge(record controlplane.ArchiveRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	for index, pack := range record.Packs {
		if err := s.client.DeleteObject(ctx, pack.Key); err != nil {
			return fmt.Errorf("archiveverify: delete pack %d: %w", index, err)
		}
	}
	if err := s.client.DeleteObject(ctx, record.Manifest.Key); err != nil {
		return fmt.Errorf("archiveverify: delete manifest: %w", err)
	}
	return nil
}

func uuidString(raw [16]byte) string {
	var formatted [36]byte
	hex.Encode(formatted[0:8], raw[0:4])
	formatted[8] = '-'
	hex.Encode(formatted[9:13], raw[4:6])
	formatted[13] = '-'
	hex.Encode(formatted[14:18], raw[6:8])
	formatted[18] = '-'
	hex.Encode(formatted[19:23], raw[8:10])
	formatted[23] = '-'
	hex.Encode(formatted[24:36], raw[10:16])
	return string(formatted[:])
}
