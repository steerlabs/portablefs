package cellhost

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

const (
	archiveConfigName             = "archiver.json"
	hydratorConfigName            = "hydrator.json"
	archiveSealedName             = "archive-sealed.json"
	restoreNamespaceReadyName     = "restore-namespace-ready.json"
	restoreProgressName           = "restore-progress.json"
	restoreConvergedName          = "restore-converged.json"
	archiveResultDirectoryName    = "archive"
	maxLaunchConfigBytes          = 4 << 10
	maxArchiveSealedBytes         = 768 << 10
	maxRestoreResultBytes         = 4 << 10
	archiveCredentialsServicePath = "/run/portablefs-archive.env"
)

var (
	ErrArchiveSealedAbsent         = errors.New("cellhost: archive seal has not been written")
	ErrRestoreNamespaceReadyAbsent = errors.New("cellhost: restore namespace is not ready")
	ErrRestoreProgressAbsent       = errors.New("cellhost: restore progress has not been written")
	ErrRestoreConvergedAbsent      = errors.New("cellhost: restore has not converged")
)

type HydratorMode string

const (
	HydratorModeRestoreNamespace HydratorMode = "restore-namespace"
	HydratorModeServe            HydratorMode = "serve"
)

func validHydratorMode(mode HydratorMode) bool {
	return mode == HydratorModeRestoreNamespace || mode == HydratorModeServe
}

type ArchiverConfig struct {
	Version           uint32 `json:"version"`
	VolumeID          string `json:"volume_id"`
	CellID            string `json:"cell_id"`
	AuthorityEpoch    uint64 `json:"authority_epoch"`
	PlacementSequence uint64 `json:"placement_sequence"`
	Attempt           string `json:"attempt"`
	KeyVersion        string `json:"key_version"`
	ChunkSizeBytes    uint32 `json:"chunk_size_bytes"`
}

type HydratorConfig struct {
	Version           uint32       `json:"version"`
	VolumeID          string       `json:"volume_id"`
	CellID            string       `json:"cell_id"`
	SealedEpoch       uint64       `json:"sealed_epoch"`
	Attempt           string       `json:"attempt"`
	Mode              HydratorMode `json:"mode"`
	ManifestSHA256    string       `json:"manifest_sha256"`
	ManifestSizeBytes uint64       `json:"manifest_size_bytes"`
	ManifestCRC64NVME string       `json:"manifest_crc64nvme"`
	ChunkSizeBytes    uint32       `json:"chunk_size_bytes"`
}

type ArchiveSealedRecord struct {
	Version              uint32                   `json:"version"`
	VolumeID             string                   `json:"volume_id"`
	CellID               string                   `json:"cell_id"`
	SealedEpoch          uint64                   `json:"sealed_epoch"`
	Attempt              string                   `json:"attempt"`
	Manifest             controlplane.ObjectRef   `json:"manifest"`
	Packs                []controlplane.ObjectRef `json:"packs"`
	RootDigest           string                   `json:"root_digest_sha256"`
	LogicalBytes         uint64                   `json:"logical_bytes"`
	LogicalInodes        uint64                   `json:"logical_inodes"`
	SealedAllocatedBytes uint64                   `json:"sealed_allocated_bytes"`
	SealedInodes         uint64                   `json:"sealed_inodes"`
	FormatVersion        uint32                   `json:"format_version"`
	ChunkSizeBytes       uint32                   `json:"chunk_size_bytes"`
	KeyVersion           string                   `json:"key_version"`
	WrittenUnix          int64                    `json:"written_unix"`
}

func (record ArchiveSealedRecord) Observation() *controlplane.ArchiveSealedObservation {
	return &controlplane.ArchiveSealedObservation{
		Attempt: record.Attempt, Manifest: record.Manifest, Packs: append([]controlplane.ObjectRef(nil), record.Packs...),
		RootDigest: record.RootDigest, LogicalBytes: record.LogicalBytes, LogicalInodes: record.LogicalInodes,
		SealedAllocatedBytes: record.SealedAllocatedBytes, SealedInodes: record.SealedInodes,
		FormatVersion: record.FormatVersion, ChunkSizeBytes: record.ChunkSizeBytes, KeyVersion: record.KeyVersion,
	}
}

type RestoreNamespaceReadyRecord struct {
	Version     uint32 `json:"version"`
	VolumeID    string `json:"volume_id"`
	SealedEpoch uint64 `json:"sealed_epoch"`
	Attempt     string `json:"attempt"`
	Entries     uint64 `json:"entries"`
	WrittenUnix int64  `json:"written_unix"`
}

type RestoreProgressRecord struct {
	Version          uint32 `json:"version"`
	ProgressPermille uint32 `json:"progress_permille"`
	State            string `json:"state"`
	RecalledBytes    uint64 `json:"recalled_bytes"`
	DrainedBytes     uint64 `json:"drained_bytes"`
	UpdatedUnix      int64  `json:"updated_unix"`
}

// The specification pins the convergence identity and drained totals but not
// a separate schema listing. This record uses the same versioned, strict shape
// as the other restore status files and names both byte and chunk totals.
type RestoreConvergedRecord struct {
	Version        uint32 `json:"version"`
	VolumeID       string `json:"volume_id"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	Attempt        string `json:"attempt"`
	DrainedBytes   uint64 `json:"drained_bytes"`
	DrainedChunks  uint64 `json:"drained_chunks"`
	WrittenUnix    int64  `json:"written_unix"`
}

func validSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == hex.EncodeToString(decoded)
}

func validateObjectRef(ref controlplane.ObjectRef) bool {
	return ref.Key != "" && len(ref.Key) <= controlplane.MaxArchiveObjectKeyBytes && utf8.ValidString(ref.Key) &&
		!strings.ContainsRune(ref.Key, 0) && ref.SizeBytes > 0 && validSHA256Hex(ref.SHA256) &&
		(ref.CRC64NVME == "" || validLowerHexBytes(ref.CRC64NVME, 8))
}

func validLowerHexBytes(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && value == hex.EncodeToString(decoded)
}

func validateArchiveSealed(record ArchiveSealedRecord, volumeID, cellID string) error {
	if record.Version != 1 || record.VolumeID != volumeID || record.CellID != cellID || record.SealedEpoch == 0 ||
		!cellplan.ValidID(record.Attempt) || !validateObjectRef(record.Manifest) || len(record.Packs) == 0 ||
		len(record.Packs) > controlplane.MaxArchivePacks || !validSHA256Hex(record.RootDigest) || record.FormatVersion == 0 ||
		record.ChunkSizeBytes == 0 || record.KeyVersion == "" || record.SealedAllocatedBytes == 0 || record.SealedInodes == 0 || record.WrittenUnix <= 0 {
		return errors.New("cellhost: archive seal is incomplete or belongs to another placement")
	}
	for _, pack := range record.Packs {
		if !validateObjectRef(pack) {
			return errors.New("cellhost: archive seal contains an invalid pack reference")
		}
	}
	return nil
}
