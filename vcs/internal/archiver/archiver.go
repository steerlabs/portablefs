package archiver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
)

// The pinned paths of the ARCHIVE phase's unit (restore-mode.md, "Components").
// Every one of them is a bind the helper establishes; none is ever selected by
// anything the process reads over the network.
const (
	// DefaultLaunchConfigPath is the helper-written launch configuration inside
	// the volume's read-only ConfigRoot bind.
	DefaultLaunchConfigPath = "/run/portablefs-volume/" + LaunchConfigName
	// DefaultArchiveConfigPath is the root-provisioned archive-store credential
	// file the unit binds; the flag default and the environment override name
	// it, and nothing else may.
	DefaultArchiveConfigPath = "/run/portablefs-archive.env"
	// ArchiveConfigEnv is the environment variable the unit sets to override
	// the credential file path.
	ArchiveConfigEnv = "PORTABLEFS_ARCHIVE_CONFIG"
	// DefaultVolumeRoot is the read-only bind of the quiesced volume tree.
	DefaultVolumeRoot = "/srv/portablefs-volume"
	// DefaultResultDir is the read-write result bind, StateRoot/<vol>/archive
	// on the host, which the helper reads durably before it observes.
	DefaultResultDir = "/var/lib/portablefs-volume-archive"

	// DefaultPartSizeBytes is the multipart part size. The format's window is
	// 8..64 MiB; 16 MiB uploads a 64 GiB pack in 4096 parts, comfortably inside
	// the 10,000-part limit, and bounds the uploader's resident set at one part.
	DefaultPartSizeBytes uint64 = 16 << 20
)

// Options is everything the run needs that is not in the launch configuration.
// The zero value names the production paths; the tests fill in a client and
// temporary directories.
type Options struct {
	LaunchConfigPath  string
	ArchiveConfigPath string
	VolumeRoot        string
	ResultDir         string

	// PartSizeBytes, PackTargetBytes, CompressionLevel, WindowLog, and
	// PriorityLogicalBytes are the format's deployment knobs. Zero means the
	// documented default.
	PartSizeBytes        uint64
	PackTargetBytes      uint64
	CompressionLevel     int32
	WindowLog            uint32
	PriorityLogicalBytes uint64

	// VerifyStreams is the read-back parallelism, roughly one stream per
	// 85-90 MB/s of provisioned bandwidth. Zero means four.
	VerifyStreams int

	// Client, when set, is used instead of loading the credential file. It is
	// the test seam and the only way a caller may supply a store.
	Client *archivestore.Client

	Now  func() time.Time
	Logf func(format string, args ...any)
}

func (o Options) withDefaults() Options {
	if o.LaunchConfigPath == "" {
		o.LaunchConfigPath = DefaultLaunchConfigPath
	}
	if o.ArchiveConfigPath == "" {
		o.ArchiveConfigPath = DefaultArchiveConfigPath
	}
	if o.VolumeRoot == "" {
		o.VolumeRoot = DefaultVolumeRoot
	}
	if o.ResultDir == "" {
		o.ResultDir = DefaultResultDir
	}
	if o.PartSizeBytes == 0 {
		o.PartSizeBytes = DefaultPartSizeBytes
	}
	if o.PackTargetBytes == 0 {
		o.PackTargetBytes = archive.MaxPackTargetBytes
	}
	if o.CompressionLevel == 0 {
		o.CompressionLevel = archive.DefaultCompressionLevel
	}
	if o.WindowLog == 0 {
		o.WindowLog = archive.DefaultWindowLog
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// Run performs one ARCHIVE phase: load and validate the launch configuration,
// archive the volume tree, verify every uploaded byte by read-back, and write
// the sealed result record.
//
// It is idempotent by attempt. A result record that already describes this
// attempt means a previous run of this unit completed and the helper restarted
// it; the record is validated against the launch configuration and the run
// succeeds without touching the store. Any failure leaves no result record at
// all, which is what makes the helper's observation honest: a seal exists only
// when every chunk has been read back and verified.
func Run(ctx context.Context, options Options) error {
	options = options.withDefaults()
	config, err := LoadLaunchConfig(options.LaunchConfigPath)
	if err != nil {
		return err
	}
	resultPath := sealedPath(options.ResultDir)
	switch existing, err := ReadSealed(resultPath); {
	case err == nil:
		if err := existing.Describes(config); err != nil {
			return err
		}
		options.Logf("archive already sealed for volume %s attempt %s", config.VolumeID, config.Attempt)
		return nil
	case errors.Is(err, os.ErrNotExist):
		// The ordinary path: no seal yet, so archive.
	default:
		return fmt.Errorf("archiver: existing result record: %w", err)
	}

	client := options.Client
	if client == nil {
		storeConfig, err := archivestore.LoadConfigFile(options.ArchiveConfigPath)
		if err != nil {
			return fmt.Errorf("archiver: archive-store configuration: %w", err)
		}
		if client, err = archivestore.New(storeConfig); err != nil {
			return fmt.Errorf("archiver: archive-store client: %w", err)
		}
	}

	sealed, err := archiveVolume(ctx, client, config, options)
	if err != nil {
		return err
	}
	if err := WriteSealed(resultPath, sealed); err != nil {
		return fmt.Errorf("archiver: write result record: %w", err)
	}
	options.Logf("sealed volume %s epoch %d attempt %s: %d packs under %s",
		config.VolumeID, config.AuthorityEpoch, config.Attempt, len(sealed.Packs), keyPrefixOf(sealed.Manifest.Key))
	return nil
}

// archiveVolume builds, uploads, and verifies one attempt. It returns the
// record to seal; it never writes anything to the result directory itself, so
// every failure path is "no seal" by construction.
func archiveVolume(ctx context.Context, client *archivestore.Client, config LaunchConfig, options Options) (Sealed, error) {
	volumeID, err := parseUUIDBytes(config.VolumeID)
	if err != nil {
		return Sealed{}, err
	}
	attempt, err := parseUUIDBytes(config.Attempt)
	if err != nil {
		return Sealed{}, err
	}

	walker, err := OpenVolume(options.VolumeRoot)
	if err != nil {
		return Sealed{}, err
	}
	defer func() { _ = walker.Close() }()

	upload, err := newUploader(ctx, client, config, options.PartSizeBytes)
	if err != nil {
		return Sealed{}, err
	}
	// A failed build leaves at most one multipart upload in flight; abort is a
	// no-op once every pack has been completed.
	defer upload.abort()

	builderConfig := archive.BuilderConfig{
		ChunkSizeBytes:       config.ChunkSizeBytes,
		CompressionLevel:     options.CompressionLevel,
		WindowLog:            options.WindowLog,
		VolumeID:             volumeID,
		SealedEpoch:          config.AuthorityEpoch,
		Attempt:              attempt,
		PackTargetBytes:      options.PackTargetBytes,
		PartSizeBytes:        options.PartSizeBytes,
		PriorityLogicalBytes: options.PriorityLogicalBytes,
	}
	if options.PriorityLogicalBytes == 0 {
		builderConfig.PriorityLogicalBytes = archive.DefaultBuilderConfig().PriorityLogicalBytes
	}
	manifest, err := archive.Build(builderConfig, walker, upload)
	if err != nil {
		return Sealed{}, fmt.Errorf("archiver: build archive: %w", err)
	}
	payload, err := archive.Encode(manifest)
	if err != nil {
		return Sealed{}, fmt.Errorf("archiver: encode manifest: %w", err)
	}

	manifestKey, err := upload.key(manifestObjectName)
	if err != nil {
		return Sealed{}, err
	}
	manifestCRC, err := putManifest(ctx, client, manifestKey, payload)
	if err != nil {
		return Sealed{}, err
	}

	// Read-back verification. Nothing below this line may be skipped: the seal
	// is the claim that every byte of this archive has been fetched back out of
	// the store and matched against the manifest.
	if err := verifyPackObjects(ctx, client, manifest, upload.packs); err != nil {
		return Sealed{}, err
	}
	if err := proveObjectIdentical(ctx, client, manifestKey, payload, manifestCRC); err != nil {
		return Sealed{}, fmt.Errorf("archiver: manifest read-back: %w", err)
	}
	policy := verifyPolicy{streams: options.VerifyStreams}.withDefaults(uint64(config.ChunkSizeBytes))
	source := &packSource{ctx: ctx, client: client, keys: packKeys(upload.packs), maxBytes: policy.maxRangeBytes}
	if err := verifyChunks(ctx, source, manifest, policy); err != nil {
		return Sealed{}, fmt.Errorf("archiver: content read-back: %w", err)
	}

	sealed := Sealed{
		Version:     SealedVersion,
		VolumeID:    config.VolumeID,
		CellID:      config.CellID,
		SealedEpoch: config.AuthorityEpoch,
		Attempt:     config.Attempt,
		Manifest: ObjectRef{
			Key:       manifestKey,
			SizeBytes: uint64(len(payload)),
			SHA256:    sha256Hex(payload),
			CRC64NVME: manifestCRC,
		},
		Packs:                packRefs(manifest, upload.packs),
		RootDigest:           archive.RootDigestHex(manifest),
		LogicalBytes:         manifest.Header.LogicalBytes,
		LogicalInodes:        manifest.Header.LogicalInodes,
		SealedAllocatedBytes: manifest.Header.SealedAllocatedBytes,
		SealedInodes:         manifest.Header.SealedInodes,
		FormatVersion:        manifest.Header.FormatVersion,
		ChunkSizeBytes:       manifest.Header.ChunkSizeBytes,
		KeyVersion:           config.KeyVersion,
		WrittenUnix:          options.Now().Unix(),
	}
	if err := sealed.Validate(); err != nil {
		return Sealed{}, err
	}
	return sealed, nil
}

func packKeys(packs []uploadedPack) []string {
	keys := make([]string, len(packs))
	for index, pack := range packs {
		keys[index] = pack.key
	}
	return keys
}

func packRefs(manifest *archive.Manifest, packs []uploadedPack) []ObjectRef {
	refs := make([]ObjectRef, len(packs))
	for index, pack := range packs {
		recorded := manifest.Header.Packs[index]
		refs[index] = ObjectRef{
			Key:       pack.key,
			SizeBytes: recorded.SizeBytes,
			SHA256:    hex.EncodeToString(recorded.SHA256[:]),
			CRC64NVME: archivestore.CRC64Hex(recorded.CRC64NVME),
		}
	}
	return refs
}
