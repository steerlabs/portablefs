package hydrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
)

// The pinned paths of the RESTORE phase's unit (restore-mode.md, "Components").
const (
	// DefaultLaunchConfigPath is the helper-written launch configuration inside
	// the volume's read-only ConfigRoot bind.
	DefaultLaunchConfigPath = "/run/portablefs-volume/" + LaunchConfigName
	// DefaultArchiveConfigPath is the root-provisioned archive-store credential
	// file; in restore the credentials are read-scoped.
	DefaultArchiveConfigPath = "/run/portablefs-archive.env"
	// ArchiveConfigEnv is the environment variable the unit sets to override
	// the credential file path.
	ArchiveConfigEnv = "PORTABLEFS_ARCHIVE_CONFIG"
	// DefaultVolumeRoot is the volume data directory. It is bound read-write by
	// a per-phase drop-in for restore-namespace mode only; serve mode has no
	// data-directory access at all and never opens this path.
	DefaultVolumeRoot = "/srv/portablefs-volume"
	// DefaultStateDir is the volume's state bind, StateRoot/<vol> on the host:
	// the bindings table, the ready marker, and the socket live here, beside
	// the authority's own state.
	DefaultStateDir = "/var/lib/portablefs-volume"
)

// Options is everything a run needs that is not in the launch configuration.
// The zero value names the production paths.
type Options struct {
	LaunchConfigPath  string
	ArchiveConfigPath string
	VolumeRoot        string
	StateDir          string
	// SocketPath overrides the serve-mode socket. Empty means StateDir's
	// pinned hydrator.sock.
	SocketPath string

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
	if o.StateDir == "" {
		o.StateDir = DefaultStateDir
	}
	if o.SocketPath == "" {
		o.SocketPath = filepath.Join(o.StateDir, SocketName)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// Run performs one RESTORE-phase mode, chosen by the launch configuration.
func Run(ctx context.Context, options Options) error {
	options = options.withDefaults()
	config, err := LoadLaunchConfig(options.LaunchConfigPath)
	if err != nil {
		return err
	}
	switch config.Mode {
	case ModeRestoreNamespace:
		return RestoreNamespace(ctx, config, options)
	case ModeServe:
		return Serve(ctx, config, options)
	default:
		// Validate already refused anything else; the default keeps the switch
		// exhaustive rather than silently doing nothing.
		return fmt.Errorf("%w: mode %q", ErrInvalid, config.Mode)
	}
}

// RestoreNamespace materializes the complete namespace and reports it ready.
//
// It is idempotent by attempt: a ready marker that already describes this
// volume, epoch, and attempt means a previous run completed and the helper
// restarted the unit, so the run succeeds without touching the tree. Any
// failure leaves no marker, and the volume tree — which the phase requires to
// be empty — is the helper's to reprovision.
func RestoreNamespace(ctx context.Context, config LaunchConfig, options Options) error {
	options = options.withDefaults()
	readyPath := filepath.Join(options.StateDir, ReadyName)
	switch existing, err := ReadReady(readyPath); {
	case err == nil:
		if err := existing.Describes(config); err != nil {
			return err
		}
		options.Logf("namespace already restored for volume %s attempt %s", config.VolumeID, config.Attempt)
		return nil
	case errors.Is(err, os.ErrNotExist):
		// The ordinary path: no marker yet, so restore.
	default:
		return fmt.Errorf("hydrator: existing ready marker: %w", err)
	}

	client, err := options.store()
	if err != nil {
		return err
	}
	manifest, err := LoadManifest(ctx, client, config)
	if err != nil {
		return err
	}
	root, err := openRootDirectory(options.VolumeRoot)
	if err != nil {
		return fmt.Errorf("hydrator: open volume root: %w", err)
	}
	defer func() { _ = root.Close() }()

	bindings, err := materialize(root, manifest)
	if err != nil {
		return err
	}
	table, err := EncodeBindings(bindings)
	if err != nil {
		return err
	}
	// The bindings table is written before the marker: the marker is what the
	// helper observes, and it must never be durable before the table the
	// authority will need.
	if err := writeAtomic(filepath.Join(options.StateDir, BindingsName), table); err != nil {
		return fmt.Errorf("hydrator: write bindings: %w", err)
	}
	ready := Ready{
		Version:     ReadyVersion,
		VolumeID:    config.VolumeID,
		SealedEpoch: config.SealedEpoch,
		Attempt:     config.Attempt,
		Entries:     uint64(len(manifest.Entries)),
		WrittenUnix: options.Now().Unix(),
	}
	if err := ready.Validate(); err != nil {
		return err
	}
	payload, err := marshalReady(ready)
	if err != nil {
		return err
	}
	if err := writeAtomic(readyPath, payload); err != nil {
		return fmt.Errorf("hydrator: write ready marker: %w", err)
	}
	options.Logf("restored %d entries of volume %s epoch %d attempt %s",
		ready.Entries, config.VolumeID, config.SealedEpoch, config.Attempt)
	return nil
}

// Serve runs the serve-mode socket until the context is cancelled. It never
// opens the volume data directory: in this mode the process has no access to it
// at all, and the authority is the only writer of XFS.
func Serve(ctx context.Context, config LaunchConfig, options Options) error {
	options = options.withDefaults()
	client, err := options.store()
	if err != nil {
		return err
	}
	manifest, err := LoadManifest(ctx, client, config)
	if err != nil {
		return err
	}
	server, err := NewServer(client, manifest, config, options.Logf)
	if err != nil {
		return err
	}
	options.Logf("serving volume %s epoch %d attempt %s: %d entries, %d drain chunks (%d in the prefetch region)",
		config.VolumeID, config.SealedEpoch, config.Attempt, server.info.EntryCount,
		server.info.DrainCount, server.info.PriorityDrainCount)
	return server.Serve(ctx, options.SocketPath)
}

func (o Options) store() (*archivestore.Client, error) {
	if o.Client != nil {
		return o.Client, nil
	}
	config, err := archivestore.LoadConfigFile(o.ArchiveConfigPath)
	if err != nil {
		return nil, fmt.Errorf("hydrator: archive-store configuration: %w", err)
	}
	client, err := archivestore.New(config)
	if err != nil {
		return nil, fmt.Errorf("hydrator: archive-store client: %w", err)
	}
	return client, nil
}
