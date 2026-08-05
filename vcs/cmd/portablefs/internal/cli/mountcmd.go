package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/accountsession"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

const mountTokenEnv = "PORTABLEFS_MOUNT_TOKEN"

type mountOpts struct {
	common              commonOpts
	// branch stays a field because the mount records, ownership locks, and
	// persistence keys are branch-shaped; a v3 mount is branchless, so it is
	// always empty (the --branch flag itself is retired).
	branch              string
	strategy            string
	addr                string
	mountToken          string
	dataPlaneTransport  string
	dataPlaneServerName string
	dataPlaneCAPath     string
	clientCertPath      string
	clientKeyPath       string
	coherence           string
	foreground          bool
	readyFD             int
	opLockFD            int
	localDirs           stringListFlag
	noLocalDirs         bool
}

// errFastRetired is the typed refusal for the retired --fast flag: write
// mode is no longer a mount property — the authority delegates adaptively on
// every mount, and fsync is always durable at the authority.
var errFastRetired = fmt.Errorf("--fast is retired: every mount is adaptive (the authority delegates write-back per scope automatically); remove the flag")

// errBranchRetired is the typed refusal for the retired --branch flag: a v3
// volume is branchless — one durable workspace, no branch graph — so there is
// nothing the flag could select.
var errBranchRetired = fmt.Errorf("--branch is retired: a v3 volume is branchless; remove the flag")

// errMountNeedsDirectV3Credentials is the refusal for a mount invocation that
// still expects the legacy manager/lease flow. The retained manager mints
// only v2 HMAC leases, which cannot admit a v3 authority session, and there
// is deliberately no fallback to the legacy clientcore mount — so the absent
// arguments are named instead of silently mounting a weaker engine.
var errMountNeedsDirectV3Credentials = fmt.Errorf(
	"portablefs mount attaches the v3 authority stack and needs direct credentials: pass " +
		"--addr <host:port>, a mount capability via --mount-token (or " + mountTokenEnv + "), " +
		"--data-plane-transport tls-private-ca|tls-system-pki (with --data-plane-server-name, and --data-plane-ca for a private CA), " +
		"and the mutual-TLS client identity via --client-cert/--client-key. " +
		"The retained authority manager cannot mint v3 credentials, so a manager/lease-only invocation is refused rather than mounted on the retired v2 engine")

func addMountFlags(fs *flag.FlagSet, o *mountOpts) {
	addCommonFlags(fs, &o.common)
	fs.BoolFunc("branch", "retired: v3 volumes are branchless; passing this flag is an error", func(string) error {
		return errBranchRetired
	})
	fs.StringVar(&o.strategy, "strategy", "auto", "mount strategy: auto (fskit on macOS, fuse on Linux), fskit, or fuse")
	fs.StringVar(&o.addr, "addr", "", "v3 authority address (host:port)")
	fs.StringVar(&o.mountToken, "mount-token", "", "single-use volume mount capability (or "+mountTokenEnv+")")
	fs.StringVar(&o.dataPlaneTransport, "data-plane-transport", "", "required: tls-private-ca or tls-system-pki (v3 sessions are mutually authenticated TLS; plaintext cannot mount)")
	fs.StringVar(&o.dataPlaneServerName, "data-plane-server-name", "", "exact TLS verification name of the authority")
	fs.StringVar(&o.dataPlaneCAPath, "data-plane-ca", "", "private CA PEM file for tls-private-ca")
	fs.StringVar(&o.clientCertPath, "client-cert", "", "mutual-TLS client certificate PEM file")
	fs.StringVar(&o.clientKeyPath, "client-key", "", "mutual-TLS client private key PEM file (must be chmod 600)")
	fs.StringVar(&o.coherence, "coherence", "strict", "kernel cache contract: strict (cache names and attributes, join the authority visibility barrier) or uncached (cache nothing; Linux only)")
	fs.BoolFunc("fast", "retired: every mount is adaptive; passing this flag is an error", func(string) error {
		return errFastRetired
	})
	fs.Var(&o.localDirs, "local-dir", "refused: machine-local routes are declared volume-wide in "+localdirs.VolumeConfigPath)
	fs.BoolVar(&o.noLocalDirs, "no-local-dirs", false, "refuse to mount a volume that declares machine-local routes in "+localdirs.VolumeConfigPath+" (and clear this mount's persisted legacy --local-dir state)")
	fs.BoolVar(&o.foreground, "foreground", false, "stay attached instead of daemonizing")
	fs.IntVar(&o.readyFD, "ready-fd", 0, "internal: fd to write the readiness report to")
	fs.IntVar(&o.opLockFD, "op-lock-fd", 0, "internal: inherited mount operation lock fd")
}

// validateDirectV3MountOpts is the one gate every mount invocation passes:
// the complete direct v3 credential shape, stated up front in the parent
// process, so errors surface immediately instead of via the daemonized
// child's readiness report. It returns the validated transport.
func validateDirectV3MountOpts(o *mountOpts, getenv func(string) string) (dataPlaneTransport, error) {
	if len(o.localDirs) > 0 {
		return dataPlaneTransport{}, fmt.Errorf(
			"machine-local routes are declared volume-wide in %s; --local-dir would add a route only this machine knows about, which desynchronizes the routing topology the authority pins every mount to",
			localdirs.VolumeConfigPath,
		)
	}
	if o.addr == "" || o.dataPlaneTransport == "" {
		return dataPlaneTransport{}, errMountNeedsDirectV3Credentials
	}
	if o.dataPlaneTransport == dataPlaneTransportPlaintext {
		return dataPlaneTransport{}, fmt.Errorf(
			"v3 authority sessions are mutually authenticated TLS 1.3; --data-plane-transport plaintext cannot mount (use tls-private-ca or tls-system-pki)")
	}
	transport, err := directDataPlaneTransport(o.dataPlaneTransport, o.dataPlaneServerName, o.dataPlaneCAPath)
	if err != nil {
		return dataPlaneTransport{}, err
	}
	if o.resolveMountToken(getenv) == "" {
		return dataPlaneTransport{}, fmt.Errorf("a v3 mount needs its single-use volume capability: pass --mount-token or set %s", mountTokenEnv)
	}
	if o.clientCertPath == "" || o.clientKeyPath == "" {
		return dataPlaneTransport{}, fmt.Errorf("a v3 mount authenticates with a mutual-TLS client identity: pass --client-cert and --client-key")
	}
	if o.coherence != "strict" && o.coherence != "uncached" {
		return dataPlaneTransport{}, fmt.Errorf("--coherence must be strict or uncached, not %q", o.coherence)
	}
	return transport, nil
}

// perfOptions carries the FUSE mount cache options plus the write-back
// engine's durable state location. There is no write-mode knob: the
// authority delegates adaptively per scope. Plain writes may return before
// the local group-sync; fsync forces local sync and authority durability.
type perfOptions struct {
	// negativeCache forces the negative dentry cache on; negativeCacheOff
	// forces it off. Neither (the default) keeps the v8 baseline: on.
	negativeCache    bool
	negativeCacheOff bool
	// writebackDir is the engine's durable state directory, keyed by
	// (volume, branch) so parked streams recover across mount paths.
	writebackDir string
	volumeID     string
	branch       string
}

func perfOptionsFromEnv(getenv func(string) string) perfOptions {
	return perfOptions{
		negativeCache:    getenv("PORTABLEFS_NEGATIVE_CACHE") == "1",
		negativeCacheOff: getenv("PORTABLEFS_NEGATIVE_CACHE") == "0",
	}
}

// storageDirID names the per-(volume, branch) write-back state directory:
// stable across mount paths so a parked stream recovers wherever the volume
// mounts next.
func storageDirID(volumeID, branch string) string {
	sum := sha256.Sum256([]byte(volumeID + "\x00" + branch))
	return hex.EncodeToString(sum[:8])
}

// mountReady is the readiness handshake between the daemonized child and the
// parent `portablefs mount` invocation (one JSON line over a pipe).
type mountReady struct {
	OK        bool     `json:"ok"`
	Cleaned   bool     `json:"cleaned,omitempty"`
	Error     string   `json:"error,omitempty"`
	PID       int      `json:"pid,omitempty"`
	Strategy  string   `json:"strategy,omitempty"`
	MountPath string   `json:"mountPath,omitempty"`
	VolumeID  string   `json:"volumeId,omitempty"`
	Branch    string   `json:"branch,omitempty"`
	AttachRef string   `json:"attachRef,omitempty"`
	LocalDirs []string `json:"localDirs,omitempty"`
	// LocalRoutes is the FUSE mount's activated route set and
	// LocalRouteRevision the VOLUME DECLARATION's revision it answers for.
	// LocalRoutesPerMachine marks the legacy case where the rules came from
	// this machine's --local-dir flags instead, which the parent warns about.
	LocalRoutes           []string `json:"localRoutes,omitempty"`
	LocalRouteRevision    string   `json:"localRouteRevision,omitempty"`
	LocalRoutesPerMachine bool     `json:"localRoutesPerMachine,omitempty"`
}

// resolveLocalDirs applies the documented precedence for machine-local dirs:
// explicit --local-dir flags win and update the persisted per-mount record;
// no flags reuses the persisted record; --no-local-dirs clears it and
// disables grafts (including the volume's declaration file) for this mount.
// A volume that publishes .portablefs/local-dirs owns its routing outright:
// the mount refuses --local-dir there (see resolveRoutes), so this precedence
// only ever decides the legacy path on volumes that declare nothing.
func resolveLocalDirs(o *mountOpts, stateDir, volumeID, mountPath string) (flagDirs []string, volumeFileEnabled bool, err error) {
	if o.noLocalDirs && len(o.localDirs) > 0 {
		return nil, false, fmt.Errorf("--local-dir and --no-local-dirs are mutually exclusive")
	}
	if o.noLocalDirs {
		if err := writePersistedLocalDirs(stateDir, volumeID, o.branch, mountPath, nil); err != nil {
			return nil, false, fmt.Errorf("clear persisted local dirs: %w", err)
		}
		return nil, false, nil
	}
	if len(o.localDirs) > 0 {
		if err := localdirs.ValidateStrict(o.localDirs); err != nil {
			return nil, false, err
		}
		norm, err := localdirs.Normalize(o.localDirs)
		if err != nil {
			return nil, false, err
		}
		if err := writePersistedLocalDirs(stateDir, volumeID, o.branch, mountPath, norm); err != nil {
			return nil, false, fmt.Errorf("persist local dirs: %w", err)
		}
		return norm, true, nil
	}
	dirs, err := readPersistedLocalDirs(stateDir, volumeID, o.branch, mountPath)
	if err != nil {
		return nil, false, err
	}
	return dirs, true, nil
}

func cmdMount(e *cmdEnv, args []string) int {
	fs := newFlagSet("mount")
	var o mountOpts
	addMountFlags(fs, &o)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("mount", err)
	}
	if len(positionals) != 2 {
		return e.usageError("mount", fmt.Errorf("expected <volumeId> <mountPath>"))
	}
	sessionStateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return e.fail("mount", err)
	}
	sessionGuard, err := accountsession.AcquireShared(sessionStateDir)
	if err != nil {
		return e.fail("mount", fmt.Errorf("acquire account session guard: %w; credentials or profiles may be changing", err))
	}
	defer sessionGuard.Close()
	volumeID := positionals[0]
	if !validVolumeName(volumeID) {
		return e.usageError("mount", fmt.Errorf("invalid volume id %q: must match [A-Za-z0-9_-]{1,220}", volumeID))
	}
	mountPath, err := canonicalMountPath(positionals[1])
	if err != nil {
		return e.fail("mount", err)
	}
	// Validate the complete direct v3 credential shape in the parent so
	// errors surface immediately instead of via the daemonized child's
	// readiness report.
	if _, err := validateDirectV3MountOpts(&o, e.getenv); err != nil {
		return e.usageError("mount", err)
	}
	// The identity files are proven readable (and the key private) here for
	// the same reason: the child re-reads them, but a bad path or a
	// world-readable key should stop the command before it forks anything.
	if _, err := loadClientTLSIdentity(o.clientCertPath, o.clientKeyPath); err != nil {
		return e.usageError("mount", err)
	}

	stateDir, err := e.mountStateDir()
	if err != nil {
		return e.fail("mount", err)
	}
	if err := e.validateMountOwnership(stateDir, volumeID, o.branch, mountPath); err != nil {
		return e.fail("mount", err)
	}
	selectedStrategy, err := resolveStrategy(o.strategy, runtime.GOOS)
	if err != nil {
		return e.fail("mount", err)
	}
	if selectedStrategy == "fskit" && o.coherence != "strict" {
		return e.usageError("mount", fmt.Errorf("the macOS FSKit engine declares the strict %s coherence policy; --coherence %s is Linux-only", portablefsd.V3CachePolicyMacOS26, o.coherence))
	}
	var operation *mountOperation
	if o.opLockFD > 0 {
		operation, err = adoptMountOperation(o.opLockFD, stateDir, mountPath)
	} else {
		operation, err = acquireMountOperation(stateDir, mountPath, volumeID, o.branch, selectedStrategy)
	}
	if err != nil {
		return e.fail("mount", err)
	}
	operation.volumeID = volumeID
	operation.branch = o.branch
	operation.strategy = selectedStrategy
	failAndFinalize := func(primary error) int {
		return e.fail("mount", errors.Join(primary, operation.close(true)))
	}
	if err := validateMountTarget(stateDir, mountPath); err != nil {
		return failAndFinalize(err)
	}
	if st, readErr := readMountState(stateDir, mountPath); readErr != nil {
		return failAndFinalize(readErr)
	} else if st != nil {
		present, identityErr := recordedKernelMountPresent(st)
		if identityErr != nil {
			return failAndFinalize(fmt.Errorf("recorded kernel identity for %s is not safely classifiable: %w", mountPath, identityErr))
		}
		if present {
			return failAndFinalize(fmt.Errorf("%s is already mounted (volume %s, pid %d); run `portablefs umount %s` first", mountPath, st.VolumeID, st.PID, mountPath))
		}
		return failAndFinalize(fmt.Errorf("stale mount state remains for %s (volume %s); run `portablefs umount %s` to reconcile it before mounting", mountPath, st.VolumeID, mountPath))
	}

	if o.foreground {
		return e.runMountForeground(&o, volumeID, mountPath, stateDir, operation)
	}
	return e.daemonizeMount(&o, volumeID, mountPath, stateDir, operation)
}

func validateMountTarget(stateDir, mountPath string) error {
	target, _, err := openValidatedMountTarget(stateDir, mountPath)
	if err != nil {
		return err
	}
	return target.Close()
}

type mountTargetIdentity struct {
	device uint64
	inode  uint64
}

func openValidatedMountTarget(stateDir, mountPath string) (*os.File, mountTargetIdentity, error) {
	if mountPath == string(filepath.Separator) {
		return nil, mountTargetIdentity{}, fmt.Errorf("refusing to mount over the filesystem root")
	}
	// Never enter a candidate before proving it is not itself a mountpoint
	// and does not cover another kernel mount. ReadDir on a wedged userspace
	// mount could otherwise hang the CLI before it has classified the path.
	if err := preflightKernelMountTarget(mountPath); err != nil {
		return nil, mountTargetIdentity{}, err
	}
	target, err := privatepath.OpenOwnedDir(mountPath)
	if err != nil {
		return nil, mountTargetIdentity{}, fmt.Errorf("open pinned mount target %s: %w", mountPath, err)
	}
	fail := func(err error) (*os.File, mountTargetIdentity, error) {
		return nil, mountTargetIdentity{}, errors.Join(err, target.Close())
	}
	identity, err := mountTargetIdentityOf(target)
	if err != nil {
		return fail(err)
	}
	entries, err := target.ReadDir(-1)
	if err != nil {
		return fail(fmt.Errorf("inspect pinned mount directory %s: %w", mountPath, err))
	}
	if len(entries) != 0 {
		return fail(fmt.Errorf("mount directory %s is not empty; refusing to cover unrelated data", mountPath))
	}
	states, err := listMountStates(stateDir)
	if err != nil {
		return fail(fmt.Errorf("inspect existing PortableFS mounts: %w", err))
	}
	for _, state := range states {
		present, err := recordedKernelMountPresent(&state)
		if err != nil {
			return fail(fmt.Errorf("recorded kernel identity for %s is not safely classifiable: %w", state.MountPath, err))
		}
		if !present {
			continue
		}
		if mountPathsOverlap(mountPath, state.MountPath) {
			return fail(fmt.Errorf("mount path %s overlaps live PortableFS mount %s; nested mounts are not supported", mountPath, state.MountPath))
		}
	}
	return target, identity, nil
}

func mountTargetIdentityOf(target *os.File) (mountTargetIdentity, error) {
	info, err := target.Stat()
	if err != nil {
		return mountTargetIdentity{}, fmt.Errorf("inspect pinned mount target: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return mountTargetIdentity{}, fmt.Errorf("pinned mount target has unsupported filesystem identity")
	}
	return mountTargetIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func revalidatePinnedMountTarget(mountPath string, expected mountTargetIdentity) error {
	// Keep the table-first ordering: never enter a path after a kernel mount
	// appeared over it.
	if err := preflightKernelMountTarget(mountPath); err != nil {
		return err
	}
	current, err := privatepath.OpenExistingOwnedDir(mountPath)
	if err != nil {
		return fmt.Errorf("reopen mount target immediately before mount: %w", err)
	}
	defer current.Close()
	identity, err := mountTargetIdentityOf(current)
	if err != nil {
		return err
	}
	if identity != expected {
		return fmt.Errorf(
			"mount target %s changed before mount (device/inode %d:%d, expected %d:%d)",
			mountPath, identity.device, identity.inode, expected.device, expected.inode,
		)
	}
	entries, err := current.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("recheck mount target immediately before mount: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("mount directory %s became non-empty before mount; refusing to cover unrelated data", mountPath)
	}
	return nil
}

// volumeBranchLabel renders a volume identity for messages. A v3 mount is
// branchless, and "vol@" is not a name anything else prints, so the branch
// suffix appears only when a branch exists (legacy v2 records).
func volumeBranchLabel(volumeID, branch string) string {
	if branch == "" {
		return volumeID
	}
	return volumeID + "@" + branch
}

func mountOwnershipLockName(volumeID, branch string) string {
	sum := sha256.Sum256([]byte(volumeID + "\x00" + branch))
	return "mount-ownership-" + hex.EncodeToString(sum[:16]) + ".lock"
}

// validateMountOwnership enforces the machine/account contract of one live
// mount per (volume, branch). Every durable source is inventoried strictly:
// state, operation intents, kernel mounts, and daemon attaches. An
// uncorrelated PortableFS kernel mount is uncertainty, not permission.
func (e *cmdEnv) validateMountOwnership(stateDir, volumeID, branch, mountPath string) error {
	states, err := listMountStates(stateDir)
	if err != nil {
		return fmt.Errorf("strict mount-state inventory: %w", err)
	}
	intents, err := listMountIntents(stateDir)
	if err != nil {
		return fmt.Errorf("strict mount-operation inventory: %w", err)
	}
	knownPaths := make(map[string]struct{}, len(states)+len(intents))
	for i := range states {
		state := &states[i]
		knownPaths[state.MountPath] = struct{}{}
		if state.MountPath != mountPath && state.VolumeID == volumeID && state.Branch == branch {
			return fmt.Errorf(
				"%s already has a mount record at %s; one live mount per volume is supported on this machine (run `portablefs umount %s` first)",
				volumeBranchLabel(volumeID, branch), state.MountPath, state.MountPath,
			)
		}
	}
	for i := range intents {
		intent := &intents[i]
		knownPaths[intent.MountPath] = struct{}{}
		if intent.MountPath != mountPath && intent.VolumeID == volumeID && intent.Branch == branch {
			return fmt.Errorf(
				"%s has an incomplete %s operation at %s; run `portablefs umount %s` before mounting this volume elsewhere",
				volumeBranchLabel(volumeID, branch), intent.Phase, intent.MountPath, intent.MountPath,
			)
		}
	}
	kernelPaths, err := e.kernelMountInventory()
	if err != nil {
		return fmt.Errorf("strict PortableFS kernel inventory: %w", err)
	}
	for _, path := range kernelPaths {
		if _, known := knownPaths[path]; !known {
			return fmt.Errorf(
				"unrecorded PortableFS kernel mount remains at %s; reconcile it before creating another mount",
				path,
			)
		}
	}
	persistedAttaches, err := portablefsd.ReadPersistedAttachInventory(
		filepath.Join(filepath.Dir(stateDir), "portablefsd"),
	)
	if err != nil {
		return fmt.Errorf("strict durable daemon attach inventory: %w", err)
	}
	persistedByRef := make(map[string]portablefsd.PersistedAttachIdentity, len(persistedAttaches))
	for _, attach := range persistedAttaches {
		persistedByRef[attach.AttachRef] = attach
		if attach.MountPath != mountPath && attach.VolumeID == volumeID && attach.Branch == branch {
			return fmt.Errorf(
				"%s already has durable daemon attach %s at %s; run `portablefs umount %s` first",
				volumeBranchLabel(volumeID, branch), attach.AttachRef, attach.MountPath, attach.MountPath,
			)
		}
	}

	cfg, err := fskitConfigFromEnv(e.getenv)
	if err != nil {
		return err
	}
	liveness := newFsdControl(cfg.controlSock)
	liveness.httpClient.Timeout = 3 * time.Second
	if liveness.healthy() {
		ctl, err := connectCompatiblePortablefsd(cfg, e.version)
		if err != nil {
			return fmt.Errorf("strict daemon identity inventory: %w", err)
		}
		attaches, err := ctl.listAttaches()
		if err != nil {
			return fmt.Errorf("strict daemon attach inventory: %w", err)
		}
		for _, attach := range attaches {
			persisted, ok := persistedByRef[attach.AttachRef]
			if !ok || persisted.VolumeID != attach.VolumeID || persisted.Branch != attach.Branch || persisted.MountPath != attach.MountPath {
				return fmt.Errorf("live daemon attach %s is inconsistent with strict durable inventory", attach.AttachRef)
			}
			if attach.MountPath != mountPath && attach.VolumeID == volumeID && attach.Branch == branch {
				return fmt.Errorf(
					"%s already has daemon attach %s at %s; run `portablefs umount %s` first",
					volumeBranchLabel(volumeID, branch), attach.AttachRef, attach.MountPath, attach.MountPath,
				)
			}
			delete(persistedByRef, attach.AttachRef)
		}
		if len(persistedByRef) != 0 {
			return fmt.Errorf("durable daemon attach inventory contains entries absent from the live daemon")
		}
	} else {
		for i := range intents {
			if intents[i].AttachRef != "" {
				return fmt.Errorf(
					"daemon is unavailable, so attach %s from incomplete operation at %s cannot be inventoried; run `portablefs umount %s` first",
					intents[i].AttachRef, intents[i].MountPath, intents[i].MountPath,
				)
			}
		}
	}
	return nil
}

// lstatMountPath, kernelMountsAt and liveDaemonAttachMountPaths are the three
// ways this package learns about a mount path. They are vars so CLI tests can
// drive the dead-volume and stale-record classifications without a real wedged
// kernel mount.
var (
	lstatMountPath             = os.Lstat
	kernelMountsAt             = platformKernelMountsAt
	liveDaemonAttachMountPaths = defaultLiveDaemonAttachMountPaths
)

// mountPathProbeBudget bounds every filesystem probe of a mount path.
//
// EVERY `portablefs umount` BEGINS BY STATTING THE MOUNT POINT, AND THAT IS A
// CALL INTO THE FILESYSTEM BEING UNMOUNTED. lstat(2) on a mount point resolves
// to the mounted filesystem's root vnode, so on a wedged mount it parks in the
// VFS until the extension answers — which, for the mount an operator is trying
// to unmount precisely because it stopped answering, is never. Both `portablefs
// umount` and `portablefs umount --force` hung there for more than five minutes
// before reaching a single line of unmount logic; the operator killed them.
//
// The probe is therefore bounded, and a probe that exceeds its budget reports
// ETIMEDOUT — the exact shape canonicalMountPath already routes to the
// identification paths that never touch the filesystem (the kernel mount table
// via getfsstat(2), and the daemon's own attach inventory). An unresponsive
// mount now takes the dead-volume path instead of stopping the command.
//
// A var so tests compress it; production never changes it.
var mountPathProbeBudget = 10 * time.Second

// boundedLstatMountPath runs the lstat probe with a hard ceiling.
//
// The probe runs on its own goroutine because there is no interruptible lstat.
// If the budget expires that goroutine stays parked until the kernel releases
// it; it holds no lock and owns no state, and — unlike an unmount(2) teardown —
// a path lookup is an interruptible VFS wait, so it can never keep this process
// from exiting.
func boundedLstatMountPath(path string) (os.FileInfo, error) {
	type probe struct {
		info os.FileInfo
		err  error
	}
	// Resolve the statter on THIS goroutine. The probe goroutine can outlive the
	// call, and it must not still be reading a package variable afterwards.
	stat := lstatMountPath
	done := make(chan probe, 1)
	go func() {
		info, err := stat(path)
		done <- probe{info: info, err: err}
	}()
	timer := time.NewTimer(mountPathProbeBudget)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.info, result.err
	case <-timer.C:
		return nil, &os.PathError{Op: "lstat", Path: path, Err: syscall.ETIMEDOUT}
	}
}

// unresponsiveMountPathErr reports whether err is the shape a mount point
// takes once its filesystem stops answering: EIO once the kernel has declared
// the volume dead, ETIMEDOUT while it is still waiting for an extension that
// will never reply. Both mean "this pathname cannot be resolved THROUGH the
// filesystem", never "this pathname does not name a PortableFS mount", so both
// must route to the identification paths that do not touch the filesystem.
func unresponsiveMountPathErr(err error) bool {
	return errors.Is(err, syscall.EIO) || errors.Is(err, syscall.ETIMEDOUT)
}

// defaultLiveDaemonAttachMountPaths reports the mount paths of every attach a
// LIVE portablefsd currently owns. It deliberately answers "no attaches, no
// error" when the daemon is unreachable: an absent daemon is not evidence
// about the path, and the caller's underlying error must stand in that case.
func defaultLiveDaemonAttachMountPaths() ([]string, error) {
	cfg, err := fskitConfigFromEnv(os.Getenv)
	if err != nil {
		return nil, nil
	}
	ctl := newFsdControl(cfg.controlSock)
	ctl.httpClient.Timeout = 3 * time.Second
	if !ctl.healthy() {
		return nil, nil
	}
	attaches, err := ctl.listAttaches()
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(attaches))
	for _, attach := range attaches {
		if attach.MountPath != "" {
			paths = append(paths, filepath.Clean(attach.MountPath))
		}
	}
	return paths, nil
}

// liveDaemonAttachAt reports whether a live daemon owns an attach whose mount
// path is exactly path.
func liveDaemonAttachAt(path string) (bool, error) {
	paths, err := liveDaemonAttachMountPaths()
	if err != nil {
		return false, err
	}
	for _, candidate := range paths {
		if candidate == path {
			return true, nil
		}
	}
	return false, nil
}

// exactKernelMountAt returns the single kernel mount whose mount point is
// exactly path, or nil when nothing is mounted there. Stacked mounts are an
// ambiguity this product refuses to act on. It never resolves a pathname
// through a mounted filesystem, so it is the ONLY identification that still
// answers once a volume is dead and every syscall into it returns EIO.
func exactKernelMountAt(path string) (*kernelMountIdentity, error) {
	mounts, err := kernelMountsAt(path)
	if err != nil {
		return nil, err
	}
	switch len(mounts) {
	case 0:
		return nil, nil
	case 1:
		mount := mounts[0]
		return &mount, nil
	default:
		return nil, fmt.Errorf(
			"kernel mount identity at %s is ambiguous: %d stacked entries share the path",
			path, len(mounts),
		)
	}
}

func canonicalMountPath(input string) (string, error) {
	absolute, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	info, lstatErr := boundedLstatMountPath(absolute)
	if lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("mount path %s is a symlink; use a real directory", absolute)
	}
	if lstatErr != nil && !os.IsNotExist(lstatErr) {
		// A dead volume answers EIO — or, while the kernel is still waiting on
		// an extension that will never reply, ETIMEDOUT — for every pathname
		// that resolves THROUGH it, including its own mount point. Detaching
		// is the remedy for exactly that state, so the CLI must not need a
		// working filesystem to name the mount. Ask the kernel mount table
		// instead: a mount whose mount point is this exact path proves the
		// path is already canonical (the kernel records the fully resolved
		// mount point), and the caller can proceed to the daemon-owned detach.
		mount, tableErr := exactKernelMountAt(absolute)
		if tableErr == nil && mount != nil {
			return absolute, nil
		}
		if tableErr == nil && unresponsiveMountPathErr(lstatErr) {
			// THE DEAD-RESIDUE SHAPE. The kernel already tore its mount down
			// (or never published one the table can see) while portablefsd
			// still owns a live attach at this path, holding the write-back
			// tail the detach has to drain and reconcile. Nothing about that
			// state is ambiguous and nothing about it is recoverable through
			// the filesystem: the daemon's own attach inventory names the
			// mount, so the path is canonical and the caller proceeds to the
			// daemon-owned detach. Refusing here left the daemon control API
			// as the only recovery.
			live, attachErr := liveDaemonAttachAt(absolute)
			if attachErr == nil && live {
				return absolute, nil
			}
			return "", errors.Join(
				fmt.Errorf("inspect mount path %s: %w", absolute, lstatErr),
				attachErr,
			)
		}
		return "", errors.Join(
			fmt.Errorf("inspect mount path %s: %w", absolute, lstatErr),
			tableErr,
		)
	}
	current := absolute
	var missing []string
	for {
		_, err := boundedLstatMountPath(current)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("inspect mount path ancestor %s: %w", current, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for mount path %s", absolute)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return "", fmt.Errorf("resolve mount path ancestor %s: %w", current, err)
	}
	for i := len(missing) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, missing[i])
	}
	return filepath.Clean(resolved), nil
}

func mountPathsOverlap(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	return pathContains(a, b) || pathContains(b, a)
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// daemonizeMount re-execs this binary with --foreground in a detached session,
// then waits for its readiness report so `portablefs mount` returns only once
// the path is live (or with the child's real error).
func (e *cmdEnv) daemonizeMount(o *mountOpts, volumeID, mountPath, stateDir string, operation *mountOperation) int {
	transferredOperation := false
	failBeforeTransfer := func(primary error) int {
		if transferredOperation {
			return e.fail("mount", primary)
		}
		transferredOperation = true
		return e.fail("mount", errors.Join(primary, operation.close(true)))
	}
	exe, err := os.Executable()
	if err != nil {
		return failBeforeTransfer(fmt.Errorf("locate own executable for daemonizing: %w", err))
	}
	logPath := mountLogPath(stateDir, mountPath)
	logFile, err := privatepath.OpenFileTruncate(logPath)
	if err != nil {
		return failBeforeTransfer(err)
	}
	defer logFile.Close()

	childArgs := []string{"mount", volumeID, mountPath,
		"--strategy", o.strategy, "--foreground", "--ready-fd", "3", "--op-lock-fd", "4",
		"--addr", o.addr,
		"--data-plane-transport", o.dataPlaneTransport,
		"--client-cert", o.clientCertPath,
		"--client-key", o.clientKeyPath,
		"--coherence", o.coherence,
	}
	if o.dataPlaneServerName != "" {
		childArgs = append(childArgs, "--data-plane-server-name", o.dataPlaneServerName)
	}
	if o.dataPlaneCAPath != "" {
		childArgs = append(childArgs, "--data-plane-ca", o.dataPlaneCAPath)
	}
	if o.noLocalDirs {
		childArgs = append(childArgs, "--no-local-dirs")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return failBeforeTransfer(err)
	}
	defer r.Close()

	cmd := exec.Command(exe, childArgs...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{w, operation.file} // child fd 3: readiness; fd 4: path operation lock
	// THE SUPERVISOR MUST NOT INHERIT A WORKING DIRECTORY IT COULD BE PINNING.
	//
	// A working directory is an open directory reference exactly like any other
	// fd, and it is invisible in the code that opens things. An operator who
	// runs `portablefs mount ~/vol ~/vol` from inside (or at) the mount point
	// hands this long-lived, session-detached supervisor a cwd on the directory
	// it is about to mount over — which then answers EBUSY to that same mount's
	// unmount for the life of the process, with nothing in the mount code to
	// point at. Root is the only directory that can never be a mount target.
	cmd.Dir = "/"
	// Detach into its own session so the mount daemon survives this process's
	// terminal and signals. The mount capability travels via environment,
	// never argv, where any process on the machine could read it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = os.Environ()
	if tok := o.resolveMountToken(e.getenv); tok != "" {
		cmd.Env = append(cmd.Env, mountTokenEnv+"="+tok)
	}
	if err := cmd.Start(); err != nil {
		_ = w.Close()
		return failBeforeTransfer(fmt.Errorf("start mount daemon: %w", err))
	}
	// Start is the irreversible ownership edge: the child can adopt the
	// inherited operation lock and advance the durable intent before this
	// parent can inspect /proc. Never remove the intent after Start.
	transferredOperation = true
	_ = operation.file.Close()
	operation.file = nil
	_ = w.Close()
	childStartIdentity, identityErr := processStartIdentity(cmd.Process.Pid)
	if identityErr != nil {
		return e.fail("mount", terminateUnidentifiedStartedMount(cmd, operation, identityErr))
	}

	readyCh := make(chan mountReady, 1)
	errCh := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(r).ReadString('\n')
		if err != nil && line == "" {
			errCh <- fmt.Errorf("mount daemon exited before reporting readiness")
			return
		}
		var ready mountReady
		if err := json.Unmarshal([]byte(line), &ready); err != nil {
			errCh <- fmt.Errorf("unreadable readiness report from mount daemon: %q", strings.TrimSpace(line))
			return
		}
		readyCh <- ready
	}()

	var ready mountReady
	select {
	case ready = <-readyCh:
	case err := <-errCh:
		cleanupErr := terminateSpawnedMount(cmd, childStartIdentity)
		cleanupErr = errors.Join(cleanupErr, operation.preserveCleanupIntent(cmd.Process.Pid, childStartIdentity))
		if cleanupErr != nil {
			return e.fail("mount", fmt.Errorf("%w; cleanup: %v; incomplete operation intent preserved at %s; see %s", err, cleanupErr, operation.intentPath, logPath))
		}
		return e.fail("mount", fmt.Errorf("%w; the exact child was reaped, but mount/attach absence was not proven; operation intent preserved at %s; see %s", err, operation.intentPath, logPath))
	case <-time.After(3 * time.Minute):
		cleanupErr := terminateSpawnedMount(cmd, childStartIdentity)
		cleanupErr = errors.Join(cleanupErr, operation.preserveCleanupIntent(cmd.Process.Pid, childStartIdentity))
		if cleanupErr != nil {
			return e.fail("mount", fmt.Errorf("mount did not become ready within 3 minutes; exact-child cleanup failed: %v; incomplete operation intent preserved at %s (log: %s)", cleanupErr, operation.intentPath, logPath))
		}
		return e.fail("mount", fmt.Errorf("mount did not become ready within 3 minutes; the exact spawned session was terminated and reaped, but mount/attach absence was not proven; operation intent preserved at %s (log: %s)", operation.intentPath, logPath))
	}
	if !ready.OK {
		cleanupErr := terminateSpawnedMount(cmd, childStartIdentity)
		if ready.Cleaned {
			cleanupErr = errors.Join(cleanupErr, operation.close(true))
		} else {
			cleanupErr = errors.Join(cleanupErr, operation.preserveCleanupIntent(cmd.Process.Pid, childStartIdentity))
		}
		if cleanupErr != nil {
			return e.fail("mount", fmt.Errorf("%s; cleanup: %v; incomplete operation intent preserved at %s (log: %s)", ready.Error, cleanupErr, operation.intentPath, logPath))
		}
		if ready.Cleaned {
			return e.fail("mount", fmt.Errorf("%s; the exact child was reaped and its failed startup transaction was fully rolled back (log: %s)", ready.Error, logPath))
		}
		return e.fail("mount", fmt.Errorf("%s; the exact child was reaped, but mount/attach absence was not proven; operation intent preserved at %s (log: %s)", ready.Error, operation.intentPath, logPath))
	}
	_ = cmd.Process.Release()
	if o.common.jsonOut {
		return e.printJSON(ready)
	}
	fmt.Fprintf(e.stdout, "mounted %s at %s (%s, pid %d)\n", volumeBranchLabel(ready.VolumeID, ready.Branch), ready.MountPath, ready.Strategy, ready.PID)
	if ready.LocalRoutesPerMachine {
		// The user asked for routing only this machine knows about. It is
		// allowed here solely because the volume declares none, and the
		// asymmetry it creates is worth saying out loud rather than burying
		// in a log the user has no reason to open.
		fmt.Fprintf(e.stderr, "portablefs mount: warning: %s is served from machine-local disk on THIS machine only (--local-dir); peers still treat those paths as shared. Declare them in %s so every machine routes identically.\n",
			strings.Join(ready.LocalRoutes, ", "), localdirs.VolumeConfigPath)
	}
	fmt.Fprintf(e.stdout, "unmount with: portablefs umount %s\n", ready.MountPath)
	return 0
}

func terminateUnidentifiedStartedMount(cmd *exec.Cmd, operation *mountOperation, identityErr error) error {
	killErr := cmd.Process.Kill()
	waitErr := cmd.Wait()
	if errors.Is(killErr, os.ErrProcessDone) {
		killErr = nil
	}
	return errors.Join(
		fmt.Errorf(
			"record spawned mount process identity: %w; the child was terminated, but its operation intent was preserved at %s for explicit exact reconciliation",
			identityErr, operation.intentPath,
		),
		killErr,
		waitErr,
	)
}

func releaseStartupAccessLease(keeper *leaseKeeper, operationID string) error {
	if keeper == nil {
		return nil
	}
	releaseCtx, cancelRelease := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelRelease()
	if err := keeper.releaseWithOperation(releaseCtx, operationID); err != nil {
		return fmt.Errorf("release startup access lease: %w", err)
	}
	return nil
}

func detachFUSEWithPreparedIntent(operation *mountOperation, pid int, identity string, detach func() error) error {
	if operation == nil || detach == nil {
		return fmt.Errorf("missing FUSE detach transaction")
	}
	prior, err := readMountIntent(operation.intentPath, operation.mountPath)
	if err != nil {
		return fmt.Errorf("read pre-detach intent: %w", err)
	}
	if prior == nil {
		return fmt.Errorf("pre-detach intent is missing")
	}
	if prior.Phase == "force-prepared" {
		// The explicit force request and durable journal-park proof already
		// form the recovery barrier. Preserve that stronger fact until exact
		// detach and resource finalization complete.
		return detach()
	}
	if err := operation.writeIntent("drain-prepared", pid, identity); err != nil {
		return fmt.Errorf("publish drain-prepared intent: %w", err)
	}
	if err := detach(); err != nil {
		operationIdentity, identityErr := processStartIdentity(os.Getpid())
		if identityErr == nil {
			prior.OperationOwnerPID = os.Getpid()
			prior.OperationOwnerStartIdentity = operationIdentity
			prior.UpdatedAtMs = time.Now().UnixMilli()
		}
		rollbackErr := writeMountIntentRecord(operation.intentPath, prior)
		abortErr := func() error {
			if identityErr != nil {
				return fmt.Errorf("record drain-prepared abort identity: %w", identityErr)
			}
			if rollbackErr != nil {
				return fmt.Errorf("durably abort drain-prepared intent: %w", rollbackErr)
			}
			return nil
		}()
		if rollbackErr != nil {
			return &fusePreparedAbortFailFrozenError{cause: errors.Join(err, abortErr)}
		}
		return errors.Join(err, abortErr)
	}
	return nil
}

type fusePreparedAbortFailFrozenError struct {
	cause error
}

func (e *fusePreparedAbortFailFrozenError) Error() string { return e.cause.Error() }
func (e *fusePreparedAbortFailFrozenError) Unwrap() error { return e.cause }
func (e *fusePreparedAbortFailFrozenError) KeepWritebackFrozen() bool {
	return true
}

func terminateSpawnedMount(cmd *exec.Cmd, expectedStart string) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return nil
	case <-time.After(250 * time.Millisecond):
	}
	current, err := processStartIdentity(cmd.Process.Pid)
	if err != nil || current != expectedStart {
		return fmt.Errorf("refusing to signal pid %d because its start identity changed (got %q, want %q): %v", cmd.Process.Pid, current, expectedStart, err)
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		return fmt.Errorf("terminate spawned mount process group %d: %w", cmd.Process.Pid, err)
	}
	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
	}
	current, err = processStartIdentity(cmd.Process.Pid)
	if err != nil || current != expectedStart {
		return fmt.Errorf("refusing forced cleanup of pid %d because its start identity changed (got %q, want %q): %v", cmd.Process.Pid, current, expectedStart, err)
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return fmt.Errorf("kill spawned mount process group %d: %w", cmd.Process.Pid, err)
	}
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("spawned mount process %d did not exit after SIGKILL", cmd.Process.Pid)
	}
}

func (o *mountOpts) resolveMountToken(getenv func(string) string) string {
	if o.mountToken != "" {
		return o.mountToken
	}
	return getenv(mountTokenEnv)
}

// sessionTokenSource serves the current lease's data-plane credential to
// reconnect handshakes. Only the lease keeper may advance it; rejection is a
// terminal visible failure, never a trigger to mint a replacement lease.
type sessionTokenSource struct {
	mu sync.Mutex
	// seq is the source's MONOTONE state sequence, advanced by every accepted
	// credential change. It is what makes delivery ordered; see deliver.
	seq         uint64
	token       string
	expiresAtMs int64
	dataPlanes  []*boundDataPlane

	// deliverMu serializes DELIVERY, and is never held together with mu.
	// Installation reaches the data plane's own locks and opens a credential
	// generation, neither of which may happen under the source lock — and two
	// installations that overlap are precisely the defect this serialization
	// closes, so the delivery pass needs a lock of its own.
	deliverMu sync.Mutex
}

// boundDataPlane is one registered data plane and the highest SOURCE sequence
// installed into it. delivered and seeded are guarded by deliverMu alone; the
// slice they live in is guarded by mu.
type boundDataPlane struct {
	inst       credentialInstaller
	delivered  uint64
	seeded     bool
	seedToken  string
	seedExpiry int64
}

// credentialInstaller is a data plane a rotated lease credential must reach.
// *clientcore.Volume is the production implementation.
type credentialInstaller interface {
	InstallCredential(token string, expiresAtMs int64)
}

// bindDataPlane registers a data plane that every FUTURE rotation is installed
// into, and repairs the one gap the registration itself opens.
//
// It hangs off the token SOURCE deliberately. The rotated credential used to
// reach the data plane through a per-strategy hook, and the FUSE branch simply
// never stored one — a mistake nothing could catch, because a missing hook
// looks exactly like a healthy mount. Every strategy's lease keeper already
// writes every renewal through setToken, so binding here leaves no per-strategy
// step to forget.
//
// seedToken/seedExpiry are the credential the caller ALREADY seeded this data
// plane with (the one its construction handshake proved). A data plane that is
// still current is left alone: installing a credential it has already proved
// would open a generation that completed handshake can no longer speak for, and
// nothing in a quiet mount would ever go on to prove it. A rotation that landed
// in the window between that seed and this call is installed at once — the data
// plane is holding a superseded credential and nothing else would tell it.
func (t *sessionTokenSource) bindDataPlane(inst credentialInstaller, seedToken string, seedExpiry int64) {
	t.mu.Lock()
	t.dataPlanes = append(t.dataPlanes, &boundDataPlane{
		inst: inst, seeded: true, seedToken: seedToken, seedExpiry: seedExpiry,
	})
	t.mu.Unlock()
	// The bind runs through the SAME ordered delivery pass a rotation does. It
	// used to install from its own read of the source, which is a second,
	// unordered writer into the data plane: a rotation racing the bind could be
	// overtaken by the bind's older read, or vice versa, and the data plane was
	// left holding whichever arrived last rather than whichever is current.
	t.deliver()
}

// setToken installs a fresh data-plane credential (the lease keeper pushes
// renewed/rotated tokens here so reconnect handshakes always use the live one)
// and PUSHES it into every bound data plane.
//
// The push is the point. Storing the token here used to be the whole of a FUSE
// renewal: the data plane read this source live on each handshake, so it went
// on offering the NEW token under the OLD credential generation's tag. No
// generation was opened, so nothing verified the replacement; the old
// generation stayed "verified" on evidence a superseded credential had earned;
// and no pending state was ever entered, so the credential's own stated expiry
// could not harden it either. A mount rotated onto a dead credential reported
// itself perfectly healthy.
// ── AND WHY DELIVERY CARRIES A SEQUENCE ─────────────────────────────────────
//
// The push used to be "store under the lock, copy the installers, install after
// unlocking", and that loses the ORDER the source establishes. Two rotations
// overlap — T2 blocks between the unlock and its install while T3 stores and
// installs — and T2's install lands LAST: the source says T3, the data plane
// offers T2's credential under the newest generation's tag, and verification
// then faithfully verifies the wrong credential and latches a verdict about it.
// Nothing repairs that, because from every layer's point of view the
// installation succeeded. Atomicity inside Client.InstallCredential cannot help;
// the order was already lost above it.
//
// So the source carries a monotone sequence and delivery is a serialized pass
// that always installs the source's CURRENT state, skipping any data plane
// already at that sequence. An overtaken delivery therefore finds the newer
// state and installs it (or finds it already installed and does nothing); it
// can never install an older one.
func (t *sessionTokenSource) setToken(token string, expiresAtMs int64) {
	t.mu.Lock()
	t.seq++
	t.token = token
	t.expiresAtMs = expiresAtMs
	t.mu.Unlock()
	t.deliver()
}

// deliver installs the source's current credential into every bound data plane
// that has not already received this sequence.
//
// It runs with mu RELEASED — installation reaches the data plane's own locks and
// opens a credential generation — and under deliverMu, which orders the passes
// against each other. Reading the source state INSIDE that serialization is
// what makes an obsolete delivery impossible rather than merely unlikely: a
// pass that was overtaken re-reads the newer state and either installs it or
// finds the sequence already delivered.
func (t *sessionTokenSource) deliver() {
	t.deliverMu.Lock()
	defer t.deliverMu.Unlock()
	t.mu.Lock()
	seq, token, expiresAtMs := t.seq, t.token, t.expiresAtMs
	planes := append([]*boundDataPlane(nil), t.dataPlanes...)
	t.mu.Unlock()
	for _, plane := range planes {
		if plane.delivered >= seq && !plane.seeded {
			continue
		}
		seeded := plane.seeded
		plane.seeded = false
		plane.delivered = seq
		if seeded && token == plane.seedToken && expiresAtMs == plane.seedExpiry {
			// The data plane's construction handshake already proved exactly this
			// credential. Installing it would open a generation that completed
			// handshake can no longer speak for, and nothing in a quiet mount
			// would ever go on to prove it. A rotation that landed between the
			// seed and the bind does NOT match, and is installed at once.
			continue
		}
		plane.inst.InstallCredential(token, expiresAtMs)
	}
}

// get serves the live credential AND the deadline its issuer stated for it.
//
// It used to drop the expiry on the floor, which is how the mount ended up
// with an unbounded UNPROVEN credential state: the deadline existed one layer
// up the whole time (leaseState.ExpiresAtMs, carried into this very struct by
// setToken) and simply never reached the client that needed it. Handing it
// down is what lets an unproven credential stop being unproven — past the
// lease's own expiry it hardens to expired, on the lease's terms rather than
// on some retry budget invented in the data plane.
//
// The env-token fallback states NO deadline (0). A static VCS_AUTH_TOKEN is
// not a lease: nothing about it expires, so nothing about it may harden.
func (t *sessionTokenSource) get() (string, int64) {
	t.mu.Lock()
	token := t.token
	expiresAtMs := t.expiresAtMs
	t.mu.Unlock()
	if token != "" {
		return token, expiresAtMs
	}
	// Direct --addr mounts without a token: the VCS_AUTH_TOKEN environment
	// variable authenticates the data plane.
	return os.Getenv("VCS_AUTH_TOKEN"), 0
}

// resolveVolumeTeamID looks up the volume's tenant id through the volume API
// so manager requests can carry it as teamId (journal-native production
// managers key authorities and leases by the tenant namespace and require
// it). Split deployments fail closed when the tenant cannot be resolved.
//
// Tenancy ownership is deployment-shaped. A UNIFIED control plane (the hosted
// broker, where the manager and API share an origin) derives tenancy from the
// credential and rejects a client-asserted teamId, so the client must not send
// one. A SPLIT self-host deployment (a distinct volume-api and authority-
// manager) has no server-side tenancy authority on the manager, so the client
// resolves the volume's tenant and passes it through. The origin comparison is
// exactly that distinction, not a heuristic.
func (e *cmdEnv) resolveVolumeTeamID(s settings, volumeID, branch string) (string, error) {
	unified, err := sameOrigin(s.managerURL, s.apiURL)
	if err != nil {
		return "", err
	}
	if unified {
		return "", nil
	}
	if s.apiURL == "" || s.apiToken == "" {
		return "", fmt.Errorf("split manager/API deployment requires an authenticated API endpoint to resolve tenant ownership")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Mode-agnostic metadata resolution is strict: an absent tenant identity
	// is an error and is never converted into an unscoped manager request.
	teamID, err := e.apiClient(s.apiURL, s.apiToken).resolveVolumeTenant(ctx, volumeID, branch)
	if err != nil {
		return "", err
	}
	if teamID == "" {
		return "", fmt.Errorf("split deployment returned no tenant identity for %s@%s", volumeID, branch)
	}
	return teamID, nil
}

// sameOrigin reports whether two endpoint URLs share a scheme+host+port, i.e.
// one control-plane origin fronts both the API and the manager. An empty
// manager URL means the manager defaulted to the API origin (unified).
func sameOrigin(managerURL, apiURL string) (bool, error) {
	apiOrigin, err := canonicalOrigin(apiURL)
	if err != nil {
		return false, fmt.Errorf("invalid API origin: %w", err)
	}
	if managerURL == "" {
		return true, nil
	}
	managerOrigin, err := canonicalOrigin(managerURL)
	if err != nil {
		return false, fmt.Errorf("invalid manager origin: %w", err)
	}
	return managerOrigin == apiOrigin, nil
}

func canonicalOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("endpoint %q must be an absolute URL with no userinfo", raw)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("endpoint %q has unsupported scheme %q", raw, parsed.Scheme)
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portValue, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portValue == 0 {
		return "", fmt.Errorf("endpoint %q has invalid port %q", raw, port)
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(parsed.Hostname()), port), nil
}

// runMountForeground performs the actual mount in this process: resolve the
// session, pick a strategy, attach, record state, then serve until unmounted.
func (e *cmdEnv) runMountForeground(o *mountOpts, volumeID, mountPath, stateDir string, operation *mountOperation) int {
	defer func() {
		if operation != nil {
			if err := operation.close(false); err != nil {
				fmt.Fprintf(e.stderr, "portablefs mount: release mount operation lock: %v; cleanup intent remains at %s\n", err, operation.intentPath)
			}
		}
	}()
	var readyPipe *os.File
	if o.readyFD > 0 {
		readyPipe = os.NewFile(uintptr(o.readyFD), "portablefs-ready")
	}
	// keeper is always nil on the v3 path: a mount capability is single-use
	// and never renewed, so there is no lease to keep. The scaffolding stays
	// because unmount reconciliation of RECORDED v2 mounts still releases
	// their leases; it goes when the v2 architecture is deleted.
	var keeper *leaseKeeper
	leaseCleanupSafe := true
	leaseCleanupAttempted := false
	startupCleanupComplete := false
	report := func(ready mountReady) {
		line, _ := json.Marshal(ready)
		if readyPipe != nil {
			_, _ = readyPipe.Write(append(line, '\n'))
			_ = readyPipe.Close()
			return
		}
		if o.common.jsonOut {
			_, _ = e.stdout.Write(append(line, '\n'))
		} else if ready.OK {
			fmt.Fprintf(e.stdout, "mounted %s at %s (%s); Ctrl-C unmounts\n", volumeBranchLabel(ready.VolumeID, ready.Branch), ready.MountPath, ready.Strategy)
		}
	}
	failReady := func(err error) int {
		if leaseCleanupSafe && !startupCleanupComplete && operation != nil {
			var releaseErr error
			if keeper != nil && !leaseCleanupAttempted {
				leaseCleanupAttempted = true
				releaseErr = releaseStartupAccessLease(keeper, operation.leaseReleaseOp)
			} else if operation.managerURL != "" && !leaseCleanupAttempted {
				leaseCleanupAttempted = true
				intent, readErr := readMountIntent(operation.intentPath, operation.mountPath)
				if readErr != nil {
					releaseErr = readErr
				} else {
					releaseErr = e.releaseIntentAccessLease(intent)
				}
			}
			if releaseErr == nil {
				if closeErr := operation.close(true); closeErr != nil {
					err = errors.Join(err, fmt.Errorf("finalize clean failed startup: %w", closeErr))
				} else {
					operation = nil
					startupCleanupComplete = true
				}
			} else {
				err = errors.Join(err, releaseErr)
			}
		}
		report(mountReady{OK: false, Cleaned: startupCleanupComplete, Error: err.Error()})
		if readyPipe != nil {
			fmt.Fprintf(e.stderr, "portablefs mount: %v\n", err)
			return 1
		}
		return e.fail("mount", err)
	}

	lifecycleStateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return failReady(err)
	}
	lifecycleGuard, err := mountlifecycle.AcquireShared(lifecycleStateDir)
	if err != nil {
		return failReady(fmt.Errorf("acquire mount lifecycle guard: %w; an installation or update may be in progress", err))
	}
	defer lifecycleGuard.Close()
	ownershipGuard, err := mountlifecycle.AcquireNamedExclusive(
		lifecycleStateDir,
		mountOwnershipLockName(volumeID, o.branch),
	)
	if err != nil {
		return failReady(fmt.Errorf("%s already has a mount startup or live session on this machine: %w", volumeBranchLabel(volumeID, o.branch), err))
	}
	defer ownershipGuard.Close()
	if err := e.validateMountOwnership(stateDir, volumeID, o.branch, mountPath); err != nil {
		return failReady(err)
	}

	strategy, err := resolveStrategy(o.strategy, runtime.GOOS)
	if err != nil {
		return failReady(err)
	}
	hostFacts := mounthost.Check(mounthost.Transport(strategy))
	if hostFacts.State == mounthost.Blocked {
		return failReady(mountHostBlockedError(hostFacts))
	}
	mountMechanism := "fskit-system"
	fuseHelperPath := ""
	if strategy == "fuse" {
		mountMechanism = hostFacts.MountMechanism
		fuseHelperPath = hostFacts.HelperPath
		if mountMechanism != "direct" && mountMechanism != "helper" {
			return failReady(fmt.Errorf("host inventory did not select one deterministic FUSE mount mechanism"))
		}
	}

	// The direct v3 credential shape is the only one a mount accepts: the
	// retained manager mints v2 leases, which cannot admit a v3 authority
	// session, and there is deliberately no fallback to the legacy clientcore
	// engine. cmdMount validates the same shape in the parent; this repeats it
	// because the daemonized child is its own process and must fail closed on
	// its own evidence.
	authorityURL := o.addr
	transport, err := validateDirectV3MountOpts(o, e.getenv)
	if err != nil {
		return failReady(err)
	}
	mountToken := o.resolveMountToken(e.getenv)
	clientIdentity, err := loadClientTLSIdentity(o.clientCertPath, o.clientKeyPath)
	if err != nil {
		return failReady(err)
	}
	dataPlaneCAPath, dataPlaneCASHA256, err := transport.materializePrivateCA(stateDir)
	if err != nil {
		return failReady(err)
	}

	// v3 routing is volume-wide state adopted from the declaration at attach.
	// The one --local-dir state operation left is the documented clear.
	if o.noLocalDirs {
		if err := writePersistedLocalDirs(stateDir, volumeID, o.branch, mountPath, nil); err != nil {
			return failReady(fmt.Errorf("clear persisted local dirs: %w", err))
		}
	}
	// Re-run the complete table-first target validation immediately before
	// mount side effects. The parent validation may have happened minutes
	// earlier while resolving credentials or spawning this foreground child.
	mountTarget, mountTargetIdentity, err := openValidatedMountTarget(stateDir, mountPath)
	if err != nil {
		return failReady(err)
	}
	// THE PIN IS FOR THE VALIDATE→MOUNT WINDOW, AND FOR NOTHING AFTER IT.
	//
	// openValidatedMountTarget returns an O_DIRECTORY fd on the mount point so
	// the dev/ino identity it captured cannot be defeated by inode reuse
	// between here and the moment the kernel mount lands: revalidatePinnedMount
	// Target reopens BY PATH and compares identities, and holding the original
	// inode open is what makes that comparison mean "the same directory" rather
	// than "a directory with the same numbers".
	//
	// The instant the mount is established that fd stops referring to the
	// directory this process validated and starts referring to the COVERED
	// vnode underneath a live mount — and an open fd on a covered vnode is
	// precisely what unmount(2) answers EBUSY for. Held to the end of
	// runMountForeground (a plain `defer`, as it was), it made this supervisor
	// the thing that blocked the unmount of its own mount: `umount` refused,
	// `umount --force` refused, and the only recovery was to kill the
	// supervisor — the product's own process — by hand.
	//
	// So the release is EXPLICIT, at the point where the pin's purpose is
	// discharged, and the defer remains only as the failure-path backstop.
	// releaseMountTargetPin is idempotent so the two never double-close.
	var mountTargetPinOnce sync.Once
	releaseMountTargetPin := func() {
		mountTargetPinOnce.Do(func() { _ = mountTarget.Close() })
	}
	defer releaseMountTargetPin()
	processIdentity, err := processStartIdentity(os.Getpid())
	if err != nil {
		return failReady(fmt.Errorf("record exact mount process identity: %w", err))
	}
	mountInstanceID, err := mountid.NewMountInstance()
	if err != nil {
		return failReady(fmt.Errorf("generate stable mount instance identity: %w", err))
	}
	// The engine is recorded beside the strategy: the strategy names the
	// platform transport (fuse/fskit), the engine names the data plane behind
	// it, and unmount picks its teardown from the pair. Every new mount is a
	// v3 engine; an empty engine on an old record means the retired clientcore
	// path.
	engine := mountEngineFuseV3
	if strategy == "fskit" {
		engine = mountEngineDaemonV3
	}
	operation.engine = engine
	operation.mountInstanceID = mountInstanceID
	operation.mountTarget = mountTargetIdentity
	operation.mountMechanism = mountMechanism
	operation.fuseHelperPath = fuseHelperPath
	operation.startedAtMs = time.Now().UnixMilli()
	operation.authorityURL = authorityURL
	operation.transportMode = transport.Mode
	operation.transportServer = transport.ServerName
	operation.dataPlaneCAPath = dataPlaneCAPath
	operation.dataPlaneCAHash = dataPlaneCASHA256
	if err := operation.writeIntent("mounting", os.Getpid(), processIdentity); err != nil {
		return failReady(err)
	}

	state := mountState{
		MountPath:                     mountPath,
		VolumeID:                      volumeID,
		Branch:                        o.branch,
		PID:                           os.Getpid(),
		ProcessStartIdentity:          processIdentity,
		Strategy:                      strategy,
		Engine:                        engine,
		MountInstanceID:               mountInstanceID,
		MountTargetDevice:             mountTargetIdentity.device,
		MountTargetInode:              mountTargetIdentity.inode,
		AuthorityURL:                  authorityURL,
		StartedAtMs:                   operation.startedAtMs,
		DataPlaneCAPath:               dataPlaneCAPath,
		DataPlaneCASHA256:             dataPlaneCASHA256,
		DataPlaneTransport:            transport.Mode,
		DataPlaneServerName:           transport.ServerName,
		MountMechanism: mountMechanism,
		FUSEHelperPath: fuseHelperPath,
	}
	removePublishedState := func() error {
		current, err := readMountState(stateDir, mountPath)
		if err != nil {
			return fmt.Errorf("inspect failed-startup mount state: %w", err)
		}
		if current == nil {
			return nil
		}
		if current.MountInstanceID != state.MountInstanceID ||
			current.VolumeID != state.VolumeID || current.Branch != state.Branch {
			return fmt.Errorf("failed-startup mount state identity changed; refusing to remove it")
		}
		if err := removeMountState(stateDir, mountPath); err != nil {
			return fmt.Errorf("remove failed-startup mount state: %w", err)
		}
		return nil
	}
	publishCleanedResourcesAndFinalizeLease := func() error {
		if keeper != nil {
			lease := keeper.snapshot()
			operation.accessLease = &lease
		}
		// This unconditional checkpoint bridges exact local teardown to
		// state deletion for both manager-backed and direct --addr mounts.
		if err := operation.writeIntent("resources-cleaned", 0, ""); err != nil {
			return fmt.Errorf("publish durable resources-cleaned fact: %w", err)
		}
		if keeper == nil {
			return nil
		}
		leaseCleanupAttempted = true
		if err := releaseStartupAccessLease(keeper, operation.leaseReleaseOp); err != nil {
			return err
		}
		if err := operation.writeIntent("lease-released", 0, ""); err != nil {
			return fmt.Errorf("publish durable released-lease fact: %w", err)
		}
		return nil
	}
	finalizeCleanedStartup := func(cause error) int {
		// Callers enter only after exact kernel/attach cleanup. Lease release
		// is part of the same transaction and precedes deletion of either
		// recovery anchor.
		if err := publishCleanedResourcesAndFinalizeLease(); err != nil {
			return failReady(errors.Join(cause, err))
		}
		if err := removePublishedState(); err != nil {
			return failReady(errors.Join(cause, err))
		}
		if err := operation.close(true); err != nil {
			return failReady(errors.Join(cause, fmt.Errorf("remove verified-clean startup intent: %w", err)))
		}
		operation = nil
		startupCleanupComplete = true
		return failReady(cause)
	}
	ready := mountReady{
		OK: true, PID: os.Getpid(), Strategy: strategy,
		MountPath: mountPath, VolumeID: volumeID, Branch: o.branch,
	}

	switch strategy {
	case "fuse":
		if err := revalidatePinnedMountTarget(mountPath, mountTargetIdentity); err != nil {
			return failReady(err)
		}
		leaseCleanupSafe = false
		// The v3 engine. The mount capability is single-use — its nonce is
		// spent by the attach below — so from here every failure path must
		// tear down exactly, never retry the attach.
		m, err := mountFUSEv3(fuseV3Config{
			addr: authorityURL, token: mountToken, transport: transport,
			identity: clientIdentity, coherence: o.coherence,
			volumeID: volumeID, mountPath: mountPath, mountInstanceID: mountInstanceID,
			backingRoot: localDirsBackingRoot(stateDir, volumeID),
			noLocalDirs: o.noLocalDirs,
		})
		if err != nil {
			return failReady(err)
		}
		kernelMountID, err := captureFUSEKernelMountID(mountPath, mountInstanceID)
		if err != nil {
			// A path-based unmount is unsafe when the kernel table is absent,
			// foreign, or stacked. Preserve the rich mounting intent and let
			// explicit reconciliation classify the exact mount.
			return failReady(err)
		}
		// The kernel mount is established and identified, so the pin's
		// validate→mount window is closed. It is a covered-vnode reference from
		// here on and would answer EBUSY to this mount's own unmount; see the
		// pin's definition in runMountForeground.
		releaseMountTargetPin()
		state.KernelMountID = kernelMountID
		operation.kernelMountID = kernelMountID
		cleanupMountedFUSE := func(cause error) int {
			// Startup rollback runs the same exact teardown as a live unmount:
			// kernel detach, then session release with its recorded verdict.
			if unmountErr := m.Unmount(); unmountErr != nil {
				return failReady(errors.Join(cause, fmt.Errorf("transactional startup FUSE unmount failed: %w", unmountErr)))
			}
			m.Wait()
			if teardownErr := m.Close(); teardownErr != nil {
				return failReady(errors.Join(cause, fmt.Errorf("close failed-startup FUSE resources: %w", teardownErr)))
			}
			return finalizeCleanedStartup(cause)
		}
		if err := operation.writeIntent("kernel-mounted", os.Getpid(), processIdentity); err != nil {
			return cleanupMountedFUSE(err)
		}
		// Publish what this machine now routes for the volume, so prune-local
		// can tell live backing from orphaned backing even when nothing is
		// mounted. The revision is the VOLUME declaration's — adopted from the
		// attach protocol, never a per-machine derivative: it is what the
		// authority pins this attach to.
		if err := writeLocalRoutesRecord(stateDir, volumeID, m.routes, time.Now().UnixMilli()); err != nil {
			fmt.Fprintf(e.stderr, "portablefs mount: persist active machine-local routes: %v\n", err)
		}
		state.LocalRoutes = m.routes.rules.Patterns()
		state.LocalRouteRevision = m.routes.revision
		if !m.routes.rules.Empty() {
			state.LocalBackingRoot = m.backing
		}
		ready.LocalRoutes = state.LocalRoutes
		ready.LocalRouteRevision = state.LocalRouteRevision
		if err := writeMountState(stateDir, state); err != nil {
			return cleanupMountedFUSE(err)
		}
		if err := operation.writeIntent("live", os.Getpid(), processIdentity); err != nil {
			return cleanupMountedFUSE(err)
		}
		if err := operation.close(false); err != nil {
			return cleanupMountedFUSE(fmt.Errorf("release mount operation lock before readiness: %w", err))
		}
		report(ready)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			for range sig {
				// EBUSY keeps the mount up; the next signal retries. There is no
				// write-back tail in v3 — every acknowledged write is already
				// durable at the authority — so there is nothing to park and no
				// forced variant of this teardown.
				if err := m.Unmount(); err != nil {
					log.Printf("portablefs mount: shutdown request refused: %v", err)
					continue
				}
				return
			}
		}()
		m.Wait() // returns when the kernel mount is gone (signal or external umount)
		signal.Stop(sig)
		// Close releases the authority session. After an external unmount it
		// also delivers the mount-absence proof; after this supervisor's own
		// Unmount it only reports any recorded fatal session verdict.
		if waitErr := m.Close(); waitErr != nil {
			return e.fail("mount", fmt.Errorf("kernel mount is gone but FUSE teardown did not complete; state and intent were preserved for explicit reconciliation: %w", waitErr))
		}
		if err := publishCleanedResourcesAndFinalizeLease(); err != nil {
			return e.fail("mount", fmt.Errorf("kernel mount is gone but exact resource finalization did not complete; state and intent were preserved: %w", err))
		}
		if err := removeMountState(stateDir, mountPath); err != nil {
			return e.fail("mount", fmt.Errorf("mount is gone but its state record could not be removed: %w", err))
		}
		if err := operation.close(true); err != nil {
			return e.fail("mount", fmt.Errorf("finalize clean mount operation: %w", err))
		}
		operation = nil
		return 0

	case "fskit":
		fskitCfg, err := fskitConfigFromEnv(e.getenv)
		if err != nil {
			return failReady(err)
		}
		operation.fsType = fskitCfg.fsType
		ctl, err := e.ensureFskitDaemon(fskitCfg, filepath.Dir(stateDir))
		if err != nil {
			return failReady(err)
		}
		attachRef, err := mountid.NewAttachRef()
		if err != nil {
			return failReady(fmt.Errorf("generate stable FSKit attach identity: %w", err))
		}
		operation.attachRef = attachRef
		if err := operation.writeIntent("attaching", os.Getpid(), processIdentity); err != nil {
			return failReady(err)
		}
		leaseCleanupSafe = false
		// The daemon-owned v3 attach: portablefsd dials the authority under
		// this exact transport with the mutual-TLS identity below, declares the
		// strict barrier contract, and never exposes the credentials to the
		// FSKit extension. Branch is empty (a v3 volume is branchless) and the
		// clientcore-only options are omitted — the daemon refuses both.
		attachReply, err := ctl.ensureAttachDetailed(fskitEnsureAttachRequest{
			AttachRef:           attachRef,
			VolumeID:            volumeID,
			Branch:              "",
			AuthorityURL:        authorityURL,
			AuthToken:           mountToken,
			DataPlaneTransport:  transport.Mode,
			DataPlaneServerName: transport.ServerName,
			TLSCAPEM:            transport.CAPEM,
			TLSCASHA256:         transport.CASHA256,
			MountPath:           mountPath,
			Options:             fskitAttachOptions{},
			V3: &fskitV3AttachRequest{
				ClientCertPEM:      string(clientIdentity.certPEM),
				ClientKeyPEM:       string(clientIdentity.keyPEM),
				CachedNameCapacity: mountv3.CachedNameCapacity,
				RepairBudgetMillis: uint64(mountv3.RepairBudget / time.Millisecond),
				CachePolicy:        portablefsd.V3CachePolicyMacOS26,
				// The daemon does not join the route adoption protocol, so the
				// revision declared here is the empty rule set's. A volume that
				// declares machine-local routes is refused by the authority with
				// both revisions named; declare the routes' removal or mount it
				// from Linux, which adopts them.
				RoutesRevision: emptyRoutesRevision(),
			},
		})
		if err != nil {
			return failReady(err)
		}
		if attachReply.AttachRef != attachRef {
			return failReady(fmt.Errorf("portablefsd returned attach %s, want durable requested identity %s", attachReply.AttachRef, attachRef))
		}
		if err := operation.writeIntent("attached", os.Getpid(), processIdentity); err != nil {
			if detachErr := ctl.unmountAttach(attachRef); detachErr != nil {
				return failReady(errors.Join(err, fmt.Errorf("exact cleanup detach %s failed: %w", attachRef, detachErr)))
			}
			return finalizeCleanedStartup(err)
		}
		detach := func() error {
			return ctl.unmountAttach(attachRef)
		}
		failAfterAttach := func(cause error) int {
			if err := detach(); err != nil {
				return failReady(errors.Join(cause, fmt.Errorf("exact cleanup detach %s failed: %w", attachRef, err)))
			}
			return finalizeCleanedStartup(cause)
		}
		failAfterKernelMount := func(cause error) int {
			if err := ctl.unmountAttach(attachRef); err != nil {
				return failReady(errors.Join(cause, fmt.Errorf("daemon-owned exact FSKit cleanup for attach %s failed: %w", attachRef, err)))
			}
			return finalizeCleanedStartup(cause)
		}
		if err := fskitPreflight(fskitCfg.frontendSock, attachRef, e.version); err != nil {
			return failAfterAttach(err)
		}
		state.AttachRef = attachRef
		state.FSType = fskitCfg.fsType
		if err := revalidatePinnedMountTarget(mountPath, mountTargetIdentity); err != nil {
			return failAfterAttach(err)
		}
		if err := mountFSKitPath(fskitCfg.fsType, attachRef, mountPath); err != nil {
			present, identityErr := recordedKernelMountPresent(&state)
			if identityErr != nil {
				return failReady(errors.Join(err, fmt.Errorf("classify FSKit mount side effect for attach %s: %w", attachRef, identityErr)))
			}
			if present {
				return failAfterKernelMount(err)
			}
			return failAfterAttach(err)
		}
		if err := operation.writeIntent("kernel-mounted", os.Getpid(), processIdentity); err != nil {
			return failAfterKernelMount(err)
		}
		if err := waitForFSKitRoot(
			mountPath,
			fskitCfg.fsType,
			fskitidentity.ResourcePrefix+attachRef,
			15*time.Second,
		); err != nil {
			return failAfterKernelMount(err)
		}
		// THE MOUNT IS PROVEN; DROP THE PIN BEFORE ANYONE CAN ASK TO UNMOUNT.
		//
		// waitForFSKitRoot has confirmed the exact kernel mount for this attach
		// is present and serving, so the validate→mount window this fd exists to
		// protect is closed. From here on the fd is only a covered-vnode
		// reference, and the one thing it can still do is answer EBUSY to this
		// mount's own unmount. Release it BEFORE readiness is reported, so no
		// unmount request can ever race a live pin. See the pin's definition in
		// runMountForeground.
		releaseMountTargetPin()
		// There is no credential rotation to hand off: the mount capability is
		// single-use, already consumed by the daemon's attach, and a v3 session
		// is never re-authenticated from this supervisor.
		ready.AttachRef = attachRef
		state.LocalDirs = attachReply.LocalDirs
		state.LocalDirsDeclared = attachReply.LocalDirsDeclared
		ready.LocalDirs = attachReply.LocalDirs
		if err := writeMountState(stateDir, state); err != nil {
			return failAfterKernelMount(err)
		}
		if err := operation.writeIntent("live", os.Getpid(), processIdentity); err != nil {
			return failAfterKernelMount(err)
		}
		if err := operation.close(false); err != nil {
			return failAfterKernelMount(fmt.Errorf("release mount operation lock before readiness: %w", err))
		}
		report(ready)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sig)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			shutdownRequested := false
			select {
			case <-sig:
				shutdownRequested = true
			case <-ticker.C:
			}
			present, identityErr := recordedKernelMountPresent(&state)
			if identityErr != nil {
				fmt.Fprintf(e.stderr, "portablefs mount: kernel mount identity changed; refusing detach: %v\n", identityErr)
				continue
			}
			if shutdownRequested && present {
				if err := ctl.unmountAttach(attachRef); err != nil {
					fmt.Fprintf(e.stderr, "portablefs mount: daemon-owned shutdown transaction refused; mount remains live: %v\n", err)
					continue
				}
				present = false
			}
			if present {
				continue
			}
			// External exact unmount is the normal command-driven shutdown:
			// no PID signal is needed. The wrapper observes disappearance,
			// repeats the daemon durability barrier, and exits cooperatively.
			if err := detach(); err != nil {
				fmt.Fprintf(e.stderr, "portablefs mount: detach after kernel unmount refused; attach remains live: %v\n", err)
				continue
			}
			break
		}
		if err := publishCleanedResourcesAndFinalizeLease(); err != nil {
			return e.fail("mount", fmt.Errorf("kernel mount and attach are gone but exact resource finalization did not complete; state and intent were preserved: %w", err))
		}
		if err := removeMountState(stateDir, mountPath); err != nil {
			return e.fail("mount", fmt.Errorf("mount and attach are gone but state could not be removed: %w", err))
		}
		if err := operation.close(true); err != nil {
			return e.fail("mount", fmt.Errorf("finalize clean mount operation: %w", err))
		}
		operation = nil
		return 0

	default:
		return failReady(fmt.Errorf("unknown strategy %q", strategy))
	}
}

// waitForFSKitRoot waits for a kernel-visible mount whose root can answer a
// real filesystem operation. mount(8) may return before the FSKit resource
// has completed loading; reporting readiness in that gap makes the first
// user operation fail even though the mount becomes usable moments later.
func waitForFSKitRoot(mountPath, expectedFSType, expectedSource string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := verifyFSKitMountIdentity(mountPath, expectedFSType, expectedSource); err != nil {
			lastErr = err
		} else {
			remaining := time.Until(deadline)
			if remaining > time.Second {
				remaining = time.Second
			}
			if remaining > 0 {
				if err := probeFSKitRootOnce(mountPath, remaining); err != nil {
					lastErr = err
				} else if err := verifyFSKitMountIdentity(mountPath, expectedFSType, expectedSource); err != nil {
					lastErr = fmt.Errorf("kernel mount identity changed after root probe: %w", err)
				} else {
					return nil
				}
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"FSKit mounted %s but its root did not become usable within %s: %w",
				mountPath, timeout, lastErr,
			)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func cmdUmount(e *cmdEnv, args []string) int {
	fs := newFlagSet("umount")
	var o commonOpts
	var force bool
	var discardRecord bool
	addCommonFlags(fs, &o)
	fs.BoolVar(&force, "force", false, "detach even with an unshipped write-back tail: it parks as a durable recovery job (its ID is printed) for verified exact replay on the next attach")
	fs.BoolVar(&discardRecord, "discard-record", false, "discard this mount's bookkeeping after proving its kernel mount, owner process, and daemon attach are all gone; it unmounts nothing and refuses if any of them survives")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("umount", err)
	}
	if len(positionals) != 1 {
		return e.usageError("umount", fmt.Errorf("expected exactly one mount path"))
	}
	mountPath, err := canonicalMountPath(positionals[0])
	if err != nil {
		return e.fail("umount", err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		return e.fail("umount", err)
	}
	operation, err := acquireMountOperation(stateDir, mountPath, "", "", "")
	if err != nil {
		return e.fail("umount", err)
	}
	defer func() {
		if operation != nil {
			if err := operation.close(false); err != nil {
				fmt.Fprintf(e.stderr, "portablefs umount: release mount operation lock: %v; cleanup intent remains at %s\n", err, operation.intentPath)
			}
		}
	}()
	finalize := func() error {
		err := operation.close(true)
		operation = nil
		return err
	}
	lifecycleStateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return e.fail("umount", err)
	}
	lifecycleGuard, err := mountlifecycle.AcquireShared(lifecycleStateDir)
	if err != nil {
		return e.fail("umount", fmt.Errorf("acquire mount lifecycle guard: %w; an installation or update may be in progress", err))
	}
	defer lifecycleGuard.Close()
	st, err := readMountState(stateDir, mountPath)
	if err != nil && !discardRecord {
		return e.fail("umount", fmt.Errorf("recorded mount state is invalid; nothing was unmounted: %w", err))
	}
	if discardRecord {
		if force {
			return e.usageError("umount", fmt.Errorf("--discard-record and --force are different operations: --force detaches a live mount, --discard-record only removes bookkeeping whose resources are already gone"))
		}
		return e.discardMountRecord(&o, stateDir, mountPath, st, operation, finalize)
	}
	if st != nil {
		hydrateMountOperationFromState(operation, st)
	}
	if st != nil && operation.prior != nil &&
		(operation.prior.Phase == "drain-prepared" ||
			operation.prior.Phase == "force-requested" ||
			operation.prior.Phase == "force-prepared" ||
			operation.prior.Phase == "resources-cleaned" ||
			operation.prior.Phase == "lease-released") {
		resumePhase := operation.prior.Phase
		if err := verifyCleanupIntentMatchesState(operation.prior, st); err != nil {
			return e.fail("umount", fmt.Errorf("cleaned-resource finalization identity mismatch: %w; state and intent were preserved", err))
		}
		ownerLive := mountIntentOperationOwnerMatches(operation.prior)
		advanceForce, retryErr := preparedFUSERetryDecision(resumePhase, ownerLive, force, st.ForceParkAcknowledged)
		if retryErr != nil {
			return e.fail("umount", fmt.Errorf("%w (owner pid %d)", retryErr, operation.prior.OperationOwnerPID))
		}
		if advanceForce {
			if err := operation.writeIntent("force-requested", st.PID, st.ProcessStartIdentity); err != nil {
				return e.fail("umount", fmt.Errorf("advance fail-frozen drain to durable force request: %w", err))
			}
			resumePhase = "force-requested"
		}
		if resumePhase == "drain-prepared" ||
			resumePhase == "force-requested" ||
			resumePhase == "force-prepared" {
			if st.Strategy != "fuse" {
				return e.fail("umount", fmt.Errorf("%s intent is valid only for an exact FUSE detach", resumePhase))
			}
			if resumePhase == "force-requested" && !st.ForceParkAcknowledged {
				if _, err := e.forceParkFUSEMount(stateDir, st); err != nil {
					return e.fail("umount", fmt.Errorf("resume durable FUSE force request: %w", err))
				}
			}
			present, err := recordedKernelMountPresent(st)
			if err != nil {
				return e.fail("umount", fmt.Errorf("classify %s FUSE mount: %w", resumePhase, err))
			}
			if present {
				if err := platformUnmountRecorded(st); err != nil {
					stillPresent, classifyErr := recordedKernelMountPresent(st)
					if classifyErr != nil || stillPresent {
						return e.fail("umount", errors.Join(
							fmt.Errorf("resume exact %s FUSE detach: %w", resumePhase, err),
							classifyErr,
						))
					}
				}
			}
			if mountProcessMatches(st) {
				if err := stopMountDaemon(st); err != nil {
					return e.fail("umount", fmt.Errorf("stop %s FUSE owner: %w", resumePhase, err))
				}
			}
			if err := publishResourcesCleanedIntent(operation, stateDir, mountPath); err != nil {
				return e.fail("umount", fmt.Errorf("publish resumed %s cleanup: %w", resumePhase, err))
			}
		}
		if resumePhase == "drain-prepared" ||
			resumePhase == "force-requested" ||
			resumePhase == "force-prepared" ||
			resumePhase == "resources-cleaned" {
			if err := e.releaseRecordedAccessLease(&o, stateDir, st); err != nil {
				return e.fail("umount", fmt.Errorf("resources are cleaned but access-lease finalization is incomplete; state and intent were preserved: %w", err))
			}
			if err := publishReleasedLeaseIntent(operation, stateDir, mountPath); err != nil {
				return e.fail("umount", fmt.Errorf("publish released-lease finalization: %w", err))
			}
		}
		if err := removeMountState(stateDir, mountPath); err != nil {
			return e.fail("umount", fmt.Errorf("remove state after verified cleaned-resource fact: %w", err))
		}
		if err := finalize(); err != nil {
			return e.fail("umount", fmt.Errorf("finalize verified cleaned-resource intent: %w", err))
		}
		if o.jsonOut {
			return e.printJSON(map[string]any{"mountPath": mountPath, "volumeId": st.VolumeID, "unmounted": true, "tracked": true, "finalizedCleanedResources": true})
		}
		fmt.Fprintf(e.stdout, "finalized cleaned mount transaction for %s (volume %s)\n", mountPath, st.VolumeID)
		return 0
	}
	if st == nil {
		if operation.prior != nil {
			prior := operation.prior
			recoveryJobs, reconcileErr := e.reconcileMountIntent(prior, force)
			if reconcileErr != nil {
				return e.fail("umount", fmt.Errorf("reconcile incomplete %s operation: %w; intent was preserved at %s", prior.Phase, reconcileErr, operation.intentPath))
			}
			if err := finalize(); err != nil {
				return e.fail("umount", fmt.Errorf("finalize reconciled mount intent: %w", err))
			}
			if o.jsonOut {
				return e.printJSON(map[string]any{"mountPath": mountPath, "volumeId": prior.VolumeID, "unmounted": true, "tracked": false, "reconciledIntent": true, "forced": force, "recoveryJobs": recoveryJobs})
			}
			fmt.Fprintf(e.stdout, "reconciled incomplete mount operation for %s\n", mountPath)
			return 0
		}
		untrackedErr := fmt.Errorf("no PortableFS mount state is recorded for %s; refusing an unverified plain unmount", mountPath)
		return e.fail("umount", errors.Join(untrackedErr, finalize()))
	}
	intentPID := st.PID
	if st.ProcessStartIdentity == "" {
		intentPID = 0
	}
	intentPhase := "unmounting"
	if force && st.Strategy == "fuse" && st.Engine != mountEngineFuseV3 {
		// The force phases exist to make write-back parking durable. A v3
		// mount has no journal, so its forced detach is an ordinary unmounting
		// transaction and must never enter the parking protocol.
		intentPhase = "force-requested"
	}
	if err := operation.writeIntent(intentPhase, intentPID, st.ProcessStartIdentity); err != nil {
		return e.fail("umount", fmt.Errorf("recorded mount state cannot publish an exact unmount intent; nothing was unmounted: %w", err))
	}
	mounted, err := recordedKernelMountPresent(st)
	if err != nil {
		return e.fail("umount", fmt.Errorf("kernel mount identity does not match the PortableFS record; refusing drain, signal, or detach: %w", err))
	}
	if !mounted && !mountProcessMatches(st) {
		var recoveryJobs []string
		if st.Strategy == "fskit" && st.AttachRef != "" {
			cfg, cfgErr := fskitConfigFromEnv(e.getenv)
			if cfgErr != nil {
				return e.fail("umount", cfgErr)
			}
			// An unclean exit or reboot can leave the exact attach registry
			// and write-back WAL durable while no daemon process survives.
			// Explicit unmount reconciliation starts the exact installed peer
			// so that peer can reload and drain that preserved transaction.
			ctl, err := e.ensureFskitDaemon(cfg, filepath.Dir(stateDir))
			if err != nil {
				return e.fail("umount", fmt.Errorf("kernel mount is gone and the recorded wrapper identity is not live; exact FSKit attach %s could not be reconciled: %w", st.AttachRef, err))
			}
			attachPresent, inventoryErr := verifyRecordedFskitAttach(ctl, st)
			if inventoryErr != nil {
				return e.fail("umount", fmt.Errorf("verify orphaned FSKit attach %s: %w", st.AttachRef, inventoryErr))
			}
			if force && attachPresent {
				if jobID, err := ctl.forceDetach(st.AttachRef); err != nil {
					return e.fail("umount", fmt.Errorf("force-reconcile FSKit attach %s: %w", st.AttachRef, err))
				} else if jobID != "" {
					recoveryJobs = append(recoveryJobs, jobID)
				}
			} else if attachPresent {
				if err := ctl.unmountRecordedAttach(st); err != nil {
					return e.fail("umount", fmt.Errorf(
						"reconcile orphaned FSKit attach %s: %w; retry with `portablefs umount --force %s` to durably park any offline write-back tail",
						st.AttachRef,
						err,
						mountPath,
					))
				}
			}
		} else if st.Strategy == "fuse" && st.Engine == mountEngineFuseV3 {
			// A v3 FUSE mount holds no write-back tail: acknowledged writes are
			// already durable at the authority. With its kernel mount and exact
			// owner both gone there is nothing to drain, park, or prove, so the
			// record is reconciled directly; the authority fences the abandoned
			// session on its lease.
		} else if force && st.Strategy == "fuse" {
			jobs, parkErr := e.forceParkFUSEMount(stateDir, st)
			if parkErr != nil {
				return e.fail("umount", fmt.Errorf("force-reconcile abandoned FUSE store: %w", parkErr))
			}
			recoveryJobs = append(recoveryJobs, jobs...)
		} else {
			detail := fmt.Sprintf("cannot prove a clean drain for the recorded %s mount because both its exact process owner and kernel mount are gone", st.Strategy)
			if st.Strategy == "fskit" && st.AttachRef == "" {
				detail = "the recorded FSKit mount has no exact attach identity, so PortableFS cannot prove a clean drain"
			}
			if force {
				// A DEAD END NEEDS AN EXIT NAMED ON IT. This is the state the
				// live transcript reached after kill -9 + daemon restart, and it
				// used to end here: no command named, and --discard-record's own
				// refusal pointed back at --force. Both remaining moves are
				// stated, in the order they apply.
				return e.fail("umount", fmt.Errorf(
					"%s; --force cannot durably park a tail without its exact owner/attach, so state and intent were preserved.\n"+
						"Inspect what the local store still holds with\n"+
						"    portablefs recovery list %s\n"+
						"resolve any terminally conflict/corrupt job with\n"+
						"    portablefs recovery resolve %s --all-terminal\n"+
						"and, once nothing owns the path any more, end the bookkeeping with\n"+
						"    portablefs umount --discard-record %s",
					detail, mountPath, mountPath, mountPath))
			}
			return e.fail("umount", fmt.Errorf("%s; nothing was unmounted and state was preserved (retry with `portablefs umount --force %s` only while its exact owner/attach remains available to park any durable recovery tail)", detail, mountPath))
		}
		if err := publishResourcesCleanedIntent(operation, stateDir, mountPath); err != nil {
			return e.fail("umount", fmt.Errorf("mount resources are gone but their durable cleanup fact could not be published; state and intent were preserved: %w", err))
		}
		if err := e.releaseRecordedAccessLease(&o, stateDir, st); err != nil {
			return e.fail("umount", fmt.Errorf("mount resources are gone but access-lease cleanup is incomplete; state and intent were preserved: %w", err))
		}
		if err := publishReleasedLeaseIntent(operation, stateDir, mountPath); err != nil {
			return e.fail("umount", fmt.Errorf("access lease is released but its durable finalization fact could not be published; state and intent were preserved: %w", err))
		}
		if err := removeMountState(stateDir, mountPath); err != nil {
			return e.fail("umount", fmt.Errorf("remove reconciled mount state: %w", err))
		}
		if err := finalize(); err != nil {
			return e.fail("umount", fmt.Errorf("finalize reconciled mount operation: %w", err))
		}
		if o.jsonOut {
			return e.printJSON(map[string]any{"mountPath": mountPath, "volumeId": st.VolumeID, "unmounted": true, "tracked": true, "forced": force, "recoveryJobs": recoveryJobs})
		}
		fmt.Fprintf(e.stdout, "reconciled stale mount state for %s (volume %s); no unrelated pid was signaled\n", mountPath, st.VolumeID)
		return 0
	}

	var forcedJobs []string
	fuseForceCompleted := false
	fskitUnmountCompleted := false
	switch {
	case force:
		switch st.Strategy {
		case "fskit":
			// The daemon must durably park and acknowledge the exact attach
			// before the kernel resource can be removed.
			forcedJobs, err = e.forceDetachForUnmount(st)
			if err != nil {
				return e.fail("umount", err)
			}
			fskitUnmountCompleted = true
		case "fuse":
			if st.Engine == mountEngineFuseV3 {
				// A v3 mount has no journal to park: forced detach is the same
				// exact identity-checked kernel detach with the cooperative
				// drain skipped. The shared platform-unmount step below performs
				// it, and stopMountDaemon then ends the supervisor.
				break
			}
			ownerWasLive := mountProcessMatches(st)
			forcedJobs, err = e.forceParkFUSEMount(stateDir, st)
			if err != nil {
				return e.fail("umount", err)
			}
			// A live owner performs its own exact detach before acknowledging.
			// The abandoned-store path only publishes the durability proof;
			// this operation still owns the subsequent exact kernel detach.
			fuseForceCompleted = ownerWasLive
		default:
			return e.fail("umount", fmt.Errorf("unsupported recorded mount strategy %q", st.Strategy))
		}
	default:
		if st.Strategy == "fuse" && !mountProcessMatches(st) {
			return e.fail("umount", fmt.Errorf("mount process pid %d does not match its recorded start identity (or this older record has no identity), so PortableFS refuses to signal it; nothing was unmounted", st.PID))
		}
		// A NORMAL unmount requires the full drain barrier. Failure aborts
		// with the mount fully alive — never a silently parked tail behind a
		// healthy-looking unmount.
		if mounted && st.Strategy == "fskit" {
			cfg, err := fskitConfigFromEnv(e.getenv)
			if err != nil {
				return e.fail("umount", err)
			}
			ctl, err := e.ensureFskitDaemon(cfg, filepath.Dir(stateDir))
			if err != nil {
				return e.fail("umount", fmt.Errorf("connect exact FSKit daemon for unmount: %w", err))
			}
			present, err := verifyRecordedFskitAttach(ctl, st)
			if err != nil {
				return e.fail("umount", fmt.Errorf("verify exact FSKit attach for unmount: %w", err))
			}
			if !present {
				return e.fail("umount", fmt.Errorf("exact FSKit attach %s is absent; mount remains live", st.AttachRef))
			}
			if err := ctl.unmountRecordedAttach(st); err != nil {
				return e.fail("umount", fmt.Errorf(
					"daemon-owned FSKit unmount refused; mount remains live: %w; retry when the authority is reachable, or run `portablefs umount --force %s` to durably park any offline write-back tail",
					err,
					mountPath,
				))
			}
			fskitUnmountCompleted = true
		} else if mounted {
			if err := e.drainBeforeUnmount(st); err != nil {
				return e.fail("umount", fmt.Errorf("%v\nnothing was unmounted: the write-back tail could not reach the authority. Retry when it is reachable, or run `portablefs umount --force %s` to detach now — the tail then parks as a durable recovery job for verified exact replay on the next attach", err, mountPath))
			}
		}
	}

	mounted, err = recordedKernelMountPresent(st)
	if err != nil {
		return e.fail("umount", fmt.Errorf("kernel mount identity changed after drain; refusing unmount: %w", err))
	}
	needsPlatformUnmount, reconcileStale, completionErr := decidePostUnmount(
		mounted,
		fuseForceCompleted,
		fskitUnmountCompleted,
	)
	if completionErr != nil {
		return e.fail("umount", completionErr)
	}
	if needsPlatformUnmount {
		if unmountErr := platformUnmountRecorded(st); unmountErr != nil {
			stillMounted, identityErr := recordedKernelMountPresent(st)
			if identityErr != nil {
				return e.fail("umount", fmt.Errorf("platform unmount failed and kernel identity changed: %v: %w", unmountErr, identityErr))
			}
			if stillMounted {
				return e.fail("umount", fmt.Errorf("%w\nif the volume is busy, close processes using %s and retry", unmountErr, mountPath))
			}
		}
	} else if reconcileStale {
		if mountProcessMatches(st) {
			// The platform mount was torn down externally (forced diskutil
			// unmount, extension crash) but the daemon lingers: reconcile —
			// stop it and drop the record — instead of reporting "busy" for
			// a path that has nothing mounted on it.
			fmt.Fprintf(e.stderr, "portablefs umount: warning: %s was not mounted (daemon pid %d still running); stopping it and removing stale mount state\n", mountPath, st.PID)
		} else {
			// Daemon already gone and nothing to unmount: a stale record. Clean it
			// up instead of failing, so `mounts` stops flagging it.
			fmt.Fprintf(e.stderr, "portablefs umount: warning: %s was not mounted (daemon pid %d already gone); removing stale mount state\n", mountPath, st.PID)
		}
	}
	if mountProcessMatches(st) {
		if err := stopMountDaemon(st); err != nil {
			return e.fail("umount", err)
		}
	}
	if force {
		// FUSE parks its job inside the daemon during teardown; report every
		// parked stream from the on-disk registry (visible OUTSIDE any
		// attach) so forced unmounts always print their recovery handles.
		forcedJobs = append(forcedJobs, parkedRecoveryJobs(stateDir, st)...)
		forcedJobs = dedupeStrings(forcedJobs)
		for _, id := range forcedJobs {
			fmt.Fprintf(e.stdout, "parked write-back recovery job %s (verified and replayed exactly on the next attach of %s)\n", id, volumeBranchLabel(st.VolumeID, st.Branch))
		}
	}
	if err := publishResourcesCleanedIntent(operation, stateDir, mountPath); err != nil {
		return e.fail("umount", fmt.Errorf("mount resources are gone but their durable cleanup fact could not be published; state and intent were preserved: %w", err))
	}
	if err := e.releaseRecordedAccessLease(&o, stateDir, st); err != nil {
		return e.fail("umount", fmt.Errorf("mount resources are gone but access-lease cleanup is incomplete; state and intent were preserved: %w", err))
	}
	if err := publishReleasedLeaseIntent(operation, stateDir, mountPath); err != nil {
		return e.fail("umount", fmt.Errorf("access lease is released but its durable finalization fact could not be published; state and intent were preserved: %w", err))
	}
	if err := removeMountState(stateDir, mountPath); err != nil {
		return e.fail("umount", fmt.Errorf("mount is gone but its state record could not be removed: %w", err))
	}
	if err := finalize(); err != nil {
		return e.fail("umount", fmt.Errorf("finalize clean unmount operation: %w", err))
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"mountPath": mountPath, "volumeId": st.VolumeID, "unmounted": true, "tracked": true, "forced": force, "recoveryJobs": forcedJobs})
	}
	fmt.Fprintf(e.stdout, "unmounted %s (volume %s)\n", mountPath, st.VolumeID)
	return 0
}

// decidePostUnmount classifies the exact kernel state after a drain/detach
// acknowledgement. A successful daemon-owned FSKit transaction already
// performed the kernel detach, so absence is normal and presence is an
// FSKit-specific invariant violation. Only an unacknowledged absence is
// stale-state reconciliation.
func decidePostUnmount(mounted, fuseForceCompleted, fskitUnmountCompleted bool) (needsPlatformUnmount, reconcileStale bool, err error) {
	switch {
	case mounted && fskitUnmountCompleted:
		return false, false, fmt.Errorf("daemon-owned FSKit unmount acknowledged completion but the exact kernel mount remains; state and intent were preserved")
	case mounted && fuseForceCompleted:
		return false, false, fmt.Errorf("forced FUSE owner acknowledged parking but the exact kernel mount remains; state and intent were preserved")
	case mounted:
		return true, false, nil
	case fskitUnmountCompleted || fuseForceCompleted:
		return false, false, nil
	default:
		return false, true, nil
	}
}

func preparedFUSERetryDecision(phase string, ownerLive, explicitForce, parkAcknowledged bool) (bool, error) {
	switch {
	case phase == "drain-prepared" && ownerLive && !explicitForce:
		return false, fmt.Errorf("drain-prepared transaction is still live; retry with --force to durably park its fail-frozen tail")
	case phase == "drain-prepared" && ownerLive:
		return true, nil
	case phase == "force-prepared" && ownerLive && !parkAcknowledged:
		return false, fmt.Errorf("live force-prepared owner lacks the exact durable park acknowledgement")
	default:
		return false, nil
	}
}

func hydrateMountOperationFromState(operation *mountOperation, state *mountState) {
	operation.volumeID = state.VolumeID
	operation.branch = state.Branch
	operation.strategy = state.Strategy
	operation.engine = state.Engine
	operation.attachRef = state.AttachRef
	operation.mountInstanceID = state.MountInstanceID
	operation.kernelMountID = state.KernelMountID
	operation.mountTarget = mountTargetIdentity{device: state.MountTargetDevice, inode: state.MountTargetInode}
	operation.mountMechanism = state.MountMechanism
	operation.fuseHelperPath = state.FUSEHelperPath
	operation.fsType = state.FSType
	operation.startedAtMs = state.StartedAtMs
	operation.authorityURL = state.AuthorityURL
	operation.transportMode = state.DataPlaneTransport
	operation.transportServer = state.DataPlaneServerName
	operation.dataPlaneCAPath = state.DataPlaneCAPath
	operation.dataPlaneCAHash = state.DataPlaneCASHA256
	operation.managerURL = state.ManagerURL
	operation.leaseReleaseOp = state.AccessLeaseReleaseOperationID
	operation.accessLease = state.AccessLease
	if operation.prior != nil {
		operation.leaseCreateOp = operation.prior.LeaseCreateOperationID
		operation.leaseConsumerID = operation.prior.LeaseConsumerID
		operation.leaseTeamID = operation.prior.LeaseTeamID
	}
}

func verifyCleanupIntentMatchesState(intent *mountIntent, state *mountState) error {
	if intent == nil || state == nil ||
		(intent.Phase != "drain-prepared" &&
			intent.Phase != "force-requested" &&
			intent.Phase != "force-prepared" &&
			intent.Phase != "resources-cleaned" &&
			intent.Phase != "lease-released") {
		return fmt.Errorf("missing cleaned-resource intent or mount state")
	}
	if intent.MountPath != state.MountPath || intent.VolumeID != state.VolumeID ||
		intent.Branch != state.Branch || intent.Strategy != state.Strategy ||
		intent.Engine != state.Engine ||
		intent.FSType != state.FSType ||
		intent.MountInstanceID != state.MountInstanceID ||
		intent.KernelMountID != state.KernelMountID ||
		intent.AttachRef != state.AttachRef ||
		intent.MountTargetDevice != state.MountTargetDevice ||
		intent.MountTargetInode != state.MountTargetInode ||
		intent.MountMechanism != state.MountMechanism ||
		intent.FUSEHelperPath != state.FUSEHelperPath ||
		intent.StartedAtMs != state.StartedAtMs ||
		intent.AuthorityURL != state.AuthorityURL ||
		intent.DataPlaneTransport != state.DataPlaneTransport ||
		intent.DataPlaneServerName != state.DataPlaneServerName ||
		intent.DataPlaneCAPath != state.DataPlaneCAPath ||
		intent.DataPlaneCASHA256 != state.DataPlaneCASHA256 ||
		intent.ManagerURL != state.ManagerURL ||
		intent.LeaseReleaseOperationID != state.AccessLeaseReleaseOperationID {
		return fmt.Errorf("cleanup intent and state identify different mount transactions")
	}
	if (intent.AccessLease == nil) != (state.AccessLease == nil) {
		return fmt.Errorf("cleanup intent and state disagree on access-lease ownership")
	}
	if state.AccessLease != nil {
		if intent.AccessLease.AccessLeaseID != state.AccessLease.AccessLeaseID {
			return fmt.Errorf("cleanup intent and state identify different access leases")
		}
		if (intent.Phase == "resources-cleaned" || intent.Phase == "lease-released") &&
			(intent.AccessLease.AccessToken != state.AccessLease.AccessToken ||
				intent.AccessLease.ControlSeq != state.AccessLease.ControlSeq ||
				intent.AccessLease.ExpiresAtMs != state.AccessLease.ExpiresAtMs) {
			return fmt.Errorf("terminal cleanup intent does not contain the latest state lease identity")
		}
	}
	return nil
}

func publishResourcesCleanedIntent(operation *mountOperation, stateDir, mountPath string) error {
	if operation == nil {
		return fmt.Errorf("missing mount operation")
	}
	latest, err := readMountState(stateDir, mountPath)
	if err != nil {
		return fmt.Errorf("read latest cleaned-resource state: %w", err)
	}
	if latest != nil {
		hydrateMountOperationFromState(operation, latest)
	}
	if err := operation.writeIntent("resources-cleaned", 0, ""); err != nil {
		return fmt.Errorf("publish resources-cleaned intent: %w", err)
	}
	return nil
}

func publishReleasedLeaseIntent(operation *mountOperation, stateDir, mountPath string) error {
	if operation == nil {
		return fmt.Errorf("missing mount operation")
	}
	latest, err := readMountState(stateDir, mountPath)
	if err != nil {
		return fmt.Errorf("read latest released access lease: %w", err)
	}
	if latest == nil || latest.AccessLease == nil {
		return nil
	}
	hydrateMountOperationFromState(operation, latest)
	if err := operation.writeIntent("lease-released", 0, ""); err != nil {
		return fmt.Errorf("publish released access-lease intent: %w", err)
	}
	return nil
}

func (e *cmdEnv) releaseRecordedAccessLease(o *commonOpts, stateDir string, recorded *mountState) error {
	if recorded == nil || recorded.AccessLease == nil {
		return nil
	}
	latest, err := readMountState(stateDir, recorded.MountPath)
	if err != nil {
		return fmt.Errorf("read latest access-lease cleanup state: %w", err)
	}
	if latest != nil {
		recorded = latest
	}
	if recorded.ManagerURL == "" || recorded.AccessLeaseReleaseOperationID == "" {
		return fmt.Errorf("recorded access lease %s lacks exact manager/release-operation identity", recorded.AccessLease.AccessLeaseID)
	}
	settings, err := e.resolveSettings(o)
	if err != nil {
		return err
	}
	managerURL, managerToken := settings.managerEndpoint()
	if managerURL != recorded.ManagerURL {
		return fmt.Errorf("configured manager %q does not match recorded lease manager %q", managerURL, recorded.ManagerURL)
	}
	keeper := newLeaseKeeper(
		e.managerClient(managerURL, managerToken),
		nil,
		*recorded.AccessLease,
		nil,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return keeper.releaseWithOperation(ctx, recorded.AccessLeaseReleaseOperationID)
}

func (e *cmdEnv) reconcileMountIntent(intent *mountIntent, force bool) ([]string, error) {
	if intent == nil {
		return nil, fmt.Errorf("missing intent")
	}
	if intent.Phase == "resources-cleaned" {
		if err := e.releaseIntentAccessLease(intent); err != nil {
			return nil, fmt.Errorf("resources are cleaned but access-lease finalization failed: %w", err)
		}
		if intent.AccessLease != nil {
			intent.Phase = "lease-released"
			operationIdentity, err := processStartIdentity(os.Getpid())
			if err != nil {
				return nil, fmt.Errorf("record cleanup finalization process identity: %w", err)
			}
			intent.OperationOwnerPID = os.Getpid()
			intent.OperationOwnerStartIdentity = operationIdentity
			intent.UpdatedAtMs = time.Now().UnixMilli()
			stateDir, err := e.mountStateDir()
			if err != nil {
				return nil, err
			}
			_, intentPath := mountOperationPaths(stateDir, intent.MountPath)
			if err := writeMountIntentRecord(intentPath, intent); err != nil {
				return nil, fmt.Errorf("publish released-lease finalization: %w", err)
			}
		}
		return nil, nil
	}
	if intent.Phase == "lease-released" {
		// This fact is published only after exact kernel/attach teardown and
		// successful exact release. Its sole purpose is to bridge crashes
		// between release/state deletion and intent deletion.
		return nil, nil
	}
	if intent.Phase == "starting" {
		// "starting" is durably published before any attach or kernel-mount
		// side effect. Reconciliation is still explicit: prove the intent has
		// no side-effect identity and that its target is not a kernel
		// mountpoint before the caller removes it.
		if intent.MountOwnerPID != 0 || intent.MountInstanceID != "" ||
			intent.AttachRef != "" || intent.KernelMountID != "" {
			return nil, fmt.Errorf("starting intent contains mount side-effect identity")
		}
		boundaries, err := kernelMountBoundaries()
		if err != nil {
			return nil, fmt.Errorf("inventory kernel mounts for starting intent: %w", err)
		}
		for _, boundary := range boundaries {
			if boundary.path == intent.MountPath {
				return nil, fmt.Errorf(
					"target is now a kernel mountpoint (%s from %s), so starting intent cleanup is unsafe",
					boundary.fsType, boundary.source,
				)
			}
		}
		if err := e.releaseIntentAccessLease(intent); err != nil {
			return nil, fmt.Errorf("release starting-operation access lease: %w", err)
		}
		return nil, nil
	}
	st := &mountState{
		MountPath:                     intent.MountPath,
		VolumeID:                      intent.VolumeID,
		Branch:                        intent.Branch,
		PID:                           intent.MountOwnerPID,
		ProcessStartIdentity:          intent.MountOwnerStartIdentity,
		Strategy:                      intent.Strategy,
		Engine:                        intent.Engine,
		FSType:                        intent.FSType,
		AttachRef:                     intent.AttachRef,
		MountInstanceID:               intent.MountInstanceID,
		KernelMountID:                 intent.KernelMountID,
		MountTargetDevice:             intent.MountTargetDevice,
		MountTargetInode:              intent.MountTargetInode,
		MountMechanism:                intent.MountMechanism,
		FUSEHelperPath:                intent.FUSEHelperPath,
		StartedAtMs:                   intent.StartedAtMs,
		AuthorityURL:                  intent.AuthorityURL,
		DataPlaneTransport:            intent.DataPlaneTransport,
		DataPlaneServerName:           intent.DataPlaneServerName,
		DataPlaneCAPath:               intent.DataPlaneCAPath,
		DataPlaneCASHA256:             intent.DataPlaneCASHA256,
		ManagerURL:                    intent.ManagerURL,
		AccessLease:                   intent.AccessLease,
		AccessLeaseReleaseOperationID: intent.LeaseReleaseOperationID,
	}
	if st.Strategy != "fuse" && st.Strategy != "fskit" {
		return nil, fmt.Errorf("intent has unsupported strategy %q", st.Strategy)
	}
	mounted := false
	var err error
	if intent.Phase == "mounting" && st.Strategy == "fuse" && st.KernelMountID == "" {
		kernelMountID, present, err := recoverFUSEMountingIdentity(st.MountPath, st.MountInstanceID)
		if err != nil {
			return nil, fmt.Errorf("recover mounting-phase FUSE kernel identity: %w", err)
		}
		if present {
			operationIdentity, err := processStartIdentity(os.Getpid())
			if err != nil {
				return nil, fmt.Errorf("record reconciliation process identity: %w", err)
			}
			intent.KernelMountID = kernelMountID
			intent.OperationOwnerPID = os.Getpid()
			intent.OperationOwnerStartIdentity = operationIdentity
			intent.UpdatedAtMs = time.Now().UnixMilli()
			stateDir, err := e.mountStateDir()
			if err != nil {
				return nil, err
			}
			_, intentPath := mountOperationPaths(stateDir, intent.MountPath)
			if err := writeMountIntentRecord(intentPath, intent); err != nil {
				return nil, fmt.Errorf("durably publish recovered FUSE kernel identity: %w", err)
			}
			st.KernelMountID = kernelMountID
			mounted, err = recordedKernelMountPresent(st)
			if err != nil {
				return nil, fmt.Errorf("reverify recovered FUSE kernel identity: %w", err)
			}
			if !mounted {
				return nil, fmt.Errorf("recovered FUSE kernel mount disappeared after identity publication")
			}
		}
	} else {
		mounted, err = recordedKernelMountPresent(st)
		if err != nil {
			return nil, fmt.Errorf("kernel identity is not safely classifiable: %w", err)
		}
	}
	if force && st.Strategy == "fuse" && st.Engine != mountEngineFuseV3 &&
		intent.Phase != "force-requested" && intent.Phase != "force-prepared" {
		if !validKernelMountID(st.KernelMountID) {
			return nil, fmt.Errorf("explicit force recovery cannot identify the exact FUSE kernel transaction")
		}
		operationIdentity, err := processStartIdentity(os.Getpid())
		if err != nil {
			return nil, fmt.Errorf("record FUSE force-recovery authorization owner: %w", err)
		}
		intent.Phase = "force-requested"
		intent.OperationOwnerPID = os.Getpid()
		intent.OperationOwnerStartIdentity = operationIdentity
		intent.UpdatedAtMs = time.Now().UnixMilli()
		stateDir, err := e.mountStateDir()
		if err != nil {
			return nil, err
		}
		_, intentPath := mountOperationPaths(stateDir, intent.MountPath)
		if err := writeMountIntentRecord(intentPath, intent); err != nil {
			return nil, fmt.Errorf("publish durable FUSE force-recovery authorization: %w", err)
		}
	}
	if intent.Phase == "drain-prepared" {
		if st.Strategy != "fuse" {
			return nil, fmt.Errorf("drain-prepared recovery is valid only for FUSE")
		}
		if mountIntentOperationOwnerMatches(intent) {
			return nil, fmt.Errorf(
				"drain-prepared transaction is still owned by live pid %d; refusing a concurrent exact detach",
				intent.OperationOwnerPID,
			)
		}
		if mounted {
			if err := platformUnmountRecorded(st); err != nil {
				stillPresent, classifyErr := recordedKernelMountPresent(st)
				if classifyErr != nil || stillPresent {
					return nil, errors.Join(
						fmt.Errorf("resume exact drain-prepared FUSE detach: %w", err),
						classifyErr,
					)
				}
			}
		}
		if mountProcessMatches(st) {
			if err := stopMountDaemon(st); err != nil {
				return nil, fmt.Errorf("stop drain-prepared FUSE owner: %w", err)
			}
		}
		if err := e.releaseIntentAccessLease(intent); err != nil {
			return nil, fmt.Errorf("release drain-prepared access lease: %w", err)
		}
		return nil, nil
	}
	if intent.Phase == "force-requested" || intent.Phase == "force-prepared" {
		if st.Strategy != "fuse" {
			return nil, fmt.Errorf("%s recovery is valid only for FUSE", intent.Phase)
		}
		var recoveryJobs []string
		if intent.Phase == "force-requested" {
			stateDir, err := e.mountStateDir()
			if err != nil {
				return nil, err
			}
			if err := writeMountState(stateDir, *st); err != nil {
				return nil, fmt.Errorf("publish complete force-request recovery state: %w", err)
			}
			recoveryJobs, err = e.forceParkFUSEMount(stateDir, st)
			if err != nil {
				return nil, err
			}
			mounted, err = recordedKernelMountPresent(st)
			if err != nil {
				return nil, fmt.Errorf("reclassify force-prepared FUSE mount: %w", err)
			}
			if mounted {
				if err := platformUnmountRecorded(st); err != nil {
					stillPresent, classifyErr := recordedKernelMountPresent(st)
					if classifyErr != nil || stillPresent {
						return nil, errors.Join(
							fmt.Errorf("resume exact force-prepared FUSE detach: %w", err),
							classifyErr,
						)
					}
				}
				mounted = false
			}
			if mountProcessMatches(st) {
				if err := stopMountDaemon(st); err != nil {
					return nil, fmt.Errorf("stop force-prepared FUSE owner: %w", err)
				}
			}
			if err := removeMountState(stateDir, st.MountPath); err != nil {
				return nil, fmt.Errorf("remove force-request recovery state: %w", err)
			}
		}
		if mounted {
			if err := platformUnmountRecorded(st); err != nil {
				stillPresent, classifyErr := recordedKernelMountPresent(st)
				if classifyErr != nil || stillPresent {
					return nil, errors.Join(
						fmt.Errorf("resume exact %s FUSE detach: %w", intent.Phase, err),
						classifyErr,
					)
				}
			}
		}
		if mountProcessMatches(st) {
			if err := stopMountDaemon(st); err != nil {
				return nil, fmt.Errorf("stop %s FUSE owner: %w", intent.Phase, err)
			}
		}
		if err := e.releaseIntentAccessLease(intent); err != nil {
			return nil, fmt.Errorf("release %s access lease: %w", intent.Phase, err)
		}
		return recoveryJobs, nil
	}

	var ctl *fsdControl
	attachPresent := false
	if st.Strategy == "fskit" && st.AttachRef != "" {
		cfg, cfgErr := fskitConfigFromEnv(e.getenv)
		if cfgErr != nil {
			return nil, cfgErr
		}
		stateDir, stateErr := e.mountStateDir()
		if stateErr != nil {
			return nil, stateErr
		}
		ctl, err = e.ensureFskitDaemon(cfg, filepath.Dir(stateDir))
		if err != nil {
			return nil, fmt.Errorf("start exact daemon to reconcile attach %s: %w", st.AttachRef, err)
		}
		attachPresent, err = verifyRecordedFskitAttach(ctl, st)
		if err != nil {
			return nil, fmt.Errorf("inventory exact attach %s: %w", st.AttachRef, err)
		}
	}

	var recoveryJobs []string
	if mounted {
		switch st.Strategy {
		case "fuse":
			if st.Engine == mountEngineFuseV3 {
				// A v3 mount owes the authority nothing at detach beyond the
				// session end: acknowledged writes are already durable there. A
				// live owner is asked to detach cooperatively; an abandoned
				// kernel mount is removed by the exact identity-checked
				// platform detach, and the authority fences its session.
				if mountProcessMatches(st) {
					if err := e.drainBeforeUnmount(st); err != nil {
						return nil, err
					}
				} else if err := platformUnmountRecorded(st); err != nil {
					stillPresent, classifyErr := recordedKernelMountPresent(st)
					if classifyErr != nil || stillPresent {
						return nil, errors.Join(
							fmt.Errorf("detach abandoned v3 FUSE mount: %w", err),
							classifyErr,
						)
					}
				}
				break
			}
			if force {
				if !mountProcessMatches(st) {
					return nil, fmt.Errorf("exact FUSE process owner is unavailable, so the journal cannot be durably parked")
				}
				stateDir, stateErr := e.mountStateDir()
				if stateErr != nil {
					return nil, stateErr
				}
				if err := writeMountState(stateDir, *st); err != nil {
					return nil, fmt.Errorf("publish recovery state for forced FUSE reconciliation: %w", err)
				}
				jobs, err := e.forceParkFUSEMount(stateDir, st)
				if err != nil {
					return nil, err
				}
				recoveryJobs = append(recoveryJobs, jobs...)
				if err := removeMountState(stateDir, st.MountPath); err != nil {
					return nil, fmt.Errorf("remove forced FUSE reconciliation state: %w", err)
				}
			} else {
				if !mountProcessMatches(st) {
					return nil, fmt.Errorf("exact FUSE process owner is unavailable; retry with --force")
				}
				if err := e.drainBeforeUnmount(st); err != nil {
					return nil, err
				}
			}
		case "fskit":
			if !attachPresent || ctl == nil {
				return nil, fmt.Errorf("kernel mount is live but exact attach %s is unavailable", st.AttachRef)
			}
			if force {
				if jobID, err := ctl.forceDetach(st.AttachRef); err != nil {
					return nil, err
				} else if jobID != "" {
					recoveryJobs = append(recoveryJobs, jobID)
				}
				attachPresent = false
			} else {
				if err := ctl.unmountRecordedAttach(st); err != nil {
					return nil, fmt.Errorf("daemon-owned exact FSKit unmount: %w", err)
				}
				attachPresent = false
			}
		}
	}
	if attachPresent {
		if force {
			jobID, err := ctl.forceDetach(st.AttachRef)
			if err != nil {
				return nil, err
			}
			if jobID != "" {
				recoveryJobs = append(recoveryJobs, jobID)
			}
		} else {
			if err := ctl.unmountRecordedAttach(st); err != nil {
				return nil, err
			}
		}
	}
	if mountProcessMatches(st) {
		if err := stopMountDaemon(st); err != nil {
			return nil, err
		}
	}
	if err := e.releaseIntentAccessLease(intent); err != nil {
		return nil, fmt.Errorf("mount resources are gone but access-lease reconciliation failed: %w", err)
	}
	return dedupeStrings(recoveryJobs), nil
}

func (e *cmdEnv) releaseIntentAccessLease(intent *mountIntent) error {
	if intent == nil || intent.ManagerURL == "" {
		return nil
	}
	settings, err := e.resolveSettings(&commonOpts{})
	if err != nil {
		return err
	}
	managerURL, managerToken := settings.managerEndpoint()
	if managerURL != intent.ManagerURL {
		return fmt.Errorf("configured manager %q does not match intent manager %q", managerURL, intent.ManagerURL)
	}
	manager := e.managerClient(managerURL, managerToken)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lease := intent.AccessLease
	if lease == nil {
		// Only the crash-before-create-response window needs to replay the
		// permanent create receipt. Once the response was durably published,
		// cleanup depends solely on the exact lease/release transaction.
		session, err := manager.resolveAccessExact(
			ctx,
			intent.LeaseCreateOperationID,
			intent.VolumeID,
			intent.Branch,
			intent.LeaseTeamID,
			intent.LeaseConsumerID,
		)
		if err != nil {
			return fmt.Errorf("replay exact access-lease create receipt: %w", err)
		}
		lease = session.Lease
	}
	if lease == nil {
		return fmt.Errorf("replayed access-lease create returned no lease")
	}
	keeper := newLeaseKeeper(manager, nil, *lease, nil)
	if err := keeper.releaseWithOperation(ctx, intent.LeaseReleaseOperationID); err != nil {
		return fmt.Errorf("release access lease %s: %w", lease.AccessLeaseID, err)
	}
	return nil
}

// drainBeforeUnmount runs the REQUIRED normal-unmount drain barrier while
// the mount is still fully alive. An error means the unmount must not
// proceed.
func (e *cmdEnv) drainBeforeUnmount(st *mountState) error {
	switch {
	case st.Strategy == "fskit" && st.AttachRef != "":
		cfg, err := fskitConfigFromEnv(e.getenv)
		if err != nil {
			return err
		}
		stateDir, err := e.mountStateDir()
		if err != nil {
			return err
		}
		ctl, err := e.ensureFskitDaemon(cfg, filepath.Dir(stateDir))
		if err != nil {
			return fmt.Errorf("pre-unmount daemon identity: %w", err)
		}
		present, err := verifyRecordedFskitAttach(ctl, st)
		if err != nil {
			return fmt.Errorf("pre-unmount attach identity: %w", err)
		}
		if !present {
			return fmt.Errorf("pre-unmount attach %s is absent from the exact daemon", st.AttachRef)
		}
		if st.AccessLease != nil {
			if !validLeaseState(st.AccessLease) {
				return fmt.Errorf("pre-unmount access lease for attach %s is invalid", st.AttachRef)
			}
			if err := ctl.setCredential(st.AttachRef, st.AccessLease.AccessToken, st.AccessLease.ExpiresAtMs); err != nil {
				return fmt.Errorf("pre-unmount credential activation failed: %w", err)
			}
		}
		if _, err := ctl.syncAttach(st.AttachRef); err != nil {
			return fmt.Errorf("pre-unmount drain failed: %w", err)
		}
		return nil
	case st.Strategy == "fuse":
		// The FUSE daemon owns its drain: SIGTERM asks it to drain and
		// detach; a failed drain leaves the mount up, which we detect.
		if err := signalMountProcess(st, syscall.SIGTERM); err != nil {
			return err
		}
		deadline := time.Now().Add(daemonStopTimeout)
		for time.Now().Before(deadline) {
			present, err := recordedKernelMountPresent(st)
			if err != nil {
				return fmt.Errorf("kernel mount identity changed while draining: %w", err)
			}
			if !present {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		if present, err := recordedKernelMountPresent(st); err != nil {
			return fmt.Errorf("kernel mount identity changed while draining: %w", err)
		} else if present {
			return fmt.Errorf("the mount daemon could not drain within %v (the mount stays up)", daemonStopTimeout)
		}
		return nil
	}
	return fmt.Errorf("unsupported recorded mount strategy %q", st.Strategy)
}

// forceDetachForUnmount runs the required explicit force path against the
// exact live daemon attach. The caller must not remove the kernel mount,
// state, or intent unless this durable parking acknowledgement succeeds.
func (e *cmdEnv) forceDetachForUnmount(st *mountState) ([]string, error) {
	if st.Strategy != "fskit" || !mountid.ValidAttachRef(st.AttachRef) {
		return nil, fmt.Errorf("recorded FSKit attach identity is incomplete; refusing forced detach")
	}
	cfg, cfgErr := fskitConfigFromEnv(e.getenv)
	if cfgErr != nil {
		return nil, cfgErr
	}
	stateDir, stateErr := e.mountStateDir()
	if stateErr != nil {
		return nil, stateErr
	}
	ctl, identityErr := e.ensureFskitDaemon(cfg, filepath.Dir(stateDir))
	if identityErr != nil {
		return nil, fmt.Errorf("exact daemon identity is required for forced detach: %w", identityErr)
	}
	present, inventoryErr := verifyRecordedFskitAttach(ctl, st)
	if inventoryErr != nil {
		return nil, fmt.Errorf("verify exact daemon attach for forced detach: %w", inventoryErr)
	}
	if !present {
		return nil, fmt.Errorf("exact daemon attach %s is absent; refusing to force-detach an uncorrelated kernel mount", st.AttachRef)
	}
	jobID, err := ctl.forceDetach(st.AttachRef)
	if err != nil {
		return nil, fmt.Errorf("daemon did not durably acknowledge forced detach for %s: %w", st.AttachRef, err)
	}
	if jobID == "" {
		return nil, nil
	}
	return []string{jobID}, nil
}

func (e *cmdEnv) forceParkFUSEMount(stateDir string, st *mountState) ([]string, error) {
	if st.Strategy != "fuse" || !mountid.ValidMountInstance(st.MountInstanceID) ||
		!validKernelMountID(st.KernelMountID) {
		return nil, fmt.Errorf("exact FUSE mount and kernel identities are required for forced journal parking")
	}
	if !mountProcessMatches(st) {
		return e.forceParkAbandonedFUSEMount(stateDir, st)
	}
	if err := signalMountProcess(st, syscall.SIGUSR1); err != nil {
		return nil, fmt.Errorf("send identity-bound forced-park request: %w", err)
	}
	deadline := time.Now().Add(daemonStopTimeout)
	var acknowledged bool
	var jobID string
	for time.Now().Before(deadline) {
		current, err := readMountState(stateDir, st.MountPath)
		if err != nil {
			return nil, fmt.Errorf("read forced-park acknowledgement: %w", err)
		}
		if current == nil {
			return nil, fmt.Errorf("mount state disappeared before forced-park acknowledgement")
		}
		if current.PID != st.PID ||
			current.ProcessStartIdentity != st.ProcessStartIdentity ||
			current.MountInstanceID != st.MountInstanceID ||
			current.KernelMountID != st.KernelMountID {
			return nil, fmt.Errorf("mount identity changed while awaiting forced-park acknowledgement")
		}
		acknowledged = current.ForceParkAcknowledged
		jobID = current.ForceRecoveryJobID
		present, err := recordedKernelMountPresent(st)
		if err != nil {
			return nil, fmt.Errorf("kernel identity changed during forced parking: %w", err)
		}
		if acknowledged && !present {
			if jobID == "" {
				return nil, nil
			}
			return []string{jobID}, nil
		}
		if !mountProcessMatches(st) {
			// The force authorization was published before signaling. If the
			// exact owner dies anywhere in the acknowledgement window, continue
			// the same transaction under the abandoned-store lock; exact kernel
			// detach still waits for that local durability proof.
			return e.forceParkAbandonedFUSEMount(stateDir, st)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if acknowledged {
		return nil, fmt.Errorf("forced write-back parking was acknowledged but exact kernel detach did not complete within %v", daemonStopTimeout)
	}
	return nil, fmt.Errorf("FUSE owner did not acknowledge durable forced parking within %v", daemonStopTimeout)
}

// forceParkAbandonedFUSEMount is the local-only continuation of a durable
// force-requested transaction after the exact owner process is proven gone.
// It never dials the authority and never detaches the kernel resource until
// the exact write-back store has published a transaction-bound park proof.
func (e *cmdEnv) forceParkAbandonedFUSEMount(stateDir string, st *mountState) ([]string, error) {
	if mountProcessMatches(st) {
		return nil, fmt.Errorf("FUSE owner is still live; refusing abandoned-store parking")
	}
	_, intentPath := mountOperationPaths(stateDir, st.MountPath)
	intent, err := readMountIntent(intentPath, st.MountPath)
	if err != nil {
		return nil, fmt.Errorf("read durable FUSE force request: %w", err)
	}
	if intent == nil || (intent.Phase != "force-requested" && intent.Phase != "force-prepared") {
		return nil, fmt.Errorf("abandoned FUSE store parking requires a durable force-requested intent")
	}
	if err := verifyCleanupIntentMatchesState(intent, st); err != nil {
		return nil, fmt.Errorf("verify abandoned FUSE force identity: %w", err)
	}
	proof, err := writeback.ForceParkAbandonedStore(
		filepath.Join(stateDir, "writeback", storageDirID(st.VolumeID, st.Branch)),
		st.VolumeID,
		st.Branch,
		st.MountInstanceID,
		"explicit forced FUSE unmount after exact owner death",
	)
	if err != nil {
		if errors.Is(err, writeback.ErrRecoveryResolutionRequired) {
			// The FUSE half of the same cycle. See recoverycmd.go: this refusal
			// named a resolution that had no command, and --discard-record's
			// refusal pointed straight back here.
			return nil, fmt.Errorf(
				"durably park abandoned FUSE store: %w\n"+
					"this job blocks force-park and every attach until it is resolved. Inspect it with\n"+
					"    portablefs recovery list %s\n"+
					"and resolve it with\n"+
					"    portablefs recovery resolve %s --all-terminal\n"+
					"which quarantines the job's bytes (nothing is deleted) and reports exactly what was lost",
				err, st.MountPath, st.MountPath,
			)
		}
		return nil, fmt.Errorf("durably park abandoned FUSE store: %w", err)
	}
	jobID := ""
	if len(proof.JobIDs) != 0 {
		jobID = proof.JobIDs[len(proof.JobIDs)-1]
	}
	updated, err := updateMountState(stateDir, st.MountPath, func(current *mountState) {
		current.ForceParkAcknowledged = true
		current.ForceRecoveryJobID = jobID
	})
	if err != nil {
		return nil, fmt.Errorf("publish abandoned FUSE park acknowledgement: %w", err)
	}
	if !updated {
		return nil, fmt.Errorf("mount state disappeared before abandoned FUSE park acknowledgement")
	}
	latest, err := readMountState(stateDir, st.MountPath)
	if err != nil || latest == nil {
		return nil, fmt.Errorf("read abandoned FUSE park acknowledgement: %w", err)
	}
	if err := verifyCleanupIntentMatchesState(intent, latest); err != nil {
		return nil, fmt.Errorf("reverify abandoned FUSE force identity: %w", err)
	}
	operationIdentity, err := processStartIdentity(os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("record abandoned FUSE parking owner: %w", err)
	}
	intent.Phase = "force-prepared"
	intent.OperationOwnerPID = os.Getpid()
	intent.OperationOwnerStartIdentity = operationIdentity
	intent.AccessLease = latest.AccessLease
	intent.UpdatedAtMs = time.Now().UnixMilli()
	if err := writeMountIntentRecord(intentPath, intent); err != nil {
		return nil, fmt.Errorf("publish abandoned FUSE force-prepared proof: %w", err)
	}
	return append([]string(nil), proof.JobIDs...), nil
}

// parkedRecoveryJobs reads the on-disk recovery registry for this mount's
// (volume, branch) write-back store: job.json lives OUTSIDE any attach, so a
// forced unmount can always name the recovery handles it parked.
func parkedRecoveryJobs(stateDir string, st *mountState) []string {
	roots := []string{
		// FUSE mounts key the store under the CLI state dir.
		filepath.Join(stateDir, "writeback", storageDirID(st.VolumeID, st.Branch)),
	}
	// FSKit mounts key it under the daemon's state dir (a sibling of the
	// mount state dir).
	roots = append(roots, filepath.Join(filepath.Dir(stateDir), "portablefsd", "wal", storageDirID(st.VolumeID, st.Branch)))
	var ids []string
	for _, root := range roots {
		matches, _ := filepath.Glob(filepath.Join(root, "stream-*", "job.json"))
		for _, m := range matches {
			var job struct {
				JobID string `json:"jobId"`
			}
			if b, err := os.ReadFile(m); err == nil && json.Unmarshal(b, &job) == nil && job.JobID != "" {
				ids = append(ids, job.JobID)
			}
		}
	}
	return ids
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// daemonStopTimeout bounds the cooperative foreground-process shutdown after
// the authority drain and platform unmount have both succeeded.
const daemonStopTimeout = 60 * time.Second

// stopMountDaemon only requests cooperative termination. It never escalates
// to SIGKILL: a process that does not acknowledge SIGTERM remains visible to
// the operator and keeps its mount-state record instead of being silently
// converted into a crash-recovery path.
func signalMountProcess(st *mountState, signal syscall.Signal) error {
	return signalMountProcessExact(st, signal)
}

func stopMountDaemon(st *mountState) error {
	if st.Strategy != "fskit" {
		if err := signalMountProcess(st, syscall.SIGTERM); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(daemonStopTimeout)
	for time.Now().Before(deadline) {
		if !mountProcessMatches(st) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf(
		"foreground mount process %d did not exit within %v after SIGTERM; it was left running and its mount-state record was preserved (no forced termination was attempted)",
		st.PID,
		daemonStopTimeout,
	)
}

func cmdMounts(e *cmdEnv, args []string) int {
	fs := newFlagSet("mounts")
	var o commonOpts
	addCommonFlags(fs, &o)
	if _, err := parseArgs(fs, args); err != nil {
		return e.handleParseError("mounts", err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		return e.fail("mounts", err)
	}
	states, err := listMountStates(stateDir)
	if err != nil {
		return e.fail("mounts", err)
	}
	intents, err := listMountIntents(stateDir)
	if err != nil {
		return e.fail("mounts", err)
	}
	type mountRow struct {
		MountPath    string   `json:"mountPath"`
		VolumeID     string   `json:"volumeId"`
		Branch       string   `json:"branch"`
		PID          int      `json:"pid"`
		Strategy     string   `json:"strategy"`
		AuthorityURL string   `json:"authorityUrl,omitempty"`
		AttachRef    string   `json:"attachRef,omitempty"`
		StartedAtMs  int64    `json:"startedAtMs"`
		LocalDirs    []string `json:"localDirs,omitempty"`
		// LocalRoutes and LocalRouteRevision are the machine-local route set
		// a FUSE mount activated and the revision it answers for.
		LocalRoutes        []string `json:"localRoutes,omitempty"`
		LocalRouteRevision string   `json:"localRouteRevision,omitempty"`
		Alive              bool     `json:"alive"`
		Status             string   `json:"status,omitempty"`
		StatusChangedAtMs  int64    `json:"statusChangedAtMs,omitempty"`
		// Health folds pid-liveness and the persisted credential status:
		// live | stale | credential-expired.
		Health string `json:"health"`
		// WriteBack carries the daemon's durability-debt view for fskit
		// mounts: live un-flushed backlog plus parked WALs awaiting the
		// background recovery job.
		WriteBack *cliWriteBackStatus `json:"writeBack,omitempty"`
		// AttachState is the daemon-reported attach state (degraded carries
		// the daemon's last error in the printed line).
		AttachState string `json:"attachState,omitempty"`
		// AttachError is the daemon's own lastError for the attach. The
		// printed line already shows it; the JSON view dropped it, so an agent
		// reading --json could see attachState=degraded with no reason at all.
		AttachError string `json:"attachError,omitempty"`
		// AttachCredential names WHICH credential-plane fault a degraded attach
		// has: "rejected" (the authority answered no -> log in again),
		// "pending-verification" (the authority never answered at all -> the
		// handshake is being torn down before the ack, so look at the router),
		// or "router-refused" (the router answered, and its answer was not
		// about the credential -> capacity, a lease transition, or an
		// authority outage behind it; retryable, and re-authenticating changes
		// none of them). Empty means no credential-plane fault. These are DELIBERATELY not folded
		// into Health: Health carries the CLI-side lease-keeper verdict from
		// persisted mount state, which is a different, disjoint path.
		AttachCredential string `json:"attachCredential,omitempty"`
		// CleanupRequired marks a durable operation intent with no matching
		// mount-state record. It is deliberately a first-class inventory row:
		// crash recovery must never disappear from the CLI or app view.
		CleanupRequired bool   `json:"cleanupRequired,omitempty"`
		OperationPhase  string `json:"operationPhase,omitempty"`
	}
	var daemonView map[string]cliAttachStatus
	for i := range states {
		if states[i].Strategy == "fskit" && states[i].AttachRef != "" {
			daemonView, err = fskitAttachStatuses(e.getenv, e.version)
			if err != nil {
				return e.fail("mounts", err)
			}
			break
		}
	}
	rows := make([]mountRow, 0, len(states))
	statePaths := make(map[string]struct{}, len(states))
	for i := range states {
		st := &states[i]
		statePaths[st.MountPath] = struct{}{}
		// mountState contains the live access credential because the daemon
		// needs it for renewal. Never embed that persistence object in a
		// presentation type: JSON output is routinely captured in agent logs.
		row := mountRow{
			MountPath:          st.MountPath,
			VolumeID:           st.VolumeID,
			Branch:             st.Branch,
			PID:                st.PID,
			Strategy:           st.Strategy,
			AuthorityURL:       st.AuthorityURL,
			AttachRef:          st.AttachRef,
			StartedAtMs:        st.StartedAtMs,
			LocalDirs:          st.LocalDirs,
			LocalRoutes:        st.LocalRoutes,
			LocalRouteRevision: st.LocalRouteRevision,
			Alive:              mountProcessMatches(st),
			Status:             st.Status,
			Health:             e.classifyMount(st),
			StatusChangedAtMs:  st.StatusChangedAtMs,
		}
		if a, ok := daemonView[states[i].AttachRef]; ok {
			row.WriteBack = a.WriteBack
			row.AttachState = a.State
			row.AttachError = a.LastError
			row.AttachCredential = a.Credential
		}
		rows = append(rows, row)
	}
	for i := range intents {
		intent := &intents[i]
		if _, tracked := statePaths[intent.MountPath]; tracked {
			continue
		}
		rows = append(rows, mountRow{
			MountPath:       intent.MountPath,
			VolumeID:        intent.VolumeID,
			Branch:          intent.Branch,
			PID:             intent.MountOwnerPID,
			Strategy:        intent.Strategy,
			AttachRef:       intent.AttachRef,
			Health:          "cleanup-required",
			CleanupRequired: true,
			OperationPhase:  intent.Phase,
		})
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"mounts": rows})
	}
	if len(rows) == 0 {
		fmt.Fprintln(e.stdout, "no active mounts")
		return 0
	}
	for _, row := range rows {
		status := mountStatusWord(mountStatusInput{
			health:            row.Health,
			mountPath:         row.MountPath,
			operationPhase:    row.OperationPhase,
			statusChangedAtMs: row.StatusChangedAtMs,
			attachState:       row.AttachState,
			attachCredential:  row.AttachCredential,
			attachLastError:   row.AttachError,
		})
		extras := ""
		if len(row.LocalDirs) > 0 {
			extras = "  local-dirs:" + strings.Join(row.LocalDirs, ",")
		}
		if len(row.LocalRoutes) > 0 {
			extras += "  local-routes:" + strings.Join(row.LocalRoutes, " ") +
				" @" + revisionPrefix(row.LocalRouteRevision)
		}
		if wb := row.WriteBack; wb != nil {
			parkedRecords := 0
			for _, p := range wb.ParkedWALs {
				parkedRecords += p.Records
			}
			if parkedRecords > 0 {
				extras += fmt.Sprintf("  write-back:%d records pending recovery", parkedRecords)
			} else if wb.PendingRecords > 0 {
				extras += fmt.Sprintf("  write-back:%d records flushing", wb.PendingRecords)
			}
			// The credit controller is pacing writers on purpose; without this
			// the backlog above is indistinguishable from a stalled flusher.
			if wb.paced() {
				extras += fmt.Sprintf("  data-lane:%d writer(s) paced, credit %d/%d B", wb.CreditWaiters, wb.CreditDebt, wb.CreditSetpoint)
				if wb.DataLaneFull {
					extras += ", at ceiling"
				}
			}
		}
		fmt.Fprintf(e.stdout, "%s  %s  %s  pid %d%s  %s\n", row.MountPath, volumeBranchLabel(row.VolumeID, row.Branch), row.Strategy, row.PID, extras, status)
	}
	return 0
}

// fskitAttachStatuses reads the daemon's observational attach table, keyed by
// attach ref. This bounded status query is not used for lifecycle authority;
// strict persisted/live inventories guard mount and account mutations.
// mountStatusInput is one inventory row reduced to the facts that decide its
// operator-facing status word.
type mountStatusInput struct {
	health            string
	mountPath         string
	operationPhase    string
	statusChangedAtMs int64
	attachState       string
	attachCredential  string
	// attachLastError is the daemon's own sentence for this degradation. A
	// router refusal has three different conditions behind it with three
	// different remedies, and a fixed status word cannot name which — so for
	// that one word the daemon's sentence is carried through verbatim rather
	// than being flattened into a generic instruction.
	attachLastError string
}

// mountStatusWord renders the status word `portablefs mounts` prints for a row,
// with the remediation that word implies.
//
// It is a named function rather than an inline switch because these words are
// the whole operator-facing contract of the command, and one of them was
// actively misleading: a data-plane attach could be degraded for a credential
// reason and the line said only "degraded", which reads as a write-back
// problem. The two credential faults are distinguished here because they call
// for opposite actions — a REJECTED credential is answered by logging in
// again, an UNPROVEN one is answered by looking at whatever is tearing the
// handshake down before the authority replies, and telling someone to
// re-authenticate for the second one wastes the outage.
func mountStatusWord(row mountStatusInput) string {
	switch row.health {
	case "stale":
		return "stale (daemon gone; run `portablefs umount " + row.mountPath + "` to clean up)"
	case "cleanup-required":
		return "cleanup-required (incomplete " + row.operationPhase + " operation; run `portablefs umount " + row.mountPath + "`)"
	case mountStatusCredentialExpired:
		// The CLI-side lease keeper's own persisted verdict. It stays exactly
		// as it was: a control-plane renewal refusal is a different, disjoint
		// path from anything the data-plane handshake observes.
		since := ""
		if row.statusChangedAtMs != 0 {
			since = " since " + formatMs(row.statusChangedAtMs)
		}
		// The persisted verdict does not record WHICH typed answer ended the
		// lease (see leaseEndMessage), and four of the five are ended LEASES
		// rather than revoked credentials — so the word leads with the action
		// that works for all five and qualifies the one that does not.
		return "credential-expired" + since +
			" (this mount's access lease ended and cannot be renewed; remount to " +
			"re-establish it — run `portablefs login` first only if the saved " +
			"account credential is also rejected; see the mount log for which)"
	}
	if row.attachState != "degraded" {
		return "live"
	}
	switch row.attachCredential {
	case attachCredentialPendingVerification:
		return "degraded (credential pending-verification; the authority has " +
			"neither accepted nor refused it — check the data-plane " +
			"router/authority, not your login)"
	case attachCredentialRejected:
		return "degraded (credential rejected; run `portablefs login` and remount)"
	case attachCredentialRouterRefused:
		// The router refused for a reason that is NOT the credential, and the
		// three reasons have three different remedies (wait out a full lease,
		// remount through a lease transition, wait out an authority outage).
		// A word that named one of them would be wrong for the other two, and
		// the word this used to render — "credential rejected; run `portablefs
		// login`" — was wrong for all three.
		if row.attachLastError != "" {
			return "degraded (data-plane tunnel refused, retrying: " +
				row.attachLastError + ")"
		}
		return "degraded (data-plane tunnel refused, retrying; this is NOT a " +
			"credential failure and `portablefs login` will not change it)"
	}
	return "degraded"
}

func fskitAttachStatuses(getenv func(string) string, cliVersion string) (map[string]cliAttachStatus, error) {
	cfg, err := fskitConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	liveness := newFsdControl(cfg.controlSock)
	liveness.httpClient.Timeout = 3 * time.Second
	if !liveness.healthy() {
		return nil, nil
	}
	ctl, err := connectCompatiblePortablefsd(cfg, cliVersion)
	if err != nil {
		return nil, fmt.Errorf("portablefsd identity: %w", err)
	}
	ctl.httpClient.Timeout = 3 * time.Second
	attaches, err := ctl.listAttaches()
	if err != nil {
		return nil, err
	}
	out := make(map[string]cliAttachStatus, len(attaches))
	for _, a := range attaches {
		out[a.AttachRef] = a
	}
	return out, nil
}
