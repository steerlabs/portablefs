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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/accountsession"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/mountlog"
	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

const mountTokenEnv = "PORTABLEFS_MOUNT_TOKEN"

type mountReady struct {
	Renewal                *mountenrollment.RenewalReadiness `json:"renewal,omitempty"`
	OK                     bool                              `json:"ok"`
	Cleaned                bool                              `json:"cleaned,omitempty"`
	Error                  string                            `json:"error,omitempty"`
	PID                    int                               `json:"pid,omitempty"`
	Strategy               string                            `json:"strategy,omitempty"`
	MountPath              string                            `json:"mountPath,omitempty"`
	VolumeID               string                            `json:"volumeId,omitempty"`
	AttachRef              string                            `json:"attachRef,omitempty"`
	AuthorizationSessionID string                            `json:"authorizationSessionId,omitempty"`
	LocalRoutes            []string                          `json:"localRoutes,omitempty"`
	LocalRouteRevision     string                            `json:"localRouteRevision,omitempty"`
}

type mountOpts struct {
	common                                                   commonOpts
	strategy                                                 string
	addr                                                     string
	mountToken                                               string
	dataPlaneTransport                                       string
	dataPlaneServerName                                      string
	dataPlaneCAPath                                          string
	clientCertPath                                           string
	clientKeyPath                                            string
	authExpiresAtMs                                          int64
	managerURL                                               string
	managerServerName                                        string
	managerCAPath                                            string
	enrollmentID                                             string
	enrollmentCertPath                                       string
	authorityGeneration                                      uint64
	foreground                                               bool
	readyFD                                                  int
	opLockFD                                                 int
	workspaceGateFD                                          int
	workspaceOwnerFD                                         int
	workspaceBootstrapFD, workspaceClockFD, workspaceReadyFD int
	workspaceReconcileFD                                     int
}

// A mount that is already absent cannot fail closed a second time. Keep a
// bounded renewal-owner shutdown failure distinct from an authorization
// failure so teardown reports the correct operational outcome and closes the
// remote enrollment as an ordinary detach.
var errAutomaticRenewalStopTimeout = errors.New("automatic mount renewal did not stop within its cancellation bound")

// Once an automatic owner exists, remote closure is safe only after exact
// local cleanup proves that owner and its kernel/daemon attach are terminal.
func automaticEnrollmentCanCloseAfterStartupFailure(ownerEstablished, cleanupComplete bool) bool {
	return !ownerEstablished || cleanupComplete
}

var errMountNeedsDirectV3Credentials = fmt.Errorf(
	"portablefs mount attaches the v3 authority stack and needs direct credentials: pass " +
		"--addr <host:port>, a mount capability via --mount-token (or " + mountTokenEnv + "), " +
		"--data-plane-transport tls-private-ca|tls-system-pki (with --data-plane-server-name, and --data-plane-ca for a private CA), " +
		"and the mutual-TLS client identity via --client-cert/--client-key. " +
		"The initial attach requires a volume mount capability.")

func addMountFlags(fs *flag.FlagSet, o *mountOpts) {
	addCommonFlags(fs, &o.common)

	fs.StringVar(&o.strategy, "strategy", "auto", "mount strategy: auto (fskit on macOS, fuse on Linux), fskit, or fuse")
	fs.StringVar(&o.addr, "addr", "", "v3 authority address (host:port)")
	fs.StringVar(&o.mountToken, "mount-token", "", "single-use volume mount capability (or "+mountTokenEnv+")")
	fs.StringVar(&o.dataPlaneTransport, "data-plane-transport", "", "required: tls-private-ca or tls-system-pki (v3 sessions are mutually authenticated TLS; plaintext cannot mount)")
	fs.StringVar(&o.dataPlaneServerName, "data-plane-server-name", "", "exact TLS verification name of the authority")
	fs.StringVar(&o.dataPlaneCAPath, "data-plane-ca", "", "private CA PEM file for tls-private-ca")
	fs.StringVar(&o.clientCertPath, "client-cert", "", "mutual-TLS client certificate PEM file")
	fs.StringVar(&o.clientKeyPath, "client-key", "", "mutual-TLS client private key PEM file (must be chmod 600)")
	fs.Int64Var(&o.authExpiresAtMs, "auth-expires-at-ms", 0, "initial Manager authorization expiry as unix milliseconds (required with automatic enrollment)")
	fs.StringVar(&o.managerURL, "manager-url", "", "HTTPS origin of the hosted Manager for automatic mount authorization")
	fs.StringVar(&o.managerServerName, "manager-server-name", "", "exact TLS verification name of the hosted Manager")
	fs.StringVar(&o.managerCAPath, "manager-ca", "", "Manager private CA bundle PEM file")
	fs.StringVar(&o.enrollmentID, "mount-enrollment-id", "", "Manager-issued key-bound mount enrollment identity")
	fs.StringVar(&o.enrollmentCertPath, "mount-enrollment-cert", "", "Manager-issued mount enrollment certificate PEM file")
	fs.Uint64Var(&o.authorityGeneration, "authority-generation", 0, "exact hosted authority generation bound to the mount enrollment")
	fs.BoolVar(&o.foreground, "foreground", false, "stay attached instead of daemonizing")
	fs.IntVar(&o.readyFD, "ready-fd", 0, "internal: fd to write the readiness report to")
	fs.IntVar(&o.workspaceGateFD, "workspace-gate-fd", 0, "internal: sealed read-only workspace admission descriptor")
	fs.IntVar(&o.workspaceOwnerFD, "workspace-owner-fd", 0, "internal: workspace supervisor lifetime reader")
	fs.IntVar(&o.workspaceBootstrapFD, "workspace-bootstrap-fd", 0, "internal: workspace private launch pipe")
	fs.IntVar(&o.workspaceClockFD, "workspace-clock-fd", 0, "internal: shared TLS clock reader")
	fs.IntVar(&o.workspaceReadyFD, "workspace-ready-fd", 0, "internal: workspace control readiness pipe")
	fs.IntVar(&o.workspaceReconcileFD, "workspace-reconcile-fd", 0, "internal: workspace inventory reconciliation pipe")
	fs.IntVar(&o.opLockFD, "op-lock-fd", 0, "internal: inherited mount operation lock fd")
}

// validateDirectV3MountOpts is the one gate every mount invocation passes:
// the complete direct v3 credential shape, stated up front in the parent
// process, so errors surface immediately instead of via the daemonized
// child's readiness report. It returns the validated transport.
func validateDirectV3MountOpts(o *mountOpts, getenv func(string) string) (dataPlaneTransport, error) {
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
	enrollmentFields := []bool{
		o.managerURL != "", o.managerServerName != "", o.managerCAPath != "", o.enrollmentID != "",
		o.enrollmentCertPath != "", o.authorityGeneration != 0, o.authExpiresAtMs != 0,
	}
	var enrollmentSet int
	for _, set := range enrollmentFields {
		if set {
			enrollmentSet++
		}
	}
	if enrollmentSet != 0 && enrollmentSet != len(enrollmentFields) {
		return dataPlaneTransport{}, errors.New("automatic mount authorization requires --manager-url, --manager-server-name, --manager-ca, --mount-enrollment-id, --mount-enrollment-cert, --authority-generation, and --auth-expires-at-ms together")
	}
	if enrollmentSet != 0 && o.authExpiresAtMs <= time.Now().UnixMilli() {
		return dataPlaneTransport{}, errors.New("automatic mount initial authorization must be unexpired")
	}

	return transport, nil
}

func (o *mountOpts) automaticEnrollment(clientIdentity *clientTLSIdentity, volumeID string) (*mountenrollment.Client, time.Time, error) {
	if o.enrollmentID == "" {
		return nil, time.Time{}, nil
	}
	managerCA, err := readBoundedRegularFile(o.managerCAPath, false)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read --manager-ca: %w", err)
	}
	enrollmentCertificate, err := readBoundedRegularFile(o.enrollmentCertPath, false)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read --mount-enrollment-cert: %w", err)
	}
	client, err := mountenrollment.NewClient(mountenrollment.Config{
		ManagerURL: o.managerURL, ManagerServerName: o.managerServerName, ManagerCAPEM: managerCA,
		EnrollmentID: o.enrollmentID, EnrollmentCertificatePEM: enrollmentCertificate,
		ClientKeyPEM: clientIdentity.keyPEM, VolumeID: volumeID, AuthorityGeneration: o.authorityGeneration,
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return client, time.UnixMilli(o.authExpiresAtMs), nil
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
	if o.workspaceReconcileFD != 0 {
		return e.runWorkspaceReconcile(o.workspaceReconcileFD, positionals[0], positionals[1])
	}
	if o.workspaceGateFD != 0 || o.workspaceOwnerFD != 0 || o.workspaceBootstrapFD != 0 || o.workspaceClockFD != 0 || o.workspaceReadyFD != 0 {
		return e.runWorkspaceMount(&o, positionals[0], positionals[1])
	}
	if err := refuseManagedWorkspaceMount(&o); err != nil {
		return e.fail("mount", err)
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
	parentIdentity, err := loadClientTLSIdentity(o.clientCertPath, o.clientKeyPath)
	if err != nil {
		return e.usageError("mount", err)
	}
	if _, _, err := o.automaticEnrollment(parentIdentity, volumeID); err != nil {
		return e.usageError("mount", err)
	}

	stateDir, err := e.mountStateDir()
	if err != nil {
		return e.fail("mount", err)
	}
	if runtime.GOOS == "darwin" && (o.strategy == "auto" || o.strategy == "fskit") {
		if err := requireSupportedFSKit(); err != nil {
			return e.fail("mount", err)
		}
	}
	if err := e.validateMountOwnership(stateDir, volumeID, mountPath); err != nil {
		return e.fail("mount", err)
	}
	selectedStrategy, err := resolveStrategy(o.strategy, runtime.GOOS)
	if err != nil {
		return e.fail("mount", err)
	}
	var operation *mountOperation
	if o.opLockFD > 0 {
		operation, err = adoptMountOperation(o.opLockFD, stateDir, mountPath)
	} else {
		operation, err = acquireMountOperation(stateDir, mountPath, volumeID, selectedStrategy)
	}
	if err != nil {
		return e.fail("mount", err)
	}
	operation.volumeID = volumeID
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

func mountOwnershipLockName(volumeID string) string {
	sum := sha256.Sum256([]byte(volumeID))
	return "mount-ownership-" + hex.EncodeToString(sum[:16]) + ".lock"
}

// validateMountOwnership enforces the machine/account contract of one live
// mount per volume. Every durable source is inventoried strictly:
// state, operation intents, kernel mounts, and daemon attaches. An
// uncorrelated PortableFS kernel mount is uncertainty, not permission.
func (e *cmdEnv) validateMountOwnership(stateDir, volumeID, mountPath string) error {
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
		if state.MountPath != mountPath && state.VolumeID == volumeID {
			return fmt.Errorf(
				"%s already has a mount record at %s; one live mount per volume is supported on this machine (run `portablefs umount %s` first)",
				volumeID, state.MountPath, state.MountPath,
			)
		}
	}
	for i := range intents {
		intent := &intents[i]
		knownPaths[intent.MountPath] = struct{}{}
		if intent.MountPath != mountPath && intent.VolumeID == volumeID {
			return fmt.Errorf(
				"%s has an incomplete %s operation at %s; run `portablefs umount %s` before mounting this volume elsewhere",
				volumeID, intent.Phase, intent.MountPath, intent.MountPath,
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
		// Kernel absence does not retire daemon authority for this path. A
		// remount would spend a fresh capability before registration discovers
		// the old attach; umount owns the exact durable recovery instead.
		if attach.MountPath == mountPath {
			return fmt.Errorf(
				"mount path %s already has durable daemon attach %s; run `portablefs umount %s` first",
				mountPath, attach.AttachRef, mountPath,
			)
		}
		if attach.VolumeID == volumeID {
			return fmt.Errorf(
				"%s already has durable daemon attach %s at %s; run `portablefs umount %s` first",
				volumeID, attach.AttachRef, attach.MountPath, attach.MountPath,
			)
		}
	}

	cfg, err := fixedFSKitConfig()
	if err != nil {
		return err
	}
	if _, statErr := os.Lstat(cfg.controlSock); statErr == nil {
		ctl, err := connectCompatiblePortablefsd(cfg, e.version)
		if err != nil {
			return fmt.Errorf("strict daemon identity inventory: %w", err)
		}
		defer ctl.close()
		attaches, err := ctl.listAttaches()
		if err != nil {
			return fmt.Errorf("strict daemon attach inventory: %w", err)
		}
		for _, attach := range attaches {
			if attach.MountPath == mountPath {
				return fmt.Errorf(
					"mount path %s already has live daemon attach %s; run `portablefs umount %s` first",
					mountPath, attach.AttachRef, mountPath,
				)
			}
			persisted, ok := persistedByRef[attach.AttachRef]
			if !ok || persisted.VolumeID != attach.VolumeID || persisted.MountPath != attach.MountPath {
				return fmt.Errorf("live daemon attach %s is inconsistent with strict durable inventory", attach.AttachRef)
			}
			if attach.VolumeID == volumeID {
				return fmt.Errorf(
					"%s already has daemon attach %s at %s; run `portablefs umount %s` first",
					volumeID, attach.AttachRef, attach.MountPath, attach.MountPath,
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
	cfg, err := fixedFSKitConfig()
	if err != nil {
		return nil, nil
	}
	if _, err := os.Lstat(cfg.controlSock); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	ctl, err := connectInstalledPortablefsd(cfg)
	if err != nil {
		return nil, err
	}
	defer ctl.close()
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
		// path is canonical, and the caller can proceed to the detach.
		//
		// The kernel records the RESOLVED mount point — the healthy path below
		// canonicalizes through EvalSymlinks before anything is mounted — so
		// the dead path must be resolved the same way first or a symlinked
		// ancestor (/tmp on macOS) makes the table lookup miss and turns the
		// one state detaching exists for into a refusal. Only the ancestors
		// are resolved; they live outside the dead filesystem, so resolving
		// them never enters it.
		if resolvedParent, resolveErr := filepath.EvalSymlinks(filepath.Dir(absolute)); resolveErr == nil {
			absolute = filepath.Clean(filepath.Join(resolvedParent, filepath.Base(absolute)))
		}
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
	}
	if o.dataPlaneServerName != "" {
		childArgs = append(childArgs, "--data-plane-server-name", o.dataPlaneServerName)
	}
	if o.dataPlaneCAPath != "" {
		childArgs = append(childArgs, "--data-plane-ca", o.dataPlaneCAPath)
	}
	if o.enrollmentID != "" {
		childArgs = append(childArgs,
			"--manager-url", o.managerURL,
			"--manager-server-name", o.managerServerName,
			"--manager-ca", o.managerCAPath,
			"--mount-enrollment-id", o.enrollmentID,
			"--mount-enrollment-cert", o.enrollmentCertPath,
			"--authority-generation", strconv.FormatUint(o.authorityGeneration, 10),
			"--auth-expires-at-ms", strconv.FormatInt(o.authExpiresAtMs, 10),
		)
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
	fmt.Fprintf(e.stdout, "mounted %s at %s (%s, pid %d)\n", ready.VolumeID, ready.MountPath, ready.Strategy, ready.PID)

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
	if err := refuseManagedWorkspaceMount(o); err != nil {
		return e.fail("mount", err)
	}
	// Leave a full minute for exact rollback before the parent's three-minute
	// startup limit. This bound starts before attach and enrollment work.
	startupDeadline := time.Now().Add(2 * time.Minute)
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
	// A v3 mount capability is single-use. Automatic hosted reauthorization, when
	// requested, is owned by the distinct enrollment client below; this cleanup
	// state tracks only the initial Manager mount request until the local attach
	// has durably taken ownership.
	startupCleanupSafe := true
	startupCleanupComplete := false
	var enrollmentClient *mountenrollment.Client
	var initialAuthorizationDeadline time.Time
	enrollmentCloseAttempted := false
	automaticOwnerEstablished := false
	closeFailedStartupEnrollment := func() {
		if enrollmentClient == nil || enrollmentCloseAttempted {
			return
		}
		if !automaticEnrollmentCanCloseAfterStartupFailure(automaticOwnerEstablished, startupCleanupComplete) {
			log.Printf("portablefs mount: retaining failed-startup enrollment because its local attach is not yet proven terminal")
			return
		}
		enrollmentCloseAttempted = true
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := enrollmentClient.Close(closeCtx, "mount startup rolled back")
		cancel()
		if closeErr != nil {
			log.Printf("portablefs mount: failed-startup enrollment could not be closed and will expire or be revoked remotely: %v", closeErr)
		}
	}
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
			fmt.Fprintf(e.stdout, "mounted %s at %s (%s); Ctrl-C unmounts\n", ready.VolumeID, ready.MountPath, ready.Strategy)
		}
	}
	failReady := func(err error) int {
		if startupCleanupSafe && !startupCleanupComplete && operation != nil {
			if closeErr := operation.close(true); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("finalize clean failed startup: %w", closeErr))
			} else {
				operation = nil
				startupCleanupComplete = true
			}

		}
		closeFailedStartupEnrollment()
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
		mountOwnershipLockName(volumeID),
	)
	if err != nil {
		return failReady(fmt.Errorf("%s already has a mount startup or live session on this machine: %w", volumeID, err))
	}
	defer ownershipGuard.Close()
	if err := e.validateMountOwnership(stateDir, volumeID, mountPath); err != nil {
		return failReady(err)
	}

	strategy, err := resolveStrategy(o.strategy, runtime.GOOS)
	if err != nil {
		return failReady(err)
	}
	if strategy == "fskit" {
		if err := requireSupportedFSKit(); err != nil {
			return failReady(err)
		}
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
	enrollmentClient, initialAuthorizationDeadline, err = o.automaticEnrollment(clientIdentity, volumeID)
	if err != nil {
		return failReady(err)
	}
	dataPlaneCAPath, dataPlaneCASHA256, err := transport.materializePrivateCA(stateDir)
	if err != nil {
		return failReady(err)
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
		SchemaVersion:        mountStateSchemaVersion,
		MountPath:            mountPath,
		VolumeID:             volumeID,
		PID:                  os.Getpid(),
		ProcessStartIdentity: processIdentity,
		Strategy:             strategy,
		Engine:               engine,
		MountInstanceID:      mountInstanceID,
		MountTargetDevice:    mountTargetIdentity.device,
		MountTargetInode:     mountTargetIdentity.inode,
		AuthorityURL:         authorityURL,
		StartedAtMs:          operation.startedAtMs,
		DataPlaneCAPath:      dataPlaneCAPath,
		DataPlaneCASHA256:    dataPlaneCASHA256,
		DataPlaneTransport:   transport.Mode,
		DataPlaneServerName:  transport.ServerName,
		MountMechanism:       mountMechanism,
		FUSEHelperPath:       fuseHelperPath,
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
			current.VolumeID != state.VolumeID {
			return fmt.Errorf("failed-startup mount state identity changed; refusing to remove it")
		}
		if err := removeMountState(stateDir, mountPath); err != nil {
			return fmt.Errorf("remove failed-startup mount state: %w", err)
		}
		return nil
	}
	publishCleanedResources := func() error {
		// This unconditional checkpoint bridges exact local teardown to
		// state deletion.
		if err := operation.writeIntent("resources-cleaned", 0, ""); err != nil {
			return fmt.Errorf("publish durable resources-cleaned fact: %w", err)
		}
		return nil
	}
	finalizeCleanedStartup := func(cause error) int {
		// Exact kernel/attach cleanup precedes deletion of either recovery anchor.
		if err := publishCleanedResources(); err != nil {
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
		MountPath: mountPath, VolumeID: volumeID,
	}

	switch strategy {
	case "fuse":
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sig)
		attachCtx, stopAttachSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stopAttachSignals()
		if err := revalidatePinnedMountTarget(mountPath, mountTargetIdentity); err != nil {
			return failReady(err)
		}
		startupCleanupSafe = false
		// The v3 engine. The mount capability is single-use — its nonce is
		// spent by the attach below — so from here every failure path must
		// tear down exactly, never retry the attach.
		// The Linux half of the revocation observation contract. The engine
		// self-revokes on its own terminal edges — a coherence violation, a
		// fenced session, a repair budget it could not keep — and this is what
		// turns that into a durable, machine-readable record. Without it a
		// revoked mount whose MNT_DETACH failed stayed installed in the
		// namespace with `portablefs mounts` still calling it live.
		recordRevocation := func(revocation mountRevocation) {
			if !setMountRevoked(stateDir, mountPath, revocation.reason, revocation.detail, time.Now().UnixMilli()) {
				log.Printf("portablefs mount: could not record the revoked status for %s (%s)", mountPath, revocation.reason)
			}
			log.Printf("portablefs mount: %s self-revoked (%s): %s", mountPath, revocation.reason, revocation.detail)
			if !revocation.kernelStateWithdrawn {
				log.Printf("portablefs mount: %s is revoked but its kernel mount could not be withdrawn; "+
					"the authority's strict membership for this session must be discharged explicitly", mountPath)
			}
		}
		m, authorityAttached, startupClean, err := mountFUSEv3(attachCtx, fuseV3Config{
			addr: authorityURL, token: mountToken, transport: transport,
			identity: clientIdentity,
			volumeID: volumeID, mountPath: mountPath, mountInstanceID: mountInstanceID,
			backingRoot:            localDirsBackingRoot(stateDir, volumeID),
			requireMountEnrollment: enrollmentClient != nil,
			onRevoked:              recordRevocation,
		})
		attachInterrupted := attachCtx.Err()
		stopAttachSignals()
		automaticOwnerEstablished = enrollmentClient != nil && authorityAttached
		if err != nil {
			if attachInterrupted != nil {
				err = errors.Join(errors.New("mount startup interrupted"), err)
			}
			if startupClean {
				return finalizeCleanedStartup(err)
			}
			return failReady(err)
		}
		mountGone := make(chan struct{})
		go func() { m.Wait(); close(mountGone) }()
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
		var unmountMu sync.Mutex
		requestUnmount := func() error {
			unmountMu.Lock()
			defer unmountMu.Unlock()
			return m.Unmount()
		}
		var reauthorizationControl fuseReauthorizationControl
		var renewalCancel context.CancelFunc
		var renewalDone chan error
		renewalFailedEarly := make(chan error, 1)
		var renewalOwner *mountenrollment.Renewer
		initialRenewal := make(chan struct{}, 1)
		stopRenewal := func() error {
			if renewalCancel == nil {
				return nil
			}
			renewalCancel()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			var err error
			select {
			case err = <-renewalDone:
			case <-timer.C:
				err = errAutomaticRenewalStopTimeout
			}
			renewalCancel = nil
			return err
		}
		cleanupMountedFUSE := func(cause error) int {
			if renewalErr := stopRenewal(); renewalErr != nil {
				cause = errors.Join(cause, renewalErr)
			}
			if reauthorizationControl != nil {
				if controlErr := reauthorizationControl.Close(); controlErr != nil {
					cause = errors.Join(cause, fmt.Errorf("close reauthorization control: %w", controlErr))
				}
			}
			// Startup rollback runs the same exact teardown as a live unmount:
			// kernel detach, then session release with its recorded verdict.
			select {
			case <-mountGone:
			default:
				if unmountErr := requestUnmount(); unmountErr != nil {
					return failReady(errors.Join(cause, fmt.Errorf("transactional startup FUSE unmount failed: %w", unmountErr)))
				}
			}
			<-mountGone
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
		authorizationSessionID := m.AuthorizationSessionID()
		if len(authorizationSessionID) != 22 {
			return cleanupMountedFUSE(fmt.Errorf("authority attach returned no hosted reauthorization session identity"))
		}
		if enrollmentClient != nil {
			authorityDeadline := m.InitialAuthorizationDeadline()
			if !authorityDeadline.Equal(initialAuthorizationDeadline) {
				return cleanupMountedFUSE(fmt.Errorf("authority installed authorization deadline %s, Manager response declared %s", authorityDeadline.UTC().Format(time.RFC3339Nano), initialAuthorizationDeadline.UTC().Format(time.RFC3339Nano)))
			}
			initialAuthorizationDeadline = authorityDeadline
		}
		state.AuthorizationSessionID = authorizationSessionID
		var externalReauthorization fuseReauthorizationHandler
		if enrollmentClient == nil {
			externalReauthorization = m.Reauthorize
		} else {
			state.MountEnrollmentID = o.enrollmentID
			state.AuthorizationDeadlineAtMs = initialAuthorizationDeadline.UnixMilli()
		}
		// Every Linux supervisor exposes the exact live loss counter. Automatic
		// enrollment still owns renewal exclusively; a nil renewal handler makes
		// that policy hold at the socket as well as the public CLI.
		reauthorizationControl, err = startFuseReauthorizationControl(externalReauthorization, func() (mountLossSnapshot, error) {
			stats := m.WritebackStats()
			if stats == nil {
				return mountLossSnapshot{}, errors.New("live writeback state unavailable")
			}
			return mountLossSnapshot{MountInstanceID: mountInstanceID, LossSequence: strconv.FormatUint(stats.LossSequence, 10)}, nil
		})
		if err != nil {
			return cleanupMountedFUSE(err)
		}
		state.ReauthorizationControlSocket = reauthorizationControl.SocketPath()
		ready.AuthorizationSessionID = authorizationSessionID
		if err := writeMountState(stateDir, state); err != nil {
			return cleanupMountedFUSE(err)
		}
		if enrollmentClient != nil {
			renewalCtx, cancel := context.WithCancel(context.Background())
			renewalCancel = cancel
			renewalDone = make(chan error, 1)
			renewalEvents, eventLogErr := mountlog.New(e.stderr, "linux-fuse", mountInstanceID)
			if eventLogErr != nil {
				return cleanupMountedFUSE(fmt.Errorf("initialize per-mount renewal event log: %w", eventLogErr))
			}
			renewalOwner = &mountenrollment.Renewer{
				Source: enrollmentClient,
				Observe: func(event mountenrollment.RenewalEvent) {
					recordFUSERenewalEvent(renewalEvents, stateDir, mountPath, o.enrollmentID, event, m.WritebackStats())
					if event.Kind == mountenrollment.RenewalSucceeded {
						select {
						case initialRenewal <- struct{}{}:
						default:
						}
					}
				},
			}
			go func() {
				renewErr := renewalOwner.Run(renewalCtx, authorizationSessionID, initialAuthorizationDeadline, m.Reauthorize)
				if renewErr != nil {
					// Failure is observable before busy detach retries finish. Startup can
					// now cancel that loop and own one exact rollback attempt.
					renewalFailedEarly <- renewErr
					setMountStatus(stateDir, mountPath, mountStatusCredentialExpired, time.Now().UnixMilli())
					log.Printf("portablefs mount: automatic reauthorization ended the mount: %v", renewErr)
					backoff := 250 * time.Millisecond
					attempts := 0
				detachRetry:
					for {
						select {
						case <-renewalCtx.Done():
							break detachRetry
						case <-mountGone:
							break detachRetry
						default:
						}
						attempts++
						if unmountErr := requestUnmount(); unmountErr == nil {
							break
						} else if attempts == 1 || attempts%12 == 0 {
							log.Printf("portablefs mount: retrying exact detach after automatic reauthorization failure: %v", unmountErr)
						}
						select {
						case <-renewalCtx.Done():
							break detachRetry
						case <-mountGone:
							break detachRetry
						case <-time.After(backoff):
						}
						if backoff < 5*time.Second {
							backoff *= 2
							if backoff > 5*time.Second {
								backoff = 5 * time.Second
							}
						}
					}
				}
				renewalDone <- renewErr
			}()
		}
		if enrollmentClient != nil {
			// The owner signals a completed installer; its typed snapshot remains
			// the authority for publication, independently of event logs/sockets.
			if err := awaitInitialFUSERenewal(initialRenewal, renewalFailedEarly, mountGone, sig, startupDeadline); err != nil {
				return cleanupMountedFUSE(err)
			}
			proof := renewalOwner.Readiness()
			if err := validateFUSERenewalReadiness(proof, true, authorizationSessionID, m.AuthorizationDeadline(), time.Now()); err != nil {
				return cleanupMountedFUSE(errors.New("initial renewal readiness unavailable"))
			}
			ready.Renewal = &proof
		} else {
			proof := mountenrollment.RenewalReadiness{State: "not-required"}
			ready.Renewal = &proof
		}
		select {
		case <-sig:
			return cleanupMountedFUSE(errors.New("mount startup interrupted"))
		default:
		}
		if err := operation.writeIntent("live", os.Getpid(), processIdentity); err != nil {
			return cleanupMountedFUSE(err)
		}
		if err := operation.close(false); err != nil {
			return cleanupMountedFUSE(fmt.Errorf("release mount operation lock before readiness: %w", err))
		}
		report(ready)
		go func() {
			for {
				select {
				case <-mountGone:
					return
				case <-sig:
				}
				// EBUSY keeps the mount up; the next signal retries. Accepted
				// delegated writes can still be buffered. Exact teardown owns
				// their drain and reports any durability failure or loss.
				if err := requestUnmount(); err != nil {
					log.Printf("portablefs mount: shutdown request refused: %v", err)
					continue
				}
				return
			}
		}()
		<-mountGone // signal or external umount; supervision began at kernel install
		renewalErr := stopRenewal()
		renewalStopTimedOut := errors.Is(renewalErr, errAutomaticRenewalStopTimeout)
		renewalFailed := renewalErr != nil && !renewalStopTimedOut
		if reauthorizationControl != nil {
			if err := reauthorizationControl.Close(); err != nil {
				return e.fail("mount", fmt.Errorf("kernel mount is gone but reauthorization control did not close: %w", err))
			}
		}
		// Close releases the authority session. After an external unmount it
		// also delivers the mount-absence proof; after this supervisor's own
		// Unmount it only reports any recorded fatal session verdict.
		if waitErr := m.Close(); waitErr != nil {
			return e.fail("mount", fmt.Errorf("kernel mount is gone but FUSE teardown did not complete; state and intent were preserved for explicit reconciliation: %w", waitErr))
		}
		if err := publishCleanedResources(); err != nil {
			return e.fail("mount", fmt.Errorf("kernel mount is gone but exact resource finalization did not complete; state and intent were preserved: %w", err))
		}
		if err := removeMountState(stateDir, mountPath); err != nil {
			return e.fail("mount", fmt.Errorf("mount is gone but its state record could not be removed: %w", err))
		}
		if err := operation.close(true); err != nil {
			return e.fail("mount", fmt.Errorf("finalize clean mount operation: %w", err))
		}
		operation = nil
		if enrollmentClient != nil {
			closeReason := "mount detached"
			if renewalFailed {
				closeReason = "automatic reauthorization failed closed"
			}
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			closeErr := enrollmentClient.Close(closeCtx, closeReason)
			cancel()
			if closeErr != nil {
				log.Printf("portablefs mount: detached mount enrollment could not be closed and will expire or be revoked remotely: %v", closeErr)
			}
		}
		if renewalStopTimedOut {
			return e.fail("mount", fmt.Errorf("mount detached cleanly but its automatic renewal owner did not stop: %w", renewalErr))
		}
		if renewalFailed {
			return e.fail("mount", fmt.Errorf("mount failed closed after automatic reauthorization failure: %w", renewalErr))
		}
		return 0

	case "fskit":
		fskitCfg, err := fixedFSKitConfig()
		if err != nil {
			return failReady(err)
		}
		operation.fsType = fskitCfg.fsType
		ctl, err := e.ensureFskitDaemon(fskitCfg, filepath.Dir(stateDir))
		if err != nil {
			return failReady(err)
		}
		defer ctl.close()
		attachRef, err := mountid.NewAttachRef()
		if err != nil {
			return failReady(fmt.Errorf("generate stable FSKit attach identity: %w", err))
		}
		operation.attachRef = attachRef
		if err := operation.writeIntent("attaching", os.Getpid(), processIdentity); err != nil {
			return failReady(err)
		}
		startupCleanupSafe = false
		var daemonEnrollment *fskitV3MountEnrollmentRequest
		if enrollmentClient != nil {
			managerCA, readErr := readBoundedRegularFile(o.managerCAPath, false)
			if readErr != nil {
				return failReady(fmt.Errorf("read --manager-ca: %w", readErr))
			}
			enrollmentCertificate, readErr := readBoundedRegularFile(o.enrollmentCertPath, false)
			if readErr != nil {
				return failReady(fmt.Errorf("read --mount-enrollment-cert: %w", readErr))
			}
			daemonEnrollment = &fskitV3MountEnrollmentRequest{
				ManagerURL: o.managerURL, ManagerServerName: o.managerServerName, ManagerCAPEM: string(managerCA),
				EnrollmentID: o.enrollmentID, EnrollmentCertificatePEM: string(enrollmentCertificate),
				AuthorityGeneration:             o.authorityGeneration,
				InitialAuthorizationExpiresAtMs: o.authExpiresAtMs,
			}
		}
		// The daemon-owned v3 attach: portablefsd dials the authority under
		// this exact transport with the mutual-TLS identity below, declares the
		// strict barrier contract, and receives the current required attach
		// shape. Credentials never enter the FSKit extension.
		attachReply, err := ctl.ensureAttachDetailed(fskitEnsureAttachRequest{
			AttachRef:            attachRef,
			VolumeID:             volumeID,
			AuthorityURL:         authorityURL,
			AuthToken:            mountToken,
			AuthTokenExpiresAtMs: o.authExpiresAtMs,
			DataPlaneTransport:   transport.Mode,
			DataPlaneServerName:  transport.ServerName,
			TLSCAPEM:             transport.CAPEM,
			TLSCASHA256:          transport.CASHA256,
			MountPath:            mountPath,
			V3: fskitV3AttachRequest{
				ClientCertPEM: string(clientIdentity.certPEM),
				ClientKeyPEM:  string(clientIdentity.keyPEM),
				// The daemon does not join the route adoption protocol, so the
				// revision declared here is the empty rule set's. A volume that
				// declares machine-local routes is refused by the authority with
				// both revisions named; declare the routes' removal or mount it
				// from Linux, which adopts them.
				RoutesRevision: emptyRoutesRevision(),
				Enrollment:     daemonEnrollment,
			},
		})
		if err != nil {
			return failReady(err)
		}
		automaticOwnerEstablished = enrollmentClient != nil
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
			if _, err := unmountFSKitWithKernelOutcome(&state, func() error { return ctl.unmountAttach(attachRef) }); err != nil {
				return failReady(errors.Join(cause, fmt.Errorf("daemon-owned exact FSKit cleanup for attach %s failed: %w", attachRef, err)))
			}
			return finalizeCleanedStartup(cause)
		}
		if err := ctl.preflightAttach(attachRef); err != nil {
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
		attestReadiness := func() error { return ctl.requireFrontendReady(attachRef) }
		if err := waitForFSKitReady(
			mountPath,
			fskitCfg.fsType,
			fskitidentity.ResourcePrefix+attachRef,
			attestReadiness,
			15*time.Second,
		); err != nil {
			return failAfterKernelMount(err)
		}
		releaseMountTargetPin()
		if len(attachReply.AuthorizationSessionID) != 22 {
			return failAfterKernelMount(fmt.Errorf("portablefsd returned no hosted reauthorization session identity"))
		}
		ready.AttachRef = attachRef
		ready.AuthorizationSessionID = attachReply.AuthorizationSessionID
		state.AuthorizationSessionID = attachReply.AuthorizationSessionID
		if enrollmentClient != nil {
			state.MountEnrollmentID = o.enrollmentID
			state.AuthorizationDeadlineAtMs = initialAuthorizationDeadline.UnixMilli()
		}
		if err := writeMountState(stateDir, state); err != nil {
			return failAfterKernelMount(err)
		}
		if err := operation.writeIntent("live", os.Getpid(), processIdentity); err != nil {
			return failAfterKernelMount(err)
		}
		if err := operation.close(false); err != nil {
			return failAfterKernelMount(fmt.Errorf("release mount operation lock before readiness: %w", err))
		}
		watcher, err := newFSKitMountWatcher()
		if err != nil {
			return failReady(fmt.Errorf("establish kernel mount supervision; state and intent were preserved: %w", err))
		}
		report(ready)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sig)
		if err := superviseFSKit(&state, sig, func() (fsKitMountWatcher, error) { return watcher, nil }, recordedKernelMountPresent,
			func() error { return ctl.unmountAttach(attachRef) },
			func() error { return finalizeExternallyAbsentFSKit(ctl, &state) }, e.stderr); err != nil {
			return e.fail("mount", err)
		}
		// A concurrent CLI unmount owns its cleanup transaction and waits for this
		// supervisor to exit. Never compete with its held operation lock.
		cleanupOperation, err := acquireMountOperation(stateDir, mountPath, "", "")
		if errors.Is(err, syscall.EWOULDBLOCK) {
			operation = nil
			return 0
		}
		if err != nil {
			return e.fail("mount", err)
		}
		operation = cleanupOperation
		current, err := readMountState(stateDir, mountPath)
		if err != nil {
			return e.fail("mount", err)
		}
		if current == nil && operation.prior == nil {
			if err := operation.close(true); err != nil {
				return e.fail("mount", fmt.Errorf("finalize absent supervisor records: %w", err))
			}
			operation = nil
			return 0
		}
		if current == nil || current.MountInstanceID != state.MountInstanceID || current.AttachRef != state.AttachRef || current.PID != state.PID {
			return e.fail("mount", fmt.Errorf("supervisor mount record ownership changed; state and intent were preserved"))
		}
		hydrateMountOperationFromState(operation, current)
		if operation.prior != nil {
			prior := *operation.prior
			prior.Phase = "resources-cleaned"
			if err := verifyCleanupIntentMatchesState(&prior, current); err != nil {
				return e.fail("mount", fmt.Errorf("supervisor mount intent ownership changed; state and intent were preserved: %w", err))
			}
		}
		if err := publishCleanedResources(); err != nil {
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

// Kernel lifetime and shutdown remain supervised during initial network renewal.
func awaitInitialFUSERenewal(installed <-chan struct{}, failed <-chan error, gone <-chan struct{}, signals <-chan os.Signal, deadline time.Time) error {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-installed:
		// A queued success cannot win a select against an already elapsed bound.
		if !time.Now().Before(deadline) {
			return errors.New("initial automatic renewal exceeded the two-minute startup bound")
		}
		return nil
	case err := <-failed:
		return fmt.Errorf("initial automatic renewal failed: %w", err)
	case <-gone:
		return errors.New("kernel mount ended before initial renewal")
	case <-signals:
		return errors.New("mount startup interrupted")
	case <-timer.C:
		return errors.New("initial automatic renewal exceeded the two-minute startup bound")
	}
}

func validateFUSERenewalReadiness(proof mountenrollment.RenewalReadiness, hosted bool, session string, deadline, now time.Time) error {
	if !proof.Ready(!hosted, mountenrollment.Permit{}, session, deadline) || hosted && !deadline.After(now) {
		return errors.New("initial renewal installation and deadline not proven")
	}
	return nil
}

func recordFUSERenewalEvent(events *mountlog.Writer, stateDir, mountPath, enrollmentID string, event mountenrollment.RenewalEvent, writeback *mountlog.WritebackStats) {
	if err := events.WriteRenewal(event, writeback); err != nil {
		log.Printf("portablefs mount: write renewal event: %v", err)
	}
	status := event.Status
	updated, stateErr := updateMountState(stateDir, mountPath, func(current *mountState) {
		if current.MountEnrollmentID != enrollmentID {
			return
		}
		current.AuthorizationDeadlineAtMs = status.AuthorizationDeadline.UnixMilli()
		current.LastReauthorizationAtMs = 0
		if !status.LastSuccess.IsZero() {
			current.LastReauthorizationAtMs = status.LastSuccess.UnixMilli()
		}
		current.NextReauthorizationAtMs = 0
		if !status.NextAttempt.IsZero() {
			current.NextReauthorizationAtMs = status.NextAttempt.UnixMilli()
		}
		current.ReauthorizationFailures = status.ConsecutiveFailures
		current.ReauthorizationError = status.LastError
	})
	if stateErr != nil {
		log.Printf("portablefs mount: persist renewal status: %v", stateErr)
	} else if !updated {
		log.Printf("portablefs mount: renewal status had no matching mount record")
	}
}

func waitForFSKitReady(
	mountPath, expectedFSType, expectedSource string,
	attestReadiness func() error,
	timeout time.Duration,
) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		retry, err := proveFSKitReadyOnce(
			func() error {
				return verifyFSKitMountIdentity(mountPath, expectedFSType, expectedSource)
			},
			attestReadiness,
		)
		if err == nil {
			return nil
		}
		if !retry {
			return err
		}
		lastErr = err
		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"FSKit mounted %s but policy readiness was not attested within %s: %w",
				mountPath, timeout, lastErr,
			)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// proveFSKitReadyOnce preserves the security-critical
// kernel→policy-witness→kernel order. Once a witness succeeds, any identity
// change is a mount substitution and fails immediately instead of retrying
// against the replacement.
func proveFSKitReadyOnce(verifyIdentity, attestReadiness func() error) (retry bool, err error) {
	if err := verifyIdentity(); err != nil {
		return true, err
	}
	if err := attestReadiness(); err != nil {
		return true, fmt.Errorf("attest the exact FSKit frontend: %w", err)
	}
	if err := verifyIdentity(); err != nil {
		return false, fmt.Errorf("kernel mount identity changed after readiness attestation: %w", err)
	}
	return false, nil
}

func cmdUmount(e *cmdEnv, args []string) int {
	fs := newFlagSet("umount")
	var o commonOpts
	var force bool
	var discardRecord bool
	addCommonFlags(fs, &o)
	fs.BoolVar(&force, "force", false, "force detach the exact recorded mount")
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
	operation, err := acquireMountOperation(stateDir, mountPath, "", "")
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
	if st != nil && operation.prior != nil && operation.prior.Phase == "resources-cleaned" {
		if err := verifyCleanupIntentMatchesState(operation.prior, st); err != nil {
			return e.fail("umount", err)
		}
		if err := removeMountState(stateDir, mountPath); err != nil {
			return e.fail("umount", err)
		}
		if err := finalize(); err != nil {
			return e.fail("umount", err)
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
			reconcileErr := e.reconcileMountIntent(prior, force)
			if reconcileErr != nil {
				return e.fail("umount", fmt.Errorf("reconcile incomplete %s operation: %w; intent was preserved at %s", prior.Phase, reconcileErr, operation.intentPath))
			}
			if err := finalize(); err != nil {
				return e.fail("umount", fmt.Errorf("finalize reconciled mount intent: %w", err))
			}
			if o.jsonOut {
				return e.printJSON(map[string]any{"mountPath": mountPath, "volumeId": prior.VolumeID, "unmounted": true, "tracked": false, "reconciledIntent": true, "forced": force})
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
	if err := operation.writeIntent(intentPhase, intentPID, st.ProcessStartIdentity); err != nil {
		return e.fail("umount", fmt.Errorf("recorded mount state cannot publish an exact unmount intent; nothing was unmounted: %w", err))
	}
	mounted, err := recordedKernelMountPresent(st)
	if err != nil {
		return e.fail("umount", fmt.Errorf("kernel mount identity does not match the PortableFS record; refusing drain, signal, or detach: %w", err))
	}
	if !mounted && !mountProcessMatches(st) {
		if st.Strategy == "fskit" && st.AttachRef != "" {
			if _, err := e.v3FSKitDaemonDetach(st, force); err != nil {
				return e.fail("umount", err)
			}
		}
		if err := publishResourcesCleanedIntent(operation, stateDir, mountPath); err != nil {
			return e.fail("umount", fmt.Errorf("mount resources are gone but their durable cleanup fact could not be published; state and intent were preserved: %w", err))
		}

		if err := removeMountState(stateDir, mountPath); err != nil {
			return e.fail("umount", fmt.Errorf("remove reconciled mount state: %w", err))
		}
		if err := finalize(); err != nil {
			return e.fail("umount", fmt.Errorf("finalize reconciled mount operation: %w", err))
		}
		if o.jsonOut {
			return e.printJSON(map[string]any{"mountPath": mountPath, "volumeId": st.VolumeID, "unmounted": true, "tracked": true, "forced": force})
		}
		fmt.Fprintf(e.stdout, "reconciled stale mount state for %s (volume %s); no unrelated pid was signaled\n", mountPath, st.VolumeID)
		return 0
	}

	outcome := detachNone
	switch st.Strategy {
	case "fskit":
		detached, detachErr := e.v3FSKitDaemonDetach(st, force)
		if detachErr != nil {
			return e.fail("umount", detachErr)
		}
		if detached {
			outcome = detachFSKitDaemon
		}
	case "fuse":
		if !force && mounted {
			if !mountProcessMatches(st) {
				return e.fail("umount", fmt.Errorf("mount process pid %d does not match its recorded start identity; nothing was unmounted", st.PID))
			}
			if err := e.drainBeforeUnmount(st); err != nil {
				return e.fail("umount", err)
			}
			outcome = detachFUSECooperative
		}
	default:
		return e.fail("umount", fmt.Errorf("unsupported mount strategy %q", st.Strategy))
	}

	mounted, err = recordedKernelMountPresent(st)
	if err != nil {
		return e.fail("umount", fmt.Errorf("kernel mount identity changed after drain; refusing unmount: %w", err))
	}
	needsPlatformUnmount, reconcileStale, completionErr := decidePostUnmount(
		mounted,
		outcome,
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
	if err := publishResourcesCleanedIntent(operation, stateDir, mountPath); err != nil {
		return e.fail("umount", fmt.Errorf("mount resources are gone but their durable cleanup fact could not be published; state and intent were preserved: %w", err))
	}

	if err := removeMountState(stateDir, mountPath); err != nil {
		return e.fail("umount", fmt.Errorf("mount is gone but its state record could not be removed: %w", err))
	}
	if err := finalize(); err != nil {
		return e.fail("umount", fmt.Errorf("finalize clean unmount operation: %w", err))
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"mountPath": mountPath, "volumeId": st.VolumeID, "unmounted": true, "tracked": true, "forced": force})
	}
	fmt.Fprintf(e.stdout, "unmounted %s (volume %s)\n", mountPath, st.VolumeID)
	return 0
}

// detachOutcome is the positive completion evidence returned by the strategy
// that owned an unmount. It is deliberately not inferred from process liveness
// or from the final kernel snapshot: absence without one of these outcomes is
// stale-state reconciliation, while absence after one is normal completion.
type detachOutcome uint8

const (
	detachNone detachOutcome = iota
	detachFUSECooperative
	detachFSKitDaemon
)

// decidePostUnmount verifies a strategy's completion claim against the exact
// kernel state. The claim is correctness evidence carried in-process from the
// operation that produced it; logs and PID timing are never inputs.
func decidePostUnmount(mounted bool, outcome detachOutcome) (needsPlatformUnmount, reconcileStale bool, err error) {
	switch {
	case outcome > detachFSKitDaemon:
		return false, false, fmt.Errorf("unmount produced an unknown detach outcome %d; state and intent were preserved", outcome)
	case mounted && outcome == detachFSKitDaemon:
		return false, false, fmt.Errorf("daemon-owned FSKit unmount acknowledged completion but the exact kernel mount remains; state and intent were preserved")
	case mounted && outcome == detachFUSECooperative:
		return false, false, fmt.Errorf("cooperative FUSE unmount completed but the exact kernel mount remains; state and intent were preserved")
	case mounted:
		return true, false, nil
	case outcome != detachNone:
		return false, false, nil
	default:
		return false, true, nil
	}
}

func hydrateMountOperationFromState(operation *mountOperation, state *mountState) {
	operation.volumeID = state.VolumeID
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

}

func verifyCleanupIntentMatchesState(intent *mountIntent, state *mountState) error {
	if intent == nil || state == nil || intent.Phase != "resources-cleaned" {
		return fmt.Errorf("missing cleaned-resource intent or mount state")
	}
	return verifyMountIntentMatchesState(intent, state)
}

func verifyMountIntentMatchesState(intent *mountIntent, state *mountState) error {
	if intent == nil || state == nil {
		return fmt.Errorf("missing mount intent or state")
	}
	if intent.MountPath != state.MountPath || intent.VolumeID != state.VolumeID ||
		intent.Strategy != state.Strategy ||
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
		intent.DataPlaneCASHA256 != state.DataPlaneCASHA256 {
		return fmt.Errorf("cleanup intent and state identify different mount transactions")
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

func (e *cmdEnv) reconcileMountIntent(intent *mountIntent, force bool) error {
	return e.reconcileMountIntentWithProcess(intent, force, true)
}

// The workspace helper has an independent joined-exit or discarded-kernel-boot
// proof. It may inspect the old intent, but must never signal a process whose
// numeric PID/start happens to recur in a new kernel boot.
func (e *cmdEnv) reconcileMountIntentWithProcess(intent *mountIntent, force, ownProcess bool) error {
	if intent == nil {
		return fmt.Errorf("missing intent")
	}
	if intent.Phase == "resources-cleaned" {
		return nil
	}
	if intent.Phase == "starting" {
		// "starting" is durably published before any attach or kernel-mount
		// side effect. Reconciliation is still explicit: prove the intent has
		// no side-effect identity and that its target is not a kernel
		// mountpoint before the caller removes it.
		if intent.MountOwnerPID != 0 || intent.MountInstanceID != "" ||
			intent.AttachRef != "" || intent.KernelMountID != "" {
			return fmt.Errorf("starting intent contains mount side-effect identity")
		}
		boundaries, err := kernelMountBoundaries()
		if err != nil {
			return fmt.Errorf("inventory kernel mounts for starting intent: %w", err)
		}
		for _, boundary := range boundaries {
			if boundary.path == intent.MountPath {
				return fmt.Errorf(
					"target is now a kernel mountpoint (%s from %s), so starting intent cleanup is unsafe",
					boundary.fsType, boundary.source,
				)
			}
		}

		return nil
	}
	st := &mountState{
		MountPath:            intent.MountPath,
		VolumeID:             intent.VolumeID,
		PID:                  intent.MountOwnerPID,
		ProcessStartIdentity: intent.MountOwnerStartIdentity,
		Strategy:             intent.Strategy,
		Engine:               intent.Engine,
		FSType:               intent.FSType,
		AttachRef:            intent.AttachRef,
		MountInstanceID:      intent.MountInstanceID,
		KernelMountID:        intent.KernelMountID,
		MountTargetDevice:    intent.MountTargetDevice,
		MountTargetInode:     intent.MountTargetInode,
		MountMechanism:       intent.MountMechanism,
		FUSEHelperPath:       intent.FUSEHelperPath,
		StartedAtMs:          intent.StartedAtMs,
		AuthorityURL:         intent.AuthorityURL,
		DataPlaneTransport:   intent.DataPlaneTransport,
		DataPlaneServerName:  intent.DataPlaneServerName,
		DataPlaneCAPath:      intent.DataPlaneCAPath,
		DataPlaneCASHA256:    intent.DataPlaneCASHA256,
	}
	if st.Strategy != "fuse" && st.Strategy != "fskit" {
		return fmt.Errorf("intent has unsupported strategy %q", st.Strategy)
	}
	mounted := false
	var err error
	if intent.Phase == "mounting" && st.Strategy == "fuse" && st.KernelMountID == "" {
		kernelMountID, present, err := recoverFUSEMountingIdentity(st.MountPath, st.MountInstanceID)
		if err != nil {
			return fmt.Errorf("recover mounting-phase FUSE kernel identity: %w", err)
		}
		if present {
			operationIdentity, err := processStartIdentity(os.Getpid())
			if err != nil {
				return fmt.Errorf("record reconciliation process identity: %w", err)
			}
			intent.KernelMountID = kernelMountID
			intent.OperationOwnerPID = os.Getpid()
			intent.OperationOwnerStartIdentity = operationIdentity
			intent.UpdatedAtMs = time.Now().UnixMilli()
			stateDir, err := e.mountStateDir()
			if err != nil {
				return err
			}
			_, intentPath := mountOperationPaths(stateDir, intent.MountPath)
			if err := writeMountIntentRecord(intentPath, intent); err != nil {
				return fmt.Errorf("durably publish recovered FUSE kernel identity: %w", err)
			}
			st.KernelMountID = kernelMountID
			mounted, err = recordedKernelMountPresent(st)
			if err != nil {
				return fmt.Errorf("reverify recovered FUSE kernel identity: %w", err)
			}
			if !mounted {
				return fmt.Errorf("recovered FUSE kernel mount disappeared after identity publication")
			}
		}
	} else {
		mounted, err = recordedKernelMountPresent(st)
		if err != nil {
			return fmt.Errorf("kernel identity is not safely classifiable: %w", err)
		}
	}

	if mounted {
		if !ownProcess {
			return fmt.Errorf("workspace intent still owns a kernel mount")
		}
		if st.Strategy == "fskit" {
			if _, err := e.v3FSKitDaemonDetach(st, force); err != nil {
				return err
			}
		} else if !force && mountProcessMatches(st) {
			if err := e.drainBeforeUnmount(st); err != nil {
				return err
			}
		}
		present, err := recordedKernelMountPresent(st)
		if err != nil {
			return err
		}
		if present {
			if err := platformUnmountRecorded(st); err != nil {
				return err
			}
		}
	}
	if st.Strategy == "fskit" && !mounted {
		_, err := unmountFSKitWithKernelOutcome(st, func() error {
			cfg, err := fixedFSKitConfig()
			if err != nil {
				return err
			}
			stateDir, err := e.mountStateDir()
			if err != nil {
				return err
			}
			ctl, err := e.ensureFskitDaemon(cfg, filepath.Dir(stateDir))
			if err != nil {
				return err
			}
			defer ctl.close()
			present, err := verifyRecordedFskitAttach(ctl, st)
			if err != nil {
				return err
			}
			if !present {
				return nil
			}
			if force {
				return ctl.forceDetach(st.AttachRef)
			}
			return ctl.unmountRecordedAttach(st)
		})
		if err != nil {
			return err
		}
	}

	if ownProcess && mountProcessMatches(st) {
		if err := stopMountDaemon(st); err != nil {
			return err
		}
	}
	return nil
}

func (e *cmdEnv) drainBeforeUnmount(st *mountState) error {
	switch {
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

// The daemon owns synchronization and proof delivery. Explicit user force may
// also abandon kernel dirty pages, but cannot erase a failed daemon result.
func (e *cmdEnv) v3FSKitDaemonDetach(st *mountState, force bool) (bool, error) {
	return unmountFSKitWithKernelOutcome(st, func() error {
		cfg, err := fixedFSKitConfig()
		if err != nil {
			return err
		}
		stateDir, err := e.mountStateDir()
		if err != nil {
			return err
		}
		ctl, err := e.ensureFskitDaemon(cfg, filepath.Dir(stateDir))
		if err != nil {
			return explicitForceAfterDaemonError(st, force, err)
		}
		defer ctl.close()
		attach, err := recordedFskitAttachStatus(ctl, st)
		if errors.Is(err, errFskitAttachIdentityMismatch) {
			return err
		}
		if err != nil {
			return explicitForceAfterDaemonError(st, force, err)
		}
		if attach == nil {
			if force {
				return forceFSKitKernelMount(st)
			}
			present, err := recordedKernelMountPresent(st)
			if err != nil || !present {
				return err
			}
			return platformUnmountRecorded(st)
		}
		if force {
			return explicitForceAfterDaemonError(st, true, ctl.forceDetach(st.AttachRef))
		}
		return ctl.unmountRecordedAttach(st)
	})
}

func explicitForceAfterDaemonError(st *mountState, force bool, daemonErr error) error {
	if !force || daemonErr == nil {
		return daemonErr
	}
	return errors.Join(daemonErr, forceFSKitKernelMount(st))
}

// A daemon error cannot establish whether the kernel detach completed. Keep
// exact kernel absence independent of the daemon's remaining transaction work.
func unmountFSKitWithKernelOutcome(st *mountState, unmount func() error) (bool, error) {
	unmountErr := unmount()
	present, classifyErr := recordedKernelMountPresent(st)
	if classifyErr != nil {
		return false, errors.Join(unmountErr, fmt.Errorf("kernel mount presence is unverified: %w; state and intent were preserved", classifyErr))
	}
	if unmountErr != nil {
		if !present {
			return true, fmt.Errorf("kernel mount is absent; daemon unmount completion is unconfirmed (absence-proof delivery or cleanup may be incomplete): %w; state and intent were preserved", unmountErr)
		}
		return false, fmt.Errorf("kernel mount remains present; daemon-owned FSKit unmount failed or is incomplete: %w; state and intent were preserved", unmountErr)
	}
	if present {
		return false, fmt.Errorf("daemon-owned FSKit unmount acknowledged completion but the exact kernel mount remains; state and intent were preserved")
	}
	return true, nil
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
			// An exited supervisor needs no signal, including when exit raced it.
			if mountProcessMatches(st) {
				return err
			}
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

// mountInventoryRow is one `portablefs mounts` row. It is a package-level
// type, not a local one, because it IS the command's JSON contract: the
// fields below are what an agent or the app reads, and a contract that
// cannot be named cannot be tested.
type mountInventoryRow struct {
	MountPath              string `json:"mountPath"`
	MountInstanceID        string `json:"mountInstanceId,omitempty"`
	VolumeID               string `json:"volumeId"`
	PID                    int    `json:"pid"`
	Strategy               string `json:"strategy"`
	AuthorityURL           string `json:"authorityUrl,omitempty"`
	AttachRef              string `json:"attachRef,omitempty"`
	AuthorizationSessionID string `json:"authorizationSessionId,omitempty"`
	StartedAtMs            int64  `json:"startedAtMs"`
	// LocalRoutes and LocalRouteRevision are the machine-local route set
	// a FUSE mount activated and the revision it answers for.
	LocalRoutes        []string `json:"localRoutes,omitempty"`
	LocalRouteRevision string   `json:"localRouteRevision,omitempty"`
	Alive              bool     `json:"alive"`
	Status             string   `json:"status,omitempty"`
	StatusChangedAtMs  int64    `json:"statusChangedAtMs,omitempty"`
	// StatusReason and StatusDetail carry a revocation's machine-readable
	// class and the engine's own sentence. They are the reason a revoked
	// mount is actionable rather than merely alarming, and they are
	// recorded identically by the Linux and macOS supervisors.
	StatusReason string `json:"statusReason,omitempty"`
	StatusDetail string `json:"statusDetail,omitempty"`
	// Health folds pid-liveness and the persisted status:
	// live | stale | credential-expired | revoked | cleanup-required.
	Health string `json:"health"`
	// AttachState is the daemon-reported attach state (degraded carries
	// the daemon's last error in the printed line).
	AttachState string `json:"attachState,omitempty"`
	// SessionTerminal is the authenticated daemon's permanent session verdict.
	// It reports availability and does not authorize automatic force.
	SessionTerminal bool `json:"sessionTerminal,omitempty"`
	// AttachError is the daemon's own lastError for the attach. The
	// printed line already shows it; the JSON view dropped it, so an agent
	// reading --json could see attachState=degraded with no reason at all.
	AttachError string `json:"attachError,omitempty"`
	// CleanupRequired marks a durable operation intent with no matching
	// mount-state record. It is deliberately a first-class inventory row:
	// crash recovery must never disappear from the CLI or app view.
	CleanupRequired           bool   `json:"cleanupRequired,omitempty"`
	OperationPhase            string `json:"operationPhase,omitempty"`
	MountEnrollmentID         string `json:"mountEnrollmentId,omitempty"`
	AuthorizationDeadlineAtMs int64  `json:"authorizationDeadlineAtMs,omitempty"`
	LastReauthorizationAtMs   int64  `json:"lastReauthorizationAtMs,omitempty"`
	NextReauthorizationAtMs   int64  `json:"nextReauthorizationAtMs,omitempty"`
	ReauthorizationFailures   uint64 `json:"reauthorizationFailures,omitempty"`
	ReauthorizationError      string `json:"reauthorizationError,omitempty"`
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
	if e.stateDir == "" {
		managed, err := platformManagedMountStates()
		if err != nil {
			return e.fail("mounts", err)
		}
		states = append(states, managed...)
	}
	intents, err := listMountIntents(stateDir)
	if err != nil {
		return e.fail("mounts", err)
	}
	var daemonView map[string]cliAttachStatus
	for i := range states {
		if states[i].Strategy == "fskit" && states[i].AttachRef != "" {
			daemonView, err = fskitAttachStatuses(e.version)
			if err != nil {
				return e.fail("mounts", err)
			}
			break
		}
	}
	rows := make([]mountInventoryRow, 0, len(states))
	statePaths := make(map[string]struct{}, len(states))
	for i := range states {
		st := &states[i]
		statePaths[st.MountPath] = struct{}{}
		// mountState contains the live access credential because the daemon
		// needs it for renewal. Never embed that persistence object in a
		// presentation type: JSON output is routinely captured in agent logs.
		row := mountInventoryRow{
			MountPath:                 st.MountPath,
			VolumeID:                  st.VolumeID,
			PID:                       st.PID,
			Strategy:                  st.Strategy,
			AuthorityURL:              st.AuthorityURL,
			AttachRef:                 st.AttachRef,
			AuthorizationSessionID:    st.AuthorizationSessionID,
			MountInstanceID:           st.MountInstanceID,
			StartedAtMs:               st.StartedAtMs,
			LocalRoutes:               st.LocalRoutes,
			LocalRouteRevision:        st.LocalRouteRevision,
			Alive:                     mountProcessMatches(st),
			Status:                    st.Status,
			Health:                    e.classifyMount(st),
			StatusChangedAtMs:         st.StatusChangedAtMs,
			StatusReason:              st.StatusReason,
			StatusDetail:              st.StatusDetail,
			MountEnrollmentID:         st.MountEnrollmentID,
			AuthorizationDeadlineAtMs: st.AuthorizationDeadlineAtMs, LastReauthorizationAtMs: st.LastReauthorizationAtMs,
			NextReauthorizationAtMs: st.NextReauthorizationAtMs, ReauthorizationFailures: st.ReauthorizationFailures,
			ReauthorizationError: st.ReauthorizationError,
		}
		if a, ok := daemonView[states[i].AttachRef]; ok {
			row.AttachState = a.State
			row.AttachError = a.LastError
			row.SessionTerminal = a.SessionTerminal
			if a.MountEnrollmentID != "" {
				row.MountEnrollmentID = a.MountEnrollmentID
				row.AuthorizationDeadlineAtMs = a.AuthorizationDeadlineAtMs
				row.LastReauthorizationAtMs = a.LastReauthorizationAtMs
				row.NextReauthorizationAtMs = a.NextReauthorizationAtMs
				row.ReauthorizationFailures = a.ReauthorizationFailures
				row.ReauthorizationError = a.ReauthorizationError
			}
		}
		rows = append(rows, row)
	}
	for i := range intents {
		intent := &intents[i]
		if _, tracked := statePaths[intent.MountPath]; tracked {
			continue
		}
		rows = append(rows, mountInventoryRow{
			MountPath:       intent.MountPath,
			VolumeID:        intent.VolumeID,
			PID:             intent.MountOwnerPID,
			Strategy:        intent.Strategy,
			AttachRef:       intent.AttachRef,
			Health:          "cleanup-required",
			CleanupRequired: true,
			OperationPhase:  intent.Phase,
			MountInstanceID: intent.MountInstanceID,
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
			statusReason:      row.StatusReason,
			statusDetail:      row.StatusDetail,
			attachState:       row.AttachState,
			attachLastError:   row.AttachError,
		})
		extras := ""

		if len(row.LocalRoutes) > 0 {
			extras += "  local-routes:" + strings.Join(row.LocalRoutes, " ") +
				" @" + revisionPrefix(row.LocalRouteRevision)
		}
		fmt.Fprintf(e.stdout, "%s  %s  %s  pid %d%s  %s\n", row.MountPath, row.VolumeID, row.Strategy, row.PID, extras, status)
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
	// statusReason and statusDetail are a revocation's recorded class and the
	// engine's sentence. A revoked mount's whole value to an operator is why,
	// so the word carries both rather than a bare "revoked".
	statusReason string
	statusDetail string
	attachState  string
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
		// A persisted verdict from a mount whose signed authorization already
		// ended. Reauthorization must happen before that deadline, so remounting
		// is now the whole remedy.
		since := ""
		if row.statusChangedAtMs != 0 {
			since = " since " + formatMs(row.statusChangedAtMs)
		}
		return "credential-expired" + since +
			" (this mount's authorization ended and can no longer be renewed; mount again " +
			"with a fresh volume mount capability)"
	case mountStatusRevoked:
		// A revoked mount refuses to serve and can never serve again. It is
		// reported ahead of liveness precisely because it may still look alive:
		// its owner is running and, when the withdrawal escalation could not
		// finish, its kernel mount is still installed.
		since := ""
		if row.statusChangedAtMs != 0 {
			since = " since " + formatMs(row.statusChangedAtMs)
		}
		word := "revoked" + since
		if row.statusReason != "" {
			word += " (" + row.statusReason
			if row.statusDetail != "" {
				word += ": " + row.statusDetail
			}
			word += "; run `portablefs umount " + row.mountPath + "` and mount again)"
			return word
		}
		return word + " (run `portablefs umount " + row.mountPath + "` and mount again)"
	}
	if row.attachState != "degraded" {
		return "live"
	}
	if row.attachLastError != "" {
		return "degraded (" + row.attachLastError + ")"
	}
	return "degraded"
}

func fskitAttachStatuses(cliVersion string) (map[string]cliAttachStatus, error) {
	cfg, err := fixedFSKitConfig()
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(cfg.controlSock); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	ctl, err := connectCompatiblePortablefsd(cfg, cliVersion)
	if err != nil {
		return nil, fmt.Errorf("portablefsd identity: %w", err)
	}
	defer ctl.close()
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

// volumeNamePattern mirrors the authority-side volume id constraints;
// validating client-side turns a refused attach into an immediate, specific
// error.
var volumeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,220}$`)

func validVolumeName(name string) bool { return volumeNamePattern.MatchString(name) }

// formatMs renders a unix-millisecond instant for the human-readable mount
// reports; the zero instant prints as "-".
func formatMs(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).Local().Format(time.RFC3339)
}

// Managed launch remains unavailable until the real kernel, clock and root
// lifecycle owners are integrated. Ordinary launches carry neither descriptor.
func refuseManagedWorkspaceMount(o *mountOpts) error {
	if o.workspaceGateFD == 0 && o.workspaceOwnerFD == 0 {
		return nil
	}
	if runtime.GOOS != "linux" || !o.foreground || o.workspaceGateFD <= 2 || o.workspaceOwnerFD <= 2 || o.workspaceGateFD == o.workspaceOwnerFD {
		return errors.New("managed workspace launch requires Linux foreground mode and two distinct inherited descriptors")
	}
	return errors.New("managed workspace mounts are unavailable until the kernel, clock and root lifecycle owners are integrated")
}
