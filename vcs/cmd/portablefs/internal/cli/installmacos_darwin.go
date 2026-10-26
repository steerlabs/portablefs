//go:build darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/accountsession"
	"github.com/steerlabs/portablefs/vcs/internal/apphost"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"golang.org/x/sys/unix"
)

const (
	macOSActivationReadyRequestTimeout        = 20 * time.Second
	macOSActivationLiveProofTimeout           = 5 * time.Second
	macOSActivationAcceptReconcileTimeout     = 30 * time.Second
	macOSActivationCompletionRequestTimeout   = 10 * time.Second
	macOSActivationResumeRequestTimeout       = 10 * time.Second
	macOSActivationTerminalProofTimeout       = 5 * time.Second
	macOSActivationCompletionReconcileTimeout = 45 * time.Second
	macOSActivationFenceAndAbsenceTimeout     = 20 * time.Second
	// The deadline margin is not operation time. It keeps an outer admission
	// from consuming an exact downstream reserve through scheduling and
	// cancellation-delivery latency at a child deadline boundary.
	macOSActivationDeadlineMargin          = 5 * time.Second
	macOSActivationCompletionReserve       = macOSActivationCompletionReconcileTimeout + macOSActivationDeadlineMargin
	macOSRollbackPostLaunchReserve         = macOSActivationLiveProofTimeout + macOSActivationAcceptReconcileTimeout + macOSActivationCompletionReserve + macOSActivationDeadlineMargin
	macOSFreshRollbackActivationBudget     = macOSActivationReadyRequestTimeout + macOSRollbackPostLaunchReserve + macOSActivationDeadlineMargin
	macOSActivationFenceAndRollbackReserve = macOSActivationFenceAndAbsenceTimeout + macOSFreshRollbackActivationBudget + macOSActivationDeadlineMargin
	macOSActivationPostLaunchReserve       = macOSActivationLiveProofTimeout + macOSActivationAcceptReconcileTimeout + macOSActivationFenceAndRollbackReserve + macOSActivationDeadlineMargin
	macOSActivationTransactionTimeout      = 4 * time.Minute
)

const (
	macOSCLIName       = "portablefs"
	fskitExtensionType = "com.apple.fskit.fsmodule"
)

type macOSInstallCodeIdentityPolicy uint8

const (
	macOSInstallDeveloperIDRelease macOSInstallCodeIdentityPolicy = iota + 1
	macOSInstallDevelopmentHost
)

// macOSInstallLayout is a compile-time product identity, not input. Every
// installer transaction carries exactly one layout through validation,
// process admission, staging, rollback, and terminal reconciliation. A bundle
// can never be accepted by trying multiple layouts.
type macOSInstallLayout struct {
	appName             string
	stagedAppName       string
	appExecutable       string
	extensionExecutable string
	serviceMinimumOS    string
	requiredAppID       string
	codeIdentity        macOSInstallCodeIdentityPolicy
}

func (layout macOSInstallLayout) validate() error {
	for name, value := range map[string]string{
		"app name":             layout.appName,
		"staged app name":      layout.stagedAppName,
		"app executable":       layout.appExecutable,
		"extension executable": layout.extensionExecutable,
		"service minimum OS":   layout.serviceMinimumOS,
	} {
		if value == "" || filepath.Base(value) != value || value == "." || value == ".." {
			return fmt.Errorf("invalid compiled macOS install %s %q", name, value)
		}
	}
	if !strings.HasSuffix(layout.appName, ".app") || strings.HasSuffix(layout.stagedAppName, ".app") {
		return fmt.Errorf("invalid compiled macOS install app names")
	}
	if layout.serviceMinimumOS != "26.0" {
		return fmt.Errorf("invalid compiled macOS service minimum system version %q", layout.serviceMinimumOS)
	}
	if layout.requiredAppID != "" &&
		(filepath.Base(layout.requiredAppID) != layout.requiredAppID ||
			!strings.Contains(layout.requiredAppID, ".")) {
		return fmt.Errorf("invalid compiled macOS install app identifier %q", layout.requiredAppID)
	}
	if layout.codeIdentity != macOSInstallDeveloperIDRelease && layout.codeIdentity != macOSInstallDevelopmentHost {
		return fmt.Errorf("invalid compiled macOS signing policy")
	}
	return nil
}

type preparedMacOSInstall struct {
	stageRoot     string
	stageApp      string
	linkRoot      string
	linkTemp      string
	linkPath      string
	stageID       pathSnapshot
	appID         pathSnapshot
	linkID        pathSnapshot
	appParentID   pathSnapshot
	linkParentID  pathSnapshot
	linkRootID    pathSnapshot
	linkStageID   pathSnapshot
	stageRootID   pathSnapshot
	expectedAppID string
	layout        macOSInstallLayout
	preserve      bool
}

type pathSnapshot struct {
	exists bool
	dev    uint64
	ino    uint64
	mode   os.FileMode
	target string
}

func (p *preparedMacOSInstall) cleanup() {
	if p == nil || p.preserve {
		return
	}
	if p.linkRoot != "" {
		parent, err := openSnapshottedDirectory(filepath.Dir(p.linkRoot), p.linkParentID)
		if err == nil {
			err = removeSnapshottedTreeAt(
				parent,
				filepath.Base(p.linkRoot),
				p.linkRootID,
				nil,
			)
			_ = unix.Close(parent)
		}
		if err != nil {
			p.preserve = true
			return
		}
		p.linkRoot = ""
		p.linkTemp = ""
	}
	if p.stageRoot != "" {
		parent, err := openSnapshottedDirectory(filepath.Dir(p.stageRoot), p.appParentID)
		if err == nil {
			err = removeSnapshottedTreeAt(
				parent,
				filepath.Base(p.stageRoot),
				p.stageRootID,
				nil,
			)
			_ = unix.Close(parent)
		}
		if err != nil {
			p.preserve = true
			return
		}
		p.stageRoot = ""
		p.stageApp = ""
	}
}

func runInstallMacOSApp(e *cmdEnv, sourceApp, requestedLinkDir string) (macOSInstallResult, error) {
	return runInstallMacOSAppWithLayout(
		e,
		sourceApp,
		requestedLinkDir,
		compiledMacOSInstallLayout,
	)
}

func runInstallMacOSAppWithLayout(
	e *cmdEnv,
	sourceApp string,
	requestedLinkDir string,
	layout macOSInstallLayout,
) (macOSInstallResult, error) {
	if err := layout.validate(); err != nil {
		return macOSInstallResult{}, err
	}
	home, err := accountpath.Home()
	if err != nil {
		return macOSInstallResult{}, fmt.Errorf("resolve canonical account home: %w", err)
	}
	sourceApp, err = validateMacOSInstallSourceWithLayout(sourceApp, layout)
	if err != nil {
		return macOSInstallResult{}, err
	}
	expectedAppID, err := sourceMacOSBundleIdentityWithLayout(sourceApp, layout)
	if err != nil {
		return macOSInstallResult{}, err
	}
	appDir := filepath.Join(home, "Applications")
	if err := ensureOwnedDirectoryTree(home, appDir); err != nil {
		return macOSInstallResult{}, fmt.Errorf("prepare application directory: %w", err)
	}
	if err := rejectOrphanedMacOSInstallTransactions(appDir, ""); err != nil {
		return macOSInstallResult{}, err
	}
	linkDir := requestedLinkDir
	if linkDir == "" {
		linkDir = filepath.Join(home, ".local", "bin")
	}
	if err := validateContainedPath(home, linkDir); err != nil {
		return macOSInstallResult{}, fmt.Errorf("invalid --link-dir: %w", err)
	}
	if err := ensureOwnedDirectoryTree(home, linkDir); err != nil {
		return macOSInstallResult{}, fmt.Errorf("prepare CLI link directory: %w", err)
	}
	if err := rejectOrphanedMacOSLinkTransactions(linkDir, ""); err != nil {
		return macOSInstallResult{}, err
	}
	if pathsOverlap(appDir, linkDir) {
		return macOSInstallResult{}, fmt.Errorf(
			"application directory %s and CLI link directory %s must not overlap",
			appDir,
			linkDir,
		)
	}

	destinationApp := filepath.Join(appDir, layout.appName)
	cliLink := filepath.Join(linkDir, macOSCLIName)
	if err := validateStagedBundleForPublicationWithLayout(sourceApp, e.version, expectedAppID, layout); err != nil {
		return macOSInstallResult{}, err
	}
	if err := validateExistingManagedMacOSAppWithLayout(destinationApp, expectedAppID, layout); err != nil {
		return macOSInstallResult{}, err
	}
	if err := preflightMacOSInstallSpace(sourceApp, appDir); err != nil {
		return macOSInstallResult{}, err
	}
	prepared, err := prepareMacOSInstallWithLayout(sourceApp, destinationApp, cliLink, layout)
	if err != nil {
		return macOSInstallResult{}, err
	}
	prepared.expectedAppID = expectedAppID
	defer prepared.cleanup()
	targetRelease, err := macOSServiceReleaseIdentity(prepared.stageApp, e.version)
	if err != nil {
		return macOSInstallResult{}, err
	}
	// Finish every avoidable filesystem/signature/durability check before the
	// old host is asked to unregister. The guarded post-commit rechecks remain
	// necessary for races, but ordinary validation failures never create a
	// service-absent handoff that requires rollback.
	if err := rejectConflictingPFSProviders(home, destinationApp); err != nil {
		return macOSInstallResult{}, err
	}
	if err := validateStagedBundleForPublicationWithLayout(prepared.stageApp, e.version, expectedAppID, layout); err != nil {
		return macOSInstallResult{}, err
	}

	if err := makeStagedMacOSAppDurable(prepared.stageApp); err != nil {
		return macOSInstallResult{}, err
	}

	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return macOSInstallResult{}, err
	}
	var updateSession *hostctl.Session
	var oldRelease hostctl.ReleaseIdentity
	updateCommitted := false
	if prepared.appID.exists {
		oldVersion, err := plistValue(
			filepath.Join(destinationApp, "Contents", "Info.plist"),
			"CFBundleShortVersionString",
		)
		if err != nil {
			return macOSInstallResult{}, fmt.Errorf("read installed release version: %w", err)
		}
		oldRelease, err = macOSServiceReleaseIdentity(destinationApp, oldVersion)
		if err != nil {
			return macOSInstallResult{}, err
		}
		updateContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		updateSession, err = prepareInstalledHostUpdate(
			updateContext,
			destinationApp,
			hostctl.SocketPath(home),
			oldRelease,
			targetRelease,
		)
		cancel()
		if err != nil {
			return macOSInstallResult{}, err
		}
		defer func() {
			if updateCommitted {
				_ = updateSession.Close()
				return
			}
			cancelContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_ = updateSession.Cancel(cancelContext)
		}()
	}

	accountGuard, err := accountsession.AcquireExclusive(stateDir)
	if err != nil {
		return macOSInstallResult{}, fmt.Errorf(
			"acquire exclusive account session guard: %w; quit PortableFS and cleanly unmount every volume before installing",
			err,
		)
	}
	defer accountGuard.Close()
	guard, err := mountlifecycle.AcquireExclusive(stateDir)
	if err != nil {
		return macOSInstallResult{}, fmt.Errorf(
			"acquire exclusive mount lifecycle guard: %w; quit PortableFS and cleanly unmount every volume before installing",
			err,
		)
	}
	defer guard.Close()
	// Hold the exact canonical workspace singleton across publication and
	// rollback. No service execution may enter behind the final absence proof.
	if layout.codeIdentity == macOSInstallDeveloperIDRelease {
		workspaceExclusion, err := mountlifecycle.AcquireNamedExclusive(filepath.Join(stateDir, "workspace"), "service.lock")
		if err != nil {
			return macOSInstallResult{}, fmt.Errorf("workspace singleton release unconfirmed: %w", err)
		}
		defer workspaceExclusion.Close()
		ownerExclusion, err := mountlifecycle.AcquireNamedExclusive(filepath.Join(stateDir, "workspace"), "owner.lock")
		if err != nil {
			return macOSInstallResult{}, fmt.Errorf("workspace VM owner singleton release unconfirmed: %w", err)
		}
		defer ownerExclusion.Close()
		if err := requireWorkspaceResourcesAbsent(stateDir); err != nil {
			return macOSInstallResult{}, err
		}
		for _, name := range []string{"control.sock", "ssh.sock"} {
			if _, err := os.Lstat(filepath.Join(stateDir, "workspace", name)); !os.IsNotExist(err) {
				return macOSInstallResult{}, fmt.Errorf("workspace endpoint absence unconfirmed: %s: %v", name, err)
			}
		}
	}

	if updateSession != nil {
		if err := rejectPreparedMacOSRuntime(
			e,
			stateDir,
			updateSession.HostProcessWitness(),
			filepath.Join(destinationApp, "Contents", "MacOS", layout.appExecutable),
			hostctl.SocketPath(home),
		); err != nil {
			return macOSInstallResult{}, err
		}
		commitContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = updateSession.Commit(commitContext)
		cancel()
		if err != nil {
			// Once commit-exit may have crossed the host, Cancel is no longer a
			// valid recovery. Keep the in-memory token and reconcile the exact
			// durable phase before this installer is allowed to return.
			updateCommitted = true
			return macOSInstallResult{}, recoverFailedMacOSUpdateCommit(
				e,
				prepared,
				destinationApp,
				hostctl.SocketPath(home),
				hostctl.LeasePath(home),
				updateSession.Token(),
				updateSession.HostPID(),
				oldRelease,
				targetRelease,
				fmt.Errorf("commit installed host update preparation: %w", err),
			)
		}
		updateCommitted = true
		if err := waitForPreparedHostAbsence(
			updateSession.HostPID(),
			hostctl.SocketPath(home),
			10*time.Second,
		); err != nil {
			return macOSInstallResult{}, err
		}
		if err := hostctl.RequireLease(
			hostctl.LeasePath(home),
			updateSession.Token(),
			hostctl.PhaseOldAbsent,
			oldRelease,
			targetRelease,
		); err != nil {
			return macOSInstallResult{}, fmt.Errorf("recheck committed host activation lease: %w", err)
		}
	}
	recoverUnpublished := func(failure error) error {
		if updateSession == nil {
			return failure
		}
		return reactivateUnpublishedOldMacOSRelease(
			e,
			prepared,
			destinationApp,
			hostctl.SocketPath(home),
			hostctl.LeasePath(home),
			updateSession.Token(),
			oldRelease,
			targetRelease,
			failure,
		)
	}
	if err := rejectLiveMacOSRuntimeWithLayout(e, stateDir, layout); err != nil {
		return macOSInstallResult{}, recoverUnpublished(err)
	}
	if err := rejectOrphanedMacOSInstallTransactions(appDir, prepared.stageRoot); err != nil {
		return macOSInstallResult{}, recoverUnpublished(err)
	}
	if err := rejectOrphanedMacOSLinkTransactions(linkDir, prepared.linkRoot); err != nil {
		return macOSInstallResult{}, recoverUnpublished(err)
	}
	if err := rejectConflictingPFSProviders(home, destinationApp); err != nil {
		return macOSInstallResult{}, recoverUnpublished(err)
	}
	if err := validateExistingManagedMacOSAppWithLayout(destinationApp, expectedAppID, layout); err != nil {
		return macOSInstallResult{}, recoverUnpublished(err)
	}
	if err := validateStagedBundleForPublicationWithLayout(prepared.stageApp, e.version, expectedAppID, layout); err != nil {
		return macOSInstallResult{}, recoverUnpublished(err)
	}

	if updateSession == nil {
		if err := commitMacOSInstall(prepared, destinationApp); err != nil {
			return macOSInstallResult{}, err
		}
		if err := requestExactMacOSHostForProof(destinationApp); err != nil {
			return macOSInstallResult{}, fmt.Errorf("launch installed PortableFS host: %w", err)
		}
		if err := requireLiveMacOSServiceRelease(destinationApp, targetRelease, true, 15*time.Second); err != nil {
			return macOSInstallResult{}, fmt.Errorf(
				"prove installed PortableFS service release after host launch: %w",
				err,
			)
		}
	} else {
		if err := publishMacOSInstall(prepared, destinationApp); err != nil {
			if requireUnchangedPath(destinationApp, prepared.appID) == nil &&
				requireUnchangedPath(prepared.stageApp, prepared.stageID) == nil {
				return macOSInstallResult{}, recoverUnpublished(err)
			}
			prepared.preserve = true
			return macOSInstallResult{}, fmt.Errorf(
				"publish replacement PortableFS.app: %w; retained transaction at %s because the named release state is ambiguous",
				err,
				prepared.stageRoot,
			)
		}
		if err := activatePublishedMacOSUpdate(
			e,
			prepared,
			destinationApp,
			hostctl.SocketPath(home),
			hostctl.LeasePath(home),
			updateSession.Token(),
			oldRelease,
			targetRelease,
		); err != nil {
			return macOSInstallResult{}, err
		}
	}

	return macOSInstallResult{
		SchemaVersion: 1,
		AppPath:       destinationApp,
		CLILink:       cliLink,
		Version:       e.version,
	}, nil
}

func validateMacOSInstallSource(sourceApp string) (string, error) {
	return validateMacOSInstallSourceWithLayout(sourceApp, compiledMacOSInstallLayout)
}

func validateMacOSInstallSourceWithLayout(
	sourceApp string,
	layout macOSInstallLayout,
) (string, error) {
	if err := layout.validate(); err != nil {
		return "", err
	}
	if !filepath.IsAbs(sourceApp) || filepath.Clean(sourceApp) != sourceApp {
		return "", fmt.Errorf("--source-app must be an absolute clean path: %q", sourceApp)
	}
	if filepath.Base(sourceApp) != layout.appName {
		return "", fmt.Errorf(
			"--source-app must be the exact compiled bundle %s, got %s",
			layout.appName,
			filepath.Base(sourceApp),
		)
	}
	info, err := os.Lstat(sourceApp)
	if err != nil {
		return "", fmt.Errorf("inspect staged app %s: %w", sourceApp, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("staged app %s is not a real directory", sourceApp)
	}
	if err := requireOwnedByEUID(sourceApp, info); err != nil {
		return "", err
	}
	expectedCLI := filepath.Join(sourceApp, "Contents", "Helpers", macOSCLIName)
	cliInfo, err := os.Lstat(expectedCLI)
	if err != nil {
		return "", fmt.Errorf("inspect staged CLI %s: %w", expectedCLI, err)
	}
	if cliInfo.Mode()&os.ModeSymlink != 0 || !cliInfo.Mode().IsRegular() || cliInfo.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("staged CLI %s is not a real executable file", expectedCLI)
	}
	if err := requireOwnedByEUID(expectedCLI, cliInfo); err != nil {
		return "", err
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve installer executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve installer executable identity: %w", err)
	}
	expectedCLI, err = filepath.EvalSymlinks(expectedCLI)
	if err != nil {
		return "", fmt.Errorf("resolve staged CLI identity: %w", err)
	}
	if executable != expectedCLI {
		return "", fmt.Errorf(
			"installer must run the CLI nested in --source-app (running %s, expected %s)",
			executable,
			expectedCLI,
		)
	}
	return sourceApp, nil
}

func sourceMacOSBundleIdentity(sourceApp string) (string, error) {
	return sourceMacOSBundleIdentityWithLayout(sourceApp, compiledMacOSInstallLayout)
}

func sourceMacOSBundleIdentityWithLayout(
	sourceApp string,
	layout macOSInstallLayout,
) (string, error) {
	if err := layout.validate(); err != nil {
		return "", err
	}
	appInfo := filepath.Join(sourceApp, "Contents", "Info.plist")
	extensionInfo := filepath.Join(
		sourceApp,
		"Contents",
		"Extensions",
		layout.extensionExecutable+".appex",
		"Contents",
		"Info.plist",
	)
	appID, err := plistValue(appInfo, "CFBundleIdentifier")
	if err != nil {
		return "", err
	}
	if appID == "" {
		return "", fmt.Errorf("source app has an empty CFBundleIdentifier")
	}
	if layout.requiredAppID != "" && appID != layout.requiredAppID {
		return "", fmt.Errorf(
			"source app identifier %q does not match compiled installer identity %q",
			appID,
			layout.requiredAppID,
		)
	}
	appExecutable, err := plistValue(appInfo, "CFBundleExecutable")
	if err != nil {
		return "", err
	}
	extensionID, err := plistValue(extensionInfo, "CFBundleIdentifier")
	if err != nil {
		return "", err
	}
	extensionExecutable, err := plistValue(extensionInfo, "CFBundleExecutable")
	if err != nil {
		return "", err
	}
	expectedExtensionID := appID + "." + layout.extensionExecutable
	if appExecutable != layout.appExecutable ||
		extensionID != expectedExtensionID ||
		extensionExecutable != layout.extensionExecutable {
		return "", fmt.Errorf(
			"source bundle identity mismatch: app %q executable %q, extension %q executable %q",
			appID,
			appExecutable,
			extensionID,
			extensionExecutable,
		)
	}
	return appID, nil
}

func requireOwnedByEUID(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is not owned by uid %d", path, os.Geteuid())
	}
	return nil
}

func validateContainedPath(home, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("path must be absolute and clean: %q", path)
	}
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is outside canonical account home %s", path, home)
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	contains := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		return err == nil &&
			(relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
	}
	return contains(first, second) || contains(second, first)
}

// ensureOwnedDirectoryTree creates only missing components below home and
// rejects symlinks, foreign ownership, and group/world-writable directories.
// It never follows a mutable HOME value.
func ensureOwnedDirectoryTree(home, path string) error {
	if err := validateContainedPath(home, path); err != nil {
		return err
	}
	homeSnapshot, err := snapshotPath(home)
	if err != nil {
		return fmt.Errorf("snapshot canonical account home %s: %w", home, err)
	}
	current, err := openSnapshottedDirectory(home, homeSnapshot)
	if err != nil {
		return fmt.Errorf("pin canonical account home %s: %w", home, err)
	}
	defer func() {
		_ = unix.Close(current)
	}()
	relative, _ := filepath.Rel(home, path)
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		next, openErr := unix.Openat(
			current,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if errors.Is(openErr, unix.ENOENT) {
			if err := unix.Mkdirat(current, component, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("create %s: %w", filepath.Join(home, relative), err)
			}
			if err := unix.Fsync(current); err != nil {
				return fmt.Errorf("sync parent after creating %s: %w", filepath.Join(home, relative), err)
			}
			next, openErr = unix.Openat(
				current,
				component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
				0,
			)
		}
		if openErr != nil {
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return fmt.Errorf("%s is not a real directory", filepath.Join(home, component))
			}
			return fmt.Errorf("open directory component %s without following symlinks: %w", component, openErr)
		}
		var opened, named unix.Stat_t
		openedErr := unix.Fstat(next, &opened)
		namedErr := unix.Fstatat(current, component, &named, unix.AT_SYMLINK_NOFOLLOW)
		if openedErr != nil || namedErr != nil ||
			opened.Dev != named.Dev || opened.Ino != named.Ino ||
			opened.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(next)
			return fmt.Errorf("directory component %s changed while it was pinned", component)
		}
		if opened.Uid != uint32(os.Geteuid()) {
			_ = unix.Close(next)
			return fmt.Errorf("%s is not owned by uid %d", filepath.Join(home, relative), os.Geteuid())
		}
		if opened.Mode&0o022 != 0 {
			_ = unix.Close(next)
			return fmt.Errorf("%s is group/world writable (%04o)", filepath.Join(home, relative), opened.Mode&0o777)
		}
		_ = unix.Close(current)
		current = next
	}
	return nil
}

func prepareMacOSInstall(sourceApp, destinationApp, cliLink string) (*preparedMacOSInstall, error) {
	return prepareMacOSInstallWithLayout(
		sourceApp,
		destinationApp,
		cliLink,
		compiledMacOSInstallLayout,
	)
}

func prepareMacOSInstallWithLayout(
	sourceApp string,
	destinationApp string,
	cliLink string,
	layout macOSInstallLayout,
) (*preparedMacOSInstall, error) {
	if err := layout.validate(); err != nil {
		return nil, err
	}
	if err := validateExistingAppDestination(destinationApp); err != nil {
		return nil, err
	}
	if err := validateExistingCLILink(cliLink, destinationApp); err != nil {
		return nil, err
	}
	appID, err := snapshotPath(destinationApp)
	if err != nil {
		return nil, fmt.Errorf("snapshot destination app: %w", err)
	}
	linkID, err := snapshotPath(cliLink)
	if err != nil {
		return nil, fmt.Errorf("snapshot CLI link: %w", err)
	}
	appParentID, err := snapshotPath(filepath.Dir(destinationApp))
	if err != nil {
		return nil, fmt.Errorf("snapshot application directory: %w", err)
	}
	linkParentID, err := snapshotPath(filepath.Dir(cliLink))
	if err != nil {
		return nil, fmt.Errorf("snapshot CLI link directory: %w", err)
	}
	stageRoot, err := os.MkdirTemp(filepath.Dir(destinationApp), ".portablefs-install-")
	if err != nil {
		return nil, fmt.Errorf("create app staging directory: %w", err)
	}
	prepared := &preparedMacOSInstall{
		stageRoot:    stageRoot,
		appParentID:  appParentID,
		linkParentID: linkParentID,
		layout:       layout,
	}
	prepared.stageRootID, err = snapshotPath(stageRoot)
	if err != nil {
		return nil, fmt.Errorf("snapshot app staging directory: %w", err)
	}
	success := false
	defer func() {
		if !success {
			prepared.cleanup()
		}
	}()
	// Deliberately avoid an .app suffix while the bundle is staged and after
	// an update exchange. If power is lost before checked cleanup, PlugInKit
	// cannot discover the displaced provider as a second application bundle.
	prepared.stageApp = filepath.Join(stageRoot, layout.stagedAppName)
	out, err := exec.Command(
		"/usr/bin/ditto",
		"--rsrc",
		"--extattr",
		"--acl",
		sourceApp,
		prepared.stageApp,
	).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("stage app with ditto: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	info, err := os.Lstat(prepared.stageApp)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("ditto did not create a real staged app at %s", prepared.stageApp)
	}
	prepared.stageID, err = snapshotPath(prepared.stageApp)
	if err != nil {
		return nil, fmt.Errorf("snapshot staged app: %w", err)
	}
	prepared.appID = appID
	prepared.linkID = linkID
	prepared.linkPath = cliLink

	if linkID.exists {
		success = true
		return prepared, nil
	}
	prepared.linkRoot, err = os.MkdirTemp(filepath.Dir(cliLink), ".portablefs-link-")
	if err != nil {
		return nil, fmt.Errorf("create CLI link staging directory: %w", err)
	}
	prepared.linkRootID, err = snapshotPath(prepared.linkRoot)
	if err != nil {
		return nil, fmt.Errorf("snapshot staged CLI link directory: %w", err)
	}
	prepared.linkTemp = filepath.Join(prepared.linkRoot, macOSCLIName)
	target := filepath.Join(destinationApp, "Contents", "Helpers", macOSCLIName)
	if err := os.Symlink(target, prepared.linkTemp); err != nil {
		return nil, fmt.Errorf("stage CLI symlink: %w", err)
	}
	prepared.linkStageID, err = snapshotPath(prepared.linkTemp)
	if err != nil {
		return nil, fmt.Errorf("snapshot staged CLI link: %w", err)
	}
	success = true
	return prepared, nil
}

func validateExistingAppDestination(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing app %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("existing app path %s is not a real directory; remove it explicitly before installing", path)
	}
	return requireOwnedByEUID(path, info)
}

func validateExistingManagedMacOSApp(path, expectedAppID string) error {
	return validateExistingManagedMacOSAppWithLayout(
		path,
		expectedAppID,
		compiledMacOSInstallLayout,
	)
}

func validateExistingManagedMacOSAppWithLayout(
	path string,
	expectedAppID string,
	layout macOSInstallLayout,
) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect existing app %s: %w", path, err)
	}
	if err := validateExistingAppDestination(path); err != nil {
		return err
	}
	version, err := plistValue(
		filepath.Join(path, "Contents", "Info.plist"),
		"CFBundleShortVersionString",
	)
	if err != nil {
		return fmt.Errorf(
			"existing app at %s is not a managed PortableFS release; remove it explicitly before installing: %w",
			path,
			err,
		)
	}
	if err := validateInstalledMacOSBundleForPublicationWithLayout(
		path,
		version,
		expectedAppID,
		layout,
	); err != nil {
		return fmt.Errorf(
			"existing app at %s is not a managed PortableFS release; remove it explicitly before installing: %w",
			path,
			err,
		)
	}
	return nil
}

func validateExistingCLILink(linkPath, destinationApp string) error {
	info, err := os.Lstat(linkPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing CLI path %s: %w", linkPath, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("existing CLI path %s is not a symlink; move it explicitly before installing", linkPath)
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		return fmt.Errorf("read existing CLI symlink %s: %w", linkPath, err)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(linkPath), target)
	}
	target = filepath.Clean(target)
	expected := filepath.Join(destinationApp, "Contents", "Helpers", macOSCLIName)
	if target != expected {
		return fmt.Errorf(
			"existing CLI symlink %s targets unexpected path %s; remove it explicitly before installing",
			linkPath,
			target,
		)
	}
	return nil
}

func commitMacOSInstall(prepared *preparedMacOSInstall, destinationApp string) error {
	if err := publishMacOSInstall(prepared, destinationApp); err != nil {
		return err
	}
	return finalizePublishedMacOSInstall(prepared, destinationApp)
}

// publishMacOSInstall makes the staged release visible but deliberately leaves
// the displaced release in its snapshotted transaction directory. Updaters
// must retain that exact rollback point until the replacement host and daemon
// prove their sealed live identity.
func publishMacOSInstall(prepared *preparedMacOSInstall, destinationApp string) error {
	if err := requireUnchangedPath(prepared.stageApp, prepared.stageID); err != nil {
		return fmt.Errorf("staged app changed before publication: %w", err)
	}
	if err := requireUnchangedPath(destinationApp, prepared.appID); err != nil {
		return fmt.Errorf("destination app changed during installation: %w", err)
	}
	if err := requireUnchangedPath(prepared.linkPath, prepared.linkID); err != nil {
		return fmt.Errorf("CLI link changed during installation: %w", err)
	}
	if !prepared.linkID.exists {
		if err := requireUnchangedPath(prepared.linkTemp, prepared.linkStageID); err != nil {
			return fmt.Errorf("staged CLI link changed before publication: %w", err)
		}
	}
	parent, err := openSnapshottedDirectory(filepath.Dir(destinationApp), prepared.appParentID)
	if err != nil {
		return fmt.Errorf("open application directory for atomic publication: %w", err)
	}
	defer unix.Close(parent)
	linkParent, err := openSnapshottedDirectory(filepath.Dir(prepared.linkPath), prepared.linkParentID)
	if err != nil {
		return fmt.Errorf("open CLI link directory for atomic publication: %w", err)
	}
	defer unix.Close(linkParent)
	linkSourceParent := -1
	if !prepared.linkID.exists {
		linkSourceParent, err = openSnapshottedDirectory(prepared.linkRoot, prepared.linkRootID)
		if err != nil {
			return fmt.Errorf("open staged CLI link directory for atomic publication: %w", err)
		}
		defer unix.Close(linkSourceParent)
	}
	stageName := filepath.Base(prepared.stageRoot)
	stageRelative := filepath.Join(stageName, filepath.Base(prepared.stageApp))
	destinationName := filepath.Base(destinationApp)
	if err := publishPreparedApp(prepared, parent, stageRelative, destinationName); err != nil {
		return err
	}

	var linkErr error
	if prepared.linkID.exists {
		// The link's canonical target is stable across app swaps. Leaving its
		// already-validated inode untouched removes an unnecessary publication
		// edge; this recheck detects a race that occurred during the app swap.
		linkErr = requireUnchangedPath(prepared.linkPath, prepared.linkID)
	} else {
		linkErr = publishPreparedCLILink(prepared, linkSourceParent, linkParent)
	}
	if linkErr != nil {
		rollbackErr := rollbackPublishedApp(prepared, parent, stageRelative, destinationName)
		if rollbackErr != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"publish CLI symlink: %w; app rollback also failed: %v; preserved transaction at %s",
				linkErr,
				rollbackErr,
				prepared.stageRoot,
			)
		}
		if err := unix.Fsync(parent); err != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"publish CLI symlink: %w; app rollback completed but could not be made durable: %v; preserved transaction at %s",
				linkErr,
				err,
				prepared.stageRoot,
			)
		}
		return fmt.Errorf("publish CLI symlink: %w (app publication rolled back)", linkErr)
	}
	if err := unix.Fsync(parent); err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"sync application directory after publication: %w; preserved transaction at %s",
			err,
			prepared.stageRoot,
		)
	}
	if !prepared.linkID.exists {
		if err := unix.Fsync(linkParent); err != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"sync CLI link directory after publication: %w; preserved transactions at %s and %s",
				err,
				prepared.stageRoot,
				prepared.linkRoot,
			)
		}
	}
	return nil
}

func finalizePublishedMacOSInstall(
	prepared *preparedMacOSInstall,
	destinationApp string,
) error {
	if err := requirePublishedMacOSInstall(prepared, destinationApp); err != nil {
		prepared.preserve = true
		return err
	}
	parent, err := openSnapshottedDirectory(filepath.Dir(destinationApp), prepared.appParentID)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf("open application directory to retire displaced release: %w", err)
	}
	defer unix.Close(parent)
	linkParent, err := openSnapshottedDirectory(filepath.Dir(prepared.linkPath), prepared.linkParentID)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf("open CLI link directory to retire install transaction: %w", err)
	}
	defer unix.Close(linkParent)
	if err := removePublishedMacOSStaging(prepared, parent, linkParent); err != nil {
		prepared.preserve = true
		return err
	}
	return nil
}

func requirePublishedMacOSInstall(
	prepared *preparedMacOSInstall,
	destinationApp string,
) error {
	if prepared == nil || prepared.stageRoot == "" || prepared.stageApp == "" {
		return fmt.Errorf("macOS install has no retained publication transaction")
	}
	if err := requireUnchangedPath(destinationApp, prepared.stageID); err != nil {
		return fmt.Errorf("published app changed before activation completed: %w", err)
	}
	displaced := pathSnapshot{}
	if prepared.appID.exists {
		displaced = prepared.appID
	}
	if err := requireUnchangedPath(prepared.stageApp, displaced); err != nil {
		return fmt.Errorf("retained displaced app changed before activation completed: %w", err)
	}
	if err := requireUnchangedPath(prepared.linkPath, func() pathSnapshot {
		if prepared.linkID.exists {
			return prepared.linkID
		}
		return prepared.linkStageID
	}()); err != nil {
		return fmt.Errorf("published CLI link changed before activation completed: %w", err)
	}
	return nil
}

// rollbackPublishedMacOSInstall restores the exact displaced release with one
// atomic exchange. It never guesses at, replaces, or recursively removes an
// unpinned path. The newly rejected release remains under stageApp until the
// exchange is durably synced and the exact transaction is cleaned.
func rollbackPublishedMacOSInstall(
	prepared *preparedMacOSInstall,
	destinationApp string,
) error {
	if err := restorePublishedMacOSInstall(prepared, destinationApp); err != nil {
		return err
	}
	return finalizeRolledBackMacOSInstall(prepared, destinationApp)
}

func restorePublishedMacOSInstall(
	prepared *preparedMacOSInstall,
	destinationApp string,
) error {
	if !prepared.appID.exists {
		return fmt.Errorf("published macOS install has no previous release to restore")
	}
	if err := requirePublishedMacOSInstall(prepared, destinationApp); err != nil {
		prepared.preserve = true
		return err
	}
	parent, err := openSnapshottedDirectory(filepath.Dir(destinationApp), prepared.appParentID)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf("open application directory for activation rollback: %w", err)
	}
	defer unix.Close(parent)
	stageRelative := filepath.Join(
		filepath.Base(prepared.stageRoot),
		filepath.Base(prepared.stageApp),
	)
	if err := rollbackPublishedApp(
		prepared,
		parent,
		stageRelative,
		filepath.Base(destinationApp),
	); err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"atomically restore previous PortableFS.app: %w; preserved transaction at %s",
			err,
			prepared.stageRoot,
		)
	}
	if err := unix.Fsync(parent); err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"sync restored PortableFS.app: %w; preserved transaction at %s",
			err,
			prepared.stageRoot,
		)
	}
	if err := requireUnchangedPath(destinationApp, prepared.appID); err != nil {
		prepared.preserve = true
		return fmt.Errorf("restored app identity is not the displaced release: %w", err)
	}
	if err := requireUnchangedPath(prepared.stageApp, prepared.stageID); err != nil {
		prepared.preserve = true
		return fmt.Errorf("rejected app identity changed during rollback: %w", err)
	}
	return nil
}

func finalizeRolledBackMacOSInstall(
	prepared *preparedMacOSInstall,
	destinationApp string,
) error {
	if err := requireRolledBackMacOSInstall(prepared, destinationApp); err != nil {
		prepared.preserve = true
		return err
	}
	parent, err := openSnapshottedDirectory(filepath.Dir(destinationApp), prepared.appParentID)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf("open application directory to retire rejected release: %w", err)
	}
	defer unix.Close(parent)
	linkParent, err := openSnapshottedDirectory(filepath.Dir(prepared.linkPath), prepared.linkParentID)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf("open CLI link directory after activation rollback: %w", err)
	}
	defer unix.Close(linkParent)
	if err := removePublishedMacOSStaging(prepared, parent, linkParent); err != nil {
		prepared.preserve = true
		return err
	}
	return nil
}

func requireRolledBackMacOSInstall(
	prepared *preparedMacOSInstall,
	destinationApp string,
) error {
	if prepared == nil || prepared.stageRoot == "" || prepared.stageApp == "" ||
		!prepared.appID.exists {
		return fmt.Errorf("macOS install has no retained rollback transaction")
	}
	if err := requireUnchangedPath(destinationApp, prepared.appID); err != nil {
		return fmt.Errorf("restored app changed before rollback activation completed: %w", err)
	}
	if err := requireUnchangedPath(prepared.stageApp, prepared.stageID); err != nil {
		return fmt.Errorf("retained rejected app changed before rollback activation completed: %w", err)
	}
	expectedLink := prepared.linkID
	if !expectedLink.exists {
		expectedLink = prepared.linkStageID
	}
	if err := requireUnchangedPath(prepared.linkPath, expectedLink); err != nil {
		return fmt.Errorf("CLI link changed before rollback activation completed: %w", err)
	}
	return nil
}

func publishPreparedApp(
	prepared *preparedMacOSInstall,
	parent int,
	stageRelative string,
	destinationName string,
) error {
	if prepared.appID.exists {
		if err := unix.RenameatxNp(
			parent,
			stageRelative,
			parent,
			destinationName,
			unix.RENAME_SWAP|unix.RENAME_NOFOLLOW_ANY,
		); err != nil {
			return fmt.Errorf("atomically swap PortableFS.app: %w", err)
		}
		publishedErr := requireUnchangedPath(
			filepath.Join(filepath.Dir(prepared.stageRoot), destinationName),
			prepared.stageID,
		)
		displacedErr := requireUnchangedPath(prepared.stageApp, prepared.appID)
		if publishedErr == nil && displacedErr == nil {
			return nil
		}
		rollbackErr := unix.RenameatxNp(
			parent,
			stageRelative,
			parent,
			destinationName,
			unix.RENAME_SWAP|unix.RENAME_NOFOLLOW_ANY,
		)
		if rollbackErr != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"app exchange raced (published: %v, displaced: %v); rollback also failed: %v; preserved transaction at %s",
				publishedErr,
				displacedErr,
				rollbackErr,
				prepared.stageRoot,
			)
		}
		if err := unix.Fsync(parent); err != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"app exchange raced (published: %v, displaced: %v); exchange rolled back but could not be made durable: %v; preserved transaction at %s",
				publishedErr,
				displacedErr,
				err,
				prepared.stageRoot,
			)
		}
		return fmt.Errorf(
			"app exchange raced (published: %v, displaced: %v); exchange rolled back",
			publishedErr,
			displacedErr,
		)
	}

	if err := unix.RenameatxNp(
		parent,
		stageRelative,
		parent,
		destinationName,
		unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY,
	); err != nil {
		return fmt.Errorf("atomically publish PortableFS.app: %w", err)
	}
	destinationApp := filepath.Join(filepath.Dir(prepared.stageRoot), destinationName)
	if err := requireUnchangedPath(destinationApp, prepared.stageID); err != nil {
		rollbackErr := unix.RenameatxNp(
			parent,
			destinationName,
			parent,
			stageRelative,
			unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY,
		)
		if rollbackErr != nil {
			prepared.preserve = true
			return fmt.Errorf("validate published app: %w; rollback also failed: %v", err, rollbackErr)
		}
		if syncErr := unix.Fsync(parent); syncErr != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"validate published app: %w; rollback completed but could not be made durable: %v; preserved transaction at %s",
				err,
				syncErr,
				prepared.stageRoot,
			)
		}
		return fmt.Errorf("validate published app: %w (publication rolled back)", err)
	}
	return nil
}

func removePublishedMacOSStaging(
	prepared *preparedMacOSInstall,
	appParent int,
	linkParent int,
) error {
	if prepared.linkRoot != "" {
		if err := requireUnchangedPath(prepared.linkRoot, prepared.linkRootID); err != nil {
			return fmt.Errorf("CLI transaction directory changed before cleanup: %w", err)
		}
		if err := removeSnapshottedTreeAt(
			linkParent,
			filepath.Base(prepared.linkRoot),
			prepared.linkRootID,
			nil,
		); err != nil {
			return fmt.Errorf(
				"installed app is published but remove CLI transaction %s: %w",
				prepared.linkRoot,
				err,
			)
		}
		prepared.linkRoot = ""
	}
	if err := requireUnchangedPath(prepared.stageRoot, prepared.stageRootID); err != nil {
		return fmt.Errorf("app transaction directory changed before cleanup: %w", err)
	}
	if err := removeSnapshottedTreeAt(
		appParent,
		filepath.Base(prepared.stageRoot),
		prepared.stageRootID,
		nil,
	); err != nil {
		return fmt.Errorf(
			"installed app is published but remove app transaction %s: %w",
			prepared.stageRoot,
			err,
		)
	}
	prepared.stageRoot = ""
	prepared.stageApp = ""
	return nil
}

func rejectOrphanedMacOSInstallTransactions(appDir, current string) error {
	return rejectOrphanedMacOSTransactions(
		appDir,
		".portablefs-install-",
		current,
		"install",
	)
}

func rejectOrphanedMacOSLinkTransactions(linkDir, current string) error {
	return rejectOrphanedMacOSTransactions(
		linkDir,
		".portablefs-link-",
		current,
		"CLI-link",
	)
}

func rejectOrphanedMacOSTransactions(directory, prefix, current, kind string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("inspect directory for incomplete %s transactions: %w", kind, err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if path == current {
			continue
		}
		return fmt.Errorf(
			"incomplete PortableFS %s transaction remains at %s; archive or remove that exact path after reviewing it, then retry",
			kind,
			path,
		)
	}
	return nil
}

func rollbackPublishedApp(
	prepared *preparedMacOSInstall,
	parent int,
	stageRelative string,
	destinationName string,
) error {
	if prepared.appID.exists {
		return unix.RenameatxNp(
			parent,
			stageRelative,
			parent,
			destinationName,
			unix.RENAME_SWAP|unix.RENAME_NOFOLLOW_ANY,
		)
	}
	return unix.RenameatxNp(
		parent,
		destinationName,
		parent,
		stageRelative,
		unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY,
	)
}

func publishPreparedCLILink(prepared *preparedMacOSInstall, sourceParent, destinationParent int) error {
	if prepared.linkID.exists {
		return fmt.Errorf("internal error: existing canonical CLI link must not be republished")
	}
	if err := unix.RenameatxNp(
		sourceParent,
		filepath.Base(prepared.linkTemp),
		destinationParent,
		filepath.Base(prepared.linkPath),
		unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY,
	); err != nil {
		return err
	}
	if err := requireUnchangedPath(prepared.linkPath, prepared.linkStageID); err != nil {
		rollbackErr := unix.RenameatxNp(
			destinationParent,
			filepath.Base(prepared.linkPath),
			sourceParent,
			filepath.Base(prepared.linkTemp),
			unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY,
		)
		if rollbackErr != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"validate published CLI link: %w; rollback also failed: %v; preserved transaction at %s",
				err,
				rollbackErr,
				prepared.linkRoot,
			)
		}
		if syncErr := unix.Fsync(destinationParent); syncErr != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"validate published CLI link: %w; rollback completed but destination sync failed: %v; preserved transaction at %s",
				err,
				syncErr,
				prepared.linkRoot,
			)
		}
		if syncErr := unix.Fsync(sourceParent); syncErr != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"validate published CLI link: %w; rollback completed but staging sync failed: %v; preserved transaction at %s",
				err,
				syncErr,
				prepared.linkRoot,
			)
		}
		return fmt.Errorf("validate published CLI link: %w (publication rolled back)", err)
	}
	return nil
}

func snapshotPath(path string) (pathSnapshot, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return pathSnapshot{}, nil
	}
	if err != nil {
		return pathSnapshot{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return pathSnapshot{}, fmt.Errorf("inode metadata unavailable for %s", path)
	}
	snapshot := pathSnapshot{
		exists: true,
		dev:    uint64(stat.Dev),
		ino:    stat.Ino,
		mode:   info.Mode(),
	}
	if info.Mode()&os.ModeSymlink != 0 {
		snapshot.target, err = os.Readlink(path)
		if err != nil {
			return pathSnapshot{}, err
		}
	}
	return snapshot, nil
}

func openSnapshottedDirectory(path string, expected pathSnapshot) (int, error) {
	if !expected.exists || !expected.mode.IsDir() {
		return -1, fmt.Errorf("expected a snapshotted directory at %s", path)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return -1, fmt.Errorf("snapshotted directory path must be absolute, clean, and non-root: %q", path)
	}
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		next, err := unix.Openat(
			current,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if err != nil {
			_ = unix.Close(current)
			return -1, fmt.Errorf("open directory component %s in %s without following symlinks: %w", component, path, err)
		}
		var opened, named unix.Stat_t
		openedErr := unix.Fstat(next, &opened)
		namedErr := unix.Fstatat(current, component, &named, unix.AT_SYMLINK_NOFOLLOW)
		_ = unix.Close(current)
		if openedErr != nil || namedErr != nil ||
			opened.Dev != named.Dev || opened.Ino != named.Ino ||
			opened.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(next)
			return -1, fmt.Errorf("directory component %s changed while opening %s", component, path)
		}
		current = next
	}
	var final unix.Stat_t
	if err := unix.Fstat(current, &final); err != nil {
		_ = unix.Close(current)
		return -1, err
	}
	if uint64(final.Dev) != expected.dev || final.Ino != expected.ino {
		_ = unix.Close(current)
		return -1, fmt.Errorf("%s changed while it was being opened", path)
	}
	return current, nil
}

func removeSnapshottedTreeAt(
	parent int,
	name string,
	expected pathSnapshot,
	afterPin func(),
) error {
	if filepath.Base(name) != name || name == "." || name == "" {
		return fmt.Errorf("invalid transaction directory name %q", name)
	}
	if !expected.exists || !expected.mode.IsDir() {
		return fmt.Errorf("transaction %s has no exact directory snapshot", name)
	}
	fd, err := unix.Openat(
		parent,
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("pin transaction directory %s: %w", name, err)
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return fmt.Errorf("inspect pinned transaction directory %s: %w", name, err)
	}
	if uint64(opened.Dev) != expected.dev || opened.Ino != expected.ino {
		return fmt.Errorf("transaction directory %s changed before cleanup", name)
	}
	if afterPin != nil {
		afterPin()
	}
	if err := removeDirectoryContentsAt(fd, name); err != nil {
		return err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(parent, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck transaction directory %s before removal: %w", name, err)
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino || named.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("transaction directory %s changed while its pinned inode was cleaned; replacement was preserved", name)
	}
	if err := unix.Unlinkat(parent, name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove exact transaction directory %s: %w", name, err)
	}
	if err := unix.Fsync(parent); err != nil {
		return fmt.Errorf("sync transaction directory removal %s: %w", name, err)
	}
	return nil
}

func removeDirectoryContentsAt(directory int, display string) error {
	readerFD, err := unix.Openat(
		directory,
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("open transaction directory %s for enumeration: %w", display, err)
	}
	reader := os.NewFile(uintptr(readerFD), display)
	entries, readErr := reader.ReadDir(-1)
	closeErr := reader.Close()
	if readErr != nil {
		return fmt.Errorf("enumerate transaction directory %s: %w", display, readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close transaction directory enumeration %s: %w", display, closeErr)
	}
	for _, entry := range entries {
		entryName := entry.Name()
		entryPath := filepath.Join(display, entryName)
		var before unix.Stat_t
		if err := unix.Fstatat(directory, entryName, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("inspect transaction entry %s: %w", entryPath, err)
		}
		if before.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("transaction entry %s is not owned by uid %d; it was preserved", entryPath, os.Geteuid())
		}
		switch before.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			child, err := unix.Openat(
				directory,
				entryName,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
				0,
			)
			if err != nil {
				return fmt.Errorf("pin transaction subdirectory %s: %w", entryPath, err)
			}
			var openedChild unix.Stat_t
			if err := unix.Fstat(child, &openedChild); err != nil {
				_ = unix.Close(child)
				return fmt.Errorf("inspect pinned transaction subdirectory %s: %w", entryPath, err)
			}
			if openedChild.Dev != before.Dev || openedChild.Ino != before.Ino {
				_ = unix.Close(child)
				return fmt.Errorf("transaction subdirectory %s changed while opening", entryPath)
			}
			removeErr := removeDirectoryContentsAt(child, entryPath)
			closeErr := unix.Close(child)
			if removeErr != nil {
				return removeErr
			}
			if closeErr != nil {
				return fmt.Errorf("close transaction subdirectory %s: %w", entryPath, closeErr)
			}
			var current unix.Stat_t
			if err := unix.Fstatat(directory, entryName, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("recheck transaction subdirectory %s: %w", entryPath, err)
			}
			if current.Dev != before.Dev || current.Ino != before.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
				return fmt.Errorf("transaction subdirectory %s changed during cleanup; replacement was preserved", entryPath)
			}
			if err := unix.Unlinkat(directory, entryName, unix.AT_REMOVEDIR); err != nil {
				return fmt.Errorf("remove transaction subdirectory %s: %w", entryPath, err)
			}
		case unix.S_IFREG, unix.S_IFLNK:
			if before.Nlink != 1 {
				return fmt.Errorf("transaction entry %s has %d links; it was preserved", entryPath, before.Nlink)
			}
			var current unix.Stat_t
			if err := unix.Fstatat(directory, entryName, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("recheck transaction entry %s: %w", entryPath, err)
			}
			if current.Dev != before.Dev || current.Ino != before.Ino || current.Mode != before.Mode {
				return fmt.Errorf("transaction entry %s changed during cleanup; replacement was preserved", entryPath)
			}
			if err := unix.Unlinkat(directory, entryName, 0); err != nil {
				return fmt.Errorf("remove transaction entry %s: %w", entryPath, err)
			}
		default:
			return fmt.Errorf("transaction entry %s has unsupported filesystem type; it was preserved", entryPath)
		}
	}
	if err := unix.Fsync(directory); err != nil {
		return fmt.Errorf("sync cleaned transaction directory %s: %w", display, err)
	}
	return nil
}

func requireUnchangedPath(path string, before pathSnapshot) error {
	after, err := snapshotPath(path)
	if err != nil {
		return err
	}
	if after != before {
		return fmt.Errorf("path identity changed at %s", path)
	}
	return nil
}

func prepareInstalledHostUpdate(
	ctx context.Context,
	destinationApp string,
	socketPath string,
	oldRelease hostctl.ReleaseIdentity,
	targetRelease hostctl.ReleaseIdentity,
) (*hostctl.Session, error) {
	if err := requestExactMacOSHostForProof(destinationApp); err != nil {
		return nil, fmt.Errorf("wake installed PortableFS host for update: %w", err)
	}
	var lastError error
	for {
		session, err := hostctl.Prepare(
			ctx,
			socketPath,
			oldRelease,
			targetRelease,
		)
		if err == nil {
			return session, nil
		}
		lastError = err
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf(
				"installed PortableFS host did not prepare its service for update: %w (last error: %v)",
				ctx.Err(),
				lastError,
			)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func macOSServiceReleaseIdentity(
	app string,
	version string,
) (hostctl.ReleaseIdentity, error) {
	daemonPath := filepath.Join(
		app,
		"Contents",
		filepath.FromSlash(macOSPortableFSDRelativePath),
	)
	daemon, err := openPortablefsdPeer(daemonPath)
	if err != nil {
		return hostctl.ReleaseIdentity{}, fmt.Errorf("pin sealed daemon release: %w", err)
	}
	defer daemon.close()
	serviceApp := filepath.Join(
		app,
		"Contents",
		"Library",
		"LaunchAgents",
		"PortableFSDService.app",
	)
	architecture, err := nativeCodeArchitecture()
	if err != nil {
		return hostctl.ReleaseIdentity{}, err
	}
	out, err := exec.Command(
		"/usr/bin/codesign",
		"-dv",
		"--verbose=4",
		"--arch", architecture,
		serviceApp,
	).CombinedOutput()
	if err != nil {
		return hostctl.ReleaseIdentity{}, fmt.Errorf(
			"inspect sealed daemon code directory: %w (output: %s)",
			err,
			strings.TrimSpace(string(out)),
		)
	}
	codeDirectoryHash, err := exactCodesignField(string(out), "CDHash")
	if err != nil {
		return hostctl.ReleaseIdentity{}, err
	}
	identity := hostctl.ReleaseIdentity{
		CodeDirectoryHash: codeDirectoryHash,
		ExecutableSHA256:  daemon.sha256,
		DaemonVersion:     version,
	}
	if err := hostctl.ValidateReleaseIdentity(identity); err != nil {
		return hostctl.ReleaseIdentity{}, fmt.Errorf("invalid sealed daemon release identity: %w", err)
	}
	return identity, nil
}

func exactCodesignField(output, field string) (string, error) {
	prefix := field + "="
	value := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if value != "" {
			return "", fmt.Errorf("codesign output carries duplicate %s", field)
		}
		value = strings.TrimPrefix(line, prefix)
	}
	if value == "" {
		return "", fmt.Errorf("codesign output carries no %s", field)
	}
	return value, nil
}

func reactivateUnpublishedOldMacOSRelease(
	e *cmdEnv,
	prepared *preparedMacOSInstall,
	destinationApp string,
	updateSocket string,
	leasePath string,
	token string,
	oldRelease hostctl.ReleaseIdentity,
	targetRelease hostctl.ReleaseIdentity,
	installFailure error,
) error {
	rollbackContext, rollbackCancel := context.WithTimeout(context.Background(), macOSActivationTransactionTimeout)
	defer rollbackCancel()
	if err := requireUnchangedPath(destinationApp, prepared.appID); err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"installation failed after old-host exit: %w; installed old release is no longer exact: %v; retained transaction at %s",
			installFailure,
			err,
			prepared.stageRoot,
		)
	}
	if err := requireUnchangedPath(prepared.stageApp, prepared.stageID); err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"installation failed after old-host exit: %w; staged target is no longer exact: %v; retained transaction at %s",
			installFailure,
			err,
			prepared.stageRoot,
		)
	}
	if err := hostctl.RequireLease(
		leasePath,
		token,
		hostctl.PhaseOldAbsent,
		oldRelease,
		targetRelease,
	); err != nil {
		prepared.preserve = true
		return fmt.Errorf("installation failed after old-host exit: %w; old-absent lease is not exact: %v", installFailure, err)
	}
	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf("installation failed after old-host exit: %w; resolve recovery inventory: %v", installFailure, err)
	}
	if err := rejectLiveMacOSRuntimeWithLayout(e, stateDir, prepared.layout); err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"installation failed after old-host exit: %w; old service absence is not proven: %v; retained transaction at %s",
			installFailure,
			err,
			prepared.stageRoot,
		)
	}
	activation, err := connectRollbackActivationRecoveringReadyLoss(
		rollbackContext,
		destinationApp,
		updateSocket,
		leasePath,
		token,
		oldRelease,
		targetRelease,
	)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"installation failed after old-host exit: %w; reactivate exact old host: %v; retained transaction at %s",
			installFailure,
			err,
			prepared.stageRoot,
		)
	}
	defer activation.Close()
	liveTimeout, timeoutErr := boundedContextDuration(rollbackContext, 5*time.Second)
	if timeoutErr != nil {
		prepared.preserve = true
		return fmt.Errorf("installation failed after old-host exit: %w; old activation deadline exhausted: %v", installFailure, timeoutErr)
	}
	if err := requireLiveMacOSServiceRelease(destinationApp, oldRelease, false, liveTimeout); err != nil {
		fenceErr := fenceReadyMacOSActivation(
			rollbackContext, activation, updateSocket, macOSActivationFenceAndAbsenceTimeout,
		)
		prepared.preserve = true
		return fmt.Errorf(
			"installation failed after old-host exit: %w; old live proof failed: %v; fence result: %v; retained transaction at %s",
			installFailure,
			err,
			fenceErr,
			prepared.stageRoot,
		)
	}
	accepted, err := acceptRollbackMacOSActivationRecoveringFence(
		rollbackContext,
		activation,
		destinationApp,
		updateSocket,
		leasePath,
		token,
		oldRelease,
		targetRelease,
	)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"installation failed after old-host exit: %w; accept old activation: %v; retained transaction at %s",
			installFailure,
			err,
			prepared.stageRoot,
		)
	}
	if accepted != activation {
		defer accepted.Close()
		activation = accepted
	}
	if err := hostctl.RequireLease(
		leasePath,
		token,
		hostctl.PhaseRollbackActive,
		oldRelease,
		targetRelease,
	); err != nil {
		prepared.preserve = true
		return fmt.Errorf("verify pre-publication rollback activation lease: %w", err)
	}
	// The old app was never displaced on this recovery path. Retire the
	// unpublished target durably before requesting completion so a lost reply
	// can be reconciled by the exact rollback-complete marker + old-live identity
	// with no second app copy left behind.
	prepared.cleanup()
	if prepared.preserve || prepared.stageRoot != "" || prepared.stageApp != "" || prepared.linkRoot != "" {
		return fmt.Errorf(
			"installation failed after old-host exit: %w; could not durably retire the unpublished target before completing old activation",
			installFailure,
		)
	}
	err = completeOrResumeMacOSActivation(
		rollbackContext,
		activation,
		destinationApp,
		updateSocket,
		leasePath,
		token,
		"rollback",
		oldRelease,
		oldRelease,
		targetRelease,
		func() error {
			return reconcileCompletedMacOSActivation(
				leasePath,
				destinationApp,
				token,
				hostctl.PhaseRollbackComplete,
				oldRelease,
				targetRelease,
				prepared.appID,
				prepared,
			)
		},
	)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"installation failed: %w; old release completion/reconciliation failed: %v",
			installFailure,
			err,
		)
	}
	return fmt.Errorf("installation failed and the old release was reactivated: %w", installFailure)
}

// recoverFailedMacOSUpdateCommit resolves the only two safe outcomes after a
// commit-exit write or reply fails. An exact old-absent lease means the host
// accepted the handoff, so the installer retains its plaintext token and
// performs the normal prepublication rollback. An exact rollback-complete
// marker means the host rejected/lost the commit before its irreversible edge
// and already restored the old release; that result is accepted only after the
// installed and live old identities are independently re-proved. No absence or
// guessed phase is treated as success.
func recoverFailedMacOSUpdateCommit(
	e *cmdEnv,
	prepared *preparedMacOSInstall,
	destinationApp string,
	updateSocket string,
	leasePath string,
	token string,
	hostPID int,
	oldRelease hostctl.ReleaseIdentity,
	targetRelease hostctl.ReleaseIdentity,
	commitFailure error,
) error {
	deadline := time.Now().Add(20 * time.Second)
	var oldAbsentErr, rollbackCompleteErr error
	for {
		decided, recoveryErr := reconcileFailedMacOSCommitOutcome(
			failedMacOSCommitRecoveryProofs{
				requireOldAbsent: func() error {
					return hostctl.RequireLease(
						leasePath,
						token,
						hostctl.PhaseOldAbsent,
						oldRelease,
						targetRelease,
					)
				},
				requireRollbackComplete: func() error {
					return hostctl.RequireLease(
						leasePath,
						token,
						hostctl.PhaseRollbackComplete,
						oldRelease,
						targetRelease,
					)
				},
				waitHostProcessAbsent: func() error {
					err := waitForPreparedHostProcessAbsence(hostPID, 10*time.Second)
					if err != nil {
						prepared.preserve = true
					}
					return err
				},
				rollbackOld: func() error {
					// A stale listener name is not authority. The relaunched
					// exact old host safely reclaims only a refusing, owned
					// canonical socket inode.
					return reactivateUnpublishedOldMacOSRelease(
						e,
						prepared,
						destinationApp,
						updateSocket,
						leasePath,
						token,
						oldRelease,
						targetRelease,
						commitFailure,
					)
				},
				requireRollbackCompleteLive: func() error {
					err := requireExactUnpublishedOldMacOSRelease(
						prepared,
						destinationApp,
						leasePath,
						token,
						oldRelease,
						targetRelease,
					)
					if err != nil {
						prepared.preserve = true
					}
					return err
				},
			},
			commitFailure,
		)
		if decided {
			return recoveryErr
		}
		oldAbsentErr = hostctl.RequireLease(
			leasePath, token, hostctl.PhaseOldAbsent, oldRelease, targetRelease,
		)
		rollbackCompleteErr = hostctl.RequireLease(
			leasePath, token, hostctl.PhaseRollbackComplete, oldRelease, targetRelease,
		)
		if time.Now().After(deadline) {
			prepared.preserve = true
			return fmt.Errorf(
				"%w; activation lease proved neither old-absent (%v) nor rollback-complete (%v); retained transaction at %s",
				commitFailure,
				oldAbsentErr,
				rollbackCompleteErr,
				prepared.stageRoot,
			)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type failedMacOSCommitRecoveryProofs struct {
	requireOldAbsent            func() error
	requireRollbackComplete     func() error
	waitHostProcessAbsent       func() error
	rollbackOld                 func() error
	requireRollbackCompleteLive func() error
}

func reconcileFailedMacOSCommitOutcome(
	proofs failedMacOSCommitRecoveryProofs,
	commitFailure error,
) (bool, error) {
	if err := proofs.requireOldAbsent(); err == nil {
		if err := proofs.waitHostProcessAbsent(); err != nil {
			return true, fmt.Errorf(
				"%w; exact old-absent lease is durable but the prepared host did not exit: %v",
				commitFailure,
				err,
			)
		}
		return true, proofs.rollbackOld()
	}
	if err := proofs.requireRollbackComplete(); err == nil {
		if err := proofs.requireRollbackCompleteLive(); err != nil {
			return true, fmt.Errorf(
				"%w; rollback-complete marker did not prove the exact old release: %v",
				commitFailure,
				err,
			)
		}
		return true, fmt.Errorf(
			"%w; the host durably restored and live-proved the exact old release",
			commitFailure,
		)
	}
	return false, nil
}

func requireExactUnpublishedOldMacOSRelease(
	prepared *preparedMacOSInstall,
	destinationApp string,
	leasePath string,
	token string,
	oldRelease hostctl.ReleaseIdentity,
	targetRelease hostctl.ReleaseIdentity,
) error {
	if err := requireUnchangedPath(destinationApp, prepared.appID); err != nil {
		return err
	}
	if prepared.expectedAppID == "" {
		return fmt.Errorf("missing exact installed host bundle identity")
	}
	if err := validateInstalledMacOSBundleForPublicationWithLayout(
		destinationApp,
		oldRelease.DaemonVersion,
		prepared.expectedAppID,
		prepared.layout,
	); err != nil {
		return err
	}
	sealed, err := macOSServiceReleaseIdentity(
		destinationApp,
		oldRelease.DaemonVersion,
	)
	if err != nil {
		return err
	}
	if sealed != oldRelease {
		return fmt.Errorf("installed old daemon release identity changed")
	}
	if err := requireLiveMacOSServiceRelease(destinationApp, oldRelease, false, 5*time.Second); err != nil {
		return err
	}
	return hostctl.RequireLease(
		leasePath,
		token,
		hostctl.PhaseRollbackComplete,
		oldRelease,
		targetRelease,
	)
}

func activatePublishedMacOSUpdate(
	e *cmdEnv,
	prepared *preparedMacOSInstall,
	destinationApp string,
	updateSocket string,
	leasePath string,
	token string,
	oldRelease hostctl.ReleaseIdentity,
	targetRelease hostctl.ReleaseIdentity,
) error {
	transactionContext, transactionCancel := context.WithTimeout(context.Background(), macOSActivationTransactionTimeout)
	defer transactionCancel()
	if err := requestExactMacOSHostForProof(destinationApp); err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"launch replacement PortableFS host: %w; retained the previous release at %s because host activation is ambiguous",
			err,
			prepared.stageRoot,
		)
	}
	activationContext, cancel, err := activationChildContext(
		transactionContext,
		macOSActivationReadyRequestTimeout,
		macOSActivationPostLaunchReserve,
	)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf("replacement activation budget: %w", err)
	}
	activation, err := connectHostActivation(
		activationContext,
		updateSocket,
		"activate-target",
		token,
		targetRelease,
	)
	cancel()
	if err != nil {
		var fenced *hostctl.ActivationFencedError
		if errors.As(err, &fenced) {
			if waitErr := waitForPreparedHostAbsence(
				fenced.HostPID,
				updateSocket,
				10*time.Second,
			); waitErr != nil {
				prepared.preserve = true
				return fmt.Errorf("%w; prove fenced replacement host absence: %v", err, waitErr)
			}
			return restorePreviousMacOSRelease(
				transactionContext,
				e,
				prepared,
				destinationApp,
				updateSocket,
				leasePath,
				token,
				oldRelease,
				targetRelease,
				err,
			)
		}
		var ambiguous *hostctl.ActivationRequestAmbiguousError
		if errors.As(err, &ambiguous) {
			if waitErr := waitForAmbiguousActivationFence(
				ambiguous,
				updateSocket,
				leasePath,
				token,
				oldRelease,
				targetRelease,
				20*time.Second,
			); waitErr == nil {
				return restorePreviousMacOSRelease(
					transactionContext,
					e,
					prepared,
					destinationApp,
					updateSocket,
					leasePath,
					token,
					oldRelease,
					targetRelease,
					err,
				)
			} else {
				prepared.preserve = true
				return fmt.Errorf(
					"activate replacement PortableFS host: %w; exact ready-session fence proof failed: %v; retained both releases at %s",
					err,
					waitErr,
					prepared.stageRoot,
				)
			}
		}
		prepared.preserve = true
		return fmt.Errorf(
			"activate replacement PortableFS host: %w; retained both releases at %s because the service state is ambiguous",
			err,
			prepared.stageRoot,
		)
	}
	defer activation.Close()

	if err := requireLiveMacOSServiceRelease(destinationApp, targetRelease, true, 5*time.Second); err != nil {
		fenceErr := fenceReadyMacOSActivation(
			transactionContext, activation, updateSocket, macOSActivationFenceAndAbsenceTimeout,
		)
		if fenceErr != nil {
			prepared.preserve = true
			return fmt.Errorf(
				"replacement live identity failed: %w; service fence was ambiguous: %v; retained both releases at %s",
				err,
				fenceErr,
				prepared.stageRoot,
			)
		}
		return restorePreviousMacOSRelease(
			transactionContext,
			e,
			prepared,
			destinationApp,
			updateSocket,
			leasePath,
			token,
			oldRelease,
			targetRelease,
			err,
		)
	}
	acceptContext, cancel, err := activationChildContext(
		transactionContext,
		macOSActivationAcceptReconcileTimeout,
		macOSActivationFenceAndRollbackReserve,
	)
	if err != nil {
		fenceErr := fenceReadyMacOSActivation(
			transactionContext, activation, updateSocket, macOSActivationFenceAndAbsenceTimeout,
		)
		if fenceErr != nil {
			prepared.preserve = true
			return fmt.Errorf("replacement activation lacks safe acceptance budget: %w; fence failed: %v", err, fenceErr)
		}
		return restorePreviousMacOSRelease(
			transactionContext,
			e,
			prepared,
			destinationApp,
			updateSocket,
			leasePath,
			token,
			oldRelease,
			targetRelease,
			err,
		)
	}
	accepted, fenced, err := acceptOrResumeMacOSActivation(
		acceptContext,
		activation,
		destinationApp,
		updateSocket,
		leasePath,
		token,
		"target",
		targetRelease,
		oldRelease,
		targetRelease,
	)
	cancel()
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"accept replacement PortableFS activation: %w; retained both releases at %s because activation may already be live",
			err,
			prepared.stageRoot,
		)
	}
	if fenced {
		return restorePreviousMacOSRelease(
			transactionContext,
			e,
			prepared,
			destinationApp,
			updateSocket,
			leasePath,
			token,
			oldRelease,
			targetRelease,
			fmt.Errorf("replacement activation connection closed before acceptance became durable"),
		)
	}
	if accepted != activation {
		defer accepted.Close()
		activation = accepted
	}
	if err := hostctl.RequireLease(
		leasePath,
		token,
		hostctl.PhaseTargetActive,
		oldRelease,
		targetRelease,
	); err != nil {
		prepared.preserve = true
		return fmt.Errorf("verify active target lease before retiring previous release: %w", err)
	}
	if err := finalizePublishedMacOSInstall(prepared, destinationApp); err != nil {
		return err
	}
	err = completeOrResumeMacOSActivation(
		transactionContext,
		activation,
		destinationApp,
		updateSocket,
		leasePath,
		token,
		"target",
		targetRelease,
		oldRelease,
		targetRelease,
		func() error {
			return reconcileCompletedMacOSActivation(
				leasePath,
				destinationApp,
				token,
				hostctl.PhaseTargetComplete,
				oldRelease,
				targetRelease,
				prepared.stageID,
				prepared,
			)
		},
	)
	if err != nil {
		return fmt.Errorf("complete replacement activation after durable publication: %w", err)
	}
	return nil
}

func restorePreviousMacOSRelease(
	transactionContext context.Context,
	e *cmdEnv,
	prepared *preparedMacOSInstall,
	destinationApp string,
	updateSocket string,
	leasePath string,
	token string,
	oldRelease hostctl.ReleaseIdentity,
	targetRelease hostctl.ReleaseIdentity,
	targetFailure error,
) error {
	if err := hostctl.RequireLease(
		leasePath,
		token,
		hostctl.PhaseRollbackAbsent,
		oldRelease,
		targetRelease,
	); err != nil {
		prepared.preserve = true
		return fmt.Errorf("replacement activation failed: %w; rollback lease is not proven: %v", targetFailure, err)
	}
	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf("replacement activation failed: %w; resolve rollback inventory: %v", targetFailure, err)
	}
	if err := rejectLiveMacOSRuntimeWithLayout(e, stateDir, prepared.layout); err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"replacement activation failed: %w; fenced target runtime is not absent: %v; retained both releases at %s",
			targetFailure,
			err,
			prepared.stageRoot,
		)
	}
	if err := restorePublishedMacOSInstall(prepared, destinationApp); err != nil {
		return fmt.Errorf("replacement activation failed: %w; restore previous release: %v", targetFailure, err)
	}
	activation, err := connectRollbackActivationRecoveringReadyLoss(
		transactionContext,
		destinationApp,
		updateSocket,
		leasePath,
		token,
		oldRelease,
		targetRelease,
	)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"replacement activation failed: %w; restored host activation failed: %v; rejected release retained at %s",
			targetFailure,
			err,
			prepared.stageRoot,
		)
	}
	defer activation.Close()
	liveTimeout, timeoutErr := boundedContextDuration(transactionContext, 5*time.Second)
	if timeoutErr != nil {
		prepared.preserve = true
		return fmt.Errorf("replacement activation failed: %w; rollback activation deadline exhausted: %v", targetFailure, timeoutErr)
	}
	if err := requireLiveMacOSServiceRelease(destinationApp, oldRelease, false, liveTimeout); err != nil {
		fenceErr := fenceReadyMacOSActivation(
			transactionContext, activation, updateSocket, macOSActivationFenceAndAbsenceTimeout,
		)
		prepared.preserve = true
		return fmt.Errorf(
			"replacement activation failed: %w; restored release live proof failed: %v; fence result: %v; rejected release retained at %s",
			targetFailure,
			err,
			fenceErr,
			prepared.stageRoot,
		)
	}
	accepted, err := acceptRollbackMacOSActivationRecoveringFence(
		transactionContext,
		activation,
		destinationApp,
		updateSocket,
		leasePath,
		token,
		oldRelease,
		targetRelease,
	)
	if err != nil {
		prepared.preserve = true
		return fmt.Errorf(
			"replacement activation failed: %w; accept restored release activation: %v; rejected release retained at %s",
			targetFailure,
			err,
			prepared.stageRoot,
		)
	}
	if accepted != activation {
		defer accepted.Close()
		activation = accepted
	}
	if err := hostctl.RequireLease(
		leasePath,
		token,
		hostctl.PhaseRollbackActive,
		oldRelease,
		targetRelease,
	); err != nil {
		prepared.preserve = true
		return fmt.Errorf("verify active rollback lease before retiring rejected release: %w", err)
	}
	if err := finalizeRolledBackMacOSInstall(prepared, destinationApp); err != nil {
		return fmt.Errorf("replacement activation failed: %w; retire rejected release: %v", targetFailure, err)
	}
	err = completeOrResumeMacOSActivation(
		transactionContext,
		activation,
		destinationApp,
		updateSocket,
		leasePath,
		token,
		"rollback",
		oldRelease,
		oldRelease,
		targetRelease,
		func() error {
			return reconcileCompletedMacOSActivation(
				leasePath,
				destinationApp,
				token,
				hostctl.PhaseRollbackComplete,
				oldRelease,
				targetRelease,
				prepared.appID,
				prepared,
			)
		},
	)
	if err != nil {
		return fmt.Errorf(
			"replacement activation failed: %w; previous release completion/reconciliation failed: %v",
			targetFailure,
			err,
		)
	}
	return fmt.Errorf("replacement activation failed and the previous release was restored: %w", targetFailure)
}

var launchExactMacOSApp = apphost.LaunchExactApp

// requestExactMacOSHostForProof rejects a synchronous NSWorkspace error. A
// missing completion callback is allowed to proceed only because every caller
// immediately performs a bounded authenticated hostctl or exact daemon-release
// proof; this function is never an activation-success boundary by itself.
func requestExactMacOSHostForProof(app string) error {
	err := launchExactMacOSApp(app)
	if errors.Is(err, apphost.ErrLaunchCompletionAmbiguous) {
		return nil
	}
	return err
}

func connectHostActivation(
	ctx context.Context,
	socketPath string,
	operation string,
	token string,
	release hostctl.ReleaseIdentity,
) (*hostctl.ActivationSession, error) {
	for {
		info, err := os.Lstat(socketPath)
		if err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, fmt.Errorf("host activation path %s is not a Unix socket", socketPath)
			}
			break
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect host activation socket %s: %w", socketPath, err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for host activation socket %s: %w", socketPath, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	return hostctl.Activate(ctx, socketPath, operation, token, release)
}

func waitForAmbiguousActivationFence(
	ambiguous *hostctl.ActivationRequestAmbiguousError,
	socketPath, leasePath, token string,
	oldRelease, targetRelease hostctl.ReleaseIdentity,
	timeout time.Duration,
) error {
	if ambiguous == nil || ambiguous.HostPID <= 0 {
		return fmt.Errorf("missing exact ambiguous activation peer")
	}
	deadline := time.Now().Add(timeout)
	var leaseErr, absenceErr error
	for time.Now().Before(deadline) {
		leaseErr = hostctl.RequireLease(
			leasePath,
			token,
			hostctl.PhaseRollbackAbsent,
			oldRelease,
			targetRelease,
		)
		if leaseErr == nil {
			remaining := time.Until(deadline)
			if remaining > time.Second {
				remaining = time.Second
			}
			absenceErr = waitForPreparedHostAbsence(
				ambiguous.HostPID,
				socketPath,
				remaining,
			)
			if absenceErr == nil {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf(
		"ambiguous host pid %d did not durably fence: lease=%v absence=%v",
		ambiguous.HostPID,
		leaseErr,
		absenceErr,
	)
}

func connectRollbackActivationRecoveringReadyLoss(
	ctx context.Context,
	app, socketPath, leasePath, token string,
	oldRelease, targetRelease hostctl.ReleaseIdentity,
) (*hostctl.ActivationSession, error) {
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("rollback activation did not survive the bounded ready-session retry: %w", errors.Join(last, err))
		}
		activationContext, cancel, err := activationChildContext(
			ctx,
			macOSActivationReadyRequestTimeout,
			macOSRollbackPostLaunchReserve,
		)
		if err != nil {
			return nil, fmt.Errorf("rollback activation has insufficient residual budget before launch: %w", errors.Join(last, err))
		}
		if err := requestExactMacOSHostForProof(app); err != nil {
			cancel()
			return nil, err
		}
		activation, err := connectHostActivation(
			activationContext,
			socketPath,
			"activate-rollback",
			token,
			oldRelease,
		)
		cancel()
		if err == nil {
			return activation, nil
		}
		last = err
		var ambiguous *hostctl.ActivationRequestAmbiguousError
		if !errors.As(err, &ambiguous) {
			return nil, err
		}
		remaining, remainingErr := remainingContextDuration(ctx)
		if remainingErr != nil {
			return nil, errors.Join(last, remainingErr)
		}
		if remaining > macOSActivationFenceAndAbsenceTimeout {
			remaining = macOSActivationFenceAndAbsenceTimeout
		}
		if err := waitForAmbiguousActivationFence(
			ambiguous,
			socketPath,
			leasePath,
			token,
			oldRelease,
			targetRelease,
			remaining,
		); err != nil {
			return nil, errors.Join(last, err)
		}
		// The first host is now durably rollback-absent. A retry is admitted
		// only if the same parent deadline still contains a complete fresh
		// activation budget. Otherwise stop at this proven safe phase rather
		// than launching a host that could outlive the in-memory token holder.
		if _, _, err := activationAdmission(
			time.Now(),
			contextDeadline(ctx),
			macOSFreshRollbackActivationBudget,
			0,
		); err != nil {
			return nil, fmt.Errorf("rollback activation self-fenced but lacks a complete retry budget: %w", errors.Join(last, err))
		}
	}
}

func acceptRollbackMacOSActivationRecoveringFence(
	ctx context.Context,
	activation *hostctl.ActivationSession,
	app, socketPath, leasePath, token string,
	oldRelease, targetRelease hostctl.ReleaseIdentity,
) (*hostctl.ActivationSession, error) {
	current := activation
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("rollback activation was repeatedly fenced before acceptance: %w", err)
		}
		if current == nil {
			var err error
			current, err = connectRollbackActivationRecoveringReadyLoss(
				ctx,
				app, socketPath, leasePath, token, oldRelease, targetRelease,
			)
			if err != nil {
				return nil, err
			}
			liveTimeout, timeoutErr := boundedContextDuration(ctx, 5*time.Second)
			if timeoutErr != nil {
				return nil, timeoutErr
			}
			if err := requireLiveMacOSServiceRelease(app, oldRelease, false, liveTimeout); err != nil {
				fenceErr := fenceReadyMacOSActivation(
					ctx, current, socketPath, macOSActivationFenceAndAbsenceTimeout,
				)
				_ = current.Close()
				current = nil
				if fenceErr != nil {
					return nil, errors.Join(err, fenceErr)
				}
				continue
			}
		}
		acceptContext, cancel, admissionErr := activationChildContext(
			ctx,
			macOSActivationAcceptReconcileTimeout,
			macOSActivationCompletionReserve,
		)
		if admissionErr != nil {
			fenceErr := fenceReadyMacOSActivation(
				ctx, current, socketPath, macOSActivationFenceAndAbsenceTimeout,
			)
			if current != activation {
				_ = current.Close()
			}
			if fenceErr != nil {
				return nil, fmt.Errorf("rollback activation lacks safe acceptance budget: %w; fence=%v", admissionErr, fenceErr)
			}
			return nil, &activationFencedForBudgetError{Cause: admissionErr}
		}
		accepted, fenced, err := acceptOrResumeMacOSActivation(
			acceptContext,
			current,
			app,
			socketPath,
			leasePath,
			token,
			"rollback",
			oldRelease,
			oldRelease,
			targetRelease,
		)
		cancel()
		if err != nil {
			return nil, err
		}
		if !fenced {
			return accepted, nil
		}
		if current != activation {
			_ = current.Close()
		}
		current = nil
	}
}

type activationFencedForBudgetError struct{ Cause error }

func (e *activationFencedForBudgetError) Error() string {
	return "activation was explicitly fenced before an under-budget irreversible edge: " + e.Cause.Error()
}

func (e *activationFencedForBudgetError) Unwrap() error { return e.Cause }

func remainingContextDuration(ctx context.Context) (time.Duration, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, fmt.Errorf("activation reconciliation context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, ctx.Err()
	}
	return remaining, nil
}

func contextDeadline(ctx context.Context) time.Time {
	deadline, _ := ctx.Deadline()
	return deadline
}

func activationAdmission(
	now, deadline time.Time,
	operation, reserve time.Duration,
) (time.Duration, time.Duration, error) {
	if deadline.IsZero() || operation <= 0 || reserve < 0 {
		return 0, 0, fmt.Errorf("activation admission has an invalid deadline or budget")
	}
	remaining := deadline.Sub(now)
	required := operation + reserve
	if remaining < required {
		return remaining, required, fmt.Errorf(
			"activation deadline has %s remaining; operation requires %s plus %s reserved for reconciliation",
			remaining, operation, reserve,
		)
	}
	return operation, reserve, nil
}

func activationChildContext(
	parent context.Context,
	operation, reserve time.Duration,
) (context.Context, context.CancelFunc, error) {
	deadline, ok := parent.Deadline()
	if !ok {
		return nil, nil, fmt.Errorf("activation reconciliation context has no deadline")
	}
	childBudget, _, err := activationAdmission(time.Now(), deadline, operation, reserve)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(parent, childBudget)
	return ctx, cancel, nil
}

func fenceReadyMacOSActivation(
	ctx context.Context,
	activation *hostctl.ActivationSession,
	socketPath string,
	totalBudget time.Duration,
) error {
	fenceContext, cancel, err := activationChildContext(ctx, totalBudget/2, totalBudget/2)
	if err != nil {
		return err
	}
	peerPID := activation.HostPID()
	fenceErr := activation.Fence(fenceContext)
	cancel()
	if fenceErr != nil {
		return fenceErr
	}
	absenceTimeout, err := boundedContextDuration(ctx, totalBudget/2)
	if err != nil {
		return err
	}
	return waitForPreparedHostAbsence(peerPID, socketPath, absenceTimeout)
}

func boundedContextDuration(ctx context.Context, maximum time.Duration) (time.Duration, error) {
	remaining, err := remainingContextDuration(ctx)
	if err != nil {
		return 0, err
	}
	if remaining < maximum {
		return remaining, nil
	}
	return maximum, nil
}

// acceptOrResumeMacOSActivation resolves the only two durable outcomes after
// an activation decision write or acknowledgement fails. An exact active
// lease is resumed over a new credentialed connection after re-proving the
// running release. An exact rollback-absent lease is returned only after the
// original host execution and listener have departed. The plaintext token is
// retained solely by this process throughout reconciliation.
func acceptOrResumeMacOSActivation(
	ctx context.Context,
	activation *hostctl.ActivationSession,
	app, socketPath, leasePath, token, kind string,
	activeRelease, oldRelease, targetRelease hostctl.ReleaseIdentity,
) (*hostctl.ActivationSession, bool, error) {
	if kind != "target" && kind != "rollback" {
		return nil, false, fmt.Errorf("invalid activation kind %q", kind)
	}
	acceptContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := activation.Accept(acceptContext)
	cancel()
	if err == nil {
		return activation, false, nil
	} else {
		acceptErr := err
		activePhase := hostctl.PhaseTargetActive
		resumeOperation := "resume-target"
		if kind == "rollback" {
			activePhase = hostctl.PhaseRollbackActive
			resumeOperation = "resume-rollback"
		}
		var activeErr, fencedErr, resumeErr error
		for {
			if err := hostctl.RequireLease(
				leasePath, token, activePhase, oldRelease, targetRelease,
			); err == nil {
				if err := requireLiveMacOSServiceRelease(app, activeRelease, kind == "target", 2*time.Second); err != nil {
					activeErr = err
				} else {
					resumed, err := hostctl.ResumeActive(
						ctx,
						socketPath,
						resumeOperation,
						token,
						activeRelease,
						oldRelease,
						targetRelease,
					)
					if err == nil {
						return resumed, false, nil
					}
					resumeErr = err
				}
			} else {
				activeErr = err
			}
			if err := hostctl.RequireLease(
				leasePath, token, hostctl.PhaseRollbackAbsent, oldRelease, targetRelease,
			); err == nil {
				if err := waitForPreparedHostAbsence(
					activation.HostPID(), socketPath, time.Second,
				); err == nil {
					return nil, true, nil
				} else {
					fencedErr = err
				}
			} else {
				fencedErr = err
			}
			select {
			case <-ctx.Done():
				return nil, false, fmt.Errorf(
					"activation acceptance is neither resumably %s nor exactly fenced: accept=%v active=%v resume=%v fenced=%v: %w",
					activePhase, acceptErr, activeErr, resumeErr, fencedErr, ctx.Err(),
				)
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
}

// completeOrResumeMacOSActivation makes the terminal marker the authority for
// completion acknowledgement loss. If the host never crossed that edge, the
// exact active lease and live release authorize a fresh completion-only
// session. Neither absence nor a launch callback is interpreted as success.
func completeOrResumeMacOSActivation(
	ctx context.Context,
	activation *hostctl.ActivationSession,
	app, socketPath, leasePath, token, kind string,
	activeRelease, oldRelease, targetRelease hostctl.ReleaseIdentity,
	reconcileCompleted func() error,
) error {
	completeContext, completeCancel, admissionErr := activationChildContext(
		ctx,
		macOSActivationCompletionRequestTimeout,
		macOSActivationCompletionReconcileTimeout-macOSActivationCompletionRequestTimeout,
	)
	if admissionErr != nil {
		return fmt.Errorf("activation completion lacks its exact reconciliation reserve: %w", admissionErr)
	}
	err := activation.Complete(completeContext)
	completeCancel()
	if err == nil {
		return nil
	}
	firstErr := err
	activePhase := hostctl.PhaseTargetActive
	resumeOperation := "resume-target"
	if kind == "rollback" {
		activePhase = hostctl.PhaseRollbackActive
		resumeOperation = "resume-rollback"
	} else if kind != "target" {
		return fmt.Errorf("invalid activation kind %q", kind)
	}
	var completedErr, activeErr, resumeErr error
	for {
		if err := reconcileCompleted(); err == nil {
			return nil
		} else {
			completedErr = err
		}
		if err := hostctl.RequireLease(
			leasePath, token, activePhase, oldRelease, targetRelease,
		); err == nil {
			if err := requireLiveMacOSServiceRelease(app, activeRelease, kind == "target", 2*time.Second); err != nil {
				activeErr = err
			} else {
				resumeContext, resumeCancel, admissionErr := activationChildContext(
					ctx,
					macOSActivationResumeRequestTimeout,
					macOSActivationCompletionRequestTimeout+macOSActivationTerminalProofTimeout,
				)
				if admissionErr != nil {
					return fmt.Errorf("active activation lacks resume/completion reserve: %w", admissionErr)
				}
				resumed, err := hostctl.ResumeActive(
					resumeContext,
					socketPath,
					resumeOperation,
					token,
					activeRelease,
					oldRelease,
					targetRelease,
				)
				resumeCancel()
				if err == nil {
					completeContext, completeCancel, admissionErr := activationChildContext(
						ctx,
						macOSActivationCompletionRequestTimeout,
						macOSActivationTerminalProofTimeout,
					)
					if admissionErr != nil {
						_ = resumed.Close()
						return fmt.Errorf("resumed activation lacks completion/terminal-proof reserve: %w", admissionErr)
					}
					completeErr := resumed.Complete(completeContext)
					completeCancel()
					_ = resumed.Close()
					if completeErr == nil {
						return nil
					}
					resumeErr = completeErr
				} else {
					resumeErr = err
				}
			}
		} else {
			activeErr = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"activation completion is neither durably complete nor resumably %s: first=%v completed=%v active=%v resume=%v: %w",
				activePhase, firstErr, completedErr, activeErr, resumeErr, ctx.Err(),
			)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func requireLiveMacOSServiceRelease(app string, release hostctl.ReleaseIdentity, incoming bool, timeout time.Duration) error {
	cfg, err := fixedFSKitConfig()
	if err != nil {
		return err
	}
	return requireLiveMacOSServiceReleaseWithConfig(cfg, app, release, incoming, timeout)
}

func requireLiveMacOSServiceReleaseWithConfig(cfg fskitConfig, app string, release hostctl.ReleaseIdentity, incoming bool, timeout time.Duration) error {
	path := filepath.Join(app, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath))
	ctl, err := cfg.controlForRelease(path, release.DaemonVersion)
	if err != nil {
		return err
	}
	defer ctl.close()
	if ctl.expected.identity != release {
		return fmt.Errorf("authenticated daemon release changed")
	}
	if incoming {
		return ctl.requireCompatibleIdentityWithin(release.DaemonVersion, release.ExecutableSHA256, timeout)
	}
	return ctl.requireOutgoingIdentityWithin(release, timeout)
}

func nativeCodeArchitecture() (string, error) {
	if runtime.GOARCH == "arm64" {
		return "arm64", nil
	}
	if runtime.GOARCH != "amd64" {
		return "", fmt.Errorf("unsupported native daemon architecture %s", runtime.GOARCH)
	}
	translated, err := unix.SysctlUint32("sysctl.proc_translated")
	if errors.Is(err, syscall.ENOENT) {
		return "x86_64", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect native daemon architecture: %w", err)
	}
	if translated == 1 {
		return "arm64", nil
	}
	if translated == 0 {
		return "x86_64", nil
	}
	return "", fmt.Errorf("invalid process translation status %d", translated)
}

// The exact bundle hierarchy, signatures, entitlements and executable digest
// authorize the expected socket identity. Caller-supplied hashes cannot do so.
func authenticateDaemonRelease(path, version string) (daemonRelease, error) {
	suffix := "/Contents/" + macOSPortableFSDRelativePath
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasSuffix(path, suffix) {
		return daemonRelease{}, fmt.Errorf("expected daemon must be at its canonical owning-bundle path")
	}
	app := strings.TrimSuffix(path, suffix)
	resolved, err := filepath.EvalSymlinks(app)
	if err != nil || resolved != app {
		return daemonRelease{}, fmt.Errorf("daemon owning bundle path is not canonical: %v", err)
	}
	appID, err := sourceMacOSBundleIdentity(app)
	if err != nil {
		return daemonRelease{}, err
	}
	if err := validateInstalledMacOSBundleForPublicationWithLayout(app, version, appID, compiledMacOSInstallLayout); err != nil {
		return daemonRelease{}, err
	}
	identity, err := macOSServiceReleaseIdentity(app, version)
	if err != nil {
		return daemonRelease{}, err
	}
	return daemonRelease{path: path, identity: identity}, nil
}

// reconcileCompletedMacOSActivation is the only safe interpretation of a
// lost/invalid completion reply. The host persists an exact token-bound
// terminal marker before replying, so a reply can be lost after the transaction
// is complete. Absence is never success: the completed marker, retired other
// release, installed hierarchy, sealed service tuple, and live daemon must all
// agree. Every ambiguity remains an installation failure.
func reconcileCompletedMacOSActivation(
	leasePath string,
	destinationApp string,
	token string,
	completedPhase string,
	oldRelease hostctl.ReleaseIdentity,
	targetRelease hostctl.ReleaseIdentity,
	expectedApp pathSnapshot,
	prepared *preparedMacOSInstall,
) error {
	var expected hostctl.ReleaseIdentity
	switch completedPhase {
	case hostctl.PhaseTargetComplete:
		expected = targetRelease
	case hostctl.PhaseRollbackComplete:
		expected = oldRelease
	default:
		return fmt.Errorf("unsupported completed activation phase %q", completedPhase)
	}
	proofs := completedMacOSActivationProofs{
		requireCompletedLease: func() error {
			return hostctl.RequireLease(
				leasePath,
				token,
				completedPhase,
				oldRelease,
				targetRelease,
			)
		},
		requireFinalized: func() error {
			if prepared == nil || prepared.stageRoot != "" || prepared.stageApp != "" || prepared.linkRoot != "" {
				return fmt.Errorf("the displaced release transaction was not durably retired")
			}
			if err := rejectOrphanedMacOSInstallTransactions(filepath.Dir(destinationApp), ""); err != nil {
				return err
			}
			return rejectOrphanedMacOSLinkTransactions(filepath.Dir(prepared.linkPath), "")
		},
		requireDestination: func() error {
			if err := requireUnchangedPath(destinationApp, expectedApp); err != nil {
				return err
			}
			if prepared.expectedAppID == "" {
				return fmt.Errorf("missing exact installed host bundle identity")
			}
			validateDestination := validateMacOSBundleForPublicationWithLayout
			if completedPhase == hostctl.PhaseRollbackComplete {
				validateDestination = validateInstalledMacOSBundleForPublicationWithLayout
			}
			if err := validateDestination(
				destinationApp, expected.DaemonVersion, prepared.expectedAppID, prepared.layout,
			); err != nil {
				return err
			}
			observed, err := macOSServiceReleaseIdentity(destinationApp, expected.DaemonVersion)
			if err != nil {
				return err
			}
			if observed != expected {
				return fmt.Errorf("installed daemon release identity changed after activation acceptance")
			}
			return nil
		},
		requireLive: func() error {
			return requireLiveMacOSServiceRelease(destinationApp, expected, completedPhase == hostctl.PhaseTargetComplete, 5*time.Second)
		},
	}
	return reconcileCompletedMacOSActivationProofs(proofs)
}

type completedMacOSActivationProofs struct {
	requireCompletedLease func() error
	requireFinalized      func() error
	requireDestination    func() error
	requireLive           func() error
}

func reconcileCompletedMacOSActivationProofs(proofs completedMacOSActivationProofs) error {
	for _, proof := range []struct {
		name string
		fn   func() error
	}{
		{name: "completed activation marker", fn: proofs.requireCompletedLease},
		{name: "retired alternate release", fn: proofs.requireFinalized},
		{name: "installed release identity", fn: proofs.requireDestination},
		{name: "live daemon identity", fn: proofs.requireLive},
		// Re-prove the mutable named boundaries after the live query.
		{name: "completed activation marker recheck", fn: proofs.requireCompletedLease},
		{name: "installed release identity recheck", fn: proofs.requireDestination},
	} {
		if proof.fn == nil {
			return fmt.Errorf("missing %s proof", proof.name)
		}
		if err := proof.fn(); err != nil {
			return fmt.Errorf("%s: %w", proof.name, err)
		}
	}
	return nil
}

func rejectPreparedMacOSRuntime(
	e *cmdEnv,
	stateDir string,
	hostWitness hostctl.ProcessWitness,
	expectedHostExecutable string,
	updateSocket string,
) error {
	hostPID := hostWitness.PID
	if hostPID <= 0 || hostPID == os.Getpid() {
		return fmt.Errorf("invalid prepared PortableFS host pid %d", hostPID)
	}
	if err := rejectDurableMountAnchors(stateDir); err != nil {
		return err
	}
	mounts, err := darwinMountTable()
	if err != nil {
		return err
	}
	liveMounts, err := portableFSKernelPaths(mounts)
	if err != nil {
		return fmt.Errorf("strict PortableFS kernel inventory: %w", err)
	}
	if len(liveMounts) != 0 {
		return fmt.Errorf("kernel FSKit mount remains at %s; cleanly unmount it before installing", liveMounts[0])
	}
	// Bracket the immutable audit-token/path proof with full same-user process
	// inventories. p_comm is only a conservative rejection filter; the one
	// allowed prepared host is authorized by its socket-captured pidversion and
	// executable path, never by a reusable pid or truncated name.
	for proof := 0; proof < 2; proof++ {
		processes, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Geteuid())
		if err != nil {
			return fmt.Errorf("inventory same-user processes during prepared installation: %w", err)
		}
		if err := rejectPreparedMacOSProcessInventory(processes, os.Getpid(), hostPID); err != nil {
			return err
		}
		if err := hostWitness.RequireCurrentExecutable(expectedHostExecutable); err != nil {
			return fmt.Errorf("re-prove prepared PortableFS host: %w", err)
		}
	}
	cfg, err := fixedFSKitConfig()
	if err != nil {
		return err
	}
	if err := requireRuntimePathAbsent(cfg.controlSock, "portablefsd control socket"); err != nil {
		return err
	}
	info, err := os.Lstat(updateSocket)
	if err != nil {
		return fmt.Errorf("inspect prepared host update socket %s: %w", updateSocket, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("prepared host update path %s is not a Unix socket", updateSocket)
	}
	return nil
}

func rejectPreparedMacOSProcessInventory(
	processes []unix.KinfoProc,
	installerPID int,
	hostPID int,
) error {
	preparedHostFound := false
	for _, process := range processes {
		pid := int(process.Proc.P_pid)
		if pid == installerPID {
			continue
		}
		name := unix.ByteSliceToString(process.Proc.P_comm[:])
		if !isPortableFSMacOSProcessName(name) {
			continue
		}
		if pid == hostPID {
			preparedHostFound = true
			continue
		}
		return fmt.Errorf(
			"same-user %s process (pid %d) raced the prepared PortableFS update",
			name,
			pid,
		)
	}
	if !preparedHostFound {
		return fmt.Errorf("prepared PortableFS host pid %d disappeared before update commit", hostPID)
	}
	return nil
}

func waitForPreparedHostAbsence(hostPID int, socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		processGone := unix.Kill(hostPID, 0) == unix.ESRCH
		_, err := os.Lstat(socketPath)
		socketGone := os.IsNotExist(err)
		if err != nil && !socketGone {
			return fmt.Errorf("inspect committed host update socket %s: %w", socketPath, err)
		}
		if processGone && socketGone {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf(
		"prepared PortableFS host pid %d or update socket %s remained after commit-exit",
		hostPID,
		socketPath,
	)
}

func waitForPreparedHostProcessAbsence(hostPID int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if unix.Kill(hostPID, 0) == unix.ESRCH {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("prepared PortableFS host pid %d remained after commit-exit", hostPID)
}

func requireRuntimePathAbsent(path, label string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s %s still exists", label, path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect %s %s: %w", label, path, err)
	}
	return nil
}

func rejectLiveMacOSRuntime(e *cmdEnv, stateDir string) error {
	return rejectLiveMacOSRuntimeWithLayout(e, stateDir, compiledMacOSInstallLayout)
}

func rejectLiveMacOSRuntimeWithLayout(
	e *cmdEnv,
	stateDir string,
	layout macOSInstallLayout,
) error {
	if err := layout.validate(); err != nil {
		return err
	}
	if err := rejectDurableMountAnchors(stateDir); err != nil {
		return err
	}
	mounts, err := darwinMountTable()
	if err != nil {
		return err
	}
	liveMounts, err := portableFSKernelPaths(mounts)
	if err != nil {
		return fmt.Errorf("strict PortableFS kernel inventory: %w", err)
	}
	if len(liveMounts) != 0 {
		return fmt.Errorf(
			"kernel FSKit mount remains at %s; cleanly unmount it before installing",
			liveMounts[0],
		)
	}
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Geteuid())
	if err != nil {
		return fmt.Errorf("inventory same-user processes before installation: %w", err)
	}
	for _, process := range processes {
		if int(process.Proc.P_pid) == os.Getpid() {
			continue
		}
		name := unix.ByteSliceToString(process.Proc.P_comm[:])
		if isPortableFSMacOSProcessName(name) {
			return fmt.Errorf(
				"same-user %s process (pid %d) is still running; quit the app, cleanly unmount every volume, and stop portablefsd before installing",
				name,
				process.Proc.P_pid,
			)
		}
	}
	cfg, err := fixedFSKitConfig()
	if err != nil {
		return err
	}
	// The installer CLI may inspect only the external control socket. The
	// app-group frontend belongs to the host/agent/extension Data Vault and is
	// never resolved or traversed by a shell process.
	if _, err := os.Lstat(cfg.controlSock); err == nil {
		return fmt.Errorf(
			"portablefsd control socket %s still exists; prepare the host for update after unmounting",
			cfg.controlSock,
		)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect portablefsd control socket %s: %w", cfg.controlSock, err)
	}
	return nil
}

func isPortableFSMacOSProcessName(name string) bool {
	for _, executable := range []string{
		"PortableFS",
		"PortableFSApp",
		"PortableFSExt",
		"PortableFSKitDev",
		"PortableFSKitMacOS27Dev",
		"PortableFSDev",
		macOSCLIName,
		"portablefsd",
		"portablefs-workspace-service",
	} {
		if name == truncatedProcessName(executable) {
			return true
		}
	}
	return false
}

func truncatedProcessName(name string) string {
	// Darwin's struct extern_proc stores p_comm[MAXCOMLEN + 1]. Deriving the
	// remembered byte count from x/sys avoids repeating the former off-by-one
	// assumption that rejected an exact 16-byte executable name.
	const darwinProcessNameLimit = len(unix.ExternProc{}.P_comm) - 1
	if len(name) > darwinProcessNameLimit {
		return name[:darwinProcessNameLimit]
	}
	return name
}

type darwinMount = kernelMountIdentity

func darwinMountTable() ([]darwinMount, error) {
	count, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, fmt.Errorf("read kernel mount count: %w", err)
	}
	for {
		stats := make([]unix.Statfs_t, count+8)
		n, err := unix.Getfsstat(stats, unix.MNT_NOWAIT)
		if err != nil {
			return nil, fmt.Errorf("read kernel mount table: %w", err)
		}
		// A completely filled buffer may have truncated mounts that appeared
		// after the count probe. Only a result with spare capacity is complete.
		if n < len(stats) {
			out := make([]darwinMount, 0, n)
			for _, stat := range stats[:n] {
				out = append(out, darwinMount{
					fsType: unix.ByteSliceToString(stat.Fstypename[:]),
					path:   unix.ByteSliceToString(stat.Mntonname[:]),
					source: unix.ByteSliceToString(stat.Mntfromname[:]),
				})
			}
			return out, nil
		}
		count = n
	}
}

func validateStagedBundleForPublication(app, version, expectedAppID string) error {
	return validateStagedBundleForPublicationWithLayout(
		app,
		version,
		expectedAppID,
		compiledMacOSInstallLayout,
	)
}

func validateStagedBundleForPublicationWithLayout(
	app string,
	version string,
	expectedAppID string,
	layout macOSInstallLayout,
) error {
	return validateMacOSBundleForPublicationWithLayout(
		app,
		version,
		expectedAppID,
		layout,
	)
}

func validateMacOSBundleForPublication(
	app, version, expectedAppID string,
) error {
	return validateMacOSBundleForPublicationWithLayout(
		app,
		version,
		expectedAppID,
		compiledMacOSInstallLayout,
	)
}

func validateInstalledMacOSBundleForPublicationWithLayout(
	app, version, expectedAppID string,
	layout macOSInstallLayout,
) error {
	return validateMacOSBundleForPublicationWithLayout(app, version, expectedAppID, layout)
}

func validateMacOSBundleForPublicationWithLayout(
	app, version, expectedAppID string,
	layout macOSInstallLayout,
) error {
	if err := layout.validate(); err != nil {
		return err
	}
	var symlink string
	err := filepath.WalkDir(app, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			symlink = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk staged app hierarchy: %w", err)
	}
	if symlink != "" {
		return fmt.Errorf("staged app contains unexpected symlink %s", symlink)
	}

	appID, err := sourceMacOSBundleIdentityWithLayout(app, layout)
	if err != nil {
		return err
	}
	if appID != expectedAppID {
		return fmt.Errorf("bundle identifier %q differs from expected %q", appID, expectedAppID)
	}

	appExecutable := filepath.Join(app, "Contents", "MacOS", layout.appExecutable)
	cli := filepath.Join(app, "Contents", "Helpers", macOSCLIName)
	daemon := filepath.Join(app, "Contents", filepath.FromSlash(macOSPortableFSDRelativePath))
	serviceApp := filepath.Join(app, "Contents", "Library", "LaunchAgents", "PortableFSDService.app")
	extension := filepath.Join(app, "Contents", "Extensions", layout.extensionExecutable+".appex")
	extensionExecutable := filepath.Join(
		extension,
		"Contents",
		"MacOS",
		layout.extensionExecutable,
	)
	for _, executable := range []string{appExecutable, cli, daemon, extensionExecutable} {
		info, err := os.Lstat(executable)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("staged app has no real executable at %s", executable)
		}
	}
	extensions, err := filepath.Glob(filepath.Join(app, "Contents", "Extensions", "*.appex"))
	if err != nil || len(extensions) != 1 || extensions[0] != extension {
		return fmt.Errorf("staged app must contain exactly %s.appex", layout.extensionExecutable)
	}
	serviceApps, err := filepath.Glob(filepath.Join(app, "Contents", "Library", "LaunchAgents", "*.app"))
	expectedServices := []string{serviceApp}
	if layout.codeIdentity == macOSInstallDeveloperIDRelease {
		expectedServices = append(expectedServices, filepath.Join(app, "Contents/Library/LaunchAgents/PortableFSWorkspaceService.app"))
	}
	if err != nil || !reflect.DeepEqual(serviceApps, expectedServices) {
		return fmt.Errorf("staged app must contain its exact service applications")
	}
	launchAgent := filepath.Join(
		app,
		"Contents",
		"Library",
		"LaunchAgents",
		expectedAppID+".portablefsd.plist",
	)
	launchAgents, err := filepath.Glob(filepath.Join(app, "Contents", "Library", "LaunchAgents", "*.plist"))
	expectedAgents := []string{launchAgent}
	if layout.codeIdentity == macOSInstallDeveloperIDRelease {
		expectedAgents = append(expectedAgents, filepath.Join(app, "Contents/Library/LaunchAgents", expectedAppID+".workspace.plist"))
	}
	if err != nil || !reflect.DeepEqual(launchAgents, expectedAgents) {
		return fmt.Errorf("staged app must contain exactly its sealed PortableFS LaunchAgent plist")
	}
	if err := validatePortableFSDLaunchAgentPlist(launchAgent, expectedAppID); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(serviceApp, "Contents", "embedded.provisionprofile")); err == nil {
		return fmt.Errorf("staged daemon service unexpectedly embeds a provisioning profile")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect staged daemon service profile: %w", err)
	}

	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", "--verbose=2", app).CombinedOutput(); err != nil {
		return fmt.Errorf("verify staged app code hierarchy: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	if layout.codeIdentity == macOSInstallDeveloperIDRelease {
		if out, err := exec.Command("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=2", app).CombinedOutput(); err != nil {
			return fmt.Errorf("Gatekeeper rejected staged app: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("/usr/bin/xcrun", "stapler", "validate", app).CombinedOutput(); err != nil {
			return fmt.Errorf("staged app has no valid notarization ticket: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
	}

	if layout.codeIdentity == macOSInstallDeveloperIDRelease {
		if err := validateWorkspaceBundleForPublication(app, version, expectedAppID, layout); err != nil {
			return err
		}
	}
	appVersion, err := plistValue(filepath.Join(app, "Contents", "Info.plist"), "CFBundleShortVersionString")
	if err != nil {
		return err
	}
	extensionVersion, err := plistValue(filepath.Join(extension, "Contents", "Info.plist"), "CFBundleShortVersionString")
	if err != nil {
		return err
	}
	serviceVersion, err := plistValue(filepath.Join(serviceApp, "Contents", "Info.plist"), "CFBundleShortVersionString")
	if err != nil {
		return err
	}
	if appVersion != version || extensionVersion != version || serviceVersion != version {
		return fmt.Errorf(
			"staged app versions do not match installer CLI %q (app %q, extension %q, service %q)",
			version,
			appVersion,
			extensionVersion,
			serviceVersion,
		)
	}
	if err := validatePortableFSDServiceInfo(
		filepath.Join(serviceApp, "Contents", "Info.plist"),
		expectedAppID+".PortableFSDService",
		version,
		layout.serviceMinimumOS,
	); err != nil {
		return err
	}
	for _, identity := range []struct {
		name       string
		plist      string
		bundleID   string
		executable string
	}{
		{
			name:       "app",
			plist:      filepath.Join(app, "Contents", "Info.plist"),
			bundleID:   expectedAppID,
			executable: layout.appExecutable,
		},
		{
			name:       "extension",
			plist:      filepath.Join(extension, "Contents", "Info.plist"),
			bundleID:   expectedAppID + "." + layout.extensionExecutable,
			executable: layout.extensionExecutable,
		},
		{
			name:       "daemon service",
			plist:      filepath.Join(serviceApp, "Contents", "Info.plist"),
			bundleID:   expectedAppID + ".PortableFSDService",
			executable: "portablefsd",
		},
	} {
		bundleID, err := plistValue(identity.plist, "CFBundleIdentifier")
		if err != nil {
			return err
		}
		executableName, err := plistValue(identity.plist, "CFBundleExecutable")
		if err != nil {
			return err
		}
		if bundleID != identity.bundleID || executableName != identity.executable {
			return fmt.Errorf(
				"staged %s identity mismatch: bundle %q executable %q, expected %q and %q",
				identity.name,
				bundleID,
				executableName,
				identity.bundleID,
				identity.executable,
			)
		}
	}
	extensionPoint, err := plistValue(
		filepath.Join(extension, "Contents", "Info.plist"),
		"EXAppExtensionAttributes:EXExtensionPointIdentifier",
	)
	if err != nil {
		return err
	}
	extensionFSName, err := plistValue(
		filepath.Join(extension, "Contents", "Info.plist"),
		"EXAppExtensionAttributes:FSShortName",
	)
	if err != nil {
		return err
	}
	extensionPersonalityName, err := plistValue(
		filepath.Join(extension, "Contents", "Info.plist"),
		"EXAppExtensionAttributes:FSPersonalities:PortableFSPersonality:FSName",
	)
	if err != nil {
		return err
	}
	supportsGenericURLResources, err := plistValue(
		filepath.Join(extension, "Contents", "Info.plist"),
		"EXAppExtensionAttributes:FSSupportsGenericURLResources",
	)
	if err != nil {
		return err
	}
	extensionSchemes, err := plistStringArray(
		filepath.Join(extension, "Contents", "Info.plist"),
		"EXAppExtensionAttributes.FSSupportedSchemes",
	)
	if err != nil {
		return err
	}
	profileOK := validMacOSBundleRegistration(
		extensionFSName,
		extensionPersonalityName,
		supportsGenericURLResources,
		extensionSchemes,
	)
	if extensionPoint != fskitExtensionType ||
		!profileOK {
		return fmt.Errorf(
			"staged extension registration mismatch: point %q fs type %q personality %q generic URL resources %q resource schemes %q",
			extensionPoint,
			extensionFSName,
			extensionPersonalityName,
			supportsGenericURLResources,
			extensionSchemes,
		)
	}
	extensionGroup, err := plistValue(
		filepath.Join(extension, "Contents", "Info.plist"),
		"PFSAppGroupIdentifier",
	)
	if err != nil {
		return err
	}
	if extensionGroup != fskitidentity.AppGroup {
		return fmt.Errorf(
			"staged extension app group %q does not match CLI app group %q",
			extensionGroup,
			fskitidentity.AppGroup,
		)
	}
	// Never execute bundle helpers until the complete nested hierarchy,
	// signing team, hardened runtime, signed identifiers, and app-group
	// entitlement have all been authenticated.
	if err := validateMacOSBundleCodeIdentity(
		app,
		extension,
		serviceApp,
		cli,
		daemon,
		expectedAppID,
		layout,
	); err != nil {
		return err
	}

	cliVersion, err := runExactOutput(cli, "version")
	if err != nil || cliVersion != "portablefs "+version {
		return fmt.Errorf("staged CLI version mismatch: got %q, expected %q (%v)", cliVersion, "portablefs "+version, err)
	}
	daemonVersion, err := runExactOutput(daemon, "-version")
	if err != nil || daemonVersion != version {
		return fmt.Errorf("staged daemon version mismatch: got %q, expected %q (%v)", daemonVersion, version, err)
	}
	for name, command := range map[string][]string{
		"CLI":    {cli, "lifecycle", "identity", "--json"},
		"daemon": {daemon, "-identity-json"},
	} {
		out, err := exec.Command(command[0], command[1:]...).Output()
		if err != nil {
			return fmt.Errorf("read staged %s identity: %w", name, err)
		}
		if !validMacOSBundleIdentityJSON(out) {
			return fmt.Errorf(
				"staged %s identity does not match release identity %+v",
				name,
				fskitidentity.Current(),
			)
		}
	}

	return nil
}

func validateMacOSBundleCodeIdentity(
	app, extension, serviceApp, cli, daemon, expectedAppID string,
	layout macOSInstallLayout,
) error {
	teamID, _, ok := strings.Cut(fskitidentity.AppGroup, ".")
	if !ok || teamID == "" {
		return fmt.Errorf("invalid linker-stamped app group %q", fskitidentity.AppGroup)
	}
	for _, code := range []struct {
		name, path, executable, identifier string
	}{
		{"host", app, filepath.Join(app, "Contents", "MacOS", layout.appExecutable), expectedAppID},
		{"extension", extension, filepath.Join(extension, "Contents", "MacOS", layout.extensionExecutable), expectedAppID + "." + layout.extensionExecutable},
		{"daemon service", serviceApp, daemon, expectedAppID + ".PortableFSDService"},
		{"CLI", cli, cli, ""},
		{"daemon", daemon, daemon, expectedAppID + ".PortableFSDService"},
	} {
		out, err := exec.Command("/usr/bin/lipo", "-archs", code.executable).CombinedOutput()
		if err != nil {
			return fmt.Errorf("inspect staged %s architectures: %w (output: %s)", code.name, err, strings.TrimSpace(string(out)))
		}
		architectures, err := macOSCodeArchitectures(string(out), layout.codeIdentity)
		if err != nil {
			return fmt.Errorf("staged %s: %w", code.name, err)
		}
		for _, architecture := range architectures {
			out, err := exec.Command("/usr/bin/codesign", "-dv", "--verbose=4", "--arch", architecture, code.path).CombinedOutput()
			if err != nil {
				return fmt.Errorf("inspect staged %s %s code identity: %w", code.name, architecture, err)
			}
			if err := validateMacOSCodeSignature(string(out), layout.codeIdentity, code.name, teamID, code.identifier); err != nil {
				return fmt.Errorf("staged %s %s: %w", code.name, architecture, err)
			}
			entitlements, err := exactCodeEntitlementsForArchitecture(code.path, filepath.Dir(app), architecture)
			if err != nil {
				return err
			}
			if err := validateMacOSComponentEntitlements(entitlements, code.name, fskitidentity.AppGroup); err != nil {
				return fmt.Errorf("staged %s %s: %w", code.name, architecture, err)
			}
		}
	}
	return nil
}

func macOSCodeArchitectures(output string, policy macOSInstallCodeIdentityPolicy) ([]string, error) {
	architectures := strings.Fields(output)
	seen := map[string]bool{}
	for _, architecture := range architectures {
		if (architecture != "arm64" && architecture != "x86_64") || seen[architecture] {
			return nil, fmt.Errorf("invalid code architectures %q", output)
		}
		seen[architecture] = true
	}
	if len(architectures) == 0 {
		return nil, fmt.Errorf("code has no architectures")
	}
	if policy == macOSInstallDeveloperIDRelease && (!seen["arm64"] || !seen["x86_64"]) {
		return nil, fmt.Errorf("production code must include arm64 and x86_64")
	}
	return architectures, nil
}

func validateMacOSCodeSignature(output string, policy macOSInstallCodeIdentityPolicy, component, teamID, identifier string) error {
	team, err := exactCodesignField(output, "TeamIdentifier")
	if err != nil || team != teamID {
		return fmt.Errorf("signature team does not equal %q: %v", teamID, err)
	}
	if !strings.Contains(output, "flags=0x10000(runtime)") {
		return fmt.Errorf("signature is missing hardened runtime")
	}
	if err := validateMacOSSigningAuthorities(output, policy, component); err != nil {
		return err
	}
	if identifier != "" {
		signed, err := exactCodesignField(output, "Identifier")
		if err != nil || signed != identifier {
			return fmt.Errorf("signature identifier does not match plist identifier %q: %v", identifier, err)
		}
	}
	return nil
}

func validateMacOSComponentEntitlements(entitlements map[string]any, component, group string) error {
	if _, ok := entitlements["com.apple.security.virtualization"]; ok {
		return fmt.Errorf("only the workspace service may hold virtualization")
	}

	if component == "CLI" {
		return validateAbsentMacOSAppGroupEntitlementDictionary(entitlements, component)
	}
	// The app-like service and its executable carry the same restricted signature.
	if component == "daemon service" {
		component = "daemon"
	}
	if component == "daemon" && len(entitlements) != 1 {
		return fmt.Errorf("signed daemon must carry only its app-group entitlement, got %v", entitlements)
	}
	return validateExactMacOSAppGroupEntitlementDictionary(entitlements, component, group)
}

func exactCodeEntitlements(code, tempRoot string) (map[string]any, error) {
	return exactCodeEntitlementsForArchitecture(code, tempRoot, "")
}

func exactCodeEntitlementsForArchitecture(code, tempRoot, architecture string) (map[string]any, error) {
	args := []string{"-d", "--entitlements", ":-"}
	if architecture != "" {
		args = append(args, "--arch", architecture)
	}
	args = append(args, code)
	entitlements, err := exec.Command("/usr/bin/codesign", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("read exact staged entitlements %s: %w", code, err)
	}
	return decodeExactCodeEntitlements(entitlements, tempRoot)
}

func decodeExactCodeEntitlements(entitlements []byte, tempRoot string) (map[string]any, error) {
	if len(bytes.TrimSpace(entitlements)) == 0 {
		return map[string]any{}, nil
	}
	entitlementPath, cleanup, err := writeEntitlementValidationFile(tempRoot, entitlements)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	out, err := exec.Command(
		"/usr/bin/plutil", "-convert", "json", "-o", "-", entitlementPath,
	).Output()
	if err != nil {
		return nil, fmt.Errorf("decode exact staged entitlements: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse exact staged entitlements: %w", err)
	}
	return result, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	return fmt.Errorf("invalid trailing JSON: %w", err)
}

func validateMacOSSigningAuthorities(output string, policy macOSInstallCodeIdentityPolicy, component string) error {
	prefix := "Authority=Developer ID Application: "
	switch policy {
	case macOSInstallDeveloperIDRelease:
	case macOSInstallDevelopmentHost:
		switch component {
		case "host", "extension", "CLI":
			prefix = "Authority=Apple Development: "
		case "daemon service", "daemon":
		default:
			return fmt.Errorf("unsupported development signing component %q", component)
		}
	default:
		return fmt.Errorf("unsupported macOS code identity policy")
	}
	matches := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("%s has %d exact %q signing authorities", component, matches, prefix)
	}
	return nil
}

func validateExactMacOSAppGroupEntitlementDictionary(
	entitlements map[string]any, name, expected string,
) error {
	groupsValue, ok := entitlements["com.apple.security.application-groups"]
	groups, groupsOK := groupsValue.([]any)
	if !ok || !groupsOK || len(groups) != 1 || groups[0] != expected {
		return fmt.Errorf(
			"signed %s app-group entitlement %q does not exactly match %q",
			name,
			groupsValue,
			expected,
		)
	}
	return nil
}

func validateAbsentMacOSAppGroupEntitlementDictionary(
	entitlements map[string]any, name string,
) error {
	if len(entitlements) != 0 {
		return fmt.Errorf("signed %s must carry no entitlements, got %v", name, entitlements)
	}
	return nil
}

func writeEntitlementValidationFile(
	tempRoot string,
	contents []byte,
) (string, func(), error) {
	file, err := os.CreateTemp(tempRoot, ".portablefs-entitlements-*.plist")
	if err != nil {
		return "", func() {}, fmt.Errorf("create entitlement validation file: %w", err)
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func validMacOSBundleRegistration(
	fsName string,
	personalityName string,
	supportsGenericURLResources string,
	resourceSchemes []string,
) bool {
	return fsName == defaultFskitType &&
		personalityName == defaultFskitType &&
		supportsGenericURLResources == "true" &&
		len(resourceSchemes) == 1 && resourceSchemes[0] == fskitidentity.ResourceScheme
}

func validMacOSBundleIdentityJSON(data []byte) bool {
	object, ok := decodeExactJSONObject(data)
	if !ok || len(object) != 4 {
		return false
	}
	var identity fskitidentity.Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return false
	}
	for _, key := range []string{"schemaVersion", "fsType", "resourceScheme", "appGroup"} {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return identity == fskitidentity.Current()
}

func plistValue(path, key string) (string, error) {
	out, err := exec.Command("/usr/libexec/PlistBuddy", "-c", "Print :"+key, path).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read %s from %s: %w (output: %s)", key, path, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func plistJSONObject(path string) (map[string]json.RawMessage, error) {
	out, err := exec.Command(
		"/usr/bin/plutil", "-convert", "json", "-o", "-", path,
	).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("decode exact property list %s: %w (output: %s)", path, err, strings.TrimSpace(string(out)))
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(out, &object); err != nil || object == nil {
		return nil, fmt.Errorf("decode exact property list object %s: %w", path, err)
	}
	return object, nil
}

func exactJSONString(value string) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}

func validateExactPlistObject(
	path string,
	expected map[string]json.RawMessage,
) error {
	object, err := plistJSONObject(path)
	if err != nil {
		return err
	}
	if len(object) != len(expected) {
		return fmt.Errorf("property list %s has %d top-level keys, expected exactly %d", path, len(object), len(expected))
	}
	for key, want := range expected {
		got, ok := object[key]
		if !ok || !exactJSONValueEqual(got, want) {
			return fmt.Errorf("property list %s has invalid %s", path, key)
		}
	}
	return nil
}

// plutil may choose any valid JSON spelling when it converts a property list.
// In particular, current macOS releases escape `/` as `\/`, while
// encoding/json emits `/`. Compare the decoded value and JSON type rather
// than those equivalent wire spellings. The caller still enforces the exact
// top-level key set and count.
func exactJSONValueEqual(got, want json.RawMessage) bool {
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		return false
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		return false
	}
	return reflect.DeepEqual(gotValue, wantValue)
}

func validatePortableFSDLaunchAgentPlist(path, appID string) error {
	return validateExactPlistObject(path, map[string]json.RawMessage{
		"Label":         exactJSONString(appID + ".portablefsd"),
		"BundleProgram": exactJSONString("Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd"),
		"RunAtLoad":     json.RawMessage("true"),
		"KeepAlive":     json.RawMessage("true"),
	})
}

func validatePortableFSDServiceInfo(
	path, serviceID, version, minimumSystemVersion string,
) error {
	object, err := plistJSONObject(path)
	if err != nil {
		return err
	}
	build, ok := object["CFBundleVersion"]
	if !ok {
		return fmt.Errorf("daemon service property list %s has no CFBundleVersion", path)
	}
	var buildString string
	if err := json.Unmarshal(build, &buildString); err != nil || buildString == "" || strings.IndexFunc(buildString, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return fmt.Errorf("daemon service property list %s has invalid CFBundleVersion", path)
	}
	return validateExactPlistObject(path, map[string]json.RawMessage{
		"CFBundleDevelopmentRegion":        exactJSONString("en"),
		"CFBundleExecutable":               exactJSONString("portablefsd"),
		"CFBundleIdentifier":               exactJSONString(serviceID),
		"CFBundleInfoDictionaryVersion":    exactJSONString("6.0"),
		"CFBundleName":                     exactJSONString("PortableFSDService"),
		"CFBundlePackageType":              exactJSONString("APPL"),
		"CFBundleShortVersionString":       exactJSONString(version),
		"CFBundleVersion":                  exactJSONString(buildString),
		"LSBackgroundOnly":                 json.RawMessage("true"),
		"LSMinimumSystemVersion":           exactJSONString(minimumSystemVersion),
		"NSLocalNetworkUsageDescription":   exactJSONString("PortableFS connects to filesystem authorities on your local network to mount and access your files."),
		"NSNetworkVolumesUsageDescription": exactJSONString("PortableFS accesses the volumes you mount to keep their files consistent with the filesystem authority."),
	})
}

func plistStringArray(path, keyPath string) ([]string, error) {
	out, err := exec.Command(
		"/usr/bin/plutil",
		"-extract",
		keyPath,
		"json",
		"-o",
		"-",
		path,
	).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"read %s from %s: %w (output: %s)",
			keyPath,
			path,
			err,
			strings.TrimSpace(string(out)),
		)
	}
	var values []string
	if err := json.Unmarshal(out, &values); err != nil {
		return nil, fmt.Errorf("decode %s from %s: %w", keyPath, path, err)
	}
	return values, nil
}

func runExactOutput(path string, args ...string) (string, error) {
	out, err := exec.Command(path, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func syncInstallDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

func makeStagedMacOSAppDurable(app string) error {
	var directories []string
	err := filepath.WalkDir(app, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("staged app contains unexpected symlink %s", path)
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("staged app contains unsupported non-regular entry %s", path)
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("open staged file %s for sync: %w", path, err)
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(fd, &stat)
		syncErr := unix.Fsync(fd)
		closeErr := unix.Close(fd)
		if statErr != nil {
			return fmt.Errorf("inspect staged file %s before sync: %w", path, statErr)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("staged file %s changed type before sync", path)
		}
		if syncErr != nil {
			return fmt.Errorf("sync staged file %s: %w", path, syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close staged file %s after sync: %w", path, closeErr)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("make staged app files durable: %w", err)
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncInstallDirectory(directories[index]); err != nil {
			return fmt.Errorf("sync staged app directory %s: %w", directories[index], err)
		}
	}
	if err := syncInstallDirectory(filepath.Dir(app)); err != nil {
		return fmt.Errorf("sync staged app parent before publication: %w", err)
	}
	return nil
}

func rejectConflictingPFSProviders(home, canonicalApp string) error {
	for _, appDomain := range []string{filepath.Join(home, "Applications"), "/Applications"} {
		entries, err := os.ReadDir(appDomain)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect app domain %s for FSKit conflicts: %w", appDomain, err)
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".app") {
				continue
			}
			appPath := filepath.Join(appDomain, entry.Name())
			if filepath.Clean(appPath) == canonicalApp {
				continue
			}
			claims, err := appClaimsPFS(appPath)
			if err != nil {
				return err
			}
			if claims {
				return pfsProviderConflict(appPath, "")
			}
		}
	}

	out, err := exec.Command(
		"/usr/bin/pluginkit",
		"-m", "-A", "-D", "-v",
		"-p", fskitExtensionType,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("inventory registered FSKit providers with PlugInKit: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		appexPath := strings.TrimSpace(fields[len(fields)-1])
		if !filepath.IsAbs(appexPath) {
			continue
		}
		claims, err := extensionClaimsPFS(appexPath)
		if err != nil {
			return err
		}
		if !claims {
			continue
		}
		appPath := containingAppPath(appexPath)
		if appPath != "" && filepath.Clean(appPath) == canonicalApp {
			continue
		}
		return pfsProviderConflict(appPath, appexPath)
	}
	return nil
}

func appClaimsPFS(appPath string) (bool, error) {
	pattern := filepath.Join(appPath, "Contents", "Extensions", "*.appex")
	extensions, err := filepath.Glob(pattern)
	if err != nil {
		return false, fmt.Errorf("inspect FSKit extensions in %s: %w", appPath, err)
	}
	for _, extension := range extensions {
		claims, err := extensionClaimsPFS(extension)
		if err != nil {
			return false, err
		}
		if claims {
			return true, nil
		}
	}
	return false, nil
}

func extensionClaimsPFS(extensionPath string) (bool, error) {
	infoPath := filepath.Join(extensionPath, "Contents", "Info.plist")
	if _, err := os.Lstat(infoPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("inspect FSKit extension metadata %s: %w", infoPath, err)
	}
	shortNameOut, shortNameErr := exec.Command(
		"/usr/libexec/PlistBuddy",
		"-c", "Print :EXAppExtensionAttributes:FSShortName",
		infoPath,
	).CombinedOutput()
	if shortNameErr != nil && !strings.Contains(string(shortNameOut), "Does Not Exist") {
		return false, fmt.Errorf(
			"read FSShortName from %s: %w (output: %s)",
			infoPath,
			shortNameErr,
			strings.TrimSpace(string(shortNameOut)),
		)
	}
	if shortNameErr == nil && strings.TrimSpace(string(shortNameOut)) == defaultFskitType {
		return true, nil
	}

	schemesOut, schemesErr := exec.Command(
		"/usr/bin/plutil",
		"-extract",
		"EXAppExtensionAttributes.FSSupportedSchemes",
		"json",
		"-o",
		"-",
		infoPath,
	).CombinedOutput()
	if schemesErr != nil {
		if strings.Contains(string(schemesOut), "No value at that key path") {
			return false, nil
		}
		return false, fmt.Errorf(
			"read FSSupportedSchemes from %s: %w (output: %s)",
			infoPath,
			schemesErr,
			strings.TrimSpace(string(schemesOut)),
		)
	}
	var schemes []string
	if err := json.Unmarshal(schemesOut, &schemes); err != nil {
		return false, fmt.Errorf("decode FSSupportedSchemes from %s: %w", infoPath, err)
	}
	for _, scheme := range schemes {
		if strings.EqualFold(scheme, fskitidentity.ResourceScheme) {
			return true, nil
		}
	}
	return false, nil
}

func containingAppPath(path string) string {
	index := strings.LastIndex(path, ".app/")
	if index < 0 {
		return ""
	}
	return path[:index+len(".app")]
}

func pfsProviderConflict(appPath, extensionPath string) error {
	target := appPath
	if target == "" {
		target = extensionPath
	}
	cleanup := fmt.Sprintf("remove the conflicting app at %s", target)
	if extensionPath != "" {
		cleanup = fmt.Sprintf("remove its containing app, or run `pluginkit -r %s`", extensionPath)
	}
	return fmt.Errorf(
		"another registered or installed provider claims the PortableFS OSS FSKit type or resource scheme at %s; %s, then retry so macOS has exactly one deterministic provider",
		target,
		cleanup,
	)
}

func connectInstalledPortablefsd(cfg fskitConfig) (*fsdControl, error) {
	path, err := findPortablefsd("")
	if err != nil {
		return nil, err
	}
	app := strings.TrimSuffix(path, "/Contents/"+macOSPortableFSDRelativePath)
	version, err := plistValue(filepath.Join(app, "Contents", "Info.plist"), "CFBundleShortVersionString")
	if err != nil {
		return nil, err
	}
	return connectCompatiblePortablefsd(cfg, version)
}

func preflightMacOSInstallSpace(sourceApp, destinationDirectory string) error {
	var expanded uint64
	err := filepath.WalkDir(sourceApp, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() < 0 {
			return fmt.Errorf("unsafe installer member %s", path)
		}
		size := uint64(info.Size())
		if size > (^uint64(0) - expanded) {
			return fmt.Errorf("installer size overflow")
		}
		expanded += size
		return nil
	})
	if err != nil {
		return err
	}
	if expanded > (^uint64(0)-(2<<30))/2 {
		return fmt.Errorf("installer size overflow")
	}
	var space unix.Statfs_t
	if err := unix.Statfs(destinationDirectory, &space); err != nil {
		return fmt.Errorf("check install free space: %w", err)
	}
	required := 2*expanded + (2 << 30)
	available := uint64(space.Bavail) * uint64(space.Bsize)
	if available < required {
		return fmt.Errorf("Not enough disk space: need %d bytes; available %d", required, available)
	}
	return nil
}
