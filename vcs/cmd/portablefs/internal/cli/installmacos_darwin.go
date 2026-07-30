//go:build darwin

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"golang.org/x/sys/unix"
)

const (
	macOSAppName             = "PortableFS.app"
	macOSStagedAppName       = "PortableFS.next"
	macOSAppExecutable       = "PortableFS"
	macOSExtensionExecutable = "PortableFSExt"
	macOSCLIName             = "portablefs"
	fskitExtensionType       = "com.apple.fskit.fsmodule"
)

type preparedMacOSInstall struct {
	stageRoot    string
	stageApp     string
	linkRoot     string
	linkTemp     string
	linkPath     string
	stageID      pathSnapshot
	appID        pathSnapshot
	linkID       pathSnapshot
	appParentID  pathSnapshot
	linkParentID pathSnapshot
	linkRootID   pathSnapshot
	linkStageID  pathSnapshot
	stageRootID  pathSnapshot
	preserve     bool
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
	home, err := accountpath.Home()
	if err != nil {
		return macOSInstallResult{}, fmt.Errorf("resolve canonical account home: %w", err)
	}
	sourceApp, err = validateMacOSInstallSource(sourceApp)
	if err != nil {
		return macOSInstallResult{}, err
	}
	expectedAppID, err := sourceMacOSBundleIdentity(sourceApp)
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

	destinationApp := filepath.Join(appDir, macOSAppName)
	cliLink := filepath.Join(linkDir, macOSCLIName)
	if err := validateExistingManagedMacOSApp(destinationApp, expectedAppID); err != nil {
		return macOSInstallResult{}, err
	}
	prepared, err := prepareMacOSInstall(sourceApp, destinationApp, cliLink)
	if err != nil {
		return macOSInstallResult{}, err
	}
	defer prepared.cleanup()

	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return macOSInstallResult{}, err
	}
	guard, err := mountlifecycle.AcquireExclusive(stateDir)
	if err != nil {
		return macOSInstallResult{}, fmt.Errorf(
			"acquire exclusive mount lifecycle guard: %w; quit PortableFS and cleanly unmount every volume before installing",
			err,
		)
	}
	defer guard.Close()

	if err := rejectLiveMacOSRuntime(e, stateDir); err != nil {
		return macOSInstallResult{}, err
	}
	if err := rejectOrphanedMacOSInstallTransactions(appDir, prepared.stageRoot); err != nil {
		return macOSInstallResult{}, err
	}
	if err := rejectOrphanedMacOSLinkTransactions(linkDir, prepared.linkRoot); err != nil {
		return macOSInstallResult{}, err
	}
	if err := rejectConflictingPFSProviders(home, destinationApp); err != nil {
		return macOSInstallResult{}, err
	}
	if err := validateExistingManagedMacOSApp(destinationApp, expectedAppID); err != nil {
		return macOSInstallResult{}, err
	}
	if err := validateStagedBundleForPublication(prepared.stageApp, e.version, expectedAppID); err != nil {
		return macOSInstallResult{}, err
	}
	if err := rejectLegacyPortablefsdState(home); err != nil {
		return macOSInstallResult{}, err
	}
	if err := makeStagedMacOSAppDurable(prepared.stageApp); err != nil {
		return macOSInstallResult{}, err
	}
	if err := commitMacOSInstall(prepared, destinationApp); err != nil {
		return macOSInstallResult{}, err
	}

	return macOSInstallResult{
		SchemaVersion: 1,
		AppPath:       destinationApp,
		CLILink:       cliLink,
		Version:       e.version,
	}, nil
}

func validateMacOSInstallSource(sourceApp string) (string, error) {
	if !filepath.IsAbs(sourceApp) || filepath.Clean(sourceApp) != sourceApp {
		return "", fmt.Errorf("--source-app must be an absolute clean path: %q", sourceApp)
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
	appInfo := filepath.Join(sourceApp, "Contents", "Info.plist")
	extensionInfo := filepath.Join(
		sourceApp,
		"Contents",
		"Extensions",
		macOSExtensionExecutable+".appex",
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
	expectedExtensionID := appID + "." + macOSExtensionExecutable
	if appExecutable != macOSAppExecutable ||
		extensionID != expectedExtensionID ||
		extensionExecutable != macOSExtensionExecutable {
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
	prepared.stageApp = filepath.Join(stageRoot, macOSStagedAppName)
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
	if err := validateStagedBundleForPublication(path, version, expectedAppID); err != nil {
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
	if err := removePublishedMacOSStaging(prepared, parent, linkParent); err != nil {
		prepared.preserve = true
		return err
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

func rejectLiveMacOSRuntime(e *cmdEnv, stateDir string) error {
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
	cfg, err := fskitConfigFromEnv(func(string) string { return "" })
	if err != nil {
		return err
	}
	for _, socket := range []string{cfg.controlSock, cfg.frontendSock} {
		if _, err := os.Lstat(socket); err == nil {
			return fmt.Errorf(
				"portablefsd socket %s still exists; run `portablefs daemon stop` after unmounting, or remove only a proven-stale socket before installing",
				socket,
			)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect portablefsd socket %s: %w", socket, err)
		}
	}
	return nil
}

func isPortableFSMacOSProcessName(name string) bool {
	switch name {
	case macOSAppExecutable,
		"PortableFSApp",
		macOSExtensionExecutable,
		"PortableFSKitDev",
		"PortableFSKitDe",
		"PortableFSDev",
		macOSCLIName,
		"portablefsd":
		return true
	default:
		return false
	}
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

	appExecutable := filepath.Join(app, "Contents", "MacOS", macOSAppExecutable)
	cli := filepath.Join(app, "Contents", "Helpers", macOSCLIName)
	daemon := filepath.Join(app, "Contents", "Helpers", "portablefsd")
	extension := filepath.Join(app, "Contents", "Extensions", macOSExtensionExecutable+".appex")
	extensionExecutable := filepath.Join(
		extension,
		"Contents",
		"MacOS",
		macOSExtensionExecutable,
	)
	for _, executable := range []string{appExecutable, cli, daemon, extensionExecutable} {
		info, err := os.Lstat(executable)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("staged app has no real executable at %s", executable)
		}
	}
	extensions, err := filepath.Glob(filepath.Join(app, "Contents", "Extensions", "*.appex"))
	if err != nil || len(extensions) != 1 || extensions[0] != extension {
		return fmt.Errorf("staged app must contain exactly PortableFSExt.appex")
	}

	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app).CombinedOutput(); err != nil {
		return fmt.Errorf("verify staged app code hierarchy: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=2", app).CombinedOutput(); err != nil {
		return fmt.Errorf("Gatekeeper rejected staged app: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("/usr/bin/xcrun", "stapler", "validate", app).CombinedOutput(); err != nil {
		return fmt.Errorf("staged app has no valid notarization ticket: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	appVersion, err := plistValue(filepath.Join(app, "Contents", "Info.plist"), "CFBundleShortVersionString")
	if err != nil {
		return err
	}
	extensionVersion, err := plistValue(filepath.Join(extension, "Contents", "Info.plist"), "CFBundleShortVersionString")
	if err != nil {
		return err
	}
	if appVersion != version || extensionVersion != version {
		return fmt.Errorf(
			"staged app versions do not match installer CLI %q (app %q, extension %q)",
			version,
			appVersion,
			extensionVersion,
		)
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
			executable: macOSAppExecutable,
		},
		{
			name:       "extension",
			plist:      filepath.Join(extension, "Contents", "Info.plist"),
			bundleID:   expectedAppID + "." + macOSExtensionExecutable,
			executable: macOSExtensionExecutable,
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
	if extensionPoint != fskitExtensionType || extensionFSName != defaultFskitType {
		return fmt.Errorf(
			"staged extension registration mismatch: point %q fs type %q",
			extensionPoint,
			extensionFSName,
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
		var identity struct {
			SchemaVersion int    `json:"schemaVersion"`
			AppGroup      string `json:"appGroup"`
		}
		if err := json.Unmarshal(out, &identity); err != nil ||
			identity.SchemaVersion != 1 ||
			identity.AppGroup != fskitidentity.AppGroup {
			return fmt.Errorf(
				"staged %s identity does not match app group %q",
				name,
				fskitidentity.AppGroup,
			)
		}
	}

	teamID, _, ok := strings.Cut(fskitidentity.AppGroup, ".")
	if !ok || teamID == "" {
		return fmt.Errorf("invalid linker-stamped app group %q", fskitidentity.AppGroup)
	}
	for _, code := range []string{app, extension, cli, daemon} {
		out, err := exec.Command("/usr/bin/codesign", "-dv", "--verbose=4", code).CombinedOutput()
		if err != nil {
			return fmt.Errorf("inspect staged code identity %s: %w", code, err)
		}
		identity := string(out)
		for _, required := range []string{
			"TeamIdentifier=" + teamID,
			"Authority=Developer ID Application: ",
			"flags=0x10000(runtime)",
		} {
			if !strings.Contains(identity, required) {
				return fmt.Errorf("staged code %s is missing required identity marker %q", code, required)
			}
		}
	}
	for code, expectedIdentifier := range map[string]string{
		app:       expectedAppID,
		extension: expectedAppID + "." + macOSExtensionExecutable,
	} {
		out, err := exec.Command("/usr/bin/codesign", "-dv", "--verbose=4", code).CombinedOutput()
		if err != nil {
			return fmt.Errorf("inspect staged code identifier %s: %w", code, err)
		}
		if !strings.Contains(string(out), "\nIdentifier="+expectedIdentifier+"\n") &&
			!strings.HasPrefix(string(out), "Identifier="+expectedIdentifier+"\n") {
			return fmt.Errorf(
				"staged code %s signature identifier does not match plist identifier %q",
				code,
				expectedIdentifier,
			)
		}
	}

	entitlements, err := exec.Command(
		"/usr/bin/codesign", "-d", "--entitlements", ":-", extension,
	).Output()
	if err != nil {
		return fmt.Errorf("read staged extension entitlements: %w", err)
	}
	entitlementFile, err := os.CreateTemp(filepath.Dir(app), ".portablefs-entitlements-*.plist")
	if err != nil {
		return fmt.Errorf("create entitlement validation file: %w", err)
	}
	entitlementPath := entitlementFile.Name()
	defer os.Remove(entitlementPath)
	if err := entitlementFile.Chmod(0o600); err != nil {
		entitlementFile.Close()
		return err
	}
	if _, err := entitlementFile.Write(entitlements); err != nil {
		entitlementFile.Close()
		return err
	}
	if err := entitlementFile.Close(); err != nil {
		return err
	}
	entitlementGroup, err := plistValue(entitlementPath, "com.apple.security.application-groups:0")
	if err != nil {
		return err
	}
	if entitlementGroup != fskitidentity.AppGroup {
		return fmt.Errorf(
			"signed extension app group %q does not match CLI app group %q",
			entitlementGroup,
			fskitidentity.AppGroup,
		)
	}
	return nil
}

func plistValue(path, key string) (string, error) {
	out, err := exec.Command("/usr/libexec/PlistBuddy", "-c", "Print :"+key, path).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read %s from %s: %w (output: %s)", key, path, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func runExactOutput(path string, args ...string) (string, error) {
	out, err := exec.Command(path, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func rejectLegacyPortablefsdState(home string) error {
	legacy := filepath.Join(home, "Library", "Application Support", "PortableFS", "portablefsd")
	legacyNonempty, err := inspectedStateDirectory(legacy)
	if err != nil {
		return fmt.Errorf("inspect legacy portablefsd state: %w", err)
	}
	if !legacyNonempty {
		return nil
	}
	return fmt.Errorf(
		"legacy portablefsd runtime state remains at %s; nothing was changed. After every old PortableFS mount is cleanly unmounted and the old daemon is stopped, archive that directory for inspection and remove it explicitly, then retry",
		legacy,
	)
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

func inspectedStateDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("%s is not a real directory", path)
	}
	if err := requireOwnedByEUID(path, info); err != nil {
		return false, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
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
	out, err := exec.Command(
		"/usr/libexec/PlistBuddy",
		"-c", "Print :EXAppExtensionAttributes:FSShortName",
		infoPath,
	).CombinedOutput()
	if err != nil {
		// An ExtensionKit provider without FSShortName does not claim the pfs
		// type. Other metadata/read failures remain visible.
		if strings.Contains(string(out), "Does Not Exist") {
			return false, nil
		}
		return false, fmt.Errorf("read FSShortName from %s: %w (output: %s)", infoPath, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)) == defaultFskitType, nil
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
		"another registered or installed provider claims the pfs FSKit type at %s; %s, then retry so macOS has exactly one deterministic provider",
		target,
		cleanup,
	)
}
