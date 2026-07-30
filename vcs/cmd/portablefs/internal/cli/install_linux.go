//go:build linux

package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"golang.org/x/sys/unix"
)

const (
	linuxInstallerSchemaVersion = 1
	linuxReleasePrefix          = "sha256-"
)

type linuxInstallResult struct {
	SchemaVersion int    `json:"schemaVersion"`
	Version       string `json:"version"`
	ReleaseDir    string `json:"releaseDir"`
	CLILink       string `json:"cliLink"`
}

func cmdInstallLinuxRelease(e *cmdEnv, args []string) int {
	fs := newFlagSet("install-linux-release")
	var sourceDir, linkDir string
	var jsonOut bool
	fs.StringVar(&sourceDir, "source-dir", "", "directory containing the verified release binaries")
	fs.StringVar(&linkDir, "link-dir", "", "directory for the portablefs activation link")
	fs.BoolVar(&jsonOut, "json", false, "print machine-readable JSON")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("install-linux-release", err)
	}
	if len(positionals) != 0 {
		return e.usageError("install-linux-release", fmt.Errorf("expected no positional arguments"))
	}
	if sourceDir == "" {
		return e.usageError("install-linux-release", fmt.Errorf("--source-dir is required"))
	}

	home, err := accountpath.Home()
	if err != nil {
		return e.fail("install-linux-release", fmt.Errorf("resolve canonical account home: %w", err))
	}
	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return e.fail("install-linux-release", err)
	}
	installer := newLinuxReleaseInstaller(home, stateDir, sourceDir, linkDir, e.version)
	result, err := installer.install()
	if err != nil {
		return e.fail("install-linux-release", err)
	}
	if jsonOut {
		return e.printJSON(result)
	}
	fmt.Fprintf(e.stdout, "portablefs %s installed at %s\n", result.Version, result.CLILink)
	fmt.Fprintf(e.stdout, "immutable CLI/daemon release: %s\n", result.ReleaseDir)
	linkDir = filepath.Dir(result.CLILink)
	pathValue := os.Getenv("PATH")
	if e.getenv != nil {
		pathValue = e.getenv("PATH")
	}
	if !pathListContains(pathValue, linkDir) {
		fmt.Fprintf(e.stdout, "\nnote: %s is not in PATH. Add this to your shell profile:\n", linkDir)
		fmt.Fprintf(e.stdout, "  export PATH=%s:\"$PATH\"\n", shellSingleQuote(linkDir))
	}
	return 0
}

type linuxReleaseInstaller struct {
	home                     string
	stateDir                 string
	sourceDir                string
	linkDir                  string
	version                  string
	procRoot                 string
	mountInfoPath            string
	currentPID               int
	selfExecutable           string
	runBinary                func(string, ...string) ([]byte, error)
	renameat2                func(int, string, int, string, uint) error
	randomSuffix             func() (string, error)
	afterStage               func()
	beforeActivationExchange func()
	afterActivationExchange  func() error
}

func newLinuxReleaseInstaller(home, stateDir, sourceDir, linkDir, version string) *linuxReleaseInstaller {
	selfExecutable, _ := os.Executable()
	return &linuxReleaseInstaller{
		home:           home,
		stateDir:       stateDir,
		sourceDir:      sourceDir,
		linkDir:        linkDir,
		version:        version,
		procRoot:       "/proc",
		mountInfoPath:  "/proc/self/mountinfo",
		currentPID:     os.Getpid(),
		selfExecutable: selfExecutable,
		runBinary:      runInstallerBinary,
		renameat2: func(oldDirFD int, oldName string, newDirFD int, newName string, flags uint) error {
			return unix.Renameat2(oldDirFD, oldName, newDirFD, newName, flags)
		},
		randomSuffix: secureInstallerSuffix,
	}
}

type installerBinary struct {
	name string
	path string
	hash [sha256.Size]byte
}

type installerSourcePair struct {
	cli       installerBinary
	daemon    installerBinary
	releaseID string
}

type activationKind uint8

const (
	activationAbsent activationKind = iota
	activationManaged
)

type activationState struct {
	kind     activationKind
	snapshot installerNamedSnapshot
}

func (i *linuxReleaseInstaller) install() (result linuxInstallResult, resultErr error) {
	if err := validateInstallerRoot(i.home, "account home"); err != nil {
		return linuxInstallResult{}, err
	}
	if !filepath.IsAbs(i.sourceDir) || filepath.Clean(i.sourceDir) != i.sourceDir {
		return linuxInstallResult{}, fmt.Errorf("source directory must be an absolute clean path: %q", i.sourceDir)
	}
	if !validStableReleaseVersion(i.version) {
		return linuxInstallResult{}, fmt.Errorf(
			"release version must be stable SemVer MAJOR.MINOR.PATCH without leading zeroes: %q",
			i.version,
		)
	}
	if i.linkDir == "" {
		i.linkDir = filepath.Join(i.home, ".local", "bin")
	}
	if err := validatePathWithinHome(i.home, i.linkDir, "link directory"); err != nil {
		return linuxInstallResult{}, err
	}

	productRoot := filepath.Join(i.home, ".local", "lib", "portablefs")
	if pathWithin(productRoot, i.linkDir) || pathWithin(i.linkDir, productRoot) {
		return linuxInstallResult{}, fmt.Errorf("link directory %s must not overlap the immutable release root %s", i.linkDir, productRoot)
	}
	releasesRoot := filepath.Join(productRoot, "releases")
	releasesDir, err := openPinnedInstallerDir(i.home, releasesRoot, true)
	if err != nil {
		return linuxInstallResult{}, fmt.Errorf("prepare immutable release root: %w", err)
	}
	defer releasesDir.Close()
	linkDir, err := openPinnedInstallerDir(i.home, i.linkDir, true)
	if err != nil {
		return linuxInstallResult{}, fmt.Errorf("prepare CLI link directory: %w", err)
	}
	defer linkDir.Close()
	if err := rejectLinuxInstallerOrphans(releasesDir, ".install-stage-", "", "release"); err != nil {
		return linuxInstallResult{}, err
	}
	if err := rejectLinuxInstallerOrphans(linkDir, ".portablefs.activate-", "", "activation"); err != nil {
		return linuxInstallResult{}, err
	}

	source, err := i.validateSourcePair()
	if err != nil {
		return linuxInstallResult{}, err
	}
	releaseDir := filepath.Join(releasesRoot, source.releaseID)
	stageName, err := i.stageRelease(releasesDir, source)
	if err != nil {
		return linuxInstallResult{}, err
	}
	stageOwned := true
	defer func() {
		if stageOwned {
			if cleanupErr := removeInstallerStage(releasesDir.final(), stageName); cleanupErr != nil {
				cleanupErr = fmt.Errorf("remove current release transaction %s: %w", filepath.Join(releasesRoot, stageName), cleanupErr)
				if resultErr == nil {
					resultErr = cleanupErr
				} else {
					resultErr = errors.Join(resultErr, cleanupErr)
				}
			}
		}
	}()
	if i.afterStage != nil {
		i.afterStage()
	}

	guard, err := mountlifecycle.AcquireExclusive(i.stateDir)
	if err != nil {
		return linuxInstallResult{}, fmt.Errorf("acquire exclusive mount/update lifecycle guard: %w", err)
	}
	defer guard.Close()

	if err := releasesDir.validate(); err != nil {
		return linuxInstallResult{}, err
	}
	if err := linkDir.validate(); err != nil {
		return linuxInstallResult{}, err
	}
	if err := rejectLinuxInstallerOrphans(releasesDir, ".install-stage-", stageName, "release"); err != nil {
		return linuxInstallResult{}, err
	}
	if err := rejectLinuxInstallerOrphans(linkDir, ".portablefs.activate-", "", "activation"); err != nil {
		return linuxInstallResult{}, err
	}
	revalidatedSource, err := i.validateSourcePair()
	if err != nil {
		return linuxInstallResult{}, fmt.Errorf("revalidate source pair under the exclusive lifecycle guard: %w", err)
	}
	if revalidatedSource.releaseID != source.releaseID ||
		!equalHash(revalidatedSource.cli.hash[:], source.cli.hash[:]) ||
		!equalHash(revalidatedSource.daemon.hash[:], source.daemon.hash[:]) {
		return linuxInstallResult{}, fmt.Errorf("source CLI/daemon pair changed after staging; refusing replacement")
	}
	if err := validatePublishedReleaseAt(releasesDir.final(), stageName, filepath.Join(releasesRoot, stageName), source); err != nil {
		return linuxInstallResult{}, fmt.Errorf("revalidate staged release under the exclusive lifecycle guard: %w", err)
	}

	activationPath := filepath.Join(i.linkDir, "portablefs")
	activation, err := i.inspectActivation(activationPath, releasesRoot)
	if err != nil {
		return linuxInstallResult{}, err
	}
	if err := i.assertReplacementIdle(); err != nil {
		return linuxInstallResult{}, err
	}

	if err := releasesDir.validate(); err != nil {
		return linuxInstallResult{}, err
	}
	if err := i.publishRelease(releasesDir.final(), stageName, source.releaseID, releaseDir, source); err != nil {
		return linuxInstallResult{}, err
	}
	stageOwned = false
	// Compliant mount starts cannot cross the exclusive guard. Rechecking at
	// the activation edge additionally narrows the legacy-client race for
	// installs that predate lifecycle locking.
	if err := i.assertReplacementIdle(); err != nil {
		return linuxInstallResult{}, err
	}
	if err := linkDir.validate(); err != nil {
		return linuxInstallResult{}, err
	}
	if err := i.activate(linkDir.final(), activationPath, releaseDir, activation); err != nil {
		return linuxInstallResult{}, err
	}
	if err := releasesDir.validate(); err != nil {
		return linuxInstallResult{}, err
	}
	if err := linkDir.validate(); err != nil {
		return linuxInstallResult{}, err
	}

	return linuxInstallResult{
		SchemaVersion: linuxInstallerSchemaVersion,
		Version:       i.version,
		ReleaseDir:    releaseDir,
		CLILink:       activationPath,
	}, nil
}

func validStableReleaseVersion(version string) bool {
	components := strings.Split(version, ".")
	if len(components) != 3 {
		return false
	}
	for _, component := range components {
		if component == "" || (len(component) > 1 && component[0] == '0') {
			return false
		}
		for _, char := range component {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func (i *linuxReleaseInstaller) validateSourcePair() (installerSourcePair, error) {
	info, err := os.Lstat(i.sourceDir)
	if err != nil {
		return installerSourcePair{}, fmt.Errorf("inspect source directory %s: %w", i.sourceDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return installerSourcePair{}, fmt.Errorf("source path %s is not a real directory", i.sourceDir)
	}
	if err := requireOwnedByEUID(i.sourceDir, info); err != nil {
		return installerSourcePair{}, err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return installerSourcePair{}, fmt.Errorf("source directory %s is writable by another account (mode %04o)", i.sourceDir, info.Mode().Perm())
	}

	cliBinary, err := inspectInstallerBinary(filepath.Join(i.sourceDir, "portablefs"), "portablefs")
	if err != nil {
		return installerSourcePair{}, err
	}
	if i.selfExecutable == "" {
		return installerSourcePair{}, fmt.Errorf("cannot resolve the staged installer executable")
	}
	selfInfo, err := os.Stat(i.selfExecutable)
	if err != nil {
		return installerSourcePair{}, fmt.Errorf("inspect staged installer executable %s: %w", i.selfExecutable, err)
	}
	sourceCLIInfo, err := os.Lstat(cliBinary.path)
	if err != nil {
		return installerSourcePair{}, fmt.Errorf("recheck source CLI %s: %w", cliBinary.path, err)
	}
	if !os.SameFile(selfInfo, sourceCLIInfo) {
		return installerSourcePair{}, fmt.Errorf("source CLI %s is not the staged installer executable %s", cliBinary.path, i.selfExecutable)
	}
	daemonBinary, err := inspectInstallerBinary(filepath.Join(i.sourceDir, "portablefsd"), "portablefsd")
	if err != nil {
		return installerSourcePair{}, err
	}
	cliOutput, err := i.runBinary(cliBinary.path, "version")
	if err != nil {
		return installerSourcePair{}, fmt.Errorf("run source portablefs version check: %w", err)
	}
	wantCLI := "portablefs " + i.version
	if strings.TrimSpace(string(cliOutput)) != wantCLI {
		return installerSourcePair{}, fmt.Errorf("source CLI identifies as %q, want %q", strings.TrimSpace(string(cliOutput)), wantCLI)
	}
	daemonOutput, err := i.runBinary(daemonBinary.path, "-version")
	if err != nil {
		return installerSourcePair{}, fmt.Errorf("run source portablefsd version check: %w", err)
	}
	if strings.TrimSpace(string(daemonOutput)) != i.version {
		return installerSourcePair{}, fmt.Errorf("source daemon identifies as %q, want %q", strings.TrimSpace(string(daemonOutput)), i.version)
	}

	pairHash := sha256.New()
	_, _ = io.WriteString(pairHash, "portablefs\x00")
	_, _ = pairHash.Write(cliBinary.hash[:])
	_, _ = io.WriteString(pairHash, "\x00portablefsd\x00")
	_, _ = pairHash.Write(daemonBinary.hash[:])
	return installerSourcePair{
		cli:       cliBinary,
		daemon:    daemonBinary,
		releaseID: linuxReleasePrefix + hex.EncodeToString(pairHash.Sum(nil)),
	}, nil
}

func inspectInstallerBinary(path, name string) (installerBinary, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return installerBinary{}, fmt.Errorf("inspect source %s: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return installerBinary{}, fmt.Errorf("source %s is not a regular non-symlink file", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return installerBinary{}, fmt.Errorf("source %s is not executable", path)
	}
	if err := requireOwnedByEUID(path, info); err != nil {
		return installerBinary{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return installerBinary{}, fmt.Errorf("source %s must have exactly one filesystem link", path)
	}

	file, err := openRegularNoFollow(path)
	if err != nil {
		return installerBinary{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return installerBinary{}, fmt.Errorf("inspect opened source %s: %w", path, err)
	}
	if !os.SameFile(info, openedInfo) {
		return installerBinary{}, fmt.Errorf("source %s changed while it was opened", path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return installerBinary{}, fmt.Errorf("hash source %s: %w", path, err)
	}
	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))
	return installerBinary{name: name, path: path, hash: sum}, nil
}

func (i *linuxReleaseInstaller) stageRelease(releasesRoot *pinnedInstallerDir, source installerSourcePair) (stageName string, resultErr error) {
	if err := releasesRoot.validate(); err != nil {
		return "", err
	}
	suffix, err := i.randomSuffix()
	if err != nil {
		return "", fmt.Errorf("create release transaction nonce: %w", err)
	}
	stageName = ".install-stage-" + suffix
	parent := releasesRoot.final()
	if err := unix.Mkdirat(int(parent.Fd()), stageName, 0o700); err != nil {
		return "", fmt.Errorf("create release staging directory %s: %w", filepath.Join(releasesRoot.path, stageName), err)
	}
	if err := parent.Sync(); err != nil {
		return "", fmt.Errorf("sync release transaction creation: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			if cleanupErr := removeInstallerStage(parent, stageName); cleanupErr != nil {
				cleanupErr = fmt.Errorf("remove failed release transaction: %w", cleanupErr)
				if resultErr == nil {
					resultErr = cleanupErr
				} else {
					resultErr = errors.Join(resultErr, cleanupErr)
				}
			}
		}
	}()
	stageFD, err := unix.Openat(
		int(parent.Fd()),
		stageName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("pin release staging directory: %w", err)
	}
	stage := os.NewFile(uintptr(stageFD), filepath.Join(releasesRoot.path, stageName))
	defer stage.Close()
	for _, binary := range []installerBinary{source.cli, source.daemon} {
		if err := copyInstallerBinaryAt(stage, binary); err != nil {
			return "", err
		}
	}
	if err := stage.Sync(); err != nil {
		return "", fmt.Errorf("sync staged release: %w", err)
	}
	if err := stage.Chmod(0o555); err != nil {
		return "", fmt.Errorf("make staged release immutable: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return "", fmt.Errorf("sync immutable staged release metadata: %w", err)
	}
	cleanup = false
	return stageName, nil
}

func copyInstallerBinaryAt(parent *os.File, source installerBinary) error {
	input, err := openRegularNoFollow(source.path)
	if err != nil {
		return err
	}
	defer input.Close()
	outputFD, err := unix.Openat(
		int(parent.Fd()),
		source.name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o500,
	)
	if err != nil {
		return fmt.Errorf("create staged binary %s: %w", filepath.Join(parent.Name(), source.name), err)
	}
	output := os.NewFile(uintptr(outputFD), filepath.Join(parent.Name(), source.name))
	if output == nil {
		_ = unix.Close(outputFD)
		return fmt.Errorf("create staged binary %s: invalid file descriptor", source.name)
	}
	copiedHash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, copiedHash), input)
	if copyErr == nil && !equalHash(copiedHash.Sum(nil), source.hash[:]) {
		copyErr = fmt.Errorf("source %s changed while it was copied", source.path)
	}
	if copyErr == nil {
		copyErr = output.Chmod(0o555)
	}
	if copyErr == nil {
		copyErr = output.Sync()
	}
	closeErr := output.Close()
	if copyErr != nil {
		return fmt.Errorf("stage %s: %w", source.name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close staged %s: %w", source.name, closeErr)
	}
	return nil
}

func (i *linuxReleaseInstaller) publishRelease(
	parent *os.File,
	stageName string,
	releaseName string,
	releaseDir string,
	source installerSourcePair,
) error {
	err := i.renameat2(int(parent.Fd()), stageName, int(parent.Fd()), releaseName, unix.RENAME_NOREPLACE)
	if err == nil {
		if err := parent.Sync(); err != nil {
			return fmt.Errorf("sync immutable release publication: %w", err)
		}
		return nil
	}
	if !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("atomically publish immutable release: %w", err)
	}
	if err := validatePublishedReleaseAt(parent, releaseName, releaseDir, source); err != nil {
		return fmt.Errorf("content-addressed release path already exists but is not the verified release: %w", err)
	}
	if err := removeInstallerStage(parent, stageName); err != nil {
		return fmt.Errorf("reuse verified immutable release but remove current transaction: %w", err)
	}
	return nil
}

func validatePublishedReleaseAt(parent *os.File, name, releaseDir string, source installerSourcePair) error {
	fd, err := unix.Openat(
		int(parent.Fd()),
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("open release directory %s without following symlinks: %w", releaseDir, err)
	}
	release := os.NewFile(uintptr(fd), releaseDir)
	defer release.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect release directory %s: %w", releaseDir, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o555 {
		return fmt.Errorf("%s must be a real 0555 directory", releaseDir)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("path %s is owned by uid %d, want %d", releaseDir, stat.Uid, os.Geteuid())
	}
	names, err := readInstallerDirNames(release)
	if err != nil {
		return fmt.Errorf("read release directory %s: %w", releaseDir, err)
	}
	if len(names) != 2 {
		return fmt.Errorf("%s contains %d entries, want exactly portablefs and portablefsd", releaseDir, len(names))
	}
	for _, binary := range []installerBinary{source.cli, source.daemon} {
		got, err := inspectImmutableBinaryAt(release, binary.name)
		if err != nil {
			return err
		}
		if !equalHash(got[:], binary.hash[:]) {
			return fmt.Errorf("immutable binary %s has an unexpected digest", binary.name)
		}
	}
	var current, named unix.Stat_t
	if err := unix.Fstat(fd, &current); err != nil {
		return fmt.Errorf("recheck opened release directory %s: %w", releaseDir, err)
	}
	if err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck named release directory %s: %w", releaseDir, err)
	}
	if !sameInstallerFileStat(stat, current) ||
		current.Dev != named.Dev || current.Ino != named.Ino || current.Mode != named.Mode {
		return fmt.Errorf("release directory %s changed while it was validated", releaseDir)
	}
	return nil
}

func inspectImmutableBinaryAt(parent *os.File, name string) ([sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, fmt.Errorf("open immutable binary %s: %w", filepath.Join(parent.Name(), name), err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return empty, fmt.Errorf("inspect immutable binary %s: %w", file.Name(), err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o555 {
		return empty, fmt.Errorf("immutable binary %s must be a regular 0555 file", file.Name())
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return empty, fmt.Errorf("path %s is owned by uid %d, want %d", file.Name(), stat.Uid, os.Geteuid())
	}
	if stat.Nlink != 1 {
		return empty, fmt.Errorf("immutable binary %s must have exactly one filesystem link", file.Name())
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return empty, fmt.Errorf("hash immutable binary %s: %w", file.Name(), err)
	}
	var current, named unix.Stat_t
	if err := unix.Fstat(fd, &current); err != nil {
		return empty, fmt.Errorf("recheck immutable binary %s: %w", file.Name(), err)
	}
	if err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return empty, fmt.Errorf("recheck named immutable binary %s: %w", file.Name(), err)
	}
	if !sameInstallerFileStat(stat, current) || !sameInstallerFileStat(current, named) {
		return empty, fmt.Errorf("immutable binary %s changed while it was validated", file.Name())
	}
	copy(empty[:], hash.Sum(nil))
	return empty, nil
}

func inspectImmutableBinary(path string) ([sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	info, err := os.Lstat(path)
	if err != nil {
		return empty, fmt.Errorf("inspect immutable binary %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 {
		return empty, fmt.Errorf("immutable binary %s must be a regular 0555 file", path)
	}
	if err := requireOwnedByEUID(path, info); err != nil {
		return empty, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return empty, fmt.Errorf("immutable binary %s must have exactly one filesystem link", path)
	}
	file, err := openRegularNoFollow(path)
	if err != nil {
		return empty, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return empty, fmt.Errorf("hash immutable binary %s: %w", path, err)
	}
	copy(empty[:], hash.Sum(nil))
	return empty, nil
}

func (i *linuxReleaseInstaller) inspectActivation(activationPath, releasesRoot string) (activationState, error) {
	info, err := os.Lstat(activationPath)
	if os.IsNotExist(err) {
		legacyDaemon := filepath.Join(i.linkDir, "portablefsd")
		if _, daemonErr := os.Lstat(legacyDaemon); daemonErr == nil {
			return activationState{}, fmt.Errorf("legacy daemon exists at %s without its matching CLI; refusing to guess ownership or remove it", legacyDaemon)
		} else if !os.IsNotExist(daemonErr) {
			return activationState{}, fmt.Errorf("inspect possible legacy daemon %s: %w", legacyDaemon, daemonErr)
		}
		return activationState{kind: activationAbsent}, nil
	}
	if err != nil {
		return activationState{}, fmt.Errorf("inspect activation path %s: %w", activationPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(activationPath)
		if err != nil {
			return activationState{}, fmt.Errorf("read activation link %s: %w", activationPath, err)
		}
		resolved := target
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(filepath.Dir(activationPath), resolved)
		}
		resolved = filepath.Clean(resolved)
		if _, err := validateManagedActivationTarget(resolved, releasesRoot, i.runBinary); err != nil {
			return activationState{}, fmt.Errorf("existing activation link %s is not managed by the PortableFS release layout: %w", activationPath, err)
		}
		snapshot, err := snapshotInstallerFileInfo(info, target)
		if err != nil {
			return activationState{}, fmt.Errorf("snapshot activation link %s: %w", activationPath, err)
		}
		state := activationState{
			kind:     activationManaged,
			snapshot: snapshot,
		}
		legacyDaemon := filepath.Join(i.linkDir, "portablefsd")
		daemonInfo, daemonErr := os.Lstat(legacyDaemon)
		if daemonErr == nil {
			if err := validateLegacyDaemon(legacyDaemon, daemonInfo, i.runBinary); err != nil {
				return activationState{}, fmt.Errorf("managed activation has an unrecognized sibling at %s: %w", legacyDaemon, err)
			}
			return activationState{}, fmt.Errorf(
				"legacy daemon remains at %s beside the managed activation; stop PortableFS, archive or remove that exact file explicitly, and retry",
				legacyDaemon,
			)
		} else if !os.IsNotExist(daemonErr) {
			return activationState{}, fmt.Errorf("inspect possible legacy daemon %s: %w", legacyDaemon, daemonErr)
		}
		return state, nil
	}
	if !info.Mode().IsRegular() {
		return activationState{}, fmt.Errorf("activation path %s is neither a managed symlink nor a legacy PortableFS binary", activationPath)
	}
	if err := requireOwnedByEUID(activationPath, info); err != nil {
		return activationState{}, err
	}
	daemonPath := filepath.Join(i.linkDir, "portablefsd")
	daemonInfo, err := os.Lstat(daemonPath)
	if err != nil {
		return activationState{}, fmt.Errorf("legacy CLI exists at %s but its matching daemon cannot be inspected: %w", activationPath, err)
	}
	if err := validateLegacyDaemon(daemonPath, daemonInfo, i.runBinary); err != nil {
		return activationState{}, err
	}
	for path, candidate := range map[string]os.FileInfo{activationPath: info} {
		stat, ok := candidate.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			return activationState{}, fmt.Errorf("legacy binary %s must have exactly one filesystem link", path)
		}
	}
	cliOutput, err := i.runBinary(activationPath, "version")
	if err != nil {
		return activationState{}, fmt.Errorf("validate legacy CLI %s: %w", activationPath, err)
	}
	legacyVersion, ok := strings.CutPrefix(strings.TrimSpace(string(cliOutput)), "portablefs ")
	if !ok || legacyVersion == "" || strings.ContainsAny(legacyVersion, "\r\n") {
		return activationState{}, fmt.Errorf("legacy CLI %s returned an invalid product identity", activationPath)
	}
	daemonOutput, err := i.runBinary(daemonPath, "-version")
	if err != nil {
		return activationState{}, fmt.Errorf("validate legacy daemon %s: %w", daemonPath, err)
	}
	if strings.TrimSpace(string(daemonOutput)) != legacyVersion {
		return activationState{}, fmt.Errorf("legacy CLI and daemon are a mixed-version pair (%q and %q); refusing replacement", legacyVersion, strings.TrimSpace(string(daemonOutput)))
	}
	return activationState{}, fmt.Errorf(
		"legacy PortableFS CLI/daemon pair remains at %s and %s; stop PortableFS, archive or remove those exact files explicitly, and retry",
		activationPath,
		daemonPath,
	)
}

func validateManagedActivationTarget(target, releasesRoot string, runBinary func(string, ...string) ([]byte, error)) (string, error) {
	if filepath.Base(target) != "portablefs" {
		return "", fmt.Errorf("target basename is %q, want portablefs", filepath.Base(target))
	}
	releaseDir := filepath.Dir(target)
	if filepath.Dir(releaseDir) != releasesRoot {
		return "", fmt.Errorf("target %s is outside %s", target, releasesRoot)
	}
	releaseID := filepath.Base(releaseDir)
	if !strings.HasPrefix(releaseID, linuxReleasePrefix) || len(strings.TrimPrefix(releaseID, linuxReleasePrefix)) != sha256.Size*2 {
		return "", fmt.Errorf("release directory %q is not content-addressed", releaseID)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(releaseID, linuxReleasePrefix)); err != nil {
		return "", fmt.Errorf("release directory %q has an invalid digest", releaseID)
	}
	info, err := os.Lstat(releaseDir)
	if err != nil {
		return "", fmt.Errorf("inspect release directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o555 {
		return "", fmt.Errorf("release directory is not a real 0555 directory")
	}
	if err := requireOwnedByEUID(releaseDir, info); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(releaseDir)
	if err != nil {
		return "", fmt.Errorf("read managed release directory: %w", err)
	}
	if len(entries) != 2 {
		return "", fmt.Errorf("managed release contains %d entries, want exactly portablefs and portablefsd", len(entries))
	}
	cliHash, err := inspectImmutableBinary(filepath.Join(releaseDir, "portablefs"))
	if err != nil {
		return "", err
	}
	daemonHash, err := inspectImmutableBinary(filepath.Join(releaseDir, "portablefsd"))
	if err != nil {
		return "", err
	}
	pairHash := sha256.New()
	_, _ = io.WriteString(pairHash, "portablefs\x00")
	_, _ = pairHash.Write(cliHash[:])
	_, _ = io.WriteString(pairHash, "\x00portablefsd\x00")
	_, _ = pairHash.Write(daemonHash[:])
	if linuxReleasePrefix+hex.EncodeToString(pairHash.Sum(nil)) != releaseID {
		return "", fmt.Errorf("managed release directory digest does not match its CLI/daemon content")
	}
	cliOutput, err := runBinary(target, "version")
	if err != nil {
		return "", fmt.Errorf("run managed CLI identity check: %w", err)
	}
	version, ok := strings.CutPrefix(strings.TrimSpace(string(cliOutput)), "portablefs ")
	if !ok || version == "" {
		return "", fmt.Errorf("managed CLI returned an invalid product identity")
	}
	daemonOutput, err := runBinary(filepath.Join(releaseDir, "portablefsd"), "-version")
	if err != nil {
		return "", fmt.Errorf("run managed daemon identity check: %w", err)
	}
	if strings.TrimSpace(string(daemonOutput)) != version {
		return "", fmt.Errorf("managed CLI and daemon are a mixed-version pair")
	}
	return version, nil
}

func (i *linuxReleaseInstaller) activate(
	parent *os.File,
	activationPath string,
	releaseDir string,
	previous activationState,
) error {
	activationName := filepath.Base(activationPath)
	target, err := filepath.Rel(filepath.Dir(activationPath), filepath.Join(releaseDir, "portablefs"))
	if err != nil {
		return fmt.Errorf("construct activation target: %w", err)
	}
	suffix, err := i.randomSuffix()
	if err != nil {
		return fmt.Errorf("create activation nonce: %w", err)
	}
	tempName := ".portablefs.activate-" + suffix
	tempPath := filepath.Join(filepath.Dir(activationPath), tempName)
	if err := unix.Symlinkat(target, int(parent.Fd()), tempName); err != nil {
		return fmt.Errorf("create activation symlink: %w", err)
	}
	cleanupOwnTemp := func(cause error) error {
		if cleanupErr := unlinkInstallerNameDurable(parent, tempName, 0); cleanupErr != nil {
			return errors.Join(cause, fmt.Errorf("remove current activation transaction %s: %w", tempPath, cleanupErr))
		}
		return cause
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync activation link directory before replacement: %w", err)
	}
	staged, err := snapshotInstallerNameAt(parent, tempName)
	if err != nil {
		return cleanupOwnTemp(fmt.Errorf("snapshot staged activation symlink: %w", err))
	}
	if !staged.exists || staged.mode&unix.S_IFMT != unix.S_IFLNK || staged.target != target ||
		staged.uid != uint32(os.Geteuid()) {
		return cleanupOwnTemp(fmt.Errorf("staged activation symlink has unexpected identity"))
	}

	current, err := snapshotInstallerNameAt(parent, activationName)
	if err != nil {
		return cleanupOwnTemp(fmt.Errorf("recheck activation path %s: %w", activationPath, err))
	}
	if previous.kind == activationAbsent {
		if current.exists {
			return cleanupOwnTemp(fmt.Errorf("activation path %s appeared during installation; refusing to replace it", activationPath))
		}
		if err := i.renameat2(
			int(parent.Fd()),
			tempName,
			int(parent.Fd()),
			activationName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return cleanupOwnTemp(fmt.Errorf(
				"atomically activate release (Linux renameat2 is required; no non-atomic replacement is attempted): %w",
				err,
			))
		}
		if err := parent.Sync(); err != nil {
			return fmt.Errorf("release is active at %s, but syncing the activation rename failed: %w", activationPath, err)
		}
		return nil
	}
	if !sameInstallerSnapshot(current, previous.snapshot) {
		return cleanupOwnTemp(fmt.Errorf("activation path %s changed during installation; refusing replacement", activationPath))
	}
	if i.beforeActivationExchange != nil {
		i.beforeActivationExchange()
	}
	if err := i.renameat2(
		int(parent.Fd()),
		tempName,
		int(parent.Fd()),
		activationName,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return cleanupOwnTemp(fmt.Errorf("atomically exchange activation link: %w", err))
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf(
			"activation exchange at %s could not be made durable: %w; preserved transaction at %s",
			activationPath,
			err,
			tempPath,
		)
	}
	if i.afterActivationExchange != nil {
		if err := i.afterActivationExchange(); err != nil {
			return fmt.Errorf(
				"activation exchange stopped before checked completion: %w; preserved transaction at %s",
				err,
				tempPath,
			)
		}
	}

	displaced, err := snapshotInstallerNameAt(parent, tempName)
	if err != nil {
		return fmt.Errorf(
			"inspect displaced activation after exchange: %w; preserved transaction at %s",
			err,
			tempPath,
		)
	}
	if sameInstallerSnapshot(displaced, previous.snapshot) {
		if err := unlinkInstallerNameDurable(parent, tempName, 0); err != nil {
			return fmt.Errorf(
				"new release is active, but remove displaced activation transaction %s: %w",
				tempPath,
				err,
			)
		}
		return nil
	}

	if err := i.renameat2(
		int(parent.Fd()),
		tempName,
		int(parent.Fd()),
		activationName,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return fmt.Errorf(
			"activation compare-and-swap detected a race, and rollback failed: %w; preserved transaction at %s",
			err,
			tempPath,
		)
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf(
			"activation compare-and-swap rollback could not be made durable: %w; preserved transaction at %s",
			err,
			tempPath,
		)
	}
	restored, restoredErr := snapshotInstallerNameAt(parent, activationName)
	returnedStage, stageErr := snapshotInstallerNameAt(parent, tempName)
	if restoredErr != nil || stageErr != nil ||
		!sameInstallerSnapshot(restored, displaced) ||
		!sameInstallerSnapshot(returnedStage, staged) {
		return fmt.Errorf(
			"activation compare-and-swap rollback could not prove restoration (activation: %v, transaction: %v); preserved transaction at %s",
			restoredErr,
			stageErr,
			tempPath,
		)
	}
	if err := unlinkInstallerNameDurable(parent, tempName, 0); err != nil {
		return fmt.Errorf(
			"activation race was rolled back, but remove current transaction %s: %w",
			tempPath,
			err,
		)
	}
	return fmt.Errorf("activation path %s changed at the atomic exchange edge; concurrent state was restored exactly", activationPath)
}

func validateLegacyDaemon(path string, info os.FileInfo, runBinary func(string, ...string) ([]byte, error)) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("legacy daemon %s is not a regular non-symlink file", path)
	}
	if err := requireOwnedByEUID(path, info); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("legacy daemon %s must have exactly one filesystem link", path)
	}
	output, err := runBinary(path, "-version")
	if err != nil {
		return fmt.Errorf("validate legacy daemon %s: %w", path, err)
	}
	version := strings.TrimSpace(string(output))
	if version == "" || strings.ContainsAny(version, "\r\n") {
		return fmt.Errorf("legacy daemon %s returned an invalid product identity", path)
	}
	return nil
}

func (i *linuxReleaseInstaller) assertReplacementIdle() error {
	if err := rejectDurableMountAnchors(i.stateDir); err != nil {
		return err
	}
	if mounts, err := portableFSMountsFrom(i.mountInfoPath); err != nil {
		return err
	} else if len(mounts) != 0 {
		return fmt.Errorf("refusing replacement while PortableFS FUSE mounts are live: %s; cleanly unmount them and retry", strings.Join(mounts, ", "))
	}
	if processes, err := portableFSProcessesFrom(i.procRoot, i.currentPID); err != nil {
		return err
	} else if len(processes) != 0 {
		return fmt.Errorf("refusing replacement while PortableFS processes are live: %s; cleanly unmount every volume, stop the idle daemon, and retry", strings.Join(processes, ", "))
	}
	return nil
}

func portableFSMountsFrom(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read Linux kernel mount table %s: %w", path, err)
	}
	defer file.Close()
	var mounts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mountPath, fsType, source, ok := parseInstallerMountInfoLine(scanner.Text())
		instance, unique := strings.CutPrefix(source, "portablefs:")
		if ok && fsType == "fuse.portablefs" {
			if source != "portablefs" && !(unique && mountid.ValidMountInstance(instance)) {
				return nil, fmt.Errorf("PortableFS kernel mount at %s has malformed source identity %q; refusing replacement", mountPath, source)
			}
			mounts = append(mounts, mountPath)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan Linux kernel mount table %s: %w", path, err)
	}
	return mounts, nil
}

func parseInstallerMountInfoLine(line string) (mountPath, fsType, source string, ok bool) {
	before, after, found := strings.Cut(line, " - ")
	if !found {
		return "", "", "", false
	}
	left, right := strings.Fields(before), strings.Fields(after)
	if len(left) < 5 || len(right) < 2 {
		return "", "", "", false
	}
	return unescapeInstallerMountField(left[4]), right[0], unescapeInstallerMountField(right[1]), true
}

func unescapeInstallerMountField(value string) string {
	var out strings.Builder
	for index := 0; index < len(value); {
		if value[index] == '\\' && index+3 < len(value) {
			if decoded, err := strconv.ParseUint(value[index+1:index+4], 8, 8); err == nil {
				out.WriteByte(byte(decoded))
				index += 4
				continue
			}
		}
		out.WriteByte(value[index])
		index++
	}
	return out.String()
}

func portableFSProcessesFrom(procRoot string, currentPID int) ([]string, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("read Linux process table %s: %w", procRoot, err)
	}
	var found []string
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == currentPID {
			continue
		}
		processDir := filepath.Join(procRoot, entry.Name())
		info, err := os.Stat(processDir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect process %d: %w", pid, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) {
			continue
		}
		commBytes, err := os.ReadFile(filepath.Join(processDir, "comm"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read process %d identity: %w", pid, err)
		}
		comm := strings.TrimSpace(string(commBytes))
		if comm != "portablefs" && comm != "portablefsd" {
			continue
		}
		executable, err := os.Readlink(filepath.Join(processDir, "exe"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read executable identity for PortableFS process %d: %w", pid, err)
		}
		executable = strings.TrimSuffix(executable, " (deleted)")
		if filepath.Base(executable) != comm {
			continue
		}
		found = append(found, fmt.Sprintf("%s(pid=%d)", comm, pid))
	}
	return found, nil
}

func validateInstallerRoot(path, label string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be an absolute clean path: %q", label, path)
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("%s contains an invalid control character", label)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s %s: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s %s is not a real directory", label, path)
	}
	if err := requireOwnedByEUID(path, info); err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s %s is writable by another account (mode %04o)", label, path, info.Mode().Perm())
	}
	return nil
}

func validatePathWithinHome(home, path, label string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be an absolute clean path: %q", label, path)
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("%s contains an invalid control character", label)
	}
	if path == home || !pathWithin(home, path) {
		return fmt.Errorf("%s %s must be strictly inside the canonical account home %s", label, path, home)
	}
	return nil
}

func pathWithin(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func requireOwnedByEUID(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("path %s has unavailable owner metadata", path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("path %s is owned by uid %d, want %d", path, stat.Uid, os.Geteuid())
	}
	return nil
}

func openRegularNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open regular file %s without following symlinks: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open regular file %s: invalid file descriptor", path)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect open file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("path %s is not a regular file", path)
	}
	return file, nil
}

func removeInstallerStage(parent *os.File, name string) error {
	if filepath.Base(name) != name || !strings.HasPrefix(name, ".install-stage-") {
		return fmt.Errorf("refuse invalid release transaction name %q", name)
	}
	fd, err := unix.Openat(
		int(parent.Fd()),
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open release transaction %s: %w", filepath.Join(parent.Name(), name), err)
	}
	stage := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	defer stage.Close()
	var stageStat unix.Stat_t
	if err := unix.Fstat(fd, &stageStat); err != nil {
		return fmt.Errorf("inspect release transaction %s: %w", stage.Name(), err)
	}
	if stageStat.Mode&unix.S_IFMT != unix.S_IFDIR || stageStat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("release transaction %s is not an owned real directory", stage.Name())
	}
	names, err := readInstallerDirNames(stage)
	if err != nil {
		return fmt.Errorf("inspect release transaction %s: %w", stage.Name(), err)
	}
	for _, entry := range names {
		if entry != "portablefs" && entry != "portablefsd" {
			return fmt.Errorf("release transaction %s contains unexpected entry %s; it was preserved", stage.Name(), entry)
		}
		snapshot, err := snapshotInstallerNameAt(stage, entry)
		if err != nil {
			return fmt.Errorf("inspect release transaction entry %s: %w", filepath.Join(stage.Name(), entry), err)
		}
		if snapshot.mode&unix.S_IFMT != unix.S_IFREG ||
			snapshot.uid != uint32(os.Geteuid()) ||
			snapshot.nlink != 1 {
			return fmt.Errorf("release transaction entry %s has unexpected identity; it was preserved", filepath.Join(stage.Name(), entry))
		}
	}
	if err := stage.Chmod(0o700); err != nil {
		return fmt.Errorf("make release transaction removable: %w", err)
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("sync release transaction permissions: %w", err)
	}
	for _, entry := range names {
		if err := unix.Unlinkat(fd, entry, 0); err != nil {
			return fmt.Errorf("remove release transaction entry %s: %w", filepath.Join(stage.Name(), entry), err)
		}
	}
	if err := stage.Sync(); err != nil {
		return fmt.Errorf("sync emptied release transaction: %w", err)
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove release transaction directory %s: %w", stage.Name(), err)
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync release transaction removal: %w", err)
	}
	return nil
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for index := range a {
		difference |= a[index] ^ b[index]
	}
	return difference == 0
}

func runInstallerBinary(path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, args...)
	command.Stdin = nil
	output, err := command.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out", path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", path, strings.Join(args, " "), err)
	}
	return output, nil
}

func secureInstallerSuffix() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func pathListContains(list, directory string) bool {
	for _, candidate := range filepath.SplitList(list) {
		if candidate == directory {
			return true
		}
	}
	return false
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
