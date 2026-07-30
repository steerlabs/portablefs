//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
)

func TestLinuxReleaseInstallerActivatesImmutablePair(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	result, err := installer.install()
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != linuxInstallerSchemaVersion || result.Version != "1.2.3" {
		t.Fatalf("result = %#v", result)
	}
	assertLinuxInstallLayout(t, result)

	// Reinstalling the exact content reuses the verified content-addressed
	// directory and atomically refreshes only the activation link.
	second := testLinuxInstallerAt(t, installer.home, installer.stateDir, installer.sourceDir, "source-v1")
	second.procRoot = installer.procRoot
	second.mountInfoPath = installer.mountInfoPath
	second.runBinary = fakeInstallerBinary
	result2, err := second.install()
	if err != nil {
		t.Fatal(err)
	}
	if result2.ReleaseDir != result.ReleaseDir {
		t.Fatalf("idempotent release = %s, want %s", result2.ReleaseDir, result.ReleaseDir)
	}
	assertLinuxInstallLayout(t, result2)
}

func TestLinuxReleaseInstallerRefusesValidatedLegacyPairWithoutMutation(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	linkDir := filepath.Join(installer.home, ".local", "bin")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestInstallerBinary(t, filepath.Join(linkDir, "portablefs"), "legacy-cli")
	writeTestInstallerBinary(t, filepath.Join(linkDir, "portablefsd"), "legacy-daemon")

	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), "archive or remove those exact files explicitly") {
		t.Fatalf("legacy pair refusal = %v", err)
	}
	for _, name := range []string{"portablefs", "portablefsd"} {
		data, readErr := os.ReadFile(filepath.Join(linkDir, name))
		if readErr != nil || !strings.Contains(string(data), "legacy") {
			t.Fatalf("legacy %s was changed: %q, %v", name, data, readErr)
		}
	}
}

func TestLinuxReleaseInstallerRefusesLegacyDaemonBesideManagedActivation(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	result, err := installer.install()
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(filepath.Dir(result.CLILink), "portablefsd")
	writeTestInstallerBinary(t, orphan, "legacy-daemon")

	second := testLinuxInstallerAt(t, installer.home, installer.stateDir, installer.sourceDir, "source-v1")
	second.procRoot = installer.procRoot
	second.mountInfoPath = installer.mountInfoPath
	second.runBinary = fakeInstallerBinary
	if _, err := second.install(); err == nil || !strings.Contains(err.Error(), "archive or remove that exact file explicitly") {
		t.Fatalf("legacy sibling refusal = %v", err)
	}
	data, readErr := os.ReadFile(orphan)
	if readErr != nil || string(data) != "legacy-daemon" {
		t.Fatalf("legacy sibling changed: %q, %v", data, readErr)
	}
	assertLinuxInstallLayout(t, result)
}

func TestLinuxReleaseInstallerRejectsUnknownActivation(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	linkDir := filepath.Join(installer.home, ".local", "bin")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	activation := filepath.Join(linkDir, "portablefs")
	if err := os.WriteFile(activation, []byte("unrelated user file"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), "matching daemon") {
		t.Fatalf("unknown activation error = %v", err)
	}
	data, readErr := os.ReadFile(activation)
	if readErr != nil || string(data) != "unrelated user file" {
		t.Fatalf("unknown activation was changed: %q, %v", data, readErr)
	}
}

func TestLinuxReleaseInstallerRejectsLiveKernelMount(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	if err := os.WriteFile(installer.mountInfoPath,
		[]byte("36 29 0:32 / /work/portable\\040fs rw - fuse.portablefs portablefs rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), "/work/portable fs") {
		t.Fatalf("live mount error = %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(installer.home, ".local", "bin", "portablefs")); !os.IsNotExist(statErr) {
		t.Fatalf("activation changed despite live mount: %v", statErr)
	}
}

func TestLinuxReleaseInstallerRejectsLiveExactProcess(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	processDir := filepath.Join(installer.procRoot, "4242")
	if err := os.Mkdir(processDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(processDir, "comm"), []byte("portablefsd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/old/portablefsd", filepath.Join(processDir, "exe")); err != nil {
		t.Fatal(err)
	}
	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), "portablefsd(pid=4242)") {
		t.Fatalf("live process error = %v", err)
	}
}

func TestLinuxReleaseInstallerHonorsSharedLifecycleGuard(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	guard, err := mountlifecycle.AcquireShared(installer.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	_, err = installer.install()
	if !errors.Is(err, mountlifecycle.ErrBusy) {
		t.Fatalf("lock contention error = %v", err)
	}
}

func TestLinuxReleaseInstallerRevalidatesSourceUnderExclusiveGuard(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	installer.afterStage = func() {
		writeTestInstallerBinary(t, filepath.Join(installer.sourceDir, "portablefsd"), "source-v2-daemon")
	}
	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), "changed after staging") {
		t.Fatalf("source substitution error = %v", err)
	}
}

func TestLinuxReleaseInstallerExchangeCASRestoresConcurrentActivation(t *testing.T) {
	first := testLinuxInstaller(t, "source-v1")
	firstResult, err := first.install()
	if err != nil {
		t.Fatal(err)
	}
	second := testLinuxInstallerWithNewSource(t, first, "source-v2")
	second.beforeActivationExchange = func() {
		if err := os.Remove(firstResult.CLILink); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("concurrent-activation", firstResult.CLILink); err != nil {
			t.Fatal(err)
		}
	}
	_, err = second.install()
	if err == nil || !strings.Contains(err.Error(), "concurrent state was restored exactly") {
		t.Fatalf("exchange race error = %v", err)
	}
	target, readErr := os.Readlink(firstResult.CLILink)
	if readErr != nil || target != "concurrent-activation" {
		t.Fatalf("concurrent activation was not restored: %q, %v", target, readErr)
	}
	entries, readErr := os.ReadDir(filepath.Dir(firstResult.CLILink))
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".portablefs.activate-") {
			t.Fatalf("rolled-back transaction remains at %s", entry.Name())
		}
	}
}

func TestLinuxReleaseInstallerPreservesAndRefusesInterruptedExchange(t *testing.T) {
	first := testLinuxInstaller(t, "source-v1")
	if _, err := first.install(); err != nil {
		t.Fatal(err)
	}
	second := testLinuxInstallerWithNewSource(t, first, "source-v2")
	second.afterActivationExchange = func() error {
		return errors.New("injected process interruption")
	}
	_, err := second.install()
	if err == nil || !strings.Contains(err.Error(), "preserved transaction") {
		t.Fatalf("interrupted exchange error = %v", err)
	}
	activationDir := filepath.Join(first.home, ".local", "bin")
	transaction := filepath.Join(activationDir, ".portablefs.activate-0123456789abcdef")
	if _, statErr := os.Lstat(transaction); statErr != nil {
		t.Fatalf("interrupted exchange transaction was not preserved: %v", statErr)
	}

	third := testLinuxInstallerWithNewSource(t, first, "source-v3")
	_, err = third.install()
	if err == nil || !strings.Contains(err.Error(), transaction) {
		t.Fatalf("orphan transaction refusal = %v", err)
	}
	if _, statErr := os.Lstat(transaction); statErr != nil {
		t.Fatalf("orphan transaction was mutated: %v", statErr)
	}
}

func TestLinuxReleaseInstallerRefusesOrphanReleaseTransaction(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	orphan := filepath.Join(
		installer.home,
		".local",
		"lib",
		"portablefs",
		"releases",
		".install-stage-interrupted",
	)
	if err := os.MkdirAll(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), orphan) {
		t.Fatalf("release orphan refusal = %v", err)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Fatalf("release orphan was mutated: %v", statErr)
	}
}

func TestLinuxReleaseInstallerDetectsPinnedAncestorReplacement(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	local := filepath.Join(installer.home, ".local")
	moved := filepath.Join(installer.home, ".local-moved")
	installer.afterStage = func() {
		if err := os.Rename(local, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(local, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), "directory chain") {
		t.Fatalf("ancestor replacement error = %v", err)
	}
	for _, activation := range []string{
		filepath.Join(local, "bin", "portablefs"),
		filepath.Join(moved, "bin", "portablefs"),
	} {
		if _, statErr := os.Lstat(activation); !os.IsNotExist(statErr) {
			t.Fatalf("activation published through replaced ancestor at %s: %v", activation, statErr)
		}
	}
}

func TestLinuxReleaseInstallerRequiresAtomicRenameat2(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	installer.renameat2 = func(_ int, _ string, _ int, _ string, _ uint) error {
		return syscall.ENOSYS
	}
	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), "atomically publish") {
		t.Fatalf("renameat2 error = %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(installer.home, ".local", "bin", "portablefs")); !os.IsNotExist(statErr) {
		t.Fatalf("non-atomic activation was attempted: %v", statErr)
	}
}

func TestLinuxReleaseInstallerRequiresSourceCLIToBeRunningInstaller(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	other := filepath.Join(installer.sourceDir, "other-portablefs")
	writeTestInstallerBinary(t, other, "source-v1-cli")
	installer.selfExecutable = other
	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), "is not the staged installer executable") {
		t.Fatalf("source identity error = %v", err)
	}
}

func TestLinuxReleaseInstallerRejectsReleaseTampering(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	result, err := installer.install()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(result.ReleaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(result.ReleaseDir, "portablefsd"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestInstallerBinary(t, filepath.Join(result.ReleaseDir, "portablefsd"), "source-tampered-daemon")
	if err := os.Chmod(filepath.Join(result.ReleaseDir, "portablefsd"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(result.ReleaseDir, 0o555); err != nil {
		t.Fatal(err)
	}

	second := testLinuxInstallerAt(t, installer.home, installer.stateDir, installer.sourceDir, "source-v1")
	second.procRoot = installer.procRoot
	second.mountInfoPath = installer.mountInfoPath
	second.runBinary = fakeInstallerBinary
	_, err = second.install()
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered release error = %v", err)
	}
}

func TestLinuxReleaseInstallerRejectsLinkDirectoryOutsideHome(t *testing.T) {
	installer := testLinuxInstaller(t, "source-v1")
	installer.linkDir = filepath.Join(filepath.Dir(installer.home), "outside-home")
	_, err := installer.install()
	if err == nil || !strings.Contains(err.Error(), "must be strictly inside") {
		t.Fatalf("outside link directory error = %v", err)
	}
}

func TestLinuxReleaseInstallerRequiresExactStableVersion(t *testing.T) {
	for _, version := range []string{"", "1", "1.2", "01.2.3", "1.02.3", "1.2.03", "v1.2.3", "1.2.3-rc.1"} {
		t.Run(version, func(t *testing.T) {
			installer := testLinuxInstaller(t, "source-v1")
			installer.version = version
			_, err := installer.install()
			if err == nil || !strings.Contains(err.Error(), "stable SemVer") {
				t.Fatalf("version %q error = %v", version, err)
			}
			if _, statErr := os.Lstat(filepath.Join(installer.home, ".local")); !os.IsNotExist(statErr) {
				t.Fatalf("version %q mutated install roots: %v", version, statErr)
			}
		})
	}
	if !validStableReleaseVersion("0.0.0") || !validStableReleaseVersion("12.34.56") {
		t.Fatal("valid stable versions were rejected")
	}
}

func TestPortableFSMountsFromMatchesExactIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mountinfo")
	data := strings.Join([]string{
		"36 29 0:32 / /portable rw - fuse.portablefs portablefs rw",
		"39 29 0:35 / /portable-new rw - fuse.portablefs portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA rw",
		"37 29 0:33 / /other rw - fuse.sshfs portablefs rw",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	mounts, err := portableFSMountsFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(mounts) != "[/portable /portable-new]" {
		t.Fatalf("mounts = %v", mounts)
	}
}

func TestPortableFSMountsFromRejectsMalformedSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte("38 29 0:34 / /wrong-source rw - fuse.portablefs other rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := portableFSMountsFrom(path); err == nil {
		t.Fatal("malformed PortableFS source was ignored")
	}
}

func testLinuxInstaller(t *testing.T, payload string) *linuxReleaseInstaller {
	t.Helper()
	home := t.TempDir()
	stateDir := filepath.Join(home, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(home, "download")
	if err := os.Mkdir(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestInstallerBinary(t, filepath.Join(sourceDir, "portablefs"), payload+"-cli")
	writeTestInstallerBinary(t, filepath.Join(sourceDir, "portablefsd"), payload+"-daemon")
	return testLinuxInstallerAt(t, home, stateDir, sourceDir, payload)
}

func testLinuxInstallerAt(t *testing.T, home, stateDir, sourceDir, _ string) *linuxReleaseInstaller {
	t.Helper()
	// Successful installs deliberately leave the release pair and directory
	// read-only. Restore owner-write permission only during test cleanup so
	// testing.TempDir can remove its fixture without weakening the asserted
	// installed state.
	t.Cleanup(func() {
		root := filepath.Join(home, ".local", "lib", "portablefs", "releases")
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				if os.IsNotExist(walkErr) {
					return nil
				}
				return walkErr
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			switch {
			case info.IsDir():
				return os.Chmod(path, 0o700)
			case info.Mode().IsRegular():
				return os.Chmod(path, 0o600)
			default:
				return nil
			}
		})
		if err != nil && !os.IsNotExist(err) {
			t.Errorf("restore installer fixture permissions: %v", err)
		}
	})
	procRoot := filepath.Join(home, "proc")
	if err := os.MkdirAll(procRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	mountInfo := filepath.Join(home, "mountinfo")
	if err := os.WriteFile(mountInfo, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	installer := newLinuxReleaseInstaller(home, stateDir, sourceDir, "", "1.2.3")
	installer.procRoot = procRoot
	installer.mountInfoPath = mountInfo
	installer.currentPID = 9999
	installer.selfExecutable = filepath.Join(sourceDir, "portablefs")
	installer.runBinary = fakeInstallerBinary
	installer.randomSuffix = func() (string, error) { return "0123456789abcdef", nil }
	return installer
}

func testLinuxInstallerWithNewSource(
	t *testing.T,
	previous *linuxReleaseInstaller,
	payload string,
) *linuxReleaseInstaller {
	t.Helper()
	sourceDir := filepath.Join(previous.home, "download-"+payload)
	if err := os.Mkdir(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestInstallerBinary(t, filepath.Join(sourceDir, "portablefs"), payload+"-cli")
	writeTestInstallerBinary(t, filepath.Join(sourceDir, "portablefsd"), payload+"-daemon")
	installer := testLinuxInstallerAt(t, previous.home, previous.stateDir, sourceDir, payload)
	installer.procRoot = previous.procRoot
	installer.mountInfoPath = previous.mountInfoPath
	return installer
}

func writeTestInstallerBinary(t *testing.T, path, payload string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func fakeInstallerBinary(path string, args ...string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	payload := string(data)
	if len(args) != 1 {
		return nil, fmt.Errorf("unexpected arguments: %v", args)
	}
	switch filepath.Base(path) {
	case "portablefs":
		if args[0] != "version" {
			return nil, fmt.Errorf("unexpected CLI argument %q", args[0])
		}
		switch {
		case strings.Contains(payload, "legacy"):
			return []byte("portablefs 0.9.0\n"), nil
		case strings.Contains(payload, "source"):
			return []byte("portablefs 1.2.3\n"), nil
		}
	case "portablefsd":
		if args[0] != "-version" {
			return nil, fmt.Errorf("unexpected daemon argument %q", args[0])
		}
		switch {
		case strings.Contains(payload, "legacy"):
			return []byte("0.9.0\n"), nil
		case strings.Contains(payload, "source"):
			return []byte("1.2.3\n"), nil
		}
	}
	return nil, fmt.Errorf("unknown test binary payload %q at %s", payload, path)
}

func assertLinuxInstallLayout(t *testing.T, result linuxInstallResult) {
	t.Helper()
	linkInfo, err := os.Lstat(result.CLILink)
	if err != nil {
		t.Fatal(err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("activation mode = %v, want symlink", linkInfo.Mode())
	}
	target, err := filepath.EvalSymlinks(result.CLILink)
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Join(result.ReleaseDir, "portablefs") {
		t.Fatalf("activation target = %s", target)
	}
	releaseInfo, err := os.Lstat(result.ReleaseDir)
	if err != nil {
		t.Fatal(err)
	}
	if releaseInfo.Mode().Perm() != 0o555 {
		t.Fatalf("release mode = %04o, want 0555", releaseInfo.Mode().Perm())
	}
	for _, name := range []string{"portablefs", "portablefsd"} {
		info, err := os.Lstat(filepath.Join(result.ReleaseDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 {
			t.Fatalf("%s mode = %v, want regular 0555", name, info.Mode())
		}
	}
}
