//go:build darwin

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func makeFakeMacOSApp(t *testing.T, root, marker string) string {
	t.Helper()
	app := filepath.Join(root, macOSAppName)
	helperDir := filepath.Join(app, "Contents", "Helpers")
	if err := os.MkdirAll(helperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helperDir, macOSCLIName), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "marker"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	return app
}

func writeTestBundleInfo(t *testing.T, path, bundleID, executable string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>` + bundleID + `</string>
<key>CFBundleExecutable</key><string>` + executable + `</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
</dict></plist>
`
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
}

func addTestBundleIdentity(t *testing.T, app, appID string) {
	t.Helper()
	writeTestBundleInfo(
		t,
		filepath.Join(app, "Contents", "Info.plist"),
		appID,
		macOSAppExecutable,
	)
	writeTestBundleInfo(
		t,
		filepath.Join(
			app,
			"Contents",
			"Extensions",
			macOSExtensionExecutable+".appex",
			"Contents",
			"Info.plist",
		),
		appID+"."+macOSExtensionExecutable,
		macOSExtensionExecutable,
	)
}

func TestCommitMacOSInstallPublishesAndUpdatesWholeBundle(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(appDir, macOSAppName)
	link := filepath.Join(linkDir, macOSCLIName)
	var stableLink pathSnapshot

	for index, marker := range []string{"one", "two"} {
		sourceRoot := t.TempDir()
		source := makeFakeMacOSApp(t, sourceRoot, marker)
		prepared, err := prepareMacOSInstall(source, destination, link)
		if err != nil {
			t.Fatalf("prepare update %d: %v", index, err)
		}
		if err := commitMacOSInstall(prepared, destination); err != nil {
			prepared.cleanup()
			t.Fatalf("commit update %d: %v", index, err)
		}
		if prepared.stageRoot != "" {
			t.Fatalf("successful commit retained app transaction %s", prepared.stageRoot)
		}
		prepared.cleanup()
		got, err := os.ReadFile(filepath.Join(destination, "marker"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != marker {
			t.Fatalf("marker after update %d = %q, want %q", index, got, marker)
		}
		target, err := os.Readlink(link)
		if err != nil {
			t.Fatal(err)
		}
		wantTarget := filepath.Join(destination, "Contents", "Helpers", macOSCLIName)
		if target != wantTarget {
			t.Fatalf("CLI link = %q, want %q", target, wantTarget)
		}
		if index == 0 {
			stableLink, err = snapshotPath(link)
			if err != nil {
				t.Fatal(err)
			}
		} else if err := requireUnchangedPath(link, stableLink); err != nil {
			t.Fatalf("canonical CLI link was needlessly replaced: %v", err)
		}
	}
}

func TestPreparedMacOSBundleNeverUsesAppSuffix(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareMacOSInstall(
		makeFakeMacOSApp(t, t.TempDir(), "source"),
		filepath.Join(appDir, macOSAppName),
		filepath.Join(linkDir, macOSCLIName),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if filepath.Ext(prepared.stageApp) == ".app" {
		t.Fatalf("staged provider is discoverable as an app bundle: %s", prepared.stageApp)
	}
}

func TestRejectOrphanedMacOSInstallTransactions(t *testing.T) {
	appDir := t.TempDir()
	orphan := filepath.Join(appDir, ".portablefs-install-orphan")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	err := rejectOrphanedMacOSInstallTransactions(appDir, "")
	if err == nil || !strings.Contains(err.Error(), orphan) {
		t.Fatalf("orphaned install was not refused precisely: %v", err)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Fatalf("orphan was mutated: %v", statErr)
	}
	if err := rejectOrphanedMacOSInstallTransactions(appDir, orphan); err != nil {
		t.Fatalf("current transaction was refused: %v", err)
	}
}

func TestRejectOrphanedMacOSLinkTransactions(t *testing.T) {
	linkDir := t.TempDir()
	orphan := filepath.Join(linkDir, ".portablefs-link-orphan")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	err := rejectOrphanedMacOSLinkTransactions(linkDir, "")
	if err == nil || !strings.Contains(err.Error(), orphan) {
		t.Fatalf("orphaned CLI-link transaction was not refused: %v", err)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Fatalf("orphan was mutated: %v", statErr)
	}
}

func TestPrepareMacOSInstallRefusesUnrelatedCLIFile(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	link := filepath.Join(linkDir, macOSCLIName)
	if err := os.WriteFile(link, []byte("user file"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := prepareMacOSInstall(source, filepath.Join(appDir, macOSAppName), link)
	if err == nil || !strings.Contains(err.Error(), "is not a symlink") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCommitMacOSInstallRefusesLinkThatAppearedAfterPreparation(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	destination := filepath.Join(appDir, macOSAppName)
	link := filepath.Join(linkDir, macOSCLIName)
	prepared, err := prepareMacOSInstall(source, destination, link)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := os.WriteFile(link, []byte("appeared"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = commitMacOSInstall(prepared, destination)
	if err == nil || !strings.Contains(err.Error(), "CLI link changed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination app was published despite link race: %v", err)
	}
}

func TestCommitMacOSInstallRefusesChangedStagedLink(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	destination := filepath.Join(appDir, macOSAppName)
	link := filepath.Join(linkDir, macOSCLIName)
	prepared, err := prepareMacOSInstall(source, destination, link)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := os.Remove(prepared.linkTemp); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/not-portablefs", prepared.linkTemp); err != nil {
		t.Fatal(err)
	}
	err = commitMacOSInstall(prepared, destination)
	if err == nil || !strings.Contains(err.Error(), "staged CLI link changed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination app was published despite staged-link race: %v", err)
	}
}

func TestPublishPreparedCLILinkDoesNotOverwriteAppearedDestination(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	prepared, err := prepareMacOSInstall(
		source,
		filepath.Join(appDir, macOSAppName),
		filepath.Join(linkDir, macOSCLIName),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := os.WriteFile(prepared.linkPath, []byte("appeared"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceParent, err := openSnapshottedDirectory(prepared.linkRoot, prepared.linkRootID)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sourceParent)
	destinationParent, err := openSnapshottedDirectory(filepath.Dir(prepared.linkPath), prepared.linkParentID)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(destinationParent)

	if err := publishPreparedCLILink(prepared, sourceParent, destinationParent); err == nil {
		t.Fatal("appeared destination was overwritten")
	}
	got, err := os.ReadFile(prepared.linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "appeared" {
		t.Fatalf("appeared destination changed to %q", got)
	}
	if err := requireUnchangedPath(prepared.linkTemp, prepared.linkStageID); err != nil {
		t.Fatalf("staged link changed after refused publication: %v", err)
	}
}

func TestPublishPreparedAppRollsBackDisplacedAppRace(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications")
	linkDir := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(appDir, macOSAppName)
	link := filepath.Join(linkDir, macOSCLIName)
	makeFakeMacOSApp(t, appDir, "old")
	source := makeFakeMacOSApp(t, t.TempDir(), "source")
	prepared, err := prepareMacOSInstall(source, destination, link)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.cleanup()
	if err := os.RemoveAll(destination); err != nil {
		t.Fatal(err)
	}
	makeFakeMacOSApp(t, appDir, "raced")
	parent, err := openSnapshottedDirectory(appDir, prepared.appParentID)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parent)

	err = publishPreparedApp(
		prepared,
		parent,
		filepath.Join(filepath.Base(prepared.stageRoot), macOSStagedAppName),
		macOSAppName,
	)
	if err == nil || !strings.Contains(err.Error(), "exchange rolled back") {
		t.Fatalf("unexpected result: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "marker"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "raced" {
		t.Fatalf("destination marker = %q, want raced", got)
	}
	got, err = os.ReadFile(filepath.Join(prepared.stageApp, "marker"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "source" {
		t.Fatalf("staged marker = %q, want source", got)
	}
}

func TestOpenSnapshottedDirectoryRefusesReplacement(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "Applications")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotPath(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(directory, directory+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if fd, err := openSnapshottedDirectory(directory, snapshot); err == nil {
		_ = os.NewFile(uintptr(fd), directory).Close()
		t.Fatal("replaced directory was accepted")
	}
}

func TestOpenSnapshottedDirectoryRefusesSymlinkedAncestor(t *testing.T) {
	root := t.TempDir()
	realRoot := filepath.Join(root, "real")
	directory := filepath.Join(realRoot, "Applications")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realRoot, alias); err != nil {
		t.Fatal(err)
	}
	throughAlias := filepath.Join(alias, "Applications")
	snapshot, err := snapshotPath(throughAlias)
	if err != nil {
		t.Fatal(err)
	}
	if fd, err := openSnapshottedDirectory(throughAlias, snapshot); err == nil {
		_ = unix.Close(fd)
		t.Fatal("symlinked ancestor was accepted")
	}
}

func TestRemoveSnapshottedTreePreservesReplacementAfterPin(t *testing.T) {
	parentPath := t.TempDir()
	transaction := filepath.Join(parentPath, ".portablefs-install-transaction")
	if err := os.Mkdir(transaction, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transaction, "owned"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := snapshotPath(transaction)
	if err != nil {
		t.Fatal(err)
	}
	parentSnapshot, err := snapshotPath(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openSnapshottedDirectory(parentPath, parentSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parent)
	moved := transaction + ".moved"
	err = removeSnapshottedTreeAt(parent, filepath.Base(transaction), expected, func() {
		if renameErr := os.Rename(transaction, moved); renameErr != nil {
			t.Fatal(renameErr)
		}
		if mkdirErr := os.Mkdir(transaction, 0o700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		if writeErr := os.WriteFile(filepath.Join(transaction, "preserve"), []byte("replacement"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "replacement was preserved") {
		t.Fatalf("replacement race error = %v", err)
	}
	data, readErr := os.ReadFile(filepath.Join(transaction, "preserve"))
	if readErr != nil || string(data) != "replacement" {
		t.Fatalf("replacement tree was changed: %q, %v", data, readErr)
	}
	entries, readErr := os.ReadDir(moved)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("pinned original transaction was not the cleaned inode: %v", entries)
	}
}

func TestSourceMacOSBundleIdentitySupportsExactCustomForkIdentity(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	const appID = "org.example.portablefs"
	addTestBundleIdentity(t, app, appID)
	got, err := sourceMacOSBundleIdentity(app)
	if err != nil {
		t.Fatal(err)
	}
	if got != appID {
		t.Fatalf("app id = %q, want %q", got, appID)
	}
}

func TestValidateStagedBundleRequiresRealExtensionExecutable(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	for _, executable := range []string{
		filepath.Join(app, "Contents", "MacOS", macOSAppExecutable),
		filepath.Join(app, "Contents", "Helpers", "portablefsd"),
	} {
		if err := os.MkdirAll(filepath.Dir(executable), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	missing := filepath.Join(
		app,
		"Contents",
		"Extensions",
		macOSExtensionExecutable+".appex",
		"Contents",
		"MacOS",
		macOSExtensionExecutable,
	)
	if err := os.MkdirAll(filepath.Dir(missing), 0o755); err != nil {
		t.Fatal(err)
	}
	err := validateStagedBundleForPublication(app, "1.2.3", "dev.portablefs.test")
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing extension executable error = %v", err)
	}
}

func TestSourceMacOSBundleIdentityRejectsMismatchedExtension(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	addTestBundleIdentity(t, app, "org.example.portablefs")
	writeTestBundleInfo(
		t,
		filepath.Join(
			app,
			"Contents",
			"Extensions",
			macOSExtensionExecutable+".appex",
			"Contents",
			"Info.plist",
		),
		"org.example.counterfeit",
		macOSExtensionExecutable,
	)
	if _, err := sourceMacOSBundleIdentity(app); err == nil {
		t.Fatal("mismatched extension identity was accepted")
	}
}

func TestValidateExistingManagedMacOSAppRejectsCounterfeitDirectory(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "counterfeit")
	const appID = "org.example.portablefs"
	addTestBundleIdentity(t, app, appID)
	err := validateExistingManagedMacOSApp(app, appID)
	if err == nil || !strings.Contains(err.Error(), "remove it explicitly") {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestPortableFSMacOSProcessNamesCoverReleaseAndDevRuntime(t *testing.T) {
	for _, name := range []string{
		"PortableFS",
		"PortableFSApp",
		"PortableFSExt",
		"PortableFSKitDev",
		"PortableFSKitDe",
		"PortableFSDev",
		"portablefs",
		"portablefsd",
	} {
		if !isPortableFSMacOSProcessName(name) {
			t.Fatalf("PortableFS process name %q was not recognized", name)
		}
	}
	if isPortableFSMacOSProcessName("unrelated") {
		t.Fatal("unrelated process was classified as PortableFS")
	}
}

func TestRejectLegacyPortablefsdStateLeavesNonemptyStateUntouched(t *testing.T) {
	home := t.TempDir()
	legacy := filepath.Join(home, "Library", "Application Support", "PortableFS", "portablefsd")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "attaches.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := rejectLegacyPortablefsdState(home)
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(legacy, "attaches.json")); err != nil {
		t.Fatalf("legacy state was mutated: %v", err)
	}
}

func TestRejectLegacyPortablefsdStateLeavesEmptyDirectoryUntouched(t *testing.T) {
	home := t.TempDir()
	legacy := filepath.Join(home, "Library", "Application Support", "PortableFS", "portablefsd")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rejectLegacyPortablefsdState(home); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(legacy); err != nil || !info.IsDir() {
		t.Fatalf("empty legacy directory was mutated: %v", err)
	}
}

func TestMakeStagedMacOSAppDurableRejectsSymlink(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	if err := os.Symlink("/tmp", filepath.Join(app, "unexpected")); err != nil {
		t.Fatal(err)
	}
	err := makeStagedMacOSAppDurable(app)
	if err == nil || !strings.Contains(err.Error(), "unexpected symlink") {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestMakeStagedMacOSAppDurableSyncsRegularTree(t *testing.T) {
	app := makeFakeMacOSApp(t, t.TempDir(), "source")
	if err := makeStagedMacOSAppDurable(app); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureOwnedDirectoryTreeRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".local")); err != nil {
		t.Fatal(err)
	}
	err := ensureOwnedDirectoryTree(home, filepath.Join(home, ".local", "bin"))
	if err == nil ||
		(!strings.Contains(err.Error(), "not a real directory") &&
			!strings.Contains(err.Error(), "not a directory")) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstallPathsMustBeStrictlyContainedAndNonOverlapping(t *testing.T) {
	home := t.TempDir()
	if err := validateContainedPath(home, home); err == nil {
		t.Fatal("account home itself was accepted as an install directory")
	}
	appDir := filepath.Join(home, "Applications")
	if !pathsOverlap(appDir, filepath.Join(appDir, "bin")) {
		t.Fatal("nested app/link roots were not detected")
	}
	if pathsOverlap(appDir, filepath.Join(home, ".local", "bin")) {
		t.Fatal("independent app/link roots were reported as overlapping")
	}
}

func TestContainingAppPath(t *testing.T) {
	path := "/Applications/PortableFS.app/Contents/Extensions/PortableFSExt.appex"
	if got := containingAppPath(path); got != "/Applications/PortableFS.app" {
		t.Fatalf("containing app = %q", got)
	}
}
