//go:build linux

package cellhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scriptedRunner is the fake host command surface: it records every
// invocation, and it answers the two systemctl questions destroy asks - is a
// unit active, is a unit enabled - from explicit sets, so a test can put a
// live authority or a live archiver in front of destroy and see it refuse.
type scriptedRunner struct {
	calls        []recordedCommand
	activeUnits  map[string]bool
	enabledUnits map[string]bool
	failures     map[string]error
	quotaFailure error
}

func newScriptedRunner() *scriptedRunner {
	return &scriptedRunner{
		activeUnits:  map[string]bool{},
		enabledUnits: map[string]bool{},
		failures:     map[string]error{},
	}
}

func (runner *scriptedRunner) Run(_ context.Context, executable string, arguments ...string) ([]byte, error) {
	runner.calls = append(runner.calls, recordedCommand{executable: executable, arguments: append([]string(nil), arguments...)})
	if strings.HasSuffix(executable, "systemd-run") {
		return nil, runner.quotaFailure
	}
	if len(arguments) == 0 {
		return nil, nil
	}
	unit := arguments[len(arguments)-1]
	switch arguments[0] {
	case "is-active":
		if runner.activeUnits[unit] {
			return nil, nil
		}
		return []byte("inactive"), errors.New("exit status 3")
	case "is-enabled":
		if runner.enabledUnits[unit] {
			return []byte("enabled"), nil
		}
		return []byte("disabled"), errors.New("exit status 1")
	case "show":
		// An absent authority has no control group; authorityAbsent treats
		// "/" as "nothing to inspect".
		return []byte("/\n"), nil
	}
	return nil, runner.failures[arguments[0]]
}

func (runner *scriptedRunner) invocations(verb string) []recordedCommand {
	var matched []recordedCommand
	for _, call := range runner.calls {
		if len(call.arguments) > 0 && call.arguments[0] == verb {
			matched = append(matched, call)
		}
	}
	return matched
}

func (runner *scriptedRunner) transients() []recordedCommand {
	var matched []recordedCommand
	for _, call := range runner.calls {
		if strings.HasSuffix(call.executable, "systemd-run") {
			matched = append(matched, call)
		}
	}
	return matched
}

// placementFixture is one fully provisioned placement on temporary roots: the
// project tree with real content, the sysusers configuration, both drop-in
// directories, the ConfigRoot and the StateRoot. Nothing here needs XFS: the
// remover and every postcondition check are plain openat2/unlinkat, and the
// one XFS-specific step (zeroing the project quota) is a command.
type placementFixture struct {
	host         *Host
	runner       *scriptedRunner
	cellRoot     string
	configRoot   string
	stateRoot    string
	unitRoot     string
	sysusersRoot string
	outsideFile  string
}

func newPlacementFixture(t *testing.T) *placementFixture {
	t.Helper()
	base := t.TempDir()
	fixture := &placementFixture{
		runner:       newScriptedRunner(),
		cellRoot:     filepath.Join(base, "cell"),
		configRoot:   filepath.Join(base, "config"),
		stateRoot:    filepath.Join(base, "state"),
		unitRoot:     filepath.Join(base, "units"),
		sysusersRoot: filepath.Join(base, "sysusers"),
		outsideFile:  filepath.Join(base, "outside", "keep.txt"),
	}
	for _, directory := range []string{fixture.cellRoot, fixture.configRoot, fixture.stateRoot,
		fixture.unitRoot, fixture.sysusersRoot, filepath.Dir(fixture.outsideFile)} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, fixture.outsideFile, "a file outside every pinned root")
	host, err := New(Config{
		CellID: testCellID, CellRoot: fixture.cellRoot, ConfigRoot: fixture.configRoot,
		StateRoot: fixture.stateRoot, SystemdUnitRoot: fixture.unitRoot, SysusersRoot: fixture.sysusersRoot,
		XFSQuotaBinary: "/usr/sbin/xfs_quota", SystemctlBinary: "/usr/bin/systemctl",
		SystemdRunBinary: "/usr/bin/systemd-run", SysusersBinary: "/usr/bin/systemd-sysusers",
		Runner: fixture.runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.host = host
	fixture.provision(t)
	return fixture
}

// provision writes what a served placement leaves on the host, including the
// two shapes a confined remover has to survive: a symlink pointing out of the
// tree, and a dangling symlink.
func (fixture *placementFixture) provision(t *testing.T) {
	t.Helper()
	volumeTree := filepath.Join(fixture.cellRoot, testVolumeID)
	writeTestFile(t, filepath.Join(volumeTree, "data", "nested", "deep", "payload.bin"), "user data")
	writeTestFile(t, filepath.Join(volumeTree, "data", "top.txt"), "user data")
	if err := os.Symlink(filepath.Dir(fixture.outsideFile), filepath.Join(volumeTree, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent/target", filepath.Join(volumeTree, "data", "dangling")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(fixture.sysusersRoot, sysusersConfigName(testVolumeID)), "u pfs-x 210000")
	writeTestFile(t, filepath.Join(fixture.unitRoot, authorityServiceDropInDirectory(testVolumeID), "10-portablefs.conf"), "[Service]\n")
	writeTestFile(t, filepath.Join(fixture.unitRoot, authoritySocketDropInDirectory(testVolumeID), "10-portablefs.conf"), "[Socket]\n")
	writeTestFile(t, filepath.Join(fixture.configRoot, testVolumeID, "authority-1.csr"), "csr")
	writeTestFile(t, filepath.Join(fixture.stateRoot, testVolumeID, visibilityMembershipName), membershipDocument(testVolumeID))
}

func (fixture *placementFixture) input() DestroyInput {
	return DestroyInput{
		VolumeID: testVolumeID, AuthorityID: testAuthorityName, AuthorityServerName: testAuthorityName,
		AuthorityEpoch: 7, PlacementSequence: 3, ProjectID: 43001,
		ServiceUID: 210000, ServiceGID: 210000, ListenPort: 9443, QuotaWasApplied: true,
	}
}

func (fixture *placementFixture) assertPlacementGone(t *testing.T) {
	t.Helper()
	for _, path := range []string{
		filepath.Join(fixture.cellRoot, testVolumeID),
		filepath.Join(fixture.sysusersRoot, sysusersConfigName(testVolumeID)),
		filepath.Join(fixture.unitRoot, authorityServiceDropInDirectory(testVolumeID)),
		filepath.Join(fixture.unitRoot, authoritySocketDropInDirectory(testVolumeID)),
		filepath.Join(fixture.configRoot, testVolumeID),
		filepath.Join(fixture.stateRoot, testVolumeID),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived destroy: %v", path, err)
		}
	}
	// The pinned roots themselves are operator-provisioned and must survive.
	for _, root := range []string{fixture.cellRoot, fixture.configRoot, fixture.stateRoot, fixture.unitRoot, fixture.sysusersRoot} {
		if info, err := os.Lstat(root); err != nil || !info.IsDir() {
			t.Fatalf("destroy removed the pinned root %s: %v", root, err)
		}
	}
	if _, err := os.Lstat(fixture.outsideFile); err != nil {
		t.Fatalf("destroy followed a symlink out of the volume tree: %v", err)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDestroyRemovesEveryPlacementResourceAndProvesIt is the whole of archive
// step 4: the five operations run, every postcondition is re-verified from the
// filesystem, and the proof matches the constant the manager will store.
func TestDestroyRemovesEveryPlacementResourceAndProvesIt(t *testing.T) {
	fixture := newPlacementFixture(t)
	result, err := fixture.host.Destroy(context.Background(), fixture.input())
	if err != nil {
		t.Fatal(err)
	}
	if unsatisfied := result.Record.Postconditions.Unsatisfied(); unsatisfied != "" {
		t.Fatalf("postcondition %s is unsatisfied after a successful destroy", unsatisfied)
	}
	if result.ProofSHA256 != pinnedDestroyProof {
		t.Fatalf("destroy proof = %s, want %s", result.ProofSHA256, pinnedDestroyProof)
	}
	fixture.assertPlacementGone(t)

	transients := fixture.runner.transients()
	if len(transients) != 1 {
		t.Fatalf("quota transients = %d, want exactly one", len(transients))
	}
	quota := strings.Join(transients[0].arguments, "\n")
	for _, required := range []string{
		"--unit=portablefs-xfs-destroy-" + testVolumeID,
		"CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER CAP_SYS_ADMIN",
		"/usr/sbin/xfs_quota", "-x", "-c", "limit -p bhard=0 ihard=0 43001", fixture.cellRoot,
	} {
		if !strings.Contains(quota, required) {
			t.Fatalf("quota transient is missing %q: %q", required, quota)
		}
	}
	// The same rule as provisioning: a private mount namespace would point
	// xfs_quota at a different view of the cell mount.
	for _, forbidden := range []string{"PrivateDevices=yes", "PrivateTmp=yes"} {
		if strings.Contains(quota, forbidden) {
			t.Fatalf("quota transient contains mount-namespace isolation %q", forbidden)
		}
	}
	if disables := fixture.runner.invocations("disable"); len(disables) != 1 ||
		disables[0].arguments[len(disables[0].arguments)-1] != authoritySocketUnit(testVolumeID) {
		t.Fatalf("disable invocations = %#v", disables)
	}
	// Authority, archiver, and hydrator drop-in removal each own their reload
	// ("part of the operation, not a caller obligation"), so a full destroy
	// reloads exactly three times.
	if reloads := fixture.runner.invocations("daemon-reload"); len(reloads) != 3 {
		t.Fatalf("daemon-reload invocations = %#v", reloads)
	}
}

// TestDestroyIsIdempotentAndReplaysTheSameProof is the crash-resume property:
// the proof is over verified postconditions, so a second run that removes
// nothing still proves the same end state with the same hash.
func TestDestroyIsIdempotentAndReplaysTheSameProof(t *testing.T) {
	fixture := newPlacementFixture(t)
	first, err := fixture.host.Destroy(context.Background(), fixture.input())
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.host.Destroy(context.Background(), fixture.input())
	if err != nil {
		t.Fatalf("second destroy failed: %v", err)
	}
	if first.ProofSHA256 != second.ProofSHA256 {
		t.Fatalf("destroy proof changed on replay: %s then %s", first.ProofSHA256, second.ProofSHA256)
	}
	if first.Record != second.Record {
		t.Fatalf("destroy record changed on replay: %+v then %+v", first.Record, second.Record)
	}
	fixture.assertPlacementGone(t)
}

// TestDestroyOnAnAbsentTreeSkipsTheQuotaCommand: with no tree and no recorded
// limit there is nothing to clear, and the helper does not invent host work to
// justify a postcondition.
func TestDestroyOnAnAbsentTreeSkipsTheQuotaCommand(t *testing.T) {
	fixture := newPlacementFixture(t)
	input := fixture.input()
	input.QuotaWasApplied = false
	if _, err := fixture.host.Destroy(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	before := len(fixture.runner.transients())
	result, err := fixture.host.Destroy(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(fixture.runner.transients()) - before; got != 0 {
		t.Fatalf("replay ran %d quota transients against an absent tree", got)
	}
	if !result.Record.Postconditions.QuotaCleared || result.ProofSHA256 != pinnedDestroyProof {
		t.Fatalf("replay result = %+v", result)
	}
}

// TestDestroyRefusesUnderALiveAuthority: destroy never stops anything. A
// running authority means quiesce is unfinished, and removing the tree under
// the single writer would be data loss with a live epoch.
func TestDestroyRefusesUnderALiveAuthority(t *testing.T) {
	fixture := newPlacementFixture(t)
	fixture.runner.activeUnits[authorityServiceUnit(testVolumeID)] = true
	result, err := fixture.host.Destroy(context.Background(), fixture.input())
	if err == nil {
		t.Fatal("destroy proceeded under a live authority")
	}
	if result.ProofSHA256 != "" {
		t.Fatalf("a refused destroy returned a proof: %+v", result)
	}
	if len(fixture.runner.transients()) != 0 {
		t.Fatal("destroy touched the project quota before proving the authority absent")
	}
	if _, statErr := os.Lstat(filepath.Join(fixture.cellRoot, testVolumeID)); statErr != nil {
		t.Fatalf("refused destroy removed the volume tree: %v", statErr)
	}
}

// TestDestroyRefusesUnderALiveArchiverOrHydrator: an export or a namespace
// restore holds the tree open and talks to the archive store; is-active
// exiting zero is the only proof of life, and it is enough to refuse.
func TestDestroyRefusesUnderALiveArchiverOrHydrator(t *testing.T) {
	for name, unit := range map[string]string{
		"archiver": archiverUnit(testVolumeID),
		"hydrator": hydratorUnit(testVolumeID),
	} {
		fixture := newPlacementFixture(t)
		fixture.runner.activeUnits[unit] = true
		_, err := fixture.host.Destroy(context.Background(), fixture.input())
		if err == nil || !strings.Contains(err.Error(), unit) {
			t.Fatalf("%s: destroy error = %v, want a refusal naming %s", name, err, unit)
		}
		if _, statErr := os.Lstat(filepath.Join(fixture.cellRoot, testVolumeID)); statErr != nil {
			t.Fatalf("%s: refused destroy removed the volume tree: %v", name, statErr)
		}
	}
}

// TestDestroyToleratesADisableThatCannotApply: a socket that was never enabled
// (or whose unit file is already gone) cannot be disabled, and that is the
// desired end state. The distinction is made by asking is-enabled, not by
// reading systemctl's error text.
func TestDestroyToleratesADisableThatCannotApply(t *testing.T) {
	fixture := newPlacementFixture(t)
	fixture.runner.failures["disable"] = errors.New("exit status 1")
	if _, err := fixture.host.Destroy(context.Background(), fixture.input()); err != nil {
		t.Fatalf("destroy failed on a not-enabled socket: %v", err)
	}
	fixture.assertPlacementGone(t)

	stillEnabled := newPlacementFixture(t)
	stillEnabled.runner.failures["disable"] = errors.New("exit status 1")
	stillEnabled.runner.enabledUnits[authoritySocketUnit(testVolumeID)] = true
	if _, err := stillEnabled.host.Destroy(context.Background(), stillEnabled.input()); err == nil {
		t.Fatal("destroy ignored a socket that is still enabled")
	}
}

// TestDestroyRefusesAQuotaFailureOverALiveTree: the tree is still there, so a
// failed zeroing is a real failure and destroy stops before removing data.
func TestDestroyRefusesAQuotaFailureOverALiveTree(t *testing.T) {
	fixture := newPlacementFixture(t)
	fixture.runner.quotaFailure = errors.New("exit status 1")
	if _, err := fixture.host.Destroy(context.Background(), fixture.input()); err == nil {
		t.Fatal("destroy removed a tree whose project quota could not be zeroed")
	}
	if _, err := os.Lstat(filepath.Join(fixture.cellRoot, testVolumeID)); err != nil {
		t.Fatalf("refused destroy removed the volume tree: %v", err)
	}
}

// TestDestroyRefusesAnUnboundPlacement: the proof binds to one placement, so a
// caller that cannot name the placement gets no destroy at all.
func TestDestroyRefusesAnUnboundPlacement(t *testing.T) {
	fixture := newPlacementFixture(t)
	for name, mutate := range map[string]func(*DestroyInput){
		"no volume":    func(input *DestroyInput) { input.VolumeID = "" },
		"no epoch":     func(input *DestroyInput) { input.AuthorityEpoch = 0 },
		"no sequence":  func(input *DestroyInput) { input.PlacementSequence = 0 },
		"no project":   func(input *DestroyInput) { input.ProjectID = 0 },
		"system uid":   func(input *DestroyInput) { input.ServiceUID = 0 },
		"system gid":   func(input *DestroyInput) { input.ServiceGID = 0 },
		"no port":      func(input *DestroyInput) { input.ListenPort = 0 },
		"no authority": func(input *DestroyInput) { input.AuthorityID = "" },
		"no name":      func(input *DestroyInput) { input.AuthorityServerName = "" },
	} {
		input := fixture.input()
		mutate(&input)
		if _, err := fixture.host.Destroy(context.Background(), input); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: destroy error = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(fixture.cellRoot, testVolumeID)); err != nil {
		t.Fatalf("a refused destroy removed the volume tree: %v", err)
	}
}

// TestVerifyDestroyedReadsTheFilesystemNotTheActions: the postcondition record
// is a fresh set of lstats, so an untouched placement reports every
// postcondition false and names the first one.
func TestVerifyDestroyedReadsTheFilesystemNotTheActions(t *testing.T) {
	fixture := newPlacementFixture(t)
	postconditions, err := fixture.host.verifyDestroyed(testVolumeID, false)
	if err != nil {
		t.Fatal(err)
	}
	want := DestroyPostconditions{}
	if postconditions != want {
		t.Fatalf("postconditions of an intact placement = %+v, want all false", postconditions)
	}
	if unsatisfied := postconditions.Unsatisfied(); unsatisfied != "config_root_absent" {
		t.Fatalf("Unsatisfied() = %q", unsatisfied)
	}
}
