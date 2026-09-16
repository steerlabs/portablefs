//go:build linux

package fusev3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/bench/coherencebench"
)

const envCoherenceProfileDir = "PORTABLEFS_PROFILE_DIR"

// TestShippingCapacityGitAddCompletes preserves the exact untimed setup that
// disconnected the protocol-6 mount. The fixture starts at the shipping name
// cache and item-table capacities; it does not use the former 4,096-name setup
// workaround before git add.
func TestShippingCapacityGitAddCompletes(t *testing.T) {
	if os.Getenv(envPerformance) != "1" {
		t.Skipf("set %s=1 to run the shipping-capacity git-add regression", envPerformance)
	}
	fixture := newIntegrationFixture(t, baselineIntegrationConfig(1))
	root := fixture.join(0, "repo")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("create mounted git repository: %v", err)
	}
	rootBarrier, err := os.Open(fixture.mountPath(0))
	if err != nil {
		t.Fatalf("open mount-root barrier: %v", err)
	}
	t.Cleanup(func() { _ = rootBarrier.Close() })
	if err := coherencebench.PrepareGit(root, baselineGitFiles); err != nil {
		_ = rootBarrier.Close()
		writeCoherenceFailureDiagnostics(t, fixture, "shipping-capacity-git-add")
		t.Fatalf("prepare 20,000-file repository at name/item capacities %d/%d: %v; mount health: %s",
			baselineNameCapacity, baselineItemLimit, err, fixture.sessionDiagnostics())
	}
	if err := rootBarrier.Sync(); err != nil {
		_ = rootBarrier.Close()
		writeCoherenceFailureDiagnostics(t, fixture, "shipping-capacity-git-add-sync")
		t.Fatalf("sync repository root after shipping-capacity git add: %v; mount health: %s", err, fixture.sessionDiagnostics())
	}
	if err := rootBarrier.Close(); err != nil {
		writeCoherenceFailureDiagnostics(t, fixture, "shipping-capacity-git-add-close")
		t.Fatalf("close repository root after shipping-capacity git add: %v; mount health: %s", err, fixture.sessionDiagnostics())
	}
	tracked, err := coherenceTrackedFiles(root)
	if err != nil {
		writeCoherenceFailureDiagnostics(t, fixture, "shipping-capacity-git-ls-files")
		t.Fatalf("enumerate tracked files after shipping-capacity git add: %v; mount health: %s", err, fixture.sessionDiagnostics())
	}
	if tracked != baselineGitFiles {
		t.Fatalf("shipping-capacity git add tracked %d files, want %d", tracked, baselineGitFiles)
	}
	if _, err := coherencebench.GitStatus(root, "post-add-check", baselineGitFiles); err != nil {
		writeCoherenceFailureDiagnostics(t, fixture, "shipping-capacity-git-status-check")
		t.Fatalf("verify repository after shipping-capacity git add: %v; mount health: %s", err, fixture.sessionDiagnostics())
	}
}

// TestCoherenceProfiles records the requested full-size workloads. The mount
// frontend, RPC transport, and Authority fixture intentionally share this test
// process, so each raw profile is a combined process profile. Stack filtering
// attributes samples to the two sides without pretending that shared runtime
// frames have an exclusive owner.
func TestCoherenceProfiles(t *testing.T) {
	if os.Getenv(envPerformance) != "1" {
		t.Skipf("set %s=1 to run the coherence-v2 profiles", envPerformance)
	}
	profileDir := os.Getenv(envCoherenceProfileDir)
	if profileDir == "" {
		t.Skipf("set %s to an output directory for raw profiles", envCoherenceProfileDir)
	}
	if !filepath.IsAbs(profileDir) {
		t.Fatalf("%s must be an absolute path: %q", envCoherenceProfileDir, profileDir)
	}
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatalf("create profile directory: %v", err)
	}
	copyCoherenceProfileExecutable(t, profileDir)

	t.Run("install-1", func(t *testing.T) {
		fixture := newIntegrationFixture(t, baselineIntegrationConfig(1))
		root := fixture.join(0, "install")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatalf("create mounted install root: %v", err)
		}
		profileCoherenceWorkload(t, profileDir, "install-1", fixture, func() (coherencebench.WorkloadResult, error) {
			return coherencebench.Install(root, baselineInstallFiles, baselineInstallDirs, 1)
		})
	})

	t.Run("git-status-cold", func(t *testing.T) {
		preparationConfig := baselineIntegrationConfig(1)
		preparationConfig.CachedNameCapacity = integrationCachedNames
		fixture := newIntegrationFixture(t, preparationConfig)
		root := fixture.join(0, "repo")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatalf("create mounted git repository: %v", err)
		}
		if err := coherencebench.PrepareGit(root, baselineGitFiles); err != nil {
			writeCoherenceFailureDiagnostics(t, fixture, "profile-git-prepare")
			t.Fatalf("prepare 20,000-file repository for cold profile: %v; mount health: %s", err, fixture.sessionDiagnostics())
		}
		// Cold has the same definition as the baseline: recreate the complete
		// Authority and mount at the shipping name capacity while retaining
		// only durable XFS state. Untimed setup uses the 4,096-name profile.
		fixture.cfg.CachedNameCapacity = baselineNameCapacity
		fixture.remount()
		profileCoherenceWorkload(t, profileDir, "git-status-cold", fixture, func() (coherencebench.WorkloadResult, error) {
			return coherencebench.GitStatus(root, "cold", baselineGitFiles)
		})
	})
}

func profileCoherenceWorkload(
	t *testing.T,
	profileDir string,
	name string,
	fixture *integrationFixture,
	run func() (coherencebench.WorkloadResult, error),
) {
	t.Helper()
	prefix := coherenceProfilePrefix(name)
	enableBaselineOpenTracking(fixture.counter)
	drainBaselineOpens(t, fixture.counter)
	// Allocation accounting can lag by two GC cycles.
	runtime.GC()
	runtime.GC()
	writeNamedRuntimeProfile(t, "allocs", filepath.Join(profileDir, prefix+".allocs.before.pprof"))

	cpuPath := filepath.Join(profileDir, prefix+".cpu.pprof")
	cpu, err := os.Create(cpuPath)
	if err != nil {
		t.Fatalf("create CPU profile %s: %v", cpuPath, err)
	}
	if err := pprof.StartCPUProfile(cpu); err != nil {
		_ = cpu.Close()
		t.Fatalf("start CPU profile %s: %v", cpuPath, err)
	}
	// Stop profiling even if the close-drain assertion terminates this subtest.
	defer func() {
		pprof.StopCPUProfile()
		_ = cpu.Close()
	}()
	result, runErr := run()
	if runErr == nil {
		// Keep both CPU and allocation capture open through application,
		// delegation release, and the final Authority CLOSE for every handle.
		drainBaselineOpens(t, fixture.counter)
	}
	pprof.StopCPUProfile()
	if err := cpu.Close(); err != nil {
		t.Fatalf("close CPU profile %s: %v", cpuPath, err)
	}
	if runErr != nil {
		writeCoherenceFailureDiagnostics(t, fixture, prefix)
		t.Fatalf("profile workload %s: %v; mount health: %s", name, runErr, fixture.sessionDiagnostics())
	}

	// Allocation accounting can lag by two GC cycles.
	runtime.GC()
	runtime.GC()
	writeNamedRuntimeProfile(t, "allocs", filepath.Join(profileDir, prefix+".allocs.after.pprof"))
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode profile workload result: %v", err)
	}
	t.Logf("PORTABLEFS_PROFILE workload=%s process=combined files=%s result=%s", name, prefix, encoded)
}

func coherenceTrackedFiles(root string) (int, error) {
	command := exec.Command("git", "-C", root, "ls-files", "-z")
	command.Env = append(os.Environ(), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	output, err := command.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("git ls-files: %w: %s", err, bytes.TrimSpace(output))
	}
	return bytes.Count(output, []byte{0}), nil
}

func copyCoherenceProfileExecutable(t *testing.T, profileDir string) {
	t.Helper()
	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatalf("locate profile process executable: %v", err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open profile process executable: %v", err)
	}
	defer source.Close()
	destinationPath := filepath.Join(profileDir, coherenceProfilePrefix("fusev3.test"))
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatalf("create profile process executable %s: %v", destinationPath, err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		t.Fatalf("copy profile process executable %s: %v", destinationPath, err)
	}
	if err := destination.Close(); err != nil {
		t.Fatalf("close profile process executable %s: %v", destinationPath, err)
	}
}

func coherenceProfilePrefix(name string) string {
	run := strings.TrimSpace(os.Getenv("PORTABLEFS_PROFILE_RUN"))
	if run == "" {
		return name
	}
	run = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, run)
	return run + "." + name
}

func writeNamedRuntimeProfile(t *testing.T, name, path string) {
	t.Helper()
	profile := pprof.Lookup(name)
	if profile == nil {
		t.Fatalf("runtime profile %q is unavailable", name)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create runtime profile %s: %v", path, err)
	}
	if err := profile.WriteTo(file, 0); err != nil {
		_ = file.Close()
		t.Fatalf("write runtime profile %s: %v", path, err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close runtime profile %s: %v", path, err)
	}
}

func writeCoherenceFailureDiagnostics(t *testing.T, fixture *integrationFixture, label string) {
	t.Helper()
	var stacks bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&stacks, 2); err != nil {
		t.Logf("write goroutine diagnostics: %v", err)
	} else {
		t.Logf("PORTABLEFS_MEASURE_GOROUTINES %s\n%s", label, stacks.Bytes())
	}
	fixture.counter.mu.Lock()
	requests := make(map[string]int, len(fixture.counter.byKind))
	for kind, count := range fixture.counter.byKind {
		requests[kind] = count
	}
	fixture.counter.mu.Unlock()
	encoded, err := json.Marshal(requests)
	if err != nil {
		t.Logf("encode Authority request diagnostics: %v", err)
	} else {
		t.Logf("PORTABLEFS_MEASURE_AUTHORITY_REQUESTS %s %s", label, encoded)
	}
	for index, mount := range fixture.mounts {
		t.Logf("PORTABLEFS_MEASURE_MOUNT %s index=%d fatal=%v mounted=%t", label, index, mount.fatalError(), isMounted(t, fixture.mountPath(index)))
	}
	if dir := os.Getenv(envCoherenceProfileDir); dir != "" && filepath.IsAbs(dir) {
		path := filepath.Join(dir, fmt.Sprintf("%s.goroutines.txt", coherenceProfilePrefix(label)))
		if err := os.WriteFile(path, stacks.Bytes(), 0o600); err != nil {
			t.Logf("write goroutine diagnostics %s: %v", path, err)
		}
	}
}
