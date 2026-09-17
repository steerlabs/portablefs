//go:build linux

package fusev3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func coherenceTrackedFiles(root string) (int, error) {
	command := exec.Command("git", "-C", root, "ls-files", "-z")
	command.Env = append(os.Environ(), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	output, err := command.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("git ls-files: %w: %s", err, bytes.TrimSpace(output))
	}
	return bytes.Count(output, []byte{0}), nil
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
