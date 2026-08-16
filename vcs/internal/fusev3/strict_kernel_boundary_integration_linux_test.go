//go:build linux

package fusev3

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const envStrictStackTestScript = "PORTABLEFS_STRICT_STACK_TEST_SCRIPT"

// TestStrictKernelRefusesStackingExportAndLoopBacking keeps one production
// strict mount alive while the kernel patch's privileged live oracle probes all
// superblock and file-backed-cache escape boundaries.  It intentionally runs
// in the harness's separate capability-scoped process: overlay, raw
// delayed-INIT FUSE, and loop configuration require CAP_SYS_ADMIN, while the
// ordinary integration suite must remain capability-free so its DAC assertions
// are meaningful.
func TestStrictKernelRefusesStackingExportAndLoopBacking(t *testing.T) {
	script := os.Getenv(envStrictStackTestScript)
	if script == "" {
		t.Skipf("set %s to the checked-in strict stacking oracle", envStrictStackTestScript)
	}
	if !strings.HasSuffix(script, "/tests/test_strict_stacking.py") {
		t.Fatalf("%s must name the checked-in strict stacking oracle, got %q", envStrictStackTestScript, script)
	}
	if info, err := os.Stat(script); err != nil {
		t.Fatalf("stat strict stacking oracle: %v", err)
	} else if !info.Mode().IsRegular() {
		t.Fatalf("strict stacking oracle %q is not a regular file", script)
	}

	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	cmd := exec.Command("python3", script)
	cmd.Env = append(os.Environ(), "PFS_STRICT_STACK_TEST_DIR="+f.mountPath(0))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("strict stacking/export/loop oracle: %v\n%s", err, output)
	}
	t.Logf("strict stacking/export/loop oracle:\n%s", output)

	// The Python suite is deliberately verbose and exact.  Require every live
	// case here too so a decorator change cannot silently turn the subprocess
	// into a successful all-skipped run.
	for _, name := range []string{
		"test_delayed_init_never_exposes_a_stackable_fuse_superblock",
		"test_strict_mount_is_refused_as_overlay_lower",
		"test_strict_mount_is_refused_as_overlay_upper",
		"test_shared_file_is_refused_as_read_only_loop_backing",
	} {
		if !strings.Contains(string(output), fmt.Sprintf("%s (__main__.StrictStackingTests.%s) ... ok", name, name)) {
			t.Fatalf("strict kernel oracle did not execute %s to an exact PASS", name)
		}
	}
}
