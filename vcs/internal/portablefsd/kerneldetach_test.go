package portablefsd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func sleepHelperPath(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/bin/sleep", "/usr/bin/sleep"} {
		if err := validateKernelDetachHelper(candidate); err == nil {
			return candidate
		}
	}
	t.Skip("no root-owned sleep binary available to model a wedged detach helper")
	return ""
}

// A DETACH THAT NEVER RETURNS MUST NOT BECOME THE DAEMON'S PROBLEM.
//
// This is the whole termination guarantee in one test: the helper is pinned for
// far longer than the budget, and the caller is back — with a definite verdict —
// almost immediately. On the base revision the equivalent call was unix.Unmount
// on this goroutine's own thread, which cannot be bounded at all.
func TestKernelDetachAbandonsAWedgedHelperInsteadOfWaiting(t *testing.T) {
	helper := sleepHelperPath(t)
	restore := kernelDetachHelper
	kernelDetachHelper = helper
	t.Cleanup(func() { kernelDetachHelper = restore })

	start := time.Now()
	err := execKernelDetachHelper(150*time.Millisecond, "/Volumes/wedged", "30")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a helper that never returns must not be reported as a completed detach")
	}
	if !abandonedKernelDetach(err) {
		t.Fatalf("want an abandoned-detach verdict, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the caller waited %s on an abandoned detach; the budget was 150ms", elapsed)
	}
	if !strings.Contains(err.Error(), "remains terminable") {
		t.Fatalf("the verdict must tell the operator the daemon is still killable: %v", err)
	}
}

func TestKernelDetachReportsHelperSuccess(t *testing.T) {
	helper := sleepHelperPath(t)
	restore := kernelDetachHelper
	kernelDetachHelper = helper
	t.Cleanup(func() { kernelDetachHelper = restore })

	if err := execKernelDetachHelper(10*time.Second, "/Volumes/fine", "0"); err != nil {
		t.Fatalf("a helper that exits 0 is a completed detach: %v", err)
	}
}

func TestKernelDetachReportsHelperFailureWithItsOutput(t *testing.T) {
	helper := sleepHelperPath(t)
	restore := kernelDetachHelper
	kernelDetachHelper = helper
	t.Cleanup(func() { kernelDetachHelper = restore })

	err := execKernelDetachHelper(10*time.Second, "/Volumes/bad", "not-a-duration")
	if err == nil {
		t.Fatal("a nonzero helper exit must be a refusal")
	}
	if abandonedKernelDetach(err) {
		t.Fatalf("a nonzero exit is a refusal, not an abandonment: %v", err)
	}
}

func TestKernelDetachClassifiesOnlyExactCLocaleBusyRefusal(t *testing.T) {
	for _, output := range []string{
		"umount: /Volumes/pfs: Resource busy\n",
		"umount(/Volumes/pfs): Resource busy -- try 'diskutil unmount'\n",
	} {
		busy := classifyKernelDetachHelperError(
			"/Volumes/pfs",
			errors.New("exit status 1"),
			output,
		)
		if !errors.Is(busy, syscall.EBUSY) {
			t.Fatalf("busy refusal was not classified as EBUSY: %v", busy)
		}
	}
	for _, output := range []string{
		"umount: /Volumes/Resource busy: Input/output error",
		"umount: /Volumes/pfs: Input/output error",
		"Resource busy but not an errno suffix",
		"umount(/Volumes/other): Resource busy -- try 'diskutil unmount'",
		"umount(/Volumes/pfs): Resource busy -- try 'diskutil unmount' plus noise",
	} {
		err := classifyKernelDetachHelperError(
			"/Volumes/pfs",
			errors.New("exit status 1"),
			output,
		)
		if errors.Is(err, syscall.EBUSY) {
			t.Fatalf("non-busy helper output was classified as EBUSY: %q", output)
		}
	}
}

func TestKernelDetachRefusesAnUntrustedHelper(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "umount")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Chmod, not the WriteFile mode: the create mode is filtered by umask, and
	// under a 022 umask the file lands 0755 — which a root test process also
	// owns, making it a genuinely trusted helper and the test vacuous.
	if err := os.Chmod(fake, 0o777); err != nil {
		t.Fatal(err)
	}
	restore := kernelDetachHelper
	kernelDetachHelper = fake
	t.Cleanup(func() { kernelDetachHelper = restore })

	if err := execKernelDetachHelper(time.Second, "/Volumes/x", "/Volumes/x"); err == nil {
		t.Fatal("a user-writable helper must never be executed with this daemon's privileges")
	}
}

// THE CONSTRUCTIVE PROOF. The kernel-unkillable state cannot be reproduced in a
// unit test, so the invariant is enforced at the source level instead: no file
// in this package may issue unmount(2) in process. Every detach goes through
// runKernelDetach, which runs it in a child that can be abandoned.
func TestDaemonNeverIssuesUnmountSyscallInProcess(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"unix.Unmount(", "syscall.Unmount(", "unix.Unmount2("} {
			if strings.Contains(string(body), forbidden) {
				t.Fatalf(
					"%s calls %s in process: an unmount(2) that the filesystem extension never answers "+
						"parks its thread in an uninterruptible kernel wait, which makes portablefsd immune "+
						"to SIGKILL and leaves its state-dir flock held forever. Issue it through "+
						"runKernelDetach instead.",
					name, forbidden,
				)
			}
		}
	}
}

func TestWaitBoundedReturnsWhenAServingGoroutineNeverFinishes(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1) // never Done: models a serving goroutine that cannot return.
	start := time.Now()
	waitBounded(&wg, 100*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("shutdown waited %s on a goroutine that never returns", elapsed)
	}
}
