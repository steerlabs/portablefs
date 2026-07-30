package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStartedChildIdentityFailurePreservesAdvancedIntent(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "mounts")
	mountPath := filepath.Join(t.TempDir(), "mount")
	operation, err := acquireMountOperation(stateDir, mountPath, "volume", "main", "fuse")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.close(false)
	identity, err := processStartIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	operation.mountInstanceID = "mnt_AAAAAAAAAAAAAAAAAAAAAA"
	operation.mountMechanism = "direct"
	if err := operation.writeIntent("mounting", os.Getpid(), identity); err != nil {
		t.Fatal(err)
	}
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	err = terminateUnidentifiedStartedMount(child, operation, fmt.Errorf("injected identity read failure"))
	if err == nil || !strings.Contains(err.Error(), "explicit exact reconciliation") {
		t.Fatalf("termination error = %v", err)
	}
	intent, err := readMountIntent(operation.intentPath, mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if intent == nil || intent.Phase != "mounting" || intent.MountInstanceID != operation.mountInstanceID {
		t.Fatalf("advanced intent was removed or changed: %+v", intent)
	}
}

func TestIsMountpoint(t *testing.T) {
	dir := t.TempDir()
	if isMountpoint(dir) {
		t.Fatalf("ordinary directory %s must not be a mountpoint", dir)
	}
	if isMountpoint(filepath.Join(dir, "does-not-exist")) {
		t.Fatal("nonexistent path must not be a mountpoint")
	}
	if runtime.GOOS == "darwin" && !isMountpoint("/dev") {
		t.Fatal("/dev (devfs) must be a mountpoint on macOS")
	}
}

// umountTestEnv is testEnv plus an isolated mount state dir, the setup every
// umount test needs.
func umountTestEnv(t *testing.T) (e *cmdEnv, stdout, stderr *bytes.Buffer, stateDir string) {
	t.Helper()
	e, stdout, stderr = testEnv(t)
	stateHome := t.TempDir()
	baseGetenv := e.getenv
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return baseGetenv(k)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	return e, stdout, stderr, stateDir
}

// TestUmountOrphanedMountWithoutAttachRefFailsClosed is the production incident:
// the platform mount was torn down externally (forced diskutil unmount,
// extension crash) while the recorded daemon pid stayed alive. Without an
// attachRef PortableFS cannot prove the drain and must preserve both daemon
// and state.
func TestUmountOrphanedMountWithoutAttachRefFailsClosed(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir()) // ordinary directory: nothing mounted on it
	if err != nil {
		t.Fatal(err)
	}

	// A fake mount daemon that is genuinely alive. Reap it in the background
	// so pidAlive flips false the moment it dies, like a real daemon that
	// init/launchd reaps after reparenting.
	daemon := exec.Command("sleep", "60")
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	daemonDone := make(chan struct{})
	go func() { _ = daemon.Wait(); close(daemonDone) }()
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		<-daemonDone
	})

	daemonIdentity, err := processStartIdentity(daemon.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	invalidState := mountState{
		MountPath: mountPath, VolumeID: "vol_orphan", Branch: "main",
		PID: daemon.Process.Pid, ProcessStartIdentity: daemonIdentity, Strategy: "fskit",
	}
	writeRawMountState(t, stateDir, invalidState)
	statePath := mountStatePath(stateDir, mountPath)
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatalf("umount unexpectedly succeeded, stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "incomplete mount instance identity") ||
		!strings.Contains(stderr.String(), "nothing was unmounted") {
		t.Fatalf("fail-closed explanation missing: %q", stderr.String())
	}
	select {
	case <-daemonDone:
		t.Fatal("fail-closed unmount stopped the daemon")
	case <-time.After(100 * time.Millisecond):
	}
	after, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("invalid mount-state evidence changed: err=%v before=%q after=%q", err, before, after)
	}
}

// TestUmountDeadDaemonWithoutDrainProofFailsClosed pins stale-state handling.
func TestUmountDeadDaemonWithoutDrainProofFailsClosed(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath, err := canonicalMountPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	invalidState := mountState{
		MountPath: mountPath, VolumeID: "vol_stale", Branch: "main",
		PID: 4194000, ProcessStartIdentity: "dead-process", Strategy: "fuse",
	}
	writeRawMountState(t, stateDir, invalidState)
	statePath := mountStatePath(stateDir, mountPath)
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"umount", mountPath, "--json"}); rc == 0 {
		t.Fatalf("umount unexpectedly succeeded, stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "incomplete mount instance identity") ||
		!strings.Contains(stderr.String(), "nothing was unmounted") {
		t.Fatalf("fail-closed detail missing: %q", stderr.String())
	}
	after, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("invalid mount-state evidence changed: err=%v before=%q after=%q", err, before, after)
	}
}

// TestUmountUntrackedFailsClosed: without recorded identity and durability
// state PortableFS never substitutes a plain platform unmount.
func TestUmountUntrackedFailsClosed(t *testing.T) {
	e, _, stderr, _ := umountTestEnv(t)
	mountPath := t.TempDir()
	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatalf("umount unexpectedly succeeded, stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "refusing an unverified plain unmount") {
		t.Fatalf("fail-closed detail missing: %q", stderr.String())
	}
}
