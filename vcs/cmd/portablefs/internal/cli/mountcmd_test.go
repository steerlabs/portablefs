package cli

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

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
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return ""
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
	mountPath := t.TempDir() // ordinary directory: nothing mounted on it

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

	if err := writeMountState(stateDir, mountState{
		MountPath: mountPath, VolumeID: "vol_orphan", Branch: "main",
		PID: daemon.Process.Pid, Strategy: "fskit",
	}); err != nil {
		t.Fatal(err)
	}

	if rc := e.run([]string{"umount", mountPath}); rc == 0 {
		t.Fatalf("umount unexpectedly succeeded, stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "unsupported recorded mount strategy") ||
		!strings.Contains(stderr.String(), "nothing was unmounted") {
		t.Fatalf("fail-closed explanation missing: %q", stderr.String())
	}
	select {
	case <-daemonDone:
		t.Fatal("fail-closed unmount stopped the daemon")
	case <-time.After(100 * time.Millisecond):
	}
	if st, err := readMountState(stateDir, mountPath); err != nil || st == nil {
		t.Fatalf("mount state must remain: %+v %v", st, err)
	}
}

// TestUmountDeadDaemonWithoutDrainProofFailsClosed pins stale-state handling.
func TestUmountDeadDaemonWithoutDrainProofFailsClosed(t *testing.T) {
	e, _, stderr, stateDir := umountTestEnv(t)
	mountPath := t.TempDir()
	if err := writeMountState(stateDir, mountState{
		MountPath: mountPath, VolumeID: "vol_stale", Branch: "main",
		PID: 4194000, Strategy: "fuse",
	}); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"umount", mountPath, "--json"}); rc == 0 {
		t.Fatalf("umount unexpectedly succeeded, stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "cannot prove a clean drain") {
		t.Fatalf("fail-closed detail missing: %q", stderr.String())
	}
	if st, err := readMountState(stateDir, mountPath); err != nil || st == nil {
		t.Fatalf("mount state must remain: %+v %v", st, err)
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
