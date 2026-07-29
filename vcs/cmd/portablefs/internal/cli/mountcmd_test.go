package cli

import (
	"bytes"
	"encoding/json"
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

// TestUmountReconcilesOrphanedMountWithLiveDaemon is the production incident:
// the platform mount was torn down externally (forced diskutil unmount,
// extension crash) while the recorded daemon pid stayed alive. umount must
// not report "busy" for a path with nothing mounted on it — it stops the
// daemon, removes the stale record, and succeeds.
func TestUmountReconcilesOrphanedMountWithLiveDaemon(t *testing.T) {
	e, stdout, stderr, stateDir := umountTestEnv(t)
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

	if rc := e.run([]string{"umount", mountPath}); rc != 0 {
		t.Fatalf("umount rc = %d, stderr: %q", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "still running") || !strings.Contains(stderr.String(), "stopping it") {
		t.Fatalf("reconcile must explain itself: %q", stderr.String())
	}
	select {
	case <-daemonDone:
	case <-time.After(6 * time.Second): // stopMountDaemon escalates to SIGKILL at 5s
		t.Fatal("fake daemon still alive after umount; stopMountDaemon must stop it")
	}
	if st, err := readMountState(stateDir, mountPath); err != nil || st != nil {
		t.Fatalf("mount state must be removed: %+v %v", st, err)
	}
	if !strings.Contains(stdout.String(), "unmounted "+mountPath) || !strings.Contains(stdout.String(), "vol_orphan") {
		t.Fatalf("umount must report success: %q", stdout.String())
	}
}

// TestUmountDeadDaemonNotMountedCleansState pins stale-state cleanup:
// a stale record whose daemon is gone and whose path is not mounted cleans up
// and exits 0 (here through the --json path).
func TestUmountDeadDaemonNotMountedCleansState(t *testing.T) {
	e, stdout, stderr, stateDir := umountTestEnv(t)
	mountPath := t.TempDir()
	if err := writeMountState(stateDir, mountState{
		MountPath: mountPath, VolumeID: "vol_stale", Branch: "main",
		PID: 4194000, Strategy: "fuse",
	}); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"umount", mountPath, "--json"}); rc != 0 {
		t.Fatalf("umount rc = %d, stderr: %q", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "already gone") {
		t.Fatalf("stale-record warning missing: %q", stderr.String())
	}
	if st, err := readMountState(stateDir, mountPath); err != nil || st != nil {
		t.Fatalf("mount state must be removed: %+v %v", st, err)
	}
	var parsed struct {
		MountPath string `json:"mountPath"`
		VolumeID  string `json:"volumeId"`
		Unmounted bool   `json:"unmounted"`
		Tracked   bool   `json:"tracked"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &parsed); err != nil {
		t.Fatalf("umount --json must emit valid JSON: %v (%q)", err, stdout.String())
	}
	if parsed.MountPath != mountPath || parsed.VolumeID != "vol_stale" || !parsed.Unmounted || !parsed.Tracked {
		t.Fatalf("parsed = %+v", parsed)
	}
}

// TestUmountUntrackedNotMountedIsIdempotent: unmounting a path that has no
// recorded state and nothing mounted on it is a no-op success, not an error —
// unmount is naturally idempotent.
func TestUmountUntrackedNotMountedIsIdempotent(t *testing.T) {
	e, stdout, stderr, _ := umountTestEnv(t)
	mountPath := t.TempDir()
	if rc := e.run([]string{"umount", mountPath}); rc != 0 {
		t.Fatalf("umount rc = %d, stderr: %q", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "nothing was mounted") {
		t.Fatalf("idempotent no-op must warn: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "unmounted "+mountPath) {
		t.Fatalf("umount must report success: %q", stdout.String())
	}
}
