package cli

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	base, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		panic(err)
	}
	root, err := os.MkdirTemp(base, "pfs-")
	if err != nil {
		panic(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		panic(err)
	}
	if err := os.Setenv("TMPDIR", root); err != nil {
		panic(err)
	}
	resolveFSKitAccountHome = func() (string, error) { return root, nil }
	code := m.Run()
	_ = os.RemoveAll(root)
	os.Exit(code)
}

// testEnv builds a cmdEnv whose every process boundary is a temporary
// directory: the external daemon control socket, the mount lifecycle guard,
// and canonical operational state. Nothing it returns touches the real account.
func testEnv(t *testing.T) (*cmdEnv, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	e := &cmdEnv{
		stdout:            stdout,
		stderr:            stderr,
		getenv:            func(string) string { return "" },
		version:           "test",
		lifecycleStateDir: filepath.Join(t.TempDir(), "state", "portablefs"),
		stateDir:          filepath.Join(t.TempDir(), "operational-state", "portablefs"),
		sleepFn:           func(time.Duration) {},
		kernelInventoryFn: func() ([]string, error) { return nil, nil },
	}
	return e, stdout, stderr
}

// shortSocketDir is a temporary directory outside the test framework's deep
// per-test path, so a unix socket created under it stays inside sun_path.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// leaveCLIStaleUnixSocket leaves an unbound socket file behind at path — the
// exact debris a killed owner leaves, which every listener path must reclaim
// rather than refuse.
func leaveCLIStaleUnixSocket(t *testing.T, path string) {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
}
