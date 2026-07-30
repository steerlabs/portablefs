package portablefsd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	base, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		panic(err)
	}
	root, err := os.MkdirTemp(base, "pfs-daemon-tests-")
	if err != nil {
		panic(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		panic(err)
	}
	if err := os.Setenv("TMPDIR", root); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(root)
	os.Exit(code)
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
