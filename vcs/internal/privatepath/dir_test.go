package privatepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := EnsureDir(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v", info.Mode())
	}
}

func TestEnsureDirRejectsExistingUnsafePath(t *testing.T) {
	t.Run("mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := EnsureDir(path); err == nil {
			t.Fatal("wrong mode accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "private")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := EnsureDir(path); err == nil {
			t.Fatal("symlink accepted")
		}
	})
	t.Run("writable ancestor", func(t *testing.T) {
		root := t.TempDir()
		ancestor := filepath.Join(root, "hostile")
		if err := os.Mkdir(ancestor, 0o777); err != nil {
			t.Fatal(err)
		}
		// Ensure the test is independent of a restrictive umask.
		if err := os.Chmod(ancestor, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := EnsureDir(filepath.Join(ancestor, "private")); err == nil {
			t.Fatal("group/world-writable non-sticky ancestor accepted")
		}
	})
}
