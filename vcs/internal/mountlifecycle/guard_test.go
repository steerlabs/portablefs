package mountlifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPath(t *testing.T) {
	if got := Path("/Users/me/.local/state/portablefs"); got != "/Users/me/.local/state/portablefs/mount-lifecycle.lock" {
		t.Fatalf("Path = %q", got)
	}
}

func TestSharedGuardsExcludeReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard")
	first, err := acquire(path, "mount-lifecycle.lock", syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := acquire(path, "mount-lifecycle.lock", syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquire(path, "mount-lifecycle.lock", syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, ErrBusy) {
		t.Fatalf("exclusive while shared = %v, want ErrBusy", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	exclusive, err := acquire(path, "mount-lifecycle.lock", syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		t.Fatalf("exclusive after shared release: %v", err)
	}
	defer exclusive.Close()
	if _, err := acquire(path, "mount-lifecycle.lock", syscall.LOCK_SH|syscall.LOCK_NB); !errors.Is(err, ErrBusy) {
		t.Fatalf("shared while exclusive = %v, want ErrBusy", err)
	}
}

func TestGuardRejectsUnsafeInodes(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, nil, 0o666); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "guard")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := openLockFile(path); err == nil {
			t.Fatal("symlink guard did not fail")
		}
	})

	t.Run("wrong permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "guard")
		if err := os.WriteFile(path, nil, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := openLockFile(path); err == nil {
			t.Fatal("wrong-mode guard did not fail")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o666 {
			t.Fatalf("guard permissions were repaired to %04o", info.Mode().Perm())
		}
	})

	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "guard")
		if err := os.Mkdir(path, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := openLockFile(path); err == nil {
			t.Fatal("directory guard did not fail")
		}
	})
}

func TestGuardRejectsUnsafeStateDirectory(t *testing.T) {
	t.Run("wrong mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := acquire(path, "mount-lifecycle.lock", syscall.LOCK_SH|syscall.LOCK_NB); err == nil {
			t.Fatal("wrong-mode state dir did not fail")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "state")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := acquire(path, "mount-lifecycle.lock", syscall.LOCK_SH|syscall.LOCK_NB); err == nil {
			t.Fatal("symlink state dir did not fail")
		}
	})
}
