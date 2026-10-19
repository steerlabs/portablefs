package privatepath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRecordLockRejectsTamperingAfterFlock(t *testing.T) {
	for _, operation := range []int{unix.LOCK_SH, unix.LOCK_EX} {
		for _, tamper := range []string{"rename", "replace", "hardlink", "symlink", "permissions"} {
			t.Run(map[int]string{unix.LOCK_SH: "shared", unix.LOCK_EX: "exclusive"}[operation]+"/"+tamper, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "private", "record")
				if err := WriteFileAtomic(path, []byte("valid")); err != nil {
					t.Fatal(err)
				}
				original := validateRecordLock
				t.Cleanup(func() { validateRecordLock = original })
				validateRecordLock = func(parent *os.File, dir, name string, file *os.File) error {
					path := filepath.Join(dir, name)
					var err error
					switch tamper {
					case "rename":
						err = os.Rename(path, path+".moved")
					case "replace":
						err = WriteFileAtomic(path, []byte("new lock"))
					case "hardlink":
						err = os.Link(path, path+".alias")
					case "symlink":
						err = os.Rename(path, path+".moved")
						if err == nil {
							err = os.Symlink(path+".moved", path)
						}
					case "permissions":
						err = os.Chmod(path, 0644)
					}
					if err != nil {
						return err
					}
					return original(parent, dir, name, file)
				}
				called := false
				err := WithFileLock(path, operation, func() error { called = true; return nil })
				if err == nil || called {
					t.Fatalf("tampered lock accepted: err=%v callback=%v", err, called)
				}
				if tamper == "rename" && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rename error=%v", err)
				}
				if _, err := ReadFile(path); err != nil {
					t.Fatalf("valid record lost: %v", err)
				}
			})
		}
	}
}
