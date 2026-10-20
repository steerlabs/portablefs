package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
)

// Offer a real writer a deterministic turn after open and before validation.
// An unlocked reader loses its exact inode; a protected reader excludes EX.
func readWithPublication(t *testing.T, path string, publish func() error, blocked *bool) ([]byte, error) {
	t.Helper()
	dir := filepath.Dir(path)
	parent, err := privatepath.OpenExistingDir(dir)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	writer, err := privatepath.OpenLockFile(parent, dir, filepath.Base(path)+".lock")
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	if err := unix.Flock(int(writer.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		return nil, err
	}
	if err := unix.Flock(int(writer.Fd()), unix.LOCK_UN); err != nil {
		return nil, err
	}
	err = unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		if err := unix.Flock(int(writer.Fd()), unix.LOCK_UN); err != nil {
			return nil, err
		}
		if err := publish(); err != nil {
			return nil, err
		}
	case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN):
		*blocked = true
	default:
		return nil, err
	}
	if err := privatepath.ValidateOpenFile(parent, dir, filepath.Base(path), file); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func TestIntentReadersExcludePublicationDuringRead(t *testing.T) {
	for _, inventory := range []bool{false, true} {
		for _, remove := range []bool{false, true} {
			name := map[bool]string{false: "lookup", true: "inventory"}[inventory] + "/" + map[bool]string{false: "replace", true: "remove"}[remove]
			t.Run(name, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "mounts")
				op, err := acquireMountOperation(dir, "/tmp/intent-race", "vol_intent", "fuse")
				if err != nil {
					t.Fatal(err)
				}
				defer op.close(false)
				read := func() (int, error) {
					if inventory {
						rows, err := listMountIntents(dir)
						return len(rows), err
					}
					row, err := readMountIntent(op.intentPath, op.mountPath)
					if row == nil {
						return 0, err
					}
					return 1, err
				}
				publish := func() error {
					if remove {
						return op.close(true)
					}
					return op.writeIntent("starting", 0, "")
				}
				original := mountIntentReadFile
				t.Cleanup(func() { mountIntentReadFile = original })
				blocked := false
				mountIntentReadFile = func(path string) ([]byte, error) { return readWithPublication(t, path, publish, &blocked) }
				if n, err := read(); err != nil || n != 1 || !blocked {
					t.Fatalf("read=%d err=%v writer blocked=%v", n, err, blocked)
				}
				mountIntentReadFile = original
				if err := publish(); err != nil {
					t.Fatal(err)
				}
				want := 1
				if remove {
					want = 0
				}
				if n, err := read(); err != nil || n != want {
					t.Fatalf("after publication read=%d err=%v", n, err)
				}
			})
		}
	}
}

func TestRouteReadersExcludePublicationDuringRead(t *testing.T) {
	for _, storage := range []bool{false, true} {
		for _, remove := range []bool{false, true} {
			name := map[bool]string{false: "volume", true: "storage"}[storage] + "/" + map[bool]string{false: "replace", true: "remove"}[remove]
			t.Run(name, func(t *testing.T) {
				mounts := filepath.Join(t.TempDir(), "mounts")
				rules, err := localroutes.Parse([]byte("node_modules/\n"))
				if err != nil {
					t.Fatal(err)
				}
				routes := mountRoutes{rules: rules, revision: rules.RevisionHex(), declared: true}
				write := func() error { return writeLocalRoutesRecord(mounts, "vol_race", routes, 2) }
				if err := write(); err != nil {
					t.Fatal(err)
				}
				path := localRoutesRecordPath(mounts, "vol_race")
				read := func() (*localRoutesRecord, error) {
					if storage {
						return readLocalRoutesRecordByStorage(mounts, localdirs.StorageID("vol_race"))
					}
					return readLocalRoutesRecord(mounts, "vol_race")
				}
				publish := write
				if remove {
					publish = func() error {
						return privatepath.WithFileLock(path, unix.LOCK_EX, func() error { return privatepath.RemoveFileDurable(path) })
					}
				}
				original := localRoutesReadFile
				t.Cleanup(func() { localRoutesReadFile = original })
				blocked := false
				localRoutesReadFile = func(path string) ([]byte, error) { return readWithPublication(t, path, publish, &blocked) }
				if rec, err := read(); err != nil || rec == nil || !blocked {
					t.Fatalf("record=%+v err=%v writer blocked=%v", rec, err, blocked)
				}
				localRoutesReadFile = original
				if err := publish(); err != nil {
					t.Fatal(err)
				}
				if rec, err := read(); err != nil || (rec == nil) != remove {
					t.Fatalf("after publication record=%+v err=%v", rec, err)
				}
			})
		}
	}
}

func TestMountStateLockRenameIsNotRecordAbsence(t *testing.T) {
	for name, read := range mountStateReaders() {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "mounts")
			st := validFuseMountState(t, "/tmp/lock-rename")
			if err := writeMountState(dir, st); err != nil {
				t.Fatal(err)
			}
			original := withMountStateLock
			t.Cleanup(func() { withMountStateLock = original })
			withMountStateLock = func(path string, operation int, fn func() error) error {
				return original(path, operation, func() error {
					// The real helper has acquired flock. Rename preserves nlink=1;
					// no-follow named-inode validation must still reject ENOENT.
					parent, err := privatepath.OpenExistingDir(filepath.Dir(path))
					if err != nil {
						return err
					}
					defer parent.Close()
					lock, err := privatepath.OpenLockFile(parent, filepath.Dir(path), filepath.Base(path)+".lock")
					if err != nil {
						return err
					}
					defer lock.Close()
					if err := os.Rename(path+".lock", path+".renamed"); err != nil {
						return err
					}
					return privatepath.ValidateOpenFile(parent, filepath.Dir(path), filepath.Base(path)+".lock", lock)
				})
			}
			if _, err := read(dir, st.MountPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("lock rename must propagate ENOENT: %v", err)
			}
			if _, err := privatepath.ReadFile(mountStatePath(dir, st.MountPath)); err != nil {
				t.Fatalf("record was damaged: %v", err)
			}
		})
	}
}

func TestLocalRoutesOfPropagatesReadErrors(t *testing.T) {
	for _, source := range []string{"mount", "route"} {
		t.Run(source, func(t *testing.T) {
			e, _, _ := testEnv(t)
			original := localRoutesReadFile
			originalMount := mountStateReadFile
			t.Cleanup(func() { localRoutesReadFile = original; mountStateReadFile = originalMount })
			dir, err := e.mountStateDir()
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("unsafe routing record")
			if source == "mount" {
				st := validFuseMountState(t, "/tmp/routing-errors")
				st.VolumeID = "vol_race"
				if err := writeMountState(dir, st); err != nil {
					t.Fatal(err)
				}
				mountStateReadFile = func(string) ([]byte, error) { return nil, sentinel }
			} else {
				if err := privatepath.EnsureDir(filepath.Dir(localRoutesRecordPath(dir, "vol_race"))); err != nil {
					t.Fatal(err)
				}
				localRoutesReadFile = func(string) ([]byte, error) { return nil, sentinel }
			}
			if _, err := e.localRoutesOf("vol_race"); !errors.Is(err, sentinel) {
				t.Fatalf("read error was hidden: %v", err)
			}
		})
	}
}

func TestMutableRecordReadersRejectUnsafeLocks(t *testing.T) {
	for _, reader := range []string{"intent-lookup", "intent-inventory", "route-volume", "route-storage"} {
		for _, tamper := range []string{"rename", "hardlink", "symlink", "permissions"} {
			t.Run(reader+"/"+tamper, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "mounts")
				var path string
				var read func() error
				if reader == "intent-lookup" || reader == "intent-inventory" {
					op, err := acquireMountOperation(dir, "/tmp/unsafe-intent", "vol_intent", "fuse")
					if err != nil {
						t.Fatal(err)
					}
					defer op.close(false)
					path = op.intentPath
					read = func() error {
						if reader == "intent-inventory" {
							_, err := listMountIntents(dir)
							return err
						}
						_, err := readMountIntent(path, op.mountPath)
						return err
					}
				} else {
					rules := localroutes.RuleSet{}
					if err := writeLocalRoutesRecord(dir, "vol_race", mountRoutes{rules: rules, revision: rules.RevisionHex()}, 1); err != nil {
						t.Fatal(err)
					}
					path = localRoutesRecordPath(dir, "vol_race")
					read = func() error {
						if reader == "route-storage" {
							_, err := readLocalRoutesRecordByStorage(dir, localdirs.StorageID("vol_race"))
							return err
						}
						_, err := readLocalRoutesRecord(dir, "vol_race")
						return err
					}
				}
				lock := path + ".lock"
				if err := privatepath.WriteFileAtomic(lock, []byte("")); err != nil {
					t.Fatal(err)
				}
				switch tamper {
				case "hardlink":
					if err := os.Link(lock, lock+".alias"); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Rename(lock, lock+".target"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(lock+".target", lock); err != nil {
						t.Fatal(err)
					}
				case "permissions":
					if err := os.Chmod(lock, 0644); err != nil {
						t.Fatal(err)
					}
				case "rename":
					// Reader's file seam runs after flock. Keep the record valid, then
					// return a named-lock validation error through the real read callback.
					originalIntent, originalRoutes := mountIntentReadFile, localRoutesReadFile
					t.Cleanup(func() { mountIntentReadFile = originalIntent; localRoutesReadFile = originalRoutes })
					seam := func(string) ([]byte, error) {
						parent, err := privatepath.OpenExistingDir(filepath.Dir(path))
						if err != nil {
							return nil, err
						}
						defer parent.Close()
						file, err := privatepath.OpenLockFile(parent, filepath.Dir(path), filepath.Base(lock))
						if err != nil {
							return nil, err
						}
						defer file.Close()
						if err := os.Rename(lock, lock+".moved"); err != nil {
							return nil, err
						}
						return nil, privatepath.ValidateOpenFile(parent, filepath.Dir(path), filepath.Base(lock), file)
					}
					mountIntentReadFile, localRoutesReadFile = seam, seam
				}
				if err := read(); err == nil {
					t.Fatal("unsafe lock accepted")
				}
				if _, err := privatepath.ReadFile(path); err != nil {
					t.Fatalf("valid record damaged: %v", err)
				}
			})
		}
	}
}
