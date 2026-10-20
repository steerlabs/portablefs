package portablefsd

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
)

func openRegistryForValidation(path string) (*os.File, *os.File, error) {
	parent, err := privatepath.OpenExistingDir(filepath.Dir(path))
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		parent.Close()
		return nil, nil, err
	}
	return parent, os.NewFile(uintptr(fd), path), nil
}

func TestAttachRegistryReadersExcludePublicationDuringRead(t *testing.T) {
	for _, external := range []bool{false, true} {
		for _, remove := range []bool{false, true} {
			name := map[bool]string{false: "startup", true: "external"}[external] + "/" + map[bool]string{false: "replace", true: "remove"}[remove]
			t.Run(name, func(t *testing.T) {
				dir := privateTestDir(t)
				writeFSKitDetachFixture(t, dir)
				entries, err := loadPersistedAttaches(dir)
				if err != nil {
					t.Fatal(err)
				}
				publish := func() error {
					if remove {
						return writePersistedAttaches(dir, nil)
					}
					return writePersistedAttaches(dir, entries)
				}
				original := attachRegistryReadFile
				t.Cleanup(func() { attachRegistryReadFile = original })
				blocked := false
				attachRegistryReadFile = func(path string) ([]byte, error) {
					parent, file, err := openRegistryForValidation(path)
					if err != nil {
						return nil, err
					}
					defer parent.Close()
					defer file.Close()
					lock, err := privatepath.OpenLockFile(parent, dir, filepath.Base(path)+".lock")
					if err != nil {
						return nil, err
					}
					defer lock.Close()
					if err := unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
						return nil, err
					}
					if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
						return nil, err
					}
					err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
					switch {
					case err == nil:
						if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
							return nil, err
						}
						if err := publish(); err != nil {
							return nil, err
						}
					case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN):
						blocked = true
					default:
						return nil, err
					}
					if err := privatepath.ValidateOpenFile(parent, dir, filepath.Base(path), file); err != nil {
						return nil, err
					}
					return io.ReadAll(file)
				}
				read := func() (int, error) {
					if external {
						rows, err := ReadPersistedAttachInventory(dir)
						return len(rows), err
					}
					rows, err := loadPersistedAttaches(dir)
					return len(rows), err
				}
				if n, err := read(); err != nil || n != 1 || !blocked {
					t.Fatalf("read=%d err=%v writer blocked=%v", n, err, blocked)
				}
				attachRegistryReadFile = original
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

func TestAttachRegistryPersistenceDoesNotHoldServingMutexes(t *testing.T) {
	dir := privateTestDir(t)
	writeFSKitDetachFixture(t, dir)
	r := newRegistry(dir)
	original := attachRegistryReadFile
	t.Cleanup(func() { attachRegistryReadFile = original })
	opened, release := make(chan struct{}), make(chan struct{})
	attachRegistryReadFile = func(path string) ([]byte, error) {
		parent, file, err := openRegistryForValidation(path)
		if err != nil {
			return nil, err
		}
		defer parent.Close()
		defer file.Close()
		close(opened)
		<-release
		if err := privatepath.ValidateOpenFile(parent, dir, filepath.Base(path), file); err != nil {
			return nil, err
		}
		return io.ReadAll(file)
	}
	readerDone := make(chan error, 1)
	go func() { _, err := ReadPersistedAttachInventory(dir); readerDone <- err }()
	<-opened
	// A nonblocking EX probe proves the reader owns SH before the real
	// daemon persistence starts. No scheduler delay is used as evidence.
	parent, err := privatepath.OpenExistingDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	lock, err := privatepath.OpenLockFile(parent, dir, filepath.Base(attachRegistryPath(dir))+".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	probeErr := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if probeErr == nil {
		unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	}
	reached := make(chan struct{})
	r.writeAttaches = func(dir string, entries []persistedAttachEntry) error {
		close(reached)
		return writePersistedAttaches(dir, entries)
	}
	writerDone := make(chan error, 1)
	go func() { writerDone <- r.persist() }()
	<-reached
	registryFree := r.mu.TryLock()
	if registryFree {
		r.mu.Unlock()
	}
	a := r.get(testFSKitAttachRef)
	attachFree := a.mu.TryLock()
	if attachFree {
		a.mu.Unlock()
	}
	// Release before assertions so a failing control cannot strand goroutines.
	close(release)
	readerErr, writerErr := <-readerDone, <-writerDone
	if !errors.Is(probeErr, unix.EWOULDBLOCK) && !errors.Is(probeErr, unix.EAGAIN) {
		t.Fatalf("reader did not exclude writer: %v", probeErr)
	}
	if !registryFree || !attachFree {
		t.Fatalf("serving mutex held: registry free=%v attach free=%v", registryFree, attachFree)
	}
	if readerErr != nil || writerErr != nil {
		t.Fatalf("reader=%v writer=%v", readerErr, writerErr)
	}
}

func TestAttachRegistryReadersRejectUnsafeLocks(t *testing.T) {
	for _, external := range []bool{false, true} {
		for _, tamper := range []string{"hardlink", "symlink", "permissions"} {
			t.Run(map[bool]string{false: "startup", true: "external"}[external]+"/"+tamper, func(t *testing.T) {
				dir := privateTestDir(t)
				writeFSKitDetachFixture(t, dir)
				path := attachRegistryPath(dir) + ".lock"
				if err := privatepath.WriteFileAtomic(path, nil); err != nil {
					t.Fatal(err)
				}
				var err error
				switch tamper {
				case "hardlink":
					err = os.Link(path, path+".alias")
				case "symlink":
					err = os.Rename(path, path+".target")
					if err == nil {
						err = os.Symlink(path+".target", path)
					}
				case "permissions":
					err = os.Chmod(path, 0644)
				}
				if err != nil {
					t.Fatal(err)
				}
				if external {
					_, err = ReadPersistedAttachInventory(dir)
				} else {
					_, err = loadPersistedAttaches(dir)
				}
				if err == nil {
					t.Fatal("unsafe registry lock accepted")
				}
				if _, err := privatepath.ReadFile(attachRegistryPath(dir)); err != nil {
					t.Fatalf("valid registry damaged: %v", err)
				}
			})
		}
	}
}
