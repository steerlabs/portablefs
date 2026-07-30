// Package mountlifecycle serializes PortableFS mount lifetimes against
// installation replacement.
//
// Mount startup, serving, and unmount hold a shared guard. An installer holds
// an exclusive guard while it rechecks for live mounts and replaces the app.
// Both modes are nonblocking: contention is a visible refusal, never an
// unbounded wait.
package mountlifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

// ErrBusy means a replacement or mount lifetime currently holds an
// incompatible guard.
var ErrBusy = errors.New("PortableFS mount lifecycle is busy")

// DefaultStateDir returns this user's canonical PortableFS state directory.
func DefaultStateDir() (string, error) {
	home, err := accountpath.Home()
	if err != nil {
		return "", fmt.Errorf("resolve home directory for mount lifecycle guard: %w", err)
	}
	return filepath.Join(home, ".local", "state", "portablefs"), nil
}

// Path returns the lifecycle lock path under the canonical fixed per-account
// PortableFS state directory.
func Path(stateDir string) string { return filepath.Join(stateDir, "mount-lifecycle.lock") }

// NamedPath returns a fixed coordination lock beneath the canonical state
// directory. The name must be a plain filename, never a caller-controlled
// path.
func NamedPath(stateDir, name string) (string, error) {
	if name == "" || filepath.Base(name) != name || name == "." {
		return "", fmt.Errorf("invalid user coordination lock name %q", name)
	}
	return filepath.Join(stateDir, name), nil
}

// Guard owns one flock until Close.
type Guard struct {
	mu   sync.Mutex
	file *os.File
	dir  *os.File
}

// AcquireShared acquires the guard used by mount startup, live mounts, and
// unmount. It refuses immediately when replacement owns the exclusive guard.
func AcquireShared(stateDir string) (*Guard, error) {
	return acquire(stateDir, "mount-lifecycle.lock", syscall.LOCK_SH|syscall.LOCK_NB)
}

// AcquireExclusive acquires the guard used by replacement. Once acquired,
// the caller must recheck the OS mount table and daemon attaches while still
// holding it; the guard closes the startup race but does not discover mounts
// that predate this protocol.
func AcquireExclusive(stateDir string) (*Guard, error) {
	return acquire(stateDir, "mount-lifecycle.lock", syscall.LOCK_EX|syscall.LOCK_NB)
}

// AcquireNamedShared/Exclusive support other fixed account-wide protocols
// that need the same hardened per-user inode guarantees without duplicating
// lock implementation.
func AcquireNamedShared(stateDir, name string) (*Guard, error) {
	return acquire(stateDir, name, syscall.LOCK_SH|syscall.LOCK_NB)
}

func AcquireNamedExclusive(stateDir, name string) (*Guard, error) {
	return acquire(stateDir, name, syscall.LOCK_EX|syscall.LOCK_NB)
}

func acquire(stateDir, name string, operation int) (*Guard, error) {
	path, err := NamedPath(stateDir, name)
	if err != nil {
		return nil, err
	}
	dir, err := privatepath.OpenDir(stateDir)
	if err != nil {
		return nil, err
	}
	file, err := privatepath.OpenLockFile(dir, stateDir, name)
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), operation); err != nil {
		_ = file.Close()
		_ = dir.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: %s", ErrBusy, path)
		}
		return nil, fmt.Errorf("lock mount lifecycle guard %s: %w", path, err)
	}
	// Revalidate after taking the lock. A replaced or unlinked lock file
	// would split coordination across two inodes, so it is a hard refusal.
	if err := privatepath.ValidateOpenFile(dir, stateDir, name, file); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		_ = dir.Close()
		return nil, err
	}
	return &Guard{file: file, dir: dir}, nil
}

func ensurePrivateStateDir(path string) error {
	return privatepath.EnsureDir(path)
}

// openLockFile creates the stable per-user coordination inode once, respecting
// neither the caller's umask nor symlinks. Existing files are never repaired:
// unexpected type, link count, mode, or replacement is treated as tampering.
func openLockFile(path string) (*os.File, error) {
	dirPath, name := filepath.Dir(path), filepath.Base(path)
	dir, err := privatepath.OpenDir(dirPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return privatepath.OpenLockFile(dir, dirPath, name)
}

// Close releases the guard. It is safe to call more than once.
func (g *Guard) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.file == nil {
		return nil
	}
	file := g.file
	g.file = nil
	dir := g.dir
	g.dir = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	var dirErr error
	if dir != nil {
		dirErr = dir.Close()
	}
	if unlockErr != nil {
		return fmt.Errorf("unlock mount lifecycle guard: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close mount lifecycle guard: %w", closeErr)
	}
	if dirErr != nil {
		return fmt.Errorf("close pinned mount lifecycle directory: %w", dirErr)
	}
	return nil
}
