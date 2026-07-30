// Package privatepath provides pinned, no-symlink access to per-user
// coordination and state paths.
package privatepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// EnsureDir creates path when absent and validates it through a component by
// component openat(O_NOFOLLOW) walk rooted at a pinned /. The final directory
// must be an exact uid-owned 0700 inode. Intermediate system/account
// directories may have broader modes, but no component may be a symlink.
func EnsureDir(path string) error {
	dir, err := OpenDir(path)
	if err != nil {
		return err
	}
	return dir.Close()
}

// OpenDir returns a pinned descriptor for one private directory, creating
// missing components with 0700 and syncing each parent publication.
func OpenDir(path string) (*os.File, error) {
	return openDir(path, true, true)
}

// OpenExistingDir returns a pinned descriptor without creating components.
func OpenExistingDir(path string) (*os.File, error) {
	return openDir(path, false, true)
}

// OpenOwnedDir returns a pinned descriptor for an account-owned, non-writable
// directory, creating missing components with 0700. It is the path boundary
// for mount targets: ancestors must be root/euid-owned and non-writable
// (except root-owned sticky temporary roots), while the final directory must
// be euid-owned and not group/world-writable.
func OpenOwnedDir(path string) (*os.File, error) {
	return openDir(path, true, false)
}

// OpenExistingOwnedDir is OpenOwnedDir without directory creation.
func OpenExistingOwnedDir(path string) (*os.File, error) {
	return openDir(path, false, false)
}

func ReadDir(path string) ([]os.DirEntry, error) {
	dir, err := OpenExistingDir(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.ReadDir(-1)
}

func openDir(path string, create, requirePrivateFinal bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, fmt.Errorf("private directory must be an absolute clean non-root path: %q", path)
	}
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("pin filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(rootFD), "/")
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, component := range components {
		fd, openErr := unix.Openat(
			int(current.Fd()), component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if errors.Is(openErr, unix.ENOENT) && create {
			if err := unix.Mkdirat(int(current.Fd()), component, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				_ = current.Close()
				return nil, fmt.Errorf("create private directory component %s in %s: %w", component, path, err)
			}
			if err := current.Sync(); err != nil {
				_ = current.Close()
				return nil, fmt.Errorf("sync private directory parent while creating %s: %w", path, err)
			}
			fd, openErr = unix.Openat(
				int(current.Fd()), component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
				0,
			)
		}
		if openErr != nil {
			_ = current.Close()
			if errors.Is(openErr, unix.ENOENT) {
				return nil, &os.PathError{Op: "open", Path: path, Err: openErr}
			}
			return nil, fmt.Errorf("open private directory component %s in %s without symlinks: %w", component, path, openErr)
		}
		next := os.NewFile(uintptr(fd), filepath.Join(current.Name(), component))
		var opened, named unix.Stat_t
		if err := unix.Fstat(fd, &opened); err != nil {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("inspect opened private directory %s: %w", path, err)
		}
		if err := unix.Fstatat(int(current.Fd()), component, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("private directory component %s changed during pinned traversal", component)
		}
		if opened.Uid != 0 && opened.Uid != uint32(os.Geteuid()) {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("private directory ancestor %s is owned by unrelated uid %d", next.Name(), opened.Uid)
		}
		if opened.Mode&0o022 != 0 {
			// Root-owned sticky temporary roots (/tmp and the corresponding
			// platform temp hierarchy) cannot have an entry replaced by
			// another uid and are the sole allowed writable ancestors.
			rootSticky := index != len(components)-1 &&
				opened.Uid == 0 && opened.Mode&unix.S_ISVTX != 0
			if !rootSticky {
				_ = next.Close()
				_ = current.Close()
				return nil, fmt.Errorf("private directory ancestor %s is group/world-writable without root sticky ownership", next.Name())
			}
		}
		_ = current.Close()
		current = next

		if index == len(components)-1 {
			if opened.Uid != uint32(os.Geteuid()) {
				_ = current.Close()
				return nil, fmt.Errorf("directory %s is not owned by uid %d", path, os.Geteuid())
			}
			if requirePrivateFinal && opened.Mode&0o777 != 0o700 {
				_ = current.Close()
				return nil, fmt.Errorf("private directory %s has permissions %04o, want 0700", path, opened.Mode&0o777)
			}
		}
	}
	return current, nil
}
