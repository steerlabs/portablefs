//go:build darwin

package portablefsd

import (
	"log"
	"strings"

	"golang.org/x/sys/unix"
)

// O_RESOLVE_BENEATH is present in the macOS 15+ SDK (required by FSKit) but
// is not yet exported by x/sys/unix. Keep the SDK value local to this
// Darwin-only file until x/sys exposes it.
const darwinResolveBeneath = 0x00001000

// refreshKernelFile updates one live kernel vnode to match the authoritative
// file state: ftruncate(2) pushes the fresh size (the daemon's setattr handler
// consumes the marked request, so the authority never sees it), and
// msync(MS_INVALIDATE) over a bounded sliding mapping drops the stale cached
// pages. Pages are never touched, so nothing faults in and a concurrent
// truncate cannot SIGBUS us.
//
// The file is opened relative to an already-open mount descriptor with both
// O_RESOLVE_BENEATH and O_NOFOLLOW_ANY. This is one atomic kernel resolution:
// an authority-controlled symlink, or a concurrent rename-to-symlink at any
// component, fails instead of escaping the mount and truncating a host file.
// The same descriptor is used for truncate and mmap so there is no second
// pathname race between the two operations.
func refreshKernelFile(mountPath, relativePath string, expectedItemID uint64, size int64) bool {
	fd, err := openKernelRefreshFile(mountPath, relativePath)
	if err != nil {
		return false // gone or renamed away: nothing to refresh
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		uint64(stat.Ino) != expectedItemID ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG {
		// The namespace changed between scheduling and opening. In
		// particular, do not let a regular-file rename swap redirect the
		// refresh to a different FSItem merely because it is not a symlink.
		return false
	}
	if err := unix.Ftruncate(fd, size); err != nil {
		return false
	}
	if size <= 0 {
		return true
	}
	const window = 256 << 20
	for off := int64(0); off < size; off += window {
		length := size - off
		if length > window {
			length = window
		}
		data, err := unix.Mmap(fd, off, int(length), unix.PROT_READ, unix.MAP_SHARED)
		if err != nil {
			return true
		}
		if err := unix.Msync(data, unix.MS_INVALIDATE); err != nil {
			// Loud: a silently broken purge reintroduces stale reads.
			log.Printf("portablefsd: msync(MS_INVALIDATE) %s: %v", relativePath, err)
			_ = unix.Munmap(data)
			return true
		}
		_ = unix.Munmap(data)
	}
	return true
}

func openKernelRefreshFile(mountPath, relativePath string) (int, error) {
	// Paths from fsproto are slash-separated and normalized, but keep this
	// syscall boundary fail-closed if a malformed path reaches it.
	if relativePath == "" ||
		strings.HasPrefix(relativePath, "/") ||
		strings.IndexByte(relativePath, 0) >= 0 {
		return -1, unix.EINVAL
	}
	for _, component := range strings.Split(relativePath, "/") {
		if component == "" || component == "." || component == ".." {
			return -1, unix.EINVAL
		}
	}

	rootFD, err := unix.Open(
		mountPath,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(rootFD) }()

	return unix.Openat(
		rootFD,
		relativePath,
		unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW_ANY|darwinResolveBeneath,
		0,
	)
}
