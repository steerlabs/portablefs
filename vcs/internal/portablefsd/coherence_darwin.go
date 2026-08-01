//go:build darwin

package portablefsd

import (
	"errors"
	"fmt"
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
//
// armTruncate opens the daemon's provenance window and returns its closer. It
// is called ONCE, immediately before the ftruncate, and only when an ftruncate
// is actually issued: the window's claim is "this process is inside the
// syscall that produced the upcall you are classifying", and a refresh that
// finds the vnode size already correct makes no such syscall.
//
// armTruncate may REFUSE. The window is opened atomically with the daemon
// installing the sampled size as its composed view, so an arm that can no
// longer prove the sample current has nothing truthful to install and nothing
// truthful to claim. Its refusal must abort the ftruncate rather than let it
// proceed unwindowed: an unwindowed refresh upcall is indistinguishable from an
// application truncate and would be forwarded to the authority — the one
// outcome that destroys data.
func refreshKernelFile(
	mountPath, relativePath string,
	expectedItemID uint64,
	size int64,
	armTruncate func() (func(), error),
) (kernelRefreshOutcome, error) {
	fd, err := openKernelRefreshFile(mountPath, relativePath)
	if err != nil {
		if errors.Is(err, unix.ENOENT) ||
			errors.Is(err, unix.ENOTDIR) ||
			errors.Is(err, unix.ELOOP) {
			return kernelRefreshObsolete, err
		}
		return kernelRefreshRetry, err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return kernelRefreshRetry, err
	}
	if uint64(stat.Ino) != expectedItemID ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG {
		// The namespace changed between scheduling and opening. In
		// particular, do not let a regular-file rename swap redirect the
		// refresh to a different FSItem merely because it is not a symlink.
		return kernelRefreshObsolete, fmt.Errorf(
			"resolved inode/type changed: inode=%d mode=%#o",
			stat.Ino, stat.Mode&unix.S_IFMT,
		)
	}
	if stat.Size != size {
		if err := truncateWithProvenance(fd, size, armTruncate); err != nil {
			return kernelRefreshRetry, err
		}
	}
	if size <= 0 {
		return kernelRefreshApplied, nil
	}
	const window = 256 << 20
	for off := int64(0); off < size; off += window {
		length := size - off
		if length > window {
			length = window
		}
		data, err := unix.Mmap(fd, off, int(length), unix.PROT_READ, unix.MAP_SHARED)
		if err != nil {
			return kernelRefreshRetry, err
		}
		if err := unix.Msync(data, unix.MS_INVALIDATE); err != nil {
			// Loud: a silently broken purge reintroduces stale reads.
			log.Printf("portablefsd: msync(MS_INVALIDATE) %s: %v", relativePath, err)
			_ = unix.Munmap(data)
			return kernelRefreshRetry, err
		}
		_ = unix.Munmap(data)
	}
	return kernelRefreshApplied, nil
}

// truncateWithProvenance holds the provenance window open for EXACTLY the
// extent of the ftruncate(2) that produces the upcall it identifies. The
// disarm runs before the error is inspected: the syscall has returned, so its
// premise ("this process has not left the call") no longer holds either way.
func truncateWithProvenance(fd int, size int64, armTruncate func() (func(), error)) error {
	if armTruncate != nil {
		disarm, err := armTruncate()
		if err != nil {
			// No window, no syscall. The refusal is a retry outcome, never a
			// licence to truncate the kernel's view on a sample the daemon can
			// no longer vouch for.
			return err
		}
		defer disarm()
	}
	return unix.Ftruncate(fd, size)
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
