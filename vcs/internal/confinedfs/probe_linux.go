//go:build linux

package confinedfs

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

var linuxOpenat2 = unix.Openat2

// platformProbe enforces the Linux kernel floor. RESOLVE_IN_ROOT gives
// chroot-like resolution for absolute links while NO_MAGICLINKS forbids procfs
// magic-link traversal. PortableFS operations themselves use os.Root's
// component-wise fd traversal because openat2 has no rename/link equivalent.
func platformProbe(backingRoot string) error {
	rootfd, err := unix.Open(backingRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open backing root for openat2 probe: %w", err)
	}
	defer unix.Close(rootfd)

	fd, err := linuxOpenat2(rootfd, ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
			return fmt.Errorf("%w: Linux openat2 with RESOLVE_IN_ROOT and RESOLVE_NO_MAGICLINKS is required: %v", ErrUnsupportedPlatform, err)
		}
		return fmt.Errorf("verify Linux openat2 confinement: %w", err)
	}
	return unix.Close(fd)
}
