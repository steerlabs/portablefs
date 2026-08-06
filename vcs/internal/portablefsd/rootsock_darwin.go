//go:build darwin

package portablefsd

import (
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"golang.org/x/sys/unix"
)

// openVerifiedMountRoot opens the attach's kernel mount root and proves,
// through the descriptor itself, that what it opened is that exact mount: the
// filesystem's mount source must equal this attach's resource URL. Verifying
// the path before opening would race a remount; verifying the descriptor
// cannot.
func openVerifiedMountRoot(mountPath, attachRef string) (int, error) {
	fd, err := unix.Open(mountPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open mount root: %w", err)
	}
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("fstatfs mount root: %w", err)
	}
	source := cString(st.Mntfromname[:])
	if want := fskitidentity.ResourcePrefix + attachRef; source != want {
		unix.Close(fd)
		return -1, fmt.Errorf("mount source is %q, want %q", source, want)
	}
	return fd, nil
}

func closeMountRootFD(fd int)        { _ = unix.Close(fd) }
func mountRootRights(fd int) []byte  { return unix.UnixRights(fd) }

func cString(raw []byte) string {
	for i, b := range raw {
		if b == 0 {
			return string(raw[:i])
		}
	}
	return string(raw)
}
