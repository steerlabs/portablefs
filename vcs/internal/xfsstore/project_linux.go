//go:build linux

package xfsstore

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fsxattr and FS_IOC_FSGETXATTR are Linux's stable UAPI from <linux/fs.h>.
// Keeping the exact ABI here avoids invoking xfs_io in the request-serving
// process. Quota creation remains a separate privileged provisioning step.
type fsxattr struct {
	XFlags     uint32
	ExtSize    uint32
	Nextents   uint32
	ProjectID  uint32
	CowExtSize uint32
	Pad        [8]byte
}

const (
	fsIOCFSGetXattr    = 0x801c581f
	fsXFlagProjInherit = 0x00000200
)

// projectOf reads an inode's XFS project identity. It requires a descriptor
// opened for access: ioctl(2) rejects an O_PATH descriptor with EBADF, and
// there is no path-based or statx-based way to read a project ID without
// CAP_SYS_ADMIN. Every caller therefore holds a descriptor that was opened
// with real access rights, which is exactly the set of descriptors through
// which this volume can charge blocks or inodes to a project.
func projectOf(fd int) (fsxattr, error) {
	var attr fsxattr
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), fsIOCFSGetXattr, uintptr(unsafe.Pointer(&attr))); errno != 0 {
		return fsxattr{}, fmt.Errorf("query XFS project: %w", errno)
	}
	return attr, nil
}

// verifyProject fails closed when an inode is not accounted to this volume's
// project. requireInherit additionally demands XFS_DIFLAG_PROJINHERIT, which
// only directories carry and which is what makes every inode created beneath
// them inherit the project.
func verifyProject(fd int, expected uint32, requireInherit bool) error {
	if expected == 0 {
		return fmt.Errorf("%w: project ID must be nonzero", ErrProjectIsolation)
	}
	attr, err := projectOf(fd)
	if err != nil {
		return err
	}
	inherits := attr.XFlags&fsXFlagProjInherit != 0
	if attr.ProjectID != expected || requireInherit && !inherits {
		return fmt.Errorf("%w: got project=%d inherit=%t, want project=%d inherit=%t",
			ErrProjectIsolation, attr.ProjectID, inherits, expected, requireInherit)
	}
	return nil
}
