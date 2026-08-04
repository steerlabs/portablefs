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

func verifyProjectRoot(fd int, expected uint32) error {
	var attr fsxattr
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), fsIOCFSGetXattr, uintptr(unsafe.Pointer(&attr)))
	if errno != 0 {
		return fmt.Errorf("query XFS project root: %w", errno)
	}
	if expected == 0 || attr.ProjectID != expected || attr.XFlags&fsXFlagProjInherit == 0 {
		return fmt.Errorf("%w: got project=%d inherit=%t, want project=%d inherit=true",
			ErrProjectIsolation, attr.ProjectID, attr.XFlags&fsXFlagProjInherit != 0, expected)
	}
	return nil
}
