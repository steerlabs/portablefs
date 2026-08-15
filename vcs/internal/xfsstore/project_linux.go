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
	fsIOCFSGetXattr = 0x801c581f
	// XFS_IOC_FSGEOMETRY_V1 is the stable 112-byte XFS geometry ABI. The
	// first two fields are the data-block size and realtime extent size in
	// data blocks, exactly the inputs to xfs_inode_alloc_unitsize.
	xfsIOCFsGeometryV1 = 0x80705864
	fsXFlagRealtime    = 0x00000001
	fsXFlagProjInherit = 0x00000200
)

type xfsFSGeometryV1 struct {
	BlockSize    uint32
	RTextSize    uint32
	AGBlocks     uint32
	AGCount      uint32
	LogBlocks    uint32
	SectSize     uint32
	InodeSize    uint32
	IMaxPct      uint32
	DataBlocks   uint64
	RTBlocks     uint64
	RTExtents    uint64
	LogStart     uint64
	UUID         [16]byte
	SUnit        uint32
	SWidth       uint32
	Version      int32
	Flags        uint32
	LogSectSize  uint32
	RTSectSize   uint32
	DirBlockSize uint32
}

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

// xfsFallocateAllocationUnit reproduces xfs_inode_alloc_unitsize for the
// collapse/insert alignment checks. Ordinary XFS files use one filesystem
// block; realtime files use one realtime extent. Guessing from statfs or from
// an extent-size hint would get realtime files wrong and could reorder EINVAL
// behind a caller RLIMIT failure, spuriously delivering SIGXFSZ.
func xfsFallocateAllocationUnit(fd int) (uint64, error) {
	attr, err := projectOf(fd)
	if err != nil {
		return 0, err
	}
	var geometry xfsFSGeometryV1
	if unsafe.Sizeof(geometry) != 112 {
		return 0, fmt.Errorf("unexpected XFS geometry ABI size %d", unsafe.Sizeof(geometry))
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), xfsIOCFsGeometryV1, uintptr(unsafe.Pointer(&geometry))); errno != 0 {
		return 0, fmt.Errorf("query XFS geometry: %w", errno)
	}
	if geometry.BlockSize == 0 {
		return 0, fmt.Errorf("invalid XFS block size 0")
	}
	unit := uint64(geometry.BlockSize)
	if attr.XFlags&fsXFlagRealtime != 0 {
		if geometry.RTextSize == 0 || unit > ^uint64(0)/uint64(geometry.RTextSize) {
			return 0, fmt.Errorf("invalid XFS realtime geometry block=%d extent=%d", geometry.BlockSize, geometry.RTextSize)
		}
		unit *= uint64(geometry.RTextSize)
	}
	return unit, nil
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
