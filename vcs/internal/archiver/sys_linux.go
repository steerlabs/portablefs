//go:build linux

package archiver

import (
	"fmt"
	"os"

	"github.com/steerlabs/portablefs/vcs/archive"
	"golang.org/x/sys/unix"
)

// The production confinement discipline, matching cellhost's
// (internal/cellhost/host_linux.go): every descendant descriptor is derived
// with openat2 from an already-open ancestor under
// RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV, and additionally
// RESOLVE_NO_SYMLINKS because the archiver resolves exactly one raw name
// component at a time and must never traverse a link. O_NOFOLLOW is kept as
// well: the two mechanisms fail closed independently.
const (
	walkResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
		unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS
	commonFlags = unix.O_CLOEXEC | unix.O_NOFOLLOW
)

// openNoFollow opens one absolute, root-provisioned file without following a
// symlink at its final component.
func openNoFollow(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|commonFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return fileFromDescriptor(descriptor, path)
}

// openRootDirectory opens the volume tree's root. It is the only path string
// this package resolves; everything inside the tree is descriptor-relative from
// the descriptor it returns.
func openRootDirectory(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|commonFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return fileFromDescriptor(descriptor, path)
}

func openChildDirectory(dirFD int, name string) (*os.File, error) {
	return openChild(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|commonFlags)
}

func openChildFile(dirFD int, name string) (*os.File, error) {
	return openChild(dirFD, name, unix.O_RDONLY|commonFlags)
}

func openChild(dirFD int, name string, flags int) (*os.File, error) {
	descriptor, err := unix.Openat2(dirFD, name, &unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: walkResolve,
	})
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: name, Err: err}
	}
	return fileFromDescriptor(descriptor, name)
}

func fileFromDescriptor(descriptor int, name string) (*os.File, error) {
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("%w: descriptor for %q could not be adopted", ErrInvalid, name)
	}
	return file, nil
}

func statFD(fd int) (fileStat, error) {
	return statxAt(fd, "", unix.AT_EMPTY_PATH)
}

func statChild(dirFD int, name string) (fileStat, error) {
	return statxAt(dirFD, name, unix.AT_SYMLINK_NOFOLLOW)
}

// statxAt reads the nanosecond timestamps the format preserves. statx is used
// rather than fstatat because the archive contract is exact ns-mtime, and
// because it reports the device as a (major, minor) pair without the encoding
// guesswork of st_dev.
func statxAt(dirFD int, name string, flags int) (fileStat, error) {
	var raw unix.Statx_t
	if err := unix.Statx(dirFD, name, flags|unix.AT_NO_AUTOMOUNT,
		unix.STATX_BASIC_STATS, &raw); err != nil {
		return fileStat{}, err
	}
	return fileStat{
		Kind:       kindFromRawMode(uint32(raw.Mode)),
		Mode:       uint32(raw.Mode) & archive.ModeMask,
		Size:       int64(raw.Size),
		MTimeNanos: raw.Mtime.Sec*1e9 + int64(raw.Mtime.Nsec),
		CTimeNanos: raw.Ctime.Sec*1e9 + int64(raw.Ctime.Nsec),
		Nlink:      raw.Nlink,
		Ino:        raw.Ino,
		Dev:        uint64(raw.Dev_major)<<32 | uint64(raw.Dev_minor),
	}, nil
}

func kindFromRawMode(mode uint32) inodeKind {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return kindRegular
	case unix.S_IFDIR:
		return kindDirectory
	case unix.S_IFLNK:
		return kindSymlink
	default:
		return kindOther
	}
}

// readLinkChild reads a symlink target as raw bytes. A target is not required
// to be UTF-8 and is never interpreted here; it is carried verbatim.
func readLinkChild(dirFD int, name string, size int64) ([]byte, error) {
	// The size from stat is a hint; the buffer is one byte larger so a target
	// that grew between stat and read is detected as truncation rather than
	// silently shortened.
	length := size + 1
	if length < 64 {
		length = 64
	}
	if length > archive.MaxLinkNameBytes+1 {
		length = archive.MaxLinkNameBytes + 1
	}
	buffer := make([]byte, length)
	n, err := unix.Readlinkat(dirFD, name, buffer)
	if err != nil {
		return nil, err
	}
	if n >= len(buffer) {
		return nil, fmt.Errorf("%w: symlink target exceeds %d bytes", ErrInvalid, archive.MaxLinkNameBytes)
	}
	return append([]byte(nil), buffer[:n]...), nil
}

func listXattrNames(fd int, buffer []byte) (int, error) { return unix.Flistxattr(fd, buffer) }

func getXattrValue(fd int, name string, buffer []byte) (int, error) {
	return unix.Fgetxattr(fd, name, buffer)
}

func xattrUnsupported(err error) bool {
	return err == unix.ENOTSUP || err == unix.EOPNOTSUPP || err == unix.ENODATA || err == unix.EPERM
}

// scanExtents is the export-side sparseness scanner. On Linux it is the format
// library's SEEK_DATA/SEEK_HOLE walk, so the manifest's extent maps are the
// filesystem's own answer.
func scanExtents(file *os.File, size int64) ([]archive.Extent, error) {
	extents, err := archive.ScanFileExtents(file, size)
	if err == nil {
		return extents, nil
	}
	if err == archive.ErrExtentScanUnsupported {
		// A filesystem without hole awareness is stored as fully allocated.
		// That direction costs storage and never correctness; the opposite
		// direction — believing a claimed hole — is what must never happen.
		return archive.WholeFileExtents(file, size)
	}
	return nil, err
}
