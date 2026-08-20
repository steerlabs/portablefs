//go:build darwin

package archiver

import (
	"fmt"
	"os"

	"github.com/steerlabs/portablefs/vcs/archive"
	"golang.org/x/sys/unix"
)

// The development platform. It exists so the round-trip suite runs where the
// work is written; production is Linux and the command refuses to start
// anywhere else.
//
// The discipline is the same shape with a weaker kernel: every descendant
// descriptor is derived with openat from an already-open ancestor, one raw name
// component at a time, with O_NOFOLLOW so no symlink is ever traversed. What is
// missing relative to Linux is openat2's RESOLVE_BENEATH — but a single
// component that is validated to contain no separator and to be neither "." nor
// ".." cannot escape its parent, so the confinement argument holds by
// construction rather than by kernel enforcement.
const commonFlags = unix.O_CLOEXEC | unix.O_NOFOLLOW

func openNoFollow(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|commonFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return fileFromDescriptor(descriptor, path)
}

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
	descriptor, err := unix.Openat(dirFD, name, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
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
	var raw unix.Stat_t
	if err := unix.Fstat(fd, &raw); err != nil {
		return fileStat{}, err
	}
	return statFromRaw(raw), nil
}

func statChild(dirFD int, name string) (fileStat, error) {
	var raw unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &raw, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fileStat{}, err
	}
	return statFromRaw(raw), nil
}

func statFromRaw(raw unix.Stat_t) fileStat {
	return fileStat{
		Kind:       kindFromRawMode(uint32(raw.Mode)),
		Mode:       uint32(raw.Mode) & archive.ModeMask,
		Size:       raw.Size,
		MTimeNanos: raw.Mtim.Sec*1e9 + raw.Mtim.Nsec,
		CTimeNanos: raw.Ctim.Sec*1e9 + raw.Ctim.Nsec,
		Nlink:      uint32(raw.Nlink),
		Ino:        raw.Ino,
		Dev:        uint64(uint32(raw.Dev)),
	}
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

func readLinkChild(dirFD int, name string, size int64) ([]byte, error) {
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
	return err == unix.ENOTSUP || err == unix.EPERM || err == unix.ENOATTR
}

// scanExtents reports the whole file as allocated. Darwin's SEEK_HOLE support
// varies by filesystem and this platform is not the production one, so the
// portable answer is used: always correct, and only ever more expensive.
func scanExtents(file *os.File, size int64) ([]archive.Extent, error) {
	return archive.WholeFileExtents(file, size)
}
