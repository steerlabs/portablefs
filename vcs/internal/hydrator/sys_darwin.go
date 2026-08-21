//go:build darwin

package hydrator

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// The development platform, so the restore and serve suites run where the work
// is written. Production is Linux and the command refuses to start anywhere
// else.
//
// The discipline is the same shape with a weaker kernel: descendant descriptors
// come from openat on an already-open ancestor, one validated raw name
// component at a time, with O_NOFOLLOW. A single component that is neither "."
// nor ".." and contains no separator cannot escape its parent, which is what
// openat2's RESOLVE_BENEATH enforces on Linux.
const commonFlags = unix.O_CLOEXEC | unix.O_NOFOLLOW

// utimeOmitNsec is macOS's UTIME_OMIT, which golang.org/x/sys does not export
// for this platform. It has the same meaning as Linux's: leave that timestamp
// untouched.
const utimeOmitNsec = -2

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
	descriptor, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|commonFlags, 0)
	if err != nil {
		return nil, errnoContext("open directory", name, err)
	}
	return fileFromDescriptor(descriptor, name)
}

func createFile(dirFD int, name string) (*os.File, error) {
	descriptor, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|commonFlags, 0o600)
	if err != nil {
		return nil, errnoContext("create", name, err)
	}
	return fileFromDescriptor(descriptor, name)
}

func makeDirectory(dirFD int, name string) error {
	if err := unix.Mkdirat(dirFD, name, 0o700); err != nil {
		return errnoContext("mkdir", name, err)
	}
	return nil
}

func symlinkAt(target string, dirFD int, name string) error {
	if err := unix.Symlinkat(target, dirFD, name); err != nil {
		return errnoContext("symlink", name, err)
	}
	return nil
}

func linkAt(oldDirFD int, oldName string, newDirFD int, newName string) error {
	if err := unix.Linkat(oldDirFD, oldName, newDirFD, newName, 0); err != nil {
		return errnoContext("link", newName, err)
	}
	return nil
}

func setXattr(fd int, name string, value []byte) error {
	if err := unix.Fsetxattr(fd, name, value, 0); err != nil {
		return errnoContext("set attribute", name, err)
	}
	return nil
}

func chmodFD(fd int, mode uint32) error { return unix.Fchmod(fd, mode) }

func truncateFD(fd int, size int64) error { return unix.Ftruncate(fd, size) }

func fsyncFD(fd int) error { return unix.Fsync(fd) }

// syncFS has no darwin equivalent that covers a whole filesystem from a
// descriptor; fsync of the root directory is the closest honest approximation
// on the development platform.
func syncFS(fd int) error { return unix.Fsync(fd) }

func setTimes(dirFD int, name string, mtimeNanos int64) error {
	times := []unix.Timespec{
		{Sec: 0, Nsec: utimeOmitNsec},
		unix.NsecToTimespec(mtimeNanos),
	}
	if err := unix.UtimesNanoAt(dirFD, name, times, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return errnoContext("set times", name, err)
	}
	return nil
}

func setTimesSelf(dirFD int, mtimeNanos int64) error {
	times := []unix.Timespec{
		{Sec: 0, Nsec: utimeOmitNsec},
		unix.NsecToTimespec(mtimeNanos),
	}
	if err := unix.UtimesNanoAt(dirFD, ".", times, 0); err != nil {
		return errnoContext("set times", ".", err)
	}
	return nil
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
	device := uint64(uint32(raw.Dev))
	return fileStat{
		Ino:      raw.Ino,
		DevMajor: unix.Major(device),
		DevMinor: unix.Minor(device),
	}
}

func fileFromDescriptor(descriptor int, name string) (*os.File, error) {
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("%w: descriptor for %q could not be adopted", ErrInvalid, name)
	}
	return file, nil
}

// identityFD and identityChild produce the restored-inode identity. Darwin has
// no name_to_handle_at, so the development platform always takes the fallback
// packing xfsstore uses off XFS: device major, device minor, inode number, all
// big-endian (internal/xfsstore/volume_linux.go, fallbackIdentityFromAttr).
func identityFD(fd int) ([16]byte, error) {
	stat, err := statFD(fd)
	if err != nil {
		return [16]byte{}, err
	}
	return fallbackIdentity(stat), nil
}

func identityChild(dirFD int, name string) ([16]byte, error) {
	stat, err := statChild(dirFD, name)
	if err != nil {
		return [16]byte{}, err
	}
	return fallbackIdentity(stat), nil
}

func fallbackIdentity(stat fileStat) [16]byte {
	var identity [16]byte
	binary.BigEndian.PutUint32(identity[0:4], stat.DevMajor)
	binary.BigEndian.PutUint32(identity[4:8], stat.DevMinor)
	binary.BigEndian.PutUint64(identity[8:16], stat.Ino)
	return identity
}
