//go:build linux

package hydrator

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Production confinement, matching cellhost's discipline
// (internal/cellhost/host_linux.go): every descendant descriptor is derived
// with openat2 from an already-open ancestor under
// RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV, plus
// RESOLVE_NO_SYMLINKS because the restorer resolves exactly one raw name
// component at a time into a tree it created itself and must never traverse a
// link. O_NOFOLLOW is kept alongside so the two mechanisms fail closed
// independently.
const (
	restoreResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
		unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS
	commonFlags = unix.O_CLOEXEC | unix.O_NOFOLLOW

	// utimeOmitNsec leaves a timestamp untouched. atime is not part of the
	// archive contract, so a restore never sets it.
	utimeOmitNsec = unix.UTIME_OMIT
)

func openNoFollow(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|commonFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return fileFromDescriptor(descriptor, path)
}

// openRootDirectory opens the volume tree's root read-write. It is the only
// path string the restorer resolves.
func openRootDirectory(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|commonFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return fileFromDescriptor(descriptor, path)
}

func openChildDirectory(dirFD int, name string) (*os.File, error) {
	descriptor, err := unix.Openat2(dirFD, name, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | commonFlags),
		Resolve: restoreResolve,
	})
	if err != nil {
		return nil, errnoContext("open directory", name, err)
	}
	return fileFromDescriptor(descriptor, name)
}

// createFile creates one regular file that must not already exist. The
// restorer proved the tree empty before it started, so an existing name is a
// duplicate the manifest promised could not happen, and O_EXCL turns that into
// a failure rather than an overwrite.
func createFile(dirFD int, name string) (*os.File, error) {
	descriptor, err := unix.Openat2(dirFD, name, &unix.OpenHow{
		Flags:   uint64(unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | commonFlags),
		Mode:    0o600,
		Resolve: restoreResolve,
	})
	if err != nil {
		return nil, errnoContext("create", name, err)
	}
	return fileFromDescriptor(descriptor, name)
}

func makeDirectory(dirFD int, name string) error {
	// Directories are created private and permissive to their owner so children
	// can be created inside them; the archived mode is applied on the way back
	// up, after the subtree exists.
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

// syncFS flushes the whole volume filesystem once. The restore writes a tree
// that is entirely reproducible from the sealed archive, so per-file fsync
// would buy nothing but time; the durability boundary is this one call plus the
// atomically written ready marker that follows it.
func syncFS(fd int) error { return unix.Syncfs(fd) }

// setTimes applies an exact nanosecond mtime to a child, without following a
// symlink, leaving atime untouched. ctime is deliberately not restored: Linux
// offers no honest way, and the format records it as metadata only.
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

// setTimesSelf applies an mtime to the directory a descriptor already names.
// "." resolves relative to the descriptor, so no path is reconstructed and the
// volume root — which has no parent inside the confinement — is reachable.
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

func statFD(fd int) (fileStat, error) { return statxAt(fd, "", unix.AT_EMPTY_PATH) }

func statChild(dirFD int, name string) (fileStat, error) {
	return statxAt(dirFD, name, unix.AT_SYMLINK_NOFOLLOW)
}

func statxAt(dirFD int, name string, flags int) (fileStat, error) {
	var raw unix.Statx_t
	if err := unix.Statx(dirFD, name, flags|unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS, &raw); err != nil {
		return fileStat{}, err
	}
	return fileStat{
		Ino:      raw.Ino,
		DevMajor: raw.Dev_major,
		DevMinor: raw.Dev_minor,
	}, nil
}

func fileFromDescriptor(descriptor int, name string) (*os.File, error) {
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("%w: descriptor for %q could not be adopted", ErrInvalid, name)
	}
	return file, nil
}

// identityFD and identityChild produce the restored-inode identity the
// authority's hydration map is keyed by.
//
// The packing is deliberately identical to xfsstore's StableIdentity
// (internal/xfsstore/volume_linux.go, stableIdentityFD and
// exactXFSHandleIdentity): the 12-byte XFS export handle, which includes the
// inode generation, preceded by its 4-byte handle type, both big-endian, in one
// 16-byte value. It is replicated here rather than imported because the
// hydrator is a separate process with a separate dependency surface, and this
// comment is the citation that keeps the two in step. A change to either must
// change both, or a restored volume's bindings would not match the identities
// the authority computes.
//
// The fallbacks below the exact case mirror xfsstore's non-production path so
// the restore suite runs on a development filesystem; on XFS, which is the only
// production filesystem, the exact case always applies.
func identityFD(fd int) ([16]byte, error) {
	handle, _, err := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		stat, statErr := statFD(fd)
		if statErr != nil {
			return [16]byte{}, statErr
		}
		return fallbackIdentity(stat), nil
	}
	return identityFromHandle(handle)
}

func identityChild(dirFD int, name string) ([16]byte, error) {
	handle, _, err := unix.NameToHandleAt(dirFD, name, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		stat, statErr := statChild(dirFD, name)
		if statErr != nil {
			return [16]byte{}, statErr
		}
		return fallbackIdentity(stat), nil
	}
	return identityFromHandle(handle)
}

func identityFromHandle(handle unix.FileHandle) ([16]byte, error) {
	var identity [16]byte
	raw := handle.Bytes()
	if len(raw) != 12 {
		return identity, fmt.Errorf("%w: export handle type=%d is %d bytes, not the 12 an XFS handle carries",
			ErrInvalid, handle.Type(), len(raw))
	}
	binary.BigEndian.PutUint32(identity[:4], uint32(handle.Type()))
	copy(identity[4:], raw)
	return identity, nil
}

// fallbackIdentity mirrors xfsstore's fallbackIdentityFromAttr: device major,
// device minor, inode number, all big-endian.
func fallbackIdentity(stat fileStat) [16]byte {
	var identity [16]byte
	binary.BigEndian.PutUint32(identity[0:4], stat.DevMajor)
	binary.BigEndian.PutUint32(identity[4:8], stat.DevMinor)
	binary.BigEndian.PutUint64(identity[8:16], stat.Ino)
	return identity
}
