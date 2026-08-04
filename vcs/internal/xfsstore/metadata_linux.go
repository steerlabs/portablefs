//go:build linux

package xfsstore

import (
	"bytes"
	"errors"
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

func (v *Volume) withDataFD(id Capability, write bool, fn func(int) error) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	obj, err := v.objectLocked(id)
	if err != nil {
		return err
	}
	if obj.kind == KindSymlink {
		return syscall.EOPNOTSUPP
	}
	flags := unix.O_RDONLY
	if write && obj.kind == KindRegular {
		flags = unix.O_RDWR
	}
	if obj.kind == KindDirectory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := reopen(obj.fd, flags)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return fn(fd)
}

func (v *Volume) Chmod(id Capability, mode fs.FileMode) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	obj, err := v.objectLocked(id)
	if err != nil {
		return err
	}
	if obj.kind == KindSymlink {
		return syscall.EOPNOTSUPP
	}
	return unix.Fchmodat(obj.fd, "", modeToUnix(mode), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

// Chown uses -1 to leave one side unchanged, matching fchownat.
func (v *Volume) Chown(id Capability, uid, gid int) error {
	if uid >= 0 && uint32(uid) != v.ownerUID || gid >= 0 && uint32(gid) != v.ownerGID {
		return syscall.EPERM
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	obj, err := v.objectLocked(id)
	if err != nil {
		return err
	}
	return unix.Fchownat(obj.fd, "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

func (v *Volume) SetTimes(id Capability, atimeNS, mtimeNS *int64, atimeNow, mtimeNow bool) error {
	if atimeNS == nil && mtimeNS == nil && !atimeNow && !mtimeNow {
		return fs.ErrInvalid
	}
	if atimeNS != nil && atimeNow || mtimeNS != nil && mtimeNow {
		return fs.ErrInvalid
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	obj, err := v.objectLocked(id)
	if err != nil {
		return err
	}
	times := []unix.Timespec{{Nsec: unix.UTIME_OMIT}, {Nsec: unix.UTIME_OMIT}}
	if atimeNow {
		times[0].Nsec = unix.UTIME_NOW
	} else if atimeNS != nil {
		times[0] = unix.NsecToTimespec(*atimeNS)
	}
	if mtimeNow {
		times[1].Nsec = unix.UTIME_NOW
	} else if mtimeNS != nil {
		times[1] = unix.NsecToTimespec(*mtimeNS)
	}
	return unix.UtimesNanoAt(obj.fd, "", times, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

func (v *Volume) TruncateObject(id Capability, size int64) error {
	if size < 0 {
		return fs.ErrInvalid
	}
	return v.withDataFD(id, true, func(fd int) error { return unix.Ftruncate(fd, size) })
}

func (v *Volume) GetXattr(id Capability, name string) ([]byte, error) {
	if err := ValidateXattr(name); err != nil {
		return nil, err
	}
	var value []byte
	err := v.withDataFD(id, false, func(fd int) error {
		var err error
		value, err = getXattrValue(fd, name)
		return err
	})
	return value, err
}

func getXattrValue(fd int, name string) ([]byte, error) {
	// getxattr's size probe and read are not atomic with replacement. Never use
	// the returned count until the syscall succeeds: Linux returns -1 on ERANGE,
	// which would otherwise become a negative slice bound and panic the worker.
	for range 8 {
		size, err := unix.Fgetxattr(fd, name, nil)
		if err != nil {
			return nil, err
		}
		value := make([]byte, size)
		n, err := unix.Fgetxattr(fd, name, value)
		if errors.Is(err, syscall.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n < 0 || n > len(value) {
			return nil, syscall.EIO
		}
		return value[:n], nil
	}
	return nil, syscall.EAGAIN
}

func (v *Volume) SetXattr(id Capability, name string, value []byte, mode XattrMode) error {
	_ = id
	_ = name
	_ = value
	_ = mode
	// XFS explicitly excludes extended attributes from project-quota usage.
	// Per-inode limits therefore cannot protect a shared cell: a tenant can
	// multiply them by its inode entitlement and consume uncharged cell space.
	// Portable user-xattr writes stay disabled until the storage substrate can
	// enforce one durable aggregate quota without a second metadata truth.
	return syscall.EOPNOTSUPP
}

func (v *Volume) RemoveXattr(id Capability, name string) error {
	if err := ValidateXattr(name); err != nil {
		return err
	}
	return v.withDataFD(id, true, func(fd int) error { return unix.Fremovexattr(fd, name) })
}

func (v *Volume) ListXattr(id Capability) ([]string, error) {
	var names []string
	err := v.withDataFD(id, false, func(fd int) error {
		size, err := unix.Flistxattr(fd, nil)
		if err != nil {
			return err
		}
		buf := make([]byte, size)
		n, err := unix.Flistxattr(fd, buf)
		if err != nil {
			return err
		}
		for _, raw := range bytes.Split(buf[:n], []byte{0}) {
			if len(raw) == 0 {
				continue
			}
			name := string(raw)
			if ValidateXattr(name) == nil {
				names = append(names, name)
			}
		}
		return nil
	})
	return names, err
}

func (v *Volume) StatFS() (FSStat, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return FSStat{}, ErrClosed
	}
	if v.fenced != nil {
		return FSStat{}, v.fenced
	}
	var stat unix.Statfs_t
	if err := unix.Fstatfs(v.rootFD, &stat); err != nil {
		return FSStat{}, err
	}
	// Project quota accounting is intentionally not queried here. Linux protects
	// project-quota records with CAP_SYS_ADMIN, while the data-plane process must
	// remain unprivileged. XFS still enforces the provisioned hard limits and
	// returns EDQUOT; statfs has the same cell-wide meaning it has for an ordinary
	// local directory on that XFS mount. Privileged provisioning and monitoring
	// attest the per-project limits outside the request process.
	return FSStat{
		BlockSize:       uint64(stat.Bsize),
		Blocks:          stat.Blocks,
		BlocksFree:      stat.Bfree,
		BlocksAvailable: stat.Bavail,
		Files:           stat.Files,
		FilesFree:       stat.Ffree,
		NameMax:         uint32(nameMax),
	}, nil
}
