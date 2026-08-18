//go:build linux

package xfsstore

import (
	"bytes"
	"errors"
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

// XATTR_SIZE_MAX and XATTR_LIST_MAX from <uapi/linux/limits.h>. The VFS
// enforces both on every filesystem in vfs_setxattr and when assembling a
// listing, so a buffer of this size cannot come back short.
const (
	xattrSizeMax = 65536
	xattrListMax = 65536
)

func (v *Volume) withDataFD(id Capability, write bool, fn func(int) error) error {
	obj, err := v.holdObject(id)
	if err != nil {
		return err
	}
	defer obj.release()
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
	fd, err := v.reopen(obj.fd(), flags, obj.kind)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return fn(fd)
}

func (v *Volume) Chmod(id Capability, mode fs.FileMode) error {
	unixMode, err := modeToUnix(mode)
	if err != nil {
		return err
	}
	obj, err := v.holdObject(id)
	if err != nil {
		return err
	}
	defer obj.release()
	if obj.kind == KindSymlink {
		return syscall.EOPNOTSUPP
	}
	return v.chmodCapability(obj.fd(), obj.kind, unixMode)
}

// chmodCapability applies a mode to an O_PATH capability descriptor.
//
// Fchmodat with AT_EMPTY_PATH is the natural spelling, but Go routes any
// nonzero flags to fchmodat2(2), which only exists on Linux 6.6+ — on an older
// authority host every chmod would fail mid-mutation with ENOSYS and fence the
// epoch. Reopening and fchmod(2) is no substitute: a mode-0 object cannot be
// reopened by the unprivileged service identity, and restoring such a mode is
// exactly what Chmod must be able to do. chmod(2) through the /proc magic link
// is glibc's own pre-fchmodat2 fallback: it needs no open permission, and the
// held O_PATH descriptor pins the inode the link resolves to.
func (v *Volume) chmodCapability(fd int, _ Kind, unixMode uint32) error {
	return unix.Chmod(procFDPath(fd), unixMode)
}

// Chown uses -1 to leave one side unchanged, matching fchownat. The owner
// identity it compares against is written once, before the volume is
// published, and never afterwards.
func (v *Volume) Chown(id Capability, uid, gid int) error {
	if uid >= 0 && uint32(uid) != v.ownerUID || gid >= 0 && uint32(gid) != v.ownerGID {
		return syscall.EPERM
	}
	obj, err := v.holdObject(id)
	if err != nil {
		return err
	}
	defer obj.release()
	return unix.Fchownat(obj.fd(), "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

// SetTimes addresses the inode through the descriptor itself. x/sys passes a
// pointer to an empty string rather than NULL, so this is the AT_EMPTY_PATH
// form of utimensat(2) rather than the NULL-pathname form; utimensat(2)
// documents only "0 or AT_SYMLINK_NOFOLLOW", but the kernel accepts and
// implements AT_EMPTY_PATH here (verified on Linux 6.8 against XFS, for both
// a regular file and a symlink held by an O_PATH descriptor, including that
// the requested timestamps land). The same call without AT_EMPTY_PATH returns
// ENOENT, so this is not an optional flag that could be dropped.
func (v *Volume) SetTimes(id Capability, atimeNS, mtimeNS *int64, atimeNow, mtimeNow bool) error {
	if atimeNS == nil && mtimeNS == nil && !atimeNow && !mtimeNow {
		return fs.ErrInvalid
	}
	if atimeNS != nil && atimeNow || mtimeNS != nil && mtimeNow {
		return fs.ErrInvalid
	}
	obj, err := v.holdObject(id)
	if err != nil {
		return err
	}
	defer obj.release()
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
	return unix.UtimesNanoAt(obj.fd(), "", times, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

func (v *Volume) TruncateObject(id Capability, size int64) error {
	if size < 0 {
		return fs.ErrInvalid
	}
	obj, err := v.holdObject(id)
	if err != nil {
		return err
	}
	defer obj.release()
	if obj.kind == KindSymlink {
		return syscall.EOPNOTSUPP
	}
	flags := unix.O_RDONLY
	if obj.kind == KindRegular {
		flags = unix.O_RDWR
	}
	if obj.kind == KindDirectory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := v.reopen(obj.fd(), flags, obj.kind)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	mutation := v.inodeMutationLock(obj.coordinate.Stable)
	mutation.Lock()
	defer mutation.Unlock()
	return unix.Ftruncate(fd, size)
}

// SetAttr executes every requested syscall and takes the final stat while its
// authority handler retains the stable-identity writer stripe. Keeping the
// compound operation here prevents an intermediate snapshot and closes the
// historical gap where only truncate participated in mutation sequencing.
func (v *Volume) SetAttr(itemID, handleID Capability, spec SetAttrSpec) (Attr, error) {
	if itemID == (Capability{}) && handleID == (Capability{}) {
		return Attr{}, fs.ErrInvalid
	}
	var obj object
	var opened *openFile
	var err error
	if itemID != (Capability{}) {
		obj, err = v.holdObject(itemID)
		if err != nil {
			return Attr{}, err
		}
		defer obj.release()
	}
	if handleID != (Capability{}) {
		opened, err = v.holdOpen(handleID)
		if err != nil {
			return Attr{}, err
		}
		defer opened.release()
	}
	coordinate := obj.coordinate
	if itemID == (Capability{}) {
		coordinate = opened.coordinate
	} else if handleID != (Capability{}) && coordinate.Stable != opened.coordinate.Stable {
		return Attr{}, fs.ErrInvalid
	}
	changed := false
	apply := func(operation func() error) error {
		if err := operation(); err != nil {
			if changed {
				return outcomeUncertain(err)
			}
			return err
		}
		changed = true
		return nil
	}
	if spec.Mode != nil {
		unixMode, modeErr := modeToUnix(*spec.Mode)
		if modeErr != nil {
			return Attr{}, modeErr
		}
		if itemID == (Capability{}) || obj.kind == KindSymlink {
			return Attr{}, syscall.EOPNOTSUPP
		}
		if err := apply(func() error { return v.chmodCapability(obj.fd(), obj.kind, unixMode) }); err != nil {
			return v.setAttrPost(obj, opened, itemID, err)
		}
	}
	if spec.UID != nil || spec.GID != nil {
		uid, gid := -1, -1
		if spec.UID != nil {
			if *spec.UID != v.ownerUID {
				return Attr{}, syscall.EPERM
			}
			uid = int(*spec.UID)
		}
		if spec.GID != nil {
			if *spec.GID != v.ownerGID {
				return Attr{}, syscall.EPERM
			}
			gid = int(*spec.GID)
		}
		if itemID == (Capability{}) {
			return Attr{}, fs.ErrInvalid
		}
		if err := apply(func() error {
			return unix.Fchownat(obj.fd(), "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
		}); err != nil {
			return v.setAttrPost(obj, opened, itemID, err)
		}
	}
	if spec.Size != nil {
		if *spec.Size < 0 {
			return Attr{}, fs.ErrInvalid
		}
		if handleID != (Capability{}) {
			if !opened.write {
				return Attr{}, fs.ErrInvalid
			}
			if err := apply(func() error { return unix.Ftruncate(opened.fd(), *spec.Size) }); err != nil {
				return v.setAttrPost(obj, opened, itemID, err)
			}
		} else {
			if obj.kind == KindSymlink {
				return Attr{}, syscall.EOPNOTSUPP
			}
			flags := unix.O_RDONLY
			if obj.kind == KindRegular {
				flags = unix.O_RDWR
			}
			if obj.kind == KindDirectory {
				flags |= unix.O_DIRECTORY
			}
			fd, reopenErr := v.reopen(obj.fd(), flags, obj.kind)
			if reopenErr != nil {
				return v.setAttrPost(obj, opened, itemID, firstError(reopenErr, syscall.EIO))
			}
			truncateErr := unix.Ftruncate(fd, *spec.Size)
			closeErr := unix.Close(fd)
			if err := apply(func() error { return errors.Join(truncateErr, closeErr) }); err != nil {
				return v.setAttrPost(obj, opened, itemID, err)
			}
		}
	}
	if spec.ATimeNS != nil || spec.MTimeNS != nil || spec.ATimeNow || spec.MTimeNow {
		if itemID == (Capability{}) || spec.ATimeNS != nil && spec.ATimeNow || spec.MTimeNS != nil && spec.MTimeNow {
			return Attr{}, fs.ErrInvalid
		}
		times := []unix.Timespec{{Nsec: unix.UTIME_OMIT}, {Nsec: unix.UTIME_OMIT}}
		if spec.ATimeNow {
			times[0].Nsec = unix.UTIME_NOW
		} else if spec.ATimeNS != nil {
			times[0] = unix.NsecToTimespec(*spec.ATimeNS)
		}
		if spec.MTimeNow {
			times[1].Nsec = unix.UTIME_NOW
		} else if spec.MTimeNS != nil {
			times[1] = unix.NsecToTimespec(*spec.MTimeNS)
		}
		if err := apply(func() error {
			return unix.UtimesNanoAt(obj.fd(), "", times, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
		}); err != nil {
			return v.setAttrPost(obj, opened, itemID, err)
		}
	}
	return v.setAttrPost(obj, opened, itemID, nil)
}

func (v *Volume) setAttrPost(obj object, opened *openFile, hasItem Capability, applyErr error) (Attr, error) {
	fd := -1
	if opened != nil {
		fd = opened.fd()
	} else if hasItem != (Capability{}) {
		fd = obj.fd()
	} else {
		return Attr{}, fs.ErrInvalid
	}
	post, statErr := statFD(fd)
	if statErr != nil {
		return Attr{}, outcomeUncertain(errors.Join(applyErr, statErr))
	}
	return post, applyErr
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

// sizedRead runs the two-call size-probe pattern shared by getxattr and
// listxattr. The probe and the fetch are not atomic, so a concurrent
// replacement can grow the value in between and the fetch fails with ERANGE.
// The retry then uses the kernel's own hard ceiling for the object, which
// vfs_setxattr enforces on every filesystem, so the second call cannot report
// ERANGE for any value that could exist. Two bounded attempts always settle
// it; there is no attempt count to run out of and therefore no need to invent
// an errno - getxattr(2) has no EAGAIN, and a client that receives one has no
// correct handling for it.
func sizedRead(ceiling int, fetch func(buf []byte) (int, error)) ([]byte, error) {
	size, err := fetch(nil)
	if err != nil {
		return nil, err
	}
	if size < 0 || size > ceiling {
		return nil, syscall.EIO
	}
	buf := make([]byte, size)
	n, err := fetch(buf)
	if errors.Is(err, syscall.ERANGE) {
		buf = make([]byte, ceiling)
		n, err = fetch(buf)
	}
	if err != nil {
		return nil, err
	}
	if n < 0 || n > len(buf) {
		return nil, syscall.EIO
	}
	return buf[:n], nil
}

func getXattrValue(fd int, name string) ([]byte, error) {
	return sizedRead(xattrSizeMax, func(buf []byte) (int, error) {
		return unix.Fgetxattr(fd, name, buf)
	})
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
		list, err := sizedRead(xattrListMax, func(buf []byte) (int, error) {
			return unix.Flistxattr(fd, buf)
		})
		if err != nil {
			return err
		}
		for _, raw := range bytes.Split(list, []byte{0}) {
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

// StatFS reports this volume's entitlement, not the cell's.
//
// The descriptor is the volume root, which carries XFS_DIFLAG_PROJINHERIT and
// a provisioned project ID. xfs_fs_statfs calls xfs_qm_statvfs for exactly
// such an inode when the mount has project-quota accounting and enforcement
// (-o prjquota), and rewrites f_blocks/f_bfree/f_bavail and f_files/f_ffree to
// the project's limits and usage. No capability is required for that: it is
// statfs(2) on a directory, not quotactl(2), and it is how per-container df
// works on overlay2 with pquota.
//
// Verified on Linux 6.8 against a real XFS mounted -o prjquota with a project
// carrying bhard=100m,ihard=1000: the volume root reports f_blocks*f_bsize =
// 104857600 and f_files = 1000, while the cell root on the same mount reports
// 4227858432 and 2097152. Writes into the volume stopped at exactly the
// reported capacity.
//
// This depends on provisioning setting a limit for the project: XFS reports
// cell-wide values for a project with no limit, and then every free-space
// precheck in rsync, an installer or a database sees the cell.
func (v *Volume) StatFS() (FSStat, error) {
	root, err := v.holdObject(v.rootCapability())
	if err != nil {
		return FSStat{}, err
	}
	defer root.release()
	var stat unix.Statfs_t
	if err := unix.Fstatfs(root.fd(), &stat); err != nil {
		return FSStat{}, err
	}
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
