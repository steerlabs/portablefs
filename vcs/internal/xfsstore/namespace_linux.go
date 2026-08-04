//go:build linux

package xfsstore

import (
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

func (v *Volume) parentFDLocked(id Capability) (int, error) {
	obj, err := v.objectLocked(id)
	if err != nil {
		return -1, err
	}
	if obj.kind != KindDirectory {
		return -1, syscall.ENOTDIR
	}
	return obj.fd, nil
}

// Create creates or opens one regular-file child. The returned capability is
// an object reference, not an open file description; OpenFile establishes the
// latter with explicit access flags.
func (v *Volume) Create(parent Capability, name string, mode fs.FileMode, exclusive bool) (Capability, Attr, error) {
	if err := ValidateComponent(name); err != nil {
		return Capability{}, Attr{}, err
	}
	v.namespace.Lock()
	defer v.namespace.Unlock()
	v.mu.RLock()
	pfd, err := v.parentFDLocked(parent)
	if err != nil {
		v.mu.RUnlock()
		return Capability{}, Attr{}, err
	}
	fd, created, err := openOrCreateRegular(pfd, name, mode, exclusive)
	v.mu.RUnlock()
	if err != nil {
		return Capability{}, Attr{}, err
	}
	if created {
		// The client kernel has already applied its umask. Applying the worker's
		// ambient umask a second time would silently change the requested mode.
		// fchmod is descriptor-relative and is completed before the new inode can
		// be returned by this authority.
		if err := unix.Fchmod(fd, modeToUnix(mode)); err != nil {
			_ = unix.Close(fd)
			return Capability{}, Attr{}, outcomeUncertain(err)
		}
	}
	item, attr, err := v.installObject(fd)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	return item, attr, nil
}

func openOrCreateRegular(parentFD int, name string, mode fs.FileMode, exclusive bool) (fd int, created bool, err error) {
	const resolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV
	baseFlags := uint64(unix.O_RDWR | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY | unix.O_NONBLOCK)
	open := func(flags uint64) (int, error) {
		return unix.Openat2(parentFD, name, &unix.OpenHow{
			Flags:   flags,
			Mode:    uint64(modeToUnix(mode)),
			Resolve: resolve,
		})
	}
	if exclusive {
		fd, err = open(baseFlags | unix.O_EXCL)
		return fd, err == nil, err
	}
	fd, err = open(baseFlags | unix.O_EXCL)
	if err == nil {
		return fd, true, nil
	}
	if err != syscall.EEXIST {
		return -1, false, err
	}
	fd, err = open(baseFlags)
	return fd, false, err
}

func (v *Volume) Mkdir(parent Capability, name string, mode fs.FileMode) (Capability, Attr, error) {
	if err := ValidateComponent(name); err != nil {
		return Capability{}, Attr{}, err
	}
	v.namespace.Lock()
	defer v.namespace.Unlock()
	v.mu.RLock()
	pfd, err := v.parentFDLocked(parent)
	if err == nil {
		err = unix.Mkdirat(pfd, name, modeToUnix(mode))
	}
	v.mu.RUnlock()
	if err != nil {
		return Capability{}, Attr{}, err
	}
	fd, err := v.openChild(parent, name)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	if err := unix.Fchmodat(fd, "", modeToUnix(mode), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	item, attr, err := v.installObject(fd)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	return item, attr, nil
}

func (v *Volume) Symlink(parent Capability, name, target string) (Capability, Attr, error) {
	if err := ValidateComponent(name); err != nil || len(target) == 0 || len(target) > 4096 {
		if err != nil {
			return Capability{}, Attr{}, err
		}
		return Capability{}, Attr{}, fs.ErrInvalid
	}
	for i := range len(target) {
		if target[i] == 0 {
			return Capability{}, Attr{}, fs.ErrInvalid
		}
	}
	v.namespace.Lock()
	defer v.namespace.Unlock()
	v.mu.RLock()
	pfd, err := v.parentFDLocked(parent)
	if err == nil {
		err = unix.Symlinkat(target, pfd, name)
	}
	v.mu.RUnlock()
	if err != nil {
		return Capability{}, Attr{}, err
	}
	fd, err := v.openChild(parent, name)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	item, attr, err := v.installObject(fd)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	return item, attr, nil
}

func (v *Volume) Readlink(id Capability) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	obj, err := v.objectLocked(id)
	if err != nil {
		return "", err
	}
	if obj.kind != KindSymlink {
		return "", syscall.EINVAL
	}
	for size := 256; size <= 4096; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(obj.fd, "", buf)
		if err != nil {
			return "", err
		}
		if n < len(buf) {
			return string(buf[:n]), nil
		}
	}
	return "", syscall.ENAMETOOLONG
}

func (v *Volume) Unlink(parent Capability, name string, directory bool) error {
	if err := ValidateComponent(name); err != nil {
		return err
	}
	v.namespace.Lock()
	defer v.namespace.Unlock()
	v.mu.RLock()
	defer v.mu.RUnlock()
	pfd, err := v.parentFDLocked(parent)
	if err != nil {
		return err
	}
	flags := 0
	if directory {
		flags = unix.AT_REMOVEDIR
	}
	return unix.Unlinkat(pfd, name, flags)
}

func (v *Volume) Rename(oldParent Capability, oldName string, newParent Capability, newName string, flags RenameFlags) error {
	if err := ValidateComponent(oldName); err != nil {
		return err
	}
	if err := ValidateComponent(newName); err != nil {
		return err
	}
	if flags&^(RenameNoReplace|RenameExchange) != 0 || flags == RenameNoReplace|RenameExchange {
		return fs.ErrInvalid
	}
	v.namespace.Lock()
	defer v.namespace.Unlock()
	v.mu.RLock()
	defer v.mu.RUnlock()
	oldFD, err := v.parentFDLocked(oldParent)
	if err != nil {
		return err
	}
	newFD, err := v.parentFDLocked(newParent)
	if err != nil {
		return err
	}
	var linuxFlags uint
	if flags&RenameNoReplace != 0 {
		linuxFlags |= unix.RENAME_NOREPLACE
	}
	if flags&RenameExchange != 0 {
		linuxFlags |= unix.RENAME_EXCHANGE
	}
	return unix.Renameat2(oldFD, oldName, newFD, newName, linuxFlags)
}

func (v *Volume) Link(source Capability, newParent Capability, newName string) (Attr, error) {
	if err := ValidateComponent(newName); err != nil {
		return Attr{}, err
	}
	v.namespace.Lock()
	defer v.namespace.Unlock()
	v.mu.RLock()
	defer v.mu.RUnlock()
	src, err := v.objectLocked(source)
	if err != nil {
		return Attr{}, err
	}
	if src.kind == KindDirectory {
		return Attr{}, syscall.EPERM
	}
	newFD, err := v.parentFDLocked(newParent)
	if err != nil {
		return Attr{}, err
	}
	attr, err := statFD(src.fd)
	if err != nil {
		return Attr{}, err
	}
	// AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH, which the production worker
	// deliberately does not have. Linux documents this procfs form as the
	// unprivileged equivalent for linking an already-open object.
	if err := unix.Linkat(unix.AT_FDCWD, procFDPath(src.fd), newFD, newName, unix.AT_SYMLINK_FOLLOW); err != nil {
		return Attr{}, err
	}
	// LINK has already committed. Returning the pre-link stat with its exact
	// new link count avoids a second fallible syscall after the mutation. The
	// FUSE entry has zero TTL, so ctime is refreshed on the next getattr.
	attr.Nlink++
	return attr, nil
}
