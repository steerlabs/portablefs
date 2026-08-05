//go:build linux

package xfsstore

import (
	"errors"
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

// The namespace operations below take no volume-wide lock. XFS already
// provides the per-directory locking these calls need, and renameat2 and
// openat2 already provide the atomicity: a userspace mutex over the whole
// volume adds nothing to either, while making one create that blocks in XFS on
// log-space reservation or quota handling stall every unlink, rename and
// lookup in unrelated directories. Different replay slots execute
// concurrently, which is what the architecture promises.

// holdParent resolves a directory capability for use as a dirfd. The reference
// keeps the descriptor alive for the syscall without holding any volume lock
// across it.
func (v *Volume) holdParent(id Capability) (object, error) {
	obj, err := v.holdObject(id)
	if err != nil {
		return object{}, err
	}
	if obj.kind != KindDirectory {
		obj.release()
		return object{}, syscall.ENOTDIR
	}
	return obj, nil
}

// Create creates or opens one regular-file child.
//
// A creation grants access; it does not re-derive it. Linux decides what the
// creating caller may do with the new inode at the moment it creates it -
// finish_open skips may_open for the file it just made - and never consults
// the mode again for that file description. That is exactly why
// open(O_CREAT|O_EXCL, 0444) hands back a writable descriptor, which
// mkstemp(3), git, dpkg and rpm all build on. A second open of the same inode
// cannot reproduce it and must not: it is a different caller at a different
// time, and the mode is what answers for it.
//
// So the description this creation produced is kept with the new object and
// handed to the open handle that follows, instead of being thrown away and a
// permission decision re-run against a mode the caller itself chose.
func (v *Volume) Create(parent Capability, name string, mode fs.FileMode, exclusive bool) (Capability, Attr, error) {
	if err := ValidateComponent(name); err != nil {
		return Capability{}, Attr{}, err
	}
	unixMode, err := modeToUnix(mode)
	if err != nil {
		return Capability{}, Attr{}, err
	}
	p, err := v.holdParent(parent)
	if err != nil {
		return Capability{}, Attr{}, err
	}
	defer p.release()
	// Each iteration needs another client to have created and then removed this
	// exact name, so the loop only continues while someone else makes progress
	// on it. The bound keeps one worker from being pinned by a peer that does
	// nothing else, and then reports the last honest failure.
	for range 16 {
		fd, err := createRegular(p.fd(), name, unixMode)
		if err == nil {
			identity, identityErr := stableIdentityAt(p.fd(), name, fd, v.productionIdentity)
			if identityErr != nil {
				_ = unix.Close(fd)
				return Capability{}, Attr{}, outcomeUncertain(identityErr)
			}
			return v.installCreated(fd, unixMode, identity)
		}
		if exclusive || err != syscall.EEXIST {
			return Capability{}, Attr{}, err
		}
		// The name already exists, so nothing is created and nothing is
		// granted: what this caller may do with that inode is decided when a
		// handle is opened for it, against its mode, exactly as open(2)
		// decides it. Taking an O_PATH reference here asks for no access at
		// all, so a read-only file can still be reached with a read intent.
		existing, err := openChildAt(p.fd(), name)
		if err == nil {
			// Nothing was mutated on this path, so no failure below it can be
			// an uncertain outcome: reporting one would re-establish the mount
			// for an operation that provably did not touch XFS.
			identity, identityErr := stableIdentityAt(p.fd(), name, existing, v.productionIdentity)
			if identityErr != nil {
				_ = unix.Close(existing)
				return Capability{}, Attr{}, identityErr
			}
			return v.installObject(existing, nil, identity)
		}
		if err != syscall.ENOENT {
			return Capability{}, Attr{}, err
		}
	}
	return Capability{}, Attr{}, syscall.EEXIST
}

// createRegular performs the creating open. The description it returns is the
// one the kernel granted access to at creation.
func createRegular(parentFD int, name string, unixMode uint32) (int, error) {
	return unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags: unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW |
			unix.O_CLOEXEC | unix.O_NOCTTY | unix.O_NONBLOCK,
		Mode: uint64(unixMode),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_XDEV,
	})
}

// installCreated takes ownership of the creation description. Everything from
// here on has already modified XFS, so every failure is an uncertain outcome.
func (v *Volume) installCreated(fd int, unixMode uint32, identity [16]byte) (Capability, Attr, error) {
	fail := func(err error) (Capability, Attr, error) {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	// The descriptor is open for access, so this is one of the two places
	// where an inode's XFS project can be read at all. Verifying the child
	// also verifies the parent it inherited from.
	if err := v.verifyProjectOf(fd, KindRegular); err != nil {
		return fail(err)
	}
	// The client kernel has already applied its umask. Applying the worker's
	// ambient umask a second time would silently change the requested mode.
	// fchmod is descriptor-relative and is completed before the new inode can
	// be returned by this authority.
	if err := unix.Fchmod(fd, unixMode); err != nil {
		return fail(err)
	}
	// The object capability holds an O_PATH reference like every other one;
	// O_PATH asks for no access, so it is unaffected by the mode just applied.
	reference, err := pathReferenceTo(fd)
	if err != nil {
		return fail(err)
	}
	item, attr, err := v.installObject(reference, newResource(fd), identity)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	return item, attr, nil
}

// pathReferenceTo opens a second, access-free reference to an already-open
// inode. It re-stats device and inode because /proc/self/fd resolution is a
// path walk, the same reason reopen does.
func pathReferenceTo(fd int) (int, error) {
	reference, err := unix.Open(procFDPath(fd), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		_ = unix.Close(reference)
		return -1, err
	}
	if err := unix.Fstat(reference, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		_ = unix.Close(reference)
		if err != nil {
			return -1, err
		}
		return -1, ErrStaleObject
	}
	return reference, nil
}

// Mkdir creates the directory owner-accessible and applies the requested mode
// once its project accounting has been verified. The intermediate mode is
// never wider than owner-only, and this volume is a single-principal
// workspace, so no other principal can observe or use the window; the payoff
// is that the project check is unconditional instead of being possible only
// for modes that happen to include a read bit.
func (v *Volume) Mkdir(parent Capability, name string, mode fs.FileMode) (Capability, Attr, error) {
	if err := ValidateComponent(name); err != nil {
		return Capability{}, Attr{}, err
	}
	unixMode, err := modeToUnix(mode)
	if err != nil {
		return Capability{}, Attr{}, err
	}
	p, err := v.holdParent(parent)
	if err != nil {
		return Capability{}, Attr{}, err
	}
	defer p.release()
	if err := unix.Mkdirat(p.fd(), name, 0o700); err != nil {
		return Capability{}, Attr{}, err
	}
	if err := v.verifyCreatedDirectory(p.fd(), name); err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	fd, err := openChildAt(p.fd(), name)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	if err := unix.Fchmodat(fd, "", unixMode, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	identity, identityErr := stableIdentityAt(p.fd(), name, fd, v.productionIdentity)
	if identityErr != nil {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, outcomeUncertain(identityErr)
	}
	item, attr, err := v.installObject(fd, nil, identity)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	return item, attr, nil
}

// verifyCreatedDirectory opens the new directory for access - which is only
// possible because Mkdir created it owner-readable - and rejects a directory
// that did not inherit this volume's project, which is exactly what happens
// when the parent it was created in belongs to another project or to none.
func (v *Volume) verifyCreatedDirectory(parentFD int, name string) error {
	if v.projectID == 0 {
		return nil
	}
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return verifyProject(fd, v.projectID, true)
}

func (v *Volume) Symlink(parent Capability, name, target string) (Capability, Attr, error) {
	if err := ValidateComponent(name); err != nil {
		return Capability{}, Attr{}, err
	}
	if len(target) == 0 || len(target) > 4096 {
		return Capability{}, Attr{}, fs.ErrInvalid
	}
	for i := range len(target) {
		if target[i] == 0 {
			return Capability{}, Attr{}, fs.ErrInvalid
		}
	}
	p, err := v.holdParent(parent)
	if err != nil {
		return Capability{}, Attr{}, err
	}
	defer p.release()
	if err := unix.Symlinkat(target, p.fd(), name); err != nil {
		return Capability{}, Attr{}, err
	}
	fd, err := openChildAt(p.fd(), name)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	identity, identityErr := stableIdentityAt(p.fd(), name, fd, v.productionIdentity)
	if identityErr != nil {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, outcomeUncertain(identityErr)
	}
	item, attr, err := v.installObject(fd, nil, identity)
	if err != nil {
		return Capability{}, Attr{}, outcomeUncertain(err)
	}
	return item, attr, nil
}

func (v *Volume) Readlink(id Capability) (string, error) {
	obj, err := v.holdObject(id)
	if err != nil {
		return "", err
	}
	defer obj.release()
	if obj.kind != KindSymlink {
		return "", syscall.EINVAL
	}
	for size := 256; size <= 4096; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(obj.fd(), "", buf)
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
	p, err := v.holdParent(parent)
	if err != nil {
		return err
	}
	defer p.release()
	flags := 0
	if directory {
		flags = unix.AT_REMOVEDIR
	}
	return unix.Unlinkat(p.fd(), name, flags)
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
	from, err := v.holdParent(oldParent)
	if err != nil {
		return err
	}
	defer from.release()
	to, err := v.holdParent(newParent)
	if err != nil {
		return err
	}
	defer to.release()
	var linuxFlags uint
	if flags&RenameNoReplace != 0 {
		linuxFlags |= unix.RENAME_NOREPLACE
	}
	if flags&RenameExchange != 0 {
		linuxFlags |= unix.RENAME_EXCHANGE
	}
	return unix.Renameat2(from.fd(), oldName, to.fd(), newName, linuxFlags)
}

// Link creates a second name for an existing inode and reports the attributes
// the inode actually has afterwards. The post-link stat is not a nicety: link
// counts change under concurrency, so any count computed from a stat taken
// before the mutation is a guess, and hardlink detection in cp, tar, rsync and
// find acts on it.
//
// The same stat is what verifies the link. This is the only path-based,
// symlink-following syscall in the package: linkat needs AT_SYMLINK_FOLLOW to
// traverse the /proc magic link, because AT_EMPTY_PATH would require
// CAP_DAC_READ_SEARCH that the worker deliberately does not have. Comparing
// the new entry's device and inode with the source proves the kernel linked
// the inode this call named and not something the magic link resolved through.
func (v *Volume) Link(source Capability, newParent Capability, newName string) (Attr, error) {
	if err := ValidateComponent(newName); err != nil {
		return Attr{}, err
	}
	src, err := v.holdObject(source)
	if err != nil {
		return Attr{}, err
	}
	defer src.release()
	if src.kind == KindDirectory {
		return Attr{}, syscall.EPERM
	}
	to, err := v.holdParent(newParent)
	if err != nil {
		return Attr{}, err
	}
	defer to.release()
	before, err := statFD(src.fd())
	if err != nil {
		return Attr{}, err
	}
	if err := unix.Linkat(unix.AT_FDCWD, procFDPath(src.fd()), to.fd(), newName, unix.AT_SYMLINK_FOLLOW); err != nil {
		return Attr{}, err
	}
	attr, err := statChild(to.fd(), newName)
	switch {
	case err == nil:
		if attr.Ino != before.Ino || attr.DeviceMajor != before.DeviceMajor || attr.DeviceMinor != before.DeviceMinor {
			// The name now refers to an inode this call did not name. The
			// namespace has been changed in a way this authority cannot
			// describe, which is precisely an uncertain outcome.
			return Attr{}, outcomeUncertain(ErrStaleObject)
		}
		return attr, nil
	case errors.Is(err, syscall.ENOENT):
		// A concurrent unlink removed the new name again. The link did
		// happen; the source inode's own post-mutation attributes are the
		// truthful answer, and they are still read after the mutation.
		return statFD(src.fd())
	default:
		return Attr{}, outcomeUncertain(err)
	}
}
