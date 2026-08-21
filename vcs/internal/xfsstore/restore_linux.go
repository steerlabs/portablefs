//go:build linux

package xfsstore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// RestoreFiles is a bounded entry-index to inode binding for authority-owned
// hydration writes. ResolveRestoreFiles builds it before serving by walking the
// confined namespace and comparing descriptor-derived stable identities. Each
// regular restored inode retains one O_PATH descriptor, so a later rename does
// not redirect drain to a different inode. Linked checks st_nlink immediately
// before drain and skips an inode the user has unlinked.
type RestoreFiles struct {
	volume *Volume
	mu     sync.RWMutex
	closed bool
	files  map[uint32]restoreFile
}

type restoreFile struct {
	res      *resource
	identity [16]byte
	mtimeNS  int64
}

// ResolveRestoreFiles walks at most maxVisited namespace entries. identities
// may contain directories and symlinks; only regular files are retained since
// only they can occur in the hydrator drain order.
func (v *Volume) ResolveRestoreFiles(identities map[[16]byte]uint32, maxVisited uint64) (*RestoreFiles, error) {
	if len(identities) == 0 || maxVisited == 0 {
		return nil, errors.New("xfsstore: restore binding and walk bounds must be positive")
	}
	r := &RestoreFiles{volume: v, files: make(map[uint32]restoreFile)}
	root, err := unix.Dup(v.rootFD)
	if err != nil {
		return nil, err
	}
	visited := uint64(0)
	err = v.walkRestoreDirectory(root, identities, maxVisited, &visited, r)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

func (v *Volume) walkRestoreDirectory(dirFD int, identities map[[16]byte]uint32, maxVisited uint64, visited *uint64, result *RestoreFiles) error {
	file := os.NewFile(uintptr(dirFD), "portablefs-restore-walk")
	if file == nil {
		return syscall.EBADF
	}
	defer file.Close()
	names, err := file.Readdirnames(-1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	for _, name := range names {
		(*visited)++
		if *visited > maxVisited {
			return errors.New("xfsstore: restore namespace walk bound exceeded")
		}
		pathFD, err := openChildAt(int(file.Fd()), name)
		if err != nil {
			return err
		}
		attr, err := statFD(pathFD)
		if err != nil {
			_ = unix.Close(pathFD)
			return err
		}
		identity, err := stableIdentityFD(pathFD, v.productionIdentity)
		if err != nil {
			_ = unix.Close(pathFD)
			return err
		}
		if entry, matched := identities[identity]; matched && attr.Kind == KindRegular {
			if _, duplicate := result.files[entry]; duplicate {
				// A hard-link alias is another name for the exact same stable
				// identity. The first descriptor is already the complete binding.
				_ = unix.Close(pathFD)
				pathFD = -1
			} else {
				result.files[entry] = restoreFile{res: newResource(pathFD), identity: identity, mtimeNS: attr.MTimeNS}
				pathFD = -1
			}
		}
		if attr.Kind == KindDirectory {
			if err := v.walkRestoreSubtree(pathFD, identities, maxVisited, visited, result); err != nil {
				if pathFD >= 0 {
					_ = unix.Close(pathFD)
				}
				return err
			}
		}
		if pathFD >= 0 {
			_ = unix.Close(pathFD)
		}
	}
	return nil
}

// restoreWalkBits is the owner access the binding walk needs on one directory:
// read, to enumerate it, and search, to open the children it named. Nothing
// more, and never write.
const restoreWalkBits = 0o500

// walkRestoreSubtree opens one restored directory for reading and walks it,
// stepping around an archived mode that denies its own owner exactly as
// writeThrough does for a file. A restored tree can contain a 0000 or
// write-only directory - the archiver is granted CAP_DAC_READ_SEARCH so that
// such a tree can be archived at all - and this authority holds no capability,
// so the mode has to move for the walk and move back after it.
//
// The window here spans the subtree walk rather than a single syscall, which is
// why it is acceptable only where it is used: ResolveRestoreFiles runs once
// during authority startup, strictly before the volume server begins accepting
// sessions, so no client exists that could observe the widened mode. The
// deferred restore puts the exact bits back, and a failure to put them back is
// joined into the walk's error rather than swallowed.
func (v *Volume) walkRestoreSubtree(pathFD int, identities map[[16]byte]uint32, maxVisited uint64, visited *uint64, result *RestoreFiles) (err error) {
	readFD, openErr := v.reopen(pathFD, unix.O_RDONLY|unix.O_DIRECTORY, KindDirectory)
	if openErr == nil {
		return v.walkRestoreDirectory(readFD, identities, maxVisited, visited, result)
	}
	if !errors.Is(openErr, unix.EACCES) {
		return openErr
	}
	original, err := permissionBitsFD(pathFD)
	if err != nil {
		return err
	}
	if err := setPermissionBitsFD(pathFD, original|restoreWalkBits); err != nil {
		return err
	}
	defer func() {
		if restoreErr := setPermissionBitsFD(pathFD, original); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf(
				"xfsstore: the restore binding walk could not restore mode %#o on the directory it widened: %w",
				original, restoreErr))
		}
	}()
	readFD, openErr = v.reopen(pathFD, unix.O_RDONLY|unix.O_DIRECTORY, KindDirectory)
	if openErr != nil {
		return openErr
	}
	return v.walkRestoreDirectory(readFD, identities, maxVisited, visited, result)
}

func (r *RestoreFiles) hold(entry uint32) (restoreFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return restoreFile{}, ErrClosed
	}
	file, ok := r.files[entry]
	if !ok {
		return restoreFile{}, ErrStaleObject
	}
	file.res.acquire()
	return file, nil
}

func (r *RestoreFiles) LogicalSize(entry uint32) (int64, error) {
	file, err := r.hold(entry)
	if err != nil {
		return 0, err
	}
	defer file.res.release()
	attr, err := statFD(file.res.fd)
	return attr.Size, err
}

// hydrationWriteBits is the owner access a hydration write needs. It is the
// minimum that lets reopen(O_RDWR) succeed, and it is added to the file's own
// mode rather than replacing it, so no other bit of the archived mode is
// disturbed by the window.
const hydrationWriteBits = 0o600

// writeThrough runs one hydration operation against an O_RDWR descriptor on the
// held inode, stepping around an archived mode that denies its own owner.
//
// A restore materializes the namespace at its final modes immediately and fills
// the bytes in afterwards, so the file this authority must write into may
// already be 0444, 0400, or 0000. The volume is single-owner by contract, and
// this process is that owner, but ownership does not grant access: reopening
// such an inode for writing answers EACCES to everyone without
// CAP_DAC_OVERRIDE, which no cell component holds. So on EACCES - and only on
// EACCES, the common path is untouched - the exact mode is read from the held
// descriptor, owner read/write is added, the write is performed, and the exact
// original mode is put back, including on the error path. A restore that could
// not put it back fails loudly rather than leaving the file quietly widened.
//
// Every mode operation here addresses the inode through the held O_PATH
// descriptor with AT_EMPTY_PATH, never by re-resolving a name: the descriptor
// is the file's identity, and a rename or a replacement under the same name
// must not be able to redirect the chmod at another inode.
//
// Visibility. Drain and recall call this while holding the restore mode's
// per-entry lock (restoremode.Mode.hydrateLocked), and the authority's GETATTR
// takes that same lock for reading (WithAttrLock, called from
// authorityrpc.VolumeHandler.getattr), so a GETATTR of this inode cannot land
// inside the window. That exclusion is not total, and this comment does not
// claim it is: LOOKUP and READDIR with attributes answer from
// Store.Getattr/StatOpenDirChild without taking the entry lock, so a concurrent
// listing can transiently report the owner-writable mode. The inode's ctime
// also moves, twice, and is not restored - Linux offers no way to set it, and
// the archive format records ctime as metadata only. A crash inside the window
// leaves the widened mode behind, which the next restore of the same archive
// corrects only because it materializes a fresh tree.
func (r *RestoreFiles) writeThrough(file restoreFile, apply func(fd int) error) (err error) {
	fd, openErr := r.volume.reopen(file.res.fd, unix.O_RDWR, KindRegular)
	if openErr == nil {
		defer unix.Close(fd)
		return apply(fd)
	}
	if !errors.Is(openErr, unix.EACCES) {
		return openErr
	}
	original, err := permissionBitsFD(file.res.fd)
	if err != nil {
		return err
	}
	if err := setPermissionBitsFD(file.res.fd, original|hydrationWriteBits); err != nil {
		return err
	}
	defer func() {
		if restoreErr := setPermissionBitsFD(file.res.fd, original); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf(
				"xfsstore: a hydration write could not restore mode %#o on the inode it widened: %w",
				original, restoreErr))
		}
	}()
	fd, openErr = r.volume.reopen(file.res.fd, unix.O_RDWR, KindRegular)
	if openErr != nil {
		return openErr
	}
	defer unix.Close(fd)
	return apply(fd)
}

// permissionBitsFD reads the exact mode bits - permissions plus set-ID and
// sticky - of the inode a descriptor names. It is deliberately raw rather than
// the Attr conversion: the mode has to be put back byte for byte, and the
// fs.FileMode round trip is lossy at exactly the bits a faithful restore must
// not drop.
func permissionBitsFD(fd int) (uint32, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MODE, &st); err != nil {
		return 0, err
	}
	return uint32(st.Mode) & 0o7777, nil
}

func setPermissionBitsFD(fd int, bits uint32) error {
	return unix.Fchmodat(fd, "", bits, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

func (r *RestoreFiles) PWrite(entry uint32, off int64, data []byte) error {
	file, err := r.hold(entry)
	if err != nil {
		return err
	}
	defer file.res.release()
	return r.writeThrough(file, func(fd int) error {
		for len(data) != 0 {
			n, err := unix.Pwrite(fd, data, off)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			data, off = data[n:], off+int64(n)
		}
		return nil
	})
}

// Fdatasync goes through the same dance as PWrite. fdatasync(2) itself needs no
// write access, but the descriptor it is given here does not exist yet, and
// reopening an archived 0444 or 0000 file - for reading just as much as for
// writing - is the operation that EACCES refuses.
func (r *RestoreFiles) Fdatasync(entry uint32) error {
	file, err := r.hold(entry)
	if err != nil {
		return err
	}
	defer file.res.release()
	return r.writeThrough(file, unix.Fdatasync)
}

// RestoreMtime needs no dance and must not have one. utimensat with explicit
// timestamps is permitted to the inode's owner regardless of its mode - the
// kernel requires write permission only for the UTIME_NOW form - and this call
// addresses the held descriptor with AT_EMPTY_PATH, so it resolves no path
// component and cannot be refused by an unsearchable directory either.
func (r *RestoreFiles) RestoreMtime(entry uint32) error {
	file, err := r.hold(entry)
	if err != nil {
		return err
	}
	defer file.res.release()
	times := []unix.Timespec{{Nsec: unix.UTIME_OMIT}, unix.NsecToTimespec(file.mtimeNS)}
	return unix.UtimesNanoAt(file.res.fd, "", times, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

func (r *RestoreFiles) Linked(entry uint32) (bool, error) {
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return false, ErrClosed
	}
	file, ok := r.files[entry]
	if !ok {
		r.mu.RUnlock()
		return false, nil
	}
	file.res.acquire()
	r.mu.RUnlock()
	defer file.res.release()
	attr, err := statFD(file.res.fd)
	return err == nil && attr.Nlink != 0, err
}

// DiscardUnlinked forgets an inode only when both its namespace link count and
// every authority capability reference are gone. Until then an unlinked open
// (or a retained item that may be opened) must remain recallable.
func (r *RestoreFiles) DiscardUnlinked(entry uint32) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false, ErrClosed
	}
	file, ok := r.files[entry]
	if !ok {
		return true, nil
	}
	attr, err := statFD(file.res.fd)
	if err != nil {
		return false, err
	}
	if attr.Nlink != 0 {
		return false, nil
	}
	r.volume.mu.RLock()
	referenced := false
	for _, object := range r.volume.objects {
		if object.identity == file.identity {
			referenced = true
			break
		}
	}
	if !referenced {
		for _, open := range r.volume.opens {
			if open.identity == file.identity {
				referenced = true
				break
			}
		}
	}
	r.volume.mu.RUnlock()
	if referenced {
		return false, nil
	}
	delete(r.files, entry)
	return true, file.res.release()
}

func (r *RestoreFiles) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var result error
	for entry, file := range r.files {
		result = errors.Join(result, file.res.release())
		delete(r.files, entry)
	}
	return result
}
