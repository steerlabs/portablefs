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
// regular restored inode retains one O_RDWR descriptor, so a later rename does
// not redirect drain to a different inode. Linked checks st_nlink immediately
// before drain and skips an inode the user has unlinked.
//
// The descriptor is opened for writing once, by the binding walk, and every
// hydration write, fdatasync and size query then addresses it directly. That is
// the whole reason the walk exists in this shape: a restore materializes the
// namespace at its final archived modes and fills the bytes in afterwards, so
// the inode this authority must write into is routinely 0444, 0400 or 0000, and
// no cell component holds CAP_DAC_OVERRIDE. The kernel checks permission at
// open(2) and never again, so a descriptor obtained before serving carries
// every later write regardless of the mode the file ends up presenting. Nothing
// in this file touches a mode once ResolveRestoreFiles has returned.
//
// Holding a writable description raises the inode's writer count for as long as
// the restore lasts, which is what makes execve answer ETXTBSY. That is
// invisible here and must stay invisible: these descriptors address XFS inodes
// that no client can reach, since every client sees the FUSE inode the
// authority serves and grafts are backed by machine-local disk rather than by
// this tree. Exposing the restored tree to a client directly - a bind mount, a
// passthrough backing descriptor - would make every executable in a restoring
// workspace unrunnable until the drain converges.
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
		err = v.visitRestoreEntry(pathFD, identities, maxVisited, visited, result)
		_ = unix.Close(pathFD)
		if err != nil {
			return err
		}
	}
	return nil
}

// visitRestoreEntry inspects one named child. The O_PATH descriptor is the
// entry's identity for as long as this call runs and belongs to the caller: a
// retained binding is a separate descriptor of its own, so nothing here can
// hand a walk descriptor to the result and leave its lifetime ambiguous.
func (v *Volume) visitRestoreEntry(pathFD int, identities map[[16]byte]uint32, maxVisited uint64, visited *uint64, result *RestoreFiles) error {
	attr, err := statFD(pathFD)
	if err != nil {
		return err
	}
	identity, err := stableIdentityFD(pathFD, v.productionIdentity)
	if err != nil {
		return err
	}
	if attr.Kind == KindDirectory {
		return v.walkRestoreSubtree(pathFD, identities, maxVisited, visited, result)
	}
	entry, matched := identities[identity]
	if !matched || attr.Kind != KindRegular {
		return nil
	}
	if _, duplicate := result.files[entry]; duplicate {
		// A hard-link alias is another name for the exact same stable
		// identity. The first descriptor is already the complete binding.
		return nil
	}
	// One descriptor per bound restore file, which is the shape the design has
	// always had: the walk binds the same set of inodes it used to bind with an
	// O_PATH descriptor, so the authority's descriptor budget is unchanged and
	// is bounded by the hydrator's binding table rather than by the namespace.
	writeFD, err := v.openRestoreFile(pathFD)
	if err != nil {
		return err
	}
	result.files[entry] = restoreFile{res: newResource(writeFD), identity: identity, mtimeNS: attr.MTimeNS}
	return nil
}

// restoreWalkBits is the owner access the binding walk needs on one directory:
// read, to enumerate it, and search, to open the children it named. Nothing
// more, and never write.
const restoreWalkBits = 0o500

// restoreWriteBits is the owner access the binding walk needs on one regular
// restore file, and it is the minimum that lets an O_RDWR open succeed. It is
// added to the file's own mode rather than replacing it, so no other bit of the
// archived mode is disturbed while the descriptor is being obtained.
const restoreWriteBits = 0o600

// The archived mode of a restored inode can deny its own owner every access,
// because the archiver is granted CAP_DAC_READ_SEARCH precisely so that such a
// tree can be archived at all, and this authority holds no capability. Both
// halves of the binding walk therefore have to move a mode out of the way to
// obtain the descriptor they need, and put the exact bits back afterwards.
//
// That window is confined to ResolveRestoreFiles by construction, and this is
// the reason the descriptors are opened here rather than at the point of use:
// the walk runs once during authority startup, strictly before the volume
// server accepts a session, so there is no client that could observe a widened
// mode through LOOKUP, READDIR or GETATTR, and no user operation that could
// have its own chmod overwritten by the restore. A failure to put the bits back
// is joined into the walk's error rather than swallowed, so a restore that
// widened something it could not narrow again refuses to serve.
//
// The residual is honest and small: a crash between the widen and the restore
// leaves that one inode widened, and nothing later notices. It is corrected
// only by the next restore of the same archive, which materializes a fresh
// tree. The inode's ctime also moves, twice, and cannot be put back - Linux
// offers no way to set it, and the archive format records ctime as metadata
// only.

// walkRestoreSubtree opens one restored directory for reading and walks it.
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

// openRestoreFile produces the one descriptor a bound restore file keeps for the
// lifetime of the restore. reopen is the only way this volume ever obtains a
// writable descriptor, so the retained fd carries the project-accounting check
// with it; addressing the inode through the walk's O_PATH descriptor with
// AT_EMPTY_PATH rather than re-resolving a name is what stops a rename, or a
// replacement under the same name, from redirecting the chmod or the open at
// another inode.
func (v *Volume) openRestoreFile(pathFD int) (int, error) {
	fd, openErr := v.reopen(pathFD, unix.O_RDWR, KindRegular)
	if openErr == nil {
		return fd, nil
	}
	if !errors.Is(openErr, unix.EACCES) {
		return -1, openErr
	}
	original, err := permissionBitsFD(pathFD)
	if err != nil {
		return -1, err
	}
	if err := setPermissionBitsFD(pathFD, original|restoreWriteBits); err != nil {
		return -1, err
	}
	fd, openErr = v.reopen(pathFD, unix.O_RDWR, KindRegular)
	if restoreErr := setPermissionBitsFD(pathFD, original); restoreErr != nil {
		if openErr == nil {
			_ = unix.Close(fd)
		}
		return -1, errors.Join(openErr, fmt.Errorf(
			"xfsstore: the restore binding walk could not restore mode %#o on the file it widened: %w",
			original, restoreErr))
	}
	if openErr != nil {
		return -1, openErr
	}
	return fd, nil
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

// PWrite lands hydrated bytes through the retained descriptor. The file's own
// mode is irrelevant here and is never consulted: the descriptor was opened for
// writing before any client existed, and a mode the user changes afterwards -
// in either direction - neither refuses this write nor is disturbed by it.
//
// The caller holds the restore mode's per-entry lock (restoremode.Mode installs
// a fetched chunk under it), which is what keeps the mtime this write moves
// from being observed before RestoreMtime puts the archived one back.
func (r *RestoreFiles) PWrite(entry uint32, off int64, data []byte) error {
	file, err := r.hold(entry)
	if err != nil {
		return err
	}
	defer file.res.release()
	for len(data) != 0 {
		n, err := unix.Pwrite(file.res.fd, data, off)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data, off = data[n:], off+int64(n)
	}
	return nil
}

func (r *RestoreFiles) Fdatasync(entry uint32) error {
	file, err := r.hold(entry)
	if err != nil {
		return err
	}
	defer file.res.release()
	return unix.Fdatasync(file.res.fd)
}

// RestoreMtime puts the archived mtime back after a hydration write moved it.
// utimensat with explicit timestamps is permitted to the inode's owner
// regardless of its mode - the kernel requires write permission only for the
// UTIME_NOW form - and this call addresses the retained descriptor with
// AT_EMPTY_PATH, so it resolves no path component and cannot be refused by an
// unsearchable directory either.
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
