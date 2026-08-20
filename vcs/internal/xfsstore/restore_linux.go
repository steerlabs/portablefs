//go:build linux

package xfsstore

import (
	"errors"
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
			readFD, openErr := v.reopen(pathFD, unix.O_RDONLY|unix.O_DIRECTORY, KindDirectory)
			if openErr != nil {
				if pathFD >= 0 {
					_ = unix.Close(pathFD)
				}
				return openErr
			}
			if err := v.walkRestoreDirectory(readFD, identities, maxVisited, visited, result); err != nil {
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

func (r *RestoreFiles) PWrite(entry uint32, off int64, data []byte) error {
	file, err := r.hold(entry)
	if err != nil {
		return err
	}
	defer file.res.release()
	fd, err := r.volume.reopen(file.res.fd, unix.O_RDWR, KindRegular)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
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
}

func (r *RestoreFiles) Fdatasync(entry uint32) error {
	file, err := r.hold(entry)
	if err != nil {
		return err
	}
	defer file.res.release()
	fd, err := r.volume.reopen(file.res.fd, unix.O_RDWR, KindRegular)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fdatasync(fd)
}

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
