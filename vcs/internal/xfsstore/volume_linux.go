//go:build linux

package xfsstore

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type object struct {
	fd   int
	kind Kind
}

type openFile struct {
	fd        int
	dir       *os.File
	append    bool
	object    Capability
	kind      Kind
	mu        sync.Mutex
	dirCookie uint64
	dirHigh   uint64
}

// Volume owns all descriptors for one authority epoch. Closing it atomically
// makes every issued capability stale.
type Volume struct {
	namespace sync.RWMutex
	mu        sync.RWMutex
	rootFD    int
	root      Capability
	device    uint64
	ownerUID  uint32
	ownerGID  uint32
	closed    bool
	fenced    error
	objects   map[Capability]object
	opens     map[Capability]*openFile
}

func (v *Volume) openChild(parent Capability, name string) (int, error) {
	if err := ValidateComponent(name); err != nil {
		return -1, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	p, err := v.objectLocked(parent)
	if err != nil {
		return -1, err
	}
	if p.kind != KindDirectory {
		return -1, syscall.ENOTDIR
	}
	return unix.Openat2(p.fd, name, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_XDEV,
	})
}

// Open establishes a production volume. It deliberately refuses non-XFS
// storage instead of offering a weaker production fallback.
func Open(rootPath string, config Config) (*Volume, error) {
	if config.ExpectedProjectID == 0 {
		return nil, fmt.Errorf("%w: project ID must be nonzero", ErrProjectIsolation)
	}
	v, err := open(rootPath, true, config.ExpectedProjectID)
	if err != nil {
		return nil, err
	}
	v.ownerUID, v.ownerGID = config.ExpectedOwnerUID, config.ExpectedOwnerGID
	rootAttr, err := v.Getattr(v.root)
	if err != nil || rootAttr.UID != v.ownerUID || rootAttr.GID != v.ownerGID {
		_ = v.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: root owner is %d:%d, expected %d:%d", ErrProjectIsolation, rootAttr.UID, rootAttr.GID, v.ownerUID, v.ownerGID)
	}
	return v, nil
}

func open(rootPath string, requireXFS bool, expectedProjectID uint32) (*Volume, error) {
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, fmt.Errorf("xfsstore: root must be an absolute clean path")
	}
	fd, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open volume root: %w", err)
	}
	fail := func(err error) (*Volume, error) {
		_ = unix.Close(fd)
		return nil, err
	}

	var statfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &statfs); err != nil {
		return fail(fmt.Errorf("stat volume filesystem: %w", err))
	}
	if requireXFS && uint64(statfs.Type) != uint64(unix.XFS_SUPER_MAGIC) {
		return fail(ErrNotXFS)
	}
	if requireXFS {
		if err := verifyProjectRoot(fd, expectedProjectID); err != nil {
			return fail(err)
		}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fail(fmt.Errorf("stat volume root: %w", err))
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fail(fmt.Errorf("xfsstore: volume root is not a directory"))
	}
	// A second authority process cannot open this root concurrently. This lock
	// complements infrastructure fencing; it is not claimed to fence another
	// host that can access shared block storage.
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(fmt.Errorf("lock volume root: %w", err))
	}

	v := &Volume{
		rootFD:   fd,
		device:   uint64(st.Dev),
		ownerUID: st.Uid,
		ownerGID: st.Gid,
		objects:  make(map[Capability]object),
		opens:    make(map[Capability]*openFile),
	}
	root, err := randomCapability(v.objects)
	if err != nil {
		return fail(err)
	}
	v.root = root
	v.objects[root] = object{fd: fd, kind: KindDirectory}
	return v, nil
}

func randomCapability[T any](existing map[Capability]T) (Capability, error) {
	for range 8 {
		var c Capability
		if _, err := rand.Read(c[:]); err != nil {
			return Capability{}, fmt.Errorf("generate capability: %w", err)
		}
		if c == (Capability{}) {
			continue
		}
		if _, exists := existing[c]; !exists {
			return c, nil
		}
	}
	return Capability{}, errors.New("xfsstore: capability collision budget exhausted")
}

func (v *Volume) Root() (Capability, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return Capability{}, ErrClosed
	}
	if v.fenced != nil {
		return Capability{}, v.fenced
	}
	return v.root, nil
}

// Fence permanently stops this authority epoch from touching filesystem
// state. It is used after a storage EIO, where continuing could acknowledge
// operations against a shut-down or detached filesystem. Only process restart
// after operator/storage recovery creates a new usable epoch.
func (v *Volume) Fence(cause error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.fenced != nil {
		return
	}
	if cause == nil {
		cause = syscall.EIO
	}
	v.fenced = fmt.Errorf("%w: %v", ErrFenced, cause)
}

func (v *Volume) Health() error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return ErrClosed
	}
	return v.fenced
}

func (v *Volume) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	var result error
	for id, opened := range v.opens {
		if opened.dir != nil {
			result = errors.Join(result, opened.dir.Close())
		} else {
			result = errors.Join(result, unix.Close(opened.fd))
		}
		delete(v.opens, id)
	}
	for id, obj := range v.objects {
		if obj.fd != v.rootFD {
			result = errors.Join(result, unix.Close(obj.fd))
		}
		delete(v.objects, id)
	}
	result = errors.Join(result, unix.Flock(v.rootFD, unix.LOCK_UN), unix.Close(v.rootFD))
	v.rootFD = -1
	return result
}

func (v *Volume) objectLocked(id Capability) (object, error) {
	if v.closed {
		return object{}, ErrClosed
	}
	if v.fenced != nil {
		return object{}, v.fenced
	}
	obj, ok := v.objects[id]
	if !ok {
		return object{}, ErrStaleObject
	}
	return obj, nil
}

func (v *Volume) openLocked(id Capability) (*openFile, error) {
	if v.closed {
		return nil, ErrClosed
	}
	if v.fenced != nil {
		return nil, v.fenced
	}
	f, ok := v.opens[id]
	if !ok {
		return nil, ErrStaleOpen
	}
	return f, nil
}

func (v *Volume) installObject(fd int) (Capability, Attr, error) {
	attr, err := statFD(fd)
	if err != nil {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, err
	}
	if kindErr := allowedKind(attr.Kind); kindErr != nil {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, kindErr
	}
	if attr.UID != v.ownerUID || attr.GID != v.ownerGID {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, ErrProjectIsolation
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, err
	}
	if uint64(st.Dev) != v.device {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, ErrWrongDevice
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, ErrClosed
	}
	if v.fenced != nil {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, v.fenced
	}
	id, err := randomCapability(v.objects)
	if err != nil {
		_ = unix.Close(fd)
		return Capability{}, Attr{}, err
	}
	v.objects[id] = object{fd: fd, kind: attr.Kind}
	return id, attr, nil
}

func allowedKind(kind Kind) error {
	switch kind {
	case KindRegular, KindDirectory, KindSymlink:
		return nil
	default:
		return ErrForbiddenType
	}
}

func (v *Volume) Lookup(parent Capability, name string) (Capability, Attr, error) {
	v.namespace.RLock()
	defer v.namespace.RUnlock()
	fd, err := v.openChild(parent, name)
	if err != nil {
		return Capability{}, Attr{}, err
	}
	return v.installObject(fd)
}

func (v *Volume) Forget(id Capability) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	if id == v.root {
		return nil
	}
	obj, ok := v.objects[id]
	if !ok {
		return ErrStaleObject
	}
	delete(v.objects, id)
	return unix.Close(obj.fd)
}

func (v *Volume) Getattr(id Capability) (Attr, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	obj, err := v.objectLocked(id)
	if err != nil {
		return Attr{}, err
	}
	return statFD(obj.fd)
}

// Identity is stable for every hard-link alias during this mounted XFS
// lifetime. It is coordination identity only, never authorization.
func (v *Volume) Identity(id Capability) ([16]byte, error) {
	attr, err := v.Getattr(id)
	if err != nil {
		return [16]byte{}, err
	}
	return identityFromAttr(attr), nil
}

func (v *Volume) IdentityOpen(id Capability) ([16]byte, error) {
	attr, err := v.GetattrOpen(id)
	if err != nil {
		return [16]byte{}, err
	}
	return identityFromAttr(attr), nil
}

func identityFromAttr(attr Attr) [16]byte {
	var identity [16]byte
	binary.BigEndian.PutUint32(identity[0:4], attr.DeviceMajor)
	binary.BigEndian.PutUint32(identity[4:8], attr.DeviceMinor)
	binary.BigEndian.PutUint64(identity[8:16], attr.Ino)
	return identity
}

func statFD(fd int) (Attr, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW,
		unix.STATX_BASIC_STATS|unix.STATX_BTIME, &st); err != nil {
		return Attr{}, err
	}
	return attrFromStatx(st)
}

func statChild(dirFD int, name string) (Attr, error) {
	var st unix.Statx_t
	if err := unix.Statx(dirFD, name, unix.AT_SYMLINK_NOFOLLOW,
		unix.STATX_BASIC_STATS|unix.STATX_BTIME, &st); err != nil {
		return Attr{}, err
	}
	return attrFromStatx(st)
}

func attrFromStatx(st unix.Statx_t) (Attr, error) {
	kind, err := kindFromMode(uint32(st.Mode))
	if err != nil {
		return Attr{}, err
	}
	return Attr{
		Kind: kind, Ino: st.Ino, Size: int64(st.Size), Blocks: st.Blocks,
		Mode: modeFromUnix(uint32(st.Mode)), UID: st.Uid, GID: st.Gid, Nlink: st.Nlink,
		DeviceMajor: st.Dev_major, DeviceMinor: st.Dev_minor,
		ATimeNS: timestampNS(st.Atime), MTimeNS: timestampNS(st.Mtime),
		CTimeNS: timestampNS(st.Ctime), BirthTimeNS: timestampNS(st.Btime),
	}, nil
}

func timestampNS(ts unix.StatxTimestamp) int64 { return ts.Sec*1e9 + int64(ts.Nsec) }

func kindFromMode(mode uint32) (Kind, error) {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return KindRegular, nil
	case unix.S_IFDIR:
		return KindDirectory, nil
	case unix.S_IFLNK:
		return KindSymlink, nil
	default:
		return 0, ErrForbiddenType
	}
}

func modeFromUnix(mode uint32) fs.FileMode {
	m := fs.FileMode(mode & 0o777)
	if mode&unix.S_ISUID != 0 {
		m |= fs.ModeSetuid
	}
	if mode&unix.S_ISGID != 0 {
		m |= fs.ModeSetgid
	}
	if mode&unix.S_ISVTX != 0 {
		m |= fs.ModeSticky
	}
	return m
}

func modeToUnix(mode fs.FileMode) uint32 {
	m := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		m |= unix.S_ISUID
	}
	if mode&fs.ModeSetgid != 0 {
		m |= unix.S_ISGID
	}
	if mode&fs.ModeSticky != 0 {
		m |= unix.S_ISVTX
	}
	return m
}

func procFDPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

func reopen(fd, flags int) (int, error) {
	opened, err := unix.Open(procFDPath(fd), flags|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return -1, err
	}
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		_ = unix.Close(opened)
		return -1, err
	}
	if err := unix.Fstat(opened, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		_ = unix.Close(opened)
		if err != nil {
			return -1, err
		}
		return -1, ErrStaleObject
	}
	return opened, nil
}

func (v *Volume) OpenFile(id Capability, flags OpenFlags) (Capability, error) {
	if !flags.Read && !flags.Write {
		return Capability{}, fs.ErrInvalid
	}
	if flags.Append && !flags.Write || flags.Truncate && !flags.Write {
		return Capability{}, fs.ErrInvalid
	}
	v.mu.RLock()
	obj, err := v.objectLocked(id)
	if err != nil {
		v.mu.RUnlock()
		return Capability{}, err
	}
	if obj.kind != KindRegular && obj.kind != KindDirectory {
		v.mu.RUnlock()
		return Capability{}, ErrForbiddenType
	}
	linuxFlags := unix.O_RDONLY
	if flags.Read && flags.Write {
		linuxFlags = unix.O_RDWR
	} else if flags.Write {
		linuxFlags = unix.O_WRONLY
	}
	if flags.Append {
		linuxFlags |= unix.O_APPEND
	}
	if flags.Truncate {
		linuxFlags |= unix.O_TRUNC
	}
	if flags.Sync {
		linuxFlags |= unix.O_SYNC
	}
	if flags.DataSync {
		linuxFlags |= unix.O_DSYNC
	}
	if obj.kind == KindDirectory {
		linuxFlags |= unix.O_DIRECTORY
	}
	fd, err := reopen(obj.fd, linuxFlags)
	v.mu.RUnlock()
	if err != nil {
		return Capability{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		_ = unix.Close(fd)
		return Capability{}, ErrClosed
	}
	if v.fenced != nil {
		_ = unix.Close(fd)
		return Capability{}, v.fenced
	}
	openID, err := randomCapability(v.opens)
	if err != nil {
		_ = unix.Close(fd)
		return Capability{}, err
	}
	opened := &openFile{fd: fd, append: flags.Append, object: id, kind: obj.kind}
	if obj.kind == KindDirectory {
		opened.dir = os.NewFile(uintptr(fd), "portablefs-open-directory")
		if opened.dir == nil {
			_ = unix.Close(fd)
			return Capability{}, syscall.EBADF
		}
	}
	v.opens[openID] = opened
	return openID, nil
}

func (v *Volume) CloseOpen(id Capability) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	f, ok := v.opens[id]
	if !ok {
		return ErrStaleOpen
	}
	delete(v.opens, id)
	if f.dir != nil {
		return f.dir.Close()
	}
	return unix.Close(f.fd)
}

func (v *Volume) ReadAt(id Capability, dst []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	f, err := v.openLocked(id)
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := unix.Pread(f.fd, dst, off)
	if n == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}

func (v *Volume) WriteAt(id Capability, src []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	f, err := v.openLocked(id)
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.append {
		return 0, fs.ErrInvalid
	}
	return unix.Pwrite(f.fd, src, off)
}

// Append uses a retained O_APPEND file description and returns the offset XFS
// assigned to this write. The handle mutex keeps the following SEEK_CUR paired
// with its write even when one remote handle is used concurrently.
func (v *Volume) Append(id Capability, src []byte) (count int, assignedOffset int64, err error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	f, err := v.openLocked(id)
	if err != nil {
		return 0, 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.append {
		return 0, 0, fs.ErrInvalid
	}
	n, err := unix.Write(f.fd, src)
	if n == 0 {
		return 0, 0, err
	}
	end, seekErr := unix.Seek(f.fd, 0, io.SeekCurrent)
	if seekErr != nil {
		return n, 0, seekErr
	}
	return n, end - int64(n), err
}

func (v *Volume) Truncate(id Capability, size int64) error {
	if size < 0 {
		return fs.ErrInvalid
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	f, err := v.openLocked(id)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return unix.Ftruncate(f.fd, size)
}

func (v *Volume) Fsync(id Capability, dataOnly bool) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	f, err := v.openLocked(id)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if dataOnly {
		return unix.Fdatasync(f.fd)
	}
	return unix.Fsync(f.fd)
}

func (v *Volume) GetattrOpen(id Capability) (Attr, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	f, err := v.openLocked(id)
	if err != nil {
		return Attr{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return statFD(f.fd)
}

func (v *Volume) SyncObject(id Capability) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	obj, err := v.objectLocked(id)
	if err != nil {
		return err
	}
	fd, err := reopen(obj.fd, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

func (v *Volume) SyncFS() error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return ErrClosed
	}
	if v.fenced != nil {
		return v.fenced
	}
	return unix.Syncfs(v.rootFD)
}

// ReadDirOpen provides a sequential, verifier-checked enumeration cursor on a
// retained directory handle. Nonzero cookies are meaningful only on this open
// handle and this authority epoch.
func (v *Volume) ReadDirOpen(id Capability, cookie uint64, verifier [16]byte, max int) (entries []Dirent, next uint64, current [16]byte, eof bool, parent Capability, err error) {
	if max <= 0 {
		return nil, 0, current, false, parent, fs.ErrInvalid
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	opened, err := v.openLocked(id)
	if err != nil {
		return nil, 0, current, false, parent, err
	}
	opened.mu.Lock()
	defer opened.mu.Unlock()
	if opened.kind != KindDirectory {
		return nil, 0, current, false, parent, syscall.ENOTDIR
	}
	attr, err := statFD(opened.fd)
	if err != nil {
		return nil, 0, current, false, parent, err
	}
	binary.BigEndian.PutUint64(current[0:8], attr.Ino)
	binary.BigEndian.PutUint64(current[8:16], uint64(attr.CTimeNS))
	if verifier != ([16]byte{}) && verifier != current {
		return nil, 0, current, false, parent, syscall.ESTALE
	}
	if cookie != opened.dirCookie {
		if cookie > opened.dirHigh {
			return nil, 0, current, false, parent, syscall.ESTALE
		}
		if _, err := opened.dir.Seek(0, io.SeekStart); err != nil {
			return nil, 0, current, false, parent, err
		}
		opened.dirCookie = 0
		for opened.dirCookie < cookie {
			remaining := cookie - opened.dirCookie
			batch := 4096
			if remaining < uint64(batch) {
				batch = int(remaining)
			}
			skipped, readErr := opened.dir.ReadDir(batch)
			opened.dirCookie += uint64(len(skipped))
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return nil, 0, current, false, parent, readErr
			}
			if len(skipped) < batch {
				return nil, 0, current, false, parent, syscall.ESTALE
			}
		}
	}
	raw, readErr := opened.dir.ReadDir(max)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, 0, current, false, parent, readErr
	}
	entries = make([]Dirent, 0, len(raw))
	for _, entry := range raw {
		childAttr, err := statChild(opened.fd, entry.Name())
		if err != nil {
			return nil, 0, current, false, parent, err
		}
		entries = append(entries, Dirent{Name: entry.Name(), Kind: childAttr.Kind, Ino: childAttr.Ino})
	}
	opened.dirCookie += uint64(len(entries))
	if opened.dirCookie > opened.dirHigh {
		opened.dirHigh = opened.dirCookie
	}
	return entries, opened.dirCookie, current, errors.Is(readErr, io.EOF), opened.object, nil
}

// StatOpenDirChild returns directory-entry metadata without allocating an
// exported object capability. Readdir therefore scales with its page size,
// not with the total number of entries enumerated.
func (v *Volume) StatOpenDirChild(id Capability, name string) (Attr, error) {
	if err := ValidateComponent(name); err != nil {
		return Attr{}, err
	}
	v.namespace.RLock()
	defer v.namespace.RUnlock()
	v.mu.RLock()
	opened, err := v.openLocked(id)
	if err != nil {
		v.mu.RUnlock()
		return Attr{}, err
	}
	if opened.kind != KindDirectory {
		v.mu.RUnlock()
		return Attr{}, syscall.ENOTDIR
	}
	fd, err := unix.Openat2(opened.fd, name, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_XDEV,
	})
	v.mu.RUnlock()
	if err != nil {
		return Attr{}, err
	}
	defer unix.Close(fd)
	attr, err := statFD(fd)
	if err != nil {
		return Attr{}, err
	}
	if attr.UID != v.ownerUID || attr.GID != v.ownerGID {
		return Attr{}, ErrProjectIsolation
	}
	return attr, allowedKind(attr.Kind)
}
