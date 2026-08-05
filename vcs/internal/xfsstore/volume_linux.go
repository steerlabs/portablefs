//go:build linux

package xfsstore

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// direntHeaderSize is the fixed prefix of struct linux_dirent64:
	// d_ino (8), d_off (8), d_reclen (2), d_type (1). Stable Linux UAPI.
	direntHeaderSize = 19
	// dirBufferSize is one getdents64(2) transfer, retained per open handle.
	dirBufferSize = 32 << 10
	// checkpointStride bounds repositioning work. The kernel directory offset
	// is remembered every this many entries, so resuming at any issued cookie
	// costs one lseek plus at most this many entry parses, whatever the
	// cookie's magnitude. Enumeration is therefore linear in the directory,
	// not quadratic.
	checkpointStride = 512
	// pageAllocationCap bounds the slice a single readdir page preallocates so
	// an absurd max cannot be turned into an allocation by a peer.
	pageAllocationCap = 512
)

// resource owns exactly one descriptor. A volume map holds one reference and
// every in-flight operation holds another for as long as it uses the
// descriptor. The descriptor is returned to the kernel when the last reference
// goes away, which is what lets Close, Forget and Fence complete immediately
// while a slow read is still running: they drop the map's reference and never
// wait for the syscall, and the syscall can never be handed a descriptor
// number the kernel has already reused.
type resource struct {
	fd   int
	refs atomic.Int64
}

func newResource(fd int) *resource {
	r := &resource{fd: fd}
	r.refs.Store(1)
	return r
}

// acquire is only ever called while the volume lock is held and the resource
// is still reachable from a volume map, so the map's own reference keeps the
// count above zero and this can never revive a closed descriptor.
func (r *resource) acquire() { r.refs.Add(1) }

func (r *resource) release() error {
	switch remaining := r.refs.Add(-1); {
	case remaining > 0:
		return nil
	case remaining < 0:
		panic("xfsstore: descriptor released more times than acquired")
	}
	return unix.Close(r.fd)
}

// object is a held reference to an installed inode. Values are copied freely;
// the descriptor stays valid until release is called exactly once.
type object struct {
	res      *resource
	kind     Kind
	identity [16]byte
	// grant is the file description this authority created the inode with,
	// for as long as no handle has taken it. See createGrant.
	grant *createGrant
}

func (o object) fd() int  { return o.res.fd }
func (o object) release() { _ = o.res.release() }

// createGrant holds the file description an inode was created with until one
// open handle takes it, or until the capability goes away unused.
//
// Access to a newly created file is granted once, by the creation, and is
// never re-derived from the mode afterwards: that is what makes
// open(O_CREAT|O_EXCL, 0444) return a writable descriptor. Re-opening the same
// inode through /proc/self/fd is a full open(2) and runs the permission check
// against the mode the caller just chose, which answers EACCES for a file the
// caller is entitled to write. The description itself is therefore the only
// thing that can carry the grant to the handle, so it is kept rather than
// closed.
type createGrant struct {
	mu  sync.Mutex
	res *resource
}

// take transfers ownership of the description to the caller, exactly once.
func (g *createGrant) take() *resource {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	res := g.res
	g.res = nil
	return res
}

// restore returns a taken description to the slot after a failed adoption.
// The grant is filled once, at creation, and taken exactly once, so the slot
// is empty for as long as the caller holds the description.
func (g *createGrant) restore(res *resource) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.res = res
}

// discard releases an unused grant. Every path that drops an object runs it,
// so an ungranted description is never leaked.
func (g *createGrant) discard() error {
	if res := g.take(); res != nil {
		return res.release()
	}
	return nil
}

type openFile struct {
	res      *resource
	identity [16]byte
	// read and write are the access this handle was opened for. They are
	// enforced here rather than left to the underlying description, because a
	// handle may be served by a creation grant whose description is wider than
	// the access that was asked for.
	read   bool
	write  bool
	append bool
	object Capability
	kind   Kind

	// mu serializes the state that only exists in this process: the append
	// offset report and the directory cursor. It deliberately does not cover
	// pread/pwrite/ftruncate/fstat, none of which touch the file description
	// offset, so one slow read on a handle cannot block another.
	mu     sync.Mutex
	cursor dirCursor
}

func (f *openFile) fd() int  { return f.res.fd }
func (f *openFile) release() { _ = f.res.release() }

// Volume owns all descriptors for one authority epoch. Closing it atomically
// makes every issued capability stale.
//
// mu guards only epoch state and the capability maps. No syscall is ever
// issued while it is held, because Go's RWMutex hands the lock to a waiting
// writer ahead of new readers: one blocking read under a read lock would
// otherwise queue Fence - the emergency stop - behind gigabytes of I/O and
// every later request behind Fence.
type Volume struct {
	mu      sync.RWMutex
	closed  bool
	fenced  error
	objects map[Capability]object
	opens   map[Capability]*openFile

	// The fields below are written once, before the Volume is reachable by
	// any other goroutine, and never again. That is what makes them safe to
	// read without mu; it is not an accident of the current call graph.
	rootFD    int
	root      Capability
	device    uint64
	ownerUID  uint32
	ownerGID  uint32
	projectID uint32
	// productionIdentity requires the exact XFS export handle shape
	// (type 129, 12 opaque bytes containing inode+generation). Tests on a
	// non-XFS filesystem may fall back to device+inode, but production never
	// does: inode reuse must create a different coordination identity.
	productionIdentity bool
}

// holdObject resolves a capability and takes a reference to its descriptor.
// The caller must release the returned object exactly once, and may issue
// syscalls on it without holding any volume lock.
func (v *Volume) holdObject(id Capability) (object, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	obj, err := v.objectLocked(id)
	if err != nil {
		return object{}, err
	}
	obj.res.acquire()
	return obj, nil
}

func (v *Volume) holdOpen(id Capability) (*openFile, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	f, err := v.openLocked(id)
	if err != nil {
		return nil, err
	}
	f.res.acquire()
	return f, nil
}

func (v *Volume) openChild(parent Capability, name string) (int, [16]byte, error) {
	if err := ValidateComponent(name); err != nil {
		return -1, [16]byte{}, err
	}
	p, err := v.holdObject(parent)
	if err != nil {
		return -1, [16]byte{}, err
	}
	defer p.release()
	if p.kind != KindDirectory {
		return -1, [16]byte{}, syscall.ENOTDIR
	}
	fd, err := openChildAt(p.fd(), name)
	if err != nil {
		return -1, [16]byte{}, err
	}
	identity, err := stableIdentityAt(p.fd(), name, fd, v.productionIdentity)
	if err != nil {
		_ = unix.Close(fd)
		return -1, [16]byte{}, err
	}
	return fd, identity, nil
}

func openChildAt(parentFD int, name string) (int, error) {
	return unix.Openat2(parentFD, name, &unix.OpenHow{
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
	return open(rootPath, true, config.ExpectedProjectID, &config)
}

// open builds the volume. A nil config selects the non-production form used by
// tests on ordinary filesystems: it adopts the root inode's own identity and
// performs no project accounting, and it is unreachable from Open.
func open(rootPath string, requireXFS bool, expectedProjectID uint32, config *Config) (*Volume, error) {
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
		requiredFlags := int64(unix.ST_NODEV | unix.ST_NOSUID | unix.ST_NOEXEC | unix.ST_NOATIME)
		if int64(statfs.Flags)&requiredFlags != requiredFlags {
			return fail(fmt.Errorf("%w: flags=%#x require=%#x", ErrUnsafeMount, statfs.Flags, requiredFlags))
		}
		// The root descriptor is opened for access, so the project ioctl is
		// available on it.
		if err := verifyProject(fd, expectedProjectID, true); err != nil {
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
	ownerUID, ownerGID := st.Uid, st.Gid
	if config != nil {
		ownerUID, ownerGID = config.ExpectedOwnerUID, config.ExpectedOwnerGID
		if st.Uid != ownerUID || st.Gid != ownerGID {
			return fail(fmt.Errorf("%w: root owner is %d:%d, expected %d:%d",
				ErrProjectIsolation, st.Uid, st.Gid, ownerUID, ownerGID))
		}
	}
	// A second authority process cannot open this root concurrently. This lock
	// complements infrastructure fencing; it is not claimed to fence another
	// host that can access shared block storage.
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(fmt.Errorf("lock volume root: %w", err))
	}

	v := &Volume{
		rootFD:             fd,
		device:             uint64(st.Dev),
		ownerUID:           ownerUID,
		ownerGID:           ownerGID,
		projectID:          expectedProjectID,
		objects:            make(map[Capability]object),
		opens:              make(map[Capability]*openFile),
		productionIdentity: requireXFS,
	}
	rootIdentity, err := stableIdentityAt(unix.AT_FDCWD, rootPath, fd, requireXFS)
	if err != nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return fail(fmt.Errorf("derive stable root identity: %w", err))
	}
	root, err := randomCapability(v.objects)
	if err != nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return fail(err)
	}
	v.root = root
	v.objects[root] = object{res: newResource(fd), kind: KindDirectory, identity: rootIdentity}
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
//
// It takes the write lock for map-free bookkeeping only, so it completes
// immediately even while slow I/O is in flight: an emergency stop that queues
// behind the work it is stopping is not an emergency stop.
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
	// Releasing the root's flock does not wait for in-flight operations: the
	// unlock takes effect on the open file description immediately, while the
	// descriptor itself survives until the last in-flight reference drops it.
	result := unix.Flock(v.rootFD, unix.LOCK_UN)
	for id, opened := range v.opens {
		result = errors.Join(result, opened.res.release())
		delete(v.opens, id)
	}
	for id, obj := range v.objects {
		result = errors.Join(result, obj.res.release(), obj.grant.discard())
		delete(v.objects, id)
	}
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

// installObject takes ownership of fd, and of grant when the caller created
// this inode, and issues a capability for them. Every check that decides
// whether this inode belongs to the volume happens here, before any capability
// exists, and independently of how the descriptor was obtained.
func (v *Volume) installObject(fd int, grant *resource, identity [16]byte) (Capability, Attr, error) {
	fail := func(err error) (Capability, Attr, error) {
		_ = unix.Close(fd)
		if grant != nil {
			_ = grant.release()
		}
		return Capability{}, Attr{}, err
	}
	attr, err := statFD(fd)
	if err != nil {
		return fail(err)
	}
	if kindErr := allowedKind(attr.Kind); kindErr != nil {
		return fail(kindErr)
	}
	if attr.UID != v.ownerUID || attr.GID != v.ownerGID {
		return fail(ErrProjectIsolation)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fail(err)
	}
	if uint64(st.Dev) != v.device {
		return fail(ErrWrongDevice)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return fail(ErrClosed)
	}
	if v.fenced != nil {
		return fail(v.fenced)
	}
	id, err := randomCapability(v.objects)
	if err != nil {
		return fail(err)
	}
	if identity == ([16]byte{}) {
		return fail(errors.New("xfsstore: object has no stable incarnation identity"))
	}
	installed := object{res: newResource(fd), kind: attr.Kind, identity: identity}
	if grant != nil {
		installed.grant = &createGrant{res: grant}
	}
	v.objects[id] = installed
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
	fd, identity, err := v.openChild(parent, name)
	if err != nil {
		return Capability{}, Attr{}, err
	}
	return v.installObject(fd, nil, identity)
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
	return errors.Join(obj.res.release(), obj.grant.discard())
}

func (v *Volume) Getattr(id Capability) (Attr, error) {
	obj, err := v.holdObject(id)
	if err != nil {
		return Attr{}, err
	}
	defer obj.release()
	return statFD(obj.fd())
}

// Identity is the stored XFS export-handle identity. XFS includes inode
// generation in that handle, so hard-link aliases compare equal while a reused
// inode number in the same authority epoch does not. It is coordination
// identity only, never authorization.
func (v *Volume) Identity(id Capability) ([16]byte, error) {
	obj, err := v.holdObject(id)
	if err != nil {
		return [16]byte{}, err
	}
	defer obj.release()
	return obj.identity, nil
}

func (v *Volume) IdentityOpen(id Capability) ([16]byte, error) {
	opened, err := v.holdOpen(id)
	if err != nil {
		return [16]byte{}, err
	}
	defer opened.release()
	return opened.identity, nil
}

func fallbackIdentityFromAttr(attr Attr) [16]byte {
	var identity [16]byte
	binary.BigEndian.PutUint32(identity[0:4], attr.DeviceMajor)
	binary.BigEndian.PutUint32(identity[4:8], attr.DeviceMinor)
	binary.BigEndian.PutUint64(identity[8:16], attr.Ino)
	return identity
}

// stableIdentityAt copies the exact 12-byte XFS export handle plus its 4-byte
// type. Linux export handles are designed for file-server identity and include
// XFS i_generation. Holding fd prevents inode reuse while the pathname handle
// is derived; the trailing stat comparison proves the path still names fd.
func stableIdentityAt(dirfd int, path string, fd int, production bool) ([16]byte, error) {
	var identity [16]byte
	handle, _, err := unix.NameToHandleAt(dirfd, path, 0)
	if err != nil {
		// The error must be inspected before the handle: on every error path
		// NameToHandleAt returns the zero FileHandle, whose accessors
		// dereference a nil pointer. ENOENT/ESTALE here is an ordinary race —
		// another mount unlinked or renamed the name between resolution and
		// handle derivation — so it is stale-object staleness, not an
		// invariant break and never a reason to take the process down.
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESTALE) {
			return identity, ErrStaleObject
		}
		if production {
			return identity, fmt.Errorf("xfsstore: XFS export handle cannot provide incarnation identity: %w", err)
		}
		attr, statErr := statFD(fd)
		if statErr != nil {
			return identity, statErr
		}
		return fallbackIdentityFromAttr(attr), nil
	}
	packed, exact := exactXFSHandleIdentity(handle.Type(), handle.Bytes())
	if exact || !production && len(handle.Bytes()) == 12 {
		var held, named unix.Stat_t
		if err := unix.Fstat(fd, &held); err != nil {
			return identity, err
		}
		if err := unix.Fstatat(dirfd, path, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return identity, err
		}
		if held.Dev != named.Dev || held.Ino != named.Ino {
			return identity, ErrStaleObject
		}
		if exact {
			return packed, nil
		}
		binary.BigEndian.PutUint32(identity[:4], uint32(handle.Type()))
		copy(identity[4:], handle.Bytes())
		return identity, nil
	}
	if production {
		return identity, fmt.Errorf("xfsstore: XFS export handle cannot provide incarnation identity: unexpected XFS export handle type=%d bytes=%d",
			handle.Type(), len(handle.Bytes()))
	}
	attr, statErr := statFD(fd)
	if statErr != nil {
		return identity, statErr
	}
	return fallbackIdentityFromAttr(attr), nil
}

func exactXFSHandleIdentity(handleType int32, raw []byte) ([16]byte, bool) {
	var identity [16]byte
	if handleType != 129 || len(raw) != 12 {
		return identity, false
	}
	binary.BigEndian.PutUint32(identity[:4], uint32(handleType))
	copy(identity[4:], raw)
	return identity, true
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

// modeToUnix refuses set-user-ID and set-group-ID outright, and it returns an
// error rather than dropping them so no caller can quietly create a file whose
// mode is not what was asked for. A PortableFS volume is a single-principal
// workspace whose inodes are owned by the authority service identity, so a
// setuid inode there is a privilege-escalation primitive handed to whoever can
// reach the underlying filesystem. The nosuid mount option that provisioning
// sets is a second line; it is not this layer's guarantee.
func modeToUnix(mode fs.FileMode) (uint32, error) {
	if mode&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
		return 0, syscall.EPERM
	}
	m := uint32(mode.Perm())
	if mode&fs.ModeSticky != 0 {
		m |= unix.S_ISVTX
	}
	return m, nil
}

// procFDPath is the only path this package constructs after bootstrap.
// /proc/self/fd is a hard requirement of the worker's mount namespace: it is
// the sole unprivileged way to turn an O_PATH descriptor into one that can
// read or write, because AT_EMPTY_PATH on open(2) does not exist and
// linkat(AT_EMPTY_PATH) needs CAP_DAC_READ_SEARCH. Open checks it once, at
// startup, so a unit built without /proc fails at boot instead of failing
// every first write far from the cause.
func procFDPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

// reopen turns an O_PATH capability descriptor into an accessible one. It
// re-stats device and inode afterwards because /proc/self/fd resolution is a
// path walk: this catches a magic link that resolved through a symlink and
// fails closed rather than serving a different inode. It also verifies XFS
// project accounting, which is possible here and only here - ioctl(2) rejects
// O_PATH descriptors with EBADF, and no unprivileged path- or statx-based way
// to read a project ID exists. Every descriptor this volume can write through,
// or charge blocks through, is produced by this function or by Create, so the
// check is not a sample: it is the boundary.
func (v *Volume) reopen(fd, flags int, kind Kind) (int, error) {
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
	if err := v.verifyProjectOf(opened, kind); err != nil {
		_ = unix.Close(opened)
		return -1, err
	}
	return opened, nil
}

// verifyProjectOf is a no-op only for the internal non-XFS constructor, which
// Open cannot reach: a production volume always carries a nonzero project.
func (v *Volume) verifyProjectOf(fd int, kind Kind) error {
	if v.projectID == 0 {
		return nil
	}
	return verifyProject(fd, v.projectID, kind == KindDirectory)
}

func (v *Volume) OpenFile(id Capability, flags OpenFlags) (Capability, error) {
	if !flags.Read && !flags.Write {
		return Capability{}, fs.ErrInvalid
	}
	if flags.Append && !flags.Write || flags.Truncate && !flags.Write {
		return Capability{}, fs.ErrInvalid
	}
	obj, err := v.holdObject(id)
	if err != nil {
		return Capability{}, err
	}
	defer obj.release()
	if obj.kind != KindRegular && obj.kind != KindDirectory {
		return Capability{}, ErrForbiddenType
	}
	// A description this authority created the inode with already carries the
	// access the creating caller was granted, so it answers this open without
	// re-deriving anything from the mode. O_SYNC and O_DSYNC are the one thing
	// it cannot be given afterwards - fcntl's F_SETFL mask excludes them - so
	// a handle that asks for them is opened fresh and the mode decides, as it
	// does for every non-creating open.
	if !flags.Sync && !flags.DataSync {
		if granted := obj.grant.take(); granted != nil {
			return v.adoptGrantedDescription(obj.grant, granted, id, obj.kind, flags)
		}
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
	fd, err := v.reopen(obj.fd(), linuxFlags, obj.kind)
	if err != nil {
		return Capability{}, err
	}
	return v.installHandle(newResource(fd), id, obj.kind, flags)
}

// adoptGrantedDescription turns the creation description into this handle.
// O_APPEND and O_TRUNC are the two open-time behaviors that still have to be
// applied to it; both are expressible on an existing description, which is why
// this is a handover and not an approximation of one.
//
// A failed step returns the description to the grant slot instead of closing
// it. The grant is the only carrier of the access the creation conferred —
// that is what makes open(O_CREAT|O_EXCL, 0444) writable — so consuming it on
// a transient failure would permanently re-derive a later open's access from
// the mode, the exact behavior the grant exists to prevent. The truncate runs
// before the flag change so every restorable failure restores a description
// whose flags are still exactly what creation produced.
func (v *Volume) adoptGrantedDescription(grant *createGrant, granted *resource, id Capability, kind Kind, flags OpenFlags) (Capability, error) {
	if flags.Truncate {
		if err := unix.Ftruncate(granted.fd, 0); err != nil {
			grant.restore(granted)
			return Capability{}, err
		}
	}
	if flags.Append {
		current, err := unix.FcntlInt(uintptr(granted.fd), unix.F_GETFL, 0)
		if err != nil {
			grant.restore(granted)
			return Capability{}, err
		}
		if _, err := unix.FcntlInt(uintptr(granted.fd), unix.F_SETFL, current|unix.O_APPEND); err != nil {
			grant.restore(granted)
			return Capability{}, err
		}
	}
	return v.installHandle(granted, id, kind, flags)
}

// installHandle takes ownership of one open file description and issues the
// handle capability for it.
func (v *Volume) installHandle(res *resource, id Capability, kind Kind, flags OpenFlags) (Capability, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	fail := func(err error) (Capability, error) {
		_ = res.release()
		return Capability{}, err
	}
	if v.closed {
		return fail(ErrClosed)
	}
	if v.fenced != nil {
		return fail(v.fenced)
	}
	openID, err := randomCapability(v.opens)
	if err != nil {
		return fail(err)
	}
	obj, ok := v.objects[id]
	if !ok {
		return fail(ErrStaleObject)
	}
	v.opens[openID] = &openFile{
		res: res, read: flags.Read, write: flags.Write, append: flags.Append,
		object: id, kind: kind, identity: obj.identity,
	}
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
	return f.res.release()
}

// ReadAt reports (0, nil) for an empty destination. io.EOF is reserved for a
// read that asked for bytes and found none, so no caller has to special-case a
// zero-length request.
func (v *Volume) ReadAt(id Capability, dst []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	f, err := v.holdOpen(id)
	if err != nil {
		return 0, err
	}
	defer f.release()
	// The handle's declared intent is what answers here. A handle served by a
	// creation grant holds a read-write description whatever it asked for, so
	// leaving the check to the description would widen every such handle.
	if !f.read {
		return 0, syscall.EBADF
	}
	if len(dst) == 0 {
		return 0, nil
	}
	n, err := unix.Pread(f.fd(), dst, off)
	if n == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}

func (v *Volume) WriteAt(id Capability, src []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	f, err := v.holdOpen(id)
	if err != nil {
		return 0, err
	}
	defer f.release()
	if !f.write {
		return 0, syscall.EBADF
	}
	if f.append {
		return 0, fs.ErrInvalid
	}
	return unix.Pwrite(f.fd(), src, off)
}

// Append uses a retained O_APPEND file description and returns the offset XFS
// assigned to this write. The handle mutex keeps the following SEEK_CUR paired
// with its write even when one remote handle is used concurrently.
func (v *Volume) Append(id Capability, src []byte) (count int, assignedOffset int64, err error) {
	f, err := v.holdOpen(id)
	if err != nil {
		return 0, 0, err
	}
	defer f.release()
	if !f.write {
		return 0, 0, syscall.EBADF
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.append {
		return 0, 0, fs.ErrInvalid
	}
	if len(src) == 0 {
		// A zero-length write is defined to change nothing, and Linux returns
		// from it before O_APPEND repositions the description, so SEEK_CUR
		// would report a stale offset. The offset this write was assigned is
		// the current end of the file.
		var st unix.Stat_t
		if err := unix.Fstat(f.fd(), &st); err != nil {
			return 0, 0, err
		}
		return 0, st.Size, nil
	}
	n, err := unix.Write(f.fd(), src)
	if n <= 0 {
		return 0, 0, err
	}
	end, seekErr := unix.Seek(f.fd(), 0, io.SeekCurrent)
	if seekErr != nil {
		return n, 0, seekErr
	}
	return n, end - int64(n), err
}

func (v *Volume) Truncate(id Capability, size int64) error {
	if size < 0 {
		return fs.ErrInvalid
	}
	f, err := v.holdOpen(id)
	if err != nil {
		return err
	}
	defer f.release()
	// ftruncate(2) reports EINVAL, not EBADF, for a descriptor that is open
	// but not for writing.
	if !f.write {
		return fs.ErrInvalid
	}
	return unix.Ftruncate(f.fd(), size)
}

func (v *Volume) Fsync(id Capability, dataOnly bool) error {
	f, err := v.holdOpen(id)
	if err != nil {
		return err
	}
	defer f.release()
	if dataOnly {
		return unix.Fdatasync(f.fd())
	}
	return unix.Fsync(f.fd())
}

func (v *Volume) GetattrOpen(id Capability) (Attr, error) {
	f, err := v.holdOpen(id)
	if err != nil {
		return Attr{}, err
	}
	defer f.release()
	return statFD(f.fd())
}

func (v *Volume) SyncObject(id Capability) error {
	obj, err := v.holdObject(id)
	if err != nil {
		return err
	}
	defer obj.release()
	flags := unix.O_RDONLY
	if obj.kind == KindDirectory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := v.reopen(obj.fd(), flags, obj.kind)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

func (v *Volume) SyncFS() error {
	root, err := v.holdObject(v.rootCapability())
	if err != nil {
		return err
	}
	defer root.release()
	return unix.Syncfs(root.fd())
}

// rootCapability is safe without the lock: v.root is written once, before the
// Volume is published.
func (v *Volume) rootCapability() Capability { return v.root }

// dirCursor is the server side of one directory enumeration. Cookies are entry
// ordinals within a snapshot that the verifier pins; checkpoints remember the
// kernel's own directory offset every checkpointStride entries so repositioning
// to an already issued cookie is a seek plus a bounded scan instead of a
// re-read of everything before it.
type dirCursor struct {
	verifier    [16]byte
	index       uint64
	high        uint64
	checkpoints []int64
	buf         []byte
	pos, end    int
}

// restart drops every position this cursor knows. It runs whenever the
// directory snapshot changes, because no offset recorded against the old
// snapshot describes a position in the new one.
func (c *dirCursor) restart(verifier [16]byte) {
	c.verifier = verifier
	c.index, c.high = 0, 0
	c.checkpoints = c.checkpoints[:0]
	c.pos, c.end = 0, 0
}

func (c *dirCursor) note(off int64) {
	if c.index == 0 || c.index%checkpointStride != 0 {
		return
	}
	if k := c.index/checkpointStride - 1; uint64(len(c.checkpoints)) == k {
		c.checkpoints = append(c.checkpoints, off)
	}
}

// rewind positions the kernel offset and resets the parse buffer together;
// they are one piece of state and drifting apart would silently skip entries.
func (c *dirCursor) rewind(fd int, off int64, index uint64) error {
	if _, err := unix.Seek(fd, off, io.SeekStart); err != nil {
		return err
	}
	c.index, c.pos, c.end = index, 0, 0
	return nil
}

// next yields one real directory entry. "." and ".." are consumed here: this
// layer enumerates children only, and a frontend that needs the two dot
// entries synthesizes them from the handle it already holds. ok is false at
// end of directory.
func (c *dirCursor) next(fd int) (name string, ino uint64, off int64, typ byte, ok bool, err error) {
	for {
		if c.pos >= c.end {
			if c.buf == nil {
				c.buf = make([]byte, dirBufferSize)
			}
			n, err := unix.Getdents(fd, c.buf)
			if err != nil {
				return "", 0, 0, 0, false, err
			}
			if n == 0 {
				return "", 0, 0, 0, false, nil
			}
			c.pos, c.end = 0, n
		}
		if c.end-c.pos < direntHeaderSize {
			return "", 0, 0, 0, false, syscall.EIO
		}
		reclen := int(binary.NativeEndian.Uint16(c.buf[c.pos+16:]))
		if reclen <= direntHeaderSize || c.pos+reclen > c.end {
			return "", 0, 0, 0, false, syscall.EIO
		}
		record := c.buf[c.pos : c.pos+reclen]
		c.pos += reclen
		raw := record[direntHeaderSize:]
		if i := bytes.IndexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}
		if len(raw) == 0 || string(raw) == "." || string(raw) == ".." {
			continue
		}
		return string(raw), binary.NativeEndian.Uint64(record),
			int64(binary.NativeEndian.Uint64(record[8:])), record[18], true, nil
	}
}

// ReadDirOpen provides a sequential, verifier-checked enumeration cursor on a
// retained directory handle. Nonzero cookies are meaningful only on this open
// handle and this authority epoch, and only together with the verifier that
// was issued with them.
//
// Entry kind and inode come from getdents64 itself. Nothing is stat'ed per
// entry, so a concurrent unlink cannot turn one entry's ENOENT into a failure
// of the whole page - a local ls does not do that - and an inode this
// authority never exposes is listed as KindOpaque instead of making the
// directory permanently unreadable.
func (v *Volume) ReadDirOpen(id Capability, cookie uint64, verifier [16]byte, max int) (entries []Dirent, next uint64, current [16]byte, eof bool, parent Capability, err error) {
	if max <= 0 {
		return nil, 0, current, false, parent, fs.ErrInvalid
	}
	opened, err := v.holdOpen(id)
	if err != nil {
		return nil, 0, current, false, parent, err
	}
	defer opened.release()
	if opened.kind != KindDirectory {
		return nil, 0, current, false, parent, syscall.ENOTDIR
	}
	opened.mu.Lock()
	defer opened.mu.Unlock()

	attr, err := statFD(opened.fd())
	if err != nil {
		return nil, 0, current, false, parent, err
	}
	binary.BigEndian.PutUint64(current[0:8], attr.Ino)
	binary.BigEndian.PutUint64(current[8:16], uint64(attr.CTimeNS))
	// The verifier is not optional past the first page. A resume is a claim
	// about a snapshot, and a client that cannot name the snapshot it is
	// resuming has no position to resume to: without this, omitting the
	// verifier bought a client silent repositioning into a directory that had
	// changed underneath it. An all-zero verifier can only mean "absent",
	// because it embeds a live inode number, which is never zero.
	switch {
	case cookie == 0:
		// Starting over needs no prior snapshot, but a client that presents
		// one is asserting it, and an assertion that is false must fail.
		if verifier != ([16]byte{}) && verifier != current {
			return nil, 0, current, false, parent, syscall.ESTALE
		}
	case verifier == ([16]byte{}):
		return nil, 0, current, false, parent, fs.ErrInvalid
	case verifier != current:
		return nil, 0, current, false, parent, syscall.ESTALE
	}
	if opened.cursor.verifier != current {
		opened.cursor.restart(current)
		if err := opened.cursor.rewind(opened.fd(), 0, 0); err != nil {
			return nil, 0, current, false, parent, err
		}
	}
	if err := opened.seekCursor(cookie); err != nil {
		return nil, 0, current, false, parent, err
	}

	capacity := max
	if capacity > pageAllocationCap {
		capacity = pageAllocationCap
	}
	entries = make([]Dirent, 0, capacity)
	for len(entries) < max {
		name, ino, off, typ, ok, err := opened.cursor.next(opened.fd())
		if err != nil {
			return nil, 0, current, false, parent, err
		}
		if !ok {
			eof = true
			break
		}
		kind, err := opened.entryKind(typ, name)
		if err != nil {
			return nil, 0, current, false, parent, err
		}
		opened.cursor.index++
		opened.cursor.note(off)
		entries = append(entries, Dirent{Name: name, Kind: kind, Ino: ino})
	}
	if opened.cursor.index > opened.cursor.high {
		opened.cursor.high = opened.cursor.index
	}
	return entries, opened.cursor.index, current, eof, v.installedParent(opened.object), nil
}

// entryKind resolves d_type. XFS with ftype - the mkfs default this store
// requires - always reports it, so the statx below is the compatibility path
// for a filesystem that does not, not a per-entry cost on the real one.
func (f *openFile) entryKind(typ byte, name string) (Kind, error) {
	switch typ {
	case unix.DT_REG:
		return KindRegular, nil
	case unix.DT_DIR:
		return KindDirectory, nil
	case unix.DT_LNK:
		return KindSymlink, nil
	case unix.DT_UNKNOWN:
		attr, err := statChild(f.fd(), name)
		switch {
		case err == nil:
			return attr.Kind, nil
		case errors.Is(err, ErrForbiddenType), errors.Is(err, syscall.ENOENT):
			// A type this authority never exposes, or an entry a concurrent
			// unlink removed between getdents and statx. Both are listed; a
			// later lookup answers for them.
			return KindOpaque, nil
		default:
			return 0, err
		}
	default:
		return KindOpaque, nil
	}
}

// seekCursor positions the enumeration at an already issued cookie. It starts
// from the nearest known position at or before the target - the live cursor
// when it has not passed the target, otherwise the last checkpoint - so the
// scan it performs is bounded by checkpointStride and never by the cookie.
func (f *openFile) seekCursor(cookie uint64) error {
	c := &f.cursor
	if cookie == c.index {
		return nil
	}
	if cookie > c.high {
		// A position this handle never issued. Repositioning to it would
		// return a page from an arbitrary place in the directory.
		return syscall.ESTALE
	}
	if cookie < c.index {
		start, off := uint64(0), int64(0)
		if k := cookie / checkpointStride; k > 0 {
			if uint64(len(c.checkpoints)) < k {
				return syscall.ESTALE
			}
			start, off = k*checkpointStride, c.checkpoints[k-1]
		}
		if err := c.rewind(f.fd(), off, start); err != nil {
			return err
		}
	}
	for c.index < cookie {
		_, _, off, _, ok, err := c.next(f.fd())
		if err != nil {
			return err
		}
		if !ok {
			// The snapshot the verifier pinned has fewer entries than the
			// cookie names, which cannot happen while the verifier holds.
			return syscall.ESTALE
		}
		c.index++
		c.note(off)
	}
	return nil
}

// installedParent answers with the directory's object capability only while it
// is still installed. After a Forget the capability is guaranteed to fail, and
// handing one back would give a caller a reference it cannot tell from a live
// one; the zero Capability is never a valid capability and says so.
func (v *Volume) installedParent(id Capability) Capability {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if _, ok := v.objects[id]; !ok {
		return Capability{}
	}
	return id
}

// StatOpenDirChild returns directory-entry metadata without allocating an
// exported object capability. Readdir therefore scales with its page size,
// not with the total number of entries enumerated.
func (v *Volume) StatOpenDirChild(id Capability, name string) (Attr, error) {
	if err := ValidateComponent(name); err != nil {
		return Attr{}, err
	}
	opened, err := v.holdOpen(id)
	if err != nil {
		return Attr{}, err
	}
	defer opened.release()
	if opened.kind != KindDirectory {
		return Attr{}, syscall.ENOTDIR
	}
	fd, err := openChildAt(opened.fd(), name)
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
