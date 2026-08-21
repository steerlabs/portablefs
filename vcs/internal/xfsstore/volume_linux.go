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
	"math"
	"path/filepath"
	"slices"
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
	// inodeMutationStripeCount bounds the storage-side coordination state while
	// retaining parallelism between unrelated inodes. A collision only
	// serializes two mutations; it cannot merge their identities or affect
	// correctness. Keep this a power of two for the mask in inodeMutationLock.
	inodeMutationStripeCount = 4096
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
	res        *resource
	kind       Kind
	coordinate ObjectCoordinate
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
	volume     *Volume
	res        *resource
	coordinate ObjectCoordinate
	fsyncState *inodeFsyncState
	// read and write are the access this handle was opened for. They are
	// enforced here rather than left to the underlying description, because a
	// handle may be served by a creation grant whose description is wider than
	// the access that was asked for.
	read     bool
	write    bool
	sync     bool
	dataSync bool
	object   Capability
	kind     Kind

	// cursorMu serializes only the directory cursor. Regular-file operations
	// use the inode mutation stripes where size atomicity requires it; they do
	// not share a per-handle mutex.
	cursorMu sync.Mutex
	cursor   dirCursor
}

type writeTarget struct {
	volume     *Volume
	res        *resource
	coordinate ObjectCoordinate
	fsyncState *inodeFsyncState
	// mu makes Close and CommitWrite mutually exclusive. The target owns one
	// descriptor reference from PinWriteTarget until Close, and a commit must
	// not race that final release: otherwise the kernel may recycle the fd
	// number while an append transaction is still issuing fstat/pwritev2.
	mu     sync.Mutex
	closed bool
}

func (t *writeTarget) Coordinate() ObjectCoordinate { return t.coordinate }

// Getattr samples the pinned write description even after the client handle
// has closed. Restore mode uses it immediately before apply to identify the
// exact append/truncate boundary without reopening a path.
func (t *writeTarget) Getattr() (Attr, error) {
	if t == nil {
		return Attr{}, ErrStaleOpen
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.res == nil || t.closed {
		return Attr{}, ErrStaleOpen
	}
	return statFD(t.res.fd)
}

func (t *writeTarget) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.res == nil || t.closed {
		return nil
	}
	t.closed = true
	result := t.res.release()
	t.volume.releaseFsyncState(t.fsyncState)
	return result
}

func (f *openFile) fd() int { return f.res.fd }
func (f *openFile) release() {
	_ = f.res.release()
	f.volume.releaseFsyncState(f.fsyncState)
}

// Volume owns all descriptors for one authority epoch. Closing it atomically
// makes every issued capability stale.
//
// mu guards only epoch state and the capability maps. No syscall is ever
// issued while it is held, because Go's RWMutex hands the lock to a waiting
// writer ahead of new readers: one blocking read under a read lock would
// otherwise queue Fence - the emergency stop - behind gigabytes of I/O and
// every later request behind Fence.
type Volume struct {
	mu sync.RWMutex
	// inodeMutation is keyed by the immutable XFS incarnation identity, not by
	// a capability or open handle. Hard-link aliases and independently opened
	// descriptions of one inode therefore share the same EOF atomicity domain.
	// A fixed stripe array avoids an unbounded lifecycle map. Append validation
	// and every possible size-changing operation participate in this domain.
	inodeMutation [inodeMutationStripeCount]sync.RWMutex
	closed        bool
	fenced        error
	objects       map[Capability]object
	opens         map[Capability]*openFile
	fsyncMu       sync.Mutex
	fsyncStates   map[[16]byte]*inodeFsyncState

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
	// fallocate is fixed to unix.Fallocate in production. Keeping the syscall
	// seam on the Volume lets tests deterministically model XFS committing an
	// internal transaction before a later allocation step reports an error.
	fallocate               func(int, uint32, int64, int64) error
	fallocateAllocationUnit func(int) (uint64, error)
	// The write/copy seams are likewise fixed to their unix implementations in
	// production. Tests use them to model XFS running file_modified before a
	// later zero-byte data-path failure.
	pwrite                    func(int, []byte, int64) (int, error)
	pwritev2                  func(int, [][]byte, int64, int) (int, error)
	sendfile                  func(int, int, *int64, int) (int, error)
	copyFileRange             func(int, *int64, int, *int64, int, int) (int, error)
	postStat                  func(int) (Attr, error)
	fsync                     func(int) error
	fdatasync                 func(int) error
	inspectSecurityCapability func(int) (bool, error)
	// removeWritePrivileges is fixed to the package implementation in
	// production. The seam lets tests prove that a delegated killpriv failure
	// does not suppress the one logical sync attempt owed by a clean backend
	// mutation.
	removeWritePrivileges       func(int, uint32, bool) error
	removePinnedWritePrivileges func(int, uint32, bool, *bool) error
}

func inodeMutationStripe(identity [16]byte) uint64 {
	// Stable identities are uniformly opaque in production, but mix both words
	// so the non-XFS test identity (which has visible device/inode structure)
	// distributes just as well. This function chooses a lock only; identity
	// equality and authorization never depend on the hash.
	hash := binary.LittleEndian.Uint64(identity[:8]) ^ binary.LittleEndian.Uint64(identity[8:])
	hash ^= hash >> 33
	hash *= 0xff51afd7ed558ccd
	hash ^= hash >> 33
	return hash & (inodeMutationStripeCount - 1)
}

func (v *Volume) inodeMutationLock(identity [16]byte) *sync.RWMutex {
	return &v.inodeMutation[inodeMutationStripe(identity)]
}

// LockMutation takes the writer stripes for a complete touched-identity set in
// increasing stripe order. The returned release function is idempotent so an
// authority handler can retain it through replay-record persistence and still
// use one deferred cleanup path on every rejection.
func (v *Volume) LockMutation(identities [][16]byte) func() {
	stripes := make([]uint64, 0, len(identities))
	seen := make(map[uint64]struct{}, len(identities))
	for _, identity := range identities {
		stripe := inodeMutationStripe(identity)
		if _, exists := seen[stripe]; exists {
			continue
		}
		seen[stripe] = struct{}{}
		stripes = append(stripes, stripe)
	}
	slices.Sort(stripes)
	for _, stripe := range stripes {
		v.inodeMutation[stripe].Lock()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for i := len(stripes) - 1; i >= 0; i-- {
				v.inodeMutation[stripes[i]].Unlock()
			}
		})
	}
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
	v.retainFsyncState(f.fsyncState)
	return f, nil
}

func (v *Volume) fsyncState(identity [16]byte) *inodeFsyncState {
	v.fsyncMu.Lock()
	defer v.fsyncMu.Unlock()
	state := v.fsyncStates[identity]
	if state == nil {
		state = &inodeFsyncState{identity: identity}
		v.fsyncStates[identity] = state
	}
	state.refs++
	return state
}

func (v *Volume) retainFsyncState(state *inodeFsyncState) {
	if state == nil {
		return
	}
	v.fsyncMu.Lock()
	state.refs++
	v.fsyncMu.Unlock()
}

func (v *Volume) releaseFsyncState(state *inodeFsyncState) {
	if state == nil {
		return
	}
	v.fsyncMu.Lock()
	state.refs--
	if state.refs < 0 {
		v.fsyncMu.Unlock()
		panic("xfsstore: fsync state released more times than acquired")
	}
	if state.refs == 0 && v.fsyncStates[state.identity] == state {
		delete(v.fsyncStates, state.identity)
	}
	v.fsyncMu.Unlock()
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
	identity, err := stableIdentityFD(fd, v.productionIdentity)
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
		if err := qualifyAtomicAppend(fd); err != nil {
			return fail(fmt.Errorf("xfsstore: qualify RWF_APPEND: %w", err))
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
		rootFD:                      fd,
		device:                      uint64(st.Dev),
		ownerUID:                    ownerUID,
		ownerGID:                    ownerGID,
		projectID:                   expectedProjectID,
		objects:                     make(map[Capability]object),
		opens:                       make(map[Capability]*openFile),
		fsyncStates:                 make(map[[16]byte]*inodeFsyncState),
		productionIdentity:          requireXFS,
		fallocate:                   unix.Fallocate,
		fallocateAllocationUnit:     xfsFallocateAllocationUnit,
		pwrite:                      unix.Pwrite,
		pwritev2:                    unix.Pwritev2,
		sendfile:                    unix.Sendfile,
		copyFileRange:               unix.CopyFileRange,
		postStat:                    statFD,
		fsync:                       unix.Fsync,
		fdatasync:                   unix.Fdatasync,
		inspectSecurityCapability:   inspectSecurityCapability,
		removeWritePrivileges:       removeWritePrivileges,
		removePinnedWritePrivileges: removeWritePrivilegesWithCapability,
	}
	rootIdentity, err := stableIdentityFD(fd, requireXFS)
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
	v.objects[root] = object{res: newResource(fd), kind: KindDirectory, coordinate: ObjectCoordinate{
		Stable: rootIdentity, Ino: st.Ino,
		DeviceMajor: uint32(unix.Major(uint64(st.Dev))), DeviceMinor: uint32(unix.Minor(uint64(st.Dev))),
	}}
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
		v.releaseFsyncState(opened.fsyncState)
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
	installed := object{res: newResource(fd), kind: attr.Kind, coordinate: ObjectCoordinate{
		Stable: identity, Ino: attr.Ino, DeviceMajor: attr.DeviceMajor, DeviceMinor: attr.DeviceMinor,
	}}
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

// LookupOpen is Lookup with the directory named by an open handle instead of by
// the directory's own object capability.
//
// Enumerating an open directory must not depend on a reference the open does
// not itself imply. A frontend that keeps no namespace of its own -- the files
// gateway is the one in this tree -- reclaims the directory's object capability
// as soon as it holds the handle, exactly as it does for a file it is about to
// read. Reading that file keeps working because reads are answered from the
// handle; readdir was not, so it resolved each entry against a capability the
// caller had legitimately dropped and failed every page with ErrStaleObject.
func (v *Volume) LookupOpen(handle Capability, name string) (Capability, Attr, error) {
	fd, identity, err := v.openChildOfOpen(handle, name)
	if err != nil {
		return Capability{}, Attr{}, err
	}
	return v.installObject(fd, nil, identity)
}

// openChildOfOpen is openChild resolved from an open directory handle. The
// authorization that produced the handle is the same one that produced the
// object capability it was opened from, so this reaches no name the caller
// could not already reach.
func (v *Volume) openChildOfOpen(handle Capability, name string) (int, [16]byte, error) {
	if err := ValidateComponent(name); err != nil {
		return -1, [16]byte{}, err
	}
	opened, err := v.holdOpen(handle)
	if err != nil {
		return -1, [16]byte{}, err
	}
	defer opened.release()
	if opened.kind != KindDirectory {
		return -1, [16]byte{}, syscall.ENOTDIR
	}
	fd, err := openChildAt(opened.fd(), name)
	if err != nil {
		return -1, [16]byte{}, err
	}
	identity, err := stableIdentityFD(fd, v.productionIdentity)
	if err != nil {
		_ = unix.Close(fd)
		return -1, [16]byte{}, err
	}
	return fd, identity, nil
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
	coordinate, err := v.CoordinateItem(id)
	return coordinate.Stable, err
}

// CoordinateItem returns the immutable coordination facts retained when this
// object capability was installed. It deliberately performs no statx: size,
// timestamps and mode are mutable, but stable identity, inode and device are
// properties of the held incarnation itself.
func (v *Volume) CoordinateItem(id Capability) (ObjectCoordinate, error) {
	obj, err := v.holdObject(id)
	if err != nil {
		return ObjectCoordinate{}, err
	}
	defer obj.release()
	return obj.coordinate, nil
}

func (v *Volume) IdentityOpen(id Capability) ([16]byte, error) {
	coordinate, err := v.CoordinateOpen(id)
	return coordinate.Stable, err
}

// CoordinateOpen returns the immutable coordination facts retained when this
// handle's object was installed. It deliberately performs no fstat: size,
// timestamps and mode are mutable, but stable identity, inode and device are
// properties of the open incarnation itself.
func (v *Volume) CoordinateOpen(id Capability) (ObjectCoordinate, error) {
	opened, err := v.holdOpen(id)
	if err != nil {
		return ObjectCoordinate{}, err
	}
	defer opened.release()
	return opened.coordinate, nil
}

func fallbackIdentityFromAttr(attr Attr) [16]byte {
	var identity [16]byte
	binary.BigEndian.PutUint32(identity[0:4], attr.DeviceMajor)
	binary.BigEndian.PutUint32(identity[4:8], attr.DeviceMinor)
	binary.BigEndian.PutUint64(identity[8:16], attr.Ino)
	return identity
}

// stableIdentityFD copies the exact 12-byte XFS export handle plus its 4-byte
// type, derived from the open descriptor itself (AT_EMPTY_PATH). Linux export
// handles are designed for file-server identity and include XFS i_generation.
//
// The descriptor is the identity's subject, so no pathname is re-resolved: an
// earlier revision derived the handle by walking dirfd/name again and proved
// the pair still matched with a double stat, which turned an ordinary race —
// a peer unlinking the name between open and derivation — into a stale-object
// error for a healthy, held-open object. A local open(O_CREAT) never fails
// that way, and neither does this.
func stableIdentityFD(fd int, production bool) ([16]byte, error) {
	var identity [16]byte
	handle, _, err := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		// The error must be inspected before the handle: on every error path
		// NameToHandleAt returns the zero FileHandle, whose accessors
		// dereference a nil pointer.
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
	if exact {
		return packed, nil
	}
	if !production && len(handle.Bytes()) == 12 {
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
		unix.STATX_ALL, &st); err != nil {
		return Attr{}, err
	}
	return attrFromStatx(st)
}

func statChild(dirFD int, name string) (Attr, error) {
	var st unix.Statx_t
	if err := unix.Statx(dirFD, name, unix.AT_SYMLINK_NOFOLLOW,
		unix.STATX_ALL, &st); err != nil {
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
		Rdev: newEncodeDevice(st.Rdev_major, st.Rdev_minor), BlockSize: st.Blksize,
		Flags:   uint32(st.Attributes & st.Attributes_mask),
		ATimeNS: timestampNS(st.Atime), MTimeNS: timestampNS(st.Mtime),
		CTimeNS: timestampNS(st.Ctime), BirthTimeNS: timestampNS(st.Btime),
	}, nil
}

// newEncodeDevice is Linux's new_encode_dev() UAPI representation. It is not
// the authority volume's st_dev; it encodes statx's rdev pair for the inode.
func newEncodeDevice(major, minor uint32) uint32 {
	return (minor & 0xff) | (major << 8) | ((minor &^ 0xff) << 12)
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
	// O_TRUNC is serialized by the authority's full-operation mutation lease,
	// which remains held through post-state sampling and replay persistence.
	// A description this authority created the inode with already carries the
	// access the creating caller was granted, so it answers this open without
	// re-deriving anything from the mode. Sync intent is retained logically on
	// the handle instead of being installed on the fd: transactional writes may
	// span many bounded pwrite calls and must issue one aggregate sync, while
	// XFS fallocate/CFR semantics need the immutable OPEN intent once after a
	// clean operation. A sticky O_SYNC/O_DSYNC fd would flush every fragment.
	if granted := obj.grant.take(); granted != nil {
		return v.adoptGrantedDescription(obj.grant, granted, id, obj.kind, flags)
	}
	linuxFlags := unix.O_RDONLY
	if flags.Read && flags.Write {
		linuxFlags = unix.O_RDWR
	} else if flags.Write {
		linuxFlags = unix.O_WRONLY
	}
	if flags.Truncate {
		linuxFlags |= unix.O_TRUNC
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
// Append intent is deliberately not installed on the authority descriptor:
// Linux may change O_APPEND with fcntl or override it per call with RWF_APPEND
// and RWF_NOAPPEND. Only the private append transaction chooses append; the
// retained description stays position-neutral.
//
// A failed step returns the description to the grant slot instead of closing
// it. The grant is the only carrier of the access the creation conferred —
// that is what makes open(O_CREAT|O_EXCL, 0444) writable — so consuming it on
// a transient failure would permanently re-derive a later open's access from
// the mode, the exact behavior the grant exists to prevent. The truncate runs
// before handle installation so every restorable failure leaves ownership
// unambiguous and restores the original description.
func (v *Volume) adoptGrantedDescription(grant *createGrant, granted *resource, id Capability, kind Kind, flags OpenFlags) (Capability, error) {
	if flags.Truncate {
		if err := unix.Ftruncate(granted.fd, 0); err != nil {
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
		volume: v, res: res, read: flags.Read, write: flags.Write,
		sync: flags.Sync, dataSync: flags.DataSync && !flags.Sync,
		object: id, kind: kind, coordinate: obj.coordinate,
		fsyncState: v.fsyncState(obj.coordinate.Stable),
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
	result := f.res.release()
	v.releaseFsyncState(f.fsyncState)
	return result
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
	if int64(len(src)) > int64(^uint64(0)>>1)-off {
		return 0, fs.ErrInvalid
	}
	end := off + int64(len(src))
	mutation := v.inodeMutationLock(f.coordinate.Stable)
	// Writes wholly inside the current extent cannot change EOF, so they may
	// remain parallel with each other. Keep the read lock through pwrite: a
	// concurrent truncate must not turn an in-place write into an extension
	// after this check.
	mutation.RLock()
	var current unix.Stat_t
	if err := unix.Fstat(f.fd(), &current); err != nil {
		mutation.RUnlock()
		return 0, err
	}
	if end <= current.Size {
		n, err := unix.Pwrite(f.fd(), src, off)
		mutation.RUnlock()
		if n > 0 {
			f.fsyncState.applied()
		}
		return n, err
	}
	mutation.RUnlock()

	// A positional extension shares the writer side with append validation,
	// truncate and O_TRUNC. The fixed offset itself never needs revalidation;
	// taking the writer lock is solely what makes its possible EOF change
	// indivisible with those operations.
	mutation.Lock()
	defer mutation.Unlock()
	n, err := unix.Pwrite(f.fd(), src, off)
	if n > 0 {
		f.fsyncState.applied()
	}
	return n, err
}

// PinWriteTarget transfers one in-flight reference out of the handle table.
// The returned target remains valid after CloseOpen removes the capability.
func (v *Volume) PinWriteTarget(id Capability) (WriteTarget, error) {
	f, err := v.holdOpen(id)
	if err != nil {
		return nil, err
	}
	if !f.write || f.kind != KindRegular {
		f.release()
		return nil, syscall.EBADF
	}
	if err := f.fsyncState.inspectWritePrivileges(f.fd(), v.inspectSecurityCapability); err != nil {
		f.release()
		return nil, err
	}
	return &writeTarget{
		volume: v, res: f.res, coordinate: f.coordinate,
		fsyncState: f.fsyncState,
	}, nil
}

func (v *Volume) syncDescriptor(fd int, full, dataOnly bool) error {
	if full {
		return v.fsync(fd)
	}
	if dataOnly {
		return v.fdatasync(fd)
	}
	return nil
}

type writeTargetApply func(limit, assigned uint64) (committed uint64, dispatched, invalidResult bool, err error)

func (t *writeTarget) CommitWrite(staged io.ReaderAt, spec WriteCommit, scratch []byte) (uint64, uint64, Attr, error) {
	if staged == nil || spec.Mode == WriteAppend && len(scratch) == 0 {
		return 0, 0, Attr{}, fs.ErrInvalid
	}
	return t.commitWrite(spec, func(limit, assigned uint64) (uint64, bool, bool, error) {
		if spec.Mode == WritePositioned {
			stageFD, ok := staged.(interface{ Fd() uintptr })
			if !ok || stageFD.Fd() > uintptr(math.MaxInt) {
				return 0, false, false, fs.ErrInvalid
			}
			var stageStat unix.Stat_t
			if err := unix.Fstat(int(stageFD.Fd()), &stageStat); err != nil {
				return 0, false, false, err
			}
			if stageStat.Mode&unix.S_IFMT != unix.S_IFREG || stageStat.Size < int64(limit) {
				return 0, false, false, io.ErrUnexpectedEOF
			}
			// sendfile has no output-offset argument. The inode mutation lock
			// excludes every PortableFS size-changing operation while this cursor
			// is installed and consumed.
			if _, err := unix.Seek(t.res.fd, int64(assigned), io.SeekStart); err != nil {
				return 0, false, false, err
			}
			inputOffset := int64(0)
			n, copyErr := t.volume.sendfile(t.res.fd, int(stageFD.Fd()), &inputOffset, int(limit))
			invalid := false
			if n < 0 {
				if n == -1 && copyErr != nil {
					n = 0
				} else {
					invalid = true
					n = 0
				}
			}
			if uint64(n) > limit || inputOffset != int64(n) {
				invalid = true
			}
			committed := uint64(n)
			if invalid {
				return committed, true, true, syscall.EIO
			}
			if copyErr == nil && committed != limit {
				copyErr = io.ErrShortWrite
			}
			return committed, true, false, copyErr
		}

		var committed uint64
		for committed < limit {
			chunk := uint64(len(scratch))
			if remaining := limit - committed; chunk > remaining {
				chunk = remaining
			}
			buf := scratch[:int(chunk)]
			n, readErr := staged.ReadAt(buf, int64(committed))
			if n != len(buf) || readErr != nil && !errors.Is(readErr, io.EOF) {
				if committed != 0 {
					return committed, true, false, outcomeUncertain(firstError(readErr, io.ErrUnexpectedEOF))
				}
				return 0, false, false, firstError(readErr, io.ErrUnexpectedEOF)
			}
			written, writeErr := t.volume.pwritev2(t.res.fd, [][]byte{buf}, 0, unix.RWF_APPEND)
			if written > 0 {
				committed += uint64(written)
			}
			if writeErr != nil || written != len(buf) {
				if writeErr == nil {
					writeErr = io.ErrShortWrite
				}
				return committed, true, false, writeErr
			}
		}
		return committed, true, false, nil
	})
}

// CommitWriteData applies a complete one-frame write directly from the
// retained authority frame. It never creates a staging file and dispatches
// exactly one data syscall to XFS.
func (t *writeTarget) CommitWriteData(data []byte, spec WriteCommit) (uint64, uint64, Attr, error) {
	if uint64(len(data)) != spec.RequestedSize || len(data) == 0 {
		return 0, 0, Attr{}, fs.ErrInvalid
	}
	return t.commitWrite(spec, func(limit, assigned uint64) (uint64, bool, bool, error) {
		payload := data[:int(limit)]
		var n int
		var err error
		if spec.Mode == WriteAppend {
			n, err = t.volume.pwritev2(t.res.fd, [][]byte{payload}, 0, unix.RWF_APPEND)
		} else {
			n, err = t.volume.pwrite(t.res.fd, payload, int64(assigned))
		}
		invalid := false
		if n < 0 {
			if n == -1 && err != nil {
				n = 0
			} else {
				invalid = true
				n = 0
			}
		}
		if uint64(n) > limit {
			invalid = true
		}
		if invalid {
			return uint64(n), true, true, syscall.EIO
		}
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		return uint64(n), true, false, err
	})
}

func (t *writeTarget) commitWrite(spec WriteCommit, apply writeTargetApply) (uint64, uint64, Attr, error) {
	if t == nil {
		return 0, 0, Attr{}, fs.ErrInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.volume == nil || t.res == nil || t.closed || apply == nil || spec.RequestedSize == 0 ||
		spec.RequestedSize > math.MaxInt64 || spec.Position > math.MaxInt64 ||
		spec.FileMaxSize > math.MaxInt64 || spec.FileMaxSize == 0 ||
		(spec.Mode != WritePositioned && spec.Mode != WriteAppend) || spec.Mode == WriteAppend && spec.Position != 0 {
		return 0, 0, Attr{}, fs.ErrInvalid
	}
	if err := t.volume.Health(); err != nil {
		return 0, 0, Attr{}, err
	}
	before, err := statFD(t.res.fd)
	if err != nil {
		return 0, 0, Attr{}, err
	}
	if before.Kind != KindRegular || before.Size < 0 {
		return 0, 0, Attr{}, syscall.EIO
	}
	assigned := spec.Position
	if spec.Mode == WriteAppend {
		assigned = uint64(before.Size)
	}
	finiteRLimit := spec.RLimitSize != math.MaxUint64
	if finiteRLimit && assigned >= spec.RLimitSize {
		return 0, assigned, Attr{}, &WriteLimitError{RLimit: true}
	}
	if assigned >= spec.FileMaxSize {
		return 0, assigned, Attr{}, &WriteLimitError{}
	}
	limit := spec.RequestedSize
	limitedByRLimit := false
	if finiteRLimit {
		available := spec.RLimitSize - assigned
		if limit > available {
			limit = available
			limitedByRLimit = true
		}
	}
	if available := spec.FileMaxSize - assigned; limit > available {
		limit = available
		limitedByRLimit = false
	}
	committed, dispatched, invalidCopyResult, applyErr := apply(limit, assigned)
	var postApplyErr error
	if !dispatched && applyErr != nil {
		return 0, assigned, Attr{}, applyErr
	}
	if committed > limit {
		invalidCopyResult = true
		committed = limit
		applyErr = syscall.EIO
	}
	expectedPost := uint64(before.Size)
	if end := assigned + committed; end > expectedPost {
		expectedPost = end
	}
	if dispatched {
		t.fsyncState.applied()
		if err := t.fsyncState.removeWritePrivileges(t.res.fd, uint32(before.Mode), spec.KillPrivileges, t.volume.removePinnedWritePrivileges); err != nil {
			postApplyErr = err
		}
	}
	if committed != 0 {
		syncErr := t.volume.syncDescriptor(t.res.fd, spec.Sync, spec.DataSync)
		postApplyErr = errors.Join(postApplyErr, syncErr)
	}
	post, statErr := t.volume.postStat(t.res.fd)
	if statErr != nil {
		if dispatched {
			return committed, assigned, Attr{}, outcomeUncertain(statErr)
		}
		return 0, assigned, Attr{}, statErr
	}
	if post.Size < 0 || uint64(post.Size) != expectedPost {
		return committed, assigned, post, outcomeUncertain(syscall.EIO)
	}
	if invalidCopyResult {
		return committed, assigned, post, outcomeUncertain(syscall.EIO)
	}
	if committed == 0 && dispatched {
		// XFS runs file_modified/kiocb_modified before data I/O. A zero-byte
		// syscall error can therefore have changed timestamps, privilege bits,
		// or security.capability even when EOF and every data byte are intact.
		// Conservatively publish the exact post-state for every dispatched zero
		// result; only validation/staging failures before dispatch are definite
		// no-change rejections.
		cause := errors.Join(applyErr, postApplyErr)
		if cause == nil {
			cause = syscall.EIO
		}
		return 0, assigned, post, fmt.Errorf("%w: %w", ErrWritePostApply, cause)
	}
	if committed != 0 && postApplyErr != nil {
		return committed, assigned, post, fmt.Errorf("%w: %w", ErrWritePostApply, postApplyErr)
	}
	if committed < spec.RequestedSize {
		if applyErr != nil {
			return committed, assigned, post, applyErr
		}
		return committed, assigned, post, &WriteLimitError{RLimit: limitedByRLimit}
	}
	return committed, assigned, post, nil
}

func validFallocateMode(mode uint32) bool {
	switch mode {
	case 0,
		uint32(unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_ZERO_RANGE),
		uint32(unix.FALLOC_FL_ZERO_RANGE | unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_COLLAPSE_RANGE),
		uint32(unix.FALLOC_FL_INSERT_RANGE),
		uint32(unix.FALLOC_FL_UNSHARE_RANGE),
		uint32(unix.FALLOC_FL_UNSHARE_RANGE | unix.FALLOC_FL_KEEP_SIZE):
		return true
	default:
		return false
	}
}

func fallocateNeedsAlignment(mode uint32) bool {
	return mode == uint32(unix.FALLOC_FL_COLLAPSE_RANGE) || mode == uint32(unix.FALLOC_FL_INSERT_RANGE)
}

// fallocateExpectedSize performs every authoritative-EOF-dependent check in
// the same order as Linux XFS after alignment has been proven.
// Universal offset+length/s_maxbytes validation happens before this helper.
func fallocateExpectedSize(before uint64, spec FallocateSpec) (uint64, error) {
	end := spec.Offset + spec.Length
	switch spec.Mode {
	case uint32(unix.FALLOC_FL_COLLAPSE_RANGE):
		if end >= before {
			return 0, syscall.EINVAL
		}
		return before - spec.Length, nil
	case uint32(unix.FALLOC_FL_INSERT_RANGE):
		// XFS tests the resulting EOF against s_maxbytes before offset<EOF.
		if before > spec.FileMaxSize-spec.Length {
			return 0, &WriteLimitError{}
		}
		expected := before + spec.Length
		if spec.Offset >= before {
			return 0, syscall.EINVAL
		}
		if spec.RLimitSize != math.MaxUint64 && expected > spec.RLimitSize {
			return 0, &WriteLimitError{RLimit: true}
		}
		return expected, nil
	}

	expected := before
	if spec.Mode&uint32(unix.FALLOC_FL_KEEP_SIZE) == 0 && end > expected {
		expected = end
	}
	if spec.RLimitSize != math.MaxUint64 && expected > before && expected > spec.RLimitSize {
		return 0, &WriteLimitError{RLimit: true}
	}
	return expected, nil
}

// Fallocate applies one range mutation while excluding every alias that can
// change the same inode's data or EOF. XFS may commit internal allocation,
// unmap, or zeroing transactions before a later step returns an error. Once the
// syscall is dispatched, its outcome is therefore always published from an
// exact post-stat; only validation and limit checks before dispatch are definite
// no-change refusals.
func (v *Volume) Fallocate(id Capability, spec FallocateSpec) (Attr, error) {
	if spec.Length == 0 || spec.Offset > math.MaxInt64 || spec.Length > math.MaxInt64-spec.Offset ||
		spec.FileMaxSize == 0 || spec.FileMaxSize > math.MaxInt64 || !validFallocateMode(spec.Mode) {
		return Attr{}, fs.ErrInvalid
	}
	end := spec.Offset + spec.Length
	if end > spec.FileMaxSize {
		return Attr{}, &WriteLimitError{}
	}
	f, err := v.holdOpen(id)
	if err != nil {
		return Attr{}, err
	}
	defer f.release()
	if !f.write || f.kind != KindRegular {
		return Attr{}, syscall.EBADF
	}
	if err := v.Health(); err != nil {
		return Attr{}, err
	}
	before, err := statFD(f.fd())
	if err != nil {
		return Attr{}, err
	}
	if before.Kind != KindRegular || before.Size < 0 {
		return Attr{}, syscall.EIO
	}
	if fallocateNeedsAlignment(spec.Mode) {
		unit, unitErr := v.fallocateAllocationUnit(f.fd())
		if unitErr != nil {
			// Both geometry queries are read-only and run before the backend
			// fallocate dispatch. Their failure proves that no filesystem state
			// was changed, so it is a definite refusal rather than an uncertain
			// post-apply outcome.
			return Attr{}, unitErr
		}
		if spec.Offset%unit != 0 || spec.Length%unit != 0 {
			return Attr{}, syscall.EINVAL
		}
	}
	expectedSize, err := fallocateExpectedSize(uint64(before.Size), spec)
	if err != nil {
		var limit *WriteLimitError
		if errors.As(err, &limit) && limit.RLimit {
			// The caller needs this authoritative pre-size to prove an INSERT
			// RLIMIT rejection and deliver SIGXFSZ exactly once.
			return before, err
		}
		return Attr{}, err
	}
	applyErr := v.fallocate(f.fd(), spec.Mode, int64(spec.Offset), int64(spec.Length))
	privilegeErr := v.removeWritePrivileges(f.fd(), uint32(before.Mode), spec.KillPrivileges)
	var syncErr error
	if applyErr == nil {
		syncErr = v.syncDescriptor(f.fd(), f.sync, f.dataSync)
	}
	post, statErr := v.postStat(f.fd())
	if statErr != nil {
		return Attr{}, outcomeUncertain(statErr)
	}
	if post.Kind != KindRegular || post.Size < 0 {
		return post, outcomeUncertain(syscall.EIO)
	}
	if applyErr != nil || privilegeErr != nil || syncErr != nil {
		return post, fmt.Errorf("%w: %w", ErrWritePostApply, errors.Join(applyErr, privilegeErr, syncErr))
	}
	if uint64(post.Size) != expectedSize {
		return post, outcomeUncertain(syscall.EIO)
	}
	return post, nil
}

// CopyFileRange performs one server-side copy without a userspace splice or
// payload round trip. Its authority caller owns the canonical LockMutation set
// for both resolved identities through this syscall and both post-state
// samples, so the complete record belongs to one authority ordering interval.
func (v *Volume) CopyFileRange(input, output Capability, spec CopyFileRangeSpec) (uint64, Attr, error) {
	if spec.Length == 0 || spec.InputOffset > math.MaxInt64 || spec.Length > math.MaxInt64-spec.InputOffset ||
		spec.OutputOffset > math.MaxInt64 || spec.Length > math.MaxInt64-spec.OutputOffset ||
		spec.FileMaxSize == 0 || spec.FileMaxSize > math.MaxInt64 {
		return 0, Attr{}, fs.ErrInvalid
	}
	source, err := v.holdOpen(input)
	if err != nil {
		return 0, Attr{}, err
	}
	defer source.release()
	destination, err := v.holdOpen(output)
	if err != nil {
		return 0, Attr{}, err
	}
	defer destination.release()
	if !source.read || !destination.write || source.kind != KindRegular || destination.kind != KindRegular {
		return 0, Attr{}, syscall.EBADF
	}
	if err := v.Health(); err != nil {
		return 0, Attr{}, err
	}
	beforeSource, err := statFD(source.fd())
	if err != nil {
		return 0, Attr{}, err
	}
	beforeDestination, err := statFD(destination.fd())
	if err != nil {
		return 0, Attr{}, err
	}
	if beforeSource.Kind != KindRegular || beforeDestination.Kind != KindRegular ||
		beforeSource.Size < 0 || beforeDestination.Size < 0 {
		return 0, Attr{}, syscall.EIO
	}
	limit := spec.Length
	if sourceSize := uint64(beforeSource.Size); spec.InputOffset >= sourceSize {
		limit = 0
	} else if available := sourceSize - spec.InputOffset; limit > available {
		limit = available
	}
	// Linux detects same-inode overlap only after clipping the source range to
	// its authoritative EOF. The kernel cannot perform this check from a stale
	// peer inode size; doing it here avoids rejecting a request whose only
	// overlap lies in the beyond-EOF tail.
	if source.coordinate.Stable == destination.coordinate.Stable {
		inputEnd := spec.InputOffset + limit
		outputEnd := spec.OutputOffset + limit
		if spec.InputOffset < outputEnd && spec.OutputOffset < inputEnd {
			return 0, Attr{}, syscall.EINVAL
		}
	}
	// Linux generic_write_check_limits constrains the output position itself,
	// including overwrites below an already-larger EOF. Never raise a finite
	// caller RLIMIT to the destination's current size: doing so would let a
	// remote copy write past the caller's process limit without SIGXFSZ.
	// generic_write_check_limits checks RLIMIT_FSIZE before the filesystem
	// maximum, even when source-EOF clipping produced a zero-length copy.
	// Preserve that precedence so the kernel can deliver SIGXFSZ exactly once.
	if spec.RLimitSize != math.MaxUint64 {
		if spec.OutputOffset >= spec.RLimitSize {
			return 0, Attr{}, &WriteLimitError{RLimit: true}
		}
		if available := spec.RLimitSize - spec.OutputOffset; limit > available {
			limit = available
		}
	}
	if spec.OutputOffset >= spec.FileMaxSize {
		return 0, Attr{}, &WriteLimitError{}
	}
	if available := spec.FileMaxSize - spec.OutputOffset; limit > available {
		limit = available
	}
	if limit == 0 {
		return 0, Attr{}, nil
	}
	inputOffset, outputOffset := int64(spec.InputOffset), int64(spec.OutputOffset)
	n, copyErr := v.copyFileRange(source.fd(), &inputOffset, destination.fd(), &outputOffset, int(limit), 0)
	// x/sys exposes the raw Linux failure return as n == -1 alongside errno.
	// Canonicalize that ordinary zero-progress error before converting to the
	// unsigned protocol count. Every other negative/oversized result, or an
	// offset update that disagrees with the positive count, is an impossible
	// syscall outcome; capture exact post-state below, then fence it.
	invalidResult := false
	if n < 0 {
		if copyErr != nil && n == -1 {
			n = 0
		} else {
			invalidResult = true
			n = 0
		}
	}
	if uint64(n) > limit || inputOffset != int64(spec.InputOffset)+int64(n) || outputOffset != int64(spec.OutputOffset)+int64(n) {
		invalidResult = true
	}
	committed := uint64(n)
	if committed != 0 {
		// Linux cannot return a positive count and an errno from one syscall.
		// Preserve the positive prefix if a test seam or wrapper supplies both:
		// it is the observable result and must still receive logical sync.
		copyErr = nil
	}
	expectedSize := uint64(beforeDestination.Size)
	if end := spec.OutputOffset + committed; end > expectedSize {
		expectedSize = end
	}
	var postApplyErr error
	if err := v.removeWritePrivileges(destination.fd(), uint32(beforeDestination.Mode), spec.KillPrivileges); err != nil {
		postApplyErr = err
	}
	if copyErr == nil && !invalidResult {
		postApplyErr = errors.Join(postApplyErr,
			v.syncDescriptor(destination.fd(), source.sync || destination.sync, source.dataSync || destination.dataSync))
	}
	post, statErr := v.postStat(destination.fd())
	if statErr != nil {
		return committed, Attr{}, outcomeUncertain(statErr)
	}
	if post.Kind != KindRegular || post.Size < 0 || uint64(post.Size) != expectedSize {
		return committed, post, outcomeUncertain(syscall.EIO)
	}
	if invalidResult {
		return committed, post, outcomeUncertain(syscall.EIO)
	}
	if committed == 0 {
		// copy_file_range reaches file_modified on the destination before the
		// extent operation. As with WRITE, a zero data result is not proof of a
		// no-change outcome once the backend syscall was dispatched.
		cause := errors.Join(copyErr, postApplyErr)
		if cause == nil {
			cause = syscall.EIO
		}
		return 0, post, fmt.Errorf("%w: %w", ErrWritePostApply, cause)
	}
	if postApplyErr != nil {
		return committed, post, fmt.Errorf("%w: %w", ErrWritePostApply, postApplyErr)
	}
	// A positive copy result is the complete Linux result even if the syscall
	// also supplied an errno; retrying would duplicate the applied prefix.
	_ = copyErr
	return committed, post, nil
}

// removeWritePrivileges implements HANDLE_KILLPRIV_V2 on the authoritative
// inode while the same stable-identity writer stripe still excludes every
// alias, truncate, and extending write. Linux delegates capability removal on
// every modification; WRITE_KILL_SUIDGID additionally requests the caller-
// privilege-dependent mode-bit removal. SGID without group execute is the
// mandatory-locking form and is deliberately retained, matching
// setattr_should_drop_suidgid.
func inspectSecurityCapability(fd int) (bool, error) {
	// An unprivileged authority is intentionally able to own and mutate the
	// volume without CAP_SETFCAP. Linux checks permission before existence for
	// fremovexattr("security.capability"), so blindly removing an absent xattr
	// returns EPERM and would terminal-fence every ordinary write.
	if _, err := unix.Fgetxattr(fd, "security.capability", nil); err != nil {
		if !errors.Is(err, unix.ENODATA) {
			return false, fmt.Errorf("%w: inspect security.capability: %w", ErrWritePrivilege, err)
		}
		return false, nil
	}
	return true, nil
}

func removeWritePrivileges(fd int, beforeMode uint32, killSUIDGID bool) error {
	present, err := inspectSecurityCapability(fd)
	if err != nil {
		return err
	}
	return removeWritePrivilegesWithCapability(fd, beforeMode, killSUIDGID, &present)
}

func removeWritePrivilegesWithCapability(fd int, beforeMode uint32, killSUIDGID bool, securityCapability *bool) error {
	if securityCapability == nil {
		return fs.ErrInvalid
	}
	if *securityCapability {
		if err := unix.Fremovexattr(fd, "security.capability"); err != nil && !errors.Is(err, unix.ENODATA) {
			return fmt.Errorf("%w: remove security.capability: %w", ErrWritePrivilege, err)
		}
		*securityCapability = false
	}
	if !killSUIDGID {
		return nil
	}
	want := beforeMode &^ uint32(unix.S_ISUID)
	if beforeMode&uint32(unix.S_IXGRP) != 0 {
		want &^= uint32(unix.S_ISGID)
	}
	if want == beforeMode {
		return nil
	}
	if err := unix.Fchmod(fd, want&0o7777); err != nil {
		return fmt.Errorf("%w: clear set-id mode: %w", ErrWritePrivilege, err)
	}
	return nil
}

func firstError(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

func qualifyAtomicAppend(rootFD int) error {
	fd, err := unix.Openat(rootFD, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte{'a'}); err != nil {
		return err
	}
	if n, err := unix.Pwritev2(fd, [][]byte{{'b'}}, 0, unix.RWF_APPEND); err != nil || n != 1 {
		return firstError(err, io.ErrShortWrite)
	}
	var got [2]byte
	if n, err := unix.Pread(fd, got[:], 0); err != nil || n != len(got) || got != [2]byte{'a', 'b'} {
		return firstError(err, syscall.EIO)
	}
	return nil
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
	mutation := v.inodeMutationLock(f.coordinate.Stable)
	mutation.Lock()
	defer mutation.Unlock()
	return unix.Ftruncate(f.fd(), size)
}

func (v *Volume) Fsync(id Capability, dataOnly bool) error {
	_, err := v.FsyncCoalesced(id, dataOnly)
	return err
}

// FsyncCoalesced returns the number of barrier requests served by the real
// storage sync when this caller led a batch. Followers return zero. Every call
// still waits for a completed sync whose generation and class cover it.
func (v *Volume) FsyncCoalesced(id Capability, dataOnly bool) (int, error) {
	f, err := v.holdOpen(id)
	if err != nil {
		return 0, err
	}
	defer f.release()
	return f.fsyncState.barrier(f.fd(), dataOnly, v.fsync, v.fdatasync)
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
	opened.cursorMu.Lock()
	defer opened.cursorMu.Unlock()

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
