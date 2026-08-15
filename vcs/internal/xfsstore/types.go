// Package xfsstore exposes one authoritative XFS directory through
// descriptor-relative operations. It has no path-based operation API: a host
// path is accepted once, at volume bootstrap, and every later operation uses a
// server-issued object or open-handle capability.
package xfsstore

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/errnos"
)

// Every sentinel below carries the exact errno it must become at the protocol
// boundary. The errno is part of the value, so the shared wire mapping
// classifies it through errors.Is without having to recognize this package,
// and in particular without inspecting any message text.
var (
	// ENOSYS: this build of PortableFS cannot serve authoritative storage at
	// all on this platform, as opposed to failing one operation.
	ErrUnsupportedPlatform = errnos.Sentinel("xfsstore: production storage requires Linux", syscall.ENOSYS)
	// ENOTSUP: the configured root is a filesystem that cannot provide the
	// guarantees this store is built on (project quota, reflink, d_type).
	ErrNotXFS = errnos.Sentinel("xfsstore: volume root is not on XFS", syscall.ENOTSUP)
	// ENOTSUP: production mount flags are part of confinement and coherence,
	// not deployment hints. In particular, without noatime an ordinary read is
	// a hidden metadata mutation that bypasses the strict write barrier.
	ErrUnsafeMount = errnos.Sentinel("xfsstore: XFS mount is missing required safety options", syscall.ENOTSUP)
	// ESTALE: capabilities are epoch-local. A capability this epoch never
	// issued, or one issued by a closed epoch, is exactly a stale handle.
	ErrStaleObject = errnos.Sentinel("xfsstore: stale object capability", syscall.ESTALE)
	ErrStaleOpen   = errnos.Sentinel("xfsstore: stale open-handle capability", syscall.ESTALE)
	ErrClosed      = errnos.Sentinel("xfsstore: volume is closed", syscall.ESTALE)
	// EIO: fencing follows a storage failure, and the client must treat the
	// volume as broken rather than retry.
	ErrFenced = errnos.Sentinel("xfsstore: authoritative storage is fenced", syscall.EIO)
	// EXDEV: an object outside this volume's device is exactly the condition
	// rename(2) reports so callers fall back to copy+unlink.
	ErrWrongDevice = errnos.Sentinel("xfsstore: object crossed the volume device boundary", syscall.EXDEV)
	// EPERM: the object exists but is not this volume's to operate on.
	ErrProjectIsolation = errnos.Sentinel("xfsstore: XFS project inheritance does not match the volume", syscall.EPERM)
	ErrForbiddenType    = errnos.Sentinel("xfsstore: object type is not remotely accessible", syscall.EPERM)
	// ENOTSUP is what getxattr(2)/setxattr(2) report for a namespace the
	// filesystem does not serve, which is what a refused namespace is here.
	ErrForbiddenXattr = errnos.Sentinel("xfsstore: extended attribute namespace is forbidden", syscall.ENOTSUP)
)

// ErrOutcomeUncertain deliberately carries no errno: it is a marker that is
// only ever joined to the failure that produced it, and that failure supplies
// the errno. Giving it one would also make every uncertain outcome look like
// the storage EIO that fences the volume.
var ErrOutcomeUncertain = errors.New("xfsstore: operation changed XFS before a later local step failed")

// ErrWritePostApply identifies a write whose data placement and exact post
// attributes are known, but whose required post-apply step failed. The caller
// must publish the committed size before returning the embedded errno: hiding
// the successful prefix would let a kernel retain pre-write inode state and
// would make a retry duplicate already-applied bytes.
var ErrWritePostApply = errors.New("xfsstore: write committed before a required post-apply step failed")

// ErrWritePrivilege marks failure to remove a privilege-bearing mode bit or
// security.capability after a write. Unlike an ordinary durability error this
// is a security boundary: the authority must fence the storage epoch even when
// the underlying errno is not one of Linux's filesystem-fatal errnos.
var ErrWritePrivilege = errors.New("xfsstore: write could not remove inode privileges")

// outcomeUncertain marks a failure that happened after XFS was already
// modified. It refuses a nil cause so the marker can never travel alone and
// reach the wire mapping without an errno.
func outcomeUncertain(cause error) error {
	if cause == nil {
		panic("xfsstore: uncertain outcome without a cause")
	}
	return fmt.Errorf("%w: %w", ErrOutcomeUncertain, cause)
}

// Config contains provisioned identity, not tuning knobs. Project zero is
// never a production volume because XFS does not enforce project-zero limits.
type Config struct {
	ExpectedProjectID uint32
	// PortableFS v3 volumes are single-principal workspaces. Every inode is
	// owned by the unprivileged authority service identity; mount frontends
	// project that principal to the mounting user on each machine.
	ExpectedOwnerUID uint32
	ExpectedOwnerGID uint32
}

// Capability is a cryptographically random, epoch-local reference. Values are
// opaque to clients and useful only to the Volume instance that issued them.
type Capability [16]byte

type Kind uint8

const (
	KindRegular Kind = iota + 1
	KindDirectory
	KindSymlink
	// KindOpaque names a directory entry that exists in the namespace but
	// whose inode this authority never exposes: a device node, FIFO or socket
	// that some other writer placed in the tree. It appears only in Dirent,
	// never in Attr, because no capability is ever issued for such an inode.
	// Listing it keeps one non-portable inode from making a whole directory
	// unreadable, exactly as a local readdir(3) lists it and a later stat(2)
	// on it fails.
	KindOpaque
)

// Attr is the portable part of Linux statx. Change is assigned by the upper
// authority after an ordered mutation; XFS remains the metadata source.
type Attr struct {
	Kind        Kind
	Ino         uint64
	Size        int64
	Blocks      uint64
	Mode        fs.FileMode
	UID         uint32
	GID         uint32
	Nlink       uint32
	DeviceMajor uint32
	DeviceMinor uint32
	ATimeNS     int64
	MTimeNS     int64
	CTimeNS     int64
	BirthTimeNS int64
}

// ObjectCoordinate is the immutable identity needed to address one inode in
// the visibility protocol. Stable is the XFS export-handle incarnation; Ino
// and Device are the kernel-cache coordinate projected to frontends. None of
// these change for a live open file description, so the store retains them at
// object installation instead of rediscovering them with fstat before every
// write.
type ObjectCoordinate struct {
	Stable      [16]byte
	Ino         uint64
	DeviceMajor uint32
	DeviceMinor uint32
}

// WriteMode is the one per-syscall placement decision captured by the private
// kernel transaction. It is never inherited from the authority descriptor:
// fcntl(F_SETFL), RWF_APPEND, and RWF_NOAPPEND may change that decision for
// every call on the same open file description.
type WriteMode uint8

const (
	WritePositioned WriteMode = iota + 1
	WriteAppend
)

// WriteCommit is the immutable placement and durability contract captured at
// BEGIN. Sync is stronger than DataSync; callers set at most one, but the store
// treats Sync as authoritative if both are true and never inherits either bit
// from the retained descriptor.
type WriteCommit struct {
	RequestedSize uint64
	Position      uint64
	// RLimitSize is the raw Linux rlim_cur: math.MaxUint64 means
	// RLIM_INFINITY and zero is a finite zero-byte ceiling.
	RLimitSize  uint64
	FileMaxSize uint64
	Mode        WriteMode
	DataSync    bool
	Sync        bool
	// KillPrivileges implements FUSE_WRITE_KILL_SUIDGID/HANDLE_KILLPRIV_V2
	// inside the same stable-inode writer critical section as the data. It is a
	// per-call kernel decision, never retained on the open description.
	KillPrivileges bool
}

// FallocateSpec is the complete authority-side contract for one private
// SHARED fallocate request. Mode is the closed Linux fallocate bitset validated
// by the caller and again by the store. Limits are supplied independently so
// RLIMIT_FSIZE remains distinguishable from the filesystem size ceiling. Once
// the XFS syscall starts, any error may follow a partial internal transaction
// and must therefore be returned with exact post state as post-apply.
type FallocateSpec struct {
	Offset         uint64
	Length         uint64
	RLimitSize     uint64
	FileMaxSize    uint64
	Mode           uint32
	KillPrivileges bool
}

// CopyFileRangeSpec freezes both ranges and the destination growth limits for
// one whole SHARED-to-SHARED server-side copy. The store holds a canonical
// source-read/destination-write stable-identity lock set through the syscall
// and exact post-state capture.
type CopyFileRangeSpec struct {
	InputOffset    uint64
	OutputOffset   uint64
	Length         uint64
	RLimitSize     uint64
	FileMaxSize    uint64
	KillPrivileges bool
}

// WriteLimitError distinguishes the two Linux EFBIG boundaries. Crossing
// RLIMIT_FSIZE requires SIGXFSZ; crossing s_maxbytes/MAX_NON_LFS does not. Only
// the authority knows the true EOF for append, so the distinction survives the
// storage layer as typed evidence instead of being inferred from errno text.
type WriteLimitError struct{ RLimit bool }

func (e *WriteLimitError) Error() string {
	if e != nil && e.RLimit {
		return "xfsstore: write reached RLIMIT_FSIZE"
	}
	return "xfsstore: write reached filesystem size limit"
}

func (*WriteLimitError) Unwrap() error { return syscall.EFBIG }

// WriteTarget is one pinned writable open description and its immutable XFS
// identity. Pinning separates handle-table lifetime from one staged write:
// CLOSE may retire the client handle while a previously accepted transaction
// still owns the descriptor. CommitWrite is the only shared-file write
// primitive; the private kernel protocol maps one whole write syscall to one
// call even when its payload spans many transport frames.
type WriteTarget interface {
	Coordinate() ObjectCoordinate
	CommitWrite(staged io.ReaderAt, spec WriteCommit, scratch []byte) (committedSize, assignedOffset uint64, post Attr, err error)
	Close() error
}

type Dirent struct {
	Name string
	Kind Kind
	Ino  uint64
}

type FSStat struct {
	BlockSize       uint64
	Blocks          uint64
	BlocksFree      uint64
	BlocksAvailable uint64
	Files           uint64
	FilesFree       uint64
	NameMax         uint32
}

type XattrMode uint8

const (
	XattrUpsert XattrMode = iota
	XattrCreate
	XattrReplace
)

// OpenFlags is the intentionally small set of file-open behavior exposed on
// the remote protocol. Arbitrary Linux flags are never accepted from a peer.
// Sync and DataSync are immutable logical handle state: the authority keeps
// its data fd non-sticky so a fragmented transaction does not flush once per
// fragment, then performs the one operation-level sync Linux requires.
type OpenFlags struct {
	Read     bool
	Write    bool
	Append   bool
	Truncate bool
	Sync     bool
	DataSync bool
}

// RenameFlags map to renameat2's atomic behaviors.
type RenameFlags uint32

const (
	RenameNoReplace RenameFlags = 1 << iota
	RenameExchange
)
