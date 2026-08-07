// Package xfsstore exposes one authoritative XFS directory through
// descriptor-relative operations. It has no path-based operation API: a host
// path is accepted once, at volume bootstrap, and every later operation uses a
// server-issued object or open-handle capability.
package xfsstore

import (
	"errors"
	"fmt"
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
