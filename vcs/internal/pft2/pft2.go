// Package pft2 implements the PFT2 immutable filesystem format: the
// digest-verified, strictly canonical object tree used as the immutable
// filesystem base for ready HistoryCuts (docs/history.md). It is not the
// ordinary-write journal format.
//
// Every metadata object is:
//
//	"PFT2" || strict-pfwire-body
//	digest = sha256(exact complete bytes)
//
// The body follows the strict deterministic pfwire rules (ascending frozen
// fields, minimal varints, omitted defaults, contiguous repeated fields,
// rejection of unknown/duplicate/out-of-order fields, malformed UTF-8,
// explicit defaults, overflow, and trailing bytes), so any accepted object
// re-encodes to identical bytes. An object reference carries the raw 32-byte
// digest and the exact encoded size; the advertised size is enforced before
// allocation and the fetched bytes are hashed before decoding.
//
// ────────────────────────────────────────────────────────────────────────────
// FROZEN SCHEMA — never renumber or reuse a field. New fields append new
// numbers; removed fields retire their number forever.
//
//	Node (top level, after the "PFT2" magic):
//	  1  kind               uint (1..14, the Kind constants)
//	  2  root               message Root            (kind 1)
//	  3  inode              message Inode           (kind 2)
//	  4  directory_leaf     message DirectoryLeaf   (kind 3)
//	  5  directory_index    message DirectoryIndex  (kind 4)
//	  6  extent_leaf        message ExtentLeaf      (kind 5)
//	  7  extent_index       message ExtentIndex     (kind 6)
//	  8  inode_index_leaf   message InodeIndexLeaf  (kind 7)
//	  9  inode_index_index  message InodeIndexIndex (kind 8)
//	 10  recovery_root      message RecoveryRoot    (kind 9)
//	 11  data_page          message DataPage        (kind 10)
//	 12  control_root       message ControlRoot     (kind 11)
//	 13  control_leaf       message ControlLeaf     (kind 12)
//	 14  control_index      message ControlIndex    (kind 13)
//	 15  xattr_leaf         message XattrLeaf       (kind 14; APPENDED —
//	                          a pre-xattr reader rejects both the kind and
//	                          the arm field, failing closed on anchors that
//	                          carry live xattr state)
//	  (exactly the one arm numbered kind+1 is present)
//
//	ObjectRef:      1 digest bytes[32]  2 size uint64
//	  (metadata refs: MinNodeBytes..MaxNodeBytes;
//	   pack refs: MinPackBytes..MaxPackBytes and size%CellBytes == 0)
//
//	Root:           1 root_inode ObjectRef   2 inode_index ObjectRef
//	                3 max_ino_seen uint64    4 inode_count uint64
//	                5 dirent_count uint64    6 logical_bytes uint64
//	                7 features   uint64 (defined mask is currently empty)
//	                8 xattr_leaves repeated ObjectRef (APPENDED; ordered
//	                  XATTR_LEAF list for filesystem-homed inodes, hence
//	                  part of the user closure and preserved by snapshots
//	                  and forks; absent when no named inode has xattrs)
//	  The filesystem root carries no session, lock, checkout, access, manager,
//	  orphan-only metadata, or future-allocation state; those live only under
//	  RecoveryRoot.
//	  max_ino_seen (wire tag 3, formerly documented as max_ino; encoding
//	  unchanged) is the monotonic allocation/observation high-water: an upper
//	  bound covering every inode id ever live — parked orphans included — not
//	  the exact maximum currently present after deletion.
//
//	Inode:          1 ino uint64   2 kind uint (1 file, 2 directory, 3 symlink)
//	                3 mode uint32 (<= 0o7777)  4 uid uint32  5 gid uint32
//	                6 nlink uint64 (1..MaxNlink)  7 size uint64
//	                8 mtime_ms sint64  9 ctime_ms sint64  10 atime_ms sint64
//	                11 directory_root ObjectRef (directory only; absent = empty)
//	                12 extent_root ObjectRef (file only; absent = no pages;
//	                   must be absent when size == 0)
//	                13 symlink_target string (symlink only; required; 1..4096
//	                   bytes, UTF-8, NUL-free; size must equal its byte length)
//	  Directory size must be 0. Every timestamp satisfies |ms| <= MaxAbsTimeMs.
//
//	DirEntry:       1 name string (1..255 bytes; UTF-8; no NUL or '/'; not "."
//	                  or "..")   2 ino uint64   3 kind uint (1..3)
//	DirectoryLeaf:  1 entries repeated DirEntry (1..MaxLeafEntries, strictly
//	                  ascending by raw name bytes; no Unicode normalization)
//	DirectoryIndexChild: 1 first_name string  2 last_name string
//	                3 child ObjectRef  4 entry_count uint64
//	DirectoryIndex: 1 children repeated DirectoryIndexChild
//	                  (MinIndexChildren..MaxIndexChildren;
//	                   child[i].last_name < child[i+1].first_name)
//
//	ExtentEntry:    1 page_offset uint64 (multiple of PageBytes,
//	                  <= MaxLogicalFileBytes-PageBytes)   2 page ObjectRef
//	ExtentLeaf:     1 entries repeated ExtentEntry (1..MaxLeafEntries,
//	                  strictly ascending page_offset)
//	ExtentIndexChild: 1 first_page uint64  2 last_page uint64
//	                3 child ObjectRef  4 entry_count uint64
//	                  (entry_count-1 <= (last_page-first_page)/PageBytes:
//	                   a PageBytes-aligned range cannot hold more entries)
//	ExtentIndex:    1 children repeated ExtentIndexChild (bounds as directory)
//
//	InodeIndexEntry: 1 ino uint64  2 inode ObjectRef
//	InodeIndexLeaf: 1 entries repeated InodeIndexEntry (ascending ino)
//	InodeIndexChild: 1 first_ino uint64  2 last_ino uint64
//	                3 child ObjectRef  4 entry_count uint64
//	InodeIndexIndex: 1 children repeated InodeIndexChild (bounds as directory)
//
//	RecoveryRoot:   1 as_of_seq uint64  2 filesystem_root ObjectRef
//	                3 control_root ObjectRef  4 orphan_index ObjectRef
//	                5 ino_namespace uint32 (1..MaxInodeNamespace)
//	                6 next_local uint64 (1..MaxInodeLocalCounter+1; the +1
//	                  value marks an exhausted namespace)
//	                7 features uint64 (defined mask is currently empty)
//	                8 xattr_leaves repeated ObjectRef (APPENDED; ordered
//	                  XATTR_LEAF list carrying the LIVE per-inode extended
//	                  attributes at the cut — keys strictly ascending ACROSS
//	                  leaves, which the loader re-verifies; absent when no
//	                  inode carries xattrs. This complete recovery copy also
//	                  includes parked open-after-unlink orphans; Root field 8
//	                  carries only filesystem-homed rows for snapshots/forks.)
//	  RecoveryRoot is never reachable from a filesystem Root; only the active
//	  journal generation's internal control anchor references it.
//
//	XattrEntry:     1 ino uint64 (1..MaxIno)
//	                2 name string (1..MaxXattrNameBytes; UTF-8; no NUL)
//	                3 value bytes (0..MaxXattrValueBytes; empty omitted)
//	XattrLeaf:      1 entries repeated XattrEntry (1..MaxLeafEntries,
//	                  strictly ascending by (ino, raw name bytes))
//
//	CellRef:        1 cell_digest bytes[32] (sha256 of the canonical 4096
//	                  logical bytes; must differ from ZeroCellDigest — an
//	                  all-zero cell is canonically a hole)
//	                2 object ObjectRef (packed immutable data object)
//	                3 object_offset uint64 (multiple of CellBytes;
//	                  object_offset+CellBytes <= object.size)
//	  The slice length is structurally exact: every cell slice is exactly
//	  CellBytes bytes of the referenced object.
//	DataPage:       1..16 cell CellRef (field k holds cell index k-1; missing
//	                  cells are holes; at least one cell present — an all-hole
//	                  page is omitted from its extent tree)
//
//	ControlKindCount: 1 kind uint64 (1..MaxControlEntryKind)  2 count uint64
//	ControlEntry:   1 key bytes (1..MaxControlKeyBytes)
//	                2 kind uint64 (1..MaxControlEntryKind)
//	                3 value bytes (0..MaxControlValueBytes; empty omitted;
//	                  payload bytes are strict PFC2 records owned by the
//	                  control layer — opaque at the PFT2 tree layer)
//	ControlLeaf:    1 entries repeated ControlEntry (ascending unique key)
//	ControlIndexChild: 1 first_key bytes  2 last_key bytes
//	                3 child ObjectRef  4 entry_count uint64
//	ControlIndex:   1 children repeated ControlIndexChild (bounds as directory)
//	ControlRoot:    1 schema uint64 (== ControlSchemaVersion)
//	                2 map_root ObjectRef (absent = empty map)
//	                3 next_checkout_epoch uint64 (1..MaxCheckoutEpoch)
//	                4 features uint64 (defined mask is currently empty)
//	                5 counts repeated ControlKindCount (ascending kind; present
//	                  exactly for kinds with entries; absent iff map_root
//	                  absent)
//	                6 db_time_floor_ms uint64 (0..MaxAbsTimeMs; the durable
//	                  database-time floor at the anchor cut, carried on the
//	                  root so it survives cuts whose reduced map is empty; 0
//	                  is canonically absent — no time fact ever journaled)
//
// ────────────────────────────────────────────────────────────────────────────
//
// Structural separation: the schema gives the filesystem Root no field that
// can name session, lock, checkout, access, manager, orphan-only metadata, or
// allocation state, and
// readers verify the node kind of every fetched reference against the edge it
// was reached through, so a Root can never resolve to a RecoveryRoot or
// control node. Beyond the kind, every fetched B+tree descent cross-checks
// the child's actual first key, last key, and entry count against the
// parent-advertised summary (strict equality; see verify.go), and the
// filesystem inode index root is pinned against the ROOT object's verified
// facts, so crafted digest-correct graphs that hide, duplicate, reorder, or
// misroute entries fail closed on the first traversal that touches them.
// Verification inspects only fetched nodes: lazy reads never scan unrelated
// subtrees, so lies behind never-fetched edges surface only when traversed.
// Nothing in this package performs object-store work on behalf of a mutation
// path: it only encodes, decodes, verifies, builds, and lazily reads
// immutable objects.
package pft2

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Magic prefixes every canonical PFT2 object; digests cover it.
var Magic = [4]byte{'P', 'F', 'T', '2'}

// Frozen format constants. These are wire-contract values: changing any of
// them is a format break.
const (
	// DigestBytes is the exact length of every SHA-256 reference digest.
	DigestBytes = 32
	// CellBytes is the exact logical (and physical slice) size of one data cell.
	CellBytes = 4096
	// CellsPerPage is the exact number of optional cell slots in one DataPage.
	CellsPerPage = 16
	// PageBytes is the logical span of one page (64 KiB).
	PageBytes = CellBytes * CellsPerPage
	// TargetNodeBytes is the builder's soft target for one encoded node.
	TargetNodeBytes = 64 << 10
	// MaxNodeBytes is the hard encoded ceiling for one metadata node.
	MaxNodeBytes = 256 << 10
	// MinNodeBytes is the smallest canonical encoded node: a minimal
	// CONTROL_ROOT is exactly 12 bytes (4 magic + 2 kind field + 2 arm
	// framing + 4 body). Any advertised metadata size below this is invalid
	// before fetching.
	MinNodeBytes = 12
	// MaxLeafEntries bounds entries in one leaf node.
	MaxLeafEntries = 4096
	// MaxIndexChildren bounds children in one index node.
	MaxIndexChildren = 256
	// MinIndexChildren is the collapse bound: an index node with fewer
	// children must be replaced by its child (or the leaf becomes the root).
	MinIndexChildren = 2
	// MaxNameBytes bounds one directory entry name.
	MaxNameBytes = 255
	// MaxSymlinkTargetBytes bounds one inline symlink target.
	MaxSymlinkTargetBytes = 4096
	// MaxTreeDepth bounds every PFT2 B+tree walk (root = depth 1).
	MaxTreeDepth = 12
	// MinPackBytes and MaxPackBytes bound one packed immutable data object;
	// pack sizes are exact multiples of CellBytes.
	MinPackBytes = CellBytes
	MaxPackBytes = 4 << 20
	// MaxLogicalFileBytes bounds one file's logical size (2^62 leaves 64-bit
	// offset+length arithmetic overflow-free).
	MaxLogicalFileBytes = uint64(1) << 62
	// MaxIno keeps every inode positive in a PostgreSQL signed BIGINT.
	MaxIno = uint64(1<<63 - 1)
	// MaxNlink bounds one inode's link count.
	MaxNlink = uint64(1<<32 - 1)
	// MaxModeBits bounds stored mode bits (permissions + setuid/setgid/sticky).
	MaxModeBits = uint32(0o7777)
	// MaxAbsTimeMs bounds every stored timestamp's absolute value.
	MaxAbsTimeMs = int64(1<<56 - 1)
	// MaxCount64 bounds every stored counter (BIGINT-safe).
	MaxCount64 = uint64(1<<63 - 1)
	// MaxControlKeyBytes / MaxControlValueBytes / MaxControlEntryKind bound
	// one control map entry.
	MaxControlKeyBytes   = 512
	MaxControlValueBytes = 4096
	MaxControlEntryKind  = 64
	// MaxXattrNameBytes / MaxXattrValueBytes bound one extended-attribute
	// entry in an XATTR_LEAF. Wire-contract mirrors of the frozen wal
	// apply-level bounds (wal.MaxXattrNameBytes / wal.MaxXattrValueBytes),
	// duplicated so the tree codec stays free of a wal import.
	MaxXattrNameBytes  = 255
	MaxXattrValueBytes = 64 << 10
	// ControlSchemaVersion is the current (only) control map schema.
	ControlSchemaVersion = 1
	// MaxCheckoutEpoch keeps checkout epochs positive BIGINT values.
	MaxCheckoutEpoch = uint64(1<<63 - 1)
	// RootIno is the fixed inode number of the filesystem root directory.
	RootIno = uint64(1)
)

// Inode namespace composition (docs/history.md "Stable inode allocation"):
//
//	ino = (namespace << 32) | localCounter
const (
	// MaxInodeNamespace bounds one branch's never-reused allocation namespace.
	// Namespace 0 is reserved for inode 1 and verified legacy inode ids.
	MaxInodeNamespace = uint32(1<<31 - 1)
	// MaxInodeLocalCounter bounds the per-namespace local counter.
	MaxInodeLocalCounter = uint64(1<<32 - 1)
)

// ZeroCellDigest is sha256 of CellBytes zero bytes. A CellRef must never carry
// it: an all-zero cell is canonically a hole.
var ZeroCellDigest = sha256.Sum256(make([]byte, CellBytes))

// Kind identifies one node type. Values are frozen wire constants.
type Kind uint8

const (
	KindRoot            Kind = 1
	KindInode           Kind = 2
	KindDirectoryLeaf   Kind = 3
	KindDirectoryIndex  Kind = 4
	KindExtentLeaf      Kind = 5
	KindExtentIndex     Kind = 6
	KindInodeIndexLeaf  Kind = 7
	KindInodeIndexIndex Kind = 8
	KindRecoveryRoot    Kind = 9
	KindDataPage        Kind = 10
	KindControlRoot     Kind = 11
	KindControlLeaf     Kind = 12
	KindControlIndex    Kind = 13
	KindXattrLeaf       Kind = 14

	minKind = KindRoot
	maxKind = KindXattrLeaf
)

// String names a kind for diagnostics.
func (k Kind) String() string {
	switch k {
	case KindRoot:
		return "ROOT"
	case KindInode:
		return "INODE"
	case KindDirectoryLeaf:
		return "DIRECTORY_LEAF"
	case KindDirectoryIndex:
		return "DIRECTORY_INDEX"
	case KindExtentLeaf:
		return "EXTENT_LEAF"
	case KindExtentIndex:
		return "EXTENT_INDEX"
	case KindInodeIndexLeaf:
		return "INODE_INDEX_LEAF"
	case KindInodeIndexIndex:
		return "INODE_INDEX_INDEX"
	case KindRecoveryRoot:
		return "RECOVERY_ROOT"
	case KindDataPage:
		return "DATA_PAGE"
	case KindControlRoot:
		return "CONTROL_ROOT"
	case KindControlLeaf:
		return "CONTROL_LEAF"
	case KindControlIndex:
		return "CONTROL_INDEX"
	case KindXattrLeaf:
		return "XATTR_LEAF"
	default:
		return fmt.Sprintf("KIND_%d", uint8(k))
	}
}

// FileKind is the inode/dirent kind enum. Values are frozen wire constants.
type FileKind uint8

const (
	FileKindRegular   FileKind = 1
	FileKindDirectory FileKind = 2
	FileKindSymlink   FileKind = 3
)

// String names a file kind for diagnostics.
func (k FileKind) String() string {
	switch k {
	case FileKindRegular:
		return "file"
	case FileKindDirectory:
		return "directory"
	case FileKindSymlink:
		return "symlink"
	default:
		return fmt.Sprintf("filekind_%d", uint8(k))
	}
}

// Error taxonomy. Wire-level canonical-encoding rejections additionally match
// pfwire.ErrMalformed.
var (
	// ErrInvalidNode classifies every structural validation rejection (both
	// encode-side and decode-side).
	ErrInvalidNode = errors.New("pft2: invalid node")
	// ErrCorrupt classifies cross-object verification failures: digest or
	// size mismatch, wrong node kind for an edge, or invariants broken
	// between a parent's advertisement and a fetched child. Fail closed.
	ErrCorrupt = errors.New("pft2: corrupt object")
	// ErrNotFound reports a missing name, inode, or key (a normal outcome).
	ErrNotFound = errors.New("pft2: not found")
	// ErrBoundExceeded reports that a caller-supplied read bound (pages,
	// bytes, entries, depth, or pending fetches) was exhausted.
	ErrBoundExceeded = errors.New("pft2: read bound exceeded")
	// ErrInodeCounterExhausted is the typed terminal error for a namespace
	// whose local counter is consumed. The counter never wraps.
	ErrInodeCounterExhausted = errors.New("pft2: inode local counter exhausted")
	// ErrInodeNamespaceExhausted is the typed terminal error for namespace
	// values outside 1..MaxInodeNamespace. Namespaces are never reused.
	ErrInodeNamespaceExhausted = errors.New("pft2: inode namespace exhausted")
	// ErrTransactionLimit reports that an explicit per-transaction editor
	// limit (edits, staged bytes, new objects/bytes) would be exceeded. The
	// check happens before the corresponding allocation.
	ErrTransactionLimit = errors.New("pft2: transaction limit exceeded")
	// ErrEditorSealed reports an operation on an editor whose transaction
	// already committed successfully.
	ErrEditorSealed = errors.New("pft2: editor already committed")
)

func transactionLimitf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrTransactionLimit, fmt.Sprintf(format, args...))
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidNode, fmt.Sprintf(format, args...))
}

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

// Ref is one object reference: the raw SHA-256 digest of the exact complete
// encoded bytes plus that exact byte count.
type Ref struct {
	Digest [DigestBytes]byte
	Size   uint64
}

// RefOf computes the reference of encoded object bytes.
func RefOf(encoded []byte) Ref {
	return Ref{Digest: sha256.Sum256(encoded), Size: uint64(len(encoded))}
}

// Hex returns the lowercase hex digest (no prefix).
func (r Ref) Hex() string { return hex.EncodeToString(r.Digest[:]) }

// IsZero reports whether the reference is entirely unset.
func (r Ref) IsZero() bool { return r == Ref{} }

// String renders the reference for diagnostics.
func (r Ref) String() string { return fmt.Sprintf("%s/%d", r.Hex(), r.Size) }

// checkNodeRefBounds enforces metadata-reference bounds before any fetch or
// allocation.
func checkNodeRefBounds(what string, r Ref) error {
	if r.Size < MinNodeBytes || r.Size > MaxNodeBytes {
		return invalidf("%s: node ref size %d outside %d..%d", what, r.Size, MinNodeBytes, MaxNodeBytes)
	}
	return nil
}

// checkPackRefBounds enforces packed-data-object reference bounds.
func checkPackRefBounds(what string, r Ref) error {
	if r.Size < MinPackBytes || r.Size > MaxPackBytes {
		return invalidf("%s: pack ref size %d outside %d..%d", what, r.Size, MinPackBytes, MaxPackBytes)
	}
	if r.Size%CellBytes != 0 {
		return invalidf("%s: pack ref size %d is not a multiple of %d", what, r.Size, CellBytes)
	}
	return nil
}

// VerifyObjectBytes checks fetched bytes against their reference: exact size
// first (before any decode work), then the digest over the complete bytes.
func VerifyObjectBytes(ref Ref, data []byte) error {
	if uint64(len(data)) != ref.Size {
		return corruptf("object %s: fetched %d bytes, advertised %d", ref.Hex(), len(data), ref.Size)
	}
	if sha256.Sum256(data) != ref.Digest {
		return corruptf("object %s: digest mismatch over %d bytes", ref.Hex(), len(data))
	}
	return nil
}
