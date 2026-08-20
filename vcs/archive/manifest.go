package archive

import (
	"errors"
)

// FormatVersion is the only manifest version this build accepts. A manifest
// carrying any other value is refused whole; there is no partial parse and no
// forward compatibility by field skipping.
const FormatVersion uint32 = 1

// Format defaults and the bounds every configured value is held to. The chunk
// size and compression parameters are per-deployment configuration recorded in
// the header, never compile-time constants, but they are still bounded: a
// manifest may not name a chunk size that is not a power of two in range, and
// may not name a window log outside what a zstd frame header can express.
const (
	DefaultChunkSizeBytes   uint32 = 1 << 23
	DefaultCompressionLevel int32  = 9
	DefaultWindowLog        uint32 = 22

	MinChunkSizeBytes   uint32 = 1 << 12
	MaxChunkSizeBytes   uint32 = 1 << 30
	MinCompressionLevel int32  = 1
	MaxCompressionLevel int32  = 22
	MinWindowLog        uint32 = 10
	MaxWindowLog        uint32 = 31
)

// Structural bounds. Every one of them is checked against the bytes actually
// remaining in the input before it is used to size an allocation, so these are
// a second ceiling rather than the only one. MaxPacks mirrors the ArchiveRecord
// bound in identity-lifecycle-and-capacity.md section 3.
const (
	MaxManifestBytes = 2 << 30
	MaxEntries       = 1 << 24
	MaxFrames        = 1 << 24
	MaxChunks        = 1 << 28
	MaxPacks         = 1024
	MaxNameBytes     = 255
	MaxLinkNameBytes = 4096
	MaxPathBytes     = 4096

	// MaxExtentsPerChunk bounds one chunk's extent list. It caps how
	// fragmented a single chunk may be; an export whose source file is more
	// fragmented than this inside one chunk fails the seal rather than
	// silently coalescing holes into data.
	MaxExtentsPerChunk = 4096

	// Xattr bounds. Only pre-existing portable user.* attributes are carried,
	// and they are carried exactly: raw name bytes and raw value bytes.
	MaxXattrsPerEntry = 64
	MaxXattrNameBytes = 255
	MaxXattrValueSize = 64 << 10

	// ModeMask is every mode bit the format carries: permissions plus the
	// set-user-ID, set-group-ID, and sticky bits. File type is carried by
	// Entry.Type, never by the mode word.
	ModeMask uint32 = 0o7777
)

// XattrPrefix is the only extended-attribute namespace the format carries.
// PortableFS exposes pre-existing user.* attributes for reading, listing, and
// removal, so dropping them across a wake would silently erase data a caller
// can see. Every other namespace is refused rather than recorded: restoring a
// security.* or trusted.* attribute onto a new placement's service identity
// would recreate a privilege decision the source host made, which is exactly
// what the ownership model refuses to carry.
const XattrPrefix = "user."

// NoFrame marks a chunk that is stored nowhere: a chunk lying wholly inside a
// hole. Such a chunk has no extents, zero length, and is implicitly hydrated at
// restore. It is the only value of ChunkRef.FrameIndex that does not index the
// frame table, and it is required exactly when Length is zero.
const NoFrame uint32 = ^uint32(0)

// ErrInvalid is the root of every rejection this package makes. Callers match
// on it; the wrapped text names the specific invariant that failed so a
// rejection is diagnosable without being ambiguous.
var ErrInvalid = errors.New("archive: invalid manifest")

// EntryType is the entry's file type. Sparseness is a property of a regular
// file's chunk extents, not a type of its own.
type EntryType uint8

const (
	TypeRegular   EntryType = 1
	TypeDirectory EntryType = 2
	TypeSymlink   EntryType = 3
)

func (t EntryType) String() string {
	switch t {
	case TypeRegular:
		return "regular"
	case TypeDirectory:
		return "directory"
	case TypeSymlink:
		return "symlink"
	default:
		return "unknown"
	}
}

// Xattr is one extended attribute. Both halves are raw bytes: an xattr name is
// a NUL-terminated string in the kernel interface but the value is arbitrary
// binary, and neither is required to be UTF-8. An entry's attributes are stored
// in strictly increasing name order, which both makes the encoding canonical
// and makes a duplicate name unrepresentable.
type Xattr struct {
	Name  []byte
	Value []byte
}

// Extent is one contiguous run of data bytes. Inside a ChunkRef, Offset is the
// spec's offsetInChunk: it is relative to the start of that chunk's logical
// span, not to the start of the file. As a whole-file extent map (what a source
// reports and what the Linux scanner produces) Offset is relative to the start
// of the file. Extent lists are always strictly increasing, non-empty, and
// non-adjacent, so one byte range has exactly one representation.
type Extent struct {
	Offset uint64
	Length uint64
}

// ChunkRef locates the bytes one file stores for one of its logical chunks.
//
// The chunk covers logical bytes [k*chunkSize, min((k+1)*chunkSize, size)) of
// its file, where k is the chunk's index in Entry.Chunks. Length is the number
// of bytes actually stored, which is the sum of the extent lengths, and equals
// the chunk's logical span only for a fully allocated chunk. The stored bytes
// are the chunk's data extents concatenated in offset order, living at
// [InnerOffset, InnerOffset+Length) of frame FrameIndex's decompressed content.
// SliceDigest is SHA-256 over exactly those stored bytes and is verified on
// every fetch; for a stored-nowhere chunk it is SHA-256 of the empty string.
type ChunkRef struct {
	FrameIndex  uint32
	InnerOffset uint64
	Length      uint64
	SliceDigest [32]byte
	Extents     []Extent
}

// Stored reports whether the chunk has bytes in a pack. A chunk that is not
// stored lies wholly inside a hole and is born hydrated at restore.
func (c ChunkRef) Stored() bool { return c.FrameIndex != NoFrame }

// Entry is one node of the namespace. The table is depth-first with entry 0 the
// volume root; ParentIndex is strictly less than the entry's own index, which
// makes acyclicity structural rather than checked. Name is one raw component,
// never a path, because a Linux name is not required to be UTF-8.
//
// HardlinkGroup is zero for an entry that is the only link to its inode, and
// otherwise a group number. Group numbers are dense from 1 and assigned in
// order of each group's first appearance in entry order, so the encoding of a
// tree is canonical. Every member of a group carries the same Nlink, Size, and
// ContentDigest, and the group's membership count equals Nlink: a dangling
// count fails the seal.
//
// ContentDigest is SHA-256 of the file's logical bytes with holes read as
// zeros for a regular file, SHA-256 of the link target for a symlink, and all
// zeros for a directory. CTimeNanos is archive metadata only and is never
// restored.
type Entry struct {
	ParentIndex   uint32
	Name          []byte
	Type          EntryType
	Size          uint64
	Mode          uint32
	MTimeNanos    int64
	CTimeNanos    int64
	LinkName      []byte
	Nlink         uint32
	HardlinkGroup uint32
	ContentDigest [32]byte
	Xattrs        []Xattr
	Chunks        []ChunkRef
}

// Frame locates one zstd frame inside one pack object. The frame checksum
// covers the whole decompressed frame and exists for cheap corruption
// localization; correctness comes from the per-slice digests. RawBlocks is a
// hint that the frame was written from raw blocks and that decompression is a
// memcpy — it is never a licence to skip the zstd decoder, because every pack
// is a plain zstd stream whether or not the hint is set.
type Frame struct {
	PackIndex          uint32
	PackOffset         uint64
	CompressedLength   uint64
	UncompressedLength uint64
	RawBlocks          bool
	XXH64Lo32          uint32
}

// PackRef is one pack object's identity. Keys are never recorded: they are
// derived locally from {volumeID, sealedEpoch, attempt} and root-provisioned
// configuration, preserving the rule that no path is ever selected by the
// network. CRC64NVME is the S3 full-object checksum, comparable against
// HeadObject without downloading the object.
type PackRef struct {
	CRC64NVME uint64
	SHA256    [32]byte
	SizeBytes uint64
}

// PriorityBoundary is the landmark that ends the wake-prefetch region. It is a
// position in the ordered pack sequence, not a single scalar offset, because a
// scalar cannot say which object it indexes once an archive shards into more
// than one pack. Prefetch reads packs [0, PackIndex) in full and pack PackIndex
// up to PackOffset: one contiguous ranged GET per object, never a multi-range
// GET, and in the ordinary single-pack archive exactly one GET.
//
// The boundary always falls on a frame boundary, and never inside or after the
// first large-file frame: files larger than one chunk are demand-recall only
// and are ordered after the prefetchable region for exactly that reason.
type PriorityBoundary struct {
	PackIndex  uint32
	PackOffset uint64
}

// Header carries the parameters every consumer needs before it can interpret a
// single entry, plus the totals the Manager's admission and display paths read
// without walking the tree.
//
// LogicalBytes is the sum of Size over distinct regular-file inodes, counting a
// hardlink group once, and LogicalInodes is the number of distinct inodes:
// these are the product-facing totals, and they describe the tree as a user
// sees it. SealedAllocatedBytes and SealedInodes are the admission-sizing
// totals: deliberately different numbers, computed the pinned way documented on
// SealedAllocation, and deliberately an over-estimate.
type Header struct {
	FormatVersion        uint32
	ChunkSizeBytes       uint32
	CompressionLevel     int32
	WindowLog            uint32
	VolumeID             [16]byte
	SealedEpoch          uint64
	Attempt              [16]byte
	LogicalBytes         uint64
	LogicalInodes        uint64
	SealedAllocatedBytes uint64
	SealedInodes         uint64
	Priority             PriorityBoundary
	Packs                []PackRef
}

// Manifest is one sealed archive attempt's complete description. Counts are not
// fields: they are the lengths of these slices, and the encoder writes them so
// that one tree model has exactly one encoding.
type Manifest struct {
	Header  Header
	Entries []Entry
	Frames  []Frame
}

// ChunkCount is the total number of chunk references across all entries. It is
// the count the header records and the bound the decoder budgets against.
func (m *Manifest) ChunkCount() uint64 {
	total := uint64(0)
	for i := range m.Entries {
		total += uint64(len(m.Entries[i].Chunks))
	}
	return total
}

// TotalPackBytes is the size of every pack object read as one concatenation.
func (m *Manifest) TotalPackBytes() uint64 {
	total := uint64(0)
	for _, pack := range m.Header.Packs {
		total += pack.SizeBytes
	}
	return total
}

// AllocationBlockBytes is the block size the sealed allocation totals round to.
// It is pinned rather than measured: an admission charge computed on the export
// host must mean the same thing on whatever host later admits the restore, and
// a number that varied with the source filesystem's geometry would not.
const AllocationBlockBytes uint64 = 4096

// MetadataBytesPerEntry is the pinned per-entry metadata allowance in the
// sealed allocation total: one block covering the inode, the parent directory
// entry, and any out-of-line symlink target. It is a deliberate over-estimate.
// The number sizes an admission charge that is released the moment a real usage
// measurement arrives, so erring high costs a little headroom for minutes and
// erring low would let a restore land on a cell that cannot hold it.
const MetadataBytesPerEntry uint64 = 4096

// SealedAllocation computes the pinned admission-sizing totals for one tree.
//
//	SealedAllocatedBytes = Σ over every stored extent of every chunk of every
//	                       entry: ceil(length / 4096) * 4096
//	                     + 4096 * entryCount
//	SealedInodes         = entryCount
//
// It is deliberately literal. Hardlink members are counted once each rather
// than once per inode, and a deduplicated file is counted for every entry that
// references the shared bytes, because the number being sized is what the
// restore target must be able to hold before anything has been measured, and
// both of those cases restore as separate allocations until the restorer
// re-establishes the links.
func SealedAllocation(entries []Entry) (allocatedBytes, inodes uint64, err error) {
	for index := range entries {
		for _, chunk := range entries[index].Chunks {
			for _, extent := range chunk.Extents {
				blocks := (extent.Length + AllocationBlockBytes - 1) / AllocationBlockBytes
				rounded, ok := checkedMul(blocks, AllocationBlockBytes)
				if !ok {
					return 0, 0, errOverflow("sealed allocation")
				}
				if allocatedBytes, ok = checkedAdd(allocatedBytes, rounded); !ok {
					return 0, 0, errOverflow("sealed allocation")
				}
			}
		}
	}
	metadata, ok := checkedMul(uint64(len(entries)), MetadataBytesPerEntry)
	if !ok {
		return 0, 0, errOverflow("sealed allocation metadata")
	}
	if allocatedBytes, ok = checkedAdd(allocatedBytes, metadata); !ok {
		return 0, 0, errOverflow("sealed allocation")
	}
	return allocatedBytes, uint64(len(entries)), nil
}
