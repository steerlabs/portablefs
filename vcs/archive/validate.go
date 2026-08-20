package archive

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/bits"
)

// emptySliceDigest is SHA-256 of the empty string: the slice digest a chunk
// that stores nothing carries, so the rule "SliceDigest is SHA-256 over the
// chunk's stored bytes" holds with no exception.
var emptySliceDigest = sha256.Sum256(nil)

var zeroDigest [32]byte

// Validate enforces every structural invariant the format guarantees. Decode
// runs it on input it has already bounds-checked, and Encode runs it before
// emitting a single byte, so the encoder can never write a manifest the decoder
// would refuse. It is exported because the Manager verifies a downloaded
// manifest's graph as part of committing ARCHIVED and must be able to run
// exactly the same checks the archiver ran.
//
// Validate does not read pack bytes; it proves the manifest describes one
// well-formed tree whose chunk and frame references are all in range and
// mutually consistent. Content correctness is proved separately by verifying a
// slice digest on every fetch.
func Validate(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("%w: nil manifest", ErrInvalid)
	}
	if err := validateHeader(&m.Header); err != nil {
		return err
	}
	if len(m.Entries) == 0 {
		return fmt.Errorf("%w: entry table is empty; a volume always has a root", ErrInvalid)
	}
	if len(m.Entries) > MaxEntries {
		return fmt.Errorf("%w: entry count %d exceeds the format bound", ErrInvalid, len(m.Entries))
	}
	if len(m.Frames) > MaxFrames {
		return fmt.Errorf("%w: frame count %d exceeds the format bound", ErrInvalid, len(m.Frames))
	}
	if err := validateFrames(m); err != nil {
		return err
	}
	if err := validateEntries(m); err != nil {
		return err
	}
	if err := validateHardlinkGroups(m); err != nil {
		return err
	}
	return validateTotals(m)
}

func validateHeader(header *Header) error {
	if header.FormatVersion != FormatVersion {
		return fmt.Errorf("%w: unsupported format version %d", ErrInvalid, header.FormatVersion)
	}
	if header.ChunkSizeBytes < MinChunkSizeBytes || header.ChunkSizeBytes > MaxChunkSizeBytes ||
		bits.OnesCount32(header.ChunkSizeBytes) != 1 {
		return fmt.Errorf("%w: chunk size %d is not a bounded power of two", ErrInvalid, header.ChunkSizeBytes)
	}
	if header.CompressionLevel < MinCompressionLevel || header.CompressionLevel > MaxCompressionLevel {
		return fmt.Errorf("%w: compression level %d is out of range", ErrInvalid, header.CompressionLevel)
	}
	if header.WindowLog < MinWindowLog || header.WindowLog > MaxWindowLog {
		return fmt.Errorf("%w: window log %d is out of range", ErrInvalid, header.WindowLog)
	}
	if header.SealedEpoch == 0 {
		return fmt.Errorf("%w: sealed epoch must be non-zero", ErrInvalid)
	}
	if header.VolumeID == [16]byte{} {
		return fmt.Errorf("%w: volume ID must be non-zero", ErrInvalid)
	}
	if header.Attempt == [16]byte{} {
		return fmt.Errorf("%w: attempt UUID must be non-zero", ErrInvalid)
	}
	if len(header.Packs) > MaxPacks {
		return fmt.Errorf("%w: pack count %d exceeds the format bound", ErrInvalid, len(header.Packs))
	}
	total := uint64(0)
	for index, pack := range header.Packs {
		if pack.SizeBytes == 0 {
			return fmt.Errorf("%w: pack %d is empty", ErrInvalid, index)
		}
		sum, ok := checkedAdd(total, pack.SizeBytes)
		if !ok {
			return errOverflow("pack sizes")
		}
		total = sum
	}
	return validatePriority(header)
}

// validatePriority holds the prefetch landmark to a real position in the pack
// sequence. An empty archive has no packs and its boundary must be the origin;
// otherwise the boundary names an existing pack and an offset inside it, where
// the end of the last pack is expressed as PackIndex == len(Packs) with a zero
// offset so that "prefetch everything" has one representation.
func validatePriority(header *Header) error {
	packCount := uint32(len(header.Packs))
	priority := header.Priority
	if priority.PackIndex == packCount {
		if priority.PackOffset != 0 {
			return fmt.Errorf("%w: priority boundary past the last pack carries a non-zero offset", ErrInvalid)
		}
		return nil
	}
	if priority.PackIndex > packCount {
		return fmt.Errorf("%w: priority boundary names pack %d of %d", ErrInvalid, priority.PackIndex, packCount)
	}
	if priority.PackOffset > header.Packs[priority.PackIndex].SizeBytes {
		return fmt.Errorf("%w: priority boundary offset %d runs past pack %d",
			ErrInvalid, priority.PackOffset, priority.PackIndex)
	}
	return nil
}

// validateFrames proves the frame table is the canonical description of a set
// of packs that are plain concatenations of frames: frames are ordered by
// (pack, offset), and within each pack they tile it exactly from zero to its
// size with no gap and no overlap. A gap would be bytes stock zstd cannot
// account for; an overlap would be two frames claiming one byte.
func validateFrames(m *Manifest) error {
	packCount := uint32(len(m.Header.Packs))
	nextPack := uint32(0)
	nextOffset := uint64(0)
	for index := range m.Frames {
		frame := &m.Frames[index]
		if frame.PackIndex >= packCount {
			return fmt.Errorf("%w: frame %d references pack %d of %d", ErrInvalid, index, frame.PackIndex, packCount)
		}
		if frame.PackIndex < nextPack {
			return fmt.Errorf("%w: frame %d is out of pack order", ErrInvalid, index)
		}
		for nextPack < frame.PackIndex {
			if nextOffset != m.Header.Packs[nextPack].SizeBytes {
				return fmt.Errorf("%w: pack %d is not fully covered by frames", ErrInvalid, nextPack)
			}
			nextPack++
			nextOffset = 0
		}
		if frame.PackOffset != nextOffset {
			return fmt.Errorf("%w: frame %d starts at %d, breaking the pack concatenation at %d",
				ErrInvalid, index, frame.PackOffset, nextOffset)
		}
		if frame.CompressedLength == 0 || frame.UncompressedLength == 0 {
			return fmt.Errorf("%w: frame %d is empty", ErrInvalid, index)
		}
		// A frame never holds more than one chunk's worth of content: large
		// files get one frame per chunk and small files share a frame only up
		// to the chunk boundary. That makes the header's chunk size the
		// decompression buffer bound every consumer can size from the header
		// alone, before it touches a pack.
		if frame.UncompressedLength > uint64(m.Header.ChunkSizeBytes) {
			return fmt.Errorf("%w: frame %d decompresses to %d bytes, past the chunk size %d",
				ErrInvalid, index, frame.UncompressedLength, m.Header.ChunkSizeBytes)
		}
		end, ok := checkedRange(frame.PackOffset, frame.CompressedLength, m.Header.Packs[frame.PackIndex].SizeBytes)
		if !ok {
			return fmt.Errorf("%w: frame %d runs past the end of pack %d", ErrInvalid, index, frame.PackIndex)
		}
		nextOffset = end
	}
	for nextPack < packCount {
		if nextOffset != m.Header.Packs[nextPack].SizeBytes {
			return fmt.Errorf("%w: pack %d is not fully covered by frames", ErrInvalid, nextPack)
		}
		nextPack++
		nextOffset = 0
	}
	return nil
}

type childKey struct {
	parent uint32
	name   string
}

func validateEntries(m *Manifest) error {
	chunkSize := uint64(m.Header.ChunkSizeBytes)
	children := make(map[childKey]struct{}, len(m.Entries))
	chunkTotal := uint64(0)
	// path is the depth-first stack of ancestor indices. An entry is in
	// depth-first order exactly when its parent is on the stack, and popping to
	// that parent is what closes the subtrees it ends. parentIndex < index
	// alone would only prove topological order; depth-first order is what the
	// format states and what lets a restorer materialize the namespace in one
	// forward pass with a single open directory handle per level.
	path := make([]uint32, 1, 16)
	for index := range m.Entries {
		entry := &m.Entries[index]
		self := uint32(index)
		if index == 0 {
			if entry.ParentIndex != 0 {
				return fmt.Errorf("%w: entry 0 is not its own parent", ErrInvalid)
			}
			if entry.Type != TypeDirectory {
				return fmt.Errorf("%w: entry 0 is not a directory", ErrInvalid)
			}
			if len(entry.Name) != 0 {
				return fmt.Errorf("%w: entry 0 must have an empty name", ErrInvalid)
			}
		} else {
			if entry.ParentIndex >= self {
				return fmt.Errorf("%w: entry %d names parent %d, which is not earlier in the table",
					ErrInvalid, index, entry.ParentIndex)
			}
			if m.Entries[entry.ParentIndex].Type != TypeDirectory {
				return fmt.Errorf("%w: entry %d has a non-directory parent %d", ErrInvalid, index, entry.ParentIndex)
			}
			for len(path) > 0 && path[len(path)-1] != entry.ParentIndex {
				path = path[:len(path)-1]
			}
			if len(path) == 0 {
				return fmt.Errorf("%w: entry %d breaks depth-first order; parent %d is not an open ancestor",
					ErrInvalid, index, entry.ParentIndex)
			}
			path = append(path, self)
			if err := validateName(entry.Name); err != nil {
				return fmt.Errorf("%w: entry %d: %s", ErrInvalid, index, err.Error())
			}
			key := childKey{parent: entry.ParentIndex, name: string(entry.Name)}
			if _, duplicate := children[key]; duplicate {
				return fmt.Errorf("%w: entry %d duplicates a name under parent %d", ErrInvalid, index, entry.ParentIndex)
			}
			children[key] = struct{}{}
		}
		if entry.Mode&^ModeMask != 0 {
			return fmt.Errorf("%w: entry %d carries mode bits outside the permission and set-ID mask", ErrInvalid, index)
		}
		if entry.Nlink == 0 {
			return fmt.Errorf("%w: entry %d has a zero link count", ErrInvalid, index)
		}
		if err := validateXattrs(entry.Xattrs, index); err != nil {
			return err
		}
		if err := validateEntryShape(m, entry, index, chunkSize); err != nil {
			return err
		}
		chunkTotal += uint64(len(entry.Chunks))
		if chunkTotal > MaxChunks {
			return fmt.Errorf("%w: chunk count exceeds the format bound", ErrInvalid)
		}
	}
	return nil
}

// validateXattrs holds an entry's attributes to the portable user.* namespace,
// to the per-entry and per-attribute bounds, and to strictly increasing name
// order, which is what makes the list canonical and a duplicate name
// unrepresentable rather than merely rejected.
func validateXattrs(xattrs []Xattr, index int) error {
	if len(xattrs) > MaxXattrsPerEntry {
		return fmt.Errorf("%w: entry %d carries %d extended attributes, past the bound of %d",
			ErrInvalid, index, len(xattrs), MaxXattrsPerEntry)
	}
	for position, xattr := range xattrs {
		if len(xattr.Name) == 0 || len(xattr.Name) > MaxXattrNameBytes {
			return fmt.Errorf("%w: entry %d extended attribute %d has an out-of-range name",
				ErrInvalid, index, position)
		}
		if bytes.IndexByte(xattr.Name, 0) >= 0 {
			return fmt.Errorf("%w: entry %d extended attribute %d has a name containing NUL",
				ErrInvalid, index, position)
		}
		if !bytes.HasPrefix(xattr.Name, []byte(XattrPrefix)) {
			return fmt.Errorf("%w: entry %d extended attribute %d is outside the %s namespace",
				ErrInvalid, index, position, XattrPrefix)
		}
		if len(xattr.Value) > MaxXattrValueSize {
			return fmt.Errorf("%w: entry %d extended attribute %d has a %d byte value, past the bound of %d",
				ErrInvalid, index, position, len(xattr.Value), MaxXattrValueSize)
		}
		if position > 0 && bytes.Compare(xattrs[position-1].Name, xattr.Name) >= 0 {
			return fmt.Errorf("%w: entry %d extended attribute %d is not strictly after its predecessor",
				ErrInvalid, index, position)
		}
	}
	return nil
}

func validateEntryShape(m *Manifest, entry *Entry, index int, chunkSize uint64) error {
	switch entry.Type {
	case TypeDirectory:
		if len(entry.LinkName) != 0 || len(entry.Chunks) != 0 || entry.HardlinkGroup != 0 {
			return fmt.Errorf("%w: entry %d is a directory carrying file state", ErrInvalid, index)
		}
		if entry.ContentDigest != zeroDigest {
			return fmt.Errorf("%w: entry %d is a directory with a non-zero content digest", ErrInvalid, index)
		}
	case TypeSymlink:
		if len(entry.LinkName) == 0 || len(entry.LinkName) > MaxLinkNameBytes {
			return fmt.Errorf("%w: entry %d has an out-of-range symlink target", ErrInvalid, index)
		}
		if bytes.IndexByte(entry.LinkName, 0) >= 0 {
			return fmt.Errorf("%w: entry %d has a symlink target containing NUL", ErrInvalid, index)
		}
		if len(entry.Chunks) != 0 || entry.HardlinkGroup != 0 {
			return fmt.Errorf("%w: entry %d is a symlink carrying file state", ErrInvalid, index)
		}
		if entry.Size != uint64(len(entry.LinkName)) {
			return fmt.Errorf("%w: entry %d symlink size does not match its target length", ErrInvalid, index)
		}
		if entry.ContentDigest != sha256.Sum256(entry.LinkName) {
			return fmt.Errorf("%w: entry %d symlink content digest does not cover its target", ErrInvalid, index)
		}
		if entry.Nlink != 1 {
			return fmt.Errorf("%w: entry %d is a symlink with link count %d", ErrInvalid, index, entry.Nlink)
		}
	case TypeRegular:
		if len(entry.LinkName) != 0 {
			return fmt.Errorf("%w: entry %d is a regular file carrying a link target", ErrInvalid, index)
		}
		if entry.HardlinkGroup == 0 && entry.Nlink != 1 {
			return fmt.Errorf("%w: entry %d has link count %d with no hardlink group", ErrInvalid, index, entry.Nlink)
		}
		if entry.HardlinkGroup != 0 && entry.Nlink < 2 {
			return fmt.Errorf("%w: entry %d is in a hardlink group with link count %d", ErrInvalid, index, entry.Nlink)
		}
		return validateChunks(m, entry, index, chunkSize)
	default:
		return fmt.Errorf("%w: entry %d has unknown type %d", ErrInvalid, index, uint8(entry.Type))
	}
	return nil
}

// validateChunks proves a regular file's chunk array covers its logical size
// exactly and that every extent describes real stored bytes: the count is
// ceil(size/chunkSize), each chunk's extents are inside that chunk's logical
// span, strictly increasing and non-adjacent so one layout has one encoding,
// the recorded length is the sum of the extent lengths, an unstored chunk is
// exactly a chunk with no extents, and a stored chunk's slice fits inside the
// frame it names.
func validateChunks(m *Manifest, entry *Entry, index int, chunkSize uint64) error {
	expected := entry.Size / chunkSize
	if entry.Size%chunkSize != 0 {
		expected++
	}
	if uint64(len(entry.Chunks)) != expected {
		return fmt.Errorf("%w: entry %d has %d chunks but its size needs %d",
			ErrInvalid, index, len(entry.Chunks), expected)
	}
	frameCount := uint32(len(m.Frames))
	for chunkIndex := range entry.Chunks {
		chunk := &entry.Chunks[chunkIndex]
		if len(chunk.Extents) > MaxExtentsPerChunk {
			return fmt.Errorf("%w: entry %d chunk %d has %d extents, past the bound of %d",
				ErrInvalid, index, chunkIndex, len(chunk.Extents), MaxExtentsPerChunk)
		}
		span := chunkSpan(entry.Size, chunkSize, chunkIndex)
		stored := uint64(0)
		previousEnd := uint64(0)
		for extentIndex, extent := range chunk.Extents {
			if extent.Length == 0 {
				return fmt.Errorf("%w: entry %d chunk %d extent %d is empty",
					ErrInvalid, index, chunkIndex, extentIndex)
			}
			if extentIndex > 0 && extent.Offset <= previousEnd {
				return fmt.Errorf("%w: entry %d chunk %d extent %d is not strictly after and apart from its predecessor",
					ErrInvalid, index, chunkIndex, extentIndex)
			}
			end, ok := checkedRange(extent.Offset, extent.Length, span)
			if !ok {
				return fmt.Errorf("%w: entry %d chunk %d extent %d runs past the chunk span %d",
					ErrInvalid, index, chunkIndex, extentIndex, span)
			}
			previousEnd = end
			if stored, ok = checkedAdd(stored, extent.Length); !ok {
				return errOverflow("chunk stored length")
			}
		}
		if stored != chunk.Length {
			return fmt.Errorf("%w: entry %d chunk %d stores %d extent bytes but records length %d",
				ErrInvalid, index, chunkIndex, stored, chunk.Length)
		}
		if chunk.Length == 0 {
			if chunk.FrameIndex != NoFrame || chunk.InnerOffset != 0 {
				return fmt.Errorf("%w: entry %d chunk %d stores nothing but names a frame location",
					ErrInvalid, index, chunkIndex)
			}
			if chunk.SliceDigest != emptySliceDigest {
				return fmt.Errorf("%w: entry %d chunk %d stores nothing but does not carry the empty digest",
					ErrInvalid, index, chunkIndex)
			}
			continue
		}
		if chunk.FrameIndex >= frameCount {
			return fmt.Errorf("%w: entry %d chunk %d references frame %d of %d",
				ErrInvalid, index, chunkIndex, chunk.FrameIndex, frameCount)
		}
		if _, ok := checkedRange(chunk.InnerOffset, chunk.Length, m.Frames[chunk.FrameIndex].UncompressedLength); !ok {
			return fmt.Errorf("%w: entry %d chunk %d runs past the end of frame %d",
				ErrInvalid, index, chunkIndex, chunk.FrameIndex)
		}
	}
	return nil
}

// validateHardlinkGroups proves every group is closed and canonically numbered.
// Group numbers are dense from 1 in order of first appearance, every member is
// a regular file, all members agree on size, link count, and content digest,
// and the number of members equals the recorded link count. A count that does
// not match its membership is the dangling case the seal must refuse: it means
// a link the archive cannot recreate.
func validateHardlinkGroups(m *Manifest) error {
	type group struct {
		firstIndex int
		members    uint32
	}
	groups := make(map[uint32]*group)
	next := uint32(1)
	for index := range m.Entries {
		entry := &m.Entries[index]
		if entry.HardlinkGroup == 0 {
			continue
		}
		existing, ok := groups[entry.HardlinkGroup]
		if !ok {
			if entry.HardlinkGroup != next {
				return fmt.Errorf("%w: entry %d opens hardlink group %d out of canonical order, expected %d",
					ErrInvalid, index, entry.HardlinkGroup, next)
			}
			next++
			groups[entry.HardlinkGroup] = &group{firstIndex: index, members: 1}
			continue
		}
		first := &m.Entries[existing.firstIndex]
		if entry.Nlink != first.Nlink || entry.Size != first.Size || entry.ContentDigest != first.ContentDigest {
			return fmt.Errorf("%w: entry %d disagrees with entry %d about their shared inode",
				ErrInvalid, index, existing.firstIndex)
		}
		existing.members++
	}
	for number, state := range groups {
		if state.members != m.Entries[state.firstIndex].Nlink {
			return fmt.Errorf("%w: hardlink group %d has %d members but a link count of %d",
				ErrInvalid, number, state.members, m.Entries[state.firstIndex].Nlink)
		}
	}
	return nil
}

// validateTotals re-derives every total the header claims. All four are
// functions of the tree — the two logical totals describe it as a user sees it,
// counting a hardlink group once, and the two sealed totals are the pinned
// admission-sizing computation of SealedAllocation — so all four are checked
// for exact equality. A header total that does not match its tree is a header
// that would misinform admission or the product, and is refused.
func validateTotals(m *Manifest) error {
	logicalBytes := uint64(0)
	inodes := uint64(0)
	seenGroup := make(map[uint32]struct{})
	for index := range m.Entries {
		entry := &m.Entries[index]
		if entry.HardlinkGroup != 0 {
			if _, seen := seenGroup[entry.HardlinkGroup]; seen {
				continue
			}
			seenGroup[entry.HardlinkGroup] = struct{}{}
		}
		inodes++
		if entry.Type != TypeRegular {
			continue
		}
		sum, ok := checkedAdd(logicalBytes, entry.Size)
		if !ok {
			return errOverflow("logical bytes")
		}
		logicalBytes = sum
	}
	if m.Header.LogicalBytes != logicalBytes {
		return fmt.Errorf("%w: header claims %d logical bytes, the tree holds %d",
			ErrInvalid, m.Header.LogicalBytes, logicalBytes)
	}
	if m.Header.LogicalInodes != inodes {
		return fmt.Errorf("%w: header claims %d logical inodes, the tree holds %d",
			ErrInvalid, m.Header.LogicalInodes, inodes)
	}
	allocated, sealedInodes, err := SealedAllocation(m.Entries)
	if err != nil {
		return err
	}
	if m.Header.SealedAllocatedBytes != allocated {
		return fmt.Errorf("%w: header claims %d sealed allocated bytes, the pinned computation gives %d",
			ErrInvalid, m.Header.SealedAllocatedBytes, allocated)
	}
	if m.Header.SealedInodes != sealedInodes {
		return fmt.Errorf("%w: header claims %d sealed inodes, the tree holds %d entries",
			ErrInvalid, m.Header.SealedInodes, sealedInodes)
	}
	return nil
}

func validateName(name []byte) error {
	if len(name) == 0 {
		return fmt.Errorf("name is empty")
	}
	if len(name) > MaxNameBytes {
		return fmt.Errorf("name is longer than %d bytes", MaxNameBytes)
	}
	if bytes.IndexByte(name, 0) >= 0 || bytes.IndexByte(name, '/') >= 0 {
		return fmt.Errorf("name contains a separator or NUL")
	}
	if bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
		return fmt.Errorf("name is a directory alias")
	}
	return nil
}
