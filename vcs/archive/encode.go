package archive

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// manifestMagic terminates every manifest. It is the last thing in the object,
// after the seal digest, exactly as the format states: the footer is SHA-256
// over every preceding byte followed by this magic.
const manifestMagic = "PFSMAN1\n"

// Fixed record sizes, and with them the normative byte layout. Every count and
// every length prefix in the manifest is a little-endian u32, uniformly, so
// that no field's width has to be remembered and no field can be widened later
// without a version bump. Each constant below is the minimum a record occupies,
// which is what lets a count be checked against the bytes actually remaining
// before the count is used to size anything.
//
//	header  formatVersion u32 | chunkSize u32 | compressionLevel i32 |
//	        windowLog u32 | volumeID 16B | sealedEpoch u64 | attempt 16B |
//	        entryCount u32 | frameCount u32 | chunkCount u32 |
//	        logicalBytes u64 | logicalInodes u64 |
//	        sealedAllocatedBytes u64 | sealedInodes u64 |
//	        priorityPackIndex u32 | priorityPackOffset u64 | packCount u32 |
//	        packCount x (crc64nvme u64 | sha256 32B | sizeBytes u64)
//
//	entry   parentIndex u32 | type u8 | mode u32 | size u64 | mtimeNs i64 |
//	        ctimeNs i64 | nlink u32 | hardlinkGroup u32 |
//	        nameLen u32 | name | linkNameLen u32 | linkName |
//	        contentDigest 32B | xattrCount u32 |
//	        xattrCount x (nameLen u32 | name | valueLen u32 | value) |
//	        chunkCount u32
//
//	frame   packIndex u32 | packOffset u64 | compressedLength u64 |
//	        uncompressedLength u64 | rawBlocks u8 | xxh64lo32 u32
//
//	chunk   frameIndex u32 | innerOffset u64 | length u64 |
//	        sliceDigest 32B | extentCount u32 |
//	        extentCount x (offset u64 | length u64)
//
//	footer  sha256 32B over every preceding byte | magic 8B
const (
	headerFixedBytes = 116
	packRecordBytes  = 48
	entryFixedBytes  = 89
	xattrFixedBytes  = 8
	frameRecordBytes = 33
	chunkFixedBytes  = 56
	extentBytes      = 16
	footerBytes      = 32 + len(manifestMagic)
)

// Encode serializes a manifest canonically: one tree model has exactly one
// encoding, byte for byte, on every platform. Encode validates first and
// refuses to emit anything Decode would reject, so a manifest that leaves this
// process is a manifest that means one tree.
//
// The layout is [header][entry table][frame table][chunk-ref arrays][footer],
// all little-endian and length-prefixed. Chunk-ref arrays are written back to
// back in entry order and carry no offsets: each entry's chunk count, already
// in the entry table, delimits its array, so there is no offset table to
// forge and no cross-reference to validate.
func Encode(m *Manifest) ([]byte, error) {
	if err := Validate(m); err != nil {
		return nil, err
	}
	size, err := encodedSize(m)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, size)
	out = appendHeader(out, m)
	for index := range m.Entries {
		out = appendEntry(out, &m.Entries[index])
	}
	for index := range m.Frames {
		out = appendFrame(out, &m.Frames[index])
	}
	for index := range m.Entries {
		for chunkIndex := range m.Entries[index].Chunks {
			out = appendChunk(out, &m.Entries[index].Chunks[chunkIndex])
		}
	}
	seal := sha256.Sum256(out)
	out = append(out, seal[:]...)
	out = append(out, manifestMagic...)
	if len(out) != size {
		return nil, fmt.Errorf("%w: encoder produced %d bytes, predicted %d", ErrInvalid, len(out), size)
	}
	return out, nil
}

func encodedSize(m *Manifest) (int, error) {
	size := uint64(headerFixedBytes) + uint64(packRecordBytes)*uint64(len(m.Header.Packs))
	add := func(n uint64) bool {
		sum, ok := checkedAdd(size, n)
		size = sum
		return ok
	}
	for index := range m.Entries {
		entry := &m.Entries[index]
		if !add(uint64(entryFixedBytes) + uint64(len(entry.Name)) + uint64(len(entry.LinkName))) {
			return 0, errOverflow("encoded size")
		}
		for _, xattr := range entry.Xattrs {
			if !add(uint64(xattrFixedBytes) + uint64(len(xattr.Name)) + uint64(len(xattr.Value))) {
				return 0, errOverflow("encoded size")
			}
		}
		for chunkIndex := range entry.Chunks {
			if !add(uint64(chunkFixedBytes) + uint64(extentBytes)*uint64(len(entry.Chunks[chunkIndex].Extents))) {
				return 0, errOverflow("encoded size")
			}
		}
	}
	if !add(uint64(frameRecordBytes)*uint64(len(m.Frames)) + uint64(footerBytes)) {
		return 0, errOverflow("encoded size")
	}
	if size > MaxManifestBytes {
		return 0, fmt.Errorf("%w: encoded manifest of %d bytes exceeds the format bound", ErrInvalid, size)
	}
	return int(size), nil
}

func appendHeader(out []byte, m *Manifest) []byte {
	header := &m.Header
	out = binary.LittleEndian.AppendUint32(out, header.FormatVersion)
	out = binary.LittleEndian.AppendUint32(out, header.ChunkSizeBytes)
	out = binary.LittleEndian.AppendUint32(out, uint32(header.CompressionLevel))
	out = binary.LittleEndian.AppendUint32(out, header.WindowLog)
	out = append(out, header.VolumeID[:]...)
	out = binary.LittleEndian.AppendUint64(out, header.SealedEpoch)
	out = append(out, header.Attempt[:]...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(m.Entries)))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(m.Frames)))
	out = binary.LittleEndian.AppendUint32(out, uint32(m.ChunkCount()))
	out = binary.LittleEndian.AppendUint64(out, header.LogicalBytes)
	out = binary.LittleEndian.AppendUint64(out, header.LogicalInodes)
	out = binary.LittleEndian.AppendUint64(out, header.SealedAllocatedBytes)
	out = binary.LittleEndian.AppendUint64(out, header.SealedInodes)
	out = binary.LittleEndian.AppendUint32(out, header.Priority.PackIndex)
	out = binary.LittleEndian.AppendUint64(out, header.Priority.PackOffset)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(header.Packs)))
	for _, pack := range header.Packs {
		out = binary.LittleEndian.AppendUint64(out, pack.CRC64NVME)
		out = append(out, pack.SHA256[:]...)
		out = binary.LittleEndian.AppendUint64(out, pack.SizeBytes)
	}
	return out
}

func appendEntry(out []byte, entry *Entry) []byte {
	out = binary.LittleEndian.AppendUint32(out, entry.ParentIndex)
	out = append(out, byte(entry.Type))
	out = binary.LittleEndian.AppendUint32(out, entry.Mode)
	out = binary.LittleEndian.AppendUint64(out, entry.Size)
	out = binary.LittleEndian.AppendUint64(out, uint64(entry.MTimeNanos))
	out = binary.LittleEndian.AppendUint64(out, uint64(entry.CTimeNanos))
	out = binary.LittleEndian.AppendUint32(out, entry.Nlink)
	out = binary.LittleEndian.AppendUint32(out, entry.HardlinkGroup)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(entry.Name)))
	out = append(out, entry.Name...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(entry.LinkName)))
	out = append(out, entry.LinkName...)
	out = append(out, entry.ContentDigest[:]...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(entry.Xattrs)))
	for _, xattr := range entry.Xattrs {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(xattr.Name)))
		out = append(out, xattr.Name...)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(xattr.Value)))
		out = append(out, xattr.Value...)
	}
	return binary.LittleEndian.AppendUint32(out, uint32(len(entry.Chunks)))
}

func appendFrame(out []byte, frame *Frame) []byte {
	out = binary.LittleEndian.AppendUint32(out, frame.PackIndex)
	out = binary.LittleEndian.AppendUint64(out, frame.PackOffset)
	out = binary.LittleEndian.AppendUint64(out, frame.CompressedLength)
	out = binary.LittleEndian.AppendUint64(out, frame.UncompressedLength)
	raw := byte(0)
	if frame.RawBlocks {
		raw = 1
	}
	out = append(out, raw)
	return binary.LittleEndian.AppendUint32(out, frame.XXH64Lo32)
}

func appendChunk(out []byte, chunk *ChunkRef) []byte {
	out = binary.LittleEndian.AppendUint32(out, chunk.FrameIndex)
	out = binary.LittleEndian.AppendUint64(out, chunk.InnerOffset)
	out = binary.LittleEndian.AppendUint64(out, chunk.Length)
	out = append(out, chunk.SliceDigest[:]...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(chunk.Extents)))
	for _, extent := range chunk.Extents {
		out = binary.LittleEndian.AppendUint64(out, extent.Offset)
		out = binary.LittleEndian.AppendUint64(out, extent.Length)
	}
	return out
}
