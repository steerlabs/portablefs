package archive

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// RootDigest is the whole-tree identity the Manager records in the
// ArchiveRecord. It covers restored semantics: everything a wake is obliged to
// reproduce, and nothing about where the bytes happened to be stored.
//
// The exact byte serialization, which is normative — a consumer that computes
// this differently computes a different archive identity. For each entry in
// entry-table order, with nothing between entries, append:
//
//	parentIndex    u32
//	nameLen        u32
//	name           nameLen raw bytes
//	type           u8
//	size           u64
//	mode           u32
//	mtimeNs        i64  (two's complement, as u64)
//	linkNameLen    u32
//	linkName       linkNameLen raw bytes
//	hardlinkGroup  u32
//	contentDigest  32 bytes
//	xattrCount     u32
//	  per xattr, in the entry's canonical name order:
//	    nameLen    u32
//	    name       nameLen raw bytes
//	    valueLen   u32
//	    value      valueLen raw bytes
//	chunkCount     u32
//	  per chunk, in chunk order:
//	    extentCount u32
//	    per extent, in offset order:
//	      offsetInChunk u64
//	      length        u64
//
// All integers are little-endian. Every variable-length field is
// length-prefixed rather than delimited, because a Linux name, a symlink
// target, and an xattr value may all contain any byte pattern, so no delimiter
// is safe and an unprefixed concatenation would let two different trees
// collide.
//
// What is deliberately excluded, and why: frame indices, inner offsets, slice
// digests, pack indices, pack offsets, compressed lengths, chunk sizes,
// compression parameters, and ctime. None of them is restored, and all of them
// change when the same tree is re-archived with different settings or different
// pack sharding. Excluding them is what makes RootDigest a property of the
// volume rather than of one archive run: two attempts over an unchanged volume
// produce the same RootDigest even when they produce entirely different packs.
//
// What is deliberately included beyond content identity: mode, mtime, hardlink
// grouping, xattrs, and the per-chunk extent map. Each of those is a restored
// semantic. The extent map is included because sparseness round-trips — an
// allocated zero-filled file and a fully sparse file of the same length share a
// content digest but must restore to different on-disk shapes, and a tree
// identity that could not tell them apart would call two different volumes the
// same volume.
func RootDigest(m *Manifest) [32]byte {
	digest := sha256.New()
	for index := range m.Entries {
		appendSemanticEntry(digest, &m.Entries[index])
	}
	var out [32]byte
	copy(out[:], digest.Sum(nil))
	return out
}

func appendSemanticEntry(digest hash.Hash, entry *Entry) {
	var scratch [8]byte
	writeU32 := func(value uint32) {
		binary.LittleEndian.PutUint32(scratch[:4], value)
		_, _ = digest.Write(scratch[:4])
	}
	writeU64 := func(value uint64) {
		binary.LittleEndian.PutUint64(scratch[:8], value)
		_, _ = digest.Write(scratch[:8])
	}
	writeBytes := func(value []byte) {
		writeU32(uint32(len(value)))
		_, _ = digest.Write(value)
	}

	writeU32(entry.ParentIndex)
	writeBytes(entry.Name)
	_, _ = digest.Write([]byte{byte(entry.Type)})
	writeU64(entry.Size)
	writeU32(entry.Mode)
	writeU64(uint64(entry.MTimeNanos))
	writeBytes(entry.LinkName)
	writeU32(entry.HardlinkGroup)
	_, _ = digest.Write(entry.ContentDigest[:])
	writeU32(uint32(len(entry.Xattrs)))
	for _, xattr := range entry.Xattrs {
		writeBytes(xattr.Name)
		writeBytes(xattr.Value)
	}
	writeU32(uint32(len(entry.Chunks)))
	for _, chunk := range entry.Chunks {
		writeU32(uint32(len(chunk.Extents)))
		for _, extent := range chunk.Extents {
			writeU64(extent.Offset)
			writeU64(extent.Length)
		}
	}
}

// RootDigestHex is RootDigest in the lowercase hex form the Manager's
// ArchiveRecord stores.
func RootDigestHex(m *Manifest) string {
	digest := RootDigest(m)
	return hex.EncodeToString(digest[:])
}
