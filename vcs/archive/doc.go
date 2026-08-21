// Package archive implements the PortableFS tiered-storage pack and manifest
// format: the versioned, shared contract of docs/tiered-storage/pack-format.md,
// consumed by the archiver, the restorer, the hydrator, the Manager's seal
// verification, and the files gateway's archived mode.
//
// One archive attempt is one binary manifest object plus one or more pack
// objects. A pack is a plain concatenation of valid zstd frames with no
// container of its own, so stock `zstd -d` decodes every pack ever written;
// incompressible content is stored in frames built from raw blocks rather than
// escaping the frame format. Frame identity (pack, offset, lengths, XXH64) is
// fully separated from file-slice identity (SHA-256 over exactly the bytes one
// file stores in that frame), so deduplication shares a fetch source without
// ever aliasing restored inodes.
//
// The manifest is explicit little-endian, length-prefixed, and laid out as
// [header][entry table][frame table][chunk-ref arrays][footer]; the footer is
// SHA-256 over every preceding byte followed by a fixed magic. An unknown
// format version is refused, never partially parsed. Decode is fail-closed and
// bounded: every count is checked against the minimum bytes its records would
// occupy in the remaining input before anything is allocated, so a hostile
// manifest cannot make the decoder allocate more than the object it came from.
// Decode re-derives and enforces every structural invariant the seal depends
// on — depth-first parent ordering with parentIndex strictly less than the
// entry's own index, a self-parented directory at entry 0, no duplicate name
// under one parent, closed hardlink groups whose membership equals the recorded
// link count, chunk coverage that matches file size and sparseness exactly,
// ordered non-overlapping non-adjacent extents inside chunk bounds, extended
// attributes in the portable user namespace and in canonical name order, frames
// that tile their pack without gap or overlap, header totals that match the tree
// they describe, and the footer digest — so a manifest that decodes is a
// manifest that means exactly one tree.
//
// RootDigest is the archive's identity in the Manager's record, and it covers
// restored semantics rather than storage: names, graph, types, sizes, modes,
// mtimes, symlink targets, hardlink grouping, content digests, extended
// attributes, and per-chunk extent maps, and nothing about frames, packs,
// offsets, compression, or ctime. Re-archiving an unchanged volume with
// different settings produces the same RootDigest and entirely different packs.
//
// Encode is canonical: the same tree model always produces the same bytes, and
// Encode refuses to emit anything Decode would reject. Everything in the
// encode and decode path is portable Go; only the export-side extent scanner is
// Linux-specific and it lives behind a portable interface.
//
// Ownership is deliberately absent. Volumes are single-principal, every
// restored inode belongs to the new placement's service identity, and recording
// source host IDs would invite restoring forbidden owners. ctime is carried as
// archive metadata only and is never restored; Linux offers no honest way to
// restore it.
package archive
