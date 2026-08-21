# Tiered storage: pack + manifest format

Status: **Phase 0 contract, revision 3 — incorporates both adversarial
reviews; versioned shared format, frozen before implementation.** The
reference implementation in `vcs/archive` and its golden manifest files are
the normative byte-level layout; this document freezes the semantic
content, the bounds, and every invariant a second implementation must
honor. All counts are u32; digests are raw 32 bytes; all integers
little-endian. Bounds: entry count and frame count each ≤ 16,777,216;
chunks per file ≤ 4,194,304; name ≤ 255 bytes; linkName ≤ 4096 bytes;
extents per chunk ≤ 4096; xattrs per entry ≤ 64 (name ≤ 255 bytes, value ≤
64 KiB); manifest object ≤ 2 GiB. A decoder validates every count against
the remaining input size before allocating and uses checked offset
arithmetic; violations refuse the manifest.

One volume archive attempt is exactly: one binary **manifest** object plus
one or more **pack** objects in an S3-compatible store, under the key
prefix `<root-pinned>/<volumeID>/<sealedEpoch>-<attemptUUID>/`. Objects are
immutable; every attempt writes fresh keys; attempt UUIDs are never reused.
The format is a shared, versioned contract consumed by the archiver, the
restorer/hydrator, the Manager's seal verification, and the
`portablefs-files` gateway's archived mode. Format libraries land first and
are property-tested before any consumer ships.

## Chunking

- Fixed power-of-two chunking over **logical file offsets**, default
  **8 MiB** (`chunkSize = 1 << 23`). Chunk `k` of a file covers logical
  bytes `[k*chunkSize, (k+1)*chunkSize)`. A per-deployment configuration
  knob recorded in the manifest header, not a compile-time constant. CDC is
  rejected on evidence: it exists to absorb mutable-stream shifts; sealed
  packs have none.
- Hydration granularity is size-banded: files ≤ chunkSize are exactly one
  chunk; larger files sub-chunk at chunkSize. Large files are excluded from
  speculative prefetch (demand recall only).
- **Sparse files.** Each chunk record carries an extent list
  `{offsetInChunk, length}` of the data extents it stores (from
  `SEEK_DATA`/`SEEK_HOLE` at export). A chunk lying wholly inside a hole
  stores nothing and appears in the manifest with an empty extent list
  (implicitly hydrated at restore). A partially-holed chunk stores exactly
  its data extents, concatenated in offset order; the chunk's slice digest
  covers that concatenation. Restore materializes files at full logical
  size and punches holes per the extent map, so sparseness round-trips.

## Compression and pack layout

- A **pack is a plain concatenation of valid zstd frames** — no exceptions.
  Incompressible chunks are encoded as zstd frames built from raw
  (uncompressed) blocks, so stock `zstd -d` decodes **every** pack — the
  unconditional disaster-recovery property; the `rawBlocks` flag exists
  only as a hint that decompression is a memcpy.
- One frame per chunk for large files; small files share frames up to the
  chunk boundary (measured 2.85× ratio loss for per-small-file frames),
  grouped by directory/extension locality, addressed by `innerOffset`
  within the decompressed frame.
- zstd level ~9, `windowLog` pinned (≈4 MiB), both recorded in the header.
  No dictionaries; no `--long` (both measured no-ops once small files
  share frames).
- Whole-file content dedup within one archive: two files dedup only when
  their logical size, per-chunk extent maps, and per-chunk slice digests
  are all identical — equal `contentDigest` alone is insufficient (a
  sparse file and an allocated zero-filled file share logical bytes but
  must restore different extent maps). Dedup shares **fetch source only**
  — restored inodes never share hydration state (restore-mode.md).
- The zstd seekable format is rejected; its per-chunk sizes and checksums
  live in the manifest.

## Manifest

Binary with explicit little-endian layout; never JSON (non-UTF-8 paths are
legal; hex digests bloat; JSON parse was the measured restore bottleneck).
Layout: `[header] [entry table] [frame table] [chunk-ref arrays] [footer]`.
An unknown format version is refused, never partially parsed.

**Header:** format version, chunk size, compression parameters, volume ID,
sealed epoch, attempt UUID, entry/frame/chunk counts, logical totals
(bytes, inodes), **sealed allocation totals** — pinned algorithm:
`SealedAllocatedBytes = Σ over stored extents of ceil(extentLength/4096) ×
4096, plus 4096 bytes per entry` (inode + directory-entry + symlink
allowance); `SealedInodes = entry count` — the priority boundary
`(packIndex, packOffset)`, and the pack table (per pack: CRC64NVME,
SHA-256, size).

**Entry table** — entries in depth-first order; entry 0 is the volume
root:

- `parentIndex` (u32, strictly less than the entry's own index; root is
  its own parent) — the canonical namespace graph: parent + one raw name
  component, mirroring the authority's object-relative model. Duplicate
  names under one parent are rejected at seal; acyclicity is by
  construction.
- name: length-prefixed raw bytes (one component, never a path).
- type: regular | directory | symlink (sparse is a property, not a type).
- size, mode (permission bits, sticky/set-ID), mtime ns.
- ctime ns — **recorded as archive metadata only, never restored** (Linux
  offers no honest ctime restoration; the round-trip test compares mtime,
  not ctime).
- **No uid/gid.** Volumes are single-principal; every restored inode is
  owned by the new placement's service identity, exactly as the
  architecture requires (`xfs-authority-architecture.md:466-474`).
  Recording source host IDs would invite restoring forbidden owners.
- linkName (symlinks, raw bytes), nlink + hardlink group id (groups
  validated closed at seal; a dangling count fails the seal),
  contentDigest (SHA-256 of the file's logical bytes, holes as zeros —
  computed streaming at export),
- **xattrs**: the entry's pre-existing portable `user.*` extended
  attributes as raw name/value pairs (bounds in the header of this
  document). PortableFS exposes read/list/remove of pre-existing `user.*`
  xattrs, so an archive that dropped them would silently erase
  mounted-API-visible data; they are restored before serving and covered
  by the round-trip suite. Non-`user.*` attributes are never recorded (the
  authority never serves them).
- chunk-ref array: per chunk `{frameIndex, innerOffset, length,
  sliceDigestSHA256, extents[]}`.

**Frame table** — per frame: `{packIndex, packOffset, compressedLength,
uncompressedLength, rawBlocks bool, xxh64lo32}`. Frame identity (offsets,
checksums) is fully separated from file-slice identity: the frame checksum
covers the whole decompressed frame; each slice digest covers exactly that
file's stored bytes within it. A reader verifies the slice digest for
correctness and may use the frame checksum for cheap corruption
localization.

**Footer:** SHA-256 over every preceding byte of the manifest (the seal),
then a fixed magic. The manifest's `ObjectRef` in the Manager state records
the object's size, SHA-256, and CRC64NVME.

## Checksum roles (one table, no overlap)

| Level | Checksum | Purpose |
| --- | --- | --- |
| file slice (chunk) | SHA-256 | content identity; verified on every fetch |
| frame | XXH64 low 32 | cheap corruption localization |
| pack object | SHA-256 (manifest + ObjectRef) | end-to-end object identity |
| pack object | CRC64NVME (S3 full-object) | transport/storage integrity; verifiable via HeadObject without download |
| manifest | footer SHA-256 + ObjectRef SHA-256/CRC64NVME | seal + object identity |
| whole tree | RootDigest — SHA-256 over the canonical **semantic** entry serialization | archive identity in the Manager record |

RootDigest covers everything a restore must reproduce and nothing physical:
per entry, in table order — `parentIndex u32 | nameLen u32 | name | type u8
| size u64 | mode u32 | mtimeNs i64 | linkNameLen u32 | linkName |
hardlinkGroup u32 | contentDigest 32B | xattrCount u32 | per-xattr
(nameLen u32 | name | valueLen u32 | value) | chunkCount u32 | per-chunk
extentCount u32 + extents (offsetInChunk u64, length u64)` — all
little-endian, pack-location fields excluded. Two archives restoring to
observably different filesystems therefore cannot share a RootDigest. A
golden vector in the reference implementation pins the encoding.

## Ordering

Pack content is sorted mtime-descending with a landmark boundary. The
priority boundary is a `(packIndex u32, packOffset u64)` pair — a bare
offset would be ambiguous across shards: wake prefetch fetches packs
`0..packIndex-1` in full plus pack `packIndex` up to `packOffset`, each as
one contiguous ranged GET. Access-order recording is a flagged future
upgrade; there is no dynamic runtime priority system, ever.

## S3 mechanics

- No multi-range GETs — coalesce adjacent ranges or issue parallel
  single-range GETs (~1 stream per 85–90 MB/s of provisioned bandwidth).
- **Multipart parts are compressed-byte ranges containing whole frames**,
  chosen after compression: every non-final part in `[8 MiB, 5 GiB]`
  (comfortably above S3's 5 MiB non-final-part minimum), parts numbered
  consecutively from 1, checksum algorithm CRC64NVME declared at
  `CreateMultipartUpload` (full-object checksum mode, so HeadObject
  returns a comparable value). Part boundaries need not align to chunks.
- Packs shard by **compressed size**: target ≤ 64 GiB per pack object,
  hard-capped by the 10,000-part limit at the chosen part size.
- Uploads target attempt-unique keys and use conditional create
  (`If-None-Match: *`) where the store supports it; the attempt discipline
  (§ header) is the primary defense against stale writers.
- Never LIST — every object is named in the manifest; the manifest key is
  the only entry point, derived from `{volumeID, epoch, attempt}`.
- One pack is ~400× cheaper in requests than per-file objects; packs make
  IA/Glacier tiers viable later (deferred).

## Identity contract (deliberate)

- Hardlink groups are recreated as real hardlinks (one inode per group).
- ns-mtimes are preserved exactly; ctime is metadata only (above).
- All inodes are owned by the placement's service identity; modes and
  set-ID/sticky bits round-trip.
- `st_ino`/`st_dev`/StableIdentity change across a wake exactly as they
  already change across any remount. No virtual inode table.
- Verified by tests: `make` does not rebuild after a wake; `git status`
  re-stats and reports clean.

## Verification

- Every chunk slice digest is verified on read-back after upload before
  the seal is reported; the Manager independently verifies the manifest
  seal and pack HeadObject identities before committing ARCHIVED.
- Property-based round-trip on random trees (deep paths, non-UTF-8 names,
  duplicate names across directories, unicode, hardlink groups including
  dangling detection, sparse files with hole-spanning chunks,
  allocated-zeros vs holes pairs — which must not dedup — `user.*` xattrs
  with non-UTF-8 values, empty files, empty volume, >chunkSize and
  multi-pack files): archive → restore → full-tree compare of bytes,
  modes, ns-mtimes, symlink targets, sparse extent maps, xattrs, and
  hardlink relations. Golden manifest files (empty volume; a tree with
  sparse data, hardlinks, xattrs, and non-UTF-8 names) pin the byte
  layout.
- Stock `zstd -d` decodes every pack produced by the property suite,
  including packs containing raw-block frames.
