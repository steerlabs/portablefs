package archive

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"sort"
)

// BuilderConfig is everything about an archive that is a deployment choice
// rather than a property of the tree. Every field that changes how a consumer
// must read the result is recorded in the manifest header; the rest only shapes
// layout, which a reader discovers from the frame and pack tables.
type BuilderConfig struct {
	// ChunkSizeBytes is the hydration granularity: a power of two, over
	// logical file offsets. Files no larger than one chunk are exactly one
	// chunk; larger files sub-chunk at this size.
	ChunkSizeBytes uint32

	// CompressionLevel and WindowLog are the pinned zstd parameters. They are
	// recorded so that a reader can size a decompression window from the
	// header without inspecting a pack.
	CompressionLevel int32
	WindowLog        uint32

	// VolumeID, SealedEpoch, and Attempt bind the archive to exactly one
	// attempt of one volume at one epoch. Attempt UUIDs are never reused, and
	// object keys are derived from this triple locally, never carried.
	VolumeID    [16]byte
	SealedEpoch uint64
	Attempt     [16]byte

	// PackTargetBytes is the compressed size a pack is sharded at. It is a
	// target, not a cap: a frame is never split across pack objects, so a pack
	// may exceed it by up to one frame.
	PackTargetBytes uint64

	// PartSizeBytes is the multipart part size the uploader will use. It is
	// not written anywhere; it is here so that the pack target can be checked
	// against the 10,000-part limit at build time rather than discovered at
	// upload time.
	PartSizeBytes uint64

	// PriorityLogicalBytes is how much small-file content the wake-prefetch
	// region should cover. Zero means no prefetch region at all. The boundary
	// lands on the first frame boundary at or after this many logical bytes of
	// small-file content, and never past the end of the small-file region.
	PriorityLogicalBytes uint64
}

// S3 mechanics the builder is held to, from the format contract: a non-final
// multipart part is at least 8 MiB (comfortably above the 5 MiB floor) and at
// most 5 GiB, an upload is at most 10,000 parts, and a pack object targets at
// most 64 GiB.
const (
	MinPartSizeBytes   uint64 = 8 << 20
	MaxPartSizeBytes   uint64 = 5 << 30
	MaxPartsPerUpload  uint64 = 10000
	MaxPackTargetBytes uint64 = 64 << 30
)

// DefaultBuilderConfig is the format's defaults with the identity fields left
// for the caller to fill: an archive with no volume, epoch, or attempt is not
// an archive, so those have no defaults worth offering.
func DefaultBuilderConfig() BuilderConfig {
	return BuilderConfig{
		ChunkSizeBytes:       DefaultChunkSizeBytes,
		CompressionLevel:     DefaultCompressionLevel,
		WindowLog:            DefaultWindowLog,
		PackTargetBytes:      MaxPackTargetBytes,
		PartSizeBytes:        16 << 20,
		PriorityLogicalBytes: 1 << 30,
	}
}

func (c BuilderConfig) validate() error {
	header := Header{
		FormatVersion:    FormatVersion,
		ChunkSizeBytes:   c.ChunkSizeBytes,
		CompressionLevel: c.CompressionLevel,
		WindowLog:        c.WindowLog,
		VolumeID:         c.VolumeID,
		SealedEpoch:      c.SealedEpoch,
		Attempt:          c.Attempt,
	}
	if err := validateHeader(&header); err != nil {
		return err
	}
	if c.PartSizeBytes < MinPartSizeBytes || c.PartSizeBytes > MaxPartSizeBytes {
		return fmt.Errorf("%w: part size %d is outside [%d, %d]",
			ErrInvalid, c.PartSizeBytes, MinPartSizeBytes, MaxPartSizeBytes)
	}
	if c.PackTargetBytes < uint64(c.ChunkSizeBytes) || c.PackTargetBytes > MaxPackTargetBytes {
		return fmt.Errorf("%w: pack target %d is outside [chunk size %d, %d]",
			ErrInvalid, c.PackTargetBytes, c.ChunkSizeBytes, MaxPackTargetBytes)
	}
	// A pack is uploaded as one multipart upload, so the target must be
	// reachable inside the part limit at the part size the uploader will use.
	// Catching this here means a fleet misconfiguration fails at build, not
	// after tens of gigabytes have been uploaded.
	capacity, ok := checkedMul(c.PartSizeBytes, MaxPartsPerUpload)
	if !ok || c.PackTargetBytes > capacity {
		return fmt.Errorf("%w: pack target %d cannot be uploaded in %d parts of %d bytes",
			ErrInvalid, c.PackTargetBytes, MaxPartsPerUpload, c.PartSizeBytes)
	}
	return nil
}

// Build turns one walk into pack objects and a manifest.
//
// Layout decisions, all of which are the format contract's and none of which a
// reader has to know:
//
//   - Content is ordered mtime-descending, most recently modified first, within
//     each of two prefetch classes: files no larger than one chunk, then files
//     larger than one chunk. The classes are separated rather than interleaved
//     because large files are demand-recall only, so a recent large file must
//     not be able to land inside the prefetch region and truncate it to
//     nothing. The priority boundary is therefore always a real landmark.
//   - Small files share frames up to the chunk boundary, grouped by parent
//     directory and extension, because per-small-file frames measured a 2.85x
//     compression ratio loss. Locality groups are emitted in the order of their
//     most recently modified member, so the mtime-descending shape survives the
//     grouping.
//   - Large files get one frame per chunk.
//   - Content is deduplicated by the bytes a chunk stores, so two files that
//     store identical bytes fetch from one place. Whole-file dedup is the
//     consequence for two files that agree on size, extent map, and every
//     slice digest — and only those: an allocated zero-filled file and a fully
//     sparse file of the same length share a content digest but store different
//     bytes at different extents, and must restore to different shapes.
//   - Packs shard by compressed size at the configured target, never splitting
//     a frame.
//
// Every digest is computed streaming. The builder holds at most one chunk's
// stored bytes and one frame's assembly buffer at a time, so its memory is
// bounded by the chunk size regardless of how large the volume is.
func Build(config BuilderConfig, source Source, sink PackSink) (*Manifest, error) {
	if source == nil || sink == nil {
		return nil, fmt.Errorf("%w: build needs a source and a sink", ErrInvalid)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	b := &builder{
		config:     config,
		sink:       sink,
		chunkSize:  uint64(config.ChunkSizeBytes),
		sliceIndex: make(map[[32]byte]chunkLocation),
	}
	if err := b.collect(source); err != nil {
		return nil, err
	}
	if err := b.assignHardlinkGroups(); err != nil {
		return nil, err
	}
	if err := b.writeContent(); err != nil {
		return nil, err
	}
	return b.finish()
}

type chunkLocation struct {
	frameIndex  uint32
	innerOffset uint64
	length      uint64
}

// contentUnit is one distinct inode with bytes to store: the entry that owns
// the content, and the entries that are additional links to it.
type contentUnit struct {
	ownerIndex int
	mtime      int64
	size       uint64
	open       func() (SourceFile, error)
}

type builder struct {
	config    BuilderConfig
	sink      PackSink
	chunkSize uint64

	sources []SourceEntry
	entries []Entry
	frames  []Frame
	packs   []PackRef

	// inodeOwner maps a source inode key to the entry index that owns its
	// content, so additional links copy chunk refs rather than re-read bytes.
	inodeOwner map[uint64]int

	sliceIndex map[[32]byte]chunkLocation

	// Frame assembly. pendingFrame accumulates decompressed bytes; the frame
	// it will become is index len(frames), which is what chunk refs written
	// into it record before it is flushed.
	pendingFrame []byte

	// Pack assembly.
	packOpen   bool
	packWriter io.WriteCloser
	packSHA    hash.Hash
	packCRC    crc64NVME
	packBytes  uint64

	priority      PriorityBoundary
	prioritySet   bool
	priorityBytes uint64
}

// collect drains the walk, validating the shape of every entry as it arrives so
// that a malformed walk is refused at its first bad entry rather than after the
// whole tree has been read.
func (b *builder) collect(source Source) error {
	for {
		entry, err := source.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("archive: source walk: %w", err)
		}
		index := len(b.sources)
		if index >= MaxEntries {
			return fmt.Errorf("%w: source produced more than %d entries", ErrInvalid, MaxEntries)
		}
		if index == 0 {
			if entry.Type != TypeDirectory || len(entry.Name) != 0 || entry.ParentIndex != 0 {
				return fmt.Errorf("%w: the first source entry must be the unnamed self-parented root", ErrInvalid)
			}
		} else if entry.ParentIndex >= uint32(index) {
			return fmt.Errorf("%w: source entry %d names parent %d, which it has not yet produced",
				ErrInvalid, index, entry.ParentIndex)
		}
		if entry.Type == TypeRegular && entry.Size > 0 && entry.Open == nil {
			return fmt.Errorf("%w: source entry %d is a non-empty regular file with no reader", ErrInvalid, index)
		}
		b.sources = append(b.sources, entry)
	}
	if len(b.sources) == 0 {
		return fmt.Errorf("%w: source produced no entries; a volume always has a root", ErrInvalid)
	}
	b.entries = make([]Entry, len(b.sources))
	for index := range b.sources {
		source := &b.sources[index]
		entry := &b.entries[index]
		entry.ParentIndex = source.ParentIndex
		entry.Name = append([]byte(nil), source.Name...)
		entry.Type = source.Type
		entry.Size = source.Size
		entry.Mode = source.Mode & ModeMask
		entry.MTimeNanos = source.MTimeNanos
		entry.CTimeNanos = source.CTimeNanos
		entry.LinkName = append([]byte(nil), source.LinkName...)
		entry.Nlink = source.Nlink
		if entry.Nlink == 0 {
			entry.Nlink = 1
		}
		entry.Xattrs = canonicalXattrs(source.Xattrs)
		switch source.Type {
		case TypeSymlink:
			entry.ContentDigest = sha256.Sum256(source.LinkName)
		case TypeDirectory:
			entry.ContentDigest = zeroDigest
		case TypeRegular:
			// The digest of a file with no bytes is the digest of no bytes.
			// Files with content overwrite this once they are read.
			entry.ContentDigest = emptySliceDigest
		}
		if err := validateXattrs(entry.Xattrs, index); err != nil {
			return err
		}
	}
	return nil
}

// canonicalXattrs copies and sorts an entry's attributes into the strictly
// increasing name order the format requires. Sorting here rather than demanding
// it of the source means a walk can report attributes in whatever order
// listxattr gave them; a duplicate name survives the sort and is caught by
// validation, because silently dropping one of two values for one name would
// pick a winner the source never chose.
func canonicalXattrs(xattrs []Xattr) []Xattr {
	if len(xattrs) == 0 {
		return nil
	}
	out := make([]Xattr, len(xattrs))
	for index, xattr := range xattrs {
		out[index] = Xattr{
			Name:  append([]byte(nil), xattr.Name...),
			Value: append([]byte(nil), xattr.Value...),
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return bytes.Compare(out[i].Name, out[j].Name) < 0 })
	return out
}

// assignHardlinkGroups turns source inode keys into dense group numbers in
// order of first appearance, and proves every group closed. A group whose
// membership does not equal its link count is refused: the missing link is
// outside the volume, and restoring the archive would silently convert a
// hardlink into independent copies.
func (b *builder) assignHardlinkGroups() error {
	members := make(map[uint64][]int)
	for index := range b.sources {
		source := &b.sources[index]
		if source.Type != TypeRegular || source.InodeKey == 0 {
			continue
		}
		members[source.InodeKey] = append(members[source.InodeKey], index)
	}
	b.inodeOwner = make(map[uint64]int, len(members))
	next := uint32(1)
	for index := range b.sources {
		source := &b.sources[index]
		if source.Type != TypeRegular || source.InodeKey == 0 {
			if source.Type == TypeRegular && b.entries[index].Nlink != 1 {
				return fmt.Errorf("%w: source entry %d reports %d links with no inode identity",
					ErrInvalid, index, b.entries[index].Nlink)
			}
			continue
		}
		group := members[source.InodeKey]
		if len(group) == 1 {
			if b.entries[index].Nlink != 1 {
				return fmt.Errorf("%w: source entry %d reports %d links but is the only link in the volume",
					ErrInvalid, index, b.entries[index].Nlink)
			}
			continue
		}
		if uint32(len(group)) != b.entries[index].Nlink {
			return fmt.Errorf("%w: source entry %d reports %d links but %d are in the volume",
				ErrInvalid, index, b.entries[index].Nlink, len(group))
		}
		if group[0] == index {
			b.entries[index].HardlinkGroup = next
			b.inodeOwner[source.InodeKey] = index
			next++
			continue
		}
		owner := group[0]
		if b.sources[index].Size != b.sources[owner].Size {
			return fmt.Errorf("%w: source entries %d and %d share an inode but disagree on size",
				ErrInvalid, index, owner)
		}
		b.entries[index].HardlinkGroup = b.entries[owner].HardlinkGroup
	}
	return nil
}

// contentUnits is every distinct inode with bytes to store, ordered
// mtime-descending with the entry index as a stable tie-break.
func (b *builder) contentUnits() []contentUnit {
	units := make([]contentUnit, 0, len(b.sources))
	for index := range b.sources {
		source := &b.sources[index]
		if source.Type != TypeRegular || source.Size == 0 {
			continue
		}
		if source.InodeKey != 0 {
			if owner, ok := b.inodeOwner[source.InodeKey]; ok && owner != index {
				continue
			}
		}
		units = append(units, contentUnit{
			ownerIndex: index,
			mtime:      source.MTimeNanos,
			size:       source.Size,
			open:       source.Open,
		})
	}
	sort.SliceStable(units, func(i, j int) bool {
		if units[i].mtime != units[j].mtime {
			return units[i].mtime > units[j].mtime
		}
		return units[i].ownerIndex < units[j].ownerIndex
	})
	return units
}

// localityKey groups small files that are likely to compress well together and
// to be read together: same parent directory, same extension.
type localityKey struct {
	parent    uint32
	extension string
}

func (b *builder) writeContent() error {
	units := b.contentUnits()
	small := make([]contentUnit, 0, len(units))
	large := make([]contentUnit, 0, len(units))
	for _, unit := range units {
		if unit.size <= b.chunkSize {
			small = append(small, unit)
		} else {
			large = append(large, unit)
		}
	}
	if b.config.PriorityLogicalBytes == 0 {
		b.prioritySet = true
	}
	for _, unit := range b.groupByLocality(small) {
		if err := b.writeSmallFile(unit); err != nil {
			return err
		}
	}
	// Flush the shared frame before the large-file region so that the
	// boundary lands on a frame boundary and no prefetched frame contains
	// demand-recall content.
	if err := b.flushFrame(); err != nil {
		return err
	}
	if !b.prioritySet {
		b.setPriorityHere()
	}
	for _, unit := range large {
		if err := b.writeLargeFile(unit); err != nil {
			return err
		}
	}
	return b.closePack()
}

// groupByLocality reorders small files so that files sharing a parent directory
// and extension are adjacent, while keeping the groups themselves in
// mtime-descending order by their most recent member. The input is already
// mtime-descending, so the first member a group sees is its most recent one.
func (b *builder) groupByLocality(units []contentUnit) []contentUnit {
	order := make([]localityKey, 0, len(units))
	groups := make(map[localityKey][]contentUnit, len(units))
	for _, unit := range units {
		key := localityKey{
			parent:    b.sources[unit.ownerIndex].ParentIndex,
			extension: path.Ext(string(b.sources[unit.ownerIndex].Name)),
		}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], unit)
	}
	out := make([]contentUnit, 0, len(units))
	for _, key := range order {
		out = append(out, groups[key]...)
	}
	return out
}

// writeSmallFile stores one file of at most one chunk into the shared frame
// under assembly, starting a new frame whenever the current one has reached the
// chunk boundary.
func (b *builder) writeSmallFile(unit contentUnit) error {
	stored, extents, digest, err := b.readChunk(unit, 0)
	if err != nil {
		return err
	}
	b.entries[unit.ownerIndex].ContentDigest = digest
	chunk, err := b.placeChunk(stored, extents, true)
	if err != nil {
		return err
	}
	b.entries[unit.ownerIndex].Chunks = []ChunkRef{chunk}
	b.propagateToLinks(unit.ownerIndex)
	if b.prioritySet {
		return nil
	}
	sum, ok := checkedAdd(b.priorityBytes, unit.size)
	if !ok {
		return errOverflow("priority region")
	}
	b.priorityBytes = sum
	if b.priorityBytes >= b.config.PriorityLogicalBytes {
		// The boundary must be a frame boundary, so close the frame under
		// assembly and land on the offset that produces.
		if err := b.flushFrame(); err != nil {
			return err
		}
		b.setPriorityHere()
	}
	return nil
}

// writeLargeFile stores one file of more than one chunk, one frame per chunk.
func (b *builder) writeLargeFile(unit contentUnit) error {
	chunkCount := unit.size / b.chunkSize
	if unit.size%b.chunkSize != 0 {
		chunkCount++
	}
	if chunkCount > uint64(MaxChunks) {
		return fmt.Errorf("%w: entry %d needs %d chunks", ErrInvalid, unit.ownerIndex, chunkCount)
	}
	chunks := make([]ChunkRef, 0, chunkCount)
	digest := sha256.New()
	file, err := unit.open()
	if err != nil {
		return fmt.Errorf("archive: open entry %d: %w", unit.ownerIndex, err)
	}
	defer func() { _ = file.Close() }()
	extents, err := b.fileExtents(file, unit)
	if err != nil {
		return err
	}
	for chunkIndex := uint64(0); chunkIndex < chunkCount; chunkIndex++ {
		stored, chunkExtents, err := b.readChunkFrom(file, extents, unit, int(chunkIndex), digest)
		if err != nil {
			return err
		}
		chunk, err := b.placeChunk(stored, chunkExtents, false)
		if err != nil {
			return err
		}
		chunks = append(chunks, chunk)
	}
	var contentDigest [32]byte
	copy(contentDigest[:], digest.Sum(nil))
	b.entries[unit.ownerIndex].ContentDigest = contentDigest
	b.entries[unit.ownerIndex].Chunks = chunks
	b.propagateToLinks(unit.ownerIndex)
	return nil
}

// propagateToLinks copies an inode's content identity onto every other link to
// it. Hardlink group members are the same inode, so they share chunk refs and
// content digest exactly; the restorer creates one file and links the rest.
func (b *builder) propagateToLinks(ownerIndex int) {
	key := b.sources[ownerIndex].InodeKey
	if key == 0 || b.entries[ownerIndex].HardlinkGroup == 0 {
		return
	}
	for index := range b.sources {
		if index == ownerIndex || b.sources[index].InodeKey != key {
			continue
		}
		b.entries[index].ContentDigest = b.entries[ownerIndex].ContentDigest
		b.entries[index].Chunks = b.entries[ownerIndex].Chunks
	}
}

// placeChunk deduplicates, appends to the frame under assembly or emits a whole
// frame, and returns the chunk reference. inShared selects the small-file path,
// where the frame fills to the chunk boundary across many files, from the
// large-file path, where the chunk is the frame.
func (b *builder) placeChunk(stored []byte, extents []Extent, inShared bool) (ChunkRef, error) {
	if len(extents) > MaxExtentsPerChunk {
		return ChunkRef{}, fmt.Errorf("%w: chunk has %d extents, past the bound of %d",
			ErrInvalid, len(extents), MaxExtentsPerChunk)
	}
	if len(stored) == 0 {
		// A chunk wholly inside a hole is stored nowhere and restores as a
		// hole. It never enters the dedup index: it has no bytes to share.
		return ChunkRef{FrameIndex: NoFrame, SliceDigest: emptySliceDigest, Extents: extents}, nil
	}
	digest := sha256.Sum256(stored)
	if existing, ok := b.sliceIndex[digest]; ok && existing.length == uint64(len(stored)) {
		return ChunkRef{
			FrameIndex:  existing.frameIndex,
			InnerOffset: existing.innerOffset,
			Length:      existing.length,
			SliceDigest: digest,
			Extents:     extents,
		}, nil
	}
	if inShared && uint64(len(b.pendingFrame))+uint64(len(stored)) > b.chunkSize {
		if err := b.flushFrame(); err != nil {
			return ChunkRef{}, err
		}
	}
	frameIndex := uint32(len(b.frames))
	innerOffset := uint64(len(b.pendingFrame))
	b.pendingFrame = append(b.pendingFrame, stored...)
	b.sliceIndex[digest] = chunkLocation{
		frameIndex:  frameIndex,
		innerOffset: innerOffset,
		length:      uint64(len(stored)),
	}
	chunk := ChunkRef{
		FrameIndex:  frameIndex,
		InnerOffset: innerOffset,
		Length:      uint64(len(stored)),
		SliceDigest: digest,
		Extents:     extents,
	}
	if !inShared {
		if err := b.flushFrame(); err != nil {
			return ChunkRef{}, err
		}
	}
	return chunk, nil
}

// flushFrame compresses the frame under assembly, writes it into the current
// pack, and records it. Frames are never split across packs, so a frame that
// would push the current pack past its target starts the next one.
func (b *builder) flushFrame() error {
	if len(b.pendingFrame) == 0 {
		return nil
	}
	content := b.pendingFrame
	encoded, rawBlocks, err := encodeFrame(b.config.CompressionLevel, b.config.WindowLog, content)
	if err != nil {
		return err
	}
	if b.packOpen && b.packBytes+uint64(len(encoded)) > b.config.PackTargetBytes {
		if err := b.closePack(); err != nil {
			return err
		}
	}
	if !b.packOpen {
		if err := b.openPack(); err != nil {
			return err
		}
	}
	if _, err := b.packWriter.Write(encoded); err != nil {
		return fmt.Errorf("archive: write pack %d: %w", len(b.packs), err)
	}
	_, _ = b.packSHA.Write(encoded)
	_, _ = b.packCRC.Write(encoded)
	b.frames = append(b.frames, Frame{
		PackIndex:          uint32(len(b.packs)),
		PackOffset:         b.packBytes,
		CompressedLength:   uint64(len(encoded)),
		UncompressedLength: uint64(len(content)),
		RawBlocks:          rawBlocks,
		XXH64Lo32:          XXH64Lo32Of(content),
	})
	b.packBytes += uint64(len(encoded))
	b.pendingFrame = b.pendingFrame[:0]
	if len(b.frames) > MaxFrames {
		return fmt.Errorf("%w: archive needs more than %d frames", ErrInvalid, MaxFrames)
	}
	return nil
}

func (b *builder) openPack() error {
	index := uint32(len(b.packs))
	if int(index) >= MaxPacks {
		return fmt.Errorf("%w: archive needs more than %d pack objects", ErrInvalid, MaxPacks)
	}
	writer, err := b.sink.OpenPack(index)
	if err != nil {
		return fmt.Errorf("archive: open pack %d: %w", index, err)
	}
	b.packWriter = writer
	b.packSHA = sha256.New()
	b.packCRC = crc64NVME{}
	b.packBytes = 0
	b.packOpen = true
	return nil
}

func (b *builder) closePack() error {
	if !b.packOpen {
		return nil
	}
	if err := b.packWriter.Close(); err != nil {
		return fmt.Errorf("archive: close pack %d: %w", len(b.packs), err)
	}
	pack := PackRef{CRC64NVME: b.packCRC.Sum64(), SizeBytes: b.packBytes}
	copy(pack.SHA256[:], b.packSHA.Sum(nil))
	b.packs = append(b.packs, pack)
	b.packOpen = false
	b.packWriter = nil
	return nil
}

// setPriorityHere records the boundary at the current write position. Because
// it is only ever called with no frame under assembly, the position is always a
// frame boundary; the end of a pack is expressed as the next pack's origin so
// that every boundary has one representation.
func (b *builder) setPriorityHere() {
	index := uint32(len(b.packs))
	offset := uint64(0)
	if b.packOpen {
		offset = b.packBytes
	}
	b.priority = PriorityBoundary{PackIndex: index, PackOffset: offset}
	b.prioritySet = true
}

// fileExtents fetches and validates one file's whole extent map. A source that
// reports overlapping, unordered, adjacent, or out-of-range extents is refused:
// every one of those would produce a manifest whose extent map is either not
// canonical or not true, and both are seal failures.
func (b *builder) fileExtents(file SourceFile, unit contentUnit) ([]Extent, error) {
	extents, err := file.Extents()
	if err != nil {
		return nil, fmt.Errorf("archive: extents of entry %d: %w", unit.ownerIndex, err)
	}
	previousEnd := uint64(0)
	for index, extent := range extents {
		if extent.Length == 0 {
			return nil, fmt.Errorf("%w: entry %d extent %d is empty", ErrInvalid, unit.ownerIndex, index)
		}
		if index > 0 && extent.Offset <= previousEnd {
			return nil, fmt.Errorf("%w: entry %d extent %d is not strictly after and apart from its predecessor",
				ErrInvalid, unit.ownerIndex, index)
		}
		end, ok := checkedRange(extent.Offset, extent.Length, unit.size)
		if !ok {
			return nil, fmt.Errorf("%w: entry %d extent %d runs past the file size %d",
				ErrInvalid, unit.ownerIndex, index, unit.size)
		}
		previousEnd = end
	}
	return extents, nil
}

// readChunk opens a file, reads exactly one chunk, and closes it. It is the
// small-file path, where the whole file is one chunk.
func (b *builder) readChunk(unit contentUnit, chunkIndex int) ([]byte, []Extent, [32]byte, error) {
	var contentDigest [32]byte
	file, err := unit.open()
	if err != nil {
		return nil, nil, contentDigest, fmt.Errorf("archive: open entry %d: %w", unit.ownerIndex, err)
	}
	defer func() { _ = file.Close() }()
	extents, err := b.fileExtents(file, unit)
	if err != nil {
		return nil, nil, contentDigest, err
	}
	digest := sha256.New()
	stored, chunkExtents, err := b.readChunkFrom(file, extents, unit, chunkIndex, digest)
	if err != nil {
		return nil, nil, contentDigest, err
	}
	copy(contentDigest[:], digest.Sum(nil))
	return stored, chunkExtents, contentDigest, nil
}

// zeroPad is the source of hole bytes for the content digest. Holes are digested
// as zeros without ever being read or stored, which is what makes the content
// digest of a sparse file equal to the digest of its allocated twin while the
// two still store different bytes.
var zeroPad = make([]byte, 64<<10)

// readChunkFrom reads one chunk's stored bytes, produces its chunk-relative
// extent map, and advances the whole-file content digest across the chunk's
// entire logical span, writing zeros where the holes are.
func (b *builder) readChunkFrom(file SourceFile, fileExtents []Extent, unit contentUnit,
	chunkIndex int, digest hash.Hash) ([]byte, []Extent, error) {

	chunkStart, ok := checkedMul(uint64(chunkIndex), b.chunkSize)
	if !ok {
		return nil, nil, errOverflow("chunk offset")
	}
	span := chunkSpan(unit.size, b.chunkSize, chunkIndex)
	chunkEnd := chunkStart + span

	var stored []byte
	var chunkExtents []Extent
	cursor := uint64(0)
	for _, extent := range fileExtents {
		start := max(extent.Offset, chunkStart)
		end := min(extent.Offset+extent.Length, chunkEnd)
		if start >= end {
			continue
		}
		relative := start - chunkStart
		length := end - start
		if err := digestZeros(digest, relative-cursor); err != nil {
			return nil, nil, err
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(io.NewSectionReader(file, int64(start), int64(length)), buf); err != nil {
			return nil, nil, fmt.Errorf("archive: read entry %d at %d: %w", unit.ownerIndex, start, err)
		}
		if _, err := digest.Write(buf); err != nil {
			return nil, nil, err
		}
		stored = append(stored, buf...)
		chunkExtents = append(chunkExtents, Extent{Offset: relative, Length: length})
		cursor = relative + length
	}
	if err := digestZeros(digest, span-cursor); err != nil {
		return nil, nil, err
	}
	return stored, chunkExtents, nil
}

func digestZeros(digest hash.Hash, count uint64) error {
	for count > 0 {
		step := uint64(len(zeroPad))
		if count < step {
			step = count
		}
		if _, err := digest.Write(zeroPad[:step]); err != nil {
			return err
		}
		count -= step
	}
	return nil
}

// finish assembles the manifest, fills the totals from the tree rather than
// from anything the builder tracked separately, and validates the result. A
// manifest only leaves Build if it would survive Decode.
func (b *builder) finish() (*Manifest, error) {
	if err := b.flushFrame(); err != nil {
		return nil, err
	}
	if err := b.closePack(); err != nil {
		return nil, err
	}
	if !b.prioritySet {
		b.setPriorityHere()
	}
	// The boundary is expressed as a position; once every pack is closed, a
	// boundary recorded at the end of the last pack is the pack count with a
	// zero offset, which is the canonical "prefetch everything".
	if int(b.priority.PackIndex) < len(b.packs) &&
		b.priority.PackOffset == b.packs[b.priority.PackIndex].SizeBytes {
		b.priority = PriorityBoundary{PackIndex: b.priority.PackIndex + 1}
	}

	manifest := &Manifest{
		Header: Header{
			FormatVersion:    FormatVersion,
			ChunkSizeBytes:   b.config.ChunkSizeBytes,
			CompressionLevel: b.config.CompressionLevel,
			WindowLog:        b.config.WindowLog,
			VolumeID:         b.config.VolumeID,
			SealedEpoch:      b.config.SealedEpoch,
			Attempt:          b.config.Attempt,
			Priority:         b.priority,
			Packs:            b.packs,
		},
		Entries: b.entries,
		Frames:  b.frames,
	}
	logicalBytes, logicalInodes, err := logicalTotals(manifest.Entries)
	if err != nil {
		return nil, err
	}
	manifest.Header.LogicalBytes = logicalBytes
	manifest.Header.LogicalInodes = logicalInodes
	allocated, inodes, err := SealedAllocation(manifest.Entries)
	if err != nil {
		return nil, err
	}
	manifest.Header.SealedAllocatedBytes = allocated
	manifest.Header.SealedInodes = inodes
	if err := Validate(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func logicalTotals(entries []Entry) (bytesTotal, inodes uint64, err error) {
	seenGroup := make(map[uint32]struct{})
	for index := range entries {
		entry := &entries[index]
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
		sum, ok := checkedAdd(bytesTotal, entry.Size)
		if !ok {
			return 0, 0, errOverflow("logical bytes")
		}
		bytesTotal = sum
	}
	return bytesTotal, inodes, nil
}
