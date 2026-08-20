package archive

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"unicode/utf8"
)

// TestPropertyRoundTrip is the format's central claim under random trees: build
// to packs and a manifest, encode the manifest, decode it back, and prove the
// decoded manifest plus the packs reconstruct the source tree exactly — bytes,
// modes, ns-mtimes, symlink targets, extent maps, hardlink relations, and
// extended attributes.
func TestPropertyRoundTrip(t *testing.T) {
	// The generator is random, so the suite asserts its own coverage: if a
	// change to the generator or the builder stops producing one of the classes
	// the format distinguishes, this test must fail rather than quietly stop
	// testing it.
	seen := map[string]int{}
	note := func(what string) { seen[what]++ }
	for seed := uint64(1); seed <= 48; seed++ {
		for _, chunkSize := range []uint32{MinChunkSizeBytes, 1 << 13, 1 << 14} {
			tree := generateTree(seed, uint64(chunkSize), 40)
			config := testConfig(chunkSize)
			packs := &memoryPacks{}
			manifest, err := Build(config, tree.source(), packs)
			if err != nil {
				t.Fatalf("seed %d chunk %d: build: %v", seed, chunkSize, err)
			}
			encoded, err := Encode(manifest)
			if err != nil {
				t.Fatalf("seed %d chunk %d: encode: %v", seed, chunkSize, err)
			}
			decoded, err := Decode(encoded)
			if err != nil {
				t.Fatalf("seed %d chunk %d: decode: %v", seed, chunkSize, err)
			}
			reencoded, err := Encode(decoded)
			if err != nil {
				t.Fatalf("seed %d chunk %d: re-encode: %v", seed, chunkSize, err)
			}
			if !bytes.Equal(encoded, reencoded) {
				t.Fatalf("seed %d chunk %d: encoding is not canonical across a decode", seed, chunkSize)
			}
			if RootDigest(manifest) != RootDigest(decoded) {
				t.Fatalf("seed %d chunk %d: root digest changed across a decode", seed, chunkSize)
			}
			verifyModel(t, tree, decoded, packs)
			tally(decoded, note)
		}
	}
	required := []string{
		"empty volume content", "empty file", "multi-chunk file", "whole-hole chunk",
		"partially sparse chunk", "hardlink group", "symlink", "non-utf8 name",
		"unicode name", "extended attributes", "set-id or sticky mode", "deduplicated slice",
		"multi-pack archive", "raw-block frame", "shared small-file frame", "prefetch boundary inside a pack",
	}
	for _, what := range required {
		if seen[what] == 0 {
			t.Fatalf("the property suite never produced %q, so the format's handling of it is untested", what)
		}
	}
}

// tally records which of the classes the format distinguishes a generated
// archive actually exercised.
func tally(m *Manifest, note func(string)) {
	if len(m.Header.Packs) == 0 {
		note("empty volume content")
	}
	if len(m.Header.Packs) > 1 {
		note("multi-pack archive")
	}
	if m.Header.Priority.PackIndex < uint32(len(m.Header.Packs)) && m.Header.Priority.PackOffset > 0 {
		note("prefetch boundary inside a pack")
	}
	for _, frame := range m.Frames {
		if frame.RawBlocks {
			note("raw-block frame")
		}
	}
	slices := map[[32]byte]int{}
	frameUsers := map[uint32]map[int]struct{}{}
	for index := range m.Entries {
		entry := &m.Entries[index]
		if entry.Mode&0o7000 != 0 {
			note("set-id or sticky mode")
		}
		if len(entry.Xattrs) > 0 {
			note("extended attributes")
		}
		if entry.HardlinkGroup != 0 {
			note("hardlink group")
		}
		if entry.Type == TypeSymlink {
			note("symlink")
		}
		if !utf8.Valid(entry.Name) {
			note("non-utf8 name")
		} else if len(entry.Name) > 0 && hasMultibyte(entry.Name) {
			note("unicode name")
		}
		if entry.Type != TypeRegular {
			continue
		}
		if entry.Size == 0 {
			note("empty file")
		}
		if len(entry.Chunks) > 1 {
			note("multi-chunk file")
		}
		for chunkIndex, chunk := range entry.Chunks {
			span := chunkSpan(entry.Size, uint64(m.Header.ChunkSizeBytes), chunkIndex)
			if !chunk.Stored() {
				note("whole-hole chunk")
				continue
			}
			if chunk.Length < span {
				note("partially sparse chunk")
			}
			slices[chunk.SliceDigest]++
			if slices[chunk.SliceDigest] > 1 && entry.HardlinkGroup == 0 {
				note("deduplicated slice")
			}
			if frameUsers[chunk.FrameIndex] == nil {
				frameUsers[chunk.FrameIndex] = map[int]struct{}{}
			}
			frameUsers[chunk.FrameIndex][index] = struct{}{}
		}
	}
	for _, users := range frameUsers {
		if len(users) > 1 {
			note("shared small-file frame")
		}
	}
}

func hasMultibyte(name []byte) bool {
	for _, b := range name {
		if b >= 0x80 {
			return true
		}
	}
	return false
}

// TestEmptyVolume pins the degenerate case the lifecycle must handle: a volume
// with nothing but its root. It produces no frames and no pack objects, and its
// manifest still seals, decodes, and plans.
func TestEmptyVolume(t *testing.T) {
	source := NewSliceSource([]SourceEntry{{Type: TypeDirectory, Mode: 0o755, Nlink: 1, MTimeNanos: 42}})
	packs := &memoryPacks{}
	manifest, err := Build(testConfig(MinChunkSizeBytes), source, packs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(manifest.Header.Packs) != 0 || len(manifest.Frames) != 0 {
		t.Fatalf("empty volume produced %d packs and %d frames", len(manifest.Header.Packs), len(manifest.Frames))
	}
	if manifest.Header.LogicalInodes != 1 || manifest.Header.SealedInodes != 1 {
		t.Fatalf("empty volume totals: logical %d sealed %d",
			manifest.Header.LogicalInodes, manifest.Header.SealedInodes)
	}
	if manifest.Header.SealedAllocatedBytes != MetadataBytesPerEntry {
		t.Fatalf("empty volume sealed allocation %d, want %d",
			manifest.Header.SealedAllocatedBytes, MetadataBytesPerEntry)
	}
	encoded, err := Encode(manifest)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	plan := decoded.NamespacePlan()
	step, ok := plan.Next()
	if !ok || step.Index != 0 || step.Type != TypeDirectory {
		t.Fatalf("empty volume plan does not start at the root")
	}
	if _, more := plan.Next(); more {
		t.Fatalf("empty volume plan has more than the root")
	}
}

// TestSparseAndAllocatedZerosAreNotDeduplicated is the discrimination the
// second review called out. A fully sparse file and an allocated zero-filled
// file of the same length have the same content digest, because holes read as
// zeros. They must still restore to different on-disk shapes, so they must not
// be collapsed into one another: the sparse file stores nothing at all, the
// allocated one stores its zeros, and both extent maps survive the round trip.
func TestSparseAndAllocatedZerosAreNotDeduplicated(t *testing.T) {
	const chunkSize = MinChunkSizeBytes
	size := uint64(chunkSize) * 2
	zeros := make([]byte, size)
	holes := &MemoryFile{Logical: zeros}
	allocated := &MemoryFile{Logical: zeros, Data: []Extent{{Offset: 0, Length: size}}}

	source := NewSliceSource([]SourceEntry{
		{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
		{ParentIndex: 0, Name: []byte("holes"), Type: TypeRegular, Size: size, Mode: 0o644, Nlink: 1,
			Open: func() (SourceFile, error) { return holes, nil }},
		{ParentIndex: 0, Name: []byte("allocated"), Type: TypeRegular, Size: size, Mode: 0o644, Nlink: 1,
			Open: func() (SourceFile, error) { return allocated, nil }},
	})
	packs := &memoryPacks{}
	manifest, err := Build(testConfig(chunkSize), source, packs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sparse, dense := &manifest.Entries[1], &manifest.Entries[2]
	if sparse.ContentDigest != dense.ContentDigest {
		t.Fatalf("a sparse file and its allocated twin must share a content digest")
	}
	if sparse.ContentDigest != sha256.Sum256(zeros) {
		t.Fatalf("content digest does not read holes as zeros")
	}
	for chunkIndex, chunk := range sparse.Chunks {
		if chunk.Stored() || len(chunk.Extents) != 0 || chunk.Length != 0 {
			t.Fatalf("sparse chunk %d stores %d bytes in frame %d", chunkIndex, chunk.Length, chunk.FrameIndex)
		}
	}
	for chunkIndex, chunk := range dense.Chunks {
		if !chunk.Stored() || len(chunk.Extents) != 1 || chunk.Length != uint64(chunkSize) {
			t.Fatalf("allocated chunk %d stores %d bytes in %d extents",
				chunkIndex, chunk.Length, len(chunk.Extents))
		}
	}
	reader, err := NewPackReader(manifest, packs)
	if err != nil {
		t.Fatalf("pack reader: %v", err)
	}
	for _, index := range []uint32{1, 2} {
		got, err := reader.ReadFile(index)
		if err != nil {
			t.Fatalf("entry %d read back: %v", index, err)
		}
		if !bytes.Equal(got, zeros) {
			t.Fatalf("entry %d did not reconstruct to zeros", index)
		}
	}
	// The tree identity must distinguish the two shapes: swapping the sparse
	// entry's extent map for the allocated one's changes the digest.
	before := RootDigest(manifest)
	manifest.Entries[1].Chunks = manifest.Entries[2].Chunks
	if RootDigest(manifest) == before {
		t.Fatalf("root digest does not cover the extent map, so sparseness is not part of tree identity")
	}
}

// TestWholeFileDedup proves byte-identical files with identical extent maps
// share their stored bytes, and that the sharing is of the fetch source only:
// the two entries remain separate inodes with separate chunk references.
func TestWholeFileDedup(t *testing.T) {
	const chunkSize = MinChunkSizeBytes
	content := bytes.Repeat([]byte("dedupe me "), 900)
	size := uint64(len(content))
	makeFile := func() *MemoryFile {
		return &MemoryFile{Logical: content, Data: []Extent{{Offset: 0, Length: size}}}
	}
	entries := []SourceEntry{{Type: TypeDirectory, Mode: 0o755, Nlink: 1}}
	for _, name := range []string{"one", "two", "three"} {
		file := makeFile()
		entries = append(entries, SourceEntry{
			ParentIndex: 0, Name: []byte(name), Type: TypeRegular, Size: size, Mode: 0o644, Nlink: 1,
			Open: func() (SourceFile, error) { return file, nil },
		})
	}
	packs := &memoryPacks{}
	manifest, err := Build(testConfig(chunkSize), NewSliceSource(entries), packs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	first := manifest.Entries[1].Chunks
	for index := 2; index <= 3; index++ {
		other := manifest.Entries[index].Chunks
		if len(other) != len(first) {
			t.Fatalf("entry %d has %d chunks, want %d", index, len(other), len(first))
		}
		for chunkIndex := range first {
			if other[chunkIndex].FrameIndex != first[chunkIndex].FrameIndex ||
				other[chunkIndex].InnerOffset != first[chunkIndex].InnerOffset {
				t.Fatalf("entry %d chunk %d was not deduplicated onto entry 1", index, chunkIndex)
			}
		}
		if manifest.Entries[index].HardlinkGroup != 0 {
			t.Fatalf("deduplication must not create a hardlink group")
		}
	}
	stored := uint64(0)
	for _, frame := range manifest.Frames {
		stored += frame.UncompressedLength
	}
	if stored >= size*2 {
		t.Fatalf("three identical files stored %d bytes for a %d byte file", stored, size)
	}
}

// TestHardlinkDanglingCountFails covers the seal's obligation: a link count the
// volume cannot account for is refused rather than silently restored as
// independent copies.
func TestHardlinkDanglingCountFails(t *testing.T) {
	content := []byte("linked")
	file := &MemoryFile{Logical: content, Data: []Extent{{Offset: 0, Length: uint64(len(content))}}}
	open := func() (SourceFile, error) { return file, nil }
	cases := []struct {
		name    string
		entries []SourceEntry
	}{
		{
			name: "count exceeds membership",
			entries: []SourceEntry{
				{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
				{ParentIndex: 0, Name: []byte("a"), Type: TypeRegular, Size: 6, Mode: 0o644, Nlink: 3, InodeKey: 9, Open: open},
				{ParentIndex: 0, Name: []byte("b"), Type: TypeRegular, Size: 6, Mode: 0o644, Nlink: 3, InodeKey: 9, Open: open},
			},
		},
		{
			name: "count without an inode identity",
			entries: []SourceEntry{
				{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
				{ParentIndex: 0, Name: []byte("a"), Type: TypeRegular, Size: 6, Mode: 0o644, Nlink: 2, Open: open},
			},
		},
		{
			name: "sole link claiming two",
			entries: []SourceEntry{
				{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
				{ParentIndex: 0, Name: []byte("a"), Type: TypeRegular, Size: 6, Mode: 0o644, Nlink: 2, InodeKey: 4, Open: open},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Build(testConfig(MinChunkSizeBytes), NewSliceSource(testCase.entries), &memoryPacks{})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("build accepted a dangling link count: %v", err)
			}
		})
	}
}

// TestHardlinkGroupSharesOneInode proves group members carry identical content
// identity and that the restore plan materializes the inode once and links the
// rest.
func TestHardlinkGroupSharesOneInode(t *testing.T) {
	content := bytes.Repeat([]byte("shared"), 100)
	size := uint64(len(content))
	file := &MemoryFile{Logical: content, Data: []Extent{{Offset: 0, Length: size}}}
	open := func() (SourceFile, error) { return file, nil }
	entries := []SourceEntry{
		{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
		{ParentIndex: 0, Name: []byte("dir"), Type: TypeDirectory, Mode: 0o755, Nlink: 1},
		{ParentIndex: 1, Name: []byte("first"), Type: TypeRegular, Size: size, Mode: 0o600, Nlink: 2, InodeKey: 77, Open: open},
		{ParentIndex: 0, Name: []byte("second"), Type: TypeRegular, Size: size, Mode: 0o600, Nlink: 2, InodeKey: 77, Open: open},
	}
	manifest, err := Build(testConfig(MinChunkSizeBytes), NewSliceSource(entries), &memoryPacks{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if manifest.Entries[2].HardlinkGroup != 1 || manifest.Entries[3].HardlinkGroup != 1 {
		t.Fatalf("group numbers: %d and %d", manifest.Entries[2].HardlinkGroup, manifest.Entries[3].HardlinkGroup)
	}
	if manifest.Header.LogicalInodes != 3 {
		t.Fatalf("logical inodes %d, want 3 (root, dir, one shared file)", manifest.Header.LogicalInodes)
	}
	if manifest.Header.SealedInodes != 4 {
		t.Fatalf("sealed inodes %d, want 4 (one per entry)", manifest.Header.SealedInodes)
	}
	plan := manifest.NamespacePlan()
	creates, links := 0, 0
	for {
		step, ok := plan.Next()
		if !ok {
			break
		}
		if step.Group == 0 {
			continue
		}
		if step.Creates() {
			creates++
		} else {
			links++
			if step.LinkFrom != 2 {
				t.Fatalf("link step points at entry %d, want 2", step.LinkFrom)
			}
		}
	}
	if creates != 1 || links != 1 {
		t.Fatalf("plan creates %d and links %d, want 1 and 1", creates, links)
	}
}

// TestMultiPackSharding proves an archive shards into several pack objects when
// the configured target is small, that no frame straddles a pack, and that
// every pack is fully covered by its frames.
func TestMultiPackSharding(t *testing.T) {
	const chunkSize = MinChunkSizeBytes
	config := testConfig(chunkSize)
	config.PackTargetBytes = uint64(chunkSize)
	entries := []SourceEntry{{Type: TypeDirectory, Mode: 0o755, Nlink: 1}}
	rng := newRNG(99)
	for index := 0; index < 24; index++ {
		content := rng.bytes(int(chunkSize))
		file := &MemoryFile{Logical: content, Data: []Extent{{Offset: 0, Length: uint64(len(content))}}}
		entries = append(entries, SourceEntry{
			ParentIndex: 0,
			Name:        []byte{'f', byte('a' + index)},
			Type:        TypeRegular,
			Size:        uint64(len(content)),
			Mode:        0o644,
			Nlink:       1,
			MTimeNanos:  int64(1000 - index),
			Open:        func() (SourceFile, error) { return file, nil },
		})
	}
	packs := &memoryPacks{}
	manifest, err := Build(config, NewSliceSource(entries), packs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(manifest.Header.Packs) < 2 {
		t.Fatalf("expected several packs, got %d", len(manifest.Header.Packs))
	}
	for index, pack := range manifest.Header.Packs {
		if uint64(len(packs.packs[index])) != pack.SizeBytes {
			t.Fatalf("pack %d is %d bytes, manifest says %d", index, len(packs.packs[index]), pack.SizeBytes)
		}
		if CRC64NVMESum(packs.packs[index]) != pack.CRC64NVME {
			t.Fatalf("pack %d checksum does not match the manifest", index)
		}
		if sha256.Sum256(packs.packs[index]) != pack.SHA256 {
			t.Fatalf("pack %d digest does not match the manifest", index)
		}
	}
	verifyManifestRoundTrip(t, manifest, packs)
}

// TestPriorityBoundary proves the wake-prefetch landmark is real: it lands on a
// frame boundary, it covers recently modified small files, and it never reaches
// into the large-file region, which is demand-recall only.
func TestPriorityBoundary(t *testing.T) {
	const chunkSize = MinChunkSizeBytes
	config := testConfig(chunkSize)
	config.PriorityLogicalBytes = uint64(chunkSize)
	rng := newRNG(5)
	entries := []SourceEntry{{Type: TypeDirectory, Mode: 0o755, Nlink: 1}}
	add := func(name string, size int, mtime int64) {
		content := rng.bytes(size)
		file := &MemoryFile{Logical: content, Data: []Extent{{Offset: 0, Length: uint64(size)}}}
		entries = append(entries, SourceEntry{
			ParentIndex: 0, Name: []byte(name), Type: TypeRegular, Size: uint64(size),
			Mode: 0o644, Nlink: 1, MTimeNanos: mtime,
			Open: func() (SourceFile, error) { return file, nil },
		})
	}
	// A recent large file must not be able to sit inside the prefetch region.
	add("huge", int(chunkSize)*4, 9000)
	for index := 0; index < 8; index++ {
		add("small"+string(rune('a'+index)), int(chunkSize)/2, int64(8000-index))
	}
	packs := &memoryPacks{}
	manifest, err := Build(config, NewSliceSource(entries), packs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	boundary := manifest.Header.Priority
	prefetch := uint64(0)
	for index := uint32(0); index < boundary.PackIndex; index++ {
		prefetch += manifest.Header.Packs[index].SizeBytes
	}
	prefetch += boundary.PackOffset
	if prefetch == 0 {
		t.Fatalf("prefetch region is empty")
	}
	if prefetch >= manifest.TotalPackBytes() {
		t.Fatalf("prefetch region covers the whole archive including the large file")
	}
	// Every frame that starts inside the prefetch region must belong only to
	// small files: no chunk of the large file may be reachable by prefetch.
	largeFrames := map[uint32]struct{}{}
	for _, chunk := range manifest.Entries[1].Chunks {
		largeFrames[chunk.FrameIndex] = struct{}{}
	}
	position := uint64(0)
	for index, frame := range manifest.Frames {
		if position < prefetch {
			if _, isLarge := largeFrames[uint32(index)]; isLarge {
				t.Fatalf("frame %d belongs to the large file but lies inside the prefetch region", index)
			}
		}
		position += frame.CompressedLength
	}
	// The boundary must land exactly on a frame boundary.
	position = 0
	onBoundary := prefetch == 0
	for _, frame := range manifest.Frames {
		position += frame.CompressedLength
		if position == prefetch {
			onBoundary = true
		}
	}
	if !onBoundary {
		t.Fatalf("prefetch boundary %d is not a frame boundary", prefetch)
	}
	ranges := manifest.PrefetchRanges(RangePolicy{})
	if len(ranges) == 0 {
		t.Fatalf("prefetch produced no ranges")
	}
	total := uint64(0)
	for _, byteRange := range ranges {
		total += byteRange.Length
	}
	if total != prefetch {
		t.Fatalf("prefetch ranges cover %d bytes, boundary says %d", total, prefetch)
	}
}

// TestBuilderRefusesBadConfig covers the configuration mistakes that would only
// surface after gigabytes had been uploaded.
func TestBuilderRefusesBadConfig(t *testing.T) {
	base := testConfig(MinChunkSizeBytes)
	cases := map[string]func(*BuilderConfig){
		"chunk size not a power of two": func(c *BuilderConfig) { c.ChunkSizeBytes = 5000 },
		"chunk size too small":          func(c *BuilderConfig) { c.ChunkSizeBytes = 512 },
		"window log out of range":       func(c *BuilderConfig) { c.WindowLog = 63 },
		"compression level out of range": func(c *BuilderConfig) {
			c.CompressionLevel = 99
		},
		"zero volume":    func(c *BuilderConfig) { c.VolumeID = [16]byte{} },
		"zero attempt":   func(c *BuilderConfig) { c.Attempt = [16]byte{} },
		"zero epoch":     func(c *BuilderConfig) { c.SealedEpoch = 0 },
		"part too small": func(c *BuilderConfig) { c.PartSizeBytes = 1 << 20 },
		"part too large": func(c *BuilderConfig) { c.PartSizeBytes = 6 << 30 },
		"pack too large": func(c *BuilderConfig) { c.PackTargetBytes = 128 << 30 },
		"pack below chunk": func(c *BuilderConfig) {
			c.ChunkSizeBytes = 1 << 20
			c.PackTargetBytes = 4096
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			source := NewSliceSource([]SourceEntry{{Type: TypeDirectory, Mode: 0o755, Nlink: 1}})
			if _, err := Build(config, source, &memoryPacks{}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("build accepted %s: %v", name, err)
			}
		})
	}
}

// TestBuilderRefusesBadSource covers a walk that does not describe a tree.
func TestBuilderRefusesBadSource(t *testing.T) {
	cases := map[string][]SourceEntry{
		"root is not a directory": {{Type: TypeRegular, Mode: 0o644, Nlink: 1}},
		"root is named":           {{Type: TypeDirectory, Name: []byte("x"), Mode: 0o755, Nlink: 1}},
		"forward parent reference": {
			{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
			{ParentIndex: 5, Name: []byte("a"), Type: TypeDirectory, Mode: 0o755, Nlink: 1},
		},
		"file with no reader": {
			{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
			{ParentIndex: 0, Name: []byte("a"), Type: TypeRegular, Size: 10, Mode: 0o644, Nlink: 1},
		},
		"duplicate sibling names": {
			{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
			{ParentIndex: 0, Name: []byte("a"), Type: TypeDirectory, Mode: 0o755, Nlink: 1},
			{ParentIndex: 0, Name: []byte("a"), Type: TypeDirectory, Mode: 0o755, Nlink: 1},
		},
		"name with a separator": {
			{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
			{ParentIndex: 0, Name: []byte("a/b"), Type: TypeDirectory, Mode: 0o755, Nlink: 1},
		},
		"xattr outside the user namespace": {
			{Type: TypeDirectory, Mode: 0o755, Nlink: 1,
				Xattrs: []Xattr{{Name: []byte("security.capability"), Value: []byte("x")}}},
		},
		"duplicate xattr name": {
			{Type: TypeDirectory, Mode: 0o755, Nlink: 1, Xattrs: []Xattr{
				{Name: []byte("user.a"), Value: []byte("one")},
				{Name: []byte("user.a"), Value: []byte("two")},
			}},
		},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(testConfig(MinChunkSizeBytes), NewSliceSource(entries), &memoryPacks{}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("build accepted %s: %v", name, err)
			}
		})
	}
}

// TestSourceErrorAborts proves a walk that fails does not produce a manifest
// that quietly omits what it could not read.
func TestSourceErrorAborts(t *testing.T) {
	failing := &failingSource{entries: []SourceEntry{{Type: TypeDirectory, Mode: 0o755, Nlink: 1}}}
	if _, err := Build(testConfig(MinChunkSizeBytes), failing, &memoryPacks{}); err == nil {
		t.Fatalf("build ignored a source failure")
	}
}

type failingSource struct {
	entries []SourceEntry
	at      int
}

func (f *failingSource) Next() (SourceEntry, error) {
	if f.at < len(f.entries) {
		entry := f.entries[f.at]
		f.at++
		return entry, nil
	}
	return SourceEntry{}, io.ErrUnexpectedEOF
}

func verifyManifestRoundTrip(t *testing.T, manifest *Manifest, packs *memoryPacks) {
	t.Helper()
	encoded, err := Encode(manifest)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reader, err := NewPackReader(decoded, packs)
	if err != nil {
		t.Fatalf("pack reader: %v", err)
	}
	for index := range decoded.Entries {
		if decoded.Entries[index].Type != TypeRegular {
			continue
		}
		if _, err := reader.ReadFile(uint32(index)); err != nil {
			t.Fatalf("entry %d read back: %v", index, err)
		}
	}
}
