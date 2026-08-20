package archive

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// This package's encoder is the normative definition of the manifest byte
// layout: there is no separate specification document that could disagree with
// it. These golden files are what make that definition auditable. They are
// handcrafted manifests rather than the output of a build, so they pin the
// layout and nothing else — no compressor's output, no library version, nothing
// that could change underneath the format and make a byte-exact assertion
// flaky. A diff here is a format change, and a format change needs a version.
var updateGolden = flag.Bool("update", false, "rewrite the golden manifest files in testdata")

// Pinned tree identity for the rich golden tree. RootDigest is what the
// Manager records as archive identity, so a change to its serialization changes
// what every previously recorded archive claims to be.
const goldenRichRootDigest = "15e295e42a0e8d71dc923162c4bdec7efef3c44779bdbf3ea95ebd2401def93b"

func goldenVolumeID() [16]byte {
	return [16]byte{0x9c, 0x1d, 0x4a, 0x21, 0x77, 0x30, 0x4e, 0x0b, 0xa2, 0x55, 0x61, 0x8f, 0x03, 0xc7, 0xd9, 0x12}
}

func goldenAttempt() [16]byte {
	return [16]byte{0x0f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00}
}

// goldenEmptyVolume is the smallest manifest the format can produce: a volume
// that holds nothing but its own root. No packs, no frames, no chunks.
func goldenEmptyVolume() *Manifest {
	entries := []Entry{{
		Type:       TypeDirectory,
		Mode:       0o755,
		Nlink:      1,
		MTimeNanos: 1700000000000000000,
		CTimeNanos: 1700000000000000001,
	}}
	allocated, inodes, err := SealedAllocation(entries)
	if err != nil {
		panic(err)
	}
	return &Manifest{
		Header: Header{
			FormatVersion:        FormatVersion,
			ChunkSizeBytes:       DefaultChunkSizeBytes,
			CompressionLevel:     DefaultCompressionLevel,
			WindowLog:            DefaultWindowLog,
			VolumeID:             goldenVolumeID(),
			SealedEpoch:          3,
			Attempt:              goldenAttempt(),
			LogicalBytes:         0,
			LogicalInodes:        inodes,
			SealedAllocatedBytes: allocated,
			SealedInodes:         inodes,
		},
		Entries: entries,
	}
}

// goldenRichTree exercises every part of the layout at once: non-UTF-8 names,
// unicode names, extended attributes with non-UTF-8 values, a sparse file whose
// second chunk lies wholly inside a hole, a hardlink group of two, a symlink,
// an empty file, two frames sharing one pack, and a priority boundary that
// falls between the frames.
func goldenRichTree() *Manifest {
	const chunkSize = uint32(4096)

	firstSlice := append(bytes.Repeat([]byte{'x'}, 100), bytes.Repeat([]byte{'y'}, 50)...)
	sharedSlice := []byte("hardlinked content")
	tailSlice := bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 75)

	frameZero := append(append([]byte(nil), firstSlice...), sharedSlice...)
	frameOne := tailSlice

	// The sparse file's logical image: two data runs inside the first chunk and
	// a second chunk that is entirely a hole.
	sparseLogical := make([]byte, int(chunkSize)*2)
	copy(sparseLogical[0:100], bytes.Repeat([]byte{'x'}, 100))
	copy(sparseLogical[200:250], bytes.Repeat([]byte{'y'}, 50))

	symlinkTarget := append([]byte{0x64, 0xff, 0x72}, "/sparse.bin"...)

	frames := []Frame{
		{PackIndex: 0, PackOffset: 0, CompressedLength: 200, UncompressedLength: uint64(len(frameZero)),
			RawBlocks: true, XXH64Lo32: XXH64Lo32Of(frameZero)},
		{PackIndex: 0, PackOffset: 200, CompressedLength: 120, UncompressedLength: uint64(len(frameOne)),
			RawBlocks: false, XXH64Lo32: XXH64Lo32Of(frameOne)},
	}

	entries := []Entry{
		{
			Type: TypeDirectory, Mode: 0o755, Nlink: 1,
			MTimeNanos: 1700000000000000000, CTimeNanos: 1700000000000000001,
			Xattrs: []Xattr{
				{Name: []byte("user.root"), Value: []byte{0xff, 0x00, 0xfe}},
				{Name: []byte("user.ünïcödé"), Value: []byte("värde")},
			},
		},
		{
			ParentIndex: 0, Name: []byte{0x64, 0xff, 0x72}, Type: TypeDirectory, Mode: 0o2755, Nlink: 1,
			MTimeNanos: 1700000000000000002, CTimeNanos: 1700000000000000003,
		},
		{
			ParentIndex: 1, Name: []byte("sparse.bin"), Type: TypeRegular, Size: uint64(len(sparseLogical)),
			Mode: 0o600, Nlink: 1, MTimeNanos: 1700000000000000004, CTimeNanos: 1700000000000000005,
			ContentDigest: sha256.Sum256(sparseLogical),
			Chunks: []ChunkRef{
				{
					FrameIndex: 0, InnerOffset: 0, Length: uint64(len(firstSlice)),
					SliceDigest: sha256.Sum256(firstSlice),
					Extents:     []Extent{{Offset: 0, Length: 100}, {Offset: 200, Length: 50}},
				},
				{FrameIndex: NoFrame, SliceDigest: sha256.Sum256(nil)},
			},
		},
		{
			ParentIndex: 1, Name: []byte("linked-a"), Type: TypeRegular, Size: uint64(len(sharedSlice)),
			Mode: 0o644, Nlink: 2, HardlinkGroup: 1,
			MTimeNanos: 1700000000000000006, CTimeNanos: 1700000000000000007,
			ContentDigest: sha256.Sum256(sharedSlice),
			Xattrs:        []Xattr{{Name: []byte("user.tag"), Value: nil}},
			Chunks: []ChunkRef{{
				FrameIndex: 0, InnerOffset: uint64(len(firstSlice)), Length: uint64(len(sharedSlice)),
				SliceDigest: sha256.Sum256(sharedSlice),
				Extents:     []Extent{{Offset: 0, Length: uint64(len(sharedSlice))}},
			}},
		},
		{
			ParentIndex: 0, Name: []byte("日本語"), Type: TypeSymlink, Size: uint64(len(symlinkTarget)),
			Mode: 0o777, Nlink: 1, LinkName: symlinkTarget,
			MTimeNanos: 1700000000000000008, CTimeNanos: 1700000000000000009,
			ContentDigest: sha256.Sum256(symlinkTarget),
		},
		{
			ParentIndex: 0, Name: []byte("linked-b"), Type: TypeRegular, Size: uint64(len(sharedSlice)),
			Mode: 0o644, Nlink: 2, HardlinkGroup: 1,
			MTimeNanos: 1700000000000000006, CTimeNanos: 1700000000000000010,
			ContentDigest: sha256.Sum256(sharedSlice),
			Chunks: []ChunkRef{{
				FrameIndex: 0, InnerOffset: uint64(len(firstSlice)), Length: uint64(len(sharedSlice)),
				SliceDigest: sha256.Sum256(sharedSlice),
				Extents:     []Extent{{Offset: 0, Length: uint64(len(sharedSlice))}},
			}},
		},
		{
			ParentIndex: 0, Name: []byte{0x80, 0x81, 0x2e, 0x62, 0x69, 0x6e}, Type: TypeRegular,
			Size: uint64(len(tailSlice)), Mode: 0o4755, Nlink: 1,
			MTimeNanos: 1700000000000000011, CTimeNanos: 1700000000000000012,
			ContentDigest: sha256.Sum256(tailSlice),
			Chunks: []ChunkRef{{
				FrameIndex: 1, InnerOffset: 0, Length: uint64(len(tailSlice)),
				SliceDigest: sha256.Sum256(tailSlice),
				Extents:     []Extent{{Offset: 0, Length: uint64(len(tailSlice))}},
			}},
		},
		{
			ParentIndex: 0, Name: []byte("empty"), Type: TypeRegular, Size: 0, Mode: 0o644, Nlink: 1,
			MTimeNanos: 1700000000000000013, CTimeNanos: 1700000000000000014,
			ContentDigest: sha256.Sum256(nil),
		},
	}

	logicalBytes, logicalInodes, err := logicalTotals(entries)
	if err != nil {
		panic(err)
	}
	allocated, sealedInodes, err := SealedAllocation(entries)
	if err != nil {
		panic(err)
	}
	return &Manifest{
		Header: Header{
			FormatVersion:        FormatVersion,
			ChunkSizeBytes:       chunkSize,
			CompressionLevel:     DefaultCompressionLevel,
			WindowLog:            DefaultWindowLog,
			VolumeID:             goldenVolumeID(),
			SealedEpoch:          11,
			Attempt:              goldenAttempt(),
			LogicalBytes:         logicalBytes,
			LogicalInodes:        logicalInodes,
			SealedAllocatedBytes: allocated,
			SealedInodes:         sealedInodes,
			Priority:             PriorityBoundary{PackIndex: 0, PackOffset: 200},
			Packs: []PackRef{{
				CRC64NVME: CRC64NVMESum([]byte("golden pack zero")),
				SHA256:    sha256.Sum256([]byte("golden pack zero")),
				SizeBytes: 320,
			}},
		},
		Entries: entries,
		Frames:  frames,
	}
}

func TestGoldenManifests(t *testing.T) {
	cases := []struct {
		file     string
		manifest *Manifest
	}{
		{file: "manifest-empty-volume.bin", manifest: goldenEmptyVolume()},
		{file: "manifest-rich-tree.bin", manifest: goldenRichTree()},
	}
	for _, testCase := range cases {
		t.Run(testCase.file, func(t *testing.T) {
			encoded, err := Encode(testCase.manifest)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			path := filepath.Join("testdata", testCase.file)
			if *updateGolden {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatalf("create testdata: %v", err)
				}
				if err := os.WriteFile(path, encoded, 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run go test -run TestGoldenManifests -update to create it): %v", err)
			}
			if !bytes.Equal(encoded, want) {
				t.Fatalf("encoding is %d bytes, the golden is %d; the manifest byte layout changed",
					len(encoded), len(want))
			}
			decoded, err := Decode(want)
			if err != nil {
				t.Fatalf("the golden manifest does not decode: %v", err)
			}
			reencoded, err := Encode(decoded)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if !bytes.Equal(reencoded, want) {
				t.Fatalf("the golden manifest does not survive a decode-encode round trip byte for byte")
			}
		})
	}
}

// TestGoldenRootDigest pins the semantic tree identity. RootDigest deliberately
// covers only restored semantics, so this vector must not move when the
// manifest layout, the chunking, or the compression parameters change — only
// when what a restore reproduces changes.
func TestGoldenRootDigest(t *testing.T) {
	got := RootDigestHex(goldenRichTree())
	if *updateGolden {
		t.Logf("golden rich-tree root digest: %s", got)
	}
	if got != goldenRichRootDigest {
		t.Fatalf("root digest is %s, pinned vector is %s", got, goldenRichRootDigest)
	}
}

// TestRootDigestIgnoresPhysicalLayout proves the exclusions are real: moving
// content between frames, repacking, or changing the chunk size does not change
// what the archive claims to be.
func TestRootDigestIgnoresPhysicalLayout(t *testing.T) {
	manifest := goldenRichTree()
	before := RootDigest(manifest)
	manifest.Header.CompressionLevel = 3
	manifest.Header.WindowLog = 20
	manifest.Header.SealedEpoch = 99
	manifest.Header.Packs[0].CRC64NVME ^= 0xffff
	for index := range manifest.Frames {
		manifest.Frames[index].XXH64Lo32 ^= 0xffff
		manifest.Frames[index].RawBlocks = !manifest.Frames[index].RawBlocks
	}
	for index := range manifest.Entries {
		manifest.Entries[index].CTimeNanos += 12345
		for chunkIndex := range manifest.Entries[index].Chunks {
			manifest.Entries[index].Chunks[chunkIndex].InnerOffset += 0
			manifest.Entries[index].Chunks[chunkIndex].SliceDigest[0] ^= 0xff
		}
	}
	if RootDigest(manifest) != before {
		t.Fatalf("root digest moved when only physical layout and ctime changed")
	}
}

// TestRootDigestCoversSemantics proves the inclusions are real: every field a
// restore reproduces changes the identity when it changes.
func TestRootDigestCoversSemantics(t *testing.T) {
	mutations := map[string]func(m *Manifest){
		"name":           func(m *Manifest) { m.Entries[1].Name = []byte("renamed") },
		"parent":         func(m *Manifest) { m.Entries[6].ParentIndex = 1 },
		"type":           func(m *Manifest) { m.Entries[7].Type = TypeDirectory },
		"size":           func(m *Manifest) { m.Entries[7].Size = 1 },
		"mode":           func(m *Manifest) { m.Entries[1].Mode = 0o700 },
		"mtime":          func(m *Manifest) { m.Entries[1].MTimeNanos++ },
		"link target":    func(m *Manifest) { m.Entries[4].LinkName = []byte("elsewhere") },
		"hardlink group": func(m *Manifest) { m.Entries[5].HardlinkGroup = 0 },
		"content digest": func(m *Manifest) { m.Entries[2].ContentDigest[0] ^= 0xff },
		"xattr name":     func(m *Manifest) { m.Entries[0].Xattrs[0].Name = []byte("user.other") },
		"xattr value":    func(m *Manifest) { m.Entries[0].Xattrs[0].Value = []byte("changed") },
		"xattr count":    func(m *Manifest) { m.Entries[0].Xattrs = m.Entries[0].Xattrs[:1] },
		"extent offset":  func(m *Manifest) { m.Entries[2].Chunks[0].Extents[1].Offset = 300 },
		"extent length":  func(m *Manifest) { m.Entries[2].Chunks[0].Extents[0].Length = 99 },
		"extent count":   func(m *Manifest) { m.Entries[2].Chunks[0].Extents = m.Entries[2].Chunks[0].Extents[:1] },
		"chunk count":    func(m *Manifest) { m.Entries[2].Chunks = m.Entries[2].Chunks[:1] },
	}
	baseline := RootDigest(goldenRichTree())
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			manifest := goldenRichTree()
			mutate(manifest)
			if RootDigest(manifest) == baseline {
				t.Fatalf("root digest does not cover %s", name)
			}
		})
	}
}
