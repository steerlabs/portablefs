package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// Header field offsets, from the normative layout on encode.go. They are
// written out here rather than computed so that a change to the layout breaks
// these tests loudly instead of silently relocating the bytes they patch.
const (
	offsetFormatVersion   = 0
	offsetChunkSize       = 4
	offsetEntryCount      = 56
	offsetFrameCount      = 60
	offsetChunkCount      = 64
	offsetSealedAllocated = 84
	offsetPriorityPack    = 100
	offsetPackCount       = 112
)

// encodeUnchecked serializes a manifest without validating it, so that a test
// can put a structurally wrong manifest on the wire and prove the decoder
// refuses it. Nothing outside tests may do this: Encode validates precisely so
// that an invalid manifest cannot be produced by accident.
func encodeUnchecked(m *Manifest) []byte {
	out := appendHeader(nil, m)
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
	return append(out, manifestMagic...)
}

// sampleManifest builds a small archive that exercises every entry kind the
// negative tests need to damage: directories, a symlink, a sparse file, a
// multi-chunk file, an empty file, xattrs, and a hardlink group.
func sampleManifest(t *testing.T) (*Manifest, *memoryPacks) {
	t.Helper()
	const chunkSize = uint64(MinChunkSizeBytes)
	dense := bytes.Repeat([]byte("dense payload "), 700)
	sparseLogical := make([]byte, chunkSize*3)
	copy(sparseLogical[100:200], bytes.Repeat([]byte("x"), 100))
	copy(sparseLogical[chunkSize*2+50:chunkSize*2+90], bytes.Repeat([]byte("y"), 40))
	shared := []byte("hardlinked content")
	sharedFile := &MemoryFile{Logical: shared, Data: []Extent{{Offset: 0, Length: uint64(len(shared))}}}

	entries := []SourceEntry{
		{Type: TypeDirectory, Mode: 0o755, Nlink: 1, MTimeNanos: 11,
			Xattrs: []Xattr{{Name: []byte("user.root"), Value: []byte{0xff, 0x00 ^ 0x02}}}},
		{ParentIndex: 0, Name: []byte("dir"), Type: TypeDirectory, Mode: 0o2755, Nlink: 1, MTimeNanos: 12},
		{ParentIndex: 1, Name: []byte("dense.bin"), Type: TypeRegular, Size: uint64(len(dense)),
			Mode: 0o644, Nlink: 1, MTimeNanos: 13,
			Open: func() (SourceFile, error) {
				return &MemoryFile{Logical: dense, Data: []Extent{{Offset: 0, Length: uint64(len(dense))}}}, nil
			}},
		{ParentIndex: 1, Name: []byte("sparse.bin"), Type: TypeRegular, Size: uint64(len(sparseLogical)),
			Mode: 0o600, Nlink: 1, MTimeNanos: 14,
			Open: func() (SourceFile, error) {
				return &MemoryFile{Logical: sparseLogical, Data: []Extent{
					{Offset: 100, Length: 100},
					{Offset: chunkSize*2 + 50, Length: 40},
				}}, nil
			}},
		{ParentIndex: 1, Name: []byte("empty"), Type: TypeRegular, Size: 0, Mode: 0o644, Nlink: 1, MTimeNanos: 15},
		{ParentIndex: 0, Name: []byte("link"), Type: TypeSymlink, Size: 7, LinkName: []byte("dir/foo"),
			Mode: 0o777, Nlink: 1, MTimeNanos: 16},
		{ParentIndex: 0, Name: []byte("linked-a"), Type: TypeRegular, Size: uint64(len(shared)),
			Mode: 0o644, Nlink: 2, InodeKey: 42, MTimeNanos: 17,
			Open: func() (SourceFile, error) { return sharedFile, nil }},
		{ParentIndex: 0, Name: []byte("linked-b"), Type: TypeRegular, Size: uint64(len(shared)),
			Mode: 0o644, Nlink: 2, InodeKey: 42, MTimeNanos: 17,
			Open: func() (SourceFile, error) { return sharedFile, nil }},
	}
	packs := &memoryPacks{}
	manifest, err := Build(testConfig(uint32(chunkSize)), NewSliceSource(entries), packs)
	if err != nil {
		t.Fatalf("build sample: %v", err)
	}
	return manifest, packs
}

func TestSampleManifestRoundTrips(t *testing.T) {
	manifest, packs := sampleManifest(t)
	encoded, err := Encode(manifest)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if RootDigest(decoded) != RootDigest(manifest) {
		t.Fatalf("root digest changed across a round trip")
	}
	reader, err := NewPackReader(decoded, packs)
	if err != nil {
		t.Fatalf("pack reader: %v", err)
	}
	sparse, err := reader.ReadFile(3)
	if err != nil {
		t.Fatalf("read sparse file: %v", err)
	}
	if len(sparse) != int(MinChunkSizeBytes)*3 {
		t.Fatalf("sparse file reconstructed to %d bytes", len(sparse))
	}
	if !bytes.Equal(sparse[100:200], bytes.Repeat([]byte("x"), 100)) {
		t.Fatalf("sparse file lost its first extent")
	}
	for _, index := range []int{0, 250, int(MinChunkSizeBytes), int(MinChunkSizeBytes) * 2} {
		if sparse[index] != 0 {
			t.Fatalf("sparse file byte %d is %d, want a hole", index, sparse[index])
		}
	}
	// The middle chunk lies wholly inside a hole and must be stored nowhere.
	if decoded.Entries[3].Chunks[1].Stored() {
		t.Fatalf("a whole-hole chunk was stored")
	}
}

// TestDecodeRejections is the fail-closed suite. Every mutation must be
// refused, and each must be refused for its own distinct, named reason: an
// error that merely says "invalid" would make a corrupt archive and a hostile
// one indistinguishable in an incident.
func TestDecodeRejections(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(t *testing.T, m *Manifest, encoded []byte) []byte
		wantErr string
	}{
		{
			name: "corrupted footer digest",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				encoded[len(encoded)-footerBytes] ^= 0x01
				return encoded
			},
			wantErr: "footer digest does not cover its contents",
		},
		{
			name: "corrupted body under an intact-looking footer",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				encoded[200] ^= 0xff
				return encoded
			},
			wantErr: "footer digest does not cover its contents",
		},
		{
			name: "wrong magic",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				encoded[len(encoded)-1] = 'X'
				return encoded
			},
			wantErr: "does not end with the format magic",
		},
		{
			name: "truncated to nothing",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				return encoded[:32]
			},
			wantErr: "truncated below the minimum size",
		},
		{
			name: "truncated mid-body",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				body := encoded[:len(encoded)-footerBytes]
				return resealBody(body[:len(body)/2])
			},
			wantErr: "cannot be backed by the",
		},
		{
			name: "last record truncated by one byte",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				body := encoded[:len(encoded)-footerBytes]
				return resealBody(body[:len(body)-1])
			},
			wantErr: "extent count 1 cannot be backed by the",
		},
		{
			name: "trailing bytes after the chunk arrays",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				body := append([]byte(nil), encoded[:len(encoded)-footerBytes]...)
				body = append(body, 0, 0, 0, 0)
				return resealBody(body)
			},
			wantErr: "trailing bytes",
		},
		{
			name: "unknown format version",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				return patchBody(encoded, offsetFormatVersion, 2)
			},
			wantErr: "unsupported format version",
		},
		{
			name: "oversized entry count",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				return patchBody(encoded, offsetEntryCount, 0xFFFFFFFF)
			},
			wantErr: "entry count",
		},
		{
			name: "oversized frame count",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				return patchBody(encoded, offsetFrameCount, 0x00FFFFFF)
			},
			wantErr: "frame count",
		},
		{
			name: "oversized chunk count",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				return patchBody(encoded, offsetChunkCount, 0x0FFFFFFF)
			},
			wantErr: "chunk count",
		},
		{
			name: "oversized pack count",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				return patchBody(encoded, offsetPackCount, 0xFFFFFFFF)
			},
			wantErr: "pack count",
		},
		{
			name: "chunk total disagrees with the entries",
			mutate: func(_ *testing.T, m *Manifest, encoded []byte) []byte {
				return patchBody(encoded, offsetChunkCount, uint32(m.ChunkCount())+1)
			},
			wantErr: "entry chunk counts sum to",
		},
		{
			name: "chunk size is not a power of two",
			mutate: func(_ *testing.T, _ *Manifest, encoded []byte) []byte {
				return patchBody(encoded, offsetChunkSize, 5000)
			},
			wantErr: "not a bounded power of two",
		},
		{
			name: "sealed allocation disagrees with the tree",
			mutate: func(_ *testing.T, m *Manifest, encoded []byte) []byte {
				body := append([]byte(nil), encoded[:len(encoded)-footerBytes]...)
				binary.LittleEndian.PutUint64(body[offsetSealedAllocated:], m.Header.SealedAllocatedBytes+4096)
				return resealBody(body)
			},
			wantErr: "sealed allocated bytes",
		},
		{
			name: "priority boundary past the packs",
			mutate: func(_ *testing.T, m *Manifest, encoded []byte) []byte {
				return patchBody(encoded, offsetPriorityPack, uint32(len(m.Header.Packs))+3)
			},
			wantErr: "priority boundary names pack",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			manifest, _ := sampleManifest(t)
			encoded, err := Encode(manifest)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			damaged := testCase.mutate(t, manifest, encoded)
			_, err = Decode(damaged)
			assertRejected(t, err, testCase.wantErr)
		})
	}
}

// TestStructuralRejections damages the model rather than the bytes, then puts
// it on the wire with an unchecked encoder. These are the invariants an
// attacker would have to break to make a manifest mean a different tree than
// the one that was sealed.
func TestStructuralRejections(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(m *Manifest)
		wantErr string
	}{
		{
			name:    "frame reference out of range",
			mutate:  func(m *Manifest) { m.Entries[2].Chunks[0].FrameIndex = uint32(len(m.Frames)) },
			wantErr: "references frame",
		},
		{
			name:    "chunk slice runs past its frame",
			mutate:  func(m *Manifest) { m.Entries[2].Chunks[0].InnerOffset += 1 << 20 },
			wantErr: "runs past the end of frame",
		},
		{
			name:    "parent is not earlier in the table",
			mutate:  func(m *Manifest) { m.Entries[2].ParentIndex = 5 },
			wantErr: "not earlier in the table",
		},
		{
			name:    "root is not self-parented",
			mutate:  func(m *Manifest) { m.Entries[0].ParentIndex = 1 },
			wantErr: "entry 0 is not its own parent",
		},
		{
			name:    "depth-first order broken",
			mutate:  func(m *Manifest) { m.Entries[7].ParentIndex = 1 },
			wantErr: "breaks depth-first order",
		},
		{
			name:    "duplicate sibling names",
			mutate:  func(m *Manifest) { m.Entries[3].Name = append([]byte(nil), m.Entries[2].Name...) },
			wantErr: "duplicates a name under parent",
		},
		{
			name:    "name contains a separator",
			mutate:  func(m *Manifest) { m.Entries[1].Name = []byte("a/b") },
			wantErr: "separator or NUL",
		},
		{
			name:    "name is a directory alias",
			mutate:  func(m *Manifest) { m.Entries[1].Name = []byte("..") },
			wantErr: "directory alias",
		},
		{
			name:    "dangling hardlink count",
			mutate:  func(m *Manifest) { m.Entries[6].Nlink, m.Entries[7].Nlink = 3, 3 },
			wantErr: "members but a link count of",
		},
		{
			name:    "hardlink group members disagree",
			mutate:  func(m *Manifest) { m.Entries[7].ContentDigest[0] ^= 0xff },
			wantErr: "about their shared inode",
		},
		{
			name:    "hardlink group numbers not dense",
			mutate:  func(m *Manifest) { m.Entries[6].HardlinkGroup, m.Entries[7].HardlinkGroup = 4, 4 },
			wantErr: "out of canonical order",
		},
		{
			name:    "link count without a group",
			mutate:  func(m *Manifest) { m.Entries[2].Nlink = 2 },
			wantErr: "with no hardlink group",
		},
		{
			name:    "mode carries type bits",
			mutate:  func(m *Manifest) { m.Entries[1].Mode |= 0o040000 },
			wantErr: "outside the permission and set-ID mask",
		},
		{
			name:    "unknown entry type",
			mutate:  func(m *Manifest) { m.Entries[1].Type = EntryType(9) },
			wantErr: "unknown type",
		},
		{
			name:    "symlink digest does not cover its target",
			mutate:  func(m *Manifest) { m.Entries[5].LinkName = []byte("other!!") },
			wantErr: "symlink content digest",
		},
		{
			name:    "directory carrying file state",
			mutate:  func(m *Manifest) { m.Entries[1].LinkName = []byte("x") },
			wantErr: "directory carrying file state",
		},
		{
			name:    "chunk count does not match the size",
			mutate:  func(m *Manifest) { m.Entries[2].Size += uint64(MinChunkSizeBytes) },
			wantErr: "chunks but its size needs",
		},
		{
			name: "extent runs past the chunk span",
			mutate: func(m *Manifest) {
				m.Entries[3].Chunks[0].Extents[0].Length = uint64(MinChunkSizeBytes) * 2
			},
			wantErr: "runs past the chunk span",
		},
		{
			name: "extents overlap",
			mutate: func(m *Manifest) {
				m.Entries[3].Chunks[0].Extents = []Extent{{Offset: 0, Length: 200}, {Offset: 100, Length: 50}}
			},
			wantErr: "not strictly after and apart",
		},
		{
			name: "extents are adjacent rather than merged",
			mutate: func(m *Manifest) {
				m.Entries[3].Chunks[0].Extents = []Extent{{Offset: 0, Length: 100}, {Offset: 100, Length: 100}}
			},
			wantErr: "not strictly after and apart",
		},
		{
			name: "recorded length disagrees with the extents",
			mutate: func(m *Manifest) {
				m.Entries[3].Chunks[0].Length += 8
			},
			wantErr: "extent bytes but records length",
		},
		{
			name: "unstored chunk names a frame",
			mutate: func(m *Manifest) {
				m.Entries[3].Chunks[1].FrameIndex = 0
			},
			wantErr: "stores nothing but names a frame location",
		},
		{
			name: "frames leave a gap in a pack",
			mutate: func(m *Manifest) {
				m.Frames[0].CompressedLength--
			},
			wantErr: "breaking the pack concatenation",
		},
		{
			name: "frame runs past its pack",
			mutate: func(m *Manifest) {
				last := len(m.Frames) - 1
				m.Frames[last].CompressedLength += 64
			},
			wantErr: "runs past the end of pack",
		},
		{
			name: "frame decompresses past the chunk size",
			mutate: func(m *Manifest) {
				m.Frames[0].UncompressedLength = uint64(MinChunkSizeBytes) + 1
			},
			wantErr: "past the chunk size",
		},
		{
			name: "empty frame",
			mutate: func(m *Manifest) {
				m.Frames[0].UncompressedLength = 0
			},
			wantErr: "is empty",
		},
		{
			name: "xattr outside the user namespace",
			mutate: func(m *Manifest) {
				m.Entries[0].Xattrs = []Xattr{{Name: []byte("trusted.overlay"), Value: []byte("x")}}
			},
			wantErr: "outside the user. namespace",
		},
		{
			name: "xattrs out of canonical order",
			mutate: func(m *Manifest) {
				m.Entries[0].Xattrs = []Xattr{
					{Name: []byte("user.z"), Value: []byte("1")},
					{Name: []byte("user.a"), Value: []byte("2")},
				}
			},
			wantErr: "not strictly after its predecessor",
		},
		{
			name: "duplicate xattr names",
			mutate: func(m *Manifest) {
				m.Entries[0].Xattrs = []Xattr{
					{Name: []byte("user.a"), Value: []byte("1")},
					{Name: []byte("user.a"), Value: []byte("2")},
				}
			},
			wantErr: "not strictly after its predecessor",
		},
		{
			name: "logical totals disagree with the tree",
			mutate: func(m *Manifest) {
				m.Header.LogicalBytes++
			},
			wantErr: "logical bytes",
		},
		{
			name: "logical inode total disagrees with the tree",
			mutate: func(m *Manifest) {
				m.Header.LogicalInodes++
			},
			wantErr: "logical inodes",
		},
		{
			name: "zero link count",
			mutate: func(m *Manifest) {
				m.Entries[1].Nlink = 0
			},
			wantErr: "zero link count",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			manifest, _ := sampleManifest(t)
			testCase.mutate(manifest)
			if err := Validate(manifest); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate accepted the damaged manifest: %v", err)
			}
			_, err := Decode(encodeUnchecked(manifest))
			assertRejected(t, err, testCase.wantErr)
			if _, err := Encode(manifest); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Encode emitted a manifest Decode refuses: %v", err)
			}
		})
	}
}

// TestDecodeStopsInsideAVariableLengthField covers the cursor itself: a count
// small enough to pass its byte budget, whose records then run past the end
// because their variable-length fields are longer than the budget's per-record
// minimum. The cursor must refuse the read rather than reslice past the buffer.
func TestDecodeStopsInsideAVariableLengthField(t *testing.T) {
	source := NewSliceSource([]SourceEntry{
		{Type: TypeDirectory, Mode: 0o755, Nlink: 1, MTimeNanos: 1},
		{ParentIndex: 0, Name: bytes.Repeat([]byte("n"), MaxNameBytes), Type: TypeDirectory,
			Mode: 0o755, Nlink: 1, MTimeNanos: 2},
	})
	manifest, err := Build(testConfig(MinChunkSizeBytes), source, &memoryPacks{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	encoded, err := Encode(manifest)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	body := encoded[:len(encoded)-footerBytes]
	// Enough bytes for two minimum-size entry records, far too few for the
	// second entry's NAME_MAX name.
	cut := headerFixedBytes + 2*entryFixedBytes + 20
	if cut >= len(body) {
		t.Fatalf("sample is too small to truncate meaningfully")
	}
	_, err = Decode(resealBody(body[:cut]))
	assertRejected(t, err, "manifest is truncated, needed")
}

// TestDecodeIsBoundedByInputSize proves the decoder sizes nothing from a count
// it has not first checked against the bytes it actually holds. A four-byte
// field claiming sixteen million entries in a two-hundred-byte object must be
// refused while it is still four bytes.
func TestDecodeIsBoundedByInputSize(t *testing.T) {
	manifest, _ := sampleManifest(t)
	encoded, err := Encode(manifest)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, count := range []uint32{MaxEntries, MaxEntries - 1, 1 << 20, 1 << 16} {
		damaged := patchBody(encoded, offsetEntryCount, count)
		_, err := Decode(damaged)
		assertRejected(t, err, "cannot be backed by the")
	}
}

// TestEncodeRefusesInvalid proves the encoder is the same gate as the decoder,
// so an invalid manifest cannot be produced by a caller that skips validation.
func TestEncodeRefusesInvalid(t *testing.T) {
	if _, err := Encode(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Encode accepted nil: %v", err)
	}
	if _, err := Encode(&Manifest{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Encode accepted an empty manifest: %v", err)
	}
}

func patchBody(encoded []byte, offset int, value uint32) []byte {
	body := append([]byte(nil), encoded[:len(encoded)-footerBytes]...)
	binary.LittleEndian.PutUint32(body[offset:], value)
	return resealBody(body)
}

func resealBody(body []byte) []byte {
	seal := sha256.Sum256(body)
	out := append([]byte(nil), body...)
	out = append(out, seal[:]...)
	return append(out, manifestMagic...)
}

func assertRejected(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the damaged manifest was accepted")
	}
	if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrFrameCorrupt) {
		t.Fatalf("rejection is not one of the package's errors: %v", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("rejected with %q, expected it to name %q", err.Error(), want)
	}
}
