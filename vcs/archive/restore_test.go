package archive

import (
	"bytes"
	"errors"
	"testing"
)

// TestNamespacePlanIsMaterializable proves the plan can be applied in one
// forward pass: every step's parent has already been produced, every hardlink
// step points at a step that already created the inode, and every entry appears
// exactly once.
func TestNamespacePlanIsMaterializable(t *testing.T) {
	for seed := uint64(1); seed <= 24; seed++ {
		manifest, _ := buildTree(t, seed)
		created := map[uint32]bool{}
		count := 0
		plan := manifest.NamespacePlan()
		for {
			step, ok := plan.Next()
			if !ok {
				break
			}
			if step.Index != uint32(count) {
				t.Fatalf("seed %d: plan step %d has index %d", seed, count, step.Index)
			}
			if count > 0 && !created[step.ParentIndex] {
				t.Fatalf("seed %d: step %d names parent %d, which has not been created",
					seed, step.Index, step.ParentIndex)
			}
			if count > 0 && manifest.Entries[step.ParentIndex].Type != TypeDirectory {
				t.Fatalf("seed %d: step %d has a non-directory parent", seed, step.Index)
			}
			if !step.Creates() {
				if !created[uint32(step.LinkFrom)] {
					t.Fatalf("seed %d: step %d links to %d, which has not been created",
						seed, step.Index, step.LinkFrom)
				}
				if manifest.Entries[step.LinkFrom].HardlinkGroup != step.Group {
					t.Fatalf("seed %d: step %d links across hardlink groups", seed, step.Index)
				}
			}
			created[step.Index] = true
			count++
		}
		if count != len(manifest.Entries) {
			t.Fatalf("seed %d: plan produced %d steps for %d entries", seed, count, len(manifest.Entries))
		}
	}
}

// TestPathResolves proves the plan's namespace and the manifest's path
// resolution agree, and that raw non-UTF-8 components survive both.
func TestPathResolves(t *testing.T) {
	manifest, _ := sampleManifest(t)
	components, err := manifest.Path(0)
	if err != nil || len(components) != 0 {
		t.Fatalf("root path is %v (%v), want empty", components, err)
	}
	components, err = manifest.Path(2)
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	if len(components) != 2 || !bytes.Equal(components[0], []byte("dir")) ||
		!bytes.Equal(components[1], []byte("dense.bin")) {
		t.Fatalf("path is %q", components)
	}
	if _, err := manifest.Path(uint32(len(manifest.Entries))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("path resolved an entry that does not exist")
	}
}

// TestChunkAtLocatesTheHydratorsWork proves the offset-to-chunk lookup the
// hydrator makes on every cold read is exact at chunk boundaries, at the last
// byte, and past the end.
func TestChunkAtLocatesTheHydratorsWork(t *testing.T) {
	manifest, _ := sampleManifest(t)
	const sparseEntry = uint32(3)
	size := manifest.Entries[sparseEntry].Size
	chunkSize := uint64(manifest.Header.ChunkSizeBytes)
	for offset := uint64(0); offset < size; offset += chunkSize / 3 {
		index, chunk, err := manifest.ChunkAt(sparseEntry, offset)
		if err != nil {
			t.Fatalf("offset %d: %v", offset, err)
		}
		if uint64(index) != offset/chunkSize {
			t.Fatalf("offset %d landed in chunk %d", offset, index)
		}
		if chunk.Stored() != manifest.Entries[sparseEntry].Chunks[index].Stored() {
			t.Fatalf("offset %d returned a different chunk", offset)
		}
	}
	if _, _, err := manifest.ChunkAt(sparseEntry, size); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a read past the end resolved to a chunk")
	}
	if _, _, err := manifest.ChunkAt(1, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a directory resolved to a chunk")
	}
}

// TestReadChunkLogicalMaterializesHoles proves the hydrator's per-chunk read
// places stored bytes back at their logical offsets with holes as zeros.
func TestReadChunkLogicalMaterializesHoles(t *testing.T) {
	manifest, packs := sampleManifest(t)
	reader, err := NewPackReader(manifest, packs)
	if err != nil {
		t.Fatalf("pack reader: %v", err)
	}
	first, err := reader.ReadChunkLogical(3, 0)
	if err != nil {
		t.Fatalf("read chunk: %v", err)
	}
	if len(first) != int(MinChunkSizeBytes) {
		t.Fatalf("chunk is %d bytes, want %d", len(first), MinChunkSizeBytes)
	}
	if !bytes.Equal(first[100:200], bytes.Repeat([]byte("x"), 100)) {
		t.Fatalf("chunk lost its data extent")
	}
	for _, offset := range []int{0, 99, 200, 4095} {
		if first[offset] != 0 {
			t.Fatalf("byte %d is %d, want a hole", offset, first[offset])
		}
	}
	hole, err := reader.ReadChunkLogical(3, 1)
	if err != nil {
		t.Fatalf("read whole-hole chunk: %v", err)
	}
	if len(hole) != int(MinChunkSizeBytes) || !bytes.Equal(hole, make([]byte, MinChunkSizeBytes)) {
		t.Fatalf("a whole-hole chunk did not materialize as zeros")
	}
}

// TestPackReaderRefusesDamagedContent proves verification is not optional: a
// flipped byte in a pack is caught by the frame checksum, and a slice whose
// digest does not match is refused even if the frame around it is intact.
func TestPackReaderRefusesDamagedContent(t *testing.T) {
	manifest, packs := sampleManifest(t)
	reader, err := NewPackReader(manifest, packs)
	if err != nil {
		t.Fatalf("pack reader: %v", err)
	}
	if _, err := reader.ReadFile(2); err != nil {
		t.Fatalf("intact archive: %v", err)
	}
	// Corrupt a payload byte well inside the first pack.
	packs.packs[0][len(packs.packs[0])/2] ^= 0xff
	corrupted := false
	for index := range manifest.Entries {
		if manifest.Entries[index].Type != TypeRegular {
			continue
		}
		if _, err := reader.ReadFile(uint32(index)); errors.Is(err, ErrFrameCorrupt) {
			corrupted = true
		}
	}
	if !corrupted {
		t.Fatalf("a corrupted pack byte was not detected")
	}

	// An intact frame with a lying slice digest must still be refused.
	fresh, freshPacks := sampleManifest(t)
	fresh.Entries[2].Chunks[0].SliceDigest[0] ^= 0xff
	reader, err = NewPackReader(fresh, freshPacks)
	if err == nil {
		if _, err = reader.ReadFile(2); !errors.Is(err, ErrFrameCorrupt) {
			t.Fatalf("a mismatched slice digest was accepted: %v", err)
		}
	}
}

func buildTree(t *testing.T, seed uint64) (*Manifest, *memoryPacks) {
	t.Helper()
	tree := generateTree(seed, uint64(MinChunkSizeBytes), 40)
	packs := &memoryPacks{}
	manifest, err := Build(testConfig(MinChunkSizeBytes), tree.source(), packs)
	if err != nil {
		t.Fatalf("seed %d: build: %v", seed, err)
	}
	return manifest, packs
}
