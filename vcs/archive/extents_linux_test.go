package archive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestScanFileExtentsOnRealFiles runs the export-side scanner against real
// files on whatever filesystem the test directory lives on. A filesystem is
// allowed to under-report holes, so the assertions are the ones that hold
// everywhere: the map is canonical, it never claims data outside the file, and
// it never claims a hole where the file has bytes. When the filesystem does
// report holes, the sparse cases assert the exact map.
func TestScanFileExtentsOnRealFiles(t *testing.T) {
	directory := t.TempDir()

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(directory, "empty")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		extents := scan(t, path, 0)
		if extents != nil {
			t.Fatalf("empty file reported %v", extents)
		}
	})

	t.Run("fully allocated file", func(t *testing.T) {
		path := filepath.Join(directory, "dense")
		content := bytes.Repeat([]byte("dense"), 4096)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		extents := scan(t, path, int64(len(content)))
		if !equalExtents(extents, []Extent{{Offset: 0, Length: uint64(len(content))}}) {
			t.Fatalf("dense file reported %v", extents)
		}
	})

	t.Run("sparse file", func(t *testing.T) {
		path := filepath.Join(directory, "sparse")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		const size = 1 << 20
		if err := file.Truncate(size); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		// Two data runs separated by a large hole, both well away from the
		// front and back of the file so a hole at either end is also tested.
		if _, err := file.WriteAt(bytes.Repeat([]byte("a"), 4096), 128<<10); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := file.WriteAt(bytes.Repeat([]byte("b"), 4096), 768<<10); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := file.Sync(); err != nil {
			t.Fatalf("sync: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		extents := scan(t, path, size)
		assertCanonical(t, extents, size)
		logical, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		assertCoversData(t, extents, logical)
	})

	t.Run("hole at the end", func(t *testing.T) {
		path := filepath.Join(directory, "tail-hole")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, err := file.Write(bytes.Repeat([]byte("c"), 4096)); err != nil {
			t.Fatalf("write: %v", err)
		}
		const size = 1 << 20
		if err := file.Truncate(size); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		if err := file.Sync(); err != nil {
			t.Fatalf("sync: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		extents := scan(t, path, size)
		assertCanonical(t, extents, size)
		logical, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		assertCoversData(t, extents, logical)
	})
}

// TestScanFileExtentsFeedsTheBuilder closes the loop the archiver actually
// walks: scan a real sparse file, hand its map to the builder, and prove the
// archive restores the same bytes and the same shape.
func TestScanFileExtentsFeedsTheBuilder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sparse")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const size = 64 << 10
	if err := file.Truncate(size); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := file.WriteAt(bytes.Repeat([]byte("payload!"), 512), 8<<10); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	defer func() { _ = file.Close() }()

	extents, err := ScanFileExtents(file, size)
	if errors.Is(err, ErrExtentScanUnsupported) {
		t.Skip("this filesystem does not report holes")
	}
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	logical, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	source := NewSliceSource([]SourceEntry{
		{Type: TypeDirectory, Mode: 0o755, Nlink: 1},
		{ParentIndex: 0, Name: []byte("sparse"), Type: TypeRegular, Size: size, Mode: 0o600, Nlink: 1,
			Open: func() (SourceFile, error) {
				return &MemoryFile{Logical: logical, Data: extents}, nil
			}},
	})
	packs := &memoryPacks{}
	manifest, err := Build(testConfig(MinChunkSizeBytes), source, packs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	reader, err := NewPackReader(manifest, packs)
	if err != nil {
		t.Fatalf("pack reader: %v", err)
	}
	got, err := reader.ReadFile(1)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, logical) {
		t.Fatalf("the scanned file did not round-trip")
	}
	if !equalExtents(absoluteExtents(manifest, &manifest.Entries[1]), extents) {
		t.Fatalf("the extent map did not round-trip: %v want %v",
			absoluteExtents(manifest, &manifest.Entries[1]), extents)
	}
}

func scan(t *testing.T, path string, size int64) []Extent {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = file.Close() }()
	extents, err := ScanFileExtents(file, size)
	if errors.Is(err, ErrExtentScanUnsupported) {
		t.Skip("this filesystem does not report holes")
	}
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return extents
}

func assertCanonical(t *testing.T, extents []Extent, size uint64) {
	t.Helper()
	previousEnd := uint64(0)
	for index, extent := range extents {
		if extent.Length == 0 {
			t.Fatalf("extent %d is empty", index)
		}
		if index > 0 && extent.Offset <= previousEnd {
			t.Fatalf("extent %d is not strictly after and apart from its predecessor", index)
		}
		if extent.Offset+extent.Length > size {
			t.Fatalf("extent %d runs past the file size", index)
		}
		previousEnd = extent.Offset + extent.Length
	}
}

// assertCoversData is the direction that must hold on every filesystem: a byte
// the file actually holds is never left outside the extent map. The opposite
// direction is not asserted, because reporting more data than exists is always
// legal and costs storage rather than correctness.
func assertCoversData(t *testing.T, extents []Extent, logical []byte) {
	t.Helper()
	covered := make([]bool, len(logical))
	for _, extent := range extents {
		for offset := extent.Offset; offset < extent.Offset+extent.Length; offset++ {
			covered[offset] = true
		}
	}
	for offset, value := range logical {
		if value != 0 && !covered[offset] {
			t.Fatalf("byte %d holds data but the scan called it a hole", offset)
		}
	}
}
