package pft2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestBuildDirectoryTreeDeterminismAndShape(t *testing.T) {
	makeEntries := func(count int) []DirEntry {
		entries := make([]DirEntry, count)
		for i := range entries {
			entries[i] = DirEntry{
				Name: fmt.Sprintf("entry-%08d", i),
				Ino:  uint64(i + 2),
				Kind: FileKindRegular,
			}
		}
		return entries
	}

	t.Run("single leaf collapses to root", func(t *testing.T) {
		store := NewMemoryStore()
		root, count, err := BuildDirectoryTree(makeEntries(10), store)
		if err != nil {
			t.Fatal(err)
		}
		if count != 10 {
			t.Fatalf("count %d", count)
		}
		data, err := store.Fetch(context.Background(), *root)
		if err != nil {
			t.Fatal(err)
		}
		node, err := DecodeNodeKind(data, KindDirectoryLeaf)
		if err != nil {
			t.Fatalf("single-leaf root must be the leaf itself: %v", err)
		}
		if len(node.DirectoryLeaf.Entries) != 10 {
			t.Fatalf("leaf entries %d", len(node.DirectoryLeaf.Entries))
		}
	})

	t.Run("empty directory has nil root", func(t *testing.T) {
		root, count, err := BuildDirectoryTree(nil, NewMemoryStore())
		if err != nil || root != nil || count != 0 {
			t.Fatalf("got %v %d %v", root, count, err)
		}
	})

	t.Run("large directory splits and reproduces identically", func(t *testing.T) {
		entries := makeEntries(MaxLeafEntries + 100)
		storeA := NewMemoryStore()
		rootA, countA, err := BuildDirectoryTree(entries, storeA)
		if err != nil {
			t.Fatal(err)
		}
		storeB := NewMemoryStore()
		rootB, countB, err := BuildDirectoryTree(entries, storeB)
		if err != nil {
			t.Fatal(err)
		}
		if *rootA != *rootB || countA != countB {
			t.Fatal("identical input produced different trees")
		}
		data, err := storeA.Fetch(context.Background(), *rootA)
		if err != nil {
			t.Fatal(err)
		}
		node, err := DecodeNodeKind(data, KindDirectoryIndex)
		if err != nil {
			t.Fatalf("expected an index root: %v", err)
		}
		var total uint64
		for _, child := range node.DirectoryIndex.Children {
			total += child.EntryCount
		}
		if total != uint64(len(entries)) {
			t.Fatalf("index total %d, want %d", total, len(entries))
		}
	})

	t.Run("unsorted input rejected", func(t *testing.T) {
		entries := makeEntries(3)
		entries[0], entries[2] = entries[2], entries[0]
		if _, _, err := BuildDirectoryTree(entries, NewMemoryStore()); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("index tail rebalance keeps fanout valid", func(t *testing.T) {
		// MaxLeafEntries*MaxIndexChildren+1 leaves would leave a 1-child tail
		// index without the rebalance; use a leaf count that forces it:
		// 256 full leaves + 1 → 257 leaf-level children → runs 256 + 1.
		entries := makeEntries(MaxLeafEntries*MaxIndexChildren + 1)
		// This allocates ~1M entries; keep names short to stay fast.
		for i := range entries {
			entries[i].Name = fmt.Sprintf("%07x", i)
		}
		store := NewMemoryStore()
		root, _, err := BuildDirectoryTree(entries, store)
		if err != nil {
			t.Fatal(err)
		}
		// Walk every reachable index node and check the fanout invariant by
		// decoding (DecodeNode re-validates MinIndexChildren).
		var walk func(ref Ref) error
		walk = func(ref Ref) error {
			data, err := store.Fetch(context.Background(), ref)
			if err != nil {
				return err
			}
			node, err := DecodeNode(data)
			if err != nil {
				return err
			}
			if node.Kind == KindDirectoryIndex {
				for _, child := range node.DirectoryIndex.Children {
					if err := walk(child.Child); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := walk(*root); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCellPackerBoundaries(t *testing.T) {
	cellsPerFullPack := MaxPackBytes / CellBytes

	t.Run("packs close at exactly MaxPackBytes with underfilled terminal", func(t *testing.T) {
		store := NewMemoryStore()
		packer := NewCellPacker()
		total := cellsPerFullPack + 3
		for i := 0; i < total; i++ {
			cell := make([]byte, CellBytes)
			cell[0] = byte(i%255) + 1
			if _, err := packer.Add(cell); err != nil {
				t.Fatal(err)
			}
		}
		refs, err := packer.Finish(store)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != total {
			t.Fatalf("refs %d", len(refs))
		}
		if refs[0].Object.Size != uint64(MaxPackBytes) {
			t.Fatalf("first pack size %d", refs[0].Object.Size)
		}
		terminal := refs[total-1].Object
		if terminal.Size != 3*CellBytes {
			t.Fatalf("terminal pack size %d", terminal.Size)
		}
		if refs[cellsPerFullPack].Object != terminal {
			t.Fatal("cell after the full pack must open the terminal pack")
		}
		if refs[cellsPerFullPack-1].Object != refs[0].Object {
			t.Fatal("last cell of first pack must share its object")
		}
		if store.Len() != 2 {
			t.Fatalf("stored packs %d", store.Len())
		}
	})

	t.Run("all-zero cell rejected", func(t *testing.T) {
		packer := NewCellPacker()
		if _, err := packer.Add(make([]byte, CellBytes)); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong length rejected", func(t *testing.T) {
		packer := NewCellPacker()
		if _, err := packer.Add(make([]byte, CellBytes-1)); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestBuildFileExtents(t *testing.T) {
	t.Run("all-zero content builds no extents", func(t *testing.T) {
		store := NewMemoryStore()
		root, err := BuildFileExtents(make([]byte, 3*PageBytes), store, store)
		if err != nil {
			t.Fatal(err)
		}
		if root != nil || store.Len() != 0 {
			t.Fatalf("zero content produced objects: %v %d", root, store.Len())
		}
	})

	t.Run("empty content builds no extents", func(t *testing.T) {
		store := NewMemoryStore()
		root, err := BuildFileExtents(nil, store, store)
		if err != nil || root != nil {
			t.Fatalf("got %v %v", root, err)
		}
	})

	t.Run("holes and terminal padding are canonical", func(t *testing.T) {
		content := goldenFileContentA()
		store := NewMemoryStore()
		root, err := BuildFileExtents(content, store, store)
		if err != nil {
			t.Fatal(err)
		}
		data, err := store.Fetch(context.Background(), *root)
		if err != nil {
			t.Fatal(err)
		}
		node, err := DecodeNodeKind(data, KindExtentLeaf)
		if err != nil {
			t.Fatal(err)
		}
		if len(node.ExtentLeaf.Entries) != 1 || node.ExtentLeaf.Entries[0].PageOffset != 0 {
			t.Fatalf("expected exactly page 0, got %+v", node.ExtentLeaf.Entries)
		}
		pageData, err := store.Fetch(context.Background(), node.ExtentLeaf.Entries[0].Page)
		if err != nil {
			t.Fatal(err)
		}
		pageNode, err := DecodeNodeKind(pageData, KindDataPage)
		if err != nil {
			t.Fatal(err)
		}
		for i, cell := range pageNode.DataPage.Cells {
			isHole := i >= 4 && i < 8
			if isHole != (cell == nil) {
				t.Fatalf("cell %d hole mismatch", i)
			}
		}
	})

	t.Run("terminal cell zero suffix verifies", func(t *testing.T) {
		content := []byte("hi\n")
		store := NewMemoryStore()
		root, err := BuildFileExtents(content, store, store)
		if err != nil {
			t.Fatal(err)
		}
		leafData, err := store.Fetch(context.Background(), *root)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := DecodeNodeKind(leafData, KindExtentLeaf)
		if err != nil {
			t.Fatal(err)
		}
		pageData, err := store.Fetch(context.Background(), leaf.ExtentLeaf.Entries[0].Page)
		if err != nil {
			t.Fatal(err)
		}
		page, err := DecodeNodeKind(pageData, KindDataPage)
		if err != nil {
			t.Fatal(err)
		}
		cell := page.DataPage.Cells[0]
		packBytes, err := store.Fetch(context.Background(), cell.Object)
		if err != nil {
			t.Fatal(err)
		}
		logical, err := VerifyCellBytes(cell, packBytes, 3)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(logical[:3], content) {
			t.Fatal("cell bytes mismatch")
		}
		// A dirty suffix must fail closed.
		corrupt := append([]byte(nil), packBytes...)
		corrupt[100] = 0xAA
		if _, err := VerifyCellBytes(cell, corrupt, 3); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("dirty suffix accepted: %v", err)
		}
	})

	t.Run("deterministic across rebuilds", func(t *testing.T) {
		content := goldenFileContentA()
		storeA := NewMemoryStore()
		rootA, err := BuildFileExtents(content, storeA, storeA)
		if err != nil {
			t.Fatal(err)
		}
		storeB := NewMemoryStore()
		rootB, err := BuildFileExtents(content, storeB, storeB)
		if err != nil {
			t.Fatal(err)
		}
		if *rootA != *rootB {
			t.Fatal("same content built different extent roots")
		}
	})
}

func TestBuildControlTreeCounts(t *testing.T) {
	entries := []ControlEntry{
		{Key: []byte("a"), Kind: 3, Value: []byte("x")},
		{Key: []byte("b"), Kind: 1},
		{Key: []byte("c"), Kind: 3},
	}
	store := NewMemoryStore()
	root, count, counts, err := BuildControlTree(entries, store)
	if err != nil {
		t.Fatal(err)
	}
	if root == nil || count != 3 {
		t.Fatalf("root %v count %d", root, count)
	}
	want := []ControlKindCount{{Kind: 1, Count: 1}, {Kind: 3, Count: 2}}
	if len(counts) != len(want) || counts[0] != want[0] || counts[1] != want[1] {
		t.Fatalf("counts %+v", counts)
	}
}
