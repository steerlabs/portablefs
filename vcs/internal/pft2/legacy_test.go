package pft2

import (
	"context"
	"errors"
	"testing"
)

func legacyManifestEntries() []LegacyEntry {
	return []LegacyEntry{
		// Deliberately unordered; adapter sorts by path bytes.
		{Path: "src/main.go", Kind: "file", Mode: 0o644, Size: 9000000,
			BlobDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			BlobSize:   9000000,
			Chunks: []LegacyChunk{
				{Digest: "sha256:c1", Size: 4194304, Offset: 0},
				{Digest: "sha256:c2", Size: 4194304, Offset: 4194304},
				{Digest: "sha256:c3", Size: 611392, Offset: 8388608},
			},
			Ino: 77},
		{Path: "README.md", Kind: "file", Mode: 0o644, Size: 5,
			BlobDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			BlobSize:   5, MtimeMs: 1700000000000},
		{Path: "src", Kind: "directory", Mode: 0o755},
		{Path: "docs/deep/nested.txt", Kind: "file", Mode: 0o600, Size: 0},
		// "docs" and "docs/deep" are deliberately missing from the manifest.
		{Path: "link", Kind: "symlink", Mode: 0o777, LinkTarget: "README.md"},
	}
}

func TestLegacyBaseTreeStructure(t *testing.T) {
	tree, err := NewLegacyBaseTree(legacyManifestEntries())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	root, err := tree.GetInode(ctx, RootIno)
	if err != nil {
		t.Fatal(err)
	}
	if root.Inode.Kind != FileKindDirectory {
		t.Fatalf("root kind %s", root.Inode.Kind)
	}

	// Explicit ino preserved exactly.
	entry, err := tree.Lookup(ctx, root.Ref, "src")
	if err != nil {
		t.Fatal(err)
	}
	srcDir, err := tree.GetInode(ctx, entry.Ino)
	if err != nil {
		t.Fatal(err)
	}
	mainEntry, err := tree.Lookup(ctx, srcDir.Ref, "main.go")
	if err != nil {
		t.Fatal(err)
	}
	if mainEntry.Ino != 77 {
		t.Fatalf("explicit ino not preserved: %d", mainEntry.Ino)
	}

	// Synthesized intermediate directories resolve.
	docsEntry, err := tree.Lookup(ctx, root.Ref, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if docsEntry.Kind != FileKindDirectory {
		t.Fatalf("docs kind %v", docsEntry.Kind)
	}
	docs, err := tree.GetInode(ctx, docsEntry.Ino)
	if err != nil {
		t.Fatal(err)
	}
	deepEntry, err := tree.Lookup(ctx, docs.Ref, "deep")
	if err != nil {
		t.Fatal(err)
	}
	deep, err := tree.GetInode(ctx, deepEntry.Ino)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.Lookup(ctx, deep.Ref, "nested.txt"); err != nil {
		t.Fatal(err)
	}

	// Synthetic inos start above the maximum explicit ino (77).
	if docsEntry.Ino <= 77 {
		t.Fatalf("synthetic ino %d not above explicit max", docsEntry.Ino)
	}

	// ReadDir pages in name-byte order.
	var names []string
	cursor := ""
	for {
		entries, next, err := tree.ReadDir(ctx, root.Ref, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			names = append(names, e.Name)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	want := []string{"README.md", "docs", "link", "src"}
	if len(names) != len(want) {
		t.Fatalf("names %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names %v", names)
		}
	}

	// Symlink metadata.
	linkEntry, err := tree.Lookup(ctx, root.Ref, "link")
	if err != nil {
		t.Fatal(err)
	}
	link, err := tree.GetInode(ctx, linkEntry.Ino)
	if err != nil {
		t.Fatal(err)
	}
	if link.Inode.SymlinkTarget != "README.md" || link.Inode.Size != uint64(len("README.md")) {
		t.Fatalf("link inode %+v", link.Inode)
	}

	if _, err := tree.Lookup(ctx, root.Ref, "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent lookup: %v", err)
	}
	if _, err := tree.GetInode(ctx, 123456); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent ino: %v", err)
	}
}

func TestLegacyBaseTreeExtents(t *testing.T) {
	tree, err := NewLegacyBaseTree(legacyManifestEntries())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	main, err := tree.GetInode(ctx, 77)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("chunked file window spans chunk boundary", func(t *testing.T) {
		extents, err := tree.ReadExtents(ctx, main.Ref, 4194304-100, 200)
		if err != nil {
			t.Fatal(err)
		}
		if len(extents) != 2 {
			t.Fatalf("extents %+v", extents)
		}
		first, second := extents[0], extents[1]
		if first.Legacy == nil || first.Legacy.ObjectDigest != "sha256:c1" ||
			first.FileOffset != 4194304-100 || first.Length != 100 ||
			first.Legacy.ObjectOffset != 4194304-100 {
			t.Fatalf("first extent %+v %+v", first, first.Legacy)
		}
		if second.Legacy.ObjectDigest != "sha256:c2" || second.FileOffset != 4194304 ||
			second.Length != 100 || second.Legacy.ObjectOffset != 0 {
			t.Fatalf("second extent %+v %+v", second, second.Legacy)
		}
	})

	t.Run("whole-blob file", func(t *testing.T) {
		root, err := tree.GetInode(ctx, RootIno)
		if err != nil {
			t.Fatal(err)
		}
		readmeEntry, err := tree.Lookup(ctx, root.Ref, "README.md")
		if err != nil {
			t.Fatal(err)
		}
		readme, err := tree.GetInode(ctx, readmeEntry.Ino)
		if err != nil {
			t.Fatal(err)
		}
		extents, err := tree.ReadExtents(ctx, readme.Ref, 1, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(extents) != 1 {
			t.Fatalf("extents %+v", extents)
		}
		e := extents[0]
		if e.FileOffset != 1 || e.Length != 4 || e.Legacy.ObjectOffset != 1 || e.Legacy.ObjectSize != 5 {
			t.Fatalf("extent %+v %+v", e, e.Legacy)
		}
	})

	t.Run("empty file and past-EOF windows", func(t *testing.T) {
		root, _ := tree.GetInode(ctx, RootIno)
		docsEntry, _ := tree.Lookup(ctx, root.Ref, "docs")
		docs, _ := tree.GetInode(ctx, docsEntry.Ino)
		deepEntry, _ := tree.Lookup(ctx, docs.Ref, "deep")
		deep, _ := tree.GetInode(ctx, deepEntry.Ino)
		nestedEntry, err := tree.Lookup(ctx, deep.Ref, "nested.txt")
		if err != nil {
			t.Fatal(err)
		}
		nested, _ := tree.GetInode(ctx, nestedEntry.Ino)
		if extents, err := tree.ReadExtents(ctx, nested.Ref, 0, 10); err != nil || len(extents) != 0 {
			t.Fatalf("%v %v", extents, err)
		}
		if extents, err := tree.ReadExtents(ctx, main.Ref, 9000000, 10); err != nil || len(extents) != 0 {
			t.Fatalf("%v %v", extents, err)
		}
	})

	t.Run("directory rejected", func(t *testing.T) {
		root, _ := tree.GetInode(ctx, RootIno)
		if _, err := tree.ReadExtents(ctx, root.Ref, 0, 10); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestLegacyBaseTreeRejectsBadManifests(t *testing.T) {
	cases := map[string][]LegacyEntry{
		"duplicate ino": {
			{Path: "a", Kind: "file", Mode: 0o644, Ino: 5},
			{Path: "b", Kind: "file", Mode: 0o644, Ino: 5},
		},
		"root ino claimed": {
			{Path: "a", Kind: "file", Mode: 0o644, Ino: 1},
		},
		"duplicate path": {
			{Path: "a", Kind: "file", Mode: 0o644},
			{Path: "a", Kind: "directory", Mode: 0o755},
		},
		"file as parent": {
			{Path: "a", Kind: "file", Mode: 0o644},
			{Path: "a/b", Kind: "file", Mode: 0o644},
		},
		"blob size mismatch": {
			{Path: "a", Kind: "file", Mode: 0o644, Size: 10, BlobDigest: "sha256:x", BlobSize: 9},
		},
		"missing blob": {
			{Path: "a", Kind: "file", Mode: 0o644, Size: 10},
		},
		"non-contiguous chunks": {
			{Path: "a", Kind: "file", Mode: 0o644, Size: 10, Chunks: []LegacyChunk{
				{Digest: "sha256:c", Size: 5, Offset: 1},
			}},
		},
		"chunk sum mismatch": {
			{Path: "a", Kind: "file", Mode: 0o644, Size: 10, Chunks: []LegacyChunk{
				{Digest: "sha256:c", Size: 5, Offset: 0},
			}},
		},
		"bad kind": {
			{Path: "a", Kind: "device", Mode: 0o644},
		},
		"bad path": {
			{Path: "a//b", Kind: "file", Mode: 0o644},
		},
		"dotdot path": {
			{Path: "a/../b", Kind: "file", Mode: 0o644},
		},
		"negative size": {
			{Path: "a", Kind: "file", Mode: 0o644, Size: -1},
		},
		"empty symlink target": {
			{Path: "l", Kind: "symlink", Mode: 0o777, LinkTarget: ""},
		},
		"symlink target with NUL": {
			{Path: "l", Kind: "symlink", Mode: 0o777, LinkTarget: "a\x00b"},
		},
		"timestamp beyond bound": {
			{Path: "a", Kind: "file", Mode: 0o644, MtimeMs: 1 << 60},
		},
		"negative timestamp beyond bound": {
			{Path: "a", Kind: "file", Mode: 0o644, CtimeMs: -(1 << 60)},
		},
	}
	for name, entries := range cases {
		if _, err := NewLegacyBaseTree(entries); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestLegacyModeMaskedToPermissionBits(t *testing.T) {
	// Both adapters keep only the 0o7777 mode bits (type bits are carried by
	// the kind), mirroring the TypeScript adapter exactly.
	tree, err := NewLegacyBaseTree([]LegacyEntry{{Path: "a", Kind: "file", Mode: 0o100644}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	root, err := tree.GetInode(ctx, RootIno)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := tree.Lookup(ctx, root.Ref, "a")
	if err != nil {
		t.Fatal(err)
	}
	file, err := tree.GetInode(ctx, entry.Ino)
	if err != nil {
		t.Fatal(err)
	}
	if file.Inode.Mode != 0o644 {
		t.Fatalf("mode %#o", file.Inode.Mode)
	}
}

func TestLegacyHandlesFailClosedAgainstRealStores(t *testing.T) {
	tree, err := NewLegacyBaseTree(legacyManifestEntries())
	if err != nil {
		t.Fatal(err)
	}
	root, err := tree.GetInode(context.Background(), RootIno)
	if err != nil {
		t.Fatal(err)
	}
	// A legacy handle has size 0: below MinNodeBytes, so a PFT2 reader
	// rejects it before ever fetching.
	if err := checkNodeRefBounds("probe", root.Ref); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("legacy handle passed node ref bounds: %v", err)
	}
}
