package pft2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The golden file pins the exact canonical bytes of every node kind plus the
// deterministic-builder output for a small filesystem. The TypeScript
// implementation (packages/core/src/pft2) reads the same file and must
// produce byte-identical encodings and the identical built object set.
// Regenerate with:
//
//	PFT2_UPDATE_GOLDEN=1 go test ./internal/pft2/ -run TestGolden
const goldenRelPath = "../../../testdata/pft2/golden.json"

type goldenVector struct {
	Name   string `json:"name"`
	Hex    string `json:"hex"`
	Digest string `json:"digest"`
	Size   uint64 `json:"size"`
}

type goldenTree struct {
	Name          string `json:"name"`
	RootDigest    string `json:"rootDigest"`
	RootSize      uint64 `json:"rootSize"`
	ObjectCount   int    `json:"objectCount"`
	ObjectSetHash string `json:"objectSetHash"`
}

type goldenFile struct {
	Version int            `json:"version"`
	Vectors []goldenVector `json:"vectors"`
	Trees   []goldenTree   `json:"trees"`
}

// goldenFileContentA is the deterministic 100000-byte file content: byte i is
// (i*7+13)%251, with cells 4..7 of page 0 zeroed (interior holes) and all of
// page 1 zeroed (a wholly omitted page).
func goldenFileContentA() []byte {
	content := make([]byte, 100000)
	for i := range content {
		content[i] = byte((i*7 + 13) % 251)
	}
	for i := 4 * CellBytes; i < 8*CellBytes; i++ {
		content[i] = 0
	}
	for i := PageBytes; i < len(content); i++ {
		content[i] = 0
	}
	return content
}

// buildGoldenFilesystem deterministically materializes the shared golden
// filesystem and returns the ROOT reference plus the object store.
//
//	/            ino 1  (0o755)
//	/a           ino 2  (0o755)
//	/a/empty     ino 3  (0o644, empty file)
//	/a/hello.bin ino 4  (0o644, goldenFileContentA)
//	/link        ino 5  (0o777, symlink -> "a/hello.bin")
//	/small       ino 6  (0o644, "hi\n")
func buildGoldenFilesystem(t *testing.T, store *MemoryStore) Ref {
	t.Helper()
	const timeMs = int64(1700000000000)

	extentA, err := BuildFileExtents(goldenFileContentA(), store, store)
	if err != nil {
		t.Fatal(err)
	}
	if extentA == nil {
		t.Fatal("golden file A must have present pages")
	}
	extentSmall, err := BuildFileExtents([]byte("hi\n"), store, store)
	if err != nil {
		t.Fatal(err)
	}

	putInode := func(ino Inode) Ref {
		encoded, err := EncodeNode(&Node{Kind: KindInode, Inode: &ino})
		if err != nil {
			t.Fatal(err)
		}
		ref := RefOf(encoded)
		if err := store.PutNode(ref, encoded); err != nil {
			t.Fatal(err)
		}
		return ref
	}

	emptyRef := putInode(Inode{
		Ino: 3, Kind: FileKindRegular, Mode: 0o644, Nlink: 1, MtimeMs: timeMs, CtimeMs: timeMs,
	})
	helloRef := putInode(Inode{
		Ino: 4, Kind: FileKindRegular, Mode: 0o644, Nlink: 1, Size: 100000,
		MtimeMs: timeMs, CtimeMs: timeMs, ExtentRoot: extentA,
	})
	linkRef := putInode(Inode{
		Ino: 5, Kind: FileKindSymlink, Mode: 0o777, Nlink: 1, Size: uint64(len("a/hello.bin")),
		MtimeMs: timeMs, CtimeMs: timeMs, SymlinkTarget: "a/hello.bin",
	})
	smallRef := putInode(Inode{
		Ino: 6, Kind: FileKindRegular, Mode: 0o644, Nlink: 1, Size: 3,
		MtimeMs: timeMs, CtimeMs: timeMs, ExtentRoot: extentSmall,
	})

	dirARoot, dirACount, err := BuildDirectoryTree([]DirEntry{
		{Name: "empty", Ino: 3, Kind: FileKindRegular},
		{Name: "hello.bin", Ino: 4, Kind: FileKindRegular},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	dirARef := putInode(Inode{
		Ino: 2, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1,
		MtimeMs: timeMs, CtimeMs: timeMs, DirectoryRoot: dirARoot,
	})

	rootDirRoot, rootDirCount, err := BuildDirectoryTree([]DirEntry{
		{Name: "a", Ino: 2, Kind: FileKindDirectory},
		{Name: "link", Ino: 5, Kind: FileKindSymlink},
		{Name: "small", Ino: 6, Kind: FileKindRegular},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	rootInodeRef := putInode(Inode{
		Ino: 1, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1,
		MtimeMs: timeMs, CtimeMs: timeMs, DirectoryRoot: rootDirRoot,
	})

	inodeIndexRoot, inodeCount, err := BuildInodeIndexTree([]InodeIndexEntry{
		{Ino: 1, Inode: rootInodeRef},
		{Ino: 2, Inode: dirARef},
		{Ino: 3, Inode: emptyRef},
		{Ino: 4, Inode: helloRef},
		{Ino: 5, Inode: linkRef},
		{Ino: 6, Inode: smallRef},
	}, store)
	if err != nil {
		t.Fatal(err)
	}

	rootEncoded, err := EncodeNode(&Node{Kind: KindRoot, Root: &Root{
		RootInode:    rootInodeRef,
		InodeIndex:   *inodeIndexRoot,
		MaxInoSeen:   6,
		InodeCount:   inodeCount,
		DirentCount:  dirACount + rootDirCount,
		LogicalBytes: 100000 + 3 + uint64(len("a/hello.bin")),
	}})
	if err != nil {
		t.Fatal(err)
	}
	rootRef := RefOf(rootEncoded)
	if err := store.PutNode(rootRef, rootEncoded); err != nil {
		t.Fatal(err)
	}
	return rootRef
}

// buildGoldenWideDirectory pins multi-level deterministic construction: a
// 10000-entry directory whose tree has real index nodes (unlike the small
// golden filesystem, whose trees are all single-leaf roots).
func buildGoldenWideDirectory(t *testing.T, store *MemoryStore) Ref {
	t.Helper()
	entries := make([]DirEntry, 10000)
	for i := range entries {
		kind := FileKindRegular
		if i%7 == 0 {
			kind = FileKindDirectory
		}
		entries[i] = DirEntry{
			Name: fmt.Sprintf("entry-%05d-qqqqqqqqqqqqqqqqqqqqqqqq", i),
			Ino:  uint64(i + 2),
			Kind: kind,
		}
	}
	root, count, err := BuildDirectoryTree(entries, store)
	if err != nil {
		t.Fatal(err)
	}
	if count != 10000 {
		t.Fatalf("wide directory count %d", count)
	}
	data, err := store.Fetch(context.Background(), *root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNodeKind(data, KindDirectoryIndex); err != nil {
		t.Fatalf("wide directory root must be an index node: %v", err)
	}
	return *root
}

// buildGoldenRecovery layers the control/recovery objects over the
// filesystem root.
func buildGoldenRecovery(t *testing.T, store *MemoryStore, fsRoot Ref) Ref {
	t.Helper()
	controlEntries := []ControlEntry{
		{Key: []byte("lock\x00ino:4\x000"), Kind: 3, Value: []byte("interval:0-4096")},
		{Key: []byte("session\x00s-1"), Kind: 1, Value: []byte("generation:9")},
		{Key: []byte("session\x00s-2"), Kind: 1},
	}
	mapRoot, entryCount, counts, err := BuildControlTree(controlEntries, store)
	if err != nil {
		t.Fatal(err)
	}
	if entryCount != 3 {
		t.Fatalf("control entry count %d", entryCount)
	}
	controlEncoded, err := EncodeNode(&Node{Kind: KindControlRoot, ControlRoot: &ControlRoot{
		Schema: ControlSchemaVersion, MapRoot: mapRoot, NextCheckoutEpoch: 12, Counts: counts,
	}})
	if err != nil {
		t.Fatal(err)
	}
	controlRef := RefOf(controlEncoded)
	if err := store.PutNode(controlRef, controlEncoded); err != nil {
		t.Fatal(err)
	}
	recoveryEncoded, err := EncodeNode(&Node{Kind: KindRecoveryRoot, RecoveryRoot: &RecoveryRoot{
		AsOfSeq:        987654321,
		FilesystemRoot: fsRoot,
		ControlRoot:    &controlRef,
		InoNamespace:   42,
		NextLocal:      7,
	}})
	if err != nil {
		t.Fatal(err)
	}
	recoveryRef := RefOf(recoveryEncoded)
	if err := store.PutNode(recoveryRef, recoveryEncoded); err != nil {
		t.Fatal(err)
	}
	return recoveryRef
}

func objectSetHash(store *MemoryStore) string {
	var lines []string
	store.mu.RLock()
	for ref := range store.objects {
		lines = append(lines, fmt.Sprintf("%s:%d", ref.Hex(), ref.Size))
	}
	store.mu.RUnlock()
	sort.Strings(lines)
	h := sha256.New()
	for _, line := range lines {
		h.Write([]byte(line))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func currentGolden(t *testing.T) goldenFile {
	t.Helper()
	samples := sampleNodes()
	names := make([]string, 0, len(samples))
	for name := range samples {
		names = append(names, name)
	}
	sort.Strings(names)
	out := goldenFile{Version: 1}
	for _, name := range names {
		encoded, err := EncodeNode(samples[name])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ref := RefOf(encoded)
		out.Vectors = append(out.Vectors, goldenVector{
			Name:   name,
			Hex:    hex.EncodeToString(encoded),
			Digest: ref.Hex(),
			Size:   ref.Size,
		})
	}

	fsStore := NewMemoryStore()
	fsRoot := buildGoldenFilesystem(t, fsStore)
	out.Trees = append(out.Trees, goldenTree{
		Name:          "filesystem",
		RootDigest:    fsRoot.Hex(),
		RootSize:      fsRoot.Size,
		ObjectCount:   fsStore.Len(),
		ObjectSetHash: objectSetHash(fsStore),
	})

	recoveryStore := NewMemoryStore()
	recoveryFsRoot := buildGoldenFilesystem(t, recoveryStore)
	recoveryRoot := buildGoldenRecovery(t, recoveryStore, recoveryFsRoot)
	out.Trees = append(out.Trees, goldenTree{
		Name:          "recovery",
		RootDigest:    recoveryRoot.Hex(),
		RootSize:      recoveryRoot.Size,
		ObjectCount:   recoveryStore.Len(),
		ObjectSetHash: objectSetHash(recoveryStore),
	})

	wideStore := NewMemoryStore()
	wideRoot := buildGoldenWideDirectory(t, wideStore)
	out.Trees = append(out.Trees, goldenTree{
		Name:          "wide-directory",
		RootDigest:    wideRoot.Hex(),
		RootSize:      wideRoot.Size,
		ObjectCount:   wideStore.Len(),
		ObjectSetHash: objectSetHash(wideStore),
	})
	return out
}

func TestGoldenVectors(t *testing.T) {
	current := currentGolden(t)
	path := filepath.Clean(goldenRelPath)
	if os.Getenv("PFT2_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		data, err := json.MarshalIndent(current, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file (regenerate with PFT2_UPDATE_GOLDEN=1): %v", err)
	}
	var stored goldenFile
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	currentJSON, _ := json.MarshalIndent(current, "", "  ")
	storedJSON, _ := json.MarshalIndent(stored, "", "  ")
	if !bytes.Equal(currentJSON, storedJSON) {
		t.Fatalf("golden mismatch (regenerate with PFT2_UPDATE_GOLDEN=1 if intentional)\nstored:  %s\ncurrent: %s",
			storedJSON, currentJSON)
	}

	// Every stored vector must decode strictly and re-encode byte-identically.
	for _, vector := range stored.Vectors {
		raw, err := hex.DecodeString(vector.Hex)
		if err != nil {
			t.Fatal(err)
		}
		ref := RefOf(raw)
		if ref.Hex() != vector.Digest || ref.Size != vector.Size {
			t.Fatalf("%s: stored digest/size do not match bytes", vector.Name)
		}
		node, err := DecodeNode(raw)
		if err != nil {
			t.Fatalf("%s: decode: %v", vector.Name, err)
		}
		reencoded, err := EncodeNode(node)
		if err != nil {
			t.Fatalf("%s: re-encode: %v", vector.Name, err)
		}
		if !bytes.Equal(raw, reencoded) {
			t.Fatalf("%s: golden bytes are not canonical", vector.Name)
		}
	}
}
