//go:build linux

package tierede2e

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// lifecycleChunkSize is the archive chunk size the whole flow is built around.
// 64 KiB is a power of two inside [archive.MinChunkSizeBytes, 8 MiB], which is
// what both the archiver and the hydrator bound it to, and it is small enough
// that a 200 KiB file is genuinely multi-chunk, a hole can span whole chunks,
// and a truncate can cross a chunk boundary — all without writing megabytes
// into a 512 MiB project quota.
const lifecycleChunkSize = uint32(64 << 10)

// The relative paths the flow names explicitly. Everything else in the tree is
// there to make the archive shape realistic.
const (
	pathBig        = "docs/nested/deep/big.bin"
	pathWriteMe    = "docs/nested/writeme.bin"
	pathTruncateMe = "docs/nested/truncme.bin"
	pathSparse     = "sparse.bin"
	pathSmallA     = "docs/small/a.txt"
	pathSmallB     = "docs/small/b.txt"
	pathSmallC     = "docs/small/c.txt"
	pathLinkedA    = "linked-a"
	pathLinkedB    = "linked-b"
	pathLinkedC    = "docs/linked-c"
	pathSymlink    = "link-inside"
	pathDangling   = "link-dangling"
	pathEmptyFile  = "empty"
	pathEmptyDir   = "empty-dir"
	pathUnicode    = "docs/ünïcödé-名前.txt"
	pathReadOnly   = "readonly.bin"
	pathSealed     = "sealed.bin"
	pathClosedDir  = "closed-dir"

	// protectedNamespace is the authority's own subtree inside the volume. It
	// is created by the serving authority, never by the archive, so the
	// full-tree comparisons exclude it on both sides.
	protectedNamespace = ".portablefs"
)

// longName is the near-maximum-length name the format bounds at 255 bytes.
func longName() string { return strings.Repeat("l", 251) + ".txt" }

// sourceTree is the description of the tree that was archived, retained across
// the destroy so the restored volume can be compared with something that no
// longer exists on any filesystem.
type sourceTree struct {
	root string
	// facts is the complete metadata-and-content snapshot taken immediately
	// before the source was destroyed.
	facts map[string]nodeFacts
	// bytes is the logical content of every regular file that was readable at
	// snapshot time, keyed by relative path.
	bytes map[string][]byte
}

// buildSourceTree materializes the demanding tree the lifecycle archives. Every
// property it establishes is one the pack format or the restore contract
// promises to carry: nesting, shared small-file frames, a multi-chunk file, a
// real hole, a hardlink group, symlinks including a dangling one, user.*
// xattrs, distinctive nanosecond mtimes, a unicode name, a 255-byte name, an
// empty file and an empty directory, and a read-only file.
func buildSourceTree(t *testing.T, root string) *sourceTree {
	t.Helper()
	tree := &sourceTree{root: root, bytes: map[string][]byte{}}
	chunk := uint64(lifecycleChunkSize)

	mkdir := func(rel string, mode os.FileMode) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(root, rel), mode); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		// Mkdir applies the umask; the tree asserts on exact modes.
		if err := os.Chmod(filepath.Join(root, rel), mode); err != nil {
			t.Fatalf("chmod %s: %v", rel, err)
		}
	}
	write := func(rel string, payload []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, rel), payload, mode); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
		// WriteFile applies the umask; the tree asserts on exact modes.
		if err := os.Chmod(filepath.Join(root, rel), mode); err != nil {
			t.Fatalf("chmod %s: %v", rel, err)
		}
		tree.bytes[rel] = payload
	}

	mkdir("docs", 0o755)
	mkdir("docs/nested", 0o750)
	mkdir("docs/nested/deep", 0o755)
	mkdir("docs/small", 0o755)
	mkdir(pathEmptyDir, 0o755)

	// A multi-chunk file: four chunks, the last one partial, fully allocated.
	write(pathBig, pseudoRandom(3*chunk+1234, 0x51ed270b), 0o644)
	// Two more multi-chunk files reserved for the mutation assertions, so the
	// byte-for-byte comparison of the rest of the tree stays unconditional.
	write(pathWriteMe, pseudoRandom(chunk+900, 0x1d872b41), 0o644)
	write(pathTruncateMe, pseudoRandom(2*chunk+500, 0x6c8e9cf5), 0o644)

	// Small files under one parent sharing one extension: the builder groups
	// them into a single frame, so one fetched frame answers all three.
	write(pathSmallA, pseudoRandom(137, 0x01234567), 0o644)
	write(pathSmallB, pseudoRandom(211, 0x07654321), 0o644)
	write(pathSmallC, pseudoRandom(89, 0x0abcdef1), 0o640)

	write(pathUnicode, pseudoRandom(321, 0x13579bdf), 0o644)
	write(filepath.Join("docs", longName()), pseudoRandom(97, 0x2468ace0), 0o644)
	write(pathEmptyFile, nil, 0o644)

	// A sparse file whose middle two chunks lie wholly inside one hole: the
	// archive stores nothing for them and the restored file must keep them as
	// holes that read as zeroes without ever being fetched.
	buildSparse(t, filepath.Join(root, pathSparse), tree, 4*chunk, chunk)

	// One hardlink group of three names across two directories.
	write(pathLinkedA, []byte("one inode, three names, one hydration entry"), 0o644)
	for _, rel := range []string{pathLinkedB, pathLinkedC} {
		if err := os.Link(filepath.Join(root, pathLinkedA), filepath.Join(root, rel)); err != nil {
			t.Fatalf("link %s: %v", rel, err)
		}
		tree.bytes[rel] = tree.bytes[pathLinkedA]
	}

	if err := os.Symlink("docs/small/a.txt", filepath.Join(root, pathSymlink)); err != nil {
		t.Fatalf("symlink %s: %v", pathSymlink, err)
	}
	if err := os.Symlink("nowhere/at/all", filepath.Join(root, pathDangling)); err != nil {
		t.Fatalf("symlink %s: %v", pathDangling, err)
	}

	// Ordinary portable user.* attributes on a file and on a directory. The
	// names deliberately avoid the reserved user.portablefs.* prefix, which the
	// authority hides from every client (xfsstore.ValidateXattr): an attribute
	// under that prefix would round-trip through the archive correctly and still
	// be invisible through the mount, which would be a confusing thing for this
	// test to appear to be asserting.
	setXattr(t, filepath.Join(root, pathSmallA), "user.tierede2e.file", []byte("\x00\x01binary value"))
	setXattr(t, filepath.Join(root, "docs"), "user.tierede2e.dir", []byte("directory attribute"))

	// A file the owner may read but not write, a file the owner may not even
	// read, and a directory the owner may read but not traverse. These are not
	// optional: an archive that cannot carry them cannot carry a real
	// workspace, and RestrictedModesAreCarried is the stage that proves it.
	write(pathReadOnly, pseudoRandom(chunk+777, 0x3c6ef372), 0o444)
	write(pathSealed, pseudoRandom(1500, 0x5bf03635), 0o000)
	mkdir(pathClosedDir, 0o444)

	// mtimes last and deepest first: creating a child moves its parent's mtime,
	// so the directories are stamped after everything inside them exists.
	stamp := int64(1_700_000_000_000_000_000)
	for index, path := range allPathsDeepestFirst(t, root) {
		setMTime(t, path, stamp+int64(index)*1_000_000_007)
	}
	setMTime(t, root, stamp+999_999_937)
	return tree
}

func buildSparse(t *testing.T, path string, tree *sourceTree, size, chunk uint64) {
	t.Helper()
	handle, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create the sparse file: %v", err)
	}
	logical := make([]byte, size)
	head := pseudoRandom(4096, 0x2545f491)
	tail := pseudoRandom(8192, 0x9e3779b9)
	copy(logical, head)
	copy(logical[3*chunk:], tail)
	if err := handle.Truncate(int64(size)); err != nil {
		t.Fatalf("size the sparse file: %v", err)
	}
	if _, err := handle.WriteAt(head, 0); err != nil {
		t.Fatalf("write the sparse head: %v", err)
	}
	if _, err := handle.WriteAt(tail, int64(3*chunk)); err != nil {
		t.Fatalf("write the sparse tail: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("close the sparse file: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod the sparse file: %v", err)
	}
	tree.bytes[pathSparse] = logical
}

// ---------------------------------------------------------------------------
// The snapshot and the comparison.
// ---------------------------------------------------------------------------

// nodeFacts is one tree entry as the comparison sees it. Everything here is a
// property the restore contract promises to carry across the archive, except
// inode, which is meaningless on its own and is used only to recover which
// names share one file.
type nodeFacts struct {
	kind     string
	mode     os.FileMode
	mtimeNS  int64
	size     int64
	target   string
	xattrs   string
	content  string
	readable bool
	inode    uint64
	blocks   int64
}

// snapshotTree collects every observable property of a tree, including content
// digests for every regular file the caller may read. It is used on the source
// before the destroy and on the restored volume through the kernel FUSE mount,
// so the two sides are gathered by exactly the same code.
func snapshotTree(t *testing.T, root string) map[string]nodeFacts {
	t.Helper()
	facts := map[string]nodeFacts{}
	var walk func(directory, prefix string)
	walk = func(directory, prefix string) {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("read directory %s: %v", directory, err)
		}
		for _, entry := range entries {
			if prefix == "" && entry.Name() == protectedNamespace {
				continue
			}
			relative := entry.Name()
			if prefix != "" {
				relative = prefix + "/" + entry.Name()
			}
			full := filepath.Join(directory, entry.Name())
			node := describeNode(t, full)
			facts[relative] = node
			// A directory the owner may read but not traverse has no readable
			// children by construction; the tree keeps it empty, so refusing to
			// descend is exact rather than lossy.
			if node.kind == "dir" && node.mode.Perm()&0o100 != 0 {
				walk(full, relative)
			}
		}
	}
	facts["."] = describeNode(t, root)
	walk(root, "")
	return facts
}

func describeNode(t *testing.T, path string) nodeFacts {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	node := nodeFacts{
		mode:    info.Mode().Perm() | (info.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)),
		mtimeNS: info.ModTime().UnixNano(),
	}
	if raw, ok := info.Sys().(*syscall.Stat_t); ok {
		node.inode = uint64(raw.Ino)
		node.blocks = int64(raw.Blocks)
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		node.kind = "link"
		target, err := os.Readlink(path)
		if err != nil {
			t.Fatalf("readlink %s: %v", path, err)
		}
		node.target = target
	case info.IsDir():
		node.kind = "dir"
		node.readable = node.mode.Perm()&0o400 != 0
		if node.readable {
			node.xattrs = readUserXattrs(t, path)
		}
	default:
		node.kind = "reg"
		node.size = info.Size()
		node.readable = node.mode.Perm()&0o400 != 0
		if node.readable {
			node.xattrs = readUserXattrs(t, path)
			payload, err := rawReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if int64(len(payload)) != info.Size() {
				t.Fatalf("%s reported %d bytes and delivered %d", path, info.Size(), len(payload))
			}
			digest := sha256.Sum256(payload)
			node.content = hex.EncodeToString(digest[:])
		}
	}
	return node
}

// expectation describes how one path is allowed to differ from the archived
// source, because the test itself mutated it through the mount.
type expectation struct {
	// content, when non-nil, replaces the archived bytes.
	content []byte
	// mtimeMoved says the path's mtime must now be strictly newer than the
	// archived one rather than equal to it.
	mtimeMoved bool
}

// compareTrees is the full comparison the restore contract calls for: names,
// kinds, modes, nanosecond mtimes, sizes, symlink targets, user.* extended
// attributes, hardlink relations, and — for every readable regular file — the
// content digest. Paths named in mutated are compared against the mutation
// instead of against the archive; paths named in created must exist only in the
// restored tree.
func compareTrees(t *testing.T, want, got map[string]nodeFacts, mutated map[string]expectation, created map[string][]byte, when string) {
	t.Helper()
	names := make([]string, 0, len(want)+len(created))
	for path := range want {
		names = append(names, path)
	}
	for path := range created {
		names = append(names, path)
	}
	sort.Strings(names)

	for _, path := range names {
		if payload, isNew := created[path]; isNew {
			node, present := got[path]
			if !present {
				t.Fatalf("%s: %q was created through the mount and is absent", when, path)
			}
			digest := sha256.Sum256(payload)
			if node.content != hex.EncodeToString(digest[:]) || node.size != int64(len(payload)) {
				t.Fatalf("%s: created file %q is %d bytes with digest %s, want %d bytes",
					when, path, node.size, node.content, len(payload))
			}
			continue
		}
		source, target := want[path], got[path]
		if target.kind == "" {
			t.Fatalf("%s: %q is missing from the restored tree", when, path)
		}
		change, isMutated := mutated[path]
		switch {
		case source.kind != target.kind:
			t.Fatalf("%s: %q is a %s in the archive and a %s restored", when, path, source.kind, target.kind)
		case source.mode != target.mode:
			t.Fatalf("%s: %q has mode %v in the archive and %v restored", when, path, source.mode, target.mode)
		case source.target != target.target:
			t.Fatalf("%s: %q points at %q in the archive and %q restored", when, path, source.target, target.target)
		case source.xattrs != target.xattrs:
			t.Fatalf("%s: %q carries %q in the archive and %q restored", when, path, source.xattrs, target.xattrs)
		}
		if isMutated && change.mtimeMoved {
			if target.mtimeNS <= source.mtimeNS {
				t.Fatalf("%s: %q was mutated through the mount but its mtime is still %d (archived %d)",
					when, path, target.mtimeNS, source.mtimeNS)
			}
		} else if source.mtimeNS != target.mtimeNS {
			t.Fatalf("%s: %q has mtime %d in the archive and %d restored", when, path, source.mtimeNS, target.mtimeNS)
		}
		wantSize, wantContent := source.size, source.content
		if isMutated && change.content != nil {
			digest := sha256.Sum256(change.content)
			wantSize, wantContent = int64(len(change.content)), hex.EncodeToString(digest[:])
		}
		if source.kind == "reg" && target.size != wantSize {
			t.Fatalf("%s: %q is %d bytes, want %d", when, path, target.size, wantSize)
		}
		if source.kind == "reg" && source.readable && target.content != wantContent {
			t.Fatalf("%s: %q has content digest %s, want %s", when, path, target.content, wantContent)
		}
	}

	// Paths the restored tree has and the archive did not.
	for path := range got {
		if _, known := want[path]; known {
			continue
		}
		if _, isNew := created[path]; isNew {
			continue
		}
		t.Fatalf("%s: the restored tree carries %q, which the archive does not", when, path)
	}

	if wantGroups, gotGroups := hardlinkGroups(want), hardlinkGroups(got); !equalGroups(wantGroups, gotGroups) {
		t.Fatalf("%s: hardlink relations differ: archive %v, restored %v", when, wantGroups, gotGroups)
	}
}

// hardlinkGroups collapses a tree's inode numbers into the sets of names that
// share one. The numbers themselves are meaningless across a restore; what must
// survive is which names are the same file.
func hardlinkGroups(facts map[string]nodeFacts) [][]string {
	byInode := map[uint64][]string{}
	for path, node := range facts {
		if node.kind != "reg" {
			continue
		}
		byInode[node.inode] = append(byInode[node.inode], path)
	}
	var groups [][]string
	for _, paths := range byInode {
		if len(paths) < 2 {
			continue
		}
		sort.Strings(paths)
		groups = append(groups, paths)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i][0] < groups[j][0] })
	return groups
}

func equalGroups(left, right [][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if fmt.Sprint(left[index]) != fmt.Sprint(right[index]) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Small filesystem helpers.
// ---------------------------------------------------------------------------

// pseudoRandom is SplitMix64 rather than math/rand: a fixture must reproduce
// identical bytes on any toolchain, and the comparison is byte for byte.
func pseudoRandom(size uint64, seed uint64) []byte {
	out := make([]byte, size)
	state := seed
	for index := range out {
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		out[index] = byte(z ^ (z >> 31))
	}
	return out
}

func setXattr(t *testing.T, path, name string, value []byte) {
	t.Helper()
	if err := unix.Setxattr(path, name, value, 0); err != nil {
		t.Fatalf("set %s on %s: %v", name, path, err)
	}
}

// readUserXattrs renders the entry's portable user.* attributes as one stable
// string. Namespaces other than user.* are outside the format's contract.
func readUserXattrs(t *testing.T, path string) string {
	t.Helper()
	size, err := unix.Listxattr(path, nil)
	if err != nil {
		if xattrUnsupported(err) {
			return ""
		}
		t.Fatalf("list attributes of %s: %v", path, err)
	}
	if size == 0 {
		return ""
	}
	buffer := make([]byte, size)
	size, err = unix.Listxattr(path, buffer)
	if err != nil {
		t.Fatalf("list attributes of %s: %v", path, err)
	}
	var parts []string
	for _, name := range strings.Split(strings.TrimRight(string(buffer[:size]), "\x00"), "\x00") {
		if !strings.HasPrefix(name, "user.") {
			continue
		}
		valueSize, err := unix.Getxattr(path, name, nil)
		if err != nil {
			t.Fatalf("size attribute %s of %s: %v", name, path, err)
		}
		value := make([]byte, valueSize)
		if valueSize > 0 {
			if _, err := unix.Getxattr(path, name, value); err != nil {
				t.Fatalf("read attribute %s of %s: %v", name, path, err)
			}
		}
		parts = append(parts, name+"="+string(value))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func xattrUnsupported(err error) bool {
	return err == unix.EOPNOTSUPP || err == unix.ENOTSUP || err == unix.ENOSYS
}

func setMTime(t *testing.T, path string, nanos int64) {
	t.Helper()
	times := []unix.Timespec{unix.NsecToTimespec(nanos), unix.NsecToTimespec(nanos)}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, times, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatalf("set times on %s: %v", path, err)
	}
}

// allPathsDeepestFirst lists every path under root, deepest first, so a caller
// stamping mtimes never disturbs one it has already set.
func allPathsDeepestFirst(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	var walk func(string)
	walk = func(directory string) {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("read %s: %v", directory, err)
		}
		for _, entry := range entries {
			full := filepath.Join(directory, entry.Name())
			if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				info, err := os.Lstat(full)
				if err != nil {
					t.Fatalf("lstat %s: %v", full, err)
				}
				if info.Mode().Perm()&0o100 != 0 {
					walk(full)
				}
			}
			paths = append(paths, full)
		}
	}
	walk(root)
	sort.Slice(paths, func(i, j int) bool {
		return strings.Count(paths[i], string(filepath.Separator)) > strings.Count(paths[j], string(filepath.Separator))
	})
	return paths
}
