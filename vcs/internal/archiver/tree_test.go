package archiver

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The source tree the suites archive and restore. It is built from the cases
// the format contract names: deep paths, a non-UTF-8 name, an empty file, a
// file larger than one chunk, a sparse file with a hole-spanning chunk, an
// allocated-zeros file that must not deduplicate with it, a hardlink group,
// symlinks including one whose target escapes the tree, set-ID and sticky
// modes, and portable extended attributes where the filesystem carries them.

// testChunkSize is deliberately the format's minimum. It makes "larger than one
// chunk", "spans several chunks", and "a chunk wholly inside a hole" cheap to
// build and fast to verify, without changing a single code path.
const testChunkSize = 4096

type treeFacts struct {
	root      string
	xattrs    bool
	fileBytes map[string][]byte
	// weirdName is the name that exercises names the format carries as raw
	// bytes. Some filesystems — APFS among them — refuse anything that is not
	// UTF-8, so the tree falls back to a multi-byte unicode name there and says
	// so; the format's handling of raw bytes is unchanged either way.
	weirdName    string
	weirdTarget  string
	rawNamesHeld bool
}

func buildSourceTree(t *testing.T) treeFacts {
	t.Helper()
	root := t.TempDir()
	facts := treeFacts{root: root, fileBytes: map[string][]byte{}}

	mkdir := func(path string, mode os.FileMode) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(root, path), mode); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	write := func(path string, payload []byte) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.WriteFile(full, payload, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		facts.fileBytes[path] = payload
	}

	mkdir("dir", 0o755)
	mkdir("dir/nested", 0o755)
	mkdir("dir/nested/deep", 0o755)
	mkdir("sticky", 0o755)

	write("alpha.txt", []byte("alpha content, small and compressible\n"))
	write("dir/beta.txt", []byte(strings.Repeat("beta ", 200)))
	write("dir/nested/deep/gamma.bin", randomish(3*testChunkSize+17))
	facts.weirdName = writeRawName(t, root, &facts, "\xff\xfe-not-utf8", "ünïcödé-名前",
		[]byte("unusual name bytes survive the round trip"))
	write("empty", nil)
	write("dir/duplicate-a.txt", []byte("identical content deduplicates by slice"))
	write("dir/duplicate-b.txt", []byte("identical content deduplicates by slice"))

	// A sparse file whose middle chunk lies wholly inside a hole, and its
	// allocated-zeros twin: the two share a content digest and must not share
	// an extent map.
	sparse := filepath.Join(root, "sparse.bin")
	handle, err := os.OpenFile(sparse, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("create sparse file: %v", err)
	}
	logical := make([]byte, 4*testChunkSize)
	head := []byte("data at the head of a sparse file")
	tail := []byte("data in the last chunk")
	copy(logical, head)
	copy(logical[3*testChunkSize:], tail)
	if err := handle.Truncate(int64(len(logical))); err != nil {
		t.Fatalf("size sparse file: %v", err)
	}
	if _, err := handle.WriteAt(head, 0); err != nil {
		t.Fatalf("write sparse head: %v", err)
	}
	if _, err := handle.WriteAt(tail, 3*testChunkSize); err != nil {
		t.Fatalf("write sparse tail: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("close sparse file: %v", err)
	}
	facts.fileBytes["sparse.bin"] = logical

	// The pair the format contract calls out: a wholly sparse file and an
	// allocated file of the same zeros. They share a content digest and must
	// not deduplicate, because they restore to different shapes.
	holes, err := os.OpenFile(filepath.Join(root, "holes.bin"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("create the wholly sparse file: %v", err)
	}
	if err := holes.Truncate(4 * testChunkSize); err != nil {
		t.Fatalf("size the wholly sparse file: %v", err)
	}
	if err := holes.Close(); err != nil {
		t.Fatalf("close the wholly sparse file: %v", err)
	}
	facts.fileBytes["holes.bin"] = make([]byte, 4*testChunkSize)
	write("zeros.bin", make([]byte, 4*testChunkSize))

	// One hardlink group of three names across two directories.
	write("linked-a", []byte("one inode, three names"))
	for _, name := range []string{"linked-b", "dir/linked-c"} {
		if err := os.Link(filepath.Join(root, "linked-a"), filepath.Join(root, name)); err != nil {
			t.Fatalf("link %s: %v", name, err)
		}
	}

	for name, target := range map[string]string{
		"link-inside":  "dir/beta.txt",
		"link-outside": "../outside/the/volume",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}
	facts.weirdTarget = "\xff\xfe target bytes"
	if err := os.Symlink(facts.weirdTarget, filepath.Join(root, "link-weird")); err != nil {
		if !errors.Is(err, syscall.EILSEQ) {
			t.Fatalf("symlink link-weird: %v", err)
		}
		facts.weirdTarget = "ünïcödé/target"
		if err := os.Symlink(facts.weirdTarget, filepath.Join(root, "link-weird")); err != nil {
			t.Fatalf("symlink link-weird: %v", err)
		}
	}

	write("setuid", []byte("mode bits round-trip"))
	chmod(t, filepath.Join(root, "setuid"), 0o4755)
	chmod(t, filepath.Join(root, "sticky"), 0o1755)
	chmod(t, filepath.Join(root, "dir"), 0o750)
	chmod(t, filepath.Join(root, "alpha.txt"), 0o640)

	facts.xattrs = setXattrIfSupported(t, filepath.Join(root, "alpha.txt"), "user.portablefs.test", []byte("\x00\x01binary value"))
	if facts.xattrs {
		if !setXattrIfSupported(t, filepath.Join(root, "dir"), "user.portablefs.dir", []byte("directory attribute")) {
			t.Fatalf("attributes worked on a file but not on a directory")
		}
	}

	// mtimes last, deepest first: creating a child moves its parent's mtime, so
	// the directories are stamped after everything inside them exists.
	stamp := int64(1_700_000_000_000_000_000)
	paths := allPaths(t, root)
	for index, path := range paths {
		setMTime(t, path, stamp+int64(index)*1_000_000_007)
	}
	setMTime(t, root, stamp+999_999_937)
	return facts
}

// writeRawName creates a file whose name exercises the format's raw-byte
// names, falling back to a multi-byte unicode name on a filesystem that refuses
// anything but UTF-8.
func writeRawName(t *testing.T, root string, facts *treeFacts, raw, fallback string, payload []byte) string {
	t.Helper()
	name := raw
	err := os.WriteFile(filepath.Join(root, name), payload, 0o644)
	if errors.Is(err, syscall.EILSEQ) {
		t.Logf("filesystem refuses non-UTF-8 names; using %q instead", fallback)
		name = fallback
		err = os.WriteFile(filepath.Join(root, name), payload, 0o644)
	} else if err == nil {
		facts.rawNamesHeld = true
	}
	if err != nil {
		t.Fatalf("write %q: %v", name, err)
	}
	facts.fileBytes[name] = payload
	return name
}

func randomish(size int) []byte {
	out := make([]byte, size)
	state := uint32(0x9e3779b9)
	for index := range out {
		state = state*1664525 + 1013904223
		out[index] = byte(state >> 24)
	}
	return out
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func setXattrIfSupported(t *testing.T, path, name string, value []byte) bool {
	t.Helper()
	handle, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = handle.Close() }()
	err = unix.Fsetxattr(int(handle.Fd()), name, value, 0)
	if err == nil {
		return true
	}
	if xattrUnsupported(err) {
		t.Logf("filesystem does not carry extended attributes; those cases are skipped")
		return false
	}
	t.Fatalf("set attribute on %s: %v", path, err)
	return false
}

func setMTime(t *testing.T, path string, nanos int64) {
	t.Helper()
	times := []unix.Timespec{unix.NsecToTimespec(nanos), unix.NsecToTimespec(nanos)}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, times, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatalf("set times on %s: %v", path, err)
	}
}

// allPaths lists every path under root, deepest first, so a caller stamping
// mtimes never disturbs one it has already set.
func allPaths(t *testing.T, root string) []string {
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
			if entry.IsDir() {
				walk(full)
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

// node is one tree entry as the comparison sees it.
type node struct {
	kind    string
	mode    os.FileMode
	mtime   int64
	size    int64
	target  string
	xattrs  string
	inode   uint64
	blocks  int64
	sparse  bool
	present bool
}

// walkTreeFacts collects every observable property of a tree. Content is
// deliberately absent: a restored file has its logical size and no bytes until
// the authority hydrates it, so the round-trip compares content through the
// hydrator's socket instead.
func walkTreeFacts(t *testing.T, root string) map[string]node {
	t.Helper()
	facts := map[string]node{}
	var walk func(directory, prefix string)
	walk = func(directory, prefix string) {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("read %s: %v", directory, err)
		}
		for _, entry := range entries {
			full := filepath.Join(directory, entry.Name())
			relative := entry.Name()
			if prefix != "" {
				relative = prefix + "/" + entry.Name()
			}
			facts[relative] = describe(t, full)
			if facts[relative].kind == "dir" {
				walk(full, relative)
			}
		}
	}
	facts["."] = describe(t, root)
	walk(root, "")
	return facts
}

func describe(t *testing.T, path string) node {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	out := node{
		mode:    info.Mode().Perm() | (info.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)),
		mtime:   info.ModTime().UnixNano(),
		present: true,
	}
	if raw, ok := info.Sys().(*syscall.Stat_t); ok {
		out.inode = uint64(raw.Ino)
		out.blocks = int64(raw.Blocks)
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		out.kind = "link"
		target, err := os.Readlink(path)
		if err != nil {
			t.Fatalf("readlink %s: %v", path, err)
		}
		out.target = target
	case info.IsDir():
		out.kind = "dir"
		out.xattrs = readXattrsForTest(t, path)
	default:
		out.kind = "reg"
		out.size = info.Size()
		out.sparse = out.blocks == 0
		out.xattrs = readXattrsForTest(t, path)
	}
	return out
}

func readXattrsForTest(t *testing.T, path string) string {
	t.Helper()
	handle, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = handle.Close() }()
	xattrs, err := readUserXattrs(int(handle.Fd()), path)
	if err != nil {
		t.Fatalf("read attributes of %s: %v", path, err)
	}
	parts := make([]string, 0, len(xattrs))
	for _, xattr := range xattrs {
		parts = append(parts, string(xattr.Name)+"="+string(xattr.Value))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
