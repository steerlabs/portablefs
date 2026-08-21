//go:build linux

package hydrator

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/archive"
	"golang.org/x/sys/unix"
)

// The restrictive-mode restore suite.
//
// An archive may legitimately contain an inode whose mode denies its own owner:
// a mode-0000 file, a directory with no owner write or no owner search. The
// archiver is granted CAP_DAC_READ_SEARCH so it can read such a tree
// (deploy/systemd/portablefs-archiver@.service), which makes those modes
// reachable here. The restorer holds no capability at all, so materialization
// must never depend on being able to traverse or open a node at its final mode:
// every path-based step has to happen while the tree is still owner-accessible,
// and the archived modes land bottom-up at the end.
//
// These cases only mean something for an unprivileged identity - root bypasses
// discretionary access entirely - so when the suite runs as root, which is how
// the Linux suites run in the repository's containers, each case re-executes
// the test binary as an unprivileged uid and reports that child's result.

// unprivilegedUID/GID is nobody:nogroup on Debian and Ubuntu, which is the base
// of the container image the Linux suites run in. Nothing in these cases needs
// that specific identity; it needs only an identity that is not root and does
// not own the repository checkout.
const (
	unprivilegedUID = 65534
	unprivilegedGID = 65534
)

// runsUnprivileged reports whether the file mode actually decides anything for
// this process.
func runsUnprivileged() bool { return os.Geteuid() != 0 }

// rerunUnprivileged re-executes this test binary as an unprivileged uid, running
// exactly the named case, and fails with the child's output if it fails.
//
// The binary is copied to a world-readable directory first: `go test` builds it
// under a root-only temporary directory, which the child could not execute. The
// child gets its own TMPDIR owned by the unprivileged identity so that
// t.TempDir() works there.
func rerunUnprivileged(t *testing.T, name string) {
	t.Helper()
	stage, err := os.MkdirTemp("", "portablefs-unprivileged-")
	if err != nil {
		t.Fatalf("stage directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stage) })
	if err := os.Chmod(stage, 0o755); err != nil {
		t.Fatalf("chmod stage: %v", err)
	}
	binary := filepath.Join(stage, "case.test")
	if err := copyExecutable(os.Args[0], binary); err != nil {
		t.Fatalf("stage the test binary: %v", err)
	}
	work := filepath.Join(stage, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatalf("work directory: %v", err)
	}
	if err := os.Chown(work, unprivilegedUID, unprivilegedGID); err != nil {
		t.Fatalf("chown work directory: %v", err)
	}
	command := exec.Command(binary, "-test.run", "^"+name+"$", "-test.v")
	command.Env = append(os.Environ(), "TMPDIR="+work, "HOME="+work)
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: unprivilegedUID, Gid: unprivilegedGID},
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s as uid %d failed: %v\n%s", name, unprivilegedUID, err, output)
	}
	if !strings.Contains(string(output), "PASS") {
		t.Fatalf("%s as uid %d did not report PASS:\n%s", name, unprivilegedUID, output)
	}
	t.Logf("%s ran as uid %d", name, unprivilegedUID)
}

func copyExecutable(from, to string) error {
	source, err := os.Open(from)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		return err
	}
	return destination.Close()
}

// xattrsCarried reports whether the filesystem under the restore root carries
// user.* attributes. Containers often place a temporary directory on a
// filesystem that does not, and the ordering these cases pin is the same either
// way, so the attribute assertions are conditional rather than a hard
// requirement.
func xattrsCarried(t *testing.T, directory string) bool {
	t.Helper()
	probe := filepath.Join(directory, ".xattr-probe")
	file, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("xattr probe: %v", err)
	}
	err = unix.Fsetxattr(int(file.Fd()), "user.portablefs-probe", []byte("1"), 0)
	_ = file.Close()
	_ = os.Remove(probe)
	if err == nil {
		return true
	}
	t.Logf("the restore filesystem does not carry user.* attributes (%v); the attribute assertions are skipped", err)
	return false
}

// restrictiveManifest is the tree these cases restore. Every node that could
// block the restorer at its final mode is present:
//
//	/                       0755  directory
//	/locked                 0000  file, unreadable and unwritable by its owner
//	/ro                     0500  directory, no owner write: a child cannot be
//	                              created inside it once the mode has landed
//	/ro/original.txt        0644  file, first name of a hardlink group
//	/sealed                 0000  directory, not even searchable by its owner
//	/sealed/inner           0700  directory
//	/sealed/inner/deep.txt  0400  file, read-only and larger than nothing
//	/sealed/link            ----  symlink inside the unsearchable directory
//	/alias.txt              0644  second name of the hardlink group, whose link
//	                              source lives inside the 0500 directory
func restrictiveManifest(xattrs bool) *archive.Manifest {
	attribute := func(name, value string) []archive.Xattr {
		if !xattrs {
			return nil
		}
		return []archive.Xattr{{Name: []byte(name), Value: []byte(value)}}
	}
	entries := []archive.Entry{
		{ParentIndex: 0, Name: nil, Type: archive.TypeDirectory, Mode: 0o755,
			MTimeNanos: 1_700_000_000_000_000_001, Xattrs: attribute("user.node", "root")},
		{ParentIndex: 0, Name: []byte("locked"), Type: archive.TypeRegular, Mode: 0o000,
			MTimeNanos: 1_700_000_100_000_000_002, Nlink: 1, Xattrs: attribute("user.node", "locked")},
		{ParentIndex: 0, Name: []byte("ro"), Type: archive.TypeDirectory, Mode: 0o500,
			MTimeNanos: 1_700_000_200_000_000_003, Xattrs: attribute("user.node", "ro")},
		{ParentIndex: 2, Name: []byte("original.txt"), Type: archive.TypeRegular, Mode: 0o644, Size: 3,
			MTimeNanos: 1_700_000_300_000_000_004, Nlink: 2, HardlinkGroup: 1,
			Xattrs: attribute("user.node", "original")},
		{ParentIndex: 0, Name: []byte("sealed"), Type: archive.TypeDirectory, Mode: 0o000,
			MTimeNanos: 1_700_000_400_000_000_005, Xattrs: attribute("user.node", "sealed")},
		{ParentIndex: 4, Name: []byte("inner"), Type: archive.TypeDirectory, Mode: 0o700,
			MTimeNanos: 1_700_000_500_000_000_006, Xattrs: attribute("user.node", "inner")},
		{ParentIndex: 5, Name: []byte("deep.txt"), Type: archive.TypeRegular, Mode: 0o400, Size: 4096,
			MTimeNanos: 1_700_000_600_000_000_007, Nlink: 1, Xattrs: attribute("user.node", "deep")},
		{ParentIndex: 4, Name: []byte("link"), Type: archive.TypeSymlink, LinkName: []byte("inner/deep.txt"),
			Size: 14, MTimeNanos: 1_700_000_700_000_000_008, Nlink: 1},
		{ParentIndex: 0, Name: []byte("alias.txt"), Type: archive.TypeRegular, Mode: 0o644, Size: 3,
			MTimeNanos: 1_700_000_300_000_000_004, Nlink: 2, HardlinkGroup: 1,
			Xattrs: attribute("user.node", "original")},
	}
	return &archive.Manifest{
		Header:  archive.Header{FormatVersion: 1, ChunkSizeBytes: 4096},
		Entries: entries,
	}
}

// TestMaterializeRestoresRestrictiveModes is the ordering proof: a tree whose
// archived modes deny its own owner is materialized completely, and every node
// ends at exactly the archived mode and mtime.
func TestMaterializeRestoresRestrictiveModes(t *testing.T) {
	if !runsUnprivileged() {
		rerunUnprivileged(t, "TestMaterializeRestoresRestrictiveModes")
		return
	}
	root := t.TempDir()
	xattrs := xattrsCarried(t, root)
	manifest := restrictiveManifest(xattrs)

	directory, err := openRootDirectory(root)
	if err != nil {
		t.Fatalf("open restore root: %v", err)
	}
	defer directory.Close()
	// t.TempDir's own cleanup cannot descend into a restored 0000 directory, so
	// the tree is widened before it runs however this case ends. The manifest is
	// in depth-first pre-order, so widening in index order always reaches a
	// directory through ancestors that are already searchable.
	t.Cleanup(func() {
		for index := range manifest.Entries {
			if manifest.Entries[index].Type != archive.TypeDirectory {
				continue
			}
			components, err := manifest.Path(uint32(index))
			if err != nil {
				continue
			}
			parts := []string{root}
			for _, component := range components {
				parts = append(parts, string(component))
			}
			_ = os.Chmod(filepath.Join(parts...), 0o700)
		}
	})
	bindings, err := materialize(directory, manifest)
	if err != nil {
		t.Fatalf("materialize a tree with owner-denying modes: %v", err)
	}
	if len(bindings) != len(manifest.Entries) {
		t.Fatalf("materialize returned %d bindings for %d entries", len(bindings), len(manifest.Entries))
	}
	// The hardlink group is one inode under two names, so the two entries carry
	// the same identity and the authority's hydration map has one row for them.
	if bindings[3].Identity != bindings[8].Identity {
		t.Fatal("the two names of the hardlink group do not share an inode identity")
	}

	// Pass one asserts the final mode, mtime, and size of every node. It
	// descends widening each directory to 0700 only after that directory's own
	// mode has been read, which is the only way an unprivileged verifier can
	// reach the far side of a restored 0000 directory at all - an O_PATH open
	// asks for no access to its target but still walks the path to it.
	verify := newRestoreVerifier(t, root, manifest)
	verify.modesAndTimes()
	// Pass two asserts the content the restrictive modes hid: extended
	// attributes and the symlink target. Reading a user.* attribute needs read
	// permission on the inode, so files are widened here and not before - the
	// hardlink group is one inode under two names, and widening it during pass
	// one would have changed the mode the second name reports.
	verify.relaxedContent(xattrs)
}

type restoreVerifier struct {
	t        *testing.T
	root     string
	manifest *archive.Manifest
}

func newRestoreVerifier(t *testing.T, root string, manifest *archive.Manifest) *restoreVerifier {
	return &restoreVerifier{t: t, root: root, manifest: manifest}
}

// pathOf renders one entry's path for display and for a permission-free open.
func (v *restoreVerifier) pathOf(index int) string {
	components, err := v.manifest.Path(uint32(index))
	if err != nil {
		v.t.Fatalf("path of entry %d: %v", index, err)
	}
	parts := make([]string, 0, len(components))
	for _, component := range components {
		parts = append(parts, string(component))
	}
	if len(parts) == 0 {
		return "."
	}
	return strings.Join(parts, "/")
}

// childrenOf groups the manifest by parent. Entry zero is the root, whose
// ParentIndex is itself.
func (v *restoreVerifier) childrenOf(parent int) []int {
	var children []int
	for index := range v.manifest.Entries {
		if index != 0 && int(v.manifest.Entries[index].ParentIndex) == parent {
			children = append(children, index)
		}
	}
	return children
}

// modesAndTimes descends the restored tree asserting each node's archived mode,
// mtime, and size, and widens each directory to 0700 immediately after reading
// its own mode so the descent can continue past it.
//
// The widening is the verifier's own scaffolding and not part of what is being
// proved: an unprivileged process cannot look inside a restored 0000 directory
// any other way, because an O_PATH open asks for no access to its target but
// still needs search permission on every directory on the way to it. Each
// node's own mode is read before anything widens it, which is the assertion
// that matters. Regular files are deliberately left alone here: the hardlink
// group is one inode under two names, and widening it under the first name
// would change the mode read under the second.
func (v *restoreVerifier) modesAndTimes() {
	v.t.Helper()
	root, err := unix.Open(v.root, unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		v.t.Fatalf("open restore root: %v", err)
	}
	defer unix.Close(root)
	v.checkNode(root, 0)
	v.descend(root, 0)
}

func (v *restoreVerifier) descend(dirFD, index int) {
	v.t.Helper()
	if err := unix.Fchmodat(dirFD, "", 0o700, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		v.t.Fatalf("widen %q for the descent: %v", v.pathOf(index), err)
	}
	for _, child := range v.childrenOf(index) {
		name := string(v.manifest.Entries[child].Name)
		childFD, err := unix.Openat(dirFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			v.t.Fatalf("open %q with O_PATH: %v", v.pathOf(child), err)
		}
		v.checkNode(childFD, child)
		if v.manifest.Entries[child].Type == archive.TypeDirectory {
			v.descend(childFD, child)
		}
		_ = unix.Close(childFD)
	}
}

func (v *restoreVerifier) checkNode(fd, index int) {
	v.t.Helper()
	entry := &v.manifest.Entries[index]
	display := v.pathOf(index)
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW,
		unix.STATX_MODE|unix.STATX_MTIME|unix.STATX_SIZE|unix.STATX_NLINK, &stat); err != nil {
		v.t.Fatalf("statx %q: %v", display, err)
	}
	if entry.Type == archive.TypeSymlink {
		// A symlink's own mode is not archived and Linux does not let it be
		// set; only the mtime is a restore obligation.
		v.checkMTime(display, stat, entry.MTimeNanos)
		return
	}
	if got := uint32(stat.Mode) & 0o7777; got != entry.Mode {
		v.t.Errorf("%q has mode %#o, the archive recorded %#o", display, got, entry.Mode)
	}
	v.checkMTime(display, stat, entry.MTimeNanos)
	if entry.Type == archive.TypeRegular {
		if stat.Size != entry.Size {
			v.t.Errorf("%q is %d bytes, the archive recorded %d", display, stat.Size, entry.Size)
		}
		if entry.Nlink != 0 && stat.Nlink != entry.Nlink {
			v.t.Errorf("%q has %d links, the archive recorded %d", display, stat.Nlink, entry.Nlink)
		}
	}
}

func (v *restoreVerifier) checkMTime(display string, stat unix.Statx_t, want int64) {
	v.t.Helper()
	got := stat.Mtime.Sec*1_000_000_000 + int64(stat.Mtime.Nsec)
	if got != want {
		v.t.Errorf("%q has mtime %d, the archive recorded %d", display, got, want)
	}
}

// relaxedContent runs after modesAndTimes, which has already widened every
// directory, so a plain path resolves anywhere in the tree. It widens each
// regular file just enough to read the attributes its archived mode hid, then
// asserts those attributes and the symlink target.
func (v *restoreVerifier) relaxedContent(xattrs bool) {
	v.t.Helper()
	for index := range v.manifest.Entries {
		entry := &v.manifest.Entries[index]
		display := v.pathOf(index)
		if entry.Type == archive.TypeRegular {
			if err := os.Chmod(filepath.Join(v.root, display), 0o600); err != nil {
				v.t.Fatalf("relax %q: %v", display, err)
			}
		}
		if entry.Type == archive.TypeSymlink {
			target, err := os.Readlink(filepath.Join(v.root, display))
			if err != nil {
				v.t.Fatalf("readlink %q: %v", display, err)
			}
			if target != string(entry.LinkName) {
				v.t.Errorf("%q points at %q, the archive recorded %q", display, target, entry.LinkName)
			}
			continue
		}
		if !xattrs || len(entry.Xattrs) == 0 {
			continue
		}
		for _, want := range entry.Xattrs {
			value := make([]byte, 64)
			size, err := unix.Getxattr(filepath.Join(v.root, display), string(want.Name), value)
			if err != nil {
				v.t.Errorf("read %s of %q: %v", want.Name, display, err)
				continue
			}
			if got := string(value[:size]); got != string(want.Value) {
				v.t.Errorf("%s of %q is %q, the archive recorded %q", want.Name, display, got, want.Value)
			}
		}
	}
}

// TestMaterializeRefusesANonEmptyRoot pins the precondition the ordering above
// relies on: the restorer owns every mode in the tree because it created every
// node in it.
func TestMaterializeRefusesANonEmptyRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "squatter"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := openRootDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	_, err = materialize(directory, restrictiveManifest(false))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("materialize into a non-empty root = %v, want %v", err, ErrInvalid)
	}
}
