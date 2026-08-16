//go:build linux

package xfsstore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTmpfileRetainsCreationAccessAndExactLinkability(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, attr, err := v.Tmpfile(root, 0o400, false)
	if errors.Is(err, syscall.EOPNOTSUPP) {
		// The non-production test volume may be overlayfs. Production Open has
		// already required XFS and qualified O_TMPFILE for write staging.
		t.Skip("test filesystem does not support O_TMPFILE")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(item)
	if attr.Kind != KindRegular || attr.Nlink != 0 || attr.Mode.Perm() != 0o400 {
		t.Fatalf("tmpfile attr = %+v", attr)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatalf("creation-grant open = %v", err)
	}
	defer v.CloseOpen(handle)
	if n, err := v.WriteAt(handle, []byte("tmp"), 0); n != 3 || err != nil {
		t.Fatalf("write tmpfile = (%d, %v)", n, err)
	}
	if linked, err := v.Link(item, root, "linked-tmpfile"); err != nil || linked.Nlink != 1 {
		t.Fatalf("linkable tmpfile = (%+v, %v)", linked, err)
	}

	exclusive, _, err := v.Tmpfile(root, 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(exclusive)
	if _, err := v.Link(exclusive, root, "must-not-link"); err == nil {
		t.Fatal("O_TMPFILE|O_EXCL inode was linkable")
	}
}

// TestLinkReportsAnObservationNotAComputation is the fabricated-attribute
// defect. Link used to answer with a stat taken before the mutation, with the
// link count incremented by hand: the count, the ctime and the mtime were all
// a guess about what the mutation would produce rather than what it did
// produce, and find -links, cp -a and tar dedupe on that count.
//
// The sleep is what makes this deterministic: inode timestamps come from the
// kernel's coarse clock, so a link issued in the same tick as the create
// cannot be told apart by ctime.
func TestLinkReportsAnObservationNotAComputation(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, before, err := v.Create(root, "source", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	attr, err := v.Link(item, root, "alias")
	if err != nil {
		t.Fatal(err)
	}
	if attr.Nlink != 2 {
		t.Fatalf("nlink = %d, want 2", attr.Nlink)
	}
	if attr.CTimeNS <= before.CTimeNS {
		t.Fatalf("reported ctime %d is the pre-link ctime %d: the attributes "+
			"describe the inode as it was before the mutation", attr.CTimeNS, before.CTimeNS)
	}
	fresh, err := v.Getattr(item)
	if err != nil {
		t.Fatal(err)
	}
	if attr.CTimeNS != fresh.CTimeNS || attr.Nlink != fresh.Nlink || attr.Ino != fresh.Ino {
		t.Fatalf("Link reported %+v, the inode holds %+v", attr, fresh)
	}
	// The same post-mutation stat is what proves the new name refers to the
	// source inode and not to whatever the /proc magic link resolved through:
	// this is the one path-based, symlink-following syscall in the package.
	alias, aliasAttr, err := v.Lookup(root, "alias")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(alias)
	if aliasAttr.Ino != fresh.Ino {
		t.Fatalf("linked name resolves to inode %d, want %d", aliasAttr.Ino, fresh.Ino)
	}
}

// TestLinkUnderConcurrentUnlink: with a name being removed while another is
// added, the only counts that can ever be true are 2 (the removal landed
// first) and 3 (the addition landed first). The old code could report 3 in the
// first case too, because its count came from a stat that predated both.
func TestLinkUnderConcurrentUnlink(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	for i := range 200 {
		item, _, err := v.Create(root, fmt.Sprintf("a%03d", i), 0o600, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Link(item, root, fmt.Sprintf("b%03d", i)); err != nil {
			t.Fatal(err)
		}
		unlinked := make(chan error, 1)
		go func() { unlinked <- v.Unlink(root, fmt.Sprintf("b%03d", i), false) }()
		attr, linkErr := v.Link(item, root, fmt.Sprintf("c%03d", i))
		if err := <-unlinked; err != nil {
			t.Fatal(err)
		}
		if linkErr != nil {
			t.Fatal(linkErr)
		}
		if attr.Nlink != 2 && attr.Nlink != 3 {
			t.Fatalf("Link reported nlink %d, which the inode never had", attr.Nlink)
		}
		settled, err := v.Getattr(item)
		if err != nil {
			t.Fatal(err)
		}
		if settled.Nlink != 2 || attr.Ino != settled.Ino {
			t.Fatalf("after both operations: %+v (reported %+v)", settled, attr)
		}
		if err := v.Forget(item); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCreateOfAnExistingFileNeverReportsAnUncertainOutcome: opening a file
// that already exists mutates nothing, so a failure afterwards cannot be
// uncertain. It used to be, and Uncertain tears the mount down and
// re-establishes it.
func TestCreateOfAnExistingFileNeverReportsAnUncertainOutcome(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires chown privilege to produce a badly owned file")
	}
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "adopted", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	fd := v.objects[item].res.fd
	v.mu.RUnlock()
	if err := unix.Fchownat(fd, "", 12345, 12345, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	_, _, err = v.Create(root, "adopted", 0o600, false)
	if !errors.Is(err, ErrProjectIsolation) {
		t.Fatalf("Create over a badly owned file = %v, want ErrProjectIsolation", err)
	}
	if errors.Is(err, ErrOutcomeUncertain) {
		t.Fatal("a create that changed nothing reported an uncertain outcome, " +
			"which re-establishes the mount")
	}
}

// TestCreateAndChmodRefuseSetuid: modeToUnix used to carry S_ISUID/S_ISGID
// through, so this single-principal volume could hold a setuid file owned by
// the service identity. The nosuid mount option a provisioning script sets is
// not this layer's guarantee.
func TestCreateAndChmodRefuseSetuid(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	for _, mode := range []fs.FileMode{
		0o755 | fs.ModeSetuid,
		0o755 | fs.ModeSetgid,
	} {
		if _, _, err := v.Create(root, "setuid", mode, true); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("Create(mode=%v) = %v, want EPERM", mode, err)
		}
		if _, _, err := v.Mkdir(root, "setuid-dir", mode); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("Mkdir(mode=%v) = %v, want EPERM", mode, err)
		}
	}
	item, _, err := v.Create(root, "plain", 0o644, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Chmod(item, 0o755|fs.ModeSetuid); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("Chmod(+setuid) = %v, want EPERM", err)
	}
	attr, err := v.Getattr(item)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Mode&(fs.ModeSetuid|fs.ModeSetgid) != 0 || attr.Mode.Perm() != 0o644 {
		t.Fatalf("mode = %v after a refused chmod", attr.Mode)
	}
	// The sticky bit stays available: it is meaningful and grants nothing.
	if err := v.Chmod(item, 0o644|fs.ModeSticky); err != nil {
		t.Fatalf("Chmod(+sticky) = %v", err)
	}
}

// TestZeroLengthOperations: empty positional I/O is a local no-op. The patched
// kernel also answers an empty append locally and never starts a transaction.
func TestZeroLengthOperations(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "file", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(reader)
	if n, err := v.ReadAt(reader, nil, 0); n != 0 || err != nil {
		t.Fatalf("ReadAt(empty) = (%d, %v), want (0, nil)", n, err)
	}
	if _, err := v.WriteAt(reader, []byte("0123456789"), 0); err != nil {
		t.Fatal(err)
	}
	if n, err := v.ReadAt(reader, []byte{}, 4); n != 0 || err != nil {
		t.Fatalf("ReadAt(empty, mid-file) = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := v.ReadAt(reader, make([]byte, 4), 10); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt at EOF = (%d, %v), want io.EOF", n, err)
	}

	if n, err := v.WriteAt(reader, nil, 10); n != 0 || err != nil {
		t.Fatalf("WriteAt(empty) = (%d, %v), want (0, nil)", n, err)
	}
}

// TestCreateReportsWhetherItCreated: the mode fix-up and the uncertain-outcome
// decision both hang off that answer. A non-exclusive create that raced an
// unlink used to create the inode through the second open while reporting that
// it had opened an existing one - so the requested mode was silently replaced
// by the worker's umask and a later failure looked harmless.
func TestCreateReportsWhetherItCreated(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	previous := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(previous) })

	v.mu.RLock()
	rootFD := v.objects[root].res.fd
	v.mu.RUnlock()
	for range 200 {
		unlinked := make(chan struct{})
		go func() {
			defer close(unlinked)
			for range 50 {
				if err := unix.Unlinkat(rootFD, "contended", 0); err != nil {
					return
				}
			}
		}()
		item, attr, err := v.Create(root, "contended", 0o666, false)
		<-unlinked
		if err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			t.Fatalf("Create under a concurrent unlink: %v", err)
		}
		fresh, err := v.Getattr(item)
		if err == nil && fresh.Mode.Perm() != 0o666 {
			t.Fatalf("mode = %o, want 666: the worker umask reached a file this "+
				"call reported as pre-existing", fresh.Mode.Perm())
		}
		if attr.Mode.Perm() != 0o666 {
			t.Fatalf("reported mode = %o, want 666", attr.Mode.Perm())
		}
		if err := v.Forget(item); err != nil {
			t.Fatal(err)
		}
	}
}

// modeIsEnforced reports whether the file mode actually decides anything for
// this process. Root carries CAP_DAC_OVERRIDE and opens whatever it likes, so
// the negative half of these tests - that a second open is refused - only
// means something for the unprivileged identity a volume actually runs as.
func modeIsEnforced() bool { return os.Geteuid() != 0 }

// TestCreateWithARestrictiveModeGrantsAWritableHandle is the mkstemp(3)
// contract. open(O_CREAT|O_EXCL, 0444) is granted its access by the creation,
// not by the mode: Linux skips may_open for the file the caller just made.
// Re-deriving access afterwards - which is all a fresh open of the same inode
// can do - answers EACCES for a file the caller is entitled to write, and git,
// dpkg and rpm all publish through exactly this pattern.
func TestCreateWithARestrictiveModeGrantsAWritableHandle(t *testing.T) {
	for _, mode := range []fs.FileMode{0o444, 0o400, 0o000, 0o644} {
		v := openTestVolume(t)
		root, _ := v.Root()
		item, attr, err := v.Create(root, "published", mode, true)
		if err != nil {
			t.Fatalf("Create(mode=%o): %v", mode, err)
		}
		if attr.Mode.Perm() != mode.Perm() {
			t.Fatalf("created mode = %o, want %o", attr.Mode.Perm(), mode.Perm())
		}
		handle, err := v.OpenFile(item, OpenFlags{Write: true})
		if err != nil {
			t.Fatalf("OpenFile(write) on a file created with mode %o: %v", mode, err)
		}
		payload := []byte("contents")
		if n, err := v.WriteAt(handle, payload, 0); n != len(payload) || err != nil {
			t.Fatalf("WriteAt on a mode-%o creation = (%d, %v)", mode, n, err)
		}
		if err := v.Fsync(handle, false); err != nil {
			t.Fatal(err)
		}
		if err := v.CloseOpen(handle); err != nil {
			t.Fatal(err)
		}
		// The grant is spent. A later open is a different caller at a
		// different time, and the mode is what answers for it - exactly as a
		// second open(2) of the same file would be answered locally.
		_, err = v.OpenFile(item, OpenFlags{Write: true})
		switch {
		case mode.Perm()&0o200 != 0 || !modeIsEnforced():
			if err != nil {
				t.Fatalf("second write open of a mode-%o file: %v", mode, err)
			}
		case !errors.Is(err, syscall.EACCES):
			t.Fatalf("second write open of a mode-%o file = %v, want EACCES", mode, err)
		}
	}
}

// TestCreateGrantCarriesAccessAndTruncate verifies that creation access is
// retained while append remains a per-operation choice, never a sticky fd bit.
func TestCreateGrantCarriesAccessAndTruncate(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "appended", 0o444, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true, Append: true})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := v.WriteAt(handle, []byte("one"), 0); n != 3 || err != nil {
		t.Fatalf("positional write through append-intent grant = (%d, %v)", n, err)
	}
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	if n, off, post, err := target.CommitWrite(bytes.NewReader([]byte("two")), WriteCommit{RequestedSize: 3, RLimitSize: 1 << 20, FileMaxSize: 1 << 20, Mode: WriteAppend}, make([]byte, 2)); n != 3 || off != 3 || post.Size != 6 || err != nil {
		t.Fatalf("per-call append = (%d, %d, %d, %v)", n, off, post, err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if err := v.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}

	truncated, _, err := v.Create(root, "truncated", 0o400, true)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := v.OpenFile(truncated, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.WriteAt(writer, []byte("stale"), 0); err != nil {
		t.Fatal(err)
	}
	if err := v.CloseOpen(writer); err != nil {
		t.Fatal(err)
	}
	// The grant is spent, and mode 0400 forbids a fresh write open, so this is
	// the errno the mode dictates rather than a silently widened handle.
	if _, err := v.OpenFile(truncated, OpenFlags{Write: true, Truncate: true}); modeIsEnforced() && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("truncating open after the grant = %v, want EACCES", err)
	}
}

// TestHandleAccessIsTheAccessThatWasAskedFor: a handle served by a creation
// grant holds a read-write description whatever it asked for, so the intent
// has to be enforced by this layer instead of by the description.
func TestHandleAccessIsTheAccessThatWasAskedFor(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "intent", 0o444, true)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := v.OpenFile(item, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(reader)
	if _, err := v.WriteAt(reader, []byte("x"), 0); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("WriteAt on a read-only handle = %v, want EBADF", err)
	}
	if _, err := v.PinWriteTarget(reader); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("PinWriteTarget on a read-only handle = %v, want EBADF", err)
	}
	if err := v.Truncate(reader, 0); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("Truncate on a read-only handle = %v, want EINVAL", err)
	}

	written, _, err := v.Create(root, "write-only", 0o644, true)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := v.OpenFile(written, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(writer)
	if _, err := v.WriteAt(writer, []byte("payload"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadAt(writer, make([]byte, 4), 0); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("ReadAt on a write-only handle = %v, want EBADF", err)
	}
}

// TestOpenHandleSurvivesAModeThatWouldForbidReopening: POSIX decides access
// once, when the description is created. A handle that re-derived it from the
// mode on every operation would stop working mid-write when an application
// chmods the file it is writing - which is what publish-then-seal tools do.
func TestOpenHandleSurvivesAModeThatWouldForbidReopening(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "sealed-while-open", 0o644, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	if _, err := v.WriteAt(handle, []byte("before"), 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Chmod(item, 0o000); err != nil {
		t.Fatal(err)
	}
	if n, err := v.WriteAt(handle, []byte("after"), 6); n != 5 || err != nil {
		t.Fatalf("WriteAt after the chmod = (%d, %v): the open handle lost the "+
			"access its description was created with", n, err)
	}
	buf := make([]byte, 11)
	if n, err := v.ReadAt(handle, buf, 0); n != 11 || err != nil {
		t.Fatalf("ReadAt after the chmod = (%d, %v)", n, err)
	}
	if string(buf) != "beforeafter" {
		t.Fatalf("contents = %q", buf)
	}
	if err := v.Fsync(handle, true); err != nil {
		t.Fatalf("Fsync after the chmod: %v", err)
	}
	// A fresh open is a new decision and the mode makes it.
	if _, err := v.OpenFile(item, OpenFlags{Read: true}); modeIsEnforced() && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("fresh open of a mode-000 file = %v, want EACCES", err)
	}
}

// TestCreateOverAnExistingReadOnlyFileOpensForReading: create-or-open of an
// existing file grants nothing, so it must not demand write access the caller
// never asked for.
func TestCreateOverAnExistingReadOnlyFileOpensForReading(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	if _, _, err := v.Create(root, "read-only", 0o444, true); err != nil {
		t.Fatal(err)
	}
	item, attr, err := v.Create(root, "read-only", 0o444, false)
	if err != nil {
		t.Fatalf("create-or-open of an existing 0444 file: %v", err)
	}
	if attr.Mode.Perm() != 0o444 {
		t.Fatalf("mode = %o, want 444", attr.Mode.Perm())
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true})
	if err != nil {
		t.Fatalf("OpenFile(read) on an existing 0444 file: %v", err)
	}
	defer v.CloseOpen(handle)
	if _, err := v.OpenFile(item, OpenFlags{Write: true}); modeIsEnforced() && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("OpenFile(write) on an existing 0444 file = %v, want EACCES", err)
	}
}
