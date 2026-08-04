//go:build linux

package xfsstore

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openTestVolume(t *testing.T) *Volume {
	t.Helper()
	v, err := open(filepath.Clean(t.TempDir()), false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return v
}

func TestOpenAfterUnlinkUsesRetainedFD(t *testing.T) {
	v := openTestVolume(t)
	root, err := v.Root()
	if err != nil {
		t.Fatal(err)
	}
	item, _, err := v.Create(root, "file", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := v.WriteAt(h, []byte("hello"), 0); n != 5 || err != nil {
		t.Fatalf("WriteAt = %d, %v", n, err)
	}
	if err := v.Unlink(root, "file", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Lookup(root, "file"); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("Lookup after unlink = %v, want ENOENT", err)
	}
	buf := make([]byte, 5)
	if n, err := v.ReadAt(h, buf, 0); n != 5 || err != nil {
		t.Fatalf("ReadAt after unlink = %d, %v", n, err)
	}
	if string(buf) != "hello" {
		t.Fatalf("ReadAt = %q", buf)
	}
	if err := v.Fsync(h, false); err != nil {
		t.Fatal(err)
	}
	if err := v.CloseOpen(h); err != nil {
		t.Fatal(err)
	}
}

func TestAppendHandleRequiresAppendIntent(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "append", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true, Append: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	if _, err := v.WriteAt(handle, []byte("wrong-intent"), 0); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("WriteAt on append handle = %v, want invalid intent", err)
	}
	if n, off, err := v.Append(handle, []byte("ok")); n != 2 || off != 0 || err != nil {
		t.Fatalf("Append = (%d, %d, %v)", n, off, err)
	}
}

func TestRenameKeepsObjectIdentity(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, before, err := v.Create(root, "old", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Rename(root, "old", root, "new", 0); err != nil {
		t.Fatal(err)
	}
	after, err := v.Getattr(item)
	if err != nil {
		t.Fatal(err)
	}
	if before.Ino != after.Ino {
		t.Fatalf("inode changed across rename: %d -> %d", before.Ino, after.Ino)
	}
	looked, got, err := v.Lookup(root, "new")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(looked)
	if got.Ino != before.Ino {
		t.Fatalf("lookup inode = %d, want %d", got.Ino, before.Ino)
	}
}

func TestHardLinkUsesUnprivilegedRetainedFD(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "source", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	if attr, err := v.Link(item, root, "alias"); err != nil || attr.Nlink != 2 {
		t.Fatalf("Link through retained fd: %v", err)
	}
	alias, aliasAttr, err := v.Lookup(root, "alias")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(alias)
	sourceAttr, err := v.Getattr(item)
	if err != nil {
		t.Fatal(err)
	}
	if aliasAttr.Ino != sourceAttr.Ino || sourceAttr.Nlink != 2 {
		t.Fatalf("hard-link attrs source=%+v alias=%+v", sourceAttr, aliasAttr)
	}

	symlink, _, err := v.Symlink(root, "symlink", "source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Link(symlink, root, "symlink-alias"); err != nil {
		t.Fatalf("hard-link symlink through retained fd: %v", err)
	}
	linkedSymlink, attr, err := v.Lookup(root, "symlink-alias")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(linkedSymlink)
	if attr.Kind != KindSymlink {
		t.Fatalf("hard-linked symlink kind = %v", attr.Kind)
	}
	if target, err := v.Readlink(linkedSymlink); err != nil || target != "source" {
		t.Fatalf("hard-linked symlink target = %q, %v", target, err)
	}
}

func TestSetTimesUsesAuthorityClockForNow(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "server-clock", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Second).UnixNano()
	if err := v.SetTimes(item, nil, nil, false, true); err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(time.Second).UnixNano()
	attr, err := v.Getattr(item)
	if err != nil {
		t.Fatal(err)
	}
	if attr.MTimeNS < before || attr.MTimeNS > after {
		t.Fatalf("server-clock mtime = %d, want within [%d,%d]", attr.MTimeNS, before, after)
	}
	explicit := int64(1)
	if err := v.SetTimes(item, &explicit, nil, true, false); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("conflicting time intent = %v, want invalid", err)
	}
}

func TestSymlinkTargetIsDataNotHostTraversal(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	link, attr, err := v.Symlink(root, "escape", "../../outside")
	if err != nil {
		t.Fatal(err)
	}
	if attr.Kind != KindSymlink {
		t.Fatalf("kind = %v", attr.Kind)
	}
	target, err := v.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if target != "../../outside" {
		t.Fatalf("target = %q", target)
	}
	if _, err := v.OpenFile(link, OpenFlags{Read: true}); !errors.Is(err, ErrForbiddenType) {
		t.Fatalf("OpenFile(symlink) = %v", err)
	}
}

func TestShortReadPreservesProgress(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "file", fs.FileMode(0o600), true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(h)
	if _, err := v.WriteAt(h, []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	n, err := v.ReadAt(h, buf, 0)
	if n != 1 || (err != nil && !errors.Is(err, io.EOF)) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
}

func TestUserXattrWritesAreDisabledOnProjectQuotaStorage(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "file", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SetXattr(item, "security.capability", []byte("x"), XattrUpsert); !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("privileged xattr write = %v, want EOPNOTSUPP", err)
	}
	for _, mode := range []XattrMode{XattrUpsert, XattrCreate, XattrReplace} {
		if err := v.SetXattr(item, "user.one", []byte("value"), mode); !errors.Is(err, syscall.EOPNOTSUPP) {
			t.Fatalf("SetXattr mode %d = %v, want EOPNOTSUPP", mode, err)
		}
	}
}

func TestGetXattrHandlesConcurrentReplacement(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "file", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	fd, err := v.reopen(v.objects[item].res.fd, unix.O_RDWR, KindRegular)
	v.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Fsetxattr(fd, "user.race", []byte("seed"), 0); errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		t.Skip("test filesystem has no user xattrs")
	} else if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	setterErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		small, large := []byte("x"), make([]byte, 2<<10)
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			value := small
			if i&1 != 0 {
				value = large
			}
			if err := unix.Fsetxattr(fd, "user.race", value, unix.XATTR_REPLACE); err != nil {
				setterErr <- err
				return
			}
		}
	}()
	for range 2000 {
		// Never EAGAIN: getxattr(2) cannot return it, so a client that gets
		// one has no correct handling for it. The probe/fetch race resolves
		// against the kernel's own value ceiling instead.
		value, err := v.GetXattr(item, "user.race")
		if err != nil {
			close(done)
			wg.Wait()
			t.Fatalf("GetXattr during replacement: %v", err)
		}
		if err == nil && len(value) != len("seed") && len(value) != 1 && len(value) != 2<<10 {
			close(done)
			wg.Wait()
			t.Fatalf("GetXattr returned torn length %d", len(value))
		}
	}
	close(done)
	wg.Wait()
	select {
	case err := <-setterErr:
		t.Fatal(err)
	default:
	}
}

func TestCreateAndMkdirDoNotApplyWorkerUmask(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	previous := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(previous) })

	_, attr, err := v.Create(root, "wide-file", 0o777, true)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Mode.Perm() != 0o777 {
		t.Fatalf("created file mode = %o, want 777", attr.Mode.Perm())
	}
	_, attr, err = v.Mkdir(root, "wide-directory", 0o777)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Mode.Perm() != 0o777 {
		t.Fatalf("created directory mode = %o, want 777", attr.Mode.Perm())
	}
	if _, attr, err := v.Create(root, "wide-file", 0o700, false); err != nil {
		t.Fatal(err)
	} else if attr.Mode.Perm() != 0o777 {
		t.Fatalf("opening an existing file changed mode to %o", attr.Mode.Perm())
	}
}

func TestChmodCanRestoreModeZeroObject(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "sealed", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Chmod(item, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Chmod(item, 0o600); err != nil {
		t.Fatalf("restore chmod after mode 000: %v", err)
	}
	attr, err := v.Getattr(item)
	if err != nil || attr.Mode.Perm() != 0o600 {
		t.Fatalf("restored attr = %+v, %v", attr, err)
	}
}

func TestReadDirCanSeekToIssuedCookie(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	for _, name := range []string{"a", "b", "c", "d"} {
		if _, _, err := v.Create(root, name, 0o600, true); err != nil {
			t.Fatal(err)
		}
	}
	handle, err := v.OpenFile(root, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	first, next, verifier, _, _, err := v.ReadDirOpen(handle, 0, [16]byte{}, 2)
	if err != nil || len(first) != 2 || next != 2 {
		t.Fatalf("first page = %v, %d, %v", first, next, err)
	}
	if _, _, _, _, _, err := v.ReadDirOpen(handle, next, verifier, 2); err != nil {
		t.Fatal(err)
	}
	back, next, _, _, _, err := v.ReadDirOpen(handle, 1, verifier, 1)
	if err != nil || len(back) != 1 || next != 2 || back[0].Name != first[1].Name {
		t.Fatalf("seeked page = %v, %d, %v", back, next, err)
	}
}

func TestReadDirStatDoesNotAllocateCapability(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	if _, _, err := v.Create(root, "entry", 0o600, true); err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(root, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	v.mu.RLock()
	before := len(v.objects)
	v.mu.RUnlock()
	if _, err := v.StatOpenDirChild(handle, "entry"); err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	after := len(v.objects)
	v.mu.RUnlock()
	if after != before {
		t.Fatalf("object capability count changed: %d -> %d", before, after)
	}
}

func TestForeignOwnerFailsClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires chown privilege")
	}
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "foreign", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	fd := v.objects[item].res.fd
	v.mu.RUnlock()
	if err := unix.Fchownat(fd, "", 12345, 12345, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if _, err := v.StatOpenDirChild(mustOpenDir(t, v, root), "foreign"); !errors.Is(err, ErrProjectIsolation) {
		t.Fatalf("foreign owner stat = %v", err)
	}
}

func TestFenceRejectsDataOperationsButAllowsCleanup(t *testing.T) {
	v := openTestVolume(t)
	root, err := v.Root()
	if err != nil {
		t.Fatal(err)
	}
	item, _, err := v.Create(root, "fenced", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	v.Fence(syscall.EIO)
	if !errors.Is(v.Health(), ErrFenced) {
		t.Fatalf("Health = %v, want ErrFenced", v.Health())
	}
	if _, err := v.Root(); !errors.Is(err, ErrFenced) {
		t.Fatalf("Root after fence = %v, want ErrFenced", err)
	}
	if _, err := v.ReadAt(handle, make([]byte, 1), 0); !errors.Is(err, ErrFenced) {
		t.Fatalf("ReadAt after fence = %v, want ErrFenced", err)
	}
	if _, err := v.StatFS(); !errors.Is(err, ErrFenced) {
		t.Fatalf("StatFS after fence = %v, want ErrFenced", err)
	}
	if err := v.SyncFS(); !errors.Is(err, ErrFenced) {
		t.Fatalf("SyncFS after fence = %v, want ErrFenced", err)
	}
	if err := v.CloseOpen(handle); err != nil {
		t.Fatalf("CloseOpen cleanup after fence: %v", err)
	}
	if err := v.Forget(item); err != nil {
		t.Fatalf("Forget cleanup after fence: %v", err)
	}
}

func mustOpenDir(t *testing.T, v *Volume, item Capability) Capability {
	t.Helper()
	handle, err := v.OpenFile(item, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.CloseOpen(handle) })
	return handle
}
