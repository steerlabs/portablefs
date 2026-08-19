//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"golang.org/x/sys/unix"
)

// flockReleaseBound bounds how long a flock(2) lock may survive the close(2)
// that drops its last file descriptor.
//
// The asymmetry with POSIX record locks is inherent to the FUSE protocol, not a
// defect to be papered over: the kernel issues FLUSH synchronously inside
// close(2) and the authority releases POSIX record locks there, so close(2)
// returning already means the record lock is gone. flock(2) locks are instead
// released by RELEASE, which the kernel queues as a background request after
// the last reference to the file description drops; close(2) never waits for
// it. The wait therefore cannot be removed, but it must be tight and stated:
// the round trip is a loopback RPC, so anything approaching a second is a
// regression this bound catches.
const flockReleaseBound = 250 * time.Millisecond

// TestTwoKernelMountsShareAuthoritativeXFS exercises the ordinary POSIX surface
// two independent kernel mounts of one authoritative volume must present.
func TestTwoKernelMountsShareAuthoritativeXFS(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})

	sharedA, sharedB := f.join(0, "shared"), f.join(1, "shared")
	mustWrite(t, sharedA, []byte("one"), 0o600)
	requireContent(t, sharedB, []byte("one"), "cross-mount read of a newly written file")

	// Open-after-unlink: the authority must serve a retained descriptor after the
	// last name for the object disappears from the other mount.
	opened, err := os.Open(sharedA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sharedB); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(opened); err != nil || string(got) != "one" {
		t.Fatalf("open-after-unlink read = %q, %v", got, err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	requireAbsent(t, sharedA, "after cross-mount unlink")

	mappedA, mappedB := f.join(0, "mapped"), f.join(1, "mapped")
	mappedPayload := make([]byte, 4096)
	mappedPayload[0] = 0x5a
	mustWrite(t, mappedA, mappedPayload, 0o600)
	mappedFile, err := os.OpenFile(mappedA, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer mappedFile.Close()

	// A shared mapping of a SHARED regular file is refused by the kernel with
	// exactly ENODEV (fs/fuse/file.c). The reason survived the move to a
	// retained page cache and got sharper: a writable shared mapping would
	// dirty folios that never travel the strict write transaction, and a dirty
	// folio is the one thing invalidate_inode_pages2() cannot withdraw, so it
	// would turn every later DATA repair on the inode into a revocation.
	// Accepting EINVAL or ENOSYS as well would let an unrelated mmap breakage,
	// or a mount that stopped refusing shared mappings and instead failed for
	// some other reason, pass as if the contract were being enforced.
	for _, shared := range []struct {
		what string
		prot int
	}{
		{"shared writable mmap", unix.PROT_READ | unix.PROT_WRITE},
		{"shared read-only mmap", unix.PROT_READ},
	} {
		mapping, err := unix.Mmap(int(mappedFile.Fd()), 0, 4096, shared.prot, unix.MAP_SHARED)
		if err == nil {
			_ = unix.Munmap(mapping)
			t.Fatalf("%s unexpectedly succeeded on a coherent mount", shared.what)
		}
		requireErrno(t, err, syscall.ENODEV, shared.what)
	}

	// MAP_PRIVATE is an ordinary process-local copy-on-write view. It is not a
	// shared write channel and POSIX does not promise that later external file
	// changes become visible through it, so allowing it cannot violate the
	// cross-mount coherence contract.
	mapping, err := unix.Mmap(int(mappedFile.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("private mmap = %v", err)
	}
	if mapping[0] != 0x5a {
		_ = unix.Munmap(mapping)
		t.Fatalf("private mmap initial byte = %#x, want 0x5a", mapping[0])
	}
	mapping[0] = 0x33
	if err := unix.Munmap(mapping); err != nil {
		t.Fatal(err)
	}
	underlying := []byte{0}
	if _, err := mappedFile.ReadAt(underlying, 0); err != nil {
		t.Fatal(err)
	}
	if underlying[0] != 0x5a {
		t.Fatalf("private mmap modified underlying file: got %#x, want 0x5a", underlying[0])
	}
	// The other mount must agree that nothing was written.
	if got := mustReadByte(t, mappedB, 0); got != 0x5a {
		t.Fatalf("private mmap leaked to the other mount: byte 0 = %#x, want 0x5a", got)
	}

	// Extended attributes. Writes are refused by design because XFS excludes
	// xattr space from project-quota accounting, but Getxattr and Listxattr are
	// real end-to-end paths and must behave, not merely exist.
	requireErrno(t, unix.Setxattr(mappedA, "user.portablefs-test", []byte("value"), 0), syscall.EOPNOTSUPP, "setxattr")
	_, err = unix.Getxattr(mappedA, "user.portablefs-test", make([]byte, 32))
	requireErrno(t, err, syscall.ENODATA, "getxattr of an attribute that was never set")
	size, err := unix.Listxattr(mappedB, nil)
	if err != nil {
		t.Fatalf("listxattr size probe: %v", err)
	}
	if size != 0 {
		t.Fatalf("listxattr size = %d, want 0 on a store that refuses xattr writes", size)
	}

	requirePermissionBehaviour(t, f)
	requirePOSIXRecordLocks(t, mappedA, mappedB)
	requireFlockHandoff(t, mappedA, mappedB)
}

func requirePermissionBehaviour(t *testing.T, f *integrationFixture) {
	t.Helper()
	secretA, secretB := f.join(0, "permissions"), f.join(1, "permissions")
	mustWrite(t, secretA, []byte("secret"), 0o600)
	if err := os.Chmod(secretA, 0); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(secretB)
	if err != nil {
		t.Fatalf("stat mode-000 file through the second mount: %v", err)
	}
	if info.Mode().Perm() != 0 {
		t.Fatalf("cross-mount permission bits = %#o, want 0", info.Mode().Perm())
	}
	if os.Geteuid() == 0 {
		// Root legitimately bypasses DAC through CAP_DAC_OVERRIDE. Asserting that
		// keeps this block from making no claim at all, which is what the previous
		// unconditional euid==0 skip did in exactly the privileged environment
		// this suite is designed for.
		privileged, err := os.Open(secretA)
		if err != nil {
			t.Fatalf("root open of a mode-000 file = %v, want success via CAP_DAC_OVERRIDE", err)
		}
		_ = privileged.Close()
	} else {
		denied, err := os.Open(secretA)
		if denied != nil {
			_ = denied.Close()
		}
		requireErrno(t, err, syscall.EACCES, "open chmod-000 file")
		requireErrno(t, unix.Access(secretA, unix.R_OK), syscall.EACCES, "access chmod-000 file")
		other, err := os.Open(secretB)
		if other != nil {
			_ = other.Close()
		}
		requireErrno(t, err, syscall.EACCES, "open chmod-000 file through the second mount")
	}
	// Restoring the mode from the other mount must make the object usable again.
	if err := os.Chmod(secretB, 0o600); err != nil {
		t.Fatal(err)
	}
	requireContent(t, secretA, []byte("secret"), "after restoring mode 0600 from the other mount")
}

func requirePOSIXRecordLocks(t *testing.T, pathA, pathB string) {
	t.Helper()
	lockA, err := os.OpenFile(pathA, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	lockB, err := os.OpenFile(pathB, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lockB.Close()
	lock := &unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(io.SeekStart), Start: 0, Len: 1}
	if err := unix.FcntlFlock(lockA.Fd(), unix.F_SETLK, lock); err != nil {
		t.Fatalf("acquire write lock on the first mount: %v", err)
	}
	if err := unix.FcntlFlock(lockB.Fd(), unix.F_SETLK, lock); !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EACCES) {
		// POSIX permits either errno for a refused F_SETLK; Linux returns EAGAIN.
		t.Fatalf("conflicting cross-mount record lock = %v, want EAGAIN or EACCES", err)
	}
	// The kernel issues FLUSH synchronously inside close(2) and the authority
	// releases the record locks of that lock owner there, so the lock is gone the
	// instant close(2) returns. No retry is legitimate here.
	if err := lockA.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.FcntlFlock(lockB.Fd(), unix.F_SETLK, lock); err != nil {
		t.Fatalf("record lock survived the owner's close/flush: %v", err)
	}
	lock.Type = unix.F_UNLCK
	if err := unix.FcntlFlock(lockB.Fd(), unix.F_SETLK, lock); err != nil {
		t.Fatal(err)
	}
}

func requireFlockHandoff(t *testing.T, pathA, pathB string) {
	t.Helper()
	flockA, err := os.OpenFile(pathA, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	flockB, err := os.OpenFile(pathB, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer flockB.Close()
	if err := unix.Flock(int(flockA.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("acquire flock on the first mount: %v", err)
	}
	if err := unix.Flock(int(flockB.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("conflicting cross-mount flock = %v, want EWOULDBLOCK", err)
	}

	// An explicit LOCK_UN is an ordinary synchronous FUSE SETLK. The handoff must
	// therefore be immediate: one attempt, no retry loop.
	if err := unix.Flock(int(flockA.Fd()), unix.LOCK_UN); err != nil {
		t.Fatalf("release flock on the first mount: %v", err)
	}
	if err := unix.Flock(int(flockB.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("flock was not handed over by an explicit LOCK_UN: %v", err)
	}
	if err := unix.Flock(int(flockB.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}

	// Release-on-close travels the asynchronous RELEASE path (see
	// flockReleaseBound). Wait, but only within the stated bound, and report the
	// observed latency so a drift toward it is visible before it fails.
	if err := unix.Flock(int(flockA.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("re-acquire flock on the first mount: %v", err)
	}
	if err := flockA.Close(); err != nil {
		t.Fatal(err)
	}
	elapsed := waitUntil(t, flockReleaseBound, "flock release after the owner's last close", func() bool {
		return unix.Flock(int(flockB.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil
	})
	t.Logf("flock released %s after close(2) (bound %s)", elapsed, flockReleaseBound)
	if err := unix.Flock(int(flockB.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

// TestCreateWithAReadOnlyModeReturnsAWritableHandle pins ordinary POSIX
// creation semantics. open(2) with O_CREAT|O_EXCL applies the requested mode to
// the new file and returns a descriptor with the access the caller asked for:
// the kernel does not re-check permissions against a mode it has just created.
// That is exactly what mkstemp(3) relies on, and therefore what git, dpkg, and
// every other tool that publishes through a temporary file relies on.
//
// It is also the narrowest statement of a failure that otherwise only shows up
// as "git add fails": a create whose follow-on open is refused must cost one
// syscall, never the whole authority session.
func TestCreateWithAReadOnlyModeReturnsAWritableHandle(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	for _, mode := range []os.FileMode{0o444, 0o400, 0o000} {
		name := fmt.Sprintf("created-%03o", uint32(mode))
		file, err := os.OpenFile(f.join(0, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			t.Fatalf("create %s with mode %#o for read/write: %v (mount health: %s)",
				name, uint32(mode), err, f.sessionDiagnostics())
		}
		if _, err := file.Write([]byte("payload")); err != nil {
			t.Fatalf("write to a freshly created mode-%#o file: %v", uint32(mode), err)
		}
		if _, err := file.ReadAt(make([]byte, 7), 0); err != nil {
			t.Fatalf("read from a freshly created mode-%#o file: %v", uint32(mode), err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(f.join(1, name))
		if err != nil {
			t.Fatalf("stat the created file through the second mount: %v", err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("created %s with mode %#o, the other mount reports %#o", name, uint32(mode), uint32(info.Mode().Perm()))
		}
		if info.Size() != 7 {
			t.Fatalf("created %s size = %d, want 7", name, info.Size())
		}
	}
	// Re-opening a mode-0444 file for writing is a different question and must
	// be refused, without costing the session either.
	reopened, err := os.OpenFile(f.join(1, "created-444"), os.O_RDWR, 0)
	if reopened != nil {
		_ = reopened.Close()
	}
	requireErrno(t, err, syscall.EACCES, "re-open a mode-0444 file for writing")

	if diagnostics := f.sessionDiagnostics(); strings.Contains(diagnostics, "ended") {
		t.Fatalf("a refused open terminated an authority session: %s", diagnostics)
	}
	requireContent(t, f.join(0, "created-444"), []byte("payload"), "after a refused re-open")
}

// TestCrossMountContentCoherence is the invalidation test the previous
// "coherence" assertion was not: it reads on the second mount first, mutates on
// the first, and then reads again through the same descriptor and at the same
// offset. Every mutation keeps the file length identical, so no size-derived
// heuristic can rescue a stale page.
//
// Since SHARED regular opens became FOPEN_KEEP_CACHE|FOPEN_PFS_SHARED this is
// also the load-bearing cached-page test, and the same-length payloads are what
// make it one. The first read populates mount B's page cache; every later read
// at the same offset is served from that cache unless something withdrew it.
// Only the ordered DATA publication does -- it invalidates the whole mapping by
// sequence, never by an EOF delta -- so a kernel that short-circuited the
// invalidation when i_size was unchanged fails here, as does a mount that
// stopped joining the barrier's audience for the inode.
//
// REQUIRES THE PRIVILEGED RUNNER: this test needs a real strict-coherence
// kernel and two live mounts. It cannot be exercised by the unit fixtures,
// which never populate a page cache at all.
func TestCrossMountContentCoherence(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	nameA, nameB := f.join(0, "content"), f.join(1, "content")
	const generation = 16 // every payload below is exactly this long
	mustWrite(t, nameA, []byte("first-generation"), 0o600)

	reader := mustOpenFile(t, nameB, os.O_RDONLY, 0)
	if got := readExactlyAt(t, reader, 0, generation, "first read"); string(got) != "first-generation" {
		t.Fatalf("first cross-mount read = %q", got)
	}

	// Whole-file rewrite through a different descriptor on the other mount.
	mustWrite(t, nameA, []byte("secondgeneration"), 0o600)
	if got := readExactlyAt(t, reader, 0, generation, "re-read after a remote rewrite"); string(got) != "secondgeneration" {
		t.Fatalf("re-read after a remote rewrite = %q, want %q", got, "secondgeneration")
	}
	requireContent(t, nameB, []byte("secondgeneration"), "fresh open after a remote rewrite")

	// In-place partial overwrite: the size, the name, and every other byte are
	// unchanged, so only genuine per-read coherence can observe it.
	writer := mustOpenFile(t, nameA, os.O_RDWR, 0)
	if _, err := writer.WriteAt([]byte("THIRD"), 0); err != nil {
		t.Fatalf("partial remote overwrite: %v", err)
	}
	if err := writer.Sync(); err != nil {
		t.Fatalf("sync partial remote overwrite: %v", err)
	}
	// "secondgeneration" with its first five bytes replaced. The length, the
	// name and eleven of the sixteen bytes are unchanged.
	if got := readExactlyAt(t, reader, 0, generation, "re-read after a remote partial overwrite"); string(got) != "THIRDdgeneration" {
		t.Fatalf("re-read after a remote partial overwrite = %q, want %q", got, "THIRDdgeneration")
	}

	// The reverse direction must hold too: the mount that wrote must observe a
	// mutation made by the other one.
	mustWrite(t, nameB, []byte("fourthgeneratio"), 0o600)
	requireContent(t, nameA, []byte("fourthgeneratio"), "read back a mutation made by the second mount")
}

// TestCrossMountSizeCoherence covers remote truncation and remote extension,
// including the bytes the extension must materialise.
func TestCrossMountSizeCoherence(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	nameA, nameB := f.join(0, "sized"), f.join(1, "sized")
	original := bytes.Repeat([]byte("a"), 4096)
	mustWrite(t, nameA, original, 0o600)

	reader := mustOpenFile(t, nameB, os.O_RDONLY, 0)
	requireSize(t, nameB, 4096, "initial cross-mount size")
	if got := readExactlyAt(t, reader, 0, 4096, "initial read"); !bytes.Equal(got, original) {
		t.Fatal("initial cross-mount content mismatch")
	}

	// Remote shrink.
	if err := os.Truncate(nameA, 10); err != nil {
		t.Fatalf("remote truncate: %v", err)
	}
	requireSize(t, nameB, 10, "size after a remote truncate")
	requireContent(t, nameB, original[:10], "content after a remote truncate")
	if _, err := reader.ReadAt(make([]byte, 1), 10); !errors.Is(err, io.EOF) {
		t.Fatalf("read past the new EOF through the retained descriptor = %v, want EOF", err)
	}

	// Remote extension through an already-open descriptor on the other mount.
	extender := mustOpenFile(t, nameA, os.O_RDWR, 0)
	if err := extender.Truncate(8192); err != nil {
		t.Fatalf("remote extend: %v", err)
	}
	requireSize(t, nameB, 8192, "size after a remote extend")
	expected := make([]byte, 8192)
	copy(expected, original[:10])
	requireContent(t, nameB, expected, "content after a remote extend must be zero-filled")
	if got := readExactlyAt(t, reader, 8191, 1, "read the last byte of the extension"); got[0] != 0 {
		t.Fatalf("extension byte = %#x, want 0", got[0])
	}

	// Truncate to zero, then rewrite, observed through the retained descriptor.
	if err := os.Truncate(nameA, 0); err != nil {
		t.Fatal(err)
	}
	requireSize(t, nameB, 0, "size after a remote truncate to zero")
	mustWrite(t, nameA, []byte("regrown"), 0o600)
	requireSize(t, nameB, 7, "size after the file regrew remotely")
	if got := readExactlyAt(t, reader, 0, 7, "read after the file regrew remotely"); string(got) != "regrown" {
		t.Fatalf("read after the file regrew remotely = %q", got)
	}
}

// TestCrossMountAttributeCoherence covers metadata that is not the file body:
// permission bits and modification time.
func TestCrossMountAttributeCoherence(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	nameA, nameB := f.join(0, "attributes"), f.join(1, "attributes")
	mustWrite(t, nameA, []byte("body"), 0o644)

	// Populate whatever the observing mount could cache.
	if info, err := os.Stat(nameB); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("initial cross-mount mode = %v, %v", info, err)
	}
	for _, mode := range []os.FileMode{0o600, 0o400, 0o750, 0o644} {
		if err := os.Chmod(nameA, mode); err != nil {
			t.Fatalf("remote chmod %v: %v", mode, err)
		}
		info, err := os.Stat(nameB)
		if err != nil {
			t.Fatalf("stat after a remote chmod %v: %v", mode, err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("mode after a remote chmod = %#o, want %#o", info.Mode().Perm(), mode)
		}
	}

	// Modification time, with nanosecond precision, changed remotely twice so a
	// one-shot invalidation cannot pass.
	for _, stamp := range []time.Time{
		time.Unix(1_500_000_000, 123_456_789),
		time.Unix(1_600_000_001, 987_654_321),
	} {
		if err := os.Chtimes(nameA, stamp, stamp); err != nil {
			t.Fatalf("remote chtimes: %v", err)
		}
		info, err := os.Stat(nameB)
		if err != nil {
			t.Fatalf("stat after a remote chtimes: %v", err)
		}
		if got := info.ModTime().UnixNano(); got != stamp.UnixNano() {
			t.Fatalf("mtime after a remote chtimes = %d, want %d", got, stamp.UnixNano())
		}
	}

	// Link count is authority state too: a remote hard link must be visible.
	linkA, linkB := f.join(0, "attributes-link"), f.join(1, "attributes-link")
	if err := os.Link(nameA, linkA); err != nil {
		t.Fatalf("remote hard link: %v", err)
	}
	if links := nlink(t, nameB); links != 2 {
		t.Fatalf("nlink after a remote hard link = %d, want 2", links)
	}
	if err := os.Remove(linkB); err != nil {
		t.Fatal(err)
	}
	if links := nlink(t, nameB); links != 1 {
		t.Fatalf("nlink after a remote unlink = %d, want 1", links)
	}
}

// TestCrossMountPositiveDentryInvalidation asserts that a name the observing
// mount has already resolved stops resolving once the other mount removes it.
func TestCrossMountPositiveDentryInvalidation(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	fileA, fileB := f.join(0, "victim"), f.join(1, "victim")
	directoryA, directoryB := f.join(0, "victim-dir"), f.join(1, "victim-dir")
	mustWrite(t, fileA, []byte("doomed"), 0o600)
	mustMkdir(t, directoryA)

	// Resolve both names on the observing mount so a positive dentry exists.
	requireContent(t, fileB, []byte("doomed"), "before the remote unlink")
	if info, err := os.Stat(directoryB); err != nil || !info.IsDir() {
		t.Fatalf("stat directory before the remote rmdir = %v, %v", info, err)
	}
	requireDirectoryNames(t, f.mountPath(1), []string{"victim", "victim-dir"}, "before the remote removals")

	if err := os.Remove(fileA); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directoryA); err != nil {
		t.Fatal(err)
	}

	requireAbsent(t, fileB, "file after a remote unlink")
	requireAbsent(t, directoryB, "directory after a remote rmdir")
	_, err := os.Open(fileB)
	requireErrno(t, err, syscall.ENOENT, "open after a remote unlink")
	requireDirectoryNames(t, f.mountPath(1), nil, "after the remote removals")
}

// TestCrossMountNegativeDentryInvalidation is the counterpart, and the one this
// project calls out as a platform hazard: a name that was looked up and found
// missing must start resolving as soon as the other mount creates it. A cached
// negative dentry makes the second stat below fail.
//
// The repeated probes below are not defensive any more. A strict mount
// publishes an absence with a real lifetime, so after the first miss the
// following two are answered by this kernel with no upcall at all, and the only
// thing that can make the later stat succeed is the creating mount's barrier
// expiring this entry before its own create(2) returns.
func TestCrossMountNegativeDentryInvalidation(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	ghostA, ghostB := f.join(0, "ghost"), f.join(1, "ghost")
	directoryA, directoryB := f.join(0, "ghost-dir"), f.join(1, "ghost-dir")

	// Look the names up repeatedly so any negative caching is well established.
	for range 3 {
		requireAbsent(t, ghostB, "before the remote create")
		requireAbsent(t, directoryB, "before the remote mkdir")
	}

	mustWrite(t, ghostA, []byte("materialised"), 0o600)
	if err := os.Mkdir(directoryA, 0o700); err != nil {
		t.Fatal(err)
	}

	requireContent(t, ghostB, []byte("materialised"), "after the remote create")
	info, err := os.Stat(directoryB)
	if err != nil || !info.IsDir() {
		t.Fatalf("stat after the remote mkdir = %v, %v", info, err)
	}

	// Flip back and forth: a one-shot invalidation would pass the first
	// transition and fail here.
	if err := os.Remove(ghostA); err != nil {
		t.Fatal(err)
	}
	requireAbsent(t, ghostB, "after the second remote unlink")
	mustWrite(t, ghostA, []byte("again"), 0o600)
	requireContent(t, ghostB, []byte("again"), "after the second remote create")

	// A name inside a remotely created directory must resolve without the
	// observing mount having ever listed that directory.
	nestedA, nestedB := filepath.Join(directoryA, "nested"), filepath.Join(directoryB, "nested")
	requireAbsent(t, nestedB, "before the nested remote create")
	mustWrite(t, nestedA, []byte("deep"), 0o600)
	requireContent(t, nestedB, []byte("deep"), "after the nested remote create")
}

// TestCrossMountRenameCoherence asserts both halves of a remote rename: the old
// name stops resolving and the new name resolves to the same object.
func TestCrossMountRenameCoherence(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	mustWrite(t, f.join(0, "old"), []byte("payload"), 0o600)
	mustMkdir(t, f.join(0, "subdirectory"))

	before, err := os.Stat(f.join(1, "old"))
	if err != nil {
		t.Fatal(err)
	}
	originalInode := inodeOf(t, before)

	if err := os.Rename(f.join(0, "old"), f.join(0, "new")); err != nil {
		t.Fatalf("remote rename: %v", err)
	}
	requireAbsent(t, f.join(1, "old"), "old name after a remote rename")
	after, err := os.Stat(f.join(1, "new"))
	if err != nil {
		t.Fatalf("new name after a remote rename: %v", err)
	}
	if got := inodeOf(t, after); got != originalInode {
		t.Fatalf("rename changed object identity: inode %d became %d", originalInode, got)
	}
	requireContent(t, f.join(1, "new"), []byte("payload"), "content after a remote rename")

	// Cross-directory rename.
	if err := os.Rename(f.join(0, "new"), f.join(0, "subdirectory", "moved")); err != nil {
		t.Fatalf("remote cross-directory rename: %v", err)
	}
	requireAbsent(t, f.join(1, "new"), "source after a remote cross-directory rename")
	requireContent(t, f.join(1, "subdirectory", "moved"), []byte("payload"), "target after a remote cross-directory rename")
	requireDirectoryNames(t, f.join(1, "subdirectory"), []string{"moved"}, "after a remote cross-directory rename")

	// Rename over an existing name: the observing mount must see the replacement
	// object, not the one it resolved a moment ago.
	mustWrite(t, f.join(0, "target"), []byte("replaced"), 0o600)
	replaced, err := os.Stat(f.join(1, "target"))
	if err != nil {
		t.Fatal(err)
	}
	requireContent(t, f.join(1, "target"), []byte("replaced"), "before the replacing rename")
	if err := os.Rename(f.join(0, "subdirectory", "moved"), f.join(0, "target")); err != nil {
		t.Fatalf("remote replacing rename: %v", err)
	}
	final, err := os.Stat(f.join(1, "target"))
	if err != nil {
		t.Fatal(err)
	}
	if inodeOf(t, final) == inodeOf(t, replaced) {
		t.Fatal("replacing rename left the observing mount pointing at the replaced object")
	}
	if got := inodeOf(t, final); got != originalInode {
		t.Fatalf("replacing rename resolved to inode %d, want the renamed object %d", got, originalInode)
	}
	requireContent(t, f.join(1, "target"), []byte("payload"), "content after a remote replacing rename")
}

// TestCrossMountDirectoryListingCoherence asserts that a full listing taken on
// one mount reflects creations and removals made on the other, repeatedly.
func TestCrossMountDirectoryListingCoherence(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	directoryA, directoryB := f.join(0, "listing"), f.join(1, "listing")
	mustMkdir(t, directoryA)
	for _, name := range []string{"alpha", "beta", "gamma"} {
		mustWrite(t, filepath.Join(directoryA, name), []byte(name), 0o600)
	}
	requireDirectoryNames(t, directoryB, []string{"alpha", "beta", "gamma"}, "initial listing")

	mustWrite(t, filepath.Join(directoryA, "delta"), []byte("delta"), 0o600)
	requireDirectoryNames(t, directoryB, []string{"alpha", "beta", "delta", "gamma"}, "listing after a remote create")

	if err := os.Remove(filepath.Join(directoryA, "beta")); err != nil {
		t.Fatal(err)
	}
	requireDirectoryNames(t, directoryB, []string{"alpha", "delta", "gamma"}, "listing after a remote unlink")

	// A remotely created subdirectory must appear with the right type, because
	// the listing carries d_type and a wrong kind silently breaks tree walks.
	if err := os.Mkdir(filepath.Join(directoryA, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directoryB)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, entry := range entries {
		kinds[entry.Name()] = entry.IsDir()
	}
	if len(kinds) != 4 {
		t.Fatalf("listing after a remote mkdir = %v, want 4 entries", kinds)
	}
	if !kinds["child"] {
		t.Fatal("remotely created subdirectory is not reported as a directory")
	}
	for _, name := range []string{"alpha", "delta", "gamma"} {
		if kinds[name] {
			t.Fatalf("%s is reported as a directory", name)
		}
	}

	// Emptying the directory remotely must be observable, and the now-empty
	// directory must be removable from the observing mount.
	for _, name := range []string{"alpha", "delta", "gamma", "child"} {
		if err := os.RemoveAll(filepath.Join(directoryA, name)); err != nil {
			t.Fatal(err)
		}
	}
	requireDirectoryNames(t, directoryB, nil, "listing after emptying the directory remotely")
	if err := os.Remove(directoryB); err != nil {
		t.Fatalf("rmdir a remotely emptied directory: %v", err)
	}
}

// TestDirectoryWithNonPortableInodeRemainsListable places a FIFO behind the
// authority — the server is the only supported writer, but a restore, an
// operator, or a legacy tree can leave a non-portable inode in the volume —
// and asserts the directory stays readable. The regression this guards
// against failed the whole readdir page with ESTALE for one such entry,
// making the directory permanently unlistable from every mount. The correct
// shape is the local one: the name is listed opaquely (no d_type, no
// capability), the follow-up stat on it fails, and every portable sibling is
// unaffected.
func TestDirectoryWithNonPortableInodeRemainsListable(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	directoryA, directoryB := f.join(0, "mixed"), f.join(1, "mixed")
	mustMkdir(t, directoryA)
	for _, name := range []string{"alpha", "beta"} {
		mustWrite(t, filepath.Join(directoryA, name), []byte(name), 0o600)
	}
	if err := unix.Mkfifo(filepath.Join(f.volumeRoot, "mixed", "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Readdirnames, not os.ReadDir: enumeration itself must succeed. Go's
	// os.ReadDir eagerly lstats a DT_UNKNOWN entry and fails the whole listing
	// on the pipe's EPERM, which is a Go convenience choice — ls(1) lists the
	// name and reports the failed stat beside it, and that is the boundary the
	// authority promises.
	dir, err := os.Open(directoryB)
	if err != nil {
		t.Fatal(err)
	}
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		t.Fatalf("a directory containing a FIFO is unlistable: %v", err)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"alpha", "beta", "pipe"}) {
		t.Fatalf("listing = %v, want the FIFO listed opaquely beside its portable siblings", names)
	}
	// The opaque entry carries no capability: addressing it fails exactly as
	// the authority's forbidden-type contract states, while the portable
	// siblings remain fully readable.
	if _, err := os.Lstat(filepath.Join(directoryB, "pipe")); err == nil {
		t.Fatal("stat of a non-portable inode unexpectedly succeeded")
	}
	for _, name := range []string{"alpha", "beta"} {
		data, err := os.ReadFile(filepath.Join(directoryB, name))
		if err != nil || string(data) != name {
			t.Fatalf("read %s beside a non-portable inode = %q, %v", name, data, err)
		}
	}
}

const pagedEntryCount = 600

func pagedEntryName(i int) string { return fmt.Sprintf("entry-%04d", i) }

// TestPagedReaddirReturnsEveryNameExactlyOnce asserts the exact set of names, not
// just the count. A cookie or paging defect that returns one entry twice and
// drops another keeps the count correct and is invisible to a length check.
func TestPagedReaddirReturnsEveryNameExactlyOnce(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	directoryA, directoryB := f.join(0, "many"), f.join(1, "many")
	mustMkdir(t, directoryA)
	want := make([]string, 0, pagedEntryCount)
	for i := range pagedEntryCount {
		name := pagedEntryName(i)
		want = append(want, name)
		// Every fifth entry is a directory so the per-entry kind is exercised on
		// every page, not only on the first.
		if i%5 == 0 {
			mustMkdir(t, filepath.Join(directoryA, name))
			continue
		}
		mustWrite(t, filepath.Join(directoryA, name), nil, 0o600)
	}
	slices.Sort(want)

	// Three independent enumerations: the cursor must restart cleanly and produce
	// the identical set every time.
	for attempt := range 3 {
		entries, err := os.ReadDir(directoryB)
		if err != nil {
			t.Fatalf("attempt %d: paged readdir: %v", attempt, err)
		}
		seen := make(map[string]int, len(entries))
		got := make([]string, 0, len(entries))
		for _, entry := range entries {
			seen[entry.Name()]++
			got = append(got, entry.Name())
			index, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), "entry-"))
			if err != nil {
				t.Fatalf("attempt %d: unexpected name %q", attempt, entry.Name())
			}
			if entry.IsDir() != (index%5 == 0) {
				t.Fatalf("attempt %d: %s IsDir=%t, want %t", attempt, entry.Name(), entry.IsDir(), index%5 == 0)
			}
		}
		for name, count := range seen {
			if count != 1 {
				t.Fatalf("attempt %d: %s appeared %d times in one enumeration", attempt, name, count)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Fatalf("attempt %d: paged readdir returned %d names, want the exact set of %d", attempt, len(got), len(want))
		}
	}
}

// TestPagedReaddirRefusesToPageAcrossARemoteMutation asserts the verifier
// contract: an enumeration cursor is invalidated by a concurrent directory
// mutation and reports ESTALE, rather than silently returning a listing that
// mixes two different directory states.
func TestPagedReaddirRefusesToPageAcrossARemoteMutation(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	directoryA, directoryB := f.join(0, "paged"), f.join(1, "paged")
	mustMkdir(t, directoryA)
	for i := range pagedEntryCount {
		mustWrite(t, filepath.Join(directoryA, pagedEntryName(i)), nil, 0o600)
	}

	directory, err := os.Open(directoryB)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	// One kernel READDIR carries at most a page of entries, so consuming a single
	// entry guarantees the enumeration is started but not finished.
	if _, err := directory.ReadDir(1); err != nil {
		t.Fatalf("start the enumeration: %v", err)
	}
	mustWrite(t, filepath.Join(directoryA, "inserted-midway"), nil, 0o600)

	var consumed int
	var readErr error
	for {
		batch, err := directory.ReadDir(1)
		consumed += len(batch)
		if err != nil {
			readErr = err
			break
		}
	}
	if errors.Is(readErr, io.EOF) {
		t.Fatalf("enumeration completed across a concurrent remote create after %d entries; "+
			"the readdir verifier did not invalidate the cursor", consumed)
	}
	requireErrno(t, readErr, syscall.ESTALE, "paging across a concurrent remote directory mutation")

	// The invalidation must be recoverable: a fresh enumeration sees the new set.
	entries, err := os.ReadDir(directoryB)
	if err != nil {
		t.Fatalf("re-enumerate after the invalidation: %v", err)
	}
	if len(entries) != pagedEntryCount+1 {
		t.Fatalf("re-enumeration returned %d entries, want %d", len(entries), pagedEntryCount+1)
	}
}

// TestWriteSizeClassesUseExactAuthorityShapes is gated on the pinned kernel.
// It proves the small-write optimization at the real /dev/fuse boundary and
// also pins that the transaction ladder owns both byte counts above max_write
// and iterators which fit that byte bound but exceed one request page vector.
func TestWriteSizeClassesUseExactAuthorityShapes(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	path := f.join(0, "write-size-classes")
	file := mustOpenFile(t, path, os.O_CREATE|os.O_RDWR, 0o600)
	defer file.Close()

	countWrite := func(write func() error) (oneShot, transactions int) {
		t.Helper()
		beforeOneShot := f.counter.count("one-shot-write")
		beforeTransactions := f.counter.count("write-transaction")
		if err := write(); err != nil {
			t.Fatal(err)
		}
		return f.counter.count("one-shot-write") - beforeOneShot,
			f.counter.count("write-transaction") - beforeTransactions
	}

	positioned := bytes.Repeat([]byte{0x31}, 4096)
	oneShot, transactions := countWrite(func() error {
		n, err := file.WriteAt(positioned, 0)
		if err == nil && n != len(positioned) {
			return io.ErrShortWrite
		}
		return err
	})
	if oneShot != 1 || transactions != 0 {
		t.Fatalf("4 KiB positioned write authority shapes = one-shot %d, transaction phases %d, want 1/0", oneShot, transactions)
	}

	appendFile := mustOpenFile(t, path, os.O_WRONLY|os.O_APPEND, 0)
	appendPayload := bytes.Repeat([]byte{0x32}, 4096)
	oneShot, transactions = countWrite(func() error {
		n, err := appendFile.Write(appendPayload)
		if err == nil && n != len(appendPayload) {
			return io.ErrShortWrite
		}
		return err
	})
	if err := appendFile.Close(); err != nil {
		t.Fatal(err)
	}
	if oneShot != 1 || transactions != 0 {
		t.Fatalf("4 KiB append authority shapes = one-shot %d, transaction phases %d, want 1/0", oneShot, transactions)
	}

	const maxWrite = 1 << 20
	mapping, err := unix.Mmap(-1, 0, maxWrite+os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mapping)
	for index := range mapping {
		mapping[index] = 0x33
	}
	unaligned := mapping[208 : 208+maxWrite]
	oneShot, transactions = countWrite(func() error {
		n, err := unix.Pwrite(int(file.Fd()), unaligned, 2*maxWrite)
		if err == nil && n != len(unaligned) {
			return io.ErrShortWrite
		}
		return err
	})
	if oneShot != 0 || transactions != 4 {
		t.Fatalf("unaligned max_write positioned write authority shapes = one-shot %d, transaction phases %d, want 0/4", oneShot, transactions)
	}

	large := mapping[:maxWrite+1]
	oneShot, transactions = countWrite(func() error {
		n, err := unix.Pwrite(int(file.Fd()), large, 3*maxWrite)
		if err == nil && n != len(large) {
			return io.ErrShortWrite
		}
		return err
	})
	if oneShot != 0 || transactions != 4 {
		t.Fatalf("max_write+1 positioned write authority shapes = one-shot %d, transaction phases %d, want 0/4", oneShot, transactions)
	}
	expected := make([]byte, 4*maxWrite+1)
	copy(expected, positioned)
	copy(expected[len(positioned):], appendPayload)
	copy(expected[2*maxWrite:], unaligned)
	copy(expected[3*maxWrite:], large)
	requireContent(t, path, expected, "data after both write-size shapes")
}

// TestConcurrentCrossMountWritersToOneFile covers two mounts writing the same
// file at once. Disjoint ranges must all land, and a whole-block rewrite must
// never tear, because a single kernel write below the negotiated maximum is one
// authority mutation.
func TestConcurrentCrossMountWritersToOneFile(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	const (
		blockSize = 4096
		blocks    = 64
	)
	nameA, nameB := f.join(0, "concurrent"), f.join(1, "concurrent")
	mustWrite(t, nameA, nil, 0o600)

	writerA := mustOpenFile(t, nameA, os.O_RDWR, 0)
	writerB := mustOpenFile(t, nameB, os.O_RDWR, 0)

	block := func(index int) []byte { return bytes.Repeat([]byte{byte(index)}, blockSize) }
	writersByParity := []*os.File{writerA, writerB}
	var writers sync.WaitGroup
	failures := make(chan error, blocks)
	for parity, writer := range writersByParity {
		writers.Add(1)
		go func(parity int, writer *os.File) {
			defer writers.Done()
			for index := parity; index < blocks; index += 2 {
				if _, err := writer.WriteAt(block(index), int64(index)*blockSize); err != nil {
					failures <- fmt.Errorf("write block %d: %w", index, err)
					return
				}
			}
		}(parity, writer)
	}
	writers.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}

	requireSize(t, nameB, blocks*blockSize, "size after interleaved cross-mount writes")
	got, err := os.ReadFile(nameB)
	if err != nil {
		t.Fatal(err)
	}
	for index := range blocks {
		if !bytes.Equal(got[index*blockSize:(index+1)*blockSize], block(index)) {
			t.Fatalf("block %d was lost or corrupted by the concurrent writer on the other mount", index)
		}
	}

	// Same range, both mounts, repeatedly. The final block must be entirely one
	// writer's pattern: a partially applied block means a kernel write was split
	// across authority mutations.
	const rounds = 40
	for parity, writer := range writersByParity {
		writers.Add(1)
		go func(parity int, writer *os.File) {
			defer writers.Done()
			pattern := bytes.Repeat([]byte{byte('A' + parity)}, blockSize)
			for range rounds {
				if _, err := writer.WriteAt(pattern, 0); err != nil {
					t.Errorf("contended write: %v", err)
					return
				}
			}
		}(parity, writer)
	}
	writers.Wait()
	final := readExactlyAt(t, mustOpenFile(t, nameB, os.O_RDONLY, 0), 0, blockSize, "contended block")
	if !bytes.Equal(final, bytes.Repeat([]byte{'A'}, blockSize)) && !bytes.Equal(final, bytes.Repeat([]byte{'B'}, blockSize)) {
		t.Fatalf("contended block is torn: first byte %#x, %d distinct bytes", final[0], distinctBytes(final))
	}
}

// TestAuthorityLossFailsCleanlyInsteadOfHanging asserts that losing the volume
// authority is a bounded, diagnosable mount failure rather than a wedged mount
// point or an indefinitely blocked syscall.
func TestAuthorityLossFailsCleanlyInsteadOfHanging(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	payload := []byte("pre-outage payload")
	mustWrite(t, f.join(0, "payload"), payload, 0o600)
	requireContent(t, f.join(1, "payload"), payload, "before the authority outage")
	retained := mustOpenFile(t, f.join(1, "payload"), os.O_RDONLY, 0)
	if got := readExactlyAt(t, retained, 0, len(payload), "before the authority outage"); !bytes.Equal(got, payload) {
		t.Fatal("retained descriptor did not serve the payload before the outage")
	}
	if !isMounted(t, f.mountPath(1)) {
		t.Fatalf("%s is not a mount point before the outage", f.mountPath(1))
	}

	f.stopAuthority()

	for i := range 2 {
		cause := f.requireSessionEnded(i, 30*time.Second)
		t.Logf("mount %d terminal cause: %v", i, cause)
	}
	// The mount nothing is holding open must remove itself rather than linger as
	// a path that fails or blocks every process that later touches it.
	waitUntil(t, 30*time.Second, "the idle mount to tear itself down", func() bool {
		return !isMounted(t, f.mountPath(0))
	})

	// The mount this test still holds a descriptor on cannot be unmounted while
	// it is busy, which is ordinary POSIX. What must hold is that it fails
	// immediately and never serves the pre-outage bytes again.
	outcome := make(chan error, 1)
	go func() {
		_, err := retained.ReadAt(make([]byte, len(payload)), 0)
		outcome <- err
	}()
	select {
	case err := <-outcome:
		if err == nil {
			t.Fatal("a read through a descriptor of a destroyed authority succeeded")
		}
		// Losing the authority means this frontend can no longer be told that
		// what it cached has changed, so it revokes itself and stops being a
		// filesystem rather than failing only this operation.
		//
		// This read is served through a descriptor whose pages the earlier read
		// left resident, so with FOPEN_KEEP_CACHE it is also the assertion that
		// the revocation ladder's whole-inode data withdrawal actually ran: the
		// kernel could otherwise answer it without any request reaching this
		// frontend, and neither the revoked check nor the connection abort
		// would see it.
		if !errors.Is(err, syscall.ENOTCONN) {
			t.Fatalf("read through a descriptor of a destroyed authority = %v, want ENOTCONN (revoked)", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a read through a descriptor of a destroyed authority hung")
	}

	// Releasing the last reference must let the aborted mount disappear too. A
	// mount that stays installed after its authority died, and that Unmount can
	// no longer remove because the session was already closed, is a permanently
	// EIO path that only an administrator can clear.
	if err := retained.Close(); err != nil {
		t.Logf("closing the retained descriptor reported %v", err)
	}
	waitUntil(t, 30*time.Second, "the busy mount to tear itself down once its last descriptor is closed", func() bool {
		return !isMounted(t, f.mountPath(1))
	})
}

// TestSessionExpiryReleasesABlockedLockWait asserts that an operation parked in
// the authority's lock queue is not stranded there when its session's lease
// expires. A blocked operation that outlives its own session is the worst
// possible failure mode: it is invisible, unbounded, and unkillable.
func TestSessionExpiryReleasesABlockedLockWait(t *testing.T) {
	const lease = 3 * time.Second
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: lease})
	nameA, nameB := f.join(0, "contended"), f.join(1, "contended")
	mustWrite(t, nameA, []byte("x"), 0o600)

	holder := mustOpenFile(t, nameA, os.O_RDWR, 0)
	blocked := mustOpenFile(t, nameB, os.O_RDWR, 0)
	whole := unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(io.SeekStart), Start: 0, Len: 0}
	if err := unix.FcntlFlock(holder.Fd(), unix.F_SETLK, &whole); err != nil {
		t.Fatalf("acquire the conflicting lock: %v", err)
	}

	waiting := make(chan error, 1)
	go func() {
		request := whole
		waiting <- unix.FcntlFlock(blocked.Fd(), unix.F_SETLKW, &request)
	}()
	select {
	case err := <-waiting:
		t.Fatalf("F_SETLKW against a held cross-mount lock returned immediately: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	// Age the authority past the lease and run the sweeper a worker would run.
	f.advanceClock(4 * lease)
	if removed := f.sweepSessions(); removed == 0 {
		t.Fatal("the lease sweep removed no session even though every lease had expired")
	}

	// The bound is derived from the contract: the mount renews at lease/3, so an
	// expired session must be discovered and the blocked operation released
	// within a small multiple of the lease.
	bound := 8 * lease
	start := time.Now()
	select {
	case err := <-waiting:
		if err == nil {
			t.Fatal("a blocked lock wait was granted after its authority session expired")
		}
		t.Logf("blocked F_SETLKW released %s after session expiry: %v", time.Since(start), err)
	case <-time.After(bound):
		t.Fatalf("a blocked lock wait was still parked %s after its authority session expired", bound)
	}

	cause := f.requireSessionEnded(1, bound)
	t.Logf("mount 1 terminal cause after session expiry: %v", cause)
}

// TestUnmountRemountObservesDurableState asserts that everything the authority
// acknowledged survives a complete teardown of the mounts, the RPC server, and
// the volume handle, and that nothing else does.
func TestUnmountRemountObservesDurableState(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	stamp := time.Unix(1_700_000_000, 246_813_579)

	mustMkdir(t, f.join(0, "durable"))
	mustWrite(t, f.join(0, "durable", "body"), bytes.Repeat([]byte("d"), 9000), 0o640)
	mustWrite(t, f.join(0, "durable", "empty"), nil, 0o600)
	if err := os.Symlink("body", f.join(0, "durable", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Chtimes(f.join(0, "durable", "body"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	// fsync through the mount is the only durability promise the authority makes.
	body := mustOpenFile(t, f.join(0, "durable", "body"), os.O_RDWR, 0)
	if err := body.Sync(); err != nil {
		t.Fatalf("fsync: %v", err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}

	f.remount()

	for i := range 2 {
		what := fmt.Sprintf("mount %d after remount", i)
		requireDirectoryNames(t, f.mountPath(i), []string{"durable"}, what)
		requireDirectoryNames(t, f.join(i, "durable"), []string{"body", "empty", "link"}, what)
		requireContent(t, f.join(i, "durable", "body"), bytes.Repeat([]byte("d"), 9000), what)
		requireSize(t, f.join(i, "durable", "empty"), 0, what)
		info, err := os.Stat(f.join(i, "durable", "body"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("%s: mode = %#o, want 0640", what, info.Mode().Perm())
		}
		if got := info.ModTime().UnixNano(); got != stamp.UnixNano() {
			t.Fatalf("%s: mtime = %d, want %d", what, got, stamp.UnixNano())
		}
		target, err := os.Readlink(f.join(i, "durable", "link"))
		if err != nil || target != "body" {
			t.Fatalf("%s: readlink = %q, %v", what, target, err)
		}
	}

	// Writes made after the remount must be visible across mounts exactly as
	// before, proving the new epoch is fully functional rather than read-only.
	mustWrite(t, f.join(1, "durable", "after"), []byte("new epoch"), 0o600)
	requireContent(t, f.join(0, "durable", "after"), []byte("new epoch"), "written after the remount")
}

// TestLazyUnmountWaitsForRetainedFUSEReferenceBeforeCleanDetach pins the Linux
// distinction between namespace detach and connection termination. MNT_DETACH
// removes the mount from mountinfo immediately, but an already-open file keeps
// the old FUSE connection capable of issuing requests. Durable membership must
// remain active through that interval.
func TestLazyUnmountWaitsForRetainedFUSEReferenceBeforeCleanDetach(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	path := f.join(0, "retained")
	mustWrite(t, path, []byte("still referenced"), 0o600)
	retained := mustOpenFile(t, path, os.O_RDONLY, 0)
	mount := f.mounts[0]

	connectionDone := make(chan struct{})
	go func() {
		mount.Wait()
		close(connectionDone)
	}()
	if output, err := exec.Command("fusermount3", "-u", "-z", f.mountPath(0)).CombinedOutput(); err != nil {
		_ = retained.Close()
		t.Fatalf("lazy unmount: %v (%s)", err, output)
	}
	if isMounted(t, f.mountPath(0)) {
		_ = retained.Close()
		t.Fatal("lazy unmount left the mount in this namespace")
	}
	select {
	case <-connectionDone:
		_ = retained.Close()
		t.Fatal("FUSE serving connection ended while an open descriptor still retained the lazy mount")
	case <-time.After(100 * time.Millisecond):
	}
	if count := f.membership.activeCount(); count != 1 {
		_ = retained.Close()
		t.Fatalf("durable membership during retained lazy mount = %d, want 1", count)
	}

	if err := retained.Close(); err != nil {
		t.Logf("closing the retained descriptor after lazy unmount reported %v", err)
	}
	select {
	case <-connectionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("FUSE serving connection did not end after the final retained reference closed")
	}
	if err := mount.Close(); err != nil {
		t.Fatalf("clean detach after lazy mount connection termination: %v", err)
	}
	if count := f.membership.activeCount(); count != 0 {
		t.Fatalf("durable membership after terminal lazy mount = %d, want 0", count)
	}
	// The fixture must not issue a second teardown against the mount we consumed.
	f.mounts[0] = nil
}

// TestFailedKernelMountDischargesStrictMembership covers the startup boundary
// where the authority has already admitted a strict session but fusermount3
// refuses before a kernel mount ID can be recorded. The unique planned FUSE
// source is still exact evidence: once NewServer returns without a server and
// mountinfo contains no such source, this session cannot retain kernel caches.
func TestFailedKernelMountDischargesStrictMembership(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	if count := f.membership.activeCount(); count != 1 {
		t.Fatalf("initial strict membership = %d, want 1", count)
	}

	client, transport := f.dialClient()
	if count := f.membership.activeCount(); count != 2 {
		t.Fatalf("membership after failed-startup attach = %d, want 2", count)
	}

	mountRoot := t.TempDir()
	mountpoint := filepath.Join(mountRoot, "non-searchable")
	if err := os.Mkdir(mountpoint, 0o600); err != nil {
		t.Fatal(err)
	}
	backing := filepath.Join(mountRoot, "local")
	if err := os.Mkdir(backing, 0o700); err != nil {
		t.Fatal(err)
	}
	mountInstanceID, err := mountid.NewMountInstance()
	if err != nil {
		t.Fatal(err)
	}
	mount, err := MountVolume(context.Background(), mountpoint, transport, Config{
		MountInstanceID: mountInstanceID, RequestTimeout: integrationRequestTimeout,
		MaxBackground: 64, MaxInFlight: integrationMaxInFlight, ReclaimQueue: 1024,
		PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid()),
		Coherence: CoherenceStrict, CachedNameCapacity: integrationCachedNames,
		RepairBudget: integrationRepairBudget, Routes: f.cfg.rules, LocalBacking: backing,
	})
	if err == nil || mount != nil {
		if mount != nil {
			_ = mount.Unmount()
		}
		t.Fatalf("mount on a non-searchable target = (%v, %v), want startup refusal", mount, err)
	}
	if !FailedStartupClean(err) {
		t.Fatalf("proven-absent failed startup was not classified clean: %v", err)
	}
	if isMounted(t, mountpoint) {
		t.Fatal("failed startup left a kernel mount installed")
	}
	if count := f.membership.activeCount(); count != 1 {
		t.Fatalf("membership after proven-absent failed startup = %d, want only the fixture mount", count)
	}
	select {
	case <-client.SessionDone():
	default:
		t.Fatal("failed-startup authority client remained open after clean detach")
	}
}

// TestWorkloadGitAcrossMounts runs a real git repository on the mount and reads
// it back through the other one.
func TestWorkloadGitAcrossMounts(t *testing.T) {
	requireWorkloadEnvironment(t)
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})

	repository := f.join(0, "repo")
	f.runWorkload("git", "init", repository)
	f.runWorkload("git", "-C", repository, "config", "user.email", "portablefs@example.invalid")
	f.runWorkload("git", "-C", repository, "config", "user.name", "PortableFS Test")
	mustWrite(t, filepath.Join(repository, "source.txt"), []byte("content\n"), 0o600)
	f.runWorkload("git", "-C", repository, "add", "source.txt")
	f.runWorkload("git", "-C", repository, "commit", "-m", "exercise PortableFS")
	f.runWorkload("git", "-C", f.join(1, "repo"), "fsck", "--full")
	// The commit must be readable through the other mount, not merely fsck-clean.
	log, err := exec.Command("git", "-C", f.join(1, "repo"), "log", "--format=%s").CombinedOutput()
	if err != nil || strings.TrimSpace(string(log)) != "exercise PortableFS" {
		t.Fatalf("git log through the second mount = %q, %v", log, err)
	}
}

// TestWorkloadSQLiteAcrossMounts is a separate test from the git workload on
// purpose: the two exercise different guarantees, and one failing must not hide
// the other.
func TestWorkloadSQLiteAcrossMounts(t *testing.T) {
	requireWorkloadEnvironment(t)
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	requireSQLiteRollbackJournalHandoff(t, f)
	requireSQLiteWALIsRefused(t, f)
}

// requireSQLiteRollbackJournalHandoff is the part rollback-journal mode actually
// makes hard: two connections on two different mounts contending for the write
// lock. The waiter must block until the holder commits, which is only true if
// POSIX record locks are shared by the authority. If locking were a no-op the
// waiter would return immediately and the elapsed-time assertion fails.
func requireSQLiteRollbackJournalHandoff(t *testing.T, f *integrationFixture) {
	t.Helper()
	const hold = time.Second
	databaseA, databaseB := f.join(0, "sqlite.db"), f.join(1, "sqlite.db")
	f.runWorkload("sqlite3", databaseA,
		"PRAGMA journal_mode=DELETE; CREATE TABLE items(value TEXT); INSERT INTO items VALUES ('portable');")
	if output, err := exec.Command("sqlite3", databaseB, "SELECT value FROM items;").CombinedOutput(); err != nil || string(output) != "portable\n" {
		t.Fatalf("sqlite cross-mount query = %q, %v", output, err)
	}

	holder := exec.Command("sqlite3", databaseA)
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Wait() }()
	if _, err := io.WriteString(stdin, "PRAGMA busy_timeout=0;\nBEGIN IMMEDIATE;\nINSERT INTO items VALUES('holder');\n"); err != nil {
		t.Fatal(err)
	}
	// The rollback journal appearing on the *other* mount is the observable proof
	// that the write transaction is open and its RESERVED lock is held. It needs
	// no marker round trip through a pipe, and it additionally asserts that the
	// journal file itself is visible across mounts, which rollback-journal mode
	// depends on entirely.
	waitUntil(t, 30*time.Second, "the holder's rollback journal to appear on the second mount", func() bool {
		_, err := os.Lstat(f.join(1, "sqlite.db-journal"))
		return err == nil
	})

	waiterDone := make(chan struct {
		output []byte
		err    error
		took   time.Duration
	}, 1)
	go func() {
		start := time.Now()
		output, err := exec.Command("sqlite3", "-cmd", "PRAGMA busy_timeout=60000", databaseB,
			"INSERT INTO items VALUES('waiter');").CombinedOutput()
		waiterDone <- struct {
			output []byte
			err    error
			took   time.Duration
		}{output, err, time.Since(start)}
	}()

	select {
	case result := <-waiterDone:
		t.Fatalf("the second mount's writer was not blocked by the first mount's transaction "+
			"(returned after %s: %v %q)", result.took, result.err, result.output)
	case <-time.After(hold):
	}

	if _, err := io.WriteString(stdin, "COMMIT;\n"); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-waiterDone:
		if result.err != nil {
			t.Fatalf("the waiting writer failed after the lock handoff: %v\n%s", result.err, result.output)
		}
		if result.took < hold {
			t.Fatalf("the waiting writer finished in %s, less than the %s the lock was held: "+
				"cross-mount write locking is not being enforced", result.took, hold)
		}
		t.Logf("sqlite cross-mount write lock handed over after %s", result.took)
	case <-time.After(60 * time.Second):
		t.Fatal("the waiting writer never acquired the write lock after the holder committed")
	}

	for _, database := range []string{databaseA, databaseB} {
		output, err := exec.Command("sqlite3", database,
			"PRAGMA integrity_check; SELECT count(*) FROM items;").CombinedOutput()
		if err != nil || strings.TrimSpace(string(output)) != "ok\n3" {
			t.Fatalf("sqlite state at %s = %q, %v; want integrity ok and 3 rows", database, output, err)
		}
	}
}

// requireSQLiteWALIsRefused turns the branch's claim that SQLite WAL is
// unsupported into an assertion instead of a comment. WAL needs a MAP_SHARED
// mapping of the -shm sidecar, which a coherent direct-I/O mount refuses with
// ENODEV, asserted directly in the mmap block of the POSIX-surface test.
//
// The observed shape is sharper than "unsupported" and worth recording:
// `PRAGMA journal_mode=WAL` reports success and rewrites the database header,
// and every connection after that, on either mount, fails with SQLITE_IOERR,
// leaving the database permanently unusable. What this test pins is the
// invariant that survives any improvement to that behaviour: WAL must never
// become a working cross-mount configuration, and refusing it must cost the
// database, never the mount or the rest of the volume.
func requireSQLiteWALIsRefused(t *testing.T, f *integrationFixture) {
	t.Helper()
	databaseA, databaseB := f.join(0, "wal.db"), f.join(1, "wal.db")
	f.runWorkload("sqlite3", databaseA, "CREATE TABLE t(v TEXT); INSERT INTO t VALUES('rollback');")

	switched, switchErr := exec.Command("sqlite3", databaseA, "PRAGMA journal_mode=WAL;").CombinedOutput()
	t.Logf("PRAGMA journal_mode=WAL reported %q (%v)", strings.TrimSpace(string(switched)), switchErr)

	written, writeErr := exec.Command("sqlite3", databaseA, "INSERT INTO t VALUES('wal-write');").CombinedOutput()
	read, readErr := exec.Command("sqlite3", databaseB, "SELECT v FROM t;").CombinedOutput()
	if writeErr == nil && readErr == nil && strings.Contains(string(read), "wal-write") {
		t.Fatalf("SQLite WAL is working across mounts, but this build documents it as unsupported: "+
			"write %q, cross-mount read %q", written, read)
	}
	t.Logf("WAL write %q (%v); cross-mount read %q (%v)",
		strings.TrimSpace(string(written)), writeErr, strings.TrimSpace(string(read)), readErr)

	// Refusing WAL is a database-level failure. It must not take the mount with
	// it, and it must not affect anything else stored on the same volume.
	if diagnostics := f.sessionDiagnostics(); strings.Contains(diagnostics, "ended") {
		t.Fatalf("attempting to enable WAL terminated an authority session: %s", diagnostics)
	}
	f.runWorkload("sqlite3", f.join(0, "unaffected.db"), "CREATE TABLE u(v TEXT); INSERT INTO u VALUES('ok');")
	output, err := exec.Command("sqlite3", f.join(1, "unaffected.db"),
		"PRAGMA integrity_check; SELECT v FROM u;").CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "ok\nok" {
		t.Fatalf("an unrelated rollback-journal database on the same volume = %q, %v", output, err)
	}
}

func mustReadByte(t *testing.T, path string, offset int64) byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	value := []byte{0}
	if _, err := file.ReadAt(value, offset); err != nil {
		t.Fatal(err)
	}
	return value[0]
}

func nlink(t *testing.T, path string) uint64 {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return uint64(stat.Nlink)
}

func inodeOf(t *testing.T, info os.FileInfo) uint64 {
	t.Helper()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("FileInfo for %s does not carry a Stat_t", info.Name())
	}
	return stat.Ino
}

func distinctBytes(value []byte) int {
	seen := map[byte]struct{}{}
	for _, b := range value {
		seen[b] = struct{}{}
	}
	return len(seen)
}

// --- the strict cache contract, against real kernel mounts ------------------

// TestStrictMountAnswersRepeatedPathWalksWithoutTheAuthority is the whole point
// of the change. A metadata-heavy workload re-walks the same names constantly;
// with zero entry lifetimes every one of those walks costs one authority round
// trip per component, which is the multiplier that made `git status` on a few
// thousand files cost tens of thousands of RPCs. This fails on any frontend
// that publishes nothing cacheable.
func TestStrictMountAnswersRepeatedPathWalksWithoutTheAuthority(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	const files = 64
	directory := f.join(0, "tree")
	mustMkdir(t, directory)
	for i := range files {
		mustWrite(t, filepath.Join(directory, fmt.Sprintf("file-%03d", i)), []byte("x"), 0o600)
	}
	observed := filepath.Join(f.mountPath(1), "tree")
	walk := func() {
		for i := range files {
			if _, err := os.Lstat(filepath.Join(observed, fmt.Sprintf("file-%03d", i))); err != nil {
				t.Fatalf("stat during the walk: %v", err)
			}
		}
	}
	cost := func() (int, int) {
		lookups := f.counter.count("lookup")
		attrs := f.counter.count("getattr")
		walk()
		return f.counter.count("lookup") - lookups, f.counter.count("getattr") - attrs
	}
	first, firstAttrs := cost()
	if first == 0 {
		t.Fatal("the first walk reached the authority zero times; the fixture is not measuring what it thinks")
	}
	second, secondAttrs := cost()
	third, thirdAttrs := cost()
	t.Logf("per %d-name walk: LOOKUP first=%d second=%d third=%d; GETATTR first=%d second=%d third=%d",
		files, first, second, third, firstAttrs, secondAttrs, thirdAttrs)
	if secondAttrs > files/8 || thirdAttrs > files/8 {
		t.Fatalf("repeated walks cost %d and %d GETATTRs for %d names; a cached attribute must answer lstat(2) without the authority", secondAttrs, thirdAttrs, files)
	}
	// The kernel resolves "tree" itself too, so a perfectly cached repeat walk
	// is zero LOOKUPs. Allow a small margin for a dentry the kernel evicted
	// under memory pressure, but nothing like a per-name round trip.
	if second > files/8 || third > files/8 {
		t.Fatalf("repeated walks cost %d and %d LOOKUPs for %d names; a strict mount must resolve a cached path without the authority", second, third, files)
	}
}

// TestMutationPostStateEliminatesFollowupMetadataRPCs pins the request totals
// exact post-state is meant to buy. Names are warmed before each mutation so
// the mutation itself is the only authority operation; the immediate stat is
// then a direct assertion that the reply installed the target and parent attrs.
func TestMutationPostStateEliminatesFollowupMetadataRPCs(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	modeOf := func(info os.FileInfo) os.FileMode {
		if info == nil {
			return 0
		}
		return info.Mode()
	}
	type counts struct {
		lookup, getattr, create, mkdir, unlink, rmdir, rename, write, setattr, symlink, link int
		open, tmpfile, fallocate, copyFileRange, removeXattr                                 int
	}
	measure := func(operation string, fn func()) counts {
		before := counts{
			lookup: f.counter.count("lookup"), getattr: f.counter.count("getattr"),
			create: f.counter.count("create"), mkdir: f.counter.count("mkdir"),
			unlink: f.counter.count("unlink"), rmdir: f.counter.count("rmdir"),
			rename: f.counter.count("rename"), write: f.counter.count("one-shot-write"),
			setattr: f.counter.count("setattr"), symlink: f.counter.count("symlink"), link: f.counter.count("link"),
			open: f.counter.count("open"), tmpfile: f.counter.count("tmpfile"),
			fallocate: f.counter.count("fallocate"), copyFileRange: f.counter.count("copy-file-range"),
			removeXattr: f.counter.count("remove-xattr"),
		}
		fn()
		after := counts{
			lookup: f.counter.count("lookup"), getattr: f.counter.count("getattr"),
			create: f.counter.count("create"), mkdir: f.counter.count("mkdir"),
			unlink: f.counter.count("unlink"), rmdir: f.counter.count("rmdir"),
			rename: f.counter.count("rename"), write: f.counter.count("one-shot-write"),
			setattr: f.counter.count("setattr"), symlink: f.counter.count("symlink"), link: f.counter.count("link"),
			open: f.counter.count("open"), tmpfile: f.counter.count("tmpfile"),
			fallocate: f.counter.count("fallocate"), copyFileRange: f.counter.count("copy-file-range"),
			removeXattr: f.counter.count("remove-xattr"),
		}
		delta := counts{
			lookup: after.lookup - before.lookup, getattr: after.getattr - before.getattr,
			create: after.create - before.create, mkdir: after.mkdir - before.mkdir,
			unlink: after.unlink - before.unlink, rmdir: after.rmdir - before.rmdir,
			rename: after.rename - before.rename, write: after.write - before.write,
			setattr: after.setattr - before.setattr, symlink: after.symlink - before.symlink, link: after.link - before.link,
			open: after.open - before.open, tmpfile: after.tmpfile - before.tmpfile,
			fallocate: after.fallocate - before.fallocate, copyFileRange: after.copyFileRange - before.copyFileRange,
			removeXattr: after.removeXattr - before.removeXattr,
		}
		t.Logf("%s RPCs: lookup=%d getattr=%d create=%d mkdir=%d unlink=%d rmdir=%d rename=%d one-shot-write=%d setattr=%d symlink=%d link=%d open=%d tmpfile=%d fallocate=%d copy-file-range=%d remove-xattr=%d",
			operation, delta.lookup, delta.getattr, delta.create, delta.mkdir, delta.unlink, delta.rmdir,
			delta.rename, delta.write, delta.setattr, delta.symlink, delta.link, delta.open, delta.tmpfile,
			delta.fallocate, delta.copyFileRange, delta.removeXattr)
		return delta
	}
	requireCounts := func(operation string, got, want counts) {
		t.Helper()
		if got != want {
			t.Fatalf("%s RPCs = %+v, want %+v", operation, got, want)
		}
	}

	root := f.mountPath(0)
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("warm root attrs: %v", err)
	}
	createdPath := filepath.Join(root, "post-state-created")
	if _, err := os.Lstat(createdPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("warm create destination absence: %v", err)
	}
	var created *os.File
	createRPCs := measure("create plus child/parent stat", func() {
		var err error
		// Linux always performs one fresh LOOKUP for a negative dentry before
		// CREATE, including the ordinary non-exclusive path. It precedes the
		// mutation and therefore says nothing about post-state completeness; the
		// child and parent stats below are the follow-up requests this assertion
		// requires the CREATE post-state to eliminate.
		created, err = os.OpenFile(createdPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := os.Lstat(createdPath); err != nil {
			t.Fatalf("stat created child: %v", err)
		}
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("stat parent after create: %v", err)
		}
	})
	requireCounts("create plus child/parent stat", createRPCs, counts{lookup: 1, create: 1})

	payload := []byte("exact post-state")
	writeRPCs := measure("write plus warm fstat", func() {
		if n, err := created.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("write = (%d, %v), want (%d, nil)", n, err, len(payload))
		}
		info, err := created.Stat()
		if err != nil || info.Size() != int64(len(payload)) {
			t.Fatalf("warm fstat after write: size=%v err=%v", sizeOf(info), err)
		}
	})
	requireCounts("write plus warm fstat", writeRPCs, counts{write: 1})
	if err := created.Close(); err != nil {
		t.Fatalf("close created file: %v", err)
	}

	setattrRPCs := measure("setattr plus warm stat", func() {
		if err := os.Chmod(createdPath, 0o640); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		info, err := os.Lstat(createdPath)
		if err != nil || info.Mode().Perm() != 0o640 {
			t.Fatalf("stat after chmod: mode=%v err=%v", modeOf(info), err)
		}
	})
	requireCounts("setattr plus warm stat", setattrRPCs, counts{setattr: 1})

	truncateRPCs := measure("truncating open plus warm fstat", func() {
		file, err := os.OpenFile(createdPath, os.O_TRUNC|os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("truncating open: %v", err)
		}
		info, statErr := file.Stat()
		if statErr != nil || info.Size() != 0 {
			_ = file.Close()
			t.Fatalf("fstat after truncating open: size=%v err=%v", sizeOf(info), statErr)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close truncated file: %v", err)
		}
	})
	requireCounts("truncating open plus warm fstat", truncateRPCs, counts{open: 1})

	fallocateFile, err := os.OpenFile(createdPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open fallocate target: %v", err)
	}
	fallocateRPCs := measure("fallocate plus warm fstat", func() {
		if err := unix.Fallocate(int(fallocateFile.Fd()), 0, 0, 4096); err != nil {
			t.Fatalf("fallocate: %v", err)
		}
		info, statErr := fallocateFile.Stat()
		if statErr != nil || info.Size() != 4096 {
			t.Fatalf("fstat after fallocate: size=%v err=%v", sizeOf(info), statErr)
		}
	})
	requireCounts("fallocate plus warm fstat", fallocateRPCs, counts{fallocate: 1})
	if err := fallocateFile.Close(); err != nil {
		t.Fatalf("close fallocate target: %v", err)
	}

	const removableXattr = "user.portablefs-post-state-remove"
	if err := unix.Setxattr(filepath.Join(f.volumeRoot, "post-state-created"), removableXattr, []byte("value"), 0); err != nil {
		t.Fatalf("seed removable xattr directly in the isolated backing tree: %v", err)
	}
	removeXattrRPCs := measure("remove xattr plus warm stat", func() {
		if err := unix.Removexattr(createdPath, removableXattr); err != nil {
			t.Fatalf("removexattr: %v", err)
		}
		if _, err := os.Lstat(createdPath); err != nil {
			t.Fatalf("stat after removexattr: %v", err)
		}
	})
	requireCounts("remove xattr plus warm stat", removeXattrRPCs, counts{removeXattr: 1})

	mkdirPath := filepath.Join(root, "post-state-directory")
	if _, err := os.Lstat(mkdirPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("warm mkdir destination absence: %v", err)
	}
	mkdirRPCs := measure("mkdir plus child/parent stat", func() {
		if err := os.Mkdir(mkdirPath, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := os.Lstat(mkdirPath); err != nil {
			t.Fatalf("stat created directory: %v", err)
		}
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("stat parent after mkdir: %v", err)
		}
	})
	requireCounts("mkdir plus child/parent stat", mkdirRPCs, counts{lookup: 1, mkdir: 1})

	mknodPath := filepath.Join(root, "post-state-mknod")
	if _, err := os.Lstat(mknodPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("warm mknod destination absence: %v", err)
	}
	mknodRPCs := measure("mknod plus child/parent stat", func() {
		if err := unix.Mknod(mknodPath, unix.S_IFREG|0o600, 0); err != nil {
			t.Fatalf("mknod regular file: %v", err)
		}
		for _, path := range []string{mknodPath, root} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("stat after mknod %s: %v", path, err)
			}
		}
	})
	requireCounts("mknod plus child/parent stat", mknodRPCs, counts{lookup: 1, create: 1})

	tmpfileRPCs := measure("tmpfile plus inode/parent stat", func() {
		fd, err := unix.Open(root, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
		if err != nil {
			t.Fatalf("open O_TMPFILE: %v", err)
		}
		file := os.NewFile(uintptr(fd), "post-state-tmpfile")
		if file == nil {
			_ = unix.Close(fd)
			t.Fatal("wrap O_TMPFILE descriptor")
		}
		if _, err := file.Stat(); err != nil {
			_ = file.Close()
			t.Fatalf("fstat O_TMPFILE: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close O_TMPFILE: %v", err)
		}
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("stat parent after O_TMPFILE: %v", err)
		}
	})
	requireCounts("tmpfile plus inode/parent stat", tmpfileRPCs, counts{tmpfile: 1})

	symlinkPath := filepath.Join(root, "post-state-symlink")
	if _, err := os.Lstat(symlinkPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("warm symlink destination absence: %v", err)
	}
	symlinkRPCs := measure("symlink plus child/parent stat", func() {
		if err := os.Symlink("post-state-created", symlinkPath); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if info, err := os.Lstat(symlinkPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("lstat created symlink: mode=%v err=%v", modeOf(info), err)
		}
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("stat parent after symlink: %v", err)
		}
	})
	requireCounts("symlink plus child/parent stat", symlinkRPCs, counts{lookup: 1, symlink: 1})

	linkPath := filepath.Join(root, "post-state-hardlink")
	if _, err := os.Lstat(createdPath); err != nil {
		t.Fatalf("warm link source: %v", err)
	}
	if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("warm link destination absence: %v", err)
	}
	linkRPCs := measure("link plus target/source/parent stat", func() {
		if err := os.Link(createdPath, linkPath); err != nil {
			t.Fatalf("link: %v", err)
		}
		for _, path := range []string{linkPath, createdPath, root} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("stat after link %s: %v", path, err)
			}
		}
	})
	requireCounts("link plus target/source/parent stat", linkRPCs, counts{lookup: 1, link: 1})

	copySourcePath, copyDestinationPath := filepath.Join(root, "post-state-copy-source"), filepath.Join(root, "post-state-copy-destination")
	mustWrite(t, copySourcePath, []byte("copy"), 0o600)
	mustWrite(t, copyDestinationPath, nil, 0o600)
	copySource, err := os.Open(copySourcePath)
	if err != nil {
		t.Fatalf("open copy source: %v", err)
	}
	copyDestination, err := os.OpenFile(copyDestinationPath, os.O_RDWR, 0)
	if err != nil {
		_ = copySource.Close()
		t.Fatalf("open copy destination: %v", err)
	}
	copyRPCs := measure("copy-file-range plus source/destination stat", func() {
		copied, err := unix.CopyFileRange(int(copySource.Fd()), nil, int(copyDestination.Fd()), nil, 4, 0)
		if err != nil || copied != 4 {
			t.Fatalf("copy_file_range = (%d, %v), want (4, nil)", copied, err)
		}
		for _, file := range []*os.File{copySource, copyDestination} {
			if _, err := file.Stat(); err != nil {
				t.Fatalf("fstat after copy_file_range: %v", err)
			}
		}
	})
	requireCounts("copy-file-range plus source/destination stat", copyRPCs, counts{copyFileRange: 1})
	if err := copySource.Close(); err != nil {
		t.Fatalf("close copy source: %v", err)
	}
	if err := copyDestination.Close(); err != nil {
		t.Fatalf("close copy destination: %v", err)
	}

	rmdirPath := filepath.Join(root, "post-state-rmdir")
	mustMkdir(t, rmdirPath)
	for _, path := range []string{rmdirPath, root} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("warm rmdir path %s: %v", path, err)
		}
	}
	rmdirRPCs := measure("rmdir plus child/parent stat", func() {
		if err := os.Remove(rmdirPath); err != nil {
			t.Fatalf("rmdir: %v", err)
		}
		if _, err := os.Lstat(rmdirPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat removed directory: %v", err)
		}
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("stat parent after rmdir: %v", err)
		}
	})
	requireCounts("rmdir plus child/parent stat", rmdirRPCs, counts{lookup: 1, rmdir: 1})

	existingName := "post-state-existing-create"
	existingPath := filepath.Join(root, existingName)
	if _, err := os.Lstat(existingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("warm existing-create negative: %v", err)
	}
	rootCapability, err := f.store.Root()
	if err != nil {
		t.Fatalf("acquire store root: %v", err)
	}
	type existingCreateInjection struct {
		forget func() error
		err    error
	}
	injected := make(chan existingCreateInjection, 1)
	var injectOnce sync.Once
	f.counter.setAfterHandle(func(request *authoritypb.Request, response *authoritypb.Response) {
		lookup := request.GetLookup()
		if lookup == nil || string(lookup.GetName()) != existingName || response.GetErrno() != int32(syscall.ENOENT) {
			return
		}
		injectOnce.Do(func() {
			capability, _, createErr := f.store.Create(rootCapability, existingName, 0o600, true)
			result := existingCreateInjection{err: createErr}
			if createErr == nil {
				result.forget = func() error { return f.store.Forget(capability) }
			}
			injected <- result
		})
	})
	defer f.counter.setAfterHandle(nil)
	existingCreateRPCs := measure("existing create plus child/parent stat", func() {
		file, err := os.OpenFile(existingPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("open existing name through FUSE_CREATE: %v", err)
		}
		if _, err := file.Stat(); err != nil {
			_ = file.Close()
			t.Fatalf("fstat existing-create result: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close existing-create result: %v", err)
		}
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("stat parent after existing create: %v", err)
		}
	})
	f.counter.setAfterHandle(nil)
	var injection existingCreateInjection
	select {
	case injection = <-injected:
	case <-time.After(integrationRequestTimeout):
		t.Fatal("the existing-create race observed no negative pre-CREATE lookup")
	}
	if injection.err != nil {
		t.Fatalf("materialize existing-create race after the negative lookup: %v", injection.err)
	}
	defer func() {
		if err := injection.forget(); err != nil {
			t.Errorf("forget direct existing-create capability: %v", err)
		}
	}()
	requireCounts("existing create plus child/parent stat", existingCreateRPCs, counts{lookup: 1, create: 1})

	unlinkedPath := filepath.Join(root, "post-state-unlinked")
	mustWrite(t, unlinkedPath, []byte("unlink"), 0o600)
	if _, err := os.Lstat(unlinkedPath); err != nil {
		t.Fatalf("warm unlink source: %v", err)
	}
	unlinkRPCs := measure("unlink plus child/parent stat", func() {
		if err := os.Remove(unlinkedPath); err != nil {
			t.Fatalf("unlink: %v", err)
		}
		if _, err := os.Lstat(unlinkedPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat unlinked child: %v", err)
		}
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("stat parent after unlink: %v", err)
		}
	})
	requireCounts("unlink plus child/parent stat", unlinkRPCs, counts{lookup: 1, unlink: 1})

	oldParent, newParent := filepath.Join(root, "old-parent"), filepath.Join(root, "new-parent")
	mustMkdir(t, oldParent)
	mustMkdir(t, newParent)
	source, destination := filepath.Join(oldParent, "source"), filepath.Join(newParent, "destination")
	mustWrite(t, source, []byte("rename"), 0o600)
	for _, path := range []string{oldParent, newParent, source} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("warm rename path %s: %v", path, err)
		}
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("warm rename destination absence: %v", err)
	}
	renameRPCs := measure("rename plus child/parent stats", func() {
		if err := os.Rename(source, destination); err != nil {
			t.Fatalf("rename: %v", err)
		}
		for _, path := range []string{destination, oldParent, newParent} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("stat after rename %s: %v", path, err)
			}
		}
	})
	requireCounts("rename plus child/parent stats", renameRPCs, counts{lookup: 1, rename: 1})
}

// TestRemoteRemovalIsRepairedBeforeTheMutatorsCallReturns is the barrier's
// actual promise. The observing mount has the name cached with a one-minute
// lifetime, so nothing but a synchronous repair can make it stop resolving --
// and it must have stopped by the time the removing side's syscall returns,
// with no polling, no retry, and no sleep anywhere in this test.
func TestRemoteRemovalIsRepairedBeforeTheMutatorsCallReturns(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	mustWrite(t, f.join(0, "cached"), []byte("payload"), 0o600)
	requireContent(t, f.join(1, "cached"), []byte("payload"), "establishing the cached binding")
	// Prove it really is cached: a second resolution must not reach the wire.
	if reached := f.countRequests("lookup", func() {
		if _, err := os.Lstat(f.join(1, "cached")); err != nil {
			t.Fatal(err)
		}
	}); reached != 0 {
		t.Fatalf("the observing mount still asked the authority %d times; this test needs a genuinely cached binding to be meaningful", reached)
	}

	if err := os.Remove(f.join(0, "cached")); err != nil {
		t.Fatalf("remote unlink: %v", err)
	}
	// No waitUntil. The unlink has returned, so the repair has already happened.
	requireAbsent(t, f.join(1, "cached"), "immediately after the remote unlink returned")
}

// TestRemoteWriteIsRepairedBeforeTheWritersCallReturns is the same assertion
// for inode state: a cached size must be wrong for zero time.
func TestRemoteWriteIsRepairedBeforeTheWritersCallReturns(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	mustWrite(t, f.join(0, "growing"), []byte("small"), 0o600)
	requireSize(t, f.join(1, "growing"), 5, "establishing the cached size")

	mustWrite(t, f.join(0, "growing"), []byte("considerably larger"), 0o600)
	requireSize(t, f.join(1, "growing"), 19, "immediately after the remote write returned")
	requireContent(t, f.join(1, "growing"), []byte("considerably larger"), "immediately after the remote write returned")
}

// TestTheInitiatingMountDoesNotDeadlockOnItsOwnMutation walks the shapes whose
// repair would need the very VFS lock the initiating syscall holds. Every one
// of them completes, and the mount is still usable afterwards; a frontend that
// repaired its own mutation would hang here instead of failing.
func TestTheInitiatingMountDoesNotDeadlockOnItsOwnMutation(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	directory := f.join(0, "self")
	mustMkdir(t, directory)
	for i := range 32 {
		name := filepath.Join(directory, fmt.Sprintf("entry-%02d", i))
		mustWrite(t, name, []byte("v1"), 0o600)
		// Resolve it, so the binding is genuinely in this mount's kernel cache
		// before the operation that changes it again.
		if _, err := os.Lstat(name); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(name, name+".renamed"); err != nil {
			t.Fatalf("self rename: %v", err)
		}
		if _, err := os.Lstat(name + ".renamed"); err != nil {
			t.Fatalf("stat after self rename: %v", err)
		}
		if err := os.Remove(name + ".renamed"); err != nil {
			t.Fatalf("self unlink: %v", err)
		}
	}
	requireDirectoryNames(t, directory, nil, "after the self-mutation sequence")
	// The other mount is still live, which is the real proof that none of the
	// above stalled the barrier.
	requireDirectoryNames(t, f.join(1, "self"), nil, "observed from the second mount")
}

// TestVisibilityAcknowledgmentSurvivesSaturatedIO is the liveness assertion.
// Acknowledging is what releases the mutating machine, so a visibility loop
// queued behind bulk work converts local load on one host into a stall on
// every other host in the volume.
func TestVisibilityAcknowledgmentSurvivesSaturatedIO(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	mustMkdir(t, f.join(1, "load"))
	payload := make([]byte, 256*1024)

	stop := make(chan struct{})
	var loaders sync.WaitGroup
	for worker := range 8 {
		loaders.Add(1)
		go func() {
			defer loaders.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				name := f.join(1, "load", fmt.Sprintf("w%d-%d", worker, i%4))
				if err := os.WriteFile(name, payload, 0o600); err != nil {
					return
				}
				if _, err := os.ReadFile(name); err != nil {
					return
				}
			}
		}()
	}
	t.Cleanup(func() { close(stop); loaders.Wait() })

	// Mount 0 mutates while mount 1 is saturated. Every one of these blocks
	// until mount 1 has acknowledged both phases.
	deadline := time.Now().Add(30 * time.Second)
	for i := range 40 {
		name := f.join(0, fmt.Sprintf("barrier-%02d", i))
		if time.Now().After(deadline) {
			t.Fatalf("only %d of 40 barriered mutations completed in 30s; the observing mount's acknowledgments were starved behind its own I/O", i)
		}
		mustWrite(t, name, []byte("through the barrier"), 0o600)
		if err := os.Remove(name); err != nil {
			t.Fatalf("remove through the barrier: %v", err)
		}
	}
}

// TestMetadataWorkloadRPCCost measures the thing this whole change is for, on a
// real workload. `git status` re-lstats every tracked path; the coherent name
// cache must collapse those repeated walks rather than reintroduce one
// authority round trip per path component per invocation.
//
// The assertion is on name resolution alone. That is the part a name and
// attribute cache is responsible for; the rest of what `git status` does --
// reading its index, listing directories, and re-hashing any file git considers
// racily clean -- reaches the authority by design, and how
// much of it happens depends on wall-clock timing git owns, not on coherence.
// All of it is logged, because the interesting number is the whole shape.
func TestMetadataWorkloadRPCCost(t *testing.T) {
	requireWorkloadEnvironment(t)
	const files = 200
	kinds := []string{"lookup", "getattr", "reclaim", "other"}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	repository := f.join(0, "repo")
	f.runWorkload("git", "init", "-q", repository)
	f.runWorkload("git", "-C", repository, "config", "user.email", "portablefs@example.invalid")
	f.runWorkload("git", "-C", repository, "config", "user.name", "PortableFS Test")
	for i := range files {
		mustWrite(t, filepath.Join(repository, fmt.Sprintf("source-%03d.txt", i)), []byte("content\n"), 0o600)
	}
	f.runWorkload("git", "-C", repository, "add", ".")
	f.runWorkload("git", "-C", repository, "commit", "-q", "-m", "exercise PortableFS")
	// Make the measured invocation a steady-state walk instead of a race with
	// git's one-second racily-clean mtime rule.
	time.Sleep(1100 * time.Millisecond)
	f.runWorkload("git", "-C", repository, "status", "--porcelain")

	before := make([]int, len(kinds))
	for i, kind := range kinds {
		before[i] = f.counter.count(kind)
	}
	f.runWorkload("git", "-C", repository, "status", "--porcelain")
	lookups, total := 0, 0
	breakdown := make([]string, 0, len(kinds))
	for i, kind := range kinds {
		delta := f.counter.count(kind) - before[i]
		total += delta
		if kind == "lookup" {
			lookups = delta
		}
		breakdown = append(breakdown, fmt.Sprintf("%s=%d", kind, delta))
	}
	t.Logf("%d authority requests for one steady-state `git status` over %d tracked files (%s)", total, files, strings.Join(breakdown, " "))
	if lookups >= files/4 {
		t.Fatalf("coherent cache issued %d LOOKUPs for %d tracked files; repeated path walks must stay below one lookup per four files", lookups, files)
	}
}

// TestCachedPagesSurviveRereadsAndDieAtTheBarrier is the direct proof that the
// retained page cache is both real and coherent. TestCrossMountContentCoherence
// proves the coherence half; this proves that pages are genuinely being reused
// in between, which is the whole reason the direct-I/O flag was dropped.
//
// The two halves have to be asserted together. A mount that never cached would
// pass every coherence assertion trivially and deliver none of the performance;
// a mount that cached without joining the barrier would deliver the performance
// and be wrong. So the test counts authority READs across repeated reads of the
// same offsets (reuse) and then asserts the payload flips after a same-length
// remote overwrite (withdrawal).
//
// REQUIRES THE PRIVILEGED RUNNER: it needs a real strict-coherence kernel, two
// live mounts, and a real page cache.
func TestCachedPagesSurviveRereadsAndDieAtTheBarrier(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	nameA, nameB := f.join(0, "cached"), f.join(1, "cached")

	// Several pages, so ordinary read-ahead has something to do and the reuse
	// is not an artefact of a single-folio file.
	const size = 64 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	mustWrite(t, nameA, payload, 0o600)

	reader := mustOpenFile(t, nameB, os.O_RDONLY, 0)
	defer reader.Close()
	if got := readExactlyAt(t, reader, 0, size, "first full read"); !bytes.Equal(got, payload) {
		t.Fatal("first cross-mount read returned the wrong bytes")
	}

	// Only this mount reads in the window below, so the global counter is an
	// exact per-mount count here.
	reads := f.countRequests("read", func() {
		for range 8 {
			if got := readExactlyAt(t, reader, 0, size, "cached re-read"); !bytes.Equal(got, payload) {
				t.Fatal("cached re-read returned the wrong bytes")
			}
		}
	})
	if reads != 0 {
		t.Fatalf("eight full re-reads issued %d authority READs; FOPEN_KEEP_CACHE is not retaining anything and every read still costs a round trip", reads)
	}

	// Same length, so nothing size-derived can withdraw the cache: only the
	// sequence-ordered whole-mapping invalidation the DATA repair performs can.
	rewritten := make([]byte, size)
	for i := range rewritten {
		rewritten[i] = byte('A' + i%26)
	}
	mustWrite(t, nameA, rewritten, 0o600)
	if got := readExactlyAt(t, reader, 0, size, "re-read after a same-length remote rewrite"); !bytes.Equal(got, rewritten) {
		t.Fatal("a same-length remote rewrite left this mount serving pre-write pages from its kernel; the DATA repair did not withdraw them")
	}

	// And the cache is repopulated rather than disabled: reuse must survive a
	// repair, or the first remote write to a file would permanently cost every
	// later reader a round trip.
	repopulated := f.countRequests("read", func() {
		for range 4 {
			readExactlyAt(t, reader, 0, size, "cached re-read after repair")
		}
	})
	if repopulated != 0 {
		t.Fatalf("the page cache was not repopulated after a DATA repair: %d further authority READs", repopulated)
	}
}

// TestPrivateMappingsAreTornDownByTheDataBarrier covers the one reader that no
// userspace hook can see. A MAP_PRIVATE page is served straight out of the page
// tables with no request reaching this frontend at all, so the only thing that
// can make it coherent is invalidate_inode_pages2() unmapping it inside the
// DATA repair. If that stopped happening, every other assertion in this suite
// would still pass and executables and mapped data files would silently go
// stale.
//
// REQUIRES THE PRIVILEGED RUNNER.
func TestPrivateMappingsAreTornDownByTheDataBarrier(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	nameA, nameB := f.join(0, "mapped-coherent"), f.join(1, "mapped-coherent")

	page := os.Getpagesize()
	before := bytes.Repeat([]byte{'o'}, page)
	mustWrite(t, nameA, before, 0o600)

	mapped := mustOpenFile(t, nameB, os.O_RDONLY, 0)
	defer mapped.Close()
	view, err := unix.Mmap(int(mapped.Fd()), 0, page, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("MAP_PRIVATE of a shared file: %v", err)
	}
	defer unix.Munmap(view)
	if view[0] != 'o' {
		t.Fatalf("initial mapped byte = %q", view[0])
	}

	// Same length again. The mapping is faulted in and its page table entries
	// are live; only unmap_mapping_folio() inside the repair can take them
	// back, and if it does the next touch refaults through the authority.
	after := bytes.Repeat([]byte{'n'}, page)
	mustWrite(t, nameA, after, 0o600)
	if view[0] != 'n' {
		t.Fatalf("mapped byte after a same-length remote rewrite = %q; the DATA repair did not unmap the stale page", view[0])
	}
}

// TestRevokedMountCannotServeRetainedPages is the fencing half, and it is the
// assertion that separates this platform from the macOS defect recorded in
// docs/failure-modes.md.
//
// Every other kind of stale service a revoked mount could commit is bounded by
// refusing requests. A retained page is not: with FOPEN_KEEP_CACHE the read is
// answered inside the kernel and never becomes a request, so neither the
// frontend's revoked check nor the FUSE connection abort can see it. What
// closes it is the explicit whole-inode withdrawal the revocation ladder issues
// before the abort closes its notification channel. If that regressed, this
// reader would keep observing
// pre-fence bytes for as long as it held the file open.
//
// REQUIRES THE PRIVILEGED RUNNER: revocation is only observable against a real
// kernel mount, and the reader has to be a real process holding a real mapping
// of a real page cache.
func TestRevokedMountCannotServeRetainedPages(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	nameA, nameB := f.join(0, "fenced"), f.join(1, "fenced")

	const size = 8 * 1024
	payload := bytes.Repeat([]byte{'z'}, size)
	mustWrite(t, nameA, payload, 0o600)

	reader := mustOpenFile(t, nameB, os.O_RDONLY, 0)
	defer reader.Close()
	if got := readExactlyAt(t, reader, 0, size, "pre-revocation read"); !bytes.Equal(got, payload) {
		t.Fatal("pre-revocation read returned the wrong bytes")
	}

	// The pages are now resident on mount B. Losing the authority is what fences
	// it: it can no longer be told that what it holds has changed, so it revokes
	// itself. Then read through the descriptor that is already open -- the exact
	// case the mount-namespace detach cannot reach.
	f.stopAuthority()
	for i := range 2 {
		t.Logf("mount %d terminal cause: %v", i, f.requireSessionEnded(i, 30*time.Second))
	}

	outcome := make(chan error, 1)
	buf := make([]byte, size)
	go func() {
		_, err := reader.ReadAt(buf, 0)
		outcome <- err
	}()
	select {
	case err := <-outcome:
		if err == nil {
			t.Fatal("a fenced mount served its retained pages; this is the stale-read window the withdrawal pass exists to close")
		}
		// ENOTCONN from the aborted connection, or EIO from a refaulted page
		// that cannot be filled. Which one depends on where in the teardown the
		// read landed; pinning that would pin a race rather than a contract.
		// What must never happen is a successful read.
		t.Logf("fenced-mount read failed as required: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("a read of retained pages on a fenced mount hung")
	}
	if bytes.Equal(buf, payload) {
		t.Fatal("the fenced read filled the caller's buffer with pre-fence bytes even though it reported an error")
	}
}
