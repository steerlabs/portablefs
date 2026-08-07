//go:build linux

package xfsstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func readDirAll(t *testing.T, v *Volume, handle Capability, page int) []Dirent {
	t.Helper()
	var all []Dirent
	cookie := uint64(0)
	var verifier [16]byte
	for {
		entries, next, current, eof, _, err := v.ReadDirOpen(handle, cookie, verifier, page)
		if err != nil {
			t.Fatalf("ReadDirOpen(cookie=%d): %v", cookie, err)
		}
		all = append(all, entries...)
		cookie, verifier = next, current
		if eof {
			return all
		}
	}
}

// TestReadDirSurvivesConcurrentUnlink is failure A of the readdir defect: a
// second client removing one entry between getdents and the per-entry stat
// aborted the whole page with that entry's ENOENT, so an ls of a busy
// directory failed outright. A local ls never does that.
func TestReadDirSurvivesConcurrentUnlink(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	const total = 200
	for i := range total {
		if _, _, err := v.Create(root, fmt.Sprintf("entry-%03d", i), 0o600, true); err != nil {
			t.Fatal(err)
		}
	}
	handle := mustOpenDir(t, v, root)

	// Every call below starts a fresh enumeration, so none of them can be
	// answered with a staleness error: a first page is always readable. What
	// used to break it is that entries removed between getdents and the
	// per-entry stat returned ENOENT, and one such entry failed the page.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for i := range total {
			if err := v.Unlink(root, fmt.Sprintf("entry-%03d", i), false); err != nil {
				t.Errorf("Unlink: %v", err)
				return
			}
		}
	}()
	pages, failure := 0, error(nil)
	for failure == nil {
		entries, _, _, _, _, err := v.ReadDirOpen(handle, 0, [16]byte{}, total)
		if err != nil {
			failure = err
			break
		}
		for _, entry := range entries {
			if entry.Kind != KindRegular || entry.Ino == 0 {
				failure = fmt.Errorf("entry %q listed as kind %d ino %d", entry.Name, entry.Kind, entry.Ino)
				break
			}
		}
		pages++
		select {
		case <-done:
			wg.Wait()
			if pages < 2 {
				t.Fatal("the unlink loop finished before two pages were read")
			}
			if entries, _, _, _, _, err := v.ReadDirOpen(handle, 0, [16]byte{}, total); err != nil || len(entries) != 0 {
				t.Fatalf("emptied directory = %d entries, %v", len(entries), err)
			}
			return
		default:
		}
	}
	<-done
	wg.Wait()
	t.Fatalf("first page during a concurrent unlink: %v", failure)
}

// TestReadDirListsForbiddenInodeTypes is failure B: one FIFO or device node in
// the tree - a restored backup, anything not creatable through this API - made
// the entire directory permanently unreadable, and as EIO at that.
func TestReadDirListsForbiddenInodeTypes(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	if _, _, err := v.Create(root, "regular", 0o600, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Mkdir(root, "directory", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Symlink(root, "link", "regular"); err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	rootFD := v.objects[root].res.fd
	v.mu.RUnlock()
	if err := unix.Mkfifoat(rootFD, "fifo", 0o600); err != nil {
		t.Fatalf("place a FIFO in the tree: %v", err)
	}

	handle := mustOpenDir(t, v, root)
	kinds := make(map[string]Kind)
	for _, entry := range readDirAll(t, v, handle, 2) {
		kinds[entry.Name] = entry.Kind
		if entry.Ino == 0 {
			t.Errorf("entry %q has no inode number", entry.Name)
		}
	}
	want := map[string]Kind{
		"regular": KindRegular, "directory": KindDirectory,
		"link": KindSymlink, "fifo": KindOpaque,
	}
	for name, kind := range want {
		if kinds[name] != kind {
			t.Errorf("entry %q kind = %d, want %d", name, kinds[name], kind)
		}
	}
	// The entry is listed; the inode is still never exposed.
	if _, _, err := v.Lookup(root, "fifo"); !errors.Is(err, ErrForbiddenType) {
		t.Fatalf("Lookup(fifo) = %v, want ErrForbiddenType", err)
	}
	if _, err := v.StatOpenDirChild(handle, "fifo"); !errors.Is(err, ErrForbiddenType) {
		t.Fatalf("StatOpenDirChild(fifo) = %v, want ErrForbiddenType", err)
	}
}

// TestReadDirRefusesResumeWithoutVerifier is the bypass: a client that simply
// omitted the verifier field got zero staleness checking and a silently wrong
// page. An omitted verifier is now a refused request, not a weaker one.
func TestReadDirRefusesResumeWithoutVerifier(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	for i := range 20 {
		if _, _, err := v.Create(root, fmt.Sprintf("f%02d", i), 0o600, true); err != nil {
			t.Fatal(err)
		}
	}
	handle := mustOpenDir(t, v, root)
	_, cookie, verifier, _, _, err := v.ReadDirOpen(handle, 0, [16]byte{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := v.ReadDirOpen(handle, cookie, [16]byte{}, 5); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("resume with an omitted verifier = %v, want a refused request", err)
	}
	var wrong [16]byte
	wrong[0] = verifier[0] ^ 0xff
	if _, _, _, _, _, err := v.ReadDirOpen(handle, cookie, wrong, 5); !errors.Is(err, syscall.ESTALE) {
		t.Fatalf("resume with a wrong verifier = %v, want ESTALE", err)
	}
	if _, _, _, _, _, err := v.ReadDirOpen(handle, cookie, verifier, 5); err != nil {
		t.Fatalf("resume with the issued verifier: %v", err)
	}
	// Starting over needs no verifier, and a stale one presented there is
	// still an assertion that must fail.
	if _, _, _, _, _, err := v.ReadDirOpen(handle, 0, [16]byte{}, 5); err != nil {
		t.Fatalf("fresh enumeration: %v", err)
	}
	if _, _, _, _, _, err := v.ReadDirOpen(handle, 0, wrong, 5); !errors.Is(err, syscall.ESTALE) {
		t.Fatalf("fresh enumeration with a wrong verifier = %v, want ESTALE", err)
	}
}

// TestReadDirResumesDeepCookieExactly covers repositioning past the
// checkpoint stride: resuming used to re-read every entry before the cookie,
// which is quadratic over a full enumeration.
func TestReadDirResumesDeepCookieExactly(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	const total = checkpointStride*2 + 37
	for i := range total {
		if _, _, err := v.Create(root, fmt.Sprintf("e%05d", i), 0o600, true); err != nil {
			t.Fatal(err)
		}
	}
	handle := mustOpenDir(t, v, root)
	all := readDirAll(t, v, handle, 4096)
	if len(all) != total {
		t.Fatalf("enumerated %d entries, want %d", len(all), total)
	}
	_, _, verifier, _, _, err := v.ReadDirOpen(handle, 0, [16]byte{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range []uint64{1, checkpointStride - 1, checkpointStride,
		checkpointStride + 1, 2 * checkpointStride, total - 1} {
		page, next, _, _, _, err := v.ReadDirOpen(handle, cookie, verifier, 3)
		if err != nil {
			t.Fatalf("resume at %d: %v", cookie, err)
		}
		if len(page) == 0 || page[0].Name != all[cookie].Name {
			t.Fatalf("resume at %d began with %v, want %q", cookie, page, all[cookie].Name)
		}
		if next != cookie+uint64(len(page)) {
			t.Fatalf("resume at %d issued next cookie %d for %d entries", cookie, next, len(page))
		}
	}
	if _, _, _, _, _, err := v.ReadDirOpen(handle, total+1, verifier, 3); !errors.Is(err, syscall.ESTALE) {
		t.Fatalf("resume past the end = %v, want ESTALE", err)
	}
}

// TestReadDirParentIsNeverAStaleCapability: the handle's object capability can
// be forgotten while the handle stays usable, and returning it afterwards
// hands the caller a reference that is guaranteed to fail.
func TestReadDirParentIsNeverAStaleCapability(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Mkdir(root, "sub", 0o700)
	if err != nil {
		t.Fatal(err)
	}
	handle := mustOpenDir(t, v, item)
	if _, _, _, _, parent, err := v.ReadDirOpen(handle, 0, [16]byte{}, 4); err != nil || parent != item {
		t.Fatalf("parent = %v, %v, want the directory capability", parent, err)
	}
	if err := v.Forget(item); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, parent, err := v.ReadDirOpen(handle, 0, [16]byte{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if parent != (Capability{}) {
		t.Fatalf("parent = %v after Forget, want the zero capability", parent)
	}
}

// TestFenceIsNotQueuedBehindInFlightIO pins the liveness property that the
// single volume lock destroyed: Fence is the emergency stop that keeps a
// detached filesystem from acknowledging work, and it used to wait for the
// slow read it is meant to interrupt - and every later request waited behind
// Fence, because Go's RWMutex hands the lock to a queued writer first.
func TestFenceIsNotQueuedBehindInFlightIO(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "big", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	const size = 512 << 20
	if err := v.Truncate(handle, size); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	order := make(chan string, 2)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, size)
		close(started)
		// An operation that already resolved its handle runs to completion:
		// fencing stops new work, it does not corrupt work in flight.
		if _, err := v.ReadAt(handle, buf, 0); err != nil {
			t.Errorf("in-flight read: %v", err)
		}
		order <- "read"
	}()
	<-started
	time.Sleep(20 * time.Millisecond)
	v.Fence(syscall.EIO)
	order <- "fence"
	wg.Wait()
	if first := <-order; first != "fence" {
		t.Fatal("Fence completed only after the in-flight read finished: the " +
			"emergency stop is queued behind the work it stops")
	}
	if !errors.Is(v.Health(), ErrFenced) {
		t.Fatalf("Health = %v", v.Health())
	}
}

// TestInFlightIOSurvivesConcurrentClose is the other half of dropping the
// lock: descriptors are reference-counted, so an operation already using one
// can never be handed a descriptor number that Close returned to the kernel
// and that something else has since reused.
func TestInFlightIOSurvivesConcurrentClose(t *testing.T) {
	v, err := open(t.TempDir(), false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := v.Root()
	item, _, err := v.Create(root, "data", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("portablefs")
	if _, err := v.WriteAt(handle, payload, 0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, len(payload))
			for range 500 {
				n, err := v.ReadAt(handle, buf, 0)
				switch {
				case err == nil:
					if n != len(payload) || string(buf) != string(payload) {
						t.Errorf("read %q (%d bytes) from a closing volume", buf[:n], n)
						return
					}
				case errors.Is(err, ErrClosed), errors.Is(err, ErrStaleOpen):
					return
				default:
					t.Errorf("read during close = %v", err)
					return
				}
			}
		}()
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
}

func openDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// volumeWorkload exercises every descriptor-producing path once.
func volumeWorkload(t *testing.T) {
	t.Helper()
	v, err := open(t.TempDir(), false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := v.Root()
	if err != nil {
		t.Fatal(err)
	}
	dir, _, err := v.Mkdir(root, "d", 0o700)
	if err != nil {
		t.Fatal(err)
	}
	item, _, err := v.Create(dir, "f", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Link(item, dir, "g"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Symlink(dir, "s", "f"); err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.WriteAt(handle, []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	if err := v.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}
	if err := v.TruncateObject(item, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.SyncObject(item); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ListXattr(item); err != nil {
		t.Fatal(err)
	}
	dirHandle, err := v.OpenFile(dir, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := v.ReadDirOpen(dirHandle, 0, [16]byte{}, 16); err != nil {
		t.Fatal(err)
	}
	looked, _, err := v.Lookup(dir, "g")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Forget(looked); err != nil {
		t.Fatal(err)
	}
	// Close deliberately leaves one open handle and several capabilities
	// outstanding: releasing them is its job, not the caller's.
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestDescriptorsAreNeverLeakedOrDoubleClosed is the accounting guarantee that
// reference counting has to pay for. A leak exhausts the worker's descriptor
// budget; a double close hands a live descriptor number back to the kernel and
// the next open in the process silently inherits it.
func TestDescriptorsAreNeverLeakedOrDoubleClosed(t *testing.T) {
	for range 2 {
		volumeWorkload(t)
	}
	before := openDescriptorCount(t)
	for range 5 {
		volumeWorkload(t)
	}
	if after := openDescriptorCount(t); after > before {
		t.Fatalf("open descriptors grew from %d to %d across five volume lifetimes", before, after)
	}
}
