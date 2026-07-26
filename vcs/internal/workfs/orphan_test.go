package workfs

import (
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// P2 (orphan table): a file unlinked while still open is detached from the name tree but PARKED by its
// stable ino, so an open handle keeps reading/writing it until the last close (delete-on-last-close /
// open-after-unlink). These tests pin that contract at the authority data-model level.

func newOrphanFS(t *testing.T) (*FS, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := wal.Open(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	return fs, dir
}

// reopenOrphanFS reconstructs an FS from the WAL on disk — the authority-restart path. Born-file
// content lives in the replayed OpWrite records, so a fresh (empty) blob store is fine.
func reopenOrphanFS(t *testing.T, dir string) *FS {
	t.Helper()
	w, err := wal.Open(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func readOrphan(t *testing.T, fs *FS, ino uint64, size int) []byte {
	t.Helper()
	buf := make([]byte, size)
	n, err := fs.ReadOrphanAt(ino, buf, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadOrphanAt(%d): %v", ino, err)
	}
	return buf[:n]
}

// Unlink-while-open: the name is gone, but the bytes survive and are addressable by ino.
func TestOrphanReadByInoAfterUnlink(t *testing.T) {
	fs, _ := newOrphanFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "f", Offset: 0, Data: []byte("hello")},
	)
	pre := inoAt(t, fs, "f")
	ino, err := fs.Orphan("f", "")
	if err != nil {
		t.Fatalf("Orphan: %v", err)
	}
	if ino != pre {
		t.Fatalf("orphan ino %d != pre-unlink ino %d (identity must be preserved)", ino, pre)
	}
	if fs.resolve("f") != nil {
		t.Fatal("name still resolves after orphan (must be detached from the tree)")
	}
	if got := readOrphan(t, fs, ino, 5); string(got) != "hello" {
		t.Fatalf("orphan read = %q, want %q", got, "hello")
	}
}

// Open-vs-unlink registration race — the UNLINK wins: an OpRemove destroys the inode BEFORE a mount
// registers its open, so MarkOpenInode must report the inode is gone. The mount then fails the open
// with ENOENT rather than holding a handle to a destroyed inode (a broken fd).
func TestMarkOpenLosesRaceToUnlink(t *testing.T) {
	fs, _ := newOrphanFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	ino := inoAt(t, fs, "f")
	apply(t, fs, wal.Record{Op: wal.OpRemove, Path: "f"}) // not open -> destroyed
	if fs.MarkOpenInode(ino, "A") {
		t.Fatal("MarkOpenInode on a removed inode must return false (the open lost the race to unlink)")
	}
}

// Open-vs-unlink registration race — the OPEN wins: MarkOpenInode registers the hold BEFORE the
// OpRemove lands, so the remove must PARK the inode (delete-on-last-close) instead of destroying it,
// and the registered open's fd survives. Both run under one fs.mu, so these orderings are the only
// outcomes — never a destroyed-yet-held inode.
func TestMarkOpenBeatsUnlinkParks(t *testing.T) {
	fs, _ := newOrphanFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	ino := inoAt(t, fs, "f")
	if !fs.MarkOpenInode(ino, "A") {
		t.Fatal("MarkOpenInode on a live inode must return true")
	}
	apply(t, fs, wal.Record{Op: wal.OpRemove, Path: "f"}) // A holds it open -> must park, not destroy
	if fs.resolve("f") != nil {
		t.Fatal("name f must be detached after the remove")
	}
	fs.mu.Lock()
	_, parked := fs.byIno[ino]
	fs.mu.Unlock()
	if !parked {
		t.Fatal("the inode must be PARKED (still in byIno), not destroyed, because A holds it open")
	}
}

// Writing to an unlinked-but-open file (the temp-file pattern: create, unlink, write, read).
func TestOrphanWriteThenReadByIno(t *testing.T) {
	fs, _ := newOrphanFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "tmp", Mode: 0o600},
		wal.Record{Op: wal.OpWrite, Path: "tmp", Offset: 0, Data: []byte("hello")},
	)
	ino, err := fs.Orphan("tmp", "")
	if err != nil {
		t.Fatalf("Orphan: %v", err)
	}
	// Overwrite [0,5) and extend with [5,8).
	if _, _, err := fs.WriteOrphanAt(ino, 0, []byte("WORLD"), ""); err != nil {
		t.Fatalf("WriteOrphanAt overwrite: %v", err)
	}
	if _, _, err := fs.WriteOrphanAt(ino, 5, []byte("!!!"), ""); err != nil {
		t.Fatalf("WriteOrphanAt extend: %v", err)
	}
	if got := readOrphan(t, fs, ino, 8); string(got) != "WORLD!!!" {
		t.Fatalf("orphan read-after-write = %q, want %q", got, "WORLD!!!")
	}
}

func TestConcurrentAppendToOrphanUsesDistinctOrderedRanges(t *testing.T) {
	fs, _ := newOrphanFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "tmp", Mode: 0o600},
		wal.Record{Op: wal.OpWrite, Path: "tmp", Data: []byte("base")},
	)
	ino, err := fs.Orphan("tmp", "")
	if err != nil {
		t.Fatal(err)
	}
	const writers = 64
	offsets := make(chan int64, writers)
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			record := []byte{byte(i), 0xA5}
			n, off, _, err := fs.AppendOrphanAs(ino, record, "M")
			if err != nil {
				errs <- err
				return
			}
			if n != len(record) {
				errs <- io.ErrShortWrite
				return
			}
			offsets <- off
		}()
	}
	wg.Wait()
	close(errs)
	close(offsets)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	for off := range offsets {
		if off < 4 || (off-4)%2 != 0 || seen[off] {
			t.Fatalf("invalid/duplicate append offset %d", off)
		}
		seen[off] = true
	}
	if len(seen) != writers {
		t.Fatalf("offset count=%d, want %d", len(seen), writers)
	}
	data := readOrphan(t, fs, ino, 4+writers*2)
	if len(data) != 4+writers*2 || string(data[:4]) != "base" {
		t.Fatalf("orphan append length/prefix: len=%d prefix=%q", len(data), data[:min(len(data), 4)])
	}
}

// Last close reaps the orphan: its ino stops resolving and the table is empty.
func TestOrphanReapFreesIt(t *testing.T) {
	fs, _ := newOrphanFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	ino, err := fs.Orphan("f", "")
	if err != nil {
		t.Fatalf("Orphan: %v", err)
	}
	if err := fs.Reap(ino, ""); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if _, err := fs.ReadOrphanAt(ino, make([]byte, 1), 0); err == nil {
		t.Fatal("read of a reaped orphan must fail (ErrNotExist)")
	}
	fs.mu.RLock()
	left := len(fs.orphans)
	fs.mu.RUnlock()
	if left != 0 {
		t.Fatalf("orphan table not empty after reap: %d", left)
	}
}

// Open-after-unlink + recreate at the same name: the orphan keeps the OLD content under its ino while
// a freshly created file at the same path gets a NEW ino and its own content. No aliasing — both are
// independently readable. This is the exact POSIX semantic that path-addressed st_ino got wrong.
func TestOrphanAndRecreatedNameAreDistinct(t *testing.T) {
	fs, _ := newOrphanFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "f", Offset: 0, Data: []byte("AAAAA")},
	)
	orphIno, err := fs.Orphan("f", "")
	if err != nil {
		t.Fatalf("Orphan: %v", err)
	}
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "f", Offset: 0, Data: []byte("BBBBB")},
	)
	newIno := inoAt(t, fs, "f")
	if newIno == orphIno {
		t.Fatalf("recreated file reused the orphan's ino %d (aliasing)", orphIno)
	}
	if got := readOrphan(t, fs, orphIno, 5); string(got) != "AAAAA" {
		t.Fatalf("orphan content = %q, want %q (must be unchanged by the recreate)", got, "AAAAA")
	}
	nb := fs.resolve("f")
	rbuf := make([]byte, 5)
	rn, _ := fs.readAt(nb, rbuf, 0)
	if string(rbuf[:rn]) != "BBBBB" {
		t.Fatalf("recreated file content = %q, want %q", rbuf[:rn], "BBBBB")
	}
}

// A handle-addressed write after unlink + same-name recreate must target the old inode by I1, not
// the new inode now named "f". Path is still carried for invalidation, but ino is authoritative.
func TestInoAddressedWriteAfterUnlinkRecreateTargetsOldOrphan(t *testing.T) {
	fs, _ := newOrphanFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "f", Offset: 0, Data: []byte("old-one")},
	)
	i1 := inoAt(t, fs, "f")
	orphIno, err := fs.Orphan("f", "")
	if err != nil {
		t.Fatalf("Orphan: %v", err)
	}
	if orphIno != i1 {
		t.Fatalf("orphan ino = %d, want original ino %d", orphIno, i1)
	}
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "f", Offset: 0, Data: []byte("new-two")},
	)
	i2 := inoAt(t, fs, "f")
	if i2 == i1 {
		t.Fatalf("recreated name reused old ino %d", i1)
	}

	if _, _, err := fs.WriteAtHandleExistingAs("f", i1, 0, []byte("old-fd!"), ""); err != nil {
		t.Fatalf("handle write by old ino: %v", err)
	}
	if got := readOrphan(t, fs, i1, len("old-fd!")); string(got) != "old-fd!" {
		t.Fatalf("old inode content = %q, want old-fd!", got)
	}
	if got := readFile(t, fs, "f"); got != "new-two" {
		t.Fatalf("recreated name content = %q, want new-two", got)
	}
}

// Open-after-unlink must survive an authority restart: the orphan (and its content) is reconstructed
// from the WAL with the SAME ino, deterministically.
func TestOrphanSurvivesWALReplay(t *testing.T) {
	fs, dir := newOrphanFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "f", Offset: 0, Data: []byte("persist")},
	)
	ino, err := fs.Orphan("f", "")
	if err != nil {
		t.Fatalf("Orphan: %v", err)
	}

	fs2 := reopenOrphanFS(t, dir) // authority restart: replay the WAL
	if fs2.resolve("f") != nil {
		t.Fatal("orphaned name reappeared in the tree after replay")
	}
	if got := readOrphan(t, fs2, ino, 7); string(got) != "persist" {
		t.Fatalf("orphan content after replay = %q, want %q (same ino %d)", got, "persist", ino)
	}
}

func withOrphanLeaseTiming(t *testing.T, ttl, sweep time.Duration) {
	t.Helper()
	oldTTL, oldSweep := OrphanLeaseTTL, OrphanSweepInterval
	OrphanLeaseTTL, OrphanSweepInterval = ttl, sweep
	t.Cleanup(func() {
		OrphanLeaseTTL, OrphanSweepInterval = oldTTL, oldSweep
	})
}

func TestOrphanLeaseExpiryReapsWithoutRenewal(t *testing.T) {
	withOrphanLeaseTiming(t, time.Minute, time.Millisecond)
	fs, _ := newOrphanFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	ino, err := fs.Orphan("f", "mountA")
	if err != nil {
		t.Fatal(err)
	}

	fs.mu.Lock()
	fs.orphanLeases[ino] = time.Now().Add(-time.Second)
	fs.mu.Unlock()

	if got := fs.SweepExpiredOrphans(time.Now()); got != 1 {
		t.Fatalf("swept %d expired orphans, want 1", got)
	}
	if _, err := fs.ReadOrphanAt(ino, make([]byte, 1), 0); err == nil {
		t.Fatal("expired orphan still readable")
	}
}

func TestOrphanLeaseRenewalKeepsOrphan(t *testing.T) {
	withOrphanLeaseTiming(t, time.Minute, time.Millisecond)
	fs, _ := newOrphanFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	ino, err := fs.Orphan("f", "mountA")
	if err != nil {
		t.Fatal(err)
	}

	fs.mu.Lock()
	fs.orphanLeases[ino] = time.Now().Add(-time.Second)
	fs.mu.Unlock()

	if got := fs.RenewOrphanLeases([]uint64{ino}); got != 1 {
		t.Fatalf("renewed %d leases, want 1", got)
	}
	if got := fs.SweepExpiredOrphans(time.Now()); got != 0 {
		t.Fatalf("renewed orphan was swept: %d", got)
	}
	if _, err := fs.ReadOrphanAt(ino, make([]byte, 1), 0); err != nil && err != io.EOF {
		t.Fatalf("renewed orphan not readable: %v", err)
	}
}

func TestSameOwnerRestartOldOrphanReapedByLease(t *testing.T) {
	withOrphanLeaseTiming(t, time.Minute, time.Millisecond)
	fs, _ := newOrphanFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "old", Mode: 0o644})
	ino, err := fs.Orphan("old", "stable-owner")
	if err != nil {
		t.Fatal(err)
	}

	// A restarted mount may reuse the same owner string, but it has an empty open-orphan set and
	// therefore does not renew the old crashed process's ino.
	fs.RenewOrphanLeases(nil)
	fs.mu.Lock()
	fs.orphanLeases[ino] = time.Now().Add(-time.Second)
	fs.mu.Unlock()

	if got := fs.SweepExpiredOrphans(time.Now()); got != 1 {
		t.Fatalf("swept %d expired orphans, want 1", got)
	}
	if _, err := fs.ReadOrphanAt(ino, make([]byte, 1), 0); err == nil {
		t.Fatal("same-owner restarted mount kept an old unknown orphan alive")
	}
}

// Rename-over-an-open-file (B5): `rename(src, dst)` with dst open PARKS the old dst by ino (keeping
// its bytes for its open fds) while dst's name now resolves to the moved src inode.
func TestRenameOverOpenParksDestinationByIno(t *testing.T) {
	fs, _ := newOrphanFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "src", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "src", Data: []byte("source")},
		wal.Record{Op: wal.OpCreate, Path: "dst", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "dst", Data: []byte("dest")},
	)
	srcIno := inoAt(t, fs, "src")
	dstIno := inoAt(t, fs, "dst")

	parked, err := fs.RenameWithOrphanTarget("src", "dst", true, "mountA")
	if err != nil {
		t.Fatalf("RenameWithOrphanTarget: %v", err)
	}
	if parked != dstIno {
		t.Fatalf("parked ino = %d, want old dst ino %d", parked, dstIno)
	}
	if fs.resolve("src") != nil {
		t.Fatal("source name still resolves after rename")
	}
	if got := inoAt(t, fs, "dst"); got != srcIno {
		t.Fatalf("dst ino after rename = %d, want moved src ino %d", got, srcIno)
	}
	if got := readFile(t, fs, "dst"); got != "source" {
		t.Fatalf("new dst content = %q, want source", got)
	}
	if got := readOrphan(t, fs, parked, len("dest")); string(got) != "dest" {
		t.Fatalf("parked old dst content = %q, want dest", got)
	}
}

// The rename-over-open park survives an authority restart deterministically (OrphanTarget is on the
// WAL rename record; the dest is still present at NewPath at replay time, so the same ino is parked).
func TestRenameOverOpenOrphanReplaysDeterministically(t *testing.T) {
	fs, dir := newOrphanFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "src", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "src", Data: []byte("source")},
		wal.Record{Op: wal.OpCreate, Path: "dst", Mode: 0o644},
		wal.Record{Op: wal.OpWrite, Path: "dst", Data: []byte("dest")},
	)
	srcIno := inoAt(t, fs, "src")
	dstIno := inoAt(t, fs, "dst")

	parked, err := fs.RenameWithOrphanTarget("src", "dst", true, "mountA")
	if err != nil {
		t.Fatalf("RenameWithOrphanTarget: %v", err)
	}
	if parked != dstIno {
		t.Fatalf("parked ino = %d, want %d", parked, dstIno)
	}

	fs2 := reopenOrphanFS(t, dir)
	if fs2.resolve("src") != nil {
		t.Fatal("source name reappeared after replay")
	}
	if got := inoAt(t, fs2, "dst"); got != srcIno {
		t.Fatalf("dst ino after replay = %d, want moved src ino %d", got, srcIno)
	}
	if got := readFile(t, fs2, "dst"); got != "source" {
		t.Fatalf("new dst content after replay = %q, want source", got)
	}
	if got := readOrphan(t, fs2, parked, len("dest")); string(got) != "dest" {
		t.Fatalf("parked old dst content after replay = %q, want dest", got)
	}
}

// A reap that committed before a restart stays reaped after replay (OpReap is replayed).
func TestOrphanReapSurvivesWALReplay(t *testing.T) {
	fs, dir := newOrphanFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	ino, err := fs.Orphan("f", "")
	if err != nil {
		t.Fatalf("Orphan: %v", err)
	}
	if err := fs.Reap(ino, ""); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	fs2 := reopenOrphanFS(t, dir)
	if _, err := fs2.ReadOrphanAt(ino, make([]byte, 1), 0); err == nil {
		t.Fatal("a reaped orphan must not be resurrected by replay")
	}
}
