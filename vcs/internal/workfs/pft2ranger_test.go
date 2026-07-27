package workfs

// Ranger integrity, pack-fetch amplification, and budget-contract coverage:
// each unique immutable pack is fetched at most once per operation and once
// across warm operations (shared bounded verified cache with singleflight),
// every served cell re-verifies its logical digest and terminal-zero tail,
// and dense maximal windows provably fit the reader's default per-op node
// budget at any format-legal tree depth.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// densePayload builds size bytes with no all-zero 4 KiB cell, so every cell
// of the built file is present (a dense extent range).
func densePayload(size int) []byte {
	payload := bytes.Repeat([]byte{0xAB}, size)
	for i := 0; i < size; i += 64 {
		payload[i] = byte(1 + i%251)
	}
	return payload
}

// uniquePackRefs enumerates the DISTINCT pack objects backing a file's whole
// extent range, straight from the verified reader.
func uniquePackRefs(t *testing.T, fs *FS, path string) map[pft2.Ref]struct{} {
	t.Helper()
	fs.mu.RLock()
	n := fs.resolve(path)
	fs.mu.RUnlock()
	if n == nil || n.source.Ranger == nil {
		t.Fatalf("%s is not a lazily backed file", path)
	}
	ranger := n.source.Ranger.(*pft2FileRanger)
	packs := map[pft2.Ref]struct{}{}
	for off := int64(0); off < ranger.size; off += pft2RangerWindowBytes {
		extents, err := ranger.lz.reader.ReadExtents(context.Background(), ranger.file, uint64(off), uint64(pft2RangerWindowBytes))
		if err != nil {
			t.Fatalf("enumerate extents: %v", err)
		}
		for i := range extents {
			packs[extents[i].Cell.Object] = struct{}{}
		}
	}
	return packs
}

func TestRangerFetchesEachPackOnceColdAndNeverWarm(t *testing.T) {
	payload := densePayload(4 << 20) // exactly one 4 MiB block: up to 1024 cells in one pack
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "dense.bin", Mode: 0o644},
		{Op: wal.OpWrite, Path: "dense.bin", Data: payload},
	})
	fs, _ := newLazyFS(t, base, newFakeEntryLog())
	if _, err := fs.Lstat("dense.bin"); err != nil { // hydrate the name
		t.Fatal(err)
	}

	unique := uniquePackRefs(t, fs, "dense.bin")
	if len(unique) == 0 || len(unique) > 2 {
		t.Fatalf("dense 4 MiB file spans %d packs; the amplification fixture expects ~1", len(unique))
	}
	if fetched := fs.pft2.packs.fetchCount(); fetched != 0 {
		t.Fatalf("extent enumeration fetched %d packs (enumeration must not fetch data)", fetched)
	}

	if got := lazyReadFile(t, fs, "dense.bin"); got != string(payload) {
		t.Fatalf("dense read diverged (%d bytes)", len(got))
	}
	if cold := fs.pft2.packs.fetchCount(); cold != uint64(len(unique)) {
		t.Fatalf("cold dense read fetched %d packs, want exactly the %d unique packs (per-cell refetch amplification)", cold, len(unique))
	}
	// Warm: the shared verified cache serves every pack; zero new fetches.
	before := fs.pft2.packs.fetchCount()
	if got := lazyReadFile(t, fs, "dense.bin"); got != string(payload) {
		t.Fatal("warm dense read diverged")
	}
	if delta := fs.pft2.packs.fetchCount() - before; delta != 0 {
		t.Fatalf("warm dense read fetched %d packs, want 0", delta)
	}
}

func TestRangerConcurrentReadersCoalesceAndEvictionStaysBounded(t *testing.T) {
	payload := densePayload(4 << 20)
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "dense.bin", Mode: 0o644},
		{Op: wal.OpWrite, Path: "dense.bin", Data: payload},
	})
	fs, fetcher := newLazyFS(t, base, newFakeEntryLog())
	if _, err := fs.Lstat("dense.bin"); err != nil { // hydrate the name once
		t.Fatal(err)
	}
	unique := uniquePackRefs(t, fs, "dense.bin")
	baseline := fs.pft2.packs.fetchCount()

	fetcher.setDelay(200 * time.Microsecond) // widens the coalescing window
	var wg sync.WaitGroup
	readErrs := make([]error, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			buf := make([]byte, len(payload))
			n, err := fs.ReadHandleAt("dense.bin", 0, buf, 0)
			if err != nil && err != io.EOF {
				readErrs[g] = err
				return
			}
			if n != len(payload) || !bytes.Equal(buf[:n], payload) {
				readErrs[g] = fmt.Errorf("reader %d saw %d bytes", g, n)
			}
		}(g)
	}
	wg.Wait()
	fetcher.setDelay(0)
	for g, err := range readErrs {
		if err != nil {
			t.Fatalf("concurrent reader %d: %v", g, err)
		}
	}
	if delta := fs.pft2.packs.fetchCount() - baseline; delta != uint64(len(unique)) {
		t.Fatalf("8 concurrent cold readers fetched %d packs, want the coalesced %d", delta, len(unique))
	}
	if resident := fs.pft2.packs.residentBytes(); resident > pft2PackCacheBytes {
		t.Fatalf("resident pack bytes %d exceed the %d bound", resident, pft2PackCacheBytes)
	}

	// Shrink the budget below one pack: entries are served but never
	// retained, the OPERATION-scoped dedup still bounds one full-range read
	// to one fetch per unique pack, and residency stays inside the bound.
	fs.pft2.packs.setMaxBytes(1 << 20)
	if resident := fs.pft2.packs.residentBytes(); resident > 1<<20 {
		t.Fatalf("shrunken cache retains %d bytes", resident)
	}
	beforeOp := fs.pft2.packs.fetchCount()
	buf := make([]byte, len(payload))
	if n, err := fs.ReadHandleAt("dense.bin", 0, buf, 0); (err != nil && err != io.EOF) || n != len(payload) || !bytes.Equal(buf, payload) {
		t.Fatalf("read after cache shrink diverged: n=%d err=%v", n, err)
	}
	perOp := fs.pft2.packs.fetchCount() - beforeOp
	if perOp != uint64(len(unique)) {
		t.Fatalf("uncacheable full-range read fetched %d packs, want once per unique pack (%d) per operation", perOp, len(unique))
	}
	if resident := fs.pft2.packs.residentBytes(); resident > 1<<20 {
		t.Fatalf("oversized pack was retained: %d resident bytes", resident)
	}
}

func TestRangerDenseWindowsFitDefaultReaderBudget(t *testing.T) {
	// The explicit budget contract behind pft2RangerWindowBytes: a maximal
	// window's worst-case verified traversal must sit strictly below the
	// reader's DEFAULT 64-node per-operation budget at ANY legal depth.
	windowPages := pft2RangerWindowBytes / int64(pft2.PageBytes)
	worst := int64(1) + int64(pft2.MaxTreeDepth) + (2*windowPages - 1) + windowPages
	if worst >= 64 {
		t.Fatalf("window of %d pages costs up to %d nodes; the default 64-node budget no longer holds", windowPages, worst)
	}

	// Dense exactly-4 MiB and greater-than-4 MiB reads must never trip
	// ErrBoundExceeded: 6 MiB crosses block, window, and pack boundaries.
	payload := densePayload(6 << 20)
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "big.bin", Mode: 0o644},
		{Op: wal.OpWrite, Path: "big.bin", Data: payload},
	})
	fs, _ := newLazyFS(t, base, newFakeEntryLog())
	if got := lazyReadFile(t, fs, "big.bin"); got != string(payload) {
		t.Fatalf("6 MiB dense read diverged (%d bytes)", len(got))
	}

	// One direct Ranger call spanning the WHOLE 6 MiB (larger than any
	// single block read the billy layer issues) walks multiple windows.
	fs.mu.RLock()
	n := fs.resolve("big.bin")
	fs.mu.RUnlock()
	buf := make([]byte, len(payload))
	read, err := n.source.Ranger.ReadRangeAt(context.Background(), buf, 0)
	if err != nil {
		t.Fatalf("direct 6 MiB ranger read: %v", err)
	}
	if read != len(payload) || !bytes.Equal(buf, payload) {
		t.Fatalf("direct ranger read returned %d bytes", read)
	}
}

func TestRangerPartialWriteOverDenseBase(t *testing.T) {
	payload := densePayload(4 << 20)
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "dense.bin", Mode: 0o644},
		{Op: wal.OpWrite, Path: "dense.bin", Data: payload},
	})
	log := newFakeEntryLog()
	fs, _ := newLazyFS(t, base, log)

	// A 2-byte overwrite forces the 4 MiB read-modify-write materialization
	// (warm outside fs.mu, apply from the warmed cache). Before the window
	// fix this deterministically failed with ErrBoundExceeded.
	commitTree(t, fs, wal.Record{Op: wal.OpWrite, Path: "dense.bin", Offset: 1, Data: []byte("XY")})
	want := append([]byte(nil), payload...)
	copy(want[1:], []byte("XY"))
	if got := lazyReadFile(t, fs, "dense.bin"); got != string(want) {
		t.Fatal("partial write over dense base diverged")
	}
	// Cold replay reproduces the same merged content.
	fs2, _ := newLazyFS(t, base, log)
	if got := lazyReadFile(t, fs2, "dense.bin"); got != string(want) {
		t.Fatal("replayed partial write over dense base diverged")
	}
}

// buildCraftedCellBase hand-crafts a fully verified PFT2 filesystem whose
// OBJECT digests are all exact while the CELL layer lies:
//
//	"bad-digest": the page advertises a cell digest that does not match the
//	              pack's actual cell bytes;
//	"bad-tail":   the cell digest is exact, but bytes beyond the file's
//	              logical EOF (size 100) are nonzero.
//
// Only per-cell verification (pft2.VerifyCellBytes) can reject either.
func buildCraftedCellBase(t *testing.T) *lazyTestBase {
	t.Helper()
	store := pft2.NewMemoryStore()

	cell0 := bytes.Repeat([]byte{0x41}, pft2.CellBytes)
	cell1 := make([]byte, pft2.CellBytes)
	copy(cell1, "logical-head-bytes")
	cell1[500] = 0xFF // nonzero beyond the 100-byte logical EOF
	pack := append(append([]byte(nil), cell0...), cell1...)
	packRef := pft2.RefOf(pack)
	if err := store.PutPack(packRef, pack); err != nil {
		t.Fatal(err)
	}

	wrongDigest := sha256.Sum256([]byte("not-the-cell"))
	cell1Digest := sha256.Sum256(cell1)

	badDigestPage := putNode(t, store, &pft2.Node{Kind: pft2.KindDataPage, DataPage: &pft2.DataPage{
		Cells: [pft2.CellsPerPage]*pft2.CellRef{0: {
			CellDigest: wrongDigest, Object: packRef, ObjectOffset: 0,
		}},
	}})
	badTailPage := putNode(t, store, &pft2.Node{Kind: pft2.KindDataPage, DataPage: &pft2.DataPage{
		Cells: [pft2.CellsPerPage]*pft2.CellRef{0: {
			CellDigest: cell1Digest, Object: packRef, ObjectOffset: pft2.CellBytes,
		}},
	}})
	badDigestLeaf := putNode(t, store, &pft2.Node{Kind: pft2.KindExtentLeaf, ExtentLeaf: &pft2.ExtentLeaf{
		Entries: []pft2.ExtentEntry{{PageOffset: 0, Page: badDigestPage}},
	}})
	badTailLeaf := putNode(t, store, &pft2.Node{Kind: pft2.KindExtentLeaf, ExtentLeaf: &pft2.ExtentLeaf{
		Entries: []pft2.ExtentEntry{{PageOffset: 0, Page: badTailPage}},
	}})

	badDigestInode := putNode(t, store, &pft2.Node{Kind: pft2.KindInode, Inode: &pft2.Inode{
		Ino: 2, Kind: pft2.FileKindRegular, Mode: 0o644, Nlink: 1, Size: pft2.CellBytes,
		MtimeMs: lazyTsBase, CtimeMs: lazyTsBase, AtimeMs: lazyTsBase, ExtentRoot: &badDigestLeaf,
	}})
	badTailInode := putNode(t, store, &pft2.Node{Kind: pft2.KindInode, Inode: &pft2.Inode{
		Ino: 3, Kind: pft2.FileKindRegular, Mode: 0o644, Nlink: 1, Size: 100,
		MtimeMs: lazyTsBase, CtimeMs: lazyTsBase, AtimeMs: lazyTsBase, ExtentRoot: &badTailLeaf,
	}})

	dirLeaf := putNode(t, store, &pft2.Node{Kind: pft2.KindDirectoryLeaf, DirectoryLeaf: &pft2.DirectoryLeaf{
		Entries: []pft2.DirEntry{
			{Name: "bad-digest", Ino: 2, Kind: pft2.FileKindRegular},
			{Name: "bad-tail", Ino: 3, Kind: pft2.FileKindRegular},
		},
	}})
	rootInode := putNode(t, store, &pft2.Node{Kind: pft2.KindInode, Inode: &pft2.Inode{
		Ino: 1, Kind: pft2.FileKindDirectory, Mode: 0o755, Nlink: 1,
		MtimeMs: lazyTsBase, CtimeMs: lazyTsBase, AtimeMs: lazyTsBase, DirectoryRoot: &dirLeaf,
	}})
	indexLeaf := putNode(t, store, &pft2.Node{Kind: pft2.KindInodeIndexLeaf, InodeIndexLeaf: &pft2.InodeIndexLeaf{
		Entries: []pft2.InodeIndexEntry{
			{Ino: 1, Inode: rootInode}, {Ino: 2, Inode: badDigestInode}, {Ino: 3, Inode: badTailInode},
		},
	}})
	root := putNode(t, store, &pft2.Node{Kind: pft2.KindRoot, Root: &pft2.Root{
		RootInode: rootInode, InodeIndex: indexLeaf,
		MaxInoSeen: 3, InodeCount: 3, DirentCount: 2, LogicalBytes: pft2.CellBytes + 100,
	}})
	return &lazyTestBase{store: store, root: root, facts: pft2.Root{MaxInoSeen: 3}, paths: []string{"bad-digest", "bad-tail"}}
}

func TestRangerRejectsLyingCellsBeforeServing(t *testing.T) {
	base := buildCraftedCellBase(t)
	fs, _ := newLazyFS(t, base, newFakeEntryLog())

	readAll := func(path string, size int) error {
		buf := make([]byte, size)
		_, err := fs.ReadHandleAt(path, 0, buf, 0)
		return err
	}

	// Wrong cell digest: every OBJECT hashes exactly, so only the per-cell
	// verification can reject — and it must, without serving a byte.
	err := readAll("bad-digest", pft2.CellBytes)
	if err == nil {
		t.Fatal("cell with a lying digest was served")
	}
	if !strings.Contains(err.Error(), "cell verification") || !errors.Is(err, pft2.ErrCorrupt) {
		t.Fatalf("lying cell misclassified: %v", err)
	}
	if errnos.Of(err) == errnos.ENOENT {
		t.Fatalf("integrity failure mapped to ENOENT: %v", err)
	}

	// Nonzero bytes beyond logical EOF: digest-exact cell, rejected by the
	// terminal-zero invariant at the exact logical length.
	err = readAll("bad-tail", 100)
	if err == nil {
		t.Fatal("cell with a nonzero EOF tail was served")
	}
	if !errors.Is(err, pft2.ErrCorrupt) {
		t.Fatalf("EOF-tail violation misclassified: %v", err)
	}

	// The verified pack stays cached (its object digest is exact), but a
	// retry re-verifies the cell layer and fails identically: corruption is
	// never laundered into good data by the cache.
	if err := readAll("bad-digest", pft2.CellBytes); err == nil || !errors.Is(err, pft2.ErrCorrupt) {
		t.Fatalf("cached pack served a lying cell on retry: %v", err)
	}
}

func TestHandleInfoDistinguishesOutageFromVerifiedAbsence(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpMkdir, Path: "d", Mode: 0o755},
		{Op: wal.OpCreate, Path: "d/f", Mode: 0o644},
	})
	// Learn the stable ino through a throwaway FS so the FS under test has
	// a COLD handle index.
	warmFS, _ := newLazyFS(t, base, newFakeEntryLog())
	ino := lazyLstatIno(t, warmFS, "d/f")

	log := newFakeEntryLog()
	fs, fetcher := newLazyFS(t, base, log)

	// Fail-once outage: the error is a hydration failure (EIO class), NEVER
	// a verified ENOENT that would make the mount discard the handle.
	fetcher.setFailNext(1)
	_, err := fs.HandleInfo("", ino)
	if err == nil {
		t.Fatal("handle stat succeeded through a failing fetch")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transient hydration failure reported as verified absence: %v", err)
	}
	if errnos.Of(err) != errnos.EIO {
		t.Fatalf("hydration failure errno = %d, want EIO", errnos.Of(err))
	}
	// Retry of the SAME inode succeeds: the failure poisoned nothing.
	fi, err := fs.HandleInfo("", ino)
	if err != nil {
		t.Fatalf("handle stat retry: %v", err)
	}
	if fi.Sys().(interface{ Ino() uint64 }).Ino() != ino {
		t.Fatal("retry answered a different inode")
	}

	// Verified absence: an ino above the authenticated high-water proves
	// missing through the hydrated index and is exactly ENOENT.
	if _, err := fs.HandleInfo("", base.facts.MaxInoSeen+17); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verified-missing ino = %v, want os.ErrNotExist", err)
	}

	// Corrupt base objects are an integrity failure (EIO class), and a
	// healed store serves the same inode again.
	fs2, fetcher2 := newLazyFS(t, base, log)
	fetcher2.setCorrupt(true)
	if _, err := fs2.HandleInfo("", ino); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt hydration reported as absence: %v", err)
	}
	fetcher2.setCorrupt(false)
	if _, err := fs2.HandleInfo("", ino); err != nil {
		t.Fatalf("handle stat after healing: %v", err)
	}

	// Cold replay keeps the same semantics (the journal is empty here; the
	// replayed FS distinguishes identically).
	fs3, fetcher3 := newLazyFS(t, base, log)
	fetcher3.setFailNext(1)
	if _, err := fs3.HandleInfo("", ino); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replayed authority laundered a fetch failure into ENOENT: %v", err)
	}
	if _, err := fs3.HandleInfo("", ino); err != nil {
		t.Fatalf("replayed authority retry: %v", err)
	}
}

// pinInode journals a durable PFC2 open pin so a parked orphan is never a
// reap-sweep candidate — the deterministic managed way to model "held open".
func pinInode(t *testing.T, fs *FS, ref pfc2.SessionRef, ino uint64) {
	t.Helper()
	pin := pfc2.Record{Kind: pfc2.KindOpenPinChange, OpenPinChange: &pfc2.OpenPinChange{Session: ref, Ino: ino}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{pin}, ""); err != nil {
		t.Fatalf("pin ino %d: %v", ino, err)
	}
}

func TestOrphanNlinkZeroAcrossParkReplayAndSiblings(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "solo", Mode: 0o644},
		{Op: wal.OpCreate, Path: "twin", Mode: 0o644},
		{Op: wal.OpLink, Path: "twin", NewPath: "twin2"},
	})
	log := newFakeEntryLog()
	fs, _ := newLazyFS(t, base, log)
	session := openManagedSession(t, fs, "pfs-nlink", 1)
	soloIno := lazyLstatIno(t, fs, "solo")
	twinIno := lazyLstatIno(t, fs, "twin")
	nlinkOf := func(fi os.FileInfo) uint32 {
		return fi.Sys().(interface{ LinkCount() uint32 }).LinkCount()
	}

	// Durable open pins model the fds that keep the unlinked inodes alive
	// (and deterministically exclude the managed reap sweep).
	pinInode(t, fs, session, soloIno)
	pinInode(t, fs, session, twinIno)

	commitTree(t, fs, wal.Record{Op: wal.OpRemove, Path: "solo"}) // parks (last link)
	fi, ok := fs.OrphanInfo(soloIno)
	if !ok || nlinkOf(fi) != 0 {
		t.Fatalf("parked base orphan nlink = %d (ok=%v), want 0", nlinkOf(fi), ok)
	}
	if hfi, err := fs.HandleInfo("", soloIno); err != nil || nlinkOf(hfi) != 0 {
		t.Fatalf("parked handle stat nlink = %v err = %v, want 0", hfi, err)
	}

	// Hard-link sibling: unlinking ONE alias leaves a NAMED inode with
	// nlink 1 (never 0 — it is not parked).
	commitTree(t, fs, wal.Record{Op: wal.OpRemove, Path: "twin"})
	sfi, err := fs.Lstat("twin2")
	if err != nil || nlinkOf(sfi) != 1 {
		t.Fatalf("surviving alias nlink = %v err = %v, want 1", sfi, err)
	}
	// The LAST alias parks with nlink 0.
	commitTree(t, fs, wal.Record{Op: wal.OpRemove, Path: "twin2"})
	if ofi, ok := fs.OrphanInfo(twinIno); !ok || nlinkOf(ofi) != 0 {
		t.Fatalf("last-alias park nlink != 0 (ok=%v)", ok)
	}

	// Cold replay reproduces both parked (still-pinned) orphans, nlink 0.
	fs2, _ := newLazyFS(t, base, log)
	for _, ino := range []uint64{soloIno, twinIno} {
		if ofi, ok := fs2.OrphanInfo(ino); !ok || nlinkOf(ofi) != 0 {
			t.Fatalf("replayed orphan %d nlink != 0 (ok=%v)", ino, ok)
		}
	}

	// Race: concurrent stats of a parking inode must only ever observe the
	// named count or zero — never a stale coerced 1 on the parked record.
	fs3, _ := newLazyFS(t, base, newFakeEntryLog())
	session3 := openManagedSession(t, fs3, "pfs-nlink-race", 1)
	raceIno := lazyLstatIno(t, fs3, "solo")
	pinInode(t, fs3, session3, raceIno)
	stop := make(chan struct{})
	var probes sync.WaitGroup
	probes.Add(1)
	go func() {
		defer probes.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if ofi, ok := fs3.OrphanInfo(raceIno); ok && nlinkOf(ofi) != 0 {
				panic(fmt.Sprintf("parked orphan observed nlink %d", nlinkOf(ofi)))
			}
			if hfi, err := fs3.HandleInfo("", raceIno); err == nil {
				if n := nlinkOf(hfi); n != 0 && n != 1 {
					panic(fmt.Sprintf("handle stat observed nlink %d", n))
				}
			}
		}
	}()
	commitTree(t, fs3, wal.Record{Op: wal.OpRemove, Path: "solo"})
	close(stop)
	probes.Wait()
	if ofi, ok := fs3.OrphanInfo(raceIno); !ok || nlinkOf(ofi) != 0 {
		t.Fatal("post-race parked orphan nlink != 0")
	}
}
