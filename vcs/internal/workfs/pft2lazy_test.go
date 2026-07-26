package workfs

// Deterministic fault/concurrency coverage for the lazily hydrated PFT2
// base namespace (pft2lazy.go): bounded cold start, path-proportional point
// lookups, paged directory completion, load coalescence and canonical
// hard-link identity, replay/live no-resurrection, mutation-vs-load races,
// transient-failure retry, corrupt-object fail-closed, complete snapshots
// after partial hydration, ino-addressed replay against unhydrated names,
// rmdir/rename-over emptiness against unmaterialized entries, and
// reaped-base-inode permanence.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/content"
	"github.com/trendup-ai/portablefs/vcs/internal/fstransition"
	"github.com/trendup-ai/portablefs/vcs/internal/pft2"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

const lazyTsBase = int64(1_760_000_000_000)

// lazyTestFetcher wraps the memory store with fetch counting, injectable
// transient failures, per-call delays, corruption, and a context-aware gate
// (Fetch signals arrival, then blocks until the caller's context cancels —
// modelling a production fetcher honoring cancellation mid-outage).
type lazyTestFetcher struct {
	inner pft2.Fetcher

	mu         sync.Mutex
	count      int
	failNext   int
	corruptAll bool
	delay      time.Duration
	ctxGate    chan struct{}
	onFetch    func()
}

func (f *lazyTestFetcher) Fetch(ctx context.Context, ref pft2.Ref) ([]byte, error) {
	f.mu.Lock()
	f.count++
	fail := false
	if f.failNext > 0 {
		f.failNext--
		fail = true
	}
	corrupt := f.corruptAll
	delay := f.delay
	gate := f.ctxGate
	hook := f.onFetch
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if gate != nil {
		select {
		case gate <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	if fail {
		return nil, errors.New("injected transient fetch failure")
	}
	data, err := f.inner.Fetch(ctx, ref)
	if err != nil {
		return nil, err
	}
	if corrupt {
		flipped := append([]byte(nil), data...)
		flipped[0] ^= 0xFF
		return flipped, nil
	}
	return data, nil
}

func (f *lazyTestFetcher) fetches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

func (f *lazyTestFetcher) setFailNext(n int) {
	f.mu.Lock()
	f.failNext = n
	f.mu.Unlock()
}

func (f *lazyTestFetcher) setCorrupt(corrupt bool) {
	f.mu.Lock()
	f.corruptAll = corrupt
	f.mu.Unlock()
}

func (f *lazyTestFetcher) setDelay(d time.Duration) {
	f.mu.Lock()
	f.delay = d
	f.mu.Unlock()
}

func (f *lazyTestFetcher) setCtxGate(gate chan struct{}) {
	f.mu.Lock()
	f.ctxGate = gate
	f.mu.Unlock()
}

func (f *lazyTestFetcher) setOnFetch(hook func()) {
	f.mu.Lock()
	f.onFetch = hook
	f.mu.Unlock()
}

// lazyTestBase is one committed immutable PFT2 base built through the shared
// transition engine (exactly what the HistoryCut materializer produces).
type lazyTestBase struct {
	store *pft2.MemoryStore
	root  pft2.Ref
	facts pft2.Root
	paths []string // every namespace path, sorted
}

func buildLazyTestBase(t *testing.T, records []wal.Record) *lazyTestBase {
	t.Helper()
	ctx := context.Background()
	store := pft2.NewMemoryStore()
	editor, err := pft2.NewEditor(ctx, nil, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	var engine *fstransition.Engine
	engine, err = fstransition.New(fstransition.Config{
		Tx:           editor,
		Alloc:        func() (uint64, error) { return engine.MaxInoSeen() + 1, nil },
		FallbackTsMs: lazyTsBase,
	})
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]struct{}{}
	for _, r := range records {
		if _, err := engine.Apply(ctx, r); err != nil {
			t.Fatalf("engine apply %v %q: %v", r.Op, r.Path, err)
		}
		switch r.Op {
		case wal.OpCreate, wal.OpSymlink:
			paths[r.Path] = struct{}{}
		case wal.OpMkdir:
			prefix := ""
			for _, part := range strings.Split(r.Path, "/") {
				if prefix != "" {
					prefix += "/"
				}
				prefix += part
				paths[prefix] = struct{}{}
			}
		case wal.OpLink:
			paths[r.NewPath] = struct{}{}
		}
	}
	res, err := editor.Commit(ctx, store, store)
	if err != nil {
		t.Fatal(err)
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	return &lazyTestBase{store: store, root: res.Root, facts: res.RootFacts, paths: sorted}
}

// lazyTestNamespace is the fresh DB-issued branch namespace every fork-shaped
// lazy test adopts (fresh allocations compose as lazyTestNamespace<<32|n).
const lazyTestNamespace = uint32(7)

// forkPft2Base is the exact fork-shaped base contract for tests: seq-0
// origin, no recovery anchor, the NEW branch's fresh allocator namespace,
// and the proven root high-water equal to the hashed ROOT facts.
func forkPft2Base(base *lazyTestBase, fetcher pft2.Fetcher) Pft2Base {
	return Pft2Base{
		Fetcher:             fetcher,
		Root:                base.root,
		BaseSeq:             0,
		RootMaxInoSeen:      base.facts.MaxInoSeen,
		InodeNamespace:      lazyTestNamespace,
		NextLocal:           1,
		AllocatorMaxInoSeen: 1,
	}
}

// newLazyFS cold-starts a managed FS from base over a fresh counting fetcher
// and the given journal (empty journals model a clean cold start; populated
// ones model failover replay).
func newLazyFS(t *testing.T, base *lazyTestBase, log *fakeEntryLog) (*FS, *lazyTestFetcher) {
	t.Helper()
	fetcher := &lazyTestFetcher{inner: base.store}
	fs, err := NewManagedFromPft2(context.Background(), forkPft2Base(base, fetcher), nil, log, content.NewCache(1<<20))
	if err != nil {
		t.Fatalf("cold start: %v", err)
	}
	return fs, fetcher
}

// commitTree journals one tree record through the managed row path,
// tolerating deterministic apply rejections exactly like production callers.
func commitTree(t *testing.T, fs *FS, r wal.Record) {
	t.Helper()
	if _, err := fs.CommitEntry(&r, nil, ""); err != nil {
		t.Fatalf("commit %v %q: %v", r.Op, r.Path, err)
	}
}

func lazyLstatIno(t *testing.T, fs *FS, path string) uint64 {
	t.Helper()
	fi, err := fs.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %q: %v", path, err)
	}
	return fi.Sys().(interface{ Ino() uint64 }).Ino()
}

func lazyReadFile(t *testing.T, fs *FS, path string) string {
	t.Helper()
	f, err := fs.Open(path)
	if err != nil {
		t.Fatalf("open %q: %v", path, err)
	}
	data, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return string(data)
}

// hugeBaseRecords builds dirs d00..d(nDirs-1) with files f0..f(nFiles-1)
// each, plus one deep chain deep00/deep01/... of depth deepDepth ending in
// "leaf" with content.
func hugeBaseRecords(nDirs, nFiles, deepDepth int) []wal.Record {
	var records []wal.Record
	for d := 0; d < nDirs; d++ {
		dir := fmt.Sprintf("d%02d", d)
		records = append(records, wal.Record{Op: wal.OpMkdir, Path: dir, Mode: 0o755})
		for f := 0; f < nFiles; f++ {
			records = append(records, wal.Record{Op: wal.OpCreate, Path: fmt.Sprintf("%s/f%d", dir, f), Mode: 0o644})
		}
	}
	deep := make([]string, 0, deepDepth)
	for i := 0; i < deepDepth; i++ {
		deep = append(deep, fmt.Sprintf("deep%02d", i))
	}
	deepDir := strings.Join(deep, "/")
	records = append(records,
		wal.Record{Op: wal.OpMkdir, Path: deepDir, Mode: 0o755},
		wal.Record{Op: wal.OpCreate, Path: deepDir + "/leaf", Mode: 0o640},
		wal.Record{Op: wal.OpWrite, Path: deepDir + "/leaf", Data: []byte("deep-leaf-bytes")},
	)
	return records
}

func TestLazyColdStartBoundedFetches(t *testing.T) {
	const nDirs, nFiles, depth = 40, 30, 24 // 1240 files + 64 dirs + deep chain
	base := buildLazyTestBase(t, hugeBaseRecords(nDirs, nFiles, depth))
	fs, fetcher := newLazyFS(t, base, newFakeEntryLog())

	cold := fetcher.fetches()
	if cold > 8 {
		t.Fatalf("cold start fetched %d objects; want a small anchor-only bound (namespace holds %d paths)",
			cold, len(base.paths))
	}

	// A point lookup fetches only its path components, not the tree.
	deepPath := make([]string, 0, depth)
	for i := 0; i < depth; i++ {
		deepPath = append(deepPath, fmt.Sprintf("deep%02d", i))
	}
	leaf := strings.Join(deepPath, "/") + "/leaf"
	fi, err := fs.Lstat(leaf)
	if err != nil {
		t.Fatalf("deep lstat: %v", err)
	}
	if fi.Size() != int64(len("deep-leaf-bytes")) {
		t.Fatalf("deep leaf size %d", fi.Size())
	}
	afterLookup := fetcher.fetches() - cold
	// Each component costs a bounded btree descent (directory leaf + inode
	// index + inode object, mostly cache-warm); the whole path must stay
	// FAR below namespace size.
	if maxWant := depth*6 + 16; afterLookup > maxWant {
		t.Fatalf("deep point lookup fetched %d objects (> %d); not path-proportional", afterLookup, maxWant)
	}
	if got := lazyReadFile(t, fs, leaf); got != "deep-leaf-bytes" {
		t.Fatalf("deep leaf content %q", got)
	}
}

func TestLazyPointLookupFetchesOnlyPath(t *testing.T) {
	base := buildLazyTestBase(t, hugeBaseRecords(20, 40, 4))
	fs, fetcher := newLazyFS(t, base, newFakeEntryLog())

	before := fetcher.fetches()
	if _, err := fs.Lstat("d07/f11"); err != nil {
		t.Fatalf("lstat: %v", err)
	}
	first := fetcher.fetches() - before
	if first == 0 || first > 24 {
		t.Fatalf("first point lookup fetched %d objects; want a small positive path bound", first)
	}
	// A sibling in the same directory re-walks cached nodes plus its own
	// dirent/inode; still a small bound, never the directory's 40 entries.
	before = fetcher.fetches()
	if _, err := fs.Lstat("d07/f12"); err != nil {
		t.Fatalf("sibling lstat: %v", err)
	}
	if delta := fetcher.fetches() - before; delta > 8 {
		t.Fatalf("sibling lookup fetched %d objects", delta)
	}
	// A definitively absent name is a verified miss, not an error, and must
	// not install anything.
	if _, err := fs.Lstat("d07/absent"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent lookup: %v", err)
	}
	if _, err := fs.Lstat("d07/absent"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent lookup (repeat): %v", err)
	}
}

func TestLazyReadDirPagesAndCompletes(t *testing.T) {
	const wide = 1300 // > two 512-entry load pages
	records := []wal.Record{{Op: wal.OpMkdir, Path: "wide", Mode: 0o755}}
	for i := 0; i < wide; i++ {
		records = append(records, wal.Record{Op: wal.OpCreate, Path: fmt.Sprintf("wide/e%04d", i), Mode: 0o644})
	}
	base := buildLazyTestBase(t, records)
	fs, fetcher := newLazyFS(t, base, newFakeEntryLog())

	// A pending directory reports the conventional "unknown" nlink of 1
	// (never an undercount that would enable readdir leaf optimizations).
	fi, err := fs.Lstat("wide")
	if err != nil {
		t.Fatal(err)
	}
	if nlink := fi.Sys().(interface{ LinkCount() uint32 }).LinkCount(); nlink != 1 {
		t.Fatalf("pending directory nlink %d, want the explicit unknown 1", nlink)
	}

	infos, err := fs.ReadDir("wide")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	fi, err = fs.Lstat("wide")
	if err != nil {
		t.Fatal(err)
	}
	if nlink := fi.Sys().(interface{ LinkCount() uint32 }).LinkCount(); nlink != 2 {
		t.Fatalf("completed directory nlink %d, want 2", nlink)
	}
	if len(infos) != wide {
		t.Fatalf("readdir returned %d entries, want %d", len(infos), wide)
	}
	if !sort.SliceIsSorted(infos, func(i, j int) bool { return infos[i].Name() < infos[j].Name() }) {
		t.Fatal("readdir listing is not sorted")
	}
	after := fetcher.fetches()
	// The directory completed: every further operation inside it is served
	// from the live tree with ZERO base fetches.
	if _, err := fs.ReadDir("wide"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lstat("wide/e0777"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lstat("wide/definitely-absent"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent after completion: %v", err)
	}
	if delta := fetcher.fetches() - after; delta != 0 {
		t.Fatalf("completed directory still fetched %d objects", delta)
	}
}

func TestLazyConcurrentReadDirCoalesces(t *testing.T) {
	const wide = 700
	records := []wal.Record{{Op: wal.OpMkdir, Path: "shared", Mode: 0o755}}
	for i := 0; i < wide; i++ {
		records = append(records, wal.Record{Op: wal.OpCreate, Path: fmt.Sprintf("shared/e%03d", i), Mode: 0o644})
	}
	base := buildLazyTestBase(t, records)

	// Baseline: one enumeration on a fresh FS.
	fsBase, fetcherBase := newLazyFS(t, base, newFakeEntryLog())
	start := fetcherBase.fetches()
	if _, err := fsBase.ReadDir("shared"); err != nil {
		t.Fatal(err)
	}
	baseline := fetcherBase.fetches() - start

	// Concurrent: 8 goroutines race the same enumeration; the per-directory
	// flight coalesces them onto one leader.
	fs, fetcher := newLazyFS(t, base, newFakeEntryLog())
	fetcher.setDelay(100 * time.Microsecond)
	before := fetcher.fetches()
	var wg sync.WaitGroup
	errs := make([]error, 8)
	counts := make([]int, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			infos, err := fs.ReadDir("shared")
			errs[g], counts[g] = err, len(infos)
		}(g)
	}
	wg.Wait()
	fetcher.setDelay(0)
	for g := range errs {
		if errs[g] != nil {
			t.Fatalf("reader %d: %v", g, errs[g])
		}
		if counts[g] != wide {
			t.Fatalf("reader %d saw %d entries, want %d", g, counts[g], wide)
		}
	}
	if delta := fetcher.fetches() - before; delta > baseline+8 {
		t.Fatalf("8 concurrent enumerations fetched %d objects; baseline is %d (loads did not coalesce)", delta, baseline)
	}
}

func TestLazyHardlinkCanonicalIdentity(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "h1", Mode: 0o644},
		{Op: wal.OpWrite, Path: "h1", Data: []byte("hardlink-bytes")},
		{Op: wal.OpLink, Path: "h1", NewPath: "h2"},
		{Op: wal.OpMkdir, Path: "sub", Mode: 0o755},
		{Op: wal.OpLink, Path: "h2", NewPath: "sub/h3"},
	})
	fs, _ := newLazyFS(t, base, newFakeEntryLog())

	// Hydrate the aliases CONCURRENTLY from three distinct directories.
	var wg sync.WaitGroup
	inos := make([]uint64, 3)
	statErrs := make([]error, 3)
	for i, p := range []string{"h1", "h2", "sub/h3"} {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			fi, err := fs.Lstat(p)
			if err != nil {
				statErrs[i] = err
				return
			}
			inos[i] = fi.Sys().(interface{ Ino() uint64 }).Ino()
		}(i, p)
	}
	wg.Wait()
	for i, err := range statErrs {
		if err != nil {
			t.Fatalf("alias stat %d: %v", i, err)
		}
	}
	if inos[0] != inos[1] || inos[1] != inos[2] {
		t.Fatalf("alias inos diverge: %v", inos)
	}
	fs.mu.RLock()
	a, b, c := fs.resolve("h1"), fs.resolve("h2"), fs.resolve("sub/h3")
	fs.mu.RUnlock()
	if a == nil || a != b || b != c {
		t.Fatal("aliases did not converge on one canonical inode record")
	}
	fi, err := fs.Lstat("h2")
	if err != nil {
		t.Fatal(err)
	}
	if nlink := fi.Sys().(interface{ LinkCount() uint32 }).LinkCount(); nlink != 3 {
		t.Fatalf("alias nlink %d, want 3", nlink)
	}
	// A journaled write through one alias is visible through the others.
	commitTree(t, fs, wal.Record{Op: wal.OpWrite, Path: "h1", Offset: 0, Data: []byte("REWRITTEN")})
	if got := lazyReadFile(t, fs, "sub/h3"); !strings.HasPrefix(got, "REWRITTEN") {
		t.Fatalf("alias read %q after write via h1", got)
	}
}

func TestLazyReplayNeverResurrects(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpMkdir, Path: "d", Mode: 0o755},
		{Op: wal.OpCreate, Path: "d/x", Mode: 0o644},
		{Op: wal.OpWrite, Path: "d/x", Data: []byte("x-base")},
		{Op: wal.OpCreate, Path: "d/keep", Mode: 0o644},
		{Op: wal.OpCreate, Path: "a", Mode: 0o644},
		{Op: wal.OpWrite, Path: "a", Data: []byte("a-base")},
		{Op: wal.OpCreate, Path: "b", Mode: 0o644},
		{Op: wal.OpWrite, Path: "b", Data: []byte("b-base")},
		{Op: wal.OpMkdir, Path: "dir1", Mode: 0o755},
		{Op: wal.OpCreate, Path: "dir1/inner", Mode: 0o644},
	})
	log := newFakeEntryLog()

	// Live authority mutates base names it never fully enumerated.
	fs1, _ := newLazyFS(t, base, log)
	commitTree(t, fs1, wal.Record{Op: wal.OpRemove, Path: "d/x"})
	commitTree(t, fs1, wal.Record{Op: wal.OpRename, Path: "a", NewPath: "b"}) // replaces base b
	commitTree(t, fs1, wal.Record{Op: wal.OpRename, Path: "dir1", NewPath: "dir1renamed"})
	commitTree(t, fs1, wal.Record{Op: wal.OpCreate, Path: "d/x", Mode: 0o600}) // fresh file over the deleted name

	verify := func(fs *FS, label string) {
		t.Helper()
		// Point lookups FIRST (before any enumeration) so hydration itself
		// is what must refuse to resurrect.
		if fi, err := fs.Lstat("d/x"); err != nil || fi.Size() != 0 {
			t.Fatalf("%s: recreated d/x: fi=%v err=%v (base content must not resurrect)", label, fi, err)
		}
		if _, err := fs.Lstat("a"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: renamed-away base name a resolved: %v", label, err)
		}
		if got := lazyReadFile(t, fs, "b"); got != "a-base" {
			t.Fatalf("%s: b content %q, want the renamed source", label, got)
		}
		if _, err := fs.Lstat("dir1"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: renamed-away base dir resolved: %v", label, err)
		}
		if _, err := fs.Lstat("dir1renamed/inner"); err != nil {
			t.Fatalf("%s: moved dir lost its lazy contents: %v", label, err)
		}
		infos, err := fs.ReadDir("d")
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(infos))
		for _, fi := range infos {
			names = append(names, fi.Name())
		}
		sort.Strings(names)
		if want := []string{"keep", "x"}; !equalStringSlices(names, want) {
			t.Fatalf("%s: d listing %v, want %v", label, names, want)
		}
	}
	verify(fs1, "live")

	// Failover replay over the SAME journal must decide identically, with
	// hydration racing nothing.
	fs2, _ := newLazyFS(t, base, log)
	verify(fs2, "replay")

	// Full-tree determinism: both sides materialize to identical namespaces.
	if err := fs1.MaterializeBaseNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fs2.MaterializeBaseNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	s1, s2 := fs1.Snapshot(), fs2.Snapshot()
	if len(s1.Entries) != len(s2.Entries) {
		t.Fatalf("live/replay entry counts diverge: %d vs %d", len(s1.Entries), len(s2.Entries))
	}
	for i := range s1.Entries {
		a, b := s1.Entries[i], s2.Entries[i]
		if a.Path != b.Path || a.Kind != b.Kind || a.Ino != b.Ino || a.Size != b.Size {
			t.Fatalf("live/replay diverge at %d: %+v vs %+v", i, a, b)
		}
	}
}

func TestLazyCreateOverBaseNameDoesNotClobber(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "precious", Mode: 0o644},
		{Op: wal.OpWrite, Path: "precious", Data: []byte("precious-bytes")},
	})
	log := newFakeEntryLog()
	fs, _ := newLazyFS(t, base, log)
	ref := openManagedSession(t, fs, "pfs-lazy-excl", 1)

	// O_EXCL create over an UNHYDRATED base name: the pre-apply hydration
	// must discover the base entry and reject deterministically.
	reqHash := make([]byte, 32)
	reqHash[0] = 0x5A
	_, err := fs.MutateEnv(wal.Record{
		Op: wal.OpCreate, Path: "precious", Mode: 0o600, Excl: true,
		Env: &wal.Envelope{SessionID: ref.SessionID, Generation: ref.Generation, Slot: 0, SlotSeq: 1, ReqHash: reqHash},
	}, "")
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("excl create over base name: %v, want EEXIST", err)
	}
	// Idempotent (no O_EXCL) create must not clobber the base content.
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "precious", Mode: 0o600})
	if got := lazyReadFile(t, fs, "precious"); got != "precious-bytes" {
		t.Fatalf("idempotent create clobbered base content: %q", got)
	}
}

func TestLazyMutationRacesLoad(t *testing.T) {
	const wide = 600
	records := []wal.Record{{Op: wal.OpMkdir, Path: "big", Mode: 0o755}}
	for i := 0; i < wide; i++ {
		records = append(records, wal.Record{Op: wal.OpCreate, Path: fmt.Sprintf("big/e%03d", i), Mode: 0o644})
	}
	base := buildLazyTestBase(t, records)
	log := newFakeEntryLog()
	fs, fetcher := newLazyFS(t, base, log)
	fetcher.setDelay(50 * time.Microsecond) // stretch the load window

	done := make(chan error, 1)
	go func() {
		_, err := fs.ReadDir("big")
		done <- err
	}()
	// Mutate the directory WHILE its base load is in flight.
	commitTree(t, fs, wal.Record{Op: wal.OpRemove, Path: "big/e100"})
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "big/znew", Mode: 0o644})
	commitTree(t, fs, wal.Record{Op: wal.OpRename, Path: "big/e200", NewPath: "big/e200moved"})
	if err := <-done; err != nil {
		t.Fatalf("racing readdir: %v", err)
	}
	fetcher.setDelay(0)

	expect := func(fs *FS, label string) {
		t.Helper()
		infos, err := fs.ReadDir("big")
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, fi := range infos {
			names[fi.Name()] = true
		}
		if names["e100"] {
			t.Fatalf("%s: deleted base entry resurrected by the racing load", label)
		}
		if !names["znew"] || !names["e200moved"] || names["e200"] {
			t.Fatalf("%s: journal mutations lost: znew=%v e200moved=%v e200=%v",
				label, names["znew"], names["e200moved"], names["e200"])
		}
		if len(infos) != wide { // -e100 -e200 +znew +e200moved
			t.Fatalf("%s: listing has %d entries, want %d", label, len(infos), wide)
		}
	}
	expect(fs, "live")
	// Cold replay over the same journal converges to the same directory.
	fs2, _ := newLazyFS(t, base, log)
	expect(fs2, "replay")
}

func TestLazyTransientFetchFailureRetries(t *testing.T) {
	base := buildLazyTestBase(t, hugeBaseRecords(4, 10, 3))
	log := newFakeEntryLog()
	fs, fetcher := newLazyFS(t, base, log)

	// A failing point lookup surfaces an error and poisons nothing.
	fetcher.setFailNext(1)
	if _, err := fs.Lstat("d02/f5"); err == nil {
		t.Fatal("lookup with a failing fetch succeeded")
	}
	if _, err := fs.Lstat("d02/f5"); err != nil {
		t.Fatalf("retry after transient failure: %v", err)
	}

	// A directory load failing mid-enumeration retries cleanly and the
	// directory still completes with the exact entry set. Each failing
	// attempt consumes injected faults at whatever point it reaches, so
	// retry until the outage drains — every intermediate failure must be
	// surfaced (never a partial listing) and never poison the directory.
	fetcher.setFailNext(3)
	var infos []os.FileInfo
	var rerr error
	failures := 0
	for attempt := 0; attempt < 10; attempt++ {
		infos, rerr = fs.ReadDir("d03")
		if rerr == nil {
			break
		}
		failures++
	}
	if rerr != nil {
		t.Fatalf("readdir never recovered: %v", rerr)
	}
	if failures == 0 {
		t.Fatal("fault injection never fired")
	}
	if len(infos) != 10 {
		t.Fatalf("readdir after retry returned %d entries, want 10", len(infos))
	}
	// Mutations still work: the authority was never fenced.
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "d03/new", Mode: 0o644})
	if _, err := fs.Lstat("d03/new"); err != nil {
		t.Fatal(err)
	}

	// A cold start against an unreachable base fails closed.
	badFetcher := &lazyTestFetcher{inner: base.store}
	badFetcher.setFailNext(1 << 20)
	if _, err := NewManagedFromPft2(context.Background(), forkPft2Base(base, badFetcher),
		nil, newFakeEntryLog(), content.NewCache(1<<20)); err == nil {
		t.Fatal("cold start with unreachable base succeeded")
	}
}

func TestLazyCorruptFetchFailsClosed(t *testing.T) {
	base := buildLazyTestBase(t, hugeBaseRecords(3, 6, 3))
	fs, fetcher := newLazyFS(t, base, newFakeEntryLog())

	fetcher.setCorrupt(true)
	if _, err := fs.Lstat("d01/f2"); err == nil {
		t.Fatal("corrupt object served a successful lookup")
	} else if !strings.Contains(err.Error(), "corrupt") && !strings.Contains(err.Error(), "digest") {
		t.Fatalf("corruption not classified: %v", err)
	}
	if _, err := fs.ReadDir("d01"); err == nil {
		t.Fatal("corrupt object served a successful readdir")
	}
	fetcher.setCorrupt(false)
	// Nothing was installed from corrupt bytes; healing the store heals reads.
	if _, err := fs.Lstat("d01/f2"); err != nil {
		t.Fatalf("lookup after healing: %v", err)
	}
	infos, err := fs.ReadDir("d01")
	if err != nil {
		t.Fatalf("readdir after healing: %v", err)
	}
	if len(infos) != 6 {
		t.Fatalf("readdir after healing returned %d entries", len(infos))
	}
}

func TestLazySnapshotAfterPartialHydrationIsComplete(t *testing.T) {
	base := buildLazyTestBase(t, hugeBaseRecords(6, 8, 4))
	log := newFakeEntryLog()
	fs, fetcher := newLazyFS(t, base, log)

	// Touch ONE path only, then mutate a couple of names.
	if _, err := fs.Lstat("d01/f1"); err != nil {
		t.Fatal(err)
	}
	commitTree(t, fs, wal.Record{Op: wal.OpRemove, Path: "d02/f3"})
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "d02/added", Mode: 0o644})
	partial := fetcher.fetches()

	snap := fs.Snapshot()
	if fetcher.fetches() == partial {
		t.Fatal("snapshot did not materialize the remaining base namespace")
	}
	got := make([]string, 0, len(snap.Entries))
	for _, e := range snap.Entries {
		got = append(got, e.Path)
	}
	want := map[string]struct{}{}
	for _, p := range base.paths {
		want[p] = struct{}{}
	}
	delete(want, "d02/f3")
	want["d02/added"] = struct{}{}
	wantSorted := make([]string, 0, len(want))
	for p := range want {
		wantSorted = append(wantSorted, p)
	}
	sort.Strings(wantSorted)
	if !equalStringSlices(got, wantSorted) {
		t.Fatalf("snapshot namespace incomplete:\ngot  %d entries\nwant %d entries", len(got), len(wantSorted))
	}
	// Idempotent: a second capture re-walks the now-complete tree.
	if second := fs.Snapshot(); len(second.Entries) != len(snap.Entries) {
		t.Fatal("second snapshot diverged")
	}
}

func TestLazyInoAddressedReplayHydratesByHandle(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpMkdir, Path: "dir", Mode: 0o755},
		{Op: wal.OpCreate, Path: "dir/file", Mode: 0o644},
		{Op: wal.OpWrite, Path: "dir/file", Data: []byte("0123456789")},
	})
	log := newFakeEntryLog()
	fs1, _ := newLazyFS(t, base, log)
	ino := lazyLstatIno(t, fs1, "dir/file")

	// Journal PURE ino-addressed mutations (no path at all — the stale-name
	// case a mount handle produces after a peer rename).
	commitTree(t, fs1, wal.Record{Op: wal.OpWrite, Ino: ino, Offset: 2, Data: []byte("XY")})
	commitTree(t, fs1, wal.Record{Op: wal.OpChmod, Ino: ino, Mode: 0o600})

	// Failover replay: the records must hydrate the target by INO through
	// the base's verified inode index (the name is never resolved).
	fs2, fetcher := newLazyFS(t, base, log)
	buf := make([]byte, 10)
	n, err := fs2.ReadHandleAt("", ino, buf, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("handle read: %v", err)
	}
	if got := string(buf[:n]); got != "01XY456789" {
		t.Fatalf("ino-addressed replay content %q", got)
	}
	fi, err := fs2.HandleInfo("", ino)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("ino-addressed chmod lost: err=%v mode=%v", err, fi)
	}
	// The name was NEVER enumerated: looking it up now still works and
	// converges on the SAME record.
	if got := lazyLstatIno(t, fs2, "dir/file"); got != ino {
		t.Fatalf("name hydration produced a different identity: %d vs %d", got, ino)
	}
	_ = fetcher
}

func TestLazyRmdirAndRenameOverEmptiness(t *testing.T) {
	records := []wal.Record{
		{Op: wal.OpMkdir, Path: "empty", Mode: 0o755},
		{Op: wal.OpMkdir, Path: "empty2", Mode: 0o755},
		{Op: wal.OpMkdir, Path: "full", Mode: 0o755},
		{Op: wal.OpMkdir, Path: "small", Mode: 0o755},
		{Op: wal.OpMkdir, Path: "src", Mode: 0o755},
		{Op: wal.OpMkdir, Path: "src2", Mode: 0o755},
	}
	for i := 0; i < 25; i++ {
		records = append(records, wal.Record{Op: wal.OpCreate, Path: fmt.Sprintf("full/e%02d", i), Mode: 0o644})
	}
	records = append(records,
		wal.Record{Op: wal.OpCreate, Path: "small/only", Mode: 0o644},
	)
	base := buildLazyTestBase(t, records)
	log := newFakeEntryLog()
	fs, _ := newLazyFS(t, base, log)

	// rmdir of an EMPTY, never-enumerated base directory succeeds: the
	// emptiness probe completes it as empty.
	commitTree(t, fs, wal.Record{Op: wal.OpRemove, Path: "empty"})
	if _, err := fs.Lstat("empty"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty base dir survived rmdir: %v", err)
	}
	// rmdir of a NON-EMPTY, never-enumerated base directory is rejected
	// deterministically (its unmaterialized entries count).
	commitTree(t, fs, wal.Record{Op: wal.OpRemove, Path: "full"})
	if infos, err := fs.ReadDir("full"); err != nil || len(infos) != 25 {
		t.Fatalf("non-empty base dir damaged by rejected rmdir: %d entries, err=%v", len(infos), err)
	}
	// Removing the LAST base entry via the journal, then rmdir: the probe
	// sees every base name tombstoned and completes the dir as empty.
	commitTree(t, fs, wal.Record{Op: wal.OpRemove, Path: "small/only"})
	commitTree(t, fs, wal.Record{Op: wal.OpRemove, Path: "small"})
	if _, err := fs.Lstat("small"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("emptied base dir survived rmdir: %v", err)
	}
	// rename over an EMPTY base directory replaces it; over a NON-EMPTY one
	// is rejected and destroys nothing.
	commitTree(t, fs, wal.Record{Op: wal.OpRename, Path: "src", NewPath: "empty2"})
	if _, err := fs.Lstat("src"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rename-over-empty did not move the source")
	}
	commitTree(t, fs, wal.Record{Op: wal.OpRename, Path: "src2", NewPath: "full"})
	if _, err := fs.Lstat("src2"); err != nil {
		t.Fatalf("rejected rename-over-nonempty lost its source: %v", err)
	}
	if infos, err := fs.ReadDir("full"); err != nil || len(infos) != 25 {
		t.Fatalf("rename-over-nonempty damaged the destination: %d entries, err=%v", len(infos), err)
	}

	// Cold replay converges to the identical namespace.
	fs2, _ := newLazyFS(t, base, log)
	if err := fs2.MaterializeBaseNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fs.MaterializeBaseNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	s1, s2 := fs.Snapshot(), fs2.Snapshot()
	if len(s1.Entries) != len(s2.Entries) {
		t.Fatalf("live/replay diverge: %d vs %d entries", len(s1.Entries), len(s2.Entries))
	}
	for i := range s1.Entries {
		if s1.Entries[i].Path != s2.Entries[i].Path || s1.Entries[i].Ino != s2.Entries[i].Ino {
			t.Fatalf("live/replay diverge at %q vs %q", s1.Entries[i].Path, s2.Entries[i].Path)
		}
	}
}

func TestLazyReapedBaseInoStaysDead(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "doomed", Mode: 0o644},
		{Op: wal.OpWrite, Path: "doomed", Data: []byte("doomed-bytes")},
		{Op: wal.OpCreate, Path: "survivor", Mode: 0o644},
	})
	log := newFakeEntryLog()
	fs1, _ := newLazyFS(t, base, log)
	doomed := lazyLstatIno(t, fs1, "doomed")
	survivor := lazyLstatIno(t, fs1, "survivor")
	commitTree(t, fs1, wal.Record{Op: wal.OpRemove, Path: "doomed"}) // parks (last link)
	commitTree(t, fs1, wal.Record{Op: wal.OpReap, Ino: doomed})      // destroys

	verify := func(fs *FS, label string) {
		t.Helper()
		if _, err := fs.HandleInfo("", doomed); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: reaped base inode stat = %v, want verified ENOENT", label, err)
		}
		if _, err := fs.ReadHandleAt("", doomed, make([]byte, 4), 0); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: reaped base inode readable: %v", label, err)
		}
		if _, err := fs.Lstat("doomed"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: reaped base name resolvable: %v", label, err)
		}
		// A live base ino still hydrates by handle (the dead set is exact).
		if _, err := fs.HandleInfo("", survivor); err != nil {
			t.Fatalf("%s: live base inode did not hydrate by handle: %v", label, err)
		}
	}
	verify(fs1, "live")
	fs2, _ := newLazyFS(t, base, log)
	verify(fs2, "replay") // deadBaseInos must rebuild from the replayed reap
}

func TestLazyConcurrentStressRace(t *testing.T) {
	const nDirs, nFiles = 8, 24
	base := buildLazyTestBase(t, hugeBaseRecords(nDirs, nFiles, 4))
	log := newFakeEntryLog()
	fs, _ := newLazyFS(t, base, log)

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < 6; r++ {
		readers.Add(1)
		go func(r int) {
			defer readers.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				dir := fmt.Sprintf("d%02d", (r+n)%nDirs)
				switch n % 3 {
				case 0:
					_, _ = fs.Lstat(fmt.Sprintf("%s/f%d", dir, n%nFiles))
				case 1:
					_, _ = fs.ReadDir(dir)
				case 2:
					_, _ = fs.Lstat(fmt.Sprintf("%s/missing%d", dir, n%7))
				}
			}
		}(r)
	}
	var writers sync.WaitGroup
	writerErrs := make([]error, 2)
	for w := 0; w < 2; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for k := 0; k < 60; k++ {
				dir := fmt.Sprintf("d%02d", (w*3+k)%nDirs)
				name := fmt.Sprintf("%s/w%d-%d", dir, w, k)
				if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
					writerErrs[w] = err
					return
				}
				if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpRemove, Path: fmt.Sprintf("%s/f%d", dir, k%nFiles)}, nil, ""); err != nil {
					writerErrs[w] = err
					return
				}
				if k%9 == 0 {
					_ = fs.Snapshot() // periodic complete-materialization under load
				}
			}
		}(w)
	}
	writers.Wait()
	close(stop)
	readers.Wait()
	for w, err := range writerErrs {
		if err != nil {
			t.Fatalf("writer %d: %v", w, err)
		}
	}

	// Cold replay of everything the stress journaled matches the live tree.
	fs2, _ := newLazyFS(t, base, log)
	if err := fs2.MaterializeBaseNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	s1, s2 := fs.Snapshot(), fs2.Snapshot()
	if len(s1.Entries) != len(s2.Entries) {
		t.Fatalf("stress live/replay diverge: %d vs %d entries", len(s1.Entries), len(s2.Entries))
	}
	for i := range s1.Entries {
		if s1.Entries[i].Path != s2.Entries[i].Path || s1.Entries[i].Ino != s2.Entries[i].Ino {
			t.Fatalf("stress live/replay diverge at %q vs %q", s1.Entries[i].Path, s2.Entries[i].Path)
		}
	}
}

func TestLazyCheckpointProbeContextOutageAndRecovery(t *testing.T) {
	base := buildLazyTestBase(t, hugeBaseRecords(5, 6, 3))
	log := newFakeEntryLog()
	fs, fetcher := newLazyFS(t, base, log)

	// Decide one name while the store is healthy, so live writes have a
	// hydration-free target during the outage.
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "live.txt", Mode: 0o644})

	// Outage: the probe returns a precise wrapped error — no panic, no
	// partial materialization poisoning — while live serving continues.
	fetcher.setFailNext(1 << 20)
	if _, err := fs.CheckpointProbeContext(context.Background()); err == nil {
		t.Fatal("probe succeeded against an unreachable base")
	} else if !strings.Contains(err.Error(), "checkpoint probe") {
		t.Fatalf("probe error lost its context: %v", err)
	}
	commitTree(t, fs, wal.Record{Op: wal.OpWrite, Path: "live.txt", Data: []byte("still-writing")})
	if got := lazyReadFile(t, fs, "live.txt"); got != "still-writing" {
		t.Fatalf("live write during base outage diverged: %q", got)
	}

	// A pre-canceled pass reports cancellation before any fetch.
	fetcher.setFailNext(0)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fs.CheckpointProbeContext(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled probe: %v", err)
	}

	// Cancellation MID-materialization: the fetcher blocks until the pass's
	// context cancels, exactly like a production ctx-aware fetcher during an
	// outage; the probe must return the cancellation, not hang.
	gate := make(chan struct{}, 1)
	fetcher.setCtxGate(gate)
	ctx, cancelMid := context.WithCancel(context.Background())
	probeErr := make(chan error, 1)
	go func() {
		_, err := fs.CheckpointProbeContext(ctx)
		probeErr <- err
	}()
	<-gate // the probe is inside a blocked fetch
	cancelMid()
	if err := <-probeErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-materialization cancellation: %v", err)
	}
	fetcher.setCtxGate(nil)

	// Recovery: the same probe now returns the COMPLETE namespace.
	snap, err := fs.CheckpointProbeContext(context.Background())
	if err != nil {
		t.Fatalf("probe after recovery: %v", err)
	}
	if want := len(base.paths) + 1; len(snap.Entries) != want {
		t.Fatalf("recovered probe carries %d entries, want %d", len(snap.Entries), want)
	}
	for _, e := range snap.Entries {
		if len(e.Blocks) != 0 {
			t.Fatalf("probe copied dirty block bytes for %q (must be metadata-only)", e.Path)
		}
	}
}

func TestLazyBaseFileBytesReadThroughRanger(t *testing.T) {
	payload := bytes.Repeat([]byte("cell-crossing-payload!"), 400) // ~8.8 KiB, crosses cells
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "blob.bin", Mode: 0o644},
		{Op: wal.OpWrite, Path: "blob.bin", Data: payload},
	})
	fs, _ := newLazyFS(t, base, newFakeEntryLog())
	if got := lazyReadFile(t, fs, "blob.bin"); got != string(payload) {
		t.Fatalf("lazy base file bytes diverge: %d bytes, want %d", len(got), len(payload))
	}
	// A journaled partial overwrite merges over the lazy base.
	commitTree(t, fs, wal.Record{Op: wal.OpWrite, Path: "blob.bin", Offset: 5, Data: []byte("OVERLAY")})
	want := append([]byte(nil), payload...)
	copy(want[5:], []byte("OVERLAY"))
	if got := lazyReadFile(t, fs, "blob.bin"); got != string(want) {
		t.Fatal("overlay write over lazy base diverged")
	}
}
