package workfs

// Differential goldens for the shared deterministic filesystem transition
// engine: the SAME ordered wal.Record stream is folded through (a) this
// package's live-authority apply (the semantic reference) and (b)
// fstransition.Engine over a pft2.Editor, and the resulting states must be
// IDENTICAL in paths, kinds, permission bits, uid/gid, sizes, byte content,
// inode identities, nlink (names per ino), timestamps, and the parked-orphan
// set. This is the proof that the HistoryCut materializer reproduces exactly
// the tree the live authority serves, record for record.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fstransition"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

const diffTsBase = int64(1_750_000_000_000)

// nodeFact is the normal form both sides project into.
type nodeFact struct {
	Path    string
	Kind    string
	Mode    uint32
	UID     uint32
	GID     uint32
	Size    uint64
	Ino     uint64
	Nlink   uint64
	MtimeMs int64
	AtimeMs int64
	Target  string
	Content string // sha-free: raw bytes for small goldens
}

// workfsFacts walks the live tree into the normal form.
func workfsFacts(t *testing.T, fs *FS) (map[string]nodeFact, map[uint64]string) {
	t.Helper()
	facts := map[string]nodeFact{}
	names := map[uint64]uint64{} // ino -> name count
	fs.mu.Lock()
	var walk func(prefix string, n *inode)
	walk = func(prefix string, n *inode) {
		for name, child := range n.children {
			p := name
			if prefix != "" {
				p = prefix + "/" + name
			}
			names[child.ino]++
			facts[p] = nodeFact{
				Path: p, Kind: child.kind, Mode: modeToUnix(child.mode) & 0o7777,
				UID: child.uid, GID: child.gid,
				Size: uint64(child.curSize()), Ino: child.ino,
				MtimeMs: child.mtime.UnixMilli(), AtimeMs: child.atime.UnixMilli(),
				Target: child.linkTarget,
			}
			if child.kind == "directory" {
				walk(p, child)
			}
		}
	}
	walk("", fs.root)
	orphans := map[uint64]string{}
	orphanSizes := map[uint64]int{}
	for ino, n := range fs.orphans {
		orphanSizes[ino] = int(n.curSize())
	}
	fs.mu.Unlock()

	// Content reads take fs locks themselves.
	for p, f := range facts {
		if f.Kind != "file" {
			continue
		}
		h, err := fs.Open(p)
		if err != nil {
			t.Fatalf("open %q: %v", p, err)
		}
		data, err := io.ReadAll(h)
		_ = h.Close()
		if err != nil {
			t.Fatalf("read %q: %v", p, err)
		}
		f.Content = string(data)
		f.Nlink = names[f.Ino]
		facts[p] = f
	}
	for p, f := range facts {
		if f.Kind == "file" {
			continue
		}
		f.Nlink = 1
		facts[p] = f
	}
	for ino, size := range orphanSizes {
		buf := make([]byte, size)
		n, err := fs.ReadOrphanAt(ino, buf, 0)
		if err != nil && err != io.EOF {
			t.Fatalf("orphan read %d: %v", ino, err)
		}
		orphans[ino] = string(buf[:n])
	}
	return facts, orphans
}

// engineFacts commits the editor and walks the PFT2 tree into the normal form.
func engineFacts(
	t *testing.T, store *pft2.MemoryStore, editor *pft2.Editor, engine *fstransition.Engine,
) (map[string]nodeFact, map[uint64]string) {
	t.Helper()
	ctx := context.Background()

	// Orphan content BEFORE commit (the editor's merged view by ino).
	orphans := map[uint64]string{}
	for _, ino := range engine.Orphans() {
		meta, ok, err := editor.GetOrphanInode(ctx, ino)
		if err != nil || !ok {
			t.Fatalf("orphan %d: ok=%v err=%v", ino, ok, err)
		}
		if meta.Kind != pft2.FileKindRegular {
			orphans[ino] = ""
			continue
		}
		data := make([]byte, meta.Size)
		for off := uint64(0); off < meta.Size; off += pft2.CellBytes {
			cell, err := editor.ReadCell(ctx, ino, off)
			if err != nil {
				t.Fatalf("orphan cell %d/%d: %v", ino, off, err)
			}
			copy(data[off:], cell)
		}
		orphans[ino] = string(data)
	}

	res, err := editor.Commit(ctx, store, store)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: store}, res.Root)
	if err != nil {
		t.Fatal(err)
	}
	facts := map[string]nodeFact{}
	names := map[uint64]uint64{}
	var walk func(prefix string, view pft2.InodeView)
	walk = func(prefix string, view pft2.InodeView) {
		cursor := ""
		for {
			entries, next, err := reader.ReadDir(ctx, view.Ref, cursor, 128)
			if err != nil {
				t.Fatalf("readdir %q: %v", prefix, err)
			}
			for _, entry := range entries {
				p := entry.Name
				if prefix != "" {
					p = prefix + "/" + entry.Name
				}
				child, err := reader.GetInode(ctx, entry.Ino)
				if err != nil {
					t.Fatalf("inode %d: %v", entry.Ino, err)
				}
				names[entry.Ino]++
				fact := nodeFact{
					Path: p, Kind: kindString(child.Inode.Kind),
					Mode: child.Inode.Mode & 0o7777,
					UID:  child.Inode.UID, GID: child.Inode.GID,
					Size: child.Inode.Size, Ino: child.Inode.Ino,
					Nlink:   child.Inode.Nlink,
					MtimeMs: child.Inode.MtimeMs, AtimeMs: child.Inode.AtimeMs,
					Target: child.Inode.SymlinkTarget,
				}
				if child.Inode.Kind == pft2.FileKindRegular {
					fact.Content = string(readPft2File(t, store, reader, child))
					if fact.Kind == "file" && fact.Size == 0 {
						fact.Content = ""
					}
				}
				if child.Inode.Kind == pft2.FileKindDirectory {
					fact.Size = 0
				}
				facts[p] = fact
				if child.Inode.Kind == pft2.FileKindDirectory {
					walk(p, child)
				}
			}
			if next == "" {
				break
			}
			cursor = next
		}
	}
	rootView, err := reader.GetInode(ctx, pft2.RootIno)
	if err != nil {
		t.Fatal(err)
	}
	walk("", rootView)
	// Cross-check nlink against names-per-ino for non-aliased goldens.
	for p, f := range facts {
		if f.Kind == "file" && f.Nlink != names[f.Ino] {
			t.Fatalf("pft2 %q nlink %d != %d names", p, f.Nlink, names[f.Ino])
		}
	}
	return facts, orphans
}

func kindString(k pft2.FileKind) string {
	switch k {
	case pft2.FileKindRegular:
		return "file"
	case pft2.FileKindDirectory:
		return "directory"
	case pft2.FileKindSymlink:
		return "symlink"
	}
	return fmt.Sprintf("kind-%d", k)
}

func readPft2File(t *testing.T, store *pft2.MemoryStore, reader *pft2.TreeReader, view pft2.InodeView) []byte {
	t.Helper()
	ctx := context.Background()
	out := make([]byte, view.Inode.Size)
	if view.Inode.ExtentRoot == nil || view.Inode.Size == 0 {
		return out
	}
	extents, err := reader.ReadExtents(ctx, view.Ref, 0, view.Inode.Size)
	if err != nil {
		t.Fatalf("extents ino %d: %v", view.Inode.Ino, err)
	}
	for _, ext := range extents {
		if ext.Cell == nil {
			t.Fatal("legacy extent in a freshly built tree")
		}
		raw, err := store.Fetch(ctx, ext.Cell.Object)
		if err != nil {
			t.Fatal(err)
		}
		cell := raw[ext.Cell.ObjectOffset : ext.Cell.ObjectOffset+pft2.CellBytes]
		copy(out[ext.FileOffset:ext.FileOffset+ext.Length], cell[:ext.Length])
	}
	return out
}

// applyDiff journals client intents through the managed row path one record
// at a time (deterministic apply rejections are durable outcomes, not
// errors), mirroring how production rows reach the engine.
func applyDiff(t *testing.T, fs *FS, recs ...wal.Record) {
	t.Helper()
	for _, r := range recs {
		commitTree(t, fs, r)
	}
}

// runDifferential drives the live authority with build (client intents; the
// authority stamps timestamps and inode identities at append), then folds the
// resulting DURABLE journal records — exactly what the HistoryCut
// materializer consumes — through the shared transition engine into a PFT2
// editor, and compares the two states.
func runDifferential(t *testing.T, build func(t *testing.T, live *FS)) {
	t.Helper()
	log := newFakeEntryLog()
	live, err := NewManaged(nil, &fakeBlobs{data: map[string][]byte{}}, log)
	if err != nil {
		t.Fatal(err)
	}
	build(t, live)
	// Quiesce the asynchronous reap sweep before collecting the journal:
	// unpinned parked orphans reap in the background, and both sides must
	// fold the SAME durable row stream (including those reap rows).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if live.ManagedReapSweep() == 0 && !live.managed.sweepScheduled.Load() {
			// A stale async trigger can still be mid-flight, but the state is
			// static now: a sweep that finds no unpinned parked orphan
			// journals nothing, so the row stream is complete.
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reap sweep did not quiesce")
		}
		time.Sleep(2 * time.Millisecond)
	}
	var records []wal.Record
	if err := log.ReplayEntriesInto(func(entry pfj3.JournalEntry) error {
		if entry.Tree != nil {
			records = append(records, *entry.Tree)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay durable records: %v", err)
	}

	store := pft2.NewMemoryStore()
	editor, err := pft2.NewEditor(context.Background(), nil, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	var engine *fstransition.Engine
	engine, err = fstransition.New(fstransition.Config{
		Tx: editor,
		// Mirrors the live allocator exactly: next = observed max + 1.
		Alloc:        func() (uint64, error) { return engine.MaxInoSeen() + 1, nil },
		FallbackTsMs: diffTsBase,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if r.Op.IsControl() {
			continue
		}
		if _, err := engine.Apply(context.Background(), r); err != nil {
			t.Fatalf("engine apply %v %q: %v", r.Op, r.Path, err)
		}
	}

	liveFacts, liveOrphans := workfsFacts(t, live)
	pftFacts, pftOrphans := engineFacts(t, store, editor, engine)

	livePaths := sortedKeys(liveFacts)
	pftPaths := sortedKeys(pftFacts)
	if !equalStrings(livePaths, pftPaths) {
		t.Fatalf("path sets diverge:\nlive: %v\npft2: %v", livePaths, pftPaths)
	}
	for _, p := range livePaths {
		l, e := liveFacts[p], pftFacts[p]
		if l.Kind != e.Kind || l.Mode != e.Mode || l.UID != e.UID || l.GID != e.GID ||
			l.Ino != e.Ino || l.Target != e.Target {
			t.Fatalf("%q identity diverges:\nlive: %+v\npft2: %+v", p, l, e)
		}
		if l.Kind == "file" {
			if l.Size != e.Size || l.Content != e.Content {
				t.Fatalf("%q content diverges: live %d bytes, pft2 %d bytes", p, l.Size, e.Size)
			}
			if l.Nlink != e.Nlink {
				t.Fatalf("%q nlink diverges: live %d, pft2 %d", p, l.Nlink, e.Nlink)
			}
		}
		if l.MtimeMs != e.MtimeMs || l.AtimeMs != e.AtimeMs {
			t.Fatalf("%q times diverge:\nlive: mtime=%d atime=%d\npft2: mtime=%d atime=%d",
				p, l.MtimeMs, l.AtimeMs, e.MtimeMs, e.AtimeMs)
		}
	}

	liveInos := sortedU64Keys(liveOrphans)
	pftInos := sortedU64Keys(pftOrphans)
	if !equalU64(liveInos, pftInos) {
		t.Fatalf("orphan sets diverge: live %v, pft2 %v", liveInos, pftInos)
	}
	for _, ino := range liveInos {
		if liveOrphans[ino] != pftOrphans[ino] {
			t.Fatalf("orphan %d content diverges (%d vs %d bytes)",
				ino, len(liveOrphans[ino]), len(pftOrphans[ino]))
		}
	}
}

func sortedKeys(m map[string]nodeFact) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedU64Keys(m map[uint64]string) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDifferentialStructureAndMetadata(t *testing.T) {
	runDifferential(t, func(t *testing.T, live *FS) {
		applyDiff(t, live,
			wal.Record{Op: wal.OpMkdir, Path: "a/b/c", Mode: 0o750},
			wal.Record{Op: wal.OpCreate, Path: "a/b/c/file", Mode: 0o640},
			wal.Record{Op: wal.OpWrite, Path: "a/b/c/file", Data: bytes.Repeat([]byte("data!"), 3000)},
			wal.Record{Op: wal.OpWrite, Path: "a/b/c/file", Offset: 4090, Data: []byte("CROSSCELL")},
			wal.Record{Op: wal.OpSymlink, Path: "a/link", Target: "b/c/file"},
			wal.Record{Op: wal.OpChmod, Path: "a/b/c/file", Mode: 0o600},
			wal.Record{Op: wal.OpChown, Path: "a/b/c/file", UID: 100, ChownSetUID: true},
			wal.Record{Op: wal.OpChown, Path: "a/b/c/file", GID: 200, ChownSetGID: true},
			wal.Record{Op: wal.OpChtimes, Path: "a/b/c/file", MtimeMs: 12345, AtimeMs: 999, ChtimesSetAtime: true},
			wal.Record{Op: wal.OpTruncate, Path: "a/b/c/file", Size: 6000},
			wal.Record{Op: wal.OpWrite, Path: "a/b/c/file", Append: true, Data: []byte("tail")},
			wal.Record{Op: wal.OpCreate, Path: "empty", Mode: 0o644},
			wal.Record{Op: wal.OpMkdir, Path: "deep/x/y/z/w", Mode: 0o700},
		)
	})
}

func TestDifferentialRenameOrphanReap(t *testing.T) {
	runDifferential(t, func(t *testing.T, live *FS) {
		applyDiff(t, live,
			wal.Record{Op: wal.OpCreate, Path: "src", Mode: 0o644},
			wal.Record{Op: wal.OpWrite, Path: "src", Data: []byte("source-bytes")},
			wal.Record{Op: wal.OpCreate, Path: "dst", Mode: 0o644},
			wal.Record{Op: wal.OpWrite, Path: "dst", Data: []byte("destination-bytes")},
			// Replacing rename parks the destination (deterministic detach).
			wal.Record{Op: wal.OpRename, Path: "src", NewPath: "dst"},
			wal.Record{Op: wal.OpMkdir, Path: "dir", Mode: 0o755},
			wal.Record{Op: wal.OpRename, Path: "dst", NewPath: "dir/moved"},
			// Unlink parks; a later reap destroys one parked inode.
			wal.Record{Op: wal.OpCreate, Path: "temp", Mode: 0o600},
			wal.Record{Op: wal.OpWrite, Path: "temp", Data: []byte("temporary")},
			wal.Record{Op: wal.OpMkdir, Path: "emptydir", Mode: 0o755},
			wal.Record{Op: wal.OpRemove, Path: "emptydir"},
		)
		tempIno := inoAt(t, live, "temp")
		applyDiff(t, live,
			wal.Record{Op: wal.OpRemove, Path: "temp"},
			wal.Record{Op: wal.OpReap, Ino: tempIno},
		)
	})
}

func TestDifferentialHardLinks(t *testing.T) {
	// Hard links must fold identically through the shared engine: the same
	// inode reachable under several names with a shared nlink, an aliased
	// unlink dropping only a name, and the last-link unlink parking the inode.
	runDifferential(t, func(t *testing.T, live *FS) {
		applyDiff(t, live,
			wal.Record{Op: wal.OpCreate, Path: "base", Mode: 0o644},
			wal.Record{Op: wal.OpWrite, Path: "base", Data: []byte("hardlink-content")},
			wal.Record{Op: wal.OpMkdir, Path: "sub", Mode: 0o755},
			wal.Record{Op: wal.OpLink, Path: "base", NewPath: "alias1"},
			wal.Record{Op: wal.OpLink, Path: "alias1", NewPath: "sub/alias2"},
			// Unlink two names: the inode stays live under the third.
			wal.Record{Op: wal.OpRemove, Path: "base"},
			wal.Record{Op: wal.OpRemove, Path: "alias1"},
			// A fresh file, hard-linked, then the ORIGINAL removed: the alias
			// survives with the content.
			wal.Record{Op: wal.OpCreate, Path: "keep", Mode: 0o600},
			wal.Record{Op: wal.OpWrite, Path: "keep", Data: []byte("kept")},
			wal.Record{Op: wal.OpLink, Path: "keep", NewPath: "keep-alias"},
			wal.Record{Op: wal.OpRemove, Path: "keep"},
		)
	})
}

func TestDifferentialOrphanWriteByIno(t *testing.T) {
	// The parked inode stays writable by ino (open-after-unlink), and the
	// materializer must reproduce those bytes exactly. A durable open pin
	// holds the orphan across the unlink — exactly what a mount's mark_open
	// journals before it unlinks an open file. Without it the asynchronous
	// reap sweep may legitimately destroy the pin-free orphan between
	// commits and the write-by-ino would race ENOENT.
	runDifferential(t, func(t *testing.T, live *FS) {
		applyDiff(t, live,
			wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644},
			wal.Record{Op: wal.OpWrite, Path: "f", Data: []byte("before-unlink")},
		)
		ino := inoAt(t, live, "f")
		if err := live.EstablishSessionWithToken("pfs-diff", 1, "o", 8, "tok"); err != nil {
			t.Fatalf("establish session: %v", err)
		}
		pin := pfc2.Record{
			Kind: pfc2.KindOpenPinChange,
			OpenPinChange: &pfc2.OpenPinChange{
				Session: pfc2.SessionRef{SessionID: "pfs-diff", Generation: 1},
				Ino:     ino,
			},
		}
		if _, err := live.CommitEntry(nil, []pfc2.Record{pin}, ""); err != nil {
			t.Fatalf("open pin: %v", err)
		}
		applyDiff(t, live,
			wal.Record{Op: wal.OpRemove, Path: "f"},
			wal.Record{Op: wal.OpWrite, Ino: ino, Offset: 0, Data: []byte("AFTER")},
			wal.Record{Op: wal.OpTruncate, Ino: ino, Size: 5},
		)
	})
}

func TestDifferentialBatchFrames(t *testing.T) {
	// Managed rows journal one tree record each; the engine folds the same
	// per-row stream the HistoryCut materializer consumes.
	runDifferential(t, func(t *testing.T, live *FS) {
		applyDiff(t, live,
			wal.Record{Op: wal.OpMkdir, Path: "p/q", Mode: 0o755},
			wal.Record{Op: wal.OpCreate, Path: "p/q/a", Mode: 0o644},
			wal.Record{Op: wal.OpWrite, Path: "p/q/a", Data: []byte("batched")},
			wal.Record{Op: wal.OpRename, Path: "p/q/a", NewPath: "p/renamed"},
		)
		applyDiff(t, live, wal.Record{Op: wal.OpCreate, Path: "p/q/b", Mode: 0o600})
		applyDiff(t, live, wal.Record{Op: wal.OpMkdir, Path: "p/q/sub", Mode: 0o700, Excl: true})
	})
}

func TestDifferentialSeededRandomStream(t *testing.T) {
	// Seeded pseudo-random success-only stream: the generator tracks a shadow
	// namespace so every op targets a valid path. ~400 ops cover create,
	// mkdir, write (absolute + append), truncate, chmod/chown/chtimes,
	// rename (replace + fresh), and remove in mixed order.
	runDifferential(t, func(t *testing.T, live *FS) {
		rng := rand.New(rand.NewSource(20260710))
		type entry struct {
			path string
		}
		var files, dirs []entry
		dirs = append(dirs, entry{""})
		nameSeq := 0
		newName := func() string {
			nameSeq++
			return fmt.Sprintf("n%03d", nameSeq)
		}
		pathIn := func(dir string, name string) string {
			if dir == "" {
				return name
			}
			return dir + "/" + name
		}
		for i := 0; i < 400; i++ {
			switch op := rng.Intn(9); {
			case op <= 2: // create file
				d := dirs[rng.Intn(len(dirs))]
				p := pathIn(d.path, newName())
				applyDiff(t, live,
					wal.Record{Op: wal.OpCreate, Path: p, Mode: 0o644},
					wal.Record{Op: wal.OpWrite, Path: p, Data: []byte(p)})
				files = append(files, entry{p})
			case op == 3: // mkdir
				d := dirs[rng.Intn(len(dirs))]
				p := pathIn(d.path, newName())
				applyDiff(t, live, wal.Record{Op: wal.OpMkdir, Path: p, Mode: 0o755})
				dirs = append(dirs, entry{p})
			case op == 4 && len(files) > 0: // write more
				f := files[rng.Intn(len(files))]
				if rng.Intn(2) == 0 {
					applyDiff(t, live, wal.Record{
						Op: wal.OpWrite, Path: f.path, Append: true,
						Data: bytes.Repeat([]byte("+"), rng.Intn(9000)+1)})
				} else {
					applyDiff(t, live, wal.Record{
						Op: wal.OpWrite, Path: f.path, Offset: int64(rng.Intn(5000)),
						Data: bytes.Repeat([]byte("#"), rng.Intn(5000)+1)})
				}
			case op == 5 && len(files) > 0: // truncate
				f := files[rng.Intn(len(files))]
				applyDiff(t, live, wal.Record{
					Op: wal.OpTruncate, Path: f.path, Size: int64(rng.Intn(9000))})
			case op == 6 && len(files) > 0: // metadata
				f := files[rng.Intn(len(files))]
				applyDiff(t, live,
					wal.Record{Op: wal.OpChmod, Path: f.path, Mode: uint32(0o600 + rng.Intn(0o177))},
					wal.Record{Op: wal.OpChown, Path: f.path, UID: uint32(rng.Intn(1000)), ChownSetUID: true},
					wal.Record{Op: wal.OpChtimes, Path: f.path, MtimeMs: int64(rng.Intn(1 << 30))})
			case op == 7 && len(files) > 1: // rename over an existing file (parks)
				src := rng.Intn(len(files))
				dst := rng.Intn(len(files))
				if src == dst {
					break
				}
				applyDiff(t, live, wal.Record{
					Op: wal.OpRename, Path: files[src].path, NewPath: files[dst].path})
				files = append(files[:src], files[src+1:]...)
			case op == 8 && len(files) > 0: // remove (parks)
				victim := rng.Intn(len(files))
				applyDiff(t, live, wal.Record{Op: wal.OpRemove, Path: files[victim].path})
				files = append(files[:victim], files[victim+1:]...)
			}
		}
	})
}
