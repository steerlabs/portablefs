package pft2

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
)

// ─── semantic oracle ─────────────────────────────────────────────────────────

type oracleInode struct {
	meta     Inode // metadata (roots stripped, size authoritative below)
	data     []byte
	children map[string]DirEntry
	orphan   bool
}

type oracleFS struct {
	inodes map[uint64]*oracleInode
	// graveyard preserves deleted inodes: inode identity is stable, so
	// re-creating a known ino keeps its kind, and the editor's index
	// membership ops never reset content facts staged under the ino.
	graveyard map[uint64]*oracleInode
}

func newGoldenOracle() *oracleFS {
	o := &oracleFS{inodes: map[uint64]*oracleInode{}, graveyard: map[uint64]*oracleInode{}}
	timeMs := int64(1700000000000)
	dir := func(ino uint64, children map[string]DirEntry) {
		o.inodes[ino] = &oracleInode{
			meta:     Inode{Ino: ino, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1, MtimeMs: timeMs, CtimeMs: timeMs},
			children: children,
		}
	}
	file := func(ino uint64, data []byte) {
		o.inodes[ino] = &oracleInode{
			meta: Inode{Ino: ino, Kind: FileKindRegular, Mode: 0o644, Nlink: 1, MtimeMs: timeMs, CtimeMs: timeMs},
			data: data,
		}
	}
	dir(1, map[string]DirEntry{
		"a":     {Name: "a", Ino: 2, Kind: FileKindDirectory},
		"link":  {Name: "link", Ino: 5, Kind: FileKindSymlink},
		"small": {Name: "small", Ino: 6, Kind: FileKindRegular},
	})
	dir(2, map[string]DirEntry{
		"empty":     {Name: "empty", Ino: 3, Kind: FileKindRegular},
		"hello.bin": {Name: "hello.bin", Ino: 4, Kind: FileKindRegular},
	})
	file(3, nil)
	file(4, goldenFileContentA())
	o.inodes[5] = &oracleInode{meta: Inode{
		Ino: 5, Kind: FileKindSymlink, Mode: 0o777, Nlink: 1, MtimeMs: timeMs, CtimeMs: timeMs,
		Size: uint64(len("a/hello.bin")), SymlinkTarget: "a/hello.bin",
	}}
	file(6, []byte("hi\n"))
	return o
}

func (o *oracleFS) liveFS(kind FileKind, includeAny bool) []uint64 {
	var out []uint64
	for ino, inode := range o.inodes {
		if inode.orphan {
			continue
		}
		if includeAny || inode.meta.Kind == kind {
			out = append(out, ino)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (o *oracleFS) orphans() []uint64 {
	var out []uint64
	for ino, inode := range o.inodes {
		if inode.orphan {
			out = append(out, ino)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (o *oracleFS) size(ino uint64) uint64 {
	inode := o.inodes[ino]
	if inode.meta.Kind == FileKindSymlink {
		return uint64(len(inode.meta.SymlinkTarget))
	}
	if inode.meta.Kind == FileKindDirectory {
		return 0
	}
	return uint64(len(inode.data))
}

// referenced reports whether any live directory entry points at ino.
func (o *oracleFS) referenced(ino uint64) bool {
	for _, inode := range o.inodes {
		if inode.orphan || inode.meta.Kind != FileKindDirectory {
			continue
		}
		for _, entry := range inode.children {
			if entry.Ino == ino {
				return true
			}
		}
	}
	return false
}

func (o *oracleFS) counters() (inodes, dirents, logical uint64) {
	for _, inode := range o.inodes {
		if inode.orphan {
			continue
		}
		inodes++
		if inode.meta.Kind == FileKindDirectory {
			dirents += uint64(len(inode.children))
		}
		logical += o.sizeOf(inode)
	}
	return
}

func (o *oracleFS) sizeOf(inode *oracleInode) uint64 {
	switch inode.meta.Kind {
	case FileKindSymlink:
		return uint64(len(inode.meta.SymlinkTarget))
	case FileKindRegular:
		return uint64(len(inode.data))
	default:
		return 0
	}
}

// ─── script interpreter ──────────────────────────────────────────────────────

type scriptReader struct {
	data []byte
	pos  int
}

func (s *scriptReader) next() byte {
	if s.pos >= len(s.data) {
		return 0
	}
	b := s.data[s.pos]
	s.pos++
	return b
}

func (s *scriptReader) pick(n int) int {
	if n <= 0 {
		return 0
	}
	return int(s.next()) % n
}

var fuzzNames = []string{"n0", "n1", "n2", "long-name-for-leaf-pressure", "x", "z9"}

// applyFuzzScript drives the editor and oracle together. Every editor call
// the oracle predicts as valid must succeed; oracle-invalid calls are
// skipped. Returns the number of applied operations.
func applyFuzzScript(t *testing.T, editor *Editor, oracle *oracleFS, script []byte) int {
	t.Helper()
	ctx := context.Background()
	s := &scriptReader{data: script}
	applied := 0
	for s.pos < len(s.data) {
		switch s.next() % 9 {
		case 0: // put (create, refresh, or resurrect) a filesystem inode
			ino := uint64(2 + s.pick(11))
			var meta Inode
			var resurrect *oracleInode
			if existing, ok := oracle.inodes[ino]; ok {
				if existing.orphan {
					continue
				}
				meta = existing.meta
				meta.Mode = uint32(0o600 + s.pick(0o200))
				meta.MtimeMs = int64(1700000000000 + s.pick(1000))
			} else if buried, ok := oracle.graveyard[ino]; ok {
				// Stable inode identity: a re-created ino keeps its kind and
				// (since membership ops never touch content) its bytes.
				resurrect = buried
				meta = buried.meta
				meta.Mode = uint32(0o600 + s.pick(0o200))
			} else {
				kinds := []FileKind{FileKindRegular, FileKindDirectory, FileKindSymlink}
				kind := kinds[s.pick(3)]
				meta = Inode{Ino: ino, Kind: kind, Mode: uint32(0o644), Nlink: 1}
				if kind == FileKindSymlink {
					meta.SymlinkTarget = "target-" + fuzzNames[s.pick(len(fuzzNames))]
					meta.Size = uint64(len(meta.SymlinkTarget))
				}
			}
			if err := editor.PutInode(ctx, meta); err != nil {
				t.Fatalf("PutInode(%d): %v", ino, err)
			}
			if existing, ok := oracle.inodes[ino]; ok {
				existing.meta = meta
			} else if resurrect != nil {
				resurrect.meta = meta
				oracle.inodes[ino] = resurrect
				delete(oracle.graveyard, ino)
			} else {
				inode := &oracleInode{meta: meta}
				if meta.Kind == FileKindDirectory {
					inode.children = map[string]DirEntry{}
				}
				oracle.inodes[ino] = inode
			}
			applied++
		case 1: // delete an unreferenced filesystem inode
			candidates := oracle.liveFS(0, true)
			if len(candidates) == 0 {
				continue
			}
			ino := candidates[s.pick(len(candidates))]
			inode := oracle.inodes[ino]
			if ino == RootIno || oracle.referenced(ino) {
				continue
			}
			if inode.meta.Kind == FileKindDirectory && len(inode.children) > 0 {
				continue
			}
			if err := editor.DeleteInode(ctx, ino); err != nil {
				t.Fatalf("DeleteInode(%d): %v", ino, err)
			}
			delete(oracle.inodes, ino)
			oracle.graveyard[ino] = inode
			applied++
		case 2: // put a directory entry
			dirs := oracle.liveFS(FileKindDirectory, false)
			targets := oracle.liveFS(0, true)
			if len(dirs) == 0 || len(targets) == 0 {
				continue
			}
			parent := dirs[s.pick(len(dirs))]
			target := targets[s.pick(len(targets))]
			if target == RootIno {
				continue
			}
			name := fuzzNames[s.pick(len(fuzzNames))]
			entry := DirEntry{Name: name, Ino: target, Kind: oracle.inodes[target].meta.Kind}
			if err := editor.PutDirEntry(ctx, parent, entry); err != nil {
				t.Fatalf("PutDirEntry(%d,%q->%d): %v", parent, name, target, err)
			}
			oracle.inodes[parent].children[name] = entry
			applied++
		case 3: // delete a directory entry
			dirs := oracle.liveFS(FileKindDirectory, false)
			if len(dirs) == 0 {
				continue
			}
			parent := dirs[s.pick(len(dirs))]
			children := oracle.inodes[parent].children
			if len(children) == 0 {
				continue
			}
			names := make([]string, 0, len(children))
			for name := range children {
				names = append(names, name)
			}
			sort.Strings(names)
			name := names[s.pick(len(names))]
			if err := editor.DeleteDirEntry(ctx, parent, name); err != nil {
				t.Fatalf("DeleteDirEntry(%d,%q): %v", parent, name, err)
			}
			delete(children, name)
			applied++
		case 4, 5: // write or zero one cell
			files := oracle.liveFS(FileKindRegular, false)
			files = append(files, oracle.orphans()...)
			var regular []uint64
			for _, ino := range files {
				if oracle.inodes[ino].meta.Kind == FileKindRegular {
					regular = append(regular, ino)
				}
			}
			if len(regular) == 0 {
				continue
			}
			ino := regular[s.pick(len(regular))]
			cellOffset := uint64(s.pick(8)) * CellBytes
			fill := s.next()
			size := oracle.size(ino)
			cell := make([]byte, CellBytes)
			if fill != 0 && cellOffset < size {
				// Nonzero bytes only within the logical size, so the commit
				// contract (zero suffix beyond EOF) holds.
				valid := size - cellOffset
				if valid > CellBytes {
					valid = CellBytes
				}
				for i := uint64(0); i < valid; i++ {
					cell[i] = fill
				}
			}
			if err := editor.WriteCell(ctx, ino, cellOffset, cell); err != nil {
				t.Fatalf("WriteCell(%d,%d): %v", ino, cellOffset, err)
			}
			inode := oracle.inodes[ino]
			if cellOffset < size {
				end := cellOffset + CellBytes
				if end > size {
					end = size
				}
				copy(inode.data[cellOffset:end], cell[:end-cellOffset])
			}
			applied++
		case 6: // exact truncate
			var regular []uint64
			for _, ino := range append(oracle.liveFS(FileKindRegular, false), oracle.orphans()...) {
				if oracle.inodes[ino].meta.Kind == FileKindRegular {
					regular = append(regular, ino)
				}
			}
			if len(regular) == 0 {
				continue
			}
			ino := regular[s.pick(len(regular))]
			size := uint64(s.pick(9))*(CellBytes/2) + uint64(s.pick(5))*PageBytes
			if err := editor.SetFileSize(ctx, ino, size); err != nil {
				t.Fatalf("SetFileSize(%d,%d): %v", ino, size, err)
			}
			inode := oracle.inodes[ino]
			inode.data = oracleTruncate(inode.data, size)
			applied++
		case 7: // park: drop all names, move to the orphan index
			var candidates []uint64
			for _, ino := range oracle.liveFS(FileKindRegular, false) {
				if ino != RootIno {
					candidates = append(candidates, ino)
				}
			}
			if len(candidates) == 0 {
				continue
			}
			ino := candidates[s.pick(len(candidates))]
			for parentIno, parent := range oracle.inodes {
				if parent.orphan || parent.meta.Kind != FileKindDirectory {
					continue
				}
				for name, entry := range parent.children {
					if entry.Ino != ino {
						continue
					}
					if err := editor.DeleteDirEntry(ctx, parentIno, name); err != nil {
						t.Fatalf("park DeleteDirEntry: %v", err)
					}
					delete(parent.children, name)
				}
			}
			if err := editor.DeleteInode(ctx, ino); err != nil {
				t.Fatalf("park DeleteInode(%d): %v", ino, err)
			}
			meta := oracle.inodes[ino].meta
			if err := editor.PutOrphanInode(ctx, meta); err != nil {
				t.Fatalf("park PutOrphanInode(%d): %v", ino, err)
			}
			oracle.inodes[ino].orphan = true
			applied++
		case 8: // unpark: back to the filesystem under a fresh name
			orphans := oracle.orphans()
			if len(orphans) == 0 {
				continue
			}
			ino := orphans[s.pick(len(orphans))]
			meta := oracle.inodes[ino].meta
			if err := editor.DeleteOrphanInode(ctx, ino); err != nil {
				t.Fatalf("unpark DeleteOrphanInode(%d): %v", ino, err)
			}
			if err := editor.PutInode(ctx, meta); err != nil {
				t.Fatalf("unpark PutInode(%d): %v", ino, err)
			}
			name := fmt.Sprintf("unparked-%d-%d", ino, s.pick(4))
			entry := DirEntry{Name: name, Ino: ino, Kind: meta.Kind}
			if err := editor.PutDirEntry(ctx, RootIno, entry); err != nil {
				t.Fatalf("unpark PutDirEntry: %v", err)
			}
			oracle.inodes[ino].orphan = false
			oracle.inodes[RootIno].children[name] = entry
			applied++
		}
	}
	return applied
}

// verifyAgainstOracle checks a committed root against the oracle: metadata,
// directory structure, file bytes, counters, and the orphan index.
func verifyAgainstOracle(t *testing.T, store *MemoryStore, result *CommitResult, oracle *oracleFS) {
	t.Helper()
	ctx := context.Background()
	reader, err := NewTreeReader(TreeReaderConfig{
		Fetcher: &countingFetcher{store: store},
		Bounds:  ReadBounds{MaxNodes: 1 << 20, MaxBytes: 1 << 62},
	}, result.Root)
	if err != nil {
		t.Fatal(err)
	}

	wantInodes, wantDirents, wantLogical := oracle.counters()
	if result.RootFacts.InodeCount != wantInodes ||
		result.RootFacts.DirentCount != wantDirents ||
		result.RootFacts.LogicalBytes != wantLogical {
		t.Fatalf("counters: got %+v, want inodes=%d dirents=%d logical=%d",
			result.RootFacts, wantInodes, wantDirents, wantLogical)
	}

	for _, ino := range oracle.liveFS(0, true) {
		inode := oracle.inodes[ino]
		view, err := reader.GetInode(ctx, ino)
		if err != nil {
			t.Fatalf("GetInode(%d): %v", ino, err)
		}
		if view.Inode.Kind != inode.meta.Kind || view.Inode.Mode != inode.meta.Mode ||
			view.Inode.Nlink != inode.meta.Nlink || view.Inode.SymlinkTarget != inode.meta.SymlinkTarget {
			t.Fatalf("inode %d metadata mismatch: %+v vs %+v", ino, view.Inode, inode.meta)
		}
		switch inode.meta.Kind {
		case FileKindRegular:
			if view.Inode.Size != uint64(len(inode.data)) {
				t.Fatalf("inode %d size %d, want %d", ino, view.Inode.Size, len(inode.data))
			}
			got := readWholeFile(t, reader, store, ino)
			if !bytes.Equal(got, inode.data) {
				t.Fatalf("inode %d content mismatch", ino)
			}
		case FileKindDirectory:
			var names []string
			cursor := ""
			for {
				entries, next, err := reader.ReadDir(ctx, view.Ref, cursor, 128)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					names = append(names, entry.Name)
					want, ok := inode.children[entry.Name]
					if !ok || want.Ino != entry.Ino || want.Kind != entry.Kind {
						t.Fatalf("dir %d entry %q mismatch", ino, entry.Name)
					}
				}
				if next == "" {
					break
				}
				cursor = next
			}
			if len(names) != len(inode.children) {
				t.Fatalf("dir %d has %d entries, want %d", ino, len(names), len(inode.children))
			}
		}
	}

	// Orphans resolve through the orphan index only (via a probe editor).
	orphans := oracle.orphans()
	if len(orphans) == 0 {
		if result.OrphanIndex != nil {
			t.Fatal("unexpected orphan index")
		}
		return
	}
	if result.OrphanIndex == nil {
		t.Fatal("missing orphan index")
	}
	probe, err := NewEditor(ctx, reader, result.OrphanIndex, EditorLimits{
		MaxFetchNodes: 1 << 20, MaxFetchBytes: 1 << 62,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ino := range orphans {
		inode := oracle.inodes[ino]
		got, found, err := probe.GetOrphanInode(ctx, ino)
		if err != nil || !found {
			t.Fatalf("GetOrphanInode(%d): %v %v", ino, found, err)
		}
		if got.Kind != inode.meta.Kind || got.Size != oracle.sizeOf(inode) {
			t.Fatalf("orphan %d mismatch: %+v", ino, got)
		}
		if _, err := reader.GetInode(ctx, ino); err == nil {
			t.Fatalf("orphan %d still resolves in the filesystem", ino)
		}
	}
}

func fuzzEditorLimits() EditorLimits {
	return EditorLimits{
		MaxEdits: 1 << 20, MaxFetchNodes: 1 << 20, MaxFetchBytes: 1 << 42,
		MaxNewObjects: 1 << 20, MaxNewObjectBytes: 1 << 31,
	}
}

func runEditorScript(t *testing.T, script []byte) {
	t.Helper()
	store := NewMemoryStore()
	rootRef := buildGoldenFilesystem(t, store)
	reader, err := NewTreeReader(TreeReaderConfig{Fetcher: &countingFetcher{store: store}}, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	editor, err := NewEditor(context.Background(), reader, nil, fuzzEditorLimits())
	if err != nil {
		t.Fatal(err)
	}
	oracle := newGoldenOracle()
	applied := applyFuzzScript(t, editor, oracle, script)
	sink := &countingSink{store: store}
	result, err := editor.Commit(context.Background(), sink, sink)
	if err != nil {
		t.Fatalf("commit after %d ops: %v", applied, err)
	}
	verifyAgainstOracle(t, store, result, oracle)
}

func FuzzEditorOps(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 3, 2, 9, 4, 1, 0xEE, 6, 2, 5, 3, 1})
	f.Add([]byte{7, 1, 8, 2, 7, 3, 8, 4})
	f.Add([]byte{4, 0, 0, 0xFF, 6, 0, 8, 4, 0, 1, 0xAA, 6, 0, 0})
	f.Add(bytes.Repeat([]byte{2, 5, 11, 3, 7, 13}, 20))
	f.Add(bytes.Repeat([]byte{0, 9, 1, 2, 3, 4, 5, 6, 7, 8}, 12))
	f.Fuzz(func(t *testing.T, script []byte) {
		if len(script) > 512 {
			script = script[:512]
		}
		runEditorScript(t, script)
	})
}

// TestEditorScriptedScenarios replays the fuzz seeds as a plain test (so the
// oracle machinery always runs in CI even without -fuzz) plus a couple of
// deterministic longer scripts.
func TestEditorScriptedScenarios(t *testing.T) {
	scripts := [][]byte{
		{},
		{0, 3, 2, 9, 4, 1, 0xEE, 6, 2, 5, 3, 1},
		{7, 1, 8, 2, 7, 3, 8, 4},
		{4, 0, 0, 0xFF, 6, 0, 8, 4, 0, 1, 0xAA, 6, 0, 0},
		bytes.Repeat([]byte{2, 5, 11, 3, 7, 13}, 20),
		bytes.Repeat([]byte{0, 9, 1, 2, 3, 4, 5, 6, 7, 8}, 12),
		bytes.Repeat([]byte{4, 1, 2, 0x33, 6, 3, 5, 2, 0, 0x44, 7, 0, 8, 1, 2, 2, 3, 3}, 25),
	}
	for i, script := range scripts {
		script := script
		t.Run(fmt.Sprintf("script-%d", i), func(t *testing.T) {
			runEditorScript(t, script)
		})
	}
}

// TestEditorConcurrentStagingRace stages disjoint edits from many goroutines
// into ONE editor and proves the committed root equals the sequential
// replay. Run under -race this also exercises the editor's locking.
func TestEditorConcurrentStagingRace(t *testing.T) {
	ctx := context.Background()

	stage := func(f *editorFixture, parallel bool) Ref {
		type job struct {
			ino  uint64
			name string
			fill byte
		}
		jobs := make([]job, 12)
		for i := range jobs {
			jobs[i] = job{ino: uint64(50 + i), name: fmt.Sprintf("race-%02d", i), fill: byte(i + 1)}
		}
		run := func(j job) error {
			if err := f.editor.PutInode(ctx, Inode{Ino: j.ino, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
				return err
			}
			cell := make([]byte, CellBytes)
			for k := range cell {
				cell[k] = j.fill
			}
			if err := f.editor.WriteCell(ctx, j.ino, 0, cell); err != nil {
				return err
			}
			if err := f.editor.SetFileSize(ctx, j.ino, CellBytes); err != nil {
				return err
			}
			if err := f.editor.PutDirEntry(ctx, RootIno, DirEntry{Name: j.name, Ino: j.ino, Kind: FileKindRegular}); err != nil {
				return err
			}
			// Interleave reads to race against writers on shared state.
			if _, err := f.editor.ReadCell(ctx, 4, 0); err != nil {
				return err
			}
			_, _, err := f.editor.GetDirEntry(ctx, RootIno, "small")
			return err
		}
		if parallel {
			var wg sync.WaitGroup
			errs := make([]error, len(jobs))
			for i, j := range jobs {
				wg.Add(1)
				go func(slot int, j job) {
					defer wg.Done()
					errs[slot] = run(j)
				}(i, j)
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
		} else {
			for _, j := range jobs {
				if err := run(j); err != nil {
					t.Fatal(err)
				}
			}
		}
		return f.commit(t).Root
	}

	sequential := stage(newEditorFixture(t, EditorLimits{}), false)
	parallel := stage(newEditorFixture(t, EditorLimits{}), true)
	if sequential != parallel {
		t.Fatal("goroutine count changed the committed root")
	}
}
