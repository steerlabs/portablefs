package fstransition

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/errnos"
	"github.com/trendup-ai/portablefs/vcs/internal/pft2"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

const testTsMs = int64(1_700_000_000_000)

type harness struct {
	t      *testing.T
	store  *pft2.MemoryStore
	editor *pft2.Editor
	engine *Engine
	next   uint64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	store := pft2.NewMemoryStore()
	editor, err := pft2.NewEditor(context.Background(), nil, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, store: store, editor: editor, next: 100}
	engine, err := New(Config{
		Tx: editor,
		Alloc: func() (uint64, error) {
			h.next++
			return h.next, nil
		},
		FallbackTsMs: testTsMs,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.engine = engine
	return h
}

func (h *harness) apply(records ...wal.Record) []Outcome {
	h.t.Helper()
	var all []Outcome
	for _, r := range records {
		if r.TsMs == 0 {
			r.TsMs = testTsMs
		}
		outs, err := h.engine.Apply(context.Background(), r)
		if err != nil {
			h.t.Fatalf("apply %v %q: %v", r.Op, r.Path, err)
		}
		all = append(all, outs...)
	}
	return all
}

func (h *harness) applyExpect(r wal.Record, want error) {
	h.t.Helper()
	if r.TsMs == 0 {
		r.TsMs = testTsMs
	}
	outs, err := h.engine.Apply(context.Background(), r)
	if err != nil {
		h.t.Fatalf("apply %v %q infrastructure error: %v", r.Op, r.Path, err)
	}
	if len(outs) != 1 || !errors.Is(outs[0].Err, want) {
		h.t.Fatalf("apply %v %q outcome = %+v, want %v", r.Op, r.Path, outs, want)
	}
}

func (h *harness) commit() (*pft2.CommitResult, *pft2.TreeReader) {
	h.t.Helper()
	res, err := h.editor.Commit(context.Background(), h.store, h.store)
	if err != nil {
		h.t.Fatal(err)
	}
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: h.store}, res.Root)
	if err != nil {
		h.t.Fatal(err)
	}
	return res, reader
}

func (h *harness) inode(reader *pft2.TreeReader, ino uint64) pft2.Inode {
	h.t.Helper()
	view, err := reader.GetInode(context.Background(), ino)
	if err != nil {
		h.t.Fatalf("GetInode %d: %v", ino, err)
	}
	return view.Inode
}

func (h *harness) lookup(reader *pft2.TreeReader, path string) (pft2.Inode, bool) {
	h.t.Helper()
	ctx := context.Background()
	view, err := reader.GetInode(ctx, pft2.RootIno)
	if err != nil {
		h.t.Fatal(err)
	}
	cur := view
	clean := cleanPath(path)
	if clean == "" {
		return cur.Inode, true
	}
	for _, part := range splitPath(clean) {
		entry, err := reader.Lookup(ctx, cur.Ref, part)
		if err != nil {
			if errors.Is(err, pft2.ErrNotFound) {
				return pft2.Inode{}, false
			}
			h.t.Fatalf("lookup %q: %v", part, err)
		}
		cur, err = reader.GetInode(ctx, entry.Ino)
		if err != nil {
			h.t.Fatalf("get inode %d: %v", entry.Ino, err)
		}
	}
	return cur.Inode, true
}

func splitPath(p string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			if i > start {
				out = append(out, p[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func (h *harness) readFile(reader *pft2.TreeReader, inode pft2.Inode) []byte {
	h.t.Helper()
	ctx := context.Background()
	out := make([]byte, inode.Size)
	if inode.ExtentRoot == nil {
		return out
	}
	view, err := reader.GetInode(ctx, inode.Ino)
	if err != nil {
		h.t.Fatal(err)
	}
	extents, err := reader.ReadExtents(ctx, view.Ref, 0, inode.Size)
	if err != nil {
		h.t.Fatalf("read extents: %v", err)
	}
	for _, ext := range extents {
		if ext.Cell == nil {
			h.t.Fatalf("unexpected legacy extent in fresh tree")
		}
		raw, err := h.store.Fetch(ctx, ext.Cell.Object)
		if err != nil {
			h.t.Fatal(err)
		}
		cell := raw[ext.Cell.ObjectOffset : ext.Cell.ObjectOffset+pft2.CellBytes]
		copy(out[ext.FileOffset:ext.FileOffset+ext.Length], cell[:ext.Length])
	}
	return out
}

func TestEngineCreateWriteRenameUnlinkReap(t *testing.T) {
	h := newHarness(t)
	body := bytes.Repeat([]byte("portablefs!"), 1200) // ~13 KB, crosses cells
	h.apply(
		wal.Record{Op: wal.OpMkdir, Path: "a/b", Mode: 0o755, Inos: []uint64{11, 12}},
		wal.Record{Op: wal.OpCreate, Path: "a/b/f.txt", Mode: 0o644, Ino: 20},
		wal.Record{Op: wal.OpWrite, Path: "a/b/f.txt", Data: body},
		wal.Record{Op: wal.OpWrite, Path: "a/b/f.txt", Offset: 5, Data: []byte("XYZ")},
		wal.Record{Op: wal.OpRename, Path: "a/b/f.txt", NewPath: "a/moved.txt"},
	)
	want := append([]byte{}, body...)
	copy(want[5:], []byte("XYZ"))

	// Unlink parks; reap destroys.
	outs := h.apply(wal.Record{Op: wal.OpCreate, Path: "a/gone", Mode: 0o600, Ino: 30})
	if !outs[0].Changed {
		t.Fatal("create should change the tree")
	}
	outs = h.apply(wal.Record{Op: wal.OpRemove, Path: "a/gone"})
	if outs[0].OrphanIno != 30 {
		t.Fatalf("unlink parked ino %d, want 30", outs[0].OrphanIno)
	}
	if got := h.engine.Orphans(); len(got) != 1 || got[0] != 30 {
		t.Fatalf("orphan set = %v", got)
	}
	h.apply(wal.Record{Op: wal.OpReap, Ino: 30})
	if got := h.engine.Orphans(); len(got) != 0 {
		t.Fatalf("orphan set after reap = %v", got)
	}

	res, reader := h.commit()
	if res.OrphanIndex != nil {
		t.Fatal("reaped orphan must not persist an orphan index")
	}
	moved, ok := h.lookup(reader, "a/moved.txt")
	if !ok || moved.Ino != 20 || moved.Kind != pft2.FileKindRegular {
		t.Fatalf("moved = %+v ok=%v", moved, ok)
	}
	if got := h.readFile(reader, moved); !bytes.Equal(got, want) {
		t.Fatalf("content mismatch: %d bytes vs %d", len(got), len(want))
	}
	if _, ok := h.lookup(reader, "a/b/f.txt"); ok {
		t.Fatal("old name still resolves")
	}
	if res.RootFacts.MaxInoSeen < 20 {
		t.Fatalf("root MaxInoSeen = %d, want >= 20", res.RootFacts.MaxInoSeen)
	}
	// The ENGINE's high-water covers the reaped inode too — this is the
	// monotone allocator watermark the materializer persists to the branch
	// namespace, so a reused id can never be handed out again.
	if h.engine.MaxInoSeen() != 30 {
		t.Fatalf("engine MaxInoSeen = %d, want 30 (reaped ino retained)", h.engine.MaxInoSeen())
	}
}

func TestEngineDeterministicOutcomes(t *testing.T) {
	h := newHarness(t)
	h.apply(
		wal.Record{Op: wal.OpMkdir, Path: "d", Mode: 0o755, Inos: []uint64{2}},
		wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644, Ino: 3},
		wal.Record{Op: wal.OpCreate, Path: "d/g", Mode: 0o644, Ino: 4},
	)
	// O_EXCL on existing name.
	h.applyExpect(wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644, Ino: 9, Excl: true}, ErrExist)
	// Idempotent create never clobbers (no error, no change).
	outs := h.apply(wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o600, Ino: 9})
	if outs[0].Changed || outs[0].Err != nil {
		t.Fatalf("idempotent create outcome = %+v", outs[0])
	}
	// mkdir(2) of existing is EEXIST; of missing parent ENOENT; over file ENOTDIR.
	h.applyExpect(wal.Record{Op: wal.OpMkdir, Path: "d", Mode: 0o755, Excl: true, Ino: 9}, ErrExist)
	h.applyExpect(wal.Record{Op: wal.OpMkdir, Path: "nope/x", Mode: 0o755, Excl: true, Ino: 9}, ErrNotExist)
	h.applyExpect(wal.Record{Op: wal.OpMkdir, Path: "d/f/x", Mode: 0o755, Excl: true, Ino: 9}, errNotDir)
	// Remove of a nonempty directory refuses.
	h.applyExpect(wal.Record{Op: wal.OpRemove, Path: "d"}, errNotEmpty)
	// RENAME_NOREPLACE onto existing destination.
	h.applyExpect(wal.Record{Op: wal.OpRename, Path: "d/f", NewPath: "d/g", RenameNoReplace: true}, ErrExist)
	//

	// Rename into own subtree refuses (its own benign-on-replay sentinel).
	h.apply(wal.Record{Op: wal.OpMkdir, Path: "d/sub", Mode: 0o755, Excl: true, Ino: 5})
	h.applyExpect(wal.Record{Op: wal.OpRename, Path: "d", NewPath: "d/sub/d2"}, errInvalidRename)
	// Write to a missing path.
	h.applyExpect(wal.Record{Op: wal.OpWrite, Path: "missing", Data: []byte("x")}, ErrNotExist)
	// Ino-addressed write with a dead ino has NO name fallback.
	h.applyExpect(wal.Record{Op: wal.OpWrite, Path: "d/f", Ino: 999, Data: []byte("x")}, ErrNotExist)
}

func TestEngineRenameReplaceParksDestination(t *testing.T) {
	h := newHarness(t)
	h.apply(
		wal.Record{Op: wal.OpCreate, Path: "src", Mode: 0o644, Ino: 2},
		wal.Record{Op: wal.OpWrite, Path: "src", Data: []byte("source")},
		wal.Record{Op: wal.OpCreate, Path: "dst", Mode: 0o644, Ino: 3},
		wal.Record{Op: wal.OpWrite, Path: "dst", Data: []byte("destination")},
	)
	outs := h.apply(wal.Record{Op: wal.OpRename, Path: "src", NewPath: "dst"})
	if outs[0].OrphanIno != 3 {
		t.Fatalf("replaced destination parked ino %d, want 3", outs[0].OrphanIno)
	}
	// The parked orphan keeps content and stays writable by ino.
	h.apply(wal.Record{Op: wal.OpWrite, Ino: 3, Offset: 0, Data: []byte("PARKED")})
	res, reader := h.commit()
	if res.OrphanIndex == nil {
		t.Fatal("parked orphan must persist an orphan index")
	}
	moved, ok := h.lookup(reader, "dst")
	if !ok || moved.Ino != 2 {
		t.Fatalf("dst = %+v ok=%v", moved, ok)
	}
	if got := h.readFile(reader, moved); string(got) != "source" {
		t.Fatalf("dst content = %q", got)
	}
	// The orphan arm is reachable through the recovery-side index only.
	orphanReader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: h.store}, res.Root)
	if err != nil {
		t.Fatal(err)
	}
	_ = orphanReader
	if len(h.engine.Orphans()) != 1 || h.engine.Orphans()[0] != 3 {
		t.Fatalf("orphans = %v", h.engine.Orphans())
	}
}

func TestEngineAppendResolvesEOFAndChownIntent(t *testing.T) {
	h := newHarness(t)
	h.apply(
		wal.Record{Op: wal.OpCreate, Path: "log", Mode: 0o644, Ino: 2},
		wal.Record{Op: wal.OpWrite, Path: "log", Data: []byte("aaaa")},
	)
	outs := h.apply(wal.Record{Op: wal.OpWrite, Path: "log", Append: true, Data: []byte("bbbb")})
	if outs[0].ResolvedOffset != 4 {
		t.Fatalf("append resolved offset %d, want 4", outs[0].ResolvedOffset)
	}
	h.apply(
		wal.Record{Op: wal.OpChown, Path: "log", UID: 7, ChownSetUID: true},
		wal.Record{Op: wal.OpChown, Path: "log", GID: 8, ChownSetGID: true},
		wal.Record{Op: wal.OpChmod, Path: "log", Mode: 0o600},
		wal.Record{Op: wal.OpChtimes, Path: "log", MtimeMs: 1234, AtimeMs: 77, ChtimesSetAtime: true},
		wal.Record{Op: wal.OpTruncate, Path: "log", Size: 6, TsMs: 4321},
	)
	_, reader := h.commit()
	got, ok := h.lookup(reader, "log")
	if !ok {
		t.Fatal("log missing")
	}
	if got.UID != 7 || got.GID != 8 {
		t.Fatalf("chown intents merged wrong: uid=%d gid=%d", got.UID, got.GID)
	}
	if got.Mode != 0o600 {
		t.Fatalf("mode = %o", got.Mode)
	}
	if got.Size != 6 {
		t.Fatalf("size = %d", got.Size)
	}
	if got.MtimeMs != 4321 || got.AtimeMs != 77 {
		t.Fatalf("times = mtime %d atime %d", got.MtimeMs, got.AtimeMs)
	}
	if got.Nlink != 1 {
		t.Fatalf("nlink = %d", got.Nlink)
	}
	if content := h.readFile(reader, got); string(content) != "aaaabb" {
		t.Fatalf("content = %q", content)
	}
}

func TestEngineHardlinkAliasesShareContentAndNlink(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.apply(
		wal.Record{Op: wal.OpMkdir, Path: "d", Mode: 0o755, Inos: []uint64{2}},
		wal.Record{Op: wal.OpCreate, Path: "d/one", Mode: 0o644, Ino: 3},
		wal.Record{Op: wal.OpWrite, Path: "d/one", Data: []byte("shared")},
	)
	if err := h.engine.Link(ctx, "d", "two", 3, testTsMs); err != nil {
		t.Fatal(err)
	}
	if err := h.engine.Link(ctx, "", "three", 3, testTsMs); err != nil {
		t.Fatal(err)
	}
	// A directory can never alias.
	if err := h.engine.Link(ctx, "", "dirlink", 2, testTsMs); !errors.Is(err, errIsDir) {
		t.Fatalf("directory link error = %v", err)
	}
	// Unlink one alias: nlink decrements, nothing parks.
	outs := h.apply(wal.Record{Op: wal.OpRemove, Path: "d/two"})
	if outs[0].OrphanIno != 0 {
		t.Fatalf("alias unlink parked %d", outs[0].OrphanIno)
	}
	_, reader := h.commit()
	one, ok := h.lookup(reader, "d/one")
	if !ok || one.Nlink != 2 {
		t.Fatalf("one = %+v ok=%v (want nlink 2)", one, ok)
	}
	three, ok := h.lookup(reader, "three")
	if !ok || three.Ino != one.Ino {
		t.Fatalf("three = %+v, want ino %d", three, one.Ino)
	}
	if got := h.readFile(reader, three); string(got) != "shared" {
		t.Fatalf("aliased content = %q", got)
	}
}

// TestOutcomeWireStatusParity pins every deterministic engine outcome to the
// exact errnos.Of wire status the live authority stores for the same
// failure, so a materialized exact outcome is byte-identical to the
// live/replayed one. Also pins the identity-observation and benign-envless
// classification contracts.
func TestOutcomeWireStatusParity(t *testing.T) {
	h := newHarness(t)
	h.apply(
		wal.Record{Op: wal.OpMkdir, Path: "d", Mode: 0o755, Inos: []uint64{2}},
		wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644, Ino: 3},
		wal.Record{Op: wal.OpCreate, Path: "d/g", Mode: 0o644, Ino: 4},
	)
	cases := []struct {
		name   string
		record wal.Record
		want   int32
		benign bool // benign for an env-less CURRENT-timestamp record
	}{
		{"missing target write", wal.Record{Op: wal.OpWrite, Path: "nope", Data: []byte("x")}, errnos.ENOENT, false},
		{"missing target remove", wal.Record{Op: wal.OpRemove, Path: "nope"}, errnos.ENOENT, true},
		{"excl create over existing", wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644, Ino: 9, Excl: true}, errnos.EEXIST, false},
		{"link over directory source", wal.Record{Op: wal.OpLink, Path: "d", NewPath: "alias"}, errnos.EPERM, false},
		{"mkdir under a file", wal.Record{Op: wal.OpMkdir, Path: "d/f/x", Mode: 0o755, Excl: true, Ino: 9}, errnos.ENOTDIR, true},
		{"rename file over nonempty dir", wal.Record{Op: wal.OpRename, Path: "d/f", NewPath: "d"}, errnos.EISDIR, true},
		{"remove nonempty dir", wal.Record{Op: wal.OpRemove, Path: "d"}, errnos.ENOTEMPTY, true},
		{"rename into own subtree", wal.Record{Op: wal.OpRename, Path: "d", NewPath: "d/sub"}, errnos.EINVAL, true},
		{"negative truncate", wal.Record{Op: wal.OpTruncate, Path: "d/f", Size: -1}, errnos.EINVAL, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.record
			r.TsMs = testTsMs
			outs, err := h.engine.Apply(context.Background(), r)
			if err != nil {
				t.Fatalf("infrastructure error: %v", err)
			}
			if len(outs) != 1 || outs[0].Err == nil {
				t.Fatalf("outcome = %+v, want a deterministic failure", outs)
			}
			if got := errnos.Of(outs[0].Err); got != tc.want {
				t.Fatalf("wire status %d, want %d (err %v)", got, tc.want, outs[0].Err)
			}
			if got := BenignEnvlessOutcome(r.Op, r.TsMs, outs[0].Err); got != tc.benign {
				t.Fatalf("benign-envless = %v, want %v (err %v)", got, tc.benign, outs[0].Err)
			}
		})
	}

	// The legacy zero-timestamp escape: ENOENT on write/truncate only.
	if !BenignEnvlessOutcome(wal.OpWrite, 0, ErrNotExist) || BenignEnvlessOutcome(wal.OpWrite, testTsMs, ErrNotExist) {
		t.Fatal("write ENOENT benign-envless gate must be TsMs==0 exactly")
	}

	// Identity observation is unconditional: the failed excl create and the
	// unused mkdir member above must have advanced the local watermarks.
	if got := h.engine.MaxLocalSeen(0); got != 9 {
		t.Fatalf("flat local watermark %d, want 9 (burned failure identity observed)", got)
	}
}

func TestEngineDeterministicRerunProducesIdenticalRoot(t *testing.T) {
	stream := []wal.Record{
		{Op: wal.OpMkdir, Path: "x/y/z", Mode: 0o755, Inos: []uint64{2, 3, 4}, TsMs: testTsMs},
		{Op: wal.OpCreate, Path: "x/y/z/f", Mode: 0o644, Ino: 5, TsMs: testTsMs},
		{Op: wal.OpWrite, Path: "x/y/z/f", Data: bytes.Repeat([]byte{7}, 9000), TsMs: testTsMs},
		{Op: wal.OpBatch, TsMs: testTsMs, Mutations: []wal.Record{
			{Op: wal.OpCreate, Path: "x/batch", Mode: 0o600, Ino: 6, TsMs: testTsMs},
			{Op: wal.OpRename, Path: "x/batch", NewPath: "x/y/renamed", TsMs: testTsMs},
			{Op: wal.OpChmod, Path: "x/y/renamed", Mode: 0o400, TsMs: testTsMs},
		}},
		{Op: wal.OpRemove, Path: "x/y/z/f", TsMs: testTsMs},
	}
	roots := make([]string, 2)
	orphans := make([][]uint64, 2)
	for i := range roots {
		h := newHarness(t)
		for _, r := range stream {
			if _, err := h.engine.Apply(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		}
		res, _ := h.commit()
		roots[i] = res.Root.Hex()
		orphans[i] = h.engine.Orphans()
	}
	if roots[0] != roots[1] {
		t.Fatalf("rerun roots diverge: %s vs %s", roots[0], roots[1])
	}
	if !equalU64s(orphans[0], orphans[1]) {
		t.Fatalf("rerun orphan sets diverge: %v vs %v", orphans[0], orphans[1])
	}
}

func equalU64s(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
