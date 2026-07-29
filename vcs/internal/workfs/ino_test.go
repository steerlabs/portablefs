package workfs

import (
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func snapshotBackendEntries(snap *Snapshot) []backend.Entry {
	entries := make([]backend.Entry, 0, len(snap.Entries))
	for _, e := range snap.Entries {
		entries = append(entries, backend.Entry{
			Path: e.Path, Kind: e.Kind, Mode: e.Mode, Ino: e.Ino,
			MtimeMs: e.MtimeMs, CtimeMs: e.CtimeMs, AtimeMs: e.AtimeMs,
			UID: e.UID, GID: e.GID, LinkTarget: e.LinkTarget,
		})
	}
	return entries
}

// Stage 1 (inode-identity foundation): every inode carries a stable, unique, authority-assigned
// identity that is distinct from its name/path — the basis for correct open-after-unlink, rename,
// and (later) hardlinks. These tests pin that contract.

func newInoTestFS(t *testing.T) *FS {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func inoAt(t *testing.T, fs *FS, p string) uint64 {
	t.Helper()
	n := fs.resolve(p)
	if n == nil {
		t.Fatalf("resolve %q: not found", p)
	}
	return n.ino
}

func apply(t *testing.T, fs *FS, recs ...wal.Record) {
	t.Helper()
	if err := fs.ApplyBatch(recs, ""); err != nil {
		t.Fatalf("apply %+v: %v", recs, err)
	}
}

// Every inode gets a non-zero, unique identity; root is always inode 1.
func TestInodeIdentityAllocation(t *testing.T) {
	fs := newInoTestFS(t)
	if fs.root.ino != 1 {
		t.Fatalf("root ino = %d, want 1", fs.root.ino)
	}
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644},
		wal.Record{Op: wal.OpCreate, Path: "b", Mode: 0o644},
		wal.Record{Op: wal.OpMkdir, Path: "d", Mode: 0o755},
		wal.Record{Op: wal.OpSymlink, Path: "s", Target: "a"},
	)
	seen := map[uint64]string{1: "/"}
	for _, p := range []string{"a", "b", "d", "s"} {
		ino := inoAt(t, fs, p)
		if ino == 0 {
			t.Fatalf("%q has ino 0 (unallocated)", p)
		}
		if prev, dup := seen[ino]; dup {
			t.Fatalf("%q ino %d collides with %q", p, ino, prev)
		}
		seen[ino] = p
	}
}

// Identity is NOT the name: it survives a rename unchanged (required so an open fd / SQLite's
// fileHasMoved sees the same st_ino after a move).
func TestInodeIdentitySurvivesRename(t *testing.T) {
	fs := newInoTestFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644})
	before := inoAt(t, fs, "a")
	apply(t, fs, wal.Record{Op: wal.OpRename, Path: "a", NewPath: "b"})
	if fs.resolve("a") != nil {
		t.Fatal("old name still resolves after rename")
	}
	if after := inoAt(t, fs, "b"); after != before {
		t.Fatalf("ino changed across rename: before=%d after=%d (must be stable)", before, after)
	}
}

// Delete + recreate at the same path yields a NEW identity (no aliasing — the core bug behind
// orphan vs. recreated-file st_ino collisions).
func TestInodeIdentityNoAliasOnRecreate(t *testing.T) {
	fs := newInoTestFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644})
	first := inoAt(t, fs, "a")
	apply(t, fs, wal.Record{Op: wal.OpRemove, Path: "a"})
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644})
	if second := inoAt(t, fs, "a"); second == first {
		t.Fatalf("recreated file reused ino %d (aliasing — identities must not be reused)", first)
	}
}

// mkdir -p allocates a distinct identity for every component it creates in one op.
func TestInodeIdentityMkdirAll(t *testing.T) {
	fs := newInoTestFS(t)
	apply(t, fs, wal.Record{Op: wal.OpMkdir, Path: "x/y/z", Mode: 0o755})
	seen := map[uint64]bool{1: true}
	for _, p := range []string{"x", "x/y", "x/y/z"} {
		ino := inoAt(t, fs, p)
		if ino == 0 || seen[ino] {
			t.Fatalf("%q ino %d invalid or duplicate", p, ino)
		}
		seen[ino] = true
	}
}

// Persisted identities are restored verbatim on reconstruction; entries from a pre-identity
// manifest (Ino==0) get fresh ids; nextIno clears the highest restored id so later creates never
// collide with a restored one. (This is the crash/restart-stability contract for st_ino.)
func TestInodeIdentityPersistRestore(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	entries := []backend.Entry{
		{Path: "a", Kind: "file", Mode: 0o644, Ino: 5},
		{Path: "d", Kind: "directory", Mode: 0o755, Ino: 9},
		{Path: "d/f", Kind: "file", Mode: 0o644, Ino: 7},
		{Path: "old", Kind: "file", Mode: 0o644}, // Ino == 0: entry from a pre-identity manifest
	}
	fs, err := New(entries, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want uint64
	}{{"a", 5}, {"d", 9}, {"d/f", 7}} {
		if got := inoAt(t, fs, tc.path); got != tc.want {
			t.Fatalf("%q restored ino = %d, want %d (must be verbatim)", tc.path, got, tc.want)
		}
	}
	// The pre-identity entry gets a fresh id beyond the highest restored (9).
	oldIno := inoAt(t, fs, "old")
	if oldIno <= 9 {
		t.Fatalf("pre-identity entry got ino %d, want a fresh id > 9 (the max restored)", oldIno)
	}
	// A brand-new create clears every restored + filled id (no collision).
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "new", Mode: 0o644})
	if newIno := inoAt(t, fs, "new"); newIno <= oldIno {
		t.Fatalf("new create got ino %d, want > %d (must never reuse)", newIno, oldIno)
	}
}

// TestReplayUsesLoggedCreateIno guards the crash-recovery path of the ino-addressed handle model:
// a replayed create must restore the ino RECORDED IN THE WAL, not re-derive a fresh one from the
// reloaded allocator. A checkpoint that compacts earlier create/remove churn drops the allocator
// high-water, so a replay that re-numbered the file would give it a DIFFERENT ino — and the
// ino-addressed (HandleIno) write logged against it would then miss byIno and be lost or misrouted.
func TestReplayUsesLoggedCreateIno(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	// Records exactly as a primary logs them: the create carries a high identity (100, far above any
	// reloaded base id — the post-compaction shape), and an ino-addressed write targets that id.
	if err := w.Append(wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644, Ino: 100}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(wal.Record{Op: wal.OpWrite, Path: "a", Ino: 100, Offset: 0, Data: []byte("HANDLE")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w2, err := wal.Open(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w2) // empty base: max id well below 100
	if err != nil {
		t.Fatal(err)
	}
	if got := inoAt(t, fs, "a"); got != 100 {
		t.Fatalf("replayed create ino = %d, want 100 (the logged ino must win so ino-addressed ops resolve)", got)
	}
	if got := readAllAt(t, fs, "a"); string(got) != "HANDLE" {
		t.Fatalf("content after replay = %q, want %q (the ino-100 write must reach the replayed inode)", got, "HANDLE")
	}
}

// TestReplayHandleWriteToMissingInoSkips guards the STRICT (no-name-fallback) handle resolution: a
// replayed ino-addressed write whose ino is absent from byIno — a legacy pre-identity WAL that
// re-numbered the create, or a reaped inode — must FAIL CLOSED (skip), never fall back to the name.
// Falling back would land the stale write on a same-name file that was unlinked + recreated (the
// WRONG generation) — the exact corruption ino-addressing exists to prevent. The benign ENOENT is
// skipped by tolerant replay, so the recreated name stays intact and recovery does not halt.
func TestReplayHandleWriteToMissingInoSkips(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []wal.Record{
		{Op: wal.OpCreate, Path: "f", Mode: 0o644},                       // legacy create (no logged ino)
		{Op: wal.OpRemove, Path: "f"},                                    // unlink it
		{Op: wal.OpCreate, Path: "f", Mode: 0o644},                       // a DISTINCT new inode, same name
		{Op: wal.OpWrite, Path: "f", Ino: 999999, Data: []byte("STALE")}, // stale handle write, ino not in byIno
	} {
		if err := w.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := wal.Open(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w2)
	if err != nil {
		t.Fatalf("replay must not halt on a stale-ino handle write: %v", err)
	}
	if got := readAllAt(t, fs, "f"); len(got) != 0 {
		t.Fatalf("same-name file corrupted by stale-ino handle write: content = %q, want empty", got)
	}
}

// TestRenameOverDropsReplacedInoFromIndex guards the by-ino handle index against a leak: an ordinary
// rename-over of a NOT-open destination destroys the replaced inode, so it must leave byIno —
// otherwise a detached inode (neither named nor parked) lingers and a stray handle op could mutate
// something that will never checkpoint.
func TestRenameOverDropsReplacedInoFromIndex(t *testing.T) {
	fs := newInoTestFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "src", Mode: 0o644},
		wal.Record{Op: wal.OpCreate, Path: "dst", Mode: 0o644},
	)
	replaced := inoAt(t, fs, "dst")
	apply(t, fs, wal.Record{Op: wal.OpRename, Path: "src", NewPath: "dst"})

	fs.mu.Lock()
	_, leaked := fs.byIno[replaced]
	moved := fs.resolve("dst")
	_, indexed := fs.byIno[moved.ino]
	fs.mu.Unlock()
	if leaked {
		t.Fatalf("replaced destination ino %d still in byIno after rename-over (leak)", replaced)
	}
	if !indexed {
		t.Fatalf("moved inode %d missing from byIno after rename (must stay addressable)", moved.ino)
	}
}
