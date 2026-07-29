package clientcore

import (
	"context"
	"sort"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func lsEntries(t *testing.T, v *Volume, dir string) []DirEntry {
	t.Helper()
	ents, st := v.Readdir(context.Background(), dir)
	if st != fsproto.OK {
		t.Fatalf("readdir %q: %d", dir, st)
	}
	return ents
}

func lsNames(t *testing.T, v *Volume, dir string) map[string]bool {
	t.Helper()
	ents := lsEntries(t, v, dir)
	names := map[string]bool{}
	for _, e := range ents {
		names[e.Name] = true
	}
	return names
}

func lsNameList(t *testing.T, v *Volume, dir string) []string {
	t.Helper()
	ents := lsEntries(t, v, dir)
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	return names
}

func assertNames(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("names=%v want=%v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("names=%v want=%v", got, want)
		}
	}
}

// TestWriteBackReaddirReflectsOwnMutations pins M1: on a write-back mount the dirCache must never hide
// the mount's OWN created/removed files. The authority owner-suppresses self-write invalidations, so a
// held directory's version never advances for our writes; a cached listing (get/store not session-gated,
// and the write-back Create/Remove branches not evicting) would then keep serving the pre-mutation
// enumeration until the session releases. Before and after a flush, ls must show a just-created child
// and drop a just-removed one.
func TestWriteBackReaddirReflectsOwnMutations(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:  "wb-ls",
		WALDir: t.TempDir(),
	})

	if _, st := v.Mkdir(ctx, "D", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir D: %d", st)
	}
	if _, st := v.Create(ctx, "D/y", 0o644); st != fsproto.OK {
		t.Fatalf("create D/y: %d", st)
	}
	if err := v.FlushToAuthority(ctx); err != nil {
		t.Fatalf("flush seed: %v", err)
	}

	// Warm the dir listing (pre-mutation state: only y).
	if names := lsNames(t, v, "D"); !names["y"] {
		t.Fatalf("warm ls D missing y: %v", names)
	}

	// Create a new child, flush, then ls must show it.
	if _, st := v.Create(ctx, "D/x", 0o644); st != fsproto.OK {
		t.Fatalf("create D/x: %d", st)
	}
	if names := lsNames(t, v, "D"); !names["x"] || !names["y"] {
		t.Fatalf("ls D before flush after touch D/x must show x and y, got %v", names)
	}
	if err := v.FlushToAuthority(ctx); err != nil {
		t.Fatalf("flush after create: %v", err)
	}
	if names := lsNames(t, v, "D"); !names["x"] || !names["y"] {
		t.Fatalf("ls D after touch D/x must show x and y, got %v", names)
	}

	// Remove a child, flush, then ls must drop it.
	if st := v.Remove(ctx, "D/y", nil); st != fsproto.OK {
		t.Fatalf("remove D/y: %d", st)
	}
	if names := lsNames(t, v, "D"); names["y"] {
		t.Fatalf("ls D before flush after rm D/y must not show y, got %v", names)
	}
	if err := v.FlushToAuthority(ctx); err != nil {
		t.Fatalf("flush after remove: %v", err)
	}
	if names := lsNames(t, v, "D"); names["y"] {
		t.Fatalf("ls D after rm D/y must not show y, got %v", names)
	}
}

func TestWriteBackReaddirMergesOverlayBeforeFlush(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	seed := dialCore(t, addr, Options{})
	if _, st := seed.Mkdir(ctx, "D", 0o755); st != fsproto.OK {
		t.Fatalf("seed mkdir D: %d", st)
	}
	if _, st := seed.Create(ctx, "D/keep", 0o644); st != fsproto.OK {
		t.Fatalf("seed create D/keep: %d", st)
	}
	if _, st := seed.Create(ctx, "D/drop", 0o644); st != fsproto.OK {
		t.Fatalf("seed create D/drop: %d", st)
	}

	v := dialCore(t, addr, Options{
		Owner:  "wb-merge-ls",
		WALDir: t.TempDir(),
	})
	assertNames(t, lsNameList(t, v, "D"), "drop", "keep")

	for _, name := range []string{"a", "b", "c"} {
		if _, st := v.Create(ctx, "D/"+name, 0o644); st != fsproto.OK {
			t.Fatalf("create D/%s: %d", name, st)
		}
	}
	if _, st := v.Symlink(ctx, "target.txt", "D/link"); st != fsproto.OK {
		t.Fatalf("symlink D/link: %d", st)
	}
	if st := v.Remove(ctx, "D/drop", nil); st != fsproto.OK {
		t.Fatalf("remove D/drop: %d", st)
	}

	before := lsEntries(t, v, "D")
	beforeNames := make([]string, 0, len(before))
	byName := map[string]DirEntry{}
	for _, e := range before {
		beforeNames = append(beforeNames, e.Name)
		byName[e.Name] = e
	}
	sort.Strings(beforeNames)
	assertNames(t, beforeNames, "a", "b", "c", "keep", "link")
	if link := byName["link"]; link.Attr.Kind != "symlink" || link.Attr.Size != int64(len("target.txt")) {
		t.Fatalf("link entry before flush = %+v", link)
	}

	if err := v.FlushToAuthority(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	assertNames(t, lsNameList(t, v, "D"), "a", "b", "c", "keep", "link")
}

func TestWriteBackReaddirTombstonedDirectoryReturnsENOENT(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:  "wb-tombstone-ls",
		WALDir: t.TempDir(),
	})
	// A top-level directory the mount creates itself, with an empty subdir
	// under a held delegation, so the removal tombstones locally.
	if _, st := v.Mkdir(ctx, "P", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir P: %d", st)
	}
	if _, st := v.Mkdir(ctx, "P/D", 0o755); st != fsproto.OK { // delegates P, D born empty
		t.Fatalf("mkdir P/D: %d", st)
	}
	if !v.wb.Covers("P/D") {
		t.Fatal("P/D must be covered by the P delegation")
	}
	if st := v.Remove(ctx, "P/D", nil); st != fsproto.OK {
		t.Fatalf("remove P/D: %d", st)
	}
	// The tombstoned directory reads back ENOENT locally (zero RPCs).
	if ents, st := v.Readdir(ctx, "P/D"); st != fsproto.ENOENT {
		t.Fatalf("readdir tombstoned P/D = ents=%v st=%d, want ENOENT", ents, st)
	}
}
