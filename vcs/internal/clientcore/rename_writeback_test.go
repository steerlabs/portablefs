package clientcore

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestWriteBackRenameAcrossSessionRoots pins the cross-scope rename
// contract: a rename whose two names are covered by DIFFERENT delegations
// (or one delegated and one shared name) drains the acknowledged stream and
// executes atomically write-through at the authority; the engine forgets
// both halves so reads immediately see the moved name. rename(2) callers
// never see EXDEV.
func TestWriteBackRenameAcrossSessionRoots(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()

	v := dialCore(t, addr, Options{
		Owner:  "wb-xroot",
		WALDir: t.TempDir(),
	})
	// The mount creates the top-level directories itself (top-level mkdir is
	// write-through and never delegates); writes into them then delegate
	// each directory to THIS session, so there is no cross-session
	// contention to deny the grants.
	if _, st := v.Mkdir(ctx, "work", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir work: %d", st)
	}
	if _, st := v.Mkdir(ctx, "cache", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir cache: %d", st)
	}
	writeDirty := func(path, payload string) {
		t.Helper()
		a, st := v.Create(ctx, path, 0o644)
		if st != fsproto.OK {
			t.Fatalf("create %s: %d", path, st)
		}
		n := NewNodeState(a.Ino, a.Ino != 0)
		if _, st := v.Write(ctx, path, n, 0, []byte(payload)); st != fsproto.OK {
			t.Fatalf("write %s: %d", path, st)
		}
	}
	writeDirty("work/a.txt", "payload-A")
	writeDirty("cache/b.txt", "stale-B")
	if !v.wb.Covers("work/a.txt") || !v.wb.Covers("cache/b.txt") {
		t.Fatal("test premise: both scopes delegated")
	}

	// Dirty a replaces dirty b across scopes: drained + write-through.
	if st := v.Rename(ctx, "work/a.txt", "cache/b.txt", nil, nil); st != fsproto.OK {
		t.Fatalf("cross-scope rename: status %d, want OK", st)
	}
	if data, st := v.Read(ctx, "cache/b.txt", nil, 0, 64); st != fsproto.OK || string(data) != "payload-A" {
		t.Fatalf("read after rename: %q st=%d", data, st)
	}
	if _, st := v.Lookup(ctx, "work/a.txt"); st != fsproto.ENOENT {
		t.Fatalf("old name lookup = %d, want ENOENT", st)
	}

	// Rename into a root with NO active session (the sn==nil arm).
	writeDirty("work/c.txt", "payload-C")
	if st := v.Rename(ctx, "work/c.txt", "d.txt", nil, nil); st != fsproto.OK {
		t.Fatalf("rename into sessionless root: status %d, want OK", st)
	}
	if data, st := v.Read(ctx, "d.txt", nil, 0, 64); st != fsproto.OK || string(data) != "payload-C" {
		t.Fatalf("read d.txt: %q st=%d", data, st)
	}

	// The results are durable: an independent write-through reader sees both.
	reader := dialCore(t, addr, Options{})
	if data, st := reader.Read(ctx, "cache/b.txt", nil, 0, 64); st != fsproto.OK || string(data) != "payload-A" {
		t.Fatalf("reader cache/b.txt: %q st=%d", data, st)
	}
	if data, st := reader.Read(ctx, "d.txt", nil, 0, 64); st != fsproto.OK || string(data) != "payload-C" {
		t.Fatalf("reader d.txt: %q st=%d", data, st)
	}
}
