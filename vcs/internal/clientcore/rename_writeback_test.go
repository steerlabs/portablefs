package clientcore

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestWriteBackRenameAcrossSessionRoots pins the cross-root rename fix: a
// rename whose two names are governed by DIFFERENT write-back sessions used to
// fail EXDEV, breaking rename(2) callers that never fall back to copy+delete —
// and with file-grain roots on managed authorities that includes the everyday
// tmp -> final atomic-write pattern at the volume root. Both sides now flush
// and the authority executes the rename atomically write-through; each session
// forgets its half so reads immediately see the moved name.
func TestWriteBackRenameAcrossSessionRoots(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()

	// Seed the directories write-through: a top-level mkdir on the write-back
	// volume would acquire the volume-root ("") session, which covers every
	// path and would collapse the two roots this test needs into one.
	seed := dialCore(t, addr, Options{})
	if _, st := seed.Mkdir(ctx, "work", 0o755); st != fsproto.OK {
		t.Fatalf("seed mkdir work: %d", st)
	}
	if _, st := seed.Mkdir(ctx, "cache", 0o755); st != fsproto.OK {
		t.Fatalf("seed mkdir cache: %d", st)
	}

	v := dialCore(t, addr, Options{
		Owner:         "wb-xroot",
		WriteBack:     true,
		WALDir:        t.TempDir(),
		FlushInterval: time.Hour, // only the rename path itself may flush
	})
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
	so, sn := v.sessions.For("work/a.txt"), v.sessions.For("cache/b.txt")
	if so == nil || sn == nil || so == sn {
		t.Fatalf("test premise: want two distinct sessions, got %p and %p", so, sn)
	}

	// Dirty a replaces dirty b across roots: OK now (this returned EXDEV before).
	if st := v.Rename(ctx, "work/a.txt", "cache/b.txt", nil, nil); st != fsproto.OK {
		t.Fatalf("cross-root rename: status %d, want OK", st)
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
