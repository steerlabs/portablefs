package clientcore

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestWriteToParkedInodeGoesDirectToOrphan pins that a write on a node whose
// orphanIno is set (the file was unlinked while this handle held it open)
// lands on the parked inode by ino — never a path-addressed write that would
// ENOENT against the vanished name.
func TestWriteToParkedInodeGoesDirectToOrphan(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{Owner: "orphan-writer"})

	a, st := v.Create(ctx, "orph", 0o644)
	if st != fsproto.OK || a.Ino == 0 {
		t.Fatalf("create: ino=%d st=%d", a.Ino, st)
	}
	// Hold the file open (create+open already registered the pin) so the
	// authority parks — not reaps — the inode on unlink.
	n := NewNodeState(a.Ino, true)
	if st := v.RegisterOpened(context.Background(), "orph", n); st != fsproto.OK {
		t.Fatalf("open: %d", st)
	}
	if _, st := v.Write(ctx, "orph", n, 0, []byte("AAAA")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	// Unlink while open: the inode parks and the node redirects to it.
	if st := v.Remove(ctx, "orph", n); st != fsproto.OK {
		t.Fatalf("remove while open: %d", st)
	}
	parkedIno := n.Orphan()
	if parkedIno == 0 {
		t.Fatal("unlink-while-open did not park the inode on the node")
	}

	// A write now goes straight to the parked inode.
	cnt, st := v.Write(ctx, "orph", n, 0, []byte("BBBB"))
	if st != fsproto.OK || cnt != 4 {
		t.Fatalf("write to parked inode: cnt=%d st=%d", cnt, st)
	}
	data, rst, rerr := v.client.ReadOrphan(parkedIno, 0, 4)
	if rerr != nil || rst != fsproto.OK || string(data) != "BBBB" {
		t.Fatalf("parked inode should hold the write: %q st=%d err=%v", data, rst, rerr)
	}
	// The vanished name no longer resolves.
	if _, st := v.Lookup(ctx, "orph"); st != fsproto.ENOENT {
		t.Fatalf("orphaned name lookup = %d, want ENOENT", st)
	}
}
