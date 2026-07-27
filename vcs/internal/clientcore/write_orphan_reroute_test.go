package clientcore

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestRerouteOrphanedWriteUsesParkedInoOverProbe pins P3: when a write is rejected with ErrOrphaned
// and the node already carries a parked orphanIno (set by the concurrent unlink), the reroute must use
// that ino DIRECTLY, not fall back to the RedirectToOrphan stable-ino probe. For an uncommitted
// write-back file the stable ino is a path-hash the authority can't resolve as an orphan, so
// probing first would EIO where the parked ino succeeds.
func TestRerouteOrphanedWriteUsesParkedInoOverProbe(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	seed := dialCore(t, addr, Options{})

	a, st := seed.Create(ctx, "orph", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	realIno := a.Ino
	if realIno == 0 {
		t.Fatal("authority did not assign a real inode")
	}
	n0 := NewNodeState(realIno, true)
	if _, st := seed.Write(ctx, "orph", n0, 0, []byte("AAAA")); st != fsproto.OK {
		t.Fatalf("seed write: %d", st)
	}

	// Park the inode at the authority (delete-on-last-close), yielding the orphan ino to address.
	parkedIno, ost, oerr := seed.client.Orphan("orph")
	if oerr != nil || ost != fsproto.OK || parkedIno == 0 {
		t.Fatalf("orphan: ino=%d st=%d err=%v", parkedIno, ost, oerr)
	}

	// A node with a PATH-HASH stable ino (uncommitted write-back file, authIno=false) that the
	// RedirectToOrphan probe cannot resolve, but whose parked orphanIno is the real parked inode.
	nWrite := NewNodeState(InoOf("orph"), false)
	seed.incOpen("orph", nWrite) // nopen=1 so markOrphan takes and IsOpen() is true
	if !nWrite.MarkOrphan(parkedIno, seed.openOrphans) {
		t.Fatal("MarkOrphan should set the parked ino")
	}
	if seed.RedirectToOrphan(nWrite) != 0 {
		t.Fatal("precondition: RedirectToOrphan must MISS on the path-hash stable ino")
	}

	cnt, st := seed.rerouteOrphanedWrite(nWrite, 0, []byte("BBBB"))
	if st != fsproto.OK || cnt != 4 {
		t.Fatalf("reroute must use the parked ino directly: cnt=%d st=%d", cnt, st)
	}
	data, rst, rerr := seed.client.ReadOrphan(parkedIno, 0, 4)
	if rerr != nil || rst != fsproto.OK || string(data) != "BBBB" {
		t.Fatalf("parked inode should hold the rerouted write: %q st=%d err=%v", data, rst, rerr)
	}
}
