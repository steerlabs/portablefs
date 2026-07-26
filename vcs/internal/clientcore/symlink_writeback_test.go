package clientcore

import (
	"context"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
)

// TestWriteBackReadlinkBeforeFlush pins the session-overlay readlink route: on a write-back
// mount a just-created symlink lives only in the session overlay until the flusher ships it,
// so Readlink must answer from the overlay. Resolving at the authority instead races the
// flusher and returns ENOENT for ~one flush interval (observed live as empty readlink through
// the FSKit kernel, which reads exactly st_size bytes after an ENOENT-masked lookup).
func TestWriteBackReadlinkBeforeFlush(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:         "wb-symlink",
		WriteBack:     true,
		WALDir:        t.TempDir(),
		FlushInterval: time.Hour, // never auto-flush: the overlay must serve everything
	})

	a, st := v.Symlink(ctx, "target.txt", "l")
	if st != fsproto.OK {
		t.Fatalf("symlink: %d", st)
	}
	if a.Size != int64(len("target.txt")) {
		t.Fatalf("symlink create attr size = %d, want %d", a.Size, len("target.txt"))
	}
	n := NewNodeState(a.Ino, a.Ino != 0)

	// Unflushed: the authority has never seen the link. The overlay must answer.
	if tgt, st := v.Readlink(ctx, "l"); st != fsproto.OK || tgt != "target.txt" {
		t.Fatalf("readlink before flush = %q/%d, want target.txt/OK", tgt, st)
	}

	// The overlay attr (LocalStat path) must report POSIX symlink size too.
	if ga, gst := v.Getattr(ctx, "l", n); gst != fsproto.OK {
		t.Fatalf("getattr: %d", gst)
	} else if ga.Size != int64(len("target.txt")) {
		t.Fatalf("overlay symlink size = %d, want %d", ga.Size, len("target.txt"))
	}

	// After an explicit flush the authority serves the same answer (route parity).
	if err := v.FlushToAuthority(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if tgt, st := v.Readlink(ctx, "l"); st != fsproto.OK || tgt != "target.txt" {
		t.Fatalf("readlink after flush = %q/%d, want target.txt/OK", tgt, st)
	}
}
