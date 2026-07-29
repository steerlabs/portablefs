package clientcore

import (
	"context"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// TestVolumeXattrRoundtrip: the frontend-neutral volume surface —
// set/get/list/remove/overwrite/remove-missing — write-through against the
// authority.
func TestVolumeXattrRoundtrip(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	ctx := context.Background()

	a, st := v.Create(ctx, "x.txt", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.Setxattr(ctx, "x.txt", n, "user.a", []byte("v1")); st != fsproto.OK {
		t.Fatalf("setxattr: %d", st)
	}
	if st := v.Setxattr(ctx, "x.txt", n, "user.a", []byte("v2")); st != fsproto.OK {
		t.Fatalf("overwrite: %d", st)
	}
	if st := v.Setxattr(ctx, "x.txt", n, "user.b", []byte("vb")); st != fsproto.OK {
		t.Fatalf("setxattr: %d", st)
	}
	if value, st := v.Getxattr(ctx, "x.txt", n, "user.a"); st != fsproto.OK || string(value) != "v2" {
		t.Fatalf("getxattr = %q st=%d", value, st)
	}
	if names, st := v.Listxattr(ctx, "x.txt", n); st != fsproto.OK || strings.Join(names, ",") != "user.a,user.b" {
		t.Fatalf("listxattr = %v st=%d", names, st)
	}
	if _, st := v.Getxattr(ctx, "x.txt", n, "user.absent"); st != fsproto.ENODATA {
		t.Fatalf("get missing = %d, want ENODATA", st)
	}
	if st := v.Removexattr(ctx, "x.txt", n, "user.b"); st != fsproto.OK {
		t.Fatalf("removexattr: %d", st)
	}
	if st := v.Removexattr(ctx, "x.txt", n, "user.b"); st != fsproto.ENODATA {
		t.Fatalf("remove missing = %d, want ENODATA", st)
	}

	// A second mount observes the state read-after-write (no client cache).
	v2 := dialCore(t, addr, Options{Owner: "peer"})
	if value, st := v2.Getxattr(ctx, "x.txt", NewNodeState(a.Ino, true), "user.a"); st != fsproto.OK || string(value) != "v2" {
		t.Fatalf("peer getxattr = %q st=%d", value, st)
	}
}

func TestVolumeConditionalXattrIsOneAuthorityOperation(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{Owner: "xattr-flags"})
	ctx := context.Background()
	a, st := v.Create(ctx, "f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, true)
	if st := v.Setxattr(ctx, "f", n, "user.once", []byte("first")); st != fsproto.OK {
		t.Fatalf("seed xattr: %d", st)
	}
	before := opCount(v)
	if st := v.SetxattrFlags(ctx, "f", n, "user.once", []byte("second"), wal.XattrCreate); st != fsproto.EEXIST {
		t.Fatalf("create-only existing: %d", st)
	}
	if got := opCount(v) - before; got != 1 {
		t.Fatalf("conditional xattr made %d authority operations, want exactly 1", got)
	}
}

// TestVolumeXattrWriteBackFlushFirst: on a write-back mount xattr mutations
// are write-through — the covering session is flushed first, so a locally
// buffered create exists at the authority before its xattr lands, and reads
// against a covered-but-unflushed file answer honestly.
func TestVolumeXattrWriteBackFlushFirst(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{
		Owner:  "wb-mount",
		WALDir: t.TempDir(),
		// A long interval so nothing flushes behind the test's back: the
		// xattr mutation itself must force the flush.
	})
	ctx := context.Background()

	if _, st := v.Mkdir(ctx, "wb", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if _, st := v.Create(ctx, "wb/new.txt", 0o644); st != fsproto.OK {
		t.Fatalf("write-back create: %d", st)
	}
	// The buffered create has not flushed: reads answer "no xattrs yet"
	// (never a confusing ENOENT for a file the kernel just created).
	if names, st := v.Listxattr(ctx, "wb/new.txt", nil); st != fsproto.OK || len(names) != 0 {
		t.Fatalf("unflushed listxattr = %v st=%d", names, st)
	}
	if _, st := v.Getxattr(ctx, "wb/new.txt", nil, "user.a"); st != fsproto.ENODATA {
		t.Fatalf("unflushed getxattr = %d, want ENODATA", st)
	}
	// The mutation flushes the covering session first, then writes through.
	if st := v.Setxattr(ctx, "wb/new.txt", nil, "user.a", []byte("v")); st != fsproto.OK {
		t.Fatalf("write-back setxattr: %d", st)
	}
	if value, st := v.Getxattr(ctx, "wb/new.txt", nil, "user.a"); st != fsproto.OK || string(value) != "v" {
		t.Fatalf("write-back getxattr = %q st=%d", value, st)
	}
	// The flush-first made the FILE itself durable at the authority too: a
	// peer volume sees both the file and its xattr immediately.
	peer := dialCore(t, addr, Options{Owner: "peer"})
	if value, st := peer.Getxattr(ctx, "wb/new.txt", nil, "user.a"); st != fsproto.OK || string(value) != "v" {
		t.Fatalf("peer after write-back setxattr = %q st=%d", value, st)
	}
}
