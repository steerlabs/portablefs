package clientcore

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// noDelegatedXattrFeatureFS models a v6 authority from before delegated-xattr
// flushes were advertised. Embedding preserves the managed coordination
// surface while the explicit false feature marker keeps xattrs on the exact
// authority lane.
type noDelegatedXattrFeatureFS struct{ *workfs.FS }

func (noDelegatedXattrFeatureFS) SupportsAtomicXattrFlags() bool { return false }

func serveCoreWithoutDelegatedXattrs(t *testing.T) string {
	t.Helper()
	fs := newManagedTestFS(t, testBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	wrapped := noDelegatedXattrFeatureFS{FS: fs}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = fsproto.NewServer(wrapped, wrapped).Serve(ctx, ln) }()
	return ln.Addr().String()
}

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

func TestDelegatedXattrEnforcesTotalBeforeAcknowledgement(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{Owner: "xattr-total", WALDir: t.TempDir()})
	ctx := context.Background()
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if _, st := v.Create(ctx, "d/f", 0o644); st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	value := bytes.Repeat([]byte{'x'}, wal.MaxXattrValueBytes)
	if st := v.Setxattr(ctx, "d/f", nil, "user.one", value); st != fsproto.OK {
		t.Fatalf("first max xattr: %d", st)
	}
	if st := v.Setxattr(ctx, "d/f", nil, "user.two", value); st != fsproto.ENOSPC {
		t.Fatalf("over-total delegated xattr = %d, want ENOSPC", st)
	}
	if names, st := v.Listxattr(ctx, "d/f", nil); st != fsproto.OK || strings.Join(names, ",") != "user.one" {
		t.Fatalf("xattr map changed after refused set: %v st=%d", names, st)
	}
	if st := v.FsyncPath("d/f"); st != fsproto.OK {
		t.Fatalf("fsync accepted xattr: %d", st)
	}
}

func TestDelegatedRenameCarriesXattrView(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{Owner: "xattr-rename", WALDir: t.TempDir()})
	ctx := context.Background()
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.Setxattr(ctx, "d/f", n, "user.keep", []byte("value")); st != fsproto.OK {
		t.Fatalf("setxattr: %d", st)
	}
	if st := v.Rename(ctx, "d/f", "d/g", n, nil); st != fsproto.OK {
		t.Fatalf("rename: %d", st)
	}
	if value, st := v.Getxattr(ctx, "d/g", n, "user.keep"); st != fsproto.OK || string(value) != "value" {
		t.Fatalf("renamed xattr = %q st=%d", value, st)
	}
	if st := v.FsyncPath("d/g"); st != fsproto.OK {
		t.Fatalf("fsync: %d", st)
	}
	peer := dialCore(t, addr, Options{Owner: "xattr-rename-peer"})
	if value, st := peer.Getxattr(ctx, "d/g", nil, "user.keep"); st != fsproto.OK || string(value) != "value" {
		t.Fatalf("peer renamed xattr = %q st=%d", value, st)
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

// TestVolumeXattrWriteBackLocalThenFsync proves a locally-created object's
// complete xattr view stays in the same delegated WAL lane as its file data:
// read-after-write is immediate, conditional flags are decided locally, and
// fsync makes the file+xattr pair authority-visible.
func TestVolumeXattrWriteBackLocalThenFsync(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{
		Owner:  "wb-mount",
		WALDir: t.TempDir(),
	})
	ctx := context.Background()

	if _, st := v.Mkdir(ctx, "wb", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if _, st := v.Create(ctx, "wb/new.txt", 0o644); st != fsproto.OK {
		t.Fatalf("write-back create: %d", st)
	}
	// A locally-born object has a complete empty xattr map.
	if names, st := v.Listxattr(ctx, "wb/new.txt", nil); st != fsproto.OK || len(names) != 0 {
		t.Fatalf("unflushed listxattr = %v st=%d", names, st)
	}
	if _, st := v.Getxattr(ctx, "wb/new.txt", nil, "user.a"); st != fsproto.ENODATA {
		t.Fatalf("unflushed getxattr = %d, want ENODATA", st)
	}
	if st := v.Setxattr(ctx, "wb/new.txt", nil, "user.a", []byte("v")); st != fsproto.OK {
		t.Fatalf("write-back setxattr: %d", st)
	}
	if st := v.SetxattrFlags(ctx, "wb/new.txt", nil, "user.a", []byte("again"), wal.XattrCreate); st != fsproto.EEXIST {
		t.Fatalf("delegated create-only existing: %d", st)
	}
	if st := v.SetxattrFlags(ctx, "wb/new.txt", nil, "user.missing", []byte("x"), wal.XattrReplace); st != fsproto.ENODATA {
		t.Fatalf("delegated replace-only missing: %d", st)
	}
	if st := v.Setxattr(ctx, "wb/new.txt", nil, "user.remove", []byte("gone")); st != fsproto.OK {
		t.Fatalf("delegated set before remove: %d", st)
	}
	if st := v.Removexattr(ctx, "wb/new.txt", nil, "user.remove"); st != fsproto.OK {
		t.Fatalf("delegated removexattr: %d", st)
	}
	if st := v.Removexattr(ctx, "wb/new.txt", nil, "user.remove"); st != fsproto.ENODATA {
		t.Fatalf("delegated remove missing: %d", st)
	}
	if value, st := v.Getxattr(ctx, "wb/new.txt", nil, "user.a"); st != fsproto.OK || string(value) != "v" {
		t.Fatalf("write-back getxattr = %q st=%d", value, st)
	}
	if names, st := v.Listxattr(ctx, "wb/new.txt", nil); st != fsproto.OK || strings.Join(names, ",") != "user.a" {
		t.Fatalf("delegated listxattr = %v st=%d", names, st)
	}
	if got := v.WritebackStatus().Delegations; len(got) != 1 || got[0].Scope != "wb" {
		t.Fatalf("xattr mutation released its delegation: %+v", got)
	}
	if st := v.FsyncPath("wb/new.txt"); st != fsproto.OK {
		t.Fatalf("fsync file+xattr: %d", st)
	}
	peer := dialCore(t, addr, Options{Owner: "peer"})
	if value, st := peer.Getxattr(ctx, "wb/new.txt", nil, "user.a"); st != fsproto.OK || string(value) != "v" {
		t.Fatalf("peer after fsync = %q st=%d", value, st)
	}
}

// TestXattrFeatureNegotiationSelectsAuthorityLane proves a new client remains
// compatible with a v6 authority that predates delegated-xattr flushes. The
// version probe selects the authority lane before Setxattr: the current grant
// is drained, no failed fast-path operation occurs, and the mutation is
// immediately visible to a peer.
func TestXattrFeatureNegotiationSelectsAuthorityLane(t *testing.T) {
	addr := serveCoreWithoutDelegatedXattrs(t)
	v := dialCore(t, addr, Options{
		Owner:  "old-authority-client",
		WALDir: t.TempDir(),
	})
	ctx := context.Background()

	if got := v.client.Features(); got != 0 {
		t.Fatalf("old authority features = %#x, want 0", got)
	}
	if _, st := v.Mkdir(ctx, "compat", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "compat/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if got := v.WritebackStatus().Delegations; len(got) != 1 || got[0].Scope != "compat" {
		t.Fatalf("create did not enter delegated lane: %+v", got)
	}

	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.Setxattr(ctx, "compat/f", n, "user.compat", []byte("value")); st != fsproto.OK {
		t.Fatalf("authority-lane setxattr: %d", st)
	}
	if got := v.WritebackStatus().Delegations; len(got) != 0 {
		t.Fatalf("authority-lane xattr retained a delegation: %+v", got)
	}

	peer := dialCore(t, addr, Options{Owner: "old-authority-peer"})
	if value, st := peer.Getxattr(ctx, "compat/f", nil, "user.compat"); st != fsproto.OK || string(value) != "value" {
		t.Fatalf("peer getxattr = %q st=%d", value, st)
	}
}
