package fsproto

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-git/go-billy/v5"

	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/metrics"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// xattrClientRoundtrip drives the full client surface against one authority:
// set/get/list/remove, overwrite, remove-missing (ENODATA), and the frozen
// wire bounds (ERANGE name, E2BIG value).
func xattrClientRoundtrip(t *testing.T, cli *Client) {
	t.Helper()
	if !cli.SupportsXattrs() {
		t.Fatal("authority did not advertise FeatXattrs")
	}
	if _, st, err := cli.Create("x.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if st, err := cli.Setxattr("x.txt", 0, "user.b", []byte("vb")); err != nil || st != OK {
		t.Fatalf("setxattr: st=%d err=%v", st, err)
	}
	if st, err := cli.Setxattr("x.txt", 0, "user.a", []byte("v1")); err != nil || st != OK {
		t.Fatalf("setxattr: st=%d err=%v", st, err)
	}
	if st, err := cli.Setxattr("x.txt", 0, "user.a", []byte("v2")); err != nil || st != OK {
		t.Fatalf("overwrite: st=%d err=%v", st, err)
	}
	if st, err := cli.SetxattrFlags("x.txt", 0, "user.a", []byte("no"), wal.XattrCreate); err != nil || st != EEXIST {
		t.Fatalf("create-only existing: st=%d err=%v, want EEXIST", st, err)
	}
	if st, err := cli.SetxattrFlags("x.txt", 0, "user.absent", []byte("no"), wal.XattrReplace); err != nil || st != ENODATA {
		t.Fatalf("replace-only missing: st=%d err=%v, want ENODATA", st, err)
	}
	if st, err := cli.SetxattrFlags("x.txt", 0, "user.new", []byte("created"), wal.XattrCreate); err != nil || st != OK {
		t.Fatalf("create-only missing: st=%d err=%v", st, err)
	}
	if st, err := cli.SetxattrFlags("x.txt", 0, "user.new", []byte("replaced"), wal.XattrReplace); err != nil || st != OK {
		t.Fatalf("replace-only existing: st=%d err=%v", st, err)
	}
	if v, st, err := cli.Getxattr("x.txt", 0, "user.a"); err != nil || st != OK || string(v) != "v2" {
		t.Fatalf("getxattr = %q st=%d err=%v", v, st, err)
	}
	if names, st, err := cli.Listxattr("x.txt", 0); err != nil || st != OK || strings.Join(names, ",") != "user.a,user.b,user.new" {
		t.Fatalf("listxattr = %v st=%d err=%v", names, st, err)
	}
	if _, st, err := cli.Getxattr("x.txt", 0, "user.absent"); err != nil || st != ENODATA {
		t.Fatalf("get missing: st=%d err=%v, want ENODATA", st, err)
	}
	if st, err := cli.Removexattr("x.txt", 0, "user.b"); err != nil || st != OK {
		t.Fatalf("removexattr: st=%d err=%v", st, err)
	}
	if st, err := cli.Removexattr("x.txt", 0, "user.b"); err != nil || st != ENODATA {
		t.Fatalf("remove missing: st=%d err=%v, want ENODATA", st, err)
	}
	if st, err := cli.Setxattr("x.txt", 0, strings.Repeat("n", wal.MaxXattrNameBytes+1), []byte("v")); err != nil || st != ERANGE {
		t.Fatalf("over-long name: st=%d err=%v, want ERANGE", st, err)
	}
	if st, err := cli.Setxattr("x.txt", 0, "user.big", make([]byte, wal.MaxXattrValueBytes+1)); err != nil || st != E2BIG {
		t.Fatalf("over-size value: st=%d err=%v, want E2BIG", st, err)
	}
	if _, st, err := cli.Getxattr("no-such-file", 0, "user.a"); err != nil || st != ENOENT {
		t.Fatalf("get on missing path: st=%d err=%v, want ENOENT", st, err)
	}
}

// Conditional xattr flags are evaluated at the authority's ordered apply
// position. Concurrent mounts therefore cannot both win XATTR_CREATE.
func TestXattrCreateOnlyAtomicAcrossClients(t *testing.T) {
	_, addr := serveFS(t)
	const n = 16
	clients := make([]*Client, n)
	for i := range clients {
		cli, err := Dial(addr, 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cli.Close() })
		if _, err := cli.EnsureExactSession(); err != nil {
			t.Fatal(err)
		}
		clients[i] = cli
	}
	if _, st, err := clients[0].Create("race", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}

	statuses := make(chan int32, n)
	var wg sync.WaitGroup
	for i := range clients {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := clients[i].SetxattrFlags("race", 0, "user.winner", []byte{byte(i)}, wal.XattrCreate)
			if err != nil {
				statuses <- EIO
				return
			}
			statuses <- st
		}()
	}
	wg.Wait()
	close(statuses)
	ok, exists := 0, 0
	for st := range statuses {
		switch st {
		case OK:
			ok++
		case EEXIST:
			exists++
		default:
			t.Fatalf("unexpected conditional status %d", st)
		}
	}
	if ok != 1 || exists != n-1 {
		t.Fatalf("create-only winners=%d conflicts=%d, want 1/%d", ok, exists, n-1)
	}
}

// TestXattrRoundtripLegacyAuthority: the WAL-backed generation serves and
// journals xattrs through the exact-session mutation path.
func TestXattrRoundtripLegacyAuthority(t *testing.T) {
	cli := serve(t)
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("exact session: %v", err)
	}
	xattrClientRoundtrip(t, cli)
}

// TestXattrRoundtripManagedAuthority: the managed (journal-native)
// generation routes xattr mutations through the exact/journaled path and
// serves reads from the reduced live state.
func TestXattrRoundtripManagedAuthority(t *testing.T) {
	addr := serveManagedAuthority(t)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("MX")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("exact session: %v", err)
	}
	if !cli.ServerManaged() {
		t.Fatal("authority did not negotiate managed coordination")
	}
	xattrClientRoundtrip(t, cli)
}

// billyOnly hides every optional workfs interface (XattrStore included), so
// the server behaves exactly like a pre-xattr authority: no FeatXattrs on
// the probe, EOPNOTSUPP on a direct wire op.
type billyOnly struct{ billy.Filesystem }

// legacyXattrFS models the rolling-upgrade peer that implements the original
// FeatXattrs read surface but predates conditional xattr flags.
type legacyXattrFS struct {
	billy.Filesystem
	delegate *workfs.FS
}

func (f legacyXattrFS) GetxattrHandle(path string, ino uint64, name string) ([]byte, error) {
	return f.delegate.GetxattrHandle(path, ino, name)
}

func (f legacyXattrFS) ListxattrHandle(path string, ino uint64) ([]string, error) {
	return f.delegate.ListxattrHandle(path, ino)
}

// TestXattrCapabilityNegotiation: an authority without the xattr surface
// never advertises FeatXattrs; the client's SupportsXattrs gate reports
// false and a raw wire op answers EOPNOTSUPP.
func TestXattrCapabilityNegotiation(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := NewServer(billyOnly{fs}, fs, delegation.New())
	go func() { _ = srv.Serve(ctx, ln) }()

	cli, err := Dial(ln.Addr().String(), 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	if cli.SupportsXattrs() {
		t.Fatal("pre-xattr authority advertised FeatXattrs")
	}
	// A raw wire op (bypassing the client gate) answers EOPNOTSUPP — the
	// server-side fence behind the un-advertised capability.
	if r := srv.dispatch(&Request{Op: OpGetxattr, Path: "f", XattrName: "user.a"}); r.Status != EOPNOTSUPP {
		t.Fatalf("getxattr against pre-xattr fs: status %d, want EOPNOTSUPP", r.Status)
	}
	if r := srv.dispatch(&Request{Op: OpListxattr, Path: "f"}); r.Status != EOPNOTSUPP {
		t.Fatalf("listxattr against pre-xattr fs: status %d, want EOPNOTSUPP", r.Status)
	}

	// A full workfs-backed server advertises the bit (both generations are
	// proven by the roundtrip tests above).
	feats, err := serve(t).ServerFeatures()
	if err != nil {
		t.Fatal(err)
	}
	if feats&FeatXattrs == 0 || feats&FeatAtomicXattrFlags == 0 {
		t.Fatalf("workfs authority features %b miss xattrs or atomic xattr flags", feats)
	}
}

func TestConditionalXattrRollingUpgradeFailsClosed(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := NewServer(legacyXattrFS{Filesystem: fs, delegate: fs}, fs, delegation.New())
	go func() { _ = srv.Serve(ctx, ln) }()

	cli, err := Dial(ln.Addr().String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	if !cli.SupportsXattrs() {
		t.Fatal("legacy xattr authority did not advertise basic xattrs")
	}
	if cli.SupportsAtomicXattrFlags() {
		t.Fatal("legacy xattr authority advertised conditional flags")
	}
	cli.ops = &metrics.Counter{}
	before := cli.ops.Value()
	if st, err := cli.SetxattrFlags("f", 0, "user.once", []byte("v"), wal.XattrCreate); err != nil || st != EOPNOTSUPP {
		t.Fatalf("conditional set against legacy authority: st=%d err=%v", st, err)
	}
	if got := cli.ops.Value(); got != before {
		t.Fatalf("conditional xattr made %d wire operations after capability denial", got-before)
	}
	if r := srv.dispatch(&Request{
		Op: OpSetxattr, Path: "f", XattrName: "user.once",
		XattrFlags: wal.XattrCreate, Data: []byte("v"),
	}); r.Status != EOPNOTSUPP {
		t.Fatalf("raw conditional xattr status %d, want EOPNOTSUPP", r.Status)
	}
}

// TestXattrFlushBatchRejectsSmuggledRecords: xattr mutations are
// write-through only; a write-back flush carrying one is refused before any
// apply (both admission layers enforce it — this covers the server's).
func TestXattrFlushBatchRejectsSmuggledRecords(t *testing.T) {
	fs, addr := serveFS(t)
	_ = fs
	cli, err := Dial(addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	_, st, err := cli.FlushBatch("sess-x", 1, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "f", Mode: 0o644},
		{Seq: 1, Op: wal.OpSetxattr, Path: "f", XattrName: "user.a", Data: []byte("v")},
	})
	if err != nil || st != EINVAL {
		t.Fatalf("smuggled xattr flush: st=%d err=%v, want EINVAL", st, err)
	}
}
