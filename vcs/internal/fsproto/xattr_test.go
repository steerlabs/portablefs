package fsproto

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// xattrClientRoundtrip drives the full client surface against one authority:
// set/get/list/remove, overwrite, remove-missing (ENODATA), and the frozen
// wire bounds (ERANGE name, E2BIG value).
func xattrClientRoundtrip(t *testing.T, cli *Client) {
	t.Helper()
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

// TestXattrRoundtripFileLogAuthority: the file-entry-log-backed managed
// generation serves and journals xattrs through the exact-session mutation path.
func TestXattrRoundtripFileLogAuthority(t *testing.T) {
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
	xattrClientRoundtrip(t, cli)
}

// noCondXattrFS models a store that serves xattrs but does NOT implement the
// conditional-flag evaluator: a conditional set against it must fail closed
// with a durable EOPNOTSUPP instead of silently dropping the precondition.
type noCondXattrFS struct{ *workfs.FS }

func (noCondXattrFS) SupportsAtomicXattrFlags() bool { return false }

func TestConditionalXattrWithoutEvaluatorFailsClosed(t *testing.T) {
	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	srv := NewServer(noCondXattrFS{FS: fs}, fs)
	probe := srv.probeResponse(int64(ProtocolVersion))
	if probe.Status != OK || probe.Features&FeatureDelegatedXattrs != 0 {
		t.Fatalf("authority without atomic xattr evaluator advertised delegated xattrs: %+v", probe)
	}
	cs := openExactSession(t, srv, "sess-XF", 1, "MX", "tokXF", 8)
	if r := exactDo(srv, cs, &Request{Op: OpCreate, Path: "f", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	r := exactDo(srv, cs, &Request{Op: OpSetxattr, Path: "f", XattrName: "user.k", Data: []byte("v"), XattrFlags: wal.XattrCreate}, 0, 2)
	if r == nil || r.Status != EOPNOTSUPP {
		t.Fatalf("conditional set without the evaluator: %+v, want EOPNOTSUPP", r)
	}
	// The identity was consumed durably: the identical resend replays.
	if r := exactDo(srv, cs, &Request{Op: OpSetxattr, Path: "f", XattrName: "user.k", Data: []byte("v"), XattrFlags: wal.XattrCreate}, 0, 2); r == nil || r.Status != EOPNOTSUPP || !r.Duplicate {
		t.Fatalf("replay: %+v, want duplicate EOPNOTSUPP", r)
	}
	// The unconditional set still lands.
	if r := exactDo(srv, cs, &Request{Op: OpSetxattr, Path: "f", XattrName: "user.k", Data: []byte("v")}, 0, 3); r == nil || r.Status != OK {
		t.Fatalf("unconditional set: %+v", r)
	}
}

func TestXattrFlushBatchAppliesDelegatedRecords(t *testing.T) {
	_, addr := serveFS(t)
	cli, err := Dial(addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("M")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("exact session: %v", err)
	}
	if _, st, err := cli.Mkdir("wb", 0o755); err != nil || st != OK {
		t.Fatalf("mkdir: st=%d err=%v", st, err)
	}
	grant, err := cli.DelegationAcquire("wb", "sess-x")
	if err != nil || !grant.Granted {
		t.Fatalf("delegation acquire: %+v err=%v", grant, err)
	}
	records := []wal.Record{
		{Seq: 1, Op: wal.OpCreate, Path: "wb/f", Mode: 0o644},
		{Seq: 2, Op: wal.OpSetxattr, Path: "wb/f", XattrName: "user.a", Data: []byte("v")},
	}
	_, st, err := cli.FlushWriteback("sess-x", "wb", grant.Epoch, wbZeroDigest(), wbTestDigest(t, wbZeroDigest(), records), records)
	if err != nil || st != OK {
		t.Fatalf("delegated xattr flush: st=%d err=%v", st, err)
	}
	value, st, err := cli.Getxattr("wb/f", 0, "user.a")
	if err != nil || st != OK || string(value) != "v" {
		t.Fatalf("get flushed xattr: value=%q st=%d err=%v", value, st, err)
	}
}
