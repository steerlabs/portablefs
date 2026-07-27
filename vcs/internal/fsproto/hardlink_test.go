package fsproto

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/go-git/go-billy/v5"

	"github.com/steerlabs/portablefs/vcs/internal/delegation"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

func hardLinkRoundtrip(t *testing.T, cli *Client) {
	t.Helper()
	if !cli.SupportsHardLinks() {
		t.Fatal("authority did not advertise FeatHardLinks")
	}
	src, st, err := cli.Create("source", 0o644)
	if err != nil || st != OK {
		t.Fatalf("create: attr=%+v st=%d err=%v", src, st, err)
	}
	if _, _, _, st, err := cli.WriteV("source", 0, []byte("shared"), 0o644); err != nil || st != OK {
		t.Fatalf("write: st=%d err=%v", st, err)
	}
	linked, st, err := cli.Link("source", "alias")
	if err != nil || st != OK {
		t.Fatalf("link: attr=%+v st=%d err=%v", linked, st, err)
	}
	if linked.Ino == 0 || linked.Ino != src.Ino || linked.Nlink != 2 {
		t.Fatalf("linked attr=%+v source=%+v", linked, src)
	}
	if st, err := cli.Remove("source"); err != nil || st != OK {
		t.Fatalf("unlink first alias: st=%d err=%v", st, err)
	}
	survivor, st, err := cli.Getattr("alias")
	if err != nil || st != OK || survivor.Ino != linked.Ino || survivor.Nlink != 1 {
		t.Fatalf("survivor=%+v st=%d err=%v", survivor, st, err)
	}
	data, st, err := cli.Read("alias", 0, 32)
	if err != nil || st != OK || string(data) != "shared" {
		t.Fatalf("survivor read=%q st=%d err=%v", data, st, err)
	}
	if _, st, err := cli.Mkdir("dir", 0o755); err != nil || st != OK {
		t.Fatalf("mkdir: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Link("dir", "dir-alias"); err != nil || st != EPERM {
		t.Fatalf("directory link: st=%d err=%v, want EPERM", st, err)
	}
}

func TestHardLinkRoundtripWALAuthority(t *testing.T) {
	cli := serve(t)
	cli.SetOwner("hardlink-wal")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatal(err)
	}
	hardLinkRoundtrip(t, cli)
}

func TestHardLinkRoundtripManagedAuthority(t *testing.T) {
	addr := serveManagedAuthority(t)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("hardlink-managed")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatal(err)
	}
	hardLinkRoundtrip(t, cli)
}

type noHardLinkFS struct{ billy.Filesystem }

func TestHardLinkCapabilityDowngradesWithoutSendingUnknownOp(t *testing.T) {
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
	srv := NewServer(noHardLinkFS{fs}, fs, delegation.New())
	go func() { _ = srv.Serve(ctx, ln) }()

	cli, err := Dial(ln.Addr().String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	if cli.SupportsHardLinks() {
		t.Fatal("authority without HardLinkStore advertised FeatHardLinks")
	}
	if _, st, err := cli.Link("source", "alias"); err != nil || st != EOPNOTSUPP {
		t.Fatalf("client downgrade: st=%d err=%v", st, err)
	}
	if got := srv.dispatch(&Request{Op: OpLink, Path: "source", NewPath: "alias"}); got.Status != EOPNOTSUPP {
		t.Fatalf("raw unsupported link status=%d", got.Status)
	}
}
