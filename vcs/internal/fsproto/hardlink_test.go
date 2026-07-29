package fsproto

import (
	"testing"
)

func hardLinkRoundtrip(t *testing.T, cli *Client) {
	t.Helper()
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

func TestHardLinkRoundtripFileLogAuthority(t *testing.T) {
	cli := serve(t)
	cli.SetOwner("hardlink-filelog")
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
