package fsproto

import (
	"testing"

	"github.com/go-git/go-billy/v5/memfs"
)

// TestProbeAdvertisesFsCapabilities: a workfs-backed authority advertises
// ParentVersion stamping (negative-cache default-on precondition) and the
// open-registration surface (fused create+register, batched unmarks); a plain
// billy fs advertises neither — capability gating, never wire sniffing.
func TestProbeAdvertisesFsCapabilities(t *testing.T) {
	_, addr := serveFS(t)
	cli, err := Dial(addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	feats, err := cli.ServerFeatures()
	if err != nil {
		t.Fatalf("ServerFeatures: %v", err)
	}
	if feats&FeatParentVersion == 0 {
		t.Fatalf("workfs probe features %b missing FeatParentVersion", feats)
	}
	if feats&FeatOpenRegistration == 0 {
		t.Fatalf("workfs probe features %b missing FeatOpenRegistration", feats)
	}
	if !cli.SupportsOpenRegistration() {
		t.Fatal("SupportsOpenRegistration must be true against a workfs authority")
	}

	legacy := NewServer(memfs.New(), nil, nil)
	if r := legacy.dispatch(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)}); r.Status != OK ||
		r.Features&(FeatParentVersion|FeatOpenRegistration) != 0 {
		t.Fatalf("plain billy fs must advertise neither capability: status=%d features=%b", r.Status, r.Features)
	}
}

// TestCreateRegisterOpenHoldParksPeerUnlink is the fused-path version of the
// frozen open-vs-unlink guarantee: the hold recorded by create+RegisterOpen
// (no separate MarkOpen RPC) must make a peer's immediate unlink PARK the
// inode, so the creating mount's just-returned open handle keeps working.
func TestCreateRegisterOpenHoldParksPeerUnlink(t *testing.T) {
	_, addr := serveFS(t)
	cliA, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliA.Close()
	cliA.SetOwner("mountA")
	cliB, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cliB.Close()
	cliB.SetOwner("mountB")

	a, gen, st, err := cliA.CreateRegisterOpen("fused.txt", 0o644)
	if err != nil || st != OK || a == nil || a.Ino == 0 {
		t.Fatalf("CreateRegisterOpen: attr=%+v gen=%d st=%d err=%v", a, gen, st, err)
	}
	if _, st, err := cliA.Write("fused.txt", 0, []byte("held"), 0o644); err != nil || st != OK {
		t.Fatalf("write: st=%d err=%v", st, err)
	}
	// Peer unlink immediately after the create returned: the fused hold must
	// park, exactly as a separate MarkOpen would have.
	if st, err := cliB.Remove("fused.txt"); err != nil || st != OK {
		t.Fatalf("peer remove: st=%d err=%v", st, err)
	}
	if data, st, err := cliA.ReadOrphan(a.Ino, 0, 8); err != nil || st != OK || string(data) != "held" {
		t.Fatalf("parked inode must keep serving the creator's handle: %q st=%d err=%v", data, st, err)
	}
	if _, st, err := cliA.GetattrOrphan(a.Ino); err != nil || st != OK {
		t.Fatalf("GetattrOrphan after peer unlink: st=%d err=%v (inode destroyed, not parked)", st, err)
	}
}

// TestUnmarkOpenBatchReleasesHolds: after a batched unmark, a remove destroys
// (the deferred last-close release has exactly UnmarkOpenInode semantics).
func TestUnmarkOpenBatchReleasesHolds(t *testing.T) {
	_, addr := serveFS(t)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cli.SetOwner("mountA")

	var inos []uint64
	for _, name := range []string{"u1", "u2"} {
		a, _, st, err := cli.CreateRegisterOpen(name, 0o644)
		if err != nil || st != OK || a.Ino == 0 {
			t.Fatalf("create %s: st=%d err=%v", name, st, err)
		}
		inos = append(inos, a.Ino)
	}
	if st, err := cli.UnmarkOpenBatch(inos); err != nil || st != OK {
		t.Fatalf("UnmarkOpenBatch: st=%d err=%v", st, err)
	}
	for i, name := range []string{"u1", "u2"} {
		if st, err := cli.Remove(name); err != nil || st != OK {
			t.Fatalf("remove %s: st=%d err=%v", name, st, err)
		}
		if _, st, err := cli.GetattrOrphan(inos[i]); err != nil || st != ENOENT {
			t.Fatalf("%s must be destroyed after unmark+remove, got orphan stat st=%d err=%v", name, st, err)
		}
	}
}
