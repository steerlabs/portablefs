package main

import (
	"context"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestExplicitUnlockSwallowsRPCErrors pins P2: an explicit F_UNLCK whose release RPC fails must return
// success (0), not EIO. A failed unlock is reclaimed by the authority's ReleaseOwner when the mount
// disconnects; surfacing EIO to the app is a behavior regression from the pre-extraction mount.
func TestExplicitUnlockSwallowsRPCErrors(t *testing.T) {
	cli, stop := newAuthorityStoppable(t)
	ctx := context.Background()
	const (
		path  = "unlk_err_f"
		owner = uint64(0x9999)
	)
	if _, st, err := cli.Create(path, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}
	n := &node{c: cli, path: path}
	fh, _, e := n.Open(ctx, 0)
	if e != 0 {
		t.Fatalf("Open: errno=%d", e)
	}
	if e := n.Setlk(ctx, fh, owner, &fuse.FileLock{Start: 0, End: ^uint64(0), Typ: lockWrite}, 0); e != 0 {
		t.Fatalf("Setlk acquire: errno=%d", e)
	}

	// Kill the authority so the unlock RPC cannot complete.
	stop()

	if e := n.Setlk(ctx, fh, owner, &fuse.FileLock{Start: 0, End: ^uint64(0), Typ: lockUnlock}, 0); e != 0 {
		t.Fatalf("F_UNLCK against a dead authority must return success, got errno=%d", e)
	}
	if e := n.Setlkw(ctx, fh, owner, &fuse.FileLock{Start: 0, End: ^uint64(0), Typ: lockUnlock}, 0); e != 0 {
		t.Fatalf("blocking F_UNLCK against a dead authority must return success, got errno=%d", e)
	}
}
