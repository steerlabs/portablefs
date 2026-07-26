package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/clientcore"
	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/pfslocal"
)

// TestRemoteRenameOverReopens pins the open-after-remote-replace contract: a
// peer machine atomically replacing a file (git's ref update: write name.lock,
// rename over name) must not wedge opens through a kernel item bound before
// the replace. Open registration pins inodes, and the daemon used to keep
// pinning the REPLACED inode for the path — the authority correctly answers
// ENOENT for it, forever. POSIX open resolves the name at open time: once
// fresh attributes reveal the new inode, registerWithItemLocked swaps the
// record's NodeState and the same kernel item serves the current file.
func TestRemoteRenameOverReopens(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	ref := ensureAttach(t, hc, authority, "vol-remote-renameover", "main", "/Volumes/RemoteRenameOver")

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "remote-rename-over"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root

	f := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("main"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: f.Handle, Data: []byte("old-hash\n")})
	c.call(&pfslocal.CloseRequest{Handle: f.Handle})

	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	cli := remote.Client()
	if _, st, err := cli.Create("main.lock", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("remote create st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("main.lock", 0, []byte("new-hash\n"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("remote write st=%d err=%v", st, err)
	}
	if st, _, err := cli.RenameWithOrphanTarget("main.lock", "main", false); err != nil || st != fsproto.OK {
		t.Fatalf("remote rename st=%d err=%v", st, err)
	}

	// The kernel's pattern for a fresh read of a held item: getattr (which
	// refetches authoritative attributes once the invalidation lands), then
	// open. Poll until the daemon converges; without the NodeState swap this
	// never succeeds — every open answers ENOENT for the replaced inode.
	deadline := time.Now().Add(5 * time.Second)
	var lastRead string
	for {
		if _, er := c.callMaybe(&pfslocal.GetAttrRequest{Item: f.Attr.Item}); er != nil {
			t.Fatalf("getattr errno=%d", er.Errno)
		}
		opened, er := c.callMaybe(&pfslocal.OpenRequest{Item: f.Attr.Item, Mode: pfslocal.OpenModeRead})
		if er == nil {
			h := opened.(*pfslocal.OpenReply).Handle
			got := c.call(&pfslocal.ReadRequest{Handle: h, Length: 64}).(*pfslocal.ReadReply)
			c.call(&pfslocal.CloseRequest{Handle: h})
			lastRead = string(got.Data)
			if lastRead == "new-hash\n" {
				return
			}
			// The remote mutation and subscription delivery are
			// asynchronous. An open may still succeed on the old inode before
			// the invalidation arrives; keep polling for convergence just as
			// we do when the interim open returns ENOENT.
			if lastRead != "old-hash\n" {
				t.Fatalf("read unexpected content during remote rename-over convergence = %q", got.Data)
			}
		}
		if time.Now().After(deadline) {
			if er != nil {
				t.Fatalf("open never converged after remote rename-over: errno=%d lastRead=%q", er.Errno, lastRead)
			}
			t.Fatalf("read never converged after remote rename-over: lastRead=%q", lastRead)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
