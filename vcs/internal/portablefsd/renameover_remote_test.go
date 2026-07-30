package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestRemoteRenameOverReincarnatesItem pins the POSIX identity boundary for a
// peer rename-over. The directory entry "a" starts as one inode with hard-link
// alias "b". Replacing only "a" must publish a fresh frontend Item while the
// old Item, alias, and already-open handle continue to address the old inode.
func TestRemoteRenameOverReincarnatesItem(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	ref := ensureAttach(t, hc, authority, "vol-remote-renameover", "main", "/Volumes/RemoteRenameOver")

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "remote-rename-over"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root

	f := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("a"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: f.Handle, Data: []byte("old-hash\n")})
	c.call(&pfslocal.CloseRequest{Handle: f.Handle})
	b := c.call(&pfslocal.HardLinkRequest{
		Item: f.Attr.Item, Dir: root, Name: []byte("b"),
	}).(*pfslocal.HardLinkReply)
	if b.Attr.Item != f.Attr.Item || b.Attr.Nlink != 2 {
		t.Fatalf("hard-link identity split before replace: a=%+v b=%+v", f.Attr, b.Attr)
	}
	oldOpen := c.call(&pfslocal.OpenRequest{
		Item: f.Attr.Item, Mode: pfslocal.OpenModeRead,
	}).(*pfslocal.OpenReply)

	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	cli := remote.Client()
	if _, st, err := cli.Create("a.lock", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("remote create st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("a.lock", 0, []byte("new-hash\n"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("remote write st=%d err=%v", st, err)
	}
	if st, _, err := cli.RenameWithOrphanTarget("a.lock", "a", false); err != nil || st != fsproto.OK {
		t.Fatalf("remote rename st=%d err=%v", st, err)
	}

	// Lookup by name must observe the replacement as a distinct Item. The
	// subscription is asynchronous, so poll the authoritative lookup until
	// the replacement inode is visible through the daemon.
	deadline := time.Now().Add(5 * time.Second)
	var replacement *pfslocal.LookupReply
	for {
		got := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("a")}).(*pfslocal.LookupReply)
		if got.Attr.Item != f.Attr.Item {
			replacement = got
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("replacement lookup retained old item: old=%+v got=%+v", f.Attr.Item, got.Attr.Item)
		}
		time.Sleep(50 * time.Millisecond)
	}

	survivor := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("b")}).(*pfslocal.LookupReply)
	if survivor.Attr.Item != f.Attr.Item || survivor.Attr.Nlink != 1 {
		t.Fatalf("surviving hard link lost old identity: old=%+v b=%+v", f.Attr, survivor.Attr)
	}

	newOpen := c.call(&pfslocal.OpenRequest{
		Item: replacement.Attr.Item, Mode: pfslocal.OpenModeRead,
	}).(*pfslocal.OpenReply)
	if got := c.call(&pfslocal.ReadRequest{Handle: newOpen.Handle, Length: 64}).(*pfslocal.ReadReply); string(got.Data) != "new-hash\n" {
		t.Fatalf("replacement bytes=%q want new-hash", got.Data)
	}
	c.call(&pfslocal.CloseRequest{Handle: newOpen.Handle})

	if got := c.call(&pfslocal.ReadRequest{Handle: oldOpen.Handle, Length: 64}).(*pfslocal.ReadReply); string(got.Data) != "old-hash\n" {
		t.Fatalf("pre-replace handle bytes=%q want old-hash", got.Data)
	}
	oldAliasOpen := c.call(&pfslocal.OpenRequest{
		Item: survivor.Attr.Item, Mode: pfslocal.OpenModeRead,
	}).(*pfslocal.OpenReply)
	if got := c.call(&pfslocal.ReadRequest{Handle: oldAliasOpen.Handle, Length: 64}).(*pfslocal.ReadReply); string(got.Data) != "old-hash\n" {
		t.Fatalf("surviving alias bytes=%q want old-hash", got.Data)
	}
	c.call(&pfslocal.CloseRequest{Handle: oldAliasOpen.Handle})
	c.call(&pfslocal.CloseRequest{Handle: oldOpen.Handle})
}

// TestRemoteUnobservedHardLinkRecoversDetachedLocalIdentity covers the
// asymmetric multi-machine case: portablefsd has published a daemon-local
// Item for "a", a peer creates hard link "b" without the frontend looking it
// up, then the peer replaces "a". Discovery of "b" must recover the retained
// inode-to-Item mapping rather than minting a second frontend identity.
func TestRemoteUnobservedHardLinkRecoversDetachedLocalIdentity(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _ := startDaemonNoAttach(t, authority)
	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(
		t, hc, authority, "vol-unobserved-reincarnation", "main",
		"/Volumes/UnobservedReincarnation", "writeback", opts,
	)

	local := dialPFS(t, cfg.FrontendSocket)
	defer local.close()
	local.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "unobserved-hardlink-local"})
	root := local.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root
	dir := local.call(&pfslocal.MkdirRequest{
		Dir: root, Name: []byte("delegated"), Mode: 0o755,
	}).(*pfslocal.MkdirReply)
	old := local.call(&pfslocal.CreateRequest{
		Dir: dir.Attr.Item, Name: []byte("a"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	if old.Attr.Item.ItemID&localItemIDMarker == 0 {
		t.Fatalf("write-back create item=%+v, want daemon-local identity", old.Attr.Item)
	}
	local.call(&pfslocal.WriteRequest{Handle: old.Handle, Data: []byte("old-local\n")})
	local.call(&pfslocal.SyncVolumeRequest{})

	peer, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr: authority, Pool: 2, Owner: "unobserved-hardlink-peer",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	oldAttr, st := peer.Lookup(context.Background(), "delegated/a")
	if st != fsproto.OK || oldAttr.Ino == 0 {
		t.Fatalf("peer lookup a: attr=%+v st=%d", oldAttr, st)
	}
	oldState := clientcore.NewNodeState(oldAttr.Ino, true)
	if linked, st := peer.Link(context.Background(), "delegated/a", "delegated/b", oldState); st != fsproto.OK ||
		linked.Ino != oldAttr.Ino {
		t.Fatalf("peer unobserved hard link: attr=%+v st=%d", linked, st)
	}

	cli := peer.Client()
	if _, st, err := cli.Create("delegated/a.lock", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("peer create replacement st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("delegated/a.lock", 0, []byte("new-peer\n"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("peer write replacement st=%d err=%v", st, err)
	}
	if st, _, err := cli.RenameWithOrphanTarget("delegated/a.lock", "delegated/a", false); err != nil || st != fsproto.OK {
		t.Fatalf("peer replace a st=%d err=%v", st, err)
	}

	replacement := local.call(&pfslocal.LookupRequest{
		Dir: dir.Attr.Item, Name: []byte("a"),
	}).(*pfslocal.LookupReply)
	if replacement.Attr.Item == old.Attr.Item {
		t.Fatalf("replacement reused local-born old item: old=%+v replacement=%+v",
			old.Attr.Item, replacement.Attr.Item)
	}
	survivor := local.call(&pfslocal.LookupRequest{
		Dir: dir.Attr.Item, Name: []byte("b"),
	}).(*pfslocal.LookupReply)
	if survivor.Attr.Item != old.Attr.Item {
		t.Fatalf("unobserved hard link did not recover old item: old=%+v b=%+v",
			old.Attr.Item, survivor.Attr.Item)
	}

	newOpen := local.call(&pfslocal.OpenRequest{
		Item: replacement.Attr.Item, Mode: pfslocal.OpenModeRead,
	}).(*pfslocal.OpenReply)
	if got := local.call(&pfslocal.ReadRequest{
		Handle: newOpen.Handle, Length: 64,
	}).(*pfslocal.ReadReply); string(got.Data) != "new-peer\n" {
		t.Fatalf("replacement bytes=%q want new-peer", got.Data)
	}
	local.call(&pfslocal.CloseRequest{Handle: newOpen.Handle})

	bOpen := local.call(&pfslocal.OpenRequest{
		Item: survivor.Attr.Item, Mode: pfslocal.OpenModeRead,
	}).(*pfslocal.OpenReply)
	if got := local.call(&pfslocal.ReadRequest{
		Handle: bOpen.Handle, Length: 64,
	}).(*pfslocal.ReadReply); string(got.Data) != "old-local\n" {
		t.Fatalf("unobserved alias bytes=%q want old-local", got.Data)
	}
	if got := local.call(&pfslocal.ReadRequest{
		Handle: old.Handle, Length: 64,
	}).(*pfslocal.ReadReply); string(got.Data) != "old-local\n" {
		t.Fatalf("pre-replace local handle bytes=%q want old-local", got.Data)
	}
	local.call(&pfslocal.CloseRequest{Handle: bOpen.Handle})
	local.call(&pfslocal.CloseRequest{Handle: old.Handle})
}

func TestLocalRemovalRetainsIdentityForUnobservedPeerHardLink(t *testing.T) {
	for _, mode := range []string{"unlink", "rename-over"} {
		t.Run(mode, func(t *testing.T) {
			authority := serveAuthority(t)
			cfg, hc, _ := startDaemonNoAttach(t, authority)
			opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
			ref := ensureAttachWithPolicyOptions(
				t, hc, authority, "vol-local-removal-"+mode, "main",
				"/Volumes/LocalRemoval-"+mode, "writeback", opts,
			)

			local := dialPFS(t, cfg.FrontendSocket)
			defer local.close()
			local.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "local-removal-" + mode})
			root := local.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root
			dir := local.call(&pfslocal.MkdirRequest{
				Dir: root, Name: []byte("delegated"), Mode: 0o755,
			}).(*pfslocal.MkdirReply)
			old := local.call(&pfslocal.CreateRequest{
				Dir: dir.Attr.Item, Name: []byte("a"), Mode: 0o644, Exclusive: true,
			}).(*pfslocal.CreateReply)
			if old.Attr.Item.ItemID&localItemIDMarker == 0 {
				t.Fatalf("write-back create item=%+v, want daemon-local identity", old.Attr.Item)
			}
			local.call(&pfslocal.WriteRequest{Handle: old.Handle, Data: []byte("old-local\n")})
			local.call(&pfslocal.SyncVolumeRequest{})

			peer, err := clientcore.Dial(context.Background(), clientcore.Options{
				Addr: authority, Pool: 2, Owner: "local-removal-peer-" + mode,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			oldAttr, st := peer.Lookup(context.Background(), "delegated/a")
			if st != fsproto.OK || oldAttr.Ino == 0 {
				t.Fatalf("peer lookup a: attr=%+v st=%d", oldAttr, st)
			}
			if linked, st := peer.Link(
				context.Background(), "delegated/a", "delegated/b",
				clientcore.NewNodeState(oldAttr.Ino, true),
			); st != fsproto.OK || linked.Ino != oldAttr.Ino {
				t.Fatalf("peer unobserved hard link: attr=%+v st=%d", linked, st)
			}

			var replacement pfslocal.Item
			switch mode {
			case "unlink":
				local.call(&pfslocal.RemoveRequest{
					Dir: dir.Attr.Item, Name: []byte("a"),
				})
			case "rename-over":
				fresh := local.call(&pfslocal.CreateRequest{
					Dir: dir.Attr.Item, Name: []byte("fresh"), Mode: 0o644, Exclusive: true,
				}).(*pfslocal.CreateReply)
				replacement = fresh.Attr.Item
				local.call(&pfslocal.WriteRequest{
					Handle: fresh.Handle, Data: []byte("new-local\n"),
				})
				local.call(&pfslocal.CloseRequest{Handle: fresh.Handle})
				local.call(&pfslocal.RenameRequest{
					FromDir: dir.Attr.Item, FromName: []byte("fresh"),
					ToDir: dir.Attr.Item, ToName: []byte("a"),
				})
				got := local.call(&pfslocal.LookupRequest{
					Dir: dir.Attr.Item, Name: []byte("a"),
				}).(*pfslocal.LookupReply)
				if got.Attr.Item != replacement || got.Attr.Item == old.Attr.Item {
					t.Fatalf("rename replacement identity: old=%+v fresh=%+v got=%+v",
						old.Attr.Item, replacement, got.Attr.Item)
				}
			}

			survivor := local.call(&pfslocal.LookupRequest{
				Dir: dir.Attr.Item, Name: []byte("b"),
			}).(*pfslocal.LookupReply)
			if survivor.Attr.Item != old.Attr.Item {
				t.Fatalf("%s lost old identity through unseen alias: old=%+v b=%+v",
					mode, old.Attr.Item, survivor.Attr.Item)
			}

			// Once the unseen alias is known, mutations through that retained
			// identity must update the now-canonical alias.
			updated := []byte("old-after\n")
			bOpen := local.call(&pfslocal.OpenRequest{
				Item: survivor.Attr.Item, Mode: pfslocal.OpenModeReadWrite,
			}).(*pfslocal.OpenReply)
			local.call(&pfslocal.WriteRequest{
				Handle: bOpen.Handle, Offset: 0, Data: updated,
			})
			local.call(&pfslocal.FsyncRequest{Handle: bOpen.Handle})
			if got := local.call(&pfslocal.ReadRequest{
				Handle: bOpen.Handle, Length: 64,
			}).(*pfslocal.ReadReply); string(got.Data) != string(updated) {
				t.Fatalf("%s retained alias bytes=%q want=%q", mode, got.Data, updated)
			}
			local.call(&pfslocal.CloseRequest{Handle: bOpen.Handle})
			local.call(&pfslocal.CloseRequest{Handle: old.Handle})
		})
	}
}

func TestRenameBetweenSameInodeHardLinksIsRegistryNoOp(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	ref := ensureAttach(t, hc, authority, "vol-same-inode-rename", "main", "/Volumes/SameInodeRename")

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "same-inode-rename"})
	root := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root
	a := c.call(&pfslocal.CreateRequest{
		Dir: root, Name: []byte("a"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.CloseRequest{Handle: a.Handle})
	b := c.call(&pfslocal.HardLinkRequest{
		Item: a.Attr.Item, Dir: root, Name: []byte("b"),
	}).(*pfslocal.HardLinkReply)
	c.call(&pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("a"),
		ToDir: root, ToName: []byte("b"),
	})

	aAfter := c.call(&pfslocal.LookupRequest{
		Dir: root, Name: []byte("a"),
	}).(*pfslocal.LookupReply)
	bAfter := c.call(&pfslocal.LookupRequest{
		Dir: root, Name: []byte("b"),
	}).(*pfslocal.LookupReply)
	if aAfter.Attr.Item != a.Attr.Item || bAfter.Attr.Item != a.Attr.Item ||
		aAfter.Attr.Nlink != 2 || bAfter.Attr.Nlink != 2 || b.Attr.Item != a.Attr.Item {
		t.Fatalf("same-inode rename changed links: before a=%+v b=%+v after a=%+v b=%+v",
			a.Attr, b.Attr, aAfter.Attr, bAfter.Attr)
	}
}
