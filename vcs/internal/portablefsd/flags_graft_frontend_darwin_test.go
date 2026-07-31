package portablefsd

// chflags(2) through the FRONTEND surface on an attach that mixes both kinds
// of backing.
//
// The distinction this pins: an attach's authority and an attach's namespace
// are not the same thing. Capabilities.FlagsSupported describes the AUTHORITY
// (does it durably store a flag word), and it is false here. A machine-local
// graft in the same namespace is backed by a real host inode, so chflags(2) on
// it is the durable store and no authority feature is involved at all.
//
// A frontend that treated FlagsSupported as a volume-wide verdict would refuse
// every chflags on this mount, grafts included — the regression this file
// exists to keep out. The daemon therefore decides PER TARGET, and it
// advertises FlagsUnderstood (do I parse set_flags at all) as the only
// volume-wide fact a frontend may gate on.
//
// Deliberately routed through the pfslocal socket rather than calling
// attach.setattr directly: the direct call cannot observe what the resolve
// reply told the frontend, which is exactly where the regression lived.

import (
	"net/http"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// graftBackingPath finds a grafted file's real backing inode under the
// daemon's state dir. The storage-id segment is an implementation detail, so
// it is globbed rather than recomputed.
func graftBackingPath(t *testing.T, cfg Config, rel string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(cfg.StateDir, "local", "*", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("graft backing for %q: %d matches (%v)", rel, len(matches), matches)
	}
	return matches[0]
}

// TestFrontendGraftFlagsSucceedWhileAuthorityFlagsAreRefused: one attach, one
// connection, two targets, two answers.
func TestFrontendGraftFlagsSucceedWhileAuthorityFlagsAreRefused(t *testing.T) {
	authority := serveAuthorityWithoutFlagPersistence(t)
	cfg, hc, cancel := startDaemonNoAttach(t, authority)
	defer cancel()
	ref := ensureLocalDirsAttach(t, hc, authority, "vol-graft-flags", "/Volumes/GraftFlags",
		[]string{"cache"})

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "go-test"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)

	// The authority genuinely cannot persist a flag word...
	if res.Capabilities.FlagsSupported {
		t.Fatal("resolve advertised FlagsSupported for an authority that cannot persist flags")
	}
	// ...and the daemon still says it PARSES set_flags, because it does. This
	// is the fact the frontend gates forwarding on; suppressing it here is
	// what silently broke graft chflags.
	if !res.Capabilities.FlagsUnderstood {
		t.Fatal("resolve withheld FlagsUnderstood on an attach whose authority lacks the feature")
	}
	root := res.Root

	// The graft root is owned by the rule, so it does not exist until it is
	// created locally.
	cacheDir := mkdirItem(t, c, root, "cache")

	created := c.call(&pfslocal.CreateRequest{
		Dir: cacheDir.Item, Name: []byte("grafted.txt"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.CloseRequest{Handle: created.Handle})

	want := uint32(unix.UF_HIDDEN | unix.UF_NODUMP)
	set := c.call(&pfslocal.SetAttrRequest{
		Item: created.Attr.Item, SetFlags: true, Flags: want,
	}).(*pfslocal.SetAttrReply)
	if set.Attr.Flags != want {
		t.Fatalf("graft chflags reply flags = %#x, want %#x", set.Attr.Flags, want)
	}
	// Not just the reply: the change reached the real host inode, which is the
	// graft's durable store.
	var st unix.Stat_t
	backing := graftBackingPath(t, cfg, "cache/grafted.txt")
	if err := unix.Lstat(backing, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags&want != want {
		t.Fatalf("backing inode %s flags = %#x, want %#x set", backing, st.Flags, want)
	}
	if got := c.call(&pfslocal.GetAttrRequest{Item: created.Attr.Item}).(*pfslocal.GetAttrReply); got.Attr.Flags != want {
		t.Fatalf("graft getattr flags = %#x, want %#x", got.Attr.Flags, want)
	}

	// The SAME request shape against an AUTHORITY-backed path in the SAME
	// namespace is refused, because that authority has nowhere to put it.
	remote := c.call(&pfslocal.CreateRequest{
		Dir: root, Name: []byte("authority.txt"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.CloseRequest{Handle: remote.Handle})

	mode := uint32(0o600)
	if er := c.callErr(&pfslocal.SetAttrRequest{
		Item: remote.Attr.Item, Mode: &mode, SetFlags: true, Flags: want,
	}); er.Errno != darwinENOTSUP {
		t.Fatalf("authority-backed chflags errno=%d, want ENOTSUP(%d)", er.Errno, darwinENOTSUP)
	}
	// And the refusal took the whole setattr with it.
	after := c.call(&pfslocal.GetAttrRequest{Item: remote.Attr.Item}).(*pfslocal.GetAttrReply)
	if after.Attr.Flags != 0 {
		t.Fatalf("a refused authority chflags stored %#x", after.Attr.Flags)
	}
	if after.Attr.Mode&0o777 != 0o644 {
		t.Fatalf("a refused authority chflags applied its co-travelling chmod: mode=%o",
			after.Attr.Mode&0o777)
	}

	// A flags change on the graft still works after the authority refusal:
	// one target's answer is not the volume's answer.
	cleared := c.call(&pfslocal.SetAttrRequest{
		Item: created.Attr.Item, SetFlags: true,
	}).(*pfslocal.SetAttrReply)
	if cleared.Attr.Flags != 0 {
		t.Fatalf("graft clear flags = %#x, want 0", cleared.Attr.Flags)
	}
	if err := unix.Lstat(backing, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags&want != 0 {
		t.Fatalf("backing inode kept %#x after a clearing chflags", st.Flags&want)
	}

	// The capability is a property of the attach, not of the connection that
	// happened to ask first: a fresh frontend is told the same thing.
	c2 := dialPFS(t, cfg.FrontendSocket)
	defer c2.close()
	c2.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "go-test-2"})
	res2 := c2.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	if !res2.Capabilities.FlagsUnderstood || res2.Capabilities.FlagsSupported {
		t.Fatalf("second resolve capabilities = %+v", res2.Capabilities)
	}

	// Sanity: the attach really is configured with the graft (a typo in the
	// rule would make "cache" an ordinary authority directory and quietly turn
	// the first half of this test into a no-op).
	var one attachStatus
	controlJSON(t, hc, http.MethodGet, "/v1/attaches/"+ref, nil, http.StatusOK, &one)
	if len(one.LocalDirs) != 1 || one.LocalDirs[0] != "cache" {
		t.Fatalf("attach localDirs = %v, want [cache]", one.LocalDirs)
	}
}
