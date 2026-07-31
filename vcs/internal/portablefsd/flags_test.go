package portablefsd

// Daemon-side coverage for chflags(2). The daemon publishes whether this
// attach's authority can persist a flag word (resolve's FlagsSupported — what
// the frontend gates its own forwarding on) and either applies a forwarded
// change or refuses it with ENOTSUP as the invariant check against a frontend
// that forwarded anyway. Nothing here may ever be a silent no-op.

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// A BSD flag word with bits in both the user (0x0000ffff) and super-user
// (0xffff0000) halves. Spelled numerically so the test compiles on the linux
// CI runners, which have no UF_/SF_ constants.
const testBsdFlags = uint32(0x8000_0002)

// noInodeMetadataAuthority models an authority PREDATING the PFT2 inode-record
// revision that stores BSD flags and birth times. Embedding leaves every other
// capability identical, so the only observable difference is the missing
// FeatureFlagPersistence bit.
type noInodeMetadataAuthority struct{ *workfs.FS }

func (noInodeMetadataAuthority) PersistsInodeMetadata() bool { return false }

func serveAuthorityWithoutFlagPersistence(t *testing.T) string {
	t.Helper()
	fs := newManagedTestFS(t, daemonTestBlobs{}, filepath.Join(privateTestDir(t), "wal.log"))
	wrapped := noInodeMetadataAuthority{FS: fs}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = fsproto.NewServer(wrapped, wrapped).Serve(ctx, ln) }()
	return ln.Addr().String()
}

// TestFrontendSetattrFlagsPersistAgainstFeatureAdvertisingAuthority: the whole
// path a chflags(2) takes — pfslocal SetAttrRequest, the daemon's feature
// check, the split exact setattr, the authority's durable record — and back out
// through getattr and enumerate.
func TestFrontendSetattrFlagsPersistAgainstFeatureAdvertisingAuthority(t *testing.T) {
	cfg, _, ref, _ := startDaemon(t, serveAuthority(t))
	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "go-test"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	if !res.Capabilities.FlagsSupported {
		t.Fatal("resolve did not advertise FlagsSupported for a flag-persisting authority")
	}
	root := res.Root

	cr := c.call(&pfslocal.CreateRequest{
		Dir: root, Name: []byte("flagged.txt"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.CloseRequest{Handle: cr.Handle})
	if cr.Attr.Flags != 0 {
		t.Fatalf("fresh file flags = %#x, want 0", cr.Attr.Flags)
	}

	set := c.call(&pfslocal.SetAttrRequest{
		Item: cr.Attr.Item, SetFlags: true, Flags: testBsdFlags,
	}).(*pfslocal.SetAttrReply)
	if set.Attr.Flags != testBsdFlags {
		t.Fatalf("setattr reply flags = %#x, want %#x", set.Attr.Flags, testBsdFlags)
	}
	got := c.call(&pfslocal.GetAttrRequest{Item: cr.Attr.Item}).(*pfslocal.GetAttrReply)
	if got.Attr.Flags != testBsdFlags {
		t.Fatalf("getattr flags = %#x, want %#x", got.Attr.Flags, testBsdFlags)
	}
	// readdir-plus fills the frontend's attr cache, so it must agree.
	page := c.call(&pfslocal.EnumerateRequest{
		Dir: root, MaxEntries: 32, WantAttrs: true,
	}).(*pfslocal.EnumerateReply)
	var seen bool
	for _, e := range page.Entries {
		if string(e.Name) != "flagged.txt" {
			continue
		}
		seen = true
		if e.Attr.Flags != testBsdFlags {
			t.Fatalf("enumerate flags = %#x, want %#x", e.Attr.Flags, testBsdFlags)
		}
	}
	if !seen {
		t.Fatal("enumerate did not list the flagged file")
	}

	// mode + mtime + flags in ONE request: the client splits it into separate
	// exact identities and every group lands.
	mode := uint32(0o600)
	mtime := int64(456_000)
	multi := c.call(&pfslocal.SetAttrRequest{
		Item: cr.Attr.Item, Mode: &mode, MtimeMs: &mtime,
		SetFlags: true, Flags: 0x4,
	}).(*pfslocal.SetAttrReply)
	if multi.Attr.Mode&0o777 != 0o600 || multi.Attr.MtimeMs != mtime || multi.Attr.Flags != 0x4 {
		t.Fatalf("multi-group setattr attr = %+v", multi.Attr)
	}

	// Clearing to zero is a durable state, not "no change".
	cleared := c.call(&pfslocal.SetAttrRequest{
		Item: cr.Attr.Item, SetFlags: true,
	}).(*pfslocal.SetAttrReply)
	if cleared.Attr.Flags != 0 {
		t.Fatalf("cleared flags = %#x, want 0", cleared.Attr.Flags)
	}

	// A setattr with no flags intent leaves the stored word alone.
	if _, ok := c.call(&pfslocal.SetAttrRequest{
		Item: cr.Attr.Item, SetFlags: true, Flags: testBsdFlags,
	}).(*pfslocal.SetAttrReply); !ok {
		t.Fatal("restore flags")
	}
	only := c.call(&pfslocal.SetAttrRequest{Item: cr.Attr.Item, Mode: &mode}).(*pfslocal.SetAttrReply)
	if only.Attr.Flags != testBsdFlags {
		t.Fatalf("a flagless setattr reset the stored word to %#x", only.Attr.Flags)
	}
}

// TestFrontendSetattrFlagsRefusedWithoutTheFeature: the honest refusal. The
// resolve reply says so up front (the frontend turns that into its mount-time
// volume capability) and any flags setattr that arrives anyway is ENOTSUP with
// nothing applied — including the groups that travelled with it.
func TestFrontendSetattrFlagsRefusedWithoutTheFeature(t *testing.T) {
	cfg, _, ref, _ := startDaemon(t, serveAuthorityWithoutFlagPersistence(t))
	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "go-test"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	if res.Capabilities.FlagsSupported {
		t.Fatal("resolve advertised FlagsSupported for an authority that cannot persist flags")
	}
	// The rest of the capability set is unaffected by the missing bit.
	if !res.Capabilities.Symlinks || !res.Capabilities.HardLinks || !res.Capabilities.Xattrs {
		t.Fatalf("capabilities = %+v", res.Capabilities)
	}
	root := res.Root

	cr := c.call(&pfslocal.CreateRequest{
		Dir: root, Name: []byte("refused.txt"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.CloseRequest{Handle: cr.Handle})

	mode := uint32(0o600)
	if er := c.callErr(&pfslocal.SetAttrRequest{
		Item: cr.Attr.Item, Mode: &mode, SetFlags: true, Flags: testBsdFlags,
	}); er.Errno != darwinENOTSUP {
		t.Fatalf("flags setattr errno=%d want ENOTSUP(%d)", er.Errno, darwinENOTSUP)
	}
	got := c.call(&pfslocal.GetAttrRequest{Item: cr.Attr.Item}).(*pfslocal.GetAttrReply)
	if got.Attr.Flags != 0 {
		t.Fatalf("a refused chflags stored %#x", got.Attr.Flags)
	}
	if got.Attr.Mode&0o777 != 0o644 {
		t.Fatalf("a refused chflags applied its co-travelling chmod: mode=%o", got.Attr.Mode&0o777)
	}
	// A setattr with no flags intent is unaffected.
	ok := c.call(&pfslocal.SetAttrRequest{Item: cr.Attr.Item, Mode: &mode}).(*pfslocal.SetAttrReply)
	if ok.Attr.Mode&0o777 != 0o600 {
		t.Fatalf("flagless chmod mode=%o", ok.Attr.Mode&0o777)
	}
}
