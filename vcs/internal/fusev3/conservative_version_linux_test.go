//go:build linux

package fusev3

import (
	"context"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

// Object versions are conservative: the authority may raise an unchanged
// object's version past its last change when it compacts its version map. A
// sample of an unchanged object with a higher version is therefore not a
// change. Only an explicit change entry withdraws cached state, and its
// version bounds which later samples may be cached again.
func TestVersionInflationAloneWithdrawsNothing(t *testing.T) {
	fixture := newStockFixture(t)
	item := testItem(95, authoritypb.Attr_REGULAR, 95)
	item.Attr.Size = 7
	fixture.rpc.byName = map[string]*authoritypb.Item{"file": item, "alias": item}
	fixture.rpc.mu.Lock()
	fixture.rpc.readSequence = 5
	fixture.rpc.mu.Unlock()
	fixture.lookup(t, fuse.FUSE_ROOT_ID, "file")
	identity := publicationIdentity(item.GetStableIdentity())
	notifies := len(fixture.notify.snapshot())

	// A fresh sample of the same unchanged object, reached through another
	// name, carries an inflated version and the identical attributes.
	fixture.rpc.mu.Lock()
	fixture.rpc.readSequence = 100
	fixture.rpc.mu.Unlock()
	if entry := fixture.lookup(t, fuse.FUSE_ROOT_ID, "alias"); entry.Attr.Size != 7 {
		t.Fatalf("inflated sample size = %d, want 7", entry.Attr.Size)
	}
	if got := len(fixture.notify.snapshot()); got != notifies {
		t.Fatalf("an inflated version alone sent %d kernel invalidations", got-notifies)
	}
	fixture.raw.mu.Lock()
	payload := fixture.raw.cachedAttrPayloads[identity]
	fixture.raw.mu.Unlock()
	if payload.objectVersion != 100 || payload.attr.GetSize() != 7 {
		t.Fatalf("daemon payload = version %d size %d, want the inflated version with unchanged attributes", payload.objectVersion, payload.attr.GetSize())
	}
	calls := fixture.rpcCalls()
	if entry := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file"); entry.Attr.Size != 7 || fixture.rpcCalls() != calls {
		t.Fatalf("the unchanged name was withdrawn by version inflation: size %d, authority calls %d->%d", entry.Attr.Size, calls, fixture.rpcCalls())
	}

	// A real change still withdraws, and its version is the cut: a delayed
	// pre-change sample, even one carrying an inflated object version below
	// the change, is served but never cached.
	entry := &authoritypb.ChangeEntry{Position: 1, VolumeVersion: 102, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:]}
	incarnation := fixture.mount.subscription.stamp().incarnation
	if err := fixture.mount.subscription.registerChangeBatch(incarnation, &authoritypb.ChangeBatch{Incarnation: incarnation, Entries: []*authoritypb.ChangeEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.mount.subscription.applyChange(context.Background(), incarnation, entry); err != nil {
		t.Fatal(err)
	}
	if len(fixture.notify.snapshot()) == notifies {
		t.Fatal("an explicit attribute change sent no kernel invalidation")
	}
	for range 2 {
		calls = fixture.rpcCalls()
		fixture.lookup(t, fuse.FUSE_ROOT_ID, "file")
		if fixture.rpcCalls() == calls {
			t.Fatal("a pre-change sample was cached past the change that superseded it")
		}
	}
	changed := proto.Clone(item).(*authoritypb.Item)
	changed.Attr.Size = 9
	fixture.rpc.mu.Lock()
	fixture.rpc.byName["file"] = changed
	fixture.rpc.readSequence = 103
	fixture.rpc.mu.Unlock()
	if entry := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file"); entry.Attr.Size != 9 {
		t.Fatalf("post-change size = %d, want 9", entry.Attr.Size)
	}
	calls = fixture.rpcCalls()
	if entry := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file"); entry.Attr.Size != 9 || fixture.rpcCalls() != calls {
		t.Fatalf("a post-change sample was not cached: size %d, authority calls %d->%d", entry.Attr.Size, calls, fixture.rpcCalls())
	}
}

// A holder's base attributes compare object versions only, against the
// explicit change versions that invalidate them. An inflated sample of an
// unchanged object replaces the base without loss, an older sample never
// regresses it, and once a change invalidates the base no pre-change sample
// can reinstall it, whatever inflated version that sample carries.
func TestHolderBaseTreatsVersionInflationAsNoChange(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 96, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	parsed, err := delegationIdentity(id)
	if err != nil {
		t.Fatal(err)
	}
	base := func() (*authoritypb.Attr, uint64) {
		s := m.state(parsed)
		s.meta.Lock()
		defer s.meta.Unlock()
		return s.base, s.baseVersion
	}
	before := &authoritypb.Attr{Inode: 96, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: 4}
	after := &authoritypb.Attr{Inode: 96, Kind: authoritypb.Attr_REGULAR, Mode: 0o640, Size: 9}

	for _, step := range []struct {
		name        string
		install     *authoritypb.Attr
		version     uint64
		invalidate  uint64
		wantAttr    *authoritypb.Attr
		wantVersion uint64
	}{
		{name: "first sample", install: before, version: 5, wantAttr: before, wantVersion: 5},
		{name: "inflated unchanged sample", install: before, version: 100, wantAttr: before, wantVersion: 100},
		{name: "delayed older sample", install: before, version: 5, wantAttr: before, wantVersion: 100},
		{name: "explicit change", invalidate: 102, wantAttr: nil, wantVersion: 100},
		{name: "delayed inflated pre-change sample", install: before, version: 100, wantAttr: nil, wantVersion: 100},
		{name: "post-change sample", install: after, version: 102, wantAttr: after, wantVersion: 102},
	} {
		if step.install != nil {
			if err := m.SetBaseAttr(id, step.install, step.version); err != nil {
				t.Fatalf("%s: %v", step.name, err)
			}
		} else {
			m.InvalidateBaseAttr(id, step.invalidate)
		}
		attr, version := base()
		if !proto.Equal(attr, step.wantAttr) || attr != nil && version != step.wantVersion {
			t.Fatalf("%s: base = %v at version %d, want %v at %d", step.name, attr, version, step.wantAttr, step.wantVersion)
		}
		if !m.Owns(id) || m.LossSequence() != 0 {
			t.Fatalf("%s: version comparison cost the holder its delegation", step.name)
		}
	}
}
