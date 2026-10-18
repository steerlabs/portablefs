package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// lookupByName serves Lookup from a fixed name table with a fresh capability
// per reply, the way the authority does.
func lookupByName(client *fakeV3DataClient, names map[string]*authoritypb.Item) func(context.Context, authorityrpc.MutationIdentity, *authoritypb.Request) (*authoritypb.Response, error) {
	return func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		switch request.GetBody().(type) {
		case *authoritypb.Request_Reclaim:
			return client.reclaim(identity, request), nil
		case *authoritypb.Request_CloseBatch:
			return client.closeBatch(identity, request), nil
		case *authoritypb.Request_Lookup:
			template := names[string(request.GetLookup().GetName())]
			response := exactTestMutationReply(identity)
			if template == nil {
				response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: 1}}
				return response, nil
			}
			item := client.issueItem(template.GetAttr().GetInode(), template.GetAttr().GetKind(), template.GetStableIdentity()[0])
			response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: item}}
			return response, nil
		default:
			return nil, errors.New("unexpected authority mutation")
		}
	}
}

func lookupTestAttr(t *testing.T, d *v3DataPlane, dir pfslocal.Item, name string) pfslocal.Attr {
	t.Helper()
	reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{Dir: dir, Name: []byte(name)})
	if errno != 0 {
		t.Fatalf("lookup %q errno=%d", name, errno)
	}
	return reply.(*pfslocal.LookupReply).Attr
}

func TestV3FileIDsFollowTheAuthorityInodeExceptTheRoot(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	resolved := d.resolveReply()
	// The fake root's physical inode is 1, outside the non-root range: the
	// root's file ID comes from its activated identity, never its inode.
	if resolved.RootAttr.FileID != v3RootFileID || resolved.RootAttr.ParentFileID != 0 || resolved.RootAttr.Parent != nil {
		t.Fatalf("root attr = %+v, want file ID 1 with no parent", resolved.RootAttr)
	}
	file := lookupTestAttr(t, d, resolved.Root, "file")
	if file.FileID != 2 || file.ParentFileID != v3RootFileID || file.Parent == nil || *file.Parent != resolved.Root {
		t.Fatalf("lookup attr = %+v, want inode 2 under the root", file)
	}
	getattr, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.GetAttrRequest{Item: resolved.Root})
	if errno != 0 || getattr.(*pfslocal.GetAttrReply).Attr.FileID != v3RootFileID {
		t.Fatalf("root getattr = (%#v,%d), want file ID 1", getattr, errno)
	}
}

func TestV3FileIDRangeIsEnforcedAtIngestion(t *testing.T) {
	for _, test := range []struct {
		name  string
		inode uint64
		ok    bool
	}{
		{name: "zero", inode: 0},
		{name: "one", inode: 1},
		{name: "first", inode: 2, ok: true},
		{name: "last", inode: 1<<63 - 1, ok: true},
		{name: "repair-partition", inode: 1 << 63},
		{name: "max", inode: math.MaxUint64},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				if request.GetReclaim() != nil {
					return client.reclaim(identity, request), nil
				}
				response := exactTestMutationReply(identity)
				response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: client.issueItem(test.inode, authoritypb.Attr_REGULAR, 0x41)}}
				return response, nil
			}
			reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("x")})
			if test.ok {
				if errno != 0 || reply.(*pfslocal.LookupReply).Attr.FileID != test.inode {
					t.Fatalf("lookup inode %d = (%#v,%d)", test.inode, reply, errno)
				}
				return
			}
			if errno != darwinEIO || d.terminalError() == nil {
				t.Fatalf("lookup inode %d = (%#v,%d), want terminal malformed authority data", test.inode, reply, errno)
			}
		})
	}
}

func TestV3HardLinksShareFileIDWithDistinctParentBindings(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	client.mutation = lookupByName(client, map[string]*authoritypb.Item{
		"dir":   authorityTestItem(5, authoritypb.Attr_DIRECTORY, 0, 0x50),
		"alias": authorityTestItem(7, authoritypb.Attr_REGULAR, 0, 0x70),
	})
	root := d.resolveReply().Root
	dir := lookupTestAttr(t, d, root, "dir")
	first := lookupTestAttr(t, d, root, "alias")
	second := lookupTestAttr(t, d, dir.Item, "alias")
	if first.Item != second.Item || first.FileID != 7 || second.FileID != 7 {
		t.Fatalf("hard-link aliases = %+v / %+v, want one canonical item and file ID 7", first, second)
	}
	if first.ParentFileID != v3RootFileID || second.ParentFileID != dir.FileID ||
		*first.Parent != root || *second.Parent != dir.Item {
		t.Fatalf("alias parents = %d/%d, want the concrete directory of each lookup", first.ParentFileID, second.ParentFileID)
	}
	// The second lookup's capability duplicated the held one and was retired in
	// one exact batched Reclaim; the canonical capability stays live.
	waitV3ReleasesIdle(t, d)
	batches := client.reclaimBatches()
	if len(batches) != 1 || len(batches[0]) != 1 {
		t.Fatalf("reclaim batches = %x, want one duplicate retirement", batches)
	}
	if live := client.liveTokens(); live != 3 {
		t.Fatalf("live authority capabilities = %d, want root, dir, and one alias", live)
	}
	for _, request := range client.mutationRequests() {
		if reclaim := request.GetReclaim(); reclaim != nil && len(reclaim.GetItem()) != 0 {
			t.Fatal("duplicate retirement used the singular legacy Reclaim form")
		}
	}
}

func TestV3FileIDSurvivesReclaimAndRelookupUnderANewHandle(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	root := d.resolveReply().Root
	before := lookupTestAttr(t, d, root, "file")
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.ReclaimRequest{Item: before.Item}); errno != 0 {
		t.Fatalf("reclaim errno=%d", errno)
	}
	waitV3ReleasesIdle(t, d)
	if live := client.liveTokens(); live != 1 {
		t.Fatalf("live capabilities after reclaim = %d, want only the root", live)
	}
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.GetAttrRequest{Item: before.Item}); errno != darwinESTALE {
		t.Fatalf("old handle getattr errno=%d, want ESTALE", errno)
	}
	after := lookupTestAttr(t, d, root, "file")
	if after.Item.ItemID == before.Item.ItemID || after.Item.StableIdentity != before.Item.StableIdentity {
		t.Fatalf("relookup item = %+v, want a new handle for the same identity than %+v", after.Item, before.Item)
	}
	if after.FileID != before.FileID {
		t.Fatalf("file ID changed across reclaim: %d -> %d", before.FileID, after.FileID)
	}
}

func TestV3EveryLiveAttrCarriesFileIDs(t *testing.T) {
	mode := uint32(0o600)
	tests := []struct {
		name       string
		request    func(root, file pfslocal.Item, handle uint64) any
		reply      func(client *fakeV3DataClient, identity authorityrpc.MutationIdentity, request *authoritypb.Request) *authoritypb.Response
		attr       func(reply any) pfslocal.Attr
		fileID     uint64
		parentFile uint64
	}{
		{
			name:    "getattr",
			request: func(_, file pfslocal.Item, _ uint64) any { return &pfslocal.GetAttrRequest{Item: file} },
			attr:    func(reply any) pfslocal.Attr { return reply.(*pfslocal.GetAttrReply).Attr },
			fileID:  2, parentFile: v3RootFileID,
		},
		{
			name: "setattr",
			request: func(_, file pfslocal.Item, _ uint64) any {
				return &pfslocal.SetAttrRequest{Item: file, Mode: &mode}
			},
			reply: func(_ *fakeV3DataClient, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) *authoritypb.Response {
				response := exactTestMutationReply(identity)
				response.PostState = testV3TargetState(0x40, &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2, Mode: 0o600, Nlink: 1}, 2)
				return response
			},
			attr:   func(reply any) pfslocal.Attr { return reply.(*pfslocal.SetAttrReply).Attr },
			fileID: 2, parentFile: v3RootFileID,
		},
		{
			name: "write",
			request: func(_, _ pfslocal.Item, handle uint64) any {
				return &pfslocal.WriteRequest{Handle: handle, Data: []byte("abc")}
			},
			reply: func(_ *fakeV3DataClient, identity authorityrpc.MutationIdentity, request *authoritypb.Request) *authoritypb.Response {
				return exactTestWriteReply(identity, request)
			},
			attr:   func(reply any) pfslocal.Attr { return reply.(*pfslocal.WriteReply).Attr },
			fileID: 2, parentFile: v3RootFileID,
		},
		{
			name: "create",
			request: func(root, _ pfslocal.Item, _ uint64) any {
				return &pfslocal.CreateRequest{Dir: root, Name: []byte("new"), Mode: 0o644, Exclusive: true}
			},
			reply: func(client *fakeV3DataClient, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) *authoritypb.Response {
				response := exactTestMutationReply(identity)
				item := client.issueItem(30, authoritypb.Attr_REGULAR, 0x63)
				response.PostState = testV3RootBinding(item, v3PostStateRoleCreated)
				response.Body = &authoritypb.Response_Create{Create: &authoritypb.CreateReply{
					Item: item, Handle: bytes.Repeat([]byte{0x64}, 16),
				}}
				return response
			},
			attr:   func(reply any) pfslocal.Attr { return reply.(*pfslocal.CreateReply).Attr },
			fileID: 30, parentFile: v3RootFileID,
		},
		{
			name: "mkdir",
			request: func(root, _ pfslocal.Item, _ uint64) any {
				return &pfslocal.MkdirRequest{Dir: root, Name: []byte("dir"), Mode: 0o755}
			},
			reply: func(client *fakeV3DataClient, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) *authoritypb.Response {
				response := exactTestMutationReply(identity)
				item := client.issueItem(31, authoritypb.Attr_DIRECTORY, 0x65)
				response.PostState = testV3RootBinding(item, v3PostStateRoleCreated)
				response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: item}}
				return response
			},
			attr:   func(reply any) pfslocal.Attr { return reply.(*pfslocal.MkdirReply).Attr },
			fileID: 31, parentFile: v3RootFileID,
		},
		{
			name: "symlink",
			request: func(root, _ pfslocal.Item, _ uint64) any {
				return &pfslocal.SymlinkRequest{Dir: root, Name: []byte("link"), Target: []byte("file")}
			},
			reply: func(client *fakeV3DataClient, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) *authoritypb.Response {
				response := exactTestMutationReply(identity)
				item := client.issueItem(32, authoritypb.Attr_SYMLINK, 0x66)
				response.PostState = testV3RootBinding(item, v3PostStateRoleCreated)
				response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: item}}
				return response
			},
			attr:   func(reply any) pfslocal.Attr { return reply.(*pfslocal.SymlinkReply).Attr },
			fileID: 32, parentFile: v3RootFileID,
		},
		{
			name: "hard-link",
			request: func(root, file pfslocal.Item, _ uint64) any {
				return &pfslocal.HardLinkRequest{Item: file, Dir: root, Name: []byte("alias")}
			},
			reply: func(_ *fakeV3DataClient, identity authorityrpc.MutationIdentity, request *authoritypb.Request) *authoritypb.Response {
				linked := authorityTestItem(2, authoritypb.Attr_REGULAR, 0, 0x40)
				linked.Token = request.GetLink().GetExistingItem()
				linked.Attr.Nlink = 2
				response := exactTestMutationReply(identity)
				response.PostState = testV3RootBinding(linked, v3PostStateRoleTarget)
				response.Body = &authoritypb.Response_Link{Link: &authoritypb.LinkReply{Item: linked}}
				return response
			},
			attr:   func(reply any) pfslocal.Attr { return reply.(*pfslocal.HardLinkReply).Attr },
			fileID: 2, parentFile: v3RootFileID,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			root := d.resolveReply().Root
			file, handle := openTestV3File(t, d, false)
			if test.reply != nil {
				client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
					return test.reply(client, identity, request), nil
				}
			}
			reply, errno := dispatchV3Test(d, context.Background(), 0, test.request(root, file, handle))
			if errno != 0 {
				t.Fatalf("%s errno=%d", test.name, errno)
			}
			attr := test.attr(reply)
			if attr.FileID != test.fileID || attr.ParentFileID != test.parentFile {
				t.Fatalf("%s attr file IDs = %d/%d, want %d/%d", test.name, attr.FileID, attr.ParentFileID, test.fileID, test.parentFile)
			}
		})
	}
}

func TestV3AttrMustDescribeItsOwnItem(t *testing.T) {
	for _, test := range []struct {
		name string
		attr *authoritypb.Attr
	}{
		{name: "other-inode", attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 3, Nlink: 1}},
		{name: "other-kind", attr: &authoritypb.Attr{Kind: authoritypb.Attr_DIRECTORY, Inode: 2, Nlink: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
			client.read = func(context.Context, *authoritypb.Request) (*authoritypb.Response, error) {
				return &authoritypb.Response{Body: &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: test.attr, ObjectVersion: 1, SnapshotSequence: 1}}}, nil
			}
			if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.GetAttrRequest{Item: file.Item}); errno != darwinEIO || d.terminalError() == nil {
				t.Fatalf("getattr of another object errno=%d, want terminal EIO", errno)
			}
		})
	}
}

// Reclaim detaches before its authority round trip, so a lookup that races it
// interns a fresh record under a new handle; the old completion retires only
// its own capability.
func TestV3LookupDuringReclaimGetsAFreshHandleTheOldCompletionCannotTouch(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	root := d.resolveReply().Root
	old := lookupTestAttr(t, d, root, "file")
	reclaimEntered, releaseReclaim := make(chan struct{}), make(chan struct{})
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		switch request.GetBody().(type) {
		case *authoritypb.Request_Reclaim:
			close(reclaimEntered)
			<-releaseReclaim
			return client.reclaim(identity, request), nil
		case *authoritypb.Request_Lookup:
			response := exactTestMutationReply(identity)
			response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: client.issueItem(2, authoritypb.Attr_REGULAR, 0x40)}}
			return response, nil
		default:
			return nil, errors.New("unexpected authority mutation")
		}
	}
	reclaimed := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.ReclaimRequest{Item: old.Item})
		reclaimed <- errno
	}()
	select {
	case <-reclaimEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("reclaim never reached the authority")
	}
	fresh := lookupTestAttr(t, d, root, "file")
	if fresh.Item.ItemID == old.Item.ItemID || fresh.FileID != old.FileID {
		t.Fatalf("lookup during reclaim = %+v, want a new handle with file ID %d", fresh.Item, old.FileID)
	}
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.GetAttrRequest{Item: old.Item}); errno != darwinESTALE {
		t.Fatalf("retiring handle errno=%d, want ESTALE", errno)
	}
	close(releaseReclaim)
	if errno := <-reclaimed; errno != 0 {
		t.Fatalf("reclaim errno=%d", errno)
	}
	waitV3ReleasesIdle(t, d)
	d.mu.Lock()
	record := d.itemsByID[fresh.Item.ItemID]
	canonical := d.itemsByIdentity[fresh.Item.StableIdentity]
	d.mu.Unlock()
	if record == nil || canonical != record || !record.accepted {
		t.Fatal("the old completion removed the replacement record")
	}
	if live := client.liveTokens(); live != 2 {
		t.Fatalf("live capabilities = %d, want the root and the replacement only", live)
	}
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.GetAttrRequest{Item: fresh.Item}); errno != 0 {
		t.Fatalf("replacement getattr errno=%d", errno)
	}
}

// intern takes the reply's provisional reference in the same critical
// section that resolves the record, so an FSKit reclaim arriving before the
// reply is settled defers instead of retiring an item the reply will hand out.
func TestV3InternedItemIsOwnedBeforeReclaimCanObserveIt(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	root := d.resolveReply().Root
	held := lookupTestAttr(t, d, root, "file")
	collector := &v3ReplyResourceCollector{d: d}
	reply, errno := d.dispatchFrontend(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), 0, &pfslocal.LookupRequest{Dir: root, Name: []byte("file")})
	if errno != 0 || reply.(*pfslocal.LookupReply).Attr.Item != held.Item {
		t.Fatalf("overlapping lookup = (%#v,%d)", reply, errno)
	}
	d.mu.Lock()
	record := d.itemsByID[held.Item.ItemID]
	provisional := record.provisional
	d.mu.Unlock()
	if provisional != 1 || len(collector.items) != 1 || collector.items[0] != record {
		t.Fatalf("interned record provisional=%d collected=%d, want the reply's reference already held", provisional, len(collector.items))
	}
	if _, errno := d.reclaim(context.Background(), &pfslocal.ReclaimRequest{Item: held.Item}); errno != 0 {
		t.Fatalf("reclaim errno=%d", errno)
	}
	d.mu.Lock()
	deferred := d.itemsByID[held.Item.ItemID] == record && !record.accepted
	d.mu.Unlock()
	if !deferred {
		t.Fatal("reclaim retired an item a pending reply still owns")
	}
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup, err := d.applyReplyResourceDisposition(resources, false, 1); err != nil || cleanup.required() {
		t.Fatalf("accept cleanup=%+v err=%v", cleanup, err)
	}
	waitV3ReleasesIdle(t, d)
	if !record.accepted || client.liveTokens() != 2 {
		t.Fatal("accepting the overlapping reply did not keep the item and its one capability")
	}
}

// Lookup, accept, and reclaim race on one identity from many callbacks while
// the fake authority enforces that every reclaimed capability is live and
// unique. Every capability must end retired exactly once.
func TestV3ConcurrentLookupAndReclaimRetireEveryCapabilityExactlyOnce(t *testing.T) {
	client := newFakeV3DataClient()
	client.limit = 8
	d := testV3DataPlane(t, client)
	root := d.resolveReply().Root
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{Dir: root, Name: []byte("file")})
				if errno != 0 {
					t.Errorf("lookup errno=%d", errno)
					return
				}
				item := reply.(*pfslocal.LookupReply).Attr.Item
				if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.ReclaimRequest{Item: item}); errno != 0 {
					t.Errorf("reclaim errno=%d", errno)
					return
				}
			}
		}()
	}
	wg.Wait()
	waitV3ReleasesIdle(t, d)
	if err := d.terminalError(); err != nil {
		t.Fatalf("ownership race was terminal: %v", err)
	}
	d.mu.Lock()
	items, identities := len(d.itemsByID), len(d.itemsByIdentity)
	d.mu.Unlock()
	if items != 1 || identities != 1 || client.liveTokens() != 1 {
		t.Fatalf("after the race items=%d identities=%d live=%d, want only the root", items, identities, client.liveTokens())
	}
	for _, batch := range client.reclaimBatches() {
		if len(batch) > d.releases.limit {
			t.Fatalf("reclaim batch of %d exceeds the bound %d", len(batch), d.releases.limit)
		}
	}
}

func TestV3AbandonedItemIsRetiredThroughTheReleaseOwner(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	collector := &v3ReplyResourceCollector{d: d}
	if _, errno := d.dispatchFrontend(context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector), 0,
		&pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")}); errno != 0 {
		t.Fatalf("lookup errno=%d", errno)
	}
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 0)
	if err != nil || len(cleanup.items) != 1 {
		t.Fatalf("abandon cleanup=%+v err=%v", cleanup, err)
	}
	if err := cleanup.finish(); err != nil {
		t.Fatal(err)
	}
	waitV3ReleasesIdle(t, d)
	batches := client.reclaimBatches()
	if len(batches) != 1 || len(batches[0]) != 1 || client.liveTokens() != 1 {
		t.Fatalf("abandon reclaim batches=%x live=%d, want one batched retirement", batches, client.liveTokens())
	}
}

func TestV3ReclaimBatchFailureIsTerminalForTheDataPlane(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		response := exactTestMutationReply(identity)
		response.Errno = errnos.ESTALE
		return response, nil
	}
	// The reply follows local retirement; the release failure that arrives
	// afterwards ends the mount instead.
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.ReclaimRequest{Item: file.Item}); errno != 0 {
		t.Fatalf("reclaim errno=%d", errno)
	}
	waitV3ReleasesIdle(t, d)
	if d.terminalError() == nil {
		t.Fatal("a failed reclaim batch left the data plane serving")
	}
}

func TestV3DrainedReleaseOwnerLeavesRetirementToTheDetach(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
	if err := waitV3ReleaseOwner(context.Background(), d.releases); err != nil {
		t.Fatal(err)
	}
	before := len(client.mutationRequests())
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.ReclaimRequest{Item: file.Item}); errno != 0 {
		t.Fatalf("reclaim after drain errno=%d", errno)
	}
	if after := len(client.mutationRequests()); after != before {
		t.Fatalf("reclaim after drain sent %d authority requests, want none", after-before)
	}
	if d.terminalError() != nil {
		t.Fatalf("reclaim after drain was terminal: %v", d.terminalError())
	}
}

type v3TestObject struct {
	inode   uint64
	kind    authoritypb.Attr_Kind
	nlink   uint32
	size    int64
	mode    uint32
	version uint64
}

// v3TestNamespace is a versioned fake authority: lookups mint fresh
// capabilities, every committed mutation advances one storage sequence and
// stamps each changed object with it, and every reply carries the coherent
// read stamps or whole PostState the real authority sends under
// fskit-versioned-metadata-v1.
type v3TestNamespace struct {
	client  *fakeV3DataClient
	mu      sync.Mutex
	seq     uint64
	objects map[byte]*v3TestObject // by identity byte
	names   map[string]byte        // parent identity byte + "/" + name
	tokens  map[[16]byte]byte      // issued capability -> identity byte
	// hold, when set, is called with each committed reply before it returns,
	// so a test can deliver replies in a chosen order.
	hold func(*authoritypb.Request, *authoritypb.Response)
}

func newV3TestNamespace(client *fakeV3DataClient, objects map[byte]*v3TestObject) *v3TestNamespace {
	ns := &v3TestNamespace{client: client, seq: 1, objects: objects, names: map[string]byte{}, tokens: map[[16]byte]byte{
		[16]byte(client.root.GetToken()): 0x20,
	}}
	ns.objects[0x20] = &v3TestObject{inode: 1, kind: authoritypb.Attr_DIRECTORY, nlink: 2}
	for _, object := range ns.objects {
		if object.version == 0 {
			object.version = 1
		}
	}
	client.mutation = ns.mutate
	client.read = ns.read
	return ns
}

func (ns *v3TestNamespace) bind(parent byte, name string, identity byte) {
	ns.names[fmt.Sprintf("%02x/%s", parent, name)] = identity
}

func (ns *v3TestNamespace) key(parentToken []byte, name []byte) string {
	return fmt.Sprintf("%02x/%s", ns.tokens[[16]byte(parentToken)], name)
}

func (ns *v3TestNamespace) attr(identity byte) *authoritypb.Attr {
	object := ns.objects[identity]
	mode := object.mode
	if mode == 0 {
		mode = 0o755
	}
	return &authoritypb.Attr{Kind: object.kind, Inode: object.inode, Nlink: object.nlink, Mode: mode, Size: object.size}
}

// commit advances the storage sequence and stamps the changed objects.
func (ns *v3TestNamespace) commit(changed ...byte) uint64 {
	ns.seq++
	for _, identity := range changed {
		ns.objects[identity].version = ns.seq
	}
	return ns.seq
}

func (ns *v3TestNamespace) object(identity byte, roles uint32) testV3PostObject {
	return testV3PostObject{identity: identity, attr: ns.attr(identity), version: ns.objects[identity].version, roles: roles}
}

// state merges the roles of repeated identities, as the authority does.
func (ns *v3TestNamespace) state(objects ...testV3PostObject) *authoritypb.PostState {
	merged := map[byte]int{}
	var unique []testV3PostObject
	for _, object := range objects {
		if index, seen := merged[object.identity]; seen {
			unique[index].roles |= object.roles
			continue
		}
		merged[object.identity] = len(unique)
		unique = append(unique, object)
	}
	return testV3MutationState(ns.seq, unique...)
}

func (ns *v3TestNamespace) issue(identity byte) *authoritypb.Item {
	object := ns.objects[identity]
	item := ns.client.issueItem(object.inode, object.kind, identity)
	item.Attr = ns.attr(identity)
	item.ObjectVersion, item.SnapshotSequence = object.version, ns.seq
	ns.tokens[[16]byte(item.GetToken())] = identity
	return item
}

func (ns *v3TestNamespace) read(_ context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if getattr := request.GetGetAttr(); getattr != nil {
		identity := ns.tokens[[16]byte(getattr.GetItem())]
		return &authoritypb.Response{Body: &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{
			Attr: ns.attr(identity), ObjectVersion: ns.objects[identity].version, SnapshotSequence: ns.seq,
		}}}, nil
	}
	return &authoritypb.Response{Body: &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{BlockSize: 4096, NameMax: 255}}}, nil
}

func (ns *v3TestNamespace) mutate(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
	switch request.GetBody().(type) {
	case *authoritypb.Request_Reclaim:
		return ns.client.reclaim(identity, request), nil
	case *authoritypb.Request_CloseBatch:
		return ns.client.closeBatch(identity, request), nil
	}
	ns.mu.Lock()
	response, err := ns.mutateLocked(identity, request)
	hold := ns.hold
	ns.mu.Unlock()
	if hold != nil && err == nil {
		hold(request, response)
	}
	return response, err
}

func (ns *v3TestNamespace) mutateLocked(identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
	response := exactTestMutationReply(identity)
	switch body := request.GetBody().(type) {
	case *authoritypb.Request_Lookup:
		target, ok := ns.names[ns.key(body.Lookup.GetParent(), body.Lookup.GetName())]
		if !ok {
			response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: ns.seq}}
			return response, nil
		}
		response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: ns.issue(target)}}
	case *authoritypb.Request_Open:
		handle := ns.client.issueHandle()
		ns.tokens[[16]byte(handle)] = ns.tokens[[16]byte(body.Open.GetItem())]
		response.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: handle}}
	case *authoritypb.Request_Unlink:
		parent := ns.tokens[[16]byte(body.Unlink.GetParent())]
		key := ns.key(body.Unlink.GetParent(), body.Unlink.GetName())
		removed, ok := ns.names[key]
		if !ok {
			response.Errno = errnos.ENOENT
			return response, nil
		}
		ns.objects[removed].nlink--
		delete(ns.names, key)
		ns.commit(parent, removed)
		response.PostState = ns.state(ns.object(parent, v3PostStateRoleParent), ns.object(removed, v3PostStateRoleRemoved))
	case *authoritypb.Request_Rename:
		oldParent, newParent := ns.tokens[[16]byte(body.Rename.GetOldParent())], ns.tokens[[16]byte(body.Rename.GetNewParent())]
		from := ns.key(body.Rename.GetOldParent(), body.Rename.GetOldName())
		to := ns.key(body.Rename.GetNewParent(), body.Rename.GetNewName())
		moved, ok := ns.names[from]
		if !ok {
			response.Errno = errnos.ENOENT
			return response, nil
		}
		reply := &authoritypb.RenameReply{NewPostIdentity: testV3ID(moved)}
		objects := []testV3PostObject{}
		if victim, replaced := ns.names[to]; replaced && victim == moved {
			// POSIX same-inode no-op: both names remain and nothing changes.
			reply.OldPostIdentity = testV3ID(moved)
		} else {
			changed := []byte{oldParent, newParent, moved}
			if replaced {
				ns.objects[victim].nlink--
				changed = append(changed, victim)
			}
			delete(ns.names, from)
			ns.names[to] = moved
			ns.commit(changed...)
			if replaced {
				objects = append(objects, ns.object(victim, v3PostStateRoleOverwritten))
			}
		}
		objects = append(objects, ns.object(moved, v3PostStateRoleMoved),
			ns.object(oldParent, v3PostStateRoleOldParent), ns.object(newParent, v3PostStateRoleNewParent))
		response.Body = &authoritypb.Response_Rename{Rename: reply}
		response.PostState = ns.state(objects...)
	case *authoritypb.Request_Write:
		target := ns.tokens[[16]byte(body.Write.GetHandle())]
		end := int64(body.Write.GetPosition()) + int64(body.Write.GetSize())
		ns.objects[target].size = max(ns.objects[target].size, end)
		ns.commit(target)
		response.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{
			CommittedSize: uint64(body.Write.GetSize()), AssignedOffset: body.Write.GetPosition(), PostAttr: ns.attr(target),
		}}
		response.PostState = ns.state(ns.object(target, v3PostStateRoleTarget))
	case *authoritypb.Request_SetAttr:
		target := ns.tokens[[16]byte(body.SetAttr.GetItem())]
		if body.SetAttr.Mode != nil {
			ns.objects[target].mode = body.SetAttr.GetMode()
		}
		if body.SetAttr.Size != nil {
			ns.objects[target].size = body.SetAttr.GetSize()
		}
		ns.commit(target)
		response.PostState = ns.state(ns.object(target, v3PostStateRoleTarget))
	case *authoritypb.Request_Create, *authoritypb.Request_Mkdir:
		var parentToken, name []byte
		kind, created := authoritypb.Attr_REGULAR, byte(0)
		if create := request.GetCreate(); create != nil {
			parentToken, name = create.GetParent(), create.GetName()
		} else {
			parentToken, name, kind = request.GetMkdir().GetParent(), request.GetMkdir().GetName(), authoritypb.Attr_DIRECTORY
		}
		parent := ns.tokens[[16]byte(parentToken)]
		key := ns.key(parentToken, name)
		if _, exists := ns.names[key]; exists {
			response.Errno = errnos.EEXIST
			return response, nil
		}
		for created = 0x80; ns.objects[created] != nil; created++ {
		}
		ns.objects[created] = &v3TestObject{inode: uint64(created) + 100, kind: kind, nlink: 1}
		ns.names[key] = created
		ns.commit(parent, created)
		item := ns.issue(created)
		response.PostState = ns.state(ns.object(parent, v3PostStateRoleParent), ns.object(created, v3PostStateRoleCreated))
		if kind == authoritypb.Attr_REGULAR {
			handle := ns.client.issueHandle()
			ns.tokens[[16]byte(handle)] = created
			response.Body = &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: item, Handle: handle}}
		} else {
			response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: item}}
		}
	case *authoritypb.Request_Link:
		target, parent := ns.tokens[[16]byte(body.Link.GetExistingItem())], ns.tokens[[16]byte(body.Link.GetNewParent())]
		key := ns.key(body.Link.GetNewParent(), body.Link.GetNewName())
		if _, exists := ns.names[key]; exists {
			response.Errno = errnos.EEXIST
			return response, nil
		}
		ns.objects[target].nlink++
		ns.names[key] = target
		ns.commit(parent, target)
		item := ns.issue(target)
		item.Token = body.Link.GetExistingItem()
		response.Body = &authoritypb.Response_Link{Link: &authoritypb.LinkReply{Item: item}}
		response.PostState = ns.state(ns.object(parent, v3PostStateRoleParent), ns.object(target, v3PostStateRoleTarget))
	default:
		return nil, errors.New("unexpected authority mutation")
	}
	return response, nil
}

func getattrTestAttr(t *testing.T, d *v3DataPlane, item pfslocal.Item, handle uint64) pfslocal.Attr {
	t.Helper()
	reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.GetAttrRequest{Item: item, Handle: handle})
	if errno != 0 {
		t.Fatalf("getattr errno=%d", errno)
	}
	return reply.(*pfslocal.GetAttrReply).Attr
}

func TestV3RenameRebindsTheMovedItemToItsDestination(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	ns := newV3TestNamespace(client, map[byte]*v3TestObject{
		0x60: {inode: 6, kind: authoritypb.Attr_DIRECTORY, nlink: 2},
		0x50: {inode: 5, kind: authoritypb.Attr_DIRECTORY, nlink: 2},
	})
	ns.bind(0x20, "moving", 0x60)
	ns.bind(0x20, "dst", 0x50)
	root := d.resolveReply().Root
	moving := lookupTestAttr(t, d, root, "moving")
	dst := lookupTestAttr(t, d, root, "dst")
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("moving"), ToDir: dst.Item, ToName: []byte("moving"),
	}); errno != 0 {
		t.Fatalf("rename errno=%d", errno)
	}
	// The held directory's parent is what the frontend renders as "..".
	after := getattrTestAttr(t, d, moving.Item, 0)
	if after.ParentFileID != dst.FileID || after.Parent == nil || *after.Parent != dst.Item {
		t.Fatalf("moved directory parent = %d (%+v), want the destination %d", after.ParentFileID, after.Parent, dst.FileID)
	}
}

func TestV3RenameOverClearsTheReplacedItemsParentWithItsLastLink(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	ns := newV3TestNamespace(client, map[byte]*v3TestObject{
		0x50: {inode: 5, kind: authoritypb.Attr_DIRECTORY, nlink: 2},
		0x70: {inode: 7, kind: authoritypb.Attr_REGULAR, nlink: 1},
		0x71: {inode: 8, kind: authoritypb.Attr_REGULAR, nlink: 1},
	})
	ns.bind(0x20, "dst", 0x50)
	ns.bind(0x20, "x", 0x70)
	ns.bind(0x50, "y", 0x71)
	root := d.resolveReply().Root
	dst := lookupTestAttr(t, d, root, "dst")
	x := lookupTestAttr(t, d, root, "x")
	y := lookupTestAttr(t, d, dst.Item, "y")
	opened, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{Item: y.Item, Mode: pfslocal.OpenModeRead})
	if errno != 0 {
		t.Fatalf("open errno=%d", errno)
	}
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("x"), ToDir: dst.Item, ToName: []byte("y"),
	}); errno != 0 {
		t.Fatalf("rename-over errno=%d", errno)
	}
	if moved := getattrTestAttr(t, d, x.Item, 0); moved.ParentFileID != dst.FileID || *moved.Parent != dst.Item {
		t.Fatalf("moved file parent = %d, want %d", moved.ParentFileID, dst.FileID)
	}
	replaced := getattrTestAttr(t, d, y.Item, opened.(*pfslocal.OpenReply).Handle)
	if replaced.Nlink != 0 || replaced.Parent != nil || replaced.ParentFileID != 0 {
		t.Fatalf("replaced file attr = %+v, want no parent binding once its last link is gone", replaced)
	}
}

func TestV3LastUnlinkOfAnOpenFileClearsItsParent(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	ns := newV3TestNamespace(client, map[byte]*v3TestObject{0x72: {inode: 9, kind: authoritypb.Attr_REGULAR, nlink: 1}})
	ns.bind(0x20, "f", 0x72)
	root := d.resolveReply().Root
	file := lookupTestAttr(t, d, root, "f")
	openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{Item: file.Item, Mode: pfslocal.OpenModeReadWrite})
	if errno != 0 {
		t.Fatalf("open errno=%d", errno)
	}
	handle := openedAny.(*pfslocal.OpenReply).Handle
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.RemoveRequest{Dir: root, Name: []byte("f")}); errno != 0 {
		t.Fatalf("remove errno=%d", errno)
	}
	if attr := getattrTestAttr(t, d, file.Item, handle); attr.Parent != nil || attr.ParentFileID != 0 || attr.FileID != 9 {
		t.Fatalf("unlinked open file attr = %+v, want file ID 9 with no parent", attr)
	}
	written, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{Handle: handle, Data: []byte("tail")})
	if errno != 0 {
		t.Fatalf("write errno=%d", errno)
	}
	if attr := written.(*pfslocal.WriteReply).Attr; attr.Parent != nil || attr.ParentFileID != 0 {
		t.Fatalf("unlinked write attr = %+v, want no parent", attr)
	}
}

// A record remembers one observed name. A namespace change at that name
// disproves the binding, and the record then reports no parent (unavailable)
// rather than a parent that no longer contains it, until a fresh lookup
// observes a live name again.
func TestV3ParentFollowsTheRememberedAliasOfAHardLink(t *testing.T) {
	// step is the namespace change: remove dir/b, rename root/x over dir/b,
	// or (neither) remove an unrelated name.
	type step struct {
		removeDir  bool
		renameOver bool
	}
	for _, test := range []struct {
		name string
		// lookups is the order of observations (true: dir/b, false: root/a);
		// the last one is remembered.
		lookups []bool
		change  step
		// parentIsDir/parentIsRoot is what getattr reports after the change;
		// neither means unavailable.
		parentIsDir, parentIsRoot bool
		nlink                     uint32
	}{
		{name: "remembered-alias-removed", lookups: []bool{false, true}, change: step{removeDir: true}, nlink: 1},
		{name: "other-alias-removed", lookups: []bool{true, false}, change: step{removeDir: true}, parentIsRoot: true, nlink: 1},
		{name: "remembered-alias-renamed-over", lookups: []bool{false, true}, change: step{renameOver: true}, nlink: 1},
		{name: "other-alias-renamed-over", lookups: []bool{true, false}, change: step{renameOver: true}, parentIsRoot: true, nlink: 1},
		{name: "unrelated-removal-keeps-binding", lookups: []bool{false, true}, change: step{}, parentIsDir: true, nlink: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			ns := newV3TestNamespace(client, map[byte]*v3TestObject{
				0x50: {inode: 5, kind: authoritypb.Attr_DIRECTORY, nlink: 2},
				0x73: {inode: 10, kind: authoritypb.Attr_REGULAR, nlink: 2},
				0x74: {inode: 11, kind: authoritypb.Attr_REGULAR, nlink: 1},
				0x75: {inode: 12, kind: authoritypb.Attr_REGULAR, nlink: 1},
			})
			ns.bind(0x20, "dir", 0x50)
			ns.bind(0x20, "a", 0x73)
			ns.bind(0x50, "b", 0x73)
			ns.bind(0x20, "x", 0x74)
			ns.bind(0x20, "other", 0x75)
			root := d.resolveReply().Root
			dir := lookupTestAttr(t, d, root, "dir")
			var file pfslocal.Attr
			for _, inDir := range test.lookups {
				if inDir {
					file = lookupTestAttr(t, d, dir.Item, "b")
				} else {
					file = lookupTestAttr(t, d, root, "a")
				}
			}
			switch {
			case test.change.removeDir:
				if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.RemoveRequest{Dir: dir.Item, Name: []byte("b")}); errno != 0 {
					t.Fatalf("remove errno=%d", errno)
				}
			case test.change.renameOver:
				if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.RenameRequest{
					FromDir: root, FromName: []byte("x"), ToDir: dir.Item, ToName: []byte("b"),
				}); errno != 0 {
					t.Fatalf("rename-over errno=%d", errno)
				}
			default:
				_ = lookupTestAttr(t, d, root, "other")
				if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.RemoveRequest{Dir: root, Name: []byte("other")}); errno != 0 {
					t.Fatalf("remove errno=%d", errno)
				}
			}
			attr := getattrTestAttr(t, d, file.Item, 0)
			switch {
			case attr.Nlink != test.nlink:
				t.Fatalf("nlink=%d, want %d", attr.Nlink, test.nlink)
			case test.parentIsDir && (attr.ParentFileID != dir.FileID || attr.Parent == nil || *attr.Parent != dir.Item),
				test.parentIsRoot && (attr.ParentFileID != v3RootFileID || attr.Parent == nil || *attr.Parent != root),
				!test.parentIsDir && !test.parentIsRoot && (attr.Parent != nil || attr.ParentFileID != 0):
				t.Fatalf("parent after %s = %d (%+v)", test.name, attr.ParentFileID, attr.Parent)
			}
			// A fresh lookup of the surviving root alias observes a live name.
			_ = lookupTestAttr(t, d, root, "a")
			if attr := getattrTestAttr(t, d, file.Item, 0); attr.ParentFileID != v3RootFileID || attr.Parent == nil || *attr.Parent != root {
				t.Fatalf("parent after relookup = %d (%+v), want the root", attr.ParentFileID, attr.Parent)
			}
		})
	}
}

// Removing the only name clears the binding even before the authority's link
// count is consulted, and a renamed-over victim's index entry cannot follow it.
func TestV3LastLinkRemovalAndRenameMoveTheBindingIndex(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	ns := newV3TestNamespace(client, map[byte]*v3TestObject{
		0x50: {inode: 5, kind: authoritypb.Attr_DIRECTORY, nlink: 2},
		0x76: {inode: 13, kind: authoritypb.Attr_REGULAR, nlink: 1},
		0x77: {inode: 14, kind: authoritypb.Attr_REGULAR, nlink: 1},
	})
	ns.bind(0x20, "dir", 0x50)
	ns.bind(0x20, "only", 0x76)
	ns.bind(0x20, "moved", 0x77)
	root := d.resolveReply().Root
	dir := lookupTestAttr(t, d, root, "dir")
	only := lookupTestAttr(t, d, root, "only")
	moved := lookupTestAttr(t, d, root, "moved")
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.RemoveRequest{Dir: root, Name: []byte("only")}); errno != 0 {
		t.Fatalf("remove errno=%d", errno)
	}
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("moved"), ToDir: dir.Item, ToName: []byte("moved"),
	}); errno != 0 {
		t.Fatalf("rename errno=%d", errno)
	}
	d.mu.Lock()
	rootRecord, dirRecord := d.itemsByID[root.ItemID], d.itemsByID[dir.Item.ItemID]
	onlyRecord, movedRecord := d.itemsByID[only.Item.ItemID], d.itemsByID[moved.Item.ItemID]
	onlyBound := onlyRecord.binding != nil
	staleSource := rootRecord.children["moved"] != nil
	indexed := dirRecord.children["moved"] == movedRecord && movedRecord.binding != nil &&
		movedRecord.binding.parent == dirRecord && movedRecord.binding.name == "moved"
	d.mu.Unlock()
	if onlyBound || staleSource || !indexed {
		t.Fatalf("binding index after remove/rename: only bound=%t stale source=%t moved indexed=%t", onlyBound, staleSource, indexed)
	}
	// Retiring a record drops its index entry with it, and retiring a directory
	// drops every name beneath it.
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.ReclaimRequest{Item: moved.Item}); errno != 0 {
		t.Fatalf("reclaim errno=%d", errno)
	}
	d.mu.Lock()
	_, stillIndexed := dirRecord.children["moved"]
	d.mu.Unlock()
	if stillIndexed {
		t.Fatal("a retired record left its binding in the name index")
	}
}
