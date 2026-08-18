//go:build linux

package fusev3

import (
	"sort"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func testMutationPostState(attr *authoritypb.Attr) *authoritypb.PostState {
	return &authoritypb.PostState{VisibilitySequence: 2, SnapshotSequence: 2, Objects: []*authoritypb.ObjectPostState{{
		StableIdentity: testIdentity(attr.GetInode()), ObjectVersion: 2, Attr: attr, Roles: postStateRoleTarget,
	}}}
}

func exactTestPostState(sequence uint64, objects ...struct {
	item  *authoritypb.Item
	roles uint32
}) *authoritypb.PostState {
	state := &authoritypb.PostState{VisibilitySequence: sequence, SnapshotSequence: sequence}
	merged := make(map[string]*authoritypb.ObjectPostState, len(objects))
	for _, object := range objects {
		key := string(object.item.GetStableIdentity())
		if existing := merged[key]; existing != nil {
			existing.Roles |= object.roles
			continue
		}
		attr := *object.item.GetAttr()
		entry := &authoritypb.ObjectPostState{
			StableIdentity: append([]byte(nil), object.item.GetStableIdentity()...),
			ObjectVersion:  sequence,
			Attr:           &attr,
			Roles:          object.roles,
		}
		merged[key] = entry
		state.Objects = append(state.Objects, entry)
	}
	sort.Slice(state.Objects, func(i, j int) bool {
		return string(state.Objects[i].GetStableIdentity()) < string(state.Objects[j].GetStableIdentity())
	})
	return state
}

// NEW-A's daemon-side half: one response is one admission transaction. The
// parent attr and the new binding must both remain candidates until the kernel
// has installed the same trailer; processing the parent record first must not
// make the response reject its own dentry candidate.
func TestCreateReplyAdmitsParentAndOwnDentryAsOneTransaction(t *testing.T) {
	f := newStrictFixture(t)
	created := testItem(42, authoritypb.Attr_REGULAR, 42)
	parent := testItem(1, authoritypb.Attr_DIRECTORY, 1)
	state := exactTestPostState(2,
		struct {
			item  *authoritypb.Item
			roles uint32
		}{created, postStateRoleCreated},
		struct {
			item  *authoritypb.Item
			roles uint32
		}{parent, postStateRoleParent},
	)
	f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetCreate() == nil {
			t.Fatalf("unexpected authority request in CREATE transaction: %T", request.GetBody())
		}
		return &authoritypb.Response{
			Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{
				Item: created, Handle: testToken(900),
			}},
			PostState: state,
		}, nil
	}

	unique := f.unique.Add(2)
	out := &fuse.CreateOut{}
	status := f.raw.Create(nil, &fuse.CreateIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
		Flags:    syscall.O_RDWR | syscall.O_CREAT,
		Mode:     0o644,
	}, "created", out)
	if !status.Ok() {
		t.Fatalf("CREATE = %v", status)
	}
	payload := make([]byte, fuse.PFSPostStateMaxSize)
	n, status := f.raw.PrepareReplyPayload(unique, fuse.FUSE_ROOT_ID, 35, nil, payload, 0)
	if !status.Ok() || n != fuse.PFSPostStateHeaderSize+2*fuse.PFSObjectStateSize {
		t.Fatalf("CREATE trailer = (%d, %v), want two-object post-state", n, status)
	}
	if !f.raw.ReplyPublishMarked(unique, fuse.FUSE_ROOT_ID, 35) {
		t.Fatal("CREATE reply was not marked for post-VFS publication")
	}
	f.raw.ReplyWritten(unique, fuse.OK)
	publishUnique := f.unique.Add(2)
	publish := &fuse.PFSPublishIn{
		InHeader:      fuse.InHeader{Unique: publishUnique},
		RequestUnique: unique,
		PublicationID: 1,
		Nodeid:        fuse.FUSE_ROOT_ID,
		Opcode:        35,
	}
	if status := f.raw.PFSPublish(nil, publish, &fuse.PFSPublishOut{}); !status.Ok() {
		t.Fatalf("CREATE publication receipt = %v", status)
	}
	f.raw.ReplyWritten(publishUnique, fuse.OK)

	createdIdentity, ok := publicationIdentityFromItem(created)
	if !ok {
		t.Fatal("test created identity is invalid")
	}
	parentIdentity, ok := publicationIdentityFromItem(parent)
	if !ok {
		t.Fatal("test parent identity is invalid")
	}
	f.raw.mu.Lock()
	_, nameCached := f.raw.cachedNames[nameKey{parent: 1, name: "created"}]
	_, childAttrCached := f.raw.cachedAttrs[createdIdentity]
	_, parentAttrCached := f.raw.cachedAttrs[parentIdentity]
	f.raw.mu.Unlock()
	if !nameCached || !childAttrCached || !parentAttrCached {
		t.Fatalf("CREATE transaction cache admission = name:%v child-attr:%v parent-attr:%v, want all true", nameCached, childAttrCached, parentAttrCached)
	}
}

func TestExistingCreateReplyRequiresAndAdmitsParentTargetState(t *testing.T) {
	f := newStrictFixture(t)
	target := testItem(43, authoritypb.Attr_REGULAR, 43)
	parent := testItem(1, authoritypb.Attr_DIRECTORY, 1)
	state := exactTestPostState(2,
		struct {
			item  *authoritypb.Item
			roles uint32
		}{target, postStateRoleTarget},
		struct {
			item  *authoritypb.Item
			roles uint32
		}{parent, postStateRoleParent},
	)
	f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetCreate() == nil {
			t.Fatalf("unexpected authority request in existing CREATE: %T", request.GetBody())
		}
		return &authoritypb.Response{
			Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{
				Item: target, Handle: testToken(901),
			}},
			PostState: state,
		}, nil
	}

	unique := f.unique.Add(2)
	out := &fuse.CreateOut{}
	status := f.raw.Create(nil, &fuse.CreateIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
		Flags:    syscall.O_RDWR | syscall.O_CREAT,
		Mode:     0o644,
	}, "existing", out)
	if !status.Ok() {
		t.Fatalf("existing CREATE = %v", status)
	}
	payload := make([]byte, fuse.PFSPostStateMaxSize)
	n, status := f.raw.PrepareReplyPayload(unique, fuse.FUSE_ROOT_ID, 35, nil, payload, 0)
	if !status.Ok() || n != fuse.PFSPostStateHeaderSize+2*fuse.PFSObjectStateSize {
		t.Fatalf("existing CREATE trailer = (%d, %v), want exact PARENT+TARGET", n, status)
	}
}

func TestCreateMissingPostStateFailsBeforeMarkedReplyWrite(t *testing.T) {
	f := newStrictFixture(t)
	target := testItem(44, authoritypb.Attr_REGULAR, 44)
	f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetCreate() == nil {
			t.Fatalf("unexpected authority request in missing-state CREATE: %T", request.GetBody())
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{
			Item: target, Handle: testToken(902),
		}}}, nil
	}

	unique := f.unique.Add(2)
	out := &fuse.CreateOut{}
	if status := f.raw.Create(nil, &fuse.CreateIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
		Flags:    syscall.O_RDWR | syscall.O_CREAT,
		Mode:     0o644,
	}, "missing-state", out); !status.Ok() {
		t.Fatalf("callback construction = %v, want deferred wire-boundary validation", status)
	}
	payload := make([]byte, fuse.PFSPostStateMaxSize)
	if n, status := f.raw.PrepareReplyPayload(unique, fuse.FUSE_ROOT_ID, 35, nil, payload, 0); status != fuse.EIO || n != 0 {
		t.Fatalf("missing-state reply preparation = (%d, %v), want closed EIO before write", n, status)
	}
}

func TestPostStateRejectsLiveButWrongOperandIdentity(t *testing.T) {
	first, ok := publicationIdentityFromItem(testItem(10, authoritypb.Attr_REGULAR, 10))
	if !ok {
		t.Fatal("first test identity is invalid")
	}
	wrong := testItem(11, authoritypb.Attr_REGULAR, 11)
	publication := &replyPublication{
		needsPostVFS: true,
		postState: exactTestPostState(2, struct {
			item  *authoritypb.Item
			roles uint32
		}{wrong, postStateRoleTarget}),
		expectedPostState: map[publicationIdentity]uint32{first: postStateRoleTarget},
	}
	if err := validateExpectedPostState(publication); err == nil {
		t.Fatal("live but wrong post-state identity was accepted")
	}
}
