//go:build linux

package fusev3

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

func TestCreateTruncateRetiresExistingDelegatedOverlayBeforeDispatch(t *testing.T) {
	mount, rpc := testMount(t, 32)
	raw := mount.raw
	root := raw.nodesByID[1].node
	existing := cloneItem(rpc.item)
	record, errno := raw.intern(context.Background(), existing)
	if errno != 0 {
		t.Fatal(errno)
	}
	parent, _ := publicationIdentityFromItem(root.item)
	raw.mu.Lock()
	raw.cachedStableNames[publicationNamespace{parent: parent, name: "existing"}] = record
	raw.mu.Unlock()

	handleToken := testToken(301)
	if err := mount.delegations.Install(existing.GetStableIdentity(), existing.GetToken(), handleToken, testDelegation()); err != nil {
		t.Fatal(err)
	}

	var orderMu sync.Mutex
	var order []string
	rpc.mu.Lock()
	rpc.hook = func(request *authoritypb.Request) {
		orderMu.Lock()
		defer orderMu.Unlock()
		switch {
		case request.GetWrite() != nil:
			order = append(order, "write")
		case request.GetFsync() != nil:
			order = append(order, "fsync")
		case request.GetBarrier() != nil:
			order = append(order, "barrier")
		case request.GetCreate() != nil:
			order = append(order, "create")
		}
	}
	rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		switch {
		case request.GetWrite() != nil:
			write := request.GetWrite()
			postAttr := proto.Clone(existing.GetAttr()).(*authoritypb.Attr)
			postAttr.Size = int64(write.GetPosition() + uint64(write.GetSize()))
			return &authoritypb.Response{
				PostState: testMutationPostState(postAttr),
				Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{
					CommittedSize: uint64(write.GetSize()), PostAttr: postAttr,
				}},
			}, nil
		case request.GetFsync() != nil:
			return &authoritypb.Response{Body: &authoritypb.Response_Fsync{Fsync: &authoritypb.FsyncReply{DurableSequence: rpc.applied}}}, nil
		case request.GetBarrier() != nil:
			cut := request.GetBarrier().GetCutSequence()
			return &authoritypb.Response{Body: &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{
				AppliedSequence: cut, DurableSequence: cut,
			}}}, nil
		case request.GetCreate() != nil:
			target := cloneItem(existing)
			target.Attr.Size = 0
			return &authoritypb.Response{
				Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{
					Item: target, Handle: testToken(302), Delegation: testDelegation(),
				}},
				PostState: exactTestPostState(2,
					struct {
						item  *authoritypb.Item
						roles uint32
					}{target, postStateRoleTarget},
					struct {
						item  *authoritypb.Item
						roles uint32
					}{root.item, postStateRoleParent}),
			}, nil
		default:
			return nil, syscall.EIO
		}
	}
	rpc.mu.Unlock()
	if _, err := mount.delegations.Write(context.Background(), existing.GetStableIdentity(), 0, []byte("dirty"), false); err != nil {
		t.Fatal(err)
	}

	ctx, finish := testMutationContext(t, mount)
	_, handle, _, errno := root.Create(ctx, "existing", syscall.O_CREAT|syscall.O_RDWR|syscall.O_TRUNC, 0o600)
	finish(errno == 0)
	if errno != 0 || handle == nil {
		t.Fatalf("CREATE O_TRUNC = (%p, %v)", handle, errno)
	}
	orderMu.Lock()
	got := append([]string(nil), order...)
	orderMu.Unlock()
	if want := []string{"write", "barrier", "create"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("delegated CREATE order = %v, want %v", got, want)
	}
	data, err := mount.delegations.Read(context.Background(), existing.GetStableIdentity(), 0, 4, func(context.Context, int64, int) ([]byte, error) {
		return []byte("base"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "base" {
		t.Fatalf("post-truncate holder read = %q, dirty overlay survived", data)
	}
	base, ok := mount.delegations.BaseAttr(existing.GetStableIdentity())
	if !ok || base.GetSize() != 0 {
		t.Fatalf("post-truncate delegation base = %+v, want authoritative size zero", base)
	}
}

func TestCoherenceStaleHandleStillClosesAuthorityResource(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	handle := &fileHandle{node: n, token: testToken(401)}
	n.stale.Store(true)

	ctx, finish := testMutationContext(t, mount)
	errno := handle.close(ctx, 0, false)
	finish(errno == 0)
	if errno != 0 {
		t.Fatalf("coherence-stale close errno = %v", errno)
	}
	rpc.mu.Lock()
	closed := len(rpc.fileCloses)
	rpc.mu.Unlock()
	if closed != 1 {
		t.Fatalf("authority close calls = %d, want 1", closed)
	}
	if mount.ctx.Err() != nil || mount.fatalError() != nil {
		t.Fatalf("coherence-stale cleanup revoked mount: %v", mount.fatalError())
	}
}

func TestCleanCloseBarrierFlushesAcceptedDelegatedWrites(t *testing.T) {
	mount, rpc := testMount(t, 8)
	item := rpc.item
	if err := mount.delegations.Install(item.GetStableIdentity(), item.GetToken(), testToken(501), testDelegation()); err != nil {
		t.Fatal(err)
	}
	var barrierSeen atomic.Bool
	rpc.mu.Lock()
	rpc.hook = func(request *authoritypb.Request) {
		if request.GetBarrier() != nil {
			barrierSeen.Store(true)
		}
	}
	rpc.mu.Unlock()
	if _, err := mount.delegations.Write(context.Background(), item.GetStableIdentity(), 0, []byte("pending"), false); err != nil {
		t.Fatal(err)
	}
	if err := mount.flushDelegationsBeforeClose(); err != nil {
		t.Fatal(err)
	}
	rpc.mu.Lock()
	writes := len(rpc.writes)
	rpc.mu.Unlock()
	if writes == 0 || !barrierSeen.Load() {
		t.Fatalf("clean close flush: writes=%d barrier=%v", writes, barrierSeen.Load())
	}
}

func TestCleanCloseBarriersSynchronousDelegationSequence(t *testing.T) {
	mount, rpc := testMount(t, 8)
	var barrierCut atomic.Uint64
	rpc.mu.Lock()
	rpc.hook = func(request *authoritypb.Request) {
		if barrier := request.GetBarrier(); barrier != nil {
			barrierCut.Store(barrier.GetCutSequence())
		}
	}
	rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if barrier := request.GetBarrier(); barrier != nil {
			cut := barrier.GetCutSequence()
			return &authoritypb.Response{Body: &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{
				AppliedSequence: cut, DurableSequence: cut,
			}}}, nil
		}
		return nil, syscall.EIO
	}
	rpc.mu.Unlock()
	mount.delegations.durabilityMu.Lock()
	mount.delegations.appliedHigh = 17
	mount.delegations.durableHigh = 16
	mount.delegations.durabilityMu.Unlock()
	if err := mount.flushDelegationsBeforeClose(); err != nil {
		t.Fatal(err)
	}
	if got := barrierCut.Load(); got != 17 {
		t.Fatalf("clean close barrier cut = %d, want 17", got)
	}
}
