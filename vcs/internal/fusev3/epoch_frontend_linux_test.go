//go:build linux

package fusev3

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type recoveringFrontendTestRPC struct {
	*fakeRPC
	next RPC
}

func (r *recoveringFrontendTestRPC) RecoverEpoch(context.Context) (RPC, error) {
	return r.next, nil
}

func TestEpochRecoveryStalesOldHandlesAndAdmitsNewOpens(t *testing.T) {
	oldRPC := newFakeRPC()
	newRPC := newFakeRPC()
	newRPC.root = testItem(1, authoritypb.Attr_DIRECTORY, 101)
	newRPC.item = testItem(7, authoritypb.Attr_REGULAR, 107)
	provider := &recoveringFrontendTestRPC{fakeRPC: oldRPC, next: newRPC}

	cfg := testConfig(32)
	mount := newMount(context.Background(), provider, cfg)
	root := &node{
		mount: mount, item: provider.Root(), requestTimeout: time.Second,
		maxRead: 64 * 1024, maxWrite: 64 * 1024,
	}
	raw := newRawFileSystem(mount, root)
	mount.setNotifier(&fakeNotifier{})
	if err := mount.subscription.subscribe(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		mount.cancel()
		mount.delegations.Stop()
	})

	oldItem := oldRPC.item
	oldNode := raw.newNode(oldItem)
	identity, ok := publicationIdentityFromItem(oldItem)
	if !ok {
		t.Fatal("fixture file has no stable identity")
	}
	fileRecord := &inodeRecord{
		id: 2, key: itemKey(oldItem), identity: identity, node: oldNode, lookups: 1,
	}
	oldFileHandle := &fileHandle{node: oldNode, token: testToken(201), openFlags: syscall.O_RDWR, buffered: true}
	oldDirHandle := &dirHandle{
		node: root, token: testToken(202), rootBarrier: true,
		barrierLoss: mount.delegations.LossSequence(),
	}
	raw.mu.Lock()
	raw.nodesByID[fileRecord.id] = fileRecord
	raw.nodesByKey[fileRecord.key] = fileRecord
	raw.nodesByIdentity[fileRecord.identity] = fileRecord
	raw.nextNodeID = 3
	raw.nextHandle = 10
	rootRecord := raw.nodesByID[fuse.FUSE_ROOT_ID]
	raw.mu.Unlock()
	if id, ok := raw.addHandle(fileRecord, &handleRecord{file: oldFileHandle}); !ok || id != 10 {
		t.Fatalf("register old cached file handle: %d %v", id, ok)
	}
	if id, ok := raw.addHandle(rootRecord, &handleRecord{dir: oldDirHandle}); !ok || id != 11 {
		t.Fatalf("register old root directory handle: %d %v", id, ok)
	}

	if err := mount.delegations.Install(oldItem.GetStableIdentity(), oldItem.GetToken(), oldFileHandle.token, testDelegation()); err != nil {
		t.Fatal(err)
	}
	if _, err := mount.delegations.Write(context.Background(), oldItem.GetStableIdentity(), 0, []byte("dirty"), false); err != nil {
		t.Fatal(err)
	}
	lossBefore := mount.delegations.LossSequence()

	if err := mount.recoverEpoch(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Production's subscription runner performs this cold boundary after
	// recoverEpoch resumes it. This fixture drives that runner step directly.
	if err := mount.subscription.subscribe(context.Background()); err != nil {
		t.Fatalf("cold-subscribe replacement epoch: %v", err)
	}
	if got := mount.delegations.LossSequence(); got <= lossBefore {
		t.Fatalf("loss sequence after dirty epoch change = %d, want greater than %d", got, lossBefore)
	}
	if !oldNode.epochStale.Load() || !oldFileHandle.stale.Load() || !oldDirHandle.stale.Load() {
		t.Fatal("epoch recovery did not permanently stale every old node and handle")
	}

	if _, errno := oldNode.Read(context.Background(), oldFileHandle, make([]byte, 1), 0); errno != syscall.EIO {
		t.Fatalf("old Read errno = %v, want EIO", errno)
	}
	if errno := oldNode.Getattr(context.Background(), oldFileHandle, &fuse.AttrOut{}); errno != syscall.EIO {
		t.Fatalf("old Getattr errno = %v, want EIO", errno)
	}
	if written, status := raw.writeStock(&fuse.WriteIn{
		InHeader: fuse.InHeader{Unique: nextTestRequestUnique(), NodeId: fileRecord.id},
		Fh:       10, Size: 1, Flags: syscall.O_RDWR,
	}, []byte("x")); written != 0 || status != fuse.Status(syscall.EIO) {
		t.Fatalf("old Write = (%d, %v), want (0, EIO)", written, status)
	}
	if errno := oldNode.Fsync(context.Background(), oldFileHandle, 0); errno != syscall.EIO {
		t.Fatalf("old Fsync errno = %v, want EIO", errno)
	}
	if errno := oldDirHandle.Fsyncdir(context.Background(), 0); errno != syscall.EIO {
		t.Fatalf("old Fsyncdir errno = %v, want EIO", errno)
	}

	raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: nextTestRequestUnique()}, Fh: 10})
	raw.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: nextTestRequestUnique()}, Fh: 11})
	if mount.isRevoked() {
		t.Fatal("releasing old epoch handles revoked the recovered mount")
	}

	raw.mu.Lock()
	newRoot := raw.nodesByID[fuse.FUSE_ROOT_ID].node
	raw.mu.Unlock()
	lookupCtx, finishLookup := testMutationContext(t, mount)
	item, errno := newRoot.Lookup(lookupCtx, "new-file")
	finishLookup(errno == 0)
	if errno != 0 {
		t.Fatalf("new-epoch Lookup errno = %v", errno)
	}
	newRecord, errno := raw.intern(context.Background(), item)
	if errno != 0 {
		t.Fatalf("intern new-epoch item errno = %v", errno)
	}
	openCtx, finishOpen := testMutationContext(t, mount)
	newHandle, _, errno := newRecord.node.Open(openCtx, syscall.O_RDONLY)
	finishOpen(errno == 0)
	if errno != 0 || newHandle == nil || newHandle.stale.Load() || newRecord.node.epochStale.Load() {
		t.Fatalf("new-epoch Open = (%p, %v), stale node/handle", newHandle, errno)
	}
}
