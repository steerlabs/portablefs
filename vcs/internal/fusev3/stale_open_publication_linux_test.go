//go:build linux

package fusev3

import (
	"context"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/permissionclock"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type successorSubscriptionRPC struct {
	subscriptionRPC
	clock *subscriptionTestClock
}

func (r successorSubscriptionRPC) Subscribe(ctx context.Context, snapshot, after []byte) (*authoritypb.SubscribeReply, permissionclock.Permission, error) {
	reply, _, err := r.subscriptionRPC.Subscribe(ctx, snapshot, after)
	if reply != nil {
		reply.Incarnation = 2
	}
	return reply, permissionclock.Permission{Time: r.clock.Now().Add(10 * time.Second)}, err
}

func TestStaleReadCacheOpenAndCreatePublication(t *testing.T) {
	for _, create := range []bool{false, true} {
		for _, stage := range []string{"registration", "physical_reply"} {
			t.Run(fmt.Sprintf("create_%t/%s", create, stage), func(t *testing.T) {
				f := newStockFixture(t)
				entry := f.lookup(t, 1, "file")
				sub, m := f.mount.subscription, f.mount.delegations
				clock := &subscriptionTestClock{now: sub.config.clock.Now()}
				sub.config.clock = clock
				f.rpc.mu.Lock()
				f.rpc.applied = 41
				f.rpc.replyOverride = func(r *authoritypb.Request) (*authoritypb.Response, error) {
					if r.GetBarrier() != nil {
						return &authoritypb.Response{Body: &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{AppliedSequence: 41, DurableSequence: 41}}}, nil
					}
					if r.GetOpen() != nil {
						return &authoritypb.Response{AppliedSequence: 41, VolumeVersion: 41, Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: testToken(100), CacheCapable: true, Delegation: testDelegation()}}}, nil
					}
					if r.GetCreate() != nil {
						child := testItem(101, authoritypb.Attr_REGULAR, 101)
						child.Attr.Size = 37
						return &authoritypb.Response{AppliedSequence: 41, VolumeVersion: 41, Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: child, Handle: testToken(100), CacheCapable: true, Delegation: testDelegation()}}, PostState: exactTestPostState(41, struct {
							item  *authoritypb.Item
							roles uint32
						}{child, postStateRoleCreated}, struct {
							item  *authoritypb.Item
							roles uint32
						}{f.rpc.itemForTokenLocked(r.GetCreate().Parent), postStateRoleParent})}, nil
					}
					return &authoritypb.Response{}, nil
				}
				if stage == "registration" {
					f.rpc.afterMutation = func() { clock.advance(11 * time.Second) }
				}
				f.rpc.mu.Unlock()
				unique := f.unique.Add(2)
				var outOpen fuse.OpenOut
				var outCreate fuse.CreateOut
				var payload []byte
				var status fuse.Status
				opcode := uint32(14)
				if create {
					opcode = 35
					status = f.raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}, Flags: uint32(syscall.O_RDONLY | syscall.O_CREAT), Mode: 0600}, "new-read-cache", &outCreate)
					payload = unsafe.Slice((*byte)(unsafe.Pointer(&outCreate)), int(unsafe.Sizeof(outCreate)))
				} else {
					status = f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Flags: uint32(syscall.O_RDONLY)}, &outOpen)
					payload = unsafe.Slice((*byte)(unsafe.Pointer(&outOpen)), int(unsafe.Sizeof(outOpen)))
				}
				if status != fuse.OK {
					t.Fatalf("status=%v cause=%v", status, f.mount.fatalError())
				}
				flags := func() uint32 {
					if create {
						return outCreate.OpenFlags
					}
					return outOpen.OpenFlags
				}
				fh := outOpen.Fh
				if create {
					fh = outCreate.Fh
				}
				record := f.raw.handles[fh]
				id := record.file.node.item.StableIdentity
				if stage == "registration" {
					if flags()&fuse.FOPEN_KEEP_CACHE != 0 || m.Owns(id) {
						t.Fatal("expired registration installed cache permission")
					}
					m.durabilityMu.Lock()
					applied := m.appliedHigh
					m.durabilityMu.Unlock()
					if applied != 0 {
						t.Fatal("expired registration advanced application cut")
					}
				} else {
					if flags()&fuse.FOPEN_KEEP_CACHE == 0 {
						t.Fatal("physical-reply fixture never registered read cache")
					}
					clock.advance(11 * time.Second)
				}
				_, reply, prepare := f.raw.PrepareReplyPayload(unique, 0, opcode, payload, nil, 0)
				if reply != fuse.OK || prepare != fuse.OK {
					t.Fatalf("physical reply=%v/%v", reply, prepare)
				}
				if flags()&fuse.FOPEN_KEEP_CACHE != 0 || flags()&fuse.FOPEN_DIRECT_IO == 0 {
					t.Fatalf("stale physical cache flags=%x", flags())
				}
				if create && (outCreate.EntryTimeout() != 0 || outCreate.AttrTimeout() != 0) {
					t.Fatal("stale CREATE retained metadata lifetime")
				}
				completeTestReply(t, f.raw, unique, fuse.OK)
				f.rpc.mu.Lock()
				f.rpc.afterMutation = nil
				f.rpc.replyOverride = nil
				f.rpc.mu.Unlock()
				sub.rpc = successorSubscriptionRPC{subscriptionRPC: f.rpc, clock: clock}
				if err := sub.subscribe(t.Context()); err != nil {
					t.Fatal(err)
				}
				if m.incarnation() != 2 || m.Owns(id) {
					t.Fatal("old OPEN grant entered successor")
				}
				if _, ok := m.BaseAttr(id); ok {
					t.Fatal("old metadata entered successor")
				}
				m.durabilityMu.Lock()
				applied, durable := m.appliedHigh, m.durableHigh
				m.durabilityMu.Unlock()
				if applied != 0 || durable != 0 {
					t.Fatalf("old OPEN application cut entered successor: %d/%d", applied, durable)
				}
				f.raw.mu.Lock()
				metadata := len(f.raw.cachedAttrPayloads)
				data := len(f.raw.cachedData)
				f.raw.mu.Unlock()
				if metadata != 0 || data != 0 || f.mount.isRevoked() {
					t.Fatalf("stale publication retained cache: metadata=%d data=%d cause=%v", metadata, data, f.mount.fatalError())
				}
			})
		}
	}
}
