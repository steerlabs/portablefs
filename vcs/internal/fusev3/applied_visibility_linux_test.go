//go:build linux

package fusev3

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type refusedVisibilityRPC struct {
	delegationRPC
	failure func(context.Context) error
}

func (r refusedVisibilityRPC) CallIdempotent(ctx context.Context, q *authoritypb.Request) (*authoritypb.Response, error) {
	if q.GetWaitVisibility() != nil {
		if r.failure != nil {
			if err := r.failure(ctx); err != nil {
				return nil, err
			}
			return r.delegationRPC.CallIdempotent(ctx, q)
		}
		return &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil
	}
	return r.delegationRPC.CallIdempotent(ctx, q)
}

func TestAppliedAppendVisibilityFailureSettlesSourceWithoutRevocation(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "appended")
	opened := openDelegatedWriter(t, f, entry.NodeId)
	f.mount.delegations.rpc = refusedVisibilityRPC{delegationRPC: f.mount.delegations.rpc}
	status := f.rawCall(func(unique uint64) fuse.Status {
		_, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 4, Flags: uint32(syscall.O_RDWR | syscall.O_APPEND)}, []byte("data"))
		return status
	})
	if status != fuse.EIO || f.mount.isRevoked() {
		t.Fatalf("applied write: %v; terminal=%v", status, f.mount.fatalError())
	}
	f.rpc.mu.Lock()
	writes := len(f.rpc.writes)
	f.rpc.mu.Unlock()
	if writes != 1 {
		t.Fatal("applied mutation was lost or replayed", writes)
	}
	f.raw.mu.RLock()
	holds := len(f.raw.sourceHolds)
	f.raw.mu.RUnlock()
	if holds != 0 {
		t.Fatal("failed visibility retained uncompleted source", holds)
	}
}

func TestAppliedCreateVisibilityFailureDischargesBindingAndDescriptor(t *testing.T) {
	f := newStockFixture(t)
	f.mount.delegations.rpc = refusedVisibilityRPC{delegationRPC: f.mount.delegations.rpc}
	closed := 0
	f.rpc.mu.Lock()
	f.rpc.replyOverride = func(q *authoritypb.Request) (*authoritypb.Response, error) {
		if q.GetCreate() != nil {
			item := f.rpc.namedItem(q.GetCreate().GetName())
			f.rpc.applied = 2
			return &authoritypb.Response{AppliedSequence: 2, VolumeVersion: 2,
				PostState: exactTestPostState(2, struct {
					item  *authoritypb.Item
					roles uint32
				}{item, postStateRoleCreated}, struct {
					item  *authoritypb.Item
					roles uint32
				}{f.rpc.root, postStateRoleParent}),
				Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: item, Handle: cloneBytes(f.rpc.handle), Delegation: testDelegation()}}}, nil
		}
		if q.GetBarrier() != nil {
			return &authoritypb.Response{Body: &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{AppliedSequence: f.rpc.applied, DurableSequence: f.rpc.applied}}}, nil
		}
		if q.GetCloseBatch() != nil {
			results := make([]*authoritypb.CloseBatchResult, len(q.GetCloseBatch().GetCloses()))
			for i := range results {
				closed++
				results[i] = &authoritypb.CloseBatchResult{Retired: true}
			}
			return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: results}}}, nil
		}
		if q.GetDelegationRelease() != nil {
			return releaseSuccess(), nil
		}
		return &authoritypb.Response{}, nil
	}
	f.rpc.mu.Unlock()
	before := f.raw.nextHandle
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}, Flags: uint32(syscall.O_RDWR | syscall.O_CREAT), Mode: 0o600}, "created", &fuse.CreateOut{})
	})
	// Visibility failure still owns the applied CREATE's grant and descriptor.
	// Join their retirement so a malformed cleanup cannot race this assertion.
	waitUntil(t, time.Second, "created descriptor retirement", func() bool {
		f.rpc.mu.Lock()
		retired := closed
		f.rpc.mu.Unlock()
		return retired != 0 && pendingCloses(f.mount.delegations) == 0
	})
	f.rpc.mu.Lock()
	closes := closed
	f.rpc.mu.Unlock()
	if closes != 1 {
		t.Fatalf("applied CREATE retired %d descriptors, want 1", closes)
	}
	if status != fuse.EIO || f.mount.isRevoked() {
		t.Fatalf("applied create: %v; terminal=%v", status, f.mount.fatalError())
	}
	f.raw.mu.RLock()
	holds, handles := len(f.raw.sourceHolds), f.raw.nextHandle
	f.raw.mu.RUnlock()
	if holds != 0 || handles != before {
		t.Fatal("error published a handle or retained an unresolved binding", holds, handles, before)
	}
}

func TestAppliedVisibilityIndependentFailureRemainsTerminal(t *testing.T) {
	for _, backgroundFirst := range []bool{false, true} {
		name := "foreground-failure"
		if backgroundFirst {
			name = "background-failure-before-source-completion"
		}
		t.Run(name, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "appended")
			opened := openDelegatedWriter(t, f, entry.NodeId)
			cause := errors.New("malformed visibility reply")
			f.mount.delegations.rpc = refusedVisibilityRPC{delegationRPC: f.mount.delegations.rpc, failure: func(ctx context.Context) error {
				lease := sourceLeaseFromContext(ctx)
				if !backgroundFirst {
					if lease != nil {
						return cause
					}
					return nil
				}
				if lease != nil {
					waitUntil(t, time.Second, "background terminal source withdrawal", func() bool {
						f.raw.mu.RLock()
						defer f.raw.mu.RUnlock()
						return lease.revoked
					})
				}
				return cause
			}}
			status := f.rawCall(func(unique uint64) fuse.Status {
				_, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 4, Flags: uint32(syscall.O_RDWR | syscall.O_APPEND)}, []byte("data"))
				return status
			})
			// The original fixture injected the malformed reply into both
			// foreground and background waits. If background durability wins,
			// terminal withdrawal revokes the source before it can complete;
			// that callback must report ENOTCONN. Isolate the foreground fault
			// for its EIO contract and force the competing schedule separately.
			want := fuse.EIO
			if backgroundFirst {
				want = fuse.Status(syscall.ENOTCONN)
			}
			if status != want || !f.mount.isRevoked() || !errors.Is(f.mount.fatalError(), cause) {
				t.Fatal("independent failure was hidden", status, f.mount.fatalError())
			}
			f.rpc.mu.Lock()
			writes := len(f.rpc.writes)
			f.rpc.mu.Unlock()
			if writes != 1 {
				t.Fatal("terminal visibility failure changed the applied mutation", writes)
			}
		})
	}
}

func TestAppliedRangeAndTruncatingOpenVisibilityFailuresSettleSource(t *testing.T) {
	for _, operation := range []string{"fallocate", "truncate-open"} {
		t.Run(operation, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "target")
			opened := openDelegatedWriter(t, f, entry.NodeId)
			f.mount.delegations.rpc = refusedVisibilityRPC{delegationRPC: f.mount.delegations.rpc}
			f.rpc.mu.Lock()
			f.rpc.replyOverride = func(q *authoritypb.Request) (*authoritypb.Response, error) {
				if q.GetOpen() != nil || q.GetFallocate() != nil {
					item := cloneItem(f.rpc.item)
					f.rpc.applied = 2
					item.Attr.Size = 4096
					r := &authoritypb.Response{AppliedSequence: 2, VolumeVersion: 2, PostState: exactTestPostState(2, struct {
						item  *authoritypb.Item
						roles uint32
					}{item, postStateRoleTarget})}
					if q.GetOpen() != nil {
						item.Attr.Size = 0
						r.PostState = exactTestPostState(2, struct {
							item  *authoritypb.Item
							roles uint32
						}{item, postStateRoleTarget})
						r.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: testToken(901), Delegation: testDelegation()}}
					} else {
						r.Body = &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{Flags: rangeResultApplied, PostSize: 4096, VisibilitySequence: 2}}
					}
					return r, nil
				}
				if q.GetBarrier() != nil {
					return &authoritypb.Response{Body: &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{AppliedSequence: 2, DurableSequence: 2}}}, nil
				}
				// A failed visibility wait still owns the truncating OPEN's
				// descriptor cleanup, which may race the callback's return.
				if q.GetCloseBatch() != nil {
					results := make([]*authoritypb.CloseBatchResult, len(q.GetCloseBatch().GetCloses()))
					for i := range results {
						results[i] = &authoritypb.CloseBatchResult{Retired: true}
					}
					return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: results}}}, nil
				}
				if q.GetDelegationRelease() != nil {
					return releaseSuccess(), nil
				}
				return &authoritypb.Response{}, nil
			}
			f.rpc.mu.Unlock()
			status := f.rawCall(func(unique uint64) fuse.Status {
				if operation == "truncate-open" {
					return f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Flags: uint32(syscall.O_RDWR | syscall.O_TRUNC)}, &fuse.OpenOut{})
				}
				return f.raw.Fallocate(nil, &fuse.FallocateIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Length: 4096})
			})
			if status != fuse.EIO || f.mount.isRevoked() {
				t.Fatal(status, f.mount.fatalError())
			}
			f.raw.mu.RLock()
			holds := len(f.raw.sourceHolds)
			f.raw.mu.RUnlock()
			if holds != 0 {
				t.Fatal("known commit retained source ownership", holds)
			}
		})
	}
}
