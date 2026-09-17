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

func completeDirectoryFixture(t *testing.T) (*rawFileSystem, *fakeRPC, *inodeRecord, uint64) {
	t.Helper()
	raw, _, rpc := testRawFileSystem(t, 64)
	rpc.byName = map[string]*authoritypb.Item{"dir": testItem(40, authoritypb.Attr_DIRECTORY, 40), "file": testItem(41, authoritypb.Attr_REGULAR, 41)}
	rpc.missingNames = map[string]bool{"unseen": true, "next": true, "file": true}
	unique := nextTestRequestUnique()
	out := &fuse.EntryOut{}
	if status := raw.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, Mode: 0755}, "dir", out); status != fuse.OK {
		t.Fatal(status)
	}
	return raw, rpc, raw.nodesByID[out.NodeId], unique
}

func TestMkdirCompletenessRequiresPhysicalReply(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "written"}[success], func(t *testing.T) {
			raw, _, dir, unique := completeDirectoryFixture(t)
			if len(raw.completeDirectories) != 0 {
				t.Fatal("unwritten MKDIR installed completeness")
			}
			status := fuse.EIO
			if success {
				status = fuse.OK
			}
			completeTestReply(t, raw, unique, status)
			if got := raw.completeDirectories[dir.identity] != nil; got != success {
				t.Fatalf("completeness=%v want=%v", got, success)
			}
			if len(raw.cacheReservations) != 0 {
				t.Fatal("settled completeness retained reservations")
			}
		})
	}
}

func TestCompleteDirectoryNewNameLookupIsAllocationFreeAndUsesNoRPC(t *testing.T) {
	raw, rpc, dir, unique := completeDirectoryFixture(t)
	completeTestReply(t, raw, unique, fuse.OK)
	before := rpc.calls
	out := &fuse.EntryOut{}
	allocations := testing.AllocsPerRun(100, func() {
		unique := nextTestRequestUnique()
		if !raw.lookupCachedReply(unique, dir, "unseen", out) {
			panic("missing complete-directory hit")
		}
		raw.ReplyWritten(unique, fuse.OK)
	})
	if allocations != 0 || rpc.calls != before || out.NodeId != 0 || out.EntryValid != 0 || out.AttrValid != 0 {
		t.Fatalf("inferred absence allocs=%g calls=%d out=%v", allocations, rpc.calls-before, out)
	}
	unique = nextTestRequestUnique()
	if !raw.lookupCachedReply(unique, dir, "unseen", out) {
		t.Fatal("miss")
	}
	p := raw.replyPublications[unique]
	if p.cachedCount != 2 || p.cachedCoordinates[1] != (publicationCoordinate{kind: publicationItemEnumeration, item: dir.identity}) {
		t.Fatal("inferred absence omitted enumeration withdrawal")
	}
	done := make(chan error, 1)
	go func() { done <- raw.closeCacheCoordinate(t.Context(), p.cachedCoordinates[1]) }()
	select {
	case err := <-done:
		t.Fatalf("withdrawal passed unwritten absence: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	completeTestReply(t, raw, unique, fuse.OK)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("withdrawal did not join receipt")
	}
}

func TestCreatePreservesCompleteDirectoryOnlyWithAcceptedMember(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "withdrawn"}[revoke], func(t *testing.T) {
			raw, rpc, dir, unique := completeDirectoryFixture(t)
			completeTestReply(t, raw, unique, fuse.OK)
			before := rpc.calls
			if status := testRawCall(t, raw, func(unique uint64) fuse.Status {
				return raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: dir.id}, "file", &fuse.EntryOut{})
			}); status != fuse.OK {
				t.Fatal(status)
			}
			if rpc.calls != before {
				t.Fatal("LOOKUP-before-CREATE issued an RPC")
			}
			unique = nextTestRequestUnique()
			out := &fuse.CreateOut{}
			if status := raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{Unique: unique, NodeId: dir.id}, Flags: syscall.O_CREAT | syscall.O_RDWR | syscall.O_EXCL, Mode: 0600}, "file", out); status != fuse.OK {
				t.Fatalf("create: %v cause=%v", status, raw.mount.fatalError())
			}
			coordinate := publicationCoordinate{kind: publicationItemEnumeration, item: dir.identity}
			if revoke {
				if err := raw.closeCacheCoordinate(t.Context(), coordinate); err != nil {
					t.Fatal(err)
				}
				raw.openCacheCoordinate(coordinate)
			}
			completeTestReply(t, raw, unique, fuse.OK)
			if got := raw.completeDirectories[dir.identity] != nil; got == revoke {
				t.Fatalf("preserved proof=%v withdrawn=%v", got, revoke)
			}
			before = rpc.calls
			testRawCall(t, raw, func(unique uint64) fuse.Status {
				return raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: dir.id}, "next", &fuse.EntryOut{})
			})
			if got := rpc.calls == before; got == revoke {
				t.Fatalf("next lookup cached=%v withdrawn=%v", got, revoke)
			}
			if !revoke {
				raw.mu.Lock()
				raw.dropCachedNameLocked(nameKey{parent: dir.key.inode, name: "file"})
				raw.mu.Unlock()
				if raw.completeDirectories[dir.identity] != nil {
					t.Fatal("member eviction retained completeness")
				}
			}
		})
	}
}

func TestCompleteDirectoryPeerAndColdWithdrawalRemoveAbsenceProof(t *testing.T) {
	for _, kind := range []string{"name", "enumeration", "cold", "source"} {
		t.Run(kind, func(t *testing.T) {
			raw, _, dir, unique := completeDirectoryFixture(t)
			completeTestReply(t, raw, unique, fuse.OK)
			switch kind {
			case "name":
				if err := raw.invalidateCacheCoordinate(publicationCoordinate{kind: publicationNamespaceName, parent: dir.identity, name: "peer"}, nil); err != nil {
					t.Fatal(err)
				}
			case "enumeration":
				if err := raw.invalidateCacheCoordinate(publicationCoordinate{kind: publicationItemEnumeration, item: dir.identity}, nil); err != nil {
					t.Fatal(err)
				}
			case "cold":
				if err := raw.invalidateAllCaches(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "source":
				gate, err := namespaceSourceGate(dir.node.item, "unseen", false)
				if err != nil {
					t.Fatal(err)
				}
				lease, err := raw.acquireSourcePublication(t.Context(), gate)
				if err != nil {
					t.Fatal(err)
				}
				lease.assigned = true
				lease.resolveAllNoBinding()
				if err := lease.markCallbackPublicationReady(); err != nil {
					t.Fatal(err)
				}
				lease.release()
			}
			if len(raw.completeDirectories) != 0 {
				t.Fatal("withdrawal retained complete directory")
			}
		})
	}
}

func TestMkdirCompletenessCandidateIsRevocableBeforePhysicalReply(t *testing.T) {
	raw, _, dir, unique := completeDirectoryFixture(t)
	coordinate := publicationCoordinate{kind: publicationItemEnumeration, item: dir.identity}
	if len(raw.cacheReservations[coordinate]) != 1 {
		t.Fatal("new child omitted enumeration reservation")
	}
	raw.PrepareReplyPayload(unique, dir.id, 9, nil, nil, 0)
	if !raw.replyPublications[unique].originalFinalized {
		t.Fatal("candidate not finalized")
	}
	done := make(chan error, 1)
	go func() { done <- raw.closeCacheCoordinate(t.Context(), coordinate) }()
	select {
	case err := <-done:
		t.Fatalf("withdrawal passed finalized MKDIR: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	completeTestReply(t, raw, unique, fuse.OK)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("withdrawal failed to join MKDIR")
	}
	raw.openCacheCoordinate(coordinate)
	if raw.completeDirectories[dir.identity] != nil {
		t.Fatal("completed peer withdrawal was forgotten before MKDIR settlement")
	}
}

func TestCompleteDirectoryCapacityAndUntrackedMemberRefuseAbsence(t *testing.T) {
	for _, mode := range []string{"capacity", "member"} {
		t.Run(mode, func(t *testing.T) {
			raw, _, dir, unique := completeDirectoryFixture(t)
			if mode == "capacity" {
				raw.nameCapacity = 1
			}
			completeTestReply(t, raw, unique, fuse.OK)
			if mode == "member" {
				item := testItem(50, authoritypb.Attr_REGULAR, 50)
				record, errno := raw.intern(t.Context(), item)
				if errno != 0 {
					t.Fatal(errno)
				}
				raw.mu.Lock()
				raw.bindCachedNameLocked(nameKey{parent: dir.key.inode, name: "discovered"}, publicationNamespace{parent: dir.identity, name: "discovered"}, record, raw.mount.subscription.stamp())
				raw.mu.Unlock()
			}
			if raw.completeDirectories[dir.identity] != nil {
				t.Fatal("incomplete or over-capacity proof remained installed")
			}
			raw.mu.Lock()
			total := raw.cachedNameTotalLocked()
			raw.mu.Unlock()
			if mode == "capacity" && total > raw.nameCapacity {
				t.Fatalf("capacity exceeded: %d", total)
			}
		})
	}
}
