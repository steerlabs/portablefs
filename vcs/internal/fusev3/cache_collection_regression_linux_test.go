//go:build linux

package fusev3

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func TestCacheableOpenSurvivesIdleCollectionAtPhysicalReply(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "file")
	f.openForData(t, entry.NodeId)
	unique := f.unique.Add(2)
	var out fuse.OpenOut
	if status := f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Flags: syscall.O_RDONLY}, &out); status != fuse.OK {
		t.Fatal(status)
	}
	if out.OpenFlags != fuse.FOPEN_KEEP_CACHE {
		t.Fatalf("cache-capable OPEN flags = %#x", out.OpenFlags)
	}
	record := f.raw.nodesByID[entry.NodeId]
	m := f.mount.delegations
	state := m.retainState(writeback.Identity(record.identity), true)
	defer m.releaseState(state)
	// Pause the collector inside its exclusive bookkeeping interval, after
	// OPEN has received cache authority but before its flags reach the kernel.
	state.admission.Lock()
	payload := unsafe.Slice((*byte)(unsafe.Pointer(&out)), int(unsafe.Sizeof(out)))
	_, reply, prepare := f.raw.PrepareReplyPayload(unique, entry.NodeId, 14, payload, nil, 0)
	state.admission.Unlock()
	completeTestReply(t, f.raw, unique, fuse.OK)
	if reply != fuse.OK || prepare != fuse.OK || out.OpenFlags != fuse.FOPEN_KEEP_CACHE {
		t.Fatalf("idle collection changed physical OPEN: reply=%v prepare=%v flags=%#x", reply, prepare, out.OpenFlags)
	}
}

func TestLinkPostStateSurvivesIdleParentCollection(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "file")
	parent, source := f.raw.acquire(1), f.raw.acquire(entry.NodeId)
	defer f.raw.release(parent)
	defer f.raw.release(source)
	unique := f.unique.Add(2)
	ctx, finish, status := f.raw.mutationContext(unique)
	if status != fuse.OK {
		t.Fatal(status)
	}
	// Run the same mutation/entry-publication path as raw.Link, then place
	// idle collection exactly at callback completion's post-state admission.
	item, errno := parent.node.Link(ctx, source.node, "linked")
	if errno != 0 {
		finish()
		t.Fatal(errno)
	}
	var out fuse.EntryOut
	if err := f.raw.publishEntry(ctx, &out, parent, "linked", source, item.GetAttr()); err != nil {
		finish()
		t.Fatal(err)
	}
	if err := completeSourcePublication(ctx); err != nil {
		finish()
		t.Fatal(err)
	}
	m := f.mount.delegations
	state := m.retainState(writeback.Identity(parent.identity), true)
	defer m.releaseState(state)
	state.admission.Lock()
	finish()
	state.admission.Unlock()
	payload := unsafe.Slice((*byte)(unsafe.Pointer(&out)), int(unsafe.Sizeof(out)))
	_, reply, prepare := f.raw.PrepareReplyPayload(unique, 1, 13, payload, nil, 0)
	completeTestReply(t, f.raw, unique, fuse.OK)
	if reply != fuse.OK || prepare != fuse.OK {
		t.Fatalf("physical LINK = %v/%v", reply, prepare)
	}
	before := f.rpcCalls()
	if status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}}, &fuse.AttrOut{})
	}); status != fuse.OK {
		t.Fatal(status)
	}
	if calls := f.rpcCalls() - before; calls != 0 {
		t.Fatalf("LINK parent stat issued %d follow-up RPCs despite exact post-state", calls)
	}
}
