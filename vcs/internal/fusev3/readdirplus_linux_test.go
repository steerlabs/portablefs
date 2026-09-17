//go:build linux

package fusev3

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func plusTestPages(count int) []*authoritypb.ReadDirReply {
	var pages []*authoritypb.ReadDirReply
	for start := 0; start < count; start += 256 {
		end := min(start+256, count)
		page := &authoritypb.ReadDirReply{Verifier: testToken(5), Eof: end == count}
		for i := start; i < end; i++ {
			item := testItem(uint64(i+100), authoritypb.Attr_REGULAR, uint64(i+100))
			item.ObjectVersion, item.SnapshotSequence = 2, 2
			page.Entries = append(page.Entries, &authoritypb.Dirent{Name: []byte(fmt.Sprintf("file-%04d", i)), Attr: item.Attr, Item: item, NextCookie: encodeCookie(uint64(i + 1)), ObjectVersion: 2, SnapshotSequence: 2})
		}
		pages = append(pages, page)
	}
	return pages
}

func TestReadDirPlusThousandEntriesPopulateDaemonCaches(t *testing.T) {
	raw, _, rpc := testRawFileSystem(t, 4096)
	id, _ := testDirHandle(t, raw, plusTestPages(1000)...)
	var offset uint64
	for i := 0; i < 5; i++ {
		list := fuse.NewDirEntryList(make([]byte, 128*1024), offset)
		unique := nextTestRequestUnique()
		status := raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: id, Offset: offset}, list)
		if status != fuse.OK {
			t.Fatalf("page %d: %v", i, status)
		}
		raw.PrepareReplyPayload(unique, 42, 44, nil, nil, 0)
		completeTestReply(t, raw, unique, fuse.OK)
		want := min(uint64((i+1)*256), uint64(1000))
		if list.Offset != want {
			t.Fatalf("page %d offset=%d want=%d", i, list.Offset, want)
		}
		offset = list.Offset
	}
	if len(rpc.readdirs) != 4 {
		t.Fatalf("READDIR calls=%d want=4", len(rpc.readdirs))
	}
	for _, request := range rpc.readdirs {
		if !request.WantItems {
			t.Fatal("PLUS omitted items")
		}
	}
	if len(raw.cachedNames) != 1000 || len(raw.cachedAttrs) != 1000 {
		t.Fatalf("cached names=%d attributes=%d", len(raw.cachedNames), len(raw.cachedAttrs))
	}
	held, handle := raw.acquireDirHandle(id)
	parent := held.inode.id
	raw.releaseHandleOperation(held)
	_ = handle
	before := rpc.calls
	out := &fuse.EntryOut{}
	testRawCall(t, raw, func(unique uint64) fuse.Status {
		return raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: parent}, "file-0500", out)
	})
	testRawCall(t, raw, func(unique uint64) fuse.Status {
		return raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: out.NodeId}}, &fuse.AttrOut{})
	})
	if rpc.calls != before {
		t.Fatal("PLUS metadata missed daemon cache")
	}
	if out.EntryValid != 0 || out.AttrValid != 0 {
		t.Fatal("PLUS restored kernel lifetimes")
	}
}

func TestReadDirPlusPhysicalFailureRollsBackCursorAndLookups(t *testing.T) {
	raw, _, _ := testRawFileSystem(t, 16)
	id, _ := testDirHandle(t, raw, plusTestPages(1)...)
	held, handle := raw.acquireDirHandle(id)
	raw.releaseHandleOperation(held)
	unique := nextTestRequestUnique()
	status := raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: id}, fuse.NewDirEntryList(make([]byte, 4096), 0))
	if status != fuse.OK {
		t.Fatal(status)
	}
	if handle.next != 1 {
		t.Fatal("cursor did not advance provisionally")
	}
	raw.ReplyWritten(unique, fuse.EIO)
	if handle.next != 0 || handle.plusReply != nil {
		t.Fatalf("failed reply retained cursor: next=%d tx=%v", handle.next, handle.plusReply)
	}
	if len(raw.cachedNames) != 0 || len(raw.cachedAttrs) != 0 {
		t.Fatal("failed reply installed daemon metadata")
	}
	for _, record := range raw.nodesByID {
		if record.key.inode == 100 && record.lookups != 0 {
			t.Fatal("failed reply retained kernel lookup ownership")
		}
	}
}

func TestReadDirPlusTakeOwnsCapabilityAcrossInvalidation(t *testing.T) {
	raw, mount, _ := testRawFileSystem(t, 16)
	id, _ := testDirHandle(t, raw, plusTestPages(1)...)
	held, handle := raw.acquireDirHandle(id)
	defer raw.releaseHandleOperation(held)
	ctx, finish := testMutationContext(t, mount)
	defer finish(false)
	small := fuse.NewDirEntryList(make([]byte, 1), 0)
	entry, dirent, item, out, _, errno := handle.takePlus(ctx, small, &dirPlusPageBoundary{})
	if errno != 0 || entry == nil || dirent == nil || item != nil || out != nil || dirent.Item == nil || handle.next != 0 {
		t.Fatal("full buffer consumed capability or cursor")
	}
	entry, dirent, item, out, _, errno = handle.takePlus(ctx, fuse.NewDirEntryList(make([]byte, 4096), 0), &dirPlusPageBoundary{})
	if errno != 0 || item == nil || out == nil || dirent.Item != nil {
		t.Fatal("fitting entry did not transfer capability")
	}
	handle.invalidateEnumeration()
	record, errno := raw.intern(context.Background(), item)
	if errno != 0 || record.lookups != 1 {
		t.Fatalf("detached capability lost: %v", errno)
	}
	if mount.reclaim.pending() != 0 {
		t.Fatal("invalidation reclaimed a transferred capability")
	}
	_ = entry
}

func TestReadDirPlusExpiredPageReservesNoPartialCache(t *testing.T) {
	raw, mount, _ := testRawFileSystem(t, 16)
	ctx, finish := testMutationContext(t, mount)
	defer finish(false)
	item := plusTestPages(1)[0].Entries[0].Item
	record, errno := raw.intern(ctx, item)
	if errno != 0 {
		t.Fatal(errno)
	}
	p := replyPublicationFromContext(ctx)
	p.stamp = subscriptionStamp{}
	p.servedVersion = 2
	candidate := dirPlusCandidate{entry: &fuse.EntryOut{}, dirent: plusTestPages(1)[0].Entries[0], item: item, record: record}
	if err := raw.publishDirPlusPage(ctx, raw.nodesByID[fuse.FUSE_ROOT_ID], []dirPlusCandidate{candidate}); err != nil {
		t.Fatal(err)
	}
	if len(p.names) != 0 || len(p.attrs) != 0 || raw.pendingAttrs != 0 || raw.pendingNames != 0 || len(raw.cacheReservations) != 0 {
		t.Fatal("expired page retained partial reservations")
	}
}

func TestReadDirPlusWithdrawalStopsTheCurrentReplyPage(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(fmt.Sprintf("expiry=%v", expiry), func(t *testing.T) {
			raw, mount, rpc := testRawFileSystem(t, 16)
			next := plusTestPages(2)[0]
			next.Entries = next.Entries[1:]
			id, _ := testDirHandle(t, raw, plusTestPages(2)[0], next)
			held, handle := raw.acquireDirHandle(id)
			unique := nextTestRequestUnique()
			ctx, finish, status := raw.mutationContext(unique)
			if status != fuse.OK {
				t.Fatal(status)
			}
			defer finish()
			cursor, errno := handle.beginDirPlus(ctx, 0)
			if errno != 0 {
				t.Fatal(errno)
			}
			if err := raw.attachDirPlusLookupTransaction(ctx, cursor, held); err != nil {
				t.Fatal(err)
			}
			out := fuse.NewDirEntryList(make([]byte, 4096), 0)
			var page dirPlusPageBoundary
			entry, _, item, _, _, errno := handle.takePlus(ctx, out, &page)
			if errno != 0 || entry == nil || item == nil || page.finished {
				t.Fatal("first entry missing or page prematurely exhausted")
			}
			record, errno := raw.intern(ctx, item)
			if errno != 0 {
				t.Fatal(errno)
			}
			if err := raw.stageDirPlusLookup(ctx, record, held.inode, entry.Name); err != nil {
				t.Fatal(err)
			}
			subscription := mount.subscription
			subscription.mu.Lock()
			cacheUntil := subscription.cacheUntil
			if expiry {
				subscription.cacheUntil = time.Now().Add(-time.Second)
			}
			subscription.mu.Unlock()
			if !expiry {
				handle.invalidateEnumeration()
			}
			entry, _, item, _, _, errno = handle.takePlus(ctx, out, &page)
			if errno != 0 || entry != nil || item != nil || out.Offset != 1 {
				t.Fatalf("reply crossed withdrawal: entry=%v item=%v offset=%d errno=%v", entry, item, out.Offset, errno)
			}
			if len(rpc.readdirs) != 1 {
				t.Fatal("old reply fetched a replacement page")
			}
			if err := raw.commitDirPlusLookupTransaction(ctx); err != nil {
				t.Fatal(err)
			}
			raw.PrepareReplyPayload(unique, 42, 44, nil, nil, 0)
			completeTestReply(t, raw, unique, fuse.OK)
			if handle.next != 1 || handle.plusReply != nil || record.lookups != 1 {
				t.Fatal("accepted partial reply lost its cursor or lookup")
			}
			subscription.mu.Lock()
			subscription.cacheUntil = cacheUntil
			subscription.mu.Unlock()
			nextOut := fuse.NewDirEntryList(make([]byte, 4096), 1)
			testRawCall(t, raw, func(unique uint64) fuse.Status {
				return raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: id, Offset: 1}, nextOut)
			})
			if len(rpc.readdirs) != 2 || nextOut.Offset != 2 {
				t.Fatal("next callback lost the replacement page")
			}
		})
	}
}
