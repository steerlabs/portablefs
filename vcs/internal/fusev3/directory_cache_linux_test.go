//go:build linux

package fusev3

import (
	"context"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func directoryCacheReply(t *testing.T, raw *rawFileSystem, id, offset uint64, plus bool) uint64 {
	t.Helper()
	u := nextTestRequestUnique()
	list := fuse.NewDirEntryList(make([]byte, 128*1024), offset)
	in := &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u}, Fh: id, Offset: offset}
	var status fuse.Status
	opcode := uint32(28)
	if plus {
		status = raw.ReadDirPlus(nil, in, list)
		opcode = 44
	} else {
		status = raw.ReadDir(nil, in, list)
	}
	if status != fuse.OK {
		t.Fatal(status)
	}
	_, status, lifecycle := raw.PrepareReplyPayload(u, 42, opcode, nil, nil, 0)
	if status != fuse.OK || lifecycle != fuse.OK {
		t.Fatalf("prepare=%v/%v", status, lifecycle)
	}
	completeTestReply(t, raw, u, fuse.OK)
	return list.Offset
}

func TestDirectoryCacheReusesPagesAcrossHandlesEOFAndRewind(t *testing.T) {
	for _, plus := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "plus"}[plus], func(t *testing.T) {
			raw, _, rpc := testRawFileSystem(t, 4096)
			first, _ := testDirHandle(t, raw, plusTestPages(1000)...)
			offset := uint64(0)
			for offset < 1000 {
				offset = directoryCacheReply(t, raw, first, offset, plus)
			}
			before := len(rpc.readdirs)
			held, handle := raw.acquireDirHandle(first)
			raw.releaseHandleOperation(held)
			second, ok := raw.addHandle(held.inode, &handleRecord{dir: &dirHandle{node: handle.node, token: testToken(101)}})
			if !ok {
				t.Fatal("add handle")
			}
			offset = 0
			for offset < 1000 {
				offset = directoryCacheReply(t, raw, second, offset, plus)
			}
			directoryCacheReply(t, raw, second, offset, plus)
			directoryCacheReply(t, raw, second, 0, plus)
			if len(rpc.readdirs) != before {
				t.Fatalf("warm/rewind RPCs=%d", len(rpc.readdirs)-before)
			}
			if len(raw.directories.pages) != 4 || raw.directories.hits == 0 {
				t.Fatalf("pages=%d hits=%d", len(raw.directories.pages), raw.directories.hits)
			}
		})
	}
}

func TestDirectoryCacheSingleFlightJoinsPhysicalOwner(t *testing.T) {
	raw, _, rpc := testRawFileSystem(t, 16)
	first, _ := testDirHandle(t, raw, plusTestPages(1)...)
	held, handle := raw.acquireDirHandle(first)
	raw.releaseHandleOperation(held)
	second, _ := raw.addHandle(held.inode, &handleRecord{dir: &dirHandle{node: handle.node, token: testToken(101)}})
	u := nextTestRequestUnique()
	if status := raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u}, Fh: first}, fuse.NewDirEntryList(make([]byte, 4096), 0)); status != fuse.OK {
		t.Fatal(status)
	}
	v := nextTestRequestUnique()
	done := make(chan fuse.Status, 1)
	go func() {
		done <- raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: v}, Fh: second}, fuse.NewDirEntryList(make([]byte, 4096), 0))
	}()
	waitUntil(t, time.Second, "page fill waiter", func() bool { raw.mu.RLock(); defer raw.mu.RUnlock(); return raw.directories.singleFlightWaits > 0 })
	if len(raw.directories.pages) != 0 {
		t.Fatal("fill published before physical write")
	}
	raw.PrepareReplyPayload(u, 42, 44, nil, nil, 0)
	completeTestReply(t, raw, u, fuse.OK)
	if status := <-done; status != fuse.OK {
		t.Fatal(status)
	}
	raw.PrepareReplyPayload(v, 42, 44, nil, nil, 0)
	completeTestReply(t, raw, v, fuse.OK)
	if len(rpc.readdirs) != 1 {
		t.Fatalf("RPCs=%d", len(rpc.readdirs))
	}
	if len(raw.cacheReservations) != 0 || len(raw.directories.fills) != 0 {
		t.Fatal("fill ownership leaked")
	}
}

func TestDirectoryCacheNewOpenProofSharedByOrdinaryAndWorkspace(t *testing.T) {
	for _, workspace := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "workspace"}[workspace], func(t *testing.T) {
			f := newStockFixture(t)
			if workspace {
				bindWorkspaceTestGate(t, f.mount)
			}
			open := func() uint64 {
				var out fuse.OpenOut
				status := f.rawCall(func(u uint64) fuse.Status {
					return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}}, &out)
				})
				if status != fuse.OK || out.OpenFlags != 0 {
					t.Fatalf("open=%v flags=%d", status, out.OpenFlags)
				}
				return out.Fh
			}
			first := open()
			calls := f.rpcCalls()
			second := open()
			if f.rpcCalls() != calls {
				t.Fatal("reusable open crossed authority")
			}
			a, b := f.raw.handles[first].dir, f.raw.handles[second].dir
			if a == b || a.backing != b.backing || a.backing.refs != 2 {
				t.Fatal("independent handles did not share backing")
			}
			f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: nextTestRequestUnique()}, Fh: first})
			if a.backing.refs != 1 {
				t.Fatal("release closed live backing")
			}
			coordinate := publicationCoordinate{kind: publicationItemAttributes, item: a.enumerationIdentity()}
			lease, err := f.raw.closeCacheCoordinate(context.Background(), coordinate)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.raw.invalidateCacheCoordinate(coordinate, nil); err != nil {
				t.Fatal(err)
			}
			lease.Open()
			f.rpc.replyOverride = func(q *authoritypb.Request) (*authoritypb.Response, error) {
				if q.GetOpen() != nil {
					return &authoritypb.Response{Errno: int32(syscall.EACCES)}, nil
				}
				return &authoritypb.Response{}, nil
			}
			var refused fuse.OpenOut
			if status := f.rawCall(func(u uint64) fuse.Status {
				return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}}, &refused)
			}); status != fuse.Status(syscall.EACCES) {
				t.Fatalf("new open=%v", status)
			}
			if b.backing.pending.handle == nil || b.stale.Load() {
				t.Fatal("permission withdrawal retired old handle rights")
			}
		})
	}
}

func TestDirectoryCacheChildOnlyChangesRequireFreshPlusAttributes(t *testing.T) {
	for _, scope := range []publicationCoordinateKind{publicationItemAttributes, publicationItemData} {
		t.Run(map[publicationCoordinateKind]string{publicationItemAttributes: "attributes", publicationItemData: "data"}[scope], func(t *testing.T) {
			raw, _, rpc := testRawFileSystem(t, 16)
			id, _ := testDirHandle(t, raw, plusTestPages(1)...)
			directoryCacheReply(t, raw, id, 0, true)
			identity := publicationIdentity(testIdentity(100))
			for key := range raw.cachedAttrPayloads {
				identity = key
				break
			}
			coordinate := publicationCoordinate{kind: scope, item: identity}
			lease, err := raw.closeCacheCoordinate(context.Background(), coordinate)
			if err != nil {
				t.Fatal(err)
			}
			if err = raw.invalidateCacheCoordinate(coordinate, nil); err != nil {
				t.Fatal(err)
			}
			lease.Open()
			if len(raw.directories.pages) != 1 {
				t.Fatal("child-only change discarded listing")
			}
			before := len(rpc.readdirs)
			directoryCacheReply(t, raw, id, 0, true)
			if len(rpc.readdirs) != before+1 {
				t.Fatal("PLUS reused stale child attributes")
			}
		})
	}
}

func TestDirectoryCacheEvictionIsAMissAndCannotSpliceCompleteness(t *testing.T) {
	raw, _, rpc := testRawFileSystem(t, 16)
	id, _ := testDirHandle(t, raw, plusTestPages(1)...)
	directoryCacheReply(t, raw, id, 0, true)
	raw.mu.Lock()
	raw.directories.limit = 1
	raw.trimDirectoryPagesLocked(0, 0)
	raw.mu.Unlock()
	if len(raw.directories.pages) != 0 || len(raw.completeDirectories) != 0 {
		t.Fatal("eviction retained completeness")
	}
	before := len(rpc.readdirs)
	directoryCacheReply(t, raw, id, 0, true)
	if len(rpc.readdirs) != before+1 {
		t.Fatal("eviction did not become a miss")
	}
	if raw.directories.capacityEvictions == 0 {
		t.Fatal("capacity reason not recorded")
	}
}

func TestDirectoryCacheOvertakenFillCannotRepublish(t *testing.T) {
	raw, _, _ := testRawFileSystem(t, 16)
	id, _ := testDirHandle(t, raw, plusTestPages(1)...)
	u := nextTestRequestUnique()
	if status := raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u}, Fh: id}, fuse.NewDirEntryList(make([]byte, 4096), 0)); status != fuse.OK {
		t.Fatal(status)
	}
	identity := raw.handles[id].inode.identity
	coordinate := publicationCoordinate{kind: publicationItemEnumeration, item: identity}
	lease, err := raw.closeCacheCoordinate(context.Background(), coordinate)
	if err != nil {
		t.Fatal(err)
	}
	if err = raw.invalidateCacheCoordinate(coordinate, nil); err != nil {
		t.Fatal(err)
	}
	lease.Open()
	raw.PrepareReplyPayload(u, 42, 44, nil, nil, 0)
	completeTestReply(t, raw, u, fuse.OK)
	if len(raw.directories.pages) != 0 || len(raw.completeDirectories) != 0 || len(raw.directories.fills) != 0 {
		t.Fatal("overtaken fill restored old state")
	}
}

func TestDirectoryCacheDelegationTransitionCannotRevivePageAttributes(t *testing.T) {
	raw, mount, rpc := testRawFileSystem(t, 16)
	id, _ := testDirHandle(t, raw, plusTestPages(1)...)
	directoryCacheReply(t, raw, id, 0, true)
	mount.delegations.metadataClock.Add(1)
	before := len(rpc.readdirs)
	directoryCacheReply(t, raw, id, 0, true)
	if len(rpc.readdirs) != before+1 {
		t.Fatal("ownership transition revived old page metadata")
	}
}

func TestDirectoryCacheColdRetiresIdleOwnershipAndPreservesLiveHandles(t *testing.T) {
	f := newStockFixture(t)
	var out fuse.OpenOut
	if st := f.rawCall(func(u uint64) fuse.Status {
		return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}}, &out)
	}); st != fuse.OK {
		t.Fatal(st)
	}
	h := f.raw.handles[out.Fh].dir
	before := f.raw.directories.session
	f.mount.subscription.deactivate()
	if err := f.raw.invalidateAllCaches(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.raw.directories.proofs) != 0 || len(f.raw.directories.pages) != 0 || f.raw.directories.session <= before {
		t.Fatal("cold state retained a cache proof")
	}
	if h.backing.cached || h.backing.refs != 1 || len(h.backing.pending.handle) != 16 || h.stale.Load() {
		t.Fatal("cold reset retired a live application description")
	}
}

func TestDirectoryCacheMixedRouteKeepsLocalCookiesIndependent(t *testing.T) {
	raw, _, rpc := testRawFileSystem(t, 16)
	page := plusTestPages(2)[0]
	for _, row := range page.Entries {
		row.Item = nil
	}
	id, _ := testDirHandle(t, raw, page)
	held, h := raw.acquireDirHandle(id)
	raw.releaseHandleOperation(held)
	local := []fuse.DirEntry{{Name: "file-0000", Mode: syscall.S_IFDIR, Ino: 999, Off: graftDirOffsetBase | 1}}
	shadow := func(name string) bool { return name == "file-0000" }
	h.local, h.shadow = local, shadow
	if got := directoryCacheReply(t, raw, id, 0, false); got != graftDirOffsetBase|1 {
		t.Fatalf("local continuation=%d", got)
	}
	before := len(rpc.readdirs)
	second, _ := raw.addHandle(held.inode, &handleRecord{dir: &dirHandle{node: h.node, token: testToken(101), local: local, shadow: shadow}})
	if got := directoryCacheReply(t, raw, second, 0, false); got != graftDirOffsetBase|1 {
		t.Fatalf("reused local continuation=%d", got)
	}
	if len(rpc.readdirs) != before || len(raw.directories.pages) != 1 {
		t.Fatal("shared listing was not reused independently of the graft")
	}
}

func TestDirectoryCacheAuthorityCapacityEvictsIdleDescription(t *testing.T) {
	f := newStockFixture(t)
	var first fuse.OpenOut
	if st := f.rawCall(func(u uint64) fuse.Status {
		return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}}, &first)
	}); st != fuse.OK {
		t.Fatal(st)
	}
	f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: nextTestRequestUnique()}, Fh: first.Fh})
	item := testItem(42, authoritypb.Attr_DIRECTORY, 42)
	record, errno := f.raw.intern(context.Background(), item)
	if errno != 0 {
		t.Fatal(errno)
	}
	f.rpc.byName = map[string]*authoritypb.Item{"other": item}
	f.rpc.replyOverride = func(q *authoritypb.Request) (*authoritypb.Response, error) {
		f.rpc.replyOverride = nil
		if q.GetOpen() == nil {
			t.Errorf("unexpected request %T", q.GetBody())
		}
		return &authoritypb.Response{Errno: int32(syscall.ENFILE)}, nil
	}
	var second fuse.OpenOut
	if st := f.rawCall(func(u uint64) fuse.Status {
		return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: record.id}}, &second)
	}); st != fuse.OK {
		t.Fatal("cache-owned descriptor pressure became an application error", st)
	}
	if f.raw.directories.capacityEvictions == 0 || pendingCloses(f.mount.delegations) != 0 {
		t.Fatal("capacity eviction lost counted cleanup ownership")
	}
}

func TestDirectoryCacheCompletenessWithdrawsSearchAdmission(t *testing.T) {
	raw, _, _ := testRawFileSystem(t, 16)
	id, _ := testDirHandle(t, raw, plusTestPages(1)...)
	directory := raw.handles[id].inode
	var opened fuse.OpenOut
	if st := testRawCall(t, raw, func(u uint64) fuse.Status {
		return raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: directory.id}}, &opened)
	}); st != fuse.OK {
		t.Fatal(st)
	}
	directoryCacheReply(t, raw, id, 0, true)
	u := nextTestRequestUnique()
	if !raw.lookupCachedReply(u, directory, "absent", &fuse.EntryOut{}) {
		t.Fatal("complete authorized walk did not prove absence")
	}
	if raw.replyPublications[u].cachedCount != 3 {
		t.Fatal("absence omitted its search-permission coordinate")
	}
	completeTestReply(t, raw, u, fuse.OK)
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: directory.identity}
	lease, err := raw.closeCacheCoordinate(context.Background(), coordinate)
	if err != nil {
		t.Fatal(err)
	}
	if err = raw.invalidateCacheCoordinate(coordinate, nil); err != nil {
		t.Fatal(err)
	}
	lease.Open()
	if raw.lookupCachedReply(nextTestRequestUnique(), directory, "absent", &fuse.EntryOut{}) {
		t.Fatal("permission withdrawal retained negative lookup authority")
	}
}

func TestDirectoryCacheReadOnlySearchDenialNeverAuthorizesAnotherOpen(t *testing.T) {
	f := newStockFixture(t)
	f.rpc.replyOverride = func(q *authoritypb.Request) (*authoritypb.Response, error) {
		return &authoritypb.Response{VolumeVersion: 2, Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: testToken(900), DirectoryReadProof: &authoritypb.DirectoryReadProof{StableIdentity: testIdentity(1), Incarnation: q.GetOpen().GetReusableDirectoryReadIncarnation(), ObjectVersion: 1, SnapshotSequence: 2, Reusable: false}}}}, nil
	}
	for i := 0; i < 2; i++ {
		var out fuse.OpenOut
		if st := f.rawCall(func(u uint64) fuse.Status {
			return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}}, &out)
		}); st != fuse.OK {
			t.Fatal(st)
		}
		if out.Fh == 0 || len(f.raw.directories.proofs) != 0 {
			t.Fatal("search denial became reusable open permission")
		}
	}
	if f.raw.directories.openMisses != 2 || f.raw.directories.openHits != 0 {
		t.Fatal("new opens did not return to access admission")
	}
}

func TestDirectoryCacheBufferedPlusCannotServeChangedChildAttributes(t *testing.T) {
	raw, mount, rpc := testRawFileSystem(t, 16)
	page := plusTestPages(2)[0]
	id, _ := testDirHandle(t, raw, page)
	buffer := make([]byte, int(unsafe.Sizeof(fuse.EntryOut{}))+40)
	first := fuse.NewDirEntryList(buffer, 0)
	u := nextTestRequestUnique()
	if st := raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u}, Fh: id}, first); st != fuse.OK {
		t.Fatal(st)
	}
	raw.PrepareReplyPayload(u, 42, 44, nil, nil, 0)
	completeTestReply(t, raw, u, fuse.OK)
	if first.Offset != 1 {
		t.Fatalf("first offset=%d", first.Offset)
	}
	changed := page.Entries[1]
	identity, _ := publicationIdentityFromBytes(changed.GetStableIdentity())
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: identity}
	mount.subscription.mu.Lock()
	mount.subscription.generation++
	mount.subscription.coordinates[coordinate] = subscriptionCoordinateState{generation: mount.subscription.generation, minVersion: 3}
	mount.subscription.mu.Unlock()
	lease, err := raw.closeCacheCoordinate(context.Background(), coordinate)
	if err != nil {
		t.Fatal(err)
	}
	if err = raw.invalidateCacheCoordinate(coordinate, nil); err != nil {
		t.Fatal(err)
	}
	lease.Open()
	changed.Attr.Size = 9
	changed.ObjectVersion, changed.SnapshotSequence = 3, 3
	changed.Item.Attr.Size = 9
	changed.Item.ObjectVersion, changed.Item.SnapshotSequence = 3, 3
	rpc.mu.Lock()
	rpc.readSequence = 3
	rpc.dirPages = append(rpc.dirPages, &authoritypb.ReadDirReply{Entries: []*authoritypb.Dirent{changed}, Eof: true})
	rpc.mu.Unlock()
	second := fuse.NewDirEntryList(buffer, 1)
	v := nextTestRequestUnique()
	if st := raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: v}, Fh: id, Offset: 1}, second); st != fuse.OK {
		t.Fatal(st)
	}
	raw.PrepareReplyPayload(v, 42, 44, nil, nil, 0)
	completeTestReply(t, raw, v, fuse.OK)
	if size := (*fuse.EntryOut)(unsafe.Pointer(&buffer[0])).Attr.Size; size != 9 {
		t.Fatalf("buffered changed size=%d", size)
	}
	if len(rpc.readdirs) != 2 || string(rpc.readdirs[1].GetCookie()) != string(encodeCookie(1)) {
		t.Fatal("attribute refresh abandoned the consumed XFS cookie")
	}
}

func TestDirectoryCacheMembershipWithdrawalPreservesCookieAndSeparatesGenerations(t *testing.T) {
	for _, change := range []string{"rename", "create", "unlink"} {
		t.Run(change, func(t *testing.T) {
			raw, mount, rpc := testRawFileSystem(t, 4096)
			original := plusTestPages(300)
			id, _ := testDirHandle(t, raw, original...)
			if offset := directoryCacheReply(t, raw, id, 0, true); offset != 256 {
				t.Fatalf("first page cookie=%d", offset)
			}
			directory := raw.handles[id].inode.identity
			coordinate := publicationCoordinate{kind: publicationItemEnumeration, item: directory}
			mount.subscription.mu.Lock()
			mount.subscription.generation++
			generation := mount.subscription.generation
			mount.subscription.coordinates[coordinate] = subscriptionCoordinateState{generation: generation, minVersion: 3}
			mount.subscription.mu.Unlock()
			lease, err := raw.closeCacheCoordinate(context.Background(), coordinate)
			if err != nil {
				t.Fatal(err)
			}
			if err = raw.invalidateCacheCoordinate(coordinate, nil); err != nil {
				t.Fatal(err)
			}
			lease.Open()
			if len(raw.directories.pages) != 0 {
				t.Fatal("withdrawal retained an old page")
			}
			count := 300
			if change == "create" {
				count++
			}
			updated := plusTestPages(count)[1]
			switch change {
			case "rename":
				updated.Entries[0].Name = []byte("renamed-child")
			case "unlink":
				updated.Entries = updated.Entries[1:]
			}
			for _, row := range updated.Entries {
				row.ObjectVersion, row.SnapshotSequence = 3, 3
				row.Item.ObjectVersion, row.Item.SnapshotSequence = 3, 3
			}
			rpc.mu.Lock()
			rpc.dirPages = append(rpc.dirPages[:1], updated)
			rpc.readSequence = 3
			rpc.mu.Unlock()
			if offset := directoryCacheReply(t, raw, id, 256, true); offset != uint64(count) {
				t.Fatalf("continuation=%d", offset)
			}
			if len(rpc.readdirs) != 2 || string(rpc.readdirs[1].GetCookie()) != string(encodeCookie(256)) {
				t.Fatal("membership change restarted the active cursor")
			}
			if raw.completeDirectories[directory] != nil {
				t.Fatal("old first page was spliced into a new complete walk")
			}
			for key := range raw.directories.pages {
				if key.generation != generation {
					t.Fatalf("retained page generation=%d, want %d", key.generation, generation)
				}
			}
		})
	}
}

func TestDirectoryCachePendingPayloadRespectsByteBound(t *testing.T) {
	raw, _, _ := testRawFileSystem(t, 16)
	page := plusTestPages(1)[0]
	id, _ := testDirHandle(t, raw, page)
	key := directoryReadKey{directory: raw.handles[id].inode.identity}
	payload := directoryPageFromReply(key, subscriptionStamp{version: 2}, page)
	if payload == nil {
		t.Fatal("invalid fixture page")
	}
	raw.mu.Lock()
	raw.directories.limit = raw.metadataBytesLocked() + payload.bytes + 768*len(payload.rows) - 1
	raw.mu.Unlock()
	u := nextTestRequestUnique()
	if status := raw.ReadDir(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u}, Fh: id}, fuse.NewDirEntryList(make([]byte, 4096), 0)); status != fuse.OK {
		t.Fatal(status)
	}
	raw.mu.RLock()
	used, limit := raw.metadataBytesLocked(), raw.directories.limit
	raw.mu.RUnlock()
	if used > limit {
		t.Fatalf("pending payload exceeded bound: %d > %d", used, limit)
	}
	raw.PrepareReplyPayload(u, 42, 28, nil, nil, 0)
	completeTestReply(t, raw, u, fuse.OK)
	if len(raw.directories.pages) != 0 || raw.directories.pendingBytes != 0 || raw.directories.pendingNames != 0 {
		t.Fatal("over-capacity page retained payload or reservation")
	}
}

func TestDirectoryCachePermissionWithdrawalJoinsFinalizedLocalOpen(t *testing.T) {
	f := newStockFixture(t)
	var first fuse.OpenOut
	if status := f.rawCall(func(u uint64) fuse.Status {
		return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}}, &first)
	}); status != fuse.OK {
		t.Fatal(status)
	}
	u := nextTestRequestUnique()
	var second fuse.OpenOut
	if status := f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}}, &second); status != fuse.OK {
		t.Fatal(status)
	}
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: f.raw.handles[second.Fh].inode.identity}
	done := make(chan *cacheWithdrawalLease, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		lease, err := f.raw.closeCacheCoordinate(ctx, coordinate)
		if err != nil {
			done <- nil
			return
		}
		done <- lease
	}()
	waitUntil(t, time.Second, "permission withdrawal cut", func() bool {
		f.raw.mu.RLock()
		defer f.raw.mu.RUnlock()
		return f.raw.withdrawingCoordinates[coordinate]
	})
	select {
	case <-done:
		t.Fatal("permission withdrawal passed a finalized unwritten local OPEN")
	default:
	}
	_, status, lifecycle := f.raw.PrepareReplyPayload(u, 1, 27, nil, nil, 0)
	if status != fuse.OK || lifecycle != fuse.OK {
		t.Fatalf("original granted OPEN=%v/%v", status, lifecycle)
	}
	completeTestReply(t, f.raw, u, fuse.OK)
	lease := <-done
	if lease == nil {
		t.Fatal("withdrawal did not join the physical OPEN")
	}
	if err := f.raw.invalidateCacheCoordinate(coordinate, nil); err != nil {
		t.Fatal(err)
	}
	lease.Open()
	if handle := f.raw.handles[second.Fh].dir; handle.stale.Load() || handle.backing.cached || handle.backing.refs != 2 {
		t.Fatal("permission withdrawal lost the two previously admitted handles")
	}
}

func TestDirectoryCacheUnwrittenOpenReleasesOnlyItsLocalReference(t *testing.T) {
	for _, warm := range []bool{false, true} {
		t.Run(map[bool]string{false: "fill", true: "hit"}[warm], func(t *testing.T) {
			f := newStockFixture(t)
			if warm {
				var first fuse.OpenOut
				if status := f.rawCall(func(u uint64) fuse.Status {
					return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}}, &first)
				}); status != fuse.OK {
					t.Fatal(status)
				}
			}
			u := nextTestRequestUnique()
			var opened fuse.OpenOut
			if status := f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: 1}}, &opened); status != fuse.OK {
				t.Fatal(status)
			}
			handle := f.raw.handles[opened.Fh].dir
			if !f.raw.ReplyWriteTracked(u) {
				t.Fatal("OPEN lost its raw publication owner")
			}
			_, status, lifecycle := f.raw.PrepareReplyPayload(u, 1, 27, nil, nil, 0)
			if status != fuse.OK || lifecycle != fuse.OK {
				t.Fatalf("prepare=%v/%v", status, lifecycle)
			}
			completeTestReply(t, f.raw, u, fuse.EIO)
			if !f.mount.isRevoked() {
				t.Fatal("physical reply failure did not close serving admission")
			}
			// A lost physical reply starts asynchronous terminal withdrawal.
			// Join it before inspecting ownership: a previously warm proof is
			// retired by that boundary, while the older application reference
			// remains independent of the failed OPEN's reference.
			_ = f.mount.Close()
			f.raw.mu.RLock()
			orphan := f.raw.handles[opened.Fh] != nil
			reservations := len(f.raw.cacheReservations)
			refs, cached := handle.backing.refs, handle.backing.cached
			terminal := f.raw.replyTerminal
			f.raw.mu.RUnlock()
			if orphan || reservations != 0 {
				t.Fatal("unwritten OPEN retained its local handle or reservation")
			}
			wantRefs := 0
			if warm {
				wantRefs = 1
			}
			if !terminal || refs != wantRefs || cached {
				t.Fatalf("terminal=%v backing refs=%d cached=%v, want terminal with refs=%d and no cache proof", terminal, refs, cached, wantRefs)
			}
		})
	}
}

func TestDirectoryCacheSourceRetirementDefersQueueWaitBeyondCallbackFence(t *testing.T) {
	f := newStockFixture(t)
	f.mount.delegations.Stop()
	manager, err := newDelegationManagerWithCloseCapacity(f.mount.rpc, time.Second, 1, writeback.Options{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.mount.delegations, f.mount.subscription.control, manager.subscription = manager, manager, f.mount.subscription
	entered, release := make(chan struct{}, 1), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	installAuthorityHook(f, func(q *authoritypb.Request) {
		if q.GetCloseBatch() != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
	})
	for i := uint64(20); i < 22; i++ {
		owner, err := manager.reserveRetainedClose(delegationClose{identity: testIdentity(i), handle: testToken(i), epoch: manager.sessionSerial})
		if err != nil {
			t.Fatal(err)
		}
		owner.dispatch(context.Background())
		if i == 20 {
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("first cleanup did not start")
			}
		}
	}
	if len(manager.closeQueue) != cap(manager.closeQueue) {
		t.Fatal("cleanup queue did not saturate")
	}
	root := f.raw.nodesByID[1]
	backing := &directoryBacking{identity: root.identity, stamp: f.mount.subscription.stamp().withVersion(2), cached: true, pending: delegationClose{identity: cloneBytes(root.identity[:]), handle: testToken(22), epoch: manager.sessionSerial}}
	f.raw.mu.Lock()
	f.raw.directories.proofs[root.identity] = backing
	f.raw.mu.Unlock()
	u := nextTestRequestUnique()
	ctx, finish, status := f.raw.mutationContext(u)
	if status != fuse.OK {
		t.Fatal(status)
	}
	gate, err := itemSourceGate(root.node.item, false)
	if err != nil {
		t.Fatal(err)
	}
	callback := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
	lease, err := callback.acquireSource(ctx, f.raw, gate)
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.markAssigned(); err != nil {
		t.Fatal(err)
	}
	marked, finished := make(chan error, 1), make(chan struct{})
	go func() { marked <- lease.markCallbackPublicationReady(ctx); finish(); close(finished) }()
	select {
	case err = <-marked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("source retirement waited for queue capacity inside its callback fence")
	}
	waitUntil(t, time.Second, "callback fence released before queue dispatch", func() bool {
		if f.mount.epochMu.TryLock() {
			f.mount.epochMu.Unlock()
			return true
		}
		return false
	})
	if pendingCloses(manager) != 3 || backing.cached {
		t.Fatal("source retirement lost counted ownership before queue dispatch")
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("callback did not finish after cleanup resumed")
	}
	completeTestReply(t, f.raw, u, fuse.OK)
	waitUntil(t, time.Second, "retired proof cleanup", func() bool { return pendingCloses(manager) == 0 })
}
