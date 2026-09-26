//go:build linux

package fusev3

import (
	"context"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// Delay delivery after storage sampled the attributes, without holding any
// transport or fake-storage lock needed by a concurrent clean flush/release.
type delayedMetadataRPC struct {
	RPC
	transform       func(*authoritypb.Request, *authoritypb.Response)
	matches         func(*authoritypb.Request) bool
	started, resume chan struct{}
	once            sync.Once
}

func (r *delayedMetadataRPC) delay(ctx context.Context, request *authoritypb.Request) error {
	if !r.matches(request) {
		return nil
	}
	first := false
	r.once.Do(func() { first = true; close(r.started) })
	if first {
		select {
		case <-r.resume:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (r *delayedMetadataRPC) CallReadRetained(ctx context.Context, request *authoritypb.Request, force func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, consumption, err := r.RPC.CallReadRetained(ctx, request, force)
	if err == nil && r.transform != nil {
		r.transform(request, response)
	}
	if err == nil {
		err = r.delay(ctx, request)
	}
	return response, consumption, err
}

func (r *delayedMetadataRPC) CallMutationWithIdentityRetained(ctx context.Context, request *authoritypb.Request, assigned authorityrpc.MutationAssigned, force func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, consumption, err := r.RPC.CallMutationWithIdentityRetained(ctx, request, assigned, force)
	if err == nil {
		err = r.delay(ctx, request)
	}
	return response, consumption, err
}

func (r *delayedMetadataRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetDelegationRelease() != nil {
		return &authoritypb.Response{Body: &authoritypb.Response_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseReply{}}}, nil
	}
	return r.RPC.CallIdempotent(ctx, request)
}

func installMetadataDelay(f *strictFixture, matches func(*authoritypb.Request) bool) *delayedMetadataRPC {
	rpc := &delayedMetadataRPC{RPC: f.rpc, matches: matches, started: make(chan struct{}), resume: make(chan struct{})}
	epoch := f.mount.rpc.(*epochRPC)
	epoch.mu.Lock()
	epoch.rpc = rpc
	epoch.mu.Unlock()
	return rpc
}

func metadataPage(items ...*authoritypb.Item) *authoritypb.ReadDirReply {
	page := &authoritypb.ReadDirReply{Verifier: testToken(5), Eof: true}
	for i, item := range items {
		item = cloneItem(item)
		item.ObjectVersion, item.SnapshotSequence = 1, 1
		page.Entries = append(page.Entries, &authoritypb.Dirent{
			Name: []byte{byte('a' + i)}, Attr: item.Attr, Item: item, NextCookie: encodeCookie(uint64(i + 1)),
			ObjectVersion: 1, SnapshotSequence: 1, StableIdentity: cloneBytes(item.StableIdentity),
		})
	}
	return page
}

func applyMetadataTestStorage(f *strictFixture, size int64, version uint64) {
	// The general fake records WRITE calls but does not maintain a byte store.
	f.rpc.mu.Lock()
	f.rpc.item.Attr.Size, f.rpc.readSequence = size, version
	f.rpc.mu.Unlock()
}

func TestUnownedSetattrPublishesVersionedPostState(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "file")
	// The fake records SETATTR and returns its stored attributes as post-state.
	f.rpc.mu.Lock()
	f.rpc.item.Attr.Mode = 0o640
	f.rpc.mu.Unlock()
	unique := f.unique.Add(2)
	in := &fuse.SetAttrIn{}
	in.Unique, in.NodeId = unique, entry.NodeId
	in.Valid, in.Mode = fuse.FATTR_MODE, 0o640
	var out fuse.AttrOut
	if status := f.raw.SetAttr(nil, in, &out); status != fuse.OK {
		t.Fatal(status)
	}
	completeTestReply(t, f.raw, unique, fuse.OK)
	f.raw.mu.Lock()
	cached, ok := f.raw.cachedAttrPayloads[publicationIdentity(testIdentity(7))]
	f.raw.mu.Unlock()
	if !ok || cached.objectVersion != 2 || cached.snapshot != 2 || cached.attr.GetMode() != 0o640 {
		t.Fatalf("SETATTR lost its exact versioned post-state: cached=%v payload=%+v", ok, cached)
	}
	f.rpc.mu.Lock()
	before := f.rpc.calls
	f.rpc.mu.Unlock()
	warm := f.lookup(t, 1, "file")
	var stat fuse.AttrOut
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: warm.NodeId}}, &stat)
	})
	f.rpc.mu.Lock()
	after := f.rpc.calls
	f.rpc.mu.Unlock()
	if status != fuse.OK || warm.Attr.Mode&0o777 != 0o640 || stat.Mode&0o777 != 0o640 || after != before {
		t.Fatalf("warm metadata after SETATTR: status=%v lookup mode=%o stat mode=%o extra RPCs=%d", status, warm.Attr.Mode, stat.Mode, after-before)
	}
	if f.mount.isRevoked() || f.mount.delegations.LossSequence() != 0 {
		t.Fatal("metadata publication revoked the mount or reported data loss")
	}
}

func TestMetadataReplyAcrossCleanOwnershipChange(t *testing.T) {
	for _, operation := range []string{"getattr", "lookup", "readdirplus"} {
		for _, successor := range []bool{false, true} {
			name := operation + "/release"
			if successor {
				name = operation + "/successor"
			}
			t.Run(name, func(t *testing.T) {
				f := newStrictFixture(t)
				entry := f.lookup(t, 1, "index.lock")
				opened := openV7Writer(t, f, entry.NodeId)
				writeV7(t, f, entry.NodeId, opened.Fh, 4096, []byte("dirty"))
				var dir uint64
				if operation == "readdirplus" {
					dir, _ = testDirHandle(t, f.raw, metadataPage(f.rpc.item))
				}
				delayed := installMetadataDelay(f, func(request *authoritypb.Request) bool {
					switch operation {
					case "getattr":
						return request.GetGetAttr() != nil
					case "lookup":
						return request.GetLookup() != nil
					default:
						return request.GetReadDir() != nil
					}
				})
				unique := f.unique.Add(2)
				var attr fuse.AttrOut
				var lookup fuse.EntryOut
				buffer := make([]byte, 4096)
				done := make(chan fuse.Status, 1)
				go func() {
					switch operation {
					case "getattr":
						done <- f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &attr)
					case "lookup":
						done <- f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "alias", &lookup)
					default:
						done <- f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: dir}, fuse.NewDirEntryList(buffer, 0))
					}
				}()
				select {
				case <-delayed.started:
				case <-time.After(time.Second):
					t.Fatal("metadata request did not reach storage")
				}
				identity := testIdentity(7)
				if err := f.mount.delegations.ReleaseBatch(t.Context(), [][]byte{identity}); err != nil {
					t.Fatal(err)
				}
				applyMetadataTestStorage(f, 4101, 2)
				want := uint64(4101)
				if successor {
					grant := delegationTestGrant(45, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
					grant.Generation = 2
					if err := f.mount.delegations.Install(identity, f.rpc.item.Token, testToken(101), grant); err != nil {
						t.Fatal(err)
					}
					// The next owner changed storage, then accepted another local write.
					applyMetadataTestStorage(f, 5000, 3)
					if _, err := f.mount.delegations.Write(t.Context(), identity, 6000, []byte("new"), false); err != nil {
						t.Fatal(err)
					}
					want = 6003
				}
				close(delayed.resume)
				status := <-done
				if operation == "readdirplus" {
					f.raw.PrepareReplyPayload(unique, 42, 44, nil, nil, 0)
				}
				completeTestReply(t, f.raw, unique, fuse.OK)
				got := attr.Size
				if operation == "lookup" {
					got = lookup.Attr.Size
				} else if operation == "readdirplus" {
					got = (*fuse.EntryOut)(unsafe.Pointer(&buffer[0])).Attr.Size
				}
				if status != fuse.OK || got != want {
					t.Fatalf("metadata after accepted WRITE: status=%v size=%d want=%d", status, got, want)
				}
				if loss := f.mount.delegations.LossSequence(); loss != 0 {
					t.Fatalf("clean transition reported data loss %d", loss)
				}
			})
		}
	}
}

func TestMetadataReplyPinsOwnershipUntilPhysicalWrite(t *testing.T) {
	for _, owned := range []bool{false, true} {
		name := "shared-install"
		if owned {
			name = "holder-release"
		}
		t.Run(name, func(t *testing.T) {
			f := newStrictFixture(t)
			entry := f.lookup(t, 1, "index.lock")
			if owned {
				opened := openV7Writer(t, f, entry.NodeId)
				writeV7(t, f, entry.NodeId, opened.Fh, 4096, []byte("dirty"))
			} else {
				f.raw.mu.Lock()
				delete(f.raw.cachedAttrs, publicationIdentity(testIdentity(7)))
				delete(f.raw.cachedAttrPayloads, publicationIdentity(testIdentity(7)))
				f.raw.mu.Unlock()
			}
			installMetadataDelay(f, func(*authoritypb.Request) bool { return false })
			unique := f.unique.Add(2)
			var attr fuse.AttrOut
			status := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &attr)
			if status != fuse.OK {
				t.Fatal(status)
			}
			done := make(chan error, 1)
			go func() {
				if owned {
					done <- f.mount.delegations.ReleaseBatch(t.Context(), [][]byte{testIdentity(7)})
				} else {
					done <- f.mount.delegations.Install(testIdentity(7), f.rpc.item.Token, testToken(101), delegationTestGrant(45, authoritypb.DelegationMode_DELEGATION_MODE_FULL))
				}
			}()
			select {
			case err := <-done:
				t.Fatalf("ownership changed before kernel reply: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			completeTestReply(t, f.raw, unique, fuse.OK)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("ownership remained pinned after physical reply")
			}
		})
	}
}

func TestReadDirPlusBufferedMetadataRechecksOwnershipInterval(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "index.lock")
	opened := openV7Writer(t, f, entry.NodeId)
	writeV7(t, f, entry.NodeId, opened.Fh, 4096, []byte("dirty"))
	page := metadataPage(testItem(8, authoritypb.Attr_REGULAR, 8), f.rpc.item)
	dir, _ := testDirHandle(t, f.raw, page)
	installMetadataDelay(f, func(*authoritypb.Request) bool { return false })
	buffer := make([]byte, int(unsafe.Sizeof(fuse.EntryOut{}))+32)
	first := fuse.NewDirEntryList(buffer, 0)
	unique := f.unique.Add(2)
	if status := f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: dir}, first); status != fuse.OK {
		t.Fatal(status)
	}
	f.raw.PrepareReplyPayload(unique, 42, 44, nil, nil, 0)
	completeTestReply(t, f.raw, unique, fuse.OK)
	if first.Offset != 1 {
		t.Fatalf("first reply consumed %d entries, want one", first.Offset)
	}
	if err := f.mount.delegations.ReleaseBatch(t.Context(), [][]byte{testIdentity(7)}); err != nil {
		t.Fatal(err)
	}
	applyMetadataTestStorage(f, 4101, 2)
	fresh := metadataPage(f.rpc.item)
	fresh.Entries[0].Name, fresh.Entries[0].NextCookie = []byte("b"), encodeCookie(2)
	fresh.Entries[0].ObjectVersion, fresh.Entries[0].SnapshotSequence = 2, 2
	fresh.Entries[0].Item.ObjectVersion, fresh.Entries[0].Item.SnapshotSequence = 2, 2
	f.rpc.mu.Lock()
	f.rpc.dirPages = append(f.rpc.dirPages, fresh)
	f.rpc.mu.Unlock()
	second := fuse.NewDirEntryList(buffer, first.Offset)
	unique = f.unique.Add(2)
	if status := f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: dir, Offset: first.Offset}, second); status != fuse.OK {
		t.Fatal(status)
	}
	f.raw.PrepareReplyPayload(unique, 42, 44, nil, nil, 0)
	completeTestReply(t, f.raw, unique, fuse.OK)
	if size := (*fuse.EntryOut)(unsafe.Pointer(&buffer[0])).Attr.Size; size != 4101 {
		t.Fatalf("buffered PLUS row crossed release with size %d, want 4101", size)
	}
	f.rpc.mu.Lock()
	calls := len(f.rpc.readdirs)
	f.rpc.mu.Unlock()
	if calls != 2 || f.mount.delegations.LossSequence() != 0 {
		t.Fatalf("PLUS refetch calls=%d loss=%d", calls, f.mount.delegations.LossSequence())
	}
}

func TestReadDirPlusAliasesSharePhysicalPinAndKeepIndependentNames(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "index.lock")
	opened := openV7Writer(t, f, entry.NodeId)
	writeV7(t, f, entry.NodeId, opened.Fh, 4096, []byte("dirty"))
	dir, _ := testDirHandle(t, f.raw, metadataPage(f.rpc.item, f.rpc.item, testItem(8, authoritypb.Attr_REGULAR, 8)))
	buffer := make([]byte, 4096)
	unique := f.unique.Add(2)
	list := fuse.NewDirEntryList(buffer, 0)
	if status := f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: dir}, list); status != fuse.OK {
		t.Fatal(status)
	}
	f.raw.mu.Lock()
	publication := f.raw.replyPublications[unique]
	pins := len(publication.holderAdmissions)
	if publication.holderAdmission != nil {
		pins++
	}
	f.raw.mu.Unlock()
	if pins != 2 || list.Offset != 3 {
		t.Fatalf("PLUS physical pins=%d rows=%d, want two identities and three rows", pins, list.Offset)
	}
	rowSize := int(unsafe.Sizeof(fuse.EntryOut{})) + 32
	for _, offset := range []int{0, rowSize} {
		if size := (*fuse.EntryOut)(unsafe.Pointer(&buffer[offset])).Attr.Size; size != 4101 {
			t.Fatalf("alias size %d, want 4101", size)
		}
	}
	f.raw.PrepareReplyPayload(unique, 42, 44, nil, nil, 0)
	completeTestReply(t, f.raw, unique, fuse.OK)
	f.raw.mu.Lock()
	for _, name := range []string{"a", "b", "c"} {
		if f.raw.cachedNames[nameKey{parent: 42, name: name}] == nil {
			t.Errorf("PLUS lost independent name %s", name)
		}
	}
	_, privateCached := f.raw.cachedAttrPayloads[publicationIdentity(testIdentity(7))]
	_, sharedCached := f.raw.cachedAttrPayloads[publicationIdentity(testIdentity(8))]
	f.raw.mu.Unlock()
	if privateCached || !sharedCached {
		t.Fatalf("PLUS cached holder attr=%v unrelated shared attr=%v", privateCached, sharedCached)
	}
}

func TestMetadataTimeoutRetiresRequestHistory(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "index.lock")
	opened := openV7Writer(t, f, entry.NodeId)
	writeV7(t, f, entry.NodeId, opened.Fh, 4096, []byte("dirty"))
	f.raw.requestTimeout = 20 * time.Millisecond
	installMetadataDelay(f, func(request *authoritypb.Request) bool { return request.GetGetAttr() != nil })
	unique := f.unique.Add(2)
	status := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{})
	completeTestReply(t, f.raw, unique, fuse.OK)
	if status == fuse.OK {
		t.Fatal("stalled response escaped callback deadline")
	}
	if f.mount.isRevoked() {
		t.Fatal("metadata timeout revoked the recoverable mount")
	}
	f.mount.delegations.mu.RLock()
	requests := len(f.mount.delegations.grantRequests)
	f.mount.delegations.mu.RUnlock()
	if requests != 0 {
		t.Fatalf("failed metadata retained %d retirement intervals", requests)
	}
}

func TestMetadataSamplingAndSourceAdmissionAreAtomic(t *testing.T) {
	f, entry := dirtyHolderMetadataFixture(t)
	opened := openV7Writer(t, f, entry.NodeId)
	state := f.mount.delegations.retainState(writeback.Identity(testIdentity(7)), false)
	defer f.mount.delegations.releaseState(state)
	state.meta.Lock()
	var release sync.Once
	unlock := func() { release.Do(state.meta.Unlock) }
	defer unlock()
	unique := f.unique.Add(2)
	var attr fuse.AttrOut
	metadata := make(chan fuse.Status, 1)
	go func() {
		metadata <- f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &attr)
	}()
	// The sampler must close the raw source-admission edge before reading its
	// overlay. Pausing at the metadata mutex proves these are one transaction.
	waitUntil(t, time.Second, "metadata source transaction", func() bool {
		if f.raw.mu.TryLock() {
			f.raw.mu.Unlock()
			return false
		}
		return true
	})
	written := make(chan struct{})
	go func() { writeV7(t, f, entry.NodeId, opened.Fh, 8192, []byte("later")); close(written) }()
	unlock()
	if status := <-metadata; status != fuse.OK {
		t.Fatal(status)
	}
	select {
	case <-written:
		t.Fatal("later WRITE completed before sampled metadata physically published")
	case <-time.After(20 * time.Millisecond):
	}
	completeTestReply(t, f.raw, unique, fuse.OK)
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("WRITE did not follow physical metadata reply")
	}
	if attr.Size != 4101 {
		t.Fatalf("metadata sample size=%d want4101", attr.Size)
	}
}

func TestDirectoryMetadataSettlementReleasesAllPinsBeforeIndex(t *testing.T) {
	f := newStrictFixture(t)
	dir, _ := testDirHandle(t, f.raw, metadataPage(f.rpc.item, testItem(8, authoritypb.Attr_REGULAR, 8)))
	unique := f.unique.Add(2)
	if status := f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: dir}, fuse.NewDirEntryList(make([]byte, 4096), 0)); status != fuse.OK {
		t.Fatal(status)
	}
	f.raw.PrepareReplyPayload(unique, 42, 44, nil, nil, 0)
	f.raw.mu.Lock()
	p := f.raw.replyPublications[unique]
	first, second := p.holderAdmission, p.holderAdmissions[0]
	f.raw.mu.Unlock()
	m := f.mount.delegations
	// Epoch reset holds this writer while joining each inode's readers. Hold
	// it deterministically to prove settlement unlocks the entire page before
	// its first releaseState tries to re-enter the index.
	m.mu.Lock()
	settled := make(chan struct{})
	go func() { completeTestReply(t, f.raw, unique, fuse.OK); close(settled) }()
	unlocked := make(chan struct{})
	go func() {
		first.admission.Lock()
		first.admission.Unlock()
		second.admission.Lock()
		second.admission.Unlock()
		close(unlocked)
	}()
	select {
	case <-unlocked:
	case <-time.After(time.Second):
		m.mu.Unlock()
		t.Fatal("physical settlement waited for index while retaining another inode pin")
	}
	m.mu.Unlock()
	select {
	case <-settled:
	case <-time.After(time.Second):
		t.Fatal("physical settlement did not complete")
	}
}

func TestDirectoryMetadataRefetchReleasesAllIdentityPins(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "index.lock")
	opened := openV7Writer(t, f, entry.NodeId)
	writeV7(t, f, entry.NodeId, opened.Fh, 4096, []byte("dirty"))
	unique := f.unique.Add(2)
	ctx, finish, status := f.raw.mutationContext(unique)
	if status != fuse.OK {
		t.Fatal(status)
	}
	item := testItem(8, authoritypb.Attr_REGULAR, 8)
	second, errno := f.raw.intern(ctx, item)
	if errno != 0 {
		t.Fatal(errno)
	}
	if err := f.mount.delegations.Install(item.StableIdentity, item.Token, testToken(108), delegationTestGrant(48, authoritypb.DelegationMode_DELEGATION_MODE_FULL)); err != nil {
		t.Fatal(err)
	}
	delayed := installMetadataDelay(f, func(request *authoritypb.Request) bool { return request.GetGetAttr() != nil })
	delayed.transform = func(request *authoritypb.Request, response *authoritypb.Response) {
		if string(request.GetGetAttr().GetItem()) == string(item.Token) {
			response.GetGetAttr().Attr = cloneItem(item).Attr
		}
	}
	first := f.raw.nodesByID[entry.NodeId]
	candidates := []dirPlusCandidate{
		{record: first, item: cloneItem(first.node.item), entry: &fuse.EntryOut{}},
		{record: second, item: item, entry: &fuse.EntryOut{}},
	}
	result := make(chan error, 1)
	go func() { result <- f.raw.publishDirectoryMetadata(ctx, candidates) }()
	select {
	case <-delayed.started:
	case <-time.After(time.Second):
		t.Fatal("ownership change did not refetch")
	}
	// A peer read set can require A's recall before serving the B refetch.
	// Prove that A's clean release does not depend on this page's reply.
	released := make(chan error, 1)
	go func() { released <- f.mount.delegations.ReleaseBatch(t.Context(), [][]byte{testIdentity(7)}) }()
	select {
	case err := <-released:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(delayed.resume)
		t.Fatal("GETATTR refetch retained another row's physical pin")
	}
	applyMetadataTestStorage(f, 4101, 2)
	close(delayed.resume)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	finish()
	completeTestReply(t, f.raw, unique, fuse.OK)
	if candidates[0].entry.Attr.Size != 4101 || f.mount.delegations.LossSequence() != 0 {
		t.Fatalf("page size=%d loss=%d", candidates[0].entry.Attr.Size, f.mount.delegations.LossSequence())
	}
}
