//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

func dataGrant(identity []byte, epoch, issued uint64) *authoritypb.LeaseGrant {
	return &authoritypb.LeaseGrant{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, Identity: identity},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, Epoch: epoch,
		ValidForNanos: uint64(volumeserver.Protocol6MaxLeaseTTL), IssuedSequence: issued,
	}
}

func dataRecall(identity []byte, grantEpoch, revokeEpoch uint64) *authoritypb.LeaseRecall {
	return &authoritypb.LeaseRecall{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, Identity: identity},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, GrantEpoch: grantEpoch, RevokeEpoch: revokeEpoch,
	}
}

func nameGrant(parent []byte, name string, epoch, issued uint64) *authoritypb.LeaseGrant {
	return &authoritypb.LeaseGrant{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_NAME, ParentIdentity: parent, Name: []byte(name)},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ, Epoch: epoch, ValidForNanos: uint64(volumeserver.Protocol6MaxLeaseTTL), IssuedSequence: issued,
	}
}

func attrGrant(identity []byte, epoch, issued uint64) *authoritypb.LeaseGrant {
	return &authoritypb.LeaseGrant{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, Identity: identity},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ, Epoch: epoch, ValidForNanos: uint64(volumeserver.Protocol6MaxLeaseTTL), IssuedSequence: issued,
	}
}

func enumerationGrant(identity []byte, epoch, issued uint64) *authoritypb.LeaseGrant {
	return &authoritypb.LeaseGrant{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION, Identity: identity},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_ENUMERATION_READ, Epoch: epoch, ValidForNanos: uint64(volumeserver.Protocol6MaxLeaseTTL), IssuedSequence: issued,
	}
}

func TestWireLeaseHorizonIsNotKernelCacheLifetime(t *testing.T) {
	registry := newLeaseRegistry(nil)
	started := time.Now()
	identity := testIdentity(66)
	grants, err := validateLeaseGrants([]*authoritypb.LeaseGrant{dataGrant(identity, 1, 1)}, started)
	if err != nil {
		t.Fatal(err)
	}
	accepted := registry.install(grants, started)
	if len(accepted) != 1 {
		t.Fatalf("accepted grants = %d, want 1", len(accepted))
	}
	wantCacheDeadline := started.Add(volumeserver.Protocol6MaxLeaseTTL - volumeserver.Protocol6LeaseWithdrawalBudget)
	if !accepted[0].cacheDeadline.Equal(wantCacheDeadline) {
		t.Fatalf("cache deadline = %v, want %v", accepted[0].cacheDeadline, wantCacheDeadline)
	}
	publication := &replyPublication{leaseGrants: accepted}
	if got, want := publication.leaseRemaining(authoritypb.LeaseFamily_LEASE_FAMILY_DATA, authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ,
		publicationIdentity(identity), publicationIdentity{}, "", started), volumeserver.Protocol6MaxLeaseTTL-volumeserver.Protocol6LeaseWithdrawalBudget; got != want {
		t.Fatalf("reply cache lifetime = %v, want %v", got, want)
	}
	tooLong := dataGrant(identity, 2, 2)
	tooLong.ValidForNanos = uint64(volumeserver.Protocol6MaxLeaseTTL + time.Nanosecond)
	if _, err := validateLeaseGrants([]*authoritypb.LeaseGrant{tooLong}, started); err == nil {
		t.Fatal("grant beyond the frozen authority horizon was accepted")
	}
}

func TestRenewalSelectionIsFrameBounded(t *testing.T) {
	registry := newLeaseRegistry(nil)
	now := time.Now()
	parent := publicationIdentity(testIdentity(65))
	total := maxLeaseRenewalBatch + 37
	registry.mu.Lock()
	for index := 0; index < total; index++ {
		key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_NAME, parent: parent, name: fmt.Sprintf("renew-%d", index)}
		registry.leases[key] = &heldLease{grant: validatedLeaseGrant{
			family: key.family, right: authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ, parent: parent, name: key.name,
			epoch: uint64(index + 1), issuedSequence: 1, deadline: now.Add(time.Minute), cacheDeadline: now.Add(time.Minute - time.Second),
		}, refreshAt: now.Add(-time.Second), purgeAt: now.Add(time.Minute - time.Second)}
	}
	registry.mu.Unlock()
	first := registry.dueRenewals(now, maxLeaseRenewalBatch)
	if len(first) != maxLeaseRenewalBatch {
		t.Fatalf("first renewal frame = %d, want %d", len(first), maxLeaseRenewalBatch)
	}
	second := registry.dueRenewals(now, maxLeaseRenewalBatch)
	if len(second) != total-maxLeaseRenewalBatch {
		t.Fatalf("second renewal frame = %d, want %d", len(second), total-maxLeaseRenewalBatch)
	}
	registry.mu.Lock()
	renewing := 0
	for _, lease := range registry.leases {
		if lease.renewing {
			renewing++
		}
	}
	registry.mu.Unlock()
	if renewing != total {
		t.Fatalf("marked renewing = %d, want exactly the %d submitted tokens", renewing, total)
	}
}

func TestLeaseHorizonWatchdogSurvivesSharedMountCancellation(t *testing.T) {
	fixture := newStrictFixture(t)
	now := time.Now()
	horizon := now.Add(1200 * time.Millisecond)
	identity := publicationIdentity(testIdentity(64))
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: identity}
	record, errno := fixture.raw.intern(context.Background(), testItem(64, authoritypb.Attr_REGULAR, 64))
	if errno != 0 {
		t.Fatal(errno)
	}
	fixture.raw.mu.Lock()
	fixture.raw.cachedData[record.key.inode] = record
	fixture.raw.mu.Unlock()
	fixture.notify.inodeST = fuse.EIO
	fixture.mount.leases.mu.Lock()
	fixture.mount.leases.leases[key] = &heldLease{grant: validatedLeaseGrant{
		family: key.family, right: authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, identity: identity,
		epoch: 1, issuedSequence: 1, deadline: horizon, cacheDeadline: now.Add(-time.Second),
	}, purgeAt: now.Add(-time.Second)}
	fixture.mount.leases.leaseCounts[key.family] = 1
	fixture.mount.leases.mu.Unlock()
	directAbort := make(chan time.Time, 1)
	fixture.mount.kernelMount = kernelMount{device: "0:57", point: t.TempDir()}
	fixture.mount.leaseHorizonAbort = func(kernelMount) error {
		directAbort <- time.Now()
		return nil
	}
	teardownBlocked := make(chan struct{})
	fixture.mount.withdrawal = kernelWithdrawal{
		detach: func(string) error { <-teardownBlocked; return nil },
		abort:  func(kernelMount) error { return nil },
		absent: func(kernelMount) (MountAbsenceProof, error) {
			return MountAbsenceProof{ObservedUnixNanos: 1, Observation: []byte("absent"), Component: mountInfoPath}, nil
		},
		sleep: time.Sleep,
	}

	// The cache-deadline invalidation returns EIO and cancels the ordinary
	// mount context while terminal detach is deliberately stalled. The safety
	// watchdog must retain an independent lifetime and invoke fusectl before H.
	fixture.mount.wg.Add(3)
	go fixture.mount.runLeaseMaintenance(fixture.mount.ctx)
	go fixture.mount.runLeaseExpiry(fixture.mount.ctx)
	go fixture.mount.runLeaseHardWatchdog(fixture.mount.leaseSafetyCtx)
	select {
	case <-fixture.mount.ctx.Done():
	case <-time.After(time.Second):
		close(teardownBlocked)
		t.Fatal("failed lease purge did not terminalize the ordinary mount lane")
	}
	select {
	case invoked := <-directAbort:
		if !invoked.Before(horizon) {
			close(teardownBlocked)
			t.Fatalf("direct abort at %v, not before authority horizon %v", invoked, horizon)
		}
	case <-time.After(time.Second):
		close(teardownBlocked)
		t.Fatal("shared mount cancellation suppressed the lease-horizon direct abort")
	}
	close(teardownBlocked)
	fixture.mount.wg.Wait()
}

func TestLeaseCompleteValidatesExactPostStateBeforeDischarge(t *testing.T) {
	valid := exactTestPostState(9, struct {
		item  *authoritypb.Item
		roles uint32
	}{item: testItem(69, authoritypb.Attr_REGULAR, 69), roles: postStateRoleTarget})
	if err := validateLeaseCompletePostState(nil); err != nil {
		t.Fatalf("nil abort/no-change post-state: %v", err)
	}
	if err := validateLeaseCompletePostState(valid); err != nil {
		t.Fatalf("valid post-state: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*authoritypb.PostState)
	}{
		{name: "object", mutate: func(state *authoritypb.PostState) { state.Objects[0].StableIdentity = []byte("short") }},
		{name: "version", mutate: func(state *authoritypb.PostState) { state.Objects[0].ObjectVersion = 0 }},
		{name: "role", mutate: func(state *authoritypb.PostState) { state.Objects[0].Roles = 1 << 31 }},
		{name: "cut", mutate: func(state *authoritypb.PostState) { state.SnapshotSequence++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := proto.Clone(valid).(*authoritypb.PostState)
			test.mutate(state)
			if err := validateLeaseCompletePostState(state); err == nil {
				t.Fatal("malformed peer COMPLETE post-state was accepted")
			}
		})
	}
}

func TestStockWriteTreatsTheAppendFlagAsPlacementNotRefusal(t *testing.T) {
	fixture := newStrictFixture(t)
	// The flag states where the bytes belong, so the request proceeds to ordinary
	// handle validation instead of being short-circuited.
	written, status := fixture.raw.writeStock(&fuse.WriteIn{Flags: uint32(syscall.O_APPEND)}, nil)
	if written != 0 || status != fuse.EBADF {
		t.Fatalf("append FUSE_WRITE on no handle = (%d, %v), want EBADF", written, status)
	}
}

func TestLeaseRecallRejectsOlderGrantGeneration(t *testing.T) {
	fixture := newStrictFixture(t)
	now := time.Now()
	identityA, identityB := testIdentity(70), testIdentity(71)
	initial, err := validateLeaseGrants([]*authoritypb.LeaseGrant{
		dataGrant(identityA, 1, 5), dataGrant(identityB, 2, 5),
	}, now)
	if err != nil || len(fixture.mount.leases.install(initial, now)) != 2 {
		t.Fatalf("install initial grants = %v", err)
	}
	recall := &authoritypb.LeaseRecall{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, Identity: identityA},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, GrantEpoch: 1, RevokeEpoch: 3,
	}
	if _, err := fixture.mount.leases.beginRecalls(context.Background(), 6, []*authoritypb.LeaseRecall{recall}); err != nil {
		t.Fatalf("begin recall: %v", err)
	}
	late, err := validateLeaseGrants([]*authoritypb.LeaseGrant{
		dataGrant(identityA, 1, 5), dataGrant(identityB, 4, 6),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	accepted := fixture.mount.leases.install(late, now)
	if len(accepted) != 1 || accepted[0].identity != publicationIdentity(identityB) {
		t.Fatalf("accepted reordered grants = %+v, want only post-recall B", accepted)
	}
	if got := fixture.mount.leases.remaining(leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: publicationIdentity(identityA)}, authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, now); got != 0 {
		t.Fatalf("recalled A remaining = %v", got)
	}
	if got := fixture.mount.leases.remaining(leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: publicationIdentity(identityB)}, authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, now); got <= 0 {
		t.Fatalf("disjoint B remaining = %v", got)
	}
}

func TestSuccessorDataEpochWaitsForOldPagesToPurge(t *testing.T) {
	fixture := newStrictFixture(t)
	record, errno := fixture.raw.intern(context.Background(), testItem(68, authoritypb.Attr_REGULAR, 68))
	if errno != 0 {
		t.Fatal(errno)
	}
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: record.identity}
	now := time.Now()
	oldGrant, err := validateLeaseGrants([]*authoritypb.LeaseGrant{dataGrant(record.identity[:], 1, 1)}, now)
	if err != nil || len(fixture.mount.leases.install(oldGrant, now)) != 1 {
		t.Fatalf("install old D epoch: %v", err)
	}
	fixture.raw.mu.Lock()
	fixture.raw.cachedData[record.key.inode] = record
	fixture.raw.mu.Unlock()
	successor, err := validateLeaseGrants([]*authoritypb.LeaseGrant{dataGrant(record.identity[:], 2, 2)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if accepted := fixture.mount.leases.install(successor, now); len(accepted) != 0 {
		t.Fatalf("successor D epoch borrowed old cached pages: %+v", accepted)
	}
	fixture.mount.leases.mu.Lock()
	heldEpoch := fixture.mount.leases.leases[key].grant.epoch
	fixture.mount.leases.mu.Unlock()
	if heldEpoch != 1 {
		t.Fatalf("held D epoch = %d, want old epoch 1 until purge", heldEpoch)
	}
	if err := fixture.mount.leases.expire(key); err != nil {
		t.Fatal(err)
	}
	if accepted := fixture.mount.leases.install(successor, now); len(accepted) != 1 {
		t.Fatalf("successor D epoch rejected after purge: %+v", accepted)
	}
}

func TestEnumerationPagesCannotBorrowSuccessorEpoch(t *testing.T) {
	fixture := newStrictFixture(t)
	record, errno := fixture.raw.intern(context.Background(), testItem(67, authoritypb.Attr_DIRECTORY, 67))
	if errno != 0 {
		t.Fatal(errno)
	}
	fixture.rpc.root = cloneItem(record.node.item)
	fixture.rpc.leaseEpoch, fixture.rpc.leaseIssued = 2, 2
	newPage := testDirPage(1, true, func(int) []byte { return encodeCookie(1) })
	newPage.Entries[0].Name = []byte("new")
	fixture.rpc.dirPages = []*authoritypb.ReadDirReply{newPage, newPage}
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION, identity: record.identity}
	now := time.Now()
	oldGrant, err := validateLeaseGrants([]*authoritypb.LeaseGrant{enumerationGrant(record.identity[:], 1, 1)}, now)
	if err != nil || len(fixture.mount.leases.install(oldGrant, now)) != 1 {
		t.Fatalf("install old E epoch: %v", err)
	}
	oldPage := testDirPage(1, true, func(int) []byte { return encodeCookie(1) })
	handles := []*dirHandle{
		{node: record.node, token: testToken(200), page: oldPage.Entries, index: len(oldPage.Entries), eof: true, verifier: testToken(5), pageLease: leaseStamp{epoch: 1, issuedSequence: 1}},
		{node: record.node, token: testToken(201), page: oldPage.Entries, pageLease: leaseStamp{epoch: 1, issuedSequence: 1}},
	}
	// Model the dangerous ordering directly: registry ownership moved to a new
	// epoch before two userspace continuations were touched. The per-page stamp
	// must still reject both old payloads.
	fixture.mount.leases.mu.Lock()
	fixture.mount.leases.deleteLeaseLocked(key)
	fixture.mount.leases.mu.Unlock()
	newGrant, err := validateLeaseGrants([]*authoritypb.LeaseGrant{enumerationGrant(record.identity[:], 2, 2)}, now)
	if err != nil || len(fixture.mount.leases.install(newGrant, now)) != 1 {
		t.Fatalf("install successor E epoch: %v", err)
	}
	for _, handle := range handles {
		ctx, finish := testMutationContext(t, fixture.mount)
		entry, _, gotErrno := handle.peek(ctx, false)
		finish(gotErrno == 0)
		if gotErrno != 0 || entry == nil || entry.Name != "new" {
			t.Fatalf("old E page survived successor epoch: entry=%v errno=%v", entry, gotErrno)
		}
		if handle.pageLease.epoch != 2 {
			t.Fatalf("refetched page epoch = %d, want 2", handle.pageLease.epoch)
		}
	}
}

func TestEnumerationRecallDoesNotLeakTransientError(t *testing.T) {
	fixture := newStrictFixture(t)
	record, errno := fixture.raw.intern(context.Background(), testItem(63, authoritypb.Attr_DIRECTORY, 63))
	if errno != 0 {
		t.Fatal(errno)
	}
	fixture.rpc.root = cloneItem(record.node.item)
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION, identity: record.identity}
	now := time.Now()
	oldGrant, err := validateLeaseGrants([]*authoritypb.LeaseGrant{enumerationGrant(record.identity[:], 1, 1)}, now)
	if err != nil || len(fixture.mount.leases.install(oldGrant, now)) != 1 {
		t.Fatalf("install old E epoch: %v", err)
	}
	oldPage := testDirPage(1, false, func(int) []byte { return encodeCookie(1) })
	newPage := testDirPage(1, true, func(int) []byte { return encodeCookie(2) })
	newPage.Entries[0].Name = []byte("fresh")
	fixture.rpc.dirPages = []*authoritypb.ReadDirReply{oldPage, newPage}
	handle := &dirHandle{
		node: record.node, token: testToken(202), page: oldPage.Entries, index: len(oldPage.Entries),
		cookie: encodeCookie(1), verifier: testToken(5), pageLease: leaseStamp{epoch: 1, issuedSequence: 1},
	}
	if _, ok := fixture.raw.addHandle(record, &handleRecord{dir: handle}); !ok {
		t.Fatal("register directory handle")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var requests atomic.Int32
	fixture.rpc.hook = func(request *authoritypb.Request) {
		if request.GetReadDir() != nil && requests.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	type result struct {
		entry *fuse.DirEntry
		errno syscall.Errno
	}
	resultCh := make(chan result, 1)
	go func() {
		ctx, finish := testMutationContext(t, fixture.mount)
		entry, _, gotErrno := handle.peek(ctx, false)
		finish(gotErrno == 0)
		resultCh <- result{entry: entry, errno: gotErrno}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("READDIR did not enter authority RPC")
	}
	if err := fixture.mount.leases.expire(key); err != nil {
		t.Fatalf("expire E while READDIR blocked: %v", err)
	}
	fixture.rpc.mu.Lock()
	fixture.rpc.leaseEpoch, fixture.rpc.leaseIssued = 2, 2
	fixture.rpc.mu.Unlock()
	close(release)
	select {
	case got := <-resultCh:
		if got.errno != 0 || got.entry == nil || got.entry.Name != "fresh" {
			t.Fatalf("READDIR recall leaked result/error: entry=%v errno=%v", got.entry, got.errno)
		}
	case <-time.After(time.Second):
		t.Fatal("READDIR did not retry after E purge")
	}
}

func TestSourceRenameNeverMovesCoordinateBoundNamePayloads(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		t.Run(fmt.Sprintf("exchange=%t", exchange), func(t *testing.T) {
			fixture := newStrictFixture(t)
			oldParent := fixture.raw.acquire(fuse.FUSE_ROOT_ID)
			if oldParent == nil {
				t.Fatal("root")
			}
			defer fixture.raw.release(oldParent)
			newParent, errno := fixture.raw.intern(context.Background(), testItem(66, authoritypb.Attr_DIRECTORY, 66))
			if errno != 0 {
				t.Fatal(errno)
			}
			moved, errno := fixture.raw.intern(context.Background(), testItem(65, authoritypb.Attr_REGULAR, 65))
			if errno != 0 {
				t.Fatal(errno)
			}
			replaced, errno := fixture.raw.intern(context.Background(), testItem(64, authoritypb.Attr_REGULAR, 64))
			if errno != 0 {
				t.Fatal(errno)
			}
			from := nameKey{parent: oldParent.key.inode, name: "old"}
			to := nameKey{parent: newParent.key.inode, name: "new"}
			fixture.raw.mu.Lock()
			fixture.raw.bindCachedNameLocked(from, publicationNamespace{parent: oldParent.identity, name: "old"}, moved, leaseStamp{epoch: 1, issuedSequence: 1})
			fixture.raw.bindCachedNameLocked(to, publicationNamespace{parent: newParent.identity, name: "new"}, replaced, leaseStamp{epoch: 2, issuedSequence: 1})
			fixture.raw.mu.Unlock()
			fixture.raw.moveSelf(oldParent, "old", newParent, "new", exchange)
			fixture.raw.mu.Lock()
			_, fromPayload := fixture.raw.cachedNames[from]
			_, toPayload := fixture.raw.cachedNames[to]
			_, fromStamp := fixture.raw.cachedNameLeases[from]
			_, toStamp := fixture.raw.cachedNameLeases[to]
			fixture.raw.mu.Unlock()
			if fromPayload || toPayload || fromStamp || toStamp {
				t.Fatalf("rename transplanted coordinate-bound payload: from=(%t,%t) to=(%t,%t)", fromPayload, fromStamp, toPayload, toStamp)
			}
		})
	}
}

func TestReplyLeaseCannotBorrowLaterRegistryGrant(t *testing.T) {
	identity := publicationIdentity(testIdentity(72))
	publication := &replyPublication{leaseGrants: []validatedLeaseGrant{{
		family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, right: authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ,
		identity: identity, epoch: 1, issuedSequence: 1, deadline: time.Now().Add(-time.Second),
	}}}
	fixture := newStrictFixture(t)
	now := time.Now()
	newer, err := validateLeaseGrants([]*authoritypb.LeaseGrant{dataGrant(identity[:], 2, 2)}, now)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mount.leases.install(newer, now)
	if got := publication.leaseRemaining(authoritypb.LeaseFamily_LEASE_FAMILY_DATA, authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, identity, publicationIdentity{}, "", now); got != 0 {
		t.Fatalf("expired reply-local grant borrowed a later registry grant: %v", got)
	}
}

func TestRecallDrainsFinalizedInstallingReplies(t *testing.T) {
	identity := publicationIdentity(testIdentity(73))
	parent := publicationIdentity(testIdentity(74))
	for _, test := range []struct {
		name        string
		coordinate  publicationCoordinate
		publication func(publicationCoordinate, chan struct{}) *replyPublication
	}{
		{name: "name", coordinate: publicationCoordinate{kind: publicationNamespaceName, parent: parent, name: "x"}, publication: func(coordinate publicationCoordinate, done chan struct{}) *replyPublication {
			return &replyPublication{names: []replyNamePublication{{coordinate: coordinate}}, originalFinalized: true, originalDone: done}
		}},
		{name: "attributes", coordinate: publicationCoordinate{kind: publicationItemAttributes, item: identity}, publication: func(coordinate publicationCoordinate, done chan struct{}) *replyPublication {
			return &replyPublication{attrs: []replyAttrPublication{{identity: identity, coordinate: coordinate}}, originalFinalized: true, originalDone: done}
		}},
		{name: "data", coordinate: publicationCoordinate{kind: publicationItemData, item: identity}, publication: func(coordinate publicationCoordinate, done chan struct{}) *replyPublication {
			return &replyPublication{data: []replyDataPublication{{record: &inodeRecord{identity: identity}, coordinate: coordinate}}, originalFinalized: true, originalDone: done}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStrictFixture(t)
			done := make(chan struct{})
			fixture.raw.mu.Lock()
			fixture.raw.replyPublications[41] = test.publication(test.coordinate, done)
			fixture.raw.mu.Unlock()
			closed := make(chan error, 1)
			go func() { closed <- fixture.raw.closeLeaseCoordinate(context.Background(), test.coordinate) }()
			select {
			case err := <-closed:
				t.Fatalf("recall did not drain finalized writer: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			close(done)
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("recall did not finish after physical writer edge")
			}
		})
	}
}

func TestEnumerationInvalidationDropsEveryBufferedHandle(t *testing.T) {
	frontend, _, rpc := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(74, authoritypb.Attr_DIRECTORY, 74))
	if errno != 0 {
		t.Fatal(errno)
	}
	rpc.root = cloneItem(record.node.item)
	first := testDirPage(3, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })
	second := testDirPage(2, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })
	second.Entries[0].Name = []byte("x")
	rpc.dirPages = []*authoritypb.ReadDirReply{first, first, second, second}
	handles := []*dirHandle{{node: record.node, token: testToken(100)}, {node: record.node, token: testToken(101)}}
	for _, handle := range handles {
		ctx, finish := testMutationContext(t, frontend.mount)
		entry, _, errno := handle.peek(ctx, false)
		finish(errno == 0)
		if errno != 0 || entry.Name != "a" {
			t.Fatalf("prime enumeration = (%v, %v)", entry, errno)
		}
		handle.consume()
	}
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION, identity: record.identity}
	for _, handle := range handles {
		id, ok := frontend.addHandle(record, &handleRecord{dir: handle})
		if !ok || id == 0 {
			t.Fatal("register dir handle")
		}
	}
	if err := frontend.invalidateLease(key); err != nil {
		t.Fatal(err)
	}
	for _, handle := range handles {
		ctx, finish := testMutationContext(t, frontend.mount)
		entry, _, errno := handle.peek(ctx, false)
		finish(errno == 0)
		if errno != 0 || entry == nil || entry.Name != "x" {
			t.Fatalf("post-recall enumeration = (%v, %v), want restarted x", entry, errno)
		}
	}
}

func TestSourceGrantFloorAllowsDisjointReverseCompletion(t *testing.T) {
	registry := newLeaseRegistry(nil)
	keyA := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: publicationIdentity(testIdentity(80))}
	keyB := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: publicationIdentity(testIdentity(81))}
	if err := registry.mergeSourceTombstones(9, map[leaseKey]uint64{keyA: 2}); err != nil {
		t.Fatal(err)
	}
	if err := registry.mergeSourceTombstones(7, map[leaseKey]uint64{keyB: 3}); err != nil {
		t.Fatalf("disjoint lower source sequence was rejected: %v", err)
	}
	if registry.grantFloor != 9 {
		t.Fatalf("source grant floor = %d, want 9", registry.grantFloor)
	}
}

func TestRecallSequencesAllowDisjointOvertake(t *testing.T) {
	fixture := newStrictFixture(t)
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: publicationIdentity(testIdentity(82))}
	if err := fixture.mount.leases.mergeSourceTombstones(12, map[leaseKey]uint64{key: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.mount.leases.beginRecalls(context.Background(), 11, nil); err != nil {
		t.Fatalf("source sequence incorrectly rejected disjoint CONTROL: %v", err)
	}
	if _, err := fixture.mount.leases.beginRecalls(context.Background(), 12, nil); err != nil {
		t.Fatalf("deliver overtaking CONTROL 12: %v", err)
	}
	if _, err := fixture.mount.leases.beginRecalls(context.Background(), 11, nil); err != nil {
		t.Fatalf("later delivery of disjoint CONTROL 11 was rejected: %v", err)
	}
	if _, err := fixture.mount.leases.beginRecalls(context.Background(), 0, nil); err == nil {
		t.Fatal("zero CONTROL sequence was accepted")
	}
}

func TestUnrelatedHighEpochDoesNotRejectFreshCoordinate(t *testing.T) {
	fixture := newStrictFixture(t)
	fixture.mount.leases.mu.Lock()
	fixture.mount.leases.grantFloor = 7
	fixture.mount.leases.mu.Unlock()
	now := time.Now()
	accepted := fixture.mount.leases.install([]validatedLeaseGrant{{
		family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA,
		right:  authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, identity: publicationIdentity(testIdentity(84)),
		epoch: 1, issuedSequence: 7, deadline: now.Add(time.Minute),
	}}, now)
	if len(accepted) != 1 {
		t.Fatalf("fresh coordinate with low epoch rejected: %+v", accepted)
	}
}

func TestLeaseRegistryBoundsUniqueNameChurn(t *testing.T) {
	fixture := newStrictFixture(t)
	now := time.Now()
	parent := publicationIdentity(testIdentity(83))
	for index := 0; index < fixture.mount.leases.maxPerFamily*3; index++ {
		fixture.mount.leases.install([]validatedLeaseGrant{{
			family: authoritypb.LeaseFamily_LEASE_FAMILY_NAME,
			right:  authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ,
			parent: parent, name: fmt.Sprintf("entry-%d", index),
			epoch: uint64(index + 1), issuedSequence: 1, deadline: now.Add(time.Minute),
		}}, now)
	}
	fixture.mount.leases.mu.Lock()
	count := fixture.mount.leases.leaseCounts[authoritypb.LeaseFamily_LEASE_FAMILY_NAME]
	entries := len(fixture.mount.leases.leases)
	fixture.mount.leases.mu.Unlock()
	if count != fixture.mount.leases.maxPerFamily || entries != fixture.mount.leases.maxPerFamily {
		t.Fatalf("name lease registry grew beyond capacity: count=%d entries=%d capacity=%d", count, entries, fixture.mount.leases.maxPerFamily)
	}
}

func TestBufferedHandleRefaultIsTrackedByNextRecall(t *testing.T) {
	fixture := newStrictFixture(t)
	item := testItem(85, authoritypb.Attr_REGULAR, 85)
	fixture.rpc.item = item
	fixture.rpc.byName = map[string]*authoritypb.Item{"file": item}
	fixture.rpc.fileData = []byte("data")
	entry := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file")
	opened := fixture.openForData(t, entry.NodeId)

	read := func() {
		unique := fixture.unique.Add(2)
		result, status := fixture.raw.Read(nil, &fuse.ReadIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 4,
		}, make([]byte, 4))
		if !status.Ok() || result == nil || result.Size() != 4 {
			t.Fatalf("buffered READ = (%v, %v)", result, status)
		}
		size, replyStatus, prepareStatus := fixture.raw.PrepareReplyPayload(unique, entry.NodeId, 15, nil, make([]byte, result.Size()), result.Size())
		if !prepareStatus.Ok() || !replyStatus.Ok() || size != result.Size() {
			t.Fatalf("prepare buffered READ = (%d, %v, %v)", size, replyStatus, prepareStatus)
		}
		fixture.raw.ReplyWritten(unique, fuse.OK)
	}
	recall := func(sequence, grantEpoch, revokeEpoch uint64) {
		recalls := []*authoritypb.LeaseRecall{dataRecall(item.GetStableIdentity(), grantEpoch, revokeEpoch)}
		if _, err := fixture.mount.leases.beginRecalls(context.Background(), sequence, recalls); err != nil {
			t.Fatalf("begin D recall: %v", err)
		}
		if _, err := fixture.mount.leases.completeRecalls(recalls); err != nil {
			t.Fatalf("complete D recall: %v", err)
		}
		fixture.mount.leases.finishRecalls(recalls)
	}

	read()
	recall(2, 1, 2)
	fixture.rpc.mu.Lock()
	fixture.rpc.leaseEpoch, fixture.rpc.leaseIssued = 3, 2
	fixture.rpc.mu.Unlock()
	read()
	recall(3, 3, 4)

	withdrawals := 0
	for _, call := range fixture.notify.snapshot() {
		if call.kind == "inode" && call.inode == entry.NodeId && call.off == 0 && call.length == 0 {
			withdrawals++
		}
	}
	if withdrawals != 2 {
		t.Fatalf("buffered refault withdrawals = %d, want 2", withdrawals)
	}
}

func TestExpiredEnumerationPageIsNotServedAfterResume(t *testing.T) {
	frontend, _, rpc := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(86, authoritypb.Attr_DIRECTORY, 86))
	if errno != 0 {
		t.Fatal(errno)
	}
	rpc.root = cloneItem(record.node.item)
	first := testDirPage(3, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })
	second := testDirPage(1, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })
	second.Entries[0].Name = []byte("fresh")
	rpc.dirPages = []*authoritypb.ReadDirReply{first, second}
	handle := &dirHandle{node: record.node, token: testToken(110)}
	ctx, finish := testMutationContext(t, frontend.mount)
	entry, _, errno := handle.peek(ctx, false)
	finish(errno == 0)
	if errno != 0 || entry.Name != "a" {
		t.Fatalf("prime enumeration = (%v, %v)", entry, errno)
	}
	handle.consume()
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION, identity: record.identity}
	frontend.mount.leases.mu.Lock()
	frontend.mount.leases.leases[key].purgeAt = time.Now().Add(-time.Second)
	frontend.mount.leases.mu.Unlock()
	ctx, finish = testMutationContext(t, frontend.mount)
	entry, _, errno = handle.peek(ctx, false)
	finish(errno == 0)
	if errno != 0 || entry == nil || entry.Name != "fresh" {
		t.Fatalf("expired buffered page resumed stale data: (%v, %v)", entry, errno)
	}
}

// TestEnumerationPageWithoutGrantIsServedUncachedAndRetired pins what an
// enumeration reply that carries no installable E(dir) grant means. It does not
// mean the authority broke the protocol -- §2.2 makes the grant a MAY, and this
// frontend independently declines grants a newer recall's floor, an unfinished
// local recall, or the family's cache budget has taken out from under it. It
// means exactly one thing: the reply is uncached.
//
// So the page is served, and it is bounded to the kernel callback that fetched
// it: the next callback retires the buffer and refetches from the authority
// cookie rather than resuming a page nothing is obliged to withdraw. The second
// page below is what proves the refetch happened; that the refetch skips and
// duplicates no name against a real authority is
// TestPagedReaddirRefusesToPageAcrossARemoteMutation's and the tree-install
// test's job.
func TestEnumerationPageWithoutGrantIsServedUncachedAndRetired(t *testing.T) {
	frontend, _, rpc := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(96, authoritypb.Attr_DIRECTORY, 96))
	if errno != 0 {
		t.Fatal(errno)
	}
	rpc.root = cloneItem(record.node.item)
	first := testDirPage(2, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })
	second := testDirPage(1, true, func(index int) []byte { return encodeCookie(uint64(index + 2)) })
	second.Entries[0].Name = []byte("refetched")
	fetches := 0
	// Every READDIR this handle issues is recorded with the position it asked
	// for. An earlier version of this test ignored the cookie and answered the
	// second fetch with the second page no matter what was requested, which made
	// it pass while the stream was in fact restarting from the beginning and
	// re-delivering the entries the kernel already had. The request is the
	// evidence, so it is what gets asserted.
	var requestedCookies [][]byte
	var requestedVerifiers [][]byte
	rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetReadDir() == nil {
			return &authoritypb.Response{}, nil
		}
		requestedCookies = append(requestedCookies, cloneBytes(request.GetReadDir().GetCookie()))
		requestedVerifiers = append(requestedVerifiers, cloneBytes(request.GetReadDir().GetVerifier()))
		page := first
		if fetches > 0 {
			page = second
		}
		fetches++
		return &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: proto.Clone(page).(*authoritypb.ReadDirReply)}}, nil
	}
	handle := &dirHandle{node: record.node, token: testToken(112)}
	ctx, finish := testMutationContext(t, frontend.mount)
	entry, _, errno := handle.peek(ctx, false)
	finish(errno == 0)
	if errno != 0 || entry == nil || entry.Name != "a" {
		t.Fatalf("ungranted READDIR = (%v, %v), want the page served", entry, errno)
	}
	if frontend.mount.isRevoked() {
		t.Fatalf("an ungranted enumeration page revoked the mount: %v", frontend.mount.fatalError())
	}
	handle.consume()
	if !handle.uncovered {
		t.Fatal("a page served without an enumeration grant was not marked uncovered")
	}

	// The kernel comes back for the rest of the stream. The buffered second
	// entry of the first page is not what it gets: that page is retired and the
	// authority is asked again from the cookie this handle actually reached.
	ctx, finish = testMutationContext(t, frontend.mount)
	if errno := handle.Seekdir(ctx, entry.Off); errno != 0 {
		finish(false)
		t.Fatalf("resume an uncovered enumeration = %v, want acceptance", errno)
	}
	next, _, errno := handle.peek(ctx, false)
	finish(errno == 0)
	if errno != 0 || next == nil || next.Name != "refetched" {
		t.Fatalf("second callback on an uncovered stream = (%v, %v), want the refetched page", next, errno)
	}
	if fetches != 2 {
		t.Fatalf("authority READDIRs = %d, want 2: the uncovered page was resumed instead of retired", fetches)
	}
	if !handle.uncovered {
		t.Fatal("retiring an uncovered page cleared the stream's uncovered mark, which is what let peek's guard restart it from the beginning")
	}
	// The refetch must ask to continue, not to start over. A zero cookie here is
	// the whole defect: it re-reads the directory from the first entry and hands
	// the kernel a second copy of everything it already accepted.
	if len(requestedCookies) != 2 {
		t.Fatalf("recorded %d READDIR requests, want 2", len(requestedCookies))
	}
	if len(requestedCookies[0]) != 0 {
		t.Fatalf("first READDIR asked for cookie %x, want the start of the stream", requestedCookies[0])
	}
	wantResume := entry.Off
	if got, ok := decodeCookie(requestedCookies[1]); !ok || got != wantResume {
		t.Fatalf("resumed READDIR asked for cookie %x (decoded %d, ok=%t), want the cookie following the entry already delivered (%d): an uncovered stream restarted from the beginning instead of continuing",
			requestedCookies[1], got, ok, wantResume)
	}
	// And it must name the snapshot it is continuing in. Without the verifier
	// the authority has no way to refuse a resume into a directory that moved,
	// which is the only thing making the uncached path exact rather than hopeful.
	if len(requestedVerifiers[1]) == 0 {
		t.Fatal("resumed READDIR carried no verifier, so the authority could not refuse a resume into a changed directory")
	}
	if !bytes.Equal(requestedVerifiers[1], first.GetVerifier()) {
		t.Fatalf("resumed READDIR carried verifier %x, want the one the page it is continuing was produced under (%x)",
			requestedVerifiers[1], first.GetVerifier())
	}
}

// TestEnumerationPageForAnItemWithoutAStableIdentityFailsClosed is the
// enumeration violation that stays terminal, and it must still hand back every
// capability the refused page carried.
func TestEnumerationPageForAnItemWithoutAStableIdentityFailsClosed(t *testing.T) {
	frontend, _, rpc := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(96, authoritypb.Attr_DIRECTORY, 96))
	if errno != 0 {
		t.Fatal(errno)
	}
	record.node.item.StableIdentity = nil
	page := testDirPage(2, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })
	wantReclaims := make([][]byte, len(page.Entries))
	for index, entry := range page.Entries {
		entry.Item = testItem(uint64(200+index), authoritypb.Attr_REGULAR, uint64(200+index))
		wantReclaims[index] = cloneBytes(entry.Item.GetToken())
	}
	rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetReadDir() == nil {
			return &authoritypb.Response{}, nil
		}
		return &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: proto.Clone(page).(*authoritypb.ReadDirReply)}}, nil
	}
	handle := &dirHandle{node: record.node, token: testToken(112)}
	ctx, finish := testMutationContext(t, frontend.mount)
	entry, _, errno := handle.peek(ctx, true)
	finish(false)
	if errno != syscall.ENOTCONN || entry != nil || !frontend.mount.isRevoked() {
		t.Fatalf("READDIR for an item with no stable identity = (%v, %v, revoked=%t), want terminal ENOTCONN", entry, errno, frontend.mount.isRevoked())
	}
	for _, want := range wantReclaims {
		if got := popReclaim(t, frontend.mount); !bytes.Equal(got, want) {
			t.Fatalf("reclaimed READDIR capability = %x, want %x", got, want)
		}
	}
}

func TestEnumerationLeaseExpiryPurgesBufferedPage(t *testing.T) {
	frontend, _, rpc := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(87, authoritypb.Attr_DIRECTORY, 87))
	if errno != 0 {
		t.Fatal(errno)
	}
	rpc.root = cloneItem(record.node.item)
	rpc.dirPages = []*authoritypb.ReadDirReply{testDirPage(3, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })}
	handle := &dirHandle{node: record.node, token: testToken(111)}
	if id, ok := frontend.addHandle(record, &handleRecord{dir: handle}); !ok || id == 0 {
		t.Fatal("register dir handle")
	}
	ctx, finish := testMutationContext(t, frontend.mount)
	_, _, errno = handle.peek(ctx, false)
	finish(errno == 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	handle.consume()
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION, identity: record.identity}
	if err := frontend.mount.leases.expire(key); err != nil {
		t.Fatal(err)
	}
	handle.mu.Lock()
	invalidated := handle.enumerationInvalidated && len(handle.page) == 0 && handle.pending == nil && len(handle.verifier) == 0 && handle.next == 0
	handle.mu.Unlock()
	if !invalidated {
		t.Fatal("E lease expiry left a resumable buffered page")
	}
	frontend.mount.leases.mu.Lock()
	_, live := frontend.mount.leases.leases[key]
	frontend.mount.leases.mu.Unlock()
	if live {
		t.Fatal("expired E lease remained live")
	}
}

func TestLocalExpiryRacingRemoteRecallKeepsGateClosed(t *testing.T) {
	fixture := newStrictFixture(t)
	record, errno := fixture.raw.intern(context.Background(), testItem(88, authoritypb.Attr_REGULAR, 88))
	if errno != 0 {
		t.Fatal(errno)
	}
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: record.identity}
	now := time.Now()
	grants, err := validateLeaseGrants([]*authoritypb.LeaseGrant{dataGrant(record.identity[:], 1, 1)}, now)
	if err != nil || len(fixture.mount.leases.install(grants, now)) != 1 {
		t.Fatalf("install D lease: %v", err)
	}
	fixture.mount.leases.mu.Lock()
	fixture.mount.leases.leases[key].revoking = true
	fixture.mount.leases.mu.Unlock()
	fixture.raw.mu.Lock()
	fixture.raw.cachedData[record.key.inode] = record
	fixture.raw.mu.Unlock()
	started := make(chan struct{})
	release := make(chan struct{})
	fixture.notify.block = release
	fixture.notify.onInode = func(uint64, int64, int64) {
		select {
		case <-started:
		default:
			close(started)
		}
	}
	expired := make(chan error, 1)
	go func() { expired <- fixture.mount.leases.expire(key) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("local expiry did not begin invalidation")
	}
	recalls := []*authoritypb.LeaseRecall{dataRecall(record.identity[:], 1, 2)}
	if _, err := fixture.mount.leases.beginRecalls(context.Background(), 2, recalls); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-expired; err != nil {
		t.Fatal(err)
	}
	coordinate, _ := key.publicationCoordinate()
	fixture.raw.mu.Lock()
	closed := fixture.raw.repairingCoordinates[coordinate]
	fixture.raw.mu.Unlock()
	if !closed {
		t.Fatal("local expiry reopened a coordinate now owned by remote recall")
	}
	if _, err := fixture.mount.leases.completeRecalls(recalls); err != nil {
		t.Fatal(err)
	}
	fixture.mount.leases.finishRecalls(recalls)
}

func TestWithdrawnRenewalExpiresCoordinateWithoutTerminalizingMount(t *testing.T) {
	fixture := newStrictFixture(t)
	record, errno := fixture.raw.intern(context.Background(), testItem(89, authoritypb.Attr_REGULAR, 89))
	if errno != 0 {
		t.Fatal(errno)
	}
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: record.identity}
	now := time.Now()
	grants, err := validateLeaseGrants([]*authoritypb.LeaseGrant{dataGrant(record.identity[:], 1, 1)}, now)
	if err != nil || len(fixture.mount.leases.install(grants, now)) != 1 {
		t.Fatalf("install D lease: %v", err)
	}
	fixture.raw.mu.Lock()
	fixture.raw.cachedData[record.key.inode] = record
	fixture.raw.mu.Unlock()
	withdrawn := &authoritypb.LeaseRenewal{Coordinate: leaseCoordinateFromKey(key), Epoch: 1}
	if err := fixture.mount.leases.expireWithdrawal(withdrawn); err != nil {
		t.Fatal(err)
	}
	if fixture.mount.isRevoked() {
		t.Fatal("ordinary renewal withdrawal terminalized the mount")
	}
	fixture.mount.leases.mu.Lock()
	_, live := fixture.mount.leases.leases[key]
	fixture.mount.leases.mu.Unlock()
	if live || fixture.raw.cachedDataHolds(record.key.inode) {
		t.Fatal("withdrawn renewal left its lease or cached data live")
	}
	// CONTROL can legitimately arrive after the renewal response. The missing-
	// grant recall path must still close and discharge the exact coordinate.
	recalls := []*authoritypb.LeaseRecall{dataRecall(record.identity[:], 1, 2)}
	if _, err := fixture.mount.leases.beginRecalls(context.Background(), 2, recalls); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.mount.leases.completeRecalls(recalls); err != nil {
		t.Fatal(err)
	}
	fixture.mount.leases.finishRecalls(recalls)
}

func TestSourceDischargeAcksWithoutPrivateNameBarrier(t *testing.T) {
	fixture := newStrictFixture(t)
	rootRecord := fixture.raw.acquire(fuse.FUSE_ROOT_ID)
	if rootRecord == nil {
		t.Fatal("root record")
	}
	defer fixture.raw.release(rootRecord)
	gate, err := namespaceSourceGate(rootRecord.node.item, "victim", false)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := fixture.raw.acquireSourcePublication(context.Background(), gate)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.markAssigned(); err != nil {
		t.Fatal(err)
	}
	lease.resolveAllNoBinding()
	if err := lease.markCallbackPublicationReady(); err != nil {
		t.Fatal(err)
	}
	identity := rootRecord.identity
	recall := &authoritypb.LeaseRecall{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_NAME, ParentIdentity: identity[:], Name: []byte("victim")},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ, GrantEpoch: 1, RevokeEpoch: 2,
	}
	attrRecall := &authoritypb.LeaseRecall{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, Identity: identity[:]},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ, GrantEpoch: 3, RevokeEpoch: 4,
	}
	discharge := &authoritypb.SourceLeaseDischarge{Sequence: 9, Recalls: []*authoritypb.LeaseRecall{recall, attrRecall}}
	now := time.Now()
	grants, err := validateLeaseGrants([]*authoritypb.LeaseGrant{
		nameGrant(identity[:], "victim", 1, 1), attrGrant(identity[:], 3, 1),
	}, now)
	if err != nil || len(fixture.mount.leases.install(grants, now)) != 2 {
		t.Fatalf("install source N/A leases: %v", err)
	}
	name := nameKey{parent: rootRecord.key.inode, name: "victim"}
	fixture.raw.mu.Lock()
	fixture.raw.bindCachedNegativeLocked(name, leaseStamp{epoch: 1, issuedSequence: 1})
	fixture.raw.cachedAttrs[identity] = rootRecord
	fixture.raw.cachedAttrPayloads[identity] = cachedAttrPayload{
		lease: leaseStamp{epoch: 3, issuedSequence: 1}, attr: proto.Clone(rootRecord.node.item.GetAttr()).(*authoritypb.Attr),
		objectVersion: 1, snapshot: 1,
	}
	fixture.raw.mu.Unlock()
	publication := &replyPublication{
		source: lease, sourceLeaseDischarge: discharge,
		postState: exactTestPostState(9, struct {
			item  *authoritypb.Item
			roles uint32
		}{item: rootRecord.node.item, roles: postStateRoleTarget}),
	}
	if err := fixture.mount.prepareSourceLeaseDischarge(publication); err != nil {
		t.Fatal(err)
	}
	publication.sourceLeasePrepared = true
	fixture.raw.mu.Lock()
	_, staleNegative := fixture.raw.cachedNegatives[name]
	_, staleAttr := fixture.raw.cachedAttrs[identity]
	fixture.raw.mu.Unlock()
	if staleNegative || staleAttr {
		t.Fatal("source pre-reply purge left daemon N/A payload live")
	}
	unique := fixture.unique.Add(2)
	if err := fixture.raw.registerReplyPublication(unique, publication); err != nil {
		t.Fatal(err)
	}
	fixture.raw.finishReplyPublicationRegistration(unique, publication)
	if _, replyStatus, prepareStatus := fixture.raw.PrepareReplyPayload(unique, fuse.FUSE_ROOT_ID, 10, nil, nil, 0); !replyStatus.Ok() || !prepareStatus.Ok() {
		t.Fatalf("prepare source reply = (%v, %v)", replyStatus, prepareStatus)
	}
	fixture.raw.ReplyWritten(unique, fuse.OK)
	fixture.raw.mu.Lock()
	_, staleAttr = fixture.raw.cachedAttrs[identity]
	_, staleAttrPayload := fixture.raw.cachedAttrPayloads[identity]
	fixture.raw.mu.Unlock()
	fixture.mount.leases.mu.Lock()
	_, staleAttrLease := fixture.mount.leases.leases[leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, identity: identity}]
	fixture.mount.leases.mu.Unlock()
	if staleAttr || staleAttrPayload || staleAttrLease {
		t.Fatal("mutation post-state recreated an A cache obligation without a successor grant")
	}
	fixture.rpc.mu.Lock()
	acks := append([]uint64(nil), fixture.rpc.sourceAcks...)
	fixture.rpc.mu.Unlock()
	if len(acks) != 1 || acks[0] != 9 {
		t.Fatalf("source discharge ACKs = %v, want [9]", acks)
	}
	for _, call := range fixture.notify.snapshot() {
		if call.kind == "entry" {
			t.Fatalf("source discharge used a non-ABI post-write name barrier: %+v", call)
		}
	}
}

func TestSourcePublicationWaitsForOverlappingLeaseRecall(t *testing.T) {
	for _, test := range []struct {
		name       string
		coordinate func(*inodeRecord) publicationCoordinate
	}{
		{name: "exact name", coordinate: func(root *inodeRecord) publicationCoordinate {
			return publicationCoordinate{kind: publicationNamespaceName, parent: root.identity, name: "victim"}
		}},
		{name: "unresolved child attributes", coordinate: func(*inodeRecord) publicationCoordinate {
			return publicationCoordinate{kind: publicationItemAttributes, item: publicationIdentity(testIdentity(95))}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStrictFixture(t)
			root := fixture.raw.acquire(fuse.FUSE_ROOT_ID)
			if root == nil {
				t.Fatal("root record")
			}
			defer fixture.raw.release(root)
			gate, err := namespaceSourceGate(root.node.item, "victim", false)
			if err != nil {
				t.Fatal(err)
			}
			coordinate := test.coordinate(root)
			if err := fixture.raw.closeLeaseCoordinate(context.Background(), coordinate); err != nil {
				t.Fatal(err)
			}
			acquired := make(chan *sourcePublicationLease, 1)
			failed := make(chan error, 1)
			go func() {
				lease, acquireErr := fixture.raw.acquireSourcePublication(context.Background(), gate)
				if acquireErr != nil {
					failed <- acquireErr
					return
				}
				acquired <- lease
			}()
			select {
			case lease := <-acquired:
				lease.release()
				t.Fatal("overlapping source publication crossed a live recall cut")
			case err := <-failed:
				t.Fatal(err)
			case <-time.After(20 * time.Millisecond):
			}
			fixture.raw.openLeaseCoordinate(coordinate)
			select {
			case lease := <-acquired:
				lease.release()
			case err := <-failed:
				t.Fatal(err)
			case <-time.After(time.Second):
				t.Fatal("source publication did not resume after recall discharge")
			}
		})
	}
}

func TestSourceMutationReplyHasZeroCacheValidityWithoutSuccessorLease(t *testing.T) {
	fixture := newStrictFixture(t)
	out := &fuse.EntryOut{}
	status := fixture.rawCall(func(unique uint64) fuse.Status {
		return fixture.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, Mode: 0o755}, "created", out)
	})
	if !status.Ok() {
		t.Fatalf("MKDIR = %v", status)
	}
	if out.EntryValid != 0 || out.EntryValidNsec != 0 || out.AttrValid != 0 || out.AttrValidNsec != 0 {
		t.Fatalf("source reply validity = entry(%d,%d) attr(%d,%d), want zero without N/A successor leases", out.EntryValid, out.EntryValidNsec, out.AttrValid, out.AttrValidNsec)
	}
}

func TestDaemonNameCacheKeepsKernelValidityZero(t *testing.T) {
	fixture := newStrictFixture(t)
	item := testItem(90, authoritypb.Attr_REGULAR, 90)
	item.Attr.Size = 11
	fixture.rpc.byName = map[string]*authoritypb.Item{"hit": item}
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetLookup() == nil {
			return &authoritypb.Response{}, nil
		}
		answer := cloneItem(item)
		answer.ObjectVersion, answer.SnapshotSequence = 1, 1
		return &authoritypb.Response{
			Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: answer}},
			LeaseGrants: []*authoritypb.LeaseGrant{
				nameGrant(fixture.rpc.root.GetStableIdentity(), "hit", 1, 1), attrGrant(item.GetStableIdentity(), 2, 1),
			},
		}, nil
	}
	first := fixture.lookup(t, fuse.FUSE_ROOT_ID, "hit")
	if first.EntryValid != 0 || first.EntryValidNsec != 0 {
		t.Fatalf("positive kernel entry validity = (%d,%d), want zero", first.EntryValid, first.EntryValidNsec)
	}
	fixture.rpc.mu.Lock()
	calls := fixture.rpc.calls
	fixture.rpc.mu.Unlock()
	second := fixture.lookup(t, fuse.FUSE_ROOT_ID, "hit")
	fixture.rpc.mu.Lock()
	warmCalls := fixture.rpc.calls
	fixture.rpc.mu.Unlock()
	if warmCalls != calls {
		t.Fatalf("warm daemon name hit made an authority call: before=%d after=%d", calls, warmCalls)
	}
	if second.EntryValid != 0 || second.Attr.Size != 11 {
		t.Fatalf("warm positive reply = validity %d size %d", second.EntryValid, second.Attr.Size)
	}

	negative := newStrictFixture(t)
	negative.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		return &authoritypb.Response{
			Body:        &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: 1}},
			LeaseGrants: []*authoritypb.LeaseGrant{nameGrant(negative.rpc.root.GetStableIdentity(), "missing", 1, 1)},
		}, nil
	}
	missing := negative.lookup(t, fuse.FUSE_ROOT_ID, "missing")
	if missing.NodeId != 0 || missing.EntryValid != 0 || missing.EntryValidNsec != 0 {
		t.Fatalf("negative kernel entry = node %d validity (%d,%d)", missing.NodeId, missing.EntryValid, missing.EntryValidNsec)
	}
	negative.rpc.mu.Lock()
	negativeCalls := negative.rpc.calls
	negative.rpc.mu.Unlock()
	_ = negative.lookup(t, fuse.FUSE_ROOT_ID, "missing")
	negative.rpc.mu.Lock()
	negativeWarmCalls := negative.rpc.calls
	negative.rpc.mu.Unlock()
	if negativeWarmCalls != negativeCalls {
		t.Fatalf("warm negative daemon hit made an authority call: before=%d after=%d", negativeCalls, negativeWarmCalls)
	}
}

func TestDaemonAttrCacheUsesFreshGrantBearingSnapshot(t *testing.T) {
	fixture := newStrictFixture(t)
	item := testItem(91, authoritypb.Attr_REGULAR, 91)
	fixture.rpc.byName = map[string]*authoritypb.Item{"file": item}
	version := uint64(1)
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		answer := cloneItem(item)
		answer.Attr.Size = int64(version)
		answer.ObjectVersion, answer.SnapshotSequence = version, version
		issued := uint64(1)
		nameEpoch, attrEpoch := uint64(1), uint64(2)
		if version > 1 {
			issued, attrEpoch = 2, 4
		}
		return &authoritypb.Response{
			Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: answer}},
			LeaseGrants: []*authoritypb.LeaseGrant{
				nameGrant(fixture.rpc.root.GetStableIdentity(), "file", nameEpoch, issued), attrGrant(item.GetStableIdentity(), attrEpoch, issued),
			},
		}, nil
	}
	first := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file")
	if first.Attr.Size != 1 {
		t.Fatalf("first size = %d", first.Attr.Size)
	}
	identity := publicationIdentity(item.GetStableIdentity())
	attrRecall := &authoritypb.LeaseRecall{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, Identity: identity[:]},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ, GrantEpoch: 2, RevokeEpoch: 3,
	}
	if _, err := fixture.mount.leases.beginRecalls(context.Background(), 2, []*authoritypb.LeaseRecall{attrRecall}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.mount.leases.completeRecalls([]*authoritypb.LeaseRecall{attrRecall}); err != nil {
		t.Fatal(err)
	}
	fixture.mount.leases.finishRecalls([]*authoritypb.LeaseRecall{attrRecall})
	version = 2
	second := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file")
	if second.Attr.Size != 2 {
		t.Fatalf("fresh authority size = %d", second.Attr.Size)
	}
	fixture.rpc.mu.Lock()
	calls := fixture.rpc.calls
	fixture.rpc.mu.Unlock()
	third := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file")
	fixture.rpc.mu.Lock()
	warmCalls := fixture.rpc.calls
	fixture.rpc.mu.Unlock()
	if warmCalls != calls || third.Attr.Size != 2 {
		t.Fatalf("warm fresh snapshot = size %d calls %d->%d", third.Attr.Size, calls, warmCalls)
	}
}

func TestDaemonNamePayloadCannotBorrowReplacementGrant(t *testing.T) {
	fixture := newStrictFixture(t)
	parent := fixture.raw.nodesByID[fuse.FUSE_ROOT_ID]
	item := testItem(92, authoritypb.Attr_REGULAR, 92)
	record, errno := fixture.raw.intern(context.Background(), item)
	if errno != 0 {
		t.Fatal(errno)
	}
	key := nameKey{parent: parent.key.inode, name: "stale"}
	fixture.raw.mu.Lock()
	fixture.raw.bindCachedNameLocked(key, publicationNamespace{parent: parent.identity, name: "stale"}, record, leaseStamp{epoch: 1, issuedSequence: 1})
	fixture.raw.mu.Unlock()
	now := time.Now()
	grants, err := validateLeaseGrants([]*authoritypb.LeaseGrant{nameGrant(parent.identity[:], "stale", 2, 2)}, now)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mount.leases.install(grants, now)
	if cached, _, _ := fixture.raw.cachedLookup(context.Background(), parent, "stale"); cached != nil {
		t.Fatal("old positive payload borrowed a replacement N grant")
	}
	fixture.raw.mu.Lock()
	fixture.raw.dropCachedNameLocked(key)
	fixture.raw.bindCachedNegativeLocked(key, leaseStamp{epoch: 1, issuedSequence: 1})
	fixture.raw.mu.Unlock()
	if _, _, negative := fixture.raw.cachedLookup(context.Background(), parent, "stale"); negative {
		t.Fatal("old negative payload borrowed a replacement N grant")
	}
}

func TestRenewalPreservesDaemonPayloadForSameEpoch(t *testing.T) {
	registry := newLeaseRegistry(nil)
	now := time.Now()
	identity := publicationIdentity(testIdentity(93))
	key := leaseKey{family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, identity: identity}
	initial := validatedLeaseGrant{family: key.family, right: authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, identity: identity, epoch: 5, issuedSequence: 1, deadline: now.Add(time.Minute)}
	registry.install([]validatedLeaseGrant{initial}, now)
	renewed := initial
	renewed.issuedSequence = 9
	renewed.deadline = now.Add(2 * time.Minute)
	registry.install([]validatedLeaseGrant{renewed}, now)
	if !registry.matches(key, authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, leaseStamp{epoch: 5, issuedSequence: 1}, now) {
		t.Fatal("same-epoch renewal invalidated a safe daemon payload")
	}
}

func TestSourceDischargeDoesNotRequirePostStateOrMatchingCommitSequence(t *testing.T) {
	fixture := newStrictFixture(t)
	rootIdentity, _ := publicationIdentityFromItem(fixture.raw.nodesByID[fuse.FUSE_ROOT_ID].node.item)
	recall := &authoritypb.LeaseRecall{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_NAME, ParentIdentity: rootIdentity[:], Name: []byte("x")},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ, GrantEpoch: 1, RevokeEpoch: 2,
	}
	for _, test := range []struct {
		name     string
		response *authoritypb.Response
	}{
		{name: "nil discharge", response: &authoritypb.Response{}},
		{name: "applied error without post-state", response: &authoritypb.Response{Errno: int32(5), SourceLeaseDischarge: &authoritypb.SourceLeaseDischarge{Sequence: 9, Recalls: []*authoritypb.LeaseRecall{recall}}}},
		{name: "commit sequence is independent", response: &authoritypb.Response{PostState: &authoritypb.PostState{VisibilitySequence: 3}, SourceLeaseDischarge: &authoritypb.SourceLeaseDischarge{Sequence: 9, Recalls: []*authoritypb.LeaseRecall{recall}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			callback := &mutationCallback{publication: replyPublication{source: &sourcePublicationLease{}}}
			ctx := context.WithValue(context.Background(), mutationCallbackKey{}, callback)
			if err := fixture.mount.retainSourceLeaseDischarge(ctx, test.response); err != nil {
				t.Fatal(err)
			}
		})
	}
}
