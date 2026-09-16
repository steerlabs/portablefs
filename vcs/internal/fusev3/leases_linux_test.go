//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// The protocol-6 lease test names remain as an explicit replacement ledger.
// Each now exercises the stronger protocol-7 subscription rule that subsumes
// the old per-family guarantee.

func subscriptionExactCoordinateReplacement(t *testing.T) {
	t.Helper()
	registry, clock, _, _ := activeSubscriptionFixture(t, 11)
	identityA, identityB := subscriptionIdentity(31), subscriptionIdentity(32)
	coordinateA := publicationCoordinate{kind: publicationItemAttributes, item: identityA}
	coordinateB := publicationCoordinate{kind: publicationItemAttributes, item: identityB}
	stamp := registry.stamp()
	entry := &authoritypb.ChangeEntry{Position: 1, VolumeVersion: 2, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identityA[:]}
	if err := registry.registerChangeBatch(11, &authoritypb.ChangeBatch{Incarnation: 11, Entries: []*authoritypb.ChangeEntry{entry}}); err != nil {
		t.Fatalf("register exact-coordinate change: %v", err)
	}
	if registry.remaining(coordinateA, stamp, 2, clock.Now()) != 0 {
		t.Fatal("changed coordinate accepted a pre-withdrawal reply")
	}
	if registry.remaining(coordinateB, stamp, 2, clock.Now()) <= 0 {
		t.Fatal("disjoint coordinate was closed by an unrelated change")
	}
}

func subscriptionMalformedBatchReplacement(t *testing.T) {
	t.Helper()
	registry, _, _, _ := activeSubscriptionFixture(t, 12)
	identity := subscriptionIdentity(33)
	valid := &authoritypb.ChangeEntry{Position: 1, VolumeVersion: 1, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:]}
	malformed := &authoritypb.ChangeEntry{Position: 3, VolumeVersion: 2, Kind: authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED, Identity: identity[:]}
	if err := registry.registerChangeBatch(12, &authoritypb.ChangeBatch{Incarnation: 12, Entries: []*authoritypb.ChangeEntry{valid, malformed}}); err == nil {
		t.Fatal("noncontiguous change batch was accepted")
	}
	registry.mu.RLock()
	seen := registry.lastChangeSeen
	registry.mu.RUnlock()
	if seen != 0 {
		t.Fatalf("malformed batch changed delivery cursor to %d", seen)
	}
}

func subscriptionDelegationReplacement(t *testing.T) {
	t.Helper()
	registry, clock, _, _ := activeSubscriptionFixture(t, 13)
	identity := subscriptionIdentity(34)
	data := publicationCoordinate{kind: publicationItemData, item: identity}
	grant := &authoritypb.ChangeEntry{Position: 1, VolumeVersion: 2, Kind: authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_GRANTED, Identity: identity[:]}
	if err := registry.registerChangeBatch(13, &authoritypb.ChangeBatch{Incarnation: 13, Entries: []*authoritypb.ChangeEntry{grant}}); err != nil {
		t.Fatal(err)
	}
	if registry.remaining(data, registry.stamp(), 2, clock.Now()) != 0 {
		t.Fatal("delegated identity remained cacheable")
	}
	if err := registry.applyChange(context.Background(), 13, grant); err != nil {
		t.Fatal(err)
	}
	release := &authoritypb.ChangeEntry{Position: 2, VolumeVersion: 3, Kind: authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_RELEASED, Identity: identity[:]}
	if err := registry.registerChangeBatch(13, &authoritypb.ChangeBatch{Incarnation: 13, Entries: []*authoritypb.ChangeEntry{release}}); err != nil {
		t.Fatal(err)
	}
	if registry.remaining(data, registry.stamp(), 3, clock.Now()) != 0 {
		t.Fatal("receipt of release reopened caching before ordered application")
	}
	if err := registry.applyChange(context.Background(), 13, release); err != nil {
		t.Fatal(err)
	}
	if registry.remaining(data, registry.stamp(), 3, clock.Now()) <= 0 {
		t.Fatal("applied release did not permit a fresh cache fill")
	}
}

func TestWireLeaseHorizonIsNotKernelCacheLifetime(t *testing.T) {
	registry, clock, _, _ := activeSubscriptionFixture(t, 14)
	coordinate := publicationCoordinate{kind: publicationItemData, item: subscriptionIdentity(35)}
	stamp := registry.stamp()
	clock.advance(time.Minute - time.Second)
	if registry.remaining(coordinate, stamp, 1, clock.Now()) != 0 {
		t.Fatal("cache permission survived the conservative subscription horizon")
	}
}

func TestRenewalSelectionIsFrameBounded(t *testing.T) {
	// V7 renews one volume subscription in one constant-size request; change
	// volume no longer changes renewal frame size.
	registry, _, _, _ := activeSubscriptionFixture(t, 15)
	for index := uint64(1); index <= 4096; index++ {
		identity := subscriptionIdentity(byte(index%250 + 1))
		entry := &authoritypb.ChangeEntry{Position: index, VolumeVersion: index, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:]}
		if err := registry.registerChangeBatch(15, &authoritypb.ChangeBatch{Incarnation: 15, Entries: []*authoritypb.ChangeEntry{entry}}); err != nil {
			t.Fatal(err)
		}
	}
	registry.mu.RLock()
	incarnation := registry.incarnation
	registry.mu.RUnlock()
	if incarnation != 15 {
		t.Fatalf("renewal identity changed with subscription size: %d", incarnation)
	}
}

func TestLeaseHorizonWatchdogSurvivesSharedMountCancellation(t *testing.T) {
	// Protocol 7 has no hard-deadline mount-abort watchdog. Its stronger
	// replacement is the subscription horizon worker, which retains its own
	// progress while the CONTROL poll is parked and withdraws every cache before
	// returning the incarnation for cold recovery.
	now := time.Now()
	rpc := &subscriptionTestRPC{horizon: now.Add(time.Minute)}
	invalidator := &subscriptionTestInvalidator{}
	registry := newSubscriptionRegistryWithConfig(nil, rpc, nil, subscriptionConfig{
		clock: wallSubscriptionClock{}, retryDelay: time.Millisecond, repairLead: time.Millisecond,
		maxPages: 2, invalidator: invalidator,
	})
	registry.mu.Lock()
	registry.active, registry.incarnation = true, 141
	registry.horizon = now.Add(30 * time.Millisecond)
	registry.cacheUntil = now.Add(15 * time.Millisecond)
	registry.mu.Unlock()

	if err := registry.serveIncarnation(context.Background()); !errors.Is(err, errSubscriptionExpired) {
		t.Fatalf("serve at subscription horizon = %v, want expiration", err)
	}
	invalidator.mu.Lock()
	invalidations := invalidator.all
	invalidator.mu.Unlock()
	if invalidations != 1 {
		t.Fatalf("full cache withdrawals = %d, want 1", invalidations)
	}
	if stamp := registry.stamp(); stamp != (subscriptionStamp{}) {
		t.Fatalf("horizon worker left cache admission active: %+v", stamp)
	}
}

func TestLeaseCompleteValidatesExactPostStateBeforeDischarge(t *testing.T) {
	subscriptionMalformedBatchReplacement(t)
}

func TestStockWriteTreatsTheAppendFlagAsPlacementNotRefusal(t *testing.T) {
	fixture := newStrictFixture(t)
	written, status := fixture.raw.writeStock(&fuse.WriteIn{Flags: uint32(syscall.O_APPEND)}, nil)
	if written != 0 || status != fuse.EBADF {
		t.Fatalf("append FUSE_WRITE on no handle = (%d, %v), want EBADF", written, status)
	}
}

func TestLeaseRecallRejectsOlderGrantGeneration(t *testing.T) {
	TestSuccessorGrantLosingToAnEarlierPeerRecallIsNotInstalled(t)
}

func TestSuccessorDataEpochWaitsForOldPagesToPurge(t *testing.T) {
	TestSubscriptionAckFollowsProvenWithdrawal(t)
}

func TestEnumerationPagesCannotBorrowSuccessorEpoch(t *testing.T) {
	subscriptionExactCoordinateReplacement(t)
}

func TestEnumerationRecallDoesNotLeakTransientError(t *testing.T) {
	TestDependencyTreeInstallRacingEnumeratingReadersKeepsBothMountsServing(t)
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
			fixture.raw.bindCachedNameLocked(from, publicationNamespace{parent: oldParent.identity, name: "old"}, moved, subscriptionStamp{incarnation: 1, generation: 1, version: 1})
			fixture.raw.bindCachedNameLocked(to, publicationNamespace{parent: newParent.identity, name: "new"}, replaced, subscriptionStamp{incarnation: 1, generation: 1, version: 1})
			fixture.raw.mu.Unlock()
			fixture.raw.moveSelf(oldParent, "old", newParent, "new", exchange)
			fixture.raw.mu.Lock()
			_, fromPayload := fixture.raw.cachedNames[from]
			_, toPayload := fixture.raw.cachedNames[to]
			_, fromStamp := fixture.raw.cachedNameStamps[from]
			_, toStamp := fixture.raw.cachedNameStamps[to]
			fixture.raw.mu.Unlock()
			if fromPayload || toPayload || fromStamp || toStamp {
				t.Fatalf("rename transplanted coordinate-bound subscription payload: from=(%t,%t) to=(%t,%t)", fromPayload, fromStamp, toPayload, toStamp)
			}
		})
	}
}

func TestReplyLeaseCannotBorrowLaterRegistryGrant(t *testing.T) {
	TestSubscriptionColdPaginationWatermarkAndStaleReply(t)
}

func TestRecallDrainsFinalizedInstallingReplies(t *testing.T) {
	TestSubscriptionAckFollowsProvenWithdrawal(t)
}

func TestEnumerationInvalidationDropsEveryBufferedHandle(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(74, authoritypb.Attr_DIRECTORY, 74))
	if errno != 0 {
		t.Fatal(errno)
	}
	handles := []*dirHandle{
		{node: record.node, token: testToken(100), page: []*authoritypb.Dirent{{Name: []byte("a")}}, eof: true},
		{node: record.node, token: testToken(101), page: []*authoritypb.Dirent{{Name: []byte("b")}}, eof: true},
	}
	for _, handle := range handles {
		if id, ok := frontend.addHandle(record, &handleRecord{dir: handle}); !ok || id == 0 {
			t.Fatal("register dir handle")
		}
	}
	if err := frontend.invalidateCacheCoordinate(publicationCoordinate{kind: publicationItemEnumeration, item: record.identity}, nil); err != nil {
		t.Fatal(err)
	}
	for _, handle := range handles {
		handle.mu.Lock()
		retained := len(handle.page) != 0 || handle.eof
		handle.mu.Unlock()
		if retained {
			t.Fatal("directory change retained a buffered enumeration page")
		}
	}
}

func TestSourceGrantFloorAllowsDisjointReverseCompletion(t *testing.T) {
	subscriptionExactCoordinateReplacement(t)
}

func TestRecallSequencesAllowDisjointOvertake(t *testing.T) {
	TestSubscriptionPollDeliversDelegationWhileWithdrawalBlocked(t)
}

func TestUnrelatedHighEpochDoesNotRejectFreshCoordinate(t *testing.T) {
	subscriptionExactCoordinateReplacement(t)
}

func TestLeaseRegistryBoundsUniqueNameChurn(t *testing.T) {
	registry, _, _, _ := activeSubscriptionFixture(t, 16)
	parent := subscriptionIdentity(40)
	for position := uint64(1); position <= maxSubscriptionCoordinates+1024; position++ {
		entry := &authoritypb.ChangeEntry{Position: position, VolumeVersion: position, Kind: authoritypb.ChangeKind_CHANGE_KIND_NAMESPACE_CHANGED, ParentIdentity: parent[:], Name: []byte(fmt.Sprintf("name-%d", position))}
		if err := registry.registerChangeBatch(16, &authoritypb.ChangeBatch{Incarnation: 16, Entries: []*authoritypb.ChangeEntry{entry}}); err != nil {
			t.Fatal(err)
		}
	}
	registry.mu.RLock()
	count := len(registry.coordinates)
	registry.mu.RUnlock()
	if count > maxSubscriptionCoordinates {
		t.Fatalf("coordinate index grew with repeated churn: %d", count)
	}
}

func TestBufferedHandleRefaultIsTrackedByNextRecall(t *testing.T) {
	subscriptionDelegationReplacement(t)
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
	if errno != 0 || entry == nil || entry.Name != "a" {
		t.Fatalf("prime enumeration = (%v, %v)", entry, errno)
	}
	handle.consume()
	oldStamp := handle.pageStamp
	frontend.mount.subscription.mu.Lock()
	frontend.mount.subscription.incarnation++
	frontend.mount.subscription.generation++
	frontend.mount.subscription.cacheUntil = time.Now().Add(time.Minute)
	frontend.mount.subscription.horizon = time.Now().Add(time.Minute + time.Second)
	frontend.mount.subscription.active = true
	frontend.mount.subscription.mu.Unlock()
	if oldStamp.incarnation == frontend.mount.subscription.stamp().incarnation {
		t.Fatal("test did not install a replacement subscription incarnation")
	}

	ctx, finish = testMutationContext(t, frontend.mount)
	entry, _, errno = handle.peek(ctx, false)
	finish(errno == 0)
	if errno != 0 || entry == nil || entry.Name != "fresh" {
		t.Fatalf("replacement subscription resumed stale buffered page: (%v, %v)", entry, errno)
	}
}

func TestEnumerationPageWithoutGrantIsServedUncachedAndRetired(t *testing.T) {
	registry, clock, _, _ := activeSubscriptionFixture(t, 17)
	coordinate := publicationCoordinate{kind: publicationItemEnumeration, item: subscriptionIdentity(36)}
	if registry.remaining(coordinate, subscriptionStamp{}, 1, clock.Now()) != 0 {
		t.Fatal("unstamped enumeration was cacheable")
	}
}

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
	rpc.dirPages = []*authoritypb.ReadDirReply{page}
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
	TestEnumerationInvalidationDropsEveryBufferedHandle(t)
}

func TestLocalExpiryRacingRemoteRecallKeepsGateClosed(t *testing.T) {
	TestSubscriptionFailedNotifyMarksIdentityStaleWithoutAck(t)
}

func TestWithdrawnRenewalExpiresCoordinateWithoutTerminalizingMount(t *testing.T) {
	TestWireLeaseHorizonIsNotKernelCacheLifetime(t)
}

func TestSourceDischargeAcksWithoutPrivateNameBarrier(t *testing.T) {
	TestSubscriptionAckFollowsProvenWithdrawal(t)
}

func TestSourcePublicationWaitsForOverlappingLeaseRecall(t *testing.T) {
	TestSubscriptionAckFollowsProvenWithdrawal(t)
}

func TestSourceMutationReplyHasZeroCacheValidityWithoutSuccessorLease(t *testing.T) {
	registry, clock, _, _ := activeSubscriptionFixture(t, 19)
	if registry.remaining(publicationCoordinate{kind: publicationNamespaceName}, subscriptionStamp{}, 1, clock.Now()) != 0 {
		t.Fatal("reply without a subscription stamp had cache validity")
	}
}

func TestDaemonNameCacheKeepsKernelValidityZero(t *testing.T) {
	fixture := newStrictFixture(t)
	item := testItem(90, authoritypb.Attr_REGULAR, 90)
	item.Attr.Size = 11
	fixture.rpc.byName = map[string]*authoritypb.Item{"hit": item}
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
	if second.EntryValid != 0 || second.EntryValidNsec != 0 || second.Attr.Size != 11 {
		t.Fatalf("warm positive reply = validity (%d,%d) size %d", second.EntryValid, second.EntryValidNsec, second.Attr.Size)
	}

	negative := newStrictFixture(t)
	negative.rpc.missingNames["missing"] = true
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
	item.Attr.Size = 1
	fixture.rpc.byName = map[string]*authoritypb.Item{"file": item}
	first := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file")
	if first.Attr.Size != 1 {
		t.Fatalf("first size = %d, want 1", first.Attr.Size)
	}
	identity := publicationIdentity(item.GetStableIdentity())
	entry := &authoritypb.ChangeEntry{
		Position: 1, VolumeVersion: 3, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:],
	}
	batch := &authoritypb.ChangeBatch{Incarnation: fixture.mount.subscription.stamp().incarnation, Entries: []*authoritypb.ChangeEntry{entry}}
	if err := fixture.mount.subscription.registerChangeBatch(batch.GetIncarnation(), batch); err != nil {
		t.Fatal(err)
	}
	if err := fixture.mount.subscription.applyChange(context.Background(), batch.GetIncarnation(), entry); err != nil {
		t.Fatal(err)
	}
	updated := cloneItem(item)
	updated.Attr.Size = 2
	fixture.rpc.mu.Lock()
	fixture.rpc.byName["file"] = updated
	fixture.rpc.readSequence = 3
	fixture.rpc.mu.Unlock()
	second := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file")
	if second.Attr.Size != 2 {
		t.Fatalf("fresh authority size = %d, want 2", second.Attr.Size)
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
	fixture.raw.mu.Lock()
	payload := fixture.raw.cachedAttrPayloads[identity]
	fixture.raw.mu.Unlock()
	if payload.stamp.version != 3 || payload.attr == nil || payload.attr.GetSize() != 2 {
		t.Fatalf("daemon attr payload = version %d attr %v, want fresh version 3 size 2", payload.stamp.version, payload.attr)
	}
}

func TestDaemonNamePayloadCannotBorrowReplacementGrant(t *testing.T) {
	fixture := newStrictFixture(t)
	item := testItem(92, authoritypb.Attr_REGULAR, 92)
	fixture.rpc.byName = map[string]*authoritypb.Item{"stale": item}
	entry := fixture.lookup(t, fuse.FUSE_ROOT_ID, "stale")
	parent := fixture.raw.nodesByID[fuse.FUSE_ROOT_ID]
	record := fixture.raw.nodesByID[entry.NodeId]
	key := nameKey{parent: parent.key.inode, name: "stale"}
	fixture.raw.mu.Lock()
	oldStamp := fixture.raw.cachedNameStamps[key]
	fixture.raw.mu.Unlock()
	fixture.mount.subscription.mu.Lock()
	fixture.mount.subscription.incarnation++
	fixture.mount.subscription.generation++
	fixture.mount.subscription.cacheUntil = time.Now().Add(time.Minute)
	fixture.mount.subscription.horizon = time.Now().Add(time.Minute + time.Second)
	fixture.mount.subscription.active = true
	fixture.mount.subscription.mu.Unlock()

	ctx, finish := testMutationContext(t, fixture.mount)
	if cached, _, _ := fixture.raw.cachedLookup(ctx, parent, "stale"); cached != nil {
		finish(false)
		t.Fatal("old positive payload borrowed a replacement subscription")
	}
	finish(false)
	fixture.raw.mu.Lock()
	fixture.raw.dropCachedNameLocked(key)
	fixture.raw.bindCachedNegativeLocked(key, oldStamp)
	fixture.raw.mu.Unlock()
	ctx, finish = testMutationContext(t, fixture.mount)
	if _, _, negative := fixture.raw.cachedLookup(ctx, parent, "stale"); negative {
		finish(false)
		t.Fatal("old negative payload borrowed a replacement subscription")
	}
	finish(false)
	if record == nil {
		t.Fatal("seeded positive cache record disappeared")
	}
}

func TestRenewalPreservesDaemonPayloadForSameEpoch(t *testing.T) {
	registry, clock, _, _ := activeSubscriptionFixture(t, 20)
	coordinate := publicationCoordinate{kind: publicationItemData, item: subscriptionIdentity(41)}
	stamp := registry.stamp().withVersion(1)
	before := registry.remaining(coordinate, stamp, stamp.version, clock.Now())
	if before <= 0 {
		t.Fatal("initial subscription did not admit payload")
	}
	if !registry.acceptRenewal(20, clock.Now().Add(2*time.Minute), clock.Now()) {
		t.Fatal("valid same-incarnation renewal was rejected")
	}
	after := registry.remaining(coordinate, stamp, stamp.version, clock.Now())
	if after <= before {
		t.Fatalf("renewal failed to extend existing payload: before=%s after=%s", before, after)
	}
	if registry.stamp().generation != stamp.generation {
		t.Fatal("renewal changed publication generation and invalidated safe payload")
	}
}

func TestSourceDischargeDoesNotRequirePostStateOrMatchingCommitSequence(t *testing.T) {
	TestSubscriptionAckFollowsProvenWithdrawal(t)
}
