//go:build linux

package fusev3

import (
	"context"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestBatchWithdrawalClosesEveryCoordinateBeforeReplyDrain(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "cached")
	unique := f.unique.Add(2)
	if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{}); status != fuse.OK {
		t.Fatal(status)
	}
	coordinates := []publicationCoordinate{
		{kind: publicationNamespaceName, parent: f.raw.nodesByID[1].identity, name: "cached"},
		{kind: publicationItemAttributes, item: f.raw.nodesByID[entry.NodeId].identity},
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	var lease *cacheRepairLease
	go func() { var err error; lease, err = f.raw.closeCacheCoordinates(ctx, coordinates); done <- err }()
	for {
		f.raw.mu.Lock()
		p := f.raw.replyPublications[unique]
		waiting := p != nil && p.originalDone != nil
		all := f.raw.repairingCoordinates[coordinates[0]] && f.raw.repairingCoordinates[coordinates[1]]
		f.raw.mu.Unlock()
		if waiting {
			if !all {
				t.Fatal("batch waited before closing every coordinate")
			}
			break
		}
		select {
		case err := <-done:
			t.Fatalf("withdrawal crossed reply: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}
		time.Sleep(time.Millisecond)
	}
	f.raw.ReplyWritten(unique, fuse.OK)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lease.Open()
}

func TestBatchWithdrawalDropsEveryPayloadBeforeCoalescedNotification(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "cached")
	f.lookup(t, 1, "alias")
	identity := f.raw.nodesByID[entry.NodeId].identity
	parent := f.raw.nodesByID[1]
	withdrawals := []subscriptionWithdrawal{
		{coordinate: publicationCoordinate{kind: publicationItemAttributes, item: identity}},
		{coordinate: publicationCoordinate{kind: publicationNamespaceName, parent: parent.identity, name: "cached"}},
		{coordinate: publicationCoordinate{kind: publicationItemData, item: identity}, byteRange: &authoritypb.ByteRange{Offset: 4, Length: 8}},
		{coordinate: publicationCoordinate{kind: publicationNamespaceName, parent: parent.identity, name: "alias"}},
	}
	checked := false
	f.notify.onInode = func(_ uint64, off, length int64) {
		checked = true
		f.raw.mu.Lock()
		defer f.raw.mu.Unlock()
		if f.raw.cachedNames[nameKey{parent: parent.key.inode, name: "cached"}] != nil || f.raw.cachedNames[nameKey{parent: parent.key.inode, name: "alias"}] != nil || f.raw.cachedAttrPayloads[identity].attr != nil {
			t.Error("notification preceded batch daemon purge")
		}
		if off != 4 || length != 8 {
			t.Errorf("coalesced data range=%d/%d", off, length)
		}
	}
	coordinates := make([]publicationCoordinate, len(withdrawals))
	for i, w := range withdrawals {
		coordinates[i] = w.coordinate
	}
	lease, err := f.raw.closeCacheCoordinates(t.Context(), coordinates)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.raw.invalidateCacheCoordinatesContext(t.Context(), withdrawals); err != nil {
		t.Fatal(err)
	}
	lease.Open()
	if calls := f.notify.snapshot(); !checked || len(calls) != 1 || calls[0].kind != "inode" {
		t.Fatalf("batch notifications=%v, checked=%v", calls, checked)
	}
}

func TestRegisteredGrantCannotBeClearedByEarlierRelease(t *testing.T) {
	for _, sameBatch := range []bool{false, true} {
		for _, grantLast := range []bool{false, true} {
			name := "separate"
			if sameBatch {
				name = "same"
			}
			if grantLast {
				name += "/grant-last"
			} else {
				name += "/release-last"
			}
			t.Run(name, func(t *testing.T) {
				f := newStrictFixture(t)
				identity := f.raw.nodesByID[1].identity
				s := f.mount.subscription
				incarnation := s.stamp().incarnation
				grant := authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_GRANTED
				release := authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_RELEASED
				kinds := []authoritypb.ChangeKind{grant, release}
				if grantLast {
					kinds = []authoritypb.ChangeKind{release, grant}
				}
				entries := make([]*authoritypb.ChangeEntry, 2)
				for i, kind := range kinds {
					entries[i] = &authoritypb.ChangeEntry{Position: uint64(i + 1), VolumeVersion: uint64(i + 2), Kind: kind, Identity: identity[:]}
				}
				if sameBatch {
					batch := &authoritypb.ChangeBatch{Incarnation: incarnation, Entries: entries}
					if err := s.registerChangeBatch(incarnation, batch); err != nil {
						t.Fatal(err)
					}
					if err := s.applyChangeBatch(t.Context(), incarnation, batch); err != nil {
						t.Fatal(err)
					}
				} else {
					for _, entry := range entries {
						if err := s.registerChangeBatch(incarnation, &authoritypb.ChangeBatch{Incarnation: incarnation, Entries: []*authoritypb.ChangeEntry{entry}}); err != nil {
							t.Fatal(err)
						}
					}
					if err := s.applyChange(t.Context(), incarnation, entries[0]); err != nil {
						t.Fatal(err)
					}
					if grantLast {
						s.mu.RLock()
						_, present := s.delegated[identity]
						s.mu.RUnlock()
						if !present {
							t.Fatal("earlier release cleared later registered grant")
						}
					}
					if err := s.applyChange(t.Context(), incarnation, entries[1]); err != nil {
						t.Fatal(err)
					}
				}
				s.mu.RLock()
				_, present := s.delegated[identity]
				s.mu.RUnlock()
				if present != grantLast {
					t.Fatalf("final delegation exclusion=%v, want %v", present, grantLast)
				}
			})
		}
	}
}

func TestCacheRepairOwnersSurviveOverlapAndColdRetirement(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "cached")
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: f.raw.nodesByID[entry.NodeId].identity}
	first, err := f.raw.closeCacheCoordinate(t.Context(), coordinate)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.raw.closeCacheCoordinate(t.Context(), coordinate)
	if err != nil {
		t.Fatal(err)
	}
	first.Open()
	first.Open()
	f.raw.mu.Lock()
	closed := f.raw.repairingCoordinates[coordinate]
	owners := len(f.raw.repairOwners[coordinate])
	f.raw.mu.Unlock()
	if !closed || owners != 1 {
		t.Fatalf("overlap lost ownership: closed=%v owners=%d", closed, owners)
	}
	f.mount.subscription.deactivate()
	if err := f.raw.invalidateAllCaches(t.Context()); err != nil {
		t.Fatal(err)
	}
	successor, err := f.raw.closeCacheCoordinate(t.Context(), coordinate)
	if err != nil {
		t.Fatal(err)
	}
	second.Open()
	f.raw.mu.Lock()
	closed = f.raw.repairingCoordinates[coordinate]
	owners = len(f.raw.repairOwners[coordinate])
	f.raw.mu.Unlock()
	if !closed || owners != 1 {
		t.Fatalf("pre-cold release opened successor: closed=%v owners=%d", closed, owners)
	}
	successor.Open()
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	if f.raw.repairingCoordinates[coordinate] || len(f.raw.repairOwners) != 0 {
		t.Fatal("settled repair owners leaked")
	}
}

func TestFailedColdProofRetiresOnlyItsOwnRepairOwner(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "cached")
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: f.raw.nodesByID[entry.NodeId].identity}
	local, err := f.raw.closeCacheCoordinate(t.Context(), coordinate)
	if err != nil {
		t.Fatal(err)
	}
	f.mount.subscription.deactivate()
	f.notify.inodeST = fuse.EIO
	if err := f.raw.invalidateAllCaches(t.Context()); err == nil {
		t.Fatal("cold proof accepted failed notification")
	}
	f.raw.mu.Lock()
	_, retained := f.raw.repairOwners[coordinate][local]
	owners := len(f.raw.repairOwners[coordinate])
	closed := f.raw.repairingCoordinates[coordinate]
	f.raw.mu.Unlock()
	if !retained || owners != 1 || !closed {
		t.Fatalf("failed cold cleanup affected local cut: retained=%v owners=%d closed=%v", retained, owners, closed)
	}
	local.Open()
}

func TestSubscriptionBatchAcknowledgesOnlyAfterAllWithdrawals(t *testing.T) {
	clock := &subscriptionTestClock{now: time.Unix(200, 0)}
	log := make([]string, 0, 7)
	rpc := &subscriptionTestRPC{horizon: clock.Now().Add(10 * time.Second), log: &log}
	invalidator := &subscriptionTestInvalidator{log: &log}
	registry := newSubscriptionTestRegistry(clock, rpc, invalidator, nil)
	registry.active, registry.incarnation = true, 3
	registry.horizon, registry.cacheUntil = rpc.horizon, rpc.horizon.Add(-time.Second)
	batch := &authoritypb.ChangeBatch{Incarnation: 3}
	for i := byte(1); i <= 2; i++ {
		identity := subscriptionIdentity(i)
		batch.Entries = append(batch.Entries, &authoritypb.ChangeEntry{Position: uint64(i), VolumeVersion: 4, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:]})
	}
	if err := registry.registerChangeBatch(3, batch); err != nil {
		t.Fatal(err)
	}
	queue := newSubscriptionChangeQueue()
	if err := queue.push(batch, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- registry.changeLoop(ctx, 3, queue) }()
	waitUntil(t, time.Second, "cumulative batch ack", func() bool { rpc.mu.Lock(); defer rpc.mu.Unlock(); return len(rpc.acks) == 1 })
	cancel()
	queue.close()
	<-done
	want := []string{"close", "close", "invalidate", "invalidate", "open", "open", "ack"}
	if len(log) != len(want) {
		t.Fatalf("batch lifecycle=%v", log)
	}
	for i := range want {
		if log[i] != want[i] {
			t.Fatalf("batch lifecycle=%v, want %v", log, want)
		}
	}
	if len(rpc.acks) != 1 || rpc.acks[0] != 2 {
		t.Fatalf("batch ack=%v", rpc.acks)
	}
}

func TestSubscriptionBatchFailureLeavesEveryCoordinateClosedAndUnacknowledged(t *testing.T) {
	rpc := &subscriptionTestRPC{horizon: time.Now().Add(time.Second)}
	invalidator := &subscriptionTestInvalidator{fail: context.DeadlineExceeded}
	registry := newSubscriptionRegistryWithConfig(nil, rpc, nil, subscriptionConfig{clock: wallSubscriptionClock{}, retryDelay: time.Millisecond, repairLead: 5 * time.Millisecond, maxPages: 2, invalidator: invalidator})
	registry.active, registry.incarnation = true, 9
	registry.horizon, registry.cacheUntil = rpc.horizon, rpc.horizon
	batch := &authoritypb.ChangeBatch{Incarnation: 9}
	for i := byte(1); i <= 2; i++ {
		identity := subscriptionIdentity(i)
		batch.Entries = append(batch.Entries, &authoritypb.ChangeEntry{Position: uint64(i), VolumeVersion: 1, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:]})
	}
	if err := registry.registerChangeBatch(9, batch); err != nil {
		t.Fatal(err)
	}
	queue := newSubscriptionChangeQueue()
	if err := queue.push(batch, 0); err != nil {
		t.Fatal(err)
	}
	if err := registry.changeLoop(t.Context(), 9, queue); err == nil {
		t.Fatal("failed batch accepted")
	}
	if len(invalidator.closed) != 2 || len(invalidator.opened) != 0 || len(invalidator.stale) != 2 || len(rpc.acks) != 0 {
		t.Fatalf("failed batch lifecycle closed=%d opened=%d stale=%d ack=%v", len(invalidator.closed), len(invalidator.opened), len(invalidator.stale), rpc.acks)
	}
}
