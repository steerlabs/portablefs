//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// Cache and delegation admission deny immediately at continuous expiry. Join
// the incarnation's existing worker completion before asserting kernel state;
// a zero permission stamp cannot prove that reverse notifications have run.
func subscriptionWithdrawalDone(t *testing.T, mount *Mount) <-chan struct{} {
	t.Helper()
	mount.subscription.mu.RLock()
	done := mount.subscription.serveDone
	mount.subscription.mu.RUnlock()
	select {
	case <-done:
		t.Fatal("subscription workers are not serving")
	default:
	}
	return done
}

func awaitSubscriptionWithdrawal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("subscription workers did not complete kernel withdrawal")
	}
}

func coldWithdrawalFixture(t *testing.T) (*stockFixture, *inodeRecord, *inodeRecord) {
	t.Helper()
	f := newStockFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{
		"attributes": testItem(121, authoritypb.Attr_REGULAR, 121),
		"data":       testItem(122, authoritypb.Attr_REGULAR, 122),
	}
	f.rpc.missingNames["absent"] = true
	attr := f.raw.nodesByID[f.lookup(t, 1, "attributes").NodeId]
	data := f.raw.nodesByID[f.lookup(t, 1, "data").NodeId]
	f.lookup(t, 1, "absent")
	f.openForData(t, data.id)
	return f, attr, data
}

func assertColdWithdrawalInventory(t *testing.T, f *stockFixture, retained bool) {
	t.Helper()
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	got := [4]int{len(f.raw.cachedNames), len(f.raw.cachedNegatives), len(f.raw.cachedAttrs), len(f.raw.cachedAttrPayloads)}
	want := [4]int{}
	if retained {
		want = [4]int{2, 1, 2, 2}
	}
	if got != want {
		t.Errorf("cold withdrawal inventory = %v, want %v (names, negatives, attributes, payloads)", got, want)
	}
	if len(f.raw.cachedData) != 1 {
		t.Errorf("cold withdrawal lost the retained data description: %d", len(f.raw.cachedData))
	}
}

func assertColdWithdrawalNotifications(t *testing.T, f *stockFixture, attr, data *inodeRecord) {
	t.Helper()
	names := map[string]bool{"attributes": false, "data": false, "absent": false}
	inodes := map[uint64]int64{attr.id: -1, data.id: 0}
	for _, call := range f.notify.snapshot() {
		if call.kind == "entry" && call.parent == 1 {
			names[call.name] = true
		}
		if offset, ok := inodes[call.inode]; call.kind == "inode" && ok && call.off == offset && call.length == 0 {
			delete(inodes, call.inode)
		}
	}
	for name, notified := range names {
		if !notified {
			t.Errorf("cold withdrawal omitted EntryNotify for %q", name)
		}
	}
	for inode := range inodes {
		t.Errorf("cold withdrawal omitted InodeNotify for %d", inode)
	}
}

func TestColdSubscriptionRetainsFailedKernelWithdrawal(t *testing.T) {
	for _, failure := range []string{"entry", "inode", "cancelled", "missing-notifier"} {
		t.Run(failure, func(t *testing.T) {
			f, attr, data := coldWithdrawalFixture(t)
			f.mount.subscription.deactivate()
			assertColdWithdrawalInventory(t, f, true)
			ctx := t.Context()
			switch failure {
			case "entry":
				f.notify.entryST = fuse.EIO
			case "inode":
				f.notify.inodeST = fuse.EIO
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				f.notify.onEntry = func(uint64, string) { cancel() }
			case "missing-notifier":
				f.mount.setNotifier(nil)
			}
			if err := f.raw.invalidateAllCaches(ctx); err == nil {
				t.Fatal("failed kernel withdrawal certified a cold boundary")
			}
			assertColdWithdrawalInventory(t, f, true)
			if f.mount.subscription.stamp() != (subscriptionStamp{}) {
				t.Fatal("failed withdrawal reopened cache admission")
			}
			f.notify.mu.Lock()
			f.notify.calls = nil
			f.notify.entryST, f.notify.inodeST = fuse.OK, fuse.OK
			f.notify.onEntry = nil
			f.notify.mu.Unlock()
			f.mount.setNotifier(f.notify)
			if err := f.raw.invalidateAllCaches(t.Context()); err != nil {
				t.Fatal(err)
			}
			assertColdWithdrawalNotifications(t, f, attr, data)
			assertColdWithdrawalInventory(t, f, false)
		})
	}
}

func TestSubscriptionExpiryCompletionJoinsKernelWithdrawal(t *testing.T) {
	f, attr, data := coldWithdrawalFixture(t)
	sub := f.mount.subscription
	clock := &subscriptionTestClock{now: sub.config.clock.Now()}
	sub.config.clock = clock
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	f.notify.block = release
	f.notify.onEntry = func(uint64, string) { enteredOnce.Do(func() { close(entered) }) }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- sub.serveIncarnation(ctx) }()
	waitUntil(t, time.Second, "subscription workers", func() bool {
		sub.mu.RLock()
		defer sub.mu.RUnlock()
		select {
		case <-sub.serveDone:
			return false
		default:
			return true
		}
	})
	withdrawn := subscriptionWithdrawalDone(t, f.mount)
	clock.advance(11 * time.Second)
	if sub.stamp() != (subscriptionStamp{}) || f.mount.delegations.incarnation() != 0 {
		t.Fatal("continuous expiry retained admission while timers were parked")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("observed expiry did not start kernel withdrawal")
	}
	select {
	case <-withdrawn:
		t.Fatal("withdrawal completion preceded kernel notifications")
	default:
	}
	assertColdWithdrawalInventory(t, f, true)
	unblock()
	awaitSubscriptionWithdrawal(t, withdrawn)
	if err := <-finished; !errors.Is(err, errSubscriptionExpired) {
		t.Fatalf("expiry completion: %v", err)
	}
	assertColdWithdrawalNotifications(t, f, attr, data)
	assertColdWithdrawalInventory(t, f, false)
}
