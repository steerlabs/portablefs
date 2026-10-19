//go:build linux

package fusev3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type suspendAuthorityClock struct{ *subscriptionTestClock }

func (c suspendAuthorityClock) NewTimer(d time.Duration) volumeserver.CoherenceTimer {
	return c.subscriptionTestClock.NewTimer(d)
}

type suspendSubscriptionRPC struct {
	subscriptionRPC
	clock *subscriptionTestClock
}

func (r suspendSubscriptionRPC) Subscribe(ctx context.Context, snapshot, after []byte) (*authoritypb.SubscribeReply, time.Time, error) {
	reply, _, err := r.subscriptionRPC.Subscribe(ctx, snapshot, after)
	return reply, r.clock.Now().Add(volumeserver.SubscriptionTTL), err
}

// CONTROL and Go timers remain parked while elapsed time passes the remote
// horizon. A peer's completed withdrawal then permits its create and setattr.
// New callbacks must refuse the old daemon answers before any renewal runs.
func TestSubscriptionSuspendRefusesFreshCachedLookupAndGetattr(t *testing.T) {
	f := newStockFixture(t)
	sub := f.mount.subscription
	timers := make(chan *subscriptionTestTimer, 4)
	clock := &subscriptionTestClock{now: sub.config.clock.Now(), timers: timers}
	sub.config.clock = clock
	sub.rpc = suspendSubscriptionRPC{subscriptionRPC: f.rpc, clock: clock}
	item := testItem(93, authoritypb.Attr_REGULAR, 93)
	item.Attr.Size = 11
	f.rpc.byName = map[string]*authoritypb.Item{"existing": item}
	f.rpc.missingNames["missing"] = true
	existing := f.lookup(t, 1, "existing")
	f.lookup(t, 1, "missing")
	calls := f.rpcCalls()
	f.lookup(t, 1, "missing")
	var warm fuse.AttrOut
	if status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: existing.NodeId}}, &warm)
	}); status != fuse.OK || warm.Size != 11 || f.rpcCalls() != calls {
		t.Fatalf("cache not warm: status=%v size=%d calls=%d/%d", status, warm.Size, f.rpcCalls(), calls)
	}

	authority := volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{Clock: suspendAuthorityClock{clock}})
	parent := f.raw.nodesByID[1]
	record := f.raw.nodesByID[existing.NodeId]
	sleeper, err := authority.SubscribeWithCache(volumeserver.SessionID{1}, volumeserver.CacheAdmission{Directories: [][16]byte{parent.identity}, Attributes: [][16]byte{record.identity}})
	if err != nil {
		t.Fatal(err)
	}
	// Start only the expiry worker. The fixture's CONTROL poll blocks until
	// cancellation, and no renewer is running; no event can rescue admission.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	incarnation := sub.incarnation
	horizonDone := make(chan error, 1)
	controlParked, controlDone := make(chan struct{}), make(chan error, 1)
	go func() {
		close(controlParked)
		_, err := f.rpc.NextControlEvent(ctx, incarnation, 0, 0)
		controlDone <- err
	}()
	<-controlParked
	go func() { horizonDone <- sub.horizonLoop(ctx, incarnation) }()
	timer := <-timers
	activeStart := time.Now()
	clock.advance(11 * time.Second)
	select {
	case <-timer.C():
		t.Fatal("suspend fired an active-time timer")
	default:
	}
	source, err := authority.Subscribe(volumeserver.SessionID{2})
	if err != nil {
		t.Fatal(err)
	}
	f.rpc.mu.Lock()
	delete(f.rpc.missingNames, "missing")
	f.rpc.byName["missing"] = testItem(94, authoritypb.Attr_REGULAR, 94)
	item.Attr.Size = 99
	f.rpc.mu.Unlock()
	withdrawal := authority.OnCommitTargeted([]volumeserver.ChangeEntry{
		{Kind: volumeserver.NamespaceChanged, ParentIdentity: parent.identity, Name: "missing", VolumeVersion: 2},
		{Kind: volumeserver.AttributesChanged, Identity: record.identity, VolumeVersion: 2},
	}, source.Token, volumeserver.CacheAdmission{})
	if err := authority.WaitTargeted(t.Context(), withdrawal); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-controlDone:
		t.Fatalf("CONTROL escaped its delivery hold: %v", err)
	default:
	}
	if sub.lastChangeSeen != 0 || sub.lastChangeAck != 0 {
		t.Fatal("CONTROL delivered the peer mutation before admission")
	}

	if err := authority.CheckSession(sleeper.Token); !errors.Is(err, volumeserver.ErrSubscription) && !errors.Is(err, volumeserver.ErrSessionFenced) {
		t.Fatalf("remote sleeper still live: %v", err)
	}

	// Exercise both fast cache admissions first, before any worker or callback
	// can withdraw the payload. No old answer can enter the physical reply map.
	if f.raw.lookupCachedReply(f.unique.Add(2), parent, "missing", &fuse.EntryOut{}) {
		t.Error("fresh LOOKUP admitted stale ENOENT after suspend")
	}
	if f.raw.attrCachedReply(f.unique.Add(2), record, &fuse.AttrOut{}) {
		t.Error("fresh GETATTR admitted stale size after suspend")
	}
	select {
	case err := <-horizonDone:
		if !errors.Is(err, errSubscriptionExpired) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("admission expiry did not wake cold withdrawal")
	}
	if time.Since(activeStart) >= volumeserver.SubscriptionTTL {
		t.Fatal("test advanced Go active time through the horizon")
	}
	if sub.stamp().incarnation != 0 || f.mount.delegations.incarnation() != 0 {
		t.Fatal("expired permission remained admissible")
	}
	// Fresh public callbacks also cannot publish either old answer.
	var lookup fuse.EntryOut
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "missing", &lookup)
	})
	if status == fuse.OK && lookup.NodeId == 0 {
		t.Fatal("fresh raw LOOKUP published stale ENOENT")
	}
	var attr fuse.AttrOut
	status = f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: existing.NodeId}}, &attr)
	})
	if status == fuse.OK && attr.Size == 11 {
		t.Fatal("fresh raw GETATTR published stale size")
	}
	if err := sub.subscribe(t.Context()); err != nil {
		t.Fatalf("cold withdrawal/resubscribe: %v", err)
	}
	if len(f.notify.snapshot()) == 0 {
		t.Fatal("cold subscription skipped kernel invalidation")
	}
	if f.raw.cachedNegatives[nameKey{parent: 1, name: "missing"}] != "" {
		t.Fatal("cold subscription retained stale negative")
	}
}

func TestSubscriptionSuspendRejectsAlreadyAdmittedCachePublication(t *testing.T) {
	for _, operation := range []string{"lookup", "positive-lookup", "getattr"} {
		t.Run(operation, func(t *testing.T) {
			f := newStockFixture(t)
			sub := f.mount.subscription
			clock := &subscriptionTestClock{now: sub.config.clock.Now()}
			sub.config.clock = clock
			item := testItem(95, authoritypb.Attr_REGULAR, 95)
			f.rpc.byName = map[string]*authoritypb.Item{"existing": item}
			entry := f.lookup(t, 1, "existing")
			f.rpc.missingNames["missing"] = true
			f.lookup(t, 1, "missing")
			record := f.raw.nodesByID[entry.NodeId]
			priorLookups := record.lookups
			unique := f.unique.Add(2)
			var status fuse.Status
			var opcode uint32
			if operation == "lookup" || operation == "positive-lookup" {
				name := "missing"
				if operation == "positive-lookup" {
					name = "existing"
				}
				opcode = 1
				status = f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, name, &fuse.EntryOut{})
			} else {
				opcode = 3
				status = f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{})
			}
			if status != fuse.OK {
				t.Fatal(status)
			}
			clock.advance(11 * time.Second)
			_, reply, prepare := f.raw.PrepareReplyPayload(unique, 0, opcode, nil, nil, 0)
			f.raw.ReplyWritten(unique, fuse.OK) // the EIO callback reply reached the kernel
			if reply != fuse.EIO || prepare != fuse.OK {
				t.Fatalf("expired cached publication: reply=%v prepare=%v", reply, prepare)
			}
			if f.mount.isRevoked() {
				t.Fatal("recoverable cache expiry revoked the mount")
			}
			if record.lookups != priorLookups {
				t.Fatalf("refused cached reply leaked lookup references: %d -> %d", priorLookups, record.lookups)
			}
		})
	}
}

func TestSubscriptionSuspendRejectsRenewalBeforeTimerRuns(t *testing.T) {
	sub, clock, _, _ := activeSubscriptionFixture(t, 7)
	deadline := clock.Now().Add(10 * time.Second)
	clock.advance(time.Minute)
	if sub.acceptRenewal(7, deadline) {
		t.Fatal("pre-suspend renewal revived an expired continuous horizon")
	}
	if sub.stamp().incarnation != 0 {
		t.Fatal("late renewal retained cache permission")
	}
}
