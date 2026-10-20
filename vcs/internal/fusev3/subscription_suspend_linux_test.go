//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type suspendAuthorityClock struct{ *subscriptionTestClock }

func assertMetadataPinReleased(t *testing.T, pin *delegationState) {
	t.Helper()
	if pin == nil {
		return
	}
	// Settlement can make this state idle and wake its collector, which also
	// takes admission. Exclude collection while testing for a leaked reader.
	pin.manager.mu.Lock()
	released := pin.admission.TryLock()
	if released {
		pin.admission.Unlock()
	}
	pin.manager.mu.Unlock()
	if !released {
		t.Fatal("settlement retained its metadata pin")
	}
}

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
	for _, operation := range []string{"lookup", "positive-lookup", "getattr", "holder-getattr", "slow-holder-getattr", "holder-lookup", "slow-holder-lookup", "holder-readdirplus"} {
		t.Run(operation, func(t *testing.T) {
			holder := strings.Contains(operation, "holder")
			var f *stockFixture
			var entry *fuse.EntryOut
			name := "existing"
			if holder {
				f, entry = dirtyHolderMetadataFixture(t)
				name = "cached"
			} else {
				f = newStockFixture(t)
				item := testItem(95, authoritypb.Attr_REGULAR, 95)
				f.rpc.byName = map[string]*authoritypb.Item{name: item}
				entry = f.lookup(t, 1, name)
				f.rpc.missingNames["missing"] = true
				f.lookup(t, 1, "missing")
			}
			sub := f.mount.subscription
			clock := &subscriptionTestClock{now: sub.config.clock.Now()}
			sub.config.clock = clock
			if strings.HasPrefix(operation, "slow-") {
				f.raw.cachedReplyFree = nil
			}
			record := f.raw.nodesByID[entry.NodeId]
			priorLookups, calls := record.lookups, f.rpcCalls()
			unique := f.unique.Add(2)
			var status fuse.Status
			var opcode uint32
			switch {
			case operation == "holder-readdirplus":
				dir, _ := testDirHandle(t, f.raw, metadataPage(f.rpc.item))
				opcode = 44
				status = f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: dir}, fuse.NewDirEntryList(make([]byte, 4096), 0))
			case strings.Contains(operation, "lookup"):
				if operation == "lookup" {
					name = "missing"
				}
				opcode = 1
				status = f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, name, &fuse.EntryOut{})
			default:
				opcode = 3
				var out fuse.AttrOut
				status = f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &out)
				if holder && (out.Size != 4101 || f.rpcCalls() != calls) {
					t.Fatalf("holder GETATTR missed retained overlay: size=%d RPCs=%d", out.Size, f.rpcCalls()-calls)
				}
			}
			if status != fuse.OK {
				t.Fatal(status)
			}
			p := f.raw.replyPublications[unique]
			if p == nil {
				t.Fatal("read omitted physical publication ownership")
			}
			pin := p.holderAdmission
			if holder && (pin == nil || strings.HasPrefix(operation, "slow-") && p.cachedArena) {
				t.Fatal("holder read omitted its pin or bypassed arena exhaustion")
			}
			clock.advance(11 * time.Second)
			_, reply, prepare := f.raw.PrepareReplyPayload(unique, 0, opcode, nil, nil, 0)
			f.raw.ReplyWritten(unique, fuse.OK) // the EIO callback reply reached the kernel
			if reply != fuse.EIO || prepare != fuse.OK {
				t.Errorf("expired cached publication: reply=%v prepare=%v", reply, prepare)
			}
			if f.mount.isRevoked() {
				t.Error("recoverable cache expiry revoked the mount")
			}
			if record.lookups != priorLookups {
				t.Errorf("refused read changed lookup references: %d -> %d", priorLookups, record.lookups)
			}
			assertMetadataPinReleased(t, pin)
			if f.raw.ReplyWriteTracked(unique) {
				t.Fatal("physically settled EIO retained publication ownership")
			}
		})
	}
	for _, tc := range []struct {
		name     string
		plus     bool
		retained bool
		eof      bool
	}{
		{name: "retained-readdirplus", plus: true, retained: true},
		{name: "retained-readdir", retained: true},
		{name: "retained-readdir-eof", retained: true, eof: true},
		{name: "fresh-readdirplus", plus: true},
		{name: "fresh-readdir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStockFixture(t)
			item := testItem(96, authoritypb.Attr_REGULAR, 96)
			f.rpc.byName = map[string]*authoritypb.Item{"existing": item}
			entry := f.lookup(t, 1, "existing")
			record := f.raw.nodesByID[entry.NodeId]
			sub := f.mount.subscription
			clock := &subscriptionTestClock{now: sub.config.clock.Now()}
			sub.config.clock = clock
			dir, _ := testDirHandle(t, f.raw, metadataPage(item, item))
			handle := f.raw.handles[dir].dir
			// Each one-byte name takes a 32-byte dirent, plus EntryOut in
			// PLUS. Force the authority page to span two kernel callbacks.
			bufferSize, opcode := 32, uint32(28)
			if tc.plus {
				bufferSize += int(unsafe.Sizeof(fuse.EntryOut{}))
				opcode = 44
			}
			if tc.eof {
				bufferSize *= 2
			}
			read := func(unique, offset uint64) *fuse.DirEntryList {
				out := fuse.NewDirEntryList(make([]byte, bufferSize), offset)
				input := &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: dir, Offset: offset}
				status := fuse.OK
				if tc.plus {
					status = f.raw.ReadDirPlus(nil, input, out)
				} else {
					status = f.raw.ReadDir(nil, input, out)
				}
				if status != fuse.OK {
					t.Fatal(status)
				}
				return out
			}
			consumption := &recordingResponseConsumption{}
			f.rpc.retainedConsumption = consumption
			priorLookups := record.lookups
			unique := f.unique.Add(2)
			first := read(unique, 0)
			wantOffset := uint64(1)
			if tc.eof {
				wantOffset = 2
			}
			if first.Offset != wantOffset || len(f.rpc.readdirs) != 1 {
				t.Fatalf("first callback: offset=%d RPCs=%d", first.Offset, len(f.rpc.readdirs))
			}
			if tc.retained {
				_, reply, prepare := f.raw.PrepareReplyPayload(unique, 0, opcode, nil, nil, 0)
				f.raw.ReplyWritten(unique, fuse.OK)
				if reply != fuse.OK || prepare != fuse.OK || consumption.calls.Load() != 1 {
					t.Fatalf("first page settlement: reply=%v prepare=%v consumed=%d", reply, prepare, consumption.calls.Load())
				}
				f.rpc.retainedConsumption = nil
				priorLookups = record.lookups
				calls := f.rpcCalls()
				unique = f.unique.Add(2)
				second := read(unique, first.Offset)
				if second.Offset != 2 || f.rpcCalls() != calls || len(f.rpc.readdirs) != 1 {
					t.Fatalf("retained page missed reuse: offset=%d RPCs=%d", second.Offset, f.rpcCalls()-calls)
				}
			}
			p := f.raw.replyPublications[unique]
			if p == nil || f.mount.delegations.Owns(record.identity[:]) || p.holderAdmission != nil && p.holderAdmission.ref != nil {
				t.Fatal("directory reply lost publication ownership or acquired a delegation")
			}
			if tc.plus && (record.lookups != priorLookups+1 || handle.plusReply == nil) {
				t.Fatal("PLUS omitted its provisional lookup or cursor")
			}
			pin := p.holderAdmission
			// CONTROL and renewal remain parked; only continuous time advances
			// after the complete callback, before its physical reply edge.
			clock.advance(11 * time.Second)
			_, reply, prepare := f.raw.PrepareReplyPayload(unique, 0, opcode, nil, nil, 0)
			f.raw.ReplyWritten(unique, fuse.OK) // the callback's reply reached the kernel
			wantReply := fuse.OK
			if tc.retained {
				wantReply = fuse.EIO
			}
			if reply != wantReply || prepare != fuse.OK {
				t.Errorf("directory publication after expiry: reply=%v prepare=%v, want %v/OK", reply, prepare, wantReply)
			}
			wantLookups := priorLookups
			if tc.plus && !tc.retained {
				wantLookups++
			}
			if record.lookups != wantLookups {
				t.Errorf("directory settlement changed lookup references: %d -> %d, want %d", priorLookups, record.lookups, wantLookups)
			}
			if tc.plus && (handle.plusReply != nil || handle.next != first.Offset || !bytes.Equal(handle.cookie, encodeCookie(first.Offset))) {
				t.Errorf("PLUS settlement lost cursor: next=%d cookie=%x pending=%v", handle.next, handle.cookie, handle.plusReply)
			}
			if f.mount.isRevoked() || f.raw.ReplyWriteTracked(unique) || consumption.calls.Load() != 1 {
				t.Fatal("directory settlement revoked the mount or retained reply ownership")
			}
			assertMetadataPinReleased(t, pin)
			f.rpc.retainedConsumption = nil
			sub.rpc = suspendSubscriptionRPC{subscriptionRPC: f.rpc, clock: clock}
			if err := sub.subscribe(t.Context()); err != nil {
				t.Fatalf("cold resubscription after directory reply: %v", err)
			}
			if next := f.lookup(t, 1, "existing"); next.NodeId != entry.NodeId || record.lookups != wantLookups+1 || f.mount.isRevoked() {
				t.Fatalf("mount unusable after directory recovery: node=%d lookups=%d revoked=%v", next.NodeId, record.lookups, f.mount.isRevoked())
			}
		})
	}
}

// The fixture runs callbacks synchronously with CONTROL and horizon workers
// parked. The first clock sample after the cached LOOKUP acquires its reference
// advances elapsed time, without depending on the number of admission checks.
type lookupSuspendClock struct {
	*subscriptionTestClock
	record       *inodeRecord
	priorLookups uint64
	suspended    bool
}

func (c *lookupSuspendClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.suspended && c.record.lookups > c.priorLookups {
		c.now = c.now.Add(11 * time.Second)
		c.suspended = true
	}
	return c.now
}

func TestSubscriptionSuspendInterruptedCachedLookupSettlesReferenceOnce(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "cached")
	record := f.raw.nodesByID[entry.NodeId]
	priorLookups, calls := record.lookups, f.rpcCalls()
	sub := f.mount.subscription
	clock := &lookupSuspendClock{subscriptionTestClock: &subscriptionTestClock{now: sub.config.clock.Now()}, record: record, priorLookups: priorLookups}
	sub.config.clock = clock
	f.raw.cachedReplyFree = nil
	unique := f.unique.Add(2)
	status := f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{})
	if status != fuse.EIO || !clock.suspended || f.rpcCalls() != calls {
		t.Fatalf("slow cached LOOKUP missed interruption: status=%v suspended=%v RPCs=%d", status, clock.suspended, f.rpcCalls()-calls)
	}
	p := f.raw.replyPublications[unique]
	if p == nil || p.cachedArena || p.lookupReference != record || p.holderAdmission != nil {
		t.Fatal("interrupted cache hit lost its physical lookup ownership or published metadata")
	}
	_, reply, prepare := f.raw.PrepareReplyPayload(unique, 1, 1, nil, nil, 0)
	f.raw.ReplyWritten(unique, fuse.OK)
	if reply != fuse.EIO || prepare != fuse.OK {
		t.Errorf("physical EIO lifecycle: reply=%v prepare=%v", reply, prepare)
	}
	if record.lookups != priorLookups {
		t.Errorf("interrupted cached LOOKUP released a kernel reference: %d -> %d", priorLookups, record.lookups)
	}
	if f.mount.isRevoked() || f.raw.ReplyWriteTracked(unique) {
		t.Fatal("interrupted cached LOOKUP left a revoked mount or unsettled reply")
	}
	// Exercise ordinary cold recovery and a new public callback on this mount.
	sub.config.clock = clock.subscriptionTestClock
	sub.rpc = suspendSubscriptionRPC{subscriptionRPC: f.rpc, clock: clock.subscriptionTestClock}
	if err := sub.subscribe(t.Context()); err != nil {
		t.Fatalf("cold resubscription after physical EIO: %v", err)
	}
	if next := f.lookup(t, 1, "cached"); next.NodeId != entry.NodeId || record.lookups != priorLookups+1 || f.mount.isRevoked() {
		t.Fatalf("mount unusable after recovery: node=%d lookups=%d revoked=%v", next.NodeId, record.lookups, f.mount.isRevoked())
	}
}

func TestSubscriptionSuspendPreservesAcceptedHolderMutation(t *testing.T) {
	for _, delegated := range []bool{false, true} {
		name := "authority"
		if delegated {
			name = "delegated"
		}
		t.Run(name, func(t *testing.T) {
			var f *stockFixture
			var entry *fuse.EntryOut
			if delegated {
				f, entry = dirtyHolderMetadataFixture(t)
			} else {
				f = newStockFixture(t)
				entry = f.lookup(t, 1, "cached")
			}
			sub := f.mount.subscription
			clock := &subscriptionTestClock{now: sub.config.clock.Now()}
			sub.config.clock = clock
			unique := f.unique.Add(2)
			in := &fuse.SetAttrIn{}
			in.Unique, in.NodeId, in.Valid, in.Mode = unique, entry.NodeId, fuse.FATTR_MODE, 0o640
			if status := f.raw.SetAttr(nil, in, &fuse.AttrOut{}); status != fuse.OK {
				t.Fatal(status)
			}
			p := f.raw.replyPublications[unique]
			if p == nil || p.holderAdmission == nil || p.source == nil || (p.postState == nil) != delegated {
				t.Fatal("mutation missed its metadata pin, source ownership or expected post-state")
			}
			pin := p.holderAdmission
			clock.advance(11 * time.Second)
			_, reply, prepare := f.raw.PrepareReplyPayload(unique, entry.NodeId, 4, nil, nil, 0)
			f.raw.ReplyWritten(unique, fuse.OK)
			if reply != fuse.OK || prepare != fuse.OK || f.mount.isRevoked() {
				t.Fatalf("accepted mutation lost its result: reply=%v prepare=%v revoked=%v", reply, prepare, f.mount.isRevoked())
			}
			assertMetadataPinReleased(t, pin)
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
