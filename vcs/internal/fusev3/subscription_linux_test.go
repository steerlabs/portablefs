//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type subscriptionTestClock struct {
	mu     sync.Mutex
	now    time.Time
	timers chan<- *subscriptionTestTimer
}

func (c *subscriptionTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

type subscriptionTestTimer struct {
	duration time.Duration
	fired    chan time.Time
}

func (t *subscriptionTestTimer) C() <-chan time.Time { return t.fired }
func (*subscriptionTestTimer) Stop() bool            { return true }

func (c *subscriptionTestClock) NewTimer(d time.Duration) subscriptionTimer {
	if c.timers != nil {
		timer := &subscriptionTestTimer{duration: d, fired: make(chan time.Time, 1)}
		c.timers <- timer
		return timer
	}
	return wallSubscriptionTimer{timer: time.NewTimer(d)}
}

func (c *subscriptionTestClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type subscriptionTestRPC struct {
	mu sync.Mutex

	pages       []*authoritypb.SubscribeReply
	page        int
	horizon     time.Time
	events      []*authoritypb.ControlEvent
	event       int
	eventNotify chan struct{}
	renewed     chan<- uint64
	acks        []uint64
	log         *[]string
}

func (r *subscriptionTestRPC) Subscribe(_ context.Context, snapshotID, after []byte) (*authoritypb.SubscribeReply, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.log != nil {
		*r.log = append(*r.log, "subscribe")
	}
	if r.page >= len(r.pages) {
		return nil, time.Time{}, errors.New("unexpected subscribe")
	}
	reply := r.pages[r.page]
	if r.page == 0 && (len(snapshotID) != 0 || len(after) != 0) {
		return nil, time.Time{}, errors.New("initial subscribe carried a cursor")
	}
	if r.page > 0 {
		if !bytes.Equal(snapshotID, r.pages[0].GetSnapshotId()) ||
			!bytes.Equal(after, r.pages[r.page-1].GetNextAfterIdentity()) {
			return nil, time.Time{}, errors.New("continuation subscribe carried the wrong snapshot cursor")
		}
	}
	r.page++
	return reply, r.horizon, nil
}

func (r *subscriptionTestRPC) RenewSubscription(_ context.Context, incarnation uint64) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.renewed != nil {
		r.renewed <- incarnation
	}
	return r.horizon, nil
}

func (r *subscriptionTestRPC) NextControlEvent(ctx context.Context, _ uint64, _ uint64, _ uint64) (*authoritypb.ControlEvent, error) {
	r.mu.Lock()
	if r.event < len(r.events) {
		event := r.events[r.event]
		r.event++
		if r.eventNotify != nil {
			select {
			case r.eventNotify <- struct{}{}:
			default:
			}
		}
		r.mu.Unlock()
		return event, nil
	}
	r.mu.Unlock()
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r *subscriptionTestRPC) AcknowledgeChanges(_ context.Context, _ uint64, position uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.acks = append(r.acks, position)
	if r.log != nil {
		*r.log = append(*r.log, "ack")
	}
	return nil
}

type subscriptionTestInvalidator struct {
	mu sync.Mutex

	all       int
	closed    []publicationCoordinate
	opened    []publicationCoordinate
	stale     []publicationIdentity
	log       *[]string
	fail      error
	block     <-chan struct{}
	entered   chan<- struct{}
	blockOnce sync.Once
}

func (i *subscriptionTestInvalidator) CloseCacheCoordinate(_ context.Context, coordinate publicationCoordinate) error {
	i.mu.Lock()
	i.closed = append(i.closed, coordinate)
	if i.log != nil {
		*i.log = append(*i.log, "close")
	}
	i.mu.Unlock()
	return nil
}

func (i *subscriptionTestInvalidator) InvalidateCacheCoordinate(context.Context, publicationCoordinate, *authoritypb.ByteRange) error {
	i.blockOnce.Do(func() {
		if i.entered != nil {
			i.entered <- struct{}{}
		}
		if i.block != nil {
			<-i.block
		}
	})
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.log != nil {
		*i.log = append(*i.log, "invalidate")
	}
	return i.fail
}

func (i *subscriptionTestInvalidator) OpenCacheCoordinate(context publicationCoordinate) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.opened = append(i.opened, context)
	if i.log != nil {
		*i.log = append(*i.log, "open")
	}
}

func (i *subscriptionTestInvalidator) InvalidateAllCaches(context.Context) error {
	i.mu.Lock()
	i.all++
	i.mu.Unlock()
	return nil
}

func (i *subscriptionTestInvalidator) MarkIdentityStale(identity publicationIdentity) {
	i.mu.Lock()
	i.stale = append(i.stale, identity)
	i.mu.Unlock()
}

type subscriptionTestControl struct {
	mu          sync.Mutex
	incarnation uint64
	events      []*authoritypb.ControlEvent
	delivered   chan struct{}
	fences      []string
	log         *[]string
}

func (c *subscriptionTestControl) InterruptSubscription() {
	c.mu.Lock()
	c.incarnation = 0
	if c.log != nil {
		*c.log = append(*c.log, "interrupt")
	}
	c.mu.Unlock()
}

func (c *subscriptionTestControl) FenceSubscription(reason string) {
	c.mu.Lock()
	c.fences = append(c.fences, reason)
	if c.log != nil {
		*c.log = append(*c.log, "fence")
	}
	c.mu.Unlock()
}

func (c *subscriptionTestControl) SetIncarnation(incarnation uint64) {
	c.mu.Lock()
	c.incarnation = incarnation
	if c.log != nil {
		*c.log = append(*c.log, "incarnation")
	}
	c.mu.Unlock()
}

func (c *subscriptionTestControl) HandleControlEvent(_ context.Context, event *authoritypb.ControlEvent) <-chan struct{} {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.mu.Unlock()
	if c.delivered != nil {
		select {
		case c.delivered <- struct{}{}:
		default:
		}
	}
	done := make(chan struct{})
	close(done)
	return done
}

func subscriptionIdentity(value byte) publicationIdentity {
	var identity publicationIdentity
	for index := range identity {
		identity[index] = value
	}
	return identity
}

func subscriptionIdentityBytes(value byte) []byte {
	identity := subscriptionIdentity(value)
	return bytes.Clone(identity[:])
}

func newSubscriptionTestRegistry(clock *subscriptionTestClock, rpc *subscriptionTestRPC, invalidator *subscriptionTestInvalidator, control subscriptionControlHandler) *subscriptionRegistry {
	return newSubscriptionRegistryWithConfig(nil, rpc, control, subscriptionConfig{
		clock: clock, retryDelay: time.Millisecond, repairLead: time.Second,
		maxPages: 16, invalidator: invalidator,
	})
}

func TestSubscriptionColdPaginationWatermarkAndStaleReply(t *testing.T) {
	clock := &subscriptionTestClock{now: time.Unix(100, 0)}
	controlLog := make([]string, 0, 4)
	rpc := &subscriptionTestRPC{
		horizon: clock.Now().Add(10 * time.Second),
		log:     &controlLog,
		pages: []*authoritypb.SubscribeReply{
			{Watermark: 10, Incarnation: 7, HorizonNanos: uint64(10 * time.Second), SnapshotId: []byte("snapshot"), DelegatedIdentities: [][]byte{subscriptionIdentityBytes(1)}, NextAfterIdentity: subscriptionIdentityBytes(1)},
			{Watermark: 10, Incarnation: 7, HorizonNanos: uint64(10 * time.Second), SnapshotId: []byte("snapshot"), DelegatedIdentities: [][]byte{subscriptionIdentityBytes(2)}},
		},
	}
	invalidator := &subscriptionTestInvalidator{}
	control := &subscriptionTestControl{log: &controlLog}
	registry := newSubscriptionTestRegistry(clock, rpc, invalidator, control)
	if err := registry.subscribe(context.Background()); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if invalidator.all != 1 {
		t.Fatalf("cold invalidations = %d, want 1", invalidator.all)
	}
	if control.incarnation != 7 {
		t.Fatalf("delegation incarnation = %d, want 7", control.incarnation)
	}
	if len(control.fences) != 1 || control.fences[0] != "cold subscription replacement" {
		t.Fatalf("delegation fences = %v, want one cold replacement", control.fences)
	}
	wantControlLog := []string{"interrupt", "fence", "subscribe", "subscribe", "incarnation"}
	if !slices.Equal(controlLog, wantControlLog) {
		t.Fatalf("cold subscription order = %v, want %v", controlLog, wantControlLog)
	}

	stamp := registry.stamp()
	identity := subscriptionIdentity(1)
	attr := publicationCoordinate{kind: publicationItemAttributes, item: identity}
	name := publicationCoordinate{kind: publicationNamespaceName, parent: identity, name: "file"}
	if got := registry.remaining(attr, stamp, 10, clock.Now()); got != 0 {
		t.Fatalf("delegated attribute remained cacheable for %s", got)
	}
	if got := registry.remaining(name, stamp, 9, clock.Now()); got != 0 {
		t.Fatalf("pre-watermark name remained cacheable for %s", got)
	}
	if got := registry.remaining(name, stamp, 10, clock.Now()); got <= 0 {
		t.Fatalf("watermark name was not cacheable: %s", got)
	}

	entry := &authoritypb.ChangeEntry{Position: 1, VolumeVersion: 11, Kind: authoritypb.ChangeKind_CHANGE_KIND_NAMESPACE_CHANGED, ParentIdentity: identity[:], Name: []byte("file")}
	batch := &authoritypb.ChangeBatch{Incarnation: 7, Entries: []*authoritypb.ChangeEntry{entry}}
	if err := registry.registerChangeBatch(7, batch); err != nil {
		t.Fatalf("register change: %v", err)
	}
	if got := registry.remaining(name, stamp, 11, clock.Now()); got != 0 {
		t.Fatalf("pre-withdrawal stamp remained cacheable for %s", got)
	}
	fresh := registry.stamp()
	if got := registry.remaining(name, fresh, 10, clock.Now()); got != 0 {
		t.Fatalf("reply older than coordinate version remained cacheable for %s", got)
	}
	if got := registry.remaining(name, fresh, 11, clock.Now()); got <= 0 {
		t.Fatalf("fresh reply at change version was not cacheable: %s", got)
	}

	clock.advance(9 * time.Second)
	if got := registry.remaining(name, fresh, 11, clock.Now()); got != 0 {
		t.Fatalf("cache survived conservative horizon for %s", got)
	}
}

func TestSubscriptionAckFollowsProvenWithdrawal(t *testing.T) {
	clock := &subscriptionTestClock{now: time.Unix(200, 0)}
	log := make([]string, 0, 4)
	rpc := &subscriptionTestRPC{horizon: clock.Now().Add(10 * time.Second), log: &log}
	invalidator := &subscriptionTestInvalidator{log: &log}
	registry := newSubscriptionTestRegistry(clock, rpc, invalidator, nil)
	registry.mu.Lock()
	registry.active, registry.incarnation = true, 3
	registry.horizon, registry.cacheUntil = rpc.horizon, rpc.horizon.Add(-time.Second)
	registry.mu.Unlock()
	identity := subscriptionIdentity(3)
	entry := &authoritypb.ChangeEntry{Position: 1, VolumeVersion: 4, Kind: authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED, Identity: identity[:]}
	batch := &authoritypb.ChangeBatch{Incarnation: 3, Entries: []*authoritypb.ChangeEntry{entry}}
	if err := registry.registerChangeBatch(3, batch); err != nil {
		t.Fatalf("register: %v", err)
	}
	queue := newSubscriptionChangeQueue()
	if err := queue.push(batch, 0); err != nil {
		t.Fatalf("queue: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- registry.changeLoop(ctx, 3, queue) }()
	deadline := time.After(time.Second)
	for {
		rpc.mu.Lock()
		acked := len(rpc.acks) != 0
		rpc.mu.Unlock()
		if acked {
			break
		}
		select {
		case <-deadline:
			t.Fatal("change acknowledgment did not arrive")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	queue.close()
	<-done
	want := []string{"close", "invalidate", "open", "ack"}
	if len(log) != len(want) {
		t.Fatalf("withdrawal log = %v, want %v", log, want)
	}
	for index := range want {
		if log[index] != want[index] {
			t.Fatalf("withdrawal log = %v, want %v", log, want)
		}
	}
}

func TestSubscriptionFailedNotifyMarksIdentityStaleWithoutAck(t *testing.T) {
	clock := &subscriptionTestClock{now: time.Now()}
	rpc := &subscriptionTestRPC{horizon: clock.Now().Add(time.Second)}
	invalidator := &subscriptionTestInvalidator{fail: errors.New("notify busy")}
	registry := newSubscriptionRegistryWithConfig(nil, rpc, nil, subscriptionConfig{
		clock: wallSubscriptionClock{}, retryDelay: time.Millisecond, repairLead: 5 * time.Millisecond,
		maxPages: 2, invalidator: invalidator,
	})
	registry.mu.Lock()
	registry.active, registry.incarnation = true, 9
	registry.horizon, registry.cacheUntil = time.Now().Add(time.Second), time.Now().Add(time.Second)
	registry.mu.Unlock()
	identity := subscriptionIdentity(9)
	entry := &authoritypb.ChangeEntry{Position: 1, VolumeVersion: 1, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:]}
	batch := &authoritypb.ChangeBatch{Incarnation: 9, Entries: []*authoritypb.ChangeEntry{entry}}
	if err := registry.registerChangeBatch(9, batch); err != nil {
		t.Fatalf("register: %v", err)
	}
	queue := newSubscriptionChangeQueue()
	if err := queue.push(batch, 0); err != nil {
		t.Fatalf("queue: %v", err)
	}
	if err := registry.changeLoop(context.Background(), 9, queue); err == nil {
		t.Fatal("change loop accepted an unconfirmed invalidation")
	}
	if len(invalidator.stale) != 1 || invalidator.stale[0] != identity {
		t.Fatalf("stale identities = %x, want %x", invalidator.stale, identity)
	}
	if len(rpc.acks) != 0 {
		t.Fatalf("acknowledged unconfirmed invalidation: %v", rpc.acks)
	}
}

func TestSubscriptionPollDeliversDelegationWhileWithdrawalBlocked(t *testing.T) {
	clock := &subscriptionTestClock{now: time.Now()}
	identity := subscriptionIdentity(4)
	change := &authoritypb.ChangeEntry{Position: 1, VolumeVersion: 1, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:]}
	rpc := &subscriptionTestRPC{events: []*authoritypb.ControlEvent{
		{Incarnation: 5, Sequence: 1, Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{Incarnation: 5, Entries: []*authoritypb.ChangeEntry{change}}}},
		{Incarnation: 5, Sequence: 2, Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{Identity: identity[:]}}},
	}}
	unblock := make(chan struct{})
	entered := make(chan struct{}, 1)
	invalidator := &subscriptionTestInvalidator{block: unblock, entered: entered}
	control := &subscriptionTestControl{delivered: make(chan struct{}, 1)}
	registry := newSubscriptionTestRegistry(clock, rpc, invalidator, control)
	registry.mu.Lock()
	registry.active, registry.incarnation = true, 5
	registry.horizon, registry.cacheUntil = clock.Now().Add(time.Minute), clock.Now().Add(time.Minute)
	registry.mu.Unlock()
	queue := newSubscriptionChangeQueue()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changeDone := make(chan error, 1)
	go func() { changeDone <- registry.changeLoop(ctx, 5, queue) }()
	pollDone := make(chan error, 1)
	go func() { pollDone <- registry.pollLoop(ctx, 5, queue) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("withdrawal never entered invalidation")
	}
	select {
	case <-control.delivered:
	case <-time.After(time.Second):
		t.Fatal("delegation event was blocked behind withdrawal")
	}
	close(unblock)
	cancel()
	queue.close()
	<-changeDone
	<-pollDone
}

func TestSubscriptionSuspendDrainsWorkersBeforeResume(t *testing.T) {
	clock := &subscriptionTestClock{now: time.Now()}
	rpc := &subscriptionTestRPC{}
	registry := newSubscriptionTestRegistry(clock, rpc, &subscriptionTestInvalidator{}, nil)
	registry.mu.Lock()
	registry.active, registry.incarnation = true, 12
	registry.horizon, registry.cacheUntil = clock.Now().Add(time.Minute), clock.Now().Add(time.Minute)
	registry.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- registry.serveIncarnation(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for {
		registry.mu.RLock()
		serving := registry.serveDone
		registry.mu.RUnlock()
		select {
		case <-serving:
			if time.Now().After(deadline) {
				t.Fatal("subscription workers did not start")
			}
			time.Sleep(time.Millisecond)
			continue
		default:
		}
		break
	}
	registry.suspend()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := registry.drainSuspended(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, errSubscriptionExpired) {
		t.Fatalf("serve after suspension = %v, want expiration", err)
	}
	if stamp := registry.stamp(); stamp != (subscriptionStamp{}) {
		t.Fatalf("suspended subscription issued stamp %+v", stamp)
	}
	registry.resume()
	registry.mu.RLock()
	paused := registry.paused
	registry.mu.RUnlock()
	if paused {
		t.Fatal("resume left subscription paused")
	}
}

func TestSubscriptionHorizonInvalidatesAllCaches(t *testing.T) {
	now := time.Now()
	rpc := &subscriptionTestRPC{
		horizon: now.Add(time.Minute),
		pages: []*authoritypb.SubscribeReply{{
			Watermark: 2, Incarnation: 24, HorizonNanos: uint64(time.Minute), SnapshotId: []byte("replacement"),
		}},
	}
	invalidator := &subscriptionTestInvalidator{}
	control := &subscriptionTestControl{}
	registry := newSubscriptionRegistryWithConfig(nil, rpc, control, subscriptionConfig{
		clock: wallSubscriptionClock{}, retryDelay: time.Millisecond, repairLead: time.Millisecond,
		maxPages: 2, invalidator: invalidator,
	})
	registry.mu.Lock()
	registry.active, registry.incarnation = true, 23
	registry.horizon = now.Add(30 * time.Millisecond)
	registry.cacheUntil = now.Add(15 * time.Millisecond)
	registry.mu.Unlock()

	err := registry.serveIncarnation(context.Background())
	if !errors.Is(err, errSubscriptionExpired) {
		t.Fatalf("serve at horizon = %v, want subscription expiry", err)
	}
	invalidator.mu.Lock()
	invalidations := invalidator.all
	invalidator.mu.Unlock()
	if invalidations != 1 {
		t.Fatalf("cold invalidations after horizon = %d, want 1", invalidations)
	}
	if stamp := registry.stamp(); stamp != (subscriptionStamp{}) {
		t.Fatalf("expired subscription issued stamp %+v", stamp)
	}
	if err := registry.subscribe(context.Background()); err != nil {
		t.Fatalf("cold subscribe after horizon: %v", err)
	}
	control.mu.Lock()
	fences := slices.Clone(control.fences)
	incarnation := control.incarnation
	control.mu.Unlock()
	if len(fences) != 1 || incarnation != 24 {
		t.Fatalf("cold recovery delegation fence/incarnation = %v/%d, want one fence then 24", fences, incarnation)
	}
}

func TestColdSubscriptionNeverClearsEpochStaleness(t *testing.T) {
	fixture := newStrictFixture(t)
	root := fixture.raw.acquire(1)
	if root == nil {
		t.Fatal("root inode")
	}
	defer fixture.raw.release(root)
	negative := nameKey{parent: root.key.inode, name: "absent"}
	fixture.raw.mu.Lock()
	fixture.raw.bindCachedNegativeLocked(negative, subscriptionStamp{incarnation: 1, generation: 1, version: 1})
	fixture.raw.mu.Unlock()
	epochRecord, errno := fixture.raw.intern(context.Background(), testItem(78, authoritypb.Attr_REGULAR, 78))
	if errno != 0 {
		t.Fatal(errno)
	}
	repairableRecord, errno := fixture.raw.intern(context.Background(), testItem(79, authoritypb.Attr_REGULAR, 79))
	if errno != 0 {
		t.Fatal(errno)
	}
	epochRecord.stale.Store(true)
	epochRecord.node.stale.Store(true)
	epochRecord.node.epochStale.Store(true)
	repairableRecord.stale.Store(true)
	repairableRecord.node.stale.Store(true)

	if err := fixture.raw.invalidateAllCaches(context.Background()); err != nil {
		t.Fatalf("cold invalidation: %v", err)
	}
	if !epochRecord.stale.Load() || !epochRecord.node.stale.Load() || !epochRecord.node.epochStale.Load() {
		t.Fatal("cold subscription resurrected an old-epoch inode")
	}
	if repairableRecord.stale.Load() || repairableRecord.node.stale.Load() {
		t.Fatal("cold subscription retained repairable coherence staleness")
	}
	fixture.raw.mu.Lock()
	_, retainedNegative := fixture.raw.cachedNegatives[negative]
	fixture.raw.mu.Unlock()
	if retainedNegative {
		t.Fatal("cold subscription retained a daemon negative entry")
	}
	fixture.notify.mu.Lock()
	defer fixture.notify.mu.Unlock()
	foundNegativeNotify := false
	for _, call := range fixture.notify.calls {
		if call.kind == "entry" && call.parent == root.id && call.name == negative.name {
			foundNegativeNotify = true
		}
	}
	if !foundNegativeNotify {
		t.Fatal("cold subscription omitted notification for a cached negative name")
	}
}

func TestUnlicensedReadRemainsIndexedUntilPostWritePurge(t *testing.T) {
	fixture := newStrictFixture(t)
	record, errno := fixture.raw.intern(context.Background(), testItem(80, authoritypb.Attr_REGULAR, 80))
	if errno != 0 {
		t.Fatal(errno)
	}
	unique := fixture.unique.Add(2)
	ctx, finish, status := fixture.raw.mutationContext(unique)
	if !status.Ok() {
		t.Fatal(status)
	}
	if !fixture.raw.beginBufferedRead(ctx, record) {
		t.Fatal("buffered read was not admitted")
	}
	finish()
	fixture.mount.subscription.deactivate()
	if _, _, payloadStatus := fixture.raw.PrepareReplyPayload(unique, record.id, 15, nil, nil, 0); !payloadStatus.Ok() {
		t.Fatalf("prepare unlicensed READ reply: %v", payloadStatus)
	}

	coordinate := publicationCoordinate{kind: publicationItemData, item: record.identity}
	fixture.raw.mu.Lock()
	publication := fixture.raw.replyPublications[unique]
	_, indexed := fixture.raw.dataPublications[record.identity][publication]
	unlicensed := publication != nil && len(publication.unlicensed) == 1
	fixture.raw.mu.Unlock()
	if !indexed || !unlicensed {
		t.Fatalf("finalized unlicensed READ = indexed %t unlicensed %t, want true/true", indexed, unlicensed)
	}

	notifyEntered := make(chan struct{}, 1)
	notifyRelease := make(chan struct{})
	fixture.notify.mu.Lock()
	fixture.notify.block = notifyRelease
	fixture.notify.onInode = func(uint64, int64, int64) { notifyEntered <- struct{}{} }
	fixture.notify.mu.Unlock()
	closeDone := make(chan error, 1)
	closeCtx, cancelClose := context.WithTimeout(context.Background(), time.Second)
	defer cancelClose()
	go func() { _, err := fixture.raw.closeCacheCoordinate(closeCtx, coordinate); closeDone <- err }()
	replyDone := make(chan struct{})
	go func() {
		fixture.raw.ReplyWritten(unique, fuse.OK)
		close(replyDone)
	}()
	select {
	case <-notifyEntered:
	case <-time.After(time.Second):
		close(notifyRelease)
		t.Fatal("unlicensed READ did not enter its post-write purge")
	}
	select {
	case err := <-closeDone:
		close(notifyRelease)
		t.Fatalf("coordinate withdrawal crossed the blocked post-write purge: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(notifyRelease)
	select {
	case <-replyDone:
	case <-time.After(time.Second):
		t.Fatal("unlicensed READ reply did not settle after its purge")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("coordinate withdrawal did not resume after physical reply drain")
	}
	fixture.raw.mu.Lock()
	_, retained := fixture.raw.dataPublications[record.identity][publication]
	fixture.raw.mu.Unlock()
	if retained || fixture.raw.ReplyWriteTracked(unique) {
		t.Fatal("settled READ remained in the per-identity publication index")
	}
}

func TestCancelledBufferedReadReleasesIdentityIndex(t *testing.T) {
	fixture := newStrictFixture(t)
	record, errno := fixture.raw.intern(context.Background(), testItem(81, authoritypb.Attr_REGULAR, 81))
	if errno != 0 {
		t.Fatal(errno)
	}
	unique := fixture.unique.Add(2)
	ctx, finish, status := fixture.raw.mutationContext(unique)
	if !status.Ok() {
		t.Fatal(status)
	}
	if !fixture.raw.beginBufferedRead(ctx, record) {
		t.Fatal("buffered read was not admitted")
	}
	fixture.raw.mu.Lock()
	publication := fixture.raw.replyPublications[unique]
	fixture.raw.mu.Unlock()
	fixture.raw.cancelBufferedRead(ctx, record)
	finish()

	fixture.raw.mu.Lock()
	_, indexed := fixture.raw.dataPublications[record.identity][publication]
	fixture.raw.mu.Unlock()
	if indexed {
		t.Fatal("canceled READ leaked its per-identity publication index")
	}
	if fixture.raw.ReplyWriteTracked(unique) {
		t.Fatal("empty canceled READ retained physical reply tracking")
	}
}

var benchmarkSubscriptionDuration time.Duration

func BenchmarkSubscriptionCachePermission(b *testing.B) {
	clock := &subscriptionTestClock{now: time.Unix(500, 0)}
	registry := newSubscriptionTestRegistry(clock, &subscriptionTestRPC{}, &subscriptionTestInvalidator{}, nil)
	registry.mu.Lock()
	registry.active = true
	registry.incarnation = 31
	registry.generation = 1
	registry.watermark = 1
	registry.horizon = clock.Now().Add(time.Hour)
	registry.cacheUntil = registry.horizon.Add(-time.Second)
	registry.mu.Unlock()
	coordinate := publicationCoordinate{kind: publicationNamespaceName, parent: subscriptionIdentity(31), name: "benchmark"}
	stamp := registry.stamp().withVersion(1)
	now := clock.Now()
	b.ReportAllocs()
	b.ResetTimer()
	var remaining time.Duration
	for range b.N {
		remaining = registry.remaining(coordinate, stamp, stamp.version, now)
	}
	benchmarkSubscriptionDuration = remaining
}

func BenchmarkSubscriptionChangeAdmission(b *testing.B) {
	clock := &subscriptionTestClock{now: time.Unix(600, 0)}
	registry := newSubscriptionTestRegistry(clock, &subscriptionTestRPC{}, &subscriptionTestInvalidator{}, nil)
	registry.mu.Lock()
	registry.active = true
	registry.incarnation = 32
	registry.horizon = clock.Now().Add(time.Hour)
	registry.cacheUntil = registry.horizon.Add(-time.Second)
	registry.mu.Unlock()
	identity := subscriptionIdentity(32)
	entry := &authoritypb.ChangeEntry{
		Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:],
	}
	batch := &authoritypb.ChangeBatch{Incarnation: 32, Entries: []*authoritypb.ChangeEntry{entry}}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		position := uint64(index + 1)
		entry.Position = position
		entry.VolumeVersion = position
		if err := registry.registerChangeBatch(32, batch); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSubscriptionLocalPromotedOwnershipClosesCacheAdmission(t *testing.T) {
	mount, _ := testMount(t, 8)
	identity := delegationTestIdentity(24)
	coordinate := publicationCoordinate{kind: publicationItemAttributes}
	copy(coordinate.item[:], identity)
	stamp := mount.subscription.stamp()
	if got := mount.subscription.remaining(coordinate, stamp, 1, time.Now()); got <= 0 {
		t.Fatalf("initial permission=%v", got)
	}
	if err := mount.delegations.Install(identity, []byte{24, 1}, []byte{24, 2}, delegationTestGrant(56, authoritypb.DelegationMode_DELEGATION_MODE_FULL)); err != nil {
		t.Fatal(err)
	}
	if got := mount.subscription.remaining(coordinate, stamp, 1, time.Now()); got != 0 {
		t.Fatalf("locally owned identity retains cache permission=%v", got)
	}

	if _, present := mount.subscription.delegated[coordinate.item]; present {
		t.Fatal("test depends on a holder-local grant event")
	}
	id, err := delegationIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	state := mount.delegations.state(id)
	state.admission.Lock()
	state.clearGrantLocked()
	state.admission.Unlock()
	if got := mount.subscription.remaining(coordinate, stamp, 1, time.Now()); got <= 0 {
		t.Fatalf("released local grant retains cache exclusion=%v", got)
	}
}

func TestControlCompletionReceiptWaitsForEveryEarlierHandler(t *testing.T) {
	queue := newSubscriptionChangeQueue()
	queue.complete(2)
	if got := queue.completedThrough(); got != 0 {
		t.Fatalf("receipt skipped unfinished event 1: %d", got)
	}
	queue.complete(1)
	if got := queue.completedThrough(); got != 2 {
		t.Fatalf("receipt=%d", got)
	}
	queue.complete(1)
	for sequence := uint64(3); sequence <= 10000; sequence++ {
		queue.complete(sequence)
	}
	if queue.completedThrough() != 10000 || len(queue.finished) != 0 {
		t.Fatalf("completion retained history: %+v", queue)
	}
}

func TestNamespaceWithdrawalPurgesBindingsWithoutEntryNotify(t *testing.T) {
	fixture := newStrictFixture(t)
	root := fixture.raw.acquire(1)
	defer fixture.raw.release(root)
	coordinate := publicationCoordinate{kind: publicationNamespaceName, parent: root.identity, name: "absent"}
	key := nameKey{parent: root.key.inode, name: coordinate.name}
	fixture.raw.mu.Lock()
	fixture.raw.bindCachedNegativeLocked(key, fixture.mount.subscription.stamp())
	fixture.raw.mu.Unlock()
	fixture.notify.entryST = fuse.EIO
	if err := fixture.raw.invalidateCacheCoordinateContext(context.Background(), coordinate, nil); err != nil {
		t.Fatalf("zero-validity namespace withdrawal: %v", err)
	}
	fixture.raw.mu.Lock()
	_, retained := fixture.raw.cachedNegatives[key]
	fixture.raw.mu.Unlock()
	if retained {
		t.Fatal("withdrawal retained the negative binding")
	}
	fixture.notify.mu.Lock()
	defer fixture.notify.mu.Unlock()
	if len(fixture.notify.calls) != 0 {
		t.Fatal("namespace withdrawal issued EntryNotify, which can wait on a CREATE parent lock")
	}
}

func TestCachedLookupWaitsForFinalizedReplyCacheSettlement(t *testing.T) {
	for _, kind := range []string{"negative", "positive", "attributes", "revoked", "superseded"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newStrictFixture(t)
			parent := fixture.raw.acquire(fuse.FUSE_ROOT_ID)
			defer fixture.raw.release(parent)
			unique := fixture.unique.Add(2)
			ctx, finish, status := fixture.raw.mutationContext(unique)
			if !status.Ok() {
				t.Fatal(status)
			}
			publication := replyPublicationFromContext(ctx)
			publication.servedVersion = 1
			publication.cacheStamp = &cacheSnapshot{SnapshotSequence: 1, ObjectVersion: 1}
			item := testItem(80, authoritypb.Attr_REGULAR, 80)
			record, errno := fixture.raw.intern(ctx, item)
			if errno != 0 {
				t.Fatal(errno)
			}
			opcode := uint32(1)
			if kind == "attributes" {
				var out fuse.AttrOut
				fixture.raw.publishAttr(ctx, &out, record.identity, item.GetAttr())
				opcode = 3
			} else if kind == "positive" {
				var out fuse.EntryOut
				if err := fixture.raw.publishEntry(ctx, &out, parent, "name", record, item.GetAttr()); err != nil {
					t.Fatal(err)
				}
			} else {
				var out fuse.EntryOut
				if status, err := fixture.raw.publishNegativeEntry(ctx, &out, parent, "name"); !status.Ok() || err != nil {
					t.Fatalf("publish negative: %v, %v", status, err)
				}
			}
			finish()
			if _, _, status := fixture.raw.PrepareReplyPayload(unique, parent.id, opcode, nil, nil, 0); !status.Ok() {
				t.Fatal(status)
			}
			if kind == "revoked" || kind == "superseded" {
				fixture.raw.mu.Lock()
				if kind == "revoked" {
					publication.names[0].reservation.revoked = true
				} else {
					publication.names[0].negativeState.superseded = true
				}
				fixture.raw.mu.Unlock()
			}
			// The kernel can re-enter before ReplyWritten settles the daemon cache.
			nextUnique := fixture.unique.Add(2)
			next, complete, status := fixture.raw.mutationContext(nextUnique)
			if !status.Ok() {
				t.Fatal(status)
			}
			defer func() { complete(); completeTestReply(t, fixture.raw, nextUnique, fuse.OK) }()
			result := make(chan bool, 1)
			go func() {
				if kind == "attributes" {
					attr, hit := fixture.raw.cachedAttrRecord(next, record)
					result <- hit && attr.GetInode() == item.GetAttr().GetInode()
				} else {
					found, attr, negative := fixture.raw.cachedLookup(next, parent, "name")
					result <- negative || found == record && attr.GetInode() == item.GetAttr().GetInode()
				}
			}()
			if kind == "revoked" || kind == "superseded" {
				select {
				case hit := <-result:
					if hit {
						t.Error("revoked candidate served from cache")
					}
				case <-time.After(time.Second):
					t.Error("revoked candidate stalled the cache miss")
				}
				fixture.raw.ReplyWritten(unique, fuse.OK)
				return
			}
			select {
			case hit := <-result:
				fixture.raw.ReplyWritten(unique, fuse.OK)
				t.Fatalf("lookup overtook finalized cache settlement: hit=%t", hit)
			case <-time.After(20 * time.Millisecond):
			}
			fixture.raw.ReplyWritten(unique, fuse.OK)
			select {
			case hit := <-result:
				if !hit {
					t.Fatal("settled payload required another Authority request")
				}
			case <-time.After(time.Second):
				t.Fatal("cache lookup did not resume after settlement")
			}
		})
	}
}

func TestSubscriptionShutdownBudgetUsesLiveHorizon(t *testing.T) {
	now := time.Unix(1234, 0)
	for _, test := range []struct {
		name    string
		active  bool
		horizon time.Time
		want    time.Duration
	}{
		{"live", true, now.Add(700 * time.Millisecond), 700 * time.Millisecond},
		{"expired", true, now.Add(-time.Millisecond), 0},
		{"inactive", false, now.Add(time.Second), volumeserver.SubscriptionTTL},
		{"no horizon", true, time.Time{}, volumeserver.SubscriptionTTL},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := newSubscriptionRegistryWithConfig(nil, nil, nil, subscriptionConfig{clock: &subscriptionTestClock{now: now}})
			registry.active, registry.horizon = test.active, test.horizon
			if got := registry.shutdownBudget(); got != test.want {
				t.Fatalf("budget=%s, want %s", got, test.want)
			}
		})
	}
}

func TestSubscriptionRenewLoopUsesCoordinatorInterval(t *testing.T) {
	now := time.Unix(700, 0)
	timers := make(chan *subscriptionTestTimer, 2)
	renewed := make(chan uint64, 1)
	clock := &subscriptionTestClock{now: now, timers: timers}
	rpc := &subscriptionTestRPC{horizon: now.Add(volumeserver.SubscriptionTTL), renewed: renewed}
	registry := newSubscriptionTestRegistry(clock, rpc, &subscriptionTestInvalidator{}, nil)
	registry.mu.Lock()
	registry.active, registry.incarnation = true, 17
	registry.horizon = rpc.horizon
	registry.cacheUntil = rpc.horizon.Add(-time.Second)
	registry.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- registry.renewLoop(ctx, 17) }()
	var timer *subscriptionTestTimer
	select {
	case timer = <-timers:
	case <-time.After(time.Second):
		t.Fatal("renew loop did not arm its timer")
	}
	if timer.duration != volumeserver.SubscriptionRenewInterval {
		t.Fatalf("renew timer=%s, want %s", timer.duration, volumeserver.SubscriptionRenewInterval)
	}
	clock.advance(volumeserver.SubscriptionRenewInterval)
	nextHorizon := clock.Now().Add(volumeserver.SubscriptionTTL)
	rpc.mu.Lock()
	rpc.horizon = nextHorizon
	rpc.mu.Unlock()
	timer.fired <- clock.Now()
	select {
	case incarnation := <-renewed:
		if incarnation != 17 {
			t.Fatalf("renewed incarnation=%d, want 17", incarnation)
		}
	case <-time.After(time.Second):
		t.Fatal("renew loop did not renew on interval")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("renew loop stop=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("renew loop did not stop")
	}
}

type testCacheWithdrawal func()

func (f testCacheWithdrawal) Open() { f() }
func (i *subscriptionTestInvalidator) CloseCacheCoordinates(ctx context.Context, coordinates []publicationCoordinate) (cacheWithdrawal, error) {
	for _, coordinate := range coordinates {
		if err := i.CloseCacheCoordinate(ctx, coordinate); err != nil {
			return nil, err
		}
	}
	return testCacheWithdrawal(func() {
		for _, coordinate := range coordinates {
			i.OpenCacheCoordinate(coordinate)
		}
	}), nil
}

func (i *subscriptionTestInvalidator) InvalidateCacheCoordinates(ctx context.Context, withdrawals []subscriptionWithdrawal) error {
	for _, w := range withdrawals {
		if err := i.InvalidateCacheCoordinate(ctx, w.coordinate, w.byteRange); err != nil {
			return err
		}
	}
	return nil
}
