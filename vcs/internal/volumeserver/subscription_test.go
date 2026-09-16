package volumeserver

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// cv2Clock is a deterministic monotonic clock shared by the coherence-v2
// coordinator tests. Timer channels are buffered so advancing the clock never
// depends on a waiter being scheduled, and stopped timers are never delivered.
type cv2Clock struct {
	mu      sync.Mutex
	now     time.Time
	timers  map[*cv2Timer]struct{}
	changed chan struct{}
}

type cv2Timer struct {
	clock    *cv2Clock
	deadline time.Time
	c        chan time.Time
	fired    bool
	stopped  bool
}

func newCV2Clock() *cv2Clock {
	return &cv2Clock{
		now:     time.Unix(1_700_000_000, 0),
		timers:  make(map[*cv2Timer]struct{}),
		changed: make(chan struct{}),
	}
}

func (c *cv2Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *cv2Clock) NewTimer(d time.Duration) CoherenceTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &cv2Timer{clock: c, deadline: c.now.Add(d), c: make(chan time.Time, 1)}
	if d <= 0 {
		timer.fired = true
		timer.c <- c.now
		return timer
	}
	c.timers[timer] = struct{}{}
	c.signalLocked()
	return timer
}

func (c *cv2Clock) Advance(d time.Duration) {
	if d < 0 {
		panic("volumeserver test clock cannot move backwards")
	}
	c.AdvanceTo(c.Now().Add(d))
}

func (c *cv2Clock) AdvanceTo(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Before(c.now) {
		panic("volumeserver test clock cannot move backwards")
	}
	c.now = now
	for timer := range c.timers {
		if now.Before(timer.deadline) {
			continue
		}
		delete(c.timers, timer)
		timer.fired = true
		timer.c <- now
	}
	c.signalLocked()
}

func (c *cv2Clock) signalLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *cv2Clock) waitForTimers(t testing.TB, count int) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		c.mu.Lock()
		if len(c.timers) >= count {
			c.mu.Unlock()
			return
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("registered timers = %d, want at least %d", c.timerCount(), count)
		}
	}
}

func (c *cv2Clock) timerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

func (t *cv2Timer) C() <-chan time.Time { return t.c }

func (t *cv2Timer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.fired || t.stopped {
		return false
	}
	t.stopped = true
	delete(t.clock.timers, t)
	t.clock.signalLocked()
	return true
}

func TestSubscriptionChangeVocabulary(t *testing.T) {
	clock := newCV2Clock()
	coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: clock})
	snapshot, err := coordinator.Subscribe(SessionID{1})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	identity := [16]byte{1}
	parent := [16]byte{2}
	entries := []ChangeEntry{
		{Kind: NamespaceChanged, ParentIdentity: parent, Name: "created", VolumeVersion: 11},
		{Kind: AttributesChanged, Identity: identity, VolumeVersion: 12},
		{Kind: DataChanged, Identity: identity, VolumeVersion: 13},
		{Kind: DataChanged, Identity: identity, HasRange: true, Offset: 4096, Length: 8192, VolumeVersion: 14},
		{Kind: DelegationGranted, Identity: identity, VolumeVersion: 15},
		{Kind: DelegationReleased, Identity: identity, VolumeVersion: 16},
		{Kind: DirectoryChanged, Identity: parent, VolumeVersion: 17},
	}
	position := coordinator.OnCommit(entries)
	if want := uint64(len(entries)); position != want {
		t.Fatalf("OnCommit position = %d, want %d", position, want)
	}

	events, err := coordinator.Poll(context.Background(), snapshot.Token, snapshot.Position, nil, len(entries))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != len(entries) {
		t.Fatalf("Poll returned %d events, want %d", len(events), len(entries))
	}
	for i, event := range events {
		want := entries[i]
		want.Position = uint64(i + 1)
		if event.Kind != StreamChange || !reflect.DeepEqual(event.Change, want) || event.Position != want.Position {
			t.Errorf("event %d = %+v, want StreamChange %+v", i, event, want)
		}
	}

	next, err := coordinator.Subscribe(SessionID{2})
	if err != nil {
		t.Fatalf("Subscribe after changes: %v", err)
	}
	if next.Position != position || next.Watermark != 17 {
		t.Fatalf("snapshot position/watermark = %d/%d, want %d/17", next.Position, next.Watermark, position)
	}
}

func TestSubscriptionCumulativeAckAndIncarnation(t *testing.T) {
	coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock()})
	if _, err := coordinator.Subscribe(SessionID{}); !errors.Is(err, ErrSubscription) {
		t.Fatalf("Subscribe(zero) = %v, want ErrSubscription", err)
	}
	first, err := coordinator.Subscribe(SessionID{1})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	coordinator.OnCommit([]ChangeEntry{
		{Kind: AttributesChanged, Identity: [16]byte{1}},
		{Kind: AttributesChanged, Identity: [16]byte{2}},
		{Kind: AttributesChanged, Identity: [16]byte{3}},
	})
	if err := coordinator.Ack(first.Token, 1); !errors.Is(err, ErrSubscriptionPosition) {
		t.Fatalf("Ack before delivery = %v, want ErrSubscriptionPosition", err)
	}
	if _, err := coordinator.Poll(context.Background(), first.Token, first.Position, nil, 3); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if err := coordinator.Ack(first.Token, 2); err != nil {
		t.Fatalf("cumulative Ack(2): %v", err)
	}
	for _, position := range []uint64{1, 2} {
		if err := coordinator.Ack(first.Token, position); err != nil {
			t.Errorf("idempotent Ack(%d): %v", position, err)
		}
	}
	if err := coordinator.Ack(first.Token, 4); !errors.Is(err, ErrSubscriptionPosition) {
		t.Fatalf("Ack beyond delivery = %v, want ErrSubscriptionPosition", err)
	}

	second, err := coordinator.Subscribe(first.Token.Session)
	if err != nil {
		t.Fatalf("cold resubscribe: %v", err)
	}
	if second.Token.Incarnation <= first.Token.Incarnation || second.Position != 3 {
		t.Fatalf("cold snapshot = %+v, want later incarnation at position 3", second)
	}
	for name, call := range map[string]func() error{
		"check": func() error { return coordinator.CheckSession(first.Token) },
		"renew": func() error { _, err := coordinator.Renew(first.Token); return err },
		"ack":   func() error { return coordinator.Ack(first.Token, 2) },
	} {
		t.Run(name+" rejects old incarnation", func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrSubscription) {
				t.Fatalf("old incarnation error = %v, want ErrSubscription", err)
			}
		})
	}
}

func TestSubscriptionRenewBoundary(t *testing.T) {
	t.Run("exact horizon fences", func(t *testing.T) {
		clock := newCV2Clock()
		coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: clock})
		snapshot, err := coordinator.Subscribe(SessionID{1})
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		clock.Advance(SubscriptionTTL)
		if err := coordinator.CheckSession(snapshot.Token); !errors.Is(err, ErrSessionFenced) {
			t.Fatalf("CheckSession at horizon = %v, want ErrSessionFenced", err)
		}
		if _, err := coordinator.Renew(snapshot.Token); !errors.Is(err, ErrSessionFenced) {
			t.Fatalf("Renew at horizon = %v, want ErrSessionFenced", err)
		}
	})

	t.Run("renew immediately before horizon extends from now", func(t *testing.T) {
		clock := newCV2Clock()
		coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: clock})
		snapshot, err := coordinator.Subscribe(SessionID{1})
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		clock.Advance(SubscriptionTTL - time.Nanosecond)
		horizon, err := coordinator.Renew(snapshot.Token)
		if err != nil {
			t.Fatalf("Renew before horizon: %v", err)
		}
		if want := clock.Now().Add(SubscriptionTTL); !horizon.Equal(want) {
			t.Fatalf("renewed horizon = %v, want %v", horizon, want)
		}
		clock.Advance(time.Nanosecond)
		if err := coordinator.CheckSession(snapshot.Token); err != nil {
			t.Fatalf("CheckSession at original horizon: %v", err)
		}
		clock.Advance(SubscriptionTTL - time.Nanosecond)
		if err := coordinator.CheckSession(snapshot.Token); !errors.Is(err, ErrSessionFenced) {
			t.Fatalf("CheckSession at renewed horizon = %v, want ErrSessionFenced", err)
		}
	})
}

func TestSubscriptionColdSnapshotIncludesDelegatedSet(t *testing.T) {
	clock := newCV2Clock()
	coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: clock})
	holder, err := coordinator.Subscribe(SessionID{1})
	if err != nil {
		t.Fatalf("subscribe holder: %v", err)
	}
	identities := [][16]byte{{1}, {2}}
	for _, identity := range identities {
		reservation, err := coordinator.ReserveNew(holder.Token, identity)
		if err != nil {
			t.Fatalf("ReserveNew(%v): %v", identity, err)
		}
		if _, err := reservation.Grant(context.Background()); err != nil {
			t.Fatalf("Grant(%v): %v", identity, err)
		}
	}
	coordinator.OnCommit([]ChangeEntry{{Kind: DirectoryChanged, Identity: [16]byte{9}, VolumeVersion: 23}})

	clock.Advance(time.Second)
	observer, err := coordinator.Subscribe(SessionID{2})
	if err != nil {
		t.Fatalf("subscribe observer: %v", err)
	}
	clock.Advance(8 * time.Second)
	if _, err := coordinator.Renew(holder.Token); err != nil {
		t.Fatalf("renew holder: %v", err)
	}
	clock.Advance(2 * time.Second)
	if err := coordinator.CheckSession(observer.Token); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("observer after horizon = %v, want ErrSessionFenced", err)
	}
	cold, err := coordinator.Subscribe(observer.Token.Session)
	if err != nil {
		t.Fatalf("cold resubscribe observer: %v", err)
	}
	if cold.Token.Incarnation <= observer.Token.Incarnation || cold.Position != 3 || cold.Watermark != 23 {
		t.Fatalf("cold snapshot = %+v, want later incarnation at position 3, watermark 23", cold)
	}
	sort.Slice(cold.Delegated, func(i, j int) bool { return cold.Delegated[i][0] < cold.Delegated[j][0] })
	if !reflect.DeepEqual(cold.Delegated, identities) {
		t.Fatalf("cold delegated set = %v, want %v", cold.Delegated, identities)
	}
}

func TestWaitWithdrawnExcludesSourceAndHonorsPartitionHorizon(t *testing.T) {
	t.Run("excluded source need not ack", func(t *testing.T) {
		coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock()})
		source, err := coordinator.Subscribe(SessionID{1})
		if err != nil {
			t.Fatalf("subscribe source: %v", err)
		}
		peer, err := coordinator.Subscribe(SessionID{2})
		if err != nil {
			t.Fatalf("subscribe peer: %v", err)
		}
		position := coordinator.OnCommit([]ChangeEntry{{Kind: AttributesChanged, Identity: [16]byte{1}}})
		if _, err := coordinator.Poll(context.Background(), peer.Token, peer.Position, nil, 1); err != nil {
			t.Fatalf("poll peer: %v", err)
		}
		if err := coordinator.Ack(peer.Token, position); err != nil {
			t.Fatalf("ack peer: %v", err)
		}
		if err := coordinator.WaitWithdrawn(context.Background(), position, source.Token.Session); err != nil {
			t.Fatalf("WaitWithdrawn excluding unacked source: %v", err)
		}
	})

	t.Run("partition waits through laggard horizon", func(t *testing.T) {
		clock := newCV2Clock()
		coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: clock})
		source, err := coordinator.Subscribe(SessionID{1})
		if err != nil {
			t.Fatalf("subscribe source: %v", err)
		}
		clock.Advance(2 * time.Second)
		if _, err := coordinator.Subscribe(SessionID{2}); err != nil {
			t.Fatalf("subscribe partitioned peer: %v", err)
		}
		position := coordinator.OnCommit([]ChangeEntry{{Kind: DataChanged, Identity: [16]byte{1}}})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- coordinator.WaitWithdrawn(ctx, position, source.Token.Session) }()

		clock.waitForTimers(t, 1)
		clock.Advance(8 * time.Second)
		clock.waitForTimers(t, 1)
		select {
		case err := <-done:
			t.Fatalf("WaitWithdrawn returned at excluded source horizon: %v", err)
		default:
		}
		clock.Advance(2 * time.Second)
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("WaitWithdrawn after peer horizon: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("WaitWithdrawn did not finish after partitioned peer horizon")
		}
	})
}

func TestSubscriptionOverflowFencesEveryAdmissionPath(t *testing.T) {
	tests := []struct {
		name string
		call func(*CoherenceCoordinator, SubscriptionToken) error
	}{
		{name: "check session", call: func(c *CoherenceCoordinator, token SubscriptionToken) error {
			return c.CheckSession(token)
		}},
		{name: "renew", call: func(c *CoherenceCoordinator, token SubscriptionToken) error {
			_, err := c.Renew(token)
			return err
		}},
		{name: "poll", call: func(c *CoherenceCoordinator, token SubscriptionToken) error {
			_, err := c.Poll(context.Background(), token, 0, nil, 1)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxLogEntries: 2})
			snapshot, err := coordinator.Subscribe(SessionID{1})
			if err != nil {
				t.Fatalf("Subscribe: %v", err)
			}
			coordinator.OnCommit([]ChangeEntry{
				{Kind: AttributesChanged, Identity: [16]byte{1}},
				{Kind: AttributesChanged, Identity: [16]byte{2}},
				{Kind: AttributesChanged, Identity: [16]byte{3}},
			})
			if err := test.call(coordinator, snapshot.Token); !errors.Is(err, ErrSessionFenced) {
				t.Fatalf("overflow admission = %v, want ErrSessionFenced", err)
			}
		})
	}
}

func TestSubscriptionDeliveryReplayAndIndependentAcks(t *testing.T) {
	coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock()})
	first, err := coordinator.Subscribe(SessionID{1})
	if err != nil {
		t.Fatalf("subscribe first: %v", err)
	}
	second, err := coordinator.Subscribe(SessionID{2})
	if err != nil {
		t.Fatalf("subscribe second: %v", err)
	}
	coordinator.OnCommit([]ChangeEntry{
		{Kind: AttributesChanged, Identity: [16]byte{1}},
		{Kind: DataChanged, Identity: [16]byte{2}},
		{Kind: DirectoryChanged, Identity: [16]byte{3}},
	})

	one, err := coordinator.Poll(context.Background(), first.Token, 0, nil, 1)
	if err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	replay, err := coordinator.Poll(context.Background(), first.Token, 0, nil, 1)
	if err != nil {
		t.Fatalf("replay Poll: %v", err)
	}
	if !reflect.DeepEqual(replay, one) {
		t.Fatalf("replay = %+v, want %+v", replay, one)
	}
	if err := coordinator.Ack(first.Token, 1); err != nil {
		t.Fatalf("first Ack(1): %v", err)
	}
	remaining, err := coordinator.Poll(context.Background(), first.Token, 1, nil, 8)
	if err != nil {
		t.Fatalf("first remaining Poll: %v", err)
	}
	all, err := coordinator.Poll(context.Background(), second.Token, 0, nil, 8)
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if got := []uint64{one[0].Position, remaining[0].Position, remaining[1].Position}; !reflect.DeepEqual(got, []uint64{1, 2, 3}) {
		t.Fatalf("first delivery positions = %v, want [1 2 3]", got)
	}
	if got := []uint64{all[0].Position, all[1].Position, all[2].Position}; !reflect.DeepEqual(got, []uint64{1, 2, 3}) {
		t.Fatalf("second delivery positions = %v, want [1 2 3]", got)
	}
	if err := coordinator.Ack(first.Token, 3); err != nil {
		t.Fatalf("first Ack(3): %v", err)
	}
	coordinator.mu.Lock()
	secondAck := coordinator.subscribers[second.Token.Session].acked
	coordinator.mu.Unlock()
	if secondAck != 0 {
		t.Fatalf("second subscriber ack = %d after first subscriber Ack(3), want 0", secondAck)
	}
}

func TestSubscriptionTruncatesThroughMinimumAck(t *testing.T) {
	coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxLogEntries: 8})
	first, _ := coordinator.Subscribe(SessionID{1})
	second, _ := coordinator.Subscribe(SessionID{2})
	coordinator.OnCommit([]ChangeEntry{
		{Kind: AttributesChanged, Identity: [16]byte{1}},
		{Kind: AttributesChanged, Identity: [16]byte{2}},
		{Kind: AttributesChanged, Identity: [16]byte{3}},
	})
	for _, snapshot := range []SubscriptionSnapshot{first, second} {
		if _, err := coordinator.Poll(context.Background(), snapshot.Token, 0, nil, 3); err != nil {
			t.Fatalf("Poll(%v): %v", snapshot.Token.Session, err)
		}
	}
	if err := coordinator.Ack(first.Token, 3); err != nil {
		t.Fatalf("first Ack: %v", err)
	}
	assertFirstPosition(t, coordinator, 1)
	if err := coordinator.Ack(second.Token, 2); err != nil {
		t.Fatalf("second Ack(2): %v", err)
	}
	assertFirstPosition(t, coordinator, 3)
	if err := coordinator.Ack(second.Token, 3); err != nil {
		t.Fatalf("second Ack(3): %v", err)
	}
	assertFirstPosition(t, coordinator, 4)
	for i := uint64(1); i <= 3; i++ {
		if event := coordinator.log[(i-1)%uint64(len(coordinator.log))]; event != (StreamEvent{}) {
			t.Errorf("truncated log position %d still contains %+v", i, event)
		}
	}
}

func assertFirstPosition(t testing.TB, coordinator *CoherenceCoordinator, want uint64) {
	t.Helper()
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.first != want {
		t.Fatalf("first retained position = %d, want %d", coordinator.first, want)
	}
}

func TestDurableSequenceIsMonotonic(t *testing.T) {
	coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock()})
	for _, sequence := range []uint64{4, 2, 4, 9, 7, 12, 1} {
		coordinator.DurableSequence(sequence)
	}
	if got := coordinator.LatestDurable(); got != 12 {
		t.Fatalf("LatestDurable = %d, want 12", got)
	}

	var workers sync.WaitGroup
	for sequence := uint64(13); sequence <= 64; sequence++ {
		workers.Add(1)
		go func(sequence uint64) {
			defer workers.Done()
			coordinator.DurableSequence(sequence)
		}(sequence)
	}
	workers.Wait()
	if got := coordinator.LatestDurable(); got != 64 {
		t.Fatalf("LatestDurable after concurrent publication = %d, want 64", got)
	}
}

func TestWaitWithdrawnDoesNotHoldCoordinatorLock(t *testing.T) {
	clock := newCV2Clock()
	coordinator := NewCoherenceCoordinator(CoherenceConfig{Clock: clock})
	peer, err := coordinator.Subscribe(SessionID{1})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	position := coordinator.OnCommit([]ChangeEntry{{Kind: AttributesChanged, Identity: [16]byte{1}}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	waitDone := make(chan error, 1)
	go func() { waitDone <- coordinator.WaitWithdrawn(ctx, position, SessionID{}) }()
	clock.waitForTimers(t, 1)

	commitDone := make(chan uint64, 1)
	go func() {
		commitDone <- coordinator.OnCommit([]ChangeEntry{{Kind: AttributesChanged, Identity: [16]byte{2}}})
	}()
	select {
	case got := <-commitDone:
		if got != position+1 {
			t.Fatalf("concurrent OnCommit position = %d, want %d", got, position+1)
		}
	case <-ctx.Done():
		t.Fatal("OnCommit blocked behind WaitWithdrawn")
	}

	if _, err := coordinator.Poll(ctx, peer.Token, peer.Position, nil, 2); err != nil {
		t.Fatalf("Poll peer: %v", err)
	}
	if err := coordinator.Ack(peer.Token, position); err != nil {
		t.Fatalf("Ack peer: %v", err)
	}
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("WaitWithdrawn: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("WaitWithdrawn did not observe cumulative ack")
	}
}
