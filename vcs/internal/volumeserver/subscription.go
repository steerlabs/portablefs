package volumeserver

import (
	"container/heap"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const (
	SubscriptionTTL           = 10 * time.Second
	SubscriptionRenewInterval = 3 * time.Second
	DelegationRecallBudget    = 5 * time.Second
)

var (
	ErrSubscription         = errors.New("volumeserver: invalid subscription incarnation")
	ErrSubscriptionPosition = errors.New("volumeserver: invalid subscription position")
	ErrCoherenceIdentity    = errors.New("volumeserver: invalid coherence identity")
)

// CoherenceClock must use one monotonic time domain. NewTimer must accept zero
// durations. Implementations must not call the coordinator from these methods.
type CoherenceClock interface {
	Now() time.Time
	NewTimer(time.Duration) CoherenceTimer
}
type CoherenceTimer interface {
	C() <-chan time.Time
	Stop() bool
}
type coherenceWallClock struct{}
type coherenceWallTimer struct{ *time.Timer }

func (coherenceWallClock) Now() time.Time { return time.Now() }
func (coherenceWallClock) NewTimer(d time.Duration) CoherenceTimer {
	return coherenceWallTimer{time.NewTimer(d)}
}
func (t coherenceWallTimer) C() <-chan time.Time { return t.Timer.C }

// ChangeKind is the v7 vocabulary, independent of the historical lease families.
type ChangeKind uint8

const (
	NamespaceChanged ChangeKind = iota + 1
	AttributesChanged
	DataChanged
	DelegationGranted
	DelegationReleased
	DirectoryChanged
)

// ChangeEntry owns no mutable backing storage. Range is [Offset, Offset+Length)
// when HasRange is true; otherwise DataChanged withdraws the whole identity.
// Position is assigned by OnCommit. VolumeVersion comes from the storage cut.
type ChangeEntry struct {
	Position, VolumeVersion  uint64
	Kind                     ChangeKind
	Identity, ParentIdentity [16]byte
	Name                     string
	HasRange                 bool
	Offset, Length           uint64
}

type StreamEventKind uint8

const (
	StreamChange StreamEventKind = iota + 1
	StreamRecall
	StreamBreakForRead
	StreamDelegationMode
	StreamLoss
	// StreamAdvance preserves a position occupied by another holder's event.
	StreamAdvance
)

// StreamEvent is a value in the single CONTROL stream. Target is zero for a
// broadcast change. A private event becomes StreamAdvance in other outboxes.
// Request identifies a break/recall independently of cumulative withdrawal ack.
type StreamEvent struct {
	Position uint64
	Kind     StreamEventKind
	Target   SessionID
	Source   SessionID
	// LocalOwner limits implicit delegation bookkeeping to one incarnation.
	LocalOwner                             SubscriptionToken
	Change                                 ChangeEntry
	Delegation                             Delegation
	Request, AppliedSequence, LossSequence uint64
	Deadline                               time.Time
}

type SubscriptionToken struct {
	Session     SessionID
	Incarnation uint64
}
type SubscriptionSnapshot struct {
	Token                             SubscriptionToken
	Position, Watermark, LossSequence uint64
	Horizon                           time.Time
	Delegated                         [][16]byte
}

type CoherenceConfig struct {
	PriorLinuxCaches bool
	Clock            CoherenceClock
	// MaxLogEntries bounds retention even if a live subscriber renews without
	// acking. Overflow requires cold resubscription, but never shortens its old
	// cache horizon: WaitWithdrawn still waits until that horizon or a cold reset.
	MaxLogEntries int
	// Per scope and subscription. Overflow conservatively targets every
	// coordinate in that scope until the next proven cold subscription.
	MaxCacheFootprint int
}

type changeSubscriber struct {
	directories, attributes, data cacheFootprint
	token                         SubscriptionToken
	acked, delivered              uint64
	horizon                       time.Time
	fenced                        bool
	ackIndex, timeIndex           int
	loss                          uint64
	held                          map[[16]byte]*delegationRecord
	handles                       map[[16]byte]uint64
}

// subscriberHeap is indexed, so renewal and ack cost O(log subscribers), with
// no stale heap nodes accumulating during renewal storms.
type subscriberHeap struct {
	items  []*changeSubscriber
	byTime bool
}

func (h subscriberHeap) Len() int { return len(h.items) }
func (h subscriberHeap) Less(i, j int) bool {
	if h.byTime {
		return h.items[i].horizon.Before(h.items[j].horizon)
	}
	return h.items[i].acked < h.items[j].acked
}
func (h subscriberHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.index(i)
	h.index(j)
}
func (h subscriberHeap) index(i int) {
	if h.byTime {
		h.items[i].timeIndex = i
	} else {
		h.items[i].ackIndex = i
	}
}
func (h *subscriberHeap) Push(x any) {
	h.items = append(h.items, x.(*changeSubscriber))
	h.index(len(h.items) - 1)
}
func (h *subscriberHeap) Pop() any {
	n := len(h.items) - 1
	s := h.items[n]
	h.items[n] = nil
	h.items = h.items[:n]
	if h.byTime {
		s.timeIndex = -1
	} else {
		s.ackIndex = -1
	}
	return s
}

// CoherenceCoordinator is disposable state for exactly one volume and epoch.
// Its mutex protects only memory, never storage I/O, peer waits, or callbacks.
// Request ordering and storage ordering are deliberately separate: a holder's
// flush and CONTROL ack must run while a peer owns a delegation request turn.
//
// The log ring doubles as each subscriber's outbox, indexed by delivered. One
// append is O(1), independent of subscriber count. Ack is O(log subscribers)
// plus amortized reclamation of entries; lookup is O(1). Notification channels
// are allocated only when somebody actually waits, never per appended entry.
type CoherenceCoordinator struct {
	maxCacheFootprint                       int
	mu                                      sync.Mutex
	clock                                   CoherenceClock
	priorCacheUntil                         time.Time
	subscribers                             map[SessionID]*changeSubscriber
	acks, horizons                          subscriberHeap
	log                                     []StreamEvent
	first, position, watermark, incarnation uint64
	changed                                 chan struct{}
	durable                                 atomic.Uint64
	requests                                *mutationSequencer
	delegations                             map[[16]byte]*delegationRecord
	cacheHandles                            map[[16]byte]*cacheHandleCounts
	nextDelegation, nextRequest             uint64
}

func NewCoherenceCoordinator(cfg CoherenceConfig) *CoherenceCoordinator {
	if cfg.Clock == nil {
		cfg.Clock = coherenceWallClock{}
	}
	if cfg.MaxCacheFootprint <= 0 {
		cfg.MaxCacheFootprint = 65536
	}
	if cfg.MaxLogEntries <= 0 {
		cfg.MaxLogEntries = 65536
	}
	var priorCacheUntil time.Time
	if cfg.PriorLinuxCaches {
		priorCacheUntil = cfg.Clock.Now().Add(SubscriptionTTL)
	}
	return &CoherenceCoordinator{maxCacheFootprint: cfg.MaxCacheFootprint, priorCacheUntil: priorCacheUntil, clock: cfg.Clock, subscribers: make(map[SessionID]*changeSubscriber),
		// The initial storage snapshot is version 1, matching the handler. A
		// reservation can publish a cache withdrawal before the first commit.
		horizons: subscriberHeap{byTime: true}, log: make([]StreamEvent, cfg.MaxLogEntries), first: 1, watermark: 1,
		requests: newMutationSequencer(), delegations: make(map[[16]byte]*delegationRecord), cacheHandles: make(map[[16]byte]*cacheHandleCounts)}
}

// WaitPriorCacheHorizon fences only prior Linux cache authority. Durable mount
// records remain intact for topology/archive proof; unknown or Mac records are
// separately subject to the compatibility coordinator's unbounded exclusion.
func (c *CoherenceCoordinator) WaitPriorCacheHorizon(ctx context.Context) error {
	if ctx == nil {
		return errors.New("volumeserver: prior-cache wait needs a context")
	}
	remaining := c.priorCacheUntil.Sub(c.clock.Now())
	if remaining <= 0 {
		return ctx.Err()
	}
	timer := c.clock.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C():
		return ctx.Err()
	}
}

func (c *CoherenceCoordinator) signalLocked() {
	if c.changed != nil {
		close(c.changed)
		c.changed = nil
	}
}
func (c *CoherenceCoordinator) notificationLocked() <-chan struct{} {
	if c.changed == nil {
		c.changed = make(chan struct{})
	}
	return c.changed
}

// Subscribe is a cold reset, not renewal. The authenticated caller attests it
// has invalidated all kernel/daemon cache and abandoned prior delegations.
// Incarnations are volume-global so removing a session cannot revive old acks.
// Cache-capable handles survive subscription expiry/resubscription: invalidating
// pages does not change FOPEN_KEEP_CACHE on an existing open description. Their
// counts remain conservative until close or permanent runtime session removal.
func (c *CoherenceCoordinator) Subscribe(id SessionID) (SubscriptionSnapshot, error) {
	return c.SubscribeWithCache(id, CacheAdmission{})
}

// SubscribeWithCache includes bootstrap facts in the same cut as registration.
func (c *CoherenceCoordinator) SubscribeWithCache(id SessionID, initial CacheAdmission) (SubscriptionSnapshot, error) {
	if id == (SessionID{}) {
		return SubscriptionSnapshot{}, ErrSubscription
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	loss := uint64(0)
	handles := make(map[[16]byte]uint64)
	if old := c.subscribers[id]; old != nil {
		c.retireSubscriberLocked(old)
		loss = old.loss
		handles = old.handles
	}
	c.incarnation++
	if c.incarnation == 0 {
		panic("volumeserver: subscription incarnation exhausted")
	}
	s := &changeSubscriber{token: SubscriptionToken{id, c.incarnation}, acked: c.position, delivered: c.position,
		horizon: c.clock.Now().Add(SubscriptionTTL), ackIndex: -1, timeIndex: -1, loss: loss,
		held: make(map[[16]byte]*delegationRecord), handles: handles}
	s.admit(initial, c.maxCacheFootprint)
	for identity := range handles {
		s.data.add([][16]byte{identity}, c.maxCacheFootprint)
	}
	c.subscribers[id] = s
	heap.Push(&c.acks, s)
	heap.Push(&c.horizons, s)
	result := SubscriptionSnapshot{Token: s.token, Position: c.position, Watermark: c.watermark, Horizon: s.horizon, LossSequence: s.loss}
	for identity := range c.delegations {
		result.Delegated = append(result.Delegated, identity)
	}
	c.truncateLocked()
	c.signalLocked()
	return result, nil
}
func (c *CoherenceCoordinator) subscriberLocked(token SubscriptionToken) (*changeSubscriber, error) {
	c.expireLocked()
	s := c.subscribers[token.Session]
	if s == nil || s.token != token {
		return nil, ErrSubscription
	}
	if s.acked+1 < c.first && !s.fenced {
		s.fenced = true
		for _, r := range s.held {
			c.dropDelegationLocked(r, true)
		}
		c.signalLocked()
	}
	if s.fenced {
		return nil, ErrSessionFenced
	}
	return s, nil
}

// CheckSession is mandatory at admission of every v7 request except Subscribe.
// It supplements runtime authentication; subscription expiry must NOT call the
// historical Authority.FenceSession, which permanently destroys the session.
func (c *CoherenceCoordinator) CheckSession(token SubscriptionToken) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.subscriberLocked(token)
	return err
}
func (c *CoherenceCoordinator) Renew(token SubscriptionToken) (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return time.Time{}, err
	}
	s.horizon = c.clock.Now().Add(SubscriptionTTL)
	heap.Fix(&c.horizons, s.timeIndex)
	c.signalLocked()
	return s.horizon, nil
}

// OnCommit must run after storage apply, in the sequencer's commit-publication
// order, before releasing storage dependencies. It never waits. Release ALL
// storage/sequencer commit locks before WaitWithdrawn(position, sourceSession).
// Caller supplies immutable entries and monotonically published VolumeVersion;
// disjoint operations may apply concurrently but must publish their cuts here.
func (c *CoherenceCoordinator) OnCommit(entries []ChangeEntry) uint64 {
	return c.OnCommitFrom(entries, SessionID{})
}

// OnCommitFrom excludes the initiating frontend from reverse notifications.
// Its exact source publication gate repairs its local caches before replying;
// notifying it while the syscall holds VFS locks can deadlock cumulative peer
// acknowledgments against concurrent commits on another mount.
func (c *CoherenceCoordinator) OnCommitFrom(entries []ChangeEntry, source SessionID) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	for _, entry := range entries {
		if entry.VolumeVersion > c.watermark {
			c.watermark = entry.VolumeVersion
		}
		c.appendLocked(StreamEvent{Kind: StreamChange, Change: entry, Source: source})
	}
	return c.position
}
func (c *CoherenceCoordinator) appendLocked(event StreamEvent) uint64 {
	c.position++
	if c.position == 0 {
		panic("volumeserver: change position exhausted")
	}
	event.Position = c.position
	if event.Kind == StreamChange {
		event.Change.Position = c.position
	}
	// Overrun does not discard an outstanding withdrawal obligation. A lagging
	// subscriber is fenced lazily at request admission; its heap entry remains
	// until its original horizon or explicit cold resubscription.
	if c.position-c.first >= uint64(len(c.log)) {
		c.first = c.position - uint64(len(c.log)) + 1
	}
	c.log[(c.position-1)%uint64(len(c.log))] = event
	c.signalLocked()
	c.truncateLocked()
	return c.position
}
func (c *CoherenceCoordinator) truncateLocked() {
	through := c.position
	if c.acks.Len() > 0 {
		through = c.acks.items[0].acked
	}
	for c.first <= through {
		c.log[(c.first-1)%uint64(len(c.log))] = StreamEvent{}
		c.first++
	}
}

// Poll appends at most limit events to dst, allowing a reused transport batch.
// after is the last delivered position, not necessarily the last ack. Repeating
// an unacked cursor replays safely; Poll never waits for withdrawal acks, so a
// recall behind a pending withdrawal can always reach the holder.
func (c *CoherenceCoordinator) Poll(ctx context.Context, token SubscriptionToken, after uint64, dst []StreamEvent, limit int) ([]StreamEvent, error) {
	events, _, err := c.poll(ctx, token, after, dst, limit, false)
	return events, err
}

// PollControl silently retires source-only positions covered by the initiating
// frontend's publication gate. A delivered or queued peer change still requires
// its withdrawal receipt. The returned cursor must be saved even on cancellation.
func (c *CoherenceCoordinator) PollControl(ctx context.Context, token SubscriptionToken, after uint64, dst []StreamEvent, limit int) ([]StreamEvent, uint64, error) {
	return c.poll(ctx, token, after, dst, limit, true)
}

func (c *CoherenceCoordinator) poll(ctx context.Context, token SubscriptionToken, after uint64, dst []StreamEvent, limit int, implicitSource bool) ([]StreamEvent, uint64, error) {
	if limit <= 0 {
		return dst, after, ErrSubscriptionPosition
	}
	for {
		c.mu.Lock()
		s, err := c.subscriberLocked(token)
		if err != nil {
			c.mu.Unlock()
			return dst, after, err
		}
		if s.acked+1 < c.first {
			s.fenced = true
			c.mu.Unlock()
			return dst, after, ErrSessionFenced
		}
		if after < s.acked || after > s.delivered {
			c.mu.Unlock()
			return dst, after, ErrSubscriptionPosition
		}
		if after < c.position {
			end := c.position
			if end-after > uint64(limit) {
				end = after + uint64(limit)
			}
			ownOnly := implicitSource && after == s.acked && after == s.delivered
			base := len(dst)
			needed := len(dst) + int(end-after)
			if cap(dst) < needed {
				// Grow amortized, but never retain more than one requested batch
				// beyond the caller's existing prefix.
				capacity := min(max(needed, 2*cap(dst)), len(dst)+limit)
				grown := make([]StreamEvent, len(dst), capacity)
				copy(grown, dst)
				dst = grown
			}
			for pos := after + 1; pos <= end; pos++ {
				event := c.log[(pos-1)%uint64(len(c.log))]
				local := event.Source == token.Session
				if implicitSource && event.LocalOwner != (SubscriptionToken{}) {
					local = event.LocalOwner == token
				}
				if event.Kind != StreamChange || !local {
					ownOnly = false
				}
				if local || event.Target != (SessionID{}) && event.Target != token.Session {
					event = StreamEvent{Position: pos, Kind: StreamAdvance}
				}
				dst = append(dst, event)
			}
			if end > s.delivered {
				s.delivered = end
			}
			after = end
			if ownOnly {
				clear(dst[base:])
				dst = dst[:base]
				s.acked = end
				heap.Fix(&c.acks, s.ackIndex)
				c.truncateLocked()
				c.signalLocked()
				c.mu.Unlock()
				continue
			}
			c.mu.Unlock()
			return dst, after, nil
		}
		changed := c.notificationLocked()
		deadline := s.horizon
		c.mu.Unlock()
		if err := c.wait(ctx, changed, deadline); err != nil {
			return dst, after, err
		}
	}
}
func (c *CoherenceCoordinator) Ack(token SubscriptionToken, position uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return err
	}
	if s.acked+1 < c.first {
		s.fenced = true
		return ErrSessionFenced
	}
	if position > s.delivered {
		return ErrSubscriptionPosition
	}
	if position <= s.acked {
		return nil
	}
	s.acked = position
	heap.Fix(&c.acks, s.ackIndex)
	c.truncateLocked()
	c.signalLocked()
	return nil
}
func (c *CoherenceCoordinator) minimumOtherLocked(exclude SessionID) *changeSubscriber {
	if c.acks.Len() == 0 {
		return nil
	}
	s := c.acks.items[0]
	if s.token.Session != exclude {
		return s
	}
	if c.acks.Len() == 1 {
		return nil
	}
	s = c.acks.items[1]
	if c.acks.Len() > 2 && c.acks.items[2].acked < s.acked {
		s = c.acks.items[2]
	}
	return s
}
func (c *CoherenceCoordinator) WaitWithdrawn(ctx context.Context, position uint64, excludeSession SessionID) error {
	for {
		c.mu.Lock()
		c.expireLocked()
		if position > c.position {
			c.mu.Unlock()
			return ErrSubscriptionPosition
		}
		s := c.minimumOtherLocked(excludeSession)
		if s == nil || s.acked >= position {
			c.mu.Unlock()
			return nil
		}
		changed := c.notificationLocked()
		deadline := c.horizons.items[0].horizon
		c.mu.Unlock()
		if err := c.wait(ctx, changed, deadline); err != nil {
			return err
		}
	}
}
func (c *CoherenceCoordinator) wait(ctx context.Context, changed <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-changed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	timer := c.clock.NewTimer(max(time.Duration(0), deadline.Sub(c.clock.Now())))
	defer timer.Stop()
	select {
	case <-changed:
		return nil
	case <-timer.C():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *CoherenceCoordinator) expireLocked() {
	now := c.clock.Now()
	for c.horizons.Len() > 0 && !now.Before(c.horizons.items[0].horizon) {
		s := c.horizons.items[0]
		c.retireSubscriberLocked(s)
	}
}
func (c *CoherenceCoordinator) retireSubscriberLocked(s *changeSubscriber) {
	s.fenced = true
	s.directories, s.attributes, s.data = cacheFootprint{}, cacheFootprint{}, cacheFootprint{}
	if s.timeIndex >= 0 {
		heap.Remove(&c.horizons, s.timeIndex)
	}
	if s.ackIndex >= 0 {
		heap.Remove(&c.acks, s.ackIndex)
	}
	for _, r := range s.held {
		c.dropDelegationLocked(r, true)
	}
	c.truncateLocked()
	c.signalLocked()
}

// ExpireSession is the runtime terminal hook. Cache permission remains an
// obligation until the old horizon; holder write authority ends immediately.
func (c *CoherenceCoordinator) ExpireSession(id SessionID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	if s := c.subscribers[id]; s != nil {
		s.fenced = true
		for _, r := range s.held {
			c.dropDelegationLocked(r, true)
		}
		for identity, n := range s.handles {
			c.closeHandlesLocked(s, identity, n)
		}
		c.signalLocked()
	}
}

// Sweep permits an authority housekeeping loop to retire idle expired state.
func (c *CoherenceCoordinator) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	c.expireDelegationCutsLocked()
}

// ForgetSession requires proven cache absence or a passed subscription horizon.
// The runtime must also have permanently retired this session's handles; a
// horizon alone does not make their open descriptions non-cache-capable.
// It releases the session tombstone, including its loss counter.
func (c *CoherenceCoordinator) ForgetSession(id SessionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	if s := c.subscribers[id]; s != nil {
		if s.timeIndex >= 0 {
			return ErrSessionActive
		}
		for identity, n := range s.handles {
			c.closeHandlesLocked(s, identity, n)
		}
		delete(c.subscribers, id)
	}
	return nil
}
func (c *CoherenceCoordinator) LossSequence(id SessionID) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	if s := c.subscribers[id]; s != nil {
		return s.loss
	}
	return 0
}

// DurableSequence publishes a contiguous applied-and-durable cut, never merely
// the largest individual completed fsync. The fsync group owns that proof.
func (c *CoherenceCoordinator) DurableSequence(seq uint64) {
	for {
		old := c.durable.Load()
		if seq <= old || c.durable.CompareAndSwap(old, seq) {
			return
		}
	}
}
func (c *CoherenceCoordinator) LatestDurable() uint64 { return c.durable.Load() }
