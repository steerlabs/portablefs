//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

const (
	subscriptionRetryDelay     = 10 * time.Millisecond
	maxSubscriptionPages       = 1 << 20
	maxSubscriptionCoordinates = 65_536
)

var (
	errSubscriptionInvalid = errors.New("fusev3: invalid subscription response")
	errSubscriptionExpired = errors.New("fusev3: subscription cache horizon reached")
	errSubscriptionPaused  = errors.New("fusev3: subscription recovery is paused")
)

// subscriptionStamp binds one cache decision to both the subscription
// incarnation and the exact local publication generation at which the reply
// was admitted. Version is filled only when a reply becomes a cache candidate.
// Keeping it alongside the stamp lets daemon-resident cache entries be checked
// without a second side table.
type subscriptionStamp struct {
	incarnation uint64
	generation  uint64
	version     uint64
}

func (s subscriptionStamp) withVersion(version uint64) subscriptionStamp {
	s.version = version
	return s
}

type subscriptionRPC interface {
	Subscribe(context.Context, []byte, []byte) (*authoritypb.SubscribeReply, time.Time, error)
	RenewSubscription(context.Context, uint64) (time.Time, error)
	NextControlEvent(context.Context, uint64, uint64, uint64) (*authoritypb.ControlEvent, error)
	AcknowledgeChanges(context.Context, uint64, uint64) error
}

// subscriptionControlHandler must return after accepting an event. Delegation
// flushing and acknowledgments run asynchronously so a withdrawal which is
// waiting on a cache-installing reply can never stop the poll that delivers the
// delegation event needed to release that reply.
type subscriptionControlHandler interface {
	FenceSubscription(string)
	SetIncarnation(uint64)
	HandleControlEvent(context.Context, *authoritypb.ControlEvent) <-chan struct{}
}

type subscriptionInvalidator interface {
	CloseCacheCoordinate(context.Context, publicationCoordinate) error
	InvalidateCacheCoordinate(context.Context, publicationCoordinate, *authoritypb.ByteRange) error
	OpenCacheCoordinate(publicationCoordinate)
	InvalidateAllCaches(context.Context) error
	MarkIdentityStale(publicationIdentity)
}

type subscriptionTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type subscriptionClock interface {
	Now() time.Time
	NewTimer(time.Duration) subscriptionTimer
}

type wallSubscriptionClock struct{}

type wallSubscriptionTimer struct{ timer *time.Timer }

func (wallSubscriptionClock) Now() time.Time { return time.Now() }
func (wallSubscriptionClock) NewTimer(d time.Duration) subscriptionTimer {
	return wallSubscriptionTimer{timer: time.NewTimer(d)}
}
func (t wallSubscriptionTimer) C() <-chan time.Time { return t.timer.C }
func (t wallSubscriptionTimer) Stop() bool          { return t.timer.Stop() }

type subscriptionConfig struct {
	clock       subscriptionClock
	retryDelay  time.Duration
	repairLead  time.Duration
	maxPages    int
	invalidator subscriptionInvalidator
}

type subscriptionCoordinateState struct {
	generation uint64
	minVersion uint64
}

// subscriptionRegistry owns one volume-wide protocol-7 subscription. Its mutex
// covers cache admission state only and is never held across transport calls,
// reverse notifications, or publication drains.
type subscriptionRegistry struct {
	mount   *Mount
	rpc     subscriptionRPC
	control subscriptionControlHandler
	config  subscriptionConfig

	mu              sync.RWMutex
	active          bool
	paused          bool
	incarnation     uint64
	generation      uint64
	watermark       uint64
	horizon         time.Time
	cacheUntil      time.Time
	delegated       map[publicationIdentity]struct{}
	stale           map[publicationIdentity]struct{}
	coordinates     map[publicationCoordinate]subscriptionCoordinateState
	generationFloor uint64
	versionFloor    uint64
	lastChangeSeen  uint64
	lastChangeAck   uint64

	horizonChanged chan struct{}
	pauseChanged   chan struct{}
	serveDone      chan struct{}
}

type mountSubscriptionInvalidator struct{ mount *Mount }

func (i mountSubscriptionInvalidator) raw() (*rawFileSystem, error) {
	if i.mount == nil || i.mount.raw == nil {
		return nil, errors.New("fusev3: subscription invalidation has no kernel frontend")
	}
	return i.mount.raw, nil
}

func (i mountSubscriptionInvalidator) CloseCacheCoordinate(ctx context.Context, coordinate publicationCoordinate) error {
	raw, err := i.raw()
	if err != nil {
		return err
	}
	return raw.closeCacheCoordinate(ctx, coordinate)
}

func (i mountSubscriptionInvalidator) InvalidateCacheCoordinate(ctx context.Context, coordinate publicationCoordinate, byteRange *authoritypb.ByteRange) error {
	raw, err := i.raw()
	if err != nil {
		return err
	}
	return raw.invalidateCacheCoordinateContext(ctx, coordinate, byteRange)
}

func (i mountSubscriptionInvalidator) OpenCacheCoordinate(coordinate publicationCoordinate) {
	if raw, err := i.raw(); err == nil {
		raw.openCacheCoordinate(coordinate)
	}
}

func (i mountSubscriptionInvalidator) InvalidateAllCaches(ctx context.Context) error {
	raw, err := i.raw()
	if err != nil {
		return err
	}
	return raw.invalidateAllCaches(ctx)
}

func (i mountSubscriptionInvalidator) MarkIdentityStale(identity publicationIdentity) {
	if raw, err := i.raw(); err == nil {
		raw.markIdentityStale(identity)
	}
}

func newSubscriptionRegistry(mount *Mount, rpc subscriptionRPC, control subscriptionControlHandler) *subscriptionRegistry {
	repairLead := time.Second
	if mount != nil && mount.repairBudget > 0 && mount.repairBudget < repairLead {
		repairLead = mount.repairBudget
	}
	return newSubscriptionRegistryWithConfig(mount, rpc, control, subscriptionConfig{
		clock: wallSubscriptionClock{}, retryDelay: subscriptionRetryDelay, repairLead: repairLead,
		maxPages: maxSubscriptionPages, invalidator: mountSubscriptionInvalidator{mount: mount},
	})
}

func newSubscriptionRegistryWithConfig(mount *Mount, rpc subscriptionRPC, control subscriptionControlHandler, config subscriptionConfig) *subscriptionRegistry {
	if config.clock == nil {
		config.clock = wallSubscriptionClock{}
	}
	if config.retryDelay <= 0 {
		config.retryDelay = subscriptionRetryDelay
	}
	if config.repairLead <= 0 {
		config.repairLead = time.Second
	}
	if config.maxPages <= 0 {
		config.maxPages = maxSubscriptionPages
	}
	if config.invalidator == nil {
		config.invalidator = mountSubscriptionInvalidator{mount: mount}
	}
	serveDone := make(chan struct{})
	close(serveDone)
	return &subscriptionRegistry{
		mount: mount, rpc: rpc, control: control, config: config,
		delegated: make(map[publicationIdentity]struct{}), stale: make(map[publicationIdentity]struct{}),
		coordinates:    make(map[publicationCoordinate]subscriptionCoordinateState),
		horizonChanged: make(chan struct{}),
		pauseChanged:   make(chan struct{}),
		serveDone:      serveDone,
	}
}

// shutdownBudget uses the Authority horizon, not the earlier cache boundary.
// An expired live horizon still requires a barrier attempt with zero budget.
func (s *subscriptionRegistry) shutdownBudget() time.Duration {
	if s == nil {
		return volumeserver.SubscriptionTTL
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.active || s.horizon.IsZero() {
		return volumeserver.SubscriptionTTL
	}
	return max(time.Duration(0), s.horizon.Sub(s.config.clock.Now()))
}

func (s *subscriptionRegistry) stamp() subscriptionStamp {
	if s == nil {
		return subscriptionStamp{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.active || !s.config.clock.Now().Before(s.cacheUntil) {
		return subscriptionStamp{}
	}
	return subscriptionStamp{incarnation: s.incarnation, generation: s.generation}
}

// remaining is the sole cache-admission predicate. A change advances only its
// exact coordinates, so an unrelated event does not invalidate a reply already
// in flight. The global generation remains in the stamp to distinguish a reply
// admitted before a same-version withdrawal from one admitted after it.
func (s *subscriptionRegistry) remaining(coordinate publicationCoordinate, stamp subscriptionStamp, servedVersion uint64, now time.Time) time.Duration {
	if s == nil || stamp.incarnation == 0 {
		return 0
	}
	// A private synchronous generation can become an owned delegation in its
	// DATA reply without a source stream event. Local ownership is decisive,
	// including when an older release event overtakes that reply.
	if (coordinate.kind == publicationItemAttributes || coordinate.kind == publicationItemData) && s.mount != nil && s.mount.delegations != nil && s.mount.delegations.Owns(coordinate.item[:]) {
		return 0
	}
	return s.remainingAfterOwnershipCheck(coordinate, stamp, servedVersion, now)
}

// remainingAfterOwnershipCheck is used by a cached reply after checking local
// delegation ownership outside raw.mu. Acquiring delegation locks under raw.mu
// could deadlock with a queued epoch fence and a write's source gate.
func (s *subscriptionRegistry) remainingAfterOwnershipCheck(coordinate publicationCoordinate, stamp subscriptionStamp, servedVersion uint64, now time.Time) time.Duration {
	if s == nil || stamp.incarnation == 0 {
		return 0
	}
	if servedVersion == 0 {
		servedVersion = stamp.version
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.active || stamp.incarnation != s.incarnation || !now.Before(s.cacheUntil) {
		return 0
	}
	if coordinate.kind == publicationNamespaceName {
		if _, stale := s.stale[coordinate.parent]; stale {
			return 0
		}
	} else {
		if _, stale := s.stale[coordinate.item]; stale {
			return 0
		}
	}
	if coordinate.kind == publicationItemAttributes || coordinate.kind == publicationItemData {
		if _, excluded := s.delegated[coordinate.item]; excluded {
			return 0
		}
	}
	state := s.coordinates[coordinate]
	if stamp.generation < s.generationFloor || stamp.generation < state.generation ||
		servedVersion < s.watermark || servedVersion < s.versionFloor || servedVersion < state.minVersion {
		return 0
	}
	return s.cacheUntil.Sub(now)
}

func (s *subscriptionRegistry) signalHorizonChangedLocked() {
	close(s.horizonChanged)
	s.horizonChanged = make(chan struct{})
}

func (s *subscriptionRegistry) deactivate() {
	s.mu.Lock()
	if s.active {
		s.active = false
		s.generation++
		s.signalHorizonChangedLocked()
	}
	s.mu.Unlock()
}

// suspend is the authority-epoch cut. It denies cache admission immediately
// and prevents the recovery loop from subscribing through the old session.
func (s *subscriptionRegistry) suspend() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.paused = true
	s.active = false
	s.generation++
	close(s.pauseChanged)
	s.pauseChanged = make(chan struct{})
	s.signalHorizonChangedLocked()
	s.mu.Unlock()
}

func (s *subscriptionRegistry) suspendAndDrain(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.suspend()
	return s.drainSuspended(ctx)
}

func (s *subscriptionRegistry) drainSuspended(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	if !s.paused {
		s.mu.RUnlock()
		return errors.New("fusev3: cannot drain subscription workers before suspension")
	}
	done := s.serveDone
	s.mu.RUnlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("fusev3: drain subscription workers for epoch change: %w", ctx.Err())
	}
}

// resume permits a cold subscription only after the mount has installed the
// replacement epoch transport and staled the old server handles.
func (s *subscriptionRegistry) resume() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.paused {
		s.paused = false
		close(s.pauseChanged)
		s.pauseChanged = make(chan struct{})
	}
	s.mu.Unlock()
}

func (s *subscriptionRegistry) retry(ctx context.Context, deadline time.Time, operation func() error) error {
	var last error
	for s.config.clock.Now().Before(deadline) {
		if err := operation(); err == nil {
			return nil
		} else {
			last = err
		}
		remaining := deadline.Sub(s.config.clock.Now())
		if remaining <= 0 {
			break
		}
		delay := s.config.retryDelay
		if remaining < delay {
			delay = remaining
		}
		timer := s.config.clock.NewTimer(delay)
		select {
		case <-timer.C():
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
	if last == nil {
		last = errSubscriptionExpired
	}
	return last
}

func (s *subscriptionRegistry) invalidateAll(ctx context.Context) error {
	s.deactivate()
	deadline := s.config.clock.Now().Add(s.config.repairLead)
	repairCtx, cancel := context.WithTimeout(ctx, s.config.repairLead)
	defer cancel()
	return s.retry(repairCtx, deadline, func() error { return s.config.invalidator.InvalidateAllCaches(repairCtx) })
}

func (s *subscriptionRegistry) subscribe(ctx context.Context) error {
	if s == nil || s.rpc == nil {
		return errors.New("fusev3: subscription transport is required")
	}
	s.mu.RLock()
	paused := s.paused
	s.mu.RUnlock()
	if paused {
		return errSubscriptionPaused
	}
	if err := s.invalidateAll(ctx); err != nil {
		return fmt.Errorf("fusev3: cold subscription cache withdrawal: %w", err)
	}
	// A cold Subscribe asserts that this client has abandoned the preceding
	// incarnation's delegated buffer. Fence it before making that assertion on
	// the wire; SetIncarnation re-enables grant admission only after the complete
	// snapshot has been installed.
	if s.control != nil {
		s.control.FenceSubscription("cold subscription replacement")
	}

	var (
		snapshotID   []byte
		after        []byte
		watermark    uint64
		incarnation  uint64
		horizonNanos uint64
		horizon      time.Time
		delegated    []publicationIdentity
		previous     publicationIdentity
		havePrevious bool
	)
	for page := 0; page < s.config.maxPages; page++ {
		reply, pageHorizon, err := s.rpc.Subscribe(ctx, snapshotID, after)
		if err != nil {
			return fmt.Errorf("fusev3: subscribe page %d: %w", page, err)
		}
		if reply == nil || reply.GetIncarnation() == 0 || reply.GetHorizonNanos() == 0 ||
			len(reply.GetSnapshotId()) == 0 || !pageHorizon.After(s.config.clock.Now()) {
			return fmt.Errorf("%w: malformed page %d", errSubscriptionInvalid, page)
		}
		if page == 0 {
			watermark, incarnation, horizonNanos = reply.GetWatermark(), reply.GetIncarnation(), reply.GetHorizonNanos()
			horizon = pageHorizon
			snapshotID = bytes.Clone(reply.GetSnapshotId())
		} else if reply.GetWatermark() != watermark || reply.GetIncarnation() != incarnation ||
			reply.GetHorizonNanos() != horizonNanos || !bytes.Equal(reply.GetSnapshotId(), snapshotID) {
			return fmt.Errorf("%w: snapshot fields changed on page %d", errSubscriptionInvalid, page)
		}
		for _, rawIdentity := range reply.GetDelegatedIdentities() {
			identity, ok := publicationIdentityFromBytes(rawIdentity)
			if !ok || havePrevious && bytes.Compare(previous[:], identity[:]) >= 0 {
				return fmt.Errorf("%w: delegated identity order on page %d", errSubscriptionInvalid, page)
			}
			delegated = append(delegated, identity)
			previous, havePrevious = identity, true
		}
		next := reply.GetNextAfterIdentity()
		if len(next) == 0 {
			cacheUntil := horizon.Add(-s.config.repairLead)
			if !cacheUntil.After(s.config.clock.Now()) {
				return fmt.Errorf("%w: snapshot completed too near its horizon", errSubscriptionExpired)
			}
			set := make(map[publicationIdentity]struct{}, len(delegated))
			for _, identity := range delegated {
				set[identity] = struct{}{}
			}
			s.mu.Lock()
			if s.paused {
				s.mu.Unlock()
				return errSubscriptionPaused
			}
			s.active = true
			s.incarnation = incarnation
			s.generation++
			s.watermark = watermark
			s.horizon = horizon
			s.cacheUntil = cacheUntil
			s.delegated = set
			s.stale = make(map[publicationIdentity]struct{})
			s.coordinates = make(map[publicationCoordinate]subscriptionCoordinateState)
			s.generationFloor = 0
			s.versionFloor = 0
			s.lastChangeSeen = 0
			s.lastChangeAck = 0
			s.signalHorizonChangedLocked()
			s.mu.Unlock()
			if s.control != nil {
				s.control.SetIncarnation(incarnation)
			}
			return nil
		}
		if len(reply.GetDelegatedIdentities()) == 0 || len(next) != len(publicationIdentity{}) ||
			!bytes.Equal(next, reply.GetDelegatedIdentities()[len(reply.GetDelegatedIdentities())-1]) {
			return fmt.Errorf("%w: invalid pagination cursor on page %d", errSubscriptionInvalid, page)
		}
		after = bytes.Clone(next)
	}
	return fmt.Errorf("%w: pagination exceeded %d pages", errSubscriptionInvalid, s.config.maxPages)
}

func (s *subscriptionRegistry) currentIncarnation() (uint64, time.Time, <-chan struct{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.incarnation, s.cacheUntil, s.horizonChanged, s.active
}

// run keeps CONTROL delivery, renewal, and cumulative withdrawal independent.
// It returns only when the mount context ends. Every recovery iteration first
// performs a cold cache withdrawal, so an expired incarnation is never revived.
func (s *subscriptionRegistry) run(ctx context.Context) error {
	if s == nil {
		return errors.New("fusev3: subscription registry is required")
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.mu.RLock()
		paused, pauseChanged := s.paused, s.pauseChanged
		s.mu.RUnlock()
		if paused {
			select {
			case <-pauseChanged:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		_, _, _, active := s.currentIncarnation()
		if !active {
			if err := s.subscribe(ctx); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if errors.Is(err, errSubscriptionPaused) {
					continue
				}
				if err := s.waitRetry(ctx); err != nil {
					return err
				}
				continue
			}
		}
		if err := s.serveIncarnation(ctx); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (s *subscriptionRegistry) serveIncarnation(parent context.Context) error {
	s.mu.Lock()
	incarnation, active := s.incarnation, s.active && !s.paused
	if !active || incarnation == 0 {
		s.mu.Unlock()
		return errSubscriptionExpired
	}
	done := make(chan struct{})
	s.serveDone = done
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.serveDone == done {
			close(done)
		}
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	failures := make(chan error, 4)
	changeQueue := newSubscriptionChangeQueue()
	var workers sync.WaitGroup
	start := func(run func(context.Context) error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := run(ctx); err != nil && ctx.Err() == nil {
				select {
				case failures <- err:
				default:
				}
			}
		}()
	}
	start(func(ctx context.Context) error { return s.pollLoop(ctx, incarnation, changeQueue) })
	start(func(ctx context.Context) error { return s.changeLoop(ctx, incarnation, changeQueue) })
	start(func(ctx context.Context) error { return s.renewLoop(ctx, incarnation) })
	start(func(ctx context.Context) error { return s.horizonLoop(ctx, incarnation) })

	var result error
	select {
	case result = <-failures:
	case <-parent.Done():
		result = parent.Err()
	}
	cancel()
	changeQueue.close()
	workers.Wait()
	if parent.Err() != nil {
		return parent.Err()
	}
	if err := s.invalidateAll(parent); err != nil {
		return errors.Join(result, fmt.Errorf("fusev3: fence subscription incarnation %d: %w", incarnation, err))
	}
	return result
}

type subscriptionChangeQueue struct {
	mu        sync.Mutex
	wake      chan struct{}
	closed    bool
	head      int
	items     []subscriptionChangeWork
	completed uint64
	finished  map[uint64]struct{}
}

type subscriptionChangeWork struct {
	batch    *authoritypb.ChangeBatch
	sequence uint64
}

func (q *subscriptionChangeQueue) complete(sequence uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if sequence <= q.completed {
		return
	}
	if q.finished == nil {
		q.finished = make(map[uint64]struct{})
	}
	q.finished[sequence] = struct{}{}
	for {
		if _, ok := q.finished[q.completed+1]; !ok {
			break
		}
		q.completed++
		delete(q.finished, q.completed)
	}
}
func (q *subscriptionChangeQueue) completedThrough() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.completed
}

func newSubscriptionChangeQueue() *subscriptionChangeQueue {
	return &subscriptionChangeQueue{wake: make(chan struct{}, 1)}
}

func (q *subscriptionChangeQueue) push(batch *authoritypb.ChangeBatch, sequence uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return context.Canceled
	}
	q.items = append(q.items, subscriptionChangeWork{batch, sequence})
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

func (q *subscriptionChangeQueue) pop(ctx context.Context) (subscriptionChangeWork, error) {
	for {
		q.mu.Lock()
		if q.head < len(q.items) {
			batch := q.items[q.head]
			q.items[q.head] = subscriptionChangeWork{}
			q.head++
			if q.head == len(q.items) {
				q.items = q.items[:0]
				q.head = 0
			} else if q.head >= 1024 && q.head*2 >= len(q.items) {
				q.items = append(q.items[:0], q.items[q.head:]...)
				q.head = 0
			}
			q.mu.Unlock()
			return batch, nil
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return subscriptionChangeWork{}, context.Canceled
		}
		select {
		case <-q.wake:
		case <-ctx.Done():
			return subscriptionChangeWork{}, ctx.Err()
		}
	}
}

func (q *subscriptionChangeQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.items = nil
	q.head = 0
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (s *subscriptionRegistry) pollLoop(ctx context.Context, incarnation uint64, changes *subscriptionChangeQueue) error {
	var after uint64
	for {
		event, err := s.rpc.NextControlEvent(ctx, incarnation, after, changes.completedThrough())
		if err != nil {
			if errors.Is(err, authorityrpc.ErrSubscriptionReset) {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := s.waitRetry(ctx); err != nil {
				return err
			}
			continue
		}
		if event == nil || event.GetIncarnation() != incarnation || event.GetSequence() != after+1 || event.GetEvent() == nil {
			return fmt.Errorf("%w: malformed CONTROL event after %d", errSubscriptionInvalid, after)
		}
		if batch := event.GetChangeBatch(); batch != nil {
			if batch.GetIncarnation() != incarnation || len(batch.GetEntries()) == 0 {
				return fmt.Errorf("%w: malformed change batch at event %d", errSubscriptionInvalid, event.GetSequence())
			}
			if err := s.registerChangeBatch(incarnation, batch); err != nil {
				return err
			}
			if err := changes.push(batch, event.GetSequence()); err != nil {
				return err
			}
		} else if s.control == nil {
			return fmt.Errorf("%w: delegation event has no handler", errSubscriptionInvalid)
		} else {
			done := s.control.HandleControlEvent(ctx, event)
			go func(sequence uint64) {
				select {
				case <-done:
					changes.complete(sequence)
				case <-ctx.Done():
				}
			}(event.GetSequence())
		}
		after = event.GetSequence()
	}
}

func (s *subscriptionRegistry) waitRetry(ctx context.Context) error {
	timer := s.config.clock.NewTimer(s.config.retryDelay)
	select {
	case <-timer.C():
		return nil
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	}
}

func (s *subscriptionRegistry) registerChangeBatch(incarnation uint64, batch *authoritypb.ChangeBatch) error {
	type validatedChange struct {
		entry       *authoritypb.ChangeEntry
		coordinates []publicationCoordinate
		identity    publicationIdentity
		grant       bool
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.incarnation != incarnation {
		return errSubscriptionExpired
	}
	expected := s.lastChangeSeen + 1
	validated := make([]validatedChange, 0, len(batch.GetEntries()))
	for _, entry := range batch.GetEntries() {
		coordinates, identity, grant, _, err := validateChangeEntry(entry)
		if err != nil || entry.GetPosition() != expected {
			if err == nil {
				err = fmt.Errorf("position %d follows %d", entry.GetPosition(), s.lastChangeSeen)
			}
			return fmt.Errorf("%w: %v", errSubscriptionInvalid, err)
		}
		expected++
		validated = append(validated, validatedChange{entry: entry, coordinates: coordinates, identity: identity, grant: grant})
	}
	for _, change := range validated {
		entry, coordinates := change.entry, change.coordinates
		s.generation++
		if len(s.coordinates)+len(coordinates) > maxSubscriptionCoordinates {
			s.coordinates = make(map[publicationCoordinate]subscriptionCoordinateState)
			s.generationFloor = s.generation
			if entry.GetVolumeVersion() > s.versionFloor {
				s.versionFloor = entry.GetVolumeVersion()
			}
		}
		for _, coordinate := range coordinates {
			state := s.coordinates[coordinate]
			state.generation = s.generation
			if entry.GetVolumeVersion() > state.minVersion {
				state.minVersion = entry.GetVolumeVersion()
			}
			s.coordinates[coordinate] = state
		}
		if change.grant {
			s.delegated[change.identity] = struct{}{}
		}
		// Release is installed only by the ordered change worker, after every
		// earlier withdrawal is proven. Registering it here could briefly reopen
		// cache admission past a still-unacknowledged grant.
		s.lastChangeSeen = entry.GetPosition()
	}
	return nil
}

func validateChangeEntry(entry *authoritypb.ChangeEntry) ([]publicationCoordinate, publicationIdentity, bool, bool, error) {
	if entry == nil || entry.GetPosition() == 0 || entry.GetVolumeVersion() == 0 {
		return nil, publicationIdentity{}, false, false, errors.New("zero change entry field")
	}
	var identity publicationIdentity
	switch entry.GetKind() {
	case authoritypb.ChangeKind_CHANGE_KIND_NAMESPACE_CHANGED:
		parent, ok := publicationIdentityFromBytes(entry.GetParentIdentity())
		if !ok || len(entry.GetIdentity()) != 0 || !validSourceNamespaceName(string(entry.GetName())) || entry.GetByteRange() != nil {
			return nil, identity, false, false, errors.New("invalid namespace change")
		}
		return []publicationCoordinate{{kind: publicationNamespaceName, parent: parent, name: string(entry.GetName())}}, identity, false, false, nil
	case authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED:
		var ok bool
		identity, ok = publicationIdentityFromBytes(entry.GetIdentity())
		if !ok || len(entry.GetParentIdentity()) != 0 || len(entry.GetName()) != 0 || entry.GetByteRange() != nil {
			return nil, identity, false, false, errors.New("invalid attributes change")
		}
		return []publicationCoordinate{{kind: publicationItemAttributes, item: identity}}, identity, false, false, nil
	case authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED:
		var ok bool
		identity, ok = publicationIdentityFromBytes(entry.GetIdentity())
		byteRange := entry.GetByteRange()
		if !ok || len(entry.GetParentIdentity()) != 0 || len(entry.GetName()) != 0 ||
			byteRange != nil && (byteRange.GetLength() == 0 || byteRange.GetOffset() > math.MaxUint64-byteRange.GetLength()) {
			return nil, identity, false, false, errors.New("invalid data change")
		}
		return []publicationCoordinate{{kind: publicationItemData, item: identity}}, identity, false, false, nil
	case authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_GRANTED:
		var ok bool
		identity, ok = publicationIdentityFromBytes(entry.GetIdentity())
		if !ok || len(entry.GetParentIdentity()) != 0 || len(entry.GetName()) != 0 || entry.GetByteRange() != nil {
			return nil, identity, false, false, errors.New("invalid delegation grant change")
		}
		return []publicationCoordinate{{kind: publicationItemAttributes, item: identity}, {kind: publicationItemData, item: identity}}, identity, true, false, nil
	case authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_RELEASED:
		var ok bool
		identity, ok = publicationIdentityFromBytes(entry.GetIdentity())
		if !ok || len(entry.GetParentIdentity()) != 0 || len(entry.GetName()) != 0 || entry.GetByteRange() != nil {
			return nil, identity, false, false, errors.New("invalid delegation release change")
		}
		return nil, identity, false, true, nil
	case authoritypb.ChangeKind_CHANGE_KIND_DIRECTORY_CHANGED:
		var ok bool
		identity, ok = publicationIdentityFromBytes(entry.GetIdentity())
		if !ok || len(entry.GetParentIdentity()) != 0 || len(entry.GetName()) != 0 || entry.GetByteRange() != nil {
			return nil, identity, false, false, errors.New("invalid directory change")
		}
		return []publicationCoordinate{{kind: publicationItemEnumeration, item: identity}}, identity, false, false, nil
	default:
		return nil, identity, false, false, fmt.Errorf("unknown change kind %d", entry.GetKind())
	}
}

func (s *subscriptionRegistry) changeLoop(ctx context.Context, incarnation uint64, changes *subscriptionChangeQueue) error {
	for {
		work, err := changes.pop(ctx)
		if err != nil {
			return err
		}
		batch := work.batch
		for _, entry := range batch.GetEntries() {
			if err := s.applyChange(ctx, incarnation, entry); err != nil {
				return err
			}
		}
		position := batch.GetEntries()[len(batch.GetEntries())-1].GetPosition()
		if err := s.ackChanges(ctx, incarnation, position); err != nil {
			return err
		}
		s.mu.Lock()
		if s.incarnation == incarnation && position > s.lastChangeAck {
			s.lastChangeAck = position
		}
		s.mu.Unlock()
		changes.complete(work.sequence)
	}
}

func (s *subscriptionRegistry) applyChange(ctx context.Context, incarnation uint64, entry *authoritypb.ChangeEntry) error {
	coordinates, identity, _, release, err := validateChangeEntry(entry)
	if err != nil {
		return fmt.Errorf("%w: %v", errSubscriptionInvalid, err)
	}
	if release {
		s.mu.Lock()
		if s.active && s.incarnation == incarnation {
			delete(s.delegated, identity)
		}
		s.mu.Unlock()
		return nil
	}
	if entry.GetKind() == authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED || entry.GetKind() == authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED {
		if invalidator, ok := s.control.(interface{ InvalidateBaseAttr([]byte, uint64) }); ok {
			invalidator.InvalidateBaseAttr(identity[:], entry.GetVolumeVersion())
		}
	}
	for _, coordinate := range coordinates {
		if err := s.withdrawCoordinate(ctx, coordinate, entry.GetByteRange()); err != nil {
			s.markChangeStale(coordinate)
			return err
		}
	}
	return nil
}

func (s *subscriptionRegistry) withdrawCoordinate(ctx context.Context, coordinate publicationCoordinate, byteRange *authoritypb.ByteRange) error {
	deadline := s.config.clock.Now().Add(s.config.repairLead)
	s.mu.RLock()
	if s.cacheUntil.Before(deadline) {
		deadline = s.cacheUntil
	}
	s.mu.RUnlock()
	remaining := deadline.Sub(s.config.clock.Now())
	if remaining <= 0 {
		return errSubscriptionExpired
	}
	repairCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	if err := s.config.invalidator.CloseCacheCoordinate(repairCtx, coordinate); err != nil {
		return fmt.Errorf("fusev3: close cache coordinate: %w", err)
	}
	err := s.retry(repairCtx, deadline, func() error {
		return s.config.invalidator.InvalidateCacheCoordinate(repairCtx, coordinate, byteRange)
	})
	if err != nil {
		return fmt.Errorf("fusev3: invalidate cache coordinate: %w", err)
	}
	s.config.invalidator.OpenCacheCoordinate(coordinate)
	return nil
}

func (s *subscriptionRegistry) markChangeStale(coordinate publicationCoordinate) {
	identity := coordinate.item
	if coordinate.kind == publicationNamespaceName {
		identity = coordinate.parent
	}
	if identity == (publicationIdentity{}) {
		return
	}
	s.mu.Lock()
	s.stale[identity] = struct{}{}
	s.mu.Unlock()
	s.config.invalidator.MarkIdentityStale(identity)
}

func (s *subscriptionRegistry) ackChanges(ctx context.Context, incarnation, position uint64) error {
	s.mu.RLock()
	deadline := s.cacheUntil
	s.mu.RUnlock()
	err := s.retry(ctx, deadline, func() error {
		return s.rpc.AcknowledgeChanges(ctx, incarnation, position)
	})
	if err != nil {
		return fmt.Errorf("fusev3: acknowledge changes through %d: %w", position, err)
	}
	return nil
}

func (s *subscriptionRegistry) renewLoop(ctx context.Context, incarnation uint64) error {
	for {
		timer := s.config.clock.NewTimer(volumeserver.SubscriptionRenewInterval)
		select {
		case <-timer.C():
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
		deadline, err := s.rpc.RenewSubscription(ctx, incarnation)
		if err != nil {
			if errors.Is(err, authorityrpc.ErrSubscriptionReset) {
				return err
			}
			continue
		}
		if !s.acceptRenewal(incarnation, deadline, s.config.clock.Now()) {
			s.mu.RLock()
			current := s.active && s.incarnation == incarnation
			s.mu.RUnlock()
			if current {
				continue
			}
			return errSubscriptionExpired
		}
	}
}

func (s *subscriptionRegistry) acceptRenewal(incarnation uint64, deadline, now time.Time) bool {
	cacheUntil := deadline.Add(-s.config.repairLead)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.paused || s.incarnation != incarnation {
		return false
	}
	// A late renewal cannot revive permission after the prior conservative
	// boundary. It is deliberately ignored rather than extending from receipt.
	if !now.Before(s.cacheUntil) || !cacheUntil.After(now) {
		return false
	}
	if deadline.After(s.horizon) {
		s.horizon = deadline
		s.cacheUntil = cacheUntil
		s.signalHorizonChangedLocked()
	}
	return true
}

func (s *subscriptionRegistry) horizonLoop(ctx context.Context, incarnation uint64) error {
	for {
		current, deadline, changed, active := s.currentIncarnation()
		if !active || current != incarnation {
			return errSubscriptionExpired
		}
		delay := deadline.Sub(s.config.clock.Now())
		if delay <= 0 {
			return errSubscriptionExpired
		}
		timer := s.config.clock.NewTimer(delay)
		select {
		case <-timer.C():
			return errSubscriptionExpired
		case <-changed:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

// invalidateCacheCoordinate performs the reverse-notify side of one proven
// withdrawal. closeCacheCoordinate, called first by the registry, has already
// rejected and drained cache-installing replies for this exact coordinate.
func (r *rawFileSystem) invalidateCacheCoordinate(coordinate publicationCoordinate, byteRange *authoritypb.ByteRange) error {
	ctx := context.Background()
	if r != nil && r.mount != nil && r.mount.ctx != nil {
		ctx = r.mount.ctx
	}
	return r.invalidateCacheCoordinateContext(ctx, coordinate, byteRange)
}

func (r *rawFileSystem) invalidateCacheCoordinateContext(ctx context.Context, coordinate publicationCoordinate, byteRange *authoritypb.ByteRange) error {
	if r == nil {
		return errors.New("fusev3: cache invalidation has no frontend")
	}
	switch coordinate.kind {
	case publicationNamespaceName:
		r.mu.Lock()
		parent := r.byIdentityLocked(coordinate.parent)
		if parent == nil {
			r.mu.Unlock()
			return nil
		}
		key := nameKey{parent: parent.key.inode, name: coordinate.name}
		child := r.cachedNames[key]
		r.dropCachedNameLocked(key)
		r.dropCachedNegativeLocked(key)
		reclaim := r.collectLocked(child)
		r.mu.Unlock()
		r.mount.deferReclaim(reclaim)
		// Every Authority-backed kernel name reply has entry_valid=0. Purging daemon bindings
		// after the exact reply drain fully withdraws namespace permission.
		// EntryNotify adds no validity proof and can deadlock on a parent lock
		// held by a mutation callback that has not reached our source gate yet.
		return nil
	case publicationItemEnumeration:
		r.mu.Lock()
		handles := make([]*dirHandle, 0)
		for _, handle := range r.handles {
			if handle != nil && handle.dir != nil && handle.inode != nil && handle.inode.identity == coordinate.item {
				handles = append(handles, handle.dir)
			}
		}
		r.mu.Unlock()
		for _, handle := range handles {
			handle.invalidateEnumeration()
		}
		return nil
	case publicationItemAttributes, publicationItemData:
		notifier := r.mount.notifier()
		if notifier == nil {
			return errors.New("fusev3: cache invalidation has no kernel notification channel")
		}
		if coordinate.kind == publicationItemData {
			if err := r.drainDataPublicationsContext(ctx, coordinate); err != nil {
				return err
			}
		}
		r.mu.Lock()
		record := r.byIdentityLocked(coordinate.item)
		// Whole/range data invalidation also withdraws kernel attributes. Drop
		// the daemon payload in both cases so a later LOOKUP cannot reuse size or
		// timestamps from before the data mutation.
		delete(r.cachedAttrs, coordinate.item)
		delete(r.cachedAttrPayloads, coordinate.item)
		r.mu.Unlock()
		if record == nil {
			return nil
		}
		if coordinate.kind == publicationItemAttributes {
			if status := notifier.InodeNotify(record.id, -1, 0); !status.Ok() && status != fuse.ENOENT {
				return fmt.Errorf("fusev3: invalidate attributes for inode %d: %v", record.id, status)
			}
			return nil
		}
		offset, length := int64(0), int64(0)
		if byteRange != nil && byteRange.GetOffset() <= math.MaxInt64 && byteRange.GetLength() <= math.MaxInt64 &&
			byteRange.GetOffset() <= math.MaxInt64-byteRange.GetLength() {
			offset, length = int64(byteRange.GetOffset()), int64(byteRange.GetLength())
		}
		if status := notifier.InodeNotify(record.id, offset, length); !status.Ok() && status != fuse.ENOENT {
			return fmt.Errorf("fusev3: invalidate data for inode %d: %v", record.id, status)
		}
		return nil
	default:
		return errors.New("fusev3: invalidate unknown cache coordinate")
	}
}

// invalidateAllCaches proves a cold boundary. Data records remain indexed:
// cache-capable open descriptions survive a subscription incarnation and may
// refill after resubscription, so later changes must still be able to find and
// invalidate them.
func (r *rawFileSystem) invalidateAllCaches(ctx context.Context) error {
	if r == nil {
		return errors.New("fusev3: cold cache invalidation has no frontend")
	}
	// First close every coordinate which either has payload or can still install
	// payload from an admitted reply. This is the F10 drain: invalidating before
	// these physical replies finish would allow one of them to refill behind the
	// cold boundary.
	r.mu.Lock()
	coordinates := make(map[publicationCoordinate]struct{})
	for coordinate := range r.cacheReservations {
		coordinates[coordinate] = struct{}{}
	}
	for namespace := range r.cachedStableNames {
		coordinates[publicationCoordinate{kind: publicationNamespaceName, parent: namespace.parent, name: namespace.name}] = struct{}{}
	}
	for key := range r.cachedNegatives {
		if parent := r.directoryLocked(key.parent); parent != nil && !parent.reclaimed {
			coordinates[publicationCoordinate{kind: publicationNamespaceName, parent: parent.identity, name: key.name}] = struct{}{}
		}
	}
	for identity := range r.cachedAttrs {
		coordinates[publicationCoordinate{kind: publicationItemAttributes, item: identity}] = struct{}{}
	}
	for _, record := range r.cachedData {
		if record != nil {
			coordinates[publicationCoordinate{kind: publicationItemData, item: record.identity}] = struct{}{}
		}
	}
	for _, publication := range r.replyPublications {
		if publication == nil {
			continue
		}
		for _, coordinate := range publication.cachedCoordinates[:publication.cachedCount] {
			coordinates[coordinate] = struct{}{}
		}
		for _, candidate := range publication.names {
			coordinates[candidate.coordinate] = struct{}{}
		}
		for _, candidate := range publication.attrs {
			coordinates[candidate.coordinate] = struct{}{}
		}
		for _, candidate := range publication.data {
			coordinates[candidate.coordinate] = struct{}{}
		}
		for _, coordinate := range publication.admittedData {
			coordinates[coordinate] = struct{}{}
		}
	}
	r.mu.Unlock()
	for coordinate := range coordinates {
		if err := r.closeCacheCoordinate(ctx, coordinate); err != nil {
			return fmt.Errorf("fusev3: close cache coordinate for cold subscription: %w", err)
		}
	}

	r.mu.Lock()
	type nameInvalidation struct {
		parent uint64
		name   string
	}
	nameInvalidations := make([]nameInvalidation, 0, len(r.cachedStableNames)+len(r.cachedNegatives))
	for namespace := range r.cachedStableNames {
		if parent := r.byIdentityLocked(namespace.parent); parent != nil {
			nameInvalidations = append(nameInvalidations, nameInvalidation{parent: parent.id, name: namespace.name})
		}
	}
	for key := range r.cachedNegatives {
		if parent := r.directoryLocked(key.parent); parent != nil && !parent.reclaimed {
			nameInvalidations = append(nameInvalidations, nameInvalidation{parent: parent.id, name: key.name})
		}
	}
	for key := range r.cachedNames {
		r.dropCachedNameLocked(key)
	}
	for key := range r.cachedNegatives {
		r.dropCachedNegativeLocked(key)
	}
	dataRecords := make(map[*inodeRecord]struct{}, len(r.cachedData))
	for _, record := range r.cachedData {
		if record != nil && !record.reclaimed {
			dataRecords[record] = struct{}{}
		}
	}
	attrRecords := make(map[*inodeRecord]struct{}, len(r.cachedAttrs))
	for _, record := range r.cachedAttrs {
		if record != nil && !record.reclaimed {
			if _, covered := dataRecords[record]; !covered {
				attrRecords[record] = struct{}{}
			}
		}
	}
	// A failed reverse notification permanently denied this record in the old
	// subscription even after its daemon payload was discarded. Include it in
	// the cold proof so a successful resubscribe may clear coherence staleness.
	for _, record := range r.nodesByID {
		if record != nil && !record.reclaimed && record.stale.Load() {
			if _, covered := dataRecords[record]; !covered {
				attrRecords[record] = struct{}{}
			}
		}
	}
	r.cachedAttrs = make(map[publicationIdentity]*inodeRecord)
	r.cachedAttrPayloads = make(map[publicationIdentity]cachedAttrPayload)
	dirHandles := make([]*dirHandle, 0)
	for _, handle := range r.handles {
		if handle != nil && handle.dir != nil {
			dirHandles = append(dirHandles, handle.dir)
		}
	}
	r.mu.Unlock()

	for _, handle := range dirHandles {
		handle.invalidateEnumeration()
	}
	notifier := r.mount.notifier()
	if notifier == nil && len(nameInvalidations)+len(dataRecords)+len(attrRecords) != 0 {
		return errors.New("fusev3: cold cache invalidation has no kernel notification channel")
	}
	for _, name := range nameInvalidations {
		if status := notifier.EntryNotify(name.parent, name.name); !status.Ok() && status != fuse.ENOENT {
			return fmt.Errorf("fusev3: cold invalidate name %q under inode %d: %v", name.name, name.parent, status)
		}
	}
	identities := make([]publicationIdentity, 0, len(dataRecords)+len(attrRecords))
	for record := range dataRecords {
		identities = append(identities, record.identity)
	}
	for record := range attrRecords {
		identities = append(identities, record.identity)
	}
	sort.Slice(identities, func(i, j int) bool { return bytes.Compare(identities[i][:], identities[j][:]) < 0 })
	for _, identity := range identities {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		r.mu.Lock()
		record := r.byIdentityLocked(identity)
		_, data := dataRecords[record]
		r.mu.Unlock()
		if record == nil {
			continue
		}
		offset := int64(-1)
		if data {
			offset = 0
		}
		if status := notifier.InodeNotify(record.id, offset, 0); !status.Ok() && status != fuse.ENOENT {
			return fmt.Errorf("fusev3: cold invalidate inode %d: %v", record.id, status)
		}
	}
	r.mu.Lock()
	for _, record := range r.nodesByID {
		if record != nil {
			// Epoch staleness belongs to the old server handle, not to the
			// subscription incarnation. A cold cache proof can repair an inode
			// invalidation failure, but it must never resurrect an old-epoch node.
			if record.node == nil || !record.node.epochStale.Load() {
				record.stale.Store(false)
			}
			if record.node != nil && !record.node.epochStale.Load() {
				record.node.stale.Store(false)
			}
		}
	}
	for coordinate := range r.repairingCoordinates {
		delete(r.repairingCoordinates, coordinate)
	}
	r.signalSourceChangedLocked()
	r.mu.Unlock()
	return nil
}

func (r *rawFileSystem) markIdentityStale(identity publicationIdentity) {
	if r == nil || identity == (publicationIdentity{}) {
		return
	}
	r.mu.Lock()
	record := r.byIdentityLocked(identity)
	r.mu.Unlock()
	if record != nil {
		record.stale.Store(true)
		if record.node != nil {
			record.node.stale.Store(true)
		}
	}
}
