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
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/permissionclock"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
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
	Subscribe(context.Context, []byte, []byte) (*authoritypb.SubscribeReply, permissionclock.Permission, error)
	RenewSubscription(context.Context, uint64) (permissionclock.Permission, error)
	NextControlEvent(context.Context, uint64, uint64, uint64) (*authoritypb.ControlEvent, error)
	AcknowledgeChanges(context.Context, uint64, uint64) error
}

// subscriptionControlHandler must return after accepting an event. Delegation
// flushing and acknowledgments run asynchronously so a withdrawal which is
// waiting on a cache-installing reply can never stop the poll that delivers the
// delegation event needed to release that reply.
type subscriptionControlHandler interface {
	InterruptSubscription()
	FenceSubscription(string)
	SetIncarnation(uint64)
	HandleControlEvent(context.Context, *authoritypb.ControlEvent) <-chan struct{}
}

type subscriptionInvalidator interface {
	CloseCacheCoordinates(context.Context, []publicationCoordinate) (cacheWithdrawal, error)
	InvalidateCacheCoordinates(context.Context, []subscriptionWithdrawal) error
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

type continuousSubscriptionClock struct{}

type wallSubscriptionTimer struct{ timer *time.Timer }

func (continuousSubscriptionClock) Now() time.Time { return continuous.Time() }
func (continuousSubscriptionClock) NewTimer(d time.Duration) subscriptionTimer {
	return wallSubscriptionTimer{timer: time.NewTimer(d)}
}
func (t wallSubscriptionTimer) C() <-chan time.Time { return t.timer.C }
func (t wallSubscriptionTimer) Stop() bool          { return t.timer.Stop() }

type subscriptionConfig struct {
	beforeRecoveryProof func(install bool)
	// Deterministic test schedule at the last proof check/local-store boundary.
	beforeWorkspaceInstall func()
	afterWorkspaceSample   func() // deterministic register-return/use cut; nil in production
	clock                  subscriptionClock
	retryDelay             time.Duration
	withdrawalLead         time.Duration
	maxPages               int
	invalidator            subscriptionInvalidator
}

type subscriptionCoordinateState struct {
	generation uint64
	minVersion uint64
}

// subscriptionRegistry owns the mount's one volume-wide subscription. Its mutex
// covers cache admission state only and is never held across transport calls,
// reverse notifications, or publication drains.
type subscriptionRegistry struct {
	mount   *Mount
	rpc     subscriptionRPC
	control subscriptionControlHandler
	config  subscriptionConfig

	mu                     sync.RWMutex
	workspaceProof         *workspaceadmission.RecoveryPermit
	workspaceDrain         *workspaceDrainPermit
	workspaceOwned         bool
	subscribeCancel        context.CancelFunc
	subscribeDone          chan struct{}
	renewCancel            context.CancelFunc
	renewDone              chan struct{}
	controlCancel          context.CancelFunc
	pollCancel             context.CancelFunc
	pollDone               chan struct{}
	controlQueue           *subscriptionChangeQueue
	workspaceFailure       error
	workspaceReset         bool
	ordinaryWithdrawalDone chan struct{}
	active                 bool
	paused                 bool
	incarnation            uint64
	generation             uint64
	watermark              uint64
	horizon                time.Time
	cacheUntil             time.Time
	permission             permissionclock.Permission
	rtcClosed              bool
	delegated              map[publicationIdentity]uint64
	stale                  map[publicationIdentity]struct{}
	coordinates            map[publicationCoordinate]subscriptionCoordinateState
	generationFloor        uint64
	versionFloor           uint64
	lastChangeSeen         uint64
	lastChangeAck          uint64

	progressChanged chan struct{}
	horizonChanged  chan struct{}
	pauseChanged    chan struct{}
	serveDone       chan struct{}
}

type mountSubscriptionInvalidator struct{ mount *Mount }

func (i mountSubscriptionInvalidator) raw() (*rawFileSystem, error) {
	if i.mount == nil || i.mount.raw == nil {
		return nil, errors.New("fusev3: subscription invalidation has no kernel frontend")
	}
	return i.mount.raw, nil
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
	withdrawalLead := time.Second
	if mount != nil && mount.withdrawalTimeout > 0 && mount.withdrawalTimeout < withdrawalLead {
		withdrawalLead = mount.withdrawalTimeout
	}
	return newSubscriptionRegistryWithConfig(mount, rpc, control, subscriptionConfig{
		clock: continuousSubscriptionClock{}, retryDelay: subscriptionRetryDelay, withdrawalLead: withdrawalLead,
		maxPages: maxSubscriptionPages, invalidator: mountSubscriptionInvalidator{mount: mount},
	})
}

func newSubscriptionRegistryWithConfig(mount *Mount, rpc subscriptionRPC, control subscriptionControlHandler, config subscriptionConfig) *subscriptionRegistry {
	if config.clock == nil {
		config.clock = continuousSubscriptionClock{}
	}
	if config.retryDelay <= 0 {
		config.retryDelay = subscriptionRetryDelay
	}
	if config.withdrawalLead <= 0 {
		config.withdrawalLead = time.Second
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
		delegated: make(map[publicationIdentity]uint64), stale: make(map[publicationIdentity]struct{}),
		coordinates:     make(map[publicationCoordinate]subscriptionCoordinateState),
		progressChanged: make(chan struct{}),
		horizonChanged:  make(chan struct{}),
		pauseChanged:    make(chan struct{}),
		serveDone:       serveDone,
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.liveLocked() || s.mount != nil && s.mount.workspace != nil && !s.workspaceServingLocked() {
		return subscriptionStamp{}
	}
	// The publication owns the entry's serving permit. Cache facts need only
	// the subscription generation, which changes at every cold installation.
	return subscriptionStamp{incarnation: s.incarnation, generation: s.generation}
}

// The source is omitted from the authority's change stream. Its own commit
// must nevertheless reject older in-flight samples after its local gate opens.
// Refresh only the committing reply; unrelated coordinates retain their stamps.
func (s *subscriptionRegistry) advanceSource(stamp subscriptionStamp, coordinates map[publicationCoordinate]struct{}, version uint64) subscriptionStamp {
	if s == nil {
		return stamp
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || stamp.incarnation != s.incarnation {
		return stamp
	}
	s.generation++
	if len(s.coordinates)+len(coordinates) > maxSubscriptionCoordinates {
		clear(s.coordinates)
		s.generationFloor = s.generation
		s.versionFloor = max(s.versionFloor, version)
	}
	for coordinate := range coordinates {
		state := s.coordinates[coordinate]
		state.generation = s.generation
		state.minVersion = max(state.minVersion, version)
		s.coordinates[coordinate] = state
	}
	stamp.generation = s.generation
	return stamp
}

// remaining is the sole cache-admission predicate. A change advances only its
// exact coordinates, so an unrelated event does not invalidate a reply already
// in flight. The global generation remains in the stamp to distinguish a reply
// admitted before a same-version withdrawal from one admitted after it.
func (s *subscriptionRegistry) remaining(coordinate publicationCoordinate, stamp subscriptionStamp, servedVersion uint64) time.Duration {
	if s == nil || stamp.incarnation == 0 {
		return 0
	}
	// A private synchronous generation can become an owned delegation in its
	// DATA reply without a source stream event. Local ownership is decisive,
	// including when an older release event overtakes that reply.
	if (coordinate.kind == publicationItemAttributes || coordinate.kind == publicationItemData) && s.mount != nil && s.mount.delegations != nil && !s.mount.delegations.sharedCacheAllowed(coordinate.item[:]) {
		return 0
	}
	return s.remainingAfterOwnershipCheck(coordinate, stamp, servedVersion)
}

// remainingAfterOwnershipCheck is used by a cached reply after checking local
// delegation ownership outside raw.mu. Acquiring delegation locks under raw.mu
// could deadlock with a queued epoch fence and a write's source gate.
func (s *subscriptionRegistry) remainingAfterOwnershipCheck(coordinate publicationCoordinate, stamp subscriptionStamp, servedVersion uint64) time.Duration {
	if s == nil || stamp.incarnation == 0 {
		return 0
	}
	if servedVersion == 0 {
		servedVersion = stamp.version
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.liveLocked() || s.mount != nil && s.mount.workspace != nil && !s.workspaceServingLocked() || stamp.incarnation != s.incarnation {
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
	return max(time.Duration(0), s.permissionRemainingLocked(s.config.withdrawalLead))
}

func (s *subscriptionRegistry) signalHorizonChangedLocked() {
	close(s.horizonChanged)
	s.horizonChanged = make(chan struct{})
}

func (s *subscriptionRegistry) deactivate() {
	s.mu.Lock()
	if s.workspaceOwned {
		s.workspaceReset = true
		s.mu.Unlock()
		return
	}
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
		if err := ctx.Err(); err != nil {
			return err
		}
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
	s.mu.Lock()
	if s.workspaceOwned {
		s.mu.Unlock()
		return errSubscriptionPaused
	}
	if s.active {
		s.active = false
		s.generation++
		s.signalHorizonChangedLocked()
	}
	done := make(chan struct{})
	s.ordinaryWithdrawalDone = done
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.ordinaryWithdrawalDone = nil; close(done); s.mu.Unlock() }()
	deadline := s.config.clock.Now().Add(s.config.withdrawalLead)
	withdrawalCtx, cancel := context.WithTimeout(ctx, s.config.withdrawalLead)
	defer cancel()
	return s.retry(withdrawalCtx, deadline, func() error { return s.config.invalidator.InvalidateAllCaches(withdrawalCtx) })
}

func (s *subscriptionRegistry) subscribe(ctx context.Context) error {
	if s == nil || s.rpc == nil {
		return errors.New("fusev3: subscription transport is required")
	}
	s.mu.Lock()
	_, recovery := ctx.Value(workspaceRecoveryKey{}).(workspaceadmission.RecoveryPermit)
	if s.subscribeDone != nil || s.workspaceOwned && !recovery {
		s.mu.Unlock()
		return errSubscriptionPaused
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.subscribeCancel, s.subscribeDone = cancel, done
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		s.subscribeCancel, s.subscribeDone = nil, nil
		close(done)
		s.mu.Unlock()
	}()
	var proof *workspaceadmission.RecoveryPermit
	if s.mount != nil && s.mount.workspace != nil {
		if s.config.beforeRecoveryProof != nil {
			s.config.beforeRecoveryProof(false)
		}
		p, ok := ctx.Value(workspaceRecoveryKey{}).(workspaceadmission.RecoveryPermit)
		if !ok {
			return workspaceadmission.ErrClosed
		}
		if err := s.mount.workspace.Recover(p); err != nil {
			return err
		}
		proof = &p
	}
	s.mu.RLock()
	paused := s.paused
	s.mu.RUnlock()
	if paused {
		return errSubscriptionPaused
	}
	withdraw := s.invalidateAll
	if proof != nil {
		withdraw = s.config.invalidator.InvalidateAllCaches
	}
	if err := withdraw(ctx); err != nil {
		return fmt.Errorf("fusev3: cold subscription cache withdrawal: %w", err)
	}
	// A cold Subscribe asserts that this client has abandoned the preceding
	// incarnation's delegated buffer. Fence it before making that assertion on
	// the wire; SetIncarnation re-enables grant admission only after the complete
	// snapshot has been installed.
	if s.control != nil {
		// Wake buffered admissions which own callback readers before waiting
		// for those readers. Final retirement still follows their completion.
		s.control.InterruptSubscription()
		// A metadata callback may pin several inode admission readers until
		// its physical reply. Finish sampling every row before reset takes
		// manager epoch/index writers; otherwise a later row can wait behind
		// a reset which is itself waiting for the earlier row's reply.
		// Physical reply settlement does not require this callback fence.
		if s.mount != nil {
			s.mount.epochMu.Lock()
		}
		s.control.FenceSubscription("cold subscription replacement")
		if s.mount != nil {
			s.mount.epochMu.Unlock()
		}
	}

	var (
		snapshotID   []byte
		after        []byte
		watermark    uint64
		incarnation  uint64
		horizonNanos uint64
		horizon      time.Time
		permission   permissionclock.Permission
		delegated    []publicationIdentity
		previous     publicationIdentity
		havePrevious bool
	)
	for page := 0; page < s.config.maxPages; page++ {
		reply, pageHorizon, err := s.rpc.Subscribe(ctx, snapshotID, after)
		if err != nil {
			if errors.Is(err, permissionclock.ErrUnavailable) {
				s.mu.Lock()
				s.closeRTCIntervalLocked()
				s.mu.Unlock()
				return fmt.Errorf("%w: subscribe RTC evidence", errSubscriptionExpired)
			}
			return fmt.Errorf("fusev3: subscribe page %d: %w", page, err)
		}
		if reply == nil || reply.GetIncarnation() == 0 || reply.GetHorizonNanos() == 0 ||
			len(reply.GetSnapshotId()) == 0 {
			return fmt.Errorf("%w: malformed page %d", errSubscriptionInvalid, page)
		}
		if !pageHorizon.After(s.config.clock.Now()) {
			return fmt.Errorf("%w: aged page %d", errSubscriptionExpired, page)
		}
		if page == 0 {
			watermark, incarnation, horizonNanos = reply.GetWatermark(), reply.GetIncarnation(), reply.GetHorizonNanos()
			horizon = pageHorizon.Time
			permission = pageHorizon
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
			cacheUntil := horizon.Add(-s.config.withdrawalLead)
			if !cacheUntil.After(s.config.clock.Now()) {
				return fmt.Errorf("%w: snapshot completed too near its horizon", errSubscriptionExpired)
			}
			set := make(map[publicationIdentity]uint64, len(delegated))
			for _, identity := range delegated {
				set[identity] = 0
			}
			s.mu.Lock()
			if err := ctx.Err(); err != nil {
				s.mu.Unlock()
				return err
			}
			if proof != nil {
				if s.config.beforeRecoveryProof != nil {
					s.config.beforeRecoveryProof(true)
				}
				if err := s.mount.workspace.Recover(*proof); err != nil {
					s.mu.Unlock()
					return err
				}
			}
			if s.paused || s.workspaceOwned && proof == nil {
				s.mu.Unlock()
				return errSubscriptionPaused
			}
			if s.config.beforeWorkspaceInstall != nil {
				s.config.beforeWorkspaceInstall()
			}
			if s.mount != nil && s.mount.workspaceRTC != nil {
				if permission.Horizon != time.Duration(horizonNanos) || permission.Remaining(s.config.clock.Now(), s.mount.workspaceRTC, s.config.withdrawalLead) <= 0 {
					s.closeRTCIntervalLocked()
					s.mu.Unlock()
					return errSubscriptionExpired
				}
				// The sample may have straddled a new host generation. It cannot install
				// into that generation or clear its closure.
				if proof == nil || s.mount.workspace.Recover(*proof) != nil {
					s.mu.Unlock()
					return workspaceadmission.ErrClosed
				}
			}
			s.permission = permission
			s.rtcClosed = false
			s.workspaceDrain = nil
			s.workspaceReset = false
			s.workspaceProof = proof
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
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.controlLiveLocked()
	deadline := s.cacheUntil
	if s.workspaceDrain != nil {
		deadline = s.workspaceDrain.deadline
	}
	return s.incarnation, deadline, s.horizonChanged, live
}

func (s *subscriptionRegistry) waitActive(ctx context.Context) error {
	if s == nil {
		return errors.New("fusev3: subscription registry is required")
	}
	for {
		_, _, changed, active := s.currentIncarnation()
		if active {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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
		paused, pauseChanged := s.paused || s.workspaceOwned, s.pauseChanged
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
			progress := s.progress()
			if err := s.subscribe(ctx); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if errors.Is(err, errSubscriptionPaused) {
					continue
				}
				if err := s.waitProgress(ctx, progress); err != nil {
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
	incarnation, active := s.incarnation, s.active && !s.paused && !s.workspaceOwned
	if !active || incarnation == 0 {
		s.mu.Unlock()
		return errSubscriptionExpired
	}
	ctx, cancel := context.WithCancel(parent)
	renewalCtx, renewalCancel := context.WithCancel(ctx)
	renewalDone := make(chan struct{})
	s.controlCancel, s.renewCancel, s.renewDone = cancel, renewalCancel, renewalDone
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
	defer cancel()
	defer renewalCancel()
	failures := make(chan error, 4)
	changeQueue := newSubscriptionChangeQueue()
	changeQueue.controlContext = ctx
	pollCtx, pollCancel := context.WithCancel(ctx)
	defer pollCancel()
	pollDone := make(chan struct{})
	s.mu.Lock()
	s.pollCancel, s.pollDone, s.controlQueue = pollCancel, pollDone, changeQueue
	s.mu.Unlock()
	var workers sync.WaitGroup
	start := func(workerCtx context.Context, run func(context.Context) error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := run(workerCtx); err != nil {
				disposition := authorityrpc.LifecycleCompletion(workerCtx, err)
				reset := subscriptionResetAttempt(err)
				independent := disposition.Disposition == authorityrpc.LifecycleFailed && !reset
				s.mu.Lock()
				if independent {
					s.workspaceFailure = errors.Join(s.workspaceFailure, &authorityrpc.LifecycleIndependentFailure{Err: disposition.Err})
				}
				if reset {
					s.workspaceReset = true
				}
				s.mu.Unlock()
				if !independent && workerCtx.Err() != nil {
					return
				}
				select {
				case failures <- err:
				default:
				}
			}
		}()
	}
	start(pollCtx, func(ctx context.Context) error {
		defer close(pollDone)
		return s.pollLoop(ctx, incarnation, changeQueue)
	})
	start(ctx, func(ctx context.Context) error { return s.changeLoop(ctx, incarnation, changeQueue) })
	start(renewalCtx, func(ctx context.Context) error { defer close(renewalDone); return s.renewLoop(ctx, incarnation) })
	start(ctx, func(ctx context.Context) error { return s.horizonLoop(ctx, incarnation) })

	var result error
	select {
	case result = <-failures:
	case <-ctx.Done():
		result = ctx.Err()
	}
	cancel()
	changeQueue.close()
	workers.Wait()
	s.mu.RLock()
	owned := s.workspaceOwned
	s.mu.RUnlock()
	if owned {
		return result
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	if err := s.invalidateAll(parent); err != nil {
		return errors.Join(result, fmt.Errorf("fusev3: fence subscription incarnation %d: %w", incarnation, err))
	}
	return result
}

type subscriptionChangeQueue struct {
	controlContext context.Context
	accepted       uint64
	progress       chan struct{}
	mu             sync.Mutex
	wake           chan struct{}
	closed         bool
	head           int
	items          []subscriptionChangeWork
	completed      uint64
	finished       map[uint64]struct{}
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
	if q.progress != nil {
		close(q.progress)
		q.progress = nil
	}
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
		progress := s.progress()
		event, err := s.rpc.NextControlEvent(ctx, incarnation, after, changes.completedThrough())
		if err != nil {
			if errors.Is(err, authorityrpc.ErrSubscriptionReset) {
				return err
			}
			// Semantic, local and authority errors remain independent even
			// when the lifecycle cancels this poll before it returns.
			if !authorityrpc.TransientTransport(err) {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := s.waitProgress(ctx, progress); err != nil {
				return err
			}
			continue
		}
		if event == nil || event.GetIncarnation() != incarnation || event.GetSequence() != after+1 || event.GetEvent() == nil {
			return fmt.Errorf("%w: malformed CONTROL event after %d", errSubscriptionInvalid, after)
		}
		changes.mu.Lock()
		changes.accepted = event.GetSequence()
		changes.mu.Unlock()
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
			handlerContext := changes.controlContext
			if handlerContext == nil {
				handlerContext = ctx
			}
			done := s.control.HandleControlEvent(handlerContext, event)
			go func(sequence uint64) {
				select {
				case <-done:
					changes.complete(sequence)
				case <-handlerContext.Done():
				}
			}(event.GetSequence())
		}
		s.madeProgress()
		after = event.GetSequence()
	}
}

// A retry waits for actual CONTROL contact or an epoch pause/resume edge.
// Snapshot before the failed operation so concurrent progress cannot be lost.
type subscriptionProgress struct {
	contact, pause <-chan struct{}
}

func (s *subscriptionRegistry) progress() subscriptionProgress {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return subscriptionProgress{s.progressChanged, s.pauseChanged}
}

func (s *subscriptionRegistry) madeProgress() {
	s.mu.Lock()
	close(s.progressChanged)
	s.progressChanged = make(chan struct{})
	s.mu.Unlock()
}

func (s *subscriptionRegistry) waitProgress(ctx context.Context, progress subscriptionProgress) error {
	select {
	case <-progress.contact:
		return nil
	case <-progress.pause:
		return nil
	case <-ctx.Done():
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
			s.delegated[change.identity] = entry.GetPosition()
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
		if err := s.applyChangeBatch(ctx, incarnation, batch); err != nil {
			return err
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
	return s.applyChangeBatch(ctx, incarnation, &authoritypb.ChangeBatch{Incarnation: incarnation, Entries: []*authoritypb.ChangeEntry{entry}})
}

func (s *subscriptionRegistry) withdrawCoordinate(ctx context.Context, coordinate publicationCoordinate, byteRange *authoritypb.ByteRange) error {
	return s.withdrawCoordinates(ctx, []subscriptionWithdrawal{{coordinate: coordinate, byteRange: byteRange}})
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
	if s.workspaceDrain != nil {
		deadline = s.workspaceDrain.deadline
	}
	s.mu.RUnlock()
	// The horizon is the real bound. Renewal, polling and KeepAlive supply
	// readiness after a failed CONTROL call; a 10 ms timer supplies none.
	remaining := deadline.Sub(s.config.clock.Now())
	if remaining <= 0 {
		return errSubscriptionExpired
	}
	ackCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	for {
		if err := ackCtx.Err(); err != nil {
			return err
		}
		progress := s.progress()
		if err := s.rpc.AcknowledgeChanges(ackCtx, incarnation, position); err == nil {
			s.madeProgress()
			return nil
		} else if errors.Is(err, authorityrpc.ErrSubscriptionReset) {
			return err
		}
		if err := s.waitProgress(ackCtx, progress); err != nil {
			return fmt.Errorf("fusev3: acknowledge changes through %d: %w", position, err)
		}
	}
}

func (s *subscriptionRegistry) renewLoop(ctx context.Context, incarnation uint64) error {
	for {
		timer := s.config.clock.NewTimer(s.renewInterval())
		select {
		case <-timer.C():
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
		s.mu.Lock()
		live := s.incarnation == incarnation && s.renewalLiveLocked()
		s.mu.Unlock()
		if !live {
			continue
		}
		deadline, err := s.rpc.RenewSubscription(ctx, incarnation)
		if err != nil {
			if s.mount != nil && s.mount.workspaceRTC != nil && errors.Is(err, permissionclock.ErrUnavailable) {
				s.mu.Lock()
				if s.incarnation == incarnation {
					s.closeRTCIntervalLocked()
				}
				s.mu.Unlock()
				return errSubscriptionExpired
			}
			if errors.Is(err, authorityrpc.ErrSubscriptionReset) || !authorityrpc.TransientTransport(err) {
				return err
			}
			continue
		}
		s.madeProgress()
		if !s.acceptRenewal(incarnation, deadline) {
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

func (s *subscriptionRegistry) acceptRenewal(incarnation uint64, candidate permissionclock.Permission) bool {
	deadline := candidate.Time
	cacheUntil := deadline.Add(-s.config.withdrawalLead)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.incarnation != incarnation || s.paused || !s.renewalLiveLocked() {
		return false
	}
	now := s.config.clock.Now()
	// A late renewal cannot revive permission after the prior conservative
	// boundary. It is deliberately ignored rather than extending from receipt.
	if !now.Before(s.cacheUntil) || !cacheUntil.After(now) {
		return false
	}
	if s.mount != nil && s.mount.workspaceRTC != nil && candidate.Remaining(s.config.clock.Now(), s.mount.workspaceRTC, s.config.withdrawalLead) <= 0 {
		s.closeRTCIntervalLocked()
		return false
	}
	if s.mount != nil && s.mount.workspaceRTC != nil && (s.workspaceProof == nil ||
		s.mount.workspace.Recover(*s.workspaceProof) != nil && !s.mount.workspace.Installed(*s.workspaceProof)) {
		return false
	}
	if deadline.After(s.horizon) {
		s.permission = candidate
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
	return r.invalidateCacheCoordinatesContext(ctx, []subscriptionWithdrawal{{coordinate: coordinate, byteRange: byteRange}})
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
	for identity := range r.completeDirectories {
		coordinates[publicationCoordinate{kind: publicationItemEnumeration, item: identity}] = struct{}{}
	}
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
		// Unfinalized callbacks still construct their slices outside raw.mu.
		// Their pending cache coordinates are in cacheReservations above;
		// final preparation revalidates the inactive subscription before use.
		if publication == nil || !publication.originalFinalized {
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
	closed := make([]publicationCoordinate, 0, len(coordinates))
	for coordinate := range coordinates {
		closed = append(closed, coordinate)
	}
	inactive := false
	if r.mount != nil && r.mount.subscription != nil {
		r.mount.subscription.mu.RLock()
		inactive = !r.mount.subscription.active
		r.mount.subscription.mu.RUnlock()
	}
	lease, err := r.closeCacheCoordinates(ctx, closed)
	defer func() {
		// Production cold invalidation runs with subscription admission inactive.
		// A failed attempt retires only its own owner, preserving every local cut.
		if inactive {
			lease.Open()
		}
	}()
	if err != nil {
		return fmt.Errorf("fusev3: close cache coordinates for cold subscription: %w", err)
	}

	r.mu.Lock()
	clear(r.directoryPageHints)
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
	for identity := range r.completeDirectories {
		r.dropCompleteDirectoryLocked(identity)
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
	// Admission is already closed. Keep its withdrawal inventory until every
	// kernel notification succeeds: a failed attempt must not let a retry prove
	// a cold boundary by finding only the daemon caches it previously emptied.
	for key := range r.cachedNames {
		r.dropCachedNameLocked(key)
	}
	for key := range r.cachedNegatives {
		r.dropCachedNegativeLocked(key)
	}
	clear(r.cachedAttrs)
	clear(r.cachedAttrPayloads)
	for _, record := range r.nodesByID {
		if record != nil {
			// Epoch staleness belongs to the old server handle, not to the
			// subscription incarnation. A cold cache proof can clear an inode
			// invalidation failure, but it must never resurrect an old-epoch node.
			if record.node == nil || !record.node.epochStale.Load() {
				record.stale.Store(false)
			}
			if record.node != nil && !record.node.epochStale.Load() {
				record.node.stale.Store(false)
			}
		}
	}
	for coordinate := range r.withdrawingCoordinates {
		delete(r.withdrawingCoordinates, coordinate)
		delete(r.withdrawalOwners, coordinate)
	}
	reclaims := make([][]byte, 0)
	for _, record := range r.nodesByID {
		if token := r.collectLocked(record); len(token) != 0 {
			reclaims = append(reclaims, token)
		}
	}
	r.signalSourceChangedLocked()
	r.mu.Unlock()
	for _, token := range reclaims {
		r.mount.deferReclaim(token)
	}
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

// liveLocked denies admission at the moment of use even when active-time
// timers and CONTROL have not run since resume. Waking the horizon worker
// preserves the ordinary cold-withdrawal path; no renewal may bridge this cut.
// Denial is not withdrawal completion: serveDone joins the workers and their
// subsequent kernel invalidation attempt.
func (s *subscriptionRegistry) liveLocked() bool {
	if s.active && s.permissionRemainingLocked(s.config.withdrawalLead) <= 0 {
		s.closeRTCIntervalLocked()
	}
	return s.active
}

// Delegation reset owns its admission cut separately from cache withdrawal:
// retained metadata callbacks may still drain between deactivate and
// InterruptSubscription. That interval must nevertheless never cross expiry.
func (s *subscriptionRegistry) delegationHorizonLive(incarnation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if incarnation == 0 || incarnation != s.incarnation {
		return false
	}
	if s.workspaceDrain != nil {
		return s.workspaceDrain.incarnation == incarnation && s.drainLiveLocked()
	}
	if s.permissionRemainingLocked(s.config.withdrawalLead) <= 0 {
		s.closeRTCIntervalLocked()
		return false
	}
	return true
}

// Only managed subscriptions need the cold proof. Keep its large Installed
// check out of the ordinary horizon caller's stack frame.
//
//go:noinline
func (s *subscriptionRegistry) workspaceServingLocked() bool {
	return s.workspaceDrain == nil && s.workspaceProof != nil && s.mount.workspace.Installed(*s.workspaceProof)
}
func (s *subscriptionRegistry) controlLiveLocked() bool {
	if s.workspaceDrain != nil {
		return s.workspaceDrain.incarnation == s.incarnation && s.drainLiveLocked()
	}
	if !s.liveLocked() {
		return false
	}
	if s.mount == nil || s.mount.workspace == nil {
		return true
	}
	// Installation bound this proof to this reader and incarnation. Closing
	// serving never revokes the old CONTROL capability before its fixed
	// conservative horizon; takeover may only shorten it with workspaceDrain.
	return s.workspaceProof != nil
}

// A drain may finish the old CONTROL cut, but may not extend its exclusion.
func (s *subscriptionRegistry) renewalLiveLocked() bool {
	if s.workspaceOwned || s.workspaceDrain != nil || !s.controlLiveLocked() {
		return false
	}
	if s.mount == nil || s.mount.workspace == nil {
		return true
	}
	return s.workspaceProof != nil && (s.mount.workspace.Recover(*s.workspaceProof) == nil || s.mount.workspace.Installed(*s.workspaceProof))
}

// Ordinary clients retain the protocol's three-second cadence. The workspace
// has an earlier RTC cutoff under the full endpoint uncertainty envelope.
func (s *subscriptionRegistry) renewInterval() time.Duration {
	if s.mount != nil && s.mount.workspaceRTC != nil {
		return time.Second
	}
	return volumeserver.SubscriptionRenewInterval
}

func (s *subscriptionRegistry) permissionRemainingLocked(lead time.Duration) time.Duration {
	if s.mount == nil || s.mount.workspaceRTC == nil {
		return max(time.Duration(0), s.cacheUntil.Sub(s.config.clock.Now()))
	}
	if s.rtcClosed {
		return 0
	}
	remaining := s.permission.Remaining(s.config.clock.Now(), s.mount.workspaceRTC, lead)
	if s.config.afterWorkspaceSample != nil {
		s.config.afterWorkspaceSample()
	}
	if remaining <= 0 {
		s.closeRTCIntervalLocked()
	}
	return remaining
}

// The caller owns only the local use lock. Closure never joins workers or
// reenters lifecycle/manager locks. A late successful sample cannot clear it.
func (s *subscriptionRegistry) closeRTCIntervalLocked() {
	if s.mount != nil && s.mount.workspaceRTC != nil {
		s.rtcClosed = true
	}
	if s.active {
		s.active = false
		s.generation++
		s.signalHorizonChangedLocked()
	}
}

func (s *subscriptionRegistry) drainLiveLocked() bool {
	return s.workspaceDrain != nil && s.config.clock.Now().Before(s.workspaceDrain.deadline) && s.permissionRemainingLocked(s.config.withdrawalLead) > 0
}

func (s *subscriptionRegistry) workspaceRemaining() time.Duration {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.liveLocked() {
		return 0
	}
	return s.permissionRemainingLocked(s.config.withdrawalLead)
}

func (s *subscriptionRegistry) rtcIntervalClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rtcClosed
}
