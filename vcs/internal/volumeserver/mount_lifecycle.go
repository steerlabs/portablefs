package volumeserver

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrMountHolder = errors.New("volumeserver: mount holder is not active")
	ErrRoutesLive  = errors.New("volumeserver: route change requires clean mount absence")
)

// MountLifecycle owns durable mount membership and topology exclusion.
// Cache authority belongs to the independent v7 and Mac coordinators.
type MountLifecycle struct {
	membership DurableVisibilityMembership
	now        func() time.Time
	clockSkew  time.Duration

	topology sync.RWMutex
	mu       sync.Mutex
	active   map[SessionID]time.Time
	profiles map[SessionID]MountMembershipProfile
	// priorUnproven cannot be cleared by process-local events. Only reopening the
	// durable membership with the operator's fencing assertion can clear it.
	priorUnproven bool
}

type MountLifecycleConfig struct {
	Membership DurableVisibilityMembership
	Prior      PriorEpochDisposition
	Now        func() time.Time
	ClockSkew  time.Duration
}

func NewMountLifecycle(cfg MountLifecycleConfig) (*MountLifecycle, error) {
	if cfg.Membership == nil || cfg.ClockSkew < 0 {
		return nil, errors.New("volumeserver: mount lifecycle needs durable membership and nonnegative clock skew")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &MountLifecycle{
		membership: cfg.Membership, now: cfg.Now, clockSkew: cfg.ClockSkew,
		active: make(map[SessionID]time.Time), profiles: make(map[SessionID]MountMembershipProfile), priorUnproven: cfg.Prior != PriorEpochStrictMountsFenced,
	}, nil
}

// AcquireTopologyRead pins one attach or filesystem request to the active LOCAL
// route revision until it can no longer reach storage.
func (l *MountLifecycle) AcquireTopologyRead() *TopologyReadGuard {
	l.topology.RLock()
	return &TopologyReadGuard{release: l.topology.RUnlock}
}

// ExecuteTopologyExclusive serializes the route CAS and durable publication
// against every admitted attach and filesystem request. Cache or membership
// readiness is checked separately only after the CAS proves a real change.
func (l *MountLifecycle) ExecuteTopologyExclusive(ctx context.Context, execute func() (int, error)) (int, error) {
	if ctx == nil || execute == nil {
		return 0, errors.New("volumeserver: topology transition needs a context and executor")
	}
	l.topology.Lock()
	defer l.topology.Unlock()
	return execute()
}

// RequireCleanRouteAbsence is called under topology exclusion after a route CAS
// proves the revision would change. Process memory is insufficient after a
// restart, so both prior durable uncertainty and every current activation keep
// the route immutable.
func (l *MountLifecycle) RequireCleanRouteAbsence() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.priorUnproven || len(l.active) != 0 {
		return ErrRoutesLive
	}
	return nil
}

// Activate records durable membership before the supplied infallible runtime
// publication can escape. The caller already holds a topology read guard so a
// route change cannot fit between revision admission and this registration.
func (l *MountLifecycle) Activate(id SessionID, publish func() error) error {
	return l.ActivateProfile(id, MembershipCompatibility, publish)
}

func activateMembership(m DurableVisibilityMembership, id SessionID, profile MountMembershipProfile) error {
	if typed, ok := m.(interface {
		ActivateProfile(SessionID, MountMembershipProfile) error
	}); ok {
		return typed.ActivateProfile(id, profile)
	}
	return m.Activate(id)
}

func (l *MountLifecycle) ActivateProfile(id SessionID, profile MountMembershipProfile, publish func() error) error {
	if id == (SessionID{}) || publish == nil {
		return ErrMountHolder
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.active[id]; exists {
		return ErrMountHolder
	}
	if err := activateMembership(l.membership, id, profile); err != nil {
		return err
	}
	if err := publish(); err != nil {
		rollbackErr := l.membership.Deactivate(id)
		if rollbackErr != nil {
			// Durable state may still name this mount even though runtime
			// publication failed. Preserve a process-local route obligation until
			// restart/operator reconciliation proves it absent.
			l.priorUnproven = true
		}
		return errors.Join(err, rollbackErr)
	}
	l.active[id] = l.now()
	l.profiles[id] = profile
	return nil
}

// CleanDetach accepts only an authenticated, complete observation belonging to
// this activation. Durable removal happens before process-local removal; if the
// latter fails, membership is restored so a restart remains fail-closed.
func (l *MountLifecycle) CleanDetach(id SessionID, proof MountAbsenceProof, remove func() error) error {
	if remove == nil {
		return ErrVisibilityProof
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	registered, exists := l.active[id]
	if !exists {
		return ErrSessionExpired
	}
	if err := l.validateMountAbsence(proof, registered); err != nil {
		return err
	}
	if err := l.membership.Deactivate(id); err != nil {
		return err
	}
	if err := remove(); err != nil {
		rollbackErr := activateMembership(l.membership, id, l.profiles[id])
		if rollbackErr != nil {
			l.priorUnproven = true
		}
		return errors.Join(err, rollbackErr)
	}
	delete(l.active, id)
	delete(l.profiles, id)
	return nil
}

func (l *MountLifecycle) validateMountAbsence(proof MountAbsenceProof, registered time.Time) error {
	if len(proof.Observation) == 0 || len(proof.Observation) > maxMountAbsenceObservation ||
		proof.Component == "" || len(proof.Component) > maxMountAbsenceComponent || proof.ObservedUnixNanos <= 0 {
		return ErrVisibilityProof
	}
	observed := time.Unix(0, proof.ObservedUnixNanos)
	now := l.now()
	if observed.After(now.Add(l.clockSkew)) || observed.Before(registered.Add(-l.clockSkew)) {
		return ErrVisibilityProof
	}
	return nil
}

// TopologyReadGuard pins the routing revision a filesystem request or attach
// was admitted against. ApplyRoutes takes the corresponding write side before
// it rechecks compare-and-swap and keeps it through durable commit, so a request
// can never pass admission under one topology and reach XFS under another.
//
// The guard is intentionally opaque and pointer-only. Release is idempotent so
// a deferred release remains safe on every handler exit.
type TopologyReadGuard struct {
	release func()
	once    sync.Once
}

// Release ends one route-revision admission critical section.
func (g *TopologyReadGuard) Release() {
	if g == nil || g.release == nil {
		return
	}
	g.once.Do(g.release)
}
