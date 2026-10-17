package volumeserver

import (
	"errors"
	"math"
	"sync"
	"time"
)

// MaxCacheProof is frozen by fskit-versioned-metadata-v1, independent of the
// configured renewable session lease.
const MaxCacheProof = 60 * time.Second

// CompatibilityExclusion follows one session, independently of its repair
// participation. Fence closes grants before removing the participant; the last
// session pin supplies the proof that old storage applies have drained.
type CompatibilityExclusion struct {
	mu          sync.Mutex
	now         func() (time.Duration, error)
	deadline    time.Duration
	last        time.Duration
	clockFailed bool
	stopped     bool
	drained     bool
	absent      bool
}

func (e *CompatibilityExclusion) grant(remaining time.Duration) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return ErrSessionFenced
	}
	now, err := e.now()
	if e.clockFailed || err != nil || now < e.last || now < 0 || remaining < 0 || remaining > time.Duration(math.MaxInt64)-now {
		e.clockFailed = true
		return errors.New("volumeserver: invalid continuous exclusion clock")
	}
	e.last = now
	e.deadline = max(e.deadline, now+remaining)
	return nil
}

func (e *CompatibilityExclusion) closed() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopped || e.clockFailed
}

func (e *CompatibilityExclusion) stop(absent bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.stopped = true
	e.absent = e.absent || absent
	e.mu.Unlock()
}

func (e *CompatibilityExclusion) drain() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.drained = true
	e.mu.Unlock()
}

func (e *CompatibilityExclusion) outstanding() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.stopped || !e.drained {
		return true
	}
	if e.absent {
		return false
	}
	now, err := e.now()
	if err != nil || now < e.last {
		e.clockFailed = true
	}
	e.last = now
	return e.clockFailed || now < e.deadline
}

// CompatibilityExclusion binds the existing session's proof grants and drain to
// the coordinator before activation commits. It allocates no durable state.
func (a *Authority) CompatibilityExclusion(id SessionID) (*CompatibilityExclusion, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[id]
	if s == nil {
		return nil, ErrSessionExpired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fenced || s.ending {
		return nil, ErrSessionFenced
	}
	if s.exclusion == nil {
		s.exclusion = &CompatibilityExclusion{now: a.cfg.ContinuousNow}
	}
	return s.exclusion, nil
}

func (a *Authority) leaseRemainingLocked(s *session) time.Duration {
	now := a.cfg.Now()
	return max(0, min(s.leaseExpires.Sub(now), s.authorizationDeadline.Sub(now), a.cfg.SessionLease))
}

// RenewalProof samples after renewal under session admission. Only KeepAlive
// publishes it; ordinary lease renewal grants no cache permission.
func (u *SessionUse) RenewalProof() (time.Duration, error) {
	s := u.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fenced || s.ending || s.state != SessionStateActive || s.exclusion == nil {
		return 0, ErrSessionFenced
	}
	remaining := min(u.authority.leaseRemainingLocked(s), u.authority.cfg.SessionLease/time.Millisecond*time.Millisecond, MaxCacheProof)
	remaining = remaining / time.Millisecond * time.Millisecond
	if remaining <= 0 {
		return 0, ErrSessionExpired
	}
	if err := s.exclusion.grant(remaining); err != nil {
		return 0, err
	}
	return remaining, nil
}
