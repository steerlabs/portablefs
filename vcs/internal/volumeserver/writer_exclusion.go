package volumeserver

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// MaxCacheProof is the protocol-8 metadata-proof ceiling, independent of the
// configured renewable session lease.
const MaxCacheProof = 60 * time.Second

// WriterExclusion follows one session. Fence closes grants before removing
// writer ownership; the last
// session pin supplies the proof that old storage applies have drained.
type WriterExclusion struct {
	mu          sync.Mutex
	now         func() (time.Duration, error)
	deadline    time.Duration
	last        time.Duration
	clockFailed bool
	stopped     bool
	drained     bool
	absent      bool
}

func (e *WriterExclusion) grant(remaining time.Duration) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return ErrSessionFenced
	}
	now, err := e.now()
	if e.clockFailed || err != nil || now < e.last || now < 0 || now > time.Duration(math.MaxInt64)-MaxCacheProof || remaining < 0 || remaining > time.Duration(math.MaxInt64)-now {
		e.clockFailed = true
		return errors.New("volumeserver: invalid continuous exclusion clock")
	}
	e.last = now
	e.deadline = max(e.deadline, now+remaining)
	return nil
}

func (e *WriterExclusion) closed() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopped || e.clockFailed
}

func (e *WriterExclusion) stop(absent bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.stopped = true
	e.absent = e.absent || absent
	e.mu.Unlock()
}

func (e *WriterExclusion) drain() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.drained = true
	e.mu.Unlock()
}

func (e *WriterExclusion) outstanding() bool {
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

// WriterExclusion binds the existing session's proof grants and drain to
// the coordinator before activation commits. It allocates no durable state.
func (a *Authority) WriterExclusion(id SessionID) (*WriterExclusion, error) {
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
	// Apply drain is retained even before this session has granted any cache
	// proof. An ordinary lease renewal alone never grants a time promise.
	if s.exclusion == nil {
		s.exclusion = &WriterExclusion{now: a.cfg.ContinuousNow}
	}
	return s.exclusion, nil
}

func (a *Authority) leaseRemainingLocked(s *session) (time.Duration, error) {
	now := a.cfg.Now()
	elapsed, err := a.cfg.ContinuousNow()
	if err != nil {
		return 0, fmt.Errorf("sample continuous lease clock: %w", err)
	}
	return max(0, min(s.leaseExpires.Sub(time.Unix(0, int64(elapsed))), s.authorizationDeadline.Sub(now), a.cfg.SessionLease)), nil
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
	remaining, err := u.authority.leaseRemainingLocked(s)
	if err != nil {
		s.exclusion.mu.Lock()
		s.exclusion.clockFailed = true
		s.exclusion.mu.Unlock()
		return 0, err
	}
	remaining = min(remaining, u.authority.cfg.SessionLease/time.Millisecond*time.Millisecond, MaxCacheProof)
	remaining = remaining / time.Millisecond * time.Millisecond
	if err := s.exclusion.grant(remaining); err != nil {
		return 0, err
	}
	if remaining <= 0 {
		return 0, ErrSessionExpired
	}
	return remaining, nil
}
