package volumeserver

import (
	"errors"
	"sync"
	"time"
)

// WriterRegistry owns exclusive Mac apply admission and retained proof/drain
// obligations. MountLifecycle alone owns durable membership. Linux activation
// uses the handler's profile gate; ordinary Mac work never takes that gate.
type WriterRegistry struct {
	mu                    sync.Mutex
	fencer                SessionFencer
	now                   func() (time.Duration, error)
	startupReady          bool
	owner                 SessionID
	exclusion             *WriterExclusion
	left                  chan struct{}
	exclusions            map[SessionID]*WriterExclusion
	poisoned              error
	writerRestartDeadline time.Duration
	writerRestartLast     time.Duration
	writerRestartStarted  bool
	writerRestartFailed   bool
}

type WriterRegistryConfig struct {
	Fencer        SessionFencer
	Prior         PriorEpochDisposition
	ContinuousNow func() (time.Duration, error)
}

func NewWriterRegistry(cfg WriterRegistryConfig) (*WriterRegistry, error) {
	if cfg.ContinuousNow == nil {
		cfg.ContinuousNow = continuousNow
	}
	return &WriterRegistry{fencer: cfg.Fencer, now: cfg.ContinuousNow, startupReady: cfg.Prior == PriorEpochStrictMountsFenced, exclusions: make(map[SessionID]*WriterExclusion)}, nil
}

func (c *WriterRegistry) checkLocked(source SessionID, requireOwner bool) error {
	if c.poisoned != nil {
		return c.poisoned
	}
	if c.priorWriterBlockedLocked() || c.excludedLocked(source) {
		return ErrWriterExcluded
	}
	if requireOwner {
		if c.owner != source || c.exclusion == nil || c.exclusion.closed() {
			return ErrSessionFenced
		}
	} else if c.owner != (SessionID{}) && (c.owner != source || c.exclusion.closed()) {
		return ErrWriterExcluded
	}
	return nil
}

// CheckWriter admits foreign writers only after all old proof time AND apply
// drain have ended. CheckOwner additionally proves the exact live Mac writer.
// The caller retains its runtime pin from this cut through apply,
// commit, withdrawal, durability and replay settlement.
func (c *WriterRegistry) CheckWriter(source SessionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkLocked(source, false)
}
func (c *WriterRegistry) CheckOwner(source SessionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkLocked(source, true)
}

// Activate runs inside durable membership publication and exclusive profile
// admission. Preparing the exact reply can fail; runtime commit cannot. The
// owner mutex serializes publication with fence. Runtime commit runs outside
// it because deferred session teardown can synchronously re-enter the registry.
func (c *WriterRegistry) Activate(id SessionID, terminal <-chan struct{}, exclusion *WriterExclusion, prepare func() error, commit func()) error {
	if id == (SessionID{}) || terminal == nil || exclusion == nil || prepare == nil || commit == nil {
		return ErrMountProfile
	}
	c.mu.Lock()
	if !c.startupReady {
		c.mu.Unlock()
		return ErrWriterExcluded
	}
	if err := c.checkLocked(id, false); err != nil {
		c.mu.Unlock()
		return err
	}
	if c.owner != (SessionID{}) {
		c.mu.Unlock()
		return ErrWriterExcluded
	}
	select {
	case <-terminal:
		c.mu.Unlock()
		return ErrSessionFenced
	default:
	}
	if exclusion.closed() {
		c.mu.Unlock()
		return ErrSessionFenced
	}
	if err := prepare(); err != nil {
		c.mu.Unlock()
		return err
	}
	c.owner, c.exclusion, c.left = id, exclusion, make(chan struct{})
	left := c.left
	c.mu.Unlock()
	commit()
	go func() {
		select {
		case <-terminal:
			c.Fence(id)
		case <-left:
		}
	}()
	return nil
}

// Fence closes grants before dropping ownership. Session teardown closes
// admission independently and marks the same exclusion drained after its last
// pin retires. No process-local event removes durable mount membership.
func (c *WriterRegistry) Fence(id SessionID) {
	c.mu.Lock()
	c.retireLocked(id, false)
	c.mu.Unlock()
	if c.fencer != nil {
		c.fencer.FenceSession(id)
	}
}

// Remove is called only within MountLifecycle's validated clean-detach
// transaction. Exact absence discharges promised time, never admitted work.
func (c *WriterRegistry) Remove(id SessionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retireLocked(id, true)
	if e := c.exclusions[id]; e != nil {
		e.stop(true)
	}
	return nil
}

func (c *WriterRegistry) retireLocked(id SessionID, absent bool) {
	if c.owner != id || c.exclusion == nil {
		return
	}
	c.exclusion.stop(absent)
	c.exclusions[id] = c.exclusion
	c.owner, c.exclusion = SessionID{}, nil
	close(c.left)
	c.left = nil
}
func (c *WriterRegistry) excludedLocked(source SessionID) bool {
	blocked := false
	for id, e := range c.exclusions {
		if !e.outstanding() {
			delete(c.exclusions, id)
		} else if id != source {
			blocked = true
		}
	}
	return blocked
}
func (c *WriterRegistry) SweepExclusions() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.excludedLocked(SessionID{})
}
func (c *WriterRegistry) Poison(cause error) error {
	c.mu.Lock()
	if c.poisoned == nil {
		c.poisoned = errors.Join(ErrMutationPoisoned, cause)
	}
	owner := c.owner
	if owner != (SessionID{}) {
		c.retireLocked(owner, false)
	}
	err := c.poisoned
	c.mu.Unlock()
	if owner != (SessionID{}) && c.fencer != nil {
		c.fencer.FenceSession(owner)
	}
	return err
}
