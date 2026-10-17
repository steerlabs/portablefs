package volumeserver

import (
	"fmt"
	"math"
	"time"
)

// CheckCompatibilityWriter refuses a writer while another FSKit mount owns
// the compatibility exclusion. The handler holds its activation admission
// guard across this check and the operation which can establish write intent.
func (c *VisibilityCoordinator) CheckCompatibilityWriter(source SessionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.priorCompatibilityWriterBlockedLocked() || c.compatibilityExcludedLocked(source) {
		return ErrCompatibilityWriterLease
	}
	for id, p := range c.participants {
		if id != source && p.compatibilityWriter {
			return ErrCompatibilityWriterLease
		}
	}
	return nil
}

// DelegatedIdentities is a point snapshot used when a Mac compatibility mount
// takes exclusive writer admission. It includes reservations: those must also
// retire before an unrevocable Mac cache can become active.
func (c *CoherenceCoordinator) DelegatedIdentities() [][16]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([][16]byte, 0, len(c.delegations))
	for identity := range c.delegations {
		result = append(result, identity)
	}
	return result
}

func (c *VisibilityCoordinator) retainExclusionLocked(p *visibilityParticipant, absent bool) {
	if !p.compatibilityWriter || p.exclusion == nil {
		return
	}
	p.exclusion.stop(absent)
	c.exclusions[p.id] = p.exclusion
}

func (c *VisibilityCoordinator) compatibilityExcludedLocked(source SessionID) bool {
	for id, exclusion := range c.exclusions {
		if !exclusion.outstanding() {
			delete(c.exclusions, id)
		} else if id != source {
			return true
		}
	}
	return false
}

// SweepCompatibilityExclusions reuses the session sweep, so retired proofs do
// not accumulate when there is no foreign writer to trigger admission cleanup.
func (c *VisibilityCoordinator) SweepCompatibilityExclusions() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, exclusion := range c.exclusions {
		if !exclusion.outstanding() {
			delete(c.exclusions, id)
		}
	}
}

// CompatibilityRestartGrace is frozen alongside MaxCacheProof. The extra
// second and 1,000 ppm term cover the supported cross-host clock assumptions.
const CompatibilityRestartGrace = MaxCacheProof + time.Second + (MaxCacheProof+999)/1000

// StartCompatibilityWriterGrace must be called only after safe takeover: root
// and membership ownership are exclusive, predecessor renewal is irrevocably
// closed, and predecessor storage work has drained. Shipping shutdown joins
// transport workers and restore background work before releasing those locks.
// A root lock alone is not proof of an arbitrary embedding's quiescence.
func (c *VisibilityCoordinator) StartCompatibilityWriterGrace() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writerRestartStarted {
		return fmt.Errorf("volumeserver: compatibility takeover already sampled")
	}
	c.writerRestartStarted = true
	now, err := c.cfg.ContinuousNow()
	if err != nil || now < 0 || now > time.Duration(math.MaxInt64)-CompatibilityRestartGrace {
		c.writerRestartFailed = true
		return fmt.Errorf("volumeserver: unusable continuous takeover clock (sample %v): %v", now, err)
	}
	c.writerRestartLast = now
	c.writerRestartDeadline = now + CompatibilityRestartGrace
	return nil
}

func (c *VisibilityCoordinator) priorCompatibilityWriterBlockedLocked() bool {
	if c.startupReady {
		return false
	}
	if !c.writerRestartStarted || c.writerRestartFailed {
		return true
	}
	now, err := c.cfg.ContinuousNow()
	if err != nil || now < c.writerRestartLast {
		c.writerRestartFailed = true
		return true
	}
	c.writerRestartLast = now
	return now < c.writerRestartDeadline
}
