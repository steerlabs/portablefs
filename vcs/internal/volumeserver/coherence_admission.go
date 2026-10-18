package volumeserver

import (
	"fmt"
	"math"
	"time"
)

func (c *CoherenceCoordinator) DelegatedIdentities() [][16]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([][16]byte, 0, len(c.delegations))
	for identity := range c.delegations {
		result = append(result, identity)
	}
	return result
}

// WriterRestartGrace is frozen alongside MaxCacheProof. The extra
// second and 1,000 ppm term cover the supported cross-host clock assumptions.
const WriterRestartGrace = MaxCacheProof + time.Second + (MaxCacheProof+999)/1000

// StartWriterGrace must be called only after safe takeover: root
// and membership ownership are exclusive, predecessor renewal is irrevocably
// closed, and predecessor storage work has drained. Shipping shutdown joins
// transport workers and restore background work before releasing those locks.
// A root lock alone is not proof of an arbitrary embedding's quiescence.
func (c *WriterRegistry) StartWriterGrace() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writerRestartStarted {
		return fmt.Errorf("volumeserver: writer takeover already sampled")
	}
	c.writerRestartStarted = true
	now, err := c.now()
	if err != nil || now < 0 || now > time.Duration(math.MaxInt64)-WriterRestartGrace {
		c.writerRestartFailed = true
		return fmt.Errorf("volumeserver: unusable continuous takeover clock (sample %v): %v", now, err)
	}
	c.writerRestartLast = now
	c.writerRestartDeadline = now + WriterRestartGrace
	return nil
}

func (c *WriterRegistry) priorWriterBlockedLocked() bool {
	if c.startupReady {
		return false
	}
	if !c.writerRestartStarted || c.writerRestartFailed {
		return true
	}
	now, err := c.now()
	if err != nil || now < c.writerRestartLast {
		c.writerRestartFailed = true
		return true
	}
	c.writerRestartLast = now
	return now < c.writerRestartDeadline
}
