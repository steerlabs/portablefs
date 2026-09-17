//go:build linux

package fusev3

import (
	"context"
	"sync"
	"sync/atomic"
)

// Closed KEEP_CACHE descriptions can leave folios resident. The retained bit
// lasts as long as the inode, while readers counts descriptions including any
// in-flight READ whose RELEASE is waiting to finish.
type ownReadCache struct {
	retained atomic.Bool
	mu       sync.Mutex
	drain    sync.Mutex
	readers  uint64
	pending  bool
	start    int64
	end      int64
}

func (c *ownReadCache) addReader() {
	c.mu.Lock()
	c.readers++
	c.retained.Store(true)
	c.mu.Unlock()
}

func (c *ownReadCache) removeReader() {
	c.mu.Lock()
	if c.readers == 0 {
		c.mu.Unlock()
		panic("fusev3: cached reader count underflow")
	}
	c.readers--
	c.mu.Unlock()
}

func (c *ownReadCache) mergeLocked(start, end int64) {
	if !c.pending {
		c.start, c.end, c.pending = start, end, true
	} else {
		c.start, c.end = min(c.start, start), max(c.end, end)
	}
}

func (record *inodeRecord) acceptOwnWrite(ctx context.Context, offset, length int64) error {
	c := &record.readCache
	if length == 0 || !c.retained.Load() {
		return nil
	}
	c.mu.Lock()
	c.mergeLocked(offset, offset+length)
	readers := c.readers
	c.mu.Unlock()
	if readers == 0 {
		return nil
	}
	// A resident folio bypasses the daemon. Deferring this until a background
	// tick would let a read issued after successful WRITE return old bytes.
	return record.drainOwnWrites(ctx)
}

func (record *inodeRecord) drainOwnWrites(ctx context.Context) error {
	c := &record.readCache
	if !c.retained.Load() {
		return nil
	}
	c.drain.Lock()
	defer c.drain.Unlock()
	for {
		c.mu.Lock()
		if !c.pending {
			c.mu.Unlock()
			return nil
		}
		start, end := c.start, c.end
		c.pending = false
		c.mu.Unlock()
		if err := record.node.invalidateOwnData(ctx, start, end-start); err != nil {
			c.mu.Lock()
			c.mergeLocked(start, end)
			c.mu.Unlock()
			return err
		}
		// Include a write accepted while notify was in flight. Neither the
		// next cached OPEN nor a waiting live-reader WRITE may outrun it.
	}
}
