package volumeserver

import (
	"context"
	"errors"
	"sync"
)

// topologyGate admits dependent readers even when a writer is waiting: a
// reader can wait for a delegation flush that itself needs read admission.
// Exclusion begins only by observing zero readers and no writer atomically
// with read admission. Continuous overlapping readers can starve a topology
// writer until its context expires; bounded admin latency is not promised.
// The mutex covers only admission state, never callbacks, storage or waits.
type topologyGate struct {
	mu      sync.Mutex
	readers uint64
	writer  bool
	changed chan struct{}
}

func (g *topologyGate) acquire(ctx context.Context, exclusive bool) error {
	for {
		g.mu.Lock()
		if err := ctx.Err(); err != nil {
			g.mu.Unlock()
			return err
		}
		if !g.writer && (!exclusive || g.readers == 0) {
			if exclusive {
				g.writer = true
			} else {
				if g.readers == ^uint64(0) {
					g.mu.Unlock()
					return errors.New("volumeserver: topology reader count exhausted")
				}
				g.readers++
			}
			g.mu.Unlock()
			return nil
		}
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (g *topologyGate) release(exclusive bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if exclusive {
		if !g.writer {
			panic("volumeserver: topology exclusion not held")
		}
		g.writer = false
	} else {
		if g.readers == 0 {
			panic("volumeserver: topology reader underflow")
		}
		g.readers--
	}
	if !g.writer && g.readers == 0 && g.changed != nil {
		close(g.changed)
		g.changed = nil
	}
}
