//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"sync"
)

// writerPriorityGate serves independent profile and blocking-lock admission
// gates. Pending exclusive admission has priority over new shared admission,
// so continuous Linux writes cannot indefinitely postpone Mac activation.
// The mutex covers only counters and notifications; counted permits span the
// caller's work. Never use this policy for topology: an admitted reader can
// depend on a new reader to flush a recalled delegation.
type writerPriorityGate struct {
	mu             sync.Mutex
	changed        chan struct{}
	readers        uint64
	writersWaiting uint64
	writer         bool
}

func (g *writerPriorityGate) notificationLocked() <-chan struct{} {
	if g.changed == nil {
		g.changed = make(chan struct{})
	}
	return g.changed
}

func (g *writerPriorityGate) signalLocked() {
	if g.changed != nil {
		close(g.changed)
		g.changed = nil
	}
}

func (g *writerPriorityGate) RLockContext(ctx context.Context) error {
	for {
		g.mu.Lock()
		if err := ctx.Err(); err != nil {
			g.mu.Unlock()
			return err
		}
		if !g.writer && g.writersWaiting == 0 {
			if g.readers == ^uint64(0) {
				g.mu.Unlock()
				return errors.New("authorityrpc: shared admission count exhausted")
			}
			g.readers++
			g.mu.Unlock()
			return nil
		}
		changed := g.notificationLocked()
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (g *writerPriorityGate) RLock() { _ = g.RLockContext(context.Background()) }

func (g *writerPriorityGate) RUnlock() {
	g.mu.Lock()
	if g.readers == 0 {
		g.mu.Unlock()
		panic("authorityrpc: shared admission underflow")
	}
	g.readers--
	if g.readers == 0 {
		g.signalLocked()
	}
	g.mu.Unlock()
}

func (g *writerPriorityGate) LockContext(ctx context.Context) error {
	g.mu.Lock()
	if err := ctx.Err(); err != nil {
		g.mu.Unlock()
		return err
	}
	if g.writersWaiting == ^uint64(0) {
		g.mu.Unlock()
		return errors.New("authorityrpc: pending admission count exhausted")
	}
	g.writersWaiting++
	for {
		if err := ctx.Err(); err != nil {
			g.writersWaiting--
			g.signalLocked()
			g.mu.Unlock()
			return err
		}
		if !g.writer && g.readers == 0 {
			g.writersWaiting--
			g.writer = true
			g.mu.Unlock()
			return nil
		}
		changed := g.notificationLocked()
		g.mu.Unlock()
		select {
		case <-changed:
			g.mu.Lock()
		case <-ctx.Done():
			g.mu.Lock()
			g.writersWaiting--
			g.signalLocked()
			g.mu.Unlock()
			return ctx.Err()
		}
	}
}

func (g *writerPriorityGate) Lock() { _ = g.LockContext(context.Background()) }

func (g *writerPriorityGate) Unlock() {
	g.mu.Lock()
	if !g.writer {
		g.mu.Unlock()
		panic("authorityrpc: exclusive admission not held")
	}
	g.writer = false
	g.signalLocked()
	g.mu.Unlock()
}
