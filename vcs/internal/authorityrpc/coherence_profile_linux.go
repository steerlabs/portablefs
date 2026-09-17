//go:build linux

package authorityrpc

import (
	"context"
	"sync"
)

// coherenceProfileGate lets ordinary Linux writer admission overlap while a
// macOS compatibility-writer activation remains exclusive. The mutex protects
// only the counters and wake channel; callers hold a counted permit,
// rather than this mutex, across storage and coordinator waits.
//
// Pending exclusive admission has priority over new shared admission. That
// bounds activation even when Linux write traffic is continuous.
type coherenceProfileGate struct {
	mu             sync.Mutex
	changed        chan struct{}
	readers        uint64
	writersWaiting uint64
	writer         bool
}

func (g *coherenceProfileGate) notificationLocked() <-chan struct{} {
	if g.changed == nil {
		g.changed = make(chan struct{})
	}
	return g.changed
}

func (g *coherenceProfileGate) signalLocked() {
	if g.changed != nil {
		close(g.changed)
		g.changed = nil
	}
}

func (g *coherenceProfileGate) RLockContext(ctx context.Context) error {
	for {
		g.mu.Lock()
		if !g.writer && g.writersWaiting == 0 {
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

func (g *coherenceProfileGate) RLock() { _ = g.RLockContext(context.Background()) }

func (g *coherenceProfileGate) RUnlock() {
	g.mu.Lock()
	if g.readers == 0 {
		g.mu.Unlock()
		panic("authorityrpc: coherence profile shared admission underflow")
	}
	g.readers--
	if g.readers == 0 {
		g.signalLocked()
	}
	g.mu.Unlock()
}

func (g *coherenceProfileGate) LockContext(ctx context.Context) error {
	g.mu.Lock()
	g.writersWaiting++
	for {
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

func (g *coherenceProfileGate) Lock() { _ = g.LockContext(context.Background()) }

func (g *coherenceProfileGate) Unlock() {
	g.mu.Lock()
	if !g.writer {
		g.mu.Unlock()
		panic("authorityrpc: coherence profile exclusive admission not held")
	}
	g.writer = false
	g.signalLocked()
	g.mu.Unlock()
}
