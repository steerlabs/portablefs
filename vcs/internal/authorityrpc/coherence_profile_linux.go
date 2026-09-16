//go:build linux

package authorityrpc

import "sync"

// coherenceProfileGate lets ordinary Linux writer admission overlap while a
// macOS compatibility-writer activation remains exclusive. The mutex protects
// only the counters and condition variable; callers hold a counted permit,
// rather than this mutex, across storage and coordinator waits.
//
// Pending exclusive admission has priority over new shared admission. That
// bounds activation even when Linux write traffic is continuous.
type coherenceProfileGate struct {
	mu             sync.Mutex
	changed        *sync.Cond
	readers        uint64
	writersWaiting uint64
	writer         bool
}

func (g *coherenceProfileGate) conditionLocked() *sync.Cond {
	if g.changed == nil {
		g.changed = sync.NewCond(&g.mu)
	}
	return g.changed
}

func (g *coherenceProfileGate) RLock() {
	g.mu.Lock()
	changed := g.conditionLocked()
	for g.writer || g.writersWaiting != 0 {
		changed.Wait()
	}
	g.readers++
	g.mu.Unlock()
}

func (g *coherenceProfileGate) RUnlock() {
	g.mu.Lock()
	if g.readers == 0 {
		g.mu.Unlock()
		panic("authorityrpc: coherence profile shared admission underflow")
	}
	g.readers--
	if g.readers == 0 {
		g.conditionLocked().Broadcast()
	}
	g.mu.Unlock()
}

func (g *coherenceProfileGate) Lock() {
	g.mu.Lock()
	changed := g.conditionLocked()
	g.writersWaiting++
	for g.writer || g.readers != 0 {
		changed.Wait()
	}
	g.writersWaiting--
	g.writer = true
	g.mu.Unlock()
}

func (g *coherenceProfileGate) Unlock() {
	g.mu.Lock()
	if !g.writer {
		g.mu.Unlock()
		panic("authorityrpc: coherence profile exclusive admission not held")
	}
	g.writer = false
	g.conditionLocked().Broadcast()
	g.mu.Unlock()
}
