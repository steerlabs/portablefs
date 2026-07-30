// Package fusefrontend contains the small amount of coordination shared by
// PortableFS's in-process FUSE frontends.
package fusefrontend

import (
	"context"
	"strings"
	"sync"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// ReplyGate prevents a delegation handoff from being followed by an older
// content reply for the released subtree. Its zero value is ready for use.
//
// Read admission is path-scoped. Closing "a/b" waits for reads of "a/b" and
// descendants while reads in "a/c" continue. A closed scope remains closed
// until EndHandoff, so the exact cache flush and authority Checkin execute
// without a newer overlapping reply entering the old view.
type ReplyGate struct {
	mu sync.Mutex

	active  map[string]int
	closing map[string]int
	changed chan struct{}
}

// ReadAdmission owns one admitted content reply. On success, Wrap transfers
// the admission to go-fuse and keeps it live through ReadResult.Done. Abort
// releases an operation that will not return a ReadResult.
type ReadAdmission struct {
	fuse.ReadResult

	gate *ReplyGate
	path string

	mu    sync.Mutex
	state readAdmissionState
}

type readAdmissionState uint8

const (
	readAdmissionOpen readAdmissionState = iota
	readAdmissionWrapped
	readAdmissionFinished
)

// BeginRead enters content-reply admission for path. It waits only for a
// handoff whose scope contains path and returns the context error if the kernel
// request is canceled before admission.
func (g *ReplyGate) BeginRead(ctx context.Context, path string) (*ReadAdmission, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		g.mu.Lock()
		if !g.blockedLocked(path) {
			if g.active == nil {
				g.active = make(map[string]int)
			}
			g.active[path]++
			g.mu.Unlock()
			return &ReadAdmission{gate: g, path: path}, nil
		}
		changed := g.changedLocked()
		g.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// BeginHandoff closes reply admission for scope and waits for every admitted
// content reply in that subtree to reach ReadResult.Done. If ctx is canceled,
// the provisional close is removed before the error is returned.
func (g *ReplyGate) BeginHandoff(ctx context.Context, scope string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	g.mu.Lock()
	if g.closing == nil {
		g.closing = make(map[string]int)
	}
	g.closing[scope]++

	for g.activeUnderLocked(scope) != 0 {
		changed := g.changedLocked()
		g.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			g.mu.Lock()
			g.removeClosingLocked(scope)
			g.signalLocked()
			g.mu.Unlock()
			return ctx.Err()
		}

		if err := ctx.Err(); err != nil {
			g.mu.Lock()
			g.removeClosingLocked(scope)
			g.signalLocked()
			g.mu.Unlock()
			return err
		}
		g.mu.Lock()
	}
	g.mu.Unlock()
	return nil
}

// EndHandoff reopens one successfully closed scope. An unmatched call is a
// programming error: silently reopening a different boundary would violate
// the handoff proof.
func (g *ReplyGate) EndHandoff(scope string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.removeClosingLocked(scope)
	g.signalLocked()
}

// Wrap transfers this admission to result. go-fuse calls Done after publishing
// the read to the kernel; the gate is released only after the wrapped Done
// completes. Wrap must be called exactly once.
func (a *ReadAdmission) Wrap(result fuse.ReadResult) fuse.ReadResult {
	if result == nil {
		panic("fusefrontend: cannot wrap a nil read result")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != readAdmissionOpen {
		panic("fusefrontend: read admission already wrapped")
	}
	a.ReadResult = result
	a.state = readAdmissionWrapped
	return a
}

// Abort releases an admission whose operation will not publish a ReadResult.
// It is safe to call more than once.
func (a *ReadAdmission) Abort() {
	if a == nil {
		return
	}
	a.mu.Lock()
	switch a.state {
	case readAdmissionOpen:
		a.state = readAdmissionFinished
		a.mu.Unlock()
		a.release()
	case readAdmissionFinished:
		a.mu.Unlock()
	case readAdmissionWrapped:
		a.mu.Unlock()
		panic("fusefrontend: cannot abort a published read result")
	default:
		a.mu.Unlock()
		panic("fusefrontend: invalid read admission state")
	}
}

// Done implements fuse.ReadResult. The deferred release preserves the gate
// invariant even if a custom wrapped ReadResult panics during cleanup.
func (a *ReadAdmission) Done() {
	a.mu.Lock()
	switch a.state {
	case readAdmissionWrapped:
		result := a.ReadResult
		a.state = readAdmissionFinished
		a.mu.Unlock()
		defer a.release()
		result.Done()
	case readAdmissionFinished:
		a.mu.Unlock()
	case readAdmissionOpen:
		a.mu.Unlock()
		panic("fusefrontend: unwrapped read admission completed")
	default:
		a.mu.Unlock()
		panic("fusefrontend: invalid read admission state")
	}
}

func (a *ReadAdmission) release() {
	g := a.gate
	g.mu.Lock()
	count := g.active[a.path]
	if count <= 0 {
		g.mu.Unlock()
		panic("fusefrontend: read admission underflow")
	}
	if count == 1 {
		delete(g.active, a.path)
	} else {
		g.active[a.path] = count - 1
	}
	g.signalLocked()
	g.mu.Unlock()
}

func (g *ReplyGate) blockedLocked(path string) bool {
	for scope := range g.closing {
		if pathWithinScope(path, scope) {
			return true
		}
	}
	return false
}

func (g *ReplyGate) activeUnderLocked(scope string) int {
	total := 0
	for path, count := range g.active {
		if pathWithinScope(path, scope) {
			total += count
		}
	}
	return total
}

func (g *ReplyGate) removeClosingLocked(scope string) {
	count := g.closing[scope]
	if count <= 0 {
		panic("fusefrontend: unmatched handoff end")
	}
	if count == 1 {
		delete(g.closing, scope)
	} else {
		g.closing[scope] = count - 1
	}
}

func (g *ReplyGate) changedLocked() <-chan struct{} {
	if g.changed == nil {
		g.changed = make(chan struct{})
	}
	return g.changed
}

func (g *ReplyGate) signalLocked() {
	if g.changed != nil {
		close(g.changed)
		g.changed = nil
	}
}

func pathWithinScope(path, scope string) bool {
	return scope == "" || path == scope || strings.HasPrefix(path, scope+"/")
}
