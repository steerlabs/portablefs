package writeback

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// ReadPermit pins one delegation-backed read view across a complete
// clientcore operation. The concrete permit is deliberately private and
// pointer-backed: copying this interface still shares one idempotent Close
// state, so a deferred close cannot release an admission twice.
type ReadPermit interface {
	Close()
	Covers(path string) bool
	Lookup(path string) (Entry, LookupResult)
	Readdir(dir string) ([]Entry, bool)
	MergeReaddir(dir string, authority []Entry) []Entry
	ReadAt(path string, dst []byte, off int64, base BaseReader) (int, bool, error)
	Readlink(path string) (target string, kind string, ok bool)
	Getxattr(path, name string) ([]byte, LookupResult)
	Listxattr(path string) ([]string, bool)
}

type delegatedReadPermit struct {
	engine     *Engine
	delegation *delegation
	once       sync.Once
	closed     atomic.Bool
}

// sharedReadPermit is the allocation-free steady-state read lane.
type sharedReadPermit struct{}

var authorityReadPermit ReadPermit = sharedReadPermit{}

// SharedReadPermit returns the immutable authority-lane permit. It is useful
// to embedders that construct a Volume without a write-back engine.
func SharedReadPermit() ReadPermit { return authorityReadPermit }

// BeginRead enters the current read view for path. During the WAL-drain phase,
// reads continue joining the still-authoritative overlay. Once the drained
// tail is authority-visible, finishRelease closes admission and waits for
// every permit before Checkin. New readers then wait for that immutable
// release attempt and retry against either the post-release authority view or
// the retained overlay after a definite release failure.
func (e *Engine) BeginRead(ctx context.Context, path string) (ReadPermit, error) {
	for {
		// Most reads happen while no grant is held. The atomic mirror makes
		// that lane lock- and allocation-free. A concurrent grant either
		// publishes held first (and is observed below) or this read
		// linearizes immediately before acquisition on the authority view.
		if e.held.Load() == 0 {
			select {
			case <-e.ctx.Done():
				return nil, ErrFenced
			default:
				return authorityReadPermit, nil
			}
		}

		e.mu.RLock()
		if e.closed {
			e.mu.RUnlock()
			return nil, ErrFenced
		}
		d := e.coveringLocked(path)
		if d == nil {
			e.mu.RUnlock()
			return authorityReadPermit, nil
		}
		attempt := d.attempt
		e.mu.RUnlock()

		d.readMu.Lock()
		if !d.readClosing {
			d.readers++
			d.readMu.Unlock()
			return &delegatedReadPermit{engine: e, delegation: d}, nil
		}
		d.readMu.Unlock()

		// The handoff may have started after the delegation lookup above.
		// Re-read its immutable attempt under the engine lock if needed.
		if attempt == nil {
			e.mu.RLock()
			attempt = d.attempt
			e.mu.RUnlock()
			if attempt == nil {
				return nil, fmt.Errorf("%w: delegation read handoff has no release attempt", ErrConflict)
			}
		}
		select {
		case <-attempt.done:
			// Success removed the delegation and failure reopened its retained
			// overlay before completing the attempt. Re-resolve under e.mu.
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Close releases the read view. It is idempotent so deferred cleanup remains
// safe along every frontend error path.
func (p *delegatedReadPermit) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		p.closed.Store(true)
		if p.engine == nil || p.delegation == nil {
			return
		}
		d := p.delegation
		d.readMu.Lock()
		if d.readers <= 0 {
			d.readMu.Unlock()
			panic("writeback: delegation read permit underflow")
		}
		d.readers--
		if d.readers == 0 && d.readersZero != nil {
			close(d.readersZero)
			d.readersZero = nil
		}
		d.readMu.Unlock()
	})
}

func (sharedReadPermit) Close() {}

// Covers reports whether this permit pins the retained delegation that
// covers path. A shared-lane permit deliberately returns false even if a
// grant is acquired later: the read overlapped that acquisition and remains
// linearized on its original authority view.
func (p *delegatedReadPermit) Covers(path string) bool {
	if p == nil || p.closed.Load() || p.engine == nil || p.delegation == nil {
		return false
	}
	// The reader count pins d until Close: a normal handoff cannot remove or
	// replace it while this permit is live. The overlay method itself takes
	// e.mu for map safety, so this hot-path ownership test needs no second
	// lock acquisition.
	return pathUnder(path, p.delegation.scope)
}

func (sharedReadPermit) Covers(string) bool { return false }

// Lookup resolves path through the exact read view pinned by this permit.
func (p *delegatedReadPermit) Lookup(path string) (Entry, LookupResult) {
	if !p.Covers(path) {
		return Entry{}, LookupUndecided
	}
	return p.engine.lookup(path)
}

func (sharedReadPermit) Lookup(string) (Entry, LookupResult) {
	return Entry{}, LookupUndecided
}

// Readdir resolves a complete directory listing through the pinned view.
func (p *delegatedReadPermit) Readdir(dir string) ([]Entry, bool) {
	if !p.Covers(dir) {
		return nil, false
	}
	return p.engine.readdir(dir)
}

func (sharedReadPermit) Readdir(string) ([]Entry, bool) { return nil, false }

// MergeReaddir composes an authority listing with the pinned overlay. A
// shared-lane permit returns the authority listing unchanged.
func (p *delegatedReadPermit) MergeReaddir(dir string, authority []Entry) []Entry {
	if !p.Covers(dir) {
		return authority
	}
	return p.engine.mergeReaddir(dir, authority)
}

func (sharedReadPermit) MergeReaddir(_ string, authority []Entry) []Entry {
	return authority
}

// ReadAt composes dirty extents over base through the pinned view.
func (p *delegatedReadPermit) ReadAt(path string, dst []byte, off int64, base BaseReader) (int, bool, error) {
	if !p.Covers(path) {
		return 0, false, nil
	}
	return p.engine.readAt(path, dst, off, base)
}

func (sharedReadPermit) ReadAt(string, []byte, int64, BaseReader) (int, bool, error) {
	return 0, false, nil
}

// Readlink resolves a symlink through the pinned view.
func (p *delegatedReadPermit) Readlink(path string) (target string, kind string, ok bool) {
	if !p.Covers(path) {
		return "", "", false
	}
	return p.engine.readlink(path)
}

func (sharedReadPermit) Readlink(string) (string, string, bool) { return "", "", false }

// Getxattr resolves one xattr through the pinned view.
func (p *delegatedReadPermit) Getxattr(path, name string) ([]byte, LookupResult) {
	if !p.Covers(path) {
		return nil, LookupUndecided
	}
	return p.engine.getxattr(path, name)
}

func (sharedReadPermit) Getxattr(string, string) ([]byte, LookupResult) {
	return nil, LookupUndecided
}

// Listxattr resolves the complete xattr name set through the pinned view.
func (p *delegatedReadPermit) Listxattr(path string) ([]string, bool) {
	if !p.Covers(path) {
		return nil, false
	}
	return p.engine.listxattr(path)
}

func (sharedReadPermit) Listxattr(string) ([]string, bool) { return nil, false }

// closeReadAdmission waits until every operation that entered the overlay
// view has completed. Caller performs this only after drainThrough proved the
// captured tail authority-visible and before sending Checkin.
func (e *Engine) closeReadAdmission(ctx context.Context, d *delegation, attempt *releaseAttempt) error {
	e.mu.RLock()
	if e.delegations[d.scope] != d || d.attempt != attempt || !d.draining {
		e.mu.RUnlock()
		return fmt.Errorf("%w: delegation changed before read handoff", ErrConflict)
	}
	e.mu.RUnlock()

	d.readMu.Lock()
	d.readClosing = true
	if d.readers == 0 {
		d.readMu.Unlock()
		return nil
	}
	if d.readersZero == nil {
		d.readersZero = make(chan struct{})
	}
	zero := d.readersZero
	d.readMu.Unlock()
	select {
	case <-zero:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
