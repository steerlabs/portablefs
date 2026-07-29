package writeback

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type acquireFlight struct {
	done chan struct{}
	err  error
}

// acquire asks the authority to delegate scope (singleflight per scope).
// The resolution runs DETACHED on the engine's lifetime context: whatever
// the outcome (grant or definite denial), the resolver installs or denies it
// even if every waiting mutation's context has expired — the authority can
// never hold a grant the engine does not know exists. Callers wait bounded
// on their own contexts.
func (e *Engine) acquire(ctx context.Context, scope string) (bool, error) {
	e.acquireMu.Lock()
	flight, inflight := e.acquiring[scope]
	if !inflight {
		flight = &acquireFlight{done: make(chan struct{})}
		e.acquiring[scope] = flight
		go e.resolveAcquire(scope, flight)
	}
	e.acquireMu.Unlock()
	select {
	case <-flight.done:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	if flight.err != nil {
		return false, flight.err
	}
	e.mu.RLock()
	_, held := e.delegations[scope]
	e.mu.RUnlock()
	return held, nil
}

// resolveAcquire runs one scope's acquire to a KNOWN end state. The remote
// resolves sent-but-unanswered requests by replaying the identical exact
// identity, so an error here means: never sent (authority holds nothing),
// session fenced, or engine shutdown — in the latter two any committed grant
// is bound to a generation whose fate the recovery machinery owns (swept or
// rebound on the next attach); it is never reinterpreted as a denial that
// forks the mutation lanes mid-session.
func (e *Engine) resolveAcquire(scope string, flight *acquireFlight) {
	defer func() {
		e.acquireMu.Lock()
		delete(e.acquiring, scope)
		e.acquireMu.Unlock()
		close(flight.done)
	}()
	// The stream (and its recovery-job registry) must be durable before the
	// grant can admit anything. A dead (parked) stream never installs a new
	// grant: its WAL can never advance.
	e.mu.Lock()
	if e.closed || e.frozen {
		flight.err = errors.New("writeback: engine stopped during delegation acquisition")
		e.mu.Unlock()
		return
	}
	if err := e.MutationError(); err != nil {
		flight.err = err
		e.mu.Unlock()
		return
	}
	if err := e.ensureStreamLocked(); err != nil {
		flight.err = err
		e.mu.Unlock()
		e.logf("writeback: acquire %q: stream unavailable: %v", scope, err)
		return
	}
	e.mu.Unlock()

	reply, err := e.remote.DelegationAcquire(e.ctx, scope, e.writebackID)
	if err != nil {
		flight.err = fmt.Errorf("writeback: acquire %q: %w", scope, err)
		e.logf("writeback: acquire %q failed: %v", scope, err)
		return
	}
	if !reply.Granted {
		e.noteDenial(scope, 0)
		return
	}
	if err := e.installGrant(scope, reply); err != nil {
		// The WAL rejected the grant record: abort the grant so the
		// authority does not hold a scope we cannot use.
		if releaseErr := e.remote.ReleaseDelegation(e.ctx, scope, reply.Epoch); releaseErr != nil {
			flight.err = fmt.Errorf("writeback: install grant %q failed (%w); releasing unusable grant also failed: %v", scope, err, releaseErr)
			return
		}
		flight.err = err
		return
	}
	if e.cfg.Events.OnGrant != nil {
		e.cfg.Events.OnGrant(scope)
	}
}

func (e *Engine) noteDenial(scope string, backoff time.Duration) {
	if backoff <= 0 {
		backoff = acquireDenialBackoff
	}
	e.mu.Lock()
	e.denials[scope] = time.Now().Add(backoff)
	e.mu.Unlock()
}

// prepareReleaseLocked starts a fresh drain+release attempt when the
// delegation is active or its previous attempt failed. Caller holds e.mu.
// A release already in progress keeps its signal so racing releasers share
// one definite outcome.
func (e *Engine) prepareReleaseLocked(d *delegation) {
	if !d.draining || d.drainErr != nil {
		d.draining = true
		d.drainErr = nil
		d.done = make(chan struct{})
	}
}

func closeReleaseSignal(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// failRelease records a definite failed attempt before waking admissions.
// The grant remains held and draining, so callers can retry the release but
// mutations cannot fall through inside the authority-owned scope.
func (e *Engine) failRelease(d *delegation, err error) error {
	e.mu.Lock()
	if e.delegations[d.scope] == d {
		if e.streamDead != nil {
			err = e.streamDead
		}
		d.draining = true
		d.drainErr = err
		closeReleaseSignal(d.done)
	}
	e.mu.Unlock()
	return err
}

// installGrant records the grant durably (a DELEGATION frame precedes every
// mutation that relies on it) and installs the authoritative snapshot. The
// authority only delegates existing directories; a duplicate replay of a
// lost grant reply carries no snapshot — the client re-seeds with one
// readdir under the held grant.
func (e *Engine) installGrant(scope string, reply AcquireReply) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.frozen || e.streamDead != nil {
		return ErrFenced
	}
	if err := e.ensureStreamLocked(); err != nil {
		return err
	}
	if err := e.wal.appendControl(frameDelegation, delegationFrame{Scope: scope, Epoch: reply.Epoch}); err != nil {
		return e.failLocalWAL("record delegation", err)
	}
	d := &delegation{
		scope: scope, epoch: reply.Epoch,
		grantedAt: time.Now(), lastActive: time.Now(),
	}
	e.delegations[scope] = d
	e.held.Store(int64(len(e.delegations)))
	delete(e.denials, scope)
	if reply.Exists {
		// The scope root itself is authoritative under the grant too. FSKit
		// asks for parent attributes during nearly every create; omitting
		// Self forced those getattr callbacks onto the network even while we
		// exclusively owned the directory, adding one authority RTT to every
		// small-file create.
		e.installEntryLocked(scope, reply.Self)
	}
	if reply.HasChildren {
		dv := newDirView(true)
		for i := range reply.Children {
			ent := reply.Children[i]
			dv.children[ent.Name] = &ent
		}
		e.dirs[scope] = dv
	}
	return nil
}

// Recall drains and releases every delegation overlapping path (the
// authority recalled it for a peer). It returns once the release is durable
// at the authority — the peer's wait ends then.
func (e *Engine) Recall(ctx context.Context, path string) error {
	e.mu.Lock()
	var targets []*delegation
	for _, d := range e.delegations {
		if pathUnder(path, d.scope) || pathUnder(d.scope, path) {
			targets = append(targets, d)
		}
	}
	for _, d := range targets {
		if !d.draining || d.drainErr != nil {
			e.prepareReleaseLocked(d)
			// Contention recalled this scope: do not immediately re-acquire.
			e.denials[d.scope] = time.Now().Add(acquireDenialBackoff)
		}
	}
	e.mu.Unlock()
	var first error
	for _, d := range targets {
		if err := e.finishRelease(ctx, d); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// finishRelease drains the stream through the scope's admitted tail, sends
// the durable release, and drops the overlay state. Single-winner: relMu
// serializes racing releasers (recall, idle, release-before-write-through);
// the loser observes the completed release and returns nil.
func (e *Engine) finishRelease(ctx context.Context, d *delegation) error {
	d.relMu.Lock()
	defer d.relMu.Unlock()
	e.mu.RLock()
	if e.delegations[d.scope] != d {
		e.mu.RUnlock()
		return nil // already released
	}
	if d.drainErr != nil {
		err := d.drainErr
		e.mu.RUnlock()
		return err // racing releaser observes this attempt's outcome
	}
	w := e.wal
	e.mu.RUnlock()
	if w != nil {
		if err := w.Sync(); err != nil {
			return e.failRelease(d, e.failLocalWAL("pre-release sync", err))
		}
		if err := e.fl.drainThrough(ctx, w.LastSeq()); err != nil {
			return e.failRelease(d, err)
		}
	}
	if e.cfg.EnsureOpenPins != nil {
		// Open handles under the scope must hold authority-durable open
		// pins BEFORE the release: a peer unlink after the release must
		// park the inode (open-after-unlink), never destroy it.
		if err := e.cfg.EnsureOpenPins(ctx, d.scope); err != nil {
			return e.failRelease(d, err)
		}
	}
	if err := e.remote.ReleaseDelegation(ctx, d.scope, d.epoch); err != nil {
		return e.failRelease(d, err)
	}
	e.mu.Lock()
	if e.delegations[d.scope] == d {
		delete(e.delegations, d.scope)
		e.held.Store(int64(len(e.delegations)))
	}
	e.dropScopeStateLocked(d.scope)
	var localErr error
	if w != nil {
		if err := w.appendControl(frameRelease, delegationFrame{Scope: d.scope, Epoch: d.epoch}); err != nil {
			localErr = e.failLocalWAL("record delegation release", err)
		} else if err := w.Sync(); err != nil {
			localErr = e.failLocalWAL("sync delegation release", err)
		}
	}
	closeReleaseSignal(d.done)
	e.mu.Unlock()
	if e.cfg.Events.OnRelease != nil {
		e.cfg.Events.OnRelease(d.scope)
	}
	return localErr
}

// ReleaseFor drains and RELEASES every delegation covering any of paths: the
// caller is about to execute a write-through operation (hard link,
// cross-scope rename, orphan transition, xattr, unsupported shape), and no
// mutation ever runs write-through INSIDE a held delegation — the scope
// leaves delegated mode first, so the write-through orders after the
// drained, durably released state.
func (e *Engine) ReleaseFor(ctx context.Context, paths ...string) error {
	if err := e.MutationError(); err != nil {
		return err
	}
	if e.held.Load() == 0 {
		return nil
	}
	e.mu.Lock()
	var targets []*delegation
	seen := map[*delegation]bool{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		d := e.coveringLocked(p)
		if d == nil || seen[d] {
			continue
		}
		seen[d] = true
		if !d.draining || d.drainErr != nil {
			e.prepareReleaseLocked(d)
		}
		targets = append(targets, d)
	}
	e.mu.Unlock()
	var first error
	for _, d := range targets {
		if err := e.finishRelease(ctx, d); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// dropScopeStateLocked drops every overlay view under scope: the delegation
// is gone, so the shared version-gated paths own the truth again.
func (e *Engine) dropScopeStateLocked(scope string) {
	for p := range e.dirs {
		if pathUnder(p, scope) {
			delete(e.dirs, p)
		}
	}
	for p := range e.files {
		if pathUnder(p, scope) {
			delete(e.files, p)
		}
	}
	for p := range e.xattrs {
		if pathUnder(p, scope) {
			delete(e.xattrs, p)
		}
	}
	// The scope root's entry lives in its parent's view; that view is not
	// under the scope, so evict just the entry (its attrs may be stale once
	// shared mode resumes).
	if dv := e.dirs[parentDir(scope)]; dv != nil {
		delete(dv.children, baseName(scope))
		if !dv.complete {
			// Absence must not read as a tombstone: forget the name entirely.
			delete(dv.tombstones, baseName(scope))
		}
	}
}

// releaseAll drains and releases every delegation (clean unmount).
func (e *Engine) releaseAll(ctx context.Context) error {
	e.mu.Lock()
	var targets []*delegation
	for _, d := range e.delegations {
		if !d.draining || d.drainErr != nil {
			e.prepareReleaseLocked(d)
		}
		targets = append(targets, d)
	}
	e.mu.Unlock()
	var first error
	for _, d := range targets {
		if err := e.finishRelease(ctx, d); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// releaseIdle voluntarily releases clean delegations that have been idle for
// idleReleaseAfter with nothing pending and no open handles under them.
func (e *Engine) releaseIdle() {
	e.mu.Lock()
	var targets []*delegation
	now := time.Now()
	for _, d := range e.delegations {
		if d.draining || now.Sub(d.lastActive) < idleReleaseAfter {
			continue
		}
		if e.fl.outstanding(d.scope) != 0 {
			continue
		}
		if e.cfg.Busy != nil && e.cfg.Busy(d.scope) {
			continue
		}
		e.prepareReleaseLocked(d)
		targets = append(targets, d)
	}
	e.mu.Unlock()
	for _, d := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := e.finishRelease(ctx, d); err != nil {
			e.logf("writeback: idle release of %q failed (will retry): %v", d.scope, err)
			// This release was voluntary. failRelease already woke waiters
			// with a definite outcome; re-arm only while the stream is
			// healthy so they can safely resume delegated admission.
			e.mu.Lock()
			if e.delegations[d.scope] == d && e.streamDead == nil {
				d.draining = false
				d.drainErr = nil
				d.done = nil
			}
			e.mu.Unlock()
		}
		cancel()
	}
}
