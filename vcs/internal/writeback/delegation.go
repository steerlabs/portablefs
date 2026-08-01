package writeback

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// maxLiveDelegations is the ceiling on retained grants. Every live grant is a
// DELEGATION frame that rotation re-emits and an APPLIED+RELEASE pair the
// stream is later obliged to write, so the WAL's control reserve grows with the
// live set; without a ceiling that reserve — and therefore the cap it is carved
// from — has no closed form. The number is far above any real working set (the
// idle releaser hands scopes back after one second), so it binds only on a
// pathological fan-out, where refusing the grant is the correct answer anyway.
const maxLiveDelegations = 64

// errGrantNotAffordable is the definite "this stream cannot retain another
// grant" outcome: the ceiling is reached, or the WAL's control reserve can no
// longer dominate the close-out the new grant would join. It is not a failure —
// the grant is handed back and the mutation takes the authority lane, which
// consumes no stream budget at all.
var errGrantNotAffordable = errors.New("writeback: stream cannot retain another delegation")

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
	// A scope the WAL cannot represent, and a stream already holding the
	// maximum number of grants, are both answered before the authority is asked:
	// not delegable, so the mutation takes the authority lane. Both are definite
	// outcomes of the local bound, not transient failures, so they never become
	// an error that would fail the mutation instead of relanding it.
	if len(scope) > maxScopeBytes || e.held.Load() >= maxLiveDelegations {
		e.noteDenial(scope, 0)
		return false, nil
	}
	e.acquireMu.Lock()
	flight, inflight := e.acquiring[scope]
	if !inflight {
		flight = &acquireFlight{done: make(chan struct{})}
		e.acquiring[scope] = flight
		go e.resolveAcquire(scope, flight)
	}
	e.acquireMu.Unlock()
	// The resolver's outcome can depend on the authority recalling a peer's
	// delegation. A frontend operation waiting here can no longer publish a
	// pre-transition local view, so its publication must suspend — otherwise
	// two clients acquiring into each other's scopes re-create the reciprocal
	// handoff wait.
	var resume func()
	if e.cfg.Events.OnReleaseWait != nil {
		resume = e.cfg.Events.OnReleaseWait(ctx)
	}
	if resume != nil {
		defer resume()
	}
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
	var guard DelegationAcquireGuard
	if e.cfg.DelegationAcquireGate != nil {
		var err error
		guard, err = e.cfg.DelegationAcquireGate(e.ctx, scope)
		if err != nil {
			flight.err = fmt.Errorf("writeback: acquire %q transition: %w", scope, err)
			return
		}
		if guard.End != nil {
			defer guard.End()
		}
	}
	e.exactMu.RLock()
	defer e.exactMu.RUnlock()
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
		if reply.Granted {
			if releaseErr := e.remote.ReleaseDelegation(
				e.ctx,
				scope,
				reply.Epoch,
			); releaseErr != nil {
				flight.err = fmt.Errorf(
					"writeback: acquire %q failed after grant (%w); releasing the uninstalled grant also failed: %v",
					scope,
					err,
					releaseErr,
				)
				e.logf("%v", flight.err)
				return
			}
		}
		flight.err = fmt.Errorf("writeback: acquire %q: %w", scope, err)
		e.logf("writeback: acquire %q failed: %v", scope, err)
		return
	}
	install := true
	if guard.ReconcileReply != nil {
		install = guard.ReconcileReply(reply)
	}
	if !reply.Granted {
		e.noteDenial(scope, 0)
		return
	}
	if !install {
		if releaseErr := e.remote.ReleaseDelegation(e.ctx, scope, reply.Epoch); releaseErr != nil {
			flight.err = fmt.Errorf("writeback: reject conflicting grant %q: %w", scope, releaseErr)
			return
		}
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
		if errors.Is(err, errGrantNotAffordable) {
			// The grant is back with the authority and nothing was written.
			// This is a denial, not a failure: the mutation takes the
			// authority lane.
			e.noteDenial(scope, 0)
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
func (e *Engine) prepareReleaseLocked(ctx context.Context, d *delegation) *releaseAttempt {
	d.draining = true
	d.drainErr = nil
	// Release durability is owned by the engine context, not by the request
	// that happened to trigger it. Preserve only the triggering context's
	// values so frontend handoff hooks can identify their own in-flight
	// operation without allowing request cancellation to interrupt Checkin.
	eventCtx := e.ctx
	if ctx != nil {
		eventCtx = valueOverlayContext{Context: e.ctx, values: ctx}
	}
	d.attempt = newReleaseAttempt(eventCtx)
	attempt := d.attempt
	if e.forcing || e.closed {
		err := ErrFenced
		d.drainErr = err
		attempt.complete(err)
		return attempt
	}
	e.releaseWG.Add(1)
	go func() {
		defer e.releaseWG.Done()
		_ = e.finishRelease(e.ctx, d, attempt)
	}()
	return d.attempt
}

type releaseClaim struct {
	d       *delegation
	attempt *releaseAttempt
	owner   bool
}

func (e *Engine) claimReleaseLocked(ctx context.Context, d *delegation) releaseClaim {
	if !d.draining || d.drainErr != nil || d.attempt == nil {
		return releaseClaim{d: d, attempt: e.prepareReleaseLocked(ctx, d), owner: true}
	}
	return releaseClaim{d: d, attempt: d.attempt}
}

func waitReleaseAttempt(ctx context.Context, attempt *releaseAttempt) error {
	if attempt == nil {
		return fmt.Errorf("%w: delegation is draining without a release attempt", ErrConflict)
	}
	select {
	case <-attempt.done:
		return attempt.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) waitReleaseForCaller(ctx context.Context, attempt *releaseAttempt) error {
	var resume func()
	if e.cfg.Events.OnReleaseWait != nil {
		resume = e.cfg.Events.OnReleaseWait(ctx)
	}
	if resume != nil {
		defer resume()
	}
	return waitReleaseAttempt(ctx, attempt)
}

func (e *Engine) runReleaseClaims(ctx context.Context, claims []releaseClaim) error {
	var resume func()
	if len(claims) != 0 && e.cfg.Events.OnReleaseWait != nil {
		resume = e.cfg.Events.OnReleaseWait(ctx)
	}
	if resume != nil {
		defer resume()
	}
	var first error
	for _, claim := range claims {
		if err := waitReleaseAttempt(ctx, claim.attempt); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// failRelease records a definite failed attempt before waking admissions.
// The grant remains held and draining, so callers can retry the release but
// mutations cannot fall through inside the authority-owned scope.
func (e *Engine) failRelease(d *delegation, attempt *releaseAttempt, err error) error {
	e.mu.Lock()
	if e.delegations[d.scope] == d {
		if e.forcing {
			err = ErrFenced
		} else if e.streamDead != nil {
			err = e.streamDead
		}
		if d.attempt == attempt {
			d.draining = true
			d.drainErr = err
			d.readMu.Lock()
			d.readClosing = false
			d.readMu.Unlock()
		}
	}
	e.mu.Unlock()
	return attempt.complete(err)
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
	if len(e.delegations) >= maxLiveDelegations {
		return errGrantNotAffordable
	}
	// An epoch the WAL cannot frame is an authority protocol violation, not a
	// local resource bound: refuse the grant definitely rather than let the
	// unrepresentable value reach the log.
	if len(reply.Epoch) > maxEpochBytes {
		return fmt.Errorf(
			"writeback: authority grant epoch for %q is %d bytes, past the %d-byte control-frame bound",
			scope, len(reply.Epoch), maxEpochBytes,
		)
	}
	// The grant record is the ONE control frame that is refusable: it is what
	// grows the control reserve, so it is admitted only while the reserve still
	// dominates the close-out of the set it joins. It reserves against the whole
	// cap, like every other control frame.
	if err := e.wal.appendControlWithin(
		frameDelegation,
		delegationFrame{Scope: scope, Epoch: reply.Epoch},
		e.cfg.BudgetBytes,
	); err != nil {
		if errors.Is(err, ErrNoSpace) {
			return errGrantNotAffordable
		}
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
	if e.forcing || e.closed {
		e.mu.Unlock()
		return ErrFenced
	}
	if e.streamDead != nil {
		err := e.streamDead
		e.mu.Unlock()
		return err
	}
	var claims []releaseClaim
	for _, d := range e.delegations {
		if pathUnder(path, d.scope) || pathUnder(d.scope, path) {
			claim := e.claimReleaseLocked(ctx, d)
			claims = append(claims, claim)
			if claim.owner {
				// Contention recalled this scope: do not immediately re-acquire.
				e.denials[d.scope] = time.Now().Add(acquireDenialBackoff)
			}
		}
	}
	e.mu.Unlock()
	return e.runReleaseClaims(ctx, claims)
}

// finishRelease drains the stream through the scope's admitted tail, sends
// the durable release, and drops the overlay state. Only the owner of the
// explicit releaseAttempt enters this body; every racing caller waits on
// that attempt's immutable, context-aware outcome.
func (e *Engine) finishRelease(ctx context.Context, d *delegation, attempt *releaseAttempt) error {
	e.mu.RLock()
	if e.delegations[d.scope] != d {
		e.mu.RUnlock()
		return attempt.complete(nil) // already released
	}
	if d.attempt != attempt {
		e.mu.RUnlock()
		return waitReleaseAttempt(ctx, attempt)
	}
	if d.drainErr != nil || e.streamDead != nil {
		err := d.drainErr
		if e.streamDead != nil {
			err = e.streamDead
		}
		e.mu.RUnlock()
		return attempt.complete(err)
	}
	w := e.wal
	e.mu.RUnlock()
	var target uint64
	if w != nil {
		target = w.LastSeq()
		if err := w.Sync(); err != nil {
			return e.failRelease(d, attempt, e.failLocalWAL("pre-release sync", err))
		}
		if err := e.fl.drainThrough(ctx, target); err != nil {
			return e.failRelease(d, attempt, err)
		}
	}
	select {
	case <-attempt.done:
		return attempt.err
	default:
	}
	e.mu.RLock()
	current := e.delegations[d.scope] == d &&
		d.attempt == attempt &&
		d.draining
	e.mu.RUnlock()
	if !current {
		return attempt.complete(fmt.Errorf("%w: release attempt lost ownership before local finalization", ErrConflict))
	}
	handoffStarted := false
	if e.cfg.Events.OnHandoffStart != nil {
		if err := e.cfg.Events.OnHandoffStart(attempt.eventCtx, d.scope); err != nil {
			return e.failRelease(d, attempt, fmt.Errorf("writeback: frontend handoff start %q: %w", d.scope, err))
		}
		handoffStarted = true
	}
	if handoffStarted {
		defer e.cfg.Events.OnHandoffEnd(d.scope)
	}
	if err := e.closeReadAdmission(ctx, d, attempt); err != nil {
		return e.failRelease(d, attempt, err)
	}
	if e.cfg.Events.OnHandoff != nil {
		// Read admission is closed and every overlay reader has exited, while
		// the authority grant still excludes peers. Drop every user-space
		// cache that could otherwise bypass the exact read-view handoff.
		if err := e.cfg.Events.OnHandoff(d.scope); err != nil {
			return e.failRelease(d, attempt, fmt.Errorf("writeback: frontend handoff %q: %w", d.scope, err))
		}
	}
	var endOpenProtection func(bool)
	if e.cfg.ProtectOpenPins != nil {
		// Establish the open barrier only after the frontend cache handoff.
		// Some frontends implement that handoff with a daemon-owned open
		// through the mount; installing this barrier earlier would make that
		// exact refresh wait on the release it is preparing. Mutation and read
		// admission are already closed here, so the snapshot still captures
		// every earlier open, and the barrier remains live through Checkin.
		// A peer unlink after the release then parks the inode
		// (open-after-unlink), never destroys it.
		var err error
		endOpenProtection, err = e.cfg.ProtectOpenPins(ctx, d.scope, d.epoch)
		if err != nil {
			return e.failRelease(d, attempt, err)
		}
	}
	var endPublishedProtection func(bool)
	if e.cfg.Events.OnHandoffPrepared != nil {
		var err error
		endPublishedProtection, err = e.cfg.Events.OnHandoffPrepared(
			attempt.eventCtx, d.scope, d.epoch,
		)
		if err != nil {
			if endOpenProtection != nil {
				endOpenProtection(false)
			}
			return e.failRelease(
				d, attempt,
				fmt.Errorf("writeback: prepared frontend handoff %q: %w", d.scope, err),
			)
		}
	}
	endProtections := func(released bool) {
		if endPublishedProtection != nil {
			endPublishedProtection(released)
		}
		if endOpenProtection != nil {
			endOpenProtection(released)
		}
	}
	// All fallible local handoff preparation is complete. Record the
	// authority-confirmed applied prefix and locally-final release in one WAL
	// sync immediately before Checkin. Once this record is durable, the
	// release is intentionally irreversible: if Checkin commits but its reply
	// is lost and the authority retires the stream ledger, recovery has the
	// exact prefix certificate needed to retire the stream.
	if w != nil {
		through, digest := e.fl.appliedState()
		if through < target {
			endProtections(false)
			return e.failRelease(d, attempt, fmt.Errorf(
				"%w: release drain stopped at %d before target %d",
				ErrConflict, through, target,
			))
		}
		if err := w.recordDrainedRelease(d.scope, d.epoch, through, digest); err != nil {
			endProtections(false)
			return e.failRelease(d, attempt, e.failLocalWAL("record drained delegation release", err))
		}
		e.mu.Lock()
		current = e.delegations[d.scope] == d &&
			d.attempt == attempt &&
			d.draining
		if current {
			d.localFinal = true
		}
		e.mu.Unlock()
		if !current {
			endProtections(false)
			return attempt.complete(e.failClosed(fmt.Errorf(
				"writeback: release attempt lost ownership after durable local finalization",
			)))
		}
	}
	if err := e.remote.ReleaseDelegation(ctx, d.scope, d.epoch); err != nil {
		endProtections(false)
		return e.failRelease(d, attempt, err)
	}
	e.mu.Lock()
	if e.delegations[d.scope] == d {
		delete(e.delegations, d.scope)
		e.held.Store(int64(len(e.delegations)))
	}
	e.dropScopeStateLocked(d.scope)
	e.mu.Unlock()
	endProtections(true)
	if e.cfg.Events.OnRelease != nil {
		e.cfg.Events.OnRelease(d.scope)
	}
	return attempt.complete(nil)
}

// ReleaseFor drains and RELEASES every delegation overlapping any of paths:
// equal, ancestor, or descendant. The caller is about to execute a
// write-through namespace/metadata mutation (hard link, directory rename,
// orphan transition, xattr, unsupported shape), and a descendant grant is
// just as exclusive as a covering grant when its ancestor moves or changes.
// The scope leaves delegated mode first, so write-through always orders after
// the drained, durably released state.
func (e *Engine) ReleaseFor(ctx context.Context, paths ...string) error {
	if err := e.MutationError(); err != nil {
		return err
	}
	if e.held.Load() == 0 {
		return nil
	}
	e.mu.Lock()
	var claims []releaseClaim
	seen := map[*delegation]bool{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		for scope, d := range e.delegations {
			if seen[d] || !delegationPathsOverlap(scope, p) {
				continue
			}
			seen[d] = true
			claims = append(claims, e.claimReleaseLocked(ctx, d))
		}
	}
	e.mu.Unlock()
	return e.runReleaseClaims(ctx, claims)
}

func delegationPathsOverlap(a, b string) bool {
	return a == b ||
		strings.HasPrefix(a, b+"/") ||
		strings.HasPrefix(b, a+"/")
}

// BeginExact drains and releases every delegation retained by this engine,
// then excludes new asynchronous acquisition until the returned end function
// is called. It is reserved for stable-inode operations whose namespace
// aliases are all unknown: no pathname can prove which delegation may contain
// acknowledged state for that inode.
//
// Acquisition resolvers hold exactMu shared for their complete lifetime. This
// includes the deliberate detached-resolution interval after their initiating
// request times out, so BeginExact cannot miss an in-flight grant that later
// installs while the exact authority operation is running.
func (e *Engine) BeginExact(ctx context.Context) (end func(), err error) {
	// Acquisition resolvers hold exactMu shared across their complete
	// authority round-trip, so this exclusive acquisition is itself an
	// authority-bound wait and must suspend the caller's publication.
	var resumeLock func()
	if e.cfg.Events.OnReleaseWait != nil {
		resumeLock = e.cfg.Events.OnReleaseWait(ctx)
	}
	e.exactMu.Lock()
	if resumeLock != nil {
		resumeLock()
	}
	// Single-shot: the caller's exclusion may be handed to a parked exact
	// identity's replayer (clientcore exclusionRelease), so the end closure
	// can be invoked from a different goroutine than the one that acquired it.
	// Make a second invocation impossible rather than an unlock-of-unlocked
	// panic if any owner ever double-releases.
	var endOnce sync.Once
	end = func() { endOnce.Do(e.exactMu.Unlock) }
	if err := e.MutationError(); err != nil {
		end()
		return nil, err
	}
	if e.held.Load() == 0 {
		return end, nil
	}
	e.mu.Lock()
	claims := make([]releaseClaim, 0, len(e.delegations))
	for _, d := range e.delegations {
		claims = append(claims, e.claimReleaseLocked(ctx, d))
	}
	e.mu.Unlock()
	if err := e.runReleaseClaims(ctx, claims); err != nil {
		end()
		return nil, err
	}
	return end, nil
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
	var claims []releaseClaim
	for _, d := range e.delegations {
		claims = append(claims, e.claimReleaseLocked(ctx, d))
	}
	e.mu.Unlock()
	return e.runReleaseClaims(ctx, claims)
}

// releaseIdle voluntarily releases clean delegations that have been idle for
// idleReleaseAfter with nothing pending and no open handles under them.
func (e *Engine) releaseIdle() {
	e.releaseIdleWithWait(30 * time.Second)
}

// releaseIdleWithWait is split out so tests can exercise waiter timeout
// independently of the engine-owned release worker's lifetime.
func (e *Engine) releaseIdleWithWait(wait time.Duration) {
	e.mu.Lock()
	var claims []releaseClaim
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
		claims = append(claims, e.claimReleaseLocked(e.ctx, d))
	}
	e.mu.Unlock()
	for _, claim := range claims {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		if err := waitReleaseAttempt(ctx, claim.attempt); err != nil {
			e.mu.Lock()
			attemptDone := false
			select {
			case <-claim.attempt.done:
				attemptDone = true
			default:
			}
			canRearm := attemptDone &&
				e.delegations[claim.d.scope] == claim.d &&
				claim.d.attempt == claim.attempt &&
				!claim.d.localFinal &&
				e.streamDead == nil &&
				!e.forcing &&
				!e.closed &&
				e.MutationError() == nil
			if canRearm {
				claim.d.draining = false
				claim.d.drainErr = nil
				claim.d.attempt = nil
			}
			e.mu.Unlock()
			if canRearm {
				e.logf("writeback: idle release of %q failed before local finalization; delegated admission re-armed: %v", claim.d.scope, err)
			} else {
				// Checkin can fail after the WAL has made release locally
				// final. That boundary is irreversible; an explicit release
				// may retry Checkin, while crash recovery reconciles it.
				e.logf("writeback: idle release of %q failed; scope remains draining: %v", claim.d.scope, err)
			}
		}
		cancel()
	}
}
