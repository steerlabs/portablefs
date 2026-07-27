package workfs

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Managed session-store bridge: the SAME SessionStore surface the fsproto
// server drives (EstablishSessionWithToken, ResumeSession, CheckSlot,
// MutateEnv, ...) implemented over journaled PFC2 controls when the FS is a
// managed PFJ3/PFC2 generation.
//
// Every durable transition is one CommitEntry row: validate/stage against the
// reservation-order reducer, encode the exact bytes once, one synchronous
// fenced database transaction, apply to the applied-order reducer, publish
// one revision, reply. Lease times are exact database facts observed through
// capability-bound admission facts; the ONLY thing host clocks do here is
// schedule re-checks and project remaining durations. There is no reclaim
// grace, no public reap/reassert, and no wall-time pruning in managed mode.

// managedSessionInfo projects one session id's bridge view. Deadlines are
// exact DATABASE times (they are comparable to other database times and to
// the projections the client was handed, never to an authoritative host
// clock).
func (fs *FS) managedSessionInfo(sessionID string) (SessionInfo, bool) {
	reserved, ok := fs.managed.reserved.Session(sessionID)
	if !ok {
		return SessionInfo{}, false
	}
	info := SessionInfo{
		SessionID:  sessionID,
		Generation: reserved.Ref.Generation,
		Owner:      reserved.Owner,
		Slots:      reserved.Slots,
		Expired:    reserved.Terminal,
		ExpiresMs:  reserved.ExpiresDbMs,
	}
	if applied, ok := fs.managed.applied.Session(sessionID); ok && applied.Ref == reserved.Ref {
		info.DurableExpiresMs = applied.ExpiresDbMs
		info.Durable = applied.Terminal == reserved.Terminal &&
			applied.Owner == reserved.Owner && applied.Slots == reserved.Slots
	}
	return info, true
}

// mapManagedControlError translates reducer classifications onto the
// session-store error vocabulary the protocol layer already speaks.
func mapManagedControlError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pfc2.ErrCapacity):
		return fmt.Errorf("%w: %v", ErrControlCapacity, err)
	case errors.Is(err, pfc2.ErrFence):
		return fmt.Errorf("%w: %v", ErrSessionStale, err)
	default:
		return err
	}
}

// managedEstablishSession journals one PFC2 SessionOpen under a fresh
// admission fact. The exact (id, generation, owner, slots, tokenHash) tuple
// is lost-reply safe: a replay of an identical establish answers success from
// durable state WITHOUT journaling a second open (the second open would carry
// a different minted fact, and identical bytes — not identical intents — are
// the journal's retry unit).
func (fs *FS) managedEstablishSession(sessionID string, generation uint64, owner string, slots uint32, token string) error {
	if err := validateSessionInput(sessionID, owner, slots, token); err != nil {
		return err
	}
	// Serialize lifecycle transitions PER SESSION (open, renew, terminal,
	// expiry all share the shard lock), so overlapping transitions of one
	// identity can never interleave their observe→journal windows.
	lifecycle := &fs.renewLocks[sessionRenewShard(sessionID)]
	lifecycle.Lock()
	defer lifecycle.Unlock()
	sum := sha256.Sum256([]byte(token))
	ref := pfc2.SessionRef{SessionID: sessionID, Generation: generation}
	if done, err := fs.managedEstablishReplay(ref, owner, slots, sum); done {
		return err
	}
	// Serialize mint→journal: issuance binds the exact durable control floor
	// and facts consume in issuance order.
	fs.managed.factMu.Lock()
	defer fs.managed.factMu.Unlock()
	if done, err := fs.managedEstablishReplay(ref, owner, slots, sum); done {
		return err
	}
	issued, err := fs.IssueAdmissionFact(ref, pfc2.FactPurposeSessionOpen)
	if err != nil {
		return err
	}
	rec, err := pfc2.NewSessionOpenRecord(ref, owner, sum, slots, issued.Fact, SessionLeaseTTL)
	if err != nil {
		return err
	}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{*rec}, ""); err != nil {
		// A racing identical establish may have won the reservation between
		// the replay check and staging; classify against the current view.
		if done, rerr := fs.managedEstablishReplay(ref, owner, slots, sum); done {
			return rerr
		}
		return mapManagedControlError(err)
	}
	// The database minted the lease; anchor its projection on the local
	// monotonic clock (deadline = now + TTL, the record's own
	// expires − minted delta).
	fs.anchorProjectedLease(sessionID, generation, SessionLeaseTTL.Milliseconds())
	return nil
}

// managedEstablishReplay classifies an establish against the reservation-
// order view: (true, nil) is an idempotent replay of the identical durable
// tuple, (true, err) is a definite stale/conflict answer, and (false, _)
// means the open is fresh and must be journaled.
func (fs *FS) managedEstablishReplay(ref pfc2.SessionRef, owner string, slots uint32, tokenHash [pfc2.TokenHashBytes]byte) (bool, error) {
	reserved := fs.managed.reserved
	info, ok := reserved.Session(ref.SessionID)
	if !ok || info.Ref.Generation < ref.Generation {
		return false, nil // fresh identity (or a supersede of a lower generation)
	}
	if info.Ref.Generation > ref.Generation {
		return true, fmt.Errorf("%w: session %s generation %d is superseded by %d",
			ErrSessionStale, ref.SessionID, ref.Generation, info.Ref.Generation)
	}
	if info.Terminal {
		return true, fmt.Errorf("%w: session %s generation %d is fenced",
			ErrSessionStale, ref.SessionID, ref.Generation)
	}
	hash, ok := reserved.SessionTokenHash(ref)
	if ok && subtle.ConstantTimeCompare(hash[:], tokenHash[:]) == 1 &&
		info.Owner == owner && info.Slots == slots {
		return true, nil // identical durable tuple: lost-reply replay
	}
	return true, fmt.Errorf("%w: session %s generation %d presented a different tuple",
		ErrSessionConflict, ref.SessionID, ref.Generation)
}

// managedResumeSession authenticates a reconnect and journals one PFC2
// SessionRenew under a fresh admission fact. The durable deadline strictly
// advances; a same-millisecond renewal that would not advance it is
// suppressed at admission and answered from durable state.
func (fs *FS) managedResumeSession(sessionID string, generation uint64, token string) (SessionInfo, error) {
	if token == "" || len(token) > MaxSessionTokenBytes {
		return SessionInfo{}, ErrSessionStale
	}
	lock := &fs.renewLocks[sessionRenewShard(sessionID)]
	lock.Lock()
	defer lock.Unlock()
	sum := sha256.Sum256([]byte(token))
	ref := pfc2.SessionRef{SessionID: sessionID, Generation: generation}
	if err := fs.managedAuthenticateTuple(ref, sum); err != nil {
		return SessionInfo{}, err
	}
	fs.managed.factMu.Lock()
	defer fs.managed.factMu.Unlock()
	issued, err := fs.IssueAdmissionFact(ref, pfc2.FactPurposeSessionRenew)
	if err != nil {
		return SessionInfo{}, err
	}
	rec, err := pfc2.NewSessionRenewRecord(ref, sum, issued.Fact, SessionLeaseTTL)
	if err != nil {
		return SessionInfo{}, err
	}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{*rec}, ""); err != nil {
		if errors.Is(err, pfc2.ErrIntegrity) {
			// Non-advancing renewal: suppressed, answer from durable state.
		} else {
			return SessionInfo{}, mapManagedControlError(err)
		}
	} else {
		// The database renewed the lease; re-anchor the monotonic projection
		// with the record's own expires − minted delta.
		fs.anchorProjectedLease(sessionID, generation, SessionLeaseTTL.Milliseconds())
	}
	info, ok := fs.managedSessionInfo(sessionID)
	if !ok || info.Expired || info.Generation != generation {
		return SessionInfo{}, ErrSessionStale
	}
	return info, nil
}

// managedAuthenticateSession verifies a token against the live generation
// without renewing anything.
func (fs *FS) managedAuthenticateSession(sessionID string, token string) (SessionInfo, error) {
	if token == "" || len(token) > MaxSessionTokenBytes {
		return SessionInfo{}, ErrSessionStale
	}
	sum := sha256.Sum256([]byte(token))
	info, ok := fs.managedSessionInfo(sessionID)
	if !ok || info.Expired {
		return SessionInfo{}, ErrSessionStale
	}
	ref := pfc2.SessionRef{SessionID: sessionID, Generation: info.Generation}
	if err := fs.managedAuthenticateTuple(ref, sum); err != nil {
		return SessionInfo{}, err
	}
	return info, nil
}

// managedAuthenticateTuple proves (id, generation, token) against BOTH
// reducer views: the reservation-order view (the generation is not already
// fenced or superseded by an in-flight transition) and the applied view.
func (fs *FS) managedAuthenticateTuple(ref pfc2.SessionRef, tokenHash [pfc2.TokenHashBytes]byte) error {
	for _, view := range []*pfc2.State{fs.managed.reserved, fs.managed.applied} {
		info, ok := view.Session(ref.SessionID)
		if !ok || info.Terminal || info.Ref.Generation != ref.Generation {
			return ErrSessionStale
		}
		hash, ok := view.SessionTokenHash(ref)
		if !ok || subtle.ConstantTimeCompare(hash[:], tokenHash[:]) != 1 {
			return ErrSessionStale
		}
	}
	return nil
}

// managedTerminalSession journals one SessionTerminal for the named live
// generation. Unknown, superseded, and already-terminal generations are
// idempotent no-ops (they are already as fenced as a terminal would leave
// them, by ordering).
func (fs *FS) managedTerminalSession(sessionID string, generation uint64, reason pfc2.TerminalReason) error {
	lifecycle := &fs.renewLocks[sessionRenewShard(sessionID)]
	lifecycle.Lock()
	defer lifecycle.Unlock()
	info, ok := fs.managed.reserved.Session(sessionID)
	if !ok || info.Ref.Generation != generation || info.Terminal {
		return nil
	}
	rec := pfc2.Record{Kind: pfc2.KindSessionTerminal, SessionTerminal: &pfc2.SessionTerminal{
		Session: pfc2.SessionRef{SessionID: sessionID, Generation: generation},
		Reason:  reason,
	}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{rec}, ""); err != nil {
		if errors.Is(err, pfc2.ErrFence) {
			return nil // raced another terminal transition: already fenced
		}
		return mapManagedControlError(err)
	}
	return nil
}

// managedExpiredSessions is the DATABASE-time expiry sweep. The caller's
// clock only NOMINATES candidates (an early or skewed timer can only make
// this re-check early or late); each expiry decision is authorized by a fresh
// database admission fact whose exact time must have reached the durable
// deadline, and the conditional SessionTerminal row carries both. A renewal
// ordered first turns the row into a deterministic no-op and the session
// stays live.
func (fs *FS) managedExpiredSessions(now time.Time) []SessionInfo {
	hostNowMs := now.UnixMilli()
	var out []SessionInfo
	for _, live := range fs.managed.applied.LiveSessions() {
		if live.ExpiresDbMs > hostNowMs {
			continue // scheduling heuristic only; never an authorization
		}
		// Per-session lifecycle serialization (shared with open/renew/
		// terminal), then the fact-issuance section.
		lifecycle := &fs.renewLocks[sessionRenewShard(live.Ref.SessionID)]
		lifecycle.Lock()
		fs.managed.factMu.Lock()
		out = fs.managedExpireOne(live, out)
		fs.managed.factMu.Unlock()
		lifecycle.Unlock()
	}
	return out
}

// managedExpireOne re-checks and (when due) journals one conditional expiry
// under factMu.
func (fs *FS) managedExpireOne(live pfc2.SessionInfo, out []SessionInfo) []SessionInfo {
	issued, err := fs.IssueAdmissionFact(live.Ref, pfc2.FactPurposeSessionExpiry)
	if err != nil {
		return out // no fact, no authority to expire anything
	}
	due, err := pfc2.ExpiryDue(issued.Fact, live.ExpiresDbMs)
	if err != nil || !due {
		return out // database time says the lease has NOT elapsed
	}
	rec, err := pfc2.NewSessionExpiryRecord(live.Ref, live.ExpiresDbMs, issued.Fact)
	if err != nil {
		return out
	}
	results, err := fs.CommitEntry(nil, []pfc2.Record{*rec}, "")
	if err != nil || len(results) != 1 || results[0].NoOp {
		return out // raced a renewal (or a fence): nothing expired
	}
	return append(out, SessionInfo{
		SessionID: live.Ref.SessionID, Generation: live.Ref.Generation,
		Owner: live.Owner, Slots: live.Slots,
		Expired: true, Durable: true,
		ExpiresMs: live.ExpiresDbMs, DurableExpiresMs: live.ExpiresDbMs,
	})
}

// managedCheckSlot classifies an exact identity: the durable applied view
// answers replays (it holds the real recorded outcomes), and the reservation
// view must ALSO admit a fresh identity so an in-flight reservation is never
// double-admitted.
func (fs *FS) managedCheckSlot(env *wal.Envelope) (SlotCheckResult, SlotOutcome) {
	key, err := managedExactKey(env)
	if err != nil {
		return SlotUnknownSession, SlotOutcome{}
	}
	applied := fs.managed.applied.CheckExact(key)
	switch applied.Disposition {
	case pfc2.ExactAdmit:
		if reserved := fs.managed.reserved.CheckExact(key); reserved.Disposition != pfc2.ExactAdmit {
			// The identity is reserved but not yet applied. The protocol
			// layer serializes per (session, slot), so on a healthy authority
			// this is unreachable; fail closed as unknown rather than
			// double-admitting or guessing an outcome.
			return SlotUnknownSession, SlotOutcome{}
		}
		return SlotNew, SlotOutcome{}
	case pfc2.ExactReplay:
		// Durable replays deliberately return coherence version 0: the
		// mount re-stats under the current generation.
		return SlotDuplicate, SlotOutcome{
			Status: applied.Outcome.Status, Count: applied.Outcome.Count,
			Offset: applied.Outcome.Offset, Ino: applied.Outcome.Ino,
			OrphanIno: applied.Outcome.OrphanIno,
		}
	case pfc2.ExactRetired:
		return SlotRetired, SlotOutcome{}
	case pfc2.ExactConflict:
		return SlotConflict, SlotOutcome{}
	case pfc2.ExactSessionUnknown:
		return SlotUnknownSession, SlotOutcome{}
	default:
		return SlotGap, SlotOutcome{}
	}
}

// managedRecordStaticOutcome journals one definite pre-admission rejection as
// a PFC2 ExactOutcome row, so the slot sequence advances durably exactly as
// it would for an executed mutation.
func (fs *FS) managedRecordStaticOutcome(env *wal.Envelope, status int32) error {
	key, err := managedExactKey(env)
	if err != nil {
		return err
	}
	rec := pfc2.Record{Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
		Key: key, Outcome: pfc2.Outcome{Status: status},
	}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{rec}, ""); err != nil {
		return mapManagedControlError(err)
	}
	return nil
}

// managedMutateEnv commits one exact-once mutation as one managed journal row
// and returns its essential apply outcome (deterministic apply rejections are
// returned as the error with the outcome durably recorded, exactly like the
// legacy path).
func (fs *FS) managedMutateEnv(r wal.Record, owner string) (MutationResult, error) {
	out, err := fs.commitEntry(&r, nil, owner)
	if err != nil {
		return MutationResult{}, mapManagedControlError(err)
	}
	if len(out.tree) != 1 {
		return MutationResult{}, fmt.Errorf("workfs: managed mutation produced %d leaf outcomes", len(out.tree))
	}
	return out.tree[0].res, out.tree[0].err
}
