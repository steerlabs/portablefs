// Package volumeserver contains the disposable coordination state around one
// authoritative filesystem volume. It never stores filesystem contents or
// metadata. Restarting it creates a new epoch and intentionally invalidates all
// sessions, handles, locks, reply slots, and cache state.
package volumeserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrEpochMismatch          = errors.New("volumeserver: authority epoch changed")
	ErrSessionExpired         = errors.New("volumeserver: session expired")
	ErrSessionFenced          = errors.New("volumeserver: session fenced")
	ErrSequenceGap            = errors.New("volumeserver: mutation sequence gap")
	ErrRequestMismatch        = errors.New("volumeserver: operation identity reused with different request")
	ErrSlotRange              = errors.New("volumeserver: replay slot is outside the negotiated range")
	ErrAdmission              = errors.New("volumeserver: runtime admission bound reached")
	ErrAuthorizationSequence  = errors.New("volumeserver: authorization sequence is not the exact next value")
	ErrAuthorizationBroadened = errors.New("volumeserver: reauthorization attempted to broaden access")
	ErrAuthorizationOwner     = errors.New("volumeserver: reauthorization issuer does not own this session")
)

type Epoch [16]byte
type SessionID [16]byte
type ResumeSecret [32]byte
type RequestHash [32]byte
type PeerIdentity [32]byte
type Access uint8

const (
	AccessRead Access = 1 << iota
	AccessWrite
	// AccessAdmin authorizes volume-wide configuration, which is a different
	// thing from writing files and is granted separately. There was no such bit
	// before machine-local routing existed: the only volume-wide state was the
	// filesystem itself, so write access covered everything. It does not cover
	// this. .portablefs/local-dirs decides which subtrees a mount can see at
	// all, so a capability that lets an agent write files must not also let it
	// hide a directory tree from every other machine. Mount mutations under
	// .portablefs/ are refused outright for the same reason: the file is
	// reachable only through ApplyRoutes, which runs the change through the
	// visibility barrier instead of skewing one machine's topology silently.
	AccessAdmin
)

// Authorization is the complete, signed authorization installed when a
// session is attached or exactly reauthorized. Ordinary lease renewal never
// extends Deadline; only a new session-bound signed authorization can do so.
type Authorization struct {
	Access            Access
	Deadline          time.Time
	MountEnrollmentID string
}

type Config struct {
	// These are runtime admission policy, not filesystem-size or memory-budget
	// claims. They are explicitly sized for each worker deployment.
	SessionLease   time.Duration
	MaxReplaySlots uint32
	MaxSessions    uint32
	MaxLockRecords uint32
	// MaxLockRecordsPerSession bounds the held plus queued byte-range lock
	// records one session may occupy. Zero selects the equal-share value
	// MaxLockRecords/MaxSessions: the largest bound under which a session that
	// exhausts its budget provably cannot deny any other session the budget it
	// was admitted on. Raising it above the equal share deliberately
	// over-commits the table and gives up that guarantee.
	MaxLockRecordsPerSession uint32
	Now                      func() time.Time
}

// sessionCredentialGeneration identifies the authority-minted resume secret.
// Reauthorization rotates the signed access decision and optionally its TLS
// peer key, not this secret, so the wire credential generation remains one.
const sessionCredentialGeneration uint64 = 1

type SessionCredential struct {
	Epoch      Epoch
	ID         SessionID
	Generation uint64
	Secret     ResumeSecret
	// Peer is derived from the authenticated TLS certificate and is never read
	// from the request payload.
	Peer   PeerIdentity
	Access Access
}

type MutationID struct {
	Slot                uint32
	Sequence            uint64
	Hash                RequestHash
	FrontendOperationID uint64
	// SourcePhaseQueueable is a request-scoped frontend progress proof, not a
	// replay identity or capability. It permits this mutation to wait behind a
	// distinct own-source callback phase only when the frontend has promised
	// the callback is ordered-only and therefore excluded from PREPARE's drain.
	SourcePhaseQueueable bool
}

// Outcome is the exact wire-ready result retained for a duplicate request.
// Errno is a Linux errno number; Reply contains the operation-specific body.
type Outcome struct {
	Errno int32
	Reply []byte
}

type replaySlot struct {
	mu       sync.Mutex
	sequence uint64
	hash     RequestHash
	outcome  Outcome
	present  bool
}

type session struct {
	mu                    sync.Mutex
	id                    SessionID
	secret                ResumeSecret
	peer                  PeerIdentity
	access                Access
	leaseExpires          time.Time
	authorizationDeadline time.Time
	authorizationSequence uint64
	authorizationProof    [32]byte
	mountEnrollmentID     string
	// lockLease publishes leaseExpires to the lock table. It is written under
	// s.mu wherever leaseExpires is, so the table can never read a lease
	// boundary the authority has not granted.
	lockLease      *LockLease
	fenced         bool
	ending         bool
	active         uint64
	cleanupStarted bool
	terminal       chan struct{}
	slots          []replaySlot
}

// SessionUse pins runtime resources for one admitted operation. Ending a
// session fences new work immediately, while resource cleanup waits until all
// admitted operations release their pins.
type SessionUse struct {
	authority *Authority
	session   *session
	id        SessionID
	access    Access
	once      sync.Once
}

func (u *SessionUse) Access() Access {
	if u == nil {
		return 0
	}
	return u.access
}

func (u *SessionUse) End() {
	if u == nil {
		return
	}
	u.once.Do(func() {
		s := u.session
		s.mu.Lock()
		if s.active == 0 {
			s.mu.Unlock()
			panic("volumeserver: unbalanced session use")
		}
		s.active--
		cleanup := s.ending && s.active == 0 && !s.cleanupStarted
		if cleanup {
			s.cleanupStarted = true
		}
		s.mu.Unlock()
		if cleanup {
			u.authority.finishSession(u.id)
		}
	})
}

// Authority owns one epoch of runtime coordination for one volume.
type Authority struct {
	volumeID string
	epoch    Epoch
	cfg      Config

	mu           sync.Mutex
	sessions     map[SessionID]*session
	sessionCount uint32
	locks        *LockTable
	endHooks     []func(SessionID)
}

func New(volumeID string, cfg Config) (*Authority, error) {
	if volumeID == "" {
		return nil, errors.New("volumeserver: volume ID is required")
	}
	if cfg.SessionLease <= 0 || cfg.MaxReplaySlots == 0 || cfg.MaxSessions == 0 || cfg.MaxLockRecords == 0 {
		return nil, errors.New("volumeserver: lease and runtime admission bounds must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	perSession := cfg.MaxLockRecordsPerSession
	if perSession == 0 {
		if perSession = cfg.MaxLockRecords / cfg.MaxSessions; perSession == 0 {
			perSession = 1
		}
	}
	if perSession > cfg.MaxLockRecords {
		return nil, errors.New("volumeserver: per-session lock budget exceeds the lock table bound")
	}
	cfg.MaxLockRecordsPerSession = perSession
	a := &Authority{volumeID: volumeID, cfg: cfg, sessions: make(map[SessionID]*session), locks: NewLockTable(cfg.MaxLockRecords, perSession, cfg.Now)}
	if _, err := rand.Read(a.epoch[:]); err != nil {
		return nil, fmt.Errorf("generate authority epoch: %w", err)
	}
	return a, nil
}

func (a *Authority) Epoch() Epoch                { return a.epoch }
func (a *Authority) VolumeID() string            { return a.volumeID }
func (a *Authority) Locks() *LockTable           { return a.locks }
func (a *Authority) SessionLease() time.Duration { return a.cfg.SessionLease }

// ValidateAttachSlots checks the peer-controlled replay allocation without
// creating a session. Handlers use it before spending a single-use attach
// capability; Attach repeats the check so direct callers get the same bound.
func (a *Authority) ValidateAttachSlots(slots uint32) error {
	if slots == 0 || slots > a.cfg.MaxReplaySlots {
		return ErrSlotRange
	}
	return nil
}

// OnSessionEnd registers runtime-resource cleanup. Hooks must be fast enough
// for session sweeping and must not call back into this Authority. Durable
// filesystem state never belongs in a hook.
func (a *Authority) OnSessionEnd(hook func(SessionID)) {
	if hook == nil {
		return
	}
	a.mu.Lock()
	a.endHooks = append(a.endHooks, hook)
	a.mu.Unlock()
}

func (a *Authority) notifySessionEnd(id SessionID) {
	a.mu.Lock()
	hooks := append([]func(SessionID){}, a.endHooks...)
	a.mu.Unlock()
	for _, hook := range hooks {
		hook(id)
	}
}

func (a *Authority) Attach(slots uint32, peer PeerIdentity, authorization Authorization) (SessionCredential, error) {
	if err := a.ValidateAttachSlots(slots); err != nil {
		return SessionCredential{}, err
	}
	access := authorization.Access
	if access&AccessRead == 0 || access&^(AccessRead|AccessWrite|AccessAdmin) != 0 {
		return SessionCredential{}, ErrSessionFenced
	}
	now := a.cfg.Now()
	if authorization.Deadline.IsZero() || !now.Before(authorization.Deadline) {
		return SessionCredential{}, ErrSessionExpired
	}
	var id SessionID
	var secret ResumeSecret
	if _, err := rand.Read(id[:]); err != nil {
		return SessionCredential{}, err
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return SessionCredential{}, err
	}
	s := &session{
		id: id, secret: secret, peer: peer, access: access,
		leaseExpires:          minTime(now.Add(a.cfg.SessionLease), authorization.Deadline),
		authorizationDeadline: authorization.Deadline,
		slots:                 make([]replaySlot, slots),
		terminal:              make(chan struct{}),
		mountEnrollmentID:     authorization.MountEnrollmentID,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessionCount >= a.cfg.MaxSessions {
		return SessionCredential{}, ErrAdmission
	}
	if _, collision := a.sessions[id]; collision {
		return SessionCredential{}, errors.New("volumeserver: session ID collision")
	}
	a.sessions[id] = s
	a.sessionCount++
	// A session becomes able to hold locks at exactly the moment it becomes
	// live, and stops at exactly the moment it becomes terminal or its lease
	// runs out. Registration is the only way a record or waiter can ever exist.
	s.lockLease = a.locks.RegisterSession(id, s.leaseExpires)
	return SessionCredential{Epoch: a.epoch, ID: id, Generation: sessionCredentialGeneration, Secret: secret, Peer: peer, Access: access}, nil
}

// SessionTerminal closes at the exact fencing boundary, before deferred
// descriptor cleanup. Cache-coherence coordination uses it because a blocked
// operation must not keep an unclean mount looking live.
func (a *Authority) SessionTerminal(id SessionID) (<-chan struct{}, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[id]
	if s == nil {
		return nil, ErrSessionExpired
	}
	return s.terminal, nil
}

// FenceSession ends one session immediately and permanently. It is the action
// behind participant-scoped cache fencing: the authority stops recognising this
// mount, and the mount learns it has been fenced from its own session dying,
// which is what obliges it to revoke its kernel mount locally. It is idempotent,
// so the path that fences a session and the terminal-channel watcher that
// observes the result can both call it.
func (a *Authority) FenceSession(id SessionID) {
	a.mu.Lock()
	s := a.sessions[id]
	if s == nil {
		a.mu.Unlock()
		return
	}
	s.mu.Lock()
	s.fenced = true
	cleanup := a.endSessionLocked(id, s)
	s.mu.Unlock()
	a.mu.Unlock()
	if cleanup {
		a.finishSession(id)
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (a *Authority) begin(cred SessionCredential, renew bool) (*SessionUse, error) {
	if cred.Epoch != a.epoch {
		return nil, ErrEpochMismatch
	}
	a.mu.Lock()
	s := a.sessions[cred.ID]
	if s == nil {
		a.mu.Unlock()
		return nil, ErrSessionExpired
	}
	s.mu.Lock()
	if s.fenced || s.ending {
		cleanup := a.endSessionLocked(cred.ID, s)
		s.mu.Unlock()
		a.mu.Unlock()
		if cleanup {
			a.finishSession(cred.ID)
		}
		return nil, ErrSessionFenced
	}
	if cred.Generation != sessionCredentialGeneration || subtle.ConstantTimeCompare(s.secret[:], cred.Secret[:]) != 1 {
		s.fenced = true
		cleanup := a.endSessionLocked(cred.ID, s)
		s.mu.Unlock()
		a.mu.Unlock()
		if cleanup {
			a.finishSession(cred.ID)
		}
		return nil, ErrSessionFenced
	}
	if subtle.ConstantTimeCompare(s.peer[:], cred.Peer[:]) != 1 {
		s.fenced = true
		cleanup := a.endSessionLocked(cred.ID, s)
		s.mu.Unlock()
		a.mu.Unlock()
		if cleanup {
			a.finishSession(cred.ID)
		}
		return nil, ErrSessionFenced
	}
	now := a.cfg.Now()
	if !now.Before(s.leaseExpires) || !now.Before(s.authorizationDeadline) {
		s.fenced = true
		cleanup := a.endSessionLocked(cred.ID, s)
		s.mu.Unlock()
		a.mu.Unlock()
		if cleanup {
			a.finishSession(cred.ID)
		}
		return nil, ErrSessionExpired
	}
	if renew {
		s.leaseExpires = minTime(now.Add(a.cfg.SessionLease), s.authorizationDeadline)
		s.lockLease.Renew(s.leaseExpires)
	}
	s.active++
	use := &SessionUse{authority: a, session: s, id: cred.ID, access: s.access}
	s.mu.Unlock()
	a.mu.Unlock()
	return use, nil
}

// Begin authenticates, renews the renewable lease without extending the signed
// authorization deadline, and pins the session until SessionUse.End.
func (a *Authority) Begin(cred SessionCredential) (*SessionUse, error) {
	return a.begin(cred, true)
}

// endSessionLocked marks a session terminal and removes it from admission. The
// caller holds a.mu and s.mu. It reports whether cleanup can start immediately.
//
// Byte-range locks are surrendered here rather than in finishSession. A
// terminal session may still have admitted operations in flight — including a
// blocking F_SETLKW whose pin is precisely what keeps cleanup deferred — and
// those operations must not be able to acquire, hold, or be granted a lock
// under a session the authority has already given up on. Releasing at the
// instant the session becomes terminal makes the two facts, "the authority
// still recognises this session" and "this session may own locks", the same
// fact, and it unblocks the waiters whose pins would otherwise stall the drain
// forever.
//
// Lock order is a.mu -> s.mu -> LockTable.mu. The lock table is a leaf: it
// never calls back into the authority.
func (a *Authority) endSessionLocked(id SessionID, s *session) bool {
	if !s.ending {
		s.ending = true
		s.fenced = true
		close(s.terminal)
		if a.sessions[id] == s {
			delete(a.sessions, id)
		}
		a.locks.ReleaseSession(id)
	}
	if s.active == 0 && !s.cleanupStarted {
		s.cleanupStarted = true
		return true
	}
	return false
}

// finishSession runs once the last admitted operation of a terminal session has
// released its pin. Byte-range locks are already gone by then; what remains is
// the runtime resource cleanup that must outlive in-flight operations, such as
// the open file descriptions they are still reading and writing.
func (a *Authority) finishSession(id SessionID) {
	a.notifySessionEnd(id)
	a.mu.Lock()
	if a.sessionCount > 0 {
		a.sessionCount--
	}
	a.mu.Unlock()
}

func (a *Authority) Resume(cred SessionCredential) error {
	use, err := a.Begin(cred)
	if err != nil {
		return err
	}
	use.End()
	return nil
}

// Reauthorize installs the exact next signed authorization for a live session.
// It is idempotent for a lost response, cannot broaden access, and may replace
// the TLS peer identity only because the new grant was verified against that
// peer before this method is called.
func (a *Authority) Reauthorize(cred SessionCredential, authorization Authorization, sequence uint64, proof [32]byte) error {
	if cred.Epoch != a.epoch || sequence == 0 || proof == ([32]byte{}) {
		return ErrEpochMismatch
	}
	a.mu.Lock()
	s := a.sessions[cred.ID]
	if s == nil {
		a.mu.Unlock()
		return ErrSessionExpired
	}
	s.mu.Lock()
	fail := func(err error, fence bool) error {
		cleanup := false
		if fence {
			s.fenced = true
			cleanup = a.endSessionLocked(cred.ID, s)
		}
		s.mu.Unlock()
		a.mu.Unlock()
		if cleanup {
			a.finishSession(cred.ID)
		}
		return err
	}
	if s.fenced || s.ending {
		return fail(ErrSessionFenced, true)
	}
	if cred.Generation != sessionCredentialGeneration || subtle.ConstantTimeCompare(s.secret[:], cred.Secret[:]) != 1 {
		return fail(ErrSessionFenced, true)
	}
	if s.mountEnrollmentID != authorization.MountEnrollmentID {
		// A valid credential from the wrong issuer is not evidence that the live
		// mount itself is corrupt. Refuse it without killing the enrollment-owned
		// session; sequence and changed-replay violations from the actual owner
		// retain their fail-closed fencing semantics below.
		return fail(ErrAuthorizationOwner, false)
	}
	if sequence == s.authorizationSequence {
		if subtle.ConstantTimeCompare(s.authorizationProof[:], proof[:]) != 1 ||
			subtle.ConstantTimeCompare(s.peer[:], cred.Peer[:]) != 1 {
			return fail(ErrRequestMismatch, true)
		}
		s.mu.Unlock()
		a.mu.Unlock()
		return nil
	}
	if sequence != s.authorizationSequence+1 {
		return fail(ErrAuthorizationSequence, true)
	}
	if authorization.Access&AccessRead == 0 || authorization.Access&^(AccessRead|AccessWrite|AccessAdmin) != 0 {
		return fail(ErrSessionFenced, true)
	}
	if authorization.Access&^s.access != 0 {
		return fail(ErrAuthorizationBroadened, true)
	}
	now := a.cfg.Now()
	if authorization.Deadline.IsZero() || !now.Before(authorization.Deadline) {
		return fail(ErrSessionExpired, true)
	}
	s.peer = cred.Peer
	s.access = authorization.Access
	s.authorizationDeadline = authorization.Deadline
	s.authorizationSequence = sequence
	s.authorizationProof = proof
	s.leaseExpires = minTime(now.Add(a.cfg.SessionLease), authorization.Deadline)
	s.lockLease.Renew(s.leaseExpires)
	s.mu.Unlock()
	a.mu.Unlock()
	return nil
}

func (a *Authority) Access(cred SessionCredential) (Access, error) {
	use, err := a.Begin(cred)
	if err != nil {
		return 0, err
	}
	defer use.End()
	return use.Access(), nil
}

// ExecuteMutation provides at-most-once execution for duplicate delivery in
// the current epoch. apply must execute one already-authorized filesystem
// operation. Its result is copied before publication so callers cannot mutate
// a retained replay response.
func (a *Authority) ExecuteMutation(ctx context.Context, cred SessionCredential, id MutationID, apply func(context.Context) Outcome) (Outcome, error) {
	use, err := a.Begin(cred)
	if err != nil {
		return Outcome{}, err
	}
	defer use.End()
	s := use.session
	if id.Sequence == 0 || id.Slot >= uint32(len(s.slots)) {
		return Outcome{}, ErrSlotRange
	}
	slot := &s.slots[id.Slot]
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Outcome{}, err
	}

	s.mu.Lock()
	if s.fenced {
		s.mu.Unlock()
		a.endKnownSession(cred.ID, s)
		return Outcome{}, ErrSessionFenced
	}
	if slot.present && id.Sequence == slot.sequence {
		if slot.hash != id.Hash {
			s.fenced = true
			s.mu.Unlock()
			a.endKnownSession(cred.ID, s)
			return Outcome{}, ErrRequestMismatch
		}
		out := cloneOutcome(slot.outcome)
		s.mu.Unlock()
		return out, nil
	}
	next := uint64(1)
	if slot.present {
		next = slot.sequence + 1
	}
	if id.Sequence != next {
		s.fenced = true
		s.mu.Unlock()
		a.endKnownSession(cred.ID, s)
		return Outcome{}, ErrSequenceGap
	}
	s.mu.Unlock()

	out := cloneOutcome(apply(ctx))
	s.mu.Lock()
	// The operation already reached XFS. Record its outcome even if a different
	// slot fenced this session meanwhile; never make it eligible to re-execute.
	slot.sequence, slot.hash, slot.outcome, slot.present = id.Sequence, id.Hash, out, true
	s.mu.Unlock()
	return cloneOutcome(out), nil
}

func (a *Authority) endKnownSession(id SessionID, s *session) {
	a.mu.Lock()
	s.mu.Lock()
	cleanup := a.endSessionLocked(id, s)
	s.mu.Unlock()
	a.mu.Unlock()
	if cleanup {
		a.finishSession(id)
	}
}

func cloneOutcome(out Outcome) Outcome {
	out.Reply = append([]byte(nil), out.Reply...)
	return out
}

func (a *Authority) Detach(cred SessionCredential) error {
	use, err := a.begin(cred, false)
	if err != nil {
		return err
	}
	defer use.End()
	s := use.session
	a.mu.Lock()
	s.mu.Lock()
	if a.sessions[cred.ID] != s || s.ending {
		s.mu.Unlock()
		a.mu.Unlock()
		return ErrSessionExpired
	}
	_ = a.endSessionLocked(cred.ID, s)
	s.mu.Unlock()
	a.mu.Unlock()
	return nil
}

// Sweep removes sessions whose renewable lease is no longer live. The caller
// schedules it; tests can drive it with a deterministic clock.
func (a *Authority) Sweep() int {
	now := a.cfg.Now()
	a.mu.Lock()
	var cleanup []SessionID
	removed := 0
	for id, s := range a.sessions {
		s.mu.Lock()
		dead := s.fenced || s.ending || !now.Before(s.leaseExpires) || !now.Before(s.authorizationDeadline)
		if dead {
			removed++
			if a.endSessionLocked(id, s) {
				cleanup = append(cleanup, id)
			}
		}
		s.mu.Unlock()
	}
	a.mu.Unlock()
	for _, id := range cleanup {
		a.finishSession(id)
	}
	return removed
}
