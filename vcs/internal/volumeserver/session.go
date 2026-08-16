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
	"io"
	"sync"
	"time"

	"github.com/minio/highwayhash"
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
	ErrSessionProvisional     = errors.New("volumeserver: session is not active")
	ErrAttachAttemptMismatch  = errors.New("volumeserver: attach attempt was reused with a different request")
	ErrSessionActive          = errors.New("volumeserver: active session cannot be aborted")
)

type Epoch [16]byte
type SessionID [16]byte
type ResumeSecret [32]byte
type RequestFingerprint [32]byte
type AttachAttemptID [32]byte
type AttachRequestFingerprint [32]byte
type PeerIdentity [32]byte
type Access uint8

// SessionState is the externally observable lifecycle of an exact attach
// attempt. Provisional sessions have credentials so a client can prove receipt
// of PrepareAttach, but those credentials authorize only activation or abort.
// They cannot execute filesystem work or own locks. Terminal includes an
// active session that was detached, fenced, or expired; Aborted is reserved for
// a provisional attempt that was explicitly abandoned or timed out.
type SessionState uint8

const (
	SessionStateUnknown SessionState = iota
	SessionStateProvisional
	SessionStateActive
	SessionStateAborted
	SessionStateTerminal
)

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
	Slot                         uint32
	Sequence                     uint64
	Fingerprint                  RequestFingerprint
	FrontendOperationID          uint64
	VisibilityRetryAfterSequence uint64
}

// Outcome is the exact wire-ready result retained for a duplicate request.
// Errno is a Linux errno number; Reply contains the operation-specific body.
// TerminalDeliveryRequired records that this exact structured post-apply result
// caused a terminal drain and therefore every reconstructed delivery must be
// receipted after the frontend's publication boundary. It is replay metadata,
// not an authority wire field.
type Outcome struct {
	Errno                    int32
	Reply                    []byte
	TerminalDeliveryRequired bool
}

type replaySlot struct {
	mu          sync.Mutex
	sequence    uint64
	fingerprint RequestFingerprint
	outcome     Outcome
	present     bool
}

type session struct {
	mu                    sync.Mutex
	id                    SessionID
	attempt               AttachAttemptID
	secret                ResumeSecret
	peer                  PeerIdentity
	access                Access
	state                 SessionState
	provisionalDeadline   time.Time
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
	activation     *ActivationToken
}

// attachAttempt is the exact-once record for PrepareAttach. It is installed
// before authorization is invoked, after both the session and attempt bounds
// have been reserved. Exact concurrent duplicates wait on ready; a changed
// reuse is refused without invoking either authorization closure.
type attachAttempt struct {
	fingerprint AttachRequestFingerprint
	peer        PeerIdentity
	slots       uint32
	deadline    time.Time
	ready       chan struct{}
	credential  SessionCredential
	session     *session
	err         error
	complete    bool
	activated   bool
	cleaned     bool
}

// ActivationToken is an opaque, single transition reservation returned by
// PrepareActivation. While it is live, AbortProvisional and Sweep cannot race
// between durable visibility registration and the runtime commit. The caller
// must either CommitActivation or CancelActivation on every path.
type ActivationToken struct {
	authority *Authority
	session   *session
	attempt   AttachAttemptID
	done      chan struct{}
	replay    bool
	resolved  bool // guarded by Authority.mu -> session.mu
}

// Replay reports whether PrepareActivation observed an already-active exact
// attempt. A protocol handler uses this to return its retained ActivateReply;
// it must not recreate resources or rerun the visibility transaction.
func (t *ActivationToken) Replay() bool {
	return t != nil && t.replay
}

// ProvisionalDeadline is the absolute, nonrenewable time by which a prepared
// attach must commit. It is safe to put in AttachReply; reading it has no lease
// side effect and cannot extend it.
func (a *Authority) ProvisionalDeadline(cred SessionCredential, attemptID AttachAttemptID) (time.Time, error) {
	if cred.Epoch != a.epoch {
		return time.Time{}, ErrEpochMismatch
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	attempt := a.attempts[attemptID]
	if attempt == nil || !attempt.complete || attempt.session == nil || attempt.credential.ID != cred.ID {
		return time.Time{}, ErrSessionExpired
	}
	s := attempt.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if !credentialMatchesSession(s, cred) {
		return time.Time{}, ErrSessionFenced
	}
	return s.provisionalDeadline, nil
}

// AuthorizationDeadline returns the authoritative signed deadline installed
// by the one successful authorization of this exact attach attempt. It does
// not renew or otherwise mutate the session. In particular, an exact replay
// can initialize or verify handler resources from this value without relying
// on a local variable that only the first PrepareAttach caller observed.
func (a *Authority) AuthorizationDeadline(cred SessionCredential, attemptID AttachAttemptID) (time.Time, error) {
	if cred.Epoch != a.epoch {
		return time.Time{}, ErrEpochMismatch
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	attempt := a.attempts[attemptID]
	if attempt == nil || !attempt.complete || attempt.session == nil || attempt.credential.ID != cred.ID {
		return time.Time{}, ErrSessionExpired
	}
	s := attempt.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if !credentialMatchesSession(s, cred) {
		return time.Time{}, ErrSessionFenced
	}
	return s.authorizationDeadline, nil
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
	volumeID             string
	epoch                Epoch
	replayFingerprintKey [32]byte
	cfg                  Config

	mu           sync.Mutex
	sessions     map[SessionID]*session
	attempts     map[AttachAttemptID]*attachAttempt
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
	a := &Authority{
		volumeID: volumeID, cfg: cfg,
		sessions: make(map[SessionID]*session), attempts: make(map[AttachAttemptID]*attachAttempt),
		locks: NewLockTable(cfg.MaxLockRecords, perSession, cfg.Now),
	}
	if _, err := rand.Read(a.epoch[:]); err != nil {
		return nil, fmt.Errorf("generate authority epoch: %w", err)
	}
	if _, err := rand.Read(a.replayFingerprintKey[:]); err != nil {
		return nil, fmt.Errorf("generate replay fingerprint key: %w", err)
	}
	return a, nil
}

func (a *Authority) Epoch() Epoch                { return a.epoch }
func (a *Authority) VolumeID() string            { return a.volumeID }
func (a *Authority) Locks() *LockTable           { return a.locks }
func (a *Authority) SessionLease() time.Duration { return a.cfg.SessionLease }

// ReplayFingerprint authenticates one canonical mutation body with a secret
// that exists only for this authority epoch. Replay slots and sessions are
// discarded whenever the epoch changes, so publishing a content digest on the
// wire only made every client hash large writes before sending them. Keeping
// the 256-bit PRF key here preserves altered-replay detection while removing
// that duplicate client-side payload pass. The fingerprint is never returned
// to a peer and has no meaning outside this Authority.
func (a *Authority) ReplayFingerprint(writeCanonical func(io.Writer) error) (RequestFingerprint, error) {
	if writeCanonical == nil {
		return RequestFingerprint{}, errors.New("volumeserver: canonical replay writer is required")
	}
	digest, err := highwayhash.New(a.replayFingerprintKey[:])
	if err != nil {
		return RequestFingerprint{}, fmt.Errorf("construct replay fingerprint: %w", err)
	}
	if err := writeCanonical(digest); err != nil {
		return RequestFingerprint{}, err
	}
	var fingerprint RequestFingerprint
	digest.Sum(fingerprint[:0])
	return fingerprint, nil
}

// ValidateAttachSlots checks the peer-controlled replay allocation without
// creating a session. Handlers use it before spending a single-use attach
// capability; PrepareAttach repeats the check before reserving admission.
func (a *Authority) ValidateAttachSlots(slots uint32) error {
	if slots == 0 || slots > a.cfg.MaxReplaySlots {
		return ErrSlotRange
	}
	return nil
}

func validAuthorization(now time.Time, authorization Authorization) error {
	if authorization.Access&AccessRead == 0 || authorization.Access&^(AccessRead|AccessWrite|AccessAdmin) != 0 {
		return ErrSessionFenced
	}
	if authorization.Deadline.IsZero() || !now.Before(authorization.Deadline) {
		return ErrSessionExpired
	}
	return nil
}

func (a *Authority) purgeAttachAttemptsLocked(now time.Time) {
	for id, attempt := range a.attempts {
		if !attempt.complete || now.Before(attempt.deadline) {
			continue
		}
		if attempt.session == nil {
			delete(a.attempts, id)
			continue
		}
		attempt.session.mu.Lock()
		terminal := attempt.session.state == SessionStateAborted || attempt.session.state == SessionStateTerminal
		attempt.session.mu.Unlock()
		if terminal {
			delete(a.attempts, id)
		}
	}
}

// PrepareAttach creates one non-executable session for an exact protocol-5
// attach attempt. Admission is reserved before authorize is called, so a full
// authority neither spends a single-use capability nor starts unbounded work.
// The attempt record is installed before the call and retained through its
// absolute deadline: exact concurrent/retried requests receive one result,
// while reusing the ID with any different peer, slot count, or canonical
// fingerprint is refused without invoking authorize.
func (a *Authority) PrepareAttach(
	ctx context.Context,
	attemptID AttachAttemptID,
	fingerprint AttachRequestFingerprint,
	slots uint32,
	peer PeerIdentity,
	authorize func(context.Context) (Authorization, error),
) (SessionCredential, error) {
	if ctx == nil || authorize == nil || attemptID == (AttachAttemptID{}) || fingerprint == (AttachRequestFingerprint{}) {
		return SessionCredential{}, ErrRequestMismatch
	}
	if err := a.ValidateAttachSlots(slots); err != nil {
		return SessionCredential{}, err
	}
	now := a.cfg.Now()
	a.mu.Lock()
	a.purgeAttachAttemptsLocked(now)
	if existing := a.attempts[attemptID]; existing != nil {
		if existing.fingerprint != fingerprint || existing.peer != peer || existing.slots != slots {
			a.mu.Unlock()
			return SessionCredential{}, ErrAttachAttemptMismatch
		}
		ready := existing.ready
		a.mu.Unlock()
		select {
		case <-ready:
			return a.preparedAttachResult(attemptID)
		case <-ctx.Done():
			return SessionCredential{}, ctx.Err()
		}
	}
	// MaxSessions bounds both allocated runtime sessions and exact-attempt
	// records. A failed/aborted attempt remains a tombstone only until its
	// absolute provisional deadline, so neither collection is unbounded.
	if a.sessionCount >= a.cfg.MaxSessions || uint32(len(a.attempts)) >= a.cfg.MaxSessions {
		a.mu.Unlock()
		return SessionCredential{}, ErrAdmission
	}
	admissionDeadline := now.Add(a.cfg.SessionLease)
	attempt := &attachAttempt{
		fingerprint: fingerprint, peer: peer, slots: slots,
		deadline: admissionDeadline, ready: make(chan struct{}),
	}
	a.attempts[attemptID] = attempt
	a.sessionCount++ // reserves capacity across the authorization closure
	a.mu.Unlock()

	authorization, err := authorize(ctx)
	if err == nil {
		err = validAuthorization(a.cfg.Now(), authorization)
	}
	if err != nil {
		a.finishPreparedAttach(attemptID, attempt, admissionDeadline, SessionCredential{}, nil, err)
		return SessionCredential{}, err
	}
	provisionalDeadline := minTime(admissionDeadline, authorization.Deadline)
	if !a.cfg.Now().Before(provisionalDeadline) {
		err = ErrSessionExpired
		a.finishPreparedAttach(attemptID, attempt, provisionalDeadline, SessionCredential{}, nil, err)
		return SessionCredential{}, err
	}

	var id SessionID
	var secret ResumeSecret
	if _, err = rand.Read(id[:]); err == nil {
		_, err = rand.Read(secret[:])
	}
	if err != nil {
		a.finishPreparedAttach(attemptID, attempt, provisionalDeadline, SessionCredential{}, nil, err)
		return SessionCredential{}, err
	}
	s := &session{
		id: id, attempt: attemptID, secret: secret, peer: peer, access: authorization.Access,
		state: SessionStateProvisional, provisionalDeadline: provisionalDeadline,
		leaseExpires: provisionalDeadline, authorizationDeadline: authorization.Deadline,
		slots: make([]replaySlot, slots), terminal: make(chan struct{}),
		mountEnrollmentID: authorization.MountEnrollmentID,
	}
	cred := SessionCredential{
		Epoch: a.epoch, ID: id, Generation: sessionCredentialGeneration,
		Secret: secret, Peer: peer, Access: authorization.Access,
	}
	a.mu.Lock()
	if _, collision := a.sessions[id]; collision {
		a.mu.Unlock()
		err = errors.New("volumeserver: session ID collision")
		a.finishPreparedAttach(attemptID, attempt, provisionalDeadline, SessionCredential{}, nil, err)
		return SessionCredential{}, err
	}
	a.sessions[id] = s
	attempt.deadline = provisionalDeadline
	attempt.credential, attempt.session, attempt.complete = cred, s, true
	close(attempt.ready)
	a.mu.Unlock()
	return cred, nil
}

func (a *Authority) finishPreparedAttach(attemptID AttachAttemptID, attempt *attachAttempt, deadline time.Time, cred SessionCredential, s *session, err error) {
	a.mu.Lock()
	if a.attempts[attemptID] == attempt && !attempt.complete {
		attempt.deadline = deadline
		attempt.credential, attempt.session, attempt.err, attempt.complete = cred, s, err, true
		if a.sessionCount > 0 {
			a.sessionCount--
		}
		close(attempt.ready)
	}
	a.mu.Unlock()
}

func (a *Authority) preparedAttachResult(attemptID AttachAttemptID) (SessionCredential, error) {
	now := a.cfg.Now()
	a.mu.Lock()
	attempt := a.attempts[attemptID]
	if attempt == nil || !attempt.complete {
		a.mu.Unlock()
		return SessionCredential{}, ErrSessionExpired
	}
	if attempt.err != nil {
		err := attempt.err
		a.mu.Unlock()
		return SessionCredential{}, err
	}
	s := attempt.session
	s.mu.Lock()
	cleanup := false
	if s.state == SessionStateProvisional && s.activation == nil && !now.Before(s.provisionalDeadline) {
		s.state = SessionStateAborted
		cleanup = a.endSessionLocked(s.id, s)
	}
	state := s.state
	cred := attempt.credential
	s.mu.Unlock()
	a.mu.Unlock()
	if cleanup {
		a.finishSession(s.id)
	}
	switch state {
	case SessionStateProvisional, SessionStateActive:
		return cred, nil
	case SessionStateAborted:
		return SessionCredential{}, ErrSessionExpired
	default:
		return SessionCredential{}, ErrSessionFenced
	}
}

func credentialMatchesSession(s *session, cred SessionCredential) bool {
	return cred.Generation == sessionCredentialGeneration &&
		subtle.ConstantTimeCompare(s.secret[:], cred.Secret[:]) == 1 &&
		subtle.ConstantTimeCompare(s.peer[:], cred.Peer[:]) == 1
}

// PrepareActivation authenticates proof that the peer received the provisional
// AttachReply and reserves the only PROVISIONAL -> ACTIVE transition. The
// reservation closes the abort/sweep race while durable visibility membership
// is written. An exact replay after commit succeeds with a no-op token.
func (a *Authority) PrepareActivation(ctx context.Context, cred SessionCredential, attemptID AttachAttemptID) (*ActivationToken, error) {
	if ctx == nil || cred.Epoch != a.epoch || attemptID == (AttachAttemptID{}) {
		return nil, ErrEpochMismatch
	}
	for {
		a.mu.Lock()
		attempt := a.attempts[attemptID]
		if attempt == nil || !attempt.complete || attempt.session == nil || attempt.credential.ID != cred.ID {
			a.mu.Unlock()
			return nil, ErrSessionExpired
		}
		s := attempt.session
		s.mu.Lock()
		if !credentialMatchesSession(s, cred) {
			s.fenced = true
			cleanup := a.endSessionLocked(s.id, s)
			s.mu.Unlock()
			a.mu.Unlock()
			if cleanup {
				a.finishSession(s.id)
			}
			return nil, ErrSessionFenced
		}
		switch s.state {
		case SessionStateActive:
			now := a.cfg.Now()
			if !now.Before(s.leaseExpires) || !now.Before(s.authorizationDeadline) {
				cleanup := a.endSessionLocked(s.id, s)
				s.mu.Unlock()
				a.mu.Unlock()
				if cleanup {
					a.finishSession(s.id)
				}
				return nil, ErrSessionExpired
			}
			token := &ActivationToken{
				authority: a, session: s, attempt: attemptID,
				done: make(chan struct{}), replay: true, resolved: true,
			}
			close(token.done)
			s.mu.Unlock()
			a.mu.Unlock()
			return token, nil
		case SessionStateAborted:
			s.mu.Unlock()
			a.mu.Unlock()
			return nil, ErrSessionExpired
		case SessionStateTerminal:
			s.mu.Unlock()
			a.mu.Unlock()
			return nil, ErrSessionFenced
		case SessionStateProvisional:
		default:
			s.mu.Unlock()
			a.mu.Unlock()
			return nil, ErrSessionFenced
		}
		if s.activation != nil {
			done := s.activation.done
			s.mu.Unlock()
			a.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		now := a.cfg.Now()
		if !now.Before(s.provisionalDeadline) || !now.Before(s.authorizationDeadline) {
			s.state = SessionStateAborted
			cleanup := a.endSessionLocked(s.id, s)
			s.mu.Unlock()
			a.mu.Unlock()
			if cleanup {
				a.finishSession(s.id)
			}
			return nil, ErrSessionExpired
		}
		token := &ActivationToken{authority: a, session: s, attempt: attemptID, done: make(chan struct{})}
		s.activation = token
		s.mu.Unlock()
		a.mu.Unlock()
		return token, nil
	}
}

// CommitActivation is infallible for a live token. PrepareActivation performed
// every check that may refuse, and the token excludes abort and sweep until
// this transition publishes the active lock lease. A panic therefore denotes
// an internal transaction bug, not a peer-controlled error.
func (a *Authority) CommitActivation(token *ActivationToken) {
	if token == nil || token.authority != a {
		panic("volumeserver: invalid activation token")
	}
	if token.replay {
		return
	}
	a.mu.Lock()
	s := token.session
	s.mu.Lock()
	if token.resolved || s.activation != token || s.state != SessionStateProvisional || a.sessions[s.id] != s {
		s.mu.Unlock()
		a.mu.Unlock()
		panic("volumeserver: activation token is not live")
	}
	now := a.cfg.Now()
	s.state = SessionStateActive
	s.leaseExpires = minTime(now.Add(a.cfg.SessionLease), s.authorizationDeadline)
	s.lockLease = a.locks.RegisterSession(s.id, s.leaseExpires)
	s.activation = nil
	token.resolved = true
	if attempt := a.attempts[token.attempt]; attempt != nil && attempt.session == s {
		attempt.activated = true
	}
	close(token.done)
	cleanup := false
	if s.fenced {
		// A fence requested while the durable activation transaction was in
		// flight could not safely tear down its provisional half. Publish the
		// commit point first, then make that fence terminal under the same locks.
		cleanup = a.endSessionLocked(s.id, s)
	}
	s.mu.Unlock()
	a.mu.Unlock()
	if cleanup {
		a.finishSession(s.id)
	}
}

// CancelActivation releases a prepared transition after a precommit failure.
// It leaves the session provisional and is idempotent for the caller's cleanup
// path. A committed or replay token is deliberately not rolled back.
func (a *Authority) CancelActivation(token *ActivationToken) {
	if token == nil || token.authority != a || token.replay {
		return
	}
	a.mu.Lock()
	s := token.session
	s.mu.Lock()
	cleanup := false
	if !token.resolved && s.activation == token && s.state == SessionStateProvisional {
		s.activation = nil
		token.resolved = true
		close(token.done)
		if s.fenced {
			cleanup = a.endSessionLocked(s.id, s)
		}
	}
	s.mu.Unlock()
	a.mu.Unlock()
	if cleanup {
		a.finishSession(s.id)
	}
}

// AbortProvisional abandons an exact attempt that never crossed activation's
// commit point. It is idempotent for an already-aborted attempt. If activation
// currently owns the transition, Abort waits for that transaction's definite
// commit/cancel verdict instead of racing through its durable membership write.
func (a *Authority) AbortProvisional(ctx context.Context, cred SessionCredential, attemptID AttachAttemptID) error {
	if ctx == nil || cred.Epoch != a.epoch || attemptID == (AttachAttemptID{}) {
		return ErrEpochMismatch
	}
	for {
		a.mu.Lock()
		attempt := a.attempts[attemptID]
		if attempt == nil || !attempt.complete || attempt.session == nil || attempt.credential.ID != cred.ID {
			a.mu.Unlock()
			return ErrSessionExpired
		}
		s := attempt.session
		s.mu.Lock()
		if !credentialMatchesSession(s, cred) {
			s.fenced = true
			cleanup := a.endSessionLocked(s.id, s)
			s.mu.Unlock()
			a.mu.Unlock()
			if cleanup {
				a.finishSession(s.id)
			}
			return ErrSessionFenced
		}
		if attempt.activated || s.state == SessionStateActive {
			s.mu.Unlock()
			a.mu.Unlock()
			return ErrSessionActive
		}
		if s.state == SessionStateAborted {
			s.mu.Unlock()
			a.mu.Unlock()
			return nil
		}
		if s.state == SessionStateTerminal {
			s.mu.Unlock()
			a.mu.Unlock()
			return ErrSessionFenced
		}
		if s.activation != nil {
			done := s.activation.done
			s.mu.Unlock()
			a.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		s.state = SessionStateAborted
		cleanup := a.endSessionLocked(s.id, s)
		s.mu.Unlock()
		a.mu.Unlock()
		if cleanup {
			a.finishSession(s.id)
		}
		return nil
	}
}

// SessionState reports the lifecycle of the exact credential/attempt pair.
// It never renews a lease and never turns a tombstone back into a session.
func (a *Authority) SessionState(cred SessionCredential, attemptID AttachAttemptID) (SessionState, error) {
	if cred.Epoch != a.epoch {
		return SessionStateUnknown, ErrEpochMismatch
	}
	a.mu.Lock()
	attempt := a.attempts[attemptID]
	if attempt == nil || !attempt.complete || attempt.session == nil || attempt.credential.ID != cred.ID {
		a.mu.Unlock()
		return SessionStateUnknown, ErrSessionExpired
	}
	s := attempt.session
	s.mu.Lock()
	defer s.mu.Unlock()
	defer a.mu.Unlock()
	if !credentialMatchesSession(s, cred) {
		return SessionStateUnknown, ErrSessionFenced
	}
	return s.state, nil
}

// SessionStateByID is the trusted, process-local transport reconciliation
// query. It neither authenticates a peer nor renews a lease: callers must never
// expose it as a protocol operation. A live provisional or active session is
// returned exactly; a completed attempt whose session already left the live
// map returns its retained ABORTED/TERMINAL state while that attempt tombstone
// is still required. Unknown IDs and terminal attempts whose bounded tombstone
// has expired are absent; transport reconciliation treats both as non-live.
//
// This closes the end-before-transport-bind edge: after publishing a registry
// binding, the server rechecks this runtime fact before exposing either lane.
func (a *Authority) SessionStateByID(id SessionID) (SessionState, bool) {
	if id == (SessionID{}) {
		return SessionStateUnknown, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s := a.sessions[id]; s != nil {
		s.mu.Lock()
		state := s.state
		s.mu.Unlock()
		return state, true
	}
	for _, attempt := range a.attempts {
		if attempt.complete && attempt.session != nil && attempt.session.id == id {
			attempt.session.mu.Lock()
			state := attempt.session.state
			attempt.session.mu.Unlock()
			return state, true
		}
	}
	return SessionStateUnknown, false
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

// AttachActiveForTest creates an immediately active session solely for direct
// tests of post-activation runtime behavior. Its explicit name prevents a
// production handler from accidentally bypassing protocol 5's provisional
// receipt proof and visibility-transactional activation boundary.
func (a *Authority) AttachActiveForTest(slots uint32, peer PeerIdentity, authorization Authorization) (SessionCredential, error) {
	if err := a.ValidateAttachSlots(slots); err != nil {
		return SessionCredential{}, err
	}
	now := a.cfg.Now()
	if err := validAuthorization(now, authorization); err != nil {
		return SessionCredential{}, err
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
		id: id, secret: secret, peer: peer, access: authorization.Access, state: SessionStateActive,
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
	return SessionCredential{Epoch: a.epoch, ID: id, Generation: sessionCredentialGeneration, Secret: secret, Peer: peer, Access: authorization.Access}, nil
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
	for {
		a.mu.Lock()
		s := a.sessions[id]
		if s == nil {
			a.mu.Unlock()
			return
		}
		s.mu.Lock()
		s.fenced = true
		if s.activation != nil {
			done := s.activation.done
			_ = a.endSessionLocked(id, s) // records the deferred fence
			s.mu.Unlock()
			a.mu.Unlock()
			<-done
			continue
		}
		cleanup := a.endSessionLocked(id, s)
		s.mu.Unlock()
		a.mu.Unlock()
		if cleanup {
			a.finishSession(id)
		}
		return
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
	if s.state == SessionStateProvisional {
		if s.activation == nil && (!now.Before(s.provisionalDeadline) || !now.Before(s.authorizationDeadline)) {
			s.state = SessionStateAborted
			cleanup := a.endSessionLocked(cred.ID, s)
			s.mu.Unlock()
			a.mu.Unlock()
			if cleanup {
				a.finishSession(cred.ID)
			}
			return nil, ErrSessionExpired
		}
		s.mu.Unlock()
		a.mu.Unlock()
		return nil, ErrSessionProvisional
	}
	if s.state != SessionStateActive {
		cleanup := a.endSessionLocked(cred.ID, s)
		s.mu.Unlock()
		a.mu.Unlock()
		if cleanup {
			a.finishSession(cred.ID)
		}
		return nil, ErrSessionFenced
	}
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
		if s.lockLease == nil {
			s.mu.Unlock()
			a.mu.Unlock()
			panic("volumeserver: active session has no lock lease")
		}
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
	if s.activation != nil {
		// The token may already sit behind a durable membership write. Ending
		// only the runtime half would make CommitActivation fallible and strand
		// that record. Remember the fence; CommitActivation or CancelActivation
		// applies it immediately after resolving the indivisible transition.
		s.fenced = true
		return false
	}
	if !s.ending {
		s.ending = true
		s.fenced = true
		if s.state != SessionStateAborted {
			s.state = SessionStateTerminal
		}
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
	decrement := true
	for _, attempt := range a.attempts {
		if attempt.session != nil && attempt.session.id == id {
			if attempt.cleaned {
				decrement = false
			} else {
				attempt.cleaned = true
			}
			break
		}
	}
	if decrement && a.sessionCount > 0 {
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
	if s.state == SessionStateProvisional {
		return fail(ErrSessionProvisional, false)
	}
	if s.state != SessionStateActive {
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
	return a.ExecuteMutationAdmitted(ctx, cred, id, nil, apply)
}

// ExecuteMutationAdmitted is ExecuteMutation with one pre-apply admission
// decision. admit runs only for the exact next sequence, while that replay
// slot's mutex is held, after duplicate/mismatch/gap validation and before
// apply. An admission refusal neither advances nor fences the slot. Serializing
// admission with execution is required when capacity depends on the outcome
// already retained by this slot: two pipelined sequences must not both price
// themselves against the same old outcome.
func (a *Authority) ExecuteMutationAdmitted(ctx context.Context, cred SessionCredential, id MutationID, admit func() error, apply func(context.Context) Outcome) (Outcome, error) {
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
		if subtle.ConstantTimeCompare(slot.fingerprint[:], id.Fingerprint[:]) != 1 {
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

	if admit != nil {
		if err := admit(); err != nil {
			return Outcome{}, err
		}
	}
	out := cloneOutcome(apply(ctx))
	s.mu.Lock()
	// The operation already reached XFS. Record its outcome even if a different
	// slot fenced this session meanwhile; never make it eligible to re-execute.
	slot.sequence, slot.fingerprint, slot.outcome, slot.present = id.Sequence, id.Fingerprint, out, true
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
		dead := s.fenced || s.ending
		if s.state == SessionStateProvisional {
			// PrepareActivation owns the transition until CommitActivation or
			// CancelActivation. It was admitted before the absolute deadline and
			// must not be cut between durable membership and runtime publication.
			// A concurrent fence is remembered by endSessionLocked and applied by
			// whichever resolution owns the token.
			expired := s.activation == nil &&
				(!now.Before(s.provisionalDeadline) || !now.Before(s.authorizationDeadline))
			dead = dead || expired
			if expired && !s.fenced && !s.ending {
				s.state = SessionStateAborted
			}
		} else if s.state == SessionStateActive {
			dead = dead || !now.Before(s.leaseExpires) || !now.Before(s.authorizationDeadline)
		} else {
			dead = true
		}
		if dead {
			cleanupNow := a.endSessionLocked(id, s)
			if s.ending {
				removed++
			}
			if cleanupNow {
				cleanup = append(cleanup, id)
			}
		}
		s.mu.Unlock()
	}
	a.purgeAttachAttemptsLocked(now)
	a.mu.Unlock()
	for _, id := range cleanup {
		a.finishSession(id)
	}
	return removed
}
