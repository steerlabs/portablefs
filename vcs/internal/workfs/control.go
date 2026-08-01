package workfs

// The session-store surface the fsproto server drives (exact mount sessions:
// identity, generation, token proof, slot budget, lease) — implemented over
// journaled PFC2 controls (managed_control.go). Every durable transition is
// one fenced journal row in the SAME total order as tree mutations, so a
// restart or failover reconstructs exactly-once state from replay alone:
// there is no reclaim grace, no wall-time pruning, and no separate control
// record stream.
//
// The raw WAL-backed FS (New — the bench/torture/test data plane) carries no
// session store at all: every API here fails closed with ErrNotManaged.

import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// sessionRenewShards bounds the per-session lifecycle serialization locks.
const sessionRenewShards = 64

// sessionLeaseTTL is the authority-side lifetime of a protocol session
// without renewal, in nanoseconds. Atomic because tests shorten it around
// live servers whose sweepers and session handlers sample it concurrently.
var sessionLeaseTTL atomic.Int64

func init() { sessionLeaseTTL.Store(int64(90 * time.Second)) }

// SessionLeaseTTL returns the session lease lifetime: locks, delegations,
// and open state owned by a session are released ONLY on explicit expire or
// on this lease elapsing — never on a socket flap.
func SessionLeaseTTL() time.Duration { return time.Duration(sessionLeaseTTL.Load()) }

// SetSessionLeaseTTL adjusts the lease lifetime (tests; production keeps the
// default).
func SetSessionLeaseTTL(d time.Duration) { sessionLeaseTTL.Store(int64(d)) }

var (
	ErrSessionStale    = errors.New("vcs: session generation is stale or expired")
	ErrSessionConflict = errors.New("vcs: session generation tuple conflicts")
	ErrControlCapacity = errors.New("vcs: replicated control-state capacity exhausted")
)

// ErrDurabilityUnknown wraps a commit failure whose outcome is ambiguous: the
// record was appended (and may be durably prepared) but the durability barrier
// failed. The node is fencing; the protocol layer MUST NOT answer with a
// definite errno — it drops the connection and the client replays the
// identical identity against a surviving authority.
var ErrDurabilityUnknown = errors.New("vcs: mutation durability unknown (durability barrier failed; node fencing)")

// Session input bounds, enforced at establishment.
const (
	MaxSessionSlots      = 4096
	MaxSessionIDBytes    = 128
	MaxSessionOwnerBytes = 256
	MaxSessionTokenBytes = 256
)

func sessionRenewShard(id string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= 16777619
	}
	return h % sessionRenewShards
}

// ---- protocol session registry (fsproto server API) ----

// SessionInfo is the authority's view of one protocol session. ExpiresMs is
// the exact database lease deadline.
type SessionInfo struct {
	SessionID  string
	Generation uint64
	Owner      string
	Slots      uint32
	Expired    bool
	ExpiresMs  int64
	// DurableExpiresMs is the durably recorded expiry a replacement authority
	// will recover; Durable reports whether the latest generation transition
	// has crossed its durability boundary.
	DurableExpiresMs int64
	Durable          bool
}

func validateSessionInput(sessionID, owner string, slots uint32, token string) error {
	if sessionID == "" || len(sessionID) > MaxSessionIDBytes {
		return fmt.Errorf("vcs: invalid session id")
	}
	if len(owner) > MaxSessionOwnerBytes {
		return fmt.Errorf("vcs: session owner exceeds %d bytes", MaxSessionOwnerBytes)
	}
	if slots == 0 || slots > MaxSessionSlots {
		return fmt.Errorf("vcs: session slots must be in [1,%d]", MaxSessionSlots)
	}
	if token == "" || len(token) > MaxSessionTokenBytes {
		return fmt.Errorf("vcs: session token must be in [1,%d] bytes", MaxSessionTokenBytes)
	}
	return nil
}

// EstablishSession registers (or re-establishes) a protocol session identity
// under a durable journal row and returns the opaque session token the client
// must present on reconnect. Establishing a HIGHER generation of the same
// session id tombstones every lower generation (stale-generation requests
// reject). Re-establishing the SAME generation requires the exact token
// (reconnect); a mismatch fails.
func (fs *FS) EstablishSession(sessionID string, generation uint64, owner string, slots uint32) (token string, err error) {
	var raw [24]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return "", err
	}
	token = "pfsess_" + hex.EncodeToString(raw[:])
	if err := fs.EstablishSessionWithToken(sessionID, generation, owner, slots, token); err != nil {
		return "", err
	}
	return token, nil
}

// EstablishSessionWithToken binds a client-minted credential to a session
// generation under one durable journal row. The exact (id, generation, owner,
// slots, token-hash) tuple is idempotent, making a lost establish reply
// safely replayable. A same-generation tuple mismatch is a conflict; a higher
// generation supersedes (tombstoning every lower one); a lower generation is
// stale.
func (fs *FS) EstablishSessionWithToken(sessionID string, generation uint64, owner string, slots uint32, token string) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	if generation == 0 {
		return fmt.Errorf("vcs: session generation must be nonzero")
	}
	return fs.managedEstablishSession(sessionID, generation, owner, slots, token)
}

// ResumeSession authenticates a reconnect: the presented token must hash to
// the session's recorded credential and the generation must be current. It
// durably renews the lease and returns the session's info.
func (fs *FS) ResumeSession(sessionID string, generation uint64, token string) (SessionInfo, error) {
	if fs.managed == nil {
		return SessionInfo{}, ErrNotManaged
	}
	return fs.managedResumeSession(sessionID, generation, token)
}

// AuthenticateSession verifies a presented token against a live session and
// returns its info without renewing. Used per-connection attach.
func (fs *FS) AuthenticateSession(sessionID string, token string) (SessionInfo, error) {
	if fs.managed == nil {
		return SessionInfo{}, ErrNotManaged
	}
	return fs.managedAuthenticateSession(sessionID, token)
}

// CurrentSession returns the latest view of one session (including expired
// tombstones).
func (fs *FS) CurrentSession(sessionID string) (SessionInfo, bool) {
	if fs.managed == nil {
		return SessionInfo{}, false
	}
	return fs.managedSessionInfo(sessionID)
}

// ExpireSession durably fences a session generation (voluntary close): the
// terminal transition releases the generation's locks, checkouts, pins, and
// flush privileges in the same journal row. Idempotent: fencing an
// already-expired or superseded generation is a no-op.
func (fs *FS) ExpireSession(sessionID string, generation uint64) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	return fs.managedTerminalSession(sessionID, generation, pfc2.TerminalClose)
}

// FenceSession durably fences the named generation. It is the run-attempt
// lifecycle hook: no coordinator is required because the fence shares the
// reservation order with exact mutations and higher-generation establishment.
func (fs *FS) FenceSession(sessionID string, generation uint64) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	return fs.managedTerminalSession(sessionID, generation, pfc2.TerminalAdminFence)
}

// FenceSessionCorrupt durably fences a generation whose client PROVED state
// corruption: a changed request digest at an occupied exact identity, or a
// slot-sequence gap. Same durable transition as ExpireSession with the
// distinct durable terminal reason; the protocol layer decides when
// corruption was proven.
func (fs *FS) FenceSessionCorrupt(sessionID string, generation uint64) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	return fs.managedTerminalSession(sessionID, generation, pfc2.TerminalSlotCorruption)
}

// Managed reports whether this store journals through a PFJ3/PFC2 journal
// generation (journaled coordination, exact sessions). The raw WAL-backed
// store (New) is the bench/torture/test data plane and is never managed.
func (fs *FS) Managed() bool { return fs.managed != nil }

// PersistsInodeMetadata is the affirmative durability claim behind
// fsproto.FeatureFlagPersistence: per-inode BSD file flags and birth time
// survive a restart of THIS store.
//
// It reports the backing MODE, not the type, because one *FS fronts both
// generations. The managed generation carries both facts end to end — the PFJ3
// entry log records them (wal.OpChflags, the create record's ordered op time)
// and the PFT2 base persists them as inode fields 14/15, so a cold start from
// an adopted base restores them. The raw WAL-backed generation does not: its
// committed base is a backend manifest (backend.Entry), which has no field for
// either, so every fact the WAL replay restores is lost the moment a
// checkpoint commits the manifest and compacts the WAL behind it. That store
// must therefore not advertise a durability it only appears to have while the
// log is still intact.
func (fs *FS) PersistsInodeMetadata() bool { return fs.Managed() }

// SessionAdmissible reports whether the session may consume identities right
// now: the managed store fails closed between a session's projected lease
// deadline and its durable database resolution (managed.go).
func (fs *FS) SessionAdmissible(sessionID string) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	return fs.managedSessionAdmissible(sessionID)
}

// ExpiredSessions durably fences each elapsed lease before returning it. The
// protocol layer may then release the session's locks/delegations knowing a
// crash cannot resurrect its authority; re-fencing is an idempotent no-op.
func (fs *FS) ExpiredSessions(now time.Time) []SessionInfo {
	if fs.managed == nil {
		return nil
	}
	return fs.managedExpiredSessions(now)
}

// ---- exact-once slot surface (fsproto server API) ----

// SlotCheckResult classifies an exact-once envelope against the slot table.
type SlotCheckResult int

const (
	// SlotNew means the envelope is the slot's next sequence: execute it.
	SlotNew SlotCheckResult = iota
	// SlotDuplicate means the envelope exactly matches the slot's latest
	// recorded outcome (same seq + request hash): return the stored outcome.
	SlotDuplicate
	// SlotConflict means the sequence matches the latest outcome but the
	// request hash differs — the same identity was reused for a DIFFERENT
	// request. Fence the session; never execute.
	SlotConflict
	// SlotGap means the sequence skips ahead or lags behind: fence.
	SlotGap
	// SlotUnknownSession means the session/generation is unknown, superseded,
	// or expired: reject; the client must re-establish (remount).
	SlotUnknownSession
	// SlotRetired means the sequence is at or below the durable acknowledged
	// floor: its detailed outcome was explicitly released. The reply is a
	// definite outcome-retired error; it never re-executes and never fences
	// the session.
	SlotRetired
)

// SlotOutcome is the stored essential response for a duplicate retry.
type SlotOutcome struct {
	Status    int32
	Count     int32
	Version   uint64
	Offset    int64
	Ino       uint64
	OrphanIno uint64
}

// CheckSlot classifies env against the current slot table. It does NOT
// reserve anything; the caller serializes per (session, slot) so check +
// execute are atomic per slot.
func (fs *FS) CheckSlot(env *wal.Envelope) (SlotCheckResult, SlotOutcome) {
	if fs.managed == nil {
		return SlotUnknownSession, SlotOutcome{}
	}
	return fs.managedCheckSlot(env)
}

// RecordStaticOutcome durably records a definite PRE-ADMISSION rejection
// (e.g. ENAMETOOLONG) for an exact-once slot, so sequence progression
// survives restart/failover even though no user mutation was appended. The
// reply happens only after the record is durable.
func (fs *FS) RecordStaticOutcome(env *wal.Envelope, status int32) error {
	if !env.Valid() {
		return nil
	}
	if fs.managed == nil {
		return ErrNotManaged
	}
	return fs.managedRecordStaticOutcome(env, status)
}

// MutationResult is the essential apply outcome of one exact mutation: the
// deterministic status (0 = applied OK, else the recorded errno) plus the
// fields a duplicate retry replays verbatim.
type MutationResult struct {
	Status    int32
	Count     int32
	Version   uint64
	Offset    int64
	Ino       uint64
	OrphanIno uint64
	// Post is the post-op state of every NAME this record's version stamp
	// covers — the mutated name (or its absence) and, for a namespace
	// mutation, the parent directory. It is captured at the record's ordered
	// apply position under the SAME lock hold that assigned Version, so the
	// attributes and their coherence anchor are one atomic observation: a
	// concurrent mutation is either ordered before this one (and visible in
	// these attributes) or after it (and carries a strictly greater version).
	//
	// It is NOT part of the durable exact outcome: a duplicate replay carries
	// only the essential fields, and its client re-stats. Post is a
	// fresh-execution observation, never a replayed fact.
	Post []PostAttr
}

// PostAttr is one affected name's post-op state. Exists=false is a POSITIVE
// statement of absence at the record's ordered position (the name the record
// removed or renamed away), not "unknown": it is emitted only when the parent
// directory's version was stamped by the same record, which is the anchor a
// cached negative is gated on.
type PostAttr struct {
	Path   string
	Exists bool
	Info   os.FileInfo // nil when Exists is false
}

// MutateEnv commits one exact-once mutation as one managed journal row and
// returns its essential apply outcome. Deterministic apply rejections
// (ENOENT, EEXIST, ...) are DEFINITE outcomes carried in
// MutationResult.Status; the returned error is reserved for infrastructure
// states (ErrSessionStale, ErrDurabilityUnknown, static rejects) that the
// protocol layer classifies.
func (fs *FS) MutateEnv(r wal.Record, owner string) (MutationResult, error) {
	if !r.Env.Valid() {
		return MutationResult{}, fmt.Errorf("vcs: exact mutation lacks an envelope")
	}
	if fs.managed == nil {
		return MutationResult{}, ErrNotManaged
	}
	return fs.managedMutateEnv(r, owner)
}

// MutateEnvGated is MutateEnv with atomic write-back delegation admission.
// paths are the mutation's affected namespace paths. The final overlap check
// and the mutation-or-EAGAIN row are selected under the same fs.mu
// reservation used by delegation grants.
func (fs *FS) MutateEnvGated(r wal.Record, owner string, paths ...string) (MutationResult, error) {
	if !r.Env.Valid() {
		return MutationResult{}, fmt.Errorf("vcs: exact gated mutation lacks an envelope")
	}
	if fs.managed == nil {
		return MutationResult{}, ErrNotManaged
	}
	return fs.managedMutateEnvGated(r, owner, paths...)
}

// errnoOf maps an apply error to the wire errno recorded in a slot outcome.
// It MUST agree with the protocol layer's error mapping (fsproto.toErrno) so
// a duplicate retry replays exactly the status the live reply carried; both
// delegate to the shared errnos mapping, making the agreement structural.
// Workfs-local sentinels are handled first.
func errnoOf(err error) int32 {
	if err != nil && errors.Is(err, ErrSealed) {
		return errnos.EROFS
	}
	return errnos.Of(err)
}
