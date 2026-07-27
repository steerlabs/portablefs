package workfs

// Replicated control metadata for exact mount sessions: the durable session
// table (identity, generation, token hash, slot budget, lease), the per-slot
// exact-once outcome table, and generation tombstones. Every transition rides
// a wal.OpControl record (or the Envelope embedded in the user record it
// describes) through the same append/fsync/replicate/replay pipeline as user
// mutations, so a restart or standby promotion reconstructs exactly-once
// state byte-for-byte.
//
// Unlike the root PortableFS implementation this port derives from, there is
// no separate reservation-order shadow of the control state: this FS holds
// fs.mu across WAL append AND in-memory apply (apply-before-durable, exactly
// like every user mutation here), so the applied view IS the reservation
// order. Definite replies are still released only after CommitThrough, and a
// durability failure surfaces as ErrDurabilityUnknown so the protocol layer
// drops the connection instead of inventing an errno.

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// sessionRenewShards bounds the per-session lifecycle serialization locks.
const sessionRenewShards = 64

// SessionLeaseTTL is the authority-side lifetime of a protocol session without
// renewal. Locks, delegations, and open state owned by a session are released
// ONLY on explicit expire or on this lease elapsing — never on a socket flap.
// Tests shorten it.
var SessionLeaseTTL = 90 * time.Second

// SessionReclaimGrace is the bounded local window granted after restart/
// promotion replay so a token-proven prior session can resume and re-assert
// its volatile coordination state (locks, checkouts) before it is declared
// abandoned. The window is deliberately not replicated and does not freeze
// ordinary reads; the serving layer uses ReclaimableSessions to withhold only
// conflicting state grants.
var SessionReclaimGrace = 90 * time.Second

// SessionTombstoneGrace retains an expired session's slot outcomes past its
// expiry so a delayed retry is answered with its recorded outcome (or an
// explicit stale-generation reject) instead of being re-executed.
var SessionTombstoneGrace = 10 * time.Minute

var (
	ErrSessionStale    = errors.New("vcs: session generation is stale or expired")
	ErrSessionConflict = errors.New("vcs: session generation tuple conflicts")
	ErrControlCapacity = errors.New("vcs: replicated control-state capacity exhausted")
	ErrExactConflict   = errors.New("vcs: exact mutation identity hash conflicts")
	ErrExactGap        = errors.New("vcs: exact mutation slot sequence is not contiguous")
	errLeaseRenewed    = errors.New("vcs: session lease was renewed before conditional expiry")
)

// ErrDurabilityUnknown wraps a commit failure whose outcome is ambiguous: the
// record was appended (and may be durably prepared) but the durability barrier
// failed. The node is fencing; the protocol layer MUST NOT answer with a
// definite errno — it drops the connection and the client replays the
// identical identity against a surviving authority.
var ErrDurabilityUnknown = errors.New("vcs: mutation durability unknown (durability barrier failed; node fencing)")

// Control-state bounds, enforced at live admission and on snapshot decode so
// replicated control state keeps one finite shape.
const (
	MaxSessionSlots      = 4096
	MaxControlSessions   = 4096
	MaxControlSlotStates = 262144
	MaxControlWatermarks = 4096
	MaxSessionIDBytes    = 128
	MaxSessionOwnerBytes = 256
	MaxSessionTokenBytes = 256
	// RequestHashBytes is the exact length of a canonical request fingerprint
	// (SHA-256); envelopes carrying any other length are malformed.
	RequestHashBytes = 32
)

type slotOutcome struct {
	seq       uint64
	reqHash   []byte
	status    int32 // 0 = applied OK; otherwise the deterministic errno recorded
	count     int32
	offset    int64
	version   uint64
	ino       uint64
	orphanIno uint64
}

type ctlSession struct {
	generation     uint64
	owner          string
	tokenHash      []byte
	slots          uint32
	expiresMs      int64 // replicated/durable absolute expiry
	localExpiresMs int64 // volatile local extension (startup reclaim grace); never serialized
	expired        bool
	outcomes       map[uint32]*slotOutcome
}

// ctlWatermark is one write-back session's flush-dedup cursor: the next
// expected mount-local Seq under the session generation (epoch).
type ctlWatermark struct {
	epoch   uint64
	through uint64
}

type controlState struct {
	sessions   map[string]*ctlSession
	watermarks map[string]ctlWatermark
	slotStates int
}

func (c *controlState) initIfNeeded() {
	if c.sessions == nil {
		c.sessions = map[string]*ctlSession{}
	}
	if c.watermarks == nil {
		c.watermarks = map[string]ctlWatermark{}
	}
}

func sessionEffectiveExpiry(s *ctlSession) int64 {
	if s == nil {
		return 0
	}
	if s.localExpiresMs > s.expiresMs {
		return s.localExpiresMs
	}
	return s.expiresMs
}

func sessionTupleMatches(s *ctlSession, owner string, slots uint32, tokenHash []byte) bool {
	return s != nil && s.owner == owner && s.slots == slots && subtle.ConstantTimeCompare(s.tokenHash, tokenHash) == 1
}

func sessionRenewShard(id string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= 16777619
	}
	return h % sessionRenewShards
}

// grantStartupReclaimLocked extends the volatile local lease of every live
// replayed session by the reclaim grace, so a token-proven prior session that
// was mid-lease when the old process died can still resume and re-assert its
// coordination state on the promoted authority. The durable expiry is
// untouched: a session that never resumes is fenced once the grace elapses.
// Called once from New, after replay, before serving.
func (fs *FS) grantStartupReclaimLocked(now time.Time) {
	reclaimUntil := now.Add(SessionReclaimGrace).UnixMilli()
	for _, s := range fs.ctl.sessions {
		if !s.expired && reclaimUntil > s.localExpiresMs {
			s.localExpiresMs = reclaimUntil
		}
	}
}

// ---- control-record apply (shared by live commit and WAL replay) ----

// applyControlRecord decodes and applies one OpControl record. Caller holds
// fs.mu. It is monotonic and replay-safe: replaying the same record sequence
// reconstructs the same control state. Unknown kinds fail closed.
func (fs *FS) applyControlRecord(r wal.Record) error {
	p, err := decodeCtlPayload(r.Data)
	if err != nil {
		return err
	}
	return fs.applyControlPayloadLocked(p)
}

func (fs *FS) applyControlPayloadLocked(p ctlPayload) error {
	fs.ctl.initIfNeeded()
	switch p.Kind {
	case ctlKindSession:
		s := p.Session
		cur := fs.ctl.sessions[s.SessionID]
		if cur != nil && cur.generation > s.Generation {
			return nil // already superseded — deterministic no-op
		}
		if cur != nil && cur.generation == s.Generation {
			if cur.expired || !sessionTupleMatches(cur, s.Owner, s.Slots, s.TokenHash) {
				return fmt.Errorf("%w: session %s generation %d", ErrSessionConflict, s.SessionID, s.Generation)
			}
			if s.ExpiresMs > cur.expiresMs {
				cur.expiresMs = s.ExpiresMs
			}
			if s.ExpiresMs > cur.localExpiresMs {
				cur.localExpiresMs = s.ExpiresMs
			}
			return nil
		}
		if cur == nil && len(fs.ctl.sessions) >= MaxControlSessions {
			return ErrControlCapacity
		}
		if cur != nil {
			// A higher generation supersedes: the old generation's retained
			// outcomes are dropped with it (a delayed old-generation retry is
			// answered with a stale-generation reject, never re-executed).
			fs.ctl.slotStates -= len(cur.outcomes)
		}
		fs.ctl.sessions[s.SessionID] = &ctlSession{
			generation: s.Generation, owner: s.Owner,
			tokenHash: append([]byte(nil), s.TokenHash...), slots: s.Slots,
			expiresMs: s.ExpiresMs, localExpiresMs: s.ExpiresMs,
			outcomes: map[uint32]*slotOutcome{},
		}
		return nil
	case ctlKindRenew:
		r := p.Renew
		s := fs.ctl.sessions[r.SessionID]
		if s == nil || s.generation != r.Generation || s.expired || subtle.ConstantTimeCompare(s.tokenHash, r.TokenHash) != 1 {
			return fmt.Errorf("%w: renewal %s generation %d", ErrSessionStale, r.SessionID, r.Generation)
		}
		if r.ExpiresMs > s.expiresMs {
			s.expiresMs = r.ExpiresMs
		}
		if r.ExpiresMs > s.localExpiresMs {
			s.localExpiresMs = r.ExpiresMs
		}
		return nil
	case ctlKindExpire:
		e := p.Expire
		s := fs.ctl.sessions[e.SessionID]
		if s == nil || s.generation != e.Generation {
			return nil // unknown/superseded: fencing it is moot
		}
		if !e.Force && sessionEffectiveExpiry(s) > e.AtMs {
			// A conditional (sweeper) expiry that lost to a renewal. The
			// renewal rode the WAL before this record, so replay reproduces
			// the same rejection deterministically (a benign phantom).
			return errLeaseRenewed
		}
		s.expired = true
		s.expiresMs = e.AtMs
		s.localExpiresMs = e.AtMs
		return nil
	case ctlKindOutcome:
		o := p.Outcome
		return fs.recordSlotOutcomeLocked(&wal.Envelope{
			SessionID: o.SessionID, Generation: o.Generation, Slot: o.Slot, SlotSeq: o.SlotSeq, ReqHash: o.ReqHash,
		}, exactOutcome{status: o.Status})
	case ctlKindSnapshot:
		return fs.mergeControlSnapshotLocked(p.Snapshot)
	case ctlKindWatermark:
		return fs.applyWatermarkLocked(p.Watermark)
	default:
		return fmt.Errorf("vcs: unknown control payload kind %d", p.Kind)
	}
}

// applyWatermarkLocked advances one write-back session's flush watermark,
// monotonically per (epoch, through): a higher epoch resets the Seq space, a
// same-epoch record takes the max — so replay and a snapshot merge reproduce
// the identical cursor regardless of interleaving. Caller holds fs.mu.
func (fs *FS) applyWatermarkLocked(w *ctlWatermarkRec) error {
	if w == nil || w.SessionID == "" || len(w.SessionID) > MaxSessionIDBytes {
		return fmt.Errorf("vcs: malformed flush watermark record")
	}
	cur, ok := fs.ctl.watermarks[w.SessionID]
	if !ok && len(fs.ctl.watermarks) >= MaxControlWatermarks {
		return ErrControlCapacity
	}
	if !ok || w.Epoch > cur.epoch || (w.Epoch == cur.epoch && w.Through > cur.through) {
		fs.ctl.watermarks[w.SessionID] = ctlWatermark{epoch: w.Epoch, through: w.Through}
	}
	return nil
}

// exactOutcome is the essential apply result recorded for one exact identity.
type exactOutcome struct {
	status    int32
	count     int32
	offset    int64
	version   uint64
	ino       uint64
	orphanIno uint64
}

// recordSlotOutcomeLocked stores the latest outcome for the envelope's slot.
// Caller holds fs.mu. It runs identically at live apply and at replay, so the
// slot table is reconstructed exactly on restart/promotion.
func (fs *FS) recordSlotOutcomeLocked(env *wal.Envelope, res exactOutcome) error {
	if !env.Valid() {
		return nil
	}
	fs.ctl.initIfNeeded()
	s := fs.ctl.sessions[env.SessionID]
	if s == nil || s.generation != env.Generation {
		return nil // session unknown/superseded: the reject was already decided upstream
	}
	if env.Slot >= s.slots || env.SlotSeq == 0 || len(env.ReqHash) != RequestHashBytes {
		return fmt.Errorf("vcs: malformed exact outcome envelope")
	}
	prev := s.outcomes[env.Slot]
	if prev != nil {
		if prev.seq == env.SlotSeq && (!bytes.Equal(prev.reqHash, env.ReqHash) || prev.status != res.status) {
			return ErrExactConflict
		}
		if prev.seq >= env.SlotSeq {
			return nil // a snapshot merge already covers this record
		}
		if env.SlotSeq != prev.seq+1 {
			return ErrExactGap
		}
	} else if env.SlotSeq != 1 {
		return ErrExactGap
	}
	if prev == nil {
		if fs.ctl.slotStates >= MaxControlSlotStates {
			return ErrControlCapacity
		}
		fs.ctl.slotStates++
	}
	s.outcomes[env.Slot] = &slotOutcome{
		seq: env.SlotSeq, reqHash: append([]byte(nil), env.ReqHash...),
		status: res.status, count: res.count, offset: res.offset, version: res.version,
		ino: res.ino, orphanIno: res.orphanIno,
	}
	return nil
}

// mergeControlSnapshotLocked merges a control snapshot by per-key monotonic
// newest-wins, so replay is correct regardless of how the snapshot record
// interleaves with surviving incremental records. Caller holds fs.mu.
func (fs *FS) mergeControlSnapshotLocked(snap *ctlSnapshotRec) error {
	if snap == nil {
		return fmt.Errorf("vcs: control snapshot payload missing")
	}
	if snap.AllocatorValid {
		state := AllocatorState{
			Namespace: snap.AllocatorNamespace, NextLocal: snap.AllocatorNextLocal,
			MaxInoSeen: snap.AllocatorMaxInoSeen, DurableFloor: snap.AllocatorDurableFloor,
		}
		if err := state.validate(); err != nil {
			return fmt.Errorf("vcs: control snapshot allocator: %w", err)
		}
		if state.Namespace != fs.alloc.namespace {
			return fmt.Errorf("vcs: control snapshot allocator namespace %d does not match live %d",
				state.Namespace, fs.alloc.namespace)
		}
		if state.NextLocal > fs.alloc.nextLocal {
			fs.alloc.nextLocal = state.NextLocal
		}
		if state.MaxInoSeen > fs.alloc.maxInoSeen {
			fs.alloc.maxInoSeen = state.MaxInoSeen
		}
		if state.DurableFloor > fs.alloc.durableFloor {
			fs.alloc.durableFloor = state.DurableFloor
		}
	}
	fs.ctl.initIfNeeded()
	for i := range snap.Watermarks {
		w := snap.Watermarks[i]
		if err := fs.applyWatermarkLocked(&w); err != nil {
			return err
		}
	}
	for i := range snap.Sessions {
		ss := &snap.Sessions[i]
		cur := fs.ctl.sessions[ss.SessionID]
		switch {
		case cur == nil || cur.generation < ss.Generation:
			if cur == nil && len(fs.ctl.sessions) >= MaxControlSessions {
				return ErrControlCapacity
			}
			if cur != nil {
				fs.ctl.slotStates -= len(cur.outcomes)
			}
			cur = &ctlSession{
				generation: ss.Generation, owner: ss.Owner,
				tokenHash: append([]byte(nil), ss.TokenHash...), slots: ss.Slots,
				expiresMs: ss.ExpiresMs, localExpiresMs: ss.ExpiresMs,
				expired: ss.Expired, outcomes: map[uint32]*slotOutcome{},
			}
			fs.ctl.sessions[ss.SessionID] = cur
		case cur.generation > ss.Generation:
			continue // live state is newer than the snapshot's
		default:
			if cur.owner != ss.Owner || cur.slots != ss.Slots || subtle.ConstantTimeCompare(cur.tokenHash, ss.TokenHash) != 1 {
				return fmt.Errorf("%w: snapshot session %s generation %d", ErrSessionConflict, ss.SessionID, ss.Generation)
			}
			if ss.ExpiresMs > cur.expiresMs {
				cur.expiresMs = ss.ExpiresMs
			}
			if ss.ExpiresMs > cur.localExpiresMs {
				cur.localExpiresMs = ss.ExpiresMs
			}
			cur.expired = cur.expired || ss.Expired
		}
		for j := range ss.SlotStates {
			st := &ss.SlotStates[j]
			prev := cur.outcomes[st.Slot]
			if prev != nil && st.SlotSeq <= prev.seq {
				continue
			}
			if prev == nil {
				if fs.ctl.slotStates >= MaxControlSlotStates {
					return ErrControlCapacity
				}
				fs.ctl.slotStates++
			}
			cur.outcomes[st.Slot] = &slotOutcome{
				seq: st.SlotSeq, reqHash: append([]byte(nil), st.ReqHash...),
				// Coherence versions are scoped to one authority generation: a
				// restored outcome replays version 0 so the reconnecting client
				// refreshes under this process's new generation.
				status: st.Status, count: st.Count, offset: st.Offset, version: 0,
				ino: st.Ino, orphanIno: st.OrphanIno,
			}
		}
	}
	return nil
}

// ---- live control commit path ----

// commitControl appends one control record and applies it under the same
// fs.mu hold (validate → append → apply), then makes it durable. check runs
// under fs.mu BEFORE the append and returns the definite client-facing
// rejection (stale/conflict/capacity) without consuming a WAL slot.
// admitGate routes ordinary control transitions (establish/renew/outcome)
// through the seal admission gate; fences/expiries bypass it — a retiring
// authority must still be able to fence sessions durably.
func (fs *FS) commitControl(p ctlPayload, admitGate bool, check func() error) error {
	if admitGate {
		if aerr := fs.admit.enter(); aerr != nil {
			return aerr
		}
		defer fs.admit.exit()
	}
	data, err := encodeCtlPayload(p)
	if err != nil {
		return err
	}
	fs.mu.Lock()
	fs.ctl.initIfNeeded()
	if check != nil {
		if cerr := check(); cerr != nil {
			fs.mu.Unlock()
			return cerr
		}
	}
	seq, bufErr := fs.wal.AppendBuffered(wal.Record{Op: wal.OpControl, Data: data})
	if bufErr != nil {
		fs.mu.Unlock()
		return bufErr // nothing buffered; wal.ErrPoisoned classifies for the caller
	}
	fs.epoch++
	applyErr := fs.applyControlPayloadLocked(p)
	fs.mu.Unlock()
	if cErr := fs.wal.CommitThrough(seq); cErr != nil {
		return fmt.Errorf("%w (control record durability: %v)", ErrDurabilityUnknown, cErr)
	}
	return applyErr
}

// ---- protocol session registry (fsproto server API) ----

// SessionInfo is the authority's view of one protocol session. ExpiresMs is
// the effective local expiry, including the bounded post-replay reclaim grace
// (WAL store) or the exact database lease deadline (managed store).
type SessionInfo struct {
	SessionID  string
	Generation uint64
	Owner      string
	Slots      uint32
	Expired    bool
	ExpiresMs  int64
	// DurableExpiresMs is the replicated expiry a replacement authority will
	// recover; Durable reports whether the latest generation transition has
	// crossed its durability boundary. The WAL store (apply-before-durable
	// under fs.mu) reports its applied view as durable by construction.
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
// under a durable, replicated control record and returns the opaque session
// token the client must present on reconnect. Establishing a HIGHER generation
// of the same session id tombstones every lower generation (stale-generation
// requests reject). Re-establishing the SAME generation requires the exact
// token (reconnect); a mismatch fails.
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
// generation under a durable, replicated control record. The exact
// (id, generation, owner, slots, token-hash) tuple is idempotent, making a
// lost establish reply safely replayable. A same-generation tuple mismatch is
// a conflict; a higher generation supersedes (tombstoning every lower one); a
// lower generation is stale.
func (fs *FS) EstablishSessionWithToken(sessionID string, generation uint64, owner string, slots uint32, token string) error {
	if fs.managed != nil {
		if generation == 0 {
			return fmt.Errorf("vcs: session generation must be nonzero")
		}
		return fs.managedEstablishSession(sessionID, generation, owner, slots, token)
	}
	if err := validateSessionInput(sessionID, owner, slots, token); err != nil {
		return err
	}
	if generation == 0 {
		return fmt.Errorf("vcs: session generation must be nonzero")
	}
	sum := sha256.Sum256([]byte(token))
	lock := &fs.renewLocks[sessionRenewShard(sessionID)]
	lock.Lock()
	defer lock.Unlock()
	expiresMs := time.Now().Add(SessionLeaseTTL).UnixMilli()
	rec := &ctlSessionRec{
		SessionID: sessionID, Generation: generation, Owner: owner,
		TokenHash: sum[:], Slots: slots, ExpiresMs: expiresMs,
	}
	return fs.commitControl(ctlPayload{Kind: ctlKindSession, Session: rec}, true, func() error {
		cur := fs.ctl.sessions[sessionID]
		switch {
		case cur == nil:
			if len(fs.ctl.sessions) >= MaxControlSessions {
				return ErrControlCapacity
			}
		case cur.generation > generation:
			return fmt.Errorf("%w: session %s generation %d superseded", ErrSessionStale, sessionID, generation)
		case cur.generation == generation:
			if cur.expired {
				return fmt.Errorf("%w: session %s generation %d expired", ErrSessionStale, sessionID, generation)
			}
			if !sessionTupleMatches(cur, owner, slots, sum[:]) {
				return fmt.Errorf("%w: session %s generation %d", ErrSessionConflict, sessionID, generation)
			}
		}
		return nil
	})
}

// ResumeSession authenticates a reconnect: the presented token must hash to
// the session's recorded credential and the generation must be current. It
// durably renews the lease and returns the session's info.
func (fs *FS) ResumeSession(sessionID string, generation uint64, token string) (SessionInfo, error) {
	if fs.managed != nil {
		return fs.managedResumeSession(sessionID, generation, token)
	}
	if token == "" || len(token) > MaxSessionTokenBytes {
		return SessionInfo{}, ErrSessionStale
	}
	sum := sha256.Sum256([]byte(token))
	lock := &fs.renewLocks[sessionRenewShard(sessionID)]
	lock.Lock()
	defer lock.Unlock()
	if _, err := fs.authenticateSessionTuple(sessionID, generation, sum[:]); err != nil {
		return SessionInfo{}, err
	}
	expiresMs := time.Now().Add(SessionLeaseTTL).UnixMilli()
	rec := &ctlRenewRec{SessionID: sessionID, Generation: generation, TokenHash: sum[:], ExpiresMs: expiresMs}
	err := fs.commitControl(ctlPayload{Kind: ctlKindRenew, Renew: rec}, true, func() error {
		s := fs.ctl.sessions[sessionID]
		if s == nil || s.generation != generation || s.expired || subtle.ConstantTimeCompare(s.tokenHash, sum[:]) != 1 {
			return ErrSessionStale
		}
		return nil
	})
	if err != nil {
		return SessionInfo{}, err
	}
	info, ok := fs.CurrentSession(sessionID)
	if !ok || info.Expired || info.Generation != generation {
		return SessionInfo{}, ErrSessionStale
	}
	return info, nil
}

// RenewSessionLease extends a session's lease (any authenticated activity).
func (fs *FS) RenewSessionLease(sessionID string) {
	if fs.managed != nil {
		// Managed lease deadlines are exact database facts advanced ONLY by
		// journaled renewals (ResumeSession); ambient activity never mints
		// database time.
		return
	}
	lock := &fs.renewLocks[sessionRenewShard(sessionID)]
	lock.Lock()
	defer lock.Unlock()
	fs.mu.RLock()
	s := fs.ctl.sessions[sessionID]
	if s == nil || s.expired {
		fs.mu.RUnlock()
		return
	}
	generation := s.generation
	tokenHash := append([]byte(nil), s.tokenHash...)
	fs.mu.RUnlock()
	expiresMs := time.Now().Add(SessionLeaseTTL).UnixMilli()
	rec := &ctlRenewRec{SessionID: sessionID, Generation: generation, TokenHash: tokenHash, ExpiresMs: expiresMs}
	_ = fs.commitControl(ctlPayload{Kind: ctlKindRenew, Renew: rec}, true, func() error {
		s := fs.ctl.sessions[sessionID]
		if s == nil || s.generation != generation || s.expired {
			return ErrSessionStale
		}
		return nil
	}) // durability failures already poison/fence the authority
}

// AuthenticateSession verifies a presented token against a live session and
// returns its info without renewing. Used per-connection attach.
func (fs *FS) AuthenticateSession(sessionID string, token string) (SessionInfo, error) {
	if fs.managed != nil {
		return fs.managedAuthenticateSession(sessionID, token)
	}
	if token == "" || len(token) > MaxSessionTokenBytes {
		return SessionInfo{}, ErrSessionStale
	}
	sum := sha256.Sum256([]byte(token))
	fs.mu.RLock()
	s := fs.ctl.sessions[sessionID]
	if s == nil {
		fs.mu.RUnlock()
		return SessionInfo{}, ErrSessionStale
	}
	generation := s.generation
	fs.mu.RUnlock()
	return fs.authenticateSessionTuple(sessionID, generation, sum[:])
}

func (fs *FS) authenticateSessionTuple(sessionID string, generation uint64, tokenHash []byte) (SessionInfo, error) {
	nowMs := time.Now().UnixMilli()
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	s := fs.ctl.sessions[sessionID]
	if s == nil || s.generation != generation || s.expired ||
		sessionEffectiveExpiry(s) <= nowMs || subtle.ConstantTimeCompare(s.tokenHash, tokenHash) != 1 {
		return SessionInfo{}, ErrSessionStale
	}
	return SessionInfo{
		SessionID: sessionID, Generation: generation, Owner: s.owner, Slots: s.slots,
		ExpiresMs: sessionEffectiveExpiry(s),
	}, nil
}

// CurrentSession returns the latest view of one session (including expired
// tombstones, until pruned).
func (fs *FS) CurrentSession(sessionID string) (SessionInfo, bool) {
	if fs.managed != nil {
		return fs.managedSessionInfo(sessionID)
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	s := fs.ctl.sessions[sessionID]
	if s == nil {
		return SessionInfo{}, false
	}
	return SessionInfo{
		SessionID: sessionID, Generation: s.generation, Owner: s.owner, Slots: s.slots,
		Expired: s.expired, ExpiresMs: sessionEffectiveExpiry(s),
		DurableExpiresMs: s.expiresMs, Durable: true,
	}, true
}

// ExpireSession durably fences a session generation (voluntary close, or the
// protocol's corruption fence). Idempotent: fencing an already-expired or
// superseded generation is a no-op.
func (fs *FS) ExpireSession(sessionID string, generation uint64) error {
	if fs.managed != nil {
		// Voluntary close (clean unmount): the terminal transition releases
		// the generation's locks, checkouts, pins, and flush privileges in
		// the same journal row.
		return fs.managedTerminalSession(sessionID, generation, pfc2.TerminalClose)
	}
	return fs.expireSessionAt(sessionID, generation, time.Now().UnixMilli(), true)
}

// FenceSession durably fences the named generation. It is the run-attempt
// lifecycle hook: no coordinator is required because the fence shares the
// reservation order with exact mutations and higher-generation establishment.
func (fs *FS) FenceSession(sessionID string, generation uint64) error {
	if fs.managed != nil {
		return fs.managedTerminalSession(sessionID, generation, pfc2.TerminalAdminFence)
	}
	return fs.ExpireSession(sessionID, generation)
}

// FenceSessionCorrupt durably fences a generation whose client PROVED state
// corruption: a changed request digest at an occupied exact identity, or a
// slot-sequence gap. Same durable transition as ExpireSession; the protocol
// layer decides when corruption was proven. The managed store records the
// distinct durable terminal reason.
func (fs *FS) FenceSessionCorrupt(sessionID string, generation uint64) error {
	if fs.managed != nil {
		return fs.managedTerminalSession(sessionID, generation, pfc2.TerminalSlotCorruption)
	}
	return fs.expireSessionAt(sessionID, generation, time.Now().UnixMilli(), true)
}

func (fs *FS) expireSessionAt(sessionID string, generation uint64, atMs int64, force bool) error {
	rec := &ctlExpireRec{SessionID: sessionID, Generation: generation, AtMs: atMs, Force: force}
	err := fs.commitControl(ctlPayload{Kind: ctlKindExpire, Expire: rec}, false, func() error {
		s := fs.ctl.sessions[sessionID]
		if s == nil || s.generation != generation {
			return errAlreadyExpired // unknown or superseded: fencing is moot, skip the record
		}
		if s.expired {
			return errAlreadyExpired // idempotent: no fresh record needed
		}
		if !force && sessionEffectiveExpiry(s) > atMs {
			return errLeaseRenewed
		}
		return nil
	})
	if errors.Is(err, errAlreadyExpired) {
		return nil
	}
	return err
}

var errAlreadyExpired = errors.New("vcs: session generation already expired")

// ---- control snapshot (compaction / reset safety) ----

// captureControlSnapshot deep-copies the whole control state plus the inode
// allocator high-water under one read lock. It is never empty: checkpoint
// compaction must not make identities of deleted inodes reusable even when
// there are no live sessions.
func (fs *FS) captureControlSnapshot() *ctlSnapshotRec {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	snap := &ctlSnapshotRec{
		AllocatorValid:        true,
		AllocatorNamespace:    fs.alloc.namespace,
		AllocatorNextLocal:    fs.alloc.nextLocal,
		AllocatorMaxInoSeen:   fs.alloc.maxInoSeen,
		AllocatorDurableFloor: fs.alloc.durableFloor,
	}
	wmIDs := make([]string, 0, len(fs.ctl.watermarks))
	for id := range fs.ctl.watermarks {
		wmIDs = append(wmIDs, id)
	}
	sort.Strings(wmIDs)
	for _, id := range wmIDs {
		w := fs.ctl.watermarks[id]
		snap.Watermarks = append(snap.Watermarks, ctlWatermarkRec{SessionID: id, Epoch: w.epoch, Through: w.through})
	}
	ids := make([]string, 0, len(fs.ctl.sessions))
	for id := range fs.ctl.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := fs.ctl.sessions[id]
		ss := ctlSessionState{
			SessionID: id, Generation: s.generation, Owner: s.owner,
			TokenHash: append([]byte(nil), s.tokenHash...), Slots: s.slots,
			ExpiresMs: s.expiresMs, Expired: s.expired,
		}
		slots := make([]uint32, 0, len(s.outcomes))
		for slot := range s.outcomes {
			slots = append(slots, slot)
		}
		sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
		for _, slot := range slots {
			o := s.outcomes[slot]
			ss.SlotStates = append(ss.SlotStates, ctlSlotState{
				Slot: slot, SlotSeq: o.seq, ReqHash: append([]byte(nil), o.reqHash...),
				Status: o.status, Count: o.count, Offset: o.offset, Ino: o.ino, OrphanIno: o.orphanIno,
			})
		}
		snap.Sessions = append(snap.Sessions, ss)
	}
	return snap
}

// AppendControlSnapshot durably appends the current control state as one
// snapshot record. It bypasses the client admission gate: it is an internal
// record that never touches the user tree, and the terminal quiesce barrier
// appends it AFTER sealing admission.
func (fs *FS) AppendControlSnapshot() error {
	return fs.appendControlSnapshot()
}

// appendControlSnapshot durably appends the current control state as one
// ctlKindSnapshot record, so a following WAL compaction (or a reset) cannot
// orphan the control history that reconstructs exactly-once state or the
// monotonic inode allocator on replay.
// The record is NOT applied live — it describes state the in-memory view
// already holds (or exceeds; the snapshot merge is per-key monotonic, so any
// control transition that lands between capture and append wins on replay).
func (fs *FS) appendControlSnapshot() error {
	snap := fs.captureControlSnapshot()
	data, err := encodeCtlPayload(ctlPayload{Kind: ctlKindSnapshot, Snapshot: snap})
	if err != nil {
		return err
	}
	fs.mu.Lock()
	seq, bufErr := fs.wal.AppendBuffered(wal.Record{Op: wal.OpControl, Data: data})
	fs.mu.Unlock()
	if bufErr != nil {
		return bufErr
	}
	if cErr := fs.wal.CommitThrough(seq); cErr != nil {
		return fmt.Errorf("%w (control snapshot durability: %v)", ErrDurabilityUnknown, cErr)
	}
	return nil
}

// HasControlState reports whether any replicated control state exists.
func (fs *FS) HasControlState() bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.ctl.sessions) > 0 || len(fs.ctl.watermarks) > 0
}

// FlushWatermark reads a write-back session's replicated flush watermark:
// the session generation (epoch) and the next expected mount-local Seq.
// ok=false means no control watermark exists yet (a first flush, or one still
// on the legacy hidden-file watermark awaiting migration).
func (fs *FS) FlushWatermark(sessionID string) (epoch, through uint64, ok bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	w, ok := fs.ctl.watermarks[sessionID]
	if !ok {
		return 0, 0, false
	}
	return w.epoch, w.through, true
}

// FlushWatermarkRecord builds the OpControl record that advances a write-back
// session's flush watermark. The protocol layer appends it INSIDE the same
// atomic flush batch as the user mutations it covers, so the watermark moves
// iff the mutations land — one group commit, one durability point.
func FlushWatermarkRecord(sessionID string, epoch, through uint64) (wal.Record, error) {
	if sessionID == "" || len(sessionID) > MaxSessionIDBytes {
		return wal.Record{}, fmt.Errorf("vcs: malformed flush watermark session id")
	}
	data, err := encodeCtlPayload(ctlPayload{Kind: ctlKindWatermark, Watermark: &ctlWatermarkRec{
		SessionID: sessionID, Epoch: epoch, Through: through,
	}})
	if err != nil {
		return wal.Record{}, err
	}
	return wal.Record{Op: wal.OpControl, Data: data}, nil
}

// Managed reports whether this store journals through a fenced remote journal
// generation (journaled coordination, journaled-protocol negotiation, no
// reclaim grace, no wall-time outcome pruning). The WAL-backed store is the
// development / self-host / fault-test implementation and is never managed.
func (fs *FS) Managed() bool { return fs.managed != nil }

// SessionAdmissible reports whether the session may consume identities right
// now. The WAL-backed store owns its leases as its own replicated control
// records, so it always admits; the managed store fails closed between a
// session's projected lease deadline and its durable database resolution
// (managed.go).
func (fs *FS) SessionAdmissible(sessionID string) error {
	if fs.managed != nil {
		return fs.managedSessionAdmissible(sessionID)
	}
	return nil
}

// ExpiredSessions durably fences each elapsed lease before returning it. The
// protocol layer may then release the session's locks/delegations knowing a
// crash cannot resurrect its authority; re-fencing is an idempotent no-op.
func (fs *FS) ExpiredSessions(now time.Time) []SessionInfo {
	if fs.managed != nil {
		return fs.managedExpiredSessions(now)
	}
	nowMs := now.UnixMilli()
	fs.mu.RLock()
	var candidates []SessionInfo
	for id, s := range fs.ctl.sessions {
		if !s.expired && sessionEffectiveExpiry(s) > 0 && sessionEffectiveExpiry(s) <= nowMs {
			candidates = append(candidates, SessionInfo{
				SessionID: id, Generation: s.generation, Owner: s.owner, Slots: s.slots,
				ExpiresMs: sessionEffectiveExpiry(s),
			})
		}
	}
	fs.mu.RUnlock()
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].SessionID < candidates[j].SessionID })
	out := make([]SessionInfo, 0, len(candidates))
	for _, info := range candidates {
		if err := fs.expireSessionAt(info.SessionID, info.Generation, nowMs, false); err == nil {
			info.Expired = true
			out = append(out, info)
		}
	}
	return out
}

// IsCurrentSession reports whether (sessionID, generation, owner) names the
// live current generation (run/coordination hook).
func (fs *FS) IsCurrentSession(sessionID string, generation uint64, owner string) bool {
	info, ok := fs.CurrentSession(sessionID)
	return ok && !info.Expired && info.Generation == generation && info.Owner == owner
}

// IsReclaimableSession is the allocation-free run/coordination hook for one
// generation. Token proof still belongs to ResumeSession.
func (fs *FS) IsReclaimableSession(sessionID string, generation uint64, owner string, now time.Time) bool {
	if fs.managed != nil {
		return false // no reclaim phase in managed mode
	}
	info, ok := fs.CurrentSession(sessionID)
	if !ok || info.Expired || info.Generation != generation || info.Owner != owner {
		return false
	}
	fs.mu.RLock()
	applied := fs.ctl.sessions[sessionID]
	reclaimable := applied != nil && !applied.expired && applied.generation == generation && sessionEffectiveExpiry(applied) > now.UnixMilli()
	fs.mu.RUnlock()
	return reclaimable
}

// ReclaimableSessions returns durably recorded sessions whose effective lease
// (including the bounded post-replay grace) is live at now. A freshly promoted
// serving layer snapshots this list when it begins coordination reclaim; it
// admits token-proven resumes while temporarily withholding conflicting locks
// and delegations. Ordinary reads keep flowing.
func (fs *FS) ReclaimableSessions(now time.Time) []SessionInfo {
	if fs.managed != nil {
		// Managed recovery is exact: the replayed journal already owns every
		// coordination object. There is nothing to reclaim and no grace.
		return nil
	}
	nowMs := now.UnixMilli()
	fs.mu.RLock()
	out := make([]SessionInfo, 0, len(fs.ctl.sessions))
	for id, s := range fs.ctl.sessions {
		if s.expired || sessionEffectiveExpiry(s) <= nowMs {
			continue
		}
		out = append(out, SessionInfo{
			SessionID: id, Generation: s.generation, Owner: s.owner, Slots: s.slots,
			ExpiresMs: sessionEffectiveExpiry(s),
		})
	}
	fs.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out
}

// PruneExpiredSessions drops retained exact outcomes past the tombstone grace
// window, but preserves the compact generation tombstone. Deleting that final
// fence would let a delayed establish + exact mutation reuse an old identity.
func (fs *FS) PruneExpiredSessions(now time.Time) {
	if fs.managed != nil {
		// Managed control state is never time-pruned: retained outcomes and
		// tombstones are exactness, and capacity is explicit (ErrCapacity).
		return
	}
	cutoff := now.Add(-SessionTombstoneGrace).UnixMilli()
	fs.mu.Lock()
	for _, s := range fs.ctl.sessions {
		if s.expired && s.expiresMs > 0 && s.expiresMs < cutoff && len(s.outcomes) > 0 {
			fs.ctl.slotStates -= len(s.outcomes)
			s.outcomes = map[uint32]*slotOutcome{}
		}
	}
	fs.mu.Unlock()
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
	// floor (managed PFC2 only): its detailed outcome was explicitly released.
	// The reply is a definite outcome-retired error; it never re-executes and
	// never fences the session.
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
	if fs.managed != nil {
		return fs.managedCheckSlot(env)
	}
	nowMs := time.Now().UnixMilli()
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	s := fs.ctl.sessions[env.SessionID]
	if s == nil || s.generation != env.Generation || s.expired || sessionEffectiveExpiry(s) <= nowMs {
		return SlotUnknownSession, SlotOutcome{}
	}
	if env.Slot >= s.slots {
		return SlotGap, SlotOutcome{}
	}
	prev := s.outcomes[env.Slot]
	var prevSeq uint64
	if prev != nil {
		prevSeq = prev.seq
	}
	switch {
	case prev != nil && env.SlotSeq == prev.seq:
		if bytes.Equal(prev.reqHash, env.ReqHash) {
			return SlotDuplicate, SlotOutcome{
				Status: prev.status, Count: prev.count, Version: prev.version,
				Offset: prev.offset, Ino: prev.ino, OrphanIno: prev.orphanIno,
			}
		}
		return SlotConflict, SlotOutcome{}
	case env.SlotSeq == prevSeq+1:
		return SlotNew, SlotOutcome{}
	default:
		return SlotGap, SlotOutcome{}
	}
}

// RecordStaticOutcome durably records a definite PRE-ADMISSION rejection
// (e.g. ENAMETOOLONG) for an exact-once slot, so sequence progression
// survives restart/failover even though no user mutation was appended. The
// reply happens only after the record is durable.
func (fs *FS) RecordStaticOutcome(env *wal.Envelope, status int32) error {
	if !env.Valid() {
		return nil
	}
	if fs.managed != nil {
		return fs.managedRecordStaticOutcome(env, status)
	}
	rec := &ctlOutcomeRec{
		SessionID: env.SessionID, Generation: env.Generation,
		Slot: env.Slot, SlotSeq: env.SlotSeq, ReqHash: env.ReqHash, Status: status,
	}
	return fs.commitControl(ctlPayload{Kind: ctlKindOutcome, Outcome: rec}, true, func() error {
		return fs.checkEnvelopeLocked(env)
	})
}

// checkEnvelopeLocked re-validates an exact identity against the slot table at
// the fs.mu-held point where its record receives a WAL position — atomically
// with any concurrent fence, supersession, or lease sweep. Caller holds fs.mu.
func (fs *FS) checkEnvelopeLocked(env *wal.Envelope) error {
	nowMs := time.Now().UnixMilli()
	s := fs.ctl.sessions[env.SessionID]
	if s == nil || s.generation != env.Generation || s.expired || sessionEffectiveExpiry(s) <= nowMs {
		return ErrSessionStale
	}
	if env.Slot >= s.slots || env.SlotSeq == 0 || len(env.ReqHash) != RequestHashBytes {
		return ErrSessionStale
	}
	prev := s.outcomes[env.Slot]
	switch {
	case prev != nil && env.SlotSeq == prev.seq:
		if bytes.Equal(prev.reqHash, env.ReqHash) {
			// The caller holds the (session, slot) protocol lock, so a live
			// duplicate cannot reach this point; a matching outcome here
			// means state advanced underneath us — fail safe.
			return ErrSessionStale
		}
		return ErrExactConflict
	case prev == nil && env.SlotSeq == 1, prev != nil && env.SlotSeq == prev.seq+1:
		if prev == nil && fs.ctl.slotStates >= MaxControlSlotStates {
			return ErrControlCapacity
		}
		return nil
	default:
		return ErrExactGap
	}
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
}

// MutateEnv commits one exact-once mutation: the envelope rides the SAME WAL
// record as the mutation (same append, fsync, replication), and the essential
// outcome is recorded in the slot table under the same fs.mu hold as the
// apply. Deterministic apply rejections (ENOENT, EEXIST, ...) are DEFINITE
// outcomes carried in MutationResult.Status; the returned error is reserved
// for infrastructure states (ErrSessionStale, ErrDurabilityUnknown,
// wal.ErrPoisoned, static rejects) that the protocol layer classifies.
func (fs *FS) MutateEnv(r wal.Record, owner string) (MutationResult, error) {
	if !r.Env.Valid() {
		return MutationResult{}, fmt.Errorf("vcs: exact mutation lacks an envelope")
	}
	if fs.managed != nil {
		return fs.managedMutateEnv(r, owner)
	}
	if aerr := fs.admit.enter(); aerr != nil {
		return MutationResult{}, aerr
	}
	defer fs.admit.exit()
	if err := validateIntroducedName(r); err != nil {
		return MutationResult{}, err // static reject: nothing appended, identity not consumed here
	}
	if r.Op == wal.OpWrite {
		// Warm read-modified base blocks OUTSIDE fs.mu (a backend fetch under
		// the lock would stall every other writer), like the v1 write path.
		if r.Ino != 0 {
			fs.mu.RLock()
			target := fs.resolveForRW(r.Path, r.Ino)
			off := r.Offset
			if r.Append && target != nil {
				off = target.curSize()
			}
			fs.mu.RUnlock()
			fs.warmBaseForWriteNode(target, off, int64(len(r.Data)))
		} else {
			fs.mu.RLock()
			target := fs.resolve(r.Path)
			off := r.Offset
			if r.Append && target != nil {
				off = target.curSize()
			}
			fs.mu.RUnlock()
			fs.warmBaseForWriteNode(target, off, int64(len(r.Data)))
		}
	}
	fs.mu.Lock()
	if err := fs.checkEnvelopeLocked(r.Env); err != nil {
		fs.mu.Unlock()
		return MutationResult{}, err
	}
	if err := fs.admitDirtyWriteLocked(&r); err != nil {
		// Definite pre-append refusal at the dirty-block bound; the protocol
		// layer records it as a durable ENOSPC outcome like the other
		// capacity rejections.
		fs.mu.Unlock()
		return MutationResult{}, err
	}
	fs.preassignIno(&r)
	seq, bufErr := fs.wal.AppendBuffered(r)
	if bufErr != nil {
		fs.mu.Unlock()
		return MutationResult{}, bufErr // nothing buffered; wal.ErrPoisoned classifies
	}
	fs.epoch++
	resolvedOffset := r.Offset
	if r.Op == wal.OpWrite && r.Append {
		if target := fs.resolveForRW(r.Path, r.Ino); target != nil {
			resolvedOffset = target.curSize()
		}
	}
	relatedInos := fs.relatedInodesLocked(r)
	orphanIno, changed, applyErr := fs.applyMutationAs(r, owner)
	var version uint64
	if changed {
		version = fs.stampVersion(r, orphanIno, true)
	}
	res := fs.exactOutcomeLocked(r, orphanIno, version, resolvedOffset, applyErr)
	recErr := fs.recordSlotOutcomeLocked(r.Env, res)
	var invs []coherence.Invalidation
	if changed && applyErr == nil {
		invs = fs.changesFor(r, owner, version, orphanIno, relatedInos...)
	}
	fs.mu.Unlock()
	if recErr != nil {
		// checkEnvelopeLocked admitted this identity under the same fs.mu
		// hold, so a record failure here is an invariant break: the record IS
		// appended (replay will record it); reply nothing.
		return MutationResult{}, fmt.Errorf("%w (exact outcome record: %v)", ErrDurabilityUnknown, recErr)
	}
	if cErr := fs.wal.CommitThrough(seq); cErr != nil {
		return MutationResult{}, fmt.Errorf("%w (exact mutation durability: %v)", ErrDurabilityUnknown, cErr)
	}
	if changed && applyErr == nil {
		mutationsTotal.Inc()
		fs.publish(invs)
	}
	return MutationResult{
		Status: res.status, Count: res.count, Version: res.version,
		Offset: res.offset, Ino: res.ino, OrphanIno: res.orphanIno,
	}, nil
}

// exactOutcomeLocked derives the essential recorded outcome of one applied (or
// deterministically rejected) exact mutation. Caller holds fs.mu.
func (fs *FS) exactOutcomeLocked(r wal.Record, orphanIno, version uint64, resolvedOffset int64, applyErr error) exactOutcome {
	res := exactOutcome{status: errnoOf(applyErr), version: version, orphanIno: orphanIno}
	if applyErr == nil && r.Op == wal.OpWrite {
		res.count = int32(len(r.Data))
		res.offset = resolvedOffset
	}
	if applyErr == nil {
		switch r.Op {
		case wal.OpOrphan:
			res.ino = orphanIno
		case wal.OpReap:
			res.ino = r.Ino
		default:
			if n := fs.resolveForRW(r.Path, r.Ino); n != nil {
				res.ino = n.ino
			}
		}
	}
	return res
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
