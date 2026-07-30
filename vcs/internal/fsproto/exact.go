package fsproto

// Exact mount sessions, server side.
//
// Every write-through mutation carries an exact-once identity — (session,
// generation, slot, slot sequence) plus a deterministic canonical request
// hash — inside the SAME journal row as the mutation. The authority checks
// the slot table, executes at most once, and durably records the essential
// outcome, so a lost-response retry returns the byte-identical
// status/count/version/ino/orphan-ino instead of re-executing. Identity reuse
// with a different request (changed hash) and slot-sequence gaps FENCE the
// session: they prove client-state corruption, after which no further
// mutation from that generation may be trusted.
//
// The durable session/slot machinery lives in workfs (journaled PFC2
// coordination rows); this file is the protocol-side admission and execution
// logic on top of it. Envelope-less mutations are always refused: sessions
// are mandatory in the v8 baseline.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/modebits"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// SessionStore is the authority FS's durable mount-session + exact-once slot
// surface (workfs.FS). A v8 server requires one, and it must be MANAGED:
// coordination state journals through the fenced entry log and recovers by
// exact cold replay — no reclaim grace, no wall-time pruning.
type SessionStore interface {
	EstablishSessionWithToken(sessionID string, generation uint64, owner string, slots uint32, token string) error
	ResumeSession(sessionID string, generation uint64, token string) (workfs.SessionInfo, error)
	AuthenticateSession(sessionID string, token string) (workfs.SessionInfo, error)
	CurrentSession(sessionID string) (workfs.SessionInfo, bool)
	ExpireSession(sessionID string, generation uint64) error
	// FenceSessionCorrupt fences a generation that PROVED client-state
	// corruption (changed digest at an occupied identity, sequence gap).
	FenceSessionCorrupt(sessionID string, generation uint64) error
	// SessionAdmissible fails a session closed between its PROJECTED local
	// monotonic lease deadline and the durable database resolution (renewal
	// or terminal). The protocol maps it to an UNKNOWN that consumes
	// nothing.
	SessionAdmissible(sessionID string) error
	ExpiredSessions(now time.Time) []workfs.SessionInfo
	CheckSlot(env *wal.Envelope) (workfs.SlotCheckResult, workfs.SlotOutcome)
	RecordStaticOutcome(env *wal.Envelope, status int32) error
	MutateEnv(r wal.Record, owner string) (workfs.MutationResult, error)
	MutateEnvGated(r wal.Record, owner string, paths ...string) (workfs.MutationResult, error)
	// Managed reports whether this store journals through a fenced journal
	// generation. Construction asserts it: a v8 server never serves a
	// non-managed session store.
	Managed() bool
}

// sessionIDPattern bounds the session id alphabet: it appears in logs and
// durable control records, so it must never carry path separators, control
// bytes, or an empty value.
var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// connSession is one connection's protocol state: the mount session
// authenticated onto it. A session survives the connection (socket flap):
// dropping the conn releases NOTHING — cleanup is lease-owned.
type connSession struct {
	id    string
	gen   uint64
	owner string
}

func (cs *connSession) attached() bool { return cs != nil && cs.id != "" }

// exactState is the server's session machinery, present only when the backing
// filesystem is a SessionStore.
type exactState struct {
	store SessionStore

	// slotShards serialize check+execute per (session, slot), so a duplicate
	// retry racing its original cannot double-execute between CheckSlot and
	// MutateEnv. Sharded by hash; cross-slot sharing only adds serialization.
	slotShards [256]sync.Mutex

	sweeperOnce sync.Once
	sweeperStop chan struct{}
	sweeperDone chan struct{} // closed when the sweeper goroutine has exited
}

func newExactState(store SessionStore) *exactState {
	if !store.Managed() {
		// Managed (journaled) recovery is exact: the replayed journal already
		// says which session owns every lock, checkout, pin, and outcome.
		// The legacy in-memory coordination shadow (reclaim grace, wall-time
		// pruning) no longer exists, so a non-managed store cannot be served.
		panic("fsproto: a v8 server requires a MANAGED (journaled) session store")
	}
	return &exactState{
		store:       store,
		sweeperStop: make(chan struct{}),
		sweeperDone: make(chan struct{}),
	}
}

func (e *exactState) slotLock(sessionID string, slot uint32) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sessionID))
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], slot)
	_, _ = h.Write(b[:])
	return &e.slotShards[h.Sum32()%uint32(len(e.slotShards))]
}

// ---- request -> canonical WAL record ----

// buildMutationRecord maps one exact mutation request to its WAL record
// (WITHOUT the envelope — the caller stamps it). It is the wire-bounds gate:
// everything here fails BEFORE any WAL append. A non-OK errno means the
// request is statically malformed; the (deterministic) rejection is still
// durably recorded against the slot so sequence progression survives failover.
//
// The mapping is deliberately total and side-effect free: the same Request
// always yields the same Record, which is what makes the canonical request
// hash (a hash of this record) deterministic across client retries, server
// restarts, and standby promotion.
func buildMutationRecord(req *Request) (wal.Record, int32) {
	if len(req.Path) > MaxPathBytes || len(req.NewPath) > MaxPathBytes || len(req.Target) > MaxPathBytes {
		return wal.Record{}, ENAMETOOLONG
	}
	if len(req.Data) > MaxWriteBytes {
		return wal.Record{}, EINVAL
	}
	switch req.Op {
	case OpWrite:
		if req.Offset < 0 || (req.Append && req.Offset != 0) {
			return wal.Record{}, EINVAL
		}
		r := wal.Record{Op: wal.OpWrite, Offset: req.Offset, Append: req.Append, Data: req.Data}
		if req.OrphanIno != 0 {
			r.Ino = req.OrphanIno
		} else {
			r.Path = req.Path
			r.Ino = req.HandleIno
		}
		return r, OK
	case OpCreate:
		// req.Excl carries the O_EXCL/POSIX-exclusive intent to apply, where
		// requireAbsent decides EEXIST at the record's ordered position.
		// Without it this stays idempotent create (O_CREAT without O_TRUNC):
		// apply never clobbers an existing entry, matching the server's v1
		// create semantics.
		return wal.Record{Op: wal.OpCreate, Path: req.Path, Mode: modebits.CleanUnix(req.Mode), Excl: req.Excl}, OK
	case OpMkdir:
		// mkdir keeps this server's v1 mkdir-all apply semantics; the mount
		// issues single-component mkdirs, so EEXIST/ENOTDIR decisions are
		// deterministic at the record's ordered apply position.
		return wal.Record{Op: wal.OpMkdir, Path: req.Path, Mode: modebits.CleanUnix(req.Mode)}, OK
	case OpRemove:
		return wal.Record{Op: wal.OpRemove, Path: req.Path}, OK
	case OpOrphan:
		return wal.Record{Op: wal.OpOrphan, Path: req.Path}, OK
	case OpReap:
		if req.OrphanIno == 0 {
			return wal.Record{}, EINVAL
		}
		return wal.Record{Op: wal.OpReap, Ino: req.OrphanIno}, OK
	case OpRename:
		return wal.Record{Op: wal.OpRename, Path: req.Path, NewPath: req.NewPath, OrphanTarget: req.OrphanTarget}, OK
	case OpSymlink:
		return wal.Record{Op: wal.OpSymlink, Path: req.Path, Target: req.Target}, OK
	case OpLink:
		return wal.Record{Op: wal.OpLink, Path: req.Path, NewPath: req.NewPath}, OK
	case OpTruncate:
		if req.Size < 0 {
			return wal.Record{}, EINVAL
		}
		r := wal.Record{Op: wal.OpTruncate, Size: req.Size}
		if req.OrphanIno != 0 {
			r.Ino = req.OrphanIno
		} else {
			r.Path = req.Path
			r.Ino = req.HandleIno
		}
		return r, OK
	case OpSetxattr, OpRemovexattr:
		// Wire bounds mirror the server's legacy path (validateXattrRequest):
		// definitive pre-reservation rejections, durably recorded against the
		// slot like every static reject.
		if len(req.XattrName) == 0 || strings.IndexByte(req.XattrName, 0) >= 0 || !utf8.ValidString(req.XattrName) {
			return wal.Record{}, EINVAL
		}
		if len(req.XattrName) > wal.MaxXattrNameBytes {
			return wal.Record{}, ERANGE
		}
		if req.Op == OpSetxattr {
			if len(req.Data) > wal.MaxXattrValueBytes {
				return wal.Record{}, E2BIG
			}
			if req.XattrFlags&^wal.XattrFlagMask != 0 || req.XattrFlags == wal.XattrFlagMask {
				return wal.Record{}, EINVAL
			}
			return wal.Record{
				Op: wal.OpSetxattr, Path: req.Path, Ino: req.HandleIno,
				XattrName: req.XattrName, XattrFlags: req.XattrFlags, Data: req.Data,
			}, OK
		}
		if len(req.Data) != 0 || req.XattrFlags != 0 {
			return wal.Record{}, EINVAL
		}
		return wal.Record{Op: wal.OpRemovexattr, Path: req.Path, Ino: req.HandleIno, XattrName: req.XattrName}, OK
	case OpSetattr:
		// Exactly ONE attribute group per exact mutation: the identity maps
		// 1:1 to a single WAL record, so a multi-group setattr must be split
		// by the client into separate identities (it is on the wire what it
		// is in the log).
		groups := 0
		if req.SetMode {
			groups++
		}
		if req.SetTime {
			groups++
		}
		if req.SetUID || req.SetGID {
			groups++
		}
		if groups != 1 {
			return wal.Record{}, EINVAL
		}
		switch {
		case req.SetMode:
			return wal.Record{Op: wal.OpChmod, Path: req.Path, Ino: req.HandleIno, Mode: modebits.CleanUnix(req.Mode)}, OK
		case req.SetTime:
			return wal.Record{Op: wal.OpChtimes, Path: req.Path, Ino: req.HandleIno, MtimeMs: req.MtimeMs}, OK
		default:
			// Chown intent flags: only the flagged field changes; the other
			// resolves at ordered apply (deterministic on replay). A
			// request-time resolution would hash differently across retries.
			r := wal.Record{Op: wal.OpChown, Path: req.Path, Ino: req.HandleIno, ChownSetUID: req.SetUID, ChownSetGID: req.SetGID}
			if req.SetUID {
				r.UID = req.UID
			}
			if req.SetGID {
				r.GID = req.GID
			}
			return r, OK
		}
	default:
		return wal.Record{}, EINVAL
	}
}

// canonicalRecordHash is the deterministic canonical request fingerprint: a
// SHA-256 over an unambiguous length-prefixed encoding of the record's
// semantic fields. It is computed SERVER-side from the record the server will
// execute, stored durably with the outcome, and compared on every retry — an
// identity replayed with different content therefore always fences, even if a
// malicious client fabricates the hash field itself.
func canonicalRecordHash(r wal.Record) []byte {
	h := sha256.New()
	var b [8]byte
	u64 := func(v uint64) { binary.BigEndian.PutUint64(b[:], v); h.Write(b[:]) }
	str := func(s string) { u64(uint64(len(s))); h.Write([]byte(s)) }
	u64(uint64(r.Op))
	str(r.Path)
	str(r.NewPath)
	u64(uint64(r.Offset))
	u64(uint64(r.Size))
	u64(uint64(r.Mode))
	str(r.Target)
	u64(uint64(r.MtimeMs))
	u64(uint64(r.AtimeMs))
	u64(boolBit(r.ChtimesSetAtime))
	u64(uint64(r.UID))
	u64(uint64(r.GID))
	u64(boolBit(r.ChownSetUID))
	u64(boolBit(r.ChownSetGID))
	u64(r.Ino)
	u64(boolBit(r.OrphanTarget))
	u64(boolBit(r.Append))
	u64(boolBit(r.Excl))
	u64(boolBit(r.RenameNoReplace))
	u64(uint64(len(r.Data)))
	h.Write(r.Data)
	// XattrName is folded in ONLY for the ops that carry it: every
	// pre-xattr op's fingerprint stays byte-identical across the upgrade,
	// so a parked retry recorded by an older authority can never fence as
	// a hash conflict after a rolling upgrade. The new ops never executed
	// on an older authority, so their conditional segment is unambiguous.
	if r.Op == wal.OpSetxattr || r.Op == wal.OpRemovexattr {
		str(r.XattrName)
		u64(uint64(r.XattrFlags))
	}
	var digest [sha256.Size]byte
	return h.Sum(digest[:0])
}

func boolBit(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

// ---- session op handlers ----

func validSessionFields(id, token, owner string) bool {
	return sessionIDPattern.MatchString(id) &&
		token != "" && len(token) <= MaxTokenBytes &&
		len(owner) <= MaxOwnerBytes
}

// probeResponse answers OpProtocolVersion. The response carries the version,
// optional feature bitmap, and session lease. clientVersion is the version
// the probing client declared (Request.Size): anything but exactly
// ProtocolVersion is refused EINVAL — with our version still in the response,
// so a newer client reports the mismatch clearly, and an older one fails
// closed.
func (s *Server) probeResponse(clientVersion int64) *Response {
	resp := &Response{ProtoVersion: ProtocolVersion, Gen: s.gen()}
	if clientVersion != int64(ProtocolVersion) {
		resp.Status = EINVAL
		return resp
	}
	if s.exact != nil {
		resp.LeaseMs = workfs.SessionLeaseTTL().Milliseconds()
		if s.coordStore() != nil && s.supportsAtomicXattrFlags() {
			resp.Features |= FeatureDelegatedXattrs
		}
	}
	return resp
}

// sessionOpen establishes (or idempotently re-establishes) a session. The
// exact (id, generation, owner, slots, token) tuple is lost-response safe: a
// replay of the identical establish succeeds; a same-generation tuple mismatch
// is EPERM (credential conflict); a superseded generation is ESTALE.
func (s *Server) sessionOpen(cs *connSession, req *Request) *Response {
	if s.exact == nil {
		return &Response{Status: EPERM}
	}
	if !validSessionFields(req.SessionID, req.SessionToken, req.Owner) ||
		req.SessionGen == 0 || req.SessionSlots == 0 || req.SessionSlots > MaxSessionSlots {
		return &Response{Status: EINVAL}
	}
	err := s.exact.store.EstablishSessionWithToken(req.SessionID, req.SessionGen, req.Owner, req.SessionSlots, req.SessionToken)
	switch {
	case err == nil:
	case errors.Is(err, workfs.ErrSessionStale):
		return &Response{Status: ESTALE}
	case errors.Is(err, workfs.ErrSessionConflict):
		return &Response{Status: EPERM}
	case errors.Is(err, workfs.ErrControlCapacity):
		return &Response{Status: EBUSY}
	case errors.Is(err, workfs.ErrDurabilityUnknown), errors.Is(err, wal.ErrPoisoned):
		return nil // UNKNOWN: drop the conn; the identical establish tuple replays safely
	default:
		return &Response{Status: toErrno(err)}
	}
	cs.id, cs.gen, cs.owner = req.SessionID, req.SessionGen, req.Owner
	return &Response{
		Gen: s.gen(), LeaseMs: workfs.SessionLeaseTTL().Milliseconds(),
		SessionSlots: req.SessionSlots, ProtoVersion: ProtocolVersion,
	}
}

// sessionResume authenticates + durably renews an existing session and binds
// it to this connection. It is both the reconnect path and the periodic lease
// renewal.
func (s *Server) sessionResume(cs *connSession, req *Request) *Response {
	if s.exact == nil {
		return &Response{Status: EPERM}
	}
	if !sessionIDPattern.MatchString(req.SessionID) || req.SessionToken == "" || len(req.SessionToken) > MaxTokenBytes || req.SessionGen == 0 {
		return &Response{Status: EINVAL}
	}
	info, err := s.exact.store.ResumeSession(req.SessionID, req.SessionGen, req.SessionToken)
	switch {
	case err == nil:
	case errors.Is(err, workfs.ErrSessionStale):
		return &Response{Status: ESTALE}
	case errors.Is(err, workfs.ErrDurabilityUnknown), errors.Is(err, wal.ErrPoisoned):
		return nil // UNKNOWN: resume is replay-safe (renewals are idempotent)
	default:
		return &Response{Status: toErrno(err)}
	}
	cs.id, cs.gen, cs.owner = info.SessionID, info.Generation, info.Owner
	return &Response{
		Gen: s.gen(), LeaseMs: time.Until(time.UnixMilli(info.ExpiresMs)).Milliseconds(),
		SessionSlots: info.Slots, ProtoVersion: ProtocolVersion,
	}
}

// sessionAttach authenticates an existing session onto this connection without
// a durable renewal (cheap: pooled data connections attach on dial).
func (s *Server) sessionAttach(cs *connSession, req *Request) *Response {
	if s.exact == nil {
		return &Response{Status: EPERM}
	}
	if !sessionIDPattern.MatchString(req.SessionID) || req.SessionToken == "" || len(req.SessionToken) > MaxTokenBytes {
		return &Response{Status: EINVAL}
	}
	info, err := s.exact.store.AuthenticateSession(req.SessionID, req.SessionToken)
	if err != nil {
		return &Response{Status: ESTALE}
	}
	if req.SessionGen != 0 && req.SessionGen != info.Generation {
		return &Response{Status: ESTALE}
	}
	cs.id, cs.gen, cs.owner = info.SessionID, info.Generation, info.Owner
	return &Response{
		Gen: s.gen(), LeaseMs: time.Until(time.UnixMilli(info.ExpiresMs)).Milliseconds(),
		SessionSlots: info.Slots, ProtoVersion: ProtocolVersion,
	}
}

// sessionExpire voluntarily fences the attached generation (clean unmount).
// Its lease-owned coordination state is released immediately and durably.
func (s *Server) sessionExpire(cs *connSession, req *Request) *Response {
	if s.exact == nil {
		return &Response{Status: EPERM}
	}
	if !cs.attached() || cs.id != req.SessionID || (req.SessionGen != 0 && req.SessionGen != cs.gen) {
		return &Response{Status: EPERM}
	}
	if err := s.exact.store.ExpireSession(cs.id, cs.gen); err != nil {
		if errors.Is(err, workfs.ErrDurabilityUnknown) || errors.Is(err, wal.ErrPoisoned) {
			return nil
		}
		return &Response{Status: toErrno(err)}
	}
	s.releaseSessionOwner(cs.owner)
	return &Response{Gen: s.gen()}
}

// releaseSessionOwner traces a dead session's teardown. Its coordination
// state (locks, checkouts, pins) is journaled and released by the store's own
// durable expiry decision; open-inode/orphan pins release the same way.
func (s *Server) releaseSessionOwner(owner string) {
	if owner == "" {
		return
	}
	trace(evRelease, 0, tag(owner), 0, 0, 0)
}

// leaseSweeper schedules the store's re-check of elapsed session leases: the
// store durably fences them (a crash cannot resurrect a session) and releases
// their journaled coordination state. Managed stores never time-prune
// outcomes or tombstones — capacity is explicit and exactness is never
// forgotten. The TTL is sampled once at start (the accessor is atomic, so a
// test shortening it around a live server is safe either way).
func (s *Server) leaseSweeper(stop <-chan struct{}) {
	defer close(s.exact.sweeperDone)
	ttl := workfs.SessionLeaseTTL() / 4
	if ttl < 100*time.Millisecond {
		ttl = 100 * time.Millisecond
	}
	if ttl > 5*time.Second {
		ttl = 5 * time.Second
	}
	for {
		select {
		case <-stop:
			return
		case <-time.After(ttl):
		}
		for _, info := range s.exact.store.ExpiredSessions(time.Now()) {
			s.releaseSessionOwner(info.Owner)
		}
	}
}

// ---- exact mutation execution ----

// exactMutate executes one exact-once mutation. Returning nil means the
// outcome is UNKNOWN (possibly durably prepared): the connection is dropped
// WITHOUT a reply, and the client must park + replay the identical identity —
// never reuse it — until it gets a definite answer.
func (s *Server) exactMutate(cs *connSession, req *Request) *Response {
	env := req.Env
	// The envelope must be the connection's authenticated session: token proof
	// happened at attach; a forged envelope for someone else's session dies here.
	if !cs.attached() || env == nil || env.SessionID != cs.id || env.Generation != cs.gen || env.SlotSeq == 0 {
		return &Response{Status: ESTALE}
	}
	if !s.admissible(env.SessionID) {
		// Projected-expired lease (managed): fail closed (UNKNOWN — nothing
		// consumed) until the database renews the lease or commits terminal.
		return nil
	}

	// Serialize per (session, slot): check + execute must be atomic per slot,
	// so a retry racing its original on another connection cannot double-run.
	lk := s.exact.slotLock(env.SessionID, env.Slot)
	lk.Lock()
	defer lk.Unlock()

	record, errno := buildMutationRecord(req)
	if errno != OK {
		// Statically malformed: record the definite rejection durably so the
		// slot's sequence progression survives retry, restart, and failover.
		return s.staticRejectLocked(env, errno)
	}
	record.Env = &wal.Envelope{
		SessionID:  env.SessionID,
		Generation: env.Generation,
		Slot:       env.Slot,
		SlotSeq:    env.SlotSeq,
		// The canonical fingerprint is computed SERVER-side from the record
		// the server would execute; a client-supplied hash is ignored, so a
		// client cannot lie an altered replay past the conflict check.
		ReqHash: canonicalRecordHash(record),
	}

	switch res, outcome := s.exact.store.CheckSlot(record.Env); res {
	case workfs.SlotDuplicate:
		return duplicateResponse(outcome, s.gen())
	case workfs.SlotRetired:
		// The identity's detail was explicitly acknowledged and released
		// (managed durable floor). Definite outcome-retired answer: never
		// re-execute, never fence.
		return &Response{Status: EIO, Gen: s.gen()}
	case workfs.SlotConflict:
		// Same identity, DIFFERENT request digest: client identity
		// corruption. Fence the whole generation durably; never execute.
		return s.fenceSessionCorrupt(cs, env)
	case workfs.SlotGap:
		// A sequence hole proves lost client state (an identity was skipped
		// or rewound). Executing ANY further mutation from this generation
		// could interleave with the missing one; fence.
		return s.fenceSessionCorrupt(cs, env)
	case workfs.SlotUnknownSession:
		return &Response{Status: ESTALE}
	}

	// Admission gates, evaluated ONLY for a provably fresh identity (SlotNew
	// above, under the slot lock) and recorded DURABLY like any other
	// definite outcome — under the request's CANONICAL hash, so a replay of
	// the same request dedupes to the stored rejection instead of
	// conflicting. A gate reply that skipped the slot table would leave the
	// client unable to know whether its identity was consumed. The app-level
	// retry uses a FRESH identity, which re-evaluates the (transient) gate.
	if isReserved(req.Path) || isReserved(req.NewPath) {
		return s.rejectLocked(record.Env, ENOENT) // reserved metadata is invisible
	}
	if record.Op == wal.OpReap {
		// Public reap is removed from the protocol: only the authority
		// reaps, after durable state proves no pins. The rejection is a
		// durable exact outcome so the slot sequence still advances.
		return s.rejectLocked(record.Env, EPERM)
	}
	if req.Op == OpSetxattr && req.XattrFlags != 0 && !s.supportsAtomicXattrFlags() {
		// Definite fail-closed outcome for a store without the conditional
		// evaluator. Consume the exact identity so an identical retry cannot
		// later change meaning.
		return s.rejectLocked(record.Env, EOPNOTSUPP)
	}
	if req.Path != "" || req.NewPath != "" {
		// A write-through mutation overlapping ANY delegation — foreign OR
		// the caller's own — waits for recall only after the connection's
		// envelope has authenticated and duplicate/slot-gap classification has
		// proved this is a fresh identity. A bounded gate rejection is recorded
		// under the canonical mutation hash before replying, exactly like every
		// other definite outcome; replay therefore returns the stored EAGAIN
		// and the next slot sequence remains contiguous. MutateEnvGated repeats
		// the overlap decision against the RESERVED projection in the same
		// journal reservation as the tree-or-EAGAIN row; this volatile wait is
		// recall delivery and latency optimization, not the correctness gate.
		if st := s.delegationGate(cs, false, req.Path, req.NewPath); st != OK {
			return s.rejectLocked(record.Env, st)
		}
	}

	result, err := s.exact.store.MutateEnvGated(record, cs.owner, req.Path, req.NewPath)
	if err == nil {
		// A definite outcome (applied, or a deterministic apply rejection
		// like ENOENT/EEXIST), durably recorded under this identity. Reply
		// the RECORDED status so a duplicate retry is byte-identical.
		resp := &Response{
			Status: result.Status, Count: result.Count, Version: result.Version,
			Offset: result.Offset, Ino: result.Ino, OrphanIno: result.OrphanIno, Gen: s.gen(),
		}
		if result.Status == OK {
			s.fillExactAttr(req, record, resp)
		}
		return resp
	}
	if errors.Is(err, workfs.ErrSessionStale) {
		// Lost the admission race to a fence/supersession: nothing durable.
		return &Response{Status: ESTALE}
	}
	// Authoritative classification: if the record reached the slot table, the
	// error is this identity's recorded outcome — reply exactly what a
	// duplicate retry would be given.
	if res, outcome := s.exact.store.CheckSlot(record.Env); res == workfs.SlotDuplicate {
		return duplicateResponse(outcome, s.gen())
	}
	if isStaticReject(err) {
		// Deterministic pre-admission validation rejection: nothing was
		// appended; durably record the definite outcome so the slot sequence
		// still advances.
		return s.staticRejectLocked(env, toErrno(err))
	}
	if errno, quota := quotaErrno(err); quota {
		// Data-quota/capacity exhaustion is a DEFINITE pre-reservation
		// rejection recorded as a DURABLE outcome: the rejection row is
		// control-only and rides the bounded control reserve, which exists
		// precisely so exactness never becomes unrecordable at quota. The
		// slot sequence advances durably; the client's next attempt is a
		// fresh identity.
		return s.rejectLocked(record.Env, errno)
	}
	// ErrDurabilityUnknown, poisoned WAL, or any unclassified failure: the
	// outcome may be durably prepared (or no durable record is possible right
	// now). Reply NOTHING — the connection drops; the client parks and
	// replays the identical identity (UNKNOWN, never a guessed errno).
	return nil
}

// quotaErrno classifies definite capacity rejections: the database-owned
// journal DATA quota maps to EDQUOT; the local WAL capacity threshold maps
// to ENOSPC. Both are recorded as durable outcomes through the control
// reserve.
func quotaErrno(err error) (int32, bool) {
	switch {
	case errors.Is(err, wal.ErrJournalQuota):
		return EDQUOT, true
	case errors.Is(err, workfs.ErrWALCapacity):
		return ENOSPC, true
	default:
		return 0, false
	}
}

// fenceSessionCorrupt durably fences the envelope's generation (changed digest
// at an occupied identity, or a sequence gap) and releases its coordination
// state.
func (s *Server) fenceSessionCorrupt(cs *connSession, env *wal.Envelope) *Response {
	if err := s.exact.store.FenceSessionCorrupt(env.SessionID, env.Generation); err != nil &&
		(errors.Is(err, workfs.ErrDurabilityUnknown) || errors.Is(err, wal.ErrPoisoned)) {
		return nil // cannot prove the fence: drop the conn instead of answering
	}
	s.releaseSessionOwner(cs.owner)
	return &Response{Status: ESTALE}
}

// staticRejectLocked durably records a definite pre-admission rejection of a
// MALFORMED request (no canonical record exists, so the fingerprint is derived
// from the errno) and replies it. Caller holds the (session, slot) lock.
func (s *Server) staticRejectLocked(env *wal.Envelope, errno int32) *Response {
	return s.rejectLocked(&wal.Envelope{
		SessionID:  env.SessionID,
		Generation: env.Generation,
		Slot:       env.Slot,
		SlotSeq:    env.SlotSeq,
		ReqHash:    staticRejectHash(errno),
	}, errno)
}

// rejectLocked durably records a definite rejection outcome for an identity
// under the given (fully hashed) envelope and replies it. Caller holds the
// (session, slot) lock. If even the durable record cannot be written, the
// outcome is UNKNOWN and the conn drops (nil).
func (s *Server) rejectLocked(full *wal.Envelope, errno int32) *Response {
	switch res, outcome := s.exact.store.CheckSlot(full); res {
	case workfs.SlotDuplicate:
		return duplicateResponse(outcome, s.gen())
	case workfs.SlotUnknownSession:
		return &Response{Status: ESTALE}
	case workfs.SlotNew:
	default:
		_ = s.exact.store.FenceSessionCorrupt(full.SessionID, full.Generation)
		return &Response{Status: ESTALE}
	}
	if err := s.exact.store.RecordStaticOutcome(full, errno); err != nil {
		if errors.Is(err, workfs.ErrSessionStale) {
			return &Response{Status: ESTALE}
		}
		return nil // durability unknown: drop conn, client replays
	}
	return &Response{Status: errno, Gen: s.gen()}
}

// staticRejectHash fingerprints a statically rejected request by its errno.
// The raw request bytes may be unbounded/malformed (that is WHY it was
// rejected), so the canonical record hash is unavailable; what must stay
// stable across a replay is only that the same slot sequence maps to the same
// definite outcome. A different malformed request replayed on the same
// identity is a client-state violation and correctly fences via hash mismatch.
func staticRejectHash(errno int32) []byte {
	sum := sha256.Sum256([]byte{'s', 't', 'a', 't', 'i', 'c', byte(errno >> 24), byte(errno >> 16), byte(errno >> 8), byte(errno)})
	return sum[:]
}

func duplicateResponse(o workfs.SlotOutcome, gen uint64) *Response {
	return &Response{
		Status: o.Status, Count: o.Count, Version: o.Version,
		Offset: o.Offset, Ino: o.Ino, OrphanIno: o.OrphanIno,
		Gen: gen, Duplicate: true,
	}
}

// fillExactAttr adds the fresh-execution convenience Attr for ops whose v1
// responses carried one. Duplicate retries never carry it (the stored outcome
// is essential-only); the client re-stats when it needs attributes.
func (s *Server) fillExactAttr(req *Request, record wal.Record, resp *Response) {
	switch req.Op {
	case OpCreate, OpMkdir, OpSymlink, OpLink, OpSetattr:
		attrPath := record.Path
		if req.Op == OpLink {
			attrPath = record.NewPath
		}
		if hs, ok := s.fs.(HandleStore); ok && resp.Ino != 0 {
			// Attr is a fresh-execution convenience only: the mutation
			// already succeeded, so ANY HandleInfo failure (absence after a
			// racing unlink, or a lazy-base fetch error) simply omits the
			// attr and the client re-stats through the error-aware path.
			if fi, err := hs.HandleInfo(attrPath, resp.Ino); err == nil {
				a := attrOf(fi)
				resp.Attr = &a
				return
			}
		}
		if fi, err := s.fs.Lstat(attrPath); err == nil {
			a := attrOf(fi)
			resp.Attr = &a
		}
	}
}

// isStaticReject classifies a MutateEnv error as a deterministic pre-admission
// validation rejection (nothing was appended; re-validating the identical
// request yields the identical rejection). ERANGE/E2BIG are the xattr
// name/value bound rejections — deterministic exactly like ENAMETOOLONG.
func isStaticReject(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENAMETOOLONG) ||
		errors.Is(err, syscall.ERANGE) || errors.Is(err, syscall.E2BIG)
}
