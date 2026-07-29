package fsproto

// Managed (PFJ3/PFC2) coordination path: locks, checkouts, open pins, flush
// rows, and the volume sync barrier as exact-once journal decisions. On a
// managed generation NO state-changing coordination op ever reaches the
// legacy in-memory managers (they are not even constructed); every decision
// commits in the same ordered PFJ3 total order as tree mutations and
// recovers from cold replay with no reclaim grace. Reads (GETLK, watermark
// queries) answer from the applied (durable) reducer.
//
// Exactness model: the request's canonical fingerprint is computed
// SERVER-side from the decision record the server would commit; the identity
// is checked against the durable slot table under the (session, slot) shard
// lock; a duplicate replays the stored outcome; a changed fingerprint fences
// the generation with the durable TerminalSlotCorruption reason; gaps fence.
// The decision itself — grant row OR control-only rejection row — is emitted
// from ONE workfs reservation that observes the staged state (never a
// protocol pre-check followed by a later journal write), so every consumed
// identity has exactly one durable applied outcome. Blocking waits (SETLKW,
// contended checkout) are VOLATILE, cancelable, and happen BEFORE the
// identity is consumed: nothing is journaled while waiting, and no
// per-slice rejection rows are written.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// kernelOffsetEOF is the kernel's OFFSET_MAX end offset for a through-EOF
// POSIX lock range (l_len = 0). Conflict replies use it so the kernel sees
// the shape it speaks.
const kernelOffsetEOF = uint64(0x7fffffffffffffff)

// setlkwWaitBudget bounds ONE blocking-acquire RPC's volatile server-side
// wait. The wait consumes NOTHING (no identity, no journal rows); on expiry
// the single decision attempt runs — grant row or one durable EAGAIN — and
// the client re-issues at its own cadence.
const setlkwWaitBudget = 45 * time.Second

// CoordinationStore is the managed coordination surface of workfs.FS. The
// server type-asserts it exactly once at construction; a managed SessionStore
// that lacks it is a wiring error and fails closed.
type CoordinationStore interface {
	ManagedLockConflict(ino uint64, owner pfc2.LockOwner, start, length uint64, write bool) (pfc2.HeldLock, bool, error)
	ManagedLockDecide(env *wal.Envelope, ino, kernelLockOwner uint64, op pfc2.LockOp, start, length uint64) (workfs.CoordinationDecision, error)
	ManagedCheckoutDecide(env *wal.Envelope, path string) (workfs.CoordinationDecision, error)
	ManagedCheckinDecide(env *wal.Envelope, path, epoch string) (workfs.CoordinationDecision, error)
	ManagedCheckoutAt(path string) (pfc2.CheckoutView, bool, error)
	ManagedOverlappingCheckouts(path string) ([]pfc2.CheckoutView, error)
	ManagedSessionOwner(ref pfc2.SessionRef) string
	ManagedPinChange(env *wal.Envelope, ino uint64, unpin bool, reqHash []byte) error
	ManagedEnsureOpenPin(ref pfc2.SessionRef, ino uint64) error
	ManagedUnpinBatch(env *wal.Envelope, inos []uint64, reqHash []byte) error
	ManagedRecordCoordinationOutcome(env *wal.Envelope, reqHash []byte, status int32) error
	ManagedSyncBarrierRow(env *wal.Envelope, reqHash []byte) error

	// Write-back streams and delegations.
	ManagedDelegationDecide(env *wal.Envelope, path, writebackID string) (workfs.CoordinationDecision, error)
	ManagedDelegationsOverlapping(path string) []pfc2.CheckoutView
	ManagedWritebackState(writebackID string) (pfc2.StreamStateView, bool, error)
	ManagedWritebackRebind(env *wal.Envelope, envHash []byte, writebackID string, scopes []workfs.WritebackScope, through uint64, digest [32]byte) ([]workfs.WritebackConflict, error)
	ManagedWritebackDiscard(env *wal.Envelope, envHash []byte, writebackID string, scopes []workfs.WritebackScope) error
	ManagedFlushApply(ref pfc2.SessionRef, writebackID, checkoutPath, checkoutEpoch string, prevDigest, endDigest [32]byte, rows []workfs.ManagedFlushRow, owner string) (uint64, error)

	SyncBarrier() error
	WaitCoordinationClear(deadline time.Time, check func() bool) bool
}

// coordStore returns the managed coordination surface (nil on a server
// without a session store — reads-only test servers).
func (s *Server) coordStore() CoordinationStore {
	if s.exact == nil {
		return nil
	}
	cs, _ := s.exact.store.(CoordinationStore)
	return cs
}

// coordinationHash fingerprints a coordination request that has no PFC2
// record of its own (pin transitions, the volume sync barrier): a
// domain-separated SHA-256 over the semantic fields.
func coordinationHash(domain string, fields ...uint64) []byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	var b [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(b[:], f)
		h.Write(b[:])
	}
	return h.Sum(nil)
}

// pinRequestHash fingerprints a MarkOpen pin transition.
func pinRequestHash(ino uint64, unpin bool) []byte {
	state := uint64(0)
	if unpin {
		state = 1
	}
	return coordinationHash("PFC2-PIN", ino, state)
}

// unpinBatchRequestHash fingerprints one batched last-close unmark: the
// domain plus the ino list in wire order. The client's lost-reply resend is
// byte-identical, so the fingerprint replays; a reordered or edited list is
// a different request at the same identity and correctly fences.
func unpinBatchRequestHash(inos []uint64) []byte {
	return coordinationHash("PFC2-UNPIN-BATCH", inos...)
}

// barrierRequestHash fingerprints one volume sync barrier identity.
func barrierRequestHash(env *wal.Envelope) []byte {
	return coordinationHash("PFC2-BARRIER", env.Generation, uint64(env.Slot), env.SlotSeq)
}

// wireLockRange converts the inclusive wire [start,end] into the PFC2
// (start, length; 0 = through EOF) shape. The kernel expresses through-EOF as
// OFFSET_MAX (and some shims as ^0); both map to length 0.
func wireLockRange(start, end uint64) (uint64, uint64, bool) {
	if end < start {
		return 0, 0, false
	}
	if end >= kernelOffsetEOF {
		return start, 0, true
	}
	return start, end - start + 1, true
}

// lockWireEnd converts a held-lock end back to the kernel shape.
func lockWireEnd(end uint64) uint64 {
	if end == pfc2.LockRangeEOF {
		return kernelOffsetEOF
	}
	return end
}

// resolveLockIno resolves the lock target's stable inode: the client's open
// handle ino when supplied (rename/unlink stable), the parked orphan ino for
// unlinked-open files, else the authority's own path resolution at decision
// time. Zero means the target does not exist.
func (s *Server) resolveLockIno(req *Request) uint64 {
	if req.HandleIno != 0 {
		return req.HandleIno
	}
	if req.OrphanIno != 0 {
		return req.OrphanIno
	}
	if fi, err := s.fs.Lstat(req.Path); err == nil {
		if i, ok := fi.Sys().(interface{ Ino() uint64 }); ok {
			return i.Ino()
		}
	}
	return 0
}

// managedGetlk answers F_GETLK from the applied (durable) reducer. Pure read:
// no identity, no journal row. The probing owner derives from the
// AUTHENTICATED session (Request.Owner is display-only everywhere).
func (s *Server) managedGetlk(cs *connSession, req *Request) *Response {
	store := s.coordStore()
	if store == nil {
		return &Response{Status: EPERM}
	}
	if !cs.attached() {
		return &Response{Status: ESTALE}
	}
	ino := s.resolveLockIno(req)
	if ino == 0 {
		return &Response{Status: ENOENT}
	}
	start, length, ok := wireLockRange(req.LkStart, req.LkEnd)
	if !ok {
		return &Response{Status: EINVAL}
	}
	owner := pfc2.LockOwner{
		Session:         pfc2.SessionRef{SessionID: cs.id, Generation: cs.gen},
		KernelLockOwner: req.LkID,
	}
	h, conflict, err := store.ManagedLockConflict(ino, owner, start, length, req.LkWrite)
	if err != nil {
		return &Response{Status: toErrno(err)}
	}
	if !conflict {
		return &Response{Gen: s.gen()}
	}
	return &Response{
		LkConflict: true, LkStart: h.Start, LkEnd: lockWireEnd(h.End), LkWrite: h.Write,
		Gen: s.gen(),
	}
}

// exactCoordinate executes one managed coordination mutation exactly once:
// (optional volatile wait, consuming nothing) then ONE identity-classified
// decision under the shard lock, whose grant-or-rejection row is emitted from
// one workfs reservation. nil means UNKNOWN (conn drop; the client replays
// the identical identity).
func (s *Server) exactCoordinate(cs *connSession, req *Request) *Response {
	store := s.coordStore()
	if store == nil {
		return &Response{Status: EPERM}
	}
	env := req.Env
	if !cs.attached() || env == nil || env.SessionID != cs.id || env.Generation != cs.gen || env.SlotSeq == 0 {
		return &Response{Status: ESTALE}
	}
	if !s.admissible(env.SessionID) {
		return nil // projected-expired lease: fail closed, consume nothing
	}
	if isReserved(req.Path) {
		// Reserved metadata is invisible; the rejection row consumes the
		// identity durably under a static fingerprint.
		return s.coordReject(env, staticRejectHash(ENOENT), ENOENT)
	}

	switch req.Op {
	case OpLock:
		return s.coordinateLock(cs, store, req)
	case OpCheckout:
		return s.coordinateCheckout(cs, store, req)
	case OpCheckin:
		return s.coordinateCheckin(store, req)
	case OpMarkOpen:
		return s.coordinatePin(store, req)
	case OpUnmarkOpenInodes:
		return s.coordinateUnpinBatch(store, req)
	case OpDelegationAcquire:
		return s.coordinateDelegationAcquire(cs, store, req)
	case OpWritebackRebind:
		return s.coordinateWritebackRebind(store, req)
	case OpWritebackDiscard:
		return s.coordinateWritebackDiscard(store, req)
	default:
		return &Response{Status: EINVAL}
	}
}

// admissible reports whether the session may consume identities right now.
// Between a session's PROJECTED monotonic lease deadline and its durable
// database resolution the authority fails CLOSED by dropping the connection
// (an UNKNOWN, consuming nothing): a definite errno here would have to be
// either durable (impossible — the whole point is not to trust the lease) or
// unconsumed (which would desynchronize the client's slot sequence). The
// client parks and replays the identical identity while its independent
// renewal loop re-anchors the lease; a durable terminal then resolves every
// replay to a proof-backed ESTALE.
func (s *Server) admissible(sessionID string) bool {
	return s.exact.store.SessionAdmissible(sessionID) == nil
}

// coordReject durably records a definite pre-observation rejection (reserved
// namespace, static EINVAL) and replies it.
func (s *Server) coordReject(env *wal.Envelope, reqHash []byte, errno int32) *Response {
	store := s.coordStore()
	full := &wal.Envelope{
		SessionID: env.SessionID, Generation: env.Generation,
		Slot: env.Slot, SlotSeq: env.SlotSeq, ReqHash: reqHash,
	}
	lk := s.exact.slotLock(env.SessionID, env.Slot)
	lk.Lock()
	defer lk.Unlock()
	switch res, outcome := s.exact.store.CheckSlot(full); res {
	case workfs.SlotDuplicate:
		return duplicateResponse(outcome, s.gen())
	case workfs.SlotUnknownSession:
		return &Response{Status: ESTALE}
	case workfs.SlotNew:
	default:
		return s.fenceCorrupt(full.SessionID, full.Generation)
	}
	if err := store.ManagedRecordCoordinationOutcome(full, reqHash, errno); err != nil {
		if errors.Is(err, workfs.ErrSessionStale) {
			return &Response{Status: ESTALE}
		}
		return nil // durability unknown: drop conn, client replays
	}
	return &Response{Status: errno, Gen: s.gen()}
}

// fenceCorrupt durably fences a generation that PROVED client-state
// corruption (changed digest at an occupied identity, or a sequence gap)
// with the TerminalSlotCorruption reason.
func (s *Server) fenceCorrupt(sessionID string, generation uint64) *Response {
	if err := s.exact.store.FenceSessionCorrupt(sessionID, generation); err != nil &&
		(errors.Is(err, workfs.ErrDurabilityUnknown) || errors.Is(err, wal.ErrPoisoned)) {
		return nil // cannot prove the fence: drop the conn instead of answering
	}
	return &Response{Status: ESTALE}
}

// coordinateDecide runs ONE identity-classified decision attempt under the
// shard lock. decide performs the single-reservation observe+journal step.
func (s *Server) coordinateDecide(env *wal.Envelope, reqHash []byte, decide func(full *wal.Envelope) (workfs.CoordinationDecision, error)) *Response {
	full := &wal.Envelope{
		SessionID: env.SessionID, Generation: env.Generation,
		Slot: env.Slot, SlotSeq: env.SlotSeq, ReqHash: reqHash,
	}
	lk := s.exact.slotLock(env.SessionID, env.Slot)
	lk.Lock()
	defer lk.Unlock()
	switch res, outcome := s.exact.store.CheckSlot(full); res {
	case workfs.SlotDuplicate:
		return duplicateResponse(outcome, s.gen())
	case workfs.SlotRetired:
		return &Response{Status: EIO, Gen: s.gen()}
	case workfs.SlotConflict, workfs.SlotGap:
		return s.fenceCorrupt(env.SessionID, env.Generation)
	case workfs.SlotUnknownSession:
		return &Response{Status: ESTALE}
	}
	decision, err := decide(full)
	switch {
	case err == nil:
		resp := &Response{Status: decision.Status, Gen: s.gen()}
		resp.CheckoutEpoch = decision.Epoch
		return resp
	case errors.Is(err, workfs.ErrSessionStale):
		return &Response{Status: ESTALE}
	default:
		return nil // UNKNOWN (durability/poison): drop conn, client replays
	}
}

// coordinateLock is the managed OpLock mutation path (setlk/setlkw/unlock).
func (s *Server) coordinateLock(cs *connSession, store CoordinationStore, req *Request) *Response {
	env := req.Env
	if req.LkMode == LkGetlk {
		return &Response{Status: EINVAL} // queries never carry identities
	}
	start, length, ok := wireLockRange(req.LkStart, req.LkEnd)
	if !ok {
		return s.coordReject(env, staticRejectHash(EINVAL), EINVAL)
	}
	op := pfc2.LockSetRead
	switch {
	case req.LkUnlock:
		op = pfc2.LockUnlock
	case req.LkWrite:
		op = pfc2.LockSetWrite
	}
	ino := s.resolveLockIno(req)
	if ino == 0 {
		return s.coordReject(env, staticRejectHash(ENOENT), ENOENT)
	}
	reqHash, err := workfs.LockChangeRequestHash(env, ino, req.LkID, op, start, length)
	if err != nil {
		return &Response{Status: ESTALE}
	}
	if req.LkMode == LkSetlkw && op != pfc2.LockUnlock {
		// VOLATILE, cancelable wait BEFORE the identity is consumed: nothing
		// is journaled while waiting (no rejection slices), and a conflicting
		// live holder is never force-revoked. On budget expiry the single
		// decision below records at most ONE durable EAGAIN.
		owner := pfc2.LockOwner{
			Session:         pfc2.SessionRef{SessionID: cs.id, Generation: cs.gen},
			KernelLockOwner: req.LkID,
		}
		store.WaitCoordinationClear(time.Now().Add(setlkwWaitBudget), func() bool {
			_, conflicted, err := store.ManagedLockConflict(ino, owner, start, length, op == pfc2.LockSetWrite)
			return err == nil && !conflicted
		})
	}
	return s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
		return store.ManagedLockDecide(full, ino, req.LkID, op, start, length)
	})
}

// coordinateCheckout is the managed OpCheckout path: grant with the durable
// monotonic epoch (stored in the identity's slot outcome), or one durable
// EBUSY. Contention publishes a recall HINT and waits volatilely BEFORE the
// identity is consumed; a live holder is never force-transferred — it must
// check in, terminalize, or expire through a DB-time fact.
func (s *Server) coordinateCheckout(cs *connSession, store CoordinationStore, req *Request) *Response {
	env := req.Env
	reqHash, err := workfs.CheckoutRequestHash(env, false, req.Path, "")
	if err != nil {
		return &Response{Status: ESTALE}
	}
	if overlaps, _ := store.ManagedOverlappingCheckouts(req.Path); len(overlaps) > 0 {
		if s.recaller != nil {
			s.recaller.PublishRecall(req.Path) // a HINT to the holder, never authority
		}
		store.WaitCoordinationClear(time.Now().Add(recallTimeout), func() bool {
			overlaps, err := store.ManagedOverlappingCheckouts(req.Path)
			return err == nil && len(overlaps) == 0
		})
	}
	resp := s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
		return store.ManagedCheckoutDecide(full, req.Path)
	})
	if resp != nil && resp.Status == OK && resp.Duplicate && resp.CheckoutEpoch == "" && resp.Offset > 0 {
		// Duplicate replay: the granted epoch was stored in the durable slot
		// outcome (Offset as the exact decimal integer).
		if epoch, err := pfc2.EpochFromInt64(resp.Offset); err == nil {
			resp.CheckoutEpoch = string(epoch)
		}
	}
	if resp != nil && resp.Status == EBUSY && resp.Owner == "" {
		if overlaps, _ := store.ManagedOverlappingCheckouts(req.Path); len(overlaps) > 0 {
			resp.Owner = store.ManagedSessionOwner(overlaps[0].Holder) // debuggability (live reply only)
		}
	}
	return resp
}

// coordinateCheckin is the managed OpCheckin path: release of exactly the
// caller's live (path, epoch) grant, or one durable ENOENT — never another
// owner's grant.
func (s *Server) coordinateCheckin(store CoordinationStore, req *Request) *Response {
	env := req.Env
	if req.CheckoutEpoch == "" {
		return s.coordReject(env, staticRejectHash(EINVAL), EINVAL)
	}
	reqHash, err := workfs.CheckoutRequestHash(env, true, req.Path, req.CheckoutEpoch)
	if err != nil {
		return &Response{Status: ESTALE}
	}
	return s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
		return store.ManagedCheckinDecide(full, req.Path, req.CheckoutEpoch)
	})
}

// coordinatePin is the managed OpMarkOpen path: one atomic existence
// decision + pin transition + identity outcome in one journal row.
func (s *Server) coordinatePin(store CoordinationStore, req *Request) *Response {
	env := req.Env
	unpin := !req.OpenState
	if req.OpenIno == 0 {
		return s.coordReject(env, staticRejectHash(EINVAL), EINVAL)
	}
	reqHash := pinRequestHash(req.OpenIno, unpin)
	return s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
		switch cerr := store.ManagedPinChange(full, req.OpenIno, unpin, reqHash); {
		case cerr == nil:
			return workfs.CoordinationDecision{}, nil
		case errors.Is(cerr, workfs.ErrPinTargetGone):
			// The ENOENT outcome is ALREADY durably journaled by the same row.
			return workfs.CoordinationDecision{Status: ENOENT}, nil
		default:
			return workfs.CoordinationDecision{}, cerr
		}
	})
}

// maxUnmarkBatchInos bounds one OpUnmarkOpenInodes request (the client
// flushes in batches of 512; the bound only refuses runaway input, as a
// durable EINVAL so the identity is still consumed).
const maxUnmarkBatchInos = 4096

// coordinateUnpinBatch is the managed OpUnmarkOpenInodes path
// (baseline open registration): the deferred last-close unmarks release as ONE
// journal row — the identity's durable outcome plus one unpin transition per
// held pin — under ONE exact identity. Per-ino semantics match the legacy
// batch exactly (release what is held, idempotently skip the rest; a close
// carries no open-vs-unlink guarantee), the batch only removes the per-inode
// round-trips, and the identical resend replays the stored outcome without
// re-applying. Each released pin's inode becomes a reap candidate through
// the same applied-row scheduling as a single unpin.
func (s *Server) coordinateUnpinBatch(store CoordinationStore, req *Request) *Response {
	env := req.Env
	if len(req.OpenInos) > maxUnmarkBatchInos {
		return s.coordReject(env, staticRejectHash(EINVAL), EINVAL)
	}
	reqHash := unpinBatchRequestHash(req.OpenInos)
	return s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
		if err := store.ManagedUnpinBatch(full, req.OpenInos, reqHash); err != nil {
			return workfs.CoordinationDecision{}, err
		}
		return workfs.CoordinationDecision{}, nil
	})
}

// registerCreateOpenManaged fuses Stage-2 open registration into a managed
// OpCreate reply (Request.RegisterOpen on the managed
// generation). The create itself is the exact journaled mutation whose
// durable outcome names the inode the path bound to at the create's ordered
// position; this step then ensures the session's durable open pin on that
// inode — its own journaled coordination row, idempotent per (session, ino)
// — BEFORE the reply leaves the server. It runs on fresh executions AND
// duplicate exact replays, mirroring the legacy fused create: a duplicate
// replay returns the stored create outcome and re-ensures (never
// double-pins) the pin, which is also what repairs a crash between the
// create row and the pin row — no reply was emitted, so the client replays
// the identical identity and the ensure step converges. If the inode is
// already gone (a peer unlink won and the reap landed), the reply degrades
// to ENOENT exactly like the two-RPC create-then-MarkOpen flow.
func (s *Server) registerCreateOpenManaged(cs *connSession, req *Request, resp *Response) *Response {
	store := s.coordStore()
	if store == nil || !cs.attached() {
		// The managed create path only replies OK through an attached exact
		// session, so this is defense in depth.
		return &Response{Status: EPERM}
	}
	ino := resp.Ino
	if ino == 0 && resp.Attr != nil {
		ino = resp.Attr.Ino
	}
	if ino == 0 {
		// A stored outcome that carries no ino (paranoia; managed outcomes
		// record the bound inode): resolve the name's CURRENT binding — the
		// same inode the two-RPC client would have re-stat'ed and marked.
		if fi, err := s.fs.Lstat(req.Path); err == nil {
			a := attrOf(fi)
			ino = a.Ino
		}
	}
	if ino == 0 {
		return &Response{Status: ENOENT, Gen: s.gen()}
	}
	ref := pfc2.SessionRef{SessionID: cs.id, Generation: cs.gen}
	switch err := store.ManagedEnsureOpenPin(ref, ino); {
	case err == nil:
		if resp.Ino == 0 {
			// Report the inode the pin was ensured on, so the client
			// refcounts (and eventually unmarks) exactly this ino.
			resp.Ino = ino
		}
		return resp
	case errors.Is(err, workfs.ErrPinTargetGone):
		return &Response{Status: ENOENT, Gen: s.gen()}
	case errors.Is(err, workfs.ErrSessionStale):
		return &Response{Status: ESTALE}
	default:
		// UNKNOWN (durability/poison): drop the conn without a reply; the
		// client replays the identical create identity and the ensure step
		// re-runs against the stored outcome.
		return nil
	}
}

// coordinateBarrier is the managed OpFsync path with an exact identity: one
// journaled control-only no-op row whose ordered apply proves every earlier
// row is durable, applied, and published (the volume sync barrier) — then a
// wait for every live subscriber to acknowledge the covering invalidation
// position, making the completed barrier immediately visible to every
// connected peer's subsequent reads. The subscriber wait runs on duplicate
// replays too: an unresolved barrier retried by the client still owes the
// cross-machine guarantee.
func (s *Server) coordinateBarrier(cs *connSession, req *Request) *Response {
	store := s.coordStore()
	if store == nil {
		return &Response{Status: EPERM}
	}
	env := req.Env
	if !cs.attached() || env == nil || env.SessionID != cs.id || env.Generation != cs.gen || env.SlotSeq == 0 {
		return &Response{Status: ESTALE}
	}
	if !s.admissible(env.SessionID) {
		return nil // projected-expired lease: fail closed, consume nothing
	}
	reqHash := barrierRequestHash(env)
	resp := s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
		if err := store.ManagedSyncBarrierRow(full, reqHash); err != nil {
			return workfs.CoordinationDecision{}, err
		}
		return workfs.CoordinationDecision{}, nil
	})
	if resp == nil || resp.Status != OK {
		return resp
	}
	if st := s.awaitSubscriberAcks(s.notifierPosition()); st != OK {
		// The barrier's rows are durable and applied, but a LIVE subscriber
		// did not acknowledge the invalidations within the bound: the
		// barrier fails typed rather than claiming cross-machine
		// visibility it cannot prove. (The identity is consumed; the
		// caller's retry uses a fresh identity and re-waits.)
		return &Response{Status: st, Gen: s.gen()}
	}
	return resp
}

// flushBatchManaged applies one dense same-scope run of a mount write-back
// stream as ordered PFJ3 rows (one record per row with its FlushAdvance in
// the same row) after validating the attached session, the delegation grant,
// and the per-record subtree bounds. The stream's durable watermark + digest
// ARE the exactness: a lost-reply retry resends identical bytes and the
// authority drops the covered prefix, so no per-RPC slot identity is needed.
func (s *Server) flushBatchManaged(cs *connSession, req *Request) *Response {
	store := s.coordStore()
	if store == nil {
		return &Response{Status: EPERM}
	}
	if !cs.attached() {
		return &Response{Status: ESTALE}
	}
	if !s.admissible(cs.id) {
		return nil // projected-expired lease: fail closed, consume nothing
	}
	if req.CheckoutPath == "" || req.CheckoutEpoch == "" || req.SessionID == "" {
		return &Response{Status: EINVAL}
	}
	if len(req.Records) > MaxBatchRecords {
		return &Response{Status: EINVAL}
	}
	ref := pfc2.SessionRef{SessionID: cs.id, Generation: cs.gen}
	cleanCheckout := cleanWirePath(req.CheckoutPath)
	rows := make([]workfs.ManagedFlushRow, 0, len(req.Records))
	for i := range req.Records {
		r := req.Records[i]
		if r.Op.IsControl() {
			// Managed flushes carry watermarks natively as FlushAdvance; a
			// legacy control record here is a protocol violation.
			return &Response{Status: EINVAL}
		}
		if isReserved(r.Path) || isReserved(r.NewPath) {
			return &Response{Status: EINVAL}
		}
		// Containment must be tested on the canonical path the authority will
		// actually apply (cleanPath resolves ".." at apply time), not the raw
		// wire path: a byte-prefix test on "work/../victim" passes for a "work"
		// grant yet writes to "victim". isReserved above already canonicalizes.
		if !pathWithin(cleanWirePath(r.Path), cleanCheckout) || (r.NewPath != "" && !pathWithin(cleanWirePath(r.NewPath), cleanCheckout)) {
			return &Response{Status: EPERM} // records (rename pair included) must stay inside the granted subtree
		}
		seq := r.Seq
		r.Seq = 0
		rows = append(rows, workfs.ManagedFlushRow{Seq: seq, Record: r})
	}
	var prev, end [32]byte
	if len(req.WBPrevDigest) == 32 {
		copy(prev[:], req.WBPrevDigest)
	}
	if len(req.WBEndDigest) == 32 {
		copy(end[:], req.WBEndDigest)
	}
	through, err := store.ManagedFlushApply(ref, req.SessionID, req.CheckoutPath, req.CheckoutEpoch, prev, end, rows, cs.owner)
	if err != nil {
		if errors.Is(err, workfs.ErrSessionStale) {
			return &Response{Status: ESTALE, AppliedThrough: through}
		}
		if errors.Is(err, workfs.ErrWritebackCorrupt) {
			return &Response{Status: EINVAL, AppliedThrough: through, Gen: s.gen()}
		}
		if errors.Is(err, workfs.ErrSessionExpiryPending) {
			return &Response{Status: EAGAIN, AppliedThrough: through, Gen: s.gen()}
		}
		if errors.Is(err, workfs.ErrDurabilityUnknown) || errors.Is(err, wal.ErrPoisoned) {
			return nil // UNKNOWN: drop conn; the retry re-reads the durable watermark
		}
		return &Response{Status: toErrno(err), AppliedThrough: through}
	}
	return &Response{AppliedThrough: through, Gen: s.gen()}
}

// coordinateDelegationAcquire is the adaptive grant decision: the volatile
// policy (recall cooldown, scope shape, snapshot bound) runs first; an
// eligible uncontended scope commits the durable grant and returns the
// authoritative children snapshot, everything else answers a durable EBUSY
// and the client runs write-through. The path is canonicalized ONCE here and
// only the canonical value flows downstream (policy, durable decision,
// snapshot), so alias spellings share one identity.
func (s *Server) coordinateDelegationAcquire(cs *connSession, store CoordinationStore, req *Request) *Response {
	_ = cs
	env := req.Env
	if req.SessionID == "" {
		return s.coordReject(env, staticRejectHash(EINVAL), EINVAL)
	}
	scope := cleanWirePath(req.Path)
	if verdict := s.delegations.policyVerdict(scope); verdict != OK {
		return s.coordReject(env, staticRejectHash(verdict), verdict)
	}
	// Scope-shape policy: only an EXISTING DIRECTORY whose child set fits
	// the grant bound is delegable. Everything else is a durable decline —
	// the operation runs write-through. (Volatile pre-checks; the durable
	// overlap decision happens inside the journaled decide.)
	fi, err := s.fs.Lstat(scope)
	if err != nil || !fi.IsDir() {
		return s.coordReject(env, staticRejectHash(EBUSY), EBUSY)
	}
	if fis, err := s.fs.ReadDir(scope); err != nil || len(fis) > grantChildrenBound {
		return s.coordReject(env, staticRejectHash(EBUSY), EBUSY)
	}
	reqHash, err := workfs.DelegationRequestHash(env, scope, req.SessionID)
	if err != nil {
		return &Response{Status: ESTALE}
	}
	resp := s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
		return store.ManagedDelegationDecide(full, scope, req.SessionID)
	})
	if resp == nil {
		return nil
	}
	if resp.Status == OK && resp.Duplicate && resp.CheckoutEpoch == "" && resp.Offset > 0 {
		// Duplicate replay of a lost grant reply: the epoch was stored in
		// the durable slot outcome. The snapshot is not replayed; the client
		// re-seeds with one readdir under the held grant.
		if epoch, err := pfc2.EpochFromInt64(resp.Offset); err == nil {
			resp.CheckoutEpoch = string(epoch)
		}
		return resp
	}
	if resp.Status != OK || resp.CheckoutEpoch == "" {
		return resp
	}
	// Fresh grant: the grant is durable, and same-session write-through
	// mutations no longer bypass the peer gate, so the snapshot taken now is
	// the authoritative delegated view — nothing (peer or same-session) can
	// mutate the scope between the grant and this snapshot.
	s.fillGrantSnapshot(scope, resp)
	return resp
}

// grantChildrenBound declines a delegation whose initial snapshot would
// exceed this many children (the operation runs write-through instead).
const grantChildrenBound = 8192

// fillGrantSnapshot attaches the scope's self attr and its authoritative
// children snapshot to a fresh grant reply. The reply bound is REAL: a
// directory that grew past the grant bound between the policy pre-check and
// this snapshot ships no children (never an unbounded reply); the client
// then seeds with one readdir under the held grant.
func (s *Server) fillGrantSnapshot(path string, resp *Response) {
	fi, err := s.fs.Lstat(path)
	if err != nil || !fi.IsDir() {
		return
	}
	a := attrOf(fi)
	resp.Attr = &a
	fis, err := s.fs.ReadDir(path)
	if err != nil || len(fis) > grantChildrenBound {
		return
	}
	ents := make([]Dirent, 0, len(fis))
	for _, cfi := range fis {
		if isReserved(pathJoin(path, cfi.Name())) {
			continue
		}
		ents = append(ents, Dirent{Name: cfi.Name(), Attr: attrOf(cfi)})
	}
	resp.Entries = ents
}

// writebackStateRead answers OpWritebackState from the durable reducer.
func (s *Server) writebackStateRead(req *Request) *Response {
	store := s.coordStore()
	if store == nil {
		return &Response{Status: EPERM}
	}
	view, ok, err := store.ManagedWritebackState(req.SessionID)
	if err != nil {
		return &Response{Status: toErrno(err)}
	}
	resp := &Response{Gen: s.gen(), WBExists: ok}
	if ok {
		resp.AppliedThrough = view.Through
		resp.WBDigest = append([]byte(nil), view.Digest[:]...)
	}
	return resp
}

// rebindRequestHash fingerprints one stream-rebind identity.
func rebindRequestHash(writebackID string, scopes []WBScope, through uint64, digest []byte) []byte {
	h := sha256.New()
	h.Write([]byte("PFC2-WB-REBIND"))
	h.Write([]byte{0})
	str := func(v string) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(len(v)))
		h.Write(b[:])
		h.Write([]byte(v))
	}
	str(writebackID)
	for _, sc := range scopes {
		str(sc.Path)
		str(sc.Epoch)
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], through)
	h.Write(b[:])
	h.Write(digest)
	return h.Sum(nil)
}

// coordinateWritebackRebind claims a parked stream's recovery scopes for the
// caller's session. Typed conflicts return in the reply; nothing partial
// commits and nothing is guessed.
func (s *Server) coordinateWritebackRebind(store CoordinationStore, req *Request) *Response {
	env := req.Env
	if req.SessionID == "" {
		return s.coordReject(env, staticRejectHash(EINVAL), EINVAL)
	}
	scopes := make([]workfs.WritebackScope, 0, len(req.WBScopes))
	for _, sc := range req.WBScopes {
		scopes = append(scopes, workfs.WritebackScope{Path: sc.Path, Epoch: sc.Epoch})
	}
	var digest [32]byte
	copy(digest[:], req.WBPrevDigest)
	reqHash := rebindRequestHash(req.SessionID, req.WBScopes, req.WBThrough, req.WBPrevDigest)
	var conflicts []workfs.WritebackConflict
	resp := s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
		var err error
		conflicts, err = store.ManagedWritebackRebind(full, reqHash, req.SessionID, scopes, req.WBThrough, digest)
		if err != nil {
			return workfs.CoordinationDecision{}, err
		}
		if len(conflicts) > 0 {
			return workfs.CoordinationDecision{Status: EIO}, nil
		}
		return workfs.CoordinationDecision{}, nil
	})
	if resp != nil {
		for _, c := range conflicts {
			resp.WBConflicts = append(resp.WBConflicts, WBConflict{Path: c.Path, Epoch: c.Epoch, Kind: c.Kind})
		}
	}
	return resp
}

// coordinateWritebackDiscard releases a parked stream's recovery scopes as
// an audited data-loss decision.
func (s *Server) coordinateWritebackDiscard(store CoordinationStore, req *Request) *Response {
	env := req.Env
	if req.SessionID == "" {
		return s.coordReject(env, staticRejectHash(EINVAL), EINVAL)
	}
	scopes := make([]workfs.WritebackScope, 0, len(req.WBScopes))
	for _, sc := range req.WBScopes {
		scopes = append(scopes, workfs.WritebackScope{Path: sc.Path, Epoch: sc.Epoch})
	}
	reqHash := rebindRequestHash("discard\x00"+req.SessionID, req.WBScopes, 0, nil)
	return s.coordinateDecide(env, reqHash, func(full *wal.Envelope) (workfs.CoordinationDecision, error) {
		if err := store.ManagedWritebackDiscard(full, reqHash, req.SessionID, scopes); err != nil {
			return workfs.CoordinationDecision{}, err
		}
		return workfs.CoordinationDecision{}, nil
	})
}

func pathJoin(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// pathWithin reports whether p equals root or lies beneath it (both already
// wire-clean relative paths).
func pathWithin(p, root string) bool {
	if root == "" || p == root {
		return true
	}
	return len(p) > len(root) && p[:len(root)] == root && p[len(root)] == '/'
}
