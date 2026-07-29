package pfc2

import (
	"fmt"
	"sort"
)

// ApplyResult reports the observable effects of one applied record.
type ApplyResult struct {
	Kind Kind
	// NoOp reports the deterministic no-op transitions: an identical
	// idempotent SessionOpen re-send, a non-advancing renewal, or a
	// conditional expiry invalidated by a renewal ordered first.
	NoOp bool
	// SupersededGeneration is the lower live generation atomically fenced by
	// this SessionOpen (0 otherwise).
	SupersededGeneration uint64
	// NewlyUnpinnedInos lists inodes whose LAST durable open pin was released
	// by this record, ascending. The authority intersects them with its
	// orphan table to schedule authority-internal reap; PFC2 does not know
	// which inodes are orphans, and replay after a crash re-derives the same
	// schedule (a missed reap is a temporary leak, never a correctness loss).
	NewlyUnpinnedInos []uint64
	// GrantedEpoch is the checkout epoch a CheckoutGrant/ForceTransfer
	// installed (empty otherwise). The SAME value is stored in the identity's
	// durable slot outcome (Outcome.Offset as the decimal integer), so a
	// duplicate retry replays the exact granted epoch instead of guessing
	// from the current view.
	GrantedEpoch Epoch
}

// Txn is one atomic reducer transaction: the unit of "reservation staging"
// and of batch apply. It holds the state's write lock from Begin until Commit
// or Rollback. Records applied inside it become visible to queries only
// through the same state (queries block while it is open); Rollback restores
// the exact pre-transaction state byte-for-byte.
//
// Txn methods are not safe for concurrent use and must finish with exactly
// one Commit or Rollback; misuse panics.
type Txn struct {
	st    *State
	undos []func()
	done  bool
}

// Begin opens a transaction, taking the state's write lock.
func (st *State) Begin() *Txn {
	st.mu.Lock()
	return &Txn{st: st}
}

// Commit publishes every staged record and releases the lock.
func (tx *Txn) Commit() {
	if tx.done {
		panic("pfc2: transaction already finished")
	}
	tx.done = true
	tx.undos = nil
	tx.st.mu.Unlock()
}

// Rollback undoes every staged record in reverse order and releases the lock.
func (tx *Txn) Rollback() {
	if tx.done {
		panic("pfc2: transaction already finished")
	}
	tx.done = true
	for i := len(tx.undos) - 1; i >= 0; i-- {
		tx.undos[i]()
	}
	tx.undos = nil
	tx.st.mu.Unlock()
}

func (tx *Txn) push(undo func()) { tx.undos = append(tx.undos, undo) }

// Apply validates r completely against the staged state and then applies it.
// On error the staged state is EXACTLY as before this call (validation
// precedes every mutation); earlier records staged in this transaction remain
// staged, and the caller chooses Commit or Rollback.
func (tx *Txn) Apply(r *Record) (ApplyResult, error) {
	if tx.done {
		panic("pfc2: apply on a finished transaction")
	}
	if err := r.Validate(); err != nil {
		return ApplyResult{}, err
	}
	return tx.st.applyRecord(tx, r, false)
}

// Check dry-runs r against the staged state: it returns exactly the error
// Apply would return, without mutating anything. The result fields other than
// the error are not computed.
func (tx *Txn) Check(r *Record) error {
	if tx.done {
		panic("pfc2: check on a finished transaction")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	_, err := tx.st.applyRecord(nil, r, true)
	return err
}

// RecordExternalOutcome records the deterministically rebuilt outcome of one
// exact envelope carried by a PFR1 tree record. PFR1 records own their
// envelopes and replay them during tree apply, so they never get a second
// PFC2 commit boundary; this is the hook that advances the PFC2 slot table in
// the same transaction as the surrounding batch.
func (tx *Txn) RecordExternalOutcome(key ExactKey, out Outcome) error {
	if tx.done {
		panic("pfc2: record on a finished transaction")
	}
	if err := validateExactKey("external outcome", &key); err != nil {
		return err
	}
	st := tx.st
	s := st.liveSessionLocked(key.Session)
	if s == nil {
		return fencedf("external outcome targets non-live generation %v", key.Session)
	}
	if err := st.checkOutcomeSlot(s, key); err != nil {
		return err
	}
	tx.commitOutcomeSlot(s, key, out)
	return nil
}

// Apply applies one record as its own atomic transaction.
func (st *State) Apply(r *Record) (ApplyResult, error) {
	tx := st.Begin()
	res, err := tx.Apply(r)
	if err != nil {
		tx.Rollback()
		return ApplyResult{}, err
	}
	tx.Commit()
	return res, nil
}

// ApplyBatch applies records atomically in order: either every record applies
// or none does. Batches are bounded by MaxBatchRecords.
func (st *State) ApplyBatch(records []*Record) ([]ApplyResult, error) {
	if len(records) == 0 {
		return nil, malformedf("empty batch")
	}
	if len(records) > MaxBatchRecords {
		return nil, malformedf("batch has %d records (max %d)", len(records), MaxBatchRecords)
	}
	tx := st.Begin()
	results := make([]ApplyResult, 0, len(records))
	for i, r := range records {
		res, err := tx.Apply(r)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("batch record %d (%v): %w", i, r.Kind, err)
		}
		results = append(results, res)
	}
	tx.Commit()
	return results, nil
}

// Check dry-runs one record against the published state.
func (st *State) Check(r *Record) error {
	if err := r.Validate(); err != nil {
		return err
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	_, err := st.applyRecord(nil, r, true)
	return err
}

// RecordExternalOutcome records one PFR1-carried outcome as its own atomic
// transaction (replay of a single enveloped tree record).
func (st *State) RecordExternalOutcome(key ExactKey, out Outcome) error {
	tx := st.Begin()
	if err := tx.RecordExternalOutcome(key, out); err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()
	return nil
}

// applyRecord dispatches one structurally-valid record. dry runs validation
// only (tx may be nil); otherwise every mutation goes through tx primitives
// that stage undo entries. Callers hold the state lock.
func (st *State) applyRecord(tx *Txn, r *Record, dry bool) (ApplyResult, error) {
	switch r.Kind {
	case KindSessionOpen:
		return st.applySessionOpen(tx, r.SessionOpen, dry)
	case KindSessionRenew:
		return st.applySessionRenew(tx, r.SessionRenew, dry)
	case KindSessionTerminal:
		return st.applySessionTerminal(tx, r.SessionTerminal, dry)
	case KindExactOutcome:
		return st.applyExactOutcome(tx, r.ExactOutcome, dry)
	case KindOutcomeFloor:
		return st.applyOutcomeFloor(tx, r.OutcomeFloor, dry)
	case KindFlushAdvance:
		return st.applyFlushAdvance(tx, r.FlushAdvance, dry)
	case KindLockChange:
		return st.applyLockChange(tx, r.LockChange, dry)
	case KindCheckoutChange:
		return st.applyCheckoutChange(tx, r.CheckoutChange, dry)
	case KindOpenPinChange:
		return st.applyOpenPinChange(tx, r.OpenPinChange, dry)
	default:
		return ApplyResult{}, malformedf("unknown record kind %d", r.Kind)
	}
}

// ─── session lifecycle ──────────────────────────────────────────────────────

// sessionTupleIdentical compares the durable establish tuple. The admission
// fact's one-time identity is deliberately excluded: the reducer retains only
// the frozen source/time values (facts are consumed exactly once at append),
// so the comparison is identical before and after a projection rebuild.
func sessionTupleIdentical(s *sessionState, o *SessionOpen) bool {
	return s.owner == o.Owner && s.tokenHash == o.TokenHash && s.slots == o.Slots &&
		s.timeSource == o.Fact.Source && s.issuedDbMs == o.Fact.DbMs && s.expiresDbMs == o.ExpiresDbMs
}

// checkMintedAgainstFloor rejects any record whose minted database time
// regresses the durable floor. Correctly minted facts cannot regress: the
// fenced admission serializes with journal order, so a backward time proves a
// smuggled host wall clock, an old authority's straggler, or corruption.
func (st *State) checkMintedAgainstFloor(what string, mintedDbMs int64) error {
	if mintedDbMs < st.dbTimeFloorMs {
		return integrityf("%s carries database time %d behind the durable floor %d; wall-clock-skewed or non-database times are never authorized",
			what, mintedDbMs, st.dbTimeFloorMs)
	}
	return nil
}

func (st *State) applySessionOpen(tx *Txn, o *SessionOpen, dry bool) (ApplyResult, error) {
	res := ApplyResult{Kind: KindSessionOpen}
	cur := st.sessions[o.Session.SessionID]
	var supersedeLive *sessionState
	switch {
	case cur == nil:
		if st.liveSessions >= MaxLiveSessions {
			return res, capacityf("live sessions exhausted (%d)", MaxLiveSessions)
		}
		if len(st.sessions) >= MaxSessionEntries {
			return res, capacityf("session entries (live + tombstones) exhausted (%d); exactness is never forgotten to make room", MaxSessionEntries)
		}
	case cur.ref.Generation > o.Session.Generation:
		return res, fencedf("session %s: generation %d is older than the durable generation %d",
			o.Session.SessionID, o.Session.Generation, cur.ref.Generation)
	case cur.ref.Generation == o.Session.Generation:
		if cur.terminal {
			return res, fencedf("session %v: generation is terminal (%v); a fenced identity never reopens", o.Session, cur.reason)
		}
		if sessionTupleIdentical(cur, o) {
			// Idempotent re-send of a lost establish reply: byte-identical,
			// so its (already-applied) time facts never re-touch the floor.
			res.NoOp = true
			return res, nil
		}
		return res, fencedf("session %v: same generation presented with a different tuple", o.Session)
	default: // cur.ref.Generation < o.Session.Generation
		if cur.terminal {
			// The higher live generation subsumes the old tombstone's fencing:
			// every request below the current generation rejects as stale.
			if st.liveSessions >= MaxLiveSessions {
				return res, capacityf("live sessions exhausted (%d)", MaxLiveSessions)
			}
		} else {
			supersedeLive = cur
			res.SupersededGeneration = cur.ref.Generation
		}
	}
	if err := st.checkMintedAgainstFloor("session open", o.Fact.DbMs); err != nil {
		return res, err
	}
	if dry {
		return res, nil
	}
	if supersedeLive != nil {
		res.NewlyUnpinnedInos = tx.terminalize(supersedeLive, TerminalSupersede)
	}
	tx.setSession(o.Session.SessionID, &sessionState{
		ref: o.Session, owner: o.Owner, tokenHash: o.TokenHash, slots: o.Slots,
		timeSource: o.Fact.Source, issuedDbMs: o.Fact.DbMs, expiresDbMs: o.ExpiresDbMs,
		slotStates: map[uint32]*slotState{},
	})
	tx.setLiveSessions(st.liveSessions + 1)
	tx.setDbTimeFloor(o.Fact.DbMs)
	return res, nil
}

func (st *State) applySessionRenew(tx *Txn, rn *SessionRenew, dry bool) (ApplyResult, error) {
	res := ApplyResult{Kind: KindSessionRenew}
	s := st.liveSessionLocked(rn.Session)
	if s == nil {
		return res, fencedf("renewal targets non-live generation %v", rn.Session)
	}
	if s.tokenHash != rn.TokenHash {
		return res, fencedf("renewal credential mismatch for %v", rn.Session)
	}
	if err := st.checkMintedAgainstFloor("session renewal", rn.Fact.DbMs); err != nil {
		return res, err
	}
	// A lease is renewable only while database time has not passed its
	// deadline: the fenced admission proves liveness by minting a time below
	// it. An after-deadline renewal lost the race to expiry — the sweeper's
	// fence is already ordered or imminent — and is never journaled.
	if rn.Fact.DbMs >= s.expiresDbMs {
		return res, fencedf("renewal for %v was minted at %d, at or past the durable deadline %d; an elapsed lease never renews",
			rn.Session, rn.Fact.DbMs, s.expiresDbMs)
	}
	// Deadlines strictly advance. The admission suppresses (answers from
	// durable state) any renewal that would not move the deadline, so a
	// non-advancing renewal record is corruption, not a no-op.
	if rn.ExpiresDbMs <= s.expiresDbMs {
		return res, integrityf("renewal for %v does not advance the durable deadline (%d -> %d); stale or replayed renewals are rejected",
			rn.Session, s.expiresDbMs, rn.ExpiresDbMs)
	}
	if dry {
		return res, nil
	}
	oldExpires := s.expiresDbMs
	tx.push(func() { s.expiresDbMs = oldExpires })
	s.expiresDbMs = rn.ExpiresDbMs
	tx.setDbTimeFloor(rn.Fact.DbMs)
	return res, nil
}

func (st *State) applySessionTerminal(tx *Txn, t *SessionTerminal, dry bool) (ApplyResult, error) {
	res := ApplyResult{Kind: KindSessionTerminal}
	s := st.liveSessionLocked(t.Session)
	if s == nil {
		return res, fencedf("terminal targets non-live generation %v", t.Session)
	}
	if t.Reason == TerminalExpire {
		// The decision time is a minted database fact regardless of how the
		// race below resolves; it enters the floor either way.
		if err := st.checkMintedAgainstFloor("session expiry decision", t.DecisionFact.DbMs); err != nil {
			return res, err
		}
		if s.expiresDbMs > t.ObservedDeadlineDbMs {
			// A renewal ordered first invalidated the conditional expiry: the
			// observed deadline is no longer the durable one. Deterministic
			// no-op for coordination state; the floor still advances.
			if dry {
				res.NoOp = true
				return res, nil
			}
			tx.setDbTimeFloor(t.DecisionFact.DbMs)
			res.NoOp = true
			return res, nil
		}
		if s.expiresDbMs < t.ObservedDeadlineDbMs {
			return res, integrityf("expiry for %v observed deadline %d that was never durable (durable %d)",
				t.Session, t.ObservedDeadlineDbMs, s.expiresDbMs)
		}
		// Observed deadline is exactly the durable one. Validate() already
		// proved DecisionFact.DbMs >= ObservedDeadlineDbMs: database time
		// really passed the deadline; a local timer only scheduled the
		// re-check.
	}
	if dry {
		return res, nil
	}
	if t.Reason == TerminalExpire {
		tx.setDbTimeFloor(t.DecisionFact.DbMs)
	}
	res.NewlyUnpinnedInos = tx.terminalize(s, t.Reason)
	return res, nil
}

// terminalize applies the one atomic terminal transition: mark the generation
// terminal retaining its compact tombstone, retire detailed outcomes, release
// its locks, checkouts, and open pins, and invalidate its flush ledger. It
// returns the inodes whose last pin was released, ascending.
func (tx *Txn) terminalize(s *sessionState, reason TerminalReason) []uint64 {
	st := tx.st
	ref := s.ref

	prev := *s
	tx.push(func() { *s = prev })
	retired := len(s.slotStates)
	s.terminal, s.reason = true, reason
	s.owner, s.tokenHash, s.slots = "", [TokenHashBytes]byte{}, 0
	s.timeSource, s.issuedDbMs, s.expiresDbMs = 0, 0, 0
	s.slotStates = nil
	tx.setSlotStates(st.slotStates - retired)
	tx.setLiveSessions(st.liveSessions - 1)

	var lockInos []uint64
	for ino, set := range st.locks {
		for _, h := range set {
			if h.Owner.Session == ref {
				lockInos = append(lockInos, ino)
				break
			}
		}
	}
	sort.Slice(lockInos, func(i, j int) bool { return lockInos[i] < lockInos[j] })
	for _, ino := range lockInos {
		old := st.locks[ino]
		kept := make([]HeldLock, 0, len(old))
		for _, h := range old {
			if h.Owner.Session != ref {
				kept = append(kept, h)
			}
		}
		tx.setLocks(ino, kept)
	}

	// Delegation grants (bound to a write-back stream) are NEVER silently
	// released on holder death: they may cover unshipped acknowledged state,
	// so they flip to recovery-required and block peers until the stream
	// rebinds and drains, or an operator discards them. Plain coordination
	// checkouts release as before.
	var paths []string
	for p, g := range st.checkouts {
		if g.holder == ref {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		g := st.checkouts[p]
		if g.writebackID != "" {
			g.recovery = true
			tx.setCheckout(p, g)
		} else {
			tx.deleteCheckout(p)
		}
	}

	// Stream ledgers owned by the dead session survive exactly while a
	// recovery scope still references them (the recovering stream needs the
	// watermark + digest); a fully-released stream's entry drops with its
	// session.
	var wbids []string
	for id, e := range st.ledger {
		if e.owner == ref {
			wbids = append(wbids, id)
		}
	}
	sort.Strings(wbids)
	for _, id := range wbids {
		referenced := false
		for _, g := range st.checkouts {
			if g.writebackID == id {
				referenced = true
				break
			}
		}
		if !referenced {
			tx.deleteLedger(id)
		}
	}

	var pinInos []uint64
	for ino, holders := range st.pins {
		if _, ok := holders[ref]; ok {
			pinInos = append(pinInos, ino)
		}
	}
	sort.Slice(pinInos, func(i, j int) bool { return pinInos[i] < pinInos[j] })
	var released []uint64
	for _, ino := range pinInos {
		if tx.removePin(ref, ino) {
			released = append(released, ino)
		}
	}
	return released
}

// ─── exact outcomes and floors ──────────────────────────────────────────────

// checkOutcomeSlot validates one outcome transition without mutating.
func (st *State) checkOutcomeSlot(s *sessionState, key ExactKey) error {
	if key.Slot >= s.slots {
		return integrityf("slot %d is outside %v's granted window of %d", key.Slot, s.ref, s.slots)
	}
	ss := s.slotStates[key.Slot]
	if ss == nil {
		if key.SlotSeq != 1 {
			return integrityf("first outcome on %v slot %d must carry sequence 1 (got %d)", s.ref, key.Slot, key.SlotSeq)
		}
		if st.slotStates >= MaxSlotStates {
			return capacityf("slot states exhausted (%d)", MaxSlotStates)
		}
		return nil
	}
	if key.SlotSeq != ss.nextSeq {
		return integrityf("%v slot %d expects sequence %d; record carries %d (duplicate, retired, or gapped)",
			s.ref, key.Slot, ss.nextSeq, key.SlotSeq)
	}
	return nil
}

// commitOutcomeSlot installs the outcome as the slot's latest, implicitly
// retiring the previous latest: admitting N proves the client definitively
// completed N-1.
func (tx *Txn) commitOutcomeSlot(s *sessionState, key ExactKey, out Outcome) {
	ss := s.slotStates[key.Slot]
	if ss == nil {
		slots := s.slotStates
		tx.push(func() { delete(slots, key.Slot) })
		slots[key.Slot] = &slotState{nextSeq: 2, latest: &latestOutcome{seq: 1, hash: key.RequestHash, out: out}}
		tx.setSlotStates(tx.st.slotStates + 1)
		return
	}
	prevNext, prevLatest := ss.nextSeq, ss.latest
	tx.push(func() { ss.nextSeq, ss.latest = prevNext, prevLatest })
	ss.latest = &latestOutcome{seq: key.SlotSeq, hash: key.RequestHash, out: out}
	ss.nextSeq = key.SlotSeq + 1
}

func (st *State) applyExactOutcome(tx *Txn, o *ExactOutcome, dry bool) (ApplyResult, error) {
	res := ApplyResult{Kind: KindExactOutcome}
	s := st.liveSessionLocked(o.Key.Session)
	if s == nil {
		return res, fencedf("exact outcome targets non-live generation %v", o.Key.Session)
	}
	if err := st.checkOutcomeSlot(s, o.Key); err != nil {
		return res, err
	}
	if dry {
		return res, nil
	}
	tx.commitOutcomeSlot(s, o.Key, o.Outcome)
	return res, nil
}

func (st *State) applyOutcomeFloor(tx *Txn, f *OutcomeFloor, dry bool) (ApplyResult, error) {
	res := ApplyResult{Kind: KindOutcomeFloor}
	s := st.liveSessionLocked(f.Session)
	if s == nil {
		return res, fencedf("outcome floor targets non-live generation %v", f.Session)
	}
	if f.Slot >= s.slots {
		return res, integrityf("slot %d is outside %v's granted window of %d", f.Slot, s.ref, s.slots)
	}
	ss := s.slotStates[f.Slot]
	if ss == nil || ss.latest == nil {
		return res, integrityf("%v slot %d has no idle latest outcome to acknowledge", f.Session, f.Slot)
	}
	if f.Through != ss.latest.seq {
		return res, integrityf("%v slot %d floor %d does not acknowledge the latest sequence %d",
			f.Session, f.Slot, f.Through, ss.latest.seq)
	}
	if dry {
		return res, nil
	}
	prevLatest := ss.latest
	tx.push(func() { ss.latest = prevLatest })
	ss.latest = nil // retiredThrough advances to nextSeq-1
	return res, nil
}

// ─── flush ledger ───────────────────────────────────────────────────────────

func (st *State) applyFlushAdvance(tx *Txn, f *FlushAdvance, dry bool) (ApplyResult, error) {
	res := ApplyResult{Kind: KindFlushAdvance}
	s := st.liveSessionLocked(f.Session)
	if s == nil {
		return res, fencedf("flush advance targets non-live generation %v", f.Session)
	}
	g, ok := st.checkouts[f.CheckoutPath]
	if !ok || g.holder != f.Session || g.epoch != f.CheckoutEpoch {
		return res, fencedf("flush advance names checkout %q epoch %s that is not the live grant (released or transferred flushes are stale)",
			f.CheckoutPath, f.CheckoutEpoch)
	}
	if g.recovery {
		return res, fencedf("flush advance names recovery-required scope %q; the stream must rebind first", f.CheckoutPath)
	}
	if g.writebackID != f.WritebackID {
		// Never echo the grant's true stream ID (a recovery capability).
		return res, integrityf("flush advance stream %q does not match the grant's stream", f.WritebackID)
	}
	cur, exists := st.ledger[f.WritebackID]
	if exists && f.Through <= cur.through {
		return res, integrityf("flush advance to %d does not advance the durable watermark %d", f.Through, cur.through)
	}
	if !exists && len(st.ledger) >= MaxFlushEntries {
		return res, capacityf("flush ledger exhausted (%d)", MaxFlushEntries)
	}
	if dry {
		return res, nil
	}
	tx.setLedger(f.WritebackID, ledgerEntry{through: f.Through, digest: f.Digest, owner: f.Session})
	return res, nil
}

// ─── locks ──────────────────────────────────────────────────────────────────

func (st *State) applyLockChange(tx *Txn, l *LockChange, dry bool) (ApplyResult, error) {
	res := ApplyResult{Kind: KindLockChange}
	s := st.liveSessionLocked(l.Key.Session)
	if s == nil {
		return res, fencedf("lock change targets non-live generation %v", l.Key.Session)
	}
	if err := st.checkOutcomeSlot(s, l.Key); err != nil {
		return res, err
	}
	owner := LockOwner{Session: l.Key.Session, KernelLockOwner: l.KernelLockOwner}
	start, end := l.Start, lockEnd(l.Start, l.Length)
	set := st.locks[l.Ino]
	var next []HeldLock
	switch l.Op {
	case LockSetRead, LockSetWrite:
		write := l.Op == LockSetWrite
		if h, conflict := lockConflict(set, owner, start, end, write); conflict {
			return res, integrityf("granted lock on ino %d conflicts with %v [%d,%d]", l.Ino, h.Owner, h.Start, h.End)
		}
		next = setLockRange(set, owner, start, end, write)
	case LockUnlock:
		next = unlockRange(set, owner, start, end)
	}
	if len(next) > MaxInodeIntervals {
		return res, capacityf("ino %d would hold %d intervals (max %d)", l.Ino, len(next), MaxInodeIntervals)
	}
	if grow := len(next) - len(set); grow > 0 && st.lockCount+grow > MaxLockIntervals {
		return res, capacityf("lock intervals exhausted (%d)", MaxLockIntervals)
	}
	if dry {
		return res, nil
	}
	tx.commitOutcomeSlot(s, l.Key, l.Outcome)
	tx.setLocks(l.Ino, next)
	return res, nil
}

// ─── checkouts ──────────────────────────────────────────────────────────────

func (st *State) applyCheckoutChange(tx *Txn, c *CheckoutChange, dry bool) (ApplyResult, error) {
	res := ApplyResult{Kind: KindCheckoutChange}
	var s *sessionState
	if c.Op.keyed() {
		s = st.liveSessionLocked(c.Key.Session)
		if s == nil {
			return res, fencedf("checkout change targets non-live generation %v", c.Key.Session)
		}
		if err := st.checkOutcomeSlot(s, c.Key); err != nil {
			return res, err
		}
	}
	switch c.Op {
	case CheckoutGrant:
		if conflicts := st.overlappingCheckoutsLocked(c.Path); len(conflicts) != 0 {
			return res, integrityf("grant of %q overlaps existing checkout %q", c.Path, conflicts[0].Path)
		}
		if c.Epoch != st.nextEpoch {
			return res, integrityf("grant epoch %s is not the server-controlled next epoch %s", c.Epoch, st.nextEpoch)
		}
		nextEpoch, err := st.nextEpoch.Next()
		if err != nil {
			return res, err
		}
		if len(st.checkouts) >= MaxCheckouts {
			return res, capacityf("checkouts exhausted (%d)", MaxCheckouts)
		}
		if dry {
			return res, nil
		}
		// The durable slot outcome stores the granted epoch (Offset as the
		// decimal integer): a duplicate retry replays the EXACT grant, never
		// a guess from the current view. Deterministic on replay — the epoch
		// is the record's own field.
		tx.commitOutcomeSlot(s, c.Key, grantOutcome(c.Epoch))
		tx.setCheckout(c.Path, checkoutGrant{holder: c.Key.Session, epoch: c.Epoch, writebackID: c.WritebackID})
		tx.setNextEpoch(nextEpoch)
		res.GrantedEpoch = c.Epoch
	case CheckoutRelease:
		g, ok := st.checkouts[c.Path]
		if !ok || g.holder != c.Key.Session || g.epoch != c.Epoch {
			return res, fencedf("release names checkout %q epoch %s that is not the caller's live grant", c.Path, c.Epoch)
		}
		if g.recovery {
			return res, fencedf("release names recovery-required scope %q; only rebind or discard resolve it", c.Path)
		}
		if dry {
			return res, nil
		}
		tx.commitOutcomeSlot(s, c.Key, c.Outcome)
		tx.deleteCheckout(c.Path)
	case CheckoutForceTransfer:
		conflicts := st.overlappingCheckoutsLocked(c.Path)
		if len(conflicts) == 0 {
			return res, integrityf("force transfer of %q found no conflicting grants (an ordinary grant must be used)", c.Path)
		}
		for _, conflict := range conflicts {
			if conflict.WritebackID != "" {
				// A delegation may cover unshipped acknowledged state; force
				// transfer would silently discard it (recovery/discard are
				// the only paths past a dead holder).
				return res, integrityf("force transfer of %q would revoke delegation %q; delegations are never force-transferred", c.Path, conflict.Path)
			}
		}
		if RecallDigest(conflicts) != c.RecalledDigest {
			return res, integrityf("force transfer of %q carries a stale recalled-conflict digest: the conflict set changed after the recall", c.Path)
		}
		if c.Epoch != st.nextEpoch {
			return res, integrityf("transfer epoch %s is not the server-controlled next epoch %s", c.Epoch, st.nextEpoch)
		}
		nextEpoch, err := st.nextEpoch.Next()
		if err != nil {
			return res, err
		}
		if dry {
			return res, nil
		}
		tx.commitOutcomeSlot(s, c.Key, grantOutcome(c.Epoch))
		for _, conflict := range conflicts {
			tx.deleteCheckout(conflict.Path)
		}
		tx.setCheckout(c.Path, checkoutGrant{holder: c.Key.Session, epoch: c.Epoch})
		tx.setNextEpoch(nextEpoch)
		res.GrantedEpoch = c.Epoch
	case CheckoutRebind:
		g, ok := st.checkouts[c.Path]
		if !ok || g.epoch != c.Epoch || g.writebackID != c.WritebackID {
			return res, fencedf("rebind names checkout %q epoch %s stream %q that is not durable state", c.Path, c.Epoch, c.WritebackID)
		}
		if !g.recovery {
			return res, integrityf("rebind of %q requires the recovery-required state (the holder is still bound)", c.Path)
		}
		holder := st.liveSessionLocked(c.NewHolder)
		if holder == nil {
			return res, fencedf("rebind targets non-live generation %v", c.NewHolder)
		}
		if dry {
			return res, nil
		}
		g.holder = c.NewHolder
		g.recovery = false
		tx.setCheckout(c.Path, g)
		if e, ok := st.ledger[c.WritebackID]; ok {
			e.owner = c.NewHolder
			tx.setLedger(c.WritebackID, e)
		}
	case CheckoutDiscard:
		g, ok := st.checkouts[c.Path]
		if !ok || g.epoch != c.Epoch || g.writebackID != c.WritebackID {
			return res, fencedf("discard names checkout %q epoch %s stream %q that is not durable state", c.Path, c.Epoch, c.WritebackID)
		}
		if !g.recovery {
			return res, integrityf("discard of %q requires the recovery-required state (a live grant releases normally)", c.Path)
		}
		if dry {
			return res, nil
		}
		tx.deleteCheckout(c.Path)
		remaining := false
		for _, other := range st.checkouts {
			if other.writebackID == c.WritebackID {
				remaining = true
				break
			}
		}
		if !remaining {
			tx.deleteLedger(c.WritebackID)
		}
	}
	return res, nil
}

// grantOutcome is the durable slot outcome of a checkout grant: success with
// the granted decimal epoch in Offset. The epoch domain is bounded to int64
// (EpochBound), so the conversion is exact; a malformed epoch cannot reach
// here (Record.Validate enforced the canonical decimal domain).
func grantOutcome(epoch Epoch) Outcome {
	v, err := epoch.Int64()
	if err != nil {
		// Unreachable for validated records; store plain success rather than
		// guessing an epoch.
		return Outcome{}
	}
	return Outcome{Offset: v}
}

// ─── open pins ──────────────────────────────────────────────────────────────

func (st *State) applyOpenPinChange(tx *Txn, p *OpenPinChange, dry bool) (ApplyResult, error) {
	res := ApplyResult{Kind: KindOpenPinChange}
	s := st.liveSessionLocked(p.Session)
	if s == nil {
		return res, fencedf("open pin change targets non-live generation %v", p.Session)
	}
	_, held := st.pins[p.Ino][p.Session]
	if p.Unpin {
		if !held {
			return res, integrityf("unpin of ino %d without a durable pin for %v", p.Ino, p.Session)
		}
		if dry {
			return res, nil
		}
		if tx.removePin(p.Session, p.Ino) {
			res.NewlyUnpinnedInos = []uint64{p.Ino}
		}
		return res, nil
	}
	if held {
		return res, integrityf("pin of ino %d already held by %v", p.Ino, p.Session)
	}
	if st.pinCount >= MaxOpenPins {
		return res, capacityf("open pins exhausted (%d)", MaxOpenPins)
	}
	if dry {
		return res, nil
	}
	tx.addPin(p.Session, p.Ino)
	return res, nil
}

// ─── staged mutation primitives (undo-logged) ───────────────────────────────

func (tx *Txn) setLiveSessions(n int) {
	old := tx.st.liveSessions
	tx.push(func() { tx.st.liveSessions = old })
	tx.st.liveSessions = n
}

func (tx *Txn) setSlotStates(n int) {
	old := tx.st.slotStates
	tx.push(func() { tx.st.slotStates = old })
	tx.st.slotStates = n
}

func (tx *Txn) setSession(id string, s *sessionState) {
	st := tx.st
	prev, had := st.sessions[id]
	tx.push(func() {
		if had {
			st.sessions[id] = prev
		} else {
			delete(st.sessions, id)
		}
	})
	st.sessions[id] = s
}

func (tx *Txn) setLocks(ino uint64, set []HeldLock) {
	st := tx.st
	old, had := st.locks[ino]
	oldCount := st.lockCount
	tx.push(func() {
		if had {
			st.locks[ino] = old
		} else {
			delete(st.locks, ino)
		}
		st.lockCount = oldCount
	})
	st.lockCount += len(set) - len(old)
	if len(set) == 0 {
		delete(st.locks, ino)
	} else {
		st.locks[ino] = set
	}
}

func (tx *Txn) setCheckout(path string, g checkoutGrant) {
	st := tx.st
	prev, had := st.checkouts[path]
	tx.push(func() {
		if had {
			st.checkouts[path] = prev
		} else {
			delete(st.checkouts, path)
		}
	})
	st.checkouts[path] = g
}

func (tx *Txn) deleteCheckout(path string) {
	st := tx.st
	prev, had := st.checkouts[path]
	if !had {
		return
	}
	tx.push(func() { st.checkouts[path] = prev })
	delete(st.checkouts, path)
}

func (tx *Txn) setLedger(writebackID string, e ledgerEntry) {
	st := tx.st
	prev, had := st.ledger[writebackID]
	tx.push(func() {
		if had {
			st.ledger[writebackID] = prev
		} else {
			delete(st.ledger, writebackID)
		}
	})
	st.ledger[writebackID] = e
}

func (tx *Txn) deleteLedger(writebackID string) {
	st := tx.st
	prev, had := st.ledger[writebackID]
	if !had {
		return
	}
	tx.push(func() { st.ledger[writebackID] = prev })
	delete(st.ledger, writebackID)
}

func (tx *Txn) addPin(ref SessionRef, ino uint64) {
	st := tx.st
	holders, had := st.pins[ino]
	if !had {
		holders = map[SessionRef]struct{}{}
		st.pins[ino] = holders
	}
	tx.push(func() {
		delete(holders, ref)
		if !had {
			delete(st.pins, ino)
		}
		st.pinCount--
	})
	holders[ref] = struct{}{}
	st.pinCount++
}

// removePin releases one pin and reports whether it was the inode's last.
func (tx *Txn) removePin(ref SessionRef, ino uint64) bool {
	st := tx.st
	holders := st.pins[ino]
	last := len(holders) == 1
	tx.push(func() {
		holders[ref] = struct{}{}
		st.pins[ino] = holders
		st.pinCount++
	})
	delete(holders, ref)
	if last {
		delete(st.pins, ino)
	}
	st.pinCount--
	return last
}

func (tx *Txn) setNextEpoch(e Epoch) {
	old := tx.st.nextEpoch
	tx.push(func() { tx.st.nextEpoch = old })
	tx.st.nextEpoch = e
}

// setDbTimeFloor advances the durable database-time floor (monotonic max).
func (tx *Txn) setDbTimeFloor(mintedDbMs int64) {
	if mintedDbMs <= tx.st.dbTimeFloorMs {
		return
	}
	old := tx.st.dbTimeFloorMs
	tx.push(func() { tx.st.dbTimeFloorMs = old })
	tx.st.dbTimeFloorMs = mintedDbMs
}
