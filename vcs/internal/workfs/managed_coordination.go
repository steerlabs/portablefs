package workfs

// Managed (PFJ3/PFC2) coordination bridge: locks, checkouts, open pins, flush
// rows, reap scheduling, and the volume sync barrier — every decision is one
// ordered journal row through CommitEntry, validated against the reservation-
// order reducer under fs.mu, durable through the fenced database transaction,
// applied to the applied-order reducer, and only then replied. On a managed
// generation NO state-changing coordination touches the legacy in-memory lock
// manager, delegation manager, open-inode map, orphan lease clock, or reclaim
// grace; those exist only for legacy-pair authorities.
//
// Exactness: ONE fs.mu reservation observes the staged state and emits either
// the granted decision row (LockChange/CheckoutChange carry their own
// ExactKey; pin transitions ride an ExactOutcome in the same row) or a
// control-only exact REJECTION row (EAGAIN/EBUSY/ENOENT/EDQUOT/...) under the
// SAME canonical request fingerprint — never a protocol pre-check followed by
// a later journal write. Every consumed identity therefore has exactly one
// durable applied outcome; the same fingerprint replays it, a changed
// fingerprint fences the generation (TerminalSlotCorruption), and gaps fence.
// Reserved-but-unapplied state never acknowledges anything.

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/errnos"
	"github.com/trendup-ai/portablefs/vcs/internal/pfc2"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// ErrCoordinationConflict is the typed "definite conflict at this ordered
// position" outcome for managed coordination acquires: a foreign lock range
// (EAGAIN) or an overlapping foreign checkout (EBUSY). The caller records the
// canonical errno as a durable ExactOutcome and replies definitively.
var ErrCoordinationConflict = errors.New("vcs: managed coordination conflict")

// ErrPinTargetGone is the typed decision that a MarkOpen target inode is
// neither live nor parked at the decision's ordered position (durable ENOENT).
var ErrPinTargetGone = errors.New("vcs: open-pin target inode is neither live nor parked")

// ErrSessionExpiryPending fails a session closed between its PROJECTED local
// deadline (database facts anchored to the local monotonic clock) and the
// durable resolution: nothing is consumed and nothing terminal is claimed —
// the caller retries the identical identity until a database renewal advances
// the deadline or a durable terminal commits (then ESTALE with proof).
var ErrSessionExpiryPending = errors.New("vcs: session lease projected-expired; failing closed until the database renews or commits terminal")

// managedSessionRef authenticates env against the managed reducers and
// returns its SessionRef.
func managedSessionRef(env *wal.Envelope) (pfc2.SessionRef, error) {
	if env == nil || !env.Valid() {
		return pfc2.SessionRef{}, ErrSessionStale
	}
	return pfc2.SessionRef{SessionID: env.SessionID, Generation: env.Generation}, nil
}

// CoordinationDecision is the durable applied outcome of one coordination
// identity: the canonical wire status (0 = granted) plus the granted checkout
// epoch where applicable. Duplicate retries reconstruct the identical
// decision from the slot table.
type CoordinationDecision struct {
	Status int32
	Epoch  string
}

// decideRejection builds the control-only exact rejection row for an
// identity, in the SAME reservation as the observation that produced it.
func decideRejection(key pfc2.ExactKey, status int32) []pfc2.Record {
	return []pfc2.Record{{Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
		Key: key, Outcome: pfc2.Outcome{Status: status},
	}}}
}

// ManagedLockDecide observes the staged lock table under the ONE fs.mu
// reservation and journals either the granted LockChange row or the
// control-only EAGAIN rejection row for the identity. Unlocks always grant.
// The returned decision is the durable applied outcome.
func (fs *FS) ManagedLockDecide(env *wal.Envelope, ino, kernelLockOwner uint64, op pfc2.LockOp, start, length uint64) (CoordinationDecision, error) {
	if fs.managed == nil {
		return CoordinationDecision{}, ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return CoordinationDecision{}, err
	}
	rec := &pfc2.LockChange{
		Key: pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq},
		Ino: ino, KernelLockOwner: kernelLockOwner,
		Op: op, Start: start, Length: length,
	}
	rec.Key.RequestHash = rec.RequestHash()
	if err := envHashMatches(env, rec.Key.RequestHash); err != nil {
		return CoordinationDecision{}, err
	}
	decision := CoordinationDecision{}
	build := func() ([]pfc2.Record, error) {
		if op != pfc2.LockUnlock {
			owner := pfc2.LockOwner{Session: ref, KernelLockOwner: kernelLockOwner}
			if _, conflict := fs.managed.reserved.LockConflict(ino, owner, start, length, op == pfc2.LockSetWrite); conflict {
				decision.Status = errnos.EAGAIN
				return decideRejection(rec.Key, errnos.EAGAIN), nil
			}
		}
		return []pfc2.Record{{Kind: pfc2.KindLockChange, LockChange: rec}}, nil
	}
	if _, err := fs.commitEntryDynamic(build, ""); err != nil {
		return CoordinationDecision{}, classifyCoordinationCommit(err)
	}
	return decision, nil
}

// ManagedLockConflict reports the first durable lock blocking owner from
// acquiring [start, start+length) on ino (F_GETLK and setlk pre-checks).
// Pure read against the applied (durable) reducer.
func (fs *FS) ManagedLockConflict(ino uint64, owner pfc2.LockOwner, start, length uint64, write bool) (pfc2.HeldLock, bool, error) {
	if fs.managed == nil {
		return pfc2.HeldLock{}, false, ErrNotManaged
	}
	h, conflict := fs.managed.applied.LockConflict(ino, owner, start, length, write)
	return h, conflict, nil
}

// LockChangeRequestHash is the canonical fingerprint of a managed lock
// request: exactly the hash the durable LockChange record would carry, so
// grants and rejections of the same request share one identity fingerprint.
func LockChangeRequestHash(env *wal.Envelope, ino, kernelLockOwner uint64, op pfc2.LockOp, start, length uint64) ([]byte, error) {
	ref, err := managedSessionRef(env)
	if err != nil {
		return nil, err
	}
	rec := &pfc2.LockChange{
		Key: pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq},
		Ino: ino, KernelLockOwner: kernelLockOwner,
		Op: op, Start: start, Length: length,
	}
	h := rec.RequestHash()
	return h[:], nil
}

// ManagedCheckoutDecide observes the staged checkout table under the ONE
// fs.mu reservation and journals either the granted CheckoutChange row (with
// the server-controlled next epoch at the STAGED position, stored durably in
// the identity's slot outcome) or the control-only EBUSY rejection row. The
// returned decision carries the granted epoch.
func (fs *FS) ManagedCheckoutDecide(env *wal.Envelope, path string) (CoordinationDecision, error) {
	if fs.managed == nil {
		return CoordinationDecision{}, ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return CoordinationDecision{}, err
	}
	canonical := cleanPath(path)
	if canonical == "" {
		return CoordinationDecision{}, invalidMutation("checkout path is empty/root")
	}
	key := pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq}
	probe := &pfc2.CheckoutChange{Key: key, Op: pfc2.CheckoutGrant, Path: canonical, Epoch: pfc2.FirstEpoch}
	key.RequestHash = probe.RequestHash() // acquire fingerprint excludes the epoch
	if err := envHashMatches(env, key.RequestHash); err != nil {
		return CoordinationDecision{}, err
	}
	decision := CoordinationDecision{}
	build := func() ([]pfc2.Record, error) {
		if overlaps := fs.managed.reserved.OverlappingCheckouts(canonical); len(overlaps) != 0 {
			decision.Status = errnos.EBUSY
			return decideRejection(key, errnos.EBUSY), nil
		}
		epoch := fs.managed.reserved.NextCheckoutEpoch()
		rec := &pfc2.CheckoutChange{Key: key, Op: pfc2.CheckoutGrant, Path: canonical, Epoch: epoch}
		rec.Key.RequestHash = rec.RequestHash()
		decision.Epoch = string(epoch)
		return []pfc2.Record{{Kind: pfc2.KindCheckoutChange, CheckoutChange: rec}}, nil
	}
	if _, err := fs.commitEntryDynamic(build, ""); err != nil {
		decision = CoordinationDecision{}
		return decision, classifyCoordinationCommit(err)
	}
	return decision, nil
}

// ManagedCheckinDecide observes the staged grant under the ONE fs.mu
// reservation and journals either the CheckoutRelease row or the control-only
// ENOENT rejection ("not the caller's live grant") — a release can never free
// another owner's grant, and a delayed release after a transfer is a durable
// ENOENT even if the path later becomes free.
func (fs *FS) ManagedCheckinDecide(env *wal.Envelope, path, epoch string) (CoordinationDecision, error) {
	if fs.managed == nil {
		return CoordinationDecision{}, ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return CoordinationDecision{}, err
	}
	canonical := cleanPath(path)
	if canonical == "" {
		return CoordinationDecision{}, invalidMutation("checkin path is empty/root")
	}
	rec := &pfc2.CheckoutChange{
		Key: pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq},
		Op:  pfc2.CheckoutRelease, Path: canonical, Epoch: pfc2.Epoch(epoch),
	}
	rec.Key.RequestHash = rec.RequestHash()
	if err := envHashMatches(env, rec.Key.RequestHash); err != nil {
		return CoordinationDecision{}, err
	}
	decision := CoordinationDecision{}
	build := func() ([]pfc2.Record, error) {
		g, held := fs.managed.reserved.CheckoutAt(canonical)
		if !held || g.Holder != ref || string(g.Epoch) != epoch {
			decision.Status = errnos.ENOENT
			return decideRejection(rec.Key, errnos.ENOENT), nil
		}
		return []pfc2.Record{{Kind: pfc2.KindCheckoutChange, CheckoutChange: rec}}, nil
	}
	if _, err := fs.commitEntryDynamic(build, ""); err != nil {
		decision = CoordinationDecision{}
		return decision, classifyCoordinationCommit(err)
	}
	return decision, nil
}

// CheckoutRequestHash is the canonical fingerprint of a managed checkout
// request. The ACQUIRE fingerprint deliberately excludes the server-chosen
// epoch (pfc2 hashes `class‖path` for acquires), so a lost-reply retry hashes
// identically before knowing which epoch was granted; the RELEASE fingerprint
// includes the client-known epoch.
func CheckoutRequestHash(env *wal.Envelope, release bool, path, epoch string) ([]byte, error) {
	ref, err := managedSessionRef(env)
	if err != nil {
		return nil, err
	}
	op := pfc2.CheckoutGrant
	if release {
		op = pfc2.CheckoutRelease
	}
	rec := &pfc2.CheckoutChange{
		Key: pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq},
		Op:  op, Path: cleanPath(path), Epoch: pfc2.Epoch(epoch),
	}
	h := rec.RequestHash()
	return h[:], nil
}

// ManagedCheckoutAt reports the durable grant covering exactly path.
func (fs *FS) ManagedCheckoutAt(path string) (pfc2.CheckoutView, bool, error) {
	if fs.managed == nil {
		return pfc2.CheckoutView{}, false, ErrNotManaged
	}
	v, ok := fs.managed.applied.CheckoutAt(cleanPath(path))
	return v, ok, nil
}

// ManagedOverlappingCheckouts reports every durable grant overlapping path.
func (fs *FS) ManagedOverlappingCheckouts(path string) ([]pfc2.CheckoutView, error) {
	if fs.managed == nil {
		return nil, ErrNotManaged
	}
	return fs.managed.applied.OverlappingCheckouts(cleanPath(path)), nil
}

// ManagedSessionOwner resolves a live session's display owner string.
func (fs *FS) ManagedSessionOwner(ref pfc2.SessionRef) string {
	if fs.managed == nil {
		return ""
	}
	info, ok := fs.managed.applied.Session(ref.SessionID)
	if !ok || info.Terminal || info.Ref != ref {
		return ""
	}
	return info.Owner
}

// ManagedPinChange atomically decides existence (live inode or parked
// orphan) and journals one open-pin transition PLUS the identity's durable
// ExactOutcome in the same row. Pin transitions are per-owner idempotent at
// this layer: an already-held pin (or an already-released unpin) journals
// only the ExactOutcome. A target that is neither live nor parked yields the
// durable ENOENT outcome (row with only the ExactOutcome) and
// ErrPinTargetGone so the caller replies canonically.
func (fs *FS) ManagedPinChange(env *wal.Envelope, ino uint64, unpin bool, reqHash []byte) (pinErr error) {
	if fs.managed == nil {
		return ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return err
	}
	if err := envHashExact(env, reqHash); err != nil {
		return err
	}
	key := pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq}
	copy(key.RequestHash[:], reqHash)

	// A reconnecting mount may pin a base inode this authority has not
	// hydrated yet; make the stable-handle index answerable BEFORE the
	// locked existence decision (never a fetch under fs.mu). A fetch
	// failure aborts the pin rather than journaling a wrong ENOENT.
	if err := fs.hydrateHandleIno(ino); err != nil {
		return err
	}

	gone := false
	build := func() ([]pfc2.Record, error) {
		// Under fs.mu: the existence decision and the staged row are one
		// atomic step against every concurrently staged reap/unlink/create.
		_, live := fs.byIno[ino]
		_, parked := fs.orphans[ino]
		held := fs.managed.reserved.HasPin(ref, ino)
		switch {
		case ino == 0 || (!live && !parked):
			gone = true
			return []pfc2.Record{{Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
				Key: key, Outcome: pfc2.Outcome{Status: errnoOf(os.ErrNotExist)},
			}}}, nil
		case unpin != held:
			// Idempotent transition (pin while pinned / unpin while not):
			// consume the identity durably, journal no state change.
			return []pfc2.Record{{Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
				Key: key, Outcome: pfc2.Outcome{Ino: ino},
			}}}, nil
		default:
			return []pfc2.Record{
				{Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
					Key: key, Outcome: pfc2.Outcome{Ino: ino},
				}},
				{Kind: pfc2.KindOpenPinChange, OpenPinChange: &pfc2.OpenPinChange{
					Session: ref, Ino: ino, Unpin: unpin,
				}},
			}, nil
		}
	}
	if _, err := fs.commitEntryDynamic(build, ""); err != nil {
		return classifyCoordinationCommit(err)
	}
	if gone {
		return ErrPinTargetGone
	}
	return nil
}

// errPinAlreadyHeld vetoes an ensure-pin row whose pin is already staged for
// the session (idempotent ensure: nothing journals, nothing changes).
var errPinAlreadyHeld = errors.New("vcs: open pin already held (idempotent ensure)")

// ManagedEnsureOpenPin journals ONE open-pin acquisition for ref on ino
// unless the session's pin is already staged — the FUSED create+register
// ensure step (FeatOpenRegistration on the managed generation). Unlike
// ManagedPinChange it consumes NO exact identity: the fused create's
// identity was consumed by the create's own journaled row, and this ensure
// step re-runs on EVERY reply attempt for that identity — fresh execution
// and duplicate replay alike, exactly like the legacy in-memory re-mark —
// each run converging on exactly one durable pin (never a second
// OpenPinChange while one is staged, so the reducer's duplicate-transition
// integrity rule is preserved). The existence decision, the idempotence
// decision, and the staged row are one atomic step under fs.mu, ordered
// against every concurrently staged pin, unpin, and reap. A target that is
// neither live nor parked returns ErrPinTargetGone: the caller degrades the
// fused reply to ENOENT exactly like the two-RPC create-then-MarkOpen flow.
func (fs *FS) ManagedEnsureOpenPin(ref pfc2.SessionRef, ino uint64) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	if ino == 0 {
		return ErrPinTargetGone
	}
	// A reconnecting mount may pin a base inode this authority has not
	// hydrated yet; make the stable-handle index answerable BEFORE the
	// locked existence decision (never a fetch under fs.mu).
	if err := fs.hydrateHandleIno(ino); err != nil {
		return err
	}
	build := func() ([]pfc2.Record, error) {
		_, live := fs.byIno[ino]
		_, parked := fs.orphans[ino]
		if !live && !parked {
			return nil, ErrPinTargetGone // veto: nothing journals
		}
		if fs.managed.reserved.HasPin(ref, ino) {
			return nil, errPinAlreadyHeld // veto: nothing journals
		}
		return []pfc2.Record{{Kind: pfc2.KindOpenPinChange, OpenPinChange: &pfc2.OpenPinChange{
			Session: ref, Ino: ino,
		}}}, nil
	}
	_, err := fs.commitEntryDynamic(build, "")
	switch {
	case err == nil, errors.Is(err, errPinAlreadyHeld):
		return nil
	case errors.Is(err, ErrPinTargetGone):
		return ErrPinTargetGone
	default:
		return classifyCoordinationCommit(err)
	}
}

// ManagedUnpinBatch journals the release of every open pin the session holds
// among inos as ONE journal row: the identity's durable ExactOutcome plus one
// OpenPinChange(unpin) per HELD pin, decided under fs.mu atomically with the
// staging. One row means one atomic durability decision — a crash can never
// split the batch, and the identical resend replays the stored outcome from
// the slot table without re-applying. Pins the session does not hold (and
// duplicate inos within the batch) are idempotently skipped: a close carries
// no open-vs-unlink guarantee, so the batch releases exactly what is held —
// the same per-ino semantics as the legacy batched unmark, with the reducer's
// duplicate-transition integrity rule preserved.
func (fs *FS) ManagedUnpinBatch(env *wal.Envelope, inos []uint64, reqHash []byte) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return err
	}
	if err := envHashExact(env, reqHash); err != nil {
		return err
	}
	key := pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq}
	copy(key.RequestHash[:], reqHash)
	build := func() ([]pfc2.Record, error) {
		records := []pfc2.Record{{Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
			Key: key, Outcome: pfc2.Outcome{},
		}}}
		released := make(map[uint64]struct{}, len(inos))
		for _, ino := range inos {
			if ino == 0 {
				continue
			}
			if _, done := released[ino]; done {
				continue
			}
			if !fs.managed.reserved.HasPin(ref, ino) {
				continue
			}
			released[ino] = struct{}{}
			records = append(records, pfc2.Record{Kind: pfc2.KindOpenPinChange, OpenPinChange: &pfc2.OpenPinChange{
				Session: ref, Ino: ino, Unpin: true,
			}})
		}
		return records, nil
	}
	if _, err := fs.commitEntryDynamic(build, ""); err != nil {
		return classifyCoordinationCommit(err)
	}
	return nil
}

// ManagedRecordCoordinationOutcome durably records a definite pre-observation
// rejection (reserved namespace, static EINVAL/EOPNOTSUPP) for an identity
// under its canonical request hash — one control-only rejection row in its
// own reservation, advancing the slot sequence exactly as a granted decision
// would.
func (fs *FS) ManagedRecordCoordinationOutcome(env *wal.Envelope, reqHash []byte, status int32) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return err
	}
	if err := envHashExact(env, reqHash); err != nil {
		return err
	}
	key := pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq}
	copy(key.RequestHash[:], reqHash)
	if _, err := fs.CommitEntry(nil, decideRejection(key, status), ""); err != nil {
		return mapManagedControlError(err)
	}
	return nil
}

// ManagedSyncBarrierRow journals one control-only exact no-op row for the
// caller's barrier identity and returns after the row is durable, applied,
// and its (empty) revision published. Because rows apply strictly in LSN
// order, returning proves every row admitted BEFORE the barrier is durable,
// applied, and its invalidations are published — the volume sync barrier,
// with no HistoryCut, checkpoint, snapshot, publish, object storage, or
// global drain anywhere on the path.
func (fs *FS) ManagedSyncBarrierRow(env *wal.Envelope, reqHash []byte) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return err
	}
	if err := envHashExact(env, reqHash); err != nil {
		return err
	}
	key := pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq}
	copy(key.RequestHash[:], reqHash)
	rec := pfc2.Record{Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
		Key: key, Outcome: pfc2.Outcome{},
	}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{rec}, ""); err != nil {
		return mapManagedControlError(err)
	}
	return nil
}

// CapacityReport reports the durable log's database-owned backlog quota and
// current backlog (bytes). quota 0 means "no quota installed" (legacy file
// WALs without a capacity bound); free space is quota-backlog floored at 0,
// so statfs observes real journal backpressure: a volume that would reject
// writes with EDQUOT reports zero free bytes instead of an invented constant.
func (fs *FS) CapacityReport() (quotaBytes, backlogBytes int64) {
	type quotaReporter interface{ QuotaBytes() int64 }
	if q, ok := fs.log.(quotaReporter); ok {
		quotaBytes = q.QuotaBytes()
	}
	return quotaBytes, fs.log.BacklogBytes()
}

// SyncBarrier blocks until every journal row RESERVED before the call is
// durable, applied, and its invalidations published, then re-verifies the
// authority can still guarantee durability. It is a pure barrier: no
// HistoryCut, snapshot, checkpoint, publish, object-store access, or global
// drain — the write path already made every acknowledged row durable before
// its reply; this orders the caller AFTER everything admitted so far.
func (fs *FS) SyncBarrier() error {
	if err := fs.DurabilityBarrier(); err != nil {
		return err
	}
	// Watermark() is the next LSN to reserve == exclusive upper bound of
	// every reserved row at this instant.
	target := fs.log.Watermark()
	if err := fs.seq.waitApplied(target); err != nil {
		return err
	}
	return fs.DurabilityBarrier()
}

// waitApplied blocks until the applied cursor reaches target (exclusive
// bound) or the sequencer is poisoned.
func (s *mutationSequencer) waitApplied(target uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.poison == nil && s.applied < target {
		s.cond.Wait()
	}
	return s.poison
}

// ─── managed write-back flush ────────────────────────────────────────────────

// ManagedFlushRow is one write-back record with its local (mount) sequence.
type ManagedFlushRow struct {
	LocalSeq uint64
	Record   wal.Record
}

// ManagedFlushThrough reads the durable flush watermark for one write-back
// identity (session, writebackID, checkoutPath, checkoutEpoch).
func (fs *FS) ManagedFlushThrough(ref pfc2.SessionRef, writebackID, checkoutPath, checkoutEpoch string) (uint64, bool, error) {
	if fs.managed == nil {
		return 0, false, ErrNotManaged
	}
	through, ok := fs.managed.applied.FlushThrough(ref, writebackID, cleanPath(checkoutPath), pfc2.Epoch(checkoutEpoch))
	return through, ok, nil
}

// ManagedFlushApply applies a write-back flush as ordered PFJ3 rows: each
// user record is ONE row whose controls carry the matching FlushAdvance —
// tree state never applies without its watermark and the watermark never
// advances without its tree state (same journal row, same fenced
// transaction). The ledger maps a local writeback sequence to
// Through = LocalSeq + 1, DENSE: every applied record advances the watermark
// by exactly one, local sequence 0 (a fresh session WAL's first record) is
// representable, a retry drops exactly the durably covered prefix, and the
// remainder must continue at previous+1 (anything else is a corrupt or
// reordered flush and rejects before any reservation). The whole bounded
// batch stages as one ordered row list behind ONE CommitThrough barrier. An
// oversized write splits into bounded chunks with the advance riding ONLY
// the final chunk (earlier chunks are idempotently re-covered by a retry).
// When env carries the flush RPC's exact identity, one final control-only
// row stores the definite AppliedThrough (Outcome.Offset) so a lost-reply
// retry replays the identical answer without touching the ledger. Returns
// the durable through watermark (== AppliedThrough semantics: local
// sequences strictly below it are durable).
func (fs *FS) ManagedFlushApply(env *wal.Envelope, envHash []byte, ref pfc2.SessionRef, writebackID, checkoutPath, checkoutEpoch string, rows []ManagedFlushRow, owner string) (uint64, error) {
	if fs.managed == nil {
		return 0, ErrNotManaged
	}
	canonical := cleanPath(checkoutPath)
	epoch := pfc2.Epoch(checkoutEpoch)
	if err := epoch.Validate(); err != nil {
		return 0, invalidMutation("flush checkout epoch: %v", err)
	}
	durable, _, err := fs.ManagedFlushThrough(ref, writebackID, canonical, checkoutEpoch)
	if err != nil {
		return 0, err
	}
	// The grant must be live at admission; each row's FlushAdvance
	// re-validates it at its own ordered position (a mid-flush transfer
	// fences the remainder).
	if g, ok := fs.managed.reserved.CheckoutAt(canonical); !ok || g.Holder != ref || g.Epoch != epoch {
		return durable, ErrSessionStale
	}
	var specs []entrySpec
	next := durable
	established := durable > 0 // false only for the first-ever flush of this writeback id
	for _, row := range rows {
		if row.Record.Op.IsControl() || row.Record.Op.IsBatch() {
			return durable, invalidMutation("managed flush records must be plain user mutations (watermarks ride natively as FlushAdvance)")
		}
		through := row.LocalSeq + 1
		if through == 0 {
			return durable, invalidMutation("flush local sequence overflows the ledger domain")
		}
		if through <= durable {
			continue // already durably covered (retry catch-up)
		}
		if !established {
			// First-ever flush of this writeback id: its first record's
			// local sequence establishes the base; everything after must be
			// strictly contiguous (+1). Retries re-establish the identical
			// base deterministically.
			established = true
			next = through
		} else if through != next+1 {
			return durable, invalidMutation("flush is not dense: local sequence %d does not continue the covered prefix (next expected %d)", row.LocalSeq, next)
		} else {
			next = through
		}
		chunks, err := fs.splitFlushRecord(row.Record)
		if err != nil {
			return durable, err
		}
		for ci, chunk := range chunks {
			spec := entrySpec{tree: new(wal.Record)}
			*spec.tree = chunk
			spec.tree.Seq = 0 // the journal assigns the LSN; LocalSeq rides the advance
			if ci == len(chunks)-1 {
				spec.controls = []pfc2.Record{{Kind: pfc2.KindFlushAdvance, FlushAdvance: &pfc2.FlushAdvance{
					Session: ref, WritebackID: writebackID,
					CheckoutPath: canonical, CheckoutEpoch: epoch,
					Through: through,
				}}}
				spec.through = through
			}
			specs = append(specs, spec)
		}
	}
	finalThrough := next // ledger units (Seq+1); dense
	// The client-visible AppliedThrough is the highest local Seq durably
	// covered (Through−1): "records with Seq ≤ AppliedThrough are durable".
	appliedSeq := int64(-1)
	if finalThrough > 0 {
		appliedSeq = int64(finalThrough) - 1
	}
	if env.Valid() {
		// The flush RPC's own exact identity: one final control-only row in
		// the SAME ordered group stores the definite AppliedThrough, so a
		// lost-reply retry replays the identical outcome.
		key, kerr := managedExactKey(env)
		if kerr != nil {
			return uint64(max64(appliedSeq, 0)), kerr
		}
		if err := envHashExact(env, envHash); err != nil {
			return uint64(max64(appliedSeq, 0)), err
		}
		specs = append(specs, entrySpec{controls: []pfc2.Record{{
			Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
				Key: key, Outcome: pfc2.Outcome{Offset: appliedSeq},
			},
		}}})
	}
	if len(specs) == 0 {
		return uint64(max64(appliedSeq, int64(durableSeq(durable)))), nil
	}
	if _, err := fs.commitEntriesGroup(specs, owner); err != nil {
		return uint64(durableSeq(durable)), classifyCoordinationCommit(err)
	}
	return uint64(max64(appliedSeq, 0)), nil
}

// durableSeq converts a ledger Through watermark (Seq+1) to the highest
// durable local Seq (0 when nothing is covered).
func durableSeq(through uint64) int64 {
	if through == 0 {
		return 0
	}
	return int64(through) - 1
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// splitFlushRecord splits one oversized plain write into bounded chunks
// (identical policy to the legacy splitBatchForBounds leaf expansion); every
// other record passes through unchanged.
func (fs *FS) splitFlushRecord(r wal.Record) ([]wal.Record, error) {
	maxData := fs.bounds.MaxWriteDataBytes
	if maxData <= 0 || r.Op != wal.OpWrite || len(r.Data) <= maxData {
		return []wal.Record{r}, nil
	}
	if r.Env != nil || r.Append {
		return nil, invalidMutation("flush write of %d bytes exceeds the durable log's %d-byte write bound", len(r.Data), maxData)
	}
	var out []wal.Record
	for chunkStart := 0; chunkStart < len(r.Data); chunkStart += maxData {
		chunkEnd := chunkStart + maxData
		if chunkEnd > len(r.Data) {
			chunkEnd = len(r.Data)
		}
		sub := r
		sub.Offset = r.Offset + int64(chunkStart)
		sub.Data = r.Data[chunkStart:chunkEnd]
		out = append(out, sub)
	}
	return out, nil
}

// ─── managed reap scheduling ─────────────────────────────────────────────────

// ManagedReapSweep journals an OpReap row for every parked orphan whose last
// durable open pin is gone (in the reserved view, checked atomically with the
// row's staging). It is called after commits that released pins and after
// cold replay; a crash between the unpin row and the reap row only delays the
// reap until the next sweep (a temporary leak, never a correctness loss —
// the decision re-derives deterministically from journaled state).
func (fs *FS) ManagedReapSweep() int {
	if fs.managed == nil {
		return 0
	}
	fs.mu.RLock()
	var candidates []uint64
	for ino := range fs.orphans {
		candidates = append(candidates, ino)
	}
	fs.mu.RUnlock()
	sort.Slice(candidates, func(i, j int) bool { return candidates[i] < candidates[j] })
	reaped := 0
	for _, ino := range candidates {
		ino := ino
		build := func() ([]pfc2.Record, error) {
			// Atomic decision at the staged position: still parked, no pins.
			if fs.orphans[ino] == nil || len(fs.managed.reserved.PinHolders(ino)) != 0 {
				return nil, errReapConditionNotMet
			}
			return nil, nil // tree-only row, no controls
		}
		tree := wal.Record{Op: wal.OpReap, Ino: ino}
		if _, err := fs.commitEntryDynamicTree(&tree, build, ""); err == nil {
			reaped++
		}
	}
	return reaped
}

// ─── shared plumbing ─────────────────────────────────────────────────────────

// envHashMatches verifies the transport envelope's hash equals the canonical
// record fingerprint (the protocol layer computes it server-side; a mismatch
// is an internal wiring error, never client input).
func envHashMatches(env *wal.Envelope, want [pfc2.RequestHashBytes]byte) error {
	if len(env.ReqHash) != pfc2.RequestHashBytes {
		return invalidMutation("coordination envelope hash has %d bytes", len(env.ReqHash))
	}
	for i, b := range env.ReqHash {
		if want[i] != b {
			return invalidMutation("coordination envelope hash does not match the canonical record fingerprint")
		}
	}
	return nil
}

func envHashExact(env *wal.Envelope, reqHash []byte) error {
	if len(reqHash) != pfc2.RequestHashBytes || len(env.ReqHash) != pfc2.RequestHashBytes {
		return invalidMutation("coordination request hash has wrong length")
	}
	for i := range reqHash {
		if env.ReqHash[i] != reqHash[i] {
			return invalidMutation("coordination envelope hash does not match the request fingerprint")
		}
	}
	return nil
}

// classifyCoordinationCommit maps CommitEntry failures onto the coordination
// error vocabulary: reducer integrity conflicts (a foreign lock/checkout at
// the staged position) become ErrCoordinationConflict; fences become
// ErrSessionStale; everything else keeps its classification (capacity,
// durability-unknown, quota).
func classifyCoordinationCommit(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pfc2.ErrIntegrity):
		return fmt.Errorf("%w: %v", ErrCoordinationConflict, err)
	default:
		return mapManagedControlError(err)
	}
}

// commitEntryPre is commitEntry with an optional precondition evaluated under
// fs.mu immediately before staging (atomic with the reservation decision).
func (fs *FS) commitEntryPre(tree *wal.Record, controls []pfc2.Record, owner string, pre func() error) (entryOutcome, error) {
	if pre == nil {
		return fs.commitEntry(tree, controls, owner)
	}
	build := func() ([]pfc2.Record, error) {
		if err := pre(); err != nil {
			return nil, err
		}
		return controls, nil
	}
	if tree != nil {
		return fs.commitEntryDynamicTree(tree, build, owner)
	}
	return fs.commitEntryDynamic(build, owner)
}

// commitEntryDynamic commits one control-only row whose records are built
// UNDER fs.mu by build (atomic with the reservation staging).
func (fs *FS) commitEntryDynamic(build func() ([]pfc2.Record, error), owner string) (entryOutcome, error) {
	return fs.commitEntryDynamicTree(nil, build, owner)
}

// waitCoordinationClear polls the reservation-order reducer until check
// reports no conflict, the deadline passes, or the authority poisons. The
// wait is VOLATILE: nothing is journaled, nothing survives a restart, and no
// durable decision is consumed while waiting. Returns true when clear.
func (fs *FS) WaitCoordinationClear(deadline time.Time, check func() bool) bool {
	for {
		if check() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		if fs.log.IsPoisoned() || fs.Sealed() {
			return false
		}
		time.Sleep(15 * time.Millisecond)
	}
}
