package workfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Managed PFJ3/PFC2 mode: the live data plane journals whole PFJ3 entries —
// at most one canonical PFR1 tree intent plus ordered PFC2 controls — through
// ONE synchronous fenced PostgreSQL transaction per row. That transaction is
// the only visibility/durability boundary: ordinary appends never consult
// checkpoint, cut, history, or object-store state, and no local WAL, opstate,
// checkpoint intent, or cache is authoritative truth.
//
// Coordination state (exact sessions, outcomes, floors, locks, checkouts,
// open pins, flush ledgers) lives in the deterministic pfc2 reducer, in the
// SAME total order as tree mutations. WorkFS keeps two reducer views exactly
// like the legacy control shadow: pfc2Reserved is the reservation-order
// staging view (decisions), pfc2Applied is the applied view (queries after
// durability). Failed staging rolls the reservation back; committed rows
// recover by replay. There is NO reclaim grace and NO wall-time pruning in
// managed mode: cold replay already contains authoritative coordination.
var (
	// ErrNotManaged reports a managed-only API called on a legacy FS.
	ErrNotManaged = errors.New("vcs: filesystem is not a managed PFJ3/PFC2 generation")
	// ErrManagedMode reports a legacy control API called on a managed FS.
	ErrManagedMode = errors.New("vcs: legacy control path is not available on a managed PFJ3/PFC2 generation")
)

// managedState is the PFJ3/PFC2 attachment on FS.
type managedState struct {
	log pfj3.EntryLog
	// reserved is the reservation-order staging reducer; applied is the
	// post-durability reducer serving queries. Both rebuild identically from
	// the journal.
	reserved *pfc2.State
	applied  *pfc2.State
	// factMu serializes issue-fact → journal-row sections (session open,
	// renew, expiry). Fact issuance binds the EXACT durable control floor,
	// and facts must be consumed in issuance order, so overlapping mint/
	// commit windows would fail closed at the database; serializing the rare
	// control transitions avoids those spurious rejections entirely.
	factMu sync.Mutex
	// sweepScheduled debounces the asynchronous reap sweep kicked after
	// commits that released the last durable pin on parked orphans.
	sweepScheduled atomic.Bool

	// projected anchors each live session's DATABASE lease deadline on the
	// local MONOTONIC clock: deadline = anchor + (expiresDbMs − factDbMs),
	// captured when the database minted the fact (open/renew commit). The
	// host wall clock never extends or nominates expiry — the projection
	// only FAILS the session CLOSED between its projected deadline and the
	// durable resolution (a database renewal advances it; a durable terminal
	// turns it into proof-backed ESTALE).
	projMu    sync.Mutex
	projected map[string]projectedLease
}

// projectedLease is one session's monotonic-clock lease projection.
type projectedLease struct {
	generation uint64
	deadline   time.Time
}

// anchorProjectedLease records the monotonic deadline for (session,
// generation): remainingDbMs is the database-time remaining at the anchor
// instant (expiresDbMs − mintedDbMs, from the SAME committed record).
func (fs *FS) anchorProjectedLease(sessionID string, generation uint64, remainingDbMs int64) {
	if fs.managed == nil || remainingDbMs < 0 {
		remainingDbMs = 0
	}
	m := fs.managed
	m.projMu.Lock()
	if m.projected == nil {
		m.projected = map[string]projectedLease{}
	}
	cur, ok := m.projected[sessionID]
	deadline := time.Now().Add(time.Duration(remainingDbMs) * time.Millisecond)
	if !ok || cur.generation != generation || deadline.After(cur.deadline) {
		m.projected[sessionID] = projectedLease{generation: generation, deadline: deadline}
	}
	m.projMu.Unlock()
}

// SessionAdmissible fails a session CLOSED unless a FRESH database-time fact
// authorizes it: only a fenced open/renew/resume transaction that returned a
// current DB-time fact on THIS authority anchors the session's monotonic
// deadline (deadline = anchor + (expiresDbMs − factDbMs), from the SAME
// committed record). The local monotonic clock is purely a fail-closed
// watchdog — it can only SHORTEN authority, never extend or nominate expiry.
// A cold-replayed session has NO anchor and admits no mutation until its
// client's resume/renew round-trips the database; nothing is guessed from
// wall clocks, recovery-time floors, or grace windows. Nothing is consumed
// and nothing terminal is claimed here: a durable renewal re-opens
// admission, a durable terminal turns the answer into proof-backed ESTALE
// downstream.
func (fs *FS) managedSessionAdmissible(sessionID string) error {
	if fs.managed == nil {
		return nil
	}
	info, ok := fs.managed.applied.Session(sessionID)
	if !ok || info.Terminal {
		return nil // terminal/unknown resolves to ESTALE downstream with durable proof
	}
	m := fs.managed
	m.projMu.Lock()
	lease, anchored := m.projected[sessionID]
	m.projMu.Unlock()
	if anchored && lease.generation == info.Ref.Generation && time.Now().Before(lease.deadline) {
		return nil
	}
	return fmt.Errorf("%w: session %s generation %d has no current database-time authorization on this authority",
		ErrSessionExpiryPending, sessionID, info.Ref.Generation)
}

// scheduleReapSweep runs one asynchronous ManagedReapSweep, coalescing
// concurrent triggers. The sweep's decisions re-validate atomically at their
// own staged positions, so a coalesced or crashed-away trigger is only a
// deferral (the next trigger or cold-start sweep re-derives the same
// candidates from journaled state), never a correctness loss.
func (fs *FS) scheduleReapSweep() {
	if fs.managed == nil || !fs.managed.sweepScheduled.CompareAndSwap(false, true) {
		return
	}
	go func() {
		fs.managed.sweepScheduled.Store(false)
		fs.ManagedReapSweep()
	}()
}

// DurabilityBarrier is the fsync/synchronize contract: it returns nil when
// every already-ACKNOWLEDGED mutation on this authority is durable and
// applied. It is a pure BARRIER, never a history operation — there is no
// HistoryCut, snapshot, publish, global drain, or object-store access on this
// path. The managed/exact write path releases a mutation reply only AFTER its
// fenced database commit and ordered apply, so a caller that observed a reply
// already has durability; this only fails closed when the authority can no
// longer make that guarantee (sealed for teardown, or a poisoned log whose
// durability is unknown).
func (fs *FS) DurabilityBarrier() error {
	if fs.Sealed() {
		return ErrSealed
	}
	if fs.managed != nil {
		if fs.log.IsPoisoned() {
			return ErrDurabilityUnknown
		}
		return nil
	}
	select {
	case <-fs.wal.PoisonedCh():
		return ErrDurabilityUnknown
	default:
		return nil
	}
}

// AppliedWatermark is the exclusive upper bound of applied (and durable)
// LSNs on a managed generation (the sequencer's cursor).
func (fs *FS) AppliedWatermark() uint64 { return fs.seq.appliedWatermark() }

// ManagedControl returns the applied-order PFC2 reducer for read queries
// (session views, exact dispositions, lock/checkout/pin/flush lookups).
func (fs *FS) ManagedControl() (*pfc2.State, error) {
	if fs.managed == nil {
		return nil, ErrNotManaged
	}
	return fs.managed.applied, nil
}

// ManagedReservedControl returns the reservation-order PFC2 view: the state
// admission decisions run against, ahead of durability.
func (fs *FS) ManagedReservedControl() (*pfc2.State, error) {
	if fs.managed == nil {
		return nil, ErrNotManaged
	}
	return fs.managed.reserved, nil
}

// IssueAdmissionFact mints one capability-bound short-lived database time
// fact for a PFC2 control transition of the given session and purpose. The
// issuance binds the EXACT durable control floor (the applied view advances
// only when a fenced database commit did): a stale or ahead-of-durable view
// fails closed at the database rather than minting against superseded state.
func (fs *FS) IssueAdmissionFact(session pfc2.SessionRef, purpose pfc2.FactPurpose) (pfc2.IssuedFact, error) {
	if fs.managed == nil {
		return pfc2.IssuedFact{}, ErrNotManaged
	}
	return fs.managed.log.IssueAdmissionFact(pfc2.FactScope{
		Purpose:            purpose,
		Session:            session,
		PriorDbTimeFloorMs: fs.managed.applied.DbTimeFloorMs(),
	})
}

// NewManaged constructs the managed PFJ3/PFC2 authority filesystem over an
// entry log, cold-replaying EVERY retained entry — tree intent then controls,
// in one total order — into one WorkFS state BEFORE returning. Callers bind
// listeners and publish readiness only after this returns.
func NewManaged(entries []backend.Entry, blobs content.BlobReader, log pfj3.EntryLog) (*FS, error) {
	return NewManagedWithCache(entries, blobs, log, content.NewCache(defaultCacheBytes))
}

// NewManagedWithCache is NewManaged with a caller-provided content cache and a
// zero base high-water (a base carrying no MaxInoSeen fact).
func NewManagedWithCache(entries []backend.Entry, blobs content.BlobReader, log pfj3.EntryLog, cache content.Cache) (*FS, error) {
	return NewManagedFromBase(BaseImage{Entries: entries, MaxInoSeen: 0}, blobs, log, cache)
}

// BaseImage is the immutable base a managed authority cold-loads: the manifest
// entries plus the PERSISTED monotonic inode namespace high-water
// (PFT2 Root.MaxInoSeen). MaxInoSeen bounds every inode id ever live in the
// branch's history — parked orphans included — even ids no longer present in
// the tree, so seeding the allocator from it (not just the loaded tree)
// guarantees a deleted inode id is never reused after compaction dropped it.
type BaseImage struct {
	Entries    []backend.Entry
	MaxInoSeen uint64
}

// NewManagedFromBase is NewManagedWithCache with an explicit base high-water.
func NewManagedFromBase(base BaseImage, blobs content.BlobReader, log pfj3.EntryLog, cache content.Cache) (*FS, error) {
	if log.RecordCodec() != pfj3.RecordCodec || log.ControlCodec() != pfj3.ControlCodec {
		return nil, fmt.Errorf("%w: log speaks %s/%s", ErrNotManaged, log.RecordCodec(), log.ControlCodec())
	}
	now := time.Now()
	fs := &FS{
		root:         &inode{ino: 1, kind: "directory", mode: os.ModeDir | 0o755, mtime: now, ctime: now, atime: now, children: map[string]*inode{}},
		blobs:        blobs,
		cache:        cache,
		log:          log,
		bounds:       log.Bounds(),
		generation:   randomNonce(),
		alloc:        newInoAllocator(),
		orphans:      map[uint64]*inode{},
		orphanLeases: map[uint64]time.Time{},
		openInodes:   map[uint64]map[string]time.Time{},
		pendingReaps: map[uint64]uint32{},
		byIno:        map[uint64]*inode{},
		xattrs:       map[uint64]map[string][]byte{},
		deadBaseInos: map[uint64]struct{}{},
		managed: &managedState{
			log:      log,
			reserved: pfc2.NewState(),
			applied:  pfc2.NewState(),
		},
	}
	fs.byIno[1] = fs.root
	sorted := append([]backend.Entry(nil), base.Entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, e := range sorted {
		fs.insertBase(e)
	}
	if err := fs.assignMissingInos(); err != nil {
		return nil, err
	}
	// Seed the allocator's DURABLE FLOOR from the persisted high-water BEFORE
	// replay: a compaction that dropped create/remove churn (and any
	// parked-orphan ids no longer in the tree) leaves the tree scan below the
	// true high-water, and reusing those ids would collide a fresh create
	// with a still-pinned or still-open historical inode.
	fs.alloc.durableFloor = base.MaxInoSeen
	fs.alloc.observe(base.MaxInoSeen)
	fs.indexSubtree(fs.root)
	// Managed generations have no legacy checkpoint sidecars: recovery bases
	// arrive as exact RecoveryRoot adoption (migration 013+), never as
	// KindSnapshot control records inside the log.
	if err := log.ReplayEntriesInto(fs.replayEntry); err != nil {
		return nil, err
	}
	// Advance the high-water past every inode the replayed control state and
	// orphan table reference (pins/locks on parked-or-detached inodes can
	// name ids above the current tree). Inode ids are never reused, so the
	// allocator must dominate the whole observed history, not just the tree.
	fs.advanceInoHighWaterFromControl()
	// The reservation view starts exactly at the applied view: rebuild it
	// from the applied projection so both reducers are byte-identical.
	projection := fs.managed.applied.Project()
	reserved, err := pfc2.Rebuild(projection)
	if err != nil {
		return nil, fmt.Errorf("workfs: managed control replay projection: %w", err)
	}
	fs.managed.reserved = reserved
	fs.seq.init(log.Watermark())
	fs.pins = map[uint64]uint64{}
	return fs, nil
}

// advanceInoHighWaterFromControl lifts the allocator high-water above every
// inode id observed in the replayed PFC2 control state (open pins, held
// locks) and the orphan table, so a freshly allocated id can never collide a
// historical inode that is still pinned, locked, or parked. Single-threaded
// at construction.
func (fs *FS) advanceInoHighWaterFromControl() {
	for ino := range fs.orphans {
		fs.alloc.observe(ino)
	}
	if fs.managed != nil {
		for _, ino := range fs.managed.applied.PinnedInodes() {
			fs.alloc.observe(ino)
		}
		for _, ino := range fs.managed.applied.LockedInodes() {
			fs.alloc.observe(ino)
		}
	}
}

// replayEntry applies one journal entry during single-threaded construction
// replay: the tree intent through the exact legacy mutation replay (including
// deterministic exact-envelope outcome rebuild into the PFC2 reducer), then
// every control record, in order, into the same reducer.
func (fs *FS) replayEntry(entry pfj3.JournalEntry) error {
	if entry.Tree != nil {
		if entry.Tree.Op.IsControl() {
			return fmt.Errorf("workfs: managed replay entry %d carries a PFR1 OpControl tree record", entry.LSN)
		}
		if err := fs.replayManagedTree(entry.LSN, *entry.Tree); err != nil {
			return err
		}
	}
	for i := range entry.Controls {
		if _, err := fs.managed.applied.Apply(&entry.Controls[i]); err != nil {
			return fmt.Errorf("workfs: managed replay entry %d control %d: %w", entry.LSN, i, err)
		}
	}
	return nil
}

// replayManagedTree replays one tree intent through the ONE managed leaf
// reducer (applyManagedLeaf), rebuilding exact envelope outcomes into the
// PFC2 reducer (PFR1 records own their envelopes; they never get a second
// PFC2 record).
func (fs *FS) replayManagedTree(lsn uint64, intent wal.Record) error {
	leaves, lerr := intentLeaves([]wal.Record{intent})
	if lerr != nil {
		return fmt.Errorf("workfs: managed replay intent %d: %w", lsn, lerr)
	}
	for _, r := range leaves {
		if r.Op.IsControl() {
			return fmt.Errorf("workfs: managed replay intent %d carries an OpControl leaf", lsn)
		}
		if _, err := fs.applyManagedLeaf(r, managedLeafReplay{}, fs.managed.applied); err != nil {
			return fmt.Errorf("workfs: managed replay intent %d: %w", lsn, err)
		}
	}
	return nil
}

// exactOutcomeSink is where the reducer stores an exact envelope's rebuilt
// outcome: the live apply passes its open PFC2 transaction, cold replay the
// applied state directly. Both store byte-identical outcomes.
type exactOutcomeSink interface {
	RecordExternalOutcome(pfc2.ExactKey, pfc2.Outcome) error
}

// managedLeafMode selects the mechanical (never semantic) differences
// between the reducer's two callers.
type managedLeafMode interface {
	// owner tags live invalidations; replay publishes nothing.
	owner() string
	// stampCtime: replay stamps deterministic ctimes from the record
	// timestamp (the live apply already stamped them inside the mutation).
	stampCtime() bool
	// onParked runs between the apply and the version stamp for a leaf that
	// parked an inode (the live path captures the orphan's version for its
	// undo transaction).
	onParked(orphanIno uint64)
	// countSkip records a tolerated benign env-less outcome (replay metric).
	countSkip()
}

type managedLeafLive struct {
	ownerName string
	tx        *mutationTransaction
}

func (m managedLeafLive) owner() string  { return m.ownerName }
func (managedLeafLive) stampCtime() bool { return false }
func (managedLeafLive) countSkip()       {}
func (m managedLeafLive) onParked(ino uint64) {
	m.tx.captureOrphanVersion(ino)
}

type managedLeafReplay struct{}

func (managedLeafReplay) owner() string    { return "" }
func (managedLeafReplay) stampCtime() bool { return true }
func (managedLeafReplay) onParked(uint64)  {}
func (managedLeafReplay) countSkip()       { replaySkipsTotal.Inc() }

// managedLeafResult is one leaf's reduced outcome: the MutationResult the
// protocol layer serializes, the deterministic apply error (nil on
// success), and the facts the live pipeline turns into invalidations and
// reap candidacy.
type managedLeafResult struct {
	res       MutationResult
	err       error
	orphanIno uint64
	changed   bool
}

// applyManagedLeaf is THE canonical managed-entry leaf reducer: live apply
// (under the apply turn) and cold-start replay (single-threaded
// construction) fold every durable tree leaf through this one function, so
// tolerance classification, version stamping, and the exact-outcome bytes
// stored for envelope-carrying leaves cannot diverge between them. The
// HistoryCut materializer reproduces the same classification and outcome
// serialization through the shared transition engine
// (fstransition.BenignEnvlessOutcome + historycut.applyTreeRow); the
// managed parity goldens prove all three byte-identical.
//
// Every logged identity (r.Ino and every member of r.Inos) is observed by
// applyMutationAs BEFORE semantic application — success, deterministic
// failure, and unused reservation members alike — so a replayed or
// materialized allocator can never re-issue an identity the live authority
// burned. Caller holds fs.mu (or is the single-threaded constructor).
func (fs *FS) applyManagedLeaf(r wal.Record, mode managedLeafMode, sink exactOutcomeSink) (managedLeafResult, error) {
	fs.epoch++
	resolvedOffset := r.Offset
	if r.Op == wal.OpWrite && r.Append {
		// O_APPEND: EOF is resolved HERE, at this record's ordered position,
		// so every replica, every replay, and the materializer choose the
		// same offset.
		if n := fs.resolveForRW(r.Path, r.Ino); n != nil && n.kind == "file" {
			resolvedOffset = n.curSize()
		}
	}
	orphanIno, changed, aerr := fs.applyManagedMutation(r, mode.owner())
	if aerr != nil {
		switch {
		case r.Env.Valid() && deterministicApplyError(aerr):
			// Exact records store their deterministic outcome below.
		case !r.Env.Valid() && benignReplayErrorForRecord(r, aerr):
			// Env-less rows (write-back flush leaves) tolerate exactly the
			// benign idempotent-retry outcomes everywhere — live apply, cold
			// replay, and HistoryCut materialization classify identically.
			mode.countSkip()
		default:
			// The row is durable; a non-deterministic apply failure is
			// authority corruption and must fail closed loudly.
			return managedLeafResult{}, aerr
		}
	}
	out := managedLeafResult{err: aerr, orphanIno: orphanIno, changed: changed && aerr == nil}
	if out.changed {
		if orphanIno != 0 {
			mode.onParked(orphanIno)
		}
		out.res.Version = fs.stampVersionAt(r, orphanIno, mode.stampCtime(), replayTs(r))
	}
	out.res.OrphanIno = orphanIno
	if n := fs.resolveForRW(r.Path, r.Ino); n != nil {
		out.res.Ino = n.ino
	}
	if r.Op == wal.OpWrite {
		out.res.Count = int32(len(r.Data))
		out.res.Offset = resolvedOffset
	}
	if r.Env.Valid() {
		exact := pfc2.Outcome{
			Status: errnoOf(aerr), OrphanIno: orphanIno, Ino: out.res.Ino,
			Count: out.res.Count, Offset: out.res.Offset,
		}
		key, kerr := managedExactKey(r.Env)
		if kerr != nil {
			return managedLeafResult{}, kerr
		}
		if rerr := sink.RecordExternalOutcome(key, exact); rerr != nil {
			return managedLeafResult{}, fmt.Errorf("workfs: managed exact outcome: %w", rerr)
		}
	}
	return out, nil
}

func managedExactKey(env *wal.Envelope) (pfc2.ExactKey, error) {
	if env == nil || !env.Valid() {
		return pfc2.ExactKey{}, fmt.Errorf("workfs: exact record carries no envelope")
	}
	if len(env.ReqHash) != pfc2.RequestHashBytes {
		return pfc2.ExactKey{}, fmt.Errorf("workfs: exact envelope hash is %d bytes", len(env.ReqHash))
	}
	key := pfc2.ExactKey{
		Session: pfc2.SessionRef{SessionID: env.SessionID, Generation: env.Generation},
		Slot:    env.Slot,
		SlotSeq: env.SlotSeq,
	}
	copy(key.RequestHash[:], env.ReqHash)
	return key, nil
}

// entryLeafOutcome is one tree leaf's essential apply outcome inside a
// committed managed row: the MutationResult the protocol layer serializes
// plus the deterministic apply error (nil on success).
type entryLeafOutcome struct {
	res MutationResult
	err error
}

// entryOutcome reports everything one committed managed row produced.
type entryOutcome struct {
	tree     []entryLeafOutcome
	controls []pfc2.ApplyResult
}

// CommitEntry validates, reserves, journals, applies, and publishes ONE
// managed journal row: an optional tree intent (one mutation or one OpBatch;
// a write-back flush is user records + its FlushAdvance control in this one
// row) plus ordered PFC2 controls. The reservation view stages every control
// (and exact tree envelope) atomically and rolls back completely if the row
// cannot be built; after the fenced database commit the same transitions
// apply to the applied view, one revision publishes, and the caller replies.
func (fs *FS) CommitEntry(tree *wal.Record, controls []pfc2.Record, owner string) ([]pfc2.ApplyResult, error) {
	out, err := fs.commitEntry(tree, controls, owner)
	if err != nil {
		return nil, err
	}
	return out.controls, nil
}

// commitEntry is CommitEntry returning the full per-arm outcome (the managed
// session-store bridge needs the tree leaf results).
func (fs *FS) commitEntry(tree *wal.Record, controls []pfc2.Record, owner string) (entryOutcome, error) {
	return fs.commitEntryDynamicTree(tree, func() ([]pfc2.Record, error) { return controls, nil }, owner)
}

// commitEntryDynamicTree is the managed commit core. build runs UNDER fs.mu
// immediately before staging — atomic with the reservation decision — and
// returns the row's control records (it may also veto the whole row with an
// error, e.g. a reap whose no-pin condition no longer holds). A nil tree with
// no controls from build is rejected exactly like the static path.
func (fs *FS) commitEntryDynamicTree(tree *wal.Record, build func() ([]pfc2.Record, error), owner string) (entryOutcome, error) {
	return fs.commitEntryDynamicTreePre(tree, build, owner, nil)
}

// commitEntryDynamicTreePre is commitEntryDynamicTree with one additional
// reservation-order admission decision. pre runs under fs.mu before the tree
// intent is prepared. Returning reject=true replaces the tree row with the
// supplied control-only decision in this same reservation. This is the
// atomic boundary used by delegated write-through admission: a mutation is
// ordered either before a concurrently reserving delegation, or as an exact
// EAGAIN after it; it can never be admitted beneath the grant.
func (fs *FS) commitEntryDynamicTreePre(
	tree *wal.Record,
	build func() ([]pfc2.Record, error),
	owner string,
	pre func() (controls []pfc2.Record, reject bool, err error),
) (entryOutcome, error) {
	if fs.managed == nil {
		return entryOutcome{}, ErrNotManaged
	}
	if err := fs.admit.enter(); err != nil {
		return entryOutcome{}, err
	}
	defer fs.admit.exit()

	var records []wal.Record
	if tree != nil {
		trust := intentUser
		if tree.Op.IsBatch() {
			trust = intentWritebackBatch
		} else if tree.Env != nil {
			trust = intentExactUser
		}
		normalized, err := fs.normalizeAndValidateIntent([]wal.Record{*tree}, trust)
		if err != nil {
			return entryOutcome{}, err
		}
		records = normalized
		// Lazy-base hydration OUTSIDE fs.mu, before reservation: base
		// fetches never run under the tree lock, and a fetch failure here
		// is a definite pre-journal rejection. The exact pass under the
		// apply turn settles any names a concurrent lower-LSN row moves.
		if herr := fs.hydrateIntentTargets(context.Background(), leavesOf(records), hydrateOptimistic); herr != nil {
			return entryOutcome{}, herr
		}
		fs.warmIntentWriteTargets(leavesOf(records))
	}

	fs.mu.Lock()
	// Identity preassignment below burns allocator ids. Until the buffered
	// append succeeds nothing durable references them, and fs.mu is held
	// throughout, so every pre-append rejection restores the allocator —
	// a rejected duplicate/conflicting row must not consume identities.
	allocBefore := fs.alloc
	restoreAlloc := func() { fs.alloc = allocBefore }
	var (
		controls   []pfc2.Record
		rejectTree bool
	)
	if pre != nil {
		var preErr error
		controls, rejectTree, preErr = pre()
		if preErr != nil {
			restoreAlloc()
			fs.mu.Unlock()
			return entryOutcome{}, preErr
		}
		if rejectTree {
			records = nil
		}
	}
	if records != nil {
		if err := fs.prepareIntentLocked(records, time.Now().UnixMilli()); err != nil {
			restoreAlloc()
			fs.mu.Unlock()
			return entryOutcome{}, err
		}
	}
	// The row's controls are decided HERE, under fs.mu, so precondition
	// checks (existence, pin state, next epoch) are atomic with staging.
	if !rejectTree {
		var buildErr error
		controls, buildErr = build()
		if buildErr != nil {
			restoreAlloc()
			fs.mu.Unlock()
			return entryOutcome{}, buildErr
		}
	}
	if records == nil && len(controls) == 0 {
		restoreAlloc()
		fs.mu.Unlock()
		return entryOutcome{}, invalidMutation("managed entry carries neither tree nor controls")
	}
	// Stage the reservation-order control transitions atomically. The open
	// transaction IS the reserved shadow: concurrent admissions serialize on
	// fs.mu here, and a failed build rolls everything back.
	tx := fs.managed.reserved.Begin()
	staged := false
	defer func() {
		if !staged {
			tx.Rollback()
		}
	}()
	if records != nil {
		for _, leaf := range leavesOf(records) {
			if leaf.Env.Valid() {
				key, err := managedExactKey(leaf.Env)
				if err != nil {
					restoreAlloc()
					fs.mu.Unlock()
					return entryOutcome{}, err
				}
				// The reserved view admits the envelope now; the applied view
				// records the real outcome after apply.
				if err := tx.RecordExternalOutcome(key, pfc2.Outcome{}); err != nil {
					restoreAlloc()
					fs.mu.Unlock()
					return entryOutcome{}, err
				}
			}
		}
	}
	for i := range controls {
		if _, err := tx.Apply(&controls[i]); err != nil {
			restoreAlloc()
			fs.mu.Unlock()
			return entryOutcome{}, err
		}
	}

	// Dirty-RSS admission (check-and-reserve) under the SAME fs.mu hold that
	// reserves the row's LSN: a row admitted here holds its worst-case block
	// growth in dirtyReserved until it applies, so concurrent writers near
	// the bound cannot all pass one stale check and overshoot at their apply
	// turns. Control-only rows reserve nothing — exactness outcomes, session
	// terminals, and lock releases stay recordable at the bound, mirroring
	// the journal control reserve. The refusal is pre-reservation and
	// definite: nothing was journaled, and the identity is free to record a
	// durable rejection.
	var dirtyReserve int64
	if records != nil {
		dirtyReserve = dirtyWriteReserveTotal(leavesOf(records))
	}
	if err := fs.reserveDirtyGrowthLocked(dirtyReserve); err != nil {
		restoreAlloc()
		fs.mu.Unlock()
		return entryOutcome{}, err
	}
	defer fs.releaseDirtyReserve(dirtyReserve) // the apply (or any failure) settles the exact bytes

	entry := pfj3.JournalEntry{Controls: controls}
	if records != nil {
		entry.Tree = &records[0]
	}
	first, end, err := fs.managed.log.AppendEntriesBuffered([]pfj3.JournalEntry{entry})
	if err != nil {
		restoreAlloc()
		fs.mu.Unlock()
		return entryOutcome{}, err
	}
	if end != first+1 {
		// One entry must reserve exactly one LSN; anything else means the
		// log broke the contiguous-reservation contract and the applied
		// cursor can no longer be trusted. The reservation already exists,
		// so fence the authority rather than strand the LSN chain.
		restoreAlloc()
		fs.mu.Unlock()
		cause := fmt.Errorf("managed entry reserved [%d,%d) for one row", first, end)
		fs.log.Poison()
		fs.seq.poisonWith(cause)
		return entryOutcome{}, fmt.Errorf("%w (reservation shape: %v)", ErrDurabilityUnknown, cause)
	}
	tx.Commit()
	staged = true
	fs.mu.Unlock()

	// Durability: the one fenced database transaction. Only after it commits
	// does anything become visible.
	if err := fs.log.CommitThrough(end - 1); err != nil {
		fs.seq.poisonWith(err)
		return entryOutcome{}, fmt.Errorf("%w (managed entry durability: %v)", ErrDurabilityUnknown, err)
	}
	if err := fs.seq.waitTurn(first); err != nil {
		return entryOutcome{}, err
	}
	if err := fs.hydrateCommittedEntryTargets(entry); err != nil {
		return entryOutcome{}, err
	}
	// The row's exact applied position comes from the append RESERVATION
	// return (one entry: end == first+1), never from a log-mutated
	// entry.LSN, and the apply advances it ITSELF while fs.mu is still held
	// — tree transition, applied watermark, and publication are one
	// visibility unit, so a snapshot can never capture the new tree with
	// the old cursor. A failed apply self-fences WITHOUT advancing.
	out, aerr := fs.applyCommittedEntry(entry, owner, end)
	if aerr != nil {
		return entryOutcome{}, aerr
	}
	return out, nil
}

// entrySpec is one staged managed row: an optional validated tree record plus
// its ordered controls. through is the flush watermark the row advances (0
// for rows that carry none) — used to report the durable prefix on failure.
type entrySpec struct {
	tree     *wal.Record
	controls []pfc2.Record
	through  uint64
}

// commitEntriesGroup validates, reserves, journals, applies, and publishes an
// ORDERED list of managed rows with one durability barrier: all rows stage in
// one reservation transaction (all-or-nothing), one CommitThrough covers the
// whole range (the journal groups the rows into as few fenced database
// transactions as its bounds allow), and the rows apply strictly in order —
// each row remains its own visibility unit. Returns the highest flush
// watermark (entrySpec.through) among rows proven durable AND applied, so a
// failure mid-barrier reports exactly the durable prefix.
func (fs *FS) commitEntriesGroup(specs []entrySpec, owner string) (uint64, error) {
	if fs.managed == nil {
		return 0, ErrNotManaged
	}
	if len(specs) == 0 {
		return 0, invalidMutation("managed group carries no rows")
	}
	if err := fs.admit.enter(); err != nil {
		return 0, err
	}
	defer fs.admit.exit()

	entries := make([]pfj3.JournalEntry, 0, len(specs))
	for i := range specs {
		spec := &specs[i]
		if spec.tree == nil && len(spec.controls) == 0 {
			return 0, invalidMutation("managed group row %d carries neither tree nor controls", i)
		}
		if spec.tree != nil {
			trust := intentUser
			if spec.tree.Op.IsBatch() {
				trust = intentWritebackBatch
			} else if spec.tree.Env != nil {
				trust = intentExactUser
			}
			normalized, err := fs.normalizeAndValidateIntent([]wal.Record{*spec.tree}, trust)
			if err != nil {
				return 0, fmt.Errorf("managed group row %d: %w", i, err)
			}
			spec.tree = &normalized[0]
		}
		entry := pfj3.JournalEntry{Controls: spec.controls}
		entry.Tree = spec.tree
		entries = append(entries, entry)
	}
	// Lazy-base hydration OUTSIDE fs.mu before the group reserves; the
	// per-row exact pass under the apply turn settles the rest.
	for i := range specs {
		if specs[i].tree == nil {
			continue
		}
		if herr := fs.hydrateIntentTargets(context.Background(), leavesOf([]wal.Record{*specs[i].tree}), hydrateOptimistic); herr != nil {
			return 0, fmt.Errorf("managed group row %d: %w", i, herr)
		}
		fs.warmIntentWriteTargets(leavesOf([]wal.Record{*specs[i].tree}))
	}

	fs.mu.Lock()
	nowMs := time.Now().UnixMilli()
	for i := range specs {
		if specs[i].tree == nil {
			continue
		}
		// Prepare IN PLACE: identity preassignment and server timestamps
		// must land in the exact record the row journals, or the durable
		// row would carry ino 0 / ts 0 and replay would RE-DERIVE fresh
		// identities at its own cursor — different inode numbers than the
		// live tree handed out (and nondeterministic timestamps).
		records := []wal.Record{*specs[i].tree}
		if err := fs.prepareIntentLocked(records, nowMs); err != nil {
			fs.mu.Unlock()
			return 0, fmt.Errorf("managed group row %d: %w", i, err)
		}
		*specs[i].tree = records[0]
		entries[i].Tree = specs[i].tree
	}
	tx := fs.managed.reserved.Begin()
	staged := false
	defer func() {
		if !staged {
			tx.Rollback()
		}
	}()
	for i := range specs {
		if specs[i].tree != nil {
			for _, leaf := range leavesOf([]wal.Record{*specs[i].tree}) {
				if leaf.Env.Valid() {
					key, err := managedExactKey(leaf.Env)
					if err != nil {
						fs.mu.Unlock()
						return 0, err
					}
					if err := tx.RecordExternalOutcome(key, pfc2.Outcome{}); err != nil {
						fs.mu.Unlock()
						return 0, err
					}
				}
			}
		}
		for c := range specs[i].controls {
			if _, err := tx.Apply(&specs[i].controls[c]); err != nil {
				fs.mu.Unlock()
				return 0, fmt.Errorf("managed group row %d control %d: %w", i, c, err)
			}
		}
	}
	// Dirty-RSS admission for the whole group, atomic with its LSN
	// reservation (same rationale as commitEntryDynamicTree): the summed
	// worst-case growth of every write leaf is either reserved here or the
	// whole group refuses before anything journals.
	var dirtyReserve int64
	for i := range specs {
		if specs[i].tree != nil {
			dirtyReserve += dirtyWriteReserveTotal(leavesOf([]wal.Record{*specs[i].tree}))
		}
	}
	if err := fs.reserveDirtyGrowthLocked(dirtyReserve); err != nil {
		fs.mu.Unlock()
		return 0, err
	}
	defer fs.releaseDirtyReserve(dirtyReserve)

	first, end, err := fs.managed.log.AppendEntriesBuffered(entries)
	if err != nil {
		fs.mu.Unlock()
		return 0, err
	}
	if end != first+uint64(len(entries)) {
		// The reservation contract — contiguous LSNs, exactly one per entry
		// — broke, and the buffered reservation cannot be abandoned (a later
		// durability barrier would commit rows this authority never applied).
		// Fence the authority.
		fs.mu.Unlock()
		cause := fmt.Errorf("managed group reserved [%d,%d) for %d rows", first, end, len(entries))
		fs.log.Poison()
		fs.seq.poisonWith(cause)
		return 0, fmt.Errorf("%w (reservation shape: %v)", ErrDurabilityUnknown, cause)
	}
	tx.Commit()
	staged = true
	fs.mu.Unlock()

	if err := fs.log.CommitThrough(end - 1); err != nil {
		fs.seq.poisonWith(err)
		return 0, fmt.Errorf("%w (managed group durability: %v)", ErrDurabilityUnknown, err)
	}
	if err := fs.seq.waitTurn(first); err != nil {
		return 0, err
	}
	var appliedThrough uint64
	for i := range entries {
		// The exact hydration pass runs per row, after every earlier row of
		// the group applied, so resolution reflects exactly this row's LSN.
		if err := fs.hydrateCommittedEntryTargets(entries[i]); err != nil {
			return appliedThrough, fmt.Errorf("managed group row %d: %w", i, err)
		}
		// Each row advances the applied cursor to ITS OWN exclusive position
		// (row i occupies LSN first+i; the positions derive from the append
		// reservation return, never from log-mutated entry fields) inside
		// the row's fs.mu visibility unit. A snapshot between rows therefore
		// sees exactly the applied prefix: tree and watermark are never torn
		// even mid-group. A failed row self-fences WITHOUT advancing — the
		// durable suffix stays for the replacement's cold replay.
		if _, err := fs.applyCommittedEntry(entries[i], owner, first+uint64(i)+1); err != nil {
			return appliedThrough, fmt.Errorf("managed group row %d apply: %w", i, err)
		}
		if specs[i].through > appliedThrough {
			appliedThrough = specs[i].through
		}
	}
	return appliedThrough, nil
}

// applyCommittedEntry applies one durable entry — tree then controls — under
// fs.mu as ONE atomic visibility unit: a staged tree undo transaction plus
// ONE PFC2 reducer transaction, validated across every arm, then EXACTLY one
// advanced applied cursor and one published revision — or none of them. The
// caller passes the row's exclusive applied position (appliedEnd), derived
// from the append reservation return; the cursor advances WHILE fs.mu IS
// STILL HELD, so a concurrent snapshot/probe (which takes fs.mu) can never
// pair the new tree with the old applied watermark, mid-group included. A
// post-durability mismatch (a durable row the live reducer refuses) rolls
// both transactions back, publishes nothing, advances nothing, and
// SELF-FENCES the authority (poisoned log + sequencer, so no later row can
// apply or acknowledge here); the row remains durable for the replacement's
// cold replay.
func (fs *FS) applyCommittedEntry(entry pfj3.JournalEntry, owner string, appliedEnd uint64) (out entryOutcome, err error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	tx := newMutationTransaction(fs)
	ctl := fs.managed.applied.Begin()
	committed := false
	defer func() {
		if committed {
			return
		}
		// Publish nothing, restore both views byte-for-byte, and fence.
		tx.rollback()
		ctl.Rollback()
		fs.log.Poison()
		fs.seq.poisonWith(fmt.Errorf("managed apply diverged from durable row %d: %v", entry.LSN, err))
	}()
	var invs []coherence.Invalidation
	var parkedInos, unpinnedInos []uint64
	if entry.Tree != nil {
		leaves, lerr := intentLeaves([]wal.Record{*entry.Tree})
		if lerr != nil {
			err = lerr
			return entryOutcome{}, err
		}
		for _, r := range leaves {
			if cerr := tx.captureMutation(r); cerr != nil {
				err = fmt.Errorf("workfs: managed apply undo capture (row %d): %w", entry.LSN, cerr)
				return entryOutcome{}, err
			}
			// THE one managed leaf reducer — identical semantics for live
			// apply and cold replay (and, through the shared transition
			// engine, HistoryCut materialization).
			relatedInos := fs.relatedInodesLocked(r)
			leaf, lerr := fs.applyManagedLeaf(r, managedLeafLive{ownerName: owner, tx: tx}, ctl)
			if lerr != nil {
				err = fmt.Errorf("workfs: managed apply intent %d: %w", entry.LSN, lerr)
				return entryOutcome{}, err
			}
			if leaf.changed {
				invs = append(invs, fs.changesFor(r, owner, leaf.res.Version, leaf.orphanIno, relatedInos...)...)
			}
			if leaf.orphanIno != 0 && leaf.changed {
				// A detached inode is a reap candidate the moment no durable
				// open pin holds it (never a wall-clock lease). Candidacy is
				// decided AFTER the atomic commit below. Do not mark it as a
				// pending reap here: pendingReaps is exclusively the
				// reservation fence for an OpReap row that has already won.
				// The sweep re-validates pin-freedom atomically at its own
				// staged position.
				parkedInos = append(parkedInos, leaf.orphanIno)
			}
			out.tree = append(out.tree, entryLeafOutcome{err: leaf.err, res: leaf.res})
		}
	}
	out.controls = make([]pfc2.ApplyResult, 0, len(entry.Controls))
	for i := range entry.Controls {
		res, cerr := ctl.Apply(&entry.Controls[i])
		if cerr != nil {
			err = fmt.Errorf("workfs: managed apply control %d: %w", i, cerr)
			return entryOutcome{}, err
		}
		out.controls = append(out.controls, res)
		unpinnedInos = append(unpinnedInos, res.NewlyUnpinnedInos...)
	}
	ctl.Commit()
	committed = true
	// Reap candidacy is decided only AFTER the atomic commit (the reducer
	// lock is released; nothing here can roll back anymore). The
	// asynchronous sweep journals the deterministic OpReap rows; its
	// decisions re-validate (still parked, still pin-free) atomically at
	// their own staged positions.
	schedule := false
	for _, ino := range parkedInos {
		if fs.orphans[ino] != nil && len(fs.managed.applied.PinHolders(ino)) == 0 {
			schedule = true
		}
	}
	for _, ino := range unpinnedInos {
		if fs.orphans[ino] != nil {
			schedule = true
		}
	}
	if schedule {
		fs.scheduleReapSweep()
	}
	// Applied-cursor advance and revision publication happen INSIDE the same
	// fs.mu hold as the tree transition: this row's visibility unit is
	// exactly {tree state, applied watermark, published revision}. Waking a
	// later writer's turn here is safe — it still needs fs.mu (released by
	// our deferred unlock) before it can apply.
	fs.seq.advance(appliedEnd)
	fs.publish(invs)
	return out, nil
}

// leavesOf unwraps a validated intent into its leaves without error paths
// (the intent was already validated).
func leavesOf(records []wal.Record) []wal.Record {
	if len(records) == 1 && records[0].Op.IsBatch() {
		return records[0].Mutations
	}
	return records
}

// hydrateCommittedEntryTargets is the exact lazy-base pass for one DURABLE
// managed row, run under the held apply turn (nothing else can apply, so
// the fixpoint is guaranteed): the row's remaining undecided names hydrate
// before the locked apply, which then resolves entirely in memory. A
// durable row whose inputs cannot be decided fences the authority exactly
// like an apply divergence — the row stays in the journal for the
// replacement's cold replay.
func (fs *FS) hydrateCommittedEntryTargets(entry pfj3.JournalEntry) error {
	if entry.Tree == nil {
		return nil
	}
	if fs.pft2 != nil {
		if err := fs.hydrateIntentTargets(context.Background(), leavesOf([]wal.Record{*entry.Tree}), hydrateExact); err != nil {
			fs.log.Poison()
			fs.seq.poisonWith(err)
			return fmt.Errorf("%w (lazy base hydration for durable row %d: %v)", ErrDurabilityUnknown, entry.LSN, err)
		}
	}
	// Exact warm under the held turn: the row's write targets are settled
	// now (nothing else can apply), so the locked apply's read-modify-write
	// is a cache hit instead of remote I/O under fs.mu. Best-effort — the
	// under-lock read remains the correctness fallback for eviction races.
	fs.warmIntentWriteTargets(leavesOf([]wal.Record{*entry.Tree}))
	return nil
}

// warmIntentWriteTargets pre-reads, strictly OUTSIDE fs.mu, the base blocks
// every OpWrite leaf will only PARTIALLY overwrite, so the apply's
// writeBlocks read-modify-write — which runs under fs.mu — hits warm caches
// (the content cache for blob/chunk sources, the verified pack cache and
// decoded-node cache for lazy PFT2 rangers) instead of stalling every other
// writer on remote I/O. Purely an optimization: correct under every race
// (writeBlocks re-reads through the same caches and falls back to a remote
// read only when eviction lost the warm bytes).
func (fs *FS) warmIntentWriteTargets(leaves []wal.Record) {
	for i := range leaves {
		r := &leaves[i]
		if r.Op != wal.OpWrite || len(r.Data) == 0 {
			continue
		}
		fs.mu.RLock()
		n := fs.resolveForRW(r.Path, r.Ino)
		off := r.Offset
		if r.Append && n != nil && n.kind == "file" {
			// Approximate EOF sample; the apply resolves the exact offset at
			// its ordered position. A stale sample only mis-warms.
			off = n.curSize()
		}
		fs.mu.RUnlock()
		if n == nil {
			continue
		}
		fs.warmBaseForWriteNode(n, off, int64(len(r.Data)))
	}
}
