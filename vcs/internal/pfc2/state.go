package pfc2

import (
	"crypto/sha256"
	"sort"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

// State is the deterministic PFC2 reducer: the complete journaled control
// state of one authority generation. Records apply in ONE total order (the
// journal order); every apply fully validates against immutable state before
// mutating, and a transaction stages atomically with complete rollback.
//
// The integration layer drives the same State type for both of WorkFS's
// views: the reservation-order shadow (stage in a Txn under the reservation
// lock, roll back on failed staging) and the applied-order view (Apply after
// the journal commit). Replay of the identical records rebuilds the identical
// state; any record a correct authority could not have appended fails closed
// with a typed error instead of guessing at exactly-once state.
//
// State performs no wall-clock reads, keeps no reclaim grace, and never
// time-prunes outcomes or tombstones: capacity is explicit and exhaustion
// rejects new state with ErrCapacity.
type State struct {
	mu sync.RWMutex

	// sessions holds, per session id, the latest generation: live or its
	// retained compact tombstone. Lower generations are fenced by ordering.
	sessions     map[string]*sessionState
	liveSessions int
	slotStates   int

	locks     map[uint64][]HeldLock // by stable inode; normalized
	lockCount int

	checkouts map[string]checkoutGrant // by canonical path; non-overlapping
	pins      map[uint64]map[SessionRef]struct{}
	pinCount  int
	ledger    map[string]ledgerEntry // by writebackID (one entry per mount stream)

	nextEpoch Epoch

	// dbTimeFloorMs is the durable database-time floor: the maximum minted
	// database time any applied record has carried (session opens, renewals,
	// and expiry decisions). Database time is the ONLY clock PFC2 knows; the
	// floor makes it non-regressive under the journal's total order, so a
	// record minted "in the past" — a host wall clock smuggled in, an
	// old-authority straggler, or a corrupted value — fails closed.
	dbTimeFloorMs int64
}

type sessionState struct {
	ref      SessionRef
	terminal bool
	reason   TerminalReason // valid when terminal

	// Live-generation identity; cleared to the compact tombstone on terminal.
	owner       string
	tokenHash   [TokenHashBytes]byte
	slots       uint32
	timeSource  TimeSource
	issuedDbMs  int64
	expiresDbMs int64

	slotStates map[uint32]*slotState
}

// slotState is one slot's exact-outcome floor state. retiredThrough is fully
// determined by (nextSeq, latest): admitting N proves the client completed
// N-1, so at most one latest outcome is ever retained per slot.
type slotState struct {
	nextSeq uint64 // exactly this sequence may be admitted next
	latest  *latestOutcome
}

type latestOutcome struct {
	seq  uint64
	hash [RequestHashBytes]byte
	out  Outcome
}

func (s *slotState) retiredThrough() uint64 {
	if s.latest != nil {
		return s.latest.seq - 1
	}
	return s.nextSeq - 1
}

type checkoutGrant struct {
	holder SessionRef
	epoch  Epoch
	// writebackID binds a delegation grant to its mount write-back stream;
	// empty for plain coordination checkouts.
	writebackID string
	// recovery marks a delegation whose holder went terminal without a
	// clean release: it blocks peers until rebound or discarded.
	recovery bool
}

// laneMark is one lane's durable position: its watermark and the chained
// mutation digest at that watermark. The zero value means the lane has never
// applied anything, which is distinguishable from any applied position because
// a lane's first sequence is 1.
type laneMark struct {
	through uint64
	digest  [DigestBytes]byte
}

// ledgerEntry is one mount stream's durable flush state: ONE entry per stream
// carrying every lane's independent (watermark, digest) pair, plus the session
// that last advanced any of them.
//
// The lanes live in one entry rather than one entry per (stream, lane) so that
// every landed bound and sweep keeps meaning what it meant: MaxFlushEntries
// still counts STREAMS, session death still retires a stream in one step, and
// the projection key is still the writeback id alone (so a stream with no laned
// state projects to byte-identical bytes and the projection digest of existing
// control state is unchanged).
type ledgerEntry struct {
	// through/digest are the LEGACY lane, spelled as the original fields so
	// every existing read of "the stream's watermark" keeps naming the single
	// total-order stream it has always named.
	through uint64
	digest  [DigestBytes]byte
	ns      laneMark
	data    laneMark
	owner   SessionRef
}

// mark reads one lane's durable position.
func (e ledgerEntry) mark(lane StreamLane) laneMark {
	switch lane {
	case StreamLaneNamespace:
		return e.ns
	case StreamLaneData:
		return e.data
	default:
		return laneMark{through: e.through, digest: e.digest}
	}
}

// withMark returns e with one lane's position replaced.
func (e ledgerEntry) withMark(lane StreamLane, m laneMark) ledgerEntry {
	switch lane {
	case StreamLaneNamespace:
		e.ns = m
	case StreamLaneData:
		e.data = m
	default:
		e.through, e.digest = m.through, m.digest
	}
	return e
}

// NewState returns the empty control state of a fresh generation: no
// sessions, no coordination, next checkout epoch 1.
func NewState() *State {
	return &State{
		sessions:  map[string]*sessionState{},
		locks:     map[uint64][]HeldLock{},
		checkouts: map[string]checkoutGrant{},
		pins:      map[uint64]map[SessionRef]struct{}{},
		ledger:    map[string]ledgerEntry{},
		nextEpoch: FirstEpoch,
	}
}

// ─── read views ─────────────────────────────────────────────────────────────

// SessionInfo is one session id's current view.
type SessionInfo struct {
	Ref      SessionRef
	Terminal bool
	Reason   TerminalReason // valid when Terminal
	Owner    string
	Slots    uint32
	// TimeSource declares who minted the lease facts below (TimeSourceDB).
	TimeSource TimeSource
	// IssuedDbMs is the database time the generation was opened.
	IssuedDbMs int64
	// ExpiresDbMs is the durable database-time lease deadline. It is
	// comparable ONLY to other database-issued times (State.DbTimeFloorMs, a
	// fresh DBTimeFact) — never to a host wall clock.
	ExpiresDbMs int64
}

// Session returns the latest generation recorded for a session id.
func (st *State) Session(sessionID string) (SessionInfo, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	s, ok := st.sessions[sessionID]
	if !ok {
		return SessionInfo{}, false
	}
	return SessionInfo{
		Ref: s.ref, Terminal: s.terminal, Reason: s.reason,
		Owner: s.owner, Slots: s.slots,
		TimeSource: s.timeSource, IssuedDbMs: s.issuedDbMs, ExpiresDbMs: s.expiresDbMs,
	}, true
}

// DbTimeFloorMs returns the durable database-time floor: the latest minted
// database time any applied record carried. 0 means no time fact has ever
// been journaled.
func (st *State) DbTimeFloorMs() int64 {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.dbTimeFloorMs
}

// LiveSessions returns every live (non-terminal) session generation, ordered
// by session id. Integrations use it to SCHEDULE database-time expiry
// re-checks; the returned deadlines are database times and never compare
// against host clocks for authorization.
func (st *State) LiveSessions() []SessionInfo {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]SessionInfo, 0, st.liveSessions)
	for _, s := range st.sessions {
		if s.terminal {
			continue
		}
		out = append(out, SessionInfo{
			Ref: s.ref, Owner: s.owner, Slots: s.slots,
			TimeSource: s.timeSource, IssuedDbMs: s.issuedDbMs, ExpiresDbMs: s.expiresDbMs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref.SessionID < out[j].Ref.SessionID })
	return out
}

// SessionTokenHash returns the live generation's reconnect credential hash.
func (st *State) SessionTokenHash(ref SessionRef) ([TokenHashBytes]byte, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	s := st.liveSessionLocked(ref)
	if s == nil {
		return [TokenHashBytes]byte{}, false
	}
	return s.tokenHash, true
}

func (st *State) liveSessionLocked(ref SessionRef) *sessionState {
	s := st.sessions[ref.SessionID]
	if s == nil || s.terminal || s.ref.Generation != ref.Generation {
		return nil
	}
	return s
}

// SlotView is one slot's durable floor state.
type SlotView struct {
	NextSeq        uint64
	RetiredThrough uint64
	HasLatest      bool
	LatestSeq      uint64
	LatestHash     [RequestHashBytes]byte
	LatestOutcome  Outcome
}

// Slot returns one slot's state for a live session generation.
func (st *State) Slot(ref SessionRef, slot uint32) (SlotView, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	s := st.liveSessionLocked(ref)
	if s == nil {
		return SlotView{}, false
	}
	ss := s.slotStates[slot]
	if ss == nil {
		return SlotView{NextSeq: 1}, true
	}
	v := SlotView{NextSeq: ss.nextSeq, RetiredThrough: ss.retiredThrough()}
	if ss.latest != nil {
		v.HasLatest, v.LatestSeq, v.LatestHash, v.LatestOutcome = true, ss.latest.seq, ss.latest.hash, ss.latest.out
	}
	return v, true
}

// ExactDisposition classifies one presented exact identity against the slot
// table (the admission decision of docs/pfc2-control-format.md).
type ExactDisposition uint8

const (
	// ExactAdmit: the identity is exactly nextSeq — execute exactly once.
	ExactAdmit ExactDisposition = iota + 1
	// ExactReplay: the identity matches the retained latest outcome — return
	// the stored outcome without re-executing.
	ExactReplay
	// ExactRetired: the sequence is at or below the durable floor — answer
	// with the explicit OutcomeRetired result; never re-execute, never fence.
	ExactRetired
	// ExactConflict: the latest sequence was reused with DIFFERENT bytes —
	// proof of client corruption; durably fence the generation.
	ExactConflict
	// ExactGap: a sequence gap, unexplained future sequence, or slot outside
	// the granted window — proof of client corruption; durably fence.
	ExactGap
	// ExactSessionUnknown: the session id/generation is unknown, superseded,
	// or terminal — fence the request with ESTALE; never a fresh identity.
	ExactSessionUnknown
)

// ExactCheck is the result of CheckExact.
type ExactCheck struct {
	Disposition ExactDisposition
	Outcome     Outcome // stored outcome for ExactReplay
}

// CheckExact classifies key without changing state. Callers serialize
// admission per (session, slot) themselves; the classification is only as
// current as the state it ran against.
func (st *State) CheckExact(key ExactKey) ExactCheck {
	st.mu.RLock()
	defer st.mu.RUnlock()
	s := st.liveSessionLocked(key.Session)
	if s == nil {
		return ExactCheck{Disposition: ExactSessionUnknown}
	}
	if key.Slot >= s.slots {
		return ExactCheck{Disposition: ExactGap}
	}
	ss := s.slotStates[key.Slot]
	if ss == nil {
		if key.SlotSeq == 1 {
			return ExactCheck{Disposition: ExactAdmit}
		}
		return ExactCheck{Disposition: ExactGap}
	}
	switch {
	case key.SlotSeq == ss.nextSeq:
		return ExactCheck{Disposition: ExactAdmit}
	case ss.latest != nil && key.SlotSeq == ss.latest.seq:
		if key.RequestHash == ss.latest.hash {
			return ExactCheck{Disposition: ExactReplay, Outcome: ss.latest.out}
		}
		return ExactCheck{Disposition: ExactConflict}
	case key.SlotSeq <= ss.retiredThrough():
		return ExactCheck{Disposition: ExactRetired}
	default:
		return ExactCheck{Disposition: ExactGap}
	}
}

// HeldLocks returns the normalized granted intervals on one inode.
func (st *State) HeldLocks(ino uint64) []HeldLock {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return append([]HeldLock(nil), st.locks[ino]...)
}

// LockConflict reports the first lock in canonical order that would block
// owner acquiring the range (F_GETLK and setlk admission).
func (st *State) LockConflict(ino uint64, owner LockOwner, start, length uint64, write bool) (HeldLock, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return lockConflict(st.locks[ino], owner, start, lockEnd(start, length), write)
}

// CheckoutView is one granted checkout.
type CheckoutView struct {
	Path        string
	Holder      SessionRef
	Epoch       Epoch
	WritebackID string
	Recovery    bool
}

// CheckoutAt returns the grant covering exactly path.
func (st *State) CheckoutAt(path string) (CheckoutView, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	g, ok := st.checkouts[path]
	if !ok {
		return CheckoutView{}, false
	}
	return checkoutView(path, g), true
}

func checkoutView(path string, g checkoutGrant) CheckoutView {
	return CheckoutView{Path: path, Holder: g.holder, Epoch: g.epoch, WritebackID: g.writebackID, Recovery: g.recovery}
}

// OverlappingCheckouts returns every grant whose subtree overlaps path
// (equal, ancestor, or descendant), sorted by path.
func (st *State) OverlappingCheckouts(path string) []CheckoutView {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.overlappingCheckoutsLocked(path)
}

func (st *State) overlappingCheckoutsLocked(path string) []CheckoutView {
	var out []CheckoutView
	for p, g := range st.checkouts {
		if pathsOverlap(p, path) {
			out = append(out, checkoutView(p, g))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// StreamCheckouts returns every grant bound to one write-back stream,
// sorted by path.
func (st *State) StreamCheckouts(writebackID string) []CheckoutView {
	st.mu.RLock()
	defer st.mu.RUnlock()
	var out []CheckoutView
	for p, g := range st.checkouts {
		if g.writebackID == writebackID && writebackID != "" {
			out = append(out, checkoutView(p, g))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// RecallDigest is the canonical digest of the conflict set a force transfer
// must have recalled: SHA-256 over "PFC2" || 0xF1 || the strict pfwire
// encoding of the overlapping grants sorted by path (repeated message
// {1 path, 2 session, 3 epoch}). A CheckoutForceTransfer record must carry
// exactly this digest as computed when the recall was issued; if the conflict
// set changed in between (holder released, fresh grant appeared), the digest
// no longer matches and the stale transfer cannot revoke the new holder.
func RecallDigest(conflicts []CheckoutView) [DigestBytes]byte {
	sorted := append([]CheckoutView(nil), conflicts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	var body []byte
	for _, c := range sorted {
		var entry []byte
		entry = pfwire.AppendString(entry, 1, c.Path)
		entry = pfwire.AppendBytes(entry, 2, appendSessionRef(nil, c.Holder))
		entry = pfwire.AppendString(entry, 3, string(c.Epoch))
		body = pfwire.AppendBytes(body, 1, entry)
	}
	h := sha256.New()
	h.Write(Magic[:])
	h.Write([]byte{0xF1})
	h.Write(body)
	var out [DigestBytes]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RecallDigestAt computes RecallDigest for the grants currently overlapping
// path (what a recall issued right now would capture).
func (st *State) RecallDigestAt(path string) [DigestBytes]byte {
	return RecallDigest(st.OverlappingCheckouts(path))
}

// StreamStateView is one mount stream's durable flush state: the legacy
// single-stream watermark plus every lane's independent one.
type StreamStateView struct {
	WritebackID string
	Through     uint64
	Digest      [DigestBytes]byte
	Owner       SessionRef
	// NSThrough/NSDigest and DataThrough/DataDigest are the namespace and data
	// lanes. Zero means the lane has applied nothing — either the stream is
	// still pre-boundary (legacy) or the lane simply has no records yet.
	NSThrough   uint64
	NSDigest    [DigestBytes]byte
	DataThrough uint64
	DataDigest  [DigestBytes]byte
}

// LaneThrough reads one lane's durable watermark out of the view.
func (v StreamStateView) LaneThrough(lane StreamLane) uint64 {
	switch lane {
	case StreamLaneNamespace:
		return v.NSThrough
	case StreamLaneData:
		return v.DataThrough
	default:
		return v.Through
	}
}

// LaneDigest reads one lane's durable chain digest out of the view.
func (v StreamStateView) LaneDigest(lane StreamLane) [DigestBytes]byte {
	switch lane {
	case StreamLaneNamespace:
		return v.NSDigest
	case StreamLaneData:
		return v.DataDigest
	default:
		return v.Digest
	}
}

// WritebackRebindView is one coherent read-only snapshot of the stream ledger
// and the exact checkout entries named by a recovery rebind. Scope vectors are
// aligned with the caller's ordered path vector.
type WritebackRebindView struct {
	Stream       StreamStateView
	StreamExists bool
	Scopes       []CheckoutView
	ScopeExists  []bool
}

// StreamState returns one write-back stream's durable watermark and digest.
func (st *State) StreamState(writebackID string) (StreamStateView, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	e, ok := st.ledger[writebackID]
	if !ok {
		return StreamStateView{}, false
	}
	return streamStateView(writebackID, e), true
}

func streamStateView(writebackID string, e ledgerEntry) StreamStateView {
	return StreamStateView{
		WritebackID: writebackID,
		Through:     e.through, Digest: e.digest,
		NSThrough: e.ns.through, NSDigest: e.ns.digest,
		DataThrough: e.data.through, DataDigest: e.data.digest,
		Owner: e.owner,
	}
}

// WritebackRebindSnapshot reads every fact used by rebind conflict
// evaluation under one reducer read lock. This prevents a duplicate audit
// from combining a stream watermark from one applied position with checkout
// holders from another.
func (st *State) WritebackRebindSnapshot(writebackID string, paths []string) WritebackRebindView {
	st.mu.RLock()
	defer st.mu.RUnlock()

	view := WritebackRebindView{
		Scopes:      make([]CheckoutView, len(paths)),
		ScopeExists: make([]bool, len(paths)),
	}
	if e, ok := st.ledger[writebackID]; ok {
		view.Stream = streamStateView(writebackID, e)
		view.StreamExists = true
	}
	for i, path := range paths {
		if grant, ok := st.checkouts[path]; ok {
			view.Scopes[i] = checkoutView(path, grant)
			view.ScopeExists[i] = true
		}
	}
	return view
}

// HasPin reports whether session holds the durable open pin on ino.
func (st *State) HasPin(session SessionRef, ino uint64) bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	_, ok := st.pins[ino][session]
	return ok
}

// PinnedInodes returns every inode with at least one durable open pin, in
// ascending order. Integrations use it to lift the inode allocator high-water
// past pinned-but-detached inodes on cold recovery (ids are never reused).
func (st *State) PinnedInodes() []uint64 {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]uint64, 0, len(st.pins))
	for ino := range st.pins {
		out = append(out, ino)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// LockedInodes returns every inode carrying at least one held POSIX lock, in
// ascending order (same high-water purpose as PinnedInodes).
func (st *State) LockedInodes() []uint64 {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]uint64, 0, len(st.locks))
	for ino := range st.locks {
		out = append(out, ino)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PinHolders returns the sessions holding pins on ino, in canonical order.
func (st *State) PinHolders(ino uint64) []SessionRef {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]SessionRef, 0, len(st.pins[ino]))
	for ref := range st.pins[ino] {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SessionID != out[j].SessionID {
			return out[i].SessionID < out[j].SessionID
		}
		return out[i].Generation < out[j].Generation
	})
	return out
}

// NextCheckoutEpoch returns the next server-controlled checkout epoch.
func (st *State) NextCheckoutEpoch() Epoch {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.nextEpoch
}

// Counts reports every bounded table's size (capacity observability).
type Counts struct {
	LiveSessions  int
	Tombstones    int
	SlotStates    int
	LockIntervals int
	Checkouts     int
	OpenPins      int
	FlushEntries  int
}

// Counts returns the current table sizes.
func (st *State) Counts() Counts {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return Counts{
		LiveSessions:  st.liveSessions,
		Tombstones:    len(st.sessions) - st.liveSessions,
		SlotStates:    st.slotStates,
		LockIntervals: st.lockCount,
		Checkouts:     len(st.checkouts),
		OpenPins:      st.pinCount,
		FlushEntries:  len(st.ledger),
	}
}

// DiscardTombstonesAtGenerationRetirement drops every retained terminal
// tombstone. A format generation may do this ONLY at exceptional generation
// retirement, after every session is terminal; it fails otherwise. Ordinary
// operation never prunes tombstones.
func (st *State) DiscardTombstonesAtGenerationRetirement() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.liveSessions != 0 {
		return integrityf("%d sessions are still live; tombstones may be discarded only after every session is terminal", st.liveSessions)
	}
	st.sessions = map[string]*sessionState{}
	return nil
}
