package clientcore

import (
	"container/list"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// This file is the mount side of Stage-2 open-state tracking (see
// docs/open-after-unlink.md). The contract it must preserve, unchanged: at the
// moment an open() returns to the application, this mount's hold on the inode
// is applied at the authority, so a concurrent peer unlink PARKS the inode
// (delete-on-last-close) instead of destroying it; and an open whose inode was
// already destroyed fails ENOENT rather than returning a dead handle.
//
// What changed for op-count (the mark_open reduction):
//
//   - Per-inode coalescing: concurrent opens of one inode share a single
//     in-flight MarkOpen (joiners observe the same race outcome by awaiting
//     the same reply) and refcounted re-opens of an already-registered inode
//     round-trip zero times. Correct because the guarantee is about the hold
//     being APPLIED at the authority when open() returns — one applied hold
//     covers every local handle.
//   - Registration retention: the LAST close does not unmark. The
//     registration is retained (bounded LRU) and kept alive by the periodic
//     renewal, so re-opening a recently-closed inode is another zero-RPC hit.
//     Reuse is validated by authority generation stamp and renewal freshness
//     (invalidation/lease-driven, never a coherence TTL): a stale entry just
//     falls back to a fresh MarkOpen — fail-closed, one RPC, today's path.
//   - Deferred batched unmarks: releasing a hold has no synchronous
//     contract (until the unmark applies, the authority errs toward parking,
//     and a spuriously parked inode is reclaimed by orphan lease GC), so
//     unmarks queue and flush as one OpUnmarkOpenInodes batch. The one
//     op-ORDER dependency is a name mutation by this same mount whose
//     park-vs-destroy decision reads our holds: Remove/Rename call
//     ReleaseNameChange first, which flushes synchronously.
//
// All three behaviors are gated on the authority advertising
// baseline open registration; without it every open would mark and every
// last close unmarks, bit-for-bit the previous behavior.

// retentionLeaseSlack bounds how stale the last authority confirmation (a
// MarkOpen reply or a RenewOpenInodes round) of a registration may be for a
// zero-RPC reuse. It must stay well under the authority's open-lease TTL
// (workfs orphanLeaseTTL, 60s) minus a renewal period (20s): within the slack
// the hold provably still exists server-side. This is lease liveness — the
// same wall-clock lease contract RenewOpenInodes already implements — not a
// coherence TTL: expiry only forces the next open to pay a MarkOpen RPC,
// never lets anyone observe stale data.
const retentionLeaseSlack = 30 * time.Second

// defaultOpenRetentionEntries bounds the retained-registration LRU. Sized to
// cover a repository-scale working set (a warm grep re-opens every file) at a
// few dozen bytes per entry client-side and one map entry server-side.
const defaultOpenRetentionEntries = 65536

// unmarkFlushBatch bounds one OpUnmarkOpenInodes RPC (mirrors the write-back
// flush record bound; pure batching, apply semantics per ino unchanged).
const unmarkFlushBatch = 512

// renewChunk bounds one RenewOpenInodes RPC now that retained registrations
// can make the renewal set large.
const renewChunk = 4096

// OpenRegistrar is the authority surface the registry drives
// (*fsproto.Client implements it; tests substitute fakes).
type OpenRegistrar interface {
	MarkOpenGen(ino uint64) (int32, uint64, error)
	UnmarkOpen(ino uint64) (int32, error)
	UnmarkOpenBatch(inos []uint64) (int32, error)
}

type openRegEntry struct {
	ino  uint64
	path string // last name this ino was opened/closed under; retention index for self name-mutation release
	refs int    // local open handles on this ino, across every NodeState

	registered  bool      // the authority confirmed a hold (mark OK or renewal round)
	gen         uint64    // authority generation of that confirmation
	confirmedAt time.Time // when the authority last confirmed the hold
	noRetain    bool      // orphaned/name-dropped: unmark on last close instead of retaining

	pending chan struct{} // non-nil while a mark or unmark RPC covering this ino is in flight
	queued  bool          // sitting in unmarkQueue awaiting a batched unmark
	lru     *list.Element // non-nil while retained (refs==0, registered, not queued)
}

// openRegistry serializes every per-inode registration transition (mark,
// reuse, unmark) so RPCs for one ino can never reorder against each other,
// and owns the retention LRU plus the deferred unmark queue.
type openRegistry struct {
	reg     OpenRegistrar
	curGen  func() uint64 // the volume's currently anchored authority generation
	openSet *InodeSet     // renewal view: every ino with a live or retained registration
	debugf  func(string, ...any)

	// retentionCap bounds retained (closed but still registered) entries;
	// fused-create open registration and batched unmarks are part of the v5
	// baseline.
	retentionCap int

	mu          sync.Mutex
	entries     map[uint64]*openRegEntry
	byPath      map[string]uint64 // retained (refs==0) entries only
	lru         *list.List        // retained entries, least-recently-closed at front
	unmarkQueue []uint64
	flushing    bool
}

func newOpenRegistry(reg OpenRegistrar, curGen func() uint64, openSet *InodeSet, retentionCap int, debugf func(string, ...any)) *openRegistry {
	if retentionCap == 0 {
		retentionCap = defaultOpenRetentionEntries
	}
	return &openRegistry{
		reg: reg, curGen: curGen, openSet: openSet, debugf: debugf,
		retentionCap: retentionCap,
		entries:      map[uint64]*openRegEntry{}, byPath: map[string]uint64{}, lru: list.New(),
	}
}

func (r *openRegistry) debug(format string, a ...any) {
	if r.debugf != nil {
		r.debugf(format, a...)
	}
}

func (r *openRegistry) retentionOn() bool { return r.retentionCap > 0 }

// retentionValidLocked reports whether a retained registration may be reused
// with zero round-trips: confirmed under the CURRENT authority generation (a
// restarted authority lost its in-memory open table, so old-generation stamps
// are worthless until a renewal re-creates the hold) and within the lease
// slack (a hold the renewal loop has not confirmed recently may have been
// pruned server-side). Both checks fail toward a fresh MarkOpen.
func (r *openRegistry) retentionValidLocked(e *openRegEntry) bool {
	if !r.retentionOn() || e.noRetain || !e.registered {
		return false
	}
	if e.gen == 0 || e.gen != r.curGen() {
		return false
	}
	return time.Since(e.confirmedAt) < retentionLeaseSlack
}

func (r *openRegistry) detachRetainedLocked(e *openRegEntry) {
	if e.lru != nil {
		r.lru.Remove(e.lru)
		e.lru = nil
	}
	if e.path != "" && r.byPath[e.path] == e.ino {
		delete(r.byPath, e.path)
	}
}

func (r *openRegistry) unqueueLocked(e *openRegEntry) {
	if !e.queued {
		return
	}
	e.queued = false
	for i, ino := range r.unmarkQueue {
		if ino == e.ino {
			r.unmarkQueue = append(r.unmarkQueue[:i], r.unmarkQueue[i+1:]...)
			break
		}
	}
	r.openSet.Add(e.ino)
}

// queueUnmarkLocked schedules e's hold for release. The ino leaves the
// renewal view IMMEDIATELY: a renewal that fired after the unmark applied
// would re-create the hold server-side (RenewOpenInodes registers absent
// entries), leaving a ghost hold only lease expiry could clear.
func (r *openRegistry) queueUnmarkLocked(e *openRegEntry) {
	if e.queued {
		return
	}
	r.detachRetainedLocked(e)
	r.openSet.Remove(e.ino)
	e.queued = true
	r.unmarkQueue = append(r.unmarkQueue, e.ino)
}

func (r *openRegistry) kickFlushLocked() {
	if r.flushing || len(r.unmarkQueue) == 0 {
		return
	}
	r.flushing = true
	go r.flushUnmarks()
}

// Open registers one open of ino. It returns success only when the authority
// has confirmed the hold under the current generation and lease window;
// transport errors and definite refusals fail the open instead of exposing an
// unpinned handle. Exactly one MarkOpen round-trips per inode transition, and
// joiners re-examine that confirmed result.
func (r *openRegistry) Open(path string, ino uint64) Status {
	if ino == 0 {
		return fsproto.OK
	}
	r.mu.Lock()
	for {
		e := r.entries[ino]
		if e == nil {
			e = &openRegEntry{ino: ino}
			r.entries[ino] = e
		}
		if e.pending != nil {
			// A mark or unmark transition is mid-flight for this ino. Await
			// it and re-examine: per-inode RPC order is what keeps a fresh
			// mark from racing a deferred unmark on another pool connection.
			ch := e.pending
			r.mu.Unlock()
			<-ch
			r.mu.Lock()
			continue
		}
		if e.queued {
			// The deferred unmark was decided but never sent: cancel it and
			// reuse the still-live hold. Equivalent to the unlink/open race
			// resolving in the open's favor — no RPC ever left, so there is
			// no ordering to violate.
			r.unqueueLocked(e)
			e.noRetain = false
		}
		if e.refs > 0 && r.retentionValidLocked(e) {
			e.refs++
			e.path = path
			r.mu.Unlock()
			return fsproto.OK
		}
		if r.retentionValidLocked(e) {
			// Retained-registration reuse: the hold is applied at the
			// authority, so a peer unlink ordered after this open parks —
			// the same guarantee the per-open MarkOpen bought, for zero
			// round-trips. A destroyed inode is impossible here: destruction
			// requires no live holds, and this hold is live.
			r.detachRetainedLocked(e)
			e.refs = 1
			e.path = path
			r.mu.Unlock()
			return fsproto.OK
		}
		// First open of this ino (or a stale retained entry): the hold must
		// be applied at the authority before the open returns.
		ch := make(chan struct{})
		e.pending = ch
		r.detachRetainedLocked(e)
		requestPath := path
		previousPath := e.path
		e.path = path
		r.mu.Unlock()
		st, gen, err := r.reg.MarkOpenGen(ino)
		r.mu.Lock()
		e.pending = nil
		close(ch)
		switch {
		case err != nil:
			r.debug("MarkOpen %d: %v", ino, err)
			r.restoreAfterFailedOpenLocked(e, requestPath, previousPath)
			r.mu.Unlock()
			return fsproto.EIO
		case st == fsproto.OK:
			e.refs++
			e.registered = true
			e.gen = gen
			e.confirmedAt = time.Now()
			r.openSet.Add(ino)
			r.mu.Unlock()
			return fsproto.OK
		default:
			r.restoreAfterFailedOpenLocked(e, requestPath, previousPath)
			r.mu.Unlock()
			return st
		}
	}
}

func (r *openRegistry) restoreAfterFailedOpenLocked(e *openRegEntry, requestPath, previousPath string) {
	if e.path == requestPath {
		// A concurrent successful rename may already have changed e.path.
		// Preserve that re-key; otherwise restore the live entry's old name.
		e.path = previousPath
	}
	if e.refs != 0 {
		return
	}
	r.openSet.Remove(e.ino)
	delete(r.entries, e.ino)
}

// SeedRegistered records a hold the authority just confirmed as a side effect
// of another RPC (the fused create+register): refs stays zero — the caller's
// RegisterOpened turns it into a live handle via the retention-hit path.
func (r *openRegistry) SeedRegistered(path string, ino uint64, gen uint64) {
	if ino == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entries[ino]
	if e == nil {
		e = &openRegEntry{ino: ino}
		r.entries[ino] = e
	}
	if e.pending != nil || e.queued {
		// A transition is racing this seed (pathological reuse of the ino);
		// keep the transition's outcome rather than fighting it.
		return
	}
	e.registered = true
	e.gen = gen
	e.confirmedAt = time.Now()
	e.path = path
	e.noRetain = false
	r.openSet.Add(ino)
	if e.refs == 0 {
		r.retainLocked(e)
	}
}

// retainLocked parks a zero-ref registered entry in the retention LRU (or
// queues its unmark when retention is off/over cap).
func (r *openRegistry) retainLocked(e *openRegEntry) {
	if !r.retentionOn() || e.noRetain || !e.registered {
		r.queueUnmarkLocked(e)
		r.kickFlushLocked()
		return
	}
	if e.lru == nil {
		e.lru = r.lru.PushBack(e)
	}
	if e.path != "" {
		r.byPath[e.path] = e.ino
	}
	for r.lru.Len() > r.retentionCap {
		oldest := r.lru.Front().Value.(*openRegEntry)
		r.queueUnmarkLocked(oldest)
	}
	r.kickFlushLocked()
}

// Close drops one open hold on ino. The last close RETAINS the registration
// (renewal keeps it alive; a re-open reuses it RPC-free) unless discard is set
// (the node was an unlinked orphan — no name can ever resolve to it again).
func (r *openRegistry) Close(path string, ino uint64, discard bool) {
	if ino == 0 {
		return
	}
	r.mu.Lock()
	e := r.entries[ino]
	if e == nil {
		r.mu.Unlock()
		return
	}
	if e.refs > 0 {
		e.refs--
	}
	if discard {
		e.noRetain = true
	}
	if e.refs > 0 || e.pending != nil || e.queued {
		// Still open, or a transition owns the entry (its finisher / the
		// flusher re-evaluates).
		r.mu.Unlock()
		return
	}
	if path != "" {
		e.path = path
	}
	r.retainLocked(e)
	r.mu.Unlock()
}

// ReleaseNameChange synchronously clears any ZERO-REF registration covering
// path (or ino, when the caller knows it) before a name mutation by this
// mount whose park-vs-destroy decision reads our holds — remove and
// rename-over. Without this, a retained hold would make the authority park
// this mount's own remove of a recently-closed file, pinning the inode until
// lease GC. Live (refs>0) holds are deliberately left alone: the caller's
// explicit orphan path owns open files. This is the op-ORDER flush window for
// deferred unmarks: the release must be applied before the name mutation is
// issued, and it piggybacks the whole pending queue into the same batch.
func (r *openRegistry) ReleaseNameChange(path string, ino uint64) {
	r.mu.Lock()
	for {
		e := r.entries[ino]
		if e == nil && path != "" {
			if byIno, ok := r.byPath[path]; ok {
				e = r.entries[byIno]
			}
		}
		if e == nil {
			r.mu.Unlock()
			return
		}
		if e.pending != nil {
			ch := e.pending
			r.mu.Unlock()
			<-ch
			r.mu.Lock()
			continue
		}
		if e.refs > 0 {
			r.mu.Unlock()
			return
		}
		if e.queued {
			r.unqueueLocked(e)
			r.openSet.Remove(e.ino) // unqueue re-added it; this release still unmarks
		} else {
			r.detachRetainedLocked(e)
			r.openSet.Remove(e.ino)
		}
		batch := append(r.drainQueueLocked(unmarkFlushBatch-1), e.ino)
		ch := make(chan struct{})
		for _, i := range batch {
			if be := r.entries[i]; be != nil {
				be.pending = ch
			}
		}
		r.mu.Unlock()
		r.sendUnmarks(batch)
		r.mu.Lock()
		r.finishUnmarksLocked(batch, ch)
		r.mu.Unlock()
		return
	}
}

// NotePathMoved re-keys every live or retained entry after a successful
// rename by this mount. Directory renames include descendants, and boundary
// matching prevents a rename of "a" from touching "ab".
func (r *openRegistry) NotePathMoved(oldPath, newPath string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		moved, ok := rekeyPathPrefix(e.path, oldPath, newPath)
		if !ok {
			continue
		}
		if e.lru != nil && e.path != "" && r.byPath[e.path] == e.ino {
			delete(r.byPath, e.path)
		}
		e.path = moved
		if e.lru != nil && moved != "" {
			r.byPath[moved] = e.ino
		}
	}
}

// DropIno invalidates any retained registration for ino (a peer orphaned or
// otherwise detached it): the hold has no future reuse value, and while we
// keep renewing it the parked inode can never be lease-reaped.
func (r *openRegistry) DropIno(ino uint64) {
	r.mu.Lock()
	e := r.entries[ino]
	if e == nil {
		r.mu.Unlock()
		return
	}
	e.noRetain = true
	if e.refs == 0 && e.pending == nil && !e.queued {
		r.queueUnmarkLocked(e)
		r.kickFlushLocked()
	}
	r.mu.Unlock()
}

// DropPath invalidates any retained registration under path (a peer's
// create/remove/rename changed the name's binding; the retained mapping is no
// longer trustworthy — dropping costs at most one future re-mark).
func (r *openRegistry) DropPath(path string) {
	r.mu.Lock()
	ino, ok := r.byPath[path]
	r.mu.Unlock()
	if ok {
		r.DropIno(ino)
	}
}

// DropAllRetained releases every zero-ref retained registration. Called when
// invalidations may have been missed wholesale (stream reconnect / overflow
// FlushAll): retained holds whose names may have silently changed are worth
// at most one re-mark each, so conservatively give them all up.
func (r *openRegistry) DropAllRetained() {
	r.mu.Lock()
	for el := r.lru.Front(); el != nil; {
		e := el.Value.(*openRegEntry)
		el = el.Next()
		r.queueUnmarkLocked(e)
	}
	r.kickFlushLocked()
	r.mu.Unlock()
}

// drainQueueLocked pops up to n inos from the unmark queue (their entries
// keep queued=true until finishUnmarksLocked deletes them; membership in the
// returned batch is exclusive because the queue slice is mu-guarded).
func (r *openRegistry) drainQueueLocked(n int) []uint64 {
	if n <= 0 || len(r.unmarkQueue) == 0 {
		return nil
	}
	if n > len(r.unmarkQueue) {
		n = len(r.unmarkQueue)
	}
	batch := append([]uint64(nil), r.unmarkQueue[:n]...)
	r.unmarkQueue = append(r.unmarkQueue[:0], r.unmarkQueue[n:]...)
	return batch
}

func (r *openRegistry) sendUnmarks(inos []uint64) {
	if len(inos) == 0 {
		return
	}
	_, err := r.reg.UnmarkOpenBatch(inos)
	if err != nil {
		// Best-effort like the previous per-close UnmarkOpen: a hold that
		// never got cleared is pruned by the authority's open-lease expiry.
		r.debug("UnmarkOpen batch (%d inos): %v", len(inos), err)
	}
}

func (r *openRegistry) finishUnmarksLocked(inos []uint64, ch chan struct{}) {
	for _, ino := range inos {
		e := r.entries[ino]
		if e == nil {
			continue
		}
		e.pending = nil
		e.queued = false
		e.registered = false
		e.gen = 0
		if e.refs == 0 {
			delete(r.entries, ino)
		}
	}
	close(ch)
}

func (r *openRegistry) flushUnmarks() {
	for {
		r.mu.Lock()
		batch := r.drainQueueLocked(unmarkFlushBatch)
		if len(batch) == 0 {
			r.flushing = false
			r.mu.Unlock()
			return
		}
		ch := make(chan struct{})
		for _, ino := range batch {
			if e := r.entries[ino]; e != nil {
				e.pending = ch
			}
		}
		r.mu.Unlock()
		r.sendUnmarks(batch)
		r.mu.Lock()
		r.finishUnmarksLocked(batch, ch)
		r.mu.Unlock()
	}
}

// ConfirmRenewal records a successful RenewOpenInodes round for inos under
// gen. Renewal re-creates absent holds server-side, so it re-validates entries
// that predate an authority restart without any per-open probing.
func (r *openRegistry) ConfirmRenewal(inos []uint64, gen uint64) {
	now := time.Now()
	r.mu.Lock()
	for _, ino := range inos {
		e := r.entries[ino]
		if e == nil || e.queued || e.pending != nil {
			continue // a release decision owns this entry; don't resurrect it
		}
		e.registered = true
		e.gen = gen
		e.confirmedAt = now
	}
	r.mu.Unlock()
}

// Shutdown flushes every queued and retained unmark, bounded: a dead
// authority must not stall teardown (its lease sweeper clears our holds).
func (r *openRegistry) Shutdown(timeout time.Duration) {
	r.DropAllRetained()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.flushUnmarks()
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}
