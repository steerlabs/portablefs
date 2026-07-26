package session

import (
	"context"
	"errors"
	"hash/fnv"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/metrics"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// mgrMetrics are the write-back observability instruments (all atomic, no hot-path locks).
type mgrMetrics struct {
	sessions     *metrics.Gauge     // active write-back sessions (held checkouts)
	pendingRecs  *metrics.Gauge     // un-flushed records (the box-loss / durability window)
	pendingBytes *metrics.Gauge     // un-flushed bytes
	flushes      *metrics.Counter   // flush batches sent to the authority
	flushRecs    *metrics.Counter   // records flushed (write-back throughput)
	flushErrs    *metrics.Counter   // flush failures
	flushLat     *metrics.Histogram // per-batch flush latency (authority round-trip)
	handoffs     *metrics.Counter   // idle-releases (subtree handed to another mount)
	acquires     *metrics.Counter   // checkouts acquired (new sessions)
	acquireBusy  *metrics.Counter   // checkout EBUSY waits (cross-mount contention)
	recovered    *metrics.Counter   // crash-recovered sessions (re-flushed un-flushed tails)
}

func newMgrMetrics(r *metrics.Registry) *mgrMetrics {
	return &mgrMetrics{
		sessions:     r.Gauge("writeback_sessions"),
		pendingRecs:  r.Gauge("writeback_pending_records"),
		pendingBytes: r.Gauge("writeback_pending_bytes"),
		flushes:      r.Counter("writeback_flush_total"),
		flushRecs:    r.Counter("writeback_flush_records_total"),
		flushErrs:    r.Counter("writeback_flush_errors_total"),
		flushLat:     r.Histogram("writeback_flush_seconds"),
		handoffs:     r.Counter("writeback_idle_release_total"),
		acquires:     r.Counter("writeback_acquire_total"),
		acquireBusy:  r.Counter("writeback_acquire_busy_total"),
		recovered:    r.Counter("writeback_recovered_total"),
	}
}

// acquireBackoff is how long a contending writer waits between checkout retries while the
// holder finishes + idle-releases (the handoff). acquireGrace is added to the idle window to
// bound how long a write blocks waiting for a handoff before failing with EAGAIN.
const (
	acquireBackoff = 100 * time.Millisecond
	acquireGrace   = 3 * time.Second
)

// recallGrace defers a recall while the subtree was active within this window — covering the gaps
// BETWEEN a workflow's file opens (e.g. between `mkdir dir` and the app opening a file in it) where
// no handle is momentarily held but the holder is plainly still mid-workflow. A recall there would
// pull the checkout out from under it. Sized to absorb scheduler/IO stalls between ops (a build that
// briefly stalls is not "done"), yet well under a realistic hand-off settle so the legitimate
// hand-off — the holder finished and went quiet — is never delayed.
const recallGrace = 2 * time.Second

// Manager owns a mount's write-back sessions: one per checked-out subtree. It resolves
// which session (if any) covers a path, auto-checks-out the governing subtree (a file's
// parent directory — so SQLite's -wal/-journal/-shm siblings are co-owned) on first write,
// and drives periodic background flushes.
type Manager struct {
	auth          Authority
	owner         string        // this mount's stable checkout-owner id
	walDir        string        // directory for per-session durable flush logs
	idle          time.Duration // release a checkout after this long idle (0 = never; no handoff)
	mu            sync.Mutex
	byRoot        map[string]*Session
	stop          chan struct{}
	stopped       bool
	runWG         sync.WaitGroup               // the periodic flush/sweep goroutine; Stop waits on it before closing
	onRelease     func(root string)            // notified when a subtree is idle-released (mount drops its stale cache)
	onAcquire     func(root string)            // notified when a NEW session is created for a subtree (re-acquire: evict stale cache)
	busyCheck     func(root string) bool       // reports a subtree with files still open: the sweeper must NOT release it mid-workflow
	onFlushHealth func(root string, err error) // per-root flush outcome: non-nil err flips the mount degraded, nil clears it
	reg           *metrics.Registry
	mx            *mgrMetrics // write-back instruments (always non-nil)
	// releasing[root] is closed when an in-flight idle-release of that subtree finishes (its
	// flush + checkin + WAL close/remove are done). A would-be re-acquirer of the SAME root WAITS
	// on it — otherwise New() would open a SECOND handle on the same per-session WAL file (same
	// owner+root ⇒ same walPath) while release() is still flushing/removing it: data corruption,
	// and a stale-vs-fresh generation racing on one watermark. The release-before-acquire barrier.
	releasing map[string]chan struct{}
	// pendingRecall[root] is set when a recall arrived for a subtree that still had OPEN FILES: a
	// recall must hand off a CONSISTENT state, so we cannot flush mid-workflow (a torn SQLite
	// transaction). The deferred recall completes from the periodic pass once the files close.
	pendingRecall map[string]bool
	flushLimits   FlushLimits // per-batch flush bounds applied to each new session (zero = defaults)
	// fileGrainRoot: on a managed authority (which refuses a volume-root "" checkout), a
	// top-level file checks out ITSELF instead of "". Set from cli.ServerManaged() at wiring.
	fileGrainRoot bool
}

// NewManager builds a session manager. owner is the mount's checkout-owner id (also sent on
// the subscribe stream so the authority releases sessions if the mount dies). walDir holds
// per-session flush logs on local disk. idle is the idle-release window for multi-mount
// handoff (0 disables release — a subtree stays exclusively held for the mount's lifetime).
func NewManager(auth Authority, owner, walDir string, idle time.Duration) *Manager {
	reg := metrics.NewRegistry()
	// Seed + persist the session-generation floor in the WAL dir so generations stay monotonic
	// across a restart even if the wall clock steps backward (otherwise a regressed epoch strands
	// a live owner's writes behind a permanent ESTALE). Harmless for an ephemeral walDir.
	if walDir != "" {
		ConfigureEpochFloor(filepath.Join(walDir, ".epoch"))
	}
	return &Manager{
		auth:          auth,
		owner:         owner,
		walDir:        walDir,
		idle:          idle,
		byRoot:        map[string]*Session{},
		releasing:     map[string]chan struct{}{},
		pendingRecall: map[string]bool{},
		stop:          make(chan struct{}),
		reg:           reg,
		mx:            newMgrMetrics(reg),
	}
}

// SetBusyCheck registers a predicate the idle-sweeper consults before releasing a subtree: if it
// reports the subtree still has open file handles, the release is deferred. This keeps handoff on
// clean boundaries (no release while an app — e.g. SQLite — holds a file open mid-transaction).
// Call once at startup.
func (m *Manager) SetBusyCheck(fn func(root string) bool) { m.busyCheck = fn }

// SetFileGrainRootCheckouts makes top-level files check out themselves rather than the volume
// root "". A managed (journal-native) authority refuses a root checkout (managed_coordination
// rejects an empty CheckoutPath), so write-back of a top-level file requires file-grain root
// grants. Set from cli.ServerManaged() at startup.
func (m *Manager) SetFileGrainRootCheckouts(on bool) { m.fileGrainRoot = on }

// governing maps a write path to its checkout root: the parent directory, except that a
// top-level file governs itself when file-grain root checkouts are enabled (managed authority),
// since managed refuses the volume-root "" checkout.
func (m *Manager) governing(p string) string {
	root := governingSubtree(p)
	if root == "" && m.fileGrainRoot && p != "" {
		return p
	}
	return root
}

// SetFlushLimits applies per-batch flush bounds to every session created from now on.
// Zero values keep the defaults (512 records, unbounded bytes). Call once at startup.
func (m *Manager) SetFlushLimits(l FlushLimits) {
	m.mu.Lock()
	m.flushLimits = l
	m.mu.Unlock()
}

// SetOnRelease registers a callback invoked (with the subtree root) each time a subtree is
// cleanly idle-released, so the mount can drop the now-stale kernel cache / self-write markers
// for that subtree before another mount writes it. Call once at startup.
func (m *Manager) SetOnRelease(fn func(root string)) { m.onRelease = fn }

// SetOnAcquire registers a callback invoked (with the subtree root) each time a NEW session is
// created for a subtree — i.e. a (re)acquire — so the mount can evict the now-possibly-stale
// kernel cache for that subtree before the first read. Call once at startup.
func (m *Manager) SetOnAcquire(fn func(root string)) { m.onAcquire = fn }

// SetOnFlushHealth registers a callback invoked after each session flush with that subtree's
// root and the flush error (nil on success). A persistent flush failure surfaces as a degraded
// mount instead of only a log line, so acked-but-unflushable write-back never fails silently.
// Call once at startup.
func (m *Manager) SetOnFlushHealth(fn func(root string, err error)) { m.onFlushHealth = fn }

// AttachMetrics points the manager's write-back instruments at a shared registry (so one HTTP
// endpoint can expose write-back + client + node metrics together). Call once at startup.
func (m *Manager) AttachMetrics(reg *metrics.Registry) {
	m.reg = reg
	m.mx = newMgrMetrics(reg)
}

// Metrics refreshes the point-in-time gauges (active sessions, un-flushed backlog) and returns
// the registry for serving.
func (m *Manager) Metrics() *metrics.Registry {
	m.updateGauges()
	return m.reg
}

// updateGauges recomputes the snapshot gauges from current session state (so they're correct at
// scrape time without per-op gauge churn on the hot path).
func (m *Manager) updateGauges() {
	m.mu.Lock()
	n := len(m.byRoot)
	var recs int64
	var bytes int64
	for _, s := range m.byRoot {
		r, b := s.PendingStats()
		recs += int64(r)
		bytes += b
	}
	m.mu.Unlock()
	m.mx.sessions.Set(int64(n))
	m.mx.pendingRecs.Set(recs)
	m.mx.pendingBytes.Set(bytes)
}

// For returns the session covering path (its checkout root equals path or is an ancestor),
// or nil if the path is not under any active write-back session.
func (m *Manager) For(path string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.coveringLocked(path)
}

// AwaitRelease blocks until no in-flight idle-release covers path. A read that resolves to NO
// session (For returned nil) must call this before reading through to the authority: the sweeper
// removes a session from byRoot BEFORE its release() flush lands on the authority, so a read in
// that window would otherwise see a stale, pre-flush state (e.g. SQLite's db without its latest
// pages → "no such table"). Bounded so a wedged release can never hang reads indefinitely.
func (m *Manager) AwaitRelease(path string) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		var ch chan struct{}
		for root, done := range m.releasing {
			if root == "" || path == root || strings.HasPrefix(path, root+"/") {
				ch = done
				break
			}
		}
		m.mu.Unlock()
		if ch == nil || !time.Now().Before(deadline) {
			return
		}
		select {
		case <-ch:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (m *Manager) coveringLocked(p string) *Session {
	for root, s := range m.byRoot {
		// root == "" is a checkout at the VOLUME ROOT: it covers every path (root-relative paths
		// have no leading "/", so the prefix test below would otherwise never match it). This
		// mirrors delegation.covers, and without it For() never resolves a root-level file to its
		// session — the write goes to the overlay but the read can't see it (vanished file).
		if root == "" || p == root || strings.HasPrefix(p, root+"/") {
			if s.isReleased() {
				delete(m.byRoot, root) // dead (idle-released) session — drop it, treat as uncovered
				return nil             // checkouts don't overlap, so no other session covers p
			}
			return s
		}
	}
	return nil
}

// Ensure returns a session covering path, auto-checking-out path's governing subtree (its
// parent directory) if none exists yet. On a checkout conflict (another mount holds it) it
// RETRIES with backoff until the holder idle-releases (the handoff) or a bounded grace
// elapses, then returns the *BusyError so the caller fails the op with EAGAIN.
func (m *Manager) Ensure(path string) (*Session, error) {
	return m.EnsureContext(context.Background(), path)
}

// EnsureContext is Ensure that respects the caller's context: if the FUSE op is cancelled
// while waiting out a handoff, it returns the BusyError instead of blocking further (the
// caller maps it to EAGAIN). This bounds how long a FUSE handler can block on contention.
func (m *Manager) EnsureContext(ctx context.Context, path string) (*Session, error) {
	return m.ensureRoot(ctx, m.governing(path))
}

// ensureRoot acquires (or returns the existing) session for an EXACT checkout root. EnsureContext
// derives the root from a write path; crash recovery passes the crashed session's true root.
func (m *Manager) ensureRoot(ctx context.Context, root string) (*Session, error) {
	deadline := time.Now().Add(m.idle + acquireGrace)
	for {
		m.mu.Lock()
		if s := m.coveringLocked(root); s != nil {
			m.mu.Unlock()
			return s, nil
		}
		// Release-before-acquire barrier: if this root is mid-release, WAIT for it to finish
		// before New() — else we'd open a second handle on the same WAL file while release() is
		// flushing/removing it (corruption + a stale/fresh generation racing on one watermark).
		if done, ok := m.releasing[root]; ok {
			m.mu.Unlock()
			if !time.Now().Before(deadline) {
				return nil, &BusyError{Path: root}
			}
			select {
			case <-ctx.Done():
				return nil, &BusyError{Path: root} // FUSE op cancelled — caller retries (EAGAIN)
			case <-done:
			case <-time.After(acquireBackoff):
			}
			continue
		}
		id := m.owner + "-" + hashHex(root)
		s, err := New(m.auth, m.owner, id, root, m.walPath(id))
		if err == nil {
			s.mx = m.mx // share the mount's write-back instruments
			s.limits = m.flushLimits
			m.byRoot[root] = s
			m.mu.Unlock()
			m.mx.acquires.Inc()
			if m.onAcquire != nil {
				// Fresh checkout of this subtree: evict whatever stale view our kernel cache still
				// holds (another mount may have rewritten it while we didn't hold it), so the first
				// read after acquire — e.g. SQLite probing for a hot -journal — sees the CURRENT
				// state, not a stale page it would then roll back over.
				m.onAcquire(root)
			}
			return s, nil
		}
		m.mu.Unlock()
		var busy *BusyError
		if !errors.As(err, &busy) || !time.Now().Before(deadline) {
			return nil, err // a real error, or we waited out the handoff grace → give up
		}
		m.mx.acquireBusy.Inc() // cross-mount contention: the holder hasn't released yet
		select {
		case <-ctx.Done():
			return nil, err // FUSE op cancelled — stop waiting for the handoff
		case <-time.After(acquireBackoff):
		}
	}
}

// sweepIdle releases every session that has been idle (no mutation, fully flushed) for the
// configured window, handing its subtree back so another mount can acquire it. Flush-before-
// checkin happens inside release(). A session is removed from byRoot under m.mu BEFORE the
// (network) release so resolution never returns a session mid-handoff.
func (m *Manager) sweepIdle() {
	if m.idle <= 0 {
		return
	}
	type relJob struct {
		s    *Session
		done chan struct{}
	}
	m.mu.Lock()
	var jobs []relJob
	for root, s := range m.byRoot {
		// Defer release of a subtree that still has open files: handing it off mid-workflow would
		// flush + check in a transient state (an in-flight SQLite journal, a half-written page).
		if m.busyCheck != nil && m.busyCheck(root) {
			continue
		}
		if s.Idle(m.idle) && !s.isSuperseded() {
			delete(m.byRoot, root)
			done := make(chan struct{})
			m.releasing[root] = done // arm the barrier: re-acquirers of this root now wait
			jobs = append(jobs, relJob{s, done})
		}
	}
	m.mu.Unlock()
	for _, jb := range jobs {
		m.finishRelease(jb.s, jb.done)
	}
}

// finishRelease performs a session's flush + checkin (release()), updates the barrier + metrics,
// and notifies onRelease so the mount drops its now-stale caches/self-write markers for the subtree
// (otherwise a phantom -journal could survive the handoff and SQLite would roll back). On flush
// failure it restores the session so a later attempt retries — checking in an un-flushed session
// would hand its un-flushed tail to the next holder (silent loss). The caller must have removed the
// session from byRoot and armed m.releasing[root]=done under m.mu before calling.
func (m *Manager) finishRelease(s *Session, done chan struct{}) {
	err := s.release()
	m.mu.Lock()
	delete(m.releasing, s.root)
	if err != nil {
		log.Printf("write-back: release failed for %q (will retry): %v", s.root, err)
		if _, exists := m.byRoot[s.root]; !exists {
			m.byRoot[s.root] = s
		}
	} else {
		m.mx.handoffs.Inc()
		if m.onRelease != nil {
			m.onRelease(s.root)
		}
	}
	close(done) // release the barrier: flush + checkin + WAL removal are done
	m.mu.Unlock()
}

// ReleaseSubtree force-releases the session covering path NOW (flush + check in), in response to a
// RECALL — another client is contending for the subtree. Unlike sweepIdle it ignores the idle timer
// AND the busy gate: the recall is authoritative, and a holder that is idle when contended (the
// common, sequential handoff) flushes a clean, complete state. A no-op if this mount holds no
// session covering path (the recall was for some other holder, or it was already released).
func (m *Manager) ReleaseSubtree(path string) {
	m.mu.Lock()
	s := m.coveringLocked(path)
	if s == nil {
		m.mu.Unlock()
		return
	}
	root := s.root
	// A recall must hand off a CONSISTENT state. If the subtree still has open files OR was active
	// within recallGrace, the holder is mid-workflow (e.g. SQLite mid-transaction with its db +
	// journal open, or between a `mkdir` and the first open in it): flushing + checking in NOW would
	// ship a torn state, and pulling the checkout out from under the running process corrupts it.
	// DEFER — record the recall and complete it from the periodic pass once the subtree goes quiet.
	// The contender's bounded AwaitFree covers the wait (or force-revokes a truly stuck holder).
	if (m.busyCheck != nil && m.busyCheck(root)) || !s.Idle(recallGrace) {
		m.pendingRecall[root] = true
		m.mu.Unlock()
		return
	}
	if _, busy := m.releasing[root]; busy {
		m.mu.Unlock()
		return // a release of this root is already in flight
	}
	delete(m.byRoot, root)
	delete(m.pendingRecall, root)
	done := make(chan struct{})
	m.releasing[root] = done
	m.mu.Unlock()
	m.finishRelease(s, done)
}

// processPendingRecalls completes any recall that was deferred because the subtree had open files,
// now that they have closed. Called from the periodic pass so a recall that arrived mid-workflow
// hands off the moment the workflow finishes (rather than waiting out the contender's timeout).
func (m *Manager) processPendingRecalls() {
	m.mu.Lock()
	type job struct {
		s    *Session
		done chan struct{}
	}
	var jobs []job
	for root := range m.pendingRecall {
		s := m.byRoot[root]
		if s == nil {
			delete(m.pendingRecall, root) // already released/gone
			continue
		}
		if (m.busyCheck != nil && m.busyCheck(root)) || !s.Idle(recallGrace) {
			continue // still in use or recently active — keep deferring
		}
		if _, busy := m.releasing[root]; busy {
			continue
		}
		delete(m.byRoot, root)
		delete(m.pendingRecall, root)
		done := make(chan struct{})
		m.releasing[root] = done
		jobs = append(jobs, job{s, done})
	}
	m.mu.Unlock()
	for _, jb := range jobs {
		m.finishRelease(jb.s, jb.done)
	}
}

// governingSubtree is the checkout root for a path: its parent directory (root files are
// governed at the volume root, ""). Parent-dir granularity co-owns sibling files (SQLite's
// db + db-wal + db-shm + db-journal land under one checkout).
func governingSubtree(p string) string {
	dir := path.Dir(p)
	if dir == "." || dir == "/" {
		return ""
	}
	return dir
}

func (m *Manager) walPath(id string) string {
	return path.Join(m.walDir, "sess-"+id+".wal")
}

// RecoverAll re-flushes the un-flushed tail of every persistent session WAL left behind by a
// crash. A graceful unmount drains + closes (and the OS later reuses) its WALs; any WAL that
// still holds un-flushed records on startup is crash debris. The subtree is read from the WAL's
// first record (we can't reverse the hashed id), and re-acquiring it runs the per-session
// recovery (Replay → re-number → re-flush under a fresh epoch). Best-effort + bounded by the
// acquire grace: a subtree another live mount now holds is skipped (it recovers lazily on next
// use). No-op for the ephemeral default (a fresh temp walDir has no leftover WALs). Call once at
// startup, BEFORE Start.
func (m *Manager) RecoverAll() {
	files, _ := filepath.Glob(filepath.Join(m.walDir, "sess-*.wal"))
	for _, f := range files {
		candidate, ok := m.recoverRoot(f)
		if !ok {
			continue // empty/clean/unrecognizable WAL — nothing to recover
		}
		ctx, cancel := context.WithTimeout(context.Background(), m.idle+acquireGrace)
		s, err := m.ensureRoot(ctx, candidate.root)
		cancel()
		if err != nil {
			log.Printf("write-back: startup recovery for %q failed: records=%d payloadBytes=%d walBytes=%d wal=%s err=%v (WAL preserved)",
				candidate.root, candidate.records, candidate.payloadBytes, candidate.walBytes, candidate.path, err)
			continue
		}
		m.mx.recovered.Inc()
		result := s.RecoveryResult()
		if result.Records > 0 {
			log.Printf("write-back: recovered un-flushed writes for subtree %q: records=%d payloadBytes=%d appliedThrough=%d flushed=%t wal=%s",
				s.root, result.Records, result.PayloadBytes, result.AppliedThrough, result.Flushed, result.WALPath)
		} else {
			log.Printf("write-back: startup recovery for subtree %q found no remaining records in %s", s.root, candidate.path)
		}
	}
}

type recoveryCandidate struct {
	path         string
	root         string
	records      int
	payloadBytes int64
	walBytes     int64
}

// recoverRoot determines the TRUE checkout root of a crash-leftover session WAL. The filename
// encodes id = owner-hashHex(root) but the hash isn't reversible, and the first SURVIVING record
// may not sit directly under the root (the original first write was compacted away, or an op
// targets the root dir / a deeper path). So we replay the WAL and find the ancestor of some
// record path whose hashHex matches the filename — the only root that resolves to THIS WAL file.
func (m *Manager) recoverRoot(walPath string) (recoveryCandidate, bool) {
	candidate := recoveryCandidate{path: walPath}
	if info, err := os.Stat(walPath); err == nil {
		candidate.walBytes = info.Size()
	}
	w, err := wal.Open(walPath)
	if err != nil {
		return recoveryCandidate{}, false
	}
	recs, rerr := w.Replay()
	_ = w.Close()
	// rerr != nil still yields the valid prefix in recs (mid-log corruption salvage); use it to
	// locate the root so proactive recovery re-flushes the survivors instead of skipping them.
	_ = rerr
	if len(recs) == 0 {
		return recoveryCandidate{}, false
	}
	candidate.records = len(recs)
	candidate.payloadBytes = recoveryPayloadBytes(recs)
	base := filepath.Base(walPath)
	id := strings.TrimSuffix(strings.TrimPrefix(base, "sess-"), ".wal") // owner-hashHex(root)
	seen := map[string]struct{}{}
	for _, r := range recs {
		for _, p := range []string{r.Path, r.NewPath} {
			if p == "" {
				continue
			}
			for cand := clean(p); ; cand = parentDir(cand) {
				if _, dup := seen[cand]; !dup {
					seen[cand] = struct{}{}
					if m.owner+"-"+hashHex(cand) == id {
						candidate.root = cand
						return candidate, true
					}
				}
				if cand == "" {
					break
				}
			}
		}
	}
	return recoveryCandidate{}, false
}

// parentDir returns the parent of a volume-relative path ("" is the root, its own parent).
func parentDir(p string) string {
	d := path.Dir(p)
	if d == "." || d == "/" {
		return ""
	}
	return d
}

func clean(p string) string { return strings.Trim(path.Clean("/"+p), "/") }

// Roots snapshots the subtree roots with an active write-back session, sorted
// for determinism. The post-failover reclaim hook re-asserts each root's
// checkout on the promoted authority.
func (m *Manager) Roots() []string {
	m.mu.Lock()
	out := make([]string, 0, len(m.byRoot))
	for r := range m.byRoot {
		out = append(out, r)
	}
	m.mu.Unlock()
	sort.Strings(out)
	return out
}

// FlushAll flushes every active session CONCURRENTLY, so a large backlog in one session
// (e.g. a busy SQLite DB) cannot block another session's small, latency-sensitive flush.
// Per-session failures are logged (the flusher otherwise swallows them) and the first is
// returned; the pending set persists so the next tick retries.
func (m *Manager) FlushAll() error {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.byRoot))
	roots := make([]string, 0, len(m.byRoot))
	for r, s := range m.byRoot {
		sessions = append(sessions, s)
		roots = append(roots, r)
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	for i := range sessions {
		wg.Add(1)
		go func(s *Session, root string) {
			defer wg.Done()
			err := s.Flush()
			if m.onFlushHealth != nil {
				m.onFlushHealth(root, err) // surface/clear degraded even when the flusher would otherwise swallow it
			}
			if err != nil {
				log.Printf("write-back: flush failed for %q: %v", root, err)
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
			}
		}(sessions[i], roots[i])
	}
	wg.Wait()
	return firstErr
}

// Start runs background flushes every interval until Stop. The cache is warm under 5 min,
// so a sub-second cadence keeps the box-loss window tiny without much overhead.
func (m *Manager) Start(interval time.Duration) {
	m.runWG.Add(1)
	go func() {
		defer m.runWG.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-t.C:
				_ = m.FlushAll()          // drain pending first...
				m.processPendingRecalls() // ...complete recalls deferred while files were open...
				m.sweepIdle()             // ...then release fully-flushed idle subtrees (legacy timer handoff)
			}
		}
	}()
}

// Stop ends the background flusher, does a final FlushAll, and checks in every session.
func (m *Manager) Stop() error {
	m.mu.Lock()
	if !m.stopped {
		m.stopped = true
		close(m.stop)
	}
	m.mu.Unlock()
	// Wait for the periodic flush/sweep goroutine to finish any IN-FLIGHT tick before we close
	// sessions. Otherwise its sweepIdle could be releasing a subtree (flush + checkin + WAL
	// close/remove) for the very session we're about to Close — a double WAL close and a
	// concurrent flush on shutdown. With the goroutine quiesced, the closes below are exclusive.
	m.runWG.Wait()
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.byRoot))
	for _, s := range m.byRoot {
		sessions = append(sessions, s)
	}
	m.byRoot = map[string]*Session{}
	m.mu.Unlock()
	var firstErr error
	for _, s := range sessions {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func hashHex(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return strconv.FormatUint(h.Sum64(), 16)
}
