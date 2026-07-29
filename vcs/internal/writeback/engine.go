// Package writeback is the mount-level write-back engine: one engine per
// mounted (volume, branch) owning one dense mutation stream, one segmented
// WAL, one sparse overlay, one flusher, and a set of authority-issued
// delegations. Write mode is not a mount property: every mutation is either
// executed synchronously by the authority or acknowledged locally under a
// currently valid delegation, and the authority makes the grant decision.
package writeback

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// acquireDenialBackoff is how long the client runs write-through on a scope
// after the authority declined to delegate it (or a recall evicted it). A var
// so acceptance tests can compress it; production never changes it.
var acquireDenialBackoff = 5 * time.Second

// SetDenialBackoffForTest compresses the client-side acquire-denial backoff
// so lifecycle tests exercise contention degrade + re-grant deterministically
// without multi-second waits. Test-only; never called in production.
func SetDenialBackoffForTest(d time.Duration) { acquireDenialBackoff = d }

const (
	// idleReleaseAfter is the voluntary-release window: a clean delegation
	// with no local mutation for this long (and no open handles under it)
	// releases so the authority's checkout table stays small.
	idleReleaseAfter = time.Second

	// defaultBudgetBytes bounds the stream WAL on disk when the caller does
	// not derive one from its cache capacity.
	defaultBudgetBytes = 512 << 20
)

// Hard overlay bounds (no spill): a mutation that would grow a directory
// view or a file's extent set past these drains, releases the covering
// delegation, and runs write-through instead — overlay memory is bounded by
// construction, never by a second persistence system. Vars so bound tests
// stay fast; production never changes them.
var (
	maxDirViewChildren = 16384
	maxFileExtents     = 8192
)

// ErrNoSpace reports WAL budget exhaustion that folding and reclaiming could
// not relieve: the mutation is refused before any WAL append.
var ErrNoSpace = errors.New("writeback: stream WAL budget exhausted")

// ErrNoXattr is the engine's deterministic ENODATA outcome.
var ErrNoXattr = errors.New("writeback: extended attribute does not exist")

// ErrFailedClosed marks a terminal engine verdict. Once latched, the mount
// refuses every later mutation until it is remounted; it never changes the
// operation to the authority lane because local state became unavailable.
var ErrFailedClosed = errors.New("writeback: engine failed closed; remount required")

// Events are the engine-to-frontend hooks.
type Events struct {
	// OnGrant fires after a delegation installs: the caller evicts shared
	// attr/negative/directory/kernel state under the scope.
	OnGrant func(scope string)
	// OnRelease fires after a delegation fully releases (drained): the
	// caller drops overlay-derived cache entries and invalidates the kernel
	// scope before shared-mode requests resume.
	OnRelease func(scope string)
	// OnHealth reports the sticky flusher health verdict (nil clears).
	OnHealth func(err error)
}

// Config configures one engine.
type Config struct {
	// StateDir is the per-(volume,branch) store directory. The engine owns
	// it exclusively (flock) for its lifetime.
	StateDir string
	VolumeID string
	Branch   string

	Remote Remote
	Events Events

	// Busy reports open handles under a path (defers voluntary release).
	Busy func(scope string) bool

	// EnsureOpenPins establishes authority-durable open pins for every open
	// handle under scope BEFORE the delegation releases, preserving
	// open-after-unlink across the release boundary (a peer unlink then
	// parks the inode instead of destroying it). nil skips (tests without
	// open tracking).
	EnsureOpenPins func(ctx context.Context, scope string) error

	// BudgetBytes bounds the stream WAL on disk (0 = 512 MiB).
	BudgetBytes int64

	// DisableDelegation forces write-through for every operation
	// (PORTABLEFS_DEBUG_WRITE_THROUGH=1). The engine still recovers parked
	// streams.
	DisableDelegation bool

	// DisableDelegatedXattrs keeps xattr mutations on the authority lane
	// when the negotiated authority does not advertise that optional flush
	// record class. The decision is fixed before the first mutation.
	DisableDelegatedXattrs bool

	Logf func(string, ...any)
}

// delegation is one authority-issued grant held by this engine.
type delegation struct {
	scope      string
	epoch      string
	grantedAt  time.Time
	lastActive time.Time
	draining   bool
	// done is closed whenever the current drain+release attempt reaches a
	// definite outcome. A failed attempt leaves drainErr set and the
	// delegation held: admissions wake, re-evaluate, and fail instead of
	// escaping into write-through while the authority still owns the grant.
	done     chan struct{}
	drainErr error
	// relMu serializes the drain+release so exactly one caller executes it
	// (recall, idle release, and release-before-write-through can race).
	relMu sync.Mutex
}

type engineFailure struct {
	err error
}

// Engine is the mount write-back engine.
type Engine struct {
	cfg         Config
	remote      Remote
	writebackID string
	mountID     [16]byte
	epoch       uint64

	// ctx is the engine lifetime: canceled on force-close/abandon so
	// in-flight remote calls resolve promptly and background goroutines
	// terminate before the WAL closes.
	ctx       context.Context
	cancelCtx context.CancelFunc

	lock *os.File // store-dir flock

	mu         sync.RWMutex
	closed     bool
	frozen     bool // no further delegated admissions (unmount/force-close)
	streamOpen bool
	// streamDead is the flusher's terminal verdict (fence/conflict/corrupt).
	// It also latches failure, sealing the whole mount mutation gate until
	// remount so no operation changes lanes around parked history.
	streamDead  error
	delegations map[string]*delegation
	dirs        map[string]*dirView
	files       map[string]*fileView
	xattrs      map[string]*xattrView
	denials     map[string]time.Time

	// held mirrors len(delegations) so the shared-path read surfaces
	// (lookup/readdir/readlink of a mount holding NO delegations — the
	// steady state of read-heavy workloads) skip the lock + ancestor walk
	// with one atomic load.
	held atomic.Int64

	acquireMu sync.Mutex
	acquiring map[string]*acquireFlight

	// failure is the mount-lifetime terminal verdict. Atomic reads keep the
	// mutation fast path lock-free while the first failure wins permanently.
	failure atomic.Pointer[engineFailure]

	wal *streamWAL
	fl  *flusher
	job *jobState

	// createWAL is fixed to createStreamWAL in production and replaceable by
	// package tests for deterministic initialization-failure coverage.
	createWAL func(string, [16]byte, string, string, uint64) (*streamWAL, error)

	recovery *recoveryRunner
	idleStop chan struct{}
	idleOnce sync.Once
}

func (e *Engine) stopIdle() {
	e.idleOnce.Do(func() {
		if e.idleStop != nil {
			close(e.idleStop)
		}
	})
}

func (e *Engine) logf(format string, args ...any) {
	if e.cfg.Logf != nil {
		e.cfg.Logf(format, args...)
	}
}

// Open initializes the engine: locks the store, reconciles every parked
// stream for this (volume, branch), and prepares (lazily) a fresh stream.
func Open(ctx context.Context, cfg Config) (*Engine, error) {
	if cfg.StateDir == "" || cfg.VolumeID == "" || cfg.Remote == nil {
		return nil, errors.New("writeback: StateDir, VolumeID, and Remote are required")
	}
	if cfg.BudgetBytes <= 0 {
		cfg.BudgetBytes = defaultBudgetBytes
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	lock, err := lockStoreDir(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	mountID, err := ensureMountID(cfg.StateDir)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	e := &Engine{
		cfg: cfg, remote: cfg.Remote, mountID: mountID, lock: lock,
		delegations: map[string]*delegation{},
		dirs:        map[string]*dirView{},
		files:       map[string]*fileView{},
		xattrs:      map[string]*xattrView{},
		denials:     map[string]time.Time{},
		acquiring:   map[string]*acquireFlight{},
		createWAL:   createStreamWAL,
	}
	e.ctx, e.cancelCtx = context.WithCancel(context.Background())
	e.fl = newFlusher(e)
	e.recovery = newRecoveryRunner(e)
	maxEpoch := e.recovery.discover()
	e.epoch = maxEpoch + 1
	e.writebackID = streamID(mountID, e.epoch)
	// Attach-readiness gate: every prior parked stream must drain — or park
	// in an explicit terminal conflict/corrupt state — BEFORE the mount
	// serves. A transient failure fails the attach; there is no
	// live-serve-while-recovering.
	if err := e.recovery.reconcileAll(ctx); err != nil {
		e.cancelCtx()
		_ = lock.Close()
		return nil, err
	}
	e.fl.start()
	e.idleStop = make(chan struct{})
	go e.idleLoop()
	return e, nil
}

// idleLoop voluntarily releases clean, idle delegations so the authority's
// checkout table stays bounded (peers can then acquire without a recall).
func (e *Engine) idleLoop() {
	t := time.NewTicker(idleReleaseAfter / 2)
	defer t.Stop()
	for {
		select {
		case <-e.idleStop:
			return
		case <-t.C:
			e.mu.RLock()
			closed := e.closed
			e.mu.RUnlock()
			if closed {
				return
			}
			e.releaseIdle()
		}
	}
}

func streamID(mountID [16]byte, epoch uint64) string {
	return fmt.Sprintf("wb%sx%016x", hex.EncodeToString(mountID[:]), epoch)
}

func newPublicJobID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return "job" + hex.EncodeToString(id[:]), nil
}

func lockStoreDir(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "engine.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("writeback: store %s is owned by another engine: %w", dir, err)
	}
	return f, nil
}

func ensureMountID(dir string) ([16]byte, error) {
	var id [16]byte
	path := filepath.Join(dir, "mount-id")
	b, err := os.ReadFile(path)
	if err == nil {
		raw, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(raw) != len(id) {
			return id, fmt.Errorf("%w: malformed mount identity %s", ErrCorrupt, path)
		}
		copy(id[:], raw)
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return id, fmt.Errorf("writeback: read mount identity: %w", err)
	}
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	if err := writeFileAtomicDurable(path, []byte(hex.EncodeToString(id[:])+"\n"), 0o600); err != nil {
		return id, err
	}
	return id, nil
}

// ensureStreamLocked lazily creates the live stream WAL and its recovery-job
// registry — both must be durable before the first delegated acknowledgment.
func (e *Engine) ensureStreamLocked() error {
	if err := e.MutationError(); err != nil {
		return err
	}
	if e.streamOpen {
		return nil
	}
	jobID, err := newPublicJobID()
	if err != nil {
		return e.failClosed(fmt.Errorf("initialize recovery identity: %w", err))
	}
	dir := filepath.Join(e.cfg.StateDir, streamDirName(e.epoch))
	w, err := e.createWAL(dir, e.mountID, e.cfg.VolumeID, e.cfg.Branch, e.epoch)
	if err != nil {
		return e.failLocalWAL("create stream", err)
	}
	w.onFailure = func(err error) { e.failLocalWAL("persist stream", err) }
	job := newJobState(dir, RecoveryJob{
		Version: 1, JobID: jobID, VolumeID: e.cfg.VolumeID, Branch: e.cfg.Branch,
		MountID: hex.EncodeToString(e.mountID[:]), WALEpoch: e.epoch, WritebackID: e.writebackID,
		State: JobActive, CreatedAtMs: time.Now().UnixMilli(),
	})
	if err := job.persist(); err != nil {
		_ = w.Close()
		return e.failLocalWAL("persist recovery registry", err)
	}
	e.wal = w
	e.job = job
	e.streamOpen = true
	return nil
}

// MutationError reports the mount-lifetime terminal verdict. Callers use it
// at their common mutation gate so authority-native operations cannot keep
// changing state after the local engine has failed.
func (e *Engine) MutationError() error {
	if failure := e.failure.Load(); failure != nil {
		return failure.err
	}
	return nil
}

// failClosed latches the first terminal verdict. The failure is deliberately
// never cleared in-process: remount is the only recovery boundary.
func (e *Engine) failClosed(cause error) error {
	if cause == nil {
		return nil
	}
	failure := &engineFailure{err: fmt.Errorf("%w: %w", ErrFailedClosed, cause)}
	if !e.failure.CompareAndSwap(nil, failure) {
		return e.failure.Load().err
	}
	if cb := e.cfg.Events.OnHealth; cb != nil {
		go cb(failure.err)
	}
	return failure.err
}

func (e *Engine) failLocalWAL(operation string, cause error) error {
	if cause == nil {
		return nil
	}
	return e.failClosed(fmt.Errorf("local WAL %s: %w", operation, cause))
}

// ─── scope resolution ────────────────────────────────────────────────────────

// governingScope maps a mutation path to the scope the engine would
// delegate: its parent DIRECTORY. A top-level object's parent is the volume
// root, which is never delegable, so it returns "" — top-level mutations run
// write-through (and keep their authority inode identity). Delegation is a
// subtree optimization; top-level churn is rare.
func governingScope(p string) string {
	return parentDir(p)
}

// coveringLocked finds the delegation whose scope covers p (equal or
// ancestor). Grants never overlap, so at most one covers.
func (e *Engine) coveringLocked(p string) *delegation {
	for s := p; ; {
		if d := e.delegations[s]; d != nil {
			return d
		}
		if s == "" {
			return nil
		}
		s = parentDir(s)
	}
}

// Covers reports whether an active delegation covers path.
func (e *Engine) Covers(path string) bool {
	if e.held.Load() == 0 {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(path)
	return d != nil && !d.draining
}

// ─── mutation admission ──────────────────────────────────────────────────────

// Result is a locally-acknowledged mutation's post-operation view.
type Result struct {
	Entry Entry
	Count int
}

type admission struct {
	d *delegation
}

// admit resolves the delegation admitting a mutation on path, adaptively
// acquiring one when the scope is eligible and uncontended. A grant is kept
// at the mutation's exact parent directory: when a broader ancestor grant
// covers the path, it is drained and released before the narrower grant is
// acquired. This "push down" is what lets peer mounts write sibling
// directories concurrently instead of one mount retaining a broad parent
// checkout for the lifetime of its deeper workload.
//
// ok=false with a nil error is a normal authority-lane decision made before
// the operation; failures always return an error and never change lanes.
func (e *Engine) admit(ctx context.Context, path string) (admission, bool, error) {
	if err := e.MutationError(); err != nil {
		return admission{}, false, err
	}
	if e.cfg.DisableDelegation {
		return admission{}, false, nil
	}
	scope := governingScope(path)
	for {
		e.mu.Lock()
		if e.closed || e.frozen {
			e.mu.Unlock()
			return admission{}, false, errors.New("writeback: engine is not accepting mutations")
		}
		if err := e.MutationError(); err != nil {
			e.mu.Unlock()
			return admission{}, false, err
		}
		d := e.coveringLocked(path)
		if d != nil && !d.draining {
			if d.scope == scope {
				d.lastActive = time.Now()
				return admission{d: d}, true, nil // e.mu stays held; caller releases
			}
			// The active grant is a strict ancestor of the mutation's exact
			// parent. Drain it before continuing so a long-running deep
			// workload never monopolizes a common ancestor shared with peer
			// writers. The next loop acquires the now-authoritative child
			// directory directly.
			e.prepareReleaseLocked(d)
			e.mu.Unlock()
			if err := e.finishRelease(ctx, d); err != nil {
				return admission{}, false, err
			}
			continue
		}
		if d != nil {
			if err := d.drainErr; err != nil {
				e.mu.Unlock()
				return admission{}, false, err
			}
			done := d.done
			e.mu.Unlock()
			if done == nil {
				return admission{}, false, fmt.Errorf("%w: delegation %q is draining without a release attempt", ErrConflict, d.scope)
			}
			select {
			case <-done:
			case <-ctx.Done():
				return admission{}, false, ctx.Err()
			}
			// A release signal means only that the attempt reached a
			// definite outcome. Re-evaluate ownership before choosing local
			// admission, a typed failure, or write-through.
			continue
		}
		if scope == "" {
			e.mu.Unlock()
			return admission{}, false, nil // top-level: no delegable scope
		}
		until, denied := e.denials[scope]
		e.mu.Unlock()
		if denied && time.Now().Before(until) {
			return admission{}, false, nil
		}
		granted, err := e.acquire(ctx, scope)
		if err != nil || !granted {
			return admission{}, false, err
		}
	}
}

// release pairs with a successful admit.
func (e *Engine) release(admission) { e.mu.Unlock() }

// fallThroughLocked is the ONE escape from delegated mode: the engine
// cannot (or must not) acknowledge this mutation locally, so every
// delegation covering the touched paths drains and RELEASES before the
// caller executes write-through — a mutation never runs write-through
// inside a held delegation. Called with e.mu held; returns with it held.
func (e *Engine) fallThroughLocked(ctx context.Context, paths ...string) error {
	e.mu.Unlock()
	err := e.ReleaseFor(ctx, paths...)
	e.mu.Lock()
	return err
}

// appendRecords encodes and appends one syscall's records all-or-nothing and
// registers them with the flusher. Caller holds e.mu.
func (e *Engine) appendRecordsLocked(d *delegation, records []wal.Record) ([]appendResult, error) {
	if err := e.ensureStreamLocked(); err != nil {
		return nil, err
	}
	if e.wal.DiskBytes() >= e.cfg.BudgetBytes {
		e.relieveBudgetLocked()
		if err := e.MutationError(); err != nil {
			return nil, err
		}
		if e.wal.DiskBytes() >= e.cfg.BudgetBytes {
			return nil, ErrNoSpace
		}
	}
	payloads := make([][]byte, len(records))
	for i := range records {
		p, err := wal.EncodePFR1(&records[i])
		if err != nil {
			return nil, err
		}
		payloads[i] = p
	}
	results, err := e.wal.appendMutations(payloads)
	if err != nil {
		return nil, e.failLocalWAL("append mutation", err)
	}
	for i := range results {
		records[i].Seq = results[i].seq
	}
	e.fl.admit(d.scope, results)
	return results, nil
}

// relieveBudgetLocked folds authority-applied extents and reclaims fully
// applied segments, freeing WAL space without touching unshipped data.
// Reclamation happens only through the unified durable-checkpoint operation;
// a checkpoint failure relieves nothing (the caller then refuses admission).
func (e *Engine) relieveBudgetLocked() {
	through, digest := e.fl.appliedState()
	for _, fv := range e.files {
		fv.foldApplied(through)
	}
	pins := map[uint64]bool{}
	for _, fv := range e.files {
		fv.segmentsPinned(pins)
	}
	if e.wal != nil {
		if err := e.wal.CheckpointAndReclaim(through, digest, func(ord uint64) bool { return pins[ord] }); err != nil {
			e.failLocalWAL("checkpoint", err)
			e.logf("writeback: budget-relief checkpoint at %d failed: %v", through, err)
		}
	}
}

// nowMs is stubbed in tests.
var nowMs = func() int64 { return time.Now().UnixMilli() }

// ─── directory views ─────────────────────────────────────────────────────────

// dirViewLocked returns the view for dir, optionally creating a partial one
// (dir must be covered by an active delegation).
func (e *Engine) dirViewLocked(dir string, create bool) *dirView {
	dv := e.dirs[dir]
	if dv == nil && create {
		dv = newDirView(false)
		e.dirs[dir] = dv
	}
	return dv
}

// installEntryLocked binds an entry into its parent view (creating a partial
// view when needed) and returns the stored pointer.
func (e *Engine) installEntryLocked(path string, ent Entry) *Entry {
	ent.Name = baseName(path)
	stored := &ent
	dv := e.dirViewLocked(parentDir(path), true)
	dv.children[ent.Name] = stored
	delete(dv.tombstones, ent.Name)
	return stored
}

// entryLocked resolves path against the overlay: the file view's entry, the
// parent view's child, or a file-grain delegation's self entry.
func (e *Engine) entryLocked(path string) (*Entry, bool) {
	if fv := e.files[path]; fv != nil && fv.entry != nil {
		return fv.entry, true
	}
	dv := e.dirs[parentDir(path)]
	if dv == nil {
		return nil, false
	}
	ent, ok := dv.children[baseName(path)]
	return ent, ok
}

// LookupResult classifies an engine lookup.
type LookupResult int

const (
	// LookupUndecided: the engine cannot answer; resolve at the authority.
	LookupUndecided LookupResult = iota
	// LookupHit: the entry is locally authoritative.
	LookupHit
	// LookupNegative: the name is proven absent (or locally removed).
	LookupNegative
)

// Lookup answers a name resolution from the overlay.
func (e *Engine) Lookup(path string) (Entry, LookupResult) {
	if e.held.Load() == 0 {
		return Entry{}, LookupUndecided
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if path == "" {
		return Entry{}, LookupUndecided
	}
	d := e.coveringLocked(path)
	if d == nil || d.draining {
		return Entry{}, LookupUndecided
	}
	if ent, ok := e.entryLocked(path); ok {
		return *ent, LookupHit
	}
	dv := e.dirs[parentDir(path)]
	if dv == nil {
		return Entry{}, LookupUndecided
	}
	if dv.tombstones[baseName(path)] {
		return Entry{}, LookupNegative
	}
	if dv.complete {
		return Entry{}, LookupNegative
	}
	return Entry{}, LookupUndecided
}

// Readdir serves dir's complete listing when the engine holds one.
func (e *Engine) Readdir(dir string) ([]Entry, bool) {
	if e.held.Load() == 0 {
		return nil, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(dir)
	if d == nil || d.draining {
		return nil, false
	}
	dv := e.dirs[dir]
	if dv == nil || !dv.complete {
		return nil, false
	}
	return dv.listingLocked(), true
}

func (dv *dirView) listingLocked() []Entry {
	out := make([]Entry, 0, len(dv.children))
	for _, ent := range dv.children {
		out = append(out, *ent)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// MergeReaddir folds an authority listing through the overlay and seeds
// dir's complete children set under an active delegation, so later lookups,
// negative answers, and creates are local for the life of the grant. A dir
// without an active covering delegation has no overlay (every local ack is
// strictly inside a held scope, and release drops the scope's views), so the
// authority listing passes through unchanged.
func (e *Engine) MergeReaddir(dir string, authority []Entry) []Entry {
	e.mu.Lock()
	defer e.mu.Unlock()
	d := e.coveringLocked(dir)
	if d == nil || d.draining {
		return authority
	}
	dv := e.dirViewLocked(dir, true)
	if !dv.complete {
		if len(authority) >= maxDirViewChildren {
			// Hard overlay bound: never claim completeness for a listing the
			// view cannot hold; the shared path keeps serving it.
			return authority
		}
		for i := range authority {
			ent := authority[i]
			if dv.tombstones[ent.Name] {
				continue
			}
			if _, local := dv.children[ent.Name]; local {
				continue
			}
			cp := ent
			dv.children[ent.Name] = &cp
		}
		dv.complete = true
		dv.tombstones = map[string]bool{}
	}
	return dv.listingLocked()
}

// ─── mutations ───────────────────────────────────────────────────────────────

func entryNow(kind string, mode uint32) Entry {
	now := nowMs()
	nlink := uint32(1)
	if kind == "directory" {
		nlink = 2
	}
	return Entry{Kind: kind, Mode: mode, MtimeMs: now, CtimeMs: now, AtimeMs: now, Nlink: nlink}
}

// dirBoundExceededLocked reports that adding one name to dir's view would
// grow it past the hard overlay bound.
func (e *Engine) dirBoundExceededLocked(dv *dirView) bool {
	return len(dv.children) >= maxDirViewChildren
}

// Create acknowledges an O_CREAT locally when the engine can decide
// adopt-vs-create (a complete parent view, a locally-known entry, or the
// caller's proven-absent hint). handled=false with no error selects the
// authority's idempotent create after releasing every covering delegation.
func (e *Engine) Create(ctx context.Context, path string, mode uint32, excl, knownAbsent bool) (Result, bool, error) {
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	dv := e.dirViewLocked(parentDir(path), true)
	name := baseName(path)
	if ent, present := e.entryLocked(path); present {
		if excl {
			return Result{}, true, os.ErrExist
		}
		return Result{Entry: *ent}, true, nil // idempotent O_CREAT adopt
	}
	provenAbsent := dv.complete || dv.tombstones[name] || knownAbsent
	if !provenAbsent || e.dirBoundExceededLocked(dv) {
		// Adopt-vs-create is undecidable locally (or the view hit its hard
		// bound): release and let the authority's idempotent create decide.
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	rec := wal.Record{Op: wal.OpCreate, Path: path, Mode: mode}
	if _, err := e.appendRecordsLocked(adm.d, []wal.Record{rec}); err != nil {
		return Result{}, true, err
	}
	ent := e.installEntryLocked(path, entryNow("file", mode))
	e.files[path] = &fileView{entry: ent, basePath: path}
	e.xattrs[path] = newXattrView()
	return Result{Entry: *ent}, true, nil
}

// Mkdir acknowledges a directory creation locally. A born-local directory's
// children set is complete from birth: empty.
func (e *Engine) Mkdir(ctx context.Context, path string, mode uint32) (Result, bool, error) {
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	dv := e.dirViewLocked(parentDir(path), true)
	name := baseName(path)
	if _, present := e.entryLocked(path); present {
		return Result{}, true, os.ErrExist
	}
	if (dv.complete || dv.tombstones[name]) && !e.dirBoundExceededLocked(dv) {
		rec := wal.Record{Op: wal.OpMkdir, Path: path, Mode: mode}
		if _, err := e.appendRecordsLocked(adm.d, []wal.Record{rec}); err != nil {
			return Result{}, true, err
		}
		ent := e.installEntryLocked(path, entryNow("directory", mode))
		e.dirs[path] = newDirView(true)
		e.xattrs[path] = newXattrView()
		return Result{Entry: *ent}, true, nil
	}
	return Result{}, false, e.fallThroughLocked(ctx, path)
}

// Symlink acknowledges a symlink creation locally.
func (e *Engine) Symlink(ctx context.Context, path, target string) (Result, bool, error) {
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	dv := e.dirViewLocked(parentDir(path), true)
	name := baseName(path)
	if _, present := e.entryLocked(path); present {
		return Result{}, true, os.ErrExist
	}
	if (!dv.complete && !dv.tombstones[name]) || e.dirBoundExceededLocked(dv) {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	rec := wal.Record{Op: wal.OpSymlink, Path: path, Target: target}
	if _, err := e.appendRecordsLocked(adm.d, []wal.Record{rec}); err != nil {
		return Result{}, true, err
	}
	ent := entryNow("symlink", 0o777)
	ent.Target = target
	ent.Size = int64(len(target))
	stored := e.installEntryLocked(path, ent)
	e.xattrs[path] = newXattrView()
	return Result{Entry: *stored}, true, nil
}

// Remove acknowledges an unlink/rmdir locally when the target is known (and,
// for directories, proven empty).
func (e *Engine) Remove(ctx context.Context, path string) (Result, bool, error) {
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	ent, present := e.entryLocked(path)
	if !present {
		dv := e.dirs[parentDir(path)]
		if dv != nil && (dv.complete || dv.tombstones[baseName(path)]) {
			return Result{}, true, os.ErrNotExist
		}
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	if ent.Kind == "directory" {
		sub := e.dirs[path]
		if sub == nil || !sub.complete {
			return Result{}, false, e.fallThroughLocked(ctx, path)
		}
		if len(sub.children) != 0 {
			return Result{}, true, syscall.ENOTEMPTY
		}
	}
	rec := wal.Record{Op: wal.OpRemove, Path: path}
	if _, err := e.appendRecordsLocked(adm.d, []wal.Record{rec}); err != nil {
		return Result{}, true, err
	}
	e.removeLocalLocked(path)
	return Result{}, true, nil
}

// removeLocalLocked drops path (and any views under it) from the overlay,
// tombstoning the name in a partial parent.
func (e *Engine) removeLocalLocked(path string) {
	name := baseName(path)
	if dv := e.dirs[parentDir(path)]; dv != nil {
		delete(dv.children, name)
		if !dv.complete {
			dv.tombstones[name] = true
		}
	}
	delete(e.files, path)
	delete(e.dirs, path)
	delete(e.xattrs, path)
	prefix := path + "/"
	for p := range e.files {
		if strings.HasPrefix(p, prefix) {
			delete(e.files, p)
		}
	}
	for p := range e.dirs {
		if strings.HasPrefix(p, prefix) {
			delete(e.dirs, p)
		}
	}
	for p := range e.xattrs {
		if strings.HasPrefix(p, prefix) {
			delete(e.xattrs, p)
		}
	}
}

// Rename acknowledges a rename locally when both ends are covered by the
// SAME delegation and the source is locally known. Everything else releases
// the covering delegations and runs write-through.
func (e *Engine) Rename(ctx context.Context, oldp, newp string) (Result, bool, error) {
	adm, ok, err := e.admit(ctx, oldp)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	dNew := e.coveringLocked(newp)
	srcEnt, srcKnown := e.entryLocked(oldp)
	if dNew != adm.d || !srcKnown {
		return Result{}, false, e.fallThroughLocked(ctx, oldp, newp)
	}
	newDV := e.dirViewLocked(parentDir(newp), true)
	if _, dstKnown := e.entryLocked(newp); !dstKnown && !newDV.complete && !newDV.tombstones[baseName(newp)] {
		// The destination may exist on the authority with unknowable state
		// (rename-over of an open peer file needs the orphan protocol).
		return Result{}, false, e.fallThroughLocked(ctx, oldp, newp)
	}
	if e.dirBoundExceededLocked(newDV) {
		return Result{}, false, e.fallThroughLocked(ctx, oldp, newp)
	}
	rec := wal.Record{Op: wal.OpRename, Path: oldp, NewPath: newp}
	renRes, err := e.appendRecordsLocked(adm.d, []wal.Record{rec})
	if err != nil {
		return Result{}, true, err
	}
	renameSeq := renRes[0].seq
	moved := *srcEnt
	srcXattrs := e.xattrs[oldp]
	// Re-key the moved object and every overlay object under it.
	srcFile := e.files[oldp]
	srcDir := e.dirs[oldp]
	type mv struct{ from, to string }
	var files, dirsMv, xattrsMv []mv
	prefix := oldp + "/"
	for p := range e.files {
		if strings.HasPrefix(p, prefix) {
			files = append(files, mv{p, newp + "/" + p[len(prefix):]})
		}
	}
	for p := range e.dirs {
		if strings.HasPrefix(p, prefix) {
			dirsMv = append(dirsMv, mv{p, newp + "/" + p[len(prefix):]})
		}
	}
	for p := range e.xattrs {
		if strings.HasPrefix(p, prefix) {
			xattrsMv = append(xattrsMv, mv{p, newp + "/" + p[len(prefix):]})
		}
	}
	e.removeLocalLocked(newp)
	for _, m := range files {
		mv := e.files[m.from]
		// The moved view's clean ranges stay at the OLD authority path until
		// the rename applies; base reads follow the pending move.
		mv.notePathMove(renameSeq, m.to)
		e.files[m.to] = mv
		delete(e.files, m.from)
	}
	for _, m := range dirsMv {
		e.dirs[m.to] = e.dirs[m.from]
		delete(e.dirs, m.from)
	}
	for _, m := range xattrsMv {
		e.xattrs[m.to] = e.xattrs[m.from]
		delete(e.xattrs, m.from)
	}
	// Detach the old name (tombstone in partial parents).
	if dv := e.dirs[parentDir(oldp)]; dv != nil {
		delete(dv.children, baseName(oldp))
		if !dv.complete {
			dv.tombstones[baseName(oldp)] = true
		}
	}
	delete(e.files, oldp)
	delete(e.dirs, oldp)
	delete(e.xattrs, oldp)
	stored := e.installEntryLocked(newp, moved)
	if srcFile != nil {
		srcFile.entry = stored
		srcFile.notePathMove(renameSeq, newp)
		e.files[newp] = srcFile
	}
	if srcDir != nil {
		e.dirs[newp] = srcDir
	}
	if srcXattrs != nil {
		e.xattrs[newp] = srcXattrs
	}
	return Result{Entry: *stored}, true, nil
}

// WriteAt acknowledges a write locally. Writing never hydrates the base: the
// dirty range becomes WAL-backed extents over the (unfetched) base content.
func (e *Engine) WriteAt(ctx context.Context, path string, off int64, data []byte) (Result, bool, error) {
	if off < 0 {
		return Result{}, false, errors.New("writeback: negative write offset")
	}
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	fv, ok := e.fileViewLocked(path)
	if !ok {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	return e.writeLocked(ctx, adm.d, path, fv, off, data)
}

// WriteAppend acknowledges an O_APPEND write at the locally-authoritative
// EOF (the exclusive delegation makes the local size exact).
func (e *Engine) WriteAppend(ctx context.Context, path string, data []byte) (Result, bool, error) {
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	fv, ok := e.fileViewLocked(path)
	if !ok {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	return e.writeLocked(ctx, adm.d, path, fv, fv.entry.Size, data)
}

// fileViewLocked materializes the dirty view for a locally-known file.
func (e *Engine) fileViewLocked(path string) (*fileView, bool) {
	if fv := e.files[path]; fv != nil {
		return fv, true
	}
	ent, present := e.entryLocked(path)
	if !present || ent.Kind != "file" {
		return nil, false
	}
	fv := &fileView{entry: ent, basePath: path}
	e.files[path] = fv
	return fv, true
}

func (e *Engine) writeLocked(ctx context.Context, d *delegation, path string, fv *fileView, off int64, data []byte) (Result, bool, error) {
	const chunk = 1 << 20
	records := make([]wal.Record, 0, (len(data)+chunk-1)/chunk)
	for start := 0; start < len(data); start += chunk {
		end := min(start+chunk, len(data))
		records = append(records, wal.Record{
			Op: wal.OpWrite, Path: path,
			Offset: off + int64(start), Data: data[start:end],
		})
	}
	if len(records) == 0 {
		return Result{Entry: *fv.entry}, true, nil
	}
	if len(fv.extents)+len(records)+1 > maxFileExtents {
		// Hard overlay bound (records + a possible hole extent would exceed
		// it): drain, release, write-through — no spill.
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	results, err := e.appendRecordsLocked(d, records)
	if err != nil {
		return Result{}, true, err
	}
	if uint64(off) > uint64(fv.entry.Size) {
		fv.insertExtent(extent{start: uint64(fv.entry.Size), end: uint64(off), seq: results[0].seq, zero: true})
	}
	for i, res := range results {
		rec := records[i]
		// The PFR1 payload embeds the data bytes at its tail; locate them so
		// extents reference the exact on-disk write payload.
		dataOff := res.payloadOff + int64(res.payloadLen-len(rec.Data))
		fv.insertExtent(extent{
			start: uint64(rec.Offset), end: uint64(rec.Offset) + uint64(len(rec.Data)),
			seq: res.seq, ordinal: res.ordinal, off: dataOff,
		})
	}
	if end := off + int64(len(data)); end > fv.entry.Size {
		fv.entry.Size = end
	}
	fv.entry.MtimeMs = nowMs()
	fv.entry.CtimeMs = fv.entry.MtimeMs
	return Result{Entry: *fv.entry, Count: len(data)}, true, nil
}

// Truncate acknowledges a truncate locally.
func (e *Engine) Truncate(ctx context.Context, path string, size int64) (Result, bool, error) {
	if size < 0 {
		return Result{}, false, errors.New("writeback: negative truncate size")
	}
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	fv, ok := e.fileViewLocked(path)
	if !ok {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	if len(fv.extents)+1 > maxFileExtents {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	rec := wal.Record{Op: wal.OpTruncate, Path: path, Size: size}
	results, err := e.appendRecordsLocked(adm.d, []wal.Record{rec})
	if err != nil {
		return Result{}, true, err
	}
	fv.truncateExtents(uint64(fv.entry.Size), uint64(size), results[0].seq)
	fv.entry.Size = size
	fv.entry.MtimeMs = nowMs()
	fv.entry.CtimeMs = fv.entry.MtimeMs
	return Result{Entry: *fv.entry}, true, nil
}

// SetattrRequest is the metadata mutation surface (one group per call).
type SetattrRequest struct {
	SetMode bool
	Mode    uint32
	SetTime bool
	MtimeMs int64
	SetUID  bool
	UID     uint32
	SetGID  bool
	GID     uint32
}

// Setattr acknowledges chmod/chtimes/chown locally for a known entry.
func (e *Engine) Setattr(ctx context.Context, path string, req SetattrRequest) (Result, bool, error) {
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	ent, present := e.entryLocked(path)
	if !present {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	var records []wal.Record
	if req.SetMode {
		records = append(records, wal.Record{Op: wal.OpChmod, Path: path, Mode: req.Mode})
	}
	if req.SetTime {
		records = append(records, wal.Record{Op: wal.OpChtimes, Path: path, MtimeMs: req.MtimeMs})
	}
	if req.SetUID || req.SetGID {
		rec := wal.Record{Op: wal.OpChown, Path: path, ChownSetUID: req.SetUID, ChownSetGID: req.SetGID}
		if req.SetUID {
			rec.UID = req.UID
		}
		if req.SetGID {
			rec.GID = req.GID
		}
		records = append(records, rec)
	}
	if len(records) == 0 {
		return Result{Entry: *ent}, true, nil
	}
	if _, err := e.appendRecordsLocked(adm.d, records); err != nil {
		return Result{}, true, err
	}
	if req.SetMode {
		ent.Mode = req.Mode
	}
	if req.SetTime {
		ent.MtimeMs = req.MtimeMs
	}
	if req.SetUID {
		ent.UID = req.UID
	}
	if req.SetGID {
		ent.GID = req.GID
	}
	ent.CtimeMs = nowMs()
	return Result{Entry: *ent}, true, nil
}

// Getxattr answers from a complete delegated xattr view. Such a view exists
// only for an object born locally under the grant; existing authority
// objects stay read-through because the grant snapshot does not carry their
// xattr values.
func (e *Engine) Getxattr(path, name string) ([]byte, LookupResult) {
	if e.held.Load() == 0 {
		return nil, LookupUndecided
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(path)
	if d == nil || d.draining {
		return nil, LookupUndecided
	}
	xv := e.xattrs[path]
	if xv == nil {
		return nil, LookupUndecided
	}
	value, ok := xv.values[name]
	if !ok {
		return nil, LookupNegative
	}
	return append([]byte(nil), value...), LookupHit
}

// Listxattr returns the complete sorted name set for a locally-born object.
func (e *Engine) Listxattr(path string) ([]string, bool) {
	if e.held.Load() == 0 {
		return nil, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(path)
	xv := e.xattrs[path]
	if d == nil || d.draining || xv == nil {
		return nil, false
	}
	names := make([]string, 0, len(xv.values))
	for name := range xv.values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, true
}

// Setxattr acknowledges an xattr mutation locally only when the engine owns
// the object's complete xattr map. That proves conditional flags and the
// frozen per-inode total-byte bound before acknowledgment; existing objects
// conservatively release the grant and use the authority lane.
func (e *Engine) Setxattr(ctx context.Context, path, name string, value []byte, flags uint8) (bool, error) {
	if e.cfg.DisableDelegatedXattrs {
		return false, e.ReleaseFor(ctx, path)
	}
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return false, err
	}
	defer e.release(adm)
	if _, present := e.entryLocked(path); !present {
		return false, e.fallThroughLocked(ctx, path)
	}
	xv := e.xattrs[path]
	if xv == nil {
		return false, e.fallThroughLocked(ctx, path)
	}
	_, exists := xv.values[name]
	if flags&wal.XattrCreate != 0 && exists {
		return true, os.ErrExist
	}
	if flags&wal.XattrReplace != 0 && !exists {
		return true, ErrNoXattr
	}
	if xv.totalAfterSet(name, value) > wal.MaxXattrTotalBytes {
		return true, ErrNoSpace
	}
	rec := wal.Record{Op: wal.OpSetxattr, Path: path, XattrName: name, XattrFlags: flags, Data: value}
	if _, err := e.appendRecordsLocked(adm.d, []wal.Record{rec}); err != nil {
		return true, err
	}
	xv.values[name] = append([]byte(nil), value...)
	return true, nil
}

// Removexattr acknowledges a removal locally under the same complete-view
// rule as Setxattr, preserving ENODATA exactly.
func (e *Engine) Removexattr(ctx context.Context, path, name string) (bool, error) {
	if e.cfg.DisableDelegatedXattrs {
		return false, e.ReleaseFor(ctx, path)
	}
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return false, err
	}
	defer e.release(adm)
	if _, present := e.entryLocked(path); !present {
		return false, e.fallThroughLocked(ctx, path)
	}
	xv := e.xattrs[path]
	if xv == nil {
		return false, e.fallThroughLocked(ctx, path)
	}
	if _, exists := xv.values[name]; !exists {
		return true, ErrNoXattr
	}
	rec := wal.Record{Op: wal.OpRemovexattr, Path: path, XattrName: name}
	if _, err := e.appendRecordsLocked(adm.d, []wal.Record{rec}); err != nil {
		return true, err
	}
	delete(xv.values, name)
	return true, nil
}

// ─── reads ───────────────────────────────────────────────────────────────────

// BaseReader resolves clean gaps of a composed read: it reads the authority
// (or version-gated cache) content for [off, off+len(dst)) at basePath — the
// authority path CURRENTLY serving this view's clean ranges, which trails a
// locally-acknowledged rename until the rename applies.
type BaseReader func(basePath string, off int64, dst []byte) (int, error)

// ReadAt composes a read from dirty extents over the base. handled=false
// means the file has no dirty state and the caller serves it normally.
// The extent snapshot pins its WAL segments, so a concurrent
// checkpoint+reclaim can never delete one mid-pread (no retry compensation).
func (e *Engine) ReadAt(path string, dst []byte, off int64, base BaseReader) (int, bool, error) {
	e.mu.RLock()
	fv := e.files[path]
	if fv == nil {
		e.mu.RUnlock()
		return 0, false, nil
	}
	size := fv.entry.Size
	if off >= size {
		e.mu.RUnlock()
		return 0, true, nil
	}
	end := min(off+int64(len(dst)), size)
	ext := append([]extent(nil), fv.overlapping(uint64(off), uint64(end))...)
	basePath := fv.baseAt()
	w := e.wal
	var pinned []uint64
	if w != nil {
		for _, seg := range ext {
			if !seg.zero {
				pinned = append(pinned, seg.ordinal)
			}
		}
		w.pinSegments(pinned)
		defer w.unpinSegments(pinned)
	}
	e.mu.RUnlock()

	n := int(end - off)
	cur := uint64(off)
	fill := func(from, to uint64, seg *extent) error {
		out := dst[from-uint64(off) : to-uint64(off)]
		switch {
		case seg == nil:
			// Clean gap: authority base content. Holes are always covered by
			// zero extents, so a gap is either untouched base or (post-fold)
			// flushed content the authority now serves; short base reads
			// zero-fill (the base may be shorter than our extended size).
			m, err := base(basePath, int64(from), out)
			if err != nil {
				return err
			}
			for i := m; i < len(out); i++ {
				out[i] = 0
			}
		case seg.zero:
			clear(out)
		default:
			return w.ReadAt(seg.ordinal, out, seg.off+int64(from-seg.start))
		}
		return nil
	}
	for _, seg := range ext {
		s := max(seg.start, uint64(off))
		if s > cur {
			if err := fill(cur, s, nil); err != nil {
				return 0, true, err
			}
		}
		t := min(seg.end, uint64(end))
		segCopy := seg
		if err := fill(s, t, &segCopy); err != nil {
			return 0, true, err
		}
		cur = t
	}
	if cur < uint64(end) {
		if err := fill(cur, uint64(end), nil); err != nil {
			return 0, true, err
		}
	}
	return n, true, nil
}

// Readlink serves a locally-known symlink target.
func (e *Engine) Readlink(path string) (target string, kind string, ok bool) {
	if e.held.Load() == 0 {
		return "", "", false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(path)
	if d == nil || d.draining {
		return "", "", false
	}
	ent, present := e.entryLocked(path)
	if !present {
		dv := e.dirs[parentDir(path)]
		if dv != nil && (dv.complete || dv.tombstones[baseName(path)]) {
			return "", "", true // proven absent: kind ""
		}
		return "", "", false
	}
	return ent.Target, ent.Kind, true
}

// ─── barriers and lifecycle ──────────────────────────────────────────────────

// Fsync makes every accepted mutation authority-durable: local WAL sync
// plus a flush drain through the current stream tail (flush commits are
// durable-before-reply at the authority).
func (e *Engine) Fsync(ctx context.Context, path string) error {
	_ = path // the mount stream is globally dense; fsync overflushes by design
	return e.DrainAll(ctx)
}

// DrainAll flushes the captured stream tail to the authority.
func (e *Engine) DrainAll(ctx context.Context) error {
	failure := e.MutationError()
	e.mu.RLock()
	w := e.wal
	e.mu.RUnlock()
	if w == nil {
		return failure
	}
	if err := w.Sync(); err != nil {
		return e.failLocalWAL("sync", err)
	}
	if failure != nil {
		return failure
	}
	return e.fl.drainThrough(ctx, w.LastSeq())
}

// SyncLocal makes every accepted mutation locally durable (journal-first
// barriers); no network.
func (e *Engine) SyncLocal() error {
	e.mu.RLock()
	w := e.wal
	e.mu.RUnlock()
	if w == nil {
		return nil
	}
	if err := w.Sync(); err != nil {
		return e.failLocalWAL("sync", err)
	}
	return nil
}

// Pending reports the unshipped acknowledged backlog.
func (e *Engine) Pending() (records int, bytes int64) {
	return e.fl.pendingStats()
}

// Close drains everything, releases every delegation, writes the clean CLOSE
// frame, and best-effort deletes the now-redundant local stream.
func (e *Engine) Close(ctx context.Context) error {
	return e.CloseWithBarrier(ctx, nil)
}

// CloseWithBarrier freezes new admissions, drains and releases every
// delegation, then runs barrier while the engine is still frozen and
// recoverable. A failure at any stage thaws the engine and leaves its stream
// intact so the mounted caller can keep serving and retry. The callback lets
// clientcore place the authority/subscriber visibility barrier inside the
// same no-new-mutations window as the final drain.
func (e *Engine) CloseWithBarrier(ctx context.Context, barrier func() error) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.frozen = true
	w := e.wal
	e.mu.Unlock()
	if w != nil {
		if err := w.Sync(); err != nil {
			e.thawAfterFailedClose()
			return e.failLocalWAL("clean-unmount sync", err)
		}
		if err := e.fl.drainThrough(ctx, w.LastSeq()); err != nil {
			e.thawAfterFailedClose()
			return err
		}
	}
	if err := e.releaseAll(ctx); err != nil {
		e.thawAfterFailedClose()
		return err
	}
	if barrier != nil {
		if err := barrier(); err != nil {
			e.thawAfterFailedClose()
			return err
		}
	}
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	e.stopIdle()
	e.cancelCtx()
	e.fl.stop()
	if w != nil {
		if err := w.appendControl(frameClose, closeFrame{Through: e.fl.appliedThrough()}); err != nil {
			e.logf("writeback: clean-close marker after committed final barrier: %v", err)
		} else if err := w.Sync(); err != nil {
			e.logf("writeback: clean-close marker sync after committed final barrier: %v", err)
		}
		if err := w.RemoveAll(); err != nil {
			// The authority barrier and optional frontend detach have already
			// committed, and the engine is irreversibly stopped. Report this
			// as cleanup debt instead of falsely telling the caller that the
			// still-mounted, retryable failure contract applies. Exact replay
			// makes any retained clean tail harmless on the next attach.
			e.logf("writeback: remove clean stream after committed final barrier: %v", err)
		}
	}
	_ = e.lock.Close()
	return nil
}

func (e *Engine) thawAfterFailedClose() {
	e.mu.Lock()
	if !e.closed {
		e.frozen = false
	}
	e.mu.Unlock()
}

// ForceClose makes the WAL and recovery job durable and closes locally
// without releasing delegations. It returns the visible job ID.
func (e *Engine) ForceClose(reason string) (string, error) {
	e.mu.Lock()
	e.frozen = true
	w := e.wal
	job := e.job
	e.mu.Unlock()
	e.stopIdle()
	e.cancelCtx()
	e.fl.stop()
	if w == nil {
		e.mu.Lock()
		e.closed = true
		e.mu.Unlock()
		_ = e.lock.Close()
		return "", nil
	}
	if err := w.Sync(); err != nil {
		return "", e.failLocalWAL("forced-unmount sync", err)
	}
	jobID := ""
	if job != nil {
		recs, bytes := e.fl.pendingStats()
		job.update(func(j *RecoveryJob) {
			j.State = JobForced
			j.AdmittedThrough = w.LastSeq()
			j.AppliedThrough = e.fl.appliedThrough()
			j.PendingRecords = uint64(recs)
			j.PendingBytes = uint64(bytes)
			j.LastError = reason
		})
		if err := job.persist(); err != nil {
			return "", e.failLocalWAL("persist forced recovery job", err)
		}
		jobID = job.snapshot().JobID
	}
	if err := w.appendControl(frameForcedClose, closeFrame{
		Through: e.fl.appliedThrough(), JobID: jobID, Reason: reason,
	}); err != nil {
		return jobID, e.failLocalWAL("record forced close", err)
	}
	if err := w.Sync(); err != nil {
		return jobID, e.failLocalWAL("sync forced close", err)
	}
	if err := w.Close(); err != nil {
		return jobID, e.failLocalWAL("close forced WAL", err)
	}
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	_ = e.lock.Close()
	return jobID, nil
}

// Abandon simulates a process crash for tests: background work stops and the
// store lock releases, but nothing drains, releases, or writes CLOSE frames —
// the stream stays exactly as a kill -9 would leave it (modulo the OS page
// cache, which in-process tests cannot drop).
func (e *Engine) Abandon() {
	e.mu.Lock()
	e.frozen = true
	e.closed = true
	w := e.wal
	e.mu.Unlock()
	e.stopIdle()
	e.cancelCtx()
	e.fl.stop()
	if w != nil {
		w.Abandon()
	}
	_ = e.lock.Close()
}

// Status is the engine's health and durability-debt snapshot.
type Status struct {
	Delegations     []DelegationStatus
	PendingRecords  int
	PendingBytes    int64
	AdmittedThrough uint64
	AppliedThrough  uint64
	OldestPendingMs int64
	Degraded        bool
	LastFailure     string
	LastProgressMs  int64
	WALBytes        int64
	WALBudget       int64
	Jobs            []RecoveryJob
}

// DelegationStatus is one held scope's view.
type DelegationStatus struct {
	Scope    string
	Epoch    string
	Draining bool
}

func (e *Engine) Status() Status {
	st := e.fl.status()
	if err := e.MutationError(); err != nil {
		st.Degraded = true
		st.LastFailure = err.Error()
	}
	st.WALBudget = e.cfg.BudgetBytes
	e.mu.RLock()
	if e.wal != nil {
		st.AdmittedThrough = e.wal.LastSeq()
		st.WALBytes = e.wal.DiskBytes()
	}
	for _, d := range e.delegations {
		st.Delegations = append(st.Delegations, DelegationStatus{Scope: d.scope, Epoch: d.epoch, Draining: d.draining})
	}
	e.mu.RUnlock()
	sort.Slice(st.Delegations, func(i, j int) bool { return st.Delegations[i].Scope < st.Delegations[j].Scope })
	st.Jobs = e.recovery.jobs()
	return st
}

func min[T ~int | ~int64 | ~uint64](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func max[T ~int | ~int64 | ~uint64](a, b T) T {
	if a > b {
		return a
	}
	return b
}
