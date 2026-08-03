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
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// ErrDelegatedBindingMismatch reports that a stable-inode caller's expected
// object no longer matches the name in a retained delegation snapshot. The
// caller must retry through its pathless exact lane; a pathname-scoped
// authority fallback is not sufficient because other aliases may be covered
// by unrelated retained delegations.
var ErrDelegatedBindingMismatch = errors.New("writeback: delegated path binds a different inode")

// Events are the engine-to-frontend hooks.
type Events struct {
	// OnGrant fires after a delegation installs: the caller evicts shared
	// attr/negative/directory/kernel state under the scope.
	OnGrant func(scope string)

	// AllowDelegatedMutation is re-evaluated while e.mu protects the active
	// grant selected for admission, including immediately after a newly
	// acquired grant is installed. A false result drains that exact grant
	// and selects the authority lane. The callback must not call back into
	// Engine; clientcore uses it only to consult its independent hard-link
	// identity index.
	AllowDelegatedMutation func(ctx context.Context, path string) bool
	// ValidateDelegatedMutation provides a typed rejection when a
	// stable-inode operation cannot trust the delegation snapshot's
	// path→inode binding. entry/present are copied from the exact active
	// snapshot while e.mu still owns admission, closing the validation-to-
	// mutation TOCTOU. The callback must not call back into Engine. The
	// covering grant drains before the error returns; clientcore then
	// escalates through its mount-wide exact barrier.
	ValidateDelegatedMutation func(ctx context.Context, path string, entry Entry, present bool) error
	// OnHandoff runs synchronously after the captured WAL tail is
	// authority-visible and all overlay readers have exited, but before
	// Checkin releases the grant. The client evicts every user-space cache
	// capable of bypassing read admission while peers are still excluded.
	OnHandoff func(scope string) error
	// OnHandoffStart closes frontend reply admission before overlay read
	// admission closes; OnHandoffEnd reopens it after Checkin has a definite
	// outcome. This brackets response publication around OnHandoff.
	OnHandoffStart func(ctx context.Context, scope string) error
	OnHandoffEnd   func(scope string)
	// OnHandoffPrepared runs after authority identities for protected opens
	// have been assigned, while read/frontend admission and the delegation
	// grant are still held, and before the durable Checkin. It may prepare
	// and persist identities for published-but-closed nodes. The returned
	// end hook retires any temporary authority pins after Checkin resolves.
	OnHandoffPrepared func(
		ctx context.Context,
		scope string,
		epoch string,
	) (end func(released bool), err error)
	// OnReleaseWait temporarily removes the calling frontend operation from
	// pre-handoff publication admission while it waits for a release that
	// must complete before the operation itself can run. The returned resume
	// function re-enters admission before the caller publishes any outcome.
	// This prevents concurrent write-through callers joined to one release
	// from waiting cyclically on their own unpublished replies.
	OnReleaseWait func(ctx context.Context) (resume func())
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

	// ProtectOpenPins establishes authority-durable open pins for every open
	// handle under scope and returns a release barrier. The engine retains
	// that barrier through the authority's durable delegation release, so a
	// new locally-born open or path rebind cannot enter the handoff gap.
	// nil skips (tests without open tracking).
	ProtectOpenPins func(ctx context.Context, scope, epoch string) (end func(released bool), err error)

	// DelegationAcquireGate registers one cancellable, scope-aware ownership
	// transition before the remote request. ReconcileReply atomically
	// promotes the claim with reply-discovered identities before local grant
	// installation; install=false means the embedder found a hidden alias
	// conflict and the engine must release the grant without exposing it.
	// End retains transition ownership through every install/abort outcome.
	// nil is valid for embedders that never issue authority mutations beside
	// Engine.
	DelegationAcquireGate func(
		ctx context.Context,
		scope string,
	) (DelegationAcquireGuard, error)

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

// DelegationAcquireGuard spans one remote acquire decision through its local
// installation or definite release.
type DelegationAcquireGuard struct {
	ReconcileReply func(reply AcquireReply) (install bool)
	End            func()
}

// delegation is one authority-issued grant held by this engine.
type delegation struct {
	scope      string
	epoch      string
	grantedAt  time.Time
	lastActive time.Time
	draining   bool
	// localFinal is set only after the WAL has durably recorded the
	// authority-applied prefix followed by RELEASE. Once true, delegated
	// admission is irreversible even if Checkin has not returned.
	localFinal bool
	// attempt closes whenever the current drain+release operation reaches a
	// definite outcome. A failed attempt leaves drainErr set and the
	// delegation held: admissions wake, re-evaluate, and fail instead of
	// escaping into write-through while the authority still owns the grant.
	attempt  *releaseAttempt
	drainErr error
	// readClosing is the read-side half of the handoff barrier. Readers that
	// entered before it was set pin the overlay through their whole
	// operation; later readers wait for attempt and re-resolve after the
	// grant either releases or definitely remains held.
	readMu      sync.Mutex
	readClosing bool
	readers     int
	readersZero chan struct{}
}

// releaseAttempt is one immutable single-flight outcome. Followers retain
// this exact object so a later retry cannot replace the result they joined.
type releaseAttempt struct {
	done     chan struct{}
	once     sync.Once
	err      error
	eventCtx context.Context
}

// valueOverlayContext takes cancellation, deadlines, and all engine-owned
// lifetime semantics from Context while exposing request-scoped values to
// handoff hooks. A caller cancellation must never interrupt an already-owned
// durable release, but frontend hooks still need the initiating operation's
// identity to avoid waiting on themselves.
type valueOverlayContext struct {
	context.Context
	values context.Context
}

func (c valueOverlayContext) Value(key any) any {
	if c.values != nil {
		if value := c.values.Value(key); value != nil {
			return value
		}
	}
	return c.Context.Value(key)
}

func newReleaseAttempt(eventCtx context.Context) *releaseAttempt {
	return &releaseAttempt{done: make(chan struct{}), eventCtx: eventCtx}
}

func (a *releaseAttempt) complete(err error) error {
	a.once.Do(func() {
		a.err = err
		close(a.done)
	})
	<-a.done
	return a.err
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

	mu sync.RWMutex
	// exactMu excludes asynchronous delegation acquisition while a caller
	// drains all retained scopes and performs a pathless stable-inode
	// authority operation. Acquisition resolvers hold it shared for their
	// complete remote resolution, including after their initiating request
	// times out.
	exactMu    sync.RWMutex
	closed     bool
	frozen     bool // no further delegated admissions (unmount/force-close)
	streamOpen bool
	// laned mirrors the stream WAL's lane era under e.mu, so the per-append
	// lane decision costs a field read instead of a WAL mutex acquire. The
	// boundary is one-way (openLanedEraLocked), so a cached copy can only ever
	// lag into the SAFE direction — writing the legacy stream for one more
	// admission, never writing a laned frame on a stream that has not crossed.
	laned bool
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

	// walFull mirrors "the stream WAL leaves no headroom for the bulk-data
	// lane". It is advisory — every definite verdict is re-derived under e.mu —
	// and is published in Status so an operator can see the data lane sitting
	// at its cap while metadata keeps flowing on the reserve.
	walFull atomic.Bool

	acquireMu sync.Mutex
	acquiring map[string]*acquireFlight

	// failure is the mount-lifetime terminal verdict. Atomic reads keep the
	// mutation fast path lock-free while the first failure wins permanently.
	failure atomic.Pointer[engineFailure]

	wal *streamWAL
	fl  *flusher
	job *jobState

	// credits is the drain-time admission gate for bulk data (see credit.go).
	// It paces data mutations against the measured authority-applied rate so
	// resident debt stays drainable inside one barrier bound; it never moves
	// the hard WAL cap, which the exact reservation still enforces underneath.
	credits *creditController

	// lanes tallies which door each write took onto the authority lane, and
	// how many bytes went through it (see lanerouting.go). It is pure
	// measurement: nothing reads it to make a decision.
	lanes laneCounters

	// authority is the authority lane's admission gate and unproven-byte
	// ledger (see authoritycredit.go). Every byte acknowledged on the
	// write-through lane is charged here, so no lane is uncharged and the
	// durability check has something to read.
	authority *authorityGate

	// createWAL is fixed to createStreamWAL in production and replaceable by
	// package tests for deterministic initialization-failure coverage.
	createWAL func(string, [16]byte, string, string, uint64) (*streamWAL, error)

	recovery *recoveryRunner
	idleStop chan struct{}
	idleOnce sync.Once
	idleWG   sync.WaitGroup

	// Every delegation release is an engine-owned resolver. Callers only
	// wait on its immutable attempt outcome with their own contexts. The
	// lifecycle joins these workers before closing or abandoning the WAL,
	// so no late resolver can write through a closed stream.
	releaseWG sync.WaitGroup
	forcing   bool
}

// signalIdleStop prevents the idle loop from starting more voluntary release
// work. Joining is deliberately separate: a release already in progress may
// be waiting on the engine context or flusher, both of which forced teardown
// must cancel before it waits for the loop.
func (e *Engine) signalIdleStop() {
	e.idleOnce.Do(func() {
		if e.idleStop != nil {
			close(e.idleStop)
		}
	})
}

func (e *Engine) stopIdle() {
	e.signalIdleStop()
	e.idleWG.Wait()
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
	if (cfg.Events.OnHandoffStart == nil) != (cfg.Events.OnHandoffEnd == nil) {
		return nil, errors.New("writeback: OnHandoffStart and OnHandoffEnd must be configured together")
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
	// A force-park proof is bound to the exact mount transaction that was
	// detached. Once a new engine exclusively owns the store, that proof must
	// not survive to authorize a later transaction over the same store.
	if err := clearForceParkProof(cfg.StateDir); err != nil {
		_ = lock.Close()
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
	e.credits = newCreditController(e)
	e.authority = newAuthorityGate(e.dataBudgetBytes())
	e.fl = newFlusher(e)
	e.recovery = newRecoveryRunner(e)
	maxEpoch := e.recovery.discover()
	e.epoch, err = reserveWALEpoch(cfg.StateDir, maxEpoch)
	if err != nil {
		e.cancelCtx()
		_ = lock.Close()
		return nil, err
	}
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
	e.idleWG.Add(1)
	go func() {
		defer e.idleWG.Done()
		e.idleLoop()
	}()
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

// reserveWALEpoch durably advances the stream-identity high-water mark.
// Stream directories are deliberately removed after a clean close, so
// discovering their maximum is not enough: without this independent
// reservation, the next clean mount would reuse epoch 1 and collide with the
// authority's durable write-back ledger. Gaps after a crash are harmless;
// reuse is not.
func reserveWALEpoch(dir string, discovered uint64) (uint64, error) {
	path := filepath.Join(dir, "wal-epoch")
	last := discovered
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		persisted, parseErr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if parseErr != nil || persisted == 0 {
			return 0, fmt.Errorf("%w: malformed WAL epoch high-water mark %s", ErrCorrupt, path)
		}
		last = max(last, persisted)
	case errors.Is(err, os.ErrNotExist):
	default:
		return 0, fmt.Errorf("writeback: read WAL epoch high-water mark: %w", err)
	}
	if last == math.MaxUint64 {
		return 0, errors.New("writeback: WAL epoch space exhausted")
	}
	next := last + 1
	if err := writeFileAtomicDurable(path, []byte(strconv.FormatUint(next, 10)+"\n"), 0o600); err != nil {
		return 0, fmt.Errorf("writeback: reserve WAL epoch %d: %w", next, err)
	}
	return next, nil
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

// KeepWritebackFrozenError is implemented by a finalizer error when thawing
// would violate a durable external transaction marker. CloseWithBarrier
// seals mutation admission for the process lifetime in that case.
type KeepWritebackFrozenError interface {
	KeepWritebackFrozen() bool
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

// Covers reports whether a retained delegation covers path. A draining grant
// still owns the subtree until its durable Checkin completes: reads must keep
// using its overlay, and write-through-only mutations must join its release
// rather than race the in-flight handoff.
func (e *Engine) Covers(path string) bool {
	if e.held.Load() == 0 {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(path)
	return d != nil
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
	switch resolvedLaneOf(ctx) {
	case LaneAuthority:
		// Decided outside the frontend's locks, with the covering grant already
		// released and the transition exclusion held. There is nothing to check
		// and nothing to transition: the authority lane IS the answer.
		return admission{}, false, nil
	case LaneDelegated:
		return e.admitResolved(ctx, path, scope)
	}
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
			var validationErr error
			if validate := e.cfg.Events.ValidateDelegatedMutation; validate != nil {
				var snapshot Entry
				entry, present := e.entryLocked(path)
				if present {
					snapshot = *entry
				}
				validationErr = validate(ctx, path, snapshot, present)
			}
			allowed := true
			if allow := e.cfg.Events.AllowDelegatedMutation; allow != nil {
				allowed = allow(ctx, path)
			}
			if validationErr != nil || !allowed {
				// Claim this exact snapshot's grant before dropping e.mu. A
				// release+reacquire can therefore never replace the entry
				// between validation and the local mutation decision.
				attempt := e.prepareReleaseLocked(ctx, d)
				e.mu.Unlock()
				if err := e.waitReleaseForCaller(ctx, attempt); err != nil {
					return admission{}, false, err
				}
				return admission{}, false, validationErr
			}
			if d.scope == scope {
				d.lastActive = time.Now()
				return admission{d: d}, true, nil // e.mu stays held; caller releases
			}
			// The active grant is a strict ancestor of the mutation's exact
			// parent. Drain it before continuing so a long-running deep
			// workload never monopolizes a common ancestor shared with peer
			// writers. The next loop acquires the now-authoritative child
			// directory directly.
			attempt := e.prepareReleaseLocked(ctx, d)
			e.mu.Unlock()
			if err := e.waitReleaseForCaller(ctx, attempt); err != nil {
				return admission{}, false, err
			}
			continue
		}
		if d != nil {
			if err := d.drainErr; err != nil {
				e.mu.Unlock()
				return admission{}, false, err
			}
			attempt := d.attempt
			e.mu.Unlock()
			if err := e.waitReleaseForCaller(ctx, attempt); err != nil {
				return admission{}, false, err
			}
			// A release signal means only that the attempt reached a
			// definite outcome. Re-evaluate ownership before choosing local
			// admission, a typed failure, or write-through.
			continue
		}
		// Avoid acquiring a grant that an independently proven hard-link
		// identity cannot use. A concurrent in-flight grant resolver may still
		// install after this authority-lane decision; the authority's journaled
		// mutation gate orders the path-bearing write after that grant's recall.
		if allow := e.cfg.Events.AllowDelegatedMutation; allow != nil && !allow(ctx, path) {
			e.mu.Unlock()
			return admission{}, false, nil
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

// ErrLaneChanged reports that a frontend-resolved operation's lane no longer
// holds: the classifier proved a delegation at the mutation's exact scope
// OUTSIDE the frontend's locks, and by the time the operation reached the
// engine that grant was gone (recalled, released for idleness, or taken by an
// exact operation).
//
// It is not a failure and never reaches an application. It is the ONE answer
// the engine may give in that situation, because both alternatives are
// forbidden here: acquiring the grant again is a transition, and taking the
// authority lane requires releasing whatever now covers the path, which is a
// drain — and the caller is inside its namespace and handle locks, which is
// precisely where neither may happen. The frontend unwinds to the pre-lock
// point and reclassifies, paying any transition where it costs nothing.
var ErrLaneChanged = errors.New("writeback: resolved write lane changed; reclassify outside the frontend locks")

// PrepareDelegatedWrite resolves — OUTSIDE every frontend lock — whether a data
// mutation at path will take the delegated write-back lane, performing whatever
// delegation transition that answer requires: pushing an ancestor grant down
// (drain + durable release) so the exact scope can be held, or acquiring the
// exact scope outright.
//
// This is the pre-lock half of admit, and the reason it exists is the reason
// the credit gate is placed where it is. admit's transitions are the two
// genuinely unbounded steps in a write: a push-down drain ships the ancestor's
// whole unshipped tail through the uplink that is already behind, and an
// acquisition is an authority round trip. Taken under a frontend's namespace
// lock, either one converts a slow uplink into a namespace-wide stall — the
// writer-preferring RWMutex parks one pending rename or reclaim behind the
// paced writer and every subsequent lookup behind THAT. Taken here, holding
// nothing, they cost only the operation that asked for them.
//
// A true answer is a fact about a grant that was retained at the instant of the
// call, not a lease. The engine enforces the rest: a frontend-resolved
// operation that arrives to find that grant gone is answered ErrLaneChanged
// rather than being allowed to transition under the caller's locks.
func (e *Engine) PrepareDelegatedWrite(ctx context.Context, path string, n int64) (bool, error) {
	if e.cfg.DisableDelegation {
		return false, nil
	}
	if !e.Covers(path) && !e.credits.hasHeadroom(n) {
		// Nothing covers this path, so the write is write-through TODAY: it
		// consumes no stream budget, is charged nothing, and waits for nothing.
		// Acquiring a grant would change all three — it would convert a free
		// write into one that must be credit-admitted, and then pace it against
		// a backlog it has contributed nothing to and cannot help drain.
		//
		// A delegation is an OPTIMIZATION, and it is only an optimization while
		// the lane it moves work onto can actually take that work. When the lane
		// is full the honest answer is the one the write already had.
		return false, nil
	}
	adm, ok, err := e.admit(ctx, path)
	if err != nil || !ok {
		return false, err
	}
	e.release(adm)
	return true, nil
}

// admitResolved is admit for an operation whose lane was resolved outside the
// frontend's locks (see WithResolvedLane / PrepareDelegatedWrite).
//
// It is a PEEK and nothing else. It proceeds iff the exact grant the classifier
// proved is still retained and usable, and otherwise reports ErrLaneChanged. It
// never drains, never acquires, never releases and never waits: every one of
// those is a delegation transition, and by the time this runs the caller is
// inside the namespace and handle locks a rename, a remove or a delegation
// reclaim needs. Answering "authority lane" here would be no better — the
// authority lane requires releasing whatever covers the path, and that release
// is the drain this placement exists to keep out of the locked region.
//
// Caller holds nothing of the engine's; on success e.mu stays held exactly as
// admit's own success path leaves it.
func (e *Engine) admitResolved(ctx context.Context, path, scope string) (admission, bool, error) {
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
	if d == nil || d.draining || d.scope != scope {
		// No grant, a grant already handing off, or a grant at a different
		// scope than the one that was resolved. Each needs a transition to turn
		// into an answer, so none of them may be answered here.
		e.mu.Unlock()
		return admission{}, false, ErrLaneChanged
	}
	if validate := e.cfg.Events.ValidateDelegatedMutation; validate != nil {
		var snapshot Entry
		entry, present := e.entryLocked(path)
		if present {
			snapshot = *entry
		}
		if err := validate(ctx, path, snapshot, present); err != nil {
			// A refusal is a lane decision, and the lane it selects is the
			// authority's — which this operation cannot enter from in here.
			e.mu.Unlock()
			return admission{}, false, ErrLaneChanged
		}
	}
	if allow := e.cfg.Events.AllowDelegatedMutation; allow != nil && !allow(ctx, path) {
		e.mu.Unlock()
		return admission{}, false, ErrLaneChanged
	}
	d.lastActive = time.Now()
	return admission{d: d}, true, nil // e.mu stays held; caller releases
}

// admitAcross resolves local admission from primary for a mutation touching
// every path in touched. If primary selects the authority lane, all touched
// paths must leave delegated mode before the caller can issue that mutation:
// a destination-only delegation is just as exclusive as one covering the
// source. Errors never change lanes, so an indeterminate admission failure
// preserves the retained grants and fails the operation.
//
// A successful admission returns with e.mu held. The caller may then prove
// that every other operand is covered by the same delegation; if not, it
// uses fallThroughLocked to release all operands atomically with respect to
// local admission.
func (e *Engine) admitAcross(ctx context.Context, primary string, touched ...string) (admission, bool, error) {
	adm, ok, err := e.admit(ctx, primary)
	if ok || err != nil {
		return adm, ok, err
	}
	if resolvedLaneOf(ctx) != LaneUnresolved {
		// A classified operation is inside the frontend's namespace and handle
		// locks, and the classifier already released every operand out there
		// (PrepareDelegatedMutation resolves the authority lane across the whole
		// operand set, not just the primary). Releasing again here would be the
		// drain the classification exists to hoist out of the locked region.
		return admission{}, false, nil
	}
	if err := e.ReleaseFor(ctx, touched...); err != nil {
		return admission{}, false, err
	}
	return admission{}, false, nil
}

// PrepareDelegatedMutation is the NAMESPACE lane's pre-lock classifier: the
// exact analogue of PrepareDelegatedWrite for create/mkdir/symlink/rename/
// remove/setattr/truncate/xattr.
//
// The data plane has had this since the credit controller landed; the namespace
// plane had not, and that was the other half of the incident geometry. A
// metadata mutation reached Engine.admit with LaneUnresolved while the frontend
// held a.nsMu, and admit is allowed to do both unbounded things in there: push
// an ancestor grant down (drain its whole unshipped tail through the uplink that
// is already behind, then release it durably) or acquire a grant over an
// authority round trip. Under a writer-preferring RWMutex's read side either one
// parks the next rename, remove or reclaim and every lookup behind it.
//
// So the transition is paid HERE, holding nothing, and what crosses into the
// locked region is a decided lane:
//
//   - true: every operand is covered by ONE retained grant at the mutation's
//     exact scope. The caller records LaneDelegated; under the locks admit is a
//     peek and answers ErrLaneChanged if that grant is gone.
//   - false: the authority lane. The caller then takes its transition claim and
//     releases every operand — including the destination-only grant of a rename,
//     which is just as exclusive as one covering the source — before it takes a
//     frontend lock.
//
// It DECIDES and acquires; it never releases. The two halves are separated on
// purpose, and the order matters: an acquisition needs the acquire side of the
// transition gate, which conflicts with the authority claim the caller will
// hold, so a caller that claimed first and asked for a grant second would
// deadlock against itself. Decide here holding nothing, claim afterwards, and
// the authority lane's release happens under a claim no acquisition can slip
// past.
//
// primary is the operand whose governing scope decides the lane; touched is
// every other path the mutation binds. An operand set that cannot be served by
// a single grant is an authority-lane operation by construction: two grants
// cannot be made atomic with respect to one syscall.
func (e *Engine) PrepareDelegatedMutation(
	ctx context.Context,
	primary string,
	touched ...string,
) (bool, error) {
	if e == nil || e.cfg.DisableDelegation {
		return false, nil
	}
	adm, ok, err := e.admit(ctx, primary)
	if err != nil || !ok {
		return false, err
	}
	covered := true
	for _, p := range touched {
		if p == "" || p == primary {
			continue
		}
		if e.coveringLocked(p) != adm.d {
			covered = false
			break
		}
	}
	e.release(adm)
	return covered, nil
}

// release pairs with a successful admit.
func (e *Engine) release(admission) { e.mu.Unlock() }

// releaseForResolvedLane is ReleaseFor for a release discovered by a CLASSIFIED
// operation — one that reached the engine already inside the frontend's
// namespace, name and handle locks.
//
// The same rule as fallThroughLocked, and for the same reason: a release drains
// the covering grant's whole unshipped tail through an uplink that is already
// behind, and under a writer-preferring RWMutex's read side that parks the next
// rename, remove or reclaim and every reader behind it. So a classified
// operation is answered ErrLaneChanged, unwinds with every lock released, and
// pays for the release outside them. An unclassified caller holds nothing and
// pays for it here.
func (e *Engine) releaseForResolvedLane(ctx context.Context, paths ...string) error {
	if resolvedLaneOf(ctx) != LaneUnresolved {
		return ErrLaneChanged
	}
	return e.ReleaseFor(ctx, paths...)
}

// fallThroughLocked is the ONE escape from delegated mode: the engine
// cannot (or must not) acknowledge this mutation locally, so every
// delegation covering the touched paths drains and RELEASES before the
// caller executes write-through — a mutation never runs write-through
// inside a held delegation. Called with e.mu held; returns with it held.
func (e *Engine) fallThroughLocked(ctx context.Context, paths ...string) error {
	if resolvedLaneOf(ctx) != LaneUnresolved {
		// A classified operation is inside the frontend's namespace and handle
		// locks. This release IS the drain the pre-lock classifier exists to
		// hoist out of them — the same one, reached by a different route — so
		// it is refused here and paid for outside. e.mu stays held, as the
		// caller's contract requires.
		return ErrLaneChanged
	}
	e.mu.Unlock()
	err := e.ReleaseFor(ctx, paths...)
	e.mu.Lock()
	return err
}

// appendRecords encodes and appends one syscall's records all-or-nothing and
// registers them with the flusher. Caller holds e.mu.
//
// Admission is a reservation against the stream budget, taken by the WAL under
// its own mutex from the ENCODED records: the append is either refused before
// any byte is written, or it is guaranteed to fit. The engine never lets a
// mutation's own size carry the stream past the budget and into a PHYSICAL
// ENOSPC, which is not a refusal at all — it is a mid-append local WAL failure
// that fails the whole mount closed.
func (e *Engine) appendRecordsLocked(d *delegation, records []wal.Record) ([]appendResult, error) {
	return e.appendLaneLocked(d, records, laneMetadata)
}

// walLane selects which slice of the hard cap an append may consume.
//
// The cap is one number and stays one number; the lane only decides how much
// of it a given record class is allowed to reach. Bulk data reserves against
// dataBudgetBytes (cap minus the metadata reserve), so a data flood can never
// consume the last segment. Metadata reserves against the whole cap, so it
// always has that segment available and stays instant while data is paced.
// Nothing about ordering changes: both lanes append to the same dense stream
// in sequence order, and the flusher ships that stream untouched.
type walLane int

const (
	// laneMetadata is every namespace/attribute/control record: create, mkdir,
	// symlink, remove, rename, setattr, xattr — and truncate, whose record
	// carries no bulk bytes at all. Never credit-charged.
	laneMetadata walLane = iota
	// laneData is bulk file data (OpWrite payloads). Credit-charged.
	laneData
)

func (e *Engine) laneBudget(lane walLane) int64 {
	if lane == laneData {
		return e.dataBudgetBytes()
	}
	return e.cfg.BudgetBytes
}

// streamLaneLocked maps a record's BUDGET lane to its STREAM lane. Caller holds
// e.mu.
//
// The two are different questions with the same word. The budget lane asks "how
// much of the on-disk cap may this record consume"; the stream lane asks "which
// independently-applicable chain does the authority verify it in". They agree
// for bulk data and they usually agree for metadata, and the ONE case where they
// do not is the entire soundness argument for lane separation:
//
//	A NAMESPACE RECORD ADMITTED INTO A SCOPE THAT STILL HOLDS UNAPPLIED BULK
//	DATA GOES IN THE DATA LANE.
//
// Without that rule the split would not be order-preserving. `echo hi > f; rm f`
// admits a data record and then a namespace record on the same node; the
// namespace lane ships eagerly, so the remove would reach the authority before
// the write and the write would then apply to a path that no longer exists.
// Routing the remove into the data lane puts it AFTER the write in the only
// order that matters — the data lane's own — and costs nothing anywhere else,
// because a scope with unapplied bulk data was never going to release quickly
// anyway. Metadata-only scopes, which are the ones the interactive contract is
// about, never take this branch.
//
// The condition is a fact about applied state, not about shipping: "unapplied"
// means the authority has not made the data durable yet, so a namespace record
// entering the namespace lane while it is false can only apply after data the
// authority already holds. It is read under e.mu, and the count it reads only
// rises under e.mu (admission) and only falls under f.mu (an authority advance),
// so the answer cannot become stale in the direction that would matter.
func (e *Engine) streamLaneLocked(d *delegation, lane walLane) StreamLane {
	if !e.laned {
		return StreamLaneLegacy
	}
	if lane == laneData {
		return StreamLaneData
	}
	if d != nil && e.fl.scopeHasUnappliedData(d.scope) {
		return StreamLaneData
	}
	return StreamLaneNamespace
}

// openLanedEraLocked crosses the stream's lane boundary when it is safe to, and
// is a no-op otherwise. Caller holds e.mu.
//
// THE BOUNDARY, STATED EXACTLY. A stream is in the LEGACY era until the first
// laned mutation frame is appended; from that frame on it is in the LANED era
// and an unlaned mutation is refused outright (streamWAL.appendLaneMutations
// -Within). The boundary may be crossed only when BOTH hold:
//
//   - the authority advertises FeatureWritebackLanes, because a laned batch has
//     no legacy encoding and re-serializing the lanes onto one chain would
//     rebuild exactly the coupling lanes remove; and
//   - every unlaned record this stream ever wrote is authority-applied, so the
//     legacy chain is COMPLETE at the instant it freezes.
//
// The second condition is what makes a mixed WAL well-defined: the legacy
// prefix has no outstanding tail, so recovery replays legacy (nothing), then the
// namespace lane, then the data lane, and the two lanes each start from
// digestZero with nothing behind them. It also means the transitional cost is
// paid exactly once, at the first quiet moment after an upgrade, and is bounded
// by the legacy backlog that already existed.
//
// A fresh stream reaches it immediately: it has no unlaned record, so the very
// first mutation is laned.
func (e *Engine) openLanedEraLocked() {
	if e.laned || e.wal == nil || !e.remote.SupportsLanes() {
		return
	}
	lanes := e.wal.Lanes()
	if e.fl.laneApplied(StreamLaneLegacy) < lanes[StreamLaneLegacy].through {
		return // the legacy chain still has an unapplied tail
	}
	e.wal.markLaned()
	// Mirrored on the engine under e.mu so the per-append lane decision is a
	// plain field read: the boundary is crossed once and never uncrossed, so a
	// cached copy cannot go stale in the direction that matters.
	e.laned = true
}

func (e *Engine) appendLaneLocked(d *delegation, records []wal.Record, lane walLane) ([]appendResult, error) {
	if err := e.ensureStreamLocked(); err != nil {
		return nil, err
	}
	payloads := make([][]byte, len(records))
	for i := range records {
		p, err := wal.EncodePFR1(&records[i])
		if err != nil {
			return nil, err
		}
		payloads[i] = p
	}
	// Every admission is a chance to leave the legacy era: the condition is
	// "the legacy tail is applied", which becomes true at the first quiet
	// moment after an upgrade and can never become false again.
	e.openLanedEraLocked()
	budget := e.laneBudget(lane)
	stream := e.streamLaneLocked(d, lane)
	results, err := e.wal.appendLaneMutationsWithin(payloads, budget, stream)
	if errors.Is(err, ErrNoSpace) {
		// One relief pass: fold what the authority has applied and reclaim the
		// segments that frees, then re-offer the SAME reservation. Relief is
		// the only thing that can move this bound, and it either moved it or
		// the refusal is definite.
		e.relieveBudgetLocked()
		if merr := e.MutationError(); merr != nil {
			return nil, merr
		}
		results, err = e.wal.appendLaneMutationsWithin(payloads, budget, stream)
	}
	if errors.Is(err, ErrNoSpace) {
		// Nothing was written, so nothing is latched: the engine stays healthy
		// and keeps its delegations, and this exact mutation is admitted again
		// once the uplink applies the backlog.
		e.noteBudgetLocked()
		// ENOSPC is a DEFINITE claim — "a bounded local store is full and this
		// operation can never fit" — and it is the answer an application acts on
		// by deleting things. So the definite-size question is asked for EVERY
		// lane, not just the credit-gated one: whether an append could fit an
		// empty lane is a property of the append, and a lane whose budget is
		// merely occupied right now has not earned that errno.
		//
		// The two lanes then differ only in what a TRANSIENT full means for the
		// caller, because only one of them has a caller that can wait.
		cost, cerr := e.wal.maxAppendCost(payloads)
		transient := cerr == nil && cost <= budget
		switch {
		case !transient:
			// Larger than the lane at any occupancy: draining the entire stream
			// would still not make room. That is what ENOSPC means.
			return nil, ErrNoSpace
		case lane == laneData:
			// The credit gate's ledger counts payload bytes; the hard cap counts
			// framed on-disk bytes and whole unreclaimed segments, so the cap can
			// bind first for a shape the gate thought fit. Report it as missing
			// headroom so the caller paces on applied progress, exactly like a
			// credit wait.
			return nil, errDataHeadroom
		default:
			// A transient metadata-lane full. The metadata lane is bounded by the
			// whole cap and holds a reserve bulk data can never touch, so
			// reaching here means metadata itself outran the uplink — the store
			// is not permanently full and the very same operation is admitted
			// once the authority applies the backlog.
			//
			// It is therefore not ENOSPC, and it is not an EIO either: reporting
			// a dead far end for a link the watchdog considers healthy aborts
			// mkdir(2) on a mount that is working, and the only recovery left to
			// the application is a retry. It is also not a wait — pacing here
			// would be a wait taken under e.mu with a delegation held, and the
			// namespace lane's drain dependency is bounded precisely because it
			// never does that.
			//
			// So the engine says "not here": errMetadataHeadroom is an
			// ErrLaneChanged, the operation unwinds with every frontend lock
			// released, and it re-enters AdmitMetadataMutation outside them,
			// where the wait on applied progress is free and the ONLY stall
			// verdict is the watchdog's. See metadatacredit.go.
			return nil, errMetadataHeadroom
		}
	}
	if err != nil {
		return nil, e.failLocalWAL("append mutation", err)
	}
	for i := range results {
		records[i].Seq = results[i].seq
	}
	var dataBytes []int
	if lane == laneData {
		dataBytes = make([]int, len(records))
		for i := range records {
			dataBytes[i] = len(records[i].Data)
		}
	}
	e.fl.admit(d.scope, results, dataBytes)
	e.noteBudgetLocked()
	return results, nil
}

// walExhaustedLocked reports that the stream WAL leaves no headroom for the
// BULK-DATA lane, whose cap is the budget minus the metadata reserve. The
// metadata lane still has that reserve by construction, which is the whole
// point of the split. Caller holds e.mu.
func (e *Engine) walExhaustedLocked() bool {
	return e.wal != nil && e.wal.DiskBytes() >= e.dataBudgetBytes()
}

// relieveBudgetLocked folds authority-applied extents and reclaims fully
// applied segments, freeing WAL space without touching unshipped data.
// Reclamation happens only through the unified durable-checkpoint operation;
// a checkpoint failure relieves nothing (the caller then refuses admission).
func (e *Engine) relieveBudgetLocked() {
	mark := e.fl.appliedState()
	for _, fv := range e.files {
		fv.foldApplied(mark.global)
	}
	pins := map[uint64]bool{}
	for _, fv := range e.files {
		fv.segmentsPinned(pins)
	}
	if e.wal != nil {
		if err := e.wal.CheckpointAndReclaim(mark, func(ord uint64) bool { return pins[ord] }); err != nil {
			e.failLocalWAL("checkpoint", err)
			e.logf("writeback: budget-relief checkpoint at %d failed: %v", mark.global, err)
		}
	}
	e.noteBudgetLocked()
}

// noteBudgetLocked republishes the lock-free exhaustion mirror the data plane
// reads before admission. Caller holds e.mu.
func (e *Engine) noteBudgetLocked() {
	e.walFull.Store(e.walExhaustedLocked())
}

// ─── bounded-resource admission ──────────────────────────────────────────────
//
// Every locally-acknowledged data mutation consumes two bounded local
// resources: stream WAL bytes on disk, and extents in the file's overlay.
// Both are relieved by exactly one thing — the authority applying the
// unshipped tail. When either bound binds, the ONLY way the engine could keep
// accepting the mutation is to leave delegated mode, and leaving delegated
// mode means draining the tail through the uplink that is already behind.
// That drain is unbounded: production saw fsync-appending writers block inside
// it until the frontend's operation deadline expired and surfaced ETIMEDOUT,
// while every metadata and read operation queued behind those writers on the
// frontend's own shared per-attach and per-mount admission gates, and the
// kernel finally declared the whole volume dead. The engine therefore never
// drains to escape a bound.
//
// The OVERLAY bound stays a definite ENOSPC: an extent set at its hard bound
// is a local structural limit, and the operations that would grow it past it
// cannot be paced into fitting.
//
// The WAL-BYTES bound is no longer answered at the cliff. Instant ENOSPC at
// full was the emergency behaviour that kept a saturated mount alive; the
// credit gate (credit.go) replaces it with an admission RATE derived from the
// measured authority-applied rate. A data mutation now waits, bounded, for
// credit and completes paced on a slow-but-draining uplink; only an uplink the
// watchdog declares stalled produces an error (ErrUplinkStalled, EIO-class),
// and only an operation larger than the whole data lane produces ENOSPC.
// Metadata is never credit-charged and keeps its reserve, so it stays instant
// in every one of those states.

// spaceVerdict is the pre-admission decision for one data mutation.
type spaceVerdict int

const (
	// spaceProceed: the mutation has credit; admit normally.
	spaceProceed spaceVerdict = iota
	// spaceAuthority: credit is unavailable but nothing is delegated at this
	// path, so the mutation's lane consumes no stream budget at all. The
	// authority lane is selected WITHOUT a drain (there is no grant to
	// release), which keeps a saturated local store from failing write-through.
	spaceAuthority
	// spaceExhausted: a definite refusal (ENOSPC for an operation larger than
	// the lane, ErrUplinkStalled for a stalled authority, or a latched engine
	// failure). The error carries which.
	spaceExhausted
)

// admitDataBytes is the data plane's pre-lock admission for n bulk bytes. It
// runs BEFORE admit — and therefore before e.mu, before any grant acquisition
// and before any handle lock — so a paced writer never holds anything a recall,
// a barrier or a metadata mutation needs. The steady-state path is one atomic
// load and one CAS inside the credit gate.
//
// It returns the number of bytes the caller may write. A short grant is normal
// and becomes a POSIX short write; zero-with-nil-error never escapes here,
// because the engine's own contract for a slow link is a paced completion, so
// this loops until credit arrives, the uplink is declared stalled, or ctx ends.
func (e *Engine) admitDataBytes(ctx context.Context, path string, n int64) (int64, spaceVerdict, error) {
	if n <= 0 {
		return 0, spaceProceed, nil
	}
	if resolvedLaneOf(ctx) == LaneAuthority {
		// Classified outside the frontend's locks as authority-only: these bytes
		// will never become WAL bytes, so they are not charged against the
		// STREAM ledger and never queue behind delegated traffic.
		//
		// This is consulted BEFORE the credit fast path deliberately. The fast
		// path is one CAS and would happily succeed here, charging the stream
		// ledger for a write that cannot produce a single stream byte — a debt
		// only refundable from wherever clientcore's own lane routing happens to
		// end, and one that paces honest delegated writers in the meantime.
		// Charging the STREAM is a property of the lane, not of whether credit
		// happened to be free.
		//
		// It is NOT, however, a licence to be uncharged. The lane's own gate
		// (authoritycredit.go) has already charged these bytes in the pre-lock
		// classifier, and no door counts here: whichever decision routed this
		// write counted itself where it was made.
		return 0, spaceAuthority, nil
	}
	if e.credits.tryFast(n) {
		e.lanes.noteDelegated(n)
		return n, spaceProceed, nil
	}
	if err := e.MutationError(); err != nil {
		return 0, spaceExhausted, err
	}
	e.mu.Lock()
	lifecycle := e.closed || e.frozen
	covered := e.coveringLocked(path) != nil
	if !lifecycle && e.streamOpen && e.walExhaustedLocked() {
		// One relief pass before pacing: folding applied extents and reclaiming
		// the segments that frees is what the old fail-fast floor did, and it
		// can lift the hard bound immediately.
		e.relieveBudgetLocked()
	}
	e.mu.Unlock()
	if lifecycle {
		// Lifecycle verdicts belong to admit, which owns the single
		// "not accepting mutations" answer. Never pre-empt it here.
		return 0, spaceProceed, nil
	}
	if !covered {
		// No grant covers this path: write-through consumes no stream budget
		// and has no grant to release, so there is nothing to wait for HERE.
		// The lane's own gate still charges it — an unclassified caller (FUSE's
		// pre-lock pass, package tests) reaches this point without having
		// passed clientcore's classifier, and "nothing to wait for" must not
		// mean "nothing to account".
		e.lanes.note(DoorUncovered, n)
		return 0, spaceAuthority, nil
	}
	if resolvedLaneOf(ctx) == LaneDelegated {
		// A resolved delegated write reaches the gate only on a retry, and by
		// then it is inside the frontend's locks. Queueing here would move the
		// wait back under them — the one thing the pre-lock classifier exists to
		// prevent — so the lane is reported changed and the frontend reclassifies
		// where waiting is affordable.
		e.lanes.note(DoorLaneChanged, n)
		return 0, spaceExhausted, ErrLaneChanged
	}
	for {
		granted, err := e.credits.acquire(ctx, n)
		if err != nil {
			if granted > 0 {
				e.credits.refund(int64(granted))
			}
			return 0, spaceExhausted, err
		}
		if granted > 0 {
			e.lanes.noteDelegated(int64(granted))
			return int64(granted), spaceProceed, nil
		}
		// Zero credit with a healthy uplink: the link is simply slower than one
		// wait cap. Keep pacing — ctx bounds the total wait.
		if err := ctx.Err(); err != nil {
			return 0, spaceExhausted, err
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

// lookup answers a name resolution from the overlay. A draining delegation
// remains read-authoritative until Checkin completes and dropScopeStateLocked
// removes it under e.mu. Hiding its overlay earlier would expose the
// authority's pre-flush state after a mutation had already been acknowledged.
func (e *Engine) lookup(path string) (Entry, LookupResult) {
	if e.held.Load() == 0 {
		return Entry{}, LookupUndecided
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if path == "" {
		return Entry{}, LookupUndecided
	}
	d := e.coveringLocked(path)
	if d == nil {
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

// readdir serves dir's complete listing while the engine still holds the
// delegation, including its drain interval (see Lookup).
func (e *Engine) readdir(dir string) ([]Entry, bool) {
	if e.held.Load() == 0 {
		return nil, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(dir)
	if d == nil {
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

// mergeReaddir folds an authority listing through the overlay and seeds
// dir's complete children set under an active delegation, so later lookups,
// negative answers, and creates are local for the life of the grant. A dir
// without an active covering delegation has no overlay (every local ack is
// strictly inside a held scope, and release drops the scope's views), so the
// authority listing passes through unchanged.
func (e *Engine) mergeReaddir(dir string, authority []Entry) []Entry {
	e.mu.Lock()
	defer e.mu.Unlock()
	d := e.coveringLocked(dir)
	if d == nil {
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
func (e *Engine) Rename(ctx context.Context, oldp, newp string, onCommit func()) (Result, bool, error) {
	adm, ok, err := e.admitAcross(ctx, oldp, oldp, newp)
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
	// Publish frontend open-handle namespace bookkeeping before releasing
	// e.mu. A concurrent recall must not drain/apply this WAL rename and
	// snapshot the old handle path in the gap between engine return and the
	// caller's tracker update.
	if onCommit != nil {
		onCommit()
	}
	return Result{Entry: *stored}, true, nil
}

// WriteAt acknowledges a write locally. Writing never hydrates the base: the
// dirty range becomes WAL-backed extents over the (unfetched) base content.
func (e *Engine) WriteAt(ctx context.Context, path string, off int64, data []byte) (Result, bool, error) {
	if off < 0 {
		return Result{}, false, errors.New("writeback: negative write offset")
	}
	return e.pacedWrite(ctx, path, data, func(*fileView) int64 { return off })
}

// WriteAppend acknowledges an O_APPEND write at the locally-authoritative
// EOF (the exclusive delegation makes the local size exact).
func (e *Engine) WriteAppend(ctx context.Context, path string, data []byte) (Result, bool, error) {
	// The O_APPEND lane is the exact shape production saturated. It gets the
	// same pre-admission credit as a positional write: a saturated store paces
	// the writer against the measured uplink, never drains the tail that filled
	// it. EOF is resolved under the same e.mu that admits the append.
	return e.pacedWrite(ctx, path, data, func(fv *fileView) int64 { return fv.entry.Size })
}

// pacedWrite is the shared body of WriteAt/WriteAppend: acquire data credit
// outside every lock, write what was granted, and retry — paced on applied
// progress — when the hard cap (rather than the credit gate) was the binding
// constraint. `at` resolves the write offset under e.mu.
func (e *Engine) pacedWrite(ctx context.Context, path string, data []byte, at func(*fileView) int64) (Result, bool, error) {
	// THE CAPACITY GATE, ASKED WHERE "WRITE" IS THE OPERATION. The credit
	// controller is frozen under a capacity refusal and would answer this on its
	// own, but only for a write that actually consults it: a frontend that
	// acquired its credit BEFORE the refusal carries the grant on its ctx and
	// takes it below without asking the ledger anything. That grant is still
	// real credit and would still be spent, so a refused mount would keep
	// acknowledging bytes it has just been told the authority cannot hold.
	// Asking here makes ENOSPC the answer for every write, granted or not.
	if err := e.CapacityRefusal(); err != nil {
		return Result{}, true, err
	}
	want := int64(len(data))
	// A frontend that already took credit before its own locks passes it down;
	// consume that grant once instead of charging twice. TAKING it here (rather
	// than reading it) is what makes settlement exactly-once: whatever this
	// write does not remove stays on the ctx for the frontend's own reclaim, and
	// what it does remove is settled below by writeGranted.
	pre := takeDataCredit(ctx, want)
	havePre := pre > 0
	for {
		granted, verdict, err := want, spaceProceed, error(nil)
		if havePre {
			granted, havePre = pre, false
		} else {
			granted, verdict, err = e.admitDataBytes(ctx, path, want)
		}
		switch {
		case err != nil:
			return Result{}, true, err
		case verdict == spaceAuthority:
			return Result{}, false, nil
		}
		res, handled, err := e.writeGranted(ctx, path, data[:granted], granted, at)
		if !errors.Is(err, errDataHeadroom) {
			return res, handled, err
		}
		if records, _ := e.Pending(); records == 0 {
			// The hard cap refuses with NOTHING left unshipped: the authority
			// has applied everything and relief already reclaimed all it can.
			// No amount of waiting can free another byte, so the condition is
			// definite after all and gets the definite POSIX answer.
			return Result{}, true, ErrNoSpace
		}
		if resolvedLaneOf(ctx) != LaneUnresolved {
			// A classified operation is INSIDE its namespace and handle locks by
			// the time it gets here, and both remaining moves are forbidden in
			// there: waiting for applied progress is the namespace-wide stall,
			// and diverting to the authority lane means releasing the grant that
			// is holding these very bytes — a drain, taken under the same locks.
			//
			// The previous shape took that divert, which is exactly how a
			// frontend-granted write ended up draining a delegation under nsMu.
			// The lane is reported changed instead: the frontend unwinds, and
			// the reclassification pays for the release outside every lock. The
			// grant is already refunded by writeGranted above.
			e.lanes.note(DoorLaneChanged, want)
			return Result{}, true, ErrLaneChanged
		}
		// The credit gate said yes and the hard cap said not yet. Wait for the
		// one event that frees hard-cap headroom, then re-enter admission —
		// which re-checks delegation state, lifecycle and credit from scratch.
		if werr := e.credits.waitForApplied(ctx); werr != nil {
			return Result{}, true, werr
		}
	}
}

// writeGranted runs ONE admitted write attempt and settles its credit grant:
// every granted byte that does not become WAL bytes is refunded, after e.mu is
// released. This is what keeps a grant racing a reservation failure honest —
// the hard bound holds either way, and the ledger does not drift.
func (e *Engine) writeGranted(ctx context.Context, path string, data []byte, granted int64, at func(*fileView) int64) (res Result, handled bool, err error) {
	used := int64(0)
	defer func() { e.credits.refund(granted - used) }()
	adm, ok, aerr := e.admit(ctx, path)
	if !ok {
		return Result{}, false, aerr
	}
	defer e.release(adm)
	fv, ok := e.fileViewLocked(path)
	if !ok {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	res, handled, err = e.writeLocked(ctx, adm.d, path, fv, at(fv), data)
	if err == nil && handled {
		used = int64(len(data))
	}
	return res, handled, err
}

// fileExtentBoundBindsLocked reports that the mutation would leave fv's
// overlay past the hard bound, AFTER one relief pass. project returns the
// PROJECTED post-splice cardinality — what the overlay will actually hold once
// the mutation is applied — so the bound is charged for growth only. An
// overwrite that replaces existing extents and any shrinking truncate REDUCE
// the bounded resource; refusing those with ENOSPC would deny the application
// the very operations that free the resource it is out of. It is re-evaluated
// after relief because folding changes the extent set the projection runs over.
//
// Folding is the definitive relief: extents the authority has already applied
// are served by the authority now and are not local debt. If the bound still
// binds, every remaining extent is unshipped and only the uplink can free it —
// so the condition is definite and the caller answers ENOSPC rather than
// waiting. Caller holds e.mu.
func (e *Engine) fileExtentBoundBindsLocked(fv *fileView, project func() int) bool {
	if project() <= maxFileExtents {
		return false
	}
	e.relieveBudgetLocked()
	return project() > maxFileExtents
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
	// The exact ranges this write will splice, in the order the splice happens:
	// the hole extent that a write past EOF inserts first, then one range per
	// record.
	ranges := make([]extentRange, 0, len(records)+1)
	if uint64(off) > uint64(fv.entry.Size) {
		ranges = append(ranges, extentRange{start: uint64(fv.entry.Size), end: uint64(off)})
	}
	for i := range records {
		ranges = append(ranges, extentRange{
			start: uint64(records[i].Offset),
			end:   uint64(records[i].Offset) + uint64(len(records[i].Data)),
		})
	}
	if e.fileExtentBoundBindsLocked(fv, func() int { return projectedWriteExtents(fv.extents, ranges) }) {
		// Hard overlay bound: this write genuinely GROWS the extent set past
		// it. There is no spill, and the write-through escape would have to
		// drain the unshipped tail first — the very uplink that let the set
		// grow this far. Definite bounded-resource exhaustion: ENOSPC.
		return Result{}, true, ErrNoSpace
	}
	results, err := e.appendLaneLocked(d, records, laneData)
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
	// Truncate is a data-plane operation whose RECORD carries no bulk bytes: it
	// is one size word. It is therefore never credit-charged and rides the
	// metadata lane's budget, which also means a shrink or a truncate-to-zero —
	// the cheapest way an application can free the resource it is out of — is
	// never refused for want of space a data flood took. Its bounded resource
	// is the overlay extent set, checked below.
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	fv, ok := e.fileViewLocked(path)
	if !ok {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	// Only an EXTENDING truncate needs a slot (for its hole extent). A shrink
	// drops and clips extents and a truncate to zero clears them, so refusing
	// one at the bound would deny the application the cheapest way to free the
	// resource it is out of.
	if e.fileExtentBoundBindsLocked(fv, func() int {
		return projectedTruncateExtents(fv.extents, uint64(fv.entry.Size), uint64(size))
	}) {
		return Result{}, true, ErrNoSpace
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
	SetMode  bool
	Mode     uint32
	SetTime  bool
	MtimeMs  int64
	SetATime bool
	AtimeMs  int64
	SetUID   bool
	UID      uint32
	SetGID   bool
	GID      uint32
	// SetFlags marks a chflags(2) group. The engine never acknowledges one
	// locally (see Setattr): it releases the covering delegation and reports
	// unhandled so the caller writes it through to the authority, the only
	// place a flag word is durable. Flags rides along so the field pair stays
	// a single intent and a caller cannot express half of it.
	SetFlags bool
	Flags    uint32
}

// Setattr acknowledges chmod/chtimes/chown locally for a known entry.
//
// chflags is deliberately NOT in that list. The local WAL has an OpChflags
// record, but the delegated overlay has no way to make the change visible and
// exact-once through a handoff without the authority having stored it: only
// the authority persists BSD flags (fsproto FeatureFlagPersistence). Rather
// than acknowledge a change the next getattr under this same delegation would
// contradict, the engine releases the covering delegation and reports the
// request unhandled — the caller then applies it write-through. That is the
// CORRECT lane for chflags, not a degraded fallback.
func (e *Engine) Setattr(ctx context.Context, path string, req SetattrRequest) (Result, bool, error) {
	adm, ok, err := e.admit(ctx, path)
	if !ok {
		return Result{}, false, err
	}
	defer e.release(adm)
	if req.SetFlags {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	ent, present := e.entryLocked(path)
	if !present {
		return Result{}, false, e.fallThroughLocked(ctx, path)
	}
	var records []wal.Record
	if req.SetMode {
		records = append(records, wal.Record{Op: wal.OpChmod, Path: path, Mode: req.Mode})
	}
	if req.SetTime || req.SetATime {
		records = append(records, wal.Record{
			Op: wal.OpChtimes, Path: path,
			MtimeMs: req.MtimeMs, ChtimesKeepMtime: !req.SetTime,
			AtimeMs: req.AtimeMs, ChtimesSetAtime: req.SetATime,
		})
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
	if req.SetATime {
		ent.AtimeMs = req.AtimeMs
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

// getxattr answers from a complete delegated xattr view. Such a view exists
// only for an object born locally under the grant; existing authority
// objects stay read-through because the grant snapshot does not carry their
// xattr values.
func (e *Engine) getxattr(path, name string) ([]byte, LookupResult) {
	if e.held.Load() == 0 {
		return nil, LookupUndecided
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(path)
	if d == nil {
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

// listxattr returns the complete sorted name set for a locally-born object.
func (e *Engine) listxattr(path string) ([]string, bool) {
	if e.held.Load() == 0 {
		return nil, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(path)
	xv := e.xattrs[path]
	if d == nil || xv == nil {
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
		return false, e.releaseForResolvedLane(ctx, path)
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
		return false, e.releaseForResolvedLane(ctx, path)
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

// readAt composes a read from dirty extents over the base. handled=false
// means the file has no dirty state and the caller serves it normally.
// The extent snapshot pins its WAL segments, so a concurrent
// checkpoint+reclaim can never delete one mid-pread (no retry compensation).
func (e *Engine) readAt(path string, dst []byte, off int64, base BaseReader) (int, bool, error) {
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

// readlink serves a locally-known symlink target.
func (e *Engine) readlink(path string) (target string, kind string, ok bool) {
	if e.held.Load() == 0 {
		return "", "", false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.coveringLocked(path)
	if d == nil {
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
	return e.fl.drainAll(ctx, w)
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

// Pending reports the unshipped acknowledged backlog: the live stream's
// unshipped records PLUS every parked or contained recovery job's
// durable-but-unapplied remainder.
//
// The parked half is not a refinement. A forced unmount parks its undrained
// tail as a durable recovery job, and until that job actually replays, those
// bytes are acknowledged, on disk, and NOT at the authority — which is the
// definition of this number. Reading only the live flusher made a fresh attach
// over an unreplayed 156 MiB tail report zero pending, so every drain-to-zero
// check in the product answered "drained" over data that was in fact
// unrecoverable. A contained job's remainder keeps counting for the same
// reason, and stops only when an operator clears the containment.
func (e *Engine) Pending() (records int, bytes int64) {
	records, bytes = e.fl.pendingStats()
	jobRecords, jobBytes := e.recovery.unrecovered()
	return records + int(jobRecords), bytes + int64(jobBytes)
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
	// No new data admission, and every paced writer wakes now with a definite
	// outcome instead of sitting in the queue while the close drains.
	e.credits.freeze(ErrFenced)
	if w != nil {
		if err := w.Sync(); err != nil {
			e.thawAfterFailedClose()
			return e.failLocalWAL("clean-unmount sync", err)
		}
		if err := e.fl.drainAll(ctx, w); err != nil {
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
			var keepFrozen KeepWritebackFrozenError
			if errors.As(err, &keepFrozen) && keepFrozen.KeepWritebackFrozen() {
				return e.failClosed(err)
			}
			e.thawAfterFailedClose()
			return err
		}
	}
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	e.credits.seal(ErrFenced)
	e.authority.seal(ErrFenced)
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
	e.credits.thaw()
}

// ForceClose makes the WAL and recovery job durable and closes locally
// without releasing delegations. It returns the visible job ID.
//
// ── PARKING IS A PROMISE, SO IT IS PROVED BEFORE IT IS MADE ──────────────────
//
// A forced unmount tells the operator, in the product's own words, that the
// undrained tail "will be verified and replayed exactly on the next attach".
// That is a durability promise, and a promise made about bytes nobody has
// looked at is a guess. Before the marker that publishes it is written, this
// function replays the ENTIRE LOCAL HALF of the next attach's verification
// against the stream's own synced bytes: the applied certificates must be
// mutually consistent, every lane's chain must be rebuildable from the retained
// frames at both its applied watermark and its tail, and every unapplied record
// must have a covering delegation to ship under.
//
// If that verification fails, the park does NOT promise a replay. It records a
// DEFINITE unreplayable verdict instead and returns ErrParkNotReplayable, while
// still completing the local teardown — a forced unmount is invoked precisely
// because the mount must go away, so refusing to finish would leave the operator
// with a wedged mount AND a lie. The next attach then contains the stream (see
// recoveryRunner.contain) rather than latching on it.
//
// The verification is local-only, deliberately: a forced unmount is defined by
// the authority being unreachable or unresponsive. It therefore proves that the
// snapshot is INTERNALLY replayable, which is the whole of what this side owns.
// A divergence that only the authority can reveal still surfaces at the next
// attach as a typed conflict.
func (e *Engine) ForceClose(reason string) (string, error) {
	e.mu.Lock()
	e.frozen = true
	e.forcing = true
	w := e.wal
	job := e.job
	e.mu.Unlock()
	e.credits.seal(ErrFenced)
	e.authority.seal(ErrFenced)
	e.signalIdleStop()
	e.cancelCtx()
	e.fl.stop()
	e.idleWG.Wait()
	e.releaseWG.Wait()
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
	// Every byte this park is about is now on media, so the snapshot the next
	// attach will read is exactly the one that can be proved here.
	unreplayable := verifyParkedStreamReplayable(w.Dir())
	jobID := ""
	if job != nil {
		recs, bytes := e.fl.pendingStats()
		job.update(func(j *RecoveryJob) {
			j.State = JobForced
			j.AdmittedThrough = w.LastSeq()
			j.AppliedThrough = e.fl.appliedThrough()
			j.PendingRecords = uint64(recs)
			j.PendingBytes = uint64(bytes)
			// pendingStats is the sum of each lane's unshipped queue, so it is
			// already the per-lane set the next attach's replay selects and
			// reconciles against. Naming the basis is what makes that
			// reconciliation possible at all — see RecoveryJob.PendingBasis.
			j.PendingBasis = pendingBasisLane
			j.LastError = reason
			if unreplayable != nil {
				// NOT JobForced: a forced job says "replay me". This one is a
				// proof that replay is impossible, and the state must say so
				// from the moment it becomes durable — including across a crash
				// between here and the next attach.
				j.State = JobCorrupt
				j.LastError = fmt.Sprintf("%s: %v", reason, unreplayable)
			}
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
	if unreplayable != nil {
		// The teardown is complete and the verdict is durable. The error is the
		// operator-visible half: it must never be mistaken for a parked tail
		// that will come back.
		recs, bytes := e.fl.pendingStats()
		return jobID, fmt.Errorf(
			"%w: %d acknowledged record(s) / %d byte(s) will NOT be replayed on the next attach: %w",
			ErrParkNotReplayable, recs, bytes, unreplayable,
		)
	}
	return jobID, nil
}

// ErrParkNotReplayable is the definite verdict of a forced unmount whose
// undrained tail could not be parked as a replayable snapshot. The teardown
// still completed and the bytes are still durable; what is NOT true is the
// ordinary parking promise that the next attach will replay them.
var ErrParkNotReplayable = errors.New("writeback: the forced unmount could not park a replayable snapshot")

// verifyParkedStreamReplayable runs the local half of the next attach's replay
// verification over a synced stream directory. nil means the snapshot is
// replayable by construction as far as this side can prove.
//
// It is the same evidence recoverStream demands, in the same order, and it is
// deliberately a separate reader over the on-disk bytes rather than a check
// against the engine's in-memory state: the in-memory state is what WROTE the
// stream, so agreeing with it proves nothing about whether a fresh process can
// read it back.
func verifyParkedStreamReplayable(dir string) error {
	if dir == "" {
		return nil
	}
	scan, err := scanStreamReadOnly(dir)
	if err != nil {
		return err
	}
	live, mutations, marks, _, err := decodeStreamFrames(scan.frames)
	if err != nil {
		return err
	}
	cert, err := highestAppliedCertificate(marks, scan.lastSeq)
	if err != nil {
		return err
	}
	tails := laneTails(scan, cert)
	for lane := range cert.lanes {
		l := StreamLane(lane)
		if cert.lanes[lane].through > tails[lane] {
			return fmt.Errorf("%w: applied %s-lane watermark %d is past the local tail %d",
				ErrCorrupt, l, cert.lanes[lane].through, tails[lane])
		}
		// The base recovery chains from, and the tail it chains to. A lane whose
		// digest cannot be rebuilt at either point cannot be replayed, and the
		// only moment that is cheap to discover is now.
		if _, err := laneDigestAt(scan, marks, l, cert.lanes[lane].through); err != nil {
			return err
		}
		if _, err := laneDigestAt(scan, marks, l, tails[lane]); err != nil {
			return err
		}
	}
	pos := streamMark{global: cert.global, lanes: cert.lanes}
	tail := laneTailFrames(mutations, pos)
	// The park promises the next attach will replay this tail EXACTLY. A tail
	// that is not a dense per-lane run from the verified base cannot be replayed
	// exactly by anyone — the missing records are already gone — so promising it
	// would be the lie this check exists to refuse. Proving it here also means
	// the operator learns at unmount time, when they are still present, rather
	// than at the next attach.
	if err := verifyTailPrefixConsistent(tail, pos, tails); err != nil {
		return err
	}
	if len(tail) == 0 {
		return nil
	}
	if len(live) == 0 {
		return fmt.Errorf("%w: unshipped tail without a recorded delegation", ErrCorrupt)
	}
	for _, fr := range tail {
		if _, err := wal.DecodePFR1(fr.payload); err != nil {
			return fmt.Errorf("%w: unshipped record %d does not decode: %v", ErrCorrupt, fr.seq, err)
		}
		if coveringScope(live, decodePathOf(fr)) == "" {
			return fmt.Errorf("%w: unshipped record %d has no covering delegation", ErrCorrupt, fr.seq)
		}
	}
	return nil
}

// Abandon simulates a process crash for tests: background work stops and the
// store lock releases, but nothing drains, releases, or writes CLOSE frames —
// the stream stays exactly as a kill -9 would leave it (modulo the OS page
// cache, which in-process tests cannot drop).
func (e *Engine) Abandon() {
	e.mu.Lock()
	e.frozen = true
	e.closed = true
	e.forcing = true
	w := e.wal
	e.mu.Unlock()
	e.credits.seal(ErrFenced)
	e.authority.seal(ErrFenced)
	e.signalIdleStop()
	e.cancelCtx()
	e.fl.stop()
	e.idleWG.Wait()
	e.releaseWG.Wait()
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
	// Drain-time credit control (see credit.go). CreditSetpoint is the
	// adapted operating limit on resident unapplied bulk data, CreditDebt is
	// how much of it is outstanding, CreditCeiling is the data lane's hard cap,
	// AppliedRateBps is the measured authority-applied rate the setpoint is
	// derived from, and CreditWaiters is how many data mutations are currently
	// paced (holding no locks).
	CreditSetpoint int64
	CreditDebt     int64
	CreditCeiling  int64
	AppliedRateBps float64
	CreditWaiters  int
	// DataLaneFull reports the bulk-data lane sitting at its hard cap while the
	// metadata reserve still holds.
	DataLaneFull bool
	// CapacityRefused reports a live capacity verdict from the AUTHORITY: a
	// bounded store over there is full, so this mount refuses new bytes with
	// ENOSPC while reads, metadata and releasing truncates keep working. It is
	// deliberately distinct from Degraded (a far end that stopped answering) and
	// from a terminal park: it clears by itself when the authority releases.
	CapacityRefused bool
	Jobs            []RecoveryJob
	// UnrecoveredRecords/UnrecoveredBytes are the share of PendingRecords/
	// PendingBytes that belongs to PARKED or CONTAINED recovery jobs rather
	// than to the live stream: acknowledged, locally durable, and not at the
	// authority. They are reported separately because the two halves need
	// different actions — the live half drains on its own, this half does not.
	//
	// CreditDebt above is deliberately NOT summed with these. It is the data
	// lane's PACING gauge (resident unapplied bulk bytes admitted by THIS
	// engine, bounded by CreditSetpoint), not a durability-debt figure, and a
	// previous mount's parked tail is not something this engine's controller
	// can pace. The durability-debt figure — the one a drain-completeness check
	// must read — is PendingBytes.
	UnrecoveredRecords uint64
	UnrecoveredBytes   uint64

	// Authority is the OTHER lane's durability accounting (authoritycredit.go).
	//
	// It is reported beside PendingBytes rather than folded into it because the
	// two are different obligations with different owners: PendingBytes is
	// acknowledged data THIS mount holds locally and will replay, and
	// Authority.Unproven is acknowledged data the FAR END holds and has not
	// proven. A drain-completeness check must read both — a mount that has
	// drained its WAL to zero while the authority lane holds unproven
	// acknowledged bytes has not finished, and reporting only the first is the
	// drain-success lie that let 734 MiB disappear with every local check
	// green.
	Authority AuthorityLedger
	// Routing is the lane-routing tally (lanerouting.go): which door each write
	// took onto the authority lane, and how many bytes went through it.
	Routing LaneRouting
}

// DelegationStatus is one held scope's view.
type DelegationStatus struct {
	Scope string
	Epoch string
	// Draining means a release attempt is IN FLIGHT — still waiting on the
	// authority, with no verdict yet. It is deliberately false once DrainError
	// is set: a scope whose attempt reached a definite outcome is not draining,
	// it is FAILED, and the difference is the whole point. A scope reported as
	// draining forever is the wedge shape (delegation.go, finishRelease); a
	// scope reported as failed carries a reason, refuses new mutations with that
	// reason instead of parking them, and can be retried or force-detached.
	Draining bool
	// DrainError is the recorded verdict of the last release attempt, empty when
	// there is none. ErrUplinkStalled here means the flusher's watchdog declared
	// the far end dead while this scope's drain was outstanding.
	DrainError string
}

func (e *Engine) Status() Status {
	st := e.fl.status()
	if err := e.MutationError(); err != nil {
		st.Degraded = true
		st.LastFailure = err.Error()
	}
	st.WALBudget = e.cfg.BudgetBytes
	st.CreditSetpoint, st.CreditDebt, st.CreditCeiling, st.AppliedRateBps, st.CreditWaiters = e.credits.status()
	st.DataLaneFull = e.walFull.Load()
	st.Authority = e.AuthorityLedgerStatus()
	st.Routing = e.lanes.snapshot()
	e.mu.RLock()
	if e.wal != nil {
		st.AdmittedThrough = e.wal.LastSeq()
		st.WALBytes = e.wal.DiskBytes()
	}
	for _, d := range e.delegations {
		view := DelegationStatus{
			Scope:    d.scope,
			Epoch:    d.epoch,
			Draining: d.draining && d.drainErr == nil,
		}
		if d.drainErr != nil {
			view.DrainError = d.drainErr.Error()
		}
		st.Delegations = append(st.Delegations, view)
	}
	e.mu.RUnlock()
	sort.Slice(st.Delegations, func(i, j int) bool { return st.Delegations[i].Scope < st.Delegations[j].Scope })
	st.Jobs = e.recovery.jobs()
	// Fold the parked/contained debt into the reported backlog for the reason
	// stated on Engine.Pending: a status that reports zero pending while
	// acknowledged bytes sit unreplayed is the drain-success lie this round
	// exists to remove.
	st.UnrecoveredRecords, st.UnrecoveredBytes = e.recovery.unrecovered()
	st.PendingRecords += int(st.UnrecoveredRecords)
	st.PendingBytes += int64(st.UnrecoveredBytes)
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
