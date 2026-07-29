package portablefsd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/confinedfs"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

const (
	defaultDiskCacheMB = 4096
	localItemIDMarker  = uint64(1) << 63
)

type Config struct {
	FrontendSocket   string
	ControlSocket    string
	StateDir         string
	Version          string
	ExecutableSHA256 string
}

type Server struct {
	cfg      Config
	registry *registry
	stopCh   chan struct{}
	stopOnce sync.Once

	frontendLnMu sync.Mutex
	controlLnMu  sync.Mutex
}

func NewServer(cfg Config) *Server {
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.ExecutableSHA256 == "" {
		cfg.ExecutableSHA256, _ = daemonctl.CurrentExecutableSHA256()
	}
	return &Server{
		cfg:      cfg,
		registry: newRegistry(cfg.StateDir),
		stopCh:   make(chan struct{}),
	}
}

type AttachOptions struct {
	Prefetch     bool   `json:"prefetch"`
	DiskCacheDir string `json:"diskCacheDir"`
	DiskCacheMB  int64  `json:"diskCacheMb"`
	// NegativeCache forces the negative dentry cache on; NoNegativeCache
	// forces it off. Neither set = capability-auto (on iff the authority
	// advertises ParentVersion stamping in the handshake).
	NegativeCache   bool `json:"negativeCache"`
	NoNegativeCache bool `json:"noNegativeCache,omitempty"`
	// LocalDirs graft machine-local subtrees over the volume namespace (see
	// localdirs.go). Workspace-relative directory paths.
	LocalDirs       []string `json:"localDirs,omitempty"`
	VolumeLocalDirs bool     `json:"volumeLocalDirs,omitempty"`
}

type ensureAttachRequest struct {
	VolumeID     string        `json:"volumeId"`
	Branch       string        `json:"branch"`
	AuthorityURL string        `json:"authorityUrl"`
	AuthToken    string        `json:"authToken"`
	TLSCAPEM     string        `json:"tlsCaPem"`
	MountPath    string        `json:"mountPath"`
	Options      AttachOptions `json:"options"`
}

type attachStatus struct {
	AttachRef  string           `json:"attachRef"`
	VolumeID   string           `json:"volumeId"`
	Branch     string           `json:"branch"`
	MountPath  string           `json:"mountPath"`
	State      string           `json:"state"`
	Prefetch   prefetchStatus   `json:"prefetch"`
	Cache      cacheStatus      `json:"cache"`
	LastError  string           `json:"lastError,omitempty"`
	VolumeName string           `json:"volumeName,omitempty"`
	LocalDirs  []string         `json:"localDirs,omitempty"`
	WriteBack  *writeBackStatus `json:"writeBack,omitempty"`
}

// writeBackStatus is the durability-debt view of an attach: the engine's
// full health snapshot — the unshipped acknowledged backlog, the sticky
// degraded verdict, the held delegations, and every parked stream the
// recovery machinery or an operator must still resolve.
type writeBackStatus struct {
	PendingRecords  int              `json:"pendingRecords"`
	PendingBytes    int64            `json:"pendingBytes"`
	AppliedThrough  uint64           `json:"appliedThrough,omitempty"`
	AdmittedThrough uint64           `json:"admittedThrough,omitempty"`
	OldestPendingMs int64            `json:"oldestPendingMs,omitempty"`
	Degraded        bool             `json:"degraded,omitempty"`
	LastFailure     string           `json:"lastFailure,omitempty"`
	Delegations     []delegationView `json:"delegations"`
	WALBytes        int64            `json:"walBytes,omitempty"`
	Jobs            []recoveryJobRef `json:"jobs,omitempty"`
	// ParkedWALs keeps the doctor/mounts wire name for parked recovery
	// state: one entry per parked stream.
	ParkedWALs []parkedWAL `json:"parkedWals,omitempty"`
}

type delegationView struct {
	Scope    string `json:"scope"`
	Draining bool   `json:"draining,omitempty"`
}

type recoveryJobRef struct {
	JobID     string `json:"jobId"`
	State     string `json:"state"`
	Records   uint64 `json:"records"`
	Bytes     uint64 `json:"bytes"`
	LastError string `json:"lastError,omitempty"`
}

type parkedWAL struct {
	WAL          string `json:"wal"`
	Root         string `json:"root,omitempty"`
	Records      int    `json:"records"`
	PayloadBytes int64  `json:"payloadBytes"`
	AgeMs        int64  `json:"ageMs"`
	LastError    string `json:"lastError,omitempty"`
	NextRetryMs  int64  `json:"nextRetryMs"`
}

type prefetchStatus struct {
	Done          bool  `json:"done"`
	EntriesWalked int64 `json:"entriesWalked"`
}

type cacheStatus struct {
	AttrEntries  int   `json:"attrEntries"`
	DiskBytes    int64 `json:"diskBytes"`
	DiskCapBytes int64 `json:"diskCapBytes"`
}

type registry struct {
	mu        sync.RWMutex
	persistMu sync.Mutex
	stateDir  string
	byRef     map[string]*attach
	byKey     map[string]*attach
	quiescing bool

	// Debounced background persistence for the per-file identity bindings.
	// Namespace mutations must never block on (or fail with) state-file I/O:
	// the synchronous persist-per-op this replaces rewrote and fsynced the
	// FULL state file — every attach's whole item table — inside each create/
	// remove/rename, an O(items) cost that grew quadratically over a workload
	// like git clone. Losing a binding from the final debounce window in a
	// daemon crash costs one ESTALE re-lookup after restart (open handles
	// never survive a crash anyway); membership changes and clean shutdown
	// still persist synchronously.
	persistReq  chan struct{}
	persistStop chan struct{}
	persistDone chan struct{}
	stopOnce    sync.Once

	// journal records binding deltas between full-state persists (see
	// bindingjournal.go). Ops append to it via attach.flushBindingDelta
	// before replying; persist() compacts it away.
	journal *bindingJournal
}

func newRegistry(stateDir string) *registry {
	r := &registry{
		stateDir:    stateDir,
		byRef:       map[string]*attach{},
		byKey:       map[string]*attach{},
		persistReq:  make(chan struct{}, 1),
		persistStop: make(chan struct{}),
		persistDone: make(chan struct{}),
		journal:     newBindingJournal(stateDir),
	}
	go r.persistLoop()
	persisted := loadPersistedAttaches(stateDir)
	seenStorage := map[string]string{}
	for _, e := range persisted {
		req := ensureAttachRequest{
			VolumeID:     e.VolumeID,
			Branch:       e.Branch,
			AuthorityURL: e.AuthorityURL,
			TLSCAPEM:     e.TLSCAPEM,
			MountPath:    e.MountPath,
			Options:      e.Options,
		}
		key := attachKey(req.VolumeID, req.Branch, req.MountPath)
		if r.byRef[e.Ref] != nil {
			log.Printf("portablefsd: skipping duplicate persisted attach ref %q", e.Ref)
			continue
		}
		if r.byKey[key] != nil {
			log.Printf("portablefsd: skipping duplicate persisted attach key volumeId=%q branch=%q mountPath=%q", req.VolumeID, req.Branch, req.MountPath)
			continue
		}
		if prior := seenStorage[storageKey(req.VolumeID, req.Branch)]; prior != "" {
			// One (volume, branch) = one WAL store = one checkout owner:
			// reviving two attaches of the same branch would corrupt it.
			log.Printf("portablefsd: skipping persisted attach at %q: volume %s@%s already revives at %q (one attach per branch)", req.MountPath, req.VolumeID, req.Branch, prior)
			continue
		}
		seenStorage[storageKey(req.VolumeID, req.Branch)] = req.MountPath
		a := newRevivedAttach(e.Ref, key, req, stateDir, e.IdentityEpoch, e.Items)
		a.persist = r.persist
		a.schedulePersist = r.schedulePersist
		a.journal = r.journal
		r.byRef[e.Ref] = a
		r.byKey[key] = a
	}
	// Stamp identity onto legacy mount-path-keyed WAL dirs while the mapping
	// is still derivable from the persisted attach entries — after that, an
	// attach of the same (volume, branch) adopts them from ANY mount path.
	for _, e := range persisted {
		legacy := filepath.Join(stateDir, "wal", stableStorageID(attachKey(e.VolumeID, e.Branch, e.MountPath)))
		if _, err := os.Stat(legacy); err == nil {
			writeWALIdentity(legacy, walIdentity{VolumeID: e.VolumeID, Branch: e.Branch})
		}
	}
	// One pass over the WAL root: drop fully-drained logs, report anything
	// that can never recover (never delete records), leave adoptable dirs for
	// their attach's next start.
	sweepWALRoot(stateDir, persisted)
	// Replay binding deltas the previous process journaled after its last
	// full persist, then drop the entries the replay itself buffered (they
	// are already durable in the journal being replayed).
	for _, e := range loadBindingJournal(stateDir) {
		if a := r.byRef[e.Ref]; a != nil {
			a.applyJournalEntry(e)
		}
	}
	for _, a := range r.byRef {
		a.mu.Lock()
		a.pendingBindings = nil
		a.mu.Unlock()
	}
	return r
}

// persistDebounce bounds how stale the persisted identity bindings may be
// while mutations are in flight. Small enough that a crash forgets at most a
// blink of just-created bindings; large enough to absorb a burst (a git
// checkout's thousands of creates) into a handful of full-state writes.
const persistDebounce = 100 * time.Millisecond

// schedulePersist marks the persisted state dirty; the persister loop writes
// it out after the debounce window. Never blocks.
func (r *registry) schedulePersist() {
	select {
	case r.persistReq <- struct{}{}:
	default:
	}
}

func (r *registry) persistLoop() {
	defer close(r.persistDone)
	for {
		select {
		case <-r.persistStop:
			return
		case <-r.persistReq:
		}
		timer := time.NewTimer(persistDebounce)
		select {
		case <-r.persistStop:
			timer.Stop()
			return // closeAll owns the final synchronous persist
		case <-timer.C:
		}
		// Absorb marks that arrived during the debounce: this write covers them.
		select {
		case <-r.persistReq:
		default:
		}
		if err := r.persist(); err != nil {
			// The mounts keep serving (volume data lives on the authority);
			// only restart identity is at risk, so scream but do not fail I/O.
			log.Printf("portablefsd: deferred state persist FAILED (item identity may not survive a daemon restart): %v", err)
		}
	}
}

// stopPersister halts the background persister; callers then run one final
// synchronous persist so the state file reflects the terminal item tables.
func (r *registry) stopPersister() {
	r.stopOnce.Do(func() { close(r.persistStop) })
	<-r.persistDone
}

func (r *registry) ensure(ctx context.Context, req ensureAttachRequest) (*attach, bool, error) {
	if req.VolumeID == "" || req.Branch == "" || req.AuthorityURL == "" || req.MountPath == "" {
		return nil, false, fmt.Errorf("volumeId, branch, authorityUrl, and mountPath are required")
	}
	requestedLocalDirs, err := normalizeLocalDirs(req.Options.LocalDirs)
	if err != nil {
		return nil, false, err
	}
	req.Options.LocalDirs = requestedLocalDirs
	key := attachKey(req.VolumeID, req.Branch, req.MountPath)
	r.mu.Lock()
	if r.quiescing {
		r.mu.Unlock()
		return nil, false, fmt.Errorf("portablefsd is quiescing for an idle stop; new attaches are refused")
	}
	if a := r.byKey[key]; a != nil {
		r.mu.Unlock()
		// A revived attach has not opened its Volume yet, so resolve the
		// current mount's --no-local/volume-config choice before start reads
		// .portablefs/local-dirs. Active attaches keep their established
		// routing table; ensure remains idempotent and only adds explicit
		// grafts below.
		if err := a.activateWithOptions(ctx, req.AuthToken, &req.Options); err != nil {
			return a, false, err
		}
		// Ensure is idempotent and additive for grafts: re-attaching with
		// more localDirs extends the live attach (addLocalDirs persists).
		if len(requestedLocalDirs) > 0 {
			if _, err := a.addLocalDirs(requestedLocalDirs); err != nil {
				return a, false, err
			}
		}
		if err := r.persist(); err != nil {
			return a, false, err
		}
		return a, false, nil
	}
	// Storage identity is (volume, branch): two LIVE attaches of one branch
	// would share one WAL store and one checkout owner — refuse the second
	// instead of corrupting the first's write-back state. A DORMANT revived
	// attach (never activated in this daemon lifetime) is the remount-at-a-
	// new-path flow: evict it so the new attach inherits the storage.
	for ref, other := range r.byRef {
		if other.key == key || other.isDetached() ||
			other.volumeID != req.VolumeID || other.branch != req.Branch {
			continue
		}
		if other.hasLiveVolume() {
			r.mu.Unlock()
			return nil, false, fmt.Errorf("volume %s@%s is already attached at %s; concurrent attaches of one branch are not supported", req.VolumeID, req.Branch, other.mountPath)
		}
		log.Printf("portablefsd: attach at %q supersedes the dormant persisted attach of %s@%s at %q", req.MountPath, req.VolumeID, req.Branch, other.mountPath)
		delete(r.byRef, ref)
		delete(r.byKey, other.key)
	}
	ref, err := randomAttachRef()
	if err != nil {
		r.mu.Unlock()
		return nil, false, err
	}
	a := newAttach(ref, key, req, r.stateDir)
	a.persist = r.persist
	a.schedulePersist = r.schedulePersist
	a.journal = r.journal
	r.byRef[ref] = a
	r.byKey[key] = a
	r.mu.Unlock()
	if err := a.activate(ctx, req.AuthToken); err != nil {
		r.mu.Lock()
		delete(r.byRef, ref)
		delete(r.byKey, key)
		r.mu.Unlock()
		return nil, false, err
	}
	if err := r.persist(); err != nil {
		r.mu.Lock()
		delete(r.byRef, ref)
		delete(r.byKey, key)
		r.mu.Unlock()
		_, _ = a.detach(ctx, true) // fresh attach: nothing written yet, the persist error dominates
		return nil, false, err
	}
	return a, true, nil
}

// quiesceIfIdle atomically closes attach admission and proves that no live
// Volume exists. Credential-pending entries revived from disk are durable
// restart metadata, not active mounts: they hold no WAL handles, sessions, or
// frontend service and therefore must not permanently block a clean daemon
// stop or binary upgrade.
func (r *registry) quiesceIfIdle() (bool, int, error) {
	r.mu.Lock()
	if r.quiescing {
		r.mu.Unlock()
		return true, 0, nil
	}
	liveCount := 0
	for _, a := range r.byRef {
		if a.hasLiveVolume() {
			liveCount++
		}
	}
	if liveCount != 0 {
		r.mu.Unlock()
		return false, liveCount, nil
	}
	r.quiescing = true
	r.mu.Unlock()

	if err := r.persist(); err != nil {
		r.mu.Lock()
		r.quiescing = false
		r.mu.Unlock()
		return false, 0, fmt.Errorf("persist final idle state: %w", err)
	}
	return true, 0, nil
}

func (r *registry) get(ref string) *attach {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byRef[ref]
}

func (r *registry) list() []*attach {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*attach, 0, len(r.byRef))
	for _, a := range r.byRef {
		out = append(out, a)
	}
	return out
}

// delete detaches ref. A NORMAL delete runs the full drain barrier first and
// FAILS — with the attach fully alive and registered — when the tail cannot
// reach the authority; only an explicit force detaches with an unshipped
// tail, parking it as a durable recovery job whose ID is returned.
func (r *registry) delete(ctx context.Context, ref string, force bool) (found bool, jobID string, err error) {
	r.mu.RLock()
	a := r.byRef[ref]
	r.mu.RUnlock()
	if a == nil {
		return false, "", nil
	}
	jobID, err = a.detach(ctx, force)
	if err != nil && !force {
		// The drain failed: the attach keeps serving; nothing unregisters.
		return true, "", err
	}
	r.mu.Lock()
	delete(r.byRef, ref)
	delete(r.byKey, a.key)
	r.mu.Unlock()
	if perr := r.persist(); perr != nil && err == nil {
		err = perr
	}
	return true, jobID, err
}

// closeAll is the cooperative daemon-termination path. Every attach must pass
// its normal authority durability barrier. A failed drain remains a visible
// shutdown failure; this path never changes semantics by force-detaching or
// parking a recovery job.
func (r *registry) closeAll(ctx context.Context) error {
	r.stopPersister()
	var shutdownErrs []error
	for _, a := range r.list() {
		if _, err := a.detach(ctx, false); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("detach %s: %w", a.ref, err))
		}
	}
	// The identity bindings created since the last debounce tick — and the
	// restart-identity contract itself — ride on this final write.
	if err := r.persist(); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("final state persist: %w", err))
	}
	return errors.Join(shutdownErrs...)
}

type attach struct {
	ref           string
	key           string
	volumeID      string
	branch        string
	authorityURL  string
	authorityAddr string
	tlsCAPEM      string
	mountPath     string
	volumeName    string
	storageID     string
	options       AttachOptions
	stateDir      string
	identityEpoch uint64
	persist       func() error
	// schedulePersist requests a debounced background persist. Per-file
	// namespace mutations use it instead of persist: they must never block
	// on, or fail with, state-file I/O.
	schedulePersist func()
	// journal receives binding deltas (see bindingjournal.go); pendingBindings
	// buffers them under a.mu until flushBindingDelta drains to the journal.
	journal         *bindingJournal
	pendingBindings []bindingJournalEntry
	// coherence state for remote content changes (see coherence_refresh.go):
	// purging tracks the paths with a refresh worker in flight and
	// refreshAgain the ones that took another invalidation meanwhile (the
	// worker must run one more pass so the final pass observes the settled
	// state); expectedTruncates marks the kernel-size refresh truncates the
	// daemon itself issues through the mount so the setattr handler can
	// consume them without touching the authority.
	purging           map[string]bool
	refreshAgain      map[string]bool
	expectedTruncates map[string]expectedTruncate

	credMu sync.RWMutex
	token  string

	startMu sync.Mutex

	mu                sync.RWMutex
	nsMu              sync.RWMutex
	nameLocks         [64]sync.Mutex
	vol               *clientcore.Volume
	eventClient       *fsproto.Client
	state             pfslocal.AttachStateState
	lastErr           string
	credentialPending bool
	root              *itemRecord
	items             map[uint64]*itemRecord
	paths             map[string]*itemRecord
	handles           map[uint64]*handleRecord
	enumRecords       map[uint64]*enumerationRecord
	localDirs         []string
	localRoot         string
	localFS           *confinedfs.Root
	localVersions     map[string]uint64
	// legacyParked lists adopted pre-v5 session WALs whose unresolved replay
	// blocks attach readiness (see legacydrain.go); merged into status
	// ParkedWALs for dormant/revived attaches.
	legacyParked []parkedWAL
	nextHandle   uint64
	nextEnumID   uint64
	nextOrigin   uint64
	subscribers  map[*eventSubscriber]struct{}
	conns        map[interface{ Close() error }]struct{}
	eventReady   chan struct{}
	eventOnce    sync.Once
	detached     bool

	// Test seam for deterministic frontend ordering tests; nil in production.
	testLookupAfterVolume func(path string)
}

type itemRecord struct {
	item  pfslocal.Item
	path  string
	state *clientcore.NodeState
	attr  fsproto.Attr
}

type handleRecord struct {
	id       uint64
	path     string
	openPath string
	state    *clientcore.NodeState
	write    bool
	// file backs handles for grafted local paths; nil for authority handles.
	file *os.File
}

type eventSubscriber struct {
	origin uint64
	ch     chan pfslocal.Event
}

func newAttach(ref, key string, req ensureAttachRequest, stateDir string) *attach {
	name := req.VolumeID
	if req.Branch != "" {
		name += "@" + req.Branch
	}
	localDirs, err := normalizeLocalDirs(req.Options.LocalDirs)
	if err != nil {
		// ensure() validates options before construction; a persisted entry
		// that fails validation degrades to no grafts rather than refusing to
		// serve the volume.
		log.Printf("portablefsd: ignoring invalid persisted localDirs for %s: %v", name, err)
		localDirs = nil
	}
	storageID := stableStorageID(storageKey(req.VolumeID, req.Branch))
	options := req.Options
	options.LocalDirs = localDirs
	return &attach{
		ref:           ref,
		key:           key,
		volumeID:      req.VolumeID,
		branch:        req.Branch,
		authorityURL:  strings.TrimSpace(req.AuthorityURL),
		authorityAddr: normalizeAuthority(req.AuthorityURL),
		tlsCAPEM:      req.TLSCAPEM,
		mountPath:     req.MountPath,
		volumeName:    name,
		storageID:     storageID,
		options:       options,
		stateDir:      stateDir,
		identityEpoch: 1,
		token:         req.AuthToken,
		state:         pfslocal.AttachStateAttached,
		items:         map[uint64]*itemRecord{},
		paths:         map[string]*itemRecord{},
		handles:       map[uint64]*handleRecord{},
		enumRecords:   map[uint64]*enumerationRecord{},
		subscribers:   map[*eventSubscriber]struct{}{},
		conns:         map[interface{ Close() error }]struct{}{},
		eventReady:    make(chan struct{}),
		localDirs:     localDirs,
		localRoot:     filepath.Join(stateDir, "local", storageID),
		localVersions: map[string]uint64{},
	}
}

type enumerationRecord struct {
	id         uint64
	dir        string
	entries    []clientcore.DirEntry
	dirVersion uint64
	lastUsed   time.Time
}

func newRevivedAttach(ref, key string, req ensureAttachRequest, stateDir string, identityEpoch uint64, items []persistedItemRecord) *attach {
	a := newAttach(ref, key, req, stateDir)
	if len(a.localDirs) > 0 {
		root, err := confinedfs.Open(a.localRoot, 0o700)
		if err != nil {
			log.Printf("portablefsd: local-dir backing unavailable for revived attach %s: %v", ref, err)
		} else {
			a.localFS = root
		}
	}
	if identityEpoch != 0 {
		a.identityEpoch = identityEpoch
	}
	a.token = ""
	a.credentialPending = true
	a.state = pfslocal.AttachStateDegraded
	a.lastErr = "credentials required after daemon restart"
	a.mu.Lock()
	a.restoreItemsLocked(items)
	if a.root == nil {
		a.root = a.registerLocked("", syntheticRootAttr())
	}
	a.mu.Unlock()
	return a
}

func (a *attach) persistedEntry() persistedAttachEntry {
	a.mu.RLock()
	items := a.persistedItemsLocked()
	options := a.options
	options.LocalDirs = append([]string(nil), a.options.LocalDirs...)
	a.mu.RUnlock()
	return persistedAttachEntry{
		Ref:           a.ref,
		VolumeID:      a.volumeID,
		Branch:        a.branch,
		MountPath:     a.mountPath,
		AuthorityURL:  a.authorityURL,
		TLSCAPEM:      a.tlsCAPEM,
		Options:       options,
		IdentityEpoch: a.identityEpoch,
		Items:         items,
	}
}

func (a *attach) activate(ctx context.Context, tok string) error {
	return a.activateWithOptions(ctx, tok, nil)
}

func (a *attach) activateWithOptions(ctx context.Context, tok string, options *AttachOptions) error {
	a.startMu.Lock()
	defer a.startMu.Unlock()
	a.setCredential(tok)
	a.mu.RLock()
	if a.detached {
		a.mu.RUnlock()
		return fmt.Errorf("attach is detached")
	}
	active := a.vol != nil && !a.credentialPending
	a.mu.RUnlock()
	if active {
		return nil
	}
	if options != nil {
		a.mu.Lock()
		a.options.VolumeLocalDirs = options.VolumeLocalDirs
		// A revived attach has no live routing table, so the re-ensure
		// request is authoritative for explicit grafts. In particular,
		// --no-local-dirs sends an empty set plus VolumeLocalDirs=false and
		// must clear persisted grafts rather than add nothing to them.
		a.options.LocalDirs = append([]string(nil), options.LocalDirs...)
		a.mu.Unlock()
	}
	if err := a.start(ctx); err != nil {
		a.setErr(err)
		return err
	}
	a.mu.Lock()
	a.credentialPending = false
	a.lastErr = ""
	a.state = a.currentStateLocked()
	a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{State: a.state}})
	a.mu.Unlock()
	return nil
}

func (a *attach) start(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Join(a.stateDir, "wal"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(a.stateDir, "cache"), 0o700); err != nil {
		return err
	}
	// Claim the (volume, branch) WAL store and pull in parked WALs from
	// legacy mount-path-keyed dirs BEFORE the Volume dials: the engine's
	// recovery replays its own PFW5 streams inside Dial, and the legacy
	// sess-*.wal drain below replays the pre-v5 debris.
	a.adoptWALStore()
	tlsCfg, err := tlsConfigFromPEM(a.tlsCAPEM)
	if err != nil {
		return err
	}
	diskDir := a.options.DiskCacheDir
	if diskDir == "" {
		diskDir = filepath.Join(a.stateDir, "cache", a.ref)
	}
	diskCap := a.options.DiskCacheMB
	if diskCap == 0 {
		diskCap = defaultDiskCacheMB
	}
	opts := clientcore.Options{
		Addr:      a.authorityAddr,
		Pool:      4,
		TLSConfig: tlsCfg,
		Owner:     a.ownerID(),
		VolumeID:  a.volumeID,
		CredentialSource: func() string {
			a.credMu.RLock()
			defer a.credMu.RUnlock()
			return a.token
		},
		Branch:          a.branch,
		WALDir:          filepath.Join(a.stateDir, "wal", a.storageID),
		NegativeCache:   a.options.NegativeCache,
		NoNegativeCache: a.options.NoNegativeCache,
		DiskCacheDir:    diskDir,
		DiskCacheBytes:  diskCap << 20,
		PrefetchTree:    a.options.Prefetch,
		OnFlushAll:      a.onFlushAll,
		OnMarkOrphan:    a.onMarkOrphan,
		// A persistently failing write-back flush flips the attach to degraded (visible in
		// `portablefs mounts` + pushed to the extension) instead of only logging, so acked
		// write-back that cannot reach the authority is loud, never silently dropped.
		OnWriteBackError: func(_ string, err error) { a.setErr(err) },
		Debugf: func(format string, args ...any) {
			log.Printf("attach %s: "+format, append([]any{a.ref}, args...)...)
		},
	}
	vol, err := clientcore.Dial(ctx, opts)
	if err != nil {
		return dialErrorWithTLSHint(err, a.tlsCAPEM)
	}
	// Legacy sess-*.wal records have no durable scope fencing. They must be
	// completely resolved before this Volume is published to the frontend or
	// event readiness is signaled; otherwise new live mutations could race an
	// ambiguous replay. A failure leaves the legacy WAL/sidecar in place and
	// activation returns its typed cause.
	if err := a.drainLegacyWALs(ctx, vol); err != nil {
		if closeErr := vol.Close(); closeErr != nil {
			return errors.Join(err, fmt.Errorf("close volume after blocked legacy drain: %w", closeErr))
		}
		return err
	}
	effectiveLocalDirs := append([]string(nil), a.options.LocalDirs...)
	if a.options.VolumeLocalDirs {
		declared := localdirs.ReadVolumeConfig(ctx, vol, func(format string, args ...any) {
			log.Printf("attach %s: "+format, append([]any{a.ref}, args...)...)
		})
		effectiveLocalDirs, err = localdirs.Normalize(append(effectiveLocalDirs, declared...))
		if err != nil {
			_ = vol.Close()
			return fmt.Errorf("resolve volume local dirs: %w", err)
		}
	}
	a.mu.RLock()
	localFS := a.localFS
	a.mu.RUnlock()
	openedLocalFS := false
	if len(effectiveLocalDirs) > 0 {
		if localFS == nil {
			localFS, err = confinedfs.Open(a.localRoot, 0o700)
			if err != nil {
				_ = vol.Close()
				return fmt.Errorf("open local-dir backing capability: %w", err)
			}
			openedLocalFS = true
		}
	}
	eventClient, err := fsproto.DialTLSAuth(a.authorityAddr, 1, tlsCfg, func() string {
		a.credMu.RLock()
		defer a.credMu.RUnlock()
		return a.token
	})
	if err != nil {
		if openedLocalFS {
			_ = localFS.Close()
		}
		_ = vol.Close()
		return err
	}
	eventStream, eventAck, err := eventClient.Subscribe()
	if err != nil {
		if openedLocalFS {
			_ = localFS.Close()
		}
		_ = eventClient.Close()
		_ = vol.Close()
		return err
	}
	rootAttr, st := vol.Getattr(ctx, "", clientcore.NewNodeState(1, true))
	if st != fsproto.OK {
		if openedLocalFS {
			_ = localFS.Close()
		}
		_ = eventClient.Close()
		_ = vol.Close()
		return fmt.Errorf("root getattr: status %d", st)
	}
	a.mu.Lock()
	if a.detached {
		a.mu.Unlock()
		if openedLocalFS {
			_ = localFS.Close()
		}
		_ = eventClient.Close()
		_ = vol.Close()
		return fmt.Errorf("attach is detached")
	}
	a.vol = vol
	a.eventClient = eventClient
	a.localDirs = effectiveLocalDirs
	a.localFS = localFS
	a.root = a.registerLocked("", rootAttr)
	aliasCounts := map[uint64]int{}
	for _, rec := range a.paths {
		if rec != nil && rec.path != "" && rec.state != nil && rec.state.AuthIno() {
			aliasCounts[rec.state.AuthorityIno()]++
		}
	}
	for _, rec := range a.paths {
		if rec != nil && rec.path != "" && rec.state != nil && rec.state.AuthIno() &&
			aliasCounts[rec.state.AuthorityIno()] > 1 {
			vol.RememberHardlinkAlias(rec.path, rec.state.AuthorityIno())
		}
	}
	if a.options.Prefetch {
		a.state = pfslocal.AttachStateWarming
	}
	a.mu.Unlock()
	a.eventOnce.Do(func() { close(a.eventReady) })
	go vol.StartInvalidations(ctx, false)
	go a.forwardEvents(ctx, eventClient, eventStream, eventAck)
	go a.watchPrefetch(ctx)
	return nil
}

func (a *attach) setCredential(tok string) {
	a.credMu.Lock()
	a.token = tok
	a.credMu.Unlock()
	a.mu.RLock()
	vol := a.vol
	a.mu.RUnlock()
	if vol != nil {
		vol.RenewCredential(tok)
	}
	a.mu.RLock()
	events := a.eventClient
	a.mu.RUnlock()
	if events != nil {
		events.SetAuthToken(tok)
	}
}

// detach tears the attach down. NORMAL (force=false): the full drain barrier
// runs FIRST and a failure aborts the detach with the attach fully alive —
// a normal unmount can never succeed with an unshipped acknowledged tail.
// FORCED (force=true): the tail parks as a durable recovery job (registered
// in the WAL store, outside the attach lifetime) and its ID is returned for
// the caller to surface.
func (a *attach) detach(ctx context.Context, force bool) (jobID string, err error) {
	_ = ctx
	// Quiesce every namespace/handle operation through the complete drain
	// decision. A failed normal detach releases this lock with the attach and
	// Volume still usable; a successful/forced detach publishes the terminal
	// flag before operations can resume.
	a.nsMu.Lock()
	a.mu.RLock()
	alreadyDetached := a.detached
	vol := a.vol
	a.mu.RUnlock()
	if alreadyDetached {
		a.nsMu.Unlock()
		return "", nil
	}
	if vol != nil {
		if force {
			id, cerr := vol.CloseJournalDurable()
			jobID = id
			if cerr != nil {
				err = fmt.Errorf("forced detach: journal-durable close: %w", cerr)
			} else if id != "" {
				log.Printf("portablefsd: detach %s: forced; recovery job %s parked durably (recovers on the next attach)", a.ref, id)
			}
		} else if cerr := vol.Close(); cerr != nil {
			// Close freezes admissions around the final drain and visibility
			// barrier. It is retryable on failure and has not cancelled the
			// Volume or parked its WAL. Keep the attach serving.
			recs, bytes := vol.WriteBackPending()
			a.nsMu.Unlock()
			return "", fmt.Errorf("detach refused: final drain/release barrier failed with %d records (%d bytes) unshipped: %w (retry when the authority answers, or force-detach to park them as a durable recovery job)", recs, bytes, cerr)
		}
	}
	a.mu.Lock()
	if a.detached {
		a.mu.Unlock()
		a.nsMu.Unlock()
		return "", nil
	}
	a.detached = true
	a.state = pfslocal.AttachStateDetaching
	a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{State: pfslocal.AttachStateDetaching, Detail: "detaching"}})
	events := a.eventClient
	localFS := a.localFS
	a.mu.Unlock()
	a.nsMu.Unlock()
	if events != nil {
		_ = events.Close()
	}
	if localFS != nil {
		_ = localFS.Close()
	}
	a.mu.Lock()
	for sub := range a.subscribers {
		close(sub.ch)
		delete(a.subscribers, sub)
	}
	for c := range a.conns {
		_ = c.Close()
		delete(a.conns, c)
	}
	for id, h := range a.handles {
		if h.file != nil {
			_ = h.file.Close()
			delete(a.handles, id)
		}
	}
	a.mu.Unlock()
	return jobID, err
}

func (a *attach) status() attachStatus {
	a.mu.RLock()
	state := a.currentStateLocked()
	lastErr := a.lastErr
	volumeName := a.volumeName
	vol := a.vol
	attrEntries := 0
	diskBytes, diskCap := int64(0), int64(0)
	a.mu.RUnlock()
	var pf clientcore.PrefetchProgress
	var wb *writeBackStatus
	if vol != nil {
		pf = vol.PrefetchProgress()
		attrEntries = vol.AttrCache.Len()
		if vol.DiskCache != nil {
			diskBytes, diskCap = vol.DiskCache.Stats()
		}
		st := vol.WritebackStatus()
		// A healthy zero-debt engine is still operationally meaningful:
		// expose it instead of making clients guess whether write-back is
		// absent or merely idle. Scope names make contention and overly broad
		// grants diagnosable without exposing delegation epochs.
		wb = &writeBackStatus{
			PendingRecords: st.PendingRecords, PendingBytes: st.PendingBytes,
			AppliedThrough: st.AppliedThrough, AdmittedThrough: st.AdmittedThrough,
			OldestPendingMs: st.OldestPendingMs, Degraded: st.Degraded,
			LastFailure: st.LastFailure, WALBytes: st.WALBytes,
			Delegations: make([]delegationView, 0, len(st.Delegations)),
		}
		for _, d := range st.Delegations {
			wb.Delegations = append(wb.Delegations, delegationView{Scope: d.Scope, Draining: d.Draining})
		}
		now := time.Now().UnixMilli()
		for _, j := range st.Jobs {
			wb.Jobs = append(wb.Jobs, recoveryJobRef{
				JobID: j.JobID, State: j.State,
				Records: j.PendingRecords, Bytes: j.PendingBytes,
				LastError: j.LastError,
			})
			wb.ParkedWALs = append(wb.ParkedWALs, parkedWAL{
				WAL: j.JobID, Records: int(j.PendingRecords), PayloadBytes: int64(j.PendingBytes),
				AgeMs: now - j.CreatedAtMs, LastError: j.LastError,
			})
		}
	}
	a.mu.RLock()
	localDirs := append([]string(nil), a.localDirs...)
	legacyParked := append([]parkedWAL(nil), a.legacyParked...)
	a.mu.RUnlock()
	if len(legacyParked) > 0 {
		if wb == nil {
			wb = &writeBackStatus{}
		}
		wb.ParkedWALs = append(wb.ParkedWALs, legacyParked...)
	}
	return attachStatus{
		AttachRef: a.ref, VolumeID: a.volumeID, Branch: a.branch, MountPath: a.mountPath,
		State: stateString(state), VolumeName: volumeName, LastError: lastErr,
		Prefetch:  prefetchStatus{Done: pf.Done, EntriesWalked: pf.Entries},
		Cache:     cacheStatus{AttrEntries: attrEntries, DiskBytes: diskBytes, DiskCapBytes: diskCap},
		LocalDirs: localDirs,
		WriteBack: wb,
	}
}

func (a *attach) currentStateLocked() pfslocal.AttachStateState {
	if a.detached {
		return pfslocal.AttachStateDetaching
	}
	if a.credentialPending {
		return pfslocal.AttachStateDegraded
	}
	if a.vol != nil && a.options.Prefetch {
		p := a.vol.PrefetchProgress()
		if !p.Done {
			return pfslocal.AttachStateWarming
		}
	}
	if a.lastErr != "" {
		return pfslocal.AttachStateDegraded
	}
	return pfslocal.AttachStateAttached
}

func (a *attach) setErr(err error) {
	a.mu.Lock()
	if err != nil {
		// Idempotent while degraded: the health tick re-reports a persistent
		// error every flush interval; republishing an identical state event
		// 4x/second would spam subscribers without adding information.
		if msg := err.Error(); a.lastErr != msg {
			a.lastErr = msg
			if a.vol == nil {
				a.credentialPending = true
			}
			a.state = pfslocal.AttachStateDegraded
			a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{State: pfslocal.AttachStateDegraded, Detail: a.lastErr}})
		}
	} else if a.lastErr != "" {
		a.lastErr = ""
		a.state = a.currentStateLocked()
		a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{State: a.state}})
	}
	a.mu.Unlock()
}

func (a *attach) volOrErr() (*clientcore.Volume, int32) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.detached {
		return nil, darwinENXIO
	}
	if a.credentialPending || a.vol == nil {
		return nil, darwinEIO
	}
	return a.vol, 0
}

func (a *attach) persistState() error {
	if a.persist == nil {
		return nil
	}
	return a.persist()
}

func (a *attach) persistStateBestEffort(context string) {
	if err := a.persistState(); err != nil {
		log.Printf("portablefsd: persist attach %s after %s: %v", a.ref, context, err)
	}
}

// schedulePersistState requests an asynchronous, debounced write of the daemon
// state file (attach configs + item identity bindings). Namespace mutations
// call this instead of persisting synchronously: state-file I/O must never
// gate or fail volume I/O, and a binding lost from the debounce window in a
// crash costs exactly one ESTALE re-lookup after restart.
func (a *attach) schedulePersistState() {
	if a.schedulePersist != nil {
		a.schedulePersist()
	}
}

// persistStateOrEIO persists synchronously and maps failure to EIO. Reserved
// for the two once-per-attach anchors that everything else hangs off — the
// root item binding and credential activation (identity epoch) — where a lost
// write would invalidate the whole persisted table, and the cost is paid once,
// never per file operation.
func (a *attach) persistStateOrEIO(context string) int32 {
	if err := a.persistState(); err != nil {
		log.Printf("portablefsd: persist attach %s after %s: %v", a.ref, context, err)
		return darwinEIO
	}
	return 0
}

func (a *attach) registerLocked(p string, attr fsproto.Attr) *itemRecord {
	ino := attr.Ino
	authIno := ino != 0
	if ino == 0 {
		ino = clientcore.InoOf(p)
	}
	return a.registerWithItemLocked(p, attr, ino, authIno, true)
}

func (a *attach) registerCreatedLocked(p string, attr fsproto.Attr) *itemRecord {
	if attr.Ino != 0 {
		return a.registerLocked(p, attr)
	}
	if a.paths[p] != nil {
		return a.registerLocked(p, attr)
	}
	return a.registerWithItemLocked(p, attr, a.newLocalItemIDLocked(p), false, false)
}

// registerHardLinkAliasLocked binds a new hard-link name to the exact
// frontend item and NodeState already published for its source. A source
// created under write-back may have a daemon-local FSKit item ID even after
// delegation release gives it a different authority inode; publishing the
// authority inode as a second FSKit item would split one POSIX inode into two
// independent frontend objects.
func (a *attach) registerHardLinkAliasLocked(p string, source *itemRecord, attr fsproto.Attr) *itemRecord {
	if a.paths[p] != nil {
		a.removePathLocked(p)
	}
	if current := a.paths[source.path]; current != nil {
		source = current
	}
	source.attr = attr
	a.pendBindingLocked(source)
	rec := &itemRecord{item: source.item, path: p, state: source.state, attr: attr}
	a.paths[p] = rec
	if a.items[rec.item.ItemID] == nil {
		a.items[rec.item.ItemID] = source
	}
	a.pendBindingLocked(rec)
	return rec
}

func (a *attach) registerWithItemLocked(p string, attr fsproto.Attr, ino uint64, authIno bool, reuseByItemID bool) *itemRecord {
	gen := a.identityEpoch
	if gen == 0 {
		gen = 1
		a.identityEpoch = gen
	}
	if rec := a.paths[p]; rec != nil {
		rec.attr = attr
		// Preserve the pfslocal Item already handed to the kernel for this same path. A write-back
		// create starts life with a local item, then may gain an authority inode when it flushes or
		// recovers after a daemon restart; changing ItemID at that boundary would strand existing
		// kernel-held FSItems. Fresh creates use registerCreatedLocked so recycled paths cannot inherit
		// an item that was renamed away.
		if rec.state == nil {
			var authorityItemID uint64
			if authIno {
				authorityItemID = ino
			}
			rec.state = clientcore.NewNodeStateWithAuthority(rec.item.ItemID, authorityItemID)
			if authIno {
				a.pendBindingLocked(rec)
			}
		} else if authIno && rec.state.AuthIno() && rec.state.Orphan() == 0 &&
			rec.state.AuthorityIno() != ino {
			// The authority inode BEHIND this path changed: a remote writer
			// rename-over-ed or recreated the name (git's atomic ref update).
			// The kernel's Item stays stable — same path identity — but open
			// registration pins inodes, and pinning the remembered inode now
			// answers ENOENT forever (the authority correctly reports it
			// unlinked). POSIX open resolves the NAME at open time: swap in a
			// fresh NodeState for the current inode. Handles already open
			// captured the old state at open time and unwind through it.
			rec.state = clientcore.NewNodeStateWithAuthority(rec.item.ItemID, ino)
		} else if authIno && !rec.state.AuthIno() {
			if !rec.state.RecordAuthorityIno(ino) {
				rec.state = clientcore.NewNodeStateWithAuthority(rec.item.ItemID, ino)
			}
			a.pendBindingLocked(rec) // the persisted Auth bit flipped
		}
		return rec
	}
	item := pfslocal.Item{ItemID: ino, ItemGeneration: gen}
	var canonical *itemRecord
	if reuseByItemID {
		canonical = a.items[ino]
	}
	rec := &itemRecord{item: item, state: clientcore.NewNodeState(ino, authIno)}
	if canonical == nil {
		a.items[ino] = rec
	} else {
		// Multiple paths with the same stable inode are hard-link aliases.
		// Keep one canonical item lookup while each name retains its own
		// path record; every alias shares the same open/orphan NodeState.
		rec.state = canonical.state
	}
	rec.path = p
	rec.attr = attr
	rec.item = item
	a.paths[p] = rec
	a.pendBindingLocked(rec)
	return rec
}

// pendBindingLocked buffers a binding delta for the caller's later
// flushBindingDelta. Caller holds a.mu.
func (a *attach) pendBindingLocked(rec *itemRecord) {
	var authorityItemID uint64
	if rec.state != nil {
		authorityItemID = rec.state.AuthorityIno()
	}
	persistedAuthorityItemID := authorityItemID
	if persistedAuthorityItemID == rec.item.ItemID {
		persistedAuthorityItemID = 0
	}
	a.pendingBindings = append(a.pendingBindings, bindingJournalEntry{
		Ref: a.ref, Op: "bind", Path: rec.path,
		ID: rec.item.ItemID, Gen: rec.item.ItemGeneration,
		Auth: authorityItemID != 0, AuthorityItemID: persistedAuthorityItemID,
	})
}

// flushBindingDelta journals the binding changes buffered by the registration
// primitives since the last flush, then schedules the compacting persist.
// Every operation that can change bindings calls this after releasing a.mu
// and BEFORE replying, so an item ID never reaches the kernel without its
// binding being at least process-crash durable.
func (a *attach) flushBindingDelta() {
	a.mu.Lock()
	pending := a.pendingBindings
	a.pendingBindings = nil
	a.mu.Unlock()
	if len(pending) == 0 {
		return
	}
	if a.journal != nil {
		a.journal.append(pending)
	}
	a.schedulePersistState()
}

// applyJournalEntry replays one binding delta at daemon startup, mirroring
// restoreItemsLocked's construction and sanitizePersistedItems's guards.
func (a *attach) applyJournalEntry(e bindingJournalEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch e.Op {
	case "bind":
		if e.ID == 0 || e.Gen == 0 || e.Gen != a.identityEpoch || !validJournalPath(e.Path) {
			return
		}
		if prev := a.paths[e.Path]; prev != nil {
			a.dropPathLocked(e.Path)
		}
		attr := fsproto.Attr{Ino: e.ID}
		if e.Path == "" {
			attr = syntheticRootAttr()
			attr.Ino = e.ID
		}
		rec := &itemRecord{
			item:  pfslocal.Item{ItemID: e.ID, ItemGeneration: e.Gen},
			path:  e.Path,
			state: clientcore.NewNodeStateWithAuthority(e.ID, e.authorityItemID()),
			attr:  attr,
		}
		if canonical := a.items[e.ID]; canonical != nil {
			rec.state = canonical.state
		} else {
			a.items[e.ID] = rec
		}
		a.paths[e.Path] = rec
		if e.Path == "" {
			a.root = rec
		}
	case "unbind":
		a.removePathLocked(e.Path)
	case "rekey":
		if !validJournalPath(e.From) || !validJournalPath(e.To) {
			return
		}
		a.renamePathLocked(e.From, e.To)
	}
}

func (a *attach) newLocalItemIDLocked(p string) uint64 {
	max := new(big.Int).Lsh(big.NewInt(1), 63)
	for attempt := 0; ; attempt++ {
		var id uint64
		if n, err := rand.Int(rand.Reader, max); err == nil {
			id = n.Uint64() | localItemIDMarker
		} else {
			id = clientcore.InoOf(fmt.Sprintf("local:%s:%d:%d", p, time.Now().UnixNano(), attempt)) | localItemIDMarker
		}
		if id != 0 && a.items[id] == nil {
			return id
		}
	}
}

func (a *attach) restoreItemsLocked(items []persistedItemRecord) {
	for _, item := range items {
		if item.ItemID == 0 || item.ItemGeneration == 0 {
			continue
		}
		attr := fsproto.Attr{Ino: item.ItemID}
		if item.Path == "" {
			attr = syntheticRootAttr()
			attr.Ino = item.ItemID
		}
		rec := &itemRecord{
			item:  pfslocal.Item{ItemID: item.ItemID, ItemGeneration: item.ItemGeneration},
			path:  item.Path,
			state: clientcore.NewNodeStateWithAuthority(item.ItemID, item.authorityItemID()),
			attr:  attr,
		}
		if canonical := a.items[item.ItemID]; canonical != nil {
			rec.state = canonical.state
		} else {
			a.items[item.ItemID] = rec
		}
		a.paths[item.Path] = rec
		if item.Path == "" {
			a.root = rec
		}
	}
}

func (a *attach) persistedItemsLocked() []persistedItemRecord {
	items := make([]persistedItemRecord, 0, len(a.paths))
	for _, rec := range a.paths {
		if rec == nil || rec.item.ItemID == 0 {
			continue
		}
		var authorityItemID uint64
		if rec.state != nil {
			authorityItemID = rec.state.AuthorityIno()
		}
		persistedAuthorityItemID := authorityItemID
		if persistedAuthorityItemID == rec.item.ItemID {
			persistedAuthorityItemID = 0 // legacy compact form: authorityIno=true means itemId
		}
		items = append(items, persistedItemRecord{
			Path:            rec.path,
			ItemID:          rec.item.ItemID,
			ItemGeneration:  rec.item.ItemGeneration,
			AuthorityIno:    authorityItemID != 0,
			AuthorityItemID: persistedAuthorityItemID,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Path == items[j].Path {
			return items[i].ItemID < items[j].ItemID
		}
		return items[i].Path < items[j].Path
	})
	return items
}

// lockNames serializes mutations of the SAME (directory, name) pair while
// nsMu is held SHARED. File-grain mutations (create, mkdir, symlink, unlink,
// hard link, xattr set/remove) take the stripe of the exact name they mutate,
// so two mutations of one name — whose local pre-checks and registry
// bookkeeping need a stable view, and whose legacy O_EXCL decision is a
// lookup-then-create pair — serialize, while mutations of DIFFERENT names run
// their authority round trips in parallel even inside one directory (the
// authority linearizes them, exactly as it does for two independent
// machines). A name stripe is therefore never a directory-wide lock held
// across the network: a create storm in one directory fans out. Subtree ops
// (rename, rmdir) hold nsMu EXCLUSIVELY instead, which excludes every stripe
// holder wholesale — rmdir needs that to keep its emptiness check atomic
// against concurrent creates inside the dir.
// Returns the unlock function; stripes are acquired in index order so
// multi-stripe holders can never deadlock each other.
func (a *attach) lockNames(keys ...nameKey) func() {
	seen := map[int]struct{}{}
	idx := make([]int, 0, len(keys))
	for _, k := range keys {
		i := int(clientcore.InoOf(k.dir+"\x00"+k.name) & 63)
		if _, ok := seen[i]; !ok {
			seen[i] = struct{}{}
			idx = append(idx, i)
		}
	}
	sort.Ints(idx)
	for _, i := range idx {
		a.nameLocks[i].Lock()
	}
	return func() {
		for i := len(idx) - 1; i >= 0; i-- {
			a.nameLocks[idx[i]].Unlock()
		}
	}
}

// nameKey identifies one directory entry for stripe locking.
type nameKey struct {
	dir  string
	name string
}

func entryKey(p string) nameKey {
	return nameKey{dir: parentPath(p), name: path.Base("/" + p)}
}

func (a *attach) item(item pfslocal.Item) (*itemRecord, int32) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.detached {
		return nil, darwinENXIO
	}
	rec := a.items[item.ItemID]
	if rec == nil || rec.item.ItemGeneration != item.ItemGeneration {
		return nil, darwinENOENT
	}
	cp := *rec
	return &cp, 0
}

func (a *attach) itemByPath(p string) *itemRecord {
	a.mu.RLock()
	defer a.mu.RUnlock()
	rec := a.paths[p]
	if rec == nil {
		return nil
	}
	cp := *rec
	return &cp
}

func (a *attach) removePathLocked(p string) {
	if a.dropPathLocked(p) {
		a.pendingBindings = append(a.pendingBindings, bindingJournalEntry{Ref: a.ref, Op: "unbind", Path: p})
	}
}

func (a *attach) dropPathLocked(p string) bool {
	if rec := a.paths[p]; rec != nil {
		delete(a.paths, p)
		if a.items[rec.item.ItemID] == rec {
			delete(a.items, rec.item.ItemID)
			for _, alias := range a.paths {
				if alias.item == rec.item {
					a.items[rec.item.ItemID] = alias
					break
				}
			}
		}
		return true
	}
	return false
}

func (a *attach) renamePathLocked(oldp, newp string) {
	for p, rec := range a.paths {
		if np, ok := renamedPath(p, oldp, newp); ok {
			delete(a.paths, p)
			rec.path = np
			a.paths[rec.path] = rec
		}
	}
	for id, h := range a.handles {
		if np, ok := renamedPath(h.path, oldp, newp); ok {
			cp := *h
			cp.path = np
			a.handles[id] = &cp
		}
	}
	// A volume rename that moves an ancestor of a graft root carries the graft
	// (and its machine-local backing) to the new location, mirroring how a
	// mountpoint travels with its directory vnode. Persistence is the caller's
	// job: every rename path already persists after releasing a.mu.
	a.remapLocalDirsForRenameLocked(oldp, newp)
	a.pendingBindings = append(a.pendingBindings, bindingJournalEntry{Ref: a.ref, Op: "rekey", From: oldp, To: newp})
}

func renamedPath(p, oldp, newp string) (string, bool) {
	if p != oldp && !strings.HasPrefix(p, oldp+"/") {
		return "", false
	}
	return newp + strings.TrimPrefix(p, oldp), true
}

func (a *attach) newHandleLocked(path string, state *clientcore.NodeState, write bool) uint64 {
	a.nextHandle++
	if a.nextHandle == 0 {
		a.nextHandle++
	}
	id := a.nextHandle
	a.handles[id] = &handleRecord{id: id, path: path, openPath: path, state: state, write: write}
	return id
}

func (a *attach) newLocalHandleLocked(path string, file *os.File, write bool) uint64 {
	a.nextHandle++
	if a.nextHandle == 0 {
		a.nextHandle++
	}
	id := a.nextHandle
	a.handles[id] = &handleRecord{id: id, path: path, openPath: path, write: write, file: file}
	return id
}

func (a *attach) handle(id uint64) (*handleRecord, int32) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.detached {
		return nil, darwinENXIO
	}
	h := a.handles[id]
	if h == nil {
		return nil, darwinEINVAL
	}
	cp := *h
	return &cp, 0
}

func (a *attach) closeHandle(id uint64) *handleRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	h := a.handles[id]
	delete(a.handles, id)
	return h
}

func (a *attach) subscribe(origin uint64) *eventSubscriber {
	sub := &eventSubscriber{origin: origin, ch: make(chan pfslocal.Event, 128)}
	a.mu.Lock()
	a.subscribers[sub] = struct{}{}
	state := a.currentStateLocked()
	detail := ""
	if state == pfslocal.AttachStateDegraded {
		detail = a.lastErr
	}
	a.mu.Unlock()
	sub.ch <- pfslocal.Event{Kind: &pfslocal.AttachState{State: state, Detail: detail}}
	return sub
}

func (a *attach) newOrigin() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nextOrigin++
	if a.nextOrigin == 0 {
		a.nextOrigin++
	}
	return a.nextOrigin
}

func (a *attach) addConn(c interface{ Close() error }) {
	a.mu.Lock()
	if !a.detached {
		a.conns[c] = struct{}{}
	}
	a.mu.Unlock()
}

func (a *attach) removeConn(c interface{ Close() error }) {
	a.mu.Lock()
	delete(a.conns, c)
	a.mu.Unlock()
}

func (a *attach) unsubscribe(sub *eventSubscriber) {
	a.mu.Lock()
	if _, ok := a.subscribers[sub]; ok {
		delete(a.subscribers, sub)
		close(sub.ch)
	}
	a.mu.Unlock()
}

func (a *attach) publishLocked(ev pfslocal.Event) {
	a.publishExceptLocked(ev, 0)
}

func (a *attach) publishExceptLocked(ev pfslocal.Event, skipOrigin uint64) {
	for sub := range a.subscribers {
		if skipOrigin != 0 && sub.origin == skipOrigin {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
			delete(a.subscribers, sub)
			close(sub.ch)
		}
	}
}

func (a *attach) publish(ev pfslocal.Event) {
	a.mu.Lock()
	a.publishLocked(ev)
	a.mu.Unlock()
}

func (a *attach) onInvalidate(p string, inPlace bool) {
	a.mu.Lock()
	a.publishAuthorityInvalidationLocked(p, inPlace, 0)
	a.mu.Unlock()
}

func (a *attach) publishAuthorityInvalidationLocked(p string, inPlace bool, version uint64) {
	if inPlace {
		a.publishContentInvalidationLocked(p, version, 0)
		return
	}
	a.publishNamespaceInvalidationLocked(p, version, 0)
}

func (a *attach) publishContentInvalidationLocked(p string, version uint64, skipOrigin uint64) {
	rec := a.paths[p]
	if rec == nil {
		return
	}
	ver := version
	if ver == 0 {
		if a.localDirForLocked(p) != "" {
			ver = a.bumpLocalVersionLocked(p)
		} else if a.vol != nil {
			_, ver = a.vol.VersionCache.GenAndVersion(p)
		}
	}
	ev := pfslocal.Event{Kind: &pfslocal.Invalidation{
		Item: rec.item, ContentChanged: true, AttrsChanged: true, ContentVersion: ver,
	}}
	a.publishExceptLocked(ev, skipOrigin)
}

func (a *attach) publishNamespaceInvalidationLocked(p string, version uint64, skipOrigin uint64) {
	rec := a.paths[parentPath(p)]
	if rec == nil {
		return
	}
	ver := version
	if ver == 0 {
		// The same merged version freshDirListing serves, so an invalidation
		// can never carry a version the next listing would contradict.
		ver = a.mergedDirVersionLocked(parentPath(p))
	}
	ev := pfslocal.Event{Kind: &pfslocal.Invalidation{
		Item: rec.item, AttrsChanged: true, NamespaceChanged: true, ContentVersion: ver,
	}}
	a.publishExceptLocked(ev, skipOrigin)
}

func parentPath(p string) string {
	d := path.Dir(strings.Trim(path.Clean("/"+p), "/"))
	if d == "." || d == "/" {
		return ""
	}
	return d
}

func (a *attach) onFlushAll(p string) {
	state := pfslocal.AttachState{State: a.statusState(), Detail: "cache flush"}
	a.publish(pfslocal.Event{Kind: &state})
}

func (a *attach) onMarkOrphan(p string, ino uint64) {
	a.mu.Lock()
	if rec := a.paths[p]; rec != nil {
		// Match the authority identity, never just the path. Invalidation
		// delivery can trail remove+recreate: a locally-born replacement has
		// AuthIno false but is still a different node and must not be routed
		// to the retired inode. Delegation release records the proven
		// authority inode before a peer can unlink an open local create.
		if rec.state.MatchesAuthorityIno(ino) {
			rec.state.MarkOrphan(ino, a.vol.OpenOrphans())
		}
	}
	a.mu.Unlock()
}

func (a *attach) forwardEvents(ctx context.Context, cli *fsproto.Client, first <-chan coherence.Batch, firstAck fsproto.AckFunc) {
	owner := a.ownerID()
	stream, ack := first, firstAck
	for {
		if a.isDetached() {
			return
		}
		if stream == nil {
			var err error
			stream, ack, err = cli.Subscribe()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(500 * time.Millisecond):
					continue
				}
			}
			a.eventOnce.Do(func() { close(a.eventReady) })
		}
		for batch := range stream {
			for _, inv := range batch.Invs {
				// The authority only knows the daemon's fsproto owner, not which local frontend
				// connection originated an op. Daemon-origin mutations are therefore fanned out
				// synchronously at the pfslocal boundary with an origin-connection skip; the later
				// owner-tagged authority echo is dropped here as the dedupe point.
				if inv.Owner == owner || inv.Recall {
					continue
				}
				if inv.FlushAll {
					a.publish(pfslocal.Event{Kind: &pfslocal.AttachState{State: a.statusState(), Detail: "cache flush"}})
					continue
				}
				if inv.Path == "" {
					continue
				}
				a.mu.Lock()
				// Volume changes under a graft are shadowed by the machine-local
				// subtree; surfacing them would evict valid local kernel state.
				shadowed := a.localDirForLocked(inv.Path) != ""
				if !shadowed {
					a.publishAuthorityInvalidationLocked(inv.Path, inv.InPlace, inv.Version)
				}
				a.mu.Unlock()
				if !shadowed && inv.InPlace {
					// A remote writer changed bytes behind a possibly-live
					// kernel vnode: refresh its size and drop its pages.
					a.scheduleCoherenceRefresh(inv.Path)
				}
			}
			// Acknowledge after daemon caches are updated and the batch is
			// offered to the local frontend stream. This is the strongest
			// boundary portablefsd can report; macOS 26 FSKit exposes no
			// kernel-cache invalidation hook.
			if ack != nil && (batch.Pos != 0 || batch.Bootstrap) {
				ack(batch.Pos)
			}
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		stream = nil
	}
}

func (a *attach) waitEventsReady(ctx context.Context) bool {
	select {
	case <-a.eventReady:
		return true
	case <-ctx.Done():
		return false
	}
}

func (a *attach) ownerID() string { return "portablefsd-" + a.storageID }

func (a *attach) isCredentialPending() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return !a.detached && a.credentialPending
}

func (a *attach) isDetached() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.detached
}

// hasLiveVolume reports whether this attach activated a Volume in this daemon
// lifetime — the storage-claim signal the one-live-attach-per-branch guard
// keys on (a dormant revived attach holds no WAL handles yet).
func (a *attach) hasLiveVolume() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.vol != nil
}

func (a *attach) statusState() pfslocal.AttachStateState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.currentStateLocked()
}

func (a *attach) watchPrefetch(ctx context.Context) {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	var last pfslocal.AttachStateState
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.mu.Lock()
			next := a.currentStateLocked()
			if next != last && !a.detached {
				last = next
				a.state = next
				a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{State: next}})
			}
			a.mu.Unlock()
			if next != pfslocal.AttachStateWarming {
				return
			}
		}
	}
}

func (a *attach) marshalJSONStatus(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, a.status())
}

func randomAttachRef() (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var b strings.Builder
	b.WriteString("att_")
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < 22; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[n.Int64()])
	}
	return b.String(), nil
}

func stableStorageID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", sum[:16])
}

// attachKey identifies an ATTACH (a kernel mount of a volume at a path); two
// mounts of one branch at different paths are distinct attaches.
func attachKey(volumeID, branch, mountPath string) string {
	return volumeID + "\x00" + branch + "\x00" + mountPath
}

// storageKey identifies durable per-volume STATE — the write-back WAL store
// and the checkout owner. Deliberately excludes the mount path: remounting a
// branch at a new path must find the WALs (and the authority-side coordination
// identity) its previous mount left behind, instead of stranding them under a
// path-hashed directory forever.
func storageKey(volumeID, branch string) string {
	return volumeID + "\x00" + branch
}

func syntheticRootAttr() fsproto.Attr {
	return fsproto.Attr{Kind: "directory", Mode: 0o755, Nlink: 1, Ino: clientcore.InoOf("")}
}

func normalizeAuthority(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "tcp://")
	s = strings.TrimPrefix(s, "fsproto://")
	return s
}

// dialErrorWithTLSHint annotates a rejected plaintext dial. A plaintext
// client against a TLS router writes its token frame into what the server
// expects to be a ClientHello; the router tears the connection down, which
// the handshake classifier reads as an explicit token rejection. When the
// attach carried no CA the mismatch is by far the likelier story, so say so
// instead of letting the caller chase phantom credential bugs.
func dialErrorWithTLSHint(err error, tlsCAPEM string) error {
	if err == nil || tlsCAPEM != "" || !errors.Is(err, fsproto.ErrSessionTokenRejected) {
		return err
	}
	return fmt.Errorf("%w (this attach dialed in PLAINTEXT — if the authority router serves TLS, the client must trust its CA: log in again to refresh the stored CA, or set PORTABLEFS_TLS_CA)", err)
}

func tlsConfigFromPEM(pemText string) (*tls.Config, error) {
	if strings.TrimSpace(pemText) == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemText)) {
		return nil, fmt.Errorf("invalid tlsCaPem")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}

func stateString(st pfslocal.AttachStateState) string {
	switch st {
	case pfslocal.AttachStateWarming:
		return "warming"
	case pfslocal.AttachStateDegraded:
		return "degraded"
	case pfslocal.AttachStateDetaching:
		return "detaching"
	default:
		return "attached"
	}
}

func cleanChild(parent string, name []byte) (string, int32) {
	n := string(name)
	if n == "" || strings.Contains(n, "/") || n == "." || n == ".." {
		return "", darwinEINVAL
	}
	if parent == "" {
		return n, 0
	}
	return path.Join(parent, n), 0
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeHTTPError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
