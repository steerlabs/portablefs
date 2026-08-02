package portablefsd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/confinedfs"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
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

	frontendLnMu        sync.Mutex
	controlLnMu         sync.Mutex
	frontendConnections atomic.Int32
}

func NewServer(cfg Config) *Server {
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.ExecutableSHA256 == "" {
		cfg.ExecutableSHA256, _ = daemonctl.CurrentExecutableSHA256()
	}
	return &Server{
		cfg:    cfg,
		stopCh: make(chan struct{}),
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
	AttachRef    string `json:"attachRef,omitempty"`
	VolumeID     string `json:"volumeId"`
	Branch       string `json:"branch"`
	AuthorityURL string `json:"authorityUrl"`
	AuthToken    string `json:"authToken"`
	// AuthTokenExpiresAtMs is the access lease's own stated expiry for
	// AuthToken (unix ms). Additive and OPTIONAL: an older CLI omits it, the
	// zero value means "no stated deadline", and nothing hardens — a daemon
	// must never start declaring credentials dead just because a newer field
	// exists.
	AuthTokenExpiresAtMs int64         `json:"authTokenExpiresAtMs,omitempty"`
	DataPlaneTransport   string        `json:"dataPlaneTransport"`
	DataPlaneServerName  string        `json:"dataPlaneServerName,omitempty"`
	TLSCAPEM             string        `json:"tlsCaPem"`
	TLSCASHA256          string        `json:"tlsCaSha256,omitempty"`
	MountPath            string        `json:"mountPath"`
	Options              AttachOptions `json:"options"`
}

type attachStatus struct {
	AttachRef string         `json:"attachRef"`
	VolumeID  string         `json:"volumeId"`
	Branch    string         `json:"branch"`
	MountPath string         `json:"mountPath"`
	State     string         `json:"state"`
	Prefetch  prefetchStatus `json:"prefetch"`
	Cache     cacheStatus    `json:"cache"`
	LastError string         `json:"lastError,omitempty"`
	// Credential names WHICH credential verdict is behind a degraded state,
	// because "degraded" plus a prose lastError is not something a program can
	// branch on and the two credential faults call for different repairs.
	// Empty means no credential fault at all.
	Credential string           `json:"credential,omitempty"`
	VolumeName string           `json:"volumeName,omitempty"`
	LocalDirs  []string         `json:"localDirs,omitempty"`
	WriteBack  *writeBackStatus `json:"writeBack,omitempty"`
}

// writeBackStatus is the durability-debt view of an attach: the engine's
// full health snapshot — the unshipped acknowledged backlog, the sticky
// degraded verdict, the drain-time credit control that paces bulk data, the
// held delegations, and every parked stream the recovery machinery or an
// operator must still resolve.
type writeBackStatus struct {
	PendingRecords int   `json:"pendingRecords"`
	PendingBytes   int64 `json:"pendingBytes"`
	// UnrecoveredRecords/UnrecoveredBytes is the SUBSET of the pending debt that
	// is not going to drain on its own: every parked, forced, conflicted or
	// corrupt recovery job's remainder.
	//
	// ── WHY THE SPLIT IS ITS OWN NUMBER ─────────────────────────────────────
	//
	// "Pending is zero" was being read as "the drain completed", and those are
	// not the same statement. A forced unmount parks its undrained tail as a
	// durable recovery job; the live engine then legitimately reports nothing
	// pending while the parked stream still holds every byte of it. An operator
	// — or an automated drain-to-zero check — reading only PendingBytes was
	// told the mount was clean over data that had not reached the authority and
	// might never.
	//
	// So the two facts are reported separately and always together: what is
	// still moving, and what has stopped. A drain is complete only when BOTH
	// are zero, and that is now something a caller can actually check.
	UnrecoveredRecords int              `json:"unrecoveredRecords,omitempty"`
	UnrecoveredBytes   int64            `json:"unrecoveredBytes,omitempty"`
	AppliedThrough     uint64           `json:"appliedThrough,omitempty"`
	AdmittedThrough    uint64           `json:"admittedThrough,omitempty"`
	OldestPendingMs    int64            `json:"oldestPendingMs,omitempty"`
	Degraded           bool             `json:"degraded,omitempty"`
	LastFailure        string           `json:"lastFailure,omitempty"`
	Delegations        []delegationView `json:"delegations"`
	WALBytes           int64            `json:"walBytes,omitempty"`
	// WALBudget is the WAL's byte cap; WALBytes alone cannot say how close to
	// it the engine is running. LastProgressMs is the age of the last drain
	// progress, which is what separates a paced flusher from a stuck one.
	WALBudget      int64 `json:"walBudget,omitempty"`
	LastProgressMs int64 `json:"lastProgressMs,omitempty"`
	// Drain-time credit control. CreditSetpoint is the adapted operating limit
	// on resident unapplied bulk data and CreditCeiling is the data lane's hard
	// cap — a setpoint is unreadable without its cap. CreditDebt is how much of
	// the setpoint is outstanding, AppliedRateBps is the measured
	// authority-applied rate the setpoint is derived from, CreditWaiters is how
	// many data mutations are currently paced, and DataLaneFull reports the
	// bulk-data lane sitting at its hard cap while the metadata reserve holds.
	CreditSetpoint int64   `json:"creditSetpoint,omitempty"`
	CreditDebt     int64   `json:"creditDebt,omitempty"`
	CreditCeiling  int64   `json:"creditCeiling,omitempty"`
	AppliedRateBps float64 `json:"appliedRateBps,omitempty"`
	CreditWaiters  int     `json:"creditWaiters,omitempty"`
	DataLaneFull   bool    `json:"dataLaneFull,omitempty"`

	Jobs []recoveryJobRef `json:"jobs,omitempty"`
	// ParkedWALs keeps the doctor/mounts wire name for parked recovery
	// state: one entry per parked stream.
	ParkedWALs []parkedWAL `json:"parkedWals,omitempty"`
}

type delegationView struct {
	Scope    string `json:"scope"`
	Draining bool   `json:"draining,omitempty"`
	// DrainError is the recorded verdict of a release attempt that reached a
	// definite outcome. Draining and DrainError are mutually exclusive: an
	// attempt is either still in flight or it has an answer.
	DrainError string `json:"drainError,omitempty"`
}

type recoveryJobRef struct {
	JobID   string `json:"jobId"`
	State   string `json:"state"`
	Records uint64 `json:"records"`
	Bytes   uint64 `json:"bytes"`
	// Unrecovered says this job's remainder is NOT going to drain on its own —
	// it is parked, forced, conflicted or corrupt — and is therefore part of the
	// attach's unrecovered split. It is derived from State rather than reported
	// separately so the two can never disagree.
	Unrecovered bool `json:"unrecovered,omitempty"`
	// Conflicts is the typed recovery conflict set: which SCOPES are affected
	// and why. It was already carried on the durable job and dropped here, so
	// `portablefs mounts --json` and doctor could report "conflict" and nothing
	// else — an operator was told a decision was required without being told
	// what the decision was about.
	Conflicts []recoveryConflictRef `json:"conflicts,omitempty"`
	// Remedy is the one sentence an operator can act on for this job's state.
	Remedy    string `json:"remedy,omitempty"`
	LastError string `json:"lastError,omitempty"`
}

// recoveryConflictRef is one typed recovery conflict on the wire.
type recoveryConflictRef struct {
	Scope string `json:"scope"`
	Epoch string `json:"epoch,omitempty"`
	Kind  string `json:"kind"`
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
	mu         sync.RWMutex
	mutationMu sync.Mutex
	// unmountMu guards unmounting, the at-most-one-transaction-per-attach map
	// that lets a second unmount request JOIN a running transaction instead of
	// queueing another one behind it on mutationMu.
	unmountMu  sync.Mutex
	unmounting map[string]*unmountTransaction
	// testUnmountDrain replaces the normal transaction's cancellable authority
	// drain barrier so failure-shape tests can hold it open and drive a --force
	// escalation against it. Production never sets it.
	testUnmountDrain func(context.Context, func() error) (string, error)
	persistMu        sync.Mutex
	stateDir         string
	byRef            map[string]*attach
	byKey            map[string]*attach
	quiescing        bool
	loadErr          error

	// Guarded by persistMu. An empty v1 registry is semantically compatible
	// with v2, but accepting it must remain a read-only compatibility rule.
	// The first real attach mutation writes v2 through the normal persistence
	// boundary; idle persistence never performs a hidden migration.
	preserveLegacyEmpty bool

	// Debounced background persistence for the per-file identity bindings.
	// Namespace mutations must never block on (or fail with) state-file I/O:
	// the synchronous persist-per-op this replaces rewrote and fsynced the
	// FULL state file — every attach's whole item table — inside each create/
	// remove/rename, an O(items) cost that grew quadratically over a workload
	// like git clone. A synchronous O(changes) journal transaction now gates
	// Item publication, including detached lifetimes and Reclaim tombstones;
	// this debounced snapshot is only compaction. Membership changes and clean
	// shutdown still persist synchronously.
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
	// Loading can open local backing roots and inspect/migrate durable WAL
	// metadata. Production constructs registries only after owning both
	// daemon singleton locks. Start the background worker only after the
	// complete strict load succeeds; an invalid inventory therefore leaves
	// no orphan persister behind.
	defer func() {
		if r.loadErr != nil {
			for _, a := range r.byRef {
				if a.localFS != nil {
					_ = a.localFS.Close()
					a.localFS = nil
				}
			}
			close(r.persistDone)
			return
		}
		go r.persistLoop()
	}()
	loaded, loadErr := loadAttachRegistry(stateDir)
	if loadErr != nil {
		r.loadErr = loadErr
		return r
	}
	persisted := loaded.attaches
	r.preserveLegacyEmpty = loaded.preserveLegacyEmpty
	seenStorage := map[string]string{}
	for _, e := range persisted {
		req := ensureAttachRequest{
			VolumeID:            e.VolumeID,
			Branch:              e.Branch,
			AuthorityURL:        e.AuthorityURL,
			DataPlaneTransport:  e.DataPlaneTransport,
			DataPlaneServerName: e.DataPlaneServerName,
			TLSCAPEM:            e.TLSCAPEM,
			TLSCASHA256:         e.TLSCASHA256,
			MountPath:           e.MountPath,
			Options:             e.Options,
		}
		key := attachKey(req.VolumeID, req.Branch, req.MountPath)
		if r.byRef[e.Ref] != nil {
			r.loadErr = fmt.Errorf("duplicate persisted attach ref %q", e.Ref)
			return r
		}
		if r.byKey[key] != nil {
			r.loadErr = fmt.Errorf("duplicate persisted attach key volumeId=%q branch=%q mountPath=%q", req.VolumeID, req.Branch, req.MountPath)
			return r
		}
		if prior := seenStorage[storageKey(req.VolumeID, req.Branch)]; prior != "" {
			// One (volume, branch) = one WAL store = one checkout owner:
			// reviving two attaches of the same branch would corrupt it.
			r.loadErr = fmt.Errorf("persisted attach at %q conflicts with %s@%s owner at %q", req.MountPath, req.VolumeID, req.Branch, prior)
			return r
		}
		seenStorage[storageKey(req.VolumeID, req.Branch)] = req.MountPath
		a, err := newRevivedAttach(
			e.Ref, key, req, stateDir, e.IdentityEpoch,
			e.DetachPrepared, e.DetachForce, e.DetachJobID, e.Items,
		)
		if err != nil {
			r.loadErr = fmt.Errorf("revive persisted attach %s: %w", e.Ref, err)
			return r
		}
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
			if err := a.applyJournalEntry(e); err != nil {
				r.loadErr = fmt.Errorf("replay item identity journal for attach %s: %w", e.Ref, err)
				return r
			}
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

// invalidationAnchorWait bounds how long attach blocks for the authority to
// register its invalidation subscription. It only trades a slower attach for a
// smaller pre-anchor serving window: correctness comes from the anchor fence
// itself, which applies whenever the subscription lands.
var invalidationAnchorWait = 10 * time.Second

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
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	if req.VolumeID == "" || req.Branch == "" || req.AuthorityURL == "" || req.MountPath == "" {
		return nil, false, fmt.Errorf("volumeId, branch, authorityUrl, and mountPath are required")
	}
	if req.AttachRef != "" && !mountid.ValidAttachRef(req.AttachRef) {
		return nil, false, fmt.Errorf("attachRef has invalid stable identity format")
	}
	requestedLocalDirs, err := normalizeLocalDirs(req.Options.LocalDirs)
	if err != nil {
		return nil, false, err
	}
	req.Options.LocalDirs = requestedLocalDirs
	if err := (dataPlaneTransport{
		mode:       req.DataPlaneTransport,
		serverName: req.DataPlaneServerName,
		caPEM:      req.TLSCAPEM,
		caSHA256:   req.TLSCASHA256,
	}).validate(); err != nil {
		return nil, false, fmt.Errorf("invalid data-plane transport: %w", err)
	}
	key := attachKey(req.VolumeID, req.Branch, req.MountPath)
	r.mu.Lock()
	if r.quiescing {
		r.mu.Unlock()
		return nil, false, fmt.Errorf("portablefsd is quiescing for an idle stop; new attaches are refused")
	}
	if a := r.byKey[key]; a != nil {
		if req.AttachRef != "" && req.AttachRef != a.ref {
			r.mu.Unlock()
			return nil, false, fmt.Errorf("mount identity already maps to attach %s, not requested %s", a.ref, req.AttachRef)
		}
		if strings.TrimSpace(req.AuthorityURL) != a.authorityURL ||
			req.DataPlaneTransport != a.dataPlaneTransport ||
			req.DataPlaneServerName != a.dataPlaneServerName ||
			req.TLSCAPEM != a.tlsCAPEM ||
			req.TLSCASHA256 != a.tlsCASHA256 {
			r.mu.Unlock()
			return nil, false, fmt.Errorf("attach %s is already bound to a different authority transport; detach it before changing endpoint trust", a.ref)
		}
		r.mu.Unlock()
		// A revived attach has not opened its Volume yet, so resolve the
		// current mount's --no-local/volume-config choice before start reads
		// .portablefs/local-dirs. Active attaches keep their established
		// routing table; ensure remains idempotent and only adds explicit
		// grafts below.
		if err := a.activateWithOptions(ctx, req.AuthToken, req.AuthTokenExpiresAtMs, &req.Options); err != nil {
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
	// Storage identity is (volume, branch): any second attach would share one
	// WAL store and checkout owner. Persisted dormant entries are durable
	// ownership records, not stale hints; only an explicit exact detach may
	// remove one.
	for _, other := range r.byRef {
		if other.key == key || other.isDetached() ||
			other.volumeID != req.VolumeID || other.branch != req.Branch {
			continue
		}
		r.mu.Unlock()
		return nil, false, fmt.Errorf(
			"volume %s@%s already has durable attach %s at %s; detach that exact attach before mounting it elsewhere",
			req.VolumeID, req.Branch, other.ref, other.mountPath,
		)
	}
	ref := req.AttachRef
	if ref == "" {
		var err error
		ref, err = randomAttachRef()
		if err != nil {
			r.mu.Unlock()
			return nil, false, err
		}
	}
	if existing := r.byRef[ref]; existing != nil {
		r.mu.Unlock()
		return nil, false, fmt.Errorf("attachRef %s already belongs to a different mount identity", ref)
	}
	a := newAttach(ref, key, req, r.stateDir)
	a.persist = r.persist
	a.schedulePersist = r.schedulePersist
	a.journal = r.journal
	r.byRef[ref] = a
	r.byKey[key] = a
	r.mu.Unlock()
	if err := a.activate(ctx, req.AuthToken, req.AuthTokenExpiresAtMs); err != nil {
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
		_, detachErr := a.detach(ctx, true)
		return nil, false, errors.Join(err, detachErr)
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

// activate serializes credential-driven revival with every attach membership
// mutation. Resolving the ref and publishing a live Volume therefore cannot
// race an exact detach that is removing the same registry entry.
func (r *registry) activate(ctx context.Context, ref, token string, expiresAtMs int64, onlyIfPending bool) (bool, bool, error) {
	// ── A ROTATION INTO A LIVE ATTACH TAKES NO REGISTRY MUTATION LOCK ────────
	//
	// Round 15 took the mount-wide namespace lock off this path
	// (attach.rotateLiveCredential), and the registry's global mutationMu was
	// left behind — which is the same defect one level up. runUnmountTransaction
	// holds mutationMu across the ENTIRE drain barrier (clientcore's 60s
	// volumeBarrierTimeout per attempt) plus the exact kernel detach, and
	// registry.delete holds it across a full detach. Under a flood the lease
	// keeper's credential push therefore queued behind all of that, burned its
	// full 60s control timeout, and was DROPPED — so the daemon went on using a
	// credential the keeper believed it had delivered, and the ACCESS lease died
	// underneath a mount that was busy proving it was alive.
	//
	// Safe on exactly round 15's terms, and for one more reason of its own:
	//
	//   – rotateLiveCredential answers handled=false for every state whose
	//     verdict belongs to the locked path — detached, quarantined by a
	//     prepared detach, or not yet started — so those callers keep the exact
	//     error and the exact serialization they had. handled=true is only the
	//     case the locked path reduces to one setCredential and an immediate
	//     return, so the fast path is behaviour-identical where it applies.
	//   – it re-checks detached/quarantined/started under a.mu, and its
	//     remaining window (a detach that begins after that check) installs a
	//     fresh credential into a volume that is DRAINING — which is what the
	//     barrier needs to reach the authority at all, not a hazard. That window
	//     is also not new: every in-flight frontend request calls into the same
	//     Volume concurrently with a detach and always has.
	//   – it mutates no registry state, persists nothing, and starts nothing, so
	//     there is no registry invariant for mutationMu to have been protecting.
	//
	// The read below is lock-free with respect to mutationMu, so the slow path
	// RE-RESOLVES the ref after acquiring it. That is what keeps the slow path
	// identical to the code this replaced: a concurrent delete may have removed
	// the attach (answer: not found, as before) and a concurrent ensure may have
	// registered or replaced it (answer: the current attach, as before).
	r.mu.RLock()
	a := r.byRef[ref]
	r.mu.RUnlock()
	if a != nil {
		if done, handled := a.rotateLiveCredential(token, expiresAtMs, onlyIfPending); handled {
			return true, done, nil
		}
	}
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	r.mu.RLock()
	a = r.byRef[ref]
	r.mu.RUnlock()
	if a == nil {
		return false, false, nil
	}
	if onlyIfPending {
		activated, err := a.activateIfPending(ctx, token, expiresAtMs)
		return true, activated, err
	}
	return true, true, a.activate(ctx, token, expiresAtMs)
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
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	r.mu.RLock()
	a := r.byRef[ref]
	r.mu.RUnlock()
	if a == nil {
		return false, "", nil
	}
	jobID, err = a.detach(ctx, force)
	if err != nil {
		// No detach mode may unregister an attach whose required durability
		// transition failed. In particular, force is permission to park a
		// tail, not permission to discard a failed parking transaction.
		return true, jobID, err
	}
	r.mu.Lock()
	delete(r.byRef, ref)
	delete(r.byKey, a.key)
	r.mu.Unlock()
	if perr := r.persist(); perr != nil {
		// The durable entry still exists. Retain the exact detached record so
		// a retry can converge the same deletion instead of returning a false
		// 404 and reviving it on restart.
		r.mu.Lock()
		r.byRef[ref] = a
		r.byKey[a.key] = a
		r.mu.Unlock()
		err = errors.Join(err, perr)
	}
	return true, jobID, err
}

func (r *registry) unmountFSKit(ctx context.Context, ref string, force bool) (bool, string, error) {
	return r.unmountFSKitWithContext(ctx, ref, force, hostFSKitKernelOps())
}

func (r *registry) unmountFSKitWith(
	ref string,
	force bool,
	ops fskitKernelOps,
) (bool, string, error) {
	return r.unmountFSKitWithContext(context.Background(), ref, force, ops)
}

// unmountTransactionBudget is the daemon's OWN ceiling on how long one unmount
// REQUEST may take to answer, as distinct from how long the unmount TRANSACTION
// may take to finish.
//
// The two were the same thing, and that is the defect. The transaction is a
// durable, admission-freezing sequence — freeze, authority drain barrier
// (clientcore's volumeBarrierTimeout, 60s, for ONE attempt), exact kernel
// detach, durable registry removal — and it must not be abandoned partway. The
// REQUEST, on the other hand, is answered to `portablefs umount` over a control
// socket whose HTTP client gives up at 60s. Blocking the request on the whole
// transaction therefore raced the CLI's own timeout and, on an ACTIVE HEALTHY
// drain, lost: the CLI reported rc=1 with a transport-shaped error and no
// verdict at all, while the recorded-verdict refusal path answers a definite
// HTTP 409 in under a second whenever a verdict already exists.
//
// So the request gets its own bound, strictly under the CLI's, and the
// transaction keeps running detached. Past the bound the request answers the
// definite in-progress verdict, and — this is what makes it definite rather
// than a rename of the same wait — a RETRY joins the same transaction instead
// of queueing a second one behind it, so every later request answers
// immediately too.
//
// A var so failure-shape tests compress it; production never changes it.
var unmountTransactionBudget = 40 * time.Second

type unmountOutcome struct {
	found bool
	jobID string
	err   error
}

// unmountFSKitWithContext answers ONE unmount request within the transaction's
// ABSOLUTE remaining budget. There is exactly ONE transaction per attach ref;
// every later request — including a --force — joins it rather than queueing a
// second one behind it.
//
// ── FORCE ESCALATES, IT DOES NOT RACE ───────────────────────────────────────
//
// Force used to start a SEPARATE transaction. Both transactions then took the
// registry's global mutationMu, and the normal one holds it across the whole
// authority drain barrier and the exact kernel detach. So --force — the escape
// hatch from precisely that wait — parked behind it, burned the full request
// budget, and returned having fenced nothing, parked nothing, and started no
// recovery job. The one command whose entire purpose is to preempt the drain
// could not preempt it.
//
// Force is now an ESCALATION of the running transaction, applied atomically:
// the transaction is marked forced and its drain is CANCELLED, and the
// transaction — which already owns the mutation lock — takes the journal-first
// park/fence path itself, before anything irreversible. The park/fence phase is
// therefore reachable without ever waiting on the normal drain's mutex, because
// it runs on the goroutine that holds it.
func (r *registry) unmountFSKitWithContext(
	ctx context.Context,
	ref string,
	force bool,
	ops fskitKernelOps,
) (bool, string, error) {
	r.unmountMu.Lock()
	if r.unmounting == nil {
		r.unmounting = map[string]*unmountTransaction{}
	}
	tx := r.unmounting[ref]
	if tx == nil {
		tx = &unmountTransaction{
			done:     make(chan struct{}),
			escalate: make(chan struct{}),
			force:    force,
			deadline: time.Now().Add(unmountTransactionBudget),
		}
		r.unmounting[ref] = tx
		go func() {
			found, jobID, err := r.runUnmountTransaction(ref, tx, ops)
			// THE OUTCOME IS PUBLISHED BEFORE THE TRANSACTION BECOMES
			// UNDISCOVERABLE. Removing the entry first opened a window in which
			// a retry saw no running transaction and STARTED A SECOND ONE
			// against an attach the first had already detached, and in which a
			// joiner's expiring timer could report "unknown attach" for a
			// detach that had just succeeded. A request that finds the entry in
			// that window now joins a transaction that is already resolved and
			// reads its terminal outcome immediately.
			tx.outcome = unmountOutcome{found: found, jobID: jobID, err: err}
			close(tx.done)
			r.unmountMu.Lock()
			if r.unmounting[ref] == tx {
				delete(r.unmounting, ref)
			}
			r.unmountMu.Unlock()
		}()
	} else if force && !tx.force {
		// ESCALATE the running normal transaction in place.
		tx.force = true
		close(tx.escalate)
	}
	deadline := tx.deadline
	r.unmountMu.Unlock()

	// ONE ABSOLUTE DEADLINE for the transaction, not a fresh budget per joiner:
	// a request that joins a transaction 39 seconds old must not wait another
	// 40, or a caller retrying on the CLI's advice never reaches a verdict.
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-tx.done:
		return tx.outcome.found, tx.outcome.jobID, tx.outcome.err
	case <-ctx.Done():
		// Only THIS waiter gave up. The transaction owns durable state and
		// keeps running; it is never abandoned by a departing joiner.
		select {
		case <-tx.done:
			return tx.outcome.found, tx.outcome.jobID, tx.outcome.err
		default:
		}
		return true, "", r.unmountInProgressVerdict(ref, ctx.Err())
	case <-timer.C:
		// The timer and completion can fire together; completion wins.
		select {
		case <-tx.done:
			return tx.outcome.found, tx.outcome.jobID, tx.outcome.err
		default:
		}
		return true, "", r.unmountInProgressVerdict(ref, nil)
	}
}

// unmountTransaction is one running detach, shared by every request that
// observes it. outcome is written exactly once, before done closes.
//
// force and escalate are the escalation channel: force is read under
// registry.unmountMu by the transaction goroutine at each decision point, and
// escalate is closed exactly once, by the force request that upgraded a normal
// transaction, so an in-flight drain can be cancelled.
type unmountTransaction struct {
	done     chan struct{}
	escalate chan struct{}
	deadline time.Time
	force    bool
	outcome  unmountOutcome
}

// escalated reports whether this transaction has been upgraded to a force.
func (r *registry) escalated(tx *unmountTransaction) bool {
	r.unmountMu.Lock()
	defer r.unmountMu.Unlock()
	return tx.force
}

// unmountInProgressVerdict is the definite answer to a request whose budget
// expired with the transaction still running. It NAMES what the transaction is
// waiting on and what to do next — the same shape as the recorded-verdict
// refusal — so the CLI reports a verdict instead of a transport failure.
// waiterErr, when non-nil, says this particular request's own context ended;
// the transaction is unaffected.
func (r *registry) unmountInProgressVerdict(ref string, waiterErr error) error {
	r.mu.RLock()
	a := r.byRef[ref]
	r.mu.RUnlock()
	if a == nil {
		// The attach is already out of the registry while the transaction is
		// still finishing its durable tail. This is NOT an unknown attach —
		// saying so told a caller their unmount had never been seen moments
		// after it succeeded.
		return fmt.Errorf(
			"unmount of %s is in its final durable phase; the attach is already "+
				"detached — re-run `portablefs umount` to join it for the verdict%s",
			ref, waiterSuffix(waiterErr),
		)
	}
	detail := "the authority drain barrier"
	if st := a.liveWriteBackStatus(); st != nil {
		scope := ""
		for _, d := range st.Delegations {
			if d.Draining {
				scope = d.Scope
				break
			}
		}
		switch {
		case scope != "":
			detail = fmt.Sprintf(
				"the delegation release for scope %q with %d record(s) (%d bytes) unshipped",
				scope, st.PendingRecords, st.PendingBytes,
			)
		case st.PendingRecords > 0:
			detail = fmt.Sprintf(
				"the authority drain barrier with %d record(s) (%d bytes) unshipped",
				st.PendingRecords, st.PendingBytes,
			)
		}
	}
	return fmt.Errorf(
		"unmount is still running after %s, waiting on %s; it continues in the "+
			"background — re-run `portablefs umount` to join it, or "+
			"`portablefs umount --force` to park the unshipped tail as a durable "+
			"recovery job%s",
		unmountTransactionBudget, detail, waiterSuffix(waiterErr),
	)
}

func waiterSuffix(waiterErr error) string {
	if waiterErr == nil {
		return ""
	}
	return fmt.Sprintf(" (this request stopped waiting: %v)", waiterErr)
}

type fskitKernelOps struct {
	present func(mountPath, attachRef string) (bool, error)
	// unmountExact detaches the exact kernel mount for attachRef. force asks
	// the kernel to detach a BUSY mount (MNT_FORCE) rather than answering
	// EBUSY.
	//
	// The flag exists because `umount --force` did not previously reach the
	// kernel as a force at all: every path called unmount(2) with flags 0, so a
	// single open reference anywhere in the mount — including one held by this
	// product's own mount supervisor — refused the escape hatch that exists
	// precisely to abandon a mount whose references cannot be recovered. The
	// normal path still passes false: a clean unmount that would need MNT_FORCE
	// is not a clean unmount, and forcing it silently would hide exactly the
	// leaked-reference defects the flag was added to stop papering over.
	unmountExact func(mountPath, attachRef string, force bool) error
}

// runUnmountTransaction owns the complete admission-freeze → durability
// barrier → exact kernel detach → registry removal transaction. It runs
// DETACHED from the request that started it (see unmountTransactionBudget):
// abandoning it partway would leave durable state without an owner.
func (r *registry) runUnmountTransaction(
	ref string,
	tx *unmountTransaction,
	ops fskitKernelOps,
) (bool, string, error) {
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	r.mu.RLock()
	a := r.byRef[ref]
	r.mu.RUnlock()
	if a == nil {
		return false, "", nil
	}
	force := r.escalated(tx)
	a.mu.RLock()
	prepared := a.detachPrepared
	forceAuthorized := a.detachForce
	jobID := a.detachJobID
	failFrozen := a.detachFailFrozen
	a.mu.RUnlock()
	if failFrozen {
		return true, jobID, fmt.Errorf("attach admissions are fail-frozen because the prepared-detach abort could not be persisted; restart portablefsd to reconcile the durable marker")
	}
	switch {
	case prepared:
		present, err := ops.present(a.mountPath, ref)
		if err != nil {
			return true, jobID, fmt.Errorf("classify prepared FSKit detach: %w", err)
		}
		if present {
			// A PREPARED detach is being reconciled, and it is reconciled
			// under whatever authorization the caller carries: an escalated or
			// force-authorized reconciliation is still a force.
			if err := ops.unmountExact(
				a.mountPath, ref, forceAuthorized || force,
			); err != nil {
				return true, jobID, err
			}
		}
		a.frontendSerial.Lock()
		a.nsMu.Lock()
		if _, err := a.finishDetachWithNSLocked("", nil); err != nil {
			return true, jobID, err
		}
	case forceAuthorized || force:
		var err error
		jobID, err = r.forceUnmountFSKit(a, forceAuthorized, ops)
		if err != nil {
			return true, jobID, err
		}
	default:
		a.mu.RLock()
		volumeActive := a.vol != nil && !a.credentialPending
		a.mu.RUnlock()
		if !volumeActive {
			return true, "", fmt.Errorf("normal FSKit detach requires an active credentialed volume to prove the final authority barrier")
		}
		// THE DRAIN IS CANCELLABLE BY ESCALATION. A --force arriving while this
		// barrier is running closes tx.escalate; the drain then unwinds
		// promptly and this same goroutine — which already owns mutationMu —
		// takes the journal-first park/fence path, so force never queues behind
		// the wait it exists to escape.
		drainCtx, cancelDrain := context.WithCancel(context.Background())
		drainDone := make(chan struct{})
		go func() {
			select {
			case <-tx.escalate:
				cancelDrain()
			case <-drainDone:
			}
		}()
		drain := a.detachWithFinalizerContext
		if r.testUnmountDrain != nil {
			drain = r.testUnmountDrain
		}
		_, err := drain(drainCtx, func() error {
			a.mu.Lock()
			a.detachPrepared = true
			a.mu.Unlock()
			if err := r.persist(); err != nil {
				a.mu.Lock()
				a.detachPrepared = false
				a.mu.Unlock()
				return fmt.Errorf("persist prepared FSKit detach: %w", err)
			}
			present, err := ops.present(a.mountPath, ref)
			if err == nil && present {
				// A CLEAN unmount is never a force. If this mount is busy, the
				// honest answer is EBUSY and the reference that holds it is a
				// defect to find, not one to force past.
				err = ops.unmountExact(a.mountPath, ref, false)
			}
			if err != nil {
				a.mu.Lock()
				a.detachPrepared = false
				a.mu.Unlock()
				if persistErr := r.persist(); persistErr != nil {
					// The durable registry may still say prepared. Restore the
					// in-memory fail-frozen quarantine before releasing nsMu;
					// every admission rechecks it, while shutdown remains able
					// to acquire the namespace lock and report the failure.
					a.mu.Lock()
					a.detachPrepared = true
					a.detachFailFrozen = true
					a.mu.Unlock()
					return &preparedDetachAbortDurabilityError{
						cause: errors.Join(err, fmt.Errorf("durably abort prepared FSKit detach: %w", persistErr)),
					}
				}
				return err
			}
			return nil
		})
		close(drainDone)
		cancelDrain()
		if err != nil {
			// An ESCALATION that aborted this drain is not a failed unmount: it
			// is the same transaction changing decision. Take the journal-first
			// park/fence path now, on the goroutine that already holds
			// mutationMu, before anything irreversible has happened. Any other
			// error is the normal transaction's own definite failure.
			if r.escalated(tx) {
				forcedJobID, forceErr := r.forceUnmountFSKit(a, false, ops)
				if forceErr != nil {
					return true, forcedJobID, forceErr
				}
				jobID = forcedJobID
			} else {
				return true, "", err
			}
		}
		// If the drain WON the race with an escalation, the normal detach is
		// complete and durable — strictly stronger than parking the tail — and
		// that is the outcome every joiner, force or not, is given.
	}
	r.mu.Lock()
	delete(r.byRef, ref)
	delete(r.byKey, a.key)
	r.mu.Unlock()
	if err := r.persist(); err != nil {
		// Keep the exact detached object retryable until durable removal.
		r.mu.Lock()
		r.byRef[ref] = a
		r.byKey[a.key] = a
		r.mu.Unlock()
		return true, jobID, err
	}
	return true, jobID, nil
}

// preparedDetachAbortDurabilityError means the exact unmount failed and the
// prepared marker could not be synchronously cleared. The attach remains
// explicitly quarantined; every admission rejects its prepared/fail-frozen
// state while the namespace mutex stays releasable for clean shutdown.
type preparedDetachAbortDurabilityError struct {
	cause error
}

func (e *preparedDetachAbortDurabilityError) Error() string { return e.cause.Error() }
func (e *preparedDetachAbortDurabilityError) Unwrap() error { return e.cause }

// forceUnmountFSKit durably records the user's force authorization before the
// irreversible journal close, then records the resulting recovery handle
// (including the explicit empty-handle/zero-tail case) before exact detach.
// The caller owns registry.mutationMu.
func (r *registry) forceUnmountFSKit(
	a *attach,
	forceAlreadyAuthorized bool,
	ops fskitKernelOps,
) (string, error) {
	a.frontendSerial.Lock()
	a.nsMu.Lock()
	a.mu.RLock()
	if a.detached {
		jobID := a.detachJobID
		a.mu.RUnlock()
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
		return jobID, nil
	}
	vol := a.vol
	jobID := a.detachJobID
	prepared := a.detachPrepared
	a.mu.RUnlock()

	if !forceAlreadyAuthorized {
		a.mu.Lock()
		a.detachForce = true
		a.mu.Unlock()
		if err := r.persist(); err != nil {
			a.mu.Lock()
			a.detachForce = false
			a.mu.Unlock()
			a.nsMu.Unlock()
			a.frontendSerial.Unlock()
			return "", fmt.Errorf("persist forced FSKit detach authorization: %w", err)
		}
	}

	if !prepared {
		if vol == nil {
			storeDir := filepath.Join(a.stateDir, "wal", a.storageID)
			storeIdentity, ok := readWALIdentity(storeDir)
			if !ok || storeIdentity.VolumeID != a.volumeID || storeIdentity.Branch != a.branch {
				a.nsMu.Unlock()
				a.frontendSerial.Unlock()
				return jobID, fmt.Errorf("forced FSKit detach store identity does not match exact attach %s@%s", a.volumeID, a.branch)
			}
			if legacy := a.legacyWALs(); len(legacy) != 0 {
				a.nsMu.Unlock()
				a.frontendSerial.Unlock()
				return jobID, fmt.Errorf("forced FSKit detach refuses %d unresolved legacy WAL(s); exact offline parking is available only for the PFW5 store", len(legacy))
			}
			proof, err := writeback.ForceParkAbandonedStore(
				storeDir,
				a.volumeID,
				a.branch,
				a.ref,
				"explicit forced FSKit unmount after portablefsd owner restart",
			)
			if err != nil {
				a.nsMu.Unlock()
				a.frontendSerial.Unlock()
				return jobID, fmt.Errorf("durably park abandoned FSKit store: %w", err)
			}
			if len(proof.JobIDs) != 0 {
				jobID = proof.JobIDs[len(proof.JobIDs)-1]
			}
			prepared = true
		} else {
			parkedJobID, closeErr := vol.CloseJournalDurable()
			if parkedJobID != "" {
				jobID = parkedJobID
			}
			if closeErr != nil {
				a.mu.Lock()
				a.detachJobID = jobID
				a.mu.Unlock()
				if err := r.persist(); err != nil {
					a.nsMu.Unlock()
					a.frontendSerial.Unlock()
					return jobID, fmt.Errorf("persist forced FSKit recovery handle: %w", err)
				}
				a.nsMu.Unlock()
				a.frontendSerial.Unlock()
				return jobID, fmt.Errorf("durably park forced FSKit tail: %w", closeErr)
			}
			prepared = true
		}
		a.mu.Lock()
		a.detachPrepared = prepared
		a.detachJobID = jobID
		a.mu.Unlock()
		if err := r.persist(); err != nil {
			a.nsMu.Unlock()
			a.frontendSerial.Unlock()
			return jobID, fmt.Errorf("persist forced FSKit detach proof: %w", err)
		}
	}

	// The exact kernel detach re-enters this daemon through vnode reclaim;
	// never hold the admission freeze across it (see detachWithFinalizer).
	a.nsMu.Unlock()
	a.frontendSerial.Unlock()
	present, err := ops.present(a.mountPath, a.ref)
	if err == nil && present {
		// THE FORCE PATH FORCES. Its entire purpose is to detach a mount whose
		// remaining references cannot be recovered; asking the kernel for a
		// polite detach here made `umount --force` fail for exactly the reason
		// it was invoked.
		err = ops.unmountExact(a.mountPath, a.ref, true)
	}
	if err != nil {
		// Force authorization and the parked-tail proof remain durable.
		// Operations are quarantined until an exact retry succeeds.
		return jobID, err
	}
	a.frontendSerial.Lock()
	a.nsMu.Lock()
	return a.finishDetachWithNSLocked(jobID, nil)
}

// closeAll is the cooperative daemon-termination path. Every attach must pass
// its normal authority durability barrier. A failed drain remains a visible
// shutdown failure; this path never changes semantics by force-detaching or
// parking a recovery job.
func (r *registry) closeAll(ctx context.Context) error {
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
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
	ref                 string
	key                 string
	volumeID            string
	branch              string
	authorityURL        string
	authorityAddr       string
	dataPlaneTransport  string
	dataPlaneServerName string
	tlsCAPEM            string
	tlsCASHA256         string
	mountPath           string
	volumeName          string
	storageID           string
	options             AttachOptions
	stateDir            string
	identityEpoch       uint64
	persist             func() error
	// schedulePersist requests a debounced background persist. Per-file
	// namespace mutations use it instead of persist: they must never block
	// on, or fail with, state-file I/O.
	schedulePersist func()
	// journal receives binding deltas (see bindingjournal.go); pendingBindings
	// buffers them under a.mu until flushBindingDelta drains to the journal.
	journal         *bindingJournal
	pendingBindings []bindingJournalEntry
	// expectedTruncates marks the kernel-size refresh truncates the daemon
	// itself issues through the mount so the setattr handler can consume them
	// without touching the authority.
	expectedTruncates map[string]expectedTruncate
	// expectedTruncateSeq names each marker uniquely, so the refresh that
	// installed one retires exactly that one and a later marker for the same
	// path is never mistaken for it.
	expectedTruncateSeq uint64
	// Exact refreshes for one item are one sample→truncate/page-invalidate→
	// verify transaction. Context-selectable channel stripes bound memory,
	// prevent concurrent passes from overwriting each other's truncate
	// marker, and let attach shutdown cancel a waiter even while another
	// colliding item is inside a slow kernel msync.
	kernelRefreshGateMu sync.Mutex
	kernelRefreshGates  [64]chan struct{}

	// frontendGate extends a handoff through FSKit's explicit publication
	// acknowledgement. Admission is scope-aware: disjoint subtrees continue
	// concurrently, while overlapping replies complete before Checkin.
	frontendGateMu   sync.Mutex
	frontendGateCond *sync.Cond
	frontendActive   map[*frontendOperation]struct{}
	frontendHandoffs map[string]int
	// frontendGateProgress counts every RETRACTION from the active publication
	// set. It is the publication gate's progress clock: a handoff's settle
	// window (publicationSettleWindow) is measured from the last time this
	// advanced, so a gate that keeps clearing operations never reaches a stall
	// verdict however long it is busy, while a gate that has stopped clearing
	// them reaches a definite one. Guarded by frontendGateMu.
	frontendGateProgress uint64
	// frontendGateErr is the terminal correctness verdict observed by
	// handoffs while they hold frontendGateMu. It wakes and aborts a handoff
	// that was already waiting when the attach failed closed.
	frontendGateErr error
	// frontendPathEpoch changes whenever an FSItem/handle path binding can
	// change. Publication operations snapshot it with their resolved aliases;
	// a mismatch at handoff is conservatively mount-wide, closing the narrow
	// race where a namespace mutation moves an in-flight operation.
	frontendPathEpoch atomic.Uint64

	credMu sync.RWMutex
	token  string
	// tokenExpiresAtMs is the access lease's OWN stated expiry for token
	// (unix ms; 0 = the caller stated none). It travels with the credential
	// so the mount can bound the UNPROVEN state: past this instant a
	// credential no handshake ever accepted or refused hardens into the
	// definite expired verdict instead of pending forever. Old CLIs send
	// nothing, land on 0, and keep the pre-expiry behaviour exactly.
	tokenExpiresAtMs int64

	// lifeCtx scopes everything that must live for the whole ATTACH, not for
	// the control request that happened to start it. `POST .../credential`
	// activates a restored (credential-pending) attach from an HTTP handler,
	// and its r.Context() is cancelled the moment that handler returns — a
	// request-scoped context handed to the Volume and to the invalidation
	// watcher therefore killed cross-machine coherence within milliseconds of
	// a successful activation, silently and for the life of the mount.
	lifeCtx    context.Context
	lifeCancel context.CancelFunc

	startMu sync.Mutex

	mu        sync.RWMutex
	nsMu      sync.RWMutex
	nameLocks [64]sync.Mutex
	// frontendSerial, frontendNameLocks, and each handle's frontend operation
	// lock mirror the concrete namespace lock classes at the protocol
	// boundary. A request acquires them before entering the publication gate,
	// so an admitted operation can never sit behind a lock held by the
	// operation whose delegation handoff is waiting for that admission to
	// publish.
	frontendSerial    sync.RWMutex
	frontendNameLocks [64]sync.Mutex
	vol               *clientcore.Volume
	eventClient       *fsproto.Client
	state             pfslocal.AttachStateState
	lastErr           string
	// Terminal for this attach lifetime: once a correctness-bound kernel
	// refresh fails, authority visibility was not proven. Operations fail
	// closed until an explicit unmount/restart.
	coherenceFailFrozen bool
	// coherenceRepairs counts kernel coherence repairs currently running for
	// this attach. It is the RECOVERABLE counterpart of coherenceFailFrozen:
	// the daemon could not prove some kernel state, is actively rewriting it
	// through the mount, and keeps serving meanwhile. Nonzero reports the
	// attach as degraded-with-a-reason; reaching zero clears that report,
	// because a repair that converged has discharged its debt. Guarded by mu.
	coherenceRepairs int
	// coherenceRepairGaveUp records that some repair exhausted its budget. It
	// makes that reason STICKY — unlike the transient repairing state, it is
	// never cleared by a later repair converging, because it is the only record
	// that a piece of kernel state was never proven. It still does not fail
	// admissions closed. Guarded by mu.
	coherenceRepairGaveUp bool
	// detachBarrier is set while this attach's FINAL drain/release barrier is
	// running — the window inside vol.Close/CloseWithFinalizerContext in which a
	// delegation release takes a publication handoff. It is the earliest point
	// at which the kernel cache this mount owns is provably going away, and it
	// is strictly earlier than detachPrepared/detached, which are only set AFTER
	// that barrier has already succeeded. publicationBlockersLocked needs the
	// earlier signal, because the barrier is precisely what used to be refused.
	// Guarded by mu.
	detachBarrier     bool
	credentialPending bool
	root              *itemRecord
	items             map[uint64]*itemRecord
	paths             map[string]*itemRecord
	itemAliases       map[uint64]map[string]struct{}
	// authorityItems is the second half of frontend identity. items maps the
	// stable ItemID already published to FSKit; authorityItems maps the inode
	// later assigned by the authority back to that same Item and NodeState.
	// The identities differ for a create born under a delegation.
	authorityItems         map[uint64]frontendItemIdentity
	awaitingAuthorityItems map[uint64]struct{}
	// reincarnatedAliases maps each retained hard-link alias whose cached
	// attributes were taken BEFORE a pathname reincarnation displaced their
	// inode to its unit of reconciliation work. The publisher that detected the
	// reincarnation must settle its OWN ticket before its reply leaves; see
	// reincarnation.go for why the ownership is load-bearing. Guarded by mu.
	reincarnatedAliases map[string]*aliasReconcileState
	// reincarnationArmed/reincarnationOwner attribute newly created debt to the
	// registration that created it. They are set only across a registration
	// running under mu, so they need no lock of their own beyond mu itself, and
	// they nest (see reincarnationOwnerScope).
	reincarnationArmed bool
	reincarnationOwner *reincarnationTicket
	// reincarnationSettling marks the ONE registration that is a reconciliation
	// paying its own debt, so publication admission does not treat it as another
	// publisher arriving over unsettled state and bump the requirement it is in
	// the middle of satisfying. See beginReincarnationSettleLocked.
	reincarnationSettling bool
	// itemMutations is the set of items with a size mutation somewhere between
	// its ENGINE COMMIT and its REGISTRY PUBLICATION. The refresh fence needs
	// it because itemRecord.attr witnesses only the second of those two events,
	// so an acknowledged extension is invisible to the fence for the whole gap
	// between them. See mutationseq.go. Guarded by mu.
	itemMutations map[uint64]itemMutationSeq
	// refreshPins and sizeMutationReservations are the two halves of the
	// item-scoped size-mutation token (refreshpin.go). A pin is one refresh's
	// ownership of an item's size for the extent of its unix.Ftruncate(2); a
	// reservation is one admitted size mutation's claim on the same item, held
	// from pre-lock admission until its handler has published. A refresh may not
	// arm over a reservation, and a mutation waits out a pin — which is what
	// makes the ftruncate a linearization point rather than a checked guess.
	// Both guarded by mu.
	refreshPins              map[uint64]*refreshPin
	sizeMutationReservations map[uint64]int
	// refreshIntents is the third half — the FAIRNESS half — of the same
	// protocol (refreshintent.go). A pending refresh declares an intent on the
	// item before it samples: reservations already outstanding drain on their
	// own terms, arriving ones QUEUE, and the pass pins the item the moment the
	// last outstanding one is released. Without it a refresh could only re-check
	// what was reserved at each of its stale-sample ticks, so ordinary
	// contention — one slow mutation, or a stream of overlapping writers —
	// exhausted its whole budget and fail-froze the mount. Guarded by mu.
	refreshIntents map[uint64]*refreshIntent
	// itemTurnstiles is the ORDER the other three are served in
	// (itemturnstile.go). Every refresh intent and every size-mutation
	// reservation takes a numbered ticket under mu, and the item is handed to
	// the head of that queue inside the same hold that gives it up. Without it
	// the intent's fairness ran one way only: a queued mutation was recorded
	// nowhere, so the next refresh pass off the kernel-refresh gate could take
	// the item ahead of it every time an invalidation arrived, and the writer
	// spent its whole operation deadline without attempting anything. Guarded
	// by mu.
	itemTurnstiles map[uint64]*itemTurnstile
	// repairPublicationWatches is the crossed-scope repair's convergence witness
	// (repairwitness.go): a per-item MONOTONIC generation of the committed size
	// publications this daemon has actually delivered to the kernel, plus a
	// reference count of the repairs currently watching that item.
	//
	// It is how such a repair converges on a continuously written file instead
	// of spending its whole budget being preempted (coherence_refresh.go), and
	// it replaces a resettable per-item counter that (a) credited ANY attribute
	// assignment made while ANY reservation existed — a getattr's pre-write
	// observation discharged the debt of the write that had not committed yet —
	// and (b) was reset by every new watcher and deleted by every stop, so two
	// repairs on one item blinded each other.
	//
	// It is a watch rather than a census on purpose: an entry exists only while
	// some repair is outstanding for that item, so this map is the size of the
	// in-flight repair set and never of the working set. Guarded by mu.
	repairPublicationWatches map[uint64]*repairPublicationWatch
	handles                  map[uint64]*handleRecord
	localDirs                []string
	localRoot                string
	localFS                  *confinedfs.Root
	localVersions            map[string]uint64
	// legacyParked lists adopted pre-v5 session WALs whose unresolved replay
	// blocks attach readiness (see legacydrain.go); merged into status
	// ParkedWALs for dormant/revived attaches.
	legacyParked []parkedWAL
	nextHandle   uint64
	// retiredCloseErrnos keeps the rare terminal close(2) outcome so a
	// CloseRequest whose reply was lost can replay the exact retirement
	// confirmation. Successful retirements need no entry: handle IDs are
	// monotonic for the attach, so an issued-but-absent ID proves success.
	retiredCloseErrnos map[uint64]int32
	nextOrigin         uint64
	subscribers        map[*eventSubscriber]struct{}
	conns              map[interface{ Close() error }]struct{}
	eventReady         chan struct{}
	eventOnce          sync.Once
	detached           bool
	detachPrepared     bool
	detachForce        bool
	// detachFailFrozen is process-local. The durable prepared marker and this
	// explicit flag reject every admission, while nsMu remains releasable so
	// daemon shutdown/restart can perform the required recovery.
	detachFailFrozen bool
	// Retained across a registry-persist failure so retrying the exact forced
	// delete returns the same durable recovery handle.
	detachJobID string

	// Test seam for deterministic frontend ordering tests; nil in production.
	testLookupAfterVolume func(path string)
	// Test seam for the secure kernel refresh syscall; nil in production.
	testRefreshKernelFile  func(mount, path string, itemID uint64, size int64, armTruncate func() (func(), error)) (kernelRefreshOutcome, error)
	testExactKernelRefresh func(context.Context, uint64) error
	// testMutationAdmissionBarrier stands in, for tests, for the pre-lock
	// admission park a real metadata or credit lane can impose. It exists to make
	// the dispatcher-ordering contract testable: a request held here must be
	// holding no frontend lock at all.
	//
	// It receives the ADMISSION context, because that is exactly what the
	// delegation release the real classifier performs carries: the engine
	// overlays the triggering context's VALUES onto its own so a frontend
	// handoff hook can identify the in-flight operation the release belongs to
	// (writeback.prepareReleaseLocked). A barrier handed anything else cannot
	// stand in for that step — it would drop the publication identity that
	// decides whether a handoff is waiting on its own operation.
	testMutationAdmissionBarrier func(ctx context.Context)
	// testForcedDetachFenced fires the instant a forced detach has parked its
	// tail and fenced, BEFORE it takes the namespace locks. It exists to make
	// that ordering testable: the escape hatch must reach its fence whatever is
	// holding the namespace.
	testForcedDetachFenced func()
	// testControlAdmissionProbe is called with the control plane's resolved
	// operation context at the moment its pre-lock admission completes, so a test
	// can observe both halves of the contract: what the namespace gate is doing
	// and what bound the mutation will run under.
	testControlAdmissionProbe func(context.Context)
	// Test seam standing in for a NodeState mutex the recall path is about to
	// contend for. It runs at exactly the point onMarkOrphan would block on
	// n.mu, so a test can assert the recall path is not holding a.mu there.
	testBeforeMarkOrphan func()
	// testAfterWriteCommit fires at the ONE instant this daemon's registry is
	// provably behind the engine: the write has committed and been counted, and
	// writeReplyWithAttr has not yet published its post-op attributes. It exists
	// because that gap is not otherwise reachable from a test, and it is exactly
	// the gap the per-item mutation sequence covers (see mutationseq.go).
	testAfterWriteCommit func()
	// testControlWriteRefreshFails stands in for the control write's OPTIONAL
	// trailing attribute refresh failing — a transient authority error arriving
	// after a commit that has already happened. It exists because that is the
	// interleaving in which the control path used to register its PRE-write
	// attributes and settle the item's mutation sequence over them, and it is
	// not otherwise reachable from a test: the refresh is served from the
	// engine's own overlay or from a cache the mutation just filled. nil in
	// production.
	testControlWriteRefreshFails func() bool
	// testAfterLocalFileWrite fires on the graft arm of a control replacement
	// write at the instant the HOST inode has committed and nothing has been
	// registered for it yet. It is the graft twin of testAfterWriteCommit, and
	// it exists for the same reason: the step that follows the commit is a stat
	// that can fail on its own terms, and that failure used to return an errno
	// for a size change that had really happened with nothing recorded anywhere.
	// nil in production.
	testAfterLocalFileWrite func(path string)
	// testSizeMutationQueued fires when an admitted size mutation cannot take the
	// item immediately and must wait for its turn, holding no frontend lock at
	// all. It exists because that instant is the whole of the fairness question:
	// a test standing here can arrange for another refresh to arrive AFTER the
	// mutation has queued and prove the item is not handed to it first. nil in
	// production.
	testSizeMutationQueued func(itemID uint64)
	// testSessionFenced substitutes for the volume's fence predicate. See
	// attach.sessionFenced.
	testSessionFenced func() bool
	// testControlWriteAuthorityTarget fires at the instant a control write has
	// resolved the identity the AUTHORITY binds to its pathname and is about to
	// mutate it. It exists because the local registry cannot fence a remote
	// namespace change: a test standing here is the only way to compare the
	// identity actually being mutated with the one this attempt reserved. nil in
	// production.
	testControlWriteAuthorityTarget func(authorityIno uint64)
	// testRefreshWindowTeardown fires at the instant one refresh window's PIN
	// has become invisible — removed from a.refreshPins and its waiters woken —
	// with a.mu released. It exists because the teardown of a window is two
	// removals, and a test has no other way to stand at the point BETWEEN them
	// if they are not one step: the marker states "the daemon is inside its own
	// ftruncate" and the pin is what makes that true, so a marker still visible
	// here is a provenance claim with nothing behind it. nil in production.
	testRefreshWindowTeardown func(path string, itemID uint64)
}

type itemRecord struct {
	item  pfslocal.Item
	path  string
	state *clientcore.NodeState
	attr  fsproto.Attr
	// graft is immutable Item provenance. Path inference is insufficient:
	// an authority ancestor rename remaps a graft root while a detached
	// Item's remembered path intentionally remains stale until Reclaim.
	graft bool
}

type frontendItemIdentity struct {
	item  pfslocal.Item
	state *clientcore.NodeState
}

// handleOperationLocks coordinate operations for one descriptor at both sides
// of the frontend publication gate. Ordinary operations remain concurrent
// readers; Close is the descriptor-local writer. The locks are intentionally
// distinct: frontend is acquired before a request becomes publication-active,
// while concrete is acquired after nsMu. Reusing one lock at both layers
// would recursively acquire it in the same request.
type handleOperationLocks struct {
	frontend sync.RWMutex
	concrete sync.RWMutex
}

type handleRecord struct {
	id       uint64
	itemID   uint64
	path     string
	openPath string
	state    *clientcore.NodeState
	write    bool
	// appendOnly records O_APPEND as a sticky descriptor property (POSIX: the
	// flag lives on the open file description, not on the write). Every write
	// through this handle resolves its offset at EOF under the authority's
	// serialization instead of at the frontend-supplied absolute offset.
	appendOnly bool
	// operationLocks is a pointer because handle records are copied when an
	// operation resolves its target. Every copy must retain the descriptor's
	// one serialization identity.
	operationLocks *handleOperationLocks
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
	// Both admission and strict persisted-inventory loading validate and
	// canonicalize this list before construction.
	localDirs := append([]string(nil), req.Options.LocalDirs...)
	storageID := stableStorageID(storageKey(req.VolumeID, req.Branch))
	options := req.Options
	options.LocalDirs = localDirs
	lifeCtx, lifeCancel := context.WithCancel(context.Background())
	return &attach{
		lifeCtx:                lifeCtx,
		lifeCancel:             lifeCancel,
		ref:                    ref,
		key:                    key,
		volumeID:               req.VolumeID,
		branch:                 req.Branch,
		authorityURL:           strings.TrimSpace(req.AuthorityURL),
		authorityAddr:          normalizeAuthority(req.AuthorityURL),
		dataPlaneTransport:     req.DataPlaneTransport,
		dataPlaneServerName:    req.DataPlaneServerName,
		tlsCAPEM:               req.TLSCAPEM,
		tlsCASHA256:            req.TLSCASHA256,
		mountPath:              req.MountPath,
		volumeName:             name,
		storageID:              storageID,
		options:                options,
		stateDir:               stateDir,
		identityEpoch:          1,
		token:                  req.AuthToken,
		tokenExpiresAtMs:       req.AuthTokenExpiresAtMs,
		state:                  pfslocal.AttachStateAttached,
		items:                  map[uint64]*itemRecord{},
		paths:                  map[string]*itemRecord{},
		itemAliases:            map[uint64]map[string]struct{}{},
		authorityItems:         map[uint64]frontendItemIdentity{},
		awaitingAuthorityItems: map[uint64]struct{}{},
		handles:                map[uint64]*handleRecord{},
		retiredCloseErrnos:     map[uint64]int32{},
		subscribers:            map[*eventSubscriber]struct{}{},
		conns:                  map[interface{ Close() error }]struct{}{},
		eventReady:             make(chan struct{}),
		localDirs:              localDirs,
		localRoot:              filepath.Join(stateDir, "local", storageID),
		localVersions:          map[string]uint64{},
	}
}

func newRevivedAttach(
	ref, key string,
	req ensureAttachRequest,
	stateDir string,
	identityEpoch uint64,
	detachPrepared bool,
	detachForce bool,
	detachJobID string,
	items []persistedItemRecord,
) (*attach, error) {
	a := newAttach(ref, key, req, stateDir)
	a.detachPrepared = detachPrepared
	a.detachForce = detachForce
	a.detachJobID = detachJobID
	if len(a.localDirs) > 0 {
		root, err := confinedfs.Open(a.localRoot, 0o700)
		if err != nil {
			return nil, fmt.Errorf("open persisted local-dir backing: %w", err)
		}
		a.localFS = root
	}
	if identityEpoch != 0 {
		a.identityEpoch = identityEpoch
	}
	a.token = ""
	a.tokenExpiresAtMs = 0
	a.credentialPending = true
	a.state = pfslocal.AttachStateDegraded
	a.lastErr = "credentials required after daemon restart"
	a.mu.Lock()
	a.restoreItemsLocked(items)
	if a.root == nil {
		a.root = a.registerSyntheticRootLocked()
	}
	if a.root == nil {
		a.mu.Unlock()
		if a.localFS != nil {
			_ = a.localFS.Close()
			a.localFS = nil
		}
		return nil, fmt.Errorf("restore root item identity is not representable by FSKit")
	}
	a.mu.Unlock()
	return a, nil
}

func (a *attach) persistedEntry() persistedAttachEntry {
	a.mu.RLock()
	items := a.persistedItemsLocked()
	options := a.options
	options.LocalDirs = append([]string(nil), a.options.LocalDirs...)
	identityEpoch := a.identityEpoch
	detachPrepared := a.detachPrepared
	detachForce := a.detachForce
	detachJobID := a.detachJobID
	a.mu.RUnlock()
	return persistedAttachEntry{
		Ref:                 a.ref,
		VolumeID:            a.volumeID,
		Branch:              a.branch,
		MountPath:           a.mountPath,
		AuthorityURL:        a.authorityURL,
		DataPlaneTransport:  a.dataPlaneTransport,
		DataPlaneServerName: a.dataPlaneServerName,
		TLSCAPEM:            a.tlsCAPEM,
		TLSCASHA256:         a.tlsCASHA256,
		Options:             options,
		IdentityEpoch:       identityEpoch,
		DetachPrepared:      detachPrepared,
		DetachForce:         detachForce,
		DetachJobID:         detachJobID,
		Items:               items,
	}
}

func (a *attach) activate(ctx context.Context, tok string, expiresAtMs int64) error {
	return a.activateWithOptions(ctx, tok, expiresAtMs, nil)
}

func (a *attach) activateIfPending(ctx context.Context, tok string, expiresAtMs int64) (bool, error) {
	return a.activateWithOptionsMode(ctx, tok, expiresAtMs, nil, true)
}

func (a *attach) activateWithOptions(ctx context.Context, tok string, expiresAtMs int64, options *AttachOptions) error {
	_, err := a.activateWithOptionsMode(ctx, tok, expiresAtMs, options, false)
	return err
}

func (a *attach) activateWithOptionsMode(
	ctx context.Context,
	tok string,
	expiresAtMs int64,
	options *AttachOptions,
	onlyIfPending bool,
) (bool, error) {
	// ── A CREDENTIAL ROTATION INTO A LIVE VOLUME TAKES NO NAMESPACE LOCK ─────
	//
	// This whole function used to run under lockExternalNamespaceWrite, i.e.
	// frontendSerial plus a mount-wide EXCLUSIVE nsMu. For the revive path that
	// is right — start() rebuilds the volume and republishes items, which really
	// is a namespace-wide event. For a ROTATION it is not: the body below
	// reduces to setCredential and an immediate return, and setCredential
	// publishes a token into a live volume that synchronises itself.
	//
	// The cost of taking it anyway was the D2 stranding. Go's RWMutex is
	// writer-preferring and every frontend write holds nsMu.RLock across an
	// authority round trip, so under a full-speed flood this Lock() queued
	// behind the slowest in-flight write — and the caller is the lease keeper's
	// renewal, arriving on an HTTP control request with a 60s client timeout.
	// The renewal timed out, its error was logged and dropped, the lease expired
	// underneath a mount that was busy proving it was alive, and the attach
	// fenced with "access credential rejected by a REACHABLE authority" while
	// its backlog stranded. The one operation that must never queue behind bulk
	// traffic was queued behind all of it.
	//
	// So the rotation is separated out and takes nothing heavier than a.mu.
	// Every other path keeps the lock it had.
	if done, handled := a.rotateLiveCredential(tok, expiresAtMs, onlyIfPending); handled {
		return done, nil
	}
	unlockNamespace := a.lockExternalNamespaceWrite()
	defer unlockNamespace()
	a.startMu.Lock()
	defer a.startMu.Unlock()
	a.mu.RLock()
	if a.detached {
		a.mu.RUnlock()
		return false, fmt.Errorf("attach is detached")
	}
	if a.detachPrepared || a.detachForce {
		a.mu.RUnlock()
		return false, fmt.Errorf("attach is quarantined by a durable prepared detach")
	}
	credentialPending := a.credentialPending
	active := a.vol != nil && !a.credentialPending
	a.mu.RUnlock()
	if onlyIfPending && !credentialPending {
		return false, nil
	}
	// ONE installation. setCredential publishes the credential into the live
	// volume, which opens the new generation, re-arms the reachability prober
	// and verifies the credential — all of it. This used to call the token
	// setter here and a separate CredentialInstalled notification below, so a
	// single rotation opened TWO generations: the first was never offered to
	// anyone and was superseded before any handshake could classify it.
	a.setCredential(tok, expiresAtMs)
	if active {
		return true, nil
	}
	if options != nil {
		a.mu.Lock()
		previousVolumeLocalDirs := a.options.VolumeLocalDirs
		previousLocalDirs := append([]string(nil), a.options.LocalDirs...)
		a.options.VolumeLocalDirs = options.VolumeLocalDirs
		// A revived attach has no live routing table, so the re-ensure
		// request is authoritative for explicit grafts. In particular,
		// --no-local-dirs sends an empty set plus VolumeLocalDirs=false and
		// must clear persisted grafts rather than add nothing to them.
		a.options.LocalDirs = append([]string(nil), options.LocalDirs...)
		a.mu.Unlock()
		// Persist the effective routing request before start can reincarnate
		// any published Items. A crash after this snapshot is reconciled by
		// start's provenance transition; a snapshot failure leaves both the
		// old live identities and old durable routing rules untouched.
		if err := a.persistState(); err != nil {
			a.mu.Lock()
			a.options.VolumeLocalDirs = previousVolumeLocalDirs
			a.options.LocalDirs = previousLocalDirs
			a.mu.Unlock()
			return false, fmt.Errorf("persist revived local-dir routing: %w", err)
		}
	}
	if err := a.start(ctx); err != nil {
		a.setErr(err)
		return false, err
	}
	a.mu.Lock()
	a.credentialPending = false
	a.lastErr = ""
	a.state = a.currentStateLocked()
	a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{State: a.state}})
	a.mu.Unlock()
	return true, nil
}

// rotateLiveCredential installs a rotated credential into an ALREADY ACTIVE
// attach without taking the mount-wide namespace lock, and reports whether it
// handled the request.
//
// handled is false for every state whose verdict belongs to the locked path —
// detached, quarantined by a prepared detach, or not yet started — so those
// callers still get the exact error and the exact serialization they had. It is
// true only for the case the locked path would have reduced to a single
// setCredential and an immediate return.
//
// See activateWithOptionsMode for why the rotation must not queue behind the
// mount's write traffic.
func (a *attach) rotateLiveCredential(
	tok string,
	expiresAtMs int64,
	onlyIfPending bool,
) (bool, bool) {
	a.mu.RLock()
	unavailable := a.detached || a.detachPrepared || a.detachForce
	credentialPending := a.credentialPending
	active := a.vol != nil && !credentialPending
	a.mu.RUnlock()
	if unavailable || !active {
		return false, false
	}
	if onlyIfPending {
		// An active attach has no pending credential by definition, so a
		// pending-only installation has nothing to do. Same answer the locked
		// path gives, reached without the lock.
		return false, true
	}
	a.setCredential(tok, expiresAtMs)
	return true, true
}

// controlAdmissionError is called only while nsMu is held. A persisted
// prepared attach is deliberately inert after restart until the daemon has
// reconciled the exact kernel identity; local graft operations must not be
// able to bypass that quarantine.
func (a *attach) controlAdmissionError() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	switch {
	case a.detached:
		return fmt.Errorf("attach is detached")
	case a.detachPrepared || a.detachForce:
		// ONE sentence for this state, shared with detach. It used to be
		// described two different ways — "quarantined" here, "reconcile through
		// the exact unmount endpoint" there — so an operator whose plain umount
		// and whose --force were both refused had two unrelated messages and no
		// way to tell they named the same condition or which command resolves it.
		return errPreparedDetachPending
	case a.coherenceFailFrozen:
		return fmt.Errorf("%s", a.lastErr)
	default:
		return nil
	}
}

// lifetime is the attach-scoped context every long-lived goroutine and the
// Volume itself must use. Never the control-request context: activation runs
// inside an HTTP handler whose context dies with the response.
func (a *attach) lifetime() context.Context {
	if a.lifeCtx == nil {
		return context.Background()
	}
	return a.lifeCtx
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
	tlsCfg, err := (dataPlaneTransport{
		mode:       a.dataPlaneTransport,
		serverName: a.dataPlaneServerName,
		caPEM:      a.tlsCAPEM,
		caSHA256:   a.tlsCASHA256,
	}).tlsConfig()
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
		CredentialSource: func() (string, int64) {
			a.credMu.RLock()
			defer a.credMu.RUnlock()
			return a.token, a.tokenExpiresAtMs
		},
		Branch:            a.branch,
		WALDir:            filepath.Join(a.stateDir, "wal", a.storageID),
		NegativeCache:     a.options.NegativeCache,
		NoNegativeCache:   a.options.NoNegativeCache,
		DiskCacheDir:      diskDir,
		DiskCacheBytes:    diskCap << 20,
		PrefetchTree:      a.options.Prefetch,
		OnFlushAll:        a.onFlushAll,
		OnHandoffStart:    a.startFrontendHandoff,
		OnHandoffEnd:      a.endFrontendHandoff,
		OnHandoffPrepared: a.persistAssignedAuthorityIdentities,
		OnOperationWait:   a.suspendFrontendOperation,
		OnMarkOrphan:      a.onMarkOrphan,
		// A persistently failing write-back flush flips the attach to degraded (visible in
		// `portablefs mounts` + pushed to the extension) instead of only logging, so acked
		// write-back that cannot reach the authority is loud, never silently dropped.
		OnWriteBackError: func(_ string, err error) { a.setErr(err) },
		Debugf: func(format string, args ...any) {
			log.Printf("attach %s: "+format, append([]any{a.ref}, args...)...)
		},
	}
	// The Volume's internal context is derived from the one passed here and
	// scopes write-back, credential renewal and prefetch for the whole mount,
	// so it must be the attach lifetime, never the activating request.
	vol, err := clientcore.Dial(a.lifetime(), opts)
	if err != nil {
		return err
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
	// Establish the Volume's invalidation subscription BEFORE the first read
	// that populates its caches. The root getattr below (and every frontend
	// read after it) is only ordered against peer mutations once the authority
	// has registered this mount as a subscriber; anything cached earlier can
	// only be corrected by the anchor's fence, not by an event. Starting the
	// watcher here and waiting for the anchor keeps the mount from ever
	// serving from a pre-subscription cache.
	//
	// The wait is bounded and advisory: if the authority is slow the attach
	// proceeds, because the anchor still fences away everything cached in the
	// meantime the moment it lands. A dead authority fails at the getattr.
	invalidationCtx, stopInvalidations := context.WithCancel(a.lifetime())
	activated := false
	defer func() {
		// Every remaining path out of start that is not a live attach must
		// retire the watcher; otherwise a failed activation leaves it
		// resubscribing against the closed Volume until detach.
		if !activated {
			stopInvalidations()
		}
	}()
	go vol.StartInvalidations(invalidationCtx, false)
	anchorCtx, cancelAnchor := context.WithTimeout(ctx, invalidationAnchorWait)
	anchored := vol.AwaitInvalidations(anchorCtx)
	cancelAnchor()
	if !anchored {
		log.Printf("attach %s: invalidation stream not anchored within %s; "+
			"serving continues and re-fences when it lands", a.ref, invalidationAnchorWait)
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
	rootItemID := rootAttr.Ino
	if rootItemID == 0 {
		rootItemID = clientcore.InoOf("")
	}
	if _, ok := fskitItemID(rootItemID); !ok {
		if openedLocalFS {
			_ = localFS.Close()
		}
		_ = eventClient.Close()
		_ = vol.Close()
		return fmt.Errorf("root item identity %d is not representable by FSKit", rootItemID)
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
	changedRoutingItems := a.transitionGraftProvenanceLocked(effectiveLocalDirs)
	a.localDirs = effectiveLocalDirs
	a.localFS = localFS
	a.vol = vol
	a.eventClient = eventClient
	var rootTicket *reincarnationTicket
	a.root, rootTicket = a.registerOwnedLocked("", rootAttr)
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
	for _, p := range changedRoutingItems {
		a.publishNamespaceInvalidationLocked(p, 0, 0)
	}
	a.mu.Unlock()
	// Activation republishes the root against the real authority inode, which
	// makes it a publisher that can displace a restored pathname. It settles its
	// own ticket here, with a.mu released and the volume already installed, on
	// the same footing as every frontend publisher — an activation that could
	// not reconcile is one whose first served reply would carry the impossible
	// pair, so it fails the activation instead.
	if eno, _ := rootTicket.settle(a.lifetime(), vol); eno != 0 {
		a.mu.Lock()
		a.vol = nil
		a.eventClient = nil
		if openedLocalFS {
			a.localFS = nil
		}
		a.mu.Unlock()
		if openedLocalFS {
			_ = localFS.Close()
		}
		_ = eventClient.Close()
		_ = vol.Close()
		return fmt.Errorf("reconcile retained aliases of a reincarnated root: errno %d", eno)
	}
	if err := a.flushBindingDeltaError(); err != nil {
		a.mu.Lock()
		a.vol = nil
		a.eventClient = nil
		if openedLocalFS {
			a.localFS = nil
		}
		a.mu.Unlock()
		if openedLocalFS {
			_ = localFS.Close()
		}
		_ = eventClient.Close()
		_ = vol.Close()
		return fmt.Errorf("persist effective local-dir identity transition: %w", err)
	}
	a.eventOnce.Do(func() { close(a.eventReady) })
	go a.forwardEvents(a.lifetime(), eventClient, eventStream, eventAck)
	go a.watchPrefetch(a.lifetime())
	activated = true
	return nil
}

func (a *attach) setCredential(tok string, expiresAtMs int64) {
	a.credMu.Lock()
	a.token = tok
	a.tokenExpiresAtMs = expiresAtMs
	a.credMu.Unlock()
	a.mu.RLock()
	vol := a.vol
	a.mu.RUnlock()
	if vol != nil {
		// One call: it opens the generation, publishes the token WITH the
		// issuer's stated deadline, re-arms the reachability prober and starts
		// verification. The deadline used to be dropped here — the volume was
		// handed the token alone — so the daemon's own unproven state had no
		// boundary even though the expiry was sitting in the very next field.
		vol.InstallCredential(tok, expiresAtMs)
	}
	a.mu.RLock()
	events := a.eventClient
	a.mu.RUnlock()
	if events != nil {
		// The invalidation stream's client carries the SAME credential and the
		// same deadline. Handing it the token alone left its own unproven state
		// unbounded for exactly the reason the volume's was.
		events.InstallCredential(fsproto.Credential{Token: tok, ExpiresAtMs: expiresAtMs})
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
	if force {
		// FORCED DETACH TAKES NO NAMESPACE LOCK UNTIL IT HAS FENCED.
		//
		// The whole purpose of --force is to abandon in-flight work, so queueing
		// it behind that work is a contradiction — and it was a live one: with a
		// delegation release parked in an unbounded drain, one 12-minute nsMu
		// writer had ~100 frontend goroutines behind it, and every `umount
		// --force` joined the same queue. The escape hatch could not break into
		// the mount it exists to abandon; only killing the daemon recovered it.
		//
		// So the fence comes first. CloseJournalDurable parks the acknowledged
		// tail as a durable recovery job and fences the engine, which is what
		// gives every operation still inside the namespace locks a definite
		// outcome (ErrFenced). The terminal transition then takes those locks
		// against work that is already converging rather than against work that
		// is waiting on an authority which has stopped answering.
		return a.forcedDetach()
	}
	// Quiesce every namespace/handle operation through the complete drain
	// decision. A failed normal detach releases this lock with the attach and
	// Volume still usable; a successful detach publishes the terminal flag
	// before operations can resume.
	a.frontendSerial.Lock()
	a.nsMu.Lock()
	a.mu.RLock()
	alreadyDetached := a.detached
	existingJobID := a.detachJobID
	vol := a.vol
	prepared := a.detachPrepared || a.detachForce
	a.mu.RUnlock()
	if alreadyDetached {
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
		return existingJobID, nil
	}
	if prepared {
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
		return existingJobID, errPreparedDetachPending
	}
	if vol != nil {
		exitBarrier := a.enterDetachBarrier()
		cerr := vol.Close()
		exitBarrier()
		if cerr != nil {
			// Close freezes admissions around the final drain and visibility
			// barrier. It is retryable on failure and has not cancelled the
			// Volume or parked its WAL. Keep the attach serving.
			recs, bytes := vol.WriteBackPending()
			a.nsMu.Unlock()
			a.frontendSerial.Unlock()
			return "", fmt.Errorf("detach refused: final drain/release barrier failed with %d records (%d bytes) unshipped: %w (retry when the authority answers, or force-detach to park them as a durable recovery job)", recs, bytes, cerr)
		}
	}
	return a.finishDetachWithNSLocked(jobID, err)
}

// errPreparedDetachPending is the ONE next action a caller is given when an
// attach already carries a durable prepared FSKit detach. Both unmount paths
// used to refuse with a different sentence — plain umount said the mount was
// quarantined, --force said to reconcile through the exact unmount endpoint —
// so an operator reading either one had no way to know that the two were
// describing the same state and that only one endpoint could resolve it.
var errPreparedDetachPending = errors.New(
	"attach has a durable prepared FSKit detach: reconcile it through POST " +
		"/v1/attaches/{ref}/unmount (portablefs umount), which is the only " +
		"operation that can complete or discharge it",
)

// forcedDetach parks the acknowledged tail and fences the engine BEFORE it takes
// the namespace locks. See detach for why the order is the whole point.
func (a *attach) forcedDetach() (jobID string, err error) {
	a.mu.RLock()
	alreadyDetached := a.detached
	existingJobID := a.detachJobID
	vol := a.vol
	prepared := a.detachPrepared || a.detachForce
	a.mu.RUnlock()
	if alreadyDetached {
		return existingJobID, nil
	}
	if prepared {
		return existingJobID, errPreparedDetachPending
	}
	if vol != nil {
		exitBarrier := a.enterDetachBarrier()
		id, cerr := vol.CloseJournalDurable()
		exitBarrier()
		jobID = id
		if cerr != nil {
			err = fmt.Errorf("forced detach: journal-durable close: %w", cerr)
		} else if id != "" {
			log.Printf("portablefsd: detach %s: forced; recovery job %s parked durably (recovers on the next attach)", a.ref, id)
		}
	}
	if fenced := a.testForcedDetachFenced; fenced != nil {
		fenced()
	}
	// The engine is fenced and the tail is durable. Every operation still inside
	// the namespace locks now reaches a definite outcome, so this acquisition
	// waits on work that is converging rather than on an authority that stopped
	// answering.
	a.frontendSerial.Lock()
	a.nsMu.Lock()
	a.mu.RLock()
	if a.detached {
		existingJobID = a.detachJobID
		a.mu.RUnlock()
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
		return existingJobID, err
	}
	a.mu.RUnlock()
	return a.finishDetachWithNSLocked(jobID, err)
}

// detachWithFinalizer closes the volume's durability boundary and runs one
// exact kernel detach callback. The admission freeze is held only around the
// terminal state transition, never across the callback: unmount(2) re-enters
// this daemon — the kernel reclaims every cached vnode through the FSKit
// extension, and reclaim serializes on frontendSerial exclusively — so a
// freeze spanning the callback deadlocks the daemon against its own kernel
// detach. The write-back engine's close freeze is what guarantees no new
// durability debt while the barrier and callback run. CloseWithFinalizer
// keeps the volume usable when the callback fails, so a failed platform
// unmount thaws back to the live mount.
func (a *attach) detachWithFinalizer(finalizer func() error) (string, error) {
	return a.detachWithFinalizerContext(context.Background(), finalizer)
}

// detachWithFinalizerContext lets the unmount transaction cancel its own drain
// barrier when a --force escalates it (see runUnmountTransaction). ctx bounds
// only the barrier wait; nothing committed is abandoned.
func (a *attach) detachWithFinalizerContext(
	ctx context.Context,
	finalizer func() error,
) (string, error) {
	a.mu.RLock()
	alreadyDetached := a.detached
	existingJobID := a.detachJobID
	vol := a.vol
	a.mu.RUnlock()
	if alreadyDetached {
		return existingJobID, nil
	}
	if vol != nil {
		exitBarrier := a.enterDetachBarrier()
		err := vol.CloseWithFinalizerContext(ctx, finalizer)
		exitBarrier()
		if err != nil {
			return "", fmt.Errorf("prepared FSKit detach refused: %w", err)
		}
	} else if err := finalizer(); err != nil {
		return "", err
	}
	a.frontendSerial.Lock()
	a.nsMu.Lock()
	return a.finishDetachWithNSLocked("", nil)
}

// finishDetachWithNSLocked publishes the terminal attach state and releases
// the admission freeze. The caller owns frontendSerial and nsMu exclusively.
func (a *attach) finishDetachWithNSLocked(jobID string, priorErr error) (string, error) {
	a.mu.Lock()
	if a.detached {
		existingJobID := a.detachJobID
		a.mu.Unlock()
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
		return existingJobID, priorErr
	}
	a.detached = true
	if jobID != "" {
		a.detachJobID = jobID
	}
	a.state = pfslocal.AttachStateDetaching
	a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{State: pfslocal.AttachStateDetaching, Detail: "detaching"}})
	events := a.eventClient
	localFS := a.localFS
	lifeCancel := a.lifeCancel
	a.mu.Unlock()
	a.nsMu.Unlock()
	a.frontendSerial.Unlock()
	// Detach is the attach's terminal state: retire the lifetime scope so the
	// invalidation watcher and the event forwarder stop instead of looping on
	// resubscribe backoff against a closed client forever.
	if lifeCancel != nil {
		lifeCancel()
	}
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
	return jobID, priorErr
}

// newWriteBackStatus projects the engine's health snapshot onto the wire type.
//
// A healthy zero-debt engine is still operationally meaningful: expose it
// instead of making clients guess whether write-back is absent or merely idle.
// Scope names make contention and overly broad grants diagnosable without
// exposing delegation epochs.
// liveWriteBackStatus snapshots the engine's durability-debt view without
// taking the whole attach status apart. It exists for verdicts that must NAME
// what a barrier is waiting on.
func (a *attach) liveWriteBackStatus() *writeBackStatus {
	a.mu.RLock()
	vol := a.vol
	a.mu.RUnlock()
	if vol == nil {
		return nil
	}
	return newWriteBackStatus(vol.WritebackStatus())
}

func newWriteBackStatus(st writeback.Status) *writeBackStatus {
	wb := &writeBackStatus{
		PendingRecords: st.PendingRecords, PendingBytes: st.PendingBytes,
		AppliedThrough: st.AppliedThrough, AdmittedThrough: st.AdmittedThrough,
		OldestPendingMs: st.OldestPendingMs, Degraded: st.Degraded,
		LastFailure: st.LastFailure, WALBytes: st.WALBytes,
		WALBudget: st.WALBudget, LastProgressMs: st.LastProgressMs,
		CreditSetpoint: st.CreditSetpoint, CreditDebt: st.CreditDebt,
		CreditCeiling: st.CreditCeiling, AppliedRateBps: st.AppliedRateBps,
		CreditWaiters: st.CreditWaiters, DataLaneFull: st.DataLaneFull,
		Delegations: make([]delegationView, 0, len(st.Delegations)),
	}
	for _, d := range st.Delegations {
		wb.Delegations = append(wb.Delegations, delegationView{
			Scope: d.Scope, Draining: d.Draining, DrainError: d.DrainError,
		})
	}
	now := time.Now().UnixMilli()
	for _, j := range st.Jobs {
		ref := recoveryJobRef{
			JobID: j.JobID, State: j.State,
			Records: j.PendingRecords, Bytes: j.PendingBytes,
			Unrecovered: recoveryJobIsUnrecovered(j.State),
			Remedy:      recoveryJobRemedy(j),
			LastError:   j.LastError,
		}
		for _, c := range j.Conflicts {
			ref.Conflicts = append(ref.Conflicts, recoveryConflictRef{
				Scope: c.Scope, Epoch: c.Epoch, Kind: c.Kind,
			})
		}
		if ref.Unrecovered {
			// The attach's honest drain verdict. A caller that reads
			// PendingBytes alone cannot tell "nothing left" from "nothing left
			// that is still moving"; this is the difference, and it is summed
			// from the jobs rather than asserted so it can never disagree with
			// the job list beside it.
			wb.UnrecoveredRecords += int(j.PendingRecords)
			wb.UnrecoveredBytes += int64(j.PendingBytes)
		}
		wb.Jobs = append(wb.Jobs, ref)
		wb.ParkedWALs = append(wb.ParkedWALs, parkedWAL{
			WAL: j.JobID, Records: int(j.PendingRecords), PayloadBytes: int64(j.PendingBytes),
			AgeMs: now - j.CreatedAtMs, LastError: j.LastError,
		})
	}
	return wb
}

// recoveryJobIsUnrecovered reports whether a job's remainder has STOPPED — it
// will not drain without an attach, an operator decision, or a repair.
//
// JobActive is the live stream and JobReplaying is draining right now; both are
// still moving and belong to the pending figure alone. Everything else is data
// that is sitting still, and a drain-to-zero check that cannot see it is not a
// drain-to-zero check.
func recoveryJobIsUnrecovered(state string) bool {
	switch state {
	case writeback.JobForced,
		writeback.JobParked,
		writeback.JobConflict,
		writeback.JobCorrupt:
		return true
	default:
		return false
	}
}

// recoveryJobRemedy is the one sentence an operator can act on for a stopped
// job, NAMING the affected scopes where the job records them.
//
// It exists because "state: corrupt" and "state: conflict" are verdicts without
// instructions: they tell an operator that something needs a decision and
// nothing about what the decision is, which scopes it concerns, or which
// command makes it. A status field that cannot be acted on is a status field
// that gets ignored.
func recoveryJobRemedy(j writeback.RecoveryJob) string {
	switch j.State {
	case writeback.JobForced:
		return "a forced unmount parked this stream; re-attach the volume to " +
			"replay it, or export it with `portablefs recover export`"
	case writeback.JobParked:
		return "the live stream stalled terminally; re-attach the volume to " +
			"resume recovery"
	case writeback.JobConflict:
		if scopes := recoveryConflictScopes(j); scopes != "" {
			return "recovery conflicts on " + scopes +
				"; resolve them with `portablefs recover resolve`"
		}
		return "a typed recovery conflict needs an operator decision; resolve " +
			"it with `portablefs recover resolve`"
	case writeback.JobCorrupt:
		return "WAL damage blocks automatic replay; export what survives with " +
			"`portablefs recover export` before removing the job"
	default:
		return ""
	}
}

// recoveryConflictScopes renders the distinct scopes a job's conflicts name, in
// first-seen order, as a quoted comma-separated list.
func recoveryConflictScopes(j writeback.RecoveryJob) string {
	seen := make(map[string]struct{}, len(j.Conflicts))
	var out []string
	for _, c := range j.Conflicts {
		if c.Scope == "" {
			continue
		}
		if _, dup := seen[c.Scope]; dup {
			continue
		}
		seen[c.Scope] = struct{}{}
		out = append(out, strconv.Quote(c.Scope))
	}
	return strings.Join(out, ", ")
}

// credentialStateRejected / credentialStatePendingVerification are the two
// DISJOINT credential faults an attach can report. They are distinct words
// because they are distinct facts with distinct repairs: rejected is a
// proven-dead credential (the authority answered "no" -> log in again),
// pending-verification is an UNTESTED one (the authority never answered ->
// look at the router). Overloading "expired" for both told operators to fix
// the wrong thing.
const (
	credentialStateRejected            = "rejected"
	credentialStatePendingVerification = "pending-verification"
)

func (a *attach) status() attachStatus {
	a.mu.RLock()
	state := a.currentStateLocked()
	lastErr := a.lastErr
	credential := ""
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
		wb = newWriteBackStatus(vol.WritebackStatus())
		// CREDENTIAL DEATH IS NOT UNREACHABILITY. A reachable authority that
		// refuses this mount's access credential is a DEFINITE, terminal
		// classification: no retry loop can recover it (per the lease decision
		// table only login + remount can), and the admitted backlog belongs to
		// the durable parked-job path. Reporting it as a transport problem —
		// which is what "authority unreachable (fail-fast engaged after
		// repeated transport failures)" said while a concurrent fresh mount
		// proved the authority healthy — sends the operator to the network and
		// hides the one action that works.
		// A FENCED SESSION IS A DEFINITE DEGRADED STATE, AND IT IS REPORTED
		// FIRST.
		//
		// It is checked ahead of the credential branches because it is the
		// strongest statement available about this mount: a fenced session
		// answers EVERY subsequent request with ESTALE — open, read, mkdir,
		// close, all of them — and it never mints a fresh generation, so nothing
		// short of a remount changes that.
		//
		// Nothing here asked before. attach.status() consulted exactly two
		// predicates (both credential-shaped), the write-back watchdog can only
		// latch degraded when it has pending records to be stuck on
		// (writeback/flush.go), and `portablefs mounts` derives health from pid
		// liveness plus the kernel mount table without entering the filesystem.
		// So a fenced mount reported state=attached, lastErr empty, degraded
		// absent and health=live while every operation on it returned ESTALE —
		// measured live, and the fence only became visible at umount, in the
		// final barrier's error. A mount that cannot serve must say so at the
		// moment it stops serving.
		if a.sessionFenced(vol) {
			state = pfslocal.AttachStateDegraded
			lastErr = "mount session FENCED (stale generation): the authority " +
				"terminated this mount's session lease, so every operation on this " +
				"mount now fails with ESTALE and no new generation will be minted. " +
				"Remount to recover; unshipped write-back can be parked as a durable " +
				"recovery job with `portablefs umount --force`"
		} else if vol.CredentialExpired() {
			state = pfslocal.AttachStateDegraded
			credential = credentialStateRejected
			lastErr = "access credential rejected by a REACHABLE authority " +
				"(lease expired or revoked); run `portablefs login` and remount. " +
				"Unshipped write-back is retained locally and can be parked as a " +
				"durable recovery job with `portablefs umount --force`"
		} else if vol.CredentialUnproven() {
			// AN UNTESTED CREDENTIAL IS NOT A HEALTHY ONE. The mount has
			// offered this credential and the authority has neither accepted
			// nor refused it — the handshake is being torn down before the ack
			// byte ever arrives (a router rolling, an authority shutting down
			// mid-handshake). That produces no ack to latch and no transport
			// failure to count, so nothing else in the mount says a word about
			// it, and status used to report a perfectly live attach.
			//
			// It is reported SEPARATELY from rejection on purpose. Rejection
			// means the authority answered "no" and only login + remount can
			// change it. This means nobody answered at all, and telling an
			// operator to log in again would send them to repair the one thing
			// that is not known to be broken.
			state = pfslocal.AttachStateDegraded
			credential = credentialStatePendingVerification
			lastErr = "access credential is UNPROVEN: the authority has neither " +
				"accepted nor refused it (the handshake is being torn down before " +
				"the ack), so this mount is NOT known healthy. Verification keeps " +
				"retrying until the credential's own expiry, after which it hardens " +
				"to rejected; check the data-plane router/authority rather than " +
				"re-authenticating"
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
		Credential: credential,
		Prefetch:   prefetchStatus{Done: pf.Done, EntriesWalked: pf.Entries},
		Cache:      cacheStatus{AttrEntries: attrEntries, DiskBytes: diskBytes, DiskCapBytes: diskCap},
		LocalDirs:  localDirs,
		WriteBack:  wb,
	}
}

// sessionFenced reports whether this attach's mount session has been fenced.
//
// The test seam exists because a fence is a durable authority decision (a lease
// swept terminal, a slot conflict) that a unit test cannot manufacture through
// the real handshake without racing a real TTL. The production answer is always
// the volume's own.
func (a *attach) sessionFenced(vol *clientcore.Volume) bool {
	if hook := a.testSessionFenced; hook != nil {
		return hook()
	}
	return vol != nil && vol.SessionFenced()
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
	} else if a.lastErr != "" && !a.coherenceFailFrozen {
		a.lastErr = ""
		a.state = a.currentStateLocked()
		a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{State: a.state}})
	}
	a.mu.Unlock()
}

// enterDetachBarrier marks the final drain/release barrier as running and
// returns the function that clears it. A barrier that SUCCEEDS goes on to set
// detached/detachPrepared, so clearing it afterwards is harmless; a barrier that
// FAILS leaves the attach fully alive and must restore the serving verdict.
func (a *attach) enterDetachBarrier() func() {
	a.mu.Lock()
	a.detachBarrier = true
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		a.detachBarrier = false
		a.mu.Unlock()
	}
}

func (a *attach) failCoherence(err error) {
	if err == nil {
		return
	}
	// Publish the terminal verdict to the handoff gate before waiting for the
	// frontend proxy exclusively. A handler may hold the proxy for reading
	// while its handoff waits on the very publication operation whose
	// disconnect reached this path. Waking that handoff first lets it abort,
	// remove its scope, and release the read lock; the exclusive fence below
	// then preserves the existing admitted-handler linearization.
	gateErr := fmt.Errorf("kernel coherence barrier failed closed: %w", err)
	a.failFrontendGate(gateErr)
	// Linearize the terminal fence after every already-admitted frontend
	// handler and before every later one. Callers reach this point only after
	// releasing concrete/proxy namespace locks.
	a.frontendSerial.Lock()
	defer a.frontendSerial.Unlock()
	a.mu.Lock()
	if !a.coherenceFailFrozen {
		a.coherenceFailFrozen = true
		a.lastErr = gateErr.Error()
		a.state = pfslocal.AttachStateDegraded
		a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{
			State:  pfslocal.AttachStateDegraded,
			Detail: a.lastErr,
		}})
	}
	a.mu.Unlock()
}

func (a *attach) failFrontendGate(err error) {
	if err == nil {
		return
	}
	a.frontendGateMu.Lock()
	a.initFrontendGateLocked()
	if a.frontendGateErr == nil {
		a.frontendGateErr = err
	}
	a.frontendGateCond.Broadcast()
	a.frontendGateMu.Unlock()
}

func (a *attach) frontendAdmissionError() error {
	a.frontendGateMu.Lock()
	gateErr := a.frontendGateErr
	a.frontendGateMu.Unlock()
	if gateErr != nil {
		return gateErr
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.coherenceFailFrozen {
		return fmt.Errorf("%s", a.lastErr)
	}
	return nil
}

func (a *attach) volOrErr() (*clientcore.Volume, int32) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.detached || a.detachPrepared || a.detachForce {
		return nil, darwinENXIO
	}
	if a.coherenceFailFrozen || a.credentialPending || a.vol == nil {
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
// call this after their synchronous, fallible journal transaction. The state
// snapshot is compaction; process-crash identity correctness comes from the
// journal and therefore never depends on the debounce window.
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

// registerSyntheticRootLocked binds the placeholder root of an attach that has
// no authority yet (pre-activation restore, or a resolve that arrives before
// credentials do).
//
// It is a named call site rather than an inline registerLocked because it is the
// one publisher that deliberately settles NO reconciliation ticket, and that
// deserves a stated reason rather than an omission: the root's alias set is
// exactly its own name, and detachReincarnatedPathLocked drops the detached name
// from that set BEFORE it records debt, so a root reincarnation has no retained
// alias to owe anything to. There is also no authority to ask at this point,
// which is why the reason has to be structural and not "we will refresh later".
// Callers hold a.mu.
func (a *attach) registerSyntheticRootLocked() *itemRecord {
	return a.registerLocked("", syntheticRootAttr())
}

// publishRecordAttrLocked is THE attribute assignment. Every write of
// itemRecord.attr in this daemon goes through it, and that centralization is
// the whole point.
//
// ── WHY ADMISSION CANNOT LIVE AT THE REGISTRATION ENTRY POINTS ──────────────
//
// Publication admission (admitPublicationLocked) used to sit at
// registerWithItemLocked and at registerHardLinkAliasLocked, which covers every
// registration that RESOLVES A NAME — and misses every assignment that reaches
// a record some other way. registerHandleAttrLocked is exactly that: a detached
// handle's post-op attributes are written straight onto the canonical record
// and onto every retained alias, by item identity rather than by name. A
// getattr issued before a peer's rename-over, answered after the reconciliation
// that repaired those aliases, therefore wrote the pre-reincarnation snapshot
// (Nlink=2 beside a fresh identity) back over the repair — permanently, since
// its ticket was inert and no fresh generation was ever minted for it.
//
// So admission is bound to the assignment, not to the entry point. A publisher
// that assigns attributes to an indebted alias mints a new generation exactly
// as a name registration does, and its OWN ticket then pays for a refresh
// ordered strictly after the assignment (see admitPublicationLocked).
//
// It is also where a settled-but-unpublished mutation is repaired: this is the
// moment the registry stops being behind the engine. See notePublicationLocked.
//
// admit is false for the one caller that has already admitted this exact
// pathname a few lines earlier (registerWithItemLocked), so a single
// registration cannot mint two generations for one name.
func (a *attach) publishRecordAttrLocked(rec *itemRecord, attr fsproto.Attr, admit bool) {
	if rec == nil {
		return
	}
	if admit {
		a.admitPublicationLocked(rec.path)
	}
	rec.attr = attr
	a.notePublicationLocked(rec.item.ItemID)
	// NOTE: this is deliberately NOT the crossed repair's convergence witness.
	//
	// It used to be: an assignment here credited a repair's publication counter
	// whenever ANY size reservation happened to be outstanding on the item. That
	// counted a getattr's PRE-WRITE observation as proof that the write which
	// had merely been granted its reservation had told the kernel something —
	// and the write could then fail without committing at all. The witness is
	// now bound to the mutation's own token and to the DELIVERY of its reply;
	// see repairwitness.go.
}

// publishItemSizeLocked installs a size a MUTATION decided onto the item it
// changed and onto every alias of that identity.
//
// It is the publication of last resort: it is reached only when a handler's
// optional post-op attribute refresh failed, and it exists because the
// alternative — publishing nothing — leaves the registry behind a commit the
// application has already been told is durable (see attach.writeReplyWithAttr).
//
// Only the size moves. Everything else in the record is whatever the last real
// observation stated, and a commit says nothing about it.
//
// floorOnly separates the two kinds of statement a commit makes. A WRITE proves
// a lower bound: it extended the file to at least this point, so a record
// already holding more holds something the write does not contradict (a peer's
// extension, or a later write of this daemon's that published first), and
// lowering it would be a fabrication. A TRUNCATE is exact — the authority
// applied precisely this size — and a shrink is the whole point of it, so it is
// installed as stated. Callers hold a.mu.
func (a *attach) publishItemSizeLocked(
	itemID uint64,
	rec *itemRecord,
	size int64,
	floorOnly bool,
) {
	if rec == nil {
		return
	}
	install := func(r *itemRecord) {
		if r == nil || (floorOnly && r.attr.Size >= size) {
			return
		}
		next := r.attr
		next.Size = size
		a.publishRecordAttrLocked(r, next, true)
	}
	install(rec)
	for aliasPath := range a.itemAliases[itemID] {
		alias := a.paths[aliasPath]
		if alias == nil || alias.item != rec.item {
			continue
		}
		install(alias)
	}
}

func (a *attach) registerLocked(p string, attr fsproto.Attr) *itemRecord {
	ino := attr.Ino
	authIno := ino != 0
	if ino == 0 {
		ino = clientcore.InoOf(p)
	}
	if _, ok := fskitItemID(ino); !ok {
		return nil
	}
	return a.registerWithItemLocked(p, attr, ino, authIno, true, false)
}

// registerHandleAttrLocked updates the immutable Item identity owned by an
// open handle without assuming that its remembered open path still names that
// inode. POSIX keeps an overwritten or unlinked target alive through its open
// descriptor, while the pathname may already name a replacement (or nothing).
// Re-registering the handle's stale path from a post-write getattr would
// transiently replace or resurrect that directory entry in the frontend
// registry.
//
// A still-bound handle takes the normal registration path, including
// delegated-local identity promotion. A detached handle updates only its
// retained Item and any genuine hard-link aliases. The stale open path remains
// an authority addressing hint for handle I/O; it is never namespace evidence.
// Caller holds a.mu.
func (a *attach) registerHandleAttrLocked(h *handleRecord, attr fsproto.Attr) *itemRecord {
	if h == nil || h.itemID == 0 {
		return nil
	}
	if current := a.paths[h.path]; current != nil && current.item.ItemID == h.itemID {
		if h.file != nil {
			return a.registerLocalLocked(h.path, attr)
		}
		if h.state == nil {
			return nil
		}
		return a.registerLocked(h.path, attr)
	}

	rec := a.items[h.itemID]
	if rec == nil {
		return nil
	}
	if h.file != nil {
		if !rec.graft {
			return nil
		}
		a.publishRecordAttrLocked(rec, attr, true)
		for aliasPath := range a.itemAliases[h.itemID] {
			alias := a.paths[aliasPath]
			if alias == nil || alias.item != rec.item || !alias.graft {
				continue
			}
			a.publishRecordAttrLocked(alias, attr, true)
		}
		return rec
	}
	if rec.state == nil || h.state == nil {
		return nil
	}
	recAuthorityIno := rec.state.AuthorityIno()
	handleAuthorityIno := h.state.AuthorityIno()
	if rec.state != h.state &&
		(recAuthorityIno == 0 || handleAuthorityIno == 0 ||
			recAuthorityIno != handleAuthorityIno) {
		return nil
	}
	if attr.Ino != 0 && recAuthorityIno != 0 && attr.Ino != recAuthorityIno {
		return nil
	}

	promoted := false
	if attr.Ino != 0 && recAuthorityIno == 0 {
		if !rec.state.RecordAuthorityIno(attr.Ino) {
			return nil
		}
		promoted = true
	}
	a.publishRecordAttrLocked(rec, attr, true)
	for aliasPath := range a.itemAliases[h.itemID] {
		alias := a.paths[aliasPath]
		if alias == nil || alias.item != rec.item || alias.state != rec.state {
			continue
		}
		a.publishRecordAttrLocked(alias, attr, true)
	}
	a.indexAuthorityIdentityLocked(rec)
	if promoted {
		if len(a.itemAliases[h.itemID]) == 0 {
			entry := a.bindingEntryLocked("detach", rec)
			entry.Path = h.openPath
			a.pendingBindings = append(a.pendingBindings, entry)
		} else {
			for aliasPath := range a.itemAliases[h.itemID] {
				if alias := a.paths[aliasPath]; alias != nil {
					a.pendBindingLocked(alias)
				}
			}
		}
	}
	return rec
}

func (a *attach) registerCreatedLocked(p string, attr fsproto.Attr) *itemRecord {
	if attr.Ino != 0 {
		return a.registerLocked(p, attr)
	}
	if a.paths[p] != nil {
		return a.registerLocked(p, attr)
	}
	rec := a.registerWithItemLocked(p, attr, a.newLocalItemIDLocked(p), false, false, false)
	if rec == nil {
		return nil
	}
	a.awaitingAuthorityItems[rec.item.ItemID] = struct{}{}
	return rec
}

// registerHardLinkAliasLocked binds a new hard-link name to the exact
// frontend item and NodeState already published for its source. A source
// created under write-back may have a daemon-local FSKit item ID even after
// delegation release gives it a different authority inode; publishing the
// authority inode as a second FSKit item would split one POSIX inode into two
// independent frontend objects.
func (a *attach) registerHardLinkAliasLocked(p string, source *itemRecord, attr fsproto.Attr) *itemRecord {
	// Binding a new name onto an existing identity publishes attributes for
	// that name, so it is admitted like any other publication. It does not
	// reach registerWithItemLocked, where the check otherwise lives.
	a.admitPublicationLocked(p)
	if a.paths[p] != nil {
		a.removePathLocked(p)
	}
	if current := a.paths[source.path]; current != nil {
		source = current
	}
	// The SOURCE name's attributes are restated too (its Nlink moved), so that
	// assignment is a publication of the source pathname and is admitted as one.
	a.publishRecordAttrLocked(source, attr, true)
	a.indexAuthorityIdentityLocked(source)
	a.pendBindingLocked(source)
	rec := &itemRecord{item: source.item, path: p, state: source.state, graft: source.graft}
	a.publishRecordAttrLocked(rec, attr, false) // p was admitted at the top
	a.paths[p] = rec
	a.addItemAliasLocked(rec)
	a.frontendPathEpoch.Add(1)
	if a.items[rec.item.ItemID] == nil {
		a.items[rec.item.ItemID] = source
	}
	a.pendBindingLocked(rec)
	return rec
}

func (a *attach) registerWithItemLocked(
	p string,
	attr fsproto.Attr,
	ino uint64,
	authIno bool,
	reuseByItemID bool,
	graft bool,
) *itemRecord {
	if _, ok := fskitItemID(ino); !ok {
		return nil
	}
	// PUBLICATION ADMISSION. Every registration that can put this pathname's
	// attributes in front of an application passes through here, so this is the
	// one place the check belongs. See admitPublicationLocked.
	a.admitPublicationLocked(p)
	gen := a.identityEpoch
	if gen == 0 {
		gen = 1
		a.identityEpoch = gen
	}
	if rec := a.paths[p]; rec != nil {
		if authIno && rec.state != nil && rec.state.AuthIno() &&
			rec.state.Orphan() == 0 && rec.state.AuthorityIno() != ino {
			// A pathname is not an inode identity. A peer can atomically
			// replace this directory entry while another hard-link name (or
			// an open handle) still refers to the old inode. Reusing the old
			// Item or mutating its NodeState would collapse two live POSIX
			// inodes into one frontend object. Detach only this name, retain
			// the old Item/NodeState for its aliases and kernel references,
			// then register the replacement as a fresh identity.
			a.detachReincarnatedPathLocked(p, rec, detachReplaced)
			return a.registerWithItemLocked(p, attr, ino, authIno, reuseByItemID, graft)
		}

		a.publishRecordAttrLocked(rec, attr, false) // p was admitted above
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
		} else if authIno && !rec.state.AuthIno() {
			if !rec.state.RecordAuthorityIno(ino) {
				rec.state = clientcore.NewNodeStateWithAuthority(rec.item.ItemID, ino)
			}
			a.pendBindingLocked(rec) // the persisted Auth bit flipped
		}
		if authIno {
			a.indexAuthorityIdentityLocked(rec)
		}
		return rec
	}
	item := pfslocal.Item{ItemID: ino, ItemGeneration: gen}
	var identity frontendItemIdentity
	var canonical *itemRecord
	if authIno {
		identity = a.authorityItems[ino]
	}
	if identity.state == nil && reuseByItemID {
		canonical = a.items[ino]
		if canonical != nil {
			identity = frontendItemIdentity{item: canonical.item, state: canonical.state}
		}
	}
	rec := &itemRecord{item: item, state: clientcore.NewNodeState(ino, authIno), graft: graft}
	if identity.state == nil {
		a.items[item.ItemID] = rec
	} else {
		// Multiple authority names for one inode are hard-link aliases. This
		// also covers the important asymmetric case where the first name was
		// published with a daemon-local ItemID before the authority allocated
		// its inode. Reuse both halves of the already-published identity.
		rec.item = identity.item
		rec.state = identity.state
	}
	rec.path = p
	a.publishRecordAttrLocked(rec, attr, false) // p was admitted above
	a.paths[p] = rec
	a.addItemAliasLocked(rec)
	a.frontendPathEpoch.Add(1)
	if canonical := a.items[rec.item.ItemID]; canonical == nil ||
		a.paths[canonical.path] != canonical {
		// A remotely replaced last-known name leaves its old Item detached
		// until Reclaim. Discovery of an authority hard-link alias makes that
		// live name canonical again without changing the published identity.
		a.items[rec.item.ItemID] = rec
	}
	if authIno {
		a.indexAuthorityIdentityLocked(rec)
	}
	a.pendBindingLocked(rec)
	return rec
}

// detachCause says WHY a pathname is being separated from its identity, because
// the two causes owe the retained aliases completely different things.
type detachCause int

const (
	// detachReplaced: a peer atomically rebound this directory entry to a
	// DIFFERENT inode. The displaced inode survives behind its other links, but
	// its LINK COUNT just changed, so every retained alias is now carrying an
	// attribute snapshot that predates the replacement. That is real debt.
	detachReplaced detachCause = iota
	// detachReprovisioned: the path's ROUTING OWNER changed under a new graft
	// rule set. Item provenance is immutable, so the published Item is retired
	// and the next resolution mints a fresh one — but the underlying inode was
	// not touched at all. Its link count is what it was, and every retained
	// alias's attribute snapshot is exactly as valid as it was a moment ago, so
	// there is nothing to reconcile and no debt to record.
	//
	// What DID change is which frontend identity names the path, and that is
	// already published by the caller's own namespace invalidation for every
	// changed path (addLocalDirs). Recording refresh debt here would not fix
	// anything; it would only mint obligations that no publisher owns, on a
	// control-plane call that has no reply to hold back.
	detachReprovisioned
)

// detachReincarnatedPathLocked removes one pathname from its old identity
// without reclaiming that identity. The authority may still expose the inode
// through another hard-link alias, and FSKit may still hold the published Item
// or an open handle. If the detached record was canonical, prefer a surviving
// alias as the canonical path; with no alias, retain the detached record until
// the kernel's explicit Reclaim releases the old Item.
func (a *attach) detachReincarnatedPathLocked(p string, rec *itemRecord, cause detachCause) {
	if rec == nil || a.paths[p] != rec {
		return
	}
	delete(a.paths, p)
	a.dropItemAliasLocked(rec.item.ItemID, p)
	// Keep authorityItems while the detached frontend Item remains live.
	// Locally unknown hard-link names may still resolve to this inode; their
	// later discovery must recover the exact Item/NodeState already published
	// for the replaced name. Reclaim is the lifetime boundary that drops the
	// retained identity when no kernel reference can discover more aliases.

	if a.items[rec.item.ItemID] == rec {
		var canonical *itemRecord
		for aliasPath := range a.itemAliases[rec.item.ItemID] {
			candidate := a.paths[aliasPath]
			if candidate == nil || candidate.item != rec.item || candidate.state != rec.state {
				continue
			}
			if canonical == nil || candidate.path < canonical.path {
				canonical = candidate
			}
		}
		if canonical != nil {
			a.items[rec.item.ItemID] = canonical
		}
		// No alias intentionally leaves rec canonical. The Item remains
		// addressable through its old NodeState until Reclaim.
	}
	// ── THE RETAINED ALIASES OWE A RECONCILIATION ───────────────────────────
	//
	// A pathname reincarnation replaces WHO `p` names; it does not change the
	// displaced inode, but it does change its LINK COUNT, and every retained
	// hard-link alias of that inode is now carrying a stale attribute snapshot
	// taken before the replacement.
	//
	// Nothing here can refresh them (this runs under a.mu, and refreshing needs
	// the authority), and the invalidation stream that normally does it is a
	// SEPARATE path with no ordering relationship to the lookup that is about
	// to publish the replacement. So applications saw the new `a` and then `b`
	// still claiming Nlink=2 — a lookup published a post-replacement identity
	// beside a pre-replacement alias.
	//
	// Record the debt against the registration that created it; that publisher
	// settles its OWN ticket BEFORE its reply leaves (see reincarnation.go).
	// Only a genuine replacement owes anything — see detachCause.
	if cause == detachReplaced {
		for aliasPath := range a.itemAliases[rec.item.ItemID] {
			a.recordReincarnationDebtLocked(aliasPath)
		}
	}
	if len(a.itemAliases[rec.item.ItemID]) == 0 {
		delete(a.awaitingAuthorityItems, rec.item.ItemID)
		entry := a.bindingEntryLocked("detach", rec)
		entry.Path = p
		a.pendingBindings = append(a.pendingBindings, entry)
	} else {
		a.pendingBindings = append(a.pendingBindings, bindingJournalEntry{
			Ref: a.ref, Op: "unbind", Path: p,
		})
	}
}

// indexAuthorityIdentityLocked publishes the authority side of a frontend
// identity after a delegated create is assigned its real inode. The frontend
// Item and NodeState are immutable as a pair: later lookup/readdir discovery
// of any hard-link alias must reuse both.
func (a *attach) indexAuthorityIdentityLocked(rec *itemRecord) {
	if rec == nil || rec.state == nil {
		return
	}
	authorityIno := rec.state.AuthorityIno()
	if authorityIno == 0 {
		return
	}
	identity := frontendItemIdentity{item: rec.item, state: rec.state}
	if current, ok := a.authorityItems[authorityIno]; ok &&
		(current.item != identity.item || current.state != identity.state) {
		// Identity is immutable once published. The handoff gate installs a
		// local create's mapping before peers may expose another name, so a
		// second mapping is never allowed to replace the canonical pair.
		return
	}
	a.authorityItems[authorityIno] = identity
	delete(a.awaitingAuthorityItems, rec.item.ItemID)
}

func (a *attach) dropAuthorityIdentityIfUnusedLocked(item pfslocal.Item, state *clientcore.NodeState) {
	if state == nil {
		return
	}
	authorityIno := state.AuthorityIno()
	identity, ok := a.authorityItems[authorityIno]
	if !ok || identity.item != item || identity.state != state {
		return
	}
	for alias := range a.itemAliases[item.ItemID] {
		if rec := a.paths[alias]; rec != nil && rec.state == state {
			return
		}
	}
	delete(a.authorityItems, authorityIno)
}

// publishAssignedAuthorityIdentitiesLocked advances the small set of
// delegation-born items whose NodeState was populated by the release pin
// protocol. It runs in the fallible prepared-handoff hook while the frontend
// gate and authority delegation are still held, so the mapping is journaled
// before Checkin can expose the inode to peers.
func (a *attach) publishAssignedAuthorityIdentitiesLocked() {
	for itemID := range a.awaitingAuthorityItems {
		rec := a.items[itemID]
		if rec == nil {
			delete(a.awaitingAuthorityItems, itemID)
			continue
		}
		if rec.state == nil || rec.state.AuthorityIno() == 0 {
			continue
		}
		a.indexAuthorityIdentityLocked(rec)
		for alias := range a.itemAliases[itemID] {
			if pathRec := a.paths[alias]; pathRec != nil {
				a.pendBindingLocked(pathRec)
			}
		}
	}
}

// pendBindingLocked buffers a binding delta for the caller's later
// flushBindingDelta. Caller holds a.mu.
func (a *attach) pendBindingLocked(rec *itemRecord) {
	a.pendingBindings = append(a.pendingBindings, a.bindingEntryLocked("bind", rec))
}

func (a *attach) bindingEntryLocked(op string, rec *itemRecord) bindingJournalEntry {
	if rec == nil {
		return bindingJournalEntry{Ref: a.ref, Op: op}
	}
	var authorityItemID uint64
	if rec.state != nil {
		authorityItemID = rec.state.AuthorityIno()
	}
	persistedAuthorityItemID := authorityItemID
	if persistedAuthorityItemID == rec.item.ItemID {
		persistedAuthorityItemID = 0
	}
	return bindingJournalEntry{
		Ref: a.ref, Op: op, Path: rec.path,
		ID: rec.item.ItemID, Gen: rec.item.ItemGeneration,
		Auth: authorityItemID != 0, AuthorityItemID: persistedAuthorityItemID,
		Kind:  rec.attr.Kind,
		Graft: rec.graft,
	}
}

// flushBindingDelta journals the binding changes buffered by the registration
// primitives since the last flush, then schedules the compacting persist.
// Every operation that can change bindings calls this after releasing a.mu
// and BEFORE replying, so an item ID never reaches the kernel without its
// binding being at least process-crash durable.
func (a *attach) flushBindingDelta() int32 {
	if err := a.flushBindingDeltaError(); err != nil {
		return darwinEIO
	}
	return 0
}

func (a *attach) flushBindingDeltaError() error {
	a.mu.Lock()
	pending := a.pendingBindings
	a.pendingBindings = nil
	a.mu.Unlock()
	if len(pending) == 0 {
		return nil
	}
	if a.journal != nil {
		if err := a.journal.append(pending); err != nil {
			a.failBindingPersistence(err)
			return err
		}
	}
	a.schedulePersistState()
	return nil
}

// persistAssignedAuthorityIdentities is the delegation handoff's
// OnHandoffPrepared hook. It is the a.mu acquisition that the recall-path
// lock-order invariant documented on onMarkOrphan protects: a handoff cannot
// complete until this hook has taken a.mu, so anything that holds a.mu while
// waiting on a clientcore.NodeState mutex can wedge the handoff forever. This
// hook itself only touches NodeState through the atomic authority-inode
// accessors (AuthorityIno/RecordAuthorityIno), which never take n.mu, so it
// stays on the safe side of the invariant.
func (a *attach) persistAssignedAuthorityIdentities(
	ctx context.Context,
	scope string,
	epoch string,
	cli *fsproto.Client,
) (func(bool), error) {
	type pendingIdentity struct {
		item  pfslocal.Item
		path  string
		state *clientcore.NodeState
	}
	a.mu.Lock()
	if a.coherenceFailFrozen {
		err := errors.New(a.lastErr)
		a.mu.Unlock()
		return nil, err
	}
	// protectOpenPins runs immediately before this hook and may already have
	// assigned live-open identities. Queue those durable mappings first, then
	// prepare every remaining published, active, authority-routed Item in the
	// released scope—even when its create handle was closed long ago.
	a.publishAssignedAuthorityIdentitiesLocked()
	var pending []pendingIdentity
	for itemID := range a.awaitingAuthorityItems {
		rec := a.items[itemID]
		if rec == nil || rec.graft || rec.path == "" ||
			!pathWithinScope(rec.path, scope) ||
			a.paths[rec.path] != rec ||
			rec.state == nil || rec.state.AuthorityIno() != 0 {
			continue
		}
		pending = append(pending, pendingIdentity{
			item: rec.item, path: rec.path, state: rec.state,
		})
	}
	a.mu.Unlock()
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].path == pending[j].path {
			return pending[i].item.ItemID < pending[j].item.ItemID
		}
		return pending[i].path < pending[j].path
	})

	var preparedInos []uint64
	resolved := make([]uint64, len(pending))
	cleanupPrepared := func() {
		if len(preparedInos) == 0 {
			return
		}
		unique := make([]uint64, 0, len(preparedInos))
		seen := make(map[uint64]struct{}, len(preparedInos))
		for _, ino := range preparedInos {
			if ino == 0 {
				continue
			}
			if _, ok := seen[ino]; ok {
				continue
			}
			seen[ino] = struct{}{}
			unique = append(unique, ino)
		}
		for start := 0; start < len(unique); start += fsproto.MaxPrepareOpenPaths {
			end := start + fsproto.MaxPrepareOpenPaths
			if end > len(unique) {
				end = len(unique)
			}
			if st, err := cli.UnmarkOpenBatch(unique[start:end]); err != nil || st != fsproto.OK {
				if err == nil {
					err = fmt.Errorf("authority status %d", st)
				}
				a.setErr(fmt.Errorf(
					"retire prepared published identities for %q: %w",
					scope, err,
				))
				return
			}
		}
	}
	for start := 0; start < len(pending); start += fsproto.MaxPrepareOpenPaths {
		if err := ctx.Err(); err != nil {
			cleanupPrepared()
			return nil, err
		}
		end := start + fsproto.MaxPrepareOpenPaths
		if end > len(pending) {
			end = len(pending)
		}
		paths := make([]string, end-start)
		for i := start; i < end; i++ {
			paths[i-start] = pending[i].path
		}
		inos, _, err := cli.PrepareDelegationRelease(scope, epoch, paths)
		if err != nil {
			cleanupPrepared()
			return nil, err
		}
		copy(resolved[start:end], inos)
		preparedInos = append(preparedInos, inos...)
	}

	a.mu.Lock()
	for i, target := range pending {
		rec := a.items[target.item.ItemID]
		if rec == nil || rec.item != target.item || rec.state != target.state ||
			rec.path != target.path || a.paths[target.path] != rec || rec.graft {
			a.mu.Unlock()
			cleanupPrepared()
			return nil, fmt.Errorf(
				"published identity %d at %q changed during prepared handoff",
				target.item.ItemID, target.path,
			)
		}
		if !target.state.RecordAuthorityIno(resolved[i]) {
			a.mu.Unlock()
			cleanupPrepared()
			return nil, fmt.Errorf(
				"published identity %d at %q rejected authority inode %d",
				target.item.ItemID, target.path, resolved[i],
			)
		}
	}
	a.publishAssignedAuthorityIdentitiesLocked()
	a.mu.Unlock()
	if err := a.flushBindingDeltaError(); err != nil {
		cleanupPrepared()
		return nil, err
	}
	if len(preparedInos) == 0 {
		return nil, nil
	}
	return func(bool) { cleanupPrepared() }, nil
}

func (a *attach) failBindingPersistence(err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	var gateErr error
	if !a.coherenceFailFrozen {
		a.coherenceFailFrozen = true
		a.lastErr = "item identity journal failed closed: " + err.Error()
		a.state = pfslocal.AttachStateDegraded
		a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{
			State: pfslocal.AttachStateDegraded, Detail: a.lastErr,
		}})
	}
	gateErr = errors.New(a.lastErr)
	a.mu.Unlock()
	a.failFrontendGate(gateErr)
}

// applyJournalEntry replays one binding delta at daemon startup, mirroring
// restoreItemsLocked's construction and strict persisted-item validation.
func (a *attach) applyJournalEntry(e bindingJournalEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch e.Op {
	case "bind":
		if _, ok := fskitItemID(e.ID); !ok {
			return fmt.Errorf("bind has unrepresentable item id %d", e.ID)
		}
		if authorityItemID := e.authorityItemID(); authorityItemID != 0 {
			if _, ok := fskitItemID(authorityItemID); !ok {
				return fmt.Errorf("bind has unrepresentable authority item id %d", authorityItemID)
			}
		}
		if e.Gen == 0 || e.Gen != a.identityEpoch || !validJournalPath(e.Path) {
			return nil
		}
		if prev := a.paths[e.Path]; prev != nil {
			// FSKit can remain mounted and reconnect across a portablefsd
			// restart. Preserve the replaced binding until its exact Item
			// generation is reclaimed; the new bind must not collapse a
			// still-live pre-restart vnode into the replacement identity.
			a.dropPathLocked(e.Path)
		}
		attr := fsproto.Attr{Ino: e.ID, Kind: e.Kind}
		if e.Path == "" {
			attr = syntheticRootAttr()
			attr.Ino = e.ID
		}
		rec := &itemRecord{
			item:  pfslocal.Item{ItemID: e.ID, ItemGeneration: e.Gen},
			path:  e.Path,
			state: clientcore.NewNodeStateWithAuthority(e.ID, e.authorityItemID()),
			attr:  attr,
			graft: e.Graft,
		}
		if canonical := a.items[e.ID]; canonical != nil {
			rec.state = canonical.state
			if a.paths[canonical.path] != canonical {
				a.items[e.ID] = rec
			}
		} else {
			a.items[e.ID] = rec
		}
		a.paths[e.Path] = rec
		a.addItemAliasLocked(rec)
		a.indexAuthorityIdentityLocked(rec)
		if !rec.graft && rec.path != "" && rec.state.AuthorityIno() == 0 {
			a.awaitingAuthorityItems[rec.item.ItemID] = struct{}{}
		}
		a.frontendPathEpoch.Add(1)
		if e.Path == "" {
			a.root = rec
		}
	case "unbind":
		a.dropPathLocked(e.Path)
	case "detach":
		if _, ok := fskitItemID(e.ID); !ok {
			return fmt.Errorf("detach has unrepresentable item id %d", e.ID)
		}
		if authorityItemID := e.authorityItemID(); authorityItemID != 0 {
			if _, ok := fskitItemID(authorityItemID); !ok {
				return fmt.Errorf("detach has unrepresentable authority item id %d", authorityItemID)
			}
		}
		if e.Gen == 0 || e.Gen != a.identityEpoch ||
			!validJournalPath(e.Path) || e.Path == "" {
			return nil
		}
		if prev := a.paths[e.Path]; prev != nil &&
			prev.item.ItemID == e.ID && prev.item.ItemGeneration == e.Gen {
			if e.Kind != "" {
				prev.attr.Kind = e.Kind
			}
			a.dropPathLocked(e.Path)
		}
		if current := a.items[e.ID]; current == nil ||
			current.item.ItemGeneration != e.Gen {
			rec := &itemRecord{
				item:  pfslocal.Item{ItemID: e.ID, ItemGeneration: e.Gen},
				path:  e.Path,
				state: clientcore.NewNodeStateWithAuthority(e.ID, e.authorityItemID()),
				attr:  fsproto.Attr{Ino: e.ID, Kind: e.Kind},
				graft: e.Graft,
			}
			a.items[e.ID] = rec
			a.indexAuthorityIdentityLocked(rec)
		}
	case "reclaim":
		if _, ok := fskitItemID(e.ID); !ok {
			return fmt.Errorf("reclaim has unrepresentable item id %d", e.ID)
		}
		if e.Gen == 0 || e.Gen != a.identityEpoch {
			return nil
		}
		a.reclaimItemLocked(pfslocal.Item{ItemID: e.ID, ItemGeneration: e.Gen})
	case "rekey":
		if !validJournalPath(e.From) || !validJournalPath(e.To) {
			return nil
		}
		a.renamePathLocked(e.From, e.To)
	}
	return nil
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
		// UInt64.max has no FSKit representation because the platform
		// boundary reserves one successor value for every pfslocal identity.
		// Reject it at allocation rather than letting the checked mapping fail
		// after this identity has been published and persisted.
		if _, representable := fskitItemID(id); representable && a.items[id] == nil {
			return id
		}
	}
}

func (a *attach) restoreItemsLocked(items []persistedItemRecord) {
	for _, item := range items {
		if _, ok := fskitItemID(item.ItemID); !ok || item.ItemGeneration == 0 {
			continue
		}
		if authorityItemID := item.authorityItemID(); authorityItemID != 0 {
			if _, ok := fskitItemID(authorityItemID); !ok {
				continue
			}
		}
		attr := fsproto.Attr{Ino: item.ItemID, Kind: item.Kind}
		if item.Path == "" {
			attr = syntheticRootAttr()
			attr.Ino = item.ItemID
		}
		rec := &itemRecord{
			item:  pfslocal.Item{ItemID: item.ItemID, ItemGeneration: item.ItemGeneration},
			path:  item.Path,
			state: clientcore.NewNodeStateWithAuthority(item.ItemID, item.authorityItemID()),
			attr:  attr,
			graft: item.Graft,
		}
		if canonical := a.items[item.ItemID]; canonical != nil {
			rec.state = canonical.state
		} else {
			a.items[item.ItemID] = rec
		}
		if !item.Detached {
			a.paths[item.Path] = rec
			a.addItemAliasLocked(rec)
			if canonical := a.items[item.ItemID]; canonical == nil ||
				a.paths[canonical.path] != canonical {
				a.items[item.ItemID] = rec
			}
			if !rec.graft && rec.path != "" && rec.state.AuthorityIno() == 0 {
				a.awaitingAuthorityItems[rec.item.ItemID] = struct{}{}
			}
		}
		a.indexAuthorityIdentityLocked(rec)
		a.frontendPathEpoch.Add(1)
		if item.Path == "" {
			a.root = rec
		}
	}
}

func (a *attach) persistedItemsLocked() []persistedItemRecord {
	items := make([]persistedItemRecord, 0, len(a.paths)+len(a.items))
	appendRecord := func(rec *itemRecord, detached bool) {
		if rec == nil || rec.item.ItemID == 0 {
			return
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
			Kind:            rec.attr.Kind,
			Graft:           rec.graft,
			Detached:        detached,
		})
	}
	for _, rec := range a.paths {
		appendRecord(rec, false)
	}
	for itemID, rec := range a.items {
		if rec != nil && rec.path != "" && len(a.itemAliases[itemID]) == 0 {
			appendRecord(rec, true)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Path == items[j].Path {
			if items[i].Detached != items[j].Detached {
				return !items[i].Detached
			}
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

// lockFrontendRequest establishes the same serialization order before a
// request enters frontendActive that the concrete operation will establish
// with nsMu/nameLocks afterward. The locks are separate mirrors: recursive
// acquisition of sync.RWMutex is unsafe when a writer is pending.
func (a *attach) lockFrontendRequest(body any) func() {
	exclusive := false
	mutatesName := false
	switch req := body.(type) {
	case *pfslocal.RenameRequest,
		*pfslocal.ReclaimRequest:
		// Reclaim owns nsMu exclusively while it retires item identity. Its
		// mirror must be exclusive too: otherwise a later publishing reader
		// can enter frontendActive, queue behind the pending nsMu writer, and
		// cyclically block a delegation handoff waiting for that reader to
		// publish.
		exclusive = true
	case *pfslocal.RemoveRequest:
		exclusive = req.Directory
		mutatesName = !req.Directory
	case *pfslocal.SetAttrRequest,
		*pfslocal.WriteRequest,
		*pfslocal.CreateRequest,
		*pfslocal.MkdirRequest,
		*pfslocal.SymlinkRequest,
		*pfslocal.HardLinkRequest,
		*pfslocal.XattrSetRequest,
		*pfslocal.XattrRemoveRequest:
		mutatesName = true
	}
	if exclusive {
		a.frontendSerial.Lock()
		return a.frontendSerial.Unlock
	}
	a.frontendSerial.RLock()
	unlockHandle := a.lockFrontendHandleRequest(body)
	if !mutatesName {
		if unlockHandle == nil {
			return a.frontendSerial.RUnlock
		}
		return func() {
			unlockHandle()
			a.frontendSerial.RUnlock()
		}
	}
	paths, _, _ := a.frontendOperationPaths(body)
	unlockNames := a.lockFrontendRequestNames(paths)
	return func() {
		unlockNames()
		if unlockHandle != nil {
			unlockHandle()
		}
		a.frontendSerial.RUnlock()
	}
}

func frontendRequestHandle(body any) (id uint64, exclusive bool) {
	switch req := body.(type) {
	case *pfslocal.GetAttrRequest:
		return req.Handle, false
	case *pfslocal.SetAttrRequest:
		return req.Handle, false
	case *pfslocal.CloseRequest:
		return req.Handle, true
	case *pfslocal.ReadRequest:
		return req.Handle, false
	case *pfslocal.WriteRequest:
		return req.Handle, false
	case *pfslocal.XattrGetRequest:
		return req.Handle, false
	case *pfslocal.XattrSetRequest:
		return req.Handle, false
	case *pfslocal.XattrListRequest:
		return req.Handle, false
	case *pfslocal.XattrRemoveRequest:
		return req.Handle, false
	case *pfslocal.FsyncRequest:
		return req.Handle, false
	default:
		return 0, false
	}
}

// lockFrontendHandleRequest mirrors the concrete per-handle lock before a
// logical callback becomes publication-active. Missing handles need no lock:
// handle IDs are never reused, and the concrete operation will return its
// precise protocol error.
func (a *attach) lockFrontendHandleRequest(body any) func() {
	id, exclusive := frontendRequestHandle(body)
	if id == 0 {
		return nil
	}
	a.mu.Lock()
	h := a.handles[id]
	if h == nil {
		a.mu.Unlock()
		return nil
	}
	if h.operationLocks == nil {
		h.operationLocks = &handleOperationLocks{}
	}
	gate := h.operationLocks
	a.mu.Unlock()
	if exclusive {
		gate.frontend.Lock()
		return gate.frontend.Unlock
	}
	gate.frontend.RLock()
	return gate.frontend.RUnlock
}

// lockHandleOperation coordinates concrete operations for one live descriptor.
// It never waits while holding a.mu. If the descriptor retires while this
// request waits, the operation proceeds without the stale gate so its normal
// target lookup can return the exact replay/error semantics.
func (a *attach) lockHandleOperation(id uint64, exclusive bool) func() {
	if id == 0 {
		return nil
	}
	a.mu.Lock()
	h := a.handles[id]
	if h == nil {
		a.mu.Unlock()
		return nil
	}
	if h.operationLocks == nil {
		h.operationLocks = &handleOperationLocks{}
	}
	gate := h.operationLocks
	a.mu.Unlock()

	if exclusive {
		gate.concrete.Lock()
	} else {
		gate.concrete.RLock()
	}
	a.mu.RLock()
	stillLive := a.handles[id] == h
	a.mu.RUnlock()
	if !stillLive {
		if exclusive {
			gate.concrete.Unlock()
		} else {
			gate.concrete.RUnlock()
		}
		return nil
	}
	if exclusive {
		return gate.concrete.Unlock
	}
	return gate.concrete.RUnlock
}

func unlockIfPresent(unlock func()) {
	if unlock != nil {
		unlock()
	}
}

func (a *attach) lockFrontendRequestNames(paths []string) func() {
	seen := map[int]struct{}{}
	idx := make([]int, 0, len(paths))
	for _, p := range paths {
		k := entryKey(p)
		i := int(clientcore.InoOf(k.dir+"\x00"+k.name) & 63)
		if _, ok := seen[i]; ok {
			continue
		}
		seen[i] = struct{}{}
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		a.frontendNameLocks[i].Lock()
	}
	return func() {
		for i := len(idx) - 1; i >= 0; i-- {
			a.frontendNameLocks[idx[i]].Unlock()
		}
	}
}

// Non-frontend operations acquire the mirror before the concrete namespace
// lock. A frontend callback waiting on nsMu is already represented in the
// handoff publication gate, so reversing this order would let a control or
// lifecycle operation hold nsMu while its delegation release waits for that
// same callback.
func (a *attach) lockExternalNamespaceRead() func() {
	a.frontendSerial.RLock()
	a.nsMu.RLock()
	return func() {
		a.nsMu.RUnlock()
		a.frontendSerial.RUnlock()
	}
}

func (a *attach) lockExternalNamespaceWrite() func() {
	a.frontendSerial.Lock()
	a.nsMu.Lock()
	return func() {
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
	}
}

// lockExternalNamespaceMutation is the control plane's phase 2 for a write that
// mutates exactly ONE name through the authority.
//
// It is deliberately the same shape as a name-mutating kernel request's:
// lockFrontendRequest's shared serialization mirror and the frontend stripe for
// that name, then the handler's own SHARED namespace lock and the concrete name
// stripe — the exact sequence attach.create and attach.setattr establish for the
// identical authority calls.
//
// The control write used lockExternalNamespaceWrite instead, so its Lookup,
// Create, Open, Write, Setattr and Getattr — six real round trips — ran under a
// mount-wide EXCLUSIVE nsMu.Lock. Pre-lock admission bounds the CLASSIFICATION,
// not the mutation, so that hold lasted as long as the uplink did; and because
// Go's RWMutex is writer-preferring, it parked every nsMu.RLock behind it, which
// is every lookup, getattr, read and readdir in the mount, on every path,
// including paths the write never touches. A control write is not more
// privileged than the kernel frontend performing the same mutation and must not
// hold a heavier lock than it.
//
// The exclusive gate also provided mutual exclusion between two control writes
// to the same name by accident. The concrete name stripe provides it on purpose,
// which is the same guarantee the kernel frontend relies on.
//
// The order — mirror before concrete lock — is the global one documented above.
func (a *attach) lockExternalNamespaceMutation(p string) func() {
	a.frontendSerial.RLock()
	unlockFrontendNames := a.lockFrontendRequestNames([]string{p})
	a.nsMu.RLock()
	unlockNames := a.lockNames(entryKey(p))
	return func() {
		unlockNames()
		a.nsMu.RUnlock()
		unlockFrontendNames()
		a.frontendSerial.RUnlock()
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
	if a.detached || a.detachPrepared || a.detachForce {
		return nil, darwinENXIO
	}
	rec := a.items[item.ItemID]
	if rec == nil || rec.item.ItemGeneration != item.ItemGeneration {
		return nil, darwinENOENT
	}
	if current := a.paths[rec.path]; current != rec {
		// The Item is retained solely for Reclaim, open-handle state, and
		// late hard-link discovery. Its remembered pathname has been removed
		// or now names a replacement inode; ordinary Item operations must
		// never route through that stale name.
		return nil, darwinENOENT
	}
	cp := *rec
	return &cp, 0
}

type objectTarget struct {
	rec      *itemRecord
	handle   *handleRecord
	scope    string
	detached bool
}

// objectTarget resolves an item-based operation against either its genuine
// namespace binding or one explicit live descriptor. Namespace operations
// continue to use item(): a stale remembered path is never reachability
// evidence. The explicit handle is both the lifetime witness and the exact
// object capability for fstat/ftruncate/f*xattr after unlink or rename-over.
func (a *attach) objectTarget(item pfslocal.Item, handleID uint64) (objectTarget, int32) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.detached || a.detachPrepared || a.detachForce {
		return objectTarget{}, darwinENXIO
	}
	rec := a.items[item.ItemID]
	if rec == nil || rec.item.ItemGeneration != item.ItemGeneration {
		return objectTarget{}, darwinENOENT
	}
	bound := a.paths[rec.path] == rec
	if handleID == 0 {
		if !bound {
			return objectTarget{}, darwinENOENT
		}
		recCopy := *rec
		// The identity-only lane must name the object through the same
		// deterministic alias the handle lane uses. rec.path is merely the
		// first alias that happened to register, so a hard-linked file would
		// otherwise report a different parent depending on whether a
		// descriptor is open.
		return objectTarget{rec: &recCopy, scope: a.canonicalItemAliasLocked(rec)}, 0
	}

	h := a.handles[handleID]
	if h == nil {
		if !bound {
			return objectTarget{}, darwinENOENT
		}
		return objectTarget{}, darwinEINVAL
	}
	if h.itemID != item.ItemID {
		return objectTarget{}, darwinEINVAL
	}
	if rec.graft {
		if h.state != nil || h.file == nil {
			return objectTarget{}, darwinEINVAL
		}
	} else if rec.state == nil || h.file != nil || h.state != rec.state {
		return objectTarget{}, darwinEINVAL
	}
	recCopy := *rec
	handleCopy := *h
	scope := a.canonicalItemAliasLocked(rec)
	return objectTarget{
		rec: &recCopy, handle: &handleCopy, scope: scope, detached: scope == "",
	}, 0
}

// canonicalItemAliasLocked returns a deterministic genuine namespace alias
// for rec's immutable Item/object identity. A handle's remembered open path
// is deliberately irrelevant: it may now name a replacement while another
// hard-link alias still names the retained object. Caller holds a.mu for read.
func (a *attach) canonicalItemAliasLocked(rec *itemRecord) string {
	if rec == nil {
		return ""
	}
	var canonical string
	for aliasPath := range a.itemAliases[rec.item.ItemID] {
		alias := a.paths[aliasPath]
		if alias == nil || alias.item != rec.item || alias.graft != rec.graft ||
			alias.state != rec.state {
			continue
		}
		if canonical == "" || aliasPath < canonical {
			canonical = aliasPath
		}
	}
	return canonical
}

// hasBoundDescendantsLocked reports whether any live namespace binding sits
// beneath one of rec's aliases. A directory Item is the parent identity every
// child it still binds reports, so retiring it would leave those children
// answering FSKit with an invalid parent. Refuse exactly as an open handle
// does and let the host retry once it has retired the subtree. Non-directories
// never match, so no kind test is needed. Caller holds a.mu.
func (a *attach) hasBoundDescendantsLocked(rec *itemRecord) bool {
	// The root's alias is the empty string, which prefixes every path; it is
	// also never reclaimed, so exclude it before the prefix test.
	if rec == nil || rec.path == "" {
		return false
	}
	var prefixes []string
	for aliasPath := range a.itemAliases[rec.item.ItemID] {
		if aliasPath == "" {
			continue
		}
		if alias := a.paths[aliasPath]; alias != nil && alias.item == rec.item {
			prefixes = append(prefixes, aliasPath+"/")
		}
	}
	if len(prefixes) == 0 {
		return false
	}
	for p := range a.paths {
		for _, prefix := range prefixes {
			if strings.HasPrefix(p, prefix) {
				return true
			}
		}
	}
	return false
}

// handleTarget resolves an existing read/write/fsync descriptor and returns a
// deterministic genuine alias when one exists. Authority operations use that
// alias only as delegation scope; the stable handle inode remains the object
// capability. With no genuine alias they use the pathless exact lane.
func (a *attach) handleTarget(id uint64) (*handleRecord, string, int32) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.detached || a.detachPrepared || a.detachForce {
		return nil, "", darwinENXIO
	}
	h := a.handles[id]
	if h == nil {
		return nil, "", darwinEINVAL
	}
	rec := a.items[h.itemID]
	if rec == nil {
		return nil, "", darwinENOENT
	}
	if rec.graft {
		if h.state != nil || h.file == nil {
			return nil, "", darwinEINVAL
		}
	} else if rec.state == nil || h.file != nil || h.state != rec.state {
		return nil, "", darwinEINVAL
	}
	cp := *h
	return &cp, a.canonicalItemAliasLocked(rec), 0
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
	rec := a.paths[p]
	if rec == nil {
		return
	}
	entry := bindingJournalEntry{Ref: a.ref, Op: "unbind", Path: p}
	if a.dropPathLocked(p) {
		if current := a.items[rec.item.ItemID]; current != nil &&
			current.item.ItemGeneration == rec.item.ItemGeneration &&
			len(a.itemAliases[rec.item.ItemID]) == 0 {
			// The last known name is gone, but the frontend Item lifetime is
			// not. Journal the detached identity explicitly so a daemon
			// restart cannot split an unseen peer hard link from the FSKit
			// vnode that already represents it.
			entry = a.bindingEntryLocked("detach", rec)
			entry.Path = p
		}
		a.pendingBindings = append(a.pendingBindings, entry)
	}
}

func (a *attach) dropPathLocked(p string) bool {
	if rec := a.paths[p]; rec != nil {
		// Removing a pathname does not prove that a regular-file inode is no
		// longer live. A peer may already have created a hard-link alias that
		// this frontend has never observed, and FSKit may still hold the
		// published Item or an open handle. Keep that Item↔authority identity
		// detached until explicit Reclaim; a later alias lookup can then reuse
		// it instead of publishing a second frontend object.
		retainIdentity := rec.attr.Kind != "directory"
		delete(a.paths, p)
		a.dropItemAliasLocked(rec.item.ItemID, p)
		a.frontendPathEpoch.Add(1)
		if a.items[rec.item.ItemID] == rec {
			var canonical *itemRecord
			for aliasPath := range a.itemAliases[rec.item.ItemID] {
				alias := a.paths[aliasPath]
				if alias == nil || alias.item != rec.item || alias.state != rec.state {
					continue
				}
				if canonical == nil || alias.path < canonical.path {
					canonical = alias
				}
			}
			if canonical != nil {
				a.items[rec.item.ItemID] = canonical
			} else if !retainIdentity {
				delete(a.items, rec.item.ItemID)
			}
		}
		if !retainIdentity {
			a.dropAuthorityIdentityIfUnusedLocked(rec.item, rec.state)
		}
		if len(a.itemAliases[rec.item.ItemID]) == 0 {
			delete(a.awaitingAuthorityItems, rec.item.ItemID)
		}
		return true
	}
	return false
}

// forgetPathLocked permanently drops a path identity. It is intentionally not
// used by journal replay: FSKit may remain mounted across a daemon restart, so
// only an explicit Reclaim may retire a detached frontend Item generation.
func (a *attach) forgetPathLocked(p string) bool {
	rec := a.paths[p]
	if rec == nil {
		return false
	}
	delete(a.paths, p)
	a.dropItemAliasLocked(rec.item.ItemID, p)
	a.frontendPathEpoch.Add(1)
	if a.items[rec.item.ItemID] == rec {
		delete(a.items, rec.item.ItemID)
		var canonical *itemRecord
		for aliasPath := range a.itemAliases[rec.item.ItemID] {
			alias := a.paths[aliasPath]
			if alias == nil || alias.item != rec.item || alias.state != rec.state {
				continue
			}
			if canonical == nil || alias.path < canonical.path {
				canonical = alias
			}
		}
		if canonical != nil {
			a.items[rec.item.ItemID] = canonical
		}
	}
	a.dropAuthorityIdentityIfUnusedLocked(rec.item, rec.state)
	if len(a.itemAliases[rec.item.ItemID]) == 0 {
		delete(a.awaitingAuthorityItems, rec.item.ItemID)
	}
	return true
}

// reclaimItemLocked is the sole lifetime boundary for a published non-root
// frontend Item. It removes every alias and the retained authority index for
// exactly one Item generation without touching a replacement that happens to
// reuse one of its old names. Caller holds a.mu.
func (a *attach) reclaimItemLocked(item pfslocal.Item) bool {
	rec := a.items[item.ItemID]
	if rec == nil || rec.item.ItemGeneration != item.ItemGeneration || rec.path == "" {
		return false
	}
	changed := false
	for p, alias := range a.paths {
		if alias.item != item {
			continue
		}
		delete(a.paths, p)
		a.dropItemAliasLocked(item.ItemID, p)
		changed = true
	}
	if changed {
		a.frontendPathEpoch.Add(1)
	}
	current := a.items[item.ItemID]
	if current == nil || current.item.ItemGeneration != item.ItemGeneration {
		return changed
	}
	a.dropAuthorityIdentityIfUnusedLocked(current.item, current.state)
	delete(a.items, item.ItemID)
	delete(a.awaitingAuthorityItems, item.ItemID)
	delete(a.itemAliases, item.ItemID)
	return true
}

func (a *attach) renamePathLocked(oldp, newp string) {
	changed := false
	for p, rec := range a.paths {
		if np, ok := renamedPath(p, oldp, newp); ok {
			delete(a.paths, p)
			a.dropItemAliasLocked(rec.item.ItemID, p)
			rec.path = np
			a.paths[rec.path] = rec
			a.addItemAliasLocked(rec)
			changed = true
		}
	}
	for id, h := range a.handles {
		if np, ok := renamedPath(h.path, oldp, newp); ok {
			cp := *h
			cp.path = np
			a.handles[id] = &cp
			changed = true
		}
	}
	if changed {
		a.frontendPathEpoch.Add(1)
	}
	// A volume rename that moves an ancestor of a graft root carries the graft
	// (and its machine-local backing) to the new location, mirroring how a
	// mountpoint travels with its directory vnode. Persistence is the caller's
	// job: every rename path already persists after releasing a.mu.
	a.remapLocalDirsForRenameLocked(oldp, newp)
	a.pendingBindings = append(a.pendingBindings, bindingJournalEntry{Ref: a.ref, Op: "rekey", From: oldp, To: newp})
}

func (a *attach) addItemAliasLocked(rec *itemRecord) {
	if rec == nil || rec.item.ItemID == 0 {
		return
	}
	if a.itemAliases == nil {
		a.itemAliases = map[uint64]map[string]struct{}{}
	}
	paths := a.itemAliases[rec.item.ItemID]
	if paths == nil {
		paths = map[string]struct{}{}
		a.itemAliases[rec.item.ItemID] = paths
	}
	paths[rec.path] = struct{}{}
}

func (a *attach) dropItemAliasLocked(itemID uint64, path string) {
	paths := a.itemAliases[itemID]
	delete(paths, path)
	if len(paths) == 0 {
		delete(a.itemAliases, itemID)
	}
}

func renamedPath(p, oldp, newp string) (string, bool) {
	if p != oldp && !strings.HasPrefix(p, oldp+"/") {
		return "", false
	}
	return newp + strings.TrimPrefix(p, oldp), true
}

func (a *attach) newHandleLocked(path string, itemID uint64, state *clientcore.NodeState, write, appendOnly bool) uint64 {
	a.nextHandle++
	if a.nextHandle == 0 {
		a.nextHandle++
	}
	id := a.nextHandle
	a.handles[id] = &handleRecord{
		id: id, itemID: itemID, path: path, openPath: path, state: state, write: write,
		appendOnly:     appendOnly,
		operationLocks: &handleOperationLocks{},
	}
	return id
}

func (a *attach) newLocalHandleLocked(path string, itemID uint64, file *os.File, write, appendOnly bool) uint64 {
	a.nextHandle++
	if a.nextHandle == 0 {
		a.nextHandle++
	}
	id := a.nextHandle
	a.handles[id] = &handleRecord{
		id: id, itemID: itemID, path: path, openPath: path, write: write, file: file,
		appendOnly:     appendOnly,
		operationLocks: &handleOperationLocks{},
	}
	return id
}

func (a *attach) handle(id uint64) (*handleRecord, int32) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.detached || a.detachPrepared || a.detachForce {
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

// replayRetiredClose returns the exact terminal outcome for an already
// consumed handle. Handle IDs are monotonic for one live attach, so a nonzero
// ID at or below the high-water mark that is absent from handles was issued
// and retired. Terminal close errors are retained explicitly because retrying
// close(2) is unsafe and a lost local-protocol reply must not erase that
// outcome.
func (a *attach) replayRetiredClose(id uint64) (*pfslocal.CloseReply, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if id == 0 || id > a.nextHandle || a.handles[id] != nil {
		return nil, false
	}
	return &pfslocal.CloseReply{
		Retired:    true,
		CloseErrno: a.retiredCloseErrnos[id],
	}, true
}

func (a *attach) recordRetiredCloseError(id uint64, errno int32) {
	if errno == 0 {
		return
	}
	a.mu.Lock()
	if a.retiredCloseErrnos == nil {
		a.retiredCloseErrnos = make(map[uint64]int32)
	}
	a.retiredCloseErrnos[id] = errno
	a.mu.Unlock()
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

// publishItemContentInvalidationLocked publishes against the retained Item
// identity and only derives a version from genuine current aliases. It never
// resolves the Item's remembered path, which may now name a replacement.
func (a *attach) publishItemContentInvalidationLocked(item pfslocal.Item, skipOrigin uint64) {
	rec := a.items[item.ItemID]
	if rec == nil || rec.item.ItemGeneration != item.ItemGeneration {
		return
	}
	var version uint64
	for alias := range a.itemAliases[item.ItemID] {
		current := a.paths[alias]
		if current == nil || current.item != rec.item {
			continue
		}
		var aliasVersion uint64
		if a.localDirForLocked(alias) != "" {
			aliasVersion = a.bumpLocalVersionLocked(alias)
		} else if a.vol != nil {
			_, aliasVersion = a.vol.VersionCache.GenAndVersion(alias)
		}
		if aliasVersion > version {
			version = aliasVersion
		}
	}
	a.publishExceptLocked(pfslocal.Event{Kind: &pfslocal.Invalidation{
		Item: rec.item, ContentChanged: true, AttrsChanged: true, ContentVersion: version,
	}}, skipOrigin)
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

// onMarkOrphan runs on the authority recall/invalidation path.
//
// LOCK-ORDER INVARIANT (recall path): code on this path must never block on a
// clientcore.NodeState mutex while it holds a.mu. A suspended frontend
// mutation can own its NodeState.mu across an unbounded wait for a delegation
// handoff to finish (clientcore/ops.go takes n.mu around the authority round
// trip, and the round trip suspends and resumes through the frontend
// publication gate). The handoff cannot finish until its own OnHandoffPrepared
// hook, persistAssignedAuthorityIdentities, has taken a.mu. Holding a.mu while
// waiting for n.mu therefore closes an untimed cycle:
//
//	frontend mutation: n.mu held -> waits for handoff to end
//	handoff:           waits for a.mu (persistAssignedAuthorityIdentities)
//	recall:            a.mu held  -> waits for n.mu
//
// The registry maps (a.paths, a.handles, a.vol) are the only things a.mu
// protects here, and a NodeState's own mutex has never been ordered under
// a.mu, so collecting the targets under a.mu and marking them after releasing
// it is exactly equivalent — MarkOrphan already re-checks the node's open
// count under n.mu, and a reincarnated pathname always receives a fresh
// NodeState, so the captured pointers cannot be redirected by the gap.
func (a *attach) onMarkOrphan(p string, ino uint64) {
	a.mu.Lock()
	states := make(map[*clientcore.NodeState]struct{})
	if rec := a.paths[p]; rec != nil {
		// Match the authority identity, never just the path. Invalidation
		// delivery can trail remove+recreate: a locally-born replacement has
		// AuthIno false but is still a different node and must not be routed
		// to the retired inode. Delegation release records the proven
		// authority inode before a peer can unlink an open local create.
		if rec.state.MatchesAuthorityIno(ino) {
			states[rec.state] = struct{}{}
		}
	}
	// A replacement lookup may already have reincarnated p while an old
	// handle still owns the removed inode's NodeState. Route every matching
	// live authority handle to orphan I/O; path lookup alone would miss that
	// exact open-after-rename window and redirect the handle to the new inode.
	for _, handle := range a.handles {
		if handle.file == nil && handle.state != nil &&
			handle.state.MatchesAuthorityIno(ino) {
			states[handle.state] = struct{}{}
		}
	}
	var orphans *clientcore.InodeSet
	if a.vol != nil {
		orphans = a.vol.OpenOrphans()
	}
	barrier := a.testBeforeMarkOrphan
	a.mu.Unlock()
	// Every NodeState mutex below is taken with a.mu released; see the
	// lock-order invariant on this function.
	for state := range states {
		if barrier != nil {
			barrier()
		}
		state.MarkOrphan(ino, orphans)
	}
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
			// true means a RelatedInos claim requires an exact refresh of
			// that authority inode. A false entry is an ordinary path-local
			// refresh for which namespace replacement may make the old sample
			// obsolete without a content claim.
			refreshItems := make(map[uint64]bool)
			invalidatedItems := make(map[uint64]struct{})
			refreshAll := false
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
					refreshAll = true
					continue
				}
				if inv.Path == "" && len(inv.RelatedInos) == 0 {
					continue
				}
				a.mu.Lock()
				// Volume changes under a graft are shadowed by the machine-local
				// subtree; surfacing them would evict valid local kernel state.
				shadowed := inv.Path != "" && a.localDirForLocked(inv.Path) != ""
				if inv.Path != "" && !shadowed {
					a.publishAuthorityInvalidationLocked(inv.Path, inv.InPlace, inv.Version)
					if inv.InPlace {
						if rec := a.paths[inv.Path]; rec != nil {
							requireIdentity := regularFileIdentityRequired(rec.attr.Kind)
							if current, exists := refreshItems[rec.item.ItemID]; !exists ||
								(requireIdentity && !current) {
								// A path-local regular-file write still
								// carries an exact identity claim. A
								// rename-over can otherwise replace this
								// name before sampling and let the old live
								// vnode falsely settle on the new inode.
								refreshItems[rec.item.ItemID] = requireIdentity
							}
						}
					}
				}
				for _, authorityIno := range inv.RelatedInos {
					identity, known := a.authorityItems[authorityIno]
					if !known || identity.item.ItemID == 0 {
						continue
					}
					itemID := identity.item.ItemID
					if a.itemOwnedByGraftLocked(itemID) {
						// Authority invalidations never own machine-local
						// graft state, including a detached graft Item whose
						// remembered path remains under the graft root.
						continue
					}
					var chosen *itemRecord
					for alias := range a.itemAliases[itemID] {
						// A namespace event says this particular name may now
						// bind another inode. Refresh a surviving alias of the
						// related inode, never the replaced name itself.
						if !inv.InPlace && alias == inv.Path {
							continue
						}
						candidate := a.paths[alias]
						if candidate == nil || candidate.state == nil ||
							!candidate.state.MatchesAuthorityIno(authorityIno) ||
							a.localDirForLocked(alias) != "" {
							continue
						}
						if chosen == nil || candidate.path < chosen.path {
							chosen = candidate
						}
					}
					if chosen == nil {
						// The inode is retained and therefore may back a live
						// vnode, but no current pathname proves where to
						// refresh it. Keep the barrier closed unless a lookup
						// discovers and promotes the unseen alias while the
						// bounded exact refresh is waiting.
						refreshItems[itemID] = true
						continue
					}
					// Keep future exact samples on a still-valid alias when
					// the previous canonical name was replaced.
					a.items[itemID] = chosen
					if _, already := invalidatedItems[itemID]; !already {
						a.publishContentInvalidationLocked(chosen.path, inv.Version, 0)
						invalidatedItems[itemID] = struct{}{}
					}
					refreshItems[itemID] = true
				}
				a.mu.Unlock()
			}
			if refreshAll {
				a.mu.RLock()
				for itemID, rec := range a.items {
					if rec != nil && !a.itemOwnedByGraftLocked(itemID) {
						requireIdentity := regularFileIdentityRequired(rec.attr.Kind)
						if current, exists := refreshItems[itemID]; !exists ||
							(requireIdentity && !current) {
							// FlushAll may be the overflow representation of
							// lost RelatedInos/name history. Every retained
							// regular-file Item (plus legacy records whose
							// kind is not persisted) therefore carries an
							// exact identity claim; a detached stale name
							// cannot settle the barrier. Nonregular samples
							// are independently proved safe by the sampler.
							refreshItems[itemID] = requireIdentity
						}
					}
				}
				a.mu.RUnlock()
			}
			// The authority's durability/coherence barriers wait for this
			// acknowledgement. Do not advance it until every possibly-live
			// macOS vnode has adopted the new size and discarded stale pages.
			// Any refresh failure fail-freezes the attach and keeps the
			// barrier closed rather than reporting unproven visibility.
			for itemID, requireAuthorityIdentity := range refreshItems {
				err := a.exactKernelRefreshMode(ctx, itemID, requireAuthorityIdentity)
				if err != nil {
					a.failCoherence(err)
					return
				}
			}
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

func regularFileIdentityRequired(kind string) bool {
	// Pre-kind-persistence records restore with an empty Kind. Conservatively
	// treat them as regular files; exact sampling can prove a directory or
	// symlink safe without touching the regular-file page cache.
	return kind == "" || kind == "file"
}

// itemOwnedByGraftLocked reports whether this frontend identity belongs to a
// machine-local graft. Graft mutations and control operations own their exact
// kernel refreshes; authority FlushAll/RelatedInos batches must not refresh or
// fail-freeze on either live or detached graft Items.
func (a *attach) itemOwnedByGraftLocked(itemID uint64) bool {
	rec := a.items[itemID]
	return rec != nil && rec.graft
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
	return mountid.NewAttachRef()
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
