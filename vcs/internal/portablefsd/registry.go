package portablefsd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
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
	// AuthSequence is the manager-assigned exact reauthorization sequence for
	// an already-live v3 session. Zero is the initial attach credential.
	AuthSequence uint64 `json:"authSequence,omitempty"`
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
	// V3 selects the daemon-owned authority-v3 attach mode (see v3attach.go).
	// When present the attach is branchless, served by the standalone v3 data
	// plane, and never touches the legacy clientcore path.
	V3 *v3AttachRequest `json:"v3,omitempty"`
	// observePreKernelMountAbsence is a package-test injection for platforms
	// that cannot run Darwin getfsstat. It is never decoded from control input;
	// production always constructs the observer from mountPath + attachRef.
	observePreKernelMountAbsence authorityrpc.PreKernelMountAbsenceObserver
}

type attachStatus struct {
	AttachRef string `json:"attachRef"`
	VolumeID  string `json:"volumeId"`
	Branch    string `json:"branch"`
	MountPath string `json:"mountPath"`
	State     string `json:"state"`
	LastError string `json:"lastError,omitempty"`
	// Credential names WHICH credential verdict is behind a degraded state,
	// because "degraded" plus a prose lastError is not something a program can
	// branch on. Empty means no credential fault at all.
	Credential string `json:"credential,omitempty"`
	VolumeName string `json:"volumeName,omitempty"`
	// SessionTerminal reports that this attach's v3 authority session ended
	// permanently. The mount supervisor's revocation watchdog branches on it:
	// a terminal session can never repair the kernel's caches again, so the
	// kernel mount must be made unservable within the repair budget.
	SessionTerminal           bool   `json:"sessionTerminal,omitempty"`
	MountEnrollmentID         string `json:"mountEnrollmentId,omitempty"`
	EnrollmentExpiresAtMs     int64  `json:"enrollmentExpiresAtMs,omitempty"`
	AuthorizationDeadlineAtMs int64  `json:"authorizationDeadlineAtMs,omitempty"`
	LastReauthorizationAtMs   int64  `json:"lastReauthorizationAtMs,omitempty"`
	NextReauthorizationAtMs   int64  `json:"nextReauthorizationAtMs,omitempty"`
	ReauthorizationFailures   uint64 `json:"reauthorizationFailures,omitempty"`
	ReauthorizationError      string `json:"reauthorizationError,omitempty"`
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
}

func newRegistry(stateDir string) *registry {
	return newRegistryWithStateDir(stateDir)
}

// newFSKitQualificationRegistry is retained as a package-test spelling for the
// existing protocol-5 fixture inventory. Production and tests now exercise the
// same macOS 26 cache-policy admission path.
func newFSKitQualificationRegistry(stateDir string) *registry {
	return newRegistryWithStateDir(stateDir)
}

func newRuntimeRegistry(stateDir string) *registry {
	return newRegistryWithStateDir(stateDir)
}

func newRegistryWithStateDir(stateDir string) *registry {
	r := &registry{
		stateDir:    stateDir,
		byRef:       map[string]*attach{},
		byKey:       map[string]*attach{},
		persistReq:  make(chan struct{}, 1),
		persistStop: make(chan struct{}),
		persistDone: make(chan struct{}),
	}
	// Production constructs registries only after owning both daemon
	// singleton locks. Start the background worker only after the complete
	// strict load succeeds; an invalid inventory therefore leaves no orphan
	// persister behind.
	defer func() {
		if r.loadErr != nil {
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
			// One (volume, branch) = one mount owner: reviving two attaches of
			// the same volume would leave two records naming one kernel mount.
			r.loadErr = fmt.Errorf("persisted attach at %q conflicts with %s@%s owner at %q", req.MountPath, req.VolumeID, req.Branch, prior)
			return r
		}
		seenStorage[storageKey(req.VolumeID, req.Branch)] = req.MountPath
		a, err := newRevivedAttach(
			e.Ref, key, req, stateDir, e.IdentityEpoch,
			e.DetachPrepared, e.DetachForce, e.DetachJobID,
		)
		if err != nil {
			r.loadErr = fmt.Errorf("revive persisted attach %s: %w", e.Ref, err)
			return r
		}
		if e.V3 == nil {
			// A RECORD FROM THE RETIRED CLIENT-JOURNAL ARCHITECTURE.
			//
			// It names a kernel mount this daemon can still reconcile, but no
			// engine in this build can serve it: the write-back/journal data
			// plane it was written by is gone. It revives ONLY so the exact
			// unmount can retire it, and every activation of it is refused
			// with the one action that resolves it.
			a.lastErr = legacyAttachRecordDetail
			a.credentialPending = false
			r.byRef[e.Ref] = a
			r.byKey[key] = a
			a.persist = r.persist
			a.schedulePersist = r.schedulePersist
			continue
		}
		// A revived v3 record is permanently inactivatable (its strict
		// session died with the previous process); it revives only so the
		// exact unmount can still reconcile the kernel mount it names.
		cfg, cfgErr := revivedV3AttachConfig(e.V3)
		if cfgErr != nil {
			r.loadErr = fmt.Errorf("revive persisted v3 attach %s: %w", e.Ref, cfgErr)
			return r
		}
		a.v3Config = cfg
		a.lastErr = "v3 strict session died with the previous daemon process; only an exact unmount resolves this attach"
		a.persist = r.persist
		a.schedulePersist = r.schedulePersist
		r.byRef[e.Ref] = a
		r.byKey[key] = a
	}
	return r
}

// legacyAttachRecordDetail is the ONE next action for a persisted attach
// written by the retired client-journal architecture. Nothing in this build
// can serve it: there is no write-back engine, no session WAL and no journal
// data plane to revive it into, and a v3 session cannot inherit what that
// mount's kernel cached. The record survives revival only so the exact
// unmount can retire it.
const legacyAttachRecordDetail = "this attach record predates the XFS authority (v3) data plane and cannot be served by this daemon: " +
	"unmount it (portablefs umount <mountPath>) and mount again"

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
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	if req.VolumeID == "" || req.AuthorityURL == "" || req.MountPath == "" ||
		(req.Branch == "" && req.V3 == nil) {
		return nil, false, fmt.Errorf("volumeId, branch, authorityUrl, and mountPath are required")
	}
	v3Config, err := v3ConfigForEnsure(req)
	if err != nil {
		return nil, false, err
	}
	if req.AttachRef != "" && !mountid.ValidAttachRef(req.AttachRef) {
		return nil, false, fmt.Errorf("attachRef has invalid stable identity format")
	}
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
		// A mount identity never changes attach mode or strict contract in
		// place: the v3 barrier declaration was admitted at the authority
		// exactly once, so a different declaration is a different mount.
		if (a.v3Config != nil) != (v3Config != nil) ||
			(v3Config != nil && !a.v3Config.matches(v3Config)) {
			r.mu.Unlock()
			return nil, false, fmt.Errorf("attach %s is already bound to a different attach mode or v3 contract; detach it before changing the declaration", a.ref)
		}
		r.mu.Unlock()
		renewedCertificate := ""
		if req.V3 != nil {
			renewedCertificate = req.V3.ClientCertPEM
		}
		if err := a.activateWithOptions(ctx, req.AuthToken, req.AuthTokenExpiresAtMs, req.AuthSequence, renewedCertificate, &req.Options); err != nil {
			return a, false, err
		}
		if err := r.persist(); err != nil {
			return a, false, err
		}
		return a, false, nil
	}
	// Storage identity is (volume, branch): any second attach would name the
	// same mount owner. Persisted dormant entries are durable ownership
	// records, not stale hints; only an explicit exact detach may remove one.
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
	a.v3Config = v3Config
	a.persist = r.persist
	a.schedulePersist = r.schedulePersist
	r.byRef[ref] = a
	r.byKey[key] = a
	r.mu.Unlock()
	if req.AuthSequence != 0 {
		r.mu.Lock()
		delete(r.byRef, ref)
		delete(r.byKey, key)
		r.mu.Unlock()
		return nil, false, errors.New("an initial v3 attach credential must use authSequence zero")
	}
	if err := a.activate(ctx, req.AuthToken, req.AuthTokenExpiresAtMs, 0, ""); err != nil {
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
func (r *registry) activate(ctx context.Context, ref, token string, expiresAtMs int64, sequence uint64, clientCertificatePEM string, onlyIfPending bool) (bool, bool, error) {
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
		if done, handled, err := a.rotateLiveCredential(ctx, token, expiresAtMs, sequence, clientCertificatePEM, onlyIfPending); handled {
			return true, done, err
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
		activated, err := a.activateIfPending(ctx, token, expiresAtMs, sequence, clientCertificatePEM)
		return true, activated, err
	}
	return true, true, a.activate(ctx, token, expiresAtMs, sequence, clientCertificatePEM)
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
			r.unmountMu.Lock()
			// Publish the outcome to existing joiners and atomically make this
			// transaction undiscoverable before waking them. If close(done)
			// happened first, a retry could join a completed failed transaction
			// in the tiny pre-delete window and receive stale evidence even after
			// the external mount state had changed. Existing joiners already own
			// tx, so deleting first loses nothing; close below is their happens-
			// before edge for outcome. A new retry starts the one next
			// transaction and observes current kernel state.
			tx.outcome = unmountOutcome{found: found, jobID: jobID, err: err}
			if r.unmounting[ref] == tx {
				delete(r.unmounting, ref)
			}
			r.unmountMu.Unlock()
			close(tx.done)
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
		return true, "", r.unmountInProgressVerdict(ref, r.escalated(tx), ctx.Err())
	case <-timer.C:
		// The timer and completion can fire together; completion wins.
		select {
		case <-tx.done:
			return tx.outcome.found, tx.outcome.jobID, tx.outcome.err
		default:
		}
		return true, "", r.unmountInProgressVerdict(ref, r.escalated(tx), nil)
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
func (r *registry) unmountInProgressVerdict(ref string, forced bool, waiterErr error) error {
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
	detail := "the authority visibility barrier"
	// NEVER PRESCRIBE THE COMMAND THE CALLER IS ALREADY RUNNING.
	//
	// This message used to end with "or `portablefs umount --force` to park the
	// unshipped tail" unconditionally — including when it was answering a
	// --force. Live, that produced seven identical --force invocations over four
	// minutes, each told to run --force. A progress report that prescribes the
	// caller's own command is not advice; it is a loop with a delay in it.
	//
	// A force ALREADY escalated has exactly one honest next step that is
	// different from re-running it: the escalation is durable and running, so
	// joining it is what "wait" means, and if it never completes the exit is the
	// abandoned-store path (kill the daemon, then --force again, and resolve any
	// terminal recovery job it names). That is stated instead of a self-loop.
	if forced {
		return fmt.Errorf(
			"forced unmount is still running after %s, waiting on %s; the force is "+
				"already durable and continues in the background — re-running "+
				"`portablefs umount --force` only rejoins THIS transaction and cannot "+
				"speed it up. Join it with `portablefs umount --force %s`; if it never "+
				"completes, stop the daemon (`portablefs daemon stop`) and force again%s",
			unmountTransactionBudget, detail, mountPathHint(a), waiterSuffix(waiterErr),
		)
	}
	return fmt.Errorf(
		"unmount is still running after %s, waiting on %s; it continues in the "+
			"background — re-run `portablefs umount` to join it, or "+
			"`portablefs umount --force` to park the unshipped tail as a durable "+
			"recovery job%s",
		unmountTransactionBudget, detail, waiterSuffix(waiterErr),
	)
}

// mountPathHint names the attach's mount path for a message, falling back to
// its ref when the path is not recorded.
func mountPathHint(a *attach) string {
	if a != nil && a.mountPath != "" {
		return a.mountPath
	}
	if a != nil {
		return a.ref
	}
	return "<mountPath>"
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
	case a.isV3():
		// The evidence-bearing v3 detach: exact kernel detach, getfsstat
		// absence observation, proof delivery, then local release. It shares
		// none of the prepared/force/journal machinery below because a v3
		// attach has no daemon WAL store to drain. Its normal unforced kernel
		// pass is still the mandatory FSKit synchronize/authority boundary;
		// detachV3 alone owns that v3-specific sequence.
		if err := r.detachV3(a, forceAuthorized || force, ops); err != nil {
			return true, "", err
		}
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
		sessionActive := a.v3Data != nil && !a.credentialPending
		a.mu.RUnlock()
		if !sessionActive {
			return true, "", fmt.Errorf("normal FSKit detach requires a live authority session to prove the final visibility barrier")
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
// irreversible session fence, then performs the exact kernel detach. A v3
// attach carries no client-side durability debt — every acknowledged write is
// already applied by the authority — so there is no tail to park and no
// recovery handle to hand back. The caller owns registry.mutationMu.
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
		a.fenceV3(errV3AttachDetached)
		a.mu.Lock()
		a.detachPrepared = true
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
		// Force authorization remains durable. Operations are quarantined
		// until an exact retry succeeds.
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
	// mountRootFD is this attach's kernel mount root, bound while the mount
	// was proven healthy (see bindMountRoot). mountRootBound is separate so a
	// valid descriptor 0 is representable. Every
	// path-based access to an FSKit mount is served by its own extension, so
	// this descriptor must never be re-derived during a coherence barrier.
	mountRootFD    int
	mountRootBound bool

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
	// schedulePersist requests a debounced background persist.
	schedulePersist func()

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
	// so the mount can bound the UNPROVEN state.
	tokenExpiresAtMs int64

	// lifeCtx scopes everything that must live for the whole ATTACH, not for
	// the control request that happened to start it.
	lifeCtx    context.Context
	lifeCancel context.CancelFunc

	startMu sync.Mutex

	mu   sync.RWMutex
	nsMu sync.RWMutex
	// frontendSerial mirrors the concrete namespace lock class at the protocol
	// boundary: a request acquires it before entering the publication gate.
	frontendSerial sync.RWMutex
	// v3Coherence is the strict authority-v3 local visibility stream.
	v3Coherence *v3CoherenceBridge
	// v3Config marks an authority-v3 attach and carries its immutable declared
	// contract; assigned before registration, never mutated (see v3attach.go).
	// v3Data/v3Session are that attach's live data plane and authority session,
	// installed by startV3 and guarded by mu.
	v3Config                  *v3AttachConfig
	v3Data                    *v3DataPlane
	v3Session                 v3AuthoritySession
	authorizationDeadlineAtMs int64
	lastReauthorizationAtMs   int64
	nextReauthorizationAtMs   int64
	reauthorizationFailures   uint64
	reauthorizationError      string
	state                     pfslocal.AttachStateState
	lastErr                   string
	// Terminal for this attach lifetime: once a correctness-bound kernel
	// refresh fails, authority visibility was not proven. Operations fail
	// closed until an explicit unmount/restart.
	coherenceFailFrozen bool
	// coherenceRepairs counts kernel coherence repairs currently running for
	// this attach. Nonzero reports the attach as degraded-with-a-reason;
	// reaching zero clears that report. Guarded by mu.
	coherenceRepairs int
	// coherenceRepairGaveUp records that some repair exhausted its budget. It
	// makes that reason STICKY. Guarded by mu.
	coherenceRepairGaveUp bool
	// detachBarrier is set while this attach's FINAL barrier is running. It is
	// the earliest point at which the kernel cache this mount owns is provably
	// going away, and it is strictly earlier than detachPrepared/detached.
	// Guarded by mu.
	detachBarrier     bool
	credentialPending bool
	nextOrigin        uint64
	subscribers       map[*eventSubscriber]struct{}
	conns             map[interface{ Close() error }]struct{}
	// nativeFrontendWitnesses contains only live `portablefskit` connections
	// that completed Resolve for this exact native-policy attach. It is the
	// macOS 27 readiness primitive; legacy macOS 26 policies instead retain a
	// verified mount-root descriptor. Guarded by mu.
	nativeFrontendWitnesses map[*frontendConn]struct{}
	eventReady              chan struct{}
	eventOnce               sync.Once
	detached                bool
	detachPrepared          bool
	detachForce             bool
	// detachFailFrozen is process-local. The durable prepared marker and this
	// explicit flag reject every admission, while nsMu remains releasable so
	// daemon shutdown/restart can perform the required recovery.
	detachFailFrozen bool
	// Retained across a registry-persist failure so retrying the exact forced
	// delete returns the same durable recovery handle.
	detachJobID string
}

// v3CoherenceBridge returns the strict authority-v3 local stream, if this
// attach owns one. The bridge's own lock protects its mutable protocol state;
// the attach lock protects only installation and removal of the pointer.
func (a *attach) v3CoherenceBridge() *v3CoherenceBridge {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.v3Coherence
}

type eventSubscriber struct {
	origin uint64
	ch     chan pfslocal.Event
}

func (a *attach) authorizationSessionID() string {
	a.mu.RLock()
	plane := a.v3Data
	a.mu.RUnlock()
	if plane == nil {
		return ""
	}
	return plane.authorizationSessionID()
}

func newAttach(ref, key string, req ensureAttachRequest, stateDir string) *attach {
	name := req.VolumeID
	if req.Branch != "" {
		name += "@" + req.Branch
	}
	storageID := stableStorageID(storageKey(req.VolumeID, req.Branch))
	lifeCtx, lifeCancel := context.WithCancel(context.Background())
	return &attach{
		lifeCtx:             lifeCtx,
		lifeCancel:          lifeCancel,
		ref:                 ref,
		key:                 key,
		volumeID:            req.VolumeID,
		branch:              req.Branch,
		authorityURL:        strings.TrimSpace(req.AuthorityURL),
		authorityAddr:       normalizeAuthority(req.AuthorityURL),
		dataPlaneTransport:  req.DataPlaneTransport,
		dataPlaneServerName: req.DataPlaneServerName,
		tlsCAPEM:            req.TLSCAPEM,
		tlsCASHA256:         req.TLSCASHA256,
		mountPath:           req.MountPath,
		volumeName:          name,
		storageID:           storageID,
		options:             req.Options,
		stateDir:            stateDir,
		identityEpoch:       1,
		token:               req.AuthToken,
		tokenExpiresAtMs:    req.AuthTokenExpiresAtMs,
		state:               pfslocal.AttachStateAttached,
		subscribers:         map[*eventSubscriber]struct{}{},
		conns:               map[interface{ Close() error }]struct{}{},
		eventReady:          make(chan struct{}),
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
) (*attach, error) {
	a := newAttach(ref, key, req, stateDir)
	a.detachPrepared = detachPrepared
	a.detachForce = detachForce
	a.detachJobID = detachJobID
	if identityEpoch != 0 {
		a.identityEpoch = identityEpoch
	}
	a.token = ""
	a.tokenExpiresAtMs = 0
	a.credentialPending = true
	a.state = pfslocal.AttachStateDegraded
	a.lastErr = "credentials required after daemon restart"
	return a, nil
}

func (a *attach) persistedEntry() persistedAttachEntry {
	a.mu.RLock()
	options := a.options
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
		V3:                  a.v3Config.persisted(),
	}
}

func (a *attach) activate(ctx context.Context, tok string, expiresAtMs int64, sequence uint64, clientCertificatePEM string) error {
	return a.activateWithOptions(ctx, tok, expiresAtMs, sequence, clientCertificatePEM, nil)
}

func (a *attach) activateIfPending(ctx context.Context, tok string, expiresAtMs int64, sequence uint64, clientCertificatePEM string) (bool, error) {
	return a.activateWithOptionsMode(ctx, tok, expiresAtMs, sequence, clientCertificatePEM, nil, true)
}

func (a *attach) activateWithOptions(ctx context.Context, tok string, expiresAtMs int64, sequence uint64, clientCertificatePEM string, options *AttachOptions) error {
	_, err := a.activateWithOptionsMode(ctx, tok, expiresAtMs, sequence, clientCertificatePEM, options, false)
	return err
}

func (a *attach) activateWithOptionsMode(
	ctx context.Context,
	tok string,
	expiresAtMs int64,
	sequence uint64,
	clientCertificatePEM string,
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
	if done, handled, err := a.rotateLiveCredential(ctx, tok, expiresAtMs, sequence, clientCertificatePEM, onlyIfPending); handled {
		return done, err
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
	active := a.v3Data != nil && !a.credentialPending
	v3Terminal := error(nil)
	if a.v3Data != nil {
		v3Terminal = a.v3Data.terminalError()
	}
	a.mu.RUnlock()
	if v3Terminal != nil {
		// A dead strict session is never reactivated: a replacement session
		// cannot prove what the kernel cached before it (see v3attach.go).
		return false, fmt.Errorf("v3 attach is terminal: %w; unmount it before mounting again", v3Terminal)
	}
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
	if !a.isV3() {
		return false, errors.New(legacyAttachRecordDetail)
	}
	if err := a.startV3(ctx); err != nil {
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
	ctx context.Context,
	tok string,
	expiresAtMs int64,
	sequence uint64,
	clientCertificatePEM string,
	onlyIfPending bool,
) (bool, bool, error) {
	a.mu.RLock()
	unavailable := a.detached || a.detachPrepared || a.detachForce
	credentialPending := a.credentialPending
	plane := a.v3Data
	a.mu.RUnlock()
	// A TERMINAL SESSION IS NOT A LIVE ATTACH. The fast path exists for the
	// case the locked path reduces to one setCredential; a dead strict session
	// is not that case — its verdict (refuse, and name the unmount) belongs to
	// the locked path and must not be short-circuited into a silent success.
	active := plane != nil && !credentialPending && plane.terminalError() == nil
	if unavailable || !active {
		return false, false, nil
	}
	if onlyIfPending {
		// An active attach has no pending credential by definition, so a
		// pending-only installation has nothing to do. Same answer the locked
		// path gives, reached without the lock.
		return false, true, nil
	}
	installedExpiresAtMs := expiresAtMs
	if a.v3Config != nil {
		if a.v3Config.enrollmentClient != nil {
			return false, true, errors.New("this mount has one automatic reauthorization owner; manual credential rotation is disabled")
		}
		if sequence == 0 {
			return false, true, errors.New("a live v3 credential rotation requires a nonzero authSequence")
		}
		replacement, err := a.v3Config.replacementCertificate(clientCertificatePEM, time.Now())
		if err != nil {
			return false, true, err
		}
		deadline, err := plane.reauthorize(ctx, []byte(tok), sequence)
		if err != nil {
			return false, true, fmt.Errorf("reauthorize live v3 session: %w", err)
		}
		a.v3Config.installReplacementCertificate(replacement)
		installedExpiresAtMs = deadline.UnixMilli()
		a.mu.Lock()
		a.authorizationDeadlineAtMs = installedExpiresAtMs
		a.lastReauthorizationAtMs = time.Now().UnixMilli()
		a.nextReauthorizationAtMs = 0
		a.reauthorizationFailures = 0
		a.reauthorizationError = ""
		a.mu.Unlock()
	}
	// The authority's reply is the installed truth for a v3 session. Never let
	// a copied request timestamp extend the daemon's watchdog or reported
	// authorization state beyond the deadline the authority actually accepted.
	a.setCredential(tok, installedExpiresAtMs)
	return true, true, nil
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

func (a *attach) setCredential(tok string, expiresAtMs int64) {
	a.credMu.Lock()
	a.token = tok
	a.tokenExpiresAtMs = expiresAtMs
	a.credMu.Unlock()
}

func (a *attach) authorizationDeadline() int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.authorizationDeadlineAtMs
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
	exitBarrier := a.enterDetachBarrier()
	a.fenceV3(errV3AttachDetached)
	exitBarrier()
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
	prepared := a.detachPrepared || a.detachForce
	a.mu.RUnlock()
	if alreadyDetached {
		return existingJobID, nil
	}
	if prepared {
		return existingJobID, errPreparedDetachPending
	}
	// Fence the strict session first: every operation still inside the
	// namespace locks then reaches a definite outcome, so the acquisition
	// below waits on work that is converging rather than on an authority that
	// stopped answering.
	exitBarrier := a.enterDetachBarrier()
	a.fenceV3(errV3AttachDetached)
	exitBarrier()
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
	return a.finishDetachWithNSLocked("", err)
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
	a.mu.RUnlock()
	if alreadyDetached {
		return existingJobID, nil
	}
	exitBarrier := a.enterDetachBarrier()
	a.fenceV3(errV3AttachDetached)
	exitBarrier()
	if err := finalizer(); err != nil {
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
	a.retireNativeFrontendWitnessesLocked()
	if jobID != "" {
		a.detachJobID = jobID
	}
	a.state = pfslocal.AttachStateDetaching
	a.publishLocked(pfslocal.Event{Kind: &pfslocal.AttachState{State: pfslocal.AttachStateDetaching, Detail: "detaching"}})
	lifeCancel := a.lifeCancel
	v3Data := a.v3Data
	v3Config := a.v3Config
	a.mu.Unlock()
	a.nsMu.Unlock()
	a.frontendSerial.Unlock()
	// Detach is the attach's terminal state: retire the lifetime scope so
	// everything derived from it stops instead of looping against a closed
	// client forever.
	if lifeCancel != nil {
		lifeCancel()
	}
	enrollmentCloseReason := "mount detached"
	if v3Data != nil {
		if terminalErr := v3Data.terminalError(); terminalErr != nil && !errors.Is(terminalErr, errV3AttachDetached) {
			enrollmentCloseReason = "mount failed closed"
		}
	}
	// The macOS 26 repair root is attach-scoped. Terminal FSKit teardown has
	// already removed (or deliberately abandoned) this incarnation's kernel
	// mount, so retire the owner now. Each in-flight repair holds its own dup,
	// preventing both descriptor reuse races and one leaked vnode per remount.
	a.releaseMountRoot()
	// A v3 attach's strict session must not outlive the attach. The clean
	// unmount already delivered its absence proof and terminated the plane;
	// every other detach path ends it here, closing the authority client so
	// the session dies (and the authority fences it) rather than lingering.
	if v3Data != nil {
		_ = v3Data.fail(errV3AttachDetached)
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
	a.mu.Unlock()
	// Remote enrollment closure is hygiene after every local kernel, session,
	// descriptor, and connection owner is already terminal. Manager reachability
	// therefore cannot block the local terminal transition or leave it dirty.
	if v3Config != nil && v3Config.enrollmentClient != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := v3Config.enrollmentClient.Close(closeCtx, enrollmentCloseReason)
		cancel()
		if closeErr != nil {
			log.Printf("portablefsd: detached mount enrollment %s could not be closed and will expire or be revoked remotely: %v", v3Config.enrollmentID, closeErr)
		}
	}
	return jobID, priorErr
}

// The DISJOINT credential-plane faults an attach can report. They are distinct
// words because they are distinct facts with distinct repairs, and every time
// two of them were spelled the same the operator was sent to fix the wrong
// thing:
//
//   - rejected: a proven-dead credential. The authority answered "no" ->
//     log in again and remount.
//   - pending-verification: an UNTESTED credential. Nobody answered at all ->
//     look at the router, not at the login.
//   - router-refused: the router ANSWERED, and its answer was not about the
//     credential — the lease is at its tunnel limit, or it ended/rotated
//     mid-handshake, or no backend authority was reachable. Retryable, and
//     re-authenticating changes none of them. This one existed as a fact long
//     before it had a word: the router spelled it ack 1, the same byte it used
//     for a dead credential, so a mount that lost a race for one of the
//     lease's 64 tunnel slots latched "credentials revoked or expired" over a
//     lease with four and a half minutes left.
const (
	credentialStateRejected            = "rejected"
	credentialStatePendingVerification = "pending-verification"
	credentialStateRouterRefused       = "router-refused"
)

func (a *attach) status() attachStatus {
	a.mu.RLock()
	state := a.currentStateLocked()
	lastErr := a.lastErr
	volumeName := a.volumeName
	authorizationDeadlineAtMs := a.authorizationDeadlineAtMs
	lastReauthorizationAtMs := a.lastReauthorizationAtMs
	nextReauthorizationAtMs := a.nextReauthorizationAtMs
	reauthorizationFailures := a.reauthorizationFailures
	reauthorizationError := a.reauthorizationError
	enrollmentID := ""
	enrollmentExpiresAtMs := int64(0)
	if a.v3Config != nil {
		enrollmentID = a.v3Config.enrollmentID
		enrollmentExpiresAtMs = a.v3Config.enrollmentExpires.UnixMilli()
	}
	a.mu.RUnlock()
	credential := ""
	// A terminal v3 session is this attach's strongest verdict: every
	// operation answers ENOTCONN and only an exact unmount resolves it. The
	// verdict travels as its own boolean because the mount supervisor's
	// revocation watchdog branches on it — "degraded" plus a prose lastError
	// is not something a program can branch on (see Credential above).
	sessionTerminal := false
	if d := a.v3Backend(); d != nil {
		if err := d.terminalError(); err != nil && !errors.Is(err, errV3AttachDetached) {
			state = pfslocal.AttachStateDegraded
			sessionTerminal = true
			lastErr = "v3 authority session is TERMINAL: " + err.Error() +
				"; every operation on this mount fails closed (ENOTCONN) and only an exact unmount resolves it"
		}
	}
	return attachStatus{
		AttachRef: a.ref, VolumeID: a.volumeID, Branch: a.branch, MountPath: a.mountPath,
		State: stateString(state), VolumeName: volumeName, LastError: lastErr,
		Credential: credential, SessionTerminal: sessionTerminal,
		MountEnrollmentID: enrollmentID, EnrollmentExpiresAtMs: enrollmentExpiresAtMs,
		AuthorizationDeadlineAtMs: authorizationDeadlineAtMs, LastReauthorizationAtMs: lastReauthorizationAtMs,
		NextReauthorizationAtMs: nextReauthorizationAtMs, ReauthorizationFailures: reauthorizationFailures,
		ReauthorizationError: reauthorizationError,
	}
}

func (a *attach) currentStateLocked() pfslocal.AttachStateState {
	if a.detached {
		return pfslocal.AttachStateDetaching
	}
	if a.credentialPending {
		return pfslocal.AttachStateDegraded
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

func (a *attach) persistState() error {
	if a.persist == nil {
		return nil
	}
	return a.persist()
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

func (a *attach) lockExternalNamespaceWrite() func() {
	a.frontendSerial.Lock()
	a.nsMu.Lock()
	return func() {
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
	}
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

func (a *attach) isDetached() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.detached
}

// hasLiveVolume reports whether this attach activated an authority session in
// this daemon lifetime — the claim signal the one-live-attach-per-volume guard
// keys on (a dormant revived attach holds none).
func (a *attach) hasLiveVolume() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.v3Data != nil
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

// LocalBackingRoot names portablefsd's machine-local graft tree for one
// (volume, branch). It is exported for operator tooling that must inventory
// daemon-owned backing without duplicating the storage-key algorithm.
func LocalBackingRoot(stateDir, volumeID, branch string) string {
	return filepath.Join(stateDir, "local", stableStorageID(storageKey(volumeID, branch)))
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeHTTPError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
