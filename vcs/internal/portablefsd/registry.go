package portablefsd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

type Config struct {
	// Trace is nil outside explicitly authorized diagnostic runs. Its owner
	// drains it after serving has stopped, independently of mount teardown.
	Trace            *lantrace.Recorder
	TraceFile        string
	TraceRun         string
	FrontendSocket   string
	ControlSocket    string
	StateDir         string
	MountLogDir      string
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
	if cfg.MountLogDir == "" && cfg.StateDir != "" {
		cfg.MountLogDir = defaultMountLogDir(cfg.StateDir)
	}
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

type ensureAttachRequest struct {
	AttachRef string `json:"attachRef,omitempty"`
	VolumeID  string `json:"volumeId"`

	AuthorityURL string `json:"authorityUrl"`
	AuthToken    string `json:"authToken"`
	// AuthSequence is the manager-assigned exact reauthorization sequence for
	// an already-live v3 session. Zero is the initial attach credential.
	AuthSequence uint64 `json:"authSequence,omitempty"`
	// AuthTokenExpiresAtMs is a caller-supplied deadline; zero states none.
	// The authority's installed signed authorization remains independent.
	AuthTokenExpiresAtMs int64  `json:"authTokenExpiresAtMs,omitempty"`
	DataPlaneTransport   string `json:"dataPlaneTransport"`
	DataPlaneServerName  string `json:"dataPlaneServerName,omitempty"`
	TLSCAPEM             string `json:"tlsCaPem"`
	TLSCASHA256          string `json:"tlsCaSha256,omitempty"`
	MountPath            string `json:"mountPath"`

	V3 *v3AttachRequest `json:"v3,omitempty"`
	// observePreKernelMountAbsence is a package-test injection for platforms
	// that cannot run Darwin getfsstat. It is never decoded from control input;
	// production always constructs the observer from mountPath + attachRef.
	observePreKernelMountAbsence authorityrpc.PreKernelMountAbsenceObserver
}

type attachStatus struct {
	MetadataCache *v3CacheMetrics `json:"metadataCache,omitempty"`
	AttachRef     string          `json:"attachRef"`
	VolumeID      string          `json:"volumeId"`

	MountPath string `json:"mountPath"`
	State     string `json:"state"`
	LastError string `json:"lastError,omitempty"`
	// Credential names WHICH credential verdict is behind a degraded state,
	// because "degraded" plus a prose lastError is not something a program can
	// branch on. Empty means no credential fault at all.
	Credential                string `json:"credential,omitempty"`
	VolumeName                string `json:"volumeName,omitempty"`
	SessionTerminal           bool   `json:"sessionTerminal,omitempty"`
	MountEnrollmentID         string `json:"mountEnrollmentId,omitempty"`
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
	unmountMu     sync.Mutex
	unmounting    map[string]*unmountTransaction
	persistMu     sync.Mutex
	writeAttaches func(string, []persistedAttachEntry) error
	stateDir      string
	mountLogDir   string
	byRef         map[string]*attach
	byKey         map[string]*attach
	quiescing     bool
	loadErr       error
}

func newRegistry(stateDir string) *registry {
	return newRegistryWithMountLogDir(stateDir, stateDir)
}

func newRegistryWithMountLogDir(stateDir, mountLogDir string) *registry {
	r := &registry{
		writeAttaches: writePersistedAttaches,
		stateDir:      stateDir,
		mountLogDir:   mountLogDir,
		byRef:         map[string]*attach{},
		byKey:         map[string]*attach{},
	}
	loaded, loadErr := loadAttachRegistry(stateDir)
	if loadErr != nil {
		r.loadErr = loadErr
		return r
	}
	persisted := loaded.attaches
	seenStorage := map[string]string{}
	for _, e := range persisted {
		req := ensureAttachRequest{
			VolumeID: e.VolumeID,

			AuthorityURL:        e.AuthorityURL,
			DataPlaneTransport:  e.DataPlaneTransport,
			DataPlaneServerName: e.DataPlaneServerName,
			TLSCAPEM:            e.TLSCAPEM,
			TLSCASHA256:         e.TLSCASHA256,
			MountPath:           e.MountPath,
		}
		key := attachKey(req.VolumeID, req.MountPath)
		if r.byRef[e.Ref] != nil {
			r.loadErr = fmt.Errorf("duplicate persisted attach ref %q", e.Ref)
			return r
		}
		if r.byKey[key] != nil {
			r.loadErr = fmt.Errorf("duplicate persisted attach key volumeId=%q mountPath=%q", req.VolumeID, req.MountPath)
			return r
		}
		if prior := seenStorage[req.VolumeID]; prior != "" {
			// One (volume, branch) = one mount owner: reviving two attaches of
			// the same volume would leave two records naming one kernel mount.
			r.loadErr = fmt.Errorf("persisted attach at %q conflicts with volume %s owner at %q", req.MountPath, req.VolumeID, prior)
			return r
		}
		seenStorage[req.VolumeID] = req.MountPath
		a, err := newRevivedAttach(
			e.Ref, key, req, stateDir, e.IdentityEpoch,
		)
		if err != nil {
			r.loadErr = fmt.Errorf("revive persisted attach %s: %w", e.Ref, err)
			return r
		}
		a.mountLogDir = r.mountLogDir
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
		r.byRef[e.Ref] = a
		r.byKey[key] = a
	}
	return r
}

func (r *registry) ensure(ctx context.Context, req ensureAttachRequest) (*attach, bool, error) {
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	if req.VolumeID == "" || req.AuthorityURL == "" || req.MountPath == "" ||
		req.V3 == nil {
		return nil, false, fmt.Errorf("volumeId, authorityUrl, mountPath, and v3 are required")
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
	key := attachKey(req.VolumeID, req.MountPath)
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
		if !a.v3Config.matches(v3Config) {
			r.mu.Unlock()
			return nil, false, fmt.Errorf("attach %s is already bound to a different attach mode or v3 contract; detach it before changing the declaration", a.ref)
		}
		r.mu.Unlock()
		renewedCertificate := ""
		if req.V3 != nil {
			renewedCertificate = req.V3.ClientCertPEM
		}
		if err := a.activate(ctx, req.AuthToken, req.AuthTokenExpiresAtMs, req.AuthSequence, renewedCertificate); err != nil {
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
			other.volumeID != req.VolumeID {
			continue
		}
		r.mu.Unlock()
		return nil, false, fmt.Errorf(
			"volume %s@%s already has durable attach %s at %s; detach that exact attach before mounting it elsewhere",
			req.VolumeID, "", other.ref, other.mountPath,
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
	a.mountLogDir = r.mountLogDir
	a.v3Config = v3Config
	a.persist = r.persist
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
		detachErr := a.detach(true)
		return nil, false, errors.Join(err, detachErr)
	}
	return a, true, nil
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

func (r *registry) unmountFSKit(ctx context.Context, ref string, force bool) (bool, error) {
	return r.unmountFSKitWithContext(ctx, ref, force, hostFSKitKernelOps())
}

func (r *registry) unmountFSKitWith(
	ref string,
	force bool,
	ops fskitKernelOps,
) (bool, error) {
	return r.unmountFSKitWithContext(context.Background(), ref, force, ops)
}

var unmountTransactionBudget = 40 * time.Second

type unmountOutcome struct {
	found bool
	err   error
}

// unmountFSKitWithContext answers ONE unmount request within the transaction's
// ABSOLUTE remaining budget. There is exactly ONE transaction per attach ref;
// every later request — including a --force — joins it rather than queueing a
// second one behind it.
//
// Explicit force authorizes forced revocation at the next kernel attempt.
// The transaction goroutine remains the sole teardown owner.
func (r *registry) unmountFSKitWithContext(
	ctx context.Context,
	ref string,
	force bool,
	ops fskitKernelOps,
) (bool, error) {
	r.unmountMu.Lock()
	if r.unmounting == nil {
		r.unmounting = map[string]*unmountTransaction{}
	}
	tx := r.unmounting[ref]
	if tx == nil {
		tx = &unmountTransaction{
			done:     make(chan struct{}),
			force:    force,
			deadline: time.Now().Add(unmountTransactionBudget),
		}
		r.unmounting[ref] = tx
		go func() {
			found, err := r.runUnmountTransaction(ref, tx, ops)
			r.unmountMu.Lock()
			// Publish the outcome to existing joiners and atomically make this
			// transaction undiscoverable before waking them. If close(done)
			// happened first, a retry could join a completed failed transaction
			// in the tiny pre-delete window and receive stale evidence even after
			// the external mount state had changed. Existing joiners already own
			// tx, so deleting first loses nothing; close below is their happens-
			// before edge for outcome. A new retry starts the one next
			// transaction and observes current kernel state.
			tx.outcome = unmountOutcome{found: found, err: err}
			if r.unmounting[ref] == tx {
				delete(r.unmounting, ref)
			}
			r.unmountMu.Unlock()
			close(tx.done)
		}()
	} else if force && !tx.force {
		// ESCALATE the running normal transaction in place.
		tx.force = true
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
		return tx.outcome.found, tx.outcome.err
	case <-ctx.Done():
		// Only THIS waiter gave up. The transaction owns durable state and
		// keeps running; it is never abandoned by a departing joiner.
		select {
		case <-tx.done:
			return tx.outcome.found, tx.outcome.err
		default:
		}
		return true, r.unmountInProgressVerdict(ref, r.escalated(tx), ctx.Err())
	case <-timer.C:
		// The timer and completion can fire together; completion wins.
		select {
		case <-tx.done:
			return tx.outcome.found, tx.outcome.err
		default:
		}
		return true, r.unmountInProgressVerdict(ref, r.escalated(tx), nil)
	}
}

// unmountTransaction is one running detach, shared by every request that
// observes it. outcome is written exactly once, before done closes.
//
// force is read and upgraded under registry.unmountMu. No second teardown
// owner or cancellable drain runs alongside this transaction.
type unmountTransaction struct {
	done     chan struct{}
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
	detail := "the exact kernel detach or authority absence proof"
	// A forced request can only rejoin the existing transaction.
	if forced {
		return fmt.Errorf(
			"forced unmount is still running after %s, waiting on %s; the force is "+
				"already authorized and continues in the background — re-running "+
				"`portablefs umount --force` only rejoins THIS transaction and cannot "+
				"speed it up. Join it with `portablefs umount --force %s`; if it never "+
				"completes, stop the daemon (`portablefs daemon stop`) and force again%s",
			unmountTransactionBudget, detail, mountPathHint(a), waiterSuffix(waiterErr),
		)
	}
	return fmt.Errorf(
		"unmount is still running after %s, waiting on %s; it continues in the "+
			"background — re-run `portablefs umount` to join it, or "+
			"`portablefs umount --force` to revoke the kernel mount%s",
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
) (bool, error) {
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	r.mu.RLock()
	a := r.byRef[ref]
	r.mu.RUnlock()
	if a == nil {
		return false, nil
	}
	force := r.escalated(tx)
	detachErr := r.detachV3(a, force, ops)
	if detachErr != nil && !a.isDetached() {
		// A separate force request may join while the unforced kernel attempt is
		// running. Only that explicit request authorizes a second, forced attempt.
		if !force && r.escalated(tx) {
			detachErr = r.detachV3(a, true, ops)
		}
		if detachErr != nil && !a.isDetached() {
			return true, detachErr
		}
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
		return true, errors.Join(detachErr, err)
	}
	return true, detachErr
}

// closeAll is the cooperative daemon-termination path. Every attach must pass
// its normal authority durability barrier. A failed drain remains a visible
// shutdown failure; this path never escalates to force.
func (r *registry) closeAll(ctx context.Context) error {
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	var shutdownErrs []error
	for _, a := range r.list() {
		if err := a.detach(false); err != nil {
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
	ref      string
	key      string
	volumeID string

	authorityURL        string
	authorityAddr       string
	dataPlaneTransport  string
	dataPlaneServerName string
	tlsCAPEM            string
	tlsCASHA256         string
	mountPath           string
	volumeName          string

	mountLogDir   string
	identityEpoch uint64
	persist       func() error

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
	v3Config  *v3AttachConfig
	v3Data    *v3DataPlane
	v3Session v3AuthoritySession
	// renewalDone closes only after the automatic owner has emitted its final
	// event and closed the per-mount log. Exact detach waits for it before the
	// attach identity can be reused.
	renewalDone               chan struct{}
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
	detachBarrier       bool
	credentialPending   bool

	conns             map[interface{ Close() error }]struct{}
	frontendWitnesses map[*frontendConn]struct{}

	detached bool

	// Retained across a registry-persist failure so retrying the exact forced
	// delete retains the same recorded detach outcome.

}

// v3CoherenceBridge returns the strict authority-v3 local stream, if this
// attach owns one. The bridge's own lock protects its mutable protocol state;
// the attach lock protects only installation and removal of the pointer.
func (a *attach) v3CoherenceBridge() *v3CoherenceBridge {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.v3Coherence
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

	lifeCtx, lifeCancel := context.WithCancel(context.Background())
	return &attach{
		lifeCtx:    lifeCtx,
		lifeCancel: lifeCancel,
		ref:        ref,
		key:        key,
		volumeID:   req.VolumeID,

		authorityURL:        strings.TrimSpace(req.AuthorityURL),
		authorityAddr:       normalizeAuthority(req.AuthorityURL),
		dataPlaneTransport:  req.DataPlaneTransport,
		dataPlaneServerName: req.DataPlaneServerName,
		tlsCAPEM:            req.TLSCAPEM,
		tlsCASHA256:         req.TLSCASHA256,
		mountPath:           req.MountPath,
		volumeName:          name,

		mountLogDir:      stateDir,
		identityEpoch:    1,
		token:            req.AuthToken,
		tokenExpiresAtMs: req.AuthTokenExpiresAtMs,
		state:            pfslocal.AttachStateAttached,

		conns: map[interface{ Close() error }]struct{}{},
	}
}

func newRevivedAttach(
	ref, key string,
	req ensureAttachRequest,
	stateDir string,
	identityEpoch uint64,

) (*attach, error) {
	a := newAttach(ref, key, req, stateDir)

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
	identityEpoch := a.identityEpoch

	a.mu.RUnlock()
	return persistedAttachEntry{
		Ref:                 a.ref,
		VolumeID:            a.volumeID,
		MountPath:           a.mountPath,
		AuthorityURL:        a.authorityURL,
		DataPlaneTransport:  a.dataPlaneTransport,
		DataPlaneServerName: a.dataPlaneServerName,
		TLSCAPEM:            a.tlsCAPEM,
		TLSCASHA256:         a.tlsCASHA256,

		IdentityEpoch: identityEpoch,

		V3: a.v3Config.persisted(),
	}
}

func (a *attach) activate(ctx context.Context, tok string, expiresAtMs int64, sequence uint64, clientCertificatePEM string) error {
	_, err := a.activateMode(ctx, tok, expiresAtMs, sequence, clientCertificatePEM, false)
	return err
}

func (a *attach) activateIfPending(ctx context.Context, tok string, expiresAtMs int64, sequence uint64, clientCertificatePEM string) (bool, error) {
	return a.activateMode(ctx, tok, expiresAtMs, sequence, clientCertificatePEM, true)
}

func (a *attach) activateMode(
	ctx context.Context,
	tok string,
	expiresAtMs int64,
	sequence uint64,
	clientCertificatePEM string,
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
	if err := a.startV3(ctx); err != nil {
		a.setErr(err)
		return false, err
	}
	a.mu.Lock()
	a.credentialPending = false
	a.lastErr = ""
	a.state = a.currentStateLocked()

	a.mu.Unlock()
	return true, nil
}

func (a *attach) rotateLiveCredential(
	ctx context.Context,
	tok string,
	expiresAtMs int64,
	sequence uint64,
	clientCertificatePEM string,
	onlyIfPending bool,
) (bool, bool, error) {
	a.mu.RLock()
	unavailable := a.detached
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

// detach terminally fences the attach. Force does so before waiting for
// namespace locks, so an in-flight handler cannot withhold its own revocation.
func (a *attach) detach(force bool) error {
	if force {
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
	a.mu.RUnlock()
	if alreadyDetached {
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
		return nil
	}
	exitBarrier := a.enterDetachBarrier()
	a.fenceV3(errV3AttachDetached)
	exitBarrier()
	return a.finishDetachWithNSLocked(nil)
}

// forcedDetach fences the session before taking namespace locks.
func (a *attach) forcedDetach() error {
	a.mu.RLock()
	alreadyDetached := a.detached
	a.mu.RUnlock()
	if alreadyDetached {
		return nil
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
		a.mu.RUnlock()
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
		return nil
	}
	a.mu.RUnlock()
	return a.finishDetachWithNSLocked(nil)
}

// finishDetachWithNSLocked publishes the terminal attach state and releases
// the admission freeze. The caller owns frontendSerial and nsMu exclusively.
func (a *attach) finishDetachWithNSLocked(priorErr error) error {
	a.mu.Lock()
	if a.detached {
		a.mu.Unlock()
		a.nsMu.Unlock()
		a.frontendSerial.Unlock()
		return priorErr
	}
	a.detached = true
	a.retireFrontendWitnessesLocked()
	a.state = pfslocal.AttachStateDetaching

	lifeCancel := a.lifeCancel
	v3Data := a.v3Data
	v3Config := a.v3Config
	renewalDone := a.renewalDone
	a.mu.Unlock()
	a.nsMu.Unlock()
	a.frontendSerial.Unlock()
	// Detach is the attach's terminal state: retire the lifetime scope so
	// everything derived from it stops instead of looping against a closed
	// client forever.
	if lifeCancel != nil {
		lifeCancel()
	}
	renewalStopped := true
	if renewalDone != nil {
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-renewalDone:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			renewalStopped = false
			priorErr = errors.Join(priorErr, errors.New("automatic mount renewal did not stop within its cancellation bound"))
		}
	}
	enrollmentCloseReason := "mount detached"
	if v3Data != nil {
		if terminalErr := v3Data.terminalError(); terminalErr != nil && !errors.Is(terminalErr, errV3AttachDetached) {
			enrollmentCloseReason = "mount failed closed"
		}
	}
	if v3Data != nil {
		_ = v3Data.fail(errV3AttachDetached)
	}
	a.mu.Lock()
	for c := range a.conns {
		_ = c.Close()
		delete(a.conns, c)
	}
	a.mu.Unlock()
	// Remote enrollment closure is hygiene after every local kernel, session,
	// descriptor, and connection owner is already terminal. Manager reachability
	// therefore cannot block the local terminal transition or leave it dirty.
	if v3Config != nil && v3Config.enrollmentClient != nil && renewalStopped {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := v3Config.enrollmentClient.Close(closeCtx, enrollmentCloseReason)
		cancel()
		if closeErr != nil {
			log.Printf("portablefsd: detached mount enrollment %s could not be closed and will expire or be revoked remotely: %v", v3Config.enrollmentID, closeErr)
		}
	}
	return priorErr
}

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
	if a.v3Config != nil {
		enrollmentID = a.v3Config.enrollmentID
	}
	a.mu.RUnlock()
	credential := ""
	// A terminal v3 session is this attach's strongest verdict: every
	// operation answers ENOTCONN and only an exact unmount resolves it. The
	// verdict travels as its own boolean because the mount supervisor's
	// revocation watchdog branches on it — "degraded" plus a prose lastError
	// is not something a program can branch on (see Credential above).
	sessionTerminal := false
	var metadataCache *v3CacheMetrics
	if d := a.v3Backend(); d != nil {
		metadataCache = d.cacheMetrics()
		if err := d.terminalError(); err != nil && !errors.Is(err, errV3AttachDetached) {
			state = pfslocal.AttachStateDegraded
			sessionTerminal = true
			lastErr = "v3 authority session is TERMINAL: " + err.Error() +
				"; every operation on this mount fails closed (ENOTCONN) and only an exact unmount resolves it"
		}
	}
	return attachStatus{
		AttachRef: a.ref, VolumeID: a.volumeID, MountPath: a.mountPath,
		State: stateString(state), VolumeName: volumeName, LastError: lastErr,
		Credential: credential, SessionTerminal: sessionTerminal, MetadataCache: metadataCache,
		MountEnrollmentID:         enrollmentID,
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

		}
	} else if a.lastErr != "" && !a.coherenceFailFrozen {
		a.lastErr = ""
		a.state = a.currentStateLocked()

	}
	a.mu.Unlock()
}

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

// attachKey binds one registered volume to its exact kernel mount path.
func attachKey(volumeID, mountPath string) string { return volumeID + "\x00" + mountPath }

func normalizeAuthority(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "tcp://")
	return s
}

func stateString(st pfslocal.AttachStateState) string {
	switch st {
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

// lifecycleInventory includes terminal and persisted registrations. Absence of a
// serving session is not absence of its kernel mount or registration.
func (r *registry) lifecycleInventory() (daemonctl.LifecycleInventory, error) {
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.loadErr != nil {
		return daemonctl.LifecycleInventory{}, r.loadErr
	}
	out := daemonctl.LifecycleInventory{AttachmentCount: len(r.byRef)}
	return out, out.Validate()
}
func (r *registry) quiesceIfIdle() (bool, int, error) {
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()
	r.mu.RLock()
	if r.loadErr != nil {
		r.mu.RUnlock()
		return false, 0, r.loadErr
	}
	count := len(r.byRef)
	r.mu.RUnlock()
	if err := (daemonctl.LifecycleInventory{AttachmentCount: count}).Validate(); err != nil {
		return false, count, err
	}
	if count != 0 {
		return false, count, nil
	}
	// Admission stays open unless the empty registry is durably established.
	// mutationMu excludes attach/removal until both persistence and quiescence.
	if err := r.persist(); err != nil {
		return false, 0, err
	}
	r.mu.Lock()
	r.quiescing = true
	r.mu.Unlock()
	return true, 0, nil
}

var frontendOrigins atomic.Uint64

func (a *attach) newOrigin() uint64 { return allocateFrontendOrigin(&frontendOrigins) }
func allocateFrontendOrigin(counter *atomic.Uint64) uint64 {
	for {
		old := counter.Load()
		if old == ^uint64(0) {
			return 0
		}
		if counter.CompareAndSwap(old, old+1) {
			return old + 1
		}
	}
}
