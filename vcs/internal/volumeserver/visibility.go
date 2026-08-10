package volumeserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrVisibilityLost fences one strict cache holder that disappeared without
	// a durable, post-unmount detach. It is deliberately scoped to that one
	// participant: freezing the volume would not un-stale the departed mount's
	// cache, it would only stop the machines that are still healthy.
	ErrVisibilityLost = errors.New("volumeserver: strict visibility participant was lost")
	// ErrVisibilityDeadline fences one participant that did not finish a phase
	// within the repair budget it committed to at attach.
	ErrVisibilityDeadline = errors.New("volumeserver: strict visibility participant missed its repair budget")
	// ErrVisibilityBlocked is the terminal form of a blocked report. Ordinary
	// parent-exclusive namespace repair is cycle-broken in place; a routing
	// revision cannot be adopted by releasing one directory lock, so that report
	// still fences only the participant that cannot adopt it.
	ErrVisibilityBlocked = errors.New("volumeserver: strict visibility participant cannot adopt the pending routing revision")
	// ErrVisibilityInterrupted is a definite pre-apply refusal for a frontend
	// mutation that would prevent this participant from discharging a pending
	// repair. That is volume-wide for the frozen callback-serialized profile;
	// the pipelined profile exempts only a distinct, exactly identified source
	// callback. Parent-exclusive repair is scoped to an overlapping held parent.
	// The caller may retry after the phase; no filesystem mutation was executed.
	ErrVisibilityInterrupted = errors.New("volumeserver: visible mutation interrupted by this participant's pending cache repair")
	// ErrVisibilitySequence means a participant violated the exact two-phase
	// cursor. Guessing which phase it repaired would weaken the barrier.
	ErrVisibilitySequence = errors.New("volumeserver: visibility acknowledgment cursor mismatch")
	ErrVisibilityProfile  = errors.New("volumeserver: unsupported coherence profile")
	ErrVisibilityStartup  = errors.New("volumeserver: prior strict mounts are not proven fenced")
	ErrVisibilityTargets  = errors.New("volumeserver: visible mutation omitted repair targets")
	// ErrVisibilityProof rejects a detach that carries no usable evidence that
	// the frontend's own kernel mount is gone.
	ErrVisibilityProof = errors.New("volumeserver: detach did not prove the kernel mount is absent")
	// ErrVisibilityPoisoned is reserved for coordinator-internal invariant
	// violations. It is permanent for this authority epoch, so nothing that an
	// ordinary participant can do on its own may ever produce it.
	ErrVisibilityPoisoned = errors.New("volumeserver: visibility epoch is poisoned by an authority defect")
)

// CoherenceProfile is declared by a mount at attach time. It describes the
// frontend's kernel-cache obligations, not its operating system.
type CoherenceProfile uint8

const (
	CoherenceUncached CoherenceProfile = iota
	CoherenceStrict
)

// NamespaceRepair is how a strict frontend's kernel makes one cached
// name->inode binding unservable. It is declared at attach and never inferred:
// the authority cannot observe a remote kernel, and the two answers have
// different provable properties.
type NamespaceRepair uint8

const (
	// NamespaceRepairUnspecified is refused. A strict mount that does not say
	// how it repairs has not agreed to the contract the barrier is built on.
	NamespaceRepairUnspecified NamespaceRepair = iota
	// NamespaceRepairParentExclusive is Linux FUSE: making a binding unservable
	// requires the parent directory's i_rwsem for write, and the mount's own
	// in-flight directory syscall in that parent holds it for the whole
	// authority round trip. An exact ReportBlocked handshake installs a scoped
	// pre-apply interruption for an overlapping request while the frontend's
	// local gate refuses later arrivals.
	NamespaceRepairParentExclusive
	// NamespaceRepairIndependent means repair never waits on a lock this
	// mount's own unanswered operation can hold.
	NamespaceRepairIndependent
	// NamespaceRepairCallbackSerialized is the frozen macOS 26 v1 contract: any
	// unanswered mutation is interrupted while this participant owes a phase.
	NamespaceRepairCallbackSerialized
	// NamespaceRepairCallbackSerializedPipelined is the identity-aware macOS 26
	// v2 contract. Any unanswered visible mutation can occupy the framework
	// callback capacity repair needs, independent of the mutation's cache
	// coordinates. A peer phase, an unknown callback identity, or another
	// mutation from the initiating callback is interrupted before apply. A
	// distinct nonzero source callback waits only when its exact request carries
	// SourcePhaseQueueable: the frontend contract then excludes the
	// already-dispatched ordered-only ticket from a local-source PREPARE drain,
	// and source COMPLETE waits only for the initiating callback, so that wait
	// has no reverse edge. A mixed callback stays on the interruption path.
	NamespaceRepairCallbackSerializedPipelined
)

// PriorEpochDisposition is supplied by the durable control plane when a new
// authority epoch starts. Empty process memory is never evidence that a prior
// FSKit mount stopped serving cached state.
type PriorEpochDisposition uint8

const (
	PriorEpochUnproven PriorEpochDisposition = iota
	PriorEpochStrictMountsFenced
)

// DurableVisibilityMembership is outside the disposable authority runtime.
// Activate must durably record a strict mount before attach returns. Deactivate
// must durably record an authenticated clean detach or host fencing before the
// authority drops the mount's barrier obligation.
type DurableVisibilityMembership interface {
	Activate(SessionID) error
	Deactivate(SessionID) error
}

// SessionFencer ends one session's authority-side liveness immediately.
//
// Fencing ends authority-side liveness and excludes the participant from new
// barriers. A current pending delivery remains held for one further repair
// budget so the mount, told by its session dying, can revoke itself locally
// before that obligation is discharged.
type SessionFencer interface {
	FenceSession(SessionID)
}

// VisibilityScope identifies the kernel state a frontend must synchronously
// control before it acknowledges an event.
type VisibilityScope uint8

const (
	VisibilityNamespace VisibilityScope = iota + 1
	VisibilityData
	VisibilityAttributes
)

// VisibilityTarget carries stable XFS identity, never an epoch capability
// owned by a different session. Namespace targets identify one binding in a
// parent; data and attribute targets identify one inode. Size is meaningful
// for data targets and is the authoritative post-mutation EOF.
type VisibilityTarget struct {
	Scope          VisibilityScope
	Identity       [16]byte
	ParentIdentity [16]byte
	Name           []byte
	Size           int64
	// PostIdentity is an authority-attested post-mutation binding for a
	// namespace coordinate. It is zero when COMPLETE does not prove which item
	// owns the name. Frontends may use the exact association to repair an
	// otherwise unpathable retained vnode; dependency metadata is not enough.
	PostIdentity [16]byte
	// Kernel-cache coordination facts, distinct from the stable identities
	// above. The stable identity is the exact XFS export handle — type, inode
	// and generation, never a device — and names the object for frontends
	// that index by item identity. A FUSE frontend keys its kernel caches by
	// the inode number the authority publishes in attributes, so that number
	// and the one backing device travel explicitly instead of being parsed
	// out of a layout that does not contain them.
	KernelIno       uint64
	ParentKernelIno uint64
	Device          uint64
	// RelatedIdentities is authority-internal dependency metadata for a
	// namespace target. It names inode coordinates that one read of this exact
	// pre-mutation binding can publish with the name. It is never serialized:
	// projection uses it only to keep a synthetic parent-attribute repair anchor
	// from omitting the same callback's raced inode publication.
	RelatedIdentities [][16]byte
}

// key is the exact cache coordinate this target names. Size is excluded: it is
// the post-mutation value of the state at that coordinate, not part of it.
func (t VisibilityTarget) key() []byte {
	if t.Scope == VisibilityNamespace {
		return nameKey(t.ParentIdentity, t.Name)
	}
	return inodeKey(t.Identity)
}

// VisibilityPhase is part of an event's exact acknowledgment identity.
type VisibilityPhase uint8

const (
	// VisibilityPrepare closes publication admission for affected callbacks and
	// waits only for callbacks already publishing to the kernel. Submitted
	// mutations that are still waiting for authority order stay parked outside
	// that critical section, avoiding a two-writer drain deadlock.
	VisibilityPrepare VisibilityPhase = iota + 1
	// VisibilityComplete repairs affected cache state while admission remains
	// closed, then reopens publication. Targets are empty when XFS changed
	// nothing; COMPLETE is still required to release the frontend gate.
	VisibilityComplete
)

// VisibilityCursor identifies one phase, so PREPARE and COMPLETE for the same
// mutation cannot be mistaken for duplicate delivery. Sequences a participant
// is not part of are simply never delivered to it, so a participant's observed
// cursors are increasing but need not be contiguous.
type VisibilityCursor struct {
	Sequence uint64
	Phase    VisibilityPhase
}

// RoutesChange is a volume-wide machine-local routing topology. It is carried
// on an event instead of being encoded as a namespace target because it is not
// a cache coordinate: it has no parent, no name and no inode, and a frontend
// cannot discharge it by invalidating a dentry. What it owes is to stop serving
// the old topology entirely before it acknowledges COMPLETE.
type RoutesChange struct {
	Revision  [32]byte
	Canonical []byte
}

func (r *RoutesChange) clone() *RoutesChange {
	if r == nil {
		return nil
	}
	out := *r
	out.Canonical = append([]byte(nil), r.Canonical...)
	return &out
}

// VisibilityEvent is authority-epoch local. Initiator plus slot/sequence form
// the ticket a source frontend exempts from its own PREPARE drain; the replay
// request hash remains private to that session.
type VisibilityEvent struct {
	Cursor              VisibilityCursor
	Initiator           SessionID
	MutationSlot        uint32
	MutationSequence    uint64
	FrontendOperationID uint64
	Targets             []VisibilityTarget
	// Routes is set on exactly the two phases of a routing-topology change, and
	// Targets is empty on those phases. The two are disjoint by construction.
	Routes *RoutesChange
}

// MountAbsenceProof is the authenticated supervisor's observation that its own
// exact kernel mount is gone. Observation is opaque diagnostic context: a
// remote authority cannot independently inspect the client's kernel. The trust
// boundary is the session-authenticated Detach request, and the frontend is
// responsible for making the statement only after its platform-specific mount
// identity and serving connection are terminal. See CleanDetach.
type MountAbsenceProof struct {
	ObservedUnixNanos int64
	Observation       []byte
	Component         string
}

// Bounds on the retained evidence. The authority keeps none of it, but a
// detach must not be a channel for unbounded work either.
const (
	maxMountAbsenceObservation = 4096
	maxMountAbsenceComponent   = 128
)

// VisibilityCommitment is what a strict frontend states at attach. Both numbers
// are admitted against an explicit deployment bound rather than clamped, so a
// mount can never be running against limits it did not agree to.
type VisibilityCommitment struct {
	// CachedNameCapacity is how many distinct resolutions the frontend's kernel
	// cache is expected to hold. It sizes the per-session resolved index and
	// nothing else: the index never drops a coordinate, so an understated
	// capacity costs precision, never correctness. See visibility_index.go.
	CachedNameCapacity uint64
	// RepairBudget is the longest the frontend may take to acknowledge one
	// phase, and equally the longest it may go without an authority round trip
	// before revoking its own mount. This one is load-bearing: the authority
	// fences on it, and the frontend must self-revoke on it, so the window in
	// which a fenced mount could still serve a stale name is bounded by it.
	RepairBudget time.Duration
	// NamespaceRepair is how this frontend's kernel makes a cached binding
	// unservable. It has no default: see NamespaceRepair.
	NamespaceRepair NamespaceRepair
}

// VisibilityResolution is one piece of state a read-path operation is about to
// hand a strict frontend's kernel cache. A zero Parent means the operation
// resolves no name; a zero Identity means it resolves no inode.
type VisibilityResolution struct {
	Parent   [16]byte
	Name     []byte
	Identity [16]byte
}

func (r VisibilityResolution) keys() [][]byte {
	var keys [][]byte
	if r.Parent != ([16]byte{}) && len(r.Name) != 0 {
		keys = append(keys, nameKey(r.Parent, r.Name))
	}
	if r.Identity != ([16]byte{}) {
		keys = append(keys, inodeKey(r.Identity))
	}
	return keys
}

// VisibilityBarrierError reports whether XFS apply had begun. A post-apply
// barrier failure is necessarily an uncertain filesystem outcome to the
// caller, even when the authority knows the underlying syscall succeeded.
type VisibilityBarrierError struct {
	Applied bool
	Err     error
}

func (e *VisibilityBarrierError) Error() string {
	where := "before filesystem apply"
	if e.Applied {
		where = "after filesystem apply"
	}
	return fmt.Sprintf("volumeserver: visibility barrier failed %s: %v", where, e.Err)
}
func (e *VisibilityBarrierError) Unwrap() error { return e.Err }

type visibilityDelivery struct {
	participant SessionID
	event       VisibilityEvent
	done        chan error
	once        sync.Once
	created     time.Time
	deadline    time.Time
}

func (d *visibilityDelivery) finish(err error) { d.once.Do(func() { d.done <- err; close(d.done) }) }

type visibilityParticipant struct {
	id      SessionID
	pending *visibilityDelivery
	// interrupt is installed only after a parent-exclusive frontend confirms
	// from its exact cache registry that its pending COMPLETE needs a parent
	// currently held by one of its own unanswered mutations. It stays active
	// through Ack so a new request cannot recreate the cycle while repair runs.
	interrupt *visibilityInterruption
	// reported retains the last accepted report after Ack. It is not an active
	// scope; it only makes a response-lost retry of that exact report
	// idempotent instead of turning a completed repair into a cursor violation.
	reported *visibilityInterruption
	acked    VisibilityCursor
	changed  chan struct{}
	terminal <-chan struct{}
	// left closes when this participant is out of the barrier set, so the
	// watchdog that waits on terminal cannot outlive the participant.
	left       chan struct{}
	budget     time.Duration
	registered time.Time
	index      *resolvedIndex
	repair     NamespaceRepair
}

type visibilityInterruption struct {
	cursor       VisibilityCursor
	parents      map[[16]byte]struct{}
	kernelInodes map[uint64]struct{}
}

// mutationFairnessDebt is an off-list, one-shot effective FIFO position. A
// dormant debt is tied to the peer visibility sequence that forced a queueable
// callback to leave. It becomes claimable only after that sequence's exact
// COMPLETE Ack. A wholly local frontend refusal activates the PREPARE-time cut
// at the same edge. Neither form owns mutation order while unclaimed.
type mutationFairnessDebt struct {
	sequence    uint64
	ordinal     uint64
	operationID uint64
	observed    bool
	active      bool
	deadline    time.Time
}

const mutationFairnessClaimWindow = time.Second

func (p *visibilityParticipant) signalLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

// matchingTargetKeys projects one mutation footprint onto the coordinates
// this mount could still cache. A Bloom false positive retains one unnecessary
// target; it must never import unrelated targets from the same mutation.
//
// One dependency is deliberately closed here. A namespace repair refreshes its
// parent directory's attributes on every strict frontend, while a bare parent
// attribute target is not necessarily repairable (the macOS root, for example,
// has no parent pathname). When a participant matches such a parent target but
// no name under that parent, retain the lexicographically first mutation name
// under that parent as a repair anchor. The anchor also imports only the inode
// identities that an already-admitted read of that exact binding can publish;
// omitting one would make Stabilize wait behind PREPARE while macOS PREPARE was
// waiting for the same callback to publish. Other names, inodes, and data
// targets in a compound mutation remain projected independently.
func (p *visibilityParticipant) matchingTargetKeys(targets []VisibilityTarget) map[string]struct{} {
	matched := make(map[string]struct{})
	for _, target := range targets {
		key := target.key()
		if p.index.contains(key) {
			matched[string(key)] = struct{}{}
		}
	}
	for _, target := range targets {
		if target.Scope != VisibilityAttributes {
			continue
		}
		if _, ok := matched[string(target.key())]; !ok {
			continue
		}
		anchored := false
		var anchor *VisibilityTarget
		for i := range targets {
			candidate := &targets[i]
			if candidate.Scope != VisibilityNamespace || candidate.ParentIdentity != target.Identity {
				continue
			}
			if _, ok := matched[string(candidate.key())]; ok {
				anchored = true
				break
			}
			if anchor == nil || bytes.Compare(candidate.Name, anchor.Name) < 0 {
				anchor = candidate
			}
		}
		if anchored || anchor == nil {
			continue
		}
		matched[string(anchor.key())] = struct{}{}
		for _, identity := range anchor.RelatedIdentities {
			matched[string(inodeKey(identity))] = struct{}{}
		}
	}
	return matched
}

// visibilityAudience is the exact participant set one mutation's two phases
// address. It is chosen once, at PREPARE, so the mount whose publication
// admission was closed is always the mount that is later told to reopen it.
type visibilityAudience struct {
	members []*visibilityParticipant
	// targetKeys is the PREPARE-time projection for each member. A participant
	// receives only targets its monotone resolved index says it may hold; the
	// source is assigned the full set because its initiating callback is itself
	// the local cache transition. A nil map is reserved for non-coordinate
	// events such as a routing change.
	targetKeys map[SessionID]map[string]struct{}
	// source is the initiating mount when the initiator is itself strict. Its
	// COMPLETE is deferred rather than awaited, so it is tracked separately.
	source *visibilityParticipant
}

func (a visibilityAudience) project(event VisibilityEvent, id SessionID) VisibilityEvent {
	if a.targetKeys == nil {
		return event
	}
	allowed := a.targetKeys[id]
	projected := make([]VisibilityTarget, 0, len(event.Targets))
	for _, target := range event.Targets {
		if _, ok := allowed[string(target.key())]; ok {
			projected = append(projected, target)
		}
	}
	event.Targets = projected
	return event
}

// visibilityMutationState is the read-side ordering boundary for the one
// cache-visible mutation that owns serial order.
//
// During PREPARE, a participant in audience may still have callbacks that were
// admitted before its publication gate closed. Those callbacks must be allowed
// to finish reading the old value: that publication is exactly what the
// participant's still-pending PREPARE drains before Ack. A participant outside
// audience was not told to close its gate, so its first resolution of one of
// these keys must wait for apply instead. Once an audience member acknowledges
// PREPARE, it also waits; its closed gate promises no legitimate old-value
// publication remains.
//
// applying becomes true only after every PREPARE Ack. From that point all
// conflicting reads wait until done closes immediately after XFS apply.
type visibilityMutationState struct {
	keys     map[string]struct{}
	audience map[SessionID]*visibilityParticipant
	// projectedKeys is the exact PREPARE scope delivered to each audience
	// member. A raced resolution may drain old publication only when its key was
	// actually in that scope; membership in a union audience is not enough.
	projectedKeys map[SessionID]map[string]struct{}
	cursor        VisibilityCursor
	applying      bool
	done          chan struct{}
}

// VisibilityConfig is the complete construction input. It is a struct because
// every field is a safety property and none of them has a defensible default
// that a deployment should be allowed to inherit silently.
type VisibilityConfig struct {
	Prior      PriorEpochDisposition
	Membership DurableVisibilityMembership
	Fencer     SessionFencer
	// MaxCachedNameCapacity is the largest resolved-index size this deployment
	// will allocate per strict mount. An attach declaring more is refused rather
	// than clamped, so what a mount was admitted on and what it is running
	// against are the same number.
	MaxCachedNameCapacity uint64
	// MaxRepairBudget is the longest phase deadline this deployment will admit.
	MaxRepairBudget time.Duration
	// MaxClockSkew bounds the disagreement tolerated between this authority's
	// clock and a frontend's when a mount-absence observation is timestamped.
	MaxClockSkew time.Duration
	Now          func() time.Time
	// OnFence observes participant-scoped fencing. It exists so an operator can
	// see which mount left and why without the event being escalated into an
	// epoch-wide failure.
	OnFence func(SessionID, error)
	// OnRefusedCommitment observes an attach refused for declaring numbers this
	// deployment will not admit. The refusal reaches the mount as a bare errno,
	// so this is the only place both sides of the disagreement are visible.
	OnRefusedCommitment func(SessionID, error)
}

// VisibilityCoordinator owns disposable event state around durable membership.
//
// Failure has two scopes and they are never mixed. A participant that dies,
// misses its budget, or violates the cursor is fenced individually: it leaves
// the barrier set, its session ends, and the mutation completes for everyone
// else. Poison is reserved for coordinator-internal invariant violations; it is
// permanent for this epoch, and recovery requires a new epoch plus durable
// proof that every old strict kernel mount is unusable.
type VisibilityCoordinator struct {
	// topology excludes a volume-wide routing revision switch from every
	// filesystem request and attach that was admitted against the previous
	// revision. It is deliberately separate from registration: strict participant
	// registration needs the write side of registration while attach itself holds
	// the read side of topology, and making those the same lock would recursively
	// deadlock.
	topology sync.RWMutex
	// registration prevents attach from becoming visible during an overlapping
	// mutation. With no strict participants mutations retain XFS concurrency by
	// sharing this read lock.
	registration sync.RWMutex
	// order gives cache-visible mutations one cancellable FIFO order while
	// strict mounts exist. Each waiter still watches its frontend's exact repair
	// state and can remove itself from any queue position before apply.
	order *mutationOrder

	cfg          VisibilityConfig
	startupReady bool

	mu           sync.Mutex
	participants map[SessionID]*visibilityParticipant
	fairness     map[SessionID]mutationFairnessDebt
	deferred     []*visibilityDelivery
	next         uint64
	poisoned     error
	seed         uint64
	// mutation holds both sides of the PREPARE -> apply read boundary. See
	// visibilityMutationState and Stabilize.
	mutation *visibilityMutationState
}

// TopologyReadGuard pins the routing revision a filesystem request or attach
// was admitted against. ApplyRoutes takes the corresponding write side before
// it rechecks compare-and-swap and keeps it through durable commit, so a request
// can never pass admission under one topology and reach XFS under another.
//
// The guard is intentionally opaque and pointer-only. Release is idempotent so
// a deferred release remains safe on every handler exit.
type TopologyReadGuard struct {
	coordinator *VisibilityCoordinator
	once        sync.Once
}

// AcquireTopologyRead begins one route-revision admission critical section.
func (c *VisibilityCoordinator) AcquireTopologyRead() *TopologyReadGuard {
	c.topology.RLock()
	return &TopologyReadGuard{coordinator: c}
}

// Release ends one route-revision admission critical section.
func (g *TopologyReadGuard) Release() {
	if g == nil || g.coordinator == nil {
		return
	}
	g.once.Do(func() { g.coordinator.topology.RUnlock() })
}

func NewVisibilityCoordinator(cfg VisibilityConfig) (*VisibilityCoordinator, error) {
	if cfg.Membership == nil || cfg.Fencer == nil {
		return nil, errors.New("volumeserver: visibility needs durable membership and a session fencer")
	}
	if cfg.MaxCachedNameCapacity == 0 || cfg.MaxRepairBudget <= 0 || cfg.MaxClockSkew < 0 {
		return nil, errors.New("volumeserver: visibility needs explicit cache-capacity, repair-budget, and clock-skew bounds")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("seed visibility resolved index: %w", err)
	}
	return &VisibilityCoordinator{
		cfg: cfg, order: newMutationOrder(),
		participants: make(map[SessionID]*visibilityParticipant),
		fairness:     make(map[SessionID]mutationFairnessDebt),
		startupReady: cfg.Prior == PriorEpochStrictMountsFenced,
		seed:         binary.LittleEndian.Uint64(seed[:]),
	}, nil
}

// Register installs a strict cache holder before attach becomes visible. The
// terminal channel closes at the runtime fencing boundary; an unclean close
// fences this participant even when no mutation is currently in flight.
func (c *VisibilityCoordinator) Register(id SessionID, profile CoherenceProfile, terminal <-chan struct{}, commitment VisibilityCommitment) error {
	if profile == CoherenceUncached {
		return nil
	}
	if profile != CoherenceStrict || terminal == nil {
		return ErrVisibilityProfile
	}
	// A zero session ID is rejected here rather than assumed absent. The
	// audience machinery distinguishes the initiating mount by pointer identity
	// and never by a sentinel ID, but durable membership records session IDs
	// verbatim and a zero record is meaningless, so the invariant is stated
	// once, at the only place a participant can enter the set.
	if id == (SessionID{}) {
		return ErrVisibilityProfile
	}
	if err := c.admitCommitment(id, commitment); err != nil {
		return err
	}
	c.registration.Lock()
	defer c.registration.Unlock()
	c.mu.Lock()
	if !c.startupReady {
		c.mu.Unlock()
		return ErrVisibilityStartup
	}
	if c.poisoned != nil {
		err := c.poisoned
		c.mu.Unlock()
		return err
	}
	if _, exists := c.participants[id]; exists {
		c.mu.Unlock()
		return ErrAdmission
	}
	c.mu.Unlock()
	if err := c.cfg.Membership.Activate(id); err != nil {
		return fmt.Errorf("record strict visibility participant: %w", err)
	}

	// The index is the one sizeable allocation here, so it happens before the
	// lock that every barrier decision also needs.
	index := newResolvedIndex(commitment.CachedNameCapacity, c.seed^sessionSeed(id))
	c.mu.Lock()
	initial := VisibilityCursor{}
	if c.next != 0 {
		initial = VisibilityCursor{Sequence: c.next, Phase: VisibilityComplete}
	}
	p := &visibilityParticipant{
		id: id, terminal: terminal, acked: initial,
		changed: make(chan struct{}), left: make(chan struct{}),
		budget: commitment.RepairBudget, registered: c.cfg.Now(),
		index: index, repair: commitment.NamespaceRepair,
	}
	c.participants[id] = p
	c.mu.Unlock()
	select {
	case <-terminal:
		c.Fence(id, ErrVisibilityLost)
		return ErrVisibilityLost
	default:
	}
	go func() {
		select {
		case <-terminal:
			c.Fence(id, ErrVisibilityLost)
		case <-p.left:
			// Already out of the barrier set. Waiting on terminal from here
			// would keep this goroutine alive for the rest of the epoch.
		}
	}()
	return nil
}

// admitCommitment refuses a mount whose declared numbers this deployment will
// not run against, and says which number and which bound disagreed. A refusal
// reaches the mount as a bare errno, so a message that named neither value left
// an operator with two configuration files and no way to tell which one was
// wrong.
func (c *VisibilityCoordinator) admitCommitment(id SessionID, commitment VisibilityCommitment) error {
	refusal := c.ValidateCommitment(commitment)
	if refusal == nil {
		return nil
	}
	if c.cfg.OnRefusedCommitment != nil {
		c.cfg.OnRefusedCommitment(id, refusal)
	}
	return refusal
}

// ValidateCommitment checks only the peer-declared, deployment-bounded shape
// of a strict visibility commitment. It does no durable or global admission
// and invokes no callbacks, so an RPC handler may safely call it before
// spending a single-use attach capability. Register repeats the validation.
func (c *VisibilityCoordinator) ValidateCommitment(commitment VisibilityCommitment) error {
	var refusal error
	switch {
	case commitment.CachedNameCapacity == 0:
		refusal = fmt.Errorf("%w: mount declared no kernel-cache capacity", ErrVisibilityProfile)
	case commitment.CachedNameCapacity > c.cfg.MaxCachedNameCapacity:
		refusal = fmt.Errorf("%w: mount declared kernel-cache capacity %d, authority admits at most %d",
			ErrVisibilityProfile, commitment.CachedNameCapacity, c.cfg.MaxCachedNameCapacity)
	case commitment.RepairBudget <= 0:
		refusal = fmt.Errorf("%w: mount declared no repair budget", ErrVisibilityProfile)
	case commitment.RepairBudget > c.cfg.MaxRepairBudget:
		refusal = fmt.Errorf("%w: mount declared repair budget %s, authority admits at most %s",
			ErrVisibilityProfile, commitment.RepairBudget, c.cfg.MaxRepairBudget)
	case commitment.NamespaceRepair != NamespaceRepairParentExclusive &&
		commitment.NamespaceRepair != NamespaceRepairIndependent &&
		commitment.NamespaceRepair != NamespaceRepairCallbackSerialized &&
		commitment.NamespaceRepair != NamespaceRepairCallbackSerializedPipelined:
		// There is no default here on purpose. Assuming "independent" would let
		// the authority wait out a proven cycle as though it were a slow lock;
		// assuming "parent-exclusive" would fence a mount that could have
		// repaired. Both are worse than refusing a mount that did not say.
		refusal = fmt.Errorf("%w: mount declared no namespace-repair model; a strict mount must state whether repair is parent-exclusive, callback-serialized, callback-serialized-pipelined, or independent",
			ErrVisibilityProfile)
	default:
		return nil
	}
	return refusal
}

func sessionSeed(id SessionID) uint64 {
	return binary.LittleEndian.Uint64(id[0:8]) ^ binary.LittleEndian.Uint64(id[8:16])
}

// InitialCursor is returned in the attach reply. A mount registered after
// sequence N starts from COMPLETE(N) because registration excluded overlapping
// mutation apply and the new mount has not cached pre-N state.
func (c *VisibilityCoordinator) InitialCursor(id SessionID) (VisibilityCursor, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.participants[id]
	if p == nil {
		return VisibilityCursor{}, ErrSessionExpired
	}
	return p.acked, nil
}

// CleanDetach removes the exact participant whose authenticated supervisor says
// its kernel mount is gone. Terminal mount absence is stronger than cache
// repair - there is no longer a mount that can serve the stale name - so a
// valid observation also discharges an outstanding barrier obligation.
//
// The authority cannot inspect a remote kernel, so it does not pretend the
// opaque bytes are independent attestation. The caller must have authenticated
// this request as id's current authority session. The coordinator still checks
// that the observation is complete, temporally belongs to this mount, postdates
// the obligation it discharges, and is not dated in the future. A frontend with
// nothing to observe sends nothing and lets its session die fenced.
func (c *VisibilityCoordinator) CleanDetach(id SessionID, proof MountAbsenceProof) error {
	now := c.cfg.Now()
	c.mu.Lock()
	p := c.participants[id]
	if p == nil {
		c.mu.Unlock()
		return ErrSessionExpired
	}
	if err := c.validateMountAbsenceLocked(proof, p, now); err != nil {
		c.mu.Unlock()
		return err
	}
	delete(c.participants, id)
	delete(c.fairness, id)
	pending := p.pending
	p.pending = nil
	p.signalLocked()
	close(p.left)
	c.mu.Unlock()
	// The authenticated supervisor has already made the mount terminal, so
	// nothing waits on the durable write.
	if pending != nil {
		pending.finish(nil)
	}
	if err := c.cfg.Membership.Deactivate(id); err != nil {
		// The record still names this mount, so a restarted epoch refuses to
		// serve until an operator proves the fencing. That is the conservative
		// direction; reporting success here would not be.
		return fmt.Errorf("record strict visibility detach: %w", err)
	}
	return nil
}

func (c *VisibilityCoordinator) validateMountAbsenceLocked(proof MountAbsenceProof, p *visibilityParticipant, now time.Time) error {
	if len(proof.Observation) == 0 || len(proof.Observation) > maxMountAbsenceObservation ||
		proof.Component == "" || len(proof.Component) > maxMountAbsenceComponent || proof.ObservedUnixNanos <= 0 {
		return ErrVisibilityProof
	}
	observed := time.Unix(0, proof.ObservedUnixNanos)
	skew := c.cfg.MaxClockSkew
	if observed.After(now.Add(skew)) {
		return ErrVisibilityProof
	}
	if observed.Before(p.registered.Add(-skew)) {
		return ErrVisibilityProof
	}
	if p.pending != nil && observed.Before(p.pending.created.Add(-skew)) {
		return ErrVisibilityProof
	}
	return nil
}

// Fence removes exactly one participant from the barrier and ends its session.
// Durable membership is deliberately left active: the session is gone, but
// nothing here proves the kernel mount is, so a restarted epoch must still
// refuse to serve until an operator says otherwise.
func (c *VisibilityCoordinator) Fence(id SessionID, reason error) {
	c.fence(id, nil, reason)
}

// fence removes id only when expected is nil or is still its exact pending
// delivery. The latter closes the deadline/Ack race: selecting the timer does
// not prove the phase is still outstanding once this mutex is reacquired.
func (c *VisibilityCoordinator) fence(id SessionID, expected *visibilityDelivery, reason error) bool {
	if reason == nil {
		reason = ErrVisibilityLost
	}
	c.mu.Lock()
	p := c.participants[id]
	if p == nil || (expected != nil && p.pending != expected) {
		c.mu.Unlock()
		return false
	}
	delete(c.participants, id)
	delete(c.fairness, id)
	// Ending the authority session is immediate, but it is not evidence that the
	// remote kernel stopped serving cached state at the same instant. Preserve an
	// outstanding delivery for one additional full repair budget. The frontend's
	// bounded-contact watchdog gets that grace to abort its kernel connection;
	// only then may the mutation return. A failed participant can therefore cost
	// at most two budgets: one phase deadline plus one fencing grace.
	pending := p.pending
	p.signalLocked()
	close(p.left)
	c.mu.Unlock()
	// FenceSession is the active fencing action. It remains ahead of callbacks so
	// operator logging cannot delay the session becoming terminal.
	c.cfg.Fencer.FenceSession(id)
	// The grace starts only after the authority-side fence has completed. This is
	// a full additional budget for the frontend's bounded-contact watchdog, not
	// time that a slow fencing implementation is allowed to consume.
	if pending != nil {
		time.AfterFunc(p.budget, func() { pending.finish(nil) })
	}
	if c.cfg.OnFence != nil {
		c.cfg.OnFence(id, reason)
	}
	return true
}

func (c *VisibilityCoordinator) poison(cause error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.poisonLocked(cause)
}

func (c *VisibilityCoordinator) poisonLocked(cause error) error {
	if cause == nil {
		cause = errors.New("unspecified authority defect")
	}
	if c.poisoned == nil {
		c.poisoned = fmt.Errorf("%w: %w", ErrVisibilityPoisoned, cause)
	}
	for _, participant := range c.participants {
		if participant.pending != nil {
			participant.pending.finish(c.poisoned)
			participant.pending = nil
		}
		participant.signalLocked()
	}
	return c.poisoned
}

// Execute orders one cache-visible filesystem mutation. prepare identifies the
// callback publication gates that close before apply. apply runs exactly once
// and returns post-mutation repair targets plus whether visible state changed.
//
// ctx bounds only the part of this that can be abandoned without consequence:
// queueing for mutation order, and waiting for the previous mutation's deferred
// source acknowledgment. Once a phase has been delivered, a mount is holding
// its publication admission closed and only its own acknowledgment or its
// fencing can reopen it, so a caller giving up cannot end that wait. What bounds
// it instead is the per-participant repair budget.
func (c *VisibilityCoordinator) Execute(ctx context.Context, source SessionID, mutation MutationID,
	prepare func() ([]VisibilityTarget, error), apply func() ([]VisibilityTarget, bool)) error {
	return c.execute(ctx, source, mutation, nil, prepare, apply)
}

// ExecuteWithHeldParents is Execute for a namespace callback whose kernel holds
// the listed parent directories until this authority answers. The declaration
// is scoped only to this exact request, so one concurrent request in D1 can
// never spuriously interrupt another request from the same mount in D2.
func (c *VisibilityCoordinator) ExecuteWithHeldParents(ctx context.Context, source SessionID, mutation MutationID,
	held [][16]byte, prepare func() ([]VisibilityTarget, error), apply func() ([]VisibilityTarget, bool)) error {
	return c.execute(ctx, source, mutation, held, prepare, apply)
}

func (c *VisibilityCoordinator) execute(ctx context.Context, source SessionID, mutation MutationID, held [][16]byte,
	prepare func() ([]VisibilityTarget, error), apply func() ([]VisibilityTarget, bool)) error {
	if ctx == nil || prepare == nil || apply == nil {
		return errors.New("volumeserver: visibility context, prepare, and mutation callbacks are required")
	}
	c.registration.RLock()
	defer c.registration.RUnlock()
	c.mu.Lock()
	strict := len(c.participants) != 0
	ready, poisoned := c.startupReady, c.poisoned
	c.mu.Unlock()
	if !ready {
		return &VisibilityBarrierError{Err: ErrVisibilityStartup}
	}
	if poisoned != nil {
		return &VisibilityBarrierError{Err: poisoned}
	}
	if !strict {
		return c.executeUncached(prepare, apply)
	}

	turn, err := c.acquireMutationOrder(ctx, source, mutation, held)
	if err != nil {
		return err
	}
	defer turn.release()

	if err := c.waitDeferred(ctx); err != nil {
		return &VisibilityBarrierError{Err: err}
	}
	prepareTargets, err := prepare()
	if err != nil {
		return err
	}
	if err := validateVisibilityTargets(prepareTargets); err != nil {
		return &VisibilityBarrierError{Err: ErrVisibilityTargets}
	}

	ticket := VisibilityEvent{
		Initiator:           source,
		MutationSlot:        mutation.Slot,
		MutationSequence:    mutation.Sequence,
		FrontendOperationID: mutation.FrontendOperationID,
	}
	audience, deliveries, err := c.openBarrier(source, prepareTargets, &ticket)
	// The PREPARE/apply state is released on every exit from here on, including
	// the one where opening the barrier itself failed: a reader waiting on a
	// coordinate must never outlive the mutation that claimed it.
	defer c.closeBarrier()
	if err != nil {
		return &VisibilityBarrierError{Err: err}
	}
	if err := c.awaitAll(deliveries); err != nil {
		return &VisibilityBarrierError{Err: err}
	}
	c.beginApply()

	completeTargets, changed := apply()
	// The coordinates stop being in flight the instant XFS has them, not when
	// the last mount has finished repairing its cache. A reader that found one
	// of them in flight is parked in Stabilize, and on Linux it is parked while
	// its own kernel holds the directory: lookup_slow holds i_rwsem SHARED
	// across the whole round trip (fs/namei.c:1703-1713), and iterate_dir does
	// the same for a readdir. Releasing only after COMPLETE would mean that
	// reader waits for a phase whose repair needs down_write on the very lock it
	// is holding (fs/fuse/dir.c:1351) - a second closed cycle, and one that a
	// concurrent enumeration of a directory another mount is filling hits
	// continuously rather than rarely. Releasing here bounds a reader's wait to
	// work that needs nothing from any mount: PREPARE closes frontend-local
	// gates, and apply is this authority talking to XFS.
	//
	// It costs nothing in exactness. A reader released here reads post-apply
	// state, which is the new value, not the old one; the next mutation cannot
	// have started, because this one still holds mutation order; and COMPLETE is
	// addressed to the mounts that cached the PRE-mutation value, which this
	// reader by definition did not.
	c.closeBarrier()
	if changed {
		if err := c.validateCompletion(completeTargets, prepareTargets); err != nil {
			return &VisibilityBarrierError{Applied: true, Err: err}
		}
	}
	ticket.Cursor.Phase = VisibilityComplete
	if changed {
		ticket.Targets = cloneVisibilityTargets(completeTargets)
	} else {
		ticket.Targets = nil
	}
	// Every non-source mount in this mutation's audience repairs before the
	// reply is released.
	complete, err := c.dispatch(ticket, audience, audience.source)
	if err != nil {
		return &VisibilityBarrierError{Applied: true, Err: err}
	}
	if err := c.awaitAll(complete); err != nil {
		return &VisibilityBarrierError{Applied: true, Err: err}
	}
	// Asking FSKit to run a nested source repair before its initiating callback
	// receives this operation's reply can deadlock. Queue COMPLETE for the source
	// without waiting now. The source acknowledges it after its ordinary callback
	// publishes, and the next mutation cannot begin until that deferred Ack.
	if err := c.deferSource(audience.source, ticket); err != nil {
		return &VisibilityBarrierError{Applied: true, Err: err}
	}
	c.recordSourceTargets(audience.source, prepareTargets, completeTargets)
	return nil
}

// acquireMutationOrder takes the global visible-mutation turn while honoring
// the frontend-declared progress constraints. Each caller joins the FIFO once
// and keeps that position across harmless participant-state changes. A pending
// repair can still remove a hazardous waiter from any queue position before
// prepare or apply, which is required for both FSKit callback capacity and
// Linux parent-lock cycle breaking.
//
// The post-grant check closes the edge where a phase and the FIFO handoff become
// visible together. Abandoning a waiter is safe even if the grant won that race:
// it releases the exact ownership before returning the definite-preapply result.
func (c *VisibilityCoordinator) acquireMutationOrder(ctx context.Context, source SessionID, mutation MutationID, held [][16]byte) (*mutationOrderWaiter, error) {
	var turn *mutationOrderWaiter
	for {
		c.mu.Lock()
		participant := c.participants[source]
		var changed <-chan struct{}
		interrupted := false
		queueable := fairnessQueueable(participant, mutation)
		if participant != nil {
			interrupted = c.mutationMustYieldLocked(source, mutation, participant, held)
			if participant.repair == NamespaceRepairCallbackSerialized ||
				participant.repair == NamespaceRepairCallbackSerializedPipelined ||
				(participant.repair == NamespaceRepairParentExclusive && len(held) != 0) {
				changed = participant.changed
			}
		}
		if interrupted {
			c.recordDormantFairnessLocked(source, participant, mutation, turn)
			if turn != nil {
				// Retire the exact node while c.mu still excludes COMPLETE Ack,
				// linearizing ordinal capture and removal before the debt can become
				// claimable by a later callback.
				turn.abandon()
				turn = nil
			}
		} else if turn == nil {
			reserved := c.claimFairnessLocked(source, mutation, queueable)
			turn = c.order.enqueueFor(reserved)
		}
		c.mu.Unlock()
		if interrupted {
			return nil, ErrVisibilityInterrupted
		}

		select {
		case <-turn.ready:
			// A phase may have appeared at the same instant this waiter became
			// owner. Re-read under c.mu before allowing prepare to run.
			c.mu.Lock()
			participant = c.participants[source]
			interrupted = participant != nil && c.mutationMustYieldLocked(source, mutation, participant, held)
			if interrupted {
				c.recordDormantFairnessLocked(source, participant, mutation, turn)
				turn.abandon()
				turn = nil
			}
			c.mu.Unlock()
			if interrupted {
				return nil, ErrVisibilityInterrupted
			}
			return turn, nil
		case <-changed:
			// Keep the same FIFO node. The next loop either proves it is still
			// eligible or removes it without delaying the queue head.
		case <-ctx.Done():
			turn.abandon()
			return nil, ctx.Err()
		}
	}
}

func fairnessQueueable(participant *visibilityParticipant, mutation MutationID) bool {
	return participant != nil &&
		participant.repair == NamespaceRepairCallbackSerializedPipelined &&
		mutation.SourcePhaseQueueable && mutation.FrontendOperationID != 0
}

func (c *VisibilityCoordinator) recordDormantFairnessLocked(source SessionID, participant *visibilityParticipant, mutation MutationID, turn *mutationOrderWaiter) {
	if !fairnessQueueable(participant, mutation) || participant.pending == nil {
		return
	}
	event := participant.pending.event
	if event.Initiator == source || event.Routes != nil {
		return
	}
	debt, exists := c.fairness[source]
	if exists && debt.active && c.cfg.Now().After(debt.deadline) {
		delete(c.fairness, source)
		exists = false
	}
	if exists {
		if debt.active || debt.sequence != event.Cursor.Sequence {
			return
		}
		debt.observed = true
		if debt.operationID == 0 {
			debt.operationID = mutation.FrontendOperationID
		}
		if turn != nil && turn.ordinal < debt.ordinal {
			debt.ordinal = turn.ordinal
		}
		c.fairness[source] = debt
		return
	}
	ordinal := c.order.reserveOrdinal()
	if turn != nil {
		ordinal = turn.ordinal
	}
	c.fairness[source] = mutationFairnessDebt{
		sequence:    event.Cursor.Sequence,
		ordinal:     ordinal,
		operationID: mutation.FrontendOperationID,
		observed:    true,
	}
}

func (c *VisibilityCoordinator) claimFairnessLocked(source SessionID, mutation MutationID, queueable bool) uint64 {
	if !queueable {
		return 0
	}
	debt, exists := c.fairness[source]
	if !exists || !debt.active {
		return 0
	}
	if c.cfg.Now().After(debt.deadline) {
		delete(c.fairness, source)
		return 0
	}
	if debt.operationID != 0 && debt.operationID == mutation.FrontendOperationID {
		return 0
	}
	delete(c.fairness, source)
	return debt.ordinal
}

// mutationMustYieldLocked reports the exact pending-repair dependency that a
// new mutation from source would close. Callback serialization is global for a
// peer event. For an own event, an absent queueability proof, zero on either
// side, and the initiating callback itself are deliberately fail-safe. Only a
// distinct pair of nonzero frontend operation IDs whose new request explicitly
// carries SourcePhaseQueueable can wait. That exception depends on the
// frontend's source-phase invariant stated on
// NamespaceRepairCallbackSerializedPipelined: without it, queueing a distinct
// mixed callback would make PREPARE wait for the publication of the callback
// parked behind PREPARE. Parent exclusivity is narrower: only a peer event with
// a namespace target in a parent this request is already holding can conflict.
//
// A deferred self-COMPLETE is exempt for Linux because the initiating VFS
// callback installs its own namespace result and the frontend issues no reverse
// name notification for it.
func (c *VisibilityCoordinator) mutationMustYieldLocked(source SessionID, mutation MutationID, participant *visibilityParticipant, held [][16]byte) bool {
	if participant == nil || participant.pending == nil {
		return false
	}
	switch participant.repair {
	case NamespaceRepairCallbackSerialized:
		return true
	case NamespaceRepairCallbackSerializedPipelined:
		pending := participant.pending.event
		if pending.Initiator != source {
			return true
		}
		return !mutation.SourcePhaseQueueable || mutation.FrontendOperationID == 0 ||
			pending.FrontendOperationID == 0 ||
			mutation.FrontendOperationID == pending.FrontendOperationID
	case NamespaceRepairParentExclusive:
		interrupt := participant.interrupt
		if interrupt == nil || participant.pending.event.Cursor != interrupt.cursor {
			return false
		}
		for _, parent := range held {
			if _, conflict := interrupt.parents[parent]; conflict {
				return true
			}
		}
	}
	return false
}

// recordSourceTargets indexes the coordinates the initiating mount just changed.
// It caches what it made, so the next mutation's audience has to contain it for
// exactly these coordinates.
func (c *VisibilityCoordinator) recordSourceTargets(source *visibilityParticipant, sets ...[]VisibilityTarget) {
	if source == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.participants[source.id] != source {
		return
	}
	for _, set := range sets {
		for _, target := range set {
			source.index.add(target.key())
		}
	}
}

// executeUncached is the profile every Linux-only deployment runs. It is not a
// fast path that skips checks: the same target validation runs, so a
// target-construction defect is just as visible here as it is under a strict
// mount. What it legitimately skips is the barrier, because there is no cache
// anywhere that could serve a stale name.
func (c *VisibilityCoordinator) executeUncached(prepare func() ([]VisibilityTarget, error), apply func() ([]VisibilityTarget, bool)) error {
	prepareTargets, err := prepare()
	if err != nil {
		return err
	}
	if err := validateVisibilityTargets(prepareTargets); err != nil {
		return &VisibilityBarrierError{Err: ErrVisibilityTargets}
	}
	completeTargets, changed := apply()
	if changed {
		if err := c.validateCompletion(completeTargets, prepareTargets); err != nil {
			return &VisibilityBarrierError{Applied: true, Err: err}
		}
	}
	return nil
}

// validateCompletion checks the two things that must hold of a post-apply
// target set, and poisons the epoch when either fails. Both are authority
// defects that no participant can cause: the mutation already reached XFS and
// the authority cannot describe what it did.
func (c *VisibilityCoordinator) validateCompletion(complete, prepared []VisibilityTarget) error {
	if err := validateVisibilityTargets(complete); err != nil {
		return c.poison(ErrVisibilityTargets)
	}
	// Fan-out chooses its audience from the PREPARE targets. A COMPLETE target
	// outside that set would be a repair instruction addressed to mounts that
	// were never asked to close publication for it, so it is an invariant
	// violation rather than a case to widen the audience for.
	if !visibilityTargetsCovered(complete, prepared) {
		return c.poison(fmt.Errorf("%w: completion named a coordinate prepare did not", ErrVisibilityTargets))
	}
	completeKeys := visibilityTargetKeySet(complete)
	for _, target := range complete {
		if target.Scope != VisibilityAttributes {
			continue
		}
		for _, preparedTarget := range prepared {
			if preparedTarget.Scope != VisibilityNamespace || preparedTarget.ParentIdentity != target.Identity {
				continue
			}
			if _, ok := completeKeys[string(preparedTarget.key())]; !ok {
				return c.poison(fmt.Errorf("%w: parent attributes completed without a prepared namespace dependency", ErrVisibilityTargets))
			}
		}
	}
	return nil
}

// openBarrier claims the sequence, publishes the coordinates this mutation is
// preparing to change, and chooses its audience - all in one critical section.
//
// The single step is what makes scoped fan-out sound. A strict read either
// recorded its coordinate before this point, in which case the audience
// contains it and PREPARE drains its old-value publication, or it did not, in
// which case it waits for apply and reads the value that replaced it. There is
// no third case.
func (c *VisibilityCoordinator) openBarrier(source SessionID, targets []VisibilityTarget, ticket *VisibilityEvent) (visibilityAudience, []*visibilityDelivery, error) {
	keys := visibilityTargetKeys(targets)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.poisoned != nil {
		return visibilityAudience{}, nil, c.poisoned
	}
	c.next++
	ticket.Cursor = VisibilityCursor{Sequence: c.next, Phase: VisibilityPrepare}
	ticket.Targets = cloneVisibilityTargets(targets)

	audience := visibilityAudience{targetKeys: make(map[SessionID]map[string]struct{})}
	allTargetKeys := visibilityTargetKeySet(targets)
	for id, p := range c.participants {
		if id == source {
			// The initiating mount is always in its own mutation's audience: it
			// owns the ticket exemption the frontend needs to keep its own
			// callback out of its own drain, and its local syscall can publish the
			// entire returned mutation footprint.
			audience.source = p
			audience.members = append(audience.members, p)
			audience.targetKeys[id] = allTargetKeys
			continue
		}
		matched := p.matchingTargetKeys(targets)
		if len(matched) != 0 {
			audience.members = append(audience.members, p)
			audience.targetKeys[id] = matched
		}
	}
	// A callback refused locally during peer PREPARE has no authority waiter
	// whose ordinal can be recovered. Take one shared off-list cut now, before
	// later mutation traffic can enqueue; exact peer COMPLETE feedback may
	// activate it. The cut is never a queue node and therefore never blocks.
	var fairnessCut uint64
	for _, p := range audience.members {
		if p.id == source || p.repair != NamespaceRepairCallbackSerializedPipelined {
			continue
		}
		if debt, exists := c.fairness[p.id]; exists {
			if debt.active && c.cfg.Now().After(debt.deadline) {
				delete(c.fairness, p.id)
			} else if debt.active {
				// Claims are impossible while this peer phase is pending. Carry
				// the one coalesced credit forward, preserving its earliest cut,
				// and restart the bounded claim window only on this sequence's
				// exact COMPLETE. This is not a second credit.
				debt.sequence = ticket.Cursor.Sequence
				debt.observed = true
				debt.active = false
				debt.deadline = time.Time{}
				c.fairness[p.id] = debt
				continue
			} else {
				continue
			}
		}
		if fairnessCut == 0 {
			fairnessCut = c.order.reserveOrdinal()
		}
		c.fairness[p.id] = mutationFairnessDebt{
			sequence: ticket.Cursor.Sequence,
			ordinal:  fairnessCut,
		}
	}

	state := &visibilityMutationState{
		keys:          make(map[string]struct{}, len(keys)),
		audience:      make(map[SessionID]*visibilityParticipant, len(audience.members)),
		projectedKeys: audience.targetKeys,
		cursor:        ticket.Cursor,
		done:          make(chan struct{}),
	}
	for _, key := range keys {
		state.keys[string(key)] = struct{}{}
	}
	for _, p := range audience.members {
		state.audience[p.id] = p
	}
	c.mutation = state
	deliveries, err := c.dispatchLocked(*ticket, audience, nil)
	if err != nil {
		return visibilityAudience{}, nil, err
	}
	return audience, deliveries, nil
}

// beginApply closes the old-value drain boundary after every PREPARE Ack. A
// compliant frontend still has publication admission closed, and from this
// point even an audience member must wait for XFS apply before reading one of
// the mutation's coordinates.
func (c *VisibilityCoordinator) beginApply() {
	c.mu.Lock()
	if c.mutation != nil {
		c.mutation.applying = true
	}
	c.mu.Unlock()
}

// closeBarrier releases the PREPARE/apply coordinate set. It is idempotent:
// Execute calls it as soon as apply returns and also defers it, so neither a
// pre-apply failure nor a post-apply repair wait can strand a reader.
func (c *VisibilityCoordinator) closeBarrier() {
	c.mu.Lock()
	state := c.mutation
	c.mutation = nil
	c.mu.Unlock()
	if state != nil {
		close(state.done)
	}
}

// Stabilize is the read-path half of scoped fan-out. It records what this
// operation is about to publish into a strict frontend's kernel cache, and
// orders it against the running mutation's PREPARE/apply boundary.
//
// On return the coordinates are in this mount's index and either no mutation
// owned them, apply has completed, or this participant's still-pending PREPARE
// covers their old-value publication. Everything read after that is therefore
// either post-mutation or drained before apply. Everything read *before* it is
// covered by nothing, so an operation whose coordinates are all known up front
// stabilizes first and ignores the reported wait.
//
// The wait here is bounded by the running mutation reaching XFS, never by the
// other mounts finishing their repairs. An already-covered PREPARE reader does
// not wait here at all: it finishes naturally and lets its frontend Ack. A
// non-audience reader waits because no PREPARE depends on it, and the state is
// released immediately after apply rather than after COMPLETE repair.
//
// An operation that can only learn a coordinate by reading - a lookup learns
// which inode a name resolves to - passes it here afterwards. A reported wait
// then means that read raced the mutation: the caller must discard it and try
// again.
func (c *VisibilityCoordinator) Stabilize(ctx context.Context, id SessionID, resolutions ...VisibilityResolution) (bool, error) {
	waited := false
	for {
		c.mu.Lock()
		p := c.participants[id]
		if p == nil {
			// Not a strict participant: this mount holds no cache the barrier
			// has to reason about.
			c.mu.Unlock()
			return waited, nil
		}
		state := c.mutation
		blocked := false
		prepareCoversEveryConflict := true
		if state != nil {
			projected := state.projectedKeys[id]
			for _, resolution := range resolutions {
				for _, key := range resolution.keys() {
					encoded := string(key)
					if _, conflict := state.keys[encoded]; !conflict {
						continue
					}
					blocked = true
					if _, covered := projected[encoded]; !covered {
						prepareCoversEveryConflict = false
					}
				}
			}
		}
		if blocked && prepareCoversEveryConflict && !state.applying && state.audience[id] == p &&
			p.pending != nil && p.pending.event.Cursor == state.cursor &&
			p.pending.event.Cursor.Phase == VisibilityPrepare {
			// This callback's every conflicting coordinate is covered by the
			// PREPARE actually delivered to this participant. Let it publish old
			// state; that exact scoped PREPARE cannot Ack until the frontend drains
			// the publication. A union-audience match on another target is not
			// sufficient and stays blocked through apply.
			blocked = false
		}
		if !blocked {
			for _, resolution := range resolutions {
				for _, key := range resolution.keys() {
					p.index.add(key)
				}
			}
			c.mu.Unlock()
			return waited, nil
		}
		done := state.done
		c.mu.Unlock()
		waited = true
		select {
		case <-done:
		case <-ctx.Done():
			return waited, ctx.Err()
		}
	}
}

// RecordResolvedName records that this mount resolved one binding in a parent.
func (c *VisibilityCoordinator) RecordResolvedName(id SessionID, parent [16]byte, name []byte) {
	if parent == ([16]byte{}) || len(name) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.participants[id]; p != nil {
		p.index.add(nameKey(parent, name))
	}
}

// RecordResolvedInode records that this mount resolved one inode's state.
func (c *VisibilityCoordinator) RecordResolvedInode(id SessionID, identity [16]byte) {
	if identity == ([16]byte{}) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.participants[id]; p != nil {
		p.index.add(inodeKey(identity))
	}
}

// waitDeferred drains the previous mutation's deferred source acknowledgment.
// Each entry is removed exactly once, on every outcome, so a failed wait cannot
// leave the queue describing an obligation that no longer exists.
func (c *VisibilityCoordinator) waitDeferred(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		if len(c.deferred) == 0 {
			c.mu.Unlock()
			return nil
		}
		delivery := c.deferred[0]
		c.mu.Unlock()
		err := c.awaitPhase(delivery)
		c.mu.Lock()
		if len(c.deferred) != 0 && c.deferred[0] == delivery {
			c.deferred = c.deferred[1:]
		}
		c.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (c *VisibilityCoordinator) deferSource(source *visibilityParticipant, event VisibilityEvent) error {
	if source == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.poisoned != nil {
		return c.poisoned
	}
	if c.participants[source.id] != source {
		// Fenced or cleanly detached during this mutation. Either way it has no
		// obligation left to defer.
		return nil
	}
	if source.pending != nil {
		return c.poisonLocked(errors.New("volumeserver: source already has an outstanding visibility event"))
	}
	delivery := c.newDeliveryLocked(source, event)
	c.deferred = append(c.deferred, delivery)
	return nil
}

func (c *VisibilityCoordinator) dispatch(event VisibilityEvent, audience visibilityAudience, exclude *visibilityParticipant) ([]*visibilityDelivery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dispatchLocked(event, audience, exclude)
}

func (c *VisibilityCoordinator) dispatchLocked(event VisibilityEvent, audience visibilityAudience, exclude *visibilityParticipant) ([]*visibilityDelivery, error) {
	if c.poisoned != nil {
		return nil, c.poisoned
	}
	deliveries := make([]*visibilityDelivery, 0, len(audience.members))
	for _, p := range audience.members {
		if p == exclude {
			continue
		}
		if c.participants[p.id] != p {
			// Fenced or cleanly detached since the audience was chosen. Its
			// obligation is already discharged.
			continue
		}
		if p.pending != nil {
			return nil, c.poisonLocked(errors.New("volumeserver: strict participant already has an outstanding event"))
		}
		deliveries = append(deliveries, c.newDeliveryLocked(p, audience.project(event, p.id)))
	}
	return deliveries, nil
}

// ReportBlocked is a parent-exclusive frontend proving that an exact cached-
// name repair would wait on a parent lock its own unanswered request holds.
// The report does not acknowledge COMPLETE and does not fence the mount. It
// installs a cursor-scoped interruption for the overlapping parent(s); queued
// operations then return definite pre-apply EINTR, release their kernel locks,
// and let this same participant repair and acknowledge normally.
//
// # The cycle it reports
//
// Mount B has a directory-mutating syscall in directory D. The Linux VFS holds
// D's i_rwsem for WRITE across the entire FUSE server round trip:
// do_unlinkat takes inode_lock_nested(dir, I_MUTEX_PARENT) at fs/namei.c:4389
// and releases it at :4407, spanning vfs_unlink at :4402; filename_create
// (mkdir/mknod/symlink/link/create) takes it at fs/namei.c:3895 and returns
// still holding it; do_renameat2 takes both parents through lock_rename at
// fs/namei.c:4975 (fs/namei.c:3066, :3030) and releases at :5046, spanning
// vfs_rename at :5040. The FUSE side of every one of those blocks in
// fuse_simple_request - fuse_unlink at fs/fuse/dir.c:982, fuse_rename_common at
// fs/fuse/dir.c:1014-1062 - so the write lock is held for the whole time this
// authority is deciding the operation.
//
// Mount A holds mutation order and its COMPLETE asks B to make a name in D
// unservable. The only kernel interface that does so is
// fuse_reverse_inval_entry, which takes inode_lock_nested(parent,
// I_MUTEX_PARENT) - down_write, include/linux/fs.h:837 - at fs/fuse/dir.c:1351
// and holds it to :1402. It is unconditional and blocking: the FUSE_EXPIRE_ONLY
// test is at fs/fuse/dir.c:1367, sixteen lines INSIDE the locked region, and
// grepping fs/fuse for inode_trylock in v6.8 returns nothing. So B's repair
// blocks on B's own syscall, B's syscall blocks on this authority, and this
// authority is blocked on B's repair. Closed.
//
// # The exact cycle break
//
// A's mutation still cannot return while B can serve the stale binding. The
// operation holding B's lock has not reached XFS, however, so the authority can
// answer that one operation definitively without releasing A's mutation order.
//
//  1. Holding D's lock does not stop B serving the name. RCU-walk resolves it
//     with no inode lock at all: lookup_fast's RCU branch (fs/namei.c:1617) and
//     __d_lookup_rcu (fs/dcache.c:2168) take none, and fuse_dentry_revalidate
//     returns 1 with no lock and no round trip while the entry timeout is
//     unexpired (fs/fuse/dir.c:262-273). A strict mount publishes a 60s entry
//     timeout, so this is the common path, not a corner.
//  2. Making it unservable therefore means reaching fuse_dentry_settime(entry,
//     0). That store itself needs only dentry->d_lock (fs/fuse/dir.c:65-84),
//     but the only interface that reaches it is fuse_reverse_inval_entry, which
//     has already taken the parent write lock by then (1). FUSE_EXPIRE_ONLY is
//     not an escape: it only skips d_invalidate at fs/fuse/dir.c:1368.
//     fuse_reverse_inval_inode (fs/fuse/inode.c:507-537) takes no parent lock
//     but only invalidates attributes and pages - it cannot unbind a name.
//     Verified unchanged on current master (fs/fuse/dir.c:1595).
//  3. B cannot repair before its own syscall is answered, and only this
//     authority can answer it. The blocked report wakes the exact queued
//     handler, which returns ErrVisibilityInterrupted before prepare/apply.
//     The resulting EINTR releases D without changing XFS; COMPLETE then runs
//     while A still owns mutation order.
//  4. A repair gate in B linearizes callback admission against its exact cache
//     plan. A callback admitted first is visible here as parked and gets the
//     pre-apply interruption; one arriving after the gate is refused locally.
//     There is therefore no parked-after-check gap.
//  5. Shrinking the audience on the argument that B's own parked mutation will
//     rebind the same name is not exact. It would let a read on B that starts
//     strictly after A's mutation returned still see the pre-A value, which is
//     the linearizability violation the barrier exists to prevent.
//
// The interruption scope remains active through Ack, so a transparent retry
// cannot recreate the cycle. The existing repair deadline is still the hard
// fallback: if the request cannot be answered or the kernel lock does not drain,
// the participant is fenced exactly as before.
//
// # Why the frontend declares it and this authority does not decide it
//
// The cycle needs two facts to be true at once: this mount has an unanswered
// namespace mutation in D, AND it actually holds a cached binding that this
// COMPLETE names in D. The frontend knows both from its callback and exact
// cache registries. This authority can enforce the first exactly once the
// request arrives, even when the visibility-lane report wins the network race
// and arrives first. It does NOT know the second. Its audience comes from
// the resolved-name index, which is a monotone filter chosen to have no false
// negatives and therefore plenty of false positives: a mount that once resolved
// anything in D is addressed by every later mutation in D, whether or not it
// still caches the name. Deciding the cycle from the first fact alone fences
// every mount that is merely busy in the same directory as another - which is
// an ordinary shared build tree, continuously.
//
// The frontend's cached-name registry and repair gate are exact, so the report
// carries the coordination inode(s) it actually has to notify. The authority
// maps those only through the pending event; a fabricated or stale parent is a
// cursor violation. Installing the scope does not require the ordinary RPC to
// have arrived first, which closes the visibility-lane/ordinary-lane race. A
// repeated report for the same cursor is idempotent.
func (c *VisibilityCoordinator) ReportBlocked(_ context.Context, id SessionID, cursor VisibilityCursor, parentKernelInos []uint64) error {
	c.mu.Lock()
	p := c.participants[id]
	if p == nil {
		c.mu.Unlock()
		return ErrSessionExpired
	}
	kernelInodes := make(map[uint64]struct{}, len(parentKernelInos))
	for _, inode := range parentKernelInos {
		kernelInodes[inode] = struct{}{}
	}
	// The report may have succeeded while its response was lost. If repair and
	// Ack completed before that response is retried, the exact same report must
	// stay idempotent rather than fence a healthy participant.
	if p.acked == cursor && cursor != (VisibilityCursor{}) {
		if p.reported != nil && p.reported.cursor == cursor && sameKernelParents(p.reported.kernelInodes, kernelInodes) {
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		c.Fence(id, ErrVisibilitySequence)
		return ErrVisibilitySequence
	}
	// A handler for an accepted COMPLETE can survive cancellation or reconnect
	// and arrive after later phases have advanced the participant. Such a stale
	// control replay must never mutate current state or fence the mount. Reports
	// are valid only for COMPLETE, so sequence order is sufficient here.
	if cursor.Phase == VisibilityComplete && cursor.Sequence < p.acked.Sequence {
		c.mu.Unlock()
		return nil
	}
	if p.pending == nil || p.pending.event.Cursor != cursor {
		c.mu.Unlock()
		c.Fence(id, ErrVisibilitySequence)
		return ErrVisibilitySequence
	}
	// A route declaration cannot be repaired in place. Its blocked report
	// retains the terminal meaning; ordinary namespace COMPLETE is the only
	// phase whose lock cycle a pre-apply interruption can resolve.
	event := p.pending.event
	if event.Routes != nil {
		c.mu.Unlock()
		c.Fence(id, ErrVisibilityBlocked)
		return ErrVisibilityBlocked
	}
	if event.Cursor.Phase != VisibilityComplete || p.repair != NamespaceRepairParentExclusive ||
		event.Initiator == id || len(parentKernelInos) == 0 {
		c.mu.Unlock()
		c.Fence(id, ErrVisibilitySequence)
		return ErrVisibilitySequence
	}
	parents := make(map[[16]byte]struct{}, len(parentKernelInos))
	for _, kernelIno := range parentKernelInos {
		matched := false
		for _, target := range event.Targets {
			if target.Scope == VisibilityNamespace && target.ParentKernelIno == kernelIno {
				parents[target.ParentIdentity] = struct{}{}
				matched = true
			}
		}
		if !matched {
			c.mu.Unlock()
			c.Fence(id, ErrVisibilitySequence)
			return ErrVisibilitySequence
		}
	}
	if p.interrupt != nil {
		if p.interrupt.cursor == cursor && sameVisibilityParents(p.interrupt.parents, parents) &&
			sameKernelParents(p.interrupt.kernelInodes, kernelInodes) {
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		c.Fence(id, ErrVisibilitySequence)
		return ErrVisibilitySequence
	}
	interruption := &visibilityInterruption{cursor: cursor, parents: parents, kernelInodes: kernelInodes}
	p.interrupt = interruption
	p.reported = interruption
	p.signalLocked()
	c.mu.Unlock()
	return nil
}

func sameVisibilityParents(left, right map[[16]byte]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for parent := range left {
		if _, ok := right[parent]; !ok {
			return false
		}
	}
	return true
}

func sameKernelParents(left, right map[uint64]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for parent := range left {
		if _, ok := right[parent]; !ok {
			return false
		}
	}
	return true
}

func (c *VisibilityCoordinator) newDeliveryLocked(p *visibilityParticipant, event VisibilityEvent) *visibilityDelivery {
	now := c.cfg.Now()
	delivery := &visibilityDelivery{
		participant: p.id, event: cloneVisibilityEvent(event), done: make(chan error, 1),
		created: now, deadline: now.Add(p.budget),
	}
	p.pending = delivery
	p.signalLocked()
	return delivery
}

func (c *VisibilityCoordinator) awaitAll(deliveries []*visibilityDelivery) error {
	// Deadlines are absolute and were taken at dispatch, so waiting on one
	// participant never extends another's budget.
	for _, delivery := range deliveries {
		if err := c.awaitPhase(delivery); err != nil {
			return err
		}
	}
	return nil
}

// awaitPhase waits for one mount to finish one phase, bounded by the repair
// budget that mount committed to. Expiry is not a timeout that gives up: it
// fences that one participant, which discharges its obligation, and the
// mutation continues for everyone else.
func (c *VisibilityCoordinator) awaitPhase(delivery *visibilityDelivery) error {
	// A deferred acknowledgment may already have arrived long after its
	// deadline. It arrived, so there is nothing to fence.
	select {
	case err := <-delivery.done:
		return err
	default:
	}
	timer := time.NewTimer(time.Until(delivery.deadline))
	defer timer.Stop()
	select {
	case err := <-delivery.done:
		return err
	case <-timer.C:
	}
	c.fence(delivery.participant, delivery, ErrVisibilityDeadline)
	// Fence preserves a pending delivery for one further repair-budget grace.
	// If another path already removed the participant, that path either finished
	// the delivery from verified absence or scheduled the same conservative
	// grace, so waiting on the delivery is still the single correct answer.
	return <-delivery.done
}

// Next returns the outstanding phase. after must be the exact last phase the
// caller observed Ack accept. A lost event response is redelivered because Ack,
// not Next, advances the durable-in-epoch participant cursor.
func (c *VisibilityCoordinator) Next(ctx context.Context, id SessionID, after VisibilityCursor) (VisibilityEvent, error) {
	for {
		c.mu.Lock()
		if c.poisoned != nil {
			err := c.poisoned
			c.mu.Unlock()
			return VisibilityEvent{}, err
		}
		p := c.participants[id]
		if p == nil {
			c.mu.Unlock()
			return VisibilityEvent{}, ErrSessionExpired
		}
		if p.acked != after {
			c.mu.Unlock()
			c.Fence(id, ErrVisibilitySequence)
			return VisibilityEvent{}, ErrVisibilitySequence
		}
		if p.pending != nil {
			event := cloneVisibilityEvent(p.pending.event)
			c.mu.Unlock()
			return event, nil
		}
		changed := p.changed
		terminal := p.terminal
		c.mu.Unlock()
		select {
		case <-changed:
		case <-terminal:
			c.Fence(id, ErrVisibilityLost)
			return VisibilityEvent{}, ErrVisibilityLost
		case <-ctx.Done():
			return VisibilityEvent{}, ctx.Err()
		}
	}
}

// Ack completes exactly the current phase. Repeating the last accepted Ack is
// idempotent, which lets a participant recover from a lost acknowledgment
// response without guessing whether the authority advanced its cursor.
func (c *VisibilityCoordinator) Ack(id SessionID, cursor VisibilityCursor) error {
	return c.AckWithContention(id, cursor, false)
}

// AckWithContention accepts the exact same safety acknowledgement as Ack and
// treats orderedAdmissionContended only as best-effort scheduling metadata. A
// false or inapplicable hint is ignored; a duplicate accepted Ack cannot mint a
// second turn. The hint never delays repair, changes errno, or acknowledges a
// phase that would otherwise be refused.
func (c *VisibilityCoordinator) AckWithContention(id SessionID, cursor VisibilityCursor, orderedAdmissionContended bool) error {
	c.mu.Lock()
	p := c.participants[id]
	if p == nil {
		c.mu.Unlock()
		return ErrSessionExpired
	}
	// The next phase may already be pending when the previous Ack response was
	// lost. Repeating the last accepted cursor is still idempotent. In particular,
	// do not process fairness metadata twice on a response-lost retry.
	if p.acked == cursor && cursor != (VisibilityCursor{}) {
		c.mu.Unlock()
		return nil
	}
	if p.pending == nil {
		c.mu.Unlock()
		c.Fence(id, ErrVisibilitySequence)
		return ErrVisibilitySequence
	}
	if p.pending.event.Cursor != cursor {
		c.mu.Unlock()
		c.Fence(id, ErrVisibilitySequence)
		return ErrVisibilitySequence
	}
	delivery := p.pending
	c.activateFairnessLocked(id, p, delivery.event, orderedAdmissionContended)
	p.pending = nil
	p.interrupt = nil
	p.acked = cursor
	p.signalLocked()
	c.mu.Unlock()
	delivery.finish(nil)
	return nil
}

func (c *VisibilityCoordinator) activateFairnessLocked(id SessionID, p *visibilityParticipant, event VisibilityEvent, orderedAdmissionContended bool) {
	if event.Cursor.Phase != VisibilityComplete || event.Initiator == id || event.Routes != nil ||
		p.repair != NamespaceRepairCallbackSerializedPipelined {
		return
	}
	now := c.cfg.Now()
	debt, exists := c.fairness[id]
	if !exists {
		// Feedback cannot reconstruct an earlier FIFO cut after the fact.
		return
	}
	if debt.active {
		if now.After(debt.deadline) {
			delete(c.fairness, id)
		}
		return
	}
	if debt.sequence != event.Cursor.Sequence {
		return
	}
	if !debt.observed && !orderedAdmissionContended {
		delete(c.fairness, id)
		return
	}
	window := mutationFairnessClaimWindow
	if p.budget < window {
		window = p.budget
	}
	debt.active = true
	debt.deadline = now.Add(window)
	c.fairness[id] = debt
}

func cloneVisibilityTargets(targets []VisibilityTarget) []VisibilityTarget {
	clone := make([]VisibilityTarget, len(targets))
	copy(clone, targets)
	for i := range clone {
		clone[i].Name = append([]byte(nil), targets[i].Name...)
		clone[i].RelatedIdentities = append([][16]byte(nil), targets[i].RelatedIdentities...)
	}
	return clone
}

func cloneVisibilityEvent(event VisibilityEvent) VisibilityEvent {
	event.Targets = cloneVisibilityTargets(event.Targets)
	event.Routes = event.Routes.clone()
	return event
}

func visibilityTargetKeys(targets []VisibilityTarget) [][]byte {
	keys := make([][]byte, 0, len(targets))
	for _, target := range targets {
		keys = append(keys, target.key())
	}
	return keys
}

func visibilityTargetKeySet(targets []VisibilityTarget) map[string]struct{} {
	keys := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		keys[string(target.key())] = struct{}{}
	}
	return keys
}

// visibilityTargetsCovered reports whether every completion coordinate was also
// prepared. Size is excluded deliberately: PREPARE names the coordinate, and
// the authoritative post-mutation EOF is only knowable afterwards.
func visibilityTargetsCovered(complete, prepared []VisibilityTarget) bool {
	covered := make(map[string]struct{}, len(prepared))
	for _, target := range prepared {
		covered[string(target.key())] = struct{}{}
	}
	for _, target := range complete {
		if _, ok := covered[string(target.key())]; !ok {
			return false
		}
	}
	return true
}

func validateVisibilityTargets(targets []VisibilityTarget) error {
	if len(targets) == 0 {
		return ErrVisibilityTargets
	}
	zero := [16]byte{}
	for _, target := range targets {
		switch target.Scope {
		case VisibilityNamespace:
			if target.ParentIdentity == zero || target.Identity != zero || target.Size != 0 || !legalVisibilityName(target.Name) {
				return ErrVisibilityTargets
			}
			postIsDependency := target.PostIdentity == zero
			for _, identity := range target.RelatedIdentities {
				if identity == zero {
					return ErrVisibilityTargets
				}
				postIsDependency = postIsDependency || identity == target.PostIdentity
			}
			if !postIsDependency {
				return ErrVisibilityTargets
			}
		case VisibilityData:
			if target.Identity == zero || target.ParentIdentity != zero || len(target.Name) != 0 || target.Size < 0 || target.PostIdentity != zero || len(target.RelatedIdentities) != 0 {
				return ErrVisibilityTargets
			}
		case VisibilityAttributes:
			if target.Identity == zero || target.ParentIdentity != zero || len(target.Name) != 0 || target.Size != 0 || target.PostIdentity != zero || len(target.RelatedIdentities) != 0 {
				return ErrVisibilityTargets
			}
		default:
			return ErrVisibilityTargets
		}
	}
	return nil
}

func legalVisibilityName(name []byte) bool {
	return len(name) != 0 && len(name) <= 255 && !bytes.Equal(name, []byte(".")) && !bytes.Equal(name, []byte("..")) &&
		!bytes.ContainsRune(name, '/') && !bytes.ContainsRune(name, 0)
}
