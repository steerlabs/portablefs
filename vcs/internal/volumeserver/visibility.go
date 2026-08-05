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
	// ErrVisibilityBlocked fences one participant whose repair of this COMPLETE
	// is provably unable to run: its own kernel holds the affected directory
	// exclusively for a mutation this authority has not ordered yet, and this
	// authority is the party that owes that answer. It is the same
	// participant-scoped outcome ErrVisibilityDeadline produces, reached
	// immediately from a proof instead of after the whole repair budget has
	// elapsed with the volume's mutation stream stopped. The proof, and why no
	// exact alternative exists, is at ReportBlocked.
	ErrVisibilityBlocked = errors.New("volumeserver: strict visibility participant cannot repair while its own unordered mutation holds the directory")
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
	// authority round trip. See ReportBlocked for the kernel citations.
	NamespaceRepairParentExclusive
	// NamespaceRepairIndependent means repair never waits on a lock this
	// mount's own unanswered operation can hold.
	NamespaceRepairIndependent
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
// must durably record verified kernel unmount/host fencing before the authority
// drops the mount's barrier obligation.
type DurableVisibilityMembership interface {
	Activate(SessionID) error
	Deactivate(SessionID) error
}

// MountAbsenceVerifier authenticates evidence that the exact kernel mount bound
// to a strict session is no longer capable of serving cache state. Syntax and a
// plausible timestamp are not proof: the frontend controls those bytes. A
// deployment without a verifier therefore cannot cleanly deactivate durable
// membership and must use external/operator fencing after the session ends.
type MountAbsenceVerifier interface {
	VerifyMountAbsence(SessionID, MountAbsenceProof) error
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
	Cursor           VisibilityCursor
	Initiator        SessionID
	MutationSlot     uint32
	MutationSequence uint64
	Targets          []VisibilityTarget
	// Routes is set on exactly the two phases of a routing-topology change, and
	// Targets is empty on those phases. The two are disjoint by construction.
	Routes *RoutesChange
}

// MountAbsenceProof is the evidence a strict frontend presents that its own
// kernel mount is gone. Observation is opaque to the authority: no authority
// can re-derive a remote kernel's mount table, and pretending otherwise is how
// the previous unconditional boolean came to exist. What the authority enforces
// is the ordering that makes the evidence mean something - see
// VisibilityCoordinator.CleanDetach.
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
	id       SessionID
	pending  *visibilityDelivery
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

func (p *visibilityParticipant) signalLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

// mayHold reports whether this mount could still be caching any of these
// coordinates. It is allowed to say yes about state the mount does not have
// (one wasted no-op acknowledgment) and never says no about state it does.
func (p *visibilityParticipant) mayHold(keys [][]byte) bool {
	for _, key := range keys {
		if p.index.contains(key) {
			return true
		}
	}
	return false
}

// visibilityAudience is the exact participant set one mutation's two phases
// address. It is chosen once, at PREPARE, so the mount whose publication
// admission was closed is always the mount that is later told to reopen it.
type visibilityAudience struct {
	members []*visibilityParticipant
	// source is the initiating mount when the initiator is itself strict. Its
	// COMPLETE is deferred rather than awaited, so it is tracked separately.
	source *visibilityParticipant
}

// VisibilityConfig is the complete construction input. It is a struct because
// every field is a safety property and none of them has a defensible default
// that a deployment should be allowed to inherit silently.
type VisibilityConfig struct {
	Prior      PriorEpochDisposition
	Membership DurableVisibilityMembership
	Fencer     SessionFencer
	// AbsenceVerifier is optional at construction so deployments without a host
	// attestation service can still serve conservatively. CleanDetach fails closed
	// while it is nil and leaves durable membership active.
	AbsenceVerifier MountAbsenceVerifier
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
	// serial gives cache-visible mutations one order while strict mounts exist.
	// It is a channel rather than a mutex so a caller that has been cancelled
	// can stop queueing for it, which is safe precisely because nothing has
	// happened yet at that point.
	serial chan struct{}

	cfg          VisibilityConfig
	startupReady bool

	mu           sync.Mutex
	participants map[SessionID]*visibilityParticipant
	deferred     []*visibilityDelivery
	next         uint64
	poisoned     error
	seed         uint64
	// inflight holds the exact coordinates the running mutation will change,
	// published before its audience is chosen. See Stabilize.
	inflight     map[string]struct{}
	inflightDone chan struct{}
	// parked counts, per session, the directories whose kernel lock that mount
	// is holding for a mutation this authority has accepted but not yet ordered.
	// It is what turns "this participant is not answering" into a proof rather
	// than a timeout. See ReportBlocked.
	parked map[SessionID]map[[16]byte]int
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
		cfg: cfg, serial: make(chan struct{}, 1),
		participants: make(map[SessionID]*visibilityParticipant),
		parked:       make(map[SessionID]map[[16]byte]int),
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
	case commitment.NamespaceRepair != NamespaceRepairParentExclusive && commitment.NamespaceRepair != NamespaceRepairIndependent:
		// There is no default here on purpose. Assuming "independent" would let
		// the authority wait out a proven cycle as though it were a slow lock;
		// assuming "parent-exclusive" would fence a mount that could have
		// repaired. Both are worse than refusing a mount that did not say.
		refusal = fmt.Errorf("%w: mount declared no namespace-repair model; a strict mount must state whether repairing a cached binding needs the parent directory exclusively",
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

// CleanDetach removes a participant that has proven its own kernel mount is
// gone. Verified absence is stronger than cache repair - there is no longer a
// mount that can serve the stale name - so a valid proof also discharges an
// outstanding barrier obligation.
//
// The proof is opaque, so what is checked is the ordering that makes it
// evidence rather than an assertion: the observation must postdate this mount's
// registration, must postdate the obligation it is discharging, and must not be
// dated in the future. An observation taken before the outstanding event was
// created says nothing about that event. A frontend with nothing to observe has
// no proof to send and must let its session die instead, which fences it.
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
	if c.cfg.AbsenceVerifier == nil {
		c.mu.Unlock()
		return fmt.Errorf("%w: no mount-absence verifier is configured", ErrVisibilityProof)
	}
	// Verification runs while the participant is still in the set and while the
	// current pending obligation cannot change. Verifiers must be bounded local
	// attestation checks and must not call back into the coordinator.
	if err := c.cfg.AbsenceVerifier.VerifyMountAbsence(id, proof); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrVisibilityProof, err)
	}
	delete(c.participants, id)
	delete(c.parked, id)
	pending := p.pending
	p.pending = nil
	p.signalLocked()
	close(p.left)
	c.mu.Unlock()
	// The mount is already proven absent, so nothing waits on the durable write.
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
	if reason == nil {
		reason = ErrVisibilityLost
	}
	c.mu.Lock()
	p := c.participants[id]
	if p == nil {
		c.mu.Unlock()
		return
	}
	delete(c.participants, id)
	delete(c.parked, id)
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

	select {
	case c.serial <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.serial }()

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
		Initiator:        source,
		MutationSlot:     mutation.Slot,
		MutationSequence: mutation.Sequence,
	}
	audience, deliveries, err := c.openBarrier(source, prepareTargets, &ticket)
	// The published in-flight set is released on every exit from here on,
	// including the one where opening the barrier itself failed: a reader
	// waiting on a coordinate must never outlive the mutation that claimed it.
	defer c.closeBarrier()
	if err != nil {
		return &VisibilityBarrierError{Err: err}
	}
	if err := c.awaitAll(deliveries); err != nil {
		return &VisibilityBarrierError{Err: err}
	}

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
	return nil
}

// openBarrier claims the sequence, publishes the coordinates this mutation is
// about to change, and chooses its audience - all in one critical section.
//
// The single step is what makes scoped fan-out sound. A strict read either
// recorded its coordinate before this point, in which case the audience
// contains it, or it did not, in which case it finds the coordinate in flight
// and waits for apply instead of caching a value about to be replaced - and
// then reads the value that replaced it. There is no third case.
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
	c.inflight = make(map[string]struct{}, len(keys))
	for _, key := range keys {
		c.inflight[string(key)] = struct{}{}
	}
	c.inflightDone = make(chan struct{})

	var audience visibilityAudience
	for id, p := range c.participants {
		if id == source {
			// The initiating mount is always in its own mutation's audience: it
			// owns the ticket exemption the frontend needs to keep its own
			// callback out of its own drain.
			audience.source = p
			audience.members = append(audience.members, p)
			continue
		}
		if p.mayHold(keys) {
			audience.members = append(audience.members, p)
		}
	}
	deliveries, err := c.dispatchLocked(*ticket, audience, nil)
	if err != nil {
		return visibilityAudience{}, nil, err
	}
	return audience, deliveries, nil
}

// closeBarrier releases the in-flight coordinate set. It is idempotent: Execute
// calls it as soon as apply returns and also defers it, so a path that fails
// before apply cannot leave a reader waiting on a mutation that never happened.
func (c *VisibilityCoordinator) closeBarrier() {
	c.mu.Lock()
	c.inflight = nil
	done := c.inflightDone
	c.inflightDone = nil
	c.mu.Unlock()
	if done != nil {
		close(done)
	}
}

// Stabilize is the read-path half of scoped fan-out. It records what this
// operation is about to publish into a strict frontend's kernel cache, and
// blocks while the running mutation already owns any of those coordinates.
//
// On return the coordinates are in this mount's index and were not in flight at
// the instant they were recorded. Everything read after that is therefore
// either post-mutation, or pre-mutation under a barrier this mount is part of -
// which is the ordinary guarantee. Everything read *before* it is covered by
// nothing, so an operation whose coordinates are all known up front stabilizes
// first and ignores the reported wait.
//
// The wait here is bounded by the running mutation reaching XFS, never by the
// other mounts finishing their repairs. That bound is not a latency choice: the
// caller is a syscall that is holding this directory's i_rwsem for read while it
// waits, and a repair needs that lock for write. See the release site in
// Execute.
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
		blocked := false
		for _, resolution := range resolutions {
			for _, key := range resolution.keys() {
				if _, conflict := c.inflight[string(key)]; conflict {
					blocked = true
					break
				}
			}
			if blocked {
				break
			}
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
		done := c.inflightDone
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
		deliveries = append(deliveries, c.newDeliveryLocked(p, event))
	}
	return deliveries, nil
}

// ReportBlocked is a strict frontend saying it cannot service the phase it is
// holding, because doing so would wait on a lock its own unanswered request to
// this authority holds. It fences that one participant immediately, which
// discharges its obligation and lets the mutation finish for everyone else.
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
// # Why there is no exact fix
//
// Exactness would require A's mutation not to return while B can still serve
// the stale binding, without unbounded blocking.
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
//  3. So B cannot repair before its own syscall is answered, and only this
//     authority can answer it. Reply-carried repair does not help: the repair
//     would ride on a reply that does not exist until B is granted order, and
//     granting B order means A releasing it mid-mutation.
//  4. Ordering cannot help either. The audience is fixed at PREPARE, and the
//     deadlock case is exactly the mount that parks AFTER that - an operation
//     that has not been submitted cannot be ordered first. And in the symmetric
//     case, two mounts each holding D and each caching the other's target name,
//     every ordering reproduces the cycle: whichever runs, its COMPLETE lands
//     on a peer that is parked holding D.
//  5. Shrinking the audience on the argument that B's own parked mutation will
//     rebind the same name is not exact. It would let a read on B that starts
//     strictly after A's mutation returned still see the pre-A value, which is
//     the linearizability violation the barrier exists to prevent.
//
// What is left is fencing or unbounded blocking, and unbounded blocking stops
// every healthy mount. So the bound is fencing - but it does not have to be
// paid for with the whole repair budget, which is the difference this call
// makes.
//
// # Why the frontend declares it and this authority does not decide it
//
// The cycle needs two facts to be true at once: this mount has an unanswered
// namespace mutation in D, AND it actually holds a cached binding that this
// COMPLETE names in D. This authority knows the first exactly, from the request
// bodies it is holding. It does NOT know the second. Its audience comes from
// the resolved-name index, which is a monotone filter chosen to have no false
// negatives and therefore plenty of false positives: a mount that once resolved
// anything in D is addressed by every later mutation in D, whether or not it
// still caches the name. Deciding the cycle from the first fact alone fences
// every mount that is merely busy in the same directory as another - which is
// an ordinary shared build tree, continuously.
//
// The frontend's cached-name registry is exact, and its own in-flight request
// table is exact, so the frontend is the only party that can evaluate the
// conjunction. It reports it; this authority verifies the half it can see and
// refuses a claim that half does not support, so a mount cannot use "blocked"
// to skip a repair it was able to perform.
func (c *VisibilityCoordinator) ReportBlocked(id SessionID, cursor VisibilityCursor) error {
	c.mu.Lock()
	p := c.participants[id]
	if p == nil {
		c.mu.Unlock()
		return ErrSessionExpired
	}
	// Exactly the cursor identity Ack enforces. A blocked report is an
	// acknowledgment that happens to end the session, so it may not be a way to
	// address a phase this participant is not holding.
	if p.pending == nil || p.pending.event.Cursor != cursor {
		c.mu.Unlock()
		c.Fence(id, ErrVisibilitySequence)
		return ErrVisibilitySequence
	}
	credible := c.blockedClaimIsCredibleLocked(p, p.pending.event)
	c.mu.Unlock()
	if !credible {
		// The mount says it is holding a directory this authority is not
		// holding a request for. Nothing about that is recoverable: either the
		// frontend is confused about its own kernel or it is trying to be
		// excused from a repair, and both are the same answer.
		c.Fence(id, ErrVisibilitySequence)
		return ErrVisibilitySequence
	}
	c.Fence(id, ErrVisibilityBlocked)
	return ErrVisibilityBlocked
}

// blockedClaimIsCredibleLocked checks the half of the cycle this authority can
// see: this mount has a namespace mutation waiting for order, in a directory
// this phase names. PREPARE is never credible - it closes a frontend-local
// publication gate and touches no kernel lock - and neither is a phase with no
// namespace target, because data and attribute repair is
// fuse_reverse_inval_inode, which takes no parent lock at all
// (fs/fuse/inode.c:507-537).
func (c *VisibilityCoordinator) blockedClaimIsCredibleLocked(p *visibilityParticipant, event VisibilityEvent) bool {
	if event.Cursor.Phase != VisibilityComplete || p.repair != NamespaceRepairParentExclusive {
		return false
	}
	held := c.parked[p.id]
	if len(held) == 0 {
		return false
	}
	if event.Routes != nil {
		// A routing change withdraws whole subtrees and a rule set may name any
		// of them, so any directory this mount is holding may be one whose
		// bindings it has to make unservable. There is no smaller set to check
		// the claim against.
		return true
	}
	for _, target := range event.Targets {
		if target.Scope != VisibilityNamespace {
			continue
		}
		if _, locked := held[target.ParentIdentity]; locked {
			return true
		}
	}
	return false
}

// EnterMutationOrder declares the directories whose kernel lock the submitting
// mount is holding for one mutation, for as long as that mutation is waiting
// for this authority. The returned function must be called exactly once when
// the mutation is no longer waiting.
//
// Nothing is ever fenced from this alone. It is one half of a cycle - the half
// this authority can see exactly, because it is holding the request bodies -
// and it exists to check the other half's claim, not to infer it. The other
// half is whether the mount actually caches a binding the phase names, which
// only the frontend knows: this authority's audience comes from a monotone
// filter with no false negatives and therefore many false positives, so
// "addressed by this event" and "has something to repair" are very different
// statements. See ReportBlocked.
//
// A mount that already holds mutation order is deliberately still counted. It
// changes nothing, because a COMPLETE can only be dispatched by whoever holds
// that order, and a mount is excluded from its own mutation's audience.
func (c *VisibilityCoordinator) EnterMutationOrder(id SessionID, directories ...[16]byte) func() {
	if len(directories) == 0 {
		return func() {}
	}
	c.mu.Lock()
	held := c.parked[id]
	if held == nil {
		held = make(map[[16]byte]int, len(directories))
		c.parked[id] = held
	}
	for _, directory := range directories {
		held[directory]++
	}
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			held := c.parked[id]
			if held == nil {
				return
			}
			for _, directory := range directories {
				if held[directory]--; held[directory] <= 0 {
					delete(held, directory)
				}
			}
			if len(held) == 0 {
				delete(c.parked, id)
			}
		})
	}
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
	c.Fence(delivery.participant, ErrVisibilityDeadline)
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
	c.mu.Lock()
	p := c.participants[id]
	if p == nil {
		c.mu.Unlock()
		return ErrSessionExpired
	}
	// The next phase may already be pending when the previous Ack response was
	// lost. Repeating the last accepted cursor is still idempotent.
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
	p.pending = nil
	p.acked = cursor
	p.signalLocked()
	c.mu.Unlock()
	delivery.finish(nil)
	return nil
}

func cloneVisibilityTargets(targets []VisibilityTarget) []VisibilityTarget {
	clone := make([]VisibilityTarget, len(targets))
	copy(clone, targets)
	for i := range clone {
		clone[i].Name = append([]byte(nil), targets[i].Name...)
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
		case VisibilityData:
			if target.Identity == zero || target.ParentIdentity != zero || len(target.Name) != 0 || target.Size < 0 {
				return ErrVisibilityTargets
			}
		case VisibilityAttributes:
			if target.Identity == zero || target.ParentIdentity != zero || len(target.Name) != 0 || target.Size != 0 {
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
