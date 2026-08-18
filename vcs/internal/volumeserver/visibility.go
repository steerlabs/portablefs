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

// VisibilityRetryError identifies the exact peer phase a Linux callback must
// wait behind. It covers both definite-preapply mutation handoff and a read
// which must withdraw before its participant can acknowledge PREPARE. Sequence
// is mandatory: DATA and CONTROL are independent transport lanes, so the
// frontend cannot infer which repair made the handoff necessary from arrival
// order.
type VisibilityRetryError struct {
	Sequence uint64
}

func (e *VisibilityRetryError) Error() string {
	return fmt.Sprintf("%v (visibility sequence %d)", ErrVisibilityRetry, e.Sequence)
}

func (e *VisibilityRetryError) Is(target error) bool {
	return target == ErrVisibilityRetry
}

func VisibilityRetrySequence(err error) (uint64, bool) {
	var retry *VisibilityRetryError
	if !errors.As(err, &retry) || retry.Sequence == 0 {
		return 0, false
	}
	return retry.Sequence, true
}

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
	// ErrCompatibilityWriterLease is a definite pre-apply refusal while an
	// active macOS 26 callback-serialized participant owns the volume's
	// compatibility writer lease. FSKit 26 cannot synchronously revoke every
	// peer cache shape, so allowing a second participant to mutate would make an
	// ordinary remote write capable of fencing the Mac mount. Reads remain
	// concurrent; unmounting the Mac participant releases this writer lease.
	ErrCompatibilityWriterLease = errors.New("volumeserver: macOS 26 compatibility mount is the active volume writer")
	// ErrVisibilityRetry is an internal, definite-preapply dependency for the
	// lockless Linux frontend. The authority releases the request's key set;
	// the frontend releases its source gate, completes the named peer repair,
	// and retries inside the same FUSE callback. Namespace repair does not need
	// the callback's parent i_rwsem, so no application-visible EINTR is needed.
	// Staged write bytes remain inert and reusable across this handoff.
	ErrVisibilityRetry = errors.New("volumeserver: mutation must retry after this participant's pending cache repair")
	// ErrVisibilityDependencyRefresh is returned only by a source-gated
	// authority PREPARE callback which revalidated a namespace binding under
	// its storage writer locks and found that the resolved identity changed.
	// The coordinator releases/requeues the old identity-key set, refreshes the
	// source gate, and invokes PREPARE again before any barrier or XFS apply.
	ErrVisibilityDependencyRefresh = errors.New("volumeserver: mutation dependencies changed during locked revalidation")
	// ErrSourcePublicationGate means a strict initiating frontend did not prove
	// the exact local publication cut required before mutation dispatch. It is a
	// participant protocol violation, not an authority-epoch defect.
	ErrSourcePublicationGate = errors.New("volumeserver: source publication gate is missing or malformed")
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

// CoherenceProfile is declared by a mount at attach time. Protocol 5 has one
// coherent mount contract; zero is invalid so an omitted or retired profile
// cannot accidentally enter the visibility runtime.
type CoherenceProfile uint8

const CoherenceStrict CoherenceProfile = 1

// NamespaceRepair is how a strict frontend's kernel makes one cached
// name->inode binding unservable. It is declared at attach and never inferred:
// the authority cannot observe a remote kernel, and the two answers have
// different provable properties.
type NamespaceRepair uint8

const (
	// NamespaceRepairUnspecified is refused. A strict mount that does not say
	// how it repairs has not agreed to the contract the barrier is built on.
	NamespaceRepairUnspecified NamespaceRepair = iota
	// NamespaceRepairParentExclusive is the retired stock-FUSE model. Protocol
	// 5 no longer admits it because its cycle break exposed synthetic EINTR to
	// ordinary applications. The value remains parseable only so an old client
	// receives an explicit commitment refusal instead of being misclassified.
	NamespaceRepairParentExclusive
	// NamespaceRepairIndependent means repair never waits on a lock this
	// mount's own unanswered operation can hold.
	NamespaceRepairIndependent
	// NamespaceRepairCallbackSerialized is the frozen macOS 26 v1 contract: any
	// unanswered mutation is interrupted while this participant owes a phase.
	NamespaceRepairCallbackSerialized
	// NamespaceRepairCallbackSerializedPipelined is the identity-aware macOS 26
	// v2 contract. Any unanswered visible mutation can occupy the framework
	// callback capacity repair needs, independent of cache coordinates. Every
	// mutation is interrupted while this participant owes a peer phase; a
	// nonzero callback identity exists only to preserve fair retry order after
	// that phase completes.
	NamespaceRepairCallbackSerializedPipelined
	// NamespaceRepairLocklessExpiration is the patched Linux contract. A strict
	// reverse namespace notification expires one binding under dcache locks and
	// never acquires the parent inode's i_rwsem, so repair can run while an
	// unanswered local namespace callback holds that semaphore.
	NamespaceRepairLocklessExpiration
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

const maxSourcePublicationTargets = 16

// SourcePublicationGate is the authority's stable-identity representation of
// the exact local publication cut an initiating frontend installed before it
// could dispatch a visible mutation. It contains no kernel inode/device facts:
// those are peer-repair coordinates, not portable frontend identities.
type SourcePublicationGate struct {
	Targets []SourcePublicationTarget
}

func (g SourcePublicationGate) hasNamespace() bool {
	for _, target := range g.Targets {
		if target.namespace() {
			return true
		}
	}
	return false
}

// SourcePublicationTarget is either one item coordinate (Identity) or one
// namespace coordinate (ParentIdentity+Name). BoundIdentities are resolved by
// the authority from the namespace's current binding; they are never supplied
// by the peer and exist only to make the pending-peer/source-request overlap
// test exact before the request can acquire its dependency set.
type SourcePublicationTarget struct {
	Identity        [16]byte
	ParentIdentity  [16]byte
	Name            []byte
	Attributes      bool
	Data            bool
	BoundAttributes bool
	BoundData       bool
	BoundIdentities [][16]byte
}

func (t SourcePublicationTarget) namespace() bool {
	return t.ParentIdentity != ([16]byte{})
}

func (g SourcePublicationGate) keys() map[string]struct{} {
	keys := make(map[string]struct{}, len(g.Targets)*2)
	for _, target := range g.Targets {
		if target.namespace() {
			keys[string(nameKey(target.ParentIdentity, target.Name))] = struct{}{}
			if target.BoundAttributes || target.BoundData {
				for _, identity := range target.BoundIdentities {
					keys[string(inodeKey(identity))] = struct{}{}
				}
			}
			continue
		}
		keys[string(inodeKey(target.Identity))] = struct{}{}
	}
	return keys
}

func (g SourcePublicationGate) overlaps(targets []VisibilityTarget) bool {
	for _, gateTarget := range g.Targets {
		for _, target := range targets {
			if gateTarget.namespace() {
				if target.Scope == VisibilityNamespace && target.ParentIdentity == gateTarget.ParentIdentity && bytes.Equal(target.Name, gateTarget.Name) {
					return true
				}
				// Until the ordinary response either returns the definitive bound
				// identity or proves no binding, the exact namespace lease is a
				// wildcard over item state of its requested scope. Cross-lane peer
				// PREPARE can arrive before that response, so restricting this test
				// to the authority's pre-binding would deadlock a queued create or
				// rename behind an item-only mutation of the new object. This
				// uncertainty is bounded to this one in-flight namespace lease.
				if target.Scope == VisibilityAttributes && gateTarget.BoundAttributes ||
					target.Scope == VisibilityData && (gateTarget.BoundAttributes || gateTarget.BoundData) {
					return true
				}
				continue
			}
			if target.Identity == gateTarget.Identity &&
				(target.Scope == VisibilityAttributes && gateTarget.Attributes ||
					target.Scope == VisibilityData && (gateTarget.Attributes || gateTarget.Data)) {
				return true
			}
		}
	}
	return false
}

func validateSourcePublicationGate(gate SourcePublicationGate) error {
	if len(gate.Targets) == 0 || len(gate.Targets) > maxSourcePublicationTargets {
		return ErrSourcePublicationGate
	}
	zero := [16]byte{}
	var prior *SourcePublicationTarget
	for index := range gate.Targets {
		target := &gate.Targets[index]
		switch {
		case target.namespace():
			if target.Identity != zero || !legalVisibilityName(target.Name) || target.Attributes || target.Data ||
				target.BoundData && !target.BoundAttributes || len(target.BoundIdentities) != 0 && !target.BoundAttributes {
				return ErrSourcePublicationGate
			}
			var priorIdentity [16]byte
			for relatedIndex, identity := range target.BoundIdentities {
				if identity == zero || relatedIndex != 0 && bytes.Compare(priorIdentity[:], identity[:]) >= 0 {
					return ErrSourcePublicationGate
				}
				priorIdentity = identity
			}
		case target.Identity != zero:
			if target.ParentIdentity != zero || len(target.Name) != 0 || !target.Attributes || target.BoundAttributes || target.BoundData || len(target.BoundIdentities) != 0 {
				return ErrSourcePublicationGate
			}
		default:
			return ErrSourcePublicationGate
		}
		if prior != nil && compareSourcePublicationTargets(*prior, *target) >= 0 {
			return ErrSourcePublicationGate
		}
		prior = target
	}
	return nil
}

// compareSourcePublicationTargets defines the one protocol order: item before
// namespace, then raw stable identity; namespace ties use raw name bytes.
func compareSourcePublicationTargets(left, right SourcePublicationTarget) int {
	leftNamespace, rightNamespace := left.namespace(), right.namespace()
	if leftNamespace != rightNamespace {
		if leftNamespace {
			return 1
		}
		return -1
	}
	if !leftNamespace {
		return bytes.Compare(left.Identity[:], right.Identity[:])
	}
	if compared := bytes.Compare(left.ParentIdentity[:], right.ParentIdentity[:]); compared != 0 {
		return compared
	}
	return bytes.Compare(left.Name, right.Name)
}

func sameSourcePublicationShape(left, right SourcePublicationGate) bool {
	if len(left.Targets) != len(right.Targets) {
		return false
	}
	for index := range left.Targets {
		a, b := left.Targets[index], right.Targets[index]
		if a.Identity != b.Identity || a.ParentIdentity != b.ParentIdentity || !bytes.Equal(a.Name, b.Name) ||
			a.Attributes != b.Attributes || a.Data != b.Data ||
			a.BoundAttributes != b.BoundAttributes || a.BoundData != b.BoundData {
			return false
		}
	}
	return true
}

func cloneSourcePublicationGate(gate SourcePublicationGate) SourcePublicationGate {
	cloned := SourcePublicationGate{Targets: make([]SourcePublicationTarget, len(gate.Targets))}
	for index, target := range gate.Targets {
		target.Name = bytes.Clone(target.Name)
		target.BoundIdentities = append([][16]byte(nil), target.BoundIdentities...)
		cloned.Targets[index] = target
	}
	return cloned
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
// content fingerprint remains private to that authority epoch.
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
	// CompatibilityWriter gives this participant sole visible-mutation
	// authority while it is active. Reads remain concurrent. It is assigned by
	// the trusted authority handler from either frozen macOS 26 repair profile,
	// not by an independent peer-controlled flag.
	CompatibilityWriter bool
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
	// barrier reserves this participant's single ordered CONTROL event lane
	// across both phases. A second disjoint mutation may run concurrently when
	// its audience differs, but cannot insert PREPARE between this barrier's
	// PREPARE and COMPLETE on the same participant.
	barrier uint64
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
	left                chan struct{}
	budget              time.Duration
	registered          time.Time
	index               *resolvedIndex
	repair              NamespaceRepair
	compatibilityWriter bool
}

type visibilityInterruption struct {
	cursor       VisibilityCursor
	parents      map[[16]byte]struct{}
	kernelInodes map[uint64]struct{}
}

// mutationFairnessDebt is an off-list, one-shot effective per-key FIFO
// position. A dormant debt is tied to the peer visibility sequence that forced
// an eligible later callback to leave. It becomes claimable only after that
// sequence's exact COMPLETE Ack. A wholly local frontend refusal activates the
// PREPARE-time cut at the same edge. Neither form owns dependency keys while
// unclaimed.
type mutationFairnessDebt struct {
	sequence           uint64
	ordinal            uint64
	operationID        uint64
	claimSameOperation bool
	// gate is the immutable authority-derived callback footprint which earned a
	// Linux retry. FrontendOperationID is not trusted by itself: a malformed
	// client must not reuse that number to turn one repair proof into admission
	// for a different namespace or inode mutation.
	gate     SourcePublicationGate
	observed bool
	active   bool
	deadline time.Time
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
	// source is deliberately absent because its pre-dispatch local gate is the
	// cache transition. A nil map is reserved for non-coordinate events such as
	// a routing change.
	targetKeys map[SessionID]map[string]struct{}
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

// visibilityMutationState is one read-side ordering boundary. Several states
// may coexist only when their dependency sets, and therefore their cached
// observation keys, are disjoint.
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

// visibilityLaneWaiter is one all-or-none reservation for participant CONTROL
// lanes. Tickets are assigned only after a mutation first blocks. An older
// waiter reserves every participant it needs while a later waiter may still
// pass when its audience is disjoint.
type visibilityLaneWaiter struct {
	ticket  uint64
	source  SessionID
	targets []VisibilityTarget
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
	// OnBarrier observes a successfully opened PREPARE through its terminal
	// COMPLETE acknowledgment (or bounded failure). It must be nonblocking and
	// safe for concurrent use.
	OnBarrier func(time.Duration, int)
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
	// sequencer grants complete stable-identity dependency sets. Conflicting
	// mutations retain FIFO order while disjoint mutations may keep independent
	// PREPARE/apply/COMPLETE barriers in flight.
	sequencer *mutationSequencer

	cfg          VisibilityConfig
	startupReady bool

	mu           sync.Mutex
	participants map[SessionID]*visibilityParticipant
	fairness     map[SessionID]mutationFairnessDebt
	next         uint64
	poisoned     error
	seed         uint64
	// mutations hold the independent PREPARE -> apply read boundaries. Every
	// access is under mu; the participant indexes and global sequence remain
	// protected by that same lock when several barriers run concurrently.
	mutations map[uint64]*visibilityMutationState
	// laneWaiters order all-or-none acquisition of participant CONTROL lanes.
	// laneChanged is the shared wake edge for ownership, reservation, and
	// participant-set changes.
	nextLaneTicket uint64
	laneWaiters    map[uint64]*visibilityLaneWaiter
	laneChanged    chan struct{}
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
		cfg: cfg, sequencer: newMutationSequencer(),
		participants: make(map[SessionID]*visibilityParticipant),
		fairness:     make(map[SessionID]mutationFairnessDebt),
		mutations:    make(map[uint64]*visibilityMutationState),
		laneWaiters:  make(map[uint64]*visibilityLaneWaiter),
		laneChanged:  make(chan struct{}),
		startupReady: cfg.Prior == PriorEpochStrictMountsFenced,
		seed:         binary.LittleEndian.Uint64(seed[:]),
	}, nil
}

// Register is the direct-test/protocol-4 active helper. Protocol 5 must pass
// its runtime CommitActivation callback to ActivateParticipant so visibility
// membership and runtime executability share one transaction boundary.
func (c *VisibilityCoordinator) Register(id SessionID, profile CoherenceProfile, terminal <-chan struct{}, commitment VisibilityCommitment) error {
	_, err := c.ActivateParticipant(id, profile, terminal, commitment, nil, func() {})
	return err
}

// ActivateParticipant makes one prepared runtime session executable at the
// same boundary where a strict mount becomes a cache-coherence participant.
// The resolved index is allocated before global exclusion. While registration
// is write-locked, durable membership is persisted, the participant and exact
// initial cursor are installed, and commit publishes the runtime ACTIVE state.
// Therefore a mutation sees either neither fact or both facts, never an active
// filesystem client omitted from its visibility audience.
//
// precommit and commit run without c.mu but under registration exclusion.
// precommit receives the exact initial cursor and returns inode identities that
// its fallible resource/reply preparation freshly resolved. The coordinator
// installs those identities in the participant's index before commit, so the
// first operation an ACTIVE mount can issue is already covered by visibility.
// A precommit failure must not have made externally visible state changes; that
// path rolls back the participant and durable record before the caller releases
// its runtime activation token. commit has no error result: protocol 5 passes
// Authority.CommitActivation, whose prepared token makes the transition
// infallible. This type split prevents an active runtime from ever being rolled
// back out of membership. If durable rollback itself fails, the coordinator is
// poisoned and the conservative membership record remains for restart proof.
func (c *VisibilityCoordinator) ActivateParticipant(
	id SessionID,
	profile CoherenceProfile,
	terminal <-chan struct{},
	commitment VisibilityCommitment,
	precommit func(VisibilityCursor) ([][16]byte, error),
	commit func(),
) (VisibilityCursor, error) {
	if commit == nil {
		return VisibilityCursor{}, errors.New("volumeserver: visibility activation needs a runtime commit")
	}
	if profile != CoherenceStrict || terminal == nil {
		return VisibilityCursor{}, ErrVisibilityProfile
	}
	// A zero session ID is rejected here rather than assumed absent. The
	// audience machinery distinguishes the initiating mount by pointer identity
	// and never by a sentinel ID, but durable membership records session IDs
	// verbatim and a zero record is meaningless, so the invariant is stated
	// once, at the only place a participant can enter the set.
	if id == (SessionID{}) {
		return VisibilityCursor{}, ErrVisibilityProfile
	}
	if err := c.admitCommitment(id, commitment); err != nil {
		return VisibilityCursor{}, err
	}
	// This is the only sizeable allocation in activation. It must not extend the
	// critical section that excludes every visible mutation.
	index := newResolvedIndex(commitment.CachedNameCapacity, c.seed^sessionSeed(id))
	c.registration.Lock()
	defer c.registration.Unlock()
	c.mu.Lock()
	if !c.startupReady {
		c.mu.Unlock()
		return VisibilityCursor{}, ErrVisibilityStartup
	}
	if c.poisoned != nil {
		err := c.poisoned
		c.mu.Unlock()
		return VisibilityCursor{}, err
	}
	if _, exists := c.participants[id]; exists {
		c.mu.Unlock()
		return VisibilityCursor{}, ErrAdmission
	}
	if commitment.CompatibilityWriter {
		for _, participant := range c.participants {
			if participant.compatibilityWriter {
				c.mu.Unlock()
				return VisibilityCursor{}, ErrCompatibilityWriterLease
			}
		}
	}
	c.mu.Unlock()
	select {
	case <-terminal:
		return VisibilityCursor{}, ErrVisibilityLost
	default:
	}
	if err := c.cfg.Membership.Activate(id); err != nil {
		return VisibilityCursor{}, fmt.Errorf("record strict visibility participant: %w", err)
	}

	c.mu.Lock()
	// COMPLETE(1) is the epoch's explicit empty-history baseline. Protocol 5
	// never activates a participant with a nil cursor: doing so used to be
	// indistinguishable from the retired non-participant profile. The first
	// mutation therefore claims sequence 2, and every later attach starts from
	// the latest real COMPLETE cursor.
	if c.next == 0 {
		c.next = 1
	}
	initial := VisibilityCursor{Sequence: c.next, Phase: VisibilityComplete}
	p := &visibilityParticipant{
		id: id, terminal: terminal, acked: initial,
		changed: make(chan struct{}), left: make(chan struct{}),
		budget: commitment.RepairBudget, registered: c.cfg.Now(),
		index: index, repair: commitment.NamespaceRepair,
		compatibilityWriter: commitment.CompatibilityWriter,
	}
	c.participants[id] = p
	c.mu.Unlock()
	rollback := func(cause error) (VisibilityCursor, error) {
		c.mu.Lock()
		if c.participants[id] == p {
			delete(c.participants, id)
			delete(c.fairness, id)
			p.signalLocked()
			close(p.left)
		}
		c.mu.Unlock()
		if err := c.cfg.Membership.Deactivate(id); err != nil {
			rollbackErr := fmt.Errorf("roll back strict visibility participant: %w", err)
			poisoned := c.poison(errors.Join(cause, rollbackErr))
			return VisibilityCursor{}, errors.Join(cause, rollbackErr, poisoned)
		}
		return VisibilityCursor{}, cause
	}
	select {
	case <-terminal:
		return rollback(ErrVisibilityLost)
	default:
	}
	if precommit != nil {
		resolved, err := precommit(initial)
		if err != nil {
			return rollback(err)
		}
		c.mu.Lock()
		valid := c.participants[id] == p
		if valid {
			for _, identity := range resolved {
				if identity == ([16]byte{}) {
					valid = false
					break
				}
				p.index.add(inodeKey(identity))
			}
		}
		c.mu.Unlock()
		if !valid {
			return rollback(ErrVisibilityTargets)
		}
	}
	commit()
	go func() {
		select {
		case <-terminal:
			c.Fence(id, ErrVisibilityLost)
		case <-p.left:
			// Already out of the barrier set. Waiting on terminal from here
			// would keep this goroutine alive for the rest of the epoch.
		}
	}()
	return initial, nil
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
		commitment.NamespaceRepair != NamespaceRepairCallbackSerializedPipelined &&
		commitment.NamespaceRepair != NamespaceRepairLocklessExpiration:
		// There is no default here on purpose. Assuming "independent" would let
		// the authority wait out a proven cycle as though it were a slow lock;
		// assuming "parent-exclusive" would fence a mount that could have
		// repaired. Both are worse than refusing a mount that did not say.
		refusal = fmt.Errorf("%w: mount declared an unsupported namespace-repair model; a strict mount must state lockless-expiration, callback-serialized, callback-serialized-pipelined, or independent",
			ErrVisibilityProfile)
	case commitment.CompatibilityWriter &&
		commitment.NamespaceRepair != NamespaceRepairCallbackSerialized &&
		commitment.NamespaceRepair != NamespaceRepairCallbackSerializedPipelined:
		refusal = fmt.Errorf("%w: compatibility writer requires a callback-serialized macOS repair profile", ErrVisibilityProfile)
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
	c.signalLaneChangedLocked()
	close(p.left)
	c.mu.Unlock()
	// The authenticated supervisor has already made the mount terminal, so
	// nothing waits on the durable write.
	if pending != nil {
		pending.finish(nil)
	}
	if err := c.cfg.Membership.Deactivate(id); err != nil {
		// The record still names this mount, so a restarted epoch refuses to
		// serve until an operator proves the fencing. The participant has already
		// left this coordinator's barrier set, so the live authority session must
		// become terminal synchronously: otherwise it could keep issuing ordinary
		// filesystem requests while no longer participating in cache repair.
		c.cfg.Fencer.FenceSession(id)
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
	c.signalLaneChangedLocked()
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
	c.signalLaneChangedLocked()
	return c.poisoned
}

// DependencyDeclaration is a pre-resolution snapshot of the namespace
// bindings from which an authority handler will derive a mutation's full key
// set. It is opaque so callers cannot manufacture a claim that stale binding
// identities are current.
type DependencyDeclaration struct {
	snapshot *dependencySnapshot
}

// DeclareSourceGate must run before resolving the gate's current bindings.
// The later Execute call uses the snapshot to avoid a redundant uncontended
// lookup while still detecting every sequenced binding change in between.
func (c *VisibilityCoordinator) DeclareSourceGate(gate SourcePublicationGate) DependencyDeclaration {
	return DependencyDeclaration{snapshot: c.sequencer.snapshot(bindingDependenciesForSourceGate(gate))}
}

// Release discards a declaration that will not be passed to Execute. Execute
// also calls it, so a handler may defer Release immediately after declaration
// without coordinating the success path.
func (d DependencyDeclaration) Release() {
	d.snapshot.release()
}

// Execute is the authority-derived/test entry point for a cache-visible
// mutation without a protocol-5 source gate. dependencies must be the complete
// stable-identity footprint declared before entry. Protocol-5 filesystem
// mutations use ExecuteWithSourceGate so namespace identities can be
// revalidated.
//
// ctx bounds only dependency-key queueing. Once a peer phase has been
// delivered, a mount is holding publication admission closed and only its own
// acknowledgment or fencing can reopen it, so caller cancellation cannot end
// that wait. What bounds it instead is the per-participant repair budget.
func (c *VisibilityCoordinator) Execute(ctx context.Context, source SessionID, mutation MutationID, dependencies MutationDependencies,
	prepare func() ([]VisibilityTarget, error), apply func() ([]VisibilityTarget, bool)) error {
	return c.execute(ctx, source, mutation, dependencies, DependencyDeclaration{}, nil, nil, nil, prepare,
		func(uint64) ([]VisibilityTarget, bool) { return apply() }, nil)
}

// ExecuteWithHeldParents is Execute for a namespace callback whose kernel holds
// the listed parent directories until this authority answers. The declaration
// is scoped only to this exact request, so one concurrent request in D1 can
// never spuriously interrupt another request from the same mount in D2.
func (c *VisibilityCoordinator) ExecuteWithHeldParents(ctx context.Context, source SessionID, mutation MutationID, dependencies MutationDependencies,
	held [][16]byte, prepare func() ([]VisibilityTarget, error), apply func() ([]VisibilityTarget, bool)) error {
	return c.execute(ctx, source, mutation, dependencies, DependencyDeclaration{}, nil, held, nil, prepare,
		func(uint64) ([]VisibilityTarget, bool) { return apply() }, nil)
}

// ExecuteWithSourceGate is the production protocol-5 entry point. gate is the
// initiating frontend's pre-dispatch local publication cut. published runs
// immediately after apply, while the dependency set is still held, and returns any
// exact identities the ordinary response can publish but PREPARE could not know
// (most importantly a newly created item).
func (c *VisibilityCoordinator) ExecuteWithSourceGate(ctx context.Context, source SessionID, mutation MutationID,
	declaration DependencyDeclaration, gate SourcePublicationGate, refresh func() (SourcePublicationGate, error),
	prepare func() ([]VisibilityTarget, error), apply func() ([]VisibilityTarget, bool),
	published func() ([]VisibilityResolution, error)) error {
	return c.execute(ctx, source, mutation, mutationDependenciesForSourceGate(gate), declaration, &gate, nil, refresh, prepare,
		func(uint64) ([]VisibilityTarget, bool) { return apply() }, published)
}

// ExecuteWithSourceGateAndHeldParents additionally carries the exact Linux
// parent locks held across this authority call. It retains the existing
// parent-exclusive cycle break while source-gate overlap handles the earlier
// PREPARE/source-request dependency.
func (c *VisibilityCoordinator) ExecuteWithSourceGateAndHeldParents(ctx context.Context, source SessionID, mutation MutationID,
	declaration DependencyDeclaration, gate SourcePublicationGate, held [][16]byte, refresh func() (SourcePublicationGate, error), prepare func() ([]VisibilityTarget, error),
	apply func() ([]VisibilityTarget, bool), published func() ([]VisibilityResolution, error)) error {
	return c.execute(ctx, source, mutation, mutationDependenciesForSourceGate(gate), declaration, &gate, held, refresh, prepare,
		func(uint64) ([]VisibilityTarget, bool) { return apply() }, published)
}

// ExecuteWithSourceGateSequence returns the visibility order chosen by the
// coordinator. Transactional writes and range mutations use it so the source
// kernel's exact publication and every peer COMPLETE compare one
// authority-issued sequence. Lockless Linux namespace repair needs no separate
// parent-lock declaration: the exact source gate is the complete footprint.
func (c *VisibilityCoordinator) ExecuteWithSourceGateSequence(ctx context.Context, source SessionID, mutation MutationID,
	declaration DependencyDeclaration, gate SourcePublicationGate, refresh func() (SourcePublicationGate, error), prepare func() ([]VisibilityTarget, error),
	apply func(uint64) ([]VisibilityTarget, bool), published func() ([]VisibilityResolution, error)) (uint64, error) {
	var sequence uint64
	err := c.execute(ctx, source, mutation, mutationDependenciesForSourceGate(gate), declaration, &gate, nil, refresh, prepare, func(chosen uint64) ([]VisibilityTarget, bool) {
		sequence = chosen
		return apply(chosen)
	}, published)
	return sequence, err
}

// ExecuteWithSourceGateAndHeldParentsSequence is retained for the coordinator's
// retired parent-exclusive model tests. No protocol-5 Attach can select that
// profile, and production Linux uses ExecuteWithSourceGateSequence above.
func (c *VisibilityCoordinator) ExecuteWithSourceGateAndHeldParentsSequence(ctx context.Context, source SessionID, mutation MutationID,
	declaration DependencyDeclaration, gate SourcePublicationGate, held [][16]byte, refresh func() (SourcePublicationGate, error), prepare func() ([]VisibilityTarget, error),
	apply func(uint64) ([]VisibilityTarget, bool), published func() ([]VisibilityResolution, error)) (uint64, error) {
	var sequence uint64
	err := c.execute(ctx, source, mutation, mutationDependenciesForSourceGate(gate), declaration, &gate, held, refresh, prepare, func(chosen uint64) ([]VisibilityTarget, bool) {
		sequence = chosen
		return apply(chosen)
	}, published)
	return sequence, err
}

func (c *VisibilityCoordinator) execute(ctx context.Context, source SessionID, mutation MutationID,
	dependencies MutationDependencies, declaration DependencyDeclaration,
	gate *SourcePublicationGate, held [][16]byte, refresh func() (SourcePublicationGate, error), prepare func() ([]VisibilityTarget, error),
	apply func(uint64) ([]VisibilityTarget, bool), published func() ([]VisibilityResolution, error)) error {
	if ctx == nil || prepare == nil || apply == nil {
		return errors.New("volumeserver: visibility context, prepare, and mutation callbacks are required")
	}
	if gate != nil {
		defer declaration.Release()
		if err := validateSourcePublicationGate(*gate); err != nil {
			return err
		}
		if !declaration.validFor(*gate, c.sequencer) {
			return ErrSourcePublicationGate
		}
		if refresh == nil || published == nil {
			return errors.New("volumeserver: source-gated mutation requires refresh and publication callbacks")
		}
	}
	c.registration.RLock()
	defer c.registration.RUnlock()
	c.mu.Lock()
	strict := len(c.participants) != 0
	sourceStrict := c.participants[source] != nil
	compatibilityWriterBlocked := false
	for id, participant := range c.participants {
		if id != source && participant.compatibilityWriter {
			compatibilityWriterBlocked = true
			break
		}
	}
	ready, poisoned := c.startupReady, c.poisoned
	c.mu.Unlock()
	if !ready {
		return &VisibilityBarrierError{Err: ErrVisibilityStartup}
	}
	if poisoned != nil {
		return &VisibilityBarrierError{Err: poisoned}
	}
	if sourceStrict && gate == nil {
		return &VisibilityBarrierError{Err: ErrSourcePublicationGate}
	}
	if compatibilityWriterBlocked {
		// This check precedes dependency admission and every prepare/apply callback.
		// EBUSY is therefore a retryable product-policy result, not an uncertain
		// mutation and not a coherence failure. The Mac may continue serving.
		return ErrCompatibilityWriterLease
	}
	if !strict {
		// An ACTIVE protocol-5 filesystem session is installed in this map in
		// the same activation transaction that makes its runtime executable.
		// Reaching a visible mutation with no participant therefore means the
		// one coherent mount contract was bypassed; applying without a barrier
		// would recreate the retired uncached publication race.
		return &VisibilityBarrierError{Err: ErrVisibilityProfile}
	}
	if !dependencies.valid() {
		return &VisibilityBarrierError{Err: ErrVisibilityTargets}
	}

	turn, err := c.acquireMutationDependencies(ctx, source, mutation, held, gate, dependencies, nil)
	if err != nil {
		return err
	}
	defer turn.settle()
	if gate != nil {
		// The handler captured binding versions before resolving the identities in
		// gate. An unchanged snapshot proves the uncontended resolution is still
		// current. Otherwise refresh while the structural parent/name keys are held,
		// then atomically requeue at the same ordinal if the bound inode set changed.
		// A previously reserved fairness credit can have an older ordinal and pass
		// during that requeue, so every reacquisition refreshes again. There are only
		// finitely many older ordinals, and later binding traffic cannot pass the
		// retained reservation, which makes this loop starvation-free.
		if !c.sequencer.unchanged(declaration.snapshot) {
			for {
				refreshed, refreshErr := refresh()
				if refreshErr != nil {
					return refreshErr
				}
				if validateSourcePublicationGate(refreshed) != nil || !sameSourcePublicationShape(*gate, refreshed) {
					return ErrSourcePublicationGate
				}
				refreshedDependencies := mutationDependenciesForSourceGate(refreshed)
				gate = &refreshed
				if dependencies.equal(refreshedDependencies) {
					break
				}
				turn.requeue(refreshedDependencies)
				turn, err = c.acquireMutationDependencies(ctx, source, mutation, held, &refreshed, refreshedDependencies, turn)
				if err != nil {
					return err
				}
				dependencies = refreshedDependencies
			}
		}
		// Re-read the exact pending phase under the same lock used by delivery
		// after final key acquisition and before any prepare/apply work.
		c.mu.Lock()
		participant := c.participants[source]
		yieldErr := error(nil)
		if participant != nil {
			yieldErr = c.mutationYieldErrorLocked(source, mutation, participant, held, gate)
		}
		if yieldErr != nil {
			c.recordDormantFairnessLocked(source, participant, mutation, turn, gate)
		}
		c.mu.Unlock()
		if yieldErr != nil {
			return yieldErr
		}
	}

	var prepareTargets []VisibilityTarget
	for {
		prepareTargets, err = prepare()
		if !errors.Is(err, ErrVisibilityDependencyRefresh) {
			break
		}
		if gate == nil {
			return &VisibilityBarrierError{Err: ErrVisibilityTargets}
		}
		refreshed, refreshErr := refresh()
		if refreshErr != nil {
			return refreshErr
		}
		if validateSourcePublicationGate(refreshed) != nil || !sameSourcePublicationShape(*gate, refreshed) {
			return ErrSourcePublicationGate
		}
		refreshedDependencies := mutationDependenciesForSourceGate(refreshed)
		gate = &refreshed
		if !dependencies.equal(refreshedDependencies) {
			turn.requeue(refreshedDependencies)
			turn, err = c.acquireMutationDependencies(ctx, source, mutation, held, &refreshed, refreshedDependencies, turn)
			if err != nil {
				return err
			}
			dependencies = refreshedDependencies
		}
		// A requeue may have yielded the participant to a peer repair just as
		// the original acquisition did. Re-run the exact source-yield gate
		// before PREPARE touches storage again.
		c.mu.Lock()
		participant := c.participants[source]
		yieldErr := error(nil)
		if participant != nil {
			yieldErr = c.mutationYieldErrorLocked(source, mutation, participant, held, gate)
		}
		if yieldErr != nil {
			c.recordDormantFairnessLocked(source, participant, mutation, turn, gate)
		}
		c.mu.Unlock()
		if yieldErr != nil {
			return yieldErr
		}
	}
	if err != nil {
		return err
	}
	if err := validateVisibilityTargets(prepareTargets); err != nil {
		return &VisibilityBarrierError{Err: ErrVisibilityTargets}
	}
	if !dependencies.covers(prepareTargets) {
		return &VisibilityBarrierError{Err: ErrVisibilityTargets}
	}
	// prepare is the authority's independent derivation/validation boundary.
	// A refused or forged declaration must not pollute the source's monotone
	// history, so publish the validated gate only after prepare succeeds.
	if gate != nil {
		c.recordSourceGate(source, *gate)
	}

	ticket := VisibilityEvent{
		Initiator:           source,
		MutationSlot:        mutation.Slot,
		MutationSequence:    mutation.Sequence,
		FrontendOperationID: mutation.FrontendOperationID,
	}
	barrierStarted := c.cfg.Now()
	audience, deliveries, err := c.openBarrier(ctx, source, prepareTargets, &ticket)
	if ticket.Cursor.Sequence != 0 {
		// The coordinate state and participant-lane reservations are released on
		// every exit, including an invariant failure during initial dispatch.
		defer c.finishBarrier(ticket.Cursor.Sequence, audience)
		defer c.closeBarrier(ticket.Cursor.Sequence)
	}
	if err != nil {
		return &VisibilityBarrierError{Err: err}
	}
	defer c.observeBarrier(barrierStarted, len(audience.members))
	if err := c.awaitAll(deliveries); err != nil {
		return &VisibilityBarrierError{Err: err}
	}
	c.beginApply(ticket.Cursor.Sequence)

	completeTargets, changed := apply(ticket.Cursor.Sequence)
	if changed {
		if err := c.validateCompletion(completeTargets, prepareTargets); err != nil {
			return &VisibilityBarrierError{Applied: true, Err: err}
		}
	}
	if published != nil {
		resolutions, publicationErr := published()
		if publicationErr != nil || !validVisibilityResolutions(resolutions) {
			if publicationErr == nil {
				publicationErr = ErrVisibilityTargets
			}
			return &VisibilityBarrierError{Applied: true, Err: c.poison(publicationErr)}
		}
		c.recordSourceResolutions(source, resolutions)
	}
	if changed {
		// Completion targets are also coordinates the initiating callback may
		// publish through its ordinary result. Record them before the dependency
		// set can pass even when the response contains no Item message.
		c.recordSourceTargets(source, completeTargets)
	}
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
	// state, which is the new value, not the old one; a conflicting mutation
	// cannot have started because this operation still holds all dependency
	// keys; and COMPLETE is addressed to the mounts that cached the pre-mutation
	// value, which this reader by definition did not. A disjoint mutation may be
	// active, but by construction it cannot affect this observation.
	c.closeBarrier(ticket.Cursor.Sequence)
	ticket.Cursor.Phase = VisibilityComplete
	if changed {
		ticket.Targets = cloneVisibilityTargets(completeTargets)
	} else {
		ticket.Targets = nil
	}
	// Every non-source mount in this mutation's audience repairs before the
	// reply is released.
	complete, err := c.dispatch(ticket, audience, nil)
	if err != nil {
		return &VisibilityBarrierError{Applied: true, Err: err}
	}
	if err := c.awaitAll(complete); err != nil {
		return &VisibilityBarrierError{Applied: true, Err: err}
	}
	return nil
}

func (c *VisibilityCoordinator) observeBarrier(started time.Time, audience int) {
	if c.cfg.OnBarrier == nil {
		return
	}
	elapsed := c.cfg.Now().Sub(started)
	if elapsed < 0 {
		elapsed = 0
	}
	c.cfg.OnBarrier(elapsed, audience)
}

// acquireMutationDependencies waits for one atomic dependency set while
// honoring the frontend-declared progress constraints. Each caller keeps its
// per-key FIFO position across harmless participant-state changes. A pending
// repair can still remove a hazardous waiter from any queue position before
// prepare or apply, which is required for both FSKit callback capacity and
// Linux parent-lock cycle breaking.
//
// The post-grant check closes the edge where a phase and the dependency grant
// become visible together. Abandoning a waiter is safe even if the grant won
// that race: it releases the exact ownership before returning the
// definite-preapply result.
func (c *VisibilityCoordinator) acquireMutationDependencies(ctx context.Context, source SessionID, mutation MutationID,
	held [][16]byte, gate *SourcePublicationGate, dependencies MutationDependencies,
	waiter *mutationSequencerWaiter) (*mutationSequencerWaiter, error) {
	turn := waiter
	retryProofValidated := turn != nil
	for {
		c.mu.Lock()
		participant := c.participants[source]
		var changed <-chan struct{}
		var yieldErr error
		fairnessEligible := eligibleForFairness(participant, mutation, gate)
		if !retryProofValidated && mutation.VisibilityRetryAfterSequence != 0 {
			if !c.validVisibilityRetryProofLocked(source, participant, mutation, gate) {
				if turn != nil {
					turn.abandon()
				}
				c.mu.Unlock()
				return nil, ErrSourcePublicationGate
			}
			retryProofValidated = true
		} else if !retryProofValidated && c.visibilityRetryProofRequiredLocked(source, participant, mutation, gate) {
			if turn != nil {
				turn.abandon()
			}
			c.mu.Unlock()
			return nil, ErrSourcePublicationGate
		}
		if participant != nil {
			yieldErr = c.mutationYieldErrorLocked(source, mutation, participant, held, gate)
			if gate != nil || participant.repair == NamespaceRepairCallbackSerialized ||
				participant.repair == NamespaceRepairCallbackSerializedPipelined ||
				(participant.repair == NamespaceRepairParentExclusive && len(held) != 0) {
				changed = participant.changed
			}
		}
		if yieldErr != nil {
			c.recordDormantFairnessLocked(source, participant, mutation, turn, gate)
			if turn != nil {
				// Retire the exact node while c.mu still excludes COMPLETE Ack,
				// linearizing ordinal capture and removal before the debt can become
				// claimable by a later callback.
				turn.abandon()
				turn = nil
			}
		} else if turn == nil {
			reserved := c.claimFairnessLocked(source, mutation, fairnessEligible)
			turn = c.sequencer.enqueueFor(dependencies, reserved)
		}
		c.mu.Unlock()
		if yieldErr != nil {
			return nil, yieldErr
		}

		select {
		case <-turn.ready:
			// A phase may have appeared at the same instant this waiter became
			// owner. Re-read under c.mu before allowing prepare to run.
			c.mu.Lock()
			participant = c.participants[source]
			yieldErr = nil
			if participant != nil {
				yieldErr = c.mutationYieldErrorLocked(source, mutation, participant, held, gate)
			}
			if yieldErr != nil {
				c.recordDormantFairnessLocked(source, participant, mutation, turn, gate)
				turn.abandon()
				turn = nil
			}
			c.mu.Unlock()
			if yieldErr != nil {
				return nil, yieldErr
			}
			return turn, nil
		case <-changed:
			// Keep the same per-key FIFO node. The next loop either proves it is still
			// eligible or removes it without delaying the queue head.
		case <-ctx.Done():
			turn.abandon()
			return nil, ctx.Err()
		}
	}
}

func eligibleForFairness(participant *visibilityParticipant, mutation MutationID, gate *SourcePublicationGate) bool {
	if participant == nil || mutation.FrontendOperationID == 0 {
		return false
	}
	if participant.repair == NamespaceRepairCallbackSerializedPipelined {
		return true
	}
	return participant.repair == NamespaceRepairLocklessExpiration && gate != nil
}

func (c *VisibilityCoordinator) recordDormantFairnessLocked(source SessionID, participant *visibilityParticipant, mutation MutationID,
	turn *mutationSequencerWaiter, gate *SourcePublicationGate) {
	if !eligibleForFairness(participant, mutation, gate) || participant.pending == nil {
		return
	}
	event := participant.pending.event
	if event.Routes != nil {
		return
	}
	debt, exists := c.fairness[source]
	if exists && debt.active && c.cfg.Now().After(debt.deadline) {
		delete(c.fairness, source)
		exists = false
	}
	if exists {
		if debt.active {
			// A Linux retry can be overtaken only by work which already owned an
			// earlier FIFO position. If that work opens a second overlapping phase,
			// carry the same one-shot credit to the new sequence and preserve its
			// earliest ordinal. The frontend will repair that phase and return the
			// new proof; this is coalescing, never a second credit.
			if participant.repair == NamespaceRepairLocklessExpiration && debt.claimSameOperation &&
				debt.operationID == mutation.FrontendOperationID && gate != nil &&
				sameSourcePublicationShape(debt.gate, *gate) {
				debt.sequence = event.Cursor.Sequence
				debt.observed = true
				debt.active = false
				debt.deadline = time.Time{}
				if turn != nil && turn.ordinal < debt.ordinal {
					debt.ordinal = turn.ordinal
				}
				c.fairness[source] = debt
			}
			return
		}
		if debt.sequence != event.Cursor.Sequence {
			return
		}
		debt.observed = true
		if debt.operationID == 0 && participant.repair == NamespaceRepairCallbackSerializedPipelined {
			debt.operationID = mutation.FrontendOperationID
		}
		if turn != nil && turn.ordinal < debt.ordinal {
			debt.ordinal = turn.ordinal
		}
		c.fairness[source] = debt
		return
	}
	ordinal := c.sequencer.reserveOrdinal()
	if turn != nil {
		ordinal = turn.ordinal
	}
	debt = mutationFairnessDebt{
		sequence:           event.Cursor.Sequence,
		ordinal:            ordinal,
		operationID:        mutation.FrontendOperationID,
		claimSameOperation: participant.repair == NamespaceRepairLocklessExpiration,
		observed:           true,
	}
	if debt.claimSameOperation {
		debt.gate = cloneSourcePublicationGate(*gate)
	}
	c.fairness[source] = debt
}

func (c *VisibilityCoordinator) claimFairnessLocked(source SessionID, mutation MutationID, eligible bool) uint64 {
	if !eligible {
		return 0
	}
	debt, exists := c.fairness[source]
	if !exists {
		return 0
	}
	if debt.active && c.cfg.Now().After(debt.deadline) {
		delete(c.fairness, source)
		return 0
	}
	if debt.claimSameOperation {
		// Linux retries may claim a dormant credit before the CONTROL ACK
		// reaches the authority. The queue node then waits behind the barrier's
		// current owner and is already in its preserved FIFO position when that
		// owner releases. The exact proof is what makes claiming before activation
		// safe; an ordinary or forged request cannot take this branch.
		if mutation.VisibilityRetryAfterSequence != debt.sequence ||
			mutation.FrontendOperationID == 0 || mutation.FrontendOperationID != debt.operationID {
			return 0
		}
	} else if !debt.active {
		return 0
	}
	if debt.operationID != 0 && (debt.operationID == mutation.FrontendOperationID) != debt.claimSameOperation {
		return 0
	}
	delete(c.fairness, source)
	return debt.ordinal
}

// validVisibilityRetryProofLocked authenticates a cross-lane retry against the exact
// off-list debt created when this operation was previously refused. The proof
// is deliberately not a general assertion that a frontend is repaired: it is
// valid only for the same lockless Linux participant, callback identity,
// source gate, and authority sequence. The caller holds c.mu.
func (c *VisibilityCoordinator) validVisibilityRetryProofLocked(source SessionID, participant *visibilityParticipant,
	mutation MutationID, gate *SourcePublicationGate) bool {
	if mutation.VisibilityRetryAfterSequence == 0 || mutation.FrontendOperationID == 0 || participant == nil ||
		participant.repair != NamespaceRepairLocklessExpiration || gate == nil {
		return false
	}
	debt, exists := c.fairness[source]
	if exists && debt.active && c.cfg.Now().After(debt.deadline) {
		delete(c.fairness, source)
		return false
	}
	return exists && debt.observed && debt.claimSameOperation && debt.operationID == mutation.FrontendOperationID &&
		debt.sequence == mutation.VisibilityRetryAfterSequence && sameSourcePublicationShape(debt.gate, *gate)
}

// visibilityRetryProofRequiredLocked rejects a fresh mutation identity which tries
// to continue the exact Linux callback after receiving a retry but omits the
// sequence proof. Frontend operation IDs are unique for a strict mount, so an
// outstanding same-operation debt can only belong to this callback.
func (c *VisibilityCoordinator) visibilityRetryProofRequiredLocked(source SessionID, participant *visibilityParticipant,
	mutation MutationID, gate *SourcePublicationGate) bool {
	if mutation.FrontendOperationID == 0 || participant == nil || participant.repair != NamespaceRepairLocklessExpiration ||
		gate == nil {
		return false
	}
	debt, exists := c.fairness[source]
	if !exists || !debt.observed || !debt.claimSameOperation || debt.operationID != mutation.FrontendOperationID {
		return false
	}
	if debt.active && c.cfg.Now().After(debt.deadline) {
		delete(c.fairness, source)
		return false
	}
	return true
}

// mutationYieldErrorLocked reports the exact pending-repair dependency that a
// new mutation from source would close. Every filesystem phase is now a peer
// phase: the initiating frontend pre-closes its own footprint and receives no
// PREPARE/COMPLETE. If that footprint overlaps a pending peer phase, the peer
// may already be waiting for the source callback to publish; letting the same
// request wait for its dependency set would close a cycle, so it is refused
// definite-preapply. Callback serialization and Linux parent-lock conflicts
// retain their stronger platform-specific interruption rules.
func (c *VisibilityCoordinator) mutationYieldErrorLocked(source SessionID, mutation MutationID,
	participant *visibilityParticipant, held [][16]byte, gate *SourcePublicationGate) error {
	if participant == nil || participant.pending == nil {
		return nil
	}
	pending := participant.pending.event
	if pending.Routes == nil && gate != nil && gate.overlaps(pending.Targets) {
		if participant.repair == NamespaceRepairLocklessExpiration {
			// acquireMutationDependencies authenticated this proof against the exact
			// retained debt before it could claim/enqueue. Matching the still-pending
			// sequence is therefore safe to wait behind: local repair is complete,
			// and only its CONTROL-lane ACK remains. A different phase must produce a
			// fresh internal retry so the source gate can reopen for that repair.
			if mutation.VisibilityRetryAfterSequence == pending.Cursor.Sequence {
				return nil
			}
			return &VisibilityRetryError{Sequence: pending.Cursor.Sequence}
		}
		return ErrVisibilityInterrupted
	}
	switch participant.repair {
	case NamespaceRepairCallbackSerialized:
		return ErrVisibilityInterrupted
	case NamespaceRepairCallbackSerializedPipelined:
		return ErrVisibilityInterrupted
	case NamespaceRepairParentExclusive:
		interrupt := participant.interrupt
		if interrupt == nil || participant.pending.event.Cursor != interrupt.cursor {
			return nil
		}
		for _, parent := range held {
			if _, conflict := interrupt.parents[parent]; conflict {
				return ErrVisibilityInterrupted
			}
		}
	}
	return nil
}

// recordSourceGate publishes the frontend's pre-dispatch cut into the source
// participant's monotone audience index after authority PREPARE validation and
// before a conflicting dependency owner can pass.
func (c *VisibilityCoordinator) recordSourceGate(source SessionID, gate SourcePublicationGate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	participant := c.participants[source]
	if participant == nil {
		return
	}
	for key := range gate.keys() {
		participant.index.add([]byte(key))
	}
}

// recordSourceTargets indexes actual post-apply coordinates while the mutation
// still owns its dependency set. It supplements the potential declaration with
// identities that only XFS could determine.
func (c *VisibilityCoordinator) recordSourceTargets(source SessionID, targets []VisibilityTarget) {
	c.mu.Lock()
	defer c.mu.Unlock()
	participant := c.participants[source]
	if participant == nil {
		return
	}
	for _, target := range targets {
		participant.index.add(target.key())
	}
	for _, target := range targets {
		for _, identity := range target.RelatedIdentities {
			participant.index.add(inodeKey(identity))
		}
		if target.PostIdentity != ([16]byte{}) {
			participant.index.add(inodeKey(target.PostIdentity))
		}
	}
}

func validVisibilityResolutions(resolutions []VisibilityResolution) bool {
	for _, resolution := range resolutions {
		hasNamespace := resolution.Parent != ([16]byte{}) || len(resolution.Name) != 0
		if hasNamespace && (resolution.Parent == ([16]byte{}) || !legalVisibilityName(resolution.Name)) {
			return false
		}
		if !hasNamespace && resolution.Identity == ([16]byte{}) {
			return false
		}
	}
	return true
}

func (c *VisibilityCoordinator) recordSourceResolutions(source SessionID, resolutions []VisibilityResolution) {
	c.mu.Lock()
	defer c.mu.Unlock()
	participant := c.participants[source]
	if participant == nil {
		return
	}
	for _, resolution := range resolutions {
		for _, key := range resolution.keys() {
			participant.index.add(key)
		}
	}
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

func (c *VisibilityCoordinator) signalLaneChangedLocked() {
	close(c.laneChanged)
	c.laneChanged = make(chan struct{})
}

func (c *VisibilityCoordinator) newLaneWaiterLocked(source SessionID, targets []VisibilityTarget) *visibilityLaneWaiter {
	c.nextLaneTicket++
	if c.nextLaneTicket == 0 {
		panic("volumeserver: visibility lane ticket exhausted")
	}
	waiter := &visibilityLaneWaiter{
		ticket:  c.nextLaneTicket,
		source:  source,
		targets: cloneVisibilityTargets(targets),
	}
	c.laneWaiters[waiter.ticket] = waiter
	return waiter
}

func (c *VisibilityCoordinator) laneReservedByOlderLocked(participant *visibilityParticipant, waiter *visibilityLaneWaiter) bool {
	for _, candidate := range c.laneWaiters {
		if candidate == waiter || waiter != nil && candidate.ticket >= waiter.ticket {
			continue
		}
		// A participant's resolved index is monotone and may grow while an older
		// mutation waits. Project the older footprint against its current index
		// instead of freezing the first audience, or a newly interested lane could
		// be claimed by a younger barrier before the older waiter wakes.
		if participant.id != candidate.source && len(participant.matchingTargetKeys(candidate.targets)) != 0 {
			return true
		}
	}
	return false
}

func (c *VisibilityCoordinator) removeLaneWaiterLocked(waiter *visibilityLaneWaiter) {
	if waiter == nil || c.laneWaiters[waiter.ticket] != waiter {
		return
	}
	delete(c.laneWaiters, waiter.ticket)
	c.signalLaneChangedLocked()
}

// openBarrier claims the sequence, publishes the coordinates this mutation is
// preparing to change, and chooses its audience - all in one critical section.
//
// The single step is what makes scoped fan-out sound. A strict read either
// recorded its coordinate before this point, in which case the audience
// contains it and PREPARE drains its old-value publication, or it did not, in
// which case it waits for apply and reads the value that replaced it. There is
// no third case.
//
// Concurrent-barrier progress also relies on one production admission
// invariant outside this function: the authority handler forces
// CompatibilityWriter for both callback-serialized repair profiles. Execute
// then refuses every foreign mutation while such a participant is active. A
// callback-serialized mount can therefore never be asked to Ack one mutation
// while one of its own disjoint callbacks waits here for another participant's
// lane. The all-or-none lane tickets below do not replace that invariant; any
// future change which decouples those repair profiles from CompatibilityWriter
// must first supply a different cycle breaker.
func (c *VisibilityCoordinator) openBarrier(ctx context.Context, source SessionID, targets []VisibilityTarget, ticket *VisibilityEvent) (visibilityAudience, []*visibilityDelivery, error) {
	keys := visibilityTargetKeys(targets)
	var laneWaiter *visibilityLaneWaiter
	for {
		c.mu.Lock()
		if err := ctx.Err(); err != nil {
			c.removeLaneWaiterLocked(laneWaiter)
			c.mu.Unlock()
			return visibilityAudience{}, nil, err
		}
		if c.poisoned != nil {
			err := c.poisoned
			c.removeLaneWaiterLocked(laneWaiter)
			c.mu.Unlock()
			return visibilityAudience{}, nil, err
		}

		audience := visibilityAudience{targetKeys: make(map[SessionID]map[string]struct{})}
		for id, p := range c.participants {
			if id == source {
				// The initiating frontend closed and drained this footprint before
				// dispatch. It therefore receives neither filesystem phase.
				continue
			}
			matched := p.matchingTargetKeys(targets)
			if len(matched) == 0 {
				continue
			}
			audience.members = append(audience.members, p)
			audience.targetKeys[id] = matched
		}
		blocked := false
		for _, participant := range audience.members {
			if participant.barrier != 0 || c.laneReservedByOlderLocked(participant, laneWaiter) {
				blocked = true
				break
			}
		}
		if blocked {
			if laneWaiter == nil {
				laneWaiter = c.newLaneWaiterLocked(source, targets)
			}
			// A waiter owns no lane until it can claim its complete audience. Its
			// ticket nevertheless reserves every requested lane against later
			// overlapping waiters, so a multi-participant mutation cannot be
			// overtaken forever by alternating single-participant barriers.
			laneChanged := c.laneChanged
			c.mu.Unlock()
			select {
			case <-laneChanged:
			case <-ctx.Done():
				c.mu.Lock()
				c.removeLaneWaiterLocked(laneWaiter)
				c.mu.Unlock()
				return visibilityAudience{}, nil, ctx.Err()
			}
			continue
		}
		c.removeLaneWaiterLocked(laneWaiter)

		c.next++
		if c.next == 0 {
			c.mu.Unlock()
			panic("volumeserver: visibility sequence exhausted")
		}
		ticket.Cursor = VisibilityCursor{Sequence: c.next, Phase: VisibilityPrepare}
		ticket.Targets = cloneVisibilityTargets(targets)
		for _, p := range audience.members {
			p.barrier = ticket.Cursor.Sequence
		}

		// A callback refused locally during peer PREPARE has no authority waiter
		// whose ordinal can be recovered. Take one shared off-list cut now, before
		// later mutation traffic can enqueue; exact peer COMPLETE feedback may
		// activate it. The cut is never a queue node and therefore never blocks.
		var fairnessCut uint64
		for _, p := range audience.members {
			if p.repair != NamespaceRepairCallbackSerializedPipelined {
				continue
			}
			if debt, exists := c.fairness[p.id]; exists {
				if debt.active && c.cfg.Now().After(debt.deadline) {
					delete(c.fairness, p.id)
				} else if debt.active {
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
				fairnessCut = c.sequencer.reserveOrdinal()
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
		c.mutations[ticket.Cursor.Sequence] = state
		deliveries, err := c.dispatchLocked(*ticket, audience, nil)
		c.mu.Unlock()
		return audience, deliveries, err
	}
}

// beginApply closes the old-value drain boundary after every PREPARE Ack. A
// compliant frontend still has publication admission closed, and from this
// point even an audience member must wait for XFS apply before reading one of
// the mutation's coordinates.
func (c *VisibilityCoordinator) beginApply(sequence uint64) {
	c.mu.Lock()
	if state := c.mutations[sequence]; state != nil {
		state.applying = true
	}
	c.mu.Unlock()
}

// closeBarrier releases the PREPARE/apply coordinate set. It is idempotent:
// Execute calls it as soon as apply returns and also defers it, so neither a
// pre-apply failure nor a post-apply repair wait can strand a reader.
func (c *VisibilityCoordinator) closeBarrier(sequence uint64) {
	c.mu.Lock()
	state := c.mutations[sequence]
	delete(c.mutations, sequence)
	c.mu.Unlock()
	if state != nil {
		close(state.done)
	}
}

// finishBarrier releases participant CONTROL lanes only after COMPLETE has
// either been acknowledged or discharged by fencing. The dependency set stays
// owned until the caller returns, so a conflicting mutation still cannot open
// a later sequence first.
func (c *VisibilityCoordinator) finishBarrier(sequence uint64, audience visibilityAudience) {
	c.mu.Lock()
	defer c.mu.Unlock()
	released := false
	for _, p := range audience.members {
		if c.participants[p.id] != p {
			continue
		}
		if p.barrier != sequence {
			c.poisonLocked(errors.New("volumeserver: participant visibility barrier ownership changed"))
			continue
		}
		p.barrier = 0
		p.signalLocked()
		released = true
	}
	if released {
		c.signalLaneChangedLocked()
	}
}

// Stabilize is the read-path half of scoped fan-out. It records what this
// operation is about to publish into a strict frontend's kernel cache, and
// orders it against every running mutation's PREPARE/apply boundary.
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
// non-audience reader normally waits because no PREPARE depends on it, and the
// state is released immediately after apply rather than after COMPLETE repair.
// The exception is a participant already draining a different PREPARE. Parking
// that read on a concurrent barrier could make each mutation wait for the
// other's participant Ack. Stabilize instead reports a race without publishing
// the resolutions, so the callback unwinds, its frontend Acks, and the read is
// retried.
//
// An operation that can only learn a coordinate by reading - a lookup learns
// which inode a name resolves to - passes it here afterwards. A reported wait
// then means that read raced the mutation: the caller must discard it and try
// again.
func (c *VisibilityCoordinator) Stabilize(ctx context.Context, id SessionID, resolutions ...VisibilityResolution) (bool, error) {
	waited, _, err := c.StabilizeSequence(ctx, id, resolutions...)
	return waited, err
}

// StabilizeSequence returns the authority cursor from the same critical
// section that registers every supplied cache coordinate. A cacheable read
// samples after this return and stamps the result with that cursor.
func (c *VisibilityCoordinator) StabilizeSequence(ctx context.Context, id SessionID, resolutions ...VisibilityResolution) (bool, uint64, error) {
	waited := false
	for {
		c.mu.Lock()
		p := c.participants[id]
		if p == nil {
			// Not a strict participant: this mount holds no cache the barrier
			// has to reason about.
			c.mu.Unlock()
			return waited, 0, nil
		}
		var blocked *visibilityMutationState
		for _, state := range c.mutations {
			conflicts := false
			prepareCoversEveryConflict := true
			projected := state.projectedKeys[id]
			for _, resolution := range resolutions {
				for _, key := range resolution.keys() {
					encoded := string(key)
					if _, conflict := state.keys[encoded]; !conflict {
						continue
					}
					conflicts = true
					if _, covered := projected[encoded]; !covered {
						prepareCoversEveryConflict = false
					}
				}
			}
			if !conflicts {
				continue
			}
			if prepareCoversEveryConflict && !state.applying && state.audience[id] == p &&
				p.pending != nil && p.pending.event.Cursor == state.cursor &&
				p.pending.event.Cursor.Phase == VisibilityPrepare {
				// This callback's every conflicting coordinate is covered by the
				// PREPARE actually delivered to this participant. Let it publish old
				// state; that exact scoped PREPARE cannot Ack until the frontend drains
				// the publication. A union-audience match on another target is not
				// sufficient and stays blocked through apply.
				continue
			}
			blocked = state
			break
		}
		if blocked == nil {
			for _, resolution := range resolutions {
				for _, key := range resolution.keys() {
					p.index.add(key)
				}
			}
			sequence := c.next
			c.mu.Unlock()
			return waited, sequence, nil
		}
		if blocked.audience[id] != p && p.pending != nil && p.pending.event.Cursor.Phase == VisibilityPrepare {
			// Concurrent barriers cannot share a participant lane. This participant
			// is therefore draining a different PREPARE, and waiting for an
			// out-of-audience state would close a cross-mount Ack cycle. Do not add
			// any resolution to the monotone index: the caller must discard the read.
			sequence := p.pending.event.Cursor.Sequence
			c.mu.Unlock()
			return true, 0, &VisibilityRetryError{Sequence: sequence}
		}
		done := blocked.done
		c.mu.Unlock()
		waited = true
		select {
		case <-done:
		case <-ctx.Done():
			return waited, 0, ctx.Err()
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
// Mount A holds D's dependency keys and its COMPLETE asks B to make a name in D
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
// answer that one operation definitively without releasing A's dependency keys.
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
//     while A still owns D's dependency keys.
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
	// Deadlines are absolute and were taken at dispatch. Await every participant
	// from that same boundary: if several mounts miss it together, each fence and
	// each post-fence grace must advance independently. Serially entering
	// awaitPhase preserved the phase deadlines, but it made the additional grace
	// cumulative because the next expired participant was not fenced until the
	// previous participant's grace had elapsed.
	if len(deliveries) == 0 {
		return nil
	}
	if len(deliveries) == 1 {
		return c.awaitPhase(deliveries[0])
	}
	phaseErrors := make([]error, len(deliveries))
	var waits sync.WaitGroup
	waits.Add(len(deliveries))
	for index, delivery := range deliveries {
		go func() {
			defer waits.Done()
			phaseErrors[index] = c.awaitPhase(delivery)
		}()
	}
	waits.Wait()
	// Preserve the old slice-order error precedence: the first delivery whose
	// completion failed is the error the mutation reports.
	for _, err := range phaseErrors {
		if err != nil {
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
		p.repair != NamespaceRepairCallbackSerializedPipelined && p.repair != NamespaceRepairLocklessExpiration {
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
