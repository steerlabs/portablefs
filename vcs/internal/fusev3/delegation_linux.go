//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"google.golang.org/protobuf/proto"
)

// delegationRPC is deliberately smaller than RPC. It lets the write-back
// state machine be tested without reproducing the mount/session transport.
// DATA mutations use the replay-slot API; CONTROL acknowledgements and the
// barrier use their protocol-defined idempotent request path.
type delegationRPC interface {
	CallMutation(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallIdempotent(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
}

type delegationBinding struct {
	ref        *authoritypb.DelegationRef
	item       []byte
	generation uint64
}

type delegationState struct {
	acquire           sync.Mutex
	grantChanged      chan struct{}
	retiredGeneration uint64
	// transition serializes recall, break, mode changes, release, and grant
	// installation for one identity. No network operation holds manager.mu.
	transition sync.Mutex
	// operation orders frontend admissions and synchronous operations for one
	// file. An append or fallocate flushes the accepted prefix while holding it,
	// so no later local admission can overtake the wire mutation.
	operation sync.Mutex
	// admission closes the race between checking the mode and Buffer accepting
	// an entry. It is held only across local Buffer calls, never network I/O.
	admission sync.RWMutex
	controlMu sync.Mutex
	// controlTail orders CONTROL transitions in stream receipt order without
	// making the long-poll loop wait for a flush or acknowledgment.
	controlTail <-chan struct{}

	identity                            writeback.Identity
	ref                                 *authoritypb.DelegationRef
	mode                                authoritypb.DelegationMode
	item                                []byte
	handles                             map[string][]byte
	writers                             map[string][]byte
	bindings                            map[uint64]delegationBinding
	retire                              *writeback.Retirement
	base                                *authoritypb.Attr
	baseVersion, baseInvalidatedThrough uint64

	meta        sync.Mutex
	acceptedCut uint64
	appliedCut  uint64
	applied     uint64
	dirty       bool
}

type delegationAdmissionContextKey struct{}

type delegationFlushProgress struct {
	bytes    int
	sequence uint64
	complete bool
}

// delegationManager owns the epoch-scoped write buffer and delegation table.
// Its methods return ordinary errors so the raw FUSE layer can make the errno
// policy at the callback boundary.
type delegationManager struct {
	rpc      delegationRPC
	timeout  time.Duration
	maxWrite int

	epoch    sync.RWMutex
	frontend sync.RWMutex
	mu       sync.Mutex
	buf      *writeback.Buffer
	byID     map[writeback.Identity]*delegationState
	// identityLoss retains the latest loss ticket after an epoch-scoped Buffer
	// is replaced. Existing handles compare against it once; newly registered
	// handles start at the retained value.
	identityLoss map[writeback.Identity]uint64
	inc          uint64
	// epochSerial rejects server handles queued before an Authority epoch
	// replacement. It is protected by epoch rather than mu because it fences
	// network use of those capabilities with buffer replacement.
	epochSerial uint64

	ctx       context.Context
	cancel    context.CancelFunc
	controlWG sync.WaitGroup
	workerWG  sync.WaitGroup

	durabilityMu   sync.Mutex
	durableBuffer  *writeback.Buffer
	appliedHigh    uint64
	durableHigh    uint64
	durableKick    chan struct{}
	tokenMu        sync.Mutex
	tokens         map[uint64]delegationFlushProgress
	closeQueue     chan delegationClose
	closeMu        sync.Mutex
	closePending   int
	closeChanged   chan struct{}
	closeProducers sync.WaitGroup
	closeStopped   bool

	hookMu          sync.RWMutex
	withdrawalDrain func(context.Context, []byte) error
	acceptedWrite   func(context.Context, []byte, int64, int64) error
}

type delegationClose struct {
	identity    []byte
	handle      []byte
	lockOwner   uint64
	flockUnlock bool
	epoch       uint64
}

func newDelegationManager(rpc delegationRPC, timeout time.Duration, incarnation uint64, opts writeback.Options) (*delegationManager, error) {
	if rpc == nil || timeout <= 0 {
		return nil, errors.New("fusev3: delegation manager requires an authority and request timeout")
	}
	m := &delegationManager{
		rpc: rpc, timeout: timeout, byID: make(map[writeback.Identity]*delegationState), identityLoss: make(map[writeback.Identity]uint64), inc: incarnation, epochSerial: 1,
		maxWrite: writeback.MaxPayload, durableKick: make(chan struct{}, 1), tokens: make(map[uint64]delegationFlushProgress), closeQueue: make(chan delegationClose, 4096),
	}
	if limits, ok := rpc.(interface{ IOLimits() (uint32, uint32) }); ok {
		_, maxWrite := limits.IOLimits()
		if maxWrite != 0 && maxWrite < uint32(m.maxWrite) {
			m.maxWrite = int(maxWrite)
		}
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	b, err := writeback.New(m, opts)
	if err != nil {
		m.cancel()
		return nil, fmt.Errorf("fusev3: create delegation write buffer: %w", err)
	}
	m.buf = b
	m.durableBuffer = b
	m.workerWG.Add(1)
	go m.durabilityLoop()
	m.workerWG.Add(1)
	go m.closeLoop()
	return m, nil
}

func delegationIdentity(raw []byte) (writeback.Identity, error) {
	var id writeback.Identity
	if len(raw) != len(id) {
		return id, errors.New("fusev3: delegation identity must be 16 bytes")
	}
	copy(id[:], raw)
	if id == (writeback.Identity{}) {
		return id, errors.New("fusev3: delegation identity must be nonzero")
	}
	return id, nil
}

func cloneDelegationRef(ref *authoritypb.DelegationRef) *authoritypb.DelegationRef {
	if ref == nil {
		return nil
	}
	return &authoritypb.DelegationRef{Id: cloneBytes(ref.GetId()), Generation: ref.GetGeneration()}
}

func delegationRefFromGrant(grant *authoritypb.Delegation) (*authoritypb.DelegationRef, error) {
	if grant == nil || len(grant.GetId()) != 16 || bytes.Equal(grant.GetId(), make([]byte, 16)) || grant.GetGeneration() == 0 {
		return nil, errors.New("fusev3: malformed delegation grant")
	}
	if grant.GetMode() != authoritypb.DelegationMode_DELEGATION_MODE_FULL &&
		grant.GetMode() != authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH {
		return nil, errors.New("fusev3: delegation grant has invalid mode")
	}
	return &authoritypb.DelegationRef{Id: cloneBytes(grant.GetId()), Generation: grant.GetGeneration()}, nil
}

func sameDelegation(a, b *authoritypb.DelegationRef) bool {
	return a != nil && b != nil && a.GetGeneration() == b.GetGeneration() && bytes.Equal(a.GetId(), b.GetId())
}

func (m *delegationManager) state(id writeback.Identity) *delegationState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.byID[id]
	if s == nil {
		s = &delegationState{grantChanged: make(chan struct{}), identity: id, handles: make(map[string][]byte), writers: make(map[string][]byte), bindings: make(map[uint64]delegationBinding)}
		m.byID[id] = s
	}
	return s
}

func (m *delegationManager) lookupState(id writeback.Identity) *delegationState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byID[id]
}

func (m *delegationManager) SetIncarnation(incarnation uint64) {
	m.mu.Lock()
	m.inc = incarnation
	m.mu.Unlock()
}

// FenceSubscription synchronously abandons every grant and buffered entry
// from the expired subscription before a cold Subscribe. Open server handles
// remain frontend-owned and can reacquire grants after SetIncarnation installs
// the new nonzero incarnation.
func (m *delegationManager) FenceSubscription(reason string) {
	m.SetIncarnation(0)
	m.EpochChanged(reason)
}

func (m *delegationManager) SetWithdrawalDrain(drain func(context.Context, []byte) error) {
	m.hookMu.Lock()
	m.withdrawalDrain = drain
	m.hookMu.Unlock()
}

func (m *delegationManager) SetAcceptedWriteInvalidator(invalidate func(context.Context, []byte, int64, int64) error) {
	m.hookMu.Lock()
	m.acceptedWrite = invalidate
	m.hookMu.Unlock()
}

func (m *delegationManager) Owns(identity []byte) bool {
	id, err := delegationIdentity(identity)
	if err != nil {
		return false
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	if m.incarnation() == 0 {
		return false
	}
	s := m.lookupState(id)
	if s == nil {
		return false
	}
	s.admission.RLock()
	defer s.admission.RUnlock()
	return s.ref != nil
}

func (m *delegationManager) SetBaseAttr(identity []byte, attr *authoritypb.Attr, version uint64) error {
	id, err := delegationIdentity(identity)
	if err != nil {
		return err
	}
	s := m.lookupState(id)
	if s == nil {
		return nil
	}
	s.meta.Lock()
	s.installBaseLocked(attr, version)
	s.meta.Unlock()
	return nil
}

// installBaseLocked compares object versions, never snapshot watermarks.
func (s *delegationState) installBaseLocked(attr *authoritypb.Attr, version uint64) {
	if attr != nil && version != 0 && version >= s.baseVersion && version >= s.baseInvalidatedThrough {
		s.base, s.baseVersion = proto.Clone(attr).(*authoritypb.Attr), version
	}
}

func (m *delegationManager) InvalidateBaseAttr(identity []byte, version uint64) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	state := m.lookupState(id)
	if state == nil {
		return
	}
	state.meta.Lock()
	defer state.meta.Unlock()
	state.baseInvalidatedThrough = max(state.baseInvalidatedThrough, version)
	if state.baseVersion < version {
		state.base = nil
	}
}

func (m *delegationManager) BaseAttr(identity []byte) (*authoritypb.Attr, bool) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return nil, false
	}
	if m.incarnation() == 0 {
		return nil, false
	}
	s := m.lookupState(id)
	if s == nil {
		return nil, false
	}
	s.admission.RLock()
	owned := s.ref != nil
	s.admission.RUnlock()
	if !owned {
		return nil, false
	}
	s.meta.Lock()
	defer s.meta.Unlock()
	if s.base == nil {
		return nil, false
	}
	return proto.Clone(s.base).(*authoritypb.Attr), true
}

func (m *delegationManager) incarnation() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inc
}

// Install records a grant returned by CREATE or OPEN. handle and item are the
// server capabilities used by later flushes; at least one live handle is
// required for writes. Repeated installation of the exact grant is harmless.
func (m *delegationManager) Install(identity, item, handle []byte, grant *authoritypb.Delegation) error {
	id, err := delegationIdentity(identity)
	if err != nil {
		return err
	}
	ref, err := delegationRefFromGrant(grant)
	if err != nil {
		return err
	}
	if len(handle) == 0 || len(item) == 0 {
		return errors.New("fusev3: delegated open requires item and handle capabilities")
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	if m.incarnation() == 0 {
		return errors.New("fusev3: cannot install delegation while subscription is fenced")
	}
	m.frontend.RLock()
	defer m.frontend.RUnlock()
	s := m.state(id)
	s.transition.Lock()
	defer s.transition.Unlock()
	s.operation.Lock()
	defer s.operation.Unlock()
	s.admission.Lock()
	defer s.admission.Unlock()
	if ref.GetGeneration() <= s.retiredGeneration {
		return errDelegationRetired
	}
	if s.ref != nil && !sameDelegation(s.ref, ref) {
		return errors.New("fusev3: identity received a second live delegation")
	}
	if s.ref == nil {
		// Item attributes predate OPEN arbitration and may belong to an earlier
		// ownership interval. Fetch a current base before caching it again.
		s.meta.Lock()
		s.base = nil
		s.baseVersion, s.baseInvalidatedThrough = 0, 0
		// A cut receipt belongs to this ownership generation. Carrying the
		// previous grant's last ticket into an empty successor break would
		// acknowledge data never applied under the successor reference.
		s.applied, s.appliedCut, s.acceptedCut, s.dirty = 0, 0, 0, false
		s.meta.Unlock()
	}
	s.ref, s.mode, s.item = ref, grant.GetMode(), cloneBytes(item)
	close(s.grantChanged)
	s.grantChanged = make(chan struct{})
	s.handles[string(handle)] = cloneBytes(handle)
	s.writers[string(handle)] = cloneBytes(handle)
	if s.retire != nil {
		generation := m.buf.Generation(id) + 1
		s.bindings[generation] = delegationBinding{ref: cloneDelegationRef(ref), item: cloneBytes(item), generation: generation}
		if err := s.retire.Resume(); err != nil {
			delete(s.bindings, generation)
			return fmt.Errorf("fusev3: resume delegated identity: %w", err)
		}
		s.retire = nil
	} else {
		generation := m.buf.Generation(id)
		s.bindings[generation] = delegationBinding{ref: cloneDelegationRef(ref), item: cloneBytes(item), generation: generation}
	}
	return nil
}

// AddHandle joins a currently owned generation if one remains. A read-only
// OPEN can race last-handle release; a successful Authority open stays valid
// when that release wins and must then close as an ordinary handle.
func (m *delegationManager) AddHandle(identity, item, handle []byte, writable bool) error {
	id, err := delegationIdentity(identity)
	if err != nil {
		return err
	}
	if len(handle) == 0 {
		return errors.New("fusev3: empty delegated handle")
	}
	s := m.lookupState(id)
	if s == nil {
		return nil
	}
	s.transition.Lock()
	defer s.transition.Unlock()
	s.admission.Lock()
	defer s.admission.Unlock()
	if s.ref == nil {
		return errDelegationRetired
	}
	if len(item) != 0 {
		s.item = cloneBytes(item)
	}
	s.handles[string(handle)] = cloneBytes(handle)
	if writable {
		s.writers[string(handle)] = cloneBytes(handle)
	}
	return nil
}

// A frontend closes its publication coordinates inside the same operation turn
// that checks ownership and admits the entry. A failed ownership check must not
// leave a source gate held while reacquisition waits for a recall.
type delegationPrepareContextKey struct{}

func prepareDelegationAdmission(ctx context.Context) error {
	if prepare, ok := ctx.Value(delegationPrepareContextKey{}).(func() error); ok {
		return prepare()
	}
	return nil
}

var errDelegationRetired = errors.New("fusev3: delegation retired before response registration")

func (s *delegationState) clearGrantLocked() {
	if s.ref != nil {
		s.retiredGeneration = max(s.retiredGeneration, s.ref.GetGeneration())
	}
	s.ref = nil
	s.mode = authoritypb.DelegationMode_DELEGATION_MODE_UNSPECIFIED
	close(s.grantChanged)
	s.grantChanged = make(chan struct{})
}

var errDelegationNotOwned = errors.New("fusev3: mutation has no write delegation")

func (m *delegationManager) modeAndBuffer(id writeback.Identity) (*delegationState, *writeback.Buffer, authoritypb.DelegationMode, error) {
	if m.incarnation() == 0 {
		return nil, nil, 0, errors.New("fusev3: delegated mutation while subscription is fenced")
	}
	s := m.state(id)
	s.admission.RLock()
	if s.ref == nil {
		s.admission.RUnlock()
		return nil, nil, 0, errDelegationNotOwned
	}
	mode := s.mode
	return s, m.buf, mode, nil
}

func (m *delegationManager) markAccepted(s *delegationState, cut writeback.Cut) {
	s.meta.Lock()
	defer s.meta.Unlock()
	s.acceptedCut = max(s.acceptedCut, cut.Sequence)
	m.durabilityMu.Lock()
	durable := m.durableHigh
	m.durabilityMu.Unlock()
	s.dirty = s.appliedCut < cut.Sequence || s.applied == 0 || s.applied > durable
}

func (m *delegationManager) Write(ctx context.Context, identity []byte, off int64, data []byte, syncWrite bool) (writeback.Cut, error) {
	return m.WriteWithOptions(ctx, identity, off, data, syncWrite, writeback.WriteOptions{})
}
func (m *delegationManager) WriteWithOptions(ctx context.Context, identity []byte, off int64, data []byte, syncWrite bool, opts writeback.WriteOptions) (writeback.Cut, error) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return writeback.Cut{}, err
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	m.frontend.RLock()
	defer m.frontend.RUnlock()
	s := m.state(id)
	s.operation.Lock()
	defer s.operation.Unlock()
	s, b, mode, err := m.modeAndBuffer(id)
	if err != nil {
		return writeback.Cut{}, err
	}
	if err := prepareDelegationAdmission(ctx); err != nil {
		s.admission.RUnlock()
		return writeback.Cut{}, err
	}
	var cut writeback.Cut
	if syncWrite {
		// WriteSync re-enters the manager through Flusher.Flush. The context
		// marker lets that callback use the state protected by this read fence
		// without recursively taking admission.RLock behind a queued writer.
		flushCtx := context.WithValue(ctx, delegationAdmissionContextKey{}, s)
		cut, err = b.WriteSyncWithOptions(flushCtx, id, off, data, opts)
	} else {
		cut, err = b.WriteWithOptions(ctx, id, off, data, opts)
	}
	if err == nil {
		m.markAccepted(s, cut)
	}
	s.admission.RUnlock()
	if err != nil {
		return cut, err
	}
	m.hookMu.RLock()
	invalidate := m.acceptedWrite
	m.hookMu.RUnlock()
	if invalidate != nil {
		if err := invalidate(ctx, cloneBytes(identity), off, int64(len(data))); err != nil {
			m.loseDelegation(s, "holder kernel data invalidation failed")
			return cut, fmt.Errorf("fusev3: invalidate holder read cache: %w", err)
		}
	}
	// Re-read the mode after admission: a writer waiting behind a downgrade
	// fence may have entered under the successor generation.
	s.admission.RLock()
	mode = s.mode
	s.admission.RUnlock()
	if mode == authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH && !syncWrite {
		if _, err := b.FlushIdentity(ctx, id, cut); err != nil {
			return cut, err
		}
	}
	return cut, nil
}

func (m *delegationManager) Truncate(ctx context.Context, identity []byte, size int64) (writeback.Cut, error) {
	return m.admitMetadata(ctx, identity, func(b *writeback.Buffer, id writeback.Identity) (writeback.Cut, error) {
		return b.Truncate(ctx, id, size)
	})
}

func (m *delegationManager) SetAttr(ctx context.Context, identity []byte, attrs writeback.Attributes) (writeback.Cut, error) {
	return m.admitMetadata(ctx, identity, func(b *writeback.Buffer, id writeback.Identity) (writeback.Cut, error) {
		return b.SetAttr(ctx, id, attrs)
	})
}

func (m *delegationManager) admitMetadata(ctx context.Context, identity []byte, admit func(*writeback.Buffer, writeback.Identity) (writeback.Cut, error)) (writeback.Cut, error) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return writeback.Cut{}, err
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	m.frontend.RLock()
	defer m.frontend.RUnlock()
	s := m.state(id)
	s.operation.Lock()
	defer s.operation.Unlock()
	s, b, mode, err := m.modeAndBuffer(id)
	if err != nil {
		return writeback.Cut{}, err
	}
	if err := prepareDelegationAdmission(ctx); err != nil {
		s.admission.RUnlock()
		return writeback.Cut{}, err
	}
	cut, err := admit(b, id)
	if err == nil {
		m.markAccepted(s, cut)
	}
	s.admission.RUnlock()
	if err == nil {
		s.admission.RLock()
		mode = s.mode
		s.admission.RUnlock()
		if mode == authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH {
			_, err = b.FlushIdentity(ctx, id, cut)
		}
	}
	return cut, err
}

func (m *delegationManager) Read(ctx context.Context, identity []byte, off int64, length int, fetch writeback.Fetch) ([]byte, error) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return nil, err
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	s := m.lookupState(id)
	if m.incarnation() == 0 || s == nil || !delegationStateOwned(s) {
		if off < 0 || length < 0 || fetch == nil {
			return nil, writeback.ErrInvalid
		}
		return fetch(ctx, off, length)
	}
	return m.buf.Read(ctx, id, off, length, fetch)
}

func (m *delegationManager) Size(identity []byte, base int64) (int64, error) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return 0, err
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	s := m.lookupState(id)
	if m.incarnation() == 0 || s == nil || !delegationStateOwned(s) {
		return base, nil
	}
	return m.buf.Size(id, base), nil
}

func (m *delegationManager) OverlayAttributes(identity []byte, base writeback.Attributes) (writeback.Attributes, error) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return base, err
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	s := m.lookupState(id)
	if m.incarnation() == 0 || s == nil || !delegationStateOwned(s) {
		return base, nil
	}
	return m.buf.OverlayAttributes(id, base), nil
}

func delegationStateOwned(s *delegationState) bool {
	s.admission.RLock()
	defer s.admission.RUnlock()
	return s.ref != nil
}

func (m *delegationManager) LossSequence() uint64 {
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	return m.buf.LossSequence()
}

func (m *delegationManager) IdentityLoss(identity []byte) uint64 {
	id, err := delegationIdentity(identity)
	if err != nil {
		return 0
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	current := m.buf.IdentityLoss(id)
	m.mu.Lock()
	historical := m.identityLoss[id]
	m.mu.Unlock()
	return max(current, historical)
}

func (m *delegationManager) DropIdentity(identity []byte, reason string) error {
	id, err := delegationIdentity(identity)
	if err != nil {
		return err
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	s := m.state(id)
	s.transition.Lock()
	defer s.transition.Unlock()
	s.operation.Lock()
	defer s.operation.Unlock()
	m.loseDelegation(s, reason)
	return nil
}

func (m *delegationManager) VisibleSequence(sequence uint64) {
	m.epoch.RLock()
	m.buf.VisibleSequence(sequence)
	m.epoch.RUnlock()
}

func (m *delegationManager) DurableSequence(sequence uint64) {
	m.epoch.RLock()
	m.durableCurrent(sequence)
	m.epoch.RUnlock()
}

// durableCurrent is used by Flush callbacks, which already run against the
// current epoch buffer and must not recursively take epoch.RLock while an epoch
// writer is queued.
func (m *delegationManager) durableCurrent(sequence uint64) {
	m.durabilityMu.Lock()
	buffer := m.durableBuffer
	m.durabilityMu.Unlock()
	if buffer != nil {
		m.durableForBuffer(buffer, sequence)
	}
}

func (m *delegationManager) durableForBuffer(buffer *writeback.Buffer, sequence uint64) {
	buffer.VisibleSequence(sequence)
	buffer.DurableSequence(sequence)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.durabilityMu.Lock()
	if m.durableBuffer != buffer {
		m.durabilityMu.Unlock()
		return
	}
	m.durableHigh = max(m.durableHigh, sequence)
	m.durabilityMu.Unlock()
	m.tokenMu.Lock()
	for token, progress := range m.tokens {
		if progress.complete && progress.sequence <= sequence {
			delete(m.tokens, token)
		}
	}
	m.tokenMu.Unlock()
}

func (m *delegationManager) durabilityLoop() {
	defer m.workerWG.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.durableKick:
		case <-ticker.C:
		}
		m.advanceDurability()
	}
}

func (m *delegationManager) advanceDurability() {
	m.durabilityMu.Lock()
	buffer := m.durableBuffer
	cut := m.appliedHigh
	durable := m.durableHigh
	m.durabilityMu.Unlock()
	if buffer == nil || cut == 0 || cut <= durable {
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx, m.timeout)
	response, err := m.rpc.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{CutSequence: cut}}})
	cancel()
	if err != nil || successfulDelegationResponse(response) != nil {
		return
	}
	reply := response.GetBarrier()
	if reply == nil || reply.GetAppliedSequence() < reply.GetDurableSequence() || reply.GetDurableSequence() < cut {
		return
	}
	m.durableForBuffer(buffer, reply.GetDurableSequence())
}

// Flush implements writeback.Flusher. Buffer itself serializes these calls per
// identity and pipelines disjoint identities. Its batches are bounded by
// writeback.MaxPayload, so every WRITE is at most 1 MiB.
func (m *delegationManager) Flush(ctx context.Context, id writeback.Identity, entry writeback.Entry) (uint64, error) {
	if entry.Kind == writeback.Write && (len(entry.Data) == 0 || len(entry.Data) > writeback.MaxPayload) {
		return 0, errors.New("fusev3: invalid delegated write chunk")
	}
	s := m.state(id)
	m.tokenMu.Lock()
	progress := m.tokens[entry.Token]
	if progress.sequence != 0 && progress.complete {
		m.tokenMu.Unlock()
		return progress.sequence, nil
	}
	m.tokenMu.Unlock()
	admissionHeld, _ := ctx.Value(delegationAdmissionContextKey{}).(*delegationState)
	if admissionHeld != s {
		s.admission.RLock()
	}
	binding, ok := s.bindings[entry.Generation]
	handle := firstDelegatedHandle(s.handles)
	// ftruncate requires a writable descriptor just like pwrite. A read-only
	// handle can join the holder while a buffered size change awaits flush.
	if entry.Kind == writeback.Write || entry.Kind == writeback.Truncate || entry.Attributes.HasSize {
		handle = firstDelegatedHandle(s.writers)
	}
	if admissionHeld != s {
		s.admission.RUnlock()
	}
	if !ok || binding.ref == nil {
		return 0, errors.New("fusev3: writeback entry has no delegation generation binding")
	}
	if len(handle) == 0 {
		return 0, errors.New("fusev3: delegated flush has no live server handle")
	}
	if entry.Kind == writeback.Write {
		return m.flushWrite(ctx, s, binding, handle, entry, progress)
	}
	// Generated oneof interfaces are package-private, so construct the request
	// in each branch instead of storing the body interface.
	var request *authoritypb.Request
	switch entry.Kind {
	case writeback.Truncate, writeback.SetAttr:
		a := entry.Attributes
		set := &authoritypb.SetAttrRequest{Handle: cloneBytes(handle), Delegation: cloneDelegationRef(binding.ref), AtimeNow: a.ATimeNow, MtimeNow: a.MTimeNow}
		if a.HasMode {
			set.Mode = &a.Mode
		}
		if a.HasUID {
			set.Uid = &a.UID
		}
		if a.HasGID {
			set.Gid = &a.GID
		}
		if a.HasSize {
			set.Size = &a.Size
		}
		if a.HasATime {
			set.AtimeNs = &a.ATimeNS
		}
		if a.HasMTime {
			set.MtimeNs = &a.MTimeNS
		}
		request = &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: set}}
	default:
		return 0, errors.New("fusev3: unsupported writeback entry kind")
	}
	response, err := m.rpc.CallMutation(ctx, request)
	if err != nil {
		if errors.Is(err, authorityrpc.ErrTransportUncertain) || errors.Is(err, authorityrpc.ErrAuthorityChanged) ||
			errors.Is(err, authorityrpc.ErrReplayDesynchronized) || errors.Is(err, authorityrpc.ErrSessionEnded) {
			m.loseDelegation(s, "delegated mutation outcome uncertain")
			return 0, writeback.ErrLost
		}
		return 0, err
	}
	if err := successfulDelegationResponse(response); err != nil {
		m.loseDelegation(s, "delegated mutation permanently refused")
		return 0, writeback.ErrLost
	}
	if !m.updateBaseFromResponse(s, response) {
		m.loseDelegation(s, "delegated metadata omitted exact post attributes")
		return 0, writeback.ErrLost
	}
	sequence := response.GetAppliedSequence()
	if sequence == 0 {
		m.loseDelegation(s, "delegated flush omitted application ticket")
		return 0, writeback.ErrLost
	}
	s.meta.Lock()
	s.applied = max(s.applied, sequence)
	s.appliedCut = max(s.appliedCut, entry.Last)
	s.meta.Unlock()
	m.tokenMu.Lock()
	m.tokens[entry.Token] = delegationFlushProgress{sequence: sequence, complete: true}
	m.tokenMu.Unlock()
	m.durabilityMu.Lock()
	m.appliedHigh = max(m.appliedHigh, sequence)
	m.durabilityMu.Unlock()
	select {
	case m.durableKick <- struct{}{}:
	default:
	}
	return sequence, nil
}

func (m *delegationManager) flushWrite(ctx context.Context, s *delegationState, binding delegationBinding, handle []byte, entry writeback.Entry, progress delegationFlushProgress) (uint64, error) {
	if progress.bytes < 0 || progress.bytes > len(entry.Data) {
		m.loseDelegation(s, "invalid delegated write replay progress")
		return 0, writeback.ErrLost
	}
	for progress.bytes < len(entry.Data) {
		end := min(len(entry.Data), progress.bytes+m.maxWrite)
		position := entry.Offset + int64(progress.bytes)
		chunk := entry.Data[progress.bytes:end]
		response, err := m.rpc.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
			Handle: handle, Position: uint64(position), Size: uint32(len(chunk)), Data: chunk,
			WriteFlags: entry.WriteOptions.Flags, LockOwner: entry.WriteOptions.LockOwner,
			Delegation: cloneDelegationRef(binding.ref),
		}}})
		if err != nil {
			if errors.Is(err, authorityrpc.ErrTransportUncertain) || errors.Is(err, authorityrpc.ErrAuthorityChanged) ||
				errors.Is(err, authorityrpc.ErrReplayDesynchronized) || errors.Is(err, authorityrpc.ErrSessionEnded) {
				m.loseDelegation(s, "delegated mutation outcome uncertain")
				return 0, writeback.ErrLost
			}
			return 0, err
		}
		if err := successfulDelegationResponse(response); err != nil {
			m.loseDelegation(s, "delegated mutation permanently refused")
			return 0, writeback.ErrLost
		}
		reply := response.GetWrite()
		if reply == nil || response.GetVolumeVersion() == 0 || reply.GetPostAttr() == nil || reply.GetPostAttr().GetKind() != authoritypb.Attr_REGULAR || reply.GetPostAttr().GetSize() < position+int64(len(chunk)) || reply.GetCommittedSize() != uint64(len(chunk)) || reply.GetAssignedOffset() != uint64(position) || reply.GetError() != 0 || response.GetAppliedSequence() == 0 || response.GetAppliedSequence() < progress.sequence {
			m.loseDelegation(s, "malformed delegated write success")
			return 0, writeback.ErrLost
		}
		progress.bytes = end
		progress.sequence = response.GetAppliedSequence()
		progress.complete = progress.bytes == len(entry.Data)
		m.tokenMu.Lock()
		m.tokens[entry.Token] = progress
		m.tokenMu.Unlock()
		s.meta.Lock()
		s.applied = max(s.applied, progress.sequence)
		if progress.bytes == len(entry.Data) {
			s.appliedCut = max(s.appliedCut, entry.Last)
		}
		s.meta.Unlock()
		m.durabilityMu.Lock()
		m.appliedHigh = max(m.appliedHigh, progress.sequence)
		m.durabilityMu.Unlock()
		// Retiring the overlay must expose the exact applied attributes, never
		// the pre-write base that the buffered timestamp temporarily covered.
		m.updateBaseFromResponse(s, response)
		if reply.GetDurableSequence() != 0 {
			m.durableCurrent(reply.GetDurableSequence())
		}
		select {
		case m.durableKick <- struct{}{}:
		default:
		}
	}
	return progress.sequence, nil
}

func (m *delegationManager) updateBaseFromResponse(s *delegationState, response *authoritypb.Response) bool {
	var attr *authoritypb.Attr
	version := response.GetVolumeVersion()
	if response.GetWrite() != nil {
		attr = response.GetWrite().GetPostAttr()
	}
	if attr == nil && response.GetPostState() != nil {
		for _, object := range response.GetPostState().GetObjects() {
			if bytes.Equal(object.GetStableIdentity(), s.identity[:]) {
				attr = object.GetAttr()
				version = object.GetObjectVersion()
				break
			}
		}
	}
	if attr == nil || version == 0 {
		return false
	}
	s.meta.Lock()
	s.installBaseLocked(attr, version)
	s.meta.Unlock()
	return true
}

func delegationApplied(s *delegationState, _ uint64) uint64 {
	s.meta.Lock()
	defer s.meta.Unlock()
	// Buffer retains an identity's application high-water across generations.
	// CONTROL receipts must name only this grant's applications; each flusher
	// updates s.applied before returning its receipt to Buffer.
	return s.applied
}

func firstDelegatedHandle(handles map[string][]byte) []byte {
	for _, handle := range handles {
		return cloneBytes(handle)
	}
	return nil
}

func successfulDelegationResponse(response *authoritypb.Response) error {
	if response == nil || response.GetUncertain() {
		return errors.New("fusev3: delegated request has no definite outcome")
	}
	if response.GetErrno() != 0 {
		return syscall.Errno(response.GetErrno())
	}
	return nil
}

func (m *delegationManager) FlushIdentity(ctx context.Context, identity []byte) (uint64, error) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return 0, err
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	return m.buf.FlushIdentity(ctx, id, m.buf.Snapshot())
}

// flushIdentityInEpoch is for a Synchronous callback, which already holds the
// manager epoch read fence. Taking it recursively can deadlock behind an epoch
// writer because sync.RWMutex gives queued writers preference.
func (m *delegationManager) flushIdentityInEpoch(ctx context.Context, identity []byte) (uint64, error) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return 0, err
	}
	return m.buf.FlushIdentity(ctx, id, m.buf.Snapshot())
}

// Synchronous orders an Authority mutation after every locally accepted entry
// for the identity. It is used for append (whose position only the Authority
// can choose), fallocate, copy destinations, and other delegated operations
// that the positioned-write Buffer cannot represent.
func (m *delegationManager) Synchronous(ctx context.Context, identity []byte, call func(*authoritypb.DelegationRef) (*authoritypb.Response, error)) (*authoritypb.Response, error) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return nil, err
	}
	if call == nil {
		return nil, errors.New("fusev3: nil delegated synchronous operation")
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	m.frontend.RLock()
	defer m.frontend.RUnlock()
	s := m.state(id)
	s.operation.Lock()
	defer s.operation.Unlock()
	s.admission.RLock()
	ref := cloneDelegationRef(s.ref)
	s.admission.RUnlock()
	if ref == nil {
		return nil, errDelegationNotOwned
	}
	// An external range mutation can replace bytes represented by retained
	// applied extents. Retire the prior cut before dispatch so the holder's
	// overlay cannot hide the operation's new Authority contents afterward.
	if err := m.buf.Fsync(ctx, id); err != nil {
		return nil, err
	}
	response, err := call(ref)
	if err != nil {
		return response, err
	}
	if err := successfulDelegationResponse(response); err != nil {
		return response, err
	}
	if response.GetAppliedSequence() != 0 {
		s.meta.Lock()
		s.applied = max(s.applied, response.GetAppliedSequence())
		s.meta.Unlock()
		m.durabilityMu.Lock()
		m.appliedHigh = max(m.appliedHigh, response.GetAppliedSequence())
		m.durabilityMu.Unlock()
		select {
		case m.durableKick <- struct{}{}:
		default:
		}
	}
	if response.GetWrite() != nil && response.GetWrite().GetDurableSequence() != 0 {
		m.durableCurrent(response.GetWrite().GetDurableSequence())
	}
	m.updateBaseFromResponse(s, response)
	return response, nil
}

func (m *delegationManager) syncIdentity(ctx context.Context, s *delegationState, dataOnly bool) error {
	s.admission.RLock()
	handle := firstDelegatedHandle(s.handles)
	s.admission.RUnlock()
	if len(handle) == 0 {
		return errors.New("fusev3: delegated fsync has no live server handle")
	}
	response, err := m.rpc.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: handle, DataOnly: dataOnly}}})
	if err != nil {
		return err
	}
	if err := successfulDelegationResponse(response); err != nil {
		return err
	}
	if response.GetFsync() == nil {
		return errors.New("fusev3: delegated fsync omitted reply")
	}
	m.durableCurrent(response.GetFsync().GetDurableSequence())
	return nil
}

func (m *delegationManager) Fsync(ctx context.Context, identity []byte, dataOnly bool) error {
	id, err := delegationIdentity(identity)
	if err != nil {
		return err
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	s := m.state(id)
	s.transition.Lock()
	defer s.transition.Unlock()
	s.operation.Lock()
	defer s.operation.Unlock()
	if err := m.buf.Fsync(ctx, id); err != nil {
		return err
	}
	return m.syncIdentity(ctx, s, dataOnly)
}

// Barrier implements the root-directory completion barrier. Admission is
// briefly fenced because Buffer's public durability waiter captures its own
// cut; the fence makes that cut identical to the ticket sent on the wire.
func (m *delegationManager) Barrier(ctx context.Context, observedLoss uint64) error {
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	m.frontend.Lock()
	defer m.frontend.Unlock()
	cut := m.buf.Snapshot()
	applied, err := m.buf.FlushAll(ctx, cut)
	if err != nil {
		return err
	}
	m.durabilityMu.Lock()
	applied = max(applied, m.appliedHigh)
	m.durabilityMu.Unlock()
	response, err := m.rpc.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{CutSequence: applied}}})
	if err != nil {
		return err
	}
	if err := successfulDelegationResponse(response); err != nil {
		return err
	}
	reply := response.GetBarrier()
	if reply == nil || reply.GetAppliedSequence() < reply.GetDurableSequence() || reply.GetDurableSequence() < applied {
		return errors.New("fusev3: malformed barrier reply")
	}
	m.durableCurrent(reply.GetDurableSequence())
	lost, err := m.buf.Barrier(ctx, observedLoss)
	if err != nil {
		return err
	}
	if lost {
		return writeback.ErrLost
	}
	return nil
}

func (m *delegationManager) HandleControlEvent(parent context.Context, event *authoritypb.ControlEvent) <-chan struct{} {
	done := make(chan struct{})
	started := false
	defer func() {
		if !started {
			close(done)
		}
	}()
	if event == nil {
		return done
	}
	cloned := proto.Clone(event).(*authoritypb.ControlEvent)
	if cloned.GetIncarnation() == 0 || cloned.GetIncarnation() != m.incarnation() || cloned.GetSequence() == 0 {
		return done
	}
	if cloned.GetDelegationRecall() == nil && cloned.GetDelegationBreak() == nil && cloned.GetDelegationModeChange() == nil {
		return done
	}
	var rawID []byte
	var budget uint64
	switch {
	case cloned.GetDelegationRecall() != nil:
		rawID, budget = cloned.GetDelegationRecall().GetIdentity(), cloned.GetDelegationRecall().GetBudgetNanos()
	case cloned.GetDelegationBreak() != nil:
		rawID, budget = cloned.GetDelegationBreak().GetIdentity(), cloned.GetDelegationBreak().GetBudgetNanos()
	case cloned.GetDelegationModeChange() != nil:
		rawID, budget = cloned.GetDelegationModeChange().GetIdentity(), cloned.GetDelegationModeChange().GetBudgetNanos()
	}
	id, err := delegationIdentity(rawID)
	if err != nil || budget == 0 || budget > uint64(5*time.Second) {
		return done
	}
	// The local budget begins at receipt, including time spent behind an
	// earlier transition for this identity.
	ctx, cancel := context.WithTimeout(parent, time.Duration(budget))
	m.epoch.RLock()
	epoch := m.epochSerial
	s := m.state(id)
	m.epoch.RUnlock()
	s.controlMu.Lock()
	predecessor := s.controlTail
	s.controlTail = done
	s.controlMu.Unlock()
	m.controlWG.Add(1)
	started = true
	go func() {
		defer m.controlWG.Done()
		defer cancel()
		defer close(done)
		if predecessor != nil {
			<-predecessor
		}
		m.handleControlEvent(ctx, cloned, s, epoch)
	}()
	return done
}

func (m *delegationManager) handleControlEvent(ctx context.Context, event *authoritypb.ControlEvent, s *delegationState, epoch uint64) {
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	if epoch != m.epochSerial {
		return
	}
	var ref *authoritypb.DelegationRef
	switch {
	case event.GetDelegationRecall() != nil:
		ref = event.GetDelegationRecall().GetDelegation()
	case event.GetDelegationBreak() != nil:
		ref = event.GetDelegationBreak().GetDelegation()
	case event.GetDelegationModeChange() != nil:
		ref = event.GetDelegationModeChange().GetDelegation()
	}
	// CONTROL may overtake the DATA reply carrying a newly activated grant.
	// Wait without transition/operation locks: Install needs both to publish it.
	for {
		s.transition.Lock()
		s.operation.Lock()
		s.admission.RLock()
		live, changed, retired := cloneDelegationRef(s.ref), s.grantChanged, s.retiredGeneration
		s.admission.RUnlock()
		if sameDelegation(live, ref) {
			break
		}
		s.operation.Unlock()
		s.transition.Unlock()
		if retired >= ref.GetGeneration() || live != nil && live.GetGeneration() > ref.GetGeneration() {
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return
		}
	}
	defer s.transition.Unlock()
	defer s.operation.Unlock()
	if event.GetDelegationRecall() != nil {
		m.recall(ctx, event, s)
		return
	}
	if event.GetDelegationBreak() != nil {
		m.breakDelegation(ctx, event, s)
		return
	}
	m.changeMode(ctx, event, s)
}

func (m *delegationManager) beginRetire(ctx context.Context, s *delegationState) (*writeback.Retirement, error) {
	s.admission.Lock()
	defer s.admission.Unlock()
	if s.retire != nil {
		return s.retire, nil
	}
	r, err := m.buf.BeginRetire(ctx, &s.identity)
	if err == nil {
		s.retire = r
	}
	return r, err
}

func (m *delegationManager) loseDelegation(s *delegationState, reason string) {
	s.admission.Lock()
	s.clearGrantLocked()
	s.admission.Unlock()
	// Closing the manager admission gate before Drop is the frontend retirement
	// boundary. Calling Buffer.BeginRetire from inside a Flusher callback would
	// wait on the very flush which is reporting the permanent failure.
	m.buf.Drop(s.identity, reason)
	s.meta.Lock()
	s.dirty = false
	s.meta.Unlock()
}

func (m *delegationManager) recall(ctx context.Context, event *authoritypb.ControlEvent, s *delegationState) {
	retire, err := m.beginRetire(ctx, s)
	var applied uint64
	if err == nil {
		m.hookMu.RLock()
		drain := m.withdrawalDrain
		m.hookMu.RUnlock()
		if drain != nil {
			err = drain(ctx, cloneBytes(s.identity[:]))
		}
	}
	if err == nil {
		applied, err = m.buf.FlushIdentity(ctx, s.identity, retire.Cut())
		applied = delegationApplied(s, applied)
	}
	if err == nil {
		// Once ownership is surrendered, a peer may replace these ranges. Retire
		// the old overlay first so a later local read or reacquisition cannot
		// mask the peer's Authority bytes with retained applied extents.
		err = m.buf.Fsync(ctx, s.identity)
	}
	if err == nil {
		ack := &authoritypb.DelegationRecallAck{Incarnation: event.GetIncarnation(), EventSequence: event.GetSequence(), Delegation: cloneDelegationRef(s.ref), AppliedSequence: applied}
		var response *authoritypb.Response
		response, err = m.rpc.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationRecallAck{DelegationRecallAck: ack}})
		if err == nil {
			err = successfulDelegationResponse(response)
		}
		if err == nil && response.GetDelegationRecallAck() == nil {
			err = errors.New("fusev3: recall acknowledgment omitted reply")
		}
	}
	if err != nil {
		m.loseDelegation(s, "delegation recall budget missed")
		return
	}
	s.admission.Lock()
	s.clearGrantLocked()
	s.admission.Unlock()
}

func (m *delegationManager) breakDelegation(ctx context.Context, event *authoritypb.ControlEvent, s *delegationState) {
	s.admission.Lock()
	cut := m.buf.Snapshot()
	s.admission.Unlock()
	applied, err := m.buf.FlushIdentity(ctx, s.identity, cut)
	applied = delegationApplied(s, applied)
	if err == nil {
		ack := &authoritypb.DelegationBreakAck{Incarnation: event.GetIncarnation(), EventSequence: event.GetSequence(), Delegation: cloneDelegationRef(s.ref), AppliedSequence: applied}
		var response *authoritypb.Response
		response, err = m.rpc.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationBreakAck{DelegationBreakAck: ack}})
		if err == nil {
			err = successfulDelegationResponse(response)
		}
		if err == nil && response.GetDelegationBreakAck() == nil {
			err = errors.New("fusev3: break acknowledgment omitted reply")
		}
	}
	if err != nil {
		m.loseDelegation(s, "delegation break budget missed")
	}
}

func (m *delegationManager) changeMode(ctx context.Context, event *authoritypb.ControlEvent, s *delegationState) {
	change := event.GetDelegationModeChange()
	target := change.GetMode()
	if target != authoritypb.DelegationMode_DELEGATION_MODE_FULL && target != authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH {
		return
	}
	var applied uint64
	var err error
	s.admission.RLock()
	oldMode := s.mode
	s.admission.RUnlock()
	if target == authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH && oldMode != target {
		var retire *writeback.Retirement
		retire, err = m.beginRetire(ctx, s)
		if err == nil {
			applied, err = m.buf.FlushIdentity(ctx, s.identity, retire.Cut())
			applied = delegationApplied(s, applied)
		}
		if err == nil {
			s.admission.Lock()
			next := m.buf.Generation(s.identity) + 1
			s.bindings[next] = delegationBinding{ref: cloneDelegationRef(s.ref), item: cloneBytes(s.item), generation: next}
			s.mode = target
			err = retire.Resume()
			if err == nil {
				s.retire = nil
			}
			s.admission.Unlock()
		}
	} else {
		s.admission.Lock()
		s.mode = target
		s.admission.Unlock()
		s.meta.Lock()
		applied = s.applied
		s.meta.Unlock()
	}
	if err == nil {
		ack := &authoritypb.DelegationModeChangeAck{Incarnation: event.GetIncarnation(), EventSequence: event.GetSequence(), Delegation: cloneDelegationRef(s.ref), AppliedSequence: applied}
		var response *authoritypb.Response
		response, err = m.rpc.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationModeChangeAck{DelegationModeChangeAck: ack}})
		if err == nil {
			err = successfulDelegationResponse(response)
		}
		if err == nil && response.GetDelegationModeChangeAck() == nil {
			err = errors.New("fusev3: mode-change acknowledgment omitted reply")
		}
	}
	if err != nil {
		m.loseDelegation(s, "delegation mode-change budget missed")
	}
}

// ReleaseBatch flushes and releases identities after their final local handle
// closes. The wire batch is sorted by delegation id as required by protocol 7.
func (m *delegationManager) ReleaseBatch(ctx context.Context, identities [][]byte) error {
	if len(identities) == 0 || len(identities) > 4096 {
		return errors.New("fusev3: invalid delegation release batch size")
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	type pending struct {
		s       *delegationState
		release *authoritypb.DelegationRelease
	}
	items := make([]pending, 0, len(identities))
	seen := make(map[writeback.Identity]struct{}, len(identities))
	ordered := make([][]byte, len(identities))
	for i := range identities {
		ordered[i] = cloneBytes(identities[i])
	}
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i], ordered[j]) < 0 })
	for _, raw := range ordered {
		id, err := delegationIdentity(raw)
		if err != nil {
			return err
		}
		if _, ok := seen[id]; ok {
			return errors.New("fusev3: duplicate delegation release identity")
		}
		seen[id] = struct{}{}
		s := m.state(id)
		s.transition.Lock()
		defer s.transition.Unlock()
		s.operation.Lock()
		defer s.operation.Unlock()
		if s.ref == nil {
			return errors.New("fusev3: release has no live delegation")
		}
		retire, err := m.beginRetire(ctx, s)
		if err != nil {
			return err
		}
		applied, err := m.buf.FlushIdentity(ctx, id, retire.Cut())
		if err != nil {
			return err
		}
		applied = delegationApplied(s, applied)
		if err := m.buf.Fsync(ctx, id); err != nil {
			return err
		}
		items = append(items, pending{s: s, release: &authoritypb.DelegationRelease{Delegation: cloneDelegationRef(s.ref), AppliedSequence: applied}})
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].release.GetDelegation().GetId(), items[j].release.GetDelegation().GetId()) < 0
	})
	releases := make([]*authoritypb.DelegationRelease, len(items))
	for i := range items {
		releases[i] = items[i].release
	}
	response, err := m.rpc.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseRequest{Incarnation: m.incarnation(), Delegations: releases}}})
	if err != nil {
		return err
	}
	if err := successfulDelegationResponse(response); err != nil {
		return err
	}
	if response.GetDelegationRelease() == nil {
		return errors.New("fusev3: delegation release omitted reply")
	}
	for _, item := range items {
		item.s.admission.Lock()
		item.s.clearGrantLocked()
		item.s.admission.Unlock()
	}
	return nil
}

func (m *delegationManager) TracksHandle(identity, handle []byte) bool {
	id, err := delegationIdentity(identity)
	if err != nil {
		return false
	}
	s := m.lookupState(id)
	if s == nil {
		return false
	}
	s.admission.RLock()
	_, tracked := s.handles[string(handle)]
	s.admission.RUnlock()
	return tracked
}

func (m *delegationManager) CloseHandle(ctx context.Context, identity, handle []byte) error {
	id, err := delegationIdentity(identity)
	if err != nil {
		return err
	}
	s := m.state(id)
	s.transition.Lock()
	s.admission.RLock()
	_, present := s.handles[string(handle)]
	last := present && len(s.handles) == 1 && s.ref != nil
	s.admission.RUnlock()
	if present && !last {
		s.admission.Lock()
		delete(s.handles, string(handle))
		delete(s.writers, string(handle))
		s.admission.Unlock()
	}
	s.transition.Unlock()
	if !present || !last {
		return nil
	}
	// The final server handle remains registered until every buffered entry has
	// used it. The caller invokes CloseHandle before sending CLOSE, so a
	// successful release leaves no flush that can refer to the capability.
	if err := m.ReleaseBatch(ctx, [][]byte{cloneBytes(identity)}); err != nil {
		return err
	}
	s.admission.Lock()
	delete(s.handles, string(handle))
	delete(s.writers, string(handle))
	s.admission.Unlock()
	return nil
}

// Bound deferred cleanup well below the Authority's normal open table. New
// handle admission waits before acquiring any per-identity operation locks;
// cleanup must remain able to flush and release the handles it already owns.
const deferredCloseAdmissionLimit = 256

func (m *delegationManager) waitCloseCapacity(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	for m.closePending >= deferredCloseAdmissionLimit {
		if m.closeChanged == nil {
			m.closeChanged = make(chan struct{})
		}
		changed := m.closeChanged
		m.closeMu.Unlock()
		var err error
		select {
		case <-changed:
		case <-ctx.Done():
			err = ctx.Err()
		case <-m.ctx.Done():
			err = writeback.ErrClosed
		}
		m.closeMu.Lock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *delegationManager) changePendingCloses(delta int) {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	m.closePending += delta
	if delta < 0 && m.closeChanged != nil {
		close(m.closeChanged)
		m.closeChanged = nil
	}
}

// QueueClose transfers a FUSE RELEASE to the cleanup worker. RELEASE has no
// kernel reply, so a short collection window can combine final-handle
// delegation releases while keeping every server handle alive through its
// flush. A later cleanup failure advances loss for the affected identity.
func (m *delegationManager) QueueClose(identity, handle []byte, lockOwner uint64, flockUnlock bool) error {
	if _, err := delegationIdentity(identity); err != nil {
		return err
	}
	if len(handle) == 0 {
		return errors.New("fusev3: cannot queue an empty server handle")
	}
	m.epoch.RLock()
	pending := delegationClose{
		identity: cloneBytes(identity), handle: cloneBytes(handle), lockOwner: lockOwner,
		flockUnlock: flockUnlock, epoch: m.epochSerial,
	}
	m.epoch.RUnlock()
	m.closeMu.Lock()
	if m.closeStopped || m.ctx.Err() != nil {
		m.closeMu.Unlock()
		return writeback.ErrClosed
	}
	m.closePending++
	m.closeProducers.Add(1)
	m.closeMu.Unlock()
	defer m.closeProducers.Done()
	select {
	case m.closeQueue <- pending:
		return nil
	case <-m.ctx.Done():
		m.changePendingCloses(-1)
		return writeback.ErrClosed
	}
}

func (m *delegationManager) closeLoop() {
	defer m.workerWG.Done()
	defer m.finishCloseQueue()
	for {
		var first delegationClose
		select {
		case first = <-m.closeQueue:
		case <-m.ctx.Done():
			return
		}
		batch := []delegationClose{first}
		timer := time.NewTimer(10 * time.Millisecond)
	collect:
		for len(batch) < 128 {
			select {
			case pending := <-m.closeQueue:
				batch = append(batch, pending)
			case <-timer.C:
				break collect
			case <-m.ctx.Done():
				timer.Stop()
				m.processCloseBatch(batch)
				return
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		m.processCloseBatch(batch)
	}
}

// A canceled select can still choose a ready enqueue. Seal producers and
// join those already admitted before the final drain, so Stop cannot strand
// a late close after its cleanup worker has exited.
func (m *delegationManager) finishCloseQueue() {
	m.closeMu.Lock()
	m.closeStopped = true
	m.closeMu.Unlock()
	m.closeProducers.Wait()
	m.drainCloseQueue()
}

func (m *delegationManager) drainCloseQueue() {
	batch := make([]delegationClose, 0, 128)
	for {
		select {
		case pending := <-m.closeQueue:
			batch = append(batch, pending)
			if len(batch) == cap(batch) {
				m.processCloseBatch(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) != 0 {
				m.processCloseBatch(batch)
			}
			return
		}
	}
}

func (m *delegationManager) processCloseBatch(batch []delegationClose) {
	defer m.changePendingCloses(-len(batch))
	// A background close retains its exact replay identity through an outage.
	// The queue is bounded, and mount shutdown cancels this work.
	if err := m.CloseHandles(m.ctx, batch); err != nil {
		for _, pending := range batch {
			id, parseErr := delegationIdentity(pending.identity)
			if parseErr == nil {
				m.epoch.RLock()
				if pending.epoch == m.epochSerial {
					m.loseDelegation(m.state(id), "asynchronous delegated close failed")
				}
				m.epoch.RUnlock()
			}
		}
	}
}

// CloseHandles is the synchronous batch primitive behind QueueClose. It is
// kept visible to tests and clean shutdown paths that already own a deadline.
func (m *delegationManager) CloseHandles(ctx context.Context, closes []delegationClose) error {
	if len(closes) == 0 || len(closes) > 4096 {
		return errors.New("fusev3: invalid close batch size")
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	current := make([]delegationClose, 0, len(closes))
	for _, pending := range closes {
		if pending.epoch == 0 || pending.epoch == m.epochSerial {
			current = append(current, pending)
		}
	}
	closes = current
	if len(closes) == 0 {
		return nil
	}
	type closeGroup struct {
		id      writeback.Identity
		state   *delegationState
		closing map[string]struct{}
	}
	groupsByID := make(map[writeback.Identity]*closeGroup)
	for _, pending := range closes {
		id, err := delegationIdentity(pending.identity)
		if err != nil {
			return err
		}
		group := groupsByID[id]
		if group == nil {
			group = &closeGroup{id: id, state: m.state(id), closing: make(map[string]struct{})}
			groupsByID[id] = group
		}
		if _, duplicate := group.closing[string(pending.handle)]; duplicate {
			return errors.New("fusev3: duplicate handle in close batch")
		}
		group.closing[string(pending.handle)] = struct{}{}
	}
	groups := make([]*closeGroup, 0, len(groupsByID))
	for _, group := range groupsByID {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return bytes.Compare(groups[i].id[:], groups[j].id[:]) < 0 })
	for _, group := range groups {
		group.state.acquire.Lock()
		defer group.state.acquire.Unlock()
	}
	for _, group := range groups {
		group.state.transition.Lock()
		defer group.state.transition.Unlock()
		group.state.operation.Lock()
		defer group.state.operation.Unlock()
	}

	type releasedGroup struct {
		group   *closeGroup
		release *authoritypb.DelegationRelease
	}
	var releasing []releasedGroup
	for _, group := range groups {
		s := group.state
		s.admission.RLock()
		allClosing := len(s.handles) != 0
		for handle := range s.handles {
			if _, closing := group.closing[handle]; !closing {
				allClosing = false
				break
			}
		}
		ref := cloneDelegationRef(s.ref)
		s.admission.RUnlock()
		if ref == nil {
			continue
		}
		if !allClosing {
			// A read-only description may outlive the last writable one. Apply
			// accepted bytes before closing their retained writable capability.
			if _, err := m.buf.FlushIdentity(ctx, group.id, m.buf.Snapshot()); err != nil {
				return err
			}
			continue
		}
		retire, err := m.beginRetire(ctx, s)
		if err != nil {
			return err
		}
		applied, err := m.buf.FlushIdentity(ctx, group.id, retire.Cut())
		if err != nil {
			return err
		}
		applied = delegationApplied(s, applied)
		releasing = append(releasing, releasedGroup{group: group, release: &authoritypb.DelegationRelease{Delegation: ref, AppliedSequence: applied}})
	}
	// Apply the whole close batch before waiting for durability. Waiting per
	// file turns a batched release into one serialized storage barrier per
	// handle and lets asynchronous closes exhaust the Authority's open table.
	// Admission is retired and the operation locks remain held, so no accepted
	// entry can slip past this cut before ownership is surrendered.
	for _, released := range releasing {
		if err := m.buf.Fsync(ctx, released.group.id); err != nil {
			return err
		}
	}
	if len(releasing) != 0 {
		sort.Slice(releasing, func(i, j int) bool {
			return bytes.Compare(releasing[i].release.GetDelegation().GetId(), releasing[j].release.GetDelegation().GetId()) < 0
		})
		releases := make([]*authoritypb.DelegationRelease, len(releasing))
		for i := range releasing {
			releases[i] = releasing[i].release
		}
		response, err := m.rpc.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseRequest{Incarnation: m.incarnation(), Delegations: releases}}})
		if err != nil {
			return err
		}
		if err := successfulDelegationResponse(response); err != nil || response.GetDelegationRelease() == nil {
			if err != nil {
				return err
			}
			return errors.New("fusev3: batched delegation release omitted reply")
		}
		for _, released := range releasing {
			released.group.state.admission.Lock()
			released.group.state.clearGrantLocked()
			released.group.state.admission.Unlock()
		}
	}

	var firstErr error
	for _, pending := range closes {
		response, err := m.rpc.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{
			Handle: pending.handle, LockOwner: pending.lockOwner, FlockUnlock: pending.flockUnlock,
		}}})
		if err == nil {
			err = successfulDelegationResponse(response)
		}
		id, _ := delegationIdentity(pending.identity)
		s := groupsByID[id].state
		if err == nil {
			s.admission.Lock()
			delete(s.handles, string(pending.handle))
			delete(s.writers, string(pending.handle))
			s.admission.Unlock()
		} else if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// EpochChanged permanently withdraws all old grants, records loss only for
// identities with retained non-durable entries, and replaces the epoch-scoped
// Buffer while preserving the mount loss counter.
func (m *delegationManager) EpochChanged(reason string) {
	m.epoch.Lock()
	defer m.epoch.Unlock()
	m.epochSerial++
	for {
		select {
		case <-m.closeQueue:
			m.changePendingCloses(-1)
			continue
		default:
		}
		break
	}
	old := m.buf
	m.durabilityMu.Lock()
	durable := m.durableHigh
	m.durabilityMu.Unlock()
	m.mu.Lock()
	for _, s := range m.byID {
		s.meta.Lock()
		atRisk := s.dirty && (s.appliedCut < s.acceptedCut || s.applied == 0 || s.applied > durable)
		if atRisk {
			old.Drop(s.identity, reason)
		}
		m.identityLoss[s.identity] = max(m.identityLoss[s.identity], old.IdentityLoss(s.identity))
		s.meta.Unlock()
		s.admission.Lock()
		s.ref = nil
		s.mode = authoritypb.DelegationMode_DELEGATION_MODE_UNSPECIFIED
		s.admission.Unlock()
		s.meta.Lock()
		s.dirty = false
		s.meta.Unlock()
	}
	loss := old.LossSequence()
	m.byID = make(map[writeback.Identity]*delegationState)
	m.mu.Unlock()
	old.Stop()
	// An in-flight old-buffer callback may have looked up its state after the
	// first reset while Stop was joining it. Discard that epoch-scoped residue
	// only after every old callback is gone.
	m.mu.Lock()
	m.byID = make(map[writeback.Identity]*delegationState)
	m.mu.Unlock()
	m.tokenMu.Lock()
	m.tokens = make(map[uint64]delegationFlushProgress)
	m.tokenMu.Unlock()
	b, err := writeback.New(m, writeback.Options{InitialLossSequence: loss})
	if err != nil {
		panic(fmt.Sprintf("fusev3: replace epoch write buffer: %v", err))
	}
	m.mu.Lock()
	m.buf = b
	m.durabilityMu.Lock()
	m.durableBuffer = b
	m.appliedHigh, m.durableHigh = 0, 0
	m.durabilityMu.Unlock()
	m.mu.Unlock()
}

func (m *delegationManager) Stop() {
	m.cancel()
	m.controlWG.Wait()
	m.workerWG.Wait()
	m.epoch.Lock()
	m.buf.Stop()
	m.epoch.Unlock()
}
