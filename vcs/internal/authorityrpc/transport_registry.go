package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

var ErrTransportBinding = errors.New("authorityrpc: invalid transport binding")

type connectionSetID [32]byte

type transportPairKey struct {
	peer volumeserver.PeerIdentity
	set  connectionSetID
}

// transportConnection is an authority-owned identity for one physical TLS
// connection. Generation is assigned before HelloReply and never reused in
// this server process. A candidate cannot serve session traffic until a
// proof-bearing Resume (or an exact provisional Attach replay on DATA)
// promotes it.
type transportConnection struct {
	registry   *transportRegistry
	pair       *transportPair
	role       authoritypb.TransportRole
	profile    authoritypb.FrontendProfile
	generation uint64
	// serving is guarded by registry.mu. Replacement first makes a candidate
	// current with serving=false, which generation-fences its predecessor. Only
	// after that predecessor's admitted workers drain is the successor exposed.
	serving bool
	cancel  context.CancelFunc
	close   func() error

	// executionMu protects the proof that every ordinary handler execution
	// admitted on this physical generation has ended. Admission first validates
	// current+serving under registry.mu and pins before releasing that lock;
	// promotion changes current under the same lock, so no pin can arrive after
	// generation fencing. Lifecycle requests are serialized by pair.operation
	// instead and never take an execution pin.
	executionMu      sync.Mutex
	executionPins    uint64
	executionDrained chan struct{}
}

type transportRoleBinding struct {
	current   *transportConnection
	candidate *transportConnection
}

// operation serializes only state-changing requests for this one connection
// set. The registry's global mutex is never held while operation is acquired,
// while a handler runs, or while a socket is closed.
type transportPair struct {
	operation sync.Mutex
	key       transportPairKey
	profile   authoritypb.FrontendProfile
	data      transportRoleBinding
	control   transportRoleBinding
	session   volumeserver.SessionID
	state     authoritypb.SessionState
	terminal  <-chan struct{}
	// done closes exactly when this pair is removed by a terminal transition.
	// A replacement may stop waiting for an ancient predecessor only on this
	// edge, because no successor will then be exposed.
	done chan struct{}
	// terminalResponder is the one CONTROL connection allowed to attempt a
	// planned Abort/Detach response after the runtime becomes terminal. The
	// terminal transition still removes the pair and fences every generation;
	// it merely defers closing this socket until the response attempt ends.
	terminalResponder *transportConnection
}

// bindTerminal installs the one runtime-owned terminal edge for this session.
// Exact Attach replays observe the same channel and do not create another
// watcher. A different channel for one session is an internal identity defect.
func (r *transportRegistry) bindTerminal(entry *transportConnection, session volumeserver.SessionID, terminal <-chan struct{}) (bool, error) {
	if entry == nil || terminal == nil || session == (volumeserver.SessionID{}) {
		return false, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.bySession[session]
	if pair != entry.pair || r.pairs[pair.key] != pair {
		return false, ErrTransportBinding
	}
	if pair.terminal != nil {
		if pair.terminal != terminal {
			return false, fmt.Errorf("%w: runtime terminal identity changed", ErrTransportBinding)
		}
		return false, nil
	}
	pair.terminal = terminal
	return true, nil
}

type transportRegistry struct {
	mu             sync.Mutex
	maxSets        int
	nextGeneration uint64
	pairs          map[transportPairKey]*transportPair
	bySession      map[volumeserver.SessionID]*transportPair
}

func newTransportRegistry(maxSets int) (*transportRegistry, error) {
	if maxSets <= 0 {
		return nil, fmt.Errorf("%w: connection-set bound must be positive", ErrTransportBinding)
	}
	return &transportRegistry{
		maxSets:   maxSets,
		pairs:     make(map[transportPairKey]*transportPair),
		bySession: make(map[volumeserver.SessionID]*transportPair),
	}, nil
}

func parseConnectionSetID(raw []byte) (connectionSetID, error) {
	var id connectionSetID
	if len(raw) != len(id) {
		return id, fmt.Errorf("%w: connection-set identity must be %d bytes", ErrTransportBinding, len(id))
	}
	copy(id[:], raw)
	if id == (connectionSetID{}) {
		return id, fmt.Errorf("%w: zero connection-set identity", ErrTransportBinding)
	}
	return id, nil
}

func validTransportRole(role authoritypb.TransportRole) bool {
	return role == authoritypb.TransportRole_TRANSPORT_ROLE_DATA ||
		role == authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL
}

func validFrontendProfile(profile authoritypb.FrontendProfile) bool {
	return profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED ||
		profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES ||
		profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR
}

func (r *transportRegistry) register(
	peer volumeserver.PeerIdentity,
	set connectionSetID,
	role authoritypb.TransportRole,
	profile authoritypb.FrontendProfile,
	cancel context.CancelFunc,
	closeConnection func() error,
) (*transportConnection, error) {
	if peer == (volumeserver.PeerIdentity{}) || set == (connectionSetID{}) || !validTransportRole(role) || !validFrontendProfile(profile) || cancel == nil || closeConnection == nil {
		return nil, ErrTransportBinding
	}
	key := transportPairKey{peer: peer, set: set}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[key]
	if pair == nil {
		if len(r.pairs) >= r.maxSets {
			return nil, fmt.Errorf("%w: connection-set admission bound reached", ErrTransportBinding)
		}
		pair = &transportPair{key: key, profile: profile, done: make(chan struct{})}
		r.pairs[key] = pair
	} else if pair.profile != profile {
		return nil, fmt.Errorf("%w: connection-set frontend profile mismatch", ErrTransportBinding)
	}
	slot := pair.roleBinding(role)
	if slot == nil {
		return nil, ErrTransportBinding
	}
	if r.nextGeneration == math.MaxUint64 {
		return nil, fmt.Errorf("%w: binding generation exhausted", ErrTransportBinding)
	}
	r.nextGeneration++
	executionDrained := make(chan struct{})
	close(executionDrained)
	entry := &transportConnection{
		registry: r, pair: pair, role: role, profile: profile, generation: r.nextGeneration,
		cancel: cancel, close: closeConnection, executionDrained: executionDrained,
	}
	if pair.session == (volumeserver.SessionID{}) {
		// Before Attach there is no credential with which a second same-role
		// connection could prove replacement. Refuse it instead of guessing.
		if slot.current != nil || slot.candidate != nil {
			return nil, fmt.Errorf("%w: duplicate unbound role", ErrTransportBinding)
		}
		slot.current = entry
		return entry, nil
	}
	// Once a pair is bound, Hello creates at most one non-serving candidate.
	// It cannot evict current merely by knowing a set ID and using the same CA.
	if slot.candidate != nil {
		return nil, fmt.Errorf("%w: duplicate role candidate", ErrTransportBinding)
	}
	slot.candidate = entry
	return entry, nil
}

func (p *transportPair) roleBinding(role authoritypb.TransportRole) *transportRoleBinding {
	switch role {
	case authoritypb.TransportRole_TRANSPORT_ROLE_DATA:
		return &p.data
	case authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL:
		return &p.control
	default:
		return nil
	}
}

func (r *transportRegistry) unregister(entry *transportConnection) {
	if entry == nil || entry.pair == nil {
		return
	}
	r.mu.Lock()
	pair := entry.pair
	slot := pair.roleBinding(entry.role)
	if slot != nil {
		if slot.current == entry {
			slot.current = nil
		}
		if slot.candidate == entry {
			slot.candidate = nil
		}
	}
	r.removeIfFinishedLocked(pair)
	r.mu.Unlock()
}

func (r *transportRegistry) removeIfFinishedLocked(pair *transportPair) {
	if pair == nil || pair.data.current != nil || pair.data.candidate != nil ||
		pair.control.current != nil || pair.control.candidate != nil {
		return
	}
	if r.pairs[pair.key] != pair {
		// A deferred close from an older generation must never delete a new pair
		// that happens to reuse the same authenticated peer/set key.
		return
	}
	if pair.session != (volumeserver.SessionID{}) &&
		pair.state != authoritypb.SessionState_SESSION_STATE_ABORTED &&
		pair.state != authoritypb.SessionState_SESSION_STATE_TERMINAL {
		return
	}
	delete(r.pairs, pair.key)
	if pair.session != (volumeserver.SessionID{}) && r.bySession[pair.session] == pair {
		delete(r.bySession, pair.session)
	}
}

type transportPairSnapshot struct {
	role              authoritypb.TransportRole
	connectionSetID   connectionSetID
	bindingGeneration uint64
	dataGeneration    uint64
	controlGeneration uint64
	session           volumeserver.SessionID
	state             authoritypb.SessionState
	current           bool
	candidate         bool
	serving           bool
	complete          bool
}

// transportExecutionPin is the linearization proof for an ordinary handler
// execution. The registry admits it only while entry is the current serving
// generation. Release is idempotent so error paths can defer it immediately.
type transportExecutionPin struct {
	entry *transportConnection
	once  sync.Once
}

func (pin *transportExecutionPin) Release() {
	if pin == nil || pin.entry == nil {
		return
	}
	pin.once.Do(func() {
		entry := pin.entry
		entry.executionMu.Lock()
		if entry.executionPins == 0 {
			entry.executionMu.Unlock()
			panic("authorityrpc: transport execution pin underflow")
		}
		entry.executionPins--
		if entry.executionPins == 0 {
			close(entry.executionDrained)
		}
		entry.executionMu.Unlock()
	})
}

// pinCurrentLocked is called with registry.mu held. Promotion also holds that
// lock while changing current/serving, making witness+pin atomic with the
// generation fence.
func pinCurrentLocked(entry *transportConnection) *transportExecutionPin {
	entry.executionMu.Lock()
	if entry.executionPins == 0 {
		entry.executionDrained = make(chan struct{})
	}
	entry.executionPins++
	entry.executionMu.Unlock()
	return &transportExecutionPin{entry: entry}
}

func executionDrain(entry *transportConnection) <-chan struct{} {
	if entry == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	entry.executionMu.Lock()
	drained := entry.executionDrained
	entry.executionMu.Unlock()
	return drained
}

func (r *transportRegistry) snapshot(entry *transportConnection) (transportPairSnapshot, error) {
	if entry == nil || entry.pair == nil {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	if pair != entry.pair {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	slot := pair.roleBinding(entry.role)
	if slot == nil {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	return transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set,
		bindingGeneration: entry.generation,
		dataGeneration:    generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state,
		current: slot.current == entry, candidate: slot.candidate == entry, serving: entry.serving,
		complete: pair.data.current != nil && pair.control.current != nil,
	}, nil
}

func (r *transportRegistry) attachWitness(entry *transportConnection) (transportPairSnapshot, error) {
	if entry == nil || entry.role != authoritypb.TransportRole_TRANSPORT_ROLE_DATA {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	if pair != entry.pair || (pair.control.current == nil && pair.control.candidate == nil) {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	slot := &pair.data
	if pair.session == (volumeserver.SessionID{}) {
		if slot.current != entry || pair.state != authoritypb.SessionState_SESSION_STATE_UNSPECIFIED {
			return transportPairSnapshot{}, ErrTransportBinding
		}
	} else {
		currentServing := slot.current == entry && entry.serving
		if pair.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL ||
			(!currentServing && slot.candidate != entry) {
			return transportPairSnapshot{}, ErrTransportBinding
		}
	}
	return transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state,
		current: slot.current == entry, candidate: slot.candidate == entry, serving: entry.serving,
		complete: pair.data.current != nil && pair.control.current != nil,
	}, nil
}

func (r *transportRegistry) resumeWitness(entry *transportConnection, session volumeserver.SessionID) (transportPairSnapshot, error) {
	if entry == nil || session == (volumeserver.SessionID{}) {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	slot := entry.pair.roleBinding(entry.role)
	currentServing := slot != nil && slot.current == entry && entry.serving
	if pair != entry.pair || slot == nil || (!currentServing && slot.candidate != entry) || pair.session != session ||
		(pair.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL && pair.state != authoritypb.SessionState_SESSION_STATE_ACTIVE) {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	return transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state,
		current: slot.current == entry, candidate: slot.candidate == entry, serving: entry.serving,
		complete: pair.data.current != nil && pair.control.current != nil,
	}, nil
}

func (r *transportRegistry) provisionalControlWitness(entry *transportConnection, session volumeserver.SessionID) (transportPairSnapshot, error) {
	if entry == nil || entry.role != authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL || session == (volumeserver.SessionID{}) {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	if pair != entry.pair || pair.control.current != entry || !entry.serving || pair.session != session ||
		pair.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	return transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state, current: true, serving: entry.serving,
		complete: pair.data.current != nil && pair.control.current != nil,
	}, nil
}

func (r *transportRegistry) currentWitness(entry *transportConnection, session volumeserver.SessionID) (transportPairSnapshot, error) {
	if entry == nil || session == (volumeserver.SessionID{}) {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	slot := entry.pair.roleBinding(entry.role)
	if pair != entry.pair || slot == nil || slot.current != entry || !entry.serving || pair.session != session ||
		(pair.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL && pair.state != authoritypb.SessionState_SESSION_STATE_ACTIVE) {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	return transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state, current: true, serving: entry.serving,
		complete: pair.data.current != nil && pair.control.current != nil,
	}, nil
}

// pinCurrent witnesses and pins one non-lifecycle request. Cancel uses this as
// well: although its handler is inline, its generation must not be retired
// between transport authorization and the acknowledgment.
func (r *transportRegistry) pinCurrent(entry *transportConnection, session volumeserver.SessionID) (transportPairSnapshot, *transportExecutionPin, error) {
	if entry == nil || session == (volumeserver.SessionID{}) {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	slot := entry.pair.roleBinding(entry.role)
	if pair != entry.pair || slot == nil || slot.current != entry || !entry.serving || pair.session != session ||
		(pair.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL && pair.state != authoritypb.SessionState_SESSION_STATE_ACTIVE) {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	snapshot := transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state, current: true, serving: true,
		complete: pair.data.current != nil && pair.control.current != nil,
	}
	return snapshot, pinCurrentLocked(entry), nil
}

func generation(entry *transportConnection) uint64 {
	if entry == nil {
		return 0
	}
	return entry.generation
}

// bindProvisional runs after the handler has returned one exact successful
// provisional Attach result and before that response is exposed. The caller
// owns pair.operation across the handler call and this transition.
func (r *transportRegistry) bindProvisional(entry *transportConnection, session volumeserver.SessionID) (transportPairSnapshot, []*transportConnection, error) {
	if entry == nil || entry.role != authoritypb.TransportRole_TRANSPORT_ROLE_DATA || session == (volumeserver.SessionID{}) {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	if pair != entry.pair || (pair.control.current == nil && pair.control.candidate == nil) {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	var replaced []*transportConnection
	switch {
	case pair.session == (volumeserver.SessionID{}):
		if pair.data.current != entry || pair.state != authoritypb.SessionState_SESSION_STATE_UNSPECIFIED {
			return transportPairSnapshot{}, nil, ErrTransportBinding
		}
		if existing := r.bySession[session]; existing != nil && existing != pair {
			return transportPairSnapshot{}, nil, ErrTransportBinding
		}
		pair.session = session
		pair.state = authoritypb.SessionState_SESSION_STATE_PROVISIONAL
		r.bySession[session] = pair
	case pair.session == session && pair.state == authoritypb.SessionState_SESSION_STATE_PROVISIONAL:
		if pair.data.candidate == entry {
			replaced = append(replaced, pair.data.current)
			pair.data.current = entry
			pair.data.candidate = nil
		} else if pair.data.current != entry {
			return transportPairSnapshot{}, nil, ErrTransportBinding
		}
	default:
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	// Attach conveys no active capability. On an exact provisional replay it is
	// therefore safe—and necessary after both old lanes died—to promote the
	// matching CONTROL candidate together with DATA before returning the proof.
	// The peer still cannot execute anything until it presents that proof on
	// CONTROL to Activate.
	if pair.control.candidate != nil {
		replaced = append(replaced, pair.control.current)
		pair.control.current = pair.control.candidate
		pair.control.candidate = nil
	}
	snapshot := transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state, current: true,
		complete: pair.data.current != nil && pair.control.current != nil,
	}
	return snapshot, uniqueTransportConnections(replaced...), nil
}

// exposeCurrentPair publishes the freshly bound provisional pair only after
// every replaced physical generation has drained. It is intentionally a
// separate transition from bindProvisional: combining them would let a
// pipelined request on the successor overlap an already-admitted predecessor.
func (r *transportRegistry) exposeCurrentPair(entry *transportConnection, session volumeserver.SessionID) error {
	if entry == nil || entry.role != authoritypb.TransportRole_TRANSPORT_ROLE_DATA {
		return ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	if pair != entry.pair || pair.session != session ||
		pair.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL ||
		pair.data.current != entry || pair.control.current == nil {
		return ErrTransportBinding
	}
	pair.data.current.serving = true
	pair.control.current.serving = true
	return nil
}

func (r *transportRegistry) promoteResume(entry *transportConnection, session volumeserver.SessionID, state authoritypb.SessionState) (transportPairSnapshot, *transportConnection, error) {
	if entry == nil || session == (volumeserver.SessionID{}) ||
		(state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL && state != authoritypb.SessionState_SESSION_STATE_ACTIVE) {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	if pair != entry.pair || pair.session != session || pair.state != state {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	slot := pair.roleBinding(entry.role)
	if slot == nil {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	var replaced *transportConnection
	if slot.candidate == entry {
		replaced = slot.current
		slot.current = entry
		slot.candidate = nil
	} else if slot.current != entry {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	return transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state, current: true,
		complete: pair.data.current != nil && pair.control.current != nil,
	}, replaced, nil
}

// exposeResumed is the second half of proof-bearing replacement. Promotion
// generation-fences the predecessor; exposure is legal only after its drain
// proof has completed.
func (r *transportRegistry) exposeResumed(entry *transportConnection, session volumeserver.SessionID, state authoritypb.SessionState) error {
	if entry == nil {
		return ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	slot := entry.pair.roleBinding(entry.role)
	if pair != entry.pair || slot == nil || slot.current != entry || pair.session != session || pair.state != state {
		return ErrTransportBinding
	}
	entry.serving = true
	return nil
}

func (r *transportRegistry) activationWitness(entry *transportConnection, session volumeserver.SessionID, dataGeneration, controlGeneration uint64) (transportPairSnapshot, error) {
	if entry == nil || entry.role != authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	if pair != entry.pair || pair.control.current != entry || !entry.serving || pair.session != session ||
		(pair.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL && pair.state != authoritypb.SessionState_SESSION_STATE_ACTIVE) ||
		pair.data.current == nil || !pair.data.current.serving ||
		generation(pair.data.current) != dataGeneration || generation(pair.control.current) != controlGeneration {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	return transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: dataGeneration, controlGeneration: controlGeneration,
		session: pair.session, state: pair.state, current: true, complete: true,
	}, nil
}

// markActive updates transport bookkeeping after the handler has already
// committed durable membership and runtime ACTIVE. Connection loss at this
// point must not make the transition fail: a lost Activate reply is recovered
// by proof-bearing Resume and exact Activate replay.
func (r *transportRegistry) markActive(entry *transportConnection, session volumeserver.SessionID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry == nil || entry.pair == nil {
		return ErrTransportBinding
	}
	pair := r.bySession[session]
	if pair != entry.pair || r.pairs[pair.key] != pair || pair.session != session {
		return ErrTransportBinding
	}
	if pair.state == authoritypb.SessionState_SESSION_STATE_ACTIVE {
		return nil
	}
	if pair.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL {
		return ErrTransportBinding
	}
	pair.state = authoritypb.SessionState_SESSION_STATE_ACTIVE
	return nil
}

func (r *transportRegistry) activeWitness(entry *transportConnection, session volumeserver.SessionID) (transportPairSnapshot, error) {
	if entry == nil || session == (volumeserver.SessionID{}) {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	slot := entry.pair.roleBinding(entry.role)
	if pair != entry.pair || slot == nil || slot.current != entry || !entry.serving || pair.session != session ||
		pair.state != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	return transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state, current: true,
		complete: pair.data.current != nil && pair.control.current != nil,
	}, nil
}

func (r *transportRegistry) pinActive(entry *transportConnection, session volumeserver.SessionID) (transportPairSnapshot, *transportExecutionPin, error) {
	if entry == nil || session == (volumeserver.SessionID{}) {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.pairs[entry.pair.key]
	slot := entry.pair.roleBinding(entry.role)
	if pair != entry.pair || slot == nil || slot.current != entry || !entry.serving || pair.session != session ||
		pair.state != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		return transportPairSnapshot{}, nil, ErrTransportBinding
	}
	snapshot := transportPairSnapshot{
		role: entry.role, connectionSetID: pair.key.set, bindingGeneration: entry.generation,
		dataGeneration: generation(pair.data.current), controlGeneration: generation(pair.control.current),
		session: pair.session, state: pair.state, current: true, serving: true,
		complete: pair.data.current != nil && pair.control.current != nil,
	}
	return snapshot, pinCurrentLocked(entry), nil
}

func (r *transportRegistry) beginTerminalResponse(entry *transportConnection, session volumeserver.SessionID) error {
	if entry == nil || entry.role != authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL || session == (volumeserver.SessionID{}) {
		return ErrTransportBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := r.bySession[session]
	if pair != entry.pair || pair.control.current != entry || !entry.serving || pair.terminalResponder != nil ||
		(pair.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL && pair.state != authoritypb.SessionState_SESSION_STATE_ACTIVE) {
		return ErrTransportBinding
	}
	pair.terminalResponder = entry
	return nil
}

func (r *transportRegistry) cancelTerminalResponse(entry *transportConnection) {
	if entry == nil || entry.pair == nil {
		return
	}
	r.mu.Lock()
	pair := entry.pair
	if r.pairs[pair.key] == pair && pair.terminalResponder == entry &&
		pair.state != authoritypb.SessionState_SESSION_STATE_ABORTED && pair.state != authoritypb.SessionState_SESSION_STATE_TERMINAL {
		pair.terminalResponder = nil
	}
	r.mu.Unlock()
}

// finishTerminalResponse releases the planned-response close hold. It reports
// whether the runtime became terminal while the hold was installed; the
// caller closes entry immediately after its one response attempt in that case.
func (r *transportRegistry) finishTerminalResponse(entry *transportConnection) bool {
	if entry == nil || entry.pair == nil {
		return false
	}
	r.mu.Lock()
	pair := entry.pair
	if pair.terminalResponder != entry {
		r.mu.Unlock()
		return false
	}
	pair.terminalResponder = nil
	terminal := pair.state == authoritypb.SessionState_SESSION_STATE_ABORTED || pair.state == authoritypb.SessionState_SESSION_STATE_TERMINAL
	r.mu.Unlock()
	return terminal
}

// markTerminal is the one runtime-to-transport terminal transition. It drops
// the bounded pair/session indexes immediately and returns every physical
// generation that may be closed now. A planned response connection is omitted
// until finishTerminalResponse; it has no registry authority in the interim.
func (r *transportRegistry) markTerminal(session volumeserver.SessionID, state authoritypb.SessionState) []*transportConnection {
	if state != authoritypb.SessionState_SESSION_STATE_ABORTED && state != authoritypb.SessionState_SESSION_STATE_TERMINAL {
		return nil
	}
	r.mu.Lock()
	pair := r.bySession[session]
	if pair == nil {
		r.mu.Unlock()
		return nil
	}
	pair.state = state
	entries := uniqueTransportConnections(
		pair.data.current, pair.data.candidate, pair.control.current, pair.control.candidate,
	)
	responder := pair.terminalResponder
	pair.data = transportRoleBinding{}
	pair.control = transportRoleBinding{}
	delete(r.pairs, pair.key)
	if r.bySession[session] == pair {
		delete(r.bySession, session)
	}
	close(pair.done)
	r.mu.Unlock()
	if responder == nil {
		return entries
	}
	closeNow := entries[:0]
	for _, candidate := range entries {
		if candidate != responder {
			closeNow = append(closeNow, candidate)
		}
	}
	return closeNow
}

func uniqueTransportConnections(entries ...*transportConnection) []*transportConnection {
	seen := make(map[*transportConnection]struct{}, len(entries))
	result := make([]*transportConnection, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		result = append(result, entry)
	}
	return result
}

func terminateTransportConnections(entries ...*transportConnection) {
	for _, entry := range uniqueTransportConnections(entries...) {
		entry.cancel()
		_ = entry.close()
	}
}

// retireTransportConnections is the proof boundary for role replacement. The
// registry has already made the old generation non-current, so canceling and
// closing prevents new reads; waiting for executionDrained proves every
// ordinary handler that atomically witnessed+pinned the old generation has
// exited. Lifecycle requests take pair.operation before their witness and thus
// cannot be waiting behind this transition while holding a pin.
//
// Request cancellation deliberately cannot abandon this wait. Returning true
// is the authority to expose the successor. The only alternative is pair.done:
// the runtime terminal edge removed the pair, so no successor can be exposed.
func retireTransportConnections(pair *transportPair, entries ...*transportConnection) bool {
	if pair == nil || pair.done == nil {
		return false
	}
	entries = uniqueTransportConnections(entries...)
	terminateTransportConnections(entries...)
	for _, entry := range entries {
		select {
		case <-executionDrain(entry):
		case <-pair.done:
			return false
		}
	}
	select {
	case <-pair.done:
		return false
	default:
		return true
	}
}

type transportContextKey struct{}

func withTransportConnection(ctx context.Context, entry *transportConnection) context.Context {
	return context.WithValue(ctx, transportContextKey{}, entry)
}

func transportConnectionFromContext(ctx context.Context) (*transportConnection, bool) {
	entry, ok := ctx.Value(transportContextKey{}).(*transportConnection)
	return entry, ok && entry != nil
}

func transportSnapshotFromContext(ctx context.Context) (transportPairSnapshot, error) {
	entry, ok := transportConnectionFromContext(ctx)
	if !ok || entry.registry == nil {
		return transportPairSnapshot{}, ErrTransportBinding
	}
	return entry.registry.snapshot(entry)
}
