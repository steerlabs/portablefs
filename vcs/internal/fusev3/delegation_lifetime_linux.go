//go:build linux

package fusev3

import (
	"errors"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// retainState joins the indexed state before taking any of its locks. A scoped
// reference includes time waiting for a lock or RPC, not just time owning it:
// otherwise collection could create two independent lock domains for one inode.
func (m *delegationManager) retainState(id writeback.Identity, create bool) *delegationState {
	m.mu.RLock()
	s := m.byID[id]
	if s != nil {
		s.users.Add(1)
		m.mu.RUnlock()
		return s
	}
	m.mu.RUnlock()
	if !create {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s = m.byID[id]
	if s == nil && create {
		s = &delegationState{manager: m, grantChanged: make(chan struct{}), identity: id, handles: make(map[string][]byte), writers: make(map[string][]byte), bindings: make(map[uint64]delegationBinding)}
		m.byID[id] = s
		m.stateIndex.Store(id, s)
	}
	if s != nil {
		s.users.Add(1)
	}
	return s
}

func (m *delegationManager) releaseState(s *delegationState) {
	if s == nil {
		return
	}
	remaining := s.users.Add(-1)
	if remaining < 0 {
		panic("fusev3: unbalanced delegation state reference")
	}
	if remaining != 0 {
		return
	}
	m.mu.Lock()
	if s.users.Load() == 0 && m.byID[s.identity] == s {
		if m.reclaim == nil {
			m.reclaim = make(map[*delegationState]struct{})
		}
		m.reclaim[s] = struct{}{}
	}
	m.mu.Unlock()
	m.kickReclaim()
}

func (m *delegationManager) kickReclaim() {
	select {
	case m.reclaimKick <- struct{}{}:
	default:
	}
}

// BufferIdle follows the buffer's own flush/job references, which outlive the
// manager Flush callback. It cannot take epoch: epoch replacement joins workers.
func (m *delegationManager) BufferIdle(id writeback.Identity) {
	m.mu.Lock()
	if s := m.byID[id]; s != nil {
		m.reclaim[s] = struct{}{}
	}
	m.mu.Unlock()
	m.kickReclaim()
}

func (m *delegationManager) reclaimLoop() {
	defer m.workerWG.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.reclaimKick:
			m.reapIdleStates()
		}
	}
}

// Only candidates touched since the last collection are visited. Buffer
// durability and idle notifications retry candidates still retaining records.
// The collector never waits for a state lock while holding the index lock.
func (m *delegationManager) reapIdleStates() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var oldestRequest uint64
	for request := range m.grantRequests {
		if oldestRequest == 0 || request < oldestRequest {
			oldestRequest = request
		}
	}
	for s := range m.reclaim {
		if m.byID[s.identity] != s {
			delete(m.reclaim, s)
			continue
		}
		if s.users.Load() != 0 {
			delete(m.reclaim, s)
			continue
		}
		if !s.transition.TryLock() {
			continue
		}
		if !s.operation.TryLock() {
			s.transition.Unlock()
			continue
		}
		if !s.admission.TryLock() {
			s.operation.Unlock()
			s.transition.Unlock()
			continue
		}
		delete(m.reclaim, s)
		m.reapStateLocked(s, oldestRequest)
		s.admission.Unlock()
		s.operation.Unlock()
		s.transition.Unlock()
	}
}

func (m *delegationManager) reapStateLocked(s *delegationState, oldestRequest uint64) {
	floor, retained := m.buf.RetainedGeneration(s.identity)
	m.tokenMu.Lock()
	if !retained && m.buf.Quiescent(s.identity) {
		for token := range s.flushTokens {
			delete(m.tokens, token)
		}
		s.flushTokens = nil
	}
	tokens := len(s.flushTokens)
	m.tokenMu.Unlock()
	previousBindings := len(s.bindings)
	for generation := range s.bindings {
		if generation < floor || !retained && s.ref == nil {
			delete(s.bindings, generation)
		}
	}
	if previousBindings > 8 && len(s.bindings) < previousBindings/4 {
		bindings := make(map[uint64]delegationBinding, len(s.bindings))
		for generation, binding := range s.bindings {
			bindings[generation] = binding
		}
		s.bindings = bindings
	}
	if retained || tokens != 0 || len(s.bindings) > 1 {
		m.retainedStates[s] = struct{}{}
	} else {
		delete(m.retainedStates, s)
	}
	if s.ref != nil || s.releaseFlight != nil || len(s.handles) != 0 || m.observers[s.identity] != 0 {
		s.collectCut = false
		return
	}
	if !s.collectCut {
		s.collectThrough, s.collectCut = m.grantSerial, true
	}
	if oldestRequest != 0 && oldestRequest <= s.collectThrough {
		// A response that began before retirement can still register this grant.
		// Ending an active request retries this bounded set; later creates do not
		// extend the cut or require a globally quiet namespace.
		m.reclaim[s] = struct{}{}
		return
	}
	if retained {
		return
	}
	if s.retire != nil {
		if err := s.retire.Resume(); err != nil {
			return
		}
		s.retire = nil
	}
	// The mount loss counter and root barrier observations live independently.
	// Per-identity history is now unobservable by any existing file handle.
	m.buf.ClearLost(s.identity)
	if !m.buf.Forget(s.identity) {
		return
	}
	s.collected = true
	delete(m.identityLoss, s.identity)
	delete(m.byID, s.identity)
	delete(m.retainedStates, s)
	m.stateIndex.Delete(s.identity)
	delete(m.reclaim, s)
}

func (m *delegationManager) beginLossObserver(identity []byte) uint64 {
	id, err := delegationIdentity(identity)
	if err != nil {
		return 0
	}
	m.epoch.RLock()
	defer m.epoch.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.observers[id]++
	return max(m.identityLoss[id], m.buf.IdentityLoss(id))
}

func (m *delegationManager) endLossObserver(identity []byte) {
	id, err := delegationIdentity(identity)
	if err != nil {
		return
	}
	m.mu.Lock()
	if m.observers[id] <= 1 {
		delete(m.observers, id)
		delete(m.identityLoss, id)
		if s := m.byID[id]; s != nil {
			m.reclaim[s] = struct{}{}
		}
	} else {
		m.observers[id]--
	}
	m.mu.Unlock()
	m.kickReclaim()
}

func (h *fileHandle) endLossObservation() {
	if h != nil && h.lossObserver != nil {
		h.lossObserverOnce.Do(h.lossObserver)
	}
}

func (s *delegationState) trackFlushTokenLocked(token uint64) {
	if s.flushTokens == nil {
		s.flushTokens = make(map[uint64]struct{})
	}
	s.flushTokens[token] = struct{}{}
}

// Prefix progress can retire records on many files. Ordinary lookups and
// admissions enqueue only their own state, so a read never scans a dirty mount.
func (m *delegationManager) reconsiderRetained() {
	m.mu.Lock()
	for s := range m.retainedStates {
		m.reclaim[s] = struct{}{}
	}
	m.mu.Unlock()
	m.kickReclaim()
}

func (m *delegationManager) beginGrantRequest() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.grantSerial == ^uint64(0) {
		return 0, errors.New("fusev3: grant request serial exhausted")
	}
	m.grantSerial++
	request := m.grantSerial
	m.grantRequests[request] = struct{}{}
	return request, nil
}

func (m *delegationManager) endGrantRequest(request uint64) {
	m.mu.Lock()
	delete(m.grantRequests, request)
	m.mu.Unlock()
	m.kickReclaim()
}
