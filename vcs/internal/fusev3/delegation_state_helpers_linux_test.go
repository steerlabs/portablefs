//go:build linux

package fusev3

import "github.com/steerlabs/portablefs/vcs/internal/writeback"

// Test inspection only. Production state access must hold a scoped reference.
func (m *delegationManager) state(id writeback.Identity) *delegationState {
	if s := m.lookupState(id); s != nil {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.byID[id]
	if s == nil {
		s = &delegationState{manager: m, grantChanged: make(chan struct{}), identity: id, handles: make(map[string][]byte), writers: make(map[string][]byte), bindings: make(map[uint64]delegationBinding)}
		m.byID[id] = s
		m.stateIndex.Store(id, s)
	}
	return s
}

func (m *delegationManager) lookupState(id writeback.Identity) *delegationState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byID[id]
}
