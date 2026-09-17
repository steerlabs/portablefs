//go:build linux

package fusev3

import "github.com/steerlabs/portablefs/vcs/internal/authoritypb"

type posixLockKey struct {
	identity publicationIdentity
	owner    uint64
}

func (n *node) posixLockKey(owner uint64) posixLockKey {
	var key posixLockKey
	copy(key.identity[:], n.item.GetStableIdentity())
	key.owner = owner
	return key
}

// Mark before sending an acquisition: even an uncertain result may hold a lock.
// Generations prevent a close receipt from erasing a later acquisition attempt.
func (m *Mount) notePOSIXLock(key posixLockKey) {
	m.posixMu.Lock()
	defer m.posixMu.Unlock()
	if m.posixLocks == nil {
		m.posixLocks = make(map[posixLockKey]uint64)
	}
	m.posixSequence++
	if m.posixSequence == 0 {
		panic("fusev3: POSIX lock generation exhausted")
	}
	m.posixLocks[key] = m.posixSequence
}

func (m *Mount) possiblePOSIXLock(key posixLockKey) uint64 {
	m.posixMu.Lock()
	defer m.posixMu.Unlock()
	return m.posixLocks[key]
}

func (m *Mount) dischargePOSIXLock(key posixLockKey, generation uint64) {
	m.posixMu.Lock()
	defer m.posixMu.Unlock()
	if m.posixLocks[key] == generation {
		delete(m.posixLocks, key)
	}
}

func (m *delegationManager) ownsFull(identity []byte) bool {
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
	return s.ref != nil && s.mode == authoritypb.DelegationMode_DELEGATION_MODE_FULL
}
