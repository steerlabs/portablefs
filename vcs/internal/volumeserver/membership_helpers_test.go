package volumeserver

import "sync"

type testDurableMountMembership struct {
	mu     sync.Mutex
	active map[SessionID]MountMembershipProfile
}

type faultMountMembership struct {
	mu            sync.Mutex
	active        map[SessionID]MountMembershipProfile
	activateErr   error
	deactivateErr error
}

func newFaultMountMembership() *faultMountMembership {
	return &faultMountMembership{active: make(map[SessionID]MountMembershipProfile)}
}

func (*faultMountMembership) PriorCacheState() (PriorEpochDisposition, bool) {
	return PriorEpochStrictMountsFenced, false
}

func (m *faultMountMembership) ActivateProfile(id SessionID, profile MountMembershipProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activateErr != nil {
		return m.activateErr
	}
	m.active[id] = profile
	return nil
}

func (m *faultMountMembership) Deactivate(id SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deactivateErr != nil {
		return m.deactivateErr
	}
	delete(m.active, id)
	return nil
}

func (m *faultMountMembership) contains(id SessionID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.active[id]
	return ok
}

func newTestDurableMountMembership() *testDurableMountMembership {
	return &testDurableMountMembership{active: make(map[SessionID]MountMembershipProfile)}
}

func (*testDurableMountMembership) PriorCacheState() (PriorEpochDisposition, bool) {
	return PriorEpochStrictMountsFenced, false
}

func (m *testDurableMountMembership) ActivateProfile(id SessionID, profile MountMembershipProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[id] = profile
	return nil
}

func (m *testDurableMountMembership) Deactivate(id SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.active, id)
	return nil
}

func (m *testDurableMountMembership) contains(id SessionID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.active[id]
	return ok
}

// testFencer stands in for the authority runtime: fencing a session ends it,
// which is what closes the terminal channel the coordinator watches.

func testVisibilityParent() [16]byte {
	var parent [16]byte
	parent[0] = 1
	return parent
}
func testMutationTargets(name string) []MutationTarget {
	return []MutationTarget{{
		Scope:           MutationNamespace,
		ParentIdentity:  testVisibilityParent(),
		ParentKernelIno: 101,
		Name:            []byte(name),
	}}
}
func testMutationDependencies(name string) MutationDependencies {
	return mutationDependenciesForTargets(testMutationTargets(name))
}
func testMutationFootprint(name string) MutationFootprint {
	return MutationFootprint{Targets: []FootprintTarget{{
		ParentIdentity: testVisibilityParent(), Name: []byte(name), BoundAttributes: true,
	}}}
}

func bindingDependenciesForFootprint(gate MutationFootprint) MutationDependencies {
	keys := make([][]byte, 0, len(gate.Targets))
	for _, target := range gate.Targets {
		if target.namespace() {
			keys = append(keys, nameKey(target.ParentIdentity, target.Name))
		}
	}
	return newMutationDependencies(keys...)
}
