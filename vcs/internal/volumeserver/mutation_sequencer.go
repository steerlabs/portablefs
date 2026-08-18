package volumeserver

import (
	"container/list"
	"context"
	"sort"
	"sync"
)

// MutationDependencies is the complete stable-identity footprint which one
// cache-visible mutation must own from PREPARE through COMPLETE. Keys use the
// same domain-separated encodings as the visibility index: an inode key covers
// data and attributes, while a name key covers one positive or negative
// namespace binding.
//
// The schema closes every cache-observation conflict:
//
//   - data and attribute mutations own the affected inode identity;
//   - a namespace mutation owns its parent inode (directory attributes), its
//     exact parent/name binding, and every inode currently bound there;
//   - rename is the union for both bindings, so it owns both parents, the moved
//     inode, and a replacement inode when one exists;
//   - link additionally owns its existing inode, and copy_file_range owns both
//     endpoint inodes.
//
// Consequently rename and create at one target share the target name; unlink
// and write share the bound inode; renames in one directory share its parent;
// rmdir and a child create share the removed directory identity; and range
// copies conflict with mutation of either endpoint. Operations with no shared
// cached observation have no shared key and may execute concurrently.
type MutationDependencies struct {
	keys []string
}

func newMutationDependencies(keys ...[]byte) MutationDependencies {
	encoded := make([]string, 0, len(keys))
	for _, key := range keys {
		if len(key) != 0 {
			encoded = append(encoded, string(key))
		}
	}
	sort.Strings(encoded)
	write := 0
	for _, key := range encoded {
		if write != 0 && encoded[write-1] == key {
			continue
		}
		encoded[write] = key
		write++
	}
	return MutationDependencies{keys: encoded[:write]}
}

func mutationDependenciesForTargets(targets []VisibilityTarget) MutationDependencies {
	keys := make([][]byte, 0, len(targets)*2)
	for _, target := range targets {
		keys = append(keys, target.key())
		if target.Scope == VisibilityNamespace {
			keys = append(keys, inodeKey(target.ParentIdentity))
			for _, identity := range target.RelatedIdentities {
				keys = append(keys, inodeKey(identity))
			}
		}
	}
	return newMutationDependencies(keys...)
}

// MutationDependenciesForTargets is the explicit dependency declaration for a
// caller that already has an authority-derived visibility footprint. Normal
// protocol-5 filesystem requests use DeclareSourceGate so binding identities
// can be version-checked across their XFS resolution.
func MutationDependenciesForTargets(targets []VisibilityTarget) MutationDependencies {
	return mutationDependenciesForTargets(targets)
}

func mutationDependenciesForSourceGate(gate SourcePublicationGate) MutationDependencies {
	keys := make([][]byte, 0, len(gate.Targets)*3)
	for _, target := range gate.Targets {
		if !target.namespace() {
			keys = append(keys, inodeKey(target.Identity))
			continue
		}
		keys = append(keys, inodeKey(target.ParentIdentity), nameKey(target.ParentIdentity, target.Name))
		for _, identity := range target.BoundIdentities {
			keys = append(keys, inodeKey(identity))
		}
	}
	return newMutationDependencies(keys...)
}

func bindingDependenciesForSourceGate(gate SourcePublicationGate) MutationDependencies {
	keys := make([][]byte, 0, len(gate.Targets))
	for _, target := range gate.Targets {
		if target.namespace() {
			keys = append(keys, nameKey(target.ParentIdentity, target.Name))
		}
	}
	return newMutationDependencies(keys...)
}

func (d MutationDependencies) valid() bool {
	if len(d.keys) == 0 {
		return false
	}
	for index, key := range d.keys {
		canonicalLength := len(key) > 0 && ((key[0] == 'i' && len(key) == 17) || (key[0] == 'n' && len(key) > 17))
		if !canonicalLength || index != 0 && d.keys[index-1] >= key {
			return false
		}
	}
	return true
}

func (d MutationDependencies) equal(other MutationDependencies) bool {
	if len(d.keys) != len(other.keys) {
		return false
	}
	for index := range d.keys {
		if d.keys[index] != other.keys[index] {
			return false
		}
	}
	return true
}

func (d MutationDependencies) covers(targets []VisibilityTarget) bool {
	for _, target := range targets {
		if !d.contains(target.key()) {
			return false
		}
		if target.Scope != VisibilityNamespace {
			continue
		}
		if !d.contains(inodeKey(target.ParentIdentity)) {
			return false
		}
		for _, identity := range target.RelatedIdentities {
			if !d.contains(inodeKey(identity)) {
				return false
			}
		}
	}
	return true
}

// dependencySnapshot detects whether any binding used to derive a dependency
// set changed before that set was acquired. Stable item identities need no
// snapshot; only parent/name resolution can change within an epoch. Watchers
// retain per-key versions only while a declaration is in flight, so a workload
// that continually creates new names cannot grow the registry without bound.
type dependencySnapshot struct {
	sequencer *mutationSequencer
	versions  map[string]uint64
	once      sync.Once
}

func (d DependencyDeclaration) validFor(gate SourcePublicationGate, sequencer *mutationSequencer) bool {
	bindings := bindingDependenciesForSourceGate(gate)
	if d.snapshot == nil || d.snapshot.sequencer != sequencer || len(d.snapshot.versions) != len(bindings.keys) {
		return false
	}
	for _, key := range bindings.keys {
		if _, ok := d.snapshot.versions[key]; !ok {
			return false
		}
	}
	return true
}

// mutationSequencer grants dependency sets atomically under one short registry
// lock. A waiter never holds a subset of its requested keys: it either owns all
// of them or none. Deadlock is therefore impossible. While scanning in ordinal
// order, a blocked waiter reserves every key it requested; a later waiter may
// pass only when disjoint. This is FIFO fairness on every key, and an operation
// waiting for several keys cannot be repeatedly overtaken on any one of them.
type mutationSequencer struct {
	mu          sync.Mutex
	nextOrdinal uint64
	held        map[string]*mutationSequencerWaiter
	versions    map[string]dependencyVersion
	waiters     list.List
}

type dependencyVersion struct {
	value    uint64
	watchers uint64
}

type mutationSequencerWaiter struct {
	sequencer *mutationSequencer
	ready     chan struct{}
	element   *list.Element
	keys      []string
	ordinal   uint64
	granted   bool
	settled   bool
}

func newMutationSequencer() *mutationSequencer {
	return &mutationSequencer{
		held:     make(map[string]*mutationSequencerWaiter),
		versions: make(map[string]dependencyVersion),
	}
}

func (s *mutationSequencer) nextOrdinalLocked() uint64 {
	s.nextOrdinal++
	if s.nextOrdinal == 0 {
		panic("volumeserver: mutation-sequencer ordinal exhausted")
	}
	return s.nextOrdinal
}

func (s *mutationSequencer) reserveOrdinal() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextOrdinalLocked()
}

func (s *mutationSequencer) snapshot(dependencies MutationDependencies) *dependencySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := &dependencySnapshot{sequencer: s, versions: make(map[string]uint64, len(dependencies.keys))}
	for _, key := range dependencies.keys {
		version := s.versions[key]
		version.watchers++
		if version.watchers == 0 {
			panic("volumeserver: mutation dependency watcher count exhausted")
		}
		s.versions[key] = version
		snapshot.versions[key] = version.value
	}
	return snapshot
}

func (s *mutationSequencer) unchanged(snapshot *dependencySnapshot) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	unchanged := true
	for key, version := range snapshot.versions {
		if s.versions[key].value != version {
			unchanged = false
		}
	}
	snapshot.once.Do(func() { s.releaseSnapshotLocked(snapshot) })
	return unchanged
}

func (s *mutationSequencer) releaseSnapshotLocked(snapshot *dependencySnapshot) {
	for key := range snapshot.versions {
		version := s.versions[key]
		if version.watchers == 0 {
			panic("volumeserver: mutation dependency watcher count underflow")
		}
		version.watchers--
		if version.watchers == 0 {
			delete(s.versions, key)
		} else {
			s.versions[key] = version
		}
	}
}

func (snapshot *dependencySnapshot) release() {
	if snapshot == nil || snapshot.sequencer == nil {
		return
	}
	snapshot.once.Do(func() {
		s := snapshot.sequencer
		s.mu.Lock()
		s.releaseSnapshotLocked(snapshot)
		s.mu.Unlock()
	})
}

func (s *mutationSequencer) enqueue(dependencies MutationDependencies) *mutationSequencerWaiter {
	return s.enqueueFor(dependencies, 0)
}

func (s *mutationSequencer) enqueueFor(dependencies MutationDependencies, reserved uint64) *mutationSequencerWaiter {
	if !dependencies.valid() {
		panic("volumeserver: mutation sequencer requires canonical dependencies")
	}
	w := &mutationSequencerWaiter{
		sequencer: s,
		ready:     make(chan struct{}),
		keys:      append([]string(nil), dependencies.keys...),
	}
	s.mu.Lock()
	if reserved == 0 {
		w.ordinal = s.nextOrdinalLocked()
	} else {
		w.ordinal = reserved
	}
	s.insertLocked(w)
	s.grantEligibleLocked()
	s.mu.Unlock()
	return w
}

func (s *mutationSequencer) insertLocked(w *mutationSequencerWaiter) {
	if back := s.waiters.Back(); back == nil || back.Value.(*mutationSequencerWaiter).ordinal <= w.ordinal {
		w.element = s.waiters.PushBack(w)
		return
	}
	for element := s.waiters.Front(); element != nil; element = element.Next() {
		if element.Value.(*mutationSequencerWaiter).ordinal > w.ordinal {
			w.element = s.waiters.InsertBefore(w, element)
			return
		}
	}
	w.element = s.waiters.PushBack(w)
}

func (s *mutationSequencer) acquire(ctx context.Context, dependencies MutationDependencies) (*mutationSequencerWaiter, error) {
	w := s.enqueue(dependencies)
	select {
	case <-w.ready:
		return w, nil
	case <-ctx.Done():
		w.abandon()
		return nil, ctx.Err()
	}
}

func (s *mutationSequencer) grantEligibleLocked() {
	reserved := make(map[string]struct{})
	for element := s.waiters.Front(); element != nil; {
		next := element.Next()
		w := element.Value.(*mutationSequencerWaiter)
		eligible := true
		for _, key := range w.keys {
			if s.held[key] != nil {
				eligible = false
			}
			if _, claimed := reserved[key]; claimed {
				eligible = false
			}
		}
		if !eligible {
			for _, key := range w.keys {
				reserved[key] = struct{}{}
			}
			element = next
			continue
		}
		s.waiters.Remove(element)
		w.element = nil
		w.granted = true
		for _, key := range w.keys {
			s.held[key] = w
		}
		close(w.ready)
		element = next
	}
}

func (s *mutationSequencer) releaseKeysLocked(w *mutationSequencerWaiter) {
	for _, key := range w.keys {
		if s.held[key] != w {
			panic("volumeserver: mutation sequencer lost key ownership")
		}
		delete(s.held, key)
		if version, watched := s.versions[key]; watched {
			version.value++
			if version.value == 0 {
				panic("volumeserver: mutation dependency version exhausted")
			}
			s.versions[key] = version
		}
	}
	w.granted = false
}

// requeue atomically gives up the old set and requests the corrected set at the
// same effective arrival ordinal. It is used after namespace revalidation. No
// later conflicting request can enter between release and reinsertion. A
// previously reserved older ordinal may pass, so Execute revalidates after each
// reacquisition; the finite set of older ordinals prevents livelock.
func (w *mutationSequencerWaiter) requeue(dependencies MutationDependencies) {
	if !dependencies.valid() {
		panic("volumeserver: mutation sequencer requeue requires canonical dependencies")
	}
	s := w.sequencer
	s.mu.Lock()
	if w.settled || !w.granted {
		s.mu.Unlock()
		panic("volumeserver: invalid mutation-sequencer requeue")
	}
	s.releaseKeysLocked(w)
	w.keys = append(w.keys[:0], dependencies.keys...)
	w.ready = make(chan struct{})
	s.insertLocked(w)
	s.grantEligibleLocked()
	s.mu.Unlock()
}

// abandon is safe on every cancel-vs-grant race. If the grant already won, it
// releases that exact set before returning.
func (w *mutationSequencerWaiter) abandon() {
	s := w.sequencer
	s.mu.Lock()
	if w.settled {
		s.mu.Unlock()
		return
	}
	w.settled = true
	if w.granted {
		s.releaseKeysLocked(w)
	} else if w.element != nil {
		s.waiters.Remove(w.element)
		w.element = nil
	}
	s.grantEligibleLocked()
	s.mu.Unlock()
}

func (w *mutationSequencerWaiter) release() {
	s := w.sequencer
	s.mu.Lock()
	if w.settled || !w.granted {
		s.mu.Unlock()
		panic("volumeserver: invalid mutation-sequencer release")
	}
	w.settled = true
	s.releaseKeysLocked(w)
	s.grantEligibleLocked()
	s.mu.Unlock()
}

// settle is the idempotent deferred form used by Execute. A requeued waiter may
// have abandoned itself on cancellation or a newly pending repair before the
// caller unwinds; that path has already released every key.
func (w *mutationSequencerWaiter) settle() {
	s := w.sequencer
	s.mu.Lock()
	if w.settled {
		s.mu.Unlock()
		return
	}
	if !w.granted {
		s.mu.Unlock()
		panic("volumeserver: unsettled mutation waiter owns no dependency set")
	}
	w.settled = true
	s.releaseKeysLocked(w)
	s.grantEligibleLocked()
	s.mu.Unlock()
}

func (s *mutationSequencer) queued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waiters.Len()
}

func (d MutationDependencies) contains(key []byte) bool {
	encoded := string(key)
	index := sort.SearchStrings(d.keys, encoded)
	return index != len(d.keys) && d.keys[index] == encoded
}
