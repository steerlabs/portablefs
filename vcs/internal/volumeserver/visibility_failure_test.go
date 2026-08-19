package volumeserver

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testCacheCapacity = 1024
	testRepairBudget  = 5 * time.Second
)

type testDurableVisibilityMembership struct {
	mu     sync.Mutex
	active map[SessionID]bool
}

type faultVisibilityMembership struct {
	mu            sync.Mutex
	active        map[SessionID]bool
	activateErr   error
	deactivateErr error
}

func newFaultVisibilityMembership() *faultVisibilityMembership {
	return &faultVisibilityMembership{active: make(map[SessionID]bool)}
}

func (m *faultVisibilityMembership) Activate(id SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activateErr != nil {
		return m.activateErr
	}
	m.active[id] = true
	return nil
}

func (m *faultVisibilityMembership) Deactivate(id SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deactivateErr != nil {
		return m.deactivateErr
	}
	delete(m.active, id)
	return nil
}

func (m *faultVisibilityMembership) contains(id SessionID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[id]
}

func newTestDurableVisibilityMembership() *testDurableVisibilityMembership {
	return &testDurableVisibilityMembership{active: make(map[SessionID]bool)}
}

func (m *testDurableVisibilityMembership) Activate(id SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[id] = true
	return nil
}

func (m *testDurableVisibilityMembership) Deactivate(id SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.active, id)
	return nil
}

func (m *testDurableVisibilityMembership) contains(id SessionID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[id]
}

// testFencer stands in for the authority runtime: fencing a session ends it,
// which is what closes the terminal channel the coordinator watches.
type testFencer struct {
	mu        sync.Mutex
	terminals map[SessionID]chan struct{}
	fenced    []SessionID
}

// concurrentFenceProbe holds every fencing action at the point where the
// authority session would be ended. A barrier waiting for several failed
// participants must reach this point for all of them before any one's
// post-fence grace is allowed to begin.
type concurrentFenceProbe struct {
	started chan SessionID
	release chan struct{}
}

func (f *concurrentFenceProbe) FenceSession(id SessionID) {
	f.started <- id
	<-f.release
}

func newTestFencer() *testFencer {
	return &testFencer{terminals: make(map[SessionID]chan struct{})}
}

func (f *testFencer) attach(id SessionID) chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	terminal := make(chan struct{})
	f.terminals[id] = terminal
	return terminal
}

func (f *testFencer) FenceSession(id SessionID) {
	f.mu.Lock()
	terminal := f.terminals[id]
	delete(f.terminals, id)
	if terminal != nil {
		f.fenced = append(f.fenced, id)
	}
	f.mu.Unlock()
	if terminal != nil {
		close(terminal)
	}
}

// die simulates an unclean death: the session ends without the coordinator
// asking for it, exactly as a slept laptop or a dropped transport does.
func (f *testFencer) die(id SessionID) { f.FenceSession(id) }

func (f *testFencer) wasFenced(id SessionID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, fenced := range f.fenced {
		if fenced == id {
			return true
		}
	}
	return false
}

func (f *testFencer) live(id SessionID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.terminals[id]
	return ok
}

type visibilityHarness struct {
	coordinator *VisibilityCoordinator
	membership  *testDurableVisibilityMembership
	fencer      *testFencer

	fenceMu     sync.Mutex
	fenceReason map[SessionID]error
}

func newVisibilityHarness(t *testing.T, prior PriorEpochDisposition) *visibilityHarness {
	t.Helper()
	membership := newTestDurableVisibilityMembership()
	fencer := newTestFencer()
	h := &visibilityHarness{membership: membership, fencer: fencer, fenceReason: make(map[SessionID]error)}
	coordinator, err := NewVisibilityCoordinator(VisibilityConfig{
		Prior: prior, Membership: membership, Fencer: fencer,
		MaxCachedNameCapacity: 1 << 20, MaxRepairBudget: time.Minute, MaxClockSkew: 0,
		OnFence: func(id SessionID, reason error) {
			h.fenceMu.Lock()
			defer h.fenceMu.Unlock()
			h.fenceReason[id] = reason
		},
	})
	if err != nil {
		t.Fatalf("construct visibility coordinator: %v", err)
	}
	h.coordinator = coordinator
	return h
}

func newFaultVisibilityCoordinator(t *testing.T, membership DurableVisibilityMembership, fencer SessionFencer) *VisibilityCoordinator {
	t.Helper()
	coordinator, err := NewVisibilityCoordinator(VisibilityConfig{
		Prior: PriorEpochStrictMountsFenced, Membership: membership, Fencer: fencer,
		MaxCachedNameCapacity: 1 << 20, MaxRepairBudget: time.Minute, MaxClockSkew: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func testVisibilityCommitment() VisibilityCommitment {
	return VisibilityCommitment{
		CachedNameCapacity: testCacheCapacity,
		RepairBudget:       testRepairBudget,
		NamespaceRepair:    NamespaceRepairParentExclusive,
	}
}

func initialVisibilityCursor(t *testing.T, coordinator *VisibilityCoordinator, id SessionID) VisibilityCursor {
	t.Helper()
	cursor, err := coordinator.InitialCursor(id)
	if err != nil {
		t.Fatalf("initial visibility cursor for %x: %v", id, err)
	}
	return cursor
}

func nextFromInitialVisibilityCursor(t *testing.T, coordinator *VisibilityCoordinator, ctx context.Context, id SessionID) (VisibilityEvent, error) {
	t.Helper()
	cursor, err := coordinator.InitialCursor(id)
	if err != nil {
		return VisibilityEvent{}, err
	}
	return coordinator.Next(ctx, id, cursor)
}

func TestActivateParticipantMembershipFailureNeverCommitsRuntime(t *testing.T) {
	membership := newFaultVisibilityMembership()
	membership.activateErr = errors.New("membership write failed")
	fencer := newTestFencer()
	id := SessionID{41}
	terminal := fencer.attach(id)
	coordinator := newFaultVisibilityCoordinator(t, membership, fencer)
	committed := false
	_, err := coordinator.ActivateParticipant(id, CoherenceStrict, terminal, testVisibilityCommitment(), nil, func() {
		committed = true
	})
	if err == nil || committed || membership.contains(id) {
		t.Fatalf("membership failure = %v, committed=%t durable=%t", err, committed, membership.contains(id))
	}
	if _, err := coordinator.InitialCursor(id); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("failed activation installed participant: %v", err)
	}
}

func TestActivateParticipantCommitFailureRollsBackMembership(t *testing.T) {
	membership := newFaultVisibilityMembership()
	fencer := newTestFencer()
	id := SessionID{42}
	terminal := fencer.attach(id)
	coordinator := newFaultVisibilityCoordinator(t, membership, fencer)
	commitErr := errors.New("runtime precommit failed")
	_, err := coordinator.ActivateParticipant(id, CoherenceStrict, terminal, testVisibilityCommitment(), func(VisibilityCursor) ([][16]byte, error) {
		return nil, commitErr
	}, func() { t.Fatal("failed precommit reached commit") })
	if !errors.Is(err, commitErr) || membership.contains(id) {
		t.Fatalf("commit failure = %v durable=%t", err, membership.contains(id))
	}
	if _, err := coordinator.InitialCursor(id); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("rolled-back participant remains installed: %v", err)
	}
	applied := false
	if err := coordinator.Execute(context.Background(), SessionID{99}, MutationID{Sequence: 1},
		testMutationDependencies("rollback-health"),
		testVisibilityPrepare("rollback-health"),
		func() ([]VisibilityTarget, bool) { applied = true; return nil, false }); !errors.Is(err, ErrVisibilityProfile) || applied {
		t.Fatalf("mutation after last participant rolled back = %v, applied=%t, want strict-profile refusal before apply", err, applied)
	}
}

func TestActivateParticipantRollbackFailurePoisonsCoordinator(t *testing.T) {
	membership := newFaultVisibilityMembership()
	membership.deactivateErr = errors.New("membership rollback failed")
	fencer := newTestFencer()
	id := SessionID{43}
	terminal := fencer.attach(id)
	coordinator := newFaultVisibilityCoordinator(t, membership, fencer)
	commitErr := errors.New("runtime precommit failed")
	_, err := coordinator.ActivateParticipant(id, CoherenceStrict, terminal, testVisibilityCommitment(), func(VisibilityCursor) ([][16]byte, error) {
		return nil, commitErr
	}, func() { t.Fatal("failed precommit reached commit") })
	if !errors.Is(err, commitErr) || !errors.Is(err, ErrVisibilityPoisoned) || !membership.contains(id) {
		t.Fatalf("rollback failure = %v durable=%t", err, membership.contains(id))
	}
	err = coordinator.Execute(context.Background(), SessionID{99}, MutationID{Sequence: 1},
		testMutationDependencies("poisoned"),
		func() ([]VisibilityTarget, error) { return nil, nil },
		func() ([]VisibilityTarget, bool) { t.Fatal("poisoned coordinator applied mutation"); return nil, false })
	if !errors.Is(err, ErrVisibilityPoisoned) {
		t.Fatalf("Execute after rollback failure = %v, want poison", err)
	}
}

func TestActivateParticipantExcludesMutationUntilCommitVerdict(t *testing.T) {
	membership := newFaultVisibilityMembership()
	fencer := newTestFencer()
	id := SessionID{44}
	terminal := fencer.attach(id)
	coordinator := newFaultVisibilityCoordinator(t, membership, fencer)
	commitStarted := make(chan struct{})
	releaseCommit := make(chan struct{})
	commitErr := errors.New("injected precommit refusal")
	activationDone := make(chan error, 1)
	go func() {
		_, err := coordinator.ActivateParticipant(id, CoherenceStrict, terminal, testVisibilityCommitment(), func(VisibilityCursor) ([][16]byte, error) {
			close(commitStarted)
			<-releaseCommit
			return nil, commitErr
		}, func() { t.Error("failed precommit reached commit") })
		activationDone <- err
	}()
	<-commitStarted
	prepareCalled := make(chan struct{})
	executeDone := make(chan error, 1)
	go func() {
		executeDone <- coordinator.Execute(context.Background(), SessionID{90}, MutationID{Sequence: 1},
			testMutationDependencies("excluded"),
			func() ([]VisibilityTarget, error) {
				close(prepareCalled)
				return testVisibilityTargets("excluded"), nil
			},
			func() ([]VisibilityTarget, bool) { return nil, false })
	}()
	select {
	case <-prepareCalled:
		t.Fatal("mutation crossed visibility/runtime activation transaction")
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseCommit)
	if err := <-activationDone; !errors.Is(err, commitErr) {
		t.Fatalf("activation = %v", err)
	}
	select {
	case <-prepareCalled:
		t.Fatal("mutation prepared after the only participant rolled back")
	case err := <-executeDone:
		if !errors.Is(err, ErrVisibilityProfile) {
			t.Fatalf("mutation after activation rollback = %v, want strict-profile refusal", err)
		}
	case <-time.After(time.Second):
		t.Fatal("mutation did not receive activation rollback verdict")
	}
}

func TestActivateParticipantCommitsPreparedRuntimeAtExactCursor(t *testing.T) {
	a, now := testAuthority(t)
	attempt := AttachAttemptID{45}
	cred := prepareTestSession(t, a, now, attempt)
	terminal, err := a.SessionTerminal(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	membership := newFaultVisibilityMembership()
	coordinator := newFaultVisibilityCoordinator(t, membership, a)
	token, err := a.PrepareActivation(context.Background(), cred, attempt)
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	defer func() {
		if !committed {
			a.CancelActivation(token)
		}
	}()
	rootIdentity := [16]byte{7}
	var preparedCursor VisibilityCursor
	initial, err := coordinator.ActivateParticipant(cred.ID, CoherenceStrict, terminal, testVisibilityCommitment(), func(cursor VisibilityCursor) ([][16]byte, error) {
		preparedCursor = cursor
		return [][16]byte{rootIdentity}, nil
	}, func() {
		coordinator.mu.Lock()
		participant := coordinator.participants[cred.ID]
		covered := participant != nil && participant.index.contains(inodeKey(rootIdentity))
		coordinator.mu.Unlock()
		if !covered {
			t.Error("runtime commit preceded initial root coverage")
		}
		a.CommitActivation(token)
		committed = true
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := coordinator.InitialCursor(cred.ID); err != nil || got != initial {
		t.Fatalf("initial cursor = %+v, %v; transaction returned %+v", got, err, initial)
	}
	if preparedCursor != initial {
		t.Fatalf("precommit cursor = %+v, transaction returned %+v", preparedCursor, initial)
	}
	if !membership.contains(cred.ID) {
		t.Fatal("runtime became active without durable membership")
	}
	use, err := a.Begin(cred)
	if err != nil {
		t.Fatalf("transaction did not activate runtime: %v", err)
	}
	use.End()
}

// fenceReasonFor is why a mount left the barrier. The reason is part of the
// contract, not diagnostics: "provably cannot repair" and "did not answer in
// time" are different facts about a mount and an operator has to be able to
// tell them apart.
func (h *visibilityHarness) fenceReasonFor(id SessionID) error {
	h.fenceMu.Lock()
	defer h.fenceMu.Unlock()
	return h.fenceReason[id]
}

func (h *visibilityHarness) register(t *testing.T, id SessionID, budget time.Duration) {
	t.Helper()
	h.registerRepair(t, id, budget, NamespaceRepairParentExclusive)
}

// registerRepair admits one strict participant with an explicit namespace-repair
// model. The model is never defaulted, here or on the wire: it decides whether a
// mount that is not answering is provably unable to or merely slow.
func (h *visibilityHarness) registerRepair(t *testing.T, id SessionID, budget time.Duration, repair NamespaceRepair) {
	t.Helper()
	terminal := h.fencer.attach(id)
	commitment := VisibilityCommitment{CachedNameCapacity: testCacheCapacity, RepairBudget: budget, NamespaceRepair: repair}
	if err := h.coordinator.Register(id, CoherenceStrict, terminal, commitment); err != nil {
		t.Fatalf("register strict participant: %v", err)
	}
	t.Cleanup(func() { h.fencer.FenceSession(id) })
}

// resolve makes a participant a plausible holder of these names. Fan-out is
// scoped to what a mount actually resolved, so a test that wants a participant
// in a barrier has to give it a reason to be there.
func (h *visibilityHarness) resolve(t *testing.T, id SessionID, names ...string) {
	t.Helper()
	for _, name := range names {
		h.coordinator.RecordResolvedName(id, testVisibilityParent(), []byte(name))
	}
}

func testVisibilityParent() [16]byte {
	var parent [16]byte
	parent[0] = 1
	return parent
}

func testVisibilityTargets(name string) []VisibilityTarget {
	return []VisibilityTarget{{
		Scope:           VisibilityNamespace,
		ParentIdentity:  testVisibilityParent(),
		ParentKernelIno: 101,
		Name:            []byte(name),
	}}
}

func testVisibilityPrepare(name string) func() ([]VisibilityTarget, error) {
	return func() ([]VisibilityTarget, error) { return testVisibilityTargets(name), nil }
}

func testExactVisibilityTargets(sequence uint64, targets []VisibilityTarget) []VisibilityTarget {
	exact := cloneVisibilityTargets(targets)
	for index := range exact {
		target := &exact[index]
		if target.Scope == VisibilityNamespace {
			continue
		}
		target.ExactPostState = &VisibilityObjectPostState{
			StableIdentity: target.Identity,
			ObjectVersion:  sequence,
			Roles:          1,
			Attr: VisibilityAttr{
				Kind: 1, Inode: target.KernelIno, Size: target.Size,
			},
		}
	}
	return exact
}

func executeTestExact(
	coordinator *VisibilityCoordinator,
	ctx context.Context,
	source SessionID,
	mutation MutationID,
	dependencies MutationDependencies,
	prepare func() ([]VisibilityTarget, error),
	apply func() ([]VisibilityTarget, bool),
) error {
	return coordinator.execute(ctx, source, mutation, dependencies, DependencyDeclaration{}, nil, nil, nil, prepare,
		func(sequence uint64) ([]VisibilityTarget, bool) {
			targets, changed := apply()
			if changed {
				targets = testExactVisibilityTargets(sequence, targets)
			}
			return targets, changed
		}, nil)
}

func executeTestExactWithSourceGate(
	coordinator *VisibilityCoordinator,
	ctx context.Context,
	source SessionID,
	mutation MutationID,
	declaration DependencyDeclaration,
	gate SourcePublicationGate,
	refresh func() (SourcePublicationGate, error),
	prepare func() ([]VisibilityTarget, error),
	apply func() ([]VisibilityTarget, bool),
	published func() ([]VisibilityResolution, error),
) error {
	_, err := coordinator.ExecuteWithSourceGateSequence(ctx, source, mutation, declaration, gate, refresh, prepare,
		func(sequence uint64) ([]VisibilityTarget, bool) {
			targets, changed := apply()
			if changed {
				targets = testExactVisibilityTargets(sequence, targets)
			}
			return targets, changed
		}, published)
	return err
}

func testMutationDependencies(name string) MutationDependencies {
	return mutationDependenciesForTargets(testVisibilityTargets(name))
}

func testSourcePublicationGate(name string) SourcePublicationGate {
	return SourcePublicationGate{Targets: []SourcePublicationTarget{{
		ParentIdentity: testVisibilityParent(), Name: []byte(name), BoundAttributes: true,
	}}}
}

func executeTestSourceGated(
	coordinator *VisibilityCoordinator,
	ctx context.Context,
	source SessionID,
	mutation MutationID,
	name string,
	prepare func() ([]VisibilityTarget, error),
	apply func() ([]VisibilityTarget, bool),
) error {
	gate := testSourcePublicationGate(name)
	declaration := coordinator.DeclareSourceGate(gate)
	_, err := coordinator.ExecuteWithSourceGateSequence(ctx, source, mutation, declaration, gate,
		func() (SourcePublicationGate, error) { return gate, nil },
		prepare, func(sequence uint64) ([]VisibilityTarget, bool) {
			targets, changed := apply()
			if changed {
				targets = testExactVisibilityTargets(sequence, targets)
			}
			return targets, changed
		},
		func() ([]VisibilityResolution, error) { return nil, nil },
	)
	return err
}

func executeTestSourceGatedHeld(
	coordinator *VisibilityCoordinator,
	ctx context.Context,
	source SessionID,
	mutation MutationID,
	name string,
	held [][16]byte,
	prepare func() ([]VisibilityTarget, error),
	apply func() ([]VisibilityTarget, bool),
) error {
	gate := testSourcePublicationGate(name)
	declaration := coordinator.DeclareSourceGate(gate)
	_, err := coordinator.ExecuteWithSourceGateAndHeldParentsSequence(ctx, source, mutation, declaration, gate, held,
		func() (SourcePublicationGate, error) { return gate, nil },
		prepare, func(sequence uint64) ([]VisibilityTarget, bool) {
			targets, changed := apply()
			if changed {
				targets = testExactVisibilityTargets(sequence, targets)
			}
			return targets, changed
		},
		func() ([]VisibilityResolution, error) { return nil, nil },
	)
	return err
}

func TestVisibilityRetryProofSecondPassAbandonsExistingWaiter(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairLocklessExpiration)
	gate := testSourcePublicationGate("proof-wedge")
	dependencies := mutationDependenciesForSourceGate(gate)
	owner, err := h.coordinator.sequencer.acquire(t.Context(), dependencies)
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, acquireErr := h.coordinator.acquireMutationDependencies(
			context.Background(), source, MutationID{Sequence: 1, FrontendOperationID: 77},
			nil, &gate, dependencies, nil,
		)
		result <- acquireErr
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)

	// Install the exact same-operation debt after the first pass enqueued. The
	// participant signal forces a second loop iteration, where omission of the
	// proof is rejected while turn is already non-nil.
	h.coordinator.mu.Lock()
	h.coordinator.fairness[source] = mutationFairnessDebt{
		sequence: 9, ordinal: h.coordinator.sequencer.reserveOrdinal(),
		operationID: 77, claimSameOperation: true,
		gate: cloneSourcePublicationGate(gate), observed: true,
	}
	h.coordinator.participants[source].signalLocked()
	h.coordinator.mu.Unlock()
	if err := <-result; !errors.Is(err, ErrSourcePublicationGate) {
		t.Fatalf("second-pass retry-proof rejection = %v, want ErrSourcePublicationGate", err)
	}
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 0)
	owner.release()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	probe, err := h.coordinator.sequencer.acquire(ctx, dependencies)
	if err != nil {
		t.Fatalf("retry-proof rejection wedged dependency keys: %v", err)
	}
	probe.release()
}

func testMountAbsence(observed time.Time) MountAbsenceProof {
	return MountAbsenceProof{
		ObservedUnixNanos: observed.UnixNano(),
		Observation:       []byte("fsid=0x2f1a mount-table-generation=41"),
		Component:         "test-mount-observer",
	}
}

// runBarrier services one participant's PREPARE and COMPLETE for one mutation.
func runBarrier(t *testing.T, coordinator *VisibilityCoordinator, id SessionID, after VisibilityCursor) VisibilityCursor {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := coordinator.Next(ctx, id, after)
	if err != nil {
		t.Fatalf("prepare for %x: %v", id, err)
	}
	if err := coordinator.Ack(id, prepare.Cursor); err != nil {
		t.Fatalf("ack prepare for %x: %v", id, err)
	}
	complete, err := coordinator.Next(ctx, id, prepare.Cursor)
	if err != nil {
		t.Fatalf("complete for %x: %v", id, err)
	}
	if err := coordinator.Ack(id, complete.Cursor); err != nil {
		t.Fatalf("ack complete for %x: %v", id, err)
	}
	return complete.Cursor
}

// One laptop going to sleep must not stop a production server. The lost mount
// is fenced individually and the volume keeps serving; freezing the epoch would
// not un-stale the departed cache, it would only stop the healthy machines.
func TestVisibilityParticipantLossFencesOnlyThatMount(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	lost, survivor := SessionID{1}, SessionID{2}
	// If the terminal watcher loses the scheduling race with dispatch, the
	// already-dead participant can still be in this phase's audience and must
	// receive the same conservative deadline-plus-grace treatment.
	h.register(t, lost, 80*time.Millisecond)
	h.register(t, survivor, testRepairBudget)
	h.resolve(t, lost, "prepare")
	h.resolve(t, survivor, "prepare")

	h.fencer.die(lost)
	// The watchdog observes the death asynchronously; the barrier below is what
	// must survive it either way.
	var applied atomic.Bool
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("prepare"),
			testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
				applied.Store(true)
				return testVisibilityTargets("prepare"), true
			})
	}()
	complete := runBarrier(t, h.coordinator, survivor, initialVisibilityCursor(t, h.coordinator, survivor))
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("mutation after one mount was lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("one lost mount blocked the whole volume")
	}
	if !applied.Load() {
		t.Fatal("the filesystem mutation never ran")
	}
	if !h.membership.contains(lost) {
		t.Fatal("an unclean loss cleared durable membership without kernel-unmount proof")
	}
	// The epoch is not poisoned: a further mutation and a further attach both
	// still work.
	second := make(chan error, 1)
	go func() {
		second <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 2},
			testMutationDependencies("prepare"),
			testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("prepare"), true
			})
	}()
	runBarrier(t, h.coordinator, survivor, complete)
	if err := <-second; err != nil {
		t.Fatalf("second mutation after a participant-scoped fence: %v", err)
	}
	h.register(t, SessionID{3}, testRepairBudget)
}

// A participant that blows the repair budget it committed to is fenced exactly
// like one that died, and for the same reason: the authority cannot wait on it,
// and its own budget timer obliges it to revoke its mount.
func TestVisibilityDeadlineFencesOneParticipantAndCompletes(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	wedged, healthy := SessionID{1}, SessionID{2}
	const wedgedBudget = 60 * time.Millisecond
	h.register(t, wedged, wedgedBudget)
	h.register(t, healthy, testRepairBudget)
	h.resolve(t, wedged, "prepare")
	h.resolve(t, healthy, "prepare")

	result := make(chan error, 1)
	started := time.Now()
	go func() {
		result <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("prepare"),
			testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("prepare"), true
			})
	}()
	// The wedged mount takes its PREPARE and never acknowledges it.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, wedged); err != nil {
		t.Fatalf("wedged participant prepare: %v", err)
	}
	runBarrier(t, h.coordinator, healthy, initialVisibilityCursor(t, h.coordinator, healthy))

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("mutation after a budget miss: %v", err)
		}
		if waited := time.Since(started); waited < 2*wedgedBudget || waited > 6*wedgedBudget {
			t.Fatalf("failed participant cost %s, want one %s deadline plus one full fencing grace", waited, wedgedBudget)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a wedged participant stalled the mutation past its own budget")
	}
	if !h.fencer.wasFenced(wedged) {
		t.Fatal("the participant that missed its budget was not fenced")
	}
	if !h.fencer.live(healthy) {
		t.Fatal("a budget miss fenced a participant that met its budget")
	}
	if err := h.coordinator.Ack(wedged, VisibilityCursor{Sequence: 1, Phase: VisibilityPrepare}); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("fenced participant Ack = %v, want ErrSessionExpired", err)
	}
}

// Participants share a dispatch boundary, so simultaneous deadline failures
// share one fencing-grace interval. The grace protects each remote kernel after
// its authority session ends; it is not work one failed mount may serialize in
// front of another failed mount.
func TestVisibilitySimultaneousDeadlineFencesAdvanceConcurrently(t *testing.T) {
	membership := newTestDurableVisibilityMembership()
	fencer := &concurrentFenceProbe{
		started: make(chan SessionID, 2),
		release: make(chan struct{}),
	}
	released := false
	releaseFences := func() {
		if !released {
			close(fencer.release)
			released = true
		}
	}
	defer releaseFences()

	coordinator, err := NewVisibilityCoordinator(VisibilityConfig{
		Prior: PriorEpochStrictMountsFenced, Membership: membership, Fencer: fencer,
		MaxCachedNameCapacity: testCacheCapacity, MaxRepairBudget: time.Second, MaxClockSkew: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := []SessionID{{1}, {2}}
	const grace = 10 * time.Millisecond
	for _, id := range ids {
		if err := coordinator.Register(id, CoherenceStrict, make(chan struct{}), VisibilityCommitment{
			CachedNameCapacity: testCacheCapacity,
			RepairBudget:       grace,
			NamespaceRepair:    NamespaceRepairIndependent,
		}); err != nil {
			t.Fatalf("register %x: %v", id, err)
		}
	}

	coordinator.mu.Lock()
	deliveries := make([]*visibilityDelivery, 0, len(ids))
	for _, id := range ids {
		delivery := coordinator.newDeliveryLocked(coordinator.participants[id], VisibilityEvent{
			Cursor: VisibilityCursor{Sequence: 1, Phase: VisibilityPrepare},
		})
		// Expire both before awaitAll begins so scheduling cannot turn this into
		// two merely-close deadlines. The probe below is the synchronization point.
		delivery.deadline = time.Now().Add(-time.Second)
		deliveries = append(deliveries, delivery)
	}
	coordinator.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- coordinator.awaitAll(deliveries) }()
	seen := make(map[SessionID]bool, len(ids))
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for len(seen) != len(ids) {
		select {
		case id := <-fencer.started:
			seen[id] = true
		case <-deadline.C:
			releaseFences()
			t.Fatalf("fencing remained serialized; reached %d of %d participants", len(seen), len(ids))
		}
	}
	select {
	case err := <-done:
		t.Fatalf("barrier returned before authority fencing completed: %v", err)
	default:
	}
	releaseFences()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("await simultaneous fences: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("simultaneous fence grace did not discharge the barrier")
	}
	for _, id := range ids {
		coordinator.mu.Lock()
		_, live := coordinator.participants[id]
		coordinator.mu.Unlock()
		if live {
			t.Fatalf("participant %x remained live after deadline fence", id)
		}
	}
}

// Selecting a phase deadline and accepting its Ack can race. The timer owns an
// exact delivery, not the participant forever: once that delivery is no longer
// pending, the delayed timeout path must not fence a mount that already
// repaired it (or a newer phase that happens to be pending now).
func TestVisibilityExpiredDeliveryCannotFenceAfterAck(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.register(t, participant, testRepairBudget)
	h.resolve(t, participant, "shared")

	done := make(chan error, 1)
	go func() {
		done <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("shared"),
			testVisibilityPrepare("shared"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("shared"), true })
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	expired := h.coordinator.participants[participant].pending
	h.coordinator.mu.Unlock()
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if h.coordinator.fence(participant, expired, ErrVisibilityDeadline) {
		t.Fatal("stale deadline fenced a participant after its exact delivery was acknowledged")
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if h.fencer.wasFenced(participant) || !h.fencer.live(participant) {
		t.Fatal("participant did not survive stale deadline race")
	}
}

// Fan-out is scoped to what a mount actually resolved. A mount that never
// looked at the affected name is not asked about it, which is what keeps a
// metadata-heavy workload usable while a strict mount is attached.
func TestVisibilityFanOutSkipsMountsThatNeverResolvedTheName(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	holder, stranger := SessionID{1}, SessionID{2}
	h.register(t, holder, testRepairBudget)
	h.register(t, stranger, testRepairBudget)
	h.resolve(t, holder, "watched")
	h.resolve(t, stranger, "somewhere-else")

	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("watched"),
			testVisibilityPrepare("watched"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("watched"), true
			})
	}()
	runBarrier(t, h.coordinator, holder, initialVisibilityCursor(t, h.coordinator, holder))
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("scoped mutation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the mutation waited for a mount that never resolved the name")
	}

	idle, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := nextFromInitialVisibilityCursor(t, h.coordinator, idle, stranger); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("uninvolved mount received %v, want no event at all", err)
	}
	if !h.fencer.live(stranger) {
		t.Fatal("skipping a mount fenced it")
	}
}

// One matching coordinate must not import every target in a compound mutation.
// In particular, a cached parent attribute is not evidence that the mount also
// holds every child name, replaced inode, or data page named by that operation.
func TestVisibilityFanOutProjectsTargetsPerParticipant(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	nameHolder, parentAttrHolder, dataHolder := SessionID{1}, SessionID{2}, SessionID{3}
	for _, id := range []SessionID{nameHolder, parentAttrHolder, dataHolder} {
		h.register(t, id, testRepairBudget)
	}
	parent := testVisibilityParent()
	var file [16]byte
	file[0] = 2
	h.coordinator.RecordResolvedName(nameHolder, parent, []byte("child"))
	h.coordinator.RecordResolvedInode(parentAttrHolder, parent)
	h.coordinator.RecordResolvedInode(dataHolder, file)

	prepareTargets := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("child")},
		{Scope: VisibilityAttributes, Identity: parent},
		{Scope: VisibilityData, Identity: file, Size: 10},
	}
	completeTargets := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("child")},
		{Scope: VisibilityAttributes, Identity: parent},
		{Scope: VisibilityData, Identity: file, Size: 20},
	}
	result := make(chan error, 1)
	go func() {
		result <- executeTestExact(h.coordinator,
			context.Background(), SessionID{9}, MutationID{Sequence: 1},
			mutationDependenciesForTargets(prepareTargets),
			func() ([]VisibilityTarget, error) { return prepareTargets, nil },
			func() ([]VisibilityTarget, bool) { return completeTargets, true },
		)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	expected := map[SessionID][]VisibilityScope{
		nameHolder:       {VisibilityNamespace},
		parentAttrHolder: {VisibilityNamespace, VisibilityAttributes},
		dataHolder:       {VisibilityData},
	}
	prepares := make(map[SessionID]VisibilityEvent)
	for id, scopes := range expected {
		event, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, id)
		if err != nil {
			t.Fatalf("prepare for %x: %v", id, err)
		}
		if event.Cursor.Phase != VisibilityPrepare || len(event.Targets) != len(scopes) {
			t.Fatalf("prepare projection for %x = %#v, want scopes %v", id, event.Targets, scopes)
		}
		for i, scope := range scopes {
			if event.Targets[i].Scope != scope {
				t.Fatalf("prepare projection for %x = %#v, want scopes %v", id, event.Targets, scopes)
			}
		}
		prepares[id] = event
		if err := h.coordinator.Ack(id, event.Cursor); err != nil {
			t.Fatal(err)
		}
	}
	for id, scopes := range expected {
		event, err := h.coordinator.Next(ctx, id, prepares[id].Cursor)
		if err != nil {
			t.Fatalf("complete for %x: %v", id, err)
		}
		if event.Cursor.Phase != VisibilityComplete || len(event.Targets) != len(scopes) {
			t.Fatalf("complete projection for %x = %#v, want scopes %v", id, event.Targets, scopes)
		}
		for i, scope := range scopes {
			if event.Targets[i].Scope != scope {
				t.Fatalf("complete projection for %x = %#v, want scopes %v", id, event.Targets, scopes)
			}
		}
		if id == dataHolder && event.Targets[0].Size != 20 {
			t.Fatalf("projected data EOF = %d, want 20", event.Targets[0].Size)
		}
		if err := h.coordinator.Ack(id, event.Cursor); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

// Audience membership is a union, but the PREPARE drain is participant-scoped.
// A resolution racing a different, omitted target must wait through apply; it
// cannot publish old state merely because another target put the mount in the
// audience.
func TestVisibilityProjectedPrepareDoesNotCoverRacedOmittedTarget(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.register(t, participant, testRepairBudget)
	parent := testVisibilityParent()
	h.coordinator.RecordResolvedInode(participant, parent)
	targets := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("a-repair-anchor")},
		{Scope: VisibilityAttributes, Identity: parent},
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("z-raced-child")},
	}
	applyEntered := make(chan struct{})
	releaseApply := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- executeTestExact(h.coordinator,
			context.Background(), SessionID{9}, MutationID{Sequence: 1},
			mutationDependenciesForTargets(targets),
			func() ([]VisibilityTarget, error) { return targets, nil },
			func() ([]VisibilityTarget, bool) {
				close(applyEntered)
				<-releaseApply
				return targets, true
			},
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepare.Targets) != 2 || prepare.Targets[0].Scope != VisibilityNamespace ||
		string(prepare.Targets[0].Name) != "a-repair-anchor" ||
		prepare.Targets[1].Scope != VisibilityAttributes {
		t.Fatalf("projected PREPARE = %#v, want one repair anchor plus parent attributes", prepare.Targets)
	}

	type stabilizeResult struct {
		waited bool
		err    error
	}
	stabilized := make(chan stabilizeResult, 1)
	go func() {
		waited, err := h.coordinator.Stabilize(ctx, participant, VisibilityResolution{
			Parent: parent, Name: []byte("z-raced-child"),
		})
		stabilized <- stabilizeResult{waited: waited, err: err}
	}()
	select {
	case got := <-stabilized:
		t.Fatalf("omitted target crossed pending projected PREPARE: %+v", got)
	case <-time.After(30 * time.Millisecond):
	}
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	<-applyEntered
	select {
	case got := <-stabilized:
		t.Fatalf("omitted target crossed before apply completed: %+v", got)
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseApply)
	select {
	case got := <-stabilized:
		if got.err != nil || !got.waited {
			t.Fatalf("post-apply stabilization = %+v, want waited success", got)
		}
	case <-ctx.Done():
		t.Fatal("omitted target did not resume after apply")
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(complete.Targets) != 2 || complete.Targets[0].Scope != VisibilityNamespace ||
		string(complete.Targets[0].Name) != "a-repair-anchor" ||
		complete.Targets[1].Scope != VisibilityAttributes {
		t.Fatalf("projected COMPLETE = %#v, want the fixed repair anchor plus parent attributes", complete.Targets)
	}
	if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

// The source's pre-dispatch gate replaces both self phases. Its validated
// declaration, actual completion, and response-only identity are all indexed
// before the mutation turn can pass, without sending the source an event.
func TestVisibilitySourceGateReplacesSelfPhasesAndIndexesPublication(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairLocklessExpiration)
	parent := testVisibilityParent()
	var file [16]byte
	file[0] = 2
	targets := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("child")},
		{Scope: VisibilityAttributes, Identity: parent},
		{Scope: VisibilityData, Identity: file, Size: 20},
	}
	gate := SourcePublicationGate{Targets: []SourcePublicationTarget{
		{Identity: parent, Attributes: true},
		{Identity: file, Attributes: true, Data: true},
		{ParentIdentity: parent, Name: []byte("child"), BoundAttributes: true, BoundIdentities: [][16]byte{file}},
	}}
	err := executeTestExactWithSourceGate(h.coordinator, context.Background(), source, MutationID{Sequence: 1}, h.coordinator.DeclareSourceGate(gate), gate,
		func() (SourcePublicationGate, error) { return gate, nil },
		func() ([]VisibilityTarget, error) { return targets, nil },
		func() ([]VisibilityTarget, bool) { return targets, true },
		func() ([]VisibilityResolution, error) { return []VisibilityResolution{{Identity: file}}, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	participant := h.coordinator.participants[source]
	wantKeys := [][]byte{nameKey(parent, []byte("child")), inodeKey(parent), inodeKey(file)}
	for _, key := range wantKeys {
		if !participant.index.contains(key) {
			h.coordinator.mu.Unlock()
			t.Fatalf("source index omitted publication coordinate %x", key)
		}
	}
	h.coordinator.mu.Unlock()
	idle, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := nextFromInitialVisibilityCursor(t, h.coordinator, idle, source); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("source received a filesystem phase: %v", err)
	}
}

func TestVisibilitySourceGateFenceDuringPeerPrepareRefusesApply(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source, peer := SessionID{1}, SessionID{2}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairLocklessExpiration)
	h.registerRepair(t, peer, testRepairBudget, NamespaceRepairLocklessExpiration)
	h.resolve(t, peer, "source-fence")
	gate := testSourcePublicationGate("source-fence")
	applied := 0
	result := make(chan error, 1)
	go func() {
		result <- executeTestExactWithSourceGate(
			h.coordinator, context.Background(), source, MutationID{Sequence: 1},
			h.coordinator.DeclareSourceGate(gate), gate,
			func() (SourcePublicationGate, error) { return gate, nil },
			testVisibilityPrepare("source-fence"),
			func() ([]VisibilityTarget, bool) {
				applied++
				return testVisibilityTargets("source-fence"), true
			},
			func() ([]VisibilityResolution, error) { return nil, nil },
		)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	if prepare.Cursor.Phase != VisibilityPrepare {
		t.Fatalf("peer event = %+v, want PREPARE", prepare)
	}
	h.fencer.die(source)
	if err := h.coordinator.Ack(peer, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrVisibilityLost) {
		t.Fatalf("source-gated mutation after source fence = %v, want %v", err, ErrVisibilityLost)
	}
	if applied != 0 {
		t.Fatalf("apply calls after source fence = %d, want 0", applied)
	}
}

// A successful create can return an existing item without changing XFS. That
// response still publishes a stable identity into the initiating frontend. The
// authority must index it while the create owns the resolved inode dependency:
// otherwise an immediately queued item-only peer mutation can choose its
// audience before the source is known to cache that item.
func TestVisibilityPublishedIdentityIsIndexedBeforeNextMutationTurn(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairLocklessExpiration)
	gate := testSourcePublicationGate("existing")
	var returnedIdentity [16]byte
	returnedIdentity[0] = 0xA1
	gate.Targets[0].BoundIdentities = [][16]byte{returnedIdentity}

	publicationEntered := make(chan struct{})
	releasePublication := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.ExecuteWithSourceGate(
			context.Background(), source, MutationID{Sequence: 1}, h.coordinator.DeclareSourceGate(gate), gate,
			func() (SourcePublicationGate, error) { return gate, nil },
			testVisibilityPrepare("existing"),
			func() ([]VisibilityTarget, bool) { return nil, false },
			func() ([]VisibilityResolution, error) {
				close(publicationEntered)
				<-releasePublication
				return []VisibilityResolution{{Identity: returnedIdentity}}, nil
			},
		)
	}()
	<-publicationEntered

	secondTargets := []VisibilityTarget{{
		Scope: VisibilityAttributes, Identity: returnedIdentity, KernelIno: 0xA1, Device: 1,
	}}
	second := make(chan error, 1)
	go func() {
		second <- executeTestExact(h.coordinator,
			context.Background(), SessionID{9}, MutationID{Sequence: 2},
			mutationDependenciesForTargets(secondTargets),
			func() ([]VisibilityTarget, error) { return secondTargets, nil },
			func() ([]VisibilityTarget, bool) { return secondTargets, true },
		)
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)
	close(releasePublication)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, source)
	if err != nil {
		t.Fatalf("source omitted from immediate mutation of returned identity: %v", err)
	}
	if prepare.Cursor.Phase != VisibilityPrepare || len(prepare.Targets) != 1 ||
		prepare.Targets[0].Identity != returnedIdentity {
		t.Fatalf("immediate peer PREPARE = %#v, want returned identity", prepare)
	}
	runBarrierFrom(t, h.coordinator, source, prepare)
	if err := <-first; err != nil {
		t.Fatalf("no-change publication: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("immediate peer mutation: %v", err)
	}
}

// A zero-TTL reply is still a publication while it is in flight to a kernel.
// Every FSKit synchronous-repair mount is therefore a real participant: a later peer
// mutation reaches the source's local gate and cannot apply until the earlier
// reply is physically published. This is the deterministic core witness for
// the race the retired UNCACHED profile allowed.
func TestVisibilityLaterPeerWaitsForDelayedSourceReplyPublication(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source, peer := SessionID{1}, SessionID{2}
	h.register(t, source, testRepairBudget)
	h.register(t, peer, testRepairBudget)
	var identity [16]byte
	identity[0] = 0xD1
	targets := []VisibilityTarget{{
		Scope: VisibilityData, Identity: identity, KernelIno: 0xD1, Device: 1, Size: 8,
	}}
	gate := SourcePublicationGate{Targets: []SourcePublicationTarget{{
		Identity: identity, Attributes: true, Data: true,
	}}}
	if err := executeTestExactWithSourceGate(h.coordinator,
		context.Background(), source, MutationID{Sequence: 1}, h.coordinator.DeclareSourceGate(gate), gate,
		func() (SourcePublicationGate, error) { return gate, nil },
		func() ([]VisibilityTarget, error) { return targets, nil },
		func() ([]VisibilityTarget, bool) { return targets, true },
		func() ([]VisibilityResolution, error) { return nil, nil },
	); err != nil {
		t.Fatalf("source mutation: %v", err)
	}

	// The authority response exists, but the source frontend deliberately keeps
	// its exact item lease closed until its kernel/framework reply boundary.
	sourceReplyWritten := make(chan struct{})
	secondApplied := make(chan struct{})
	second := make(chan error, 1)
	go func() {
		second <- executeTestExactWithSourceGate(h.coordinator,
			context.Background(), peer, MutationID{Sequence: 2}, h.coordinator.DeclareSourceGate(gate), gate,
			func() (SourcePublicationGate, error) { return gate, nil },
			func() ([]VisibilityTarget, error) { return targets, nil },
			func() ([]VisibilityTarget, bool) {
				close(secondApplied)
				return targets, true
			},
			func() ([]VisibilityResolution, error) { return nil, nil },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, source)
	if err != nil {
		t.Fatalf("later peer omitted source audience: %v", err)
	}
	if prepare.Cursor.Phase != VisibilityPrepare || len(prepare.Targets) != 1 || prepare.Targets[0].Identity != identity {
		t.Fatalf("later peer PREPARE = %#v, want delayed source item", prepare)
	}
	prepareAcked := make(chan error, 1)
	go func() {
		<-sourceReplyWritten
		prepareAcked <- h.coordinator.Ack(source, prepare.Cursor)
	}()
	select {
	case <-secondApplied:
		t.Fatal("later peer applied before the source reply was physically published")
	default:
	}

	close(sourceReplyWritten)
	if err := <-prepareAcked; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondApplied:
	case <-time.After(time.Second):
		t.Fatal("later peer did not apply after source publication released PREPARE")
	}
	complete, err := h.coordinator.Next(ctx, source, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(source, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
}

// A mount that resolves a name the running mutation already owns must not be
// handed the pre-mutation value. It waits for the mutation to finish instead,
// which is what makes it safe to have left it out of the audience.
func TestVisibilityStabilizeBlocksOnAnInFlightCoordinate(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	holder, latecomer := SessionID{1}, SessionID{2}
	h.register(t, holder, testRepairBudget)
	h.register(t, latecomer, testRepairBudget)
	h.resolve(t, holder, "contended")

	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("contended"),
			testVisibilityPrepare("contended"), func() ([]VisibilityTarget, bool) {
				<-release
				return testVisibilityTargets("contended"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, holder)
	if err != nil {
		t.Fatal(err)
	}

	type stabilizeResult struct {
		waited bool
		err    error
	}
	stabilized := make(chan stabilizeResult, 1)
	go func() {
		waited, err := h.coordinator.Stabilize(ctx, latecomer, VisibilityResolution{Parent: testVisibilityParent(), Name: []byte("contended")})
		stabilized <- stabilizeResult{waited: waited, err: err}
	}()
	select {
	case <-stabilized:
		t.Fatal("a non-audience resolution crossed the still-pending PREPARE")
	case <-time.After(100 * time.Millisecond):
	}
	if err := h.coordinator.Ack(holder, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stabilized:
		t.Fatal("a non-audience resolution crossed the mutation before apply")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	complete, err := h.coordinator.Next(ctx, holder, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(holder, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-stabilized:
		if result.err != nil {
			t.Fatalf("stabilize after the mutation finished: %v", result.err)
		}
		if !result.waited {
			t.Fatal("the non-audience resolution did not report crossing apply")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a resolution stayed blocked after the mutation finished")
	}
}

// A participant already in the PREPARE audience has closed publication
// admission and is draining callbacks admitted before that close. Such a
// callback must be allowed to finish reading old state: PREPARE cannot Ack
// until its framework publication has completed. Once that participant Acks,
// the same coordinate is closed to every reader until apply.
func TestVisibilityStabilizeLetsPrepareAudienceDrainThenBlocksAfterAck(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	holder := SessionID{1}
	h.register(t, holder, testRepairBudget)
	h.resolve(t, holder, "contended")

	releaseApply := make(chan struct{})
	applied := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("contended"),
			testVisibilityPrepare("contended"), func() ([]VisibilityTarget, bool) {
				close(applied)
				<-releaseApply
				return testVisibilityTargets("contended"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, holder)
	if err != nil {
		t.Fatal(err)
	}

	waited, err := h.coordinator.Stabilize(ctx, holder,
		VisibilityResolution{Parent: testVisibilityParent(), Name: []byte("contended")})
	if err != nil {
		t.Fatal(err)
	}
	if waited {
		t.Fatal("a callback covered by the pending PREPARE waited on its own drain")
	}
	select {
	case <-applied:
		t.Fatal("apply began before the audience acknowledged PREPARE")
	default:
	}

	if err := h.coordinator.Ack(holder, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	stabilized := make(chan struct {
		waited bool
		err    error
	}, 1)
	go func() {
		waited, err := h.coordinator.Stabilize(ctx, holder,
			VisibilityResolution{Parent: testVisibilityParent(), Name: []byte("contended")})
		stabilized <- struct {
			waited bool
			err    error
		}{waited: waited, err: err}
	}()
	<-applied
	select {
	case <-stabilized:
		t.Fatal("an audience resolution crossed after its PREPARE Ack but before apply")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseApply)
	select {
	case got := <-stabilized:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !got.waited {
			t.Fatal("the post-PREPARE resolution did not report crossing apply")
		}
	case <-ctx.Done():
		t.Fatal("the post-PREPARE resolution stayed blocked after apply")
	}
	complete, err := h.coordinator.Next(ctx, holder, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(holder, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

// A repair-owned read starts only after the mutation reached XFS but while the
// peer's COMPLETE repair is still outstanding. It must observe post-apply
// truth immediately: waiting for COMPLETE would make the repair wait on the
// read it needs in order to acknowledge COMPLETE.
func TestVisibilityStabilizeReleasesAfterApplyBeforeCompleteAck(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	holder, reader := SessionID{1}, SessionID{2}
	h.register(t, holder, testRepairBudget)
	h.register(t, reader, testRepairBudget)
	h.resolve(t, holder, "contended")

	releaseApply := make(chan struct{})
	applied := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("contended"),
			testVisibilityPrepare("contended"), func() ([]VisibilityTarget, bool) {
				<-releaseApply
				close(applied)
				return testVisibilityTargets("contended"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, holder)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(holder, prepare.Cursor); err != nil {
		t.Fatal(err)
	}

	stabilized := make(chan error, 1)
	go func() {
		_, err := h.coordinator.Stabilize(ctx, reader,
			VisibilityResolution{Parent: testVisibilityParent(), Name: []byte("contended")})
		stabilized <- err
	}()
	select {
	case <-stabilized:
		t.Fatal("repair-owned read crossed the mutation before apply")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseApply)
	<-applied
	complete, err := h.coordinator.Next(ctx, holder, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-stabilized:
		if err != nil {
			t.Fatalf("post-apply repair-owned read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-apply read waited for the still-unacknowledged COMPLETE")
	}

	if err := h.coordinator.Ack(holder, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

// Runtime memory starts empty after an authority restart, but an empty map is
// not proof that a prior macOS kernel mount stopped serving cached state. Both
// new strict registration and mutation admission stay closed until durable
// control state supplies the prior-epoch fencing proof.
func TestVisibilityRestartStartsClosedWithoutPriorEpochProof(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochUnproven)
	commitment := VisibilityCommitment{CachedNameCapacity: testCacheCapacity, RepairBudget: testRepairBudget, NamespaceRepair: NamespaceRepairParentExclusive}
	if err := h.coordinator.Register(SessionID{1}, CoherenceStrict, make(chan struct{}), commitment); !errors.Is(err, ErrVisibilityStartup) {
		t.Fatalf("Register without prior-epoch proof = %v, want ErrVisibilityStartup", err)
	}

	var applied atomic.Bool
	err := h.coordinator.Execute(context.Background(), SessionID{}, MutationID{Sequence: 1}, testMutationDependencies("prepare"), testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
		applied.Store(true)
		return testVisibilityTargets("prepare"), true
	})
	if !errors.Is(err, ErrVisibilityStartup) {
		t.Fatalf("Execute without prior-epoch proof = %v, want ErrVisibilityStartup", err)
	}
	if applied.Load() {
		t.Fatal("filesystem mutation ran before prior strict mounts were proven fenced")
	}
}

// Registration states its own invariants instead of assuming them: a zero
// session ID and an undeclared cache capacity or repair budget are all refused.
func TestVisibilityRegisterRefusesUnstatedCommitments(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	good := VisibilityCommitment{CachedNameCapacity: testCacheCapacity, RepairBudget: testRepairBudget, NamespaceRepair: NamespaceRepairParentExclusive}
	cases := []struct {
		name       string
		id         SessionID
		commitment VisibilityCommitment
	}{
		{"zero session id", SessionID{}, good},
		{"no cache capacity", SessionID{1}, VisibilityCommitment{RepairBudget: testRepairBudget, NamespaceRepair: NamespaceRepairParentExclusive}},
		{"no repair budget", SessionID{2}, VisibilityCommitment{CachedNameCapacity: testCacheCapacity, NamespaceRepair: NamespaceRepairParentExclusive}},
		{"capacity beyond the deployment bound", SessionID{3}, VisibilityCommitment{CachedNameCapacity: 1 << 24, RepairBudget: testRepairBudget, NamespaceRepair: NamespaceRepairParentExclusive}},
		{"budget beyond the deployment bound", SessionID{4}, VisibilityCommitment{CachedNameCapacity: testCacheCapacity, RepairBudget: time.Hour, NamespaceRepair: NamespaceRepairParentExclusive}},
		// A strict mount that does not say how its kernel makes a binding
		// unservable has not agreed to the contract: the authority would have to
		// guess whether a silent participant is deadlocked or merely slow.
		{"no namespace-repair model", SessionID{5}, VisibilityCommitment{CachedNameCapacity: testCacheCapacity, RepairBudget: testRepairBudget}},
		{"writer lease on a non-macOS repair profile", SessionID{6}, VisibilityCommitment{
			CachedNameCapacity: testCacheCapacity, RepairBudget: testRepairBudget,
			NamespaceRepair: NamespaceRepairLocklessExpiration, CompatibilityWriter: true,
		}},
	}
	for _, test := range cases {
		if err := h.coordinator.Register(test.id, CoherenceStrict, make(chan struct{}), test.commitment); !errors.Is(err, ErrVisibilityProfile) {
			t.Fatalf("%s: Register = %v, want ErrVisibilityProfile", test.name, err)
		}
	}
}

// A detach is an observation or it is nothing. The previous unconditional
// boolean let a mount that could not repair its cache escape an outstanding
// barrier just by asking to leave.
func TestVisibilityDetachWithoutEvidenceIsRefused(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.register(t, participant, testRepairBudget)
	h.resolve(t, participant, "prepare")

	now := time.Now()
	cases := []struct {
		name  string
		proof MountAbsenceProof
	}{
		{"nothing at all", MountAbsenceProof{}},
		{"no observation", MountAbsenceProof{ObservedUnixNanos: now.UnixNano(), Component: "observer"}},
		{"no component", MountAbsenceProof{ObservedUnixNanos: now.UnixNano(), Observation: []byte("fsid")}},
		{"no timestamp", MountAbsenceProof{Observation: []byte("fsid"), Component: "observer"}},
		{"dated in the future", testMountAbsence(now.Add(time.Hour))},
		{"predates this mount", testMountAbsence(now.Add(-time.Hour))},
	}
	for _, test := range cases {
		if err := h.coordinator.CleanDetach(participant, test.proof); !errors.Is(err, ErrVisibilityProof) {
			t.Fatalf("%s: CleanDetach = %v, want ErrVisibilityProof", test.name, err)
		}
	}
	if !h.membership.contains(participant) {
		t.Fatal("a refused detach cleared durable membership")
	}
}

// Clean detach is a cooperative-client statement: the transport authenticates
// the exact session and the official supervisor observes its own kernel. No
// second host-attestation service sits in that trust path.
func TestVisibilityDetachAcceptsAuthenticatedSupervisorObservation(t *testing.T) {
	membership := newTestDurableVisibilityMembership()
	fencer := newTestFencer()
	coordinator, err := NewVisibilityCoordinator(VisibilityConfig{
		Prior: PriorEpochStrictMountsFenced, Membership: membership, Fencer: fencer,
		MaxCachedNameCapacity: 1024, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := SessionID{1}
	terminal := fencer.attach(id)
	if err := coordinator.Register(id, CoherenceStrict, terminal, VisibilityCommitment{
		CachedNameCapacity: 32, RepairBudget: time.Second, NamespaceRepair: NamespaceRepairParentExclusive,
	}); err != nil {
		t.Fatal(err)
	}
	proof := testMountAbsence(time.Now())
	if err := coordinator.CleanDetach(id, proof); err != nil {
		t.Fatalf("CleanDetach with authenticated supervisor observation: %v", err)
	}
	if membership.contains(id) {
		t.Fatal("authenticated clean detach left durable membership active")
	}
	if fencer.wasFenced(id) {
		t.Fatal("clean detach fenced the authority session instead of leaving normally")
	}
}

// Removing a participant from the in-memory barrier set cannot leave its
// authority session live when the durable membership clear fails. The durable
// record correctly remains fail-closed for a future epoch, while fencing closes
// the current epoch's only remaining path around cache repair.
func TestVisibilityDetachMembershipFailureFencesLiveRuntime(t *testing.T) {
	a, _ := testAuthority(t)
	cred, err := a.AttachActiveForTest(2, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := a.SessionTerminal(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	membership := newFaultVisibilityMembership()
	coordinator := newFaultVisibilityCoordinator(t, membership, a)
	if err := coordinator.Register(cred.ID, CoherenceStrict, terminal, testVisibilityCommitment()); err != nil {
		t.Fatal(err)
	}
	membership.deactivateErr = errors.New("injected durable membership failure")

	err = coordinator.CleanDetach(cred.ID, testMountAbsence(time.Now()))
	if !errors.Is(err, membership.deactivateErr) {
		t.Fatalf("CleanDetach = %v, want durable membership failure", err)
	}
	if !membership.contains(cred.ID) {
		t.Fatal("failed durable clear removed the restart-time membership evidence")
	}
	select {
	case <-terminal:
	default:
		t.Fatal("CleanDetach returned before fencing the live authority session")
	}
	if _, err := a.Begin(cred); !errors.Is(err, ErrSessionFenced) && !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("authority session remained usable after failed detach: %v", err)
	}
	if _, err := coordinator.InitialCursor(cred.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("failed detach left participant in the in-memory barrier: %v", err)
	}
}

// An observation taken before the outstanding event existed says nothing about
// that event. Accepting it would let a mount discharge a barrier with evidence
// that predates it.
func TestVisibilityDetachProofMustPostdateTheOutstandingEvent(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.register(t, participant, testRepairBudget)
	h.resolve(t, participant, "prepare")
	stale := time.Now()
	// Make the stale observation unambiguously older than the event below.
	time.Sleep(10 * time.Millisecond)

	applied := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("prepare"),
			testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
				close(applied)
				return testVisibilityTargets("prepare"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant); err != nil {
		t.Fatalf("wait for pending prepare: %v", err)
	}
	if err := h.coordinator.CleanDetach(participant, testMountAbsence(stale)); !errors.Is(err, ErrVisibilityProof) {
		t.Fatalf("stale-proof detach = %v, want ErrVisibilityProof", err)
	}
	select {
	case <-applied:
		t.Fatal("a stale proof discharged an outstanding barrier")
	case <-time.After(100 * time.Millisecond):
	}
	// A current observation is genuine evidence and does discharge it.
	if err := h.coordinator.CleanDetach(participant, testMountAbsence(time.Now())); err != nil {
		t.Fatalf("current-proof detach: %v", err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Execute after a proven detach: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mutation remained blocked after exact mount absence")
	}
	if h.membership.contains(participant) {
		t.Fatal("clean detach left durable membership active")
	}
}

// The one coherent profile validates the authority-derived target set before
// apply. Removing the retired no-participant path must not turn malformed
// target construction into an unchecked storage mutation.
func TestVisibilityCoherentProfileValidatesTargets(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{9}
	h.register(t, source, testRepairBudget)
	gate := testSourcePublicationGate("invalid")
	var applied atomic.Bool
	err := h.coordinator.ExecuteWithSourceGate(context.Background(), source, MutationID{Sequence: 1}, h.coordinator.DeclareSourceGate(gate), gate,
		func() (SourcePublicationGate, error) { return gate, nil },
		func() ([]VisibilityTarget, error) {
			// A namespace target with no parent identity: a construction defect.
			return []VisibilityTarget{{Scope: VisibilityNamespace, Name: []byte("x")}}, nil
		},
		func() ([]VisibilityTarget, bool) {
			applied.Store(true)
			return testVisibilityTargets("x"), true
		}, func() ([]VisibilityResolution, error) { return nil, nil })
	if !errors.Is(err, ErrVisibilityTargets) {
		t.Fatalf("coherent Execute with invalid prepare targets = %v, want ErrVisibilityTargets", err)
	}
	if applied.Load() {
		t.Fatal("a target-construction defect still reached the filesystem")
	}

	postApply := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	postApply.register(t, source, testRepairBudget)
	postApplyGate := testSourcePublicationGate("x")
	err = postApply.coordinator.ExecuteWithSourceGate(context.Background(), source, MutationID{Sequence: 1}, postApply.coordinator.DeclareSourceGate(postApplyGate), postApplyGate,
		func() (SourcePublicationGate, error) { return postApplyGate, nil },
		testVisibilityPrepare("x"),
		func() ([]VisibilityTarget, bool) {
			// Changed XFS but could not describe what it changed.
			return []VisibilityTarget{}, true
		}, func() ([]VisibilityResolution, error) { return nil, nil })
	if !errors.Is(err, ErrVisibilityPoisoned) {
		t.Fatalf("coherent Execute with a post-apply defect = %v, want a poisoned epoch", err)
	}
	var barrier *VisibilityBarrierError
	if !errors.As(err, &barrier) || !barrier.Applied {
		t.Fatalf("post-apply defect reported as %v, want an applied barrier failure", err)
	}
}

// A completion that names a coordinate PREPARE did not is a repair instruction
// addressed to mounts that were never asked to close publication for it.
func TestVisibilityCompletionOutsidePrepareIsAnAuthorityDefect(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{9}
	h.register(t, source, testRepairBudget)
	gate := testSourcePublicationGate("prepared")
	err := h.coordinator.ExecuteWithSourceGate(context.Background(), source, MutationID{Sequence: 1}, h.coordinator.DeclareSourceGate(gate), gate,
		func() (SourcePublicationGate, error) { return gate, nil },
		testVisibilityPrepare("prepared"),
		func() ([]VisibilityTarget, bool) { return testVisibilityTargets("never-prepared"), true },
		func() ([]VisibilityResolution, error) { return nil, nil })
	if !errors.Is(err, ErrVisibilityPoisoned) || !errors.Is(err, ErrVisibilityTargets) {
		t.Fatalf("uncovered completion target = %v, want a poisoned epoch", err)
	}
}

// A source is absent from both filesystem phases even when its index and a
// peer's index both match. Only the peer owns a delivery and acknowledgment.
func TestVisibilityFilesystemBarrierAudienceIsPeerOnly(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source, observer := SessionID{1}, SessionID{2}
	h.register(t, source, testRepairBudget)
	h.register(t, observer, testRepairBudget)
	h.resolve(t, source, "shared")
	h.resolve(t, observer, "shared")

	result := make(chan error, 1)
	go func() {
		result <- executeTestSourceGated(h.coordinator, context.Background(), source, MutationID{Sequence: 1}, "shared",
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("shared"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, observer)
	if err != nil {
		t.Fatal(err)
	}
	if prepare.Initiator != source || prepare.Cursor.Phase != VisibilityPrepare {
		t.Fatalf("peer PREPARE = %+v", prepare)
	}
	if err := h.coordinator.Ack(observer, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, observer, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(observer, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	idle, cancelIdle := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelIdle()
	if _, err := nextFromInitialVisibilityCursor(t, h.coordinator, idle, source); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("source received peer-only phase: %v", err)
	}
}

// Strict mutations have one coordinator order. Two callers may arrive at the
// same time, but their PREPARE/APPLY/COMPLETE intervals never interleave and
// neither waits on a barrier owned by the other.
func TestVisibilityConcurrentStrictMutatorsSerializeWithoutDeadlock(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participants := []SessionID{{1}, {2}, {3}}
	for _, participant := range participants {
		h.register(t, participant, testRepairBudget)
		h.resolve(t, participant, "a", "b")
	}
	coordinator := h.coordinator

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	workerErr := make(chan error, len(participants))
	var observedMu sync.Mutex
	observed := make(map[SessionID][]VisibilityEvent)
	for _, participant := range participants {
		participant := participant
		initial := initialVisibilityCursor(t, coordinator, participant)
		go func() {
			after := initial
			wantEvents := 4
			if participant != (SessionID{1}) {
				// Each mutating mount sees only the other mount's two peer
				// phases. Its own pre-dispatch gate replaces both self phases.
				wantEvents = 2
			}
			for range wantEvents {
				event, err := coordinator.Next(ctx, participant, after)
				if err != nil {
					workerErr <- err
					return
				}
				if event.Initiator == participant {
					workerErr <- errors.New("source received its own filesystem phase")
					return
				}
				observedMu.Lock()
				observed[participant] = append(observed[participant], event)
				observedMu.Unlock()
				if err := coordinator.Ack(participant, event.Cursor); err != nil {
					workerErr <- err
					return
				}
				after = event.Cursor
			}
			workerErr <- nil
		}()
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	tickets := make(map[SessionID]MutationID)
	for sourceByte := byte(2); sourceByte <= 3; sourceByte++ {
		source := SessionID{sourceByte}
		var fingerprint RequestFingerprint
		fingerprint[0] = sourceByte
		ticket := MutationID{Slot: uint32(sourceByte), Sequence: 1, Fingerprint: fingerprint}
		tickets[source] = ticket
		name := string([]byte{'a' + sourceByte - 2})
		go func() {
			<-start
			err := executeTestSourceGated(coordinator, context.Background(), source, ticket, name, testVisibilityPrepare(name), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets(name), true
			})
			results <- err
		}()
	}
	close(start)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent Execute: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent strict mutations deadlocked")
		}
	}
	for range participants {
		if err := <-workerErr; err != nil {
			t.Fatalf("visibility participant: %v", err)
		}
	}

	observedMu.Lock()
	defer observedMu.Unlock()
	for _, participant := range participants {
		events := observed[participant]
		wantEvents := 4
		if participant != (SessionID{1}) {
			wantEvents = 2
		}
		if len(events) != wantEvents {
			t.Fatalf("participant %x observed %d events, want %d", participant, len(events), wantEvents)
		}
		type phases struct{ prepare, complete bool }
		bySequence := make(map[uint64]phases)
		for _, event := range events {
			state := bySequence[event.Cursor.Sequence]
			switch event.Cursor.Phase {
			case VisibilityPrepare:
				state.prepare = true
			case VisibilityComplete:
				state.complete = true
			default:
				t.Fatalf("participant %x received invalid phase %d", participant, event.Cursor.Phase)
			}
			bySequence[event.Cursor.Sequence] = state
			if want := tickets[event.Initiator]; event.MutationSlot != want.Slot || event.MutationSequence != want.Sequence {
				t.Fatalf("participant %x received mutation ticket %d/%d from %x, want %d/%d", participant,
					event.MutationSlot, event.MutationSequence, event.Initiator, want.Slot, want.Sequence)
			}
		}
		for sequence, state := range bySequence {
			if !state.prepare || !state.complete {
				t.Fatalf("participant %x sequence %d phases = %+v", participant, sequence, state)
			}
		}
	}
	passive := observed[SessionID{1}]
	if passive[0].Cursor.Sequence == passive[2].Cursor.Sequence {
		t.Fatalf("two mutations reused visibility sequence %d", passive[0].Cursor.Sequence)
	}
}

// macOS 26 FSKit runs synchronous repair through callback execution capacity
// an unanswered mutation can occupy. Once this participant owes PREPARE, a
// later mutation must receive a definite pre-apply interruption instead of
// parking behind the phase and preventing its own repair callback from running.
func TestMacOS26CompatibilityMountOwnsTheWriterLease(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	mac, linux := SessionID{1}, SessionID{2}
	terminal := h.fencer.attach(mac)
	if err := h.coordinator.Register(mac, CoherenceStrict, terminal, VisibilityCommitment{
		CachedNameCapacity:  testCacheCapacity,
		RepairBudget:        testRepairBudget,
		NamespaceRepair:     NamespaceRepairCallbackSerializedPipelined,
		CompatibilityWriter: true,
	}); err != nil {
		t.Fatalf("register macOS compatibility writer: %v", err)
	}
	t.Cleanup(func() { h.fencer.FenceSession(mac) })
	h.registerRepair(t, linux, testRepairBudget, NamespaceRepairLocklessExpiration)
	h.resolve(t, linux, "shared")

	prepared, applied := false, false
	err := executeTestSourceGated(
		h.coordinator, context.Background(), linux,
		MutationID{Sequence: 1, FrontendOperationID: 41}, "shared",
		func() ([]VisibilityTarget, error) {
			prepared = true
			return testVisibilityTargets("shared"), nil
		},
		func() ([]VisibilityTarget, bool) {
			applied = true
			return testVisibilityTargets("shared"), true
		},
	)
	if !errors.Is(err, ErrCompatibilityWriterLease) {
		t.Fatalf("Linux mutation while macOS 26 is mounted = %v, want ErrCompatibilityWriterLease", err)
	}
	if prepared || applied {
		t.Fatalf("refused peer mutation reached prepare=%v apply=%v", prepared, applied)
	}
	if h.fencer.wasFenced(mac) || h.fencer.wasFenced(linux) {
		t.Fatal("a definite compatibility-writer refusal fenced a healthy mount")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go serviceVisibility(ctx, h.coordinator, linux)
	if err := executeTestSourceGated(
		h.coordinator, ctx, mac,
		MutationID{Sequence: 2, FrontendOperationID: 42}, "shared",
		testVisibilityPrepare("shared"),
		func() ([]VisibilityTarget, bool) { return testVisibilityTargets("shared"), true },
	); err != nil {
		t.Fatalf("macOS 26 writer mutation: %v", err)
	}

	h.coordinator.Fence(mac, errors.New("test macOS unmount"))
	if err := executeTestSourceGated(
		h.coordinator, ctx, linux,
		MutationID{Sequence: 3, FrontendOperationID: 43}, "shared",
		testVisibilityPrepare("shared"),
		func() ([]VisibilityTarget, bool) { return testVisibilityTargets("shared"), true },
	); err != nil {
		t.Fatalf("Linux mutation after macOS lease release: %v", err)
	}
}

func TestMacOS26WriterActivationWaitsForAdmittedMutation(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	linux, mac := SessionID{1}, SessionID{2}
	h.registerRepair(t, linux, testRepairBudget, NamespaceRepairLocklessExpiration)

	applyStarted := make(chan struct{})
	releaseApply := make(chan struct{})
	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- executeTestSourceGated(
			h.coordinator, context.Background(), linux,
			MutationID{Sequence: 1, FrontendOperationID: 51}, "before-writer",
			testVisibilityPrepare("before-writer"),
			func() ([]VisibilityTarget, bool) {
				close(applyStarted)
				<-releaseApply
				return testVisibilityTargets("before-writer"), true
			},
		)
	}()
	<-applyStarted

	terminal := h.fencer.attach(mac)
	activated := make(chan struct{})
	activationDone := make(chan error, 1)
	go func() {
		_, err := h.coordinator.ActivateParticipant(mac, CoherenceStrict, terminal, VisibilityCommitment{
			CachedNameCapacity:  testCacheCapacity,
			RepairBudget:        testRepairBudget,
			NamespaceRepair:     NamespaceRepairCallbackSerializedPipelined,
			CompatibilityWriter: true,
		}, nil, func() { close(activated) })
		activationDone <- err
	}()
	select {
	case <-activated:
		t.Fatal("compatibility writer activated while an admitted mutation was still applying")
	case <-time.After(30 * time.Millisecond):
	}

	close(releaseApply)
	if err := <-mutationDone; err != nil {
		t.Fatalf("mutation admitted before writer activation: %v", err)
	}
	if err := <-activationDone; err != nil {
		t.Fatalf("activate compatibility writer: %v", err)
	}
	t.Cleanup(func() { h.fencer.FenceSession(mac) })

	prepared := false
	err := executeTestSourceGated(
		h.coordinator, context.Background(), linux,
		MutationID{Sequence: 2, FrontendOperationID: 52}, "after-writer",
		func() ([]VisibilityTarget, error) {
			prepared = true
			return testVisibilityTargets("after-writer"), nil
		},
		func() ([]VisibilityTarget, bool) {
			t.Fatal("mutation applied after the compatibility writer became active")
			return nil, false
		},
	)
	if !errors.Is(err, ErrCompatibilityWriterLease) {
		t.Fatalf("mutation after compatibility writer activation = %v, want ErrCompatibilityWriterLease", err)
	}
	if prepared {
		t.Fatal("mutation after compatibility writer activation reached prepare")
	}
}

func TestMacOS26CompatibilityWriterAdmissionIsExclusive(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	commitment := VisibilityCommitment{
		CachedNameCapacity:  testCacheCapacity,
		RepairBudget:        testRepairBudget,
		NamespaceRepair:     NamespaceRepairCallbackSerializedPipelined,
		CompatibilityWriter: true,
	}
	first, second := SessionID{1}, SessionID{2}
	firstTerminal := h.fencer.attach(first)
	if _, err := h.coordinator.ActivateParticipant(first, CoherenceStrict, firstTerminal, commitment, nil, func() {}); err != nil {
		t.Fatalf("activate first compatibility writer: %v", err)
	}
	t.Cleanup(func() { h.fencer.FenceSession(first) })

	secondTerminal := h.fencer.attach(second)
	secondCommitted := false
	if _, err := h.coordinator.ActivateParticipant(second, CoherenceStrict, secondTerminal, commitment, nil, func() {
		secondCommitted = true
	}); !errors.Is(err, ErrCompatibilityWriterLease) {
		t.Fatalf("activate second compatibility writer = %v, want ErrCompatibilityWriterLease", err)
	}
	if secondCommitted || h.membership.contains(second) {
		t.Fatalf("refused second writer committed=%t durable=%t", secondCommitted, h.membership.contains(second))
	}
	if _, err := h.coordinator.InitialCursor(second); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("refused second writer entered visibility membership: %v", err)
	}

	h.coordinator.Fence(first, errors.New("test first writer unmount"))
	if _, err := h.coordinator.ActivateParticipant(second, CoherenceStrict, secondTerminal, commitment, nil, func() {
		secondCommitted = true
	}); err != nil {
		t.Fatalf("activate second writer after handoff: %v", err)
	}
	if !secondCommitted || !h.membership.contains(second) {
		t.Fatalf("second writer after handoff committed=%t durable=%t", secondCommitted, h.membership.contains(second))
	}
	t.Cleanup(func() { h.fencer.FenceSession(second) })
}

func TestVisibilityCallbackSerializedMutationIsInterruptedByPendingRepair(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "peer-change")

	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1, FrontendOperationID: 41},
			testMutationDependencies("peer-change"),
			testVisibilityPrepare("peer-change"),
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("peer-change"), true
			},
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}

	prepared, applied := false, false
	err = executeTestSourceGated(
		h.coordinator, context.Background(), participant, MutationID{Sequence: 2, FrontendOperationID: 42}, "local-change",
		func() ([]VisibilityTarget, error) {
			prepared = true
			return testVisibilityTargets("local-change"), nil
		},
		func() ([]VisibilityTarget, bool) {
			applied = true
			return testVisibilityTargets("local-change"), true
		},
	)
	if !errors.Is(err, ErrVisibilityInterrupted) {
		t.Fatalf("mutation during PREPARE = %v, want ErrVisibilityInterrupted", err)
	}
	if prepared || applied {
		t.Fatalf("interrupted mutation reached prepare=%v apply=%v", prepared, applied)
	}

	runBarrierFrom(t, h.coordinator, participant, prepare)
	if err := <-first; err != nil {
		t.Fatalf("peer mutation: %v", err)
	}
}

// The interruption also wakes a mutation that was already waiting for a shared
// dependency before PREPARE was installed. This is the half a check performed only
// when Execute begins would miss under a sustained writer storm.
func TestVisibilityCallbackSerializedQueuedMutationWakesForPendingRepair(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "peer-change")

	// Let the peer own the shared parent key but stop immediately before it publishes
	// PREPARE, so the local mutation is already queued when pending changes.
	peerPreparing := make(chan struct{})
	releasePeerPrepare := make(chan struct{})
	peer := make(chan error, 1)
	go func() {
		peer <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1, FrontendOperationID: 41},
			testMutationDependencies("peer-change"),
			func() ([]VisibilityTarget, error) {
				close(peerPreparing)
				<-releasePeerPrepare
				return testVisibilityTargets("peer-change"), nil
			},
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("peer-change"), true
			},
		)
	}()
	<-peerPreparing

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepared, applied := false, false
	result := make(chan error, 1)
	go func() {
		result <- executeTestSourceGated(
			h.coordinator, ctx, participant, MutationID{Sequence: 2, FrontendOperationID: 42}, "local-change",
			func() ([]VisibilityTarget, error) {
				prepared = true
				return testVisibilityTargets("local-change"), nil
			},
			func() ([]VisibilityTarget, bool) {
				applied = true
				return testVisibilityTargets("local-change"), true
			},
		)
	}()
	select {
	case err := <-result:
		t.Fatalf("queued mutation returned before visibility changed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(releasePeerPrepare)
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrVisibilityInterrupted) {
			t.Fatalf("queued mutation = %v, want ErrVisibilityInterrupted", err)
		}
	case <-ctx.Done():
		t.Fatal("queued callback-serialized mutation did not wake for PREPARE")
	}
	if prepared || applied {
		t.Fatalf("interrupted queued mutation reached prepare=%v apply=%v", prepared, applied)
	}

	runBarrierFrom(t, h.coordinator, participant, prepare)
	if err := <-peer; err != nil {
		t.Fatalf("peer mutation: %v", err)
	}
}

// A conflicting callback must leave its per-key FIFO even when it is not the head.
// Otherwise one safe waiter in front of it would keep the callback alive while
// PREPARE waits for the FSKit lane that callback occupies.
func TestVisibilityDependencySequencerInterruptsConflictingNonHeadWaiter(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "peer-change")

	peerPreparing := make(chan struct{})
	releasePeerPrepare := make(chan struct{})
	peer := make(chan error, 1)
	go func() {
		peer <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1, FrontendOperationID: 41},
			testMutationDependencies("peer-change"),
			func() ([]VisibilityTarget, error) {
				close(peerPreparing)
				<-releasePeerPrepare
				return testVisibilityTargets("peer-change"), nil
			},
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("peer-change"), true
			},
		)
	}()
	<-peerPreparing

	var safePrepared atomic.Bool
	safe := make(chan error, 1)
	go func() {
		safe <- h.coordinator.Execute(
			context.Background(), SessionID{8}, MutationID{Sequence: 2, FrontendOperationID: 42},
			testMutationDependencies("safe-change"),
			func() ([]VisibilityTarget, error) {
				safePrepared.Store(true)
				return testVisibilityTargets("safe-change"), nil
			},
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("safe-change"), true
			},
		)
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)

	var hazardousPrepared atomic.Bool
	hazardous := make(chan error, 1)
	go func() {
		hazardous <- executeTestSourceGated(
			h.coordinator, context.Background(), participant, MutationID{Sequence: 3, FrontendOperationID: 43}, "local-change",
			func() ([]VisibilityTarget, error) {
				hazardousPrepared.Store(true)
				return testVisibilityTargets("local-change"), nil
			},
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("local-change"), true
			},
		)
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 2)

	close(releasePeerPrepare)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-hazardous:
		if !errors.Is(err, ErrVisibilityInterrupted) {
			t.Fatalf("non-head hazardous waiter = %v, want ErrVisibilityInterrupted", err)
		}
	case <-ctx.Done():
		t.Fatal("non-head hazardous waiter did not leave FIFO for PREPARE")
	}
	if hazardousPrepared.Load() {
		t.Fatal("interrupted non-head waiter reached prepare")
	}
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)
	if safePrepared.Load() {
		t.Fatal("safe per-key FIFO head prepared before the owner released the parent key")
	}

	runBarrierFrom(t, h.coordinator, participant, prepare)
	if err := <-peer; err != nil {
		t.Fatalf("peer mutation: %v", err)
	}
	if err := <-safe; err != nil {
		t.Fatalf("safe FIFO head: %v", err)
	}
	if !safePrepared.Load() {
		t.Fatal("safe FIFO head never prepared")
	}
}

// A namespace binding may change while a source request waits on its binding
// key. The authority refreshes only its internal bound identities after grant;
// the frontend-declared coordinate and scopes remain immutable. The refreshed
// identity, not the stale pre-enqueue one, enters the source's monotone index.
func TestVisibilityQueuedSourceRefreshesNamespaceBindingAfterGrant(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairLocklessExpiration)
	ownerPreparing := make(chan struct{})
	releaseOwner := make(chan struct{})
	owner := make(chan error, 1)
	go func() {
		owner <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("new"),
			func() ([]VisibilityTarget, error) {
				close(ownerPreparing)
				<-releaseOwner
				return testVisibilityTargets("new"), nil
			},
			func() ([]VisibilityTarget, bool) { return nil, false },
		)
	}()
	<-ownerPreparing

	var oldIdentity, newIdentity [16]byte
	oldIdentity[0], newIdentity[0] = 21, 22
	initial := testSourcePublicationGate("new")
	initial.Targets[0].BoundIdentities = [][16]byte{oldIdentity}
	current := oldIdentity
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.ExecuteWithSourceGate(
			context.Background(), source, MutationID{Sequence: 2}, h.coordinator.DeclareSourceGate(initial), initial,
			func() (SourcePublicationGate, error) {
				refreshed := testSourcePublicationGate("new")
				refreshed.Targets[0].BoundIdentities = [][16]byte{current}
				return refreshed, nil
			},
			testVisibilityPrepare("new"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("new"), true },
			func() ([]VisibilityResolution, error) { return nil, nil },
		)
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)
	current = newIdentity
	close(releaseOwner)
	if err := <-owner; err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	participant := h.coordinator.participants[source]
	hasOld := participant.index.contains(inodeKey(oldIdentity))
	hasNew := participant.index.contains(inodeKey(newIdentity))
	h.coordinator.mu.Unlock()
	if hasOld || !hasNew {
		t.Fatalf("source index stale/new binding = %v/%v, want false/true", hasOld, hasNew)
	}
}

// An item mutation with no held directory can queue while the current owner is
// still deriving PREPARE. If that owner then installs an overlapping peer
// phase, the source waiter must wake and abandon its dependency queue node
// immediately; otherwise the peer frontend waits for the source lease while
// the source waits for the peer-owned keys.
func TestVisibilityQueuedLinuxItemGateYieldsInternalRetryAndPreservesFIFO(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairLocklessExpiration)
	var identity [16]byte
	identity[0] = 31
	h.coordinator.RecordResolvedInode(source, identity)
	targets := []VisibilityTarget{{
		Scope: VisibilityAttributes, Identity: identity, KernelIno: 301, Device: 1,
	}}

	ownerPreparing := make(chan struct{})
	releaseOwnerPrepare := make(chan struct{})
	owner := make(chan error, 1)
	go func() {
		owner <- executeTestExact(h.coordinator, context.Background(), SessionID{9}, MutationID{Sequence: 1},
			mutationDependenciesForTargets(targets),
			func() ([]VisibilityTarget, error) {
				close(ownerPreparing)
				<-releaseOwnerPrepare
				return targets, nil
			},
			func() ([]VisibilityTarget, bool) { return targets, true })
	}()
	<-ownerPreparing

	gate := SourcePublicationGate{Targets: []SourcePublicationTarget{{Identity: identity, Attributes: true}}}
	var prepared atomic.Bool
	sourceResult := make(chan error, 1)
	go func() {
		sourceResult <- h.coordinator.ExecuteWithSourceGate(context.Background(), source, MutationID{Sequence: 2, FrontendOperationID: 77}, h.coordinator.DeclareSourceGate(gate), gate,
			func() (SourcePublicationGate, error) { return gate, nil },
			func() ([]VisibilityTarget, error) {
				prepared.Store(true)
				return targets, nil
			},
			func() ([]VisibilityTarget, bool) { return targets, true },
			func() ([]VisibilityResolution, error) { return nil, nil })
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)
	close(releaseOwnerPrepare)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-sourceResult:
		if !errors.Is(err, ErrVisibilityRetry) {
			t.Fatalf("queued item source = %v, want ErrVisibilityRetry", err)
		}
	case <-ctx.Done():
		t.Fatal("queued item source did not wake for overlapping PREPARE")
	}
	if prepared.Load() {
		t.Fatal("interrupted item source reached prepare")
	}
	h.coordinator.mu.Lock()
	dormant, exists := h.coordinator.fairness[source]
	h.coordinator.mu.Unlock()
	if !exists || dormant.active || !dormant.observed || dormant.operationID != 77 || !dormant.claimSameOperation || dormant.ordinal == 0 {
		t.Fatalf("dormant Linux item retry credit = %+v, present=%t", dormant, exists)
	}
	if err := h.coordinator.Ack(source, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, source, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}

	// Model the independent transport lanes exactly: the frontend has finished
	// the COMPLETE repair and sends its retry proof on DATA while the combined
	// COMPLETE ACK is still in flight on CONTROL. The proof may claim the
	// dormant ordinal, but it must remain behind the barrier owner until ACK.
	type acquired struct {
		turn *mutationSequencerWaiter
		err  error
	}
	retried := make(chan acquired, 1)
	go func() {
		turn, err := h.coordinator.acquireMutationDependencies(ctx, source, MutationID{
			Sequence: 3, FrontendOperationID: 77,
			VisibilityRetryAfterSequence: complete.Cursor.Sequence,
		}, nil, &gate, mutationDependenciesForSourceGate(gate), nil)
		retried <- acquired{turn: turn, err: err}
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)
	select {
	case got := <-retried:
		if got.turn != nil {
			got.turn.release()
		}
		t.Fatalf("proved retry escaped before COMPLETE ACK: %+v", got)
	case <-time.After(25 * time.Millisecond):
	}
	if err := h.coordinator.Ack(source, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-owner; err != nil {
		t.Fatal(err)
	}
	got := <-retried
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.turn.ordinal != dormant.ordinal {
		t.Fatalf("retried item ordinal = %d, want preserved %d", got.turn.ordinal, dormant.ordinal)
	}
	got.turn.release()
}

func TestVisibilityLinuxItemRetryProofIsExactAndMandatory(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairLocklessExpiration)
	var identity [16]byte
	identity[0] = 32
	gate := SourcePublicationGate{Targets: []SourcePublicationTarget{{Identity: identity, Attributes: true}}}
	h.coordinator.mu.Lock()
	h.coordinator.fairness[source] = mutationFairnessDebt{
		sequence: 41, ordinal: h.coordinator.sequencer.reserveOrdinal(), operationID: 77,
		claimSameOperation: true, gate: cloneSourcePublicationGate(gate), observed: true,
	}
	h.coordinator.mu.Unlock()

	for name, mutation := range map[string]MutationID{
		"omitted":         {Sequence: 2, FrontendOperationID: 77},
		"wrong sequence":  {Sequence: 2, FrontendOperationID: 77, VisibilityRetryAfterSequence: 40},
		"wrong operation": {Sequence: 2, FrontendOperationID: 78, VisibilityRetryAfterSequence: 41},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.coordinator.acquireMutationDependencies(t.Context(), source, mutation, nil, &gate, mutationDependenciesForSourceGate(gate), nil)
			if !errors.Is(err, ErrSourcePublicationGate) {
				t.Fatalf("retry proof error = %v, want ErrSourcePublicationGate", err)
			}
		})
	}

	t.Run("wrong gate", func(t *testing.T) {
		otherIdentity := identity
		otherIdentity[1] = 1
		otherGate := SourcePublicationGate{Targets: []SourcePublicationTarget{{Identity: otherIdentity, Attributes: true}}}
		_, err := h.coordinator.acquireMutationDependencies(t.Context(), source, MutationID{
			Sequence: 2, FrontendOperationID: 77, VisibilityRetryAfterSequence: 41,
		}, nil, &otherGate, mutationDependenciesForSourceGate(otherGate), nil)
		if !errors.Is(err, ErrSourcePublicationGate) {
			t.Fatalf("changed-gate retry proof error = %v, want ErrSourcePublicationGate", err)
		}
	})
}

// A currently negative namespace binding and an unrelated inode mutation have
// no shared cached observation. The namespace operation must not queue merely
// because the old volume-global turn would have put the inode operation first.
func TestVisibilityUnresolvedNamespaceGateRunsBesideDisjointItemMutation(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairLocklessExpiration)
	var newlyBound [16]byte
	newlyBound[0] = 41
	h.coordinator.RecordResolvedInode(source, newlyBound)
	itemTargets := []VisibilityTarget{{
		Scope: VisibilityAttributes, Identity: newlyBound, KernelIno: 401, Device: 1,
	}}

	ownerPreparing := make(chan struct{})
	releaseOwnerPrepare := make(chan struct{})
	owner := make(chan error, 1)
	go func() {
		owner <- executeTestExact(h.coordinator, context.Background(), SessionID{9}, MutationID{Sequence: 1},
			mutationDependenciesForTargets(itemTargets),
			func() ([]VisibilityTarget, error) {
				close(ownerPreparing)
				<-releaseOwnerPrepare
				return itemTargets, nil
			},
			func() ([]VisibilityTarget, bool) { return itemTargets, true })
	}()
	<-ownerPreparing

	gate := testSourcePublicationGate("new") // no pre-binding identity exists
	var prepared atomic.Bool
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.ExecuteWithSourceGate(context.Background(), source, MutationID{Sequence: 2, FrontendOperationID: 77}, h.coordinator.DeclareSourceGate(gate), gate,
			func() (SourcePublicationGate, error) { return gate, nil },
			func() ([]VisibilityTarget, error) {
				prepared.Store(true)
				return testVisibilityTargets("new"), nil
			},
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("new"), true },
			func() ([]VisibilityResolution, error) { return nil, nil })
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("disjoint unresolved namespace mutation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disjoint unresolved namespace mutation waited behind inode mutation")
	}
	if !prepared.Load() {
		t.Fatal("disjoint unresolved namespace mutation never prepared")
	}
	close(releaseOwnerPrepare)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	runBarrierFrom(t, h.coordinator, source, prepare)
	if err := <-owner; err != nil {
		t.Fatal(err)
	}
}

func TestVisibilityLocklessNamespaceRetryKeepsItsFIFOPositionThroughCompleteAck(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairLocklessExpiration)
	h.resolve(t, source, "same-name")
	targets := testVisibilityTargets("same-name")
	gate := testSourcePublicationGate("same-name")

	peer := make(chan error, 1)
	go func() {
		peer <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			mutationDependenciesForTargets(targets),
			func() ([]VisibilityTarget, error) { return targets, nil },
			func() ([]VisibilityTarget, bool) { return targets, true })
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, source)
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.coordinator.ExecuteWithSourceGateSequence(ctx, source, MutationID{
		Sequence: 2, FrontendOperationID: 88,
	}, h.coordinator.DeclareSourceGate(gate), gate, func() (SourcePublicationGate, error) { return gate, nil },
		func() ([]VisibilityTarget, error) {
			t.Fatal("namespace retry reached prepare before its peer repair")
			return nil, nil
		}, func(uint64) ([]VisibilityTarget, bool) {
			t.Fatal("namespace retry reached apply before its peer repair")
			return nil, false
		}, func() ([]VisibilityResolution, error) { return nil, nil })
	retrySequence, ok := VisibilityRetrySequence(err)
	if !ok || retrySequence != prepare.Cursor.Sequence {
		t.Fatalf("namespace first attempt = %v sequence=%d, want retry for %d", err, retrySequence, prepare.Cursor.Sequence)
	}

	if err := h.coordinator.Ack(source, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, source, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	var prepared, applied atomic.Bool
	retried := make(chan error, 1)
	go func() {
		_, executeErr := h.coordinator.ExecuteWithSourceGateSequence(ctx, source, MutationID{
			Sequence: 3, FrontendOperationID: 88, VisibilityRetryAfterSequence: complete.Cursor.Sequence,
		}, h.coordinator.DeclareSourceGate(gate), gate, func() (SourcePublicationGate, error) { return gate, nil },
			func() ([]VisibilityTarget, error) {
				prepared.Store(true)
				return targets, nil
			}, func(uint64) ([]VisibilityTarget, bool) {
				applied.Store(true)
				return targets, true
			}, func() ([]VisibilityResolution, error) { return nil, nil })
		retried <- executeErr
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)
	select {
	case err := <-retried:
		t.Fatalf("proved namespace retry escaped before COMPLETE Ack: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if prepared.Load() || applied.Load() {
		t.Fatal("proved namespace retry reached filesystem work before COMPLETE Ack")
	}
	if err := h.coordinator.Ack(source, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
	if err := <-retried; err != nil {
		t.Fatal(err)
	}
	if !prepared.Load() || !applied.Load() {
		t.Fatalf("namespace retry prepare=%t apply=%t, want both after Ack", prepared.Load(), applied.Load())
	}
}

// Linux enters the authority while its namespace callback already holds the
// parent i_rwsem. If a peer COMPLETE for that parent is installed while the
// request waits for a shared dependency, letting it continue to wait closes a
// cycle: COMPLETE needs the lock and only this request's reply releases it.
// The authority has both exact ordering facts, so it refuses this one request
// before prepare/apply instead of fencing the whole mount after its budget.
func TestVisibilityParentExclusiveQueuedMutationYieldsForOverlappingComplete(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairParentExclusive)
	h.resolve(t, participant, "peer-change")

	peer := make(chan error, 1)
	go func() {
		peer <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("peer-change"),
			testVisibilityPrepare("peer-change"),
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("peer-change"), true
			},
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}

	var prepared, applied atomic.Bool
	local := make(chan error, 1)
	go func() {
		local <- executeTestSourceGatedHeld(
			h.coordinator, ctx, participant, MutationID{Sequence: 2}, "local-change", [][16]byte{testVisibilityParent()},
			func() ([]VisibilityTarget, error) {
				prepared.Store(true)
				return testVisibilityTargets("local-change"), nil
			},
			func() ([]VisibilityTarget, bool) {
				applied.Store(true)
				return testVisibilityTargets("local-change"), true
			},
		)
	}()
	select {
	case err := <-local:
		t.Fatalf("parent-exclusive mutation was refused during lock-free PREPARE: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Cursor.Phase != VisibilityComplete {
		t.Fatalf("phase = %v, want COMPLETE", complete.Cursor.Phase)
	}
	select {
	case err := <-local:
		t.Fatalf("parent-exclusive mutation was interrupted without an exact frontend report: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := h.coordinator.ReportBlocked(ctx, participant, complete.Cursor, []uint64{101}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-local:
		if !errors.Is(err, ErrVisibilityInterrupted) {
			t.Fatalf("overlapping parent-exclusive mutation = %v, want ErrVisibilityInterrupted", err)
		}
	case <-ctx.Done():
		t.Fatal("overlapping parent-exclusive mutation did not release its parent for COMPLETE")
	}
	if prepared.Load() || applied.Load() {
		t.Fatalf("interrupted parent-exclusive mutation reached prepare=%v apply=%v", prepared.Load(), applied.Load())
	}
	if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-peer; err != nil {
		t.Fatalf("peer mutation: %v", err)
	}
	if !h.fencer.live(participant) || h.fencer.wasFenced(participant) {
		t.Fatal("one overlapping Linux operation fenced the participant")
	}
}

func TestVisibilityParentExclusiveDifferentParentKeepsOrdinaryOrder(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairParentExclusive)
	h.resolve(t, participant, "peer-change")

	peer := make(chan error, 1)
	go func() {
		peer <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("peer-change"),
			testVisibilityPrepare("peer-change"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("peer-change"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}

	differentParent := [16]byte{2}
	local := make(chan error, 1)
	go func() {
		local <- executeTestSourceGatedHeld(
			h.coordinator, ctx, participant, MutationID{Sequence: 2}, "local-change", [][16]byte{differentParent},
			testVisibilityPrepare("local-change"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("local-change"), true },
		)
	}()
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.ReportBlocked(ctx, participant, complete.Cursor, []uint64{101}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-local:
		t.Fatalf("different-parent mutation returned under a disjoint interruption: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	// The accepted report may be retransmitted after the Ack response wins the
	// other network lane. Exact replay remains a no-op after acknowledgment.
	if err := h.coordinator.ReportBlocked(ctx, participant, complete.Cursor, []uint64{101, 101}); err != nil {
		t.Fatalf("accepted report replayed after Ack: %v", err)
	}
	if err := <-peer; err != nil {
		t.Fatalf("peer mutation: %v", err)
	}

	if err := <-local; err != nil {
		t.Fatalf("different-parent mutation: %v", err)
	}
}

// rename(2) holds both parent i_rwsems across its authority round trip. An
// exact interruption for either one must therefore refuse the whole operation
// before prepare/apply. Naming the same parent twice is the same operation, not
// two obligations, and must remain a harmless duplicate in the held set.
func TestVisibilityParentExclusiveRenameYieldsForEitherParent(t *testing.T) {
	overlap := testVisibilityParent()
	disjoint := [16]byte{2}
	for _, test := range []struct {
		name string
		held [][16]byte
	}{
		{name: "old parent", held: [][16]byte{overlap, disjoint}},
		{name: "new parent", held: [][16]byte{disjoint, overlap}},
		{name: "same parent", held: [][16]byte{overlap, overlap}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
			participant := SessionID{1}
			h.registerRepair(t, participant, testRepairBudget, NamespaceRepairParentExclusive)
			h.resolve(t, participant, "peer-change")

			peer := make(chan error, 1)
			go func() {
				peer <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
					testMutationDependencies("peer-change"),
					testVisibilityPrepare("peer-change"),
					func() ([]VisibilityTarget, bool) { return testVisibilityTargets("peer-change"), true })
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
				t.Fatal(err)
			}
			complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.coordinator.ReportBlocked(ctx, participant, complete.Cursor, []uint64{101}); err != nil {
				t.Fatal(err)
			}

			var prepared, applied atomic.Bool
			err = executeTestSourceGatedHeld(h.coordinator, ctx, participant, MutationID{Sequence: 2}, "rename", test.held,
				func() ([]VisibilityTarget, error) {
					prepared.Store(true)
					return testVisibilityTargets("rename"), nil
				},
				func() ([]VisibilityTarget, bool) {
					applied.Store(true)
					return testVisibilityTargets("rename"), true
				})
			if !errors.Is(err, ErrVisibilityInterrupted) {
				t.Fatalf("two-parent rename = %v, want ErrVisibilityInterrupted", err)
			}
			if prepared.Load() || applied.Load() {
				t.Fatalf("interrupted rename reached prepare=%v apply=%v", prepared.Load(), applied.Load())
			}
			if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
				t.Fatal(err)
			}
			if err := <-peer; err != nil {
				t.Fatal(err)
			}
			if h.fencer.wasFenced(participant) || !h.fencer.live(participant) {
				t.Fatal("one interrupted rename fenced the participant")
			}
		})
	}
}

// The frozen callback-serialized profile interrupts a local callback whenever
// it owes a peer phase; source phases no longer exist.
func TestVisibilityCallbackSerializedFrozenProfileInterruptsDuringPeerPhase(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairCallbackSerialized)
	h.resolve(t, source, "first")

	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.Execute(
			context.Background(), SessionID{9},
			MutationID{Sequence: 1, FrontendOperationID: 41},
			testMutationDependencies("first"),
			testVisibilityPrepare("first"),
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("first"), true
			},
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, source)
	if err != nil {
		t.Fatal(err)
	}

	prepared, applied := false, false
	err = executeTestSourceGated(
		h.coordinator, context.Background(), source,
		MutationID{Sequence: 2, FrontendOperationID: 42}, "second",
		func() ([]VisibilityTarget, error) {
			prepared = true
			return testVisibilityTargets("second"), nil
		},
		func() ([]VisibilityTarget, bool) {
			applied = true
			return testVisibilityTargets("second"), true
		},
	)
	if !errors.Is(err, ErrVisibilityInterrupted) || prepared || applied {
		t.Fatalf("frozen callback during peer phase = %v prepare=%v apply=%v, want interruption", err, prepared, applied)
	}

	runBarrierFrom(t, h.coordinator, source, prepare)
	if err := <-first; err != nil {
		t.Fatalf("peer frozen-profile mutation: %v", err)
	}
}

// A strict source cannot enter cache-visible dependency sequencing without the exact
// pre-dispatch publication cut. Refusal is definite-preapply and cannot mutate
// either XFS or the source's resolved index.
func TestVisibilityStrictSourceWithoutPublicationGateIsRefused(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.register(t, source, testRepairBudget)
	prepared, applied := false, false
	err := h.coordinator.Execute(
		context.Background(), source, MutationID{Sequence: 1},
		testMutationDependencies("missing"),
		func() ([]VisibilityTarget, error) {
			prepared = true
			return testVisibilityTargets("missing"), nil
		},
		func() ([]VisibilityTarget, bool) {
			applied = true
			return testVisibilityTargets("missing"), true
		},
	)
	if !errors.Is(err, ErrSourcePublicationGate) {
		t.Fatalf("strict mutation without gate = %v, want ErrSourcePublicationGate", err)
	}
	if prepared || applied {
		t.Fatalf("missing-gate mutation reached prepare=%v apply=%v", prepared, applied)
	}
}

// A frontend operation identity is retry-fairness metadata only. It never lets
// a callback-serialized source cross an outstanding peer PREPARE or COMPLETE.
func TestVisibilityPeerPhaseAdmissionIsFailSafe(t *testing.T) {
	for _, test := range []struct {
		name        string
		repair      NamespaceRepair
		initiator   SessionID
		pendingOpID uint64
		mutation    MutationID
	}{
		{
			name:   "proof cannot exempt a peer phase",
			repair: NamespaceRepairCallbackSerializedPipelined, initiator: SessionID{9}, pendingOpID: 41,
			mutation: MutationID{Sequence: 2, FrontendOperationID: 42},
		},
		{
			name:   "proof cannot change frozen callback serialized profile",
			repair: NamespaceRepairCallbackSerialized, initiator: SessionID{9}, pendingOpID: 41,
			mutation: MutationID{Sequence: 2, FrontendOperationID: 42},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
			source := SessionID{1}
			h.registerRepair(t, source, testRepairBudget, test.repair)
			h.resolve(t, source, "first")

			first := make(chan error, 1)
			go func() {
				first <- h.coordinator.Execute(
					context.Background(), test.initiator,
					MutationID{Sequence: 1, FrontendOperationID: test.pendingOpID},
					testMutationDependencies("first"),
					testVisibilityPrepare("first"),
					func() ([]VisibilityTarget, bool) {
						return testVisibilityTargets("first"), true
					},
				)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, source)
			if err != nil {
				t.Fatal(err)
			}

			assertInterrupted := func(phase string, sequence uint64) {
				t.Helper()
				prepared, applied := false, false
				mutation := test.mutation
				mutation.Sequence = sequence
				err := executeTestSourceGated(
					h.coordinator, context.Background(), source, mutation, "blocked",
					func() ([]VisibilityTarget, error) {
						prepared = true
						return testVisibilityTargets("blocked"), nil
					},
					func() ([]VisibilityTarget, bool) {
						applied = true
						return testVisibilityTargets("blocked"), true
					},
				)
				if !errors.Is(err, ErrVisibilityInterrupted) {
					t.Fatalf("mutation during %s = %v, want ErrVisibilityInterrupted", phase, err)
				}
				if prepared || applied {
					t.Fatalf("mutation during %s reached prepare=%v apply=%v", phase, prepared, applied)
				}
			}

			assertInterrupted("PREPARE", 2)
			if err := h.coordinator.Ack(source, prepare.Cursor); err != nil {
				t.Fatal(err)
			}
			complete, err := h.coordinator.Next(ctx, source, prepare.Cursor)
			if err != nil {
				t.Fatal(err)
			}
			assertInterrupted("COMPLETE", 3)
			if err := h.coordinator.Ack(source, complete.Cursor); err != nil {
				t.Fatal(err)
			}
			if err := <-first; err != nil {
				t.Fatalf("initiating peer mutation: %v", err)
			}
		})
	}
}

// DATA repair includes attributes on both frontend implementations. Therefore
// an attributes lease overlaps ATTR and DATA peer targets, and a data lease
// (which necessarily carries attributes) does too.
func TestVisibilitySourceGateOverlapHonorsRequestedScope(t *testing.T) {
	var identity [16]byte
	identity[0] = 7
	attributesOnly := SourcePublicationGate{Targets: []SourcePublicationTarget{{Identity: identity, Attributes: true}}}
	data := SourcePublicationGate{Targets: []SourcePublicationTarget{{Identity: identity, Attributes: true, Data: true}}}
	attributeTarget := []VisibilityTarget{{Scope: VisibilityAttributes, Identity: identity}}
	dataTarget := []VisibilityTarget{{Scope: VisibilityData, Identity: identity, Size: 1}}
	if !attributesOnly.overlaps(attributeTarget) || !attributesOnly.overlaps(dataTarget) {
		t.Fatal("attributes-only source gate did not overlap DATA's attribute repair")
	}
	if !data.overlaps(attributeTarget) || !data.overlaps(dataTarget) {
		t.Fatal("data source gate did not imply attributes and data")
	}
	boundAttributes := SourcePublicationGate{Targets: []SourcePublicationTarget{{
		ParentIdentity: testVisibilityParent(), Name: []byte("child"), BoundAttributes: true,
		BoundIdentities: [][16]byte{identity},
	}}}
	if !boundAttributes.overlaps(attributeTarget) || !boundAttributes.overlaps(dataTarget) {
		t.Fatal("namespace bound-attributes gate did not overlap DATA's attribute repair")
	}
}

// Only CALLBACK_SERIALIZED has the volume-global callback-lane constraint.
// INDEPENDENT repair can run beside an unanswered mutation, and the existing
// PARENT_EXCLUSIVE model keeps its coordinate-specific blocked-report contract;
// neither profile is refused merely because a visibility phase is pending.
func TestVisibilityOtherRepairProfilesWaitAndApply(t *testing.T) {
	for _, test := range []struct {
		name   string
		repair NamespaceRepair
	}{
		{"independent", NamespaceRepairIndependent},
		{"parent-exclusive", NamespaceRepairParentExclusive},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
			participant := SessionID{1}
			h.registerRepair(t, participant, testRepairBudget, test.repair)
			h.resolve(t, participant, "peer-change")

			peer := make(chan error, 1)
			go func() {
				peer <- h.coordinator.Execute(
					context.Background(), SessionID{9}, MutationID{Sequence: 1},
					testMutationDependencies("peer-change"),
					testVisibilityPrepare("peer-change"),
					func() ([]VisibilityTarget, bool) {
						return testVisibilityTargets("peer-change"), true
					},
				)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			peerPrepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
			if err != nil {
				t.Fatal(err)
			}

			var prepared, applied atomic.Bool
			local := make(chan error, 1)
			go func() {
				local <- executeTestSourceGated(
					h.coordinator, ctx, participant, MutationID{Sequence: 2}, "local-change",
					func() ([]VisibilityTarget, error) {
						prepared.Store(true)
						return testVisibilityTargets("local-change"), nil
					},
					func() ([]VisibilityTarget, bool) {
						applied.Store(true)
						return testVisibilityTargets("local-change"), true
					},
				)
			}()
			select {
			case err := <-local:
				t.Fatalf("profile %s was refused instead of waiting: %v", test.name, err)
			case <-time.After(20 * time.Millisecond):
			}
			if prepared.Load() || applied.Load() {
				t.Fatalf("profile %s crossed dependency order early: prepare=%v apply=%v", test.name, prepared.Load(), applied.Load())
			}

			if err := h.coordinator.Ack(participant, peerPrepare.Cursor); err != nil {
				t.Fatal(err)
			}
			peerComplete, err := h.coordinator.Next(ctx, participant, peerPrepare.Cursor)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.coordinator.Ack(participant, peerComplete.Cursor); err != nil {
				t.Fatal(err)
			}
			if err := <-peer; err != nil {
				t.Fatalf("peer mutation: %v", err)
			}

			if err := <-local; err != nil {
				t.Fatalf("profile %s local mutation: %v", test.name, err)
			}
			if !prepared.Load() || !applied.Load() {
				t.Fatalf("profile %s reached prepare=%v apply=%v", test.name, prepared.Load(), applied.Load())
			}
			idle, cancelIdle := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancelIdle()
			if _, err := h.coordinator.Next(idle, participant, peerComplete.Cursor); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("profile %s source received its own phase: %v", test.name, err)
			}
		})
	}
}

// A mount caches the bindings it creates, not only the ones it looked up. A
// rename binds (newparent, newname) in the initiating mount's cache without
// that mount ever having resolved it, so the index has to learn the coordinate
// from the mutation itself or the next event for that name would skip a mount
// that holds it.
func TestVisibilitySourceIndexesTheNamesItsOwnMutationBound(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	mover, bystander := SessionID{1}, SessionID{2}
	h.register(t, mover, testRepairBudget)
	h.register(t, bystander, testRepairBudget)
	// The mover resolved only the old name. It learns the new binding by making
	// it; nothing on the read path ever tells the authority about it.
	h.resolve(t, mover, "old")

	parent := testVisibilityParent()
	rename := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("old")},
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("new")},
	}
	gate := SourcePublicationGate{Targets: []SourcePublicationTarget{
		{Identity: parent, Attributes: true},
		{ParentIdentity: parent, Name: []byte("new"), BoundAttributes: true},
		{ParentIdentity: parent, Name: []byte("old"), BoundAttributes: true},
	}}
	err := h.coordinator.ExecuteWithSourceGate(context.Background(), mover, MutationID{Sequence: 1}, h.coordinator.DeclareSourceGate(gate), gate,
		func() (SourcePublicationGate, error) { return gate, nil },
		func() ([]VisibilityTarget, error) { return rename, nil },
		func() ([]VisibilityTarget, bool) { return rename, true },
		func() ([]VisibilityResolution, error) { return nil, nil })
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Someone else now touches the name the rename created.
	second := make(chan error, 1)
	go func() {
		second <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 2},
			testMutationDependencies("new"),
			testVisibilityPrepare("new"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("new"), true
			})
	}()
	event, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, mover)
	if err != nil {
		t.Fatalf("mount that bound the name by renaming was left out of the barrier: %v", err)
	}
	if event.Cursor.Phase != VisibilityPrepare {
		t.Fatalf("phase = %v, want prepare", event.Cursor.Phase)
	}
	runBarrierFrom(t, h.coordinator, mover, event)
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second mutation never completed")
	}
	idle, cancelIdle := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelIdle()
	if _, err := nextFromInitialVisibilityCursor(t, h.coordinator, idle, bystander); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a mount that touched neither name received %v, want no event", err)
	}
}

// runBarrierFrom finishes a barrier whose PREPARE the caller already took.
func runBarrierFrom(t *testing.T, coordinator *VisibilityCoordinator, id SessionID, prepare VisibilityEvent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := coordinator.Ack(id, prepare.Cursor); err != nil {
		t.Fatalf("ack prepare for %x: %v", id, err)
	}
	complete, err := coordinator.Next(ctx, id, prepare.Cursor)
	if err != nil {
		t.Fatalf("complete for %x: %v", id, err)
	}
	if err := coordinator.Ack(id, complete.Cursor); err != nil {
		t.Fatalf("ack complete for %x: %v", id, err)
	}
}

// A Linux parent-exclusive callback already holds the parent i_rwsem when its
// request queues behind a peer mutation. The exact cached-name report installs
// a scoped interruption, so that one pre-apply operation releases the lock and
// the same mount repairs COMPLETE instead of being fenced.
func TestVisibilityParkedMountReportInterruptsOperationAndPreservesMount(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	parked, mutator := SessionID{1}, SessionID{2}
	const parkedBudget = 80 * time.Millisecond
	h.register(t, parked, parkedBudget)
	h.register(t, mutator, testRepairBudget)
	// Both mounts hold names in the same directory.
	h.resolve(t, parked, "shared")
	h.resolve(t, mutator, "shared")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The other mount is healthy: it answers every phase it is given.
	go serviceVisibility(ctx, h.coordinator, mutator)

	// The other mount's mutation starts and reaches PREPARE on the mount that
	// is about to park.
	first := make(chan error, 1)
	go func() {
		first <- executeTestSourceGated(h.coordinator, context.Background(), mutator, MutationID{Sequence: 1}, "shared",
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("shared"), true
			})
	}()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, parked)
	if err != nil {
		t.Fatal(err)
	}
	// PREPARE only closes a frontend-local publication gate, so a mount can
	// still answer it while its own syscall holds the directory lock. Only
	// COMPLETE needs the kernel lock, which is why only COMPLETE is reportable.
	if err := h.coordinator.Ack(parked, prepare.Cursor); err != nil {
		t.Fatal(err)
	}

	parkedDone := make(chan error, 1)
	go func() {
		parkedDone <- executeTestSourceGatedHeld(h.coordinator, context.Background(), parked, MutationID{Sequence: 1}, "shared",
			[][16]byte{testVisibilityParent()},
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("shared"), true
			})
	}()

	// It receives the COMPLETE, finds it holds a cached binding in a directory
	// its own unanswered syscall is holding, and says so rather than hanging.
	complete, err := h.coordinator.Next(ctx, parked, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.ReportBlocked(context.Background(), parked, complete.Cursor, []uint64{101}); err != nil {
		t.Fatalf("ReportBlocked = %v", err)
	}

	select {
	case err := <-parkedDone:
		if !errors.Is(err, ErrVisibilityInterrupted) {
			t.Fatalf("parked mutation = %v, want ErrVisibilityInterrupted", err)
		}
	case <-ctx.Done():
		t.Fatal("the parked operation did not release its parent")
	}
	// The interruption remains active until COMPLETE is acknowledged. A quick
	// application retry cannot retake the parent and recreate the same cycle.
	stillScoped := make(chan error, 1)
	go func() {
		stillScoped <- executeTestSourceGatedHeld(h.coordinator, context.Background(), parked, MutationID{Sequence: 2}, "too-early-retry",
			[][16]byte{testVisibilityParent()}, testVisibilityPrepare("too-early-retry"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("too-early-retry"), true })
	}()
	select {
	case err := <-stillScoped:
		if !errors.Is(err, ErrVisibilityInterrupted) {
			t.Fatalf("retry before COMPLETE Ack = %v, want ErrVisibilityInterrupted", err)
		}
	case <-ctx.Done():
		t.Fatal("retry before COMPLETE Ack recreated the parent-lock cycle")
	}
	if err := h.coordinator.Ack(parked, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-first:
		if err != nil {
			t.Fatalf("peer mutation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("peer mutation did not finish after repair Ack")
	}
	if h.fencer.wasFenced(parked) || !h.fencer.live(parked) || !h.fencer.live(mutator) {
		t.Fatal("cycle breaking did not preserve both mounts")
	}

	retry := make(chan error, 1)
	go func() {
		retry <- executeTestSourceGatedHeld(h.coordinator, context.Background(), parked, MutationID{Sequence: 3}, "retry",
			[][16]byte{testVisibilityParent()}, testVisibilityPrepare("retry"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("retry"), true })
	}()
	if err := <-retry; err != nil {
		t.Fatalf("fresh retry after cycle break: %v", err)
	}
}

// The visibility stream and ordinary mutation stream are independent network
// lanes. A blocked report may therefore reach the authority before the
// operation whose callback already holds the parent. Installing the exact
// scope first makes that ordering equivalent: the later request is still
// refused before prepare/apply, the lock drains, and the mount survives.
func TestVisibilityBlockedReportBeforeOrdinaryRequestIsRaceSafe(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairParentExclusive)
	h.resolve(t, participant, "peer-change")

	peer := make(chan error, 1)
	go func() {
		peer <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("peer-change"),
			testVisibilityPrepare("peer-change"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("peer-change"), true })
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.ReportBlocked(ctx, participant, complete.Cursor, []uint64{101}); err != nil {
		t.Fatal(err)
	}
	// A lost success response is retried with the same cursor and exact parent
	// set. That duplicate is idempotent, not a second state transition.
	if err := h.coordinator.ReportBlocked(ctx, participant, complete.Cursor, []uint64{101, 101}); err != nil {
		t.Fatalf("duplicate exact report: %v", err)
	}

	var prepared, applied atomic.Bool
	operation := make(chan error, 1)
	go func() {
		operation <- executeTestSourceGatedHeld(h.coordinator, ctx, participant, MutationID{Sequence: 2}, "blocked",
			[][16]byte{testVisibilityParent()},
			func() ([]VisibilityTarget, error) {
				prepared.Store(true)
				return testVisibilityTargets("local-change"), nil
			},
			func() ([]VisibilityTarget, bool) {
				applied.Store(true)
				return testVisibilityTargets("local-change"), true
			})
	}()
	select {
	case err := <-operation:
		if !errors.Is(err, ErrVisibilityInterrupted) {
			t.Fatalf("request arriving after report = %v, want ErrVisibilityInterrupted", err)
		}
	case <-ctx.Done():
		t.Fatal("request arriving after blocked report was not interrupted")
	}
	if prepared.Load() || applied.Load() {
		t.Fatalf("request arriving after report reached prepare=%v apply=%v", prepared.Load(), applied.Load())
	}
	if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
	// Advance the cursor through a later mutation, then deliver the old accepted
	// report once more. A canceled/reconnected server worker can be this late;
	// stale control replay is a no-op, never a reason to fence the mount.
	later := make(chan error, 1)
	go func() {
		later <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 3},
			testMutationDependencies("peer-change"),
			testVisibilityPrepare("peer-change"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("peer-change"), true })
	}()
	laterPrepare, err := h.coordinator.Next(ctx, participant, complete.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	runBarrierFrom(t, h.coordinator, participant, laterPrepare)
	if err := <-later; err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.ReportBlocked(ctx, participant, complete.Cursor, []uint64{101}); err != nil {
		t.Fatalf("accepted blocked report replayed after a later phase: %v", err)
	}
	if h.fencer.wasFenced(participant) || !h.fencer.live(participant) {
		t.Fatal("report-before-request ordering fenced the participant")
	}
}

// Being parked in the affected directory is only half the cycle. The other half
// is holding a cached binding the COMPLETE names, and this authority cannot see
// it: the resolved-name index is a monotone filter with no false negatives, so
// it addresses every mount that ever resolved anything in that directory,
// whether or not it still caches the name. A mount that is merely busy in the
// same tree as another must repair and carry on.
//
// This is the shape of an ordinary shared build directory - two agents in one
// workspace - so getting it wrong is not a corner case, it is continuous
// fencing of healthy mounts. An earlier revision of this coordinator decided
// the cycle from the parked half alone and did exactly that.
func TestVisibilityParkedMountThatCanRepairIsNeverFenced(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	parked, mutator := SessionID{1}, SessionID{2}
	h.register(t, parked, testRepairBudget)
	h.register(t, mutator, testRepairBudget)
	h.resolve(t, parked, "shared")
	h.resolve(t, mutator, "shared")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go serviceVisibility(ctx, h.coordinator, mutator)
	// It answers every phase. Having a mutation of its own waiting for order in
	// the same directory does not stop it: it holds nothing cached that this
	// COMPLETE names, so its repair never reaches the kernel.
	go serviceVisibility(ctx, h.coordinator, parked)

	release := make(chan struct{})
	parkedDone := make(chan error, 1)
	go func() {
		<-release
		parkedDone <- executeTestSourceGatedHeld(h.coordinator, context.Background(), parked, MutationID{Sequence: 1}, "shared",
			[][16]byte{testVisibilityParent()},
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("shared"), true
			})
	}()

	if err := executeTestSourceGated(h.coordinator, context.Background(), mutator, MutationID{Sequence: 1}, "shared",
		testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
			return testVisibilityTargets("shared"), true
		}); err != nil {
		t.Fatalf("mutation against a mount that could repair: %v", err)
	}
	if h.fencer.wasFenced(parked) {
		t.Fatalf("a mount that repaired while parked was fenced for %v", h.fenceReasonFor(parked))
	}
	close(release)
	select {
	case err := <-parkedDone:
		if err != nil {
			t.Fatalf("the parked mutation itself failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the parked mutation never returned")
	}
}

// One mount doing what a package manager does - thousands of sequential
// mutations in one directory, each one submitted while the previous is still
// being ordered - is the ordinary workload, not a cycle. The mount is the
// source of every one of those mutations, and a source is excluded from its own
// audience: its own reply is what rebinds the name, so it is never asked for a
// synchronous repair of its own change and can never be fenced for parking
// behind itself.
func TestVisibilityOneMountMutatingSequentiallyIsNeverFenced(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	only := SessionID{1}
	h.register(t, only, testRepairBudget)
	h.resolve(t, only, "shared")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go serviceVisibility(ctx, h.coordinator, only)

	// Every submission declares the exact directory its kernel callback holds.
	for sequence := uint64(1); sequence <= 64; sequence++ {
		err := executeTestSourceGatedHeld(h.coordinator, context.Background(), only, MutationID{Sequence: sequence}, "shared",
			[][16]byte{testVisibilityParent()},
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("shared"), true
			})
		if err != nil {
			t.Fatalf("sequential mutation %d: %v", sequence, err)
		}
		if h.fencer.wasFenced(only) {
			t.Fatalf("the only mount was fenced at mutation %d for %v", sequence, h.fenceReasonFor(only))
		}
	}
}

// Two mounts working in different directories share nothing the cycle needs.
// Neither may be fenced, however busy both are.
func TestVisibilityTwoMountsInDifferentDirectoriesAreNeverFenced(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	first, second := SessionID{1}, SessionID{2}
	h.register(t, first, testRepairBudget)
	h.register(t, second, testRepairBudget)
	h.resolve(t, first, "shared")
	h.resolve(t, second, "shared")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go serviceVisibility(ctx, h.coordinator, first)
	go serviceVisibility(ctx, h.coordinator, second)

	var elsewhere [16]byte
	elsewhere[0] = 2
	for sequence := uint64(1); sequence <= 16; sequence++ {
		for _, submission := range []struct {
			source SessionID
			parent [16]byte
		}{{first, testVisibilityParent()}, {second, elsewhere}} {
			if err := executeTestSourceGatedHeld(h.coordinator, context.Background(), submission.source, MutationID{Sequence: sequence}, "shared",
				[][16]byte{submission.parent},
				testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
					return testVisibilityTargets("shared"), true
				}); err != nil {
				t.Fatalf("mutation %d from %x: %v", sequence, submission.source, err)
			}
		}
	}
	for _, id := range []SessionID{first, second} {
		if h.fencer.wasFenced(id) {
			t.Fatalf("mount %x was fenced for %v while working in its own directory", id, h.fenceReasonFor(id))
		}
	}
}

// A blocked report never acknowledges the phase, but it still may not install
// an interruption for an unsupported phase or coordinate. The authority maps
// reported coordination inodes only through the exact pending COMPLETE and
// fences a client whose report cannot be reconciled with that cursor.
func TestVisibilityUnsupportedBlockedReportIsACursorViolation(t *testing.T) {
	for _, name := range []string{"prepare", "unknown complete parent"} {
		t.Run(name, func(t *testing.T) {
			h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
			claimant, mutator := SessionID{1}, SessionID{2}
			h.register(t, claimant, 80*time.Millisecond)
			h.register(t, mutator, testRepairBudget)
			h.resolve(t, claimant, "shared")
			h.resolve(t, mutator, "shared")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go serviceVisibility(ctx, h.coordinator, mutator)
			done := make(chan error, 1)
			go func() {
				done <- executeTestSourceGated(h.coordinator, context.Background(), mutator, MutationID{Sequence: 1}, "shared",
					testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
						return testVisibilityTargets("shared"), true
					})
			}()
			prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, claimant)
			if err != nil {
				t.Fatal(err)
			}
			cursor := prepare.Cursor
			parents := []uint64(nil)
			if name == "unknown complete parent" {
				if err := h.coordinator.Ack(claimant, prepare.Cursor); err != nil {
					t.Fatal(err)
				}
				complete, err := h.coordinator.Next(ctx, claimant, prepare.Cursor)
				if err != nil {
					t.Fatal(err)
				}
				cursor = complete.Cursor
				parents = []uint64{999}
			}
			if err := h.coordinator.ReportBlocked(context.Background(), claimant, cursor, parents); !errors.Is(err, ErrVisibilitySequence) {
				t.Fatalf("unsupported blocked report = %v, want ErrVisibilitySequence", err)
			}
			if reason := h.fenceReasonFor(claimant); !errors.Is(reason, ErrVisibilitySequence) {
				t.Fatalf("fenced for %v, want ErrVisibilitySequence", reason)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("the mutation failed after refusing a false claim: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("refusing a false blocked report stalled the mutation")
			}
		})
	}
}

// serviceVisibility is a healthy mount: it acknowledges every phase it is
// handed, for as long as its session lives.
func serviceVisibility(ctx context.Context, coordinator *VisibilityCoordinator, id SessionID) {
	after, err := coordinator.InitialCursor(id)
	if err != nil {
		return
	}
	for {
		event, err := coordinator.Next(ctx, id, after)
		if err != nil {
			return
		}
		if err := coordinator.Ack(id, event.Cursor); err != nil {
			return
		}
		after = event.Cursor
	}
}

// A refused attach reaches the mount as a bare errno, so the authority side has
// to say which declared number exceeded which bound. Without that an operator
// holds two configuration files and no way to tell which one is wrong.
func TestVisibilityRefusedCommitmentNamesBothValues(t *testing.T) {
	membership := newTestDurableVisibilityMembership()
	fencer := newTestFencer()
	var refusals []error
	coordinator, err := NewVisibilityCoordinator(VisibilityConfig{
		Prior: PriorEpochStrictMountsFenced, Membership: membership, Fencer: fencer,
		MaxCachedNameCapacity: 4096, MaxRepairBudget: 5 * time.Second, MaxClockSkew: 0,
		OnRefusedCommitment: func(_ SessionID, reason error) { refusals = append(refusals, reason) },
	})
	if err != nil {
		t.Fatal(err)
	}
	commitment := VisibilityCommitment{CachedNameCapacity: 4096, RepairBudget: 15 * time.Second, NamespaceRepair: NamespaceRepairParentExclusive}
	if err := coordinator.ValidateCommitment(commitment); !errors.Is(err, ErrVisibilityProfile) {
		t.Fatalf("ValidateCommitment = %v, want ErrVisibilityProfile", err)
	}
	if len(refusals) != 0 {
		t.Fatalf("pure validation invoked %d refusal callbacks", len(refusals))
	}
	if err := coordinator.Register(SessionID{1}, CoherenceStrict, make(chan struct{}), commitment); !errors.Is(err, ErrVisibilityProfile) {
		t.Fatalf("Register = %v, want ErrVisibilityProfile", err)
	}
	if len(refusals) != 1 {
		t.Fatalf("observed %d refusals, want 1", len(refusals))
	}
	message := refusals[0].Error()
	for _, want := range []string{"15s", "5s"} {
		if !strings.Contains(message, want) {
			t.Fatalf("refusal %q does not name %q", message, want)
		}
	}
	over := VisibilityCommitment{CachedNameCapacity: 1 << 20, RepairBudget: time.Second, NamespaceRepair: NamespaceRepairParentExclusive}
	if err := coordinator.Register(SessionID{2}, CoherenceStrict, make(chan struct{}), over); !errors.Is(err, ErrVisibilityProfile) {
		t.Fatalf("Register = %v, want ErrVisibilityProfile", err)
	}
	message = refusals[1].Error()
	for _, want := range []string{"1048576", "4096"} {
		if !strings.Contains(message, want) {
			t.Fatalf("refusal %q does not name %q", message, want)
		}
	}
}

// A read that races the running mutation on one of its coordinates has to wait,
// or it would publish a value that is about to be replaced into a kernel cache
// nobody is going to repair. What it must NOT wait for is the other mounts
// finishing their repairs.
//
// On Linux that reader is a syscall holding the directory it is reading: a
// dcache-miss lookup holds i_rwsem SHARED across the whole round trip
// (fs/namei.c:1703-1713) and so does a readdir through iterate_dir. Making it
// wait for COMPLETE would make it wait for a phase whose repair needs
// down_write on that same semaphore (fs/fuse/dir.c:1351) - the reader holds the
// lock the repair needs, the repair holds the mutation, the mutation holds the
// reader. One mount enumerating a directory another mount is filling - the
// shape of an install running under a concurrent reader - hits it continuously.
//
// So the wait ends when XFS has the change, and what the reader then reads is
// the new value.
func TestVisibilityRacingReadIsReleasedByApplyNotByRepair(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	reader, mutator := SessionID{1}, SessionID{2}
	h.register(t, reader, testRepairBudget)
	h.register(t, mutator, testRepairBudget)
	// The reader has touched this directory before, so it is in the audience and
	// will be asked to repair. It has not resolved the name being changed, which
	// is why its read of that name races instead of being covered.
	h.resolve(t, reader, "other")
	h.resolve(t, mutator, "shared")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	applied := make(chan struct{})
	holdComplete := make(chan struct{})
	completeSeen := make(chan struct{})
	// The mutating mount answers PREPARE at once and then holds COMPLETE, which
	// is exactly what a mount whose repair is blocked on a kernel lock looks
	// like from here.
	go func() {
		prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, mutator)
		if err != nil {
			return
		}
		if err := h.coordinator.Ack(mutator, prepare.Cursor); err != nil {
			return
		}
		complete, err := h.coordinator.Next(ctx, mutator, prepare.Cursor)
		if err != nil {
			return
		}
		close(completeSeen)
		<-holdComplete
		_ = h.coordinator.Ack(mutator, complete.Cursor)
	}()

	done := make(chan error, 1)
	go func() {
		done <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
			testMutationDependencies("shared"),
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				close(applied)
				return testVisibilityTargets("shared"), true
			})
	}()
	<-applied
	<-completeSeen

	// The mutation has reached XFS and is now waiting on a repair that is not
	// coming. The reader must be through anyway.
	released := make(chan error, 1)
	go func() {
		_, err := h.coordinator.Stabilize(ctx, reader,
			VisibilityResolution{Parent: testVisibilityParent(), Name: []byte("shared")})
		released <- err
	}()
	select {
	case err := <-released:
		if err != nil {
			t.Fatalf("the racing read failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(holdComplete)
		t.Fatal("a read that raced the mutation was still waiting for another mount's repair")
	}

	close(holdComplete)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the mutation never completed")
	}
	if h.fencer.wasFenced(reader) {
		t.Fatalf("the reading mount was fenced for %v", h.fenceReasonFor(reader))
	}
}

// The wait still exists, and it still ends only once the change is real. A read
// released before apply would cache the value the mutation is replacing.
func TestVisibilityRacingReadStillWaitsForApply(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	reader, mutator := SessionID{1}, SessionID{2}
	h.register(t, reader, testRepairBudget)
	h.register(t, mutator, testRepairBudget)
	h.resolve(t, mutator, "shared")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go serviceVisibility(ctx, h.coordinator, mutator)
	go serviceVisibility(ctx, h.coordinator, reader)

	holdApply := make(chan struct{})
	inApply := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- executeTestSourceGated(h.coordinator, context.Background(), mutator, MutationID{Sequence: 1}, "shared",
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				close(inApply)
				<-holdApply
				return testVisibilityTargets("shared"), true
			})
	}()
	<-inApply

	released := make(chan bool, 1)
	go func() {
		waited, err := h.coordinator.Stabilize(ctx, reader,
			VisibilityResolution{Parent: testVisibilityParent(), Name: []byte("shared")})
		if err != nil {
			released <- false
			return
		}
		released <- waited
	}()
	select {
	case <-released:
		close(holdApply)
		t.Fatal("a read of a coordinate this mutation had not yet applied was let through")
	case <-time.After(150 * time.Millisecond):
	}
	close(holdApply)
	select {
	case waited := <-released:
		if !waited {
			t.Fatal("the read was released without being told it raced the mutation, so it will not retry")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the read was never released")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestVisibilityPeerCompleteAckActivatesInterruptedGhostDebt(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	peer := SessionID{9}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "ghost-debt")

	result := make(chan error, 1)
	go func() {
		result <- executeTestExact(h.coordinator,
			context.Background(), peer, MutationID{Sequence: 1, FrontendOperationID: 91},
			testMutationDependencies("ghost-debt"),
			testVisibilityPrepare("ghost-debt"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("ghost-debt"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.coordinator.acquireMutationDependencies(ctx, participant, MutationID{
		Sequence: 2, FrontendOperationID: 101,
	}, nil, nil, testMutationDependencies("ghost-debt"), nil)
	if !errors.Is(err, ErrVisibilityInterrupted) {
		t.Fatalf("peer-PREPARE mutation = %v, want ErrVisibilityInterrupted", err)
	}
	h.coordinator.mu.Lock()
	dormant, ok := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if !ok || dormant.active || dormant.sequence != prepare.Cursor.Sequence || dormant.ordinal == 0 {
		t.Fatalf("dormant debt = %+v, present=%v", dormant, ok)
	}

	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	active, ok := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if !ok || !active.active || active.ordinal != dormant.ordinal || active.deadline.IsZero() {
		t.Fatalf("active debt = %+v, present=%v; dormant was %+v", active, ok, dormant)
	}

	turn, err := h.coordinator.acquireMutationDependencies(ctx, participant, MutationID{
		Sequence: 3, FrontendOperationID: 102,
	}, nil, nil, testMutationDependencies("ghost-debt"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if turn.ordinal != dormant.ordinal {
		t.Fatalf("claimed ordinal = %d, want lost ordinal %d", turn.ordinal, dormant.ordinal)
	}
	h.coordinator.mu.Lock()
	_, remains := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if remains {
		t.Fatal("claimed debt remained available")
	}
	turn.release()
}

func TestVisibilityInterruptedQueuedWaiterPreservesExactOrdinal(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	peer := SessionID{9}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "queued-debt")

	prepareEntered := make(chan struct{})
	releasePrepare := make(chan struct{})
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- h.coordinator.Execute(
			context.Background(), peer, MutationID{Sequence: 1, FrontendOperationID: 91},
			testMutationDependencies("queued-debt"),
			func() ([]VisibilityTarget, error) {
				close(prepareEntered)
				<-releasePrepare
				return testVisibilityTargets("queued-debt"), nil
			},
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("queued-debt"), true },
		)
	}()
	<-prepareEntered

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	interrupted := make(chan error, 1)
	go func() {
		_, err := h.coordinator.acquireMutationDependencies(ctx, participant, MutationID{
			Sequence: 2, FrontendOperationID: 101,
		}, nil, nil, testMutationDependencies("queued-debt"), nil)
		interrupted <- err
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)
	h.coordinator.sequencer.mu.Lock()
	lostOrdinal := h.coordinator.sequencer.waiters.Front().Value.(*mutationSequencerWaiter).ordinal
	h.coordinator.sequencer.mu.Unlock()
	close(releasePrepare)

	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-interrupted; !errors.Is(err, ErrVisibilityInterrupted) {
		t.Fatalf("queued peer-PREPARE mutation = %v", err)
	}
	h.coordinator.mu.Lock()
	dormant := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if dormant.ordinal != lostOrdinal || !dormant.observed || dormant.operationID != 101 {
		t.Fatalf("dormant debt = %+v, want queued ordinal %d", dormant, lostOrdinal)
	}
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}

	turn, err := h.coordinator.acquireMutationDependencies(ctx, participant, MutationID{
		Sequence: 3, FrontendOperationID: 102,
	}, nil, nil, testMutationDependencies("queued-debt"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if turn.ordinal != lostOrdinal {
		t.Fatalf("claimed ordinal = %d, want interrupted waiter %d", turn.ordinal, lostOrdinal)
	}
	turn.release()
}

func TestVisibilityCompleteContentionFeedbackActivatesOnePrepareCut(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	peer := SessionID{9}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "feedback-debt")

	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(
			context.Background(), peer, MutationID{Sequence: 1, FrontendOperationID: 91},
			testMutationDependencies("feedback-debt"),
			testVisibilityPrepare("feedback-debt"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("feedback-debt"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.AckWithContention(participant, complete.Cursor, true); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	first, ok := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if !ok || !first.active || first.ordinal == 0 || first.sequence != complete.Cursor.Sequence {
		t.Fatalf("feedback debt = %+v, present=%v", first, ok)
	}
	if err := h.coordinator.AckWithContention(participant, complete.Cursor, true); err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	duplicate := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if duplicate.ordinal != first.ordinal || duplicate.deadline != first.deadline {
		t.Fatalf("duplicate Ack changed debt from %+v to %+v", first, duplicate)
	}
	// Expiry removes the off-list credit; it never becomes a blocking owner.
	h.coordinator.cfg.Now = func() time.Time { return first.deadline.Add(time.Nanosecond) }
	turn, err := h.coordinator.acquireMutationDependencies(ctx, participant, MutationID{
		Sequence: 2, FrontendOperationID: 101,
	}, nil, nil, testMutationDependencies("feedback-debt"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if turn.ordinal == first.ordinal {
		t.Fatalf("expired debt reused ordinal %d", first.ordinal)
	}
	turn.release()
	h.coordinator.mu.Lock()
	_, remains := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if remains {
		t.Fatal("expired debt remained after a qualifying mutation")
	}
}

func TestVisibilityFalseContentionFeedbackDiscardsUnusedPrepareCut(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	peer := SessionID{9}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "false-feedback")
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(
			context.Background(), peer, MutationID{Sequence: 1},
			testMutationDependencies("false-feedback"),
			testVisibilityPrepare("false-feedback"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("false-feedback"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.AckWithContention(participant, complete.Cursor, false); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	_, exists := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if exists {
		t.Fatal("false feedback retained an unobserved PREPARE-time cut")
	}
}

func TestVisibilityUnclaimedDebtRollsAcrossConsecutivePeerPhases(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	peer := SessionID{9}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "rolling-debt")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	run := func(sequence uint64, after VisibilityCursor, feedback bool) VisibilityCursor {
		t.Helper()
		result := make(chan error, 1)
		go func() {
			result <- h.coordinator.Execute(
				context.Background(), peer, MutationID{Sequence: sequence},
				testMutationDependencies("rolling-debt"),
				testVisibilityPrepare("rolling-debt"),
				func() ([]VisibilityTarget, bool) { return testVisibilityTargets("rolling-debt"), true },
			)
		}()
		prepare, err := h.coordinator.Next(ctx, participant, after)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
			t.Fatal(err)
		}
		complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.coordinator.AckWithContention(participant, complete.Cursor, feedback); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		return complete.Cursor
	}

	firstCursor := run(1, initialVisibilityCursor(t, h.coordinator, participant), true)
	h.coordinator.mu.Lock()
	first := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if !first.active {
		t.Fatalf("first debt = %+v, want active", first)
	}

	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(
			context.Background(), peer, MutationID{Sequence: 2},
			testMutationDependencies("rolling-debt"),
			testVisibilityPrepare("rolling-debt"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("rolling-debt"), true },
		)
	}()
	prepare, err := h.coordinator.Next(ctx, participant, firstCursor)
	if err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	rolled := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if rolled.active || rolled.sequence != prepare.Cursor.Sequence ||
		rolled.ordinal != first.ordinal || !rolled.observed || !rolled.deadline.IsZero() {
		t.Fatalf("rolled debt = %+v, first = %+v", rolled, first)
	}
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	// The carried credit is real even when this sequence had no additional
	// local refusal feedback; it remains one coalesced opportunity.
	if err := h.coordinator.AckWithContention(participant, complete.Cursor, false); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	second := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if !second.active || second.ordinal != first.ordinal || second.deadline.IsZero() ||
		!second.deadline.After(first.deadline) {
		t.Fatalf("reactivated debt = %+v, first = %+v", second, first)
	}
}

func TestVisibilityCancellationConsumesAClaimedSchedulingCredit(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	dependencies := testInodeDependencies(0xFA)
	owner, err := h.coordinator.sequencer.acquire(context.Background(), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	reserved := h.coordinator.sequencer.reserveOrdinal()
	h.coordinator.mu.Lock()
	h.coordinator.fairness[participant] = mutationFairnessDebt{
		sequence: 1, ordinal: reserved, active: true, deadline: time.Now().Add(time.Second),
	}
	h.coordinator.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := h.coordinator.acquireMutationDependencies(ctx, participant, MutationID{
			Sequence: 1, FrontendOperationID: 101,
		}, nil, nil, dependencies, nil)
		result <- err
	}()
	waitForMutationSequencerQueue(t, h.coordinator.sequencer, 1)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("claimed waiter cancellation = %v", err)
	}
	h.coordinator.mu.Lock()
	_, remains := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if remains {
		t.Fatal("canceled claimed credit was restored as replay state")
	}
	owner.release()

	turn, err := h.coordinator.acquireMutationDependencies(context.Background(), participant, MutationID{
		Sequence: 2, FrontendOperationID: 102,
	}, nil, nil, dependencies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if turn.ordinal == reserved {
		t.Fatalf("later callback replayed consumed scheduling ordinal %d", reserved)
	}
	turn.release()
}

func TestVisibilityContentionFeedbackExcludesFrozenProfile(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	peer := SessionID{9}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerialized)
	h.resolve(t, participant, "v1-no-debt")
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(
			context.Background(), peer, MutationID{Sequence: 1},
			testMutationDependencies("v1-no-debt"),
			testVisibilityPrepare("v1-no-debt"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("v1-no-debt"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.AckWithContention(participant, complete.Cursor, true); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	h.coordinator.mu.Lock()
	_, ok := h.coordinator.fairness[participant]
	h.coordinator.mu.Unlock()
	if ok {
		t.Fatal("frozen callback profile received a fairness debt")
	}
}

func TestVisibilityImportedAnchorCarriesItsRacedInodeDependency(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.register(t, participant, testRepairBudget)
	parent := testVisibilityParent()
	var child, unrelated [16]byte
	child[0] = 2
	unrelated[0] = 3
	h.coordinator.RecordResolvedInode(participant, parent)
	targets := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("z-other")},
		{Scope: VisibilityAttributes, Identity: unrelated},
		{Scope: VisibilityAttributes, Identity: parent},
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("a-anchor"), RelatedIdentities: [][16]byte{child}},
		{Scope: VisibilityAttributes, Identity: child},
	}
	result := make(chan error, 1)
	go func() {
		result <- executeTestExact(h.coordinator,
			context.Background(), SessionID{9}, MutationID{Sequence: 1},
			mutationDependenciesForTargets(targets),
			func() ([]VisibilityTarget, error) { return targets, nil },
			func() ([]VisibilityTarget, bool) { return targets, true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepare.Targets) != 3 || prepare.Targets[0].Scope != VisibilityAttributes ||
		prepare.Targets[0].Identity != parent || prepare.Targets[1].Scope != VisibilityNamespace ||
		string(prepare.Targets[1].Name) != "a-anchor" || prepare.Targets[2].Identity != child {
		t.Fatalf("dependency projection = %#v, want parent + lexical anchor + its child", prepare.Targets)
	}
	if waited, err := h.coordinator.Stabilize(ctx, participant, VisibilityResolution{
		Parent: parent, Name: []byte("a-anchor"), Identity: child,
	}); err != nil || waited {
		t.Fatalf("covered raced lookup stabilization = waited %v, err %v", waited, err)
	}
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestVisibilityCompletionCannotDropPreparedParentNamespaceDependency(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	parent := testVisibilityParent()
	prepared := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("a")},
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("b")},
		{Scope: VisibilityAttributes, Identity: parent},
	}
	complete := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("b")},
		{Scope: VisibilityAttributes, Identity: parent},
	}
	if err := h.coordinator.validateCompletion(1, complete, prepared); err == nil {
		t.Fatal("completion dropped a prepared parent namespace dependency")
	}
}

func TestVisibilityNamespacePostIdentityIsAProjectionDependency(t *testing.T) {
	parent := testVisibilityParent()
	post := [16]byte{2}
	target := VisibilityTarget{
		Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("alias"),
		PostIdentity: post,
	}
	if err := validateVisibilityTargets([]VisibilityTarget{target}); !errors.Is(err, ErrVisibilityTargets) {
		t.Fatalf("post-binding without dependency = %v, want ErrVisibilityTargets", err)
	}
	target.RelatedIdentities = [][16]byte{post}
	if err := validateVisibilityTargets([]VisibilityTarget{target}); err != nil {
		t.Fatalf("post-binding with exact projection dependency: %v", err)
	}
}
