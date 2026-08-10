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
			testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
				applied.Store(true)
				return testVisibilityTargets("prepare"), true
			})
	}()
	runBarrier(t, h.coordinator, survivor, VisibilityCursor{})
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
			testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("prepare"), true
			})
	}()
	runBarrier(t, h.coordinator, survivor, VisibilityCursor{Sequence: 1, Phase: VisibilityComplete})
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
			testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("prepare"), true
			})
	}()
	// The wedged mount takes its PREPARE and never acknowledges it.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := h.coordinator.Next(ctx, wedged, VisibilityCursor{}); err != nil {
		t.Fatalf("wedged participant prepare: %v", err)
	}
	runBarrier(t, h.coordinator, healthy, VisibilityCursor{})

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
			testVisibilityPrepare("shared"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("shared"), true })
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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
			testVisibilityPrepare("watched"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("watched"), true
			})
	}()
	runBarrier(t, h.coordinator, holder, VisibilityCursor{})
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
	if _, err := h.coordinator.Next(idle, stranger, VisibilityCursor{}); !errors.Is(err, context.DeadlineExceeded) {
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
		result <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1},
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
		event, err := h.coordinator.Next(ctx, id, VisibilityCursor{})
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
		result <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1},
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
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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

// The source receives the complete footprint even when its resolved index was
// empty: the initiating syscall and reply are themselves allowed to populate
// every returned coordinate in its kernel cache.
func TestVisibilityFanOutKeepsFullSourceFootprint(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.register(t, source, testRepairBudget)
	parent := testVisibilityParent()
	var file [16]byte
	file[0] = 2
	targets := []VisibilityTarget{
		{Scope: VisibilityNamespace, ParentIdentity: parent, Name: []byte("child")},
		{Scope: VisibilityAttributes, Identity: parent},
		{Scope: VisibilityData, Identity: file, Size: 20},
	}
	result := make(chan error, 1)
	go func() {
		result <- h.coordinator.Execute(
			context.Background(), source, MutationID{Sequence: 1, FrontendOperationID: 41},
			func() ([]VisibilityTarget, error) { return targets, nil },
			func() ([]VisibilityTarget, bool) { return targets, true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, source, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepare.Targets) != len(targets) {
		t.Fatalf("source PREPARE targets = %d, want %d", len(prepare.Targets), len(targets))
	}
	if err := h.coordinator.Ack(source, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, source, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(complete.Targets) != len(targets) {
		t.Fatalf("source COMPLETE targets = %d, want %d", len(complete.Targets), len(targets))
	}
	if err := h.coordinator.Ack(source, complete.Cursor); err != nil {
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
			testVisibilityPrepare("contended"), func() ([]VisibilityTarget, bool) {
				<-release
				return testVisibilityTargets("contended"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, holder, VisibilityCursor{})
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
			testVisibilityPrepare("contended"), func() ([]VisibilityTarget, bool) {
				close(applied)
				<-releaseApply
				return testVisibilityTargets("contended"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, holder, VisibilityCursor{})
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
			testVisibilityPrepare("contended"), func() ([]VisibilityTarget, bool) {
				<-releaseApply
				close(applied)
				return testVisibilityTargets("contended"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, holder, VisibilityCursor{})
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
	err := h.coordinator.Execute(context.Background(), SessionID{}, MutationID{Sequence: 1}, testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
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
			testVisibilityPrepare("prepare"), func() ([]VisibilityTarget, bool) {
				close(applied)
				return testVisibilityTargets("prepare"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := h.coordinator.Next(ctx, participant, VisibilityCursor{}); err != nil {
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

// The uncached profile is a supported deployment, not a fast path that skips
// checks. A target-construction defect must be just as visible there as it is
// under a strict mount, or it stays invisible in the common configuration.
func TestVisibilityUncachedProfileStillValidatesTargets(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	var applied atomic.Bool
	err := h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
		func() ([]VisibilityTarget, error) {
			// A namespace target with no parent identity: a construction defect.
			return []VisibilityTarget{{Scope: VisibilityNamespace, Name: []byte("x")}}, nil
		},
		func() ([]VisibilityTarget, bool) {
			applied.Store(true)
			return testVisibilityTargets("x"), true
		})
	if !errors.Is(err, ErrVisibilityTargets) {
		t.Fatalf("uncached Execute with invalid prepare targets = %v, want ErrVisibilityTargets", err)
	}
	if applied.Load() {
		t.Fatal("a target-construction defect still reached the filesystem")
	}

	postApply := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	err = postApply.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
		testVisibilityPrepare("x"),
		func() ([]VisibilityTarget, bool) {
			// Changed XFS but could not describe what it changed.
			return []VisibilityTarget{}, true
		})
	if !errors.Is(err, ErrVisibilityPoisoned) {
		t.Fatalf("uncached Execute with a post-apply defect = %v, want a poisoned epoch", err)
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
	err := h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
		testVisibilityPrepare("prepared"),
		func() ([]VisibilityTarget, bool) { return testVisibilityTargets("never-prepared"), true })
	if !errors.Is(err, ErrVisibilityPoisoned) || !errors.Is(err, ErrVisibilityTargets) {
		t.Fatalf("uncovered completion target = %v, want a poisoned epoch", err)
	}
}

// A source that never acknowledges its deferred COMPLETE is fenced on the next
// mutation, and the queue entry is removed on that outcome as well - otherwise
// the queue keeps describing an obligation that no longer exists.
func TestVisibilityDeferredSourceIsFencedAndTrimmed(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source, observer := SessionID{1}, SessionID{2}
	h.register(t, source, 60*time.Millisecond)
	h.register(t, observer, testRepairBudget)
	h.resolve(t, source, "first", "second")
	h.resolve(t, observer, "first", "second")

	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.Execute(context.Background(), source, MutationID{Sequence: 1},
			testVisibilityPrepare("first"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("first"), true
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// The source acknowledges PREPARE and then goes quiet, leaving its deferred
	// COMPLETE outstanding forever.
	sourcePrepare, err := h.coordinator.Next(ctx, source, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(source, sourcePrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	runBarrier(t, h.coordinator, observer, VisibilityCursor{})
	if err := <-first; err != nil {
		t.Fatalf("first mutation: %v", err)
	}

	second := make(chan error, 1)
	go func() {
		second <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 2},
			testVisibilityPrepare("second"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("second"), true
			})
	}()
	runBarrier(t, h.coordinator, observer, VisibilityCursor{Sequence: 1, Phase: VisibilityComplete})
	select {
	case err := <-second:
		if err != nil {
			t.Fatalf("mutation after a delinquent deferred source: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a delinquent deferred source blocked every later mutation")
	}
	if !h.fencer.wasFenced(source) {
		t.Fatal("the delinquent deferred source was not fenced")
	}
	// A third mutation proves the deferred queue no longer names it.
	third := make(chan error, 1)
	go func() {
		third <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 3},
			testVisibilityPrepare("second"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("second"), true
			})
	}()
	runBarrier(t, h.coordinator, observer, VisibilityCursor{Sequence: 2, Phase: VisibilityComplete})
	select {
	case err := <-third:
		if err != nil {
			t.Fatalf("third mutation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the deferred queue was never trimmed")
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
	sourcePublished := map[SessionID]chan struct{}{
		{2}: make(chan struct{}),
		{3}: make(chan struct{}),
	}
	for _, participant := range participants {
		participant := participant
		go func() {
			var after VisibilityCursor
			wantEvents := 4 // PREPARE + COMPLETE for both mutations.
			for range wantEvents {
				event, err := coordinator.Next(ctx, participant, after)
				if err != nil {
					workerErr <- err
					return
				}
				expected := VisibilityCursor{Sequence: 1, Phase: VisibilityPrepare}
				switch after.Phase {
				case VisibilityPrepare:
					expected = VisibilityCursor{Sequence: after.Sequence, Phase: VisibilityComplete}
				case VisibilityComplete:
					expected = VisibilityCursor{Sequence: after.Sequence + 1, Phase: VisibilityPrepare}
				}
				if event.Cursor != expected {
					workerErr <- ErrVisibilitySequence
					return
				}
				observedMu.Lock()
				observed[participant] = append(observed[participant], event)
				observedMu.Unlock()
				if event.Initiator == participant && event.Cursor.Phase == VisibilityComplete {
					// The source may receive its deferred COMPLETE event immediately,
					// but it cannot acknowledge/reopen until the ordinary mutation RPC
					// returned and its FSKit callback crossed publication.
					select {
					case <-sourcePublished[participant]:
					case <-ctx.Done():
						workerErr <- ctx.Err()
						return
					}
				}
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
		var hash RequestHash
		hash[0] = sourceByte
		ticket := MutationID{Slot: uint32(sourceByte), Sequence: 1, Hash: hash}
		tickets[source] = ticket
		name := string([]byte{'a' + sourceByte - 2})
		go func() {
			<-start
			err := coordinator.Execute(context.Background(), source, ticket, testVisibilityPrepare(name), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets(name), true
			})
			close(sourcePublished[source])
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
		if participant == (SessionID{1}) {
			for sequence, state := range bySequence {
				if !state.prepare || !state.complete {
					t.Fatalf("passive participant missed phase for sequence %d: %+v", sequence, state)
				}
			}
			continue
		}
		own, other := 0, 0
		for _, event := range events {
			if event.Initiator == participant {
				// A frontend publication gate exempts this exact callback ticket
				// from its own PREPARE drain, not the whole source mount. The gate
				// remains closed until its ordinary mutation reply is published.
				if want := tickets[participant]; event.MutationSlot != want.Slot || event.MutationSequence != want.Sequence {
					t.Fatalf("participant %x received a forged own-ticket exemption", participant)
				}
				own++
			} else {
				// A submitted mutator waiting for authority order is outside the
				// publication gate, so this worker remains able to service the
				// competing mutation instead of forming a drain cycle.
				other++
			}
		}
		if own != 2 || other != 2 {
			t.Fatalf("participant %x own/other phases = %d/%d, want 2/2", participant, own, other)
		}
		for sequence, state := range bySequence {
			var initiator SessionID
			for _, event := range events {
				if event.Cursor.Sequence == sequence {
					initiator = event.Initiator
					break
				}
			}
			if !state.prepare || !state.complete {
				t.Fatalf("participant %x sequence %d from %x phases = %+v; source COMPLETE is deferred until its ordinary reply publishes, never omitted", participant, sequence, initiator, state)
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
func TestVisibilityCallbackSerializedMutationIsInterruptedByPendingRepair(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "peer-change")

	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1, FrontendOperationID: 41},
			testVisibilityPrepare("peer-change"),
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("peer-change"), true
			},
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}

	prepared, applied := false, false
	err = h.coordinator.Execute(
		context.Background(), participant, MutationID{Sequence: 2, FrontendOperationID: 42},
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

// The interruption also wakes a mutation that was already waiting for global
// order before PREPARE was installed. This is the half a check performed only
// when Execute begins would miss under a sustained writer storm.
func TestVisibilityCallbackSerializedQueuedMutationWakesForPendingRepair(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.registerRepair(t, participant, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)
	h.resolve(t, participant, "peer-change")

	// Let the peer own mutation order but stop immediately before it publishes
	// PREPARE, so the local mutation is already queued when pending changes.
	peerPreparing := make(chan struct{})
	releasePeerPrepare := make(chan struct{})
	peer := make(chan error, 1)
	go func() {
		peer <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1, FrontendOperationID: 41},
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
		result <- h.coordinator.Execute(
			ctx, participant, MutationID{Sequence: 2, FrontendOperationID: 42},
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
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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

// A conflicting callback must leave the FIFO even when it is not the head.
// Otherwise one safe waiter in front of it would keep the callback alive while
// PREPARE waits for the FSKit lane that callback occupies.
func TestVisibilityMutationOrderInterruptsConflictingNonHeadWaiter(t *testing.T) {
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
			func() ([]VisibilityTarget, error) {
				safePrepared.Store(true)
				return testVisibilityTargets("safe-change"), nil
			},
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("safe-change"), true
			},
		)
	}()
	waitForMutationOrderQueue(t, h.coordinator.order, 1)

	var hazardousPrepared atomic.Bool
	hazardous := make(chan error, 1)
	go func() {
		hazardous <- h.coordinator.Execute(
			context.Background(), participant, MutationID{Sequence: 3, FrontendOperationID: 43},
			func() ([]VisibilityTarget, error) {
				hazardousPrepared.Store(true)
				return testVisibilityTargets("local-change"), nil
			},
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("local-change"), true
			},
		)
	}()
	waitForMutationOrderQueue(t, h.coordinator.order, 2)

	close(releasePeerPrepare)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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
	waitForMutationOrderQueue(t, h.coordinator.order, 1)
	if safePrepared.Load() {
		t.Fatal("safe FIFO head prepared before the owner released mutation order")
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

// A mixed FSKit callback has already issued an ordinary request before its
// ordered mutation. PREPARE must drain that ordinary request, so letting the
// mutation wait behind an own-source PREPARE would close the exact cycle that
// deadlocked the live macOS 26 mount: PREPARE waits for the callback to publish,
// while the callback waits for PREPARE to finish. The authority must interrupt
// the mutation even when it entered the global-order queue before PREPARE was
// installed.
func TestVisibilityCallbackSerializedQueuedMixedSourceCallbackWakesForOwnPrepare(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)

	// Let the initiating callback own mutation order but pause just before it
	// publishes PREPARE. The mixed callback is then already queued when the
	// source phase appears.
	firstPreparing := make(chan struct{})
	releaseFirstPrepare := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.Execute(
			context.Background(), source,
			MutationID{Sequence: 1, FrontendOperationID: 41},
			func() ([]VisibilityTarget, error) {
				close(firstPreparing)
				<-releaseFirstPrepare
				return testVisibilityTargets("first"), nil
			},
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("first"), true
			},
		)
	}()
	<-firstPreparing

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepared, applied := false, false
	mixed := make(chan error, 1)
	go func() {
		mixed <- h.coordinator.Execute(
			ctx, source,
			MutationID{
				Sequence:            2,
				FrontendOperationID: 42,
				// False is the explicit fail-safe value: this callback is
				// mixed, so the frontend cannot prove it is safe to queue.
				SourcePhaseQueueable: false,
			},
			func() ([]VisibilityTarget, error) {
				prepared = true
				return testVisibilityTargets("mixed"), nil
			},
			func() ([]VisibilityTarget, bool) {
				applied = true
				return testVisibilityTargets("mixed"), true
			},
		)
	}()
	select {
	case err := <-mixed:
		t.Fatalf("mixed callback returned before PREPARE was installed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(releaseFirstPrepare)
	prepare, err := h.coordinator.Next(ctx, source, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-mixed:
		if !errors.Is(err, ErrVisibilityInterrupted) {
			t.Fatalf("mixed source callback = %v, want ErrVisibilityInterrupted", err)
		}
	case <-ctx.Done():
		t.Fatal("queued mixed source callback did not wake for own PREPARE")
	}
	if prepared || applied {
		t.Fatalf("interrupted mixed callback reached prepare=%v apply=%v", prepared, applied)
	}

	runBarrierFrom(t, h.coordinator, source, prepare)
	if err := <-first; err != nil {
		t.Fatalf("initiating source mutation: %v", err)
	}
}

// Linux enters the authority while its namespace callback already holds the
// parent i_rwsem. If a peer COMPLETE for that parent is installed while the
// request waits for mutation order, letting it continue to wait closes a
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
			testVisibilityPrepare("peer-change"),
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("peer-change"), true
			},
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}

	var prepared, applied atomic.Bool
	local := make(chan error, 1)
	go func() {
		local <- h.coordinator.ExecuteWithHeldParents(
			ctx, participant, MutationID{Sequence: 2}, [][16]byte{testVisibilityParent()},
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
			testVisibilityPrepare("peer-change"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("peer-change"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}

	differentParent := [16]byte{2}
	local := make(chan error, 1)
	go func() {
		local <- h.coordinator.ExecuteWithHeldParents(
			ctx, participant, MutationID{Sequence: 2}, [][16]byte{differentParent},
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

	localPrepare, err := h.coordinator.Next(ctx, participant, complete.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	runBarrierFrom(t, h.coordinator, participant, localPrepare)
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
					testVisibilityPrepare("peer-change"),
					func() ([]VisibilityTarget, bool) { return testVisibilityTargets("peer-change"), true })
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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
			err = h.coordinator.ExecuteWithHeldParents(ctx, participant, MutationID{Sequence: 2}, test.held,
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

// The frozen v1 profile predates frontend callback identity. It must retain its
// unconditional interruption boundary even when both requests happen to carry
// distinct nonzero IDs; only the explicit pipelined profile may queue them.
func TestVisibilityCallbackSerializedFrozenProfileInterruptsDistinctSourceCallback(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairCallbackSerialized)

	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.Execute(
			context.Background(), source,
			MutationID{Sequence: 1, FrontendOperationID: 41},
			testVisibilityPrepare("first"),
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("first"), true
			},
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, source, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}

	prepared, applied := false, false
	err = h.coordinator.Execute(
		context.Background(), source,
		MutationID{Sequence: 2, FrontendOperationID: 42},
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
		t.Fatalf("frozen distinct source callback = %v prepare=%v apply=%v, want interruption", err, prepared, applied)
	}

	runBarrierFrom(t, h.coordinator, source, prepare)
	if err := <-first; err != nil {
		t.Fatalf("first frozen-profile mutation: %v", err)
	}
}

// Source COMPLETE is deferred until the initiating callback publishes. Another
// mutation from that exact callback must be interrupted rather than wait behind
// the phase its own callback publication releases. Once COMPLETE is
// acknowledged, a fresh callback runs normally and the participant remains
// healthy.
func TestVisibilityCallbackSerializedSourceCompleteInterruptsThenRecovers(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)

	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.Execute(
			context.Background(), source, MutationID{Sequence: 1, FrontendOperationID: 51},
			testVisibilityPrepare("first"),
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("first"), true
			},
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, source, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(source, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatalf("first mutation: %v", err)
	}
	complete, err := h.coordinator.Next(ctx, source, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Cursor.Phase != VisibilityComplete {
		t.Fatalf("deferred event phase = %v, want COMPLETE", complete.Cursor.Phase)
	}

	prepared, applied := false, false
	err = h.coordinator.Execute(
		context.Background(), source, MutationID{Sequence: 2, FrontendOperationID: 51},
		func() ([]VisibilityTarget, error) {
			prepared = true
			return testVisibilityTargets("interrupted"), nil
		},
		func() ([]VisibilityTarget, bool) {
			applied = true
			return testVisibilityTargets("interrupted"), true
		},
	)
	if !errors.Is(err, ErrVisibilityInterrupted) {
		t.Fatalf("mutation during source COMPLETE = %v, want ErrVisibilityInterrupted", err)
	}
	if prepared || applied {
		t.Fatalf("source-COMPLETE interruption reached prepare=%v apply=%v", prepared, applied)
	}
	if err := h.coordinator.Ack(source, complete.Cursor); err != nil {
		t.Fatal(err)
	}

	var freshPrepared, freshApplied atomic.Bool
	fresh := make(chan error, 1)
	go func() {
		fresh <- h.coordinator.Execute(
			context.Background(), source, MutationID{Sequence: 3, FrontendOperationID: 52},
			func() ([]VisibilityTarget, error) {
				freshPrepared.Store(true)
				return testVisibilityTargets("fresh"), nil
			},
			func() ([]VisibilityTarget, bool) {
				freshApplied.Store(true)
				return testVisibilityTargets("fresh"), true
			},
		)
	}()
	freshPrepare, err := h.coordinator.Next(ctx, source, complete.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	runBarrierFrom(t, h.coordinator, source, freshPrepare)
	if err := <-fresh; err != nil {
		t.Fatalf("fresh mutation after COMPLETE: %v", err)
	}
	if !freshPrepared.Load() || !freshApplied.Load() {
		t.Fatalf("fresh mutation reached prepare=%v apply=%v", freshPrepared.Load(), freshApplied.Load())
	}
	if !h.fencer.live(source) || h.fencer.wasFenced(source) {
		t.Fatal("callback-serialized participant was not usable after the phase cleared")
	}
}

// The queueability proof is deliberately narrow. Every incomplete fact stays
// on the definite pre-apply interruption path during PREPARE and COMPLETE;
// merely setting the proof bit cannot override callback identity, peer
// ownership, or the frozen v1 profile.
func TestVisibilitySourcePhaseQueueabilityFailSafeMatrix(t *testing.T) {
	for _, test := range []struct {
		name        string
		repair      NamespaceRepair
		initiator   SessionID
		pendingOpID uint64
		mutation    MutationID
	}{
		{
			name:   "absent proof on distinct own callback",
			repair: NamespaceRepairCallbackSerializedPipelined, initiator: SessionID{1}, pendingOpID: 41,
			mutation: MutationID{Sequence: 2, FrontendOperationID: 42},
		},
		{
			name:   "proof cannot exempt the initiating callback",
			repair: NamespaceRepairCallbackSerializedPipelined, initiator: SessionID{1}, pendingOpID: 41,
			mutation: MutationID{Sequence: 2, FrontendOperationID: 41, SourcePhaseQueueable: true},
		},
		{
			name:   "proof cannot exempt a peer phase",
			repair: NamespaceRepairCallbackSerializedPipelined, initiator: SessionID{9}, pendingOpID: 41,
			mutation: MutationID{Sequence: 2, FrontendOperationID: 42, SourcePhaseQueueable: true},
		},
		{
			name:   "proof with zero mutation operation id",
			repair: NamespaceRepairCallbackSerializedPipelined, initiator: SessionID{1}, pendingOpID: 41,
			mutation: MutationID{Sequence: 2, SourcePhaseQueueable: true},
		},
		{
			name:   "proof against zero pending operation id",
			repair: NamespaceRepairCallbackSerializedPipelined, initiator: SessionID{1}, pendingOpID: 0,
			mutation: MutationID{Sequence: 2, FrontendOperationID: 42, SourcePhaseQueueable: true},
		},
		{
			name:   "proof cannot change frozen callback serialized v1",
			repair: NamespaceRepairCallbackSerialized, initiator: SessionID{1}, pendingOpID: 41,
			mutation: MutationID{Sequence: 2, FrontendOperationID: 42, SourcePhaseQueueable: true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
			source := SessionID{1}
			h.registerRepair(t, source, testRepairBudget, test.repair)
			if test.initiator != source {
				h.resolve(t, source, "first")
			}

			first := make(chan error, 1)
			go func() {
				first <- h.coordinator.Execute(
					context.Background(), test.initiator,
					MutationID{Sequence: 1, FrontendOperationID: test.pendingOpID},
					testVisibilityPrepare("first"),
					func() ([]VisibilityTarget, bool) {
						return testVisibilityTargets("first"), true
					},
				)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			prepare, err := h.coordinator.Next(ctx, source, VisibilityCursor{})
			if err != nil {
				t.Fatal(err)
			}

			assertInterrupted := func(phase string, sequence uint64) {
				t.Helper()
				prepared, applied := false, false
				mutation := test.mutation
				mutation.Sequence = sequence
				err := h.coordinator.Execute(
					context.Background(), source, mutation,
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
			if test.initiator == source {
				if err := <-first; err != nil {
					t.Fatalf("initiating source mutation: %v", err)
				}
			}
			complete, err := h.coordinator.Next(ctx, source, prepare.Cursor)
			if err != nil {
				t.Fatal(err)
			}
			assertInterrupted("COMPLETE", 3)
			if err := h.coordinator.Ack(source, complete.Cursor); err != nil {
				t.Fatal(err)
			}
			if test.initiator != source {
				if err := <-first; err != nil {
					t.Fatalf("initiating peer mutation: %v", err)
				}
			}
		})
	}
}

// A distinct nonzero frontend operation ID plus SourcePhaseQueueable is a
// different ordered-only FSKit callback. The matching frontend contract keeps
// its already-dispatched ticket out of a local-source PREPARE drain, and source
// COMPLETE waits only for the initiating callback. Therefore this callback can
// remain queued across both phases without forming either reverse dependency.
// Zero or an absent proof remains fail-safe: without both facts the authority
// interrupts before apply.
func TestVisibilityCallbackSerializedDistinctSourceCallbackWaitsThroughBothPhases(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	source := SessionID{1}
	h.registerRepair(t, source, testRepairBudget, NamespaceRepairCallbackSerializedPipelined)

	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.Execute(
			context.Background(), source,
			MutationID{Sequence: 1, FrontendOperationID: 61},
			testVisibilityPrepare("first"),
			func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("first"), true
			},
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	firstPrepare, err := h.coordinator.Next(ctx, source, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}

	unknownPrepared, unknownApplied := false, false
	err = h.coordinator.Execute(
		context.Background(), source, MutationID{Sequence: 2},
		func() ([]VisibilityTarget, error) {
			unknownPrepared = true
			return testVisibilityTargets("unknown"), nil
		},
		func() ([]VisibilityTarget, bool) {
			unknownApplied = true
			return testVisibilityTargets("unknown"), true
		},
	)
	if !errors.Is(err, ErrVisibilityInterrupted) || unknownPrepared || unknownApplied {
		t.Fatalf("zero-ID source mutation = %v prepare=%v apply=%v, want pre-apply interruption", err, unknownPrepared, unknownApplied)
	}

	var secondPrepared, secondApplied atomic.Bool
	second := make(chan error, 1)
	go func() {
		second <- h.coordinator.Execute(
			ctx, source, MutationID{
				Sequence:             3,
				FrontendOperationID:  62,
				SourcePhaseQueueable: true,
			},
			func() ([]VisibilityTarget, error) {
				secondPrepared.Store(true)
				return testVisibilityTargets("second"), nil
			},
			func() ([]VisibilityTarget, bool) {
				secondApplied.Store(true)
				return testVisibilityTargets("second"), true
			},
		)
	}()
	select {
	case err := <-second:
		t.Fatalf("distinct callback returned during source PREPARE: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if secondPrepared.Load() || secondApplied.Load() {
		t.Fatalf("distinct callback crossed source PREPARE: prepare=%v apply=%v", secondPrepared.Load(), secondApplied.Load())
	}

	if err := h.coordinator.Ack(source, firstPrepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatalf("first source mutation: %v", err)
	}
	firstComplete, err := h.coordinator.Next(ctx, source, firstPrepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-second:
		t.Fatalf("distinct callback returned during source COMPLETE: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if secondPrepared.Load() || secondApplied.Load() {
		t.Fatalf("distinct callback crossed source COMPLETE: prepare=%v apply=%v", secondPrepared.Load(), secondApplied.Load())
	}

	if err := h.coordinator.Ack(source, firstComplete.Cursor); err != nil {
		t.Fatal(err)
	}
	secondPrepare, err := h.coordinator.Next(ctx, source, firstComplete.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	runBarrierFrom(t, h.coordinator, source, secondPrepare)
	if err := <-second; err != nil {
		t.Fatalf("distinct source callback after wait: %v", err)
	}
	if !secondPrepared.Load() || !secondApplied.Load() {
		t.Fatalf("distinct source callback reached prepare=%v apply=%v", secondPrepared.Load(), secondApplied.Load())
	}
	if !h.fencer.live(source) || h.fencer.wasFenced(source) {
		t.Fatal("queueing a distinct source callback fenced the participant")
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
					testVisibilityPrepare("peer-change"),
					func() ([]VisibilityTarget, bool) {
						return testVisibilityTargets("peer-change"), true
					},
				)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			peerPrepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
			if err != nil {
				t.Fatal(err)
			}

			var prepared, applied atomic.Bool
			local := make(chan error, 1)
			go func() {
				local <- h.coordinator.Execute(
					ctx, participant, MutationID{Sequence: 2},
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
				t.Fatalf("profile %s crossed mutation order early: prepare=%v apply=%v", test.name, prepared.Load(), applied.Load())
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

			localPrepare, err := h.coordinator.Next(ctx, participant, peerComplete.Cursor)
			if err != nil {
				t.Fatal(err)
			}
			runBarrierFrom(t, h.coordinator, participant, localPrepare)
			if err := <-local; err != nil {
				t.Fatalf("profile %s local mutation: %v", test.name, err)
			}
			if !prepared.Load() || !applied.Load() {
				t.Fatalf("profile %s reached prepare=%v apply=%v", test.name, prepared.Load(), applied.Load())
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
	first := make(chan error, 1)
	go func() {
		first <- h.coordinator.Execute(context.Background(), mover, MutationID{Sequence: 1},
			func() ([]VisibilityTarget, error) { return rename, nil },
			func() ([]VisibilityTarget, bool) { return rename, true })
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, mover, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(mover, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatalf("rename: %v", err)
	}
	// The source's COMPLETE is deferred; acknowledging it releases the next
	// mutation exactly as the ordinary protocol does.
	complete, err := h.coordinator.Next(ctx, mover, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(mover, complete.Cursor); err != nil {
		t.Fatal(err)
	}

	// Someone else now touches the name the rename created.
	second := make(chan error, 1)
	go func() {
		second <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 2},
			testVisibilityPrepare("new"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("new"), true
			})
	}()
	event, err := h.coordinator.Next(ctx, mover, complete.Cursor)
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
	if _, err := h.coordinator.Next(idle, bystander, VisibilityCursor{}); !errors.Is(err, context.DeadlineExceeded) {
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
		first <- h.coordinator.Execute(context.Background(), mutator, MutationID{Sequence: 1},
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("shared"), true
			})
	}()
	prepare, err := h.coordinator.Next(ctx, parked, VisibilityCursor{})
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
		parkedDone <- h.coordinator.ExecuteWithHeldParents(context.Background(), parked, MutationID{Sequence: 1},
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
		stillScoped <- h.coordinator.ExecuteWithHeldParents(context.Background(), parked, MutationID{Sequence: 2},
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
		retry <- h.coordinator.ExecuteWithHeldParents(context.Background(), parked, MutationID{Sequence: 3},
			[][16]byte{testVisibilityParent()}, testVisibilityPrepare("retry"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("retry"), true })
	}()
	retryPrepare, err := h.coordinator.Next(ctx, parked, complete.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	runBarrierFrom(t, h.coordinator, parked, retryPrepare)
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
			testVisibilityPrepare("peer-change"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("peer-change"), true })
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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
		operation <- h.coordinator.ExecuteWithHeldParents(ctx, participant, MutationID{Sequence: 2},
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
		parkedDone <- h.coordinator.ExecuteWithHeldParents(context.Background(), parked, MutationID{Sequence: 1},
			[][16]byte{testVisibilityParent()},
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("shared"), true
			})
	}()

	if err := h.coordinator.Execute(context.Background(), mutator, MutationID{Sequence: 1},
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
		err := h.coordinator.ExecuteWithHeldParents(context.Background(), only, MutationID{Sequence: sequence},
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
			if err := h.coordinator.ExecuteWithHeldParents(context.Background(), submission.source, MutationID{Sequence: sequence},
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
				done <- h.coordinator.Execute(context.Background(), mutator, MutationID{Sequence: 1},
					testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
						return testVisibilityTargets("shared"), true
					})
			}()
			prepare, err := h.coordinator.Next(ctx, claimant, VisibilityCursor{})
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
	var after VisibilityCursor
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
		prepare, err := h.coordinator.Next(ctx, mutator, VisibilityCursor{})
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
		done <- h.coordinator.Execute(context.Background(), mutator, MutationID{Sequence: 1},
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
		result <- h.coordinator.Execute(
			context.Background(), peer, MutationID{Sequence: 1, FrontendOperationID: 91},
			testVisibilityPrepare("ghost-debt"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("ghost-debt"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.coordinator.acquireMutationOrder(ctx, participant, MutationID{
		Sequence: 2, FrontendOperationID: 101, SourcePhaseQueueable: true,
	}, nil)
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

	turn, err := h.coordinator.acquireMutationOrder(ctx, participant, MutationID{
		Sequence: 3, FrontendOperationID: 102, SourcePhaseQueueable: true,
	}, nil)
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
		_, err := h.coordinator.acquireMutationOrder(ctx, participant, MutationID{
			Sequence: 2, FrontendOperationID: 101, SourcePhaseQueueable: true,
		}, nil)
		interrupted <- err
	}()
	waitForMutationOrderQueue(t, h.coordinator.order, 1)
	h.coordinator.order.mu.Lock()
	lostOrdinal := h.coordinator.order.waiters.Front().Value.(*mutationOrderWaiter).ordinal
	h.coordinator.order.mu.Unlock()
	close(releasePrepare)

	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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

	turn, err := h.coordinator.acquireMutationOrder(ctx, participant, MutationID{
		Sequence: 3, FrontendOperationID: 102, SourcePhaseQueueable: true,
	}, nil)
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
			testVisibilityPrepare("feedback-debt"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("feedback-debt"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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
	turn, err := h.coordinator.acquireMutationOrder(ctx, participant, MutationID{
		Sequence: 2, FrontendOperationID: 101, SourcePhaseQueueable: true,
	}, nil)
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
			testVisibilityPrepare("false-feedback"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("false-feedback"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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

	firstCursor := run(1, VisibilityCursor{}, true)
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
	owner, err := h.coordinator.order.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reserved := h.coordinator.order.reserveOrdinal()
	h.coordinator.mu.Lock()
	h.coordinator.fairness[participant] = mutationFairnessDebt{
		sequence: 1, ordinal: reserved, active: true, deadline: time.Now().Add(time.Second),
	}
	h.coordinator.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := h.coordinator.acquireMutationOrder(ctx, participant, MutationID{
			Sequence: 1, FrontendOperationID: 101, SourcePhaseQueueable: true,
		}, nil)
		result <- err
	}()
	waitForMutationOrderQueue(t, h.coordinator.order, 1)
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

	turn, err := h.coordinator.acquireMutationOrder(context.Background(), participant, MutationID{
		Sequence: 2, FrontendOperationID: 102, SourcePhaseQueueable: true,
	}, nil)
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
			testVisibilityPrepare("v1-no-debt"),
			func() ([]VisibilityTarget, bool) { return testVisibilityTargets("v1-no-debt"), true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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
		result <- h.coordinator.Execute(
			context.Background(), SessionID{9}, MutationID{Sequence: 1},
			func() ([]VisibilityTarget, error) { return targets, nil },
			func() ([]VisibilityTarget, bool) { return targets, true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := h.coordinator.Next(ctx, participant, VisibilityCursor{})
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
	if err := h.coordinator.validateCompletion(complete, prepared); err == nil {
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
