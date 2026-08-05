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

type allowMountAbsenceVerifier struct{}

func (allowMountAbsenceVerifier) VerifyMountAbsence(SessionID, MountAbsenceProof) error { return nil }

type rejectMountAbsenceVerifier struct{ err error }

func (v rejectMountAbsenceVerifier) VerifyMountAbsence(SessionID, MountAbsenceProof) error {
	return v.err
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
		Prior: prior, Membership: membership, Fencer: fencer, AbsenceVerifier: allowMountAbsenceVerifier{},
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
		Scope:          VisibilityNamespace,
		ParentIdentity: testVisibilityParent(),
		Name:           []byte(name),
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
	if err := h.coordinator.Ack(holder, prepare.Cursor); err != nil {
		t.Fatal(err)
	}

	stabilized := make(chan error, 1)
	go func() {
		_, err := h.coordinator.Stabilize(ctx, latecomer, VisibilityResolution{Parent: testVisibilityParent(), Name: []byte("contended")})
		stabilized <- err
	}()
	select {
	case <-stabilized:
		t.Fatal("a resolution of an in-flight coordinate was allowed to read through the mutation")
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
	case err := <-stabilized:
		if err != nil {
			t.Fatalf("stabilize after the mutation finished: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a resolution stayed blocked after the mutation finished")
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

// Opaque frontend bytes are not evidence on their own. Without a deployment
// verifier, even a syntactically plausible observation must leave the strict
// participant and its durable membership intact.
func TestVisibilityDetachFailsClosedWithoutAnAbsenceVerifier(t *testing.T) {
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
	if err := coordinator.CleanDetach(id, proof); !errors.Is(err, ErrVisibilityProof) {
		t.Fatalf("CleanDetach without verifier = %v, want ErrVisibilityProof", err)
	}
	if !membership.contains(id) {
		t.Fatal("an unverified frontend observation cleared durable membership")
	}
}

func TestVisibilityDetachRejectsAForgedAbsenceAttestation(t *testing.T) {
	membership := newTestDurableVisibilityMembership()
	fencer := newTestFencer()
	forged := errors.New("attestation signature does not bind this session")
	coordinator, err := NewVisibilityCoordinator(VisibilityConfig{
		Prior: PriorEpochStrictMountsFenced, Membership: membership, Fencer: fencer,
		AbsenceVerifier:       rejectMountAbsenceVerifier{err: forged},
		MaxCachedNameCapacity: 1024, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := SessionID{2}
	terminal := fencer.attach(id)
	if err := coordinator.Register(id, CoherenceStrict, terminal, VisibilityCommitment{
		CachedNameCapacity: 32, RepairBudget: time.Second, NamespaceRepair: NamespaceRepairParentExclusive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.CleanDetach(id, testMountAbsence(time.Now())); !errors.Is(err, ErrVisibilityProof) || !errors.Is(err, forged) {
		t.Fatalf("CleanDetach with forged attestation = %v, want proof and verifier failures", err)
	}
	if !membership.contains(id) {
		t.Fatal("a rejected attestation cleared durable membership")
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

// Two mounts mutating the same directory form a real cycle on Linux, and the
// cycle is not fixable. The proof is written out at
// VisibilityCoordinator.ReportBlocked with kernel line references; in short:
// fs/namei.c holds the parent directory's i_rwsem for write across the whole
// FUSE round trip of any namespace syscall (:4389 unlink, :3895 create, :4975
// rename), fs/fuse/dir.c:1351 takes that same semaphore for write - always,
// blocking, before the FUSE_EXPIRE_ONLY test at :1367, with no trylock anywhere
// in fs/fuse - to make a cached binding unservable, and holding the lock does not
// stop the mount serving the name because RCU-walk resolves it with no inode lock
// at all (fs/namei.c:1617, fs/dcache.c:2168, fs/fuse/dir.c:262-273). So a mount
// with an unanswered directory mutation in D cannot repair a name in D, and only
// this authority can answer it.
//
// What this test pins is therefore not "a fix", it is the proven boundary and
// the part of it that WAS fixable. The old behaviour was for the mutation to sit
// on the parked mount's entire repair budget - up to half a minute with every
// other mount's mutations stopped behind it - and then fence it on a timeout.
// The mount can say so instead, and be gone in a round trip.
//
// It has to be the mount that says it, and that is the other half of the
// lesson. The cycle needs the mount to hold the directory AND to actually cache
// a binding this COMPLETE names. This authority knows the first exactly and
// cannot know the second: its audience comes from a filter chosen to have no
// false negatives, so it addresses every mount that ever resolved anything in
// that directory. Deciding the cycle from the first half alone fences every
// mount that is merely busy in the same tree as another - see
// TestVisibilityParkedMountThatCanRepairIsNeverFenced, which is what that
// mistake looked like.
func TestVisibilityParkedMountThatReportsBlockedIsFencedThenHeldForOneGrace(t *testing.T) {
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

	// The parked mount now submits its own mutation in the same directory and
	// blocks for authority order while its kernel holds that directory. It
	// declares which directory that is, exactly as the authority handler does
	// from the request body.
	leave := h.coordinator.EnterMutationOrder(parked, testVisibilityParent())
	parkedDone := make(chan error, 1)
	go func() {
		defer leave()
		parkedDone <- h.coordinator.Execute(context.Background(), parked, MutationID{Sequence: 1},
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
	started := time.Now()
	if err := h.coordinator.ReportBlocked(parked, complete.Cursor); !errors.Is(err, ErrVisibilityBlocked) {
		t.Fatalf("ReportBlocked = %v, want ErrVisibilityBlocked", err)
	}

	select {
	case err := <-first:
		if err != nil {
			t.Fatalf("mutation against a parked mount: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a mount parked in Execute deadlocked the mutation that needed its repair")
	}
	// The session was fenced synchronously, but the barrier stays closed for one
	// whole budget so the remote frontend's contact watchdog can abort the kernel
	// mount before this mutation returns.
	if waited := time.Since(started); waited < parkedBudget || waited > 4*parkedBudget {
		t.Fatalf("the mutation waited %s after fencing, want one %s grace", waited, parkedBudget)
	}
	if !h.fencer.wasFenced(parked) {
		t.Fatal("the parked mount neither repaired nor was fenced")
	}
	if reason := h.fenceReasonFor(parked); !errors.Is(reason, ErrVisibilityBlocked) {
		t.Fatalf("the parked mount was fenced for %v, want ErrVisibilityBlocked", reason)
	}
	if !h.fencer.live(mutator) {
		t.Fatal("fencing the parked mount also took down the mount that met its budget")
	}
	select {
	case err := <-parkedDone:
		if err != nil {
			t.Fatalf("the parked mutation itself failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the parked mutation never returned")
	}
	if err := h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 2},
		testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
			return testVisibilityTargets("shared"), true
		}); err != nil {
		t.Fatalf("the epoch did not survive one fenced mount: %v", err)
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

	leave := h.coordinator.EnterMutationOrder(parked, testVisibilityParent())
	release := make(chan struct{})
	parkedDone := make(chan error, 1)
	go func() {
		defer leave()
		<-release
		parkedDone <- h.coordinator.Execute(context.Background(), parked, MutationID{Sequence: 1},
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

	// Two submissions are always in flight: one being ordered, one waiting,
	// both holding the same directory. That is the npm shape.
	overlap := h.coordinator.EnterMutationOrder(only, testVisibilityParent())
	for sequence := uint64(1); sequence <= 64; sequence++ {
		leave := h.coordinator.EnterMutationOrder(only, testVisibilityParent())
		err := h.coordinator.Execute(context.Background(), only, MutationID{Sequence: sequence},
			testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
				return testVisibilityTargets("shared"), true
			})
		leave()
		if err != nil {
			t.Fatalf("sequential mutation %d: %v", sequence, err)
		}
		if h.fencer.wasFenced(only) {
			t.Fatalf("the only mount was fenced at mutation %d for %v", sequence, h.fenceReasonFor(only))
		}
	}
	overlap()
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
	// Each mount holds a directory of its own for an operation waiting on order.
	leaveFirst := h.coordinator.EnterMutationOrder(first, testVisibilityParent())
	defer leaveFirst()
	leaveSecond := h.coordinator.EnterMutationOrder(second, elsewhere)
	defer leaveSecond()

	for sequence := uint64(1); sequence <= 16; sequence++ {
		for _, source := range []SessionID{first, second} {
			if err := h.coordinator.Execute(context.Background(), source, MutationID{Sequence: sequence},
				testVisibilityPrepare("shared"), func() ([]VisibilityTarget, bool) {
					return testVisibilityTargets("shared"), true
				}); err != nil {
				t.Fatalf("mutation %d from %x: %v", sequence, source, err)
			}
		}
	}
	for _, id := range []SessionID{first, second} {
		if h.fencer.wasFenced(id) {
			t.Fatalf("mount %x was fenced for %v while working in its own directory", id, h.fenceReasonFor(id))
		}
	}
}

// A blocked report is an acknowledgment that ends a session, so it may not be a
// way to be excused from a repair the mount could have performed. The authority
// checks the half of the cycle it can see - this mount has a namespace mutation
// waiting for order, in a directory this phase names - and treats a claim that
// half does not support as the cursor violation it is.
func TestVisibilityUnsupportedBlockedReportIsACursorViolation(t *testing.T) {
	var elsewhere [16]byte
	elsewhere[0] = 2
	cases := map[string]func(*visibilityHarness, SessionID) func(){
		"holding no directory at all": func(*visibilityHarness, SessionID) func() { return func() {} },
		"holding a different directory": func(h *visibilityHarness, id SessionID) func() {
			return h.coordinator.EnterMutationOrder(id, elsewhere)
		},
	}
	for name, park := range cases {
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
			// PREPARE needs no kernel lock, so it is never a credible claim.
			if err := h.coordinator.ReportBlocked(claimant, prepare.Cursor); !errors.Is(err, ErrVisibilitySequence) {
				t.Fatalf("blocked report on PREPARE = %v, want ErrVisibilitySequence", err)
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
			release := park(h, claimant)
			release()
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
