package authorityrpc

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestRetireTransportConnectionsDoesNotExposeSuccessorBeforeExecutionDrain(t *testing.T) {
	canceled := make(chan struct{})
	closed := make(chan struct{})
	executionDrained := make(chan struct{})
	entry := &transportConnection{
		cancel:           func() { close(canceled) },
		close:            func() error { close(closed); return nil },
		executionPins:    1,
		executionDrained: executionDrained,
	}
	pair := &transportPair{done: make(chan struct{})}
	done := make(chan bool, 1)
	go func() { done <- retireTransportConnections(pair, entry) }()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("predecessor was not canceled")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("predecessor socket was not closed")
	}
	select {
	case result := <-done:
		t.Fatalf("retirement returned before admitted executions drained: %t", result)
	case <-time.After(20 * time.Millisecond):
	}
	entry.executionMu.Lock()
	entry.executionPins = 0
	close(entry.executionDrained)
	entry.executionMu.Unlock()
	select {
	case result := <-done:
		if !result {
			t.Fatal("execution drain reported a terminal pair")
		}
	case <-time.After(time.Second):
		t.Fatal("retirement did not finish after the drain proof")
	}
}

func testTransportRegistration(t *testing.T, registry *transportRegistry, peer byte, set byte, role authoritypb.TransportRole) (*transportConnection, *atomic.Int32) {
	return testTransportRegistrationForProfile(
		t, registry, peer, set, role, authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES,
	)
}

func testTransportRegistrationForProfile(
	t *testing.T,
	registry *transportRegistry,
	peer byte,
	set byte,
	role authoritypb.TransportRole,
	profile authoritypb.FrontendProfile,
) (*transportConnection, *atomic.Int32) {
	t.Helper()
	var setID connectionSetID
	setID[0] = set
	closed := new(atomic.Int32)
	entry, err := registry.register(
		volumeserver.PeerIdentity{peer}, setID, role, profile,
		func() {}, func() error { closed.Add(1); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	return entry, closed
}

func TestTransportRegistryRequiresExactPairAndRefusesUnprovedDuplicateRole(t *testing.T) {
	registry, err := newTransportRegistry(1)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	snapshot, err := registry.snapshot(data)
	if err != nil || !snapshot.current || snapshot.complete || snapshot.bindingGeneration == 0 {
		t.Fatalf("one-lane snapshot = %+v, %v", snapshot, err)
	}
	var set connectionSetID
	set[0] = 2
	if _, err := registry.register(volumeserver.PeerIdentity{1}, set, authoritypb.TransportRole_TRANSPORT_ROLE_DATA, authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES, func() {}, func() error { return nil }); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("duplicate DATA = %v, want ErrTransportBinding", err)
	}
	control, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	snapshot, err = registry.snapshot(control)
	if err != nil || !snapshot.complete || snapshot.dataGeneration != data.generation || snapshot.controlGeneration != control.generation {
		t.Fatalf("paired snapshot = %+v, %v", snapshot, err)
	}
	if _, _, err := registry.bindProvisional(control, volumeserver.SessionID{3}); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("CONTROL attach = %v, want ErrTransportBinding", err)
	}
}

func TestTransportRegistryDoesNotPairDifferentPeerOrSet(t *testing.T) {
	registry, _ := newTransportRegistry(3)
	data, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	testTransportRegistration(t, registry, 2, 2, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	testTransportRegistration(t, registry, 1, 3, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	snapshot, err := registry.snapshot(data)
	if err != nil || snapshot.complete {
		t.Fatalf("cross-peer/set lanes paired: %+v, %v", snapshot, err)
	}
}

func TestTransportRegistryCandidateCannotEvictBeforeProof(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	data, oldDataClosed := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	control, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	session := volumeserver.SessionID{7}
	snapshot, replaced, err := registry.bindProvisional(data, session)
	if err != nil || len(replaced) != 0 || snapshot.state != authoritypb.SessionState_SESSION_STATE_PROVISIONAL {
		t.Fatalf("bind = %+v, %v, %v", snapshot, replaced, err)
	}
	if err := registry.exposeCurrentPair(data, session); err != nil {
		t.Fatal(err)
	}
	candidate, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	before, err := registry.snapshot(candidate)
	if err != nil || before.current || !before.candidate || oldDataClosed.Load() != 0 {
		t.Fatalf("candidate changed current before proof: %+v closed=%d err=%v", before, oldDataClosed.Load(), err)
	}
	promoted, old, err := registry.promoteResume(candidate, session, authoritypb.SessionState_SESSION_STATE_PROVISIONAL)
	if err != nil || old != data || !promoted.current || promoted.dataGeneration != candidate.generation {
		t.Fatalf("promotion = %+v old=%p want=%p err=%v", promoted, old, data, err)
	}
	if promoted.serving {
		t.Fatal("successor was exposed before predecessor drain")
	}
	if _, err := registry.currentWitness(candidate, session); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("unexposed successor witness = %v, want ErrTransportBinding", err)
	}
	if _, err := registry.resumeWitness(candidate, session); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("duplicate Resume exposed a draining successor: %v", err)
	}
	if _, err := registry.attachWitness(candidate); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("duplicate Attach exposed a draining successor: %v", err)
	}
	if _, err := registry.activationWitness(control, session, candidate.generation, control.generation); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("Activate crossed an undrained DATA replacement: %v", err)
	}
	if !retireTransportConnections(candidate.pair, old) {
		t.Fatal("replacement observed an unexpected terminal edge")
	}
	if err := registry.exposeResumed(candidate, session, authoritypb.SessionState_SESSION_STATE_PROVISIONAL); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.currentWitness(candidate, session); err != nil {
		t.Fatalf("exposed successor witness: %v", err)
	}
	if oldDataClosed.Load() != 1 {
		t.Fatalf("replaced connection closed %d times", oldDataClosed.Load())
	}
	controlSnapshot, _ := registry.snapshot(control)
	if !controlSnapshot.current {
		t.Fatal("DATA replacement disturbed CONTROL")
	}
}

func TestTransportRegistryActivationNeedsCurrentExactGenerations(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	data, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	control, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	session := volumeserver.SessionID{8}
	snapshot, _, err := registry.bindProvisional(data, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.exposeCurrentPair(data, session); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.activationWitness(control, session, snapshot.dataGeneration+1, snapshot.controlGeneration); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("stale DATA generation = %v", err)
	}
	if _, err := registry.activationWitness(data, session, snapshot.dataGeneration, snapshot.controlGeneration); !errors.Is(err, ErrTransportBinding) {
		t.Fatalf("DATA activation = %v", err)
	}
	if _, err := registry.activationWitness(control, session, snapshot.dataGeneration, snapshot.controlGeneration); err != nil {
		t.Fatal(err)
	}
	if err := registry.markActive(control, session); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.activeWitness(data, session); err != nil {
		t.Fatal(err)
	}
	if replay, err := registry.activationWitness(control, session, snapshot.dataGeneration, snapshot.controlGeneration); err != nil || replay.state != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		t.Fatalf("duplicate activation could not reach retained runtime outcome: %+v, %v", replay, err)
	}
}

func TestTransportRegistryRecordsCommittedActivationAfterBothLanesDisappear(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	data, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	control, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	session := volumeserver.SessionID{0x88}
	snapshot, _, err := registry.bindProvisional(data, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.exposeCurrentPair(data, session); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.activationWitness(control, session, snapshot.dataGeneration, snapshot.controlGeneration); err != nil {
		t.Fatal(err)
	}
	// This models both sockets failing after the handler's durable/runtime
	// activation commit but before the server records/sends the reply.
	registry.unregister(data)
	registry.unregister(control)
	if err := registry.markActive(control, session); err != nil {
		t.Fatalf("post-commit transport transition depended on a live socket: %v", err)
	}
	newData, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	newControl, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	for _, entry := range []*transportConnection{newData, newControl} {
		witness, err := registry.resumeWitness(entry, session)
		if err != nil || witness.state != authoritypb.SessionState_SESSION_STATE_ACTIVE {
			t.Fatalf("ACTIVE recovery witness = %+v, %v", witness, err)
		}
		if _, _, err := registry.promoteResume(entry, session, authoritypb.SessionState_SESSION_STATE_ACTIVE); err != nil {
			t.Fatal(err)
		}
		if err := registry.exposeResumed(entry, session, authoritypb.SessionState_SESSION_STATE_ACTIVE); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := registry.activeWitness(newData, session); err != nil {
		t.Fatalf("recovered DATA is not active: %v", err)
	}
	if _, err := registry.activeWitness(newControl, session); err != nil {
		t.Fatalf("recovered CONTROL is not active: %v", err)
	}
}

func TestTransportRegistryProvisionalAttachReplayRecoversBothDeadLanes(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	data, dataClosed := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	control, controlClosed := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	session := volumeserver.SessionID{0x81}
	if _, _, err := registry.bindProvisional(data, session); err != nil {
		t.Fatal(err)
	}
	if err := registry.exposeCurrentPair(data, session); err != nil {
		t.Fatal(err)
	}
	registry.unregister(data)
	registry.unregister(control)
	newData, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	newControl, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	snapshot, replaced, err := registry.bindProvisional(newData, session)
	if err != nil || !snapshot.complete || snapshot.dataGeneration != newData.generation || snapshot.controlGeneration != newControl.generation {
		t.Fatalf("replayed pair = %+v replaced=%v err=%v", snapshot, replaced, err)
	}
	terminateTransportConnections(replaced...)
	if err := registry.exposeCurrentPair(newData, session); err != nil {
		t.Fatal(err)
	}
	if dataClosed.Load() != 0 || controlClosed.Load() != 0 {
		t.Fatal("already-unregistered predecessors were closed as current replacements")
	}
	if current, err := registry.currentWitness(newControl, session); err != nil || !current.current {
		t.Fatalf("replayed CONTROL not current: %+v, %v", current, err)
	}
}

func TestTransportRegistryTerminalCleanupIsGenerationSafe(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	data, dataClosed := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	_, controlClosed := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	session := volumeserver.SessionID{9}
	if _, _, err := registry.bindProvisional(data, session); err != nil {
		t.Fatal(err)
	}
	if err := registry.exposeCurrentPair(data, session); err != nil {
		t.Fatal(err)
	}
	entries := registry.markTerminal(session, authoritypb.SessionState_SESSION_STATE_ABORTED)
	terminateTransportConnections(entries...)
	if dataClosed.Load() != 1 || controlClosed.Load() != 1 {
		t.Fatalf("terminal closes = data %d control %d", dataClosed.Load(), controlClosed.Load())
	}
	if len(registry.pairs) != 0 || len(registry.bySession) != 0 {
		t.Fatalf("terminal registry retained %d pairs / %d sessions", len(registry.pairs), len(registry.bySession))
	}
	// A stale connection's deferred unregister cannot remove a newly registered
	// pair which happens to use the same peer/set key.
	replacement, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	registry.unregister(data)
	snapshot, err := registry.snapshot(replacement)
	if err != nil || !snapshot.current {
		t.Fatalf("stale unregister removed replacement: %+v, %v", snapshot, err)
	}
}

func TestTransportContextIdentityIsPrivateAndExact(t *testing.T) {
	registry, _ := newTransportRegistry(1)
	entry, _ := testTransportRegistration(t, registry, 1, 2, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	if _, ok := transportConnectionFromContext(context.Background()); ok {
		t.Fatal("empty context carried transport authority")
	}
	got, ok := transportConnectionFromContext(withTransportConnection(context.Background(), entry))
	if !ok || got != entry {
		t.Fatalf("context connection = %p, %t, want %p", got, ok, entry)
	}
}
