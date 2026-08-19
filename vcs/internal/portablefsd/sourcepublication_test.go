package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
)

func acknowledgeSourcePublished(t *testing.T, c *v3SourcePublicationCoordinator, operationID uint64) bool {
	t.Helper()
	known, err := c.acknowledge(operationID, pfslocal.PublicationSemanticCommitPublished)
	if err != nil {
		t.Fatalf("acknowledge source publication %d: %v", operationID, err)
	}
	return known
}

func acknowledgeBridgePublished(t *testing.T, b *v3CoherenceBridge, operationID uint64) bool {
	t.Helper()
	known, err := b.acknowledgePublication(operationID, pfslocal.PublicationSemanticCommitPublished)
	if err != nil {
		t.Fatalf("acknowledge bridge publication %d: %v", operationID, err)
	}
	return known
}

func testV3PublicationItem(itemID uint64, identityByte byte) pfslocal.Item {
	var identity [16]byte
	for index := range identity {
		identity[index] = identityByte
	}
	return pfslocal.Item{ItemID: itemID, StableIdentity: identity}
}

func testV3PublicationIdentity(identityByte byte) v3PublicationIdentity {
	var identity v3PublicationIdentity
	for index := range identity {
		identity[index] = identityByte
	}
	return identity
}

func testV3AttributeTarget(identityByte byte) *authoritypb.VisibilityTarget {
	return visibilitywire.Attributes(bytes.Repeat([]byte{identityByte}, 16), 2, 0x700000001)
}

func waitV3PublicationCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for publication coordinator state")
		}
		time.Sleep(time.Millisecond)
	}
}

func peerV3PublicationState(c *v3SourcePublicationCoordinator) (uint64, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerSequence, len(c.peerHolds)
}

func sourceV3PublicationHeld(c *v3SourcePublicationCoordinator, coordinate v3PublicationCoordinate) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sourceHolds[coordinate] != nil
}

func TestV3SourcePublicationGateCanonicalizesExactStableCoordinates(t *testing.T) {
	itemLow := testV3PublicationItem(2, 0x11)
	itemHigh := testV3PublicationItem(3, 0x33)
	parent := testV3PublicationItem(1, 0x22)
	low, err := v3SourceItem(itemLow, false)
	if err != nil {
		t.Fatal(err)
	}
	highAttr, err := v3SourceItem(itemHigh, false)
	if err != nil {
		t.Fatal(err)
	}
	highData, err := v3SourceItem(itemHigh, true)
	if err != nil {
		t.Fatal(err)
	}
	nameZ, err := v3SourceNamespace(parent, []byte("z"), false)
	if err != nil {
		t.Fatal(err)
	}
	nameA, err := v3SourceNamespace(parent, []byte("a"), true)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := v3CanonicalSourceGate(
		[]v3SourceItemSpec{highAttr, low, highData},
		[]v3SourceNamespaceSpec{nameZ, nameA},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(gate.GetTargets()) != 4 {
		t.Fatalf("target count = %d, want four deduplicated coordinates", len(gate.GetTargets()))
	}
	if got := gate.GetTargets()[0].GetItem(); got == nil ||
		!bytes.Equal(got.GetIdentity(), itemLow.StableIdentity[:]) || got.GetData() {
		t.Fatalf("first canonical target = %#v, want low item ATTR", gate.GetTargets()[0])
	}
	if got := gate.GetTargets()[1].GetItem(); got == nil ||
		!bytes.Equal(got.GetIdentity(), itemHigh.StableIdentity[:]) || !got.GetAttributes() || !got.GetData() {
		t.Fatalf("second canonical target = %#v, want merged high item ATTR+DATA", gate.GetTargets()[1])
	}
	if got := gate.GetTargets()[2].GetNamespace(); got == nil || !bytes.Equal(got.GetName(), []byte("a")) ||
		!got.GetBoundAttributes() || !got.GetBoundData() {
		t.Fatalf("third canonical target = %#v, want namespace a bound ATTR+DATA", gate.GetTargets()[2])
	}
	if got := gate.GetTargets()[3].GetNamespace(); got == nil || !bytes.Equal(got.GetName(), []byte("z")) ||
		!got.GetBoundAttributes() || got.GetBoundData() {
		t.Fatalf("fourth canonical target = %#v, want namespace z bound ATTR", gate.GetTargets()[3])
	}
	if _, _, err := coordinatesForV3SourceGate(gate); err != nil {
		t.Fatalf("canonical gate rejected locally: %v", err)
	}
	noncanonical := &authoritypb.FskitSourcePublication{Targets: []*authoritypb.FskitSourcePublicationTarget{
		gate.GetTargets()[1], gate.GetTargets()[0],
	}}
	if _, _, err := coordinatesForV3SourceGate(noncanonical); err == nil {
		t.Fatal("noncanonical source gate was accepted")
	}
}

func TestV3SourcePublicationRefusesMissingSerialReaderReservation(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	gate, err := v3ItemSourceGate(testV3PublicationItem(1, 0x21), false)
	if err != nil {
		t.Fatal(err)
	}
	if lease, err := c.acquireSource(context.Background(), 99, gate); lease != nil || err == nil {
		t.Fatalf("unreserved source acquire = (%#v, %v), want definite refusal", lease, err)
	}
	c.mu.Lock()
	operations, holds := len(c.operations), len(c.sourceHolds)
	c.mu.Unlock()
	if operations != 0 || holds != 0 {
		t.Fatalf("unreserved refusal created state: operations=%d holds=%d", operations, holds)
	}
}

func TestV3SourceFirstPeerPrepareWaitsForExactPublicationAck(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	item := testV3PublicationItem(1, 0x31)
	gate, err := v3ItemSourceGate(item, false)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(100)
	lease, err := c.acquireSource(context.Background(), 100, gate)
	if err != nil || lease == nil {
		t.Fatalf("source acquire = (%#v, %v)", lease, err)
	}
	coordinate := v3PublicationCoordinate{kind: v3PublicationItemAttributes, item: testV3PublicationIdentity(0x31)}
	if !sourceV3PublicationHeld(c, coordinate) {
		t.Fatal("successful acquisition did not install its exact item coordinate")
	}

	peerResult := make(chan error, 1)
	go func() {
		peerResult <- c.acquirePeer(context.Background(), 7, []*authoritypb.VisibilityTarget{testV3AttributeTarget(0x31)})
	}()
	waitV3PublicationCondition(t, func() bool {
		sequence, held := peerV3PublicationState(c)
		return sequence == 7 && held == 1
	})
	select {
	case err := <-peerResult:
		t.Fatalf("peer PREPARE crossed live source publication: %v", err)
	default:
	}

	c.retire(100)
	select {
	case err := <-peerResult:
		t.Fatalf("handler retirement released source publication before PublicationAck: %v", err)
	default:
	}
	if acknowledgeSourcePublished(t, c, 999) {
		t.Fatal("unrelated PublicationAck was accepted")
	}
	select {
	case err := <-peerResult:
		t.Fatalf("unrelated PublicationAck released source publication: %v", err)
	default:
	}
	if !acknowledgeSourcePublished(t, c, 100) {
		t.Fatal("exact PublicationAck was not accepted")
	}
	if err := <-peerResult; err != nil {
		t.Fatalf("peer PREPARE after PublicationAck: %v", err)
	}
	if err := c.validateComplete(7); err != nil {
		t.Fatal(err)
	}
	if sequence, held := peerV3PublicationState(c); sequence != 7 || held != 1 {
		t.Fatalf("PREPARE cut was not held through COMPLETE publication: sequence=%d held=%d", sequence, held)
	}
	if err := c.releasePeer(7); err != nil {
		t.Fatal(err)
	}
}

func TestV3EarlyPublicationAckWaitsForHandlerRetirementBeforeReleasingSource(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	gate, err := v3ItemSourceGate(testV3PublicationItem(1, 0x32), false)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(103)
	lease, err := c.acquireSource(context.Background(), 103, gate)
	if err != nil {
		t.Fatal(err)
	}
	if known, err := c.acknowledge(103, pfslocal.PublicationSemanticCommitUnspecified); known || err == nil {
		t.Fatalf("unspecified PublicationAck = (%t, %v), want rejection", known, err)
	}
	if !acknowledgeSourcePublished(t, c, 103) {
		t.Fatal("early PublicationAck was not recorded")
	}
	if acknowledgeSourcePublished(t, c, 103) {
		t.Fatal("duplicate PublicationAck was accepted")
	}
	c.mu.Lock()
	released := lease.released
	c.mu.Unlock()
	if released {
		t.Fatal("early PublicationAck released a still-active handler's source gate")
	}
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- c.acquirePeer(context.Background(), 8, []*authoritypb.VisibilityTarget{testV3AttributeTarget(0x32)})
	}()
	waitV3PublicationCondition(t, func() bool {
		sequence, held := peerV3PublicationState(c)
		return sequence == 8 && held == 1
	})
	select {
	case err := <-peerResult:
		t.Fatalf("peer crossed active handler after early PublicationAck: %v", err)
	default:
	}
	c.retire(103)
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	released = lease.released
	c.mu.Unlock()
	if !released {
		t.Fatal("handler retirement did not finish the acknowledged publication")
	}
	if err := c.releasePeer(8); err != nil {
		t.Fatal(err)
	}
}

func TestV3EarlyPublicationAckRetainsLateReadUntilHandlerRetirement(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	const operationID = uint64(104)
	c.reserve(operationID)
	if !acknowledgeSourcePublished(t, c, operationID) {
		t.Fatal("early PublicationAck was not recorded")
	}
	consumed := 0
	consumption := authorityrpc.ResponseConsumption(&fakeV3ResponseConsumption{consume: func() { consumed++ }})
	if err := c.retainFrontendResponseConsumption(operationID, consumption); err != nil {
		t.Fatalf("late healthy read was not retained under its acknowledged callback: %v", err)
	}
	if consumed != 0 {
		t.Fatal("late read receipt was consumed before its handler retired")
	}
	c.retire(operationID)
	consumptions, err := c.finishFrontendPublication(operationID)
	if err != nil || len(consumptions) != 1 {
		t.Fatalf("late read finish = (%d,%v), want one receipt", len(consumptions), err)
	}
	for _, retained := range consumptions {
		retained.Consume()
	}
	if consumed != 1 {
		t.Fatalf("late read receipt consumed %d time(s), want 1", consumed)
	}
}

func TestV3NotPublishedAckAfterCommittedMutationIsTerminalAndNeverReopens(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	gate, err := v3ItemSourceGate(testV3PublicationItem(1, 0x33), true)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(104)
	lease, err := c.acquireSource(context.Background(), 104, gate)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.markAssigned(); err != nil {
		t.Fatal(err)
	}
	if err := lease.markCommitted(); err != nil {
		t.Fatal(err)
	}
	known, ackErr := c.acknowledge(104, pfslocal.PublicationSemanticCommitNotPublished)
	if !known || !errors.Is(ackErr, errV3SourcePublicationNotPublished) {
		t.Fatalf("not-published committed ack = (%t, %v)", known, ackErr)
	}
	c.retire(104)
	c.mu.Lock()
	released, terminal := lease.released, c.terminal
	c.mu.Unlock()
	if released || !errors.Is(terminal, errV3SourcePublicationNotPublished) {
		t.Fatalf("terminal source lease released=%t terminal=%v", released, terminal)
	}
	if err := c.acquirePeer(context.Background(), 8, []*authoritypb.VisibilityTarget{
		testV3AttributeTarget(0x33),
	}); !errors.Is(err, errV3SourcePublicationNotPublished) {
		t.Fatalf("peer crossed terminal source lease: %v", err)
	}
}

func TestV3PeerFirstRefusesOnlyOverlappingSourceBeforeAssignment(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	if err := c.acquirePeer(context.Background(), 9, []*authoritypb.VisibilityTarget{testV3AttributeTarget(0x41)}); err != nil {
		t.Fatal(err)
	}
	overlap, err := v3ItemSourceGate(testV3PublicationItem(1, 0x41), false)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(101)
	if lease, err := c.acquireSource(context.Background(), 101, overlap); lease != nil || !errors.Is(err, errV3SourcePublicationInterrupted) {
		t.Fatalf("peer-first overlapping acquire = (%#v, %v), want definite refusal", lease, err)
	}
	if lease := c.operationLease(101); lease != nil {
		t.Fatal("peer-first refusal installed a source lease")
	}
	if !c.peerContention(9) {
		t.Fatal("peer-first ordered refusal did not record exact COMPLETE contention credit")
	}

	disjoint, err := v3ItemSourceGate(testV3PublicationItem(2, 0x42), true)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(102)
	lease, err := c.acquireSource(context.Background(), 102, disjoint)
	if err != nil || lease == nil {
		t.Fatalf("disjoint source acquire = (%#v, %v)", lease, err)
	}
	if !acknowledgeSourcePublished(t, c, 102) {
		t.Fatal("disjoint source PublicationAck was not accepted")
	}
	c.retire(102)
	if err := c.releasePeer(9); err != nil {
		t.Fatal(err)
	}
	if c.peerContention(9) {
		t.Fatal("contention credit survived its exact COMPLETE release")
	}
	lease, err = c.acquireSource(context.Background(), 101, overlap)
	if err != nil || lease == nil {
		t.Fatalf("refused callback could not acquire after peer COMPLETE: (%#v, %v)", lease, err)
	}
}

func TestV3UnresolvedNamespaceBindingConservativelyBlocksPeerItemThenNarrows(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	parent := testV3PublicationItem(1, 0x50)
	gate, err := v3NamespaceSourceGate(parent, []byte("child"), false)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(200)
	lease, err := c.acquireSource(context.Background(), 200, gate)
	if err != nil {
		t.Fatal(err)
	}

	peerResult := make(chan error, 1)
	go func() {
		peerResult <- c.acquirePeer(context.Background(), 11, []*authoritypb.VisibilityTarget{testV3AttributeTarget(0x62)})
	}()
	waitV3PublicationCondition(t, func() bool {
		sequence, held := peerV3PublicationState(c)
		return sequence == 11 && held == 1
	})
	select {
	case err := <-peerResult:
		t.Fatalf("peer item crossed unresolved namespace wildcard: %v", err)
	default:
	}
	if err := lease.attachBinding(
		gate,
		v3PublicationNamespace{parent: testV3PublicationIdentity(0x50), name: "child"},
		testV3PublicationIdentity(0x61),
	); err != nil {
		t.Fatal(err)
	}
	if err := <-peerResult; err != nil {
		t.Fatalf("disjoint peer did not proceed after definitive binding narrowed wildcard: %v", err)
	}
	if err := c.releasePeer(11); err != nil {
		t.Fatal(err)
	}
	if !sourceV3PublicationHeld(c, v3PublicationCoordinate{kind: v3PublicationItemAttributes, item: testV3PublicationIdentity(0x61)}) {
		t.Fatal("definitive returned identity was not added to the source lease")
	}
	if !acknowledgeSourcePublished(t, c, 200) {
		t.Fatal("source PublicationAck was not accepted")
	}
	c.retire(200)
}

func TestV3UnresolvedNamespaceBindingKeepsMatchingPeerUntilPublicationAck(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	parent := testV3PublicationItem(1, 0x70)
	gate, err := v3NamespaceSourceGate(parent, []byte("child"), true)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(201)
	lease, err := c.acquireSource(context.Background(), 201, gate)
	if err != nil {
		t.Fatal(err)
	}
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- c.acquirePeer(context.Background(), 12, []*authoritypb.VisibilityTarget{
			visibilitywire.Data(bytes.Repeat([]byte{0x71}, 16), 3, 0x700000001, 10),
		})
	}()
	waitV3PublicationCondition(t, func() bool {
		sequence, held := peerV3PublicationState(c)
		return sequence == 12 && held == 2
	})
	if err := lease.attachBinding(
		gate,
		v3PublicationNamespace{parent: testV3PublicationIdentity(0x70), name: "child"},
		testV3PublicationIdentity(0x71),
	); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-peerResult:
		t.Fatalf("matching peer crossed definitive ATTR+DATA source binding: %v", err)
	default:
	}
	c.retire(201)
	select {
	case err := <-peerResult:
		t.Fatalf("handler retirement released definitive binding: %v", err)
	default:
	}
	if !acknowledgeSourcePublished(t, c, 201) {
		t.Fatal("exact PublicationAck was not accepted")
	}
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}
	if err := c.releasePeer(12); err != nil {
		t.Fatal(err)
	}
}

func TestV3NoBindingResolutionReleasesOnlyWildcardItemScope(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	parent := testV3PublicationItem(1, 0x80)
	gate, err := v3NamespaceSourceGate(parent, []byte("gone"), false)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(202)
	lease, err := c.acquireSource(context.Background(), 202, gate)
	if err != nil {
		t.Fatal(err)
	}
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- c.acquirePeer(context.Background(), 13, []*authoritypb.VisibilityTarget{testV3AttributeTarget(0x81)})
	}()
	waitV3PublicationCondition(t, func() bool {
		sequence, held := peerV3PublicationState(c)
		return sequence == 13 && held == 1
	})
	if err := lease.resolveNoBinding(gate, v3PublicationNamespace{parent: testV3PublicationIdentity(0x80), name: "gone"}); err != nil {
		t.Fatal(err)
	}
	if err := <-peerResult; err != nil {
		t.Fatalf("peer remained blocked after definitive no-binding result: %v", err)
	}
	// The namespace and parent ATTR coordinates remain held until publication;
	// resolving the child wildcard must not release the callback's real result.
	if !sourceV3PublicationHeld(c, v3PublicationCoordinate{
		kind: v3PublicationNamespaceName, parent: testV3PublicationIdentity(0x80), name: "gone",
	}) {
		t.Fatal("no-binding resolution released the exact namespace coordinate")
	}
	if err := c.releasePeer(13); err != nil {
		t.Fatal(err)
	}
	if !acknowledgeSourcePublished(t, c, 202) {
		t.Fatal("source PublicationAck was not accepted")
	}
	c.retire(202)
}

func TestV3ErrorResolutionIsScopedToOneGateInSharedLogicalOperation(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	parent := testV3PublicationItem(1, 0x85)
	firstGate, err := v3NamespaceSourceGate(parent, []byte("first"), false)
	if err != nil {
		t.Fatal(err)
	}
	secondGate, err := v3NamespaceSourceGate(parent, []byte("second"), false)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(203)
	lease, err := c.acquireSource(context.Background(), 203, firstGate)
	if err != nil {
		t.Fatal(err)
	}
	continued, err := c.acquireSource(context.Background(), 203, secondGate)
	if err != nil || continued != lease {
		t.Fatalf("shared operation continuation = (%#v, %v), want same lease", continued, err)
	}
	if err := lease.resolveNoBindings(secondGate); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, firstUnresolved := lease.names[v3PublicationNamespace{parent: testV3PublicationIdentity(0x85), name: "first"}]
	_, secondUnresolved := lease.names[v3PublicationNamespace{parent: testV3PublicationIdentity(0x85), name: "second"}]
	unresolved := lease.unresolvedAttributes
	c.mu.Unlock()
	if !firstUnresolved || secondUnresolved || unresolved != 1 {
		t.Fatalf("scoped error resolution first=%t second=%t unresolved=%d", firstUnresolved, secondUnresolved, unresolved)
	}
	peerResult := make(chan error, 1)
	peerReturned := make(chan struct{})
	go func() {
		peerResult <- c.acquirePeer(context.Background(), 14, []*authoritypb.VisibilityTarget{testV3AttributeTarget(0x86)})
		close(peerReturned)
	}()
	waitV3PublicationCondition(t, func() bool {
		sequence, held := peerV3PublicationState(c)
		return sequence == 14 && held == 1
	})
	c.mu.Lock()
	peerBusy := c.peerConflictLocked(map[v3PublicationCoordinate]struct{}{
		{kind: v3PublicationItemAttributes, item: testV3PublicationIdentity(0x86)}: {},
	})
	globalUnresolved := len(c.unresolvedAttributes)
	c.mu.Unlock()
	if !peerBusy || globalUnresolved != 1 {
		t.Fatalf("peer conflict after scoped resolution busy=%t unresolved=%d", peerBusy, globalUnresolved)
	}
	select {
	case <-peerReturned:
		t.Fatalf("other mutation's unresolved wildcard was cleared by scoped error: %v", <-peerResult)
	case <-time.After(10 * time.Millisecond):
	}
	if err := lease.attachBinding(
		firstGate,
		v3PublicationNamespace{parent: testV3PublicationIdentity(0x85), name: "first"},
		testV3PublicationIdentity(0x87),
	); err != nil {
		t.Fatal(err)
	}
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}
	if err := c.releasePeer(14); err != nil {
		t.Fatal(err)
	}
	if !acknowledgeSourcePublished(t, c, 203) {
		t.Fatal("PublicationAck was not accepted")
	}
	c.retire(203)
}

func TestV3SameNamespaceErrorConsumesExactlyOneConcurrentCallClaim(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	parent := testV3PublicationItem(1, 0x88)
	gate, err := v3NamespaceSourceGate(parent, []byte("same"), true)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(204)
	type acquisition struct {
		lease *v3SourcePublicationLease
		err   error
	}
	start := make(chan struct{})
	results := make(chan acquisition, 2)
	for range 2 {
		go func() {
			<-start
			lease, acquireErr := c.acquireSource(context.Background(), 204, gate)
			results <- acquisition{lease: lease, err: acquireErr}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.lease == nil || first.lease != second.lease {
		t.Fatalf("concurrent same-name acquisitions = (%p, %v), (%p, %v)", first.lease, first.err, second.lease, second.err)
	}
	lease := first.lease
	namespace := v3PublicationNamespace{parent: testV3PublicationIdentity(0x88), name: "same"}
	if err := lease.resolveNoBindings(gate); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	claims := lease.names[namespace]
	attributes, data := lease.unresolvedAttributes, lease.unresolvedData
	c.mu.Unlock()
	if claims.attributes != 1 || claims.data != 1 || attributes != 1 || data != 1 {
		t.Fatalf("one error consumed sibling claim: claims=%+v unresolved=(%d,%d)", claims, attributes, data)
	}
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- c.acquirePeer(context.Background(), 15, []*authoritypb.VisibilityTarget{
			visibilitywire.Data(bytes.Repeat([]byte{0x89}, 16), 4, 0x880000001, 10),
		})
	}()
	waitV3PublicationCondition(t, func() bool {
		sequence, held := peerV3PublicationState(c)
		return sequence == 15 && held == 2
	})
	select {
	case err := <-peerResult:
		t.Fatalf("peer crossed the sibling call's ATTR+DATA wildcard: %v", err)
	default:
	}
	if err := lease.attachBinding(gate, namespace, testV3PublicationIdentity(0x8a)); err != nil {
		t.Fatal(err)
	}
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}
	if err := c.releasePeer(15); err != nil {
		t.Fatal(err)
	}
	if !acknowledgeSourcePublished(t, c, 204) {
		t.Fatal("PublicationAck was not accepted")
	}
	c.retire(204)
}

func TestV3SameNamespaceSuccessConsumesExactlyOneConcurrentCallClaim(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	parent := testV3PublicationItem(1, 0x8b)
	gate, err := v3NamespaceSourceGate(parent, []byte("same"), true)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(205)
	lease, err := c.acquireSource(context.Background(), 205, gate)
	if err != nil {
		t.Fatal(err)
	}
	continued, err := c.acquireSource(context.Background(), 205, gate)
	if err != nil || continued != lease {
		t.Fatalf("same callback continuation = (%p, %v), want %p", continued, err, lease)
	}
	namespace := v3PublicationNamespace{parent: testV3PublicationIdentity(0x8b), name: "same"}
	firstIdentity := testV3PublicationIdentity(0x8c)
	if err := lease.attachBinding(gate, namespace, firstIdentity); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	claims := lease.names[namespace]
	attributes, data := lease.unresolvedAttributes, lease.unresolvedData
	c.mu.Unlock()
	if claims.attributes != 1 || claims.data != 1 || attributes != 1 || data != 1 {
		t.Fatalf("one success consumed sibling claim: claims=%+v unresolved=(%d,%d)", claims, attributes, data)
	}
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- c.acquirePeer(context.Background(), 16, []*authoritypb.VisibilityTarget{
			visibilitywire.Data(bytes.Repeat([]byte{0x8d}, 16), 5, 0x8b0000001, 10),
		})
	}()
	waitV3PublicationCondition(t, func() bool {
		sequence, held := peerV3PublicationState(c)
		return sequence == 16 && held == 2
	})
	select {
	case err := <-peerResult:
		t.Fatalf("peer crossed sibling wildcard after first success: %v", err)
	default:
	}
	secondIdentity := testV3PublicationIdentity(0x8e)
	if err := lease.attachBinding(gate, namespace, secondIdentity); err != nil {
		t.Fatal(err)
	}
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}
	if err := c.releasePeer(16); err != nil {
		t.Fatal(err)
	}
	matchingPeer := make(chan error, 1)
	go func() {
		matchingPeer <- c.acquirePeer(context.Background(), 17, []*authoritypb.VisibilityTarget{
			visibilitywire.Data(firstIdentity[:], 6, 0x8c0000001, 10),
		})
	}()
	waitV3PublicationCondition(t, func() bool {
		sequence, held := peerV3PublicationState(c)
		return sequence == 17 && held == 2
	})
	c.retire(205)
	select {
	case err := <-matchingPeer:
		t.Fatalf("returned identity was released before PublicationAck: %v", err)
	default:
	}
	if !acknowledgeSourcePublished(t, c, 205) {
		t.Fatal("PublicationAck was not accepted")
	}
	if err := <-matchingPeer; err != nil {
		t.Fatal(err)
	}
	if err := c.releasePeer(17); err != nil {
		t.Fatal(err)
	}
}

func TestV3SourcePublicationFailureIsTerminalAndNeverReopens(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	gate, err := v3ItemSourceGate(testV3PublicationItem(1, 0x91), true)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(300)
	lease, err := c.acquireSource(context.Background(), 300, gate)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.markAssigned(); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("assigned mutation transport uncertainty")
	c.fail(cause)
	if !acknowledgeSourcePublished(t, c, 300) {
		t.Fatal("terminal callback's exact PublicationAck was not recorded")
	}
	c.retire(300)
	c.mu.Lock()
	released := lease.released
	held := len(c.sourceHolds)
	terminal := c.terminal
	c.mu.Unlock()
	if released || held != 2 || !errors.Is(terminal, cause) {
		t.Fatalf("terminal gate reopened: released=%t held=%d terminal=%v", released, held, terminal)
	}
	c.reserve(301)
	if next, err := c.acquireSource(context.Background(), 301, gate); next != nil || !errors.Is(err, cause) {
		t.Fatalf("terminal coordinator admitted a later source: (%#v, %v)", next, err)
	}
}
