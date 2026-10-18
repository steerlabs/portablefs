package portablefsd

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"testing"
	"time"
)

func acknowledgeSourcePublished(t *testing.T, c *v3SourcePublicationCoordinator, operationID uint64) bool {
	t.Helper()
	known, err := c.acknowledge(testCallback(operationID), pfslocal.PublicationSemanticCommitPublished)
	if err != nil {
		t.Fatalf("acknowledge source publication %d: %v", operationID, err)
	}
	return known
}

func acknowledgeBridgePublished(t *testing.T, b *v3CoherenceBridge, operationID uint64) bool {
	t.Helper()
	known, err := b.acknowledgePublication(testCallback(operationID), pfslocal.PublicationSemanticCommitPublished)
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

func sourceV3PublicationHeld(c *v3SourcePublicationCoordinator, coordinate v3PublicationCoordinate) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sourceHolds[coordinate]) != 0
}

func TestV3SourcePublicationRefusesMissingSerialReaderReservation(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	gate, err := v3ItemSourceGate(testV3PublicationItem(1, 0x21), false)
	if err != nil {
		t.Fatal(err)
	}
	if lease, err := c.acquireSource(context.Background(), testCallback(99), gate); lease != nil || err == nil {
		t.Fatalf("unreserved source acquire = (%#v, %v), want definite refusal", lease, err)
	}
	c.mu.Lock()
	operations, holds := len(c.operations), len(c.sourceHolds)
	c.mu.Unlock()
	if operations != 0 || holds != 0 {
		t.Fatalf("unreserved refusal created state: operations=%d holds=%d", operations, holds)
	}
}

func TestV3EarlyPublicationAckRetainsLateReadUntilHandlerRetirement(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	const operationID = uint64(104)
	c.reserve(testCallback(operationID))
	if !acknowledgeSourcePublished(t, c, operationID) {
		t.Fatal("early PublicationAck was not recorded")
	}
	consumed := 0
	consumption := authorityrpc.ResponseConsumption(&fakeV3ResponseConsumption{consume: func() { consumed++ }})
	if err := c.retainFrontendResponseConsumption(testCallback(operationID), consumption); err != nil {
		t.Fatalf("late healthy read was not retained under its acknowledged callback: %v", err)
	}
	if consumed != 0 {
		t.Fatal("late read receipt was consumed before its handler retired")
	}
	c.retire(testCallback(operationID))
	consumptions, err := c.finishFrontendPublication(testCallback(operationID))
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

func TestV3SourcePublicationFailureIsTerminalAndNeverReopens(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	gate, err := v3ItemSourceGate(testV3PublicationItem(1, 0x91), true)
	if err != nil {
		t.Fatal(err)
	}
	c.reserve(testCallback(300))
	lease, err := c.acquireSource(context.Background(), testCallback(300), gate)
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
	c.retire(testCallback(300))
	c.mu.Lock()
	released := lease.released
	held := len(c.sourceHolds)
	terminal := c.terminal
	c.mu.Unlock()
	if released || held != 2 || !errors.Is(terminal, cause) {
		t.Fatalf("terminal gate reopened: released=%t held=%d terminal=%v", released, held, terminal)
	}
	c.reserve(testCallback(301))
	if next, err := c.acquireSource(context.Background(), testCallback(301), gate); next != nil || !errors.Is(err, cause) {
		t.Fatalf("terminal coordinator admitted a later source: (%#v, %v)", next, err)
	}
}

func TestV3CacheReadNeedsEveryActiveSourceRequestAndClaimSettled(t *testing.T) {
	c := newV3SourcePublicationCoordinator()
	c.reserve(testCallback(98001))
	parent := testV3PublicationItem(1, 0x20)
	gate, err := v3NamespaceSourceGate(parent, []byte("name"), false)
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.acquireSource(context.Background(), testCallback(98001), gate)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.acquireSource(context.Background(), testCallback(98001), gate)
	if err != nil || second != first {
		t.Fatalf("second acquisition: %v", err)
	}
	coordinate := v3PublicationCoordinate{kind: v3PublicationNamespaceName, parent: testV3PublicationIdentity(0x20), name: "name"}
	check := func(want bool) {
		t.Helper()
		c.cacheRead(func(conflict v3CacheConflict) {
			if got := conflict(coordinate) != v3CacheHit; got != want {
				t.Fatalf("conflict=%t, want %t", got, want)
			}
		})
	}
	check(true)
	if err := first.resolveNoBindings(gate); err != nil {
		t.Fatal(err)
	}
	first.finishRequest()
	check(true) // the second request and its claim are still active
	second.finishRequest()
	check(true) // an unresolved claim prevents eligibility even at active=0
	if err := second.resolveNoBindings(gate); err != nil {
		t.Fatal(err)
	}
	check(false)
	if !sourceV3PublicationHeld(c, coordinate) {
		t.Fatal("cache eligibility released mutation ordering hold before ack")
	}
	c.reserve(testCallback(98002))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.acquireSource(ctx, testCallback(98002), gate); !errors.Is(err, context.Canceled) {
		t.Fatalf("mutation passed retained hold: %v", err)
	}
}
