package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeV3SessionClient struct {
	epoch, session []byte
	done           chan struct{}
	mu             sync.Mutex
	closed         bool
	err            error
}

func newFakeV3SessionClient() *fakeV3SessionClient {
	return &fakeV3SessionClient{epoch: bytes.Repeat([]byte{0x11}, 16), session: bytes.Repeat([]byte{0x22}, 16), done: make(chan struct{})}
}
func (f *fakeV3SessionClient) Epoch() []byte                { return append([]byte(nil), f.epoch...) }
func (f *fakeV3SessionClient) SessionID() []byte            { return append([]byte(nil), f.session...) }
func (f *fakeV3SessionClient) SessionDone() <-chan struct{} { return f.done }
func (f *fakeV3SessionClient) SessionError() error          { f.mu.Lock(); defer f.mu.Unlock(); return f.err }
func (f *fakeV3SessionClient) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.done)
	}
	return nil
}
func TestV3CoherenceBridgeKeepsAuthorityAliveForPlannedKernelDetach(t *testing.T) {
	client := newFakeV3SessionClient()
	failures := make(chan error, 1)
	bridge, err := newV3CoherenceBridge(client, func(err error) { failures <- err })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.run(ctx, func(*pfslocal.Event) error { return nil }) }()
	deadline := time.Now().Add(time.Second)
	for {
		bridge.mu.Lock()
		subscribed := bridge.subscribed
		bridge.mu.Unlock()
		if subscribed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("visibility stream did not subscribe")
		}
		time.Sleep(time.Millisecond)
	}
	if err := bridge.beginDetach(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("planned detach stream exit=%v", err)
	}
	select {
	case err := <-failures:
		t.Fatalf("planned detach fenced the authority session: %v", err)
	default:
	}
	client.mu.Lock()
	closed := client.closed
	client.mu.Unlock()
	if closed {
		t.Fatal("planned detach closed the authority before mount-absence proof delivery")
	}
	if err := bridge.bind(); !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("planned detach accepted a replacement frontend: %v", err)
	}
	_ = client.Close()
}

func TestV3CoherenceBridgeFencesIfPlannedDetachAbortsAfterFrontendExit(t *testing.T) {
	client := newFakeV3SessionClient()
	failures := make(chan error, 1)
	bridge, err := newV3CoherenceBridge(client, func(err error) { failures <- err })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.run(ctx, func(*pfslocal.Event) error { return nil }) }()
	deadline := time.Now().Add(time.Second)
	for {
		bridge.mu.Lock()
		subscribed := bridge.subscribed
		bridge.mu.Unlock()
		if subscribed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("visibility stream did not subscribe")
		}
		time.Sleep(time.Millisecond)
	}
	if err := bridge.beginDetach(); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	bridge.abortDetach(syscall.EIO)
	select {
	case <-failures:
	case <-time.After(time.Second):
		t.Fatal("aborted detach resumed after losing its frontend")
	}
	if err := bridge.bind(); !errors.Is(err, errV3EventTerminal) {
		t.Fatalf("aborted detach did not fence the bridge: %v", err)
	}
}

func TestV3CoherenceBridgeEarlyPublicationAckPreventsSourceLeaseReopen(t *testing.T) {
	client := newFakeV3SessionClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, nil)
	if err != nil {
		t.Fatal(err)
	}

	const operationID = uint64(91)
	bridge.reserveFrontendPublication(testCallback(operationID))
	if !acknowledgeBridgePublished(t, bridge, operationID) {
		t.Fatal("publication acknowledgement did not find the serial-reader reservation")
	}
	gate, err := v3ItemSourceGate(pfslocal.Item{
		ItemID: 1, StableIdentity: [16]byte{1},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.sourcePublication.acquireSource(context.Background(), testCallback(operationID), gate); err == nil {
		t.Fatal("early PublicationAck allowed a source lease to reopen")
	}
}

func TestV3CoherenceBridgeBoundsNonmutationPublicationReservations(t *testing.T) {
	client := newFakeV3SessionClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, nil)
	if err != nil {
		t.Fatal(err)
	}

	// ACK before handler retirement: the channel is closed, then the absence of
	// any authority ticket proves this was read-only and retirement removes it.
	bridge.reserveFrontendPublication(testCallback(101))
	if !acknowledgeBridgePublished(t, bridge, 101) {
		t.Fatal("early read-only acknowledgement was refused")
	}
	bridge.releaseFrontendPublication(testCallback(101))

	// Handler retirement before ACK: minor 15 retains the bounded operation fact
	// until the explicit semantic verdict arrives, even when no source lease was
	// acquired. Otherwise a healthy read-only callback's mandatory Ack would be
	// indistinguishable from an unknown operation.
	bridge.reserveFrontendPublication(testCallback(102))
	bridge.releaseFrontendPublication(testCallback(102))
	if !acknowledgeBridgePublished(t, bridge, 102) {
		t.Fatal("finish-before-ack lost its read-only semantic-verdict state")
	}

	bridge.sourcePublication.mu.Lock()
	operations := len(bridge.sourcePublication.operations)
	bridge.sourcePublication.mu.Unlock()
	if operations != 0 {
		t.Fatalf("read-only operations leaked %d source-publication operation(s)", operations)
	}
}

func TestV3CoherenceBridgeReactivatesSequentialContinuationBeforeEarlyAck(t *testing.T) {
	client := newFakeV3SessionClient()
	defer client.Close()
	bridge, err := newV3CoherenceBridge(client, nil)
	if err != nil {
		t.Fatal(err)
	}

	const operationID = uint64(103)
	// Request one is a completed read. The frontend operation remains available
	// for a sequential continuation and its bounded semantic-verdict state stays
	// dormant while no handler is active.
	bridge.reserveFrontendPublication(testCallback(operationID))
	bridge.releaseFrontendPublication(testCallback(operationID))

	// The serial reader sees request two before launching its handler and
	// idempotently reactivates the same operation ID. Its ACK may then overtake
	// handler scheduling; a later source lease must be refused before assignment.
	bridge.reserveFrontendPublication(testCallback(operationID))
	if !acknowledgeBridgePublished(t, bridge, operationID) {
		t.Fatal("continuation acknowledgement did not find the reactivated reservation")
	}
	gate, err := v3ItemSourceGate(pfslocal.Item{
		ItemID: 1, StableIdentity: [16]byte{1},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.sourcePublication.acquireSource(context.Background(), testCallback(operationID), gate); err == nil {
		t.Fatal("continuation mutation reopened after its callback acknowledgement")
	}

	bridge.releaseFrontendPublication(testCallback(operationID))
	bridge.sourcePublication.mu.Lock()
	operations := len(bridge.sourcePublication.operations)
	bridge.sourcePublication.mu.Unlock()
	if operations != 0 {
		t.Fatalf("sequential continuation leaked %d operation(s)", operations)
	}
}
