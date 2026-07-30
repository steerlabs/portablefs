package fusefrontend

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const gateTestTimeout = 2 * time.Second

type trackedReadResult struct {
	mu    sync.Mutex
	dones int
}

func (*trackedReadResult) Bytes(buf []byte) ([]byte, fuse.Status) { return buf[:0], fuse.OK }
func (*trackedReadResult) Size() int                              { return 0 }
func (r *trackedReadResult) Done() {
	r.mu.Lock()
	r.dones++
	r.mu.Unlock()
}

func (r *trackedReadResult) doneCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dones
}

func TestReplyGateHandoffWaitsThroughReadResultDone(t *testing.T) {
	var gate ReplyGate
	admission, err := gate.BeginRead(context.Background(), "scope/file")
	if err != nil {
		t.Fatal(err)
	}
	underlying := &trackedReadResult{}
	result := admission.Wrap(underlying)

	started := make(chan struct{})
	handoff := make(chan error, 1)
	go func() {
		close(started)
		handoff <- gate.BeginHandoff(context.Background(), "scope")
	}()
	<-started
	waitForClosingScope(t, &gate, "scope")
	assertNoGateResult(t, handoff, "handoff crossed a reply before ReadResult.Done")

	result.Done()
	if err := receiveGateResult(t, handoff); err != nil {
		t.Fatalf("handoff failed after Done: %v", err)
	}
	if got := underlying.doneCount(); got != 1 {
		t.Fatalf("wrapped Done calls = %d, want 1", got)
	}
	result.Done()
	if got := underlying.doneCount(); got != 1 {
		t.Fatalf("second Done reached wrapped result: calls=%d", got)
	}
	gate.EndHandoff("scope")
}

func TestReplyGateAllowsUnrelatedSubtreeDuringHandoff(t *testing.T) {
	var gate ReplyGate
	active, err := gate.BeginRead(context.Background(), "scope/file")
	if err != nil {
		t.Fatal(err)
	}

	handoff := make(chan error, 1)
	go func() { handoff <- gate.BeginHandoff(context.Background(), "scope") }()
	waitForClosingScope(t, &gate, "scope")
	assertNoGateResult(t, handoff, "handoff did not wait for its subtree")

	ctx, cancel := context.WithTimeout(context.Background(), gateTestTimeout)
	defer cancel()
	unrelated, err := gate.BeginRead(ctx, "sibling/file")
	if err != nil {
		t.Fatalf("unrelated subtree was blocked: %v", err)
	}
	unrelated.Abort()

	active.Abort()
	if err := receiveGateResult(t, handoff); err != nil {
		t.Fatal(err)
	}
	gate.EndHandoff("scope")
}

func TestReplyGateReadCancellationWhileScopeClosed(t *testing.T) {
	var gate ReplyGate
	if err := gate.BeginHandoff(context.Background(), "scope"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := gate.BeginRead(ctx, "scope/file")
		result <- err
	}()
	cancel()
	if err := receiveGateResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("BeginRead error = %v, want context.Canceled", err)
	}
	gate.EndHandoff("scope")
}

func TestReplyGateCanceledHandoffReopensScope(t *testing.T) {
	var gate ReplyGate
	active, err := gate.BeginRead(context.Background(), "scope/file")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- gate.BeginHandoff(ctx, "scope") }()
	waitForClosingScope(t, &gate, "scope")
	assertNoGateResult(t, result, "handoff did not wait for its subtree")
	cancel()
	if err := receiveGateResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("BeginHandoff error = %v, want context.Canceled", err)
	}

	nextCtx, nextCancel := context.WithTimeout(context.Background(), gateTestTimeout)
	defer nextCancel()
	next, err := gate.BeginRead(nextCtx, "scope/next")
	if err != nil {
		t.Fatalf("canceled handoff left scope closed: %v", err)
	}
	next.Abort()
	active.Abort()
}

func TestReplyGateScopeBoundaryAndRoot(t *testing.T) {
	var gate ReplyGate
	if err := gate.BeginHandoff(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), gateTestTimeout)
	defer cancel()
	neighbor, err := gate.BeginRead(ctx, "ab/file")
	if err != nil {
		t.Fatalf("component neighbor was blocked: %v", err)
	}
	neighbor.Abort()
	gate.EndHandoff("a")

	if err := gate.BeginHandoff(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	blockedCtx, blockedCancel := context.WithCancel(context.Background())
	blocked := make(chan error, 1)
	go func() {
		_, err := gate.BeginRead(blockedCtx, "anything")
		blocked <- err
	}()
	assertNoGateResult(t, blocked, "root handoff admitted a read")
	blockedCancel()
	if err := receiveGateResult(t, blocked); !errors.Is(err, context.Canceled) {
		t.Fatalf("root handoff admission error = %v, want context.Canceled", err)
	}
	gate.EndHandoff("")
}

func TestReplyGateAbortIsIdempotent(t *testing.T) {
	var gate ReplyGate
	admission, err := gate.BeginRead(context.Background(), "scope/file")
	if err != nil {
		t.Fatal(err)
	}
	admission.Abort()
	admission.Abort()
	if err := gate.BeginHandoff(context.Background(), "scope"); err != nil {
		t.Fatalf("aborted admission remained active: %v", err)
	}
	gate.EndHandoff("scope")
}

func assertNoGateResult[T any](t *testing.T, result <-chan T, message string) {
	t.Helper()
	select {
	case <-result:
		t.Fatal(message)
	case <-time.After(25 * time.Millisecond):
	}
}

func receiveGateResult[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(gateTestTimeout):
		t.Fatal("timed out waiting for gate result")
		var zero T
		return zero
	}
}

func waitForClosingScope(t *testing.T, gate *ReplyGate, scope string) {
	t.Helper()
	deadline := time.Now().Add(gateTestTimeout)
	for {
		gate.mu.Lock()
		closing := gate.closing[scope]
		gate.mu.Unlock()
		if closing != 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("scope %q never entered handoff", scope)
		}
		time.Sleep(time.Millisecond)
	}
}
