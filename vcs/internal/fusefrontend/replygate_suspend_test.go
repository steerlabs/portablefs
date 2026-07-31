package fusefrontend

import (
	"context"
	"testing"
	"time"
)

// gateState reports one path's admitted-reply count and the operation's wait
// depth. Reading the gate directly is deliberate: the properties under test are
// about who is inside the drain set, which has no external observer other than
// BeginHandoff itself.
func gateActiveCount(gate *ReplyGate, path string) int {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.active[path]
}

func gateOperation(t *testing.T, ctx context.Context, gate *ReplyGate) *operation {
	t.Helper()
	op := gate.operationFrom(ctx)
	if op == nil {
		t.Fatal("context does not carry a gate operation")
	}
	return op
}

// TestReplyGateSuspendedReadDoesNotBlockHandoffDrain is the liveness property
// the FUSE frontend was missing: a read that is admitted but blocked on the
// authority must leave the drain set, or the handoff it is waiting behind can
// never complete.
func TestReplyGateSuspendedReadDoesNotBlockHandoffDrain(t *testing.T) {
	var gate ReplyGate
	ctx := gate.Operation(context.Background())
	admission, err := gate.BeginRead(ctx, "scope/file")
	if err != nil {
		t.Fatal(err)
	}

	handoff := make(chan error, 1)
	go func() { handoff <- gate.BeginHandoff(context.Background(), "scope") }()
	waitForClosingScope(t, &gate, "scope")
	assertNoGateResult(t, handoff, "handoff crossed an admitted reply")

	resume := gate.SuspendOperation(ctx)
	if resume == nil {
		t.Fatal("bound operation did not suspend")
	}
	if err := receiveGateResult(t, handoff); err != nil {
		t.Fatalf("drain did not complete after suspension: %v", err)
	}
	if got := gateActiveCount(&gate, "scope/file"); got != 0 {
		t.Fatalf("suspended reply is still admitted: count=%d", got)
	}

	resumed := make(chan struct{})
	go func() { resume(); close(resumed) }()
	assertNoGateResult(t, resumed, "resume published back into a closed scope")

	gate.EndHandoff("scope")
	receiveGateResult(t, resumed)
	if got := gateActiveCount(&gate, "scope/file"); got != 1 {
		t.Fatalf("resumed reply was not re-admitted: count=%d", got)
	}
	admission.Abort()
}

// TestReplyGateSuspendedReadReentersBeforeAConcurrentHandoff proves the second
// half of the invariant end to end: the reply that enabled a drain is published
// only after that handoff has finished, and it blocks the NEXT drain again.
func TestReplyGateSuspendedReadReentersBeforeAConcurrentHandoff(t *testing.T) {
	var gate ReplyGate
	ctx := gate.Operation(context.Background())
	admission, err := gate.BeginRead(ctx, "scope/file")
	if err != nil {
		t.Fatal(err)
	}
	resume := gate.SuspendOperation(ctx)
	if err := gate.BeginHandoff(context.Background(), "scope"); err != nil {
		t.Fatal(err)
	}
	gate.EndHandoff("scope")
	resume()

	next := make(chan error, 1)
	go func() { next <- gate.BeginHandoff(context.Background(), "scope") }()
	waitForClosingScope(t, &gate, "scope")
	assertNoGateResult(t, next, "re-admitted reply did not rejoin the drain set")
	admission.Abort()
	if err := receiveGateResult(t, next); err != nil {
		t.Fatal(err)
	}
	gate.EndHandoff("scope")
}

// TestReplyGateSuspensionSpansOnlyOverlappingScopes keeps suspension as
// path-scoped as admission: an unrelated handoff must not hold a resuming
// reply.
func TestReplyGateSuspensionSpansOnlyOverlappingScopes(t *testing.T) {
	var gate ReplyGate
	ctx := gate.Operation(context.Background())
	admission, err := gate.BeginRead(ctx, "scope/file")
	if err != nil {
		t.Fatal(err)
	}
	resume := gate.SuspendOperation(ctx)
	if err := gate.BeginHandoff(context.Background(), "sibling"); err != nil {
		t.Fatal(err)
	}

	resumed := make(chan struct{})
	go func() { resume(); close(resumed) }()
	receiveGateResult(t, resumed)
	if got := gateActiveCount(&gate, "scope/file"); got != 1 {
		t.Fatalf("disjoint handoff blocked a resume: count=%d", got)
	}
	gate.EndHandoff("sibling")
	admission.Abort()
}

// TestReplyGateNestedSuspensionReentersOnlyAtFinalResume covers a mutation that
// waits for a delegation release and then makes its own authority call.
func TestReplyGateNestedSuspensionReentersOnlyAtFinalResume(t *testing.T) {
	for _, tc := range []struct {
		name        string
		resumeOuter bool
	}{
		{name: "outer first", resumeOuter: true},
		{name: "inner first", resumeOuter: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gate ReplyGate
			ctx := gate.Operation(context.Background())
			admission, err := gate.BeginRead(ctx, "scope/file")
			if err != nil {
				t.Fatal(err)
			}
			op := gateOperation(t, ctx, &gate)

			outer := gate.SuspendOperation(ctx)
			inner := gate.SuspendOperation(ctx)
			first, final := inner, outer
			if tc.resumeOuter {
				first, final = outer, inner
			}
			assertGateState := func(wantDepth, wantActive int) {
				t.Helper()
				gate.mu.Lock()
				depth := op.depth
				gate.mu.Unlock()
				active := gateActiveCount(&gate, "scope/file")
				if depth != wantDepth || active != wantActive {
					t.Fatalf("depth=%d active=%d, want %d/%d", depth, active, wantDepth, wantActive)
				}
			}
			assertGateState(2, 0)
			first()
			assertGateState(1, 0)
			first() // every resume closure is idempotent
			assertGateState(1, 0)
			final()
			assertGateState(0, 1)
			final()
			assertGateState(0, 1)
			admission.Abort()
		})
	}
}

// TestReplyGateSuspensionWithoutAdmissionIsInert is the non-read FUSE op:
// metadata, write and advisory-lock requests carry an operation but publish
// nothing through the gate, so their waits neither drain nor block.
func TestReplyGateSuspensionWithoutAdmissionIsInert(t *testing.T) {
	var gate ReplyGate
	ctx := gate.Operation(context.Background())
	if err := gate.BeginHandoff(context.Background(), ""); err != nil {
		t.Fatal(err)
	}

	resume := gate.SuspendOperation(ctx)
	if resume == nil {
		t.Fatal("bound operation did not suspend")
	}
	resumed := make(chan struct{})
	go func() { resume(); close(resumed) }()
	receiveGateResult(t, resumed)
	gate.EndHandoff("")
}

// TestReplyGateSuspensionWithoutOperationIsUnbound keeps a frontend that never
// binds an operation (and any other gate's context) exactly as it is today.
func TestReplyGateSuspensionWithoutOperationIsUnbound(t *testing.T) {
	var gate, other ReplyGate
	if resume := gate.SuspendOperation(context.Background()); resume != nil {
		t.Fatal("unbound context produced a suspension")
	}
	foreign := other.Operation(context.Background())
	if resume := gate.SuspendOperation(foreign); resume != nil {
		t.Fatal("another gate's operation produced a suspension")
	}
	if got := gate.Operation(foreign); got == foreign {
		t.Fatal("another gate's operation was adopted instead of rebound")
	}
}

// TestReplyGateOperationBindsOnce keeps one kernel request to one publication
// identity however many layers ask for it.
func TestReplyGateOperationBindsOnce(t *testing.T) {
	var gate ReplyGate
	ctx := gate.Operation(context.Background())
	if again := gate.Operation(ctx); again != ctx {
		t.Fatal("rebinding an operation created a second identity")
	}
}

// TestReplyGateCanceledResumeRevokesInsteadOfPublishing covers an interrupt
// that lands while the reply is suspended: it must not wait for the handoff it
// unblocked, must not silently re-enter, and must tell the frontend that the
// reply can no longer be published.
func TestReplyGateCanceledResumeRevokesInsteadOfPublishing(t *testing.T) {
	var gate ReplyGate
	ctx, cancel := context.WithCancel(context.Background())
	ctx = gate.Operation(ctx)
	admission, err := gate.BeginRead(ctx, "scope/file")
	if err != nil {
		t.Fatal(err)
	}
	resume := gate.SuspendOperation(ctx)
	if err := gate.BeginHandoff(context.Background(), "scope"); err != nil {
		t.Fatal(err)
	}

	resumed := make(chan struct{})
	go func() { resume(); close(resumed) }()
	assertNoGateResult(t, resumed, "resume ignored the closed scope")
	cancel()
	receiveGateResult(t, resumed)

	if !admission.Revoked() {
		t.Fatal("canceled resume left the reply publishable")
	}
	if got := gateActiveCount(&gate, "scope/file"); got != 0 {
		t.Fatalf("canceled resume re-entered the drain set: count=%d", got)
	}
	admission.Abort()
	gate.EndHandoff("scope")
	if err := gate.BeginHandoff(context.Background(), "scope"); err != nil {
		t.Fatalf("revoked reply outlived its request: %v", err)
	}
	gate.EndHandoff("scope")
}

// TestReplyGateAdmissionInsideSuspensionStaysSuspended keeps the accounting
// rule total: an admission is counted exactly while its request is running.
func TestReplyGateAdmissionInsideSuspensionStaysSuspended(t *testing.T) {
	var gate ReplyGate
	ctx := gate.Operation(context.Background())
	resume := gate.SuspendOperation(ctx)
	admission, err := gate.BeginRead(ctx, "scope/file")
	if err != nil {
		t.Fatal(err)
	}
	if got := gateActiveCount(&gate, "scope/file"); got != 0 {
		t.Fatalf("reply admitted inside a suspension joined the drain set: count=%d", got)
	}
	if err := gate.BeginHandoff(context.Background(), "scope"); err != nil {
		t.Fatal(err)
	}
	gate.EndHandoff("scope")
	resume()
	if got := gateActiveCount(&gate, "scope/file"); got != 1 {
		t.Fatalf("reply was not admitted at resume: count=%d", got)
	}
	admission.Abort()
}

// TestReplyGateSuspendedReplyPublishesThroughDone proves the suspension path
// leaves the ReadResult.Done accounting intact: the wrapped result still
// releases exactly one admission.
func TestReplyGateSuspendedReplyPublishesThroughDone(t *testing.T) {
	var gate ReplyGate
	ctx := gate.Operation(context.Background())
	admission, err := gate.BeginRead(ctx, "scope/file")
	if err != nil {
		t.Fatal(err)
	}
	resume := gate.SuspendOperation(ctx)
	resume()

	underlying := &trackedReadResult{}
	result := admission.Wrap(underlying)
	handoff := make(chan error, 1)
	go func() { handoff <- gate.BeginHandoff(context.Background(), "scope") }()
	waitForClosingScope(t, &gate, "scope")
	assertNoGateResult(t, handoff, "handoff crossed a resumed reply")
	result.Done()
	if err := receiveGateResult(t, handoff); err != nil {
		t.Fatal(err)
	}
	if got := underlying.doneCount(); got != 1 {
		t.Fatalf("wrapped Done calls = %d, want 1", got)
	}
	gate.EndHandoff("scope")
}

// TestReplyGateConcurrentSuspensionsAllDrainOneHandoff is the joined-waiter
// shape: several admitted reads block on the same authority transition, and the
// drain must complete once the last of them suspends.
func TestReplyGateConcurrentSuspensionsAllDrainOneHandoff(t *testing.T) {
	var gate ReplyGate
	const readers = 4
	resumes := make([]func(), 0, readers)
	admissions := make([]*ReadAdmission, 0, readers)
	for i := 0; i < readers; i++ {
		ctx := gate.Operation(context.Background())
		admission, err := gate.BeginRead(ctx, "scope/file")
		if err != nil {
			t.Fatal(err)
		}
		admissions = append(admissions, admission)
		resumes = append(resumes, gate.SuspendOperation(ctx))
	}

	handoff := make(chan error, 1)
	go func() { handoff <- gate.BeginHandoff(context.Background(), "scope") }()
	if err := receiveGateResult(t, handoff); err != nil {
		t.Fatalf("drain did not complete with every reader suspended: %v", err)
	}

	done := make(chan struct{}, readers)
	for _, resume := range resumes {
		go func() { resume(); done <- struct{}{} }()
	}
	select {
	case <-done:
		t.Fatal("a reader resumed inside the closed scope")
	case <-time.After(25 * time.Millisecond):
	}
	gate.EndHandoff("scope")
	for range resumes {
		receiveGateResult(t, done)
	}
	if got := gateActiveCount(&gate, "scope/file"); got != readers {
		t.Fatalf("re-admitted readers = %d, want %d", got, readers)
	}
	for _, admission := range admissions {
		admission.Abort()
	}
}
