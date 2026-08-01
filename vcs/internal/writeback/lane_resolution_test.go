package writeback

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The pre-lock classifier's engine-side contract.
//
// A classified operation is INSIDE the frontend's namespace and handle locks by
// the time it reaches the engine. Everything the engine could do there to
// change its lane is a DELEGATION TRANSITION — acquiring a grant, pushing an
// ancestor grant down (drain + durable release), or releasing whatever covers
// the path to reach the authority lane — and every one of them can block for as
// long as the uplink is behind. Taken under a writer-preferring RWMutex's read
// side, that parks the next rename, remove or reclaim and every reader behind
// it: a whole-namespace stall caused by a backlog on one path.
//
// So inside the locks the engine only ever CHECKS the classifier's answer.
// These tests pin that it checks and does not act.

// TestResolvedWriteNeverPushesAnAncestorGrantDownUnderTheLocks is interleaving
// (a) of the finding: the classifier proved a delegated lane, and by the time
// the write arrives the retained grant is a strict ANCESTOR of the mutation's
// exact scope. admit's ordinary answer is to push it down — drain the
// ancestor's whole unshipped tail through the uplink, release it durably, then
// acquire the child. Under the caller's locks that is the incident.
//
// The proof is that the ancestor grant is UNTOUCHED afterwards: a push-down
// would have released it.
func TestResolvedWriteNeverPushesAnAncestorGrantDownUnderTheLocks(t *testing.T) {
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("fixture did not take a delegation over d")
	}
	// A path whose exact governing scope is "d/sub", covered only by the
	// ancestor grant on "d".
	const deep = "d/sub/f"
	if got := governingScope(deep); got == "d" {
		t.Fatalf("governingScope(%q) = %q; the test needs a STRICT ancestor", deep, got)
	}

	chunk := make([]byte, 64<<10)
	opCtx := WithResolvedLane(ctx, LaneDelegated)
	done := make(chan error, 1)
	go func() {
		_, _, err := f.e.WriteAt(opCtx, deep, 0, chunk)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrLaneChanged) {
			t.Fatalf("write under an ancestor-only grant = %v, want ErrLaneChanged", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a classified write blocked inside the engine; it transitioned under the caller's locks")
	}
	if !f.e.Covers("d/f") {
		t.Fatal("the ancestor grant was released: the engine pushed it down under the caller's locks")
	}
}

// TestResolvedWriteNeverAcquiresAGrantUnderTheLocks is interleaving (c): the
// classifier found nothing covering the path, so the write was routed to the
// authority lane and deliberately not charged. A grant appearing in between
// must not be turned into an acquisition here — that is an authority round trip
// under the caller's locks.
//
// The engine must reach that answer BEFORE the credit fast path, too. With a
// free ledger the fast path is one successful CAS, and a lane consulted only
// after it would charge the ledger for bytes that can never become WAL bytes.
func TestResolvedWriteNeverAcquiresAGrantUnderTheLocks(t *testing.T) {
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	// An uncovered sibling scope: admit's ordinary answer here is to acquire.
	const uncovered = "e/g"
	if f.e.Covers(uncovered) {
		t.Fatalf("%s is already covered; the acquisition path is not under test", uncovered)
	}

	before := f.e.Status().CreditDebt
	chunk := make([]byte, 64<<10)
	done := make(chan bool, 1)
	go func() {
		_, handled, _ := f.e.WriteAt(WithResolvedLane(ctx, LaneAuthority), uncovered, 0, chunk)
		done <- handled
	}()
	select {
	case handled := <-done:
		if handled {
			t.Fatal("an authority-resolved write was admitted locally")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a classified write blocked inside the engine; it acquired a grant under the caller's locks")
	}
	if f.e.Covers(uncovered) {
		t.Fatalf("the engine acquired a grant over %s under the caller's locks", uncovered)
	}
	if after := f.e.Status().CreditDebt; after != before {
		t.Fatalf("an authority-resolved write charged %d bytes: the lane was consulted after the credit fast path", after-before)
	}
}

// TestUnclassifiedWritesKeepTheEnginesOwnTransitions is the other side of the
// contract, and the reason none of this weakens the engine. A caller with no
// classifier holds no frontend lock, so every transition is still its to make
// and still costs only itself: it acquires, it pushes ancestors down, it paces.
// The restriction is a property of the CALLER's locks, not of the engine.
func TestUnclassifiedWritesKeepTheEnginesOwnTransitions(t *testing.T) {
	f := newSaturationFixture(t, 8<<20)
	f.openUplink()
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	// An unclassified write on a scope nothing covers still acquires a grant.
	const uncovered = "meta/probe"
	if f.e.Covers(uncovered) {
		t.Fatalf("%s is already covered; the acquisition path is not under test", uncovered)
	}
	if _, handled, err := f.e.WriteAt(ctx, uncovered, 0, []byte("x")); err != nil || !handled {
		t.Fatalf("unclassified write on an uncovered scope: handled=%v err=%v", handled, err)
	}
	if !f.e.Covers(uncovered) {
		t.Fatal("an unclassified mutation did not acquire a grant; the engine lost its own transition")
	}
}

// TestPrepareDelegatedWriteWillNotAcquireAGrantTheLaneCannotBack keeps a
// delegation an optimization rather than a tax. A write to an uncovered path is
// write-through today: no stream budget, no charge, no wait. Taking a grant for
// it when the data lane is already at its setpoint would convert all three —
// the write would become credit-admitted and then paced against a backlog it
// has contributed nothing to and cannot help drain.
func TestPrepareDelegatedWriteWillNotAcquireAGrantTheLaneCannotBack(t *testing.T) {
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	const uncovered = "meta/probe"
	if f.e.Covers(uncovered) {
		t.Fatalf("%s is already covered; the acquisition path is not under test", uncovered)
	}
	exhaustCreditLedger(t, f.e)

	delegated, err := f.e.PrepareDelegatedWrite(ctx, uncovered, 64<<10)
	if err != nil {
		t.Fatalf("PrepareDelegatedWrite: %v", err)
	}
	if delegated {
		t.Fatal("the classifier took a delegation the credit lane cannot admit")
	}
	if f.e.Covers(uncovered) {
		t.Fatalf("a grant was acquired over %s against a full lane; the write was "+
			"write-through and free, and is now charged and paced", uncovered)
	}
}

// TestPrepareDelegatedWriteResolvesTheLaneAndReleasesTheEngineLock is the
// classifier's engine-side entry point. It must perform the transition and hand
// back a plain answer holding NOTHING — if it returned with e.mu still held,
// the frontend would carry the engine lock into its own, which is the deadlock
// the pre-lock placement is supposed to make impossible.
func TestPrepareDelegatedWriteResolvesTheLaneAndReleasesTheEngineLock(t *testing.T) {
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}

	delegated, err := f.e.PrepareDelegatedWrite(ctx, "d/f", 64<<10)
	if err != nil {
		t.Fatalf("PrepareDelegatedWrite: %v", err)
	}
	if !delegated {
		t.Fatal("PrepareDelegatedWrite denied a covered path")
	}
	// e.mu must be free: anything else takes it without waiting.
	done := make(chan struct{})
	go func() {
		f.e.mu.Lock()
		f.e.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("PrepareDelegatedWrite returned holding e.mu")
	}
}
